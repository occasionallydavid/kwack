use std::future::Future;
use std::io;
use std::net::SocketAddr;
use std::time::Duration;

use axum::http::{self, HeaderMap, Method, Request, StatusCode};
use axum::{Extension, Router};
use bytes::Bytes;
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Incoming};
use hyper::client::conn::http1;
use hyper_util::rt::{TokioIo, TokioTimer};
use hyper_util::service::TowerToHyperService;
use tokio::io::{AsyncWriteExt, copy_bidirectional};
use tokio::net::TcpListener;
use tokio::task::{JoinHandle, JoinSet};

use crate::{Client, Connection, Error, PeerIdentity, Server};

impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PeerIdentity {
    type Rejection = (StatusCode, &'static str);
    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _: &S,
    ) -> Result<Self, Self::Rejection> {
        parts.extensions.get::<Self>().copied().ok_or((
            StatusCode::INTERNAL_SERVER_ERROR,
            "missing authenticated transport identity",
        ))
    }
}

impl Server {
    pub async fn serve_axum(self, router: Router) -> Result<(), Error> {
        self.serve_axum_with_shutdown(router, std::future::pending::<()>())
            .await
    }
    /// Cancels active handlers and closes the transport when shutdown resolves.
    pub async fn serve_axum_with_shutdown(
        mut self,
        router: Router,
        shutdown: impl Future<Output = ()> + Send,
    ) -> Result<(), Error> {
        tokio::pin!(shutdown);
        let mut tasks = JoinSet::new();
        loop {
            tokio::select! {
                _=&mut shutdown=>{self.handle().shutdown().await?;break;}
                result=self.accept(), if tasks.len() < 256 =>match result {
                    Ok(connection)=>{let router=router.clone();tasks.spawn(async move {serve_connection(connection,router).await;});}
                    Err(error)=>{if error.downcast_ref::<io::Error>().is_some_and(|e| e.kind()==io::ErrorKind::BrokenPipe) {break;}return Err(error);}
                },
                Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
            }
        }
        // JoinSet drop cancels outstanding connection and request tasks.
        Ok(())
    }
}

async fn serve_connection(connection: Connection, router: Router) {
    let router = router.layer(Extension(connection.peer_identity()));
    let mut tasks = JoinSet::new();
    loop {
        tokio::select! {
            stream=connection.accept_bi(), if tasks.len() < 64 =>match stream {
                Ok(stream)=>{
                    let service=TowerToHyperService::new(router.clone());
                    tasks.spawn(async move {
                        if let Err(error)=hyper::server::conn::http1::Builder::new()
                            .timer(TokioTimer::new()).header_read_timeout(Duration::from_secs(15))
                            .max_buf_size(64*1024).serve_connection(TokioIo::new(stream),service).await {
                            tracing::debug!(%error,"HTTP stream closed");
                        }
                    });
                }
                Err(_)=>break,
            },
            Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
        }
    }
}

/// An asynchronous HTTP client. Every request gets an independent QUIC stream.
#[derive(Clone)]
pub struct HttpClient {
    client: Client,
    authority: String,
    timeout: Duration,
}
impl Client {
    /// The authority is HTTP routing metadata. The remote public key remains the identity.
    pub fn http(&self) -> HttpClient {
        HttpClient {
            client: self.clone(),
            authority: "wireguard-quic".into(),
            timeout: Duration::from_secs(30),
        }
    }
}
impl HttpClient {
    pub fn authority(mut self, authority: impl Into<String>) -> Self {
        self.authority = authority.into();
        self
    }
    pub fn timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    pub fn get(&self, path: &str) -> RequestBuilder {
        self.request(Method::GET, path)
    }
    pub fn post(&self, path: &str) -> RequestBuilder {
        self.request(Method::POST, path)
    }
    pub fn request(&self, method: Method, path: &str) -> RequestBuilder {
        RequestBuilder {
            client: self.clone(),
            request: Request::builder().method(method).uri(path),
            body: Bytes::new(),
        }
    }
    /// Sends a streaming body without buffering it. The response body also streams.
    pub async fn execute<B>(&self, mut request: Request<B>) -> Result<Response, Error>
    where
        B: Body<Data = Bytes> + Send + 'static,
        B::Error: Into<Error>,
    {
        if request.uri().scheme().is_some()
            || request.uri().authority().is_some()
            || !request.uri().path().starts_with('/')
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "use an origin-relative path; the transport pins one remote peer",
            )
            .into());
        }
        request
            .headers_mut()
            .entry(http::header::HOST)
            .or_insert(self.authority.parse()?);
        // One request per stream avoids HTTP connection-level head-of-line blocking.
        request.headers_mut().insert(
            http::header::CONNECTION,
            http::HeaderValue::from_static("close"),
        );
        let response = tokio::time::timeout(self.timeout, async {
            let stream = self.client.connection().open_bi().await?;
            let (mut sender, driver) = http1::handshake(TokioIo::new(stream)).await?;
            tokio::spawn(async move {
                if let Err(error) = driver.await {
                    tracing::debug!(%error,"HTTP client stream closed");
                }
            });
            sender
                .send_request(request)
                .await
                .map_err(Into::<Error>::into)
        })
        .await??;
        Ok(Response {
            inner: response,
            timeout: self.timeout,
        })
    }
}

pub struct RequestBuilder {
    client: HttpClient,
    request: http::request::Builder,
    body: Bytes,
}
impl RequestBuilder {
    pub fn header(mut self, name: &str, value: &str) -> Self {
        self.request = self.request.header(name, value);
        self
    }
    pub fn body(mut self, body: impl Into<Bytes>) -> Self {
        self.body = body.into();
        self
    }
    pub async fn send(self) -> Result<Response, Error> {
        let request = self.request.body(Full::new(self.body))?;
        self.client.execute(request).await
    }
}

pub struct Response {
    inner: http::Response<Incoming>,
    timeout: Duration,
}
impl Response {
    pub fn status(&self) -> StatusCode {
        self.inner.status()
    }
    pub fn headers(&self) -> &HeaderMap {
        self.inner.headers()
    }
    /// Access the streaming response directly, without the convenience buffering limit.
    pub fn into_inner(self) -> http::Response<Incoming> {
        self.inner
    }
    /// Buffers at most 8 MiB, with a total body-read timeout.
    pub async fn bytes(self) -> Result<Bytes, Error> {
        self.bytes_with_limit(8 * 1024 * 1024).await
    }
    pub async fn bytes_with_limit(self, limit: usize) -> Result<Bytes, Error> {
        Ok(tokio::time::timeout(
            self.timeout,
            Limited::new(self.inner.into_body(), limit).collect(),
        )
        .await??
        .to_bytes())
    }
    pub async fn text(self) -> Result<String, Error> {
        Ok(String::from_utf8(self.bytes().await?.to_vec())?)
    }
}

/// Managed loopback byte-stream bridge for unmodified reqwest or ureq clients.
/// Each accepted TCP connection opens a stream to the already pinned peer.
/// Keep this object alive for as long as the HTTP client is in use.
pub struct ReqwestBridge {
    address: SocketAddr,
    task: JoinHandle<()>,
}
impl ReqwestBridge {
    pub fn local_addr(&self) -> SocketAddr {
        self.address
    }
    pub fn base_url(&self) -> String {
        format!("http://{}", self.address)
    }
}
impl Drop for ReqwestBridge {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl Client {
    pub async fn reqwest_bridge(&self) -> Result<ReqwestBridge, Error> {
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let address = listener.local_addr()?;
        let connection = self.connection().clone();
        let task = tokio::spawn(async move {
            let mut tasks = JoinSet::new();
            loop {
                tokio::select! {
                    accepted=listener.accept()=>match accepted {
                        Ok((mut tcp,_))=>{
                            let connection=connection.clone();
                            // Bound the local bridge's concurrency and handshake wait.
                            if tasks.len()>=64 {continue;}
                            tasks.spawn(async move {
                                if let Ok(Ok(mut stream))=tokio::time::timeout(Duration::from_secs(10),connection.open_bi()).await {
                                    let _=tokio::time::timeout(Duration::from_secs(300),copy_bidirectional(&mut tcp,&mut stream)).await;
                                    let _=stream.shutdown().await;
                                }
                            });
                        }
                        Err(_)=>break,
                    },
                    _=connection.closed()=>break,
                    Some(_)=tasks.join_next(),if !tasks.is_empty()=>{},
                }
            }
        });
        Ok(ReqwestBridge { address, task })
    }
}
