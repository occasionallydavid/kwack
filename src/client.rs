use std::io;
use std::time::Duration;

use bytes::Bytes;
use http::{HeaderMap, Method, Request, StatusCode};
use http_body_util::{BodyExt, Full, Limited};
use hyper::body::{Body, Incoming};
use hyper::client::conn::http1;
use hyper_util::rt::TokioIo;

use crate::{Client, Error};

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
