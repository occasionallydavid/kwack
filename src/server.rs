//! Serve a Tower service over HTTP/3 with optional Ed25519 client authorization.

#[cfg(feature = "axum")]
use std::convert::Infallible;
use std::io;
use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use bytes::{Buf, Bytes};
use h3::error::{Code, StreamError};
use h3::server::RequestStream;
use http::{Request, Response};
use http_body::{Body, Frame};
use http_body_util::BodyExt;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::CertificateDer;
use tokio::task::JoinSet;
use tower::{Service, ServiceExt};
use webpki::EndEntityCert;

use crate::{Error, Identity, PeerAuthorizer, PublicKey, Verifier, invalid_cert, leaf_public_key};

#[cfg(feature = "axum")]
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PublicKey {
    type Rejection = http::StatusCode;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Self, Self::Rejection> {
        parts
            .extensions
            .get::<Self>()
            .copied()
            .ok_or(http::StatusCode::UNAUTHORIZED)
    }
}

#[cfg(feature = "axum")]
impl<S: Send + Sync> axum::extract::OptionalFromRequestParts<S> for PublicKey {
    type Rejection = Infallible;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        _state: &S,
    ) -> Result<Option<Self>, Self::Rejection> {
        Ok(parts.extensions.get::<Self>().copied())
    }
}

/// Configures a Tower service for HTTP/3. Call [`Server::bind`] with
/// the UDP address, then [`Listener::run`] to begin accepting requests.
/// With `None`, clients can connect anonymously or present a valid certificate.
/// With a callback, clients must present a valid certificate with an admitted key.
pub fn serve<S, B>(
    service: S,
    private_key: &str,
    authorize_client: Option<PeerAuthorizer>,
) -> Result<Server<S>, Error>
where
    S: Service<Request<RequestBody>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<Error>,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Error>,
{
    let (chain, key) = Identity::from_private_key(private_key)?.into_rustls();
    let require_fresh_authorization = authorize_client.is_some();
    let verifier = Arc::new(Verifier::new(authorize_client));
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_client_cert_verifier(verifier)
    .with_single_cert(chain, key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];
    if require_fresh_authorization {
        tls.send_tls13_tickets = 0;
    }

    let config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    Ok(Server { service, config })
}

/// An HTTP/3 server configured with a Tower service and TLS.
pub struct Server<S> {
    service: S,
    config: quinn::ServerConfig,
}

impl<S> Server<S> {
    /// Binds the UDP address from inside a Tokio runtime.
    pub fn bind(self, address: SocketAddr) -> Result<Listener<S>, Error> {
        Ok(Listener {
            service: self.service,
            endpoint: quinn::Endpoint::server(self.config, address)?,
        })
    }
}

/// A bound HTTP/3 listener.
pub struct Listener<S> {
    service: S,
    endpoint: quinn::Endpoint,
}

impl<S> Listener<S> {
    /// Returns the bound UDP socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }
}

impl<S, B> Listener<S>
where
    S: Service<Request<RequestBody>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<Error>,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Error>,
{
    /// Serves until the listener closes or the future is cancelled.
    pub async fn run(self) {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    let service = self.service.clone();
                    connections.spawn(async move {
                        // Connection and stream failures are local to the peer.
                        let _ = serve_connection(service, incoming).await;
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    }
}

async fn serve_connection<S, B>(service: S, incoming: quinn::Incoming) -> Result<(), Error>
where
    S: Service<Request<RequestBody>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<Error>,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Error>,
{
    let quic = incoming.await?;
    let identity = peer_identity(&quic)?;
    let mut connection = h3::server::Connection::new(h3_quinn::Connection::new(quic)).await?;
    let mut requests = JoinSet::new();
    loop {
        tokio::select! {
            accepted = connection.accept() => {
                let Some(resolver) = accepted? else { break };
                let service = service.clone();
                requests.spawn(async move {
                    if let Ok((request, stream)) = resolver.resolve_request().await {
                        let (mut send, recv) = stream.split();
                        let mut request = request.map(|()| RequestBody {
                            stream: recv,
                            receiving: Receiving::Data,
                        });
                        if let Some(identity) = identity {
                            request.extensions_mut().insert(identity);
                        }
                        if respond(service, request, &mut send).await.is_err() {
                            send.stop_stream(Code::H3_INTERNAL_ERROR);
                        }
                    }
                });
            }
            _ = requests.join_next(), if !requests.is_empty() => {}
        }
    }
    while requests.join_next().await.is_some() {}
    Ok(())
}

fn peer_identity(quic: &quinn::Connection) -> Result<Option<PublicKey>, Error> {
    let Some(identity) = quic.peer_identity() else {
        return Ok(None);
    };
    let chain = identity
        .downcast::<Vec<CertificateDer<'static>>>()
        .map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "unexpected TLS peer identity"))?;
    let [certificate] = chain.as_slice() else {
        return Err(
            io::Error::new(io::ErrorKind::InvalidData, "expected one peer certificate").into(),
        );
    };
    let leaf = EndEntityCert::try_from(certificate).map_err(invalid_cert)?;
    Ok(Some(leaf_public_key(&leaf).map_err(rustls::Error::from)?))
}

async fn respond<S, B>(
    service: S,
    request: Request<RequestBody>,
    send: &mut RequestStream<h3_quinn::SendStream<Bytes>, Bytes>,
) -> Result<(), Error>
where
    S: Service<Request<RequestBody>, Response = Response<B>>,
    S::Error: Into<Error>,
    B: Body<Data = Bytes>,
    B::Error: Into<Error>,
{
    let (parts, body) = service
        .oneshot(request)
        .await
        .map_err(Into::into)?
        .into_parts();
    send.send_response(Response::from_parts(parts, ())).await?;
    let mut body = pin!(body);
    loop {
        let frame = body.frame().await.transpose().map_err(Into::into)?;
        let Some(frame) = frame else { break };
        match frame.into_data() {
            Ok(data) if !data.is_empty() => send.send_data(data).await?,
            Ok(_) => {}
            Err(frame) => {
                if let Ok(trailers) = frame.into_trailers() {
                    send.send_trailers(trailers).await?;
                    break;
                }
            }
        }
    }
    send.finish().await?;
    Ok(())
}

/// The streaming HTTP/3 request body passed to a Tower service.
pub struct RequestBody {
    stream: RequestStream<h3_quinn::RecvStream, Bytes>,
    receiving: Receiving,
}

enum Receiving {
    Data,
    Trailers,
    Done,
}

impl Body for RequestBody {
    type Data = Bytes;
    type Error = StreamError;

    fn poll_frame(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
    ) -> Poll<Option<Result<Frame<Bytes>, StreamError>>> {
        let this = self.get_mut();
        if matches!(this.receiving, Receiving::Data) {
            match ready!(this.stream.poll_recv_data(cx)) {
                Ok(Some(mut data)) => {
                    return Poll::Ready(Some(Ok(Frame::data(
                        data.copy_to_bytes(data.remaining()),
                    ))));
                }
                Ok(None) => this.receiving = Receiving::Trailers,
                Err(error) => {
                    this.receiving = Receiving::Done;
                    return Poll::Ready(Some(Err(error)));
                }
            }
        }

        if matches!(this.receiving, Receiving::Trailers) {
            let trailers = ready!(this.stream.poll_recv_trailers(cx));
            this.receiving = Receiving::Done;
            return Poll::Ready(
                trailers
                    .map(|trailers| trailers.map(Frame::trailers))
                    .transpose(),
            );
        }

        Poll::Ready(None)
    }

    fn is_end_stream(&self) -> bool {
        matches!(self.receiving, Receiving::Done)
    }
}
