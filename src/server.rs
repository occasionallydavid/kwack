//! Serve a Tower service over HTTP/3 with an Ed25519 client allowlist.

use std::io;
use std::net::SocketAddr;
use std::pin::{Pin, pin};
use std::sync::Arc;
use std::task::{Context, Poll, ready};

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
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

use crate::{Error, Identity, Verifier, invalid_cert, leaf_public_key};

/// The authenticated client's Ed25519 public key in the HTTP request extensions.
/// With the `axum` feature, handlers can take it as a direct extractor or
/// as `axum::Extension<kwack::server::PeerIdentity>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct PeerIdentity([u8; 32]);

impl PeerIdentity {
    /// Returns the raw Ed25519 public key.
    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }

    /// Returns the public key in the same format as a kwack allowlist entry.
    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(self.0)
    }
}

#[cfg(feature = "axum")]
impl<S: Send + Sync> axum::extract::FromRequestParts<S> for PeerIdentity {
    type Rejection = axum::extract::rejection::ExtensionRejection;

    async fn from_request_parts(
        parts: &mut http::request::Parts,
        state: &S,
    ) -> Result<Self, Self::Rejection> {
        let axum::Extension(peer) = axum::Extension::from_request_parts(parts, state).await?;
        Ok(peer)
    }
}

/// Configures a Tower service for HTTP/3 mTLS. Call [`Server::bind`] with
/// the UDP address, then [`Listener::run`] to begin accepting requests.
pub fn serve<S, B>(
    service: S,
    private_key: &str,
    accepted_keys: &[impl AsRef<str>],
) -> Result<Server<S>, Error>
where
    S: Service<Request<RequestBody>, Response = Response<B>> + Clone + Send + 'static,
    S::Future: Send,
    S::Error: Into<Error>,
    B: Body<Data = Bytes> + Send + 'static,
    B::Error: Into<Error>,
{
    let (chain, key) = Identity::from_private_key(private_key)?.into_rustls();
    let verifier = Arc::new(Verifier::new(accepted_keys)?);
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .with_client_cert_verifier(verifier)
    .with_single_cert(chain, key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    Ok(Server { service, config })
}

/// An HTTP/3 server configured with a Tower service and mTLS.
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
    let chain = quic
        .peer_identity()
        .and_then(|identity| identity.downcast::<Vec<CertificateDer<'static>>>().ok())
        .ok_or_else(|| {
            io::Error::new(io::ErrorKind::PermissionDenied, "missing TLS peer identity")
        })?;
    let [certificate] = chain.as_slice() else {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "expected one peer certificate",
        )
        .into());
    };
    let leaf = EndEntityCert::try_from(certificate).map_err(invalid_cert)?;
    let identity = PeerIdentity(leaf_public_key(&leaf).map_err(rustls::Error::from)?);
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
                        request.extensions_mut().insert(identity);
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
