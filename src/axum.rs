//! Serve an Axum router over HTTP/3 with an Ed25519 client allowlist.

use std::io;
use std::net::SocketAddr;
use std::sync::Arc;

use ::axum::{Extension, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use quinn::crypto::rustls::QuicServerConfig;
use rustls::pki_types::CertificateDer;
use tokio::task::JoinSet;
use webpki::EndEntityCert;

use crate::{Error, Identity, Verifier, invalid_cert, leaf_public_key};

/// The authenticated client's Ed25519 public key. Extract it in a handler as
/// `axum::Extension<kwack::axum::PeerIdentity>`.
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

/// Configures an HTTP/3 server for an Axum router. Call [`Server::bind`] with
/// the UDP address, then [`Listener::run`] to begin accepting requests.
pub fn serve(
    router: Router,
    private_key: &str,
    accepted_keys: &[impl AsRef<str>],
) -> Result<Server, Error> {
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
    Ok(Server { router, config })
}

/// An HTTP/3 server configured with a router and mTLS.
pub struct Server {
    router: Router,
    config: quinn::ServerConfig,
}

impl Server {
    /// Binds the UDP address from inside a Tokio runtime.
    pub fn bind(self, address: SocketAddr) -> Result<Listener, Error> {
        Ok(Listener {
            router: self.router,
            endpoint: quinn::Endpoint::server(self.config, address)?,
        })
    }
}

/// A bound HTTP/3 listener.
pub struct Listener {
    router: Router,
    endpoint: quinn::Endpoint,
}

impl Listener {
    /// Returns the bound UDP socket address.
    pub fn local_addr(&self) -> io::Result<SocketAddr> {
        self.endpoint.local_addr()
    }

    /// Serves until the listener closes or the future is cancelled.
    pub async fn run(self) {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                incoming = self.endpoint.accept() => {
                    let Some(incoming) = incoming else { break };
                    let router = self.router.clone();
                    connections.spawn(async move {
                        // Connection and stream failures are local to the peer.
                        let _ = serve_connection(router, incoming).await;
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    }
}

async fn serve_connection(router: Router, incoming: quinn::Incoming) -> Result<(), Error> {
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
    let router = router.layer(Extension(identity));
    let connection = h3::server::Connection::new(h3_quinn::Connection::new(quic)).await?;
    h3_axum::serve_h3_connection_with_axum(router, connection).await
}
