#![deny(clippy::unwrap_used, clippy::expect_used)]
use axum::body::Bytes;
use axum::routing::{get, post};
use axum::{Extension, Router};
use wireguard_quic::{Error, PeerIdentity, PrivateKey, PublicKey, Server};

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
        .try_init()?;
    let mut args = std::env::args().skip(1);
    let encoded_private = args
        .next()
        .ok_or("usage: server PRIVATE_KEY AUTHORIZED_PUBLIC_KEY [MORE_KEYS...]")?;
    let private: PrivateKey = encoded_private.parse()?;
    let peers = args
        .map(|key| key.parse::<PublicKey>())
        .collect::<Result<Vec<_>, _>>()?;
    if peers.is_empty() {
        return Err("provide at least one authorized client public key".into());
    }
    let bind = std::env::var("BIND_ADDR").unwrap_or_else(|_| "127.0.0.1:4433".into());
    let server = Server::builder(private)
        .authorized_peers(peers)
        .bind(&bind)
        .await?;
    println!("listening on {}", server.local_addr());
    let mut rejected = server
        .take_rejected()
        .ok_or("rejection receiver already taken")?;
    let observer = tokio::spawn(async move {
        while let Some(packet) = rejected.recv().await {
            tracing::debug!(source=%packet.source,reason=?packet.reason,bytes=packet.data.len(),"rejected UDP datagram");
        }
    });
    let router = Router::new()
        .route("/", get(|| async { "hello over WireGuard–QUIC\n" }))
        .route(
            "/whoami",
            get(|Extension(peer): Extension<PeerIdentity>| async move {
                format!("{}\n", peer.public_key())
            }),
        )
        .route("/echo", post(|body: Bytes| async move { body }));
    let result = server
        .serve_with_shutdown(router, async {
            let _ = tokio::signal::ctrl_c().await;
        })
        .await;
    observer.abort();
    result
}
