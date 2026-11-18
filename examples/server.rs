use std::env;
use std::sync::Arc;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::post;
use kwack::{Error, Identity, Verifier};
use quinn::crypto::rustls::QuicServerConfig;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let mut args = env::args().skip(1);
    let usage = "usage: KWACK_PRIVATE_KEY=... server BIND_ADDRESS CLIENT_PUBLIC_KEY [CLIENT_PUBLIC_KEY ...]";
    let bind = args.next().ok_or(usage)?.parse()?;
    let allowed_clients: Vec<_> = args.collect();
    if allowed_clients.is_empty() {
        return Err(usage.into());
    }

    let (chain, key) = Identity::from_private_key(&env::var("KWACK_PRIVATE_KEY")?)?.into_rustls();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(Verifier::new(allowed_clients)?))
        .with_single_cert(chain, key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];

    let config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    let endpoint = quinn::Endpoint::server(config, bind)?;
    let app = Router::new()
        .route("/echo", post(echo))
        .layer(DefaultBodyLimit::max(1024));

    println!("listening on {}", endpoint.local_addr()?);
    while let Some(incoming) = endpoint.accept().await {
        let app = app.clone();
        tokio::spawn(async move {
            if let Err(error) = serve(app, incoming).await {
                eprintln!("connection failed: {error}");
            }
        });
    }
    Ok(())
}

async fn serve(app: Router, incoming: quinn::Incoming) -> Result<(), Error> {
    let quic = incoming.await?;
    let connection = h3::server::Connection::new(h3_quinn::Connection::new(quic)).await?;
    h3_axum::serve_h3_connection_with_axum(app, connection).await
}

async fn echo(body: String) -> String {
    body
}
