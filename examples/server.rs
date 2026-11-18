use std::sync::Arc;
use std::time::Duration;
use std::{env, io};

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
    tls.alpn_protocols = vec![b"kwack-example".to_vec()];

    let config = quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(tls)?));
    let endpoint = quinn::Endpoint::server(config, bind)?;
    println!("listening on {}", endpoint.local_addr()?);
    while let Some(incoming) = endpoint.accept().await {
        match tokio::time::timeout(Duration::from_secs(5), echo(incoming)).await {
            Ok(Ok(())) => {}
            Ok(Err(error)) => eprintln!("connection failed: {error}"),
            Err(_) => eprintln!("connection timed out"),
        }
    }
    Ok(())
}

async fn echo(incoming: quinn::Incoming) -> Result<(), Error> {
    let connection = incoming.await?;
    let (mut send, mut recv) = connection.accept_bi().await?;
    let message = recv.read_to_end(1024).await?;
    send.write_all(&message).await?;
    send.finish()?;
    if send.stopped().await?.is_some() {
        return Err(io::Error::new(io::ErrorKind::BrokenPipe, "client stopped reading").into());
    }
    Ok(())
}
