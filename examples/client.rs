use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use kwack::{Error, Identity, Verifier};
use quinn::crypto::rustls::QuicClientConfig;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    tokio::time::timeout(Duration::from_secs(5), exchange()).await?
}

async fn exchange() -> Result<(), Error> {
    let mut args = env::args().skip(1);
    let usage = "usage: KWACK_PRIVATE_KEY=... client SERVER_ADDRESS SERVER_PUBLIC_KEY [MESSAGE]";
    let server: SocketAddr = args.next().ok_or(usage)?.parse()?;
    let server_public = args.next().ok_or(usage)?;
    let message = args
        .next()
        .unwrap_or_else(|| "hello over mutual TLS".into());
    if args.next().is_some() {
        return Err(usage.into());
    }

    let (chain, key) = Identity::from_private_key(&env::var("KWACK_PRIVATE_KEY")?)?.into_rustls();
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let mut tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Verifier::new([server_public])?))
        .with_client_auth_cert(chain, key)?;
    tls.alpn_protocols = vec![b"kwack-example".to_vec()];

    let bind = if server.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let mut endpoint = quinn::Endpoint::client(bind.parse()?)?;
    endpoint.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(tls)?,
    )));
    let connection = endpoint.connect(server, "a")?.await?;
    let (mut send, mut recv) = connection.open_bi().await?;
    send.write_all(message.as_bytes()).await?;
    send.finish()?;
    let reply = recv.read_to_end(1024).await?;
    println!("{}", String::from_utf8(reply)?);
    connection.close(0u32.into(), b"done");
    endpoint.wait_idle().await;
    Ok(())
}
