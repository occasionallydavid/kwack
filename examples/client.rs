use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use kwack::{Error, Identity, Verifier};

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
    tls.alpn_protocols = vec![b"h3".to_vec()];

    // Resolve the certificate's DNS name to the user-supplied UDP endpoint.
    let client = reqwest::Client::builder()
        .use_preconfigured_tls(tls)
        .http3_prior_knowledge()
        .no_proxy()
        .resolve("a", server)
        .build()?;
    let reply = client
        .post(format!("https://a:{}/echo", server.port()))
        .version(reqwest::Version::HTTP_3)
        .header(reqwest::header::CONTENT_TYPE, "text/plain; charset=utf-8")
        .body(message)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    println!("{reply}");
    Ok(())
}
