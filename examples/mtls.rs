use std::io;
use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use kwack::{Error, Identity, Verifier};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    tokio::time::timeout(Duration::from_secs(5), exchange()).await?
}

async fn exchange() -> Result<(), Error> {
    let server_identity = generate_identity()?;
    let client_identity = generate_identity()?;
    let client_verifier = Arc::new(Verifier::new([client_identity.public_key_base64()])?);
    let server_verifier = Arc::new(Verifier::new([server_identity.public_key_base64()])?);
    let (server_chain, server_key) = server_identity.into_rustls();
    let (client_chain, client_key) = client_identity.into_rustls();

    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let versions = &[&rustls::version::TLS13];
    let mut server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(versions)?
        .with_client_cert_verifier(client_verifier)
        .with_single_cert(server_chain, server_key)?;
    let mut client_tls = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(versions)?
        .dangerous()
        .with_custom_certificate_verifier(server_verifier)
        .with_client_auth_cert(client_chain, client_key)?;
    server_tls.alpn_protocols = vec![b"kwack-example".to_vec()];
    client_tls.alpn_protocols = server_tls.alpn_protocols.clone();

    let server = quinn::Endpoint::server(
        quinn::ServerConfig::with_crypto(Arc::new(QuicServerConfig::try_from(server_tls)?)),
        "127.0.0.1:0".parse()?,
    )?;
    let mut client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
        QuicClientConfig::try_from(client_tls)?,
    )));

    let connecting = client.connect(server.local_addr()?, "a")?;
    let accept = async {
        let incoming = server.accept().await.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "server stopped accepting connections",
            )
        })?;
        incoming.await.map_err(Error::from)
    };
    let (outbound, inbound) = tokio::try_join!(async { Ok(connecting.await?) }, accept)?;

    let mut send = outbound.open_uni().await?;
    send.write_all(b"hello over mutual TLS").await?;
    send.finish()?;
    let message = inbound.accept_uni().await?.read_to_end(1024).await?;
    println!("{}", String::from_utf8(message)?);
    Ok(())
}

fn generate_identity() -> Result<Identity, Error> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    Identity::from_private_key(&STANDARD.encode(key.serialized_der()))
}
