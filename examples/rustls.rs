//! Build client and server configurations for mutual TLS with rustls.
//!
//! Run with `cargo run --example rustls`. To use the configurations with
//! Quinn, convert them with `QuicClientConfig::try_from` and
//! `QuicServerConfig::try_from`. Use `a` as the server name when connecting.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use kwack::{Error, Identity, Verifier};

mod support;

fn main() -> Result<(), Error> {
    let mut seeds = [0; 64];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut seeds)
        .map_err(|_| std::io::Error::other("could not generate Ed25519 seeds"))?;
    let client = Identity::from_private_key(&STANDARD.encode(&seeds[..32]))?;
    let server = Identity::from_private_key(&STANDARD.encode(&seeds[32..]))?;

    let (_client, _server) = tls_configs(client, server)?;
    println!("Built rustls client and server configurations for mutual TLS.");
    Ok(())
}

fn tls_configs(
    client: Identity,
    server: Identity,
) -> Result<(rustls::ClientConfig, rustls::ServerConfig), Error> {
    let allowed_client = support::parse_public_key(&client.public_key_base64())?;
    let allowed_server = support::parse_public_key(&server.public_key_base64())?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (client_chain, client_key) = client.into_rustls();
    let (server_chain, server_key) = server.into_rustls();

    let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Verifier::new(Some(Box::new(move |peer| {
            peer.raw() == allowed_server
        })))))
        .with_client_auth_cert(client_chain, client_key)?;

    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(Verifier::new(Some(Box::new(move |peer| {
            peer.raw() == allowed_client
        })))))
        .with_single_cert(server_chain, server_key)?;

    client.alpn_protocols = vec![b"my-app".to_vec()];
    server.alpn_protocols = client.alpn_protocols.clone();
    client.resumption = rustls::client::Resumption::disabled();
    server.send_tls13_tickets = 0;
    Ok((client, server))
}
