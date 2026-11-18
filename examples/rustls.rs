//! Build client and server configurations for mutual TLS with rustls.
//!
//! Run with `cargo run --example rustls`. To use the configurations with
//! Quinn, convert them with `QuicClientConfig::try_from` and
//! `QuicServerConfig::try_from`. Use `a` as the server name when connecting.

use std::sync::Arc;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use kwack::{Error, Identity, Verifier};
use rcgen::{KeyPair, PKCS_ED25519};

fn main() -> Result<(), Error> {
    let client = KeyPair::generate_for(&PKCS_ED25519)?;
    let server = KeyPair::generate_for(&PKCS_ED25519)?;

    let (_client, _server) = tls_configs(
        &STANDARD.encode(client.serialize_der()),
        &STANDARD.encode(server.serialize_der()),
        client.public_key_raw().try_into()?,
        server.public_key_raw().try_into()?,
    )?;
    println!("Built rustls client and server configurations for mutual TLS.");
    Ok(())
}

fn tls_configs(
    client_private: &str,
    server_private: &str,
    allowed_client: [u8; 32],
    allowed_server: [u8; 32],
) -> Result<(rustls::ClientConfig, rustls::ServerConfig), Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (client_chain, client_key) = Identity::from_private_key(client_private)?.into_rustls();
    let (server_chain, server_key) = Identity::from_private_key(server_private)?.into_rustls();

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
