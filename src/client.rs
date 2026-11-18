//! Reqwest clients with HTTP/3 mutual TLS and an Ed25519 server allowlist.

use std::sync::Arc;

use ::reqwest::{Client, ClientBuilder};

use crate::{Error, Identity, Verifier};

/// Builds a reqwest client with the supplied private key and accepted server keys.
///
/// Select HTTP/3 on each request with `.version(reqwest::Version::HTTP_3)`.
/// For a server using a kwack-generated certificate, use `https://a` as the
/// origin. Use [`client_builder`] to override where that name resolves.
pub fn client(private_key: &str, accepted_keys: &[impl AsRef<str>]) -> Result<Client, Error> {
    Ok(client_builder(private_key, accepted_keys)?.build()?)
}

/// Prepares the same mTLS client with room for reqwest settings such as
/// a DNS override or a request timeout.
pub fn client_builder(
    private_key: &str,
    accepted_keys: &[impl AsRef<str>],
) -> Result<ClientBuilder, Error> {
    let (chain, key) = Identity::from_private_key(private_key)?.into_rustls();
    let verifier = Arc::new(Verifier::new(accepted_keys)?);
    let mut tls = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .dangerous()
    .with_custom_certificate_verifier(verifier)
    .with_client_auth_cert(chain, key)?;
    tls.alpn_protocols = vec![b"h3".to_vec()];

    Ok(Client::builder()
        .use_preconfigured_tls(tls)
        .http3_prior_knowledge()
        .https_only(true)
        .no_proxy())
}
