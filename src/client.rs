//! Reqwest clients with HTTP/3 and optional Ed25519 client identity and server admission.

use std::sync::Arc;

use ::reqwest::{Client, ClientBuilder};

use crate::{Error, Identity, PeerAuthorizer, Verifier};

/// Builds a reqwest client with an optional private key and server admission policy.
///
/// Select HTTP/3 on each request with `.version(reqwest::Version::HTTP_3)`.
/// For a server using a kwack-generated certificate, use `https://a` as the
/// origin. Use [`client_builder`] to override where that name resolves.
pub fn client(
    private_key: Option<&str>,
    authorize_server: Option<PeerAuthorizer>,
) -> Result<Client, Error> {
    Ok(client_builder(private_key, authorize_server)?.build()?)
}

/// Prepares the same client with room for reqwest settings such as
/// a DNS override or a request timeout.
/// See [`Verifier`] for the security implications of passing no admission policy.
pub fn client_builder(
    private_key: Option<&str>,
    authorize_server: Option<PeerAuthorizer>,
) -> Result<ClientBuilder, Error> {
    let require_fresh_authorization = authorize_server.is_some();
    let verifier = Arc::new(Verifier::new(authorize_server));
    let builder = rustls::ClientConfig::builder_with_provider(Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])?
    .dangerous()
    .with_custom_certificate_verifier(verifier);
    let mut tls = if let Some(private_key) = private_key {
        let (chain, key) = Identity::from_private_key(private_key)?.into_rustls();
        builder.with_client_auth_cert(chain, key)?
    } else {
        builder.with_no_client_auth()
    };
    tls.alpn_protocols = vec![b"h3".to_vec()];
    if require_fresh_authorization {
        tls.resumption = rustls::client::Resumption::disabled();
    }

    Ok(Client::builder()
        .use_preconfigured_tls(tls)
        .http3_prior_knowledge()
        .https_only(true)
        .no_proxy())
}
