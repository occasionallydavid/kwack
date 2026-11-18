# kwack

Two helpers for Ed25519 mutual TLS with rustls and quinn.

- `Identity` takes a base64 Ed25519 private key and generates a deterministic
  self-signed X.509 certificate. It accepts a raw 32-byte seed or PKCS #8 DER.
- `Verifier` takes an allowlist of base64 Ed25519 public keys. It accepts raw
  32-byte keys or SubjectPublicKeyInfo DER and implements both rustls verifier
  traits. An empty list denies every peer.

Use standard padded base64. Ed25519 is a signing key format and is distinct
from the X25519 keys used by WireGuard.

The generated certificate has DNS name `a` and fixed validity from
2000-01-01 to 2049-01-01 UTC. The same key produces the same certificate with
the same generation profile. A certificate can also be exported as base64 DER
with `certificate_base64()`.

A peer must present a self-signed Ed25519 leaf whose public key is in the
allowlist and prove possession of the private key in TLS. The verifier checks
certificate signatures, validity dates, and TLS purpose. Server verification
also checks the supplied name against the SAN. To revoke a pin, replace the
verifier and close any existing sessions for that key.

## Run the examples

- `cargo run --example mtls` starts a client and server on loopback with freshly
  generated keys, authenticates both peers with public-key pins, and sends a
  message over a QUIC stream.
- `cargo run --example keygen` prints a new base64 PKCS #8 private key, its raw
  public key, and its certificate. The first line is secret.

## Use with rustls

The example uses rustls with its `ring` feature. Kwack's library API only
depends on rustls for the types and verifier traits. Quinn owns the transport.
Convert the resulting TLS configurations with `QuicClientConfig::try_from`
and `QuicServerConfig::try_from` when using quinn.

```rust
use std::sync::Arc;
use kwack::{Identity, Verifier};

fn tls_configs(
    client_private: &str,
    server_private: &str,
    allowed_clients: &[String],
    allowed_servers: &[String],
) -> Result<(rustls::ClientConfig, rustls::ServerConfig), kwack::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (client_chain, client_key) = Identity::from_private_key(client_private)?.into_rustls();
    let (server_chain, server_key) = Identity::from_private_key(server_private)?.into_rustls();

    let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Verifier::new(allowed_servers)?))
        .with_client_auth_cert(client_chain, client_key)?;

    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(Verifier::new(allowed_clients)?))
        .with_single_cert(server_chain, server_key)?;

    client.alpn_protocols = vec![b"my-app".to_vec()];
    server.alpn_protocols = client.alpn_protocols.clone();
    Ok((client, server))
}
```

When connecting to a server using the generated certificate, pass `"a"` as
quinn's server name. It can be different from the host's DNS name or address.
