# kwack

## Why?

We want to use software that expects X.509 without a doctorate in certificate
management. If you already know which peers you want to trust, an Ed25519
public key can be their identity. Give each peer its own private key and a list
of the public keys it should accept. Kwack makes those keys work with mutual
TLS:

- `Identity` takes a base64 Ed25519 private key and generates a deterministic
  self-signed X.509 certificate. It accepts a raw 32-byte seed or PKCS #8 DER.
- `Verifier` plugs into rustls on either side of the handshake. A peer gets
  in when its key passes your admission policy and it proves it holds the
  private key.
- The optional Tower server puts the authenticated key in each request as
  `PeerIdentity`. Your service can use it to decide who can do what.
- The optional reqwest helper builds an HTTP/3 mTLS client from its private
  key and the server public keys it trusts.

## Certificate and key formats

Use standard padded base64. Ed25519 is a signing key format and is distinct
from the X25519 keys used by WireGuard. `PeerIdentity::from_public_key_base64`
accepts raw 32-byte public keys or SubjectPublicKeyInfo DER.

The generated certificate has DNS name `a` and fixed validity from
2000-01-01 to 2049-01-01 UTC. The same key produces the same certificate with
the same generation profile. A certificate can also be exported as base64 DER
with `certificate_base64()`.

The verifier checks certificate signatures, validity dates, and TLS purpose.
When verifying a server it also checks the requested name against the SAN.

`Verifier::new` takes an optional `PeerAuthorizer`, a boxed
`Fn(PeerIdentity) -> bool + Send + Sync`. The callback can compare a single
key or consult shared policy state. Returning `false` rejects the handshake.
On the server, `None` accepts any valid self-signed Ed25519 client certificate
and allows anonymous clients. On the client, `None` accepts any valid
self-signed Ed25519 server certificate for the requested name. Use an explicit
server admission policy to verify that you're connecting to the intended peer.

The HTTP/3 helpers disable TLS resumption when a callback is configured,
so a new connection checks the current policy. Changes to your policy apply
to new handshakes. An existing connection keeps its authenticated identity.

## Optional HTTP/3 helpers

Enable the `reqwest` feature for `kwack::client::client(private_key, authorize_server)`.
Use `Some(private_key)` to present a client certificate or `None` to connect
anonymously. Select HTTP/3 with
`.version(reqwest::Version::HTTP_3)` on the request. The `client_builder` variant
lets you set a timeout or map the generated server name `a` to a socket address.

Enable `server` for
`kwack::server::serve(service, private_key, authorize_client)?.bind(addr)?.run().await`.
Pass a Tower service that accepts `http::Request<kwack::server::RequestBody>`
and returns an HTTP response with a byte body. An identified client request
carries its authenticated key in `request.extensions().get::<PeerIdentity>()`.

The `axum` feature implies `server` and adds a direct `PeerIdentity` extractor
for Axum handlers. An Axum router is a Tower service, so the same `serve`
function accepts it. Use `peer: PeerIdentity` to require an identity and
return HTTP 401 when absent, or `peer: Option<PeerIdentity>` to also handle
anonymous requests. You can also read the extension with
`axum::Extension<PeerIdentity>`.

Reqwest requires the compiler flag `--cfg reqwest_unstable` for HTTP/3.
This repository sets it in `.cargo/config.toml`. Set it in your application's
Cargo config or `RUSTFLAGS` when enabling kwack's `reqwest` feature.

## Run the examples

The server takes a private key, a UDP bind address, and optional client public
keys. The client takes a private key, a server address, the server's public
key, and an optional message to send to `POST /echo`. To try an anonymous
request, start the server with no client public keys and pass `-` as the
client private key. The client then sends the message to `POST /optional-echo`.
`keygen` prints `PRIVATE_KEY="..."` and `PUBLIC_KEY="..."` with base64 values.

```bash
mapfile -t server_keys < <(cargo run --quiet --example keygen | cut -d '"' -f 2)
mapfile -t client_keys < <(cargo run --quiet --example keygen | cut -d '"' -f 2)

cargo run --quiet --features axum --example server -- \
  "${server_keys[0]}" 127.0.0.1:4433 "${client_keys[1]}" &
server_pid=$!
# Wait for the server to print its listening address before running the client.
cargo run --quiet --features reqwest --example client -- \
  "${client_keys[0]}" 127.0.0.1:4433 "${server_keys[1]}"
kill "$server_pid"
```

These examples accept private keys on the command line. Use disposable keys
because command lines can be visible to other processes.

## Use with rustls

The example uses rustls with its `ring` feature. Kwack's library API only
depends on rustls for the types and verifier traits. Quinn owns the transport.
Convert the resulting TLS configurations with `QuicClientConfig::try_from`
and `QuicServerConfig::try_from` when using quinn.

```rust
use std::sync::Arc;
use kwack::{Identity, PeerIdentity, Verifier};

fn tls_configs(
    client_private: &str,
    server_private: &str,
    allowed_client: PeerIdentity,
    allowed_server: PeerIdentity,
) -> Result<(rustls::ClientConfig, rustls::ServerConfig), kwack::Error> {
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let (client_chain, client_key) = Identity::from_private_key(client_private)?.into_rustls();
    let (server_chain, server_key) = Identity::from_private_key(server_private)?.into_rustls();

    let mut client = rustls::ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Verifier::new(Some(Box::new(
            move |peer| peer == allowed_server,
        )))))
        .with_client_auth_cert(client_chain, client_key)?;

    let mut server = rustls::ServerConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .with_client_cert_verifier(Arc::new(Verifier::new(Some(Box::new(
            move |peer| peer == allowed_client,
        )))))
        .with_single_cert(server_chain, server_key)?;

    client.alpn_protocols = vec![b"my-app".to_vec()];
    server.alpn_protocols = client.alpn_protocols.clone();
    client.resumption = rustls::client::Resumption::disabled();
    server.send_tls13_tickets = 0;
    Ok((client, server))
}
```

When connecting to a server using the generated certificate, pass `"a"` as
quinn's server name. It can be different from the host's DNS name or address.
