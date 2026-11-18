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
  `PublicKey`. Your service can use it to decide who can do what.
- The optional reqwest helper builds an HTTP/3 mTLS client from its private
  key and the server public keys it trusts.

## Certificate and key formats

Use standard padded base64. Ed25519 is a signing key format and is distinct
from the X25519 keys used by WireGuard. `PublicKey::raw()` returns the
32-byte Ed25519 key, and `PublicKey::encoded()` returns its base64 string.

The generated certificate has DNS name `a` and fixed validity from
2000-01-01 to 2049-01-01 UTC. The same key produces the same certificate with
the same generation profile. A certificate can also be exported as base64 DER
with `certificate_base64()`.

The verifier checks certificate signatures, validity dates, and TLS purpose.
When verifying a server it also checks the requested name against the SAN.

`Verifier::new` takes an optional `PeerAuthorizer`, a boxed
`Fn(PublicKey) -> bool + Send + Sync`. The callback can compare a single
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
carries its authenticated key in `request.extensions().get::<PublicKey>()`.

The `axum` feature implies `server` and adds a direct `PublicKey` extractor
for Axum handlers. An Axum router is a Tower service, so the same `serve`
function accepts it. Use `peer: PublicKey` to require an identity and
return HTTP 401 when absent, or `peer: Option<PublicKey>` to also handle
anonymous requests. You can also read the extension with
`axum::Extension<PublicKey>`.

Reqwest requires the compiler flag `--cfg reqwest_unstable` for HTTP/3.
This repository sets it in `.cargo/config.toml`. Set it in your application's
Cargo config or `RUSTFLAGS` when enabling kwack's `reqwest` feature.

## Examples

- [client.rs](examples/client.rs) sends an HTTP/3 request with reqwest.
- [server.rs](examples/server.rs) serves Axum routes with required or optional client identity.
- [rustls.rs](examples/rustls.rs) configures mutual TLS directly in rustls.
- [keygen.rs](examples/keygen.rs) generates a Base64 Ed25519 key pair.
