QUIC streams and HTTP authenticated and encrypted by BoringTun's userspace
WireGuard state machine. One library owns the UDP socket, WireGuard handshakes,
rekeys, and QUIC endpoints. No TUN device, OS routes, or root access is needed.

```text
Axum / HTTP client ↔ HTTP/1.1 ↔ QUIC streams ↔ WireGuard ↔ UDP
```

The server has its own private key and an authorization callback for client
public keys. The client supplies its private key and pins the server public key.
WireGuard provides authentication, encryption, and replay protection. The inner
QUIC implementation provides reliability, congestion control, and independent
streams. Inner QUIC packets carry no additional checksum or authentication tag.
Plaintext QUIC configuration is private to the crate.

## Server API

`serve(service)` accepts a cloneable Tower `Service<Request<hyper::body::Incoming>>`
returning an HTTP response with any sendable body. Axum routers work directly;
plain handlers can use `tower::service_fn`. Axum is only a development dependency
for this crate's examples and tests.

```rust,no_run
# #[cfg(feature = "server")]
# mod example {
use axum::{Extension, Router, routing::get};
use quic_wg::{Error, PeerIdentity, PrivateKey, PublicKey, Server};

# async fn example(server_private: PrivateKey, client_public: PublicKey) -> Result<(), Error> {
let router = Router::new().route("/whoami", get(|Extension(peer): Extension<PeerIdentity>| async move {
    peer.public_key().to_string()
}));
let server = Server::builder(server_private)
    .authorize(Box::new(move |key| key == client_public))
    .bind("0.0.0.0:4433")
    .await?;
let handle = server.handle();
// handle.revoke_peer(client_public).await?;
server.serve(router).await?;
# Ok(())
# }
# }
```

`PeerIdentity` is inserted into request extensions from the authenticated transport
on every HTTP request. Read it through `request.extensions()` or Axum's
`Extension<PeerIdentity>` extractor.
It is never taken from a header or the network address. Each authorized public key
has its own virtual QUIC endpoint, so one peer cannot inject QUIC packets into
another peer's connections. Revocation removes the WireGuard state and closes
that peer's existing QUIC connections and denies it for the server's lifetime.

`authorize(Box::new(|key| ...))` is the only admission interface. The callback runs
on every WireGuard handshake initiation, including rekeys, and may consult shared
mutable state to change admission without rebinding. It runs synchronously on
the UDP dispatcher: use an in-memory lookup, not blocking database or network I/O.
The callback sees a claimed key before full handshake authentication; peer state
is installed only after the handshake authenticates. Returning false affects
subsequent handshakes; call `revoke_peer` to terminate an existing session.
Without a callback the server denies all peers. New peers are created lazily,
with at most 1,024 cached peers per server. A peer with no live QUIC connections
is evicted after 60 seconds and may be admitted again through the callback.
WireGuard keepalives do not extend this idle period.

Use `serve_with_shutdown(router, shutdown_future)` for coordinated shutdown,
or `accept()` / `Connection::accept_bi()` for a custom application protocol.
Streams implement Tokio's `AsyncRead` and `AsyncWrite`. Handshakes are accepted
concurrently with a bound on outstanding accept tasks.

## Client API

```rust,no_run
# #[cfg(feature = "client")]
# mod example {
use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Empty};
use quic_wg::{Client, Error, PrivateKey, PublicKey};
# async fn example(private: PrivateKey, server_key: PublicKey) -> Result<(), Error> {
let client = Client::builder(private)
    .remote("127.0.0.1:4433".parse()?, server_key)
    .connect().await?;
let request = Request::builder()
    .uri("/whoami")
    .header("host", "my-service")
    .body(Empty::<Bytes>::new())?;
let response = client.send(request).await?;
let body = response.into_body().collect().await?.to_bytes();
println!("{}", String::from_utf8(body.to_vec())?);
client.close().await;
# Ok(())
# }
# }
```

`Client::send()` accepts `http::Request<B>` with a streaming body and returns
`http::Response<hyper::body::Incoming>`. Set headers and HTTP routing metadata
such as `Host` using the standard request builder. Requests use origin-relative
paths and stay on the pinned peer. Each request opens a QUIC stream on the
existing connection and sets `Connection: close` for that stream.

Callers control timeouts and body collection, including buffering limits;
`http-body-util` supplies standard body utilities. The client example bounds
both request time and response size. HTTP/1.1 runs directly over QUIC streams;
this is not standard TLS HTTP/3.

Keys parse from WireGuard's standard base64 format. `PrivateKey::generate()` uses
an OS-backed cryptographic RNG. Private-key debug output is redacted. Keys use ordinary byte arrays and base64
exports return ordinary strings.

## Rejected packets and shared-port QUIC

`server.take_rejected()` returns a bounded receiver of `RejectedDatagram` values:

- `data`: untouched outer UDP bytes, including rejected WireGuard ciphertext.
- `source`: original sender address.
- `local_address`: bound socket address; wildcard binds do not expose the exact destination IP.
- `reason`: unrecognized traffic, malformed WireGuard, unauthorized peer, unknown
  session, authentication failure, invalid inner packet, or peer capacity reached.

The feed never exposes decrypted application data. It is suitable for inspection
or mirroring to a separate service. Queue capacity is 256 datagrams; overload
causes drops rather than blocking authenticated traffic.

For a normal QUIC service sharing the **same UDP port**, take the fallback socket:

```rust,ignore
let fallback = server.take_fallback_socket()?;
let ordinary_quic = quinn::Endpoint::new_with_abstract_socket(
    quinn::EndpointConfig::default(),
    Some(your_normal_tls_server_config),
    fallback,
    std::sync::Arc::new(quinn::TokioRuntime),
)?;
```

The dispatcher automatically routes non-WireGuard datagrams to that virtual
socket. Responses leave through the original bound UDP socket, preserving its
port. Recognizable WireGuard packets that fail authentication remain on the
rejection feed and are not automatically passed to the fallback. Only one
fallback socket and one rejection receiver can be taken. Keep the server or its
handle alive while the fallback is in use. Separate `recv_from` loops on the
physical socket are not needed.

## Transport details and compatibility

The crate uses minimal IPv4/UDP envelopes inside WireGuard because BoringTun's
public API validates inner IP packets. These addresses are internal to each peer
namespace and never enter the OS routing table. Authenticated packets may update
a peer's outer address, allowing UDP endpoint roaming. BoringTun timers run every
250 ms and handle handshake retries, keepalives, and rekeys.

Inner QUIC datagrams are capped at 1200 bytes. With the internal IPv4/UDP header
and WireGuard transport overhead, the outer UDP payload is 1260 bytes. The path
must accommodate this plus its outer IP/UDP headers; outer IP fragmentation and
path MTU adaptation are not implemented. UDP segmentation offload is disabled. Unidirectional QUIC streams and QUIC
datagrams are disabled. Each connection has an 8 MiB aggregate receive window,
a 1 MiB per-stream receive window, and an 8 MiB send window. Each peer endpoint
allows 64 pending connections, with at most 256 KiB buffered per pending
connection and 2 MiB total pending-connection buffering.

Dropped streams keep the transport alive for up to five seconds while queued
data is acknowledged. Final transport teardown also allows up to five seconds
for QUIC connection-close packets to drain. This requires a running Tokio runtime;
explicitly close clients before shutting the runtime down.

This package replaces the former `quinn-plaintext` public API and does not
interoperate directly with stock TLS QUIC clients. Ordinary QUIC uses the
optional shared-port fallback. A general-purpose WireGuard VPN peer alone does
not provide the inner QUIC/HTTP application endpoint.

## Features

The default `http` feature enables all HTTP conveniences. Select only what your
application uses with `default-features = false`:

| Feature | Provides |
| --- | --- |
| `server` | Generic Tower HTTP service support over Hyper. |
| `client` | Native streaming HTTP client over Hyper. |
| `http` | Both features above. |

The library uses the caller's Tokio runtime. Examples and tests use the
current-thread runtime. Signal handling is enabled only for development targets.

Disable defaults to use only authenticated streams:

```toml
quic_wg = { version = "0.5", default-features = false }
```

