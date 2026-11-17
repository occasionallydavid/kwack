# wireguard-quic

QUIC streams and HTTP authenticated and encrypted by BoringTun's userspace
WireGuard state machine. One library owns the UDP socket, WireGuard handshakes,
rekeys, and QUIC endpoints. No TUN device, OS routes, or root access is needed.

```text
Axum / HTTP client ↔ HTTP/1.1 ↔ QUIC streams ↔ WireGuard ↔ UDP
```

The server has its own private key and an explicit list of authorized client
public keys. The client supplies its private key and pins the server public key.
WireGuard provides authentication, encryption, and replay protection. The inner
QUIC implementation provides reliability, congestion control, and independent
streams. Inner QUIC packets carry no additional checksum or authentication tag.
Plaintext QUIC configuration is private to the crate.

## Run the examples

The examples take base64 private keys directly as command-line arguments.
Generate key pairs into shell variables (Bash); `keygen` prints the private and
public key on one line, separated by a space:

```sh
read -r SERVER_PRIVATE SERVER_PUBLIC < <(cargo run --quiet --example keygen)
read -r CLIENT_PRIVATE CLIENT_PUBLIC < <(cargo run --quiet --example keygen)
printf 'Server public key: %s\nClient public key: %s\n' "$SERVER_PUBLIC" "$CLIENT_PUBLIC"
```

Start the Axum server in one terminal:

```sh
cargo run --example server -- "$SERVER_PRIVATE" "$CLIENT_PUBLIC"
```

In another terminal, set the client private key and server public key variables
to their generated values, then run:

```sh
cargo run --example client -- "$CLIENT_PRIVATE" 127.0.0.1:4433 "$SERVER_PUBLIC" /whoami
```

`/whoami` returns the authenticated **client public key**. `/` returns a greeting,
and `POST /echo` echoes the request body. Set `BIND_ADDR` to change the listener;
pass additional authorized public keys as additional server arguments. Ctrl-C
shuts down the example server.

There is also an example using an actual, unmodified reqwest client:

```sh
cargo run --example reqwest -- "$CLIENT_PRIVATE" 127.0.0.1:4433 "$SERVER_PUBLIC"
```

## Server API

```rust,no_run
use axum::{Router, routing::get};
use wireguard_quic::{Error, PeerIdentity, PrivateKey, PublicKey, Server};

# async fn example(server_private: PrivateKey, client_public: PublicKey) -> Result<(), Error> {
let router = Router::new().route("/whoami", get(|peer: PeerIdentity| async move {
    peer.public_key().to_string()
}));
let server = Server::builder(server_private)
    .authorized_peers([client_public])
    .bind("0.0.0.0:4433")
    .await?;
let handle = server.handle();
// handle.revoke_peer(client_public).await?;
server.serve_axum(router).await?;
# Ok(())
# }
```

`PeerIdentity` is inserted from the authenticated transport on every HTTP request.
It is never taken from a header or the network address. Each authorized public key
has its own virtual QUIC endpoint, so one peer cannot inject QUIC packets into
another peer's connections. Revocation removes the WireGuard state and closes
that peer's existing QUIC connections. Adding peers currently requires rebinding
with a new authorized list.

Use `serve_axum_with_shutdown(router, shutdown_future)` for coordinated shutdown,
or `accept()` / `Connection::accept_bi()` for a custom application protocol.
Streams implement Tokio's `AsyncRead` and `AsyncWrite`. Handshakes are accepted
concurrently with a bound on outstanding accept tasks.

## Client API

```rust,no_run
use wireguard_quic::{Client, Error, PrivateKey, PublicKey};
# async fn example(private: PrivateKey, server_key: PublicKey) -> Result<(), Error> {
let client = Client::builder(private)
    .remote("127.0.0.1:4433".parse()?, server_key)
    .connect().await?;
let response = client.http().get("/whoami").send().await?;
println!("{}", response.text().await?);
client.close().await;
# Ok(())
# }
```

Requests use origin-relative paths and stay on the pinned peer. Each request
opens a QUIC stream on the existing connection. `HttpClient::execute()` accepts
streaming HTTP bodies; `Response::into_inner()` exposes the streaming Hyper
response. Convenience body collection is limited to 8 MiB and a configurable
read timeout. `bytes_with_limit()` overrides the buffering limit. HTTP/1.1 runs
directly over QUIC streams; this is not standard TLS HTTP/3.

For reqwest or ureq, `client.reqwest_bridge().await?` creates a managed loopback
listener. Connect an ordinary HTTP client to `bridge.base_url()`. Keep the bridge
alive. Its TCP connections become QUIC streams to the pinned peer. Configure
that HTTP client with proxies and automatic redirects disabled, as demonstrated
in `examples/reqwest.rs`, so those features cannot send requests outside the
transport. The bridge trusts local processes that can reach its loopback port;
use the native client when local access must not be shared.

Keys parse from WireGuard's standard base64 format. `PrivateKey::generate()` uses
an OS-backed cryptographic RNG. Private-key debug output is redacted. Keys use ordinary byte arrays and base64
exports return ordinary strings.

## Rejected packets and shared-port QUIC

`server.take_rejected()` returns a bounded receiver of `RejectedDatagram` values:

- `data`: untouched outer UDP bytes, including rejected WireGuard ciphertext.
- `source`: original sender address.
- `local_address`: bound socket address; wildcard binds do not expose the exact destination IP.
- `reason`: unrecognized traffic, malformed WireGuard, unauthorized peer, unknown
  session, authentication failure, or invalid inner packet.

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
path MTU adaptation are not implemented. UDP segmentation offload is disabled.

This package replaces the former `quinn-plaintext` public API and does not
interoperate directly with stock TLS QUIC clients. Ordinary QUIC uses the
optional shared-port fallback. A general-purpose WireGuard VPN peer alone does
not provide the inner QUIC/HTTP application endpoint.

## Features and validation

The default `http` feature includes Axum, Hyper, and the reqwest-compatible
loopback bridge. Disable defaults to use only authenticated streams:

```toml
wireguard-quic = { version = "0.5", default-features = false }
```

```sh
cargo fmt --check
cargo check --no-default-features --lib
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets -- -D warnings
```

Tests exercise authorization, server-key pinning, per-peer identity, revocation,
HTTP and reqwest, replay rejection, packet loss, endpoint roaming, ciphertext
on the wire, and ordinary TLS QUIC sharing the same UDP port. CI includes x86,
x86-64, and ARM64. `unwrap()` and `expect()` are denied outside tests.

## Source provenance

The untouched initial import is preserved as the first local commit, from
[jeromegn/quinn-plaintext](https://github.com/jeromegn/quinn-plaintext), upstream
commit `5c0bb8962aa00e9ec51ed07c969bd01dfc69be10`. Subsequent fixes and this fused
transport are layered on top. The original declared license is MIT OR Apache-2.0.
