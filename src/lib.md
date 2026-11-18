Reliable streams and Tower/HTTP services over **outer Noise IKpsk2 encryption**
and **inner KCP conversations**. One Tokio UDP socket carries multiple independent
conversations per authenticated session. No IP packets, TUN devices, or OS routes.

```text
Tower / Axum / Hyper HTTP/1.1
             ↕
KcpStream: reliable OPEN / DATA / FIN records
             ↕
Independent KCP conversations (one per stream)
             ↕
Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s
             ↕
            UDP
```

## Authentication and admission

Each endpoint owns an X25519 private key. Clients pin the server public key;
servers authorize client public keys with an in-memory callback. Base64 key
encoding is compatible with WireGuard's key format. The wire protocol is kwack's,
and does not interoperate with a WireGuard VPN or a raw KCP endpoint.

An opening MAC derived from the server public key silently rejects senders who
do not know that key, before performing the Noise handshake. Knowing that public
key does not grant authorization. The Noise handshake proves the client static
identity; the first encrypted KCP packet proves possession of the final session
keys before the server exposes a connection. The client can send data immediately
after the two Noise handshake messages, without a separate confirmation exchange. A mismatched PSK never establishes a session.

`preshared_key([u8; 32])` configures an optional additional secret on either builder.
The server uses that same PSK for all its peers. Both ends default to 32 zero bytes,
as in WireGuard when no additional PSK is configured. The Noise pattern is always
IKpsk2. Key generation uses an OS-backed RNG. Private key Debug output is redacted;
explicit key exports use ordinary byte arrays and strings.

## Tower / Axum server

```rust,no_run
# #[cfg(feature = "server")]
# async fn example(private: kwack::PrivateKey, client_public: kwack::PublicKey) -> Result<(), kwack::Error> {
use axum::{Extension, Router, routing::get};
use kwack::{PeerIdentity, Server};

let router = Router::new().route("/whoami", get(
    |Extension(peer): Extension<PeerIdentity>| async move {
        peer.public_key().to_string()
    },
));
let server = Server::builder(private)
    .authorize(Box::new(move |key| key == client_public))
    .bind("0.0.0.0:4433")
    .await?;
server.serve(router).await?;
# Ok(())
# }
```

`serve` accepts a cloneable Tower service of `Request<hyper::body::Incoming>`.
Tower readiness is honored. Authenticated `PeerIdentity` is inserted into every
request's extensions, never read from an HTTP header or inferred from the IP address.
Each HTTP exchange opens an independent KCP conversation. Request and response
bodies stream through Hyper. `serve_with_shutdown` accepts a shutdown future.

Admission defaults to deny. The authorization callback runs synchronously on
handshake initiation after the first Noise message authenticates the client's
static key, but before final PSK confirmation. It must not perform blocking I/O.
Changes to the callback's policy affect subsequent handshakes.
`server.handle().revoke_peer(key).await?` closes all current sessions of that key
and denies it for the listener's lifetime.

## HTTP client

```rust,no_run
# #[cfg(feature = "client")]
# async fn example(private: kwack::PrivateKey, server_public: kwack::PublicKey) -> Result<(), kwack::Error> {
use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Empty};
use kwack::Client;

let client = Client::builder(private)
    .remote("127.0.0.1:4433".parse()?, server_public)
    .connect().await?;
let response = client.send(Request::builder()
    .uri("/whoami")
    .header("host", "my-service")
    .body(Empty::<Bytes>::new())?
).await?;
let body = response.into_body().collect().await?.to_bytes();
println!("{}", String::from_utf8(body.to_vec())?);
client.close().await;
# Ok(())
# }
```

URIs must use origin-relative paths and stay on the pinned peer. Set `Host` and
other routing metadata with the normal request builder. This is HTTP/1.1 over
KCP streams. Callers choose request deadlines and body collection limits.

## Independent conversations and byte streams

`Server::accept()` returns a Noise `Connection` after the first authenticated
transport packet arrives. Open/write a client stream to trigger it; an idle
client's ordinary keepalive also triggers admission. Either endpoint can open a
conversation with `Connection::open_stream()`; the other endpoint receives it
through `Connection::accept_stream()`. Each `KcpStream` implements Tokio's
`AsyncRead` and `AsyncWrite`, so it can be passed to Hyper through `TokioIo` or to
ordinary Tokio read/write utilities. `conversation_id()` identifies its KCP state
within the Noise session. Client-opened IDs are odd and server-opened IDs are even.

```rust,no_run
# async fn example(connection: kwack::Connection) -> Result<(), kwack::Error> {
use tokio::io::{AsyncReadExt, AsyncWriteExt};
let mut first = connection.open_stream().await?;
let mut second = connection.open_stream().await?;
assert_ne!(first.conversation_id(), second.conversation_id());
first.write_all(b"request").await?;
first.shutdown().await?; // queue a reliable FIN; the read half remains usable
second.write_all(b"independent request").await?;
second.shutdown().await?;
let mut reply = Vec::new();
first.read_to_end(&mut reply).await?;
# Ok(())
# }
```

KCP message mode carries bounded OPEN/DATA/FIN records; `KcpStream` concatenates
DATA into a byte stream. OPEN includes the first write's data when available, and
vectored writes combine HTTP headers and bodies into that record. A conversation
opened for reading alone sends an empty OPEN after a short scheduling grace period.
There is no OPEN acknowledgment barrier before sending application data. KCP acknowledges and retransmits all three record types.
`flush()` waits for KCP acknowledgment of queued records; `shutdown()` queues a reliable FIN after pending DATA; it returns without
waiting for the peer to acknowledge it. A dropped stream queues FIN and permits a bounded drain.
`Connection::close()` aborts local I/O immediately and sends closure in the
background. `Connection::shutdown().await` and `Client::close().await` also wait
for an encrypted close acknowledgment, retrying for up to one second. Neither
flushes queued application writes. Await the async close before stopping the
runtime. Streams keep their UDP driver alive after the Client or
Connection handle is dropped. The final driver drains for up to five seconds;
stopping the Tokio runtime interrupts that drain.

## Wire format and bounds

Openings contain a protocol/version marker, a random 128-bit session ID, the
Noise initiation with an encrypted timestamp, and a 16-byte public-key gate MAC.
The session ID and protocol domain are bound into the Noise prologue. Identical
handshake retries reuse the cached response without resetting transport counters.
Openings expire after 30 seconds of clock skew; accepted initiation IDs are kept
in a bounded replay cache for 65 seconds.

Transport datagrams contain the marker, packet type, session ID, an explicit
64-bit counter, and a Noise ciphertext/tag. The counter's high 32 bits identify
the key generation; its low 32 bits count packets independently in each direction. The full 29-byte transport header is
AEAD associated data. A 2,048-packet replay window admits reordering and rejects
duplicates; it advances only after successful authentication. KCP retransmissions
are encrypted with fresh Noise nonces. Only authenticated packets can update the
peer's UDP address, permitting roaming.

Outer UDP payloads are capped at 1,200 bytes, including the 29-byte header and
16-byte authentication tag. There is no synthetic IP/UDP framing. The KCP MTU is
1,154 bytes, leaving one encrypted byte for the packet subtype. Each conversation
has an 8-segment send window, a 128-segment receive window, and a bounded application receive queue of
approximately 256 KiB. Application writes are chunked at 16 KiB; the send queue
applies backpressure at 128 segments. KCP congestion control is disabled, so
the sender can fill the available flow-control window from the first flight.

A session permits 128 active/draining conversations. Opening another at capacity
returns `WouldBlock`. Closed conversation IDs are not reused; retired IDs use a
bounded replay window. Dropped conversations linger briefly to ACK retransmitted
FINs and are removed within five seconds. The listener permits 1,024 sessions,
128 queued connections, and 256 queued raw packet rejections. Unconfirmed sessions
expire after 60 seconds. Confirmed peers exchange keepalives every ten seconds
and time out after 60 seconds without authenticated traffic.

`take_rejected()` returns untouched UDP bytes with source, bound local address,
and a rejection reason. Its bounded queue drops on overload. It never exposes
decrypted data. A wildcard bind does not reveal the exact local destination IP.

Session closure stops KCP and keepalives immediately. Close and acknowledgment
packets are authenticated; the initiator retries for one second, and the receiver
lingers for two seconds solely to acknowledge close retransmissions. An unreachable
peer can still require the idle timeout to detect a crash or lost close exchange.
The public-key gate is not a substitute
for WireGuard's cookie challenge/rate limiter, which this protocol does not yet
implement. Path MTU discovery and UDP segmentation offload are not implemented.

## Rekeying

The client initiates a fresh `Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s` handshake every
120 seconds, including on idle sessions. This performs fresh ephemeral DH; it is
not just symmetric-key derivation. Rekey initiation and response messages travel
inside the existing encrypted session. The logical session ID, authenticated
identity, KCP conversation IDs, queues, windows, and retransmissions remain intact.

Each rekey binds the logical session ID and strictly increasing generation into
the Noise prologue, checks that the static peer identity has not changed, and
checks the server's current authorization policy before replying. Retransmitted
handshake messages reuse the cached Noise bytes but receive fresh outer packet
nonces. The client retries a lost initiation/response every 200 ms.

After validating the Noise response, the client immediately sends application
data under the candidate keys. The responder switches after authenticating its
first new-key KCP packet or normal keepalive. The initiator settles the exchange
when it receives normal traffic under the new keys. There is no explicit key
confirmation or acknowledgment frame, and no added data RTT. Idle sessions use
their existing ten-second keepalives to confirm the switch.

Previous receive keys overlap until they reach 180 seconds of age. Every generation
has its own replay window; reordering and duplicates cannot reset counters or roll
back the active generation. Old keys are discarded at their age limit. If rekeying
cannot succeed before the current keys reach 180 seconds, the session closes and
streams fail rather than continuing indefinitely with expired keys. Packet counters
and generation numbers cannot wrap. Session resumption is not implemented.

## Features

The default `http` feature enables `server` and `client`. Disable default features
for authenticated KCP streams without Hyper or Tower:

```toml
kwack = { version = "0.6", default-features = false }
```

The transport uses `noise-protocol` with `noise-rust-crypto` configured for only
X25519, ChaCha20-Poly1305, and BLAKE2, and `kcp` for reliability. All dependencies
come from crates.io; there is no vendored or locally patched crypto implementation.
