# kwack

Authenticated reliable byte streams and Tower/HTTP services over UDP.
**Noise IKpsk2 is the outer protocol; KCP is the inner protocol.**

```text
Tower / Axum / Hyper HTTP/1.1 ↔ KCP conversations ↔ Noise IKpsk2 ↔ UDP
```

Each endpoint has an X25519 key pair. Clients pin server public keys; servers
explicitly authorize client public keys. A public-key opening MAC keeps the
listener silent to senders who do not know its public key. Multiple independent
KCP conversations share an authenticated Noise session. Each conversation is a
Tokio `AsyncRead`/`AsyncWrite` stream with reliable retransmission and half-close.
No fake IP framing, TUN device, OS routes, root access, QUIC, or TLS.

The generic Tower service adapter accepts Axum routers and inserts authenticated
`PeerIdentity` into every HTTP request. Hyper carries streaming HTTP/1.1 request
and response bodies over separate KCP conversations. Key encoding remains
compatible with WireGuard's base64 key format; the network protocol is kwack's.

See [the API guide](src/lib.md) for builders, stream APIs, wire format, resource
limits, automatic fresh-DH rekeying every two minutes, and current limitations.

## Run the examples

Generate two key pairs in Bash. The examples accept private keys directly:

```sh
read -r SERVER_PRIVATE SERVER_PUBLIC < <(cargo run --quiet --example keygen)
read -r CLIENT_PRIVATE CLIENT_PUBLIC < <(cargo run --quiet --example keygen)
printf 'Server public key: %s\nClient public key: %s\n' "$SERVER_PUBLIC" "$CLIENT_PUBLIC"
```

Start the Axum server:

```sh
cargo run --example server -- "$SERVER_PRIVATE" "$CLIENT_PUBLIC"
```

In another terminal, set the client private key and server public key to the
values above, then run:

```sh
cargo run --example client -- "$CLIENT_PRIVATE" 127.0.0.1:4433 "$SERVER_PUBLIC" /whoami
```

`/whoami` returns the authenticated client public key, `/` returns a greeting,
and `POST /echo` echoes the request body. `BIND_ADDR` changes the listener.
Additional server arguments authorize additional client public keys.
Ctrl-C shuts down the server.

## Development

```sh
cargo +nightly fmt --check
cargo check --no-default-features --lib
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets -- -D warnings
```

Tests cover public-key authentication and pinning, PSKs, independent conversations,
HTTP/Tower readiness and identity, revocation, replay rejection, retransmission,
packet loss/reordering, endpoint roaming, and stream shutdown/draining.

Uses [noise-protocol / noise-rust-crypto](https://github.com/sopium/noise-rust)
and [kcp](https://github.com/Matrix-Zhang/kcp) from crates.io. No crypto fork.
