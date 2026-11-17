# quic_wg

QUIC streams and HTTP authenticated and encrypted by BoringTun's userspace
WireGuard state machine. One library owns the UDP socket, WireGuard handshakes,
rekeys, and QUIC endpoints. No TUN device, OS routes, or root access is needed.

## Why?

WireGuard exposes a UDP port that stays silent unless the sender knows its public
key, with decentralised identity and authentication based on self-administered key
pairs. QUIC adds a modern transport suitable for streaming and bulk requests.

```text
Axum / HTTP client ↔ HTTP/1.1 ↔ QUIC streams ↔ WireGuard ↔ UDP
```

See the [crate documentation](https://docs.rs/quic_wg) for the API guide,
features, transport details, and compatibility notes.

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

## Development

Formatting uses nightly rustfmt for module-level import grouping.

```sh
cargo +nightly fmt --check
cargo check --no-default-features --lib
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets -- -D warnings
```

Tests exercise authorization, server-key pinning, per-peer identity, revocation,
HTTP, replay rejection, packet loss, endpoint roaming, ciphertext
on the wire, and ordinary TLS QUIC sharing the same UDP port. `unwrap()` and `expect()` are denied outside tests.

## Source provenance

Based on [quinn-plaintext](https://github.com/jeromegn/quinn-plaintext).
