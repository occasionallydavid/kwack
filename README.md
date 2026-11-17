# quinn-plaintext

Use QUIC without encryption.

Run this only inside an authenticated, encrypted tunnel such as WireGuard.
The unkeyed SeaHash checksum detects accidental corruption. It provides no
protection against intentional modification, peer authentication, or confidentiality.
TLS identities, TLS key export, and authenticated Retry packets are not provided.

## Compatibility

Version 0.4 uses a four-byte big-endian length prefix for handshake transport
parameters, limited to 64 KiB. Both peers must upgrade together; handshakes with
0.3 and earlier are incompatible.

Packet tags contain the big-endian SeaHash checksum of
`header_length_le64 || header || payload_length_le64 || payload`.
This fixes the architecture-dependent `usize` lengths used in earlier versions
and preserves the earlier 64-bit checksum format. Checksums stay enabled.

## Source provenance

This independently maintained copy starts from
[jeromegn/quinn-plaintext](https://github.com/jeromegn/quinn-plaintext), commit
`5c0bb8962aa00e9ec51ed07c969bd01dfc69be10`. The original source is preserved in
the first local commit; subsequent changes are layered on top.

## Usage

Basic examples are available under [`examples/`](examples)

### Server

```rust
let server = quinn::Endpoint::server(quinn_plaintext::server_config(), "[::]:0".parse()?)?;
// ...
```

### Client

```rust
let mut client = quinn::Endpoint::client("[::]:0".parse()?)?;
client.set_default_client_config(quinn_plaintext::client_config());
// ...
```

## Development

```sh
cargo fmt --check
cargo check --lib
cargo test --all-targets
cargo test --doc
cargo clippy --all-targets -- -D warnings
```

Clippy denies `unwrap()` and `expect()` outside tests. CI also tests the checksum
vectors and endpoint transfers on 32-bit x86 and 64-bit x86/ARM.
