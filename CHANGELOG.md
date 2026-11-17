# Changelog

## 0.5.0

- (BREAKING) Rename the crate to `wireguard-quic` and make bare plaintext QUIC configuration private.
- Add mandatory BoringTun authentication/encryption around QUIC with userspace IP/UDP envelopes; no TUN device is needed.
- Add server/client builders, authorized public keys, server key pinning, authenticated peer identity, and revocation.
- Isolate peers in separate internal QUIC endpoints; support encrypted endpoint roaming.
- Drive WireGuard handshake retries, keepalives, and rekeys from a managed UDP dispatcher.
- Add Axum serving with a peer identity extractor, streaming HTTP client, and an unmodified reqwest/ureq loopback bridge.
- Expose rejected outer UDP datagrams and a same-port fallback socket for ordinary QUIC services.
- Add key generation, server, native client, and reqwest examples.
- Add integration tests for loss, replay, roaming, wire encryption, authorization, identity, revocation, HTTP, and shared-port TLS QUIC.

## 0.4.0

- Reject malformed transport parameters with a transport error instead of panicking.
- (BREAKING) Frame handshake parameters with a four-byte big-endian length; buffer fragmented messages and cap parameters at 64 KiB. Upgrade both peers together.
- Use fixed 64-bit little-endian lengths in checksums on every architecture, preserving the original 64-bit packet checksum format.
- Reject short or corrupt packet tags without panicking or modifying the payload.
- Correct handshake completion and report handshake data only once.
- Return an error for unsupported key material export.
- Remove packet payload logging and all unwrap/expect calls outside tests.
- Make examples propagate errors and explicitly finish streams.
- Add malformed-input, checksum portability, fragmentation, and endpoint regression tests.

## 0.2.0

- (BREAKING) Add checksum for both header and payload in the tag storage

## 0.1.1

- Documentation improvements

## 0.1.0

- Initial release