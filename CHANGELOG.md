# Changelog

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