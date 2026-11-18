use std::io;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

const ED25519_SPKI_PREFIX: &[u8] = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

pub(super) fn parse_public_key(encoded: &str) -> Result<[u8; 32], kwack::Error> {
    let decoded = STANDARD.decode(encoded.trim())?;
    let raw = if decoded.len() == 32 {
        decoded.as_slice()
    } else {
        decoded
            .strip_prefix(ED25519_SPKI_PREFIX)
            .unwrap_or_default()
    };
    raw.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected an Ed25519 public key",
        )
        .into()
    })
}
