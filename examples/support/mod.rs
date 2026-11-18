use std::io;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;

pub(super) fn parse_public_key(encoded: &str) -> Result<[u8; 32], kwack::Error> {
    let decoded = STANDARD.decode(encoded.trim())?;
    decoded.try_into().map_err(|_| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            "expected a base64-encoded 32-byte Ed25519 public key",
        )
        .into()
    })
}
