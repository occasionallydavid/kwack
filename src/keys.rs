use std::fmt;
use std::str::FromStr;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use x25519_dalek as x25519;

use crate::Error;

/// An X25519 static private key. Debug output is always redacted.
pub struct PrivateKey([u8; 32]);

impl PrivateKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn generate() -> Result<Self, Error> {
        let mut bytes = [0; 32];
        rand::fill(&mut bytes);
        Ok(Self(bytes))
    }

    pub fn public_key(&self) -> PublicKey {
        PublicKey(x25519::PublicKey::from(&self.secret()).to_bytes())
    }

    /// Explicit secret export in WireGuard's base64 format.
    pub fn to_base64(&self) -> String {
        STANDARD.encode(self.0)
    }

    pub(crate) fn secret(&self) -> x25519::StaticSecret {
        x25519::StaticSecret::from(self.0)
    }
}

impl fmt::Debug for PrivateKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("PrivateKey([REDACTED])")
    }
}

impl FromStr for PrivateKey {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Error> {
        let mut bytes = [0; 32];
        let len = STANDARD.decode_slice(value.trim(), &mut bytes)?;
        if len != 32 {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "private key must contain 32 bytes",
            )
            .into());
        }
        Ok(Self(bytes))
    }
}

/// An X25519 public key, displayed and parsed using WireGuard-compatible base64.
#[derive(Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(pub(crate) [u8; 32]);

impl PublicKey {
    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    pub fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}

impl fmt::Display for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&STANDARD.encode(self.0))
    }
}

impl fmt::Debug for PublicKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

impl FromStr for PublicKey {
    type Err = Error;

    fn from_str(value: &str) -> Result<Self, Error> {
        let bytes = STANDARD.decode(value.trim())?;
        let bytes = bytes.try_into().map_err(|_| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidInput,
                "public key must contain 32 bytes",
            )
        })?;
        Ok(Self(bytes))
    }
}
