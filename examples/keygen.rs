#![deny(clippy::unwrap_used, clippy::expect_used)]
use kwack::{Error, PrivateKey};

fn main() -> Result<(), Error> {
    let key = PrivateKey::generate()?;
    // One line: base64 private key, then base64 public key.
    println!("{} {}", key.to_base64().as_str(), key.public_key());
    Ok(())
}
