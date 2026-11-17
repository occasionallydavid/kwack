#![deny(clippy::unwrap_used, clippy::expect_used)]
use std::io::Write;
use wireguard_quic::{Error, PrivateKey};

fn main() -> Result<(), Error> {
    let path = std::env::args()
        .nth(1)
        .ok_or("usage: keygen PRIVATE_KEY_FILE (prints public key)")?;
    let key = PrivateKey::generate()?;
    let mut options = std::fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(path)?;
    file.write_all(key.to_base64().as_bytes())?;
    file.write_all(b"\n")?;
    println!("{}", key.public_key());
    Ok(())
}
