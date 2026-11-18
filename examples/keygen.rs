use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use kwack::{Error, Identity};

fn main() -> Result<(), Error> {
    let mut seed = [0; 32];
    rustls::crypto::ring::default_provider()
        .secure_random
        .fill(&mut seed)
        .map_err(|_| std::io::Error::other("could not generate an Ed25519 seed"))?;
    let private_key = STANDARD.encode(seed);
    let identity = Identity::from_private_key(&private_key)?;
    println!("PRIVATE_KEY=\"{private_key}\"");
    println!("PUBLIC_KEY=\"{}\"", identity.public_key_base64());
    Ok(())
}
