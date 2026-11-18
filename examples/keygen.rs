use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use kwack::{Error, Identity};

fn main() -> Result<(), Error> {
    let key = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519)?;
    let private_key = STANDARD.encode(key.serialized_der());
    let identity = Identity::from_private_key(&private_key)?;
    println!("PRIVATE_KEY=\"{private_key}\"");
    println!("PUBLIC_KEY=\"{}\"", identity.public_key_base64());
    Ok(())
}
