#![deny(clippy::unwrap_used, clippy::expect_used)]
use wireguard_quic::{Client, Error, PrivateKey};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args().skip(1);
    let encoded_private = args
        .next()
        .ok_or("usage: client PRIVATE_KEY SERVER_ADDRESS SERVER_PUBLIC_KEY [PATH]")?;
    let private: PrivateKey = encoded_private.parse()?;
    let address = args.next().ok_or("missing server address")?.parse()?;
    let public = args.next().ok_or("missing server public key")?.parse()?;
    let path = args.next().unwrap_or_else(|| "/whoami".into());
    let client = Client::builder(private)
        .remote(address, public)
        .connect()
        .await?;
    println!(
        "authenticated server: {}",
        client.peer_identity().public_key()
    );
    let response = client.http().get(&path).send().await?;
    println!("{}\n{}", response.status(), response.text().await?);
    client.close().await;
    Ok(())
}
