#![deny(clippy::unwrap_used, clippy::expect_used)]
use wireguard_quic::{Client, Error, PrivateKey};

#[tokio::main]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args().skip(1);
    let encoded_private = args
        .next()
        .ok_or("usage: reqwest PRIVATE_KEY SERVER_ADDRESS SERVER_PUBLIC_KEY")?;
    let private: PrivateKey = encoded_private.parse()?;
    let address = args.next().ok_or("missing server address")?.parse()?;
    let public = args.next().ok_or("missing server public key")?.parse()?;
    let transport = Client::builder(private)
        .remote(address, public)
        .connect()
        .await?;
    let bridge = transport.reqwest_bridge().await?;
    // Keep bridge alive. Prevent proxy settings or redirects from bypassing the pinned peer.
    let client = reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .build()?;
    let response = client
        .get(format!("{}/whoami", bridge.base_url()))
        .send()
        .await?;
    println!("{}", response.text().await?);
    transport.close().await;
    Ok(())
}
