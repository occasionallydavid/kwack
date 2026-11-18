use std::net::SocketAddr;
use std::time::Duration;

use kwack::{Error, PeerIdentity};

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: client PRIVATE_KEY_OR_DASH SERVER_ADDRESS SERVER_PUBLIC_KEY [MESSAGE]";
    let private_key = args.next().ok_or(usage)?;
    let private_key = (private_key != "-").then_some(private_key.as_str());
    let server: SocketAddr = args.next().ok_or(usage)?.parse()?;
    let server_public = PeerIdentity::from_public_key_base64(&args.next().ok_or(usage)?)?;
    let message = args
        .next()
        .unwrap_or_else(|| "hello over mutual TLS".into());
    if args.next().is_some() {
        return Err(usage.into());
    }

    let client = kwack::client::client_builder(
        private_key,
        Some(Box::new(move |peer| peer == server_public)),
    )?
    .resolve("a", server)
    .timeout(Duration::from_secs(5))
    .build()?;
    let path = if private_key.is_some() {
        "echo"
    } else {
        "optional-echo"
    };
    let reply = client
        .post(format!("https://a:{}/{path}", server.port()))
        .version(reqwest::Version::HTTP_3)
        .body(message)
        .send()
        .await?
        .error_for_status()?
        .text()
        .await?;
    println!("{reply}");
    Ok(())
}
