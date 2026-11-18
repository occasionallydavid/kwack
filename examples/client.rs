use std::net::SocketAddr;
use std::time::Duration;

use kwack::Error;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: client PRIVATE_KEY SERVER_ADDRESS SERVER_PUBLIC_KEY [MESSAGE]";
    let private_key = args.next().ok_or(usage)?;
    let server: SocketAddr = args.next().ok_or(usage)?.parse()?;
    let server_public = args.next().ok_or(usage)?;
    let message = args
        .next()
        .unwrap_or_else(|| "hello over mutual TLS".into());
    if args.next().is_some() {
        return Err(usage.into());
    }

    let client = kwack::reqwest::client_builder(&private_key, &[server_public])?
        .resolve("a", server)
        .timeout(Duration::from_secs(5))
        .build()?;
    let reply = client
        .post(format!("https://a:{}/echo", server.port()))
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
