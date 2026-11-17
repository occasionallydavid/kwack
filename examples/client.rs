#![deny(clippy::unwrap_used, clippy::expect_used)]
use bytes::Bytes;
use http::Request;
use http_body_util::{BodyExt, Empty, Limited};
use quic_wg::{Client, Error, PrivateKey};

#[tokio::main(flavor = "current_thread")]
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
    let request = Request::builder()
        .uri(&path)
        .header("host", "quic_wg")
        .body(Empty::<Bytes>::new())?;
    let (status, body) = tokio::time::timeout(std::time::Duration::from_secs(30), async {
        let response = client.send(request).await?;
        let status = response.status();
        let body = Limited::new(response.into_body(), 8 * 1024 * 1024)
            .collect()
            .await?
            .to_bytes();
        Ok::<_, Error>((status, body))
    })
    .await??;
    println!("{}\n{}", status, String::from_utf8(body.to_vec())?);
    client.close().await;
    Ok(())
}
