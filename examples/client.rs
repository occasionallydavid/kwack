#![deny(clippy::unwrap_used, clippy::expect_used)]

use tracing::info;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init()?;

    let client = quinn::Endpoint::client("127.0.0.1:0".parse()?)?;
    let conn = client
        .connect_with(
            quinn_plaintext::client_config(),
            "127.0.0.1:1337".parse()?,
            "plaintext.test",
        )?
        .await?;

    let mut send = conn.open_uni().await?;
    send.write_all(b"hello world").await?;
    send.finish()?;
    send.stopped().await?;
    info!("message delivered");

    conn.close(0u32.into(), b"done");
    client.wait_idle().await;
    Ok(())
}
