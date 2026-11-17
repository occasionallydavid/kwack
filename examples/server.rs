#![deny(clippy::unwrap_used, clippy::expect_used)]

use std::time::Duration;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

type Error = Box<dyn std::error::Error + Send + Sync>;

#[tokio::main]
async fn main() -> Result<(), Error> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .try_init()?;

    let server =
        quinn::Endpoint::server(quinn_plaintext::server_config(), "127.0.0.1:1337".parse()?)?;
    info!(address = %server.local_addr()?, "listening");
    while let Some(incoming) = server.accept().await {
        tokio::spawn(async move {
            match tokio::time::timeout(Duration::from_secs(30), receive(incoming)).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => warn!(%error, "connection failed"),
                Err(_) => warn!("connection timed out"),
            }
        });
    }
    Ok(())
}

async fn receive(incoming: quinn::Incoming) -> Result<(), Error> {
    let conn = incoming.await?;
    let mut recv = conn.accept_uni().await?;
    let message = recv.read_to_end(64 * 1024).await?;
    info!(message = %String::from_utf8_lossy(&message), "received message");
    // Keep the connection alive until the sender has received acknowledgements.
    conn.closed().await;
    Ok(())
}
