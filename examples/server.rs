use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::post;
use kwack::Error;
use kwack::server::PeerIdentity;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: server PRIVATE_KEY BIND_ADDRESS CLIENT_PUBLIC_KEY [CLIENT_PUBLIC_KEY ...]";
    let private_key = args.next().ok_or(usage)?;
    let address = args.next().ok_or(usage)?.parse()?;
    let accepted_keys: Vec<_> = args.collect();
    if accepted_keys.is_empty() {
        return Err(usage.into());
    }

    let router = Router::new()
        .route("/echo", post(echo))
        .layer(DefaultBodyLimit::max(1024));
    let listener = kwack::server::serve(router, &private_key, &accepted_keys)?.bind(address)?;
    println!("listening on {}", listener.local_addr()?);
    listener.run().await;
    Ok(())
}

async fn echo(peer: PeerIdentity, body: String) -> String {
    eprintln!("request from {}", peer.public_key_base64());
    body
}
