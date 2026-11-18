use std::collections::HashSet;

use axum::Router;
use axum::extract::DefaultBodyLimit;
use axum::routing::post;
use kwack::{Error, PeerAuthorizer, PublicKey};

mod support;

#[tokio::main(flavor = "current_thread")]
async fn main() -> Result<(), Error> {
    let mut args = std::env::args().skip(1);
    let usage = "usage: server PRIVATE_KEY BIND_ADDRESS [CLIENT_PUBLIC_KEY ...]";
    let private_key = args.next().ok_or(usage)?;
    let address = args.next().ok_or(usage)?.parse()?;
    let accepted_keys = args
        .map(|key| support::parse_public_key(&key))
        .collect::<Result<HashSet<_>, _>>()?;
    let authorize_client: Option<PeerAuthorizer> = if accepted_keys.is_empty() {
        None
    } else {
        Some(Box::new(move |peer| accepted_keys.contains(&peer.raw())))
    };

    let router = Router::new()
        .route("/echo", post(echo))
        .route("/optional-echo", post(optional_echo))
        .layer(DefaultBodyLimit::max(1024));
    let listener = kwack::server::serve(router, &private_key, authorize_client)?.bind(address)?;
    println!("listening on {}", listener.local_addr()?);
    listener.run().await;
    Ok(())
}

async fn echo(peer: PublicKey, body: String) -> String {
    eprintln!("request from {}", peer.encoded());
    body
}

async fn optional_echo(peer: Option<PublicKey>, body: String) -> String {
    match peer {
        Some(peer) => eprintln!("request from {}", peer.encoded()),
        None => eprintln!("anonymous request"),
    }
    body
}
