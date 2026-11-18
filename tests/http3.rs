#![cfg(all(feature = "axum", feature = "reqwest"))]

use std::time::Duration;

use axum::routing::get;
use axum::{Extension, Router};
use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use kwack::Identity;
use kwack::axum::PeerIdentity;

fn keys(seed: u8) -> (String, String) {
    let private = STANDARD.encode([seed; 32]);
    let public = Identity::from_private_key(&private)
        .unwrap()
        .public_key_base64();
    (private, public)
}

#[tokio::test]
async fn http3_handler_gets_the_authenticated_clients_key() {
    let (server_key, server_pin) = keys(1);
    let (first_key, first_pin) = keys(2);
    let (second_key, second_pin) = keys(3);
    let (other_key, _) = keys(4);
    let router = Router::new().route(
        "/whoami",
        get(|Extension(peer): Extension<PeerIdentity>| async move { peer.public_key_base64() }),
    );
    let listener = kwack::axum::serve(router, &server_key, &[&first_pin, &second_pin])
        .unwrap()
        .bind("127.0.0.1:0".parse().unwrap())
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(listener.run());
    let make_client = |key: &str| {
        kwack::reqwest::client_builder(key, &[&server_pin])
            .unwrap()
            .resolve("a", address)
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap()
    };
    let request = |client: reqwest::Client| {
        client
            .get(format!("https://a:{}/whoami", address.port()))
            .header("x-peer-identity", "untrusted header")
            .version(reqwest::Version::HTTP_3)
            .send()
    };
    let (first, second, denied) = tokio::join!(
        request(make_client(&first_key)),
        request(make_client(&second_key)),
        request(make_client(&other_key)),
    );
    for (result, pin) in [(first, first_pin), (second, second_pin)] {
        let response = result.unwrap().error_for_status().unwrap();
        assert_eq!(response.version(), reqwest::Version::HTTP_3);
        assert_eq!(response.text().await.unwrap(), pin);
    }
    assert!(denied.is_err());
    server.abort();
}
