#![cfg(all(feature = "server", feature = "reqwest"))]

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use kwack::Identity;
use kwack::server::PeerIdentity;

fn keys(seed: u8) -> (String, String) {
    let private = STANDARD.encode([seed; 32]);
    let public = Identity::from_private_key(&private)
        .unwrap()
        .public_key_base64();
    (private, public)
}

#[tokio::test]
async fn tower_service_reads_authenticated_identity_from_request_extensions() {
    use std::convert::Infallible;

    use bytes::Bytes;
    use http::{Request, Response};
    use http_body_util::{BodyExt, Full};
    use kwack::server::RequestBody;
    use tower::service_fn;

    let (server_key, server_pin) = keys(1);
    let (client_key, client_pin) = keys(2);
    let service = service_fn(|request: Request<RequestBody>| async move {
        let peer = *request.extensions().get::<PeerIdentity>().unwrap();
        let bytes = request.into_body().collect().await.unwrap().to_bytes();
        Ok::<_, Infallible>(
            Response::builder()
                .header("x-authenticated-key", peer.public_key_base64())
                .body(Full::new(bytes))
                .unwrap(),
        )
    });
    let listener = kwack::server::serve(service, &server_key, &[&client_pin])
        .unwrap()
        .bind("127.0.0.1:0".parse().unwrap())
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(listener.run());
    let client = kwack::client::client_builder(&client_key, &[server_pin])
        .unwrap()
        .resolve("a", address)
        .timeout(Duration::from_secs(3))
        .build()
        .unwrap();
    let message = Bytes::from(vec![b'x'; 64 * 1024]);
    let response = client
        .post(format!("https://a:{}/echo", address.port()))
        .header("x-authenticated-key", "untrusted")
        .version(reqwest::Version::HTTP_3)
        .body(message.clone())
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap();
    assert_eq!(response.headers()["x-authenticated-key"], client_pin);
    assert_eq!(response.bytes().await.unwrap(), message);
    server.abort();
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn axum_extracts_the_authenticated_clients_key() {
    use axum::Router;
    use axum::routing::get;

    let (server_key, server_pin) = keys(1);
    let (first_key, first_pin) = keys(2);
    let (second_key, second_pin) = keys(3);
    let (other_key, _) = keys(4);
    let router = Router::new().route(
        "/whoami",
        get(|peer: PeerIdentity| async move { peer.public_key_base64() }),
    );
    let listener = kwack::server::serve(router, &server_key, &[&first_pin, &second_pin])
        .unwrap()
        .bind("127.0.0.1:0".parse().unwrap())
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(listener.run());
    let make_client = |key: &str| {
        kwack::client::client_builder(key, &[&server_pin])
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
