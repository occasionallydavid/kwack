#![cfg(all(feature = "server", feature = "reqwest"))]

use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use kwack::{Identity, PeerAuthorizer, PublicKey};

fn keys(seed: u8) -> (String, String) {
    let private = STANDARD.encode([seed; 32]);
    let public = Identity::from_private_key(&private)
        .unwrap()
        .public_key_base64();
    (private, public)
}

fn pin(key: &str) -> PeerAuthorizer {
    let expected = raw_key(key);
    Box::new(move |peer| peer.raw() == expected)
}

fn raw_key(key: &str) -> [u8; 32] {
    STANDARD.decode(key).unwrap().try_into().unwrap()
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
        let peer = *request.extensions().get::<PublicKey>().unwrap();
        let bytes = request.into_body().collect().await.unwrap().to_bytes();
        Ok::<_, Infallible>(
            Response::builder()
                .header("x-authenticated-key", peer.encoded())
                .body(Full::new(bytes))
                .unwrap(),
        )
    });
    let listener = kwack::server::serve(service, &server_key, Some(pin(&client_pin)))
        .unwrap()
        .bind("127.0.0.1:0".parse().unwrap())
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(listener.run());
    let client = kwack::client::client_builder(Some(&client_key), Some(pin(&server_pin)))
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
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    use axum::Router;
    use axum::routing::get;

    let (server_key, server_pin) = keys(1);
    let (first_key, first_pin) = keys(2);
    let (second_key, second_pin) = keys(3);
    let (other_key, _) = keys(4);
    let router = Router::new().route(
        "/whoami",
        get(|peer: PublicKey| async move { peer.encoded() }),
    );
    let first_identity = raw_key(&first_pin);
    let second_identity = raw_key(&second_pin);
    let admit_first = Arc::new(AtomicBool::new(true));
    let policy = {
        let admit_first = admit_first.clone();
        move |peer: PublicKey| {
            let key = peer.raw();
            key == second_identity || (key == first_identity && admit_first.load(Ordering::Relaxed))
        }
    };
    let listener = kwack::server::serve(router, &server_key, Some(Box::new(policy)))
        .unwrap()
        .bind("127.0.0.1:0".parse().unwrap())
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(listener.run());
    let make_client = |key: &str| {
        kwack::client::client_builder(Some(key), Some(pin(&server_pin)))
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
    admit_first.store(false, Ordering::Relaxed);
    assert!(request(make_client(&first_key)).await.is_err());
    server.abort();
}

#[cfg(feature = "axum")]
#[tokio::test]
async fn open_server_supports_anonymous_and_identified_requests() {
    use axum::Router;
    use axum::routing::get;

    let (server_key, server_pin) = keys(1);
    let (client_key, client_pin) = keys(2);
    let router = Router::new()
        .route(
            "/required",
            get(|peer: PublicKey| async move { peer.encoded() }),
        )
        .route(
            "/optional",
            get(|peer: Option<PublicKey>| async move {
                peer.map_or_else(|| "anonymous".into(), |peer| peer.encoded())
            }),
        );
    let listener = kwack::server::serve(router, &server_key, None)
        .unwrap()
        .bind("127.0.0.1:0".parse().unwrap())
        .unwrap();
    let address = listener.local_addr().unwrap();
    let server = tokio::spawn(listener.run());
    let make_client = |key: Option<&str>, authorizer| {
        kwack::client::client_builder(key, authorizer)
            .unwrap()
            .resolve("a", address)
            .timeout(Duration::from_secs(3))
            .build()
            .unwrap()
    };
    let anonymous = make_client(None, Some(pin(&server_pin)));
    let identified = make_client(Some(&client_key), None);
    let request = |client: &reqwest::Client, path: &str| {
        client
            .get(format!("https://a:{}/{path}", address.port()))
            .version(reqwest::Version::HTTP_3)
            .send()
    };
    let response = request(&anonymous, "required").await.unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::UNAUTHORIZED);
    for (client, path, expected) in [
        (&anonymous, "optional", "anonymous"),
        (&identified, "optional", &client_pin),
        (&identified, "required", &client_pin),
    ] {
        let response = request(client, path)
            .await
            .unwrap()
            .error_for_status()
            .unwrap();
        assert_eq!(response.text().await.unwrap(), expected);
    }
    server.abort();
}
