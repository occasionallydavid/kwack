#![cfg(feature = "http")]
use std::time::Duration;

use axum::Router;
use axum::body::Bytes;
use axum::routing::{get, post};
use tokio::task::JoinSet;
use wireguard_quic::{Client, PeerIdentity, PrivateKey, Server};

#[tokio::test]
async fn axum_streaming_http_and_reqwest_use_authenticated_transport() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let server_key = PrivateKey::from_bytes([20; 32]);
        let server_public = server_key.public_key();
        let client_key = PrivateKey::from_bytes([21; 32]);
        let client_public = client_key.public_key();
        let server = Server::builder(server_key)
            .authorized_peers([client_public])
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr();
        let handle = server.handle();
        let router = Router::new()
            .route(
                "/whoami",
                get(|peer: PeerIdentity| async move { peer.public_key().to_string() }),
            )
            .route("/echo", post(|body: Bytes| async move { body }));
        let mut tasks = JoinSet::new();
        tasks.spawn(server.serve_axum(router));
        let client = Client::builder(client_key)
            .remote(address, server_public)
            .connect()
            .await
            .unwrap();
        assert_eq!(
            client
                .http()
                .get("/whoami")
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            client_public.to_string()
        );
        let body = vec![0x5a; 128 * 1024];
        assert_eq!(
            &client
                .http()
                .post("/echo")
                .body(body.clone())
                .send()
                .await
                .unwrap()
                .bytes()
                .await
                .unwrap()[..],
            body
        );
        let bridge = client.reqwest_bridge().await.unwrap();
        let reqwest = reqwest::Client::builder()
            .no_proxy()
            .redirect(reqwest::redirect::Policy::none())
            .build()
            .unwrap();
        assert_eq!(
            reqwest
                .get(format!("{}/whoami", bridge.base_url()))
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            client_public.to_string()
        );
        for _ in 0..5 {
            let http = client.http();
            tasks.spawn(async move { http.get("/whoami").send().await.map(|_| ()) });
        }
        for _ in 0..5 {
            assert!(tasks.join_next().await.unwrap().unwrap().is_ok());
        }
        assert!(
            client
                .http()
                .get("http://example.com/")
                .send()
                .await
                .is_err()
        );
        drop(bridge);
        client.close().await;
        handle.shutdown().await.unwrap();
    })
    .await
    .expect("HTTP test timed out");
}

#[tokio::test]
async fn revocation_closes_existing_connections_and_blocks_reconnect() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server_key = PrivateKey::from_bytes([22; 32]);
        let public = server_key.public_key();
        let client_key = PrivateKey::from_bytes([23; 32]);
        let peer = client_key.public_key();
        let server = Server::builder(server_key)
            .authorized_peers([peer])
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr();
        let handle = server.handle();
        let mut tasks = JoinSet::new();
        tasks.spawn(server.serve_axum(Router::new().route("/", get(|| async { "ok" }))));
        let client = Client::builder(client_key)
            .remote(address, public)
            .connect()
            .await
            .unwrap();
        assert_eq!(
            client
                .http()
                .get("/")
                .send()
                .await
                .unwrap()
                .text()
                .await
                .unwrap(),
            "ok"
        );
        handle.revoke_peer(peer).await.unwrap();
        // The remote can only learn revocation by closure or timeout; the server must
        // immediately cease servicing requests regardless of notification delivery.
        assert!(
            client
                .http()
                .timeout(Duration::from_millis(300))
                .get("/")
                .send()
                .await
                .is_err()
        );
        assert!(
            Client::builder(PrivateKey::from_bytes([23; 32]))
                .remote(address, public)
                .connect_timeout(Duration::from_millis(300))
                .connect()
                .await
                .is_err()
        );
    })
    .await
    .expect("revocation test timed out");
}
