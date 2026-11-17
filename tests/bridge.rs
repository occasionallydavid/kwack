#![cfg(feature = "bridge")]
use std::time::Duration;

use quic_wg::{Client, PrivateKey, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

#[tokio::test(flavor = "current_thread")]
async fn bridge_transfers_bytes_without_http_features() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server_key = PrivateKey::from_bytes([27; 32]);
        let server_public = server_key.public_key();
        let client_key = PrivateKey::from_bytes([28; 32]);
        let mut server = Server::builder(server_key)
            .authorized_peers([client_key.public_key()])
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr();
        let task = tokio::spawn(async move {
            let connection = server.accept().await.unwrap();
            for _ in 0..2 {
                let mut stream = connection.accept_bi().await.unwrap();
                let mut data = vec![0; 128 * 1024];
                stream.read_exact(&mut data).await.unwrap();
                stream.write_all(&data).await.unwrap();
                stream.shutdown().await.unwrap();
            }
            connection.closed().await;
        });
        let client = Client::builder(client_key)
            .remote(address, server_public)
            .connect()
            .await
            .unwrap();
        let bridge = client.reqwest_bridge().await.unwrap();
        for byte in [0x5a, 0xa5] {
            let data = vec![byte; 128 * 1024];
            let mut tcp = TcpStream::connect(bridge.local_addr()).await.unwrap();
            tcp.write_all(&data).await.unwrap();
            let mut echoed = vec![0; data.len()];
            tcp.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, data);
        }
        drop(bridge);
        client.close().await;
        task.await.unwrap();
    })
    .await
    .expect("bridge test timed out");
}

#[cfg(feature = "http-server")]
#[tokio::test(flavor = "current_thread")]
async fn reqwest_bridge_preserves_authenticated_identity() {
    use axum::routing::get;
    use axum::{Extension, Router};
    use quic_wg::PeerIdentity;

    tokio::time::timeout(Duration::from_secs(10), async {
        let server_key = PrivateKey::from_bytes([29; 32]);
        let server_public = server_key.public_key();
        let client_key = PrivateKey::from_bytes([30; 32]);
        let client_public = client_key.public_key();
        let server = Server::builder(server_key)
            .authorized_peers([client_public])
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr();
        let handle = server.handle();
        let router =
            Router::new().route(
                "/whoami",
                get(|Extension(peer): Extension<PeerIdentity>| async move {
                    peer.public_key().to_string()
                }),
            );
        let task = tokio::spawn(server.serve(router));
        let client = Client::builder(client_key)
            .remote(address, server_public)
            .connect()
            .await
            .unwrap();
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
        drop(bridge);
        client.close().await;
        handle.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
    })
    .await
    .expect("reqwest bridge test timed out");
}
