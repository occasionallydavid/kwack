#![cfg(all(feature = "http-client", feature = "http-server"))]
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::routing::{get, post};
use axum::{Extension, Router};
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Full};
use hyper::body::Incoming;
use quic_wg::{Client, Error, PeerIdentity, PrivateKey, Server};
use tokio::task::JoinSet;
use tower_service::Service;

#[tokio::test(flavor = "current_thread")]
async fn axum_streaming_http_uses_authenticated_transport() {
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
                get(|Extension(peer): Extension<PeerIdentity>| async move {
                    peer.public_key().to_string()
                }),
            )
            .route("/echo", post(|body: Bytes| async move { body }));
        let mut tasks = JoinSet::new();
        tasks.spawn(server.serve(router));
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
        client.close().await;
        handle.shutdown().await.unwrap();
    })
    .await
    .expect("HTTP test timed out");
}

#[tokio::test(flavor = "current_thread")]
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
        tasks.spawn(
            server.serve(tower::service_fn(|_: Request<Incoming>| async {
                Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(
                    b"ok",
                ))))
            })),
        );
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

// Each cloned service must become ready before it can handle a request.
#[derive(Clone, Default)]
struct EchoService {
    ready: bool,
}

impl Service<Request<Incoming>> for EchoService {
    type Response = Response<Full<Bytes>>;
    type Error = Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        if self.ready {
            Poll::Ready(Ok(()))
        } else {
            self.ready = true;
            cx.waker().wake_by_ref();
            Poll::Pending
        }
    }

    fn call(&mut self, request: Request<Incoming>) -> Self::Future {
        assert!(std::mem::replace(&mut self.ready, false));
        Box::pin(async move {
            let peer = *request.extensions().get::<PeerIdentity>().unwrap();
            let body = request.into_body().collect().await?.to_bytes();
            Ok(Response::builder()
                .header("x-peer-key", peer.public_key().to_string())
                .body(Full::new(body))?)
        })
    }
}

#[tokio::test(flavor = "current_thread")]
async fn tower_service_honors_readiness_and_isolates_peer_identity() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server_key = PrivateKey::from_bytes([24; 32]);
        let server_public = server_key.public_key();
        let keys = [
            PrivateKey::from_bytes([25; 32]),
            PrivateKey::from_bytes([26; 32]),
        ];
        let server = Server::builder(server_key)
            .authorized_peers(keys.iter().map(PrivateKey::public_key))
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr();
        let (shutdown, stopped) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(server.serve_with_shutdown(EchoService::default(), async {
            let _ = stopped.await;
        }));
        let mut requests = JoinSet::new();
        for key in keys {
            requests.spawn(async move {
                let peer = key.public_key();
                let client = Client::builder(key)
                    .remote(address, server_public)
                    .connect()
                    .await
                    .unwrap();
                for body in [Vec::new(), vec![0xa5; 128 * 1024]] {
                    let response = client
                        .http()
                        .post("/echo")
                        .header("x-peer-key", "untrusted identity")
                        .body(body.clone())
                        .send()
                        .await
                        .unwrap();
                    assert_eq!(response.headers()["x-peer-key"], peer.to_string());
                    assert_eq!(response.bytes().await.unwrap().as_ref(), body);
                }
                client.close().await;
            });
        }
        while let Some(result) = requests.join_next().await {
            result.unwrap();
        }
        shutdown.send(()).unwrap();
        task.await.unwrap().unwrap();
    })
    .await
    .expect("Tower service test timed out");
}
