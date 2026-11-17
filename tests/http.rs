#![cfg(all(feature = "client", feature = "server"))]
use std::future::Future;
use std::pin::Pin;
use std::task::{Context, Poll};
use std::time::Duration;

use axum::routing::{get, post};
use axum::{Extension, Router};
use bytes::Bytes;
use http::{Request, Response};
use http_body_util::{BodyExt, Empty, Full};
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
            .authorize(Box::new(move |key| key == client_public))
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
        let request = Request::builder()
            .uri("/whoami")
            .header("host", "identity-service")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = client.send(request).await.unwrap();
        assert_eq!(response.status(), http::StatusCode::OK);
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            client_public.to_string()
        );
        let body = vec![0x5a; 128 * 1024];
        let request = Request::builder()
            .method("POST")
            .uri("/echo")
            .header("host", "echo-service")
            .body(Full::new(Bytes::from(body.clone())))
            .unwrap();
        let response = client.send(request).await.unwrap();
        assert_eq!(
            response
                .into_body()
                .collect()
                .await
                .unwrap()
                .to_bytes()
                .as_ref(),
            body
        );
        for _ in 0..5 {
            let client = client.clone();
            tasks.spawn(async move {
                let request = Request::builder()
                    .uri("/whoami")
                    .header("host", "identity-service")
                    .body(Empty::<Bytes>::new())
                    .unwrap();
                let response = client.send(request).await?;
                let body = response.into_body().collect().await?.to_bytes();
                assert_eq!(body, client_public.to_string());
                Ok::<_, Error>(())
            });
        }
        for _ in 0..5 {
            tasks.join_next().await.unwrap().unwrap().unwrap();
        }
        for uri in ["http://example.com/", "example.com:443", "*"] {
            let request = Request::builder()
                .uri(uri)
                .body(Empty::<Bytes>::new())
                .unwrap();
            assert!(client.send(request).await.is_err());
        }
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
            .authorize(Box::new(move |key| key == peer))
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
        let request = Request::builder()
            .uri("/")
            .header("host", "service")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = client.send(request).await.unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "ok"
        );
        handle.revoke_peer(peer).await.unwrap();
        // The server must stop serving revoked peers immediately; the remote
        // learns revocation through closure or a caller-controlled timeout.
        let request = Request::builder()
            .uri("/")
            .header("host", "service")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert!(!matches!(
            tokio::time::timeout(Duration::from_millis(300), client.send(request)).await,
            Ok(Ok(_))
        ));
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
            let host = request.headers()["host"].clone();
            let body = request.into_body().collect().await?.to_bytes();
            Ok(Response::builder()
                .header("x-peer-key", peer.public_key().to_string())
                .header("x-request-host", host)
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
        let public_keys: Vec<_> = keys.iter().map(PrivateKey::public_key).collect();
        let server = Server::builder(server_key)
            .authorize(Box::new(move |key| public_keys.contains(&key)))
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
                    let request = Request::builder()
                        .method("POST")
                        .uri("/echo")
                        .header("host", "echo-service")
                        .header("x-peer-key", "untrusted identity")
                        .body(Full::new(std::io::Cursor::new(body.clone())))
                        .unwrap();
                    let response = client.send(request).await.unwrap();
                    assert_eq!(response.headers()["x-peer-key"], peer.to_string());
                    assert_eq!(response.headers()["x-request-host"], "echo-service");
                    // Feed the streaming response directly into a second request.
                    let request = Request::builder()
                        .method("POST")
                        .uri("/echo")
                        .header("host", "echo-service")
                        .body(response.into_body())
                        .unwrap();
                    let response = client.send(request).await.unwrap();
                    assert_eq!(response.headers()["x-peer-key"], peer.to_string());
                    assert_eq!(response.headers()["x-request-host"], "echo-service");
                    assert_eq!(
                        response
                            .into_body()
                            .collect()
                            .await
                            .unwrap()
                            .to_bytes()
                            .as_ref(),
                        body
                    );
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

#[tokio::test(flavor = "current_thread")]
async fn handler_panics_are_logged_without_stopping_other_streams() {
    use std::io::Write;
    use std::sync::{Arc, Mutex};

    struct Log(Arc<Mutex<Vec<u8>>>);
    impl Write for Log {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let log = Arc::new(Mutex::new(Vec::new()));
    let output = log.clone();
    let subscriber = tracing_subscriber::fmt()
        .without_time()
        .with_writer(move || Log(output.clone()))
        .finish();
    let _guard = tracing::subscriber::set_default(subscriber);
    tokio::time::timeout(Duration::from_secs(10), async {
        let server_key = PrivateKey::from_bytes([90; 32]);
        let server_public = server_key.public_key();
        let client_key = PrivateKey::from_bytes([91; 32]);
        let peer = client_key.public_key();
        let server = Server::builder(server_key)
            .authorize(Box::new(move |key| key == peer))
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let handle = server.handle();
        let address = server.local_addr();
        let service = tower::service_fn(|request: Request<Incoming>| async move {
            assert_ne!(request.uri().path(), "/panic", "intentional handler panic");
            Ok::<_, std::convert::Infallible>(Response::new(Full::new(Bytes::from_static(b"ok"))))
        });
        let task = tokio::spawn(server.serve(service));
        let client = Client::builder(client_key)
            .remote(address, server_public)
            .connect()
            .await
            .unwrap();
        let request = Request::builder()
            .uri("/panic")
            .header("host", "test")
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert!(client.send(request).await.is_err());
        loop {
            if String::from_utf8_lossy(&log.lock().unwrap()).contains("HTTP stream task failed") {
                break;
            }
            tokio::task::yield_now().await;
        }
        let request = Request::builder()
            .uri("/")
            .header("host", "test")
            .body(Empty::<Bytes>::new())
            .unwrap();
        let response = client.send(request).await.unwrap();
        assert_eq!(
            response.into_body().collect().await.unwrap().to_bytes(),
            "ok"
        );
        client.close().await;
        handle.shutdown().await.unwrap();
        task.await.unwrap().unwrap();
    })
    .await
    .expect("handler panic test timed out");
}
