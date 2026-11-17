use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::UdpSocket,
};
use wireguard_quic::{Client, PrivateKey, PublicKey, RejectionReason, Server};

fn key(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes([byte; 32])
}

#[tokio::test]
async fn authenticated_streams_bind_identity_to_each_peer() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server_key = key(1);
        let server_public = server_key.public_key();
        let alice = key(2);
        let alice_public = alice.public_key();
        let bob = key(3);
        let bob_public = bob.public_key();
        let mut server = Server::builder(server_key)
            .authorized_peers([alice_public, bob_public])
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr();
        let server_task = async {
            let first = server.accept().await.unwrap();
            let second = server.accept().await.unwrap();
            assert_ne!(first.peer_identity(), second.peer_identity());
            for connection in [first, second] {
                let mut stream = connection.accept_bi().await.unwrap();
                let mut data = vec![0; 128 * 1024];
                stream.read_exact(&mut data).await.unwrap();
                assert_eq!(data, vec![0xab; 128 * 1024]);
                stream
                    .write_all(connection.peer_identity().public_key().as_bytes())
                    .await
                    .unwrap();
                stream.shutdown().await.unwrap();
                connection.closed().await;
            }
        };
        let client_task = async {
            let alice = Client::builder(alice)
                .remote(address, server_public)
                .connect()
                .await
                .unwrap();
            let bob = Client::builder(bob)
                .remote(address, server_public)
                .connect()
                .await
                .unwrap();
            for (client, public) in [(alice, alice_public), (bob, bob_public)] {
                assert_eq!(client.peer_identity().public_key(), server_public);
                let mut stream = client.connection().open_bi().await.unwrap();
                stream.write_all(&vec![0xab; 128 * 1024]).await.unwrap();
                stream.shutdown().await.unwrap();
                let mut reply = Vec::new();
                stream.read_to_end(&mut reply).await.unwrap();
                assert_eq!(reply, public.as_bytes());
                client.close().await;
            }
        };
        tokio::join!(server_task, client_task);
    })
    .await
    .expect("transport timed out");
}

#[tokio::test]
async fn wrong_key_and_unauthorized_clients_never_connect() {
    let server_key = key(4);
    let public = server_key.public_key();
    let server = Server::builder(server_key)
        .authorized_peers([key(5).public_key()])
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let address = server.local_addr();
    assert!(
        Client::builder(key(6))
            .remote(address, public)
            .connect_timeout(Duration::from_millis(350))
            .connect()
            .await
            .is_err()
    );
    assert!(
        Client::builder(key(5))
            .remote(address, key(7).public_key())
            .connect_timeout(Duration::from_millis(350))
            .connect()
            .await
            .is_err()
    );
}

#[tokio::test]
async fn raw_udp_rejections_are_preserved_and_fallback_can_reply() {
    use quinn::AsyncUdpSocket;
    use std::sync::Arc;
    let server = Server::builder(key(8)).bind("127.0.0.1:0").await.unwrap();
    let mut rejected = server.take_rejected().unwrap();
    let fallback: Arc<dyn AsyncUdpSocket> = server.take_fallback_socket().unwrap();
    assert!(server.take_fallback_socket().is_err());
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.send_to(b"ordinary UDP", server.local_addr())
        .await
        .unwrap();
    let packet = tokio::time::timeout(Duration::from_secs(1), rejected.recv())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(packet.reason, RejectionReason::NonWireGuard);
    assert_eq!(&packet.data[..], b"ordinary UDP");
    assert_eq!(packet.source, udp.local_addr().unwrap());
    let mut buffer = [0; 64];
    let mut meta = [quinn::udp::RecvMeta::default()];
    let received = std::future::poll_fn(|cx| {
        let mut bufs = [std::io::IoSliceMut::new(&mut buffer)];
        fallback.poll_recv(cx, &mut bufs, &mut meta)
    })
    .await
    .unwrap();
    assert_eq!(received, 1);
    assert_eq!(&buffer[..meta[0].len], b"ordinary UDP");
    let transmit = quinn::udp::Transmit {
        destination: packet.source,
        ecn: None,
        contents: b"reply",
        segment_size: None,
        src_ip: None,
    };
    loop {
        match fallback.try_send(&transmit) {
            Ok(()) => break,
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                let mut poller = fallback.clone().create_io_poller();
                std::future::poll_fn(|cx| poller.as_mut().poll_writable(cx))
                    .await
                    .unwrap();
            }
            Err(error) => panic!("{error}"),
        }
    }
    let (len, source) = tokio::time::timeout(Duration::from_secs(1), udp.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..len], b"reply");
    assert_eq!(source, server.local_addr());
}

#[tokio::test]
async fn key_formats_roundtrip_and_debug_redacts_private_key() {
    let private = PrivateKey::generate().unwrap();
    let decoded: PrivateKey = private.to_base64().parse().unwrap();
    assert_eq!(private.public_key(), decoded.public_key());
    let public: PublicKey = private.public_key().to_string().parse().unwrap();
    assert_eq!(public, private.public_key());
    assert_eq!(format!("{private:?}"), "PrivateKey([REDACTED])");
    assert!("bad".parse::<PrivateKey>().is_err());
    assert!("bad".parse::<PublicKey>().is_err());
}

#[tokio::test]
async fn encrypted_transport_survives_loss_replay_and_udp_roaming() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    };
    use tokio::task::JoinSet;
    tokio::time::timeout(Duration::from_secs(15),async {
        let server_key=key(30);let public=server_key.public_key();let client_key=key(31);
        let mut server=Server::builder(server_key).authorized_peers([client_key.public_key()]).bind("127.0.0.1:0").await.unwrap();
        let server_address=server.local_addr();
        let front=UdpSocket::bind("127.0.0.1:0").await.unwrap();let relay_address=front.local_addr().unwrap();
        let back1=UdpSocket::bind("127.0.0.1:0").await.unwrap();let back2=UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let switched=Arc::new(AtomicBool::new(false));let changed=switched.clone();
        let marker=vec![0x6c;64];let needle=marker.clone();
        let mut tasks=JoinSet::new();
        tasks.spawn(async move {
            let mut a=vec![0;65536];let mut b=vec![0;65536];let mut c=vec![0;65536];
            let mut client_address=None;let mut count=0;
            loop {
                tokio::select! {
                    received=front.recv_from(&mut a)=>{
                        let (len,source)=received.unwrap();client_address=Some(source);
                        assert!(!a[..len].windows(needle.len()).any(|window|window==needle));
                        let socket=if changed.load(Ordering::SeqCst) {&back2}else{&back1};
                        count+=1;
                        if a[..len].starts_with(&[4,0,0,0]) {
                            if count%7==0 {continue;}
                            // Duplicate every delivered data packet. WG must reject replays.
                            socket.send_to(&a[..len],server_address).await.unwrap();
                        }
                        socket.send_to(&a[..len],server_address).await.unwrap();
                    }
                    received=back1.recv_from(&mut b)=>{let (len,_)=received.unwrap();if !changed.load(Ordering::SeqCst) && let Some(client)=client_address {front.send_to(&b[..len],client).await.unwrap();}}
                    received=back2.recv_from(&mut c)=>{let (len,_)=received.unwrap();if let Some(client)=client_address {front.send_to(&c[..len],client).await.unwrap();}}
                }
            }
        });
        tasks.spawn(async move {
            let connection=server.accept().await.unwrap();
            for _ in 0..2 {
                let mut stream=connection.accept_bi().await.unwrap();
                let mut request=vec![0;128*1024];stream.read_exact(&mut request).await.unwrap();
                stream.write_all(&request).await.unwrap();stream.shutdown().await.unwrap();
            }
            connection.closed().await;
        });
        let client=Client::builder(client_key).remote(relay_address,public).connect().await.unwrap();
        let data=marker.repeat(2048);
        for round in 0..2 {
            if round==1 {switched.store(true,Ordering::SeqCst);}
            let mut stream=client.connection().open_bi().await.unwrap();stream.write_all(&data).await.unwrap();stream.shutdown().await.unwrap();
            let mut response=Vec::new();stream.read_to_end(&mut response).await.unwrap();assert_eq!(response,data);
        }
        client.close().await;
    }).await.expect("loss/roaming test timed out");
}

#[tokio::test]
async fn standard_tls_quic_and_wireguard_quic_share_one_udp_port() {
    use std::sync::Arc;
    tokio::time::timeout(Duration::from_secs(10), async {
        let server_key = key(40);
        let public = server_key.public_key();
        let client_key = key(41);
        let mut server = Server::builder(server_key)
            .authorized_peers([client_key.public_key()])
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
        let certificate = certified.cert.der().clone();
        let tls = quinn::ServerConfig::with_single_cert(
            vec![certificate.clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(certified.signing_key.serialize_der())
                .into(),
        )
        .unwrap();
        let ordinary = quinn::Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            Some(tls),
            server.take_fallback_socket().unwrap(),
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let mut normal_client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        normal_client.set_default_client_config(
            quinn::ClientConfig::with_root_certificates(Arc::new(roots)).unwrap(),
        );
        let tls_server = async {
            let connection = ordinary.accept().await.unwrap().await.unwrap();
            let (mut send, mut recv) = connection.accept_bi().await.unwrap();
            assert_eq!(recv.read_to_end(64).await.unwrap(), b"standard QUIC");
            send.write_all(b"TLS reply").await.unwrap();
            send.finish().unwrap();
            send.stopped().await.unwrap();
        };
        let wg_server = async {
            let connection = server.accept().await.unwrap();
            assert_eq!(
                connection.peer_identity().public_key(),
                client_key.public_key()
            );
            let mut stream = connection.accept_bi().await.unwrap();
            let mut input = [0; 2];
            stream.read_exact(&mut input).await.unwrap();
            assert_eq!(&input, b"WG");
            stream.write_all(b"WG reply").await.unwrap();
            stream.shutdown().await.unwrap();
            connection.closed().await;
        };
        let clients = async {
            let connection = normal_client
                .connect(address, "localhost")
                .unwrap()
                .await
                .unwrap();
            let (mut send, mut recv) = connection.open_bi().await.unwrap();
            send.write_all(b"standard QUIC").await.unwrap();
            send.finish().unwrap();
            assert_eq!(recv.read_to_end(64).await.unwrap(), b"TLS reply");
            let client = Client::builder(key(41))
                .remote(address, public)
                .connect()
                .await
                .unwrap();
            let mut stream = client.connection().open_bi().await.unwrap();
            stream.write_all(b"WG").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut response = Vec::new();
            stream.read_to_end(&mut response).await.unwrap();
            assert_eq!(response, b"WG reply");
            client.close().await;
            connection.close(0u32.into(), b"done");
            normal_client.wait_idle().await;
        };
        tokio::join!(tls_server, wg_server, clients);
    })
    .await
    .expect("shared QUIC port test timed out");
}
