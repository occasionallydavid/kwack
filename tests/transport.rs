use std::time::Duration;

use kwack::{Client, PrivateKey, PublicKey, Server};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::UdpSocket;

fn key(byte: u8) -> PrivateKey {
    PrivateKey::from_bytes([byte; 32])
}

#[tokio::test(flavor = "current_thread")]
async fn authenticated_streams_bind_identity_to_each_peer() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server_key = key(1);
        let server_public = server_key.public_key();
        let alice = key(2);
        let alice_public = alice.public_key();
        let bob = key(3);
        let bob_public = bob.public_key();
        let mut server = Server::builder(server_key)
            .authorize(Box::new(move |key| {
                [alice_public, bob_public].contains(&key)
            }))
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr();
        let server_task = async {
            let first = server.accept().await.unwrap();
            let second = server.accept().await.unwrap();
            assert_ne!(first.peer_identity(), second.peer_identity());
            let mut handlers = tokio::task::JoinSet::new();
            for connection in [first, second] {
                handlers.spawn(async move {
                    let mut stream = connection.accept_stream().await.unwrap();
                    let mut data = vec![0; 128 * 1024];
                    stream.read_exact(&mut data).await.unwrap();
                    assert_eq!(data, vec![0xab; 128 * 1024]);
                    stream
                        .write_all(connection.peer_identity().public_key().as_bytes())
                        .await
                        .unwrap();
                    stream.shutdown().await.unwrap();
                    connection.closed().await;
                });
            }
            while let Some(result) = handlers.join_next().await {
                result.unwrap();
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
            let alice_stream = alice.connection().open_stream().await.unwrap();
            let bob_stream = bob.connection().open_stream().await.unwrap();
            for (client, public, mut stream) in [
                (alice, alice_public, alice_stream),
                (bob, bob_public, bob_stream),
            ] {
                assert_eq!(client.peer_identity().public_key(), server_public);
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

#[tokio::test(flavor = "current_thread")]
async fn wrong_key_and_unauthorized_clients_never_connect() {
    let server_key = key(4);
    let public = server_key.public_key();
    let server = Server::builder(server_key)
        .authorize(Box::new(|peer| peer == key(5).public_key()))
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

#[tokio::test(flavor = "current_thread")]
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

#[tokio::test(flavor = "current_thread")]
async fn encrypted_transport_survives_loss_replay_and_udp_roaming() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};

    tokio::time::timeout(Duration::from_secs(20), async {
        let server_key = key(30);
        let public = server_key.public_key();
        let peer = key(31).public_key();
        let mut server = Server::builder(server_key)
            .authorize(Box::new(move |key| key == peer))
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr();
        let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay = front.local_addr().unwrap();
        let back1 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let back2 = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let switched = Arc::new(AtomicBool::new(false));
        let changed = switched.clone();
        let marker = vec![0x6c; 64];
        let needle = marker.clone();
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            let mut a = [0; 65536];
            let mut b = [0; 65536];
            let mut c = [0; 65536];
            let mut client_address = None;
            let mut count = 0;
            let mut reply_count = 0;
            let mut held: Option<Vec<u8>> = None;
            let mut held_reply: Option<Vec<u8>> = None;
            let mut dropped_response = false;
            let mut dropped_first_kcp = false;
            let mut reorder_timer = tokio::time::interval(Duration::from_millis(20));
            loop {
                tokio::select! {
                    _ = reorder_timer.tick() => {
                        if let Some(packet) = held.take() {
                            let socket = if changed.load(Ordering::SeqCst) { &back2 } else { &back1 };
                            socket.send_to(&packet, address).await.unwrap();
                        }
                        if let Some(packet) = held_reply.take() && let Some(client) = client_address {
                            front.send_to(&packet, client).await.unwrap();
                        }
                    }
                    received = front.recv_from(&mut a) => {
                        let (len, source) = received.unwrap();
                        client_address = Some(source);
                        assert!(len <= 1200);
                        assert!(!a[..len].windows(needle.len()).any(|w| w == needle));
                        let socket = if changed.load(Ordering::SeqCst) { &back2 } else { &back1 };
                        if len > 4 && a[4] == 3 {
                            count += 1;
                            if count % 7 == 0 { continue; }
                            if count % 11 == 0 && held.is_none() {
                                held = Some(a[..len].to_vec());
                                continue;
                            }
                            // Exact ciphertext replay: only one copy may reach inner KCP.
                            socket.send_to(&a[..len], address).await.unwrap();
                        }
                        socket.send_to(&a[..len], address).await.unwrap();
                        if let Some(packet) = held.take() {
                            socket.send_to(&packet, address).await.unwrap();
                        }
                    }
                    received = back1.recv_from(&mut b) => {
                        let (len, _) = received.unwrap();
                        assert!(len <= 1200);
                        assert!(!b[..len].windows(needle.len()).any(|w| w == needle));
                        if b[4] == 2 && !dropped_response {
                            dropped_response = true;
                            continue;
                        }
                        if b[4] == 3 && !dropped_first_kcp {
                            dropped_first_kcp = true;
                            continue;
                        }
                        if !changed.load(Ordering::SeqCst) && let Some(client) = client_address {
                            reply_count += 1;
                            if reply_count % 9 == 0 { continue; }
                            if reply_count % 5 == 0 && held_reply.is_none() {
                                held_reply = Some(b[..len].to_vec());
                                continue;
                            }
                            front.send_to(&b[..len], client).await.unwrap();
                            if let Some(packet) = held_reply.take() {
                                front.send_to(&packet, client).await.unwrap();
                            }
                        }
                    }
                    received = back2.recv_from(&mut c) => {
                        let (len, _) = received.unwrap();
                        if let Some(client) = client_address {
                            front.send_to(&c[..len], client).await.unwrap();
                        }
                    }
                }
            }
        });
        tasks.spawn(async move {
            let connection = server.accept().await.unwrap();
            for _ in 0..2 {
                let mut stream = connection.accept_stream().await.unwrap();
                let mut data = Vec::new();
                stream.read_to_end(&mut data).await.unwrap();
                stream.write_all(&data).await.unwrap();
                stream.shutdown().await.unwrap();
            }
            connection.closed().await;
        });
        let client = Client::builder(key(31))
            .remote(relay, public)
            .connect()
            .await
            .unwrap();
        let data = marker.repeat(2048);
        for round in 0..2 {
            if round == 1 {
                switched.store(true, Ordering::SeqCst);
            }
            let mut stream = client.connection().open_stream().await.unwrap();
            stream.write_all(&data).await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            stream.read_to_end(&mut reply).await.unwrap();
            assert_eq!(reply, data);
        }
        client.close().await;
    })
    .await
    .expect("loss/reordering/roaming test timed out");
}

#[tokio::test(flavor = "current_thread")]
async fn authorization_callback_observes_live_policy_changes() {
    use std::collections::HashSet;
    use std::sync::atomic::{AtomicUsize, Ordering};
    use std::sync::{Arc, RwLock};
    tokio::time::timeout(Duration::from_secs(10), async {
        let server_key = key(50);
        let server_public = server_key.public_key();
        let alice = key(51).public_key();
        let bob = key(52).public_key();
        let policy = Arc::new(RwLock::new(HashSet::new()));
        let lookup = policy.clone();
        let calls = Arc::new(AtomicUsize::new(0));
        let observed = calls.clone();
        let mut count = 0;
        let mut server = Server::builder(server_key)
            .authorize(Box::new(move |key| {
                count += 1;
                observed.store(count, Ordering::SeqCst);
                lookup.read().unwrap().contains(&key)
            }))
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let address = server.local_addr();
        let handle = server.handle();
        let task = tokio::spawn(async move {
            for expected in [alice, bob] {
                let connection = server.accept().await.unwrap();
                assert_eq!(connection.peer_identity().public_key(), expected);
                let mut stream = connection.accept_stream().await.unwrap();
                let mut byte = [0];
                stream.read_exact(&mut byte).await.unwrap();
                stream.write_all(&byte).await.unwrap();
                stream.shutdown().await.unwrap();
                connection.closed().await;
            }
        });
        assert!(
            Client::builder(key(51))
                .remote(address, server_public)
                .connect_timeout(Duration::from_millis(150))
                .connect()
                .await
                .is_err()
        );
        for (byte, public) in [(51, alice), (52, bob)] {
            policy.write().unwrap().insert(public);
            let client = Client::builder(key(byte))
                .remote(address, server_public)
                .connect()
                .await
                .unwrap();
            let mut stream = client.connection().open_stream().await.unwrap();
            stream.write_all(b"x").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut echoed = [0];
            stream.read_exact(&mut echoed).await.unwrap();
            assert_eq!(echoed, [b'x']);
            client.close().await;
            policy.write().unwrap().remove(&public);
            assert!(
                Client::builder(key(byte))
                    .remote(address, server_public)
                    .connect_timeout(Duration::from_millis(150))
                    .connect()
                    .await
                    .is_err()
            );
        }
        task.await.unwrap();
        assert!(calls.load(Ordering::SeqCst) >= 5);
        handle.shutdown().await.unwrap();
    })
    .await
    .expect("dynamic admission test timed out");
}

#[tokio::test(flavor = "current_thread")]
async fn no_authorization_callback_denies_every_peer() {
    let server_key = key(53);
    let server_public = server_key.public_key();
    let server = Server::builder(server_key)
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    assert!(
        Client::builder(key(54))
            .remote(server.local_addr(), server_public)
            .connect_timeout(Duration::from_millis(150))
            .connect()
            .await
            .is_err()
    );
}

#[tokio::test(flavor = "current_thread")]
async fn queued_revocation_closes_connections_even_if_caller_cancels() {
    use std::future::{Future, poll_fn};
    use std::task::Poll;
    tokio::time::timeout(Duration::from_secs(10), async {
        let server_key = key(55);
        let server_public = server_key.public_key();
        let client_key = key(56);
        let peer = client_key.public_key();
        let mut server = Server::builder(server_key)
            .authorize(Box::new(|_| true))
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let handle = server.handle();
        let _client = Client::builder(client_key)
            .remote(server.local_addr(), server_public)
            .connect()
            .await
            .unwrap();
        let _stream = _client.connection().open_stream().await.unwrap();
        let connection = server.accept().await.unwrap();
        let mut revoke = Box::pin(handle.revoke_peer(peer));
        poll_fn(|cx| {
            assert!(revoke.as_mut().poll(cx).is_pending());
            Poll::Ready(())
        })
        .await;
        drop(revoke);
        connection.closed().await;
    })
    .await
    .expect("cancelled revocation test timed out");
}

#[tokio::test(flavor = "current_thread")]
async fn dropping_last_stream_drains_finished_writes() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let server_key = key(80);
        let server_public = server_key.public_key();
        let client_key = key(81);
        let peer = client_key.public_key();
        let mut server = Server::builder(server_key)
            .authorize(Box::new(move |key| key == peer))
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let client = Client::builder(client_key)
            .remote(server.local_addr(), server_public)
            .connect()
            .await
            .unwrap();
        let data = vec![0xa5; 128 * 1024];
        let mut stream = client.connection().open_stream().await.unwrap();
        stream.write_all(&data).await.unwrap();
        stream.shutdown().await.unwrap();
        let connection = server.accept().await.unwrap();
        drop(client);
        drop(stream);
        let mut received = Vec::new();
        let mut stream = connection.accept_stream().await.unwrap();
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, data);
    })
    .await
    .expect("stream drain timed out");
}

#[tokio::test(flavor = "current_thread")]
async fn simultaneous_conversations_work_in_both_directions() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let private = key(100);
        let public = private.public_key();
        let mut server = Server::builder(private)
            .authorize(Box::new(|_| true))
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let client = Client::builder(key(101))
            .remote(server.local_addr(), public)
            .connect()
            .await
            .unwrap();
        let bootstrap = client.connection().open_stream().await.unwrap();
        let server_connection = server.accept().await.unwrap();
        let accepted_bootstrap = server_connection.accept_stream().await.unwrap();
        drop(bootstrap);
        drop(accepted_bootstrap);
        let mut tasks = tokio::task::JoinSet::new();
        for (opener, receiver, parity) in [
            (client.connection().clone(), server_connection.clone(), 1),
            (server_connection.clone(), client.connection().clone(), 0),
        ] {
            tasks.spawn(async move {
                let mut handlers = tokio::task::JoinSet::new();
                for _ in 0..12 {
                    let mut stream = receiver.accept_stream().await.unwrap();
                    assert_eq!(stream.conversation_id() % 2, parity);
                    handlers.spawn(async move {
                        let mut request = Vec::new();
                        stream.read_to_end(&mut request).await.unwrap();
                        stream.write_all(&request).await.unwrap();
                        stream.shutdown().await.unwrap();
                    });
                }
                while let Some(result) = handlers.join_next().await {
                    result.unwrap();
                }
            });
            for n in 0..12 {
                // Each conversation receives a different pattern, including record tag values.
                let data: Vec<u8> = (0..48 * 1024).map(|i| (i + n * 31) as u8).collect();
                let mut stream = opener.open_stream().await.unwrap();
                assert_eq!(stream.conversation_id() % 2, parity);
                tasks.spawn(async move {
                    stream.write_all(&data).await.unwrap();
                    stream.shutdown().await.unwrap();
                    assert!(stream.write_all(b"after FIN").await.is_err());
                    let mut reply = Vec::new();
                    stream.read_to_end(&mut reply).await.unwrap();
                    assert_eq!(reply, data);
                });
            }
        }
        while let Some(result) = tasks.join_next().await {
            result.unwrap();
        }
        client.close().await;
    })
    .await
    .expect("bidirectional conversation test timed out");
}

#[tokio::test(flavor = "current_thread")]
async fn a_blocked_conversation_does_not_block_another() {
    tokio::time::timeout(Duration::from_secs(15), async {
        let private = key(102);
        let public = private.public_key();
        let mut server = Server::builder(private)
            .authorize(Box::new(|_| true))
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let client = Client::builder(key(103))
            .remote(server.local_addr(), public)
            .connect()
            .await
            .unwrap();
        let mut blocked = client.connection().open_stream().await.unwrap();
        let connection = server.accept().await.unwrap();
        let mut slow_reader = connection.accept_stream().await.unwrap();
        let data = vec![0x63; 2 * 1024 * 1024];
        // Receiver doesn't consume bytes: the bounded queue and KCP window must stall writes.
        assert!(
            tokio::time::timeout(Duration::from_millis(400), blocked.write_all(&data))
                .await
                .is_err()
        );
        let mut healthy = client.connection().open_stream().await.unwrap();
        let mut receiver = connection.accept_stream().await.unwrap();
        healthy.write_all(b"independent").await.unwrap();
        healthy.shutdown().await.unwrap();
        let mut got = Vec::new();
        receiver.read_to_end(&mut got).await.unwrap();
        assert_eq!(got, b"independent");
        // Dropping the stalled stream finishes the bytes accepted before cancellation.
        drop(blocked);
        let mut partial = Vec::new();
        slow_reader.read_to_end(&mut partial).await.unwrap();
        assert!(!partial.is_empty() && partial.len() < data.len());
        assert!(partial.iter().all(|b| *b == 0x63));
        client.close().await;
    })
    .await
    .expect("conversation backpressure test timed out");
}

#[tokio::test(flavor = "current_thread")]
async fn optional_psk_is_required_for_session_confirmation() {
    let private = key(104);
    let public = private.public_key();
    let mut server = Server::builder(private)
        .preshared_key([0x91; 32])
        .authorize(Box::new(|_| true))
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    for psk in [[0; 32], [0x92; 32]] {
        assert!(
            Client::builder(key(105))
                .remote(server.local_addr(), public)
                .preshared_key(psk)
                .connect_timeout(Duration::from_millis(300))
                .connect()
                .await
                .is_err()
        );
    }
    assert!(
        tokio::time::timeout(Duration::from_millis(50), server.accept())
            .await
            .is_err()
    );
    let client = Client::builder(key(105))
        .remote(server.local_addr(), public)
        .preshared_key([0x91; 32])
        .connect()
        .await
        .unwrap();
    let _stream = client.connection().open_stream().await.unwrap();
    let connection = tokio::time::timeout(Duration::from_secs(1), server.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        connection.peer_identity().public_key(),
        key(105).public_key()
    );
    client.close().await;
}

#[tokio::test(flavor = "current_thread")]
async fn unknown_and_truncated_packets_get_no_network_response() {
    let private = key(106);
    let public = private.public_key();
    let mut server = Server::builder(private)
        .authorize(Box::new(|_| true))
        .bind("127.0.0.1:0")
        .await
        .unwrap();
    let mut rejections = server.take_rejected().unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for len in 0..200 {
        let mut packet = vec![0; len];
        if len >= 5 {
            packet[..5].copy_from_slice(b"KW\x01\x00\x01");
        }
        socket.send_to(&packet, server.local_addr()).await.unwrap();
    }
    let mut buf = [0; 1500];
    assert!(
        tokio::time::timeout(Duration::from_millis(150), socket.recv_from(&mut buf))
            .await
            .is_err()
    );
    let rejected = rejections.recv().await.unwrap();
    assert_eq!(rejected.source, socket.local_addr().unwrap());
    assert!(rejected.data.is_empty());
    // Malformed unauthenticated inputs must not stop the dispatcher.
    let client = Client::builder(key(107))
        .remote(server.local_addr(), public)
        .connect()
        .await
        .unwrap();
    let _stream = client.connection().open_stream().await.unwrap();
    let connection = server.accept().await.unwrap();
    assert_eq!(
        connection.peer_identity().public_key(),
        key(107).public_key()
    );
    client.close().await;
}

#[tokio::test(flavor = "current_thread")]
async fn closing_retries_lost_close_and_ack_and_stops_server_udp() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};

    tokio::time::timeout(Duration::from_secs(20), async {
        let private = key(108);
        let public = private.public_key();
        let mut server = Server::builder(private).authorize(Box::new(|_| true))
            .bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr();
        let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_address = front.local_addr().unwrap();
        let back = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let closing = Arc::new(AtomicBool::new(false));
        let closing_observer = closing.clone();
        let drops = Arc::new(AtomicUsize::new(0));
        let drop_observer = drops.clone();
        let (udp_events, mut udp_received) = tokio::sync::mpsc::channel(256);
        let mut tasks = tokio::task::JoinSet::new();
        tasks.spawn(async move {
            let mut a = [0; 65536];
            let mut b = [0; 65536];
            let mut client = None;
            let mut dropped_close = false;
            let mut dropped_ack = false;
            loop {
                tokio::select! {
                    received = front.recv_from(&mut a) => {
                        let (len, source) = received.unwrap();
                        client = Some(source);
                        // One-byte encrypted control packets are 46 bytes long.
                        if closing_observer.load(Ordering::SeqCst) && len == 46 && !dropped_close {
                            dropped_close = true;
                            drop_observer.fetch_add(1, Ordering::SeqCst);
                            continue;
                        }
                        back.send_to(&a[..len], address).await.unwrap();
                    }
                    received = back.recv_from(&mut b) => {
                        let (len, _) = received.unwrap();
                        let _ = udp_events.try_send(());
                        if closing_observer.load(Ordering::SeqCst) && len == 46 && !dropped_ack {
                            dropped_ack = true;
                            drop_observer.fetch_add(1, Ordering::SeqCst);
                            continue;
                        }
                        if let Some(client) = client { front.send_to(&b[..len], client).await.unwrap(); }
                    }
                }
            }
        });
        let client = Client::builder(key(109)).remote(relay_address, public).connect().await.unwrap();
        let unread = client.connection().open_stream().await.unwrap();
        let connection = server.accept().await.unwrap();
        let mut sending = connection.accept_stream().await.unwrap();
        let writer = tokio::spawn(async move { sending.write_all(&vec![0x42; 2 * 1024 * 1024]).await });
        tokio::time::sleep(Duration::from_millis(100)).await;
        closing.store(true, Ordering::SeqCst);
        tokio::time::timeout(Duration::from_secs(2), client.close()).await.unwrap();
        assert_eq!(drops.load(Ordering::SeqCst), 2);
        assert!(writer.await.unwrap().is_err());
        connection.closed().await;
        drop(unread);
        drop(client);
        while udp_received.try_recv().is_ok() {}
        // Cover the 10-second keepalive interval as well as pending KCP retries.
        assert!(tokio::time::timeout(Duration::from_secs(11), udp_received.recv()).await.is_err(),
            "server sent UDP after acknowledging client close");
    }).await.expect("session close regression test timed out");
}
