use std::collections::HashMap;
use std::net::SocketAddr;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};
use std::time::Duration;
use std::{fmt, io};

use boringtun::noise::handshake::parse_handshake_anon;
use boringtun::noise::rate_limiter::RateLimiter;
use boringtun::noise::{Packet, Tunn, TunnResult};
use boringtun::x25519;
use bytes::Bytes;
use parking_lot::Mutex;
use quinn::{AsyncUdpSocket, Endpoint};
use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
use tokio::net::UdpSocket;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{JoinHandle, JoinSet};

use crate::socket::{self, Inbound, Outbound, QUEUE, Target, VirtualSocket};
use crate::{Error, PrivateKey, PublicKey, packet};

/// Identity is attached only after a WireGuard-authenticated packet reaches QUIC.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PeerIdentity {
    key: PublicKey,
}
impl PeerIdentity {
    pub fn public_key(&self) -> PublicKey {
        self.key
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RejectionReason {
    NonWireGuard,
    MalformedWireGuard,
    UnauthorizedPeer,
    UnknownSession,
    AuthenticationFailed,
    InvalidInnerPacket,
}

/// Original outer UDP bytes; never contains decrypted tunnel payloads.
#[derive(Debug, Clone)]
pub struct RejectedDatagram {
    pub data: Bytes,
    pub source: SocketAddr,
    /// Bound socket address. A wildcard bind does not reveal the specific destination IP.
    pub local_address: SocketAddr,
    pub reason: RejectionReason,
}

struct Peer {
    tunnel: Tunn,
    remote: Option<SocketAddr>,
    incoming: mpsc::Sender<Inbound>,
}

enum Command {
    Revoke(PublicKey, oneshot::Sender<()>),
    Stop,
}

struct Network {
    local: SocketAddr,
    endpoints: HashMap<PublicKey, Endpoint>,
    outgoing: mpsc::Sender<Outbound>,
    command: mpsc::Sender<Command>,
    rejected: Mutex<Option<mpsc::Receiver<RejectedDatagram>>>,
    fallback: Mutex<Option<mpsc::Receiver<Inbound>>>,
    driver: JoinHandle<()>,
    acceptors: Vec<JoinHandle<()>>,
}
impl Drop for Network {
    fn drop(&mut self) {
        for endpoint in self.endpoints.values() {
            endpoint.close(0u32.into(), b"shutdown");
        }
        self.driver.abort();
        for acceptor in &self.acceptors {
            acceptor.abort();
        }
    }
}
impl Network {
    fn fallback_socket(&self) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        let incoming = self.fallback.lock().take().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::AlreadyExists,
                "fallback socket already taken",
            )
        })?;
        Ok(Arc::new(VirtualSocket {
            incoming: Mutex::new(incoming),
            outgoing: self.outgoing.clone(),
            target: Target::Raw,
            local: self.local,
        }))
    }
}

/// Server configuration. Peers are denied unless explicitly listed.
pub struct ServerBuilder {
    private: PrivateKey,
    peers: Vec<PublicKey>,
}
impl ServerBuilder {
    pub fn authorized_peers(mut self, peers: impl IntoIterator<Item = PublicKey>) -> Self {
        self.peers = peers.into_iter().collect();
        self
    }
    pub async fn bind(self, address: impl tokio::net::ToSocketAddrs) -> Result<Server, Error> {
        let socket = UdpSocket::bind(address).await?;
        let (network, incoming) = start(
            socket,
            self.private,
            self.peers.into_iter().map(|key| (key, None)).collect(),
            false,
        )?;
        Ok(Server {
            network,
            incoming,
            pending: JoinSet::new(),
            accepting: true,
        })
    }
}

/// A listening transport, with one isolated QUIC namespace per authorized public key.
pub struct Server {
    network: Arc<Network>,
    incoming: mpsc::Receiver<(PublicKey, quinn::Incoming)>,
    pending: JoinSet<(PublicKey, Result<quinn::Connection, quinn::ConnectionError>)>,
    accepting: bool,
}
impl Server {
    pub fn builder(private: PrivateKey) -> ServerBuilder {
        ServerBuilder {
            private,
            peers: Vec::new(),
        }
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.network.local
    }
    pub fn handle(&self) -> ServerHandle {
        ServerHandle {
            network: self.network.clone(),
        }
    }
    pub fn take_rejected(&self) -> Option<mpsc::Receiver<RejectedDatagram>> {
        self.network.rejected.lock().take()
    }
    /// Non-WireGuard datagrams are delivered here. Replies use the original bound UDP socket.
    /// Feed this socket to a normal Quinn endpoint to share the port with ordinary QUIC.
    pub fn take_fallback_socket(&self) -> io::Result<Arc<dyn AsyncUdpSocket>> {
        self.network.fallback_socket()
    }
    pub async fn accept(&mut self) -> Result<Connection, Error> {
        loop {
            if !self.accepting && self.pending.is_empty() {
                return Err(io::Error::from(io::ErrorKind::BrokenPipe).into());
            }
            tokio::select! {
                incoming = self.incoming.recv(), if self.accepting && self.pending.len() < 64 => {
                    match incoming {
                        Some((key, incoming)) => { self.pending.spawn(async move { (key, incoming.await) }); }
                        None => self.accepting = false,
                    }
                }
                Some(completed) = self.pending.join_next(), if !self.pending.is_empty() => {
                    match completed {
                        Ok((key, Ok(inner))) => return Ok(Connection { inner, identity: PeerIdentity { key }, network: self.network.clone() }),
                        Ok((_, Err(error))) => tracing::debug!(%error, "QUIC connection rejected"),
                        Err(error) => tracing::debug!(%error, "QUIC accept task stopped"),
                    }
                }
            }
        }
    }
}

#[derive(Clone)]
pub struct ServerHandle {
    network: Arc<Network>,
}
impl ServerHandle {
    /// Removes the WireGuard state before closing all of this peer's QUIC connections.
    pub async fn revoke_peer(&self, key: PublicKey) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.network.command.send(Command::Revoke(key, tx)).await?;
        rx.await?;
        if let Some(endpoint) = self.network.endpoints.get(&key) {
            endpoint.close(0u32.into(), b"peer revoked");
        }
        Ok(())
    }
    pub async fn shutdown(&self) -> Result<(), Error> {
        for endpoint in self.network.endpoints.values() {
            endpoint.close(0u32.into(), b"shutdown");
        }
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            for endpoint in self.network.endpoints.values() {
                endpoint.wait_idle().await;
            }
        })
        .await;
        self.network.command.send(Command::Stop).await?;
        Ok(())
    }
}

pub struct ClientBuilder {
    private: PrivateKey,
    remote: Option<(SocketAddr, PublicKey)>,
    bind: Option<SocketAddr>,
    timeout: Duration,
}
impl ClientBuilder {
    pub fn remote(mut self, address: SocketAddr, expected_key: PublicKey) -> Self {
        self.remote = Some((address, expected_key));
        self
    }
    pub fn bind(mut self, address: SocketAddr) -> Self {
        self.bind = Some(address);
        self
    }
    pub fn connect_timeout(mut self, timeout: Duration) -> Self {
        self.timeout = timeout;
        self
    }
    pub async fn connect(self) -> Result<Client, Error> {
        let (address, key) = self.remote.ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::InvalidInput,
                "remote address and public key are required",
            )
        })?;
        let bind = self.bind.unwrap_or_else(|| {
            if address.is_ipv4() {
                SocketAddr::from(([0, 0, 0, 0], 0))
            } else {
                SocketAddr::from(([0u16; 8], 0))
            }
        });
        let socket = UdpSocket::bind(bind).await?;
        let (network, _) = start(socket, self.private, vec![(key, Some(address))], true)?;
        let endpoint = network
            .endpoints
            .get(&key)
            .ok_or_else(|| io::Error::other("missing client endpoint"))?;
        let inner = tokio::time::timeout(
            self.timeout,
            endpoint.connect(socket::VIRTUAL_REMOTE, "wireguard-quic")?,
        )
        .await??;
        Ok(Client {
            connection: Connection {
                inner,
                identity: PeerIdentity { key },
                network,
            },
        })
    }
}

#[derive(Clone)]
pub struct Client {
    connection: Connection,
}
impl Client {
    pub fn builder(private: PrivateKey) -> ClientBuilder {
        ClientBuilder {
            private,
            remote: None,
            bind: None,
            timeout: Duration::from_secs(10),
        }
    }
    pub fn connection(&self) -> &Connection {
        &self.connection
    }
    pub fn peer_identity(&self) -> PeerIdentity {
        self.connection.identity
    }
    pub fn local_addr(&self) -> SocketAddr {
        self.connection.network.local
    }
    /// Sends a close and keeps UDP processing alive until Quinn finishes draining.
    pub async fn close(&self) {
        self.connection.close();
        if let Some(endpoint) = self
            .connection
            .network
            .endpoints
            .get(&self.connection.identity.key)
        {
            endpoint.wait_idle().await;
        }
    }
}

#[derive(Clone)]
pub struct Connection {
    inner: quinn::Connection,
    identity: PeerIdentity,
    network: Arc<Network>,
}
impl Connection {
    pub fn peer_identity(&self) -> PeerIdentity {
        self.identity
    }
    pub async fn open_bi(&self) -> Result<Stream, Error> {
        let (send, recv) = self.inner.open_bi().await?;
        Ok(Stream {
            send,
            recv,
            network: self.network.clone(),
        })
    }
    pub async fn accept_bi(&self) -> Result<Stream, Error> {
        let (send, recv) = self.inner.accept_bi().await?;
        Ok(Stream {
            send,
            recv,
            network: self.network.clone(),
        })
    }
    pub fn close(&self) {
        self.inner.close(0u32.into(), b"done");
    }
    pub async fn closed(&self) {
        self.inner.closed().await;
    }
}
impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("peer", &self.identity)
            .finish_non_exhaustive()
    }
}

/// One independent reliable byte stream, backed by a QUIC bidirectional stream.
pub struct Stream {
    send: quinn::SendStream,
    recv: quinn::RecvStream,
    // Streams keep the UDP driver alive even if their Client/Connection is dropped.
    network: Arc<Network>,
}
impl fmt::Debug for Stream {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Stream")
            .field("local_address", &self.network.local)
            .finish_non_exhaustive()
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.recv).poll_read(cx, buf)
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        AsyncWrite::poll_write(Pin::new(&mut self.send), cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.send), cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.send), cx)
    }
}

fn transport_config() -> Arc<quinn::TransportConfig> {
    let mut config = quinn::TransportConfig::default();
    config
        .initial_mtu(packet::QUIC_MTU as u16)
        .min_mtu(packet::QUIC_MTU as u16)
        .mtu_discovery_config(None);
    config.max_concurrent_bidi_streams(64u32.into());
    config.keep_alive_interval(Some(Duration::from_secs(10)));
    Arc::new(config)
}

type Accepted = mpsc::Receiver<(PublicKey, quinn::Incoming)>;
fn start(
    socket: UdpSocket,
    private: PrivateKey,
    configs: Vec<(PublicKey, Option<SocketAddr>)>,
    client: bool,
) -> Result<(Arc<Network>, Accepted), Error> {
    if configs.len() > 65535 {
        return Err(io::Error::new(io::ErrorKind::InvalidInput, "too many peers").into());
    }
    let local = socket.local_addr()?;
    let (outgoing, out_rx) = mpsc::channel(QUEUE);
    let (command, cmd_rx) = mpsc::channel(32);
    let (rejected, rejected_rx) = mpsc::channel(QUEUE);
    let (fallback, fallback_rx) = mpsc::channel(QUEUE);
    let (accepted, accepted_rx) = mpsc::channel(QUEUE);
    let public = x25519::PublicKey::from(&private.secret());
    let limiter = Arc::new(RateLimiter::new(&public, 100));
    let mut peers = HashMap::new();
    let mut indices = HashMap::new();
    let mut endpoints = HashMap::new();
    let mut acceptors = Vec::new();
    for (offset, (key, remote)) in configs.into_iter().enumerate() {
        if peers.contains_key(&key) {
            return Err(io::Error::new(io::ErrorKind::InvalidInput, "duplicate peer key").into());
        }
        let index = offset as u32 + 1;
        let (incoming, rx) = mpsc::channel(QUEUE);
        let virtual_socket = Arc::new(VirtualSocket {
            incoming: Mutex::new(rx),
            outgoing: outgoing.clone(),
            target: Target::Peer(key),
            local: socket::VIRTUAL_LOCAL,
        });
        let server_config = if client {
            None
        } else {
            let mut config = crate::plaintext::server_config();
            config.transport_config(transport_config());
            config.migration(false);
            Some(config)
        };
        let mut endpoint = Endpoint::new_with_abstract_socket(
            quinn::EndpointConfig::default(),
            server_config,
            virtual_socket,
            Arc::new(quinn::TokioRuntime),
        )?;
        let mut config = crate::plaintext::client_config();
        config.transport_config(transport_config());
        endpoint.set_default_client_config(config);
        if !client {
            let listener = endpoint.clone();
            let accepted = accepted.clone();
            acceptors.push(tokio::spawn(async move {
                while let Some(incoming) = listener.accept().await {
                    if accepted.send((key, incoming)).await.is_err() {
                        break;
                    }
                }
            }));
        }
        peers.insert(
            key,
            Peer {
                tunnel: Tunn::new(
                    private.secret(),
                    x25519::PublicKey::from(key.0),
                    None,
                    Some(25),
                    index,
                    Some(limiter.clone()),
                ),
                remote,
                incoming,
            },
        );
        indices.insert(index, key);
        endpoints.insert(key, endpoint);
    }
    let driver = tokio::spawn(async move {
        let mut dispatcher = Dispatcher {
            socket,
            private,
            public,
            limiter,
            peers,
            indices,
            rejected,
            fallback,
            local,
            client,
        };
        if let Err(error) = dispatcher.run(out_rx, cmd_rx).await {
            tracing::error!(%error,"WireGuard UDP driver stopped");
        }
    });
    Ok((
        Arc::new(Network {
            local,
            endpoints,
            outgoing,
            command,
            rejected: Mutex::new(Some(rejected_rx)),
            fallback: Mutex::new(Some(fallback_rx)),
            driver,
            acceptors,
        }),
        accepted_rx,
    ))
}

struct Dispatcher {
    socket: UdpSocket,
    private: PrivateKey,
    public: x25519::PublicKey,
    limiter: Arc<RateLimiter>,
    peers: HashMap<PublicKey, Peer>,
    indices: HashMap<u32, PublicKey>,
    rejected: mpsc::Sender<RejectedDatagram>,
    fallback: mpsc::Sender<Inbound>,
    local: SocketAddr,
    client: bool,
}
impl Dispatcher {
    async fn run(
        &mut self,
        mut outgoing: mpsc::Receiver<Outbound>,
        mut commands: mpsc::Receiver<Command>,
    ) -> io::Result<()> {
        let mut timer = tokio::time::interval(Duration::from_millis(250));
        timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut receive = vec![0; 65536];
        let mut scratch = vec![0; 65568];
        loop {
            tokio::select! {
                command=commands.recv()=>match command {
                    Some(Command::Revoke(key,ack))=>{self.peers.remove(&key);self.indices.retain(|_,v|*v!=key);let _=ack.send(());}
                    Some(Command::Stop)|None=>return Ok(()),
                },
                Some(out)=outgoing.recv()=>{
                    match out.target {
                        Target::Raw=>{self.send(&out.data,out.destination).await;}
                        Target::Peer(key)=>{
                            let Some(peer)=self.peers.get_mut(&key) else {continue;};
                            let Some(remote)=peer.remote else {continue;};
                            let data=packet::wrap(&out.data,self.client)?;
                            if let TunnResult::WriteToNetwork(data)=peer.tunnel.encapsulate(&data,&mut scratch) {
                                self.send(data,remote).await;
                            }
                        }
                    }
                },
                received=self.socket.recv_from(&mut receive)=>{
                    let (len,source)=received?;
                    self.receive(&receive[..len],source,&mut scratch).await;
                },
                _=timer.tick()=>{
                    self.limiter.reset_count();
                    // Collect before awaiting so no mutable tunnel borrow crosses send().
                    let mut packets=Vec::new();
                    for peer in self.peers.values_mut() {
                        if let Some(remote)=peer.remote
                            && let TunnResult::WriteToNetwork(data)=peer.tunnel.update_timers(&mut scratch)
                        {
                            packets.push((remote,data.to_vec()));
                        }
                    }
                    for (remote,data) in packets {self.send(&data,remote).await;}
                }
            }
        }
    }
    async fn send(&self, data: &[u8], destination: SocketAddr) {
        if let Err(error) = self.socket.send_to(data, destination).await {
            tracing::debug!(%error,"UDP send failed");
        }
    }
    fn reject(&self, data: &[u8], source: SocketAddr, reason: RejectionReason) {
        let data = Bytes::copy_from_slice(data);
        if reason == RejectionReason::NonWireGuard {
            let _ = self.fallback.try_send(Inbound {
                source,
                data: data.clone(),
            });
        }
        let _ = self.rejected.try_send(RejectedDatagram {
            data,
            source,
            local_address: self.local,
            reason,
        });
    }
    async fn receive(&mut self, data: &[u8], source: SocketAddr, scratch: &mut [u8]) {
        if data.len() < 4 || !matches!(&data[..4], [1..=4, 0, 0, 0]) {
            self.reject(data, source, RejectionReason::NonWireGuard);
            return;
        }
        let mut cookie = [0; 64];
        let packet = match self
            .limiter
            .verify_packet(Some(source.ip()), data, &mut cookie)
        {
            Ok(packet) => packet,
            Err(TunnResult::WriteToNetwork(reply)) => {
                self.send(reply, source).await;
                return;
            }
            Err(_) => {
                self.reject(data, source, RejectionReason::MalformedWireGuard);
                return;
            }
        };
        let is_data = matches!(&packet, Packet::PacketData(_));
        let key = match packet {
            Packet::HandshakeInit(init) => {
                match parse_handshake_anon(&self.private.secret(), &self.public, &init) {
                    Ok(handshake) => PublicKey(handshake.peer_static_public),
                    Err(_) => {
                        self.reject(data, source, RejectionReason::AuthenticationFailed);
                        return;
                    }
                }
            }
            Packet::HandshakeResponse(p) => match self.indices.get(&(p.receiver_idx >> 8)) {
                Some(key) => *key,
                None => {
                    self.reject(data, source, RejectionReason::UnknownSession);
                    return;
                }
            },
            Packet::PacketCookieReply(p) => match self.indices.get(&(p.receiver_idx >> 8)) {
                Some(key) => *key,
                None => {
                    self.reject(data, source, RejectionReason::UnknownSession);
                    return;
                }
            },
            Packet::PacketData(p) => match self.indices.get(&(p.receiver_idx >> 8)) {
                Some(key) => *key,
                None => {
                    self.reject(data, source, RejectionReason::UnknownSession);
                    return;
                }
            },
        };
        let Some(peer) = self.peers.get_mut(&key) else {
            self.reject(data, source, RejectionReason::UnauthorizedPeer);
            return;
        };
        let mut replies = Vec::new();
        let mut failure = None;
        match peer.tunnel.decapsulate(Some(source.ip()), data, scratch) {
            TunnResult::WriteToNetwork(reply) => replies.push(reply.to_vec()),
            TunnResult::WriteToTunnelV4(inner, _) => {
                // Endpoint roaming is permitted only after an authenticated transport packet.
                peer.remote = Some(source);
                match packet::unwrap(inner, self.client) {
                    Ok(payload) => {
                        let _ = peer.incoming.try_send(Inbound {
                            source: socket::VIRTUAL_REMOTE,
                            data: Bytes::copy_from_slice(payload),
                        });
                    }
                    Err(_) => failure = Some(RejectionReason::InvalidInnerPacket),
                }
            }
            TunnResult::Done => {
                if is_data {
                    peer.remote = Some(source);
                }
            }
            TunnResult::Err(_) => failure = Some(RejectionReason::AuthenticationFailed),
            TunnResult::WriteToTunnelV6(_, _) => {
                failure = Some(RejectionReason::InvalidInnerPacket)
            }
        }
        // Flush packets queued before the first handshake, as required by BoringTun.
        if failure.is_none() {
            for _ in 0..QUEUE {
                match peer.tunnel.decapsulate(None, &[], scratch) {
                    TunnResult::WriteToNetwork(reply) => replies.push(reply.to_vec()),
                    _ => break,
                }
            }
        }
        if let Some(reason) = failure {
            self.reject(data, source, reason);
        }
        for reply in replies {
            self.send(&reply, source).await;
        }
    }
}
