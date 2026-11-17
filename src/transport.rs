use std::collections::{HashMap, HashSet};
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
use tokio::task::{AbortHandle, JoinHandle, JoinSet};
use tokio::time::Instant;

use crate::socket::{self, Inbound, Outbound, QUEUE, Target, VirtualSocket};
use crate::{Error, PrivateKey, PublicKey, packet};

const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);
const PEER_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const MAX_PEERS: usize = 1024;
const RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const STREAM_RECEIVE_WINDOW: u32 = 1024 * 1024;

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
    PeerLimitReached,
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
    index: u32,
    acceptor: Option<AbortHandle>,
    idle_since: Option<Instant>,
    tunnel: Tunn,
    remote: Option<SocketAddr>,
    incoming: mpsc::Sender<Inbound>,
}

enum Command {
    Revoke(PublicKey, oneshot::Sender<()>),
    Close(oneshot::Sender<()>),
    Stop,
}

struct Network {
    local: SocketAddr,
    endpoints: Arc<Mutex<HashMap<PublicKey, Endpoint>>>,
    outgoing: mpsc::Sender<Outbound>,
    command: mpsc::Sender<Command>,
    rejected: Mutex<Option<mpsc::Receiver<RejectedDatagram>>>,
    fallback: Mutex<Option<mpsc::Receiver<Inbound>>>,
    driver: JoinHandle<()>,
}
impl Drop for Network {
    fn drop(&mut self) {
        let endpoints: Vec<_> = self.endpoints.lock().values().cloned().collect();
        for endpoint in &endpoints {
            endpoint.close(0u32.into(), b"shutdown");
        }
        let abort = self.driver.abort_handle();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            // The dispatcher exits when its command channel closes. Keep it open
            // until close packets have drained, even after Network is dropped.
            let command = self.command.clone();
            runtime.spawn(async move {
                let _ = tokio::time::timeout(DRAIN_TIMEOUT, async {
                    for endpoint in endpoints {
                        endpoint.wait_idle().await;
                    }
                })
                .await;
                abort.abort();
                drop(command);
            });
        } else {
            abort.abort();
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

type Authorize = Box<dyn FnMut(PublicKey) -> bool + Send>;

/// Server configuration. Peers are denied unless accepted by the callback.
pub struct ServerBuilder {
    private: PrivateKey,
    authorize: Authorize,
}
impl ServerBuilder {
    /// Checks each WireGuard handshake initiation, including rekeys.
    ///
    /// The callback receives the claimed public key before the handshake has
    /// fully authenticated. It runs on the UDP dispatcher and must not block.
    /// Changes affect subsequent handshakes; use `revoke_peer` to close existing
    /// sessions and deny that key for the rest of this server's lifetime.
    pub fn authorize(mut self, callback: Box<dyn FnMut(PublicKey) -> bool + Send>) -> Self {
        self.authorize = callback;
        self
    }
    pub async fn bind(self, address: impl tokio::net::ToSocketAddrs) -> Result<Server, Error> {
        let socket = UdpSocket::bind(address).await?;
        let (network, incoming) = start(socket, self.private, None, Some(self.authorize))?;
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
            authorize: Box::new(|_| false),
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
    /// Removes WireGuard state, closes QUIC connections, and denies future admission
    /// of this key for the rest of the server's lifetime.
    pub async fn revoke_peer(&self, key: PublicKey) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.network.command.send(Command::Revoke(key, tx)).await?;
        rx.await?;
        Ok(())
    }
    pub async fn shutdown(&self) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.network.command.send(Command::Close(tx)).await?;
        rx.await?;
        let endpoints: Vec<_> = self.network.endpoints.lock().values().cloned().collect();
        let _ = tokio::time::timeout(Duration::from_secs(2), async {
            for endpoint in endpoints {
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
        let (network, _) = start(socket, self.private, Some((key, address)), None)?;
        let endpoint = network
            .endpoints
            .lock()
            .get(&key)
            .cloned()
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
    /// Initiates connection closure and returns immediately.
    ///
    /// Close packets drain in the background while the Tokio runtime is running.
    /// This does not wait for pending stream data to be acknowledged.
    pub async fn close(&self) {
        self.connection.close();
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
impl Drop for Stream {
    fn drop(&mut self) {
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            // SendStream's destructor finishes the stream. Keep its transport alive
            // until all queued bytes and the FIN are acknowledged, or draining expires.
            let stopped = self.send.stopped();
            let network = self.network.clone();
            runtime.spawn(async move {
                let _ = tokio::time::timeout(DRAIN_TIMEOUT, stopped).await;
                drop(network);
            });
        }
    }
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
    config.max_concurrent_uni_streams(0u32.into());
    config.datagram_receive_buffer_size(None);
    config.datagram_send_buffer_size(0);
    config.receive_window(RECEIVE_WINDOW.into());
    config.stream_receive_window(STREAM_RECEIVE_WINDOW.into());
    config.send_window(u64::from(RECEIVE_WINDOW));
    config.keep_alive_interval(Some(Duration::from_secs(10)));
    Arc::new(config)
}

type Accepted = mpsc::Receiver<(PublicKey, quinn::Incoming)>;

fn peer_endpoint(
    key: PublicKey,
    client: bool,
    outgoing: mpsc::Sender<Outbound>,
) -> io::Result<(Endpoint, mpsc::Sender<Inbound>)> {
    let (incoming, rx) = mpsc::channel(QUEUE);
    let virtual_socket = Arc::new(VirtualSocket {
        incoming: Mutex::new(rx),
        outgoing,
        target: Target::Peer(key),
        local: socket::VIRTUAL_LOCAL,
    });
    let server_config = if client {
        None
    } else {
        let mut config = crate::plaintext::server_config();
        config.transport_config(transport_config());
        config.migration(false);
        config.max_incoming(64);
        config.incoming_buffer_size(256 * 1024);
        config.incoming_buffer_size_total(2 * 1024 * 1024);
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
    Ok((endpoint, incoming))
}

fn start(
    socket: UdpSocket,
    private: PrivateKey,
    remote: Option<(PublicKey, SocketAddr)>,
    authorize: Option<Authorize>,
) -> Result<(Arc<Network>, Accepted), Error> {
    let client = remote.is_some();
    let local = socket.local_addr()?;
    let (outgoing, out_rx) = mpsc::channel(QUEUE);
    let (command, cmd_rx) = mpsc::channel(32);
    let (rejected, rejected_rx) = mpsc::channel(QUEUE);
    let (fallback, fallback_rx) = mpsc::channel(QUEUE);
    let (accepted, accepted_rx) = mpsc::channel(QUEUE);
    let public = x25519::PublicKey::from(&private.secret());
    let limiter = Arc::new(RateLimiter::new(&public, 100));
    // BoringTun rechecks MAC1 internally. Its validation-only limiter must not
    // charge the dispatcher's global budget again or issue conflicting cookies.
    let verifier = Arc::new(RateLimiter::new(&public, u64::MAX));
    let mut peers = HashMap::new();
    let mut indices = HashMap::new();
    let endpoints = Arc::new(Mutex::new(HashMap::new()));
    if let Some((key, address)) = remote {
        let (endpoint, incoming) = peer_endpoint(key, true, outgoing.clone())?;
        peers.insert(
            key,
            Peer {
                index: 1,
                acceptor: None,
                idle_since: None,
                tunnel: Tunn::new(
                    private.secret(),
                    x25519::PublicKey::from(key.0),
                    None,
                    Some(25),
                    1,
                    Some(verifier.clone()),
                ),
                remote: Some(address),
                incoming,
            },
        );
        indices.insert(1, key);
        endpoints.lock().insert(key, endpoint);
    }
    let driver_endpoints = endpoints.clone();
    let driver_outgoing = outgoing.clone();
    let driver = tokio::spawn(async move {
        let mut dispatcher = Dispatcher {
            socket,
            private,
            public,
            limiter,
            verifier,
            peers,
            indices,
            rejected,
            fallback,
            local,
            client,
            authorize,
            endpoints: driver_endpoints,
            outgoing: driver_outgoing,
            accepted,
            acceptors: JoinSet::new(),
            revoked: HashSet::new(),
            next_index: 2,
            free_indices: Vec::new(),
            closing: false,
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
        }),
        accepted_rx,
    ))
}

struct Dispatcher {
    socket: UdpSocket,
    private: PrivateKey,
    public: x25519::PublicKey,
    limiter: Arc<RateLimiter>,
    verifier: Arc<RateLimiter>,
    peers: HashMap<PublicKey, Peer>,
    indices: HashMap<u32, PublicKey>,
    rejected: mpsc::Sender<RejectedDatagram>,
    fallback: mpsc::Sender<Inbound>,
    local: SocketAddr,
    client: bool,
    authorize: Option<Authorize>,
    endpoints: Arc<Mutex<HashMap<PublicKey, Endpoint>>>,
    outgoing: mpsc::Sender<Outbound>,
    accepted: mpsc::Sender<(PublicKey, quinn::Incoming)>,
    acceptors: JoinSet<()>,
    revoked: HashSet<PublicKey>,
    next_index: u32,
    free_indices: Vec<u32>,
    closing: bool,
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
                    Some(Command::Revoke(key,ack))=>{
                        self.revoked.insert(key);
                        self.remove_peer(key,b"peer revoked");
                        let _=ack.send(());
                    }
                    Some(Command::Close(ack))=>{
                        self.closing=true;
                        for endpoint in self.endpoints.lock().values() {
                            endpoint.close(0u32.into(),b"shutdown");
                        }
                        let _=ack.send(());
                    }
                    Some(Command::Stop)|None=>return Ok(()),
                },
                Some(result)=self.acceptors.join_next(), if !self.acceptors.is_empty()=>{
                    if let Err(error)=result {tracing::debug!(%error,"QUIC acceptor stopped");}
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
                    self.verifier.reset_count();
                    self.expire_idle_peers(Instant::now());
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
    fn remove_peer(&mut self, key: PublicKey, reason: &[u8]) {
        if let Some(peer) = self.peers.remove(&key) {
            if let Some(acceptor) = peer.acceptor {
                acceptor.abort();
            }
            self.indices.remove(&peer.index);
            self.free_indices.push(peer.index);
        }
        if let Some(endpoint) = self.endpoints.lock().remove(&key) {
            endpoint.close(0u32.into(), reason);
        }
    }

    fn expire_idle_peers(&mut self, now: Instant) {
        if self.client || self.closing {
            return;
        }
        let mut expired = Vec::new();
        {
            let endpoints = self.endpoints.lock();
            for (key, peer) in &mut self.peers {
                if endpoints
                    .get(key)
                    .is_some_and(|endpoint| endpoint.open_connections() != 0)
                {
                    peer.idle_since = None;
                } else {
                    let since = peer.idle_since.get_or_insert(now);
                    if now.duration_since(*since) >= PEER_IDLE_TIMEOUT {
                        expired.push(*key);
                    }
                }
            }
        }
        for key in expired {
            self.remove_peer(key, b"peer idle");
        }
    }

    async fn send(&mut self, data: &[u8], destination: SocketAddr) {
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
    async fn admit(&mut self, key: PublicKey, data: &[u8], source: SocketAddr, scratch: &mut [u8]) {
        if self.peers.len() >= MAX_PEERS
            || (self.free_indices.is_empty() && self.next_index > 0x00ff_ffff)
        {
            self.reject(data, source, RejectionReason::PeerLimitReached);
            return;
        }
        // Do not consume an index until the handshake fully authenticates.
        let index = self.free_indices.last().copied().unwrap_or(self.next_index);
        let mut tunnel = Tunn::new(
            self.private.secret(),
            x25519::PublicKey::from(key.0),
            None,
            Some(25),
            index,
            Some(self.verifier.clone()),
        );
        let reply = match tunnel.decapsulate(Some(source.ip()), data, scratch) {
            TunnResult::WriteToNetwork(reply) if reply.starts_with(&[2, 0, 0, 0]) => reply.to_vec(),
            TunnResult::WriteToNetwork(reply) => {
                self.send(reply, source).await;
                return;
            }
            _ => {
                self.reject(data, source, RejectionReason::AuthenticationFailed);
                return;
            }
        };
        let (endpoint, incoming) = match peer_endpoint(key, false, self.outgoing.clone()) {
            Ok(peer) => peer,
            Err(error) => {
                tracing::error!(%error, %key, "could not create peer endpoint");
                return;
            }
        };
        let listener = endpoint.clone();
        let accepted = self.accepted.clone();
        let acceptor = self.acceptors.spawn(async move {
            while let Some(incoming) = listener.accept().await {
                if accepted.send((key, incoming)).await.is_err() {
                    break;
                }
            }
        });
        self.endpoints.lock().insert(key, endpoint);
        self.peers.insert(
            key,
            Peer {
                index,
                acceptor: Some(acceptor),
                idle_since: Some(Instant::now()),
                tunnel,
                remote: None,
                incoming,
            },
        );
        self.indices.insert(index, key);
        if self.free_indices.pop().is_none() {
            self.next_index += 1;
        }
        self.send(&reply, source).await;
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
        let is_init = matches!(&packet, Packet::HandshakeInit(_));
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
        if is_init && !self.client {
            if self.closing
                || self.revoked.contains(&key)
                || !self
                    .authorize
                    .as_mut()
                    .is_some_and(|authorize| authorize(key))
            {
                self.reject(data, source, RejectionReason::UnauthorizedPeer);
                return;
            }
            if !self.peers.contains_key(&key) {
                self.admit(key, data, source, scratch).await;
                return;
            }
        }
        let Some(peer) = self.peers.get_mut(&key) else {
            self.reject(data, source, RejectionReason::UnauthorizedPeer);
            return;
        };
        let mut replies = Vec::new();
        let mut failure = None;
        match peer.tunnel.decapsulate(Some(source.ip()), data, scratch) {
            TunnResult::WriteToNetwork(reply) => {
                if is_init && reply.starts_with(&[2, 0, 0, 0]) {
                    peer.idle_since = Some(Instant::now());
                }
                replies.push(reply.to_vec());
            }
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

#[cfg(test)]
mod tests {
    use blake2::digest::Mac;
    use blake2::digest::consts::U16;
    use blake2::{Blake2s256, Blake2sMac, Digest};
    use tokio::io::AsyncWriteExt;

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn claimed_key_does_not_allocate_peer_before_authentication() {
        let server_key = PrivateKey::from_bytes([70; 32]);
        let server_public = server_key.public_key();
        let claimed = PrivateKey::from_bytes([71; 32]).public_key();
        let server = Server::builder(server_key)
            .authorize(Box::new(move |key| key == claimed))
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        assert!(server.network.endpoints.lock().is_empty());
        let mut rejected = server.take_rejected().unwrap();
        let mut initiator = Tunn::new(
            x25519::StaticSecret::from([71; 32]),
            x25519::PublicKey::from(*server_public.as_bytes()),
            None,
            None,
            1,
            None,
        );
        let mut scratch = [0; 2048];
        let init = match initiator.format_handshake_initiation(&mut scratch, false) {
            TunnResult::WriteToNetwork(init) => init,
            _ => panic!("expected a handshake initiation"),
        };
        // Corrupt the encrypted timestamp while preserving the encrypted identity.
        // MAC1 uses public information, so a valid MAC alone cannot authenticate it.
        init[88] ^= 1;
        let mut key = Blake2s256::new();
        Digest::update(&mut key, b"mac1----");
        Digest::update(&mut key, server_public.as_bytes());
        let mut mac = <Blake2sMac<U16> as Mac>::new_from_slice(&key.finalize()).unwrap();
        Mac::update(&mut mac, &init[..116]);
        init[116..132].copy_from_slice(&mac.finalize().into_bytes());
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp.send_to(init, server.local_addr()).await.unwrap();
        let rejection = tokio::time::timeout(Duration::from_secs(1), rejected.recv())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(rejection.reason, RejectionReason::AuthenticationFailed);
        assert!(server.network.endpoints.lock().is_empty());
    }
    #[tokio::test(flavor = "current_thread")]
    async fn idle_peers_expire_and_can_be_readmitted() {
        let server_key = PrivateKey::from_bytes([82; 32]);
        let server_public = server_key.public_key();
        let peer = PrivateKey::from_bytes([83; 32]).public_key();
        let mut server = Server::builder(server_key)
            .authorize(Box::new(move |key| key == peer))
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let (client, connection) = tokio::join!(
            Client::builder(PrivateKey::from_bytes([83; 32]))
                .remote(server.local_addr(), server_public)
                .connect(),
            server.accept()
        );
        let client = client.unwrap();
        let connection = connection.unwrap();
        assert!(!server.network.endpoints.lock().is_empty());
        connection.close();
        client.close().await;
        drop(client);
        drop(connection);
        let endpoint = server.network.endpoints.lock().get(&peer).unwrap().clone();
        endpoint.wait_idle().await;
        tokio::time::pause();
        tokio::time::advance(Duration::from_millis(250)).await;
        tokio::task::yield_now().await;
        assert!(!server.network.endpoints.lock().is_empty());
        tokio::time::advance(PEER_IDLE_TIMEOUT).await;
        tokio::task::yield_now().await;
        assert!(server.network.endpoints.lock().is_empty());
        tokio::time::resume();
        let (client, connection) = tokio::join!(
            Client::builder(PrivateKey::from_bytes([83; 32]))
                .remote(server.local_addr(), server_public)
                .connect(),
            server.accept()
        );
        let client = client.unwrap();
        assert_eq!(connection.unwrap().peer_identity().public_key(), peer);
        client.close().await;
    }

    #[tokio::test(flavor = "current_thread")]
    async fn unsupported_quic_capabilities_are_not_advertised() {
        let server_key = PrivateKey::from_bytes([84; 32]);
        let server_public = server_key.public_key();
        let client_key = PrivateKey::from_bytes([85; 32]);
        let mut server = Server::builder(server_key)
            .authorize(Box::new(|_| true))
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let (client, connection) = tokio::join!(
            Client::builder(client_key)
                .remote(server.local_addr(), server_public)
                .connect(),
            server.accept()
        );
        let client = client.unwrap();
        let connection = connection.unwrap();
        assert!(client.connection.inner.max_datagram_size().is_none());
        assert!(connection.inner.max_datagram_size().is_none());
        assert!(
            tokio::time::timeout(
                Duration::from_millis(50),
                client.connection.inner.open_uni()
            )
            .await
            .is_err()
        );
        assert!(
            tokio::time::timeout(Duration::from_millis(50), connection.inner.open_uni())
                .await
                .is_err()
        );
        client.close().await;
    }

    #[test]
    fn tunnel_validation_does_not_charge_the_global_rate_budget() {
        let private = x25519::StaticSecret::from([86; 32]);
        let public = x25519::PublicKey::from(&private);
        let client_private = x25519::StaticSecret::from([87; 32]);
        let client_public = x25519::PublicKey::from(&client_private);
        let limiter = RateLimiter::new(&public, 1);
        let verifier = Arc::new(RateLimiter::new(&public, u64::MAX));
        let mut server = Tunn::new(private, client_public, None, None, 1, Some(verifier));
        let mut client = Tunn::new(client_private, public, None, None, 1, None);
        let mut init_buf = [0; 2048];
        let init = match client.format_handshake_initiation(&mut init_buf, false) {
            TunnResult::WriteToNetwork(packet) => packet,
            _ => panic!("expected initiation"),
        };
        let source = Some("127.0.0.1".parse().unwrap());
        let mut scratch = [0; 2048];
        assert!(limiter.verify_packet(source, init, &mut scratch).is_ok());
        match server.decapsulate(source, init, &mut scratch) {
            TunnResult::WriteToNetwork(packet) => assert_eq!(&packet[..4], &[2, 0, 0, 0]),
            _ => panic!("first handshake must pass without another global budget charge"),
        }
        assert!(matches!(limiter.verify_packet(source, init, &mut scratch),
            Err(TunnResult::WriteToNetwork(packet)) if packet.starts_with(&[3,0,0,0])));
    }
    #[tokio::test(flavor = "current_thread")]
    async fn unacknowledged_stream_drain_has_a_deadline() {
        let server_key = PrivateKey::from_bytes([88; 32]);
        let server_public = server_key.public_key();
        let client_key = PrivateKey::from_bytes([89; 32]);
        let mut server = Server::builder(server_key)
            .authorize(Box::new(|_| true))
            .bind("127.0.0.1:0")
            .await
            .unwrap();
        let (client, connection) = tokio::join!(
            Client::builder(client_key)
                .remote(server.local_addr(), server_public)
                .connect(),
            server.accept()
        );
        let client = client.unwrap();
        let _connection = connection.unwrap();
        // Stop the remote UDP driver so the last stream can never be acknowledged.
        server.network.driver.abort();
        tokio::task::yield_now().await;
        let network = Arc::downgrade(&client.connection.network);
        let driver = client.connection.network.driver.abort_handle();
        let mut stream = client.connection().open_bi().await.unwrap();
        stream.write_all(b"unacknowledged").await.unwrap();
        stream.shutdown().await.unwrap();
        tokio::time::pause();
        drop(client);
        drop(stream);
        tokio::task::yield_now().await;
        assert!(network.upgrade().is_some());
        tokio::time::advance(DRAIN_TIMEOUT + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(network.upgrade().is_none());
        tokio::time::advance(DRAIN_TIMEOUT + Duration::from_millis(1)).await;
        tokio::task::yield_now().await;
        assert!(driver.is_finished());
    }
}
