use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{fmt, io};

use bytes::Bytes;
use parking_lot::Mutex;
use tokio::net::UdpSocket;
use tokio::sync::{Mutex as AsyncMutex, Notify, mpsc, oneshot, watch};
use tokio::task::JoinHandle;
use tokio::time::Instant;

use crate::crypto::{self, DatagramCrypto, ReplayWindow, SessionId};
use crate::rekey::{self, SessionKeys};
use crate::stream::{Conversation, MAX_CONVERSATIONS};
use crate::{Error, KcpStream, PrivateKey, PublicKey};

const MAX_SESSIONS: usize = 1024;

const QUEUE: usize = 128;

const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(60);

const IDLE_TIMEOUT: Duration = Duration::from_secs(60);

const DRAIN_TIMEOUT: Duration = Duration::from_secs(5);

const RETRY: Duration = Duration::from_millis(200);

type SharedConversation = Arc<Mutex<Conversation>>;

type Authorize = Box<dyn FnMut(PublicKey) -> bool + Send>;

/// Identity established by the Noise static-key handshake, never by an address or HTTP header.
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
    UnknownProtocol,
    MalformedPacket,
    UnauthorizedPeer,
    UnknownSession,
    AuthenticationFailed,
    ExpiredHandshake,
    CapacityReached,
}

/// Original UDP bytes only; decrypted application data is never exposed here.
#[derive(Debug, Clone)]
pub struct RejectedDatagram {
    pub data: Bytes,
    pub source: SocketAddr,
    pub local_address: SocketAddr,
    pub reason: RejectionReason,
}

struct SessionState {
    id: SessionId,
    identity: PeerIdentity,
    conversations: Mutex<HashMap<u32, SharedConversation>>,
    incoming: Mutex<Option<mpsc::Sender<SharedConversation>>>,
    accepted: AsyncMutex<mpsc::Receiver<SharedConversation>>,
    closed: watch::Sender<bool>,
    next_conv: Mutex<u32>,
    initiator: bool,
}

impl SessionState {
    fn new(id: SessionId, key: PublicKey, initiator: bool) -> Arc<Self> {
        let (incoming, accepted) = mpsc::channel(QUEUE);
        let (closed, _) = watch::channel(false);
        Arc::new(Self {
            id,
            identity: PeerIdentity { key },
            conversations: Mutex::new(HashMap::new()),
            incoming: Mutex::new(Some(incoming)),
            accepted: AsyncMutex::new(accepted),
            closed,
            next_conv: Mutex::new(if initiator { 1 } else { 2 }),
            initiator,
        })
    }

    fn is_closed(&self) -> bool {
        *self.closed.borrow()
    }

    fn close(&self) {
        // Serialize close with open_stream and incoming conversation creation.
        let conversations = self.conversations.lock();
        self.closed.send_replace(true);
        self.incoming.lock().take();
        for conversation in conversations.values() {
            conversation.lock().fail(io::ErrorKind::ConnectionAborted);
        }
    }
}

struct Closing {
    started: Instant,
    last_sent: Instant,
    acknowledged: bool,
    waiters: Vec<oneshot::Sender<()>>,
}

impl Closing {
    fn complete(&mut self) {
        self.acknowledged = true;
        for waiter in self.waiters.drain(..) {
            let _ = waiter.send(());
        }
    }
}

struct Session {
    id: SessionId,
    crypto: SessionKeys,
    state: Arc<SessionState>,
    remote: SocketAddr,
    response: Option<Vec<u8>>,
    initiation: Option<Vec<u8>>,
    confirmed: bool,
    created: Instant,
    last_received: Instant,
    last_ping: Instant,
    remote_convs: ReplayWindow,
    closing: Option<Closing>,
}

impl Session {
    fn new(
        id: SessionId,
        crypto: DatagramCrypto,
        key: PublicKey,
        remote: SocketAddr,
        initiator: bool,
    ) -> Self {
        let now = Instant::now();
        Self {
            id,
            crypto: SessionKeys::new(crypto),
            state: SessionState::new(id, key, initiator),
            remote,
            response: None,
            initiation: None,
            confirmed: initiator,
            created: now,
            last_received: now,
            last_ping: now,
            remote_convs: ReplayWindow::default(),
            closing: None,
        }
    }

    fn send(&mut self, socket: &UdpSocket, payload: &[u8]) {
        match self.crypto.encrypt_data(self.id, payload) {
            Ok(packet) => {
                let _ = socket.try_send_to(&packet, self.remote);
            }
            Err(_) => self.state.close(),
        }
    }

    fn begin_close(&mut self, socket: &UdpSocket, waiter: Option<oneshot::Sender<()>>) {
        self.state.close();
        if self.closing.is_none() {
            self.send(socket, &[crypto::CLOSE]);
            self.closing = Some(Closing {
                started: Instant::now(),
                last_sent: Instant::now(),
                acknowledged: false,
                waiters: Vec::new(),
            });
        }
        if let Some(waiter) = waiter
            && let Some(closing) = &mut self.closing
        {
            if closing.acknowledged {
                let _ = waiter.send(());
            } else {
                closing.waiters.push(waiter);
            }
        }
    }

    fn receive_close(&mut self, socket: &UdpSocket) {
        self.state.close();
        self.send(socket, &[crypto::CLOSE_ACK]);
        let closing = self.closing.get_or_insert_with(|| Closing {
            started: Instant::now(),
            last_sent: Instant::now(),
            acknowledged: true,
            waiters: Vec::new(),
        });
        // Simultaneous close also confirms that the peer has stopped the session.
        closing.complete();
    }

    fn segment(&mut self, segment: &[u8], elapsed: u32) -> io::Result<()> {
        if segment.len() < kcp::KCP_OVERHEAD {
            return Err(io::Error::other("truncated KCP segment"));
        }
        let id = kcp::get_conv(segment);
        let mut conversations = self.state.conversations.lock();
        if !conversations.contains_key(&id) {
            let remote_parity = if self.state.initiator { 0 } else { 1 };
            if id == 0 || id % 2 != remote_parity || self.remote_convs.contains(u64::from(id / 2)) {
                return Ok(()); // retired or invalid conversation; never resurrect one
            }
            if conversations.len() >= MAX_CONVERSATIONS {
                return Ok(());
            }
            let conversation = Conversation::new(id, false)?;
            conversations.insert(id, Arc::new(Mutex::new(conversation)));
            self.remote_convs.insert(u64::from(id / 2));
        }
        if let Some(conversation) = conversations.get(&id) {
            let mut conversation = conversation.lock();
            conversation.io_pending = true;
            // KCP measures ACK latency against the clock set by update().
            conversation.kcp.update(elapsed)?;
            conversation.kcp.input(segment)?;
        }
        Ok(())
    }

    fn update(&mut self, socket: &UdpSocket, elapsed: u32, timer: bool) {
        let mut packets = Vec::new();
        {
            let mut conversations = self.state.conversations.lock();
            conversations.retain(|_, shared| {
                let mut c = shared.lock();

                if c.error.is_some() {
                    return false;
                }
                let io_pending = std::mem::take(&mut c.io_pending);
                if !timer && !io_pending {
                    return true;
                }

                let mut process = || -> io::Result<()> {
                    if timer {
                        c.flush_open(false)?;
                    }
                    c.receive_records()?;
                    c.kcp.update(elapsed)?;
                    // update() can defer its flush until the next protocol tick.
                    if io_pending {
                        c.kcp.flush()?;
                    }
                    Ok(())
                };
                if let Err(error) = process() {
                    c.fail(error.kind());
                    return false;
                }
                if c.kcp.is_dead_link() {
                    c.fail(io::ErrorKind::TimedOut);
                    return false;
                }
                if c.opened && !c.delivered {
                    let incoming = self.state.incoming.lock();
                    match incoming.as_ref().map(|tx| tx.try_send(shared.clone())) {
                        Some(Ok(())) => c.delivered = true,
                        Some(Err(mpsc::error::TrySendError::Full(_))) => {}
                        _ => {
                            c.fail(io::ErrorKind::BrokenPipe);
                            return false;
                        }
                    }
                }
                packets.extend(c.output.0.lock().drain(..));
                c.wake();
                // Keep KCP around briefly to ACK a retransmitted peer FIN after its ACK was lost.
                let complete = c.local_fin && c.remote_fin && c.kcp.wait_snd() == 0;
                if let Some(dropped) = c.dropped {
                    return !(complete && dropped.elapsed() >= Duration::from_secs(2)
                        || dropped.elapsed() >= DRAIN_TIMEOUT);
                }
                true
            });
        }
        for packet in packets {
            let mut payload = Vec::with_capacity(packet.len() + 1);
            payload.push(crypto::SEGMENT);
            payload.extend_from_slice(&packet);
            self.send(socket, &payload);
        }
    }
}

enum Command {
    #[cfg(test)]
    AgeKeys(Duration, oneshot::Sender<()>),
    Close(SessionId, oneshot::Sender<()>),
    Revoke(PublicKey, oneshot::Sender<()>),
    Shutdown(oneshot::Sender<()>),
}

pub(crate) struct Network {
    pub(crate) io_ready: Arc<Notify>,
    local: SocketAddr,
    command: mpsc::Sender<Command>,
    rejected: Mutex<Option<mpsc::Receiver<RejectedDatagram>>>,
    driver: JoinHandle<()>,
}

impl Drop for Network {
    fn drop(&mut self) {
        // The driver notices command-channel closure and drains queued KCP data.
        // Abort is a final upper bound, including when a UDP peer disappears.
        let abort = self.driver.abort_handle();
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            runtime.spawn(async move {
                tokio::time::sleep(DRAIN_TIMEOUT + Duration::from_millis(100)).await;
                abort.abort();
            });
        } else {
            abort.abort();
        }
    }
}

/// Server admission policy. Without an authorization callback, every client is denied.
pub struct ServerBuilder {
    private: PrivateKey,
    public: PublicKey,
    psk: [u8; 32],
    authorize: Authorize,
}

impl ServerBuilder {
    /// Called for authenticated client static keys. Must be quick and nonblocking.
    pub fn authorize(mut self, callback: Box<dyn FnMut(PublicKey) -> bool + Send>) -> Self {
        self.authorize = callback;
        self
    }

    /// Optional additional shared secret, common to this listener's peers. Defaults to zeros.
    pub fn preshared_key(mut self, psk: [u8; 32]) -> Self {
        self.psk = psk;
        self
    }

    pub async fn bind(self, address: impl tokio::net::ToSocketAddrs) -> Result<Server, Error> {
        let socket = UdpSocket::bind(address).await?;
        let (network, incoming) = start(socket, Some(self), None, None)?;
        Ok(Server { network, incoming })
    }
}

/// A UDP listener accepting authenticated Noise sessions containing KCP conversations.
pub struct Server {
    network: Arc<Network>,
    incoming: mpsc::Receiver<Arc<SessionState>>,
}

impl Server {
    pub fn builder(private: PrivateKey) -> ServerBuilder {
        ServerBuilder {
            public: private.public_key(),
            private,
            psk: [0; 32],
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

    pub async fn accept(&mut self) -> Result<Connection, Error> {
        loop {
            let state = self.incoming.recv().await.ok_or_else(broken_pipe)?;
            if !state.is_closed() {
                return Ok(Connection {
                    state,
                    network: self.network.clone(),
                });
            }
        }
    }
}

#[derive(Clone)]
pub struct ServerHandle {
    network: Arc<Network>,
}

impl ServerHandle {
    /// Closes all sessions of this key and denies it for this listener's lifetime.
    pub async fn revoke_peer(&self, key: PublicKey) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        self.network
            .command
            .send(Command::Revoke(key, tx))
            .await
            .map_err(|_| broken_pipe())?;
        rx.await?;
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<(), Error> {
        let (tx, rx) = oneshot::channel();
        if self
            .network
            .command
            .send(Command::Shutdown(tx))
            .await
            .is_ok()
        {
            let _ = rx.await;
        }
        Ok(())
    }
}

pub struct ClientBuilder {
    private: PrivateKey,
    psk: [u8; 32],
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

    pub fn preshared_key(mut self, psk: [u8; 32]) -> Self {
        self.psk = psk;
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
        let session = tokio::time::timeout(
            self.timeout,
            connect(&socket, &self.private, self.psk, address, key),
        )
        .await??;
        let state = session.state.clone();
        let (network, _) = start(socket, None, Some(session), Some((self.private, self.psk)))?;
        Ok(Client {
            connection: Connection { state, network },
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
            psk: [0; 32],
            remote: None,
            bind: None,
            timeout: Duration::from_secs(10),
        }
    }

    pub fn connection(&self) -> &Connection {
        &self.connection
    }

    pub fn peer_identity(&self) -> PeerIdentity {
        self.connection.peer_identity()
    }

    pub fn local_addr(&self) -> SocketAddr {
        self.connection.network.local
    }

    /// Stops application I/O and waits for the encrypted close acknowledgment.
    /// Retries for up to one second if the peer or its reply is lost.
    /// Does not flush pending application writes.
    pub async fn close(&self) {
        self.connection.shutdown().await;
    }
}

/// An authenticated Noise session. Both ends can open independent KCP conversations.
#[derive(Clone)]
pub struct Connection {
    state: Arc<SessionState>,
    network: Arc<Network>,
}

impl Connection {
    pub fn peer_identity(&self) -> PeerIdentity {
        self.state.identity
    }

    pub async fn open_stream(&self) -> Result<KcpStream, Error> {
        let mut conversations = self.state.conversations.lock();
        if self.state.is_closed() {
            return Err(broken_pipe().into());
        }
        if conversations.len() >= MAX_CONVERSATIONS {
            return Err(io::Error::new(
                io::ErrorKind::WouldBlock,
                "KCP conversation limit reached",
            )
            .into());
        }
        let mut next = self.state.next_conv.lock();
        let id = *next;
        *next = next
            .checked_add(2)
            .ok_or_else(|| io::Error::other("KCP conversation IDs exhausted; reconnect"))?;
        let inner = Arc::new(Mutex::new(Conversation::new(id, true)?));
        conversations.insert(id, inner.clone());
        Ok(KcpStream {
            inner,
            network: self.network.clone(),
        })
    }

    pub async fn accept_stream(&self) -> Result<KcpStream, Error> {
        let mut closed = self.state.closed.subscribe();
        if *closed.borrow() {
            return Err(broken_pipe().into());
        }
        tokio::select! {
            stream = async { self.state.accepted.lock().await.recv().await } => {
                let inner = stream.ok_or_else(broken_pipe)?;
                if self.state.is_closed() { return Err(broken_pipe().into()); }
                Ok(KcpStream { inner, network: self.network.clone() })
            }
            _ = closed.wait_for(|value| *value) => Err(broken_pipe().into()),
        }
    }

    /// Aborts local I/O immediately; the driver sends closure in the background.
    /// Use `shutdown().await` before stopping the runtime.
    pub fn close(&self) {
        self.state.close();
    }

    /// Waits for the peer's encrypted close acknowledgment, with a one-second retry bound.
    pub async fn shutdown(&self) {
        self.state.close();
        let (tx, rx) = oneshot::channel();
        if self
            .network
            .command
            .send(Command::Close(self.state.id, tx))
            .await
            .is_ok()
        {
            // Also bound the wait if the network task has failed.
            let _ = tokio::time::timeout(Duration::from_millis(1100), rx).await;
        }
    }

    pub async fn closed(&self) {
        let _ = self
            .state
            .closed
            .subscribe()
            .wait_for(|closed| *closed)
            .await;
    }
}

impl fmt::Debug for Connection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Connection")
            .field("peer", &self.state.identity)
            .finish_non_exhaustive()
    }
}

fn broken_pipe() -> io::Error {
    io::Error::new(io::ErrorKind::BrokenPipe, "Noise session closed")
}

fn timestamp() -> Result<u64, Error> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

async fn connect(
    socket: &UdpSocket,
    private: &PrivateKey,
    psk: [u8; 32],
    remote: SocketAddr,
    key: PublicKey,
) -> Result<Session, Error> {
    let id: SessionId = rand::random();
    let (hs, initiation) = crypto::initiate(private, key, psk, id, timestamp()?)?;
    let mut retry = tokio::time::interval(RETRY);
    let mut buf = [0; 65536];
    loop {
        tokio::select! {
            _ = retry.tick() => { socket.send_to(&initiation, remote).await?; }
            received = socket.recv_from(&mut buf) => {
                let (len, source) = received?;
                let packet = &buf[..len];
                if source != remote || len < crypto::HEADER || &packet[..4] != crypto::MAGIC || packet[5..crypto::HEADER] != id { continue; }
                if packet[4] == crypto::RESPONSE {
                    // Invalid replies must not corrupt the retained handshake state.
                    if let Ok(crypto) = crypto::finish(&mut hs.clone(), packet) {
                        // The first KCP packet implicitly confirms the keys at the
                        // responder. No READY/READY_ACK exchange or extra RTT.
                        return Ok(Session::new(id, crypto, key, remote, true));
                    }
                }
            }
        }
    }
}

fn start(
    socket: UdpSocket,
    config: Option<ServerBuilder>,
    initial: Option<Session>,
    client_keys: Option<(PrivateKey, [u8; 32])>,
) -> Result<(Arc<Network>, mpsc::Receiver<Arc<SessionState>>), Error> {
    let local = socket.local_addr()?;
    let (command, commands) = mpsc::channel(QUEUE);
    let (incoming, accepted) = mpsc::channel(QUEUE);
    let (rejected, rejections) = mpsc::channel(256);
    let mut sessions = HashMap::new();
    if let Some(session) = initial {
        sessions.insert(session.id, session);
    }
    let io_ready = Arc::new(Notify::new());
    let driver = Driver {
        io_ready: io_ready.clone(),
        socket,
        local,
        config,
        client_keys,
        sessions,
        incoming,
        rejected,
        revoked: HashSet::new(),
        seen: HashMap::new(),
    };
    let driver = tokio::spawn(driver.run(commands));
    Ok((
        Arc::new(Network {
            io_ready,
            local,
            command,
            rejected: Mutex::new(Some(rejections)),
            driver,
        }),
        accepted,
    ))
}

struct Driver {
    io_ready: Arc<Notify>,
    socket: UdpSocket,
    local: SocketAddr,
    config: Option<ServerBuilder>,
    client_keys: Option<(PrivateKey, [u8; 32])>,
    sessions: HashMap<SessionId, Session>,
    incoming: mpsc::Sender<Arc<SessionState>>,
    rejected: mpsc::Sender<RejectedDatagram>,
    revoked: HashSet<PublicKey>,
    seen: HashMap<SessionId, Instant>,
}

impl Driver {
    fn reject(&self, packet: &[u8], source: SocketAddr, reason: RejectionReason) {
        let _ = self.rejected.try_send(RejectedDatagram {
            data: Bytes::copy_from_slice(packet),
            source,
            local_address: self.local,
            reason,
        });
    }

    fn initiation(&mut self, packet: &[u8], source: SocketAddr, id: SessionId) {
        let Some(config) = &mut self.config else {
            return;
        };
        if !crypto::verify_gate(config.public, packet) {
            self.reject(packet, source, RejectionReason::AuthenticationFailed);
            return;
        }
        if let Some(session) = self.sessions.get(&id) {
            // Retransmissions resend the same response, never reset cipher state.
            if session.remote == source
                && session.initiation.as_deref() == Some(packet)
                && !session.state.is_closed()
                && let Some(response) = &session.response
            {
                let _ = self.socket.try_send_to(response, source);
            }
            return;
        }
        if self.seen.contains_key(&id) {
            return;
        }
        if self.sessions.len() >= MAX_SESSIONS || self.seen.len() >= MAX_SESSIONS * 4 {
            self.reject(packet, source, RejectionReason::CapacityReached);
            return;
        }
        let Ok((crypto, key, time, response)) =
            crypto::respond(&config.private, config.psk, id, packet)
        else {
            self.reject(packet, source, RejectionReason::AuthenticationFailed);
            return;
        };
        if timestamp().map_or(true, |now| now.abs_diff(time) > 30) {
            self.reject(packet, source, RejectionReason::ExpiredHandshake);
            return;
        }
        if self.revoked.contains(&key) || !(config.authorize)(key) {
            self.reject(packet, source, RejectionReason::UnauthorizedPeer);
            return;
        }
        let mut session = Session::new(id, crypto, key, source, false);
        let _ = self.socket.try_send_to(&response, source);
        session.response = Some(response);
        session.initiation = Some(packet.to_vec());
        self.seen.insert(id, Instant::now());
        self.sessions.insert(id, session);
    }

    fn packet(&mut self, packet: &[u8], source: SocketAddr, elapsed: u32) {
        if packet.len() < crypto::HEADER || &packet[..4] != crypto::MAGIC {
            self.reject(packet, source, RejectionReason::UnknownProtocol);
            return;
        }
        if packet.len() > crypto::MTU {
            self.reject(packet, source, RejectionReason::MalformedPacket);
            return;
        }
        let Ok(id) = packet[5..crypto::HEADER].try_into() else {
            return;
        };
        match packet[4] {
            crypto::INIT => self.initiation(packet, source, id),
            crypto::TRANSPORT => {
                let Some(session) = self.sessions.get_mut(&id) else {
                    self.reject(packet, source, RejectionReason::UnknownSession);
                    return;
                };
                let Ok(payload) = session.crypto.decrypt(packet) else {
                    self.reject(packet, source, RejectionReason::AuthenticationFailed);
                    return;
                };
                // Only authenticated packets may update the roaming UDP endpoint.
                session.remote = source;
                session.last_received = Instant::now();
                // Closing sessions process only authenticated close/ack retransmissions.
                if session.state.is_closed()
                    && payload != [crypto::CLOSE]
                    && payload != [crypto::CLOSE_ACK]
                {
                    return;
                }
                if !session.confirmed {
                    // The first authenticated KCP/keepalive packet provides key
                    // confirmation, including PSK possession, without extra frames.
                    if self.incoming.try_send(session.state.clone()).is_err() {
                        session.begin_close(&self.socket, None);
                        return;
                    }
                    session.confirmed = true;
                }
                match payload.as_slice() {
                    [rekey::INIT | rekey::RESPONSE, ..] if session.confirmed => {
                        let credentials = self
                            .config
                            .as_ref()
                            .map(|cfg| (&cfg.private, cfg.psk))
                            .or_else(|| {
                                self.client_keys
                                    .as_ref()
                                    .map(|(private, psk)| (private, *psk))
                            });
                        if let Some((private, psk)) = credentials {
                            let context = rekey::Context {
                                id: session.id,
                                peer: session.state.identity.key,
                                initiator: session.state.initiator,
                                private,
                                psk,
                            };
                            let epoch = crypto::packet_epoch(packet).unwrap_or(0);
                            let result = session.crypto.handle(context, epoch, &payload);
                            // Check live authorization again after authenticating
                            // the fresh handshake, before sending its response.
                            if payload[0] == rekey::INIT
                                && result.is_ok()
                                && let Some(config) = &mut self.config
                                && !(config.authorize)(session.state.identity.key)
                            {
                                session.begin_close(&self.socket, None);
                                return;
                            }
                            match result {
                                Ok(Some(packet)) => {
                                    let _ = self.socket.try_send_to(&packet, session.remote);
                                }
                                Ok(None) => {}
                                Err(error) => tracing::debug!(%error, "rekey message rejected"),
                            }
                        }
                    }
                    [crypto::CLOSE] => session.receive_close(&self.socket),
                    [crypto::CLOSE_ACK] => {
                        if let Some(closing) = &mut session.closing {
                            closing.complete();
                        }
                    }
                    [crypto::PING] if session.confirmed => {
                        session.send(&self.socket, &[crypto::PONG])
                    }
                    [crypto::PONG] if session.confirmed => {}
                    [crypto::SEGMENT, segment @ ..] if session.confirmed => {
                        if let Err(error) = session.segment(segment, elapsed) {
                            tracing::debug!(%error, "invalid authenticated KCP segment");
                        }
                        session.update(&self.socket, elapsed, false);
                    }
                    _ => {}
                }
            }
            crypto::RESPONSE => {} // a delayed duplicate handshake response
            _ => self.reject(packet, source, RejectionReason::MalformedPacket),
        }
    }

    fn tick(&mut self, elapsed: u32) {
        self.seen
            .retain(|_, time| time.elapsed() < Duration::from_secs(65));
        self.sessions.retain(|_, session| {
            let expired = if session.confirmed {
                session.last_received.elapsed() >= IDLE_TIMEOUT
            } else {
                session.created.elapsed() >= HANDSHAKE_TIMEOUT
            };
            if expired || session.crypto.expired() || session.state.is_closed() {
                if session.closing.is_none() {
                    session.begin_close(&self.socket, None);
                }
                let retry = session.closing.as_ref().is_some_and(|c| {
                    !c.acknowledged
                        && c.started.elapsed() < Duration::from_secs(1)
                        && c.last_sent.elapsed() >= RETRY
                });
                if retry {
                    session.send(&self.socket, &[crypto::CLOSE]);
                    if let Some(closing) = &mut session.closing {
                        closing.last_sent = Instant::now();
                    }
                }
                if let Some(closing) = &mut session.closing {
                    if closing.started.elapsed() >= Duration::from_secs(1) {
                        // Release callers even when the peer has gone away.
                        for waiter in closing.waiters.drain(..) {
                            let _ = waiter.send(());
                        }
                    }
                    // Linger only to answer close retries; never run KCP or keepalives.
                    return closing.started.elapsed() < Duration::from_secs(2);
                }
                return false;
            }
            if session.confirmed {
                let context = self
                    .client_keys
                    .as_ref()
                    .map(|(private, psk)| rekey::Context {
                        id: session.id,
                        peer: session.state.identity.key,
                        initiator: true,
                        private,
                        psk: *psk,
                    });
                match session.crypto.tick(context) {
                    Ok(Some(packet)) => {
                        let _ = self.socket.try_send_to(&packet, session.remote);
                    }
                    Ok(None) => {}
                    Err(_) => {
                        session.begin_close(&self.socket, None);
                        return true;
                    }
                }
                session.update(&self.socket, elapsed, true);
                if session.last_ping.elapsed() >= Duration::from_secs(10) {
                    session.send(&self.socket, &[crypto::PING]);
                    session.last_ping = Instant::now();
                }
            }
            true
        });
    }

    async fn run(mut self, mut commands: mpsc::Receiver<Command>) {
        if self.socket.writable().await.is_err() {
            return;
        }
        let start = Instant::now();
        let mut tick = tokio::time::interval(Duration::from_millis(10));
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        let mut buf = [0; 65536];
        let mut drain: Option<Instant> = None;
        loop {
            tokio::select! {
                command = commands.recv(), if drain.is_none() => match command {
                    #[cfg(test)]
                    Some(Command::AgeKeys(age, ack)) => {
                        for session in self.sessions.values_mut() { session.crypto.age_for_test(age); }
                        let _ = ack.send(());
                    }
                    Some(Command::Close(id, ack)) => {
                        if let Some(session) = self.sessions.get_mut(&id) {
                            session.begin_close(&self.socket, Some(ack));
                        } else { let _ = ack.send(()); }
                    }
                    Some(Command::Revoke(key, ack)) => {
                        self.revoked.insert(key);
                        for session in self.sessions.values_mut().filter(|s| s.state.identity.key == key) {
                            session.begin_close(&self.socket, None);
                        }
                        let _ = ack.send(());
                    }
                    Some(Command::Shutdown(ack)) => { let _ = ack.send(()); break; }
                    None => drain = Some(Instant::now()),
                },
                received = self.socket.recv_from(&mut buf) => match received {
                    Ok((len, source)) => self.packet(&buf[..len], source, start.elapsed().as_millis() as u32),
                    Err(error) => { tracing::debug!(%error, "UDP receiver stopped"); break; }
                },
                _ = self.io_ready.notified() => {
                    let elapsed = start.elapsed().as_millis() as u32;
                    for session in self.sessions.values_mut() {
                        if session.confirmed && !session.state.is_closed() && !session.crypto.expired() {
                            session.update(&self.socket, elapsed, false);
                        }
                    }
                },
                _ = tick.tick() => {
                    self.tick(start.elapsed().as_millis() as u32);
                    if drain.is_some_and(|time| time.elapsed() >= DRAIN_TIMEOUT) { break; }
                },
            }
        }
        for session in self.sessions.values_mut() {
            session.send(&self.socket, &[crypto::CLOSE]);
            session.state.close();
        }
    }
}

#[cfg(test)]
mod tests {
    use std::sync::atomic::{AtomicU32, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    use super::*;

    #[tokio::test(flavor = "current_thread")]
    async fn live_conversations_survive_two_fresh_handshakes_and_recheck_authorization() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let private = PrivateKey::from_bytes([210; 32]);
            let public = private.public_key();
            let calls = Arc::new(AtomicU32::new(0));
            let checked = calls.clone();
            let mut server = Server::builder(private).authorize(Box::new(move |_| {
                // Admit initially and for two rekeys, then withdraw policy.
                checked.fetch_add(1, Ordering::Relaxed) < 3
            })).bind("127.0.0.1:0").await.unwrap();
            let front = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let relay = front.local_addr().unwrap();
            let back = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let server_address = server.local_addr();
            let observed = Arc::new(AtomicU32::new(0));
            let seen = observed.clone();
            let mut tasks = tokio::task::JoinSet::new();
            tasks.spawn(async move {
                let mut a = [0; 1500];
                let mut b = [0; 1500];
                let mut client = None;
                loop {
                    tokio::select! {
                        received = front.recv_from(&mut a) => {
                            let (len, source) = received.unwrap();
                            client = Some(source);
                            back.send_to(&a[..len], server_address).await.unwrap();
                        }
                        received = back.recv_from(&mut b) => {
                            let (len, _) = received.unwrap();
                            if b[4] == crypto::TRANSPORT {
                                seen.fetch_max(crypto::packet_epoch(&b[..len]).unwrap(), Ordering::Relaxed);
                            }
                            if let Some(client) = client { front.send_to(&b[..len], client).await.unwrap(); }
                        }
                    }
                }
            });
            let client = Client::builder(PrivateKey::from_bytes([211; 32])).remote(relay, public).connect().await.unwrap();
            let mut first = client.connection().open_stream().await.unwrap();
            let mut second = client.connection().open_stream().await.unwrap();
            let connection = server.accept().await.unwrap();
            for _ in 0..2 {
                let mut stream = connection.accept_stream().await.unwrap();
                tasks.spawn(async move {
                    let mut buffer = [0; 8192];
                    while let Ok(count) = stream.read(&mut buffer).await {
                        if count == 0 { break; }
                        if stream.write_all(&buffer[..count]).await.is_err() { break; }
                    }
                });
            }
            let ids = [first.conversation_id(), second.conversation_id()];
            for generation in 0..=2 {
                if generation > 0 {
                    let (tx, rx) = oneshot::channel();
                    client.connection.network.command.send(Command::AgeKeys(rekey::REKEY_AFTER, tx)).await.unwrap();
                    rx.await.unwrap();
                }
                // Keep both streams active while the rekey handshake runs.
                loop {
                    for (n, stream) in [&mut first, &mut second].into_iter().enumerate() {
                        let data = vec![(generation * 7 + n as u32) as u8; 32 * 1024];
                        stream.write_all(&data).await.unwrap();
                        let mut reply = vec![0; data.len()];
                        stream.read_exact(&mut reply).await.unwrap();
                        assert_eq!(reply, data);
                        assert_eq!(stream.conversation_id(), ids[n]);
                    }
                    if observed.load(Ordering::Relaxed) >= generation { break; }
                    tokio::task::yield_now().await;
                }
            }
            assert_eq!(calls.load(Ordering::Relaxed), 3, "admission and both rekeys must check policy");
            let (tx, rx) = oneshot::channel();
            client.connection.network.command.send(Command::AgeKeys(rekey::REKEY_AFTER, tx)).await.unwrap();
            rx.await.unwrap();
            client.connection.closed().await;
            connection.closed().await;
            assert_eq!(calls.load(Ordering::Relaxed), 4);
            client.close().await;
        }).await.expect("live rekey test timed out");
    }
}
