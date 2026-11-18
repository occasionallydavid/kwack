//! Fresh IKpsk2 exchanges inside an existing authenticated session.
//! KCP state and the logical session ID survive key generation changes.
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use std::{io, mem};

use tokio::time::Instant;

use crate::crypto::{self, DatagramCrypto, Initiation, SessionId};
use crate::{Error, PrivateKey, PublicKey};

pub(crate) const REKEY_AFTER: Duration = Duration::from_secs(120);

pub(crate) const REJECT_AFTER: Duration = Duration::from_secs(180);

pub(crate) const INIT: u8 = 8;

pub(crate) const RESPONSE: u8 = 9;

const RETRY: Duration = Duration::from_millis(200);

pub(crate) struct Context<'a> {
    pub id: SessionId,
    pub peer: PublicKey,
    pub initiator: bool,
    pub private: &'a PrivateKey,
    pub psk: [u8; 32],
}

struct Epoch {
    crypto: DatagramCrypto,
    created: Instant,
}

struct Pending {
    epoch: u32,
    created: Instant,
    last_sent: Instant,
    phase: Phase,
}

enum Phase {
    Initiating {
        handshake: Box<Initiation>,
        opening: Vec<u8>,
    },
    Confirming {
        keys: Epoch,
    },
    Responding {
        keys: Epoch,
        opening: Vec<u8>,
        response: Vec<u8>,
    },
}

pub(crate) struct SessionKeys {
    current: Epoch,
    previous: Option<Epoch>,
    pending: Option<Pending>,
}

impl SessionKeys {
    pub(crate) fn new(crypto: DatagramCrypto) -> Self {
        Self {
            current: Epoch {
                crypto,
                created: Instant::now(),
            },
            previous: None,
            pending: None,
        }
    }

    pub(crate) fn expired(&self) -> bool {
        self.current.created.elapsed() >= REJECT_AFTER
    }

    pub(crate) fn epoch(&self) -> u32 {
        self.current.crypto.epoch()
    }

    pub(crate) fn encrypt(&mut self, id: SessionId, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if self.expired() {
            return Err(io::Error::other("Noise keys expired").into());
        }
        self.current.crypto.encrypt(id, payload)
    }

    pub(crate) fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        let epoch = crypto::packet_epoch(packet)?;
        self.expire_previous();
        if epoch == self.epoch() && !self.expired() {
            return self.current.crypto.decrypt(packet);
        }
        if let Some(previous) = &mut self.previous
            && epoch == previous.crypto.epoch()
        {
            return previous.crypto.decrypt(packet);
        }
        if let Some(pending) = &mut self.pending
            && epoch == pending.epoch
        {
            let keys = match &mut pending.phase {
                Phase::Confirming { keys } | Phase::Responding { keys, .. } => keys,
                Phase::Initiating { .. } => {
                    return Err(io::Error::other("keys not established").into());
                }
            };
            if keys.created.elapsed() >= REJECT_AFTER {
                return Err(io::Error::other("pending Noise keys expired").into());
            }
            let plaintext = keys.crypto.decrypt(packet)?;
            // Any valid new-key datagram proves possession, including the first
            // KCP packet. There is no confirmation-ack round trip.
            self.promote();
            return Ok(plaintext);
        }
        Err(io::Error::other("unknown or expired key generation").into())
    }

    fn expire_previous(&mut self) {
        if self
            .previous
            .as_ref()
            .is_some_and(|keys| keys.created.elapsed() >= REJECT_AFTER)
        {
            self.previous = None;
        }
    }

    fn promote(&mut self) {
        let Some(pending) = self.pending.take() else {
            return;
        };
        let next = match pending.phase {
            Phase::Confirming { keys } | Phase::Responding { keys, .. } => keys,
            Phase::Initiating { .. } => return,
        };
        self.previous = Some(mem::replace(&mut self.current, next));
        self.expire_previous();
    }

    pub(crate) fn tick(&mut self, context: Option<Context<'_>>) -> Result<Option<Vec<u8>>, Error> {
        self.expire_previous();
        let Some(context) = context else {
            return Ok(None);
        };
        if self.expired() {
            return Err(io::Error::other("Noise keys expired").into());
        }
        if self.pending.is_none() && self.current.created.elapsed() >= REKEY_AFTER {
            let epoch = self
                .epoch()
                .checked_add(1)
                .ok_or_else(|| io::Error::other("key generations exhausted"))?;
            let (handshake, opening) = crypto::initiate_epoch(
                context.private,
                context.peer,
                context.psk,
                context.id,
                timestamp()?,
                epoch,
            )?;
            self.pending = Some(Pending {
                epoch,
                created: Instant::now(),
                last_sent: Instant::now() - RETRY,
                phase: Phase::Initiating {
                    handshake: Box::new(handshake),
                    opening,
                },
            });
        }
        let Some(pending) = &mut self.pending else {
            return Ok(None);
        };
        if pending.last_sent.elapsed() < RETRY {
            return Ok(None);
        }
        pending.last_sent = Instant::now();
        match &mut pending.phase {
            Phase::Initiating { opening, .. } => {
                let payload = message(INIT, pending.epoch, opening);
                Ok(Some(self.encrypt(context.id, &payload)?))
            }
            // New-key KCP packets or ordinary keepalives confirm the handshake.
            // There are no standalone confirmation or acknowledgment messages.
            Phase::Confirming { .. } => Ok(None),
            Phase::Responding { .. } => Ok(None),
        }
    }

    /// Sending switches to the candidate keys immediately after a valid Noise
    /// response, without waiting for an acknowledgment from the peer.
    pub(crate) fn encrypt_data(&mut self, id: SessionId, payload: &[u8]) -> Result<Vec<u8>, Error> {
        if let Some(Pending {
            phase: Phase::Confirming { keys },
            ..
        }) = &mut self.pending
        {
            if keys.created.elapsed() >= REJECT_AFTER {
                return Err(io::Error::other("Noise keys expired").into());
            }
            return keys.crypto.encrypt(id, payload);
        }
        self.encrypt(id, payload)
    }

    pub(crate) fn handle(
        &mut self,
        context: Context<'_>,
        packet_epoch: u32,
        payload: &[u8],
    ) -> Result<Option<Vec<u8>>, Error> {
        if payload.len() < 5 || packet_epoch != self.epoch() {
            return Err(io::Error::other("invalid rekey message").into());
        }
        let epoch = u32::from_le_bytes(payload[1..5].try_into()?);
        if self.epoch().checked_add(1) != Some(epoch) {
            return Err(io::Error::other("unexpected key generation").into());
        }
        match payload[0] {
            INIT if !context.initiator => {
                let opening = &payload[5..];
                if let Some(pending) = &self.pending {
                    if let Phase::Responding {
                        opening: cached,
                        response,
                        ..
                    } = &pending.phase
                        && pending.epoch == epoch
                        && cached == opening
                    {
                        let payload = message(RESPONSE, epoch, response);
                        return Ok(Some(self.encrypt(context.id, &payload)?));
                    }
                    return Err(io::Error::other("conflicting rekey initiation").into());
                }
                if opening.get(5..crypto::HEADER) != Some(context.id.as_slice())
                    || !crypto::verify_gate(context.private.public_key(), opening)
                {
                    return Err(io::Error::other("invalid rekey opening").into());
                }
                let (crypto, peer, _time, response) = crypto::respond_epoch(
                    context.private,
                    context.psk,
                    context.id,
                    opening,
                    epoch,
                )?;
                // This opening is already authenticated by the live outer
                // session and bound to its next generation. Applying the cold
                // opening's wall-clock limit here would break delayed retries.
                if peer != context.peer {
                    return Err(io::Error::other("rekey peer mismatch").into());
                }
                let payload = message(RESPONSE, epoch, &response);
                self.pending = Some(Pending {
                    epoch,
                    created: Instant::now(),
                    last_sent: Instant::now(),
                    phase: Phase::Responding {
                        keys: Epoch {
                            crypto,
                            created: Instant::now(),
                        },
                        opening: opening.to_vec(),
                        response,
                    },
                });
                Ok(Some(self.encrypt(context.id, &payload)?))
            }
            RESPONSE if context.initiator => {
                let Some(pending) = &mut self.pending else {
                    return Ok(None);
                };
                if pending.epoch != epoch {
                    return Err(io::Error::other("unexpected rekey response").into());
                }
                let Phase::Initiating { handshake, .. } = &pending.phase else {
                    return Ok(None);
                };
                if payload[5..].get(5..crypto::HEADER) != Some(context.id.as_slice()) {
                    return Err(io::Error::other("rekey response session mismatch").into());
                }
                // Bad replies must not poison the cached handshake state.
                let crypto =
                    crypto::finish_epoch(&mut handshake.as_ref().clone(), &payload[5..], epoch)?;
                pending.phase = Phase::Confirming {
                    keys: Epoch {
                        crypto,
                        created: pending.created,
                    },
                };
                // Application data uses the new keys immediately. KCP ACKs or
                // ordinary keepalives confirm possession without another flight.
                Ok(None)
            }
            _ => Err(io::Error::other("invalid rekey role or message").into()),
        }
    }

    #[cfg(test)]
    pub(crate) fn age_for_test(&mut self, age: Duration) {
        self.current.created -= age;
    }
}

fn message(kind: u8, epoch: u32, noise: &[u8]) -> Vec<u8> {
    let mut payload = Vec::with_capacity(5 + noise.len());
    payload.push(kind);
    payload.extend_from_slice(&epoch.to_le_bytes());
    payload.extend_from_slice(noise);
    payload
}

fn timestamp() -> Result<u64, Error> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Peers {
        client_private: PrivateKey,
        server_private: PrivateKey,
        client: SessionKeys,
        server: SessionKeys,
        id: SessionId,
    }

    impl Peers {
        fn new() -> Self {
            let client_private = PrivateKey::from_bytes([201; 32]);
            let server_private = PrivateKey::from_bytes([202; 32]);
            let id = [0x55; 16];
            let (mut handshake, opening) = crypto::initiate(
                &client_private,
                server_private.public_key(),
                [0; 32],
                id,
                timestamp().unwrap(),
            )
            .unwrap();
            let (server, _, _, response) =
                crypto::respond(&server_private, [0; 32], id, &opening).unwrap();
            let client = crypto::finish(&mut handshake, &response).unwrap();
            Self {
                client_private,
                server_private,
                client: SessionKeys::new(client),
                server: SessionKeys::new(server),
                id,
            }
        }

        fn tick(&mut self) -> Option<Vec<u8>> {
            self.client
                .tick(Some(Context {
                    id: self.id,
                    peer: self.server_private.public_key(),
                    initiator: true,
                    private: &self.client_private,
                    psk: [0; 32],
                }))
                .unwrap()
        }

        fn deliver_server(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, Error> {
            let payload = self.server.decrypt(packet)?;
            self.server.handle(
                Context {
                    id: self.id,
                    peer: self.client_private.public_key(),
                    initiator: false,
                    private: &self.server_private,
                    psk: [0; 32],
                },
                crypto::packet_epoch(packet)?,
                &payload,
            )
        }

        fn deliver_client(&mut self, packet: &[u8]) -> Result<Option<Vec<u8>>, Error> {
            let payload = self.client.decrypt(packet)?;
            self.client.handle(
                Context {
                    id: self.id,
                    peer: self.server_private.public_key(),
                    initiator: true,
                    private: &self.client_private,
                    psk: [0; 32],
                },
                crypto::packet_epoch(packet)?,
                &payload,
            )
        }

        fn exchange_data(&mut self, epoch: u32) {
            // No confirmation frame: real data is immediately usable under new keys.
            let data = self.client.encrypt_data(self.id, b"request").unwrap();
            assert_eq!(crypto::packet_epoch(&data).unwrap(), epoch);
            assert_eq!(self.server.decrypt(&data).unwrap(), b"request");
            let reply = self.server.encrypt_data(self.id, b"reply").unwrap();
            assert_eq!(self.client.decrypt(&reply).unwrap(), b"reply");
            assert_eq!(self.client.epoch(), epoch);
            assert_eq!(self.server.epoch(), epoch);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn fresh_handshakes_every_120_seconds_and_old_keys_expire_at_180() {
        let mut peers = Peers::new();
        let old = peers
            .client
            .encrypt_data(peers.id, b"old reordered packet")
            .unwrap();
        let too_late = peers
            .client
            .encrypt_data(peers.id, b"expired old packet")
            .unwrap();
        let old_reply = peers
            .server
            .encrypt_data(peers.id, b"expired old reply")
            .unwrap();
        tokio::time::advance(Duration::from_secs(119)).await;
        assert!(peers.tick().is_none());
        tokio::time::advance(Duration::from_secs(1)).await;
        let opening = peers.tick().expect("rekey must start at 120 seconds");
        let response = peers.deliver_server(&opening).unwrap().unwrap();
        assert!(peers.deliver_client(&response).unwrap().is_none());
        peers.exchange_data(1);
        assert_eq!(peers.server.decrypt(&old).unwrap(), b"old reordered packet");
        assert!(peers.server.decrypt(&old).is_err());
        tokio::time::advance(Duration::from_secs(60)).await;
        assert!(peers.server.decrypt(&too_late).is_err());
        assert!(peers.client.decrypt(&old_reply).is_err());
        assert!(peers.client.previous.is_none());
        tokio::time::advance(Duration::from_secs(60)).await;
        let second_opening = peers.tick().expect("next rekey at 240 seconds");
        let response = peers.deliver_server(&second_opening).unwrap().unwrap();
        peers.deliver_client(&response).unwrap();
        peers.exchange_data(2);
    }

    #[tokio::test(start_paused = true)]
    async fn losses_duplicates_and_bad_replies_do_not_reset_keys_or_nonces() {
        let mut peers = Peers::new();
        tokio::time::advance(REKEY_AFTER).await;
        let _lost_opening = peers.tick().unwrap();
        tokio::time::advance(RETRY).await;
        let opening = peers.tick().unwrap();
        let lost_response = peers.deliver_server(&opening).unwrap().unwrap();
        tokio::time::advance(RETRY).await;
        let retry = peers.tick().unwrap();
        assert_ne!(retry, opening, "outer retries must use fresh nonces");
        let response = peers.deliver_server(&retry).unwrap().unwrap();
        let mut forged = response.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(peers.deliver_client(&forged).is_err());
        peers.deliver_client(&response).unwrap();
        // A delayed response is harmless while the client is already sending
        // with the new keys; it must not reset its candidate packet counter.
        peers.deliver_client(&lost_response).unwrap();
        let first = peers.client.encrypt_data(peers.id, b"first").unwrap();
        let second = peers.client.encrypt_data(peers.id, b"second").unwrap();
        let mut forged = first.clone();
        *forged.last_mut().unwrap() ^= 1;
        assert!(peers.server.decrypt(&forged).is_err());
        assert_eq!(peers.server.epoch(), 0);
        assert_eq!(peers.server.decrypt(&second).unwrap(), b"second");
        assert_eq!(peers.server.decrypt(&first).unwrap(), b"first");
        assert!(peers.server.decrypt(&second).is_err());
        assert!(peers.deliver_server(&opening).is_err());
        peers.exchange_data(1);
    }

    #[tokio::test(start_paused = true)]
    async fn rekey_is_bound_to_peer_session_and_generation_and_fails_closed() {
        let mut peers = Peers::new();
        let other = PrivateKey::from_bytes([203; 32]);
        let (_, opening) = crypto::initiate_epoch(
            &other,
            peers.server_private.public_key(),
            [0; 32],
            peers.id,
            timestamp().unwrap(),
            1,
        )
        .unwrap();
        let packet = peers
            .client
            .encrypt(peers.id, &message(INIT, 1, &opening))
            .unwrap();
        assert!(
            peers.deliver_server(&packet).is_err(),
            "cannot replace a connection's static identity"
        );
        assert!(peers.server.pending.is_none());
        tokio::time::advance(REKEY_AFTER).await;
        let _lost = peers.tick().unwrap();
        let old = peers.server.encrypt(peers.id, b"old").unwrap();
        tokio::time::advance(REJECT_AFTER - REKEY_AFTER).await;
        assert!(peers.client.expired());
        assert!(
            peers
                .client
                .encrypt_data(peers.id, b"must not send")
                .is_err()
        );
        assert!(peers.client.decrypt(&old).is_err());
        assert!(peers.server.expired());
    }
}
