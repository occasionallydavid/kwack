//! Outer Noise IKpsk2 datagrams. KCP sees only authenticated plaintext.
use std::io;

use blake2::digest::{KeyInit, Mac};
use blake2::{Blake2s256, Blake2sMac, Digest};
use noise_protocol::{Cipher, CipherState, DH, HandshakeState, U8Array};
use noise_rust_crypto::sensitive::Sensitive;
use noise_rust_crypto::{Blake2s, ChaCha20Poly1305, X25519};
use subtle::ConstantTimeEq;

use crate::{Error, PrivateKey, PublicKey};

pub(crate) type SessionId = [u8; 16];

pub(crate) type Initiation = HandshakeState<CheckedX25519, ChaCha20Poly1305, Blake2s>;

pub(crate) enum CheckedX25519 {}

impl DH for CheckedX25519 {
    type Key = <X25519 as DH>::Key;
    type Pubkey = <X25519 as DH>::Pubkey;
    type Output = <X25519 as DH>::Output;

    fn name() -> &'static str {
        X25519::name()
    }

    fn genkey() -> Self::Key {
        X25519::genkey()
    }

    fn pubkey(key: &Self::Key) -> Self::Pubkey {
        X25519::pubkey(key)
    }

    fn dh(key: &Self::Key, peer: &Self::Pubkey) -> Result<Self::Output, ()> {
        let shared = X25519::dh(key, peer)?;
        if bool::from(shared.as_slice().ct_eq(&[0; 32])) {
            return Err(());
        }
        Ok(shared)
    }
}

pub(crate) const MAGIC: &[u8; 4] = b"KW\x01\x00";

pub(crate) const INIT: u8 = 1;

pub(crate) const RESPONSE: u8 = 2;

pub(crate) const TRANSPORT: u8 = 3;

pub(crate) const HEADER: usize = 21;

pub(crate) const DATA_HEADER: usize = HEADER + 8;

pub(crate) const MTU: usize = 1200;

pub(crate) const SEGMENT: u8 = 3;

pub(crate) const CLOSE: u8 = 4;

pub(crate) const CLOSE_ACK: u8 = 7;

pub(crate) const PING: u8 = 5;

pub(crate) const PONG: u8 = 6;

const INIT_NOISE_LEN: usize = 104; // e(32), encrypted s(48), encrypted timestamp(24)

pub(crate) const INIT_LEN: usize = HEADER + INIT_NOISE_LEN + 16;

pub(crate) const RESPONSE_LEN: usize = HEADER + 48;

pub(crate) fn header(kind: u8, id: SessionId) -> Vec<u8> {
    let mut result = Vec::from(*MAGIC);
    result.push(kind);
    result.extend_from_slice(&id);
    result
}

fn prologue(id: SessionId, epoch: u32) -> Vec<u8> {
    let mut p = b"kwack/1 outer IKpsk2; inner KCP records\0".to_vec();
    p.extend_from_slice(&id);
    p.extend_from_slice(&epoch.to_le_bytes());
    p
}

fn gate(key: PublicKey, packet: &[u8]) -> [u8; 16] {
    let mut hash = Blake2s256::new();
    Digest::update(&mut hash, b"kwack/1 opening gate\0");
    Digest::update(&mut hash, key.as_bytes());
    let key = hash.finalize();
    // Blake2 accepts every 32-byte key; use a fixed 16-byte output MAC.
    let mut mac = <Blake2sMac<blake2::digest::consts::U16> as KeyInit>::new(&key);
    Mac::update(&mut mac, packet);
    mac.finalize().into_bytes().into()
}

pub(crate) fn verify_gate(public: PublicKey, packet: &[u8]) -> bool {
    packet.len() == INIT_LEN
        && bool::from(gate(public, &packet[..INIT_LEN - 16]).ct_eq(&packet[INIT_LEN - 16..]))
}

pub(crate) fn initiate(
    private: &PrivateKey,
    public: PublicKey,
    psk: [u8; 32],
    id: SessionId,
    timestamp: u64,
) -> Result<(Initiation, Vec<u8>), Error> {
    initiate_epoch(private, public, psk, id, timestamp, 0)
}

pub(crate) fn initiate_epoch(
    private: &PrivateKey,
    public: PublicKey,
    psk: [u8; 32],
    id: SessionId,
    timestamp: u64,
    epoch: u32,
) -> Result<(Initiation, Vec<u8>), Error> {
    let mut hs = Initiation::new(
        noise_protocol::patterns::noise_ik_psk2(),
        true,
        prologue(id, epoch),
        Some(Sensitive::from_slice(private.secret().as_bytes())),
        None,
        Some(*public.as_bytes()),
        None,
    );
    hs.push_psk(&psk);
    let mut noise = [0; INIT_NOISE_LEN];
    hs.write_message(&timestamp.to_le_bytes(), &mut noise)?;
    let mut packet = header(INIT, id);
    packet.extend_from_slice(&noise);
    packet.extend_from_slice(&gate(public, &packet));
    Ok((hs, packet))
}

pub(crate) fn respond(
    private: &PrivateKey,
    psk: [u8; 32],
    id: SessionId,
    packet: &[u8],
) -> Result<(DatagramCrypto, PublicKey, u64, Vec<u8>), Error> {
    respond_epoch(private, psk, id, packet, 0)
}

pub(crate) fn respond_epoch(
    private: &PrivateKey,
    psk: [u8; 32],
    id: SessionId,
    packet: &[u8],
    epoch: u32,
) -> Result<(DatagramCrypto, PublicKey, u64, Vec<u8>), Error> {
    if packet.len() != INIT_LEN {
        return Err(io::Error::other("invalid initiation length").into());
    }
    let mut hs = Initiation::new(
        noise_protocol::patterns::noise_ik_psk2(),
        false,
        prologue(id, epoch),
        Some(Sensitive::from_slice(private.secret().as_bytes())),
        None,
        None,
        None,
    );
    hs.push_psk(&psk);
    let mut payload = [0; 8];
    hs.read_message(&packet[HEADER..INIT_LEN - 16], &mut payload)?;
    let timestamp = u64::from_le_bytes(payload);
    let public = hs
        .get_rs()
        .ok_or_else(|| io::Error::other("missing client identity"))?;
    let mut response = header(RESPONSE, id);
    let mut noise = [0; 48];
    hs.write_message(&[], &mut noise)?;
    response.extend_from_slice(&noise);
    Ok((
        DatagramCrypto::new(&hs, epoch),
        PublicKey::from_bytes(public),
        timestamp,
        response,
    ))
}

pub(crate) fn finish(hs: &mut Initiation, packet: &[u8]) -> Result<DatagramCrypto, Error> {
    finish_epoch(hs, packet, 0)
}

pub(crate) fn finish_epoch(
    hs: &mut Initiation,
    packet: &[u8],
    epoch: u32,
) -> Result<DatagramCrypto, Error> {
    if packet.len() != RESPONSE_LEN {
        return Err(io::Error::other("invalid response length").into());
    }
    hs.read_message(&packet[HEADER..], &mut [])?;
    Ok(DatagramCrypto::new(hs, epoch))
}

/// Epoch shares the existing 64-bit wire counter: high 32 bits are the key
/// generation, low 32 bits are the per-direction packet number.
pub(crate) fn packet_epoch(packet: &[u8]) -> Result<u32, Error> {
    let bytes = packet
        .get(HEADER..DATA_HEADER)
        .ok_or_else(|| io::Error::other("truncated counter"))?;
    Ok((u64::from_le_bytes(bytes.try_into()?) >> 32) as u32)
}

/// Sliding window shared by packet counters and remote conversation allocation.
/// Test first, then commit only after authenticating the packet.
#[derive(Default)]
pub(crate) struct ReplayWindow {
    highest: u64,
    bits: [u64; 32],
    initialized: bool,
}

impl ReplayWindow {
    pub(crate) fn contains(&self, n: u64) -> bool {
        if !self.initialized || n > self.highest {
            return false;
        }
        let age = self.highest - n;
        age >= 2048 || self.bits[(age / 64) as usize] & (1 << (age % 64)) != 0
    }

    pub(crate) fn insert(&mut self, n: u64) {
        if !self.initialized {
            self.highest = n;
            self.initialized = true;
        }
        if n > self.highest {
            let delta = n - self.highest;
            let old = self.bits;
            self.bits = [0; 32];
            if delta < 2048 {
                for age in 0..2048 - delta {
                    if old[(age / 64) as usize] & (1 << (age % 64)) != 0 {
                        let shifted = age + delta;
                        self.bits[(shifted / 64) as usize] |= 1 << (shifted % 64);
                    }
                }
            }
            self.highest = n;
        }
        let age = self.highest - n;
        if age < 2048 {
            self.bits[(age / 64) as usize] |= 1 << (age % 64);
        }
    }
}

pub(crate) struct DatagramCrypto {
    send: CipherState<ChaCha20Poly1305>,
    recv: Sensitive<[u8; 32]>,
    counter: u64,
    replay: ReplayWindow,
    epoch: u32,
}

impl DatagramCrypto {
    fn new(state: &Initiation, epoch: u32) -> Self {
        let (init, resp) = state.get_ciphers();
        let (send, recv) = if state.get_is_initiator() {
            (init, resp)
        } else {
            (resp, init)
        };
        let counter = u64::from(epoch) << 32;
        let (key, _) = send.extract();
        Self {
            send: CipherState::new(key.as_slice(), counter),
            recv: recv.extract().0,
            counter,
            replay: ReplayWindow::default(),
            epoch,
        }
    }

    pub(crate) fn epoch(&self) -> u32 {
        self.epoch
    }

    pub(crate) fn encrypt(&mut self, id: SessionId, payload: &[u8]) -> Result<Vec<u8>, Error> {
        // Reserve upper values and never wrap the nonce. Reconnect before exhaustion.
        if self.counter as u32 >= u32::MAX - 1 || payload.len() > MTU - DATA_HEADER - 16 {
            return Err(io::Error::other("Noise packet limit reached").into());
        }
        let mut packet = header(TRANSPORT, id);
        packet.extend_from_slice(&self.counter.to_le_bytes());
        let mut ciphertext = vec![0; payload.len() + 16];
        self.send.encrypt_ad(&packet, payload, &mut ciphertext);
        self.counter += 1;
        packet.extend_from_slice(&ciphertext);
        Ok(packet)
    }

    pub(crate) fn decrypt(&mut self, packet: &[u8]) -> Result<Vec<u8>, Error> {
        if packet.len() < DATA_HEADER + 17 || packet.len() > MTU {
            return Err(io::Error::other("invalid encrypted packet length").into());
        }
        let counter = u64::from_le_bytes(packet[HEADER..DATA_HEADER].try_into()?);
        if (counter >> 32) as u32 != self.epoch
            || counter as u32 >= u32::MAX - 1
            || self.replay.contains(counter)
        {
            return Err(io::Error::other("replayed or expired packet").into());
        }
        let mut plaintext = vec![0; packet.len() - DATA_HEADER - 16];
        ChaCha20Poly1305::decrypt(
            &self.recv,
            counter,
            &packet[..DATA_HEADER],
            &packet[DATA_HEADER..],
            &mut plaintext,
        )
        .map_err(|_| io::Error::other("packet authentication failed"))?;
        self.replay.insert(counter);
        Ok(plaintext)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn x25519_rejects_all_zero_shared_secrets() {
        let local = CheckedX25519::genkey();
        let peer = CheckedX25519::genkey();
        assert!(CheckedX25519::dh(&local, &CheckedX25519::pubkey(&peer)).is_ok());
        assert!(CheckedX25519::dh(&local, &[0; 32]).is_err());
        let mut low_order = [0; 32];
        low_order[0] = 1;
        assert!(CheckedX25519::dh(&local, &low_order).is_err());
    }

    #[test]
    fn datagrams_allow_loss_and_reordering_but_reject_replays_and_forgery() {
        let server_private = PrivateKey::from_bytes([1; 32]);
        let client_private = PrivateKey::from_bytes([2; 32]);
        let public = server_private.public_key();
        let id = [0xa5; 16];
        let (mut hs, opening) = initiate(&client_private, public, [0; 32], id, 123).unwrap();
        assert!(verify_gate(public, &opening));
        assert!(!verify_gate(client_private.public_key(), &opening));
        let (mut server, identity, time, response) =
            respond(&server_private, [0; 32], id, &opening).unwrap();
        assert_eq!(identity, client_private.public_key());
        assert_eq!(time, 123);
        let mut client = finish(&mut hs, &response).unwrap();
        let first = client.encrypt(id, b"first").unwrap();
        let _lost = client.encrypt(id, b"lost").unwrap();
        let third = client.encrypt(id, b"third").unwrap();
        assert_eq!(server.decrypt(&third).unwrap(), b"third");
        assert_eq!(server.decrypt(&first).unwrap(), b"first");
        assert!(server.decrypt(&first).is_err());
        let valid = client.encrypt(id, b"still valid").unwrap();
        let mut forged = valid.clone();
        forged[HEADER..DATA_HEADER].copy_from_slice(&1_000_000u64.to_le_bytes());
        assert!(server.decrypt(&forged).is_err());
        assert_eq!(server.decrypt(&valid).unwrap(), b"still valid");
        let mut forged_id = client.encrypt(id, b"bound header").unwrap();
        forged_id[5] ^= 1;
        assert!(server.decrypt(&forged_id).is_err());
        let response = server.encrypt(id, b"reply").unwrap();
        assert_eq!(client.decrypt(&response).unwrap(), b"reply");
        // Reflection must fail because the two directions have different keys.
        assert!(server.decrypt(&response).is_err());
        for _ in 0..2050 {
            let packet = client.encrypt(id, b"advance window").unwrap();
            server.decrypt(&packet).unwrap();
        }
        assert!(server.decrypt(&first).is_err());
    }
}
