//! Plaintext QUIC for use inside an authenticated, encrypted tunnel.
//!
//! Packet checksums detect accidental corruption; they do not authenticate peers.

use std::{hash::Hasher, sync::Arc};

use bytes::BytesMut;

use quinn_proto::{
    crypto::{self, CryptoError, HeaderKey},
    transport_parameters, ConnectionId, Side, TransportError,
};
use seahash::SeaHasher;
use tracing::trace;

// The frame length excludes its four-byte prefix.
const MAX_HANDSHAKE_LEN: usize = 64 * 1024;

fn write_transport_parameters(
    params: &transport_parameters::TransportParameters,
    buf: &mut Vec<u8>,
) {
    let start = buf.len();
    buf.extend_from_slice(&[0; 4]);
    params.write(buf);
    // Quinn transport parameters have bounded fields and fit in a u32.
    let len = buf.len() - start - 4;
    buf[start..start + 4].copy_from_slice(&(len as u32).to_be_bytes());
}

fn packet_checksum(header: &[u8], payload: &[u8]) -> u64 {
    let mut hasher = SeaHasher::default();
    // Fixed-width lengths preserve the original 64-bit checksum format on every target.
    hasher.write(&(header.len() as u64).to_le_bytes());
    hasher.write(header);
    hasher.write(&(payload.len() as u64).to_le_bytes());
    hasher.write(payload);
    hasher.finish()
}

pub fn server_config() -> quinn_proto::ServerConfig {
    quinn_proto::ServerConfig::with_crypto(Arc::new(PlaintextServerConfig::new()))
}

pub fn client_config() -> quinn_proto::ClientConfig {
    quinn_proto::ClientConfig::new(Arc::new(PlaintextClientConfig::new()))
}

pub struct PlaintextHeaderKey {
    side: Side,
}

impl PlaintextHeaderKey {
    pub fn new(side: Side) -> Self {
        Self { side }
    }
}

impl HeaderKey for PlaintextHeaderKey {
    fn decrypt(&self, pn_offset: usize, _packet: &mut [u8]) {
        trace!(side = ?self.side, "HeaderKey::decrypt pn_offset: {pn_offset}");
    }

    fn encrypt(&self, pn_offset: usize, _packet: &mut [u8]) {
        trace!(side = ?self.side, "HeaderKey::encrypt pn_offset: {pn_offset}");
    }

    fn sample_size(&self) -> usize {
        trace!(side = ?self.side, "HeaderKey::sample_size");
        0
    }
}

pub struct PlaintextPacketKey {
    side: Side,
}

impl PlaintextPacketKey {
    fn new(side: Side) -> Self {
        Self { side }
    }
}

#[derive(Default)]
pub struct PlaintextClientConfig;

impl PlaintextClientConfig {
    pub fn new() -> Self {
        Self
    }
}

#[derive(Default)]
pub struct PlaintextServerConfig;

impl PlaintextServerConfig {
    pub fn new() -> Self {
        Self
    }
}

fn crypto_keys(side: Side) -> crypto::Keys {
    crypto::Keys {
        header: crypto_header_keypair(side),
        packet: crypto_packet_keypair(side),
    }
}

fn crypto_header_keypair(side: Side) -> crypto::KeyPair<Box<dyn crypto::HeaderKey>> {
    crypto::KeyPair {
        local: Box::new(PlaintextHeaderKey::new(side)),
        remote: Box::new(PlaintextHeaderKey::new(side)),
    }
}

fn crypto_packet_keypair(side: Side) -> crypto::KeyPair<Box<dyn crypto::PacketKey>> {
    crypto::KeyPair {
        local: Box::new(PlaintextPacketKey::new(side)),
        remote: Box::new(PlaintextPacketKey::new(side)),
    }
}

/// A plaintext session which does not perform packet encryption/decryption
pub struct PlaintextSession {
    side: Side,
    params: transport_parameters::TransportParameters,
    peer_params: Option<transport_parameters::TransportParameters>,
    handshake_buf: Vec<u8>,
    wrote_transport_params: bool,
    initial_keys: Option<crypto::Keys>,
    handshake_keys: Option<crypto::Keys>,
}

impl PlaintextSession {
    fn new(side: Side, params: transport_parameters::TransportParameters) -> Self {
        Self {
            side,
            params,
            peer_params: None,
            handshake_buf: Vec::new(),
            wrote_transport_params: false,
            initial_keys: Some(crypto_keys(side)),
            handshake_keys: Some(crypto_keys(side)),
        }
    }
}

impl crypto::Session for PlaintextSession {
    fn initial_keys(&self, dst_cid: &ConnectionId, _side: Side) -> crypto::Keys {
        trace!(side = ?self.side, "initial_keys dst_cid: {dst_cid}");
        crypto_keys(self.side)
    }

    fn handshake_data(&self) -> Option<Box<dyn std::any::Any>> {
        trace!(side = ?self.side, "handshake_data");
        self.peer_params
            .map(|tp| Box::new(tp) as Box<dyn std::any::Any>)
    }

    fn peer_identity(&self) -> Option<Box<dyn std::any::Any>> {
        trace!(side = ?self.side, "peer_identity");
        None
    }

    fn early_crypto(&self) -> Option<(Box<dyn crypto::HeaderKey>, Box<dyn crypto::PacketKey>)> {
        trace!(side = ?self.side, "early_crypto");
        None
    }

    fn early_data_accepted(&self) -> Option<bool> {
        trace!(side = ?self.side, "early_data_accepted");
        Some(false)
    }

    fn is_handshaking(&self) -> bool {
        trace!(side = ?self.side, "is_handshaking");
        self.peer_params.is_none()
            || !self.wrote_transport_params
            || self.initial_keys.is_some()
            || self.handshake_keys.is_some()
    }

    fn read_handshake(&mut self, buf: &[u8]) -> Result<bool, TransportError> {
        if self.peer_params.is_some() {
            if buf.is_empty() {
                return Ok(false);
            }
            return Err(TransportError {
                code: quinn_proto::TransportErrorCode::PROTOCOL_VIOLATION,
                frame: None,
                reason: "unexpected handshake data".into(),
            });
        }
        if buf.len() > MAX_HANDSHAKE_LEN + 4 - self.handshake_buf.len() {
            return Err(TransportError {
                code: quinn_proto::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                frame: None,
                reason: "handshake too large".into(),
            });
        }
        self.handshake_buf.extend_from_slice(buf);
        let Some(prefix) = self.handshake_buf.get(..4) else {
            return Ok(false);
        };
        let len = u32::from_be_bytes([prefix[0], prefix[1], prefix[2], prefix[3]]) as usize;
        if len > MAX_HANDSHAKE_LEN {
            return Err(TransportError {
                code: quinn_proto::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                frame: None,
                reason: "handshake too large".into(),
            });
        }
        let expected = len + 4;
        if self.handshake_buf.len() < expected {
            return Ok(false);
        }
        if self.handshake_buf.len() > expected {
            return Err(TransportError {
                code: quinn_proto::TransportErrorCode::TRANSPORT_PARAMETER_ERROR,
                frame: None,
                reason: "trailing handshake data".into(),
            });
        }
        let params = transport_parameters::TransportParameters::read(
            self.side,
            &mut &self.handshake_buf[4..],
        )?;
        self.peer_params = Some(params);
        self.handshake_buf.clear();
        Ok(true)
    }

    fn transport_parameters(
        &self,
    ) -> Result<Option<transport_parameters::TransportParameters>, TransportError> {
        trace!(side = ?self.side, "transport_parameters");
        Ok(self.peer_params)
    }

    fn write_handshake(&mut self, buf: &mut Vec<u8>) -> Option<crypto::Keys> {
        if self.side.is_client() && !self.wrote_transport_params {
            write_transport_parameters(&self.params, buf);
            self.wrote_transport_params = true;
        }

        trace!(side = ?self.side, "write_handshake");

        if let Some(keys) = self.initial_keys.take() {
            return Some(keys);
        }
        let keys = self.handshake_keys.take()?;
        if self.side.is_server() && !self.wrote_transport_params {
            write_transport_parameters(&self.params, buf);
            self.wrote_transport_params = true;
        }
        Some(keys)
    }

    fn next_1rtt_keys(&mut self) -> Option<crypto::KeyPair<Box<dyn crypto::PacketKey>>> {
        trace!(side = ?self.side, "next_1rtt_keys");
        Some(crypto_packet_keypair(self.side))
    }

    fn is_valid_retry(&self, orig_dst_cid: &ConnectionId, _header: &[u8], _payload: &[u8]) -> bool {
        trace!(side = ?self.side, "is_valid_retry orig_dst_cid: {orig_dst_cid}");
        true
    }

    fn export_keying_material(
        &self,
        _output: &mut [u8],
        _label: &[u8],
        _context: &[u8],
    ) -> Result<(), crypto::ExportKeyingMaterialError> {
        trace!(side = ?self.side, "export_keying_material");
        Err(crypto::ExportKeyingMaterialError)
    }
}

impl crypto::ClientConfig for PlaintextClientConfig {
    fn start_session(
        self: std::sync::Arc<Self>,
        _version: u32,
        _server_name: &str,
        params: &transport_parameters::TransportParameters,
    ) -> Result<Box<dyn crypto::Session>, quinn_proto::ConnectError> {
        Ok(Box::new(PlaintextSession::new(Side::Client, *params)))
    }
}

impl crypto::ServerConfig for PlaintextServerConfig {
    fn initial_keys(
        &self,
        version: u32,
        dst_cid: &ConnectionId,
    ) -> Result<crypto::Keys, crypto::UnsupportedVersion> {
        trace!("ServerConfig::initial_keys version: {version}, dst_cid: {dst_cid:?}, side: Server");
        Ok(crypto_keys(Side::Server))
    }

    fn retry_tag(&self, _version: u32, _orig_dst_cid: &ConnectionId, _packet: &[u8]) -> [u8; 16] {
        [0u8; 16]
    }

    fn start_session(
        self: Arc<Self>,
        _version: u32,
        params: &transport_parameters::TransportParameters,
    ) -> Box<dyn crypto::Session> {
        Box::new(PlaintextSession::new(Side::Server, *params))
    }
}

impl crypto::PacketKey for PlaintextPacketKey {
    fn encrypt(&self, packet: u64, buf: &mut [u8], header_len: usize) {
        trace!(side = ?self.side, packet, header_len, "checksum packet");
        let (header, payload_tag) = buf.split_at_mut(header_len);
        let (payload, tag) = payload_tag.split_at_mut(payload_tag.len() - self.tag_len());
        tag.copy_from_slice(&packet_checksum(header, payload).to_be_bytes());
    }

    fn decrypt(
        &self,
        packet: u64,
        header: &[u8],
        payload: &mut BytesMut,
    ) -> Result<(), CryptoError> {
        trace!(side = ?self.side, packet, "verify packet checksum");
        let payload_len = payload
            .len()
            .checked_sub(self.tag_len())
            .ok_or(CryptoError)?;
        let (data, tag) = payload.split_at(payload_len);
        if packet_checksum(header, data).to_be_bytes() != tag {
            return Err(CryptoError);
        }
        payload.truncate(payload_len);
        Ok(())
    }

    fn tag_len(&self) -> usize {
        trace!(side = ?self.side, "PacketKey::tag_len");
        8
    }

    fn confidentiality_limit(&self) -> u64 {
        trace!(side = ?self.side, "PacketKey::confidentiality_limit");
        u64::MAX
    }

    fn integrity_limit(&self) -> u64 {
        trace!(side = ?self.side, "PacketKey::integrity_limit");
        1 << 36
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto::{PacketKey, Session};
    use quinn_proto::{transport_parameters::TransportParameters, TransportErrorCode};
    use std::time::Duration;

    fn session(side: Side) -> PlaintextSession {
        PlaintextSession::new(
            side,
            TransportParameters::read(Side::Client, &mut &[][..]).unwrap(),
        )
    }

    fn framed(params: &[u8]) -> Vec<u8> {
        let mut frame = (params.len() as u32).to_be_bytes().to_vec();
        frame.extend_from_slice(params);
        frame
    }

    #[test]
    fn malformed_parameters_return_transport_error() {
        // Truncated ID, missing length, truncated value, illegal max UDP payload,
        // duplicate max idle timeout, and a server-only parameter from a client.
        for params in [
            &[0x40][..],
            &[1],
            &[1, 1],
            &[3, 1, 0],
            &[1, 1, 0, 1, 1, 0],
            &[0, 0],
        ] {
            let mut receiver = session(Side::Server);
            let error = receiver.read_handshake(&framed(params)).unwrap_err();
            assert_eq!(error.code, TransportErrorCode::TRANSPORT_PARAMETER_ERROR);
            assert!(receiver.transport_parameters().unwrap().is_none());
            assert!(receiver.is_handshaking());
        }
    }

    #[test]
    fn handshake_supports_every_split_and_one_byte_chunks() {
        for side in [Side::Client, Side::Server] {
            let mut frame = Vec::new();
            write_transport_parameters(
                &TransportParameters::read(Side::Client, &mut &[][..]).unwrap(),
                &mut frame,
            );
            for split in 0..frame.len() {
                let mut receiver = session(side);
                assert!(!receiver.read_handshake(&frame[..split]).unwrap());
                assert!(receiver.handshake_data().is_none());
                assert!(receiver.read_handshake(&frame[split..]).unwrap());
                assert!(receiver.handshake_data().is_some());
                assert!(!receiver.read_handshake(&[]).unwrap());
                assert!(receiver.read_handshake(&[0]).is_err());
            }
            let mut receiver = session(side);
            for (index, byte) in frame.iter().enumerate() {
                assert_eq!(
                    receiver.read_handshake(&[*byte]).unwrap(),
                    index + 1 == frame.len()
                );
            }
        }
    }

    #[test]
    fn oversized_and_trailing_handshake_data_is_rejected() {
        for frame in [
            ((MAX_HANDSHAKE_LEN + 1) as u32).to_be_bytes().to_vec(),
            vec![0; MAX_HANDSHAKE_LEN + 5],
            vec![0, 0, 0, 0, 1],
        ] {
            let mut receiver = session(Side::Server);
            assert!(receiver.read_handshake(&frame).is_err());
            assert!(receiver.peer_params.is_none());
            assert!(receiver.handshake_buf.len() <= MAX_HANDSHAKE_LEN + 4);
        }
    }

    #[test]
    fn handshake_waits_for_both_key_transitions() {
        for side in [Side::Client, Side::Server] {
            let mut receiver = session(side);
            assert!(receiver.read_handshake(&framed(&[])).unwrap());
            assert!(receiver.is_handshaking());
            let mut outgoing = Vec::new();
            assert!(receiver.write_handshake(&mut outgoing).is_some());
            assert!(receiver.is_handshaking());
            assert!(receiver.write_handshake(&mut outgoing).is_some());
            assert!(!receiver.is_handshaking());
            let len = outgoing.len();
            assert!(receiver.write_handshake(&mut outgoing).is_none());
            assert_eq!(outgoing.len(), len);
        }
    }

    #[test]
    fn key_export_is_explicitly_unsupported() {
        let mut output = [0xa5; 32];
        assert!(session(Side::Client)
            .export_keying_material(&mut output, b"label", b"context")
            .is_err());
        assert_eq!(output, [0xa5; 32]);
    }

    #[test]
    fn checksum_uses_fixed_width_lengths() {
        let header = b"header";
        let payload = b"payload";
        let mut canonical = vec![6, 0, 0, 0, 0, 0, 0, 0];
        canonical.extend_from_slice(header);
        canonical.extend_from_slice(&[7, 0, 0, 0, 0, 0, 0, 0]);
        canonical.extend_from_slice(payload);
        assert_eq!(packet_checksum(header, payload), 0x2301_d2c1_d557_ee91);
        assert_eq!(packet_checksum(header, payload), seahash::hash(&canonical));
        // Hash::hash historically used 32-bit length prefixes on 32-bit targets.
        let mut legacy32 = Vec::new();
        legacy32.extend_from_slice(&6u32.to_le_bytes());
        legacy32.extend_from_slice(header);
        legacy32.extend_from_slice(&7u32.to_le_bytes());
        legacy32.extend_from_slice(payload);
        assert_ne!(packet_checksum(header, payload), seahash::hash(&legacy32));
    }

    #[test]
    fn packet_roundtrips_cover_empty_and_long_payloads() {
        for side in [Side::Client, Side::Server] {
            let key = PlaintextPacketKey::new(side);
            for len in [0, 1, 7, 8, 31, 32, 33, 1200, 65536] {
                let header = b"header";
                let data: Vec<_> = (0..len).map(|i| i as u8).collect();
                let mut packet = header.to_vec();
                packet.extend_from_slice(&data);
                packet.resize(packet.len() + key.tag_len(), 0);
                key.encrypt(1, &mut packet, header.len());
                let mut payload = BytesMut::from(&packet[header.len()..]);
                key.decrypt(1, header, &mut payload).unwrap();
                assert_eq!(payload.as_ref(), data);
            }
        }
    }

    #[test]
    fn corrupted_packets_and_short_tags_are_rejected_without_mutation() {
        let key = PlaintextPacketKey::new(Side::Server);
        for len in 0..key.tag_len() {
            let mut payload = BytesMut::from(&vec![0; len][..]);
            let original = payload.clone();
            assert!(key.decrypt(0, b"header", &mut payload).is_err());
            assert_eq!(payload, original);
        }
        let mut packet = b"headerpayload".to_vec();
        packet.resize(packet.len() + key.tag_len(), 0);
        key.encrypt(0, &mut packet, 6);
        for index in 0..packet.len() {
            let mut corrupted = packet.clone();
            corrupted[index] ^= 1;
            let mut payload = BytesMut::from(&corrupted[6..]);
            let original = payload.clone();
            assert!(key.decrypt(0, &corrupted[..6], &mut payload).is_err());
            assert_eq!(payload, original);
        }
    }

    #[tokio::test]
    async fn endpoints_transfer_large_bidirectional_stream() {
        tokio::time::timeout(Duration::from_secs(10), async {
            let server =
                quinn::Endpoint::server(server_config(), "127.0.0.1:0".parse().unwrap()).unwrap();
            let addr = server.local_addr().unwrap();
            let test_data = vec![0xa5; 128 * 1024];
            let server_fut = async {
                let conn = server.accept().await.unwrap().await.unwrap();
                let (mut send, mut recv) = conn.accept_bi().await.unwrap();
                let received = recv.read_to_end(test_data.len()).await.unwrap();
                assert_eq!(received, test_data);
                send.write_all(&received).await.unwrap();
                send.finish().unwrap();
                send.stopped().await.unwrap();
                conn.closed().await;
            };
            let client_fut = async {
                let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
                client.set_default_client_config(client_config());
                let conn = client
                    .connect(addr, "plaintext.test")
                    .unwrap()
                    .await
                    .unwrap();
                let (mut send, mut recv) = conn.open_bi().await.unwrap();
                send.write_all(&test_data).await.unwrap();
                send.finish().unwrap();
                assert_eq!(recv.read_to_end(test_data.len()).await.unwrap(), test_data);
                conn.close(0u32.into(), b"done");
                client.wait_idle().await;
            };
            tokio::join!(server_fut, client_fut);
        })
        .await
        .expect("endpoint test timed out");
    }
}
