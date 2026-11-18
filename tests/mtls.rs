use std::sync::Arc;
use std::time::Duration;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use kwack::{Identity, Verifier};
use quinn::crypto::rustls::{QuicClientConfig, QuicServerConfig};
use rustls::pki_types::{CertificateDer, UnixTime};
use rustls::server::danger::ClientCertVerifier;

fn identity(byte: u8) -> Identity {
    Identity::from_private_key(&STANDARD.encode([byte; 32])).unwrap()
}

fn raw_key(identity: &Identity) -> [u8; 32] {
    STANDARD
        .decode(identity.public_key_base64())
        .unwrap()
        .try_into()
        .unwrap()
}

#[test]
fn deterministic_for_seed_and_rejects_der_input() {
    let from_seed = identity(3);
    let certificate = from_seed.certificate_base64();
    assert_eq!(STANDARD.decode(&certificate).unwrap().len(), 217);
    let (_, pkcs8) = from_seed.into_rustls();
    let generated = rcgen::KeyPair::generate_for(&rcgen::PKCS_ED25519).unwrap();
    assert_eq!(certificate, identity(3).certificate_base64());
    assert_ne!(certificate, identity(2).certificate_base64());
    assert!(Identity::from_private_key(&STANDARD.encode(pkcs8.secret_der())).is_err());
    assert!(Identity::from_private_key(&STANDARD.encode(generated.serialized_der())).is_err());
    assert!(Identity::from_private_key(&STANDARD.encode([3; 31])).is_err());
    assert!(Identity::from_private_key(&STANDARD.encode([3; 33])).is_err());
    assert!(Identity::from_private_key("invalid").is_err());
}

#[test]
fn certificate_checks_reject_tampering_expiry_and_trailing_data() {
    let identity = identity(1);
    let peer = raw_key(&identity);
    let verifier = Verifier::new(Some(Box::new(move |presented| presented.raw() == peer)));
    let (chain, _) = identity.into_rustls();
    let cert = &chain[0];
    assert!(
        verifier
            .verify_client_cert(cert, &[], UnixTime::now())
            .is_ok()
    );
    assert!(
        verifier
            .verify_client_cert(
                cert,
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(0))
            )
            .is_err()
    );
    assert!(
        verifier
            .verify_client_cert(
                cert,
                &[],
                UnixTime::since_unix_epoch(Duration::from_secs(4_200_000_000))
            )
            .is_err()
    );
    assert!(
        verifier
            .verify_client_cert(cert, &chain, UnixTime::now())
            .is_err()
    );
    let mut tampered = cert.as_ref().to_vec();
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        verifier
            .verify_client_cert(&CertificateDer::from(tampered), &[], UnixTime::now())
            .is_err()
    );
    let mut trailing = cert.as_ref().to_vec();
    trailing.push(0);
    assert!(
        verifier
            .verify_client_cert(&CertificateDer::from(trailing), &[], UnixTime::now())
            .is_err()
    );
}

#[tokio::test]
async fn quinn_mutual_tls_enforces_pins_in_both_directions() {
    for (server_pin, client_pin, client_identity, name, expected) in [
        (1, 2, Some(2), "a", true),
        (1, 2, Some(3), "a", false),
        (3, 2, Some(2), "a", false),
        (1, 2, None, "a", false),
        (1, 2, Some(2), "b", false),
    ] {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let client_pin = raw_key(&identity(client_pin));
        let server_pin = raw_key(&identity(server_pin));
        let (server_chain, server_key) = identity(1).into_rustls();
        let server_tls = rustls::ServerConfig::builder_with_provider(provider.clone())
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .with_client_cert_verifier(Arc::new(Verifier::new(Some(Box::new(move |peer| {
                peer.raw() == client_pin
            })))))
            .with_single_cert(server_chain, server_key)
            .unwrap();
        let client_builder = rustls::ClientConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])
            .unwrap()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(Verifier::new(Some(Box::new(
                move |peer| peer.raw() == server_pin,
            )))));
        let client_tls = if let Some(seed) = client_identity {
            let (chain, key) = identity(seed).into_rustls();
            client_builder.with_client_auth_cert(chain, key).unwrap()
        } else {
            client_builder.with_no_client_auth()
        };
        let server_config = quinn::ServerConfig::with_crypto(Arc::new(
            QuicServerConfig::try_from(server_tls).unwrap(),
        ));
        let server =
            quinn::Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
        let mut client = quinn::Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client.set_default_client_config(quinn::ClientConfig::new(Arc::new(
            QuicClientConfig::try_from(client_tls).unwrap(),
        )));
        let connecting = client.connect(server.local_addr().unwrap(), name).unwrap();
        let (outgoing, incoming) = tokio::time::timeout(Duration::from_secs(5), async {
            tokio::join!(connecting, async { server.accept().await.unwrap().await })
        })
        .await
        .unwrap();
        assert_eq!(incoming.is_ok(), expected, "{incoming:?}");
        if expected {
            let outgoing = outgoing.unwrap();
            let incoming = incoming.unwrap();
            let mut send = outgoing.open_uni().await.unwrap();
            send.write_all(b"mutual TLS").await.unwrap();
            send.finish().unwrap();
            assert_eq!(
                incoming
                    .accept_uni()
                    .await
                    .unwrap()
                    .read_to_end(100)
                    .await
                    .unwrap(),
                b"mutual TLS"
            );
        }
    }
}
