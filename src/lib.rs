#![doc = include_str!("../README.md")]

use std::collections::HashSet;
use std::io;

use base64::Engine;
use base64::engine::general_purpose::STANDARD;
use rcgen::{CertificateParams, DistinguishedName, DnType, KeyPair, PKCS_ED25519};
use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName, UnixTime};
use rustls::server::danger::{ClientCertVerified, ClientCertVerifier};
use rustls::{CertificateError, DigitallySignedStruct, DistinguishedName as Name, SignatureScheme};
use webpki::ring::ED25519;
use webpki::{EndEntityCert, KeyUsage, anchor_from_trusted_cert};

/// An invalid key, base64 value, or certificate generation error.
pub type Error = Box<dyn std::error::Error + Send + Sync>;

const PKCS8_SEED_PREFIX: &[u8] =
    b"\x30\x2e\x02\x01\x00\x30\x05\x06\x03\x2b\x65\x70\x04\x22\x04\x20";

const ED25519_SPKI_PREFIX: &[u8] = b"\x30\x2a\x30\x05\x06\x03\x2b\x65\x70\x03\x21\x00";

/// A deterministic self-signed identity for TLS client or server authentication.
pub struct Identity {
    certificate: CertificateDer<'static>,
    private_key: PrivatePkcs8KeyDer<'static>,
    public_key: [u8; 32],
}

impl Identity {
    /// Accepts standard base64 containing a 32-byte Ed25519 seed or PKCS #8 DER.
    pub fn from_private_key(private_key: &str) -> Result<Self, Error> {
        let decoded = STANDARD.decode(private_key.trim())?;
        let key = if decoded.len() == 32 {
            [PKCS8_SEED_PREFIX, &decoded].concat()
        } else {
            decoded
        };
        let private_key = PrivatePkcs8KeyDer::from(key);
        let signer = KeyPair::from_pkcs8_der_and_sign_algo(&private_key, &PKCS_ED25519)?;
        let public_key = signer.public_key_raw().try_into()?;
        let mut params = CertificateParams::new(vec!["a".into()])?;
        params.distinguished_name = DistinguishedName::new();
        params.distinguished_name.push(DnType::CommonName, "a");
        params.serial_number = Some(1u64.into());
        params.not_before = rcgen::date_time_ymd(2000, 1, 1);
        params.not_after = rcgen::date_time_ymd(2049, 1, 1);
        let certificate = params.self_signed(&signer)?.der().clone();
        Ok(Self {
            certificate,
            private_key,
            public_key,
        })
    }

    /// Returns the standard base64 encoding of the 32-byte Ed25519 public key.
    pub fn public_key_base64(&self) -> String {
        STANDARD.encode(self.public_key)
    }

    /// Returns the standard base64 encoding of the X.509 certificate DER.
    pub fn certificate_base64(&self) -> String {
        STANDARD.encode(&self.certificate)
    }

    /// Supplies the chain and key to rustls's certificate configuration methods.
    pub fn into_rustls(self) -> (Vec<CertificateDer<'static>>, PrivateKeyDer<'static>) {
        (vec![self.certificate], self.private_key.into())
    }
}

/// Authenticates self-signed Ed25519 peers by exact public-key pin.
///
/// On the server this requires a client certificate. On the client it also
/// checks the configured server name against the certificate's SAN.
#[derive(Debug)]
pub struct Verifier {
    keys: HashSet<[u8; 32]>,
}

impl Verifier {
    /// Each entry is standard base64 containing a raw 32-byte Ed25519 public key
    /// or Ed25519 SubjectPublicKeyInfo DER. An empty list denies all peers.
    pub fn new(keys: impl IntoIterator<Item = impl AsRef<str>>) -> Result<Self, Error> {
        let mut pins = HashSet::new();
        for key in keys {
            let key = STANDARD.decode(key.as_ref().trim())?;
            let raw = if key.len() == 32 {
                key.as_slice()
            } else {
                key.strip_prefix(ED25519_SPKI_PREFIX).unwrap_or(&[])
            };
            let pin = raw.try_into().map_err(|_| {
                io::Error::new(
                    io::ErrorKind::InvalidInput,
                    "expected an Ed25519 public key",
                )
            })?;
            pins.insert(pin);
        }
        Ok(Self { keys: pins })
    }

    fn verify_leaf<'a>(
        &self,
        certificate: &'a CertificateDer<'a>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
        usage: KeyUsage,
    ) -> Result<EndEntityCert<'a>, rustls::Error> {
        if !intermediates.is_empty() {
            return Err(CertificateError::UnknownIssuer.into());
        }
        let leaf = EndEntityCert::try_from(certificate).map_err(invalid_cert)?;
        let spki = leaf.subject_public_key_info();
        let key: &[u8; 32] = spki
            .as_ref()
            .strip_prefix(ED25519_SPKI_PREFIX)
            .and_then(|raw| raw.try_into().ok())
            .ok_or(CertificateError::BadEncoding)?;
        if !self.keys.contains(key) {
            return Err(CertificateError::UnknownIssuer.into());
        }

        // After matching the pin, trust only this leaf's subject and key.
        // WebPKI validates the one-certificate path, including the signature.
        let anchor = anchor_from_trusted_cert(certificate).map_err(invalid_cert)?;
        leaf.verify_for_usage(&[ED25519], &[anchor], &[], now, usage, None, None)
            .map_err(invalid_cert)?;
        Ok(leaf)
    }

    fn verify_handshake_signature(
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        if signature.scheme != SignatureScheme::ED25519 {
            return Err(CertificateError::BadSignature.into());
        }
        EndEntityCert::try_from(certificate)
            .and_then(|leaf| leaf.verify_signature(ED25519, message, signature.signature()))
            .map_err(invalid_cert)?;
        Ok(HandshakeSignatureValid::assertion())
    }
}

impl ClientCertVerifier for Verifier {
    fn root_hint_subjects(&self) -> &[Name] {
        &[]
    }

    fn verify_client_cert(
        &self,
        certificate: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        now: UnixTime,
    ) -> Result<ClientCertVerified, rustls::Error> {
        self.verify_leaf(certificate, intermediates, now, KeyUsage::client_auth())?;
        Ok(ClientCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Self::verify_handshake_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Self::verify_handshake_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

impl ServerCertVerifier for Verifier {
    fn verify_server_cert(
        &self,
        certificate: &CertificateDer<'_>,
        intermediates: &[CertificateDer<'_>],
        name: &ServerName<'_>,
        _ocsp_response: &[u8],
        now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        self.verify_leaf(certificate, intermediates, now, KeyUsage::server_auth())?
            .verify_is_valid_for_subject_name(name)
            .map_err(invalid_cert)?;
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Self::verify_handshake_signature(message, certificate, signature)
    }

    fn verify_tls13_signature(
        &self,
        message: &[u8],
        certificate: &CertificateDer<'_>,
        signature: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Self::verify_handshake_signature(message, certificate, signature)
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![SignatureScheme::ED25519]
    }
}

fn invalid_cert(error: webpki::Error) -> rustls::Error {
    use webpki::Error as W;
    let kind = match error {
        W::BadDer | W::BadDerTime | W::TrailingData(_) => CertificateError::BadEncoding,
        W::UnknownIssuer => CertificateError::UnknownIssuer,
        W::InvalidSignatureForPublicKey => CertificateError::BadSignature,
        W::CertExpired { .. } => CertificateError::Expired,
        W::CertNotValidYet { .. } => CertificateError::NotValidYet,
        W::CertNotValidForName(_) => CertificateError::NotValidForName,
        _ => CertificateError::Other(rustls::OtherError(std::sync::Arc::new(error))),
    };
    kind.into()
}
