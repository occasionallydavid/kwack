#![cfg_attr(feature = "http", doc = include_str!("../README.md"))]
//! QUIC streams authenticated and encrypted by a userspace WireGuard transport.
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

#[cfg(feature = "client")]
mod client;
mod keys;
mod packet;
mod plaintext;
#[cfg(feature = "server")]
mod server;
mod socket;
mod transport;

#[cfg(feature = "client")]
pub use client::{HttpClient, RequestBuilder, Response};
pub use keys::{PrivateKey, PublicKey};
pub use transport::{
    Client, ClientBuilder, Connection, PeerIdentity, RejectedDatagram, RejectionReason, Server,
    ServerBuilder, ServerHandle, Stream,
};

/// Errors are propagated through all public async operations.
pub type Error = Box<dyn std::error::Error + Send + Sync>;
