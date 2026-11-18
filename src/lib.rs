#![doc = include_str!("lib.md")]
#![cfg_attr(not(test), deny(clippy::unwrap_used, clippy::expect_used))]

#[cfg(feature = "client")]
mod client;

mod crypto;

mod keys;

mod rekey;

#[cfg(feature = "server")]
mod server;

mod stream;

mod transport;
pub use keys::{PrivateKey, PublicKey};
pub use stream::KcpStream;
pub use transport::{
    Client, ClientBuilder, Connection, PeerIdentity, RejectedDatagram, RejectionReason, Server,
    ServerBuilder, ServerHandle,
};

/// Errors are propagated through all public async operations.
pub type Error = Box<dyn std::error::Error + Send + Sync>;
