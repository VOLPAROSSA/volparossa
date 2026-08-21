//! Fail-closed primitives for VOLPAROSSA's transparent TCP proxy.
//!
//! The client connector accepts only an already-connected, helper-acquired
//! route-namespace MPTCP descriptor and then adds a TLS 1.3-only layer. Before
//! it can be used, the caller must also supply an exit reservation and at least
//! two distinct, independently signed relay-path reservations. Socket creation
//! and host routing remain the privileged helper's responsibility.
//!
//! Destination names are intentionally absent from error and `Debug` output.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod authorization;
mod framing;
mod route;
mod streaming;
mod tls;

pub use authorization::{AuthorizedTcpFlow, TcpAuthorizationScope};
pub use framing::{read_authorized_open_tcp, write_open_tcp};
pub use route::{MINIMUM_MPTCP_PATHS, VerifiedMptcpRoute};
pub use streaming::{StreamTransferLimits, StreamTransferStats, proxy_bidirectional};
pub use tls::{Tls13MptcpClient, Tls13MptcpServer, Tls13MptcpStream, VOLPAROSSA_TCP_ALPN};

use thiserror::Error;

/// Errors returned by TCP authorization, framing, TLS, and streaming.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum TcpProxyError {
    /// A signed control message was malformed, expired, replayed, or invalid.
    #[error("TCP control authorization failed: {0}")]
    Protocol(#[from] volparossa_protocol::ProtocolError),

    /// The active threshold-signed whitelist denied the exact tuple.
    #[error("TCP whitelist authorization failed: {0}")]
    Policy(#[from] volparossa_policy::PolicyError),

    /// A local or network I/O operation failed.
    #[error("TCP proxy I/O failed: {0}")]
    Io(#[from] std::io::Error),

    /// A TLS 1.3 configuration could not be built.
    #[error("TLS 1.3 configuration failed: {0}")]
    TlsConfiguration(#[from] rustls::Error),

    /// A reservation, route, or flow did not match its fixed session scope.
    #[error("TCP session binding is invalid: {0}")]
    InvalidBinding(&'static str),

    /// The verified route or flow authorization has expired.
    #[error("TCP session authorization has expired")]
    Expired,

    /// No stream activity completed within the configured idle interval.
    #[error("TCP proxy stream reached its idle timeout")]
    IdleTimeout,

    /// One direction exceeded its fixed byte allowance.
    #[error("TCP proxy stream exceeded its configured byte limit")]
    ByteLimit,
}
