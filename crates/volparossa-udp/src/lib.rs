//! Real, datagram-preserving UDP association components for VOLPAROSSA.
//!
//! A usable association requires one exit reservation, one doubly signed relay
//! reservation, and one client-signed UDP flow authorization. Its destination
//! tuple, relay identity, route context, and idle timeout are immutable. QUIC
//! DATAGRAM support is mandatory; no stream-based reliable fallback exists.
//!
//! This crate owns the authorization and data-pump layer. A connected QUIC
//! transport is supplied by the native MASQUE boundary or another audited
//! single-path QUIC endpoint whose packets are already forced through the
//! selected `WireGuard` relay path.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod association;
mod authorization;
mod bridge;
mod endpoint;
mod framing;
mod path;

pub use association::{MAX_UDP_PAYLOAD_BYTES, QuicUdpAssociation, UdpAssociationState};
pub use authorization::{AuthorizedUdpFlow, PinnedUdpFlow, UdpAuthorizationScope};
pub use bridge::{DatagramLimits, ExitUdpBridge, UdpBridgeStats};
pub use endpoint::endpoint_from_bound_owned_fd;
pub use framing::{read_authorized_udp_flow, write_udp_authorization};
pub use path::VerifiedSingleRelayPath;

use thiserror::Error;

/// Fail-closed errors returned by UDP route, policy, QUIC, and bridge code.
#[derive(Debug, Error)]
#[non_exhaustive]
pub enum UdpError {
    /// A signed control message was malformed, expired, replayed, or invalid.
    #[error("UDP control authorization failed: {0}")]
    Protocol(#[from] volparossa_protocol::ProtocolError),

    /// The threshold-signed whitelist denied the exact tuple.
    #[error("UDP whitelist authorization failed: {0}")]
    Policy(#[from] volparossa_policy::PolicyError),

    /// A local socket or control-stream I/O operation failed.
    #[error("UDP association I/O failed: {0}")]
    Io(#[from] std::io::Error),

    /// The connected QUIC session terminated.
    #[error("UDP QUIC association terminated: {0}")]
    QuicConnection(#[from] quinn::ConnectionError),

    /// QUIC rejected an outbound datagram.
    #[error("UDP QUIC datagram send failed: {0}")]
    QuicDatagram(#[from] quinn::SendDatagramError),

    /// QUIC DATAGRAM was not negotiated, so no permitted UDP fallback exists.
    #[error("QUIC DATAGRAM support was not negotiated")]
    DatagramUnsupported,

    /// A reservation, route, flow, or datagram violated a fixed binding.
    #[error("UDP association binding is invalid: {0}")]
    InvalidBinding(&'static str),

    /// A signed route or flow has reached its exclusive expiry.
    #[error("UDP association authorization has expired")]
    Expired,

    /// The immutable association reached its configured inactivity deadline.
    #[error("UDP association reached its idle timeout")]
    IdleTimeout,

    /// A payload or session counter exceeded its configured bound.
    #[error("UDP association resource limit exceeded")]
    ResourceLimit,

    /// No acceptable Internet address was returned for an authorized name.
    #[error("authorized UDP name did not resolve to an acceptable address")]
    ResolutionFailed,

    /// The API was called outside a Tokio runtime needed for the idle guard.
    #[error("UDP association requires an active Tokio runtime")]
    RuntimeUnavailable,
}
