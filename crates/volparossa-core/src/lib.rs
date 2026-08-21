//! Shared domain types and validation rules for VOLPAROSSA.
//!
//! This crate intentionally contains no networking or persistence.  It keeps
//! the data exchanged by selection, reservation and peer storage small and
//! gives untrusted advertisement data one validation boundary.

mod advertisement;
mod capacity;
mod id;
mod network;
mod time;

pub use advertisement::{
    AdvertisementError, MAX_ADVERTISEMENT_ENDPOINTS, MAX_ADVERTISEMENT_TTL_SECONDS,
    NetworkMetadata, NodeAdvertisement, NodeCapabilities, NodeQuality, NodeRoles,
    ObservedNetworkOrigin,
};
pub use capacity::{Bandwidth, CapacityError, CapacitySnapshot, ConservativeCapacity};
pub use id::{
    ClientEphemeralId, FlowId, IdentifierError, LocalProfileId, NodeId, OperatorId, OriginKey,
    PathId, PeerId, ReservationId, RouteContextId,
};
pub use network::{ObservedNetworkPrefix, is_public_routable_ip};
pub use time::{TimeError, UnixTime};

use serde::{Deserialize, Serialize};

/// The incompatible control and advertisement protocol version implemented by this release.
pub const PROTOCOL_VERSION: u16 = 3;

/// A transport advertised by a node or requested for a route.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Transport {
    /// Transparent TCP proxying over TLS 1.3 over kernel MPTCP.
    TcpMptcp,
    /// General UDP over a protected single-path QUIC association.
    UdpSinglePath,
    /// Browser QUIC inside MASQUE CONNECT-IP over genuine Multipath QUIC.
    MultipathQuic,
}

/// An address family required by a route.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum IpFamily {
    /// Internet Protocol version 4.
    Ipv4,
    /// Internet Protocol version 6.
    Ipv6,
}

/// A role for which a node is being considered.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ServiceRole {
    /// A voluntary forwarding relay with no Internet egress.
    Relay,
    /// An explicitly enabled, policy-enforcing Internet exit.
    Exit,
}

/// The hash of the exact whitelist manifest a route must use.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(transparent)]
pub struct PolicyHash([u8; 32]);

impl PolicyHash {
    /// Builds a policy hash from canonical manifest digest bytes.
    #[must_use]
    pub const fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns the canonical manifest digest bytes.
    #[must_use]
    pub const fn as_bytes(&self) -> &[u8; 32] {
        &self.0
    }
}
