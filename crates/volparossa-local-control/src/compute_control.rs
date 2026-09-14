//! Explicit broker attachment and same-socket protected compute handoff.

use prost::Message;

use crate::ControlProtocolError;

/// Local operator attachment; no remote peer chooses a path on this host.
#[derive(Clone, PartialEq, Message)]
pub struct ComputeAttachRequest {
    /// Existing protected same-UID broker socket.
    #[prost(string, tag = "1")]
    pub broker_socket: String,
    /// Explicit unprivileged provider listener address and port.
    #[prost(string, tag = "2")]
    pub bind_address: String,
    /// Policy-authorized hostname; no arbitrary destination fallback.
    #[prost(string, tag = "3")]
    pub advertised_hostname: String,
    /// Independently trusted publishers of public input datasets.
    #[prost(bytes = "vec", repeated, tag = "4")]
    pub trusted_dataset_publishers: Vec<Vec<u8>>,
}

/// Select a provider before upgrading this exact local connection for a bounded job RPC.
#[derive(Clone, PartialEq, Message)]
pub struct ComputeRemoteRequest {
    /// Independently selected Ed25519 provider key.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
}

/// Readiness for a single request, not a successful job or completed network exchange.
#[derive(Clone, PartialEq, Message)]
pub struct ComputeReady {
    /// Exact selected remote provider.
    #[prost(bytes = "vec", tag = "1")]
    pub provider_key: Vec<u8>,
    /// Node key the agent will use to authenticate this caller's request.
    #[prost(bytes = "vec", tag = "2")]
    pub requester_key: Vec<u8>,
}

impl ComputeAttachRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        if !self.broker_socket.starts_with('/')
            || self.broker_socket.len() > 107
            || self.broker_socket.contains('\0')
            || self.bind_address.parse::<std::net::SocketAddr>().is_err()
            || self.advertised_hostname.is_empty()
            || self.advertised_hostname.len() > 253
            || !(1..=64).contains(&self.trusted_dataset_publishers.len())
            || self
                .trusted_dataset_publishers
                .iter()
                .any(|key| key.len() != 32)
        {
            return Err(ControlProtocolError::Invalid("compute attachment scope"));
        }
        let unique: std::collections::BTreeSet<_> =
            self.trusted_dataset_publishers.iter().collect();
        if unique.len() != self.trusted_dataset_publishers.len() {
            return Err(ControlProtocolError::Invalid("duplicate compute publisher"));
        }
        Ok(())
    }
}

impl ComputeRemoteRequest {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.provider_key.len() != 32 {
            return Err(ControlProtocolError::Invalid("compute provider"));
        }
        Ok(())
    }
}

impl ComputeReady {
    pub(crate) fn validate(&self) -> Result<(), ControlProtocolError> {
        if self.provider_key.len() != 32 || self.requester_key.len() != 32 {
            return Err(ControlProtocolError::Invalid("compute readiness"));
        }
        Ok(())
    }
}
