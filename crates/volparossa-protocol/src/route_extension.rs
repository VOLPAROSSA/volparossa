//! One-path additions to an immutable finalized route, never replacement route authority.

use prost::Message;

use crate::{
    ControlMessageType, ControlPayload, ExitReservation, FinalizedRelayPath, ProbeAddressFamily,
    ProtocolError, SignedEnvelope, Transport, decode_canonical,
};

/// Bound for a complete signed extension including its one nested probe transcript.
pub const MAX_ROUTE_EXTENSION_BYTES: usize = 64 * 1024;

/// Independently replay-bound phases; only Commit exposes the enlarged usable path set.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, PartialEq, Eq, prost::Enumeration)]
#[repr(i32)]
pub enum RouteExtensionPhase {
    Probe = 1,
    Authorize = 2,
    Commit = 3,
    Abort = 4,
}

/// Immutable parent and exactly one previously unused path. No Client address is present.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct RouteExtensionScope {
    #[prost(bytes = "vec", tag = "1")]
    pub extension_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub signed_exit_reservation: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub finalized_bundle_hash: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub path_id: u32,
    #[prost(bytes = "vec", tag = "5")]
    pub relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub probe_id: Vec<u8>,
    #[prost(enumeration = "ProbeAddressFamily", tag = "8")]
    pub address_family: i32,
}

/// Fresh session-signed operation; Authorize carries one real probe and Commit one Relay grant.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct RouteExtensionRequest {
    #[prost(message, optional, tag = "1")]
    pub scope: Option<RouteExtensionScope>,
    #[prost(enumeration = "RouteExtensionPhase", tag = "2")]
    pub phase: i32,
    #[prost(message, optional, tag = "3")]
    pub path: Option<FinalizedRelayPath>,
    #[prost(bytes = "vec", tag = "4")]
    pub signed_confirmation: Vec<u8>,
}

/// Exit-signed result. Only committed results authorize the effective expanded path set.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct RouteExtension {
    #[prost(message, optional, tag = "1")]
    pub scope: Option<RouteExtensionScope>,
    #[prost(enumeration = "RouteExtensionPhase", tag = "2")]
    pub phase: i32,
    #[prost(bytes = "vec", tag = "3")]
    pub signed_probe_permit: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub signed_relay_authorization: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub signed_confirmation_receipt: Vec<u8>,
    #[prost(uint32, repeated, tag = "6")]
    pub selected_path_ids: Vec<u32>,
    #[prost(uint64, tag = "7")]
    pub hard_expires_at_ms: u64,
}

/// Exact new Relay's short-lived acknowledgement of its helper commit and capacity activation.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct RouteExtensionRelayCommit {
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub extension_id: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub path_id: u32,
    #[prost(bytes = "vec", tag = "5")]
    pub relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub authorization_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub confirmation_sha256: Vec<u8>,
    #[prost(uint64, tag = "8")]
    pub hard_expires_at_ms: u64,
}

impl ControlPayload for RouteExtensionRelayCommit {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::RouteExtensionRelayCommit;

    fn validate(&self) -> Result<(), ProtocolError> {
        nonzero(&self.route_context_id, 16)?;
        nonzero(&self.reservation_id, 16)?;
        nonzero(&self.extension_id, 16)?;
        nonzero(&self.relay_node_id, 32)?;
        nonzero(&self.authorization_sha256, 32)?;
        nonzero(&self.confirmation_sha256, 32)?;
        if !(1..=8).contains(&self.path_id) || self.hard_expires_at_ms == 0 {
            return Err(ProtocolError::InvalidField("extension relay commit"));
        }
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        if envelope.sender_id != self.relay_node_id
            || envelope.expires_at_ms > self.hard_expires_at_ms
            || !envelope
                .expires_at_ms
                .checked_sub(envelope.timestamp_ms)
                .is_some_and(|n| (1..=30_000).contains(&n))
        {
            return Err(ProtocolError::InvalidField(
                "extension relay commit authority",
            ));
        }
        Ok(())
    }
}

fn nonzero(bytes: &[u8], length: usize) -> Result<(), ProtocolError> {
    if bytes.len() != length || bytes.iter().all(|byte| *byte == 0) {
        return Err(ProtocolError::InvalidField("extension identifier"));
    }
    Ok(())
}

impl RouteExtensionScope {
    /// Decode the canonical original parent. Signature/time verification remains the caller's duty.
    ///
    /// # Errors
    /// Rejects malformed, oversized, non-MPTCP, cross-type or endpoint-bearing scope material.
    pub fn parent(&self) -> Result<ExitReservation, ProtocolError> {
        nonzero(&self.extension_id, 16)?;
        nonzero(&self.finalized_bundle_hash, 32)?;
        nonzero(&self.relay_node_id, 32)?;
        nonzero(&self.probe_id, 16)?;
        if !(1..=8).contains(&self.path_id)
            || self.relay_peer_id.is_empty()
            || self.relay_peer_id.len() > 64
            || !matches!(
                ProbeAddressFamily::try_from(self.address_family),
                Ok(ProbeAddressFamily::Ipv4 | ProbeAddressFamily::Ipv6)
            )
        {
            return Err(ProtocolError::InvalidField("extension path"));
        }
        let envelope: SignedEnvelope = decode_canonical(&self.signed_exit_reservation, 8192)?;
        if envelope.message_type != ControlMessageType::ExitReservation as i32
            || envelope.protocol_version != crate::PROTOCOL_VERSION
        {
            return Err(ProtocolError::InvalidField("extension parent type"));
        }
        let parent: ExitReservation = decode_canonical(&envelope.payload, 8192)?;
        parent.validate()?;
        parent.validate_envelope(&envelope)?;
        if parent.allowed_transports.as_slice() != [Transport::TcpMptcp as i32]
            || self.relay_node_id == parent.exit_node_id
            || self.relay_node_id == parent.control_relay_node_id
            || self.relay_peer_id == parent.exit_peer_id
            || self.relay_peer_id == parent.control_relay_peer_id
        {
            return Err(ProtocolError::InvalidField(
                "extension original route scope",
            ));
        }
        Ok(parent)
    }
}

impl ControlPayload for RouteExtensionRequest {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::RouteExtensionRequest;

    fn validate(&self) -> Result<(), ProtocolError> {
        let scope = self
            .scope
            .as_ref()
            .ok_or(ProtocolError::InvalidField("extension scope"))?;
        scope.parent()?;
        if self.encoded_len() > MAX_ROUTE_EXTENSION_BYTES {
            return Err(ProtocolError::InvalidField("extension size"));
        }
        match RouteExtensionPhase::try_from(self.phase) {
            Ok(RouteExtensionPhase::Authorize) => {
                let path = self
                    .path
                    .as_ref()
                    .ok_or(ProtocolError::InvalidField("extension measured path"))?;
                if !self.signed_confirmation.is_empty()
                    || path.path_id != scope.path_id
                    || path.relay_node_id != scope.relay_node_id
                    || path.relay_peer_id != scope.relay_peer_id
                    || path.relay_probe_permit.is_empty()
                    || path.relay_probe_result.is_empty()
                {
                    return Err(ProtocolError::InvalidField("extension measured path scope"));
                }
                nonzero(&path.client_wireguard_public_key, 32)?;
            }
            Ok(RouteExtensionPhase::Commit)
                if self.path.is_none() && !self.signed_confirmation.is_empty() => {}
            Ok(RouteExtensionPhase::Probe | RouteExtensionPhase::Abort)
                if self.path.is_none() && self.signed_confirmation.is_empty() => {}
            _ => return Err(ProtocolError::InvalidField("extension request phase")),
        }
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        let parent = self
            .scope
            .as_ref()
            .ok_or(ProtocolError::InvalidField("extension scope"))?
            .parent()?;
        if envelope.sender_id != parent.client_session_id
            || envelope.sender_public_key != parent.client_session_public_key
            || envelope.timestamp_ms < parent.created_at_ms
            || envelope.expires_at_ms > parent.expires_at_ms
            || !envelope
                .expires_at_ms
                .checked_sub(envelope.timestamp_ms)
                .is_some_and(|n| (1..=30_000).contains(&n))
        {
            return Err(ProtocolError::InvalidField("extension request authority"));
        }
        Ok(())
    }
}

impl ControlPayload for RouteExtension {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::RouteExtension;

    fn validate(&self) -> Result<(), ProtocolError> {
        let scope = self
            .scope
            .as_ref()
            .ok_or(ProtocolError::InvalidField("extension scope"))?;
        let parent = scope.parent()?;
        if self.encoded_len() > MAX_ROUTE_EXTENSION_BYTES
            || self.hard_expires_at_ms != parent.expires_at_ms
            || self.selected_path_ids.is_empty()
            || self.selected_path_ids.len() > 8
            || self
                .selected_path_ids
                .iter()
                .any(|path| !(1..=8).contains(path))
            || self
                .selected_path_ids
                .windows(2)
                .any(|pair| pair[0] >= pair[1])
        {
            return Err(ProtocolError::InvalidField("extension effective scope"));
        }
        let valid = match RouteExtensionPhase::try_from(self.phase) {
            Ok(RouteExtensionPhase::Probe) => {
                !self.signed_probe_permit.is_empty()
                    && self.signed_relay_authorization.is_empty()
                    && self.signed_confirmation_receipt.is_empty()
            }
            Ok(RouteExtensionPhase::Authorize) => {
                !self.signed_probe_permit.is_empty()
                    && !self.signed_relay_authorization.is_empty()
                    && self.signed_confirmation_receipt.is_empty()
            }
            Ok(RouteExtensionPhase::Commit) => {
                !self.signed_probe_permit.is_empty()
                    && !self.signed_relay_authorization.is_empty()
                    && !self.signed_confirmation_receipt.is_empty()
                    && self.selected_path_ids.contains(&scope.path_id)
            }
            Ok(RouteExtensionPhase::Abort) => {
                self.signed_probe_permit.is_empty()
                    && self.signed_relay_authorization.is_empty()
                    && self.signed_confirmation_receipt.is_empty()
                    && !self.selected_path_ids.contains(&scope.path_id)
            }
            Err(_) => false,
        };
        if !valid {
            return Err(ProtocolError::InvalidField("extension response phase"));
        }
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        let parent = self
            .scope
            .as_ref()
            .ok_or(ProtocolError::InvalidField("extension scope"))?
            .parent()?;
        if envelope.sender_id != parent.exit_node_id
            || envelope.expires_at_ms > parent.expires_at_ms
            || envelope.timestamp_ms < parent.created_at_ms
        {
            return Err(ProtocolError::InvalidField("extension response authority"));
        }
        Ok(())
    }
}
