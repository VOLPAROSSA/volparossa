//! Short-lived, endpoint-free path state for an already established MPTCP route.

use prost::Message;
use sha2::{Digest, Sha256};

use crate::{
    ControlMessageType, ControlPayload, ExitReservation, ProtocolError, SignedEnvelope, Transport,
    decode_canonical,
};

/// Fresh session-signed query against the exact retained original reservation.
#[derive(Clone, PartialEq, Message)]
pub struct MptcpPathsRequest {
    /// Canonical original Exit grant, not new route authority.
    #[prost(bytes = "vec", tag = "1")]
    pub signed_exit_reservation: Vec<u8>,
}

impl MptcpPathsRequest {
    /// Decode the bounded original scope. The receiver must match its verified retained grant.
    ///
    /// # Errors
    /// Rejects malformed, wrong-type or non-MPTCP parent data.
    pub fn parent(&self) -> Result<ExitReservation, ProtocolError> {
        let envelope: SignedEnvelope = decode_canonical(&self.signed_exit_reservation, 8192)?;
        if envelope.message_type != ControlMessageType::ExitReservation as i32
            || envelope.protocol_version != crate::PROTOCOL_VERSION
        {
            return Err(ProtocolError::InvalidField("MPTCP path-state parent type"));
        }
        let parent: ExitReservation = decode_canonical(&envelope.payload, 8192)?;
        parent.validate()?;
        parent.validate_envelope(&envelope)?;
        if parent.allowed_transports.as_slice() != [Transport::TcpMptcp as i32] {
            return Err(ProtocolError::InvalidField("MPTCP path-state transport"));
        }
        Ok(parent)
    }
}

impl ControlPayload for MptcpPathsRequest {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::MptcpPathsRequest;

    fn validate(&self) -> Result<(), ProtocolError> {
        self.parent().map(|_| ())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        let parent = self.parent()?;
        lifetime(envelope, parent.expires_at_ms)?;
        if envelope.sender_id != parent.client_session_id
            || envelope.sender_public_key != parent.client_session_public_key
            || envelope.timestamp_ms < parent.created_at_ms
        {
            return Err(ProtocolError::InvalidField("MPTCP path-state session"));
        }
        Ok(())
    }
}

/// Exit-signed snapshot of its actual endpoint lifecycle, not evidence of subflow traffic.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct MptcpPathsState {
    #[prost(bytes = "vec", tag = "1")]
    pub request_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub exit_node_id: Vec<u8>,
    #[prost(uint64, tag = "5")]
    pub hard_expires_at_ms: u64,
    #[prost(uint64, tag = "6")]
    pub revision: u64,
    #[prost(uint32, repeated, tag = "7")]
    pub active_path_ids: Vec<u32>,
    #[prost(uint32, repeated, tag = "8")]
    pub retired_path_ids: Vec<u32>,
}

impl ControlPayload for MptcpPathsState {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::MptcpPathsState;

    fn validate(&self) -> Result<(), ProtocolError> {
        for (value, length) in [
            (&self.request_sha256, 32),
            (&self.route_context_id, 16),
            (&self.reservation_id, 16),
            (&self.exit_node_id, 32),
        ] {
            if value.len() != length || value.iter().all(|byte| *byte == 0) {
                return Err(ProtocolError::InvalidField("MPTCP path-state identity"));
            }
        }
        if self.revision == 0
            || self.hard_expires_at_ms == 0
            || self.active_path_ids.len() < 2
            || self.active_path_ids.len() + self.retired_path_ids.len() > 8
            || !paths(&self.active_path_ids)
            || !paths(&self.retired_path_ids)
            || self
                .retired_path_ids
                .iter()
                .any(|id| self.active_path_ids.contains(id))
        {
            return Err(ProtocolError::InvalidField("MPTCP path-state paths"));
        }
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        lifetime(envelope, self.hard_expires_at_ms)?;
        if envelope.sender_id != self.exit_node_id {
            return Err(ProtocolError::InvalidField("MPTCP path-state Exit"));
        }
        Ok(())
    }
}

fn paths(ids: &[u32]) -> bool {
    ids.iter().all(|id| (1..=8).contains(id)) && ids.windows(2).all(|pair| pair[0] < pair[1])
}

fn lifetime(envelope: &SignedEnvelope, hard: u64) -> Result<(), ProtocolError> {
    if envelope.expires_at_ms > hard
        || !envelope
            .expires_at_ms
            .checked_sub(envelope.timestamp_ms)
            .is_some_and(|duration| (1..=5_000).contains(&duration))
    {
        return Err(ProtocolError::InvalidField("MPTCP path-state lifetime"));
    }
    Ok(())
}

/// Bind a state response to the complete exact session-signed request, including its nonce.
#[must_use]
pub fn mptcp_paths_request_hash(encoded: &[u8]) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"volparossa:mptcp-path-state:v1\0");
    hash.update(encoded);
    hash.finalize().into()
}
