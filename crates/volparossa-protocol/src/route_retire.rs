//! Endpoint-free retirement requests. Authority remains the exact retained grant and owner.

use prost::Message;
use sha2::{Digest, Sha256};

use crate::{
    ControlMessageType, ControlPayload, PROTOCOL_VERSION, ProtocolError, SignedEnvelope,
    decode_canonical, node_id_from_public_key,
};

/// Maximum canonical signed retirement request or receipt, including a single Exit receipt.
pub const MAX_ROUTE_RETIRE_BYTES: usize = 4096;
/// Retirement authorization is fresh and short-lived even when the original route has expired.
pub const MAX_ROUTE_RETIRE_LIFETIME_MS: u64 = 15_000;

/// A session's request to destroy, never create or renew, its exact retained reservation.
///
/// The receiver must additionally match its retained signed grant, authenticated adjacent peer,
/// and all owned paths. No Internet destination or permanent Client identity is transmitted.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct RouteRetire {
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub policy_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub client_session_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub client_session_public_key: Vec<u8>,
}

/// A concrete owner's signed completion, correlated to the entire fresh signed request.
///
/// An Exit emits no nested receipt. A Relay may include its exact independently verified Exit
/// receipt; the Client must require it when that Relay was asked to retire the upstream owner.
/// This is an acknowledgement, not independent proof that an untrusted node destroyed state.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct RetirementReceipt {
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub request_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub provider_node_id: Vec<u8>,
    #[prost(bool, tag = "5")]
    pub confirmed_destroyed: bool,
    #[prost(bytes = "vec", tag = "6")]
    pub signed_exit_receipt: Vec<u8>,
}

fn fixed<const N: usize>(value: &[u8]) -> Result<[u8; N], ProtocolError> {
    let bytes = <[u8; N]>::try_from(value)
        .map_err(|_| ProtocolError::InvalidField("retirement fixed field"))?;
    if bytes.iter().all(|byte| *byte == 0) {
        return Err(ProtocolError::InvalidField("retirement zero field"));
    }
    Ok(bytes)
}

fn lifetime(envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
    if !envelope
        .expires_at_ms
        .checked_sub(envelope.timestamp_ms)
        .is_some_and(|duration| (1..=MAX_ROUTE_RETIRE_LIFETIME_MS).contains(&duration))
    {
        return Err(ProtocolError::InvalidLifetime);
    }
    Ok(())
}

impl ControlPayload for RouteRetire {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::RouteRetire;

    fn validate(&self) -> Result<(), ProtocolError> {
        fixed::<16>(&self.route_context_id)?;
        fixed::<16>(&self.reservation_id)?;
        fixed::<32>(&self.policy_hash)?;
        let key = fixed::<32>(&self.client_session_public_key)?;
        if self.client_session_id != node_id_from_public_key(&key) {
            return Err(ProtocolError::InvalidField("retirement session binding"));
        }
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        if envelope.sender_id != self.client_session_id
            || envelope.sender_public_key != self.client_session_public_key
        {
            return Err(ProtocolError::InvalidField("retirement request signer"));
        }
        lifetime(envelope)
    }
}

impl RetirementReceipt {
    fn validate_local(&self) -> Result<(), ProtocolError> {
        fixed::<16>(&self.route_context_id)?;
        fixed::<16>(&self.reservation_id)?;
        fixed::<32>(&self.request_hash)?;
        fixed::<32>(&self.provider_node_id)?;
        if !self.confirmed_destroyed || self.encoded_len() > MAX_ROUTE_RETIRE_BYTES {
            return Err(ProtocolError::InvalidField("retirement completion"));
        }
        Ok(())
    }
}

impl ControlPayload for RetirementReceipt {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::RetirementReceipt;

    fn validate(&self) -> Result<(), ProtocolError> {
        self.validate_local()?;
        if !self.signed_exit_receipt.is_empty() {
            let envelope: SignedEnvelope =
                decode_canonical(&self.signed_exit_receipt, MAX_ROUTE_RETIRE_BYTES)?;
            if envelope.protocol_version != PROTOCOL_VERSION
                || envelope.message_type != Self::MESSAGE_TYPE as i32
            {
                return Err(ProtocolError::InvalidField("retirement nested type"));
            }
            let nested: Self = decode_canonical(&envelope.payload, MAX_ROUTE_RETIRE_BYTES)?;
            // Check before any recursive validation: nesting is exactly one bounded level.
            if !nested.signed_exit_receipt.is_empty()
                || nested.route_context_id != self.route_context_id
                || nested.reservation_id != self.reservation_id
                || nested.request_hash != self.request_hash
                || nested.provider_node_id == self.provider_node_id
            {
                return Err(ProtocolError::InvalidField("retirement nested binding"));
            }
            nested.validate_local()?;
            nested.validate_envelope(&envelope)?;
        }
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        if envelope.sender_id != self.provider_node_id {
            return Err(ProtocolError::InvalidField("retirement receipt signer"));
        }
        lifetime(envelope)
    }
}

/// Hash the exact canonical signed request, including its nonce and signature.
///
/// This function validates framing only, not signature, replay or retained ownership authority.
///
/// # Errors
/// Rejects oversized/noncanonical envelopes and any other message type or invalid payload shape.
pub fn route_retire_request_hash(encoded: &[u8]) -> Result<[u8; 32], ProtocolError> {
    let envelope: SignedEnvelope = decode_canonical(encoded, MAX_ROUTE_RETIRE_BYTES)?;
    if envelope.protocol_version != PROTOCOL_VERSION
        || envelope.message_type != ControlMessageType::RouteRetire as i32
    {
        return Err(ProtocolError::InvalidField("retirement request type"));
    }
    let request: RouteRetire = decode_canonical(&envelope.payload, MAX_ROUTE_RETIRE_BYTES)?;
    request.validate()?;
    request.validate_envelope(&envelope)?;
    let mut hash = Sha256::new();
    hash.update(b"volparossa/route-retire-request/v4\0");
    hash.update(
        u32::try_from(encoded.len())
            .unwrap_or(u32::MAX)
            .to_be_bytes(),
    );
    hash.update(encoded);
    Ok(hash.finalize().into())
}
