use ed25519_dalek::SigningKey;
use prost::Message;

use super::{
    MAX_AUTH_SECONDS, MAX_RECEIPT_BYTES, ProtocolError, StorageOperation, VerifiedStorageRequest,
    envelope,
};
use crate::{CHUNK_BYTES, Validity, private_storage::LeaseId};

/// Exact provider-observed lifecycle state, not a promise of future retrievability.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum ReceiptState {
    /// Full payload charged, no prefix stored and no readable committed archive.
    Reserved = 1,
    /// A durable contiguous prefix exists; even a full prefix is not yet a committed archive.
    Partial = 2,
    /// Provider states the original full archive passed verification and is committed.
    Committed = 3,
    /// Exact lease retention was extended; this does not independently assert commit state.
    Renewed = 4,
    /// Exact owned copy was deleted, or a matching durable deletion tombstone was observed.
    Deleted = 5,
}

/// Bounded outcome supplied only after the service actually executes the authorized operation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ReceiptResult {
    /// Exact operation-compatible provider-observed state.
    pub state: ReceiptState,
    /// Exact resulting lease; newly issued only for Reserve, unchanged for other operations.
    pub lease_id: LeaseId,
    /// Contiguous stored prefix bytes, or zero after deletion; not the full charged quota.
    pub stored_bytes: u64,
    /// Current finite lease deadline, or zero for deletion; reads never extend it. An
    /// idempotent Reserve reports an existing lease's current deadline without renewing it.
    pub expires_at: u64,
    /// SHA-256 of the exact separately returned `ReadRange` bytes, absent for all other kinds.
    /// The owner still checks the original complete archive hash after full reconstruction.
    pub range_sha256: Option<[u8; 32]>,
}

#[derive(Clone, PartialEq, Message)]
struct ReceiptPayload {
    #[prost(bytes = "vec", tag = "1")]
    request_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    provider: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    capability_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    grant_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    archive_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    lease_id: Vec<u8>,
    #[prost(uint64, tag = "7")]
    ciphertext_bytes: u64,
    #[prost(bytes = "vec", tag = "8")]
    sha256: Vec<u8>,
    #[prost(enumeration = "ReceiptState", tag = "9")]
    state: i32,
    #[prost(uint64, tag = "10")]
    stored_bytes: u64,
    #[prost(uint64, tag = "11")]
    expires_at: u64,
    #[prost(bytes = "vec", tag = "12")]
    range_sha256: Vec<u8>,
}

/// Original provider-signed statement bound to one exact owner-authorized operation.
/// A dishonest provider can still lie: this signature is not proof of actual disk custody,
/// future online availability, independent replicas or a network-wide capacity credit.
#[derive(Clone, Debug)]
pub struct SignedStorageReceipt {
    envelope: envelope::Envelope,
    result: ReceiptResult,
}

impl SignedStorageReceipt {
    /// Sign an actual execution result; protocol validation itself does not touch any disk.
    ///
    /// # Errors
    /// Rejects a wrong provider, expired authorization or result incompatible with the exact
    /// request. The service must not sign a successful outcome before durable execution.
    pub fn sign(
        provider: &SigningKey,
        request: &VerifiedStorageRequest,
        result: ReceiptResult,
        validity: Validity,
    ) -> Result<Self, ProtocolError> {
        if provider.verifying_key() != *request.grant().provider_key() {
            return Err(ProtocolError::Unauthorized);
        }
        request.current(validity.created)?;
        envelope::within(validity, request.validity())?;
        validate(result, request, validity.created)?;
        let target = request.target();
        let payload = ReceiptPayload {
            request_id: request.id().to_vec(),
            provider: request.grant().provider_key().as_bytes().to_vec(),
            capability_id: request.grant().capability_id().to_vec(),
            grant_id: request.grant().id().to_vec(),
            archive_id: target.archive_id.to_vec(),
            lease_id: result.lease_id.as_bytes().to_vec(),
            ciphertext_bytes: target.ciphertext_bytes,
            sha256: target.sha256.to_vec(),
            state: result.state as i32,
            stored_bytes: result.stored_bytes,
            expires_at: result.expires_at,
            range_sha256: result
                .range_sha256
                .map(|hash| hash.to_vec())
                .unwrap_or_default(),
        };
        Ok(Self {
            envelope: envelope::sign(
                provider,
                envelope::RECEIPT,
                payload.encode_to_vec(),
                validity,
                MAX_AUTH_SECONDS,
            )?,
            result,
        })
    }

    /// Original signed receipt bytes, not a refreshed promise or replayable operation.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.envelope.encode_to_vec()
    }

    /// Exact authenticated result. It is a statement, not independently observed disk state.
    #[must_use]
    pub const fn result(&self) -> ReceiptResult {
        self.result
    }

    /// Verify the provider and exact original request before interpreting the result.
    ///
    /// # Errors
    /// Rejects stale/noncanonical/wrong-provider receipts, unrelated request hashes,
    /// changed lease/archive identities and operation-incompatible lifecycle outcomes.
    pub fn decode_and_verify(
        bytes: &[u8],
        request: &VerifiedStorageRequest,
        now: u64,
    ) -> Result<Self, ProtocolError> {
        let trusted_provider = request.grant().provider_key();
        let envelope = envelope::decode(bytes, MAX_RECEIPT_BYTES)?;
        let body = envelope::verify(
            &envelope,
            trusted_provider,
            envelope::RECEIPT,
            MAX_AUTH_SECONDS,
            now,
        )?;
        request.current(body.created)?;
        envelope::within(envelope::validity(body), request.validity())?;
        let payload: ReceiptPayload = envelope::decode(&body.payload, MAX_RECEIPT_BYTES)?;
        let target = request.target();
        if payload.request_id.as_slice() != request.id()
            || payload.provider.as_slice() != trusted_provider.as_bytes()
            || payload.capability_id.as_slice() != request.grant().capability_id()
            || payload.grant_id.as_slice() != request.grant().id()
            || payload.archive_id.as_slice() != target.archive_id
            || payload.ciphertext_bytes != target.ciphertext_bytes
            || payload.sha256.as_slice() != target.sha256
        {
            return Err(ProtocolError::Unauthorized);
        }
        let result = ReceiptResult {
            state: ReceiptState::try_from(payload.state).map_err(|_| ProtocolError::Invalid)?,
            lease_id: LeaseId::from_bytes(envelope::identifier(&payload.lease_id)?),
            stored_bytes: payload.stored_bytes,
            expires_at: payload.expires_at,
            range_sha256: if payload.range_sha256.is_empty() {
                None
            } else {
                Some(envelope::fixed(&payload.range_sha256)?)
            },
        };
        validate(result, request, body.created)?;
        Ok(Self { envelope, result })
    }
}

fn validate(
    result: ReceiptResult,
    request: &VerifiedStorageRequest,
    created: u64,
) -> Result<(), ProtocolError> {
    envelope::identifier::<16>(result.lease_id.as_bytes())?;
    let target = request.target();
    if target
        .lease_id
        .is_some_and(|lease| lease != result.lease_id)
        || result.stored_bytes > target.ciphertext_bytes
        || (result.stored_bytes != target.ciphertext_bytes
            && result.stored_bytes % CHUNK_BYTES as u64 != 0)
        || result.range_sha256.is_some()
            != matches!(request.operation(), StorageOperation::ReadRange { .. })
    {
        return Err(ProtocolError::Invalid);
    }
    match result.state {
        ReceiptState::Reserved | ReceiptState::Deleted if result.stored_bytes != 0 => {
            return Err(ProtocolError::Invalid);
        }
        ReceiptState::Partial if result.stored_bytes == 0 => return Err(ProtocolError::Invalid),
        ReceiptState::Committed if result.stored_bytes != target.ciphertext_bytes => {
            return Err(ProtocolError::Invalid);
        }
        _ => {}
    }
    if result.state == ReceiptState::Deleted {
        if result.expires_at != 0 {
            return Err(ProtocolError::Invalid);
        }
    } else if result.expires_at <= created
        || result.expires_at > request.grant().validity().expires
        || result.expires_at - created > request.grant().limits().max_retention_seconds
    {
        return Err(ProtocolError::Invalid);
    }
    let compatible = match request.operation() {
        // An exact archive retry can find a previously partial/committed/renewed copy.
        // Returning its real current state must not claim it was reset or newly renewed.
        StorageOperation::Reserve { .. } => matches!(
            result.state,
            ReceiptState::Reserved | ReceiptState::Partial | ReceiptState::Committed
        ),
        StorageOperation::Append { offset, length, .. } => {
            matches!(
                result.state,
                ReceiptState::Partial | ReceiptState::Committed
            ) && result.stored_bytes >= offset + u64::from(length)
        }
        StorageOperation::Progress => matches!(
            result.state,
            ReceiptState::Reserved | ReceiptState::Partial | ReceiptState::Committed
        ),
        StorageOperation::Finalize | StorageOperation::ReadRange { .. } => {
            result.state == ReceiptState::Committed
        }
        StorageOperation::Renew { expires_at } => {
            result.state == ReceiptState::Renewed && result.expires_at == expires_at
        }
        StorageOperation::Delete => result.state == ReceiptState::Deleted,
    };
    if !compatible {
        return Err(ProtocolError::Invalid);
    }
    Ok(())
}
