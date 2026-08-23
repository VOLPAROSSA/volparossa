use std::collections::HashMap;

use ed25519_dalek::{Signature, Signer, SigningKey, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};

use crate::{
    ControlMessageType, MAX_CONTROL_MESSAGE_SIZE, MAX_CONTROL_PAYLOAD_SIZE, PROTOCOL_VERSION,
    ProtocolError, decode_canonical, encode_canonical,
};

const SIGNATURE_DOMAIN: &[u8] = b"volparossa/control-envelope/v3\0";
const NODE_ID_DOMAIN: &[u8] = b"volparossa/node-id/v1\0";
const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 32;
const SIGNATURE_LENGTH: usize = 64;

/// The signed outer wrapper for every VOLPAROSSA control-plane payload.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct SignedEnvelope {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub sender_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub sender_public_key: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub timestamp_ms: u64,
    #[prost(uint64, tag = "5")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "6")]
    pub nonce: Vec<u8>,
    #[prost(enumeration = "ControlMessageType", tag = "7")]
    pub message_type: i32,
    #[prost(bytes = "vec", tag = "8")]
    pub payload: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub payload_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "10")]
    pub signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct SignatureInput {
    #[prost(uint32, tag = "1")]
    protocol_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    sender_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    sender_public_key: Vec<u8>,
    #[prost(uint64, tag = "4")]
    timestamp_ms: u64,
    #[prost(uint64, tag = "5")]
    expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "6")]
    nonce: Vec<u8>,
    #[prost(enumeration = "ControlMessageType", tag = "7")]
    message_type: i32,
    #[prost(bytes = "vec", tag = "8")]
    payload_hash: Vec<u8>,
}

/// Time limits applied to signed, short-lived control messages.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TimePolicy {
    /// Maximum permitted lifetime from creation to expiry.
    pub maximum_lifetime_ms: u64,
    /// Maximum clock skew accepted for a timestamp in the future.
    pub maximum_clock_skew_ms: u64,
}

impl Default for TimePolicy {
    fn default() -> Self {
        Self {
            maximum_lifetime_ms: 15 * 60 * 1_000,
            maximum_clock_skew_ms: 60 * 1_000,
        }
    }
}

impl TimePolicy {
    fn validate_window(self, timestamp_ms: u64, expires_at_ms: u64) -> Result<(), ProtocolError> {
        let lifetime = expires_at_ms
            .checked_sub(timestamp_ms)
            .ok_or(ProtocolError::InvalidLifetime)?;
        if lifetime == 0 || self.maximum_lifetime_ms == 0 || lifetime > self.maximum_lifetime_ms {
            return Err(ProtocolError::InvalidLifetime);
        }
        Ok(())
    }

    fn validate_at(
        self,
        timestamp_ms: u64,
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        self.validate_window(timestamp_ms, expires_at_ms)?;
        if timestamp_ms > now_ms.saturating_add(self.maximum_clock_skew_ms) {
            return Err(ProtocolError::NotYetValid);
        }
        if expires_at_ms <= now_ms {
            return Err(ProtocolError::Expired);
        }
        Ok(())
    }
}

/// A protobuf payload that can be carried in a signed control envelope.
pub trait ControlPayload: Message + Default {
    /// Message discriminator committed by the signed envelope.
    const MESSAGE_TYPE: ControlMessageType;

    /// Validate all payload-local resource and semantic invariants.
    ///
    /// # Errors
    ///
    /// Returns an error when a payload-local bound or semantic invariant is invalid.
    fn validate(&self) -> Result<(), ProtocolError>;

    /// Validate relationships between the payload and its signed envelope.
    ///
    /// # Errors
    ///
    /// Returns an error when the payload contradicts authenticated envelope metadata. The default
    /// implementation accepts payload types without envelope-specific relationships.
    fn validate_envelope(&self, _envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        Ok(())
    }
}

type VerifiedEnvelopeFields = (
    [u8; KEY_LENGTH],
    [u8; KEY_LENGTH],
    [u8; NONCE_LENGTH],
    ControlMessageType,
);

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct ReplayKey {
    sender_id: [u8; KEY_LENGTH],
    nonce: [u8; NONCE_LENGTH],
}

/// Bounded replay detector for accepted, still-live control messages.
///
/// Entries are retained until envelope expiry. When the configured capacity is
/// exhausted by live entries, validation fails closed instead of evicting an
/// entry and allowing its message to be replayed.
#[derive(Debug)]
pub struct ReplayCache {
    maximum_entries: usize,
    entries: HashMap<ReplayKey, u64>,
}

impl ReplayCache {
    /// Construct an empty cache with a non-zero hard entry limit.
    ///
    /// # Errors
    ///
    /// Returns an invalid-field error for a zero limit.
    pub fn new(maximum_entries: usize) -> Result<Self, ProtocolError> {
        if maximum_entries == 0 {
            return Err(ProtocolError::InvalidField("replay cache maximum_entries"));
        }
        Ok(Self {
            maximum_entries,
            entries: HashMap::with_capacity(maximum_entries.min(4_096)),
        })
    }

    /// Number of live or not-yet-pruned entries currently stored.
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Whether no entries are currently stored.
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    fn check_and_insert(
        &mut self,
        sender_id: [u8; KEY_LENGTH],
        nonce: [u8; NONCE_LENGTH],
        expires_at_ms: u64,
        now_ms: u64,
    ) -> Result<(), ProtocolError> {
        self.entries.retain(|_, expiry| *expiry > now_ms);
        let key = ReplayKey { sender_id, nonce };
        if self.entries.contains_key(&key) {
            return Err(ProtocolError::Replay);
        }
        if self.entries.len() >= self.maximum_entries {
            return Err(ProtocolError::ReplayCapacity);
        }
        self.entries.insert(key, expires_at_ms);
        Ok(())
    }

    /// Roll back one message accepted as part of an uncommitted local transaction.
    ///
    /// This is intentionally keyed by the already verified fixed sender and nonce,
    /// not by untrusted wire slices. Admission services use it only when response
    /// signing, endpoint provisioning, or capacity commit fails before any grant is
    /// returned. Successfully committed messages remain replay-protected.
    pub fn rollback(&mut self, sender_id: &[u8; KEY_LENGTH], nonce: &[u8; NONCE_LENGTH]) -> bool {
        self.entries
            .remove(&ReplayKey {
                sender_id: *sender_id,
                nonce: *nonce,
            })
            .is_some()
    }
}

/// A fully verified, replay-protected typed control message.
#[derive(Debug)]
pub struct VerifiedControlMessage<T> {
    message: T,
    sender_id: [u8; KEY_LENGTH],
    sender_public_key: [u8; KEY_LENGTH],
    timestamp_ms: u64,
    expires_at_ms: u64,
    nonce: [u8; NONCE_LENGTH],
}

impl<T> VerifiedControlMessage<T> {
    /// Borrow the validated payload.
    pub fn message(&self) -> &T {
        &self.message
    }

    /// Consume the wrapper and return the validated payload.
    pub fn into_message(self) -> T {
        self.message
    }

    /// Cryptographically derived sender identifier.
    pub fn sender_id(&self) -> &[u8; KEY_LENGTH] {
        &self.sender_id
    }

    /// Ed25519 public key that signed the envelope.
    pub fn sender_public_key(&self) -> &[u8; KEY_LENGTH] {
        &self.sender_public_key
    }

    /// Signed creation timestamp in Unix milliseconds.
    pub fn timestamp_ms(&self) -> u64 {
        self.timestamp_ms
    }

    /// Signed expiry timestamp in Unix milliseconds.
    pub fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Signed 256-bit nonce.
    pub fn nonce(&self) -> &[u8; NONCE_LENGTH] {
        &self.nonce
    }
}

/// Generate a cryptographically secure 256-bit control-message nonce.
///
/// # Panics
///
/// Panics if the operating system cannot provide cryptographically secure randomness.
pub fn generate_nonce() -> [u8; NONCE_LENGTH] {
    let mut nonce = [0_u8; NONCE_LENGTH];
    getrandom::fill(&mut nonce).expect("operating-system randomness unavailable");
    nonce
}

/// Derive the stable VOLPAROSSA node identifier from an Ed25519 public key.
pub fn node_id_from_public_key(public_key: &[u8; KEY_LENGTH]) -> [u8; KEY_LENGTH] {
    let mut hasher = Sha256::new();
    hasher.update(NODE_ID_DOMAIN);
    hasher.update(public_key);
    hasher.finalize().into()
}

/// Validate, canonicalize, and sign a typed control payload.
///
/// # Errors
///
/// Returns an error if the payload or validity window is invalid, the encoded
/// message is oversized, or protobuf encoding fails.
pub fn sign_control_message<T: ControlPayload>(
    payload: &T,
    signing_key: &SigningKey,
    timestamp_ms: u64,
    expires_at_ms: u64,
    nonce: [u8; NONCE_LENGTH],
    time_policy: TimePolicy,
) -> Result<Vec<u8>, ProtocolError> {
    sign_control_message_with(
        payload,
        signing_key.verifying_key().to_bytes(),
        timestamp_ms,
        expires_at_ms,
        nonce,
        time_policy,
        |message| Some(signing_key.sign(message).to_bytes()),
    )
}

/// Sign a control payload through an external Ed25519 identity provider.
///
/// This keeps encrypted identity implementations from exporting private key
/// material or depending on this crate. The returned signature is verified
/// against the supplied public key before an envelope is emitted.
///
/// # Errors
///
/// Returns a signing-failed error when the provider fails or returns a
/// signature that is not valid for the supplied public key. Payload, lifetime,
/// canonical encoding, and size errors are returned unchanged.
pub fn sign_control_message_with<T, F>(
    payload: &T,
    public_key: [u8; KEY_LENGTH],
    timestamp_ms: u64,
    expires_at_ms: u64,
    nonce: [u8; NONCE_LENGTH],
    time_policy: TimePolicy,
    signer: F,
) -> Result<Vec<u8>, ProtocolError>
where
    T: ControlPayload,
    F: FnOnce(&[u8]) -> Option<[u8; SIGNATURE_LENGTH]>,
{
    time_policy.validate_window(timestamp_ms, expires_at_ms)?;
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(ProtocolError::InvalidField("nonce"));
    }
    payload.validate()?;

    let payload_bytes = encode_canonical(payload, MAX_CONTROL_PAYLOAD_SIZE)?;
    let payload_hash: [u8; KEY_LENGTH] = Sha256::digest(&payload_bytes).into();
    let sender_id = node_id_from_public_key(&public_key);
    let mut envelope = SignedEnvelope {
        protocol_version: PROTOCOL_VERSION,
        sender_id: sender_id.to_vec(),
        sender_public_key: public_key.to_vec(),
        timestamp_ms,
        expires_at_ms,
        nonce: nonce.to_vec(),
        message_type: T::MESSAGE_TYPE as i32,
        payload: payload_bytes,
        payload_hash: payload_hash.to_vec(),
        signature: Vec::new(),
    };
    payload.validate_envelope(&envelope)?;
    let signing_bytes = signing_bytes(&envelope)?;
    let signature_bytes = signer(&signing_bytes).ok_or(ProtocolError::SigningFailed)?;
    let verifying_key =
        VerifyingKey::from_bytes(&public_key).map_err(|_| ProtocolError::SigningFailed)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(&signing_bytes, &signature)
        .map_err(|_| ProtocolError::SigningFailed)?;
    envelope.signature = signature_bytes.to_vec();
    encode_canonical(&envelope, MAX_CONTROL_MESSAGE_SIZE)
}

/// Verify a typed control message and atomically record its sender/nonce pair.
///
/// # Errors
///
/// Fails closed for malformed or non-canonical input, invalid versions,
/// signatures, hashes, timestamps, payloads, replays, and exhausted replay
/// capacity.
pub fn verify_control_message<T: ControlPayload>(
    encoded: &[u8],
    now_ms: u64,
    time_policy: TimePolicy,
    replay_cache: &mut ReplayCache,
) -> Result<VerifiedControlMessage<T>, ProtocolError> {
    let envelope: SignedEnvelope = decode_canonical(encoded, MAX_CONTROL_MESSAGE_SIZE)?;
    let (sender_id, sender_public_key, nonce, actual_type) =
        verify_envelope(&envelope, now_ms, time_policy)?;

    if actual_type != T::MESSAGE_TYPE {
        return Err(ProtocolError::WrongMessageType {
            expected: T::MESSAGE_TYPE,
            actual: actual_type,
        });
    }
    let payload: T = decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)?;
    payload.validate()?;
    payload.validate_envelope(&envelope)?;
    replay_cache.check_and_insert(sender_id, nonce, envelope.expires_at_ms, now_ms)?;

    Ok(VerifiedControlMessage {
        message: payload,
        sender_id,
        sender_public_key,
        timestamp_ms: envelope.timestamp_ms,
        expires_at_ms: envelope.expires_at_ms,
        nonce,
    })
}

fn verify_envelope(
    envelope: &SignedEnvelope,
    now_ms: u64,
    time_policy: TimePolicy,
) -> Result<VerifiedEnvelopeFields, ProtocolError> {
    if envelope.protocol_version != PROTOCOL_VERSION {
        return Err(ProtocolError::UnsupportedVersion(envelope.protocol_version));
    }
    time_policy.validate_at(envelope.timestamp_ms, envelope.expires_at_ms, now_ms)?;

    if envelope.payload.len() > MAX_CONTROL_PAYLOAD_SIZE {
        return Err(ProtocolError::Oversized {
            what: "control payload",
            maximum: MAX_CONTROL_PAYLOAD_SIZE,
        });
    }
    let sender_id = fixed_array::<KEY_LENGTH>(&envelope.sender_id, "sender_id")?;
    let sender_public_key =
        fixed_array::<KEY_LENGTH>(&envelope.sender_public_key, "sender_public_key")?;
    let nonce = fixed_array::<NONCE_LENGTH>(&envelope.nonce, "nonce")?;
    if nonce.iter().all(|byte| *byte == 0) {
        return Err(ProtocolError::InvalidField("nonce"));
    }
    let payload_hash = fixed_array::<KEY_LENGTH>(&envelope.payload_hash, "payload_hash")?;
    let signature_bytes = fixed_array::<SIGNATURE_LENGTH>(&envelope.signature, "signature")?;

    if node_id_from_public_key(&sender_public_key) != sender_id {
        return Err(ProtocolError::SenderKeyMismatch);
    }
    let calculated_payload_hash: [u8; KEY_LENGTH] = Sha256::digest(&envelope.payload).into();
    if calculated_payload_hash != payload_hash {
        return Err(ProtocolError::PayloadHashMismatch);
    }
    let message_type = ControlMessageType::try_from(envelope.message_type)
        .map_err(|_| ProtocolError::UnknownMessageType(envelope.message_type))?;
    if message_type == ControlMessageType::Unspecified {
        return Err(ProtocolError::UnknownMessageType(envelope.message_type));
    }

    let verifying_key = VerifyingKey::from_bytes(&sender_public_key)
        .map_err(|_| ProtocolError::InvalidSignature)?;
    let signature = Signature::from_bytes(&signature_bytes);
    verifying_key
        .verify_strict(&signing_bytes(envelope)?, &signature)
        .map_err(|_| ProtocolError::InvalidSignature)?;

    Ok((sender_id, sender_public_key, nonce, message_type))
}

fn signing_bytes(envelope: &SignedEnvelope) -> Result<Vec<u8>, ProtocolError> {
    let input = SignatureInput {
        protocol_version: envelope.protocol_version,
        sender_id: envelope.sender_id.clone(),
        sender_public_key: envelope.sender_public_key.clone(),
        timestamp_ms: envelope.timestamp_ms,
        expires_at_ms: envelope.expires_at_ms,
        nonce: envelope.nonce.clone(),
        message_type: envelope.message_type,
        payload_hash: envelope.payload_hash.clone(),
    };
    let encoded = encode_canonical(&input, MAX_CONTROL_MESSAGE_SIZE)?;
    let mut domain_separated = Vec::with_capacity(SIGNATURE_DOMAIN.len() + encoded.len());
    domain_separated.extend_from_slice(SIGNATURE_DOMAIN);
    domain_separated.extend_from_slice(&encoded);
    Ok(domain_separated)
}

pub(crate) fn fixed_array<const LENGTH: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; LENGTH], ProtocolError> {
    bytes
        .try_into()
        .map_err(|_| ProtocolError::InvalidField(field))
}
