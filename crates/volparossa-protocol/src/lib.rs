//! Canonical, bounded VOLPAROSSA v4 control-plane messages.
//!
//! The public verification API deliberately combines canonical protobuf
//! decoding, Ed25519 verification, time validation, payload validation, and
//! replay protection. Callers should prefer the typed verification function
//! over decoding the raw signed envelope directly.

mod canonical;
mod envelope;
mod messages;
mod native_route;
mod preselection_observation;
mod reservation_requests;

pub use canonical::{decode_canonical, encode_canonical};
pub use envelope::{
    ControlPayload, ReplayCache, SignedEnvelope, TimePolicy, VerifiedControlMessage,
    generate_nonce, node_id_from_public_key, sign_control_message, sign_control_message_with,
    verify_control_message,
};
pub use messages::{
    AdvertisementCapabilities, AdvertisementCapacity, AdvertisementNetwork, AdvertisementPolicy,
    AdvertisementQuality, AdvertisementRoles, ControlMessageType, ExitConfirmationReceipt,
    ExitReservation, ExitReservationConfirmation, NativeRouteIdentity, NodeAdvertisement, OpenTcp,
    RelayAuthorization, RelayReservation, Transport, UdpFlowAuthorization, WireguardEndpoint,
    exit_confirmation_envelope_hash, finalized_reservation_bundle_hash, verify_relay_reservation,
};
pub use native_route::{
    NATIVE_ROUTE_AUTH_BEARER_LENGTH, NATIVE_ROUTE_AUTH_COMMITMENT_DOMAIN,
    native_route_auth_commitment,
};
pub use preselection_observation::{
    BoundDirectPreselectionTranscript, BoundForwardedPreselectionTranscript,
    ForwardedPreselectionAttestation, MAX_FORWARDED_ATTESTATION_SIZE,
    MAX_PRESELECTION_RECEIPT_SIZE, MAX_PRESELECTION_REQUEST_SIZE, ObservationAddressFamily,
    ObservationNetworkPrefix, PreselectionActorBinding, PreselectionObservationReceipt,
    PreselectionObservationRequest, PreselectionObservationRole, PreselectionObservationScope,
    VerifiedDirectPreselectionTranscript, VerifiedForwardedPreselectionTranscript,
    consume_direct_preselection_transcript, consume_forwarded_preselection_transcript,
    preselection_observation_receipt_hash, preselection_observation_request_hash,
    verify_direct_preselection_transcript, verify_forwarded_preselection_transcript,
};
pub use reservation_requests::{
    ClientSessionCapability, ExitCapacityHold, ExitCapacityHoldRequest,
    ExitReservationFinalizeRequest, FinalizedRelayPath, ProbeAddressFamily, ProbeLegEvidence,
    RelayProbePermit, RelayProbePermitRequest, RelayProbeResult, RelayReservationRequest,
};

use thiserror::Error;

/// Current VOLPAROSSA control-plane protocol version.
pub const PROTOCOL_VERSION: u32 = 4;

/// Largest valid MASQUE context identifier encoded as a QUIC variable-length integer.
pub const MAX_MASQUE_CONTEXT_ID: u64 = (1_u64 << 62) - 1;

/// Maximum accepted encoded control message size.
pub const MAX_CONTROL_MESSAGE_SIZE: usize = 256 * 1024;

/// Maximum accepted encoded payload size inside a signed envelope.
pub const MAX_CONTROL_PAYLOAD_SIZE: usize = 192 * 1024;

/// Errors returned while creating or validating control-plane data.
#[derive(Debug, Error)]
pub enum ProtocolError {
    /// An encoded value exceeds its fixed resource limit.
    #[error("{what} exceeds the maximum size of {maximum} bytes")]
    Oversized {
        /// Name of the oversized value.
        what: &'static str,
        /// Maximum accepted size.
        maximum: usize,
    },

    /// Protobuf encoding failed.
    #[error("protobuf encoding failed: {0}")]
    Encode(#[from] prost::EncodeError),

    /// Protobuf decoding failed.
    #[error("protobuf decoding failed: {0}")]
    Decode(#[from] prost::DecodeError),

    /// The protobuf was valid but did not use the canonical representation.
    #[error("non-canonical protobuf encoding")]
    NonCanonical,

    /// A protocol version other than v4 was received.
    #[error("unsupported protocol version {0}")]
    UnsupportedVersion(u32),

    /// The message type is unknown.
    #[error("unknown control message type {0}")]
    UnknownMessageType(i32),

    /// The envelope contains another payload type than requested.
    #[error("wrong control message type: expected {expected:?}, received {actual:?}")]
    WrongMessageType {
        /// Expected type.
        expected: ControlMessageType,
        /// Actual type.
        actual: ControlMessageType,
    },

    /// A field failed structural or semantic validation.
    #[error("invalid field: {0}")]
    InvalidField(&'static str),

    /// The public key is not the key identified by the sender ID.
    #[error("sender ID does not match the signing public key")]
    SenderKeyMismatch,

    /// The payload does not match the hash committed by the envelope.
    #[error("payload hash mismatch")]
    PayloadHashMismatch,

    /// Ed25519 signature verification failed.
    #[error("invalid Ed25519 signature")]
    InvalidSignature,

    /// The configured identity provider could not produce a valid signature.
    #[error("control-message signing failed")]
    SigningFailed,

    /// The message was created too far in the future.
    #[error("message timestamp is outside the accepted clock skew")]
    NotYetValid,

    /// The message has expired.
    #[error("message has expired")]
    Expired,

    /// The message validity window is invalid or too long.
    #[error("invalid message validity window")]
    InvalidLifetime,

    /// This sender/nonce pair was already accepted.
    #[error("replayed control message")]
    Replay,

    /// The replay cache is full of still-live entries.
    #[error("replay cache capacity exhausted")]
    ReplayCapacity,

    /// A length-prefixed frame is malformed.
    #[error("invalid control-message frame")]
    InvalidFrame,
}

/// Encode a canonical envelope as a fixed-width, length-prefixed stream frame.
///
/// # Errors
///
/// Returns an oversized error if the envelope exceeds the control-message
/// limit, or an invalid-frame error if its length cannot be represented.
pub fn frame_control_message(envelope: &[u8]) -> Result<Vec<u8>, ProtocolError> {
    if envelope.len() > MAX_CONTROL_MESSAGE_SIZE {
        return Err(ProtocolError::Oversized {
            what: "control message",
            maximum: MAX_CONTROL_MESSAGE_SIZE,
        });
    }
    let length = u32::try_from(envelope.len()).map_err(|_| ProtocolError::InvalidFrame)?;
    let mut frame = Vec::with_capacity(4 + envelope.len());
    frame.extend_from_slice(&length.to_be_bytes());
    frame.extend_from_slice(envelope);
    Ok(frame)
}

/// Return the single canonical envelope carried by a complete stream frame.
///
/// # Errors
///
/// Returns an invalid-frame error for a short, oversized, truncated, or
/// trailing-byte frame.
pub fn unframe_control_message(frame: &[u8]) -> Result<&[u8], ProtocolError> {
    let length_bytes: [u8; 4] = frame
        .get(..4)
        .ok_or(ProtocolError::InvalidFrame)?
        .try_into()
        .map_err(|_| ProtocolError::InvalidFrame)?;
    let length = usize::try_from(u32::from_be_bytes(length_bytes))
        .map_err(|_| ProtocolError::InvalidFrame)?;
    if length > MAX_CONTROL_MESSAGE_SIZE || frame.len() != length.saturating_add(4) {
        return Err(ProtocolError::InvalidFrame);
    }
    Ok(&frame[4..])
}
