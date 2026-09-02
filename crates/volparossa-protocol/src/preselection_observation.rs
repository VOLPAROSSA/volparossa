//! Callerless v4 primitives for short-lived preselection observations.
//!
//! An observation challenge is unsigned. A future caller must CSPRNG-generate a
//! fresh unique challenge for every observation request, challenged subject
//! (direct relay or forwarded exit), and attempt, and never reuse it across any
//! of them. This module checks only its 32-byte non-zero shape and provides no
//! caller or uniqueness registry. A forwarding control intentionally echoes the
//! exit subject's challenge while signing with its own nonce and time window; it
//! is not separately challenged and its signature alone is no liveness or origin
//! truth proof. A receipt grants no capacity, admission, route, reservation, or
//! dispatch authority.

use prost::Message;
use sha2::{Digest, Sha256};
use volparossa_core::ObservedNetworkPrefix;

use crate::envelope::fixed_array;
use crate::{
    ControlMessageType, ControlPayload, MAX_CONTROL_MESSAGE_SIZE, PROTOCOL_VERSION, ProtocolError,
    ReplayCache, SignedEnvelope, TimePolicy, Transport, VerifiedControlMessage, decode_canonical,
    node_id_from_public_key, verify_control_message,
};

const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 32;
const MAX_PEER_ID_LENGTH: usize = 64;
/// Maximum exact canonical unsigned preselection request size.
pub const MAX_PRESELECTION_REQUEST_SIZE: usize = 4 * 1024;
/// Maximum exact canonical signed preselection receipt size.
pub const MAX_PRESELECTION_RECEIPT_SIZE: usize = 4 * 1024;
/// Maximum exact canonical signed forwarded preselection attestation size.
pub const MAX_FORWARDED_ATTESTATION_SIZE: usize = 8 * 1024;
// The request-response stream remains capped independently at five seconds. The signed one-shot
// challenge must, however, remain usable by the affine native sampler and the subsequent bounded
// production route setup. Both phases can take thirty seconds on the supported KVM topology.
const MAX_CHALLENGE_LIFETIME_MS: u64 = 120 * 1_000;
// Receipt and forwarded-attestation evidence share the same bounded route-setup headroom.
const MAX_OBSERVATION_LIFETIME_MS: u64 = 120 * 1_000;
const REQUEST_HASH_DOMAIN: &[u8] = b"volparossa/preselection-observation-request/v4\0";
const RECEIPT_HASH_DOMAIN: &[u8] = b"volparossa/preselection-observation-receipt/v4\0";

/// Actor role addressed by one preselection observation challenge.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, prost::Enumeration)]
#[repr(i32)]
pub enum PreselectionObservationRole {
    Unspecified = 0,
    Relay = 1,
    Exit = 2,
}

/// Address family whose network origin is being observed.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, prost::Enumeration)]
#[repr(i32)]
pub enum ObservationAddressFamily {
    Unspecified = 0,
    Ipv4 = 1,
    Ipv6 = 2,
}

/// Exact advertised actor identity bound into a preselection transcript.
///
/// A future producer must copy `advertisement_payload_hash` from the exact
/// `SignedEnvelope.payload_hash` of the same freshly cryptographically verified
/// canonical `NodeAdvertisement`. A0 checks its non-zero 32-byte shape and exact
/// transcript echo, not advertisement provenance.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct PreselectionActorBinding {
    #[prost(bytes = "vec", tag = "1")]
    pub node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub public_key: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub advertisement_sequence: u64,
    #[prost(uint64, tag = "5")]
    pub advertisement_expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "6")]
    pub advertisement_payload_hash: Vec<u8>,
    #[prost(uint64, tag = "7")]
    pub capability_expires_at_ms: u64,
}

/// Static route-selection scope echoed by an actor receipt.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct PreselectionObservationScope {
    #[prost(enumeration = "PreselectionObservationRole", tag = "1")]
    pub role: i32,
    #[prost(enumeration = "Transport", tag = "2")]
    pub transport: i32,
    #[prost(enumeration = "ObservationAddressFamily", tag = "3")]
    pub address_family: i32,
    #[prost(uint64, tag = "4")]
    pub policy_version: u64,
    #[prost(bytes = "vec", tag = "5")]
    pub policy_hash: Vec<u8>,
    #[prost(uint64, tag = "6")]
    pub policy_expires_at_ms: u64,
}

/// Unsigned canonical per-actor challenge.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct PreselectionObservationRequest {
    #[prost(uint32, tag = "1")]
    pub protocol_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub challenge: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub actor: Option<PreselectionActorBinding>,
    #[prost(message, optional, tag = "4")]
    pub scope: Option<PreselectionObservationScope>,
    #[prost(message, optional, tag = "5")]
    pub forwarded_control: Option<PreselectionActorBinding>,
    #[prost(uint64, tag = "6")]
    pub created_at_ms: u64,
    #[prost(uint64, tag = "7")]
    pub expires_at_ms: u64,
}

/// Actor-signed response to one exact unsigned challenge.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct PreselectionObservationReceipt {
    #[prost(bytes = "vec", tag = "1")]
    pub request_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub challenge: Vec<u8>,
    #[prost(message, optional, tag = "3")]
    pub actor: Option<PreselectionActorBinding>,
    #[prost(message, optional, tag = "4")]
    pub scope: Option<PreselectionObservationScope>,
    #[prost(uint64, tag = "5")]
    pub observed_at_ms: u64,
    #[prost(uint64, tag = "6")]
    pub valid_until_ms: u64,
    #[prost(bytes = "vec", tag = "7")]
    pub nonce: Vec<u8>,
}

/// Endpoint-free public /24 or /48 claim signed by a forwarding control relay.
///
/// A future handler must derive the claim from the exact authenticated upstream
/// connection. The control signature is not proof that a malicious control
/// relay reported its observation truthfully.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct ObservationNetworkPrefix {
    #[prost(enumeration = "ObservationAddressFamily", tag = "1")]
    pub address_family: i32,
    #[prost(bytes = "vec", tag = "2")]
    pub network_prefix: Vec<u8>,
}

/// Control-signed wrapper around one exact exit-signed observation receipt.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct ForwardedPreselectionAttestation {
    #[prost(bytes = "vec", tag = "1")]
    pub request_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub challenge: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub signed_exit_receipt: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub exit_receipt_hash: Vec<u8>,
    #[prost(message, optional, tag = "5")]
    pub control: Option<PreselectionActorBinding>,
    #[prost(message, optional, tag = "6")]
    pub exit: Option<PreselectionActorBinding>,
    #[prost(message, optional, tag = "7")]
    pub scope: Option<PreselectionObservationScope>,
    #[prost(message, optional, tag = "8")]
    pub upstream_network_prefix: Option<ObservationNetworkPrefix>,
    #[prost(uint64, tag = "9")]
    pub observed_at_ms: u64,
    #[prost(uint64, tag = "10")]
    pub valid_until_ms: u64,
    #[prost(bytes = "vec", tag = "11")]
    pub nonce: Vec<u8>,
}

/// Cryptographically verified direct actor transcript for one exact challenge.
///
/// The bundle is deliberately opaque and has no clone, debug, serialization,
/// getter, or decomposition API. It is not local reachability, RTT, origin, or
/// capacity evidence and is not a dispatch capability.
pub struct VerifiedDirectPreselectionTranscript {
    request: PreselectionObservationRequest,
    _receipt: VerifiedControlMessage<PreselectionObservationReceipt>,
}

/// Verified exit receipt plus its exact control-signed prefix transcript.
///
/// The bundle is deliberately opaque and has no clone, debug, serialization,
/// getter, or decomposition API. It is not local RTT or capacity evidence and
/// is not a dispatch capability.
pub struct VerifiedForwardedPreselectionTranscript {
    request: PreselectionObservationRequest,
    _attestation: VerifiedControlMessage<ForwardedPreselectionAttestation>,
    _exit_receipt: VerifiedControlMessage<PreselectionObservationReceipt>,
}

/// One direct transcript consumed and bound to the caller's exact request.
///
/// The token remains opaque and affine. Its only purpose is to retain the
/// cryptographic proof while a later local-observation owner remains alive.
pub struct BoundDirectPreselectionTranscript {
    _transcript: VerifiedDirectPreselectionTranscript,
}

/// One forwarded transcript consumed and bound to the caller's exact request.
///
/// The token remains opaque and affine. Its only purpose is to retain both
/// cryptographic proofs while a later local-observation owner remains alive.
pub struct BoundForwardedPreselectionTranscript {
    _transcript: VerifiedForwardedPreselectionTranscript,
}

/// Terminal direct-Relay transcript proof retained only for private freshness minting.
///
/// The projection is affine and intentionally exposes no request, identity, signature, nonce,
/// remote observation time, prefix, or wire bytes. Its signed validity ceiling is the only fact
/// a later local-observation owner may combine with its independently bound transport proof.
#[must_use = "a direct preselection freshness proof must be consumed by its private owner"]
pub struct DirectPreselectionFreshnessProof {
    valid_until_ms: u64,
}

impl DirectPreselectionFreshnessProof {
    /// Return the cryptographically verified Relay receipt validity ceiling.
    #[must_use]
    pub const fn valid_until_ms(&self) -> u64 {
        self.valid_until_ms
    }
}

/// Terminal forwarded-Exit transcript proof retained only for private freshness minting.
///
/// The projection is affine and retains only the joint signed validity ceiling and the normalized
/// public /24 or /48 observed by the authenticated control Relay. It exposes no actor identity,
/// request, signature, nonce, full endpoint, or wire bytes.
#[must_use = "a forwarded preselection freshness proof must be consumed by its private owner"]
pub struct ForwardedPreselectionFreshnessProof {
    valid_until_ms: u64,
    upstream_network_prefix: ObservedNetworkPrefix,
}

impl ForwardedPreselectionFreshnessProof {
    /// Return the earlier validity ceiling of the control attestation and nested Exit receipt.
    #[must_use]
    pub const fn valid_until_ms(&self) -> u64 {
        self.valid_until_ms
    }

    /// Return the endpoint-free public prefix cryptographically bound by the control Relay.
    #[must_use]
    pub const fn upstream_network_prefix(&self) -> ObservedNetworkPrefix {
        self.upstream_network_prefix
    }
}

impl PreselectionActorBinding {
    pub(crate) fn validate(&self, field: &'static str) -> Result<(), ProtocolError> {
        let node_id = fixed_array::<KEY_LENGTH>(&self.node_id, field)?;
        let public_key = fixed_array::<KEY_LENGTH>(&self.public_key, field)?;
        if node_id.iter().all(|byte| *byte == 0)
            || public_key.iter().all(|byte| *byte == 0)
            || node_id_from_public_key(&public_key) != node_id
            || self.peer_id.is_empty()
            || self.peer_id.len() > MAX_PEER_ID_LENGTH
            || self.peer_id.iter().all(|byte| *byte == 0)
            || self.advertisement_sequence == 0
            || self.advertisement_expires_at_ms == 0
            || fixed_array::<KEY_LENGTH>(&self.advertisement_payload_hash, field)?
                .iter()
                .all(|byte| *byte == 0)
            || self.capability_expires_at_ms == 0
            || self.capability_expires_at_ms > self.advertisement_expires_at_ms
        {
            return Err(ProtocolError::InvalidField(field));
        }
        Ok(())
    }
}

impl PreselectionObservationScope {
    fn validate(&self) -> Result<(), ProtocolError> {
        let role = PreselectionObservationRole::try_from(self.role)
            .map_err(|_| ProtocolError::InvalidField("preselection scope role"))?;
        let transport = Transport::try_from(self.transport)
            .map_err(|_| ProtocolError::InvalidField("preselection scope transport"))?;
        let family = ObservationAddressFamily::try_from(self.address_family)
            .map_err(|_| ProtocolError::InvalidField("preselection scope address_family"))?;
        if role == PreselectionObservationRole::Unspecified
            || transport == Transport::Unspecified
            || family == ObservationAddressFamily::Unspecified
            || self.policy_version == 0
            || fixed_array::<KEY_LENGTH>(&self.policy_hash, "preselection scope policy_hash")?
                .iter()
                .all(|byte| *byte == 0)
            || self.policy_expires_at_ms == 0
        {
            return Err(ProtocolError::InvalidField("preselection scope"));
        }
        Ok(())
    }

    fn role_value(&self) -> Result<PreselectionObservationRole, ProtocolError> {
        PreselectionObservationRole::try_from(self.role)
            .map_err(|_| ProtocolError::InvalidField("preselection scope role"))
    }
}

impl PreselectionObservationRequest {
    /// Validate the unsigned challenge's bounded structure and exact role shape.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed identity, scope, challenge, lifetime,
    /// or Relay/Exit forwarded-control mismatch.
    pub fn validate(&self) -> Result<(), ProtocolError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(ProtocolError::UnsupportedVersion(self.protocol_version));
        }
        require_nonzero::<NONCE_LENGTH>(&self.challenge, "preselection request challenge")?;
        let actor = required_actor(self.actor.as_ref(), "preselection request actor")?;
        let scope = required_scope(self.scope.as_ref())?;
        validate_lifetime(
            self.created_at_ms,
            self.expires_at_ms,
            MAX_CHALLENGE_LIFETIME_MS,
        )?;
        if self.expires_at_ms > actor.advertisement_expires_at_ms
            || self.expires_at_ms > actor.capability_expires_at_ms
            || self.expires_at_ms > scope.policy_expires_at_ms
        {
            return Err(ProtocolError::InvalidLifetime);
        }
        match (scope.role_value()?, self.forwarded_control.as_ref()) {
            (PreselectionObservationRole::Relay, None) => {
                validate_direct_capability_expiry(actor, scope)?;
            }
            (PreselectionObservationRole::Exit, Some(control)) => {
                control.validate("preselection request control")?;
                validate_forwarded_capability_expiry(control, actor, scope)?;
                if self.expires_at_ms > control.advertisement_expires_at_ms
                    || self.expires_at_ms > control.capability_expires_at_ms
                    || control.node_id == actor.node_id
                    || control.peer_id == actor.peer_id
                    || control.public_key == actor.public_key
                {
                    return Err(ProtocolError::InvalidField(
                        "preselection request forwarded control",
                    ));
                }
            }
            _ => {
                return Err(ProtocolError::InvalidField(
                    "preselection request role shape",
                ));
            }
        }
        Ok(())
    }
}

impl ObservationNetworkPrefix {
    pub(crate) fn validated_normalized(&self) -> Result<ObservedNetworkPrefix, ProtocolError> {
        let family = ObservationAddressFamily::try_from(self.address_family)
            .map_err(|_| ProtocolError::InvalidField("observation network prefix"))?;
        let prefix =
            match family {
                ObservationAddressFamily::Ipv4 => {
                    let prefix_octets: [u8; 3] =
                        self.network_prefix.as_slice().try_into().map_err(|_| {
                            ProtocolError::InvalidField("observation network prefix")
                        })?;
                    ObservedNetworkPrefix::ipv4_24(prefix_octets)
                }
                ObservationAddressFamily::Ipv6 => {
                    let prefix_octets: [u8; 6] =
                        self.network_prefix.as_slice().try_into().map_err(|_| {
                            ProtocolError::InvalidField("observation network prefix")
                        })?;
                    ObservedNetworkPrefix::ipv6_48(prefix_octets)
                }
                ObservationAddressFamily::Unspecified => {
                    return Err(ProtocolError::InvalidField("observation network prefix"));
                }
            };
        if !prefix.is_public_routable() {
            return Err(ProtocolError::InvalidField("observation network prefix"));
        }
        Ok(prefix)
    }

    fn validate(&self) -> Result<(), ProtocolError> {
        self.validated_normalized().map(drop)
    }
}

impl ControlPayload for PreselectionObservationReceipt {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::PreselectionObservationReceipt;

    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero::<KEY_LENGTH>(&self.request_hash, "observation receipt request_hash")?;
        require_nonzero::<NONCE_LENGTH>(&self.challenge, "observation receipt challenge")?;
        let actor = required_actor(self.actor.as_ref(), "observation receipt actor")?;
        let scope = required_scope(self.scope.as_ref())?;
        match scope.role_value()? {
            PreselectionObservationRole::Relay => {
                validate_direct_capability_expiry(actor, scope)?;
            }
            PreselectionObservationRole::Exit => validate_actor_scope_ceiling(actor, scope)?,
            PreselectionObservationRole::Unspecified => {
                return Err(ProtocolError::InvalidField("preselection scope role"));
            }
        }
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "observation receipt nonce")?;
        validate_lifetime(
            self.observed_at_ms,
            self.valid_until_ms,
            MAX_OBSERVATION_LIFETIME_MS,
        )?;
        if self.valid_until_ms > actor.advertisement_expires_at_ms
            || self.valid_until_ms > actor.capability_expires_at_ms
            || self.valid_until_ms > scope.policy_expires_at_ms
        {
            return Err(ProtocolError::InvalidLifetime);
        }
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        let actor = required_actor(self.actor.as_ref(), "observation receipt actor")?;
        validate_actor_envelope(
            actor,
            self.observed_at_ms,
            self.valid_until_ms,
            &self.nonce,
            envelope,
            "observation receipt envelope binding",
        )
    }
}

impl ControlPayload for ForwardedPreselectionAttestation {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::ForwardedPreselectionAttestation;

    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero::<KEY_LENGTH>(&self.request_hash, "forwarded observation request_hash")?;
        require_nonzero::<NONCE_LENGTH>(&self.challenge, "forwarded observation challenge")?;
        require_nonzero::<KEY_LENGTH>(
            &self.exit_receipt_hash,
            "forwarded observation exit_receipt_hash",
        )?;
        if self.signed_exit_receipt.len() > MAX_PRESELECTION_RECEIPT_SIZE {
            return Err(ProtocolError::Oversized {
                what: "signed preselection receipt",
                maximum: MAX_PRESELECTION_RECEIPT_SIZE,
            });
        }
        let nested = precheck_nested_exit_receipt(&self.signed_exit_receipt)?;
        if preselection_observation_receipt_hash(&self.signed_exit_receipt)?
            != self.exit_receipt_hash.as_slice()
        {
            return Err(ProtocolError::InvalidField(
                "forwarded observation exit_receipt_hash",
            ));
        }
        let control = required_actor(self.control.as_ref(), "forwarded observation control")?;
        let exit = required_actor(self.exit.as_ref(), "forwarded observation exit")?;
        let scope = required_scope(self.scope.as_ref())?;
        validate_forwarded_capability_expiry(control, exit, scope)?;
        if scope.role_value()? != PreselectionObservationRole::Exit
            || control.node_id == exit.node_id
            || control.peer_id == exit.peer_id
            || control.public_key == exit.public_key
        {
            return Err(ProtocolError::InvalidField(
                "forwarded observation actor binding",
            ));
        }
        let prefix = self
            .upstream_network_prefix
            .as_ref()
            .ok_or(ProtocolError::InvalidField(
                "forwarded observation upstream_network_prefix",
            ))?;
        prefix.validate()?;
        if prefix.address_family != scope.address_family {
            return Err(ProtocolError::InvalidField(
                "forwarded observation address_family",
            ));
        }
        if nested.request_hash != self.request_hash
            || nested.challenge != self.challenge
            || nested.actor.as_ref() != Some(exit)
            || nested.scope.as_ref() != Some(scope)
        {
            return Err(ProtocolError::InvalidField(
                "forwarded observation nested binding",
            ));
        }
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "forwarded observation nonce")?;
        validate_lifetime(
            self.observed_at_ms,
            self.valid_until_ms,
            MAX_OBSERVATION_LIFETIME_MS,
        )?;
        if self.valid_until_ms > control.advertisement_expires_at_ms
            || self.valid_until_ms > control.capability_expires_at_ms
            || self.valid_until_ms > exit.advertisement_expires_at_ms
            || self.valid_until_ms > exit.capability_expires_at_ms
            || self.valid_until_ms > scope.policy_expires_at_ms
        {
            return Err(ProtocolError::InvalidLifetime);
        }
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        let control = required_actor(self.control.as_ref(), "forwarded observation control")?;
        validate_actor_envelope(
            control,
            self.observed_at_ms,
            self.valid_until_ms,
            &self.nonce,
            envelope,
            "forwarded observation envelope binding",
        )
    }
}

/// Hash one exact canonical unsigned preselection request.
///
/// The digest covers a fixed domain, an unsigned 32-bit byte length, and the
/// canonical request bytes. No batch or route identifier is added.
///
/// # Errors
///
/// Returns an error for malformed, non-canonical, oversized, or semantically
/// invalid request bytes.
pub fn preselection_observation_request_hash(
    encoded_request: &[u8],
) -> Result<[u8; KEY_LENGTH], ProtocolError> {
    let (_, digest) = decode_request(encoded_request)?;
    Ok(digest)
}

/// Hash one exact canonical signed actor receipt envelope.
///
/// The digest covers a fixed domain, an unsigned 32-bit byte length, and the
/// exact canonical envelope bytes. Signature verification is still mandatory.
///
/// # Errors
///
/// Returns an error for oversized, non-canonical, wrong-version, or wrong-type
/// envelope bytes.
pub fn preselection_observation_receipt_hash(
    encoded_receipt: &[u8],
) -> Result<[u8; KEY_LENGTH], ProtocolError> {
    ensure_size(
        encoded_receipt,
        MAX_PRESELECTION_RECEIPT_SIZE,
        "signed preselection receipt",
    )?;
    let envelope: SignedEnvelope =
        decode_canonical(encoded_receipt, MAX_PRESELECTION_RECEIPT_SIZE)?;
    if envelope.protocol_version != PROTOCOL_VERSION
        || envelope.message_type != ControlMessageType::PreselectionObservationReceipt as i32
    {
        return Err(ProtocolError::InvalidField(
            "preselection observation receipt hash",
        ));
    }
    hash_exact(RECEIPT_HASH_DOMAIN, encoded_receipt)
}

/// Verify a direct-relay receipt transactionally against its exact challenge.
///
/// The signed receipt is verified and inserted first. Any later request or
/// cross-binding failure rolls back only that newly accepted replay entry.
///
/// # Errors
///
/// Returns an error for invalid canonical bytes, signatures, replay, time,
/// identity, role, challenge, or scope bindings.
pub fn verify_direct_preselection_transcript(
    encoded_receipt: &[u8],
    encoded_request: &[u8],
    now_ms: u64,
    time_policy: TimePolicy,
    replay_cache: &mut ReplayCache,
) -> Result<VerifiedDirectPreselectionTranscript, ProtocolError> {
    ensure_size(
        encoded_receipt,
        MAX_PRESELECTION_RECEIPT_SIZE,
        "signed preselection receipt",
    )?;
    let receipt = verify_control_message::<PreselectionObservationReceipt>(
        encoded_receipt,
        now_ms,
        time_policy,
        replay_cache,
    )?;
    let receipt_sender = *receipt.sender_id();
    let receipt_nonce = *receipt.nonce();
    let checked = (|| {
        let (request, request_hash) = decode_request(encoded_request)?;
        validate_request_live(&request, now_ms)?;
        if required_scope(request.scope.as_ref())?.role_value()?
            != PreselectionObservationRole::Relay
            || request.forwarded_control.is_some()
            || !receipt_matches_request(receipt.message(), &request, request_hash)?
        {
            return Err(ProtocolError::InvalidField(
                "direct preselection observation binding",
            ));
        }
        Ok(request)
    })();
    match checked {
        Ok(request) => Ok(VerifiedDirectPreselectionTranscript {
            request,
            _receipt: receipt,
        }),
        Err(error) => {
            rollback_inserted(replay_cache, &receipt_sender, &receipt_nonce).and(Err(error))
        }
    }
}

/// Verify a control wrapper first, then its exact nested exit receipt.
///
/// Both replay entries are committed only when the request, actor, scope,
/// timestamps, nested bytes, and public prefix all cross-bind. A nested failure
/// rolls back only the already accepted outer entry.
///
/// # Errors
///
/// Returns an error for invalid canonical bytes, signatures, replay, time,
/// identity, role, challenge, prefix, nested-receipt, or scope bindings.
pub fn verify_forwarded_preselection_transcript(
    encoded_attestation: &[u8],
    encoded_request: &[u8],
    now_ms: u64,
    time_policy: TimePolicy,
    replay_cache: &mut ReplayCache,
) -> Result<VerifiedForwardedPreselectionTranscript, ProtocolError> {
    ensure_size(
        encoded_attestation,
        MAX_FORWARDED_ATTESTATION_SIZE,
        "signed forwarded preselection attestation",
    )?;
    let attestation = verify_control_message::<ForwardedPreselectionAttestation>(
        encoded_attestation,
        now_ms,
        time_policy,
        replay_cache,
    )?;
    let outer_sender = *attestation.sender_id();
    let outer_nonce = *attestation.nonce();
    let (request, request_hash) = match decode_request(encoded_request) {
        Ok(decoded) => decoded,
        Err(error) => {
            return rollback_inserted(replay_cache, &outer_sender, &outer_nonce).and(Err(error));
        }
    };
    if let Err(error) =
        forwarded_outer_matches_request(attestation.message(), &request, request_hash, now_ms)
    {
        return rollback_inserted(replay_cache, &outer_sender, &outer_nonce).and(Err(error));
    }
    let decoded_exit_receipt =
        match precheck_nested_exit_receipt(&attestation.message().signed_exit_receipt) {
            Ok(receipt) => receipt,
            Err(error) => {
                return rollback_inserted(replay_cache, &outer_sender, &outer_nonce)
                    .and(Err(error));
            }
        };
    if let Err(error) = forwarded_nested_matches_request(
        attestation.message(),
        &decoded_exit_receipt,
        &request,
        request_hash,
    ) {
        return rollback_inserted(replay_cache, &outer_sender, &outer_nonce).and(Err(error));
    }
    let expected_exit = match required_actor(
        attestation.message().exit.as_ref(),
        "forwarded observation exit",
    ) {
        Ok(exit) => exit,
        Err(error) => {
            return rollback_inserted(replay_cache, &outer_sender, &outer_nonce).and(Err(error));
        }
    };
    let exit_receipt = match verify_control_message::<PreselectionObservationReceipt>(
        &attestation.message().signed_exit_receipt,
        now_ms,
        time_policy,
        replay_cache,
    ) {
        Ok(receipt) => receipt,
        Err(error) => {
            return rollback_inserted(replay_cache, &outer_sender, &outer_nonce).and(Err(error));
        }
    };
    let inner_sender = *exit_receipt.sender_id();
    let inner_nonce = *exit_receipt.nonce();
    if exit_receipt.message() != &decoded_exit_receipt
        || exit_receipt.sender_id().as_slice() != expected_exit.node_id
        || exit_receipt.sender_public_key().as_slice() != expected_exit.public_key
    {
        rollback_pair_inserted(
            replay_cache,
            (&inner_sender, &inner_nonce),
            (&outer_sender, &outer_nonce),
        )?;
        return Err(ProtocolError::InvalidField(
            "forwarded decoded receipt invariant",
        ));
    }
    Ok(VerifiedForwardedPreselectionTranscript {
        request,
        _attestation: attestation,
        _exit_receipt: exit_receipt,
    })
}

/// Consume a verified direct transcript and bind it to one exact expected request.
///
/// The returned token remains fully opaque. In particular it exposes no signed
/// timestamps, remote observation time, prefix, identity, or local freshness.
///
/// # Errors
///
/// Returns an error when the expected request is malformed or is not the exact
/// request retained by the verified transcript.
pub fn consume_direct_preselection_transcript(
    transcript: VerifiedDirectPreselectionTranscript,
    canonical_expected_request: &[u8],
) -> Result<BoundDirectPreselectionTranscript, ProtocolError> {
    let (expected_request, _) = decode_request(canonical_expected_request)?;
    if transcript.request != expected_request {
        return Err(ProtocolError::InvalidField(
            "direct preselection transcript request",
        ));
    }
    Ok(BoundDirectPreselectionTranscript {
        _transcript: transcript,
    })
}

/// Consume a verified forwarded transcript and bind it to one exact expected request.
///
/// The returned token remains fully opaque. In particular it exposes neither
/// the retained native public `/24` or `/48` claim nor any signed timestamp,
/// identity, local origin, RTT, or freshness value.
///
/// # Errors
///
/// Returns an error when the expected request is malformed, is not the exact
/// request retained by the verified transcript.
pub fn consume_forwarded_preselection_transcript(
    transcript: VerifiedForwardedPreselectionTranscript,
    canonical_expected_request: &[u8],
) -> Result<BoundForwardedPreselectionTranscript, ProtocolError> {
    let (expected_request, _) = decode_request(canonical_expected_request)?;
    if transcript.request != expected_request {
        return Err(ProtocolError::InvalidField(
            "forwarded preselection transcript request",
        ));
    }
    Ok(BoundForwardedPreselectionTranscript {
        _transcript: transcript,
    })
}

/// Purpose-consume one exact bound direct-Relay transcript for private freshness minting.
///
/// The returned affine projection carries only the signed receipt validity ceiling. In
/// particular this terminal operation cannot recover the actor, request, signature, nonce,
/// remote observation time, response bytes, or any dispatch capability.
///
/// # Errors
///
/// Returns a detail-free field error if the crate-private verified-token invariant is broken.
pub fn consume_bound_direct_preselection_transcript_for_freshness(
    transcript: BoundDirectPreselectionTranscript,
) -> Result<DirectPreselectionFreshnessProof, ProtocolError> {
    let BoundDirectPreselectionTranscript {
        _transcript: verified,
    } = transcript;
    let VerifiedDirectPreselectionTranscript {
        request,
        _receipt: receipt,
    } = verified;
    let scope = required_scope(request.scope.as_ref())?;
    if scope.role_value()? != PreselectionObservationRole::Relay
        || request.forwarded_control.is_some()
        || receipt.message().valid_until_ms == 0
    {
        return Err(ProtocolError::InvalidField(
            "direct preselection freshness proof",
        ));
    }
    Ok(DirectPreselectionFreshnessProof {
        valid_until_ms: receipt.message().valid_until_ms,
    })
}

/// Purpose-consume one exact bound forwarded-Exit transcript for private freshness minting.
///
/// The returned affine projection carries only the earlier signed validity ceiling and the
/// endpoint-free public prefix in the authenticated control-Relay wrapper. It cannot recover any
/// identity, request, signature, nonce, full endpoint, response bytes, or dispatch capability.
///
/// # Errors
///
/// Returns a detail-free field error if the crate-private verified-token invariant is broken.
pub fn consume_bound_forwarded_preselection_transcript_for_freshness(
    transcript: BoundForwardedPreselectionTranscript,
) -> Result<ForwardedPreselectionFreshnessProof, ProtocolError> {
    let BoundForwardedPreselectionTranscript {
        _transcript: verified,
    } = transcript;
    let VerifiedForwardedPreselectionTranscript {
        request,
        _attestation: attestation,
        _exit_receipt: exit_receipt,
    } = verified;
    let scope = required_scope(request.scope.as_ref())?;
    let attestation_message = attestation.message();
    let prefix = attestation_message
        .upstream_network_prefix
        .as_ref()
        .ok_or(ProtocolError::InvalidField(
            "forwarded preselection freshness proof",
        ))?
        .validated_normalized()?;
    let expected_family = ObservationAddressFamily::try_from(scope.address_family)
        .map_err(|_| ProtocolError::InvalidField("forwarded preselection freshness proof"))?;
    let family_matches = matches!(
        (prefix.family(), expected_family),
        (
            volparossa_core::IpFamily::Ipv4,
            ObservationAddressFamily::Ipv4
        ) | (
            volparossa_core::IpFamily::Ipv6,
            ObservationAddressFamily::Ipv6
        )
    );
    let valid_until_ms = attestation_message
        .valid_until_ms
        .min(exit_receipt.message().valid_until_ms);
    if scope.role_value()? != PreselectionObservationRole::Exit
        || request.forwarded_control.is_none()
        || !family_matches
        || valid_until_ms == 0
    {
        return Err(ProtocolError::InvalidField(
            "forwarded preselection freshness proof",
        ));
    }
    Ok(ForwardedPreselectionFreshnessProof {
        valid_until_ms,
        upstream_network_prefix: prefix,
    })
}

fn decode_request(
    encoded_request: &[u8],
) -> Result<(PreselectionObservationRequest, [u8; KEY_LENGTH]), ProtocolError> {
    let request: PreselectionObservationRequest =
        decode_canonical(encoded_request, MAX_PRESELECTION_REQUEST_SIZE)?;
    request.validate()?;
    let length = u32::try_from(encoded_request.len()).map_err(|_| ProtocolError::Oversized {
        what: "preselection observation request",
        maximum: MAX_PRESELECTION_REQUEST_SIZE,
    })?;
    let mut hasher = Sha256::new();
    hasher.update(REQUEST_HASH_DOMAIN);
    hasher.update(length.to_be_bytes());
    hasher.update(encoded_request);
    Ok((request, hasher.finalize().into()))
}

fn receipt_matches_request(
    receipt: &PreselectionObservationReceipt,
    request: &PreselectionObservationRequest,
    request_hash: [u8; KEY_LENGTH],
) -> Result<bool, ProtocolError> {
    let actor = required_actor(request.actor.as_ref(), "preselection request actor")?;
    let scope = required_scope(request.scope.as_ref())?;
    Ok(receipt.request_hash == request_hash
        && receipt.challenge == request.challenge
        && receipt.actor.as_ref() == Some(actor)
        && receipt.scope.as_ref() == Some(scope)
        && receipt.observed_at_ms < receipt.valid_until_ms)
}

fn forwarded_outer_matches_request(
    attestation: &ForwardedPreselectionAttestation,
    request: &PreselectionObservationRequest,
    request_hash: [u8; KEY_LENGTH],
    now_ms: u64,
) -> Result<(), ProtocolError> {
    validate_request_live(request, now_ms)?;
    let exit = required_actor(request.actor.as_ref(), "preselection request actor")?;
    let control = request
        .forwarded_control
        .as_ref()
        .ok_or(ProtocolError::InvalidField(
            "forwarded preselection control",
        ))?;
    let scope = required_scope(request.scope.as_ref())?;
    if scope.role_value()? != PreselectionObservationRole::Exit
        || attestation.request_hash != request_hash
        || attestation.challenge != request.challenge
        || attestation.control.as_ref() != Some(control)
        || attestation.exit.as_ref() != Some(exit)
        || attestation.scope.as_ref() != Some(scope)
        || attestation.observed_at_ms >= attestation.valid_until_ms
    {
        return Err(ProtocolError::InvalidField(
            "forwarded preselection observation binding",
        ));
    }
    Ok(())
}

fn forwarded_nested_matches_request(
    attestation: &ForwardedPreselectionAttestation,
    exit_receipt: &PreselectionObservationReceipt,
    request: &PreselectionObservationRequest,
    request_hash: [u8; KEY_LENGTH],
) -> Result<(), ProtocolError> {
    if !receipt_matches_request(exit_receipt, request, request_hash)?
        || preselection_observation_receipt_hash(&attestation.signed_exit_receipt)?
            != attestation.exit_receipt_hash.as_slice()
    {
        return Err(ProtocolError::InvalidField(
            "forwarded preselection exit receipt binding",
        ));
    }
    Ok(())
}

fn required_actor<'a>(
    actor: Option<&'a PreselectionActorBinding>,
    field: &'static str,
) -> Result<&'a PreselectionActorBinding, ProtocolError> {
    let actor = actor.ok_or(ProtocolError::InvalidField(field))?;
    actor.validate(field)?;
    Ok(actor)
}

fn required_scope(
    scope: Option<&PreselectionObservationScope>,
) -> Result<&PreselectionObservationScope, ProtocolError> {
    let scope = scope.ok_or(ProtocolError::InvalidField("preselection scope"))?;
    scope.validate()?;
    Ok(scope)
}

fn require_nonzero<const LENGTH: usize>(
    value: &[u8],
    field: &'static str,
) -> Result<[u8; LENGTH], ProtocolError> {
    let value = fixed_array::<LENGTH>(value, field)?;
    if value.iter().all(|byte| *byte == 0) {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(value)
}

fn validate_lifetime(
    created_at_ms: u64,
    expires_at_ms: u64,
    maximum_lifetime_ms: u64,
) -> Result<(), ProtocolError> {
    let lifetime = expires_at_ms
        .checked_sub(created_at_ms)
        .ok_or(ProtocolError::InvalidLifetime)?;
    if created_at_ms == 0 || lifetime == 0 || lifetime > maximum_lifetime_ms {
        return Err(ProtocolError::InvalidLifetime);
    }
    Ok(())
}

fn validate_actor_scope_ceiling(
    actor: &PreselectionActorBinding,
    scope: &PreselectionObservationScope,
) -> Result<(), ProtocolError> {
    if actor.capability_expires_at_ms
        > actor
            .advertisement_expires_at_ms
            .min(scope.policy_expires_at_ms)
    {
        return Err(ProtocolError::InvalidField(
            "preselection actor capability expiry",
        ));
    }
    Ok(())
}

fn validate_direct_capability_expiry(
    actor: &PreselectionActorBinding,
    scope: &PreselectionObservationScope,
) -> Result<(), ProtocolError> {
    if actor.capability_expires_at_ms
        != actor
            .advertisement_expires_at_ms
            .min(scope.policy_expires_at_ms)
    {
        return Err(ProtocolError::InvalidField(
            "preselection direct capability expiry",
        ));
    }
    Ok(())
}

fn validate_forwarded_capability_expiry(
    control: &PreselectionActorBinding,
    exit: &PreselectionActorBinding,
    scope: &PreselectionObservationScope,
) -> Result<(), ProtocolError> {
    validate_direct_capability_expiry(control, scope)?;
    if exit.capability_expires_at_ms
        != exit
            .advertisement_expires_at_ms
            .min(scope.policy_expires_at_ms)
            .min(control.capability_expires_at_ms)
    {
        return Err(ProtocolError::InvalidField(
            "preselection forwarded capability expiry",
        ));
    }
    Ok(())
}

fn validate_request_live(
    request: &PreselectionObservationRequest,
    now_ms: u64,
) -> Result<(), ProtocolError> {
    if now_ms < request.created_at_ms {
        return Err(ProtocolError::NotYetValid);
    }
    if now_ms >= request.expires_at_ms {
        return Err(ProtocolError::Expired);
    }
    Ok(())
}

fn ensure_size(encoded: &[u8], maximum: usize, what: &'static str) -> Result<(), ProtocolError> {
    if encoded.len() > maximum {
        return Err(ProtocolError::Oversized { what, maximum });
    }
    Ok(())
}

fn hash_exact(domain: &[u8], encoded: &[u8]) -> Result<[u8; KEY_LENGTH], ProtocolError> {
    let length = u32::try_from(encoded.len()).map_err(|_| ProtocolError::Oversized {
        what: "preselection transcript member",
        maximum: MAX_CONTROL_MESSAGE_SIZE,
    })?;
    let mut hasher = Sha256::new();
    hasher.update(domain);
    hasher.update(length.to_be_bytes());
    hasher.update(encoded);
    Ok(hasher.finalize().into())
}

fn rollback_inserted(
    replay_cache: &mut ReplayCache,
    sender_id: &[u8; KEY_LENGTH],
    nonce: &[u8; NONCE_LENGTH],
) -> Result<(), ProtocolError> {
    if !replay_cache.rollback(sender_id, nonce) {
        return Err(ProtocolError::InvalidField(
            "preselection replay rollback invariant",
        ));
    }
    Ok(())
}

fn rollback_pair_inserted(
    replay_cache: &mut ReplayCache,
    inner: (&[u8; KEY_LENGTH], &[u8; NONCE_LENGTH]),
    outer: (&[u8; KEY_LENGTH], &[u8; NONCE_LENGTH]),
) -> Result<(), ProtocolError> {
    let inner_removed = replay_cache.rollback(inner.0, inner.1);
    let outer_removed = replay_cache.rollback(outer.0, outer.1);
    if !inner_removed || !outer_removed {
        return Err(ProtocolError::InvalidField(
            "preselection pair rollback invariant",
        ));
    }
    Ok(())
}

fn validate_actor_envelope(
    actor: &PreselectionActorBinding,
    observed_at_ms: u64,
    valid_until_ms: u64,
    nonce: &[u8],
    envelope: &SignedEnvelope,
    field: &'static str,
) -> Result<(), ProtocolError> {
    if envelope.sender_id != actor.node_id
        || envelope.sender_public_key != actor.public_key
        || envelope.timestamp_ms != observed_at_ms
        || envelope.expires_at_ms != valid_until_ms
        || envelope.nonce != nonce
    {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn precheck_nested_exit_receipt(
    encoded: &[u8],
) -> Result<PreselectionObservationReceipt, ProtocolError> {
    let envelope: SignedEnvelope = decode_canonical(encoded, MAX_PRESELECTION_RECEIPT_SIZE)?;
    if envelope.protocol_version != PROTOCOL_VERSION
        || envelope.message_type != ControlMessageType::PreselectionObservationReceipt as i32
    {
        return Err(ProtocolError::InvalidField(
            "forwarded observation signed_exit_receipt",
        ));
    }
    let receipt: PreselectionObservationReceipt =
        decode_canonical(&envelope.payload, MAX_PRESELECTION_RECEIPT_SIZE)?;
    receipt.validate()?;
    receipt.validate_envelope(&envelope)?;
    Ok(receipt)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;

    use super::*;
    use crate::{sign_control_message, verify_control_message};

    fn signed_receipt(key_byte: u8, peer_byte: u8, nonce_byte: u8) -> (Vec<u8>, SigningKey) {
        let key = SigningKey::from_bytes(&[key_byte; 32]);
        let public_key = key.verifying_key().to_bytes();
        let actor = PreselectionActorBinding {
            node_id: node_id_from_public_key(&public_key).to_vec(),
            peer_id: vec![peer_byte; 38],
            public_key: public_key.to_vec(),
            advertisement_sequence: u64::from(peer_byte),
            advertisement_expires_at_ms: 1_000,
            advertisement_payload_hash: vec![peer_byte; 32],
            capability_expires_at_ms: 1_000,
        };
        let receipt = PreselectionObservationReceipt {
            request_hash: vec![3; 32],
            challenge: vec![4; 32],
            actor: Some(actor),
            scope: Some(PreselectionObservationScope {
                role: PreselectionObservationRole::Relay as i32,
                transport: Transport::TcpMptcp as i32,
                address_family: ObservationAddressFamily::Ipv4 as i32,
                policy_version: 1,
                policy_hash: vec![5; 32],
                policy_expires_at_ms: 1_000,
            }),
            observed_at_ms: 100,
            valid_until_ms: 200,
            nonce: vec![nonce_byte; 32],
        };
        let signed = sign_control_message(
            &receipt,
            &key,
            100,
            200,
            [nonce_byte; 32],
            TimePolicy::default(),
        )
        .unwrap();
        (signed, key)
    }

    #[test]
    fn pair_rollback_attempts_outer_after_missing_inner() {
        let (signed_inner, _) = signed_receipt(101, 11, 21);
        let (signed_outer, _) = signed_receipt(102, 12, 22);
        let mut cache = ReplayCache::new(4).unwrap();
        let inner = verify_control_message::<PreselectionObservationReceipt>(
            &signed_inner,
            150,
            TimePolicy::default(),
            &mut cache,
        )
        .unwrap();
        let outer = verify_control_message::<PreselectionObservationReceipt>(
            &signed_outer,
            150,
            TimePolicy::default(),
            &mut cache,
        )
        .unwrap();
        assert_eq!(cache.len(), 2);
        assert!(cache.rollback(inner.sender_id(), inner.nonce()));

        assert!(matches!(
            rollback_pair_inserted(
                &mut cache,
                (inner.sender_id(), inner.nonce()),
                (outer.sender_id(), outer.nonce()),
            ),
            Err(ProtocolError::InvalidField(
                "preselection pair rollback invariant"
            ))
        ));
        assert!(
            cache.is_empty(),
            "outer rollback must run even when inner removal reports false"
        );
    }
}
