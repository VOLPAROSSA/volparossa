//! Exact native-object decisions under independently configured policy authority.
//!
//! These signatures do not authorize destinations, adopt model/provider keys, or
//! prove legal or semantic correctness. Activation and durable revision floors
//! remain the caller's responsibility; verification always checks current time.

pub mod exchange;

use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use prost::Message;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use crate::{
    MAX_SIGNATURES, ManifestSpec, PolicyError, TrustStore, VerificationPolicy, VerifiedManifest,
    body_from_spec, fixed_bytes, maintainer_id, validate_time_order, validate_verification_context,
    wire::{decode_canonical, encode_canonical},
};

/// Maximum complete object-decision envelope, including all endorsements.
pub const MAX_OBJECT_DECISION_BYTES: usize = 8 * 1024;
const MAX_BODY_BYTES: usize = 1024;
const VERSION: u32 = 1;
const NATIVE_OBJECT_DECISION: u32 = 1;
const SIGNATURE_DOMAIN: &[u8] = b"VOLPAROSSA/native-object-decision/signature/v1\0";

/// A single original publication, never a domain or an arbitrary chunk selector.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Ord, PartialOrd, Hash)]
pub struct ObjectSubject {
    /// Independently selected original native publisher's Ed25519 key.
    pub publisher_key: [u8; 32],
    /// SHA-256 identity of the exact original signed native manifest.
    pub manifest_id: [u8; 32],
    /// Whole-object SHA-256 committed by that original manifest.
    pub object_sha256: [u8; 32],
}

/// Scoped outcome; uncertainty is explicit and is never an implicit allowance.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum ObjectOutcome {
    /// Allow this exact subject within the configured object-policy scope.
    Allow = 1,
    /// Deny this exact subject within the configured object-policy scope.
    Deny = 2,
    /// No supported determination; callers must not interpret this as Allow.
    Undetermined = 3,
}

/// Immutable semantic body shared by every authority endorsement.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ObjectDecision {
    /// Exact current threshold-verified destination-policy body hash/epoch.
    pub policy_hash: [u8; 32],
    /// Exact version of that current policy, not a new membership authority.
    pub policy_version: u64,
    /// Monotone revision within the authority/subject scope, enforced durably by the caller.
    pub decision_revision: u64,
    /// Original native object to which this decision applies.
    pub subject: ObjectSubject,
    /// Exact versioned principle framework digest.
    pub framework_sha256: [u8; 32],
    /// Digest of the original replay-verified assessment evidence.
    pub evidence_sha256: [u8; 32],
    /// The signed scoped outcome.
    pub outcome: ObjectOutcome,
    /// Original creation/activation time in Unix milliseconds.
    pub issued_at_ms: u64,
    /// Exclusive expiry, never later than the current policy's original expiry.
    pub expires_at_ms: u64,
    /// Nonzero caller-generated cryptographically random nonce, retained on merge/replay.
    pub nonce: [u8; 32],
}

#[derive(Clone, Debug)]
struct Endorsement {
    key_id: [u8; 32],
    signature: [u8; 64],
}

/// Canonical proposal/endorsements; this type alone confers no authority.
#[derive(Clone, Debug)]
pub struct SignedObjectDecision {
    body: ObjectDecision,
    signatures: Vec<Endorsement>,
}

impl SignedObjectDecision {
    /// Construct an unsigned proposal without changing its timestamps or nonce.
    ///
    /// # Errors
    /// Rejects invalid subject keys, zero identities/revisions or invalid time ordering.
    pub fn new(body: ObjectDecision) -> Result<Self, PolicyError> {
        validate_body(&body)?;
        Ok(Self {
            body,
            signatures: Vec::new(),
        })
    }

    /// Decode bounded canonical bytes without trusting their endorsements.
    ///
    /// # Errors
    /// Rejects unknown fields/versions/types, malformed identities, hash mismatch,
    /// duplicate or unsorted signers, and oversized/noncanonical encodings.
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        let wire: EnvelopeProto = decode_canonical(bytes, MAX_OBJECT_DECISION_BYTES)?;
        let body = wire
            .body
            .ok_or(PolicyError::InvalidField("object decision body"))?;
        let body_bytes = encode_canonical(&body, MAX_BODY_BYTES)?;
        let expected: [u8; 32] = Sha256::digest(&body_bytes).into();
        if fixed_bytes::<32>(&wire.body_hash, "object decision hash")?
            .ct_eq(&expected)
            .unwrap_u8()
            != 1
        {
            return Err(PolicyError::ManifestHashMismatch);
        }
        if wire.signatures.len() > MAX_SIGNATURES {
            return Err(PolicyError::TooManyItems {
                what: "object decision signatures",
                maximum: MAX_SIGNATURES,
            });
        }
        let value = Self {
            body: semantic(&body)?,
            signatures: wire
                .signatures
                .into_iter()
                .map(|signature| {
                    Ok(Endorsement {
                        key_id: fixed_bytes(&signature.key_id, "object signer ID")?,
                        signature: fixed_bytes(&signature.signature, "object signature")?,
                    })
                })
                .collect::<Result<_, PolicyError>>()?,
        };
        validate_signatures(&value.signatures)?;
        Ok(value)
    }

    /// Return the unique original body, without exposing a mutation capability.
    #[must_use]
    pub const fn body(&self) -> &ObjectDecision {
        &self.body
    }

    /// Encode the original body and sorted endorsements canonically.
    ///
    /// # Errors
    /// Rejects invalid fields/signers or a bound exceeded during encoding.
    pub fn encode(&self) -> Result<Vec<u8>, PolicyError> {
        validate_body(&self.body)?;
        validate_signatures(&self.signatures)?;
        let body = wire_body(&self.body);
        let body_hash = Sha256::digest(encode_canonical(&body, MAX_BODY_BYTES)?).to_vec();
        encode_canonical(
            &EnvelopeProto {
                body: Some(body),
                body_hash,
                signatures: self
                    .signatures
                    .iter()
                    .map(|signature| SignatureProto {
                        key_id: signature.key_id.to_vec(),
                        signature: signature.signature.to_vec(),
                    })
                    .collect(),
            },
            MAX_OBJECT_DECISION_BYTES,
        )
    }

    /// Endorse precisely this immutable proposal. Trust is checked separately by the verifier.
    ///
    /// # Errors
    /// Rejects a repeated signer or too many endorsements; never renews the proposal.
    pub fn endorse(&mut self, key: &SigningKey) -> Result<(), PolicyError> {
        let key_id = maintainer_id(&key.verifying_key().to_bytes());
        let input = signature_input(&self.body, &key_id)?;
        let signature = Endorsement {
            key_id,
            signature: key.sign(&input).to_bytes(),
        };
        self.merge_signatures(std::slice::from_ref(&signature))
    }

    /// Merge endorsements only for an exactly identical body, without modifying either lease.
    ///
    /// # Errors
    /// Rejects different bodies, repeated signers or a combined bound violation.
    pub fn merge(&mut self, other: &Self) -> Result<(), PolicyError> {
        if self.body != other.body {
            return Err(PolicyError::InvalidField("object decision merge body"));
        }
        self.merge_signatures(&other.signatures)
    }

    fn merge_signatures(&mut self, added: &[Endorsement]) -> Result<(), PolicyError> {
        if self.signatures.len().saturating_add(added.len()) > MAX_SIGNATURES {
            return Err(PolicyError::TooManyItems {
                what: "object decision signatures",
                maximum: MAX_SIGNATURES,
            });
        }
        let mut combined = self.signatures.clone();
        combined.extend_from_slice(added);
        combined.sort_unstable_by_key(|signature| signature.key_id);
        validate_signatures(&combined)?;
        self.signatures = combined;
        Ok(())
    }
}

/// Active-at-verification exact-object decision, not a general content or legal authority.
#[derive(Clone, Debug)]
pub struct VerifiedObjectDecision {
    body: ObjectDecision,
    decision_hash: [u8; 32],
}

impl VerifiedObjectDecision {
    /// Return the exact verified body; the caller must recheck expiry before use.
    #[must_use]
    pub const fn body(&self) -> &ObjectDecision {
        &self.body
    }

    /// Digest of the canonical immutable body, independent of detachable endorsements.
    #[must_use]
    pub const fn decision_hash(&self) -> &[u8; 32] {
        &self.decision_hash
    }
}

/// Verify an object decision under the separately selected current authority and policy epoch.
///
/// No signer, trust key, threshold, original source permission or global membership is
/// learned from the envelope. The caller independently binds the subject to its native
/// manifest, and maintains the durable per-subject revision/hash floor.
///
/// # Errors
/// Rejects noncanonical bytes, wrong authority/epoch, bad or untrusted signatures,
/// insufficient quorum, expiry and any attempted lease extension past the current policy.
pub fn verify_object_decision(
    bytes: &[u8],
    now_ms: u64,
    trust: &TrustStore,
    policy: VerificationPolicy,
    current: &VerifiedManifest,
) -> Result<VerifiedObjectDecision, PolicyError> {
    let signed = verify_signed_at(bytes, now_ms, trust, policy, current)?;
    let required = policy
        .minimum_signatures()
        .max(current.required_signatures());
    if signed.signatures.len() < required {
        return Err(PolicyError::InsufficientSignatures {
            required,
            valid: signed.signatures.len(),
        });
    }
    let decision_hash = object_body_hash(&signed.body)?;
    Ok(VerifiedObjectDecision {
        body: signed.body,
        decision_hash,
    })
}

/// One selected authority's verified endorsement, explicitly not a verified quorum.
///
/// This type cannot activate a decision. Merge original endorsements and use
/// [`verify_object_decision`] before claiming threshold authorization.
#[derive(Clone, Debug)]
pub struct VerifiedObjectEndorsement {
    body: ObjectDecision,
    decision_hash: [u8; 32],
    signer: VerifyingKey,
}

impl VerifiedObjectEndorsement {
    /// Original endorsed body; no evidence replay or semantic correctness is implied.
    #[must_use]
    pub const fn body(&self) -> &ObjectDecision {
        &self.body
    }

    /// Digest of that original canonical body, independent of its endorsement.
    #[must_use]
    pub const fn decision_hash(&self) -> &[u8; 32] {
        &self.decision_hash
    }

    /// The exact independently selected existing maintainer that signed this body.
    #[must_use]
    pub const fn signer(&self) -> &VerifyingKey {
        &self.signer
    }
}

/// Verify exactly one selected maintainer's endorsement under the current authority.
///
/// All existing epoch, trust-mode, lifetime and signature checks still apply.
/// This does not lower the quorum policy or produce a [`VerifiedObjectDecision`].
/// The caller must compare the body with its exact request and replay the evidence.
///
/// # Errors
/// Rejects zero/multiple endorsements, a different/untrusted signer, noncanonical
/// bytes, wrong epoch, invalid signatures, expiry or attempted lease extension.
pub fn verify_object_endorsement(
    bytes: &[u8],
    now_ms: u64,
    expected_signer: &VerifyingKey,
    trust: &TrustStore,
    policy: VerificationPolicy,
    current: &VerifiedManifest,
) -> Result<VerifiedObjectEndorsement, PolicyError> {
    let signed = verify_signed_at(bytes, now_ms, trust, policy, current)?;
    let [endorsement] = signed.signatures.as_slice() else {
        return Err(PolicyError::InvalidField("exactly one object endorsement"));
    };
    if endorsement.key_id != maintainer_id(&expected_signer.to_bytes()) {
        return Err(PolicyError::UntrustedSigner);
    }
    let decision_hash = object_body_hash(&signed.body)?;
    Ok(VerifiedObjectEndorsement {
        body: signed.body,
        decision_hash,
        signer: *expected_signer,
    })
}

fn object_body_hash(body: &ObjectDecision) -> Result<[u8; 32], PolicyError> {
    Ok(Sha256::digest(encode_canonical(&wire_body(body), MAX_BODY_BYTES)?).into())
}

// Shared checks deliberately do not mint either authorization result type.
// The public entry points independently enforce full quorum or exactly one selected signer.
fn verify_signed_at(
    bytes: &[u8],
    now_ms: u64,
    trust: &TrustStore,
    policy: VerificationPolicy,
    current: &VerifiedManifest,
) -> Result<SignedObjectDecision, PolicyError> {
    validate_verification_context(trust, policy)?;
    current.ensure_active_at(now_ms)?;
    verify_current_authority(current, trust)?;
    let signed = SignedObjectDecision::decode(bytes)?;
    let body = &signed.body;
    if body.policy_hash != *current.policy_hash()
        || body.policy_version != current.manifest_version()
    {
        return Err(PolicyError::InvalidField("object decision policy epoch"));
    }
    let lifetime = validate_time_order(body.issued_at_ms, body.issued_at_ms, body.expires_at_ms)?;
    if lifetime > policy.maximum_lifetime_ms()
        || body.issued_at_ms < current.valid_from_ms()
        || body.expires_at_ms > current.expires_at_ms()
    {
        return Err(PolicyError::InvalidTimeWindow);
    }
    if body.issued_at_ms > now_ms {
        return Err(PolicyError::NotYetValid);
    }
    if body.expires_at_ms <= now_ms {
        return Err(PolicyError::Expired);
    }
    if signed.signatures.len() > trust.maintainers().len() {
        return Err(PolicyError::TooManyItems {
            what: "object decision signatures",
            maximum: trust.maintainers().len(),
        });
    }
    for signature in &signed.signatures {
        let maintainer = trust
            .find_key(&signature.key_id)
            .ok_or(PolicyError::UntrustedSigner)?;
        maintainer
            .verifying_key()
            .verify_strict(
                &signature_input(body, &signature.key_id)?,
                &Signature::from_bytes(&signature.signature),
            )
            .map_err(|_| PolicyError::InvalidSignature)?;
    }
    Ok(signed)
}

fn verify_current_authority(
    current: &VerifiedManifest,
    trust: &TrustStore,
) -> Result<(), PolicyError> {
    // VerifiedManifest retains its full semantic body, but no separate trusted-key list.
    // Reconstructing with the independently supplied trust set binds that set to the
    // original current body hash, without widening VerifiedManifest or its wire format.
    let spec = ManifestSpec {
        manifest_version: current.manifest_version,
        minimum_protocol_version: current.minimum_protocol_version,
        issued_at_ms: current.issued_at_ms,
        valid_from_ms: current.valid_from_ms,
        expires_at_ms: current.expires_at_ms,
        required_signatures: current.required_signatures,
        rules: current.rules.clone(),
    };
    let encoded = encode_canonical(
        &body_from_spec(&spec, trust)?,
        crate::MAX_MANIFEST_BODY_BYTES,
    )?;
    let hash: [u8; 32] = Sha256::digest(encoded).into();
    if hash != *current.policy_hash() {
        return Err(PolicyError::TrustRootMismatch);
    }
    Ok(())
}

fn validate_body(body: &ObjectDecision) -> Result<(), PolicyError> {
    if body.policy_version == 0
        || body.decision_revision == 0
        || [
            &body.policy_hash,
            &body.subject.publisher_key,
            &body.subject.manifest_id,
            &body.subject.object_sha256,
            &body.framework_sha256,
            &body.evidence_sha256,
            &body.nonce,
        ]
        .iter()
        .any(|value| **value == [0; 32])
        || VerifyingKey::from_bytes(&body.subject.publisher_key).is_err()
    {
        return Err(PolicyError::InvalidField("object decision identity"));
    }
    validate_time_order(body.issued_at_ms, body.issued_at_ms, body.expires_at_ms)?;
    Ok(())
}

fn validate_signatures(signatures: &[Endorsement]) -> Result<(), PolicyError> {
    if signatures.len() > MAX_SIGNATURES {
        return Err(PolicyError::TooManyItems {
            what: "object decision signatures",
            maximum: MAX_SIGNATURES,
        });
    }
    for pair in signatures.windows(2) {
        if pair[0].key_id == pair[1].key_id {
            return Err(PolicyError::DuplicateItem("object decision signer"));
        }
        if pair[0].key_id > pair[1].key_id {
            return Err(PolicyError::NonCanonicalSemantic("object signer ordering"));
        }
    }
    Ok(())
}

fn signature_input(body: &ObjectDecision, signer: &[u8; 32]) -> Result<Vec<u8>, PolicyError> {
    let bytes = encode_canonical(&wire_body(body), MAX_BODY_BYTES)?;
    let hash = Sha256::digest(&bytes);
    let mut input = Vec::with_capacity(SIGNATURE_DOMAIN.len() + 64 + bytes.len());
    input.extend_from_slice(SIGNATURE_DOMAIN);
    input.extend_from_slice(signer);
    input.extend_from_slice(&hash);
    input.extend_from_slice(&bytes);
    Ok(input)
}

#[derive(Clone, PartialEq, Message)]
struct EnvelopeProto {
    #[prost(message, optional, tag = "1")]
    body: Option<BodyProto>,
    #[prost(bytes = "vec", tag = "2")]
    body_hash: Vec<u8>,
    #[prost(message, repeated, tag = "3")]
    signatures: Vec<SignatureProto>,
}

#[derive(Clone, PartialEq, Message)]
struct SignatureProto {
    #[prost(bytes = "vec", tag = "1")]
    key_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    signature: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct BodyProto {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(uint32, tag = "2")]
    message_type: u32,
    #[prost(bytes = "vec", tag = "3")]
    policy_hash: Vec<u8>,
    #[prost(uint64, tag = "4")]
    policy_version: u64,
    #[prost(uint64, tag = "5")]
    decision_revision: u64,
    #[prost(bytes = "vec", tag = "6")]
    publisher_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    manifest_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    object_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    framework_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "10")]
    evidence_sha256: Vec<u8>,
    #[prost(enumeration = "ObjectOutcome", tag = "11")]
    outcome: i32,
    #[prost(uint64, tag = "12")]
    issued_at_ms: u64,
    #[prost(uint64, tag = "13")]
    expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "14")]
    nonce: Vec<u8>,
}

fn wire_body(body: &ObjectDecision) -> BodyProto {
    BodyProto {
        version: VERSION,
        message_type: NATIVE_OBJECT_DECISION,
        policy_hash: body.policy_hash.to_vec(),
        policy_version: body.policy_version,
        decision_revision: body.decision_revision,
        publisher_key: body.subject.publisher_key.to_vec(),
        manifest_id: body.subject.manifest_id.to_vec(),
        object_sha256: body.subject.object_sha256.to_vec(),
        framework_sha256: body.framework_sha256.to_vec(),
        evidence_sha256: body.evidence_sha256.to_vec(),
        outcome: body.outcome as i32,
        issued_at_ms: body.issued_at_ms,
        expires_at_ms: body.expires_at_ms,
        nonce: body.nonce.to_vec(),
    }
}

fn semantic(body: &BodyProto) -> Result<ObjectDecision, PolicyError> {
    if body.version != VERSION {
        return Err(PolicyError::UnsupportedSchemaVersion(body.version));
    }
    if body.message_type != NATIVE_OBJECT_DECISION {
        return Err(PolicyError::InvalidField("object decision type"));
    }
    let decision = ObjectDecision {
        policy_hash: fixed_bytes(&body.policy_hash, "object policy hash")?,
        policy_version: body.policy_version,
        decision_revision: body.decision_revision,
        subject: ObjectSubject {
            publisher_key: fixed_bytes(&body.publisher_key, "object publisher")?,
            manifest_id: fixed_bytes(&body.manifest_id, "object manifest")?,
            object_sha256: fixed_bytes(&body.object_sha256, "object bytes hash")?,
        },
        framework_sha256: fixed_bytes(&body.framework_sha256, "object framework")?,
        evidence_sha256: fixed_bytes(&body.evidence_sha256, "object evidence")?,
        outcome: ObjectOutcome::try_from(body.outcome)
            .map_err(|_| PolicyError::InvalidField("object outcome"))?,
        issued_at_ms: body.issued_at_ms,
        expires_at_ms: body.expires_at_ms,
        nonce: fixed_bytes(&body.nonce, "object nonce")?,
    };
    validate_body(&decision)?;
    Ok(decision)
}

#[cfg(test)]
mod tests;
