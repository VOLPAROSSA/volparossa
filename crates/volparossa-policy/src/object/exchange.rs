//! Bounded original evidence/proposal exchange, not semantic evidence verification.
//!
//! A decoded request only proves canonical shape and byte-hash binding. Authorities
//! must independently replay the assessment bundle and check the proposal's meaning,
//! selected subject, current policy epoch and original expiry before signing.

use prost::Message;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use super::{MAX_OBJECT_DECISION_BYTES, SignedObjectDecision};
use crate::{
    PolicyError,
    wire::{decode_canonical, encode_canonical},
};

/// Maximum original opaque four-transcript assessment package accepted for exchange.
pub const MAX_ASSESSMENT_BUNDLE_BYTES: usize = 2 * 1024 * 1024;
/// Complete request limit, including both independently bounded fields and framing.
pub const MAX_DECISION_REQUEST_BYTES: usize =
    MAX_ASSESSMENT_BUNDLE_BYTES + MAX_OBJECT_DECISION_BYTES + 32;

/// Original evidence and exactly unsigned proposal; no paths, signer keys or verdict overrides.
#[derive(Clone, Debug)]
pub struct DecisionRequest {
    assessment_bundle: Vec<u8>,
    proposal: Vec<u8>,
}

impl DecisionRequest {
    /// Bind opaque original evidence bytes to an existing canonical unsigned proposal.
    ///
    /// # Errors
    /// Rejects empty/oversized fields, noncanonical or endorsed proposals and a
    /// package hash different from the proposal's original evidence digest.
    pub fn new(assessment_bundle: Vec<u8>, proposal: Vec<u8>) -> Result<Self, PolicyError> {
        validate(&assessment_bundle, &proposal)?;
        Ok(Self {
            assessment_bundle,
            proposal,
        })
    }

    /// Decode one bounded canonical version-1 request without replaying its evidence.
    ///
    /// # Errors
    /// Rejects oversized bytes before protobuf decoding, unknown fields/version,
    /// noncanonical encoding, invalid unsigned proposal or mismatched evidence bytes.
    pub fn decode(bytes: &[u8]) -> Result<Self, PolicyError> {
        if bytes.is_empty() || bytes.len() > MAX_DECISION_REQUEST_BYTES {
            return Err(PolicyError::Oversized {
                what: "object decision request",
                maximum: MAX_DECISION_REQUEST_BYTES,
            });
        }
        let wire: RequestProto = decode_canonical(bytes, MAX_DECISION_REQUEST_BYTES)?;
        if wire.version != 1 {
            return Err(PolicyError::UnsupportedSchemaVersion(wire.version));
        }
        Self::new(wire.assessment_bundle, wire.proposal)
    }

    /// Encode the unchanged request canonically; no signature or nonce is generated.
    ///
    /// # Errors
    /// Rejects an invalid field binding or the complete encoded request limit.
    pub fn encode(&self) -> Result<Vec<u8>, PolicyError> {
        validate(&self.assessment_bundle, &self.proposal)?;
        encode_canonical(
            &RequestProto {
                version: 1,
                assessment_bundle: self.assessment_bundle.clone(),
                proposal: self.proposal.clone(),
            },
            MAX_DECISION_REQUEST_BYTES,
        )
    }

    /// Return original opaque evidence bytes; decoding has not established their truth.
    #[must_use]
    pub fn assessment_bundle(&self) -> &[u8] {
        &self.assessment_bundle
    }

    /// Return the exact original canonical unsigned object-decision envelope.
    #[must_use]
    pub fn proposal(&self) -> &[u8] {
        &self.proposal
    }
}

fn validate(bundle: &[u8], proposal: &[u8]) -> Result<(), PolicyError> {
    if bundle.is_empty() || bundle.len() > MAX_ASSESSMENT_BUNDLE_BYTES {
        return Err(PolicyError::Oversized {
            what: "object assessment bundle",
            maximum: MAX_ASSESSMENT_BUNDLE_BYTES,
        });
    }
    // The decoder bounds proposal bytes before parsing. Re-encoding from the
    // immutable body explicitly excludes even a valid pre-existing endorsement.
    let signed = SignedObjectDecision::decode(proposal)?;
    if SignedObjectDecision::new(signed.body().clone())?.encode()? != proposal {
        return Err(PolicyError::InvalidField(
            "unsigned object proposal required",
        ));
    }
    let hash: [u8; 32] = Sha256::digest(bundle).into();
    if hash.ct_eq(&signed.body().evidence_sha256).unwrap_u8() != 1 {
        return Err(PolicyError::ManifestHashMismatch);
    }
    Ok(())
}

#[derive(Clone, PartialEq, Message)]
struct RequestProto {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    assessment_bundle: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    proposal: Vec<u8>,
}
