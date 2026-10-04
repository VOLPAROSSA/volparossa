//! Explicit public code generation, never a private conversation or tool grant.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::{ComputeError, DocumentDataset, DocumentQuestion, MAX_DATASET_BYTES, document};
use crate::{CHUNK_BYTES, ChunkId, model_profile::ModelProfile};

/// Separate signed purpose; ordinary document questions do not grant this operation.
pub const CODE_PROPOSAL_CONTENT_TYPE: &str =
    "application/vnd.volparossa.agent-code-proposal.v6+json";

/// A proposal is inert source text, not permission to write or execute it.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum CodeProposalOutputContract {
    /// Exact model text proposed as the replacement of the owner's selected source.
    SingleFileReplacementV1,
}

/// One explicitly public, whole-source coding task with a pinned model profile.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct CodeProposalDataset {
    /// Exactly six; existing document/training encodings remain unchanged.
    pub version: u32,
    /// Exactly `public`; no implicit export from a private conversation.
    pub visibility: String,
    /// Exactly `code_proposal`, independent of the natural-language instruction.
    pub purpose: String,
    /// Explicit publisher declaration, using the original document license set.
    pub license: String,
    /// Exact admitted Qwen profile, also bound by the frozen job model identity.
    pub model_profile: ModelProfile,
    /// Original whole-source text/plain manifest from the independently trusted publisher.
    pub source_manifest_hex: String,
    /// Exactly one question and complete source; no path, history or tool authority.
    pub inference: Vec<DocumentQuestion>,
    /// Fixed, non-executable output contract.
    pub output_contract: CodeProposalOutputContract,
}

impl CodeProposalDataset {
    fn document(&self) -> DocumentDataset {
        DocumentDataset {
            version: 2,
            visibility: self.visibility.clone(),
            license: self.license.clone(),
            source_manifest_hex: self.source_manifest_hex.clone(),
            inference: self.inference.clone(),
        }
    }

    /// Check strict shape and whole-context bounds, without granting publisher trust.
    ///
    /// # Errors
    /// Rejects private inputs, unsupported purpose/model, non-singleton or partial ranges.
    pub fn validate_shape(&self) -> Result<(), ComputeError> {
        if self.version != 6
            || self.purpose != "code_proposal"
            || !self.model_profile.is_native_conversation()
            || self.inference.len() != 1
            || self.inference[0].start != 0
        {
            return Err(ComputeError::Invalid);
        }
        self.document().validate_shape()
    }

    pub(super) fn verify_source(
        &self,
        publisher: &VerifyingKey,
        now: u64,
        package_expiry: u64,
    ) -> Result<(), ComputeError> {
        self.validate_shape()?;
        self.document()
            .verify_source(publisher, now, package_expiry)?;
        let original = document::decode_source_manifest(&self.source_manifest_hex)?
            .verify(publisher, now)
            .map_err(|_| ComputeError::Authentication)?;
        let bytes = self.inference[0].context.as_bytes();
        if original.length() != bytes.len() as u64
            || original.object_sha256() != &<[u8; 32]>::from(Sha256::digest(bytes))
            || original.chunks().len() != bytes.chunks(CHUNK_BYTES).len()
            || bytes
                .chunks(CHUNK_BYTES)
                .zip(original.chunks())
                .any(|(actual, expected)| {
                    expected.id() != &ChunkId::digest(actual)
                        || expected.length() as usize != actual.len()
                })
        {
            return Err(ComputeError::Authentication);
        }
        Ok(())
    }

    pub(super) fn derive_selected(&self, rows: &[u16]) -> Result<String, ComputeError> {
        if rows != [0] {
            return Err(ComputeError::Invalid);
        }
        serde_json::to_string(self).map_err(|_| ComputeError::Invalid)
    }
}

/// Strict broker shape admission; signature, publisher and whole-source checks are separate.
///
/// # Errors
/// Rejects excessive input, unknown/duplicate fields or anything but one public code task.
pub fn validate_code_proposal_json(json: &str, expected_rows: usize) -> Result<(), ComputeError> {
    if json.is_empty() || json.len() > MAX_DATASET_BYTES || expected_rows != 1 {
        return Err(ComputeError::Invalid);
    }
    let dataset: CodeProposalDataset =
        serde_json::from_str(json).map_err(|_| ComputeError::Invalid)?;
    dataset.validate_shape()
}

#[cfg(test)]
mod tests;
