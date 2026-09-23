//! Explicit structured public principle judgments, not automatic policy authority.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use super::{ComputeError, DocumentDataset, DocumentQuestion, MAX_DATASET_BYTES};

/// Signed fixed-contract inference, distinct from training and ordinary document answers.
pub const PRINCIPLE_CONTENT_TYPE: &str = "application/vnd.volparossa.agent-principle.v4+json";

/// Exact publisher-selected structured response, never an arbitrary decoder or executable schema.
#[derive(Clone, Copy, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum PrincipleOutputContract {
    /// A bounded principle-based assessment of the explicitly public subject.
    PrincipleAssessmentV1,
    /// A bounded cross-review of one independently bound assessment.
    PrincipleReviewV1,
}

/// One public document-context row with an immutable structured-output contract.
/// The same source-publisher, licensing and byte-range assertions apply as for document v2.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct PrincipleDataset {
    /// Exactly 4.
    pub version: u32,
    /// Exactly public; no private inputs or training records are accepted.
    pub visibility: String,
    /// The original document profile's explicit public license declaration.
    pub license: String,
    /// Canonical original text/plain source manifest, in lowercase hexadecimal.
    pub source_manifest_hex: String,
    /// Exactly one bounded original-context row; requester question replacement is forbidden.
    pub inference: Vec<DocumentQuestion>,
    /// Exact signed assessment or review contract.
    pub output_contract: PrincipleOutputContract,
}

impl PrincipleDataset {
    fn document(&self) -> DocumentDataset {
        DocumentDataset {
            version: 2,
            visibility: self.visibility.clone(),
            license: self.license.clone(),
            source_manifest_hex: self.source_manifest_hex.clone(),
            inference: self.inference.clone(),
        }
    }

    /// Validate fixed public fields, singleton input, original ranges and manifest shape.
    ///
    /// # Errors
    /// Rejects other versions, private/training data and invalid document-profile fields.
    pub fn validate_shape(&self) -> Result<(), ComputeError> {
        if self.version != 4 || self.inference.len() != 1 {
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
            .verify_source(publisher, now, package_expiry)
    }

    pub(super) fn derive_selected(&self, rows: &[u16]) -> Result<String, ComputeError> {
        if rows != [0] {
            return Err(ComputeError::Invalid);
        }
        serde_json::to_string(self).map_err(|_| ComputeError::Invalid)
    }
}

/// Strict fixed-contract broker admission, not independent publisher trust or model execution.
///
/// # Errors
/// Rejects excessive JSON, unknown/duplicate fields, other contracts and non-singleton inputs.
pub fn validate_principle_json(json: &str, expected_rows: usize) -> Result<(), ComputeError> {
    if json.is_empty() || json.len() > MAX_DATASET_BYTES || expected_rows != 1 {
        return Err(ComputeError::Invalid);
    }
    let dataset: PrincipleDataset =
        serde_json::from_str(json).map_err(|_| ComputeError::Invalid)?;
    dataset.validate_shape()
}

#[cfg(test)]
mod tests;
