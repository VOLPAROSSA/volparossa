//! Inference-only synthesis of explicitly public, model-generated intermediate answers.
//!
//! The source publisher signs a coordinator's provenance assertions. Neither a report hash
//! nor a provider key makes those assertions a portable executor attestation. Source ranges
//! describe what earlier work covered; model text is never authenticated as original text.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use super::{ComputeError, MAX_DATASET_BYTES, document::decode_source_manifest, text};

/// Distinct from original document excerpts and from training datasets.
pub const DERIVED_CONTENT_TYPE: &str = "application/vnd.volparossa.agent-derived.v3+json";
/// Exact limited meaning of the coordinator's signed lineage claims.
pub const DERIVED_CLAIM_SCOPE: &str =
    "coordinator_verified_local_rpc_status_not_portable_execution_attestation";

/// Public synthesis inputs signed by the same independently trusted original source publisher.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DerivedDataset {
    /// Exactly 3.
    pub version: u32,
    /// Exactly public; private intermediate answers are not eligible.
    pub visibility: String,
    /// Explicit GPL-3.0-only, CC0-1.0, CC-BY-4.0 or CC-BY-SA-4.0 declaration.
    pub license: String,
    /// Original canonical text/plain source manifest, not a synthesized-text manifest.
    pub source_manifest_hex: String,
    /// Bounded synthesis level, 1 through 16.
    pub level: u16,
    /// Exactly `DERIVED_CLAIM_SCOPE`; no independently portable execution proof is claimed.
    pub claim_scope: String,
    /// One to four independently bounded synthesis rows; never training/heldout records.
    pub inference: Vec<DerivedQuestion>,
}

/// A synthesis instruction and exact selected pieces of its model-generated parent answers.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DerivedQuestion {
    /// Public question of at most 512 UTF-8 bytes, optionally replaced by a bound requester task.
    pub question: String,
    /// Exact concatenated virtual-segment pieces, at most 4096 UTF-8 bytes.
    pub context: String,
    /// One to 64 parent-output provenance assertions in concatenation order.
    pub inputs: Vec<DerivedInput>,
}

/// Coordinator-authenticated lineage, not a provider signature or original-source excerpt.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DerivedInput {
    /// Full unmodified parent output, at most 1024 UTF-8 bytes, including unselected pieces.
    pub text: String,
    /// Lowercase hexadecimal nonzero Ed25519 provider key reported by the coordinator.
    pub provider_key: String,
    /// Original 16-byte worker job identifier, lowercase hexadecimal and nonzero.
    pub job_id: String,
    /// Actual full parent report SHA-256 claimed by the coordinator, not an attestation.
    pub report_sha256: String,
    /// Parent signed package identifier, lowercase hexadecimal and nonzero.
    pub package_manifest_id: String,
    /// Parent frozen model fingerprint, lowercase hexadecimal and nonzero.
    pub model_fingerprint: String,
    /// Exact parent report output index.
    pub output_index: u16,
    /// Original retained parent index; input ordering need not equal this index.
    pub parent_index: u32,
    /// Inclusive original-source coverage offset claimed by the coordinator.
    pub source_start: u64,
    /// Exclusive original-source coverage offset; overlapping coverage is allowed.
    pub source_end: u64,
    /// Inclusive UTF-8 byte offset in the virtual segment `text + '\n'`.
    pub piece_start: u64,
    /// Exclusive virtual-segment offset; no splitting within a UTF-8 codepoint.
    pub piece_end: u64,
}

impl DerivedDataset {
    /// Validate strict shape and exact piece reconstruction, without establishing publisher trust.
    ///
    /// # Errors
    /// Rejects unsupported profiles/claims, invalid identities/ranges and changed context bytes.
    pub fn validate_shape(&self) -> Result<(), ComputeError> {
        if self.version != 3
            || self.visibility != "public"
            || !matches!(
                self.license.as_str(),
                "GPL-3.0-only" | "CC0-1.0" | "CC-BY-4.0" | "CC-BY-SA-4.0"
            )
            || !(1..=16).contains(&self.level)
            || self.claim_scope != DERIVED_CLAIM_SCOPE
            || !(1..=4).contains(&self.inference.len())
        {
            return Err(ComputeError::Invalid);
        }
        decode_source_manifest(&self.source_manifest_hex)?;
        for row in &self.inference {
            row.validate()?;
        }
        Ok(())
    }

    pub(super) fn verify_source(
        &self,
        publisher: &VerifyingKey,
        now: u64,
        package_expiry: u64,
    ) -> Result<(), ComputeError> {
        self.validate_shape()?;
        let source = decode_source_manifest(&self.source_manifest_hex)?
            .verify(publisher, now)
            .map_err(|_| ComputeError::Authentication)?;
        if source.metadata().content_type != "text/plain"
            || source.length() > MAX_DATASET_BYTES as u64
            || source.validity().expires < package_expiry
            || self
                .inference
                .iter()
                .flat_map(|row| &row.inputs)
                .any(|input| input.source_end > source.length())
        {
            return Err(ComputeError::Authentication);
        }
        Ok(())
    }

    pub(super) fn derive_selected(
        &self,
        rows: &[u16],
        question: Option<&str>,
    ) -> Result<String, ComputeError> {
        let mut dataset = self.clone();
        dataset.inference = rows
            .iter()
            .map(|index| {
                let mut row = self
                    .inference
                    .get(usize::from(*index))
                    .cloned()
                    .ok_or(ComputeError::Invalid)?;
                if let Some(question) = question {
                    question.clone_into(&mut row.question);
                }
                Ok::<_, ComputeError>(row)
            })
            .collect::<Result<_, _>>()?;
        serde_json::to_string(&dataset).map_err(|_| ComputeError::Invalid)
    }
}

impl DerivedQuestion {
    fn validate(&self) -> Result<(), ComputeError> {
        text(&self.question, 512)?;
        text(&self.context, 4096)?;
        if self.question.trim().is_empty() || !(1..=64).contains(&self.inputs.len()) {
            return Err(ComputeError::Invalid);
        }
        let mut assembled = String::new();
        for input in &self.inputs {
            input.validate()?;
            let segment = format!("{}\n", input.text);
            let start = usize::try_from(input.piece_start).map_err(|_| ComputeError::Invalid)?;
            let end = usize::try_from(input.piece_end).map_err(|_| ComputeError::Invalid)?;
            let piece = segment.get(start..end).ok_or(ComputeError::Invalid)?;
            if piece.is_empty() || assembled.len() + piece.len() > 4096 {
                return Err(ComputeError::Invalid);
            }
            assembled.push_str(piece);
        }
        if assembled != self.context {
            return Err(ComputeError::Invalid);
        }
        Ok(())
    }
}

impl DerivedInput {
    fn validate(&self) -> Result<(), ComputeError> {
        text(&self.text, 1024)?;
        let provider = hex_identity::<32>(&self.provider_key)?;
        VerifyingKey::from_bytes(&provider).map_err(|_| ComputeError::Invalid)?;
        hex_identity::<16>(&self.job_id)?;
        for hash in [
            &self.report_sha256,
            &self.package_manifest_id,
            &self.model_fingerprint,
        ] {
            hex_identity::<32>(hash)?;
        }
        if self.source_start >= self.source_end
            || self.source_end > MAX_DATASET_BYTES as u64
            || self.piece_start >= self.piece_end
            || self.piece_end > self.text.len() as u64 + 1
        {
            return Err(ComputeError::Invalid);
        }
        Ok(())
    }
}

fn hex_identity<const N: usize>(value: &str) -> Result<[u8; N], ComputeError> {
    if value.len() != N * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ComputeError::Invalid);
    }
    let bytes: [u8; N] = hex::decode(value)
        .map_err(|_| ComputeError::Invalid)?
        .try_into()
        .map_err(|_| ComputeError::Invalid)?;
    if bytes == [0; N] {
        return Err(ComputeError::Invalid);
    }
    Ok(bytes)
}

/// Cheap inference-only broker validation, never independent publisher/worker authentication.
///
/// # Errors
/// Rejects excessive JSON, unknown/duplicate fields, wrong row count and invalid shape.
pub fn validate_derived_json(json: &str, expected_rows: usize) -> Result<(), ComputeError> {
    if json.is_empty() || json.len() > MAX_DATASET_BYTES || !(1..=4).contains(&expected_rows) {
        return Err(ComputeError::Invalid);
    }
    let dataset: DerivedDataset = serde_json::from_str(json).map_err(|_| ComputeError::Invalid)?;
    if dataset.inference.len() != expected_rows {
        return Err(ComputeError::Invalid);
    }
    dataset.validate_shape()
}

#[cfg(test)]
mod tests;
