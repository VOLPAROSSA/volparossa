//! Explicit public dataset provenance and deterministic independent inference-row selection.
//!
//! A publication signature proves the independently trusted publisher, not truthfulness,
//! answer quality or legal provenance. This fixed initial profile accepts only the explicit
//! public repository dataset or inference-only document package, never browsing captures
//! or private messages. Document excerpts are assertions signed by their source publisher,
//! not cryptographic range proofs of unavailable original bytes.

mod derived;
mod document;
pub use derived::{
    DERIVED_CLAIM_SCOPE, DERIVED_CONTENT_TYPE, DerivedDataset, DerivedInput, DerivedQuestion,
    validate_derived_json,
};
pub use document::{
    DOCUMENT_CONTENT_TYPE, DocumentDataset, DocumentQuestion, validate_document_json,
};

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use super::ComputeError;
use crate::{CHUNK_BYTES, ChunkId, SignedManifest, VerifiedManifest};

/// Existing native content type for explicitly published agent datasets.
pub const CONTENT_TYPE: &str = "application/vnd.volparossa.agent-dataset.v1+json";
/// Maximum exact original or derived dataset bytes; model weights are not embedded.
pub const MAX_DATASET_BYTES: usize = 1024 * 1024;

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Dataset {
    version: u32,
    visibility: String,
    license: String,
    source_revision: String,
    train: Vec<Answered>,
    heldout: Vec<Answered>,
    inference: Vec<Question>,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Answered {
    question: String,
    context: String,
    answer: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Question {
    question: String,
    context: String,
}

/// Exact verified original source; callers cannot construct one from an untrusted ID alone.
pub struct VerifiedPublicDataset {
    manifest: VerifiedManifest,
    dataset: Profile,
}

enum Profile {
    Repository(Dataset),
    Document(DocumentDataset),
    Derived(DerivedDataset),
}

impl VerifiedPublicDataset {
    /// Original signed publication ID, unchanged by selecting a subset of its rows.
    pub fn manifest_id(&self) -> &[u8; 32] {
        self.manifest.manifest_id()
    }

    /// Original exclusive expiry; peer execution may not extend it.
    pub fn expires(&self) -> u64 {
        self.manifest.validity().expires
    }

    /// Number of original independent inference rows in this bounded source.
    pub fn row_count(&self) -> usize {
        match &self.dataset {
            Profile::Repository(dataset) => dataset.inference.len(),
            Profile::Document(dataset) => dataset.inference.len(),
            Profile::Derived(dataset) => dataset.inference.len(),
        }
    }

    /// Whether this source is a public document package, which must never be used for training.
    pub fn is_document(&self) -> bool {
        matches!(self.dataset, Profile::Document(_) | Profile::Derived(_))
    }

    /// Model-generated public synthesis inputs, not original excerpts or execution attestations.
    pub fn is_derived(&self) -> bool {
        matches!(self.dataset, Profile::Derived(_))
    }

    /// Deterministically serialize the selected original rows in increasing index order.
    /// Training/heldout data and source identity are preserved; this operation does not train.
    ///
    /// # Errors
    /// Rejects empty, duplicate, unordered or absent indices and excessive serialized bytes.
    pub fn derive(&self, rows: &[u16]) -> Result<String, ComputeError> {
        self.derive_selected(rows, None)
    }

    /// Replace only selected inference questions with one explicitly public requester instruction.
    /// Source identity, training/heldout rows and selected context strings remain unchanged.
    /// The new question is requester-authored, not authenticated as the publisher's question.
    ///
    /// # Errors
    /// Rejects invalid row selection, empty/whitespace-only, NUL or over-512-byte questions,
    /// and derived datasets larger than the existing object bound.
    pub fn derive_question(&self, rows: &[u16], question: &str) -> Result<String, ComputeError> {
        text(question, 512)?;
        if question.trim().is_empty() {
            return Err(ComputeError::Invalid);
        }
        self.derive_selected(rows, Some(question))
    }

    fn derive_selected(
        &self,
        rows: &[u16],
        question: Option<&str>,
    ) -> Result<String, ComputeError> {
        if rows.is_empty() || rows.len() > 4 || rows.windows(2).any(|pair| pair[0] >= pair[1]) {
            return Err(ComputeError::Invalid);
        }
        let json = match &self.dataset {
            Profile::Repository(original) => {
                let mut dataset = original.clone();
                dataset.inference = rows
                    .iter()
                    .map(|index| {
                        let mut row = original
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
                serde_json::to_string(&dataset).map_err(|_| ComputeError::Invalid)?
            }
            Profile::Document(original) => original.derive_selected(rows, question)?,
            Profile::Derived(original) => original.derive_selected(rows, question)?,
        };
        if json.len() > MAX_DATASET_BYTES {
            return Err(ComputeError::Invalid);
        }
        Ok(json)
    }
}

/// Verify the original signature, exact object/chunk bytes, public schema and original expiry.
/// The caller independently establishes `publisher`; a key embedded in a request is not trust.
///
/// # Errors
/// Rejects wrong publishers, stale/altered publications, other content types and private schemas.
pub fn verify_source(
    manifest_bytes: &[u8],
    publisher: &VerifyingKey,
    original_json: &str,
    now: u64,
) -> Result<VerifiedPublicDataset, ComputeError> {
    if original_json.is_empty() || original_json.len() > MAX_DATASET_BYTES {
        return Err(ComputeError::Invalid);
    }
    let manifest = SignedManifest::decode(manifest_bytes)
        .and_then(|signed| signed.verify(publisher, now))
        .map_err(|_| ComputeError::Authentication)?;
    if !matches!(
        manifest.metadata().content_type.as_str(),
        CONTENT_TYPE | DOCUMENT_CONTENT_TYPE | DERIVED_CONTENT_TYPE
    ) || manifest.length() != original_json.len() as u64
        || manifest.object_sha256() != &<[u8; 32]>::from(Sha256::digest(original_json.as_bytes()))
    {
        return Err(ComputeError::Authentication);
    }
    let bytes: Vec<_> = original_json.as_bytes().chunks(CHUNK_BYTES).collect();
    if bytes.len() != manifest.chunks().len()
        || bytes
            .iter()
            .zip(manifest.chunks())
            .any(|(actual, expected)| {
                expected.id() != &ChunkId::digest(actual)
                    || expected.length() as usize != actual.len()
            })
    {
        return Err(ComputeError::Authentication);
    }
    let dataset = if manifest.metadata().content_type == DERIVED_CONTENT_TYPE {
        let derived: DerivedDataset =
            serde_json::from_str(original_json).map_err(|_| ComputeError::Invalid)?;
        derived.verify_source(publisher, now, manifest.validity().expires)?;
        Profile::Derived(derived)
    } else if manifest.metadata().content_type == DOCUMENT_CONTENT_TYPE {
        let document: DocumentDataset =
            serde_json::from_str(original_json).map_err(|_| ComputeError::Invalid)?;
        document.verify_source(publisher, now, manifest.validity().expires)?;
        Profile::Document(document)
    } else {
        let dataset: Dataset =
            serde_json::from_str(original_json).map_err(|_| ComputeError::Invalid)?;
        validate(&dataset)?;
        Profile::Repository(dataset)
    };
    Ok(VerifiedPublicDataset { manifest, dataset })
}

fn validate(dataset: &Dataset) -> Result<(), ComputeError> {
    if dataset.version != 1
        || dataset.visibility != "public"
        || dataset.license != "GPL-3.0-only"
        || dataset.source_revision.len() != 40
        || !dataset
            .source_revision
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || dataset.train.len() > 32
        || !(1..=8).contains(&dataset.heldout.len())
        || !(1..=4).contains(&dataset.inference.len())
    {
        return Err(ComputeError::Invalid);
    }
    for row in dataset.train.iter().chain(&dataset.heldout) {
        text(&row.question, 512)?;
        text(&row.context, 4096)?;
        text(&row.answer, 1024)?;
    }
    for row in &dataset.inference {
        text(&row.question, 512)?;
        text(&row.context, 4096)?;
    }
    for row in &dataset.train {
        if dataset.heldout.iter().any(|heldout| {
            row.question.trim().to_lowercase() == heldout.question.trim().to_lowercase()
        }) {
            return Err(ComputeError::Invalid);
        }
    }
    Ok(())
}

fn text(text: &str, maximum: usize) -> Result<(), ComputeError> {
    if text.is_empty() || text.len() > maximum || text.contains('\0') {
        return Err(ComputeError::Invalid);
    }
    Ok(())
}

#[cfg(test)]
mod tests;
