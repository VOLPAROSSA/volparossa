//! Inference-only excerpt packages signed by the independently trusted original publisher.
//!
//! The outer signature authenticates that publisher's excerpt/range assertion. Without
//! the original text it is not a cryptographic proof that an excerpt equals those bytes.
//! The document coordinator must check every range against the original before publishing.

use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};

use super::{ComputeError, MAX_DATASET_BYTES, text};
use crate::{MAX_MANIFEST_BYTES, SignedManifest};

/// Explicit public inference-only document package; distinct from training datasets.
pub const DOCUMENT_CONTENT_TYPE: &str = "application/vnd.volparossa.agent-document.v2+json";

/// Bounded source-publisher-authenticated document excerpts, never training/heldout records.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DocumentDataset {
    /// Exactly 2 for this fixed profile.
    pub version: u32,
    /// Exactly public; a source publication is an explicit disclosure, not private cache intake.
    pub visibility: String,
    /// Explicit publisher-declared GPL-3.0-only, CC0-1.0, CC-BY-4.0 or CC-BY-SA-4.0.
    pub license: String,
    /// Original canonical text/plain native manifest, as bounded lowercase hexadecimal.
    pub source_manifest_hex: String,
    /// One to four increasing nonoverlapping source ranges with their asserted exact text.
    pub inference: Vec<DocumentQuestion>,
}

/// One public inference input and its original UTF-8 byte range.
#[derive(Clone, Debug, Deserialize, Serialize, Eq, PartialEq)]
#[serde(deny_unknown_fields)]
pub struct DocumentQuestion {
    /// Original package question, or an independently bound public requester replacement.
    pub question: String,
    /// Nonempty asserted original excerpt, at most 4096 UTF-8 bytes; no silent truncation.
    pub context: String,
    /// Inclusive UTF-8 byte offset in the original source, not a character/token index.
    pub start: u64,
    /// Exclusive offset; end - start must equal the exact context byte length.
    pub end: u64,
}

impl DocumentDataset {
    /// Check public schema, ranges and canonical original-manifest shape, without granting trust.
    ///
    /// # Errors
    /// Rejects unsupported fields/values, excessive bytes, malformed manifests or overlapping ranges.
    pub fn validate_shape(&self) -> Result<(), ComputeError> {
        if self.version != 2
            || self.visibility != "public"
            || !matches!(
                self.license.as_str(),
                "GPL-3.0-only" | "CC0-1.0" | "CC-BY-4.0" | "CC-BY-SA-4.0"
            )
            || !(1..=4).contains(&self.inference.len())
        {
            return Err(ComputeError::Invalid);
        }
        self.source_manifest()?;
        let mut previous_end = 0;
        for row in &self.inference {
            text(&row.question, 512)?;
            text(&row.context, 4096)?;
            if row.question.trim().is_empty()
                || row.start < previous_end
                || row.end > MAX_DATASET_BYTES as u64
                || row.end.checked_sub(row.start) != Some(row.context.len() as u64)
            {
                return Err(ComputeError::Invalid);
            }
            previous_end = row.end;
        }
        Ok(())
    }

    fn source_manifest(&self) -> Result<SignedManifest, ComputeError> {
        decode_source_manifest(&self.source_manifest_hex)
    }

    pub(super) fn verify_source(
        &self,
        publisher: &VerifyingKey,
        now: u64,
        package_expiry: u64,
    ) -> Result<(), ComputeError> {
        self.validate_shape()?;
        // The source cannot supply its own trust anchor: it must match the outer publisher.
        let source = self
            .source_manifest()?
            .verify(publisher, now)
            .map_err(|_| ComputeError::Authentication)?;
        if source.metadata().content_type != "text/plain"
            || source.length() > MAX_DATASET_BYTES as u64
            || source.validity().expires < package_expiry
            || self.inference.iter().any(|row| row.end > source.length())
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

pub(super) fn decode_source_manifest(encoded: &str) -> Result<SignedManifest, ComputeError> {
    if encoded.is_empty()
        || encoded.len() > MAX_MANIFEST_BYTES * 2
        || encoded.len() % 2 != 0
        || !encoded
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(ComputeError::Invalid);
    }
    let bytes = hex::decode(encoded).map_err(|_| ComputeError::Invalid)?;
    SignedManifest::decode(&bytes).map_err(|_| ComputeError::Invalid)
}

/// Cheap strict broker admission for the inference-only profile; not source-publisher trust.
/// Full source and package authentication belongs to the agent before forwarding to the broker.
///
/// # Errors
/// Rejects excessive JSON, missing/unknown/duplicate fields, row-count mismatch and invalid shape.
pub fn validate_document_json(json: &str, expected_rows: usize) -> Result<(), ComputeError> {
    if json.is_empty() || json.len() > MAX_DATASET_BYTES || !(1..=4).contains(&expected_rows) {
        return Err(ComputeError::Invalid);
    }
    let document: DocumentDataset =
        serde_json::from_str(json).map_err(|_| ComputeError::Invalid)?;
    if document.inference.len() != expected_rows {
        return Err(ComputeError::Invalid);
    }
    document.validate_shape()
}

#[cfg(test)]
mod tests;
