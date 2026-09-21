//! Explicit owner-authorized source compilations, not assertions by original publishers.
//! Every retained label and original-byte identity is embedded in the signed text itself.

use std::{collections::BTreeSet, path::Path};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};

use super::MAX_DOCUMENT_BYTES;

const MAX_PLAN_BYTES: u64 = 256 * 1024;
const MAX_SOURCES: usize = 32;
const MAX_LABEL_BYTES: usize = 128;
const MARKER: &str = "VOLPAROSSA owner-published public source collection v1\n";

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourcePlan {
    version: u32,
    sources: Vec<SourceInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SourceInput {
    label: String,
    input: std::path::PathBuf,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Range {
    pub(super) start: u64,
    pub(super) end: u64,
}

impl Range {
    fn intersection(&self, other: &Self) -> Option<Self> {
        let start = self.start.max(other.start);
        let end = self.end.min(other.end);
        (start < end).then_some(Self { start, end })
    }

    fn slice<'a>(&self, document: &'a str) -> Result<&'a str> {
        document
            .get(usize::try_from(self.start)?..usize::try_from(self.end)?)
            .context("compute_collection_range_utf8")
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Source {
    pub(super) label: String,
    pub(super) sha256: String,
    pub(super) bytes: u64,
    pub(super) header: Range,
    pub(super) content: Range,
    pub(super) separator: Range,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Ledger {
    pub(super) version: u32,
    pub(super) document_sha256: String,
    pub(super) document_bytes: u64,
    pub(super) sources: Vec<Source>,
}

pub(super) struct Prepared {
    pub(super) document: String,
    pub(super) ledger: Ledger,
}

fn hash(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn label(value: &str) -> Result<()> {
    ensure!(
        !value.is_empty()
            && value.len() <= MAX_LABEL_BYTES
            && value.trim() == value
            && !value.chars().any(char::is_control),
        "compute_collection_label"
    );
    Ok(())
}

fn digest(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn header(index: usize, label: &str, sha256: &str, bytes: u64) -> Result<String> {
    let marker = if index == 0 { MARKER } else { "" };
    Ok(format!(
        "{marker}\n--- VOLPAROSSA source {} ---\nlabel: {}\nsha256: {sha256}\nbytes: {bytes}\n\n",
        index + 1,
        serde_json::to_string(label)?,
    ))
}

fn separator(index: usize) -> String {
    format!("\n--- END VOLPAROSSA source {} ---\n", index + 1)
}

fn append(document: &mut String, text: &str) -> Result<Range> {
    let end = document
        .len()
        .checked_add(text.len())
        .filter(|end| *end <= MAX_DOCUMENT_BYTES)
        .context("compute_collection_compiled_size")?;
    let range = Range {
        start: u64::try_from(document.len())?,
        end: u64::try_from(end)?,
    };
    document.push_str(text);
    Ok(range)
}

pub(super) fn prepare(plan_path: &Path) -> Result<Prepared> {
    let plan: SourcePlan =
        serde_json::from_slice(&crate::compute::read_file(plan_path, MAX_PLAN_BYTES)?)?;
    ensure!(
        plan.version == 1 && (2..=MAX_SOURCES).contains(&plan.sources.len()),
        "compute_collection_plan"
    );
    let mut labels = BTreeSet::new();
    for source in &plan.sources {
        label(&source.label)?;
        ensure!(
            labels.insert(&source.label),
            "compute_collection_duplicate_label"
        );
        ensure!(
            source.input.is_absolute(),
            "compute_collection_input_absolute"
        );
    }
    let mut document = String::new();
    let mut sources = Vec::with_capacity(plan.sources.len());
    for (index, source) in plan.sources.into_iter().enumerate() {
        let text = String::from_utf8(crate::compute::read_file(
            &source.input,
            u64::try_from(MAX_DOCUMENT_BYTES)?,
        )?)?;
        ensure!(
            !text.trim().is_empty() && !text.contains('\0'),
            "compute_collection_source_text"
        );
        let sha256 = hash(text.as_bytes());
        let bytes = u64::try_from(text.len())?;
        let header = append(
            &mut document,
            &header(index, &source.label, &sha256, bytes)?,
        )?;
        let content = append(&mut document, &text)?;
        let separator = append(&mut document, &separator(index))?;
        sources.push(Source {
            label: source.label,
            sha256,
            bytes,
            header,
            content,
            separator,
        });
    }
    let ledger = Ledger {
        version: 1,
        document_sha256: hash(document.as_bytes()),
        document_bytes: u64::try_from(document.len())?,
        sources,
    };
    ledger.validate(&document)?;
    Ok(Prepared { document, ledger })
}

impl Ledger {
    fn validate_layout(&self) -> Result<()> {
        ensure!(
            self.version == 1
                && (2..=MAX_SOURCES).contains(&self.sources.len())
                && self.document_bytes <= u64::try_from(MAX_DOCUMENT_BYTES)?
                && digest(&self.document_sha256),
            "compute_collection_ledger"
        );
        let mut labels = BTreeSet::new();
        let mut next = 0_u64;
        for (index, source) in self.sources.iter().enumerate() {
            label(&source.label)?;
            ensure!(
                labels.insert(&source.label),
                "compute_collection_duplicate_label"
            );
            ensure!(
                digest(&source.sha256) && source.bytes > 0,
                "compute_collection_source_identity"
            );
            let expected_header = header(index, &source.label, &source.sha256, source.bytes)?;
            for (range, bytes) in [
                (&source.header, u64::try_from(expected_header.len())?),
                (&source.content, source.bytes),
                (&source.separator, u64::try_from(separator(index).len())?),
            ] {
                let end = next
                    .checked_add(bytes)
                    .context("compute_collection_range_overflow")?;
                ensure!(
                    range.start == next && range.end == end && end <= self.document_bytes,
                    "compute_collection_coverage"
                );
                next = end;
            }
        }
        ensure!(
            next == self.document_bytes,
            "compute_collection_unowned_bytes"
        );
        Ok(())
    }

    pub(super) fn validate(&self, document: &str) -> Result<()> {
        self.validate_layout()?;
        ensure!(
            document.len() as u64 == self.document_bytes
                && hash(document.as_bytes()) == self.document_sha256,
            "compute_collection_document_identity"
        );
        for (index, source) in self.sources.iter().enumerate() {
            ensure!(
                source.header.slice(document)?
                    == header(index, &source.label, &source.sha256, source.bytes)?
                    && source.separator.slice(document)? == separator(index),
                "compute_collection_embedded_metadata"
            );
            let text = source.content.slice(document)?;
            ensure!(
                !text.trim().is_empty()
                    && !text.contains('\0')
                    && hash(text.as_bytes()) == source.sha256,
                "compute_collection_original_bytes"
            );
        }
        Ok(())
    }

    pub(super) fn sha256(&self) -> Result<String> {
        self.validate_layout()?;
        Ok(hash(&serde_json::to_vec(self)?))
    }

    /// Exact byte intersections only. Call `validate` against the signed compilation
    /// before using this ledger; neither this mapping nor a model answer proves a claim.
    pub(super) fn provenance(&self, start: u64, end: u64) -> Result<Value> {
        self.validate_layout()?;
        ensure!(
            start < end && end <= self.document_bytes,
            "compute_collection_requested_range"
        );
        let range = Range { start, end };
        let mut originals = Vec::new();
        let mut synthetic = Vec::new();
        for (index, source) in self.sources.iter().enumerate() {
            if let Some(overlap) = source.content.intersection(&range) {
                originals.push(json!({"source_index":index,"label":source.label,
                    "sha256":source.sha256,"source_bytes":source.bytes,
                    "source_range":{"start":overlap.start-source.content.start,
                        "end":overlap.end-source.content.start},"document_range":overlap}));
            }
            for (kind, generated) in [("header", &source.header), ("separator", &source.separator)]
            {
                if let Some(overlap) = generated.intersection(&range) {
                    synthetic
                        .push(json!({"source_index":index,"kind":kind,"document_range":overlap}));
                }
            }
        }
        Ok(
            json!({"units":"utf8_bytes","range":range,"original_sources":originals,
            "synthetic_ranges":synthetic,"semantic_citation":false,
            "claim_scope":"owner_compilation_exact_byte_intersections_not_source_publisher_or_model_attestation"}),
        )
    }
}

#[cfg(test)]
mod tests;
