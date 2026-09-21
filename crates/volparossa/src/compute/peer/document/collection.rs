//! Explicit owner-authorized source compilations, not assertions by original publishers.
//! Every retained label and original-byte identity is embedded in the signed text itself.

pub(super) mod network;

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
const NETWORK_MARKER: &str = "VOLPAROSSA owner-published public source collection v2\n";

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
    input: Option<std::path::PathBuf>,
    native: Option<network::Selection>,
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) native: Option<network::Selection>,
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
    pub(super) network: Option<network::Proofs>,
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

fn header(
    version: u32,
    index: usize,
    label: &str,
    sha256: &str,
    bytes: u64,
    native: Option<&network::Selection>,
) -> Result<String> {
    let marker = if index == 0 {
        if version == 1 { MARKER } else { NETWORK_MARKER }
    } else {
        ""
    };
    let identity = native
        .map(|selection| serde_json::to_string(selection).map(|json| format!("native: {json}\n")))
        .transpose()?
        .unwrap_or_default();
    Ok(format!(
        "{marker}\n--- VOLPAROSSA source {} ---\nlabel: {}\nsha256: {sha256}\nbytes: {bytes}\n{identity}\n",
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

fn load_plan(plan_path: &Path) -> Result<SourcePlan> {
    let plan: SourcePlan =
        serde_json::from_slice(&crate::compute::read_file(plan_path, MAX_PLAN_BYTES)?)?;
    ensure!(
        matches!(plan.version, 1 | 2) && (2..=MAX_SOURCES).contains(&plan.sources.len()),
        "compute_collection_plan"
    );
    let mut labels = BTreeSet::new();
    for source in &plan.sources {
        label(&source.label)?;
        ensure!(
            labels.insert(&source.label),
            "compute_collection_duplicate_label"
        );
        match (&source.input, &source.native) {
            (Some(input), None) => {
                ensure!(input.is_absolute(), "compute_collection_input_absolute");
            }
            (None, Some(native)) if plan.version == 2 => native.validate()?,
            _ => anyhow::bail!("compute_collection_exactly_one_source"),
        }
    }
    Ok(plan)
}

pub(super) struct Acquisition<'a> {
    pub(super) socket: &'a Path,
    pub(super) directory: &'a Path,
    pub(super) cache: Option<&'a Path>,
    pub(super) reuse_cache: bool,
    pub(super) limits: &'a crate::content::Limits,
    pub(super) cancelled: &'a tokio::sync::watch::Receiver<bool>,
}

pub(super) async fn acquire(plan_path: &Path, context: Acquisition<'_>) -> Result<Prepared> {
    // Validate the entire explicit selection before cache lookup or network I/O.
    let plan = load_plan(plan_path)?;
    let needs_network = plan.sources.iter().any(|source| source.native.is_some());
    ensure!(
        needs_network || context.cache.is_none(),
        "compute_collection_unneeded_cache"
    );
    if needs_network {
        let cache = context
            .cache
            .context("compute_collection_source_cache_required")?;
        ensure!(
            cache.is_absolute()
                && !cache.starts_with(context.directory)
                && !context.directory.starts_with(cache),
            "compute_collection_cache_overlap"
        );
    }
    let mut selected = Vec::with_capacity(plan.sources.len());
    let mut proofs = Vec::new();
    let mut reuse_cache = context.reuse_cache;
    let mut source_bytes = 0_usize;
    for (source_index, source) in plan.sources.into_iter().enumerate() {
        ensure!(
            !*context.cancelled.borrow(),
            "compute_collection_cancelled_before_source"
        );
        let text = if let Some(native) = &source.native {
            let query = crate::content::public_text::TextSource {
                publisher_key: super::parse_key(&native.publisher_key)
                    .map_err(anyhow::Error::msg)?,
                name: native.name.clone(),
                manifest_id: hex::decode(&native.manifest_id)?
                    .try_into()
                    .map_err(|_| anyhow::anyhow!("compute_collection_manifest_id"))?,
                cache: context
                    .cache
                    .context("compute_collection_source_cache_required")?
                    .to_path_buf(),
                reuse_cache,
                limits: context.limits.clone(),
            };
            let mut activity = context.cancelled.clone();
            let received = tokio::select! { biased;
                _ = activity.changed() => anyhow::bail!("compute_collection_cancelled_during_source"),
                received = crate::content::public_text::fetch_text_source(&query, context.socket, context.directory) => received?
            };
            reuse_cache = true;
            proofs.push(network::Proof {
                source_index,
                selection: native.clone(),
                verified_at: received.verified_at,
                expires: received.expires,
                signed_manifest_hex: hex::encode(received.signed_manifest),
                sha256: hash(received.text.as_bytes()),
                bytes: received.text.len() as u64,
                receipt: received.receipt,
            });
            received.text
        } else {
            local_text(
                source
                    .input
                    .as_deref()
                    .context("compute_collection_local_source")?,
            )?
        };
        ensure!(
            !text.trim().is_empty() && !text.contains('\0'),
            "compute_collection_source_text"
        );
        source_bytes = source_bytes
            .checked_add(text.len())
            .filter(|bytes| *bytes <= MAX_DOCUMENT_BYTES)
            .context("compute_collection_compiled_size")?;
        selected.push((source.label, text, source.native));
    }
    let mut prepared = compile(plan.version, selected)?;
    if !proofs.is_empty() {
        prepared.network = Some(network::Proofs {
            version: 1,
            sources: proofs,
        });
    }
    Ok(prepared)
}

fn local_text(path: &Path) -> Result<String> {
    Ok(String::from_utf8(crate::compute::read_file(
        path,
        MAX_DOCUMENT_BYTES as u64,
    )?)?)
}

#[cfg(test)]
pub(super) fn prepare(plan_path: &Path) -> Result<Prepared> {
    let plan = load_plan(plan_path)?;
    let sources = plan
        .sources
        .into_iter()
        .map(|source| {
            ensure!(
                source.native.is_none(),
                "compute_collection_network_acquisition_required"
            );
            let text = local_text(
                source
                    .input
                    .as_deref()
                    .context("compute_collection_local_source")?,
            )?;
            Ok((source.label, text, None))
        })
        .collect::<Result<Vec<_>>>()?;
    compile(plan.version, sources)
}

fn compile(
    version: u32,
    selected: Vec<(String, String, Option<network::Selection>)>,
) -> Result<Prepared> {
    let mut document = String::new();
    let mut sources = Vec::with_capacity(selected.len());
    for (index, (label, text, native)) in selected.into_iter().enumerate() {
        ensure!(
            !text.trim().is_empty() && !text.contains('\0'),
            "compute_collection_source_text"
        );
        let sha256 = hash(text.as_bytes());
        let bytes = u64::try_from(text.len())?;
        let header = append(
            &mut document,
            &header(version, index, &label, &sha256, bytes, native.as_ref())?,
        )?;
        let content = append(&mut document, &text)?;
        let separator = append(&mut document, &separator(index))?;
        sources.push(Source {
            label,
            sha256,
            bytes,
            header,
            content,
            separator,
            native,
        });
    }
    let ledger = Ledger {
        version,
        document_sha256: hash(document.as_bytes()),
        document_bytes: u64::try_from(document.len())?,
        sources,
    };
    ledger.validate(&document)?;
    Ok(Prepared {
        document,
        ledger,
        network: None,
    })
}

impl Ledger {
    fn validate_layout(&self) -> Result<()> {
        ensure!(
            matches!(self.version, 1 | 2)
                && (2..=MAX_SOURCES).contains(&self.sources.len())
                && self.document_bytes <= u64::try_from(MAX_DOCUMENT_BYTES)?
                && digest(&self.document_sha256),
            "compute_collection_ledger"
        );
        let mut labels = BTreeSet::new();
        let mut next = 0_u64;
        for (index, source) in self.sources.iter().enumerate() {
            label(&source.label)?;
            if let Some(native) = &source.native {
                ensure!(self.version == 2, "compute_collection_native_version");
                native.validate()?;
            }
            ensure!(
                labels.insert(&source.label),
                "compute_collection_duplicate_label"
            );
            ensure!(
                digest(&source.sha256) && source.bytes > 0,
                "compute_collection_source_identity"
            );
            let expected_header = header(
                self.version,
                index,
                &source.label,
                &source.sha256,
                source.bytes,
                source.native.as_ref(),
            )?;
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
                    == header(
                        self.version,
                        index,
                        &source.label,
                        &source.sha256,
                        source.bytes,
                        source.native.as_ref()
                    )?
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
