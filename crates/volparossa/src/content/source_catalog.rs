//! Explicitly trusted public-source catalogs, refreshed through protected named retrieval.
//! Catalog consent is a publisher assertion, not proof of legal rights or dataset quality.
//! Listed datasets retain the same enrolled publisher and are independently verified before
//! training; arbitrary cache entries and third-party trust delegation are not admitted here.

use std::{
    collections::BTreeSet,
    io::{Read as _, Seek as _, SeekFrom},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use volparossa_content::{CHUNK_BYTES, ChunkId, SignedManifest, provider::compute::dataset};

use super::{FetchName, Limits, named_download, now_seconds, parse_content_name};

pub(crate) const CONTENT_TYPE: &str = "application/vnd.volparossa.agent-source-catalog.v1+json";
pub(crate) const MAX_BYTES: usize = 64 * 1024;
pub(crate) const MAX_ENTRIES: usize = 128;

pub(crate) struct Fetch {
    pub(crate) publisher_key: VerifyingKey,
    pub(crate) name: String,
    pub(crate) min_revision: Option<u64>,
    pub(crate) manifest_id: Option<[u8; 32]>,
    pub(crate) cache: PathBuf,
    pub(crate) limits: Limits,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct Entry {
    pub(crate) name: String,
    pub(crate) revision: u64,
    pub(crate) manifest_id: [u8; 32],
}

/// Constructed only after the original signed object and correlated local delivery succeed.
pub(crate) struct VerifiedCatalog {
    revision: u64,
    manifest_id: [u8; 32],
    expires: u64,
    rows: Vec<Entry>,
    signed_manifest: Vec<u8>,
    body: Vec<u8>,
    receipt: Value,
}

impl VerifiedCatalog {
    pub(crate) const fn revision(&self) -> u64 {
        self.revision
    }

    pub(crate) const fn manifest_id(&self) -> &[u8; 32] {
        &self.manifest_id
    }

    pub(crate) const fn expires(&self) -> u64 {
        self.expires
    }

    pub(crate) fn rows(&self) -> &[Entry] {
        &self.rows
    }

    pub(crate) fn signed_manifest(&self) -> &[u8] {
        &self.signed_manifest
    }

    pub(crate) fn body(&self) -> &[u8] {
        &self.body
    }

    pub(crate) const fn receipt(&self) -> &Value {
        &self.receipt
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Catalog {
    version: u32,
    visibility: String,
    purpose: String,
    dataset_profile: String,
    license: String,
    sources: Vec<Source>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Source {
    name: String,
    revision: u64,
    manifest_id: String,
}

pub(crate) async fn fetch(
    args: &Fetch,
    socket: &Path,
    private_parent: &Path,
) -> Result<VerifiedCatalog> {
    let query = FetchName {
        publisher_key: args.publisher_key,
        name: args.name.clone(),
        min_revision: args.min_revision,
        cache: args.cache.clone(),
        reuse_cache: true,
        cache_only: false,
        local_output: private_parent.join("unused-catalog-output"),
        limits: args.limits.clone(),
    };
    let download = named_download::prepare_bounded_refresh(
        &query,
        socket,
        private_parent,
        &named_download::Requirement {
            content_type: CONTENT_TYPE,
            maximum_bytes: MAX_BYTES as u64,
            manifest_id: args.manifest_id,
        },
    )
    .await?;
    let mut file = download.as_file().try_clone()?;
    file.seek(SeekFrom::Start(0))?;
    let mut body = Vec::new();
    file.take(MAX_BYTES as u64 + 1).read_to_end(&mut body)?;
    let signed_manifest = download.signed_manifest().encode();
    let rows = verify(&signed_manifest, &body, &args.publisher_key, now_seconds()?)?;
    download.check_live()?;
    Ok(VerifiedCatalog {
        revision: download.manifest().metadata().revision,
        manifest_id: *download.manifest().manifest_id(),
        expires: download.expires(),
        rows,
        signed_manifest,
        body,
        receipt: download.report(),
    })
}

/// Verify original authority, exact bytes, original expiry and the fixed public training scope.
/// Caller-selected catalog name/revision floors are enforced separately by named retrieval.
pub(crate) fn verify(
    signed_bytes: &[u8],
    body: &[u8],
    publisher: &VerifyingKey,
    now: u64,
) -> Result<Vec<Entry>> {
    ensure!(
        !body.is_empty() && body.len() <= MAX_BYTES,
        "source_catalog_body_bound"
    );
    let manifest = SignedManifest::decode(signed_bytes)?.verify(publisher, now)?;
    ensure!(
        manifest.metadata().content_type == CONTENT_TYPE
            && manifest.length() == body.len() as u64
            && manifest.object_sha256() == &<[u8; 32]>::from(Sha256::digest(body)),
        "source_catalog_original_object"
    );
    let chunks = body.chunks(CHUNK_BYTES);
    ensure!(
        chunks.len() == manifest.chunks().len(),
        "source_catalog_chunk_count"
    );
    for (bytes, chunk) in chunks.zip(manifest.chunks()) {
        ensure!(
            chunk.id() == &ChunkId::digest(bytes) && chunk.length() as usize == bytes.len(),
            "source_catalog_chunk_identity"
        );
    }
    let catalog: Catalog = serde_json::from_slice(body).context("source_catalog_schema")?;
    ensure!(
        catalog.version == 1
            && catalog.visibility == "public"
            && catalog.purpose == "agent_training"
            && catalog.dataset_profile == dataset::CONTENT_TYPE
            && catalog.license == "GPL-3.0-only"
            && catalog.sources.len() <= MAX_ENTRIES,
        "source_catalog_scope"
    );
    let mut names = BTreeSet::new();
    catalog
        .sources
        .into_iter()
        .map(|source| {
            let name = parse_content_name(&source.name).map_err(anyhow::Error::msg)?;
            ensure!(
                source.revision > 0 && names.insert(name.clone()),
                "source_catalog_duplicate_or_revision"
            );
            ensure!(
                source.manifest_id.len() == 64
                    && source
                        .manifest_id
                        .bytes()
                        .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)),
                "source_catalog_manifest_id"
            );
            let mut manifest_id = [0; 32];
            hex::decode_to_slice(source.manifest_id, &mut manifest_id)?;
            ensure!(manifest_id != [0; 32], "source_catalog_manifest_id");
            Ok(Entry {
                name,
                revision: source.revision,
                manifest_id,
            })
        })
        .collect()
}

#[cfg(test)]
mod tests;
