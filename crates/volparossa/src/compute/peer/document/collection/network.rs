//! Retained native-source authentication, separate from the owner's compilation signature.
//! Delivery receipts are correlated local metadata, not portable provider attestations.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use volparossa_content::{
    CHUNK_BYTES, ChunkId, MAX_MANIFEST_BYTES, SignedManifest, VerifiedManifest,
};

use super::{Ledger, MAX_DOCUMENT_BYTES, MAX_SOURCES, hash};
use crate::content::{parse_content_name, parse_publisher_key};

const MAX_RECEIPT_BYTES: usize = 8 * 1024;
const MAX_PROOF_BYTES: usize = 128 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::compute::peer::document) struct Selection {
    pub(in crate::compute::peer::document) publisher_key: String,
    pub(in crate::compute::peer::document) name: String,
    pub(in crate::compute::peer::document) manifest_id: String,
}

impl Selection {
    pub(in crate::compute::peer::document) fn validate(&self) -> Result<()> {
        parse_publisher_key(&self.publisher_key).map_err(anyhow::Error::msg)?;
        parse_content_name(&self.name).map_err(anyhow::Error::msg)?;
        ensure!(
            self.publisher_key == self.publisher_key.to_ascii_lowercase()
                && volparossa_local_control::compute::nonzero_hex(&self.manifest_id, 64),
            "compute_collection_native_selection"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::compute::peer::document) struct Proof {
    pub(in crate::compute::peer::document) source_index: usize,
    pub(in crate::compute::peer::document) selection: Selection,
    pub(in crate::compute::peer::document) verified_at: u64,
    pub(in crate::compute::peer::document) expires: u64,
    pub(in crate::compute::peer::document) signed_manifest_hex: String,
    pub(in crate::compute::peer::document) sha256: String,
    pub(in crate::compute::peer::document) bytes: u64,
    pub(in crate::compute::peer::document) receipt: Value,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::compute::peer::document) struct Proofs {
    pub(in crate::compute::peer::document) version: u32,
    pub(in crate::compute::peer::document) sources: Vec<Proof>,
}

impl Proofs {
    pub(in crate::compute::peer::document) fn sha256(&self) -> Result<String> {
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= MAX_PROOF_BYTES,
            "compute_collection_native_proof_size"
        );
        Ok(hash(&bytes))
    }

    /// Historical authentication is intentional for completed offline resume. The caller
    /// still applies current-time admission before new work; this never renews authority.
    pub(in crate::compute::peer::document) fn validate(
        &self,
        ledger: &Ledger,
        document: &str,
        created: u64,
        expires: u64,
    ) -> Result<()> {
        ledger.validate(document)?;
        ensure!(
            self.version == 1
                && ledger.version == 2
                && (1..=MAX_SOURCES).contains(&self.sources.len())
                && created > 0
                && created < expires,
            "compute_collection_native_proofs"
        );
        self.sha256()?;
        let expected = ledger
            .sources
            .iter()
            .enumerate()
            .filter_map(|(index, source)| {
                source
                    .native
                    .as_ref()
                    .map(|selection| (index, source, selection))
            })
            .collect::<Vec<_>>();
        ensure!(
            expected.len() == self.sources.len(),
            "compute_collection_native_proof_coverage"
        );
        for (proof, (index, source, selection)) in self.sources.iter().zip(expected) {
            selection.validate()?;
            ensure!(
                proof.source_index == index && &proof.selection == selection,
                "compute_collection_native_proof_selection"
            );
            proof.validate(source.content.slice(document)?.as_bytes(), created, expires)?;
            ensure!(
                proof.sha256 == source.sha256 && proof.bytes == source.bytes,
                "compute_collection_native_original_identity"
            );
        }
        Ok(())
    }
}

impl Proof {
    fn validate(&self, text: &[u8], created: u64, expires: u64) -> Result<()> {
        self.selection.validate()?;
        ensure!(
            self.verified_at > 0
                && self.verified_at <= created
                && created < expires
                && expires <= self.expires
                && !text.is_empty()
                && text.len() <= MAX_DOCUMENT_BYTES
                && self.signed_manifest_hex.len() <= MAX_MANIFEST_BYTES * 2,
            "compute_collection_native_authority"
        );
        let encoded = hex::decode(&self.signed_manifest_hex)?;
        ensure!(
            hex::encode(&encoded) == self.signed_manifest_hex,
            "compute_collection_native_manifest_hex"
        );
        // Trust is selected before download and embedded in the owner's signed source.
        // Never adopt a self-declared key from the retrieved manifest.
        let publisher =
            parse_publisher_key(&self.selection.publisher_key).map_err(anyhow::Error::msg)?;
        let manifest = SignedManifest::decode(&encoded)?.verify(&publisher, self.verified_at)?;
        ensure!(
            hex::encode(manifest.manifest_id()) == self.selection.manifest_id
                && manifest.metadata().name == self.selection.name
                && manifest.metadata().content_type == "text/plain"
                && manifest.validity().expires == self.expires
                && manifest.length() == self.bytes
                && self.bytes == u64::try_from(text.len())?
                && hex::encode(manifest.object_sha256()) == self.sha256
                && hash(text) == self.sha256
                && manifest.chunks().len() == text.chunks(CHUNK_BYTES).len(),
            "compute_collection_native_manifest_binding"
        );
        for (chunk, bytes) in manifest.chunks().iter().zip(text.chunks(CHUNK_BYTES)) {
            ensure!(
                u64::from(chunk.length()) == u64::try_from(bytes.len())?
                    && chunk.id() == &ChunkId::digest(bytes),
                "compute_collection_native_chunk_binding"
            );
        }
        ensure!(
            serde_json::to_vec(&self.receipt)?.len() <= MAX_RECEIPT_BYTES,
            "compute_collection_native_receipt_size"
        );
        let receipt: Receipt = serde_json::from_value(self.receipt.clone())?;
        receipt.validate(&manifest, &self.selection)?;
        Ok(())
    }
}

/// This shape is emitted only after the existing same-operation named download finishes.
/// Rechecking it preserves local history; its transport counters are not remotely signed.
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Exact existing named-download report flags"
)]
struct Receipt {
    operation: String,
    bytes: u64,
    chunks: u64,
    publisher_key: String,
    name: String,
    revision: u64,
    manifest_id: String,
    publication_expires_unix_seconds: u64,
    sha256: String,
    local_delivery: bool,
    output_mode: String,
    ownership_changed: bool,
    origin_authenticated: bool,
    globally_latest: bool,
    peer_bytes: u64,
    providers_used: u64,
    origin_body_bytes: u64,
    origin_range_requests: u64,
    provider_peer_ids: Vec<String>,
    control_relay_peer_id: String,
    cache_only: bool,
}

impl Receipt {
    fn validate(&self, manifest: &VerifiedManifest, selection: &Selection) -> Result<()> {
        ensure!(
            self.operation == "named_content_download"
                && self.bytes == manifest.length()
                && self.chunks == u64::try_from(manifest.chunks().len())?
                && self.publisher_key == selection.publisher_key
                && self.name == selection.name
                && self.revision == manifest.metadata().revision
                && self.manifest_id == selection.manifest_id
                && self.publication_expires_unix_seconds == manifest.validity().expires
                && self.sha256 == hex::encode(manifest.object_sha256())
                && self.local_delivery
                && self.output_mode == "0600"
                && !self.ownership_changed
                && !self.origin_authenticated
                && !self.globally_latest
                && self.origin_body_bytes == 0
                && self.origin_range_requests == 0,
            "compute_collection_native_receipt_binding"
        );
        let count = usize::try_from(self.providers_used)
            .context("compute_collection_native_receipt_providers")?;
        ensure!(
            self.peer_bytes <= self.bytes
                && count <= 16
                && self.provider_peer_ids.len() == count
                && self.provider_peer_ids.iter().collect::<BTreeSet<_>>().len() == count
                && self
                    .provider_peer_ids
                    .iter()
                    .all(|id| bounded_peer(id, false))
                && bounded_peer(&self.control_relay_peer_id, true)
                && (self.peer_bytes == 0 || (count > 0 && !self.control_relay_peer_id.is_empty()))
                && (!self.cache_only
                    || (self.peer_bytes == 0
                        && count == 0
                        && self.control_relay_peer_id.is_empty())),
            "compute_collection_native_receipt_accounting"
        );
        Ok(())
    }
}

fn bounded_peer(peer: &str, empty: bool) -> bool {
    (empty || !peer.is_empty())
        && peer.len() <= 128
        && peer.bytes().all(|byte| byte.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests;
