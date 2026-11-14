// SPDX-License-Identifier: GPL-3.0-only
//! Exact local preparation metadata, never consent or a publication authorization.

use std::io::{self, Write};

use anyhow::{Result, bail};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use volparossa_content::site::{SITE_CONTENT_TYPE, SiteAsset, SiteBundle};

const MAX_RECEIPT_BYTES: usize = 512 * 1024;

/// Hash the same owned snapshots consumed by the canonical codec, without copying payloads.
pub(super) fn encode(assets: Vec<SiteAsset>) -> Result<(Vec<u8>, Value)> {
    let mut sorted: Vec<_> = assets.iter().collect();
    sorted.sort_unstable_by(|left, right| left.path.cmp(&right.path));
    let inventory: Vec<_> = sorted
        .into_iter()
        .map(|asset| {
            json!({
                "path": asset.path,
                "content_type": asset.content_type,
                "bytes": asset.bytes.len(),
                "sha256": hex::encode(Sha256::digest(&asset.bytes)),
            })
        })
        .collect();
    // The existing codec validates the complete geometry and canonical paths before effects.
    let bundle = SiteBundle::encode(assets)?;
    let receipt = json!({
        "schema_version": 1,
        "operation": "site_pack_preparation",
        "source": "explicit_local_directory",
        "content_type": SITE_CONTENT_TYPE,
        "bundle_sha256": hex::encode(Sha256::digest(&bundle)),
        "bundle_bytes": bundle.len(),
        "asset_count": inventory.len(),
        "assets": inventory,
        "symlinks_followed": false,
        "hidden_entries_excluded": true,
        "native_consent_granted": false,
        "publication_signed": false,
        "network_published": false,
        "publisher_authority_granted": false,
        "permission_authority_granted": false,
        "input_files_modified": false,
        // Returned by pack only after the existing no-clobber persist and directory sync.
        "bundle_output_created": true,
        "review_required": true,
    });
    // Count actual JSON escaping without allocating another serialized receipt or payload.
    if serde_json::to_writer(
        ReceiptLimit {
            remaining: MAX_RECEIPT_BYTES,
        },
        &receipt,
    )
    .is_err()
    {
        bail!("site preparation receipt exceeds 512 KiB");
    }
    Ok((bundle, receipt))
}

struct ReceiptLimit {
    remaining: usize,
}

impl Write for ReceiptLimit {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.remaining = self
            .remaining
            .checked_sub(bytes.len())
            .ok_or_else(|| io::Error::other("site preparation receipt size limit"))?;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests;
