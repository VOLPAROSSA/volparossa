// SPDX-License-Identifier: GPL-3.0-only
//! Exact local preparation metadata, never consent or a publication authorization.

use std::io::{self, Read, Write};

use anyhow::{Result, bail};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use volparossa_content::site::{SITE_CONTENT_TYPE, SiteAssetSource, SiteBundle};

const MAX_RECEIPT_BYTES: usize = 512 * 1024;

/// Hash each asset as the codec reads it, and the canonical bundle as it is written.
pub(super) fn write_to<R: Read, W: Write>(
    assets: Vec<SiteAssetSource<R>>,
    output: &mut W,
) -> Result<(u64, Value)> {
    let mut inventory: Vec<_> = assets
        .iter()
        .map(|asset| {
            (
                asset.path.clone(),
                asset.content_type.clone(),
                asset.length,
                Sha256::new(),
            )
        })
        .collect();
    let sources = assets
        .into_iter()
        .zip(&mut inventory)
        .map(|(asset, (_, _, _, digest))| SiteAssetSource {
            reader: HashStream {
                stream: asset.reader,
                digest,
            },
            path: asset.path,
            content_type: asset.content_type,
            length: asset.length,
        })
        .collect();
    let mut bundle_hash = Sha256::new();
    let length = SiteBundle::write_to(
        sources,
        &mut HashStream {
            stream: output,
            digest: &mut bundle_hash,
        },
    )?;
    inventory.sort_unstable_by(|left, right| left.0.cmp(&right.0));
    let inventory: Vec<_> = inventory
        .into_iter()
        .map(|(path, content_type, bytes, digest)| {
            json!({ "path": path, "content_type": content_type, "bytes": bytes,
                "sha256": hex::encode(digest.finalize()) })
        })
        .collect();
    let receipt = json!({
        "schema_version": 1,
        "operation": "site_pack_preparation",
        "source": "explicit_local_directory",
        "content_type": SITE_CONTENT_TYPE,
        "bundle_sha256": hex::encode(bundle_hash.finalize()),
        "bundle_bytes": length,
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
    Ok((length, receipt))
}

struct HashStream<'a, T> {
    stream: T,
    digest: &'a mut Sha256,
}

impl<R: Read> Read for HashStream<'_, R> {
    fn read(&mut self, bytes: &mut [u8]) -> io::Result<usize> {
        let count = self.stream.read(bytes)?;
        self.digest.update(&bytes[..count]);
        Ok(count)
    }
}

impl<W: Write> Write for HashStream<'_, W> {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        let count = self.stream.write(bytes)?;
        self.digest.update(&bytes[..count]);
        Ok(count)
    }

    fn flush(&mut self) -> io::Result<()> {
        self.stream.flush()
    }
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
