//! Explicit public text sources retain native publisher authority, not web-origin authority.

use std::{
    fs::File,
    os::unix::fs::FileExt as _,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use volparossa_content::VerifiedManifest;

use super::{FetchName, Limits, named_download, now_seconds};

const CONTENT_TYPE: &str = "text/plain";
const MAX_TEXT_BYTES: u64 = 1024 * 1024;

/// The owner selects an exact public publication; cache availability cannot change it.
pub(crate) struct TextSource {
    pub(crate) publisher_key: VerifyingKey,
    pub(crate) name: String,
    pub(crate) manifest_id: [u8; 32],
    pub(crate) cache: PathBuf,
    pub(crate) reuse_cache: bool,
    pub(crate) limits: Limits,
}

pub(crate) struct TextDownload {
    pub(crate) signed_manifest: Vec<u8>,
    pub(crate) text: String,
    /// Original named-download receipt, not a portable signed transport attestation.
    pub(crate) receipt: Value,
    pub(crate) expires: u64,
    pub(crate) verified_at: u64,
}

/// Reuse authenticated cached chunks and fetch missing bytes through the protected agent.
/// This does not publish a compilation, start a model, or fetch an unselected source.
pub(crate) async fn fetch_text_source(
    args: &TextSource,
    socket: &Path,
    private_parent: &Path,
) -> Result<TextDownload> {
    let download = named_download::prepare_bounded(
        &query(args, private_parent),
        socket,
        private_parent,
        &named_download::Requirement {
            content_type: CONTENT_TYPE,
            maximum_bytes: MAX_TEXT_BYTES,
            manifest_id: Some(args.manifest_id),
        },
    )
    .await?;
    let bytes = read_download(download.as_file())?;
    let verified_at = now_seconds()?;
    let text = checked_text(args, download.manifest(), bytes, verified_at)?;
    download.check_live()?;
    Ok(TextDownload {
        signed_manifest: download.signed_manifest().encode(),
        text,
        receipt: download.report(),
        expires: download.expires(),
        verified_at,
    })
}

fn query(args: &TextSource, private_parent: &Path) -> FetchName {
    FetchName {
        publisher_key: args.publisher_key,
        name: args.name.clone(),
        min_revision: None,
        cache: args.cache.clone(),
        reuse_cache: args.reuse_cache,
        cache_only: false,
        // The bounded downloader uses an owned temporary; no output is published here.
        local_output: private_parent.join("unused-output"),
        limits: args.limits.clone(),
    }
}

fn read_download(file: &File) -> Result<Vec<u8>> {
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && (1..=MAX_TEXT_BYTES).contains(&metadata.len()),
        "public text source is not a bounded nonempty regular file"
    );
    let mut bytes = vec![0; usize::try_from(metadata.len())?];
    file.read_exact_at(&mut bytes, 0)?;
    Ok(bytes)
}

fn checked_text(
    args: &TextSource,
    manifest: &VerifiedManifest,
    bytes: Vec<u8>,
    verified_at: u64,
) -> Result<String> {
    ensure!(
        manifest.publisher() == args.publisher_key.as_bytes()
            && manifest.metadata().name == args.name
            && manifest.manifest_id() == &args.manifest_id
            && manifest.metadata().content_type == CONTENT_TYPE,
        "public text does not match the explicitly selected publication"
    );
    ensure!(
        (1..=MAX_TEXT_BYTES).contains(&manifest.length())
            && u64::try_from(bytes.len())? == manifest.length(),
        "public text source exceeds its exact signed size or consumer bound"
    );
    let validity = manifest.validity();
    ensure!(
        validity.created <= verified_at && verified_at < validity.expires,
        "public text source is outside its original signed validity"
    );
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    ensure!(
        &hash == manifest.object_sha256(),
        "public text source differs from its signed whole-object hash"
    );
    let text = String::from_utf8(bytes).context("public text source is not UTF-8")?;
    ensure!(
        !text.trim().is_empty() && !text.contains('\0'),
        "public text source is empty or contains NUL"
    );
    Ok(text)
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity};

    use super::*;

    fn publication(bytes: &[u8], content_type: &str) -> (TextSource, VerifiedManifest) {
        let root = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[73; 32]);
        let mut store = ChunkStore::create(
            &root.path().join("cache"),
            CacheLimits {
                max_bytes: 4 * MAX_TEXT_BYTES,
                max_entries: 256,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let mut reader = bytes;
        let signed = volparossa_content::publish(
            &mut reader,
            Publication {
                metadata: Metadata {
                    name: "public-source".into(),
                    revision: 1,
                    content_type: content_type.into(),
                },
                length: bytes.len() as u64,
                validity: Validity {
                    created: 100,
                    expires: 1000,
                },
            },
            &key,
            &mut store,
        )
        .unwrap();
        let manifest = signed.verify(&key.verifying_key(), 101).unwrap();
        (
            TextSource {
                publisher_key: key.verifying_key(),
                name: "public-source".into(),
                manifest_id: *manifest.manifest_id(),
                cache: PathBuf::from("/unused-agent-cache"),
                reuse_cache: true,
                limits: Limits {
                    quota_bytes: 4 * MAX_TEXT_BYTES,
                    max_entries: 256,
                    min_free_bytes: 0,
                },
            },
            manifest,
        )
    }

    #[test]
    fn exact_public_text_preserves_utf8_bytes_and_original_validity() {
        let text = "Een openbare bron.\nUn réseau coopératif. 🦊\n";
        let (args, manifest) = publication(text.as_bytes(), CONTENT_TYPE);
        for at in [100, 101, 999] {
            assert_eq!(
                checked_text(&args, &manifest, text.as_bytes().to_vec(), at).unwrap(),
                text
            );
        }
        for at in [99, 1000, 1001] {
            assert!(checked_text(&args, &manifest, text.as_bytes().to_vec(), at).is_err());
        }
    }

    #[test]
    fn selected_publisher_name_and_exact_manifest_are_not_substitutable() {
        let bytes = b"Selected public source";
        let (mut args, manifest) = publication(bytes, CONTENT_TYPE);
        let publisher = args.publisher_key;
        args.publisher_key = SigningKey::from_bytes(&[74; 32]).verifying_key();
        assert!(checked_text(&args, &manifest, bytes.to_vec(), 101).is_err());
        args.publisher_key = publisher;
        args.name = "different-source".into();
        assert!(checked_text(&args, &manifest, bytes.to_vec(), 101).is_err());
        args.name = "public-source".into();
        args.manifest_id[0] ^= 1;
        assert!(checked_text(&args, &manifest, bytes.to_vec(), 101).is_err());
    }

    #[test]
    fn signed_profile_size_and_whole_object_hash_are_enforced() {
        let bytes = b"Selected public source";
        let (args, manifest) = publication(bytes, "text/html");
        assert!(checked_text(&args, &manifest, bytes.to_vec(), 101).is_err());
        let (args, manifest) = publication(bytes, CONTENT_TYPE);
        let mut changed = bytes.to_vec();
        changed[0] ^= 1;
        assert!(checked_text(&args, &manifest, changed, 101).is_err());
        assert!(checked_text(&args, &manifest, bytes[1..].to_vec(), 101).is_err());
        let oversized = vec![b'x'; usize::try_from(MAX_TEXT_BYTES).unwrap() + 1];
        let (args, manifest) = publication(&oversized, CONTENT_TYPE);
        assert!(checked_text(&args, &manifest, oversized, 101).is_err());
    }

    #[test]
    fn validly_signed_binary_empty_or_nul_content_is_not_public_text() {
        for bytes in [&b""[..], &b" \t\n"[..], &b"text\0text"[..], &[0xff][..]] {
            let (args, manifest) = publication(bytes, CONTENT_TYPE);
            assert!(checked_text(&args, &manifest, bytes.to_vec(), 101).is_err());
        }
    }

    #[test]
    fn query_keeps_the_selected_cache_and_allows_protected_cache_misses() {
        let (mut args, _) = publication(b"public text", CONTENT_TYPE);
        for reuse in [false, true] {
            args.reuse_cache = reuse;
            let query = query(&args, Path::new("/unused-owner-output"));
            assert_eq!(query.publisher_key, args.publisher_key);
            assert_eq!(query.name, args.name);
            assert_eq!(query.cache, args.cache);
            assert_eq!(query.reuse_cache, reuse);
            assert!(!query.cache_only);
            assert_eq!(query.min_revision, None);
            assert_eq!(query.limits.configuration(), args.limits.configuration());
        }
    }
}
