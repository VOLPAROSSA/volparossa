//! Explicit signed public filter data export, not subscription or browser-policy activation.

use std::{
    fs::{self, File, OpenOptions},
    io::Write as _,
    os::unix::fs::{MetadataExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Component, Path, PathBuf},
};

use anyhow::{Result, ensure};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use volparossa_content::{SignedManifest, VerifiedManifest};

use super::{Limits, ensure_new_output, now_seconds, output_parent, public_text};

const MAX_BYTES: usize = 1024 * 1024;
const MAX_RULES: usize = 4096;
const MAX_LINES: usize = 8192;
const HEADER: &str = "[Adblock Plus 2.0]";

#[derive(Debug, Args)]
#[group(id = "ContentFilterSnapshotOptions")]
pub(crate) struct Options {
    /// Independently authorized publisher key; never inferred from a provider or manifest.
    #[arg(long, value_parser = super::parse_publisher_key)]
    publisher_key: VerifyingKey,
    /// Exact immutable publisher-local snapshot name, not a browsing hostname.
    #[arg(long, value_parser = super::parse_content_name)]
    name: String,
    /// Exact canonical signed-envelope SHA-256, independently selected before retrieval.
    #[arg(long, value_parser = parse_manifest_id)]
    manifest_id: [u8; 32],
    /// Acknowledge that this exact publisher/name/manifest is authorized as filter data.
    #[arg(long, required = true)]
    authorize_filter_publisher: bool,
    /// Explicitly acknowledge public content; no browsing history or private source input.
    #[arg(long, required = true)]
    public_content: bool,
    /// Agent-owned source cache; a miss uses the existing protected content path.
    #[arg(long)]
    cache: PathBuf,
    /// Reopen an owned cache without resetting revision floors or renewing validity.
    #[arg(long)]
    reuse_cache: bool,
    /// NEW absolute directory beneath an owned, non-writable-by-others directory.
    /// Contains exact filters.txt, manifest.pb, delivery-receipt.json and snapshot.json.
    #[arg(long)]
    output: PathBuf,
    #[command(flatten)]
    limits: Limits,
}

fn parse_manifest_id(value: &str) -> Result<[u8; 32], String> {
    let mut id = [0; 32];
    if hex::decode_to_slice(value, &mut id).is_err() || id == [0; 32] {
        return Err("filter snapshot requires a nonzero 32-byte manifest hash".into());
    }
    Ok(id)
}

impl Options {
    fn selection(&self) -> public_text::TextSource {
        public_text::TextSource {
            publisher_key: self.publisher_key,
            name: self.name.clone(),
            manifest_id: self.manifest_id,
            cache: self.cache.clone(),
            reuse_cache: self.reuse_cache,
            limits: self.limits.clone(),
        }
    }
}

pub(crate) async fn run(args: &Options, socket: &Path) -> Result<Value> {
    ensure!(
        args.authorize_filter_publisher && args.public_content,
        "filter_snapshot_explicit_public_authority_required"
    );
    validate_output(&args.output)?;
    let pending = tempfile::Builder::new()
        .prefix(".filter-snapshot-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(output_parent(&args.output))?;
    let download =
        public_text::fetch_text_source(&args.selection(), socket, pending.path()).await?;
    persist(args, &download, pending)
}

fn validate_output(output: &Path) -> Result<()> {
    ensure!(
        output.is_absolute()
            && output.file_name().is_some()
            && output
                .components()
                .all(|part| matches!(part, Component::RootDir | Component::Normal(_))),
        "filter_snapshot_output_requires_absolute_new_directory"
    );
    ensure_new_output(output)?;
    let parent = output_parent(output);
    let metadata = fs::symlink_metadata(parent)?;
    ensure!(
        metadata.is_dir()
            && !metadata.file_type().is_symlink()
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.mode() & 0o022 == 0
            && parent.canonicalize()? == parent,
        "filter_snapshot_output_parent_not_owned_or_safe"
    );
    Ok(())
}

/// This is intentionally not a general uBO parser. No transformations are applied.
fn rule_count(text: &str) -> Result<usize> {
    ensure!(
        !text.is_empty() && text.len() <= MAX_BYTES && text.is_ascii(),
        "filter_snapshot_text_bound"
    );
    let mut rules = 0;
    for (index, line) in text.split('\n').enumerate() {
        ensure!(index < MAX_LINES, "filter_snapshot_line_bound");
        let line = line.strip_suffix('\r').unwrap_or(line);
        if line.is_empty() || (index == 0 && line == HEADER) {
            continue;
        }
        ensure!(line.len() <= 257, "filter_snapshot_rule_length_bound");
        let domain = line
            .strip_prefix("||")
            .and_then(|value| value.strip_suffix('^'))
            .ok_or_else(|| anyhow::anyhow!("filter_snapshot_unsupported_rule"))?;
        let labels: Vec<_> = domain.split('.').collect();
        ensure!(
            domain.len() <= 253
                && labels.len() >= 2
                && labels.iter().all(|label| {
                    !label.is_empty()
                        && label.len() <= 63
                        && !label.starts_with('-')
                        && !label.ends_with('-')
                        && label.bytes().all(|byte| {
                            byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-'
                        })
                })
                && labels.last().is_some_and(|label| {
                    label.len() >= 2 && label.bytes().all(|byte| byte.is_ascii_lowercase())
                }),
            "filter_snapshot_domain_not_canonical"
        );
        rules += 1;
        ensure!(rules <= MAX_RULES, "filter_snapshot_rule_bound");
    }
    ensure!(rules > 0, "filter_snapshot_requires_domain_rules");
    Ok(rules)
}

fn check_download(
    args: &Options,
    download: &public_text::TextDownload,
    now: u64,
) -> Result<(VerifiedManifest, usize)> {
    let manifest =
        SignedManifest::decode(&download.signed_manifest)?.verify(&args.publisher_key, now)?;
    ensure!(
        manifest.metadata().name == args.name
            && manifest.manifest_id() == &args.manifest_id
            && manifest.metadata().content_type == "text/plain"
            && manifest.length() == u64::try_from(download.text.len())?
            && manifest.validity().expires == download.expires
            && manifest.validity().created <= download.verified_at
            && download.verified_at <= now
            && download.verified_at < download.expires
            && manifest.object_sha256()
                == &<[u8; 32]>::from(Sha256::digest(download.text.as_bytes())),
        "filter_snapshot_selected_publication_mismatch"
    );
    Ok((manifest, rule_count(&download.text)?))
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn persist(
    args: &Options,
    download: &public_text::TextDownload,
    pending: tempfile::TempDir,
) -> Result<Value> {
    let (manifest, rules) = check_download(args, download, now_seconds()?)?;
    let receipt = serde_json::to_vec(&download.receipt)?;
    ensure!(receipt.len() <= 16 * 1024, "filter_snapshot_receipt_bound");
    let report = serde_json::json!({
        "version": 1, "operation": "content_filter_snapshot", "visibility": "public",
        "grammar": "ubo-domain-block-v1", "rules": rules, "bytes": manifest.length(),
        "publisher_key": hex::encode(manifest.publisher()), "name": manifest.metadata().name,
        "manifest_id": hex::encode(manifest.manifest_id()), "revision": manifest.metadata().revision,
        "sha256": hex::encode(manifest.object_sha256()), "verified_at_unix_seconds": download.verified_at,
        "expires_unix_seconds": manifest.validity().expires, "globally_latest": false,
        "delivery_receipt_file": "delivery-receipt.json", "delivery_receipt_is_signed_attestation": false,
        "browser_configuration_changed": false, "subscription_installed": false,
        "output": args.output,
    });
    write_new(
        &pending.path().join("filters.txt"),
        download.text.as_bytes(),
    )?;
    write_new(
        &pending.path().join("manifest.pb"),
        &download.signed_manifest,
    )?;
    write_new(&pending.path().join("delivery-receipt.json"), &receipt)?;
    write_new(
        &pending.path().join("snapshot.json"),
        &serde_json::to_vec(&report)?,
    )?;
    File::open(pending.path())?.sync_all()?;
    // Original expiry remains binding after staging; no stale output becomes an update.
    check_download(args, download, now_seconds()?)?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        pending.path(),
        rustix::fs::CWD,
        &args.output,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    drop(pending);
    File::open(output_parent(&args.output))?.sync_all()?;
    Ok(report)
}

#[cfg(test)]
mod tests;
