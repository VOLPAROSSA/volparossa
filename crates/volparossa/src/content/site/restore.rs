// SPDX-License-Identifier: GPL-3.0-only
//! Activate a separately owner-signed restoration against one locked, locally observed site head.

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, bail, ensure};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use serde_json::{Value, json};
use volparossa_content::{
    ChunkStore, SignedManifest, VerifiedManifest,
    site::{SITE_CONTENT_TYPE, SiteBundle},
};

use crate::content::{
    Limits, now_seconds, parse_content_name, parse_input_sha256, parse_publisher_key,
    read_manifest_bytes,
};

#[derive(Debug, Args)]
pub(crate) struct Restore {
    /// Independently selected owner key for all three signed site releases.
    #[arg(long, value_parser = parse_publisher_key)]
    publisher_key: VerifyingKey,
    /// Exact publisher-local site name.
    #[arg(long, value_parser = parse_content_name)]
    name: String,
    /// Still-valid earlier release selected for its complete site bytes.
    #[arg(long)]
    source_manifest: PathBuf,
    /// Reviewed canonical manifest ID of the selected earlier release.
    #[arg(long, value_parser = parse_input_sha256)]
    expected_source_id: [u8; 32],
    /// Signed release the owner expects this local name to point to.
    #[arg(long)]
    current_manifest: PathBuf,
    /// Reviewed canonical manifest ID of that expected current release.
    #[arg(long, value_parser = parse_input_sha256)]
    expected_current_id: [u8; 32],
    /// Exact successor signed by the owner using content publish on the reviewed earlier bytes.
    #[arg(long)]
    candidate_manifest: PathBuf,
    /// Reviewed canonical manifest ID of that newly authorized release.
    #[arg(long, value_parser = parse_input_sha256)]
    expected_candidate_id: [u8; 32],
    /// Existing owner-controlled native cache containing the verified historical site bytes.
    #[arg(long)]
    cache: PathBuf,
    /// On first use only, establish the explicitly reviewed current release as this cache's base.
    /// Requires its complete bytes in this cache. Cannot replace a retained or conflicted head.
    #[arg(long)]
    initialize_from_reviewed_current: bool,
    #[command(flatten)]
    limits: Limits,
}

struct Release {
    signed: SignedManifest,
    verified: VerifiedManifest,
}

impl Release {
    fn read(
        path: &Path,
        expected: &[u8; 32],
        key: &VerifyingKey,
        name: &str,
        now: u64,
    ) -> Result<Self> {
        let signed = SignedManifest::decode(&read_manifest_bytes(path)?)?;
        let verified = signed.verify(key, now)?;
        ensure!(
            verified.manifest_id() == expected,
            "site manifest differs from its reviewed ID"
        );
        ensure!(
            verified.metadata().name == name
                && verified.metadata().content_type == SITE_CONTENT_TYPE,
            "expected signed native site under the selected name"
        );
        Ok(Self { signed, verified })
    }

    fn revision(&self) -> u64 {
        self.verified.metadata().revision
    }

    fn complete_site(&self, cache: &mut ChunkStore, now: u64) -> Result<()> {
        let mut bytes = Vec::new();
        bytes.try_reserve_exact(usize::try_from(self.verified.length())?)?;
        volparossa_content::reassemble(&self.verified, &mut [cache], now, &mut bytes)?;
        SiteBundle::decode(bytes)
            .context("restoration requires a complete canonical static site")?;
        Ok(())
    }
}

pub(super) fn run(args: &Restore) -> Result<Value> {
    activate_with_clock(args, now_seconds)
}

#[cfg(test)]
fn activate(args: &Restore, now: u64) -> Result<Value> {
    activate_with_clock(args, || Ok(now))
}

fn activate_with_clock(args: &Restore, clock: impl Fn() -> Result<u64>) -> Result<Value> {
    let now = clock()?;
    let read = |path: &Path, expected: &[u8; 32]| {
        Release::read(path, expected, &args.publisher_key, &args.name, now)
    };
    let source = read(&args.source_manifest, &args.expected_source_id)?;
    let current = read(&args.current_manifest, &args.expected_current_id)?;
    let candidate = read(&args.candidate_manifest, &args.expected_candidate_id)?;
    ensure!(
        source.revision() < current.revision()
            && current.revision().checked_add(1) == Some(candidate.revision()),
        "restore requires an earlier source and the exact next revision"
    );
    ensure!(
        source.verified.object_sha256() == candidate.verified.object_sha256()
            && source.verified.length() == candidate.verified.length()
            && source.verified.chunks() == candidate.verified.chunks(),
        "signed successor differs from the selected earlier site"
    );

    // ChunkStore owns the exclusive directory-bound lock until after both floor and
    // envelope writes. Never call observe on a competing equal-revision envelope.
    let mut cache = ChunkStore::open(&args.cache, args.limits.cache_limits()?)?;
    let floor = cache.name_revision_floor(args.publisher_key.as_bytes(), &args.name)?;
    let base = match floor {
        Some(pin) if pin.conflicted() => bail!("this cache has a conflicted site revision"),
        Some(pin)
            if pin.revision() == current.revision()
                && pin.manifest_id() == current.verified.manifest_id() =>
        {
            "retained_current"
        }
        Some(pin)
            if pin.revision() == candidate.revision()
                && pin.manifest_id() == candidate.verified.manifest_id() =>
        {
            "exact_candidate"
        }
        Some(_) => bail!("retained site revision differs from the reviewed head"),
        None if args.initialize_from_reviewed_current => "reviewed_initial_current",
        None => bail!(
            "this cache has no retained site head; first use requires --initialize-from-reviewed-current"
        ),
    };
    source.complete_site(&mut cache, now)?;
    if base == "reviewed_initial_current" {
        current.complete_site(&mut cache, now)?;
    }
    let commit_time = || -> Result<u64> {
        let at = clock()?;
        ensure!(at >= now, "wall clock moved backwards during restore");
        for release in [&source, &current, &candidate] {
            let validity = release.verified.validity();
            ensure!(
                (validity.created..validity.expires).contains(&at),
                "site release leaves its signed validity interval during restore"
            );
        }
        Ok(at)
    };
    if base == "reviewed_initial_current" {
        cache.remember_named_manifest(&current.signed, &args.publisher_key, commit_time()?)?;
    }
    // A previous attempt may have advanced the floor but failed to persist its
    // cached envelope. Retry only the exact already-signed candidate, never re-sign.
    cache.remember_named_manifest(&candidate.signed, &args.publisher_key, commit_time()?)?;
    Ok(json!({
        "schema_version":1, "operation":"local_site_restore", "base":base,
        "state":if base == "exact_candidate" { "already_current" } else { "activated" },
        "publisher_key":hex::encode(args.publisher_key.as_bytes()), "name":args.name,
        "source_manifest_id":hex::encode(args.expected_source_id), "source_revision":source.revision(),
        "previous_manifest_id":hex::encode(args.expected_current_id), "previous_revision":current.revision(),
        "manifest_id":hex::encode(args.expected_candidate_id), "revision":candidate.revision(),
        "bundle_sha256":hex::encode(candidate.verified.object_sha256()), "bundle_bytes":candidate.verified.length(),
        "expires_unix_seconds":candidate.verified.validity().expires,
        "predecessor_observed_in_this_operation":base != "exact_candidate",
        "network_publication":false, "globally_latest":false
    }))
}

#[cfg(test)]
mod tests;
