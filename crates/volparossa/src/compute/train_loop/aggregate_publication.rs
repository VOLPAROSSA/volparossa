//! Explicit publication of an already approved aggregation; no model execution.
//! Retries reuse one original signed manifest, never renew source authorization.

use std::{
    fs::{self, File},
    io::Write as _,
    os::unix::fs::DirBuilderExt as _,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use nix::fcntl::{Flock, FlockArg};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use volparossa_content::{SignedManifest, VerifiedManifest, agent_artifact::ADAPTER_CONTENT_TYPE};

use super::{Activity, active, aggregate, now, private_directory, read_file};
use crate::content::{self, Limits};

#[derive(Debug, Args)]
pub(crate) struct Options {
    /// Completed aggregate-adapters directory; original inputs/approval must remain live.
    #[arg(long)]
    directory: PathBuf,
    /// Explicit publisher-local adapter channel. Other nodes must independently trust it.
    #[arg(long, value_parser=content::parse_content_name)]
    publish_name: String,
    #[arg(long, value_parser=content::parse_publisher_key)]
    publication_key: VerifyingKey,
    #[arg(long, value_parser=clap::value_parser!(u64).range(1..))]
    revision: u64,
    /// Existing encrypted node identity; never created by this command.
    #[arg(long)]
    identity: PathBuf,
    #[arg(long)]
    passphrase_file: PathBuf,
    /// Existing owned public cache, distinct from the completed aggregation directory.
    #[arg(long)]
    publish_cache: PathBuf,
    /// Without this flag only recheck and preview; no signing, writes or network handoff.
    #[arg(long)]
    execute: bool,
    #[command(flatten)]
    limits: Limits,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

fn read_json(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&read_file(path, 512 * 1024)?)?)
}

fn retain(path: &Path, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= 512 * 1024,
        "aggregate_publication_record_bound"
    );
    if present(path)? {
        ensure!(
            read_file(path, 512 * 1024)? == bytes,
            "aggregate_publication_record_changed"
        );
        return Ok(());
    }
    let parent = path
        .parent()
        .context("aggregate_publication_record_parent")?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn request(args: &Options, approved: &aggregate::Approved) -> Result<Value> {
    ensure!(
        args.directory.is_absolute()
            && args.directory.canonicalize()? == args.directory
            && args.revision > 0,
        "aggregate_publication_directory_or_revision"
    );
    content::parse_content_name(&args.publish_name).map_err(anyhow::Error::msg)?;
    for path in [&args.identity, &args.passphrase_file, &args.publish_cache] {
        ensure!(
            path.is_absolute()
                && !path.starts_with(&args.directory)
                && !args.directory.starts_with(path),
            "aggregate_publication_path_overlap"
        );
    }
    Ok(
        json!({"version":1,"operation":"compute_publish_aggregate","publication_kind":"adapter_aggregation",
        "directory":args.directory,"approval":approved.identity,
        "bundle":{"bytes":approved.bundle.len(),"sha256":digest(&approved.bundle)},
        "publisher_key":hex::encode(args.publication_key.as_bytes()),"name":args.publish_name,
        "revision":args.revision,"identity":args.identity,"passphrase_file":args.passphrase_file,
        "cache":args.publish_cache,"limits":args.limits.configuration(),
        "expires_not_after":approved.expires,"maximum_lifetime_seconds":3600,
        "optimizer_steps":0,"model_activated":false,"remote_training_attestation":false,
        "general_quality_proven":false}),
    )
}

fn manifest(
    path: &Path,
    args: &Options,
    approved: &aggregate::Approved,
    at: u64,
) -> Result<VerifiedManifest> {
    let signed = SignedManifest::decode(&read_file(path, 64 * 1024)?)?;
    let verified = signed.verify(&args.publication_key, at)?;
    ensure!(
        verified.metadata().name == args.publish_name
            && verified.metadata().revision == args.revision
            && verified.metadata().content_type == ADAPTER_CONTENT_TYPE
            && verified.length() == approved.bundle.len() as u64
            && verified.object_sha256() == &<[u8; 32]>::from(Sha256::digest(&approved.bundle))
            && verified.validity().expires <= approved.expires
            && verified
                .validity()
                .expires
                .saturating_sub(verified.validity().created)
                <= 3600,
        "aggregate_publication_original_manifest_binding"
    );
    Ok(verified)
}

fn publication_record(verified: &VerifiedManifest, raw: &[u8]) -> Value {
    json!({"manifest_id":hex::encode(verified.manifest_id()),"manifest_sha256":digest(raw),
        "created":verified.validity().created,"expires":verified.validity().expires})
}

fn validate_receipt(receipt: &Value, verified: &VerifiedManifest) -> Result<()> {
    ensure!(
        receipt["operation"] == "content_contribute"
            && receipt["network_publication"] == true
            && receipt["serving"] == true
            && receipt["publications"].as_u64().is_some_and(|n| n > 0)
            && receipt["manifest_id"] == hex::encode(verified.manifest_id())
            && receipt["publisher_key_hex"] == hex::encode(verified.publisher())
            && receipt["name"] == verified.metadata().name
            && receipt["revision"] == verified.metadata().revision
            && receipt["content_type"] == ADAPTER_CONTENT_TYPE
            && receipt["bytes"] == verified.length()
            && receipt["chunks"].as_u64() == u64::try_from(verified.chunks().len()).ok()
            && receipt["expires_unix_seconds"] == verified.validity().expires
            && receipt["original_signature_reused"] == true
            && receipt["private_keys_transferred"] == false
            && receipt["ownership_changed"] == false
            && receipt["origin_authenticated"] == false,
        "aggregate_publication_contribution_binding"
    );
    Ok(())
}

#[allow(
    clippy::too_many_lines,
    reason = "One explicit original-object sign/retain/handoff transaction"
)]
pub(in crate::compute) async fn run(args: &Options, socket: &Path) -> Result<()> {
    let approved = aggregate::reopen_approved(&args.directory, &args.limits, now()?)?;
    let authorization = request(args, &approved)?;
    let root = args.directory.join("publication");
    if present(&root)? {
        private_directory(&root)?;
        if present(&root.join("request.json"))? {
            ensure!(
                read_json(&root.join("request.json"))? == authorization,
                "aggregate_publication_authorization_changed"
            );
        }
    }
    if !args.execute {
        println!(
            "{}",
            serde_json::to_string_pretty(&json!({"operation":"compute_publish_aggregate",
            "execute":false,"authorization":authorization,"network_publication":false,"model_activated":false}))?
        );
        return Ok(());
    }
    let activity = Activity::new()?;
    if !present(&root)? {
        fs::DirBuilder::new().mode(0o700).create(&root)?;
        File::open(&args.directory)?.sync_all()?;
    }
    private_directory(&root)?;
    // A directory flock serializes only this explicit publication, not a scheduler.
    let _lock = Flock::lock(File::open(&root)?, FlockArg::LockExclusiveNonblock)
        .map_err(|_| anyhow::anyhow!("aggregate_publication_busy"))?;
    retain(&root.join("request.json"), &authorization)?;
    ensure!(
        active(&activity.receiver) && now()? < approved.expires,
        "aggregate_publication_cancelled_or_expired"
    );
    let path = root.join("publication.pb");
    let reused = present(&path)?;
    if !reused {
        // Check expected signer before writing a manifest/cache object. The content
        // API independently unlocks it for the actual signature; neither key leaves this process.
        let signer = content::unlock_signer(Some(&args.identity), Some(&args.passphrase_file))?;
        ensure!(
            signer.verifying_key() == args.publication_key,
            "aggregate_publication_identity_mismatch"
        );
        drop(signer);
        let publication = content::Publish::adapter_bundle(content::AdapterPublication {
            input: args.directory.join("adapter.bundle"),
            cache: args.publish_cache.clone(),
            reuse_cache: true,
            manifest: path.clone(),
            name: args.publish_name.clone(),
            revision: args.revision,
            lifetime_seconds: 3600,
            expires_not_after: approved.expires,
            identity: args.identity.clone(),
            passphrase_file: args.passphrase_file.clone(),
            limits: args.limits.clone(),
        });
        let _offline = content::publish_command(&publication, socket).await?;
        File::open(&root)?.sync_all()?;
    }
    let verified = manifest(&path, args, &approved, now()?)?;
    let signed_bytes = read_file(&path, 64 * 1024)?;
    let record = publication_record(&verified, &signed_bytes);
    retain(&root.join("manifest.json"), &record)?;
    // Retrying after a crash or failed handoff reuses the frozen original bytes.
    let current = aggregate::reopen_approved(&args.directory, &args.limits, now()?)?;
    ensure!(
        current.identity == approved.identity && current.bundle == approved.bundle,
        "aggregate_publication_approval_changed"
    );
    let contribution = content::Contribute::existing(
        path.clone(),
        args.publication_key,
        args.publish_cache.clone(),
        args.limits.clone(),
    )
    .expect_manifest_id(*verified.manifest_id());
    let seconds = verified.validity().expires.saturating_sub(now()?).min(60);
    ensure!(
        seconds > 0 && active(&activity.receiver),
        "aggregate_publication_cancelled_or_expired"
    );
    let mut changed = activity.receiver.clone();
    let mut receipt = tokio::select! { biased;
        _ = changed.changed() => anyhow::bail!("aggregate_publication_cancelled_original_retained"),
        result = tokio::time::timeout(Duration::from_secs(seconds), content::contribute_existing(&contribution, socket)) =>
            result.context("aggregate_publication_handoff_deadline_original_retained")??,
    };
    validate_receipt(&receipt, &verified)?;
    let observed = now()?;
    ensure!(
        observed >= verified.validity().created
            && observed < verified.validity().expires
            && read_file(&path, 64 * 1024)? == signed_bytes,
        "aggregate_publication_expired_or_changed"
    );
    // This local observation is not a portable execution/training attestation.
    receipt["coordinator_verified_at_unix_seconds"] = observed.into();
    let receipt_path = root.join("contribution.json");
    if present(&receipt_path)? {
        let original = read_json(&receipt_path)?;
        validate_receipt(&original, &verified)?;
        ensure!(
            original["coordinator_verified_at_unix_seconds"]
                .as_u64()
                .is_some_and(|at| verified.validity().created <= at
                    && at < verified.validity().expires
                    && at <= observed),
            "aggregate_publication_original_receipt_time"
        );
        // Keep the first receipt byte-for-byte; this invocation just confirmed a fresh handoff.
    } else {
        retain(&receipt_path, &receipt)?;
    }
    println!(
        "{}",
        serde_json::to_string_pretty(&json!({"version":1,"operation":"compute_publish_aggregate",
        "publication_kind":"adapter_aggregation","network_publication":true,"content_serving":true,
        "publication":record,"existing_manifest_reused":reused,"contribution":receipt,
        "original_contribution_sha256":digest(&read_file(&receipt_path,512*1024)?),
        "approval":approved.identity,"optimizer_steps":0,"model_activated":false,
        "remote_training_attestation":false,"general_quality_proven":false,
        "receiver_requires_independent_publisher_trust_and_local_evaluation":true}))?
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt as _;

    use super::*;
    use clap::Parser as _;
    use ed25519_dalek::SigningKey;
    use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity};

    #[derive(clap::Parser)]
    struct Cli {
        #[command(flatten)]
        args: Options,
    }

    fn arguments(root: &Path, key: &VerifyingKey) -> Options {
        Cli::try_parse_from([
            "publication",
            "--directory",
            root.to_str().unwrap(),
            "--publish-name",
            "combined",
            "--publication-key",
            &hex::encode(key.as_bytes()),
            "--revision",
            "7",
            "--identity",
            "/owner/identity",
            "--passphrase-file",
            "/owner/passphrase",
            "--publish-cache",
            "/owner/cache",
        ])
        .unwrap()
        .args
    }

    #[test]
    fn retained_authorization_and_receipts_are_never_overwritten() {
        let root = tempfile::tempdir().unwrap();
        let path = root.path().join("request.json");
        let original = json!({"kind":"aggregate","expires":1250,"optimizer_steps":0});
        retain(&path, &original).unwrap();
        let bytes = read_file(&path, 4096).unwrap();
        retain(&path, &original).unwrap();
        assert!(
            retain(
                &path,
                &json!({"kind":"aggregate","expires":1300,"optimizer_steps":0})
            )
            .is_err()
        );
        assert_eq!(read_file(&path, 4096).unwrap(), bytes);
    }

    #[test]
    fn one_original_signature_binds_key_name_revision_bundle_and_absolute_expiry() {
        let root = tempfile::tempdir().unwrap();
        let key = SigningKey::from_bytes(&[119; 32]);
        let args = arguments(root.path(), &key.verifying_key());
        // Opaque bytes test publication binding only, never aggregation or quality.
        let mut approved = aggregate::Approved {
            bundle: b"opaque test adapter".to_vec(),
            expires: 1300,
            identity: json!({}),
        };
        let mut cache = ChunkStore::create(
            &root.path().join("cache"),
            CacheLimits {
                max_bytes: 1024,
                max_entries: 4,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let signed = volparossa_content::publish(
            &mut approved.bundle.as_slice(),
            Publication {
                metadata: Metadata {
                    name: args.publish_name.clone(),
                    revision: args.revision,
                    content_type: ADAPTER_CONTENT_TYPE.into(),
                },
                length: approved.bundle.len() as u64,
                validity: Validity {
                    created: 1000,
                    expires: 1250,
                },
            },
            &key,
            &mut cache,
        )
        .unwrap();
        let path = root.path().join("publication.pb");
        fs::write(&path, signed.encode()).unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        let first = manifest(&path, &args, &approved, 1001).unwrap();
        let retry = manifest(&path, &args, &approved, 1249).unwrap();
        assert_eq!(first.manifest_id(), retry.manifest_id());
        assert_eq!(retry.validity().expires, 1250);
        assert!(manifest(&path, &args, &approved, 1250).is_err());
        approved.expires = 1240;
        assert!(manifest(&path, &args, &approved, 1001).is_err());
        approved.expires = 1300;
        approved.bundle[0] ^= 1;
        assert!(manifest(&path, &args, &approved, 1001).is_err());
        approved.bundle[0] ^= 1;
        let mut different = arguments(root.path(), &key.verifying_key());
        different.publish_name = "other".into();
        assert!(manifest(&path, &different, &approved, 1001).is_err());
        different.publish_name = args.publish_name.clone();
        different.revision += 1;
        assert!(manifest(&path, &different, &approved, 1001).is_err());
        different.revision = args.revision;
        different.publication_key = SigningKey::from_bytes(&[120; 32]).verifying_key();
        assert!(manifest(&path, &different, &approved, 1001).is_err());
    }
}
