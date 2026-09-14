//! Explicit model artifacts reuse the signed content plane, not an executable update channel.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt, PermissionsExt},
    path::{Path, PathBuf},
};

use anyhow::{Context, Result, ensure};
use clap::{Args, Subcommand};
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use volparossa_content::{
    SignedManifest,
    agent_artifact::{
        ADAPTER_CONTENT_TYPE, AdapterBundle, AdapterFiles, BASE_MODEL_SHA256, MAX_ADAPTER_BYTES,
        MODEL_ID, MODEL_REVISION,
    },
};

use super::{FetchName, Limits, ensure_new_output, named_download, now_seconds, output_parent};

const DATASET_CONTENT_TYPE: &str = "application/vnd.volparossa.agent-dataset.v1+json";
const MAX_DATASET: u64 = 1024 * 1024;
const MAX_SMALL_FILE: u64 = 16 * 1024;
const MAX_WEIGHTS: u64 = 2 * 1024 * 1024;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Pack actual training outputs, bound to the signed public dataset used by that job.
    Pack(Box<Pack>),
    /// Retrieve and verify an adapter and its bound public dataset; does not activate a model.
    Fetch(Box<Fetch>),
}

#[derive(Debug, Args)]
pub(crate) struct Pack {
    /// Private directory with exactly the three fixed saved adapter files.
    #[arg(long)]
    directory: PathBuf,
    /// Actual successful training report from the fixed CPU worker.
    #[arg(long)]
    training_report: PathBuf,
    /// Original signed manifest of that public dataset, previously explicitly published.
    #[arg(long)]
    dataset_manifest: PathBuf,
    /// Independently trusted publisher of the dataset, not a key adopted from its manifest.
    #[arg(long, value_parser = super::parse_publisher_key)]
    publisher_key: VerifyingKey,
    /// New private bundle file; publish with the reported content type and ordinary content CLI.
    #[arg(long)]
    output: PathBuf,
}

impl Pack {
    pub(crate) fn completed_training(
        directory: PathBuf,
        training_report: PathBuf,
        dataset_manifest: PathBuf,
        publisher_key: VerifyingKey,
        output: PathBuf,
    ) -> Self {
        Self {
            directory,
            training_report,
            dataset_manifest,
            publisher_key,
            output,
        }
    }
}

/// Explicit source selection; availability never chooses a different training publication.
pub(crate) struct TrainingSource {
    pub(crate) publisher_key: VerifyingKey,
    pub(crate) name: String,
    pub(crate) manifest_id: Option<[u8; 32]>,
    pub(crate) min_revision: Option<u64>,
    pub(crate) cache: PathBuf,
    pub(crate) reuse_cache: bool,
    pub(crate) limits: Limits,
}

pub(crate) struct TrainingDownload {
    pub(crate) signed_manifest: Vec<u8>,
    pub(crate) dataset: Vec<u8>,
    pub(crate) receipt: Value,
    pub(crate) expires: u64,
}

pub(crate) async fn fetch_training_source(
    args: &TrainingSource,
    socket: &Path,
    private_parent: &Path,
) -> Result<TrainingDownload> {
    let query = FetchName {
        publisher_key: args.publisher_key,
        name: args.name.clone(),
        min_revision: args.min_revision,
        cache: args.cache.clone(),
        reuse_cache: args.reuse_cache,
        cache_only: false,
        local_output: private_parent.join("unused-output"),
        limits: args.limits.clone(),
    };
    let download = named_download::prepare_bounded(
        &query,
        socket,
        private_parent,
        &named_download::Requirement {
            content_type: DATASET_CONTENT_TYPE,
            maximum_bytes: MAX_DATASET,
            manifest_id: args.manifest_id,
        },
    )
    .await?;
    let dataset = read_download(download.as_file(), MAX_DATASET)?;
    download.check_live()?;
    Ok(TrainingDownload {
        signed_manifest: download.signed_manifest().encode(),
        dataset,
        receipt: download.report(),
        expires: download.expires(),
    })
}

#[derive(Debug, Args)]
pub(crate) struct Fetch {
    /// Independently trusted publisher of both the adapter and dataset.
    #[arg(long, value_parser = super::parse_publisher_key)]
    publisher_key: VerifyingKey,
    /// Exact publisher-local adapter name.
    #[arg(long, value_parser = super::parse_content_name)]
    name: String,
    /// Dataset name; the returned manifest must match the exact identity in the adapter.
    #[arg(long, value_parser = super::parse_content_name)]
    dataset_name: String,
    /// Minimum adapter revision; not a globally latest-version claim.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    min_revision: Option<u64>,
    /// Agent-owned cache used for both objects, distinct from the user-owned output.
    #[arg(long)]
    cache: PathBuf,
    /// Reopen an existing agent cache instead of creating one.
    #[arg(long)]
    reuse_cache: bool,
    /// Require both complete objects already in the existing cache, without network I/O.
    #[arg(long, requires = "reuse_cache")]
    cache_only: bool,
    /// New private local directory holding adapter/, dataset.json and provenance.json.
    #[arg(long)]
    output: PathBuf,
    #[command(flatten)]
    limits: Limits,
}

pub(super) async fn run(command: Command, socket: &Path) -> Result<()> {
    let report = match command {
        Command::Pack(args) => pack(&args)?,
        Command::Fetch(args) => fetch(&args, socket).await?,
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

pub(crate) fn pack(args: &Pack) -> Result<Value> {
    ensure_new_output(&args.output)?;
    private_directory(&args.directory)?;
    let report: Value = serde_json::from_slice(&read_file(&args.training_report, MAX_SMALL_FILE)?)?;
    ensure!(
        report["model"]["id"] == MODEL_ID
            && report["model"]["revision"] == MODEL_REVISION
            && report["model"]["files"]["model.safetensors"]["sha256"].as_str()
                == Some(hex::encode(BASE_MODEL_SHA256).as_str()),
        "agent_artifact_training_base_model"
    );
    ensure!(
        report["status"] == "ok" && report["mode"] == "train" && report["device"] == "cpu",
        "agent_artifact_training_report"
    );
    ensure!(
        report["updates_completed"]
            .as_u64()
            .is_some_and(|n| n > 0 && n <= 64),
        "agent_artifact_training_steps"
    );
    for field in [
        "base_weights_unchanged",
        "adapter_weights_changed",
        "checkpoint_reloaded",
    ] {
        ensure!(report[field] == true, "agent_artifact_training_proof");
    }
    ensure!(
        report["dataset"]["visibility"] == "public"
            && report["dataset"]["license"] == "GPL-3.0-only",
        "agent_artifact_private_dataset"
    );
    let signed = SignedManifest::decode(&read_file(&args.dataset_manifest, 64 * 1024)?)?;
    let dataset = signed.verify(&args.publisher_key, now_seconds()?)?;
    ensure!(
        dataset.metadata().content_type == DATASET_CONTENT_TYPE && dataset.length() <= MAX_DATASET,
        "agent_artifact_dataset_type"
    );
    ensure!(
        report["dataset"]["bytes"].as_u64() == Some(dataset.length())
            && report["dataset"]["sha256"].as_str()
                == Some(hex::encode(dataset.object_sha256()).as_str()),
        "agent_artifact_training_dataset_mismatch"
    );
    let mut names = fs::read_dir(&args.directory)?
        .map(|entry| entry.map(|entry| entry.file_name()))
        .collect::<std::io::Result<Vec<_>>>()?;
    names.sort();
    ensure!(
        names
            == [
                "README.md",
                "adapter_config.json",
                "adapter_model.safetensors"
            ]
            .map(std::ffi::OsString::from),
        "agent_artifact_file_set"
    );
    let files = AdapterFiles {
        config: read_file(&args.directory.join("adapter_config.json"), MAX_SMALL_FILE)?,
        weights: read_file(
            &args.directory.join("adapter_model.safetensors"),
            MAX_WEIGHTS,
        )?,
        readme: read_file(&args.directory.join("README.md"), MAX_SMALL_FILE)?,
    };
    validate_training_files(&report, &files)?;
    let bytes = AdapterBundle::encode(*dataset.manifest_id(), files)?;
    let mut temporary = tempfile::NamedTempFile::new_in(output_parent(&args.output))?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temporary.write_all(&bytes)?;
    temporary.as_file().sync_all()?;
    temporary
        .persist_noclobber(&args.output)
        .map_err(|error| error.error)?;
    File::open(output_parent(&args.output))?.sync_all()?;
    Ok(serde_json::json!({
        "operation": "agent_artifact_pack", "content_type": ADAPTER_CONTENT_TYPE,
        "dataset_content_type": DATASET_CONTENT_TYPE, "bytes": bytes.len(),
        "sha256": hex::encode(Sha256::digest(&bytes)), "output": args.output,
        "dataset_manifest_id": hex::encode(dataset.manifest_id()),
        "dataset_name": dataset.metadata().name, "dataset_expires": dataset.validity().expires,
        "network_published": false, "model_activated": false,
        "training_report_is_publisher_supplied": true, "model_quality_proven": false
    }))
}

fn validate_training_files(report: &Value, files: &AdapterFiles) -> Result<()> {
    let artifacts = report["artifacts"]
        .as_array()
        .context("agent_artifact_report_files")?;
    ensure!(artifacts.len() == 3, "agent_artifact_report_files");
    for (artifact, (name, bytes)) in artifacts.iter().zip([
        ("adapter/README.md", &files.readme),
        ("adapter/adapter_config.json", &files.config),
        ("adapter/adapter_model.safetensors", &files.weights),
    ]) {
        ensure!(
            artifact["relative_path"] == name
                && artifact["bytes"].as_u64() == Some(bytes.len() as u64)
                && artifact["sha256"].as_str() == Some(hex::encode(Sha256::digest(bytes)).as_str()),
            "agent_artifact_report_hash"
        );
    }
    Ok(())
}

impl Fetch {
    fn query(&self, name: &str, reuse_cache: bool, parent: &Path) -> FetchName {
        FetchName {
            publisher_key: self.publisher_key,
            name: name.to_owned(),
            min_revision: (name == self.name).then_some(self.min_revision).flatten(),
            cache: self.cache.clone(),
            reuse_cache,
            cache_only: self.cache_only,
            local_output: parent.join("unused-output"),
            limits: Limits {
                quota_bytes: self.limits.quota_bytes,
                max_entries: self.limits.max_entries,
                min_free_bytes: self.limits.min_free_bytes,
            },
        }
    }
}

async fn fetch(args: &Fetch, socket: &Path) -> Result<Value> {
    ensure_new_output(&args.output)?;
    let parent = output_parent(&args.output);
    private_directory(parent)?;
    // This private staging directory is never visible as a completed import before both
    // publisher-authenticated objects, exact dataset binding and output hashes succeed.
    let staging = tempfile::Builder::new()
        .prefix(".agent-import-")
        .tempdir_in(parent)?;
    let adapter = named_download::prepare(
        &args.query(&args.name, args.reuse_cache, staging.path()),
        socket,
        staging.path(),
    )
    .await?;
    ensure!(
        adapter.manifest().metadata().content_type == ADAPTER_CONTENT_TYPE
            && adapter.manifest().length() <= MAX_ADAPTER_BYTES as u64,
        "agent_artifact_type"
    );
    let bundle =
        AdapterBundle::decode(read_download(adapter.as_file(), MAX_ADAPTER_BYTES as u64)?)?;
    let dataset = named_download::prepare(
        &args.query(&args.dataset_name, true, staging.path()),
        socket,
        staging.path(),
    )
    .await?;
    ensure!(
        dataset.manifest().metadata().content_type == DATASET_CONTENT_TYPE
            && dataset.manifest().length() <= MAX_DATASET,
        "agent_artifact_dataset_type"
    );
    ensure!(
        *dataset.manifest().manifest_id() == bundle.dataset_manifest_id(),
        "agent_artifact_dataset_identity"
    );
    let dataset_bytes = read_download(dataset.as_file(), MAX_DATASET)?;
    validate_public_dataset(&dataset_bytes)?;
    let adapter_root = staging.path().join("adapter");
    fs::DirBuilder::new().mode(0o700).create(&adapter_root)?;
    write_new(&adapter_root.join("adapter_config.json"), bundle.config())?;
    write_new(
        &adapter_root.join("adapter_model.safetensors"),
        bundle.weights(),
    )?;
    write_new(&adapter_root.join("README.md"), bundle.readme())?;
    write_new(&staging.path().join("dataset.json"), &dataset_bytes)?;
    File::open(&adapter_root)?.sync_all()?;
    adapter.check_live()?;
    dataset.check_live()?;
    let report = serde_json::json!({
        "operation": "agent_artifact_fetch", "publisher": hex::encode(args.publisher_key.to_bytes()),
        "adapter_manifest_id": hex::encode(adapter.manifest().manifest_id()),
        "dataset_manifest_id": hex::encode(dataset.manifest().manifest_id()),
        "adapter_receipt": adapter.report(), "dataset_receipt": dataset.report(),
        "expires_unix_seconds": adapter.expires().min(dataset.expires()),
        "output": args.output, "adapter_root": args.output.join("adapter"),
        "dataset": args.output.join("dataset.json"), "cache_only": args.cache_only,
        "model_activated": false, "remote_execution": false, "private_data_supported": false,
        "model_quality_proven": false
    });
    write_new(
        &staging.path().join("provenance.json"),
        &serde_json::to_vec(&report)?,
    )?;
    // Download temporaries are disposed before publishing the fixed final file set.
    drop(adapter);
    drop(dataset);
    File::open(staging.path())?.sync_all()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staging.path(),
        rustix::fs::CWD,
        &args.output,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    File::open(parent)?.sync_all()?;
    Ok(report)
}

fn validate_public_dataset(bytes: &[u8]) -> Result<()> {
    let data: Value = serde_json::from_slice(bytes)?;
    ensure!(
        data["version"] == 1 && data["visibility"] == "public" && data["license"] == "GPL-3.0-only",
        "agent_artifact_public_dataset"
    );
    ensure!(
        data["source_revision"]
            .as_str()
            .is_some_and(|s| s.len() == 40
                && s.bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))),
        "agent_artifact_dataset_source"
    );
    // The fixed worker independently validates the complete bounded sample/token schema.
    // A public declaration and signature are not proof of rights or training quality.
    Ok(())
}

fn read_download(file: &File, maximum: u64) -> Result<Vec<u8>> {
    use std::os::unix::fs::FileExt;
    let size = file.metadata()?.len();
    ensure!(size <= maximum, "agent_artifact_download_size");
    let mut bytes = vec![0; usize::try_from(size)?];
    file.read_exact_at(&mut bytes, 0)?;
    Ok(bytes)
}

fn read_file(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    super::open_regular(path, maximum)?
        .take(maximum + 1)
        .read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= maximum, "agent_artifact_file_size");
    Ok(bytes)
}

fn private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.mode() & 0o777 == 0o700,
        "agent_artifact_private_directory"
    );
    Ok(())
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests;
