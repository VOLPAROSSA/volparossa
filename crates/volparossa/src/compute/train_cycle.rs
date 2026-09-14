//! One explicitly authorized public training cycle; no autonomous source/model downloads.

use std::{
    fs::{self, File},
    io::Write,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail, ensure};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use volparossa_content::{
    SignedManifest,
    provider::compute::dataset::{VerifiedPublicDataset, verify_source},
};

use super::{MAX_LINE_BYTES, Mode, execute, is_hex, private_directory, read_file};
use crate::content::{
    Limits,
    agent_artifact::{self, TrainingDownload, TrainingSource},
};

#[derive(Debug, Args)]
pub(crate) struct Options {
    /// Independently trusted publisher of the explicitly selected public dataset.
    #[arg(long, value_parser = crate::content::parse_publisher_key)]
    publisher_key: VerifyingKey,
    /// Exact publisher-local dataset name, chosen independently of what happens to be cached.
    #[arg(long, value_parser = crate::content::parse_content_name)]
    dataset_name: String,
    /// Optional exact signed identity; a mismatch never authorizes a different cached dataset.
    #[arg(long, value_parser = parse_manifest_id)]
    dataset_manifest_id: Option<[u8; 32]>,
    /// Signed revision floor, not proof of the globally newest publication.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    min_revision: Option<u64>,
    /// Agent-owned native cache. A miss falls back to protected retrieval of this same source.
    #[arg(long)]
    cache: PathBuf,
    #[arg(long)]
    reuse_cache: bool,
    /// Existing explicitly provisioned fixed Python runtime; never installed by this command.
    #[arg(long)]
    runtime_root: PathBuf,
    /// Existing pinned base model; never downloaded by this command.
    #[arg(long)]
    model_root: PathBuf,
    /// Optional explicitly imported compatible adapter. Fetch/import is a separate operation.
    #[arg(long)]
    adapter_root: Option<PathBuf>,
    /// New private cycle directory. Failures retain partial evidence; nothing is overwritten.
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..=64))]
    steps: u16,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u16).range(1..=2))]
    threads: u16,
    /// Training deadline, additionally bounded by source expiry; retrieval has its own 600s bound.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u16).range(1..=600))]
    max_seconds: u16,
    /// Pause this explicitly authorized background cycle under CPU/IO pressure.
    #[arg(long)]
    spare_capacity: bool,
    /// Explicitly authorize this one cycle. Default preview performs no retrieval or training.
    #[arg(long)]
    execute: bool,
    #[command(flatten)]
    limits: Limits,
}

struct Activity {
    idle: watch::Receiver<bool>,
    listener: tokio::task::JoinHandle<()>,
}

impl Activity {
    fn new() -> Result<Self> {
        let mut signal = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let (sender, idle) = watch::channel(true);
        let listener = tokio::spawn(async move {
            if signal.recv().await.is_some() {
                let _ = sender.send(false);
            }
        });
        Ok(Self { idle, listener })
    }
}

impl Drop for Activity {
    fn drop(&mut self) {
        self.listener.abort();
    }
}

pub(super) async fn run(args: &Options, socket: &Path) -> Result<()> {
    let selection = selection(args)?;
    if !args.execute {
        println!(
            "{}",
            serde_json::json!({"operation":"compute_train_cycle_plan","execute":false,
            "selection":selection,"source_resolved":false,"network_retrieval":false,"training_executed":false})
        );
        return Ok(());
    }
    ensure!(
        !nix::unistd::geteuid().is_root(),
        "compute_unprivileged_user_required"
    );
    private_directory(&args.runtime_root)?;
    private_directory(&args.model_root)?;
    if let Some(adapter) = &args.adapter_root {
        private_directory(adapter)?;
    }
    private_directory(args.output.parent().context("train_cycle_output_parent")?)?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&args.output)
        .context("train_cycle_new_output_required")?;
    write_new(
        &args.output.join("selection.json"),
        &serde_json::to_vec(&selection)?,
    )?;
    let mut activity = Activity::new()?;
    let selected = TrainingSource {
        publisher_key: args.publisher_key,
        name: args.dataset_name.clone(),
        manifest_id: args.dataset_manifest_id,
        min_revision: args.min_revision,
        cache: args.cache.clone(),
        reuse_cache: args.reuse_cache,
        limits: args.limits.clone(),
    };
    let download = tokio::select! {
        biased;
        _ = activity.idle.changed() => bail!("train_cycle_cancelled_during_fetch_verified_cache_may_remain"),
        result = agent_artifact::fetch_training_source(&selected, socket, &args.output) => result?,
    };
    let verified = validate_source(args, &download, now()?)?;
    let source = persist_source(args, &download, &verified)?;
    ensure!(
        *activity.idle.borrow(),
        "train_cycle_cancelled_before_training"
    );
    let options = worker_options(args, verified.expires(), now()?)?;
    options.validate()?;
    // Await the real supervisor through cancellation. Dropping its future would not be a
    // valid claim that a running training worker had been killed and reaped.
    let report = execute(&options, activity.idle.clone()).await?;
    ensure!(
        *activity.idle.borrow(),
        "train_cycle_cancelled_after_training_outputs_retained"
    );
    let result = complete(args, &download, &source, &report)?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

fn selection(args: &Options) -> Result<Value> {
    crate::content::parse_content_name(&args.dataset_name).map_err(anyhow::Error::msg)?;
    ensure!(
        (1..=64).contains(&args.steps)
            && (1..=2).contains(&args.threads)
            && (1..=600).contains(&args.max_seconds),
        "train_cycle_budget"
    );
    for path in [
        &args.runtime_root,
        &args.model_root,
        &args.output,
        &args.cache,
    ] {
        ensure!(path.is_absolute(), "train_cycle_absolute_paths");
    }
    if let Some(adapter) = &args.adapter_root {
        ensure!(adapter.is_absolute(), "train_cycle_adapter_absolute");
    }
    for protected in [&args.runtime_root, &args.model_root, &args.cache]
        .into_iter()
        .chain(args.adapter_root.iter())
    {
        ensure!(
            !args.output.starts_with(protected) && !protected.starts_with(&args.output),
            "train_cycle_output_overlap"
        );
    }
    Ok(
        serde_json::json!({"version":1,"publisher_key":hex::encode(args.publisher_key.as_bytes()),
        "dataset_name":args.dataset_name,"expected_dataset_manifest_id":args.dataset_manifest_id.map(hex::encode),
        "minimum_revision":args.min_revision,"cache":args.cache,"reuse_cache":args.reuse_cache,
        "cache_only":false,"prefer_cached":true,"cache_miss_selects_different_source":false,
        "runtime_root":args.runtime_root,"model_root":args.model_root,"adapter_root":args.adapter_root,
        "output":args.output,"steps":args.steps,"threads":args.threads,"maximum_training_seconds":args.max_seconds,
        "spare_capacity":args.spare_capacity,
        "maximum_fetch_seconds":600,"private_data_supported":false,"automatic_source_discovery":false,
        "code_or_model_downloads":false,"automatic_publication":false,"globally_latest_version_claimed":false}),
    )
}

fn validate_source(
    args: &Options,
    download: &TrainingDownload,
    time: u64,
) -> Result<VerifiedPublicDataset> {
    let signed = SignedManifest::decode(&download.signed_manifest)?;
    let manifest = signed.verify(&args.publisher_key, time)?;
    ensure!(
        manifest.metadata().name == args.dataset_name
            && args
                .dataset_manifest_id
                .is_none_or(|id| manifest.manifest_id() == &id)
            && args
                .min_revision
                .is_none_or(|minimum| manifest.metadata().revision >= minimum)
            && download.expires == manifest.validity().expires,
        "train_cycle_selected_source_mismatch"
    );
    let json = std::str::from_utf8(&download.dataset)?;
    let verified = verify_source(&download.signed_manifest, &args.publisher_key, json, time)?;
    let data: Value = serde_json::from_slice(&download.dataset)?;
    ensure!(
        data["train"]
            .as_array()
            .is_some_and(|rows| !rows.is_empty()),
        "train_cycle_training_samples_required"
    );
    Ok(verified)
}

fn persist_source(
    args: &Options,
    download: &TrainingDownload,
    verified: &VerifiedPublicDataset,
) -> Result<Value> {
    write_new(&args.output.join("dataset.json"), &download.dataset)?;
    write_new(
        &args.output.join("dataset.manifest"),
        &download.signed_manifest,
    )?;
    let source = serde_json::json!({"version":1,"publisher_key":hex::encode(args.publisher_key.as_bytes()),
        "dataset_name":args.dataset_name,"dataset_manifest_id":hex::encode(verified.manifest_id()),
        "signed_manifest_sha256":sha(&download.signed_manifest),"dataset_sha256":sha(&download.dataset),
        "dataset_bytes":download.dataset.len(),"expires_unix_seconds":verified.expires(),
        "verified_at_unix_seconds":now()?,"source_receipt":download.receipt,
        "cache_only":false,"prefer_cached":true,"private_data_supported":false});
    write_new(
        &args.output.join("source-provenance.json"),
        &serde_json::to_vec(&source)?,
    )?;
    Ok(source)
}

fn worker_options(args: &Options, expires: u64, time: u64) -> Result<super::Options> {
    let remaining = expires
        .checked_sub(time)
        .filter(|remaining| *remaining > 0)
        .context("train_cycle_source_expired")?;
    Ok(super::Options {
        mode: Mode::Train,
        runtime_root: args.runtime_root.clone(),
        model_root: args.model_root.clone(),
        adapter_root: args.adapter_root.clone(),
        dataset: args.output.join("dataset.json"),
        output: args.output.join("training"),
        steps: args.steps,
        threads: args.threads,
        max_seconds: u16::try_from(remaining.min(u64::from(args.max_seconds)))?,
        execute: true,
        spare_capacity: args.spare_capacity,
    })
}

fn complete(
    args: &Options,
    download: &TrainingDownload,
    source: &Value,
    report: &Value,
) -> Result<Value> {
    let verified = validate_source(args, download, now()?)?;
    ensure!(
        report["supervisor"]["child_reaped"] == true
            && report["supervisor"]["network_access"] == false
            && report["dataset"]["sha256"] == sha(&download.dataset)
            && report["dataset"]["bytes"] == download.dataset.len()
            && report["updates_completed"] == args.steps,
        "train_cycle_training_result_binding"
    );
    let worker_path = args.output.join("training/report.json");
    let persisted: Value =
        serde_json::from_slice(&read_file(&worker_path, MAX_LINE_BYTES as u64)?)?;
    let mut original = report.clone();
    original
        .as_object_mut()
        .context("train_cycle_worker_report")?
        .remove("supervisor");
    ensure!(
        persisted == original,
        "train_cycle_saved_worker_report_changed"
    );
    let full_report = serde_json::to_vec(report)?;
    write_new(&args.output.join("training-report.json"), &full_report)?;
    let bundle = agent_artifact::pack(&agent_artifact::Pack::completed_training(
        args.output.join("training/adapter"),
        worker_path,
        args.output.join("dataset.manifest"),
        args.publisher_key,
        args.output.join("adapter.bundle"),
    ))?;
    let result = serde_json::json!({"version":1,"operation":"compute_train_cycle","complete":true,
        "dataset_manifest_id":hex::encode(verified.manifest_id()),"dataset_sha256":sha(&download.dataset),
        "source_receipt":source["source_receipt"],"source_expires_unix_seconds":verified.expires(),
        "updates_completed":report["updates_completed"],"input_adapter_applied":report["input_adapter"]["applied"] == true,
        "input_adapter":report.get("input_adapter"),"training_report_sha256":sha(&full_report),"bundle":bundle,
        "network_published":false,"private_data_supported":false,"model_quality_proven":false,
        "autonomous_training":false,"model_activated_for_peer_jobs":false,"output":args.output});
    write_new(
        &args.output.join("result.json"),
        &serde_json::to_vec(&result)?,
    )?;
    Ok(result)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("train_cycle_parent")?;
    private_directory(parent)?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

fn now() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}
fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}
fn parse_manifest_id(value: &str) -> Result<[u8; 32], String> {
    let mut id = [0; 32];
    if !is_hex(value, 64) {
        return Err("train_cycle_manifest_id_hex".into());
    }
    hex::decode_to_slice(value, &mut id).map_err(|_| "train_cycle_manifest_id_hex".to_owned())?;
    if id == [0; 32] {
        return Err("train_cycle_manifest_id_zero".into());
    }
    Ok(id)
}

#[cfg(test)]
mod tests {
    use crate::compute::Command;
    use clap::Parser;
    use volparossa_content::{
        CacheLimits, ChunkStore, Metadata, Publication, Validity,
        agent_artifact::{AdapterBundle, BASE_MODEL_SHA256, MODEL_ID, MODEL_REVISION},
    };

    use super::*;

    fn arguments(root: &Path, publisher: &VerifyingKey) -> Options {
        let command_line = vec![
            "volparossa".to_owned(),
            "compute".into(),
            "train-cycle".into(),
            "--publisher-key".into(),
            hex::encode(publisher.as_bytes()),
            "--dataset-name".into(),
            "explicit-training-fixture".into(),
            "--runtime-root".into(),
            root.join("runtime").to_str().unwrap().into(),
            "--model-root".into(),
            root.join("model").to_str().unwrap().into(),
            "--cache".into(),
            root.join("agent-cache").to_str().unwrap().into(),
            "--output".into(),
            root.join("cycle").to_str().unwrap().into(),
        ];
        let cli = crate::Cli::try_parse_from(command_line).unwrap();
        let crate::CliCommand::Compute {
            command: Command::TrainCycle(args),
        } = cli.command
        else {
            panic!("train cycle parsed")
        };
        *args
    }

    fn fixture() -> (tempfile::TempDir, Options, TrainingDownload) {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
        let args = arguments(root.path(), &key.verifying_key());
        let json = serde_json::json!({"version":1,"visibility":"public","license":"GPL-3.0-only",
            "source_revision":"a".repeat(40),
            "train":[{"question":"What is this?","context":"Public coordinator test.","answer":"A protocol fixture."}],
            "heldout":[{"question":"What does this test?","context":"Explicit public source selection.","answer":"Signed binding."}],
            "inference":[{"question":"What is supported?","context":"Public repository questions."}]}).to_string();
        let at = now().unwrap();
        let mut cache = ChunkStore::create(
            &root.path().join("publisher-cache"),
            CacheLimits {
                max_bytes: 1024 * 1024,
                max_entries: 8,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let signed = volparossa_content::publish(
            &mut json.as_bytes(),
            Publication {
                metadata: Metadata {
                    name: args.dataset_name.clone(),
                    revision: 2,
                    content_type: volparossa_content::provider::compute::dataset::CONTENT_TYPE
                        .into(),
                },
                length: json.len() as u64,
                validity: Validity {
                    created: at,
                    expires: at + 1200,
                },
            },
            &key,
            &mut cache,
        )
        .unwrap();
        let download = TrainingDownload {
            signed_manifest: signed.encode(),
            dataset: json.into_bytes(),
            receipt: serde_json::json!({"fixture_only":true,"cache_only":false,"peer_bytes":0}),
            expires: at + 1200,
        };
        (root, args, download)
    }

    #[tokio::test]
    async fn default_preview_does_not_read_cache_or_contact_a_model_or_agent() {
        let (root, args, _download) = fixture();
        assert!(!args.execute);
        let plan = selection(&args).unwrap();
        assert_eq!(plan["cache_only"], false);
        assert_eq!(plan["cache_miss_selects_different_source"], false);
        run(&args, &root.path().join("no-agent.sock"))
            .await
            .unwrap();
        assert!(!args.output.exists());
        assert!(!args.runtime_root.exists());
        assert!(!args.cache.exists());
    }

    #[test]
    fn public_source_identity_and_worker_expiry_remain_exact() {
        let (_root, mut args, download) = fixture();
        let at = now().unwrap();
        let verified = validate_source(&args, &download, at).unwrap();
        args.dataset_manifest_id = Some(*verified.manifest_id());
        assert!(validate_source(&args, &download, at).is_ok());
        assert_eq!(worker_options(&args, at + 90, at).unwrap().max_seconds, 90);
        assert_eq!(
            worker_options(&args, at + 1200, at).unwrap().max_seconds,
            600
        );
        assert!(worker_options(&args, at, at).is_err());
        args.dataset_manifest_id = Some([9; 32]);
        assert!(validate_source(&args, &download, at).is_err());
        args.dataset_manifest_id = None;
        args.dataset_name = "another-cached-dataset".into();
        assert!(validate_source(&args, &download, at).is_err());
        args.dataset_name = "explicit-training-fixture".into();
        args.min_revision = Some(3);
        assert!(validate_source(&args, &download, at).is_err());
        args.min_revision = None;
        args.publisher_key = ed25519_dalek::SigningKey::from_bytes(&[32; 32]).verifying_key();
        assert!(validate_source(&args, &download, at).is_err());
    }

    #[test]
    fn real_signed_source_and_opaque_pack_fixture_preserve_exact_cycle_binding() {
        let (_root, args, download) = fixture();
        let verified = validate_source(&args, &download, now().unwrap()).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&args.output)
            .unwrap();
        let source = persist_source(&args, &download, &verified).unwrap();
        let training = args.output.join("training");
        fs::DirBuilder::new().mode(0o700).create(&training).unwrap();
        let adapter = training.join("adapter");
        fs::DirBuilder::new().mode(0o700).create(&adapter).unwrap();
        // Opaque bytes and a synthetic report exercise packaging only: no real model,
        // remote execution, training quality or safe tensor contents are claimed by this test.
        let mut artifacts = Vec::new();
        for name in [
            "README.md",
            "adapter_config.json",
            "adapter_model.safetensors",
        ] {
            let bytes = format!("Opaque synthetic pack fixture: {name}; no model ran.");
            write_new(&adapter.join(name), bytes.as_bytes()).unwrap();
            artifacts.push(
                serde_json::json!({"relative_path":format!("adapter/{name}"),
                "bytes":bytes.len(),"sha256":sha(bytes.as_bytes())}),
            );
        }
        let report = serde_json::json!({"kind":"result","version":1,"id":"a".repeat(32),
            "mode":"train","status":"ok","device":"cpu","updates_completed":8,
            "base_weights_unchanged":true,"adapter_weights_changed":true,"checkpoint_reloaded":true,
            "dataset":{"visibility":"public","license":"GPL-3.0-only","bytes":download.dataset.len(),"sha256":sha(&download.dataset)},
            "model":{"id":MODEL_ID,"revision":MODEL_REVISION,"files":{"model.safetensors":{
                "bytes":269_060_552,"sha256":hex::encode(BASE_MODEL_SHA256)}}},"artifacts":artifacts,
            "synthetic_pack_fixture_not_training_evidence":true});
        write_new(
            &training.join("report.json"),
            &serde_json::to_vec(&report).unwrap(),
        )
        .unwrap();
        let mut supervised = report;
        supervised["supervisor"] = serde_json::json!({"child_reaped":true,"network_access":false});
        let mut mismatched = supervised.clone();
        mismatched["dataset"]["sha256"] = Value::from("b".repeat(64));
        assert!(complete(&args, &download, &source, &mismatched).is_err());
        assert!(!args.output.join("adapter.bundle").exists());
        let result = complete(&args, &download, &source, &supervised).unwrap();
        assert_eq!(result["network_published"], false);
        assert_eq!(result["model_quality_proven"], false);
        assert_eq!(
            result["dataset_manifest_id"],
            hex::encode(verified.manifest_id())
        );
        let bundle = AdapterBundle::decode(
            read_file(&args.output.join("adapter.bundle"), 4 * 1024 * 1024).unwrap(),
        )
        .unwrap();
        assert_eq!(bundle.dataset_manifest_id(), *verified.manifest_id());
        assert!(complete(&args, &download, &source, &supervised).is_err());
    }
}
