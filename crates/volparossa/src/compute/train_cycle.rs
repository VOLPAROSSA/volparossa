//! One explicitly authorized public training cycle; no autonomous source/model downloads.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File},
    io::Write,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail, ensure};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
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
    pub(super) publisher_key: VerifyingKey,
    /// Exact publisher-local dataset name, chosen independently of what happens to be cached.
    #[arg(long, value_parser = crate::content::parse_content_name)]
    pub(super) dataset_name: String,
    /// Optional exact signed identity; a mismatch never authorizes a different cached dataset.
    #[arg(long, value_parser = parse_manifest_id)]
    pub(super) dataset_manifest_id: Option<[u8; 32]>,
    /// Internal signed-catalog authorization from the enrolled training coordinator.
    #[arg(skip)]
    pub(super) source_catalog: Option<Value>,
    /// Locally approved peer warmstart, supplied only by the owning coordinator.
    #[arg(skip)]
    pub(super) peer_predecessor: Option<Value>,
    /// Locally approved three-publisher aggregate, never a fictitious peer or training cycle.
    #[arg(skip)]
    pub(super) aggregate_predecessor: Option<Value>,
    /// Original authority inherited through later local successors; never renewed by a new source.
    #[arg(skip)]
    pub(super) inherited_authority_expires: Option<u64>,
    /// Signed revision floor, not proof of the globally newest publication.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub(super) min_revision: Option<u64>,
    /// Agent-owned native cache. A miss falls back to protected retrieval of this same source.
    #[arg(long)]
    pub(super) cache: PathBuf,
    #[arg(long)]
    pub(super) reuse_cache: bool,
    /// Existing explicitly provisioned fixed Python runtime; never installed by this command.
    #[arg(long)]
    pub(super) runtime_root: PathBuf,
    /// Existing pinned base model; never downloaded by this command.
    #[arg(long)]
    pub(super) model_root: PathBuf,
    /// Optional explicitly imported compatible adapter. Fetch/import is a separate operation.
    #[arg(long)]
    pub(super) adapter_root: Option<PathBuf>,
    /// New private cycle directory. Failures retain partial evidence; nothing is overwritten.
    #[arg(long)]
    pub(super) output: PathBuf,
    #[arg(long, default_value_t = 8, value_parser = clap::value_parser!(u16).range(1..=64))]
    pub(super) steps: u16,
    #[arg(long, default_value_t = 2, value_parser = clap::value_parser!(u16).range(1..=2))]
    pub(super) threads: u16,
    /// Training deadline, additionally bounded by source expiry; retrieval has its own 600s bound.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u16).range(1..=600))]
    pub(super) max_seconds: u16,
    /// Pause this explicitly authorized background cycle under CPU/IO pressure.
    #[arg(long)]
    pub(super) spare_capacity: bool,
    /// Explicitly authorize this one cycle. Default preview performs no retrieval or training.
    #[arg(long)]
    pub(super) execute: bool,
    #[command(flatten)]
    pub(super) limits: Limits,
}

struct Activity {
    idle: watch::Receiver<bool>,
    listener: tokio::task::JoinHandle<()>,
}

/// Content-free context retained when a coordinator catches a cycle failure.
#[derive(Debug, Clone, Copy)]
enum CycleStage {
    Admission,
    Fetch,
    SourceValidation,
    WorkerAdmission,
    Supervisor,
    Completion,
}

impl CycleStage {
    const fn label(self) -> &'static str {
        match self {
            Self::Admission => "admission",
            Self::Fetch => "fetch",
            Self::SourceValidation => "source_validation",
            Self::WorkerAdmission => "worker_admission",
            Self::Supervisor => "supervisor",
            Self::Completion => "completion",
        }
    }
}

impl std::fmt::Display for CycleStage {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(self.label())
    }
}

impl std::error::Error for CycleStage {}

pub(super) fn failure_stage(error: &anyhow::Error) -> &'static str {
    error
        .downcast_ref::<CycleStage>()
        .map_or("unknown", |stage| stage.label())
}

impl Activity {
    fn new() -> Result<Self> {
        let mut interrupt =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::interrupt())?;
        let mut terminate =
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())?;
        let (sender, idle) = watch::channel(true);
        let listener = tokio::spawn(async move {
            tokio::select! {
                _ = interrupt.recv() => {},
                _ = terminate.recv() => {},
            }
            let _ = sender.send(false);
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
    let activity = Activity::new()?;
    let result = execute_cycle(args, socket, activity.idle.clone()).await?;
    println!("{}", serde_json::to_string(&result)?);
    Ok(())
}

/// Execute one explicitly authorized cycle without owning signals or printing.
/// The caller retains the activity sender through completion and must await this
/// future through cancellation so the active model supervisor can reap its child.
pub(super) async fn execute_cycle(
    args: &Options,
    socket: &Path,
    activity: watch::Receiver<bool>,
) -> Result<Value> {
    execute_cycle_guarded(args, socket, activity, None).await
}

/// An optional separately authenticated public evaluation source is never used
/// as training input. Its publisher/manifest binding belongs to the caller;
/// this guard checks current input bytes and normalized questions, not semantic
/// overlap or contamination in any earlier training run.
pub(super) async fn execute_cycle_guarded(
    args: &Options,
    socket: &Path,
    mut activity: watch::Receiver<bool>,
    validation: Option<&[u8]>,
) -> Result<Value> {
    let mut stage = CycleStage::Admission;
    let result = async {
    ensure!(args.execute, "train_cycle_execute_required");
    ensure_active(&activity, "train_cycle_cancelled_before_output")?;
    let selection = selection(args)?;
    ensure!(
        !nix::unistd::geteuid().is_root(),
        "compute_unprivileged_user_required"
    );
    private_directory(&args.runtime_root)?;
    private_directory(&args.model_root)?;
    if let Some(adapter) = &args.adapter_root {
        private_directory(adapter)?;
    }
    if let Some(origin) = &args.aggregate_predecessor {
        verify_aggregate_adapter(args.adapter_root.as_deref(), origin)?;
    }
    private_directory(args.output.parent().context("train_cycle_output_parent")?)?;
    ensure_active(&activity, "train_cycle_cancelled_before_output")?;
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&args.output)
        .context("train_cycle_new_output_required")?;
    write_new(
        &args.output.join("selection.json"),
        &serde_json::to_vec(&selection)?,
    )?;
    let selected = TrainingSource {
        publisher_key: args.publisher_key,
        name: args.dataset_name.clone(),
        manifest_id: args.dataset_manifest_id,
        min_revision: args.min_revision,
        cache: args.cache.clone(),
        reuse_cache: args.reuse_cache,
        limits: args.limits.clone(),
    };
    stage = CycleStage::Fetch;
    ensure_active(&activity, "train_cycle_cancelled_before_fetch")?;
    let download = tokio::select! {
        biased;
        () = cancelled(&mut activity) => bail!("train_cycle_cancelled_during_fetch_verified_cache_may_remain"),
        result = agent_artifact::fetch_training_source(&selected, socket, &args.output) => result?,
    };
    stage = CycleStage::SourceValidation;
    let verified = validate_source(args, &download, now()?)?;
    if let Some(validation) = validation {
        guard_overlap(&download.dataset, validation)?;
    }
    let source = persist_source(args, &download, &verified)?;
    ensure_active(&activity, "train_cycle_cancelled_before_training")?;
    let authority_expires = catalog_expiry(args, now()?)?.map_or(verified.expires(), |expires| {
        expires.min(verified.expires())
    });
    stage = CycleStage::WorkerAdmission;
    let options = worker_options(args, authority_expires, now()?)?;
    options.validate()?;
    // Await the real supervisor through cancellation. Dropping its future would not be a
    // valid claim that a running training worker had been killed and reaped.
    stage = CycleStage::Supervisor;
    let report = execute(&options, activity.clone()).await?;
    stage = CycleStage::Completion;
    ensure_active(
        &activity,
        "train_cycle_cancelled_after_training_outputs_retained",
    )?;
    complete(args, &download, &source, &report)
    }
    .await;
    result.map_err(|error: anyhow::Error| error.context(stage))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardDataset {
    version: u32,
    visibility: String,
    license: String,
    source_revision: String,
    train: Vec<GuardAnswered>,
    heldout: Vec<GuardAnswered>,
    inference: Vec<GuardQuestion>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardAnswered {
    question: String,
    context: String,
    answer: String,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct GuardQuestion {
    question: String,
    context: String,
}

fn guard_dataset(bytes: &[u8]) -> Result<GuardDataset> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= 1024 * 1024,
        "train_cycle_validation_dataset_bound"
    );
    let dataset: GuardDataset = serde_json::from_slice(bytes)
        .map_err(|_| anyhow::anyhow!("train_cycle_validation_schema"))?;
    ensure!(
        dataset.version == 1
            && dataset.visibility == "public"
            && dataset.license == "GPL-3.0-only"
            && is_hex(&dataset.source_revision, 40)
            && dataset.train.len() <= 32
            && (1..=8).contains(&dataset.heldout.len())
            && (1..=4).contains(&dataset.inference.len()),
        "train_cycle_validation_public_profile"
    );
    let text = |value: &str, limit| {
        !value.trim().is_empty() && value.len() <= limit && !value.contains('\0')
    };
    ensure!(
        dataset.train.iter().chain(&dataset.heldout).all(|row| {
            text(&row.question, 512) && text(&row.context, 4096) && text(&row.answer, 1024)
        }) && dataset
            .inference
            .iter()
            .all(|row| text(&row.question, 512) && text(&row.context, 4096)),
        "train_cycle_validation_sample"
    );
    Ok(dataset)
}

fn normalized_question(text: &str) -> String {
    text.split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_lowercase()
}

pub(super) fn guard_overlap(training_bytes: &[u8], validation_bytes: &[u8]) -> Result<()> {
    let training = guard_dataset(training_bytes)?;
    let validation = guard_dataset(validation_bytes)?;
    ensure!(
        Sha256::digest(training_bytes) != Sha256::digest(validation_bytes),
        "train_cycle_validation_source_reused"
    );
    ensure!(
        !training.train.is_empty() && validation.train.is_empty(),
        "train_cycle_validation_must_not_train"
    );
    let questions: Vec<_> = validation
        .heldout
        .iter()
        .map(|row| row.question.as_str())
        .chain(validation.inference.iter().map(|row| row.question.as_str()))
        .map(normalized_question)
        .collect();
    // Excluding the entire normalized question is intentionally wider than
    // comparing an exact normalized (question, context, answer) triple.
    ensure!(
        training
            .train
            .iter()
            .all(|row| !questions.contains(&normalized_question(&row.question))),
        "train_cycle_validation_training_overlap"
    );
    Ok(())
}

fn ensure_active(activity: &watch::Receiver<bool>, code: &'static str) -> Result<()> {
    ensure!(*activity.borrow() && activity.has_changed().is_ok(), code);
    Ok(())
}

async fn cancelled(activity: &mut watch::Receiver<bool>) {
    loop {
        let active = *activity.borrow_and_update();
        if !active || activity.changed().await.is_err() {
            return;
        }
    }
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
    let mut selected = serde_json::json!({"version":1,"publisher_key":hex::encode(args.publisher_key.as_bytes()),
        "dataset_name":args.dataset_name,"expected_dataset_manifest_id":args.dataset_manifest_id.map(hex::encode),
        "minimum_revision":args.min_revision,"cache":args.cache,"reuse_cache":args.reuse_cache,
        "cache_only":false,"prefer_cached":true,"cache_miss_selects_different_source":false,
        "runtime_root":args.runtime_root,"model_root":args.model_root,"adapter_root":args.adapter_root,
        "output":args.output,"steps":args.steps,"threads":args.threads,"maximum_training_seconds":args.max_seconds,
        "spare_capacity":args.spare_capacity,
        "maximum_fetch_seconds":600,"private_data_supported":false,"automatic_source_discovery":false,
        "code_or_model_downloads":false,"automatic_publication":false,"globally_latest_version_claimed":false});
    if let Some(proof) = &args.source_catalog {
        catalog_expiry(args, now()?)?;
        selected["source_catalog"] = proof.clone();
        selected["automatic_source_discovery"] = true.into();
        selected["source_discovery_scope"] = "enrolled-same-publisher-catalog".into();
    }
    if let Some(origin) = &args.peer_predecessor {
        ensure!(
            origin["kind"] == "peer_update" && args.adapter_root.is_some(),
            "train_cycle_peer_predecessor"
        );
        selected["peer_predecessor"] = origin.clone();
    }
    if let Some(origin) = &args.aggregate_predecessor {
        ensure!(
            args.peer_predecessor.is_none(),
            "train_cycle_conflicting_predecessors"
        );
        aggregate_expiry(args, now()?)?;
        let expected = args
            .output
            .parent()
            .context("train_cycle_aggregate_parent")?
            .join(format!(
                "aggregate-update-{:016x}/candidate/import/adapter",
                origin["aggregate_sequence"]
                    .as_u64()
                    .context("train_cycle_aggregate_sequence")?
            ));
        ensure!(
            args.adapter_root.as_ref() == Some(&expected),
            "train_cycle_aggregate_adapter_path"
        );
        selected["aggregate_predecessor"] = origin.clone();
    }
    if let Some(expires) = args.inherited_authority_expires {
        ensure!(
            now()? < expires && args.adapter_root.is_some(),
            "train_cycle_inherited_authority_expired"
        );
        selected["inherited_authority_expires"] = expires.into();
    }
    Ok(selected)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AggregateOrigin {
    kind: String,
    aggregate_sequence: u64,
    local_predecessor: Option<u64>,
    manifest_ids: [String; 3],
    dataset_manifest_id: String,
    cohort_sha256: String,
    comparison_sha256: String,
    result_sha256: String,
    adapter_files: BTreeMap<String, volparossa_local_control::compute::FileIdentity>,
    expires_unix_seconds: u64,
}

const AGGREGATE_FILES: [(&str, u64); 3] = [
    ("README.md", 16 * 1024),
    ("adapter_config.json", 16 * 1024),
    ("adapter_model.safetensors", 2 * 1024 * 1024),
];

/// Validate the retained owner-local approval identity, not a new network attestation.
/// No wall-clock check here: historical cycle verification must preserve its original lease.
pub(in crate::compute) fn aggregate_predecessor_expiry(value: &Value) -> Result<u64> {
    let origin: AggregateOrigin = serde_json::from_value(value.clone())?;
    ensure!(
        value.get("local_predecessor").is_some()
            && origin.kind == "aggregate_update"
            && origin.aggregate_sequence > 0
            && origin.local_predecessor.is_none_or(|sequence| sequence > 0)
            && origin.expires_unix_seconds > 0
            && origin.manifest_ids.iter().collect::<BTreeSet<_>>().len() == 3
            && origin
                .manifest_ids
                .iter()
                .all(|id| parse_manifest_id(id).is_ok())
            && parse_manifest_id(&origin.dataset_manifest_id).is_ok()
            && [
                &origin.cohort_sha256,
                &origin.comparison_sha256,
                &origin.result_sha256
            ]
            .iter()
            .all(|id| is_hex(id, 64))
            && origin.adapter_files.len() == AGGREGATE_FILES.len(),
        "train_cycle_aggregate_origin"
    );
    for (name, maximum) in AGGREGATE_FILES {
        let file = origin
            .adapter_files
            .get(name)
            .context("train_cycle_aggregate_file")?;
        ensure!(
            (1..=maximum).contains(&file.bytes) && is_hex(&file.sha256, 64),
            "train_cycle_aggregate_file_identity"
        );
    }
    Ok(origin.expires_unix_seconds)
}

fn aggregate_expiry(args: &Options, time: u64) -> Result<Option<u64>> {
    args.aggregate_predecessor
        .as_ref()
        .map(|origin| {
            let expires = aggregate_predecessor_expiry(origin)?;
            ensure!(time < expires, "train_cycle_aggregate_expired");
            Ok(expires)
        })
        .transpose()
}

fn verify_aggregate_adapter(adapter: Option<&Path>, origin: &Value) -> Result<()> {
    let adapter = adapter.context("train_cycle_aggregate_adapter_missing")?;
    for (name, maximum) in AGGREGATE_FILES {
        let bytes = read_file(&adapter.join(name), maximum)?;
        ensure!(
            origin["adapter_files"][name]
                == serde_json::json!({"bytes":bytes.len(),"sha256":sha(&bytes)}),
            "train_cycle_aggregate_adapter_changed"
        );
    }
    Ok(())
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogProof {
    version: u32,
    catalog_publisher_key: String,
    catalog_name: String,
    catalog_manifest_id: String,
    catalog_revision: u64,
    catalog_expires_unix_seconds: u64,
    verified_at_unix_seconds: u64,
    signed_manifest_hex: String,
    catalog_body: String,
    selected_source: CatalogSource,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CatalogSource {
    publisher_key: String,
    name: String,
    min_revision: u64,
    manifest_id: String,
}

/// Recheck the original catalog authorization at admission and after source retrieval.
/// A cached dataset does not renew that lease or authorize a different source.
fn catalog_expiry(args: &Options, time: u64) -> Result<Option<u64>> {
    let Some(value) = &args.source_catalog else {
        return Ok(None);
    };
    let proof: CatalogProof = serde_json::from_value(value.clone())?;
    let expected_publisher = hex::encode(args.publisher_key.as_bytes());
    ensure!(
        proof.version == 1
            && proof.catalog_publisher_key == expected_publisher
            && proof.selected_source.publisher_key == expected_publisher
            && proof.selected_source.name == args.dataset_name
            && Some(proof.selected_source.manifest_id.clone())
                == args.dataset_manifest_id.map(hex::encode)
            && proof.selected_source.min_revision > 0
            && args
                .min_revision
                .is_none_or(|floor| proof.selected_source.min_revision >= floor)
            && proof.verified_at_unix_seconds <= time
            && proof.catalog_body.len() <= crate::content::source_catalog::MAX_BYTES
            && proof.signed_manifest_hex.len() <= 128 * 1024,
        "train_cycle_catalog_selection"
    );
    let signed = hex::decode(&proof.signed_manifest_hex)?;
    let catalog = SignedManifest::decode(&signed)?.verify(&args.publisher_key, time)?;
    ensure!(
        catalog.metadata().name == proof.catalog_name
            && catalog.metadata().revision == proof.catalog_revision
            && hex::encode(catalog.manifest_id()) == proof.catalog_manifest_id
            && catalog.validity().expires == proof.catalog_expires_unix_seconds,
        "train_cycle_catalog_identity"
    );
    let entries = crate::content::source_catalog::verify(
        &signed,
        proof.catalog_body.as_bytes(),
        &args.publisher_key,
        time,
    )?;
    ensure!(
        entries.iter().any(|entry| entry.name == args.dataset_name
            && entry.revision == proof.selected_source.min_revision
            && Some(entry.manifest_id) == args.dataset_manifest_id),
        "train_cycle_catalog_source_missing"
    );
    Ok(Some(catalog.validity().expires))
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
            && args.source_catalog.as_ref().is_none_or(|proof| {
                proof["selected_source"]["min_revision"].as_u64()
                    == Some(manifest.metadata().revision)
            })
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
    let expires = successor_expiry(args, expires, time)?;
    let remaining = expires
        .checked_sub(time)
        .filter(|remaining| *remaining > 0)
        .context("train_cycle_source_expired")?;
    Ok(super::Options {
        model_profile: super::ModelProfile::default(),
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

fn successor_expiry(args: &Options, expires: u64, time: u64) -> Result<u64> {
    let expires = aggregate_expiry(args, time)?.map_or(expires, |aggregate| expires.min(aggregate));
    if let Some(inherited) = args.inherited_authority_expires {
        ensure!(time < inherited, "train_cycle_inherited_authority_expired");
        Ok(expires.min(inherited))
    } else {
        Ok(expires)
    }
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
    let mut result = serde_json::json!({"version":1,"operation":"compute_train_cycle","complete":true,
        "dataset_manifest_id":hex::encode(verified.manifest_id()),"dataset_sha256":sha(&download.dataset),
        "source_receipt":source["source_receipt"],"source_expires_unix_seconds":verified.expires(),
        "updates_completed":report["updates_completed"],"input_adapter_applied":report["input_adapter"]["applied"] == true,
        "input_adapter":report.get("input_adapter"),"training_report_sha256":sha(&full_report),"bundle":bundle,
        "network_published":false,"private_data_supported":false,"model_quality_proven":false,
        "autonomous_training":false,"model_activated_for_peer_jobs":false,"output":args.output});
    if args.aggregate_predecessor.is_some() || args.inherited_authority_expires.is_some() {
        let completed_at = now()?;
        let expires = successor_expiry(args, verified.expires(), completed_at)?;
        let expires =
            catalog_expiry(args, completed_at)?.map_or(expires, |catalog| expires.min(catalog));
        if let Some(origin) = &args.aggregate_predecessor {
            verify_aggregate_adapter(args.adapter_root.as_deref(), origin)?;
            ensure!(
                report["input_adapter"]["applied"] == true
                    && report["input_adapter"]["files"] == origin["adapter_files"],
                "train_cycle_aggregate_worker_input_changed"
            );
        }
        ensure!(
            completed_at < expires,
            "train_cycle_successor_authority_expired"
        );
        result["authority_expires_unix_seconds"] = expires.into();
        result["completed_at_unix_seconds"] = completed_at.into();
    }
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

    fn overlap_inputs() -> (Value, Value) {
        let training = serde_json::json!({"version":1,"visibility":"public","license":"GPL-3.0-only",
            "source_revision":"a".repeat(40),
            "train":[{"question":"What is networking?","context":"Explicit public training.","answer":"Connecting nodes."}],
            "heldout":[{"question":"What is checked?","context":"A separate evaluation row.","answer":"A heldout response."}],
            "inference":[{"question":"What is this test?","context":"Public parser fixtures."}]});
        let mut validation = training.clone();
        validation["train"] = serde_json::json!([]);
        (training, validation)
    }

    fn overlap_error(training: &Value, validation: &Value) -> String {
        guard_overlap(
            &serde_json::to_vec(training).unwrap(),
            &serde_json::to_vec(validation).unwrap(),
        )
        .unwrap_err()
        .to_string()
    }

    #[test]
    fn validation_allows_shared_nontraining_rows_and_same_repository_revision() {
        let (training, validation) = overlap_inputs();
        assert_eq!(training["heldout"], validation["heldout"]);
        assert_eq!(training["inference"], validation["inference"]);
        assert_eq!(training["source_revision"], validation["source_revision"]);
        guard_overlap(
            &serde_json::to_vec(&training).unwrap(),
            &serde_json::to_vec(&validation).unwrap(),
        )
        .unwrap();
    }

    #[test]
    fn validation_rejects_same_source_bytes_or_any_evaluation_training_rows() {
        let (training, mut validation) = overlap_inputs();
        assert_eq!(
            overlap_error(&training, &training),
            "train_cycle_validation_source_reused"
        );
        validation["train"] = serde_json::json!([{"question":"Another question?",
            "context":"Evaluation must not train this either.","answer":"No."}]);
        assert_eq!(
            overlap_error(&training, &validation),
            "train_cycle_validation_must_not_train"
        );
    }

    #[test]
    fn normalized_training_question_overlap_rejects_before_any_model_work() {
        let (training, validation) = overlap_inputs();
        for split in ["heldout", "inference"] {
            let mut overlapping = validation.clone();
            overlapping[split][0]["question"] = "  wHaT\u{2003}IS\t NETWORKING?\n".into();
            overlapping[split][0]["context"] =
                "Different context does not permit leaking a heldout question.".into();
            assert_eq!(
                overlap_error(&training, &overlapping),
                "train_cycle_validation_training_overlap"
            );
        }
        let mut exact_row = validation;
        exact_row["heldout"][0] = training["train"][0].clone();
        assert_eq!(
            overlap_error(&training, &exact_row),
            "train_cycle_validation_training_overlap"
        );
    }

    #[test]
    fn validation_guard_requires_bounded_strict_public_v1_schema() {
        let (training, validation) = overlap_inputs();
        for (field, replacement) in [
            ("version", serde_json::json!(2)),
            ("visibility", serde_json::json!("private")),
            ("heldout", serde_json::json!([])),
        ] {
            let mut invalid = validation.clone();
            invalid[field] = replacement;
            assert_eq!(
                overlap_error(&training, &invalid),
                "train_cycle_validation_public_profile"
            );
        }
        let mut invalid = validation;
        invalid["unrecognized_source"] = true.into();
        assert_eq!(
            overlap_error(&training, &invalid),
            "train_cycle_validation_schema"
        );
        assert_eq!(
            guard_overlap(
                &serde_json::to_vec(&training).unwrap(),
                &vec![b' '; 1024 * 1024 + 1]
            )
            .unwrap_err()
            .to_string(),
            "train_cycle_validation_dataset_bound"
        );
    }

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

    fn aggregate_origin(expires: u64) -> Value {
        let files: BTreeMap<_, _> = AGGREGATE_FILES
            .into_iter()
            .map(|(name, _)| {
                (
                    name,
                    serde_json::json!({"bytes":7,"sha256":sha(b"fixture")}),
                )
            })
            .collect();
        serde_json::json!({"kind":"aggregate_update","aggregate_sequence":7,
            "local_predecessor":null,"manifest_ids":["1".repeat(64),"2".repeat(64),"3".repeat(64)],
            "dataset_manifest_id":"4".repeat(64),"cohort_sha256":"5".repeat(64),
            "comparison_sha256":"6".repeat(64),"result_sha256":"7".repeat(64),
            "adapter_files":files,"expires_unix_seconds":expires})
    }

    #[test]
    fn aggregate_warmstart_is_distinct_exact_and_lease_bounded() {
        let root = tempfile::tempdir().unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[51; 32]);
        let mut args = arguments(root.path(), &key.verifying_key());
        let at = now().unwrap();
        let legacy = selection(&args).unwrap();
        assert!(legacy.get("aggregate_predecessor").is_none());
        assert!(legacy.get("inherited_authority_expires").is_none());
        let original = aggregate_origin(at + 90);
        args.aggregate_predecessor = Some(original.clone());
        let adapter = root
            .path()
            .join("aggregate-update-0000000000000007/candidate/import/adapter");
        fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(&adapter)
            .unwrap();
        for (name, _) in AGGREGATE_FILES {
            write_new(&adapter.join(name), b"fixture").unwrap();
        }
        args.adapter_root = Some(adapter.clone());
        assert_eq!(selection(&args).unwrap()["aggregate_predecessor"], original);
        verify_aggregate_adapter(args.adapter_root.as_deref(), &original).unwrap();
        assert_eq!(
            worker_options(&args, at + 1200, at).unwrap().max_seconds,
            90
        );
        assert_eq!(worker_options(&args, at + 40, at).unwrap().max_seconds, 40);
        args.inherited_authority_expires = Some(at + 20);
        assert_eq!(
            worker_options(&args, at + 1200, at).unwrap().max_seconds,
            20
        );
        assert!(worker_options(&args, at + 1200, at + 20).is_err());
        args.inherited_authority_expires = None;
        args.peer_predecessor = Some(serde_json::json!({"kind":"peer_update"}));
        assert!(selection(&args).is_err());
        args.peer_predecessor = None;
        args.adapter_root = Some(root.path().join("another-adapter"));
        assert!(selection(&args).is_err());
        args.adapter_root = Some(adapter.clone());
        fs::write(adapter.join("README.md"), b"changed").unwrap();
        assert!(verify_aggregate_adapter(args.adapter_root.as_deref(), &original).is_err());
        assert!(worker_options(&args, at + 1200, at + 90).is_err());
    }

    #[test]
    fn aggregate_origin_rejects_ambiguous_or_incomplete_identity() {
        let original = aggregate_origin(100);
        assert_eq!(aggregate_predecessor_expiry(&original).unwrap(), 100);
        for (field, value) in [
            ("kind", serde_json::json!("peer_update")),
            ("aggregate_sequence", serde_json::json!(0)),
            ("local_predecessor", serde_json::json!(0)),
            ("manifest_ids", serde_json::json!(vec!["1".repeat(64); 3])),
            ("dataset_manifest_id", serde_json::json!("0".repeat(64))),
            ("result_sha256", serde_json::json!("missing")),
            ("adapter_files", serde_json::json!({})),
            ("expires_unix_seconds", serde_json::json!(0)),
            ("unrecognized", serde_json::json!(true)),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            assert!(aggregate_predecessor_expiry(&changed).is_err(), "{field}");
        }
        for field in [
            "local_predecessor",
            "result_sha256",
            "cohort_sha256",
            "comparison_sha256",
        ] {
            let mut changed = original.clone();
            changed.as_object_mut().unwrap().remove(field);
            assert!(aggregate_predecessor_expiry(&changed).is_err(), "{field}");
        }
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

    fn catalog_fixture() -> (tempfile::TempDir, Options, u64) {
        let (root, mut args, download) = fixture();
        let time = now().unwrap();
        let dataset = SignedManifest::decode(&download.signed_manifest)
            .unwrap()
            .verify(&args.publisher_key, time)
            .unwrap();
        args.dataset_manifest_id = Some(*dataset.manifest_id());
        args.min_revision = Some(dataset.metadata().revision);
        let body = serde_json::json!({"version":1,"visibility":"public","purpose":"agent_training",
            "dataset_profile":volparossa_content::provider::compute::dataset::CONTENT_TYPE,
            "license":"GPL-3.0-only","sources":[{"name":args.dataset_name,
                "revision":dataset.metadata().revision,"manifest_id":hex::encode(dataset.manifest_id())}]}).to_string();
        let mut cache = ChunkStore::create(
            &root.path().join("catalog-cache"),
            CacheLimits {
                max_bytes: 1024 * 1024,
                max_entries: 8,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let publication = volparossa_content::publish(
            &mut body.as_bytes(),
            Publication {
                metadata: Metadata {
                    name: "chosen-catalog".into(),
                    revision: 3,
                    content_type: crate::content::source_catalog::CONTENT_TYPE.into(),
                },
                length: body.len() as u64,
                validity: Validity {
                    created: time,
                    expires: time + 60,
                },
            },
            &ed25519_dalek::SigningKey::from_bytes(&[31; 32]),
            &mut cache,
        )
        .unwrap();
        let catalog = publication.verify(&args.publisher_key, time).unwrap();
        args.source_catalog = Some(serde_json::json!({"version":1,
            "catalog_publisher_key":hex::encode(args.publisher_key.as_bytes()),"catalog_name":"chosen-catalog",
            "catalog_manifest_id":hex::encode(catalog.manifest_id()),"catalog_revision":3,
            "catalog_expires_unix_seconds":time+60,"verified_at_unix_seconds":time,
            "signed_manifest_hex":hex::encode(publication.encode()),"catalog_body":body,
            "selected_source":{"publisher_key":hex::encode(args.publisher_key.as_bytes()),
                "name":args.dataset_name,"min_revision":args.min_revision,
                "manifest_id":hex::encode(dataset.manifest_id())}}));
        (root, args, time)
    }

    #[test]
    fn catalog_authorization_pins_selected_source_and_limits_actual_worker_deadline() {
        let (_root, args, time) = catalog_fixture();
        assert_eq!(catalog_expiry(&args, time).unwrap(), Some(time + 60));
        let expiry = catalog_expiry(&args, time + 10).unwrap().unwrap();
        assert_eq!(
            worker_options(&args, expiry, time + 10)
                .unwrap()
                .max_seconds,
            50
        );
        assert!(catalog_expiry(&args, time + 60).is_err());
        let selected = selection(&args).unwrap();
        assert_eq!(selected["automatic_source_discovery"], true);
        assert_eq!(selected["source_catalog"], args.source_catalog.unwrap());
        assert!(!args.output.exists());
    }

    #[test]
    fn catalog_proof_cannot_substitute_publisher_body_row_or_original_expiry() {
        let (_root, mut args, time) = catalog_fixture();
        let original = args.source_catalog.clone().unwrap();
        for (field, value) in [
            ("catalog_publisher_key", serde_json::json!("00".repeat(32))),
            ("catalog_name", serde_json::json!("another-catalog")),
            ("catalog_manifest_id", serde_json::json!("12".repeat(32))),
            ("catalog_revision", serde_json::json!(4)),
            (
                "catalog_expires_unix_seconds",
                serde_json::json!(time + 600),
            ),
            ("verified_at_unix_seconds", serde_json::json!(time + 1)),
            ("catalog_body", serde_json::json!("{}")),
        ] {
            let mut changed = original.clone();
            changed[field] = value;
            args.source_catalog = Some(changed);
            assert!(catalog_expiry(&args, time).is_err(), "{field}");
        }
        let mut changed = original.clone();
        changed["selected_source"]["name"] = "another-dataset".into();
        args.source_catalog = Some(changed);
        assert!(catalog_expiry(&args, time).is_err());
        args.source_catalog = Some(original);
        args.dataset_manifest_id = None;
        assert!(catalog_expiry(&args, time).is_err());
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

    #[tokio::test]
    async fn callable_cycle_requires_execution_and_live_owner_before_creating_outputs() {
        let (root, mut args, _download) = fixture();
        let socket = root.path().join("no-agent.sock");
        let (sender, activity) = watch::channel(true);
        let error = execute_cycle(&args, &socket, activity.clone())
            .await
            .unwrap_err();
        assert_eq!(
            error.root_cause().to_string(),
            "train_cycle_execute_required"
        );
        assert_eq!(failure_stage(&error), "admission");
        args.execute = true;
        sender.send(false).unwrap();
        let error = execute_cycle(&args, &socket, activity.clone())
            .await
            .unwrap_err();
        assert_eq!(
            error.root_cause().to_string(),
            "train_cycle_cancelled_before_output"
        );
        sender.send(true).unwrap();
        drop(sender);
        let error = execute_cycle(&args, &socket, activity).await.unwrap_err();
        assert_eq!(
            error.root_cause().to_string(),
            "train_cycle_cancelled_before_output"
        );
        assert!(!args.output.exists());
        assert!(!args.runtime_root.exists());
        assert!(!args.cache.exists());
        assert!(!socket.exists());
    }

    #[test]
    fn failure_stage_uses_only_typed_context_and_preserves_underlying_error() {
        for stage in [
            CycleStage::Admission,
            CycleStage::Fetch,
            CycleStage::SourceValidation,
            CycleStage::WorkerAdmission,
            CycleStage::Supervisor,
            CycleStage::Completion,
        ] {
            let error = anyhow::anyhow!("PRIVATE SOURCE AND PATH").context(stage);
            assert_eq!(failure_stage(&error), stage.label());
            assert_eq!(error.root_cause().to_string(), "PRIVATE SOURCE AND PATH");
        }
        assert_eq!(failure_stage(&anyhow::anyhow!("fetch")), "unknown");
    }

    #[tokio::test]
    async fn external_owner_notifications_cancel_only_on_false_or_closed_channel() {
        let (sender, mut activity) = watch::channel(true);
        let waiting = tokio::spawn(async move { cancelled(&mut activity).await });
        sender.send(true).unwrap();
        tokio::task::yield_now().await;
        assert!(!waiting.is_finished());
        sender.send(false).unwrap();
        waiting.await.unwrap();
        let (sender, mut activity) = watch::channel(true);
        drop(sender);
        cancelled(&mut activity).await;
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
