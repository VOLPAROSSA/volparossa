//! Explicit three-publisher adapter aggregation with a real local held-out gate.
//! This bounded command neither activates a model nor publishes a training claim.

use std::{
    collections::BTreeSet,
    fs::{self, File, OpenOptions},
    io::Write as _,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::sync::watch;
use volparossa_content::{
    SignedManifest,
    agent_artifact::{
        ADAPTER_CONTENT_TYPE, AdapterBundle, AdapterFiles, BASE_MODEL_SHA256, MODEL_ID,
        MODEL_REVISION,
    },
};

use super::{Activity, Source, active, now, peer_evaluation, private_directory, read_file};
use crate::content::{
    Limits,
    agent_artifact::{self, TrainingSource},
    peer_update::{self, DatasetSource},
};

const ALGORITHM: &str = "coordinate-median-effective-lora-rank4-v1";
const FILES: [(&str, u64); 3] = [
    ("README.md", 16 * 1024),
    ("adapter_config.json", 16 * 1024),
    ("adapter_model.safetensors", 2 * 1024 * 1024),
];

#[derive(Debug, Args)]
pub(crate) struct Options {
    /// Owner plan: one exact public dataset and exactly three trusted adapter publishers.
    #[arg(long)]
    plan: PathBuf,
    /// New private directory retaining original signatures, worker outputs and comparison.
    #[arg(long)]
    directory: PathBuf,
    #[arg(long)]
    runtime_root: PathBuf,
    #[arg(long)]
    model_root: PathBuf,
    /// Existing agent-owned content cache; absent content is requested from peers.
    #[arg(long)]
    cache: PathBuf,
    /// Existing train-loop Source JSON with an exact signed validation manifest ID.
    #[arg(long)]
    validation_source: PathBuf,
    /// Optional local baseline to compare against; otherwise compare against the pinned base.
    #[arg(long)]
    adapter_root: Option<PathBuf>,
    #[arg(long, default_value_t=2, value_parser=clap::value_parser!(u16).range(1..=2))]
    threads: u16,
    /// Original deadline per isolated worker, also capped by every original source expiry.
    #[arg(long, default_value_t=600, value_parser=clap::value_parser!(u16).range(1..=600))]
    max_seconds: u16,
    /// Without this flag there is no retrieval, directory creation or model execution.
    #[arg(long)]
    execute: bool,
    #[command(flatten)]
    limits: Limits,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Dataset {
    publisher_key: String,
    name: String,
    revision: u64,
    manifest_id: String,
}

#[derive(Clone, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Channel {
    publisher_key: String,
    name: String,
    #[serde(default)]
    min_revision: Option<u64>,
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u32,
    dataset: Dataset,
    adapters: [Channel; 3],
}

impl Plan {
    fn validate(&self) -> Result<DatasetSource> {
        ensure!(self.version == 1, "aggregate_plan_version");
        let source = Source {
            publisher_key: self.dataset.publisher_key.clone(),
            name: self.dataset.name.clone(),
            min_revision: Some(self.dataset.revision),
            manifest_id: Some(self.dataset.manifest_id.clone()),
        };
        crate::content::parse_content_name(&source.name).map_err(anyhow::Error::msg)?;
        ensure!(self.dataset.revision > 0, "aggregate_dataset_revision");
        let publisher_key = source.key()?;
        ensure!(
            hex::encode(publisher_key.as_bytes()) == source.publisher_key,
            "aggregate_dataset_key"
        );
        let mut publishers = BTreeSet::new();
        for channel in &self.adapters {
            let key = crate::content::parse_publisher_key(&channel.publisher_key)
                .map_err(anyhow::Error::msg)?;
            crate::content::parse_content_name(&channel.name).map_err(anyhow::Error::msg)?;
            ensure!(
                hex::encode(key.as_bytes()) == channel.publisher_key
                    && channel.min_revision != Some(0)
                    && publishers.insert(key.to_bytes()),
                "aggregate_three_distinct_authorized_publishers"
            );
        }
        Ok(DatasetSource {
            publisher_key,
            name: source.name.clone(),
            revision: self.dataset.revision,
            manifest_id: source.manifest()?.context("aggregate_exact_dataset")?,
        })
    }
}

fn comparison_options(args: &Options, validation_source: PathBuf) -> super::Options {
    super::Options {
        plan: args.plan.clone(),
        directory: args.directory.clone(),
        resume: false,
        runtime_root: args.runtime_root.clone(),
        model_root: args.model_root.clone(),
        cache: args.cache.clone(),
        adapter_root: None,
        seed: None,
        peer_updates: None,
        aggregate_plan: None,
        validation_source: Some(validation_source),
        steps: 1,
        threads: args.threads,
        max_seconds: args.max_seconds,
        max_cycles: None,
        poll_seconds: 60,
        repeat_sources: false,
        publish_name: None,
        publication_key: None,
        identity: None,
        passphrase_file: None,
        publish_cache: None,
        serving_directory: None,
        first_publication_revision: 1,
        execute: true,
        limits: args.limits.clone(),
    }
}

fn enrollment(args: &Options) -> Result<(Plan, DatasetSource, Source, Value)> {
    ensure!(
        (1..=2).contains(&args.threads) && (1..=600).contains(&args.max_seconds),
        "aggregate_worker_bounds"
    );
    ensure!(args.directory.is_absolute(), "aggregate_absolute_directory");
    for path in [
        &args.plan,
        &args.runtime_root,
        &args.model_root,
        &args.cache,
        &args.validation_source,
    ]
    .into_iter()
    .chain(args.adapter_root.iter())
    {
        ensure!(
            path.is_absolute()
                && !path.starts_with(&args.directory)
                && !args.directory.starts_with(path),
            "aggregate_path_overlap"
        );
    }
    let plan: Plan = serde_json::from_slice(&read_file(&args.plan, 64 * 1024)?)?;
    let source = plan.validate()?;
    let validation =
        super::validation::selection(&comparison_options(args, args.validation_source.clone()))?
            .context("aggregate_pinned_validation_required")?;
    ensure!(
        validation.manifest()? != Some(source.manifest_id),
        "aggregate_training_validation_same_manifest"
    );
    let preview = preview(args, &plan, &validation);
    Ok((plan, source, validation, preview))
}

fn preview(args: &Options, plan: &Plan, validation: &Source) -> Value {
    json!({"version":1,"operation":"compute_aggregate_adapters","execute":false,
        "plan":plan,"validation_source":validation,"baseline_adapter":args.adapter_root,
        "algorithm":ALGORITHM,"peers":3,"model_id":MODEL_ID,"model_revision":MODEL_REVISION,
        "worker_deadline_seconds":args.max_seconds,"threads":args.threads,
        "limits":args.limits.configuration(),"private_data_supported":false,
        "three_keys_prove_independent_parties":false,"quality_guaranteed":false,
        "network_publication":false,"model_activated":false,"optimizer_steps":0})
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LoopSelection {
    version: u32,
    plan: Plan,
    validation_source: Source,
}

impl LoopSelection {
    fn validate(&self) -> Result<DatasetSource> {
        ensure!(self.version == 1, "aggregate_loop_selection_version");
        let source = self.plan.validate()?;
        self.validation_source.key()?;
        crate::content::parse_content_name(&self.validation_source.name)
            .map_err(anyhow::Error::msg)?;
        ensure!(
            self.validation_source.manifest()?.is_some()
                && self.validation_source.min_revision != Some(0),
            "aggregate_pinned_validation_required"
        );
        ensure!(
            self.validation_source.manifest()? != Some(source.manifest_id),
            "aggregate_training_validation_same_manifest"
        );
        Ok(source)
    }
}

fn loop_options(args: &super::Options, directory: &Path, baseline: Option<&Path>) -> Options {
    Options {
        // These are the retained frozen inputs, not mutable owner plan paths.
        plan: directory.join("selection.json"),
        directory: directory.to_path_buf(),
        runtime_root: args.runtime_root.clone(),
        model_root: args.model_root.clone(),
        cache: args.cache.clone(),
        validation_source: directory.join("validation-source.json"),
        adapter_root: baseline.map(Path::to_path_buf),
        threads: args.threads,
        max_seconds: args.max_seconds,
        execute: true,
        limits: args.limits.clone(),
    }
}

/// Freeze the owner-authorized plan and exact validation selection at enrollment.
/// Discovery and execution consume this value, not mutable enrollment files.
pub(super) fn loop_selection(args: &super::Options) -> Result<Option<Value>> {
    if args.aggregate_plan.is_none() {
        return Ok(None);
    }
    let mut options = loop_options(args, &args.directory, args.adapter_root.as_deref());
    options.plan = args
        .aggregate_plan
        .clone()
        .context("aggregate_plan_required")?;
    options.validation_source = args
        .validation_source
        .clone()
        .context("aggregate_pinned_validation_required")?;
    let (plan, _, validation_source, _) = enrollment(&options)?;
    let selected = LoopSelection {
        version: 1,
        plan,
        validation_source,
    };
    selected.validate()?;
    Ok(Some(serde_json::to_value(selected)?))
}

/// A single immutable adapter selection. Discovery does not run a model or import
/// a second choice; original signatures/receipts remain available to the loop.
pub(super) struct LoopCohort {
    pub(super) manifest_ids: [String; 3],
    pub(super) revisions: [u64; 3],
    /// Adapter-authority minimum; dataset/validation/baseline may shorten it later.
    pub(super) expires: u64,
    selection: Value,
    updates: [peer_update::VerifiedUpdate; 3],
}

pub(super) async fn discover_loop(
    args: &super::Options,
    selection: &Value,
    socket: &Path,
    staging: &Path,
    activity: &watch::Receiver<bool>,
) -> Result<LoopCohort> {
    let selected: LoopSelection = serde_json::from_value(selection.clone())?;
    let source = selected.validate()?;
    let options = loop_options(args, staging, None);
    private_directory(staging)?;
    let mut updates = Vec::with_capacity(3);
    for (index, channel) in selected.plan.adapters.iter().enumerate() {
        ensure!(active(activity), "aggregate_cancelled");
        let parent = staging.join(index.to_string());
        directory(&parent)?;
        let query = channel_query(&options, channel)?;
        let mut changed = activity.clone();
        let update = tokio::select! { biased;
            _=changed.changed()=>anyhow::bail!("aggregate_cancelled"),
            result=peer_update::fetch(&query,socket,&parent)=>result?,
        };
        ensure!(
            update.dataset_manifest_id() == &source.manifest_id,
            "aggregate_same_dataset_required"
        );
        peer_update::save_pending(&update, &parent.join("pending"))?;
        updates.push(update);
    }
    let updates: [peer_update::VerifiedUpdate; 3] = updates
        .try_into()
        .map_err(|_| anyhow::anyhow!("aggregate_three_updates_required"))?;
    let manifest_ids = updates
        .each_ref()
        .map(|update| hex::encode(update.manifest_id()));
    let revisions = updates
        .each_ref()
        .map(peer_update::VerifiedUpdate::revision);
    let expires = updates
        .iter()
        .map(peer_update::VerifiedUpdate::expires)
        .min()
        .context("aggregate_three_updates_required")?;
    ensure!(
        active(activity) && now()? < expires,
        "aggregate_cancelled_or_expired"
    );
    Ok(LoopCohort {
        manifest_ids,
        revisions,
        expires,
        selection: selection.clone(),
        updates,
    })
}

#[allow(
    clippy::too_many_arguments,
    reason = "Execute exactly one owner-frozen cohort and baseline under the loop cancellation"
)]
pub(super) async fn execute_loop(
    args: &super::Options,
    selection: &Value,
    directory: &Path,
    baseline: Option<&Path>,
    baseline_expires: Option<u64>,
    cohort: LoopCohort,
    socket: &Path,
    activity: &watch::Receiver<bool>,
) -> Result<Value> {
    ensure!(
        &cohort.selection == selection,
        "aggregate_frozen_selection_changed"
    );
    ensure!(
        baseline.is_some() || baseline_expires.is_none(),
        "aggregate_baseline_expiry_without_adapter"
    );
    let selected: LoopSelection = serde_json::from_value(selection.clone())?;
    let source = selected.validate()?;
    let options = loop_options(args, directory, baseline);
    for (index, update) in cohort.updates.iter().enumerate() {
        ensure!(
            hex::encode(update.manifest_id()) == cohort.manifest_ids[index]
                && update.revision() == cohort.revisions[index]
                && update.dataset_manifest_id() == &source.manifest_id,
            "aggregate_frozen_cohort_changed"
        );
    }
    ensure!(
        cohort
            .updates
            .iter()
            .map(peer_update::VerifiedUpdate::expires)
            .min()
            == Some(cohort.expires)
            && active(activity)
            && now()? < cohort.expires,
        "aggregate_cancelled_or_expired"
    );
    let mut preview = preview(&options, &selected.plan, &selected.validation_source);
    if let Some(expires) = baseline_expires {
        ensure!(now()? < expires, "aggregate_baseline_expired");
        preview["baseline_expires_unix_seconds"] = expires.into();
    }
    execute_selected(
        &options,
        socket,
        activity,
        (selected.plan, source, selected.validation_source, preview),
        Some(cohort.updates),
    )
    .await
}

fn directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    private_directory(path)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    File::open(path.parent().context("aggregate_output_parent")?)?.sync_all()?;
    Ok(())
}

fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    write_new(path, &serde_json::to_vec(value)?)
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn copy_adapter(input: &Path, output: &Path) -> Result<Value> {
    let original = peer_evaluation::adapter_files(input)?;
    directory(output)?;
    for (name, maximum) in FILES {
        write_new(&output.join(name), &read_file(&input.join(name), maximum)?)?;
    }
    ensure!(
        peer_evaluation::adapter_files(input)? == original
            && peer_evaluation::adapter_files(output)? == original,
        "aggregate_adapter_copy_changed"
    );
    Ok(serde_json::to_value(original)?)
}

fn channel_query(args: &Options, channel: &Channel) -> Result<peer_update::Fetch> {
    Ok(peer_update::Fetch {
        publisher_key: crate::content::parse_publisher_key(&channel.publisher_key)
            .map_err(anyhow::Error::msg)?,
        name: channel.name.clone(),
        min_revision: channel.min_revision,
        cache: args.cache.clone(),
        limits: args.limits.clone(),
    })
}

async fn validation_input(
    args: &Options,
    selected: &Source,
    socket: &Path,
    activity: &watch::Receiver<bool>,
) -> Result<u64> {
    ensure!(active(activity), "aggregate_cancelled");
    let root = args.directory.join("validation-input");
    directory(&root)?;
    let request = TrainingSource {
        publisher_key: selected.key()?,
        name: selected.name.clone(),
        manifest_id: selected.manifest()?,
        min_revision: selected.min_revision,
        cache: args.cache.clone(),
        reuse_cache: true,
        limits: args.limits.clone(),
    };
    let mut changed = activity.clone();
    let downloaded = tokio::select! { biased;
        _=changed.changed()=>anyhow::bail!("aggregate_cancelled"),
        result=agent_artifact::fetch_training_source(&request,socket,&root)=>result?,
    };
    let signed = SignedManifest::decode(&downloaded.signed_manifest)?;
    let manifest = signed.verify(&request.publisher_key, now()?)?;
    ensure!(
        Some(*manifest.manifest_id()) == request.manifest_id
            && manifest.metadata().name == selected.name
            && selected
                .min_revision
                .is_none_or(|floor| manifest.metadata().revision >= floor)
            && manifest.object_sha256() == &<[u8; 32]>::from(Sha256::digest(&downloaded.dataset))
            && manifest.length() == downloaded.dataset.len() as u64,
        "aggregate_exact_validation"
    );
    let value: Value = serde_json::from_slice(&downloaded.dataset)?;
    ensure!(
        value["version"] == 1
            && value["visibility"] == "public"
            && value["license"] == "GPL-3.0-only"
            && value["train"].as_array().is_some_and(Vec::is_empty),
        "aggregate_validation_only_public_dataset"
    );
    write_new(&root.join("dataset.json"), &downloaded.dataset)?;
    write_new(&root.join("dataset.manifest"), &downloaded.signed_manifest)?;
    save(
        &root.join("provenance.json"),
        &json!({"version":1,"selection":selected,
        "verified_at_unix_seconds":now()?,"expires_unix_seconds":downloaded.expires,
        "source_receipt":downloaded.receipt}),
    )?;
    Ok(downloaded.expires)
}

fn verify_report(
    report: &Value,
    dataset: &[u8],
    inputs: &[Value],
    adapter: &Path,
    threads: u16,
    seconds: u16,
) -> Result<()> {
    ensure!(
        report["version"] == 1
            && report["kind"] == "result"
            && report["status"] == "ok"
            && report["mode"] == "aggregate_adapter"
            && report["device"] == "cpu"
            && report["model_weights_loaded"] == false
            && report["updates_completed"] == 0
            && report["threads"] == threads
            && report["dataset"]["bytes"] == dataset.len() as u64
            && report["dataset"]["sha256"] == digest(dataset)
            && report["model"]["id"] == MODEL_ID
            && report["model"]["revision"] == MODEL_REVISION
            && report["model"]["files"]["model.safetensors"]["sha256"]
                == hex::encode(BASE_MODEL_SHA256)
            && report["aggregation"]["algorithm"] == ALGORITHM
            && report["aggregation"]["input_files"] == json!(inputs)
            && report["aggregation"]["combined_modules"] == 60
            && report["supervisor"]["child_reaped"] == true
            && report["supervisor"]["network_access"] == false
            && report["supervisor"]["spare_capacity"] == true
            && report["supervisor"]["deadline_seconds"] == seconds
            && report["elapsed_ms"]
                .as_u64()
                .is_some_and(|elapsed| elapsed <= u64::from(seconds) * 1000),
        "aggregate_worker_original_input_binding"
    );
    let files = serde_json::to_value(peer_evaluation::adapter_files(adapter)?)?;
    let artifacts = report["artifacts"]
        .as_array()
        .context("aggregate_artifacts")?;
    ensure!(artifacts.len() == FILES.len(), "aggregate_artifact_count");
    for (artifact, (name, _)) in artifacts.iter().zip(FILES) {
        ensure!(
            artifact["relative_path"] == format!("adapter/{name}")
                && artifact["bytes"] == files[name]["bytes"]
                && artifact["sha256"] == files[name]["sha256"],
            "aggregate_worker_original_output_binding"
        );
    }
    Ok(())
}

pub(super) struct Approved {
    pub(super) bundle: Vec<u8>,
    pub(super) expires: u64,
    pub(super) identity: Value,
}

/// Reopen a completed aggregation, not a training cycle or a new comparison.
/// Every original authority must still be live when publication is requested.
#[allow(
    clippy::too_many_lines,
    reason = "Recheck the complete frozen cohort before granting publication"
)]
pub(super) fn reopen_approved(root: &Path, limits: &Limits, at: u64) -> Result<Approved> {
    private_directory(root)?;
    let read = |name: &str| -> Result<Value> {
        Ok(serde_json::from_slice(&read_file(
            &root.join(name),
            512 * 1024,
        )?)?)
    };
    let selection = read("selection.json")?;
    ensure!(
        selection["version"] == 1
            && selection["execute"] == true
            && selection["operation"] == "compute_aggregate_adapters"
            && selection["algorithm"] == ALGORITHM,
        "aggregate_original_selection"
    );
    let plan: Plan = serde_json::from_value(selection["plan"].clone())?;
    let source = plan.validate()?;
    let validation: Source = serde_json::from_value(read("validation-source.json")?)?;
    ensure!(
        serde_json::to_value(&validation)? == selection["validation_source"]
            && validation.manifest()? != Some(source.manifest_id),
        "aggregate_original_validation_selection"
    );
    let dataset = read_file(&root.join("dataset.json"), 1024 * 1024)?;
    let validation_data = read_file(&root.join("validation-input/dataset.json"), 1024 * 1024)?;
    let validation_signed = read_file(&root.join("validation-input/dataset.manifest"), 64 * 1024)?;
    let manifest = SignedManifest::decode(&validation_signed)?.verify(&validation.key()?, at)?;
    ensure!(
        Some(*manifest.manifest_id()) == validation.manifest()?
            && manifest.metadata().name == validation.name
            && validation
                .min_revision
                .is_none_or(|floor| manifest.metadata().revision >= floor)
            && manifest.metadata().content_type
                == volparossa_content::provider::compute::dataset::CONTENT_TYPE
            && manifest.length() == validation_data.len() as u64
            && manifest.object_sha256() == &<[u8; 32]>::from(Sha256::digest(&validation_data)),
        "aggregate_original_validation_manifest"
    );
    let validation_value: Value = serde_json::from_slice(&validation_data)?;
    ensure!(
        validation_value["version"] == 1
            && validation_value["visibility"] == "public"
            && validation_value["license"] == "GPL-3.0-only"
            && validation_value["train"]
                .as_array()
                .is_some_and(Vec::is_empty),
        "aggregate_original_public_validation"
    );
    let mut expires = cap_baseline_expiry(&selection, manifest.validity().expires, at)?;
    let mut inputs = Vec::with_capacity(3);
    let mut provenance = Vec::with_capacity(3);
    for (index, channel) in plan.adapters.iter().enumerate() {
        let query = peer_update::Fetch {
            publisher_key: crate::content::parse_publisher_key(&channel.publisher_key)
                .map_err(anyhow::Error::msg)?,
            name: channel.name.clone(),
            min_revision: channel.min_revision,
            cache: root.to_path_buf(),
            limits: limits.clone(),
        };
        // reopen/open_pending perform no cache/network operation; the cache path is unused.
        let parent = root.join("peers").join(index.to_string());
        let imported = peer_update::reopen(&parent.join("import"), &query, &source, at)?;
        let pending = peer_update::open_pending(&parent.join("pending"), &query, at)?;
        ensure!(
            pending.manifest_id() == imported.manifest_id()
                && read_file(&parent.join("import/dataset.json"), 1024 * 1024)? == dataset,
            "aggregate_original_peer_selection"
        );
        let files = peer_evaluation::adapter_files(&parent.join("import/adapter"))?;
        ensure!(
            peer_evaluation::adapter_files(&root.join("cohort").join(index.to_string()))? == files,
            "aggregate_original_cohort_files"
        );
        inputs.push(serde_json::to_value(files)?);
        provenance.push(imported.provenance().clone());
        expires = expires.min(imported.expires());
    }
    let proof = read("cohort.json")?;
    ensure!(
        proof["version"] == 1
            && proof["kind"] == "three_publisher_adapter_aggregation"
            && proof["algorithm"] == ALGORITHM
            && proof["inputs"] == json!(provenance)
            && proof["input_files"] == json!(inputs)
            && proof["dataset_manifest_id"] == hex::encode(source.manifest_id)
            && proof["expires_unix_seconds"] == expires
            && at < expires,
        "aggregate_original_cohort_provenance"
    );
    let baseline = &proof["baseline"];
    if selection["baseline_adapter"].is_null() {
        ensure!(
            baseline == &json!({"kind":"pinned_base","original_path":null,"adapter_files":null}),
            "aggregate_original_base_baseline"
        );
    } else {
        ensure!(
            baseline["kind"] == "configured_adapter"
                && baseline["original_path"] == selection["baseline_adapter"]
                && baseline["adapter_files"]
                    == serde_json::to_value(peer_evaluation::adapter_files(
                        &root.join("baseline")
                    )?)?,
            "aggregate_original_adapter_baseline"
        );
    }
    super::super::train_cycle::guard_overlap(&dataset, &validation_data)?;
    let report = read("aggregate-report.json")?;
    let threads = u16::try_from(
        selection["threads"]
            .as_u64()
            .context("aggregate_original_threads")?,
    )?;
    let seconds = u16::try_from(
        report["supervisor"]["deadline_seconds"]
            .as_u64()
            .context("aggregate_original_deadline")?,
    )?;
    ensure!(
        (1..=2).contains(&threads)
            && (1..=600).contains(&seconds)
            && u64::from(seconds)
                <= selection["worker_deadline_seconds"]
                    .as_u64()
                    .context("aggregate_original_worker_bound")?,
        "aggregate_original_worker_bounds"
    );
    verify_report(
        &report,
        &dataset,
        &inputs,
        &root.join("job/adapter"),
        threads,
        seconds,
    )?;
    let mut original_report = report.clone();
    original_report
        .as_object_mut()
        .context("aggregate_original_worker_report")?
        .remove("supervisor");
    ensure!(
        original_report == read("job/report.json")?,
        "aggregate_original_worker_report_changed"
    );
    let candidate = root.join("candidate");
    let files = peer_evaluation::adapter_files(&candidate.join("import/adapter"))?;
    let comparison = peer_evaluation::verify(&candidate)?;
    let compared_selection = read("candidate/comparison/selection.json")?;
    ensure!(
        comparison.approved
            && comparison.import_proof == proof
            && comparison.baseline_origin == *baseline
            && comparison.candidate_files == files
            && peer_evaluation::adapter_files(&root.join("job/adapter"))? == files
            && read("candidate/import/provenance.json")? == proof
            && read_file(&candidate.join("import/dataset.json"), 1024 * 1024)? == dataset
            && read_file(&candidate.join("comparison/dataset.json"), 1024 * 1024)?
                == validation_data
            && read_file(&candidate.join("comparison/dataset.manifest"), 64 * 1024)?
                == validation_signed
            && read_file(&candidate.join("comparison/provenance.json"), 64 * 1024)?
                == read_file(&root.join("validation-input/provenance.json"), 64 * 1024)?
            && compared_selection["validation_source"] == serde_json::to_value(&validation)?
            && compared_selection["expires"] == expires,
        "aggregate_original_approved_comparison"
    );
    let result = read("result.json")?;
    ensure!(
        result["version"] == 1
            && result["operation"] == "compute_aggregate_adapters"
            && result["approved"] == true
            && result["optimizer_steps"] == 0
            && result["comparison"] == serde_json::to_value(&comparison)?
            && result["cohort"] == proof
            && result["candidate_files"] == serde_json::to_value(&files)?,
        "aggregate_original_result"
    );
    let bundle = read_file(&root.join("adapter.bundle"), 4 * 1024 * 1024)?;
    let decoded = AdapterBundle::decode(bundle.clone())?;
    ensure!(
        decoded.dataset_manifest_id() == source.manifest_id
            && decoded.readme()
                == read_file(&candidate.join("import/adapter/README.md"), 16 * 1024)?
            && decoded.config()
                == read_file(
                    &candidate.join("import/adapter/adapter_config.json"),
                    16 * 1024
                )?
            && decoded.weights()
                == read_file(
                    &candidate.join("import/adapter/adapter_model.safetensors"),
                    2 * 1024 * 1024
                )?
            && result["bundle"]
                == json!({"content_type":ADAPTER_CONTENT_TYPE,"bytes":bundle.len(),
            "sha256":digest(&bundle),"dataset_manifest_id":hex::encode(source.manifest_id),"expires_not_after":expires}),
        "aggregate_original_approved_bundle"
    );
    Ok(Approved {
        bundle,
        expires,
        identity: json!({"kind":"approved_three_publisher_adapter_aggregation",
        "result_sha256":digest(&read_file(&root.join("result.json"),512*1024)?),
        "cohort_sha256":digest(&read_file(&root.join("cohort.json"),512*1024)?),
        "comparison_sha256":digest(&read_file(&candidate.join("comparison/decision.json"),512*1024)?),
        "aggregate_report_sha256":digest(&read_file(&root.join("aggregate-report.json"),512*1024)?),
        "dataset_manifest_id":hex::encode(source.manifest_id),"adapter_files":files,
        "expires_not_after":expires,"optimizer_steps":0,"remote_training_attestation":false}),
    })
}

pub(in crate::compute) async fn run(args: &Options, socket: &Path) -> Result<()> {
    let enrolled = enrollment(args)?;
    if !args.execute {
        println!("{}", serde_json::to_string_pretty(&enrolled.3)?);
        return Ok(());
    }
    let activity = Activity::new()?;
    let result = execute_selected(args, socket, &activity.receiver, enrolled, None).await?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    Ok(())
}

fn cap_baseline_expiry(selection: &Value, expires: u64, at: u64) -> Result<u64> {
    let Some(bound) = selection.get("baseline_expires_unix_seconds") else {
        return Ok(expires);
    };
    let bound = bound.as_u64().context("aggregate_baseline_expiry")?;
    ensure!(
        at < bound && !selection["baseline_adapter"].is_null(),
        "aggregate_baseline_expired"
    );
    Ok(expires.min(bound))
}

#[allow(
    clippy::too_many_lines,
    reason = "Keep explicit cohort freeze, bounded worker and held-out approval in one sequence"
)]
async fn execute_selected(
    args: &Options,
    socket: &Path,
    activity: &watch::Receiver<bool>,
    enrolled: (Plan, DatasetSource, Source, Value),
    frozen: Option<[peer_update::VerifiedUpdate; 3]>,
) -> Result<Value> {
    let (plan, source, validation, mut selection) = enrolled;
    let automatic_training_loop_integration = frozen.is_some();
    ensure!(active(activity), "aggregate_cancelled");
    ensure!(
        (1..=2).contains(&args.threads) && (1..=600).contains(&args.max_seconds),
        "aggregate_worker_bounds"
    );
    ensure!(args.directory.is_absolute(), "aggregate_absolute_directory");
    private_directory(
        args.directory
            .parent()
            .context("aggregate_private_parent")?,
    )?;
    directory(&args.directory)?;
    selection["execute"] = true.into();
    save(&args.directory.join("selection.json"), &selection)?;
    let validation_path = args.directory.join("validation-source.json");
    save(&validation_path, &validation)?;
    let baseline_root = args
        .adapter_root
        .as_ref()
        .map(|_| args.directory.join("baseline"));
    let baseline_files = if let (Some(original), Some(copy)) = (&args.adapter_root, &baseline_root)
    {
        Some(copy_adapter(original, copy)?)
    } else {
        None
    };
    let baseline_origin = json!({"kind":if baseline_root.is_some(){"configured_adapter"}else{"pinned_base"},
        "original_path":args.adapter_root,"adapter_files":baseline_files});
    let mut expires = validation_input(args, &validation, socket, activity).await?;
    expires = cap_baseline_expiry(&selection, expires, now()?)?;
    let peers = args.directory.join("peers");
    let cohort = args.directory.join("cohort");
    directory(&peers)?;
    directory(&cohort)?;
    let mut inputs = Vec::with_capacity(3);
    let mut provenance = Vec::with_capacity(3);
    let mut queries = Vec::with_capacity(3);
    let mut dataset = Vec::new();
    let mut frozen = frozen.map(IntoIterator::into_iter);
    for (index, channel) in plan.adapters.iter().enumerate() {
        ensure!(active(activity), "aggregate_cancelled");
        let parent = peers.join(index.to_string());
        directory(&parent)?;
        let mut query = channel_query(args, channel)?;
        let mut changed = activity.clone();
        let update = if let Some(updates) = &mut frozen {
            updates
                .next()
                .context("aggregate_frozen_cohort_incomplete")?
        } else {
            tokio::select! {biased;
                _=changed.changed()=>anyhow::bail!("aggregate_cancelled"),
                result=peer_update::fetch(&query,socket,&parent)=>result?,
            }
        };
        ensure!(
            update.dataset_manifest_id() == &source.manifest_id,
            "aggregate_same_dataset_required"
        );
        // Preserve original signed bytes before importing, and never replace this selection.
        peer_update::save_pending(&update, &parent.join("pending"))?;
        query.min_revision = Some(update.revision());
        let imported_root = parent.join("import");
        let imported = tokio::select! {biased;
            _=changed.changed()=>anyhow::bail!("aggregate_cancelled"),
            result=peer_update::import(&query,&update,&source,socket,&imported_root)=>result?,
        };
        ensure!(
            imported.manifest_id() == update.manifest_id(),
            "aggregate_manifest_changed"
        );
        expires = expires.min(imported.expires());
        let bytes = read_file(&imported_root.join("dataset.json"), 1024 * 1024)?;
        if index == 0 {
            dataset = bytes;
            write_new(&args.directory.join("dataset.json"), &dataset)?;
        } else {
            ensure!(bytes == dataset, "aggregate_dataset_bytes_changed");
        }
        inputs.push(copy_adapter(
            &imported_root.join("adapter"),
            &cohort.join(index.to_string()),
        )?);
        provenance.push(imported.provenance().clone());
        queries.push(query);
    }
    let validation_bytes = read_file(
        &args.directory.join("validation-input/dataset.json"),
        1024 * 1024,
    )?;
    super::super::train_cycle::guard_overlap(&dataset, &validation_bytes)?;
    let proof = json!({"version":1,"kind":"three_publisher_adapter_aggregation",
        "algorithm":ALGORITHM,"inputs":provenance,"input_files":inputs,
        "dataset_manifest_id":hex::encode(source.manifest_id),"baseline":baseline_origin,
        "expires_unix_seconds":expires,"three_keys_prove_independent_parties":false,
        "remote_training_attestation":false,"quality_guaranteed":false});
    save(&args.directory.join("cohort.json"), &proof)?;
    let started = now()?;
    let seconds = u16::try_from(
        expires
            .checked_sub(started)
            .filter(|n| *n > 0)
            .context("aggregate_source_expired")?
            .min(u64::from(args.max_seconds)),
    )?;
    let options = super::super::Options {
        mode: super::super::Mode::AggregateAdapter,
        model_profile: super::super::ModelProfile::default(),
        runtime_root: args.runtime_root.clone(),
        model_root: args.model_root.clone(),
        adapter_root: Some(cohort.clone()),
        dataset: args.directory.join("dataset.json"),
        output: args.directory.join("job"),
        steps: 1,
        threads: args.threads,
        max_seconds: seconds,
        spare_capacity: true,
        execute: true,
    };
    options.validate()?;
    // Await the actual supervisor on cancellation, never abandon an active worker future.
    let report = super::super::execute(&options, activity.clone()).await?;
    save(&args.directory.join("aggregate-report.json"), &report)?;
    ensure!(
        active(activity) && now()? < expires,
        "aggregate_cancelled_or_expired"
    );
    verify_report(
        &report,
        &dataset,
        &inputs,
        &options.output.join("adapter"),
        args.threads,
        seconds,
    )?;
    let mut raw_report = report.clone();
    raw_report
        .as_object_mut()
        .context("aggregate_worker_report")?
        .remove("supervisor");
    ensure!(
        raw_report
            == serde_json::from_slice::<Value>(&read_file(
                &options.output.join("report.json"),
                16 * 1024
            )?)?,
        "aggregate_original_worker_report_changed"
    );
    ensure!(
        read_file(&options.dataset, 1024 * 1024)? == dataset,
        "aggregate_worker_dataset_changed"
    );
    for (index, query) in queries.iter().enumerate() {
        let restored = peer_update::reopen(
            &peers.join(index.to_string()).join("import"),
            query,
            &source,
            now()?,
        )?;
        ensure!(
            restored.provenance() == &provenance[index]
                && serde_json::to_value(peer_evaluation::adapter_files(
                    &cohort.join(index.to_string())
                )?)? == inputs[index],
            "aggregate_original_cohort_changed"
        );
    }
    if let Some(baseline) = &baseline_root {
        ensure!(
            Some(serde_json::to_value(peer_evaluation::adapter_files(
                baseline
            )?)?)
                == baseline_files,
            "aggregate_frozen_baseline_changed"
        );
    }
    let candidate = args.directory.join("candidate");
    directory(&candidate)?;
    directory(&candidate.join("import"))?;
    let candidate_files = copy_adapter(
        &options.output.join("adapter"),
        &candidate.join("import/adapter"),
    )?;
    write_new(&candidate.join("import/dataset.json"), &dataset)?;
    save(&candidate.join("import/provenance.json"), &proof)?;
    let compared = peer_evaluation::assess(
        &comparison_options(args, validation_path),
        &candidate,
        &args.directory.join("validation-input"),
        baseline_root.as_deref(),
        &baseline_origin,
        &proof,
        activity,
    )
    .await?;
    let (approved, comparison) = match compared {
        peer_evaluation::Outcome::Compared(value) => (value.approved, serde_json::to_value(value)?),
        peer_evaluation::Outcome::Quarantined => (false, json!({"quarantined":true})),
    };
    ensure!(
        active(activity) && now()? < expires,
        "aggregate_cancelled_or_expired"
    );
    let bundle = if approved {
        ensure!(
            serde_json::to_value(peer_evaluation::adapter_files(
                &candidate.join("import/adapter")
            )?)? == candidate_files,
            "aggregate_approved_candidate_changed"
        );
        let adapter = candidate.join("import/adapter");
        let bytes = AdapterBundle::encode(
            source.manifest_id,
            AdapterFiles {
                readme: read_file(&adapter.join("README.md"), 16 * 1024)?,
                config: read_file(&adapter.join("adapter_config.json"), 16 * 1024)?,
                weights: read_file(&adapter.join("adapter_model.safetensors"), 2 * 1024 * 1024)?,
            },
        )?;
        write_new(&args.directory.join("adapter.bundle"), &bytes)?;
        Some(
            json!({"content_type":ADAPTER_CONTENT_TYPE,"bytes":bytes.len(),"sha256":digest(&bytes),
            "dataset_manifest_id":hex::encode(source.manifest_id),"expires_not_after":expires}),
        )
    } else {
        None
    };
    let result = json!({"version":1,"operation":"compute_aggregate_adapters","approved":approved,
        "comparison":comparison,"cohort":proof,"candidate_files":candidate_files,"bundle":bundle,
        "network_publication":false,"model_activated":false,"optimizer_steps":0,
        "automatic_training_loop_integration":automatic_training_loop_integration,"general_quality_proven":false});
    save(&args.directory.join("result.json"), &result)?;
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    use ed25519_dalek::SigningKey;

    fn plan() -> Plan {
        let key = |byte| {
            hex::encode(
                SigningKey::from_bytes(&[byte; 32])
                    .verifying_key()
                    .as_bytes(),
            )
        };
        Plan {
            version: 1,
            dataset: Dataset {
                publisher_key: key(1),
                name: "training".into(),
                revision: 1,
                manifest_id: "a".repeat(64),
            },
            adapters: [2, 3, 4].map(|byte| Channel {
                publisher_key: key(byte),
                name: "adapter".into(),
                min_revision: Some(1),
            }),
        }
    }

    #[test]
    fn three_publishers_are_independent_authority_selections_not_three_channel_names() {
        let mut selected = plan();
        assert!(selected.validate().is_ok());
        selected.adapters[1].publisher_key = selected.adapters[0].publisher_key.clone();
        selected.adapters[1].name = "different-channel".into();
        assert!(selected.validate().is_err());
        let mut selected = plan();
        selected.dataset.manifest_id = "0".repeat(64);
        assert!(selected.validate().is_err());
        let mut selected = serde_json::to_value(plan()).unwrap();
        selected["adapters"].as_array_mut().unwrap().pop();
        assert!(serde_json::from_value::<Plan>(selected).is_err());
    }

    #[test]
    fn fixed_copy_retains_all_original_adapter_bytes() {
        let root = tempfile::tempdir().unwrap();
        let input = root.path().join("input");
        let output = root.path().join("output");
        directory(&input).unwrap();
        for (name, _) in FILES {
            write_new(&input.join(name), name.as_bytes()).unwrap();
        }
        let copied = copy_adapter(&input, &output).unwrap();
        assert_eq!(
            copied,
            serde_json::to_value(peer_evaluation::adapter_files(&input).unwrap()).unwrap()
        );
        assert!(copy_adapter(&input, &output).is_err());
    }

    #[test]
    fn worker_report_binds_all_three_original_inputs_and_actual_output_files() {
        let root = tempfile::tempdir().unwrap();
        let adapter = root.path().join("adapter");
        directory(&adapter).unwrap();
        for (name, _) in FILES {
            write_new(&adapter.join(name), name.as_bytes()).unwrap();
        }
        let files =
            serde_json::to_value(peer_evaluation::adapter_files(&adapter).unwrap()).unwrap();
        let inputs = vec![files.clone(), files.clone(), files.clone()];
        let dataset = b"public synthetic report-binding fixture, not model output";
        let artifacts: Vec<Value> = FILES
            .iter()
            .map(|(name, _)| {
                json!({
            "relative_path":format!("adapter/{name}"),"bytes":files[name]["bytes"],
            "sha256":files[name]["sha256"]})
            })
            .collect();
        let report = json!({"version":1,"kind":"result","status":"ok",
            "mode":"aggregate_adapter","device":"cpu","model_weights_loaded":false,
            "updates_completed":0,"threads":2,"elapsed_ms":500,
            "dataset":{"bytes":dataset.len(),"sha256":digest(dataset)},
            "model":{"id":MODEL_ID,"revision":MODEL_REVISION,
                "files":{"model.safetensors":{"sha256":hex::encode(BASE_MODEL_SHA256)}}},
            "aggregation":{"algorithm":ALGORITHM,"input_files":inputs,"combined_modules":60},
            "supervisor":{"child_reaped":true,"network_access":false,"spare_capacity":true,
                "deadline_seconds":600},"artifacts":artifacts});
        verify_report(&report, dataset, &inputs, &adapter, 2, 600).unwrap();
        for (pointer, value) in [
            ("/mode", json!("train")),
            ("/updates_completed", json!(1)),
            ("/dataset/sha256", json!("b".repeat(64))),
            (
                "/aggregation/input_files/1/README.md/sha256",
                json!("c".repeat(64)),
            ),
            ("/artifacts/2/sha256", json!("d".repeat(64))),
            ("/supervisor/child_reaped", json!(false)),
        ] {
            let mut changed = report.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(verify_report(&changed, dataset, &inputs, &adapter, 2, 600).is_err());
        }
    }

    #[test]
    fn preview_validates_authorities_without_creating_a_work_directory() {
        #[derive(clap::Parser)]
        struct Cli {
            #[command(flatten)]
            options: Options,
        }
        use clap::Parser as _;
        let root = tempfile::tempdir().unwrap();
        let plan_path = root.path().join("plan.json");
        let validation_path = root.path().join("validation.json");
        save(&plan_path, &plan()).unwrap();
        save(
            &validation_path,
            &json!({"publisher_key":plan().dataset.publisher_key,
            "name":"validation","manifest_id":"b".repeat(64),"min_revision":1}),
        )
        .unwrap();
        let args = Cli::try_parse_from([
            "test".into(),
            "--plan".into(),
            plan_path.display().to_string(),
            "--validation-source".into(),
            validation_path.display().to_string(),
            "--directory".into(),
            root.path().join("not-created").display().to_string(),
            "--runtime-root".into(),
            "/not-provisioned/runtime".into(),
            "--model-root".into(),
            "/not-provisioned/model".into(),
            "--cache".into(),
            "/not-acquired/cache".into(),
        ])
        .unwrap()
        .options;
        let (_, _, _, result) = enrollment(&args).unwrap();
        assert_eq!(result["execute"], false);
        assert_eq!(result["network_publication"], false);
        assert_eq!(result["model_activated"], false);
        assert!(!args.directory.exists());
        let mut loop_args = comparison_options(&args, validation_path.clone());
        assert!(loop_selection(&loop_args).unwrap().is_none());
        loop_args.aggregate_plan = Some(plan_path.clone());
        let frozen = loop_selection(&loop_args).unwrap().unwrap();
        let selected: LoopSelection = serde_json::from_value(frozen.clone()).unwrap();
        assert_eq!(
            selected.validate().unwrap().manifest_id,
            plan().validate().unwrap().manifest_id
        );
        assert_eq!(frozen["plan"], serde_json::to_value(plan()).unwrap());
        assert_eq!(frozen["validation_source"]["manifest_id"], "b".repeat(64));
        assert!(!args.directory.exists());
        // These are disposable test files. Discovery/execute use the saved value,
        // and never reopen owner configuration after the explicit selection.
        fs::write(&plan_path, b"changed after enrollment").unwrap();
        fs::write(&validation_path, b"changed after enrollment").unwrap();
        assert!(loop_selection(&loop_args).is_err());
        assert!(
            serde_json::from_value::<LoopSelection>(frozen)
                .unwrap()
                .validate()
                .is_ok()
        );
        loop_args.aggregate_plan = None;
        loop_args.validation_source = None;
        let executed = loop_options(&loop_args, &args.directory, None);
        assert_eq!(executed.plan, args.directory.join("selection.json"));
        assert_eq!(
            executed.validation_source,
            args.directory.join("validation-source.json")
        );
        assert!(loop_selection(&loop_args).unwrap().is_none());
    }

    #[test]
    fn frozen_loop_selection_requires_exact_independent_validation() {
        let mut selected = LoopSelection {
            version: 1,
            plan: plan(),
            validation_source: Source {
                publisher_key: plan().dataset.publisher_key,
                name: "validation".into(),
                min_revision: Some(1),
                manifest_id: Some("b".repeat(64)),
            },
        };
        assert!(selected.validate().is_ok());
        selected.validation_source.manifest_id = Some(selected.plan.dataset.manifest_id.clone());
        assert!(selected.validate().is_err());
        selected.validation_source.manifest_id = None;
        assert!(selected.validate().is_err());
        selected.validation_source.manifest_id = Some("b".repeat(64));
        selected.validation_source.min_revision = Some(0);
        assert!(selected.validate().is_err());
    }

    #[test]
    fn inherited_baseline_expiry_only_shortens_original_authorities() {
        let legacy = json!({"baseline_adapter":null});
        assert_eq!(cap_baseline_expiry(&legacy, 3000, 1000).unwrap(), 3000);
        assert!(legacy.get("baseline_expires_unix_seconds").is_none());
        let selected = json!({"baseline_adapter":"/owner/original-adapter",
            "baseline_expires_unix_seconds":2000});
        assert_eq!(cap_baseline_expiry(&selected, 3000, 1000).unwrap(), 2000);
        assert_eq!(cap_baseline_expiry(&selected, 1500, 1000).unwrap(), 1500);
        assert!(cap_baseline_expiry(&selected, 3000, 2000).is_err());
        let mut invalid = selected.clone();
        invalid["baseline_adapter"] = Value::Null;
        assert!(cap_baseline_expiry(&invalid, 3000, 1000).is_err());
        for bound in [Value::Null, json!(true), json!(0), json!("2000")] {
            let mut invalid = selected.clone();
            invalid["baseline_expires_unix_seconds"] = bound;
            assert!(cap_baseline_expiry(&invalid, 3000, 1000).is_err());
        }
    }
}
