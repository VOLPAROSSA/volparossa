//! Explicit finite public work enrollment, not autonomous planning or model-layer sharding.
//! Each invocation advances a bounded number of ordinary distribute/reconcile rounds.

mod cohort;

pub(super) use cohort::report_group_with_activity;

use std::{
    collections::{BTreeMap, BTreeSet},
    os::unix::fs::{DirBuilderExt, MetadataExt, OpenOptionsExt},
};

use volparossa_content::provider::compute::dataset::VerifiedPublicDataset;

use super::*;

const MAX_PLAN_BYTES: usize = 64 * 1024;
const MAX_PACKAGES: usize = 32;
const MAX_ATTEMPTS: usize = 128;
// A bounded RPC response plus the additional exact handle and local verification metadata.
const MAX_RECEIPT_BYTES: usize = rpc::MAX_RESPONSE_BYTES + 32 * 1024;

/// Absent in retained histories means the original grouped-batch contract.
#[derive(Clone, Copy, Debug, Default, Deserialize, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Scheduling {
    #[default]
    BatchBarrierV1,
    ReadyRowsV1,
}

impl Scheduling {
    pub(super) const fn from_batch_barrier(barrier: bool) -> Self {
        if barrier {
            Self::BatchBarrierV1
        } else {
            Self::ReadyRowsV1
        }
    }

    #[allow(
        clippy::trivially_copy_pass_by_ref,
        reason = "Serde skip_serializing_if takes a reference"
    )]
    pub(super) const fn is_legacy(&self) -> bool {
        matches!(self, Self::BatchBarrierV1)
    }
}

#[derive(Debug, Args)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Independent explicit CLI enrollment and execution switches"
)]
pub(crate) struct Options {
    /// Version-1 JSON with explicit dataset, `dataset_manifest` and `publisher_key` packages.
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    plan: Option<PathBuf>,
    /// New private workflow directory, or the previously enrolled directory with --resume.
    #[arg(long)]
    directory: PathBuf,
    /// Resume the exact stored sources and peer list; never replace their authorization.
    #[arg(long)]
    resume: bool,
    /// Retain grouped batches for a new enrollment; default refills free peers per source row.
    #[arg(long, conflicts_with = "resume")]
    batch_barrier: bool,
    /// Two to four explicit peers at enrollment; stored unchanged for subsequent invocations.
    #[arg(long, value_parser = parse_key, required_unless_present_any = ["resume", "discover_peers"], conflicts_with_all = ["resume", "discover_peers"])]
    provider_key: Vec<VerifyingKey>,
    #[command(flatten)]
    discovery: discovery::Options,
    /// New rounds per invocation, or per continuation window with --follow; not a worker lease.
    #[arg(long, default_value_t = 1, value_parser = clap::value_parser!(u16).range(1..=32))]
    max_batches: u16,
    /// Per-executor lease; every later round is a distinct explicitly authorized attempt.
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u16).range(1..=600))]
    max_seconds: u16,
    /// Preview only unless explicitly enabled; no subprocess recursion or model downloads.
    #[arg(long)]
    execute: bool,
    #[command(flatten)]
    follow: follow::Options,
    #[arg(skip)]
    expected_task: Option<ExpectedTask>,
    #[arg(skip)]
    expected_model_fingerprint: Option<String>,
    #[arg(skip)]
    expected_replace_peers: bool,
}

/// Exact frontend selection, checked under the workflow lock before any dispatch.
#[derive(Clone, Debug)]
pub(super) struct ExpectedTask {
    pub(super) publisher_key: String,
    pub(super) manifest_id: String,
    pub(super) dataset_sha256: String,
    pub(super) rows: usize,
    pub(super) task: rpc::PublicTask,
    pub(super) provider_keys: Vec<String>,
    pub(super) model_fingerprint: Option<String>,
    pub(super) replace_peers: bool,
    pub(super) scheduling: Scheduling,
    pub(super) selected_at_unix_seconds: u64,
}

impl Options {
    pub(super) fn task(
        plan: Option<PathBuf>,
        directory: PathBuf,
        provider_keys: Vec<VerifyingKey>,
        max_batches: u16,
        max_seconds: u16,
        execute: bool,
    ) -> Self {
        Self {
            resume: plan.is_none(),
            batch_barrier: false,
            plan,
            directory,
            provider_key: provider_keys,
            discovery: discovery::Options::default(),
            max_batches,
            max_seconds,
            execute,
            follow: follow::Options::default(),
            expected_task: None,
            expected_model_fingerprint: None,
            expected_replace_peers: false,
        }
    }

    pub(super) fn expect_task(mut self, expected: ExpectedTask) -> Self {
        self.expected_replace_peers = expected.replace_peers;
        self.expected_model_fingerprint
            .clone_from(&expected.model_fingerprint);
        self.expected_task = Some(expected);
        self
    }

    pub(super) fn with_follow(mut self, options: follow::Options) -> Self {
        self.follow = options;
        self
    }
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Plan {
    version: u32,
    packages: Vec<PackageInput>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PackageInput {
    dataset: PathBuf,
    dataset_manifest: PathBuf,
    publisher_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    task: Option<rpc::PublicTask>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    version: u32,
    #[serde(default, skip_serializing_if = "Scheduling::is_legacy")]
    scheduling: Scheduling,
    verified_at_unix_seconds: u64,
    provider_keys: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    model_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    replace_peers: bool,
    packages: Vec<Package>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Package {
    publisher_key: String,
    manifest_id: String,
    dataset_sha256: String,
    rows: usize,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    task: Option<rpc::PublicTask>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u32,
    handle: JobHandle,
    status: rpc::JobStatus,
    verified_at_unix_seconds: u64,
}

struct Part {
    path: PathBuf,
    handle: JobHandle,
    status: Option<rpc::JobStatus>,
}

struct Progress {
    parts: BTreeMap<Vec<u16>, Part>,
    attempts: usize,
    rows: usize,
    model_fingerprint: Option<String>,
}

impl Progress {
    fn ready_rows(&self) -> Result<Vec<u16>> {
        (0..self.rows)
            .map(u16::try_from)
            .filter_map(|row| match row {
                Ok(row) if self.parts.contains_key(&vec![row]) => None,
                result => Some(result.map_err(anyhow::Error::from)),
            })
            .collect()
    }

    fn ready_pending(&self) -> Vec<batch::ReadyPending> {
        self.parts
            .values()
            .filter(|part| {
                !part
                    .status
                    .as_ref()
                    .is_some_and(|status| status.state == rpc::JobState::Complete)
            })
            .map(|part| batch::ReadyPending {
                handle: part.handle.clone(),
                verified_status: part.status.clone(),
            })
            .collect()
    }

    fn complete(&self) -> bool {
        self.parts
            .values()
            .map(|part| part.handle.binding.row_indices.len())
            .sum::<usize>()
            == self.rows
            && self.parts.values().all(|part| {
                part.status
                    .as_ref()
                    .is_some_and(|status| status.state == rpc::JobState::Complete)
            })
    }

    fn pending(&self) -> Vec<PathBuf> {
        self.parts
            .values()
            .filter(|part| {
                !part
                    .status
                    .as_ref()
                    .is_some_and(|status| status.state == rpc::JobState::Complete)
            })
            .map(|part| part.path.clone())
            .collect()
    }

    fn outputs(&self) -> Result<Vec<serde_json::Value>> {
        self.output_rows(false)
    }

    fn stopped_receipts(&self) -> Vec<(JobHandle, rpc::JobStatus)> {
        self.parts
            .values()
            .filter_map(|part| {
                part.status
                    .as_ref()
                    .filter(|status| {
                        matches!(
                            status.state,
                            rpc::JobState::Failed | rpc::JobState::Cancelled
                        )
                    })
                    .map(|status| (part.handle.clone(), status.clone()))
            })
            .collect()
    }

    fn output_rows(&self, detailed: bool) -> Result<Vec<serde_json::Value>> {
        let mut outputs = Vec::new();
        for part in self.parts.values() {
            if let Some(status) = part
                .status
                .as_ref()
                .filter(|value| value.state == rpc::JobState::Complete)
            {
                let report: serde_json::Value = serde_json::from_str(
                    status
                        .report_json
                        .as_deref()
                        .context("compute_workflow_report")?,
                )?;
                let rows = report["outputs"]
                    .as_array()
                    .context("compute_workflow_outputs")?;
                for (index, row) in part.handle.binding.row_indices.iter().enumerate() {
                    let mut output = serde_json::json!({"sample_index":row,"text":rows[index]["text"],
                        "provider_key":part.handle.provider_key,"job_id":part.handle.binding.job_id,
                        "report_sha256":status.report_sha256});
                    batch::output::retain(&rows[index], &mut output)?;
                    if detailed {
                        output["output_index"] = index.into();
                        output["model_fingerprint"] =
                            part.handle.binding.model_fingerprint.clone().into();
                        output["generated_tokens"] = rows[index]["generated_tokens"].clone();
                        output["text_truncated"] = rows[index]["text_truncated"].clone();
                    }
                    outputs.push(output);
                }
            }
        }
        outputs.sort_by_key(|value| value["sample_index"].as_u64());
        Ok(outputs)
    }
}

pub(super) async fn run(args: &Options, socket: &Path) -> Result<()> {
    let report = report(args, socket).await?;
    println!("{}", serde_json::to_string(&report)?);
    ensure!(
        report["pending_failure"] != true,
        "compute_workflow_pending_state_retained"
    );
    Ok(())
}

pub(super) async fn report(args: &Options, socket: &Path) -> Result<serde_json::Value> {
    let cancellation = Cancellation::new()?;
    report_with_activity(args, socket, &cancellation.activity).await
}

pub(super) async fn report_with_activity(
    args: &Options,
    socket: &Path,
    cancelled: &tokio::sync::watch::Receiver<bool>,
) -> Result<serde_json::Value> {
    let (enrollment, lock) = if args.resume {
        super::super::private_directory(&args.directory)?;
        let lock = args
            .execute
            .then(|| lock_directory(&args.directory))
            .transpose()?;
        let enrollment = serde_json::from_slice(&read_file(
            &args.directory.join("workflow.json"),
            MAX_PLAN_BYTES,
        )?)?;
        (enrollment, lock)
    } else {
        let (mut enrollment, sources) = prepare(args)?;
        if args.discovery.discover_peers && args.execute {
            let versions = sources
                .iter()
                .map(|source| {
                    serde_json::from_str::<serde_json::Value>(&source.dataset_json)
                        .map(|value| value["version"].as_u64().unwrap_or(0))
                })
                .collect::<Result<Vec<_>, _>>()?;
            let query = args.discovery.query(
                enrollment
                    .packages
                    .iter()
                    .map(|package| package.publisher_key.clone()),
                enrollment
                    .packages
                    .iter()
                    .any(|package| package.task.is_some()),
                versions.contains(&2),
                versions.contains(&3),
            )?;
            let selected = args.discovery.select(socket, query, cancelled).await?;
            enrollment.provider_keys = selected
                .providers
                .iter()
                .map(|key| hex::encode(key.as_bytes()))
                .collect();
            enrollment.model_fingerprint = Some(selected.model_fingerprint);
            validate_enrollment(&enrollment)?;
        }
        if let Some(expected) = &args.expected_task {
            validate_expected_task(&enrollment, expected)?;
        }
        if args.execute {
            persist_enrollment(&args.directory, &enrollment, &sources)?;
            (enrollment, Some(lock_directory(&args.directory)?))
        } else {
            return Ok(
                serde_json::json!({"operation":"compute_workflow_plan","execute":false,
                "package_count":enrollment.packages.len(),"total_rows":enrollment.packages.iter().map(|value|value.rows).sum::<usize>(),
                "maximum_rounds_this_invocation":args.max_batches,"maximum_seconds_per_worker":args.max_seconds,
                "private_data_supported":false,"automatic_source_discovery":false,"new_directory":args.directory,
                "discover_peers":args.discovery.discover_peers,
                "replace_peers":args.discovery.replace_peers,
                "scheduling":enrollment.scheduling,
                "pending_failure":false,"follow":args.follow.follow}),
            );
        }
    };
    validate_enrollment(&enrollment)?;
    if let Some(expected) = &args.expected_task {
        validate_expected_task(&enrollment, expected)?;
    }
    let result = follow::run(&args.follow, cancelled, || {
        advance(args, socket, &enrollment, cancelled)
    })
    .await;
    drop(lock);
    result
}

fn prepare(args: &Options) -> Result<(Enrollment, Vec<rpc::PublicDataset>)> {
    let plan: Plan = serde_json::from_slice(&read_file(
        args.plan
            .as_ref()
            .context("compute_workflow_plan_required")?,
        MAX_PLAN_BYTES,
    )?)?;
    ensure!(
        plan.version == 1 && (1..=MAX_PACKAGES).contains(&plan.packages.len()),
        "compute_workflow_plan_bound"
    );
    let at = now()?;
    let mut packages = Vec::new();
    let mut sources = Vec::new();
    for input in plan.packages {
        let args = Source {
            dataset: input.dataset,
            dataset_manifest: input.dataset_manifest,
            publisher_key: parse_key(&input.publisher_key).map_err(anyhow::Error::msg)?,
        };
        let (public, verified) = source(&args)?;
        ensure!(
            (2..=4).contains(&verified.row_count())
                || (verified.is_document() && verified.row_count() == 1),
            "compute_workflow_package_row_profile"
        );
        packages.push(Package {
            publisher_key: public.publisher_key.clone(),
            manifest_id: hex::encode(verified.manifest_id()),
            dataset_sha256: sha(public.dataset_json.as_bytes()),
            rows: verified.row_count(),
            task: input.task,
        });
        sources.push(public);
    }
    let enrollment = Enrollment {
        version: 1,
        scheduling: args.expected_task.as_ref().map_or_else(
            || Scheduling::from_batch_barrier(args.batch_barrier),
            |expected| expected.scheduling,
        ),
        verified_at_unix_seconds: at,
        provider_keys: args
            .provider_key
            .iter()
            .map(|key| hex::encode(key.as_bytes()))
            .collect(),
        model_fingerprint: args.expected_model_fingerprint.clone(),
        replace_peers: args.discovery.replace_peers || args.expected_replace_peers,
        packages,
    };
    if args.discovery.discover_peers {
        ensure!(
            args.provider_key.is_empty(),
            "compute_discovery_conflicting_providers"
        );
        validate_packages(&enrollment.packages)?;
    } else {
        validate_enrollment(&enrollment)?;
    }
    Ok((enrollment, sources))
}

fn validate_enrollment(enrollment: &Enrollment) -> Result<()> {
    ensure!(
        !enrollment.replace_peers || enrollment.model_fingerprint.is_some(),
        "compute_executor_replacement_requires_pinned_model"
    );
    ensure!(
        enrollment.version == 1
            && enrollment.verified_at_unix_seconds > 0
            && enrollment.verified_at_unix_seconds <= now()?
            && (1..=MAX_PACKAGES).contains(&enrollment.packages.len())
            && (2..=4).contains(&enrollment.provider_keys.len()),
        "compute_workflow_enrollment_bound"
    );
    let providers: BTreeSet<_> = enrollment.provider_keys.iter().collect();
    ensure!(
        providers.len() == enrollment.provider_keys.len(),
        "compute_workflow_duplicate_provider"
    );
    for key in &enrollment.provider_keys {
        parse_key(key).map_err(anyhow::Error::msg)?;
    }
    if let Some(fingerprint) = &enrollment.model_fingerprint {
        discovery::parse_fingerprint(fingerprint).map_err(anyhow::Error::msg)?;
    }
    validate_packages(&enrollment.packages)
}

fn validate_packages(packages: &[Package]) -> Result<()> {
    let mut ids = BTreeSet::new();
    for package in packages {
        if let Some(task) = &package.task {
            task.question()?;
        }
        ensure!(
            (1..=4).contains(&package.rows) && ids.insert(&package.manifest_id),
            "compute_workflow_duplicate_or_invalid_package"
        );
    }
    Ok(())
}

fn validate_expected_task(enrollment: &Enrollment, expected: &ExpectedTask) -> Result<()> {
    ensure!(
        enrollment.packages.len() == 1
            && enrollment.provider_keys == expected.provider_keys
            && enrollment.model_fingerprint == expected.model_fingerprint
            && enrollment.replace_peers == expected.replace_peers
            && enrollment.scheduling == expected.scheduling
            && enrollment.verified_at_unix_seconds >= expected.selected_at_unix_seconds,
        "compute_task_workflow_selection"
    );
    let package = &enrollment.packages[0];
    ensure!(
        package.publisher_key == expected.publisher_key
            && package.manifest_id == expected.manifest_id
            && package.dataset_sha256 == expected.dataset_sha256
            && package.rows == expected.rows
            && package.task.as_ref() == Some(&expected.task),
        "compute_task_workflow_source_or_task"
    );
    Ok(())
}

/// Re-read the retained full statuses, not caller-supplied output hashes or completeness flags.
pub(super) fn task_snapshot(
    directory: &Path,
    expected: &ExpectedTask,
) -> Result<serde_json::Value> {
    snapshot(directory, expected, false)
}

/// Full checked worker output metadata, without changing the established public snapshot shape.
pub(super) fn task_snapshot_detailed(
    directory: &Path,
    expected: &ExpectedTask,
) -> Result<serde_json::Value> {
    snapshot(directory, expected, true)
}

fn snapshot(
    directory: &Path,
    expected: &ExpectedTask,
    detailed: bool,
) -> Result<serde_json::Value> {
    super::super::private_directory(directory)?;
    let _lock = lock_directory(directory)?;
    let enrollment: Enrollment = serde_json::from_slice(&read_file(
        &directory.join("workflow.json"),
        MAX_PLAN_BYTES,
    )?)?;
    validate_enrollment(&enrollment)?;
    validate_expected_task(&enrollment, expected)?;
    let package = &enrollment.packages[0];
    let directory = directory.join("package-0000");
    let (source, verified) =
        stored_source(&directory, package, enrollment.verified_at_unix_seconds)?;
    let progress = load_progress(&directory, &source, &verified, &enrollment)?;
    let outputs = progress.output_rows(detailed)?;
    let answer_complete = progress.complete() && batch::output::all_complete(&outputs)?;
    Ok(
        serde_json::json!({"dataset_manifest_id":package.manifest_id,"task":package.task,
        "complete":progress.complete(),"execution_complete":progress.complete(),
        "answer_complete":answer_complete,"outputs":outputs}),
    )
}

fn persist_enrollment(
    directory: &Path,
    enrollment: &Enrollment,
    sources: &[rpc::PublicDataset],
) -> Result<()> {
    super::super::private_directory(directory.parent().context("compute_workflow_parent")?)?;
    fs::DirBuilder::new().mode(0o700).create(directory)?;
    for (index, public) in sources.iter().enumerate() {
        let package = directory.join(format!("package-{index:04}"));
        fs::DirBuilder::new().mode(0o700).create(&package)?;
        save_bytes(
            &package.join("dataset.json"),
            public.dataset_json.as_bytes(),
        )?;
        save_bytes(
            &package.join("manifest.bin"),
            &hex::decode(&public.manifest_hex)?,
        )?;
    }
    // Committed last. An interrupted enrollment has never submitted any remote work.
    save_new(&directory.join("workflow.json"), enrollment)?;
    fs::File::open(directory.parent().context("compute_workflow_parent")?)?.sync_all()?;
    Ok(())
}

fn save_bytes(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().context("compute_workflow_source_parent")?;
    let mut file = tempfile::NamedTempFile::new_in(parent)?;
    file.write_all(bytes)?;
    file.flush()?;
    file.as_file().sync_all()?;
    file.persist_noclobber(path).map_err(|error| error.error)?;
    fs::File::open(parent)?.sync_all()?;
    Ok(())
}

fn lock_directory(directory: &Path) -> Result<nix::fcntl::Flock<fs::File>> {
    let file = fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(false)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(directory.join(".workflow.lock"))?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file()
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.nlink() == 1
            && metadata.mode() & 0o777 == 0o600,
        "compute_workflow_lock_owner"
    );
    nix::fcntl::Flock::lock(file, nix::fcntl::FlockArg::LockExclusiveNonblock)
        .map_err(|(_, error)| anyhow::anyhow!("compute_workflow_already_running: {error}"))
}

fn stored_source(
    directory: &Path,
    package: &Package,
    at: u64,
) -> Result<(Source, VerifiedPublicDataset)> {
    super::super::private_directory(directory)?;
    let source = Source {
        dataset: directory.join("dataset.json"),
        dataset_manifest: directory.join("manifest.bin"),
        publisher_key: parse_key(&package.publisher_key).map_err(anyhow::Error::msg)?,
    };
    let data = read_file(&source.dataset, rpc::MAX_DATASET_BYTES)?;
    let verified = verify_source(
        &read_file(&source.dataset_manifest, 64 * 1024)?,
        &source.publisher_key,
        std::str::from_utf8(&data)?,
        at,
    )?;
    ensure!(
        sha(&data) == package.dataset_sha256
            && hex::encode(verified.manifest_id()) == package.manifest_id
            && verified.row_count() == package.rows
            && (package.rows >= 2 || verified.is_document()),
        "compute_workflow_stored_source_changed"
    );
    Ok((source, verified))
}

// Persist only a fixed local category, never a provider exception, prompt or filesystem path.
fn failure_code(error: &anyhow::Error) -> &'static str {
    match error.to_string().as_str() {
        "compute_distribute_capability_probe_unavailable" => "capability_unavailable",
        "compute_distribute_capability_probe_timeout" => "capability_timeout",
        "compute_distribute_peer_busy" => "peer_busy",
        "compute_distribute_cancelled_before_submit" => "owner_cancelled_before_submit",
        "compute_distribute_incompatible_models" | "compute_peer_profile" => "incompatible_model",
        "compute_peer_document_not_supported" | "compute_peer_task_not_supported" => {
            "unsupported_profile"
        }
        "compute_peer_job_rejected" => "job_rejected",
        "compute_peer_source_expired" => "source_expired",
        _ => "execution_or_verification_failed",
    }
}

fn round_failure(result: &Result<serde_json::Value>) -> Option<&'static str> {
    match result {
        Err(error) => Some(failure_code(error)),
        Ok(report) if report["complete"] == true => None,
        Ok(report) => Some(
            if report["jobs"]
                .as_array()
                .is_some_and(|jobs| jobs.iter().any(|job| job["state"] == "unconfirmed"))
            {
                // This says nothing about whether a remote worker started or stopped.
                "jobs_unconfirmed"
            } else {
                "jobs_incomplete"
            },
        ),
    }
}

fn replacement_authorization(
    enrollment: &Enrollment,
    package: &Package,
    source: &VerifiedPublicDataset,
) -> Result<Option<executors::Authorization>> {
    if !enrollment.replace_peers {
        return Ok(None);
    }
    Ok(Some(executors::Authorization {
        workflow_sha256: sha(&serde_json::to_vec(enrollment)?),
        publisher_key: package.publisher_key.clone(),
        dataset_manifest_id: package.manifest_id.clone(),
        dataset_sha256: package.dataset_sha256.clone(),
        model_fingerprint: enrollment
            .model_fingerprint
            .clone()
            .context("compute_executor_replacement_requires_pinned_model")?,
        task: package.task.clone(),
        document: source.is_document(),
        derived: source.is_derived(),
        enrolled_at: enrollment.verified_at_unix_seconds,
        source_expires: source.expires(),
    }))
}

async fn initial_round(
    options: &batch::Options,
    output: &Path,
    authorization: Option<&executors::Authorization>,
    replacement_options: impl FnOnce(&executors::Authorization, discovery::Selected) -> batch::Options,
    socket: &Path,
    cancelled: &tokio::sync::watch::Receiver<bool>,
) -> Result<serde_json::Value> {
    let first = batch::report_with_activity(options, socket, cancelled).await;
    let Some(authorization) = authorization else {
        return first;
    };
    if !first.as_ref().is_err_and(follow::transient_preflight)
        || output.try_exists()?
        || *cancelled.borrow()
    {
        return first;
    }
    // No handle or output directory exists: the failed preflight could not have submitted.
    // The original source/model permission is unchanged, and the fresh batch retains its
    // admission record and every handle before sending the first real job.
    let Ok(selected) = executors::discover(authorization, socket, cancelled).await else {
        return first;
    };
    batch::report_with_activity(
        &replacement_options(authorization, selected),
        socket,
        cancelled,
    )
    .await
}

async fn ready_round(
    mut options: batch::ReadyOptions,
    authorization: Option<&executors::Authorization>,
    later_attempt: bool,
    socket: &Path,
    cancelled: &tokio::sync::watch::Receiver<bool>,
) -> Result<serde_json::Value> {
    // New rows have never been leased. A fresh authorized cohort may accept them without
    // retargeting any old handle; those handles are still observed under their original lease.
    if later_attempt {
        if let Some(authorization) = authorization {
            if let Ok(selected) = executors::discover(authorization, socket, cancelled).await {
                options.providers.clone_from(&selected.providers);
                options.executor_admission = Some((authorization.clone(), selected));
            }
        }
    }
    let first = batch::report_ready_with_activity(&options, socket, cancelled).await;
    let Some(authorization) = authorization else {
        return first;
    };
    if options.executor_admission.is_some()
        || !first.as_ref().is_err_and(follow::transient_preflight)
        || options.output.try_exists()?
        || *cancelled.borrow()
    {
        return first;
    }
    let Ok(selected) = executors::discover(authorization, socket, cancelled).await else {
        return first;
    };
    options.providers.clone_from(&selected.providers);
    options.executor_admission = Some((authorization.clone(), selected));
    batch::report_ready_with_activity(&options, socket, cancelled).await
}

#[allow(
    clippy::too_many_lines,
    reason = "Keep one bounded admission/reconciliation window and its retained progress together"
)]
async fn advance(
    args: &Options,
    socket: &Path,
    enrollment: &Enrollment,
    cancelled: &tokio::sync::watch::Receiver<bool>,
) -> Result<serde_json::Value> {
    if args.execute
        && enrollment.scheduling == Scheduling::ReadyRowsV1
        && enrollment.packages.len() > 1
    {
        return Ok(
            cohort::advance(&[(args, enrollment)], args.max_batches, socket, cancelled)
                .await?
                .remove(0),
        );
    }
    let providers: Vec<_> = enrollment
        .provider_keys
        .iter()
        .map(|key| parse_key(key).map_err(anyhow::Error::msg))
        .collect::<Result<_>>()?;
    let mut rounds = 0;
    let mut completed = 0;
    let mut packages = Vec::new();
    let mut stopped = if args.execute {
        "invocation_budget"
    } else {
        "preview"
    };
    let mut failed = false;
    let mut pending_expiry = None;
    for (index, package) in enrollment.packages.iter().enumerate() {
        let directory = args.directory.join(format!("package-{index:04}"));
        // Historical authentication allows already verified completed work to survive source
        // expiry. Admission below still checks the unchanged signed source against real now().
        let (source_args, verified) =
            stored_source(&directory, package, enrollment.verified_at_unix_seconds)?;
        let mut progress = load_progress(&directory, &source_args, &verified, enrollment)?;
        let authorization = replacement_authorization(enrollment, package, &verified)?;
        let mut package_failure = None;
        if !progress.complete()
            && args.execute
            && rounds < args.max_batches
            && !*cancelled.borrow()
            && !failed
        {
            if verified.expires() <= now()? {
                stopped = "source_expired_new_signed_package_required";
                failed = true;
            } else if args.follow.follow && progress.attempts >= MAX_ATTEMPTS {
                stopped = "attempt_storage_bound";
                failed = true;
            } else {
                ensure!(
                    progress.attempts < MAX_ATTEMPTS,
                    "compute_workflow_attempt_storage_bound"
                );
                let output = directory.join(format!("attempt-{:04}", progress.attempts));
                rounds += 1;
                let ready_rows = if enrollment.scheduling == Scheduling::ReadyRowsV1 {
                    progress.ready_rows()?
                } else {
                    Vec::new()
                };
                let result = if !ready_rows.is_empty() {
                    ready_round(
                        batch::ReadyOptions {
                            source: source_args.clone(),
                            providers: providers.clone(),
                            output: output.clone(),
                            max_seconds: args.max_seconds,
                            task: package.task.clone(),
                            model_fingerprint: progress.model_fingerprint.clone(),
                            ready_rows,
                            pending: progress.ready_pending(),
                            executor_admission: None,
                        },
                        authorization.as_ref(),
                        progress.attempts > 0,
                        socket,
                        cancelled,
                    )
                    .await
                } else if progress.attempts == 0 {
                    initial_round(
                        &batch::Options::workflow(
                            source_args.clone(),
                            providers[..providers.len().min(package.rows)].to_vec(),
                            output.clone(),
                            args.max_seconds,
                            package.task.clone(),
                        )
                        .with_model_fingerprint(enrollment.model_fingerprint.clone()),
                        &output,
                        authorization.as_ref(),
                        |authorization, mut selected| {
                            selected.providers.truncate(package.rows);
                            batch::Options::workflow(
                                source_args.clone(),
                                selected.providers.clone(),
                                output.clone(),
                                args.max_seconds,
                                package.task.clone(),
                            )
                            .with_model_fingerprint(enrollment.model_fingerprint.clone())
                            .allow_single_provider(true)
                            .executor_admission(authorization.clone(), selected)
                        },
                        socket,
                        cancelled,
                    )
                    .await
                } else {
                    let mut retry = resume::Options::workflow(
                        source_args.clone(),
                        progress.pending(),
                        providers.clone(),
                        output,
                        args.max_seconds,
                    )
                    .prefer_other_provider(args.follow.follow)
                    .with_verified_stopped_receipts(progress.stopped_receipts());
                    if let Some(authorization) = authorization {
                        retry = retry.discover_replacements(authorization);
                    }
                    resume::report_with_activity(&retry, socket, cancelled).await
                };
                progress = load_progress(&directory, &source_args, &verified, enrollment)?;
                package_failure = round_failure(&result);
                let result_failed = match result {
                    Err(error)
                        if args.follow.follow
                            && !*cancelled.borrow()
                            && verified.expires() > now()?
                            && !follow::transient_preflight(&error) =>
                    {
                        return Err(error);
                    }
                    result => result.is_err(),
                };
                if result_failed || !progress.complete() {
                    stopped = if progress.attempts == 0 {
                        "initial_admission_failed_no_work_submitted"
                    } else {
                        "pending_handles_retained_no_busy_retry_loop"
                    };
                    failed = true;
                }
            }
        }
        if !progress.complete() {
            pending_expiry = Some(pending_expiry.map_or(verified.expires(), |expiry: u64| {
                expiry.min(verified.expires())
            }));
        }
        completed += usize::from(progress.complete());
        let outputs = progress.outputs()?;
        let answer_complete = progress.complete() && batch::output::all_complete(&outputs)?;
        let mut package_report = serde_json::json!({"package_index":index,"dataset_manifest_id":package.manifest_id,
            "complete":progress.complete(),"execution_complete":progress.complete(),"answer_complete":answer_complete,
            "attempts":progress.attempts,"outputs":outputs,
            "pending_handles":progress.pending(),"task":package.task});
        if enrollment.scheduling == Scheduling::ReadyRowsV1 {
            package_report["ready_rows"] = serde_json::json!(progress.ready_rows()?);
        }
        if let Some(code) = package_failure {
            package_report["failure_code"] = code.into();
        }
        packages.push(package_report);
    }
    let complete = completed == enrollment.packages.len();
    let answer_complete = complete
        && packages
            .iter()
            .all(|package| package["answer_complete"] == true);
    if complete {
        stopped = "complete";
    } else if *cancelled.borrow() {
        stopped = "interrupted_handles_retained";
    }
    let mut report = serde_json::json!({"version":1,"operation":"compute_workflow","execute":args.execute,
        "execution_complete":complete,"answer_complete":answer_complete,
        "scheduling":enrollment.scheduling,"complete":complete,"completed_packages":completed,"package_count":enrollment.packages.len(),
        "rounds_this_invocation":rounds,"maximum_seconds_per_worker":args.max_seconds,"stopped":stopped,
        "packages":packages,"receipt_scope":"locally_retained_authenticated_rpc_status",
        "private_data_supported":false,"automatic_source_discovery":false,"general_task_planning":false,
        "exactly_once_execution_guaranteed":false,"result_truthfulness_guaranteed":false,
        "pending_failure":failed});
    if args.follow.follow {
        report["maximum_rounds_per_window"] = serde_json::json!(args.max_batches);
        report["source_admission_expires_unix_seconds"] = serde_json::json!(pending_expiry);
    }
    Ok(report)
}

fn attempt_directories(directory: &Path) -> Result<Vec<PathBuf>> {
    let mut attempts = BTreeMap::new();
    for (count, entry) in fs::read_dir(directory)?.enumerate() {
        ensure!(count < MAX_ATTEMPTS + 3, "compute_workflow_directory_bound");
        let entry = entry?;
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow::anyhow!("compute_workflow_entry_name"))?;
        if matches!(name.as_str(), "dataset.json" | "manifest.bin") {
            continue;
        }
        let number = name
            .strip_prefix("attempt-")
            .context("compute_workflow_unrecognized_entry")?;
        let index: usize = number.parse()?;
        ensure!(
            index < MAX_ATTEMPTS && name == format!("attempt-{index:04}"),
            "compute_workflow_attempt_name"
        );
        super::super::private_directory(&entry.path())?;
        attempts.insert(index, entry.path());
    }
    ensure!(
        attempts.keys().copied().eq(0..attempts.len()),
        "compute_workflow_attempt_gap"
    );
    Ok(attempts.into_values().collect())
}

fn checked_handle(
    path: &Path,
    args: &Source,
    verified: &VerifiedPublicDataset,
    enrollment: &Enrollment,
    admitted: &BTreeSet<String>,
) -> Result<JobHandle> {
    let options = resume::Options::workflow(
        args.clone(),
        vec![path.to_owned()],
        vec![],
        path.to_owned(),
        600,
    );
    let handle = resume::load_handles(&options, verified)?.remove(0);
    let package = enrollment
        .packages
        .iter()
        .find(|package| package.manifest_id == hex::encode(verified.manifest_id()))
        .context("compute_workflow_handle_package")?;
    ensure!(
        (enrollment.provider_keys.contains(&handle.provider_key)
            || admitted.contains(&handle.provider_key))
            && enrollment
                .model_fingerprint
                .as_ref()
                .is_none_or(|expected| expected == &handle.binding.model_fingerprint)
            && handle.binding.task == package.task
            && handle.binding.job_id.len() == 32
            && handle
                .binding
                .job_id
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
            && handle.binding.job_id != "0".repeat(32)
            && handle.binding.expires_unix_seconds > enrollment.verified_at_unix_seconds,
        "compute_workflow_handle_identity"
    );
    Ok(handle)
}

#[allow(
    clippy::too_many_lines,
    reason = "Reconcile each immutable executor admission, original handle and receipt in attempt order"
)]
fn load_progress(
    directory: &Path,
    args: &Source,
    verified: &VerifiedPublicDataset,
    enrollment: &Enrollment,
) -> Result<Progress> {
    let attempts = attempt_directories(directory)?;
    let mut progress = Progress {
        parts: BTreeMap::new(),
        attempts: attempts.len(),
        rows: verified.row_count(),
        model_fingerprint: enrollment.model_fingerprint.clone(),
    };
    let peers = enrollment.provider_keys.len().min(progress.rows);
    let package = enrollment
        .packages
        .iter()
        .find(|package| package.manifest_id == hex::encode(verified.manifest_id()))
        .context("compute_workflow_handle_package")?;
    let authorization = replacement_authorization(enrollment, package, verified)?;
    let first_admission = attempts
        .first()
        .map(|attempt| executors::load(attempt, authorization.as_ref()))
        .transpose()?
        .flatten();
    let peers = first_admission.as_ref().map_or(peers, |admission| {
        admission.provider_keys.len().min(progress.rows)
    });
    let ready = enrollment.scheduling == Scheduling::ReadyRowsV1;
    let mut expected = vec![vec![]; if ready { progress.rows } else { peers }];
    for row in 0..progress.rows {
        expected[if ready { row } else { row % peers }].push(u16::try_from(row)?);
    }
    let mut identifiers = BTreeSet::new();
    let mut admitted = BTreeSet::new();
    for (number, attempt) in attempts.iter().enumerate() {
        if let Some(admission) = executors::load(attempt, authorization.as_ref())? {
            admitted.extend(admission.provider_keys);
        }
        let plan = if attempt.join("queue-plan.json").try_exists()? {
            ensure!(ready, "compute_workflow_unexpected_ready_queue");
            let plan = batch::verify_ready_plan(
                attempt,
                args,
                verified,
                &progress.ready_rows()?,
                &progress.ready_pending(),
            )?;
            ensure!(
                plan.task == package.task
                    && plan.planned_at_unix_seconds >= enrollment.verified_at_unix_seconds
                    && plan
                        .provider_keys
                        .iter()
                        .all(|key| enrollment.provider_keys.contains(key) || admitted.contains(key))
                    && progress
                        .model_fingerprint
                        .as_ref()
                        .is_none_or(|model| model == &plan.model_fingerprint),
                "compute_workflow_ready_plan_changed"
            );
            progress.model_fingerprint = Some(plan.model_fingerprint.clone());
            Some(plan)
        } else {
            // An interrupted mkdir/admission before the immutable plan cannot have submitted
            // anything. Handles in such an attempt are rejected below, never guessed away.
            None
        };
        let mut originals = BTreeSet::new();
        for index in 0..4 {
            let path = attempt.join(format!("original-{index}.json"));
            if !path.try_exists()? {
                continue;
            }
            let original = checked_handle(&path, args, verified, enrollment, &admitted)?;
            let part = progress
                .parts
                .get(&original.binding.row_indices)
                .context("compute_workflow_unknown_original")?;
            ensure!(
                same_handle(&part.handle, &original)?,
                "compute_workflow_original_changed"
            );
            ensure!(
                originals.insert(original.binding.row_indices),
                "compute_workflow_duplicate_original"
            );
        }
        // Old observations are recorded before new replacements; preserve a completed original.
        read_receipts(attempt, &mut progress, enrollment)?;
        let mut new_groups = BTreeSet::new();
        for index in 0..4 {
            let path = attempt.join(format!("job-{index}.json"));
            if !path.try_exists()? {
                continue;
            }
            let handle = checked_handle(&path, args, verified, enrollment, &admitted)?;
            let rows = handle.binding.row_indices.clone();
            ensure!(
                expected.contains(&rows)
                    && identifiers.insert(handle.binding.job_id.clone())
                    && new_groups.insert(rows.clone()),
                "compute_workflow_assignment_changed"
            );
            if let Some(plan) = &plan {
                ensure!(
                    rows == [u16::try_from(index)?]
                        && plan.ready_rows.contains(&u16::try_from(index)?)
                        && plan.provider_keys.contains(&handle.provider_key)
                        && !progress.parts.contains_key(&rows),
                    "compute_workflow_ready_assignment_changed"
                );
            } else if number > 0 || ready {
                ensure!(
                    originals.contains(&rows),
                    "compute_workflow_retry_without_original"
                );
            }
            if let Some(previous) = progress.parts.get(&rows) {
                ensure!(
                    !previous
                        .status
                        .as_ref()
                        .is_some_and(|status| status.state == rpc::JobState::Complete)
                        && previous.handle.binding.model_fingerprint
                            == handle.binding.model_fingerprint,
                    "compute_workflow_completed_or_changed_retry"
                );
            }
            if let Some(model) = &progress.model_fingerprint {
                ensure!(
                    model == &handle.binding.model_fingerprint,
                    "compute_workflow_mixed_models"
                );
            }
            progress.model_fingerprint = Some(handle.binding.model_fingerprint.clone());
            progress.parts.insert(
                rows,
                Part {
                    path,
                    handle,
                    status: None,
                },
            );
        }
        read_receipts(attempt, &mut progress, enrollment)?;
        ensure!(
            ready || progress.parts.len() == expected.len(),
            "compute_workflow_incomplete_initial_handles_preserved"
        );
    }
    Ok(progress)
}

fn same_handle(left: &JobHandle, right: &JobHandle) -> Result<bool> {
    Ok(serde_json::to_vec(left)? == serde_json::to_vec(right)?)
}

fn read_receipts(attempt: &Path, progress: &mut Progress, enrollment: &Enrollment) -> Result<()> {
    for part in progress.parts.values_mut() {
        let path = attempt.join(format!("receipt-{}.json", part.handle.binding.job_id));
        if !path.try_exists()? {
            continue;
        }
        let receipt: Receipt = serde_json::from_slice(&read_file(&path, MAX_RECEIPT_BYTES)?)?;
        ensure!(
            receipt.version == 1
                && same_handle(&receipt.handle, &part.handle)?
                && receipt.verified_at_unix_seconds >= enrollment.verified_at_unix_seconds
                && receipt.verified_at_unix_seconds <= now()?,
            "compute_workflow_receipt_binding"
        );
        let status = job(rpc::Outcome::Job(receipt.status), &part.handle)?;
        if let Some(previous) = &part.status {
            ensure!(
                previous.state != rpc::JobState::Complete || previous == &status,
                "compute_workflow_terminal_receipt_changed"
            );
        }
        part.status = Some(status);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::PermissionsExt;
    use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity, publish};

    use super::*;

    #[test]
    fn failed_round_diagnostics_never_persist_upstream_text() {
        assert_eq!(
            failure_code(&anyhow::anyhow!("compute_peer_job_rejected")),
            "job_rejected"
        );
        assert_eq!(
            failure_code(&anyhow::anyhow!(
                "compute_distribute_capability_probe_timeout"
            )),
            "capability_timeout"
        );
        assert_eq!(
            failure_code(&anyhow::anyhow!("private prompt or /private/path")),
            "execution_or_verification_failed"
        );
        assert_eq!(
            failure_code(&anyhow::anyhow!("compute_peer_job_rejected: injected text")),
            "execution_or_verification_failed"
        );
        // An unconfirmed Submit is an Ok(partial report), not a terminal RPC error.
        assert_eq!(
            round_failure(&Ok(serde_json::json!({"complete":false,"jobs":[{
                "state":"unconfirmed","error":"private upstream exception"
            }]}))),
            Some("jobs_unconfirmed")
        );
        assert_eq!(
            round_failure(&Ok(serde_json::json!({"complete":false,"jobs":[{
                "state":"running","error":"private upstream exception"
            }]}))),
            Some("jobs_incomplete")
        );
        assert_eq!(
            round_failure(&Ok(serde_json::json!({"complete":true}))),
            None
        );
    }

    struct Fixture {
        root: tempfile::TempDir,
        options: Options,
        enrollment: Enrollment,
    }

    fn fixture(count: usize) -> Fixture {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let publisher = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
        let peer = ed25519_dalek::SigningKey::from_bytes(&[32; 32]);
        let at = now().unwrap();
        let mut cache = ChunkStore::create(
            &root.path().join("cache"),
            CacheLimits {
                max_bytes: 1024 * 1024,
                max_entries: 16,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let mut packages = Vec::new();
        for index in 0..count {
            let json = serde_json::json!({"version":1,"visibility":"public","license":"GPL-3.0-only",
                "source_revision":"a".repeat(40),"train":[],
                "heldout":[{"question":"What is this?","context":"Public coordinator fixture.","answer":"A protocol test."}],
                "inference":[{"question":format!("Package {index}, first?"),"context":"First public input."},
                    {"question":"Second?","context":"Second public input."}]}).to_string();
            let signed = publish(
                &mut json.as_bytes(),
                Publication {
                    metadata: Metadata {
                        name: format!("workflow-fixture-{index}"),
                        revision: 1,
                        content_type: volparossa_content::provider::compute::dataset::CONTENT_TYPE
                            .into(),
                    },
                    length: json.len() as u64,
                    validity: Validity {
                        created: at,
                        expires: at + 1200,
                    },
                },
                &publisher,
                &mut cache,
            )
            .unwrap();
            let dataset = root.path().join(format!("input-{index}.json"));
            let manifest = root.path().join(format!("input-{index}.bin"));
            save_bytes(&dataset, json.as_bytes()).unwrap();
            save_bytes(&manifest, &signed.encode()).unwrap();
            packages.push(
                serde_json::json!({"dataset":dataset,"dataset_manifest":manifest,
                "publisher_key":hex::encode(publisher.verifying_key().as_bytes())}),
            );
        }
        let plan = root.path().join("plan.json");
        save_new(&plan, &serde_json::json!({"version":1,"packages":packages})).unwrap();
        let options = Options {
            plan: Some(plan),
            directory: root.path().join("workflow"),
            resume: false,
            batch_barrier: true,
            provider_key: vec![publisher.verifying_key(), peer.verifying_key()],
            discovery: discovery::Options::default(),
            max_batches: 1,
            max_seconds: 600,
            execute: true,
            follow: follow::Options::default(),
            expected_task: None,
            expected_model_fingerprint: None,
            expected_replace_peers: false,
        };
        let (enrollment, sources) = prepare(&options).unwrap();
        persist_enrollment(&options.directory, &enrollment, &sources).unwrap();
        Fixture {
            root,
            options,
            enrollment,
        }
    }

    fn signed_profile(fixture: &Fixture, bytes: &str, mime: &str) -> Vec<u8> {
        let mut cache = ChunkStore::open(
            &fixture.root.path().join("cache"),
            CacheLimits {
                max_bytes: 1024 * 1024,
                max_entries: 16,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        publish(
            &mut bytes.as_bytes(),
            Publication {
                metadata: Metadata {
                    name: "singleton-fixture".into(),
                    revision: 1,
                    content_type: mime.into(),
                },
                length: bytes.len() as u64,
                validity: Validity {
                    created: fixture.enrollment.verified_at_unix_seconds,
                    expires: fixture.enrollment.verified_at_unix_seconds + 1200,
                },
            },
            &ed25519_dalek::SigningKey::from_bytes(&[31; 32]),
            &mut cache,
        )
        .unwrap()
        .encode()
    }

    #[test]
    fn fresh_singleton_document_enrolls_restores_and_assigns_one_peer_but_v1_does_not() {
        use volparossa_content::provider::compute::dataset::{CONTENT_TYPE, DOCUMENT_CONTENT_TYPE};

        let mut fixture = fixture(1);
        let dataset_path = fixture.root.path().join("input-0.json");
        let manifest_path = fixture.root.path().join("input-0.bin");
        let mut legacy: serde_json::Value =
            serde_json::from_slice(&read_file(&dataset_path, MAX_PLAN_BYTES).unwrap()).unwrap();
        legacy["inference"].as_array_mut().unwrap().truncate(1);
        let legacy = legacy.to_string();
        task::write_bytes(&dataset_path, legacy.as_bytes(), true).unwrap();
        task::write_bytes(
            &manifest_path,
            &signed_profile(&fixture, &legacy, CONTENT_TYPE),
            true,
        )
        .unwrap();
        assert!(prepare(&fixture.options).is_err());
        let args = Source {
            dataset: dataset_path.clone(),
            dataset_manifest: manifest_path.clone(),
            publisher_key: fixture.options.provider_key[0],
        };
        let (_, verified) = source(&args).unwrap();
        assert!(!verified.is_document());
        assert!(batch::assignments_for(&verified, &fixture.options.provider_key[..1]).is_err());

        let context = "One remaining public document fragment.";
        let original = signed_profile(&fixture, context, "text/plain");
        let document = serde_json::json!({"version":2,"visibility":"public","license":"CC0-1.0",
            "source_manifest_hex":hex::encode(original),"inference":[{
                "question":"What does this public text say?","context":context,"start":0,"end":context.len()}]}).to_string();
        task::write_bytes(&dataset_path, document.as_bytes(), true).unwrap();
        task::write_bytes(
            &manifest_path,
            &signed_profile(&fixture, &document, DOCUMENT_CONTENT_TYPE),
            true,
        )
        .unwrap();
        fixture.options.directory = fixture.root.path().join("document-workflow");
        let (enrollment, sources) = prepare(&fixture.options).unwrap();
        assert_eq!(enrollment.provider_keys.len(), 2); // Overall enrollment still pins two independent peers.
        assert_eq!(enrollment.packages[0].rows, 1);
        persist_enrollment(&fixture.options.directory, &enrollment, &sources).unwrap();
        let (_, verified) = stored_source(
            &fixture.options.directory.join("package-0000"),
            &enrollment.packages[0],
            enrollment.verified_at_unix_seconds,
        )
        .unwrap();
        assert!(verified.is_document());
        assert_eq!(
            batch::assignments_for(&verified, &fixture.options.provider_key[..1]).unwrap(),
            vec![vec![0]]
        );
        assert!(batch::assignments_for(&verified, &fixture.options.provider_key).is_err());
        assert!(
            !fixture
                .options
                .directory
                .join("package-0000/attempt-0000")
                .exists()
        );
    }

    fn handles(
        fixture: &Fixture,
        package: usize,
    ) -> (Source, VerifiedPublicDataset, Vec<JobHandle>) {
        let directory = fixture
            .options
            .directory
            .join(format!("package-{package:04}"));
        let (args, source) = stored_source(
            &directory,
            &fixture.enrollment.packages[package],
            fixture.enrollment.verified_at_unix_seconds,
        )
        .unwrap();
        // Synthetic metadata tests local persistence/validation only, never ML execution.
        let model = rpc::ModelIdentity {
            model_id: volparossa_content::agent_artifact::MODEL_ID.into(),
            model_revision: volparossa_content::agent_artifact::MODEL_REVISION.into(),
            base_weights: rpc::FileIdentity {
                bytes: 269_060_552,
                sha256: hex::encode(volparossa_content::agent_artifact::BASE_MODEL_SHA256),
            },
            adapter_files: None,
        };
        let caps = rpc::Capabilities {
            model_fingerprint: sha(&serde_json::to_vec(&model).unwrap()),
            model,
            accepting_work: true,
            public_inference_only: true,
            runtime_slots: 1,
            max_threads: 2,
            max_job_seconds: 600,
            max_dataset_bytes: 1024 * 1024,
            max_rows: 4,
            task_derivation_v1: true,
            document_inference_v2: false,
            derived_inference_v3: false,
        };
        let handles = (0..2)
            .map(|index| JobHandle {
                version: 1,
                provider_key: fixture.enrollment.provider_keys[index].clone(),
                binding: binding(
                    &source,
                    vec![u16::try_from(index).unwrap()],
                    &derive(
                        &source,
                        &[u16::try_from(index).unwrap()],
                        fixture.enrollment.packages[package].task.as_ref(),
                    )
                    .unwrap(),
                    &caps,
                    600,
                    fixture.enrollment.packages[package].task.clone(),
                )
                .unwrap(),
                capabilities: caps.clone(),
            })
            .collect();
        (args, source, handles)
    }

    fn synthetic_status(handle: &JobHandle) -> rpc::JobStatus {
        let report = serde_json::json!({"mode":"infer","status":"ok","updates_completed":0,
            "dataset":{"sha256":handle.binding.dataset_sha256,"visibility":"public","inference_examples":1},
            "model":{"id":handle.capabilities.model.model_id,"revision":handle.capabilities.model.model_revision,
                "files":{"model.safetensors":handle.capabilities.model.base_weights}},
            "supervisor":{"child_reaped":true,"network_access":false},
            "outputs":[{"sample_index":0,"text":"Synthetic parser fixture; not a model execution proof."}]}).to_string();
        rpc::JobStatus {
            binding: handle.binding.clone(),
            state: rpc::JobState::Complete,
            cancellation_requested: false,
            report_sha256: Some(sha(report.as_bytes())),
            report_json: Some(report),
            error: None,
        }
    }

    #[tokio::test]
    async fn token_limited_terminal_receipts_are_not_resubmitted_even_with_follow() {
        let mut fixture = fixture(1);
        let (_, _, handles) = handles(&fixture, 0);
        let directory = fixture.options.directory.join("package-0000");
        let attempt = directory.join("attempt-0000");
        fs::DirBuilder::new().mode(0o700).create(&attempt).unwrap();
        let mut originals = Vec::new();
        for (index, handle) in handles.iter().enumerate() {
            save_new(&attempt.join(format!("job-{index}.json")), handle).unwrap();
            let mut status = synthetic_status(handle);
            let mut report: serde_json::Value =
                serde_json::from_str(status.report_json.as_deref().unwrap()).unwrap();
            report["outputs"][0]["generated_tokens"] = 64.into();
            report["outputs"][0]["text_truncated"] = false.into();
            report["outputs"][0]["generation"] =
                serde_json::json!({"version":1,"stop_reason":"token_limit","max_new_tokens":64});
            let raw = report.to_string();
            status.report_sha256 = Some(sha(raw.as_bytes()));
            status.report_json = Some(raw);
            batch::save_status(&attempt, handle, &status).unwrap();
            let path = attempt.join(format!("receipt-{}.json", handle.binding.job_id));
            originals.push((path.clone(), fs::read(path).unwrap()));
        }
        fixture.options.resume = true;
        fixture.options.follow.follow = true;
        let report = report(&fixture.options, &fixture.root.path().join("no-agent.sock"))
            .await
            .unwrap();
        assert_eq!(report["complete"], true);
        assert_eq!(report["execution_complete"], true);
        assert_eq!(report["answer_complete"], false);
        assert_eq!(report["rounds_this_invocation"], 0);
        assert_eq!(
            report["packages"][0]["pending_handles"],
            serde_json::json!([])
        );
        assert_eq!(
            report["packages"][0]["outputs"][0]["generation"]["stop_reason"],
            "token_limit"
        );
        assert!(!directory.join("attempt-0001").exists());
        for (path, original) in originals {
            assert_eq!(fs::read(path).unwrap(), original);
        }
    }

    fn ready_plan(
        fixture: &Fixture,
        source: &VerifiedPublicDataset,
        model: &str,
        rows: Vec<u16>,
        pending: &[JobHandle],
    ) -> batch::ReadyPlan {
        batch::ReadyPlan {
            version: 1,
            scheduling: "ready_rows_v1".into(),
            publisher_key: fixture.enrollment.packages[0].publisher_key.clone(),
            dataset_manifest_id: hex::encode(source.manifest_id()),
            dataset_sha256: fixture.enrollment.packages[0].dataset_sha256.clone(),
            source_expires_unix_seconds: source.expires(),
            model_fingerprint: model.into(),
            task: fixture.enrollment.packages[0].task.clone(),
            provider_keys: fixture.enrollment.provider_keys.clone(),
            ready_rows: rows,
            pending_job_ids: pending
                .iter()
                .map(|handle| handle.binding.job_id.clone())
                .collect(),
            planned_at_unix_seconds: now().unwrap(),
        }
    }

    #[test]
    fn new_enrollments_default_to_ready_rows_without_changing_legacy_histories() {
        let mut fixture = fixture(1);
        let legacy = serde_json::to_value(&fixture.enrollment).unwrap();
        assert!(legacy.get("scheduling").is_none());
        let restored: Enrollment = serde_json::from_value(legacy).unwrap();
        assert_eq!(restored.scheduling, Scheduling::BatchBarrierV1);
        fixture.options.batch_barrier = false;
        let (selected, _) = prepare(&fixture.options).unwrap();
        assert_eq!(selected.scheduling, Scheduling::ReadyRowsV1);
        assert_eq!(
            serde_json::to_value(selected).unwrap()["scheduling"],
            "ready_rows_v1"
        );
    }

    #[test]
    fn partial_ready_attempt_retains_original_lease_and_dispatches_only_the_unsent_row() {
        let mut fixture = fixture(1);
        fixture.enrollment.scheduling = Scheduling::ReadyRowsV1;
        let (args, source, original) = handles(&fixture, 0);
        let directory = fixture.options.directory.join("package-0000");
        let first = directory.join("attempt-0000");
        fs::DirBuilder::new().mode(0o700).create(&first).unwrap();
        save_new(
            &first.join("queue-plan.json"),
            &ready_plan(
                &fixture,
                &source,
                &original[0].binding.model_fingerprint,
                vec![0, 1],
                &[],
            ),
        )
        .unwrap();
        // A crash before the first handle leaves both rows ready, with the model still pinned.
        let plan_only = load_progress(&directory, &args, &source, &fixture.enrollment).unwrap();
        assert_eq!(plan_only.ready_rows().unwrap(), vec![0, 1]);
        assert_eq!(
            plan_only.model_fingerprint.as_deref(),
            Some(original[0].binding.model_fingerprint.as_str())
        );
        save_new(&first.join("job-0.json"), &original[0]).unwrap();
        let partial = load_progress(&directory, &args, &source, &fixture.enrollment).unwrap();
        assert_eq!(partial.ready_rows().unwrap(), vec![1]);
        assert_eq!(partial.ready_pending().len(), 1);
        assert!(partial.ready_pending()[0].verified_status.is_none());
        let next = directory.join("attempt-0001");
        fs::DirBuilder::new().mode(0o700).create(&next).unwrap();
        save_new(&next.join("original-0.json"), &original[0]).unwrap();
        save_new(
            &next.join("queue-plan.json"),
            &ready_plan(
                &fixture,
                &source,
                &original[0].binding.model_fingerprint,
                vec![1],
                &original[..1],
            ),
        )
        .unwrap();
        save_new(&next.join("job-1.json"), &original[1]).unwrap();
        batch::save_status(&next, &original[0], &synthetic_status(&original[0])).unwrap();
        batch::save_status(&next, &original[1], &synthetic_status(&original[1])).unwrap();
        let complete = load_progress(&directory, &args, &source, &fixture.enrollment).unwrap();
        assert!(complete.complete());
        assert!(complete.ready_rows().unwrap().is_empty());
        assert_eq!(complete.outputs().unwrap().len(), 2);
        assert_eq!(complete.parts[&vec![0]].path, first.join("job-0.json"));
        assert_eq!(complete.parts[&vec![1]].path, next.join("job-1.json"));
    }

    #[test]
    fn ready_plan_rejects_reclassification_source_model_or_provider_changes() {
        for mutation in 0..5 {
            let mut fixture = fixture(1);
            fixture.enrollment.scheduling = Scheduling::ReadyRowsV1;
            let (args, source, original) = handles(&fixture, 0);
            let directory = fixture.options.directory.join("package-0000");
            let first = directory.join("attempt-0000");
            fs::DirBuilder::new().mode(0o700).create(&first).unwrap();
            let mut plan = ready_plan(
                &fixture,
                &source,
                &original[0].binding.model_fingerprint,
                vec![0, 1],
                &[],
            );
            save_new(&first.join("queue-plan.json"), &plan).unwrap();
            save_new(&first.join("job-0.json"), &original[0]).unwrap();
            let next = directory.join("attempt-0001");
            fs::DirBuilder::new().mode(0o700).create(&next).unwrap();
            save_new(&next.join("original-0.json"), &original[0]).unwrap();
            plan.ready_rows = vec![1];
            plan.pending_job_ids = vec![original[0].binding.job_id.clone()];
            match mutation {
                0 => plan.ready_rows = vec![0, 1],
                1 => plan.dataset_sha256 = "bb".repeat(32),
                2 => plan.model_fingerprint = "cc".repeat(32),
                3 => {
                    plan.provider_keys = vec![hex::encode(
                        ed25519_dalek::SigningKey::from_bytes(&[39; 32])
                            .verifying_key()
                            .as_bytes(),
                    )];
                }
                _ => plan.source_expires_unix_seconds += 1,
            }
            save_new(&next.join("queue-plan.json"), &plan).unwrap();
            assert!(
                load_progress(&directory, &args, &source, &fixture.enrollment).is_err(),
                "mutation {mutation}"
            );
        }
    }

    #[test]
    fn ready_first_submission_requires_plan_and_completed_rows_cannot_be_queued_again() {
        let mut fixture = fixture(1);
        fixture.enrollment.scheduling = Scheduling::ReadyRowsV1;
        let (args, source, original) = handles(&fixture, 0);
        let directory = fixture.options.directory.join("package-0000");
        let first = directory.join("attempt-0000");
        fs::DirBuilder::new().mode(0o700).create(&first).unwrap();
        assert!(load_progress(&directory, &args, &source, &fixture.enrollment).is_ok());
        save_new(&first.join("job-0.json"), &original[0]).unwrap();
        assert!(load_progress(&directory, &args, &source, &fixture.enrollment).is_err());
        save_new(
            &first.join("queue-plan.json"),
            &ready_plan(
                &fixture,
                &source,
                &original[0].binding.model_fingerprint,
                vec![0, 1],
                &[],
            ),
        )
        .unwrap();
        batch::save_status(&first, &original[0], &synthetic_status(&original[0])).unwrap();
        let next = directory.join("attempt-0001");
        fs::DirBuilder::new().mode(0o700).create(&next).unwrap();
        save_new(
            &next.join("queue-plan.json"),
            &ready_plan(
                &fixture,
                &source,
                &original[0].binding.model_fingerprint,
                vec![1],
                &[],
            ),
        )
        .unwrap();
        // Correctly bound model/source does not allow relabeling completed row 0 as new work.
        let mut duplicate = original[0].clone();
        duplicate.binding.job_id = "ab".repeat(16);
        save_new(&next.join("job-0.json"), &duplicate).unwrap();
        assert!(load_progress(&directory, &args, &source, &fixture.enrollment).is_err());
    }

    #[tokio::test]
    async fn shared_package_owner_reopens_completed_originals_without_a_broker_or_new_attempt() {
        let mut fixture = fixture(2);
        fixture.enrollment.scheduling = Scheduling::ReadyRowsV1;
        for package in 0..2 {
            let (_, source, original) = handles(&fixture, package);
            let directory = fixture
                .options
                .directory
                .join(format!("package-{package:04}/attempt-0000"));
            fs::DirBuilder::new()
                .mode(0o700)
                .create(&directory)
                .unwrap();
            let mut plan = ready_plan(
                &fixture,
                &source,
                &original[0].binding.model_fingerprint,
                vec![0, 1],
                &[],
            );
            plan.dataset_sha256
                .clone_from(&fixture.enrollment.packages[package].dataset_sha256);
            save_new(&directory.join("queue-plan.json"), &plan).unwrap();
            for (row, handle) in original.iter().enumerate() {
                save_new(&directory.join(format!("job-{row}.json")), handle).unwrap();
                batch::save_status(&directory, handle, &synthetic_status(handle)).unwrap();
            }
        }
        let (_owner, cancelled) = tokio::sync::watch::channel(false);
        let report = advance(
            &fixture.options,
            &fixture.root.path().join("missing-agent.sock"),
            &fixture.enrollment,
            &cancelled,
        )
        .await
        .unwrap();
        assert_eq!(report["complete"], true);
        assert_eq!(report["rounds_this_invocation"], 0);
        assert_eq!(report["completed_packages"], 2);
        assert_eq!(
            report["package_scheduling"],
            "shared_provider_round_robin_v1"
        );
        for package in 0..2 {
            assert_eq!(
                report["packages"][package]["outputs"]
                    .as_array()
                    .unwrap()
                    .len(),
                2
            );
            assert!(
                !fixture
                    .options
                    .directory
                    .join(format!("package-{package:04}/attempt-0001"))
                    .exists()
            );
        }
    }

    #[tokio::test]
    async fn cancelled_shared_window_never_admits_or_forgets_unsent_packages() {
        let mut fixture = fixture(2);
        fixture.enrollment.scheduling = Scheduling::ReadyRowsV1;
        let (_owner, cancelled) = tokio::sync::watch::channel(true);
        let report = advance(
            &fixture.options,
            &fixture.root.path().join("missing-agent.sock"),
            &fixture.enrollment,
            &cancelled,
        )
        .await
        .unwrap();
        assert_eq!(report["complete"], false);
        assert_eq!(report["rounds_this_invocation"], 0);
        assert_eq!(report["stopped"], "interrupted_handles_retained");
        for package in 0..2 {
            assert_eq!(
                report["packages"][package]["ready_rows"],
                serde_json::json!([0, 1])
            );
            assert!(
                !fixture
                    .options
                    .directory
                    .join(format!("package-{package:04}/attempt-0000"))
                    .exists()
            );
        }
    }

    #[test]
    fn enrolled_task_survives_handles_and_cannot_be_relabelled_or_downgraded() {
        let mut fixture = fixture(1);
        fixture.enrollment.packages[0].task = Some(rpc::PublicTask::SummarizeContextsV1 {});
        let (args, source, handles) = handles(&fixture, 0);
        let path = fixture.root.path().join("task-handle.json");
        save_new(&path, &handles[0]).unwrap();
        let checked =
            checked_handle(&path, &args, &source, &fixture.enrollment, &BTreeSet::new()).unwrap();
        assert_eq!(checked.binding.task, fixture.enrollment.packages[0].task);
        let mut altered = handles[0].clone();
        altered.binding.task = Some(rpc::PublicTask::AnswerPublicQuestionV1 {
            question: "Which fact is documented?".into(),
        });
        altered.binding.dataset_sha256 = sha(derive(
            &source,
            &altered.binding.row_indices,
            altered.binding.task.as_ref(),
        )
        .unwrap()
        .as_bytes());
        let other = fixture.root.path().join("other-task.json");
        save_new(&other, &altered).unwrap();
        assert!(
            checked_handle(
                &other,
                &args,
                &source,
                &fixture.enrollment,
                &BTreeSet::new()
            )
            .is_err()
        );
        let mut unsupported = checked.capabilities;
        unsupported.task_derivation_v1 = false;
        assert!(
            binding(
                &source,
                vec![0],
                &source.derive(&[0]).unwrap(),
                &unsupported,
                600,
                Some(rpc::PublicTask::SummarizeContextsV1 {})
            )
            .is_err()
        );
    }

    #[test]
    fn enrollment_copies_multiple_signed_packages_and_rejects_changes() {
        let fixture = fixture(3);
        assert_eq!(
            fixture
                .enrollment
                .packages
                .iter()
                .map(|package| package.rows)
                .sum::<usize>(),
            6
        );
        let record: Enrollment = serde_json::from_slice(
            &read_file(
                &fixture.options.directory.join("workflow.json"),
                MAX_PLAN_BYTES,
            )
            .unwrap(),
        )
        .unwrap();
        for (index, package) in record.packages.iter().enumerate() {
            fs::remove_file(fixture.root.path().join(format!("input-{index}.json"))).unwrap();
            fs::remove_file(fixture.root.path().join(format!("input-{index}.bin"))).unwrap();
            let directory = fixture
                .options
                .directory
                .join(format!("package-{index:04}"));
            let (args, verified) =
                stored_source(&directory, package, record.verified_at_unix_seconds).unwrap();
            assert_eq!(verified.row_count(), 2);
            assert!(
                verify_source(
                    &read_file(&args.dataset_manifest, 64 * 1024).unwrap(),
                    &args.publisher_key,
                    std::str::from_utf8(&read_file(&args.dataset, rpc::MAX_DATASET_BYTES).unwrap())
                        .unwrap(),
                    verified.expires() + 1
                )
                .is_err()
            );
            let mut altered: Package =
                serde_json::from_value(serde_json::to_value(package).unwrap()).unwrap();
            altered.dataset_sha256 = "b".repeat(64);
            assert!(stored_source(&directory, &altered, record.verified_at_unix_seconds).is_err());
        }
        let first = lock_directory(&fixture.options.directory).unwrap();
        assert!(lock_directory(&fixture.options.directory).is_err());
        drop(first);
        assert!(lock_directory(&fixture.options.directory).is_ok());
        assert!(persist_enrollment(&fixture.options.directory, &record, &[]).is_err());
    }

    #[tokio::test]
    async fn vanished_broker_does_not_erase_checked_terminal_failure() {
        let fixture = fixture(1);
        let (args, source, original) = handles(&fixture, 0);
        let directory = fixture.options.directory.join("package-0000");
        let first = directory.join("attempt-0000");
        fs::DirBuilder::new().mode(0o700).create(&first).unwrap();
        for (index, handle) in original.iter().enumerate() {
            save_new(&first.join(format!("job-{index}.json")), handle).unwrap();
        }
        let failed = rpc::JobStatus {
            binding: original[0].binding.clone(),
            state: rpc::JobState::Failed,
            cancellation_requested: false,
            report_json: None,
            report_sha256: None,
            error: Some(rpc::ErrorCode::WorkerFailed),
        };
        batch::save_status(&first, &original[0], &failed).unwrap();
        batch::save_status(&first, &original[1], &synthetic_status(&original[1])).unwrap();
        let progress = load_progress(&directory, &args, &source, &fixture.enrollment).unwrap();
        assert_eq!(progress.stopped_receipts().len(), 1);
        assert_eq!(progress.pending().len(), 1);
        let output = fixture.root.path().join("reconciled");
        let options = resume::Options::workflow(
            args.clone(),
            progress.pending(),
            vec![],
            output.clone(),
            600,
        )
        .with_verified_stopped_receipts(progress.stopped_receipts());
        let (_sender, activity) = tokio::sync::watch::channel(false);
        let socket = fixture.root.path().join("no-agent.sock");
        let result = resume::report_with_activity(&options, &socket, &activity)
            .await
            .unwrap();
        assert_eq!(result["complete"], false); // No replacement is available in this protocol fixture.
        assert_eq!(result["jobs"][0]["state"], "stopped");
        let retained: serde_json::Value = serde_json::from_slice(
            &read_file(&output.join("observation-0.json"), MAX_RECEIPT_BYTES).unwrap(),
        )
        .unwrap();
        assert_eq!(retained["status"], serde_json::to_value(&failed).unwrap());
        assert_eq!(
            retained["handle"],
            serde_json::to_value(&original[0]).unwrap()
        );
        assert!(original[0].binding.expires_unix_seconds > now().unwrap());
        // A mere cancellation request/running status or another executor cannot grant this shortcut.
        for index in 0..2 {
            let mut receipts = progress.stopped_receipts();
            if index == 0 {
                receipts[0].1.state = rpc::JobState::Running;
                receipts[0].1.cancellation_requested = true;
            } else {
                receipts[0]
                    .0
                    .provider_key
                    .clone_from(&original[1].provider_key);
            }
            let rejected = resume::Options::workflow(
                args.clone(),
                progress.pending(),
                vec![],
                fixture.root.path().join(format!("rejected-{index}")),
                600,
            )
            .with_verified_stopped_receipts(receipts);
            assert!(
                resume::report_with_activity(&rejected, &socket, &activity)
                    .await
                    .is_err()
            );
        }
    }

    #[tokio::test]
    async fn admitted_new_peer_preserves_completed_original_and_reopens_without_network() {
        let mut fixture = fixture(1);
        let (args, source, original) = handles(&fixture, 0);
        fixture.enrollment.replace_peers = true;
        fixture.enrollment.model_fingerprint = Some(original[0].binding.model_fingerprint.clone());
        fs::write(
            fixture.options.directory.join("workflow.json"),
            serde_json::to_vec(&fixture.enrollment).unwrap(),
        )
        .unwrap();
        let directory = fixture.options.directory.join("package-0000");
        let first = directory.join("attempt-0000");
        fs::DirBuilder::new().mode(0o700).create(&first).unwrap();
        for (index, handle) in original.iter().enumerate() {
            save_new(&first.join(format!("job-{index}.json")), handle).unwrap();
        }
        batch::save_status(&first, &original[0], &synthetic_status(&original[0])).unwrap();
        let completed_file = first.join(format!("receipt-{}.json", original[0].binding.job_id));
        let completed_bytes = fs::read(&completed_file).unwrap();
        let second = directory.join("attempt-0001");
        fs::DirBuilder::new().mode(0o700).create(&second).unwrap();
        save_new(&second.join("original-0.json"), &original[1]).unwrap();
        let mut replacement = original[1].clone();
        let provider = ed25519_dalek::SigningKey::from_bytes(&[99; 32]).verifying_key();
        replacement.provider_key = hex::encode(provider.as_bytes());
        replacement.binding.job_id = "a9".repeat(16);
        save_new(&second.join("job-0.json"), &replacement).unwrap();
        assert!(load_progress(&directory, &args, &source, &fixture.enrollment).is_err());
        let authorization = replacement_authorization(
            &fixture.enrollment,
            &fixture.enrollment.packages[0],
            &source,
        )
        .unwrap()
        .unwrap();
        executors::admit(
            &second,
            &authorization,
            &discovery::Selected {
                providers: vec![provider],
                model_fingerprint: replacement.binding.model_fingerprint.clone(),
            },
        )
        .unwrap();
        batch::save_status(&second, &replacement, &synthetic_status(&replacement)).unwrap();
        assert!(
            load_progress(&directory, &args, &source, &fixture.enrollment)
                .unwrap()
                .complete()
        );
        fixture.options.resume = true;
        let result = report(&fixture.options, &fixture.root.path().join("no-agent.sock"))
            .await
            .unwrap();
        assert_eq!(result["complete"], true);
        assert_eq!(result["rounds_this_invocation"], 0);
        assert_eq!(fs::read(completed_file).unwrap(), completed_bytes);
        fixture.enrollment.replace_peers = false;
        assert!(load_progress(&directory, &args, &source, &fixture.enrollment).is_err());
    }

    #[tokio::test]
    async fn full_status_reuse_not_aggregate_bool_and_no_rpc_for_completed_packages() {
        let mut fixture = fixture(3);
        for package in 0..3 {
            let directory = fixture
                .options
                .directory
                .join(format!("package-{package:04}"));
            let (args, source, handles) = handles(&fixture, package);
            let attempt = directory.join("attempt-0000");
            fs::DirBuilder::new().mode(0o700).create(&attempt).unwrap();
            for (index, handle) in handles.iter().enumerate() {
                save_new(&attempt.join(format!("job-{index}.json")), handle).unwrap();
            }
            save_new(
                &attempt.join("result.json"),
                &serde_json::json!({"complete":true,"outputs":["forged aggregate"]}),
            )
            .unwrap();
            assert!(
                !load_progress(&directory, &args, &source, &fixture.enrollment)
                    .unwrap()
                    .complete()
            );
            for handle in &handles {
                batch::save_status(&attempt, handle, &synthetic_status(handle)).unwrap();
            }
            let retained = load_progress(&directory, &args, &source, &fixture.enrollment).unwrap();
            assert!(retained.complete());
            assert!(retained.pending().is_empty());
            assert_eq!(retained.outputs().unwrap().len(), 2);
            let ordinary = retained.outputs().unwrap();
            let detailed = retained.output_rows(true).unwrap();
            for (plain, full) in ordinary.iter().zip(&detailed) {
                assert!(plain.get("model_fingerprint").is_none());
                assert!(full["model_fingerprint"].is_string());
                assert_eq!(plain["text"], full["text"]);
                assert_eq!(plain["report_sha256"], full["report_sha256"]);
                assert_eq!(full["output_index"], 0);
            }
        }
        fixture.options.resume = true;
        fixture.options.plan = None;
        fixture.options.provider_key.clear();
        // This proves reuse of locally validated codec fixtures without contacting this
        // nonexistent socket. No worker/model has run, and this is not remote ML evidence.
        run(&fixture.options, &fixture.root.path().join("no-agent.sock"))
            .await
            .unwrap();
        fixture.options.follow.follow = true;
        let followed = report(&fixture.options, &fixture.root.path().join("no-agent.sock"))
            .await
            .unwrap();
        assert_eq!(followed["complete"], true);
        assert_eq!(followed["follow_windows"], 1);
        assert_eq!(followed["rounds_this_invocation"], 0);
        assert_eq!(followed["follow_waits"], 0);
        for package in 0..3 {
            assert!(
                !fixture
                    .options
                    .directory
                    .join(format!("package-{package:04}/attempt-0001"))
                    .exists()
            );
        }
    }

    #[test]
    fn restarted_frontier_keeps_finished_rows_and_exact_unfinished_retry() {
        let fixture = fixture(1);
        let directory = fixture.options.directory.join("package-0000");
        let (args, source, handles) = handles(&fixture, 0);
        let first = directory.join("attempt-0000");
        fs::DirBuilder::new().mode(0o700).create(&first).unwrap();
        for (index, handle) in handles.iter().enumerate() {
            save_new(&first.join(format!("job-{index}.json")), handle).unwrap();
        }
        batch::save_status(&first, &handles[0], &synthetic_status(&handles[0])).unwrap();
        let second = directory.join("attempt-0001");
        fs::DirBuilder::new().mode(0o700).create(&second).unwrap();
        save_new(&second.join("original-0.json"), &handles[1]).unwrap();
        let mut replacement = handles[1].clone();
        replacement.binding.job_id = nonce().unwrap();
        let replacement_path = second.join("job-0.json");
        save_new(&replacement_path, &replacement).unwrap();
        let retained = load_progress(&directory, &args, &source, &fixture.enrollment).unwrap();
        assert_eq!(retained.pending(), vec![replacement_path]);
        assert_eq!(retained.outputs().unwrap().len(), 1);
        let mut wrong = synthetic_status(&replacement);
        wrong.binding.dataset_manifest_id = "b".repeat(64);
        assert!(batch::save_status(&second, &replacement, &wrong).is_err());
        batch::save_status(&second, &replacement, &synthetic_status(&replacement)).unwrap();
        assert!(
            load_progress(&directory, &args, &source, &fixture.enrollment)
                .unwrap()
                .complete()
        );
    }

    #[test]
    fn cli_has_explicit_resume_and_independent_round_budget() {
        use clap::Parser;
        for period in ["1", "60"] {
            assert!(
                crate::Cli::try_parse_from([
                    "volparossa",
                    "compute",
                    "peer",
                    "workflow",
                    "--resume",
                    "--directory",
                    "/private/workflow",
                    "--follow",
                    "--follow-poll-seconds",
                    period,
                ])
                .is_ok()
            );
        }
        for period in ["0", "61"] {
            assert!(
                crate::Cli::try_parse_from([
                    "volparossa",
                    "compute",
                    "peer",
                    "workflow",
                    "--resume",
                    "--directory",
                    "/private/workflow",
                    "--follow",
                    "--follow-poll-seconds",
                    period,
                ])
                .is_err()
            );
        }
        assert!(
            crate::Cli::try_parse_from([
                "volparossa",
                "compute",
                "peer",
                "workflow",
                "--resume",
                "--directory",
                "/private/workflow",
                "--max-batches",
                "12",
                "--max-seconds",
                "600"
            ])
            .is_ok()
        );
        assert!(
            crate::Cli::try_parse_from([
                "volparossa",
                "compute",
                "peer",
                "workflow",
                "--resume",
                "--directory",
                "/private/workflow",
                "--max-seconds",
                "601"
            ])
            .is_err()
        );
    }

    #[tokio::test]
    async fn cancelled_preparation_never_submits_even_with_a_saved_handle() {
        let fixture = fixture(1);
        let (source_args, verified, handles) = handles(&fixture, 0);
        let (publication, _) = source(&source_args).unwrap();
        let work = batch::Prepared {
            handle: handles[0].clone(),
            provider: fixture.options.provider_key[0],
            dataset_json: verified.derive(&[0]).unwrap(),
        };
        let (_stop, activity) = tokio::sync::watch::channel(true);
        let error = batch::execute(
            &fixture.root.path().join("no-agent.sock"),
            &work,
            &publication,
            activity,
        )
        .await
        .unwrap_err();
        assert_eq!(
            error.to_string(),
            "compute_distribute_cancelled_before_submit"
        );
    }
}
