//! Explicit finite public work enrollment, not autonomous planning or model-layer sharding.
//! Each invocation advances a bounded number of ordinary distribute/reconcile rounds.

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

#[derive(Debug, Args)]
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
    /// Two to four explicit peers at enrollment; stored unchanged for subsequent invocations.
    #[arg(long, value_parser = parse_key, required_unless_present = "resume", conflicts_with = "resume")]
    provider_key: Vec<VerifyingKey>,
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
            plan,
            directory,
            provider_key: provider_keys,
            max_batches,
            max_seconds,
            execute,
            follow: follow::Options::default(),
            expected_task: None,
        }
    }

    pub(super) fn expect_task(mut self, expected: ExpectedTask) -> Self {
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
    verified_at_unix_seconds: u64,
    provider_keys: Vec<String>,
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
}

impl Progress {
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
                    outputs.push(
                        serde_json::json!({"sample_index":row,"text":rows[index]["text"],
                        "provider_key":part.handle.provider_key,"job_id":part.handle.binding.job_id,
                        "report_sha256":status.report_sha256}),
                    );
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
        let (enrollment, sources) = prepare(args)?;
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
        verified_at_unix_seconds: at,
        provider_keys: args
            .provider_key
            .iter()
            .map(|key| hex::encode(key.as_bytes()))
            .collect(),
        packages,
    };
    validate_enrollment(&enrollment)?;
    Ok((enrollment, sources))
}

fn validate_enrollment(enrollment: &Enrollment) -> Result<()> {
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
    let mut ids = BTreeSet::new();
    for package in &enrollment.packages {
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
    Ok(
        serde_json::json!({"dataset_manifest_id":package.manifest_id,"task":package.task,
        "complete":progress.complete(),"outputs":progress.outputs()?}),
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
                let result = if progress.attempts == 0 {
                    batch::report_with_activity(
                        &batch::Options::workflow(
                            source_args.clone(),
                            providers[..providers.len().min(package.rows)].to_vec(),
                            output,
                            args.max_seconds,
                            package.task.clone(),
                        ),
                        socket,
                        cancelled,
                    )
                    .await
                } else {
                    resume::report_with_activity(
                        &resume::Options::workflow(
                            source_args.clone(),
                            progress.pending(),
                            providers.clone(),
                            output,
                            args.max_seconds,
                        )
                        .prefer_other_provider(args.follow.follow),
                        socket,
                        cancelled,
                    )
                    .await
                };
                progress = load_progress(&directory, &source_args, &verified, enrollment)?;
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
        packages.push(serde_json::json!({"package_index":index,"dataset_manifest_id":package.manifest_id,
            "complete":progress.complete(),"attempts":progress.attempts,"outputs":progress.outputs()?,
            "pending_handles":progress.pending(),"task":package.task}));
    }
    let complete = completed == enrollment.packages.len();
    if complete {
        stopped = "complete";
    } else if *cancelled.borrow() {
        stopped = "interrupted_handles_retained";
    }
    let mut report = serde_json::json!({"version":1,"operation":"compute_workflow","execute":args.execute,
        "complete":complete,"completed_packages":completed,"package_count":enrollment.packages.len(),
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
        enrollment.provider_keys.contains(&handle.provider_key)
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
    };
    let peers = enrollment.provider_keys.len().min(progress.rows);
    let mut expected = vec![vec![]; peers];
    for row in 0..progress.rows {
        expected[row % peers].push(u16::try_from(row)?);
    }
    let mut identifiers = BTreeSet::new();
    for (number, attempt) in attempts.iter().enumerate() {
        let mut originals = BTreeSet::new();
        for index in 0..4 {
            let path = attempt.join(format!("original-{index}.json"));
            if !path.try_exists()? {
                continue;
            }
            let original = checked_handle(&path, args, verified, enrollment)?;
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
            let handle = checked_handle(&path, args, verified, enrollment)?;
            let rows = handle.binding.row_indices.clone();
            ensure!(
                expected.contains(&rows)
                    && identifiers.insert(handle.binding.job_id.clone())
                    && new_groups.insert(rows.clone()),
                "compute_workflow_assignment_changed"
            );
            if number > 0 {
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
            if let Some(previous) = progress.parts.values().next() {
                ensure!(
                    previous.handle.binding.model_fingerprint == handle.binding.model_fingerprint,
                    "compute_workflow_mixed_models"
                );
            }
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
            progress.parts.len() == expected.len(),
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
            provider_key: vec![publisher.verifying_key(), peer.verifying_key()],
            max_batches: 1,
            max_seconds: 600,
            execute: true,
            follow: follow::Options::default(),
            expected_task: None,
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
            model_id: "coordinator-codec-fixture".into(),
            model_revision: "fixture".into(),
            base_weights: rpc::FileIdentity {
                bytes: 1,
                sha256: "a".repeat(64),
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

    #[test]
    fn enrolled_task_survives_handles_and_cannot_be_relabelled_or_downgraded() {
        let mut fixture = fixture(1);
        fixture.enrollment.packages[0].task = Some(rpc::PublicTask::SummarizeContextsV1 {});
        let (args, source, handles) = handles(&fixture, 0);
        let path = fixture.root.path().join("task-handle.json");
        save_new(&path, &handles[0]).unwrap();
        let checked = checked_handle(&path, &args, &source, &fixture.enrollment).unwrap();
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
        assert!(checked_handle(&other, &args, &source, &fixture.enrollment).is_err());
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
