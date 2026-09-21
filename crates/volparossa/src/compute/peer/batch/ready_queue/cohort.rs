//! One owner's source-aware queue, with shared provider leases rather than racing brokers.

use std::collections::BTreeMap;

use super::*;

mod driver;
pub(in crate::compute::peer) use driver::ReadyCohort;

const MAX_PACKAGES: usize = 32;
const MAX_ACTIVE_PROVIDERS: usize = 4;

#[derive(Default)]
struct Leases {
    held: BTreeMap<String, BTreeMap<String, JobHandle>>,
    probing: BTreeSet<String>,
}

impl Leases {
    fn observe(
        &mut self,
        handle: &JobHandle,
        status: Option<&rpc::JobStatus>,
        at: u64,
    ) -> Result<()> {
        parse_key(&handle.provider_key).map_err(anyhow::Error::msg)?;
        ensure!(
            handle.version == 1
                && rpc::nonzero_hex(&handle.binding.job_id, 32)
                && handle.binding.expires_unix_seconds > 0,
            "compute_cohort_reservation_binding"
        );
        if let Some(previous) = self
            .held
            .get(&handle.provider_key)
            .and_then(|jobs| jobs.get(&handle.binding.job_id))
        {
            ensure!(
                serde_json::to_vec(previous)? == serde_json::to_vec(handle)?,
                "compute_cohort_reservation_changed"
            );
        }
        if let Some(status) = status {
            job(rpc::Outcome::Job(status.clone()), handle)?;
        }
        if reusable(
            status.map(|value| value.state),
            handle.binding.expires_unix_seconds,
            at,
        ) {
            self.release(handle);
            return Ok(());
        }
        let jobs = self.held.entry(handle.provider_key.clone()).or_default();
        jobs.insert(handle.binding.job_id.clone(), handle.clone());
        Ok(())
    }

    fn release(&mut self, handle: &JobHandle) {
        if let Some(jobs) = self.held.get_mut(&handle.provider_key) {
            jobs.remove(&handle.binding.job_id);
            if jobs.is_empty() {
                self.held.remove(&handle.provider_key);
            }
        }
    }

    fn expire(&mut self, at: u64) {
        self.held.retain(|_, jobs| {
            jobs.retain(|_, handle| handle.binding.expires_unix_seconds > at);
            !jobs.is_empty()
        });
    }

    fn free(&self, provider: &str) -> bool {
        self.held.len() + self.probing.len() < MAX_ACTIVE_PROVIDERS
            && !self.held.contains_key(provider)
            && !self.probing.contains(provider)
    }

    fn next_expiry(&self, eligible: impl Fn(&str) -> bool) -> Option<u64> {
        self.held
            .iter()
            .filter(|(provider, _)| eligible(provider))
            .flat_map(|(_, jobs)| {
                jobs.values()
                    .map(|handle| handle.binding.expires_unix_seconds)
            })
            .min()
    }
}

struct Candidate {
    args: ReadyOptions,
    publication: rpc::PublicDataset,
    source: VerifiedPublicDataset,
    fingerprint: Option<String>,
}

struct Package {
    args: ReadyOptions,
    publication: Arc<rpc::PublicDataset>,
    source: VerifiedPublicDataset,
    plan: ReadyPlan,
    rows: VecDeque<u16>,
    outputs: Vec<Option<serde_json::Value>>,
    parts: Vec<serde_json::Value>,
    unavailable: BTreeSet<String>,
    stop: watch::Sender<bool>,
    activity: watch::Receiver<bool>,
    error: Option<anyhow::Error>,
    inflight: usize,
}

impl Package {
    fn fail(&mut self, error: anyhow::Error) {
        self.error.get_or_insert(error);
        let _ = self.stop.send(true);
    }

    fn eligible(&self, provider: &str) -> bool {
        self.error.is_none()
            && !self.rows.is_empty()
            && !*self.activity.borrow()
            && self.plan.provider_keys.iter().any(|key| key == provider)
            && !self.unavailable.contains(provider)
    }

    fn restore_row(&mut self, row: u16) {
        let index = self
            .rows
            .iter()
            .position(|value| *value > row)
            .unwrap_or(self.rows.len());
        self.rows.insert(index, row);
    }

    fn report(&mut self) -> Result<serde_json::Value> {
        if let Some(error) = self.error.take() {
            return Err(error);
        }
        self.parts
            .sort_by_key(|part| part["handle"]["binding"]["row_indices"][0].as_u64());
        let complete = self.rows.is_empty()
            && self.parts.len() == self.args.ready_rows.len() + self.args.pending.len()
            && self.parts.iter().all(|part| part["state"] == "complete");
        let used = self
            .parts
            .iter()
            .map(|part| part["handle"]["provider_key"].as_str())
            .collect::<BTreeSet<_>>()
            .len();
        let answer_complete = complete
            && output::all_complete(&self.outputs.iter().flatten().cloned().collect::<Vec<_>>())?;
        let value = serde_json::json!({"version":1,"operation":"compute_ready_queue","scheduling":SCHEDULING,
            "execution_complete":complete,"answer_complete":answer_complete,
            "complete":complete,"dataset_manifest_id":self.plan.dataset_manifest_id,
            "model_fingerprint":self.plan.model_fingerprint,"provider_count":self.args.providers.len(),
            "providers_used":used,"outputs":self.outputs,"jobs":self.parts,"never_submitted_rows":self.rows,
            "task":self.args.task,"private_data_supported":false,"model_layer_sharding":false,
            "exactly_once_execution_guaranteed":false,"result_truthfulness_guaranteed":false,
            "shared_package_slots":true,"maximum_active_providers":MAX_ACTIVE_PROVIDERS});
        save_new(&self.args.output.join("result.json"), &value)?;
        Ok(value)
    }
}

enum GroupEvent {
    Profile {
        package: usize,
        row: u16,
        provider: String,
        result: Result<rpc::Capabilities>,
    },
    Finished {
        package: usize,
        handle: JobHandle,
        result: Result<rpc::JobStatus>,
        new_submission: bool,
    },
}

fn prepare(args: ReadyOptions) -> Result<Candidate> {
    let (publication, source) = source(&args.source)?;
    let fingerprint = inputs(&args, &source)?;
    if let Some((authorization, selected)) = &args.executor_admission {
        ensure!(
            authorization.publisher_key == publication.publisher_key
                && authorization.dataset_sha256 == sha(publication.dataset_json.as_bytes())
                && selected.providers == args.providers
                && args.model_fingerprint.as_ref() == Some(&selected.model_fingerprint),
            "compute_distribute_executor_selection"
        );
    }
    Ok(Candidate {
        args,
        publication,
        source,
        fingerprint,
    })
}

fn cancelled_packages(
    results: Vec<Option<Result<serde_json::Value>>>,
) -> Vec<Result<serde_json::Value>> {
    results
        .into_iter()
        .map(|result| {
            result.unwrap_or_else(|| {
                Err(anyhow::anyhow!(
                    "compute_distribute_cancelled_before_submit"
                ))
            })
        })
        .collect()
}

/// Busy metadata can pin a model, but it grants no admission. Every actual dispatch has
/// another fresh accepting-work probe while the global provider reservation is held.
async fn metadata(
    socket: PathBuf,
    provider: VerifyingKey,
    mut activity: watch::Receiver<bool>,
) -> Result<rpc::Capabilities> {
    let work = async {
        for index in 0..24 {
            if index != 0 {
                sleep(Duration::from_secs(2)).await;
            }
            if let Ok(caps) = capabilities(&socket, &provider).await {
                return Ok(caps);
            }
        }
        anyhow::bail!("compute_distribute_capability_probe_unavailable")
    };
    tokio::select! {
        biased;
        () = async { while !*activity.borrow() { if activity.changed().await.is_err() { break; } } }
            => anyhow::bail!("compute_distribute_cancelled_before_submit"),
        result = timeout(Duration::from_secs(45), work)
            => result.context("compute_distribute_capability_probe_timeout")?,
    }
}

fn initialize(
    candidate: Candidate,
    metadata: &BTreeMap<String, rpc::Capabilities>,
) -> Result<Package> {
    let Candidate {
        args,
        publication,
        source,
        mut fingerprint,
    } = candidate;
    for provider in &args.providers {
        if let Some(caps) = metadata.get(&hex::encode(provider.as_bytes())) {
            validate_profile(caps)?;
            let expected = fingerprint.get_or_insert_with(|| caps.model_fingerprint.clone());
            ensure!(
                caps.model_fingerprint == *expected,
                "compute_distribute_incompatible_models"
            );
            ensure!(
                supports_source(&source, caps),
                "compute_peer_document_not_supported"
            );
            ensure!(
                args.task.is_none() || caps.task_derivation_v1,
                "compute_peer_task_not_supported"
            );
        }
    }
    let fingerprint = fingerprint.context("compute_distribute_capability_probe_unavailable")?;
    let plan = create_plan(&args, &publication, &source, &fingerprint)?;
    let (stop, activity) = watch::channel(false);
    let mut package = Package {
        publication: Arc::new(publication),
        outputs: vec![None; source.row_count()],
        source,
        plan,
        rows: args.ready_rows.iter().copied().collect(),
        parts: Vec::new(),
        unavailable: BTreeSet::new(),
        stop,
        activity,
        error: None,
        inflight: 0,
        args,
    };
    for pending in &package.args.pending {
        if let Some(status) = pending
            .verified_status
            .as_ref()
            .filter(|status| terminal(status))
        {
            package.parts.push(completed(
                &package.args.output,
                &pending.handle,
                &Ok(status.clone()),
                false,
                &mut package.outputs,
            )?);
        }
    }
    Ok(package)
}

fn next_ready(count: usize, cursor: &mut usize, eligible: impl Fn(usize) -> bool) -> Option<usize> {
    for offset in 0..count {
        let index = (*cursor + offset) % count;
        if eligible(index) {
            *cursor = (index + 1) % count;
            return Some(index);
        }
    }
    None
}

fn start_probes(
    packages: &mut [Option<Package>],
    providers: &BTreeMap<String, VerifyingKey>,
    leases: &mut Leases,
    cursor: &mut usize,
    socket: &Path,
    tasks: &mut JoinSet<GroupEvent>,
) -> Result<()> {
    for (key, provider) in providers {
        if !leases.free(key) {
            continue;
        }
        let Some(index) = next_ready(packages.len(), cursor, |index| {
            packages[index]
                .as_ref()
                .is_some_and(|package| package.eligible(key))
        }) else {
            continue;
        };
        let package = packages[index]
            .as_mut()
            .context("compute_cohort_package_missing")?;
        let row = package
            .rows
            .pop_front()
            .context("compute_cohort_ready_row_missing")?;
        leases.probing.insert(key.clone());
        let socket = socket.to_owned();
        let provider = *provider;
        let key = key.clone();
        let activity = package.activity.clone();
        package.inflight += 1;
        tasks.spawn(async move {
            let result = readiness::capabilities(&socket, &provider, activity).await;
            GroupEvent::Profile {
                package: index,
                row,
                provider: key,
                result,
            }
        });
    }
    Ok(())
}

fn stop_all(packages: &mut [Option<Package>]) {
    for package in packages.iter_mut().flatten() {
        let _ = package.stop.send(true);
    }
}

async fn observe_pending(
    index: usize,
    pending: ReadyPending,
    socket: PathBuf,
    activity: watch::Receiver<bool>,
) -> GroupEvent {
    let handle = pending.handle;
    let result = observe_existing(&socket, &handle, activity.clone()).await;
    let Event::Finished(handle, result, new_submission) =
        finish(&socket, handle, result, false, activity).await
    else {
        unreachable!()
    };
    GroupEvent::Finished {
        package: index,
        handle,
        result,
        new_submission,
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "One verified profile transfers the exact global provider reservation to a saved source-specific handle"
)]
fn accept_profile(
    index: usize,
    row: u16,
    provider: &str,
    result: Result<rpc::Capabilities>,
    packages: &mut [Option<Package>],
    leases: &mut Leases,
    socket: &Path,
    tasks: &mut JoinSet<GroupEvent>,
) -> Result<()> {
    ensure!(
        leases.probing.remove(provider),
        "compute_cohort_probe_reservation_missing"
    );
    let package = packages[index]
        .as_mut()
        .context("compute_cohort_package_missing")?;
    if *package.activity.borrow() || package.error.is_some() || leases.held.contains_key(provider) {
        package.restore_row(row);
        return Ok(());
    }
    let Ok(caps) = result else {
        package.restore_row(row);
        package.unavailable.insert(provider.into());
        return Ok(());
    };
    let provider_index = package
        .plan
        .provider_keys
        .iter()
        .position(|key| key == provider)
        .context("compute_cohort_provider_not_authorized")?;
    let work = match dispatch(
        &package.args,
        &package.source,
        provider_index,
        row,
        caps,
        &package.plan.model_fingerprint,
    ) {
        Ok(work) => work,
        Err(error) => {
            package.restore_row(row);
            package.fail(error);
            return Ok(());
        }
    };
    // The exact handle is durable before this lease or its Submit can exist. A dropped
    // execution future cannot release this reservation; only evidence or expiry can.
    leases.observe(&work.handle, None, now()?)?;
    let socket = socket.to_owned();
    let publication = Arc::clone(&package.publication);
    let activity = package.activity.clone();
    package.inflight += 1;
    tasks.spawn(async move {
        let result = execute(&socket, &work, &publication, activity.clone()).await;
        let Event::Finished(handle, result, new_submission) =
            finish(&socket, work.handle, result, true, activity).await
        else {
            unreachable!()
        };
        GroupEvent::Finished {
            package: index,
            handle,
            result,
            new_submission,
        }
    });
    Ok(())
}

fn accept_finished(
    index: usize,
    handle: &JobHandle,
    result: &Result<rpc::JobStatus>,
    new_submission: bool,
    packages: &mut [Option<Package>],
    leases: &mut Leases,
) -> Result<()> {
    let package = packages[index]
        .as_mut()
        .context("compute_cohort_package_missing")?;
    // Persist the full status before making the provider available to another source.
    match completed(
        &package.args.output,
        handle,
        result,
        new_submission,
        &mut package.outputs,
    ) {
        Ok(part) => package.parts.push(part),
        Err(error) => {
            package.fail(error);
            // If the receipt could not be made durable, retain the original lease.
            // Other sources can still use different providers; this one only reopens
            // at its original expiry, including after a process restart.
            return Ok(());
        }
    }
    leases.observe(handle, result.as_ref().ok(), now()?)?;
    if result.as_ref().is_ok_and(terminal) {
        for package in packages.iter_mut().flatten() {
            package.unavailable.remove(&handle.provider_key);
        }
    }
    Ok(())
}

pub(in super::super) async fn report(
    args: &[ReadyOptions],
    reservations: &[ReadyPending],
    socket: &Path,
    activity: &watch::Receiver<bool>,
) -> Result<Vec<Result<serde_json::Value>>> {
    ensure!(
        (1..=MAX_PACKAGES).contains(&args.len()),
        "compute_cohort_package_bound"
    );
    // The already-proven isolated single-package path is not reinterpreted.
    if args.len() == 1 && reservations.is_empty() {
        return Ok(vec![super::report(&args[0], socket, activity).await]);
    }
    let mut driver = ReadyCohort::new(reservations, socket, activity)?;
    let admitted = driver.append(args.to_vec()).await;
    if let Err(error) = admitted {
        let _ = driver.cancel_and_drain().await;
        return Err(error);
    }
    let mut results: Vec<Option<Result<serde_json::Value>>> =
        (0..args.len()).map(|_| None).collect();
    let mut error = None;
    loop {
        match driver.next_completed().await {
            Ok(Some((index, result))) => results[index] = Some(result),
            Ok(None) => break,
            Err(failure) => {
                error = Some(failure);
                break;
            }
        }
    }
    for (index, result) in driver.cancel_and_drain().await? {
        results[index] = Some(result);
    }
    if let Some(error) = error {
        return Err(error);
    }
    results
        .into_iter()
        .map(|result| result.context("compute_cohort_missing_result"))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn metadata_cancellation_preserves_aligned_source_validation_errors() {
        let mut outcomes = cancelled_packages(vec![
            None,
            Some(Err(anyhow::anyhow!(
                "compute_distribute_executor_selection"
            ))),
        ]);
        assert_eq!(outcomes.len(), 2);
        assert_eq!(
            outcomes.pop().unwrap().unwrap_err().to_string(),
            "compute_distribute_executor_selection"
        );
        assert_eq!(
            outcomes.pop().unwrap().unwrap_err().to_string(),
            "compute_distribute_cancelled_before_submit"
        );
    }

    pub(super) fn handle(provider: u8, job: u8, expiry: u64) -> JobHandle {
        let provider = ed25519_dalek::SigningKey::from_bytes(&[provider; 32]).verifying_key();
        let model = rpc::ModelIdentity {
            model_id: "lease-table-fixture".into(),
            model_revision: "fixture".into(),
            base_weights: rpc::FileIdentity {
                bytes: 1,
                sha256: "a".repeat(64),
            },
            adapter_files: None,
        };
        let fingerprint = sha(&serde_json::to_vec(&model).unwrap());
        JobHandle {
            version: 1,
            provider_key: hex::encode(provider.as_bytes()),
            binding: rpc::JobBinding {
                job_id: hex::encode([job; 16]),
                dataset_manifest_id: "b".repeat(64),
                dataset_sha256: "c".repeat(64),
                model_fingerprint: fingerprint.clone(),
                row_indices: vec![0],
                expires_unix_seconds: expiry,
                task: None,
            },
            capabilities: rpc::Capabilities {
                model,
                model_fingerprint: fingerprint,
                accepting_work: true,
                public_inference_only: true,
                runtime_slots: 1,
                max_threads: 2,
                max_job_seconds: 600,
                max_dataset_bytes: 1024 * 1024,
                max_rows: 4,
                task_derivation_v1: true,
                document_inference_v2: true,
                derived_inference_v3: true,
                successor_activation_v1: false,
            },
        }
    }

    #[test]
    fn outside_window_and_dropped_uncertain_work_keep_global_provider_reserved() {
        let mut leases = Leases::default();
        let original = handle(1, 2, 100);
        leases.observe(&original, None, 10).unwrap();
        assert!(!leases.free(&original.provider_key));
        leases.expire(99);
        assert!(!leases.free(&original.provider_key));
        let running = rpc::JobStatus {
            binding: original.binding.clone(),
            state: rpc::JobState::Running,
            cancellation_requested: true,
            report_json: None,
            report_sha256: None,
            error: None,
        };
        leases.observe(&original, Some(&running), 99).unwrap();
        assert!(!leases.free(&original.provider_key));
        leases.expire(100);
        assert!(leases.free(&original.provider_key));
    }

    #[test]
    fn terminal_evidence_releases_only_its_own_lease_and_changed_binding_is_rejected() {
        let mut leases = Leases::default();
        let original = handle(1, 2, 100);
        leases.observe(&original, None, 10).unwrap();
        let later = handle(1, 3, 200);
        leases.observe(&later, None, 10).unwrap();
        let stopped = rpc::JobStatus {
            binding: original.binding.clone(),
            state: rpc::JobState::Failed,
            cancellation_requested: false,
            report_json: None,
            report_sha256: None,
            error: None,
        };
        leases.observe(&original, Some(&stopped), 20).unwrap();
        assert!(!leases.free(&original.provider_key));
        assert_eq!(leases.next_expiry(|_| true), Some(200));
        let mut changed = later.clone();
        changed.binding.dataset_manifest_id = "d".repeat(64);
        assert!(leases.observe(&changed, None, 20).is_err());
        let changed_terminal = rpc::JobStatus {
            binding: changed.binding.clone(),
            state: rpc::JobState::Failed,
            cancellation_requested: false,
            report_json: None,
            report_sha256: None,
            error: None,
        };
        assert!(
            leases
                .observe(&changed, Some(&changed_terminal), 20)
                .is_err()
        );
        assert!(!leases.free(&original.provider_key));
        leases.expire(200);
        assert!(leases.free(&original.provider_key));
    }

    #[test]
    fn freed_peer_refills_across_sources_while_original_slow_lease_is_retained() {
        let mut rows = [VecDeque::from([0_u16, 1]), VecDeque::from([0_u16, 1])];
        let mut cursor = 0;
        let mut leases = Leases::default();
        let slow = handle(1, 10, 100);
        let fast = handle(2, 11, 100);
        let mut observed = Vec::new();
        for original in [&slow, &fast] {
            assert!(leases.free(&original.provider_key));
            let package =
                next_ready(rows.len(), &mut cursor, |index| !rows[index].is_empty()).unwrap();
            observed.push((package, rows[package].pop_front().unwrap()));
            leases.observe(original, None, 10).unwrap();
        }
        for job_id in [12_u8, 13] {
            assert!(!leases.free(&slow.provider_key));
            let previous = if job_id == 12 {
                fast.clone()
            } else {
                handle(2, 12, 100)
            };
            let terminal = rpc::JobStatus {
                binding: previous.binding.clone(),
                state: rpc::JobState::Failed,
                cancellation_requested: false,
                report_json: None,
                report_sha256: None,
                error: None,
            };
            leases.observe(&previous, Some(&terminal), 20).unwrap();
            assert!(leases.free(&fast.provider_key));
            let package =
                next_ready(rows.len(), &mut cursor, |index| !rows[index].is_empty()).unwrap();
            observed.push((package, rows[package].pop_front().unwrap()));
            leases.observe(&handle(2, job_id, 100), None, 20).unwrap();
        }
        assert_eq!(observed, [(0, 0), (1, 0), (0, 1), (1, 1)]);
        assert!(!leases.free(&slow.provider_key));
        assert_eq!(
            next_ready(rows.len(), &mut cursor, |index| !rows[index].is_empty()),
            None
        );
    }

    #[test]
    fn round_robin_skips_unavailable_sources_and_global_budget_includes_probes() {
        let mut cursor = 0;
        assert_eq!(next_ready(4, &mut cursor, |index| index == 2), Some(2));
        assert_eq!(next_ready(4, &mut cursor, |index| index == 0), Some(0));
        assert_eq!(next_ready(0, &mut cursor, |_| true), None);
        let mut leases = Leases::default();
        for index in 1..=3_u8 {
            leases
                .observe(&handle(index, index, 100), None, 10)
                .unwrap();
        }
        let probe = handle(4, 4, 100);
        assert!(leases.free(&probe.provider_key));
        leases.probing.insert(probe.provider_key.clone());
        assert!(!leases.free(&handle(5, 5, 100).provider_key));
        assert!(!leases.free(&probe.provider_key));
        leases.probing.remove(&probe.provider_key);
        assert!(leases.free(&handle(5, 5, 100).provider_key));
    }
}
