//! Work-conserving first submissions for one enrolled public source.
//! A missing reply never turns a retained lease back into an unsubmitted row.

use std::collections::VecDeque;

use super::*;

pub(super) mod cohort;

const SCHEDULING: &str = "ready_rows_v1";
const PLAN: &str = "queue-plan.json";

#[derive(Debug, PartialEq, Eq)]
enum Slot {
    Idle,
    Probing,
    Active(String),
    Unavailable,
}

struct Queue {
    rows: VecDeque<u16>,
    slots: Vec<Slot>,
}

impl Queue {
    fn new(rows: &[u16], providers: usize) -> Self {
        Self {
            rows: rows.iter().copied().collect(),
            slots: (0..providers).map(|_| Slot::Idle).collect(),
        }
    }

    fn probes(&mut self) -> Vec<usize> {
        let probing = self
            .slots
            .iter()
            .filter(|slot| **slot == Slot::Probing)
            .count();
        let mut available = self.rows.len().saturating_sub(probing);
        let mut result = Vec::new();
        for (index, slot) in self.slots.iter_mut().enumerate() {
            if available > 0 && *slot == Slot::Idle {
                *slot = Slot::Probing;
                result.push(index);
                available -= 1;
            }
        }
        result
    }

    fn row(&mut self, index: usize) -> Result<u16> {
        ensure!(
            self.slots[index] == Slot::Probing,
            "compute_ready_queue_slot_state"
        );
        self.rows
            .pop_front()
            .context("compute_ready_queue_missing_row")
    }

    fn release(&mut self, id: &str, reusable: bool) {
        for slot in &mut self.slots {
            if matches!(slot, Slot::Active(active) if active == id) {
                *slot = if reusable {
                    Slot::Idle
                } else {
                    Slot::Unavailable
                };
            }
        }
    }
}

enum Event {
    Profile(usize, Result<rpc::Capabilities>),
    Finished(JobHandle, Result<rpc::JobStatus>, bool),
}

fn terminal(status: &rpc::JobStatus) -> bool {
    status.state != rpc::JobState::Running
}

fn reusable(state: Option<rpc::JobState>, expiry: u64, time: u64) -> bool {
    state.is_some_and(|state| state != rpc::JobState::Running) || time >= expiry
}

fn provider_keys(providers: &[VerifyingKey]) -> Vec<String> {
    providers
        .iter()
        .map(|key| hex::encode(key.as_bytes()))
        .collect()
}

fn check_handle(
    handle: &JobHandle,
    source: &VerifiedPublicDataset,
    task: Option<&rpc::PublicTask>,
    fingerprint: &str,
) -> Result<()> {
    validate_profile(&handle.capabilities)?;
    parse_key(&handle.provider_key).map_err(anyhow::Error::msg)?;
    ensure!(
        handle.version == 1
            && handle.binding.row_indices.len() == 1
            && usize::from(handle.binding.row_indices[0]) < source.row_count()
            && handle.binding.dataset_manifest_id == hex::encode(source.manifest_id())
            && handle.binding.dataset_sha256
                == sha(derive(source, &handle.binding.row_indices, task)?.as_bytes())
            && handle.binding.task.as_ref() == task
            && handle.binding.model_fingerprint == fingerprint
            && handle.capabilities.model_fingerprint == fingerprint
            && supports_source(source, &handle.capabilities)
            && (task.is_none() || handle.capabilities.task_derivation_v1)
            && rpc::nonzero_hex(&handle.binding.job_id, 32)
            && handle.binding.expires_unix_seconds > 0
            && handle.binding.expires_unix_seconds <= source.expires(),
        "compute_ready_queue_original_binding"
    );
    Ok(())
}

fn inputs(args: &ReadyOptions, source: &VerifiedPublicDataset) -> Result<Option<String>> {
    ensure!(
        (1..=4).contains(&args.providers.len())
            && (1..=4).contains(&source.row_count())
            && (1..=600).contains(&args.max_seconds)
            && args.pending.len() + args.ready_rows.len() <= source.row_count()
            && !args.ready_rows.is_empty(),
        "compute_ready_queue_bound"
    );
    let distinct: BTreeSet<_> = args.providers.iter().map(VerifyingKey::to_bytes).collect();
    ensure!(
        distinct.len() == args.providers.len(),
        "compute_distribute_duplicate_provider"
    );
    ensure!(
        args.ready_rows.windows(2).all(|pair| pair[0] < pair[1])
            && args
                .ready_rows
                .iter()
                .all(|row| usize::from(*row) < source.row_count()),
        "compute_ready_queue_rows"
    );
    if let Some(task) = &args.task {
        task.question()?;
    }
    let mut fingerprint = args.model_fingerprint.clone();
    let mut rows: BTreeSet<_> = args.ready_rows.iter().copied().collect();
    let mut ids = BTreeSet::new();
    let mut occupied = BTreeSet::new();
    for pending in &args.pending {
        let handle = &pending.handle;
        let expected = fingerprint.get_or_insert_with(|| handle.binding.model_fingerprint.clone());
        check_handle(handle, source, args.task.as_ref(), expected)?;
        ensure!(
            rows.insert(handle.binding.row_indices[0]) && ids.insert(&handle.binding.job_id),
            "compute_ready_queue_queued_or_duplicate_original"
        );
        if let Some(status) = &pending.verified_status {
            job(rpc::Outcome::Job(status.clone()), handle)?;
        }
        if !reusable(
            pending.verified_status.as_ref().map(|status| status.state),
            handle.binding.expires_unix_seconds,
            now()?,
        ) {
            ensure!(
                occupied.insert(&handle.provider_key),
                "compute_ready_queue_overlapping_peer_leases"
            );
        }
    }
    if let Some(value) = &fingerprint {
        discovery::parse_fingerprint(value).map_err(anyhow::Error::msg)?;
    }
    Ok(fingerprint)
}

fn profile(
    source: &VerifiedPublicDataset,
    caps: &rpc::Capabilities,
    task: Option<&rpc::PublicTask>,
    fingerprint: &str,
) -> Result<()> {
    validate_profile(caps)?;
    ensure!(
        caps.accepting_work && caps.max_rows > 0,
        "compute_distribute_peer_busy"
    );
    ensure!(
        caps.model_fingerprint == fingerprint,
        "compute_distribute_incompatible_models"
    );
    ensure!(
        supports_source(source, caps),
        "compute_peer_document_not_supported"
    );
    ensure!(
        task.is_none() || caps.task_derivation_v1,
        "compute_peer_task_not_supported"
    );
    ensure!(now()? < source.expires(), "compute_peer_source_expired");
    Ok(())
}

/// Initial metadata-only preflight retains legacy fixed transient diagnostics and cannot
/// strand work: no directory, handle or Submit exists at this point.
async fn preflight(
    args: &ReadyOptions,
    source: &VerifiedPublicDataset,
    socket: &Path,
    activity: &watch::Receiver<bool>,
    fingerprint: &mut Option<String>,
) -> Result<Vec<Option<rpc::Capabilities>>> {
    let mut probes = JoinSet::new();
    for (index, provider) in args.providers.iter().copied().enumerate() {
        let socket = socket.to_owned();
        let activity = activity.clone();
        probes.spawn(async move {
            (
                index,
                readiness::capabilities(&socket, &provider, activity).await,
            )
        });
    }
    let mut profiles = vec![None; args.providers.len()];
    let mut first_error = None;
    while let Some(result) = probes.join_next().await {
        let (index, result) = result?;
        match result {
            Ok(caps) => {
                let expected = fingerprint.get_or_insert_with(|| caps.model_fingerprint.clone());
                profile(source, &caps, args.task.as_ref(), expected)?;
                profiles[index] = Some(caps);
            }
            Err(error) => {
                first_error.get_or_insert(error);
            }
        }
    }
    ensure!(
        !*activity.borrow(),
        "compute_distribute_cancelled_before_submit"
    );
    if profiles.iter().all(Option::is_none) {
        return Err(first_error.unwrap_or_else(|| {
            anyhow::anyhow!("compute_distribute_capability_probe_unavailable")
        }));
    }
    Ok(profiles)
}

pub(super) fn verify_plan(
    attempt: &Path,
    source_args: &Source,
    verified: &VerifiedPublicDataset,
    expected_ready_rows: &[u16],
    pending: &[ReadyPending],
) -> Result<ReadyPlan> {
    let plan: ReadyPlan = serde_json::from_slice(&read_file(&attempt.join(PLAN), 32 * 1024)?)?;
    let providers: Vec<_> = plan
        .provider_keys
        .iter()
        .map(|key| parse_key(key).map_err(anyhow::Error::msg))
        .collect::<Result<_>>()?;
    ensure!(
        plan.version == 1
            && plan.scheduling == SCHEDULING
            && plan.publisher_key == hex::encode(source_args.publisher_key.as_bytes())
            && plan.dataset_manifest_id == hex::encode(verified.manifest_id())
            && plan.dataset_sha256
                == sha(&read_file(&source_args.dataset, rpc::MAX_DATASET_BYTES)?)
            && plan.source_expires_unix_seconds == verified.expires()
            && plan.ready_rows == expected_ready_rows
            && plan.pending_job_ids
                == pending
                    .iter()
                    .map(|part| part.handle.binding.job_id.clone())
                    .collect::<Vec<_>>()
            && plan.planned_at_unix_seconds > 0
            && plan.planned_at_unix_seconds <= now()?
            && plan.planned_at_unix_seconds < verified.expires(),
        "compute_ready_queue_plan_binding"
    );
    inputs(
        &ReadyOptions {
            source: source_args.clone(),
            providers,
            output: attempt.to_owned(),
            max_seconds: 600,
            task: plan.task.clone(),
            model_fingerprint: Some(plan.model_fingerprint.clone()),
            ready_rows: plan.ready_rows.clone(),
            pending: pending.to_vec(),
            executor_admission: None,
        },
        verified,
    )?;
    for (index, original) in pending.iter().enumerate() {
        let retained: JobHandle = serde_json::from_slice(&read_file(
            &attempt.join(format!("original-{index}.json")),
            16 * 1024,
        )?)?;
        ensure!(
            serde_json::to_vec(&retained)? == serde_json::to_vec(&original.handle)?,
            "compute_ready_queue_original_changed"
        );
    }
    Ok(plan)
}

/// On an ambiguous execution error retain the provider slot through the original lease.
/// Expiry permits a fresh capability probe; it is never reported as observed termination.
async fn finish(
    socket: &Path,
    handle: JobHandle,
    mut result: Result<rpc::JobStatus>,
    new_submission: bool,
    mut activity: watch::Receiver<bool>,
) -> Event {
    let state = result.as_ref().ok().map(|status| status.state);
    while !*activity.borrow() {
        let Ok(time) = now() else { break };
        if reusable(state, handle.binding.expires_unix_seconds, time) {
            break;
        }
        tokio::select! {
            () = sleep(Duration::from_secs(handle.binding.expires_unix_seconds.saturating_sub(time))) => {},
            _ = activity.changed() => {},
        }
    }
    let owner_stopped = *activity.borrow();
    if owner_stopped && result.is_err() {
        // The original exchange can have failed after remote admission. Owner cancellation
        // still addresses that exact job; unavailable cancellation proves no termination.
        let cancellation = async {
            let provider = parse_key(&handle.provider_key).map_err(anyhow::Error::msg)?;
            let outcome = exchange(
                socket,
                &provider,
                rpc::Operation::Cancel(handle.binding.clone()),
            )
            .await?;
            job(outcome, &handle)
        }
        .await;
        if let Ok(status) = cancellation {
            result = Ok(status);
        }
    }
    Event::Finished(handle, result, new_submission)
}

fn completed(
    output: &Path,
    handle: &JobHandle,
    result: &Result<rpc::JobStatus>,
    new_submission: bool,
    outputs: &mut [Option<serde_json::Value>],
) -> Result<serde_json::Value> {
    if let Ok(status) = result {
        save_status(output, handle, status)?;
        if status.state == rpc::JobState::Complete {
            let report: serde_json::Value = serde_json::from_str(
                status
                    .report_json
                    .as_deref()
                    .context("compute_distribute_report")?,
            )?;
            let row = usize::from(handle.binding.row_indices[0]);
            ensure!(outputs[row].is_none(), "compute_distribute_duplicate_row");
            outputs[row] = Some(
                serde_json::json!({"sample_index":row,"provider_key":handle.provider_key,
                "job_id":handle.binding.job_id,"text":report["outputs"][0]["text"]}),
            );
        }
        Ok(
            serde_json::json!({"handle":handle,"state":status.state,"new_submission":new_submission,
            "report_sha256":status.report_sha256,"cancellation_requested":status.cancellation_requested,"error":status.error}),
        )
    } else {
        Ok(
            serde_json::json!({"handle":handle,"state":"unconfirmed","new_submission":new_submission,
            "error":"COMPUTE_RPC_UNCONFIRMED"}),
        )
    }
}

fn dispatch(
    args: &ReadyOptions,
    verified: &VerifiedPublicDataset,
    index: usize,
    row: u16,
    caps: rpc::Capabilities,
    fingerprint: &str,
) -> Result<Prepared> {
    profile(verified, &caps, args.task.as_ref(), fingerprint)?;
    let rows = vec![row];
    let data = derive(verified, &rows, args.task.as_ref())?;
    let handle = JobHandle {
        version: 1,
        provider_key: hex::encode(args.providers[index].as_bytes()),
        binding: binding(
            verified,
            rows,
            &data,
            &caps,
            u64::from(args.max_seconds),
            args.task.clone(),
        )?,
        capabilities: caps,
    };
    if let Some((authorization, _)) = &args.executor_admission {
        authorization.validate_handle(verified, &handle)?;
    }
    // This fsync-backed immutable handle precedes the only Submit for this row.
    save_new(&args.output.join(format!("job-{row}.json")), &handle)?;
    Ok(Prepared {
        handle,
        provider: args.providers[index],
        dataset_json: data,
    })
}

fn create_plan(
    args: &ReadyOptions,
    publication: &rpc::PublicDataset,
    verified: &VerifiedPublicDataset,
    fingerprint: &str,
) -> Result<ReadyPlan> {
    let time = now()?;
    ensure!(time < verified.expires(), "compute_peer_source_expired");
    super::super::super::private_directory(
        args.output
            .parent()
            .context("compute_distribute_output_parent")?,
    )?;
    fs::DirBuilder::new().mode(0o700).create(&args.output)?;
    if let Some((authorization, selected)) = &args.executor_admission {
        executors::admit(&args.output, authorization, selected)?;
    }
    for (index, pending) in args.pending.iter().enumerate() {
        save_new(
            &args.output.join(format!("original-{index}.json")),
            &pending.handle,
        )?;
    }
    let plan = ReadyPlan {
        version: 1,
        scheduling: SCHEDULING.into(),
        publisher_key: publication.publisher_key.clone(),
        dataset_manifest_id: hex::encode(verified.manifest_id()),
        dataset_sha256: sha(publication.dataset_json.as_bytes()),
        source_expires_unix_seconds: verified.expires(),
        model_fingerprint: fingerprint.into(),
        task: args.task.clone(),
        provider_keys: provider_keys(&args.providers),
        ready_rows: args.ready_rows.clone(),
        pending_job_ids: args
            .pending
            .iter()
            .map(|pending| pending.handle.binding.job_id.clone())
            .collect(),
        planned_at_unix_seconds: time,
    };
    save_new(&args.output.join(PLAN), &plan)?;
    Ok(plan)
}

#[allow(
    clippy::too_many_lines,
    reason = "One bounded slot-refill loop drains retained remote authority on cancellation or storage failure"
)]
pub(super) async fn report(
    args: &ReadyOptions,
    socket: &Path,
    activity: &watch::Receiver<bool>,
) -> Result<serde_json::Value> {
    let (publication, verified) = source(&args.source)?;
    let mut fingerprint = inputs(args, &verified)?;
    ensure!(
        !*activity.borrow(),
        "compute_distribute_cancelled_before_submit"
    );
    if let Some((authorization, selected)) = &args.executor_admission {
        ensure!(
            authorization.publisher_key == publication.publisher_key
                && authorization.dataset_sha256 == sha(publication.dataset_json.as_bytes())
                && selected.providers == args.providers
                && args.model_fingerprint.as_ref() == Some(&selected.model_fingerprint),
            "compute_distribute_executor_selection"
        );
    }
    let mut profiles = if args.pending.is_empty() {
        preflight(args, &verified, socket, activity, &mut fingerprint).await?
    } else {
        vec![None; args.providers.len()]
    };
    let fingerprint = fingerprint.context("compute_ready_queue_model_required")?;
    let time = now()?;
    ensure!(time < verified.expires(), "compute_peer_source_expired");
    super::super::super::private_directory(
        args.output
            .parent()
            .context("compute_distribute_output_parent")?,
    )?;
    fs::DirBuilder::new().mode(0o700).create(&args.output)?;
    if let Some((authorization, selected)) = &args.executor_admission {
        executors::admit(&args.output, authorization, selected)?;
    }
    for (index, pending) in args.pending.iter().enumerate() {
        save_new(
            &args.output.join(format!("original-{index}.json")),
            &pending.handle,
        )?;
    }
    let plan = ReadyPlan {
        version: 1,
        scheduling: SCHEDULING.into(),
        publisher_key: publication.publisher_key.clone(),
        dataset_manifest_id: hex::encode(verified.manifest_id()),
        dataset_sha256: sha(publication.dataset_json.as_bytes()),
        source_expires_unix_seconds: verified.expires(),
        model_fingerprint: fingerprint.clone(),
        task: args.task.clone(),
        provider_keys: provider_keys(&args.providers),
        ready_rows: args.ready_rows.clone(),
        pending_job_ids: args
            .pending
            .iter()
            .map(|pending| pending.handle.binding.job_id.clone())
            .collect(),
        planned_at_unix_seconds: time,
    };
    save_new(&args.output.join(PLAN), &plan)?;
    let (stop, cancellation) = watch::channel(*activity.borrow());
    let mut owner = activity.clone();
    let mut queue = Queue::new(&args.ready_rows, args.providers.len());
    if args.pending.is_empty() {
        for (index, caps) in profiles.iter().enumerate() {
            if caps.is_none() {
                queue.slots[index] = Slot::Unavailable;
            }
        }
    }
    let mut tasks = JoinSet::new();
    let mut outputs = vec![None; verified.row_count()];
    let mut parts = Vec::new();
    let mut fatal = None;
    // Complete all fallible local receipt writes before starting observation futures.
    for pending in &args.pending {
        if let Some(status) = pending
            .verified_status
            .as_ref()
            .filter(|status| terminal(status))
        {
            parts.push(completed(
                &args.output,
                &pending.handle,
                &Ok(status.clone()),
                false,
                &mut outputs,
            )?);
        }
    }
    for pending in args
        .pending
        .iter()
        .filter(|pending| !pending.verified_status.as_ref().is_some_and(terminal))
    {
        let handle = pending.handle.clone();
        if handle.binding.expires_unix_seconds > time {
            if let Some(index) = plan
                .provider_keys
                .iter()
                .position(|key| *key == handle.provider_key)
            {
                queue.slots[index] = Slot::Active(handle.binding.job_id.clone());
            }
        }
        let socket = socket.to_owned();
        let cancellation = cancellation.clone();
        tasks.spawn(async move {
            let result = observe_existing(&socket, &handle, cancellation.clone()).await;
            finish(&socket, handle, result, false, cancellation).await
        });
    }
    let publication = Arc::new(publication);
    loop {
        if *owner.borrow() {
            let _ = stop.send(true);
        }
        let time = match now() {
            Ok(time) => time,
            Err(error) => {
                fatal.get_or_insert(error);
                let _ = stop.send(true);
                0
            }
        };
        if fatal.is_none() && !*cancellation.borrow() && time < verified.expires() {
            for index in queue.probes() {
                let cached = profiles[index].take();
                let provider = args.providers[index];
                let socket = socket.to_owned();
                let cancellation = cancellation.clone();
                tasks.spawn(async move {
                    let result = match cached {
                        Some(caps) => Ok(caps),
                        None => readiness::capabilities(&socket, &provider, cancellation).await,
                    };
                    Event::Profile(index, result)
                });
            }
        }
        if tasks.is_empty() {
            break;
        }
        let event = tokio::select! {
            biased;
            changed = owner.changed(), if !*cancellation.borrow() => {
                if changed.is_err() || *owner.borrow() { let _ = stop.send(true); }
                continue;
            },
            event = tasks.join_next() => {
                let Some(event) = event else { break };
                event
            },
        };
        let handled = match event {
            Err(error) => Err(anyhow::Error::from(error)),
            Ok(Event::Profile(index, Err(_))) => {
                queue.slots[index] = Slot::Unavailable;
                Ok(())
            }
            Ok(Event::Profile(index, Ok(caps))) => {
                if fatal.is_some() || *cancellation.borrow() {
                    queue.slots[index] = Slot::Unavailable;
                    Ok(())
                } else {
                    match queue
                        .row(index)
                        .and_then(|row| dispatch(args, &verified, index, row, caps, &fingerprint))
                    {
                        Err(error) => Err(error),
                        Ok(work) => {
                            queue.slots[index] = Slot::Active(work.handle.binding.job_id.clone());
                            let socket = socket.to_owned();
                            let publication = Arc::clone(&publication);
                            let cancellation = cancellation.clone();
                            tasks.spawn(async move {
                                let result =
                                    execute(&socket, &work, &publication, cancellation.clone())
                                        .await;
                                finish(&socket, work.handle, result, true, cancellation).await
                            });
                            Ok(())
                        }
                    }
                }
            }
            Ok(Event::Finished(handle, result, new_submission)) => match now() {
                Ok(time) => {
                    queue.release(
                        &handle.binding.job_id,
                        reusable(
                            result.as_ref().ok().map(|status| status.state),
                            handle.binding.expires_unix_seconds,
                            time,
                        ),
                    );
                    completed(&args.output, &handle, &result, new_submission, &mut outputs)
                        .map(|part| parts.push(part))
                }
                Err(error) => Err(error),
            },
        };
        if let Err(error) = handled {
            fatal.get_or_insert(error);
            // Do not drop running futures after a local error: request ordinary exact-handle
            // cancellation and join them. An unavailable cancellation remains unconfirmed.
            let _ = stop.send(true);
        }
    }
    if let Some(error) = fatal {
        return Err(error);
    }
    parts.sort_by_key(|part| part["handle"]["binding"]["row_indices"][0].as_u64());
    let complete = queue.rows.is_empty()
        && parts.len() == args.ready_rows.len() + args.pending.len()
        && parts.iter().all(|part| part["state"] == "complete");
    let providers_used = parts
        .iter()
        .map(|part| part["handle"]["provider_key"].as_str())
        .collect::<BTreeSet<_>>()
        .len();
    let report = serde_json::json!({"version":1,"operation":"compute_ready_queue","scheduling":SCHEDULING,
        "complete":complete,"dataset_manifest_id":plan.dataset_manifest_id,"model_fingerprint":fingerprint,
        "provider_count":args.providers.len(),"providers_used":providers_used,"outputs":outputs,"jobs":parts,"never_submitted_rows":queue.rows,
        "task":args.task,"private_data_supported":false,"model_layer_sharding":false,
        "exactly_once_execution_guaranteed":false,"result_truthfulness_guaranteed":false});
    save_new(&args.output.join("result.json"), &report)?;
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fast_peer_refills_while_original_slow_slot_remains_owned() {
        let mut queue = Queue::new(&[0, 1, 2, 3], 2);
        assert_eq!(queue.probes(), vec![0, 1]);
        assert_eq!(queue.row(0).unwrap(), 0);
        queue.slots[0] = Slot::Active("slow-original".into());
        assert_eq!(queue.row(1).unwrap(), 1);
        queue.slots[1] = Slot::Active("fast-first".into());
        assert!(queue.probes().is_empty());
        queue.release("fast-first", true);
        assert_eq!(queue.probes(), vec![1]);
        assert_eq!(queue.row(1).unwrap(), 2);
        queue.slots[1] = Slot::Active("fast-second".into());
        assert_eq!(queue.slots[0], Slot::Active("slow-original".into()));
        queue.release("fast-second", true);
        assert_eq!(queue.probes(), vec![1]);
        assert_eq!(queue.row(1).unwrap(), 3);
        assert!(queue.rows.is_empty());
    }

    #[test]
    fn uncertain_reply_does_not_release_or_duplicate_an_unexpired_slot() {
        assert!(!reusable(None, 100, 99));
        assert!(!reusable(Some(rpc::JobState::Running), 100, 99));
        assert!(reusable(Some(rpc::JobState::Failed), 100, 99));
        assert!(reusable(Some(rpc::JobState::Cancelled), 100, 99));
        assert!(reusable(Some(rpc::JobState::Complete), 100, 99));
        assert!(reusable(None, 100, 100));
        let mut queue = Queue::new(&[2, 3], 2);
        queue.slots[0] = Slot::Active("uncertain".into());
        queue.release("some-other-expired-handle", true);
        assert_eq!(queue.probes(), vec![1]);
        assert_eq!(queue.slots[0], Slot::Active("uncertain".into()));
    }

    #[test]
    fn probe_reservations_never_exceed_genuinely_unsubmitted_rows() {
        let mut queue = Queue::new(&[3], 4);
        assert_eq!(queue.probes(), vec![0]);
        assert!(queue.probes().is_empty());
        queue.slots[0] = Slot::Unavailable;
        assert_eq!(queue.probes(), vec![1]);
        assert_eq!(queue.row(1).unwrap(), 3);
        queue.slots[1] = Slot::Active("last".into());
        assert!(queue.probes().is_empty());
    }
}
