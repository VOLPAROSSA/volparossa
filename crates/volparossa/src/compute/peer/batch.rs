//! Concurrent independent inference rows, not distributed model layers or a general planner.

use std::{collections::BTreeSet, os::unix::fs::DirBuilderExt, sync::Arc};

use tokio::{sync::watch, task::JoinSet, time::sleep};
use volparossa_content::provider::compute::dataset::VerifiedPublicDataset;

use super::*;

pub(super) mod output;
mod ready_queue;

pub(super) use ready_queue::cohort::ReadyCohort;

#[derive(Clone, Debug)]
pub(super) struct ReadyPending {
    pub(super) handle: JobHandle,
    pub(super) verified_status: Option<rpc::JobStatus>,
}

/// The owning workflow supplies only rows that have never acquired a retained handle.
/// Previously attempted rows remain exact pending handles, never fresh queue entries.
#[derive(Clone)]
pub(super) struct ReadyOptions {
    pub(super) source: Source,
    pub(super) providers: Vec<VerifyingKey>,
    pub(super) output: PathBuf,
    pub(super) max_seconds: u16,
    pub(super) task: Option<rpc::PublicTask>,
    pub(super) model_fingerprint: Option<String>,
    pub(super) ready_rows: Vec<u16>,
    pub(super) pending: Vec<ReadyPending>,
    pub(super) executor_admission: Option<(executors::Authorization, discovery::Selected)>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct ReadyPlan {
    pub(super) version: u32,
    pub(super) scheduling: String,
    pub(super) publisher_key: String,
    pub(super) dataset_manifest_id: String,
    pub(super) dataset_sha256: String,
    pub(super) source_expires_unix_seconds: u64,
    pub(super) model_fingerprint: String,
    pub(super) task: Option<rpc::PublicTask>,
    pub(super) provider_keys: Vec<String>,
    pub(super) ready_rows: Vec<u16>,
    pub(super) pending_job_ids: Vec<String>,
    pub(super) planned_at_unix_seconds: u64,
}

pub(super) async fn report_ready_with_activity(
    args: &ReadyOptions,
    socket: &Path,
    activity: &watch::Receiver<bool>,
) -> Result<serde_json::Value> {
    ready_queue::report(args, socket, activity).await
}

/// One owner schedules multiple independent sources against one shared provider lease table.
/// Reservations include current unexpired work outside this admission window.
pub(super) async fn report_ready_many_with_activity(
    args: &[ReadyOptions],
    reservations: &[ReadyPending],
    socket: &Path,
    activity: &watch::Receiver<bool>,
) -> Result<Vec<Result<serde_json::Value>>> {
    ready_queue::cohort::report(args, reservations, socket, activity).await
}

pub(super) fn verify_ready_plan(
    attempt: &Path,
    source_args: &Source,
    verified: &VerifiedPublicDataset,
    expected_ready_rows: &[u16],
    pending: &[ReadyPending],
) -> Result<ReadyPlan> {
    ready_queue::verify_plan(attempt, source_args, verified, expected_ready_rows, pending)
}

#[derive(Debug, Args)]
pub(crate) struct Options {
    #[command(flatten)]
    source: Source,
    /// Explicit independently known peers. Each receives a disjoint part of this small source.
    #[arg(long, required = true, value_parser = parse_key)]
    provider_key: Vec<VerifyingKey>,
    /// New private directory; handles are retained before any Submit is sent.
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u16).range(1..=600))]
    max_seconds: u16,
    /// Without this flag there is no network I/O or remote execution.
    #[arg(long)]
    execute: bool,
    #[arg(skip)]
    task: Option<rpc::PublicTask>,
    #[arg(skip)]
    model_fingerprint: Option<String>,
    #[arg(skip)]
    allow_single_provider: bool,
    #[arg(skip)]
    executor_admission: Option<(executors::Authorization, discovery::Selected)>,
}

impl Options {
    pub(super) fn workflow(
        source: Source,
        provider_key: Vec<VerifyingKey>,
        output: PathBuf,
        max_seconds: u16,
        task: Option<rpc::PublicTask>,
    ) -> Self {
        Self {
            source,
            provider_key,
            output,
            max_seconds,
            execute: true,
            task,
            model_fingerprint: None,
            allow_single_provider: false,
            executor_admission: None,
        }
    }

    pub(super) fn with_model_fingerprint(mut self, fingerprint: Option<String>) -> Self {
        self.model_fingerprint = fingerprint;
        self
    }

    pub(super) fn allow_single_provider(mut self, enabled: bool) -> Self {
        self.allow_single_provider = enabled;
        self
    }

    pub(super) fn executor_admission(
        mut self,
        authorization: executors::Authorization,
        selected: discovery::Selected,
    ) -> Self {
        self.executor_admission = Some((authorization, selected));
        self
    }
}

/// A local record of the full status already checked on the authenticated RPC path.
/// It is not a separately signed, independently portable execution attestation.
pub(super) fn save_status(
    output: &Path,
    handle: &JobHandle,
    status: &rpc::JobStatus,
) -> Result<()> {
    let checked = job(rpc::Outcome::Job(status.clone()), handle)?;
    save_new(
        &output.join(format!("receipt-{}.json", handle.binding.job_id)),
        &serde_json::json!({"version":1,"handle":handle,"status":checked,
            "verified_at_unix_seconds":now()?}),
    )
}

pub(super) struct Prepared {
    pub(super) handle: JobHandle,
    pub(super) provider: VerifyingKey,
    pub(super) dataset_json: String,
}

#[allow(
    clippy::too_many_lines,
    reason = "One bounded public batch retains handles across admission, cancellation and exact result joining"
)]
pub(super) async fn report_with_activity(
    args: &Options,
    socket: &Path,
    activity: &watch::Receiver<bool>,
) -> Result<serde_json::Value> {
    let (publication, source) = source(&args.source)?;
    if let Some((authorization, _)) = &args.executor_admission {
        ensure!(
            authorization.publisher_key == hex::encode(args.source.publisher_key.as_bytes())
                && authorization.dataset_sha256 == sha(publication.dataset_json.as_bytes()),
            "compute_distribute_executor_source"
        );
    }
    let assignments = if args.allow_single_provider {
        assignments(source.row_count(), &args.provider_key, true)?
    } else {
        assignments_for(&source, &args.provider_key)?
    };
    if !args.execute {
        return Ok(
            serde_json::json!({"operation":"compute_distribute_plan","execute":false,
            "dataset_manifest_id":hex::encode(source.manifest_id()),"row_assignments":assignments,
            "private_data_supported":false,"model_layer_sharding":false,"new_output":args.output,
            "task":args.task}),
        );
    }
    let activity = activity.clone();
    ensure!(
        !*activity.borrow(),
        "compute_distribute_cancelled_before_submit"
    );
    // Resolve exact compatible profiles before submitting anything. Capability hints may
    // race with new work; real admission still decides and failures stay partial failures.
    let mut probes = JoinSet::new();
    for (index, provider) in args.provider_key.iter().copied().enumerate() {
        let socket = socket.to_owned();
        let activity = activity.clone();
        probes.spawn(async move {
            (
                index,
                readiness::capabilities(&socket, &provider, activity).await,
            )
        });
    }
    let mut profiles = vec![None; args.provider_key.len()];
    while let Some(result) = probes.join_next().await {
        let (index, caps) = result?;
        profiles[index] = Some(caps?);
    }
    ensure!(
        !*activity.borrow(),
        "compute_distribute_cancelled_before_submit"
    );
    let mut prepared = Vec::new();
    let mut fingerprint = args.model_fingerprint.clone();
    for (index, rows) in assignments.into_iter().enumerate() {
        let caps = profiles[index]
            .take()
            .context("compute_distribute_missing_profile")?;
        ensure!(
            caps.accepting_work && usize::from(caps.max_rows) >= rows.len(),
            "compute_distribute_peer_busy"
        );
        if let Some(expected) = &fingerprint {
            ensure!(
                expected == &caps.model_fingerprint,
                "compute_distribute_incompatible_models"
            );
        } else {
            fingerprint = Some(caps.model_fingerprint.clone());
        }
        let data = derive(&source, &rows, args.task.as_ref())?;
        let binding = binding(
            &source,
            rows,
            &data,
            &caps,
            u64::from(args.max_seconds),
            args.task.clone(),
        )?;
        prepared.push(Prepared {
            provider: args.provider_key[index],
            dataset_json: data,
            handle: JobHandle {
                version: 1,
                provider_key: hex::encode(args.provider_key[index].to_bytes()),
                binding,
                capabilities: caps,
            },
        });
    }
    super::super::private_directory(
        args.output
            .parent()
            .context("compute_distribute_output_parent")?,
    )?;
    fs::DirBuilder::new().mode(0o700).create(&args.output)?;
    if let Some((authorization, selected)) = &args.executor_admission {
        ensure!(
            selected.providers == args.provider_key
                && args.model_fingerprint.as_ref() == Some(&selected.model_fingerprint),
            "compute_distribute_executor_selection"
        );
        for work in &prepared {
            authorization.validate_handle(&source, &work.handle)?;
        }
        executors::admit(&args.output, authorization, selected)?;
    }
    for (index, work) in prepared.iter().enumerate() {
        save_new(&args.output.join(format!("job-{index}.json")), &work.handle)?;
    }
    // This is an explicitly selected public dataset. Only now are its bytes exported.
    // Every job's handle survives interruption; unreachable jobs expire at their original lease.
    let publication = Arc::new(publication);
    let mut tasks = JoinSet::new();
    for work in prepared {
        let socket = socket.to_owned();
        let source = Arc::clone(&publication);
        let activity = activity.clone();
        tasks.spawn(async move {
            let result = execute(&socket, &work, &source, activity).await;
            (work.handle, result)
        });
    }
    let mut parts = Vec::new();
    let mut outputs = vec![None; source.row_count()];
    let mut complete = true;
    while let Some(result) = tasks.join_next().await {
        let (handle, result) = result?;
        if let Ok(status) = &result {
            save_status(&args.output, &handle, status)?;
        }
        match result {
            Ok(status) if status.state == rpc::JobState::Complete => {
                let report: serde_json::Value = serde_json::from_str(
                    status
                        .report_json
                        .as_ref()
                        .context("compute_distribute_report")?,
                )?;
                let rows = report["outputs"]
                    .as_array()
                    .context("compute_distribute_rows")?;
                for (local_index, original) in handle.binding.row_indices.iter().enumerate() {
                    ensure!(
                        outputs[usize::from(*original)].is_none(),
                        "compute_distribute_duplicate_row"
                    );
                    let mut joined = serde_json::json!({"sample_index":original,
                        "provider_key":handle.provider_key,"job_id":handle.binding.job_id,
                        "text":rows[local_index]["text"]});
                    output::retain(&rows[local_index], &mut joined)?;
                    outputs[usize::from(*original)] = Some(joined);
                }
                parts.push(serde_json::json!({"handle":handle,"state":status.state,"report_sha256":status.report_sha256}));
            }
            Ok(status) => {
                complete = false;
                parts.push(serde_json::json!({"handle":handle,"state":status.state,"cancellation_requested":status.cancellation_requested,"error":status.error}));
            }
            Err(error) => {
                complete = false;
                // No upstream exception/prompt is persisted. The retained handle can be polled
                // or cancelled explicitly; failed RPC does not prove that execution stopped.
                parts.push(serde_json::json!({"handle":handle,"state":"unconfirmed","error":"COMPUTE_RPC_UNCONFIRMED",
                    "diagnostic":rpc_diagnostic(&error)}));
            }
        }
    }
    complete &= outputs.iter().all(Option::is_some);
    let answer_complete =
        complete && output::all_complete(&outputs.iter().flatten().cloned().collect::<Vec<_>>())?;
    let report = serde_json::json!({"version":1,"operation":"compute_distribute","complete":complete,
        "execution_complete":complete,"answer_complete":answer_complete,
        "dataset_manifest_id":hex::encode(source.manifest_id()),"provider_count":args.provider_key.len(),
        "outputs":outputs,"jobs":parts,"private_data_supported":false,"model_layer_sharding":false,
        "result_truthfulness_guaranteed":false,"task":args.task});
    save_new(&args.output.join("result.json"), &report)?;
    Ok(report)
}

pub(super) async fn run(args: &Options, socket: &Path) -> Result<()> {
    let cancellation = Cancellation::new()?;
    let report = report_with_activity(args, socket, &cancellation.activity).await?;
    println!("{}", serde_json::to_string(&report)?);
    ensure!(
        !args.execute || report["complete"] == true,
        "compute_distribute_incomplete_handles_retained"
    );
    Ok(())
}

pub(super) async fn execute(
    socket: &Path,
    work: &Prepared,
    publication: &rpc::PublicDataset,
    cancelled: watch::Receiver<bool>,
) -> Result<rpc::JobStatus> {
    if *cancelled.borrow() {
        anyhow::bail!("compute_distribute_cancelled_before_submit");
    }
    let submission = rpc::Operation::Submit(rpc::Submit {
        binding: work.handle.binding.clone(),
        dataset_json: work.dataset_json.clone(),
        publication: publication.clone(),
    });
    let first = exchange(socket, &work.provider, submission).await;
    // A broken Submit reply is ambiguous; poll the same retained job, never submit a new ID.
    let status = match first {
        Ok(outcome) => Some(job_in_phase(outcome, &work.handle, RpcPhase::Submit)?),
        Err(_) => None,
    };
    follow_status(socket, &work.handle, &work.provider, status, cancelled).await
}

/// Observe a previously persisted job without ever repeating its Submit.
async fn observe_existing(
    socket: &Path,
    handle: &JobHandle,
    cancelled: watch::Receiver<bool>,
) -> Result<rpc::JobStatus> {
    let provider = parse_key(&handle.provider_key).map_err(anyhow::Error::msg)?;
    let operation = if *cancelled.borrow() {
        rpc::Operation::Cancel(handle.binding.clone())
    } else {
        rpc::Operation::Poll(handle.binding.clone())
    };
    let phase = RpcPhase::of(&operation);
    let first = exchange(socket, &provider, operation).await;
    let status = match first {
        Ok(outcome) => Some(job_in_phase(outcome, handle, phase)?),
        Err(_) => None,
    };
    follow_status(socket, handle, &provider, status, cancelled).await
}

async fn follow_status(
    socket: &Path,
    handle: &JobHandle,
    provider: &VerifyingKey,
    mut status: Option<rpc::JobStatus>,
    mut cancelled: watch::Receiver<bool>,
) -> Result<rpc::JobStatus> {
    loop {
        if let Some(current) = &status {
            if current.state != rpc::JobState::Running {
                return Ok(current.clone());
            }
        }
        let cancel = *cancelled.borrow() || now()? >= handle.binding.expires_unix_seconds;
        if cancel {
            let outcome = exchange(
                socket,
                provider,
                rpc::Operation::Cancel(handle.binding.clone()),
            )
            .await?;
            return job_in_phase(outcome, handle, RpcPhase::Cancel); // Running remains explicitly nonterminal.
        }
        tokio::select! {
            () = sleep(Duration::from_secs(2)) => {},
            _ = cancelled.changed() => {},
        }
        let operation = if *cancelled.borrow() {
            rpc::Operation::Cancel(handle.binding.clone())
        } else {
            rpc::Operation::Poll(handle.binding.clone())
        };
        let phase = RpcPhase::of(&operation);
        match exchange(socket, provider, operation).await {
            Ok(outcome) => status = Some(job_in_phase(outcome, handle, phase)?),
            Err(_) if now()? < handle.binding.expires_unix_seconds => {}
            Err(error) => return Err(error),
        }
    }
}

pub(super) fn assignments_for(
    source: &VerifiedPublicDataset,
    providers: &[VerifyingKey],
) -> Result<Vec<Vec<u16>>> {
    if source.is_document() && source.row_count() == 1 && providers.len() == 1 {
        Ok(vec![vec![0]])
    } else {
        assignments(source.row_count(), providers, false)
    }
}

fn assignments(
    rows: usize,
    providers: &[VerifyingKey],
    allow_single_provider: bool,
) -> Result<Vec<Vec<u16>>> {
    let minimum = if allow_single_provider { 1 } else { 2 };
    ensure!(
        (minimum..=rows).contains(&providers.len()) && rows <= 4,
        "compute_distribute_requires_distinct_peers_and_rows"
    );
    let distinct: BTreeSet<_> = providers.iter().map(VerifyingKey::to_bytes).collect();
    ensure!(
        distinct.len() == providers.len(),
        "compute_distribute_duplicate_provider"
    );
    let mut result = vec![Vec::new(); providers.len()];
    for index in 0..rows {
        result[index % providers.len()].push(u16::try_from(index)?);
    }
    Ok(result)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn independent_rows_cover_original_exactly_once_and_require_distinct_workers() {
        let a = ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key();
        let b = ed25519_dalek::SigningKey::from_bytes(&[2; 32]).verifying_key();
        assert_eq!(
            assignments(4, &[a, b], false).unwrap(),
            vec![vec![0, 2], vec![1, 3]]
        );
        assert!(assignments(2, &[a, a], false).is_err());
        assert!(assignments(1, &[a, b], false).is_err());
        assert!(assignments(4, &[a], false).is_err());
    }

    #[test]
    fn internal_single_provider_recovery_covers_every_row_without_changing_manual_default() {
        let peer = ed25519_dalek::SigningKey::from_bytes(&[1; 32]).verifying_key();
        assert_eq!(
            assignments(4, &[peer], true).unwrap(),
            vec![vec![0, 1, 2, 3]]
        );
        assert_eq!(assignments(1, &[peer], true).unwrap(), vec![vec![0]]);
        assert!(assignments(4, &[peer], false).is_err());
        assert!(assignments(4, &[], true).is_err());
        assert!(assignments(5, &[peer], true).is_err());
        assert!(assignments(2, &[peer, peer], true).is_err());
    }
}
