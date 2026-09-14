//! Concurrent independent inference rows, not distributed model layers or a general planner.

use std::{collections::BTreeSet, os::unix::fs::DirBuilderExt, sync::Arc};

use tokio::{sync::watch, task::JoinSet, time::sleep};

use super::*;

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
}

struct Prepared {
    handle: JobHandle,
    provider: VerifyingKey,
    dataset_json: String,
}

#[allow(
    clippy::too_many_lines,
    reason = "One bounded public batch retains handles across admission, cancellation and exact result joining"
)]
pub(super) async fn run(args: &Options, socket: &Path) -> Result<()> {
    let (publication, source) = source(&args.source)?;
    let assignments = assignments(source.row_count(), &args.provider_key)?;
    if !args.execute {
        println!(
            "{}",
            serde_json::json!({"operation":"compute_distribute_plan","execute":false,
            "dataset_manifest_id":hex::encode(source.manifest_id()),"row_assignments":assignments,
            "private_data_supported":false,"model_layer_sharding":false,"new_output":args.output})
        );
        return Ok(());
    }
    // Resolve exact compatible profiles before submitting anything. Capability hints may
    // race with new work; real admission still decides and failures stay partial failures.
    let mut probes = JoinSet::new();
    for (index, provider) in args.provider_key.iter().copied().enumerate() {
        let socket = socket.to_owned();
        probes.spawn(async move { (index, capabilities(&socket, &provider).await) });
    }
    let mut profiles = vec![None; args.provider_key.len()];
    while let Some(result) = probes.join_next().await {
        let (index, caps) = result?;
        profiles[index] = Some(caps?);
    }
    let mut prepared = Vec::new();
    let mut fingerprint = None;
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
        let data = source.derive(&rows)?;
        let binding = binding(&source, rows, &data, &caps, u64::from(args.max_seconds))?;
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
    for (index, work) in prepared.iter().enumerate() {
        save_new(&args.output.join(format!("job-{index}.json")), &work.handle)?;
    }
    // This is an explicitly selected public dataset. Only now are its bytes exported.
    // Every job's handle survives interruption; unreachable jobs expire at their original lease.
    let (stop, activity) = watch::channel(false);
    let interrupt = tokio::spawn(async move {
        let _ = tokio::signal::ctrl_c().await;
        let _ = stop.send(true);
    });
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
                    outputs[usize::from(*original)] =
                        Some(serde_json::json!({"sample_index":original,
                        "provider_key":handle.provider_key,"job_id":handle.binding.job_id,
                        "text":rows[local_index]["text"]}));
                }
                parts.push(serde_json::json!({"handle":handle,"state":status.state,"report_sha256":status.report_sha256}));
            }
            Ok(status) => {
                complete = false;
                parts.push(serde_json::json!({"handle":handle,"state":status.state,"cancellation_requested":status.cancellation_requested,"error":status.error}));
            }
            Err(_) => {
                complete = false;
                // No upstream exception/prompt is persisted. The retained handle can be polled
                // or cancelled explicitly; failed RPC does not prove that execution stopped.
                parts.push(serde_json::json!({"handle":handle,"state":"unconfirmed","error":"COMPUTE_RPC_UNCONFIRMED"}));
            }
        }
    }
    interrupt.abort();
    complete &= outputs.iter().all(Option::is_some);
    let report = serde_json::json!({"version":1,"operation":"compute_distribute","complete":complete,
        "dataset_manifest_id":hex::encode(source.manifest_id()),"provider_count":args.provider_key.len(),
        "outputs":outputs,"jobs":parts,"private_data_supported":false,"model_layer_sharding":false,
        "result_truthfulness_guaranteed":false});
    save_new(&args.output.join("result.json"), &report)?;
    println!("{}", serde_json::to_string(&report)?);
    ensure!(complete, "compute_distribute_incomplete_handles_retained");
    Ok(())
}

async fn execute(
    socket: &Path,
    work: &Prepared,
    publication: &rpc::PublicDataset,
    mut cancelled: watch::Receiver<bool>,
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
    let mut status = match first {
        Ok(outcome) => Some(job(outcome, &work.handle)?),
        Err(_) => None,
    };
    loop {
        if let Some(current) = &status {
            if current.state != rpc::JobState::Running {
                return Ok(current.clone());
            }
        }
        let cancel = *cancelled.borrow() || now()? >= work.handle.binding.expires_unix_seconds;
        if cancel {
            let outcome = exchange(
                socket,
                &work.provider,
                rpc::Operation::Cancel(work.handle.binding.clone()),
            )
            .await?;
            return job(outcome, &work.handle); // Running remains explicitly nonterminal.
        }
        tokio::select! {
            () = sleep(Duration::from_secs(2)) => {},
            _ = cancelled.changed() => {},
        }
        let operation = if *cancelled.borrow() {
            rpc::Operation::Cancel(work.handle.binding.clone())
        } else {
            rpc::Operation::Poll(work.handle.binding.clone())
        };
        match exchange(socket, &work.provider, operation).await {
            Ok(outcome) => status = Some(job(outcome, &work.handle)?),
            Err(_) if now()? < work.handle.binding.expires_unix_seconds => {}
            Err(error) => return Err(error),
        }
    }
}

fn assignments(rows: usize, providers: &[VerifyingKey]) -> Result<Vec<Vec<u16>>> {
    ensure!(
        (2..=rows).contains(&providers.len()) && rows <= 4,
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
            assignments(4, &[a, b]).unwrap(),
            vec![vec![0, 2], vec![1, 3]]
        );
        assert!(assignments(2, &[a, a]).is_err());
        assert!(assignments(1, &[a, b]).is_err());
        assert!(assignments(4, &[a]).is_err());
    }
}
