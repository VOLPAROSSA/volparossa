//! Resume public independent work from retained exact handles, with explicit bounded retry.
//! An unavailable response is not proof that the previous executor stopped.

use std::{collections::BTreeSet, os::unix::fs::DirBuilderExt};

use tokio::task::JoinSet;
use volparossa_content::provider::compute::dataset::VerifiedPublicDataset;

use super::*;

#[derive(Debug, Args)]
pub(crate) struct Options {
    #[command(flatten)]
    source: Source,
    /// Exact handles retained before the original submissions; repeat for disjoint parts.
    #[arg(long, required = true)]
    handle: Vec<PathBuf>,
    /// Optional independently selected compatible peers for one retry per unfinished part.
    #[arg(long, value_parser = parse_key)]
    replacement_provider_key: Vec<VerifyingKey>,
    /// New private result directory; originals are never overwritten or silently extended.
    #[arg(long)]
    output: PathBuf,
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u16).range(1..=600))]
    max_seconds: u16,
    /// Preview source/handle bindings only unless explicitly enabled.
    #[arg(long)]
    execute: bool,
}

impl Options {
    pub(super) fn workflow(
        source: Source,
        handle: Vec<PathBuf>,
        replacement_provider_key: Vec<VerifyingKey>,
        output: PathBuf,
        max_seconds: u16,
    ) -> Self {
        Self {
            source,
            handle,
            replacement_provider_key,
            output,
            max_seconds,
            execute: true,
        }
    }
}

#[derive(Clone, Copy, Debug, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum Observation {
    Complete,
    Running,
    Stopped,
    Missing,
    Unconfirmed,
}

struct Observed {
    handle: JobHandle,
    state: Observation,
    status: Option<rpc::JobStatus>,
}

#[allow(
    clippy::too_many_lines,
    reason = "One bounded reconciliation round retains original handles, observations and replacement reports"
)]
pub(super) async fn run(args: &Options, socket: &Path) -> Result<()> {
    let (publication, source) = source(&args.source)?;
    let handles = load_handles(args, &source)?;
    let requested_rows: Vec<_> = handles
        .iter()
        .flat_map(|handle| handle.binding.row_indices.iter().copied())
        .collect();
    if !args.execute {
        println!(
            "{}",
            serde_json::json!({"operation":"compute_resume_plan","execute":false,
            "original_handles":handles,"maximum_retries_per_part":1,"new_output":args.output,
            "requested_rows":requested_rows,"private_data_supported":false})
        );
        return Ok(());
    }
    let cancellation = Cancellation::new()?;
    let activity = cancellation.activity.clone();
    super::super::private_directory(
        args.output
            .parent()
            .context("compute_resume_output_parent")?,
    )?;
    fs::DirBuilder::new().mode(0o700).create(&args.output)?;
    for (index, handle) in handles.iter().enumerate() {
        save_new(&args.output.join(format!("original-{index}.json")), handle)?;
    }
    let observations = observe_all(socket, handles).await?;
    let mut used = BTreeSet::new();
    let mut jobs = Vec::new();
    let mut outputs = Vec::new();
    let mut retries = JoinSet::new();
    let mut unfinished = 0;
    for (index, observed) in observations.into_iter().enumerate() {
        if let Some(status) = &observed.status {
            batch::save_status(&args.output, &observed.handle, status)?;
        }
        save_new(
            &args.output.join(format!("observation-{index}.json")),
            &serde_json::json!({
            "handle":observed.handle,"state":observed.state,"status":observed.status}),
        )?;
        if observed.state == Observation::Complete {
            let status = observed
                .status
                .context("compute_resume_complete_report_missing")?;
            append_outputs(&mut outputs, &observed.handle, &status)?;
            jobs.push(
                serde_json::json!({"handle":observed.handle,"state":"complete","retried":false}),
            );
            continue;
        }
        if !retry_allowed(
            observed.state,
            observed.handle.binding.expires_unix_seconds,
            now()?,
        ) || *activity.borrow()
        {
            unfinished += 1;
            jobs.push(serde_json::json!({"handle":observed.handle,"state":observed.state,"retried":false}));
            continue;
        }
        let Some(work) = replacement(socket, args, &source, &observed.handle, &mut used).await?
        else {
            unfinished += 1;
            jobs.push(serde_json::json!({"handle":observed.handle,"state":observed.state,"retried":false,"reason":"NO_COMPATIBLE_IDLE_REPLACEMENT"}));
            continue;
        };
        // The original lease remains immutable. This is an explicit new attempt with a new
        // ID and bounded lifetime, not a disguised TTL extension or success from absence.
        save_new(&args.output.join(format!("job-{index}.json")), &work.handle)?;
        let original = observed.handle;
        let original_state = observed.state;
        let public = publication.clone();
        let socket = socket.to_owned();
        let cancelled = activity.clone();
        retries.spawn(async move {
            let result = batch::execute(&socket, &work, &public, cancelled).await;
            (index, original, original_state, work.handle, result)
        });
    }
    while let Some(result) = retries.join_next().await {
        let (index, original, original_state, handle, result) = result?;
        let status = result.ok();
        if let Some(status) = &status {
            batch::save_status(&args.output, &handle, status)?;
        }
        if let Some(complete) = status
            .as_ref()
            .filter(|value| value.state == rpc::JobState::Complete)
        {
            append_outputs(&mut outputs, &handle, complete)?;
        } else {
            unfinished += 1;
        }
        let part = serde_json::json!({"original_handle":original,"original_state":original_state,
            "handle":handle,"status":status,"retried":true,"prior_terminal_receipt_received":original_state == Observation::Stopped});
        save_new(&args.output.join(format!("retry-{index}.json")), &part)?;
        jobs.push(part);
    }
    outputs.sort_by_key(|output| output["sample_index"].as_u64());
    let report = serde_json::json!({"version":1,"operation":"compute_resume","complete":unfinished == 0,
        "dataset_manifest_id":hex::encode(source.manifest_id()),"outputs":outputs,"jobs":jobs,
        "maximum_retries_per_part":1,"exactly_once_execution_guaranteed":false,
        "requested_rows":requested_rows,"full_dataset_requested":requested_rows.len() == source.row_count(),
        "private_data_supported":false,"result_truthfulness_guaranteed":false});
    save_new(&args.output.join("result.json"), &report)?;
    println!("{}", serde_json::to_string(&report)?);
    ensure!(
        unfinished == 0,
        "compute_resume_incomplete_handles_retained"
    );
    Ok(())
}

pub(super) fn load_handles(
    args: &Options,
    source: &VerifiedPublicDataset,
) -> Result<Vec<JobHandle>> {
    ensure!(
        (1..=4).contains(&args.handle.len()) && args.replacement_provider_key.len() <= 4,
        "compute_resume_batch_bound"
    );
    let unique: BTreeSet<_> = args
        .replacement_provider_key
        .iter()
        .map(VerifyingKey::to_bytes)
        .collect();
    ensure!(
        unique.len() == args.replacement_provider_key.len(),
        "compute_resume_duplicate_replacement"
    );
    let mut handles = Vec::new();
    let mut covered = BTreeSet::new();
    for path in &args.handle {
        let handle: JobHandle = serde_json::from_slice(&read_file(path, 16 * 1024)?)?;
        parse_key(&handle.provider_key).map_err(anyhow::Error::msg)?;
        let rows = &handle.binding.row_indices;
        ensure!(
            handle.version == 1
                && handle.binding.dataset_manifest_id == hex::encode(source.manifest_id())
                && handle.binding.dataset_sha256 == sha(source.derive(rows)?.as_bytes())
                && handle.binding.expires_unix_seconds <= source.expires()
                && handle.binding.model_fingerprint == handle.capabilities.model_fingerprint
                && handle.binding.model_fingerprint
                    == sha(&serde_json::to_vec(&handle.capabilities.model)?),
            "compute_resume_original_binding"
        );
        ensure!(
            rows.iter().all(|row| covered.insert(*row)),
            "compute_resume_overlapping_rows"
        );
        handles.push(handle);
    }
    Ok(handles)
}

async fn observe_all(socket: &Path, handles: Vec<JobHandle>) -> Result<Vec<Observed>> {
    let mut tasks = JoinSet::new();
    for handle in handles {
        let socket = socket.to_owned();
        tasks.spawn(async move {
            let provider = parse_key(&handle.provider_key).map_err(anyhow::Error::msg)?;
            let reply = exchange(
                &socket,
                &provider,
                rpc::Operation::Poll(handle.binding.clone()),
            )
            .await;
            let (state, status) = match reply {
                Ok(rpc::Outcome::Job(status)) => {
                    let status = job(rpc::Outcome::Job(status), &handle)?;
                    let state = match status.state {
                        rpc::JobState::Complete => Observation::Complete,
                        rpc::JobState::Running => Observation::Running,
                        rpc::JobState::Cancelled | rpc::JobState::Failed => Observation::Stopped,
                    };
                    (state, Some(status))
                }
                Ok(rpc::Outcome::Error(rpc::ErrorCode::Missing)) => (Observation::Missing, None),
                _ => (Observation::Unconfirmed, None),
            };
            Ok::<_, anyhow::Error>(Observed {
                handle,
                state,
                status,
            })
        });
    }
    let mut observed = Vec::new();
    while let Some(result) = tasks.join_next().await {
        observed.push(result??);
    }
    observed.sort_by_key(|part| part.handle.binding.row_indices[0]);
    Ok(observed)
}

fn retry_allowed(state: Observation, expiry: u64, time: u64) -> bool {
    match state {
        Observation::Stopped | Observation::Missing => true,
        // Wait out an ambiguous lease; expiry is not reported as observed termination.
        Observation::Unconfirmed => time >= expiry,
        Observation::Running | Observation::Complete => false,
    }
}

async fn replacement(
    socket: &Path,
    args: &Options,
    source: &VerifiedPublicDataset,
    original: &JobHandle,
    used: &mut BTreeSet<[u8; 32]>,
) -> Result<Option<batch::Prepared>> {
    for provider in &args.replacement_provider_key {
        if used.contains(&provider.to_bytes()) {
            continue;
        }
        let Ok(caps) = capabilities(socket, provider).await else {
            continue;
        };
        if !caps.accepting_work
            || caps.model_fingerprint != original.binding.model_fingerprint
            || usize::from(caps.max_rows) < original.binding.row_indices.len()
        {
            continue;
        }
        let data = source.derive(&original.binding.row_indices)?;
        let binding = binding(
            source,
            original.binding.row_indices.clone(),
            &data,
            &caps,
            u64::from(args.max_seconds),
        )?;
        used.insert(provider.to_bytes());
        return Ok(Some(batch::Prepared {
            provider: *provider,
            dataset_json: data,
            handle: JobHandle {
                version: 1,
                provider_key: hex::encode(provider.to_bytes()),
                binding,
                capabilities: caps,
            },
        }));
    }
    Ok(None)
}

fn append_outputs(
    outputs: &mut Vec<serde_json::Value>,
    handle: &JobHandle,
    status: &rpc::JobStatus,
) -> Result<()> {
    let report: serde_json::Value = serde_json::from_str(
        status
            .report_json
            .as_ref()
            .context("compute_resume_report")?,
    )?;
    let returned = report["outputs"]
        .as_array()
        .context("compute_resume_outputs")?;
    for (index, original) in handle.binding.row_indices.iter().enumerate() {
        ensure!(
            !outputs
                .iter()
                .any(|output| output["sample_index"] == *original),
            "compute_resume_duplicate_result"
        );
        outputs.push(
            serde_json::json!({"sample_index":original,"text":returned[index]["text"],
            "provider_key":handle.provider_key,"job_id":handle.binding.job_id}),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::PermissionsExt;
    use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity, publish};

    #[test]
    fn unresolved_active_leases_and_completed_work_are_not_reassigned() {
        assert!(!retry_allowed(Observation::Running, 100, 200));
        assert!(!retry_allowed(Observation::Complete, 100, 200));
        assert!(!retry_allowed(Observation::Unconfirmed, 100, 99));
        assert!(retry_allowed(Observation::Unconfirmed, 100, 100));
        assert!(retry_allowed(Observation::Stopped, 100, 99));
        assert!(retry_allowed(Observation::Missing, 100, 99));
    }

    #[test]
    fn persisted_handles_retain_exact_signed_source_and_reject_overlapping_work() {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let key = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
        let json = serde_json::json!({"version":1,"visibility":"public","license":"GPL-3.0-only",
            "source_revision":"a".repeat(40),"train":[],
            "heldout":[{"question":"What is tested?","context":"A public protocol fixture.","answer":"Handle provenance."}],
            "inference":[{"question":"First?","context":"First public input."},{"question":"Second?","context":"Second public input."}]
        }).to_string();
        let at = now().unwrap();
        let mut cache = ChunkStore::create(
            &root.path().join("cache"),
            CacheLimits {
                max_bytes: 1024 * 1024,
                max_entries: 8,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let signed = publish(
            &mut json.as_bytes(),
            Publication {
                metadata: Metadata {
                    name: "resume-fixture".into(),
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
            &key,
            &mut cache,
        )
        .unwrap();
        let source = verify_source(&signed.encode(), &key.verifying_key(), &json, at).unwrap();
        // This metadata binds a protocol fixture; no model is run or declared successful.
        let model = rpc::ModelIdentity {
            model_id: "fixture".into(),
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
        };
        let handle = JobHandle {
            version: 1,
            provider_key: hex::encode(key.verifying_key().as_bytes()),
            binding: binding(&source, vec![1], &source.derive(&[1]).unwrap(), &caps, 600).unwrap(),
            capabilities: caps,
        };
        let path = root.path().join("handle.json");
        save_new(&path, &handle).unwrap();
        let mut args = Options {
            source: Source {
                dataset: root.path().join("data"),
                dataset_manifest: root.path().join("manifest"),
                publisher_key: key.verifying_key(),
            },
            handle: vec![path.clone()],
            replacement_provider_key: vec![],
            output: root.path().join("output"),
            max_seconds: 600,
            execute: false,
        };
        let loaded = load_handles(&args, &source).unwrap();
        assert_eq!(loaded[0].binding, handle.binding);
        args.handle.push(path);
        assert!(load_handles(&args, &source).is_err());
        args.handle.pop();
        let mut altered = handle;
        altered.binding.row_indices = vec![0];
        let wrong = root.path().join("altered.json");
        save_new(&wrong, &altered).unwrap();
        args.handle = vec![wrong];
        assert!(load_handles(&args, &source).is_err());
    }
}
