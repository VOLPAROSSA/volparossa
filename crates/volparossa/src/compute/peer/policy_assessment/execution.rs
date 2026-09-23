//! Four exact single-row jobs; retained handles are observed, never recreated on resume.

use super::super::{JobHandle, Source};
use super::*;

pub(super) struct Stage {
    name: String,
    state: &'static str,
    execution_complete: bool,
    pub(super) answer: Option<(String, assessment::Evidence)>,
}

impl Stage {
    pub(super) fn summary(&self, valid: bool) -> Value {
        json!({"stage":self.name,"state":self.state,"execution_complete":self.execution_complete,
            "answer_complete":self.answer.is_some(),"structured_judgment_valid":valid})
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "One exact stage binds its selected assessor, immutable context and original cancellation owner"
)]
pub(super) async fn run(
    args: &Options,
    socket: &Path,
    enrolled: &Enrollment,
    name: &str,
    index: usize,
    context: &str,
    question: &str,
    cancelled: &watch::Receiver<bool>,
) -> Result<Stage> {
    let mut stage = Stage {
        name: name.into(),
        state: "not_submitted",
        execution_complete: false,
        answer: None,
    };
    let stage_root = args.output.join(name);
    if !storage::exists(&stage_root)? && (*cancelled.borrow() || now()? >= enrolled.expires) {
        stage.state = "cancelled_or_source_expired";
        return Ok(stage);
    }
    let source = storage::prepare(args, enrolled, name, context, question)?;
    let work = stage_root.join("work");
    let handle_path = work.join("job-0.json");
    if !storage::exists(&handle_path)? {
        if *cancelled.borrow() || now()? >= enrolled.expires {
            stage.state = "cancelled_or_source_expired";
            return Ok(stage);
        }
        // A crash after directory creation but before handle persistence has no Submit authority.
        // Fail closed rather than inventing a replacement attempt in a partially written directory.
        if storage::exists(&work)? {
            stage.state = "pre_submit_interrupted";
            return Ok(stage);
        }
        let options = batch::Options::workflow(
            source.clone(),
            vec![parse_key(&enrolled.providers[index]).map_err(anyhow::Error::msg)?],
            work.clone(),
            enrolled.max_seconds,
            None,
        )
        .with_model_fingerprint(Some(enrolled.model_fingerprints[index].clone()))
        .allow_single_provider(true);
        let submitted = batch::report_with_activity(&options, socket, cancelled).await;
        if !storage::exists(&handle_path)? {
            stage.state = "preflight_unavailable";
            return Ok(stage);
        }
        // The durable handle, not success of the transport or aggregate result, controls replay.
        if submitted.is_err() {
            stage.state = "submission_unconfirmed";
        }
    }
    let handle = load_handle(&handle_path, enrolled, index, &source)?;
    let mut status = receipts(&stage_root, &handle, enrolled.selected_at)?;
    if status
        .as_ref()
        .is_none_or(|value| value.state == rpc::JobState::Running)
        && now()? < handle.binding.expires_unix_seconds
    {
        let poll = (0..32)
            .map(|index| stage_root.join(format!("poll-{index:02}")))
            .find_map(|path| match storage::exists(&path) {
                Ok(false) => Some(Ok(path)),
                Ok(true) => None,
                Err(error) => Some(Err(error)),
            })
            .transpose()?
            .context("compute_policy_observation_bound")?;
        storage::directory(&poll)?;
        match batch::observe_existing(socket, &handle, cancelled.clone()).await {
            Ok(observed) => {
                batch::save_status(&poll, &handle, &observed)?;
                status = Some(observed);
            }
            Err(_) => {
                stage.state = "observation_unconfirmed";
            }
        }
    }
    let Some(status) = status else {
        stage.state = "unconfirmed_original_handle";
        return Ok(stage);
    };
    stage.state = match status.state {
        rpc::JobState::Running => "running_or_unconfirmed",
        rpc::JobState::Failed => "failed",
        rpc::JobState::Cancelled => "cancelled",
        rpc::JobState::Complete => "complete",
    };
    if status.state != rpc::JobState::Complete {
        return Ok(stage);
    }
    if enrolled.portable_receipts {
        let proof_path = stage_root.join("provider-transcript.json");
        if !storage::exists(&proof_path)? {
            if *cancelled.borrow() || now()? >= handle.binding.expires_unix_seconds {
                stage.state = "original_signed_receipt_unavailable";
                return Ok(stage);
            }
            let proof = super::super::transcript::poll(socket, &handle).await?;
            ensure!(
                proof.check(&handle, enrolled.selected_at, &proof.requester_key)? == status,
                "compute_policy_signed_status_changed"
            );
            storage::save(&proof_path, &proof)?;
        }
        check_proof(&stage_root, enrolled, &handle, &status, None)?;
    }
    completed(stage, handle, status, enrolled, question)
}

fn check_proof(
    root: &Path,
    enrolled: &Enrollment,
    handle: &JobHandle,
    status: &rpc::JobStatus,
    requester: Option<&str>,
) -> Result<()> {
    let proof: super::super::transcript::Retained = serde_json::from_slice(&storage::read(
        &root.join("provider-transcript.json"),
        256 * 1024,
    )?)?;
    ensure!(
        proof.check(
            handle,
            enrolled.selected_at,
            requester.unwrap_or(&proof.requester_key)
        )? == *status,
        "compute_policy_signed_status_changed"
    );
    Ok(())
}

/// Offline-only replay; it has neither a socket nor a submit capability.
pub(super) fn replay(
    root: &Path,
    enrolled: &Enrollment,
    name: &str,
    index: usize,
    context: &str,
    question: &str,
    requester: &str,
) -> Result<Stage> {
    let stage_root = root.join(name);
    let source = storage::check_stage(&stage_root, enrolled, context, question)?;
    let handle = load_handle(
        &stage_root.join("work/job-0.json"),
        enrolled,
        index,
        &source,
    )?;
    let status = receipts(&stage_root, &handle, enrolled.selected_at)?
        .context("compute_policy_missing_terminal_receipt")?;
    ensure!(
        enrolled.portable_receipts && status.state == rpc::JobState::Complete,
        "compute_policy_portable_complete_required"
    );
    check_proof(&stage_root, enrolled, &handle, &status, Some(requester))?;
    completed(
        Stage {
            name: name.into(),
            state: "complete",
            execution_complete: false,
            answer: None,
        },
        handle,
        status,
        enrolled,
        question,
    )
}

fn completed(
    mut stage: Stage,
    handle: JobHandle,
    status: rpc::JobStatus,
    enrolled: &Enrollment,
    question: &str,
) -> Result<Stage> {
    stage.execution_complete = true;
    let report: Value = serde_json::from_str(
        status
            .report_json
            .as_deref()
            .context("compute_policy_report")?,
    )?;
    let outputs = report["outputs"]
        .as_array()
        .context("compute_policy_output_array")?;
    ensure!(outputs.len() == 1, "compute_policy_single_output");
    let expected = enrolled.output_contract(question)?;
    let generation = crate::compute::inference_output::Generation::from_output(&outputs[0], true)?
        .context("compute_policy_generation")?;
    ensure!(
        generation.output_contract == expected,
        "compute_policy_output_contract"
    );
    let ending = batch::output::status(&outputs[0])?;
    if ending != "eos" && !(expected.is_some() && ending == "json_boundary") {
        stage.state = "answer_incomplete";
        return Ok(stage);
    }
    stage.answer = Some((
        outputs[0]["text"]
            .as_str()
            .context("compute_policy_text")?
            .into(),
        assessment::Evidence {
            provider_key: handle.provider_key,
            job_id: handle.binding.job_id,
            report_sha256: status.report_sha256.context("compute_policy_report_hash")?,
            model_fingerprint: handle.binding.model_fingerprint,
            package_manifest_id: handle.binding.dataset_manifest_id,
        },
    ));
    Ok(stage)
}

fn load_handle(
    path: &Path,
    enrolled: &Enrollment,
    index: usize,
    source: &Source,
) -> Result<JobHandle> {
    let handle: JobHandle = serde_json::from_slice(&storage::read(path, 32 * 1024)?)?;
    super::super::validate_profile(&handle.capabilities)?;
    let dataset = String::from_utf8(storage::read(
        &source.dataset,
        rpc::MAX_DATASET_BYTES as u64,
    )?)?;
    let verified = volparossa_content::provider::compute::dataset::verify_source(
        &storage::read(&source.dataset_manifest, 64 * 1024)?,
        &source.publisher_key,
        &dataset,
        enrolled.selected_at,
    )?;
    ensure!(
        handle.version == 1
            && handle.provider_key == enrolled.providers[index]
            && handle.binding.model_fingerprint == enrolled.model_fingerprints[index]
            && handle.capabilities.model_fingerprint == handle.binding.model_fingerprint
            && crate::compute::broker::profile_for_model(&handle.capabilities.model)?
                == enrolled.profile()?
            && if enrolled.version == 1 {
                handle.capabilities.document_inference_v2
            } else {
                handle.capabilities.principle_inference_v4
            }
            && handle.binding.row_indices == [0]
            && handle.binding.task.is_none()
            && handle.binding.dataset_manifest_id == hex::encode(verified.manifest_id())
            && handle.binding.dataset_sha256 == sha(verified.derive(&[0])?.as_bytes())
            && handle.binding.expires_unix_seconds <= enrolled.expires
            && handle.binding.expires_unix_seconds > enrolled.selected_at,
        "compute_policy_original_handle_binding"
    );
    ensure!(
        rpc::nonzero_hex(&handle.binding.job_id, 32),
        "compute_policy_job_id"
    );
    Ok(handle)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    version: u32,
    handle: JobHandle,
    status: rpc::JobStatus,
    verified_at_unix_seconds: u64,
}

fn receipts(root: &Path, handle: &JobHandle, selected_at: u64) -> Result<Option<rpc::JobStatus>> {
    let mut current: Option<rpc::JobStatus> = None;
    let directories = std::iter::once(root.join("work"))
        .chain((0..32).map(|index| root.join(format!("poll-{index:02}"))));
    for directory in directories {
        let path = directory.join(format!("receipt-{}.json", handle.binding.job_id));
        if !storage::exists(&path)? {
            continue;
        }
        let receipt: Receipt = serde_json::from_slice(&storage::read(
            &path,
            (rpc::MAX_REPORT_BYTES + 64 * 1024) as u64,
        )?)?;
        ensure!(
            receipt.version == 1
                && receipt.verified_at_unix_seconds >= selected_at
                && serde_json::to_value(&receipt.handle)? == serde_json::to_value(handle)?,
            "compute_policy_retained_receipt_binding"
        );
        let checked = super::super::job(rpc::Outcome::Job(receipt.status), handle)?;
        if let Some(previous) = &current {
            ensure!(
                previous.state == rpc::JobState::Running || previous == &checked,
                "compute_policy_terminal_receipt_changed"
            );
        }
        current = Some(checked);
    }
    Ok(current)
}
