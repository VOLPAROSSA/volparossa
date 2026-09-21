//! One isolated model proposal, pinned before graph enrollment; never execution authority by itself.

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::watch;

use crate::compute::{self, task_plan};

use super::{Input, Options, Path, digest, plan, read_file, save, task};

const MAX_PLANNER_BYTES: usize = 16 * 1024;
const MAX_REPORT_BYTES: usize = 64 * 1024;
const PLANNING_KIND: &str = "bounded_model_fork_join_decomposition";

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Authority {
    version: u32,
    input_sha256: String,
    report_sha256: String,
    artifact_sha256: String,
    question: String,
    source_sha256: String,
    source_bytes: u64,
}

fn proposal(input: &task_plan::Input, questions: &task_plan::Questions) -> Result<plan::Plan> {
    input.validate()?;
    questions.validate()?;
    let mut nodes: Vec<_> = questions
        .questions
        .iter()
        .enumerate()
        .map(|(index, question)| plan::Node {
            id: format!("question-{index:02}"),
            question: question.clone(),
            depends_on: Vec::new(),
        })
        .collect();
    let parents = nodes.iter().map(|node| node.id.clone()).collect();
    nodes.push(plan::Node {
        id: "answer".into(),
        question: input.question.clone(),
        depends_on: parents,
    });
    let plan = plan::Plan {
        version: 1,
        nodes,
        output: "answer".into(),
    };
    plan.validate()?;
    Ok(plan)
}

fn checked_input(args: &Options, document: &str) -> Result<task_plan::Input> {
    // Goal-only planning still binds the exact selected source. It neither reads
    // the source content in the model prompt nor authorizes different sources.
    let input = Input {
        version: 1,
        synthesis: false,
        visibility: "public".into(),
        license: args.license.clone().context("compute_document_license")?,
        question: args
            .public_question
            .clone()
            .context("compute_document_question")?,
        document: document.into(),
    };
    input.validate()?;
    let input = task_plan::Input {
        version: 1,
        visibility: input.visibility,
        license: input.license,
        question: input.question,
        source_sha256: digest(document.as_bytes()),
        source_bytes: document.len() as u64,
    };
    input.validate()?;
    Ok(input)
}

pub(super) async fn prepare(
    args: &Options,
    document: &str,
    cancelled: &watch::Receiver<bool>,
) -> Result<(plan::Plan, Authority)> {
    ensure!(
        args.plan_tasks && args.public_content && !args.synthesize && !args.batch_barrier,
        "compute_task_planner_explicit_public_mode_required"
    );
    ensure!(!*cancelled.borrow(), "compute_task_planner_cancelled");
    let input = checked_input(args, document)?;
    let bytes = serde_json::to_vec(&input)?;
    ensure!(
        bytes.len() <= MAX_PLANNER_BYTES,
        "compute_task_planner_input_size"
    );
    task::write_bytes(&args.directory.join("planner-input.json"), &bytes, false)?;
    let output = args.directory.join("model-planner");
    let options = compute::Options {
        mode: compute::Mode::PlanTasks,
        runtime_root: args
            .runtime_root
            .clone()
            .context("compute_document_runtime")?,
        model_root: args.model_root.clone().context("compute_document_model")?,
        adapter_root: None,
        dataset: args.directory.join("planner-input.json"),
        output: output.clone(),
        steps: 1,
        threads: args.threads,
        max_seconds: args.max_seconds,
        spare_capacity: true,
        execute: true,
    };
    options.validate()?;
    let (owner, idle) = watch::channel(!*cancelled.borrow());
    let mut receiver = cancelled.clone();
    let bridge = tokio::spawn(async move {
        while !*receiver.borrow() {
            if receiver.changed().await.is_err() {
                break;
            }
        }
        let _ = owner.send(false);
    });
    // Exactly one worker invocation and owner deadline. Its bounded generation
    // retries share the original token budget; a terminal failure never replans.
    let report = compute::execute(&options, idle).await;
    bridge.abort();
    let report = match report {
        Ok(report) => report,
        Err(error) => {
            retain_failure(&args.directory, &input, &bytes, &error)?;
            return Err(error);
        }
    };
    save(&args.directory, "planner-report.json", &report, false)?;
    let artifact = read_file(&output.join("task-questions.json"), MAX_PLANNER_BYTES)?;
    let questions = task_plan::validate_report(&report, &input, &bytes, &artifact)?;
    ensure!(!*cancelled.borrow(), "compute_task_planner_cancelled");
    let plan = proposal(&input, &questions)?;
    task::write_bytes(
        &args.directory.join("planner-artifact.json"),
        &artifact,
        false,
    )?;
    let authority = Authority {
        version: 1,
        input_sha256: digest(&bytes),
        report_sha256: digest(&read_file(
            &args.directory.join("planner-report.json"),
            MAX_REPORT_BYTES,
        )?),
        artifact_sha256: digest(&artifact),
        question: input.question,
        source_sha256: input.source_sha256,
        source_bytes: input.source_bytes,
    };
    Ok((plan, authority))
}

fn retain_failure(
    root: &Path,
    input: &task_plan::Input,
    bytes: &[u8],
    error: &anyhow::Error,
) -> Result<()> {
    // WorkerFailure is exposed only after the exact child has been reaped. Neither
    // generic supervisor errors nor a string resembling a worker reply prove that.
    let Some(failure) = error.downcast_ref::<compute::supervise::WorkerFailure>() else {
        return Ok(());
    };
    let Some(diagnostic) = failure.planner_diagnostic() else {
        return Ok(());
    };
    save(
        root,
        "planner-failure.json",
        &json!({
            "version":1,"operation":"compute_public_task_planning_failure",
            "request_id":failure.request_id(),"code":failure.code(),
            "input_sha256":digest(bytes),"source_sha256":input.source_sha256,
            "source_bytes":input.source_bytes,"planner_diagnostic":diagnostic,
            "child_reaped":true,"plan_enrolled":false
        }),
        false,
    )
}

fn verify_input(authority: &Authority, input: &task_plan::Input, source: &Input) -> Result<()> {
    input.validate()?;
    source.validate()?;
    ensure!(
        authority.version == 1
            && input.question == authority.question
            && input.license == source.license
            && input.source_sha256 == authority.source_sha256
            && input.source_sha256 == digest(source.document.as_bytes())
            && input.source_bytes == authority.source_bytes
            && input.source_bytes == source.document.len() as u64,
        "compute_task_planner_original_question_or_source_changed"
    );
    Ok(())
}

pub(super) fn verify(
    root: &Path,
    authority: &Authority,
    plan: &plan::Plan,
    source: &Input,
) -> Result<()> {
    let bytes = read_file(&root.join("planner-input.json"), MAX_PLANNER_BYTES)?;
    let report_bytes = read_file(&root.join("planner-report.json"), MAX_REPORT_BYTES)?;
    let artifact = read_file(&root.join("planner-artifact.json"), MAX_PLANNER_BYTES)?;
    ensure!(
        digest(&bytes) == authority.input_sha256
            && digest(&report_bytes) == authority.report_sha256
            && digest(&artifact) == authority.artifact_sha256,
        "compute_task_planner_retained_files_changed"
    );
    let input = task_plan::Input::decode(&bytes)?;
    verify_input(authority, &input, source)?;
    let report: Value = serde_json::from_slice(&report_bytes)?;
    let questions = task_plan::validate_report(&report, &input, &bytes, &artifact)?;
    ensure!(
        proposal(&input, &questions)? == *plan,
        "compute_task_planner_enrolled_plan_changed"
    );
    Ok(())
}

pub(super) fn verify_absent(root: &Path) -> Result<()> {
    for name in [
        "planner-input.json",
        "planner-report.json",
        "planner-artifact.json",
        "planner-failure.json",
        "model-planner",
    ] {
        ensure!(
            !root.join(name).try_exists()?,
            "compute_task_planner_authority_missing"
        );
    }
    Ok(())
}

pub(super) fn summary(authority: Option<&Authority>) -> Value {
    authority.map_or(Value::Null, |authority| {
        json!({"kind":PLANNING_KIND,"authority":authority,"goal_only":true,
            "source_contents_read_by_planner":false,"model_selected_tools":false,
            "decomposition_quality_proven":false})
    })
}

#[cfg(test)]
mod tests;
