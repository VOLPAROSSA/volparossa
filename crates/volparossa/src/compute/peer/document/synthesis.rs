//! Hierarchical public peer inference. Intermediate answers are not original excerpts.

mod storage;

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::watch;

use super::storage as document_storage;
use super::{Options, now, parse_key, private_directory, rpc, workflow};
use std::path::Path;

const MAX_LEVELS: u16 = 16;
const PARENTS_PER_GROUP: usize = 64;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Answer {
    text: String,
    provider_key: String,
    job_id: String,
    report_sha256: String,
    package_manifest_id: String,
    model_fingerprint: String,
    output_index: u16,
    source_start: u64,
    source_end: u64,
    generated_tokens: u16,
    text_truncated: bool,
}

impl Answer {
    fn from_output(output: &Value, manifest: &str, start: u64, end: u64) -> Result<Self> {
        let answer: Self = serde_json::from_value(json!({
            "text":output["text"],"provider_key":output["provider_key"],
            "job_id":output["job_id"],"report_sha256":output["report_sha256"],
            "package_manifest_id":manifest,"model_fingerprint":output["model_fingerprint"],
            "output_index":output["output_index"],"source_start":start,"source_end":end,
            "generated_tokens":output["generated_tokens"],"text_truncated":output["text_truncated"]
        }))?;
        ensure!(
            start < end
                && answer.text.len() <= 1024
                && !answer.text.contains('\0')
                && answer.generated_tokens <= 64
                && rpc::nonzero_hex(&answer.job_id, 32)
                && [
                    &answer.report_sha256,
                    &answer.package_manifest_id,
                    &answer.model_fingerprint
                ]
                .into_iter()
                .all(|s| rpc::nonzero_hex(s, 64)),
            "compute_synthesis_checked_output_shape"
        );
        parse_key(&answer.provider_key).map_err(anyhow::Error::msg)?;
        Ok(answer)
    }
}

fn leaf_answers(
    root: &Path,
    enrollment: &document_storage::Enrollment,
    input: &super::Input,
    plan: &super::Plan,
) -> Result<Vec<Answer>> {
    let mut answers = Vec::new();
    for (index, package) in enrollment.packages.iter().enumerate() {
        let directory = root.join(format!("package-{index:04}"));
        let expected = document_storage::expected(&directory, enrollment, package, input, plan)?;
        let snapshot = workflow::task_snapshot_detailed(&directory.join("work"), &expected)?;
        ensure!(
            snapshot["complete"] == true,
            "compute_synthesis_incomplete_source"
        );
        let outputs = snapshot["outputs"]
            .as_array()
            .context("compute_synthesis_outputs")?;
        ensure!(
            outputs.len() == package.rows,
            "compute_synthesis_source_rows"
        );
        for (row, output) in outputs.iter().enumerate() {
            ensure!(
                output["sample_index"] == row,
                "compute_synthesis_source_order"
            );
            let part = &plan.parts[package.first_part + row];
            answers.push(Answer::from_output(
                output,
                &package.manifest_id,
                part.start,
                part.end,
            )?);
        }
    }
    ensure!(
        answers.len() == plan.parts.len(),
        "compute_synthesis_source_coverage"
    );
    Ok(answers)
}

fn unfinished(reason: &str, levels: &[Value], result: &mut Value) {
    result["complete"] = false.into();
    result["joining"] = "hierarchical_peer_synthesis_incomplete".into();
    result["synthesis"] = json!({"complete":false,"reason":reason,"levels":levels,
        "claim_scope":"coordinator_verified_local_rpc_status_not_portable_execution_attestation",
        "model_answer_correctness_proven":false});
}

fn unusable(answers: &[Answer]) -> Option<&'static str> {
    if answers.iter().any(|answer| answer.text_truncated) {
        Some("worker_output_was_wire_truncated")
    } else if answers.iter().any(|answer| answer.text.trim().is_empty()) {
        Some("worker_produced_empty_answer")
    } else {
        None
    }
}

#[allow(
    clippy::too_many_lines,
    reason = "Retained hierarchy traversal keeps one owner cancellation and round budget"
)]
pub(super) async fn advance(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
    result: &mut Value,
) -> Result<()> {
    let (enrollment, input, plan) = document_storage::load(&args.directory)?;
    ensure!(enrollment.synthesize, "compute_synthesis_not_enrolled");
    let frontier = leaf_answers(&args.directory, &enrollment, &input, &plan)?;
    advance_frontier(
        args,
        socket,
        cancelled,
        result,
        &enrollment,
        &input,
        frontier,
        false,
    )
    .await
}

/// A graph dependency is a new instruction, even when it has exactly one parent.
/// Its parent answers have already been reconstructed from each node's original receipts.
#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) async fn advance_frontier(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
    result: &mut Value,
    enrollment: &document_storage::Enrollment,
    input: &super::Input,
    mut frontier: Vec<Answer>,
    force_first: bool,
) -> Result<()> {
    let mut rounds = result["rounds_this_invocation"]
        .as_u64()
        .context("compute_synthesis_rounds")?;
    let mut levels = Vec::new();
    let root = args.directory.join("synthesis");
    if !document_storage::present(&root)? {
        storage::directory(&root)?;
    }
    private_directory(&root)?;
    for level in 1..=MAX_LEVELS + 1 {
        if let Some(reason) = unusable(&frontier) {
            unfinished(reason, &levels, result);
            return Ok(());
        }
        if frontier.len() == 1 && (!force_first || level > 1) {
            let answer = &frontier[0];
            result["complete"] = true.into();
            result["joining"] = if levels.is_empty() {
                "single_source_answer"
            } else {
                "hierarchical_peer_synthesis"
            }
            .into();
            result["synthesized_answer"] = serde_json::to_value(answer)?;
            result["synthesis"] = json!({"complete":true,"levels":levels,
                "generation_limit_reached":answer.generated_tokens == 64,
                "claim_scope":"coordinator_verified_local_rpc_status_not_portable_execution_attestation",
                "model_answer_correctness_proven":false,"semantic_completeness_proven":false});
            return Ok(());
        }
        if *cancelled.borrow() {
            unfinished("cancelled", &levels, result);
            result["interrupted"] = true.into();
            return Ok(());
        }
        if level > MAX_LEVELS {
            break;
        }
        let mut next = Vec::new();
        let mut groups = Vec::new();
        for (group, parents) in frontier.chunks(PARENTS_PER_GROUP).enumerate() {
            let directory = root.join(format!("level-{level:02}-group-{group:04}"));
            if !args.follow.follow
                && rounds >= u64::from(args.max_batches)
                && !directory.join("group.json").try_exists()?
            {
                unfinished("invocation_round_budget", &levels, result);
                return Ok(());
            }
            let prepared = storage::prepare(
                args,
                &directory,
                enrollment,
                input,
                parents,
                group * PARENTS_PER_GROUP,
                level,
                cancelled,
            )
            .await?;
            let grouped = enrollment.scheduling == workflow::Scheduling::ReadyRowsV1;
            if grouped {
                rounds = rounds
                    .checked_add(
                        advance_group_packages(
                            args, socket, cancelled, &directory, enrollment, &prepared, rounds,
                        )
                        .await?,
                    )
                    .context("compute_synthesis_round_overflow")?;
                result["rounds_this_invocation"] = rounds.into();
            }
            let mut group_complete = true;
            let mut pending_work = None;
            for (index, dataset) in prepared.datasets.iter().enumerate() {
                let package = directory.join(format!("package-{index:04}"));
                let expected = storage::expected(&package, enrollment, &prepared, dataset, index)?;
                let work = package.join("work");
                let established = document_storage::present(&work)?;
                let mut snapshot = if established {
                    Some(workflow::task_snapshot_detailed(&work, &expected)?)
                } else {
                    None
                };
                let mut last_report = None;
                if snapshot.as_ref().is_none_or(|s| s["complete"] != true)
                    && !grouped
                    && (args.follow.follow || rounds < u64::from(args.max_batches))
                    && !*cancelled.borrow()
                {
                    let providers = enrollment
                        .provider_keys
                        .iter()
                        .map(|s| parse_key(s).map_err(anyhow::Error::msg))
                        .collect::<Result<Vec<_>>>()?;
                    let options = workflow::Options::task(
                        (!established).then(|| package.join("workflow-plan.json")),
                        work.clone(),
                        providers,
                        if args.follow.follow {
                            args.max_batches
                        } else {
                            args.max_batches - u16::try_from(rounds)?
                        },
                        args.max_seconds,
                        true,
                    )
                    .expect_task(expected.clone())
                    .with_follow(args.follow.clone());
                    let report =
                        workflow::report_with_activity(&options, socket, cancelled).await?;
                    super::save(&package, "last-workflow-report.json", &report, true)?;
                    rounds = rounds
                        .checked_add(
                            report["rounds_this_invocation"]
                                .as_u64()
                                .context("compute_synthesis_rounds")?,
                        )
                        .context("compute_synthesis_round_overflow")?;
                    result["rounds_this_invocation"] = rounds.into();
                    snapshot = Some(workflow::task_snapshot_detailed(&work, &expected)?);
                    last_report = Some(report);
                }
                let Some(snapshot) = snapshot.filter(|s| s["complete"] == true) else {
                    group_complete = false;
                    pending_work = Some(json!({"package":index,
                        "workflow_stopped":last_report.as_ref().map(|r| &r["stopped"]),
                        "failure_code":last_report.as_ref().and_then(|r| r["packages"].as_array())
                            .and_then(|p| p.iter().find_map(|p| p.get("failure_code")))}));
                    break;
                };
                let outputs = snapshot["outputs"]
                    .as_array()
                    .context("compute_synthesis_outputs")?;
                ensure!(
                    outputs.len() == dataset.inference.len(),
                    "compute_synthesis_reduction_rows"
                );
                for (row, output) in outputs.iter().enumerate() {
                    ensure!(
                        output["sample_index"] == row,
                        "compute_synthesis_reduction_order"
                    );
                    let inputs = &dataset.inference[row].inputs;
                    let start = inputs
                        .iter()
                        .map(|i| i.source_start)
                        .min()
                        .context("compute_synthesis_ancestry")?;
                    let end = inputs
                        .iter()
                        .map(|i| i.source_end)
                        .max()
                        .context("compute_synthesis_ancestry")?;
                    next.push(Answer::from_output(
                        output,
                        &expected.manifest_id,
                        start,
                        end,
                    )?);
                }
            }
            groups.push(
                json!({"group":group,"parents":parents.len(),"complete":group_complete,
                "parts":prepared.parts,"input_sha256":prepared.input_sha256}),
            );
            if !group_complete {
                levels.push(json!({"level":level,"complete":false,"groups":groups}));
                result["interrupted"] = (*cancelled.borrow()).into();
                unfinished(
                    if *cancelled.borrow() {
                        "cancelled"
                    } else {
                        "peer_work_pending"
                    },
                    &levels,
                    result,
                );
                result["synthesis"]["pending_work"] = json!(pending_work);
                return Ok(());
            }
        }
        let record = json!({"level":level,"complete":true,"parents":frontier.len(),
            "outputs":next.len(),"groups":groups,"answers":next,
            "generation_limit_reached":next.iter().any(|answer| answer.generated_tokens == 64)});
        storage::retain_json(&root, &format!("level-{level:02}-result.json"), &record)?;
        levels.push(record);
        // The first graph stage applies a different instruction and may split its
        // inputs by token budget. Subsequent same-instruction reductions must shrink.
        if next.len() >= frontier.len() && !(force_first && level == 1) {
            unfinished(
                "reduction_did_not_shrink_no_inputs_discarded",
                &levels,
                result,
            );
            return Ok(());
        }
        frontier = next;
    }
    unfinished("hierarchy_budget_no_inputs_discarded", &levels, result);
    Ok(())
}

async fn advance_group_packages(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
    directory: &Path,
    enrollment: &document_storage::Enrollment,
    prepared: &storage::Prepared,
    prior_rounds: u64,
) -> Result<u64> {
    let providers = enrollment
        .provider_keys
        .iter()
        .map(|key| parse_key(key).map_err(anyhow::Error::msg))
        .collect::<Result<Vec<_>>>()?;
    let mut rounds = 0;
    for (group, datasets) in prepared.datasets.chunks(32).enumerate() {
        let used = prior_rounds
            .checked_add(rounds)
            .context("compute_synthesis_round_overflow")?;
        if *cancelled.borrow() || (!args.follow.follow && used >= u64::from(args.max_batches)) {
            break;
        }
        let budget = if args.follow.follow {
            args.max_batches
        } else {
            args.max_batches - u16::try_from(used)?
        };
        let options = datasets
            .iter()
            .enumerate()
            .map(|(offset, dataset)| {
                let index = group * 32 + offset;
                let package = directory.join(format!("package-{index:04}"));
                let expected = storage::expected(&package, enrollment, prepared, dataset, index)?;
                let work = package.join("work");
                let established = document_storage::present(&work)?;
                Ok(workflow::Options::task(
                    (!established).then(|| package.join("workflow-plan.json")),
                    work,
                    providers.clone(),
                    budget,
                    args.max_seconds,
                    true,
                )
                .expect_task(expected)
                .with_follow(args.follow.clone()))
            })
            .collect::<Result<Vec<_>>>()?;
        let report =
            workflow::report_group_with_activity(&options, budget, &args.follow, socket, cancelled)
                .await?;
        rounds = rounds
            .checked_add(
                report["rounds_this_invocation"]
                    .as_u64()
                    .context("compute_synthesis_rounds")?,
            )
            .context("compute_synthesis_round_overflow")?;
        for (offset, saved) in report["workflows"]
            .as_array()
            .context("compute_synthesis_workflows")?
            .iter()
            .enumerate()
        {
            let package = directory.join(format!("package-{:04}", group * 32 + offset));
            retain_workflow_report(&package, saved)?;
        }
        if report["complete"] != true {
            break;
        }
    }
    Ok(rounds)
}

/// A completed replay has already revalidated its source and receipts. Its zero-round
/// invocation summary must not replace the original execution summary with new budgets.
fn retain_workflow_report(package: &Path, report: &Value) -> Result<()> {
    let rounds = report["rounds_this_invocation"]
        .as_u64()
        .context("compute_synthesis_rounds")?;
    let path = package.join("last-workflow-report.json");
    if rounds == 0 && report["complete"] == true && path.try_exists()? {
        crate::compute::read_file(&path, super::MAX_SAVED_BYTES as u64)?;
        return Ok(());
    }
    super::save(package, "last-workflow-report.json", report, true)
}

#[cfg(test)]
mod tests;
