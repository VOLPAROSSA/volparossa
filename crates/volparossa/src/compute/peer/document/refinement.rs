//! One owner-enrolled source refinement level; terminal original receipts are immutable.

mod storage;
#[cfg(test)]
mod tests;

use std::path::Path;

use anyhow::{Context as _, Result, ensure};
use serde_json::{Value, json};
use tokio::sync::watch;

use super::{Input, Options, parse_key, synthesis, workflow};
use crate::compute::inference_output::{Generation, StopReason};

const MAX_LEAVES: usize = 16;

fn eligible(answer: &synthesis::Answer) -> bool {
    !answer.text_truncated
        && !answer.text.trim().is_empty()
        && answer
            .generation
            .is_some_and(|generation| generation.stop_reason == StopReason::TokenLimit)
}

fn complete(answer: &synthesis::Answer) -> bool {
    !answer.text_truncated
        && !answer.text.trim().is_empty()
        && answer.generation.is_some_and(Generation::is_eos)
}

fn halves(input: &Input, answer: &synthesis::Answer) -> Result<Option<[(u64, u64); 2]>> {
    let start = usize::try_from(answer.source_start)?;
    let end = usize::try_from(answer.source_end)?;
    let text = input
        .document
        .get(start..end)
        .context("compute_refinement_source_range")?;
    let middle = text
        .char_indices()
        .map(|(index, _)| index)
        .filter(|index| {
            *index > 0 && !text[..*index].trim().is_empty() && !text[*index..].trim().is_empty()
        })
        .min_by_key(|index| index.abs_diff(text.len() / 2));
    Ok(middle.map(|middle| {
        let middle = answer.source_start + middle as u64;
        [(answer.source_start, middle), (middle, answer.source_end)]
    }))
}

fn status(
    result: &mut Value,
    originals: usize,
    eligible: usize,
    parents: &[Value],
    answers: &[synthesis::Answer],
    reason: &str,
) {
    let refined = parents
        .iter()
        .filter(|parent| parent["complete"] == true)
        .count();
    if reason != "unsupported_or_over_limit" {
        result["execution_complete"] = (parents.len() == eligible
            && parents.iter().all(|parent| {
                parent["children"].as_array().is_some_and(|children| {
                    children.len() == 2 && children.iter().all(|child| child["complete"] == true)
                })
            }))
        .into();
    }
    if reason == "cancelled" {
        result["interrupted"] = true.into();
    }
    result["refinement"] = json!({"version":1,"enabled":true,"complete":reason=="complete",
        "reason":reason,"maximum_refined_leaves":MAX_LEAVES,"split_levels":1,
        "original_parts":originals,"eligible_leaves":eligible,"refined_leaves":refined,
        "parents":parents,"answers":answers});
}

/// Only fresh checked child receipts may replace a failed original in the effective
/// synthesis frontier. This never mutates the original plan, answers or receipts.
#[allow(
    clippy::too_many_lines,
    reason = "One bounded owner pass retains intent before publication and joins exact child receipts"
)]
pub(super) async fn advance(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
    result: &mut Value,
) -> Result<Option<Vec<synthesis::Answer>>> {
    let (enrollment, input, plan) = super::storage::load(&args.directory)?;
    if !enrollment.refine_incomplete
        || result["execution_complete"] != true
        || result["complete"] == true
    {
        return Ok(None);
    }
    let originals = synthesis::leaf_answers(&args.directory, &enrollment, &input, &plan)?;
    let count = originals.iter().filter(|answer| eligible(answer)).count();
    if count == 0 || count > MAX_LEAVES || originals.iter().any(|a| !complete(a) && !eligible(a)) {
        status(
            result,
            originals.len(),
            count,
            &[],
            &[],
            "unsupported_or_over_limit",
        );
        return Ok(None);
    }
    ensure!(
        enrollment.scheduling == workflow::Scheduling::ReadyRowsV1,
        "compute_refinement_requires_ready_rows"
    );
    let providers = enrollment
        .provider_keys
        .iter()
        .map(|key| parse_key(key).map_err(anyhow::Error::msg))
        .collect::<Result<Vec<_>>>()?;
    let mut rounds = result["rounds_this_invocation"]
        .as_u64()
        .context("compute_refinement_rounds")?;
    let initial_rounds = rounds;
    let mut frontier = Vec::with_capacity(originals.len() + count);
    let mut parents = Vec::new();
    let mut pending = false;
    for (index, original) in originals.iter().enumerate() {
        if complete(original) {
            frontier.push(original.clone());
            continue;
        }
        let Some(ranges) = halves(&input, original)? else {
            pending = true;
            continue;
        };
        // Follow authorizes repeated workflow windows, not unbounded refinement.
        // This pass has at most one shared max_batches window beyond prior follow work.
        let charged = if args.follow.follow {
            rounds - initial_rounds
        } else {
            rounds
        };
        let budget = u64::from(args.max_batches).saturating_sub(charged);
        let root = args
            .directory
            .join("refinement")
            .join(format!("leaf-{index:04}"));
        let allow_new = budget > 0
            && !*cancelled.borrow()
            && super::now()? < enrollment.expires_at_unix_seconds;
        if !storage::has_intent(&root)? && !allow_new {
            pending = true;
            continue;
        }
        let intent = storage::intent(&root, &enrollment, &input, original, index, ranges)?;
        let mut prepared = Vec::new();
        for (child, range) in ranges.into_iter().enumerate() {
            if let Some(value) = storage::prepare_child(
                args,
                &root.join(format!("child-{child}")),
                &enrollment,
                &input,
                &intent,
                child,
                range,
                cancelled,
                allow_new,
            )
            .await?
            {
                prepared.push(value);
            }
        }
        if prepared.len() == 2 && allow_new {
            let options = prepared
                .iter()
                .map(|child| {
                    let work = child.root.join("work");
                    let established = storage::present(&work)?;
                    Ok(workflow::Options::task(
                        (!established).then(|| child.root.join("workflow-plan.json")),
                        work,
                        providers.clone(),
                        u16::try_from(budget)?,
                        args.max_seconds,
                        true,
                    )
                    .expect_task(child.expected.clone()))
                })
                .collect::<Result<Vec<_>>>()?;
            // A single existing shared ready-row coordinator owns both children.
            // No free-running follow loop or second reservation ledger is introduced.
            let report = workflow::report_group_with_activity(
                &options,
                u16::try_from(budget)?,
                &super::super::follow::Options::default(),
                socket,
                cancelled,
            )
            .await?;
            let used = report["rounds_this_invocation"]
                .as_u64()
                .context("compute_refinement_rounds")?;
            ensure!(used <= budget, "compute_refinement_round_budget");
            rounds = rounds
                .checked_add(used)
                .context("compute_refinement_round_overflow")?;
            result["rounds_this_invocation"] = rounds.into();
        }
        let mut replacements = Vec::new();
        let mut children = Vec::new();
        for child in &prepared {
            let snapshot = storage::snapshot(child)?;
            let execution_complete = snapshot.as_ref().is_some_and(|s| s["complete"] == true);
            let answer = snapshot
                .as_ref()
                .filter(|_| execution_complete)
                .map(|snapshot| {
                    let outputs = snapshot["outputs"]
                        .as_array()
                        .context("compute_refinement_outputs")?;
                    ensure!(
                        outputs.len() == 1 && outputs[0]["sample_index"] == 0,
                        "compute_refinement_child_output_count"
                    );
                    let answer = synthesis::Answer::from_output(
                        &outputs[0],
                        &child.expected.manifest_id,
                        child.range.0,
                        child.range.1,
                    )?;
                    ensure!(
                        answer.generation.is_some_and(
                            |generation| generation.model_profile == input.model_profile
                        ),
                        "compute_refinement_child_profile"
                    );
                    Ok::<_, anyhow::Error>(answer)
                })
                .transpose()?;
            let answer_complete = answer.as_ref().is_some_and(complete);
            if let Some(answer) = answer.filter(complete) {
                replacements.push(answer);
            }
            children.push(json!({"start":child.range.0,"end":child.range.1,"complete":execution_complete,
                "answer_complete":answer_complete,"package_manifest_id":child.expected.manifest_id}));
        }
        let resolved = replacements.len() == 2;
        if resolved {
            ensure!(
                replacements[0].source_start == original.source_start
                    && replacements[0].source_end == replacements[1].source_start
                    && replacements[1].source_end == original.source_end,
                "compute_refinement_child_coverage"
            );
            frontier.extend(replacements);
        } else {
            pending = true;
        }
        parents.push(json!({"part_index":index,"parent_report_sha256":original.report_sha256,
            "parent_job_id":original.job_id,"parent_source_start":original.source_start,
            "parent_source_end":original.source_end,"intent_sha256":storage::sha(&serde_json::to_vec(&intent)?),
            "complete":resolved,"children":children}));
    }
    if pending {
        status(
            result,
            originals.len(),
            count,
            &parents,
            &[],
            if *cancelled.borrow() {
                "cancelled"
            } else {
                "children_incomplete"
            },
        );
        return Ok(None);
    }
    let mut end = 0;
    for answer in &frontier {
        ensure!(
            complete(answer) && answer.source_start == end,
            "compute_refinement_frontier_gap"
        );
        end = answer.source_end;
    }
    ensure!(
        end == input.document.len() as u64,
        "compute_refinement_frontier_tail"
    );
    status(
        result,
        originals.len(),
        count,
        &parents,
        &frontier,
        "complete",
    );
    Ok(Some(frontier))
}
