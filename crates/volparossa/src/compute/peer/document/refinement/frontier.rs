//! Explicit multi-level refinement over the existing shared ready-row coordinator.

use std::{
    collections::{BTreeSet, VecDeque},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use serde_json::{Value, json};
use tokio::sync::watch;

use super::super::storage::Enrollment;
use super::{Input, MAX_LEAVES, Options, complete, eligible, halves, storage, synthesis, workflow};

struct Node {
    part_index: usize,
    address: Vec<u8>,
    root: PathBuf,
    answer: synthesis::Answer,
}

struct Scan {
    parents: Vec<Value>,
    descendants: Vec<Value>,
    answers: Vec<synthesis::Answer>,
    pending: Vec<storage::Prepared>,
    reasons: BTreeSet<&'static str>,
    retained_splits: usize,
    deepest_level: usize,
    unresolved: usize,
    execution_complete: bool,
}

impl Scan {
    fn unresolved(&mut self, reason: &'static str) {
        self.unresolved += 1;
        self.reasons.insert(reason);
    }
}

/// Count the entire retained tree before admitting anything new. Otherwise a new
/// earlier sibling could consume a slot already owned by a deeper resumed node.
fn retained(root: &Path, level: u8, limit: u8) -> Result<usize> {
    if !storage::has_intent(root)? {
        return Ok(0);
    }
    ensure!(level <= limit, "compute_refinement_unenrolled_depth");
    let mut count = 1;
    for child in 0..2 {
        count += retained(
            &root.join(format!("child-{child}/refinement")),
            level + 1,
            limit,
        )?;
    }
    ensure!(
        count <= MAX_LEAVES,
        "compute_refinement_retained_split_bound"
    );
    Ok(count)
}

fn checked_answer(child: &storage::Prepared, input: &Input) -> Result<Option<synthesis::Answer>> {
    let Some(snapshot) = storage::snapshot(child)? else {
        return Ok(None);
    };
    if snapshot["complete"] != true {
        return Ok(None);
    }
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
        answer
            .generation
            .is_some_and(|generation| generation.model_profile == input.model_profile),
        "compute_refinement_child_profile"
    );
    Ok(Some(answer))
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "One bounded source tree derives children only from verified terminal parent receipts"
)]
async fn scan(
    args: &Options,
    enrollment: &Enrollment,
    input: &Input,
    originals: &[synthesis::Answer],
    cancelled: &watch::Receiver<bool>,
    budget: u64,
) -> Result<Scan> {
    let mut queue = VecDeque::new();
    let mut existing = 0;
    for (part_index, answer) in originals.iter().enumerate() {
        let root = args
            .directory
            .join("refinement")
            .join(format!("leaf-{part_index:04}"));
        existing += retained(&root, 1, enrollment.refinement_levels)?;
        ensure!(
            existing <= MAX_LEAVES,
            "compute_refinement_retained_split_bound"
        );
        queue.push_back(Node {
            part_index,
            address: Vec::new(),
            root,
            answer: answer.clone(),
        });
    }
    let mut view = Scan {
        parents: Vec::new(),
        descendants: Vec::new(),
        answers: Vec::new(),
        pending: Vec::new(),
        reasons: BTreeSet::new(),
        retained_splits: existing,
        deepest_level: 0,
        unresolved: 0,
        execution_complete: true,
    };
    while let Some(node) = queue.pop_front() {
        if complete(&node.answer) {
            ensure!(
                !storage::has_intent(&node.root)?,
                "compute_refinement_complete_leaf_has_intent"
            );
            view.answers.push(node.answer);
            continue;
        }
        if !eligible(&node.answer) {
            view.unresolved("unsupported_child");
            continue;
        }
        let level = node.address.len() + 1;
        if level > usize::from(enrollment.refinement_levels) {
            view.unresolved("split_level_exhausted");
            continue;
        }
        let Some(ranges) = halves(input, &node.answer)? else {
            view.unresolved("source_cannot_split");
            continue;
        };
        let exists = storage::has_intent(&node.root)?;
        let admission_stop = if *cancelled.borrow() {
            Some("cancelled")
        } else if super::super::now()? >= enrollment.expires_at_unix_seconds {
            Some("source_expired")
        } else if budget == 0 {
            Some("round_budget_exhausted")
        } else {
            None
        };
        if !exists {
            if let Some(reason) = admission_stop {
                view.execution_complete = false;
                view.unresolved(reason);
                continue;
            }
            if view.retained_splits >= MAX_LEAVES {
                view.unresolved("split_budget_exhausted");
                continue;
            }
        }
        let intent = storage::intent(
            &node.root,
            enrollment,
            input,
            &node.answer,
            node.part_index,
            ranges,
        )?;
        if !exists {
            view.retained_splits += 1;
        }
        view.deepest_level = view.deepest_level.max(level);
        let mut children = Vec::new();
        for (index, range) in ranges.into_iter().enumerate() {
            let prepared = storage::prepare_child(
                args,
                &node.root.join(format!("child-{index}")),
                enrollment,
                input,
                &intent,
                index,
                range,
                cancelled,
                admission_stop.is_none(),
            )
            .await?;
            let Some(child) = prepared else {
                view.execution_complete = false;
                view.unresolved(admission_stop.unwrap_or("children_incomplete"));
                children.push(json!({"start":range.0,"end":range.1,"complete":false,
                    "answer_complete":false,"package_manifest_id":null,"generation":null,
                    "text_truncated":null,"generated_tokens":null}));
                continue;
            };
            let answer = checked_answer(&child, input)?;
            children.push(
                json!({"start":range.0,"end":range.1,"complete":answer.is_some(),
                "answer_complete":answer.as_ref().is_some_and(complete),
                "package_manifest_id":child.expected.manifest_id,
                "generation":answer.as_ref().and_then(|answer| answer.generation),
                "text_truncated":answer.as_ref().map(|answer| answer.text_truncated),
                "generated_tokens":answer.as_ref().map(|answer| answer.generated_tokens)}),
            );
            if let Some(answer) = answer {
                let mut address = node.address.clone();
                address.push(u8::try_from(index)?);
                queue.push_back(Node {
                    part_index: node.part_index,
                    address,
                    root: child.root.join("refinement"),
                    answer,
                });
            } else {
                view.execution_complete = false;
                view.unresolved(admission_stop.unwrap_or("children_incomplete"));
                view.pending.push(child);
            }
        }
        let entry = json!({"part_index":node.part_index,"address":node.address,"level":level,
            "parent_report_sha256":node.answer.report_sha256,"parent_job_id":node.answer.job_id,
            "parent_source_start":node.answer.source_start,"parent_source_end":node.answer.source_end,
            "intent_sha256":storage::sha(&serde_json::to_vec(&intent)?),
            "complete":children.iter().all(|child| child["answer_complete"]==true),"children":children});
        if node.address.is_empty() {
            view.parents.push(entry);
        } else {
            view.descendants.push(entry);
        }
    }
    view.answers.sort_by_key(|answer| answer.source_start);
    if view.unresolved > 0 {
        if *cancelled.borrow() {
            view.reasons.insert("cancelled");
        }
        if super::super::now()? >= enrollment.expires_at_unix_seconds {
            view.reasons.insert("source_expired");
        }
    }
    if view.unresolved == 0 {
        let mut end = 0;
        for answer in &view.answers {
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
    }
    Ok(view)
}

fn covered(original: &synthesis::Answer, frontier: &[synthesis::Answer]) -> bool {
    let mut end = original.source_start;
    for answer in frontier.iter().filter(|answer| {
        answer.source_start >= original.source_start && answer.source_end <= original.source_end
    }) {
        if !complete(answer) || answer.source_start != end {
            return false;
        }
        end = answer.source_end;
    }
    end == original.source_end
}

fn status(
    result: &mut Value,
    enrollment: &Enrollment,
    originals: &[synthesis::Answer],
    view: &Scan,
    remaining: u64,
) {
    let finished = view.unresolved == 0;
    let reason = if finished {
        "complete"
    } else {
        [
            "cancelled",
            "source_expired",
            "round_budget_exhausted",
            "split_budget_exhausted",
            "split_level_exhausted",
            "source_cannot_split",
            "unsupported_child",
            "children_incomplete",
        ]
        .into_iter()
        .find(|reason| view.reasons.contains(reason))
        .unwrap_or("children_incomplete")
    };
    result["execution_complete"] = view.execution_complete.into();
    if reason == "cancelled" {
        result["interrupted"] = true.into();
    }
    let answers = if finished {
        view.answers.as_slice()
    } else {
        &[]
    };
    result["refinement"] = json!({"version":2,"enabled":true,"complete":finished,"reason":reason,
        "maximum_refined_leaves":MAX_LEAVES,"maximum_child_jobs":2*MAX_LEAVES,
        "split_levels":enrollment.refinement_levels,"original_parts":originals.len(),
        "eligible_leaves":originals.iter().filter(|answer| eligible(answer)).count(),
        "refined_leaves":originals.iter().filter(|answer| eligible(answer) && covered(answer,&view.answers)).count(),
        "retained_splits":view.retained_splits,"remaining_splits":MAX_LEAVES-view.retained_splits,
        "remaining_rounds":remaining,"deepest_level":view.deepest_level,
        "unresolved_leaves":view.unresolved,"stop_reasons":view.reasons,
        "source_admission_expires_unix_seconds":enrollment.expires_at_unix_seconds,
        "parents":view.parents,"descendants":view.descendants,"answers":answers});
}

#[allow(
    clippy::too_many_arguments,
    reason = "The existing owner passes verified enrollment, source and immutable original receipts"
)]
pub(super) async fn advance(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
    result: &mut Value,
    enrollment: &Enrollment,
    input: &Input,
    originals: Vec<synthesis::Answer>,
) -> Result<Option<Vec<synthesis::Answer>>> {
    ensure!(
        (2..=4).contains(&enrollment.refinement_levels)
            && enrollment.refine_incomplete
            && enrollment.scheduling == workflow::Scheduling::ReadyRowsV1,
        "compute_refinement_frontier_enrollment"
    );
    let providers = enrollment
        .provider_keys
        .iter()
        .map(|key| super::parse_key(key).map_err(anyhow::Error::msg))
        .collect::<Result<Vec<_>>>()?;
    let mut rounds = result["rounds_this_invocation"]
        .as_u64()
        .context("compute_refinement_rounds")?;
    let initial = rounds;
    loop {
        // The whole tree shares one existing window; depth does not mint new rounds.
        let charged = if args.follow.follow {
            rounds - initial
        } else {
            rounds
        };
        let budget = u64::from(args.max_batches).saturating_sub(charged);
        let view = scan(args, enrollment, input, &originals, cancelled, budget).await?;
        status(result, enrollment, &originals, &view, budget);
        if view.unresolved == 0 {
            return Ok(Some(view.answers));
        }
        if view.pending.is_empty()
            || budget == 0
            || *cancelled.borrow()
            || super::super::now()? >= enrollment.expires_at_unix_seconds
        {
            return Ok(None);
        }
        let options = view
            .pending
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
        let report = workflow::report_group_with_activity(
            &options,
            u16::try_from(budget)?,
            &super::super::super::follow::Options::default(),
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
        if used == 0 {
            // No busy retry loop: existing handles stay durable for explicit resume.
            let view = scan(args, enrollment, input, &originals, cancelled, budget).await?;
            status(result, enrollment, &originals, &view, budget);
            return Ok((view.unresolved == 0).then_some(view.answers));
        }
    }
}
