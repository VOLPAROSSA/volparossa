//! Enrolled public task dependencies, including bounded model-proposed fork/join questions.

mod leaves;
mod plan;
mod planner;
mod ready;

use std::{
    collections::BTreeMap,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use tokio::sync::watch;

use super::{
    Input, MAX_SAVED_BYTES, Options, Plan as DocumentPlan, private_directory, read_file, save,
    storage, synthesis, task, workflow,
};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    version: u32,
    plan_sha256: String,
    leaves: Vec<Leaf>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    planner: Option<planner::Authority>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Leaf {
    node: usize,
    enrollment_sha256: String,
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn node_root(root: &Path, index: usize) -> PathBuf {
    root.join(format!("node-{index:04}"))
}

fn node_options(args: &Options, index: usize) -> Options {
    let mut options = args.clone();
    options.directory = node_root(&args.directory, index);
    options.task_plan = None;
    options.plan_tasks = false;
    options.enroll_only = false;
    options.synthesize = true;
    options.batch_barrier = false;
    options
}

struct Loaded {
    plan: plan::Plan,
    enrollment: Enrollment,
    authority: storage::Enrollment,
    input: Input,
    source: Vec<u8>,
}

fn load(root: &Path) -> Result<Loaded> {
    private_directory(root)?;
    let plan = plan::Plan::load(&root.join("graph-plan.json"))?;
    let enrollment: Enrollment =
        serde_json::from_slice(&read_file(&root.join("graph.json"), MAX_SAVED_BYTES)?)?;
    let expected: Vec<_> = plan
        .nodes
        .iter()
        .enumerate()
        .filter(|(_, node)| node.depends_on.is_empty())
        .map(|(i, _)| i)
        .collect();
    ensure!(
        enrollment.version == 1
            && enrollment.plan_sha256 == plan.fingerprint()?
            && enrollment.leaves.iter().map(|leaf| leaf.node).eq(expected),
        "compute_graph_enrollment_changed"
    );
    let anchor = enrollment
        .leaves
        .first()
        .context("compute_graph_no_source_tasks")?;
    let anchor_root = node_root(root, anchor.node);
    let (authority, input, _) = storage::load(&anchor_root)?;
    let source = read_file(
        &anchor_root.join("source.manifest"),
        volparossa_content::MAX_MANIFEST_BYTES,
    )?;
    if let Some(planner) = &enrollment.planner {
        planner::verify(root, planner, &plan, &input)?;
    } else {
        planner::verify_absent(root)?;
    }
    for leaf in &enrollment.leaves {
        let directory = node_root(root, leaf.node);
        ensure!(
            digest(&read_file(
                &directory.join("document.json"),
                MAX_SAVED_BYTES
            )?) == leaf.enrollment_sha256,
            "compute_graph_leaf_enrollment_changed"
        );
        let (saved, text, _) = storage::load(&directory)?;
        ensure!(
            saved.synthesize
                && saved.scheduling == workflow::Scheduling::ReadyRowsV1
                && saved.source_manifest_id == authority.source_manifest_id
                && saved.selected_at_unix_seconds == authority.selected_at_unix_seconds
                && saved.expires_at_unix_seconds == authority.expires_at_unix_seconds
                && saved.publisher_key == authority.publisher_key
                && saved.provider_keys == authority.provider_keys
                && saved.model_fingerprint == authority.model_fingerprint
                && saved.replace_peers == authority.replace_peers
                && saved.collection_sha256 == authority.collection_sha256
                && saved.native_source_proofs_sha256 == authority.native_source_proofs_sha256
                && text.document == input.document
                && text.license == input.license
                && text.question == plan.nodes[leaf.node].question,
            "compute_graph_shared_source_or_task_changed"
        );
    }
    Ok(Loaded {
        plan,
        enrollment,
        authority,
        input,
        source,
    })
}

pub(super) async fn run(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
) -> Result<()> {
    if !args.resume {
        let manual = if args.plan_tasks {
            ensure!(
                args.task_plan.is_none(),
                "compute_graph_planning_modes_conflict"
            );
            None
        } else {
            Some(plan::Plan::load(
                args.task_plan.as_deref().context("compute_graph_plan")?,
            )?)
        };
        let selected = super::selected_input(args, socket, cancelled).await?;
        let (plan, authority) = if let Some(plan) = manual {
            (plan, None)
        } else {
            let (plan, authority) = planner::prepare(args, &selected.0, cancelled).await?;
            (plan, Some(authority))
        };
        leaves::prepare(args, socket, cancelled, &plan, &selected, authority).await?;
    }
    let loaded = load(&args.directory)?;
    if args.enroll_only {
        let mut result = json!({"operation":"compute_graph_enrolled", "execution_started":false,
            "task_complete":false,"plan_sha256":loaded.enrollment.plan_sha256,"nodes":loaded.plan.nodes.len(),
            "source_tasks":loaded.enrollment.leaves.len(),"source_manifest_id":loaded.authority.source_manifest_id,
            "provider_keys":loaded.authority.provider_keys,"private_data_supported":false});
        if loaded.enrollment.planner.is_some() {
            result["execution_started"] = true.into();
            result["automatic_task_planning"] = true.into();
            result["planning"] = planner::summary(loaded.enrollment.planner.as_ref());
            result["model_planning_performed"] = true.into();
            result["peer_execution_started"] = false.into();
        }
        println!("{result}");
        return Ok(());
    }
    let result = advance(args, socket, cancelled, &loaded).await?;
    retain_result(&args.directory, &result)?;
    println!("{}", serde_json::to_string(&result)?);
    ensure!(
        result["complete"] == true,
        "compute_graph_partial_results_retained"
    );
    Ok(())
}

/// Revalidate the exact receipt-derived answer on replay, retaining the original execution summary.
fn retain_result(root: &Path, result: &Value) -> Result<()> {
    let path = root.join("result.json");
    if result["complete"] == true && result["rounds_this_invocation"] == 0 && path.try_exists()? {
        let saved: Value = serde_json::from_slice(&read_file(&path, super::MAX_RESULT_BYTES)?)?;
        let answer = if result["operation"] == "compute_public_task_graph" {
            "output"
        } else {
            "synthesized_answer"
        };
        if saved["complete"] == true {
            ensure!(
                saved[answer] == result[answer],
                "compute_graph_retained_answer_changed"
            );
            return Ok(());
        }
    }
    save(root, "result.json", result, true)
}

async fn advance(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
    loaded: &Loaded,
) -> Result<Value> {
    super::super::follow::run(&args.follow, cancelled, || {
        ready::window(args, socket, cancelled, loaded)
    })
    .await
}

fn summarize(
    args: &Options,
    cancelled: &watch::Receiver<bool>,
    loaded: &Loaded,
    rounds: u64,
    states: &BTreeMap<usize, Value>,
    complete: &BTreeMap<usize, synthesis::Answer>,
) -> Result<Value> {
    let summaries = loaded.plan.nodes.iter().enumerate().map(|(index, node)| {
        json!({"id":node.id,"question":node.question,"depends_on":node.depends_on,
            "complete":complete.contains_key(&index),"status":if complete.contains_key(&index) { "complete" }
                else if states.contains_key(&index) { "pending" } else { "awaiting_dependencies" },
            "answer":complete.get(&index)})
    }).collect::<Vec<_>>();
    let output_node = loaded
        .plan
        .node(&loaded.plan.output)
        .context("compute_graph_output")?;
    let output_index = loaded
        .plan
        .nodes
        .iter()
        .position(|node| node.id == output_node.id)
        .context("compute_graph_output")?;
    let output = complete.get(&output_index);
    let mut result = json!({"version":1,"operation":"compute_public_task_graph","complete":output.is_some(),
        "plan_sha256":loaded.enrollment.plan_sha256,"plan":loaded.plan,"nodes":summaries,"output":output,
        "source_manifest_id":loaded.authority.source_manifest_id,"source_expires_unix_seconds":loaded.authority.expires_at_unix_seconds,
        "provider_keys":loaded.authority.provider_keys,"rounds_this_invocation":rounds,"interrupted":*cancelled.borrow(),
        "scheduling":"shared_ready_dependency_queue_v1","execute":true,
        "source_admission_expires_unix_seconds":loaded.authority.expires_at_unix_seconds,
        "private_data_supported":false,"automatic_task_planning":false,"external_actions_supported":false,
        "model_answer_correctness_proven":false,"full_b03_claimed":false});
    if loaded.enrollment.planner.is_some() {
        result["automatic_task_planning"] = true.into();
        result["planning"] = planner::summary(loaded.enrollment.planner.as_ref());
    }
    attach_provenance(&args.directory, loaded, output, &mut result)?;
    Ok(result)
}

fn attach_provenance(
    root: &Path,
    loaded: &Loaded,
    output: Option<&synthesis::Answer>,
    result: &mut Value,
) -> Result<()> {
    let anchor = loaded
        .enrollment
        .leaves
        .first()
        .context("compute_graph_no_source_tasks")?;
    let mut provenance = json!({"answers":[]});
    if let Some(answer) = output {
        provenance["synthesized_answer"] = serde_json::to_value(answer)?;
    }
    super::attach_collection(&node_root(root, anchor.node), &mut provenance)?;
    if let Some(collection) = provenance.get("source_collection") {
        result["source_collection"] = collection.clone();
        if output.is_some() {
            result["output"]["source_provenance"] =
                provenance["synthesized_answer"]["source_provenance"].clone();
        }
    }
    Ok(())
}
#[cfg(test)]
mod tests;
