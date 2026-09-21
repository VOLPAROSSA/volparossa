//! Enrolled public task dependencies, including bounded model-proposed fork/join questions.

mod leaves;
mod plan;
mod planner;

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
    if super::output::preserve_legacy_result(
        &path,
        super::MAX_RESULT_BYTES as u64,
        result["rounds_this_invocation"]
            .as_u64()
            .context("compute_graph_rounds")?,
        result,
    )? {
        return Ok(());
    }
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

fn add_rounds(rounds: &mut u64, report: &Value, args: &Options) -> Result<()> {
    *rounds = rounds
        .checked_add(
            report["rounds_this_invocation"]
                .as_u64()
                .context("compute_graph_rounds")?,
        )
        .context("compute_graph_round_overflow")?;
    ensure!(
        args.follow.follow || *rounds <= u64::from(args.max_batches),
        "compute_graph_invocation_budget"
    );
    Ok(())
}

fn budget(args: &Options, used: u64) -> Result<u16> {
    if args.follow.follow {
        Ok(args.max_batches)
    } else {
        args.max_batches
            .checked_sub(u16::try_from(used)?)
            .context("compute_graph_invocation_budget")
    }
}

async fn source_tasks(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
    loaded: &Loaded,
) -> Result<u64> {
    let providers = loaded
        .authority
        .provider_keys
        .iter()
        .map(|key| super::parse_key(key).map_err(anyhow::Error::msg))
        .collect::<Result<Vec<_>>>()?;
    let mut ready = Vec::new();
    for leaf in &loaded.enrollment.leaves {
        let root = node_root(&args.directory, leaf.node);
        let (enrollment, input, plan) = storage::load(&root)?;
        for (index, package) in enrollment.packages.iter().enumerate() {
            let directory = root.join(format!("package-{index:04}"));
            let expected = storage::expected(&directory, &enrollment, package, &input, &plan)?;
            let work = directory.join("work");
            let established = storage::present(&work)?;
            ready.push(
                workflow::Options::task(
                    (!established).then(|| directory.join("workflow-plan.json")),
                    work,
                    providers.clone(),
                    args.max_batches,
                    args.max_seconds,
                    true,
                )
                .expect_task(expected)
                .with_follow(args.follow.clone()),
            );
        }
    }
    let mut rounds = 0;
    for options in ready.chunks(32) {
        if *cancelled.borrow() || budget(args, rounds)? == 0 {
            break;
        }
        let report = workflow::report_group_with_activity(
            options,
            budget(args, rounds)?,
            &args.follow,
            socket,
            cancelled,
        )
        .await?;
        add_rounds(&mut rounds, &report, args)?;
        if report["complete"] != true {
            break;
        }
    }
    Ok(rounds)
}

async fn advance(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
    loaded: &Loaded,
) -> Result<Value> {
    let mut rounds = source_tasks(args, socket, cancelled, loaded).await?;
    let mut states = BTreeMap::<usize, Value>::new();
    let mut sources_complete = true;
    // Snapshot only: no second coordinator may compete with unconfirmed leases in the shared source queue.
    for leaf in &loaded.enrollment.leaves {
        let mut options = node_options(args, leaf.node);
        options.max_batches = 0;
        options.follow.follow = false;
        let result = super::advance(&options, socket, cancelled).await?;
        sources_complete &= result["complete"] == true;
        states.insert(leaf.node, result);
    }
    let mut complete = BTreeMap::<usize, synthesis::Answer>::new();
    if sources_complete {
        for index in loaded.plan.topological()? {
            let node = &loaded.plan.nodes[index];
            if *cancelled.borrow() {
                break;
            }
            let mut options = node_options(args, index);
            options.max_batches = budget(args, rounds)?;
            let mut result = if node.depends_on.is_empty() {
                let mut result = states
                    .remove(&index)
                    .context("compute_graph_missing_source_state")?;
                synthesis::advance(&options, socket, cancelled, &mut result).await?;
                result
            } else {
                let parents = node
                    .depends_on
                    .iter()
                    .map(|id| {
                        let parent = loaded
                            .plan
                            .nodes
                            .iter()
                            .position(|node| &node.id == id)
                            .context("compute_graph_unknown_parent")?;
                        complete
                            .get(&parent)
                            .cloned()
                            .context("compute_graph_parent_incomplete")
                    })
                    .collect::<Result<Vec<_>>>()?;
                dependent(&options, socket, cancelled, loaded, index, parents).await?
            };
            add_rounds(&mut rounds, &result, args)?;
            result["graph_node"] = json!({"id":node.id,"question":node.question,"depends_on":node.depends_on,
                "plan_sha256":loaded.enrollment.plan_sha256});
            retain_result(&options.directory, &result)?;
            let done = result["complete"] == true;
            if done {
                complete.insert(
                    index,
                    serde_json::from_value(result["synthesized_answer"].clone())?,
                );
            }
            states.insert(index, result);
            // Dependency frontiers are ordered; unresolved jobs retain their exclusive peer capacity.
            if !done {
                break;
            }
        }
    }
    let summaries = summarize_nodes(loaded, &states, &complete);
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
    let mut result = json!({"version":2,"operation":"compute_public_task_graph","complete":output.is_some(),
        "answer_complete":output.is_some(),"execution_complete":states.len()==loaded.plan.nodes.len()
            && states.values().all(|state| state["execution_complete"]==true),"semantic_completeness_proven":false,
        "plan_sha256":loaded.enrollment.plan_sha256,"plan":loaded.plan,"nodes":summaries,"output":output,
        "source_manifest_id":loaded.authority.source_manifest_id,"source_expires_unix_seconds":loaded.authority.expires_at_unix_seconds,
        "provider_keys":loaded.authority.provider_keys,"rounds_this_invocation":rounds,"interrupted":*cancelled.borrow(),
        "scheduling":"shared_source_queue_then_ordered_dependency_frontiers",
        "private_data_supported":false,"automatic_task_planning":false,"external_actions_supported":false,
        "model_answer_correctness_proven":false,"full_b03_claimed":false});
    if loaded.enrollment.planner.is_some() {
        result["automatic_task_planning"] = true.into();
        result["planning"] = planner::summary(loaded.enrollment.planner.as_ref());
    }
    attach_provenance(&args.directory, loaded, output, &mut result)?;
    Ok(result)
}

fn summarize_nodes(
    loaded: &Loaded,
    states: &BTreeMap<usize, Value>,
    complete: &BTreeMap<usize, synthesis::Answer>,
) -> Vec<Value> {
    loaded.plan.nodes.iter().enumerate().map(|(index, node)| {
        json!({"id":node.id,"question":node.question,"depends_on":node.depends_on,
            "complete":complete.contains_key(&index),"status":if complete.contains_key(&index) { "complete" }
                else if states.get(&index).is_some_and(|state| state["execution_complete"] == true) { "incomplete_answer" }
                else if states.contains_key(&index) { "pending" } else { "awaiting_dependencies" },
            "execution_complete":states.get(&index).is_some_and(|state| state["execution_complete"] == true),
            "answer_status":if complete.contains_key(&index) { "eos" }
                else if states.get(&index).is_some_and(super::output::has_legacy_unknown) { "legacy_unknown" }
                else { "incomplete" },
            "answer":complete.get(&index)})
    }).collect()
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

async fn dependent(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
    loaded: &Loaded,
    index: usize,
    parents: Vec<synthesis::Answer>,
) -> Result<Value> {
    if !storage::present(&args.directory)? {
        use std::os::unix::fs::DirBuilderExt as _;
        std::fs::DirBuilder::new()
            .mode(0o700)
            .create(&args.directory)?;
    }
    private_directory(&args.directory)?;
    let path = args.directory.join("source.manifest");
    if path.try_exists()? {
        ensure!(
            read_file(&path, volparossa_content::MAX_MANIFEST_BYTES)? == loaded.source,
            "compute_graph_source_changed"
        );
    } else {
        task::write_bytes(&path, &loaded.source, false)?;
    }
    let input = Input {
        version: 1,
        synthesis: false,
        visibility: "public".into(),
        license: loaded.input.license.clone(),
        document: loaded.input.document.clone(),
        question: loaded.plan.nodes[index].question.clone(),
    };
    let mut result = json!({"version":2,"operation":"compute_graph_dependency","complete":false,
        "execution_complete":false,"answer_complete":false,"rounds_this_invocation":0,
        "source_manifest_id":loaded.authority.source_manifest_id,"public_question":input.question,
        "model_answer_correctness_proven":false});
    synthesis::advance_frontier(
        args,
        socket,
        cancelled,
        &mut result,
        &loaded.authority,
        &input,
        parents,
        true,
    )
    .await?;
    Ok(result)
}

#[cfg(test)]
mod tests;
