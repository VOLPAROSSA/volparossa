//! Dependency-ready work shares one incremental provider-lease owner.

use super::super::super::batch;
use super::*;
use std::os::unix::fs::DirBuilderExt as _;

struct Work {
    node: usize,
    owner: workflow::ReadyWork,
}

#[derive(Default)]
struct Scan {
    states: BTreeMap<usize, Value>,
    complete: BTreeMap<usize, synthesis::Answer>,
    ready: Vec<(usize, workflow::Options)>,
}

fn snapshot(works: &[Work], path: &Path, expected: &workflow::ExpectedTask) -> Result<Value> {
    if let Some(work) = works.iter().find(|work| work.owner.directory() == path) {
        work.owner.snapshot(expected)
    } else {
        workflow::task_snapshot_detailed(path, expected)
    }
}

fn source_state(
    args: &Options,
    reader: &dyn Fn(&Path, &workflow::ExpectedTask) -> Result<Value>,
) -> Result<(Value, Vec<workflow::Options>)> {
    let (enrollment, input, plan) = storage::load(&args.directory)?;
    let providers = enrollment
        .provider_keys
        .iter()
        .map(|key| super::super::parse_key(key).map_err(anyhow::Error::msg))
        .collect::<Result<Vec<_>>>()?;
    let mut packages = Vec::new();
    let mut answers = Vec::new();
    let mut ready = Vec::new();
    for (index, package) in enrollment.packages.iter().enumerate() {
        let root = args.directory.join(format!("package-{index:04}"));
        let expected = storage::expected(&root, &enrollment, package, &input, &plan)?;
        let work = root.join("work");
        let exists = storage::present(&work)?;
        let snapshot = if exists {
            Some(reader(&work, &expected)?)
        } else {
            None
        };
        let complete = snapshot
            .as_ref()
            .is_some_and(|value| value["complete"] == true);
        if let Some(snapshot) = snapshot {
            storage::join_answers(&snapshot, package, &input, &plan, &mut answers)?;
        }
        if !complete {
            ready.push(
                workflow::Options::task(
                    (!exists).then(|| root.join("workflow-plan.json")),
                    work,
                    providers.clone(),
                    args.max_batches,
                    args.max_seconds,
                    true,
                )
                .expect_task(expected),
            );
        }
        packages.push(
            json!({"package_index":index,"manifest_id":package.manifest_id,"complete":complete,
            "first_part":package.first_part,"parts":package.rows}),
        );
    }
    let execution_complete = packages.iter().all(|package| package["complete"] == true)
        && answers.len() == plan.parts.len();
    let complete = execution_complete && super::super::output::all_complete(&answers)?;
    Ok((
        json!({"version":2,"operation":"compute_public_document","complete":complete,
        "execution_complete":execution_complete,"answer_complete":complete,"semantic_completeness_proven":false,
        "source_manifest_id":enrollment.source_manifest_id,"source_sha256":plan.source_sha256,
        "source_bytes":plan.source_bytes,"public_question":input.question,"license":input.license,
        "total_parts":plan.parts.len(),"packages":packages,"answers":answers,"rounds_this_invocation":0,
        "joining":"ordered_source_ranges_not_neural_synthesis","synthesis_requested":true,
        "source_selection_uses_cache_inventory":false,"private_data_supported":false,
        "model_answer_correctness_proven":false,"full_b03_claimed":false}),
        ready,
    ))
}

async fn dependent(
    args: &Options,
    cancelled: &watch::Receiver<bool>,
    loaded: &Loaded,
    index: usize,
    parents: Vec<synthesis::Answer>,
    reader: &dyn Fn(&Path, &workflow::ExpectedTask) -> Result<Value>,
) -> Result<(Value, Vec<workflow::Options>)> {
    let mut result = json!({"version":2,"operation":"compute_graph_dependency","complete":false,
        "execution_complete":false,"answer_complete":false,"semantic_completeness_proven":false,"rounds_this_invocation":0,
        "source_manifest_id":loaded.authority.source_manifest_id,"public_question":loaded.plan.nodes[index].question,
        "model_answer_correctness_proven":false});
    if !storage::present(&args.directory)? {
        if args.max_batches == 0 || *cancelled.borrow() {
            return Ok((result, Vec::new()));
        }
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
    } else if args.max_batches == 0 || *cancelled.borrow() {
        ensure!(
            !storage::present(&args.directory.join("synthesis"))?,
            "compute_graph_source_missing"
        );
        return Ok((result, Vec::new()));
    } else {
        task::write_bytes(&path, &loaded.source, false)?;
    }
    let input = Input {
        version: 1,
        model_profile: loaded.input.model_profile,
        synthesis: false,
        original_source: None,
        visibility: "public".into(),
        license: loaded.input.license.clone(),
        document: loaded.input.document.clone(),
        question: loaded.plan.nodes[index].question.clone(),
    };
    let ready = synthesis::prepare_frontier(
        args,
        cancelled,
        &mut result,
        &loaded.authority,
        &input,
        parents,
        true,
        reader,
    )
    .await?;
    Ok((result, ready))
}

async fn scan(
    args: &Options,
    cancelled: &watch::Receiver<bool>,
    loaded: &Loaded,
    works: &[Work],
    available: u16,
) -> Result<Scan> {
    let mut scan = Scan::default();
    let reader = |path: &Path, expected: &workflow::ExpectedTask| snapshot(works, path, expected);
    for index in loaded.plan.topological()? {
        let node = &loaded.plan.nodes[index];
        let mut options = node_options(args, index);
        // Replay the enrolled contract; absence means historical answers-only synthesis.
        options.grounded_synthesis = loaded.enrollment.grounded_synthesis;
        options.max_batches = available;
        options.follow.follow = false;
        let (mut result, ready) = if node.depends_on.is_empty() {
            let (mut result, mut ready) = source_state(&options, &reader)?;
            if result["execution_complete"] == true {
                ready.extend(synthesis::prepare(&options, cancelled, &mut result, &reader).await?);
            }
            (result, ready)
        } else {
            let parents = node
                .depends_on
                .iter()
                .map(|id| {
                    let parent = loaded.plan.nodes.iter().position(|node| &node.id == id)?;
                    scan.complete.get(&parent).cloned()
                })
                .collect::<Option<Vec<_>>>();
            let Some(parents) = parents else { continue };
            dependent(&options, cancelled, loaded, index, parents, &reader).await?
        };
        result["rounds_this_invocation"] = works
            .iter()
            .filter(|work| work.node == index)
            .map(|work| u64::from(work.owner.rounds()))
            .sum::<u64>()
            .into();
        result["graph_node"] = json!({"id":node.id,"question":node.question,"depends_on":node.depends_on,
            "plan_sha256":loaded.enrollment.plan_sha256});
        if result["complete"] == true {
            scan.complete.insert(
                index,
                serde_json::from_value(result["synthesized_answer"].clone())?,
            );
        }
        if options.directory.try_exists()? {
            retain_result(&options.directory, &result)?;
        }
        scan.states.insert(index, result);
        scan.ready
            .extend(ready.into_iter().map(|ready| (index, ready)));
    }
    Ok(scan)
}

fn rounds(works: &[Work]) -> u16 {
    works.iter().map(|work| work.owner.rounds()).sum()
}

fn reserve(driver: &mut batch::ReadyCohort, works: &[Work]) -> Result<()> {
    for work in works {
        driver.reserve(&work.owner.reservations())?;
    }
    Ok(())
}

fn register(
    works: &mut Vec<Work>,
    ready: Vec<(usize, workflow::Options)>,
    window_budget: u16,
) -> Result<()> {
    for (node, options) in ready {
        if let Some(work) = works
            .iter()
            .find(|work| work.owner.directory() == options.directory())
        {
            ensure!(node == work.node, "compute_graph_workflow_node_changed");
            work.owner.verify_selection(&options)?;
        } else {
            works.push(Work {
                node,
                owner: workflow::ReadyWork::open(options, window_budget)?,
            });
        }
    }
    Ok(())
}

fn completed(
    slot: usize,
    result: Result<Value>,
    slots: &mut BTreeMap<usize, usize>,
    works: &mut [Work],
    cancelled: bool,
) -> Result<()> {
    let work = slots
        .remove(&slot)
        .context("compute_graph_unowned_completion")?;
    works[work].owner.completed(result, cancelled)
}

fn terminal_answer_failure(states: &BTreeMap<usize, Value>) -> bool {
    states.values().any(|state| {
        matches!(
            state["synthesis"]["reason"].as_str(),
            Some(
                "legacy_generation_end_unknown"
                    | "worker_output_hit_token_limit"
                    | "worker_output_was_wire_truncated"
                    | "worker_produced_empty_answer"
            )
        )
    })
}

#[cfg(test)]
#[test]
fn terminal_answers_stop_follow_but_running_jobs_do_not() {
    for reason in [
        "legacy_generation_end_unknown",
        "worker_output_hit_token_limit",
        "worker_output_was_wire_truncated",
        "worker_produced_empty_answer",
    ] {
        let states = BTreeMap::from([
            (
                0,
                json!({"execution_complete":true,"synthesis":{"reason":reason}}),
            ),
            (
                1,
                json!({"execution_complete":false,"synthesis":{"reason":"peer_work_pending"}}),
            ),
        ]);
        assert!(terminal_answer_failure(&states));
    }
    for reason in ["peer_work_pending", "invocation_round_budget", "cancelled"] {
        assert!(!terminal_answer_failure(&BTreeMap::from([(
            0,
            json!({"synthesis":{"reason":reason}}),
        )])));
    }
}

/// One bounded window, with dynamic dependencies admitted to the same live lease table.
/// Always drain before releasing workflow locks, including on local preparation failures.
#[allow(
    clippy::too_many_lines,
    reason = "One owner scopes preparation, live completions, recovery and mandatory drain"
)]
pub(super) async fn window(
    args: &Options,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
    loaded: &Loaded,
) -> Result<Value> {
    let mut driver = batch::ReadyCohort::new(&[], socket, cancelled)?;
    let mut works = Vec::<Work>::new();
    let mut slots = BTreeMap::new();
    let execution = async {
        // Discover every already-prepared frontier before admitting any new work, so
        // even out-of-window original handles reserve their provider slots from the start.
        let initial = scan(args, cancelled, loaded, &works, 0).await?;
        if args.max_batches > 0 && !*cancelled.borrow() {
            register(&mut works, initial.ready, args.max_batches)?;
        }
        reserve(&mut driver, &works)?;
        loop {
            let available = args
                .max_batches
                .checked_sub(rounds(&works))
                .context("compute_graph_invocation_budget")?;
            let scanned = scan(args, cancelled, loaded, &works, available).await?;
            if scanned.complete.len() == loaded.plan.nodes.len() {
                break;
            }
            if available > 0 && !*cancelled.borrow() {
                register(&mut works, scanned.ready, args.max_batches)?;
                reserve(&mut driver, &works)?;
                let mut options = Vec::new();
                let mut owners = Vec::new();
                for (index, work) in works.iter_mut().enumerate() {
                    if options.len() == usize::from(available) {
                        break;
                    }
                    if let Some(ready) = work.owner.ready(socket, cancelled).await? {
                        options.push(ready);
                        owners.push(index);
                    }
                }
                if !options.is_empty() {
                    let admitted = driver.append(options).await?;
                    ensure!(
                        admitted.len() == owners.len(),
                        "compute_graph_admission_count"
                    );
                    slots.extend(admitted.into_iter().zip(owners));
                }
            }
            if let Some((slot, result)) = driver.next_completed().await? {
                completed(slot, result, &mut slots, &mut works, *cancelled.borrow())?;
                continue;
            }
            // No live shared-driver future remains. Preserve the existing sequential
            // stopped/expired retry authority for old handles, excluding all other leases.
            let mut recovered = false;
            if rounds(&works) < args.max_batches && !*cancelled.borrow() {
                for index in 0..works.len() {
                    let external = works
                        .iter()
                        .enumerate()
                        .filter(|(other, _)| *other != index)
                        .flat_map(|(_, work)| work.owner.reservations())
                        .collect::<Vec<_>>();
                    if works[index]
                        .owner
                        .recover(&external, socket, cancelled)
                        .await?
                    {
                        recovered = true;
                        reserve(&mut driver, &works)?;
                        break;
                    }
                }
            }
            if !recovered {
                break;
            }
        }
        Ok::<_, anyhow::Error>(())
    }
    .await;
    let drained = driver.cancel_and_drain().await;
    let mut completion_failure = None;
    match drained {
        Ok(drained) => {
            for (slot, result) in drained {
                if let Err(error) = completed(slot, result, &mut slots, &mut works, true) {
                    completion_failure.get_or_insert(error);
                }
            }
        }
        Err(error) => {
            completion_failure.get_or_insert(error);
        }
    }
    execution?;
    if let Some(error) = completion_failure {
        return Err(error);
    }
    let scanned = scan(args, cancelled, loaded, &works, 0).await?;
    let mut result = summarize(
        args,
        cancelled,
        loaded,
        u64::from(rounds(&works)),
        &scanned.states,
        &scanned.complete,
    )?;
    let reports = works
        .iter()
        .map(|work| work.owner.report(*cancelled.borrow()))
        .collect::<Result<Vec<_>>>()?;
    result["stopped"] = if result["complete"] == true {
        "complete"
    } else if *cancelled.borrow() {
        "interrupted_handles_retained"
    } else if terminal_answer_failure(&scanned.states) {
        "answer_incomplete_no_new_work"
    } else if loaded.authority.expires_at_unix_seconds <= super::super::now()? {
        "source_expired_new_signed_package_required"
    } else if reports
        .iter()
        .any(|report| report["stopped"] == "attempt_storage_bound")
    {
        "attempt_storage_bound"
    } else {
        "pending_handles_retained_no_busy_retry_loop"
    }
    .into();
    result["pending_failure"] = (result["complete"] != true).into();
    Ok(result)
}
