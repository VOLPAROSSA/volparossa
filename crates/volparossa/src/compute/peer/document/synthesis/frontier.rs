//! Preparation and receipt reconstruction for one externally owned shared peer queue.
//! No function here creates a second coordinator or waits for peer jobs to finish.

#[allow(
    clippy::wildcard_imports,
    reason = "Private synthesis implementation shares its parent's exact types and checks"
)]
use super::*;

pub(in crate::compute::peer::document) async fn prepare(
    args: &Options,
    cancelled: &watch::Receiver<bool>,
    result: &mut Value,
    snapshot: &dyn Fn(&Path, &workflow::ExpectedTask) -> Result<Value>,
) -> Result<Vec<workflow::Options>> {
    let (enrollment, input, plan) = document_storage::load(&args.directory)?;
    ensure!(enrollment.synthesize, "compute_synthesis_not_enrolled");
    let frontier =
        leaf_answers_with_snapshot(&args.directory, &enrollment, &input, &plan, snapshot)?;
    prepare_frontier(
        args,
        cancelled,
        result,
        &enrollment,
        &input,
        frontier,
        false,
        snapshot,
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "One receipt-derived traversal prepares work without acquiring peer slots"
)]
pub(in crate::compute::peer::document) async fn prepare_frontier(
    args: &Options,
    cancelled: &watch::Receiver<bool>,
    result: &mut Value,
    enrollment: &document_storage::Enrollment,
    input: &super::super::Input,
    mut frontier: Vec<Answer>,
    force_first: bool,
    snapshot: &dyn Fn(&Path, &workflow::ExpectedTask) -> Result<Value>,
) -> Result<Vec<workflow::Options>> {
    ensure!(
        enrollment.scheduling == workflow::Scheduling::ReadyRowsV1,
        "compute_synthesis_external_queue_requires_ready_rows"
    );
    ensure!(!frontier.is_empty(), "compute_synthesis_frontier_empty");
    let providers = enrollment
        .provider_keys
        .iter()
        .map(|key| parse_key(key).map_err(anyhow::Error::msg))
        .collect::<Result<Vec<_>>>()?;
    let mut levels = Vec::new();
    let root = args.directory.join("synthesis");
    if document_storage::present(&root)? {
        private_directory(&root)?;
    }
    for level in 1..=MAX_LEVELS + 1 {
        if let Some(reason) = unusable(&frontier) {
            unfinished(reason, &levels, result);
            return Ok(Vec::new());
        }
        if frontier.len() == 1 && (!force_first || level > 1) {
            complete_answer(&frontier[0], &levels, result)?;
            return Ok(Vec::new());
        }
        if level > MAX_LEVELS {
            break;
        }
        let mut ready = Vec::new();
        let mut next = Vec::new();
        let mut groups = Vec::new();
        let mut pending = Vec::new();
        let mut level_complete = true;
        for (group, parents) in frontier.chunks(PARENTS_PER_GROUP).enumerate() {
            let directory = root.join(format!("level-{level:02}-group-{group:04}"));
            let allow_new = args.max_batches > 0 && !*cancelled.borrow();
            let prepared = if allow_new {
                storage::directory(&root)?;
                Some(
                    storage::prepare(
                        args,
                        &directory,
                        enrollment,
                        input,
                        parents,
                        group * PARENTS_PER_GROUP,
                        level,
                        cancelled,
                    )
                    .await?,
                )
            } else {
                storage::restore(
                    args,
                    &directory,
                    enrollment,
                    input,
                    parents,
                    group * PARENTS_PER_GROUP,
                    level,
                )?
            };
            let Some(prepared) = prepared else {
                level_complete = false;
                groups.push(
                    json!({"group":group,"parents":parents.len(),"complete":false,
                    "reason":"group_preparation_pending"}),
                );
                pending.push(json!({"group":group,"reason":"group_preparation_pending"}));
                continue;
            };
            let mut group_complete = true;
            for (index, dataset) in prepared.datasets.iter().enumerate() {
                let package = directory.join(format!("package-{index:04}"));
                let work = package.join("work");
                let established = document_storage::present(&work)?;
                let mut published = true;
                for name in ["dataset.json", "dataset.manifest", "workflow-plan.json"] {
                    published &= storage::file_present(&package.join(name))?;
                }
                if !published {
                    ensure!(
                        !established,
                        "compute_synthesis_existing_work_missing_publication"
                    );
                    group_complete = false;
                    pending.push(
                        json!({"group":group,"package":index,"reason":"publication_pending"}),
                    );
                    continue;
                }
                private_directory(&package)?;
                let expected = storage::expected(&package, enrollment, &prepared, dataset, index)?;
                let checked = if established {
                    Some(snapshot(&work, &expected)?)
                } else {
                    None
                };
                if let Some(snapshot) = checked.filter(|snapshot| snapshot["complete"] == true) {
                    next.extend(reduction_answers(
                        &snapshot,
                        &expected.manifest_id,
                        dataset,
                    )?);
                    continue;
                }
                group_complete = false;
                pending.push(json!({"group":group,"package":index,"reason":"peer_work_pending"}));
                // Include ALL retained pending packages, also during a zero-budget scan.
                // The external owner applies its global admission and attempt limits.
                ready.push(
                    workflow::Options::task(
                        (!established).then(|| package.join("workflow-plan.json")),
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
            level_complete &= group_complete;
            groups.push(
                json!({"group":group,"parents":parents.len(),"complete":group_complete,
                "parts":prepared.parts,"input_sha256":prepared.input_sha256}),
            );
        }
        if !level_complete {
            levels.push(json!({"level":level,"complete":false,"groups":groups}));
            result["interrupted"] = (*cancelled.borrow()).into();
            unfinished(
                if *cancelled.borrow() {
                    "cancelled"
                } else if ready.is_empty() && args.max_batches == 0 {
                    "invocation_round_budget"
                } else {
                    "peer_work_pending"
                },
                &levels,
                result,
            );
            result["synthesis"]["pending_work"] = pending.into();
            return Ok(ready);
        }
        let record = json!({"level":level,"complete":true,"parents":frontier.len(),
            "outputs":next.len(),"groups":groups,"answers":next,
            "generation_limit_reached":next.iter().any(|answer| answer.generated_tokens == 64)});
        let name = format!("level-{level:02}-result.json");
        if args.max_batches > 0 && !*cancelled.borrow() {
            storage::retain_json(&root, &name, &record)?;
        } else if storage::file_present(&root.join(&name))? {
            ensure!(
                crate::compute::read_file(
                    &root.join(&name),
                    super::super::MAX_RESULT_BYTES as u64
                )? == serde_json::to_vec(&record)?,
                "compute_synthesis_retained_input_changed"
            );
        }
        levels.push(record);
        if next.len() >= frontier.len() && !(force_first && level == 1) {
            unfinished(
                "reduction_did_not_shrink_no_inputs_discarded",
                &levels,
                result,
            );
            return Ok(Vec::new());
        }
        frontier = next;
    }
    unfinished("hierarchy_budget_no_inputs_discarded", &levels, result);
    Ok(Vec::new())
}
