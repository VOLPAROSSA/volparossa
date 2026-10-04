//! Synthetic model outputs with actual signed sources, framed RPC and durable receipts.

use super::*;

#[test]
fn old_enrollments_keep_exact_single_level_serialization() {
    let fixture = fixture();
    let bytes = serde_json::to_vec(&fixture.enrollment).unwrap();
    let mut value: Value = serde_json::from_slice(&bytes).unwrap();
    assert!(value.get("refinement_levels").is_none());
    let legacy: super::super::super::storage::Enrollment = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(legacy.refinement_levels, 1);
    assert_eq!(serde_json::to_vec(&legacy).unwrap(), bytes);
    value["refinement_levels"] = 2.into();
    let deeper: super::super::super::storage::Enrollment = serde_json::from_value(value).unwrap();
    assert_eq!(deeper.refinement_levels, 2);
    assert_ne!(serde_json::to_vec(&deeper).unwrap(), bytes);
}

#[test]
fn retained_level_authority_rejects_disabled_refinement_or_out_of_range_depth() {
    let fixture = fixture();
    for (levels, enabled) in [(0, true), (5, true), (2, false)] {
        let mut value = serde_json::to_value(&fixture.enrollment).unwrap();
        value["refinement_levels"] = levels.into();
        value["refine_incomplete"] = enabled.into();
        super::super::super::save(fixture.root.path(), "document.json", &value, true).unwrap();
        assert!(super::super::super::storage::load(fixture.root.path()).is_err());
    }
    super::super::super::save(
        fixture.root.path(),
        "document.json",
        &fixture.enrollment,
        true,
    )
    .unwrap();
    assert!(super::super::super::storage::load(fixture.root.path()).is_ok());
}

async fn run_originals(
    fixture: &Fixture,
    socket: &Path,
    cancelled: &watch::Receiver<bool>,
) -> Vec<synthesis::Answer> {
    let root = fixture.root.path().join("package-0000");
    let expected = super::super::super::storage::expected(
        &root,
        &fixture.enrollment,
        &fixture.enrollment.packages[0],
        &fixture.input,
        &fixture.plan,
    )
    .unwrap();
    let options = workflow::Options::task(
        Some(root.join("workflow-plan.json")),
        root.join("work"),
        fixture
            .enrollment
            .provider_keys
            .iter()
            .map(|key| parse_key(key).unwrap())
            .collect(),
        4,
        600,
        true,
    )
    .expect_task(expected);
    let report = workflow::report_group_with_activity(
        &[options],
        4,
        &super::super::super::super::follow::Options::default(),
        socket,
        cancelled,
    )
    .await
    .unwrap();
    assert_eq!(report["complete"], true);
    synthesis::leaf_answers(
        fixture.root.path(),
        &fixture.enrollment,
        &fixture.input,
        &fixture.plan,
    )
    .unwrap()
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "A joined RPC lifecycle checks bounded grandchildren, cancel, resume and receipt-only replay"
)]
async fn limited_child_refines_again_without_resubmitting_complete_source_or_siblings() {
    let mut fixture = fixture();
    fixture.enrollment.refinement_levels = 2;
    super::super::super::save(
        fixture.root.path(),
        "document.json",
        &fixture.enrollment,
        true,
    )
    .unwrap();
    let sockets = tempfile::tempdir().unwrap();
    let socket = sockets.path().join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let submissions = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let server = tokio::spawn(serve_protocol_fixture(
        listener,
        fixture.enrollment.packages[0].manifest_id.clone(),
        submissions.clone(),
        true,
    ));
    let (owner, cancelled) = watch::channel(false);
    let originals = run_originals(&fixture, &socket, &cancelled).await;
    assert_eq!(submissions.lock().unwrap().len(), 2);
    let children = retain_children(&fixture, &originals[0]);
    let original_view = json!({"execution_complete":true,"complete":false,"rounds_this_invocation":0,
        "answers":["Original public projection remains unchanged."]});
    let mut args = options(fixture.root.path());
    args.max_batches = 2;
    let mut result = original_view.clone();
    assert!(
        advance(&args, &socket, &cancelled, &mut result)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(result["refinement"]["version"], 2);
    assert_eq!(result["refinement"]["reason"], "round_budget_exhausted");
    assert_eq!(result["rounds_this_invocation"], 2);
    assert_eq!(submissions.lock().unwrap().len(), 4);
    assert_eq!(
        result["refinement"]["parents"][0]["children"][0]["generation"]["stop_reason"],
        "token_limit"
    );
    assert_eq!(
        result["refinement"]["parents"][0]["children"][1]["generation"]["stop_reason"],
        "eos"
    );
    assert!(!children[0].join("refinement").exists());
    let original_and_child_receipts = retained_receipts(fixture.root.path());
    assert_eq!(original_and_child_receipts.len(), 4);

    // Seed only synthetic tokenizer plans and genuinely signed publications for
    // the grandchildren; their parents come from the actual checked child receipt.
    let root = fixture.root.path().join("refinement/leaf-0000");
    let ranges = halves(&fixture.input, &originals[0]).unwrap().unwrap();
    let intent = storage::intent(
        &root,
        &fixture.enrollment,
        &fixture.input,
        &originals[0],
        0,
        ranges,
    )
    .unwrap();
    let prepared = storage::prepare_child(
        &args,
        &children[0],
        &fixture.enrollment,
        &fixture.input,
        &intent,
        0,
        ranges[0],
        &cancelled,
        false,
    )
    .await
    .unwrap()
    .unwrap();
    let snapshot = storage::snapshot(&prepared).unwrap().unwrap();
    let child = synthesis::Answer::from_output(
        &snapshot["outputs"][0],
        &prepared.expected.manifest_id,
        prepared.range.0,
        prepared.range.1,
    )
    .unwrap();
    assert!(eligible(&child) && !complete(&child));
    let grandchildren = retain_children_at(&fixture, &child, &children[0].join("refinement"));

    args.max_batches = 1;
    owner.send(true).unwrap();
    result = original_view.clone();
    assert!(
        advance(&args, &socket, &cancelled, &mut result)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(result["interrupted"], true);
    assert_eq!(submissions.lock().unwrap().len(), 4);
    assert!(grandchildren.iter().all(|path| !path.join("work").exists()));
    owner.send(false).unwrap();

    result = original_view.clone();
    assert!(
        advance(&args, &socket, &cancelled, &mut result)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(result["rounds_this_invocation"], 1);
    assert_eq!(submissions.lock().unwrap().len(), 5);
    let first_grandchild = retained_receipts(&children[0].join("refinement"));
    assert_eq!(first_grandchild.len(), 1);
    result = original_view.clone();
    let frontier = advance(&args, &socket, &cancelled, &mut result)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(submissions.lock().unwrap().len(), 6);
    assert_eq!(result["rounds_this_invocation"], 1);
    assert_eq!(result["refinement"]["complete"], true);
    assert_eq!(result["refinement"]["refined_leaves"], 1);
    assert_eq!(result["refinement"]["retained_splits"], 2);
    assert_eq!(result["refinement"]["remaining_splits"], 14);
    assert_eq!(result["refinement"]["deepest_level"], 2);
    assert_eq!(result["refinement"]["parents"][0]["complete"], false);
    assert_eq!(
        result["refinement"]["descendants"][0]["address"],
        json!([0])
    );
    assert_eq!(result["refinement"]["descendants"][0]["complete"], true);
    assert_eq!(frontier.len(), 4);
    assert!(frontier.iter().all(complete));
    assert_eq!(frontier.last(), originals.last());
    assert_eq!(result["answers"], original_view["answers"]);
    for (path, bytes) in original_and_child_receipts.iter().chain(&first_grandchild) {
        assert_eq!(fs::read(path).unwrap(), *bytes);
    }
    server.abort();
    let _ = server.await;

    args.max_batches = 0;
    result = original_view.clone();
    let absent = sockets.path().join("no-agent.sock");
    assert_eq!(
        advance(&args, &absent, &cancelled, &mut result)
            .await
            .unwrap()
            .unwrap(),
        frontier
    );
    assert_eq!(result["rounds_this_invocation"], 0);
    let (receipt, bytes) = &first_grandchild[0];
    fs::remove_file(receipt).unwrap();
    result = original_view.clone();
    assert!(
        advance(&args, &absent, &cancelled, &mut result)
            .await
            .unwrap()
            .is_none()
    );
    assert_eq!(result["refinement"]["answers"], json!([]));
    assert_eq!(result["execution_complete"], false);
    task::write_bytes(receipt, bytes, false).unwrap();
}
