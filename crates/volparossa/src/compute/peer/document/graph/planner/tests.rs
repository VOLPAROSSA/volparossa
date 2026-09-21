//! Pure retained-protocol and CLI fixtures; not evidence of model planning or answer quality.

use super::*;
use crate::compute::ModelProfile;
use clap::Parser;
use std::os::unix::fs::PermissionsExt as _;
use volparossa_content::agent_artifact::{BASE_MODEL_SHA256, MODEL_ID, MODEL_REVISION};

fn input(document: &str) -> task_plan::Input {
    task_plan::Input {
        model_profile: ModelProfile::default(),
        version: 1,
        visibility: "public".into(),
        license: "CC0-1.0".into(),
        question: "  Compare the opportunities and constraints.\n".into(),
        source_sha256: digest(document.as_bytes()),
        source_bytes: document.len() as u64,
        source_excerpt: None,
        plan_requirement: None,
    }
}

#[test]
fn requested_internal_dependency_is_not_satisfied_by_the_local_terminal_join() {
    let document = "Constraints and alternatives are explicitly public.";
    let mut input = input(document);
    input.version = 3;
    input.source_excerpt = Some(task_plan::SourceExcerpt::prefix(document));
    let singleton = task_plan::ModelTaskGraph::decode(
        br#"{"version":3,"tasks":[{"question":"Which constraints apply?","depends_on":[]}]}"#,
        &input.question,
    )
    .unwrap();
    assert_eq!(graph_proposal(&input, &singleton).unwrap().nodes.len(), 2);
    input.plan_requirement = Some(task_plan::PlanRequirement::DependentAnalysisV1);
    assert!(graph_proposal(&input, &singleton).is_err());
    let dependent = task_plan::ModelTaskGraph::decode(
        br#"{"version":3,"tasks":[{"question":"Which constraints apply?","depends_on":[]},{"question":"How do those constraints affect the choices?","depends_on":[0]}]}"#,
        &input.question,
    ).unwrap();
    let plan = graph_proposal(&input, &dependent).unwrap();
    assert_eq!(plan.nodes[1].question, dependent.tasks[1].question);
    assert_eq!(plan.nodes[1].depends_on, ["question-00"]);
    assert_eq!(plan.nodes.last().unwrap().question, input.question);
}

#[test]
fn terminal_failure_retains_post_cleanup_trace_without_enrollment_or_overwrite() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let input = input("Explicit public source.");
    let bytes = serde_json::to_vec(&input).unwrap();
    retain_failure(
        root.path(),
        &input,
        &bytes,
        &anyhow::anyhow!("compute_reap"),
    )
    .unwrap();
    verify_absent(root.path()).unwrap();
    let diagnostic = json!({"strategy":"model_questions_scaffold_recovery_v2",
        "attempts":[],"incomplete_attempt":true});
    let failure = compute::supervise::test_worker_failure_with_diagnostic(
        "BACKEND_EXECUTION_FAILED",
        Some(diagnostic.clone()),
    );
    retain_failure(root.path(), &input, &bytes, &failure).unwrap();
    let saved = read_file(&root.path().join("planner-failure.json"), MAX_REPORT_BYTES).unwrap();
    let report: Value = serde_json::from_slice(&saved).unwrap();
    assert_eq!(
        report,
        json!({
            "version":1,"operation":"compute_public_task_planning_failure",
            "request_id":"ab".repeat(16),"code":"BACKEND_EXECUTION_FAILED",
            "input_sha256":digest(&bytes),"source_sha256":input.source_sha256,
            "source_bytes":input.source_bytes,"planner_diagnostic":diagnostic,
            "child_reaped":true,"plan_enrolled":false
        })
    );
    assert!(!root.path().join("planner-report.json").exists());
    assert!(!root.path().join("graph.json").exists());
    assert!(verify_absent(root.path()).is_err());
    assert!(retain_failure(root.path(), &input, &bytes, &failure).is_err());
    assert_eq!(
        read_file(&root.path().join("planner-failure.json"), MAX_REPORT_BYTES).unwrap(),
        saved
    );
}

fn questions(count: usize) -> task_plan::Questions {
    task_plan::Questions {
        version: 1,
        questions: (0..count)
            .map(|index| format!("What does the public source say about aspect {index}?"))
            .collect(),
    }
}

fn report(input: &task_plan::Input, bytes: &[u8], artifact: &[u8]) -> Value {
    json!({"version":1,"id":"ab".repeat(16),"kind":"result","status":"ok",
        "mode":"plan_tasks","device":"cpu","threads":2,"updates_completed":0,
        "model_weights_loaded":true,"goal_only_planning":true,"generation_limit_reached":false,
        "model_answer_correctness_proven":false,"planner_prompt_tokens":100,"planner_generated_tokens":80,
        "planner_stop_reason":"two_questions",
        "planner_strategy":"model_questions_scaffold_v1","planner_structure_generated_by":"local_schema",
        "planner_question_stats":[
            {"prompt_tokens":80,"generated_tokens":40,"stop_reason":"question_boundary"},
            {"prompt_tokens":100,"generated_tokens":40,"stop_reason":"eos"}],
        "model":{"id":MODEL_ID,"revision":MODEL_REVISION,
            "files":{"model.safetensors":{"sha256":hex::encode(BASE_MODEL_SHA256)}}},
        "dataset":{"version":1,"sha256":digest(bytes),"bytes":bytes.len(),
            "visibility":"public","license":input.license,
            "question_sha256":digest(input.question.as_bytes()),
            "source_sha256":input.source_sha256,"source_bytes":input.source_bytes},
        "artifacts":[{"relative_path":"task-questions.json","bytes":artifact.len(),"sha256":digest(artifact)}],
        "supervisor":{"child_reaped":true,"network_access":false}})
}

fn retained(root: &Path) -> (Authority, plan::Plan, Input) {
    std::fs::set_permissions(root, std::fs::Permissions::from_mode(0o700)).unwrap();
    let document = "Explicit public source used only for protocol validation.";
    let input = input(document);
    let questions = questions(2);
    let plan = proposal(&input, &questions).unwrap();
    let bytes = serde_json::to_vec(&input).unwrap();
    let artifact = serde_json::to_vec(&questions).unwrap();
    let report = serde_json::to_vec(&report(&input, &bytes, &artifact)).unwrap();
    for (name, bytes) in [
        ("planner-input.json", &bytes),
        ("planner-report.json", &report),
        ("planner-artifact.json", &artifact),
    ] {
        task::write_bytes(&root.join(name), bytes, false).unwrap();
    }
    let authority = Authority {
        version: 1,
        input_sha256: digest(&bytes),
        report_sha256: digest(&report),
        artifact_sha256: digest(&artifact),
        question: input.question,
        source_sha256: input.source_sha256,
        source_bytes: input.source_bytes,
        source_excerpt: None,
    };
    let source = Input {
        model_profile: ModelProfile::default(),
        version: 1,
        visibility: "public".into(),
        license: "CC0-1.0".into(),
        document: document.into(),
        question: questions.questions[0].clone(),
        synthesis: false,
    };
    (authority, plan, source)
}

#[test]
fn model_questions_form_bounded_fork_join_with_exact_original_terminal_question() {
    let input = input("Explicit public source.");
    for count in [2, 3, 4] {
        let questions = questions(count);
        let plan = proposal(&input, &questions).unwrap();
        assert_eq!(plan.nodes.len(), count + 1);
        assert_eq!(plan.output, "answer");
        assert_eq!(plan.nodes[count].question, input.question);
        assert_eq!(
            plan.nodes[count].depends_on,
            (0..count)
                .map(|index| format!("question-{index:02}"))
                .collect::<Vec<_>>()
        );
        for (index, node) in plan.nodes[..count].iter().enumerate() {
            assert_eq!(node.question, questions.questions[index]);
            assert!(node.depends_on.is_empty());
        }
        assert_eq!(plan.topological().unwrap(), (0..=count).collect::<Vec<_>>());
    }
    for count in [0, 1, 5] {
        assert!(proposal(&input, &questions(count)).is_err());
    }
    let mut duplicate = questions(2);
    duplicate.questions[1] = duplicate.questions[0].clone();
    assert!(proposal(&input, &duplicate).is_err());
    let mut invalid = questions(2);
    invalid.questions[0] = "\0".into();
    assert!(proposal(&input, &invalid).is_err());
}

#[test]
fn model_graph_keeps_selected_edges_and_joins_only_terminal_branches() {
    let document = "An explicitly public source used only for graph protocol tests.";
    let mut input = input(document);
    input.version = 3;
    input.source_excerpt = Some(task_plan::SourceExcerpt::prefix(document));
    let graph = task_plan::ModelTaskGraph {
        version: 3,
        tasks: vec![
            task_plan::ModelTask {
                question: "What is the first constraint?".into(),
                depends_on: vec![],
            },
            task_plan::ModelTask {
                question: "What is the second constraint?".into(),
                depends_on: vec![],
            },
            task_plan::ModelTask {
                question: "How do these constraints compare?".into(),
                depends_on: vec![1, 0],
            },
            task_plan::ModelTask {
                question: "Which opportunities are described?".into(),
                depends_on: vec![],
            },
        ],
    };
    let plan = graph_proposal(&input, &graph).unwrap();
    assert_eq!(plan.nodes.len(), 5);
    assert_eq!(plan.nodes[2].depends_on, ["question-01", "question-00"]);
    assert_eq!(plan.nodes[4].depends_on, ["question-02", "question-03"]);
    assert_eq!(plan.nodes[4].question, input.question);
    for (actual, selected) in plan.nodes.iter().zip(&graph.tasks) {
        assert_eq!(actual.question, selected.question);
    }
    let single = task_plan::ModelTaskGraph {
        version: 3,
        tasks: vec![graph.tasks[0].clone()],
    };
    let plan = graph_proposal(&input, &single).unwrap();
    assert_eq!(plan.nodes.len(), 2);
    assert_eq!(plan.nodes[1].depends_on, ["question-00"]);
    let mut bad = graph;
    bad.tasks[2].depends_on = vec![3];
    assert!(graph_proposal(&input, &bad).is_err());
}

#[test]
fn model_graph_replay_uses_the_original_artifact_and_never_replans() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let document = "A public source for retained model-graph binding tests.";
    let mut input = input(document);
    input.version = 3;
    input.source_excerpt = Some(task_plan::SourceExcerpt::prefix(document));
    let artifact = br#"{"version":3,"tasks":[{"question":"Which limits apply?","depends_on":[]},{"question":"How do those limits affect use?","depends_on":[0]}]}"#;
    let bytes = serde_json::to_vec(&input).unwrap();
    let mut report = report(&input, &bytes, artifact);
    report["goal_only_planning"] = false.into();
    report["source_contents_read_by_planner"] = true.into();
    report["source_excerpt_complete"] = true.into();
    report["dataset"]["version"] = 3.into();
    let excerpt = input.source_excerpt.as_ref().unwrap();
    report["dataset"]["source_excerpt"] = json!({"start":0,"end":excerpt.end,
        "bytes":excerpt.text.len(),"sha256":excerpt.sha256});
    report["artifacts"][0]["relative_path"] = "task-graph.json".into();
    report["planner_strategy"] = task_plan::GRAPH_STRATEGY.into();
    report["planner_structure_generated_by"] = "model".into();
    report["planner_stop_reason"] = "task_graph".into();
    report["planner_task_count"] = 2.into();
    report["planner_dependency_count"] = 1.into();
    report
        .as_object_mut()
        .unwrap()
        .remove("planner_question_stats");
    report["planner_attempts"] = json!([{"attempt":1,"prompt_tokens":100,"generated_tokens":80,
        "max_new_tokens":384,"stop_reason":"graph_boundary","accepted":true,"rejection_code":null,
        "text_bytes":artifact.len(),"text_sha256":digest(artifact)}]);
    let plan = validated_proposal(&report, &input, &bytes, artifact).unwrap();
    let report_bytes = serde_json::to_vec(&report).unwrap();
    for (name, raw) in [
        ("planner-input.json", bytes.as_slice()),
        ("planner-report.json", report_bytes.as_slice()),
        ("planner-artifact.json", artifact.as_slice()),
    ] {
        task::write_bytes(&root.path().join(name), raw, false).unwrap();
    }
    let authority = Authority {
        version: 3,
        input_sha256: digest(&bytes),
        report_sha256: digest(&report_bytes),
        artifact_sha256: digest(artifact),
        question: input.question.clone(),
        source_sha256: input.source_sha256.clone(),
        source_bytes: input.source_bytes,
        source_excerpt: input.source_excerpt.as_ref().map(Coverage::from),
    };
    let source = Input {
        model_profile: ModelProfile::default(),
        version: 1,
        visibility: input.visibility,
        license: input.license,
        document: document.into(),
        question: plan.nodes[0].question.clone(),
        synthesis: false,
    };
    verify(root.path(), &authority, &plan, &source).unwrap();
    assert_eq!(
        summary(Some(&authority))["model_selected_dependencies"],
        true
    );
    let mut changed_plan = plan.clone();
    changed_plan.nodes[1].depends_on.clear();
    assert!(verify(root.path(), &authority, &changed_plan, &source).is_err());
    let original = read_file(
        &root.path().join("planner-artifact.json"),
        MAX_PLANNER_BYTES,
    )
    .unwrap();
    assert_eq!(original, artifact);
    assert!(!root.path().join("model-planner").exists());
    let mut changed_source = source;
    changed_source.model_profile = ModelProfile::Smol360;
    assert!(verify(root.path(), &authority, &plan, &changed_source).is_err());
}

#[test]
fn retained_planning_reopens_without_original_inputs_or_worker_output_and_rejects_mutation() {
    let root = tempfile::tempdir().unwrap();
    let (authority, plan, mut source) = retained(root.path());
    verify(root.path(), &authority, &plan, &source).unwrap();
    assert!(!root.path().join("model-planner").exists());
    for name in [
        "planner-input.json",
        "planner-report.json",
        "planner-artifact.json",
    ] {
        let path = root.path().join(name);
        let original = std::fs::read(&path).unwrap();
        let mut changed = original.clone();
        changed.push(b' ');
        task::write_bytes(&path, &changed, true).unwrap();
        assert!(verify(root.path(), &authority, &plan, &source).is_err());
        task::write_bytes(&path, &original, true).unwrap();
    }
    let mut changed_plan = plan.clone();
    changed_plan.nodes.last_mut().unwrap().question = "A substituted final goal?".into();
    assert!(verify(root.path(), &authority, &changed_plan, &source).is_err());
    let mut changed_authority = authority.clone();
    changed_authority.question = "A substituted owner question?".into();
    assert!(verify(root.path(), &changed_authority, &plan, &source).is_err());
    source.document.push_str(" Different source.");
    assert!(verify(root.path(), &authority, &plan, &source).is_err());
}

#[test]
fn a_rehashed_unreaped_or_wrong_source_planner_receipt_cannot_authorize_dispatch() {
    let root = tempfile::tempdir().unwrap();
    let (mut authority, plan, source) = retained(root.path());
    let path = root.path().join("planner-report.json");
    let original: Value = serde_json::from_slice(&std::fs::read(&path).unwrap()).unwrap();
    for mutation in ["reaped", "source", "truncated"] {
        let mut report = original.clone();
        match mutation {
            "reaped" => report["supervisor"]["child_reaped"] = false.into(),
            "source" => report["dataset"]["source_sha256"] = "cd".repeat(32).into(),
            _ => report["generation_limit_reached"] = true.into(),
        }
        let bytes = serde_json::to_vec(&report).unwrap();
        authority.report_sha256 = digest(&bytes);
        task::write_bytes(&path, &bytes, true).unwrap();
        assert!(verify(root.path(), &authority, &plan, &source).is_err());
    }
}

#[test]
fn legacy_manual_graphs_stay_manual_and_cannot_discard_present_planner_authority() {
    let legacy = json!({"version":1,"plan_sha256":"ab".repeat(32),"leaves":[]});
    let enrollment: super::super::Enrollment = serde_json::from_value(legacy.clone()).unwrap();
    assert!(enrollment.planner.is_none());
    assert_eq!(serde_json::to_value(enrollment).unwrap(), legacy);
    assert!(summary(None).is_null());
    let root = tempfile::tempdir().unwrap();
    verify_absent(root.path()).unwrap();
    let (authority, _, _) = retained(root.path());
    assert!(verify_absent(root.path()).is_err());
    let summary = summary(Some(&authority));
    assert_eq!(summary["kind"], "bounded_model_fork_join_decomposition");
    assert_eq!(summary["goal_only"], true);
    assert_eq!(summary["source_contents_read_by_planner"], false);
    assert_eq!(summary["decomposition_quality_proven"], false);
}

#[test]
fn grounded_authority_binds_literal_prefix_and_reports_partial_coverage() {
    let source = Input {
        model_profile: ModelProfile::default(),
        version: 1,
        visibility: "public".into(),
        license: "CC0-1.0".into(),
        document: format!("{}é末", "a".repeat(1023)),
        question: "A source task?".into(),
        synthesis: false,
    };
    let mut input = input(&source.document);
    input.version = 2;
    input.source_excerpt = Some(task_plan::SourceExcerpt::prefix(&source.document));
    let authority = Authority {
        version: 2,
        input_sha256: "a".repeat(64),
        report_sha256: "b".repeat(64),
        artifact_sha256: "c".repeat(64),
        question: input.question.clone(),
        source_sha256: input.source_sha256.clone(),
        source_bytes: input.source_bytes,
        source_excerpt: input.source_excerpt.as_ref().map(Coverage::from),
    };
    verify_input(&authority, &input, &source).unwrap();
    let summary = summary(Some(&authority));
    assert_eq!(summary["goal_only"], false);
    assert_eq!(summary["source_contents_read_by_planner"], true);
    assert_eq!(summary["source_excerpt_complete"], false);
    assert_eq!(summary["source_coverage"]["end"], 1023);
    assert_eq!(summary["decomposition_quality_proven"], false);
    // Even a self-consistent replacement excerpt hash cannot substitute different
    // source contents or silently provide less coverage than the canonical prefix.
    for replacement in ["b".repeat(1023), "a".repeat(1000)] {
        let mut changed = input.clone();
        changed.source_excerpt = Some(task_plan::SourceExcerpt::prefix(&replacement));
        changed.validate().unwrap();
        let mut rehashed = authority.clone();
        rehashed.source_excerpt = changed.source_excerpt.as_ref().map(Coverage::from);
        assert!(verify_input(&rehashed, &changed, &source).is_err());
    }
    let mut changed = authority.clone();
    changed.source_excerpt = None;
    assert!(verify_input(&changed, &input, &source).is_err());
    let mut changed = authority;
    changed.version = 1;
    assert!(verify_input(&changed, &input, &source).is_err());
}

#[derive(Parser)]
struct Command {
    #[command(flatten)]
    options: Options,
}

#[tokio::test]
async fn model_planning_preview_is_inert_and_enrollment_only() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("new-planned-graph");
    let key = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[91; 32])
            .verifying_key()
            .as_bytes(),
    );
    let words = vec![
        "document",
        "--directory",
        directory.to_str().unwrap(),
        "--plan-tasks",
        "--public-question",
        "Compare public opportunities and constraints.",
        "--input",
        "/missing/source.txt",
        "--public-content",
        "--license",
        "CC0-1.0",
        "--runtime-root",
        "/missing/runtime",
        "--model-root",
        "/missing/model",
        "--identity",
        "/missing/identity",
        "--passphrase-file",
        "/missing/passphrase",
        "--publisher-key",
        &key,
        "--discover-peers",
    ];
    let args = Command::try_parse_from(&words).unwrap().options;
    assert!(args.plan_tasks);
    let source = "The actual public source, not a preselected model answer.";
    let planner_input = checked_input(&args, source).unwrap();
    assert_eq!(planner_input.version, 2);
    assert_eq!(planner_input.source_sha256, digest(source.as_bytes()));
    assert_eq!(planner_input.source_excerpt.unwrap().text, source);
    super::super::super::run(&args, &root.path().join("absent.sock"))
        .await
        .unwrap();
    assert!(!directory.exists());
    let mut graph_words = words.clone();
    let switch = graph_words
        .iter()
        .position(|word| *word == "--plan-tasks")
        .unwrap();
    graph_words[switch] = "--plan-task-graph";
    let graph_args = Command::try_parse_from(&graph_words).unwrap().options;
    assert!(graph_args.plan_task_graph && !graph_args.plan_tasks);
    assert_eq!(checked_input(&graph_args, source).unwrap().version, 3);
    super::super::super::run(&graph_args, &root.path().join("absent.sock"))
        .await
        .unwrap();
    assert!(!directory.exists());
    for conflict in [
        "--plan-tasks",
        "--resume",
        "--synthesize",
        "--batch-barrier",
    ] {
        let mut invalid = graph_words.clone();
        invalid.push(conflict);
        assert!(Command::try_parse_from(invalid).is_err());
    }
    for extra in [
        vec!["--task-plan", "/missing/plan.json"],
        vec!["--resume"],
        vec!["--synthesize"],
        vec!["--batch-barrier"],
    ] {
        let mut invalid = words.clone();
        invalid.extend(extra);
        assert!(Command::try_parse_from(invalid).is_err());
    }
    let mut no_question = words;
    let index = no_question
        .iter()
        .position(|word| *word == "--public-question")
        .unwrap();
    no_question.drain(index..=index + 1);
    assert!(Command::try_parse_from(no_question).is_err());
}
