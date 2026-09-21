//! Pure retained-protocol and CLI fixtures; not evidence of model planning or answer quality.

use super::*;
use clap::Parser;
use std::os::unix::fs::PermissionsExt as _;
use volparossa_content::agent_artifact::{BASE_MODEL_SHA256, MODEL_ID, MODEL_REVISION};

fn input(document: &str) -> task_plan::Input {
    task_plan::Input {
        version: 1,
        visibility: "public".into(),
        license: "CC0-1.0".into(),
        question: "  Compare the opportunities and constraints.\n".into(),
        source_sha256: digest(document.as_bytes()),
        source_bytes: document.len() as u64,
    }
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
    };
    let source = Input {
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
    super::super::super::run(&args, &root.path().join("absent.sock"))
        .await
        .unwrap();
    assert!(!directory.exists());
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
