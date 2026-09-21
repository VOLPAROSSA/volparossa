//! Local summary/CLI controls only; these never stand in for real graph execution.

use super::*;
use clap::Parser;
use std::os::unix::fs::PermissionsExt as _;

#[test]
fn completion_from_retained_receipts_replaces_partial_but_preserves_completed_summary() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    for operation in ["compute_public_task_graph", "compute_graph_dependency"] {
        let path = root.path().join("result.json");
        let partial = json!({"operation":operation,"complete":false,"rounds_this_invocation":1});
        save(root.path(), "result.json", &partial, true).unwrap();
        let answer_field = if operation == "compute_public_task_graph" {
            "output"
        } else {
            "synthesized_answer"
        };
        let mut completed =
            json!({"operation":operation,"complete":true,"rounds_this_invocation":0});
        completed[answer_field] = json!({"text":"pure retained-summary fixture"});
        retain_result(root.path(), &completed).unwrap();
        let original = std::fs::read(&path).unwrap();
        assert_eq!(
            serde_json::from_slice::<Value>(&original).unwrap(),
            completed
        );
        retain_result(root.path(), &completed).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), original);
        completed[answer_field]["text"] = "different answer".into();
        assert!(retain_result(root.path(), &completed).is_err());
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
}

#[tokio::test]
async fn graph_preview_needs_no_question_and_cannot_mix_instruction_modes() {
    #[derive(Parser)]
    struct Command {
        #[command(flatten)]
        options: Options,
    }
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("new-graph");
    let key = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[91; 32])
            .verifying_key()
            .as_bytes(),
    );
    let words = vec![
        "document",
        "--directory",
        path.to_str().unwrap(),
        "--task-plan",
        "/missing/graph.json",
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
    let options = Command::try_parse_from(&words).unwrap().options;
    super::super::run(&options, &root.path().join("missing.sock"))
        .await
        .unwrap();
    assert!(!path.exists());
    for extra in [
        vec!["--public-question", "Unselected question?"],
        vec!["--synthesize"],
        vec!["--batch-barrier"],
        vec!["--resume"],
    ] {
        let mut invalid = words.clone();
        invalid.extend(extra);
        assert!(Command::try_parse_from(invalid).is_err());
    }
}
