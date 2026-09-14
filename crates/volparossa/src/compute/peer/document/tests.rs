use super::*;
use clap::Parser;

#[derive(Parser)]
struct Command {
    #[command(flatten)]
    options: Options,
}

#[tokio::test]
async fn preview_never_loads_source_model_or_network_and_permission_precedes_creation() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("new-document");
    let mut args = Command::try_parse_from([
        "document",
        "--directory",
        directory.to_str().unwrap(),
        "--resume",
        "--follow",
    ])
    .unwrap()
    .options;
    assert!(args.follow.follow);
    let missing_socket = root.path().join("absent.sock");
    run(&args, &missing_socket).await.unwrap();
    assert!(!directory.exists());
    args.resume = false;
    args.execute = true;
    assert_eq!(
        run(&args, &missing_socket).await.unwrap_err().to_string(),
        "compute_document_public_permission_required"
    );
    assert!(!directory.exists());
}

#[test]
fn resume_retains_inputs_and_lease_and_batch_budgets_stay_separate() {
    let args = ["document", "--directory", "/absent/document", "--resume"];
    assert!(!Command::try_parse_from(args).unwrap().options.follow.follow);
    for field in [
        "--input",
        "--public-question",
        "--license",
        "--runtime-root",
    ] {
        let mut changed = args.to_vec();
        changed.extend([field, "changed"]);
        assert!(Command::try_parse_from(changed).is_err());
    }
    for (field, value) in [("--max-batches", "33"), ("--max-seconds", "601")] {
        let mut changed = args.to_vec();
        changed.extend([field, value]);
        assert!(Command::try_parse_from(changed).is_err());
    }
    let mut changed = args.to_vec();
    changed.extend([
        "--max-batches",
        "32",
        "--max-seconds",
        "60",
        "--follow",
        "--follow-poll-seconds",
        "2",
    ]);
    let parsed = Command::try_parse_from(changed).unwrap().options;
    assert_eq!(parsed.max_batches, 32);
    assert_eq!(parsed.max_seconds, 60);
    assert!(parsed.follow.follow);
    assert_eq!(parsed.follow.follow_poll_seconds, 2);
}
