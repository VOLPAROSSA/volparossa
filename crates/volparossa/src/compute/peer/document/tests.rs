use super::*;
use clap::Parser;

#[derive(Parser)]
struct Command {
    #[command(flatten)]
    options: Options,
}

#[tokio::test]
async fn automatic_peer_preview_is_networkless_and_cannot_reselect_on_resume() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("automatic-document");
    let key = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[95; 32])
            .verifying_key()
            .as_bytes(),
    );
    let words = vec![
        "document",
        "--directory",
        directory.to_str().unwrap(),
        "--input",
        "/missing/public.txt",
        "--public-content",
        "--public-question",
        "Summarize this public text.",
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
    assert!(args.provider_key.is_empty());
    run(&args, &root.path().join("absent.sock")).await.unwrap();
    assert!(!directory.exists());
    let mut enrollment = words.clone();
    enrollment.extend(["--enroll-only", "--execute"]);
    assert!(
        Command::try_parse_from(enrollment)
            .unwrap()
            .options
            .enroll_only
    );
    for extra in [
        vec!["--provider-key", &key],
        vec!["--resume"],
        vec!["--max-peers", "5"],
        vec!["--enroll-only"],
    ] {
        let mut invalid = words.clone();
        invalid.extend(extra);
        assert!(Command::try_parse_from(invalid).is_err());
    }
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
    let mut enrollment = args.to_vec();
    enrollment.extend(["--enroll-only", "--execute"]);
    assert!(Command::try_parse_from(enrollment).is_err());
    for field in [
        "--input",
        "--source-plan",
        "--public-question",
        "--license",
        "--synthesize",
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

#[tokio::test]
async fn collection_preview_never_reads_sources_and_cannot_mix_or_reselect_inputs() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("collection");
    let key = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[95; 32])
            .verifying_key()
            .as_bytes(),
    );
    let args = [
        "document",
        "--directory",
        directory.to_str().unwrap(),
        "--source-plan",
        "/missing/collection-plan.json",
        "--public-content",
        "--public-question",
        "Compare these public sources.",
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
        "--synthesize",
    ];
    let options = Command::try_parse_from(args).unwrap().options;
    assert!(options.input.is_none());
    run(&options, &root.path().join("missing.sock"))
        .await
        .unwrap();
    assert!(!directory.exists());
    let mut mixed = args.to_vec();
    mixed.extend(["--input", "/missing/other.txt"]);
    assert!(Command::try_parse_from(mixed).is_err());
    let mut resumed = args.to_vec();
    resumed.push("--resume");
    assert!(Command::try_parse_from(resumed).is_err());
}
