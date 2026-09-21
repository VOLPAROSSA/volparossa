//! Contract-only tests: no peer, model, cache acquisition or policy authority.

use clap::Parser;
use ed25519_dalek::SigningKey;
use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};

use super::*;

#[derive(Parser)]
struct Cli {
    #[command(flatten)]
    options: Options,
}

fn arguments(output: &Path) -> Vec<String> {
    let key = |byte| {
        hex::encode(
            SigningKey::from_bytes(&[byte; 32])
                .verifying_key()
                .as_bytes(),
        )
    };
    vec![
        "test".into(),
        "--output".into(),
        output.display().to_string(),
        "--source-publisher-key".into(),
        key(1),
        "--source-name".into(),
        "subject".into(),
        "--source-manifest-id".into(),
        "a".repeat(64),
        "--cache".into(),
        "/not-acquired/cache".into(),
        "--publisher-key".into(),
        key(2),
        "--provider-key".into(),
        key(3),
        "--provider-key".into(),
        key(4),
        "--license".into(),
        "CC0-1.0".into(),
    ]
}

#[test]
fn preview_is_explicit_native_public_and_never_creates_work() {
    let root = tempfile::tempdir().unwrap();
    let output = root.path().join("not-created");
    let mut args = Cli::try_parse_from(arguments(&output)).unwrap().options;
    let result = preview(&args).unwrap();
    assert_eq!(result["execute"], false);
    assert_eq!(result["planned_jobs"], 4);
    assert_eq!(result["network_policy_activation"], false);
    assert!(!output.exists());
    args.provider_key[1] = args.provider_key[0];
    assert!(preview(&args).is_err());
    let mut arguments = arguments(&output);
    arguments.extend(["--resume".into()]);
    assert!(Cli::try_parse_from(arguments).is_err());
}

#[test]
fn completed_result_replay_keeps_original_bytes_and_inode() {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("result.json");
    let completed = json!({"complete":true,"decision":{"outcome":"undetermined"}});
    storage::retain_result(&path, &completed).unwrap();
    let before = std::fs::read(&path).unwrap();
    let inode = std::fs::metadata(&path).unwrap().ino();
    storage::retain_result(&path, &completed).unwrap();
    assert_eq!(std::fs::read(&path).unwrap(), before);
    assert_eq!(std::fs::metadata(&path).unwrap().ino(), inode);
    assert!(storage::retain_result(&path, &json!({"complete":false})).is_err());
}

#[tokio::test]
async fn cancellation_or_original_expiry_starts_no_assessment_work() {
    let root = tempfile::tempdir().unwrap();
    let args = Cli::try_parse_from(arguments(root.path())).unwrap().options;
    let source_key = hex::encode(args.source_publisher_key.unwrap().as_bytes());
    let mut enrollment = Enrollment {
        version: 1,
        scope: assessment::Scope::new(&source_key, &"a".repeat(64), "Public fixture.").unwrap(),
        source_name: "subject".into(),
        source_download_sha256: "b".repeat(64),
        publisher_key: hex::encode(args.publisher_key.unwrap().as_bytes()),
        providers: [
            hex::encode(args.provider_key[0].as_bytes()),
            hex::encode(args.provider_key[1].as_bytes()),
        ],
        model_fingerprints: ["c".repeat(64), "c".repeat(64)],
        license: "CC0-1.0".into(),
        selected_at: 1,
        expires: 2,
        max_seconds: 600,
    };
    let (cancel, activity) = watch::channel(false);
    let socket = root.path().join("no-socket");
    let stage = execution::run(
        &args,
        &socket,
        &enrollment,
        "assessment-0",
        0,
        "context",
        "question",
        &activity,
    )
    .await
    .unwrap();
    assert_eq!(stage.summary(false)["execution_complete"], false);
    assert!(!root.path().join("assessment-0").exists());
    enrollment.expires = now().unwrap() + 60;
    cancel.send(true).unwrap();
    let stage = execution::run(
        &args,
        &socket,
        &enrollment,
        "assessment-0",
        0,
        "context",
        "question",
        &activity,
    )
    .await
    .unwrap();
    assert_eq!(stage.summary(false)["state"], "cancelled_or_source_expired");
    assert!(!root.path().join("assessment-0").exists());
}
