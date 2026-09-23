//! Inert owner/enrollment checks. No compute backend, network or model is invoked.

use clap::Parser as _;
use ed25519_dalek::SigningKey;

use super::*;

#[derive(clap::Parser)]
struct Command {
    #[command(flatten)]
    options: Options,
}

fn arguments(root: &Path) -> Vec<String> {
    let keys: Vec<String> = (1u8..=7)
        .map(|seed| {
            hex::encode(
                SigningKey::from_bytes(&[seed; 32])
                    .verifying_key()
                    .as_bytes(),
            )
        })
        .collect();
    let mut args = vec!["cycle".to_owned()];
    let pairs = [
        ("--directory", root.join("cycle").display().to_string()),
        ("--source-publisher-key", keys[0].clone()),
        ("--source-name", "original-public-source".into()),
        ("--source-manifest-id", hex::encode([9; 32])),
        ("--cache", root.join("source-cache").display().to_string()),
        ("--requester-key", keys[1].clone()),
        ("--publication-key", keys[2].clone()),
        (
            "--identity",
            root.join("identity.key").display().to_string(),
        ),
        (
            "--passphrase-file",
            root.join("passphrase").display().to_string(),
        ),
        ("--provider-key", keys[3].clone()),
        ("--provider-key", keys[4].clone()),
        ("--license", "CC0-1.0".into()),
        (
            "--policy-config",
            root.join("config.toml").display().to_string(),
        ),
        ("--authority", format!("{}:{}:reply", keys[5], keys[6])),
        ("--request-name", "request".into()),
        ("--publish-name", "decision".into()),
        ("--decision-revision", "1".into()),
    ];
    for (name, value) in pairs {
        args.extend([name.to_owned(), value]);
    }
    args
}

#[tokio::test]
async fn preview_has_no_source_config_directory_or_rpc_requirement() {
    let root = tempfile::tempdir().unwrap();
    let args = Command::try_parse_from(arguments(root.path()))
        .unwrap()
        .options;
    let planned = run_value(&args, &root.path().join("absent.sock"))
        .await
        .unwrap();
    assert_eq!(planned["execute"], false);
    assert_eq!(planned["planned_jobs"], 4);
    assert_eq!(planned["requires_prebuilt_assessment_bundle"], false);
    assert_eq!(
        planned["framework_sha256"],
        sha(&serde_json::to_vec(&crate::compute::policy_assessment::framework()).unwrap())
    );
    assert_eq!(std::fs::read_dir(root.path()).unwrap().count(), 0);
    let mut altered = args;
    altered.cache = altered.directory.join("aliased-cache");
    assert!(
        run_value(&altered, &root.path().join("absent.sock"))
            .await
            .is_err()
    );
}

#[test]
fn cli_has_no_bundle_shortcut_and_resume_keeps_explicit_selections() {
    let root = Path::new("/nonexistent/policy-cycle-test");
    let args = arguments(root);
    let mut shortcut = args.clone();
    shortcut.extend(["--assessment-bundle".into(), "/tmp/invented.bundle".into()]);
    assert!(Command::try_parse_from(shortcut).is_err());
    let mut resumed = args;
    resumed.extend(["--execute".into(), "--resume".into()]);
    let parsed = Command::try_parse_from(resumed).unwrap().options;
    assert!(parsed.execute && parsed.resume);
    assert!(
        Command::try_parse_from([
            "cycle",
            "--directory",
            "/tmp/cycle",
            "--execute",
            "--resume"
        ])
        .is_err()
    );
}

#[test]
fn enrollment_binds_original_selection_cache_paths_and_budgets() {
    let root = Path::new("/nonexistent/policy-cycle-test");
    let mut args = Command::try_parse_from(arguments(root)).unwrap().options;
    let socket = root.join("agent.sock");
    let original = enrollment(&args, &socket, "config-hash");
    args.execute = true;
    args.resume = true;
    assert_eq!(enrollment(&args, &socket, "config-hash"), original);
    args.worker_seconds -= 1;
    assert_ne!(enrollment(&args, &socket, "config-hash"), original);
    args.worker_seconds += 1;
    args.reuse_cache = true;
    assert_ne!(enrollment(&args, &socket, "config-hash"), original);
    args.reuse_cache = false;
    args.provider_key.swap(0, 1);
    assert_ne!(enrollment(&args, &socket, "config-hash"), original);
    args.provider_key.swap(0, 1);
    assert_ne!(enrollment(&args, &socket, "changed-config"), original);
}

#[test]
fn state_preserves_original_deadline_and_requires_complete_phase_bindings() {
    let hash = sha(b"original enrolled selections");
    let original = State::new(hash.clone(), 123_000, 3600).unwrap();
    let mut replay: State =
        serde_json::from_slice(&serde_json::to_vec(&original).unwrap()).unwrap();
    replay.check(&hash, 3600).unwrap();
    assert_eq!(replay.deadline_ms, 3_723_000);
    assert!(replay.check(&hash, 3601).is_err());
    assert!(replay.check(&sha(b"different selections"), 3600).is_err());
    replay.phase = Phase::Round;
    assert!(replay.check(&hash, 3600).is_err());
    replay.assessment_sha256 = Some(sha(b"four original valid receipts"));
    replay.bundle_sha256 = Some(sha(b"exact transferable projection"));
    replay.check(&hash, 3600).unwrap();
    replay.phase = Phase::Complete;
    assert!(replay.check(&hash, 3600).is_err());
    replay.round_sha256 = Some(sha(b"original completed quorum publication"));
    replay.check(&hash, 3600).unwrap();
}
