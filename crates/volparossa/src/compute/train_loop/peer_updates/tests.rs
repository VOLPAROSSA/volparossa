//! Pure state/filesystem tests. No fixture here claims successful model execution.

use super::*;
use std::{
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, symlink},
};

fn channel() -> Channel {
    Channel {
        publisher_key: hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[17; 32])
                .verifying_key()
                .to_bytes(),
        ),
        name: "peer-adapter".into(),
        min_revision: Some(1),
    }
}

#[test]
fn owner_enrollment_and_revision_floor_survive_serialization() {
    let enrolled = Enrollment {
        version: 1,
        channels: vec![channel()],
    };
    enrolled.validate().unwrap();
    let mut feed = Feed {
        channel: channel(),
        revision: None,
        manifest_id: None,
        processed_manifest: None,
        next_poll: 0,
    };
    let first = "11".repeat(32);
    admit_revision(&mut feed, 1, &first).unwrap();
    admit_revision(&mut feed, 1, &first).unwrap();
    let serialized = serde_json::to_vec(&feed).unwrap();
    let mut reopened: Feed = serde_json::from_slice(&serialized).unwrap();
    assert!(admit_revision(&mut reopened, 1, &"22".repeat(32)).is_err());
    admit_revision(&mut reopened, 2, &"33".repeat(32)).unwrap();
    assert!(admit_revision(&mut reopened, 1, &first).is_err());
    let mut duplicated = enrolled;
    duplicated.channels.push(channel());
    assert!(duplicated.validate().is_err());
}

#[test]
fn source_resolution_requires_an_independently_pinned_unambiguous_dataset() {
    let id = "11".repeat(32);
    let source = Source {
        publisher_key: channel().publisher_key,
        name: "public-training".into(),
        min_revision: Some(1),
        manifest_id: Some(id.clone()),
    };
    let mut plan = Plan {
        version: 1,
        sources: vec![source.clone()],
        catalogs: vec![],
    };
    let state = State::new(1);
    assert_eq!(
        resolve_source(&plan, &state, &id, 100).unwrap(),
        Some(source)
    );
    assert!(
        resolve_source(&plan, &state, &"22".repeat(32), 100)
            .unwrap()
            .is_none()
    );
    plan.sources[0].min_revision = None;
    assert!(resolve_source(&plan, &state, &id, 100).unwrap().is_none());
    plan.sources[0].min_revision = Some(1);
    plan.sources.push(plan.sources[0].clone());
    assert!(resolve_source(&plan, &state, &id, 100).is_err());
}

#[test]
fn fixed_owned_retention_does_not_erase_unrelated_files_or_follow_links() {
    let temporary = tempfile::tempdir().unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let root = temporary.path().join("peer-update-0000000000000001");
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root.join("pending"))
        .unwrap();
    let original = root.join("pending/provenance.json");
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&original)
        .unwrap();
    file.write_all(b"synthetic ownership fixture").unwrap();
    drop(file);
    let recorded = snapshot(&root).unwrap();
    assert_eq!(recorded.len(), 1);
    let unknown = root.join("keep-user-data");
    let _file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&unknown)
        .unwrap();
    assert!(prune(&root).is_err());
    assert!(unknown.is_file() && original.is_file());
    fs::remove_file(unknown).unwrap();
    let link = root.join("pending/adapter.bundle");
    symlink(&original, &link).unwrap();
    assert!(prune(&root).is_err());
    assert!(original.is_file());
    fs::remove_file(link).unwrap();
    assert_eq!(recorded, snapshot(&root).unwrap());
    prune(&root).unwrap();
    assert!(!root.exists());
}

#[test]
#[allow(clippy::too_many_lines)] // Keep the complete registry retention transaction together.
fn quarantine_consumes_only_exact_revision_and_preserves_accepted_warmstart() {
    use clap::Parser as _;
    // State/filesystem fixture only: completed evaluation records are tested
    // independently; no worker or accepted-model quality is asserted here.
    let temporary = tempfile::tempdir().unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut arguments = vec![
        "volparossa".to_owned(),
        "compute".into(),
        "train-loop".into(),
    ];
    for (flag, name) in [
        ("--plan", "plan"),
        ("--directory", "coordinator"),
        ("--runtime-root", "runtime"),
        ("--model-root", "model"),
        ("--cache", "cache"),
    ] {
        arguments.extend([
            flag.into(),
            temporary.path().join(name).to_str().unwrap().into(),
        ]);
    }
    let cli = crate::Cli::try_parse_from(arguments).unwrap();
    let crate::CliCommand::Compute {
        command: crate::compute::Command::TrainLoop(args),
    } = cli.command
    else {
        panic!("train-loop options")
    };
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&args.directory)
        .unwrap();
    let at = now().unwrap();
    let accepted = Round {
        sequence: 1,
        channel: 0,
        revision: 1,
        manifest_id: "11".repeat(32),
        dataset_manifest_id: "aa".repeat(32),
        observed_at: at,
        expires: at + 1200,
        next_attempt: 0,
        phase: Phase::Approved,
        source: None,
        imported_at: None,
        baseline: None,
        snapshot: Some(Snapshot::new()),
        retirement: None,
    };
    let mut pending = accepted.clone();
    pending.sequence = 2;
    pending.revision = 2;
    pending.manifest_id = "22".repeat(32);
    pending.phase = Phase::Evaluating;
    pending.snapshot = None;
    let root = round_root(&args, 2).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(root.join("comparison"))
        .unwrap();
    let path = root.join("comparison/quarantine.json");
    let mut file = fs::OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(&path)
        .unwrap();
    file.write_all(b"explicit synthetic retention fixture, not worker evidence")
        .unwrap();
    drop(file);
    let enrollment = Enrollment {
        version: 1,
        channels: vec![channel()],
    };
    let mut registry = Registry {
        version: 1,
        next_sequence: 3,
        cursor: 0,
        feeds: vec![Feed {
            channel: channel(),
            revision: Some(2),
            manifest_id: Some(pending.manifest_id.clone()),
            processed_manifest: Some(accepted.manifest_id.clone()),
            next_poll: 0,
        }],
        pending: Some(pending.clone()),
        completed: vec![accepted],
        active: Some(1),
        garbage: vec![],
    };
    finish(&args, &mut registry, Phase::Quarantined).unwrap();
    registry.validate(&enrollment, at).unwrap();
    assert_eq!(registry.active, Some(1));
    assert!(registry.pending.is_none());
    assert_eq!(registry.completed[1].phase, Phase::Quarantined);
    assert_eq!(
        registry.feeds[0].processed_manifest.as_ref(),
        Some(&pending.manifest_id)
    );
    assert!(
        registry.completed[1]
            .snapshot
            .as_ref()
            .unwrap()
            .contains_key("comparison/quarantine.json")
    );
    let mut reopened: Registry =
        serde_json::from_slice(&serde_json::to_vec(&registry).unwrap()).unwrap();
    reopened.validate(&enrollment, at).unwrap();
    assert_eq!(reopened.active, Some(1));
    // The same publisher remains eligible at the next version; an unrelated
    // changed artifact cannot masquerade as the already processed revision.
    assert!(admit_revision(&mut reopened.feeds[0], 2, &"33".repeat(32)).is_err());
    admit_revision(&mut reopened.feeds[0], 3, &"33".repeat(32)).unwrap();
    assert_ne!(
        reopened.feeds[0].processed_manifest,
        reopened.feeds[0].manifest_id
    );
    assert_eq!(reopened.active, Some(1));
    prune(&root).unwrap();
    assert!(!root.exists());
}
