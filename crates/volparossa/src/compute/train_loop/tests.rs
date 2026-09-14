//! Coordinator/storage fixtures only. Opaque cycle files are not model-work evidence.

use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
};

use clap::Parser;

use super::*;

fn fixture() -> (tempfile::TempDir, Options) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let publisher = ed25519_dalek::SigningKey::from_bytes(&[43; 32]).verifying_key();
    let plan = json!({"version":1,"sources":[
        {"publisher_key":hex::encode(publisher.as_bytes()),"name":"public-a"},
        {"publisher_key":hex::encode(publisher.as_bytes()),"name":"public-b","min_revision":8},
        {"publisher_key":hex::encode(publisher.as_bytes()),"name":"public-c"}
    ]});
    let plan_path = root.path().join("sources.json");
    fs::write(&plan_path, serde_json::to_vec(&plan).unwrap()).unwrap();
    fs::set_permissions(&plan_path, fs::Permissions::from_mode(0o600)).unwrap();
    let mut arguments = vec![
        "volparossa".to_owned(),
        "compute".into(),
        "train-loop".into(),
    ];
    for (flag, path) in [
        ("--plan", plan_path),
        ("--directory", root.path().join("coordinator")),
        ("--runtime-root", root.path().join("runtime")),
        ("--model-root", root.path().join("model")),
        ("--cache", root.path().join("agent-cache")),
    ] {
        arguments.push(flag.into());
        arguments.push(path.to_str().unwrap().into());
    }
    let cli = crate::Cli::try_parse_from(arguments).unwrap();
    let crate::CliCommand::Compute {
        command: super::super::Command::TrainLoop(args),
    } = cli.command
    else {
        panic!("train-loop CLI parsed")
    };
    (root, *args)
}

fn cycle_directory(store: &Store, sequence: u64, complete: bool) -> PathBuf {
    let root = store.cycle_path(sequence).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&root).unwrap();
    let mut files = vec!["selection.json"];
    if complete {
        for directory in ["training", "training/adapter"] {
            fs::DirBuilder::new()
                .mode(0o700)
                .create(root.join(directory))
                .unwrap();
        }
        files.extend([
            "dataset.json",
            "dataset.manifest",
            "source-provenance.json",
            "training-report.json",
            "result.json",
            "adapter.bundle",
            "training/report.json",
            "training/adapter/README.md",
            "training/adapter/adapter_config.json",
            "training/adapter/adapter_model.safetensors",
        ]);
    }
    for name in files {
        let path = root.join(name);
        fs::write(&path, b"{\"opaque_storage_fixture_not_training\":true}").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    root
}

fn add_cycle(store: &Store, state: &mut State, sequence: u64, phase: Phase) {
    let complete = !matches!(phase, Phase::Running | Phase::Failed);
    if complete {
        evaluation::fixture(store, sequence, phase != Phase::Rejected);
    } else {
        cycle_directory(store, sequence, false);
    }
    state.cycles.push(Cycle {
        sequence,
        source: 0,
        phase,
        snapshot: complete.then(|| store.snapshot_cycle(sequence).unwrap()),
        training: None,
        publication: (phase == Phase::PublishPending)
            .then(|| json!({"opaque_publication_fixture":true})),
        next_publication_attempt: 0,
    });
    state.next_sequence = sequence + 1;
}

#[test]
fn round_robin_source_choice_and_retry_timing_do_not_consult_cache_inventory() {
    let (_root, args) = fixture();
    let (plan, selected) = enrollment(&args).unwrap();
    assert_eq!(selected["source_choice_uses_cache_inventory"], false);
    assert!(!args.cache.exists());
    let mut state = State::new(plan.sources.len());
    for expected in 0..3 {
        assert_eq!(state.select(&plan, false, 100), Some(expected));
        state.sources[expected].next_attempt = 110;
        state.cursor = (expected + 1) % plan.sources.len();
    }
    assert_eq!(state.select(&plan, false, 109), None);
    assert_eq!(state.select(&plan, false, 110), Some(0));
    state.cursor = 2;
    assert_eq!(state.select(&plan, false, 110), Some(2));
    assert!(!args.cache.exists());
}

#[test]
fn second_source_enrollment_pins_a_distinct_public_manifest_before_execution() {
    let (root, mut args) = fixture();
    let (plan, original) = enrollment(&args).unwrap();
    assert!(original.get("validation_source").is_none());
    let path = root.path().join("validation-source.json");
    args.validation_source = Some(path.clone());
    let mut selected = json!({"publisher_key":plan.sources[0].publisher_key,
        "name":plan.sources[0].name,"manifest_id":"a".repeat(64)});
    fs::write(&path, serde_json::to_vec(&selected).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    assert!(enrollment(&args).is_err());
    selected["name"] = json!("explicit-validation-only");
    fs::write(&path, serde_json::to_vec(&selected).unwrap()).unwrap();
    let (_, enrolled) = enrollment(&args).unwrap();
    assert_eq!(
        enrolled["quality_policy"],
        "source-and-second-source-loss-v1"
    );
    assert_eq!(enrolled["validation_source"]["manifest_id"], "a".repeat(64));
    selected["manifest_id"] = Value::Null;
    fs::write(&path, serde_json::to_vec(&selected).unwrap()).unwrap();
    assert!(enrollment(&args).is_err());
    assert!(!args.directory.exists() && !args.cache.exists());
}

#[test]
fn completed_training_survives_pending_evaluation_and_saved_decision_without_retraining() {
    let (_root, args) = fixture();
    let (plan, selected) = enrollment(&args).unwrap();
    let store = Store::open(&args.directory, &selected, false).unwrap();
    evaluation::fixture(&store, 1, true);
    let mut state = State::new(plan.sources.len());
    state.next_sequence = 2;
    state.cycles.push(Cycle {
        sequence: 1,
        source: 0,
        phase: Phase::Evaluating,
        snapshot: None,
        training: Some(store.snapshot_training(1).unwrap()),
        publication: None,
        next_publication_attempt: 0,
    });
    // The decision was saved immediately before interruption; recovery must
    // preserve training and reuse that exact decision, never overwrite it.
    let original = store.read_cycle_json(1, "evaluation.json").unwrap();
    recover(&store, &mut state, plan.sources.len()).unwrap();
    assert!(state.cycles[0].phase == Phase::Evaluating);
    assert_eq!(state.completed, 0);
    assert!(state.latest.is_none());
    qualify_cycle(&store, &mut state, 1, false).unwrap();
    assert!(state.cycles[0].phase == Phase::Complete);
    assert_eq!(state.latest, Some(1));
    assert_eq!(state.completed, 1);
    assert_eq!(
        store.read_cycle_json(1, "evaluation.json").unwrap(),
        original
    );
    recover(&store, &mut state, plan.sources.len()).unwrap();
    fs::write(
        store.cycle_path(1).unwrap().join("training/report.json"),
        b"{}",
    )
    .unwrap();
    assert!(recover(&store, &mut state, plan.sources.len()).is_err());
}

#[test]
fn completed_pins_and_exhausted_revisions_require_explicit_repeat_but_names_can_seek_updates() {
    let (_root, args) = fixture();
    let (mut plan, _) = enrollment(&args).unwrap();
    plan.sources[0].manifest_id = Some(hex::encode([7; 32]));
    let mut state = State::new(plan.sources.len());
    assert_eq!(state.select(&plan, false, 100), Some(0));
    state.sources[0].revision = Some(7);
    state.sources[1].revision = Some(8);
    state.sources[2].revision = Some(u64::MAX);
    assert_eq!(state.select(&plan, false, 100), Some(1));
    state.sources[1].next_attempt = 101;
    assert_eq!(state.select(&plan, false, 100), None);
    assert_eq!(state.select(&plan, true, 100), Some(0));
    state.cursor = 2;
    assert_eq!(state.select(&plan, true, 100), Some(2));
    assert_eq!(plan.sources[0].manifest().unwrap(), Some([7; 32]));
}

#[tokio::test]
async fn preview_creates_nothing_and_resume_requires_exact_original_enrollment() {
    let (root, mut args) = fixture();
    assert!(!args.execute && !args.resume && !args.repeat_sources);
    assert!(args.max_cycles.is_none());
    let (_, selected) = enrollment(&args).unwrap();
    run(&args, &root.path().join("no-agent.sock"))
        .await
        .unwrap();
    assert!(!args.directory.exists());
    assert!(!args.runtime_root.exists());
    assert!(!args.model_root.exists());
    assert!(!args.cache.exists());
    let store = Store::open(&args.directory, &selected, false).unwrap();
    let checkpoint = json!({"exact_saved_fixture":1});
    store.save_state(&checkpoint).unwrap();
    drop(store);
    assert!(Store::open(&args.directory, &selected, false).is_err());
    args.steps += 1;
    let (_, changed) = enrollment(&args).unwrap();
    assert!(Store::open(&args.directory, &changed, true).is_err());
    let store = Store::open(&args.directory, &selected, true).unwrap();
    assert_eq!(store.load_state().unwrap(), Some(checkpoint));
}

#[test]
fn new_revision_floor_preserves_explicit_minimum_and_never_wraps_completed_revision() {
    let (_root, args) = fixture();
    let (plan, _) = enrollment(&args).unwrap();
    let mut progress = SourceProgress::default();
    assert_eq!(
        required_revision(&plan.sources[0], &progress, false).unwrap(),
        None
    );
    assert_eq!(
        required_revision(&plan.sources[1], &progress, false).unwrap(),
        Some(8)
    );
    progress.revision = Some(3);
    assert_eq!(
        required_revision(&plan.sources[0], &progress, false).unwrap(),
        Some(4)
    );
    assert_eq!(
        required_revision(&plan.sources[1], &progress, false).unwrap(),
        Some(8)
    );
    progress.revision = Some(8);
    assert_eq!(
        required_revision(&plan.sources[1], &progress, false).unwrap(),
        Some(9)
    );
    progress.revision = Some(u64::MAX);
    assert!(required_revision(&plan.sources[1], &progress, false).is_err());
    assert_eq!(
        required_revision(&plan.sources[1], &progress, true).unwrap(),
        Some(8)
    );
    assert_eq!(
        required_revision(&plan.sources[0], &progress, true).unwrap(),
        None
    );
}

#[test]
fn retention_preserves_current_warmstart_active_work_and_pending_publications() {
    let (_root, args) = fixture();
    let (plan, selected) = enrollment(&args).unwrap();
    let store = Store::open(&args.directory, &selected, false).unwrap();
    let mut state = State::new(plan.sources.len());
    for (index, phase) in [
        Phase::Complete,
        Phase::PublishPending,
        Phase::Trained,
        Phase::Running,
        Phase::PublishPending,
        Phase::Trained,
        Phase::Trained,
        Phase::PublishPending,
    ]
    .into_iter()
    .enumerate()
    {
        add_cycle(&store, &mut state, u64::try_from(index).unwrap() + 1, phase);
    }
    state.latest = Some(1);
    state.completed = 1;
    state.promoted = 1;
    let before = serde_json::to_value(&state).unwrap();
    assert!(!make_room(&store, &mut state).unwrap());
    assert_eq!(serde_json::to_value(&state).unwrap(), before);
    for sequence in 1..=8 {
        assert!(store.cycle_path(sequence).unwrap().is_dir());
    }
    state.cycles[3].phase = Phase::Failed;
    assert!(make_room(&store, &mut state).unwrap());
    assert_eq!(state.cycles.len(), RETAINED_CYCLES - 1);
    assert!(state.garbage.is_empty());
    assert_eq!(state.latest, Some(1));
    assert!(!store.cycle_path(4).unwrap().exists());
    for cycle in &state.cycles {
        store
            .validate_snapshot(cycle.sequence, cycle.snapshot.as_ref().unwrap())
            .unwrap();
    }
    assert_eq!(
        store.load_state().unwrap(),
        Some(serde_json::to_value(&state).unwrap())
    );
}

#[test]
fn restart_marks_interrupted_attempt_failed_and_finishes_partial_garbage_cleanup_idempotently() {
    let (_root, args) = fixture();
    let (plan, selected) = enrollment(&args).unwrap();
    let store = Store::open(&args.directory, &selected, false).unwrap();
    let mut state = State::new(plan.sources.len());
    add_cycle(&store, &mut state, 1, Phase::Complete);
    state.latest = Some(1);
    state.completed = 1;
    state.promoted = 1;
    cycle_directory(&store, 2, false);
    cycle_directory(&store, 3, false);
    add_cycle(&store, &mut state, 4, Phase::Running);
    state.garbage = vec![2, 3];
    store
        .save_state(&serde_json::to_value(&state).unwrap())
        .unwrap();
    assert!(store.prune_sequence(2).unwrap());
    drop(store); // Simulate restart after the first garbage directory was removed.
    let store = Store::open(&args.directory, &selected, true).unwrap();
    let mut restored: State = serde_json::from_value(store.load_state().unwrap().unwrap()).unwrap();
    recover(&store, &mut restored, plan.sources.len()).unwrap();
    assert!(restored.garbage.is_empty());
    assert!(!store.cycle_path(2).unwrap().exists());
    assert!(!store.cycle_path(3).unwrap().exists());
    assert!(
        store
            .cycle_path(4)
            .unwrap()
            .join("selection.json")
            .is_file()
    );
    let interrupted = restored
        .cycles
        .iter()
        .find(|cycle| cycle.sequence == 4)
        .unwrap();
    assert!(interrupted.phase == Phase::Failed && interrupted.snapshot.is_none());
    assert_eq!(restored.latest, Some(1));
    assert_eq!(restored.completed, 1);
    let after = serde_json::to_value(&restored).unwrap();
    recover(&store, &mut restored, plan.sources.len()).unwrap();
    assert_eq!(serde_json::to_value(&restored).unwrap(), after);
    assert_eq!(store.load_state().unwrap(), Some(after));
    store
        .validate_snapshot(1, restored.cycles[0].snapshot.as_ref().unwrap())
        .unwrap();
}

#[test]
fn rejected_successor_preserves_latest_and_never_enters_publication_before_reclamation() {
    let (_root, args) = fixture();
    let (plan, selected) = enrollment(&args).unwrap();
    assert_eq!(selected["quality_policy"], "source-heldout-loss-v1");
    let store = Store::open(&args.directory, &selected, false).unwrap();
    let mut state = State::new(plan.sources.len());
    for (sequence, approved, expected_latest) in [(1, true, 1), (2, false, 1), (3, true, 3)] {
        let input = state
            .latest
            .map(|previous| store.cycle_path(previous).unwrap().join("training/adapter"));
        evaluation::fixture_input(&store, sequence, approved, state.latest, input.as_deref());
        state.cycles.push(Cycle {
            sequence,
            source: 0,
            phase: Phase::Running,
            snapshot: None,
            training: None,
            publication: None,
            next_publication_attempt: 0,
        });
        state.next_sequence = sequence + 1;
        let decision = evaluation::verify(&store, sequence).unwrap();
        select_successor(
            &mut state,
            store.snapshot_cycle(sequence).unwrap(),
            sequence,
            &decision,
            true,
        )
        .unwrap();
        assert_eq!(state.latest, Some(expected_latest));
        assert_eq!(state.sources[0].revision, Some(sequence));
        assert!(
            state.cycles.last().unwrap().phase
                == if approved {
                    Phase::Trained
                } else {
                    Phase::Rejected
                }
        );
    }
    assert_eq!((state.completed, state.promoted, state.rejected), (3, 2, 1));
    recover(&store, &mut state, plan.sources.len()).unwrap();
    state.cycles[1].phase = Phase::Trained;
    assert!(recover(&store, &mut state, plan.sources.len()).is_err());
    state.cycles[1].phase = Phase::Rejected;
    for sequence in 4..=8 {
        add_cycle(&store, &mut state, sequence, Phase::Running);
    }
    assert!(make_room(&store, &mut state).unwrap());
    assert!(!store.cycle_path(2).unwrap().exists());
    assert!(store.cycle_path(1).unwrap().exists()); // Pending approved publication.
    assert!(store.cycle_path(3).unwrap().exists()); // Current approved warmstart.
    assert_eq!(state.latest, Some(3));
}
