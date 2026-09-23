//! Coordinator/storage fixtures only. Opaque cycle files are not model-work evidence.

use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
};

use clap::Parser;

use super::*;

pub(super) fn fixture() -> (tempfile::TempDir, Options) {
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

#[test]
fn automatic_aggregation_enrollment_is_explicit_frozen_and_exclusive() {
    let (root, mut args) = fixture();
    let key = |byte| {
        hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[byte; 32])
                .verifying_key()
                .as_bytes(),
        )
    };
    let validation = json!({"publisher_key":key(44),"name":"heldout","min_revision":1,"manifest_id":"b".repeat(64)});
    let aggregate = json!({"version":1,"dataset":{"publisher_key":key(43),"name":"public-a",
        "revision":1,"manifest_id":"a".repeat(64)},"adapters":[
            {"publisher_key":key(45),"name":"a","min_revision":1},
            {"publisher_key":key(46),"name":"b","min_revision":1},
            {"publisher_key":key(47),"name":"c","min_revision":1}]});
    let original = enrollment(&args).unwrap().1;
    assert!(original.get("aggregate_updates").is_none());
    let plan = root.path().join("aggregate.json");
    let validation_path = root.path().join("validation.json");
    for (path, value) in [(&plan, &aggregate), (&validation_path, &validation)] {
        fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    args.aggregate_plan = Some(plan);
    assert!(enrollment(&args).is_err());
    args.validation_source = Some(validation_path);
    let selected = enrollment(&args).unwrap().1;
    assert_eq!(selected["aggregate_updates"]["plan"], aggregate);
    assert_eq!(
        selected["aggregate_updates"]["validation_source"],
        validation
    );
    assert!(!args.directory.exists());
    let store = Store::open(&args.directory, &selected, false).unwrap();
    let retained = fs::read(args.directory.join("enrollment.json")).unwrap();
    drop(store);
    let mut changed = selected;
    changed["aggregate_updates"]["plan"]["adapters"][0]["publisher_key"] = key(48).into();
    assert!(Store::open(&args.directory, &changed, true).is_err());
    assert_eq!(
        fs::read(args.directory.join("enrollment.json")).unwrap(),
        retained
    );
    args.peer_updates = Some(root.path().join("peer-updates.json"));
    fs::write(
        args.peer_updates.as_ref().unwrap(),
        serde_json::to_vec(&json!({"version":1,
        "channels":[{"publisher_key":key(48),"name":"individual"}]}))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(
        args.peer_updates.as_ref().unwrap(),
        fs::Permissions::from_mode(0o600),
    )
    .unwrap();
    assert!(enrollment(&args).is_err());
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
        retirement: None,
        next_publication_attempt: 0,
    });
    state.next_sequence = sequence + 1;
}

#[test]
fn retired_local_selection_cannot_fall_back_to_base_after_restored_aggregate_expires() {
    let (_root, args) = fixture();
    let (plan, enrollment) = enrollment(&args).unwrap();
    let store = Store::open(&args.directory, &enrollment, false).unwrap();
    let mut state = State::new(plan.sources.len());
    assert_eq!(
        current_adapter(&args, &store, &state).unwrap().origin["kind"],
        "pinned_base"
    );
    state.completed = 1;
    state.promoted = 1;
    state.next_sequence = 2;
    let failure = current_adapter(&args, &store, &state).err().unwrap();
    assert_eq!(
        failure.to_string(),
        "train_loop_restored_authority_unavailable"
    );
    // Historical counters alone cannot authorize an absent local selection.
    assert!(recover(&store, &mut state, plan.sources.len()).is_err());
}

#[test]
fn restored_selection_reconciles_serving_and_next_training_without_renewing_authority() {
    // Exercise the runtime boundary after the durable recovery module selected a
    // predecessor. These are inert files, not training or model-quality evidence.
    let (root, mut args) = fixture();
    args.serving_directory = Some(root.path().join("serving"));
    for directory in [&args.runtime_root, args.serving_directory.as_ref().unwrap()] {
        fs::DirBuilder::new().mode(0o700).create(directory).unwrap();
    }
    let (plan, enrollment) = enrollment(&args).unwrap();
    let store = Store::open(&args.directory, &enrollment, false).unwrap();
    let mut serving = serving::Serving::open(&args, &enrollment).unwrap();
    let mut state = State::new(plan.sources.len());
    add_cycle(&store, &mut state, 1, Phase::Complete);
    add_cycle(&store, &mut state, 2, Phase::Complete);
    state.completed = 2;
    state.promoted = 2;
    state.latest = Some(2);
    reconcile_selected_adapter(&args, &store, &mut state, &mut serving).unwrap();
    let directory = args.serving_directory.as_ref().unwrap();
    let newer = super::super::serving_snapshot::peek(directory, &args.runtime_root)
        .unwrap()
        .unwrap();
    let (predecessor, original_expiry, provenance) = {
        state.latest = Some(1);
        serving::local_candidate(&store, &state).unwrap().unwrap()
    };
    let before = serde_json::to_value(&state).unwrap();
    reconcile_selected_adapter(&args, &store, &mut state, &mut serving).unwrap();
    assert_eq!(serde_json::to_value(&state).unwrap(), before);
    let restored = super::super::serving_snapshot::peek(directory, &args.runtime_root)
        .unwrap()
        .unwrap();
    assert_ne!(restored.id, newer.id);
    assert_eq!(restored.expires_unix_seconds, original_expiry);
    assert_eq!(
        serde_json::to_value(&restored.adapter_files).unwrap(),
        provenance["adapter_files"]
    );
    let current = current_adapter(&args, &store, &state).unwrap();
    assert_eq!(current.adapter_root.as_ref(), Some(&predecessor));
    let next = cycle_options(
        &args,
        &plan.sources[0],
        store.cycle_path(state.next_sequence).unwrap(),
        Some(3),
        current.adapter_root,
    )
    .unwrap();
    assert_eq!(next.adapter_root, Some(predecessor));
    assert_eq!(
        (next.steps, next.threads, next.max_seconds),
        (args.steps, args.threads, args.max_seconds)
    );
    assert!(next.spare_capacity);
    assert_eq!(next.dataset_name, plan.sources[0].name);
    // Reconciliation is idempotent, not a fresh selection lease or training cycle.
    let retained = fs::read(directory.join("current.json")).unwrap();
    reconcile_selected_adapter(&args, &store, &mut state, &mut serving).unwrap();
    assert_eq!(fs::read(directory.join("current.json")).unwrap(), retained);
    assert_eq!(serde_json::to_value(&state).unwrap(), before);
    let entries = || {
        fs::read_dir(directory)
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<BTreeSet<_>>()
    };
    let original_entries = entries();
    for code in [
        "peer_update_import_busy",
        "compute_deadline",
        "source_unavailable",
    ] {
        assert!(
            checked_integrity_recovery::<()>(Err(anyhow::anyhow!(code)), &mut serving).is_err()
        );
        assert_eq!(fs::read(directory.join("current.json")).unwrap(), retained);
        assert_eq!(entries(), original_entries);
    }
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
fn catalog_only_enrollment_and_empty_wait_survive_resume_without_enrolling_cache() {
    let (_root, args) = fixture();
    let (old, _) = enrollment(&args).unwrap();
    let catalog =
        json!({"publisher_key":old.sources[0].publisher_key,"name":"eligible-public-sources"});
    fs::write(
        &args.plan,
        serde_json::to_vec(&json!({"version":2,"sources":[],
        "catalogs":[catalog]}))
        .unwrap(),
    )
    .unwrap();
    let (plan, selection) = enrollment(&args).unwrap();
    assert!(plan.sources.is_empty());
    assert_eq!(selection["source_choice_uses_cache_inventory"], false);
    assert_eq!(
        selection["source_discovery"],
        "signed-same-publisher-catalogs-v1"
    );
    let store = Store::open(&args.directory, &selection, false).unwrap();
    let mut state = State::new(0);
    state.catalog = Some(catalogs::Registry::new(&plan).unwrap());
    recover(&store, &mut state, 0).unwrap();
    assert!(state.select(&plan, false, 100).is_none());
    let restored: State = serde_json::from_value(store.load_state().unwrap().unwrap()).unwrap();
    restored
        .catalog
        .unwrap()
        .validate(&plan, now().unwrap())
        .unwrap();
    assert!(!args.cache.exists());
}

#[test]
fn newly_offered_exact_revision_is_selected_without_repeating_completed_pin() {
    let (_root, args) = fixture();
    let (mut plan, _) = enrollment(&args).unwrap();
    plan.sources.truncate(1);
    plan.sources[0].manifest_id = Some(hex::encode([7; 32]));
    plan.sources[0].min_revision = Some(7);
    let mut state = State::new(1);
    state.sources[0].revision = Some(7);
    assert_eq!(state.select(&plan, false, 100), None);
    plan.sources[0].manifest_id = Some(hex::encode([8; 32]));
    plan.sources[0].min_revision = Some(8);
    assert_eq!(state.select(&plan, false, 100), Some(0));
    assert_eq!(
        required_revision(&plan.sources[0], &state.sources[0], false).unwrap(),
        Some(8)
    );
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
        retirement: None,
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
            retirement: None,
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
