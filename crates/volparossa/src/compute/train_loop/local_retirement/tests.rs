//! Real signed dataset/bundle binding with inert reports; no model execution claim.

use std::{
    fs,
    os::unix::fs::{DirBuilderExt as _, PermissionsExt as _},
};

use super::*;

fn setup(count: u64) -> (tempfile::TempDir, Options, Store, State) {
    let (root, args) = super::super::tests::fixture();
    let store = Store::open(
        &args.directory,
        &json!({"local_retirement_fixture":true}),
        false,
    )
    .unwrap();
    let mut state = State::new(1);
    for sequence in 1..=count {
        let previous = (sequence > 1).then_some(sequence - 1);
        let path = previous.map(|id| store.cycle_path(id).unwrap().join("training/adapter"));
        evaluation::fixture_input(&store, sequence, true, previous, path.as_deref());
        state.cycles.push(Cycle {
            sequence,
            source: 0,
            phase: Phase::Complete,
            snapshot: Some(store.snapshot_cycle(sequence).unwrap()),
            training: None,
            publication: None,
            next_publication_attempt: 0,
            retirement: None,
        });
    }
    state.next_sequence = count + 1;
    state.completed = count;
    state.promoted = count;
    state.latest = Some(count);
    (root, args, store, state)
}

fn damage(store: &Store, sequence: u64, name: &str) {
    let path = store.cycle_path(sequence).unwrap().join(name);
    fs::write(&path, b"different bounded local fixture bytes").unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn approved_successor_returns_only_to_exact_original_local_predecessor_and_reopens() {
    let (_root, args, store, mut state) = setup(2);
    let bundle = fs::read(store.cycle_path(2).unwrap().join("adapter.bundle")).unwrap();
    let original = state.cycles[1].snapshot.clone().unwrap();
    let approval = store.read_cycle_json(2, "evaluation.json").unwrap();
    assert_eq!(
        protected_sequences(&store, &state).unwrap(),
        BTreeSet::from([1])
    );
    damage(&store, 2, "training/adapter/adapter_model.safetensors");
    assert!(evaluation::verify(&store, 2).is_err());
    assert!(recover_active(&args, &store, &mut state, &mut None).unwrap());
    assert_eq!(state.latest, Some(1));
    assert_eq!((state.completed, state.promoted, state.rejected), (2, 2, 0));
    assert_eq!(state.cycles[1].snapshot.as_ref(), Some(&original));
    assert_eq!(
        serde_json::to_value(verify(&store, &state.cycles[1]).unwrap()).unwrap(),
        approval
    );
    assert_eq!(
        fs::read(store.cycle_path(2).unwrap().join("adapter.bundle")).unwrap(),
        bundle
    );
    let saved = store.load_state().unwrap().unwrap();
    assert!(!recover_active(&args, &store, &mut state, &mut None).unwrap());
    assert_eq!(store.load_state().unwrap().unwrap(), saved);
    drop(store);
    let reopened = Store::open(
        &args.directory,
        &json!({"local_retirement_fixture":true}),
        true,
    )
    .unwrap();
    let resumed: State = serde_json::from_value(reopened.load_state().unwrap().unwrap()).unwrap();
    assert!(verify(&reopened, &resumed.cycles[1]).unwrap().approved);
    assert_eq!(resumed.latest, Some(1));
    assert!(!args.runtime_root.exists() && !args.model_root.exists());
}

#[test]
fn pending_local_validation_against_damaged_successor_is_failed_not_reinterpreted() {
    let (_root, args, store, mut state) = setup(3);
    state.latest = Some(2);
    state.completed = 2;
    state.promoted = 2;
    let cycle = &mut state.cycles[2];
    fs::remove_file(store.cycle_path(3).unwrap().join("evaluation.json")).unwrap();
    cycle.phase = Phase::Evaluating;
    cycle.snapshot = None;
    cycle.training = Some(store.snapshot_training(3).unwrap());
    let selection = store.read_cycle_json(3, "selection.json").unwrap();
    damage(&store, 2, "training/adapter/README.md");
    assert!(recover_active(&args, &store, &mut state, &mut None).unwrap());
    assert!(state.cycles[2].phase == Phase::Failed);
    assert_eq!(
        store.read_cycle_json(3, "selection.json").unwrap(),
        selection
    );
    assert_eq!(state.latest, Some(1));
}

#[test]
fn source_bundle_or_approval_changes_are_not_extraction_retirement() {
    for name in ["dataset.json", "adapter.bundle", "evaluation.json"] {
        let (_root, args, store, mut state) = setup(2);
        let before = serde_json::to_value(&state).unwrap();
        damage(&store, 2, "training/adapter/adapter_config.json");
        damage(&store, 2, name);
        let error = recover_active(&args, &store, &mut state, &mut None).unwrap_err();
        assert!(!recovery_blocked(&error));
        assert_eq!(serde_json::to_value(&state).unwrap(), before);
    }
}

#[test]
fn missing_or_expired_exact_predecessor_never_selects_an_arbitrary_older_cycle() {
    let (_root, args, store, mut state) = setup(3);
    let record = evaluation::verify(&store, 3).unwrap();
    let before = serde_json::to_value(&state).unwrap();
    assert!(predecessor(&args, &store, &state, &record, now().unwrap() + 3600).is_err());
    damage(&store, 2, "training/adapter/adapter_model.safetensors");
    damage(&store, 3, "training/adapter/adapter_model.safetensors");
    let error = recover_active(&args, &store, &mut state, &mut None).unwrap_err();
    assert!(recovery_blocked(&error));
    assert_eq!(serde_json::to_value(&state).unwrap(), before);
    assert_eq!(state.latest, Some(3));
}

#[test]
fn proven_corruption_with_no_predecessor_withdraws_serving_before_blocking() {
    let (root, mut args, store, mut state) = setup(1);
    args.serving_directory = Some(root.path().join("serving"));
    for path in [&args.runtime_root, args.serving_directory.as_ref().unwrap()] {
        fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    }
    let mut serving =
        serving::Serving::open(&args, &json!({"local_retirement_fixture":true})).unwrap();
    serving
        .as_mut()
        .unwrap()
        .reconcile(&args, &store, &state)
        .unwrap();
    let selected = args.serving_directory.as_ref().unwrap();
    let before = crate::compute::serving_snapshot::peek(selected, &args.runtime_root)
        .unwrap()
        .unwrap();
    assert!(
        crate::compute::serving_snapshot::admission_allowed(selected, &args.runtime_root, &before)
            .unwrap()
    );
    damage(&store, 1, "training/adapter/adapter_model.safetensors");
    let error = recover_active(&args, &store, &mut state, &mut serving).unwrap_err();
    assert!(recovery_blocked(&error));
    let retained = crate::compute::serving_snapshot::peek(selected, &args.runtime_root)
        .unwrap()
        .unwrap();
    assert_eq!(retained.id, before.id);
    assert!(
        !crate::compute::serving_snapshot::admission_allowed(
            selected,
            &args.runtime_root,
            &retained
        )
        .unwrap()
    );
    assert!(state.cycles[0].retirement.is_none());
    assert!(!allows_empty_latest(&store, &state).unwrap());
}

#[test]
fn retired_evidence_cannot_be_changed_a_second_time_or_forge_a_predecessor() {
    let (_root, args, store, mut state) = setup(2);
    damage(&store, 2, "training/adapter/adapter_config.json");
    recover_active(&args, &store, &mut state, &mut None).unwrap();
    state.cycles[1].retirement.as_mut().unwrap().restored_origin["sequence"] = 99.into();
    assert!(verify(&store, &state.cycles[1]).is_err());
    state.cycles[1].retirement.as_mut().unwrap().restored_origin["sequence"] = 1.into();
    fs::write(
        store
            .cycle_path(2)
            .unwrap()
            .join("training/adapter/adapter_config.json"),
        b"second change",
    )
    .unwrap();
    assert!(verify(&store, &state.cycles[1]).is_err());
}
