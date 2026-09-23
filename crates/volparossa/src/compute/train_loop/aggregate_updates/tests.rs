//! Inert journal/filesystem contracts, not evidence of aggregation, approval or training.

use std::os::unix::fs::{DirBuilderExt as _, PermissionsExt as _, symlink};

use super::*;

fn cohort() -> Cohort {
    Cohort {
        manifest_ids: ["a".repeat(64), "b".repeat(64), "c".repeat(64)],
        revisions: [1, 2, 3],
    }
}

fn selected() -> Value {
    // Registry persistence compares this exact enrollment. Input/signature
    // admission is deliberately not simulated by these lifecycle fixtures.
    json!({"version":1,"fixture":"inert-journal-contract-only"})
}

fn setup() -> (tempfile::TempDir, Options, Store, State, Value) {
    let (temporary, mut args) = super::super::tests::fixture();
    args.aggregate_plan = Some(temporary.path().join("aggregate-plan.json"));
    let enrollment = json!({"aggregate_updates":selected()});
    let store = Store::open(&args.directory, &enrollment, false).unwrap();
    (temporary, args, store, State::new(3), enrollment)
}

fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn directory(args: &Options, sequence: u64) -> PathBuf {
    let directory = root(args, sequence).unwrap();
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    write(
        &directory.join("cohort.json"),
        b"inert original cohort bytes",
    );
    directory
}

fn round(sequence: u64, phase: Phase, at: u64, expires: u64) -> Round {
    Round {
        sequence,
        cohort: cohort(),
        phase,
        observed_at: at,
        expires,
        local_predecessor: None,
        baseline_origin: json!({"kind":"pinned_base"}),
        baseline_files: None,
        baseline_expires: None,
        approval: None,
        snapshot: None,
        publication: None,
        retirement: None,
    }
}

fn registry(rounds: Vec<Round>) -> Registry {
    Registry {
        version: 1,
        selection: selected(),
        next_sequence: rounds.last().map_or(1, |round| round.sequence + 1),
        next_poll: 0,
        verified_cohort_polls: 0,
        seen: rounds.last().map(|round| round.cohort.clone()),
        active: None,
        rounds,
        garbage: Vec::new(),
    }
}

#[test]
fn interrupted_running_round_restores_failed_once_without_replacing_original_cohort() {
    let (_temporary, mut args, store, mut state, enrollment) = setup();
    let directory = directory(&args, 1);
    let original = snapshot(&directory).unwrap();
    let at = now().unwrap();
    let registry = registry(vec![round(1, Phase::Running, at, at + 600)]);
    checkpoint(&registry, &store, &mut state).unwrap();
    drop(store);
    args.resume = true;
    let store = Store::open(&args.directory, &enrollment, true).unwrap();
    let mut state: State = serde_json::from_value(store.load_state().unwrap().unwrap()).unwrap();
    restore(&args, &store, &mut state, &enrollment).unwrap();
    let recovered = state.aggregate_updates.as_ref().unwrap();
    assert_eq!(recovered.rounds[0].phase, Phase::Failed);
    assert_eq!(recovered.rounds[0].snapshot.as_ref(), Some(&original));
    assert_eq!(recovered.seen, Some(cohort()));
    assert!(!cohort().advances(recovered.seen.as_ref()).unwrap());
    assert_eq!(recovered.next_sequence, 2);
    assert!(recovered.active.is_none());
    assert!(!directory.join("job").exists());
    assert!(!directory.join("result.json").exists());
    assert_eq!(snapshot(&directory).unwrap(), original);
    assert_eq!((state.completed, state.promoted, state.rejected), (0, 0, 0));
    assert!(state.latest.is_none());
    let retained = serde_json::to_value(&state).unwrap();
    restore(&args, &store, &mut state, &enrollment).unwrap();
    assert_eq!(serde_json::to_value(state).unwrap(), retained);
}

#[test]
fn completed_but_expired_effective_authority_restores_expired_not_a_new_approval() {
    let (_temporary, mut args, store, mut state, enrollment) = setup();
    let directory = directory(&args, 1);
    let at = now().unwrap();
    let effective = at - 5;
    // This synthetic result marker is already expired: restoration must never
    // enter model/approval verification, execute it or promote its true flag.
    let result = json!({"operation":"compute_aggregate_adapters","optimizer_steps":0,
        "approved":true,"cohort":{"expires_unix_seconds":effective},
        "synthetic_lifecycle_fixture_only":true});
    let original_result = serde_json::to_vec(&result).unwrap();
    write(&directory.join("result.json"), &original_result);
    let registry = registry(vec![round(1, Phase::Running, at - 20, at + 600)]);
    checkpoint(&registry, &store, &mut state).unwrap();
    args.resume = true;
    restore(&args, &store, &mut state, &enrollment).unwrap();
    let recovered = state.aggregate_updates.as_ref().unwrap();
    assert_eq!(recovered.rounds[0].phase, Phase::Expired);
    assert_eq!(recovered.rounds[0].expires, effective);
    assert!(recovered.rounds[0].approval.is_none());
    assert!(recovered.active.is_none());
    assert_eq!(recovered.seen, Some(cohort()));
    assert_eq!(
        fs::read(directory.join("result.json")).unwrap(),
        original_result
    );
    assert!(!directory.join("job").exists());
    let retained = serde_json::to_value(&state).unwrap();
    restore(&args, &store, &mut state, &enrollment).unwrap();
    assert_eq!(serde_json::to_value(state).unwrap(), retained);
}

#[test]
fn legacy_resume_cannot_enable_aggregation_or_rewrite_enrollment() {
    let (temporary, mut args) = super::super::tests::fixture();
    let enrollment = json!({"legacy_fixture":true});
    let store = Store::open(&args.directory, &enrollment, false).unwrap();
    let original = fs::read(args.directory.join("enrollment.json")).unwrap();
    let mut state = State::new(3);
    args.resume = true;
    restore(&args, &store, &mut state, &enrollment).unwrap();
    assert!(state.aggregate_updates.is_none());
    args.aggregate_plan = Some(temporary.path().join("new-aggregate-plan.json"));
    assert!(restore(&args, &store, &mut state, &enrollment).is_err());
    let changed = json!({"legacy_fixture":true,"aggregate_updates":selected()});
    assert_eq!(
        restore(&args, &store, &mut state, &changed)
            .unwrap_err()
            .to_string(),
        "aggregate_updates_missing_state"
    );
    assert!(state.aggregate_updates.is_none());
    drop(store);
    assert!(Store::open(&args.directory, &changed, true).is_err());
    assert_eq!(
        fs::read(args.directory.join("enrollment.json")).unwrap(),
        original
    );
}

#[test]
fn bounded_retention_preserves_active_round_and_unrelated_owned_files() {
    let (temporary, args, store, mut state, _enrollment) = setup();
    let at = now().unwrap();
    let mut rounds = Vec::new();
    for sequence in 1..=RETAINED as u64 {
        let directory = directory(&args, sequence);
        let mut round = round(sequence, Phase::Failed, at, at + 600);
        round.snapshot = Some(snapshot(&directory).unwrap());
        rounds.push(round);
    }
    // Only exercise retention's active-ID exclusion, not approval validation.
    rounds[0].phase = Phase::Approved;
    rounds[0].approval = Some(json!({"synthetic_retention_marker_not_model_approval":true}));
    let mut registry = registry(rounds);
    registry.active = Some(1);
    let active_before = snapshot(&root(&args, 1).unwrap()).unwrap();
    let unrelated = temporary.path().join("unrelated-owner-file");
    write(&unrelated, b"must survive exact round pruning");
    assert!(make_room(&args, &store, &mut state, &mut registry).unwrap());
    assert_eq!(registry.active, Some(1));
    assert_eq!(registry.rounds.len(), RETAINED - 1);
    assert!(!root(&args, 2).unwrap().exists());
    assert_eq!(snapshot(&root(&args, 1).unwrap()).unwrap(), active_before);
    assert!(registry.garbage.is_empty());
    for sequence in 3..=RETAINED as u64 {
        assert!(root(&args, sequence).unwrap().join("cohort.json").is_file());
    }
    assert_eq!(
        fs::read(unrelated).unwrap(),
        b"must survive exact round pruning"
    );
    assert_eq!(
        store.load_state().unwrap().unwrap(),
        serde_json::to_value(&state).unwrap()
    );
}

#[test]
fn publication_records_do_not_rewrite_approval_snapshot_and_remain_owned_cleanup() {
    let (_temporary, args, _store, _state, _enrollment) = setup();
    let directory = directory(&args, 1);
    let original = snapshot(&directory).unwrap();
    let publication = directory.join("publication");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&publication)
        .unwrap();
    for name in [
        "request.json",
        "publication.pb",
        "manifest.json",
        "contribution.json",
    ] {
        write(
            &publication.join(name),
            b"inert publication bytes, not a signature",
        );
    }
    assert_eq!(snapshot(&directory).unwrap(), original);
    write(
        &publication.join("contribution.json"),
        b"inert later receipt",
    );
    assert_eq!(snapshot(&directory).unwrap(), original);
    write(&publication.join("unrelated-owner-data"), b"not disposable");
    assert!(prune(&directory).is_err());
    assert!(directory.join("cohort.json").is_file());
    fs::remove_file(publication.join("unrelated-owner-data")).unwrap();
    prune(&directory).unwrap();
    assert!(!directory.exists());
}

#[test]
fn unpublished_combination_is_retained_even_after_local_successor_replaces_it() {
    let (_temporary, args, store, mut state, _enrollment) = setup();
    let at = now().unwrap();
    let mut rounds = Vec::new();
    for sequence in 1..=RETAINED as u64 {
        let directory = directory(&args, sequence);
        let mut round = round(sequence, Phase::Failed, at, at + 600);
        round.snapshot = Some(snapshot(&directory).unwrap());
        rounds.push(round);
    }
    // Retention bookkeeping only: no invented proof of model approval.
    rounds[0].phase = Phase::Approved;
    rounds[0].publication = Some(publication::Record::pending());
    let mut registry = registry(rounds);
    assert!(registry.active.is_none());
    assert!(make_room(&args, &store, &mut state, &mut registry).unwrap());
    assert!(root(&args, 1).unwrap().is_dir());
    assert!(!root(&args, 2).unwrap().exists());
    assert_eq!(publication::pending_sequences(&registry), vec![1]);
}

#[test]
fn prune_preflights_unknown_files_links_and_active_garbage_before_deleting_anything() {
    let (temporary, args, _store, _state, _enrollment) = setup();
    let directory = directory(&args, 1);
    let original = fs::read(directory.join("cohort.json")).unwrap();
    let unknown = directory.join("user-notes.txt");
    write(&unknown, b"unrecognized user content");
    assert!(prune(&directory).is_err());
    assert_eq!(fs::read(directory.join("cohort.json")).unwrap(), original);
    assert!(unknown.is_file());
    // Each remaining probe gets a new exact fixture directory, never deletes
    // the unknown input merely to make the cleanup test pass.
    let outside = temporary.path().join("outside-original");
    write(&outside, b"outside retained bytes");
    for (sequence, linked) in [(2, true), (3, false)] {
        let directory = root(&args, sequence).unwrap();
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        if linked {
            symlink(&outside, directory.join("result.json")).unwrap();
        } else {
            fs::hard_link(&outside, directory.join("result.json")).unwrap();
        }
        assert!(prune(&directory).is_err());
        assert!(fs::symlink_metadata(directory.join("result.json")).is_ok());
        assert_eq!(fs::read(&outside).unwrap(), b"outside retained bytes");
    }
    let mut entry = round(1, Phase::Approved, 1, 2);
    entry.approval = Some(json!({"synthetic_retention_marker_not_model_approval":true}));
    entry.snapshot = Some(Snapshot::new());
    let mut registry = registry(vec![entry]);
    registry.active = Some(1);
    registry.garbage = vec![1];
    assert!(validate(&registry, &selected()).is_err());
}

#[test]
fn recorded_garbage_cleanup_is_idempotent_and_only_removes_the_exact_round() {
    let (_temporary, mut args, store, mut state, enrollment) = setup();
    let obsolete = directory(&args, 1);
    let survivor = directory(&args, 2);
    let mut registry = registry(Vec::new());
    registry.next_sequence = 3;
    registry.garbage = vec![1];
    checkpoint(&registry, &store, &mut state).unwrap();
    args.resume = true;
    restore(&args, &store, &mut state, &enrollment).unwrap();
    assert!(!obsolete.exists());
    assert!(survivor.join("cohort.json").is_file());
    assert!(state.aggregate_updates.as_ref().unwrap().garbage.is_empty());
    let retained = serde_json::to_value(&state).unwrap();
    restore(&args, &store, &mut state, &enrollment).unwrap();
    assert_eq!(serde_json::to_value(state).unwrap(), retained);
    assert!(survivor.join("cohort.json").is_file());
}
