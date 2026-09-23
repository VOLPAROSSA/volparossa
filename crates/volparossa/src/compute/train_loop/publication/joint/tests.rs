//! Inert enrollment/order/checkpoint tests, not model, approval or network proof.

use std::{fs, os::unix::fs::PermissionsExt as _};

use ed25519_dalek::VerifyingKey;
use serde_json::json;

use super::*;
use crate::compute::train_loop::{self, Cycle, publication::DrainOutcome};

fn key(byte: u8) -> VerifyingKey {
    ed25519_dalek::SigningKey::from_bytes(&[byte; 32]).verifying_key()
}

fn write_json(path: &Path, value: &Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn options() -> (tempfile::TempDir, Options) {
    let (temporary, mut args) = train_loop::tests::fixture();
    let aggregate = temporary.path().join("aggregate.json");
    let validation = temporary.path().join("validation.json");
    write_json(
        &aggregate,
        &json!({"version":1,"dataset":{
        "publisher_key":hex::encode(key(43).as_bytes()),"name":"public-a",
        "revision":1,"manifest_id":"a".repeat(64)},"adapters":[
        {"publisher_key":hex::encode(key(45).as_bytes()),"name":"a","min_revision":1},
        {"publisher_key":hex::encode(key(46).as_bytes()),"name":"b","min_revision":1},
        {"publisher_key":hex::encode(key(47).as_bytes()),"name":"c","min_revision":1}]}),
    );
    write_json(
        &validation,
        &json!({"publisher_key":hex::encode(key(44).as_bytes()),
        "name":"heldout","min_revision":1,"manifest_id":"b".repeat(64)}),
    );
    args.aggregate_plan = Some(aggregate);
    args.validation_source = Some(validation);
    args.publish_name = Some("shared-adapters".into());
    args.publication_key = Some(key(48));
    // Deliberately absent: these tests must never reach signing or a model worker.
    args.identity = Some(temporary.path().join("absent-identity"));
    args.passphrase_file = Some(temporary.path().join("absent-passphrase"));
    args.publish_cache = Some(temporary.path().join("absent-publish-cache"));
    args.first_publication_revision = 17;
    (temporary, args)
}

fn setup() -> (tempfile::TempDir, Options, Store, State, Value) {
    let (temporary, args) = options();
    let (plan, enrollment) = train_loop::enrollment(&args).unwrap();
    let store = Store::open(&args.directory, &enrollment, false).unwrap();
    let mut state = State::new(plan.sources.len());
    aggregate_updates::restore(&args, &store, &mut state, &enrollment).unwrap();
    restore_order(&args, &store, &mut state, &enrollment).unwrap();
    (temporary, args, store, state, enrollment)
}

fn local(state: &mut State, sequence: u64, phase: Phase) {
    state.cycles.push(Cycle {
        sequence,
        source: 0,
        phase,
        snapshot: None,
        training: None,
        publication: None,
        next_publication_attempt: 0,
    });
    state.next_sequence = sequence + 1;
}

fn aggregate(state: &mut State, sequence: u64, phase: &str) {
    let mut registry = serde_json::to_value(state.aggregate_updates.as_ref().unwrap()).unwrap();
    let cohort =
        json!({"manifest_ids":["a".repeat(64),"b".repeat(64),"c".repeat(64)],"revisions":[1,1,1]});
    let manifest = (phase == "complete")
        .then(|| json!({"created":1,"expires":2,"manifest_id":"d".repeat(64)}));
    registry["rounds"].as_array_mut().unwrap().push(json!({
        "sequence":sequence,"cohort":cohort,"phase":"approved","observed_at":1,"expires":2,
        "local_predecessor":null,"baseline_origin":{"kind":"inert-order-fixture"},
        "baseline_files":null,"baseline_expires":null,"approval":{"inert_fixture_not_model_evidence":true},
        "snapshot":{},"publication":{"phase":phase,"next_attempt":0,"manifest":manifest}}));
    registry["next_sequence"] = (sequence + 1).into();
    registry["seen"] = cohort;
    state.aggregate_updates = Some(serde_json::from_value(registry).unwrap());
}

fn no_signing_or_worker_files(args: &Options) {
    assert!(!args.identity.as_ref().unwrap().exists());
    assert!(!args.publish_cache.as_ref().unwrap().exists());
    assert!(!args.runtime_root.exists() && !args.model_root.exists());
    assert!(fs::read_dir(&args.directory).unwrap().all(|entry| {
        let name = entry.unwrap().file_name();
        ["enrollment.json", "state.json", ".coordinator.lock"]
            .iter()
            .any(|expected| name == *expected)
    }));
}

#[test]
fn joint_mode_requires_new_exact_owner_enrollment_and_does_not_change_legacy_bytes() {
    let (temporary, mut args) = options();
    let selected = train_loop::enrollment(&args).unwrap().1;
    assert_eq!(
        selected["aggregate_publication"],
        json!({"version":1,
        "ordering":"shared-local-and-aggregate-revisions","first_revision":17,"original_authority_required":true})
    );
    let aggregate_path = args.aggregate_plan.take();
    let local_only = train_loop::enrollment(&args).unwrap().1;
    assert!(local_only.get("aggregate_publication").is_none());
    let store = Store::open(&args.directory, &local_only, false).unwrap();
    let original = fs::read(args.directory.join("enrollment.json")).unwrap();
    let mut state = State::new(3);
    let before = serde_json::to_vec(&state).unwrap();
    assert!(
        serde_json::to_value(&state)
            .unwrap()
            .get("publication_order")
            .is_none()
    );
    restore_order(&args, &store, &mut state, &local_only).unwrap();
    assert_eq!(serde_json::to_vec(&state).unwrap(), before);
    drop(store);
    args.aggregate_plan = aggregate_path;
    args.resume = true;
    assert!(Store::open(&args.directory, &selected, true).is_err());
    assert_eq!(
        fs::read(args.directory.join("enrollment.json")).unwrap(),
        original
    );
    args.publish_name = None;
    let adoption_only = train_loop::enrollment(&args).unwrap().1;
    assert!(adoption_only.get("aggregate_updates").is_some());
    assert!(adoption_only.get("aggregate_publication").is_none());
    assert!(!temporary.path().join("absent-identity").exists());
}

#[test]
fn assignment_is_checkpointed_before_signing_and_reopens_without_sequence_collision() {
    let (_temporary, mut args, store, mut state, enrollment) = setup();
    local(&mut state, 1, Phase::Trained);
    aggregate(&mut state, 1, "pending");
    assert_eq!(
        assign(&args, &store, &mut state).unwrap(),
        [(Target::Aggregate(1), 17), (Target::Local(1), 18)]
    );
    let durable = store.load_state().unwrap().unwrap();
    assert_eq!(durable, serde_json::to_value(&state).unwrap());
    no_signing_or_worker_files(&args);
    drop(store);
    args.resume = true;
    let store = Store::open(&args.directory, &enrollment, true).unwrap();
    let mut reopened: State = serde_json::from_value(store.load_state().unwrap().unwrap()).unwrap();
    restore_order(&args, &store, &mut reopened, &enrollment).unwrap();
    assert_eq!(
        assign(&args, &store, &mut reopened).unwrap(),
        [(Target::Aggregate(1), 17), (Target::Local(1), 18)]
    );
    assert_eq!(store.load_state().unwrap().unwrap(), durable);
    aggregate(&mut reopened, 2, "pending");
    local(&mut reopened, 2, Phase::PublishPending);
    assert_eq!(
        assign(&args, &store, &mut reopened).unwrap(),
        [
            (Target::Aggregate(1), 17),
            (Target::Local(1), 18),
            (Target::Aggregate(2), 19),
            (Target::Local(2), 20)
        ]
    );
    no_signing_or_worker_files(&args);
}

#[tokio::test]
async fn failed_assignment_checkpoint_prevents_any_signing_or_delivery_attempt() {
    let (_temporary, args, store, mut state, _enrollment) = setup();
    local(&mut state, 1, Phase::Trained);
    let checkpoint = args.directory.join("state.json");
    let original = fs::read(&checkpoint).unwrap();
    fs::set_permissions(&checkpoint, fs::Permissions::from_mode(0o644)).unwrap();
    let (_sender, activity) = watch::channel(true);
    let error = pending(
        &args,
        Path::new("/absent-joint-publication-control.sock"),
        &store,
        &mut state,
        &activity,
        None,
    )
    .await
    .unwrap_err();
    assert_eq!(error.to_string(), "train_loop_private_file_invalid");
    assert_eq!(fs::read(&checkpoint).unwrap(), original);
    no_signing_or_worker_files(&args);
    fs::set_permissions(&checkpoint, fs::Permissions::from_mode(0o600)).unwrap();
    let durable: State = serde_json::from_value(store.load_state().unwrap().unwrap()).unwrap();
    assert!(
        durable
            .publication_order
            .unwrap()
            .get(Target::Local(1))
            .is_none()
    );
}

#[test]
fn resume_cannot_create_missing_order_or_accept_an_unrequested_ledger() {
    let (_temporary, mut args, store, mut state, enrollment) = setup();
    args.resume = true;
    state.publication_order = None;
    store
        .save_state(&serde_json::to_value(&state).unwrap())
        .unwrap();
    let durable = store.load_state().unwrap().unwrap();
    assert_eq!(
        restore_order(&args, &store, &mut state, &enrollment)
            .unwrap_err()
            .to_string(),
        "train_publication_order_missing"
    );
    assert_eq!(store.load_state().unwrap().unwrap(), durable);
    state.publication_order = Some(Ledger::new(17).unwrap());
    let mut legacy = enrollment.clone();
    legacy
        .as_object_mut()
        .unwrap()
        .remove("aggregate_publication");
    assert_eq!(
        restore_order(&args, &store, &mut state, &legacy)
            .unwrap_err()
            .to_string(),
        "train_publication_order_unrequested"
    );
    args.first_publication_revision = 18;
    assert_eq!(
        restore_order(&args, &store, &mut state, &enrollment)
            .unwrap_err()
            .to_string(),
        "train_publication_order_enrollment"
    );
    assert_eq!(store.load_state().unwrap().unwrap(), durable);
    no_signing_or_worker_files(&args);
}

#[test]
fn pruned_durable_targets_drop_only_their_mapping_and_keep_the_monotone_cursor() {
    let (_temporary, mut args, store, mut state, enrollment) = setup();
    aggregate(&mut state, 1, "pending");
    local(&mut state, 1, Phase::Trained);
    local(&mut state, 2, Phase::Trained);
    assign(&args, &store, &mut state).unwrap();
    state.cycles.retain(|cycle| cycle.sequence == 2);
    let mut registry = serde_json::to_value(state.aggregate_updates.as_ref().unwrap()).unwrap();
    registry["rounds"] = json!([]);
    state.aggregate_updates = Some(serde_json::from_value(registry).unwrap());
    assert_eq!(
        assign(&args, &store, &mut state).unwrap(),
        [(Target::Local(2), 19)]
    );
    drop(store);
    args.resume = true;
    let store = Store::open(&args.directory, &enrollment, true).unwrap();
    let mut state: State = serde_json::from_value(store.load_state().unwrap().unwrap()).unwrap();
    restore_order(&args, &store, &mut state, &enrollment).unwrap();
    aggregate(&mut state, 2, "pending");
    local(&mut state, 3, Phase::Trained);
    assert_eq!(
        assign(&args, &store, &mut state).unwrap(),
        [
            (Target::Local(2), 19),
            (Target::Aggregate(2), 20),
            (Target::Local(3), 21)
        ]
    );
    let order = state.publication_order.as_ref().unwrap();
    assert_eq!(order.get(Target::Aggregate(1)), None);
    assert_eq!(order.get(Target::Local(1)), None);
    assert_eq!(
        store.load_state().unwrap().unwrap(),
        serde_json::to_value(&state).unwrap()
    );
    no_signing_or_worker_files(&args);
}

#[test]
fn drain_waits_for_both_kinds_and_preserves_expired_terminal_outcome() {
    let (_temporary, _args, _store, mut state, _enrollment) = setup();
    assert_eq!(super::super::settled(&state), Some(DrainOutcome::Complete));
    aggregate(&mut state, 1, "pending");
    assert_eq!(super::super::settled(&state), None);
    let mut registry = serde_json::to_value(state.aggregate_updates.as_ref().unwrap()).unwrap();
    registry["rounds"][0]["publication"]["phase"] = "expired".into();
    state.aggregate_updates = Some(serde_json::from_value(registry).unwrap());
    assert_eq!(super::super::settled(&state), Some(DrainOutcome::Expired));
    local(&mut state, 1, Phase::PublishPending);
    assert_eq!(super::super::settled(&state), None);
    state.cycles[0].phase = Phase::Complete;
    assert_eq!(super::super::settled(&state), Some(DrainOutcome::Expired));
}
