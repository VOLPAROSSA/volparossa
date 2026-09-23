//! Inert extraction/journal/retention checks, not executed aggregation or model quality.

use super::*;
use std::os::unix::fs::DirBuilderExt as _;

fn identity(value: &[u8]) -> FileSnapshot {
    FileSnapshot {
        bytes: value.len() as u64,
        sha256: hex::encode(Sha256::digest(value)),
    }
}

fn original() -> Snapshot {
    FILES
        .into_iter()
        .map(|(name, _)| {
            (
                format!("candidate/import/adapter/{name}"),
                identity(b"original"),
            )
        })
        .chain([
            ("adapter.bundle".into(), identity(b"original bundle")),
            (
                "candidate/comparison/decision.json".into(),
                identity(b"original decision"),
            ),
            (
                "job/adapter/adapter_model.safetensors".into(),
                identity(b"original"),
            ),
        ])
        .collect()
}

fn round(sequence: u64, origin: Value) -> Round {
    Round {
        sequence,
        cohort: Cohort {
            manifest_ids: ["a".repeat(64), "b".repeat(64), "c".repeat(64)],
            revisions: [1, 1, 1],
        },
        phase: Phase::Approved,
        observed_at: 1,
        expires: u64::MAX,
        local_predecessor: None,
        baseline_origin: origin,
        baseline_files: None,
        baseline_expires: None,
        approval: Some(json!({"inert_structure_only":true})),
        snapshot: Some(original()),
        publication: None,
        retirement: None,
    }
}

fn registry(rounds: Vec<Round>) -> Registry {
    Registry {
        version: 1,
        selection: json!({}),
        next_sequence: rounds.len() as u64 + 1,
        next_poll: 0,
        verified_cohort_polls: 0,
        seen: None,
        active: None,
        rounds,
        garbage: vec![],
    }
}

fn retired() -> Record {
    Record {
        version: 1,
        scope: SCOPE.into(),
        observed_at: 2,
        original_snapshot_sha256: "a".repeat(64),
        observed_adapter_files: Snapshot::new(),
        restored_origin: json!({"kind":"local_cycle","sequence":1}),
        restored_expires: 100,
    }
}

#[test]
fn only_extracted_bytes_are_attributable_and_original_bundle_job_and_approval_cannot_change() {
    let expected = original();
    assert!(changed_extraction(&expected, &expected).unwrap().is_none());
    let mut actual = expected.clone();
    actual.insert(
        "candidate/import/adapter/adapter_model.safetensors".into(),
        identity(b"damaged"),
    );
    let observed = changed_extraction(&expected, &actual).unwrap().unwrap();
    assert_eq!(observed.len(), 3);
    assert_eq!(observed["adapter_model.safetensors"], identity(b"damaged"));
    for name in [
        "adapter.bundle",
        "job/adapter/adapter_model.safetensors",
        "candidate/comparison/decision.json",
    ] {
        let mut invalid = actual.clone();
        invalid.insert(name.into(), identity(b"changed original evidence"));
        assert!(changed_extraction(&expected, &invalid).is_err());
    }
    actual.remove("candidate/import/adapter/README.md");
    assert!(changed_extraction(&expected, &actual).is_err());
    let mut oversized = expected.clone();
    oversized
        .get_mut("candidate/import/adapter/adapter_model.safetensors")
        .unwrap()
        .bytes = 2 * 1024 * 1024 + 1;
    assert!(changed_extraction(&expected, &oversized).is_err());
}

#[test]
fn old_rounds_keep_exact_serde_and_retired_approved_round_cannot_be_selected() {
    let round = round(1, json!({"kind":"pinned_base"}));
    let original = serde_json::to_vec(&round).unwrap();
    assert!(
        !String::from_utf8(original.clone())
            .unwrap()
            .contains("retirement")
    );
    let reopened: Round = serde_json::from_slice(&original).unwrap();
    assert_eq!(serde_json::to_vec(&reopened).unwrap(), original);
    let mut registry = registry(vec![reopened]);
    select_for_recovery(&mut registry, 1).unwrap();
    assert_eq!(registry.active, Some(1));
    registry.rounds[0].retirement = Some(retired());
    assert!(select_for_recovery(&mut registry, 1).is_err());
    assert!(validate(&registry, &json!({})).is_err());
    registry.active = None;
    assert!(validate(&registry, &json!({})).is_ok());
    assert!(select_for_recovery(&mut registry, 2).is_err());
}

#[test]
fn expired_or_different_local_origin_never_becomes_a_recovery_candidate() {
    let (_temporary, args) = super::super::super::tests::fixture();
    let mut registry = registry(vec![round(1, json!({"kind":"pinned_base"}))]);
    registry.rounds[0].expires = now().unwrap();
    assert!(selected_for_sequence(&args, &registry, 1, None).is_err());
    registry.rounds[0].expires = u64::MAX;
    assert!(selected_for_sequence(&args, &registry, 1, Some(1)).is_err());
    // No directory or backend was created by these rejected selections.
    assert!(!args.directory.exists());
}

#[test]
fn retention_pins_exact_active_baseline_and_local_successor_aggregate_without_pinning_retired() {
    let (_temporary, args) = super::super::super::tests::fixture();
    let store = Store::open(&args.directory, &json!({}), false).unwrap();
    let mut registry = registry(vec![
        round(1, json!({"kind":"local_cycle","sequence":1})),
        round(2, json!({"kind":"aggregate_update","aggregate_sequence":1})),
        round(3, json!({"kind":"pinned_base"})),
    ]);
    registry.active = Some(2);
    assert_eq!(
        pinned_sequences(&registry, &store, None).unwrap(),
        BTreeSet::from([1, 2])
    );
    registry.active = Some(1);
    assert_eq!(pinned_local_predecessor(&registry), Some(1));
    registry.active = None;
    let cycle = store.cycle_path(1).unwrap();
    fs::DirBuilder::new().mode(0o700).create(&cycle).unwrap();
    let selection = cycle.join("selection.json");
    fs::write(
        &selection,
        serde_json::to_vec(&json!({"aggregate_predecessor":{
        "kind":"aggregate_update","aggregate_sequence":2}}))
        .unwrap(),
    )
    .unwrap();
    fs::set_permissions(&selection, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        pinned_sequences(&registry, &store, Some(1)).unwrap(),
        BTreeSet::from([2])
    );
    registry.rounds[1].retirement = Some(retired());
    assert!(
        pinned_sequences(&registry, &store, Some(1))
            .unwrap()
            .is_empty()
    );
}
