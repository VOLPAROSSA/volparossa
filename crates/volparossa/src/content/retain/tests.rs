use std::os::unix::fs::PermissionsExt as _;

use clap::Parser as _;
use ed25519_dalek::SigningKey;

use super::*;

fn key() -> String {
    hex::encode(
        SigningKey::generate(&mut rand_core::OsRng)
            .verifying_key()
            .as_bytes(),
    )
}

#[test]
fn interrupted_upload_keeps_reservation_and_original_deadline_across_reopen() {
    let parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = parent.path().join("owner");
    let enrollment = b"exact original owner selection";
    let mut state = State::new(enrollment, 100, 500, 250).unwrap();
    assert_eq!(state.deadline, 250);
    assert!(state.reserve(key(), "deposit", 700, 1000, 110).unwrap());
    {
        let store = Store::open(&root, false).unwrap();
        store.write("enrollment.json", enrollment, false).unwrap();
        store.checkpoint(&state, "original", 250).unwrap();
        assert!(Store::open(&root, true).is_err());
    }
    let store = Store::open(&root, true).unwrap();
    let mut reopened = store.load().unwrap();
    reopened.validate(enrollment, 500, 250, 1000).unwrap();
    assert_eq!(reopened.uploads_reserved_bytes, 700);
    assert_eq!(reopened.pending.as_ref().unwrap().sequence, 1);
    assert_eq!(reopened.deadline, 250);
    reopened.pending = None; // Simulates reaped/aborted I/O, never an upload refund.
    assert!(!reopened.reserve(key(), "deposit", 700, 1000, 150).unwrap());
    assert_eq!(reopened.uploads_reserved_bytes, 700);
    assert_eq!(reopened.attempt_sequence, 1);
    assert!(reopened.reserve(key(), "inspect", 0, 1000, 150).unwrap());
    assert_eq!(reopened.uploads_reserved_bytes, 700);
    assert!(
        reopened
            .validate(b"different enrollment", 500, 250, 1000)
            .is_err()
    );
    assert!(reopened.validate(enrollment, 500, 260, 1000).is_err());
}

#[test]
fn receiptless_historical_confirmation_cannot_become_a_copy() {
    let enrollment = b"original";
    let mut state = State::new(enrollment, 100, 500, 700).unwrap();
    let provider = key();
    state.attempt_sequence = 1;
    state.last_observed = 110;
    state.observations.insert(
        provider.clone(),
        Observation {
            sequence: 1,
            operation: "inspect".into(),
            checked_at: 110,
            outcome: "complete".into(),
            original: None,
        },
    );
    state.confirmed_holders.push(provider.clone());
    state.validate(enrollment, 500, 700, 1000).unwrap();
    assert!(verify_history(&state, b"original signed manifest").is_err());
    state.observations.get_mut(&provider).unwrap().outcome = "unavailable".into();
    assert!(state.validate(enrollment, 500, 700, 1000).is_err());
    state.confirmed_holders.clear();
    state.validate(enrollment, 500, 700, 1000).unwrap();
    verify_history(&state, b"original signed manifest").unwrap();
}

#[test]
fn resume_rechecks_an_ambiguous_holder_even_when_discovery_omits_it() {
    let mut state = State::new(b"original", 100, 500, 700).unwrap();
    let known = key();
    assert!(
        state
            .reserve(known.clone(), "deposit", 100, 500, 110)
            .unwrap()
    );
    let pending = state.pending.take().unwrap();
    state.observations.insert(
        pending.provider_key,
        Observation {
            sequence: pending.sequence,
            operation: pending.operation,
            checked_at: 120,
            outcome: "interrupted".into(),
            original: None,
        },
    );
    // A deposit may have reached the peer before its reply was lost. Neither
    // reservation nor history establishes a current copy; only a new Inspect can.
    let current_discovery_batch: Vec<String> = Vec::new();
    let selected: Vec<_> = recheck_candidates(&state)
        .into_iter()
        .chain(current_discovery_batch)
        .collect();
    assert_eq!(selected, [known]);
    assert!(state.confirmed_holders.is_empty());
    assert_eq!(state.uploads_reserved_bytes, 100);
    assert_eq!(state.deadline, 600);
}

#[test]
fn state_never_follows_a_replacement_lock_or_symlink_record() {
    let parent = tempfile::tempdir().unwrap();
    std::fs::set_permissions(parent.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let root = parent.path().join("owner");
    let store = Store::open(&root, false).unwrap();
    let outside = parent.path().join("other");
    let original = b"must remain untouched";
    std::fs::write(&outside, original).unwrap();
    std::os::unix::fs::symlink(&outside, root.join("state.json")).unwrap();
    assert!(store.read("state.json", 1024).is_err());
    assert!(store.write("state.json", b"replacement", true).is_err());
    assert_eq!(std::fs::read(outside).unwrap(), original);
}

#[test]
fn retain_is_explicit_owner_enrollment_without_caller_chosen_providers() {
    use clap::CommandFactory as _;
    crate::Cli::command().debug_assert();
    let args = [
        "volparossa",
        "content",
        "retain",
        "--manifest",
        "original.pb",
        "--cache",
        "source",
        "--identity",
        "identity.key",
        "--passphrase-file",
        "passphrase",
        "--directory",
        "owner",
        "--max-upload-bytes",
        "1000",
    ];
    assert!(crate::Cli::try_parse_from(args).is_ok());
    assert!(crate::Cli::try_parse_from(args.into_iter().chain(["--resume"])).is_err());
    assert!(crate::Cli::try_parse_from(args.into_iter().chain(["--execute", "--resume"])).is_ok());
    assert!(
        crate::Cli::try_parse_from(args.into_iter().chain(["--provider-key", &key()])).is_err()
    );
}
