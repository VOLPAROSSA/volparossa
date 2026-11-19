use std::{fs, sync::atomic::Ordering};

use ed25519_dalek::Signer as _;
use sha2::{Digest as _, Sha256};
use volparossa_content::private_storage::PrivateStorageStore;

use super::super::{
    retained::{Handoff, HandoffPhase},
    state::LockedJournal,
};
use super::{Charge, LocalProviders, LockedSet, keys_and_grants, operations, transfer};

#[tokio::test]
async fn standalone_reserve_with_lost_terminal_remains_charged_by_parent_until_recovered() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let state = root.join("set");
    let child_path = state.join("copy-0");
    let (owner, providers, grants) = keys_and_grants();
    let ciphertext = b"standalone-reserve-fixture";
    let length = u64::try_from(ciphertext.len()).unwrap();
    let hash = Sha256::digest(ciphertext).into();
    let source = root.join("ciphertext");
    fs::write(&source, ciphertext).unwrap();
    let set =
        LockedSet::create(&state, &owner.verifying_key(), length, hash, &grants, 600).unwrap();
    let (mut input, _) = transfer::checked_input(&source, hash).unwrap();
    let first = LocalProviders::start(root, &providers, &grants, true);
    first.lose_terminal[0].store(true, Ordering::SeqCst);

    // The standalone writer opens only the child and cannot update the parent manifest.
    let mut child = LockedJournal::open(&child_path).unwrap();
    let original = child.journal.target().unwrap();
    assert!(
        transfer::deposit_retained(&first.socket, &grants[0], &owner, &mut child, &mut input)
            .await
            .is_err()
    );
    assert!(child.journal.lease.is_none());
    assert!(!child.journal.reserve_unsent());
    drop(child);
    assert_eq!(set.data.copies[0].charge, Charge::Unattempted);
    assert_eq!(
        set.report("status").unwrap()["uncertain_payload_bytes"],
        length
    );
    drop(set);
    first.stop().await;

    let store = PrivateStorageStore::open_existing(&root.join("provider-0")).unwrap();
    let usage = store.usage().unwrap();
    assert_eq!((usage.leases, usage.reserved_bytes), (1, length));
    drop(store);
    let mut reopened = LockedSet::open(&state).unwrap();
    assert_eq!(reopened.data.copies[0].charge, Charge::Uncertain);
    let before = reopened.report("status").unwrap();
    assert_eq!(before["uncertain_payload_bytes"], length);
    assert_eq!(before["physical_payload_charge_upper_bound"], length);

    let second = LocalProviders::start(root, &providers, &grants, false);
    second.reject_before_ready[0].store(true, Ordering::SeqCst);
    let rejected = operations::deposit(&mut reopened, &second.socket, &owner, &mut input)
        .await
        .unwrap();
    assert_eq!(rejected["operation_complete"], false);
    assert_eq!(rejected["uncertain_payload_bytes"], length);
    assert_eq!(rejected["physical_payload_charge_upper_bound"], 2 * length);
    let recovered = operations::deposit(&mut reopened, &second.socket, &owner, &mut input)
        .await
        .unwrap();
    assert_eq!(recovered["operation_complete"], true);
    assert_eq!(recovered["uncertain_payload_bytes"], 0);
    assert_eq!(recovered["committed_payload_bytes"], 2 * length);
    assert_eq!(
        reopened.copy(0).unwrap().journal.archive_id,
        original.archive_id
    );
    second.stop().await;
    let usage = PrivateStorageStore::open_existing(&root.join("provider-0"))
        .unwrap()
        .usage()
        .unwrap();
    assert_eq!((usage.leases, usage.committed_bytes), (1, length));
}

#[test]
fn legacy_child_retains_its_charge_and_original_signed_handoff_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let state = temporary.path().join("set");
    let (owner, _, grants) = keys_and_grants();
    let length = 17;
    let set = LockedSet::create(
        &state,
        &owner.verifying_key(),
        length,
        [7; 32],
        &grants,
        600,
    )
    .unwrap();
    let child_path = state.join("copy-0");
    let journal_path = child_path.join("archive.json");
    let current = fs::read_to_string(&journal_path).unwrap();
    let marker = r#","reserve_attempted":false"#;
    assert_eq!(current.matches(marker).count(), 1);
    let legacy = current.replace(marker, "");
    fs::write(&journal_path, &legacy).unwrap();
    drop(set);

    let child = LockedJournal::open(&child_path).unwrap();
    assert!(!child.journal.reserve_unsent());
    child.save().unwrap();
    assert_eq!(fs::read_to_string(journal_path).unwrap(), legacy);

    // A placement signature covers this nested handoff's original JSON field order and bytes.
    let unsigned = format!(r#"{{"from":0,"to":2,"phase":"copying","initial_journal":{legacy}}}"#);
    let placement_bytes = |handoff: &str| {
        let mut bytes = b"VOLPAROSSA/private-storage-fragment-placement/v1\0".to_vec();
        let root = serde_json::to_string(&[7_u8; 32]).unwrap();
        let authority = format!(
            r#"{{"version":1,"root_sha256":{root},"placements":[{{"fragment":0,"handoff":{handoff}}}]}}"#
        );
        bytes.extend_from_slice(authority.as_bytes());
        bytes
    };
    let signature = owner.sign(&placement_bytes(&unsigned));
    let handoff: Handoff = serde_json::from_str(&unsigned).unwrap();
    assert_eq!(handoff.phase, HandoffPhase::Copying);
    let reconstructed = serde_json::to_string(&handoff).unwrap();
    assert_eq!(reconstructed, unsigned);
    owner
        .verifying_key()
        .verify_strict(&placement_bytes(&reconstructed), &signature)
        .unwrap();
    drop(child);
    let reopened = LockedSet::open(&state).unwrap();
    assert_eq!(reopened.data.copies[0].charge, Charge::Uncertain);
    assert_eq!(reopened.data.copies[1].charge, Charge::Unattempted);
    assert_eq!(
        reopened.report("status").unwrap()["uncertain_payload_bytes"],
        length
    );
}
