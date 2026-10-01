//! Real signed storage-service lifecycles; no protected-overlay or automatic-repair claim.
use std::{fs, os::unix::fs::PermissionsExt as _, path::Path};

use ed25519_dalek::SigningKey;
use volparossa_content::{
    CHUNK_BYTES, Validity,
    private_storage::{
        PrivateStorageStore,
        protocol::{GrantLimits, SignedStorageGrant, StorageRights},
    },
};

use super::{
    super::{
        super::{
            tests::handoff::{HandoffPeers, Step},
            transfer,
        },
        operations,
        retained::LockedFragments,
        tests::{keys_and_grants, plan},
    },
    authorize, replace,
};

fn write_json(path: &Path, value: &serde_json::Value) {
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One exact signed placement proves both parent/child crash windows and rejection before unsigned recovery."
)]
async fn signed_fragment_authority_precedes_recovery_and_preserves_exact_archive_expiry() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let (owner, providers, grants) = keys_and_grants(16);
    let bytes = vec![29; 3 * CHUNK_BYTES + 73];
    let source = root.join("ciphertext");
    fs::write(&source, &bytes).unwrap();
    let (mut input, _) = transfer::checked_input(&source, plan(&bytes).sha256).unwrap();
    let state = root.join("fragments");
    let mut set =
        LockedFragments::create(&state, &owner, &mut input, plan(&bytes), &grants, 600).unwrap();
    let peers = HandoffPeers::start(root, &providers, &grants, true);
    assert_eq!(
        operations::deposit(&set, &peers.socket, &owner, &mut input)
            .await
            .unwrap()["operation_complete"],
        true
    );
    let original_root = fs::read(state.join("fragments.json")).unwrap();
    let child = state.join("fragment-0000");
    let original_child = fs::read(child.join("replicas.json")).unwrap();
    authorize(
        &mut set,
        &owner,
        0,
        &providers[0].verifying_key(),
        &grants[2],
        600,
    )
    .unwrap();
    let planned = set.fragment(0).unwrap().copy(2).unwrap().journal.clone();
    drop(set);
    let authority = state.join("placement-authorizations.json");
    let signed = fs::read(&authority).unwrap();
    // Crash after parent fsync, before child installation: only the signed parent survived.
    fs::remove_file(child.join("copy-2/archive.json")).unwrap();
    fs::remove_dir(child.join("copy-2")).unwrap();
    fs::write(child.join("replicas.json"), &original_child).unwrap();
    let reopened = LockedFragments::open(&state).unwrap();
    let actual = reopened
        .fragment(0)
        .unwrap()
        .copy(2)
        .unwrap()
        .journal
        .clone();
    assert!(actual == planned);
    assert_eq!(
        reopened.report("status").unwrap()["physical_payload_charge_upper_bound"],
        2 * bytes.len()
    );
    drop(reopened);
    let exact_child = fs::read(child.join("replicas.json")).unwrap();
    // Crash after child intent fsync, before exact per-copy journal creation.
    fs::remove_file(child.join("copy-2/archive.json")).unwrap();
    fs::remove_dir(child.join("copy-2")).unwrap();
    let mut unsigned: serde_json::Value = serde_json::from_slice(&exact_child).unwrap();
    unsigned["handoff"]["initial_journal"]["requested_expiry"] =
        (planned.requested_expiry + 1).into();
    write_json(&child.join("replicas.json"), &unsigned);
    assert!(LockedFragments::open(&state).is_err());
    assert!(
        !child.join("copy-2").exists(),
        "rejected unsigned state must not create a journal"
    );
    fs::write(child.join("replicas.json"), &exact_child).unwrap();
    fs::remove_file(&authority).unwrap();
    assert!(LockedFragments::open(&state).is_err());
    assert!(!child.join("copy-2").exists());
    fs::write(&authority, &signed).unwrap();
    // Recreated private authority must retain the production file-permission contract.
    fs::set_permissions(&authority, fs::Permissions::from_mode(0o600)).unwrap();
    let mut tampered: serde_json::Value = serde_json::from_slice(&signed).unwrap();
    tampered["authority"]["placements"][0]["fragment"] = 1.into();
    write_json(&authority, &tampered);
    assert!(LockedFragments::open(&state).is_err());
    assert!(!child.join("copy-2").exists());
    fs::write(&authority, &signed).unwrap();
    let reopened = LockedFragments::open(&state).unwrap();
    assert!(reopened.fragment(0).unwrap().copy(2).unwrap().journal == planned);
    assert_eq!(
        fs::read(state.join("fragments.json")).unwrap(),
        original_root
    );
    drop(reopened);
    // Existing replacement journals cannot silently change their signed initial expiry.
    let copy = child.join("copy-2/archive.json");
    let mut changed: serde_json::Value = serde_json::from_slice(&fs::read(&copy).unwrap()).unwrap();
    changed["requested_expiry"] = (planned.requested_expiry + 1).into();
    write_json(&copy, &changed);
    assert!(LockedFragments::open(&state).is_err());
    peers.stop().await;
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One fragment replacement joins lost reservation/readback/delete replies, restart, retained-byte accounting and ordinary archive operations."
)]
async fn fragment_replacement_reuses_signed_real_services_and_keeps_pending_retirement_charged() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let (owner, mut providers, mut grants) = keys_and_grants(16);
    let replacement = SigningKey::from_bytes(&[55; 32]);
    let now = crate::storage::now().unwrap();
    let grant = SignedStorageGrant::issue(
        &replacement,
        &owner.verifying_key(),
        GrantLimits {
            max_payload_bytes: 4 * CHUNK_BYTES as u64,
            max_leases: 16,
            rights: StorageRights::ALL,
            max_retention_seconds: 1800,
        },
        Validity {
            created: now,
            expires: now + 3600,
        },
    )
    .unwrap()
    .verify(&replacement.verifying_key(), now)
    .unwrap();
    providers.push(replacement);
    grants.push(grant);
    let bytes = vec![37; 3 * CHUNK_BYTES + 73];
    let length = bytes.len() as u64;
    let source = root.join("ciphertext");
    fs::write(&source, &bytes).unwrap();
    let (mut input, _) = transfer::checked_input(&source, plan(&bytes).sha256).unwrap();
    let state = root.join("fragments");
    let mut set =
        LockedFragments::create(&state, &owner, &mut input, plan(&bytes), &grants[..3], 600)
            .unwrap();
    let first = HandoffPeers::start(root, &providers, &grants, true);
    assert_eq!(
        operations::deposit(&set, &first.socket, &owner, &mut input)
            .await
            .unwrap()["operation_complete"],
        true
    );
    drop(input);
    fs::remove_file(&source).unwrap();
    let root_manifest = fs::read(state.join("fragments.json")).unwrap();
    first.lose_next(3, Step::Reserve);
    let pending = replace(
        &mut set,
        &first.socket,
        &owner,
        0,
        providers[0].verifying_key(),
        &grants[3],
        600,
    )
    .await
    .unwrap();
    assert_eq!(pending["handoff_stage"], "replacement_upload_pending");
    assert_eq!(pending["report_version"], 2);
    assert_eq!(pending["distinct_provider_identities"], 4);
    assert_eq!(pending["retained_copy_records"], 9);
    assert_eq!(
        pending["physical_payload_charge_upper_bound"],
        2 * length + CHUNK_BYTES as u64
    );
    let identity = set.fragment(0).unwrap().copy(2).unwrap().journal.archive_id;
    assert!(
        first
            .events()
            .iter()
            .all(|event| event.step != Step::Delete)
    );
    drop(set);
    first.stop().await;

    let second = HandoffPeers::start(root, &providers, &grants, false);
    let mut set = LockedFragments::open(&state).unwrap();
    second.lose_next(3, Step::Read);
    let pending = replace(
        &mut set,
        &second.socket,
        &owner,
        0,
        providers[0].verifying_key(),
        &grants[3],
        600,
    )
    .await
    .unwrap();
    assert_eq!(pending["handoff_stage"], "replacement_verification_pending");
    assert_eq!(
        set.fragment(0).unwrap().copy(2).unwrap().journal.archive_id,
        identity
    );
    assert!(
        second
            .events()
            .iter()
            .all(|event| event.step != Step::Delete)
    );
    drop(set);
    second.stop().await;

    let third = HandoffPeers::start(root, &providers, &grants, false);
    let mut set = LockedFragments::open(&state).unwrap();
    third.lose_next(0, Step::Delete);
    let pending = replace(
        &mut set,
        &third.socket,
        &owner,
        0,
        providers[0].verifying_key(),
        &grants[3],
        600,
    )
    .await
    .unwrap();
    assert_eq!(pending["handoff_stage"], "source_delete_unconfirmed");
    assert_eq!(
        pending["physical_payload_charge_upper_bound"],
        2 * length + CHUNK_BYTES as u64
    );
    assert_eq!(pending["fully_redundant_from_retained_receipts"], true);
    let events = third.events();
    let verified = events
        .iter()
        .position(|event| {
            event.provider == 3
                && event.step == Step::Read
                && event.bytes == CHUNK_BYTES as u64
                && event.terminal_sent
        })
        .unwrap();
    let delete = events
        .iter()
        .position(|event| event.provider == 0 && event.step == Step::Delete)
        .unwrap();
    assert!(verified < delete);
    let recovered = root.join("restored-ciphertext");
    assert_eq!(
        operations::restore(&set, &third.socket, &owner, &recovered)
            .await
            .unwrap()["operation_complete"],
        true
    );
    assert_eq!(fs::read(&recovered).unwrap(), bytes);
    assert_eq!(
        operations::refresh(&set, &third.socket, &owner, Some(1200))
            .await
            .unwrap()["operation_complete"],
        true
    );
    drop(set);
    third.stop().await;

    let fourth = HandoffPeers::start(root, &providers, &grants, false);
    let mut set = LockedFragments::open(&state).unwrap();
    let complete = replace(
        &mut set,
        &fourth.socket,
        &owner,
        0,
        providers[0].verifying_key(),
        &grants[3],
        600,
    )
    .await
    .unwrap();
    assert_eq!(complete["operation_complete"], true);
    assert_eq!(complete["pending_retirements"], 0);
    assert_eq!(complete["physical_payload_charge_upper_bound"], 2 * length);
    assert_eq!(
        set.fragment(0).unwrap().copy(2).unwrap().journal.archive_id,
        identity
    );
    assert_eq!(
        fs::read(state.join("fragments.json")).unwrap(),
        root_manifest
    );
    assert_eq!(
        operations::refresh(&set, &fourth.socket, &owner, None)
            .await
            .unwrap()["operation_complete"],
        true
    );
    let (mut restored_input, _) = transfer::checked_input(&recovered, plan(&bytes).sha256).unwrap();
    assert_eq!(
        operations::deposit(&set, &fourth.socket, &owner, &mut restored_input)
            .await
            .unwrap()["operation_complete"],
        true
    );
    assert_eq!(
        operations::delete(&set, &fourth.socket, &owner)
            .await
            .unwrap()["physical_payload_charge_upper_bound"],
        0
    );
    drop(set);
    fourth.stop().await;
    for index in 0..4 {
        let store =
            PrivateStorageStore::open_existing(&root.join(format!("handoff-provider-{index}")))
                .unwrap();
        assert_eq!(store.usage().unwrap().leases, 0);
    }
}
