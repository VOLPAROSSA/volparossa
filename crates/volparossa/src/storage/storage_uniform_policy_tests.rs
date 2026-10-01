//! Legacy fixtures are assembled here only; production creation has one fixed policy.
use std::{fs, path::Path};

use clap::Parser as _;
use ed25519_dalek::{Signer as _, SigningKey};
use sha2::{Digest as _, Sha256};
use volparossa_content::{
    CHUNK_BYTES, Validity,
    private_storage::{
        ARCHIVE_COPY_TARGET, PrivateStorageStore,
        protocol::{GrantLimits, SignedStorageGrant, StorageRights, VerifiedStorageGrant},
    },
};

use super::super::operations as fragments;
use super::{CopyBinding, LockedFragments, Plan, SignedManifest, signing_bytes};
use crate::storage::peer::{
    replicas::{operations as replicas, retained::LockedSet, tests::LocalProviders},
    state::{Journal, LockedJournal},
    transfer,
};

#[test]
fn uniform_policy_cli_accepts_only_core_target_without_advertising_a_choice() {
    let prefix = ["volparossa", "storage", "fragments", "create"];
    let key = hex::encode([11; 32]);
    let args = [
        "--state",
        "/state",
        "--input",
        "/ciphertext",
        "--sha256",
        &key,
        "--provider-key",
        &key,
        "--grant",
        "/grant",
        "--already-encrypted",
    ];
    assert_eq!(ARCHIVE_COPY_TARGET, 2);
    assert!(crate::Cli::try_parse_from(prefix.into_iter().chain(args)).is_ok());
    for copies in ["1", "2", "3", "7"] {
        assert_eq!(
            crate::Cli::try_parse_from(prefix.into_iter().chain(args).chain(["--copies", copies]))
                .is_ok(),
            copies == "2"
        );
    }
    let help = crate::Cli::try_parse_from(prefix.into_iter().chain(["--help"])).unwrap_err();
    assert!(!help.to_string().contains("--copies"));
}

fn grants() -> (SigningKey, Vec<SigningKey>, Vec<VerifiedStorageGrant>) {
    let owner = SigningKey::from_bytes(&[21; 32]);
    let providers: Vec<_> = [11, 33, 44, 55]
        .into_iter()
        .map(|byte| SigningKey::from_bytes(&[byte; 32]))
        .collect();
    let now = crate::storage::now().unwrap();
    let grants = providers
        .iter()
        .map(|provider| {
            SignedStorageGrant::issue(
                provider,
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
            .verify(&provider.verifying_key(), now)
            .unwrap()
        })
        .collect();
    (owner, providers, grants)
}

/// Encode one historically valid third copy without providing a production creation bypass.
fn legacy_third_copy(
    path: &Path,
    grant: &VerifiedStorageGrant,
    length: u64,
    hash: [u8; 32],
) -> [u8; 32] {
    let journal = Journal::new(
        grant,
        length,
        hash,
        transfer::requested_expiry(grant, 600).unwrap(),
    )
    .unwrap();
    let archive = journal.archive_id;
    let record = serde_json::json!({"provider_key": journal.provider_key, "archive_id": archive,
        "grant_sha256": <[u8; 32]>::from(Sha256::digest(grant.signed().encode())), "charge": "unattempted"});
    drop(LockedJournal::create(&path.join("copy-2"), journal).unwrap());
    let manifest = path.join("replicas.json");
    let mut value: serde_json::Value =
        serde_json::from_slice(&fs::read(&manifest).unwrap()).unwrap();
    value["copies"].as_array_mut().unwrap().push(record);
    fs::write(manifest, serde_json::to_vec(&value).unwrap()).unwrap();
    archive
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One real four-provider lifecycle proves fixed creation and nondestructive recovery of both legacy archive formats."
)]
async fn uniform_policy_preserves_legacy_three_copy_lifecycle_and_actual_charges() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let (owner, providers, grants) = grants();
    let bytes = vec![73_u8; 128];
    let length = bytes.len() as u64;
    let hash: [u8; 32] = Sha256::digest(&bytes).into();
    let source = root.join("ciphertext");
    fs::write(&source, &bytes).unwrap();
    let (mut input, _) = transfer::checked_input(&source, hash).unwrap();
    let plan = Plan {
        ciphertext_bytes: length,
        sha256: hash,
        fragment_bytes: 32,
        copies: ARCHIVE_COPY_TARGET,
    };
    let refused = root.join("refused");
    assert!(
        LockedFragments::create(
            &refused,
            &owner,
            &mut input,
            Plan { copies: 3, ..plan },
            &grants,
            600
        )
        .is_err()
    );
    assert!(!refused.exists());
    assert!(
        LockedSet::create(
            &refused,
            &owner.verifying_key(),
            length,
            hash,
            &grants[..3],
            600
        )
        .is_err()
    );
    assert!(!refused.exists());
    // Real new archives have exactly the same target, irrespective of provider-pool size.
    let fragment_path = root.join("fragments");
    let mut set =
        LockedFragments::create(&fragment_path, &owner, &mut input, plan, &grants, 600).unwrap();
    assert_eq!(set.report("status").unwrap()["copies_per_fragment"], 2);
    let replica_path = root.join("replicas");
    let whole = LockedSet::create(
        &replica_path,
        &owner.verifying_key(),
        length,
        hash,
        &grants[..2],
        600,
    )
    .unwrap();
    assert_eq!(
        whole.report("status").unwrap()["distinct_provider_identities"],
        2
    );
    drop(whole);
    // Historical layouts are fixtures, not a new production option.
    legacy_third_copy(&replica_path, &grants[2], length, hash);
    for index in 0..set.data.fragments.len() {
        let provider = (index + 2) % grants.len();
        let fragment = &set.data.fragments[index];
        let archive_id = legacy_third_copy(
            &set.fragment_path(index),
            &grants[provider],
            fragment.length,
            fragment.sha256,
        );
        set.data.fragments[index].copies.push(CopyBinding {
            provider,
            archive_id,
        });
    }
    set.data.copies_per_fragment = 3;
    let signature = hex::encode(owner.sign(&signing_bytes(&set.data).unwrap()).to_bytes());
    let encoded = serde_json::to_vec(&SignedManifest {
        manifest: set.data,
        signature,
    })
    .unwrap();
    fs::write(fragment_path.join("fragments.json"), &encoded).unwrap();
    drop(set.directory);
    let peers = LocalProviders::start(root, &providers, &grants, true);
    let set = LockedFragments::open(&fragment_path).unwrap();
    let mut whole = LockedSet::open(&replica_path).unwrap();
    assert_eq!(
        fragments::deposit(&set, &peers.socket, &owner, &mut input)
            .await
            .unwrap()["operation_complete"],
        true
    );
    assert_eq!(
        replicas::deposit(&mut whole, &peers.socket, &owner, &mut input)
            .await
            .unwrap()["operation_complete"],
        true
    );
    drop(input);
    fs::remove_file(&source).unwrap();
    drop(set);
    drop(whole);
    let set = LockedFragments::open(&fragment_path).unwrap();
    let mut whole = LockedSet::open(&replica_path).unwrap();
    for renewal in [None, Some(1200)] {
        let report = fragments::refresh(&set, &peers.socket, &owner, renewal)
            .await
            .unwrap();
        assert_eq!(report["operation_complete"], true);
        assert_eq!(report["copies_per_fragment"], 3);
        assert_eq!(report["physical_payload_charge_upper_bound"], 3 * length);
        let report = replicas::refresh(&mut whole, &peers.socket, &owner, renewal)
            .await
            .unwrap();
        assert_eq!(report["operation_complete"], true);
        assert_eq!(report["distinct_provider_identities"], 3);
        assert_eq!(report["physical_payload_charge_upper_bound"], 3 * length);
    }
    peers.online[0].store(false, std::sync::atomic::Ordering::SeqCst);
    let fragmented_output = root.join("restored-fragments");
    let whole_output = root.join("restored-replicas");
    assert_eq!(
        fragments::restore(&set, &peers.socket, &owner, &fragmented_output)
            .await
            .unwrap()["operation_complete"],
        true
    );
    assert_eq!(
        replicas::restore(&mut whole, &peers.socket, &owner, &whole_output)
            .await
            .unwrap()["operation_complete"],
        true
    );
    assert_eq!(fs::read(fragmented_output).unwrap(), bytes);
    assert_eq!(fs::read(whole_output).unwrap(), bytes);
    assert_eq!(
        set.report("status").unwrap()["physical_payload_charge_upper_bound"],
        3 * length
    );
    assert_eq!(
        whole.report("status").unwrap()["physical_payload_charge_upper_bound"],
        3 * length
    );
    assert_eq!(
        fs::read(fragment_path.join("fragments.json")).unwrap(),
        encoded
    );
    peers.online[0].store(true, std::sync::atomic::Ordering::SeqCst);
    assert_eq!(
        fragments::delete(&set, &peers.socket, &owner)
            .await
            .unwrap()["physical_payload_charge_upper_bound"],
        0
    );
    for provider in &providers[..3] {
        assert_eq!(
            replicas::delete(&mut whole, &peers.socket, &owner, provider.verifying_key())
                .await
                .unwrap()["operation_complete"],
            true
        );
    }
    assert_eq!(
        whole.report("status").unwrap()["physical_payload_charge_upper_bound"],
        0
    );
    peers.stop().await;
    for index in 0..providers.len() {
        let store =
            PrivateStorageStore::open_existing(&root.join(format!("provider-{index}"))).unwrap();
        assert_eq!(store.usage().unwrap().leases, 0);
    }
}
