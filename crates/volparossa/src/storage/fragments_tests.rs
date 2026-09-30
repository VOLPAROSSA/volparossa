//! Actual local `SQLite` custodians over signed frames; not a protected-overlay proof.

use std::{fs, os::unix::fs::MetadataExt as _, sync::atomic::Ordering};

use clap::Parser as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use volparossa_content::{
    CHUNK_BYTES, Validity,
    private_storage::{
        PrivateStorageStore,
        protocol::{GrantLimits, SignedStorageGrant, StorageRights, VerifiedStorageGrant},
    },
};

use super::super::tests::LocalProviders;
use super::{
    operations,
    retained::{LockedFragments, Plan},
    transfer,
};

fn keys_and_grants(max_leases: u32) -> (SigningKey, Vec<SigningKey>, Vec<VerifiedStorageGrant>) {
    let owner = SigningKey::from_bytes(&[21; 32]);
    let providers: Vec<_> = [11, 33, 44]
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
                    max_leases,
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

fn plan(bytes: &[u8]) -> Plan {
    Plan {
        ciphertext_bytes: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
        fragment_bytes: CHUNK_BYTES as u64,
        copies: 2,
    }
}

#[test]
fn fragments_cli_requires_encrypted_ack_and_explicit_provider_pairs() {
    let (_, providers, _) = keys_and_grants(16);
    let keys: Vec<_> = providers
        .iter()
        .map(|key| hex::encode(key.verifying_key().as_bytes()))
        .collect();
    let prefix = ["volparossa", "storage", "fragments"];
    let mut create = vec![
        "create",
        "--state",
        "/fragments",
        "--input",
        "/ciphertext",
        "--sha256",
        &keys[0],
        "--already-encrypted",
    ];
    for key in &keys {
        create.extend(["--provider-key", key, "--grant", "/grant"]);
    }
    assert!(crate::Cli::try_parse_from(prefix.into_iter().chain(create)).is_ok());
    for args in [
        vec![
            "deposit",
            "--state",
            "/fragments",
            "--input",
            "/ciphertext",
            "--already-encrypted",
        ],
        vec!["status", "--state", "/fragments"],
        vec!["progress", "--state", "/fragments"],
        vec!["restore", "--state", "/fragments", "--output", "/new"],
        vec![
            "renew",
            "--state",
            "/fragments",
            "--lifetime-seconds",
            "600",
        ],
        vec!["delete", "--state", "/fragments"],
    ] {
        assert!(crate::Cli::try_parse_from(prefix.into_iter().chain(args)).is_ok());
    }
    assert!(
        crate::Cli::try_parse_from(prefix.into_iter().chain([
            "deposit",
            "--state",
            "/fragments",
            "--input",
            "/ciphertext"
        ]))
        .is_err()
    );
}

#[test]
fn signed_root_is_private_locked_immutable_and_checks_aggregate_grant_limits() {
    let temp = tempfile::tempdir().unwrap();
    let source = temp.path().join("ciphertext");
    let bytes = vec![31; 3 * CHUNK_BYTES + 73];
    fs::write(&source, &bytes).unwrap();
    let (mut input, _) = transfer::checked_input(&source, plan(&bytes).sha256).unwrap();
    let (owner, providers, grants) = keys_and_grants(16);
    let path = temp.path().join("fragments");
    let set =
        LockedFragments::create(&path, &owner, &mut input, plan(&bytes), &grants, 600).unwrap();
    assert!(LockedFragments::open(&path).is_err());
    assert!(set.check_owner(&providers[0]).is_err());
    assert_eq!(set.data.fragments.len(), 4);
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(path.join("fragments.json")).unwrap().mode() & 0o777,
        0o600
    );
    drop(set);
    let manifest = path.join("fragments.json");
    let original = fs::read(&manifest).unwrap();
    let mut altered: serde_json::Value = serde_json::from_slice(&original).unwrap();
    altered["manifest"]["fragments"][0]["offset"] = 1.into();
    fs::write(&manifest, serde_json::to_vec(&altered).unwrap()).unwrap();
    assert!(LockedFragments::open(&path).is_err());
    fs::write(&manifest, &original).unwrap();
    assert!(LockedFragments::open(&path).is_ok());
    // Mutating both unsigned nested records consistently must still fail against the
    // immutable owner-signed root, not just the nested replica consistency check.
    let fragment = path.join("fragment-0000");
    let mut originals = Vec::new();
    for relative in ["replicas.json", "copy-0/archive.json"] {
        let file = fragment.join(relative);
        let bytes = fs::read(&file).unwrap();
        let mut value: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        if relative == "replicas.json" {
            value["copies"][0]["archive_id"] = serde_json::to_value([93_u8; 32]).unwrap();
        } else {
            value["archive_id"] = serde_json::to_value([93_u8; 32]).unwrap();
        }
        fs::write(&file, serde_json::to_vec(&value).unwrap()).unwrap();
        originals.push((file, bytes));
    }
    assert!(super::super::retained::LockedSet::open(&fragment).is_ok());
    assert!(LockedFragments::open(&path).is_err());
    for (file, bytes) in originals {
        fs::write(file, bytes).unwrap();
    }
    assert!(LockedFragments::open(&path).is_ok());
    let (_, _, limited) = keys_and_grants(1);
    let refused = temp.path().join("quota-refused");
    assert!(
        LockedFragments::create(&refused, &owner, &mut input, plan(&bytes), &limited, 600).is_err()
    );
    assert!(!refused.exists());
    let duplicate = vec![grants[0].clone(), grants[0].clone(), grants[2].clone()];
    assert!(
        LockedFragments::create(&refused, &owner, &mut input, plan(&bytes), &duplicate, 600)
            .is_err()
    );
    assert!(
        LockedFragments::create(
            &refused,
            &owner,
            &mut input,
            Plan {
                copies: 3,
                ..plan(&bytes)
            },
            &grants,
            600
        )
        .is_err()
    );
    assert!(!refused.exists());
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One three-store lifecycle joins signed fragmentation, lost reply/reopen, source removal, provider loss, repeated restoration and explicit deletion."
)]
async fn three_real_stores_hold_only_subsets_resume_then_restore_without_original_or_one_provider()
{
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let (owner, providers, grants) = keys_and_grants(16);
    let bytes: Vec<u8> = (0..3 * CHUNK_BYTES + 73)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect();
    let length = bytes.len() as u64;
    let hash = plan(&bytes).sha256;
    let source = root.join("synthetic-opaque-fixture");
    fs::write(&source, &bytes).unwrap();
    let (mut input, _) = transfer::checked_input(&source, hash).unwrap();
    let state = root.join("fragments");
    let set =
        LockedFragments::create(&state, &owner, &mut input, plan(&bytes), &grants, 600).unwrap();
    let identities: Vec<_> = (0..set.data.fragments.len())
        .map(|index| {
            let copies = set.fragment(index).unwrap();
            (0..2)
                .map(|copy| copies.copy(copy).unwrap().journal.archive_id)
                .collect::<Vec<_>>()
        })
        .collect();
    let first = LocalProviders::start(root, &providers, &grants, true);
    first.lose_terminal[0].store(true, Ordering::SeqCst);
    let partial = operations::deposit(&set, &first.socket, &owner, &mut input)
        .await
        .unwrap();
    assert_eq!(partial["operation_complete"], false);
    assert_eq!(partial["uncertain_payload_bytes"], CHUNK_BYTES as u64);
    assert_eq!(partial["physical_payload_charge_upper_bound"], 2 * length);
    assert!(
        set.fragment(0)
            .unwrap()
            .copy(0)
            .unwrap()
            .journal
            .lease
            .is_none()
    );
    drop(set);
    first.stop().await;
    for index in 0..3 {
        let store =
            PrivateStorageStore::open_existing(&root.join(format!("provider-{index}"))).unwrap();
        let usage = store.usage().unwrap();
        assert!(
            usage.reserved_bytes + usage.committed_bytes < length,
            "a provider must not hold the whole archive"
        );
        assert!(usage.leases > 0 && usage.leases < 4);
    }
    let peers = LocalProviders::start(root, &providers, &grants, false);
    let set = LockedFragments::open(&state).unwrap();
    let complete = operations::deposit(&set, &peers.socket, &owner, &mut input)
        .await
        .unwrap();
    assert_eq!(complete["operation_complete"], true);
    assert_eq!(complete["fully_redundant_from_retained_receipts"], true);
    assert_eq!(complete["committed_payload_bytes"], 2 * length);
    for (index, original) in identities.iter().enumerate() {
        let copies = set.fragment(index).unwrap();
        for (copy, archive) in original.iter().enumerate() {
            assert_eq!(&copies.copy(copy).unwrap().journal.archive_id, archive);
        }
    }
    assert_eq!(
        operations::refresh(&set, &peers.socket, &owner, None)
            .await
            .unwrap()["operation_complete"],
        true
    );
    assert_eq!(
        operations::refresh(&set, &peers.socket, &owner, Some(1200))
            .await
            .unwrap()["operation_complete"],
        true
    );
    drop(input);
    fs::remove_file(&source).unwrap();
    peers.online[0].store(false, Ordering::SeqCst);
    for index in 0..2 {
        let output = root.join(format!("reconstructed-{index}"));
        let restored = operations::restore(&set, &peers.socket, &owner, &output)
            .await
            .unwrap();
        assert_eq!(restored["operation_complete"], true);
        assert_eq!(restored["whole_archive_sha256_verified"], true);
        assert_eq!(restored["physical_payload_charge_upper_bound"], 2 * length);
        // Exercise the overlay fixture's actual validator against a genuine signed
        // three-store restore, not a separately invented JSON result shape.
        let fixture = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../tests/integration/private-storage-fragments-smoke.py");
        let mut checker = std::process::Command::new("python3")
            .args(["-B", "-c", "import json,runpy,sys; value=json.load(sys.stdin); runpy.run_path(sys.argv[1])['validate_restore_result'](value, sys.argv[2:])"])
            .arg(fixture)
            .args(providers.iter().map(|key| hex::encode(key.verifying_key().as_bytes())))
            .stdin(std::process::Stdio::piped())
            .stderr(std::process::Stdio::piped())
            .spawn()
            .unwrap();
        {
            use std::io::Write as _;
            checker
                .stdin
                .take()
                .unwrap()
                .write_all(&serde_json::to_vec(&restored).unwrap())
                .unwrap();
        }
        let checked = checker.wait_with_output().unwrap();
        assert!(
            checked.status.success(),
            "fragment fixture checker rejected actual restore: {}",
            String::from_utf8_lossy(&checked.stderr)
        );
        assert_eq!(fs::read(&output).unwrap(), bytes);
        assert_eq!(fs::metadata(&output).unwrap().mode() & 0o777, 0o600);
        assert!(
            operations::restore(&set, &peers.socket, &owner, &output)
                .await
                .is_err()
        );
    }
    // Losing both holders of fragment 0 must never publish a partially reconstructed archive.
    peers.online[1].store(false, Ordering::SeqCst);
    let incomplete_output = root.join("must-not-exist");
    let unavailable = operations::restore(&set, &peers.socket, &owner, &incomplete_output)
        .await
        .unwrap();
    assert_eq!(unavailable["operation_complete"], false);
    assert!(!incomplete_output.exists());
    peers.online[1].store(true, Ordering::SeqCst);
    let incomplete_delete = operations::delete(&set, &peers.socket, &owner)
        .await
        .unwrap();
    assert_eq!(incomplete_delete["operation_complete"], false);
    assert!(
        incomplete_delete["physical_payload_charge_upper_bound"]
            .as_u64()
            .unwrap()
            > 0
    );
    peers.online[0].store(true, Ordering::SeqCst);
    drop(set);
    let set = LockedFragments::open(&state).unwrap();
    let deleted = operations::delete(&set, &peers.socket, &owner)
        .await
        .unwrap();
    assert_eq!(deleted["operation_complete"], true);
    assert_eq!(deleted["physical_payload_charge_upper_bound"], 0);
    peers.stop().await;
    for index in 0..3 {
        let store =
            PrivateStorageStore::open_existing(&root.join(format!("provider-{index}"))).unwrap();
        assert_eq!(store.usage().unwrap().leases, 0);
        assert_eq!(store.usage().unwrap().committed_bytes, 0);
    }
}
