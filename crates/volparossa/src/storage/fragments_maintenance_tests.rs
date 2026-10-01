//! Actual signed provider services and retained journals, not a protected overlay/daemon trial.

use super::super::{
    super::tests::LocalProviders,
    tests::{keys_and_grants, plan},
};
use super::*;
use clap::Parser as _;
use std::sync::atomic::Ordering;
use volparossa_content::{
    CHUNK_BYTES, Validity,
    private_storage::protocol::{GrantLimits, StorageRights},
};

fn candidate(owner: &SigningKey) -> (SigningKey, VerifiedStorageGrant) {
    let key = SigningKey::from_bytes(&[55; 32]);
    let now = crate::storage::now().unwrap();
    let grant = SignedStorageGrant::issue(
        &key,
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
    .verify(&key.verifying_key(), now)
    .unwrap();
    (key, grant)
}

fn enrollment(
    set: &LockedFragments,
    path: PathBuf,
    owner: &SigningKey,
    providers: &[SigningKey],
    grant: &VerifiedStorageGrant,
) -> Enrollment {
    let now = crate::storage::now().unwrap();
    Enrollment {
        version: 1,
        id: [4; 32],
        owner: owner.verifying_key().to_bytes(),
        root: set.root_sha256,
        archive: path,
        source: providers[0].verifying_key().to_bytes(),
        providers: vec![grant.provider_key().to_bytes()],
        grants: vec![hex::encode(grant.signed().encode())],
        created: now,
        expires: now + 1800,
        lifetime: 900,
        renew_before: 1800,
        maximum_charged: 4 * set.data.ciphertext_bytes,
        maximum_turn: 134_217_728,
    }
}

#[test]
fn enrollment_signature_private_mode_and_restart_cursor_are_retained() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, providers, grants) = keys_and_grants(16);
    let source = temp.path().join("ciphertext");
    let bytes = vec![17; 3 * CHUNK_BYTES + 9];
    fs::write(&source, &bytes).unwrap();
    let (mut input, _) = transfer::checked_input(&source, plan(&bytes).sha256).unwrap();
    let archive = temp.path().join("fragments");
    let set =
        LockedFragments::create(&archive, &owner, &mut input, plan(&bytes), &grants, 600).unwrap();
    let (_, grant) = candidate(&owner);
    let enrollment = enrollment(&set, archive, &owner, &providers, &grant);
    let signature = hex::encode(owner.sign(&signing(&enrollment).unwrap()).to_bytes());
    let path = temp.path().join("maintenance");
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    let directory = state::directory(&path).unwrap();
    save(
        &directory,
        "enrollment.json",
        &SignedEnrollment {
            enrollment,
            signature,
        },
    )
    .unwrap();
    assert_eq!(load(&directory).unwrap().root, set.root_sha256);
    checkpoint(&directory, "working", 19, None).unwrap();
    let read = state::directory_readonly(&path).unwrap();
    assert_eq!(
        checkpoint_turns(&read).unwrap(),
        19,
        "status reads while worker owns lock"
    );
    assert!(state::directory(&path).is_err());
    drop((directory, read));
    let directory = state::directory(&path).unwrap();
    assert_eq!(
        checkpoint_turns(&directory).unwrap(),
        19,
        "restart does not reset scan cursor"
    );
    let mut signed: serde_json::Value = serde_json::from_slice(
        &state::read_private(&path.join("enrollment.json"), MAX_ENROLLMENT).unwrap(),
    )
    .unwrap();
    signed["enrollment"]["maximum_charged"] = 1.into();
    save(&directory, "enrollment.json", &signed).unwrap();
    assert!(
        load(&directory).is_err(),
        "owner authority cannot be edited without a signature"
    );
    assert!(
        crate::Cli::try_parse_from([
            "volparossa",
            "storage",
            "fragments",
            "maintenance",
            "status",
            "--enrollment",
            "/private/enrollment"
        ])
        .is_ok()
    );
    assert!(
        crate::Cli::try_parse_from([
            "volparossa",
            "storage",
            "fragments",
            "maintenance",
            "serve",
            "--enrollment",
            "/private/enrollment",
            "--maximum-turns",
            "1"
        ])
        .is_ok()
    );
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One real-provider lifecycle keeps renewal, repair, restart, surviving restore and final retirement evidence together."
)]
async fn owner_maintenance_renews_repairs_one_copy_and_retains_uncertain_charge_across_restart() {
    Box::pin(transfer::with_maintenance_turn(vec![8; 32], async {
        assert_eq!(transfer::range_bytes(), CHUNK_BYTES as u64);
        let temp = tempfile::tempdir().unwrap();
        let (owner, mut providers, mut grants) = keys_and_grants(16);
        let (replacement, grant) = candidate(&owner);
        providers.push(replacement);
        grants.push(grant);
        let bytes = vec![31; 3 * CHUNK_BYTES + 9];
        let length = bytes.len() as u64;
        let source = temp.path().join("ciphertext");
        fs::write(&source, &bytes).unwrap();
        let (mut input, _) = transfer::checked_input(&source, plan(&bytes).sha256).unwrap();
        let path = temp.path().join("fragments");
        let set =
            LockedFragments::create(&path, &owner, &mut input, plan(&bytes), &grants[..3], 600)
                .unwrap();
        let peers = LocalProviders::start(temp.path(), &providers, &grants, true);
        assert_eq!(
            operations::deposit(&set, &peers.socket, &owner, &mut input)
                .await
                .unwrap()["operation_complete"],
            true
        );
        let mut enrollment = enrollment(&set, path.clone(), &owner, &providers, &grants[3]);
        let old_expiry = set
            .fragment(0)
            .unwrap()
            .copy(0)
            .unwrap()
            .journal
            .last_expiry;
        let immutable = fs::read(path.join("fragments.json")).unwrap();
        drop((set, input));
        fs::remove_file(&source).unwrap();
        enrollment.lifetime = 300;
        let already_longer = maintain(&enrollment, &peers.socket, &owner, 0)
            .await
            .unwrap();
        assert_eq!(already_longer["maintenance_stage"], "observed");
        assert_eq!(already_longer["refresh"]["operation_complete"], true);
        let set = LockedFragments::open(&path).unwrap();
        assert_eq!(
            set.fragment(0)
                .unwrap()
                .copy(0)
                .unwrap()
                .journal
                .last_expiry,
            old_expiry
        );
        drop(set);
        enrollment.lifetime = 900;
        let renewed = maintain(&enrollment, &peers.socket, &owner, 0)
            .await
            .unwrap();
        assert_eq!(renewed["maintenance_stage"], "observed");
        assert_eq!(renewed["refresh"]["renewal"], true);
        let set = LockedFragments::open(&path).unwrap();
        assert!(
            set.fragment(0)
                .unwrap()
                .copy(0)
                .unwrap()
                .journal
                .last_expiry
                > old_expiry
        );
        drop(set);
        peers.online[0].store(false, Ordering::SeqCst);
        enrollment.maximum_charged = 2 * length;
        let denied = maintain(&enrollment, &peers.socket, &owner, 0)
            .await
            .unwrap();
        assert_eq!(denied["maintenance_stage"], "charge_limit");
        enrollment.maximum_charged = 4 * length;
        for pass in 0..3 {
            let result = maintain(&enrollment, &peers.socket, &owner, pass)
                .await
                .unwrap();
            assert_eq!(result["attempted_handoffs"], 1);
            assert_eq!(result["freshly_verified_replacements"], 1);
        }
        let set = LockedFragments::open(&path).unwrap();
        let before = set.report("status").unwrap();
        assert_eq!(before["pending_retirements"], 3);
        assert!(
            before["physical_payload_charge_upper_bound"]
                .as_u64()
                .unwrap()
                > 2 * length
        );
        drop(set);
        peers.stop().await;
        let peers = LocalProviders::start(temp.path(), &providers, &grants, false);
        peers.online[0].store(false, Ordering::SeqCst);
        let retried = maintain(&enrollment, &peers.socket, &owner, 3)
            .await
            .unwrap();
        assert_eq!(
            retried["physical_payload_charge_upper_bound"],
            before["physical_payload_charge_upper_bound"]
        );
        let set = LockedFragments::open(&path).unwrap();
        peers.online[1].store(false, Ordering::SeqCst);
        for name in ["restore-first", "restore-again"] {
            let output = temp.path().join(name);
            assert_eq!(
                operations::restore(&set, &peers.socket, &owner, &output)
                    .await
                    .unwrap()["operation_complete"],
                true
            );
            assert_eq!(fs::read(output).unwrap(), bytes);
        }
        drop(set);
        assert_eq!(fs::read(path.join("fragments.json")).unwrap(), immutable);
        peers.online[0].store(true, Ordering::SeqCst);
        peers.online[1].store(true, Ordering::SeqCst);
        for pass in 4..7 {
            maintain(&enrollment, &peers.socket, &owner, pass)
                .await
                .unwrap();
        }
        let set = LockedFragments::open(&path).unwrap();
        assert_eq!(
            set.report("status").unwrap()["physical_payload_charge_upper_bound"],
            2 * length
        );
        drop(set);
        enrollment.expires = crate::storage::now().unwrap();
        assert!(
            maintain(&enrollment, &peers.socket, &owner, 8)
                .await
                .is_err()
        );
        enrollment.expires += 3600;
        enrollment.lifetime = 3600;
        assert_eq!(
            maintain(&enrollment, &peers.socket, &owner, 8)
                .await
                .unwrap()["maintenance_stage"],
            "grant_refresh_required"
        );
        peers.stop().await;
    }))
    .await;
}
