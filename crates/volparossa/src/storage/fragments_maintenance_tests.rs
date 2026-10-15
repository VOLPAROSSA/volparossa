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

#[path = "fragments_maintenance_service_tests.rs"]
mod service;

#[path = "fragments_maintenance_expiry_tests.rs"]
mod expiry;

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
    // Construct, but never poll: the owner loop must not embed the entire
    // maintenance state machine (previously 17 KiB) in every async caller.
    let socket = temp.path().join("not-polled.sock");
    let work = maintain(&enrollment, &socket, &owner, 0);
    assert!(size_of_val(&work) <= 1024);
    drop(work);
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
        assert_eq!(
            renewed["refresh"]["copy_outcomes"],
            serde_json::json!(["confirmed", "confirmed"])
        );
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
            let outcomes = result["fragment_outcomes"].as_array().unwrap();
            assert_eq!(outcomes.len(), 1);
            assert_eq!(outcomes[0]["handoff_stage"], "source_delete_unconfirmed");
            assert_eq!(outcomes[0]["operation_complete"], false);
            assert_eq!(outcomes[0]["replacement_verified_this_pass"], true);
            assert!(outcomes[0].get("provider_key").is_none());
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

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One real-provider retention counterexample binds the signed pending intent, two incomplete turns and the later safe retirement without sleeps."
)]
async fn pending_handoff_retention_waits_for_its_fragment_renewal_rotation() {
    Box::pin(transfer::with_maintenance_turn(vec![8; 32], async {
        let temp = tempfile::tempdir().unwrap();
        let (owner, mut providers, mut grants) = keys_and_grants(16);
        let (replacement, grant) = candidate(&owner);
        providers.push(replacement);
        grants.push(grant);
        let now = crate::storage::now().unwrap();
        let bytes = vec![31; 3 * CHUNK_BYTES + 9];
        let length = bytes.len() as u64;
        let source = temp.path().join("ciphertext");
        fs::write(&source, &bytes).unwrap();
        let (mut input, _) = transfer::checked_input(&source, plan(&bytes).sha256).unwrap();
        let archive = temp.path().join("fragments");
        // Existing signed-authority caps fix expiry ordering across second boundaries;
        // no mocked clock, sleeps, edited journals or invented provider receipts.
        let mut set = transfer::with_maintenance_expiry(now + 600, async {
            LockedFragments::create(
                &archive,
                &owner,
                &mut input,
                plan(&bytes),
                &grants[..3],
                600,
            )
        })
        .await
        .unwrap();
        let peers = LocalProviders::start(temp.path(), &providers, &grants, true);
        assert_eq!(
            operations::deposit(&set, &peers.socket, &owner, &mut input)
                .await
                .unwrap()["operation_complete"],
            true
        );
        let (from, survivor) = {
            let fragment = set.fragment(0).unwrap();
            let survivor = providers
                .iter()
                .position(|key| {
                    key.verifying_key().to_bytes() == fragment.data.copies[1].provider_key
                })
                .unwrap();
            (
                VerifyingKey::from_bytes(&fragment.data.copies[0].provider_key).unwrap(),
                survivor,
            )
        };
        peers.online[survivor].store(false, Ordering::SeqCst);
        let pending = transfer::with_maintenance_expiry(now + 900, async {
            placement::replace(&mut set, &peers.socket, &owner, 0, from, &grants[3], 900).await
        })
        .await
        .unwrap();
        assert_eq!(pending["handoff_stage"], "survivor_unavailable");
        assert_eq!(pending["operation_complete"], false);
        let intent = {
            let fragment = set.fragment(0).unwrap();
            let intent = fragment.data.handoff.as_ref().unwrap().clone();
            assert_eq!(intent.phase, HandoffPhase::Copying);
            assert_eq!(intent.initial_journal.requested_expiry, now + 900);
            assert!(fragment.copy(intent.to).unwrap().journal.lease.is_none());
            assert_eq!(fragment.data.copies[intent.to].charge, Charge::Unattempted);
            assert_eq!(
                fragment.copy(intent.from).unwrap().journal.last_expiry,
                now + 600
            );
            intent
        };
        let immutable = fs::read(archive.join("fragments.json")).unwrap();
        let signed_placement = fs::read(archive.join("placement-authorizations.json")).unwrap();
        let mut enrollment = enrollment(&set, archive.clone(), &owner, &providers, &grants[3]);
        enrollment.source = from.to_bytes();
        enrollment.expires = now + 1800;
        enrollment.lifetime = 1800;
        enrollment.renew_before = 7200;
        let directory = temp.path().join("maintenance");
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&directory)
            .unwrap();
        let directory = state::directory(&directory).unwrap();
        let signature = hex::encode(owner.sign(&signing(&enrollment).unwrap()).to_bytes());
        save(
            &directory,
            "enrollment.json",
            &SignedEnrollment {
                enrollment,
                signature,
            },
        )
        .unwrap();
        let enrollment = load(&directory).unwrap();
        drop((directory, set, input));
        fs::remove_file(source).unwrap();
        peers.online[survivor].store(true, Ordering::SeqCst);

        // Scan 4 (turn 5) renews fragment 0 before repairing its lease-less target.
        // Scan 5 (turn 6) rotates to fragment 1, leaving that target's shorter lease.
        for scan in [4, 5] {
            let result = maintain(&enrollment, &peers.socket, &owner, scan)
                .await
                .unwrap();
            assert_eq!(result["maintenance_stage"], "maintained", "{result}");
            assert_eq!(result["repair_stage"], "pending_handoff", "{result}");
            assert_eq!(result["refresh"]["fragment_index"], scan % 4);
            assert_eq!(result["refresh"]["renewal"], true);
            assert_eq!(result["refresh"]["operation_complete"], scan != 4);
            assert_eq!(result["attempted_handoffs"], 1);
            assert_eq!(result["freshly_verified_replacements"], 0);
            assert_eq!(result["pending_retirements"], 1);
            assert_eq!(
                result["fragment_outcomes"],
                serde_json::json!([{"index":0,"resumed_signed_intent":true,
                    "operation_complete":false,"handoff_stage":"replacement_retention_insufficient",
                    "replacement_verified_this_pass":false}])
            );
            if scan == 4 {
                assert_eq!(
                    result["refresh"]["copy_outcomes"],
                    serde_json::json!([
                        "confirmed",
                        "confirmed",
                        "unknown_reservation_use_deposit_retry"
                    ])
                );
            }
            let set = LockedFragments::open(&archive).unwrap();
            let status = set.report("status").unwrap();
            assert_eq!(status["pending_retirements"], 1);
            assert_eq!(status["placement_authorizations"], 1);
            assert_eq!(
                status["physical_payload_charge_upper_bound"],
                2 * length + CHUNK_BYTES as u64
            );
            let fragment = set.fragment(0).unwrap();
            let retained = fragment.data.handoff.as_ref().unwrap();
            assert!(retained.same_identity(&intent));
            assert_eq!(retained.phase, HandoffPhase::Copying);
            assert_eq!(fragment.data.copies[intent.from].charge, Charge::Committed);
            assert_eq!(
                fragment.copy(intent.from).unwrap().journal.last_expiry,
                enrollment.expires
            );
            let target = fragment.copy(intent.to).unwrap();
            assert!(target.journal.lease.is_some());
            assert_eq!(target.journal.archive_id, intent.initial_journal.archive_id);
            assert_eq!(target.journal.requested_expiry, now + 900);
            assert_eq!(target.journal.last_expiry, now + 900);
        }

        // Explicitly select the next fragment-0 rotation. This only completes that
        // pending handoff, not every remaining source copy or a live overlay trial.
        let finished = maintain(&enrollment, &peers.socket, &owner, 8)
            .await
            .unwrap();
        assert_eq!(finished["refresh"]["fragment_index"], 0);
        assert_eq!(finished["refresh"]["operation_complete"], true);
        assert_eq!(finished["freshly_verified_replacements"], 1);
        assert_eq!(finished["pending_retirements"], 0);
        assert_eq!(finished["fragment_outcomes"][0]["index"], 0);
        assert_eq!(finished["fragment_outcomes"][0]["operation_complete"], true);
        assert_eq!(
            finished["fragment_outcomes"][0]["handoff_stage"],
            "complete"
        );
        let set = LockedFragments::open(&archive).unwrap();
        {
            let fragment = set.fragment(0).unwrap();
            let retained = fragment.data.handoff.as_ref().unwrap();
            assert!(retained.same_identity(&intent));
            assert_eq!(retained.phase, HandoffPhase::Complete);
            assert_eq!(fragment.data.copies[intent.from].charge, Charge::Deleted);
            let target = fragment.copy(intent.to).unwrap();
            assert_eq!(target.journal.archive_id, intent.initial_journal.archive_id);
            assert_eq!(target.journal.requested_expiry, now + 900);
            assert_eq!(target.journal.last_expiry, enrollment.expires);
        }
        assert_eq!(
            set.report("status").unwrap()["physical_payload_charge_upper_bound"],
            2 * length
        );
        assert_eq!(fs::read(archive.join("fragments.json")).unwrap(), immutable);
        assert_eq!(
            fs::read(archive.join("placement-authorizations.json")).unwrap(),
            signed_placement
        );
        assert_eq!(
            operations::delete(&set, &peers.socket, &owner)
                .await
                .unwrap()["physical_payload_charge_upper_bound"],
            0
        );
        drop(set);
        peers.stop().await;
    }))
    .await;
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One three-provider local lifecycle isolates the actual overlay fixture's retained retirement geometry without claiming route recovery."
)]
async fn three_provider_maintenance_retires_all_originals_with_exact_candidate_grants() {
    Box::pin(transfer::with_maintenance_turn(vec![8; 32], async {
        let temp = tempfile::tempdir().unwrap();
        let (owner, providers, _) = keys_and_grants(4);
        let bytes = vec![31; 3 * CHUNK_BYTES + 73];
        let length = bytes.len() as u64;
        let now = crate::storage::now().unwrap();
        let grants: Vec<_> = providers
            .iter()
            .map(|provider| {
                SignedStorageGrant::issue(
                    provider,
                    &owner.verifying_key(),
                    GrantLimits {
                        max_payload_bytes: length,
                        max_leases: 4,
                        rights: StorageRights::ALL,
                        max_retention_seconds: 7200,
                    },
                    Validity {
                        created: now,
                        expires: now + 7200,
                    },
                )
                .unwrap()
                .verify(&provider.verifying_key(), now)
                .unwrap()
            })
            .collect();
        let source = temp.path().join("ciphertext");
        fs::write(&source, &bytes).unwrap();
        let (mut input, _) = transfer::checked_input(&source, plan(&bytes).sha256).unwrap();
        let archive = temp.path().join("fragments");
        let set =
            LockedFragments::create(&archive, &owner, &mut input, plan(&bytes), &grants, 1800)
                .unwrap();
        let peers = LocalProviders::start(temp.path(), &providers, &grants, true);
        assert_eq!(
            operations::deposit(&set, &peers.socket, &owner, &mut input)
                .await
                .unwrap()["operation_complete"],
            true
        );
        assert_eq!(
            operations::refresh(&set, &peers.socket, &owner, Some(3600))
                .await
                .unwrap()["operation_complete"],
            true
        );
        let mut enrollment = enrollment(&set, archive.clone(), &owner, &providers, &grants[1]);
        enrollment.providers = providers[1..]
            .iter()
            .map(|key| key.verifying_key().to_bytes())
            .collect();
        enrollment.grants = grants[1..]
            .iter()
            .map(|grant| hex::encode(grant.signed().encode()))
            .collect();
        enrollment.expires = now + 6000;
        enrollment.lifetime = 5400;
        enrollment.renew_before = 7200;
        enrollment.maximum_charged = 2 * length + 2 * CHUNK_BYTES as u64 + 73;
        enrollment.maximum_turn = 8 * 1024 * 1024;
        drop((set, input));
        fs::remove_file(&source).unwrap();
        assert_eq!(
            maintain(&enrollment, &peers.socket, &owner, 0)
                .await
                .unwrap()["refresh"]["operation_complete"],
            true
        );
        peers.online[0].store(false, Ordering::SeqCst);
        for scan in 3..6 {
            let result = maintain(&enrollment, &peers.socket, &owner, scan)
                .await
                .unwrap();
            assert_eq!(result["freshly_verified_replacements"], 1, "{result}");
        }
        let set = LockedFragments::open(&archive).unwrap();
        assert_eq!(set.report("status").unwrap()["pending_retirements"], 3);
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
        peers.stop().await;
        let peers = LocalProviders::start(temp.path(), &providers, &grants, false);
        for scan in 6..10 {
            let result = maintain(&enrollment, &peers.socket, &owner, scan)
                .await
                .unwrap();
            assert_eq!(result["refresh"]["operation_complete"], true, "{result}");
        }
        let set = LockedFragments::open(&archive).unwrap();
        let status = set.report("status").unwrap();
        assert_eq!(status["pending_retirements"], 0, "{status}");
        assert_eq!(status["placement_authorizations"], 3);
        assert_eq!(status["physical_payload_charge_upper_bound"], 2 * length);
        for _ in 0..2 {
            assert_eq!(
                operations::delete(&set, &peers.socket, &owner)
                    .await
                    .unwrap()["operation_complete"],
                true
            );
        }
        assert_eq!(
            set.report("status").unwrap()["physical_payload_charge_upper_bound"],
            0
        );
        peers.stop().await;
    }))
    .await;
}
