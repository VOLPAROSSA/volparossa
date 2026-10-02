//! Real signed storage services and `SQLite` custody, not a protected-overlay proof.

use std::{fs, sync::atomic::Ordering};

use clap::Parser as _;
use ed25519_dalek::SigningKey;
use volparossa_content::{
    CHUNK_BYTES, Validity,
    private_storage::{
        PrivateStorageStore,
        protocol::{GrantLimits, SignedStorageGrant, StorageRights, VerifiedStorageGrant},
    },
};

use super::{
    super::{
        super::{retained::HandoffPhase, tests::LocalProviders, transfer},
        operations,
        retained::LockedFragments,
        tests::{keys_and_grants, plan},
    },
    repair,
};

fn add_candidate(
    owner: &SigningKey,
    providers: &mut Vec<SigningKey>,
    grants: &mut Vec<VerifiedStorageGrant>,
) {
    let provider = SigningKey::from_bytes(&[55; 32]);
    let now = crate::storage::now().unwrap();
    grants.push(
        SignedStorageGrant::issue(
            &provider,
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
        .unwrap(),
    );
    providers.push(provider);
}

fn provider_charge(report: &serde_json::Value, key: &SigningKey) -> u64 {
    report["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|provider| provider["provider_key"] == hex::encode(key.verifying_key().as_bytes()))
        .unwrap()["physical_payload_charge_upper_bound"]
        .as_u64()
        .unwrap()
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One real-store lifecycle proves repair progress, lost confirmation, owner restart, two-provider absence and eventual acknowledged retirement together."
)]
async fn offline_source_does_not_block_other_repairs_or_free_uncertain_custody() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let (owner, mut providers, mut grants) = keys_and_grants(16);
    add_candidate(&owner, &mut providers, &mut grants);
    let bytes: Vec<_> = (0..3 * CHUNK_BYTES + 73)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect();
    let length = bytes.len() as u64;
    let source = root.join("ciphertext");
    fs::write(&source, &bytes).unwrap();
    let (mut input, _) = transfer::checked_input(&source, plan(&bytes).sha256).unwrap();
    let state = root.join("fragments");
    let mut set =
        LockedFragments::create(&state, &owner, &mut input, plan(&bytes), &grants[..3], 600)
            .unwrap();
    let peers = LocalProviders::start(root, &providers, &grants, true);
    let deposited = operations::deposit(&set, &peers.socket, &owner, &mut input)
        .await
        .unwrap();
    assert_eq!(deposited["operation_complete"], true);
    let source_charge = provider_charge(&deposited, &providers[0]);
    let affected: Vec<_> = (0..set.data.fragments.len())
        .filter(|index| {
            set.fragment(*index)
                .unwrap()
                .data
                .copies
                .iter()
                .any(|copy| copy.provider_key == providers[0].verifying_key().to_bytes())
        })
        .collect();
    assert_eq!(affected.len(), 3);
    let immutable = fs::read(state.join("fragments.json")).unwrap();
    drop(input);
    fs::remove_file(&source).unwrap();
    peers.online[0].store(false, Ordering::SeqCst);
    peers.lose_terminal[3].store(true, Ordering::SeqCst);
    let pending = repair(
        &mut set,
        &peers.socket,
        &owner,
        providers[0].verifying_key(),
        &grants[3..],
        600,
        16,
    )
    .await
    .unwrap();
    assert_eq!(pending["repair_stage"], "pending_handoff");
    assert_eq!(pending["attempted_handoffs"], 1);
    assert_eq!(pending["freshly_verified_replacements"], 0);
    assert_eq!(pending["placement_authorizations"], 1);
    assert_eq!(
        pending["fragment_outcomes"][0]["handoff_stage"],
        "replacement_upload_pending"
    );
    let original_target = set
        .fragment(affected[0])
        .unwrap()
        .copy(2)
        .unwrap()
        .journal
        .clone();
    assert_eq!(
        pending["physical_payload_charge_upper_bound"],
        2 * length + CHUNK_BYTES as u64
    );
    drop(set);
    peers.stop().await;

    let peers = LocalProviders::start(root, &providers, &grants, false);
    peers.online[0].store(false, Ordering::SeqCst);
    let mut set = LockedFragments::open(&state).unwrap();
    // The copying intent resumes even when D is absent from the fresh candidate list.
    let resumed = repair(
        &mut set,
        &peers.socket,
        &owner,
        providers[0].verifying_key(),
        &grants[1..2],
        600,
        1,
    )
    .await
    .unwrap();
    assert_eq!(resumed["repair_stage"], "pass_limit");
    assert_eq!(
        resumed["fragment_outcomes"][0]["resumed_signed_intent"],
        true
    );
    assert_eq!(
        resumed["fragment_outcomes"][0]["handoff_stage"],
        "source_delete_unconfirmed"
    );
    assert_eq!(resumed["freshly_verified_replacements"], 1);
    assert_eq!(
        set.fragment(affected[0])
            .unwrap()
            .copy(2)
            .unwrap()
            .journal
            .archive_id,
        original_target.archive_id
    );
    assert_eq!(provider_charge(&resumed, &providers[0]), source_charge);
    // Max-one passes must advance to other fragments instead of repeatedly spending
    // their whole budget on the same unreachable source's already verified retirement.
    for completed in 2..=3 {
        let result = repair(
            &mut set,
            &peers.socket,
            &owner,
            providers[0].verifying_key(),
            &grants[3..],
            600,
            1,
        )
        .await
        .unwrap();
        assert_eq!(result["operation_complete"], false);
        assert_eq!(result["attempted_handoffs"], 1);
        assert_eq!(result["placement_authorizations"], completed);
        assert_eq!(
            result["fragment_outcomes"][0]["resumed_signed_intent"],
            false
        );
        assert_eq!(
            result["fragment_outcomes"][0]["handoff_stage"],
            "source_delete_unconfirmed"
        );
        assert_eq!(provider_charge(&result, &providers[0]), source_charge);
    }
    let pending = set.report("status").unwrap();
    assert_eq!(
        pending["physical_payload_charge_upper_bound"],
        2 * length + source_charge
    );
    assert_eq!(pending["fully_redundant_from_retained_receipts"], true);
    assert_eq!(pending["pending_retirements"], 3);
    let replacement_ids: Vec<_> = affected
        .iter()
        .map(|index| {
            let fragment = set.fragment(*index).unwrap();
            assert_eq!(
                fragment.data.handoff.as_ref().unwrap().phase,
                HandoffPhase::DeletePending
            );
            fragment.copy(2).unwrap().journal.clone()
        })
        .collect();
    assert_eq!(fs::read(state.join("fragments.json")).unwrap(), immutable);
    drop(set);
    peers.stop().await;
    assert_eq!(
        PrivateStorageStore::open_existing(&root.join("provider-0"))
            .unwrap()
            .usage()
            .unwrap()
            .committed_bytes,
        source_charge
    );
    assert_eq!(
        PrivateStorageStore::open_existing(&root.join("provider-3"))
            .unwrap()
            .usage()
            .unwrap()
            .leases,
        3
    );

    let peers = LocalProviders::start(root, &providers, &grants, false);
    peers.online[0].store(false, Ordering::SeqCst);
    let mut set = LockedFragments::open(&state).unwrap();
    peers.online[3].store(false, Ordering::SeqCst);
    let unavailable = repair(
        &mut set,
        &peers.socket,
        &owner,
        providers[0].verifying_key(),
        &grants[1..2],
        600,
        16,
    )
    .await
    .unwrap();
    // Retained DeletePending is not fresh verification when D cannot answer now.
    assert_eq!(unavailable["repair_stage"], "pending_handoff");
    assert_eq!(unavailable["attempted_handoffs"], 1);
    assert_eq!(unavailable["freshly_verified_replacements"], 0);
    assert_eq!(unavailable["placement_authorizations"], 3);
    assert_eq!(
        unavailable["physical_payload_charge_upper_bound"],
        2 * length + source_charge
    );
    peers.online[3].store(true, Ordering::SeqCst);
    let repeated = repair(
        &mut set,
        &peers.socket,
        &owner,
        providers[0].verifying_key(),
        &grants[1..2],
        600,
        16,
    )
    .await
    .unwrap();
    assert_eq!(repeated["repair_stage"], "retirement_pending");
    assert_eq!(repeated["operation_complete"], false);
    assert_eq!(repeated["freshly_verified_replacements"], 3);
    assert_eq!(
        repeated["physical_payload_charge_upper_bound"],
        2 * length + source_charge
    );
    for (index, expected) in affected.iter().zip(&replacement_ids) {
        let actual = set
            .fragment(*index)
            .unwrap()
            .copy(2)
            .unwrap()
            .journal
            .clone();
        assert_eq!(actual.archive_id, expected.archive_id);
        assert_eq!(actual.lease, expected.lease);
        assert_eq!(actual.requested_expiry, expected.requested_expiry);
        assert_eq!(actual.grant_hex, expected.grant_hex);
    }
    // Two original providers unavailable: only C and repaired D can restore.
    peers.online[1].store(false, Ordering::SeqCst);
    for index in 0..2 {
        let output = root.join(format!("restored-{index}"));
        let restored = operations::restore(&set, &peers.socket, &owner, &output)
            .await
            .unwrap();
        assert_eq!(restored["operation_complete"], true);
        assert_eq!(restored["whole_archive_sha256_verified"], true);
        assert_eq!(
            restored["physical_payload_charge_upper_bound"],
            2 * length + source_charge
        );
        for fragment in restored["fragment_outcomes"].as_array().unwrap() {
            let key = fragment["provider_key"].as_str().unwrap();
            assert!([2, 3].iter().any(
                |provider| key == hex::encode(providers[*provider].verifying_key().as_bytes())
            ));
        }
        assert_eq!(fs::read(output).unwrap(), bytes);
    }
    // A's actual store returns. Only now may authenticated deletes reduce its charge.
    peers.online[0].store(true, Ordering::SeqCst);
    peers.online[1].store(true, Ordering::SeqCst);
    let finished = repair(
        &mut set,
        &peers.socket,
        &owner,
        providers[0].verifying_key(),
        &grants[3..],
        600,
        16,
    )
    .await
    .unwrap();
    assert_eq!(finished["operation_complete"], true);
    assert_eq!(finished["repair_stage"], "complete");
    assert_eq!(finished["pending_retirements"], 0);
    assert_eq!(finished["physical_payload_charge_upper_bound"], 2 * length);
    assert_eq!(provider_charge(&finished, &providers[0]), 0);
    let again = repair(
        &mut set,
        &peers.socket,
        &owner,
        providers[0].verifying_key(),
        &grants[3..],
        600,
        16,
    )
    .await
    .unwrap();
    assert_eq!(again["attempted_handoffs"], 0);
    assert_eq!(again["freshly_verified_replacements"], 0);
    assert_eq!(fs::read(state.join("fragments.json")).unwrap(), immutable);
    assert_eq!(
        operations::delete(&set, &peers.socket, &owner)
            .await
            .unwrap()["physical_payload_charge_upper_bound"],
        0
    );
    drop(set);
    peers.stop().await;
    for index in 0..4 {
        let usage = PrivateStorageStore::open_existing(&root.join(format!("provider-{index}")))
            .unwrap()
            .usage()
            .unwrap();
        assert_eq!(usage.leases, 0);
        assert_eq!(usage.committed_bytes + usage.reserved_bytes, 0);
    }
}

#[test]
fn repair_cli_requires_named_source_explicit_grants_and_bounded_work() {
    let (_, providers, _) = keys_and_grants(16);
    let source = hex::encode(providers[0].verifying_key().as_bytes());
    let candidate = hex::encode(providers[1].verifying_key().as_bytes());
    let arguments = [
        "volparossa",
        "storage",
        "fragments",
        "repair",
        "--state",
        "/fragments",
        "--from-provider-key",
        &source,
        "--provider-key",
        &candidate,
        "--grant",
        "/grant",
    ];
    assert!(crate::Cli::try_parse_from(arguments).is_ok());
    for value in ["0", "257"] {
        assert!(
            crate::Cli::try_parse_from(arguments.into_iter().chain(["--max-fragments", value]))
                .is_err()
        );
    }
    assert!(crate::Cli::try_parse_from(&arguments[..8]).is_err());
}
