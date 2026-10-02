//! Real signed local provider services and durable journals; not overlay/discovery proof.

use std::fs;

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
        super::{
            tests::handoff::{HandoffPeers, Step},
            transfer,
        },
        operations,
        retained::LockedFragments,
        tests::{keys_and_grants, plan},
    },
    drain, select,
};

fn candidates(
    owner: &SigningKey,
    providers: &mut Vec<SigningKey>,
    grants: &mut Vec<VerifiedStorageGrant>,
) {
    let now = crate::storage::now().unwrap();
    for byte in [55, 66] {
        let provider = SigningKey::from_bytes(&[byte; 32]);
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
}

fn provider_charge(report: &serde_json::Value, provider: &SigningKey) -> u64 {
    report["providers"]
        .as_array()
        .unwrap()
        .iter()
        .find(|entry| entry["provider_key"] == hex::encode(provider.verifying_key().as_bytes()))
        .unwrap()["physical_payload_charge_upper_bound"]
        .as_u64()
        .unwrap()
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One real provider restart sequence proves pending identity, bounded drain, accounting and source-free recovery together."
)]
async fn archive_drain_resumes_exact_pending_first_then_balances_and_restores_without_source() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let (owner, mut providers, mut grants) = keys_and_grants(16);
    candidates(&owner, &mut providers, &mut grants);
    let bytes = vec![73; 3 * CHUNK_BYTES + 73];
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
    let immutable = fs::read(state.join("fragments.json")).unwrap();
    let drained = providers[0].verifying_key();
    let selected = select(&set, 0, &drained, &grants[3..], 600)
        .unwrap()
        .unwrap()
        .provider_key()
        .to_bytes();
    let selected_index = providers
        .iter()
        .position(|provider| provider.verifying_key().to_bytes() == selected)
        .unwrap();
    let other_index = if selected_index == 3 { 4 } else { 3 };
    first.lose_next(selected_index, Step::Reserve);
    let pending = drain(
        &mut set,
        &first.socket,
        &owner,
        drained,
        &grants[3..],
        600,
        16,
    )
    .await
    .unwrap();
    assert_eq!(pending["operation_complete"], false);
    assert_eq!(pending["drain_stage"], "pending_handoff");
    assert_eq!(pending["attempted_handoffs"], 1);
    assert_eq!(pending["placement_authorizations"], 1);
    assert_eq!(
        pending["physical_payload_charge_upper_bound"],
        2 * length + CHUNK_BYTES as u64
    );
    assert!(
        first
            .events()
            .iter()
            .all(|event| event.step != Step::Delete)
    );
    let exact = set.fragment(0).unwrap().copy(2).unwrap().journal.clone();
    drop(set);
    first.stop().await;

    let second = HandoffPeers::start(root, &providers, &grants, false);
    let mut set = LockedFragments::open(&state).unwrap();
    // Even with only the other (now less charged) candidate supplied, the existing
    // signed target is resumed. Losing readback must not retire any source bytes.
    second.lose_next(selected_index, Step::Read);
    let pending = drain(
        &mut set,
        &second.socket,
        &owner,
        drained,
        &grants[other_index..=other_index],
        600,
        16,
    )
    .await
    .unwrap();
    assert_eq!(pending["operation_complete"], false);
    assert_eq!(
        pending["fragment_outcomes"][0]["resumed_signed_intent"],
        true
    );
    assert_eq!(
        pending["fragment_outcomes"][0]["handoff_stage"],
        "replacement_verification_pending"
    );
    assert_eq!(pending["placement_authorizations"], 1);
    assert_eq!(
        set.fragment(0).unwrap().copy(2).unwrap().journal.archive_id,
        exact.archive_id
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
    let pending = drain(
        &mut set,
        &third.socket,
        &owner,
        drained,
        &grants[3..],
        600,
        16,
    )
    .await
    .unwrap();
    assert_eq!(
        pending["fragment_outcomes"][0]["handoff_stage"],
        "source_delete_unconfirmed"
    );
    assert_eq!(
        pending["physical_payload_charge_upper_bound"],
        2 * length + CHUNK_BYTES as u64
    );
    let events = third.events();
    let verified = events
        .iter()
        .position(|event| {
            event.provider == selected_index && event.step == Step::Read && event.terminal_sent
        })
        .unwrap();
    let deleted = events
        .iter()
        .position(|event| event.provider == 0 && event.step == Step::Delete)
        .unwrap();
    assert!(verified < deleted);
    drop(set);
    third.stop().await;

    let fourth = HandoffPeers::start(root, &providers, &grants, false);
    let mut set = LockedFragments::open(&state).unwrap();
    let bounded = drain(
        &mut set,
        &fourth.socket,
        &owner,
        drained,
        &grants[3..],
        600,
        1,
    )
    .await
    .unwrap();
    assert_eq!(bounded["operation_complete"], false);
    assert_eq!(bounded["drain_stage"], "pass_limit");
    assert_eq!(bounded["attempted_handoffs"], 1);
    assert_eq!(bounded["remaining_provider_fragments"], 2);
    assert_eq!(bounded["physical_payload_charge_upper_bound"], 2 * length);
    assert_eq!(
        set.fragment(0).unwrap().copy(2).unwrap().journal.archive_id,
        exact.archive_id
    );
    let complete = drain(
        &mut set,
        &fourth.socket,
        &owner,
        drained,
        &grants[3..],
        600,
        16,
    )
    .await
    .unwrap();
    assert_eq!(complete["operation_complete"], true);
    assert_eq!(complete["remaining_provider_fragments"], 0);
    assert_eq!(complete["pending_retirements"], 0);
    assert_eq!(complete["copies_per_fragment"], 2);
    assert_eq!(complete["physical_payload_charge_upper_bound"], 2 * length);
    assert_eq!(provider_charge(&complete, &providers[0]), 0);
    assert_eq!(
        set.fragment(2)
            .unwrap()
            .copy(2)
            .unwrap()
            .journal
            .provider_key,
        providers[other_index].verifying_key().to_bytes()
    );
    assert!(
        provider_charge(&complete, &providers[3])
            .abs_diff(provider_charge(&complete, &providers[4]))
            <= 73
    );
    assert_eq!(fs::read(state.join("fragments.json")).unwrap(), immutable);
    let restored = root.join("restored");
    assert_eq!(
        operations::restore(&set, &fourth.socket, &owner, &restored)
            .await
            .unwrap()["operation_complete"],
        true
    );
    assert_eq!(fs::read(restored).unwrap(), bytes);
    let repeated = drain(
        &mut set,
        &fourth.socket,
        &owner,
        drained,
        &grants[3..],
        600,
        16,
    )
    .await
    .unwrap();
    assert_eq!(repeated["operation_complete"], true);
    assert_eq!(repeated["attempted_handoffs"], 0);
    assert_eq!(
        operations::delete(&set, &fourth.socket, &owner)
            .await
            .unwrap()["physical_payload_charge_upper_bound"],
        0
    );
    drop(set);
    fourth.stop().await;
    for index in 0..5 {
        assert_eq!(
            PrivateStorageStore::open_existing(&root.join(format!("handoff-provider-{index}")))
                .unwrap()
                .usage()
                .unwrap()
                .leases,
            0
        );
    }
}

#[tokio::test]
async fn drain_without_eligible_capacity_is_incomplete_and_retains_existing_charges() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let (owner, providers, grants) = keys_and_grants(16);
    let bytes = vec![41; 3 * CHUNK_BYTES + 73];
    let source = root.join("ciphertext");
    fs::write(&source, &bytes).unwrap();
    let (mut input, _) = transfer::checked_input(&source, plan(&bytes).sha256).unwrap();
    let mut set = LockedFragments::create(
        &root.join("fragments"),
        &owner,
        &mut input,
        plan(&bytes),
        &grants,
        600,
    )
    .unwrap();
    let peers = HandoffPeers::start(root, &providers, &grants, true);
    assert_eq!(
        operations::deposit(&set, &peers.socket, &owner, &mut input)
            .await
            .unwrap()["operation_complete"],
        true
    );
    // B already holds the first fragment; history uniqueness excludes it even though
    // its grant has room. No implicit discovered or untrusted provider is selected.
    let report = drain(
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
    assert_eq!(report["operation_complete"], false);
    assert_eq!(report["drain_stage"], "no_eligible_candidate");
    assert_eq!(report["attempted_handoffs"], 0);
    assert_eq!(
        report["physical_payload_charge_upper_bound"],
        2 * bytes.len()
    );
    assert!(
        !root
            .join("fragments/placement-authorizations.json")
            .exists()
    );
    let replacement = SigningKey::from_bytes(&[55; 32]);
    let now = crate::storage::now().unwrap();
    let too_small = SignedStorageGrant::issue(
        &replacement,
        &owner.verifying_key(),
        GrantLimits {
            max_payload_bytes: 73,
            max_leases: 1,
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
    let capacity = drain(
        &mut set,
        &peers.socket,
        &owner,
        providers[0].verifying_key(),
        &[too_small],
        600,
        16,
    )
    .await
    .unwrap();
    assert_eq!(capacity["drain_stage"], "no_eligible_candidate");
    assert_eq!(capacity["attempted_handoffs"], 0);
    assert_eq!(
        capacity["physical_payload_charge_upper_bound"],
        2 * bytes.len()
    );
    assert!(
        drain(
            &mut set,
            &peers.socket,
            &owner,
            providers[0].verifying_key(),
            &[grants[1].clone(), grants[1].clone()],
            600,
            16
        )
        .await
        .is_err()
    );
    peers.stop().await;
}

#[test]
fn drain_cli_requires_explicit_candidates_and_a_bounded_pass() {
    let (_, providers, _) = keys_and_grants(16);
    let from = hex::encode(providers[0].verifying_key().as_bytes());
    let target = hex::encode(providers[1].verifying_key().as_bytes());
    let args = [
        "volparossa",
        "storage",
        "fragments",
        "drain",
        "--state",
        "/fragments",
        "--from-provider-key",
        &from,
        "--provider-key",
        &target,
        "--grant",
        "/grant",
    ];
    assert!(crate::Cli::try_parse_from(args).is_ok());
    for invalid in ["0", "257"] {
        assert!(
            crate::Cli::try_parse_from(args.into_iter().chain(["--max-fragments", invalid]))
                .is_err()
        );
    }
    assert!(crate::Cli::try_parse_from(&args[..8]).is_err());
}
