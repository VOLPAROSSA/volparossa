//! Synthetic signed requests and RAM lifecycle checks, not actual consumer acceptance.
use super::*;
use ed25519_dalek::SigningKey;
use volparossa_content::private_storage::wire::bridge_observation::Phase as WirePhase;
use volparossa_content::{
    Validity,
    private_storage::protocol::{
        GrantLimits, SignedStorageGrant, SignedStorageRequest, StorageChallenge, StorageRights,
        StorageTarget,
    },
};

const UID: u32 = 1000;
const EPOCH: [u8; 16] = [7; 16];

fn query(action: Action) -> Request {
    Request {
        version: 3,
        action: action as i32,
        epoch: EPOCH.to_vec(),
        target: (action == Action::Arm).then(|| StorageFixtureTarget {
            archive_id: vec![31; 32],
            provider_key: SigningKey::from_bytes(&[11; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
            operation: Operation::Reserve as i32,
        }),
        ..Default::default()
    }
}

async fn armed() -> Arc<Correlation> {
    let state = Arc::new(Correlation::default());
    state.request(UID, &query(Action::Arm)).await.unwrap();
    state
}

fn verified(archive: u8) -> VerifiedStorageRequest {
    let signer = SigningKey::from_bytes(&[11; 32]);
    let owner = SigningKey::from_bytes(&[22; 32]);
    let now = super::super::now();
    let grant = SignedStorageGrant::issue(
        &signer,
        &owner.verifying_key(),
        GrantLimits {
            max_payload_bytes: 4096,
            max_leases: 4,
            rights: StorageRights::ALL,
            max_retention_seconds: 1800,
        },
        Validity {
            created: now,
            expires: now + 3600,
        },
    )
    .unwrap()
    .verify(&signer.verifying_key(), now)
    .unwrap();
    let challenge = StorageChallenge::issue(
        &signer,
        &grant,
        Validity {
            created: now,
            expires: now + 60,
        },
    )
    .unwrap();
    SignedStorageRequest::sign(
        &owner,
        &grant,
        &challenge,
        StorageTarget {
            archive_id: [archive; 32],
            lease_id: None,
            ciphertext_bytes: 8,
            sha256: [44; 32],
        },
        StorageOperation::Reserve {
            expires_at: now + 600,
        },
        Validity {
            created: now,
            expires: now + 60,
        },
    )
    .unwrap()
    .verify(&grant, &challenge, now)
    .unwrap()
}

fn target(request: &VerifiedStorageRequest) -> StorageFixtureTarget {
    StorageFixtureTarget {
        archive_id: request.target().archive_id.to_vec(),
        provider_key: request.grant().provider_key().as_bytes().to_vec(),
        operation: operation(request.operation()) as i32,
    }
}

async fn selected(state: &Arc<Correlation>, target: StorageFixtureTarget) -> Response {
    state
        .request(
            UID,
            &Request {
                target: Some(target),
                ..query(Action::Clients)
            },
        )
        .await
        .unwrap()
}

fn client(state: &Arc<Correlation>, request: &VerifiedStorageRequest) -> Guard {
    let guard = state.client(UID);
    guard.bytes(&[55; PREFIX_BYTES]);
    guard.enter(Phase::ClientExchange);
    guard.bind_request(request, false);
    guard
}

async fn provider_row(state: &Arc<Correlation>) -> WireRecord {
    let fingerprint = {
        let bank = state.bank.lock().unwrap();
        bank.epoch
            .as_ref()
            .unwrap()
            .records
            .iter()
            .flatten()
            .find(|record| record.role == Role::Provider)
            .unwrap()
            .fingerprint
            .unwrap()
    };
    let response = state
        .request(
            UID,
            &Request {
                fingerprints: vec![fingerprint.to_vec()],
                ..query(Action::Providers)
            },
        )
        .await
        .unwrap();
    assert_eq!(response.state, State::Observed as i32);
    response.records.into_iter().next().unwrap()
}

#[tokio::test]
async fn fixture_v3_exact_target_provider_operation_and_signed_request_are_bound() {
    let state = armed().await;
    let request = verified(31);
    let selected_target = target(&request);
    let client = client(&state, &request);
    let before_flush = selected(&state, selected_target.clone()).await;
    assert!(
        before_flush.records[0]
            .request_observation
            .as_ref()
            .unwrap()
            .request_digest
            .is_none()
    );
    client.bind_request(&request, true);
    let provider = state.provider();
    provider.bytes(&[55; PREFIX_BYTES]);
    provider.bind_request(&request, false);
    provider.enter(Phase::StorageOperation);
    let client_row = selected(&state, selected_target.clone())
        .await
        .records
        .remove(0);
    let provider_row = provider_row(&state).await;
    assert_eq!(client_row.fingerprint, provider_row.fingerprint);
    assert_eq!(
        client_row.request_observation.unwrap().request_digest,
        provider_row.request_observation.unwrap().request_digest
    );
    for field in 0..3 {
        let mut wrong = selected_target.clone();
        match field {
            0 => wrong.archive_id[0] ^= 1,
            1 => wrong.provider_key[0] ^= 1,
            _ => wrong.operation = Operation::Append as i32,
        }
        let wrong = Request {
            target: Some(wrong),
            ..query(Action::Clients)
        };
        assert!(state.request(UID, &wrong).await.is_err());
    }
    let selected_query = Request {
        target: Some(selected_target),
        ..query(Action::Clients)
    };
    assert!(state.request(UID + 1, &selected_query).await.is_err());
    let mut wrong_epoch = selected_query;
    wrong_epoch.epoch[0] ^= 1;
    assert!(state.request(UID, &wrong_epoch).await.is_err());
}

#[tokio::test]
async fn fixture_v3_multiple_attempts_and_changed_request_never_choose_latest() {
    let state = armed().await;
    let first = verified(31);
    let second = verified(31);
    assert_ne!(first.id(), second.id());
    let first_guard = client(&state, &first);
    first_guard.bind_request(&first, true);
    let second_guard = client(&state, &second);
    second_guard.bind_request(&second, true);
    assert_eq!(
        selected(&state, target(&first)).await.state,
        State::Unavailable as i32
    );
    first_guard.bind_request(&second, true);
    let response = selected(&state, target(&first)).await;
    assert_eq!(response.state, State::Unavailable as i32);
    assert!(response.incomplete);
}

#[tokio::test(start_paused = true)]
async fn fixture_v3_reserve_uses_original_budget_and_freezes_first_terminal_timing() {
    let state = armed().await;
    let request = verified(31);
    let guard = client(&state, &request);
    guard.start_operation(Some(Instant::now()), Duration::from_secs(120));
    tokio::time::advance(Duration::from_secs(15)).await;
    guard.bridge_phase(WirePhase::RemoteRequestWrite);
    tokio::time::advance(Duration::from_secs(5)).await;
    guard.bind_request(&request, true);
    guard.bridge_phase(WirePhase::RemoteReceiptRead);
    tokio::time::advance(Duration::from_secs(30)).await;
    guard.finish(Terminal::OperationError);
    let first = selected(&state, target(&request)).await.records[0]
        .request_observation
        .clone()
        .unwrap()
        .reserve_timing
        .unwrap();
    assert_eq!(first.before_request_flush_elapsed, Bucket::S15To30 as i32);
    assert_eq!(
        first.before_request_flush_remaining,
        Bucket::S90To120 as i32
    );
    assert_eq!(first.receipt_wait_elapsed, Some(Bucket::S30To60 as i32));
    assert_eq!(first.receipt_wait_remaining, Some(Bucket::S90To120 as i32));
    tokio::time::advance(Duration::from_secs(5)).await;
    guard.finish(Terminal::Cancelled);
    let last = selected(&state, target(&request)).await.records[0]
        .request_observation
        .clone()
        .unwrap()
        .reserve_timing
        .unwrap();
    assert_eq!(first, last);
}

#[tokio::test]
async fn fixture_v3_late_backend_return_is_separate_and_worker_does_not_own_collector() {
    let state = armed().await;
    let request = verified(31);
    let provider = state.provider();
    provider.bytes(&[55; PREFIX_BYTES]);
    provider.bind_request(&request, false);
    provider.enter(Phase::StorageOperation);
    let owners = Arc::strong_count(&state);
    let worker = provider.worker().unwrap();
    assert_eq!(owners, Arc::strong_count(&state));
    worker.entered();
    provider.finish(Terminal::OperationError);
    let before = provider_row(&state).await;
    assert_eq!(
        before.request_observation.unwrap().worker_state,
        WorkerState::Entered as i32
    );
    worker.returned(true);
    let after = provider_row(&state).await;
    assert_eq!(after.terminal, Terminal::OperationError as i32);
    let detail = after.request_observation.unwrap();
    assert_eq!(detail.worker_state, WorkerState::ReturnedOk as i32);
    assert!(detail.worker_returned_after_terminal);
    assert_eq!(detail.provider_stage, ProviderStage::BackendEntered as i32);
}

#[tokio::test]
async fn fixture_v3_stop_and_slot_reuse_reject_old_workers_without_resurrection() {
    let state = armed().await;
    let request = verified(31);
    let old = state.provider();
    old.bind_request(&request, false);
    let worker = old.worker().unwrap();
    worker.entered();
    old.finish(Terminal::Cancelled);
    // A terminal slot may be reused; the old worker must not mutate that new generation.
    let guards: Vec<_> = (0..CAPACITY).map(|_| state.provider()).collect();
    worker.returned(true);
    {
        let bank = state.bank.lock().unwrap();
        assert!(
            bank.epoch
                .as_ref()
                .unwrap()
                .records
                .iter()
                .flatten()
                .all(|record| record.request.worker_state == WorkerState::Unobserved as i32)
        );
    }
    state.request(UID, &query(Action::Disarm)).await.unwrap();
    state.request(UID, &query(Action::Arm)).await.unwrap();
    worker.returned(false);
    assert!(
        state
            .bank
            .lock()
            .unwrap()
            .epoch
            .as_ref()
            .unwrap()
            .records
            .iter()
            .all(Option::is_none)
    );
    drop(guards);
}

#[tokio::test(start_paused = true)]
async fn fixture_v3_capacity_expiry_and_contention_are_unavailable_not_absence() {
    for mode in 0..3 {
        let state = armed().await;
        let request = verified(31);
        let guard = client(&state, &request);
        guard.bind_request(&request, true);
        let mut retained = Vec::new();
        match mode {
            0 => retained.extend((0..CAPACITY).map(|_| state.client(UID))),
            1 => {
                guard.finish(Terminal::OperationError);
                tokio::time::advance(TERMINAL_TTL + Duration::from_secs(1)).await;
            }
            _ => {
                let held = state.bank.lock().unwrap();
                guard.bridge_phase(WirePhase::RemoteRequestWrite);
                drop(held);
            }
        }
        let response = selected(&state, target(&request)).await;
        assert_eq!(response.state, State::Unavailable as i32);
        assert!(response.incomplete);
    }
}

#[tokio::test]
async fn fixture_v3_disabled_and_legacy_observers_do_not_capture_request_details() {
    let state = Arc::new(Correlation::default());
    let request = verified(31);
    let disabled = state.provider();
    disabled.bind_request(&request, false);
    assert!(disabled.worker().is_none());
    assert!(state.bank.lock().unwrap().epoch.is_none());
    let mut legacy = query(Action::Arm);
    legacy.version = 2;
    legacy.target = None;
    state.request(UID, &legacy).await.unwrap();
    let provider = state.provider();
    provider.bind_request(&request, false);
    assert!(provider.worker().is_none());
    let bank = state.bank.lock().unwrap();
    let record = bank
        .epoch
        .as_ref()
        .unwrap()
        .records
        .iter()
        .flatten()
        .next()
        .unwrap();
    assert!(record.request.target.is_none());
    assert!(record.request.digest.is_none());
}

#[tokio::test(start_paused = true)]
async fn fixture_v3_all_query_actions_reject_wrong_owner_epoch_and_expired_epoch() {
    let state = armed().await;
    let request = verified(31);
    let guard = client(&state, &request);
    guard.bind_request(&request, true);
    for action in [
        Action::Arm,
        Action::Clients,
        Action::Providers,
        Action::Disarm,
    ] {
        let mut value = query(action);
        if action == Action::Clients {
            value.target = Some(target(&request));
        }
        if action == Action::Providers {
            value.fingerprints = vec![vec![55; 32]];
        }
        assert!(state.request(UID + 1, &value).await.is_err());
        value.epoch[0] ^= 1;
        assert!(state.request(UID, &value).await.is_err());
    }
    tokio::time::advance(EPOCH_TTL + Duration::from_secs(1)).await;
    let response = selected(&state, target(&request)).await;
    assert_eq!(response.state, State::Unavailable as i32);
    assert!(response.incomplete);
    // No late observation can re-arm the expired epoch.
    guard.bind_request(&request, true);
    assert!(state.bank.lock().unwrap().epoch.is_none());
}

#[tokio::test]
async fn fixture_v3_verified_nonmatching_requests_are_excluded_and_stale_guards_cannot_reuse_slot()
{
    let state = armed().await;
    let matching = verified(31);
    let other = verified(32);
    let old = state.provider();
    old.bind_request(&other, false);
    assert!(old.worker().is_none());
    assert!(
        state
            .bank
            .lock()
            .unwrap()
            .epoch
            .as_ref()
            .unwrap()
            .records
            .iter()
            .all(Option::is_none)
    );
    let current = state.provider();
    current.bytes(&[55; PREFIX_BYTES]);
    current.bind_request(&matching, false);
    old.bind_request(&matching, true);
    let row = provider_row(&state).await;
    let detail = row.request_observation.unwrap();
    assert_eq!(detail.provider_stage, ProviderStage::RequestVerified as i32);
    assert_eq!(detail.worker_state, WorkerState::Unobserved as i32);
    let bank = state.bank.lock().unwrap();
    assert!(!bank.epoch.as_ref().unwrap().life.incomplete.load(Relaxed));
}

#[tokio::test]
async fn fixture_v3_unknown_preverification_clients_are_retained_and_not_called_nonmatching() {
    let state = armed().await;
    let request = verified(31);
    let selected_guard = client(&state, &request);
    selected_guard.bind_request(&request, true);
    let unknown = state.client(UID);
    unknown.finish(Terminal::OperationError);
    let response = selected(&state, target(&request)).await;
    assert_eq!(response.state, State::Unavailable as i32);
    assert!(response.incomplete);
    assert_eq!(
        state
            .bank
            .lock()
            .unwrap()
            .epoch
            .as_ref()
            .unwrap()
            .records
            .iter()
            .flatten()
            .count(),
        2
    );
}

#[tokio::test]
async fn fixture_v3_callback_loss_after_projection_cannot_remain_observed() {
    let state = armed().await;
    let request = verified(31);
    let provider = state.provider();
    provider.bytes(&[55; PREFIX_BYTES]);
    provider.bind_request(&request, false);
    provider.enter(Phase::StorageOperation);
    let worker = provider.worker().unwrap();
    let fingerprint = provider_row(&state).await.fingerprint.unwrap();
    let selected = Request {
        fingerprints: vec![fingerprint],
        ..query(Action::Providers)
    };
    let mut projected = state.request(UID, &selected).await.unwrap();
    assert!(!projected.incomplete);
    {
        let held = state.bank.lock().unwrap();
        // Recreate record projection before the final loss-flag load, without a
        // production scheduling hook. A real worker callback loses this held lock.
        std::thread::scope(|scope| {
            scope.spawn(|| worker.entered()).join().unwrap();
        });
        projected.incomplete = held.epoch.as_ref().unwrap().life.incomplete.load(Relaxed);
        assert!(projected.incomplete);
        assert!(projected.validate_for(&selected).is_err());
    }
    let rejected = state.request(UID, &selected).await.unwrap();
    assert_eq!(rejected.state, State::Unavailable as i32);
    assert!(rejected.incomplete);
}

#[tokio::test(start_paused = true)]
async fn fixture_v3_successful_receipt_read_excludes_later_delivery_and_tls_close() {
    let state = armed().await;
    let request = verified(31);
    let guard = client(&state, &request);
    guard.start_operation(Some(Instant::now()), Duration::from_secs(120));
    tokio::time::advance(Duration::from_secs(15)).await;
    guard.bridge_phase(WirePhase::RemoteRequestWrite);
    guard.bind_request(&request, true);
    tokio::time::advance(Duration::from_secs(5)).await;
    guard.bridge_phase(WirePhase::RemoteReceiptRead);
    tokio::time::advance(Duration::from_secs(5)).await;
    guard.bridge_phase(WirePhase::RemoteReceiptVerify);
    let received = selected(&state, target(&request)).await.records[0]
        .request_observation
        .clone()
        .unwrap()
        .reserve_timing
        .unwrap();
    assert_eq!(received.receipt_wait_elapsed, Some(Bucket::S5To15 as i32));
    tokio::time::advance(Duration::from_secs(30)).await;
    guard.bridge_phase(WirePhase::LocalReceiptWrite);
    tokio::time::advance(Duration::from_secs(35)).await;
    guard.enter(Phase::Closing);
    tokio::time::advance(Duration::from_secs(20)).await;
    guard.finish(Terminal::Complete);
    let closed = selected(&state, target(&request)).await.records[0]
        .request_observation
        .clone()
        .unwrap()
        .reserve_timing
        .unwrap();
    assert_eq!(closed, received);
    assert_eq!(closed.receipt_wait_remaining, Some(Bucket::S90To120 as i32));
}
