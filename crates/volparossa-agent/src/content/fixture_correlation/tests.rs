use super::*;

const UID: u32 = 1000;
const EPOCH: [u8; 16] = [7; 16];

fn request(action: Action) -> Request {
    Request {
        version: 1,
        action: action as i32,
        epoch: EPOCH.to_vec(),
        fingerprints: Vec::new(),
    }
}

async fn armed() -> Arc<Correlation> {
    let state = Arc::new(Correlation::default());
    assert_eq!(
        state
            .request(UID, &request(Action::Arm))
            .await
            .unwrap()
            .state,
        State::Armed as i32
    );
    state
}

async fn clients(state: &Arc<Correlation>) -> Response {
    state.request(UID, &request(Action::Clients)).await.unwrap()
}

async fn providers(state: &Arc<Correlation>, fingerprint: &[u8]) -> Response {
    let mut query = request(Action::Providers);
    query.fingerprints.push(fingerprint.to_vec());
    state.request(UID, &query).await.unwrap()
}

#[tokio::test]
async fn fixture_v2_epoch_rejects_cross_version_queries_without_resetting_lifetime() {
    for version in [1, 2] {
        let state = Arc::new(Correlation::default());
        let query = |action, version| Request {
            version,
            ..request(action)
        };
        state
            .request(UID, &query(Action::Arm, version))
            .await
            .unwrap();
        let guard = state.client(UID);
        for action in [Action::Clients, Action::Disarm] {
            assert!(
                state
                    .request(UID, &query(action, 3 - version))
                    .await
                    .is_err()
            );
        }
        let row = state
            .request(UID, &query(Action::Clients, version))
            .await
            .unwrap();
        assert_eq!(row.version, version);
        assert_eq!(row.records.len(), 1);
        state
            .request(UID, &query(Action::Disarm, version))
            .await
            .unwrap();
        state
            .request(UID, &query(Action::Arm, version))
            .await
            .unwrap();
        let new_guard = state.client(UID);
        guard.finish(Terminal::OperationError);
        let row = state
            .request(UID, &query(Action::Clients, version))
            .await
            .unwrap();
        assert_eq!(row.records[0].terminal, Terminal::Active as i32);
        drop(new_guard);
    }
}

fn acquire_summary() -> StorageFixtureAcquireSummary {
    use volparossa_local_control::{
        PrivateStorageFlowAcquireFailure, PrivateStorageFlowAcquireReason as Reason,
        PrivateStorageFlowAcquireStage as Stage, StorageFixtureAcquireFailure,
        StorageFixtureHelperDiagnostic as Code,
    };
    let failure = StorageFixtureAcquireFailure {
        failure: Some(PrivateStorageFlowAcquireFailure {
            stage: Stage::HelperAcquire as i32,
            reason: Reason::HelperCleanupIncomplete as i32,
        }),
        helper_diagnostic: Some(Code::StaleBackendResult as i32),
    };
    StorageFixtureAcquireSummary {
        rounds: 1,
        first: Some(failure),
        last: Some(failure),
    }
}

#[tokio::test]
async fn fixture_v2_contended_cancel_advance_and_reset_cannot_export_stale_detail() {
    for action in 0..3 {
        let state = Arc::new(Correlation::default());
        let request = |action| Request {
            version: 2,
            ..request(action)
        };
        state.request(UID, &request(Action::Arm)).await.unwrap();
        let guard = state.client(UID);
        guard.flow_acquire(Some(acquire_summary()));
        let held = state.bank.lock().unwrap();
        match action {
            0 => guard.finish(Terminal::Cancelled),
            1 => guard.enter(Phase::TlsHandshake),
            _ => guard.flow_acquire(None),
        }
        drop(held);
        guard.finish(Terminal::OperationError);
        let response = state.request(UID, &request(Action::Clients)).await.unwrap();
        assert!(response.incomplete);
        assert_eq!(response.records[0].flow_acquire, None);
    }
}

#[tokio::test]
async fn fixture_v2_normal_guard_drop_preserves_the_first_terminal_detail() {
    let state = Arc::new(Correlation::default());
    let request = |action| Request {
        version: 2,
        ..request(action)
    };
    state.request(UID, &request(Action::Arm)).await.unwrap();
    let guard = state.client(UID);
    guard.flow_acquire(Some(acquire_summary()));
    guard.finish(Terminal::OperationError);
    drop(guard);
    let response = state.request(UID, &request(Action::Clients)).await.unwrap();
    assert_eq!(response.records[0].flow_acquire, Some(acquire_summary()));
}

fn digest(epoch: &[u8; 16], bytes: &[u8]) -> Vec<u8> {
    let mut hash = Sha256::new();
    hash.update(DOMAIN);
    hash.update(epoch);
    hash.update(&bytes[..64]);
    hash.finalize().to_vec()
}

#[tokio::test]
async fn disabled_has_no_records_or_cleanup_task() {
    let state = Arc::new(Correlation::default());
    state.client(UID).bytes(&[1; 64]);
    state.provider().bytes(&[1; 64]);
    assert_eq!(clients(&state).await, Response::unavailable());
    assert!(state.bank.try_lock().unwrap().epoch.is_none());
    assert!(state.cleanup.try_lock().unwrap().is_none());
}

#[tokio::test]
async fn only_armed_uid_can_observe_clients_or_query_and_disarm() {
    let state = armed().await;
    let allowed = state.client(UID);
    let denied = state.client(UID + 1);
    allowed.bytes(&[1; 64]);
    denied.bytes(&[2; 64]);
    assert_eq!(clients(&state).await.records.len(), 1);
    for action in [Action::Clients, Action::Disarm] {
        assert!(state.request(UID + 1, &request(action)).await.is_err());
        let mut wrong = request(action);
        wrong.epoch[0] ^= 1;
        assert!(state.request(UID, &wrong).await.is_err());
    }
    assert_eq!(clients(&state).await.records.len(), 1);
}

#[tokio::test(start_paused = true)]
async fn rearm_cannot_extend_epoch_or_discard_active_records() {
    let state = armed().await;
    let guard = state.client(UID);
    let expires = state
        .bank
        .try_lock()
        .unwrap()
        .epoch
        .as_ref()
        .unwrap()
        .expires;
    tokio::time::advance(Duration::from_secs(20)).await;
    assert!(matches!(
        state.request(UID, &request(Action::Arm)).await,
        Err(ContentError::Busy)
    ));
    assert_eq!(
        state
            .bank
            .try_lock()
            .unwrap()
            .epoch
            .as_ref()
            .unwrap()
            .expires,
        expires
    );
    assert_eq!(clients(&state).await.records.len(), 1);
    drop(guard);
}

#[tokio::test]
async fn provider_query_only_returns_exact_complete_matches() {
    let state = armed().await;
    let guards: Vec<_> = (0..4).map(|_| state.provider()).collect();
    guards[0].bytes(&[3; 64]);
    guards[1].bytes(&[3; 64]);
    guards[2].bytes(&[4; 64]);
    guards[3].bytes(&[3; 63]);
    let expected = digest(&EPOCH, &[3; 64]);
    let response = providers(&state, &expected).await;
    assert_eq!(response.records.len(), 2);
    assert!(
        response
            .records
            .iter()
            .all(|record| record.fingerprint.as_ref() == Some(&expected))
    );
    assert!(providers(&state, &[9; 32]).await.records.is_empty());
    assert!(clients(&state).await.records.is_empty());
}

#[tokio::test]
async fn fixed_capacity_never_evicts_active_records() {
    let state = armed().await;
    let guards: Vec<_> = (0..CAPACITY).map(|_| state.client(UID)).collect();
    let excess = state.provider();
    assert!(excess.0.is_none());
    let response = clients(&state).await;
    assert_eq!(response.records.len(), CAPACITY);
    assert!(response.incomplete);
    assert!(
        response
            .records
            .iter()
            .all(|record| record.terminal == Terminal::Active as i32)
    );
    drop(guards);
}

#[tokio::test]
async fn token_exhaustion_is_incomplete_without_admission_failure() {
    let state = armed().await;
    state.bank.try_lock().unwrap().next_token = u64::MAX;
    assert!(state.client(UID).0.is_none());
    let response = clients(&state).await;
    assert!(response.incomplete);
    assert!(response.records.is_empty());
}

#[tokio::test(start_paused = true)]
async fn full_bank_replaces_only_oldest_terminal_and_late_guard_is_inert() {
    let state = armed().await;
    let guards: Vec<_> = (0..CAPACITY).map(|_| state.client(UID)).collect();
    guards[7].finish(Terminal::Complete);
    tokio::time::advance(Duration::from_secs(1)).await;
    guards[2].finish(Terminal::OperationError);
    let replacement = state.client(UID);
    replacement.bytes(&[33; 64]);
    guards[7].enter(Phase::Closing);
    guards[7].finish(Terminal::Cancelled);
    let response = clients(&state).await;
    assert_eq!(response.records.len(), CAPACITY);
    assert!(response.incomplete);
    assert_eq!(response.records[7].terminal, Terminal::Active as i32);
    assert_eq!(response.records[7].phase, Phase::FlowAcquire as i32);
    assert_eq!(
        response.records[7].fingerprint,
        Some(digest(&EPOCH, &[33; 64]))
    );
    assert_eq!(
        response.records[2].terminal,
        Terminal::OperationError as i32
    );
    assert_eq!(
        response
            .records
            .iter()
            .filter(|record| record.terminal == Terminal::Active as i32)
            .count(),
        CAPACITY - 1
    );
}

#[tokio::test(start_paused = true)]
async fn cleanup_tick_erases_terminal_records_without_a_query() {
    let state = armed().await;
    tokio::task::yield_now().await;
    let guard = state.client(UID);
    guard.bytes(&[5; 64]);
    guard.finish(Terminal::Complete);
    tokio::time::advance(TERMINAL_TTL + Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    let bank = state.bank.try_lock().unwrap();
    let epoch = bank.epoch.as_ref().unwrap();
    assert!(epoch.records.iter().all(Option::is_none));
    assert!(epoch.life.incomplete.load(Relaxed));
}

#[tokio::test(start_paused = true)]
async fn cleanup_tick_erases_epoch_and_late_guard_cannot_repopulate() {
    let state = armed().await;
    tokio::task::yield_now().await;
    let old = state.client(UID);
    old.bytes(&[6; 64]);
    tokio::time::advance(EPOCH_TTL + Duration::from_secs(1)).await;
    tokio::task::yield_now().await;
    assert!(state.bank.try_lock().unwrap().epoch.is_none());
    assert_eq!(clients(&state).await, Response::unavailable());
    state.request(UID, &request(Action::Arm)).await.unwrap();
    old.enter(Phase::Closing);
    old.finish(Terminal::Complete);
    old.bytes(&[7; 64]);
    assert!(clients(&state).await.records.is_empty());
}

#[tokio::test]
async fn disarm_joins_cleanup_and_clears_before_new_epoch() {
    let state = armed().await;
    let guard = state.client(UID);
    guard.bytes(&[7; 64]);
    let old_life = Arc::clone(&guard.0.as_ref().unwrap().life);
    let response = state.request(UID, &request(Action::Disarm)).await.unwrap();
    assert_eq!(response.state, State::Disarmed as i32);
    assert!(!old_life.alive.load(Relaxed));
    assert!(state.bank.try_lock().unwrap().epoch.is_none());
    assert!(state.cleanup.try_lock().unwrap().is_none());
    state.request(UID, &request(Action::Arm)).await.unwrap();
    drop(guard);
    assert!(clients(&state).await.records.is_empty());
}

#[tokio::test(start_paused = true)]
async fn terminal_slot_reuse_rejects_the_old_guard_token() {
    let state = armed().await;
    let old = state.client(UID);
    old.finish(Terminal::Complete);
    tokio::time::advance(TERMINAL_TTL).await;
    let current = state.client(UID);
    old.enter(Phase::Closing);
    drop(old);
    let response = clients(&state).await;
    assert_eq!(response.records.len(), 1);
    assert_eq!(response.records[0].phase, Phase::FlowAcquire as i32);
    assert_eq!(response.records[0].terminal, Terminal::Active as i32);
    drop(current);
}

#[tokio::test]
async fn drop_records_cancel_and_first_terminal_keeps_its_phase() {
    let state = armed().await;
    let guard = state.client(UID);
    guard.enter(Phase::TlsHandshake);
    guard.finish(Terminal::TlsTimeout);
    guard.enter(Phase::Closing);
    guard.finish(Terminal::Complete);
    drop(guard);
    drop(state.client(UID));
    let response = clients(&state).await;
    assert_eq!(response.records[0].phase, Phase::TlsHandshake as i32);
    assert_eq!(response.records[0].terminal, Terminal::TlsTimeout as i32);
    assert_eq!(response.records[1].terminal, Terminal::Cancelled as i32);
}

#[tokio::test]
async fn contention_is_nonblocking_and_sticky_without_fabricated_fingerprint() {
    let state = armed().await;
    let guard = state.client(UID);
    guard.bytes(&[8; 10]);
    {
        let _lock = state.bank.try_lock().unwrap();
        assert!(state.provider().0.is_none());
        guard.bytes(&[8; 1]);
        guard.enter(Phase::ClientChallenge);
    }
    guard.bytes(&[8; 64]);
    let response = clients(&state).await;
    assert!(response.incomplete);
    assert!(response.records[0].fingerprint.is_none());
}

#[tokio::test]
async fn query_contention_returns_unavailable_not_empty_observed() {
    use std::{
        future::Future,
        task::{Context, Poll, Waker},
    };
    let state = armed().await;
    let query = request(Action::Clients);
    let mut future = Box::pin(state.request(UID, &query));
    {
        let _lock = state.bank.try_lock().unwrap();
        let mut cx = Context::from_waker(Waker::noop());
        let Poll::Ready(Ok(response)) = future.as_mut().poll(&mut cx) else {
            panic!("snapshot must never block on a data-path lock");
        };
        assert_eq!(response, Response::unavailable());
    }
    let _gate = state.cleanup.try_lock().unwrap();
    assert_eq!(clients(&state).await, Response::unavailable());
}

#[tokio::test]
async fn cancelled_old_task_join_does_not_arm_or_detach_cleanup() {
    use std::{
        future::Future,
        task::{Context, Waker},
    };
    let state = Arc::new(Correlation::default());
    *state.cleanup.try_lock().unwrap() = Some(tokio::spawn(std::future::pending()));
    let query = request(Action::Arm);
    let mut future = Box::pin(state.request(UID, &query));
    let mut cx = Context::from_waker(Waker::noop());
    assert!(future.as_mut().poll(&mut cx).is_pending());
    drop(future);
    assert!(state.bank.try_lock().unwrap().epoch.is_none());
    assert!(state.cleanup.try_lock().unwrap().is_some());
    assert_eq!(
        state.request(UID, &query).await.unwrap().state,
        State::Armed as i32
    );
    state.request(UID, &request(Action::Disarm)).await.unwrap();
    assert!(state.cleanup.try_lock().unwrap().is_none());
}

#[tokio::test]
async fn completed_prefix_ignores_later_io_contention_and_bytes() {
    let state = armed().await;
    let guard = state.client(UID);
    guard.bytes(&[9; 64]);
    {
        let _lock = state.bank.try_lock().unwrap();
        guard.bytes(&[10; 128]);
    }
    guard.finish(Terminal::Complete);
    guard.bytes(&[11; 64]);
    assert_eq!(
        clients(&state).await.records[0].fingerprint,
        Some(digest(&EPOCH, &[9; 64]))
    );
}

#[tokio::test]
async fn hash_is_domain_epoch_and_exact_first_64_bytes_only() {
    let state = armed().await;
    let client = state.client(UID);
    let provider = state.provider();
    let bytes = [23; 100];
    for part in bytes.chunks(3) {
        client.bytes(part);
    }
    provider.bytes(&bytes);
    let expected = digest(&EPOCH, &bytes);
    assert_eq!(
        clients(&state).await.records[0].fingerprint,
        Some(expected.clone())
    );
    assert_eq!(providers(&state, &expected).await.records.len(), 1);
    assert_ne!(expected, digest(&[8; 16], &bytes));
    assert_ne!(expected, Sha256::digest(&bytes[..64]).to_vec());
}

#[tokio::test]
async fn unpolled_session_drop_is_cancelled_and_does_not_keep_runtime_alive() {
    let state = armed().await;
    let guard = state.provider();
    let future = async move {
        let _guard = guard;
        std::future::pending::<()>().await;
    };
    drop(future);
    {
        let bank = state.bank.try_lock().unwrap();
        assert_eq!(
            bank.epoch.as_ref().unwrap().records[0]
                .as_ref()
                .unwrap()
                .terminal,
            Terminal::Cancelled
        );
    }
    let weak = Arc::downgrade(&state);
    drop(state);
    tokio::task::yield_now().await;
    assert!(weak.upgrade().is_none());
}

#[tokio::test]
async fn provider_observer_preserves_existing_activity_and_exact_stage() {
    let state = armed().await;
    let fixture = state.provider();
    fixture.bytes(&[12; 64]);
    let activity = Arc::new(provider_activity::Activity::default());
    let session = activity.begin();
    let observer = ProviderObserver {
        activity: &session,
        fixture: &fixture,
    };
    for (stage, phase) in [
        (Stage::TlsHandshake, Phase::TlsHandshake),
        (Stage::RegistrySnapshot, Phase::RegistrySnapshot),
        (Stage::SelectorRead, Phase::SelectorRead),
        (Stage::StorageGrantReadVerify, Phase::StorageGrantReadVerify),
        (
            Stage::StorageChallengeWriteFlush,
            Phase::StorageChallengeWriteFlush,
        ),
        (
            Stage::StorageRequestReadVerify,
            Phase::StorageRequestReadVerify,
        ),
        (Stage::StorageOperation, Phase::StorageOperation),
        (Stage::OtherProtocol, Phase::OtherProtocol),
        (Stage::Closing, Phase::Closing),
    ] {
        observer.enter(stage);
        assert_eq!(activity.snapshot().active_sessions, Some(1));
        assert_eq!(
            providers(&state, &digest(&EPOCH, &[12; 64])).await.records[0].phase,
            phase as i32
        );
    }
    drop(session);
    assert_eq!(activity.snapshot().active_sessions, Some(0));
}

#[tokio::test(start_paused = true)]
async fn observed_tls_timeout_preserves_existing_error_and_handshake_stage() {
    let state = armed().await;
    let fixture = state.provider();
    let identity = libp2p::identity::Keypair::generate_ed25519();
    let tls = super::super::tls::ContentTlsServer::new(&identity, "provider.test").unwrap();
    let (_client, server) = tokio::io::duplex(4096);
    assert!(
        tls.accept_observed(Observed::provider(server, &fixture), &fixture)
            .await
            .is_err()
    );
    let bank = state.bank.try_lock().unwrap();
    let record = bank.epoch.as_ref().unwrap().records[0].as_ref().unwrap();
    assert_eq!(record.phase, Phase::TlsHandshake);
    assert_eq!(record.terminal, Terminal::TlsTimeout);
}

#[tokio::test]
async fn observed_tls_error_is_retained_with_its_transferred_prefix() {
    use tokio::io::AsyncWriteExt;
    let state = armed().await;
    let fixture = state.provider();
    let identity = libp2p::identity::Keypair::generate_ed25519();
    let tls = super::super::tls::ContentTlsServer::new(&identity, "provider.test").unwrap();
    let (mut client, server) = tokio::io::duplex(4096);
    client.write_all(&[255; 64]).await.unwrap();
    drop(client);
    assert!(
        tls.accept_observed(Observed::provider(server, &fixture), &fixture)
            .await
            .is_err()
    );
    let bank = state.bank.try_lock().unwrap();
    let record = bank.epoch.as_ref().unwrap().records[0].as_ref().unwrap();
    assert_eq!(record.phase, Phase::TlsHandshake);
    assert_eq!(record.terminal, Terminal::TlsError);
    assert!(record.bytes <= PREFIX_BYTES);
}

#[path = "io_tests.rs"]
mod io_tests;
