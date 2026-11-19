use super::*;

#[tokio::test]
async fn missing_route_uses_one_foreground_replacement_before_original_cutoff() {
    use crate::route_setup::ContentStreamOpenCause::{FlowAcquire, Policy, RouteState};
    use std::cell::Cell;
    let deadline = tokio::time::Instant::now() + Duration::from_secs(90);
    let mut replacement = challenge_idle_limit(true, deadline, deadline);
    let cutoff = replacement.unwrap().retry_before;
    let attempts = Cell::new(0);
    let reconnect = || async {
        attempts.set(attempts.get() + 1);
        Ok(())
    };
    for cause in [Policy, FlowAcquire] {
        assert!(
            reconnect_unopened_route(cause, &mut replacement, reconnect())
                .await
                .is_err()
        );
    }
    assert_eq!(attempts.get(), 0);
    assert_eq!(
        reconnect_unopened_route(RouteState, &mut replacement, reconnect())
            .await
            .unwrap(),
        cutoff
    );
    assert!(
        reconnect_unopened_route(RouteState, &mut replacement, reconnect())
            .await
            .is_err()
    );
    let mut background = challenge_idle_limit(false, deadline, deadline);
    assert!(
        reconnect_unopened_route(RouteState, &mut background, reconnect())
            .await
            .is_err()
    );
    assert_eq!(attempts.get(), 1);
}

#[tokio::test]
async fn unusable_route_stops_waiting_at_its_original_cutoff_or_requester_close() {
    use crate::route_setup::ContentStreamOpenCause::RouteState;
    use std::future::pending;
    let limit = |after| {
        Some(wire::ChallengeIdleLimit {
            idle: Duration::from_secs(1),
            retry_before: tokio::time::Instant::now() + after,
        })
    };
    let mut expired = limit(Duration::ZERO);
    assert!(
        reconnect_unopened_route(RouteState, &mut expired, async {
            panic!("expired route replacement started")
        })
        .await
        .is_err()
    );
    let mut short = limit(Duration::from_millis(20));
    assert!(
        reconnect_unopened_route(RouteState, &mut short, pending())
            .await
            .is_err()
    );
    assert!(short.is_none());

    let (client, mut local) = UnixStream::pair().unwrap();
    let (started, running) = tokio::sync::oneshot::channel();
    let job = tokio::spawn(async move {
        let observation = observation::Observation::default();
        let mut replacement = limit(Duration::from_secs(60));
        let result = observation
            .requester_boundary(
                Stage::StreamOpen,
                &mut local,
                reconnect_unopened_route(RouteState, &mut replacement, async {
                    started.send(()).unwrap();
                    pending().await
                }),
            )
            .await;
        assert!(result.is_err());
        assert!(observation.detail().is_none());
    });
    running.await.unwrap();
    drop(client);
    timeout(Duration::from_secs(2), job).await.unwrap().unwrap();
}

#[test]
fn live_control_rechecks_keep_authority_and_observe_only_this_initial_rejection() {
    use crate::route_setup::ContentProviderRouteError::{RoleOverlap, Unavailable};
    let pinned = PeerId::random();
    let other = PeerId::random();
    for (live, policy) in [
        (Err(Unavailable), false),
        (Err(RoleOverlap), true),
        (Ok(other), true),
    ] {
        let observation = observation::Observation::default();
        let error = require_pinned_control(pinned, live, Some(&observation)).unwrap_err();
        let (result, code) = if policy {
            assert!(matches!(error, ContentError::Policy));
            (ControlResult::Policy, "CONTENT_POLICY")
        } else {
            assert!(matches!(error, ContentError::Unavailable));
            (ControlResult::Unavailable, "CONTENT_UNAVAILABLE")
        };
        let detail = observation.detail().unwrap();
        detail.validate_rejection(result, code).unwrap();
        assert_eq!(detail.stage, Stage::ControlSelection as i32);
        assert_eq!(detail.deadline_scope, Deadline::None as i32);
        assert!(
            detail.tls_failure.is_none()
                && detail.challenge.is_none()
                && detail.flow_acquire.is_none()
        );
        assert!(matches!(
            require_pinned_control(pinned, live, None),
            Err(ContentError::Policy)
        ));
    }
    let sibling = observation::Observation::default();
    require_pinned_control(pinned, Ok(pinned), Some(&sibling)).unwrap();
    require_pinned_control(pinned, Ok(pinned), None).unwrap();
    assert!(sibling.detail().is_none());
}

#[tokio::test(start_paused = true)]
async fn challenge_replacement_reserves_a_handshake_within_both_original_deadlines() {
    let now = tokio::time::Instant::now();
    let idle = tls::HANDSHAKE_TIMEOUT;
    let operation_end = now + EXCHANGE_TIMEOUT;
    let offer_end = now + idle * 4;
    for (operation, exchange) in [(operation_end, offer_end), (offer_end, operation_end)] {
        let limit = challenge_idle_limit(true, operation, exchange).unwrap();
        assert_eq!(limit.idle, idle);
        assert_eq!(limit.retry_before, offer_end - idle);
        assert!(challenge_idle_limit(false, operation, exchange).is_none());
    }
    tokio::time::advance(idle * 2).await;
    assert!(challenge_idle_limit(true, operation_end, offer_end).is_none());
    tokio::time::advance(EXCHANGE_TIMEOUT).await;
    assert!(challenge_idle_limit(true, operation_end, operation_end).is_none());
}

#[tokio::test]
async fn tls_close_v9_query_opt_in_does_not_revive_or_disclose_sibling_outcomes() {
    use volparossa_local_control::{
        PrivateStorageOutcomeStatus as Status, PrivateStorageTlsCloseFailure,
    };
    let runtime = ContentRuntime::new(&volparossa_identity::Identity::generate()).unwrap();
    let (_caller, socket) = UnixStream::pair().unwrap();
    let uid = socket.peer_cred().unwrap().uid();
    for (id, enabled) in [(21, false), (22, true)] {
        let guard = runtime.storage_outcomes.begin(uid, &[id; 16]).unwrap();
        guard.enter(OutcomePhase::TransportTlsClose);
        guard.tls_close_failure(PrivateStorageTlsCloseFailure::ReadIo);
        guard.finish(&Err(ContentError::Unavailable), Deadline::None);
        assert_eq!(
            runtime
                .storage_outcomes
                .take(uid.wrapping_add(1), &[id; 16])
                .unwrap()
                .status,
            Status::Missing as i32
        );
        let mut query = PrivateStorageOutcomeRequest {
            original_request_id: vec![id; 16],
            include_append_timing: true,
            include_tls_close_failure: enabled,
        };
        let result = runtime.private_storage_outcome(&query, &socket).unwrap();
        result.validate().unwrap();
        assert_eq!(result.tls_close_failure.is_some(), enabled);
        assert!(result.append_timing.is_none());
        query.include_tls_close_failure = true;
        let consumed = runtime.private_storage_outcome(&query, &socket).unwrap();
        assert_eq!(consumed.status, Status::Missing as i32);
        assert!(consumed.tls_close_failure.is_none());
    }
}

#[test]
fn terminal_route_receipt_retains_exact_fields_and_no_custody_claim() {
    let provider = PeerId::random();
    let control = PeerId::random();
    assert_eq!(
        route_receipt(37, provider, control),
        ContentReceipt {
            bytes: 37,
            peer_bytes: 37,
            providers_used: 1,
            provider_peer_ids: vec![provider.to_string()],
            control_relay_peer_id: control.to_string(),
            ..ContentReceipt::default()
        }
    );
}

#[tokio::test]
async fn outcome_query_uses_actual_unix_peer_uid_and_consumes_only_its_request() {
    use volparossa_local_control::PrivateStorageOutcomeStatus as Status;
    let runtime = ContentRuntime::new(&volparossa_identity::Identity::generate()).unwrap();
    let (_caller, socket) = UnixStream::pair().unwrap();
    let uid = socket.peer_cred().unwrap().uid();
    let own = runtime.storage_outcomes.begin(uid, &[3; 16]).unwrap();
    own.enter(OutcomePhase::LocalRequestRead);
    drop(own);
    let sibling_uid = uid.wrapping_add(1);
    let sibling = runtime
        .storage_outcomes
        .begin(sibling_uid, &[4; 16])
        .unwrap();
    sibling.enter(OutcomePhase::LocalRequestRead);
    drop(sibling);
    let query = |id| PrivateStorageOutcomeRequest {
        include_tls_close_failure: false,
        original_request_id: vec![id; 16],
        include_append_timing: false,
    };
    for (id, expected) in [
        (4, Status::Missing),
        (3, Status::Observed),
        (3, Status::Missing),
    ] {
        assert_eq!(
            runtime
                .private_storage_outcome(&query(id), &socket)
                .unwrap()
                .status,
            expected as i32
        );
    }
    assert_eq!(
        runtime
            .storage_outcomes
            .take(sibling_uid, &[4; 16])
            .unwrap()
            .status,
        Status::Observed as i32
    );
}

#[tokio::test]
async fn append_timing_query_opt_in_is_caller_bound_and_consumes_the_same_original_slot() {
    use volparossa_local_control::PrivateStorageOutcomeStatus as Status;

    let runtime = ContentRuntime::new(&volparossa_identity::Identity::generate()).unwrap();
    let (_caller, socket) = UnixStream::pair().unwrap();
    let uid = socket.peer_cred().unwrap().uid();
    for (id, enabled) in [(31, false), (32, true)] {
        let guard = runtime.storage_outcomes.begin(uid, &[id; 16]).unwrap();
        guard.start_operation(Some(tokio::time::Instant::now()));
        guard.enter(OutcomePhase::RemotePayloadWrite);
        guard.enter(OutcomePhase::RemoteReceiptRead);
        drop(guard);
        assert_eq!(
            runtime
                .storage_outcomes
                .take(uid.wrapping_add(1), &[id; 16])
                .unwrap()
                .status,
            Status::Missing as i32
        );
        let mut query = PrivateStorageOutcomeRequest {
            include_tls_close_failure: false,
            original_request_id: vec![id; 16],
            include_append_timing: enabled,
        };
        let result = runtime.private_storage_outcome(&query, &socket).unwrap();
        result.validate().unwrap();
        assert_eq!(result.status, Status::Observed as i32);
        assert_eq!(result.append_timing.is_some(), enabled);
        // Opting in later never consumes a second copy or revives the original observation.
        query.include_append_timing = true;
        let consumed = runtime.private_storage_outcome(&query, &socket).unwrap();
        assert_eq!(consumed.status, Status::Missing as i32);
        assert!(consumed.append_timing.is_none());
    }
}

#[tokio::test]
async fn partial_private_storage_ready_write_is_already_committed_to_stream_framing() {
    use std::{
        io,
        pin::Pin,
        task::{Context, Poll},
    };
    struct PartialWrite {
        bytes: Vec<u8>,
    }
    impl AsyncWrite for PartialWrite {
        fn poll_write(
            mut self: Pin<&mut Self>,
            _: &mut Context<'_>,
            bytes: &[u8],
        ) -> Poll<io::Result<usize>> {
            if self.bytes.is_empty() {
                self.bytes.push(bytes[0]);
                Poll::Ready(Ok(1))
            } else {
                Poll::Ready(Err(io::Error::from(io::ErrorKind::BrokenPipe)))
            }
        }
        fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
        fn poll_shutdown(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<io::Result<()>> {
            Poll::Ready(Ok(()))
        }
    }
    let mut stream = PartialWrite { bytes: Vec::new() };
    let mut ready_sent = false;
    let result = send_ready(
        &mut stream,
        &[1; 16],
        &mut ready_sent,
        PrivateStorageReady {
            provider_key: SigningKey::from_bytes(&[3; 32])
                .verifying_key()
                .to_bytes()
                .to_vec(),
            challenge: vec![1],
        },
    )
    .await;
    assert!(matches!(result, Err(ContentError::Unavailable)));
    assert!(ready_sent);
    assert_eq!(stream.bytes.len(), 1);
}

fn operator_grant(owner: &SigningKey) -> PrivateStorageGrantRequest {
    PrivateStorageGrantRequest {
        owner_key: owner.verifying_key().to_bytes().to_vec(),
        max_payload_bytes: 1024,
        max_leases: 2,
        max_retention_seconds: 300,
        rights: StorageRights::RESERVE.union(StorageRights::PROGRESS).bits(),
        lifetime_seconds: 600,
    }
}

#[test]
fn private_storage_grant_preserves_exact_operator_owner_limits_and_rights() {
    let node = SigningKey::from_bytes(&[31; 32]);
    let owner = SigningKey::from_bytes(&[32; 32]);
    let request = operator_grant(&owner);
    let at = now();
    let issued = issue_grant(&node, &request, at).unwrap();
    assert_eq!(issued.provider_key, node.verifying_key().as_bytes());
    let grant = SignedStorageGrant::decode(&issued.grant)
        .unwrap()
        .verify(&node.verifying_key(), at)
        .unwrap();
    assert_eq!(grant.owner_key(), &owner.verifying_key());
    assert_eq!(grant.provider_key(), &node.verifying_key());
    assert_eq!(
        grant.validity(),
        Validity {
            created: at,
            expires: at + 600
        }
    );
    assert_eq!(grant.limits().max_payload_bytes, 1024);
    assert_eq!(grant.limits().max_leases, 2);
    assert_eq!(grant.limits().max_retention_seconds, 300);
    assert_eq!(grant.limits().rights.bits(), request.rights);
    assert_ne!(grant.limits().rights, StorageRights::ALL);
    let mut invalid = request.clone();
    invalid.rights = 128;
    assert!(issue_grant(&node, &invalid, at).is_err());
    invalid = request;
    invalid.lifetime_seconds = 0;
    assert!(issue_grant(&node, &invalid, at).is_err());
}

#[test]
fn private_storage_remote_binds_independent_provider_before_discovery() {
    let node = SigningKey::from_bytes(&[41; 32]);
    let owner = SigningKey::from_bytes(&[42; 32]);
    let issued = issue_grant(&node, &operator_grant(&owner), now()).unwrap();
    let mut request = PrivateStorageRemoteRequest {
        include_flow_acquire_detail: false,
        include_challenge_read_detail: false,
        provider_key: issued.provider_key,
        grant: issued.grant,
        maintenance_turn: Vec::new(),
    };
    let checked = validate_remote(&request).unwrap();
    assert_eq!(checked.grant.owner_key(), &owner.verifying_key());
    assert_eq!(checked.provider_key, node.verifying_key().to_bytes());
    let public = identity::ed25519::PublicKey::try_from_bytes(&checked.provider_key).unwrap();
    assert_eq!(
        checked.peer,
        PeerId::from_public_key(&identity::PublicKey::from(public))
    );
    request.provider_key = SigningKey::from_bytes(&[43; 32])
        .verifying_key()
        .to_bytes()
        .to_vec();
    assert!(validate_remote(&request).is_err());
    request.provider_key = node.verifying_key().to_bytes().to_vec();
    let last = request.grant.len() - 1;
    request.grant[last] ^= 1;
    assert!(validate_remote(&request).is_err());
}

#[test]
fn private_storage_attachment_reuses_owned_store_without_resizing_or_changing_provider() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let node = SigningKey::from_bytes(&[51; 32]);
    let mut request = PrivateStorageServeRequest {
        bind_address: "127.0.0.1:8443".into(),
        advertised_hostname: "provider.example".into(),
        store: root.to_str().unwrap().into(),
        capacity_bytes: 4096,
        min_free_bytes: 1024,
        reuse_store: false,
    };
    let provider = open_provider(&request, node.verifying_key()).unwrap();
    assert!(open_provider(&request, node.verifying_key()).is_err());
    drop(provider);
    assert!(open_provider(&request, node.verifying_key()).is_err());
    request.reuse_store = true;
    assert!(open_provider(&request, node.verifying_key()).is_err());
    request.capacity_bytes = 0;
    request.min_free_bytes = 0;
    assert!(open_provider(&request, SigningKey::from_bytes(&[52; 32]).verifying_key()).is_err());
    drop(open_provider(&request, node.verifying_key()).unwrap());
    let mut store = PrivateStorageStore::open_existing(&root).unwrap();
    assert_eq!(
        store.limits(),
        StorageLimits {
            capacity_bytes: 4096,
            min_free_bytes: 1024
        }
    );
    assert!(matches!(
        store.reserve(4097, [1; 32], now() + 60, now()),
        Err(volparossa_content::private_storage::StorageError::Quota)
    ));
    assert_eq!(store.usage().unwrap().leases, 0);
}
