use super::*;
use crate::mptcp_transport::acquire_diagnostic::{Failure, History, Reason, Stage};

fn original_failure() -> ContentStreamOpenFailure {
    let mut history = History::default();
    for reason in [Reason::HelperKernel, Reason::HelperCleanupIncomplete] {
        history.record_round(Some(Failure {
            stage: Stage::HelperAcquire,
            reason,
            helper_diagnostic: None,
        }));
    }
    ContentStreamOpenFailure::from_flow_acquire(
        ClientRouteConnectError::TransportRuntimeUnavailable,
        history.summary(),
    )
}

async fn control_with_fixture_owner() -> ClientRouteControl {
    let control = ClientRouteControl::default();
    // The injected starter owns the existing affine FakeProtocol route instead of a concrete
    // production MPTCP transport. Connecting is its marker; no CleanupPending is preinstalled.
    *control.state.lock().await = ClientRouteControlState::Connecting;
    control
}

async fn failed_flow(
    control: &ClientRouteControl,
    cleanup: impl Future<Output = Result<(), ClientRouteDisconnectError>> + Send + 'static,
) -> ContentStreamOpenFailure {
    let state = control.state.lock().await;
    control
        .finish_flow_acquire_failure(state, true, original_failure(), |prior| {
            assert!(matches!(prior, ClientRouteControlState::Connecting));
            assert!(
                control.state.try_lock().is_err(),
                "publication stays locked"
            );
            ClientRouteControlState::CleanupPending(ClientRouteRetirement::new(tokio::spawn(
                cleanup,
            )))
        })
        .await
}

async fn wait_for_cleanup_start(
    request: &mut (impl Future<Output = ContentStreamOpenFailure> + Unpin),
    started: oneshot::Receiver<()>,
) {
    timeout(TEST_TIMEOUT, async {
        tokio::select! {
            failure = request => panic!("unconfirmed cleanup returned early: {failure:?}"),
            result = started => result.expect("retained cleanup started"),
        }
    })
    .await
    .expect("bounded cleanup start");
}

async fn pending_owner(control: &ClientRouteControl) -> ClientRouteRetirement {
    let state = control.state.lock().await;
    let ClientRouteControlState::CleanupPending(owner) = &*state else {
        panic!("the failed flow must publish its retained cleanup owner");
    };
    owner.clone()
}

async fn assert_connect_is_busy(control: &ClientRouteControl) {
    let (discovery, unused_actor) = DiscoveryControlHandle::native_ready_barrier_for_test(1);
    let helper = HelperClient::new(
        PathBuf::from("/unused-helper.sock"),
        PathBuf::from("/unused-token"),
    );
    let result = timeout(
        TEST_TIMEOUT,
        control.connect(&Config::default(), &discovery, &helper),
    )
    .await;
    unused_actor.abort();
    let _ = unused_actor.await;
    assert_eq!(
        result.expect("new admission must not wait on cleanup"),
        Err(ClientRouteConnectError::Busy)
    );
}

#[tokio::test]
async fn lost_helper_retirement_no_loss_keeps_state_and_original_failure() {
    let control = control_with_fixture_owner().await;
    let failure = control
        .finish_flow_acquire_failure(
            control.state.lock().await,
            false,
            original_failure(),
            |_| panic!("ordinary acquisition failure must not retire the route"),
        )
        .await;
    assert_eq!(failure, original_failure());
    assert!(matches!(
        *control.state.lock().await,
        ClientRouteControlState::Connecting
    ));
}

#[tokio::test(start_paused = true)]
async fn lost_helper_retirement_timeout_preserves_history_and_retained_owner() {
    let control = control_with_fixture_owner().await;
    let (complete, completion) = oneshot::channel();
    let (started, start) = oneshot::channel();
    let mut request = Box::pin(failed_flow(&control, async move {
        started.send(()).expect("original waiter is live");
        completion
            .await
            .map_err(|_| ClientRouteDisconnectError::CleanupPending)
    }));
    wait_for_cleanup_start(&mut request, start).await;
    let owner = pending_owner(&control).await;
    tokio::time::advance(MAXIMUM_CALL_DURATION).await;
    assert_eq!(request.await, original_failure());
    assert!(Arc::ptr_eq(
        &pending_owner(&control).await.owner,
        &owner.owner
    ));
    assert!(owner.owner.lock().await.completed.is_none());
    complete.send(()).expect("timeout did not cancel cleanup");
    control
        .confirm_retirement(&owner, TEST_TIMEOUT)
        .await
        .expect("exact successful cleanup can enter Idle");
    assert!(matches!(
        *control.state.lock().await,
        ClientRouteControlState::Idle
    ));
}

#[tokio::test]
async fn lost_helper_retirement_caller_cancel_keeps_cleanup_and_blocks_admission() {
    let (route, manager, shared) = established_fake_route().await;
    let before = shared.events();
    let control = control_with_fixture_owner().await;
    let (complete, completion) = oneshot::channel();
    let (started, start) = oneshot::channel();
    let mut request = Box::pin(failed_flow(&control, async move {
        started.send(()).expect("original waiter is live");
        completion
            .await
            .map_err(|_| ClientRouteDisconnectError::CleanupPending)?;
        let _ = route.teardown().await;
        manager
            .shutdown()
            .await
            .map_err(|_| ClientRouteDisconnectError::CleanupPending)
    }));
    wait_for_cleanup_start(&mut request, start).await;
    let owner = pending_owner(&control).await;
    assert_connect_is_busy(&control).await;
    drop(request);
    assert_connect_is_busy(&control).await;
    timeout(TEST_TIMEOUT, control.refresh_mpquic_path_summaries())
        .await
        .expect("status is not held behind cleanup")
        .expect("no live MPQUIC route");
    assert!(Arc::ptr_eq(
        &pending_owner(&control).await.owner,
        &owner.owner
    ));
    assert_eq!(
        shared.events(),
        before,
        "cancel did not drop the route owner"
    );
    complete
        .send(())
        .expect("caller cancellation retained cleanup");
    control
        .confirm_retirement(&owner, TEST_TIMEOUT)
        .await
        .expect("original cleanup task joined");
    assert_eq!(
        shared
            .events()
            .iter()
            .filter(|event| *event == "local.destroy")
            .count(),
        1
    );
    assert!(matches!(
        *control.state.lock().await,
        ClientRouteControlState::Idle
    ));
}

#[tokio::test(start_paused = true)]
async fn lost_helper_retirement_quarantine_recovers_only_the_exact_route() {
    let (route, manager, shared) = established_fake_route().await;
    let (other_route, other_manager, other_shared) = established_fake_route().await;
    let other_before = other_shared.events();
    let retirement = Arc::clone(manager.retirement_state());
    shared.state.lock().expect("fake state").fail_destroy = true;
    let control = control_with_fixture_owner().await;
    let (quarantined, observed) = oneshot::channel();
    let mut request = Box::pin(failed_flow(&control, async move {
        assert_eq!(route.teardown().await, RetirementOutcome::Quarantined);
        quarantined.send(()).expect("original waiter is live");
        manager
            .shutdown()
            .await
            .map_err(|_| ClientRouteDisconnectError::CleanupPending)
    }));
    wait_for_cleanup_start(&mut request, observed).await;
    let owner = pending_owner(&control).await;
    assert_eq!(retirement.outstanding(), 1);
    assert_eq!(retirement.quarantined(), 1);
    assert_connect_is_busy(&control).await;
    tokio::time::advance(MAXIMUM_CALL_DURATION).await;
    assert_eq!(request.await, original_failure());
    assert!(Arc::ptr_eq(
        &pending_owner(&control).await.owner,
        &owner.owner
    ));
    assert_eq!(other_shared.events(), other_before);
    shared.state.lock().expect("fake state").fail_destroy = false;
    control
        .confirm_retirement(&owner, TEST_TIMEOUT)
        .await
        .expect("same quarantined route eventually confirmed");
    assert_eq!(retirement.outstanding(), 0);
    assert!(matches!(
        *control.state.lock().await,
        ClientRouteControlState::Idle
    ));
    assert_eq!(other_shared.events(), other_before);
    drop(other_route);
    other_manager
        .shutdown()
        .await
        .expect("separate explicit cleanup of other route");
}

#[tokio::test]
async fn lost_helper_retirement_failed_task_is_sticky_without_replacing_flow_error() {
    let control = control_with_fixture_owner().await;
    assert_eq!(
        failed_flow(&control, async {
            Err(ClientRouteDisconnectError::CleanupPending)
        })
        .await,
        original_failure()
    );
    let owner = pending_owner(&control).await;
    for _ in 0..2 {
        assert_eq!(
            control.confirm_retirement(&owner, TEST_TIMEOUT).await,
            Err(ClientRouteDisconnectError::CleanupPending)
        );
        assert!(Arc::ptr_eq(
            &pending_owner(&control).await.owner,
            &owner.owner
        ));
    }
    assert_connect_is_busy(&control).await;
}

#[tokio::test]
async fn lost_helper_retirement_delayed_completion_cannot_clear_another_owner() {
    let control = control_with_fixture_owner().await;
    let (complete, completion) = oneshot::channel();
    let (started, start) = oneshot::channel();
    let mut request = Box::pin(failed_flow(&control, async move {
        started.send(()).expect("original waiter is live");
        completion
            .await
            .map_err(|_| ClientRouteDisconnectError::CleanupPending)
    }));
    wait_for_cleanup_start(&mut request, start).await;
    let old_owner = pending_owner(&control).await;
    let (new_complete, new_completion) = oneshot::channel();
    let new_owner = ClientRouteRetirement::new(tokio::spawn(async move {
        new_completion
            .await
            .map_err(|_| ClientRouteDisconnectError::CleanupPending)
    }));
    *control.state.lock().await = ClientRouteControlState::CleanupPending(new_owner.clone());
    complete.send(()).expect("old cleanup still retained");
    assert_eq!(request.await, original_failure());
    control
        .confirm_retirement(&old_owner, TEST_TIMEOUT)
        .await
        .expect("completed owner is idempotent");
    assert!(Arc::ptr_eq(
        &pending_owner(&control).await.owner,
        &new_owner.owner
    ));
    new_complete
        .send(())
        .expect("new cleanup remains independent");
    control
        .confirm_retirement(&new_owner, TEST_TIMEOUT)
        .await
        .expect("only the current exact cleanup can release admission");
    assert!(matches!(
        *control.state.lock().await,
        ClientRouteControlState::Idle
    ));
}

#[test]
fn lost_helper_retirement_production_call_uses_retained_owner_and_original_retry_loop() {
    let source = include_str!("../../route_setup.rs");
    let acquisition = source
        .split_once("    async fn acquire_tcp_flow_transport_diagnosed(")
        .expect("production acquisition")
        .1
        .split_once("    async fn finish_flow_acquire_failure(")
        .expect("shared post-acquire failure boundary")
        .0;
    assert!(acquisition.contains("for attempt in 0..8 {"));
    assert!(acquisition.contains("mptcp_acquire_failure_lost_helper_route(&error)"));
    assert!(acquisition.contains("finish_flow_acquire_failure(state, helper_route_was_lost"));
    assert!(acquisition.contains("ClientRouteControlState::Established(established) = prior"));
    assert!(acquisition.contains("self.start_retirement(established)"));
    assert!(!acquisition.contains("ClientRouteControlState::Idle"));
    assert!(!acquisition.contains(".shutdown("));
}
