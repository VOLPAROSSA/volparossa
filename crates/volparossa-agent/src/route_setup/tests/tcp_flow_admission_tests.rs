use super::*;
use crate::mptcp_transport::acquire_diagnostic::{Failure, History, Reason, Stage};
use std::{pin::Pin, task::Poll};

fn busy() -> ContentStreamOpenFailure {
    ContentStreamOpenFailure::new(
        ContentStreamOpenCause::RouteState,
        ClientRouteConnectError::Busy,
    )
}

fn expiry_after(seconds: u64) -> ClientRouteExpiry {
    ClientRouteExpiry {
        hard_expires_at_ms: NOW_MS + seconds * 1_000,
        monotonic_deadline: Instant::now() + Duration::from_secs(seconds),
    }
}

async fn assert_pending<F: Future>(mut request: Pin<&mut F>) {
    std::future::poll_fn(|context| {
        assert!(request.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
}

async fn lock_wait_case(wall_now_ms: u64, elapsed: Duration, expired: bool) {
    let (route, manager, shared) = established_fake_route().await;
    let mut owner = Some((route, manager));
    let control = ClientRouteControl::default();
    let expiry = expiry_after(2);
    let clock = FakeClock::new();
    let clock_reads = AtomicU64::new(0);
    let acquires = AtomicU64::new(0);
    let mut held = control.state.lock().await;
    // As in the lost-helper fixture, this marker stands for the affine FakeProtocol owner.
    // It never invents a production MPTCP transport or a negotiated kernel socket.
    *held = ClientRouteControlState::Connecting;
    let mut request = Box::pin(async {
        let (state, sampled_at_ms) = control
            .admit_tcp_flow_attempt(
                None,
                || {
                    clock_reads.fetch_add(1, Ordering::Relaxed);
                    (clock.unix_millis(), Instant::now())
                },
                |state, wall_now_ms, monotonic_now| {
                    assert!(matches!(state, ClientRouteControlState::Connecting));
                    Some(expiry.is_expired(wall_now_ms, monotonic_now))
                },
                |prior| {
                    assert!(matches!(prior, ClientRouteControlState::Connecting));
                    assert!(control.state.try_lock().is_err());
                    let (route, manager) = owner.take().expect("exact fixture owner");
                    ClientRouteControlState::CleanupPending(ClientRouteRetirement::new(
                        tokio::spawn(async move {
                            let _ = route.teardown().await;
                            manager
                                .shutdown()
                                .await
                                .map_err(|_| ClientRouteDisconnectError::CleanupPending)
                        }),
                    ))
                },
                busy(),
            )
            .await?;
        assert_eq!(sampled_at_ms, wall_now_ms);
        assert!(control.state.try_lock().is_err());
        acquires.fetch_add(1, Ordering::Relaxed);
        drop(state);
        Ok::<(), ContentStreamOpenFailure>(())
    });
    assert_pending(request.as_mut()).await;
    assert_eq!(clock_reads.load(Ordering::Relaxed), 0);
    assert_eq!(acquires.load(Ordering::Relaxed), 0);
    clock.0.store(wall_now_ms, Ordering::Release);
    tokio::time::advance(elapsed).await;
    drop(held);
    let result = request.await;
    assert_eq!(clock_reads.load(Ordering::Relaxed), 1);
    if expired {
        assert_eq!(result, Err(busy()));
        assert_eq!(acquires.load(Ordering::Relaxed), 0);
        assert!(owner.is_none());
        assert!(matches!(
            *control.state.lock().await,
            ClientRouteControlState::Idle
        ));
    } else {
        assert_eq!(result, Ok(()));
        assert_eq!(acquires.load(Ordering::Relaxed), 1);
        assert!(matches!(
            *control.state.lock().await,
            ClientRouteControlState::Connecting
        ));
        let (route, manager) = owner.take().expect("live route was not retired");
        let _ = route.teardown().await;
        manager.shutdown().await.expect("fixture cleanup");
    }
    assert_eq!(
        shared
            .events()
            .iter()
            .filter(|event| *event == "local.destroy")
            .count(),
        1
    );
}

#[tokio::test(start_paused = true)]
async fn tcp_flow_admission_live_lock_wait_reaches_acquire_with_fresh_clock() {
    lock_wait_case(NOW_MS + 1_000, Duration::from_secs(1), false).await;
}

#[tokio::test(start_paused = true)]
async fn tcp_flow_admission_wall_expiry_during_lock_wait_never_acquires() {
    lock_wait_case(NOW_MS + 2_000, Duration::ZERO, true).await;
}

#[tokio::test(start_paused = true)]
async fn tcp_flow_admission_monotonic_expiry_survives_wall_rollback() {
    lock_wait_case(NOW_MS - 1_000, Duration::from_secs(2), true).await;
}

#[tokio::test(start_paused = true)]
async fn tcp_flow_admission_retry_expiry_keeps_history_without_second_acquire() {
    let (route, manager, shared) = established_fake_route().await;
    let control = ClientRouteControl::default();
    *control.state.lock().await = ClientRouteControlState::Connecting;
    let expiry = expiry_after(2);
    let clock = FakeClock::new();
    let acquires = AtomicU64::new(0);
    let (state, _) = control
        .admit_tcp_flow_attempt(
            None,
            || (clock.unix_millis(), Instant::now()),
            |_, wall, monotonic| Some(expiry.is_expired(wall, monotonic)),
            |_| panic!("live first attempt must not retire"),
            busy(),
        )
        .await
        .expect("first attempt admitted");
    acquires.fetch_add(1, Ordering::Relaxed);
    let mut history = History::default();
    history.record_round(Some(Failure {
        stage: Stage::HelperAcquire,
        reason: Reason::HelperKernel,
        helper_diagnostic: None,
    }));
    let original = ContentStreamOpenFailure::from_flow_acquire(
        ClientRouteConnectError::TransportRuntimeUnavailable,
        history.summary(),
    );
    tokio::time::advance(Duration::from_secs(2)).await;
    let result = control
        .admit_tcp_flow_attempt(
            Some(state),
            || (clock.unix_millis(), Instant::now()),
            |_, wall, monotonic| Some(expiry.is_expired(wall, monotonic)),
            |prior| {
                assert!(matches!(prior, ClientRouteControlState::Connecting));
                assert!(control.state.try_lock().is_err());
                ClientRouteControlState::CleanupPending(ClientRouteRetirement::new(tokio::spawn(
                    async move {
                        let _ = route.teardown().await;
                        manager
                            .shutdown()
                            .await
                            .map_err(|_| ClientRouteDisconnectError::CleanupPending)
                    },
                )))
            },
            original,
        )
        .await;
    let Err(failure) = result else {
            acquires.fetch_add(1, Ordering::Relaxed);
            panic!("expired retry must not reach acquire");
        };
    assert_eq!(failure, original);
    assert_eq!(failure.flow_acquire(), history.summary());
    assert_eq!(acquires.load(Ordering::Relaxed), 1);
    assert!(matches!(
        *control.state.lock().await,
        ClientRouteControlState::Idle
    ));
    assert_eq!(
        shared
            .events()
            .iter()
            .filter(|event| *event == "local.destroy")
            .count(),
        1
    );
}

#[tokio::test]
async fn tcp_flow_admission_cancel_preserves_expired_cleanup_owner() {
    let (route, manager, shared) = established_fake_route().await;
    let before = shared.events();
    let control = ClientRouteControl::default();
    *control.state.lock().await = ClientRouteControlState::Connecting;
    let expiry = expiry_after(0);
    let (started, start) = oneshot::channel();
    let (complete, completion) = oneshot::channel();
    let mut request = Box::pin(control.admit_tcp_flow_attempt(
        None,
        || (NOW_MS, Instant::now()),
        |_, wall, monotonic| Some(expiry.is_expired(wall, monotonic)),
        |prior| {
            assert!(matches!(prior, ClientRouteControlState::Connecting));
            assert!(control.state.try_lock().is_err());
            ClientRouteControlState::CleanupPending(ClientRouteRetirement::new(tokio::spawn(
                async move {
                    started.send(()).expect("original waiter exists");
                    completion
                        .await
                        .map_err(|_| ClientRouteDisconnectError::CleanupPending)?;
                    let _ = route.teardown().await;
                    manager
                        .shutdown()
                        .await
                        .map_err(|_| ClientRouteDisconnectError::CleanupPending)
                },
            )))
        },
        busy(),
    ));
    timeout(TEST_TIMEOUT, async {
        tokio::select! {
            _ = &mut request => panic!("cleanup is not yet confirmed"),
            result = start => result.expect("retained cleanup started"),
        }
    })
    .await
    .expect("bounded cleanup start");
    let retained = {
        let state = control.state.lock().await;
        let ClientRouteControlState::CleanupPending(retirement) = &*state else {
            panic!("expired owner must be retained before await");
        };
        retirement.clone()
    };
    drop(request);
    assert_eq!(shared.events(), before);
    {
        let state = control.state.lock().await;
        let ClientRouteControlState::CleanupPending(retirement) = &*state else {
            panic!("caller cancellation cannot publish Idle");
        };
        assert!(Arc::ptr_eq(&retirement.owner, &retained.owner));
    }
    complete
        .send(())
        .expect("cleanup outlives admission caller");
    control
        .confirm_retirement(&retained, TEST_TIMEOUT)
        .await
        .expect("original cleanup joined");
    assert!(matches!(
        *control.state.lock().await,
        ClientRouteControlState::Idle
    ));
    assert_eq!(
        shared
            .events()
            .iter()
            .filter(|event| *event == "local.destroy")
            .count(),
        1
    );
}

#[tokio::test]
async fn tcp_flow_admission_cleanup_failure_remains_pending() {
    let control = ClientRouteControl::default();
    *control.state.lock().await = ClientRouteControlState::Connecting;
    let expiry = expiry_after(0);
    let result = control
        .admit_tcp_flow_attempt(
            None,
            || (NOW_MS, Instant::now()),
            |_, wall, monotonic| Some(expiry.is_expired(wall, monotonic)),
            |_| {
                ClientRouteControlState::CleanupPending(ClientRouteRetirement::new(tokio::spawn(
                    async { Err(ClientRouteDisconnectError::CleanupPending) },
                )))
            },
            busy(),
        )
        .await;
    assert_eq!(result.err(), Some(busy()));
    let state = control.state.lock().await;
    let ClientRouteControlState::CleanupPending(retirement) = &*state else {
        panic!("unconfirmed cleanup must remain retained");
    };
    assert_eq!(
        retirement.owner.lock().await.completed,
        Some(Err(ClientRouteDisconnectError::CleanupPending))
    );
}

#[tokio::test]
async fn tcp_flow_admission_existing_retirement_joins_without_new_acquire() {
    let control = ClientRouteControl::default();
    *control.state.lock().await =
        ClientRouteControlState::CleanupPending(ClientRouteRetirement::new(tokio::spawn(async {
            Ok(())
        })));
    let result = control
        .admit_production_tcp_flow_attempt(None, NOW_MS, busy())
        .await;
    assert_eq!(result.err(), Some(busy()));
    assert!(matches!(
        *control.state.lock().await,
        ClientRouteControlState::Idle
    ));
}

#[test]
fn tcp_flow_admission_production_call_checks_initial_and_existing_retry_boundary() {
    let source = include_str!("../../route_setup.rs");
    let acquisition = source
        .split_once("    async fn acquire_tcp_flow_transport_diagnosed(")
        .expect("production acquisition")
        .1
        .split_once("    async fn admit_production_tcp_flow_attempt")
        .expect("production admission wrapper")
        .0;
    assert!(acquisition.contains("admit_production_tcp_flow_attempt(None, now_ms, busy)"));
    assert!(acquisition.contains("for attempt in 0..8 {"));
    assert!(acquisition.contains("if attempt == 0 {"));
    let loop_body = acquisition
        .split_once("for attempt in 0..8 {")
        .expect("unchanged attempt cap")
        .1;
    let admission = loop_body
        .find("admit_production_tcp_flow_attempt(Some(state), now_ms, failure)")
        .expect("fresh admission before each attempt");
    assert!(
        admission
            < loop_body
                .find("random_mptcp_source_port(")
                .expect("source port")
    );
    assert!(admission < loop_body.find(".acquire_flow(").expect("helper acquire"));
    assert!(
        acquisition
            .contains("client_open_tcp_material(route, policy, destination, port, admitted_at_ms)")
    );
    assert!(!acquisition.contains("retire_expired_route(now_ms"));
    let admission = source
        .split_once("    async fn admit_production_tcp_flow_attempt")
        .expect("production admission wrapper")
        .1
        .split_once("    /// Sample both clocks")
        .expect("shared admission implementation")
        .0;
    assert!(admission.contains("crate::unix_millis().max(requested_at_ms), Instant::now()"));
    assert!(admission.contains("Some(established.is_expired(wall_now_ms, monotonic_now))"));
    assert!(admission.contains("self.start_retirement(established)"));
}

#[derive(Debug)]
struct AcquiredFixtureStream(Arc<AtomicU64>);

impl Drop for AcquiredFixtureStream {
    fn drop(&mut self) {
        self.0.fetch_add(1, Ordering::Relaxed);
    }
}

fn assert_original_owner_destroyed_once(shared: &FakeShared) {
    assert_eq!(
        shared
            .events()
            .iter()
            .filter(|event| *event == "local.destroy")
            .count(),
        1
    );
}

async fn successful_acquire_case(
    wall_now_ms: u64,
    elapsed: Duration,
    expired: bool,
    original: ContentStreamOpenFailure,
) {
    let (route, manager, shared) = established_fake_route().await;
    let mut owner = Some((route, manager));
    let control = ClientRouteControl::default();
    *control.state.lock().await = ClientRouteControlState::Connecting;
    let expiry = expiry_after(2);
    let clock = FakeClock::new();
    let clock_reads = AtomicU64::new(0);
    let acquires = AtomicU64::new(0);
    let drops = Arc::new(AtomicU64::new(0));
    let (state, admitted_at_ms) = control
        .admit_tcp_flow_attempt(
            None,
            || (clock.unix_millis(), Instant::now()),
            |_, wall, monotonic| Some(expiry.is_expired(wall, monotonic)),
            |_| panic!("initial live admission cannot retire"),
            busy(),
        )
        .await
        .expect("initial live route");
    assert_eq!(admitted_at_ms, NOW_MS);
    let (complete, completion) = oneshot::channel();
    let mut request = Box::pin(async {
        acquires.fetch_add(1, Ordering::Relaxed);
        // This controlled successful acquisition holds the same affine route slot while
        // pending, just as the helper RPC does; it is not a substituted kernel transport.
        let flow = completion.await.expect("successful fixture acquisition");
        control
            .complete_tcp_flow_acquire(
                state,
                flow,
                || {
                    assert!(control.state.try_lock().is_err());
                    clock_reads.fetch_add(1, Ordering::Relaxed);
                    (clock.unix_millis(), Instant::now())
                },
                |state, wall, monotonic| {
                    assert!(matches!(state, ClientRouteControlState::Connecting));
                    Some(expiry.is_expired(wall, monotonic))
                },
                |prior| {
                    assert!(matches!(prior, ClientRouteControlState::Connecting));
                    assert!(control.state.try_lock().is_err());
                    assert_eq!(drops.load(Ordering::Relaxed), 1);
                    let (route, manager) = owner.take().expect("original fixture owner");
                    ClientRouteControlState::CleanupPending(ClientRouteRetirement::new(
                        tokio::spawn(async move {
                            let _ = route.teardown().await;
                            manager
                                .shutdown()
                                .await
                                .map_err(|_| ClientRouteDisconnectError::CleanupPending)
                        }),
                    ))
                },
                original,
            )
            .await
    });
    assert_pending(request.as_mut()).await;
    assert_eq!(clock_reads.load(Ordering::Relaxed), 0);
    assert_eq!(acquires.load(Ordering::Relaxed), 1);
    clock.0.store(wall_now_ms, Ordering::Release);
    tokio::time::advance(elapsed).await;
    complete
        .send(AcquiredFixtureStream(drops.clone()))
        .expect("original pending acquisition");
    let result = request.await;
    assert_eq!(clock_reads.load(Ordering::Relaxed), 1);
    assert_eq!(acquires.load(Ordering::Relaxed), 1);
    if expired {
        let failure = result.expect_err("expired successful acquire must be refused");
        assert_eq!(failure, original);
        assert_eq!(failure.flow_acquire(), original.flow_acquire());
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        assert!(owner.is_none());
        assert!(matches!(
            *control.state.lock().await,
            ClientRouteControlState::Idle
        ));
    } else {
        let (flow, activation_at_ms) = result.expect("live successful acquire");
        assert_eq!(activation_at_ms, wall_now_ms);
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        // Later expiry does not revoke this admitted stream or rebase the original deadline.
        tokio::time::advance(Duration::from_secs(2) - elapsed).await;
        assert!(expiry.is_expired(NOW_MS, Instant::now()));
        assert_eq!(drops.load(Ordering::Relaxed), 0);
        assert!(matches!(
            *control.state.lock().await,
            ClientRouteControlState::Connecting
        ));
        drop(flow);
        assert_eq!(drops.load(Ordering::Relaxed), 1);
        let (route, manager) = owner.take().expect("live owner was not retired");
        let _ = route.teardown().await;
        manager.shutdown().await.expect("fixture cleanup");
    }
    assert_original_owner_destroyed_once(&shared);
}

#[tokio::test(start_paused = true)]
async fn tcp_flow_admission_post_acquire_live_success_refreshes_activation_without_rebasing() {
    successful_acquire_case(NOW_MS + 1_000, Duration::from_secs(1), false, busy()).await;
}

#[tokio::test(start_paused = true)]
async fn tcp_flow_admission_post_acquire_wall_expiry_drops_stream_before_retirement() {
    successful_acquire_case(NOW_MS + 2_000, Duration::ZERO, true, busy()).await;
}

#[tokio::test(start_paused = true)]
async fn tcp_flow_admission_post_acquire_monotonic_expiry_survives_wall_rollback() {
    successful_acquire_case(NOW_MS - 1_000, Duration::from_secs(2), true, busy()).await;
}

#[tokio::test(start_paused = true)]
async fn tcp_flow_admission_post_acquire_expiry_preserves_prior_failure_history() {
    let mut history = History::default();
    history.record_round(Some(Failure {
        stage: Stage::HelperAcquire,
        reason: Reason::HelperKernel,
        helper_diagnostic: None,
    }));
    let original = ContentStreamOpenFailure::from_flow_acquire(
        ClientRouteConnectError::TransportRuntimeUnavailable,
        history.summary(),
    );
    successful_acquire_case(NOW_MS, Duration::from_secs(2), true, original).await;
}

#[tokio::test]
async fn tcp_flow_admission_post_acquire_cancel_preserves_retirement_after_stream_drop() {
    let (route, manager, shared) = established_fake_route().await;
    let before = shared.events();
    let control = ClientRouteControl::default();
    let mut state = control.state.lock().await;
    *state = ClientRouteControlState::Connecting;
    let drops = Arc::new(AtomicU64::new(0));
    let (started, start) = oneshot::channel();
    let (complete, completion) = oneshot::channel();
    let mut request = Box::pin(control.complete_tcp_flow_acquire(
        state,
        AcquiredFixtureStream(drops.clone()),
        || (NOW_MS, Instant::now()),
        |_, _, _| Some(true),
        |prior| {
            assert!(matches!(prior, ClientRouteControlState::Connecting));
            assert!(control.state.try_lock().is_err());
            assert_eq!(drops.load(Ordering::Relaxed), 1);
            ClientRouteControlState::CleanupPending(ClientRouteRetirement::new(tokio::spawn(
                async move {
                    started.send(()).expect("original caller waiting");
                    completion
                        .await
                        .map_err(|_| ClientRouteDisconnectError::CleanupPending)?;
                    let _ = route.teardown().await;
                    manager
                        .shutdown()
                        .await
                        .map_err(|_| ClientRouteDisconnectError::CleanupPending)
                },
            )))
        },
        busy(),
    ));
    timeout(TEST_TIMEOUT, async {
        tokio::select! {
            _ = &mut request => panic!("retirement has not yet joined"),
            result = start => result.expect("retirement started after stream drop"),
        }
    })
    .await
    .expect("bounded retirement start");
    let retained = {
        let state = control.state.lock().await;
        let ClientRouteControlState::CleanupPending(retirement) = &*state else {
            panic!("exact owner must be retained before cancellation");
        };
        retirement.clone()
    };
    drop(request);
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    assert_eq!(shared.events(), before);
    {
        let state = control.state.lock().await;
        let ClientRouteControlState::CleanupPending(retirement) = &*state else {
            panic!("cancel cannot discard pending cleanup");
        };
        assert!(Arc::ptr_eq(&retirement.owner, &retained.owner));
    }
    complete.send(()).expect("retirement outlives caller");
    control
        .confirm_retirement(&retained, TEST_TIMEOUT)
        .await
        .expect("exact cleanup joined");
    assert!(matches!(
        *control.state.lock().await,
        ClientRouteControlState::Idle
    ));
    assert_eq!(
        shared
            .events()
            .iter()
            .filter(|event| *event == "local.destroy")
            .count(),
        1
    );
}

#[tokio::test]
async fn tcp_flow_admission_post_acquire_cleanup_failure_retains_owner_after_stream_drop() {
    let control = ClientRouteControl::default();
    let mut state = control.state.lock().await;
    *state = ClientRouteControlState::Connecting;
    let drops = Arc::new(AtomicU64::new(0));
    let result = control
        .complete_tcp_flow_acquire(
            state,
            AcquiredFixtureStream(drops.clone()),
            || (NOW_MS, Instant::now()),
            |_, _, _| Some(true),
            |_| {
                assert_eq!(drops.load(Ordering::Relaxed), 1);
                ClientRouteControlState::CleanupPending(ClientRouteRetirement::new(tokio::spawn(
                    async { Err(ClientRouteDisconnectError::CleanupPending) },
                )))
            },
            busy(),
        )
        .await;
    assert_eq!(result.err(), Some(busy()));
    assert_eq!(drops.load(Ordering::Relaxed), 1);
    let state = control.state.lock().await;
    let ClientRouteControlState::CleanupPending(retirement) = &*state else {
        panic!("cleanup failure must remain owned");
    };
    assert_eq!(
        retirement.owner.lock().await.completed,
        Some(Err(ClientRouteDisconnectError::CleanupPending))
    );
}

#[test]
fn tcp_flow_admission_post_acquire_production_rechecks_and_forwards_fresh_activation_clock() {
    let source = include_str!("../../route_setup.rs");
    let acquisition = source
        .split_once("    async fn acquire_tcp_flow_transport_diagnosed(")
        .expect("production acquisition")
        .1
        .split_once("    async fn admit_production_tcp_flow_attempt")
        .expect("production admission wrapper")
        .0;
    let success = acquisition
        .split_once("                Ok(flow) => {")
        .expect("successful acquired stream")
        .1
        .split_once("                Err(error) => {")
        .expect("unchanged helper failure branch")
        .0;
    assert!(success.contains(".complete_tcp_flow_acquire("));
    assert!(success.contains("crate::unix_millis().max(now_ms), Instant::now()"));
    assert!(success.contains("Some(established.is_expired(wall_now_ms, monotonic_now))"));
    assert!(success.contains("self.start_retirement(established)"));
    assert!(success.contains("return Ok((flow, material, activation_at_ms))"));
    assert!(!success.contains("client_open_tcp_material("));
    for (start, end) in [
        (
            "    async fn activate_tcp_destination(",
            "    /// Open one content",
        ),
        (
            "    pub(crate) async fn open_content_stream_diagnosed(",
            "    /// Retain the carrying route",
        ),
        (
            "    pub(crate) async fn run_tcp_ingress(",
            "    pub(crate) async fn ",
        ),
    ] {
        let caller = source
            .split_once(start)
            .expect("production activation caller")
            .1
            .split_once(end)
            .expect("next production member")
            .0;
        assert!(caller.contains("let (transport, material, activation_at_ms) = self"));
        let activation = caller
            .split_once("activate_production_mptcp_client_flow(")
            .expect("protected TLS activation")
            .1
            .split_once(")\n")
            .expect("activation arguments")
            .0;
        assert!(activation.contains("activation_at_ms,"));
        assert!(!activation.contains("now_ms,"));
    }
}
