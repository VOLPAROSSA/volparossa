use super::*;

// Synthetic kernel-observation decision tests, not a claim of a live MPTCP datapath.
fn scope() -> Scope {
    Scope::new([7; 16], 44443, &[1, 2, 3], &[1, 2])
}

fn samples(scope: &Scope, ticks: &[u32]) -> Vec<MptcpSubflowInfo> {
    ticks
        .iter()
        .enumerate()
        .map(|(index, tick)| {
            let path = u32::try_from(index + 1).unwrap();
            let (client, exit) = scope.tuples[&path];
            MptcpSubflowInfo {
                subflow_id: 100 + path,
                local: SocketAddr::new(IpAddr::V6(client), 50123 + u16::try_from(path).unwrap()),
                remote: SocketAddr::new(IpAddr::V6(exit), scope.port),
                tcp_state: 1,
                bytes_acked: 100,
                bytes_received: u64::from(*tick) * 120_000,
                lost_packets: 0,
                total_retransmissions: 0,
                data_segments_sent: 1,
                smoothed_rtt_us: 10_000,
            }
        })
        .collect()
}

#[test]
fn client_refill_requires_real_same_flow_progress_and_unhelpful_observed_warm() {
    let scope = scope();
    let start = Instant::now();
    let mut history = History::default();
    assert!(!history.demand(&samples(&scope, &[0, 0, 0]), &scope, start));
    assert!(!history.demand(
        &samples(&scope, &[1, 1, 1]),
        &scope,
        start + Duration::from_secs(1)
    ));
    for tick in 2..=11 {
        let demand = history.demand(
            &samples(&scope, &[1, tick, 1]),
            &scope,
            start + Duration::from_secs(u64::from(tick)),
        );
        assert_eq!(
            demand,
            tick == 11,
            "download: stalled initial and exhausted warm, tick {tick}"
        );
    }
    // Recovery is observed immediately; it cannot be inferred from discovering a new peer.
    assert!(!history.demand(
        &samples(&scope, &[2, 12, 2]),
        &scope,
        start + Duration::from_secs(12)
    ));
}

#[test]
fn client_refill_never_grows_idle_healthy_or_useful_warm_routes() {
    let scope = scope();
    let start = Instant::now();
    for mode in 0..4 {
        let mut history = History::default();
        for tick in 0..40 {
            let snapshot = match mode {
                0 => samples(&scope, &[tick, tick, tick]), // Healthy, no useful new path required.
                1 => samples(&scope, &[tick.min(1), tick.min(1), tick.min(1)]), // Entire flow idle.
                2 => samples(&scope, &[tick.min(1), tick, tick]), // Warm path is already helping.
                _ => samples(&scope, &[tick.min(1), tick]), // Warm never tried, not exhausted.
            };
            assert!(
                !history.demand(
                    &snapshot,
                    &scope,
                    start + Duration::from_secs(u64::from(tick))
                ),
                "mode {mode}, tick {tick}"
            );
        }
    }
}

#[test]
fn client_refill_binds_client_direction_and_resets_unknown_lifetimes() {
    let scope = scope();
    let start = Instant::now();
    let mut history = History::default();
    history.demand(&samples(&scope, &[0, 0, 0]), &scope, start);
    history.demand(
        &samples(&scope, &[1, 1, 1]),
        &scope,
        start + Duration::from_secs(1),
    );
    let mut reversed = samples(&scope, &[1, 2, 1]);
    let reverse = &mut reversed[0];
    std::mem::swap(&mut reverse.local, &mut reverse.remote);
    assert!(scope.bind(&reversed).is_none());
    let mut duplicate = samples(&scope, &[1, 2, 1]);
    duplicate[2] = duplicate[0];
    assert!(scope.bind(&duplicate).is_none());
    let mut wrong_port = samples(&scope, &[1, 2, 1]);
    wrong_port[1].remote.set_port(44444);
    assert!(!history.demand(&wrong_port, &scope, start + Duration::from_secs(2)));
    assert!(history.previous.is_empty());

    for tick in 3..20 {
        let mut reset_lifetime = samples(&scope, &[1, tick, 1]);
        reset_lifetime[0].subflow_id += 1;
        assert!(!history.demand(
            &reset_lifetime,
            &scope,
            start + Duration::from_secs(u64::from(tick))
        ));
    }
}

#[test]
fn client_refill_missing_previously_productive_path_is_not_cross_flow_evidence() {
    let scope = scope();
    let start = Instant::now();
    let mut history = History::default();
    history.demand(&samples(&scope, &[0, 0, 0]), &scope, start);
    history.demand(
        &samples(&scope, &[1, 1, 1]),
        &scope,
        start + Duration::from_secs(1),
    );
    for tick in 2..=11 {
        let mut missing = samples(&scope, &[1, tick, 1]);
        missing.remove(0);
        assert_eq!(
            history.demand(
                &missing,
                &scope,
                start + Duration::from_secs(u64::from(tick))
            ),
            tick == 11
        );
        // A second flow must establish its own path history, never borrow the first flow's.
        assert!(!History::default().demand(
            &missing,
            &scope,
            start + Duration::from_secs(u64::from(tick))
        ));
    }
}

#[test]
fn client_refill_failed_attempts_and_scope_retries_preserve_thirty_second_cooldown() {
    let observations = ClientRefillObservations::new([7; 16], 44443, &[1, 2, 3], &[1, 2]);
    let now = Instant::now();
    assert!(!observations.refill_needed(now));
    assert!(observations.0.lock().unwrap().admit_attempt(true, now));
    assert!(
        !observations
            .0
            .lock()
            .unwrap()
            .admit_attempt(true, now + Duration::from_secs(29))
    );
    observations.extend(&[1, 2, 3, 4]).unwrap();
    observations.extend(&[1, 2, 3, 4]).unwrap();
    assert!(
        !observations
            .0
            .lock()
            .unwrap()
            .admit_attempt(true, now + Duration::from_secs(29))
    );
    assert!(
        observations
            .0
            .lock()
            .unwrap()
            .admit_attempt(true, now + Duration::from_secs(30))
    );
    assert!(observations.extend(&[1, 2, 4, 5]).is_err());
    let state = observations.0.lock().unwrap();
    assert_eq!(state.scope.initial, [1, 2]);
    assert_eq!(state.scope.tuples.len(), 4);
}
