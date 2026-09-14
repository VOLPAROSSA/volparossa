use super::*;

fn samples(scope: &PathScope, count: u32, tick: u32, risky: Option<u32>) -> Vec<MptcpSubflowInfo> {
    (1..=count)
        .map(|path| {
            let (local, remote) = scope.tuples[&path];
            MptcpSubflowInfo {
                subflow_id: 100 + path,
                local: SocketAddr::new(IpAddr::V6(local), scope.port),
                remote: SocketAddr::new(IpAddr::V6(remote), 50123),
                tcp_state: 1,
                bytes_acked: u64::from(tick) * 120_000,
                bytes_received: u64::from(tick) * 100,
                lost_packets: u32::from(Some(path) == risky) * 7,
                total_retransmissions: if Some(path) == risky { tick * 12 } else { 0 },
                data_segments_sent: tick * 100,
                smoothed_rtt_us: 10_000,
            }
        })
        .collect()
}

#[test]
fn mptcp_warm_growth_preserves_initial_floor_and_observes_added_failover_value() {
    for initial_count in [3, 4] {
        let initial = (1..=initial_count).collect::<Vec<_>>();
        let selected = (1..=initial_count + 1).collect::<Vec<_>>();
        let scope = PathScope::new([7; 16], 44443, &selected, &initial);
        let mut history = FlowHistory::default();
        let now = Instant::now();
        for tick in 0..3 {
            let windows = history.observe(
                &samples(&scope, initial_count, tick, Some(2)),
                &scope,
                now + Duration::from_secs(u64::from(tick)),
            );
            assert_eq!(
                history.candidate(
                    &windows,
                    &initial,
                    now + Duration::from_secs(u64::from(tick))
                ),
                None
            );
        }
        let at = now + Duration::from_secs(3);
        let windows = history.observe(&samples(&scope, initial_count, 3, Some(2)), &scope, at);
        assert_eq!(history.candidate(&windows, &initial, at), Some(2));
        let mut growth = WarmGrowth::new(scope);
        let warm = initial_count + 1;
        assert_eq!(
            growth.decide(Some(warm), Some(2), false, true, at),
            Decision::Activate { warm, risky: 2 }
        );
        growth.activated(warm, 2, at);

        // Its first genuine lifetime is only a baseline; an added address is not payload proof.
        let windows = history.observe(
            &samples(&growth.scope, warm, 4, Some(2)),
            &growth.scope,
            now + Duration::from_secs(4),
        );
        assert!(!probe_useful(
            growth.probe.as_ref().unwrap(),
            &windows,
            &initial
        ));
        let windows = history.observe(
            &samples(&growth.scope, warm, 5, Some(2)),
            &growth.scope,
            now + Duration::from_secs(5),
        );
        let useful = probe_useful(growth.probe.as_ref().unwrap(), &windows, &initial);
        assert!(useful);
        assert_eq!(
            growth.decide(
                Some(warm + 1),
                Some(1),
                useful,
                true,
                now + Duration::from_secs(5)
            ),
            Decision::Hold,
            "a live probe never launches a second one"
        );
        // A stalled/closed initial subflow must not let removal cross the actual flow floor.
        assert_eq!(
            growth.decide(None, None, false, false, now + Duration::from_secs(16)),
            Decision::Hold
        );
        assert_eq!(
            growth.decide(None, None, false, true, now + Duration::from_secs(16)),
            Decision::RetireExtra(warm)
        );
        growth.retired();
        assert!(growth.probe.is_none());
        assert_eq!(growth.scope.initial, initial);
    }
}

#[test]
fn mptcp_warm_growth_never_reuses_other_flow_lifetimes_or_ambiguous_tuples() {
    let scope = PathScope::new([7; 16], 44443, &[1, 2, 3], &[1, 2]);
    let now = Instant::now();
    let mut history = FlowHistory::default();
    history.observe(&samples(&scope, 2, 0, Some(2)), &scope, now);
    let windows = history.observe(
        &samples(&scope, 2, 1, Some(2)),
        &scope,
        now + Duration::from_secs(1),
    );
    assert_eq!(
        history.candidate(&windows, &scope.initial, now + Duration::from_secs(1)),
        None
    );
    let mut changed = samples(&scope, 2, 2, Some(2));
    changed[1].subflow_id += 50;
    let windows = history.observe(&changed, &scope, now + Duration::from_secs(4));
    assert!(!windows[&2].progressed);
    assert_eq!(
        history.candidate(&windows, &scope.initial, now + Duration::from_secs(4)),
        None
    );
    changed[0].bytes_acked = 0;
    let windows = history.observe(&changed, &scope, now + Duration::from_secs(5));
    assert!(!windows[&1].progressed);
    let mut independent = FlowHistory::default();
    let windows = independent.observe(&samples(&scope, 2, 100, Some(2)), &scope, now);
    assert!(
        windows
            .values()
            .all(|window| !window.progressed && !window.lossy)
    );
    changed.push(changed[0]);
    assert!(history.observe(&changed, &scope, now).is_empty());
    changed.pop();
    changed[0].remote.set_ip("::1".parse().unwrap());
    assert!(history.observe(&changed, &scope, now).is_empty());
    assert!(history.previous.is_empty());
}
