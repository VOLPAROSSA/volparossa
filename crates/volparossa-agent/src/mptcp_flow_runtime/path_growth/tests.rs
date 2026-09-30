use super::*;

#[test]
fn mptcp_warm_growth_stalled_productive_initial_can_use_fresh_path_but_idle_cannot() {
    let scope = PathScope::new([7; 16], 44443, &[1, 2, 3, 4], &[1, 2]);
    let start = Instant::now();
    for idle in [false, true] {
        let mut history = FlowHistory::default();
        for tick in 0..=6 {
            let mut snapshot = samples(&scope, 2, tick, None);
            if tick > 1 {
                snapshot[0] = samples(&scope, 2, 1, None)[0];
                if idle {
                    snapshot[1] = samples(&scope, 2, 1, None)[1];
                }
            }
            let at = start + Duration::from_secs(u64::from(tick));
            let windows = history.observe(&snapshot, &scope, at);
            assert_eq!(
                history.candidate(&windows, &scope.initial, at),
                (!idle && tick >= 6).then_some(1)
            );
        }
    }
}

#[test]
fn mptcp_refill_scope_preserves_original_floor_and_existing_probe() {
    let mut growth = WarmGrowth::new(PathScope::new([7; 16], 44443, &[1, 2, 3], &[1, 2]));
    let at = Instant::now();
    growth.activated(3, 1, at);
    assert!(growth.extend_scope(PathScope::new([7; 16], 44443, &[1, 2, 3, 4], &[1, 2])));
    assert_eq!(growth.scope.initial, [1, 2]);
    assert_eq!(growth.scope.tuples.len(), 4);
    assert_eq!(growth.probes[&3].added, 3);
    assert_eq!(growth.probes[&3].last_useful, at);
    // A lost control reply can replay the exact authenticated installation; observations and
    // the existing probe's grace window must not be reset by that retry.
    assert!(growth.extend_scope(PathScope::new([7; 16], 44443, &[1, 2, 3, 4], &[1, 2])));
    assert_eq!(growth.probes[&3].last_useful, at);
    let actual_new_path_samples = samples(&growth.scope, 4, 10, Some(1));
    assert_eq!(
        growth.scope.bind(&actual_new_path_samples).unwrap().len(),
        4
    );
}

#[test]
fn mptcp_refill_cannot_replace_context_floor_or_drop_existing_path() {
    let mut growth = WarmGrowth::new(PathScope::new([7; 16], 44443, &[1, 2, 3], &[1, 2]));
    for scope in [
        PathScope::new([8; 16], 44443, &[1, 2, 3, 4], &[1, 2]),
        PathScope::new([7; 16], 44444, &[1, 2, 3, 4], &[1, 2]),
        PathScope::new([7; 16], 44443, &[1, 2, 3, 4], &[1, 3]),
        PathScope::new([7; 16], 44443, &[1, 2, 4, 5], &[1, 2]),
    ] {
        assert!(!growth.extend_scope(scope));
        assert_eq!(growth.scope.tuples.len(), 3);
    }
}

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
            growth.decide(Some(warm), Some(2), &[], true, at),
            Decision::Activate { warm, risky: 2 }
        );
        growth.activated(warm, 2, at);

        // Its first genuine lifetime is only a baseline; an added address is not payload proof.
        let windows = history.observe(
            &samples(&growth.scope, warm, 4, Some(2)),
            &growth.scope,
            now + Duration::from_secs(4),
        );
        assert!(!probe_useful(&growth.probes[&warm], &windows, &initial));
        let windows = history.observe(
            &samples(&growth.scope, warm, 5, Some(2)),
            &growth.scope,
            now + Duration::from_secs(5),
        );
        let useful = probe_useful(&growth.probes[&warm], &windows, &initial);
        assert!(useful);
        assert_eq!(
            growth.decide(
                Some(warm + 1),
                Some(1),
                &[warm],
                true,
                now + Duration::from_secs(5)
            ),
            Decision::Hold,
            "a live probe never launches a second one"
        );
        // A stalled/closed initial subflow must not let removal cross the actual flow floor.
        assert_eq!(
            growth.decide(None, None, &[], false, now + Duration::from_secs(16)),
            Decision::Hold
        );
        assert_eq!(
            growth.decide(None, None, &[], true, now + Duration::from_secs(16)),
            Decision::RetireExtra(warm)
        );
        growth.retired(warm);
        assert!(growth.probes.is_empty());
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

#[test]
fn mptcp_warm_growth_known_productive_missing_or_closed_path_can_request_refill() {
    let scope = PathScope::new([7; 16], 44443, &[1, 2, 3, 4], &[1, 2]);
    let start = Instant::now();
    for missing in [false, true] {
        for idle in [false, true] {
            let mut history = FlowHistory::default();
            for tick in 0..=7 {
                let mut snapshot = samples(&scope, 2, tick, None);
                if tick > 1 {
                    if missing {
                        snapshot.remove(0);
                    } else {
                        snapshot[0] = samples(&scope, 2, 1, None)[0];
                        snapshot[0].tcp_state = 7;
                    }
                    if idle {
                        *snapshot.last_mut().unwrap() = samples(&scope, 2, 1, None)[1];
                    }
                }
                let at = start + Duration::from_secs(u64::from(tick));
                let windows = history.observe(&snapshot, &scope, at);
                let candidate = history.candidate(&windows, &scope.initial, at);
                if tick >= 6 {
                    assert_eq!(candidate, (!idle).then_some(1));
                    assert!(!windows[&1].established);
                }
            }
        }
    }
    let mut unobserved = FlowHistory::default();
    for tick in 0..=10 {
        let mut snapshot = samples(&scope, 2, tick, None);
        snapshot.remove(0);
        let at = start + Duration::from_secs(u64::from(tick));
        let windows = unobserved.observe(&snapshot, &scope, at);
        assert_eq!(unobserved.candidate(&windows, &scope.initial, at), None);
    }
}

#[test]
fn mptcp_refill_preserves_unsafe_to_retire_trial_while_new_path_can_become_useful() {
    let mut growth = WarmGrowth::new(PathScope::new([7; 16], 44443, &[1, 2, 3, 4], &[1, 2]));
    let start = Instant::now();
    growth.activated(3, 1, start);
    assert_eq!(
        growth.decide(Some(4), Some(1), &[], false, start + PROBE_GRACE),
        Decision::Activate { warm: 4, risky: 1 },
    );
    assert!(
        growth.probes.contains_key(&3),
        "old endpoint is still owned"
    );
    growth.activated(4, 1, start + PROBE_GRACE);
    assert_eq!(growth.probes.len(), 2);
    let productive = start + PROBE_GRACE + Duration::from_secs(2);
    assert_eq!(
        growth.decide(Some(5), Some(1), &[4], false, productive),
        Decision::Hold,
    );
    // Once every live flow has its original floor again, only the unhelpful endpoint leaves.
    assert_eq!(
        growth.decide(None, None, &[4], true, productive),
        Decision::RetireExtra(3),
    );
    growth.retired(3);
    assert!(growth.probes.contains_key(&4));
    assert!(!growth.probes.contains_key(&3));
}
