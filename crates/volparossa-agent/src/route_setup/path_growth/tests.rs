//! Explicit health-input lifecycle tests, not evidence of real extra MPQUIC datapaths.

use super::*;

struct Fixture {
    health: ProductionMpquicPathHealth,
    growth: WarmPathGrowth,
    start: Instant,
    minimum_paths: usize,
}

impl Fixture {
    fn new() -> Self {
        Self::with_paths(&[1, 2], &[3], 2)
    }

    fn with_paths(active: &[u32], warm: &[u32], minimum_paths: usize) -> Self {
        Self {
            health: ProductionMpquicPathHealth::new(active, warm.iter().copied(), wall(0)).unwrap(),
            growth: WarmPathGrowth::default(),
            start: Instant::now(),
            minimum_paths,
        }
    }

    fn observe(
        &mut self,
        seconds: u64,
        native: &[NativePathStatus],
        warm: Option<u32>,
    ) -> GrowthDecision {
        self.health
            .observe(native, wall(seconds))
            .expect("valid native counter fixture");
        self.growth.observe(
            native,
            &self.health,
            self.start + Duration::from_secs(seconds),
            wall(seconds),
            warm,
            self.minimum_paths,
        )
    }

    fn activate(&mut self, seconds: u64) {
        self.activate_path(3, 2, seconds);
    }

    fn activate_path(&mut self, added: u32, risky: u32, seconds: u64) {
        self.health.record_activation(added, wall(seconds)).unwrap();
        self.growth
            .activated(added, risky, self.start + Duration::from_secs(seconds));
    }
}

fn wall(seconds: u64) -> UnixTime {
    UnixTime::from_secs(1_000 + seconds)
}

fn status(path_id: u32, bytes: u64, losses: u64) -> NativePathStatus {
    NativePathStatus {
        path_id,
        smoothed_rtt_us: 10_000,
        delivered_bytes: 0,
        acked_transport_bytes: bytes,
        packets_lost: losses,
        data_carrying: bytes != 0,
        ..NativePathStatus::default()
    }
}

fn establish_probe() -> Fixture {
    let mut fixture = Fixture::new();
    assert_eq!(
        fixture.observe(0, &[status(1, 0, 0), status(2, 0, 0)], Some(3)),
        GrowthDecision::Unchanged
    );
    assert_eq!(
        fixture.observe(1, &[status(1, 12_000, 0), status(2, 12_000, 0)], Some(3)),
        GrowthDecision::Unchanged
    );
    assert_eq!(
        fixture.observe(2, &[status(1, 24_000, 0), status(2, 24_000, 2)], Some(3)),
        GrowthDecision::Hold
    );
    assert_eq!(
        fixture.observe(3, &[status(1, 36_000, 0), status(2, 36_000, 4)], Some(3)),
        GrowthDecision::Activate { warm: 3, risky: 2 }
    );
    // The owner records this only after successful, authority-bound native AddPath. Its immediate
    // GetStatus may legitimately report the third path as present but not yet payload-carrying.
    fixture.activate(3);
    fixture
        .health
        .observe(
            &[status(1, 36_000, 0), status(2, 36_000, 4), status(3, 0, 0)],
            wall(3),
        )
        .unwrap();
    fixture
}

#[test]
fn mpquic_growth_requires_live_payload_and_retains_only_observed_failover_value() {
    switching_risk_restarts_confirmation();
    let mut idle = Fixture::new();
    for seconds in [0, 1, 10, 30] {
        assert_eq!(
            idle.observe(seconds, &[status(1, 0, 0), status(2, 0, 0)], Some(3)),
            GrowthDecision::Unchanged
        );
    }
    let mut fixture = establish_probe();
    for second in 4..=20 {
        assert_eq!(
            fixture.observe(
                second,
                &[
                    status(1, second * 12_000, 0),
                    status(2, second * 12_000, (second - 1) * 2),
                    status(3, (second - 3) * 12_000, 0),
                ],
                None
            ),
            GrowthDecision::Hold,
            "all three make fresh progress and one remains lossy"
        );
    }
    assert_eq!(fixture.health.statuses.len(), 3);
    assert_eq!(
        fixture.observe(
            31,
            &[
                status(1, 372_000, 0),
                status(2, 372_000, 38),
                status(3, 204_000, 0)
            ],
            None
        ),
        GrowthDecision::Retire {
            path: 3,
            recovered: Some(2)
        },
        "no permanent third path after loss recovers or its useful payload stops"
    );
    fixture.health.retire(3);
    fixture
        .health
        .statuses
        .get_mut(&2)
        .unwrap()
        .transition(SelectionPathState::Active, wall(31))
        .unwrap();
    fixture.growth.retired(3);
    assert_eq!(
        fixture.observe(32, &[status(1, 384_000, 0), status(2, 384_000, 38)], None),
        GrowthDecision::Unchanged
    );
}

fn switching_risk_restarts_confirmation() {
    let mut fixture = Fixture::new();
    assert_eq!(
        fixture.observe(0, &[status(1, 0, 0), status(2, 0, 0)], Some(3)),
        GrowthDecision::Unchanged
    );
    assert_eq!(
        fixture.observe(1, &[status(1, 12_000, 0), status(2, 12_000, 2)], Some(3)),
        GrowthDecision::Hold
    );
    fixture
        .health
        .statuses
        .get_mut(&2)
        .unwrap()
        .transition(SelectionPathState::Active, wall(2))
        .unwrap();
    assert_eq!(
        fixture.observe(2, &[status(1, 24_000, 2), status(2, 24_000, 2)], Some(3)),
        GrowthDecision::Hold
    );
    fixture
        .health
        .statuses
        .get_mut(&1)
        .unwrap()
        .transition(SelectionPathState::Active, wall(3))
        .unwrap();
    assert_eq!(
        fixture.observe(3, &[status(1, 36_000, 2), status(2, 36_000, 4)], Some(3)),
        GrowthDecision::Hold,
        "returning to the first risk cannot reuse its old confirmation interval"
    );
    assert_eq!(
        fixture.observe(4, &[status(1, 48_000, 2), status(2, 48_000, 6)], Some(3)),
        GrowthDecision::Activate { warm: 3, risky: 2 }
    );
}

#[test]
fn mpquic_growth_idle_probe_drains_and_proven_replacement_retires_stalled_old_path() {
    let mut idle_probe = establish_probe();
    assert_eq!(
        idle_probe.observe(
            13,
            &[status(1, 48_000, 0), status(2, 48_000, 6), status(3, 0, 0)],
            None
        ),
        GrowthDecision::Retire {
            path: 3,
            recovered: None
        },
        "no fabricated third-path readiness from AddPath alone"
    );

    let mut failover = establish_probe();
    assert_eq!(
        failover.observe(
            4,
            &[
                status(1, 48_000, 0),
                status(2, 36_000, 4),
                status(3, 12_000, 0)
            ],
            None
        ),
        GrowthDecision::Hold
    );
    assert_eq!(
        failover.observe(
            13,
            &[
                status(1, 60_000, 0),
                status(2, 36_000, 4),
                status(3, 24_000, 0)
            ],
            None
        ),
        GrowthDecision::Retire {
            path: 2,
            recovered: None
        },
        "two proven payload paths replace a genuinely stalled original path"
    );
    failover.health.retire(2);
    failover.growth.retired(2);
    assert_eq!(
        failover.observe(14, &[status(1, 72_000, 0), status(3, 36_000, 0)], None),
        GrowthDecision::Unchanged
    );
    assert_eq!(
        failover.health.statuses.keys().copied().collect::<Vec<_>>(),
        [1, 3]
    );
}

fn four_path_probe() -> Fixture {
    let mut fixture = Fixture::with_paths(&[1, 2, 3, 4], &[5, 6], 3);
    let paths = |seconds: u64| {
        (1..=4)
            .map(|id| status(id, seconds * 12_000, if id == 2 { seconds * 2 } else { 0 }))
            .collect::<Vec<_>>()
    };
    assert_eq!(
        fixture.observe(0, &paths(0), Some(5)),
        GrowthDecision::Unchanged
    );
    let mut incomplete = paths(1);
    incomplete[3] = status(4, 0, 0);
    assert_eq!(
        fixture.observe(1, &incomplete, Some(5)),
        GrowthDecision::Unchanged,
        "all four original paths must contribute fresh payload, not only the original pair"
    );
    assert_eq!(fixture.observe(2, &paths(2), Some(5)), GrowthDecision::Hold);
    assert_eq!(
        fixture.observe(3, &paths(3), Some(5)),
        GrowthDecision::Activate { warm: 5, risky: 2 }
    );
    fixture.activate_path(5, 2, 3);
    let mut expanded = paths(4);
    expanded.push(status(5, 12_000, 0));
    assert_eq!(
        fixture.observe(4, &expanded, Some(6)),
        GrowthDecision::Hold,
        "one pending probe must not simultaneously consume the sixth reserved path"
    );
    fixture
}

#[test]
fn mpquic_growth_four_to_five_preserves_minimum_three_and_drains_only_with_room() {
    let mut unhelpful = four_path_probe();
    let continued = [
        status(1, 168_000, 0),
        status(2, 168_000, 40),
        status(3, 168_000, 0),
        status(4, 168_000, 0),
        status(5, 12_000, 0),
    ];
    assert_eq!(
        unhelpful.observe(14, &continued, Some(6)),
        GrowthDecision::Retire {
            path: 5,
            recovered: None
        }
    );
    unhelpful.health.retire(5);
    unhelpful.growth.retired(5);
    assert_eq!(
        unhelpful.health.statuses.len(),
        5,
        "four active plus one still-unconsumed warm"
    );

    let mut failover = four_path_probe();
    assert_eq!(
        failover.observe(
            5,
            &[
                status(1, 60_000, 0),
                status(2, 48_000, 8),
                status(3, 60_000, 0),
                status(4, 60_000, 0),
                status(5, 24_000, 0),
            ],
            Some(6)
        ),
        GrowthDecision::Hold
    );
    assert_eq!(
        failover.observe(
            14,
            &[
                status(1, 168_000, 0),
                status(2, 48_000, 8),
                status(3, 168_000, 0),
                status(4, 168_000, 0),
                status(5, 36_000, 0),
            ],
            Some(6)
        ),
        GrowthDecision::Retire {
            path: 2,
            recovered: None
        }
    );
    failover.health.retire(2);
    failover.growth.retired(2);
    assert_eq!(
        failover.observe(
            15,
            &[
                status(1, 180_000, 0),
                status(3, 180_000, 0),
                status(4, 180_000, 0),
                status(5, 48_000, 0),
            ],
            Some(6)
        ),
        GrowthDecision::Unchanged
    );

    minimum_is_not_a_retirement_target();
}

fn minimum_is_not_a_retirement_target() {
    let mut fixture = four_path_probe();
    // An exact owner can lose other paths while the extra-path probe exists. Even when its
    // timer expires, neither possible removal is allowed to cross the original signed minimum.
    for removed in [3, 4] {
        fixture.health.retire(removed);
        fixture.growth.retired(removed);
    }
    let remaining = [
        status(1, 168_000, 0),
        status(2, 168_000, 10),
        status(5, 12_000, 0),
    ];
    assert_eq!(
        fixture.observe(14, &remaining, Some(6)),
        GrowthDecision::Hold,
        "removing a useless probe would leave only two of the required three"
    );
    assert_eq!(
        fixture.observe(
            15,
            &[
                status(1, 180_000, 0),
                status(2, 168_000, 10),
                status(5, 24_000, 0),
            ],
            Some(6)
        ),
        GrowthDecision::Hold
    );
    assert_eq!(
        fixture.observe(
            24,
            &[
                status(1, 192_000, 0),
                status(2, 168_000, 10),
                status(5, 36_000, 0),
            ],
            Some(6)
        ),
        GrowthDecision::Hold,
        "removing a stalled original would also cross the signed minimum"
    );
}
