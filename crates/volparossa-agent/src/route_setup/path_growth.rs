//! A bounded failover probe, not a prediction of extra throughput from an idle path.

use std::{
    collections::{BTreeMap, BTreeSet},
    time::Duration,
};

use super::{
    HysteresisPolicy, Instant, NativePathStatus, ProductionMpquicPathHealth, SelectionPathState,
    UnixTime,
};

#[derive(Debug, Eq, PartialEq)]
pub(super) enum GrowthDecision {
    Unchanged,
    Hold,
    Activate { warm: u32, risky: u32 },
    Retire { path: u32, recovered: Option<u32> },
}

#[derive(Clone, Copy)]
struct Probe {
    added: u32,
    risky: u32,
    last_useful: Instant,
}

#[derive(Default)]
pub(super) struct WarmPathGrowth {
    previous: BTreeMap<u32, u64>,
    candidate: Option<(u32, Instant)>,
    probe: Option<Probe>,
}

impl WarmPathGrowth {
    pub(super) fn observe(
        &mut self,
        native: &[NativePathStatus],
        health: &ProductionMpquicPathHealth,
        monotonic_now: Instant,
        wall_now: UnixTime,
        warm: Option<u32>,
        minimum_paths: usize,
    ) -> GrowthDecision {
        // The owner has already checked exact native IDs and monotonic counters. A first
        // snapshot is a baseline, not evidence of fresh traffic from before this observation.
        let progressed = native
            .iter()
            .filter_map(|path| {
                (path.data_carrying
                    && self
                        .previous
                        .get(&path.path_id)
                        .is_some_and(|old| path.acked_transport_bytes > *old))
                .then_some(path.path_id)
            })
            .collect::<BTreeSet<_>>();
        self.previous = native
            .iter()
            .map(|path| (path.path_id, path.acked_transport_bytes))
            .collect();
        if let Some(probe) = self.probe {
            return self.observe_probe(
                probe,
                health,
                &progressed,
                monotonic_now,
                wall_now,
                minimum_paths,
            );
        }
        let candidate = warm.and_then(|warm| {
            if minimum_paths < 2
                || native.len() < minimum_paths
                || progressed.len() != native.len()
                || self.previous.contains_key(&warm)
            {
                return None;
            }
            let risky = native
                .iter()
                .find(|path| {
                    health.statuses.get(&path.path_id).is_some_and(|status| {
                        status.state == SelectionPathState::Degraded
                            && status.metrics.packet_loss_ratio
                                >= HysteresisPolicy::default().degraded_loss_ratio
                    })
                })?
                .path_id;
            let other_healthy = native
                .iter()
                .filter(|path| path.path_id != risky)
                .all(|path| {
                    health
                        .statuses
                        .get(&path.path_id)
                        .is_some_and(|status| status.state == SelectionPathState::Active)
                });
            other_healthy.then_some((risky, warm))
        });
        let Some((risky, warm)) = candidate else {
            self.candidate = None;
            return GrowthDecision::Unchanged;
        };
        match self.candidate {
            Some((previous, since)) if previous == risky => {
                if monotonic_now.duration_since(since) >= Duration::from_secs(1) {
                    self.candidate = None;
                    return GrowthDecision::Activate { warm, risky };
                }
            }
            _ => self.candidate = Some((risky, monotonic_now)),
        }
        // One maintenance interval confirms sustained loss while retaining every useful path.
        GrowthDecision::Hold
    }

    fn observe_probe(
        &mut self,
        probe: Probe,
        health: &ProductionMpquicPathHealth,
        progressed: &BTreeSet<u32>,
        now: Instant,
        wall_now: UnixTime,
        minimum_paths: usize,
    ) -> GrowthDecision {
        let policy = HysteresisPolicy::default();
        let grace = Duration::from_secs(policy.degraded_after_seconds);
        let Some(risky) = health.statuses.get(&probe.risky) else {
            self.probe = None;
            return GrowthDecision::Unchanged;
        };
        let can_retire =
            minimum_paths >= 2 && self.previous.len().saturating_sub(1) >= minimum_paths;
        let replacement_useful = progressed.contains(&probe.added)
            && health
                .statuses
                .get(&probe.added)
                .is_some_and(|status| status.state == SelectionPathState::Active)
            && health
                .statuses
                .iter()
                .filter(|(id, _)| {
                    **id != probe.risky && **id != probe.added && self.previous.contains_key(id)
                })
                .all(|(id, status)| {
                    progressed.contains(id) && status.state == SelectionPathState::Active
                });
        if can_retire
            && replacement_useful
            && (risky.state == SelectionPathState::Dead
                || risky.metrics.last_progress_at.age_at(wall_now) >= policy.degraded_after_seconds)
        {
            return GrowthDecision::Retire {
                path: probe.risky,
                recovered: None,
            };
        }
        if replacement_useful
            && progressed.contains(&probe.risky)
            && risky.metrics.packet_loss_ratio >= policy.degraded_loss_ratio
        {
            // Fresh acknowledged transport on every current path and a still-observed weak path
            // justify a failover reserve in use, not an aggregate throughput or unique-byte claim.
            self.probe = Some(Probe {
                last_useful: now,
                ..probe
            });
            return GrowthDecision::Hold;
        }
        if can_retire && now.duration_since(probe.last_useful) >= grace {
            let recovered = (progressed.contains(&probe.risky)
                && risky.state == SelectionPathState::Degraded
                && risky.metrics.packet_loss_ratio < policy.degraded_loss_ratio)
                .then_some(probe.risky);
            return GrowthDecision::Retire {
                path: probe.added,
                recovered,
            };
        }
        GrowthDecision::Hold
    }

    pub(super) fn activated(&mut self, added: u32, risky: u32, now: Instant) {
        self.previous.insert(added, 0);
        self.probe = Some(Probe {
            added,
            risky,
            last_useful: now,
        });
    }

    pub(super) fn retired(&mut self, path: u32) {
        self.previous.remove(&path);
        self.candidate = None;
        if self
            .probe
            .is_some_and(|probe| probe.added == path || probe.risky == path)
        {
            self.probe = None;
        }
    }
}

#[cfg(test)]
mod tests;
