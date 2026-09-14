//! RAM-only new-peer admission. Station byte counters alone never imply spare radio airtime.

use crate::resource_headroom::ResourceHeadroom;
use std::time::{Duration, Instant};
use volparossa_routing::{MAX_WIFI_MESH_OBSERVATIONS, WifiMeshSnapshot, WifiMeshSurvey};

#[derive(Default)]
pub(super) struct Admission {
    previous: Option<WifiMeshSnapshot>,
    unproven: Vec<Vec<u8>>,
    last_probe: Option<Instant>,
    discovery_probe_used: bool,
}

impl Admission {
    pub(super) fn next(
        &mut self,
        current: &WifiMeshSnapshot,
        resources: Option<ResourceHeadroom>,
        operator_ceiling: u16,
    ) -> u16 {
        self.next_at(current, resources, operator_ceiling, Instant::now())
    }

    fn next_at(
        &mut self,
        current: &WifiMeshSnapshot,
        resources: Option<ResourceHeadroom>,
        operator_ceiling: u16,
        now: Instant,
    ) -> u16 {
        let population = current.peers.len(); // Includes pending peering, not just established links.
        self.update_probes(current);
        let last_probe = *self.last_probe.get_or_insert(now);
        let resource_room = resources.is_some_and(|headroom| {
            // Conservative reservations out of free RAM/FD headroom, not peer-count targets.
            !headroom.pressured
                && headroom.memory_bytes / 32 / (1024 * 1024) > 0
                && headroom.available_fds / 4 / 4 > 0
        });
        let measured_room = self.previous.as_ref().is_some_and(|previous| {
            survey_has_room(previous.survey.as_ref(), current.survey.as_ref())
                && stable_progress(previous, current)
        });
        let unknown_survey = current.survey.is_none()
            || self.previous.as_ref().is_some_and(|previous| {
                match (&previous.survey, &current.survey) {
                    (Some(before), Some(after)) => after.active_ms <= before.active_ms,
                    _ => true,
                }
            });
        let exploration_due = now.saturating_duration_since(last_probe) >= Duration::from_secs(30);
        let progressed = self
            .previous
            .as_ref()
            .is_some_and(|previous| stable_progress(previous, current));
        // No survey does not mean free airtime. Allow a slow, one-at-a-time exploratory probe,
        // then require that new station to carry actual bytes before considering another.
        // Once only, bypass a silent initial acquaintance so it cannot prevent discovery forever.
        let initial_discovery = population == 1 && !self.discovery_probe_used;
        let exploratory_room =
            unknown_survey && exploration_due && (progressed || initial_discovery);
        let outstanding_probe = unknown_survey
            && !exploration_due
            && usize::try_from(current.maximum_peers).ok() == population.checked_add(1);
        let radio_room = population == 0
            || (self.unproven.is_empty()
                && (measured_room || exploratory_room || outstanding_probe));
        let proposed = population.saturating_add(usize::from(resource_room && radio_room));
        let ceiling = if operator_ceiling == 0 {
            MAX_WIFI_MESH_OBSERVATIONS
        } else {
            usize::from(operator_ceiling).min(MAX_WIFI_MESH_OBSERVATIONS)
        };
        // Lowering admission must not become a command to remove existing peers under pressure.
        let next = proposed
            .min(ceiling)
            .max(population)
            .min(MAX_WIFI_MESH_OBSERVATIONS);
        if next > population
            && usize::try_from(current.maximum_peers).unwrap_or(usize::MAX) <= population
        {
            self.last_probe = Some(now);
            self.discovery_probe_used |= exploratory_room && initial_discovery && !progressed;
        }
        self.previous = Some(current.clone());
        u16::try_from(next).expect("bounded station observation count")
    }

    fn update_probes(&mut self, current: &WifiMeshSnapshot) {
        let Some(previous) = &self.previous else {
            return;
        };
        self.unproven.retain(|address| {
            current.peers.iter().any(|peer| {
                &peer.address == address
                    && !previous
                        .peers
                        .iter()
                        .any(|prior| peer_progress(prior, peer))
            })
        });
        if current.peers.len() > 1 {
            for peer in &current.peers {
                if !previous
                    .peers
                    .iter()
                    .any(|prior| prior.address == peer.address)
                    && !self.unproven.contains(&peer.address)
                {
                    self.unproven.push(peer.address.clone());
                }
            }
        }
    }
}

fn peer_progress(
    before: &volparossa_routing::WifiMeshPeer,
    after: &volparossa_routing::WifiMeshPeer,
) -> bool {
    before.address == after.address
        && before.established
        && after.established
        && after.received_bytes >= before.received_bytes
        && after.transmitted_bytes >= before.transmitted_bytes
        && (after.received_bytes > before.received_bytes
            || after.transmitted_bytes > before.transmitted_bytes)
}

fn survey_has_room(before: Option<&WifiMeshSurvey>, after: Option<&WifiMeshSurvey>) -> bool {
    let (Some(before), Some(after)) = (before, after) else {
        return false;
    };
    let Some(active) = after.active_ms.checked_sub(before.active_ms) else {
        return false;
    };
    let Some(busy) = after.busy_ms.checked_sub(before.busy_ms) else {
        return false;
    };
    // At least one second of actual channel observation and 20% unoccupied airtime for a probe.
    // This is an admission margin, not a prediction of bandwidth or a no-interference guarantee.
    active >= 1000 && busy <= active && u128::from(busy) * 5 <= u128::from(active) * 4
}

fn stable_progress(before: &WifiMeshSnapshot, after: &WifiMeshSnapshot) -> bool {
    let mut progressed = false;
    for peer in &after.peers {
        let Some(prior) = before
            .peers
            .iter()
            .find(|prior| prior.address == peer.address)
        else {
            return false;
        };
        if !peer.established
            || !prior.established
            || peer.received_bytes < prior.received_bytes
            || peer.transmitted_bytes < prior.transmitted_bytes
        {
            return false;
        }
        progressed |= peer.received_bytes > prior.received_bytes
            || peer.transmitted_bytes > prior.transmitted_bytes;
    }
    progressed
}

#[cfg(test)]
mod tests {
    use super::*;
    use volparossa_routing::WifiMeshPeer;

    fn resources(pressured: bool) -> ResourceHeadroom {
        ResourceHeadroom {
            memory_bytes: 1024 * 1024 * 1024,
            available_fds: 1024,
            pressured,
        }
    }

    fn sample(peers: u8, tick: u64, busy_percent: u64) -> WifiMeshSnapshot {
        WifiMeshSnapshot {
            peers: (0..peers)
                .map(|index| WifiMeshPeer {
                    address: vec![2, 0, 0, 0, 0, index],
                    established: true,
                    received_bytes: tick * 100,
                    transmitted_bytes: tick * 200,
                    ..WifiMeshPeer::default()
                })
                .collect(),
            survey: Some(WifiMeshSurvey {
                active_ms: tick * 5000,
                busy_ms: tick * 50 * busy_percent,
            }),
            ..WifiMeshSnapshot::default()
        }
    }

    #[test]
    fn wifi_mesh_admission_requires_radio_progress_and_preserves_existing_peers() {
        let mut admission = Admission::default();
        assert_eq!(admission.next(&sample(0, 0, 30), None, 0), 0);
        assert_eq!(
            admission.next(&sample(0, 1, 30), Some(resources(false)), 0),
            1
        );
        assert_eq!(
            admission.next(&sample(1, 2, 30), Some(resources(false)), 0),
            1
        );
        assert_eq!(
            admission.next(&sample(1, 3, 30), Some(resources(false)), 0),
            2
        );
        // One reserved probe, not another slot on every monitor tick with no arrival.
        assert_eq!(
            admission.next(&sample(1, 4, 30), Some(resources(false)), 0),
            2
        );
        let mut unknown = sample(1, 5, 30);
        unknown.survey = None;
        assert_eq!(admission.next(&unknown, Some(resources(false)), 0), 1);
        assert_eq!(
            admission.next(&sample(1, 6, 90), Some(resources(false)), 0),
            1
        );
        assert_eq!(
            admission.next(&sample(1, 7, 90), Some(resources(false)), 0),
            1
        );
        // Real observed populations above the former 8/32 targets remain valid.
        admission.next(&sample(33, 8, 30), Some(resources(false)), 0);
        assert_eq!(
            admission.next(&sample(33, 9, 30), Some(resources(false)), 0),
            34
        );
        assert_eq!(
            admission.next(&sample(33, 10, 30), Some(resources(true)), 0),
            33
        );
        assert_eq!(admission.next(&sample(33, 11, 30), None, 8), 33);
        assert_eq!(
            admission.next(&sample(33, 12, 30), Some(resources(false)), 33),
            33
        );
        assert_eq!(
            admission.next(&sample(33, 0, 30), Some(resources(false)), 0),
            33
        );
    }

    #[test]
    fn wifi_mesh_admission_unknown_radio_probes_slowly_without_a_fixed_neighbor_target() {
        let mut admission = Admission::default();
        let start = Instant::now();
        let mut current = sample(1, 0, 0);
        current.survey = None;
        current.maximum_peers = 1;
        assert_eq!(
            admission.next_at(&current, Some(resources(false)), 0, start),
            1
        );
        assert_eq!(
            admission.next_at(
                &current,
                Some(resources(false)),
                0,
                start + Duration::from_secs(29)
            ),
            1
        );
        assert_eq!(
            admission.next_at(
                &current,
                Some(resources(false)),
                0,
                start + Duration::from_secs(30)
            ),
            2
        );
        current.peers.push(sample(2, 0, 0).peers.pop().unwrap());
        current.maximum_peers = 2;
        assert_eq!(
            admission.next_at(
                &current,
                Some(resources(false)),
                0,
                start + Duration::from_secs(60)
            ),
            2
        );
        assert_eq!(
            admission.next_at(
                &current,
                Some(resources(false)),
                0,
                start + Duration::from_secs(90)
            ),
            2
        );
        // Useful new station permits the next probe despite the unavailable survey.
        current.peers[1].received_bytes = 100;
        assert_eq!(
            admission.next_at(
                &current,
                Some(resources(false)),
                0,
                start + Duration::from_secs(95)
            ),
            3
        );
        current.maximum_peers = 3;
        current.peers[1].received_bytes = 200;
        assert_eq!(
            admission.next_at(
                &current,
                Some(resources(false)),
                0,
                start + Duration::from_secs(100)
            ),
            3
        );
    }
}
