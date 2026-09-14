//! Local, measured width changes. These signals never authorize content or a network route.

use std::collections::BTreeSet;

use tokio::time::Instant;

use super::{ParallelDownload, Work};

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum PeerState {
    Dormant,
    Active,
    Finishing,
    Finished,
}

pub(super) struct Measurement {
    started: Instant,
    bytes: u64,
    contributors: BTreeSet<usize>,
}

impl Measurement {
    pub(super) fn new() -> Self {
        Self {
            started: Instant::now(),
            bytes: 0,
            contributors: BTreeSet::new(),
        }
    }

    fn rate(&self) -> u64 {
        let micros = self.started.elapsed().as_micros().max(1);
        u64::try_from(u128::from(self.bytes) * 1_000_000 / micros).unwrap_or(u64::MAX)
    }
}

impl ParallelDownload {
    pub(super) fn adjust_width(&mut self, allowance: usize) {
        for peer in &mut self.peers {
            if peer.state == PeerState::Finishing && peer.results.is_closed() {
                peer.state = PeerState::Finished;
            }
        }
        // An exhausted peer cannot help even if another owner's current request later fails.
        // Merely idle peers with an unattempted, in-flight chunk remain eligible for that case.
        for index in 0..self.peers.len() {
            if self.peers[index].state == PeerState::Active
                && self.peers[index].pending.is_none()
                && !self.eligible(index)
            {
                self.finish_peer(index);
            }
        }
        let mut active = self
            .peers
            .iter()
            .filter(|peer| peer.state == PeerState::Active)
            .count();
        for index in (0..self.peers.len()).rev() {
            if active <= allowance {
                break;
            }
            if self.peers[index].state == PeerState::Active && self.peers[index].pending.is_none() {
                self.finish_peer(index);
                active -= 1;
            }
        }
        active = self.active_count();
        if active >= allowance || !self.chunks.iter().any(|c| !c.complete && c.owner.is_none()) {
            return;
        }
        if active == 0 {
            // Sequential replacement still works with a one-stream resource budget.
            for _ in 0..allowance.min(2) {
                if !self.activate_next(false) {
                    break;
                }
            }
            self.explore = false;
            return;
        }
        let probing = self
            .peers
            .iter()
            .any(|p| p.state == PeerState::Active && p.probing);
        let measured = !self.growth_blocked && self.measured_batch();
        if !probing && (self.explore || measured) {
            let baseline = self.measured_batch().then(|| self.measurement.rate());
            if self.activate_next(true) {
                self.probe_baseline = baseline;
                self.measurement = Measurement::new();
                self.explore = false;
            }
        }
    }

    fn measured_batch(&self) -> bool {
        self.measurement.bytes > 0
            && self
                .peers
                .iter()
                .enumerate()
                .filter(|(_, peer)| peer.state == PeerState::Active)
                .all(|(index, _)| self.measurement.contributors.contains(&index))
    }

    fn finish_probe(&mut self, index: usize, beneficial: bool) {
        self.peers[index].probing = false;
        if !beneficial {
            self.finish_peer(index);
            self.growth_blocked = true;
        }
        self.probe_baseline = None;
        self.measurement = Measurement::new();
        if beneficial {
            self.explore = false;
        }
    }

    fn active_count(&self) -> usize {
        self.peers
            .iter()
            .filter(|peer| matches!(peer.state, PeerState::Active | PeerState::Finishing))
            .count()
    }

    fn eligible(&self, index: usize) -> bool {
        self.chunks
            .iter()
            .any(|chunk| !chunk.complete && !chunk.attempted.contains(&index))
    }

    fn activate_next(&mut self, probing: bool) -> bool {
        let next = (0..self.peers.len())
            .find(|&index| self.peers[index].state == PeerState::Dormant && self.eligible(index));
        let Some(index) = next else { return false };
        self.peers[index].state = PeerState::Active;
        self.peers[index].probing = probing;
        true
    }

    fn finish_peer(&mut self, index: usize) {
        debug_assert!(self.peers[index].pending.is_none());
        // The caller releases its socket lease before dropping the worker/result sender.
        // Do not lend that capacity to another assignment until closure is observable.
        self.peers[index].state = PeerState::Finishing;
        let _ = self.peers[index].requests.try_send(Work::Finish);
    }

    pub(super) fn record_sample(&mut self, index: usize, bytes: u64, extra_coverage: bool) {
        if !self.adaptive {
            return;
        }
        // Count only unique, verified cache insertions from the single writer. Wall time
        // includes setup, misses and every active peer, rather than adding overlapping rates.
        self.measurement.bytes = self.measurement.bytes.saturating_add(bytes);
        self.measurement.contributors.insert(index);
        if extra_coverage && self.peers[index].probing {
            self.finish_probe(index, true);
            return;
        }
        let probe = self
            .peers
            .iter()
            .position(|peer| peer.state == PeerState::Active && peer.probing);
        if let Some(probe) = probe {
            if self.measured_batch() && self.peers[probe].pending.is_none() {
                // A shared bottleneck can redistribute rates without adding total capacity.
                // Require an observed aggregate gain; an incomplete batch cannot justify
                // opening yet another stream. Genuine missing-chunk coverage is separate.
                let rate = self.measurement.rate();
                let gain = self.probe_baseline.is_some_and(|baseline| {
                    baseline > 0 && u128::from(rate) * 10 >= u128::from(baseline) * 11
                });
                self.finish_probe(probe, gain);
            }
        }
    }
}
