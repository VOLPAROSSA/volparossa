//! One route-owned, additional failover probe using per-flow kernel TCP observations.
//!
//! Initial endpoints are never retired here: they are shared by other accepted flows. Kernel
//! scheduling/reinjection remains authoritative. ACK octets are transport evidence, not goodput.

use std::{
    collections::BTreeMap,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use tokio::time::Instant;
use volparossa_mptcp::MptcpSubflowInfo;
use volparossa_wireguard::overlay_addresses;

use super::{MAXIMUM_CONCURRENT_MPTCP_FLOWS, observed::FlowObserver};

const SUSTAINED_LOSS: Duration = Duration::from_secs(2);
const PROBE_GRACE: Duration = Duration::from_secs(10);
const STALLED: Duration = Duration::from_secs(3);

pub(crate) struct PathScope {
    tuples: BTreeMap<u32, (Ipv6Addr, Ipv6Addr)>,
    initial: Vec<u32>,
    port: u16,
}

impl PathScope {
    pub(crate) fn new(context: [u8; 16], port: u16, selected: &[u32], initial: &[u32]) -> Self {
        let tuples = selected
            .iter()
            .map(|id| {
                let addresses =
                    overlay_addresses(context, u8::try_from(*id).expect("verified path ID"))
                        .expect("verified route overlay");
                (*id, (addresses.exit, addresses.client))
            })
            .collect();
        Self {
            tuples,
            initial: initial.to_vec(),
            port,
        }
    }

    fn bind(&self, samples: &[MptcpSubflowInfo]) -> Option<BTreeMap<u32, MptcpSubflowInfo>> {
        let mut result = BTreeMap::new();
        for sample in samples {
            let (path, _) = self.tuples.iter().find(|(_, (local, remote))| {
                sample.local == SocketAddr::new(IpAddr::V6(*local), self.port)
                    && sample.remote == SocketAddr::new(IpAddr::V6(*remote), sample.remote.port())
                    && sample.remote.port() != 0
            })?;
            // More than one lifetime on one selected path is not extra route diversity.
            if result.insert(*path, *sample).is_some() {
                return None;
            }
        }
        Some(result)
    }
}

#[derive(Clone, Copy)]
struct Previous {
    sample: MptcpSubflowInfo,
    last_progress: Instant,
}

#[derive(Clone, Copy, Default)]
struct Window {
    progressed: bool,
    lossy: bool,
    stalled: bool,
}

#[derive(Default)]
struct FlowHistory {
    previous: BTreeMap<u32, Previous>,
    candidate: Option<(u32, Instant)>,
}

impl FlowHistory {
    fn observe(
        &mut self,
        samples: &[MptcpSubflowInfo],
        scope: &PathScope,
        now: Instant,
    ) -> BTreeMap<u32, Window> {
        let Some(bound) = scope.bind(samples) else {
            self.previous.clear();
            self.candidate = None;
            return BTreeMap::new();
        };
        let mut windows = BTreeMap::new();
        let mut next = BTreeMap::new();
        for (path, sample) in bound {
            let old = self.previous.get(&path).filter(|old| {
                old.sample.subflow_id == sample.subflow_id
                    && old.sample.local == sample.local
                    && old.sample.remote == sample.remote
                    && old.sample.bytes_acked <= sample.bytes_acked
                    && old.sample.bytes_received <= sample.bytes_received
                    && old.sample.total_retransmissions <= sample.total_retransmissions
                    && old.sample.data_segments_sent <= sample.data_segments_sent
            });
            let progressed = sample.tcp_state == 1
                && old.is_some_and(|old| sample.bytes_acked > old.sample.bytes_acked);
            let last_progress = old
                .filter(|_| !progressed)
                .map_or(now, |old| old.last_progress);
            let lossy = old.is_some_and(|old| {
                let sent = sample.data_segments_sent - old.sample.data_segments_sent;
                let retransmitted = sample.total_retransmissions - old.sample.total_retransmissions;
                // Actual TCP retransmit/data-segment deltas, not tcpi_lost (a non-monotone gauge)
                // or an invented packet count from bytes/MSS. A 10% interval is a failover signal.
                sent > 0 && u64::from(retransmitted) * 10 >= u64::from(sent)
            });
            windows.insert(
                path,
                Window {
                    progressed,
                    lossy,
                    stalled: now.duration_since(last_progress) >= STALLED,
                },
            );
            next.insert(
                path,
                Previous {
                    sample,
                    last_progress,
                },
            );
        }
        self.previous = next;
        windows
    }

    fn candidate(
        &mut self,
        windows: &BTreeMap<u32, Window>,
        initial: &[u32],
        now: Instant,
    ) -> Option<u32> {
        let risky = initial
            .iter()
            .copied()
            .find(|path| windows.get(path).is_some_and(|window| window.lossy));
        let ready = initial.len() >= 2
            && risky.is_some()
            && initial.iter().all(|path| {
                windows.get(path).is_some_and(|window| {
                    window.progressed && (Some(*path) == risky || !window.lossy)
                })
            });
        if !ready {
            self.candidate = None;
            return None;
        }
        let risky = risky.expect("checked risky path");
        match self.candidate {
            Some((previous, since)) if previous == risky => {
                (now.duration_since(since) >= SUSTAINED_LOSS).then_some(risky)
            }
            _ => {
                self.candidate = Some((risky, now));
                None
            }
        }
    }
}

struct Flow {
    observer: FlowObserver,
    history: FlowHistory,
}

struct Probe {
    added: u32,
    risky: u32,
    last_useful: Instant,
}

#[derive(Debug, Eq, PartialEq)]
pub(super) enum Decision {
    Hold,
    Activate { warm: u32, risky: u32 },
    RetireExtra(u32),
}

pub(super) struct WarmGrowth {
    scope: PathScope,
    flows: Vec<Flow>,
    probe: Option<Probe>,
}

impl WarmGrowth {
    pub(super) fn new(scope: PathScope) -> Self {
        Self {
            scope,
            flows: Vec::new(),
            probe: None,
        }
    }

    pub(super) fn register(&mut self, observer: FlowObserver) {
        self.flows.retain(|flow| flow.observer.is_live());
        if self.flows.len() >= MAXIMUM_CONCURRENT_MPTCP_FLOWS {
            // The flow admission cap is the observer allocation cap too; never accumulate
            // completed fast flows or let telemetry create a second unbounded registry.
            return;
        }
        self.flows.push(Flow {
            observer,
            history: FlowHistory::default(),
        });
    }

    pub(super) fn observe(&mut self, warm: Option<u32>, now: Instant) -> Decision {
        let mut candidate = None;
        let mut useful = false;
        let mut safe_to_retire = true;
        self.flows.retain_mut(|flow| {
            let samples = match flow.observer.observe(self.scope.tuples.len()) {
                Ok(Some(samples)) => samples,
                Ok(None) => return false,
                Err(_) => {
                    // Missing/unsupported/ambiguous observation grants no growth authority and
                    // does not abort an otherwise independently authorized, working flow.
                    flow.history = FlowHistory::default();
                    safe_to_retire = false;
                    return true;
                }
            };
            let windows = flow.history.observe(&samples, &self.scope, now);
            safe_to_retire &= self.scope.initial.iter().all(|path| {
                flow.history
                    .previous
                    .get(path)
                    .is_some_and(|old| old.sample.tcp_state == 1)
            });
            if let Some(probe) = &self.probe {
                useful |= probe_useful(probe, &windows, &self.scope.initial);
            } else {
                candidate = candidate
                    .or_else(|| flow.history.candidate(&windows, &self.scope.initial, now));
            }
            true
        });
        self.decide(warm, candidate, useful, safe_to_retire, now)
    }

    fn decide(
        &mut self,
        warm: Option<u32>,
        candidate: Option<u32>,
        useful: bool,
        safe_to_retire: bool,
        now: Instant,
    ) -> Decision {
        if let Some(probe) = &mut self.probe {
            if useful {
                probe.last_useful = now;
            }
            if safe_to_retire && now.duration_since(probe.last_useful) >= PROBE_GRACE {
                return Decision::RetireExtra(probe.added);
            }
        } else if let (Some(risky), Some(warm)) = (candidate, warm) {
            return Decision::Activate { warm, risky };
        }
        Decision::Hold
    }

    pub(super) fn activated(&mut self, added: u32, risky: u32, now: Instant) {
        self.probe = Some(Probe {
            added,
            risky,
            last_useful: now,
        });
        for flow in &mut self.flows {
            flow.history.candidate = None;
        }
    }

    pub(super) fn retired(&mut self) {
        self.probe = None;
        for flow in &mut self.flows {
            flow.history.candidate = None;
        }
    }
}

fn probe_useful(probe: &Probe, windows: &BTreeMap<u32, Window>, initial: &[u32]) -> bool {
    windows
        .get(&probe.added)
        .is_some_and(|added| added.progressed && !added.lossy)
        && windows
            .get(&probe.risky)
            .is_none_or(|risky| risky.lossy || risky.stalled)
        && initial
            .iter()
            .filter(|path| **path != probe.risky)
            .all(|path| {
                windows
                    .get(path)
                    .is_some_and(|window| window.progressed && !window.lossy)
            })
}

#[cfg(test)]
mod tests;
