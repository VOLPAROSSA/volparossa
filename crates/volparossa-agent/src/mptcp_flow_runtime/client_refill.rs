//! Route-local refill demand from weak observations of actual authenticated Client sockets.
//!
//! This is demand, not authority: discovery, signed reservations and helper ownership still
//! authorize every new path. Only a bounded helper command temporarily pins a live descriptor;
//! no observation keeps an application alive between maintenance ticks.

use std::{
    collections::{BTreeMap, BTreeSet},
    io,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    sync::{Arc, Mutex},
    time::Duration,
};

use tokio::time::Instant;
use volparossa_mptcp::MptcpSubflowInfo;
use volparossa_tcp_proxy::Tls13MptcpStream;
use volparossa_wireguard::overlay_addresses;

use super::{
    MAXIMUM_CONCURRENT_MPTCP_FLOWS,
    observed::{FlowObserver, ObservationSlot, ObservedTls},
};

const MAXIMUM_PATHS: usize = 8;
const STALLED: Duration = Duration::from_secs(3);
const SUSTAINED_DEGRADATION: Duration = Duration::from_secs(2);
const WARM_GRACE: Duration = Duration::from_secs(10);
const ATTEMPT_COOLDOWN: Duration = Duration::from_secs(30);

#[derive(Clone)]
pub(crate) struct ClientRefillObservations(Arc<Mutex<State>>);

struct Scope {
    context: [u8; 16],
    port: u16,
    // Client local first, Exit remote second: the inverse of the Exit growth observer.
    tuples: BTreeMap<u32, (Ipv6Addr, Ipv6Addr)>,
    initial: Vec<u32>,
}

impl Scope {
    fn new(context: [u8; 16], port: u16, selected: &[u32], initial: &[u32]) -> Self {
        let tuples = selected
            .iter()
            .map(|path| {
                let addresses =
                    overlay_addresses(context, u8::try_from(*path).expect("verified path ID"))
                        .expect("verified route overlay");
                (*path, (addresses.client, addresses.exit))
            })
            .collect();
        Self {
            context,
            port,
            tuples,
            initial: initial.to_vec(),
        }
    }

    fn bind(&self, samples: &[MptcpSubflowInfo]) -> Option<BTreeMap<u32, MptcpSubflowInfo>> {
        if samples.is_empty() || samples.len() > self.tuples.len() || samples.len() > MAXIMUM_PATHS
        {
            return None;
        }
        let mut result = BTreeMap::new();
        for sample in samples {
            let (path, _) = self.tuples.iter().find(|(_, (local, remote))| {
                sample.local.ip() == IpAddr::V6(*local)
                    && sample.local.port() != 0
                    && sample.remote == SocketAddr::new(IpAddr::V6(*remote), self.port)
            })?;
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
    first_seen: Instant,
    last_progress: Option<Instant>,
}

#[derive(Default)]
struct History {
    // Missing previously observed paths remain here, bounded by the signed selected set.
    previous: BTreeMap<u32, Previous>,
    candidate: Option<(u32, Instant)>,
}

impl History {
    /// Nominate a presently progressing, non-lossy sibling from this exact flow, not just
    /// a boolean demand. An advertised but stalled original path cannot serve as the second
    /// path of the fresh two-path native measurement.
    fn demand(&mut self, samples: &[MptcpSubflowInfo], scope: &Scope, now: Instant) -> Option<u32> {
        let Some(bound) = scope.bind(samples) else {
            *self = Self::default();
            return None;
        };
        let mut progressing = Vec::new();
        let mut lossy = Vec::new();
        for (path, sample) in &bound {
            let old = self.previous.get(path).filter(|old| {
                old.sample.subflow_id == sample.subflow_id
                    && old.sample.local == sample.local
                    && old.sample.remote == sample.remote
                    && old.sample.bytes_acked <= sample.bytes_acked
                    && old.sample.bytes_received <= sample.bytes_received
                    && old.sample.total_retransmissions <= sample.total_retransmissions
                    && old.sample.data_segments_sent <= sample.data_segments_sent
            });
            let progressed = sample.tcp_state == 1
                && old.is_some_and(|old| {
                    sample.bytes_acked > old.sample.bytes_acked
                        || sample.bytes_received > old.sample.bytes_received
                });
            if progressed {
                progressing.push(*path);
            }
            // These are local sender retransmissions. For a download they are NOT evidence
            // of remote sender loss; failed/missing/stalled productive subflows are observed
            // separately below, without inventing receiver retransmission counters.
            if old.is_some_and(|old| {
                let sent = sample.data_segments_sent - old.sample.data_segments_sent;
                let retrans = sample.total_retransmissions - old.sample.total_retransmissions;
                sent > 0 && u64::from(retrans) * 10 >= u64::from(sent)
            }) {
                lossy.push(*path);
            }
            let first_seen = old.map_or(now, |old| old.first_seen);
            let last_progress = if progressed {
                Some(now)
            } else {
                old.and_then(|old| old.last_progress)
            };
            self.previous.insert(
                *path,
                Previous {
                    sample: *sample,
                    first_seen,
                    last_progress,
                },
            );
        }
        // Never combine different flows' samples. Every initial path must have actually
        // carried bytes on this same metaconnection before any degradation can demand refill.
        let primed = scope.initial.len() >= 2
            && scope.initial.iter().all(|path| {
                self.previous
                    .get(path)
                    .is_some_and(|old| old.last_progress.is_some())
            });
        let risky = scope.initial.iter().copied().find(|path| {
            self.previous.get(path).is_some_and(|old| {
                lossy.contains(path)
                    || (old.last_progress.is_some()
                        && (bound.get(path).is_none_or(|sample| sample.tcp_state != 1)
                            || now.duration_since(old.last_progress.expect("checked progress"))
                                >= STALLED))
            })
        });
        // No refill on an idle connection: another selected path must be carrying bytes now.
        // Retain that same path identity through nomination instead of later selecting an
        // unrelated first entry in the reservation's original Relay ordering.
        let buddy = risky.filter(|_| primed).and_then(|risky| {
            progressing
                .iter()
                .copied()
                .find(|path| *path != risky && !lossy.contains(path))
        });
        if buddy.is_none() {
            self.candidate = None;
            return None;
        }
        let risky = risky.expect("checked risky path");
        let since = match self.candidate {
            Some((previous, since)) if previous == risky => since,
            _ => {
                self.candidate = Some((risky, now));
                now
            }
        };
        // A never-observed dormant path is not exhausted. Give every preselected or freshly
        // added warm path its real trial; useful warm traffic suppresses further additions.
        let warm_unhelpful = scope
            .tuples
            .keys()
            .filter(|path| !scope.initial.contains(path))
            .all(|path| {
                self.previous.get(path).is_some_and(|old| {
                    !progressing.contains(path)
                        && now.duration_since(old.last_progress.unwrap_or(old.first_seen))
                            >= WARM_GRACE
                })
            });
        if warm_unhelpful && now.duration_since(since) >= SUSTAINED_DEGRADATION {
            buddy
        } else {
            None
        }
    }
}

struct Flow {
    observer: FlowObserver,
    history: History,
    handle: [u8; 32],
    applied: BTreeSet<u32>,
}

struct State {
    scope: Scope,
    flows: Vec<Flow>,
    last_attempt: Option<Instant>,
    path_snapshot: Option<volparossa_protocol::MptcpPathsState>,
}

impl State {
    fn admit_attempt(&mut self, demand: bool, now: Instant) -> bool {
        if !demand
            || self.scope.tuples.len() >= MAXIMUM_PATHS
            || self
                .last_attempt
                .is_some_and(|last| now.duration_since(last) < ATTEMPT_COOLDOWN)
        {
            return false;
        }
        // Charge failed or empty discovery attempts too, not only successful installations.
        self.last_attempt = Some(now);
        true
    }
}

impl ClientRefillObservations {
    pub(crate) fn new(context: [u8; 16], port: u16, selected: &[u32], initial: &[u32]) -> Self {
        Self(Arc::new(Mutex::new(State {
            scope: Scope::new(context, port, selected, initial),
            flows: Vec::new(),
            last_attempt: None,
            path_snapshot: None,
        })))
    }

    pub(crate) fn attach(
        &self,
        stream: Tls13MptcpStream,
        handle: [u8; 32],
    ) -> io::Result<ObservedTls> {
        let (slot, observer) = ObservationSlot::new();
        let stream = slot.attach_owned(stream)?;
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("MPTCP refill observer poisoned"))?;
        state.flows.retain(|flow| flow.observer.is_live());
        if state.flows.len() < MAXIMUM_CONCURRENT_MPTCP_FLOWS {
            let applied = state.scope.initial.iter().copied().collect();
            state.flows.push(Flow {
                observer,
                history: History::default(),
                handle,
                applied,
            });
        }
        // Telemetry admission must not abort an independently authorized flow. Over-cap flows
        // keep functioning but supply no refill evidence; no unbounded observer is allocated.
        Ok(stream)
    }

    /// Reconcile only authenticated Exit endpoint state against the locally committed path set.
    /// At most eight owner-bound commands are issued per tick; the socket observation is weak.
    pub(crate) async fn reconcile(
        &self,
        helper: &crate::helper::HelperClient,
        context_handle: &[u8],
        snapshot: &volparossa_protocol::MptcpPathsState,
    ) -> io::Result<()> {
        {
            let mut state = self
                .0
                .lock()
                .map_err(|_| io::Error::other("MPTCP observer poisoned"))?;
            if !valid_path_state(&state.scope, state.path_snapshot.as_ref(), snapshot) {
                return Err(io::Error::other("MPTCP authenticated path state conflicts"));
            }
            state.path_snapshot = Some(snapshot.clone());
        }
        for _ in 0..MAXIMUM_PATHS {
            let command = {
                let mut state = self
                    .0
                    .lock()
                    .map_err(|_| io::Error::other("MPTCP observer poisoned"))?;
                state.flows.retain(|flow| flow.observer.is_live());
                let mut next = None;
                for flow in &state.flows {
                    let retirement = snapshot
                        .retired_path_ids
                        .iter()
                        .find(|path| flow.applied.contains(path))
                        .copied();
                    let addition = snapshot
                        .active_path_ids
                        .iter()
                        .find(|path| !flow.applied.contains(path))
                        .copied();
                    let Some((path, action)) = retirement
                        .map(|id| (id, volparossa_routing::MptcpSubflowAction::Retire))
                        .or_else(|| {
                            addition.map(|id| (id, volparossa_routing::MptcpSubflowAction::Ensure))
                        })
                    else {
                        continue;
                    };
                    if let Some(descriptor) = flow.observer.pin_descriptor()? {
                        next = Some((flow.handle, path, action, descriptor));
                        break;
                    }
                }
                next
            };
            let Some((handle, path, action, descriptor)) = command else {
                break;
            };
            let result = helper
                .update_mptcp_subflow(
                    volparossa_routing::UpdateMptcpSubflow {
                        route_context_id: snapshot.route_context_id.clone(),
                        context_handle: context_handle.to_vec(),
                        mptcp_flow_handle: handle.to_vec(),
                        path_id: path,
                        action: action as i32,
                    },
                    descriptor,
                )
                .await;
            let mut state = self
                .0
                .lock()
                .map_err(|_| io::Error::other("MPTCP observer poisoned"))?;
            if let Some(flow) = state.flows.iter_mut().find(|flow| flow.handle == handle) {
                if !flow.observer.is_live() {
                    continue;
                }
                result.map_err(|_| io::Error::other("MPTCP owned path command failed"))?;
                match action {
                    volparossa_routing::MptcpSubflowAction::Ensure => {
                        flow.applied.insert(path);
                    }
                    volparossa_routing::MptcpSubflowAction::Retire => {
                        flow.applied.remove(&path);
                    }
                    volparossa_routing::MptcpSubflowAction::Unspecified => {
                        unreachable!("closed local action")
                    }
                }
            }
        }
        Ok(())
    }

    pub(crate) fn extend(&self, selected: &[u32]) -> io::Result<()> {
        let mut state = self
            .0
            .lock()
            .map_err(|_| io::Error::other("MPTCP refill observer poisoned"))?;
        if !(state.scope.tuples.len()..=state.scope.tuples.len() + 1).contains(&selected.len())
            || selected.len() > MAXIMUM_PATHS
            || !state
                .scope
                .tuples
                .keys()
                .all(|path| selected.contains(path))
        {
            return Err(io::Error::other(
                "MPTCP refill selection changed existing paths",
            ));
        }
        state.scope = Scope::new(
            state.scope.context,
            state.scope.port,
            selected,
            &state.scope.initial,
        );
        Ok(())
    }

    pub(crate) fn refill_sample_path(&self, now: Instant) -> Option<u32> {
        let mut state = self.0.lock().ok()?;
        let State { scope, flows, .. } = &mut *state;
        let mut buddy = None;
        flows.retain_mut(|flow| {
            match flow.observer.observe(scope.tuples.len().min(MAXIMUM_PATHS)) {
                Ok(Some(samples)) => {
                    let observed = flow.history.demand(&samples, scope, now);
                    buddy = buddy.or(observed);
                }
                Ok(None) => return false,
                Err(_) => flow.history = History::default(),
            }
            true
        });
        if state.admit_attempt(buddy.is_some(), now) {
            buddy
        } else {
            None
        }
    }
}

fn valid_path_state(
    scope: &Scope,
    previous: Option<&volparossa_protocol::MptcpPathsState>,
    next: &volparossa_protocol::MptcpPathsState,
) -> bool {
    use volparossa_protocol::ControlPayload as _;
    if next.validate().is_err()
        || next.route_context_id.as_slice() != scope.context
        || !scope
            .initial
            .iter()
            .all(|id| next.active_path_ids.contains(id))
        || next
            .active_path_ids
            .iter()
            .chain(&next.retired_path_ids)
            .any(|id| !scope.tuples.contains_key(id))
    {
        return false;
    }
    previous.is_none_or(|old| {
        next.revision >= old.revision
            && old
                .retired_path_ids
                .iter()
                .all(|id| next.retired_path_ids.contains(id))
            && old
                .active_path_ids
                .iter()
                .all(|id| next.active_path_ids.contains(id) || next.retired_path_ids.contains(id))
            && (next.revision != old.revision
                || (next.active_path_ids == old.active_path_ids
                    && next.retired_path_ids == old.retired_path_ids))
    })
}

#[cfg(test)]
mod tests;
