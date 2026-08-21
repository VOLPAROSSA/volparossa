//! In-memory privacy-safe service state exposed through local control.

use std::collections::{BTreeMap, HashSet, VecDeque};

use volparossa_config::{Config, RolesConfig};
use volparossa_local_control::{
    LogLevel, LogList, LogRecord, PathList, PathSummary, PeerList, PeerSummary, PolicySnapshot,
    RoleSnapshot, SessionList, SessionSummary, StatusSnapshot,
};
use volparossa_metrics::{MetricsError, MetricsRegistry};
use volparossa_policy::VerifiedManifest;
use volparossa_selection::RouteContextCache;

const MAX_LOG_RECORDS: usize = 1_000;

/// Mutable state owned by the agent. It contains no destination, DNS, URL,
/// payload, or durable node-to-browsing association.
#[derive(Debug)]
pub struct AgentState {
    roles: RolesConfig,
    policy: Option<VerifiedManifest>,
    route_contexts: RouteContextCache,
    connected_peers: HashSet<String>,
    peers: BTreeMap<String, PeerSummary>,
    paths: Vec<PathSummary>,
    sessions: Vec<SessionSummary>,
    logs: VecDeque<LogRecord>,
    candidate_pool: usize,
    mptcp_subflows: u32,
    mpquic_paths: u32,
    rejected_policy_requests: u64,
    metrics: MetricsRegistry,
}

impl AgentState {
    /// Creates bounded privacy-safe control and route state.
    pub fn new(
        config: &Config,
        roles: RolesConfig,
        policy: Option<VerifiedManifest>,
        metrics: MetricsRegistry,
    ) -> Result<Self, StateError> {
        let route_contexts = RouteContextCache::new(
            config.routing.maximum_active_contexts,
            config.routing.context_ttl_seconds,
        )?;
        let state = Self {
            roles,
            policy,
            route_contexts,
            connected_peers: HashSet::new(),
            peers: BTreeMap::new(),
            paths: Vec::new(),
            sessions: Vec::new(),
            logs: VecDeque::with_capacity(MAX_LOG_RECORDS),
            candidate_pool: 0,
            mptcp_subflows: 0,
            mpquic_paths: 0,
            rejected_policy_requests: 0,
            metrics,
        };
        state.sync_metrics();
        Ok(state)
    }

    /// Returns aggregate transport and discovery state without destinations.
    #[must_use]
    pub fn status(&self) -> StatusSnapshot {
        StatusSnapshot {
            connected: self.route_contexts.context_count() > 0
                && (!self.paths.is_empty() || !self.sessions.is_empty()),
            active_peers: bounded_u32(self.connected_peers.len()),
            candidate_pool: bounded_u32(self.candidate_pool),
            active_contexts: bounded_u32(self.route_contexts.context_count()),
            mptcp_subflows: self.mptcp_subflows,
            mpquic_paths: self.mpquic_paths,
        }
    }

    /// Current effective roles.
    #[must_use]
    pub const fn roles(&self) -> RolesConfig {
        self.roles
    }

    /// Returns the local-control representation of roles.
    #[must_use]
    pub fn role_snapshot(&self) -> RoleSnapshot {
        RoleSnapshot {
            client: self.roles.client,
            relay: self.roles.relay,
            exit: self.roles.exit,
        }
    }

    /// Replaces the active verified manifest after a complete trust check.
    pub fn set_policy(&mut self, policy: Option<VerifiedManifest>) {
        self.policy = policy;
    }

    /// True only while the verified manifest is active at the checked clock.
    #[must_use]
    pub fn policy_active(&self, now_ms: u64) -> bool {
        self.policy
            .as_ref()
            .is_some_and(|manifest| manifest.ensure_active_at(now_ms).is_ok())
    }

    /// Returns a clone of the threshold-verified manifest only while it is active.
    #[must_use]
    pub fn active_policy(&self, now_ms: u64) -> Option<VerifiedManifest> {
        self.policy.as_ref().and_then(|manifest| {
            manifest
                .ensure_active_at(now_ms)
                .ok()
                .map(|()| manifest.clone())
        })
    }

    /// Returns policy metadata, or an explicitly inactive empty snapshot.
    #[must_use]
    pub fn policy_snapshot(&self, now_ms: u64) -> PolicySnapshot {
        let Some(manifest) = self
            .policy
            .as_ref()
            .filter(|manifest| manifest.ensure_active_at(now_ms).is_ok())
        else {
            return PolicySnapshot {
                manifest_version: 0,
                policy_hash: Vec::new(),
                expires_at_ms: 0,
                verified_signatures: 0,
                active: false,
            };
        };
        PolicySnapshot {
            manifest_version: manifest.manifest_version(),
            policy_hash: manifest.policy_hash().to_vec(),
            expires_at_ms: manifest.expires_at_ms(),
            verified_signatures: bounded_u32(manifest.verified_signatures()),
            active: true,
        }
    }

    /// Counts a denied operation without retaining its destination.
    pub fn record_policy_rejection(&mut self) {
        self.rejected_policy_requests = self.rejected_policy_requests.saturating_add(1);
        self.metrics.record_policy_denial();
    }

    /// Marks one control-plane connection as established.
    pub fn peer_connected(&mut self, peer_id: String) {
        self.connected_peers.insert(peer_id);
        self.sync_metrics();
    }

    /// Removes one peer from the active connection set.
    pub fn peer_disconnected(&mut self, peer_id: &str) {
        self.connected_peers.remove(peer_id);
        self.sync_metrics();
    }

    /// Replaces the bounded candidate display from verified peerstore records.
    pub fn replace_candidates(&mut self, peers: Vec<PeerSummary>, usable_candidates: usize) {
        self.candidate_pool = usable_candidates.min(peers.len());
        self.peers = peers
            .into_iter()
            .map(|peer| (peer.peer_id.clone(), peer))
            .collect();
        self.sync_metrics();
    }

    /// Returns known public peer metadata.
    #[must_use]
    pub fn peer_list(&self) -> PeerList {
        PeerList {
            peers: self.peers.values().cloned().collect(),
        }
    }

    /// Returns only actually selected paths; currently empty until complete
    /// dataplane orchestration creates one.
    #[must_use]
    pub fn path_list(&self) -> PathList {
        PathList {
            paths: self.paths.clone(),
        }
    }

    /// Returns only actually established sessions.
    #[must_use]
    pub fn session_list(&self) -> SessionList {
        SessionList {
            sessions: self.sessions.clone(),
        }
    }

    /// Appends one bounded code-only record to the in-memory ring.
    pub fn log(&mut self, level: LogLevel, event_code: &'static str, now_ms: u64) {
        if self.logs.len() == MAX_LOG_RECORDS {
            self.logs.pop_front();
        }
        self.logs.push_back(LogRecord {
            timestamp_ms: now_ms,
            level: level as i32,
            event_code: event_code.to_owned(),
            session_id: Vec::new(),
            path_id: None,
        });
    }

    /// Returns the newest bounded window in chronological order.
    #[must_use]
    pub fn logs(&self, maximum: usize) -> LogList {
        let skip = self.logs.len().saturating_sub(maximum.min(MAX_LOG_RECORDS));
        LogList {
            records: self.logs.iter().skip(skip).cloned().collect(),
        }
    }

    /// Clears state only after the helper confirms network teardown.
    pub fn clear_after_helper_cleanup(&mut self, config: &Config) -> Result<(), StateError> {
        self.route_contexts = RouteContextCache::new(
            config.routing.maximum_active_contexts,
            config.routing.context_ttl_seconds,
        )?;
        self.paths.clear();
        self.sessions.clear();
        self.mptcp_subflows = 0;
        self.mpquic_paths = 0;
        self.sync_metrics();
        Ok(())
    }

    /// Whether this agent currently knows of helper-owned route state.
    #[must_use]
    pub fn has_network_state(&self) -> bool {
        self.route_contexts.context_count() > 0
            || !self.paths.is_empty()
            || !self.sessions.is_empty()
    }

    fn sync_metrics(&self) {
        update_metric(self.metrics.set_active_peers(self.connected_peers.len()));
        update_metric(self.metrics.set_candidate_pool(self.candidate_pool));
        update_metric(
            self.metrics
                .set_active_route_contexts(self.route_contexts.context_count()),
        );
        update_metric(
            self.metrics
                .set_mptcp_subflows(self.mptcp_subflows as usize),
        );
        update_metric(self.metrics.set_mpquic_paths(self.mpquic_paths as usize));
    }
}

fn update_metric(result: Result<(), MetricsError>) {
    if let Err(error) = result {
        tracing::warn!(
            diagnostic_code = "METRIC_BOUND_REJECTED",
            metric_error = %error,
            "aggregate metric rejected"
        );
    }
}

fn bounded_u32(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

/// Internal bounded-state construction failure.
#[derive(Debug, thiserror::Error)]
pub enum StateError {
    /// Route-context limits were invalid.
    #[error("route-context state limits are invalid")]
    Route(#[from] volparossa_selection::RouteContextError),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn aggregate_metrics_follow_state_without_identity_labels() {
        let config = Config::default();
        let registry = MetricsRegistry::new();
        let mut state =
            AgentState::new(&config, config.roles, None, registry.clone()).expect("state");

        state.peer_connected("transient-peer".to_owned());
        state.record_policy_rejection();
        let snapshot = registry.snapshot();
        assert_eq!(snapshot.active_peers, 1);
        assert_eq!(snapshot.policy_denials, 1);
        assert!(!registry.render().contains("transient-peer"));

        state.peer_disconnected("transient-peer");
        assert_eq!(registry.snapshot().active_peers, 0);
    }
}
