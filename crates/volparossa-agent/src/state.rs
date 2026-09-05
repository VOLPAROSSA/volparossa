//! In-memory privacy-safe service state exposed through local control.

use std::collections::{BTreeMap, HashSet, VecDeque};

use volparossa_config::{Config, RolesConfig};
use volparossa_local_control::{
    LogLevel, LogList, LogRecord, PathList, PathState, PathSummary, PeerList, PeerSummary,
    PolicySnapshot, RoleSnapshot, SessionList, SessionSummary, StatusSnapshot,
};
use volparossa_metrics::{MetricsError, MetricsRegistry};
use volparossa_policy::VerifiedManifest;
use volparossa_selection::RouteContextCache;

const MAX_LOG_RECORDS: usize = 1_000;
const MAX_MPQUIC_PATHS: usize = 8;
const ROUTE_CONTEXT_ID_BYTES: usize = 16;

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
    mpquic_context_id: Option<Vec<u8>>,
    single_udp_context_id: Option<Vec<u8>>,
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
            mpquic_context_id: None,
            single_udp_context_id: None,
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
        let active_contexts = self
            .route_contexts
            .context_count()
            .saturating_add(usize::from(self.mpquic_context_id.is_some()))
            .saturating_add(usize::from(self.single_udp_context_id.is_some()));
        StatusSnapshot {
            connected: active_contexts > 0 && (!self.paths.is_empty() || !self.sessions.is_empty()),
            active_peers: bounded_u32(self.connected_peers.len()),
            candidate_pool: bounded_u32(self.candidate_pool),
            active_contexts: bounded_u32(active_contexts),
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

    /// Replaces only the currently owned MPQUIC route projection.
    ///
    /// The summaries contain route and peer identity plus aggregate path counters only. They
    /// retain no destination or payload. Paths belonging to another transport context are left
    /// untouched.
    pub fn replace_mpquic_paths(&mut self, mut paths: Vec<PathSummary>) -> Result<(), StateError> {
        let context_id = validate_mpquic_paths(&paths)?.to_vec();
        if self.single_udp_context_id.as_ref() == Some(&context_id) {
            return Err(StateError::InvalidMpquicPaths);
        }
        if let Some(previous) = self.mpquic_context_id.as_ref() {
            self.paths
                .retain(|path| path.route_context_id.as_slice() != previous.as_slice());
        }
        self.paths
            .retain(|path| path.route_context_id.as_slice() != context_id.as_slice());
        paths.sort_unstable_by_key(|path| path.path_id);
        self.mpquic_paths = bounded_u32(
            paths
                .iter()
                .filter(|path| PathState::try_from(path.state).ok() == Some(PathState::Active))
                .count(),
        );
        self.paths.extend(paths);
        self.mpquic_context_id = Some(context_id);
        self.sync_metrics();
        Ok(())
    }

    /// Removes only the MPQUIC projection after its native and helper owners stop.
    pub fn clear_mpquic_paths(&mut self) {
        if let Some(context_id) = self.mpquic_context_id.take() {
            self.paths
                .retain(|path| path.route_context_id != context_id);
        }
        self.mpquic_paths = 0;
        self.sync_metrics();
    }

    /// Publishes one committed native general-UDP path without claiming it is multipath.
    pub fn replace_single_udp_path(&mut self, path: PathSummary) -> Result<(), StateError> {
        if path.route_context_id.len() != ROUTE_CONTEXT_ID_BYTES
            || path.route_context_id.iter().all(|byte| *byte == 0)
            || path.path_id == 0
            || usize::try_from(path.path_id).map_or(true, |id| id > MAX_MPQUIC_PATHS)
            || path.relay_peer_id.is_empty()
            || path.exit_peer_id.is_empty()
            || path.relay_peer_id == path.exit_peer_id
            || !matches!(
                PathState::try_from(path.state).ok(),
                Some(PathState::Reachable | PathState::Active)
            )
            || self.mpquic_context_id.as_ref() == Some(&path.route_context_id)
        {
            return Err(StateError::InvalidSingleUdpPath);
        }
        if let Some(previous) = self.single_udp_context_id.take() {
            self.paths.retain(|path| path.route_context_id != previous);
        }
        self.paths
            .retain(|existing| existing.route_context_id != path.route_context_id);
        self.single_udp_context_id = Some(path.route_context_id.clone());
        self.paths.push(path);
        self.sync_metrics();
        Ok(())
    }

    /// Removes only the general-UDP projection after its native and helper owners stop.
    pub fn clear_single_udp_path(&mut self) {
        if let Some(context_id) = self.single_udp_context_id.take() {
            self.paths
                .retain(|path| path.route_context_id != context_id);
        }
        self.sync_metrics();
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
        self.mpquic_context_id = None;
        self.single_udp_context_id = None;
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
            || self.mpquic_context_id.is_some()
            || self.single_udp_context_id.is_some()
            || !self.paths.is_empty()
            || !self.sessions.is_empty()
    }

    fn sync_metrics(&self) {
        update_metric(self.metrics.set_active_peers(self.connected_peers.len()));
        update_metric(self.metrics.set_candidate_pool(self.candidate_pool));
        update_metric(
            self.metrics
                .set_active_route_contexts(self.status().active_contexts as usize),
        );
        update_metric(
            self.metrics
                .set_mptcp_subflows(self.mptcp_subflows as usize),
        );
        update_metric(self.metrics.set_mpquic_paths(self.mpquic_paths as usize));
    }
}

fn validate_mpquic_paths(paths: &[PathSummary]) -> Result<&[u8], StateError> {
    if !(2..=MAX_MPQUIC_PATHS).contains(&paths.len()) {
        return Err(StateError::InvalidMpquicPaths);
    }
    let context_id = paths[0].route_context_id.as_slice();
    let exit_peer_id = paths[0].exit_peer_id.as_str();
    if context_id.len() != ROUTE_CONTEXT_ID_BYTES
        || context_id.iter().all(|byte| *byte == 0)
        || exit_peer_id.is_empty()
    {
        return Err(StateError::InvalidMpquicPaths);
    }
    let mut path_ids = HashSet::with_capacity(paths.len());
    let mut relay_peer_ids = HashSet::with_capacity(paths.len());
    for path in paths {
        if path.route_context_id.as_slice() != context_id
            || path.exit_peer_id != exit_peer_id
            || path.relay_peer_id.is_empty()
            || path.path_id == 0
            || usize::try_from(path.path_id).map_or(true, |id| id > MAX_MPQUIC_PATHS)
            || !path_ids.insert(path.path_id)
            || !relay_peer_ids.insert(path.relay_peer_id.as_str())
            || !matches!(
                PathState::try_from(path.state).ok(),
                Some(PathState::Reachable | PathState::Active | PathState::Backup)
            )
        {
            return Err(StateError::InvalidMpquicPaths);
        }
    }
    Ok(context_id)
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
    /// Native MPQUIC status did not describe one exact bounded route.
    #[error("native MPQUIC path state is invalid")]
    InvalidMpquicPaths,
    /// Native single-path UDP status did not describe one exact bounded route.
    #[error("native single-path UDP path state is invalid")]
    InvalidSingleUdpPath,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_agent_role_snapshot_is_dormant_and_disconnected() {
        let config = Config::default();
        let state = AgentState::new(&config, config.roles, None, MetricsRegistry::new())
            .expect("dormant state");
        let roles = state.role_snapshot();
        assert!(!roles.client && !roles.relay && !roles.exit);
        assert!(!state.status().connected);
        assert_eq!(state.status().active_contexts, 0);
    }

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

    fn path(context: u8, path_id: u32, relay: &str, state: PathState) -> PathSummary {
        PathSummary {
            route_context_id: vec![context; ROUTE_CONTEXT_ID_BYTES],
            path_id,
            relay_peer_id: relay.to_owned(),
            exit_peer_id: "exit-peer".to_owned(),
            state: state as i32,
            smoothed_rtt_micros: 1_000_u64.saturating_mul(u64::from(path_id)),
            user_bytes: 0,
        }
    }

    #[test]
    fn mpquic_projection_updates_status_metrics_and_clears_its_context_only() {
        let config = Config::default();
        let registry = MetricsRegistry::new();
        let mut state =
            AgentState::new(&config, config.roles, None, registry.clone()).expect("state");
        state
            .paths
            .push(path(9, 8, "mptcp-relay", PathState::Active));

        state
            .replace_mpquic_paths(vec![
                path(7, 2, "relay-two", PathState::Active),
                path(7, 1, "relay-one", PathState::Reachable),
            ])
            .expect("valid MPQUIC projection");

        let status = state.status();
        assert!(status.connected);
        assert_eq!(status.active_contexts, 1);
        assert_eq!(status.mpquic_paths, 1);
        assert_eq!(registry.snapshot().mpquic_paths, 1);
        assert_eq!(state.path_list().paths.len(), 3);

        state.clear_mpquic_paths();
        assert_eq!(
            state.path_list().paths,
            [path(9, 8, "mptcp-relay", PathState::Active)]
        );
        assert_eq!(state.status().mpquic_paths, 0);
        assert_eq!(registry.snapshot().mpquic_paths, 0);
    }

    #[test]
    fn invalid_mpquic_projection_does_not_replace_existing_state() {
        let config = Config::default();
        let mut state =
            AgentState::new(&config, config.roles, None, MetricsRegistry::new()).expect("state");
        state
            .replace_mpquic_paths(vec![
                path(7, 1, "relay-one", PathState::Reachable),
                path(7, 2, "relay-two", PathState::Active),
            ])
            .expect("initial projection");
        let before = state.path_list();
        let invalid = vec![
            path(8, 1, "same-relay", PathState::Active),
            path(8, 2, "same-relay", PathState::Active),
        ];

        assert!(matches!(
            state.replace_mpquic_paths(invalid),
            Err(StateError::InvalidMpquicPaths)
        ));
        assert_eq!(state.path_list(), before);
    }

    #[test]
    fn single_udp_projection_counts_its_context_without_claiming_multipath() {
        let config = Config::default();
        let registry = MetricsRegistry::new();
        let mut state =
            AgentState::new(&config, config.roles, None, registry.clone()).expect("state");
        state
            .replace_single_udp_path(path(3, 1, "udp-relay", PathState::Active))
            .expect("UDP path");
        assert!(state.status().connected);
        assert_eq!(state.status().active_contexts, 1);
        assert_eq!(registry.snapshot().active_route_contexts, 1);
        assert_eq!(state.status().mpquic_paths, 0);
        assert_eq!(registry.snapshot().mpquic_paths, 0);
        state
            .replace_mpquic_paths(vec![
                path(7, 1, "relay-one", PathState::Active),
                path(7, 2, "relay-two", PathState::Active),
            ])
            .expect("independent MPQUIC paths");
        assert_eq!(state.status().active_contexts, 2);
        state.clear_single_udp_path();
        assert_eq!(state.status().active_contexts, 1);
        assert_eq!(state.status().mpquic_paths, 2);
        assert_eq!(state.path_list().paths.len(), 2);
        state.clear_mpquic_paths();
        assert!(!state.status().connected);
        assert_eq!(registry.snapshot().active_route_contexts, 0);
    }

    #[test]
    fn invalid_single_udp_projection_preserves_exact_existing_path() {
        let config = Config::default();
        let mut state =
            AgentState::new(&config, config.roles, None, MetricsRegistry::new()).expect("state");
        let original = path(3, 1, "udp-relay", PathState::Active);
        state
            .replace_single_udp_path(original.clone())
            .expect("UDP path");
        let mut invalid = original.clone();
        invalid.relay_peer_id.clone_from(&invalid.exit_peer_id);
        assert!(matches!(
            state.replace_single_udp_path(invalid),
            Err(StateError::InvalidSingleUdpPath)
        ));
        assert_eq!(state.path_list().paths, vec![original]);
        state.clear_after_helper_cleanup(&config).expect("cleanup");
        assert!(!state.has_network_state());
        assert!(!state.status().connected);
    }
}
