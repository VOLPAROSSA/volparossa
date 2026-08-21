use std::collections::{HashMap, HashSet};
use thiserror::Error;
use volparossa_core::{
    FlowId, LocalProfileId, NodeId, OriginKey, PolicyHash, RouteContextId, Transport, UnixTime,
};

/// Default lifetime for ordinary route contexts.
pub const NORMAL_CONTEXT_TTL_SECONDS: u64 = 600;
/// Default lifetime for authentication-sensitive route contexts.
pub const AUTHENTICATION_CONTEXT_TTL_SECONDS: u64 = 1_800;
/// Hard upper bound for any route context.
pub const MAXIMUM_CONTEXT_TTL_SECONDS: u64 = 3_600;
/// Hard allocation bound for route-context generations in one cache.
pub const MAXIMUM_ROUTE_CONTEXTS: usize = 4_096;
/// Hard allocation bound for established flow pins in one cache.
pub const MAXIMUM_ACTIVE_FLOWS: usize = 65_536;
const MAXIMUM_ROUTE_PATHS: usize = 8;

/// In-memory partition key for route reuse.
///
/// `origin_key` is opaque so this cache never needs a browsed hostname.  Route
/// contexts are intentionally not serializable and must not be persisted in
/// the peerstore.
#[derive(Clone, Debug, Eq, Hash, PartialEq)]
pub struct RouteScope {
    /// Local client profile partition.
    pub local_profile: LocalProfileId,
    /// Session-local key derived from a registrable domain or application origin.
    pub origin_key: OriginKey,
    /// Exact transport used by all new flows in the context.
    pub transport: Transport,
    /// Monotonic whitelist manifest version.
    pub policy_version: u64,
    /// Exact whitelist manifest hash.
    pub policy_hash: PolicyHash,
}

/// Exit and diverse relay pool fixed for one route-context generation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RoutePlan {
    /// Exit selected before any relay.
    pub exit_node_id: NodeId,
    /// Active voluntary relays; direct client-exit plans are invalid.
    pub active_relays: Vec<NodeId>,
    /// Distinct reserved warm relay paths.
    pub warm_relays: Vec<NodeId>,
}

impl RoutePlan {
    fn validate(&self) -> Result<(), RouteContextError> {
        if self.active_relays.is_empty() {
            return Err(RouteContextError::DirectExitPlan);
        }
        if self
            .active_relays
            .len()
            .saturating_add(self.warm_relays.len())
            > MAXIMUM_ROUTE_PATHS
        {
            return Err(RouteContextError::TooManyPaths);
        }
        let mut seen = HashSet::new();
        for relay in self.active_relays.iter().chain(&self.warm_relays) {
            if relay == &self.exit_node_id || !seen.insert(relay) {
                return Err(RouteContextError::DuplicateOrInvalidRelay);
            }
        }
        Ok(())
    }
}

/// One bounded generation of a route context.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RouteContext {
    /// Unique generation identifier.
    pub route_context_id: RouteContextId,
    /// Reuse scope.
    pub scope: RouteScope,
    /// Exit and relay pool fixed for this generation.
    pub plan: RoutePlan,
    /// Context creation instant.
    pub created_at: UnixTime,
    /// New-flow expiry; existing flows remain pinned after this instant.
    pub expires_at: UnixTime,
}

/// A copy of the route binding held for the complete lifetime of one flow.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct FlowBinding {
    /// Context generation in which the flow started.
    pub route_context_id: RouteContextId,
    /// Exit pinned until this flow ends.
    pub exit_node_id: NodeId,
    /// Active relays pinned for the flow.
    pub active_relays: Vec<NodeId>,
    /// Warm relays belonging to the same generation.
    pub warm_relays: Vec<NodeId>,
}

/// A retired generation whose associated network resources may be cleaned up.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct RetiredContext {
    /// Retired generation identifier.
    pub route_context_id: RouteContextId,
    /// Plan whose WireGuard/MPTCP/MPQUIC/routing/firewall resources must be removed.
    pub plan: RoutePlan,
}

/// Cleanup work caused while inserting a route generation.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct InsertContextOutcome {
    /// Unpinned generations retired by replacement or LRU capacity enforcement.
    pub retired: Vec<RetiredContext>,
}

#[derive(Clone, Debug)]
struct ContextEntry {
    context: RouteContext,
    last_used_at: UnixTime,
    active_flow_count: usize,
    accepts_new_flows: bool,
}

/// Bounded in-memory LRU cache with TTL generations and immutable flow pins.
#[derive(Debug)]
pub struct RouteContextCache {
    maximum_contexts: usize,
    maximum_flows: usize,
    maximum_ttl_seconds: u64,
    contexts: HashMap<RouteContextId, ContextEntry>,
    active_by_scope: HashMap<RouteScope, RouteContextId>,
    flows: HashMap<FlowId, FlowBinding>,
}

impl RouteContextCache {
    /// Constructs a cache.  A typical caller uses 64 contexts and a 3600
    /// second hard maximum; normal contexts usually request 600 seconds.
    ///
    /// The established-flow map uses the hard `MAXIMUM_ACTIVE_FLOWS` allocation limit.
    ///
    /// # Errors
    ///
    /// Returns an error when a capacity or TTL is zero or exceeds its hard limit.
    pub fn new(
        maximum_contexts: usize,
        maximum_ttl_seconds: u64,
    ) -> Result<Self, RouteContextError> {
        Self::new_with_maximum_flows(maximum_contexts, maximum_ttl_seconds, MAXIMUM_ACTIVE_FLOWS)
    }

    /// Constructs a cache with a smaller explicit established-flow limit.
    ///
    /// # Errors
    ///
    /// Returns an error when a capacity or TTL is zero or exceeds its hard limit.
    pub fn new_with_maximum_flows(
        maximum_contexts: usize,
        maximum_ttl_seconds: u64,
        maximum_flows: usize,
    ) -> Result<Self, RouteContextError> {
        if maximum_contexts == 0
            || maximum_contexts > MAXIMUM_ROUTE_CONTEXTS
            || maximum_flows == 0
            || maximum_flows > MAXIMUM_ACTIVE_FLOWS
            || maximum_ttl_seconds == 0
            || maximum_ttl_seconds > MAXIMUM_CONTEXT_TTL_SECONDS
        {
            return Err(RouteContextError::InvalidLimits);
        }
        Ok(Self {
            maximum_contexts,
            maximum_flows,
            maximum_ttl_seconds,
            contexts: HashMap::new(),
            active_by_scope: HashMap::new(),
            flows: HashMap::new(),
        })
    }

    /// Inserts a new generation, retiring only unpinned LRU entries.
    ///
    /// The operation is fail-atomic when every possible victim carries an
    /// established flow: no active mapping is changed in that case.
    ///
    /// # Errors
    ///
    /// Returns an error when the context plan or lifetime is invalid, its identifier already
    /// exists, or all potential capacity victims are pinned by established flows. The cache is not
    /// partially updated on failure.
    pub fn insert_context(
        &mut self,
        context: RouteContext,
        now: UnixTime,
    ) -> Result<InsertContextOutcome, RouteContextError> {
        self.validate_context(&context, now)?;
        if self.contexts.contains_key(&context.route_context_id) {
            return Err(RouteContextError::DuplicateContext);
        }

        let replacement = self.active_by_scope.get(&context.scope).cloned();
        let additional_slot = usize::from(
            replacement
                .as_ref()
                .and_then(|id| self.contexts.get(id))
                .is_none_or(|entry| entry.active_flow_count > 0),
        );
        let final_len_without_lru = self.contexts.len() + additional_slot;
        let lru_needed = final_len_without_lru.saturating_sub(self.maximum_contexts);
        let mut victims: Vec<(RouteContextId, UnixTime)> = self
            .contexts
            .iter()
            .filter(|(id, entry)| {
                entry.active_flow_count == 0 && replacement.as_ref().is_none_or(|old| old != *id)
            })
            .map(|(id, entry)| (id.clone(), entry.last_used_at))
            .collect();
        victims.sort_by(|(left_id, left_time), (right_id, right_time)| {
            left_time
                .cmp(right_time)
                .then_with(|| left_id.cmp(right_id))
        });
        if victims.len() < lru_needed {
            return Err(RouteContextError::AllContextsPinned);
        }
        victims.truncate(lru_needed);

        let mut retired = Vec::new();
        if let Some(old_id) = replacement {
            let old_has_flows = self
                .contexts
                .get(&old_id)
                .is_some_and(|entry| entry.active_flow_count > 0);
            if old_has_flows {
                if let Some(entry) = self.contexts.get_mut(&old_id) {
                    entry.accepts_new_flows = false;
                }
            } else if let Some(old) = self.remove_context(&old_id) {
                retired.push(old);
            }
        }
        for (victim_id, _) in victims {
            if let Some(victim) = self.remove_context(&victim_id) {
                retired.push(victim);
            }
        }

        self.active_by_scope
            .insert(context.scope.clone(), context.route_context_id.clone());
        self.contexts.insert(
            context.route_context_id.clone(),
            ContextEntry {
                context,
                last_used_at: now,
                active_flow_count: 0,
                accepts_new_flows: true,
            },
        );
        Ok(InsertContextOutcome { retired })
    }

    /// Pins a new flow to the currently active, unexpired generation.
    ///
    /// # Errors
    ///
    /// Returns an error for a duplicate flow, missing or expired active context, or flow-count
    /// overflow.
    pub fn begin_flow(
        &mut self,
        scope: &RouteScope,
        flow_id: FlowId,
        now: UnixTime,
    ) -> Result<FlowBinding, RouteContextError> {
        if self.flows.contains_key(&flow_id) {
            return Err(RouteContextError::DuplicateFlow);
        }
        if self.flows.len() >= self.maximum_flows {
            return Err(RouteContextError::TooManyFlows);
        }
        let context_id = self
            .active_by_scope
            .get(scope)
            .cloned()
            .ok_or(RouteContextError::NoActiveContext)?;
        let entry = self
            .contexts
            .get_mut(&context_id)
            .ok_or(RouteContextError::NoActiveContext)?;
        if now < entry.last_used_at {
            return Err(RouteContextError::ClockMovedBackwards);
        }
        if !entry.accepts_new_flows || entry.context.expires_at.is_expired_at(now) {
            entry.accepts_new_flows = false;
            self.active_by_scope.remove(scope);
            return Err(RouteContextError::ContextExpired);
        }
        entry.active_flow_count = entry
            .active_flow_count
            .checked_add(1)
            .ok_or(RouteContextError::FlowCountOverflow)?;
        entry.last_used_at = now;
        let binding = FlowBinding {
            route_context_id: context_id,
            exit_node_id: entry.context.plan.exit_node_id.clone(),
            active_relays: entry.context.plan.active_relays.clone(),
            warm_relays: entry.context.plan.warm_relays.clone(),
        };
        self.flows.insert(flow_id, binding.clone());
        Ok(binding)
    }

    /// Returns a pinned flow binding without changing its LRU position.
    #[must_use]
    pub fn flow_binding(&self, flow_id: &FlowId) -> Option<&FlowBinding> {
        self.flows.get(flow_id)
    }

    /// Ends a flow and returns immediate cleanup work for a retired generation.
    ///
    /// # Errors
    ///
    /// Returns an error when the flow is unknown or its binding disagrees with the context's
    /// active-flow accounting.
    pub fn finish_flow(
        &mut self,
        flow_id: &FlowId,
        now: UnixTime,
    ) -> Result<Option<RetiredContext>, RouteContextError> {
        let binding = self
            .flows
            .get(flow_id)
            .cloned()
            .ok_or(RouteContextError::UnknownFlow)?;
        let current_entry = self
            .contexts
            .get(&binding.route_context_id)
            .ok_or(RouteContextError::CorruptFlowBinding)?;
        if current_entry.active_flow_count == 0 {
            return Err(RouteContextError::CorruptFlowBinding);
        }
        if now < current_entry.last_used_at {
            return Err(RouteContextError::ClockMovedBackwards);
        }
        self.flows.remove(flow_id);
        let entry = self
            .contexts
            .get_mut(&binding.route_context_id)
            .ok_or(RouteContextError::CorruptFlowBinding)?;
        entry.active_flow_count -= 1;
        entry.last_used_at = now;
        let should_retire = entry.active_flow_count == 0
            && (!entry.accepts_new_flows || entry.context.expires_at.is_expired_at(now));
        if should_retire {
            return Ok(self.remove_context(&binding.route_context_id));
        }
        Ok(None)
    }

    /// Expires contexts for new flows and returns only generations without
    /// established flows, leaving pinned flows and their resources intact.
    pub fn expire(&mut self, now: UnixTime) -> Vec<RetiredContext> {
        let expired: Vec<RouteContextId> = self
            .contexts
            .iter()
            .filter(|(_, entry)| entry.context.expires_at.is_expired_at(now))
            .map(|(id, _)| id.clone())
            .collect();
        let mut retired = Vec::new();
        for context_id in expired {
            if let Some(entry) = self.contexts.get_mut(&context_id) {
                entry.accepts_new_flows = false;
                if self
                    .active_by_scope
                    .get(&entry.context.scope)
                    .is_some_and(|active| active == &context_id)
                {
                    self.active_by_scope.remove(&entry.context.scope);
                }
                if entry.active_flow_count == 0 {
                    if let Some(context) = self.remove_context(&context_id) {
                        retired.push(context);
                    }
                }
            }
        }
        retired
    }

    /// Returns the number of route generations, including pinned retired ones.
    #[must_use]
    pub fn context_count(&self) -> usize {
        self.contexts.len()
    }

    /// Returns the number of established flow pins.
    #[must_use]
    pub fn flow_count(&self) -> usize {
        self.flows.len()
    }

    fn validate_context(
        &self,
        context: &RouteContext,
        now: UnixTime,
    ) -> Result<(), RouteContextError> {
        context.plan.validate()?;
        let active_path_count_is_valid = match context.scope.transport {
            Transport::UdpSinglePath => context.plan.active_relays.len() == 1,
            Transport::TcpMptcp | Transport::MultipathQuic => {
                (2..=MAXIMUM_ROUTE_PATHS).contains(&context.plan.active_relays.len())
            }
        };
        if !active_path_count_is_valid {
            return Err(RouteContextError::InvalidTransportPathCount);
        }
        if context.created_at > now
            || context.expires_at <= context.created_at
            || context.expires_at.is_expired_at(now)
        {
            return Err(RouteContextError::InvalidLifetime);
        }
        let lifetime = context.expires_at.as_secs() - context.created_at.as_secs();
        if lifetime > self.maximum_ttl_seconds {
            return Err(RouteContextError::TtlTooLong);
        }
        Ok(())
    }

    fn remove_context(&mut self, context_id: &RouteContextId) -> Option<RetiredContext> {
        let entry = self.contexts.remove(context_id)?;
        if self
            .active_by_scope
            .get(&entry.context.scope)
            .is_some_and(|active| active == context_id)
        {
            self.active_by_scope.remove(&entry.context.scope);
        }
        Some(RetiredContext {
            route_context_id: entry.context.route_context_id,
            plan: entry.context.plan,
        })
    }
}

/// Route-context validation, pinning or capacity failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum RouteContextError {
    /// A cache size or maximum TTL is zero or exceeds its hard allocation limit.
    #[error("invalid route-context cache limits")]
    InvalidLimits,
    /// Active path count disagrees with the exact single-path or multipath transport.
    #[error("route plan path count is invalid for its transport")]
    InvalidTransportPathCount,
    /// A normal route plan has no voluntary relay.
    #[error("direct client-exit route plans are forbidden")]
    DirectExitPlan,
    /// A relay is duplicated or equals the selected exit.
    #[error("duplicate or invalid relay in route plan")]
    DuplicateOrInvalidRelay,
    /// More than eight active and warm relay paths were requested.
    #[error("route plan exceeds the maximum path count")]
    TooManyPaths,
    /// The context starts in the future, is expired or has inverted timestamps.
    #[error("invalid route-context lifetime")]
    InvalidLifetime,
    /// Requested context lifetime exceeds the hard configured maximum.
    #[error("route-context TTL exceeds the hard maximum")]
    TtlTooLong,
    /// A context identifier was replayed.
    #[error("duplicate route-context identifier")]
    DuplicateContext,
    /// Every LRU victim still carries an established flow.
    #[error("all route contexts are pinned by established flows")]
    AllContextsPinned,
    /// No unexpired generation exists for the requested scope.
    #[error("no active route context for scope")]
    NoActiveContext,
    /// The generation cannot accept a new flow after TTL expiry.
    #[error("route context expired for new flows")]
    ContextExpired,
    /// A flow identifier was replayed while still active.
    #[error("duplicate active flow identifier")]
    DuplicateFlow,
    /// The established-flow map reached its defensive hard limit.
    #[error("too many active flow bindings")]
    TooManyFlows,
    /// The requested flow is not active.
    #[error("unknown active flow")]
    UnknownFlow,
    /// Internal flow-count arithmetic overflowed.
    #[error("route-context flow count overflow")]
    FlowCountOverflow,
    /// A cache operation supplied a timestamp older than its last accepted use.
    #[error("route-context timestamp moved backwards")]
    ClockMovedBackwards,
    /// The in-memory binding and context indexes disagree.
    #[error("corrupt in-memory flow binding")]
    CorruptFlowBinding,
}
