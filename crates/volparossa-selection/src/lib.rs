//! Local, randomized and diversity-aware route selection.
//!
//! Selection is deliberately based on local evidence.  Advertised values are
//! used only as bounded preselection hints, and every externally controlled
//! value crosses a hard-filter validation boundary before it can be scored.

mod candidate;
mod path;
mod route_context;
mod weighted;

pub use candidate::{
    Candidate, CandidateEvidence, FilterRequirements, HardFilterReason, PrefixObservedCandidate,
    hard_filter,
};
pub use path::{
    HysteresisPolicy, MAXIMUM_HYSTERESIS_PAIRS, PathMetrics, PathMetricsError, PathState,
    PathStatus, PathTransitionError, ReplacementDecision, ReplacementHysteresis, ReplacementReason,
};
pub use route_context::{
    AUTHENTICATION_CONTEXT_TTL_SECONDS, FlowBinding, InsertContextOutcome, MAXIMUM_ACTIVE_FLOWS,
    MAXIMUM_CONTEXT_TTL_SECONDS, MAXIMUM_ROUTE_CONTEXTS, NORMAL_CONTEXT_TTL_SECONDS,
    RetiredContext, RouteContext, RouteContextCache, RouteContextError, RoutePlan, RouteScope,
};
pub use weighted::{
    CompleteRelayPathMetrics, DiversityAnchor, MAXIMUM_PROSPECTIVE_RELAYS,
    MAXIMUM_SELECTION_CANDIDATES, ProjectedRelayPath, ProspectiveRelayPolicy,
    ProspectiveRelaySelection, RelayPathCandidate, RelaySelection, RelaySelectionPolicy,
    RelaySelectionProjection, SelectedNode, SelectedPath, SelectionBand, SelectionError,
    SelectionMix, select_exit, select_exit_with_observed_prefixes, select_projected_relay_paths,
    select_prospective_relays, select_prospective_relays_with_observed_prefixes,
    select_relay_paths, validate_relay_selection_policy,
};
