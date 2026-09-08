//! Bounded, short-lived completion-cost hints, never content or connection authority.
//!
//! Unknown costs prefer the origin. An explicit peers-first operation can explore the
//! peer path; successful ordinary native transfers supply measurements too. Predictions
//! include protected setup/transfer/close and are deliberately not speed guarantees.

use std::time::Duration;

use sha2::{Digest, Sha256};
use tokio::time::Instant;
use volparossa_content::origin_https::OriginRequest;

use super::super::recent::{RecentProviderHint, RecentProviderScope};

const MAX_ORIGINS: usize = 16;
const COST_LIFETIME: Duration = Duration::from_secs(60);
const MIN_SAMPLE_BYTES: u64 = 64 * 1024;
const MAX_LOOKUP: Duration = Duration::from_secs(1);
const MIN_LOOKUP: Duration = Duration::from_millis(20);
const MAX_PEER_ATTEMPT: Duration = Duration::from_secs(30);

#[derive(Default)]
pub(crate) struct SourceCosts {
    origins: Vec<OriginCost>,
}

struct OriginCost {
    scope: RecentProviderScope,
    // No URL, path, query or plaintext hostname is retained. This RAM-only digest is
    // merely a bounded equality key, not anonymization or reusable origin authority.
    origin: [u8; 32],
    bytes: u64,
    elapsed: Duration,
    deadline: Instant,
}

impl SourceCosts {
    pub(super) fn observe_origin(
        &mut self,
        scope: RecentProviderScope,
        origin: &OriginRequest,
        bytes: u64,
        requests: u32,
        elapsed: Duration,
        at: Instant,
    ) {
        self.origins.retain(|sample| at < sample.deadline);
        // Fragmented fallback can pay many TLS setups. Do not mistake that inflated
        // aggregate cost for the time of one contiguous origin response.
        if requests != 1 || bytes < MIN_SAMPLE_BYTES || elapsed.is_zero() {
            return;
        }
        let origin = origin_key(origin);
        self.origins
            .retain(|sample| sample.scope != scope || sample.origin != origin);
        if self.origins.len() == MAX_ORIGINS {
            self.origins.remove(0);
        }
        self.origins.push(OriginCost {
            scope,
            origin,
            bytes,
            elapsed,
            deadline: at + COST_LIFETIME,
        });
    }

    pub(super) fn estimate_origin(
        &mut self,
        scope: RecentProviderScope,
        origin: &OriginRequest,
        contiguous_missing_bytes: u64,
        at: Instant,
    ) -> Option<Duration> {
        self.origins.retain(|sample| at < sample.deadline);
        if contiguous_missing_bytes < MIN_SAMPLE_BYTES {
            return None;
        }
        let key = origin_key(origin);
        let sample = self
            .origins
            .iter()
            .find(|sample| sample.scope == scope && sample.origin == key)?;
        // Avoid predicting a tiny or vastly larger object from a single old sample.
        if contiguous_missing_bytes < sample.bytes / 2
            || contiguous_missing_bytes > sample.bytes.saturating_mul(2)
        {
            return None;
        }
        scale(sample.elapsed, contiguous_missing_bytes, sample.bytes)
    }
}

fn origin_key(origin: &OriginRequest) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"volparossa-https-cost-v1\0");
    hash.update(origin.hostname().as_bytes());
    hash.update([0]);
    hash.update(origin.port().to_be_bytes());
    hash.finalize().into()
}

/// One advisory budget including fresh lookup and the complete protected peer attempt.
/// Fallback only begins once all workers have stopped; no full-object origin race exists.
pub(super) struct PeerPlan {
    pub(super) lookup_budget: Duration,
    pub(super) total_budget: Duration,
}

impl PeerPlan {
    pub(super) fn new(
        origin: Duration,
        object_bytes: u64,
        hints: &[RecentProviderHint],
    ) -> Option<Self> {
        let transfer = estimate_peers(object_bytes, hints)?;
        Self::with_transfer_cost(origin, transfer)
    }

    pub(super) fn new_digest(
        origin: Duration,
        object_bytes: u64,
        hints: &[RecentProviderHint],
        at: Instant,
        parallelism: usize,
    ) -> Option<Self> {
        Self::with_transfer_cost(
            origin,
            estimate_digest_peers(object_bytes, hints, at, parallelism)?,
        )
    }

    fn with_transfer_cost(origin: Duration, transfer: Duration) -> Option<Self> {
        // Require a projected 20% margin. This is an admission rule, not a promise
        // that real network conditions will remain equal to a recent measurement.
        let total_budget = scale(origin, 4, 5)?.min(MAX_PEER_ATTEMPT);
        let spare = total_budget.checked_sub(transfer)?;
        let lookup_budget = (spare / 2).min(MAX_LOOKUP);
        if lookup_budget < MIN_LOOKUP {
            return None;
        }
        Some(Self {
            lookup_budget,
            total_budget,
        })
    }

    pub(super) fn admits_refreshed(
        &self,
        object_bytes: u64,
        hints: &[RecentProviderHint],
        spent: Duration,
    ) -> bool {
        self.admits_cost(estimate_peers(object_bytes, hints), spent)
    }

    pub(super) fn admits_digest_refreshed(
        &self,
        object_bytes: u64,
        hints: &[RecentProviderHint],
        spent: Duration,
        at: Instant,
        parallelism: usize,
    ) -> bool {
        self.admits_cost(
            estimate_digest_peers(object_bytes, hints, at, parallelism),
            spent,
        )
    }

    pub(super) fn admits_after_index(
        &self,
        object_bytes: u64,
        hints: &[RecentProviderHint],
        selected: &[libp2p::PeerId],
        spent: Duration,
    ) -> bool {
        let retained = hints
            .iter()
            .filter(|hint| selected.contains(&hint.peer_id))
            .copied()
            .collect::<Vec<_>>();
        // Lookup has now actually elapsed. Only the selected, still-useful payload hints
        // predict the remaining work; adding the old index estimate would count it twice.
        retained.len() == selected.len() && self.admits_refreshed(object_bytes, &retained, spent)
    }

    fn admits_cost(&self, cost: Option<Duration>, spent: Duration) -> bool {
        cost.is_some_and(|transfer| {
            spent
                .checked_add(transfer)
                .is_some_and(|total| total < self.total_budget)
        })
    }
}

fn estimate_digest_peers(
    object_bytes: u64,
    hints: &[RecentProviderHint],
    at: Instant,
    parallelism: usize,
) -> Option<Duration> {
    let transfer = estimate_peers(object_bytes, hints)?;
    if parallelism == 0 {
        return None;
    }
    let mut index = Duration::ZERO;
    // Index batches use the currently resource-admissible width. Include every actual
    // batch's slowest setup, never pretend all indexes overlap when only one slot fits.
    for batch in hints.chunks(parallelism.min(hints.len())) {
        let mut batch_cost = Duration::ZERO;
        for hint in batch {
            batch_cost = batch_cost.max(hint.digest_index?.elapsed(at)?);
        }
        index = index.checked_add(batch_cost)?;
    }
    // Setup is fixed, not scaled by object size or optimistically divided by peers.
    transfer.checked_add(index)
}

fn estimate_peers(object_bytes: u64, hints: &[RecentProviderHint]) -> Option<Duration> {
    if object_bytes < MIN_SAMPLE_BYTES
        || hints.is_empty()
        || hints.len() > super::super::recent::OFFER_BATCH
    {
        return None;
    }
    let mut cost = Duration::ZERO;
    for hint in hints {
        if hint.verified_bytes < MIN_SAMPLE_BYTES || hint.elapsed.is_zero() {
            return None;
        }
        // Count the full object's cost at the slowest measured peer, not an assumed
        // sum of capacities. Keeping setup time for smaller objects is conservative.
        let estimate = scale(
            hint.elapsed,
            object_bytes.max(hint.verified_bytes),
            hint.verified_bytes,
        )?;
        cost = cost.max(estimate);
    }
    Some(cost)
}

fn scale(time: Duration, numerator: u64, denominator: u64) -> Option<Duration> {
    let nanos = time
        .as_nanos()
        .checked_mul(u128::from(numerator))?
        .checked_div(u128::from(denominator))?;
    Some(Duration::from_nanos(u64::try_from(nanos).ok()?))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scope() -> RecentProviderScope {
        RecentProviderScope::new(libp2p::PeerId::random(), [7; 32], [8; 16])
    }

    fn origin(path: &str) -> OriginRequest {
        OriginRequest::new(&format!("https://origin.example/{path}"), "/metadata").unwrap()
    }

    #[test]
    fn origin_cost_is_short_lived_route_scoped_and_not_a_url_history() {
        let mut costs = SourceCosts::default();
        let at = Instant::now();
        let scope = scope();
        let bytes = 2 * 1024 * 1024;
        assert!(
            costs
                .estimate_origin(scope, &origin("a"), bytes, at)
                .is_none()
        );
        costs.observe_origin(scope, &origin("a"), bytes, 1, Duration::from_secs(2), at);
        assert_eq!(
            costs.estimate_origin(scope, &origin("different?query=not-retained"), bytes, at),
            Some(Duration::from_secs(2))
        );
        let other_route = RecentProviderScope::new(scope.control_peer, [7; 32], [9; 16]);
        assert!(
            costs
                .estimate_origin(other_route, &origin("a"), bytes, at)
                .is_none()
        );
        assert!(
            costs
                .estimate_origin(scope, &origin("a"), 1024, at)
                .is_none()
        );
        assert!(
            costs
                .estimate_origin(scope, &origin("a"), bytes, at + COST_LIFETIME)
                .is_none()
        );
        assert!(costs.origins.is_empty());
    }

    #[test]
    fn fragmented_origin_fallback_does_not_inflate_origin_cost() {
        let mut costs = SourceCosts::default();
        let at = Instant::now();
        let scope = scope();
        costs.observe_origin(
            scope,
            &origin("a"),
            1_000_000,
            4,
            Duration::from_secs(8),
            at,
        );
        assert!(
            costs
                .estimate_origin(scope, &origin("a"), 1_000_000, at)
                .is_none()
        );
        for index in 0..=MAX_ORIGINS {
            let request = OriginRequest::new(&format!("https://h{index}.example/a"), "/m").unwrap();
            costs.observe_origin(scope, &request, 1_000_000, 1, Duration::from_secs(1), at);
        }
        assert_eq!(costs.origins.len(), MAX_ORIGINS);
    }

    #[test]
    fn only_measured_useful_peers_fit_lookup_and_transfer_inside_origin_budget() {
        let mut hints = vec![RecentProviderHint {
            peer_id: libp2p::PeerId::random(),
            verified_bytes: 1024 * 1024,
            elapsed: Duration::from_millis(100),
            digest_index: None,
        }];
        let size = 2 * 1024 * 1024;
        assert!(PeerPlan::new(Duration::from_secs(2), size, &[]).is_none());
        let plan = PeerPlan::new(Duration::from_secs(2), size, &hints).unwrap();
        assert!(plan.lookup_budget <= MAX_LOOKUP);
        assert!(plan.admits_refreshed(size, &hints, plan.lookup_budget));
        assert!(!plan.admits_refreshed(size, &[], Duration::ZERO));
        assert!(!plan.admits_refreshed(size, &hints, plan.total_budget));
        hints[0].elapsed = Duration::from_secs(2);
        assert!(PeerPlan::new(Duration::from_secs(2), size, &hints).is_none());
        hints[0].elapsed = Duration::ZERO;
        assert!(PeerPlan::new(Duration::from_secs(2), size, &hints).is_none());
    }

    #[test]
    fn digest_index_cost_is_fixed_fresh_and_rechecked_only_for_selected_payloads() {
        use crate::content::recent::DigestIndexCost;

        let at = Instant::now();
        let size = 2 * 1024 * 1024;
        let origin = Duration::from_secs(2);
        let mut hints = [100, 200].map(|millis| RecentProviderHint {
            peer_id: libp2p::PeerId::random(),
            verified_bytes: 1024 * 1024,
            elapsed: Duration::from_millis(millis),
            digest_index: None,
        });
        assert!(PeerPlan::new(origin, size, &hints).is_some());
        assert!(PeerPlan::new_digest(origin, size, &hints, at, 2).is_none());
        hints[0].digest_index = DigestIndexCost::new(Duration::from_millis(400), at);
        assert!(PeerPlan::new_digest(origin, size, &hints, at, 2).is_none());
        hints[1].digest_index = DigestIndexCost::new(Duration::from_millis(700), at);
        assert_eq!(
            estimate_digest_peers(size, &hints, at, 2),
            Some(Duration::from_millis(1100)),
            "parallel index max700 + conservative payload max400, no index scaling"
        );
        let plan = PeerPlan::new_digest(origin, size, &hints, at, 2).unwrap();
        assert!(plan.admits_digest_refreshed(size, &hints, Duration::from_millis(100), at, 2));
        assert!(!plan.admits_digest_refreshed(size, &hints, Duration::from_millis(600), at, 2));
        let selected = hints.map(|hint| hint.peer_id);
        assert!(plan.admits_after_index(size, &hints, &selected, Duration::from_secs(1)));
        assert!(!plan.admits_after_index(size, &hints, &selected, Duration::from_millis(1300)));
        assert!(plan.admits_after_index(size, &hints, &selected[..1], Duration::from_millis(1300)));
        assert!(!plan.admits_after_index(size, &hints[..1], &selected, Duration::ZERO));
        hints[1].digest_index = DigestIndexCost::new(Duration::from_secs(2), at);
        assert!(PeerPlan::new_digest(origin, size, &hints, at, 2).is_none());
        assert!(
            PeerPlan::new(origin, size, &hints).is_some(),
            "native cost is unchanged"
        );
        assert!(PeerPlan::new_digest(origin, size, &hints, at + COST_LIFETIME, 2).is_none());
    }

    #[test]
    fn digest_source_plan_accepts_three_useful_peers_and_prices_resource_limited_batches() {
        use crate::content::recent::DigestIndexCost;
        let at = Instant::now();
        let hints = [10, 20, 30].map(|cost| RecentProviderHint {
            peer_id: libp2p::PeerId::random(),
            verified_bytes: 1024 * 1024,
            elapsed: Duration::from_millis(100),
            digest_index: DigestIndexCost::new(Duration::from_millis(cost), at),
        });
        let size = 2 * 1024 * 1024;
        assert_eq!(
            estimate_digest_peers(size, &hints, at, 3),
            Some(Duration::from_millis(230))
        );
        assert_eq!(
            estimate_digest_peers(size, &hints, at, 1),
            Some(Duration::from_millis(260))
        );
        assert_eq!(
            estimate_digest_peers(size, &hints, at, 2),
            Some(Duration::from_millis(250))
        );
        assert!(PeerPlan::new_digest(Duration::from_secs(2), size, &hints, at, 3).is_some());
        assert!(PeerPlan::new_digest(Duration::from_secs(2), size, &hints, at, 0).is_none());
        let plan = PeerPlan::new_digest(Duration::from_secs(2), size, &hints, at, 3).unwrap();
        assert!(plan.admits_after_index(
            size,
            &hints,
            &hints.map(|hint| hint.peer_id),
            Duration::from_secs(1)
        ));
    }
}
