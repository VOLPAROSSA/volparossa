//! Two RAM-only useful-provider hints, not offers, content indexes or authorization.

use std::{collections::VecDeque, future::Future, time::Duration};

use libp2p::PeerId;
use tokio::time::Instant;

use super::{ContentRuntime, now};
use crate::{
    control::ControlContext,
    discovery::{DiscoveredContentProvider, DiscoveryControlHandle},
};

const MAX_RECENT: usize = 2;
const MAX_MEASUREMENT_AGE: Duration = Duration::from_secs(60);

#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) struct RecentProviderScope {
    pub(super) control_peer: PeerId,
    policy_hash: [u8; 32],
    route_context: [u8; 16],
}

impl RecentProviderScope {
    pub(super) fn new(
        control_peer: PeerId,
        policy_hash: [u8; 32],
        route_context: [u8; 16],
    ) -> Self {
        Self {
            control_peer,
            policy_hash,
            route_context,
        }
    }

    pub(super) async fn for_route(
        context: &ControlContext,
        policy: &volparossa_policy::VerifiedManifest,
    ) -> Option<Self> {
        let (control, route) = context.routes.content_discovery_scope().await?;
        Some(Self::new(control, *policy.policy_hash(), route))
    }
}

#[derive(Clone, Copy)]
pub(super) struct RecentProviderHint {
    pub(super) peer_id: PeerId,
    pub(super) verified_bytes: u64,
    /// Actual protected setup, transfer and successful close; not a predicted throughput.
    pub(super) elapsed: Duration,
}

struct Entry {
    scope: RecentProviderScope,
    hint: RecentProviderHint,
    expires: u64,
    deadline: Instant,
    measured_at: Instant,
}

#[derive(Default)]
pub(super) struct RecentProviders(VecDeque<Entry>);

impl RecentProviders {
    fn prune(&mut self, wall: u64, clock: Instant) {
        self.0.retain(|entry| {
            entry.expires > wall
                && entry.deadline > clock
                && clock.saturating_duration_since(entry.measured_at) < MAX_MEASUREMENT_AGE
        });
    }

    fn hints(
        &mut self,
        scope: RecentProviderScope,
        wall: u64,
        clock: Instant,
    ) -> Vec<RecentProviderHint> {
        self.prune(wall, clock);
        self.0
            .iter()
            .filter(|entry| entry.scope == scope)
            .map(|entry| entry.hint)
            .collect()
    }

    fn forget(&mut self, scope: RecentProviderScope, peer: PeerId) {
        self.0
            .retain(|entry| entry.scope != scope || entry.hint.peer_id != peer);
    }

    fn observe(&mut self, mut entry: Entry, wall: u64, clock: Instant) {
        self.prune(wall, clock);
        if entry.hint.verified_bytes == 0
            || entry.hint.elapsed.is_zero()
            || entry.expires <= wall
            || entry.deadline <= clock
        {
            return;
        }
        if let Some(old) = self.0.iter().find(|old| {
            old.scope == entry.scope
                && old.hint.peer_id == entry.hint.peer_id
                && old.expires == entry.expires
        }) {
            // A new successful use of the same offer never renews its monotonic validity.
            entry.deadline = entry.deadline.min(old.deadline);
        }
        self.forget(entry.scope, entry.hint.peer_id);
        if self.0.len() == MAX_RECENT {
            self.0.pop_front();
        }
        self.0.push_back(entry);
    }
}

impl ContentRuntime {
    pub(super) async fn recent_provider_hints(
        &self,
        scope: RecentProviderScope,
    ) -> Vec<RecentProviderHint> {
        self.recent.lock().await.hints(scope, now(), Instant::now())
    }

    pub(super) async fn forget_recent_provider(&self, scope: RecentProviderScope, peer: PeerId) {
        self.recent.lock().await.forget(scope, peer);
    }

    pub(super) async fn observe_recent_provider(
        &self,
        scope: RecentProviderScope,
        hint: RecentProviderHint,
        expires: u64,
        deadline: Instant,
    ) {
        let measured_at = Instant::now();
        self.recent.lock().await.observe(
            Entry {
                scope,
                hint,
                expires,
                deadline,
                measured_at,
            },
            now(),
            measured_at,
        );
    }

    /// Refresh IDs independently: an offline sibling cannot erase a timely fresh offer.
    /// Caller admission time does not replace the discovery actor's nonce/lineage checks.
    pub(super) async fn refresh_recent_provider_hints(
        &self,
        scope: RecentProviderScope,
        discovery: &DiscoveryControlHandle,
        budget: Duration,
    ) -> Vec<DiscoveredContentProvider> {
        let hints = self.recent_provider_hints(scope).await;
        if hints.is_empty() || budget.is_zero() {
            return Vec::new();
        }
        let peers = [
            hints.first().map(|hint| hint.peer_id),
            hints.get(1).map(|hint| hint.peer_id),
        ];
        let refresh = |peer: Option<PeerId>| async move {
            let peer = peer?;
            let mut offers = discovery
                .lookup_content_providers(scope.control_peer, &[peer])
                .await
                .ok()?;
            (offers.len() == 1 && offers[0].peer_id == peer).then(|| offers.remove(0))
        };
        let responses = collect_until(
            refresh(peers[0]),
            refresh(peers[1]),
            Instant::now() + budget,
        )
        .await;
        let mut providers = Vec::new();
        for (peer, response) in peers.into_iter().zip(responses) {
            if let Some(Some(provider)) = response {
                providers.push(provider);
            } else if let Some(peer) = peer {
                self.forget_recent_provider(scope, peer).await;
            }
        }
        providers
    }
}

async fn collect_until<T>(
    first: impl Future<Output = T>,
    second: impl Future<Output = T>,
    deadline: Instant,
) -> [Option<T>; 2] {
    tokio::pin!(first, second);
    let mut replies = [None, None];
    while Instant::now() < deadline && replies.iter().any(Option::is_none) {
        tokio::select! {
            result = &mut first, if replies[0].is_none() => replies[0] = Some(result),
            result = &mut second, if replies[1].is_none() => replies[1] = Some(result),
            () = tokio::time::sleep_until(deadline) => break,
        }
    }
    replies
}

#[cfg(test)]
mod tests {
    use super::*;

    struct DropProof(std::sync::Arc<std::sync::atomic::AtomicBool>);
    impl Drop for DropProof {
        fn drop(&mut self) {
            self.0.store(true, std::sync::atomic::Ordering::SeqCst);
        }
    }

    fn entry(scope: RecentProviderScope, peer: PeerId, clock: Instant) -> Entry {
        Entry {
            scope,
            hint: RecentProviderHint {
                peer_id: peer,
                verified_bytes: 262_144,
                elapsed: Duration::from_millis(80),
            },
            expires: 130,
            deadline: clock + Duration::from_secs(30),
            measured_at: clock,
        }
    }

    #[test]
    fn recent_providers_bound_scope_expiry_metrics_and_failed_hint_removal() {
        let clock = Instant::now();
        let peers = [PeerId::random(), PeerId::random(), PeerId::random()];
        let control = PeerId::random();
        let scope = RecentProviderScope::new(control, [7; 32], [9; 16]);
        let mut cache = RecentProviders::default();
        for peer in peers {
            cache.observe(entry(scope, peer, clock), 100, clock);
        }
        let hints = cache.hints(scope, 100, clock);
        assert_eq!(hints.len(), 2);
        assert_eq!(hints[0].peer_id, peers[1]);
        assert_eq!(hints[0].verified_bytes, 262_144);
        assert_eq!(hints[0].elapsed, Duration::from_millis(80));
        for different in [
            RecentProviderScope::new(PeerId::random(), [7; 32], [9; 16]),
            RecentProviderScope::new(control, [8; 32], [9; 16]),
            RecentProviderScope::new(control, [7; 32], [10; 16]),
        ] {
            assert!(cache.hints(different, 100, clock).is_empty());
        }
        cache.forget(scope, peers[1]);
        assert_eq!(cache.hints(scope, 100, clock).len(), 1);
        // Re-observation during a wall-clock rollback cannot renew the same offer's deadline.
        cache.observe(
            entry(scope, peers[2], clock + Duration::from_secs(5)),
            95,
            clock + Duration::from_secs(5),
        );
        assert!(
            cache
                .hints(scope, 100, clock + Duration::from_secs(30))
                .is_empty()
        );
        cache.observe(entry(scope, peers[0], clock), 100, clock);
        assert!(cache.hints(scope, 130, clock).is_empty());
        let mut zero = entry(scope, peers[0], clock);
        zero.hint.verified_bytes = 0;
        cache.observe(zero, 100, clock);
        assert!(cache.hints(scope, 100, clock).is_empty());
        let mut long_lived = entry(scope, peers[0], clock);
        long_lived.expires = 400;
        long_lived.deadline = clock + Duration::from_secs(300);
        cache.observe(long_lived, 100, clock);
        assert!(
            cache
                .hints(scope, 160, clock + MAX_MEASUREMENT_AGE)
                .is_empty()
        );
    }

    #[tokio::test]
    async fn recent_provider_admission_retains_ready_sibling_and_drops_late_lookup() {
        let dropped = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let proof = DropProof(dropped.clone());
        let result = collect_until(
            async { 7 },
            async move {
                let _proof = proof;
                std::future::pending::<u8>().await
            },
            Instant::now() + Duration::from_millis(20),
        )
        .await;
        assert_eq!(result, [Some(7), None]);
        assert!(dropped.load(std::sync::atomic::Ordering::SeqCst));
    }
}
