//! Bounded fresh capability snapshots for complementary native chunks.
//!
//! A completed DHT query is not a complete catalogue: a newly registered service may
//! become visible after the first snapshot. Keep one writer and original authority;
//! only previously unattempted providers may fill the remaining verified-cache gaps.

use std::{collections::BTreeSet, future::Future, time::Duration};

use libp2p::PeerId;
use tokio::time::{Instant, timeout_at};
use volparossa_content::{ChunkStore, VerifiedManifest, transfer::TransferLimits};

use super::{
    ContentError, check_publication_time, complete, parallel, recent::RecentProviderScope,
};
use crate::{
    control::ControlContext,
    discovery::{ContentDiscoveryError, DiscoveredContentProvider},
    unix_millis,
};

// One initial generic lookup and two bounded chances for late announcements. No sleeps,
// full-network catalogue, compulsory provider count, or per-round deadline renewal.
const MAX_ROUNDS: usize = 3;
const MAX_PROVIDERS: usize = volparossa_discovery::MAX_CONTENT_OFFERS;

pub(super) async fn pull(
    context: &ControlContext,
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    policy: &volparossa_policy::VerifiedManifest,
    control_peer: PeerId,
) -> Result<(Vec<String>, u64), ContentError> {
    if complete(manifest, store)? {
        return Ok((Vec::new(), 0));
    }
    // The existing outer operation timeout remains in force, including route setup.
    // All hints, discovery and batches below additionally share one transfer budget.
    let deadline = Instant::now() + TransferLimits::default().session_timeout;
    let scope = RecentProviderScope::for_route(context, policy)
        .await
        .filter(|scope| scope.control_peer == control_peer)
        .ok_or(ContentError::Unavailable)?;
    run(
        &mut ProtectedSource {
            context,
            manifest,
            store,
            policy,
            scope,
        },
        deadline,
    )
    .await
}

// The coordinator below is shared by production and deterministic tests. Test sources
// control only discovery timing/authority; successful transfers use the actual chunk wire.
trait Source {
    fn complete(&mut self) -> Result<bool, ContentError>;
    fn validate(&mut self) -> impl Future<Output = Result<(), ContentError>> + Send;
    fn recent(
        &mut self,
        budget: Duration,
    ) -> impl Future<Output = Vec<DiscoveredContentProvider>> + Send;
    // Deliberately accepts only a count: never a manifest, object ID, name or URL.
    fn discover(
        &mut self,
        maximum: usize,
    ) -> impl Future<Output = Result<Vec<DiscoveredContentProvider>, ContentDiscoveryError>> + Send;
    fn transfer(
        &mut self,
        providers: Vec<DiscoveredContentProvider>,
        deadline: Instant,
    ) -> impl Future<Output = Result<(Vec<String>, u64), ContentError>> + Send;
}

struct ProtectedSource<'a> {
    context: &'a ControlContext,
    manifest: &'a VerifiedManifest,
    store: &'a mut ChunkStore,
    policy: &'a volparossa_policy::VerifiedManifest,
    scope: RecentProviderScope,
}

impl Source for ProtectedSource<'_> {
    fn complete(&mut self) -> Result<bool, ContentError> {
        complete(self.manifest, self.store)
    }

    async fn validate(&mut self) -> Result<(), ContentError> {
        check_publication_time(self.manifest)?;
        let state = self.context.state.read().await;
        if !state.roles().client
            || state
                .active_policy(unix_millis())
                .as_ref()
                .map(volparossa_policy::VerifiedManifest::policy_hash)
                != Some(self.policy.policy_hash())
        {
            return Err(ContentError::Policy);
        }
        drop(state);
        if RecentProviderScope::for_route(self.context, self.policy).await != Some(self.scope) {
            return Err(ContentError::Policy);
        }
        Ok(())
    }

    async fn recent(&mut self, budget: Duration) -> Vec<DiscoveredContentProvider> {
        self.context
            .content
            .refresh_recent_provider_hints(self.scope, &self.context.discovery, budget)
            .await
    }

    async fn discover(
        &mut self,
        maximum: usize,
    ) -> Result<Vec<DiscoveredContentProvider>, ContentDiscoveryError> {
        self.context
            .discovery
            .discover_content_providers(self.scope.control_peer, maximum)
            .await
    }

    async fn transfer(
        &mut self,
        providers: Vec<DiscoveredContentProvider>,
        deadline: Instant,
    ) -> Result<(Vec<String>, u64), ContentError> {
        Box::pin(parallel::pull_until(
            self.context,
            self.manifest,
            self.store,
            self.policy,
            providers,
            deadline,
        ))
        .await
    }
}

#[derive(Default)]
struct Progress {
    attempted: BTreeSet<PeerId>,
    used: BTreeSet<String>,
    bytes: u64,
}

impl Progress {
    async fn transfer(
        &mut self,
        source: &mut impl Source,
        providers: Vec<DiscoveredContentProvider>,
        deadline: Instant,
    ) -> Result<(), ContentError> {
        if providers.len() > MAX_PROVIDERS {
            return Err(ContentError::Invalid);
        }
        let providers = providers
            .into_iter()
            .filter(|provider| {
                self.attempted.len() < MAX_PROVIDERS && self.attempted.insert(provider.peer_id)
            })
            .collect::<Vec<_>>();
        let remaining = deadline.saturating_duration_since(Instant::now());
        if providers.is_empty() || remaining.is_zero() {
            return Ok(());
        }
        let (used, bytes) = source.transfer(providers, deadline).await?;
        source.validate().await?;
        self.used.extend(used);
        self.bytes = self.bytes.checked_add(bytes).ok_or(ContentError::Invalid)?;
        Ok(())
    }

    fn receipt(self) -> (Vec<String>, u64) {
        (self.used.into_iter().collect(), self.bytes)
    }
}

async fn run(
    source: &mut impl Source,
    deadline: Instant,
) -> Result<(Vec<String>, u64), ContentError> {
    if source.complete()? {
        return Ok((Vec::new(), 0));
    }
    source.validate().await?;
    let mut progress = Progress::default();
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Err(ContentError::Unavailable);
    }
    let recent = timeout_at(
        deadline,
        source.recent(remaining.min(Duration::from_secs(1))),
    )
    .await
    .unwrap_or_default();
    source.validate().await?;
    progress.transfer(source, recent, deadline).await?;
    for _ in 0..MAX_ROUNDS {
        source.validate().await?;
        if source.complete()? {
            return Ok(progress.receipt());
        }
        if Instant::now() >= deadline || progress.attempted.len() >= MAX_PROVIDERS {
            break;
        }
        let discovered = timeout_at(deadline, source.discover(MAX_PROVIDERS))
            .await
            .unwrap_or(Err(ContentDiscoveryError::Timeout));
        source.validate().await?;
        let providers = match discovered {
            Ok(providers) => providers,
            Err(ContentDiscoveryError::Invalid) => return Err(ContentError::Invalid),
            Err(ContentDiscoveryError::Invalidated) => return Err(ContentError::Policy),
            Err(
                ContentDiscoveryError::Busy
                | ContentDiscoveryError::Closed
                | ContentDiscoveryError::Timeout
                | ContentDiscoveryError::Unavailable,
            ) => {
                // Transient discovery errors never discard already authenticated progress.
                // Native reconstruction still requires completeness; HTTPS may fill gaps.
                if progress.bytes == 0 {
                    return Err(ContentError::Unavailable);
                }
                break;
            }
        };
        progress.transfer(source, providers, deadline).await?;
    }
    Ok(progress.receipt())
}

#[cfg(test)]
mod tests;
