//! Up to two protected provider streams, with one bounded independently verified cache writer.

use std::{collections::BTreeSet, future::Future, time::Duration};

use tokio::time::{Instant, timeout_at};

#[cfg(test)]
mod tests;

use volparossa_content::{
    ChunkStore, VerifiedManifest,
    provider::{ProviderError, pull_publication_worker},
    transfer::{
        TransferError, TransferLimits, TransferProgress,
        parallel::{ChunkWorker, ParallelDownload},
    },
};

use super::recent::{RecentProviderHint, RecentProviderScope};
use super::{ContentError, complete, content_event, now, tls};
use crate::{control::ControlContext, discovery::DiscoveredContentProvider, unix_millis};

struct ProviderSource {
    provider: DiscoveredContentProvider,
    // Only digest-authorized callers select a provider's alternative original transport index.
    // The library compares the whole identity and exact chunk layout before workers can start.
    transport: Option<VerifiedManifest>,
}

fn exact_sources(providers: Vec<DiscoveredContentProvider>) -> Vec<ProviderSource> {
    providers
        .into_iter()
        .map(|provider| ProviderSource {
            provider,
            transport: None,
        })
        .collect()
}

pub(super) async fn pull(
    context: &ControlContext,
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    policy: &volparossa_policy::VerifiedManifest,
    providers: Vec<DiscoveredContentProvider>,
) -> Result<(Vec<String>, u64), ContentError> {
    pull_inner(
        context,
        manifest,
        store,
        policy,
        exact_sources(providers),
        None,
    )
    .await
}

/// A source-selection budget, not a new transfer protocol or a renewed operation deadline.
/// Verified writer progress survives the deadline; both workers end before origin can start.
pub(super) async fn pull_with_budget(
    context: &ControlContext,
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    policy: &volparossa_policy::VerifiedManifest,
    providers: Vec<DiscoveredContentProvider>,
    budget: Duration,
) -> Result<(Vec<String>, u64), ContentError> {
    if providers.len() > 2 {
        return Err(ContentError::Invalid);
    }
    if budget.is_zero() {
        return Ok((Vec::new(), 0));
    }
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or(ContentError::Invalid)?;
    pull_inner(
        context,
        manifest,
        store,
        policy,
        exact_sources(providers),
        Some(deadline),
    )
    .await
}

/// Whole-object HTTPS authority remains with the caller. Each provider keeps its own original
/// index on the existing v1 wire, while the single writer accepts only the exact shared layout.
pub(super) async fn pull_indexed_with_budget(
    context: &ControlContext,
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    policy: &volparossa_policy::VerifiedManifest,
    providers: Vec<(DiscoveredContentProvider, VerifiedManifest)>,
    budget: Duration,
) -> Result<(Vec<String>, u64), ContentError> {
    if providers.len() > 2 {
        return Err(ContentError::Invalid);
    }
    if budget.is_zero() {
        return Ok((Vec::new(), 0));
    }
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or(ContentError::Invalid)?;
    let sources = providers
        .into_iter()
        .map(|(provider, transport)| ProviderSource {
            provider,
            transport: Some(transport),
        })
        .collect();
    pull_inner(context, manifest, store, policy, sources, Some(deadline)).await
}

async fn pull_inner(
    context: &ControlContext,
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    policy: &volparossa_policy::VerifiedManifest,
    providers: Vec<ProviderSource>,
    deadline: Option<Instant>,
) -> Result<(Vec<String>, u64), ContentError> {
    if providers.len() > 16 {
        return Err(ContentError::Invalid);
    }
    let mut seen = BTreeSet::new();
    let mut providers = providers
        .into_iter()
        .filter(|source| seen.insert(source.provider.peer_id));
    let mut used = BTreeSet::new();
    let mut bytes = 0_u64;
    let scope = RecentProviderScope::for_route(context, policy).await;
    while !complete(manifest, store)? {
        let mut limits = TransferLimits::default();
        if let Some(deadline) = deadline {
            let remaining = deadline.saturating_duration_since(Instant::now());
            if remaining.is_zero() {
                break;
            }
            limits.session_timeout = limits.session_timeout.min(remaining);
            limits.exchange_timeout = limits.exchange_timeout.min(remaining);
        }
        let Some(first) = providers.next() else {
            break;
        };
        let second = providers.next();
        let (download, [worker_a, worker_b]) =
            pair_download(manifest, store, &first, second.as_ref(), limits)?;
        let observed_at = Instant::now();
        let observed_wall = now();
        let mut first_elapsed = None;
        let mut second_elapsed = None;
        let (progress, timed_out) = Box::pin(receive_pair_until(
            download,
            store,
            measured_peer(
                peer(context, policy, Some(&first.provider), worker_a),
                deadline,
                &mut first_elapsed,
            ),
            measured_peer(
                peer(
                    context,
                    policy,
                    second.as_ref().map(|source| &source.provider),
                    worker_b,
                ),
                deadline,
                &mut second_elapsed,
            ),
            deadline,
        ))
        .await?;
        if timed_out {
            content_event(context, "CONTENT_PROVIDER_TRANSFER_FAILED").await;
        }
        let same_route = RecentProviderScope::for_route(context, policy).await == scope;
        let (pair_used, pair_bytes) = record_pair(
            context,
            manifest,
            [Some(first), second],
            progress,
            [first_elapsed, second_elapsed],
            PairMeasurement {
                scope,
                observed_at,
                observed_wall,
                valid: !timed_out && same_route,
            },
        )
        .await?;
        used.extend(pair_used);
        bytes = bytes.checked_add(pair_bytes).ok_or(ContentError::Invalid)?;
    }
    Ok((used.into_iter().collect(), bytes))
}

fn pair_download(
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    first: &ProviderSource,
    second: Option<&ProviderSource>,
    limits: TransferLimits,
) -> Result<(ParallelDownload, [ChunkWorker; 2]), ContentError> {
    let alternate = second.and_then(|source| source.transport.as_ref());
    let prepared = if first.transport.is_some() || alternate.is_some() {
        ParallelDownload::new_with_transport_manifests(
            manifest,
            [
                first.transport.as_ref().unwrap_or(manifest),
                alternate.unwrap_or(manifest),
            ],
            store,
            limits,
        )
    } else {
        // Ordinary native/named/private transfers retain the original exact-manifest contract.
        ParallelDownload::new(manifest, store, limits)
    };
    prepared.map_err(|_| ContentError::Invalid)
}

struct PairMeasurement {
    scope: Option<RecentProviderScope>,
    observed_at: Instant,
    observed_wall: u64,
    valid: bool,
}

async fn record_pair(
    context: &ControlContext,
    manifest: &VerifiedManifest,
    sources: [Option<ProviderSource>; 2],
    progress: [TransferProgress; 2],
    elapsed: [Option<Duration>; 2],
    sample: PairMeasurement,
) -> Result<(Vec<String>, u64), ContentError> {
    let mut used = Vec::new();
    let mut bytes = 0_u64;
    for ((source, received), elapsed) in sources.into_iter().zip(progress).zip(elapsed) {
        let Some(ProviderSource {
            provider,
            transport,
        }) = source
        else {
            continue;
        };
        if let Some(scope) = sample.scope {
            let measurement =
                elapsed
                    .filter(|_| received.bytes > 0 && sample.valid)
                    .map(|elapsed| RecentProviderHint {
                        peer_id: provider.peer_id,
                        verified_bytes: received.bytes,
                        elapsed,
                    });
            remember_measurement(
                context,
                scope,
                &provider,
                measurement,
                sample.observed_at,
                sample.observed_wall,
            )
            .await;
        }
        if received.bytes == 0 {
            continue;
        }
        bytes = bytes
            .checked_add(received.bytes)
            .ok_or(ContentError::Invalid)?;
        used.push(provider.peer_id.to_string());
        context
            .content
            .remember_provider(
                provider.peer_id,
                provider.offer,
                *transport.as_ref().unwrap_or(manifest).manifest_id(),
            )
            .await;
    }
    Ok((used, bytes))
}

async fn remember_measurement(
    context: &ControlContext,
    scope: RecentProviderScope,
    provider: &DiscoveredContentProvider,
    measurement: Option<RecentProviderHint>,
    observed_at: Instant,
    observed_wall: u64,
) {
    let Some(measurement) = measurement else {
        context
            .content
            .forget_recent_provider(scope, provider.peer_id)
            .await;
        return;
    };
    let expires = provider.offer.validity().expires;
    if let Some(valid_until) =
        observed_at.checked_add(Duration::from_secs(expires.saturating_sub(observed_wall)))
    {
        context
            .content
            .observe_recent_provider(scope, measurement, expires, valid_until)
            .await;
    }
}

/// A transport/close failure cannot cancel a useful sibling or erase bytes the single
/// writer has already authenticated. Both sessions still end before a fallback begins.
/// Policy and local integrity/storage failures remain fatal; these are not clean-TLS receipts.
#[cfg(test)]
async fn receive_pair(
    download: ParallelDownload,
    store: &mut ChunkStore,
    first: impl Future<Output = Result<(), ContentError>>,
    second: impl Future<Output = Result<(), ContentError>>,
) -> Result<([TransferProgress; 2], bool), ContentError> {
    receive_pair_until(download, store, first, second, None).await
}

async fn receive_pair_until(
    download: ParallelDownload,
    store: &mut ChunkStore,
    first: impl Future<Output = Result<(), ContentError>>,
    second: impl Future<Output = Result<(), ContentError>>,
    deadline: Option<Instant>,
) -> Result<([TransferProgress; 2], bool), ContentError> {
    let mut progress = [TransferProgress::default(); 2];
    let write = async {
        let work = download.run(store, &mut progress);
        if let Some(deadline) = deadline {
            timeout_at(deadline, work)
                .await
                .unwrap_or(Err(TransferError::Timeout))
        } else {
            work.await
        }
    };
    let (written, first, second) = tokio::join!(write, first, second);
    let timed_out = match written {
        Ok(()) => false,
        Err(TransferError::Timeout) => true,
        Err(_) => return Err(ContentError::Invalid),
    } || deadline.is_some_and(|deadline| Instant::now() >= deadline);
    // A deadline-cancelled worker can close its channel before the writer polls its timer.
    // That clean coordinator EOF still consumed the source budget; it is not a speed sample.
    for outcome in [first, second] {
        match outcome {
            Ok(()) | Err(ContentError::Unavailable) => {}
            Err(error) => return Err(error),
        }
    }
    Ok((progress, timed_out))
}

async fn measured_peer(
    work: impl Future<Output = Result<bool, ContentError>>,
    deadline: Option<Instant>,
    elapsed: &mut Option<Duration>,
) -> Result<(), ContentError> {
    let started = Instant::now();
    let result = if let Some(deadline) = deadline {
        timeout_at(deadline, work)
            .await
            .map_err(|_| ContentError::Unavailable)?
    } else {
        work.await
    };
    if result? {
        *elapsed = Some(started.elapsed());
    }
    Ok(())
}

async fn peer(
    context: &ControlContext,
    policy: &volparossa_policy::VerifiedManifest,
    provider: Option<&DiscoveredContentProvider>,
    mut worker: ChunkWorker,
) -> Result<bool, ContentError> {
    let Some(provider) = provider else {
        return Ok(false);
    };
    // An earlier useful provider may have closed its idle v1 read while its sibling stalled.
    // Reopen at most once, keeping the same assignment, original deadline and byte/request limits.
    for _ in 0..2 {
        match attempt(context, policy, provider, &mut worker).await? {
            Attempt::Complete => return Ok(true),
            Attempt::Stopped => return Ok(false),
            Attempt::Retry => {}
        }
    }
    Ok(false)
}

enum Attempt {
    Complete,
    Retry,
    Stopped,
}

async fn attempt(
    context: &ControlContext,
    policy: &volparossa_policy::VerifiedManifest,
    provider: &DiscoveredContentProvider,
    worker: &mut ChunkWorker,
) -> Result<Attempt, ContentError> {
    if provider.offer.validity().expires <= now()
        || !context
            .routes
            .content_provider_is_distinct(&provider.peer_id)
            .await
    {
        return Ok(Attempt::Stopped);
    }
    let current = context
        .state
        .read()
        .await
        .active_policy(unix_millis())
        .ok_or(ContentError::Policy)?;
    if current.policy_hash() != policy.policy_hash() {
        return Err(ContentError::Policy);
    }
    let endpoint = provider.offer.endpoint();
    let Ok(mut flow) = context
        .routes
        .open_content_stream(
            &current,
            endpoint.hostname(),
            endpoint.port(),
            unix_millis(),
        )
        .await
    else {
        content_event(context, "CONTENT_PROVIDER_ROUTE_FLOW_FAILED").await;
        return Ok(Attempt::Stopped);
    };
    let Ok(mut stream) = tls::connect(flow.stream_mut(), provider.peer_id, &provider.offer).await
    else {
        content_event(context, "CONTENT_PROVIDER_TLS_FAILED").await;
        return Ok(Attempt::Stopped);
    };
    let pulled = pull_publication_worker(&mut stream, worker).await;
    if pulled.is_ok() && tls::finish(&mut stream).await.is_err() {
        content_event(context, "CONTENT_PROVIDER_TLS_CLOSE_FAILED").await;
        return Err(ContentError::Unavailable);
    }
    drop(stream);
    if pulled.is_ok() && tls::finish(flow.stream_mut()).await.is_err() {
        content_event(context, "CONTENT_PROVIDER_ROUTE_CLOSE_FAILED").await;
        return Err(ContentError::Unavailable);
    }
    flow.shutdown();
    if pulled.is_err() {
        content_event(context, "CONTENT_PROVIDER_TRANSFER_FAILED").await;
    }
    if pulled.is_ok() {
        return Ok(Attempt::Complete);
    }
    Ok(
        if worker.has_resumable_assignment()
            && matches!(
                pulled,
                Err(ProviderError::Io(_)
                    | ProviderError::Timeout
                    | ProviderError::Transfer(TransferError::Io(_) | TransferError::Timeout))
            )
        {
            Attempt::Retry
        } else {
            Attempt::Stopped
        },
    )
}
