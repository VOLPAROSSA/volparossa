//! Resource-leased protected provider streams and one independently verified cache writer.

use std::{
    collections::BTreeSet,
    future::Future,
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use tokio::time::{Instant, timeout_at};

#[cfg(test)]
mod adaptive_tests;
mod continuation;
mod drivers;
#[cfg(test)]
mod tests;

use volparossa_content::{
    ChunkStore, VerifiedManifest,
    provider::{ProviderError, pull_publication_worker},
    transfer::{
        TransferError, TransferLimits, TransferProgress,
        parallel::{ChunkWorker, ParallelDownload, ResourceRetired},
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

/// Actual joined-worker wall time; each source completed setup, bytes and clean close.
pub(super) struct CompletedBatch {
    pub(super) started: Instant,
    pub(super) elapsed: Duration,
}

#[derive(Default)]
pub(super) struct IndexedReceipt {
    pub(super) providers: Vec<String>,
    pub(super) bytes: u64,
    pub(super) completed: Option<CompletedBatch>,
}

impl IndexedReceipt {
    fn progress(self) -> (Vec<String>, u64) {
        (self.providers, self.bytes)
    }
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
    .map(IndexedReceipt::progress)
}

/// A source-selection budget, not a new transfer protocol or a renewed operation deadline.
/// Verified writer progress survives the deadline; all workers end before origin can start.
pub(super) async fn pull_with_budget(
    context: &ControlContext,
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    policy: &volparossa_policy::VerifiedManifest,
    providers: Vec<DiscoveredContentProvider>,
    budget: Duration,
) -> Result<(Vec<String>, u64), ContentError> {
    if providers.len() > super::recent::OFFER_BATCH {
        return Err(ContentError::Invalid);
    }
    if budget.is_zero() {
        return Ok((Vec::new(), 0));
    }
    let deadline = Instant::now()
        .checked_add(budget)
        .ok_or(ContentError::Invalid)?;
    pull_until(context, manifest, store, policy, providers, deadline).await
}

/// Preserve a caller's absolute session deadline across discovery and successive batches.
/// Partial verified progress survives exhaustion; no batch renews protected-stream lifetime.
pub(super) async fn pull_until(
    context: &ControlContext,
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    policy: &volparossa_policy::VerifiedManifest,
    providers: Vec<DiscoveredContentProvider>,
    deadline: Instant,
) -> Result<(Vec<String>, u64), ContentError> {
    if providers.len() > super::recent::OFFER_BATCH {
        return Err(ContentError::Invalid);
    }
    pull_inner(
        context,
        manifest,
        store,
        policy,
        exact_sources(providers),
        Some(deadline),
    )
    .await
    .map(IndexedReceipt::progress)
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
) -> Result<IndexedReceipt, ContentError> {
    if providers.len() > super::recent::OFFER_BATCH {
        return Err(ContentError::Invalid);
    }
    if budget.is_zero() {
        return Ok(IndexedReceipt::default());
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

fn distinct_sources(providers: Vec<ProviderSource>) -> Result<Vec<ProviderSource>, ContentError> {
    if providers.len() > 16 {
        return Err(ContentError::Invalid);
    }
    let mut seen = BTreeSet::new();
    Ok(providers
        .into_iter()
        .filter(|source| seen.insert(source.provider.peer_id))
        .collect())
}

async fn pull_inner(
    context: &ControlContext,
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    policy: &volparossa_policy::VerifiedManifest,
    providers: Vec<ProviderSource>,
    deadline: Option<Instant>,
) -> Result<IndexedReceipt, ContentError> {
    let providers = distinct_sources(providers)?;
    if providers.is_empty() || complete(manifest, store)? {
        return Ok(IndexedReceipt::default());
    }
    let mut limits = TransferLimits::default();
    let deadline = deadline.unwrap_or_else(|| Instant::now() + limits.session_timeout);
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Ok(IndexedReceipt::default());
    }
    limits.session_timeout = limits.session_timeout.min(remaining);
    limits.exchange_timeout = limits.exchange_timeout.min(remaining);
    // One bounded, opt-in summary of the actual admission decisions, including a zero
    // allowance or interrupted batch. It contains no publication or provider identity.
    // The inner future owns all workers, so leases drain before the summary is dropped.
    let budget = context.content.worker_budget.for_batch();
    let result = async {
        let allowance = budget.available_workers();
        if allowance == 0 {
            return Ok(IndexedReceipt::default());
        }
        let (download, workers) = prepare_download(manifest, store, &providers, limits, allowance)?;
        let scope = RecentProviderScope::for_route(context, policy).await;
        let observed_at = Instant::now();
        let observed_wall = now();
        let active = AtomicUsize::new(0);
        let drivers = workers
            .into_iter()
            .zip(&providers)
            .map(|(worker, source)| {
                drivers::assigned(
                    worker,
                    deadline,
                    &active,
                    || budget.try_acquire(),
                    move |worker| peer(context, policy, &source.provider, worker),
                )
            })
            .collect();
        let (mut progress, measurements, mut timed_out, retired) =
            Box::pin(receive_workers_retired(
                download,
                store,
                drivers,
                || budget.allowance(active.load(Ordering::Acquire)),
                deadline,
            ))
            .await?;
        let resumed = continuation::RetiredBatch {
            manifest,
            progress: &mut progress,
            measurements: &measurements,
            retired,
            deadline,
        }
        .resume(
            store,
            &ProtectedContinuations {
                context,
                policy,
                manifest,
                providers: &providers,
                budget: &budget,
                active: &active,
                deadline,
                scope,
            },
        )
        .await?;
        timed_out |= resumed.timed_out;
        let elapsed = observed_at.elapsed();
        if timed_out {
            content_event(context, "CONTENT_PROVIDER_TRANSFER_FAILED").await;
            content_event(context, "CONTENT_PROVIDER_TRANSFER_DEADLINE").await;
        }
        let same_route = RecentProviderScope::for_route(context, policy).await == scope;
        record_batch(
            context,
            manifest,
            providers,
            progress,
            measurements,
            BatchMeasurement {
                scope,
                observed_at,
                observed_wall,
                elapsed,
                // Serial recovery is useful authenticated progress, not an ordinary clean
                // concurrent-batch cost sample or a new throughput improvement claim.
                valid: !timed_out && same_route && !resumed.attempted,
            },
        )
        .await
    }
    .await;
    // Ok can contain partial progress: diagnostics call this "returned", not "complete".
    budget.finish(result.is_ok());
    result
}

struct ProtectedContinuations<'a> {
    context: &'a ControlContext,
    policy: &'a volparossa_policy::VerifiedManifest,
    manifest: &'a VerifiedManifest,
    providers: &'a [ProviderSource],
    budget: &'a super::worker_budget::BatchBudget<'a>,
    active: &'a AtomicUsize,
    deadline: Instant,
    scope: Option<RecentProviderScope>,
}

impl continuation::Sources for ProtectedContinuations<'_> {
    fn available(&self) -> bool {
        self.budget.available_workers() > 0
    }

    fn active_workers(&self) -> &AtomicUsize {
        self.active
    }

    fn transport(&self, index: usize) -> &VerifiedManifest {
        self.providers[index]
            .transport
            .as_ref()
            .unwrap_or(self.manifest)
    }

    async fn receive(
        &self,
        index: usize,
        download: ParallelDownload,
        worker: ChunkWorker,
        store: &mut ChunkStore,
        diagnostic: &continuation::diagnostics::Diagnostics<'_>,
    ) -> Result<(TransferProgress, bool), ContentError> {
        if self.scope.is_none()
            || RecentProviderScope::for_route(self.context, self.policy).await != self.scope
        {
            return Err(ContentError::Policy);
        }
        let driver = drivers::assigned(
            worker,
            self.deadline,
            self.active,
            || self.budget.try_acquire(),
            |mut worker| async move {
                // This callback runs only after actual resource-lease admission.
                // Admission is not a completed socket or authenticated transfer.
                diagnostic.admitted();
                // The clean original session consumed the first transport attempt.
                // This single continuation spends the last one; no nested reconnect.
                Ok(matches!(
                    attempt(
                        self.context,
                        self.policy,
                        &self.providers[index].provider,
                        &mut worker,
                    )
                    .await?,
                    Attempt::Complete
                ))
            },
        );
        let (progress, _, timed_out, retired) = receive_workers_retired(
            download,
            store,
            vec![driver],
            || self.budget.allowance(self.active.load(Ordering::Acquire)),
            self.deadline,
        )
        .await?;
        if RecentProviderScope::for_route(self.context, self.policy).await != self.scope {
            return Err(ContentError::Policy);
        }
        debug_assert!(
            retired.is_empty(),
            "continuations never renew retirement authority"
        );
        Ok((progress[0], timed_out))
    }
}

fn prepare_download(
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    sources: &[ProviderSource],
    limits: TransferLimits,
    allowance: usize,
) -> Result<(ParallelDownload, Vec<ChunkWorker>), ContentError> {
    let prepared = if sources.iter().any(|source| source.transport.is_some()) {
        let transports = sources
            .iter()
            .map(|source| source.transport.as_ref().unwrap_or(manifest))
            .collect::<Vec<_>>();
        ParallelDownload::new_adaptive_with_transport_manifests(
            manifest,
            &transports,
            store,
            limits,
            allowance,
        )
    } else {
        // Ordinary native/named/private transfers retain the original exact-manifest contract.
        ParallelDownload::new_adaptive(manifest, sources.len(), store, limits, allowance)
    };
    prepared.map_err(|_| ContentError::Invalid)
}

struct BatchMeasurement {
    scope: Option<RecentProviderScope>,
    observed_at: Instant,
    observed_wall: u64,
    valid: bool,
    elapsed: Duration,
}

async fn record_batch(
    context: &ControlContext,
    manifest: &VerifiedManifest,
    sources: Vec<ProviderSource>,
    progress: Vec<TransferProgress>,
    measurements: Vec<drivers::Measurement>,
    sample: BatchMeasurement,
) -> Result<IndexedReceipt, ContentError> {
    let completed = clean_completed_batch(manifest.length(), &progress, &measurements, &sample);
    let mut used = Vec::new();
    let mut bytes = 0_u64;
    for ((source, received), measurement) in sources.into_iter().zip(progress).zip(measurements) {
        let ProviderSource {
            provider,
            transport,
        } = source;
        if let Some(scope) = sample.scope.filter(|_| measurement.attempted) {
            let measurement = measurement
                .elapsed
                .filter(|_| received.bytes > 0 && sample.valid)
                .map(|elapsed| RecentProviderHint {
                    peer_id: provider.peer_id,
                    verified_bytes: received.bytes,
                    elapsed,
                    digest_index: None,
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
    Ok(IndexedReceipt {
        providers: used,
        bytes,
        completed,
    })
}

fn clean_completed_batch(
    length: u64,
    progress: &[TransferProgress],
    measurements: &[drivers::Measurement],
    sample: &BatchMeasurement,
) -> Option<CompletedBatch> {
    if !sample.valid
        || sample.scope.is_none()
        || sample.elapsed.is_zero()
        || progress.is_empty()
        || progress.len() != measurements.len()
        || progress.iter().any(|part| part.bytes == 0)
        || progress
            .iter()
            .try_fold(0_u64, |total, part| total.checked_add(part.bytes))?
            != length
        || measurements
            .iter()
            .any(|part| !part.attempted || part.elapsed.is_none())
    {
        return None;
    }
    Some(CompletedBatch {
        started: sample.observed_at,
        elapsed: sample.elapsed,
    })
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

#[cfg(test)]
async fn receive_workers<F: Future<Output = Result<drivers::Measurement, ContentError>>>(
    download: ParallelDownload,
    store: &mut ChunkStore,
    drivers: Vec<F>,
    allowance: impl Fn() -> usize,
    deadline: Instant,
) -> Result<(Vec<TransferProgress>, Vec<drivers::Measurement>, bool), ContentError> {
    receive_workers_retired(download, store, drivers, allowance, deadline)
        .await
        .map(|(progress, measurements, expired, _)| (progress, measurements, expired))
}

async fn receive_workers_retired<F: Future<Output = Result<drivers::Measurement, ContentError>>>(
    download: ParallelDownload,
    store: &mut ChunkStore,
    drivers: Vec<F>,
    allowance: impl Fn() -> usize,
    deadline: Instant,
) -> Result<
    (
        Vec<TransferProgress>,
        Vec<drivers::Measurement>,
        bool,
        Vec<ResourceRetired>,
    ),
    ContentError,
> {
    let mut progress = vec![TransferProgress::default(); drivers.len()];
    let write = timeout_at(
        deadline,
        download.run_with_allowance_retired(store, &mut progress, allowance),
    );
    // Every future remains owned here: cancellation drops both writer and stream owners.
    // A failed peer is collected independently, so verified siblings can still finish.
    let (written, outcomes) = tokio::join!(write, drivers::collect(drivers));
    let (retired, expired) = match written {
        Ok(Ok(retired)) => (retired, false),
        Ok(Err(TransferError::Timeout)) | Err(_) => (Vec::new(), true),
        Ok(Err(_)) => return Err(ContentError::Invalid),
    };
    let timed_out = expired || Instant::now() >= deadline;
    let measurements = outcomes.into_iter().collect::<Result<Vec<_>, _>>()?;
    Ok((progress, measurements, timed_out, retired))
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

#[cfg(test)]
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

#[cfg(test)]
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
    provider: &DiscoveredContentProvider,
    mut worker: ChunkWorker,
) -> Result<bool, ContentError> {
    // An earlier useful provider may have closed its idle v1 read while its sibling stalled.
    // Reopen at most once, keeping the same assignment, original deadline and byte/request limits.
    for attempt_number in 0..2 {
        match attempt(context, policy, provider, &mut worker).await? {
            // Retried bytes remain deliverable, but failed setup must not become a clean cost sample.
            Attempt::Complete => return Ok(attempt_number == 0),
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
    if let Err(error) = &pulled {
        content_event(context, "CONTENT_PROVIDER_TRANSFER_FAILED").await;
        content_event(context, super::provider_error_code(error)).await;
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

#[cfg(test)]
mod batch_cost_tests {
    use super::*;

    #[test]
    fn digest_batch_wall_requires_full_unique_bytes_and_every_clean_close() {
        let mut sample = BatchMeasurement {
            scope: Some(RecentProviderScope::new(
                libp2p::PeerId::random(),
                [1; 32],
                [2; 16],
            )),
            observed_at: Instant::now(),
            observed_wall: 100,
            valid: true,
            elapsed: Duration::from_secs(2),
        };
        let mut progress = [TransferProgress {
            bytes: 100,
            ..TransferProgress::default()
        }; 2];
        let mut measurements = [
            drivers::Measurement {
                attempted: true,
                elapsed: Some(Duration::from_secs(2)),
            },
            drivers::Measurement {
                attempted: true,
                elapsed: Some(Duration::from_secs(1)),
            },
        ];
        let full = clean_completed_batch(200, &progress, &measurements, &sample).unwrap();
        assert_eq!(full.started, sample.observed_at);
        assert_eq!(
            full.elapsed,
            Duration::from_secs(2),
            "joined wall, never sum of peer elapsed"
        );
        assert!(
            clean_completed_batch(201, &progress, &measurements, &sample).is_none(),
            "cached/prefix bytes are not a full peer sample"
        );
        measurements[1].elapsed = None;
        assert!(clean_completed_batch(200, &progress, &measurements, &sample).is_none());
        measurements[1].elapsed = Some(Duration::from_secs(1));
        sample.valid = false;
        assert!(clean_completed_batch(200, &progress, &measurements, &sample).is_none());
        sample.valid = true;
        progress[1].bytes = 0;
        assert!(
            clean_completed_batch(100, &progress, &measurements, &sample).is_none(),
            "unused source is not part of a measured provider cohort"
        );
    }
}
