//! Own-origin whole-object digest retrieval; provider signatures are only transport indexes.

use std::{collections::BTreeSet, future::Future, path::PathBuf, time::Duration};

use libp2p::PeerId;
use tokio::time::{Instant, timeout_at};
use volparossa_content::origin_https::{
    OriginAuthorizedDigest, OriginClient, OriginLimits, OriginRequest,
};
use volparossa_content::provider::digest::{DigestQuery, lookup_publication};
use volparossa_content::transfer::TransferLimits;
use volparossa_content::{ChunkStore, SignedManifest, VerifiedManifest};
use volparossa_local_control::{ContentReceipt, HttpsContentFetchRequest, HttpsSourceStrategy};
use volparossa_policy::VerifiedManifest as VerifiedPolicy;

use super::super::{
    ContentError, content_event, download_cache, limits, now, parallel,
    recent::{DigestIndexCost, OFFER_BATCH, RecentProviderScope, collect_until},
    tls,
};
use super::{
    Authorization, PreparedDownload, checked_policy, load_roots, open_origin_stream, sources,
};
use crate::{control::ControlContext, discovery::DiscoveredContentProvider, unix_millis};

#[cfg(test)]
mod parallel_lookup_tests;

pub(super) async fn retrieve(
    request: HttpsContentFetchRequest,
    context: &ControlContext,
) -> Result<PreparedDownload, ContentError> {
    if !request.origin_digest || !request.metadata_path.is_empty() {
        return Err(ContentError::Invalid);
    }
    let strategy = HttpsSourceStrategy::try_from(request.source_strategy)
        .map_err(|_| ContentError::Invalid)?;
    let origin =
        OriginRequest::resource(&request.resource_url).map_err(|_| ContentError::Invalid)?;
    let cache_limits = limits(request.limits)?;
    let client = OriginClient::new(
        load_roots(&request.ca_certificates_pem).await?,
        OriginLimits::default(),
    )
    .map_err(|_| ContentError::Invalid)?;
    let policy = {
        let state = context.state.read().await;
        if !state.roles().client {
            return Err(ContentError::Policy);
        }
        state
            .active_policy(unix_millis())
            .ok_or(ContentError::Policy)?
    };
    checked_policy(context, &origin, &policy).await?;
    Box::pin(
        context
            .routes
            .connect_tcp(&context.config, &context.discovery, &context.helper),
    )
    .await
    .map_err(|_| ContentError::Unavailable)?;
    let (control, route) = context
        .routes
        .content_discovery_scope()
        .await
        .ok_or(ContentError::Unavailable)?;
    let scope = RecentProviderScope::new(control, *policy.policy_hash(), route);
    let mut flow = open_origin_stream(context, &origin, &policy).await?;
    let authenticated = client
        .authenticate_digest(flow.stream_mut(), &origin, now())
        .await;
    if authenticated.is_ok() && tls::finish(flow.stream_mut()).await.is_err() {
        return Err(ContentError::Unavailable);
    }
    flow.shutdown();
    let authority = authenticated.map_err(|_| ContentError::Unavailable)?;
    let mut store = download_cache(&request.cache, cache_limits, request.reuse_cache)?;
    if authority.length() > cache_limits.max_bytes
        || authority
            .length()
            .div_ceil(volparossa_content::CHUNK_BYTES as u64)
            > cache_limits.max_entries as u64
    {
        return Err(ContentError::Invalid);
    }
    let (candidate, providers, peer_bytes) = peers(
        context, &origin, &authority, &mut store, &policy, scope, strategy,
    )
    .await?;
    checked_policy(context, &origin, &policy).await?;
    let (signed, origin_body_bytes) = if let Some(signed) = candidate {
        (signed, 0)
    } else {
        // A peer index never authorizes guessed HTTP ranges. This mode uses one whole GET
        // after peer owners stop, and counts any earlier peer bytes rather than hiding them.
        let signed = fetch_origin(
            context, &client, &origin, &authority, &mut store, &policy, scope,
        )
        .await?;
        (signed, authority.length())
    };
    let authorized = Authorization::verified_digest(authority, signed, &mut store)
        .map_err(|_| ContentError::Unavailable)?;
    let receipt = ContentReceipt {
        bytes: authorized.manifest().length(),
        chunks: u32::try_from(authorized.manifest().chunks().len())
            .map_err(|_| ContentError::Invalid)?,
        providers_used: u32::try_from(providers.len()).map_err(|_| ContentError::Invalid)?,
        provider_peer_ids: providers,
        control_relay_peer_id: control.to_string(),
        origin_authenticated: true,
        origin_body_bytes,
        peer_bytes,
        // This mode's fallback is a normal 200 GET, not a Range request.
        origin_range_requests: 0,
        ..ContentReceipt::default()
    };
    Ok(PreparedDownload {
        origin,
        policy,
        authorized,
        store,
        source_root: PathBuf::from(request.cache),
        source_limits: cache_limits,
        receipt,
    })
}

async fn fetch_origin(
    context: &ControlContext,
    client: &OriginClient,
    origin: &OriginRequest,
    authority: &OriginAuthorizedDigest,
    store: &mut ChunkStore,
    policy: &VerifiedPolicy,
    scope: RecentProviderScope,
) -> Result<SignedManifest, ContentError> {
    let started = Instant::now();
    let mut flow = open_origin_stream(context, origin, policy).await?;
    let received = client
        .fill_digest_from_origin(
            flow.stream_mut(),
            authority,
            store,
            &context.content.signer,
            now(),
        )
        .await;
    if received.is_ok() && tls::finish(flow.stream_mut()).await.is_err() {
        return Err(ContentError::Unavailable);
    }
    flow.shutdown();
    let signed = received.map_err(|_| ContentError::Unavailable)?;
    checked_policy(context, origin, policy).await?;
    context.content.source_costs.lock().await.observe_origin(
        scope,
        origin,
        authority.length(),
        1,
        started.elapsed(),
        Instant::now(),
    );
    Ok(signed)
}

async fn peers(
    context: &ControlContext,
    origin: &OriginRequest,
    authority: &OriginAuthorizedDigest,
    store: &mut ChunkStore,
    policy: &VerifiedPolicy,
    scope: RecentProviderScope,
    strategy: HttpsSourceStrategy,
) -> Result<(Option<SignedManifest>, Vec<String>, u64), ContentError> {
    let started = Instant::now();
    let Some(initial) = initial_peers(context, origin, authority, scope, strategy, started).await
    else {
        return Ok((None, Vec::new(), 0));
    };
    let mut attempt = PeerAttempt {
        context,
        origin,
        authority,
        policy,
        scope,
        deadline: initial.deadline,
        started,
        auto: initial.auto,
        expected: None,
        looked_up: BTreeSet::new(),
        used: BTreeSet::new(),
        bytes: 0,
    };
    let mut complete = attempt.pull(initial.providers, store).await?;
    if !complete
        && strategy == HttpsSourceStrategy::PeersFirst
        && attempt.looked_up.len() < 16
        && Instant::now() < attempt.deadline
    {
        checked_policy(context, origin, policy).await?;
        // No renewed deadline or parallel origin race: retain the earlier writer's chunks
        // and receipts, then explore the remaining bounded offer pool only if necessary.
        if let Ok(Ok(providers)) = timeout_at(
            attempt.deadline,
            context
                .discovery
                .discover_content_providers(scope.control_peer, 16),
        )
        .await
        {
            complete = attempt.pull(providers, store).await?;
        }
    }
    if !complete && attempt.expected.is_some() {
        content_event(context, "CONTENT_HTTPS_DIGEST_PEERS_INCOMPLETE").await;
    }
    Ok((
        attempt
            .expected
            .filter(|_| complete)
            .map(|(signed, _)| signed),
        attempt.used.into_iter().collect(),
        attempt.bytes,
    ))
}

struct InitialPeers {
    providers: Vec<DiscoveredContentProvider>,
    deadline: Instant,
    auto: Option<sources::PeerPlan>,
}

async fn initial_peers(
    context: &ControlContext,
    origin: &OriginRequest,
    authority: &OriginAuthorizedDigest,
    scope: RecentProviderScope,
    strategy: HttpsSourceStrategy,
    started: Instant,
) -> Option<InitialPeers> {
    match strategy {
        HttpsSourceStrategy::OriginOnly => {
            content_event(context, "CONTENT_HTTPS_SOURCE_EXPLICIT_ORIGIN").await;
            None
        }
        HttpsSourceStrategy::PeersFirst => {
            content_event(context, "CONTENT_HTTPS_SOURCE_EXPLICIT_PEERS").await;
            let deadline = started + Duration::from_secs(30);
            let refresh_deadline = deadline.min(Instant::now() + Duration::from_secs(1));
            let providers = timeout_at(
                refresh_deadline,
                context.content.refresh_recent_provider_hints(
                    scope,
                    &context.discovery,
                    refresh_deadline.saturating_duration_since(Instant::now()),
                ),
            )
            .await
            .unwrap_or_default();
            Some(InitialPeers {
                providers,
                deadline,
                auto: None,
            })
        }
        HttpsSourceStrategy::Auto => {
            let estimate = context.content.source_costs.lock().await.estimate_origin(
                scope,
                origin,
                authority.length(),
                started,
            );
            let Some(estimate) = estimate else {
                content_event(context, "CONTENT_HTTPS_SOURCE_ORIGIN_UNMEASURED").await;
                return None;
            };
            let hints = context.content.recent_provider_hints(scope).await;
            let available = context.content.worker_budget.available_workers();
            let batch = context.content.source_costs.lock().await.digest_batch(
                batch_key(scope, origin, authority),
                &hints,
                Instant::now(),
                available,
            );
            let plan = match batch {
                Some(batch) => sources::PeerPlan::from_digest_batch(estimate, batch),
                None => sources::PeerPlan::new_digest(
                    estimate,
                    authority.length(),
                    &hints,
                    Instant::now(),
                    available,
                ),
            };
            let Some(plan) = plan else {
                content_event(context, "CONTENT_HTTPS_SOURCE_ORIGIN_PREFERRED").await;
                return None;
            };
            let providers = context
                .content
                .refresh_recent_provider_hints(scope, &context.discovery, plan.lookup_budget)
                .await;
            let refreshed = context
                .content
                .recent_provider_hints(scope)
                .await
                .into_iter()
                .filter(|hint| providers.iter().any(|peer| peer.peer_id == hint.peer_id))
                .collect::<Vec<_>>();
            if !plan.admits_digest_refreshed(
                authority.length(),
                &refreshed,
                started.elapsed(),
                Instant::now(),
                context.content.worker_budget.available_workers(),
            ) {
                return None;
            }
            Some(InitialPeers {
                providers,
                deadline: started + plan.total_budget,
                auto: Some(plan),
            })
        }
    }
}

struct PeerAttempt<'a> {
    context: &'a ControlContext,
    origin: &'a OriginRequest,
    authority: &'a OriginAuthorizedDigest,
    policy: &'a VerifiedPolicy,
    scope: RecentProviderScope,
    deadline: Instant,
    started: Instant,
    auto: Option<sources::PeerPlan>,
    expected: Option<(SignedManifest, VerifiedManifest)>,
    looked_up: BTreeSet<PeerId>,
    used: BTreeSet<String>,
    bytes: u64,
}

struct IndexedProvider {
    provider: DiscoveredContentProvider,
    manifest: VerifiedManifest,
    index_cost: Option<DigestIndexCost>,
}

struct LookupResult {
    signed: SignedManifest,
    manifest: VerifiedManifest,
    cost: Option<DigestIndexCost>,
}

struct IndexBatch {
    started: Instant,
    expires: u64,
}

fn batch_key(
    scope: RecentProviderScope,
    origin: &OriginRequest,
    authority: &OriginAuthorizedDigest,
) -> sources::DigestBatchKey {
    sources::DigestBatchKey::new(
        scope,
        origin,
        *authority.object_sha256(),
        authority.length(),
    )
}

impl PeerAttempt<'_> {
    async fn pull(
        &mut self,
        providers: Vec<DiscoveredContentProvider>,
        store: &mut ChunkStore,
    ) -> Result<bool, ContentError> {
        if providers.len() > OFFER_BATCH {
            return Err(ContentError::Invalid);
        }
        // This boundary excludes completed offer discovery, but includes every actual index
        // flow/batch, validation and preparation up to the existing joined-worker start.
        let index_started = Instant::now();
        let first_round = self.looked_up.is_empty();
        let mut indexed = Vec::new();
        let mut providers = providers.into_iter();
        while Instant::now() < self.deadline && self.looked_up.len() < OFFER_BATCH {
            let width = self
                .context
                .content
                .worker_budget
                .available_workers()
                .min(OFFER_BATCH);
            if width == 0 {
                break;
            }
            let mut batch = Vec::new();
            for provider in providers.by_ref() {
                if self.looked_up.len() >= OFFER_BATCH {
                    break;
                }
                if self.looked_up.insert(provider.peer_id) {
                    batch.push(provider);
                }
                if batch.len() == width {
                    break;
                }
            }
            if batch.is_empty() {
                break;
            }
            let (context, authority, policy) = (self.context, self.authority, self.policy);
            let lookups = batch
                .iter()
                .map(|provider| async move {
                    lookup(context, authority, policy, provider)
                        .await
                        .ok()
                        .flatten()
                })
                .collect();
            let results = Box::pin(lookup_many_until(lookups, self.deadline)).await;
            // Stable input order, not completion timing, determines the original expected index.
            // An error/deadline in one future never discards its sibling's completed result.
            for (provider, result) in batch.into_iter().zip(results) {
                let Some(Some(LookupResult {
                    signed,
                    manifest,
                    cost,
                })) = result
                else {
                    self.context
                        .content
                        .forget_recent_provider(self.scope, provider.peer_id)
                        .await;
                    continue;
                };
                if let Some((_, expected)) = &self.expected {
                    if !compatible_transport(expected, &manifest) {
                        continue;
                    }
                } else {
                    self.expected = Some((signed, manifest.clone()));
                }
                indexed.push(IndexedProvider {
                    provider,
                    manifest,
                    index_cost: cost,
                });
            }
        }
        let index_batch = (first_round && indexed.len() == self.looked_up.len())
            .then(|| {
                indexed
                    .iter()
                    .map(|source| source.manifest.validity().expires)
                    .min()
            })
            .flatten()
            .map(|expires| IndexBatch {
                started: index_started,
                expires,
            });
        self.pull_sources(indexed, store, index_batch).await
    }

    async fn pull_sources(
        &mut self,
        sources: Vec<IndexedProvider>,
        store: &mut ChunkStore,
        index_batch: Option<IndexBatch>,
    ) -> Result<bool, ContentError> {
        let Some((_, expected)) = &self.expected else {
            return Ok(false);
        };
        if self.authority.verify_cached(expected, store, now()).is_ok() {
            return Ok(true);
        }
        if sources.is_empty() || Instant::now() >= self.deadline {
            return Ok(false);
        }
        if !self.admits_sources(&sources).await {
            return Ok(false);
        }
        checked_policy(self.context, self.origin, self.policy).await?;
        let attempted = sources
            .iter()
            .map(|source| (source.provider.peer_id, source.index_cost))
            .collect::<Vec<_>>();
        if self.auto.is_some() {
            // Digest admission includes the real completed index round, not just old metrics.
            content_event(self.context, "CONTENT_HTTPS_SOURCE_MEASURED_PEERS").await;
        }
        let received = parallel::pull_indexed_with_budget(
            self.context,
            expected,
            store,
            self.policy,
            sources
                .into_iter()
                .map(|source| (source.provider, source.manifest))
                .collect(),
            self.deadline.saturating_duration_since(Instant::now()),
        )
        .await;
        let received = match received {
            // The writer returns its verified prefix even when a worker times out or fails.
            Ok(progress) => progress,
            Err(ContentError::Unavailable) => parallel::IndexedReceipt::default(),
            Err(error) => return Err(error),
        };
        self.used.extend(received.providers);
        self.bytes = self
            .bytes
            .checked_add(received.bytes)
            .ok_or(ContentError::Invalid)?;
        if self.authority.verify_cached(expected, store, now()).is_ok() {
            self.remember_completed(&attempted, received.completed, index_batch)
                .await;
            return Ok(true);
        }
        for (peer, _) in attempted {
            self.context
                .content
                .forget_recent_provider(self.scope, peer)
                .await;
        }
        Ok(false)
    }

    async fn remember_completed(
        &self,
        attempted: &[(PeerId, Option<DigestIndexCost>)],
        payload: Option<parallel::CompletedBatch>,
        index: Option<IndexBatch>,
    ) {
        // The final complete origin-authorized SHA check has succeeded, after all flows closed.
        let completed_at = Instant::now();
        for (peer, cost) in attempted {
            if let Some(cost) = cost.filter(|_| self.used.contains(&peer.to_string())) {
                self.context
                    .content
                    .attach_digest_index_cost(self.scope, *peer, cost)
                    .await;
            }
        }
        let (Some(payload), Some(index)) = (payload, index) else {
            return;
        };
        if self.bytes != self.authority.length()
            || attempted.len() != self.used.len()
            || attempted
                .iter()
                .any(|(peer, _)| !self.used.contains(&peer.to_string()))
        {
            return;
        }
        let peers = attempted.iter().map(|(peer, _)| *peer).collect::<Vec<_>>();
        let Some(offer_deadline) = self
            .context
            .content
            .recent_batch_deadline(self.scope, &peers)
            .await
        else {
            return;
        };
        let Ok(expires) = self.authority.check_validity(now()) else {
            return;
        };
        // A whole-second wall expiry must never round the advisory monotonic bound upward.
        let remaining = expires
            .min(index.expires)
            .saturating_sub(now())
            .saturating_sub(1);
        let deadline = offer_deadline
            .min(index.started + Duration::from_secs(60))
            .min(completed_at + Duration::from_secs(remaining));
        self.context
            .content
            .source_costs
            .lock()
            .await
            .observe_digest_batch(
                sources::DigestBatchCost {
                    key: batch_key(self.scope, self.origin, self.authority),
                    peers,
                    index: payload.started.saturating_duration_since(index.started),
                    payload: payload
                        .elapsed
                        .max(completed_at.saturating_duration_since(payload.started)),
                    deadline,
                },
                completed_at,
            );
    }

    async fn admits_sources(&self, sources: &[IndexedProvider]) -> bool {
        let Some(plan) = &self.auto else {
            return true;
        };
        let hints = self.context.content.recent_provider_hints(self.scope).await;
        let selected = sources
            .iter()
            .map(|source| source.provider.peer_id)
            .collect::<Vec<_>>();
        plan.admits_after_index(
            self.authority.length(),
            &hints,
            &selected,
            self.started.elapsed(),
            self.context.content.worker_budget.available_workers(),
        )
    }
}

/// No tasks outlive this call: each protected lookup owns its flow until completion/drop.
/// Separate timers retain completed siblings without extending the caller's shared deadline.
async fn lookup_many_until<F: Future>(
    lookups: Vec<F>,
    deadline: Instant,
) -> Vec<Option<F::Output>> {
    collect_until(lookups, deadline).await
}

fn compatible_transport(expected: &VerifiedManifest, candidate: &VerifiedManifest) -> bool {
    expected.object_sha256() == candidate.object_sha256()
        && expected.length() == candidate.length()
        && expected.metadata().content_type == "application/octet-stream"
        && candidate.metadata().content_type == expected.metadata().content_type
        && candidate.chunks() == expected.chunks()
}

async fn lookup(
    context: &ControlContext,
    authority: &OriginAuthorizedDigest,
    policy: &VerifiedPolicy,
    provider: &DiscoveredContentProvider,
) -> Result<Option<LookupResult>, ContentError> {
    let started = Instant::now();
    // Metadata uses the same process-wide protected-flow accounting as payload work.
    // This lease precedes any route/TLS socket and survives the complete close/drop.
    let Some(_lease) = context.content.worker_budget.try_acquire() else {
        return Ok(None);
    };
    if !context
        .routes
        .content_provider_is_distinct(&provider.peer_id)
        .await
    {
        return Ok(None);
    }
    let endpoint = provider.offer.endpoint();
    let mut flow = context
        .routes
        .open_content_stream(policy, endpoint.hostname(), endpoint.port(), unix_millis())
        .await
        .map_err(|_| ContentError::Unavailable)?;
    let query = DigestQuery::new(*authority.object_sha256(), authority.length())
        .map_err(|_| ContentError::Invalid)?;
    let mut stream = tls::connect(flow.stream_mut(), provider.peer_id, &provider.offer)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    let response = lookup_publication(&mut stream, &query, TransferLimits::default()).await;
    if response.is_ok() && tls::finish(&mut stream).await.is_err() {
        return Err(ContentError::Unavailable);
    }
    drop(stream);
    if response.is_ok() && tls::finish(flow.stream_mut()).await.is_err() {
        return Err(ContentError::Unavailable);
    }
    flow.shutdown();
    let Some(candidate) = response.map_err(|_| ContentError::Unavailable)? else {
        return Ok(None);
    };
    let manifest = authority
        .verify_candidate(candidate.signed(), now())
        .map_err(|_| ContentError::Invalid)?;
    Ok(Some(LookupResult {
        signed: candidate.signed().clone(),
        manifest,
        cost: DigestIndexCost::new(started.elapsed(), started),
    }))
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use volparossa_content::{
        CHUNK_BYTES, CacheLimits, Metadata, Publication, Validity,
        private_message::PRIVATE_MESSAGE_CONTENT_TYPE, publish,
    };

    use super::*;

    fn transport(mut bytes: &[u8], content_type: &str, seed: u8) -> VerifiedManifest {
        let directory = tempfile::tempdir().unwrap();
        let mut store = ChunkStore::create(
            &directory.path().join("source"),
            CacheLimits {
                max_bytes: 2 * CHUNK_BYTES as u64,
                max_entries: 2,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let key = SigningKey::from_bytes(&[seed; 32]);
        let created = now();
        let length = bytes.len() as u64;
        publish(
            &mut bytes,
            Publication {
                metadata: Metadata {
                    name: format!("transport-{seed}"),
                    revision: 1,
                    content_type: content_type.into(),
                },
                length,
                validity: Validity {
                    created,
                    expires: created + 60,
                },
            },
            &key,
            &mut store,
        )
        .unwrap()
        .verify(&key.verifying_key(), created)
        .unwrap()
    }

    #[test]
    fn digest_pair_accepts_independent_indexes_not_other_objects_or_private_types() {
        let bytes = vec![71; CHUNK_BYTES + 17];
        let expected = transport(&bytes, "application/octet-stream", 31);
        let other = transport(&bytes, "application/octet-stream", 32);
        assert_ne!(expected.manifest_id(), other.manifest_id());
        assert_ne!(expected.publisher(), other.publisher());
        assert_ne!(expected.metadata().name, other.metadata().name);
        assert_eq!(expected.chunks(), other.chunks());
        assert!(compatible_transport(&expected, &other));

        let wrong = transport(&vec![72; bytes.len()], "application/octet-stream", 32);
        assert!(!compatible_transport(&expected, &wrong));
        let private = transport(&bytes, PRIVATE_MESSAGE_CONTENT_TYPE, 32);
        assert!(!compatible_transport(&expected, &private));
        assert!(!compatible_transport(&private, &private));
    }
}
