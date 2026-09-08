//! Own-origin whole-object digest retrieval; provider signatures are only transport indexes.

use std::{path::PathBuf, time::Duration};

use tokio::time::{Instant, timeout_at};
use volparossa_content::origin_https::{
    OriginAuthorizedDigest, OriginClient, OriginLimits, OriginRequest,
};
use volparossa_content::provider::digest::{DigestQuery, lookup_publication};
use volparossa_content::transfer::TransferLimits;
use volparossa_content::{ChunkStore, SignedManifest};
use volparossa_local_control::{ContentReceipt, HttpsContentFetchRequest, HttpsSourceStrategy};
use volparossa_policy::VerifiedManifest as VerifiedPolicy;

use super::super::{
    ContentError, content_event, download_cache, limits, now, parallel,
    recent::RecentProviderScope, tls,
};
use super::{
    Authorization, PreparedDownload, checked_policy, load_roots, open_origin_stream, sources,
};
use crate::{control::ControlContext, discovery::DiscoveredContentProvider, unix_millis};

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
    let (providers, deadline) = match strategy {
        HttpsSourceStrategy::OriginOnly => {
            content_event(context, "CONTENT_HTTPS_SOURCE_EXPLICIT_ORIGIN").await;
            return Ok((None, Vec::new(), 0));
        }
        HttpsSourceStrategy::PeersFirst => {
            content_event(context, "CONTENT_HTTPS_SOURCE_EXPLICIT_PEERS").await;
            let deadline = started + Duration::from_secs(30);
            let Ok(Ok(providers)) = timeout_at(
                deadline,
                context
                    .discovery
                    .discover_content_providers(scope.control_peer, 16),
            )
            .await
            else {
                return Ok((None, Vec::new(), 0));
            };
            if providers.len() > 16 {
                return Err(ContentError::Invalid);
            }
            (providers, deadline)
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
                return Ok((None, Vec::new(), 0));
            };
            let hints = context.content.recent_provider_hints(scope).await;
            let Some(plan) = sources::PeerPlan::new(estimate, authority.length(), &hints) else {
                content_event(context, "CONTENT_HTTPS_SOURCE_ORIGIN_PREFERRED").await;
                return Ok((None, Vec::new(), 0));
            };
            let providers = context
                .content
                .refresh_recent_provider_hints(scope, &context.discovery, plan.lookup_budget)
                .await;
            let refreshed = hints
                .into_iter()
                .filter(|hint| providers.iter().any(|peer| peer.peer_id == hint.peer_id))
                .collect::<Vec<_>>();
            if !plan.admits_refreshed(authority.length(), &refreshed, started.elapsed()) {
                return Ok((None, Vec::new(), 0));
            }
            content_event(context, "CONTENT_HTTPS_SOURCE_MEASURED_PEERS").await;
            (providers, started + plan.total_budget)
        }
    };
    let mut candidate = None;
    for provider in &providers {
        if Instant::now() >= deadline {
            break;
        }
        let result = timeout_at(deadline, lookup(context, authority, policy, provider)).await;
        if let Ok(Ok(Some(signed))) = result {
            candidate = Some(signed);
            break;
        }
    }
    let Some(signed) = candidate else {
        return Ok((None, Vec::new(), 0));
    };
    checked_policy(context, origin, policy).await?;
    let manifest = authority
        .verify_candidate(&signed, now())
        .map_err(|_| ContentError::Unavailable)?;
    let remaining = deadline.saturating_duration_since(Instant::now());
    if remaining.is_zero() {
        return Ok((None, Vec::new(), 0));
    }
    let attempted = providers
        .iter()
        .map(|peer| peer.peer_id)
        .collect::<Vec<_>>();
    let received =
        parallel::pull_with_budget(context, &manifest, store, policy, providers, remaining).await;
    let (providers, bytes) = match received {
        Ok(progress) => progress,
        Err(ContentError::Unavailable) => (Vec::new(), 0),
        Err(error) => return Err(error),
    };
    if authority.verify_cached(&manifest, store, now()).is_ok() {
        return Ok((Some(signed), providers, bytes));
    }
    for peer in attempted {
        context.content.forget_recent_provider(scope, peer).await;
    }
    content_event(context, "CONTENT_HTTPS_DIGEST_PEERS_INCOMPLETE").await;
    Ok((None, providers, bytes))
}

async fn lookup(
    context: &ControlContext,
    authority: &OriginAuthorizedDigest,
    policy: &VerifiedPolicy,
    provider: &DiscoveredContentProvider,
) -> Result<Option<SignedManifest>, ContentError> {
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
    authority
        .verify_candidate(candidate.signed(), now())
        .map_err(|_| ContentError::Invalid)?;
    Ok(Some(candidate.signed().clone()))
}
