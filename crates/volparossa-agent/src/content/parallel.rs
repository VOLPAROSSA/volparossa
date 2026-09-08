//! Up to two protected provider streams, with one bounded independently verified cache writer.

use std::collections::BTreeSet;

use volparossa_content::{
    ChunkStore, VerifiedManifest,
    provider::{ProviderError, pull_publication_worker},
    transfer::{
        TransferError, TransferLimits, TransferProgress,
        parallel::{ChunkWorker, ParallelDownload},
    },
};

use super::{ContentError, complete, content_event, now, tls};
use crate::{control::ControlContext, discovery::DiscoveredContentProvider, unix_millis};

pub(super) async fn pull(
    context: &ControlContext,
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    policy: &volparossa_policy::VerifiedManifest,
    providers: Vec<DiscoveredContentProvider>,
) -> Result<(Vec<String>, u64), ContentError> {
    if providers.len() > 16 {
        return Err(ContentError::Invalid);
    }
    let mut seen = BTreeSet::new();
    let mut providers = providers
        .into_iter()
        .filter(|provider| seen.insert(provider.peer_id));
    let mut used = BTreeSet::new();
    let mut bytes = 0_u64;
    while !complete(manifest, store)? {
        let Some(first) = providers.next() else {
            break;
        };
        let second = providers.next();
        let (download, [worker_a, worker_b]) =
            ParallelDownload::new(manifest, store, TransferLimits::default())
                .map_err(|_| ContentError::Invalid)?;
        let mut progress = [TransferProgress::default(); 2];
        let (written, peers) = tokio::join!(download.run(store, &mut progress), async {
            tokio::try_join!(
                peer(context, policy, Some(first), worker_a),
                peer(context, policy, second, worker_b),
            )
        },);
        match written {
            Ok(()) => {}
            Err(TransferError::Timeout) => {
                content_event(context, "CONTENT_PROVIDER_TRANSFER_FAILED").await;
            }
            Err(_) => return Err(ContentError::Invalid),
        }
        let (first, second) = peers?;
        for (provider, received) in [first, second].into_iter().zip(progress) {
            let Some(provider) = provider else {
                continue;
            };
            if received.bytes == 0 {
                continue;
            }
            bytes = bytes
                .checked_add(received.bytes)
                .ok_or(ContentError::Invalid)?;
            used.insert(provider.peer_id.to_string());
            context
                .content
                .remember_provider(provider.peer_id, provider.offer, *manifest.manifest_id())
                .await;
        }
    }
    Ok((used.into_iter().collect(), bytes))
}

async fn peer(
    context: &ControlContext,
    policy: &volparossa_policy::VerifiedManifest,
    provider: Option<DiscoveredContentProvider>,
    mut worker: ChunkWorker,
) -> Result<Option<DiscoveredContentProvider>, ContentError> {
    let Some(provider) = provider else {
        return Ok(None);
    };
    // An earlier useful provider may have closed its idle v1 read while its sibling stalled.
    // Reopen at most once, keeping the same assignment, original deadline and byte/request limits.
    for _ in 0..2 {
        if !attempt(context, policy, &provider, &mut worker).await? {
            break;
        }
    }
    Ok(Some(provider))
}

async fn attempt(
    context: &ControlContext,
    policy: &volparossa_policy::VerifiedManifest,
    provider: &DiscoveredContentProvider,
    worker: &mut ChunkWorker,
) -> Result<bool, ContentError> {
    if provider.offer.validity().expires <= now()
        || !context
            .routes
            .content_provider_is_distinct(&provider.peer_id)
            .await
    {
        return Ok(false);
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
        return Ok(false);
    };
    let Ok(mut stream) = tls::connect(flow.stream_mut(), provider.peer_id, &provider.offer).await
    else {
        content_event(context, "CONTENT_PROVIDER_TLS_FAILED").await;
        return Ok(false);
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
    Ok(worker.has_resumable_assignment()
        && matches!(
            pulled,
            Err(ProviderError::Io(_)
                | ProviderError::Timeout
                | ProviderError::Transfer(TransferError::Io(_) | TransferError::Timeout))
        ))
}
