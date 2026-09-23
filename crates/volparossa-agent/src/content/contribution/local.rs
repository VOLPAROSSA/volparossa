//! Owner-local public inbox reads from the live configured contribution service only.
//! Remote custody remains the delivery mechanism; this operation never opens an overlay route.

use std::{path::Path, sync::Arc, time::Duration};

use ed25519_dalek::VerifyingKey;
use tokio::{
    net::UnixStream,
    sync::{OwnedMutexGuard, watch},
    time::timeout,
};
use volparossa_content::{
    ChunkStore,
    provider::{
        ProviderEndpoint,
        named::{NameCandidate, NameQuery, NameResolution},
    },
    reassemble,
    transfer::{TransferLimits, serve_peer},
};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentLocalFetchNameRequest, ContentReceipt, ControlResponse,
    ControlResult, NamedContentTransferReady, control_response::Payload, write_response,
};

use super::super::{ContentError, ContentRuntime, now, serving_policy};
use crate::{control::ControlContext, unix_millis};

const TRANSFER_TIMEOUT: Duration = Duration::from_secs(30);

struct Prepared {
    selected: Box<NameCandidate>,
    store: ChunkStore,
    stop: watch::Receiver<bool>,
    endpoint: ProviderEndpoint,
    policy: volparossa_policy::VerifiedManifest,
    _slot: OwnedMutexGuard<()>,
}

impl ContentRuntime {
    pub(crate) async fn fetch_local_name(
        &self,
        request: ContentLocalFetchNameRequest,
        context: &ControlContext,
        stream: &mut UnixStream,
        request_id: &[u8],
        ready_sent: &mut bool,
    ) -> Result<(), ContentError> {
        let _foreground = self.foreground.enter();
        let _retrieval = self.retrieval.try_lock().map_err(|_| ContentError::Busy)?;
        timeout(TRANSFER_TIMEOUT, async {
            let prepared = super::super::cancellation::until_requester_closed(
                stream,
                prepare(self, &request, context),
            )
            .await?;
            deliver(prepared, context, stream, request_id, ready_sent).await
        })
        .await
        .map_err(|_| ContentError::Unavailable)?
    }
}

async fn prepare(
    owner: &ContentRuntime,
    request: &ContentLocalFetchNameRequest,
    context: &ControlContext,
) -> Result<Prepared, ContentError> {
    let publisher = request
        .publisher_key
        .as_slice()
        .try_into()
        .map_err(|_| ContentError::Invalid)?;
    let query = NameQuery::new(publisher, &request.name, request.min_revision)
        .map_err(|_| ContentError::Invalid)?;
    if !context.config.content_contribution.enabled
        || request.min_revision == 0
        || request.expected_content_type.is_empty()
        || request.max_object_bytes == 0
        || request.max_object_bytes > volparossa_content::MAX_OBJECT_BYTES
    {
        return Err(ContentError::Invalid);
    }
    // Match the existing service->contribution lock order. Never hold either owner lock while
    // waiting for the publication slot, because custody admission owns that slot first.
    let (runtime, registry, stop, endpoint) = {
        let current = owner.service.lock().await;
        let active = current.as_ref().ok_or(ContentError::Unavailable)?;
        let runtime = owner
            .contribution
            .lock()
            .await
            .clone()
            .ok_or(ContentError::Unavailable)?;
        if active.task.is_finished()
            || *active.stop.borrow()
            || !active.name_lookup
            || runtime.config.cache != context.config.content_contribution.cache
            || !active
                .replication
                .as_ref()
                .is_some_and(|value| Arc::ptr_eq(value, &runtime.replication))
        {
            return Err(ContentError::Unavailable);
        }
        (
            runtime,
            Arc::clone(&active.registry),
            active.stop.subscribe(),
            active.endpoint.clone(),
        )
    };
    let slot = runtime.replication.publication_slot().await?;
    if *stop.borrow() {
        return Err(ContentError::Unavailable);
    }
    let policy = current_policy(context, &endpoint).await?;
    let registry = registry.try_lock().map_err(|_| ContentError::Busy)?;
    let selected = match registry
        .resolve_local_name(&query, now())
        .map_err(|_| ContentError::Unavailable)?
    {
        NameResolution::Missing => return Err(ContentError::Unavailable),
        NameResolution::Conflict(_) => return Err(ContentError::NameConflict),
        NameResolution::Candidate(value) => value,
    };
    if selected.manifest().metadata().content_type != request.expected_content_type
        || selected.manifest().length() > request.max_object_bytes
        || !registry.contains_at(
            selected.manifest().manifest_id(),
            Path::new(&runtime.config.cache),
        )
    {
        return Err(ContentError::Invalid);
    }
    let mut store = registry
        .open_local_candidate(&selected, now())
        .map_err(|_| ContentError::Unavailable)?;
    // A registry may otherwise contain partial replicas. Readiness here means a complete local
    // source, not just metadata or a claim that the requester has received the object.
    reassemble(
        selected.manifest(),
        &mut [&mut store],
        now(),
        &mut std::io::sink(),
    )
    .map_err(|_| ContentError::Unavailable)?;
    drop(registry);
    Ok(Prepared {
        selected,
        store,
        stop,
        endpoint,
        policy,
        _slot: slot,
    })
}

async fn current_policy(
    context: &ControlContext,
    endpoint: &ProviderEndpoint,
) -> Result<volparossa_policy::VerifiedManifest, ContentError> {
    let policy = serving_policy(context).await?;
    policy
        .authorize_domain(
            unix_millis(),
            endpoint.hostname(),
            volparossa_policy::TransportProtocol::Tcp,
            endpoint.port(),
        )
        .map_err(|_| ContentError::Policy)?;
    Ok(policy)
}

async fn deliver(
    mut prepared: Prepared,
    context: &ControlContext,
    stream: &mut UnixStream,
    request_id: &[u8],
    ready_sent: &mut bool,
) -> Result<(), ContentError> {
    let manifest = prepared.selected.manifest();
    context.content.check_object_policy(manifest)?;
    let remaining = manifest
        .validity()
        .expires
        .saturating_mul(1000)
        .min(prepared.policy.expires_at_ms())
        .checked_sub(unix_millis())
        .filter(|value| *value > 0)
        .ok_or(ContentError::Unavailable)?;
    timeout(Duration::from_millis(remaining).min(TRANSFER_TIMEOUT), async {
        if *prepared.stop.borrow() {
            return Err(ContentError::Unavailable);
        }
        *ready_sent = true;
        send_response(stream, request_id, "LOCAL_NAMED_CONTENT_TRANSFER_READY",
            Payload::NamedContentTransferReady(NamedContentTransferReady {
                manifest: prepared.selected.signed().encode(), cache_only: true,
            })).await?;
        let progress = tokio::select! {
            biased;
            _ = prepared.stop.changed() => return Err(ContentError::Unavailable),
            () = context.content.object_policy.wait_until_withheld(manifest) => return Err(ContentError::Policy),
            result = serve_peer(stream, manifest, &mut prepared.store, TransferLimits {
                exchange_timeout: Duration::from_secs(5), session_timeout: TRANSFER_TIMEOUT,
                max_requests: manifest.chunks().len().max(1), max_bytes: manifest.length().max(1),
            }) => result.map_err(|_| ContentError::Unavailable)?,
        };
        // A requester may already hold chunks. Report the verified logical object size, not
        // invented network bytes; the transfer itself bounds and hashes every requested chunk.
        if progress.missing != 0 || *prepared.stop.borrow() {
            return Err(ContentError::Unavailable);
        }
        let publisher = VerifyingKey::from_bytes(manifest.publisher()).map_err(|_| ContentError::Invalid)?;
        prepared.selected.signed().verify(&publisher, now()).map_err(|_| ContentError::Unavailable)?;
        context.content.check_object_policy(manifest)?;
        if current_policy(context, &prepared.endpoint).await?.policy_hash() != prepared.policy.policy_hash() {
            return Err(ContentError::Policy);
        }
        send_response(stream, request_id, "CONTENT_OK", Payload::Content(ContentReceipt {
            bytes: manifest.length(), chunks: u32::try_from(manifest.chunks().len()).map_err(|_| ContentError::Invalid)?,
            ..ContentReceipt::default()
        })).await
    }).await.map_err(|_| ContentError::Unavailable)?
}

async fn send_response(
    stream: &mut UnixStream,
    id: &[u8],
    code: &str,
    payload: Payload,
) -> Result<(), ContentError> {
    write_response(
        stream,
        &ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: id.to_vec(),
            result: ControlResult::Ok as i32,
            diagnostic_code: code.into(),
            payload: Some(payload),
        },
    )
    .await
    .map_err(|_| ContentError::Unavailable)
}
