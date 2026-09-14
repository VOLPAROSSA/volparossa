//! Publisher signing stays in the CLI; public deposits use the existing protected provider route.

use std::time::Duration;

use ed25519_dalek::VerifyingKey;
use libp2p::{PeerId, identity};
use tokio::{net::UnixStream, time::timeout};
use volparossa_content::{
    SignedManifest, VerifiedManifest,
    private_message::PRIVATE_MESSAGE_CONTENT_TYPE,
    provider::custody::{self, CustodyOperation, CustodyState},
    transfer::TransferLimits,
};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentCustodyReady, ContentCustodyRequest, ContentReceipt,
    ControlResponse, ControlResult, control_response::Payload, write_response,
};
use volparossa_policy::VerifiedManifest as VerifiedPolicy;

use super::{ContentError, ContentRuntime, OPERATION_TIMEOUT, now, tls};
use crate::{control::ControlContext, discovery::DiscoveredContentProvider, unix_millis};

struct Request {
    provider_key: [u8; 32],
    peer: PeerId,
    signed: SignedManifest,
    manifest: VerifiedManifest,
    operation: CustodyOperation,
}

impl ContentRuntime {
    pub(crate) async fn custody_remote(
        &self,
        request: ContentCustodyRequest,
        context: &ControlContext,
        local: &mut UnixStream,
        request_id: &[u8],
        ready_sent: &mut bool,
    ) -> Result<(), ContentError> {
        let _foreground = self.foreground.enter();
        let _retrieval = self.retrieval.try_lock().map_err(|_| ContentError::Busy)?;
        timeout(
            OPERATION_TIMEOUT,
            remote(request, context, local, request_id, ready_sent),
        )
        .await
        .map_err(|_| ContentError::Unavailable)?
    }
}

fn validate(request: &ContentCustodyRequest) -> Result<Request, ContentError> {
    let provider_key: [u8; 32] = request
        .provider_key
        .as_slice()
        .try_into()
        .map_err(|_| ContentError::Invalid)?;
    let publisher: [u8; 32] = request
        .publisher_key
        .as_slice()
        .try_into()
        .map_err(|_| ContentError::Invalid)?;
    let key = VerifyingKey::from_bytes(&publisher).map_err(|_| ContentError::Invalid)?;
    let signed = SignedManifest::decode(&request.manifest).map_err(|_| ContentError::Invalid)?;
    let manifest = signed
        .verify(&key, now())
        .map_err(|_| ContentError::Invalid)?;
    if manifest.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE {
        return Err(ContentError::Policy);
    }
    let public = identity::ed25519::PublicKey::try_from_bytes(&provider_key)
        .map_err(|_| ContentError::Invalid)?;
    Ok(Request {
        provider_key,
        peer: PeerId::from_public_key(&identity::PublicKey::from(public)),
        signed,
        manifest,
        operation: CustodyOperation::try_from(request.operation)
            .map_err(|_| ContentError::Invalid)?,
    })
}

async fn checked_policy(
    context: &ControlContext,
    original: Option<&VerifiedPolicy>,
) -> Result<VerifiedPolicy, ContentError> {
    let state = context.state.read().await;
    let policy = state
        .active_policy(unix_millis())
        .ok_or(ContentError::Policy)?;
    if !state.roles().client
        || original.is_some_and(|old| old.policy_hash() != policy.policy_hash())
    {
        return Err(ContentError::Policy);
    }
    Ok(policy)
}

async fn remote(
    request: ContentCustodyRequest,
    context: &ControlContext,
    local: &mut UnixStream,
    id: &[u8],
    ready_sent: &mut bool,
) -> Result<(), ContentError> {
    let request = validate(&request)?;
    let policy = checked_policy(context, None).await?;
    Box::pin(
        context
            .routes
            .connect_tcp(&context.config, &context.discovery, &context.helper),
    )
    .await
    .map_err(|_| ContentError::Unavailable)?;
    let control = context
        .routes
        .content_discovery_control()
        .await
        .ok_or(ContentError::Unavailable)?;
    if !context
        .routes
        .content_provider_is_distinct(&request.peer)
        .await
    {
        return Err(ContentError::Policy);
    }
    let mut providers = context
        .discovery
        .lookup_content_providers(control, &[request.peer])
        .await
        .map_err(|_| ContentError::Unavailable)?;
    if providers.len() != 1 {
        return Err(ContentError::Unavailable);
    }
    let provider = providers.pop().ok_or(ContentError::Unavailable)?;
    if provider.peer_id != request.peer || provider.offer.provider_key() != &request.provider_key {
        return Err(ContentError::Invalid);
    }
    let expires = request
        .manifest
        .validity()
        .expires
        .min(provider.offer.validity().expires);
    let remaining = expires
        .checked_sub(now())
        .filter(|seconds| *seconds > 0)
        .ok_or(ContentError::Unavailable)?;
    timeout(
        Duration::from_secs(remaining.min(150)),
        exchange(
            &request, provider, &policy, control, context, local, id, ready_sent,
        ),
    )
    .await
    .map_err(|_| ContentError::Unavailable)?
}

#[allow(
    clippy::too_many_arguments,
    reason = "Exact retained request, route and same-socket handoff owners"
)]
async fn exchange(
    request: &Request,
    provider: DiscoveredContentProvider,
    policy: &VerifiedPolicy,
    control: PeerId,
    context: &ControlContext,
    local: &mut UnixStream,
    id: &[u8],
    ready_sent: &mut bool,
) -> Result<(), ContentError> {
    let current = checked_policy(context, Some(policy)).await?;
    if context.routes.content_discovery_control().await != Some(control)
        || !context
            .routes
            .content_provider_is_distinct(&request.peer)
            .await
    {
        return Err(ContentError::Policy);
    }
    super::check_publication_time(&request.manifest)?;
    let endpoint = provider.offer.endpoint();
    let mut flow = context
        .routes
        .open_content_stream(
            &current,
            endpoint.hostname(),
            endpoint.port(),
            unix_millis(),
        )
        .await
        .map_err(|_| ContentError::Unavailable)?;
    let mut remote = tls::connect(flow.stream_mut(), request.peer, &provider.offer)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    let challenge = custody::begin(&mut remote, &request.provider_key)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    checked_policy(context, Some(policy)).await?;
    super::check_publication_time(&request.manifest)?;
    *ready_sent = true;
    send(
        local,
        id,
        "CONTENT_CUSTODY_READY",
        Payload::ContentCustodyReady(ContentCustodyReady {
            provider_key: request.provider_key.to_vec(),
            challenge: challenge.encode(),
        }),
    )
    .await?;
    let receipt = custody::bridge(
        local,
        &mut remote,
        &challenge,
        &request.signed,
        request.operation,
        TransferLimits::default(),
    )
    .await
    .map_err(|_| ContentError::Unavailable)?;
    tls::finish(&mut remote)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    drop(remote);
    tls::finish(flow.stream_mut())
        .await
        .map_err(|_| ContentError::Unavailable)?;
    flow.shutdown();
    checked_policy(context, Some(policy)).await?;
    super::check_publication_time(&request.manifest)?;
    if provider.offer.validity().expires <= now() {
        return Err(ContentError::Unavailable);
    }
    let complete = receipt.state() == CustodyState::Complete;
    // Retained logical object size, not wire-upload accounting (a retry may send no new bytes).
    send(
        local,
        id,
        "CONTENT_OK",
        Payload::Content(ContentReceipt {
            bytes: if complete { receipt.object_bytes() } else { 0 },
            chunks: if complete { receipt.unique_chunks() } else { 0 },
            network_publication: complete,
            providers_used: 1,
            provider_peer_ids: vec![request.peer.to_string()],
            control_relay_peer_id: control.to_string(),
            ..ContentReceipt::default()
        }),
    )
    .await
}

async fn send(
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
