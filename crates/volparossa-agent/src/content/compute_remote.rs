//! Short signed job RPC over the existing no-direct-exit protected provider path.

use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use libp2p::{PeerId, identity};
use sha2::{Digest, Sha256};
use tokio::{net::UnixStream, time::timeout};
use volparossa_content::provider::compute::{self as wire, dataset::verify_source};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ComputeReady, ComputeRemoteRequest, ControlResponse, ControlResult,
    Empty, compute, control_response::Payload, write_response,
};
use volparossa_policy::VerifiedManifest as VerifiedPolicy;

use super::{ContentError, ContentRuntime, now, tls};
use crate::{control::ControlContext, unix_millis};

impl ContentRuntime {
    pub(crate) async fn compute_remote(
        &self,
        remote: ComputeRemoteRequest,
        context: &ControlContext,
        local: &mut UnixStream,
        request_id: &[u8],
        ready_sent: &mut bool,
    ) -> Result<(), ContentError> {
        let _foreground = self.foreground.enter();
        // No global retrieval lock across jobs. Each RPC retains its own route/stream.
        timeout(Duration::from_secs(150), async {
            let provider_key: [u8; 32] = remote
                .provider_key
                .as_slice()
                .try_into()
                .map_err(|_| ContentError::Invalid)?;
            let public = identity::ed25519::PublicKey::try_from_bytes(&provider_key)
                .map_err(|_| ContentError::Invalid)?;
            let peer = PeerId::from_public_key(&identity::PublicKey::from(public));
            if provider_key == self.signer.verifying_key().to_bytes() {
                return Err(ContentError::Invalid);
            }
            let policy = checked_policy(context, None).await?;
            *ready_sent = true;
            send(
                local,
                request_id,
                "COMPUTE_RPC_READY",
                Payload::ComputeReady(ComputeReady {
                    provider_key: provider_key.to_vec(),
                    requester_key: self.signer.verifying_key().to_bytes().to_vec(),
                }),
            )
            .await?;
            let request = timeout(Duration::from_secs(30), compute::read_request(local))
                .await
                .map_err(|_| ContentError::Unavailable)?
                .map_err(|_| ContentError::Invalid)?;
            validate_request(&request, &self.signer)?;
            let response =
                exchange(context, peer, provider_key, &policy, &self.signer, &request).await?;
            compute::write_response(local, &response)
                .await
                .map_err(|_| ContentError::Unavailable)?;
            send(local, request_id, "COMPUTE_RPC_OK", Payload::Ack(Empty {})).await
        })
        .await
        .map_err(|_| ContentError::Unavailable)?
    }
}

fn validate_request(request: &compute::Request, signer: &SigningKey) -> Result<(), ContentError> {
    request.validate(now()).map_err(|_| ContentError::Invalid)?;
    if request.requester_key != hex::encode(signer.verifying_key().as_bytes()) {
        return Err(ContentError::Invalid);
    }
    if let compute::Operation::Submit(submit) = &request.operation {
        let publisher: [u8; 32] = hex::decode(&submit.publication.publisher_key)
            .map_err(|_| ContentError::Invalid)?
            .try_into()
            .map_err(|_| ContentError::Invalid)?;
        let publisher = VerifyingKey::from_bytes(&publisher).map_err(|_| ContentError::Invalid)?;
        let manifest =
            hex::decode(&submit.publication.manifest_hex).map_err(|_| ContentError::Invalid)?;
        let source = verify_source(
            &manifest,
            &publisher,
            &submit.publication.dataset_json,
            now(),
        )
        .map_err(|_| ContentError::Invalid)?;
        if hex::encode(source.manifest_id()) != submit.binding.dataset_manifest_id
            || source.expires() < submit.binding.expires_unix_seconds
            || source
                .derive(&submit.binding.row_indices)
                .map_err(|_| ContentError::Invalid)?
                != submit.dataset_json
            || hex::encode(Sha256::digest(submit.dataset_json.as_bytes()))
                != submit.binding.dataset_sha256
        {
            return Err(ContentError::Invalid);
        }
    }
    Ok(())
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

async fn exchange(
    context: &ControlContext,
    peer: PeerId,
    provider_key: [u8; 32],
    policy: &VerifiedPolicy,
    signer: &SigningKey,
    request: &compute::Request,
) -> Result<compute::Response, ContentError> {
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
    if !context.routes.content_provider_is_distinct(&peer).await {
        return Err(ContentError::Policy);
    }
    let mut providers = context
        .discovery
        .lookup_content_providers(control, &[peer])
        .await
        .map_err(|_| ContentError::Unavailable)?;
    if providers.len() != 1 {
        return Err(ContentError::Unavailable);
    }
    let provider = providers.pop().ok_or(ContentError::Unavailable)?;
    if provider.peer_id != peer
        || provider.offer.provider_key() != &provider_key
        || provider.offer.validity().expires <= now()
    {
        return Err(ContentError::Invalid);
    }
    checked_policy(context, Some(policy)).await?;
    if context.routes.content_discovery_control().await != Some(control)
        || !context.routes.content_provider_is_distinct(&peer).await
    {
        return Err(ContentError::Policy);
    }
    let endpoint = provider.offer.endpoint();
    let mut flow = context
        .routes
        .open_content_stream(policy, endpoint.hostname(), endpoint.port(), unix_millis())
        .await
        .map_err(|_| ContentError::Unavailable)?;
    let mut remote = tls::connect(flow.stream_mut(), peer, &provider.offer)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    let challenge = wire::begin(&mut remote, &provider_key)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    checked_policy(context, Some(policy)).await?;
    validate_request(request, signer)?;
    if provider.offer.validity().expires <= now() {
        return Err(ContentError::Unavailable);
    }
    let payload = serde_json::to_vec(request).map_err(|_| ContentError::Invalid)?;
    let bytes = wire::exchange(&mut remote, challenge, signer, payload)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    let response: compute::Response =
        serde_json::from_slice(&bytes).map_err(|_| ContentError::Invalid)?;
    if response.version != compute::VERSION || response.request_id != request.request_id {
        return Err(ContentError::Invalid);
    }
    tls::finish(&mut remote)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    drop(remote);
    tls::finish(flow.stream_mut())
        .await
        .map_err(|_| ContentError::Unavailable)?;
    flow.shutdown();
    checked_policy(context, Some(policy)).await?;
    if provider.offer.validity().expires <= now() {
        return Err(ContentError::Unavailable);
    }
    Ok(response)
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
            result: ControlResult::Ok.into(),
            diagnostic_code: code.into(),
            payload: Some(payload),
        },
    )
    .await
    .map_err(|_| ContentError::Unavailable)
}
