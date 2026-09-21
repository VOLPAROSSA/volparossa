//! Short signed job RPC over the existing no-direct-exit protected provider path.

use std::time::Duration;

use ed25519_dalek::{SigningKey, VerifyingKey};
use libp2p::{PeerId, identity};
use sha2::{Digest, Sha256};
use tokio::{net::UnixStream, time::timeout};
use volparossa_content::provider::compute::{self as wire, dataset::verify_source};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ComputeReady, ComputeRemoteRequest, ComputeTranscript,
    ControlResponse, ControlResult, Empty, compute, control_response::Payload, write_response,
};
use volparossa_policy::VerifiedManifest as VerifiedPolicy;

use super::{ContentError, ContentRuntime, now, tls};
use crate::{control::ControlContext, discovery::DiscoveredContentProvider, unix_millis};

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
        let mut stage = "COMPUTE_RPC_LOCAL_REQUEST_FAILED";
        let result = timeout(Duration::from_secs(150), async {
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
            validate_transcript_operation(&request.operation, remote.retain_transcript)?;
            validate_request(&request, &self.signer)?;
            let (response, transcript) = exchange(
                context,
                peer,
                provider_key,
                &policy,
                &self.signer,
                &request,
                remote.retain_transcript,
                &mut stage,
            )
            .await?;
            stage = "COMPUTE_RPC_LOCAL_REPLY_FAILED";
            compute::write_response(local, &response)
                .await
                .map_err(|_| ContentError::Unavailable)?;
            let payload = final_payload(remote.retain_transcript, transcript)?;
            send(local, request_id, "COMPUTE_RPC_OK", payload).await
        })
        .await
        .map_err(|_| ContentError::Unavailable)
        .and_then(std::convert::identity);
        if result.is_err() {
            // Fixed codes only in the existing bounded in-memory log: no requester,
            // provider, task ID, prompt, hostname, result or upstream exception text.
            // An EOF after READY must not hide which boundary actually failed.
            super::content_event(context, stage).await;
        }
        result
    }
}

fn validate_transcript_operation(
    operation: &compute::Operation,
    retain_transcript: bool,
) -> Result<(), ContentError> {
    if retain_transcript && !matches!(operation, compute::Operation::Poll(_)) {
        return Err(ContentError::Invalid);
    }
    Ok(())
}

fn final_payload(
    retain_transcript: bool,
    transcript: Option<Vec<u8>>,
) -> Result<Payload, ContentError> {
    match (retain_transcript, transcript) {
        (false, None) => Ok(Payload::Ack(Empty {})),
        (true, Some(transcript))
            if !transcript.is_empty() && transcript.len() <= wire::MAX_TRANSCRIPT_BYTES =>
        {
            Ok(Payload::ComputeTranscript(ComputeTranscript { transcript }))
        }
        _ => Err(ContentError::Invalid),
    }
}

pub(super) fn validate_request(
    request: &compute::Request,
    signer: &SigningKey,
) -> Result<(), ContentError> {
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
            || super::compute::derive_submission(&source, &submit.binding)
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

pub(super) async fn checked_policy(
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

#[allow(
    clippy::too_many_arguments,
    reason = "The explicit retention flag stays attached to the original bounded signed exchange"
)]
async fn exchange(
    context: &ControlContext,
    peer: PeerId,
    provider_key: [u8; 32],
    policy: &VerifiedPolicy,
    signer: &SigningKey,
    request: &compute::Request,
    retain_transcript: bool,
    stage: &mut &'static str,
) -> Result<(compute::Response, Option<Vec<u8>>), ContentError> {
    *stage = "COMPUTE_RPC_ROUTE_SETUP_FAILED";
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
    *stage = "COMPUTE_RPC_DISCOVERY_FAILED";
    let mut providers = context
        .discovery
        .lookup_content_providers(control, &[peer])
        .await
        .map_err(|_| ContentError::Unavailable)?;
    if providers.len() != 1 {
        return Err(ContentError::Unavailable);
    }
    let provider = providers.pop().ok_or(ContentError::Unavailable)?;
    *stage = "COMPUTE_RPC_OFFER_BINDING_FAILED";
    if provider.peer_id != peer || provider.offer.provider_key() != &provider_key {
        return Err(ContentError::Invalid);
    }
    exchange_offer_retained(
        context,
        control,
        &provider,
        policy,
        signer,
        request,
        retain_transcript,
        stage,
    )
    .await
}

/// Use an already verified CONTENT offer, never a direct provider dial or second lookup.
pub(super) async fn exchange_offer(
    context: &ControlContext,
    control: PeerId,
    provider: &DiscoveredContentProvider,
    policy: &VerifiedPolicy,
    signer: &SigningKey,
    request: &compute::Request,
    stage: &mut &'static str,
) -> Result<compute::Response, ContentError> {
    exchange_offer_retained(
        context, control, provider, policy, signer, request, false, stage,
    )
    .await
    .map(|(response, _)| response)
}

#[allow(
    clippy::too_many_arguments,
    reason = "An existing authenticated offer and explicit Poll-only retention share the unchanged route lifecycle"
)]
async fn exchange_offer_retained(
    context: &ControlContext,
    control: PeerId,
    provider: &DiscoveredContentProvider,
    policy: &VerifiedPolicy,
    signer: &SigningKey,
    request: &compute::Request,
    retain_transcript: bool,
    stage: &mut &'static str,
) -> Result<(compute::Response, Option<Vec<u8>>), ContentError> {
    validate_transcript_operation(&request.operation, retain_transcript)?;
    let peer = provider.peer_id;
    let provider_key = *provider.offer.provider_key();
    let public = identity::ed25519::PublicKey::try_from_bytes(&provider_key)
        .map_err(|_| ContentError::Invalid)?;
    *stage = "COMPUTE_RPC_OFFER_BINDING_FAILED";
    if PeerId::from_public_key(&identity::PublicKey::from(public)) != peer
        || provider_key == signer.verifying_key().to_bytes()
        || provider.offer.validity().expires <= now()
    {
        return Err(ContentError::Invalid);
    }
    *stage = "COMPUTE_RPC_ROUTE_BINDING_FAILED";
    checked_route(context, policy, control, peer).await?;
    let endpoint = provider.offer.endpoint();
    *stage = "COMPUTE_RPC_ROUTE_FLOW_FAILED";
    let mut flow = context
        .routes
        .open_content_stream(policy, endpoint.hostname(), endpoint.port(), unix_millis())
        .await
        .map_err(|_| ContentError::Unavailable)?;
    *stage = "COMPUTE_RPC_PROVIDER_TLS_FAILED";
    let mut remote = tls::connect(flow.stream_mut(), peer, &provider.offer)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    *stage = "COMPUTE_RPC_CHALLENGE_FAILED";
    let challenge = wire::begin(&mut remote, &provider_key)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    *stage = "COMPUTE_RPC_PREEXPORT_CHECK_FAILED";
    checked_route(context, policy, control, peer).await?;
    validate_request(request, signer)?;
    if provider.offer.validity().expires <= now() {
        return Err(ContentError::Unavailable);
    }
    let payload = serde_json::to_vec(request).map_err(|_| ContentError::Invalid)?;
    *stage = "COMPUTE_RPC_SIGNED_EXCHANGE_FAILED";
    let (bytes, transcript) = if retain_transcript {
        let (bytes, transcript) = wire::exchange_attested(&mut remote, challenge, signer, payload)
            .await
            .map_err(|_| ContentError::Unavailable)?
            .into_parts();
        if transcript.is_empty() || transcript.len() > wire::MAX_TRANSCRIPT_BYTES {
            return Err(ContentError::Invalid);
        }
        (bytes, Some(transcript))
    } else {
        (
            wire::exchange(&mut remote, challenge, signer, payload)
                .await
                .map_err(|_| ContentError::Unavailable)?,
            None,
        )
    };
    *stage = "COMPUTE_RPC_REPLY_BINDING_FAILED";
    let response: compute::Response =
        serde_json::from_slice(&bytes).map_err(|_| ContentError::Invalid)?;
    if response.version != compute::VERSION || response.request_id != request.request_id {
        return Err(ContentError::Invalid);
    }
    *stage = "COMPUTE_RPC_PROVIDER_CLOSE_FAILED";
    tls::finish(&mut remote)
        .await
        .map_err(|_| ContentError::Unavailable)?;
    drop(remote);
    *stage = "COMPUTE_RPC_ROUTE_CLOSE_FAILED";
    tls::finish(flow.stream_mut())
        .await
        .map_err(|_| ContentError::Unavailable)?;
    flow.shutdown();
    *stage = "COMPUTE_RPC_FINAL_POLICY_FAILED";
    checked_route(context, policy, control, peer).await?;
    if provider.offer.validity().expires <= now() {
        return Err(ContentError::Unavailable);
    }
    Ok((response, transcript))
}

pub(super) async fn checked_route(
    context: &ControlContext,
    policy: &VerifiedPolicy,
    control: PeerId,
    provider: PeerId,
) -> Result<(), ContentError> {
    checked_policy(context, Some(policy)).await?;
    if context.routes.content_discovery_control().await != Some(control)
        || !context.routes.content_provider_is_distinct(&provider).await
    {
        return Err(ContentError::Policy);
    }
    Ok(())
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

#[cfg(test)]
mod tests {
    use super::*;

    fn binding() -> compute::JobBinding {
        compute::JobBinding {
            job_id: "1".repeat(32),
            dataset_manifest_id: "2".repeat(64),
            dataset_sha256: "3".repeat(64),
            model_fingerprint: "4".repeat(64),
            row_indices: vec![0],
            expires_unix_seconds: 1000,
            task: None,
        }
    }

    #[test]
    fn explicit_transcript_is_poll_only_before_any_remote_exchange() {
        let operations = [
            compute::Operation::Capabilities,
            compute::Operation::Eligibility(compute::EligibilityQuery {
                publisher_keys: vec!["5".repeat(64)],
                model_fingerprint: None,
                model_profile: None,
                require_task_derivation_v1: false,
                require_document_inference_v2: true,
                require_derived_inference_v3: false,
                require_principle_inference_v4: false,
            }),
            compute::Operation::Submit(compute::Submit {
                binding: binding(),
                dataset_json: "{}".into(),
                publication: compute::PublicDataset {
                    publisher_key: "5".repeat(64),
                    manifest_hex: "ab".into(),
                    dataset_json: "{}".into(),
                },
            }),
            compute::Operation::Cancel(binding()),
            compute::Operation::Poll(binding()),
        ];
        for operation in operations {
            assert!(validate_transcript_operation(&operation, false).is_ok());
            assert_eq!(
                validate_transcript_operation(&operation, true).is_ok(),
                matches!(operation, compute::Operation::Poll(_))
            );
        }
    }

    #[test]
    fn final_handoff_never_silently_downgrades_or_adds_transcript_retention() {
        assert_eq!(wire::MAX_TRANSCRIPT_BYTES, 96 * 1024);
        assert!(matches!(
            final_payload(false, None).unwrap(),
            Payload::Ack(_)
        ));
        assert!(matches!(
            final_payload(true, Some(vec![1])).unwrap(),
            Payload::ComputeTranscript(_)
        ));
        assert!(final_payload(true, None).is_err());
        assert!(final_payload(false, Some(vec![1])).is_err());
        assert!(final_payload(true, Some(Vec::new())).is_err());
        assert!(final_payload(true, Some(vec![1; wire::MAX_TRANSCRIPT_BYTES + 1])).is_err());
    }
}
