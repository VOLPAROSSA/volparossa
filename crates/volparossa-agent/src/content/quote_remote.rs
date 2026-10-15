//! Quote/explicit confirmation handoff; no public-job or raw-report logging.

mod exchange;

use std::time::Duration;

use libp2p::{PeerId, identity};
use tokio::{net::UnixStream, time::timeout};
use volparossa_content::provider::compute::quote as wire;
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ControlResponse, ControlResult, Empty, QuoteReady,
    QuoteRemoteRequest, control_response::Payload, write_response,
};

use super::{
    ContentError, ContentRuntime,
    cancellation::until_requester_closed,
    compute_remote::{checked_policy, checked_route},
    now, tls,
};
use crate::{control::ControlContext, unix_millis};

impl ContentRuntime {
    #[allow(
        clippy::too_many_lines,
        reason = "One owned route/TLS/quote/local stream lifecycle preserves readiness and cleanup ordering"
    )]
    pub(crate) async fn quote_remote(
        &self,
        request: QuoteRemoteRequest,
        context: &ControlContext,
        local: &mut UnixStream,
        request_id: &[u8],
        ready_sent: &mut bool,
    ) -> Result<(), ContentError> {
        let _foreground = self.foreground.enter();
        let mut stage = "QUOTE_LOCAL_REQUEST_FAILED";
        let result = timeout(Duration::from_secs(150), async {
            if !matches!(request.confirmation_version, None | Some(1)) {
                return Err(ContentError::Invalid);
            }
            let provider_key: [u8; 32] = request
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
            stage = "QUOTE_ROUTE_SETUP_FAILED";
            until_requester_closed(local, async {
                Box::pin(context.routes.connect_tcp(
                    &context.config,
                    &context.discovery,
                    &context.helper,
                ))
                .await
                .map_err(|_| ContentError::Unavailable)
            })
            .await?;
            let control = context
                .routes
                .content_discovery_control()
                .await
                .ok_or(ContentError::Unavailable)?;
            checked_route(context, &policy, control, peer).await?;
            stage = "QUOTE_DISCOVERY_FAILED";
            let mut providers = until_requester_closed(local, async {
                context
                    .discovery
                    .lookup_content_providers(control, &[peer])
                    .await
                    .map_err(|_| ContentError::Unavailable)
            })
            .await?;
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
            checked_route(context, &policy, control, peer).await?;
            stage = "QUOTE_ROUTE_FLOW_FAILED";
            let endpoint = provider.offer.endpoint();
            let mut flow = until_requester_closed(local, async {
                context
                    .routes
                    .open_content_stream(
                        &policy,
                        endpoint.hostname(),
                        endpoint.port(),
                        unix_millis(),
                    )
                    .await
                    .map_err(|_| ContentError::Unavailable)
            })
            .await?;
            stage = "QUOTE_PROVIDER_TLS_FAILED";
            let mut remote = until_requester_closed(local, async {
                tls::connect(flow.stream_mut(), peer, &provider.offer)
                    .await
                    .map_err(|_| ContentError::Unavailable)
            })
            .await?;
            stage = "QUOTE_CHALLENGE_FAILED";
            let mut exchange = until_requester_closed(local, async {
                exchange::Exchange::begin(&mut remote, &provider_key, request.confirmation_version)
                    .await
            })
            .await?;
            checked_route(context, &policy, control, peer).await?;
            if provider.offer.validity().expires <= now() {
                return Err(ContentError::Unavailable);
            }
            // Only now can the CLI create its fresh 30-second verification challenge.
            stage = "QUOTE_READY_FAILED";
            *ready_sent = true;
            send(
                local,
                request_id,
                "QUOTE_READY",
                Payload::QuoteReady(QuoteReady {
                    provider_key: provider_key.to_vec(),
                    requester_key: self.signer.verifying_key().to_bytes().to_vec(),
                    confirmation_version: request.confirmation_version,
                }),
            )
            .await?;
            stage = "QUOTE_LOCAL_CHALLENGE_FAILED";
            let quote_request = exchange.request(local).await?;
            checked_route(context, &policy, control, peer).await?;
            if provider.offer.validity().expires <= now() {
                return Err(ContentError::Unavailable);
            }
            stage = "QUOTE_SIGNED_EXCHANGE_FAILED";
            // Only the explicit profile accepts one typed probe after its offer.
            // EOF cancels local ownership; no arbitrary requester stream is forwarded.
            let response = exchange
                .exchange(local, &self.signer, &quote_request, &mut stage)
                .await?;
            let deadline = response.deadline();
            stage = "QUOTE_PROVIDER_CLOSE_FAILED";
            exchange::finish_before(deadline, async {
                tls::finish(&mut remote)
                    .await
                    .map_err(|_| ContentError::Unavailable)
            })
            .await?;
            drop(remote);
            stage = "QUOTE_ROUTE_CLOSE_FAILED";
            exchange::finish_before(deadline, async {
                tls::finish(flow.stream_mut())
                    .await
                    .map_err(|_| ContentError::Unavailable)
            })
            .await?;
            flow.shutdown();
            stage = "QUOTE_FINAL_POLICY_FAILED";
            exchange::finish_before(deadline, checked_route(context, &policy, control, peer))
                .await?;
            if provider.offer.validity().expires <= now() {
                return Err(ContentError::Unavailable);
            }
            stage = "QUOTE_LOCAL_REPLY_FAILED";
            exchange::finish_before(deadline, response.write(local, &quote_request)).await?;
            if deadline.is_some() {
                stage = "QUOTE_CONFIRMATION_FINAL_POLICY_FAILED";
                exchange::finish_before(deadline, checked_route(context, &policy, control, peer))
                    .await?;
                if provider.offer.validity().expires <= now() {
                    return Err(ContentError::Unavailable);
                }
            }
            exchange::check_deadline(deadline)?;
            exchange::finish_before(
                deadline,
                send(
                    local,
                    request_id,
                    response.terminal_code(),
                    Payload::Ack(Empty {}),
                ),
            )
            .await
        })
        .await
        .map_err(|_| ContentError::Unavailable)
        .and_then(std::convert::identity);
        if result.is_err() {
            super::content_event(context, stage).await;
        }
        result
    }
}

const fn terminal_code(outcome: &wire::QuoteOutcome) -> &'static str {
    match outcome {
        wire::QuoteOutcome::Evidence(_) => "QUOTE_EXCHANGE_OK",
        wire::QuoteOutcome::DeviceUnavailable => "QUOTE_DEVICE_UNAVAILABLE",
    }
}

async fn send(
    stream: &mut UnixStream,
    request_id: &[u8],
    code: &str,
    payload: Payload,
) -> Result<(), ContentError> {
    write_response(
        stream,
        &ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: request_id.to_vec(),
            result: ControlResult::Ok.into(),
            diagnostic_code: code.into(),
            private_storage_remote_detail: None,
            payload: Some(payload),
        },
    )
    .await
    .map_err(|_| ContentError::Unavailable)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_remote_device_refusal_has_a_distinct_terminal_code() {
        assert_eq!(
            terminal_code(&wire::QuoteOutcome::DeviceUnavailable),
            "QUOTE_DEVICE_UNAVAILABLE"
        );
        assert_ne!(
            terminal_code(&wire::QuoteOutcome::DeviceUnavailable),
            "QUOTE_EXCHANGE_OK"
        );
    }
}
