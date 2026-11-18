//! Bounded typed bridging only: the CLI, not the agent, owns key confirmation.

use std::{future::Future, time::Duration};

use ed25519_dalek::SigningKey;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::UnixStream,
    time::{Instant, timeout, timeout_at},
};
use volparossa_content::provider::compute::{guest::QuoteRequest, quote as wire};

use super::super::{ContentError, cancellation::until_requester_closed};

#[cfg(test)]
mod tests;

pub(super) enum Exchange<'a, S> {
    Legacy(&'a mut S, wire::QuoteChallenge),
    Confirmation(wire::confirmation::RelayConnection<'a, S>),
}

pub(super) enum Response {
    Legacy(wire::QuoteOutcome),
    Refusal(Box<wire::confirmation::Offer>, Instant),
    Confirmed(wire::confirmation::ConfirmationReply, Instant),
}

impl<'a, S: AsyncRead + AsyncWrite + Unpin> Exchange<'a, S> {
    pub(super) async fn begin(
        stream: &'a mut S,
        provider: &[u8; 32],
        version: Option<u32>,
    ) -> Result<Self, ContentError> {
        match version {
            None => wire::begin(stream, provider)
                .await
                .map(|challenge| Self::Legacy(stream, challenge)),
            Some(1) => wire::confirmation::begin(stream, provider)
                .await
                .map(Self::Confirmation),
            Some(_) => return Err(ContentError::Invalid),
        }
        .map_err(|_| ContentError::Unavailable)
    }

    pub(super) async fn request(
        &mut self,
        local: &mut UnixStream,
    ) -> Result<QuoteRequest, ContentError> {
        let result = match self {
            Self::Legacy(_, _) => timeout(Duration::from_secs(30), wire::read_request(local)).await,
            Self::Confirmation(relay) => {
                timeout_at(relay.deadline(), wire::read_request(local)).await
            }
        };
        result
            .map_err(|_| ContentError::Unavailable)?
            .map_err(|_| ContentError::Invalid)
    }

    pub(super) async fn exchange(
        self,
        local: &mut UnixStream,
        signer: &SigningKey,
        request: &QuoteRequest,
        stage: &mut &'static str,
    ) -> Result<Response, ContentError> {
        match self {
            Self::Legacy(stream, challenge) => {
                until_requester_closed(local, async {
                    wire::exchange_outcome(stream, challenge, signer, request)
                        .await
                        .map(Response::Legacy)
                        .map_err(|_| ContentError::Unavailable)
                })
                .await
            }
            Self::Confirmation(mut relay) => {
                let deadline = relay.deadline();
                timeout_at(deadline, async {
                    let offer = until_requester_closed(local, async {
                        relay
                            .quote(signer, request)
                            .await
                            .map_err(|_| ContentError::Unavailable)
                    })
                    .await?;
                    let deadline = relay.deadline();
                    if offer.is_device_unavailable() {
                        return Ok(Response::Refusal(Box::new(offer), deadline));
                    }
                    // Quote validation may reduce the original deadline to the
                    // signed request/provider grant; local waits cannot reset it.
                    timeout_at(deadline, async {
                        *stage = "QUOTE_CONFIRMATION_OFFER_FAILED";
                        wire::confirmation::write_offer(local, &offer)
                            .await
                            .map_err(|_| ContentError::Unavailable)?;
                        *stage = "QUOTE_CONFIRMATION_PROBE_FAILED";
                        let probe = wire::confirmation::read_probe(local)
                            .await
                            .map_err(|_| ContentError::Invalid)?;
                        *stage = "QUOTE_CONFIRMATION_EXCHANGE_FAILED";
                        until_requester_closed(local, async {
                            relay
                                .confirm(signer, &probe)
                                .await
                                .map(|reply| Response::Confirmed(reply, deadline))
                                .map_err(|_| ContentError::Unavailable)
                        })
                        .await
                    })
                    .await
                    .map_err(|_| ContentError::Unavailable)?
                })
                .await
                .map_err(|_| ContentError::Unavailable)?
            }
        }
    }
}

impl Response {
    pub(super) const fn deadline(&self) -> Option<Instant> {
        match self {
            Self::Legacy(_) => None,
            Self::Refusal(_, deadline) | Self::Confirmed(_, deadline) => Some(*deadline),
        }
    }

    pub(super) const fn terminal_code(&self) -> &'static str {
        match self {
            Self::Legacy(outcome) => super::terminal_code(outcome),
            Self::Refusal(_, _) => "QUOTE_DEVICE_UNAVAILABLE",
            Self::Confirmed(_, _) => "QUOTE_KEY_CONFIRMED",
        }
    }

    pub(super) async fn write(
        &self,
        local: &mut UnixStream,
        request: &QuoteRequest,
    ) -> Result<(), ContentError> {
        check_deadline(self.deadline())?;
        match self {
            Self::Legacy(outcome) => wire::write_outcome(local, outcome, request).await,
            Self::Refusal(offer, _) => wire::confirmation::write_offer(local, offer).await,
            Self::Confirmed(reply, _) => wire::confirmation::write_reply(local, reply).await,
        }
        .map_err(|_| ContentError::Unavailable)
    }
}

pub(super) fn check_deadline(deadline: Option<Instant>) -> Result<(), ContentError> {
    if deadline.is_some_and(|deadline| Instant::now() >= deadline) {
        return Err(ContentError::Unavailable);
    }
    Ok(())
}

/// Preserve legacy finalization; explicit confirmation cannot outlive its exchange.
pub(super) async fn finish_before<T>(
    deadline: Option<Instant>,
    work: impl Future<Output = Result<T, ContentError>>,
) -> Result<T, ContentError> {
    check_deadline(deadline)?;
    let value = match deadline {
        Some(deadline) => timeout_at(deadline, work)
            .await
            .map_err(|_| ContentError::Unavailable)?,
        None => work.await,
    }?;
    check_deadline(deadline)?;
    Ok(value)
}
