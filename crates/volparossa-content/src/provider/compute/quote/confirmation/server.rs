use std::time::Duration;

use prost::Message;
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::{Instant, timeout_at},
};

use super::super::super::{
    EXCHANGE_SECONDS, FRAME_OVERHEAD,
    guest::{GuestQuoteSession, MAX_QUOTE_REQUEST_BYTES, MAX_QUOTE_RESPONSE_BYTES, QuoteRequest},
    protocol::{self, Kind, Purpose, Record},
};
use super::super::{Collection, QuoteError, QuoteService};
use super::{
    MAX_PROBE_BYTES, Offer, Probe,
    wire::{Echo, quote_payload},
};

impl QuoteService {
    /// Serve the explicitly enabled confirmation profile on this exact connection.
    /// Uses the original grant, process permit, clocks and single session slot.
    /// No reconnect/retained lookup, generic decrypt operation or worker is exposed.
    ///
    /// # Errors
    /// Refuses unselected profile, stale/revoked authority, bad signed bindings,
    /// cancellation, malformed probes or any stream error; keys erase on all exits.
    pub async fn serve_confirmation<S>(&self, stream: &mut S) -> Result<(), QuoteError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        if !self.confirmation || !self.is_active() {
            return Err(QuoteError::Unauthorized);
        }
        let outer = (Instant::now() + Duration::from_secs(EXCHANGE_SECONDS))
            .min(Instant::from_std(self.owner.deadline()));
        timeout_at(outer, async {
            let challenge = Record::challenge_for(
                &self.signer,
                protocol::now()?,
                Purpose::QuoteConfirmationV1,
            )?;
            protocol::write(stream, &challenge.encode(), FRAME_OVERHEAD).await?;
            let request = Record::decode_for(
                &protocol::read(stream, MAX_QUOTE_REQUEST_BYTES + FRAME_OVERHEAD).await?,
                Kind::Request,
                protocol::now()?,
                Purpose::QuoteConfirmationV1,
            )?;
            request.matches_challenge(&challenge)?;
            self.authorize(request.sender()).await?;
            let payload = QuoteRequest::decode(request.payload())?;
            let (collected, _guard) = self
                .collect_outcome(QuoteRequest::decode(request.payload())?)
                .await?;
            let quote = match collected {
                Collection::Evidence(quote) => quote,
                Collection::DeviceUnavailable(deadline) => {
                    return self
                        .device_unavailable(
                            stream,
                            &challenge,
                            &request,
                            &payload,
                            deadline.min(outer),
                        )
                        .await;
                }
            };
            let deadline = outer.min(Instant::from_std(quote.deadline()));
            timeout_at(
                deadline,
                self.complete_confirmation(stream, &challenge, &request, &payload, quote),
            )
            .await
            .map_err(|_| QuoteError::Expired)?
            // The cancellation guard erases even on error or dropped async work.
        })
        .await
        .map_err(|_| QuoteError::Expired)?
    }

    async fn complete_confirmation<S>(
        &self,
        stream: &mut S,
        challenge: &Record,
        request: &Record,
        payload: &QuoteRequest,
        mut quote: GuestQuoteSession,
    ) -> Result<(), QuoteError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let requester = request.sender();
        self.authorize(requester).await?;
        let expires_at = quote
            .expires_at()
            .min(challenge.expires())
            .min(payload.expires_at());
        let reply = Record::reply(
            &self.signer,
            challenge,
            Sha256::digest(request.encode()).into(),
            quote_payload(quote.response()?, expires_at),
            protocol::now()?,
        )?;
        let offer = Offer::decode(
            &Offer::encode_records(challenge, request, &reply),
            &challenge.sender(),
            &requester,
            payload,
        )?;
        protocol::write(
            stream,
            &reply.encode(),
            MAX_QUOTE_RESPONSE_BYTES + FRAME_OVERHEAD,
        )
        .await?;
        self.authorize(requester).await?;
        quote.response()?;
        let signed = Record::decode_for(
            &protocol::read(stream, MAX_PROBE_BYTES + FRAME_OVERHEAD).await?,
            Kind::Request,
            protocol::now()?,
            Purpose::QuoteConfirmationV1,
        )?;
        self.authorize(requester).await?;
        quote.response()?;
        signed.matches_challenge(challenge)?;
        if signed.sender() != requester || signed.created() < reply.created() {
            return Err(QuoteError::Unauthorized);
        }
        let probe = Probe::decode(signed.payload())?;
        let context = offer.context()?;
        if probe.context != context {
            return Err(QuoteError::Unauthorized);
        }
        let echoed = quote.confirm_probe(&context, &probe.encapsulated, &probe.ciphertext)?;
        let echo = Echo {
            version: 1,
            context: context.to_vec(),
            probe_sha256: Sha256::digest(probe.encode()).to_vec(),
            value: echoed.to_vec(),
        };
        self.authorize(requester).await?;
        quote.response()?;
        let response = Record::reply(
            &self.signer,
            challenge,
            Sha256::digest(signed.encode()).into(),
            echo.encode_to_vec(),
            protocol::now()?,
        )?;
        protocol::write(
            stream,
            &response.encode(),
            MAX_QUOTE_RESPONSE_BYTES + FRAME_OVERHEAD,
        )
        .await?;
        self.authorize(requester).await?;
        quote.response()?;
        // Drop erases the key and frees its slot. No reusable decrypt handle exits.
        Ok(())
    }
}
