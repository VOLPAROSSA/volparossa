use std::time::Duration;

use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::{Instant, timeout_at},
};

use super::super::super::{
    EXCHANGE_SECONDS, FRAME_OVERHEAD,
    guest::{MAX_QUOTE_REQUEST_BYTES, MAX_QUOTE_RESPONSE_BYTES, QuoteRequest},
    protocol::{self, Kind, Purpose, Record},
};
use super::super::{QuoteError, SELECTOR_OPERATION};
use super::{ConfirmationReply, MAX_OFFER_BYTES, MAX_PROBE_BYTES, MAX_REPLY_BYTES, Offer, Probe};

/// One borrowed protected connection. No reconnect, `Clone` or replacement stream.
pub struct RelayConnection<'a, S> {
    stream: &'a mut S,
    challenge: Record,
    deadline: Instant,
    quoted: bool,
    binding: Option<([u8; 32], [u8; 32])>,
}

/// Explicitly select confirmation and authenticate the connection's provider.
/// All later frames share this original monotonic and signed-wall-clock budget.
///
/// # Errors
/// Rejects unsupported peers, wrong purpose/provider, stale or malformed records.
pub async fn begin<'a, S>(
    stream: &'a mut S,
    provider: &[u8; 32],
) -> Result<RelayConnection<'a, S>, QuoteError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let deadline = Instant::now() + Duration::from_secs(EXCHANGE_SECONDS);
    timeout_at(deadline, async {
        super::super::super::super::write_frame(
            stream,
            &super::super::super::super::Selector {
                version: super::SELECTOR_VERSION,
                operation: SELECTOR_OPERATION,
                manifest_id: Vec::new(),
            },
        )
        .await
        .map_err(|_| QuoteError::Invalid)?;
        let bytes = protocol::read(stream, FRAME_OVERHEAD).await?;
        let now = protocol::now()?;
        let challenge =
            Record::decode_for(&bytes, Kind::Challenge, now, Purpose::QuoteConfirmationV1)?;
        if challenge.sender() != *provider {
            return Err(QuoteError::Unauthorized);
        }
        let deadline =
            deadline.min(Instant::now() + Duration::from_secs(challenge.expires() - now));
        Ok(RelayConnection {
            stream,
            challenge,
            deadline,
            quoted: false,
            binding: None,
        })
    })
    .await
    .map_err(|_| QuoteError::Expired)?
}

impl<S: AsyncRead + AsyncWrite + Unpin> RelayConnection<'_, S> {
    /// The original deadline, including time already spent on setup and quote.
    /// Local bridge waits must use this value, never restart a per-frame budget.
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Obtain one independently verifiable original offer, not a worker permit.
    ///
    /// # Errors
    /// Any failure consumes this attempt; a second quote on this connection rejects.
    pub async fn quote(
        &mut self,
        signer: &SigningKey,
        request: &QuoteRequest,
    ) -> Result<Offer, QuoteError> {
        if std::mem::replace(&mut self.quoted, true) {
            return Err(QuoteError::Invalid);
        }
        let now = protocol::now()?;
        request.check_time(now)?;
        self.deadline = self
            .deadline
            .min(Instant::now() + Duration::from_secs(request.expires_at() - now));
        timeout_at(self.deadline, async {
            let envelope =
                Record::request(signer, &self.challenge, request.encode(), protocol::now()?)?;
            protocol::write(
                self.stream,
                &envelope.encode(),
                MAX_QUOTE_REQUEST_BYTES + FRAME_OVERHEAD,
            )
            .await?;
            let reply = Record::decode_for(
                &protocol::read(self.stream, MAX_QUOTE_RESPONSE_BYTES + FRAME_OVERHEAD).await?,
                Kind::Reply,
                protocol::now()?,
                Purpose::QuoteConfirmationV1,
            )?;
            let offer = Offer::decode(
                &Offer::encode_records(&self.challenge, &envelope, &reply),
                &self.challenge.sender(),
                &signer.verifying_key().to_bytes(),
                request,
            )?;
            if !offer.is_device_unavailable() {
                self.binding = Some((offer.context()?, envelope.sender()));
            }
            self.deadline = self.deadline.min(offer.deadline());
            Ok(offer)
        })
        .await
        .map_err(|_| QuoteError::Expired)?
    }

    /// Forward exactly one fixed probe and retain the original signed response.
    /// Consumes the borrowed connection state, without reconnect or time refresh.
    ///
    /// # Errors
    /// Rejects refusal, different requester/context, expiry and malformed signed replies.
    pub async fn confirm(
        self,
        signer: &SigningKey,
        probe: &Probe,
    ) -> Result<ConfirmationReply, QuoteError> {
        let (context, requester) = self.binding.ok_or(QuoteError::Invalid)?;
        if probe.context != context || signer.verifying_key().to_bytes() != requester {
            return Err(QuoteError::Unauthorized);
        }
        timeout_at(self.deadline, async {
            let request =
                Record::request(signer, &self.challenge, probe.encode(), protocol::now()?)?;
            let bytes = request.encode();
            protocol::write(self.stream, &bytes, MAX_PROBE_BYTES + FRAME_OVERHEAD).await?;
            let reply =
                protocol::read(self.stream, MAX_QUOTE_RESPONSE_BYTES + FRAME_OVERHEAD).await?;
            let parsed = Record::decode_for(
                &reply,
                Kind::Reply,
                protocol::now()?,
                Purpose::QuoteConfirmationV1,
            )?;
            parsed.matches_challenge(&self.challenge)?;
            if parsed.sender() != self.challenge.sender()
                || parsed.request_hash() != Sha256::digest(&bytes).as_slice()
                || parsed.created() < request.created()
            {
                return Err(QuoteError::Unauthorized);
            }
            Ok(ConfirmationReply {
                request: bytes,
                reply,
            })
        })
        .await
        .map_err(|_| QuoteError::Expired)?
    }
}

/// Read original provider proof on the already authorized local connection.
/// # Errors
/// Rejects framing, signature, key, request, purpose and freshness violations.
pub async fn read_offer<S: AsyncRead + Unpin>(
    stream: &mut S,
    provider: &[u8; 32],
    requester: &[u8; 32],
    request: &QuoteRequest,
) -> Result<Offer, QuoteError> {
    Offer::decode(
        &protocol::read(stream, MAX_OFFER_BYTES).await?,
        provider,
        requester,
        request,
    )
}

/// Write private original evidence. The caller owns the existing absolute deadline.
/// # Errors
/// Rejects stale evidence, stream errors or oversized encoding.
pub async fn write_offer<S: AsyncWrite + Unpin>(
    stream: &mut S,
    offer: &Offer,
) -> Result<(), QuoteError> {
    offer.check()?;
    Ok(protocol::write(stream, &offer.encode(), MAX_OFFER_BYTES).await?)
}

/// Read one fixed encrypted probe; the provider still authenticates its caller.
/// # Errors
/// Rejects invalid lengths, versions or noncanonical fields before use.
pub async fn read_probe<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Probe, QuoteError> {
    Probe::decode(&protocol::read(stream, MAX_PROBE_BYTES).await?)
}

/// Write one typed encrypted probe; never accepts arbitrary plaintext.
/// # Errors
/// Rejects failed or oversized writes; the caller owns the original deadline.
pub async fn write_probe<S: AsyncWrite + Unpin>(
    stream: &mut S,
    probe: &Probe,
) -> Result<(), QuoteError> {
    Ok(protocol::write(stream, &probe.encode(), MAX_PROBE_BYTES).await?)
}

/// Read signed proof framing; only the live owner can confirm the random echo.
/// # Errors
/// Rejects malformed/oversized private records.
pub async fn read_reply<S: AsyncRead + Unpin>(
    stream: &mut S,
) -> Result<ConfirmationReply, QuoteError> {
    ConfirmationReply::decode(&protocol::read(stream, MAX_REPLY_BYTES).await?)
}

/// Write original signed proof, never raw error text or a task result.
/// # Errors
/// Rejects failed/oversized writes; the caller owns the original deadline.
pub async fn write_reply<S: AsyncWrite + Unpin>(
    stream: &mut S,
    reply: &ConfirmationReply,
) -> Result<(), QuoteError> {
    Ok(protocol::write(stream, &reply.encode(), MAX_REPLY_BYTES).await?)
}
