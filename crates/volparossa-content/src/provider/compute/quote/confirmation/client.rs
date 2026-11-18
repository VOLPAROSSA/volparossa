use prost::Message;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;
use zeroize::Zeroizing;

use super::super::super::{
    attestation::{BoundSessionEvidence, EvidenceError, LiveSession, PendingSession},
    guest::QuoteRequest,
    protocol::{self, Kind, Purpose, Record},
};
use super::super::QuoteError;
use super::{ConfirmationReply, Offer, Probe, wire::Echo};

/// A generated probe plus a still-borrowed verifier owner. No caller plaintext,
/// task/worker authority, serializer, `Clone` or transferable historical capability.
pub struct PreparedConfirmation<'a> {
    live: LiveSession<'a>,
    offer: Offer,
    probe: Probe,
    expected: Zeroizing<[u8; 32]>,
}

/// Key possession observed on one authenticated original connection, not approved
/// key origin or hardware trust. The owner remains borrowed through the final ACK.
pub struct ConfirmedSession<'a> {
    live: LiveSession<'a>,
    offer: Offer,
}

impl<'a> PendingSession<'a> {
    /// Verify the exact original quote and create only an internally random probe.
    /// The owner slot and original deadlines remain live; old historical facts
    /// cannot be promoted into this type. All outstanding appraisal remains open.
    ///
    /// # Errors
    /// Consumes the original attempt on evidence, binding, entropy or lifecycle failure.
    pub fn prepare_confirmation(
        self,
        offer: Offer,
        vcek_der: &[u8],
        vendor_crl_der: &[u8],
    ) -> Result<PreparedConfirmation<'a>, QuoteError> {
        offer.check()?;
        let expected = QuoteRequest::from_challenge(self.challenge_bytes())?;
        if offer.request.payload() != expected.encode() {
            return Err(QuoteError::Unauthorized);
        }
        let response = offer.response()?;
        let live = self
            .verify_live(
                response.report(),
                vcek_der,
                vendor_crl_der,
                *response.public_key(),
            )
            .map_err(|error| evidence_error(&error))?;
        PreparedConfirmation::from_live(live, offer)
    }
}

fn evidence_error(error: &EvidenceError) -> QuoteError {
    match error {
        EvidenceError::Expired => QuoteError::Expired,
        EvidenceError::Unavailable => QuoteError::Unavailable,
        _ => QuoteError::Unauthorized,
    }
}

impl<'a> PreparedConfirmation<'a> {
    /// Absolute original owner, collateral and signed-connection deadline.
    /// Bridge reads/writes must never create a fresh per-frame timeout.
    pub fn deadline(&self) -> tokio::time::Instant {
        tokio::time::Instant::from_std(self.live.deadline()).min(self.offer.deadline())
    }

    pub(super) fn from_live(mut live: LiveSession<'a>, offer: Offer) -> Result<Self, QuoteError> {
        live.check().map_err(|error| evidence_error(&error))?;
        offer.check()?;
        live.constrain(offer.expires_at(), offer.deadline().into_std())
            .map_err(|error| evidence_error(&error))?;
        if live.evidence().proposed_session_key() != offer.response()?.public_key()
            || *live.evidence().challenge_sha256()
                != QuoteRequest::decode(offer.request.payload())?.sha256()
        {
            return Err(QuoteError::Unauthorized);
        }
        let context = offer.context()?;
        let sealed =
            crate::private_message::confirmation::seal(offer.response()?.public_key(), &context)
                .map_err(|_| QuoteError::Unavailable)?;
        live.check().map_err(|error| evidence_error(&error))?;
        Ok(Self {
            live,
            offer,
            probe: Probe {
                context,
                encapsulated: sealed.encapsulated,
                ciphertext: sealed.ciphertext,
            },
            expected: sealed.expected,
        })
    }

    /// Access only the generated ciphertext while its original owner is live.
    /// # Errors
    /// Rejects cancellation, original expiry or stale original signed records.
    pub fn probe(&self) -> Result<&Probe, QuoteError> {
        self.live.check().map_err(|error| evidence_error(&error))?;
        self.offer.check()?;
        Ok(&self.probe)
    }

    /// Consume exactly one signed matching echo. This proves possession only.
    /// # Errors
    /// Rejects wrong signer/context/probe/echo, replay from another connection,
    /// noncanonical messages or lifecycle failure before or after verification.
    pub fn confirm(self, reply: ConfirmationReply) -> Result<ConfirmedSession<'a>, QuoteError> {
        self.probe()?;
        let now = protocol::now()?;
        let ConfirmationReply {
            request: request_bytes,
            reply: reply_bytes,
        } = reply;
        let request = Record::decode_for(
            &request_bytes,
            Kind::Request,
            now,
            Purpose::QuoteConfirmationV1,
        )?;
        let response =
            Record::decode_for(&reply_bytes, Kind::Reply, now, Purpose::QuoteConfirmationV1)?;
        request.matches_challenge(&self.offer.challenge)?;
        response.matches_challenge(&self.offer.challenge)?;
        if request.sender() != self.offer.request.sender()
            || request.payload() != self.probe.encode()
            || request.created() < self.offer.reply.created()
            || response.sender() != self.offer.challenge.sender()
            || response.request_hash() != Sha256::digest(&request_bytes).as_slice()
            || response.created() < request.created()
        {
            return Err(QuoteError::Unauthorized);
        }
        let echo = Echo::decode(response.payload()).map_err(|_| QuoteError::Invalid)?;
        if echo.version != 1
            || echo.encode_to_vec() != response.payload()
            || echo.context.as_slice() != self.probe.context
            || echo.probe_sha256.as_slice() != Sha256::digest(self.probe.encode()).as_slice()
            || !bool::from(echo.value.as_slice().ct_eq(self.expected.as_slice()))
        {
            return Err(QuoteError::Unauthorized);
        }
        self.probe()?;
        Ok(ConfirmedSession {
            live: self.live,
            offer: self.offer,
        })
    }
}

impl ConfirmedSession<'_> {
    /// The same deadline for the final local terminal acknowledgement.
    pub fn deadline(&self) -> tokio::time::Instant {
        tokio::time::Instant::from_std(self.live.deadline()).min(self.offer.deadline())
    }

    /// Finish after the caller's original final ACK/connection cleanup. Returns
    /// historical reference evidence only, with the same four open obligations.
    /// There is no task acceptance, private-input release or worker method.
    ///
    /// # Errors
    /// Rejects cancellation, grant/challenge expiry or a late terminal handoff.
    pub fn finish(self) -> Result<BoundSessionEvidence, QuoteError> {
        self.offer.check()?;
        self.live.finish().map_err(|error| evidence_error(&error))
    }
}
