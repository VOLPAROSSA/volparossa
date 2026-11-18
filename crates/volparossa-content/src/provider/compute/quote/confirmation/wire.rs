use std::time::Duration;

use prost::Message;
use sha2::{Digest as _, Sha256};
use tokio::time::Instant;

use super::super::super::{
    guest::{QuoteRequest, QuoteResponse},
    protocol::{self, Kind, Purpose, Record},
};
use super::super::{QuoteError, QuoteOutcome, outcome};
use super::{MAX_OFFER_BYTES, MAX_PROBE_BYTES, MAX_REPLY_BYTES};

#[derive(Clone, PartialEq, Message)]
struct OfferWire {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    challenge: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    request: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    reply: Vec<u8>,
}

/// Original provider-authenticated quote, independently checkable by the owner.
/// No admission follows from parsing; no public constructor, `Clone` or `Debug`.
pub struct Offer {
    pub(super) challenge: Record,
    pub(super) request: Record,
    pub(super) reply: Record,
    pub(super) outcome: QuoteOutcome,
    deadline: Instant,
    expires_at: u64,
}

impl Offer {
    /// Canonical private local framing, not a public transcript/export.
    pub fn encode(&self) -> Vec<u8> {
        Self::encode_records(&self.challenge, &self.request, &self.reply)
    }

    pub(super) fn encode_records(challenge: &Record, request: &Record, reply: &Record) -> Vec<u8> {
        OfferWire {
            version: 1,
            challenge: challenge.encode(),
            request: request.encode(),
            reply: reply.encode(),
        }
        .encode_to_vec()
    }

    /// Authenticate all original records against the exact local request and keys.
    ///
    /// # Errors
    /// Rejects unknown/noncanonical fields, stale records, wrong keys/purpose/request.
    pub fn decode(
        bytes: &[u8],
        provider: &[u8; 32],
        requester: &[u8; 32],
        expected: &QuoteRequest,
    ) -> Result<Self, QuoteError> {
        if bytes.is_empty() || bytes.len() > MAX_OFFER_BYTES {
            return Err(QuoteError::Invalid);
        }
        let wire = OfferWire::decode(bytes).map_err(|_| QuoteError::Invalid)?;
        if wire.version != 1 || wire.encode_to_vec() != bytes {
            return Err(QuoteError::Invalid);
        }
        let now = protocol::now()?;
        expected.check_time(now)?;
        let purpose = Purpose::QuoteConfirmationV1;
        let challenge = Record::decode_for(&wire.challenge, Kind::Challenge, now, purpose)?;
        let request = Record::decode_for(&wire.request, Kind::Request, now, purpose)?;
        let reply = Record::decode_for(&wire.reply, Kind::Reply, now, purpose)?;
        request.matches_challenge(&challenge)?;
        reply.matches_challenge(&challenge)?;
        if challenge.sender() != *provider
            || reply.sender() != *provider
            || request.sender() != *requester
            || request.payload() != expected.encode()
            || reply.request_hash() != Sha256::digest(&wire.request).as_slice()
            || reply.created() < request.created()
        {
            return Err(QuoteError::Unauthorized);
        }
        let maximum_expiry = challenge.expires().min(expected.expires_at());
        let (outcome, expires_at) = decode_quote(reply.payload(), expected, maximum_expiry, now)?;
        let deadline = Instant::now() + Duration::from_secs(expires_at - now);
        Ok(Self {
            challenge,
            request,
            reply,
            outcome,
            deadline,
            expires_at,
        })
    }

    /// Authenticated provider refusal, not a successful hardware collection.
    pub const fn is_device_unavailable(&self) -> bool {
        matches!(self.outcome, QuoteOutcome::DeviceUnavailable)
    }

    /// Original signed validity converted once to a monotonic local bound.
    /// Owner continuation further caps this by its original owner/collateral deadline.
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(super) const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    pub(super) fn response(&self) -> Result<&QuoteResponse, QuoteError> {
        match &self.outcome {
            QuoteOutcome::Evidence(response) => Ok(response),
            QuoteOutcome::DeviceUnavailable => Err(QuoteError::Unavailable),
        }
    }

    pub(super) fn check(&self) -> Result<(), QuoteError> {
        if Instant::now() >= self.deadline {
            return Err(QuoteError::Expired);
        }
        let request = QuoteRequest::decode(self.request.payload())?;
        Self::decode(
            &self.encode(),
            &self.challenge.sender(),
            &self.request.sender(),
            &request,
        )?;
        Ok(())
    }

    pub(super) fn context(&self) -> Result<[u8; 32], QuoteError> {
        let context = Context {
            version: 1,
            provider: self.challenge.sender().to_vec(),
            requester: self.request.sender().to_vec(),
            challenge_sha256: Sha256::digest(self.challenge.encode()).to_vec(),
            request_sha256: Sha256::digest(self.request.encode()).to_vec(),
            quote_sha256: Sha256::digest(self.reply.encode()).to_vec(),
            session_key: self.response()?.public_key().to_vec(),
            expires_at: self.expires_at,
        };
        Ok(Sha256::digest(context.encode_to_vec()).into())
    }
}

#[derive(Clone, PartialEq, Message)]
struct GrantedQuote {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    quote: Vec<u8>,
    #[prost(uint64, tag = "3")]
    expires_at: u64,
}

pub(super) fn quote_payload(response: &QuoteResponse, expires_at: u64) -> Vec<u8> {
    GrantedQuote {
        version: 3,
        quote: response.encode(),
        expires_at,
    }
    .encode_to_vec()
}

fn decode_quote(
    bytes: &[u8],
    request: &QuoteRequest,
    maximum_expiry: u64,
    now: u64,
) -> Result<(QuoteOutcome, u64), QuoteError> {
    if let Ok(QuoteOutcome::DeviceUnavailable) = outcome::decode(bytes, request) {
        return Ok((QuoteOutcome::DeviceUnavailable, maximum_expiry));
    }
    let wire = GrantedQuote::decode(bytes).map_err(|_| QuoteError::Invalid)?;
    if wire.version != 3
        || wire.encode_to_vec() != bytes
        || wire.expires_at <= now
        || wire.expires_at > maximum_expiry
    {
        return Err(QuoteError::Invalid);
    }
    Ok((
        QuoteOutcome::Evidence(QuoteResponse::decode(&wire.quote, request)?),
        wire.expires_at,
    ))
}

// One fixed canonical context, derived from authenticated original records only.
#[derive(Clone, PartialEq, Message)]
struct Context {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    provider: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    requester: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    challenge_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    request_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    quote_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    session_key: Vec<u8>,
    #[prost(uint64, tag = "8")]
    expires_at: u64,
}

#[derive(Clone, PartialEq, Message)]
struct ProbeWire {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    context: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    encapsulated: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    ciphertext: Vec<u8>,
}

/// Fixed encrypted random probe, not a caller plaintext/decryption API.
pub struct Probe {
    pub(super) context: [u8; 32],
    pub(super) encapsulated: [u8; 32],
    pub(super) ciphertext: [u8; 48],
}

impl Probe {
    /// Canonical encrypted bytes only; no private task input is accepted here.
    pub fn encode(&self) -> Vec<u8> {
        ProbeWire {
            version: 1,
            context: self.context.to_vec(),
            encapsulated: self.encapsulated.to_vec(),
            ciphertext: self.ciphertext.to_vec(),
        }
        .encode_to_vec()
    }

    /// Read the one fixed profile; decoding is not requester authorization.
    ///
    /// # Errors
    /// Rejects noncanonical data, wrong versions or any different field lengths.
    pub fn decode(bytes: &[u8]) -> Result<Self, QuoteError> {
        if bytes.is_empty() || bytes.len() > MAX_PROBE_BYTES {
            return Err(QuoteError::Invalid);
        }
        let wire = ProbeWire::decode(bytes).map_err(|_| QuoteError::Invalid)?;
        if wire.version != 1 || wire.encode_to_vec() != bytes {
            return Err(QuoteError::Invalid);
        }
        Ok(Self {
            context: wire
                .context
                .as_slice()
                .try_into()
                .map_err(|_| QuoteError::Invalid)?,
            encapsulated: wire
                .encapsulated
                .as_slice()
                .try_into()
                .map_err(|_| QuoteError::Invalid)?,
            ciphertext: wire
                .ciphertext
                .as_slice()
                .try_into()
                .map_err(|_| QuoteError::Invalid)?,
        })
    }
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct Echo {
    #[prost(uint32, tag = "1")]
    pub(super) version: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub(super) context: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub(super) probe_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub(super) value: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct ReplyWire {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    request: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    reply: Vec<u8>,
}

/// Original signed confirmation request/reply; private bounded local framing.
pub struct ConfirmationReply {
    pub(super) request: Vec<u8>,
    pub(super) reply: Vec<u8>,
}

impl ConfirmationReply {
    /// Original private records, never a public acceptance transcript.
    pub fn encode(&self) -> Vec<u8> {
        ReplyWire {
            version: 1,
            request: self.request.clone(),
            reply: self.reply.clone(),
        }
        .encode_to_vec()
    }

    /// Decode framing only; the live owner must authenticate and consume it.
    ///
    /// # Errors
    /// Rejects unknown fields, unsupported versions, empty or oversized records.
    pub fn decode(bytes: &[u8]) -> Result<Self, QuoteError> {
        if bytes.is_empty() || bytes.len() > MAX_REPLY_BYTES {
            return Err(QuoteError::Invalid);
        }
        let wire = ReplyWire::decode(bytes).map_err(|_| QuoteError::Invalid)?;
        if wire.version != 1
            || wire.encode_to_vec() != bytes
            || wire.request.is_empty()
            || wire.reply.is_empty()
        {
            return Err(QuoteError::Invalid);
        }
        Ok(Self {
            request: wire.request,
            reply: wire.reply,
        })
    }
}
