//! Portable evidence of original compute-control signatures, not model attestation.

use prost::Message;
use sha2::{Digest as _, Sha256};

use super::{
    ComputeError, FRAME_OVERHEAD, MAX_RESPONSE_BYTES,
    protocol::{Kind, Record},
};

/// Maximum request retained in an explicitly requested transcript.
/// The application additionally restricts export to Poll, never dataset-bearing Submit.
pub const MAX_TRANSCRIPT_REQUEST_BYTES: usize = 16 * 1024;
/// Bound on the complete canonical binary transcript, including three original records.
pub const MAX_TRANSCRIPT_BYTES: usize = 96 * 1024;

#[derive(Clone, PartialEq, Message)]
struct Transcript {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    challenge: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    request: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    reply: Vec<u8>,
}

/// Exact response plus a canonical transcript of the same original exchange.
/// Deliberately has no Debug implementation that could log response contents.
pub struct AuthenticatedExchange {
    response: Vec<u8>,
    transcript: Vec<u8>,
}

impl AuthenticatedExchange {
    /// Original response payload; typed broker and result validation is still required.
    pub fn response_payload(&self) -> &[u8] {
        &self.response
    }

    /// Canonical protobuf bytes, without hexadecimal expansion or replacement signatures.
    pub fn transcript_bytes(&self) -> &[u8] {
        &self.transcript
    }

    /// Consume into `(response_payload, transcript_bytes)` without another payload copy.
    pub fn into_parts(self) -> (Vec<u8>, Vec<u8>) {
        (self.response, self.transcript)
    }
}

/// Historically authenticated statements by the independently selected identities.
/// Not proof of trusted time, current authority, sound model output or independent execution.
pub struct VerifiedTranscript {
    request: Record,
    reply: Record,
}

impl VerifiedTranscript {
    /// Original requester-signed opaque request; the consumer must require typed Poll.
    pub fn request_payload(&self) -> &[u8] {
        self.request.payload()
    }

    /// Original provider-signed opaque response, bound to that exact request.
    pub fn response_payload(&self) -> &[u8] {
        self.reply.payload()
    }

    /// Provider's signed reply timestamp, NOT an independently trusted clock reading.
    pub const fn signed_created(&self) -> u64 {
        self.reply.created()
    }

    /// Original signed exchange expiry, shared by challenge, request and reply.
    /// Historical verification does not renew it or imply it is still in the future.
    pub const fn signed_expires(&self) -> u64 {
        self.reply.expires()
    }
}

pub(super) fn authenticated(
    challenge: &Record,
    request: &Record,
    reply: &Record,
) -> Result<AuthenticatedExchange, ComputeError> {
    let transcript = Transcript {
        version: 1,
        // Every live Record decode already required exact canonical bytes, so
        // encode reproduces the original signed record rather than re-signing it.
        challenge: challenge.encode(),
        request: request.encode(),
        reply: reply.encode(),
    }
    .encode_to_vec();
    let checked = verify_transcript(&transcript, &challenge.sender(), &request.sender())?;
    Ok(AuthenticatedExchange {
        response: checked.response_payload().to_vec(),
        transcript,
    })
}

/// Verify all original domain-separated signatures and exact challenge/request binding.
///
/// No current-time parameter is intentionally accepted: old transcripts remain evidence
/// of signed statements, not current authorization. Signed timestamps must still satisfy
/// `challenge.created <= request.created <= reply.created < original expiry`; every
/// record retains the protocol's original maximum validity interval.
///
/// # Errors
/// Rejects unknown/noncanonical framing, size violations, substituted identities,
/// signatures, payload/request/challenge hashes, nonce, expiry or chronology mismatch.
pub fn verify_transcript(
    bytes: &[u8],
    expected_provider: &[u8; 32],
    expected_requester: &[u8; 32],
) -> Result<VerifiedTranscript, ComputeError> {
    if bytes.is_empty() || bytes.len() > MAX_TRANSCRIPT_BYTES {
        return Err(ComputeError::Invalid);
    }
    let transcript = Transcript::decode(bytes).map_err(|_| ComputeError::Invalid)?;
    if transcript.version != 1
        || transcript.encode_to_vec() != bytes
        || transcript.challenge.is_empty()
        || transcript.challenge.len() > FRAME_OVERHEAD
        || transcript.request.is_empty()
        || transcript.request.len() > MAX_TRANSCRIPT_REQUEST_BYTES + FRAME_OVERHEAD
        || transcript.reply.is_empty()
        || transcript.reply.len() > MAX_RESPONSE_BYTES + FRAME_OVERHEAD
    {
        return Err(ComputeError::Invalid);
    }
    let challenge = Record::decode_historical(&transcript.challenge, Kind::Challenge)?;
    let request = Record::decode_historical(&transcript.request, Kind::Request)?;
    let reply = Record::decode_historical(&transcript.reply, Kind::Reply)?;
    if &challenge.sender() != expected_provider
        || &reply.sender() != expected_provider
        || &request.sender() != expected_requester
        || request.payload().len() > MAX_TRANSCRIPT_REQUEST_BYTES
        || reply.request_hash() != Sha256::digest(&transcript.request).as_slice()
        || reply.created() < request.created()
    {
        return Err(ComputeError::Authentication);
    }
    request.matches_challenge(&challenge)?;
    reply.matches_challenge(&challenge)?;
    Ok(VerifiedTranscript { request, reply })
}

#[cfg(test)]
mod tests;
