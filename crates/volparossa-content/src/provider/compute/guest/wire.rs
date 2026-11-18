//! Canonical small payloads, not transport authentication or admission authority.

use prost::Message;
use sha2::{Digest as _, Sha256};
use subtle::ConstantTimeEq as _;

use super::{
    super::attestation::{challenge_window, session_report_data},
    GuestError,
};

/// Maximum canonical request size; the embedded challenge remains limited to 256 bytes.
pub const MAX_QUOTE_REQUEST_BYTES: usize = 272;
/// Maximum quote-only response, comfortably below the existing compute response limit.
pub const MAX_QUOTE_RESPONSE_BYTES: usize = 1408;
const REPORT_BYTES: usize = 1184;

#[derive(Clone, PartialEq, Message)]
struct Request {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    challenge: Vec<u8>,
}

/// A parsed public challenge request. No private task, model input or collateral.
/// Canonical decoding alone authenticates neither the requester nor its clock.
pub struct QuoteRequest {
    pub(super) challenge: Vec<u8>,
    pub(super) created_at: u64,
    pub(super) expires_at: u64,
}

impl QuoteRequest {
    pub(in crate::provider::compute) const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Wrap a canonical verifier challenge. Freshness is checked on guest admission.
    ///
    /// # Errors
    /// Rejects anything outside the existing canonical challenge-v2 profile.
    pub fn from_challenge(challenge: &[u8]) -> Result<Self, GuestError> {
        let (created_at, expires_at) =
            challenge_window(challenge).map_err(|_| GuestError::Encoding)?;
        Ok(Self {
            challenge: challenge.to_vec(),
            created_at,
            expires_at,
        })
    }

    /// Encode for an authenticated protected provider exchange, not an arbitrary listener.
    pub fn encode(&self) -> Vec<u8> {
        Request {
            version: 1,
            challenge: self.challenge.clone(),
        }
        .encode_to_vec()
    }

    /// Decode one exact bounded canonical request; no unknown fields/default profile.
    ///
    /// # Errors
    /// Rejects oversized, malformed, noncanonical or unsupported payloads.
    pub fn decode(raw: &[u8]) -> Result<Self, GuestError> {
        if raw.is_empty() || raw.len() > MAX_QUOTE_REQUEST_BYTES {
            return Err(GuestError::Encoding);
        }
        let parsed = Request::decode(raw).map_err(|_| GuestError::Encoding)?;
        if parsed.version != 1 || parsed.encode_to_vec() != raw {
            return Err(GuestError::Encoding);
        }
        Self::from_challenge(&parsed.challenge)
    }

    pub(in crate::provider::compute) fn sha256(&self) -> [u8; 32] {
        Sha256::digest(&self.challenge).into()
    }

    pub(in crate::provider::compute) fn check_time(&self, now: u64) -> Result<(), GuestError> {
        if self.created_at == 0 || now < self.created_at || now >= self.expires_at {
            return Err(GuestError::Expired);
        }
        Ok(())
    }
}

#[derive(Clone, PartialEq, Message)]
struct Response {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    challenge_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    report: Vec<u8>,
}

/// Exact quote bytes and their public key, NOT verified evidence or key-origin proof.
/// Raw reports can contain hardware identifiers: do not log, cache or publish them.
pub struct QuoteResponse {
    challenge_sha256: [u8; 32],
    public_key: [u8; 32],
    report: Vec<u8>,
}

impl QuoteResponse {
    pub(super) fn new(
        request: &QuoteRequest,
        public_key: [u8; 32],
        report: Vec<u8>,
    ) -> Result<Self, GuestError> {
        if report.len() != REPORT_BYTES {
            return Err(GuestError::ReportBinding);
        }
        let version = u32::from_le_bytes(report[..4].try_into().map_err(|_| GuestError::Encoding)?);
        if version != 2 {
            return Err(GuestError::UnsupportedReport(version));
        }
        let expected = session_report_data(&request.challenge, &public_key)
            .map_err(|_| GuestError::ReportBinding)?;
        if report[0x30..0x34] != [0; 4] || !bool::from(report[0x50..0x90].ct_eq(&expected)) {
            return Err(GuestError::ReportBinding);
        }
        Ok(Self {
            challenge_sha256: request.sha256(),
            public_key,
            report,
        })
    }

    /// Serialize only public evidence; does not refresh or confer session authority.
    pub fn encode(&self) -> Vec<u8> {
        Response {
            version: 1,
            challenge_sha256: self.challenge_sha256.to_vec(),
            public_key: self.public_key.to_vec(),
            report: self.report.clone(),
        }
        .encode_to_vec()
    }

    /// Decode against the exact original request. The caller must still consume
    /// its live `PendingSession` with independently obtained, appraised collateral.
    ///
    /// # Errors
    /// Rejects noncanonical, wrong-request, oversized or differently bound evidence.
    pub fn decode(raw: &[u8], request: &QuoteRequest) -> Result<Self, GuestError> {
        if raw.is_empty() || raw.len() > MAX_QUOTE_RESPONSE_BYTES {
            return Err(GuestError::Encoding);
        }
        let parsed = Response::decode(raw).map_err(|_| GuestError::Encoding)?;
        if parsed.version != 1
            || parsed.encode_to_vec() != raw
            || parsed.challenge_sha256.as_slice() != request.sha256()
        {
            return Err(GuestError::Encoding);
        }
        let public_key = parsed
            .public_key
            .as_slice()
            .try_into()
            .map_err(|_| GuestError::Encoding)?;
        Self::new(request, public_key, parsed.report)
    }

    /// The exact raw collected bytes; no version/field normalization occurred.
    pub fn report(&self) -> &[u8] {
        &self.report
    }

    /// Process-generated public X25519 key; origin is not proved by decoding.
    pub const fn public_key(&self) -> &[u8; 32] {
        &self.public_key
    }
}
