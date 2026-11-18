//! Request-bound refusal framing; no quote, hardware identifier or admission.

use prost::Message;
use sha2::{Digest as _, Sha256};

use super::super::{
    guest::{MAX_QUOTE_RESPONSE_BYTES, QuoteRequest, QuoteResponse},
    protocol,
};
use super::QuoteError;

/// An exchange result, not independently appraised evidence or a permit.
/// `exchange_outcome` authenticates the provider's signed response. The local
/// `read_outcome` framing carries no portable signature and trusts its local agent.
pub enum QuoteOutcome {
    /// Original v1 quote bytes; independent appraisal remains mandatory.
    Evidence(QuoteResponse),
    /// The authenticated provider says its fixed quote device was unusable.
    /// This does not distinguish missing hardware from device-access failure.
    DeviceUnavailable,
}

#[derive(Clone, PartialEq, Message)]
struct Refusal {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(uint32, tag = "2")]
    code: u32,
    #[prost(bytes = "vec", tag = "3")]
    request_sha256: Vec<u8>,
}

pub(super) fn encode(
    outcome: &QuoteOutcome,
    request: &QuoteRequest,
) -> Result<Vec<u8>, QuoteError> {
    match outcome {
        QuoteOutcome::Evidence(response) => {
            let bytes = response.encode();
            QuoteResponse::decode(&bytes, request)?;
            Ok(bytes)
        }
        QuoteOutcome::DeviceUnavailable => {
            request.check_time(protocol::now()?)?;
            Ok(Refusal {
                version: 2,
                code: 1,
                request_sha256: Sha256::digest(request.encode()).to_vec(),
            }
            .encode_to_vec())
        }
    }
}

pub(super) fn decode(bytes: &[u8], request: &QuoteRequest) -> Result<QuoteOutcome, QuoteError> {
    if bytes.is_empty() || bytes.len() > MAX_QUOTE_RESPONSE_BYTES {
        return Err(QuoteError::Invalid);
    }
    // Original success payloads are decoded by the unchanged v1 validator.
    if let Ok(response) = QuoteResponse::decode(bytes, request) {
        return Ok(QuoteOutcome::Evidence(response));
    }
    let refusal = Refusal::decode(bytes).map_err(|_| QuoteError::Invalid)?;
    if refusal.version != 2
        || refusal.code != 1
        || refusal.encode_to_vec() != bytes
        || refusal.request_sha256.as_slice() != Sha256::digest(request.encode()).as_slice()
    {
        return Err(QuoteError::Invalid);
    }
    request.check_time(protocol::now()?)?;
    Ok(QuoteOutcome::DeviceUnavailable)
}
