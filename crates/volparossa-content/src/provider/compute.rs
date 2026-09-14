//! Short signed compute exchanges over an already protected provider stream.
//!
//! Submit/poll/cancel are bounded control exchanges, not a model execution timeout.
//! The backend owns authorization, actual worker leases and cancellation. This module
//! never opens sockets, chooses a dataset, executes code or grants tool permissions.

mod protocol;
pub mod dataset;

use std::{future::Future, pin::Pin, sync::Arc, time::Duration};

use ed25519_dalek::SigningKey;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    time::timeout,
};

use protocol::{Kind, Record, now, read, write};

/// Additive content selector version; no unprotected transport fallback.
pub const SELECTOR_VERSION: u32 = 1;
/// Compute control is distinct from native chunks, custody and mailboxes.
pub const SELECTOR_OPERATION: u32 = 5;
/// Maximum exact request bytes passed to the separately validated broker contract.
pub const MAX_REQUEST_BYTES: usize = 2 * 1024 * 1024;
/// Maximum exact broker response bytes, not a model weight transfer.
pub const MAX_RESPONSE_BYTES: usize = 64 * 1024;
const FRAME_OVERHEAD: usize = 1024;
const EXCHANGE_SECONDS: u64 = 30;

/// Failures never imply that an asynchronously submitted model job was cancelled.
#[derive(Debug, thiserror::Error)]
pub enum ComputeError {
    /// Supplied protected stream failed.
    #[error("compute control stream failed")]
    Io(#[from] std::io::Error),
    /// Unsupported or noncanonical framing, identity, binding or length.
    #[error("invalid compute control record")]
    Invalid,
    /// Expected signer, fresh challenge or exact request binding did not match.
    #[error("compute control authentication failed")]
    Authentication,
    /// Record or short exchange expired; existing jobs retain their own bounded leases.
    #[error("compute control exchange expired")]
    Expired,
    /// Operating-system nonce generation failed.
    #[error("compute control randomness unavailable")]
    Entropy,
    /// Explicitly attached broker is unavailable or declined the request.
    #[error("compute broker unavailable")]
    Unavailable,
}

/// Caller-owned asynchronous backend, without a global retrieval lock.
pub type ComputeFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, ComputeError>> + Send + 'a>>;

/// Adapter to the explicitly configured local broker.
pub trait ComputeBackend: Send + Sync {
    /// Validate the typed request and its claimed requester against this authenticated key.
    /// Return a short capability/job-state response, never await a complete training job.
    /// A signed caller is an identity, not automatic permission to consume resources.
    fn exchange(&self, requester: [u8; 32], request: Vec<u8>) -> ComputeFuture<'_>;
}

/// An explicitly attached local compute backend plus the existing provider signing identity.
pub struct ComputeService {
    signer: Arc<SigningKey>,
    backend: Arc<dyn ComputeBackend>,
}

impl ComputeService {
    /// Attach an owned broker; this does not advertise, listen or activate a model.
    pub fn new(signer: Arc<SigningKey>, backend: Arc<dyn ComputeBackend>) -> Self {
        Self { signer, backend }
    }

    /// Serve one fresh challenge-bound request after the enclosing selector is validated.
    ///
    /// # Errors
    /// Rejects malformed signatures, replay from another stream, stale records and bad replies.
    /// Close the stream after success or error; retries use a new challenge and same job binding.
    pub async fn serve<S>(&self, stream: &mut S) -> Result<(), ComputeError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        timeout(Duration::from_secs(EXCHANGE_SECONDS), async {
            let challenge = Record::challenge(&self.signer, now()?)?;
            write(stream, &challenge.encode(), FRAME_OVERHEAD).await?;
            let bytes = read(stream, MAX_REQUEST_BYTES + FRAME_OVERHEAD).await?;
            let request = Record::decode(&bytes, Kind::Request, now()?)?;
            request.matches_challenge(&challenge)?;
            let request_hash: [u8; 32] = Sha256::digest(&bytes).into();
            let result = self
                .backend
                .exchange(request.sender(), request.payload().to_vec())
                .await?;
            if result.is_empty() || result.len() > MAX_RESPONSE_BYTES {
                return Err(ComputeError::Invalid);
            }
            let reply = Record::reply(&self.signer, &challenge, request_hash, result, now()?)?;
            write(stream, &reply.encode(), MAX_RESPONSE_BYTES + FRAME_OVERHEAD).await
        })
        .await
        .map_err(|_| ComputeError::Expired)?
    }
}

/// A fresh independently provider-authenticated connection challenge.
/// Not cloneable: one owned challenge is consumed by exactly one client exchange.
pub struct ComputeChallenge(Record);

/// Select compute on the supplied policy-authorized, provider-authenticated stream.
///
/// # Errors
/// Rejects malformed, expired or wrong-provider challenges; no fallback socket is opened.
pub async fn begin<S>(stream: &mut S, provider: &[u8; 32]) -> Result<ComputeChallenge, ComputeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(Duration::from_secs(EXCHANGE_SECONDS), async {
        super::write_frame(
            stream,
            &super::Selector {
                version: SELECTOR_VERSION,
                operation: SELECTOR_OPERATION,
                manifest_id: Vec::new(),
            },
        )
        .await
        .map_err(|_| ComputeError::Invalid)?;
        let challenge = Record::decode(
            &read(stream, FRAME_OVERHEAD).await?,
            Kind::Challenge,
            now()?,
        )?;
        if &challenge.sender() != provider {
            return Err(ComputeError::Authentication);
        }
        Ok(ComputeChallenge(challenge))
    })
    .await
    .map_err(|_| ComputeError::Expired)?
}

/// Sign and execute one short exchange on the same stream that supplied the challenge.
///
/// # Errors
/// Rejects oversize input, provider substitution, different-request replies and expiry.
/// The returned bytes still require typed broker-response and semantic result validation.
pub async fn exchange<S>(
    stream: &mut S,
    challenge: ComputeChallenge,
    requester: &SigningKey,
    payload: Vec<u8>,
) -> Result<Vec<u8>, ComputeError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(Duration::from_secs(EXCHANGE_SECONDS), async {
        let request = Record::request(requester, &challenge.0, payload, now()?)?;
        let bytes = request.encode();
        let expected: [u8; 32] = Sha256::digest(&bytes).into();
        write(stream, &bytes, MAX_REQUEST_BYTES + FRAME_OVERHEAD).await?;
        let reply = Record::decode(
            &read(stream, MAX_RESPONSE_BYTES + FRAME_OVERHEAD).await?,
            Kind::Reply,
            now()?,
        )?;
        reply.matches_challenge(&challenge.0)?;
        if reply.sender() != challenge.0.sender() || reply.request_hash() != expected {
            return Err(ComputeError::Authentication);
        }
        Ok(reply.payload().to_vec())
    })
    .await
    .map_err(|_| ComputeError::Expired)?
}

#[cfg(test)]
mod tests;
