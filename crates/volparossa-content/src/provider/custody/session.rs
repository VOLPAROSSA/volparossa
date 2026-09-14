use std::time::Duration;

use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{Instant, timeout, timeout_at},
};

use super::{
    CustodyAuthorization, CustodyChallenge, CustodyError, CustodyOperation, CustodyReceipt,
    CustodyService, CustodyState, SELECTOR_OPERATION, SELECTOR_VERSION,
    protocol::{AUTH_FRAME, SMALL_FRAME, now},
};
use crate::{
    ChunkStore, MAX_CHUNKS, MAX_OBJECT_BYTES,
    transfer::{TransferLimits, TransferProgress, pull_from_peer, serve_peer},
};

impl CustodyService {
    /// Serve one fresh operation after the enclosing provider selector is validated.
    ///
    /// # Errors
    /// Rejects replay, unsupported/private input, expiry, failed transfer or incomplete commit.
    /// Drop/close the supplied stream after every error; no direct transport is opened here.
    pub async fn serve<S>(
        &self,
        stream: &mut S,
        limits: TransferLimits,
    ) -> Result<TransferProgress, CustodyError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        validate_limits(limits)?;
        let deadline = Instant::now() + limits.session_timeout;
        timeout_at(deadline, async {
            let challenge = CustodyChallenge::new(&self.signer, now()?)?;
            write_frame(stream, &challenge.encode(), SMALL_FRAME).await?;
            let bytes = read_frame(stream, AUTH_FRAME).await?;
            let auth = CustodyAuthorization::decode(&bytes, &challenge, now()?)?;
            let remaining = auth.expires().saturating_sub(now()?);
            if remaining == 0 {
                return Err(CustodyError::Expired);
            }
            let deadline = deadline.min(Instant::now() + Duration::from_secs(remaining));
            timeout_at(deadline, async {
                let (state, progress) = match auth.operation() {
                    CustodyOperation::Deposit => {
                        let mut admission = self
                            .backend
                            .begin_deposit(auth.signed_manifest().clone(), auth.manifest().clone())
                            .await?;
                        auth.check(now()?)?;
                        let progress = pull_from_peer(
                            stream,
                            auth.manifest(),
                            admission.store(),
                            remaining_limits(limits, deadline)?,
                        )
                        .await?;
                        auth.check(now()?)?;
                        // The backend verifies all retained bytes and commits the existing journal
                        // and ready serving; payload progress alone is never a receipt.
                        admission.commit().await?;
                        (CustodyState::Complete, progress)
                    }
                    CustodyOperation::Inspect => (
                        self.backend
                            .inspect(auth.signed_manifest().clone(), auth.manifest().clone())
                            .await?,
                        TransferProgress::default(),
                    ),
                };
                auth.check(now()?)?;
                let receipt = CustodyReceipt::new(&self.signer, &auth, state, now()?)?;
                write_frame(stream, &receipt.encode(), SMALL_FRAME).await?;
                Ok(progress)
            })
            .await
            .map_err(|_| CustodyError::Timeout)?
        })
        .await
        .map_err(|_| CustodyError::Timeout)?
    }
}

/// Select custody on an already policy-authorized, authenticated provider stream.
///
/// # Errors
/// Rejects stale or wrong-provider challenges and bounded framing/I/O failures.
pub async fn begin<S>(stream: &mut S, provider: &[u8; 32]) -> Result<CustodyChallenge, CustodyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(Duration::from_secs(15), async {
        super::super::write_frame(
            stream,
            &super::super::Selector {
                version: SELECTOR_VERSION,
                manifest_id: Vec::new(),
                operation: SELECTOR_OPERATION,
            },
        )
        .await
        .map_err(|_| CustodyError::Invalid)?;
        let bytes = read_frame(stream, SMALL_FRAME).await?;
        CustodyChallenge::decode(&bytes, provider, now()?)
    })
    .await
    .map_err(|_| CustodyError::Timeout)?
}

/// Execute one already publisher-signed operation without giving the provider a signing key.
/// Deposit supplies an existing caller-owned cache; Inspect supplies no payload/cache.
///
/// # Errors
/// Rejects request/challenge substitution, expiry, incomplete uploads or wrong signed receipts.
/// All operation futures remain caller-owned and must be dropped together with a failed stream.
pub async fn execute<S>(
    stream: &mut S,
    challenge: &CustodyChallenge,
    authorization: &CustodyAuthorization,
    source: Option<&mut ChunkStore>,
    limits: TransferLimits,
) -> Result<CustodyReceipt, CustodyError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    validate_limits(limits)?;
    let auth = CustodyAuthorization::decode(&authorization.encode(), challenge, now()?)?;
    if (auth.operation() == CustodyOperation::Deposit) != source.is_some() {
        return Err(CustodyError::Invalid);
    }
    let remaining = auth.expires().saturating_sub(now()?);
    if remaining == 0 {
        return Err(CustodyError::Expired);
    }
    let deadline = Instant::now() + limits.session_timeout.min(Duration::from_secs(remaining));
    timeout_at(deadline, async {
        write_frame(stream, &auth.encode(), AUTH_FRAME).await?;
        if let Some(source) = source {
            serve_peer(
                stream,
                auth.manifest(),
                source,
                remaining_limits(limits, deadline)?,
            )
            .await?;
        }
        let receipt = read_frame(stream, SMALL_FRAME).await?;
        CustodyReceipt::decode(&receipt, &auth, now()?)
    })
    .await
    .map_err(|_| CustodyError::Timeout)?
}

/// Bridge only the caller's exact publisher-authorized operation on the selected stream.
/// The publisher key stays in the local application. One bounded chunk at a time is checked
/// against the original manifest; no raw copy, arbitrary hash request or storage path exists.
///
/// # Errors
/// Rejects changed operation/publication/provider, replay, invalid chunks/receipts and expiry.
pub async fn bridge<L, R>(
    local: &mut L,
    remote: &mut R,
    challenge: &CustodyChallenge,
    signed: &crate::SignedManifest,
    operation: CustodyOperation,
    limits: TransferLimits,
) -> Result<CustodyReceipt, CustodyError>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    validate_limits(limits)?;
    let started = Instant::now();
    timeout_at(started + limits.session_timeout, async {
        let bytes = read_frame(local, AUTH_FRAME).await?;
        let auth = CustodyAuthorization::decode(&bytes, challenge, now()?)?;
        if auth.operation() != operation || auth.signed_manifest().encode() != signed.encode() {
            return Err(CustodyError::Unauthorized);
        }
        let remaining = auth.expires().saturating_sub(now()?);
        if remaining == 0 {
            return Err(CustodyError::Expired);
        }
        let deadline =
            (started + limits.session_timeout).min(Instant::now() + Duration::from_secs(remaining));
        timeout_at(deadline, async {
            write_frame(remote, &bytes, AUTH_FRAME).await?;
            if operation == CustodyOperation::Deposit {
                crate::transfer::bridge_peer(
                    remote,
                    local,
                    auth.manifest(),
                    remaining_limits(limits, deadline)?,
                )
                .await?;
            }
            let bytes = read_frame(remote, SMALL_FRAME).await?;
            let receipt = CustodyReceipt::decode(&bytes, &auth, now()?)?;
            write_frame(local, &bytes, SMALL_FRAME).await?;
            Ok(receipt)
        })
        .await
        .map_err(|_| CustodyError::Timeout)?
    })
    .await
    .map_err(|_| CustodyError::Timeout)?
}

fn validate_limits(limits: TransferLimits) -> Result<(), CustodyError> {
    if limits.exchange_timeout.is_zero()
        || limits.exchange_timeout > Duration::from_secs(60)
        || limits.session_timeout.is_zero()
        || limits.session_timeout > Duration::from_secs(900)
        || limits.max_requests == 0
        || limits.max_requests > MAX_CHUNKS
        || limits.max_bytes == 0
        || limits.max_bytes > MAX_OBJECT_BYTES
    {
        return Err(CustodyError::Invalid);
    }
    Ok(())
}

fn remaining_limits(
    mut limits: TransferLimits,
    deadline: Instant,
) -> Result<TransferLimits, CustodyError> {
    limits.session_timeout = deadline.saturating_duration_since(Instant::now());
    if limits.session_timeout.is_zero() {
        return Err(CustodyError::Timeout);
    }
    Ok(limits)
}

pub(super) async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    maximum: usize,
) -> Result<Vec<u8>, CustodyError> {
    let length = usize::try_from(stream.read_u32().await?).map_err(|_| CustodyError::Invalid)?;
    if length == 0 || length > maximum {
        return Err(CustodyError::Invalid);
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

pub(super) async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
    maximum: usize,
) -> Result<(), CustodyError> {
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(CustodyError::Invalid);
    }
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(|_| CustodyError::Invalid)?)
        .await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}
