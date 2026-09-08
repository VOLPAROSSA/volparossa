//! Pull explicitly published native chunks over an already established protected stream.
//!
//! This module never dials or listens. The application must supply its policy-authorized,
//! encrypted overlay stream; a plain socket is not a substitute for the required route.
//! The consumer's manifest is authenticated independently of the serving peer. Providers
//! need only a verified manifest and cached pieces, not the publisher's private key.
//! These are bounded data frames inside that stream, not discovery/control messages or
//! proof of an HTTPS origin. Provider discovery and origin fallback belong to the caller.

use std::collections::BTreeMap;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use prost::Message;
use sha2::{Digest as _, Sha256};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout_at};

use crate::{CHUNK_BYTES, ChunkId, ChunkStore, MAX_CHUNKS, MAX_OBJECT_BYTES, VerifiedManifest};

pub mod parallel;

const VERSION: u32 = 1;
const MAX_REQUEST_BYTES: usize = 64;
const MAX_RESPONSE_BYTES: usize = CHUNK_BYTES + 64;

/// Hard ceilings for a single peer session, including unsuccessful chunk requests.
#[derive(Clone, Copy, Debug)]
pub struct TransferLimits {
    /// Maximum complete request/response time; byte trickling does not reset this timer.
    pub exchange_timeout: Duration,
    /// Maximum lifetime of the whole operation, never extended by successful requests.
    pub session_timeout: Duration,
    /// Maximum requested chunks, at most the maximum manifest chunk count.
    pub max_requests: usize,
    /// Maximum requested payload bytes, counting misses too.
    pub max_bytes: u64,
}

impl Default for TransferLimits {
    fn default() -> Self {
        Self {
            exchange_timeout: Duration::from_secs(15),
            session_timeout: Duration::from_secs(300),
            max_requests: MAX_CHUNKS,
            max_bytes: MAX_OBJECT_BYTES,
        }
    }
}

impl TransferLimits {
    fn validate(self) -> Result<Self, TransferError> {
        if self.exchange_timeout.is_zero()
            || self.exchange_timeout > Duration::from_secs(60)
            || self.session_timeout.is_zero()
            || self.session_timeout > Duration::from_secs(900)
            || self.max_requests == 0
            || self.max_requests > MAX_CHUNKS
            || self.max_bytes == 0
            || self.max_bytes > MAX_OBJECT_BYTES
        {
            return Err(TransferError::Limit);
        }
        Ok(self)
    }
}

/// Actual verified chunk payload transferred in one session, not network wire accounting.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct TransferProgress {
    /// Successfully verified and stored chunks, or chunks successfully sent by the provider.
    pub chunks: usize,
    /// Their total payload length, excluding framing, encryption and transport overhead.
    pub bytes: u64,
    /// Requested chunks that this provider did not hold; another provider is still needed.
    pub missing: usize,
}

/// An unsuccessful peer never contributes unverified bytes to the consumer cache.
#[derive(Debug, thiserror::Error)]
pub enum TransferError {
    /// Manifest, local store or chunk verification failure.
    #[error(transparent)]
    Content(#[from] crate::Error),
    /// The supplied stream failed or ended before a complete frame.
    #[error("content stream failed: {0}")]
    Io(#[from] std::io::Error),
    /// Invalid version, canonical encoding, correlation, scope or frame length.
    #[error("invalid content data frame")]
    Protocol,
    /// One complete exchange or the whole session exceeded its deadline.
    #[error("content peer deadline exceeded")]
    Timeout,
    /// Invalid configuration or bounded request/byte budget exhausted.
    #[error("content peer resource limit exceeded")]
    Limit,
}

#[derive(Clone, PartialEq, Message)]
struct Request {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    hash: Vec<u8>,
    #[prost(uint32, tag = "3")]
    length: u32,
    #[prost(bool, tag = "4")]
    finish: bool,
}

#[derive(Clone, PartialEq, Message)]
struct Response {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    hash: Vec<u8>,
    #[prost(uint32, tag = "3")]
    length: u32,
    #[prost(bool, tag = "4")]
    found: bool,
    #[prost(bytes = "vec", tag = "5")]
    data: Vec<u8>,
}

struct Session {
    limits: TransferLimits,
    deadline: Instant,
    requests: usize,
    requested_bytes: u64,
}

impl Session {
    fn new(limits: TransferLimits) -> Result<Self, TransferError> {
        let limits = limits.validate()?;
        Ok(Self {
            limits,
            deadline: Instant::now() + limits.session_timeout,
            requests: 0,
            requested_bytes: 0,
        })
    }

    fn exchange_deadline(&self) -> Instant {
        self.deadline
            .min(Instant::now() + self.limits.exchange_timeout)
    }

    fn check_deadline(&self) -> Result<(), TransferError> {
        if Instant::now() >= self.deadline {
            return Err(TransferError::Timeout);
        }
        Ok(())
    }

    fn reserve(&mut self, length: u32) -> Result<(), TransferError> {
        if self.requests >= self.limits.max_requests
            || u64::from(length) > self.limits.max_bytes - self.requested_bytes
        {
            return Err(TransferError::Limit);
        }
        self.requests += 1;
        self.requested_bytes += u64::from(length);
        Ok(())
    }
}

/// Fill absent chunks from one peer, verifying every byte before inserting it locally.
///
/// `manifest` must describe the exact object the application requested, not merely any
/// object signed by some peer-supplied key. Cache hits skip requests. Missing pieces are
/// counted, not declared complete: callers may repeat with another protected peer stream,
/// then use `reassemble_to_file` to publish only a complete authenticated object.
/// The receiving cache must have room for the whole object to avoid evicting its prefix.
/// Verified pieces received before an error remain useful and quota-accounted.
///
/// # Errors
/// Rejects expired manifests, malformed/corrupt responses, timeouts and resource limits.
/// On any error the caller must close this stream; it is not reusable for another session.
pub async fn pull_from_peer<S>(
    stream: &mut S,
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    limits: TransferLimits,
) -> Result<TransferProgress, TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut progress = TransferProgress::default();
    pull_from_peer_with_progress(stream, manifest, store, limits, &mut progress).await?;
    Ok(progress)
}

/// Pull chunks while retaining verified payload progress even if a later exchange fails.
///
/// Resets `progress` before starting and updates it only after successful verified inserts.
/// Existing cache hits and cache eviction do not contribute to these per-session counts.
/// Dropping this future preserves progress already recorded, but does not make it complete.
///
/// # Errors
/// Same failures and stream-close requirement as [`pull_from_peer`].
pub async fn pull_from_peer_with_progress<S>(
    stream: &mut S,
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    limits: TransferLimits,
    progress: &mut TransferProgress,
) -> Result<(), TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    *progress = TransferProgress::default();
    let mut session = Session::new(limits)?;
    check_time(manifest)?;
    store.require_object_capacity(manifest.length())?;
    for chunk in manifest.chunks() {
        session.check_deadline()?;
        check_time(manifest)?;
        if store.get(chunk.id())?.is_some() {
            continue;
        }
        session.reserve(chunk.length())?;
        let request = Request {
            version: VERSION,
            hash: chunk.id().as_bytes().to_vec(),
            length: chunk.length(),
            finish: false,
        };
        let response: Response = timeout_at(session.exchange_deadline(), async {
            write_frame(stream, &request, MAX_REQUEST_BYTES).await?;
            read_frame(stream, MAX_RESPONSE_BYTES).await
        })
        .await
        .map_err(|_| TransferError::Timeout)??;
        check_time(manifest)?;
        if response.version != VERSION
            || response.hash != request.hash
            || response.length != request.length
            || (!response.found && !response.data.is_empty())
            || (response.found && response.data.len() as u64 != u64::from(chunk.length()))
        {
            return Err(TransferError::Protocol);
        }
        if response.found {
            store.put_verified(*chunk.id(), &response.data)?;
            progress.chunks += 1;
            progress.bytes += u64::from(chunk.length());
        } else {
            progress.missing += 1;
        }
    }
    let finish = Request {
        version: VERSION,
        hash: Vec::new(),
        length: 0,
        finish: true,
    };
    session.check_deadline()?;
    timeout_at(
        session.exchange_deadline(),
        write_frame(stream, &finish, MAX_REQUEST_BYTES),
    )
    .await
    .map_err(|_| TransferError::Timeout)??;
    session.check_deadline()?;
    check_time(manifest)?;
    Ok(())
}

/// Pull one complete ordered object directly to a caller-owned writer using the existing frames.
///
/// Buffers at most one chunk; verifies every chunk and the complete hash without a second cache.
/// The writer may contain a verified prefix on failure: publish it only after success and any
/// enclosing HTTPS authorization/final-receipt checks. The manifest's trust belongs to the caller.
///
/// # Errors
/// Rejects missing/corrupt data, expiry, framing, output errors and bounded deadlines/budgets.
pub async fn pull_to_writer<S, W>(
    stream: &mut S,
    manifest: &VerifiedManifest,
    writer: &mut W,
    limits: TransferLimits,
) -> Result<TransferProgress, TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    W: std::io::Write,
{
    let mut session = Session::new(limits)?;
    let mut progress = TransferProgress::default();
    let mut whole_hash = Sha256::new();
    for chunk in manifest.chunks() {
        session.check_deadline()?;
        check_time(manifest)?;
        session.reserve(chunk.length())?;
        let request = Request {
            version: VERSION,
            hash: chunk.id().as_bytes().to_vec(),
            length: chunk.length(),
            finish: false,
        };
        let response: Response = timeout_at(session.exchange_deadline(), async {
            write_frame(stream, &request, MAX_REQUEST_BYTES).await?;
            read_frame(stream, MAX_RESPONSE_BYTES).await
        })
        .await
        .map_err(|_| TransferError::Timeout)??;
        check_time(manifest)?;
        if response.version != VERSION
            || response.hash != request.hash
            || response.length != request.length
            || !response.found
            || response.data.len() as u64 != u64::from(chunk.length())
        {
            return Err(TransferError::Protocol);
        }
        if ChunkId::digest(&response.data) != *chunk.id() {
            return Err(crate::Error::Integrity(*chunk.id()).into());
        }
        writer.write_all(&response.data)?;
        whole_hash.update(&response.data);
        progress.chunks += 1;
        progress.bytes += u64::from(chunk.length());
    }
    if progress.bytes != manifest.length()
        || <[u8; 32]>::from(whole_hash.finalize()) != manifest.whole_hash
    {
        return Err(TransferError::Protocol);
    }
    let finish = Request {
        version: VERSION,
        hash: Vec::new(),
        length: 0,
        finish: true,
    };
    session.check_deadline()?;
    timeout_at(
        session.exchange_deadline(),
        write_frame(stream, &finish, MAX_REQUEST_BYTES),
    )
    .await
    .map_err(|_| TransferError::Timeout)??;
    session.check_deadline()?;
    check_time(manifest)?;
    Ok(progress)
}

/// Serve only pieces named by one explicitly approved, verified native publication.
///
/// A partial replica reports missing chunks without requiring an online publisher or its
/// signing key. Arbitrary hashes outside this publication are rejected, not probed on disk.
/// The caller supplies a protected, authorized stream and decides which public publication
/// may be served; this API does not enable sharing of captured browsing data.
///
/// # Errors
/// Rejects expired manifests, out-of-scope requests, corrupt local pieces and exhausted
/// deadlines/budgets. On error the caller must close the supplied stream.
pub async fn serve_peer<S>(
    stream: &mut S,
    manifest: &VerifiedManifest,
    store: &mut ChunkStore,
    limits: TransferLimits,
) -> Result<TransferProgress, TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut session = Session::new(limits)?;
    check_time(manifest)?;
    let allowed: BTreeMap<ChunkId, u32> = manifest
        .chunks()
        .iter()
        .map(|chunk| (*chunk.id(), chunk.length()))
        .collect();
    let mut progress = TransferProgress::default();
    loop {
        session.check_deadline()?;
        let deadline = session.exchange_deadline();
        let request: Request = timeout_at(deadline, read_frame(stream, MAX_REQUEST_BYTES))
            .await
            .map_err(|_| TransferError::Timeout)??;
        session.check_deadline()?;
        check_time(manifest)?;
        if request.version != VERSION {
            return Err(TransferError::Protocol);
        }
        if request.finish {
            if !request.hash.is_empty() || request.length != 0 {
                return Err(TransferError::Protocol);
            }
            return Ok(progress);
        }
        let id = ChunkId(
            request
                .hash
                .as_slice()
                .try_into()
                .map_err(|_| TransferError::Protocol)?,
        );
        if allowed.get(&id).copied() != Some(request.length) {
            return Err(TransferError::Protocol);
        }
        session.reserve(request.length)?;
        let data = store.get(&id)?;
        if data
            .as_ref()
            .is_some_and(|bytes| bytes.len() as u64 != u64::from(request.length))
        {
            return Err(crate::Error::Integrity(id).into());
        }
        let response = Response {
            version: VERSION,
            hash: request.hash,
            length: request.length,
            found: data.is_some(),
            data: data.unwrap_or_default(),
        };
        timeout_at(deadline, write_frame(stream, &response, MAX_RESPONSE_BYTES))
            .await
            .map_err(|_| TransferError::Timeout)??;
        if response.found {
            progress.chunks += 1;
            progress.bytes += u64::from(response.length);
        } else {
            progress.missing += 1;
        }
    }
}

fn check_time(manifest: &VerifiedManifest) -> Result<(), TransferError> {
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| crate::Error::Expired)?
        .as_secs();
    manifest.check_time(now)?;
    Ok(())
}

async fn read_frame<S, M>(stream: &mut S, maximum: usize) -> Result<M, TransferError>
where
    S: AsyncRead + Unpin,
    M: Message + Default,
{
    let length = usize::try_from(stream.read_u32().await?).map_err(|_| TransferError::Protocol)?;
    if length == 0 || length > maximum {
        return Err(TransferError::Protocol);
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    let frame = M::decode(bytes.as_slice()).map_err(|_| TransferError::Protocol)?;
    if frame.encode_to_vec() != bytes {
        return Err(TransferError::Protocol);
    }
    Ok(frame)
}

async fn write_frame<S, M>(stream: &mut S, frame: &M, maximum: usize) -> Result<(), TransferError>
where
    S: AsyncWrite + Unpin,
    M: Message,
{
    let bytes = frame.encode_to_vec();
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(TransferError::Protocol);
    }
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(|_| TransferError::Protocol)?)
        .await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}
