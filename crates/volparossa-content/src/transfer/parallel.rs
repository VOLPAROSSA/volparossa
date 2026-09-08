//! Two independently authorized existing v1 streams, one cache writer and no duplicate requests.
//!
//! Each peer holds at most one assigned chunk and one bounded response. Only a verified cache
//! insertion completes that assignment. A miss or failed stream releases it to the other peer;
//! a merely slow in-flight request is never duplicated. Callers close and join both streams.

#[cfg(test)]
mod tests;

use std::collections::BTreeSet;

use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
    time::{Instant, timeout_at},
};

use super::{
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Request, Response, Session, TransferError,
    TransferLimits, TransferProgress, VERSION, check_time, read_frame, write_frame,
};
use crate::{Chunk, ChunkId, ChunkStore, VerifiedManifest};

enum Work {
    Chunk(Chunk),
    Finish,
}

struct PendingChunk {
    chunk: Chunk,
    attempted: u8,
    owner: Option<usize>,
    complete: bool,
}

struct Peer {
    requests: mpsc::Sender<Work>,
    results: mpsc::Receiver<Result<Option<Vec<u8>>, TransferError>>,
    pending: Option<usize>,
    live: bool,
}

/// A bounded writer/coordinator; workers never own or reopen the destination cache.
pub struct ParallelDownload {
    manifest: VerifiedManifest,
    chunks: Vec<PendingChunk>,
    peers: [Peer; 2],
    deadline: Instant,
}

/// One provider's exact subset of an independently authorized manifest; fields are not forgeable.
pub struct ChunkWorker {
    manifest: VerifiedManifest,
    requests: mpsc::Receiver<Work>,
    results: mpsc::Sender<Result<Option<Vec<u8>>, TransferError>>,
    limits: TransferLimits,
    deadline: Instant,
    session: Session,
    pending: Option<Chunk>,
    received: usize,
}

impl ParallelDownload {
    /// Prepare missing unique chunks and two worker handles without opening a stream.
    ///
    /// Drop an unused handle when only one provider exists. No cache lock is shared with workers.
    /// The initial deadline includes their caller-owned route/TLS setup, not only payload reads.
    ///
    /// # Errors
    /// Refuses invalid limits, expiry, insufficient whole-object capacity or corrupt cache hits.
    pub fn new(
        manifest: &VerifiedManifest,
        store: &mut ChunkStore,
        limits: TransferLimits,
    ) -> Result<(Self, [ChunkWorker; 2]), TransferError> {
        let limits = limits.validate()?;
        check_time(manifest)?;
        store.require_object_capacity(manifest.length())?;
        let deadline = Instant::now() + limits.session_timeout;
        let mut seen = BTreeSet::new();
        let mut chunks = Vec::new();
        for chunk in manifest.chunks() {
            if !seen.insert(*chunk.id()) {
                continue;
            }
            if let Some(bytes) = store.get(chunk.id())? {
                if bytes.len() as u64 != u64::from(chunk.length()) {
                    return Err(crate::Error::Integrity(*chunk.id()).into());
                }
                continue;
            }
            chunks.push(PendingChunk {
                chunk: chunk.clone(),
                attempted: 0,
                owner: None,
                complete: false,
            });
        }
        let (first, worker_a) = peer(manifest, limits, deadline);
        let (second, worker_b) = peer(manifest, limits, deadline);
        Ok((
            Self {
                manifest: manifest.clone(),
                chunks,
                peers: [first, second],
                deadline,
            },
            [worker_a, worker_b],
        ))
    }

    /// Commit responses from either peer as soon as ready, retaining actual progress on failure.
    ///
    /// Returns successfully when both peers have exhausted their eligible work, which may leave
    /// missing chunks for another pair/origin. It is not a full-object or clean-stream receipt.
    /// `progress` counts only this call's verified inserts, never cache hits or unverified data.
    ///
    /// # Errors
    /// Rejects local storage failure, expiry and the original whole-session deadline.
    pub async fn run(
        mut self,
        store: &mut ChunkStore,
        progress: &mut [TransferProgress; 2],
    ) -> Result<(), TransferError> {
        *progress = [TransferProgress::default(); 2];
        loop {
            check_time(&self.manifest)?;
            if Instant::now() >= self.deadline {
                return Err(TransferError::Timeout);
            }
            for index in 0..2 {
                self.assign(index)?;
            }
            let [first, second] = &mut self.peers;
            let wait_a = first.pending.is_some();
            let wait_b = second.pending.is_some();
            if !wait_a && !wait_b {
                break;
            }
            let (index, response) = tokio::select! {
                response = first.results.recv(), if wait_a => (0, response),
                response = second.results.recv(), if wait_b => (1, response),
                () = tokio::time::sleep_until(self.deadline) => return Err(TransferError::Timeout),
            };
            self.accept(index, response, store, progress)?;
        }
        for peer in &self.peers {
            if peer.live {
                let _ = peer.requests.try_send(Work::Finish);
            }
        }
        Ok(())
    }

    fn assign(&mut self, index: usize) -> Result<(), TransferError> {
        let peer = &mut self.peers[index];
        if !peer.live || peer.pending.is_some() {
            return Ok(());
        }
        let bit = 1_u8 << index;
        let Some((position, pending)) =
            self.chunks.iter_mut().enumerate().find(|(_, item)| {
                !item.complete && item.owner.is_none() && item.attempted & bit == 0
            })
        else {
            return Ok(());
        };
        match peer.requests.try_send(Work::Chunk(pending.chunk.clone())) {
            Ok(()) => {
                pending.attempted |= bit;
                pending.owner = Some(index);
                peer.pending = Some(position);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => peer.live = false,
            Err(mpsc::error::TrySendError::Full(_)) => return Err(TransferError::Protocol),
        }
        Ok(())
    }

    fn accept(
        &mut self,
        index: usize,
        response: Option<Result<Option<Vec<u8>>, TransferError>>,
        store: &mut ChunkStore,
        progress: &mut [TransferProgress; 2],
    ) -> Result<(), TransferError> {
        check_time(&self.manifest)?;
        let peer = &mut self.peers[index];
        let position = peer.pending.take().ok_or(TransferError::Protocol)?;
        let pending = &mut self.chunks[position];
        if pending.owner.take() != Some(index) {
            return Err(TransferError::Protocol);
        }
        match response {
            Some(Ok(Some(bytes))) => {
                if bytes.len() as u64 != u64::from(pending.chunk.length()) {
                    return Err(TransferError::Protocol);
                }
                store.put_verified(*pending.chunk.id(), &bytes)?;
                pending.complete = true;
                progress[index].chunks += 1;
                progress[index].bytes += u64::from(pending.chunk.length());
            }
            Some(Ok(None)) => progress[index].missing += 1,
            Some(Err(_)) | None => peer.live = false,
        }
        Ok(())
    }
}

fn peer(
    manifest: &VerifiedManifest,
    limits: TransferLimits,
    deadline: Instant,
) -> (Peer, ChunkWorker) {
    let (requests, incoming) = mpsc::channel(1);
    let (results, completed) = mpsc::channel(1);
    (
        Peer {
            requests,
            results: completed,
            pending: None,
            live: true,
        },
        ChunkWorker {
            manifest: manifest.clone(),
            requests: incoming,
            results,
            limits,
            deadline,
            session: Session {
                limits,
                deadline,
                requests: 0,
                requested_bytes: 0,
            },
            pending: None,
            received: 0,
        },
    )
}

impl ChunkWorker {
    /// The caller's independently verified exact publication, not a peer's replacement manifest.
    pub fn manifest(&self) -> &VerifiedManifest {
        &self.manifest
    }

    pub(crate) fn remaining_limits(&self) -> Result<TransferLimits, TransferError> {
        let mut limits = self.limits;
        limits.session_timeout = self.deadline.saturating_duration_since(Instant::now());
        if limits.session_timeout.is_zero() {
            return Err(TransferError::Timeout);
        }
        Ok(limits)
    }

    /// Whether a data-proven peer still owns a retryable chunk inside the original budget.
    /// This is not a cache receipt. The caller separately limits protected reconnection attempts
    /// and must never reconnect for corrupt bytes, policy/signature failures or explicit misses.
    pub fn has_resumable_assignment(&self) -> bool {
        self.received > 0 && self.pending.is_some() && Instant::now() < self.deadline
    }

    /// Pull only coordinator-assigned chunks over an already selected existing v1 stream.
    ///
    /// The caller must close the stream on every error. Dropping this worker lets the single
    /// writer release its one assignment to the other peer; active requests are never duplicated.
    ///
    /// # Errors
    /// Rejects malformed/corrupt responses, expiry, deadline, exhausted budget or writer failure.
    pub async fn run<S>(&mut self, stream: &mut S) -> Result<(), TransferError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        loop {
            let work = if let Some(chunk) = &self.pending {
                Work::Chunk(chunk.clone())
            } else {
                timeout_at(self.deadline, self.requests.recv())
                    .await
                    .map_err(|_| TransferError::Timeout)?
                    .ok_or(TransferError::Protocol)?
            };
            self.session.check_deadline()?;
            check_time(&self.manifest)?;
            match work {
                Work::Finish => {
                    let finish = Request {
                        version: VERSION,
                        hash: Vec::new(),
                        length: 0,
                        finish: true,
                    };
                    timeout_at(
                        self.session.exchange_deadline(),
                        write_frame(stream, &finish, MAX_REQUEST_BYTES),
                    )
                    .await
                    .map_err(|_| TransferError::Timeout)??;
                    check_time(&self.manifest)?;
                    return Ok(());
                }
                Work::Chunk(chunk) => {
                    self.pending = Some(chunk.clone());
                    let result = fetch(stream, &mut self.session, &self.manifest, &chunk).await?;
                    if result.is_some() {
                        self.received += 1;
                    }
                    self.results
                        .send(Ok(result))
                        .await
                        .map_err(|_| TransferError::Protocol)?;
                    self.pending = None;
                }
            }
        }
    }
}

async fn fetch<S>(
    stream: &mut S,
    session: &mut Session,
    manifest: &VerifiedManifest,
    chunk: &Chunk,
) -> Result<Option<Vec<u8>>, TransferError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
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
    if !response.found {
        return Ok(None);
    }
    if ChunkId::digest(&response.data) != *chunk.id() {
        return Err(crate::Error::Integrity(*chunk.id()).into());
    }
    Ok(Some(response.data))
}
