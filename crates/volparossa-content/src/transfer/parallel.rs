//! Independently authorized existing v1 streams, one cache writer and no duplicate requests.
//!
//! Each peer holds at most one assigned chunk and one bounded response. Only a verified cache
//! insertion completes that assignment. A miss or failed stream releases it to another peer;
//! a merely slow in-flight request is never duplicated. Callers close and join every stream.

mod adaptive;

#[cfg(test)]
mod tests;

use std::{collections::BTreeSet, future::poll_fn, task::Poll};

use tokio::{
    io::{AsyncRead, AsyncWrite},
    sync::mpsc,
    time::{Instant, timeout_at},
};

use super::{
    MAX_REQUEST_BYTES, MAX_RESPONSE_BYTES, Request, Response, Session, TransferError,
    TransferLimits, TransferProgress, VERSION, check_time, read_frame, write_frame,
};
use crate::{
    Chunk, ChunkId, ChunkStore, VerifiedManifest, private_message::PRIVATE_MESSAGE_CONTENT_TYPE,
};

enum Work {
    Chunk(Chunk),
    Finish,
}

struct PendingChunk {
    chunk: Chunk,
    attempted: BTreeSet<usize>,
    owner: Option<usize>,
    complete: bool,
}

struct Peer {
    requests: mpsc::Sender<Work>,
    results: mpsc::Receiver<Result<Option<Vec<u8>>, TransferError>>,
    pending: Option<usize>,
    state: adaptive::PeerState,
    probing: bool,
}

/// A bounded writer/coordinator; workers never own or reopen the destination cache.
pub struct ParallelDownload {
    manifest: VerifiedManifest,
    chunks: Vec<PendingChunk>,
    peers: Vec<Peer>,
    deadline: Instant,
    adaptive: bool,
    explore: bool,
    measurement: adaptive::Measurement,
    probe_baseline: Option<u64>,
    growth_blocked: bool,
}

/// One provider's original transport index for coordinator-assigned chunks; fields are sealed.
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
        let (download, workers) = Self::prepare(manifest, &[manifest; 2], store, limits, None)?;
        Ok((
            download,
            workers.try_into().map_err(|_| TransferError::Protocol)?,
        ))
    }

    /// Combine identical public chunk layouts while selecting each provider's original index.
    ///
    /// This changes only transport selection, never publisher or HTTPS authority. Callers must
    /// independently authorize the expected object and verify its complete hash before output.
    /// Each worker retains its own signed manifest identity and checks its original expiry;
    /// the coordinator retains `expected`, one writer and the ordinary no-duplicate assignments.
    /// Names, revisions, signers and envelope nonces need not match. No envelope is rewritten.
    /// Ordinary native/name callers keep [`Self::new`]'s exact-manifest contract.
    ///
    /// # Errors
    /// Rejects private-message content, expired indexes, or differing whole hashes, lengths,
    /// media types or ordered chunk references, plus the usual limits/cache errors from `new`.
    pub fn new_with_transport_manifests(
        expected: &VerifiedManifest,
        transports: [&VerifiedManifest; 2],
        store: &mut ChunkStore,
        limits: TransferLimits,
    ) -> Result<(Self, [ChunkWorker; 2]), TransferError> {
        validate_transports(expected, &transports)?;
        let (download, workers) = Self::prepare(expected, &transports, store, limits, None)?;
        Ok((
            download,
            workers.try_into().map_err(|_| TransferError::Protocol)?,
        ))
    }

    /// Prepare an adaptive set of exact-publication workers, without opening their streams.
    ///
    /// The caller bounds the candidate list and supplies its current resource allowance. Only
    /// at most two workers initially receive work; unassigned workers must remain disconnected.
    /// This exact-index constructor preserves ordinary native/private publication authority.
    ///
    /// # Errors
    /// Refuses invalid limits, expiry, insufficient object capacity or corrupt cache hits.
    pub fn new_adaptive(
        manifest: &VerifiedManifest,
        worker_count: usize,
        store: &mut ChunkStore,
        limits: TransferLimits,
        initial_allowance: usize,
    ) -> Result<(Self, Vec<ChunkWorker>), TransferError> {
        Self::prepare(
            manifest,
            &vec![manifest; worker_count],
            store,
            limits,
            Some(initial_allowance),
        )
    }

    /// Adapt across original public indexes with exactly the authorized object's chunk layout.
    ///
    /// As with [`Self::new_with_transport_manifests`], indexes are transport selection only;
    /// whole-object and consumer authority verification remain the caller's responsibility.
    /// There is no additional provider-count ceiling: the supplied, caller-bounded candidates,
    /// missing unique chunks and live resource allowance bound useful active work.
    ///
    /// # Errors
    /// Rejects private content, expired/incompatible indexes and invalid limits/cache state.
    pub fn new_adaptive_with_transport_manifests(
        expected: &VerifiedManifest,
        transports: &[&VerifiedManifest],
        store: &mut ChunkStore,
        limits: TransferLimits,
        initial_allowance: usize,
    ) -> Result<(Self, Vec<ChunkWorker>), TransferError> {
        validate_transports(expected, transports)?;
        Self::prepare(expected, transports, store, limits, Some(initial_allowance))
    }

    fn prepare(
        manifest: &VerifiedManifest,
        transports: &[&VerifiedManifest],
        store: &mut ChunkStore,
        limits: TransferLimits,
        initial_allowance: Option<usize>,
    ) -> Result<(Self, Vec<ChunkWorker>), TransferError> {
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
                attempted: BTreeSet::new(),
                owner: None,
                complete: false,
            });
        }
        let width = initial_allowance.map_or(transports.len(), |available| available.min(2));
        let (peers, workers) = transports
            .iter()
            .enumerate()
            .map(|(index, manifest)| peer(manifest, limits, deadline, index < width))
            .unzip();
        Ok((
            Self {
                manifest: manifest.clone(),
                chunks,
                peers,
                deadline,
                adaptive: initial_allowance.is_some(),
                explore: false,
                measurement: adaptive::Measurement::new(),
                probe_baseline: None,
                growth_blocked: false,
            },
            workers,
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
        self,
        store: &mut ChunkStore,
        progress: &mut [TransferProgress; 2],
    ) -> Result<(), TransferError> {
        self.run_with_allowance(store, progress, || 2).await
    }

    /// Run one writer with a live resource ceiling; pressure stops credits, never duplicates them.
    ///
    /// `allowance` reports this operation's permitted active streams, including its existing
    /// leases. Surplus workers finish after their current response. The caller must acquire its
    /// actual lease after [`ChunkWorker::wait_for_assignment`] and drop the worker immediately
    /// if that last race check fails. Progress survives partial exhaustion and deadline errors.
    /// This is local measured adaptation, not a promise of radio fairness or a global speedup.
    ///
    /// # Errors
    /// Rejects a mismatched progress slice, local storage failure, expiry or the original deadline.
    pub async fn run_with_allowance(
        mut self,
        store: &mut ChunkStore,
        progress: &mut [TransferProgress],
        allowance: impl Fn() -> usize,
    ) -> Result<(), TransferError> {
        if progress.len() != self.peers.len() {
            return Err(TransferError::Protocol);
        }
        progress.fill(TransferProgress::default());
        let mut next_result = 0;
        loop {
            check_time(&self.manifest)?;
            if Instant::now() >= self.deadline {
                return Err(TransferError::Timeout);
            }
            if self.adaptive {
                self.adjust_width(allowance());
            }
            for index in 0..self.peers.len() {
                self.assign(index)?;
            }
            if !self
                .peers
                .iter()
                .any(|peer| peer.pending.is_some() || peer.state == adaptive::PeerState::Finishing)
            {
                if self.adaptive
                    && allowance() > 0
                    && self.chunks.iter().any(|c| !c.complete)
                    && self
                        .peers
                        .iter()
                        .any(|p| p.state == adaptive::PeerState::Dormant)
                {
                    continue;
                }
                break;
            }
            let (index, response) = timeout_at(
                self.deadline,
                poll_fn(|cx| {
                    for offset in 0..self.peers.len() {
                        let index = (next_result + offset) % self.peers.len();
                        let peer = &mut self.peers[index];
                        if peer.pending.is_some() || peer.state == adaptive::PeerState::Finishing {
                            if let Poll::Ready(response) = peer.results.poll_recv(cx) {
                                return Poll::Ready((index, response));
                            }
                        }
                    }
                    Poll::Pending
                }),
            )
            .await
            .map_err(|_| TransferError::Timeout)?;
            next_result = (index + 1) % self.peers.len();
            self.accept(index, response, store, progress)?;
        }
        for peer in &self.peers {
            if peer.state != adaptive::PeerState::Finished {
                let _ = peer.requests.try_send(Work::Finish);
            }
        }
        Ok(())
    }

    fn assign(&mut self, index: usize) -> Result<(), TransferError> {
        let peer = &mut self.peers[index];
        if peer.state != adaptive::PeerState::Active || peer.pending.is_some() {
            return Ok(());
        }
        let Some((position, pending)) = self.chunks.iter_mut().enumerate().find(|(_, item)| {
            !item.complete && item.owner.is_none() && !item.attempted.contains(&index)
        }) else {
            return Ok(());
        };
        match peer.requests.try_send(Work::Chunk(pending.chunk.clone())) {
            Ok(()) => {
                pending.attempted.insert(index);
                pending.owner = Some(index);
                peer.pending = Some(position);
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                peer.state = adaptive::PeerState::Finished;
                self.explore = true;
            }
            Err(mpsc::error::TrySendError::Full(_)) => return Err(TransferError::Protocol),
        }
        Ok(())
    }

    fn accept(
        &mut self,
        index: usize,
        response: Option<Result<Option<Vec<u8>>, TransferError>>,
        store: &mut ChunkStore,
        progress: &mut [TransferProgress],
    ) -> Result<(), TransferError> {
        check_time(&self.manifest)?;
        let peer = &mut self.peers[index];
        if peer.state == adaptive::PeerState::Finishing && peer.pending.is_none() {
            if response.is_some() {
                return Err(TransferError::Protocol);
            }
            peer.state = adaptive::PeerState::Finished;
            return Ok(());
        }
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
                let unique = pending.attempted.len() > 1;
                let length = u64::from(pending.chunk.length());
                self.record_sample(index, length, unique);
            }
            Some(Ok(None)) => {
                progress[index].missing += 1;
                self.explore = true;
            }
            Some(Err(_)) | None => {
                peer.state = adaptive::PeerState::Finished;
                self.explore = true;
            }
        }
        Ok(())
    }
}

fn validate_transports(
    expected: &VerifiedManifest,
    transports: &[&VerifiedManifest],
) -> Result<(), TransferError> {
    check_time(expected)?;
    if expected.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE {
        return Err(TransferError::Protocol);
    }
    for transport in transports {
        check_time(transport)?;
        if transport.object_sha256() != expected.object_sha256()
            || transport.length() != expected.length()
            || transport.metadata().content_type != expected.metadata().content_type
            || transport.chunks() != expected.chunks()
        {
            return Err(TransferError::Protocol);
        }
    }
    Ok(())
}

fn peer(
    manifest: &VerifiedManifest,
    limits: TransferLimits,
    deadline: Instant,
    active: bool,
) -> (Peer, ChunkWorker) {
    let (requests, incoming) = mpsc::channel(1);
    let (results, completed) = mpsc::channel(1);
    (
        Peer {
            requests,
            results: completed,
            pending: None,
            state: if active {
                adaptive::PeerState::Active
            } else {
                adaptive::PeerState::Dormant
            },
            probing: false,
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
    /// This provider's original selected index, not newly acquired publisher or HTTPS authority.
    /// Default `ParallelDownload::new` workers all retain the exact expected publication.
    pub fn manifest(&self) -> &VerifiedManifest {
        &self.manifest
    }

    /// Wait for real work before the caller acquires resources or opens a protected stream.
    ///
    /// `true` retains one assignment for the existing provider worker protocol. `false` means
    /// clean finish or coordinator closure and requires no connection. A failed final resource
    /// acquisition must drop this worker immediately, releasing its assignment to the writer.
    ///
    /// # Errors
    /// Rejects expiry or exhaustion of the original deadline, including this dormant interval.
    pub async fn wait_for_assignment(&mut self) -> Result<bool, TransferError> {
        if self.pending.is_some() {
            self.session.check_deadline()?;
            check_time(&self.manifest)?;
            return Ok(true);
        }
        let work = timeout_at(self.deadline, self.requests.recv())
            .await
            .map_err(|_| TransferError::Timeout)?;
        match work {
            Some(Work::Chunk(chunk)) => {
                self.session.check_deadline()?;
                check_time(&self.manifest)?;
                self.pending = Some(chunk);
                Ok(true)
            }
            Some(Work::Finish) | None => Ok(false),
        }
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
