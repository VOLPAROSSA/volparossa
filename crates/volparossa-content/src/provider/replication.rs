//! Opt-in, scarce chunk replication over a separately authorized protected stream.
//!
//! Replicas carry only self-consistent publisher signatures, not independently established
//! publisher or HTTPS authority. Foreground consumers still authorize their own manifests.
//! Hop counts are bounded locally, not protected against a malicious peer resetting its claim.

mod expiry;
mod persistence;
pub use expiry::ReplicaReclamation;
pub use persistence::{persist_replicas, restore_replicas};

use std::{
    collections::{BTreeMap, BTreeSet},
    future::Future,
    path::PathBuf,
    time::Duration,
};

use ed25519_dalek::VerifyingKey;
use prost::Message;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    time::{Instant, timeout_at},
};

use super::{ProviderError, PublicationRegistry, Selector, SelectorSession, now};
use crate::transfer::{TransferLimits, TransferProgress};
use crate::{
    CHUNK_BYTES, CacheLimits, ChunkId, ChunkStore, MAX_MANIFEST_BYTES, SignedManifest, Validity,
    VerifiedManifest,
};

pub(super) const VERSION: u32 = 2;
pub(super) const OPERATION: u32 = 1;
pub(super) const CREDIT_VERSION: u32 = 3;
const MAX_CREDIT_BYTES: usize = 16;
const MAX_REQUEST_BYTES: usize = 4096;
const MAX_FRAME_BYTES: usize = MAX_MANIFEST_BYTES + CHUNK_BYTES + 128;
const MAX_CHUNKS: usize = 4;
const MAX_WIRE_BYTES: u64 = 1024 * 1024;
const MAX_HOPS: u8 = 8;
const MAX_EXCLUSIONS: usize = 64;
const MAX_DURATION: Duration = Duration::from_secs(30);

/// Local hard ceilings for one optional uptake session, never a background traffic mandate.
#[derive(Clone, Copy, Debug)]
pub struct ReplicationLimits {
    /// At most four distinct chunks, possibly fewer when full chunks plus framing exceed quota.
    pub max_chunks: usize,
    /// At most one MiB including this protocol's selector, requests, manifests and framing.
    /// Overlay/TLS/IP overhead belongs to the caller's separate actual transport accounting.
    pub max_wire_bytes: u64,
    /// Largest admitted locally incremented hop count, from one through eight.
    pub max_hops: u8,
    /// Fixed session deadline, no longer than thirty seconds.
    pub session_timeout: Duration,
}

impl Default for ReplicationLimits {
    fn default() -> Self {
        Self {
            max_chunks: MAX_CHUNKS,
            max_wire_bytes: MAX_WIRE_BYTES,
            max_hops: MAX_HOPS,
            session_timeout: Duration::from_secs(15),
        }
    }
}

impl ReplicationLimits {
    fn validate(self) -> Result<Self, ProviderError> {
        if !(1..=MAX_CHUNKS).contains(&self.max_chunks)
            || !(64..=MAX_WIRE_BYTES).contains(&self.max_wire_bytes)
            || !(1..=MAX_HOPS).contains(&self.max_hops)
            || self.session_timeout.is_zero()
            || self.session_timeout > MAX_DURATION
        {
            return Err(ProviderError::Limit);
        }
        Ok(self)
    }
}

/// Optional interests already held or intentionally excluded, sent only inside this stream.
/// The combined count is at most sixty-four; nothing is published in discovery/DHT records.
#[derive(Clone, Debug, Default)]
pub struct ReplicationExclusions {
    /// Exact signed-manifest IDs, for example the completed foreground publication.
    pub manifest_ids: Vec<[u8; 32]>,
    /// Already held chunk content addresses, regardless of publication.
    pub chunk_ids: Vec<ChunkId>,
}

/// Storage-only checked replica; never an independent publisher or HTTPS trust capability.
#[derive(Clone, Debug)]
pub struct Replica {
    signed: SignedManifest,
    checked: VerifiedManifest,
    hops: u8,
    chunk_ids: Vec<ChunkId>,
}

impl Replica {
    /// Original signed bytes, requiring independent publisher authorization for consumption.
    pub fn signed_manifest(&self) -> &SignedManifest {
        &self.signed
    }
    /// Self-declared signing identity, not a newly trusted publisher key.
    pub fn publisher_key_hint(&self) -> [u8; 32] {
        *self.checked.publisher()
    }
    /// Hash of the exact original canonical signed manifest.
    pub fn manifest_id(&self) -> &[u8; 32] {
        self.checked.manifest_id()
    }
    /// Locally incremented replication count, not proof against malicious hop rewriting.
    pub const fn hops(&self) -> u8 {
        self.hops
    }
    /// Original signed validity, never renewed by copying or registration.
    pub fn validity(&self) -> Validity {
        self.checked.validity()
    }
    /// Distinct received chunks verified against this object and present in the uptake store.
    pub fn chunk_ids(&self) -> &[ChunkId] {
        &self.chunk_ids
    }
}

/// Actual uptake; a zero-chunk result never claims a complete object or useful new payload.
#[derive(Debug, Default)]
pub struct ReplicationProgress {
    /// Metadata only for received chunks actually verified in the destination store.
    /// Existing duplicates may recover registration metadata without claiming new bytes.
    pub replicas: Vec<Replica>,
    /// Newly inserted distinct chunks, excluding already present duplicates.
    pub chunks: usize,
    /// Newly inserted payload bytes, excluding duplicates and protocol overhead.
    pub bytes: u64,
    /// Complete protocol bytes exchanged, including manifests, requests and length prefixes.
    pub wire_bytes: u64,
}

#[derive(Clone)]
pub(super) struct SharedPublication {
    signed: std::sync::Arc<SignedManifest>,
    hops: u8,
}

impl PublicationRegistry {
    /// Whether this exact manifest already has an explicit local registration.
    /// This is not publisher/origin authority and never exposes the registered cache path.
    pub fn contains(&self, manifest_id: &[u8; 32]) -> bool {
        self.entries.contains_key(manifest_id)
    }

    /// Explicitly opt a caller-authenticated publication into scarce extra-chunk export.
    ///
    /// Ordinary [`Self::register`] entries are not exported by this protocol. The caller must
    /// independently trust this publisher; this option is not browsing capture or HTTPS trust.
    ///
    /// # Errors
    /// Rejects wrong publisher/signature/expiry and the existing registration/path/quota errors.
    pub fn register_shareable(
        &mut self,
        signed: SignedManifest,
        trusted: &VerifyingKey,
        root: PathBuf,
        limits: CacheLimits,
        now_unix: u64,
    ) -> Result<(), ProviderError> {
        let manifest = signed.verify(trusted, now_unix)?;
        let id = *manifest.manifest_id();
        self.register_signed(signed, trusted, root, limits, now_unix)?;
        let entry = self.entries.get_mut(&id).ok_or(ProviderError::Registry)?;
        entry.replication = Some(SharedPublication {
            signed: entry.signed.clone().ok_or(ProviderError::Registry)?,
            hops: 0,
        });
        Ok(())
    }

    /// Register storage-only replica metadata without promoting the publisher to trusted status.
    ///
    /// Verifies that every received chunk is present in this exact owned cache, then permits
    /// re-serving it to independently authorizing consumers. Release other cache handles first.
    ///
    /// # Errors
    /// Rejects missing/corrupt chunks, expired or exhausted metadata, duplicate registration,
    /// foreign/busy roots, and the existing bounded registry limits.
    pub fn register_replica(
        &mut self,
        replica: Replica,
        root: PathBuf,
        limits: CacheLimits,
        now_unix: u64,
    ) -> Result<(), ProviderError> {
        replica.checked.check_time(now_unix)?;
        if replica.hops == 0 || replica.hops > MAX_HOPS || replica.chunk_ids.is_empty() {
            return Err(ProviderError::Registry);
        }
        let mut store = ChunkStore::open(&root, limits)?;
        for id in &replica.chunk_ids {
            if store.get(id)?.is_none() {
                return Err(ProviderError::Missing);
            }
        }
        drop(store);
        let id = *replica.checked.manifest_id();
        self.register(replica.checked, root, limits, now_unix)?;
        let signed = std::sync::Arc::new(replica.signed);
        let entry = self.entries.get_mut(&id).ok_or(ProviderError::Registry)?;
        entry.signed = Some(std::sync::Arc::clone(&signed));
        entry.replication = Some(SharedPublication {
            signed,
            hops: replica.hops,
        });
        Ok(())
    }
}

/// Pull a few explicitly shareable chunks after foreground work, on a caller-authorized stream.
///
/// This never dials, requires full-object capacity, evicts existing chunks, or establishes
/// publisher/HTTPS trust. The caller controls when spare transport/disk capacity is available.
/// Failed sessions can leave only individually verified bounded chunks, not successful output.
///
/// # Errors
/// Rejects invalid limits/exclusions, malformed/duplicate/expired data, bad signatures or hashes,
/// exhausted non-evicting capacity, excessive hops/wire bytes, and the original session deadline.
pub async fn pull_replicas<S>(
    stream: &mut S,
    store: &mut ChunkStore,
    limits: ReplicationLimits,
    exclusions: &ReplicationExclusions,
) -> Result<ReplicationProgress, ProviderError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    pull_with_admission(stream, store, limits, exclusions, VERSION, || {
        std::future::ready(true)
    })
    .await
}

/// Pull optional replicas with one explicit receiver credit before every chunk.
///
/// Uses protocol v3 without falling back to the unsolicited v2 protocol. The callback may
/// await local spare capacity, within the original session deadline. Returning false sends
/// stop and awaits the provider's finish, returning only already verified stored progress.
/// All credit, stop and finish framing counts against the same complete wire-byte budget.
/// One already credited chunk may still arrive; this is not a per-packet bandwidth shaper.
///
/// # Errors
/// Same validation, storage and deadline errors as [`pull_replicas`], plus invalid credit
/// responses. On error individually verified chunks may remain, never a successful session.
pub async fn pull_replicas_with_admission<S, F, Fut>(
    stream: &mut S,
    store: &mut ChunkStore,
    limits: ReplicationLimits,
    exclusions: &ReplicationExclusions,
    admission: F,
) -> Result<ReplicationProgress, ProviderError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    pull_with_admission(stream, store, limits, exclusions, CREDIT_VERSION, admission).await
}

async fn pull_with_admission<S, F, Fut>(
    stream: &mut S,
    store: &mut ChunkStore,
    limits: ReplicationLimits,
    exclusions: &ReplicationExclusions,
    version: u32,
    mut admission: F,
) -> Result<ReplicationProgress, ProviderError>
where
    S: AsyncRead + AsyncWrite + Unpin,
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let limits = limits.validate()?;
    let deadline = Instant::now() + limits.session_timeout;
    let request = Request::new(limits, exclusions, version)?;
    let mut budget = Budget::new(limits.max_wire_bytes);
    timeout_at(deadline, async {
        write(
            stream,
            &selector(version),
            super::MAX_SELECTOR_BYTES,
            &mut budget,
        )
        .await?;
        write(stream, &request, MAX_REQUEST_BYTES, &mut budget).await?;
        let mut progress = ReplicationProgress::default();
        let mut replicas = BTreeMap::new();
        let mut seen = BTreeSet::new();
        loop {
            let stopped = version == CREDIT_VERSION
                && (seen.len() >= limits.max_chunks || !admission().await);
            if version == CREDIT_VERSION {
                write(
                    stream,
                    &Credit::new(!stopped),
                    MAX_CREDIT_BYTES,
                    &mut budget,
                )
                .await?;
            }
            let frame: Frame = read(stream, MAX_FRAME_BYTES, &mut budget).await?;
            if frame.version != version {
                return Err(ProviderError::Protocol);
            }
            if frame.finished {
                if frame != Frame::finish(version) {
                    return Err(ProviderError::Protocol);
                }
                break;
            }
            if stopped {
                return Err(ProviderError::Protocol);
            }
            if seen.len() >= limits.max_chunks {
                return Err(ProviderError::Limit);
            }
            let (replica, chunk_id) = checked_frame(&frame, limits, exclusions)?;
            if !seen.insert(chunk_id) {
                return Err(ProviderError::Protocol);
            }
            let id = *replica.manifest_id();
            if replicas
                .get(&id)
                .is_some_and(|existing: &Replica| existing.hops != replica.hops)
            {
                return Err(ProviderError::Protocol);
            }
            if store.put_verified_if_space(chunk_id, &frame.data)? {
                progress.chunks += 1;
                progress.bytes += frame.data.len() as u64;
            }
            replicas
                .entry(id)
                .or_insert(replica)
                .chunk_ids
                .push(chunk_id);
        }
        if Instant::now() >= deadline {
            return Err(ProviderError::Timeout);
        }
        for replica in replicas.values() {
            replica.checked.check_time(now()?)?;
        }
        progress.replicas = replicas.into_values().collect();
        progress.wire_bytes = budget.used;
        Ok(progress)
    })
    .await
    .map_err(|_| ProviderError::Timeout)?
}

fn checked_frame(
    frame: &Frame,
    limits: ReplicationLimits,
    exclusions: &ReplicationExclusions,
) -> Result<(Replica, ChunkId), ProviderError> {
    if frame.data.is_empty()
        || frame.data.len() > CHUNK_BYTES
        || frame.hops >= u32::from(limits.max_hops)
    {
        return Err(ProviderError::Limit);
    }
    let key: [u8; 32] = frame
        .publisher
        .as_slice()
        .try_into()
        .map_err(|_| ProviderError::Protocol)?;
    let key = VerifyingKey::from_bytes(&key).map_err(|_| ProviderError::Protocol)?;
    let signed = SignedManifest::decode(&frame.manifest)?;
    // Self-consistency only. This private checked value never leaves the storage-only Replica.
    // The peer-selected key is deliberately NOT returned as a consumer trust capability.
    let checked = signed.verify(&key, now()?)?;
    let chunk = checked
        .chunks()
        .get(frame.chunk_index as usize)
        .ok_or(ProviderError::Protocol)?;
    let chunk_id = *chunk.id();
    if u64::from(chunk.length()) != frame.data.len() as u64
        || ChunkId::digest(&frame.data) != chunk_id
    {
        return Err(crate::Error::Integrity(chunk_id).into());
    }
    if exclusions.manifest_ids.contains(checked.manifest_id())
        || exclusions.chunk_ids.contains(&chunk_id)
    {
        return Err(ProviderError::Protocol);
    }
    Ok((
        Replica {
            signed,
            checked,
            hops: u8::try_from(frame.hops + 1).map_err(|_| ProviderError::Limit)?,
            chunk_ids: Vec::new(),
        },
        chunk_id,
    ))
}

pub(super) async fn serve<S>(
    stream: &mut S,
    registry: &PublicationRegistry,
    outer: &SelectorSession,
    local_limits: TransferLimits,
) -> Result<TransferProgress, ProviderError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let deadline = outer.deadline.min(Instant::now() + MAX_DURATION);
    timeout_at(deadline, async {
        let mut budget = Budget::new(MAX_WIRE_BYTES.min(local_limits.max_bytes));
        budget.reserve((selector(VERSION).encoded_len() + 4) as u64)?;
        let request: Request = timeout_at(
            outer.selector_deadline,
            read(stream, MAX_REQUEST_BYTES, &mut budget),
        )
        .await
        .map_err(|_| ProviderError::Timeout)??;
        request.validate(VERSION)?;
        budget.maximum = budget.maximum.min(request.max_wire_bytes);
        budget.reserve(0)?;
        let mut progress = TransferProgress::default();
        let mut sent = BTreeSet::new();
        for (id, entry) in &registry.entries {
            if progress.chunks >= request.max_chunks as usize
                || progress.chunks >= local_limits.max_requests
            {
                break;
            }
            let Some(shared) = &entry.replication else {
                continue;
            };
            if request
                .excluded_manifests
                .iter()
                .any(|item| item.as_slice() == id)
                || u32::from(shared.hops) >= request.max_hops
                || entry.manifest.check_time(now()?).is_err()
            {
                continue;
            }
            let Ok(mut store) = ChunkStore::open(&entry.root, entry.limits) else {
                continue;
            };
            for (index, chunk) in entry.manifest.chunks().iter().enumerate() {
                if progress.chunks >= request.max_chunks as usize
                    || progress.chunks >= local_limits.max_requests
                {
                    break;
                }
                if sent.contains(chunk.id())
                    || request
                        .excluded_chunks
                        .iter()
                        .any(|item| item.as_slice() == chunk.id().as_bytes())
                {
                    continue;
                }
                if Instant::now() >= deadline {
                    return Err(ProviderError::Timeout);
                }
                entry.manifest.check_time(now()?)?;
                let Some(data) = store.get(chunk.id())? else {
                    continue;
                };
                let frame = Frame {
                    version: VERSION,
                    finished: false,
                    publisher: entry.manifest.publisher().to_vec(),
                    manifest: shared.signed.encode(),
                    hops: u32::from(shared.hops),
                    chunk_index: u32::try_from(index).map_err(|_| ProviderError::Limit)?,
                    data,
                };
                let cost = (frame.encoded_len() + Frame::finish(VERSION).encoded_len() + 8) as u64;
                if !budget.fits(cost) {
                    continue;
                }
                write(stream, &frame, MAX_FRAME_BYTES, &mut budget).await?;
                sent.insert(*chunk.id());
                progress.chunks += 1;
                progress.bytes += frame.data.len() as u64;
            }
        }
        write(
            stream,
            &Frame::finish(VERSION),
            MAX_FRAME_BYTES,
            &mut budget,
        )
        .await?;
        if Instant::now() >= deadline {
            return Err(ProviderError::Timeout);
        }
        Ok(progress)
    })
    .await
    .map_err(|_| ProviderError::Timeout)?
}

pub(super) async fn serve_with_credit<S>(
    stream: &mut S,
    registry: &PublicationRegistry,
    outer: &SelectorSession,
    local_limits: TransferLimits,
) -> Result<TransferProgress, ProviderError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let deadline = outer.deadline.min(Instant::now() + MAX_DURATION);
    timeout_at(deadline, async {
        let mut budget = Budget::new(MAX_WIRE_BYTES.min(local_limits.max_bytes));
        budget.reserve((selector(CREDIT_VERSION).encoded_len() + 4) as u64)?;
        let request: Request = timeout_at(
            outer.selector_deadline,
            read(stream, MAX_REQUEST_BYTES, &mut budget),
        )
        .await
        .map_err(|_| ProviderError::Timeout)??;
        request.validate(CREDIT_VERSION)?;
        budget.maximum = budget.maximum.min(request.max_wire_bytes);
        budget.reserve(0)?;
        let finish = Frame::finish(CREDIT_VERSION);
        let mut progress = TransferProgress::default();
        let mut sent = BTreeSet::new();
        loop {
            // One credit permits one response, never multiple chunks. No cache is open here.
            let credit: Credit = read(stream, MAX_CREDIT_BYTES, &mut budget).await?;
            let admitted = credit.admitted()?;
            if !admitted
                || progress.chunks >= request.max_chunks as usize
                || progress.chunks >= local_limits.max_requests
            {
                break;
            }
            let Some(frame) = next_credited_frame(registry, &request, &sent, &budget, deadline)?
            else {
                break;
            };
            if Instant::now() >= deadline {
                return Err(ProviderError::Timeout);
            }
            write(stream, &frame, MAX_FRAME_BYTES, &mut budget).await?;
            sent.insert(ChunkId::digest(&frame.data));
            progress.chunks += 1;
            progress.bytes += frame.data.len() as u64;
        }
        write(stream, &finish, MAX_FRAME_BYTES, &mut budget).await?;
        if Instant::now() >= deadline {
            return Err(ProviderError::Timeout);
        }
        Ok(progress)
    })
    .await
    .map_err(|_| ProviderError::Timeout)?
}

fn next_credited_frame(
    registry: &PublicationRegistry,
    request: &Request,
    sent: &BTreeSet<ChunkId>,
    budget: &Budget,
    deadline: Instant,
) -> Result<Option<Frame>, ProviderError> {
    // Reserve the next credit/stop plus final finish before emitting any chunk. Both credit
    // decisions have the same canonical length. Returning a frame drops every cache handle.
    let closing_cost =
        Credit::new(false).encoded_len() + Frame::finish(CREDIT_VERSION).encoded_len() + 8;
    for (id, entry) in &registry.entries {
        if Instant::now() >= deadline {
            return Err(ProviderError::Timeout);
        }
        let Some(shared) = &entry.replication else {
            continue;
        };
        if request
            .excluded_manifests
            .iter()
            .any(|item| item.as_slice() == id)
            || u32::from(shared.hops) >= request.max_hops
            || entry.manifest.check_time(now()?).is_err()
        {
            continue;
        }
        let Ok(mut store) = ChunkStore::open(&entry.root, entry.limits) else {
            continue;
        };
        for (index, chunk) in entry.manifest.chunks().iter().enumerate() {
            if Instant::now() >= deadline {
                return Err(ProviderError::Timeout);
            }
            if sent.contains(chunk.id())
                || request
                    .excluded_chunks
                    .iter()
                    .any(|item| item.as_slice() == chunk.id().as_bytes())
            {
                continue;
            }
            let Some(data) = store.get(chunk.id())? else {
                continue;
            };
            entry.manifest.check_time(now()?)?;
            let frame = Frame {
                version: CREDIT_VERSION,
                finished: false,
                publisher: entry.manifest.publisher().to_vec(),
                manifest: shared.signed.encode(),
                hops: u32::from(shared.hops),
                chunk_index: u32::try_from(index).map_err(|_| ProviderError::Limit)?,
                data,
            };
            if budget.fits((frame.encoded_len() + 4 + closing_cost) as u64) {
                return Ok(Some(frame));
            }
        }
    }
    Ok(None)
}

#[derive(Clone, PartialEq, Message)]
struct Credit {
    #[prost(uint32, tag = "1")]
    version: u32,
    /// Exactly one chunk (1) or stop (2); there is no credit accumulation or batch count.
    #[prost(uint32, tag = "2")]
    decision: u32,
}
impl Credit {
    const fn new(admitted: bool) -> Self {
        Self {
            version: CREDIT_VERSION,
            decision: if admitted { 1 } else { 2 },
        }
    }
    fn admitted(&self) -> Result<bool, ProviderError> {
        match (self.version, self.decision) {
            (CREDIT_VERSION, 1) => Ok(true),
            (CREDIT_VERSION, 2) => Ok(false),
            _ => Err(ProviderError::Protocol),
        }
    }
}

fn selector(version: u32) -> Selector {
    Selector {
        version,
        manifest_id: Vec::new(),
        operation: OPERATION,
    }
}

#[derive(Clone, PartialEq, Message)]
struct Request {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(uint32, tag = "2")]
    max_chunks: u32,
    #[prost(uint64, tag = "3")]
    max_wire_bytes: u64,
    #[prost(uint32, tag = "4")]
    max_hops: u32,
    #[prost(bytes = "vec", repeated, tag = "5")]
    excluded_manifests: Vec<Vec<u8>>,
    #[prost(bytes = "vec", repeated, tag = "6")]
    excluded_chunks: Vec<Vec<u8>>,
}
impl Request {
    fn new(
        limits: ReplicationLimits,
        exclusions: &ReplicationExclusions,
        version: u32,
    ) -> Result<Self, ProviderError> {
        if exclusions.manifest_ids.len() + exclusions.chunk_ids.len() > MAX_EXCLUSIONS {
            return Err(ProviderError::Limit);
        }
        let result = Self {
            version,
            max_chunks: u32::try_from(limits.max_chunks).map_err(|_| ProviderError::Limit)?,
            max_wire_bytes: limits.max_wire_bytes,
            max_hops: u32::from(limits.max_hops),
            excluded_manifests: exclusions
                .manifest_ids
                .iter()
                .map(|id| id.to_vec())
                .collect(),
            excluded_chunks: exclusions
                .chunk_ids
                .iter()
                .map(|id| id.as_bytes().to_vec())
                .collect(),
        };
        result.validate(version)?;
        Ok(result)
    }
    fn validate(&self, version: u32) -> Result<(), ProviderError> {
        if self.version != version
            || self.excluded_manifests.len() + self.excluded_chunks.len() > MAX_EXCLUSIONS
            || self
                .excluded_manifests
                .iter()
                .chain(&self.excluded_chunks)
                .any(|id| id.len() != 32)
            || self
                .excluded_manifests
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                != self.excluded_manifests.len()
            || self.excluded_chunks.iter().collect::<BTreeSet<_>>().len()
                != self.excluded_chunks.len()
        {
            return Err(ProviderError::Protocol);
        }
        ReplicationLimits {
            max_chunks: self.max_chunks as usize,
            max_wire_bytes: self.max_wire_bytes,
            max_hops: u8::try_from(self.max_hops).map_err(|_| ProviderError::Limit)?,
            session_timeout: MAX_DURATION,
        }
        .validate()?;
        Ok(())
    }
}

#[derive(Clone, PartialEq, Message)]
struct Frame {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bool, tag = "2")]
    finished: bool,
    #[prost(bytes = "vec", tag = "3")]
    publisher: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    manifest: Vec<u8>,
    #[prost(uint32, tag = "5")]
    hops: u32,
    #[prost(uint32, tag = "6")]
    chunk_index: u32,
    #[prost(bytes = "vec", tag = "7")]
    data: Vec<u8>,
}
impl Frame {
    fn finish(version: u32) -> Self {
        Self {
            version,
            finished: true,
            ..Self::default()
        }
    }
}

struct Budget {
    maximum: u64,
    used: u64,
}
impl Budget {
    const fn new(maximum: u64) -> Self {
        Self { maximum, used: 0 }
    }
    fn fits(&self, additional: u64) -> bool {
        self.used
            .checked_add(additional)
            .is_some_and(|total| total <= self.maximum)
    }
    fn reserve(&mut self, bytes: u64) -> Result<(), ProviderError> {
        if !self.fits(bytes) {
            return Err(ProviderError::Limit);
        }
        self.used += bytes;
        Ok(())
    }
}
async fn read<S: AsyncRead + Unpin, M: Message + Default>(
    stream: &mut S,
    maximum: usize,
    budget: &mut Budget,
) -> Result<M, ProviderError> {
    budget.reserve(4)?;
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > maximum {
        return Err(ProviderError::Protocol);
    }
    budget.reserve(length as u64)?;
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    let frame = M::decode(bytes.as_slice()).map_err(|_| ProviderError::Protocol)?;
    if frame.encode_to_vec() != bytes {
        return Err(ProviderError::Protocol);
    }
    Ok(frame)
}
async fn write<S: AsyncWrite + Unpin, M: Message>(
    stream: &mut S,
    frame: &M,
    maximum: usize,
    budget: &mut Budget,
) -> Result<(), ProviderError> {
    let length = frame.encoded_len();
    if length == 0 || length > maximum {
        return Err(ProviderError::Protocol);
    }
    budget.reserve((length + 4) as u64)?;
    let bytes = frame.encode_to_vec();
    stream
        .write_u32(u32::try_from(length).map_err(|_| ProviderError::Limit)?)
        .await?;
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}

#[cfg(test)]
mod credit_tests;
