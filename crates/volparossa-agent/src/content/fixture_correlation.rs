//! Explicit disposable-fixture observations. Never protocol or admission authority.

mod io;
pub(super) use io::Observed;

use std::{
    sync::{
        Arc, Mutex, Weak,
        atomic::{AtomicBool, Ordering::Relaxed},
    },
    time::Duration,
};

use sha2::{Digest, Sha256};
use tokio::time::Instant;
use volparossa_content::{
    private_storage::protocol::{StorageOperation, VerifiedStorageRequest},
    provider::activity::{Observer, RequestStage, Stage, WorkerObserver},
};
use volparossa_local_control::{
    PrivateStorageElapsedBucket as Bucket, StorageFixtureAcquireSummary,
    StorageFixtureCorrelationAction as Action, StorageFixtureCorrelationPhase as Phase,
    StorageFixtureCorrelationRecord as WireRecord, StorageFixtureCorrelationRequest as Request,
    StorageFixtureCorrelationResponse as Response, StorageFixtureCorrelationRole as Role,
    StorageFixtureCorrelationState as State, StorageFixtureCorrelationTerminal as Terminal,
    StorageFixtureOperation as Operation, StorageFixtureProviderStage as ProviderStage,
    StorageFixtureRequestObservation, StorageFixtureReserveTiming, StorageFixtureTarget,
    StorageFixtureWorkerState as WorkerState,
};
use zeroize::Zeroize;

use super::{ContentError, ContentRuntime, provider_activity};

const CAPACITY: usize = 64;
const PREFIX_BYTES: usize = 64;
const EPOCH_TTL: Duration = Duration::from_secs(2_400);
const TERMINAL_TTL: Duration = Duration::from_secs(180);
const DOMAIN: &[u8] = b"volparossa-storage-fixture-correlation-v1\0";

#[derive(Default)]
pub(super) struct Correlation {
    bank: Mutex<Bank>,
    missed_begin: AtomicBool,
    cleanup: tokio::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

impl Drop for Correlation {
    fn drop(&mut self) {
        if let Some(task) = self.cleanup.get_mut().take() {
            task.abort();
        }
    }
}

#[derive(Default)]
struct Bank {
    next_token: u64,
    epoch: Option<Epoch>,
}

struct Epoch {
    version: u32,
    owner: u32,
    bytes: [u8; 16],
    expires: Instant,
    life: Arc<Life>,
    records: [Option<Record>; CAPACITY],
    target_scope: Option<[u8; 32]>,
}

struct Life {
    alive: AtomicBool,
    incomplete: AtomicBool,
}

struct Record {
    token: u64,
    role: Role,
    phase: Phase,
    terminal: Terminal,
    finished: Option<Instant>,
    fingerprint: Option<[u8; 32]>,
    prefix_valid: Arc<AtomicBool>,
    prefix_complete: Arc<AtomicBool>,
    hash: Option<Sha256>,
    bytes: usize,
    flow_acquire: Option<StorageFixtureAcquireSummary>,
    acquire_valid: Arc<AtomicBool>,
    request_valid: Arc<AtomicBool>,
    request: RequestRecord,
}

#[derive(Default)]
struct RequestRecord {
    target: Option<[u8; 32]>,
    digest: Option<[u8; 32]>,
    verified_digest: Option<[u8; 32]>,
    operation: i32,
    provider_stage: i32,
    worker_state: i32,
    returned_after_terminal: bool,
    started: Option<Instant>,
    deadline: Option<Instant>,
    write_started: Option<Instant>,
    receipt_started: Option<Instant>,
    receipt_ended: Option<Instant>,
}

impl RequestRecord {
    fn project(&self, ended: Instant) -> StorageFixtureRequestObservation {
        let reserve_timing = self.reserve_timing(ended);
        StorageFixtureRequestObservation {
            request_digest: self.digest.map(|value| value.to_vec()),
            operation: self.operation,
            provider_stage: self.provider_stage,
            worker_state: self.worker_state,
            worker_returned_after_terminal: self.returned_after_terminal,
            reserve_timing,
        }
    }
    fn reserve_timing(&self, ended: Instant) -> Option<StorageFixtureReserveTiming> {
        if self.operation != Operation::Reserve as i32 {
            return None;
        }
        let started = self.started?;
        let deadline = self.deadline?;
        let write = self.write_started?;
        Some(StorageFixtureReserveTiming {
            before_request_flush_elapsed: bucket(write.saturating_duration_since(started)),
            before_request_flush_remaining: bucket(deadline.saturating_duration_since(write)),
            receipt_wait_elapsed: self.receipt_started.map(|at| {
                bucket(
                    self.receipt_ended
                        .unwrap_or(ended)
                        .saturating_duration_since(at),
                )
            }),
            receipt_wait_remaining: self
                .receipt_started
                .map(|at| bucket(deadline.saturating_duration_since(at))),
        })
    }
}

fn bucket(duration: Duration) -> i32 {
    (match duration.as_secs() {
        0 => Bucket::Under1s,
        1..=4 => Bucket::S1To5,
        5..=14 => Bucket::S5To15,
        15..=29 => Bucket::S15To30,
        30..=59 => Bucket::S30To60,
        60..=89 => Bucket::S60To90,
        90..=119 => Bucket::S90To120,
        _ => Bucket::AtLeast120s,
    }) as i32
}

fn operation(value: StorageOperation) -> Operation {
    match value {
        StorageOperation::Reserve { .. } => Operation::Reserve,
        StorageOperation::Append { .. } => Operation::Append,
        StorageOperation::Progress => Operation::Progress,
        StorageOperation::Finalize => Operation::Finalize,
        StorageOperation::ReadRange { .. } => Operation::ReadRange,
        StorageOperation::Renew { .. } => Operation::Renew,
        StorageOperation::Delete => Operation::Delete,
    }
}

fn target_digest(epoch: &[u8; 16], target: &StorageFixtureTarget) -> [u8; 32] {
    let mut hash = Sha256::new();
    hash.update(b"volparossa-storage-fixture-target-v3\0");
    hash.update(epoch);
    hash.update(&target.archive_id);
    hash.update(&target.provider_key);
    hash.update(target.operation.to_be_bytes());
    hash.finalize().into()
}

impl Drop for Record {
    fn drop(&mut self) {
        self.fingerprint.zeroize();
        self.request.target.zeroize();
        self.request.digest.zeroize();
        self.request.verified_digest.zeroize();
        self.hash = None;
    }
}

impl Drop for Epoch {
    fn drop(&mut self) {
        self.life.alive.store(false, Relaxed);
        self.bytes.zeroize();
        self.target_scope.zeroize();
        // Clearing records also clears every completed fingerprint. Guards retain only
        // slot ownership and liveness, never epoch bytes, a digest or a raw prefix.
        for record in &mut self.records {
            *record = None;
        }
    }
}

impl Bank {
    fn expire(&mut self, now: Instant) {
        if self
            .epoch
            .as_ref()
            .is_some_and(|epoch| now >= epoch.expires)
        {
            self.epoch = None;
        }
        if let Some(epoch) = &mut self.epoch {
            for slot in &mut epoch.records {
                if slot.as_ref().is_some_and(|record| {
                    record.finished.is_some_and(|at| now >= at + TERMINAL_TTL)
                }) {
                    *slot = None;
                    // Expired observations are not evidence of absence.
                    epoch.life.incomplete.store(true, Relaxed);
                }
            }
        }
    }
}

impl ContentRuntime {
    /// The local dispatcher must first require `Development` mode and obtain the Unix
    /// peer UID itself. No caller-provided UID, path, peer identity or remote authority.
    pub(crate) async fn fixture_correlation(
        &self,
        uid: u32,
        request: &Request,
    ) -> Result<Response, ContentError> {
        self.fixture_correlation.request(uid, request).await
    }
}

impl Correlation {
    async fn request(
        self: &Arc<Self>,
        uid: u32,
        request: &Request,
    ) -> Result<Response, ContentError> {
        request.validate().map_err(|_| ContentError::Invalid)?;
        let Ok(mut cleanup) = self.cleanup.try_lock() else {
            return Ok(unavailable(request.version));
        };
        if request.action == Action::Arm as i32 {
            {
                let Ok(mut bank) = self.bank.try_lock() else {
                    return Ok(unavailable(request.version));
                };
                bank.expire(Instant::now());
                if bank.epoch.is_some() {
                    return Err(ContentError::Busy);
                }
            }
            // Keep ownership in the gate while awaiting: cancellation cannot detach
            // the old task or let a later arm skip its join.
            if let Some(task) = cleanup.as_mut() {
                task.abort();
                let _ = task.await;
            }
            *cleanup = None;
        }
        let response = self.request_inner(uid, request, &mut cleanup)?;
        if response.state == State::Disarmed as i32 {
            if let Some(task) = cleanup.as_mut() {
                task.abort();
                let _ = task.await;
            }
            *cleanup = None;
        }
        Ok(response)
    }

    fn cleanup_task(self: &Arc<Self>, life: Weak<Life>) -> tokio::task::JoinHandle<()> {
        let owner = Arc::downgrade(self);
        // One disposable task, absent when disabled. No identity or stream, and no
        // blocking lock. Erasure occurs on the next successful one-second tick.
        tokio::spawn(async move {
            loop {
                tokio::time::sleep(Duration::from_secs(1)).await;
                let (Some(owner), Some(life)) = (owner.upgrade(), life.upgrade()) else {
                    return;
                };
                if !life.alive.load(Relaxed) {
                    return;
                }
                let Ok(mut bank) = owner.bank.try_lock() else {
                    life.incomplete.store(true, Relaxed);
                    continue;
                };
                if !bank
                    .epoch
                    .as_ref()
                    .is_some_and(|epoch| Arc::ptr_eq(&epoch.life, &life))
                {
                    return;
                }
                bank.expire(Instant::now());
            }
        })
    }

    fn request_inner(
        self: &Arc<Self>,
        uid: u32,
        request: &Request,
        cleanup: &mut Option<tokio::task::JoinHandle<()>>,
    ) -> Result<Response, ContentError> {
        request.validate().map_err(|_| ContentError::Invalid)?;
        let action = Action::try_from(request.action).map_err(|_| ContentError::Invalid)?;
        let bytes: [u8; 16] = request
            .epoch
            .as_slice()
            .try_into()
            .map_err(|_| ContentError::Invalid)?;
        let Ok(mut bank) = self.bank.try_lock() else {
            return Ok(unavailable(request.version));
        };
        let now = Instant::now();
        bank.expire(now);
        if action == Action::Arm {
            // Even the same owner cannot reset the deadline or discard a live epoch.
            if bank.epoch.is_some() {
                return Err(ContentError::Busy);
            }
            self.missed_begin.store(false, Relaxed);
            let life = Arc::new(Life {
                alive: AtomicBool::new(true),
                incomplete: AtomicBool::new(false),
            });
            *cleanup = Some(self.cleanup_task(Arc::downgrade(&life)));
            bank.epoch = Some(Epoch {
                version: request.version,
                owner: uid,
                bytes,
                expires: now + EPOCH_TTL,
                life,
                records: std::array::from_fn(|_| None),
                target_scope: request
                    .target
                    .as_ref()
                    .map(|target| target_digest(&bytes, target)),
            });
            return Ok(empty(State::Armed, request.version));
        }
        let Some(epoch) = &bank.epoch else {
            return Ok(unavailable(request.version));
        };
        if epoch.owner != uid || epoch.bytes != bytes || epoch.version != request.version {
            return Err(ContentError::Invalid);
        }
        if action == Action::Disarm {
            bank.epoch = None;
            return Ok(empty(State::Disarmed, request.version));
        }
        if request.version == 3
            && action == Action::Clients
            && request
                .target
                .as_ref()
                .map(|target| target_digest(&bytes, target))
                != epoch.target_scope
        {
            return Err(ContentError::Invalid);
        }
        let role = if action == Action::Clients {
            Role::Client
        } else {
            Role::Provider
        };
        Ok(self.snapshot(epoch, request, role, now))
    }

    fn snapshot(&self, epoch: &Epoch, request: &Request, role: Role, now: Instant) -> Response {
        let selected_target = request
            .target
            .as_ref()
            .map(|target| target_digest(&epoch.bytes, target));
        // Verified exclusions are deliberate scope, never complete phase history. Unknown
        // client attempts might be another attempt on this target: do not guess through them.
        let unknown_client = role == Role::Client
            && epoch
                .records
                .iter()
                .flatten()
                .any(|record| record.role == Role::Client && record.request.target.is_none());
        if request.version == 3
            && (epoch.life.incomplete.load(Relaxed)
                || self.missed_begin.load(Relaxed)
                || unknown_client)
        {
            return unavailable(request.version);
        }
        let records = epoch
            .records
            .iter()
            .flatten()
            .filter_map(|record| {
                if record.role != role {
                    return None;
                }
                if let Some(target) = selected_target
                    && (!record.request_valid.load(Relaxed) || record.request.target != Some(target))
                    {
                        return None;
                    }
                let fingerprint = record
                    .prefix_valid
                    .load(Relaxed)
                    .then_some(record.fingerprint)
                    .flatten();
                if role == Role::Provider
                    && !fingerprint.is_some_and(|fingerprint| {
                        request
                            .fingerprints
                            .iter()
                            .any(|value| value.as_slice() == fingerprint)
                    })
                {
                    return None;
                }
                Some(WireRecord {
                    role: record.role as i32,
                    fingerprint: fingerprint.map(|value| value.to_vec()),
                    phase: record.phase as i32,
                    terminal: record.terminal as i32,
                    request_observation: (request.version == 3
                        && record.request_valid.load(Relaxed))
                    .then(|| record.request.project(record.finished.unwrap_or(now))),
                    flow_acquire: record.flow_acquire.filter(|_| {
                        request.version >= 2
                            && record.terminal == Terminal::OperationError
                            && record.acquire_valid.load(Relaxed)
                    }),
                })
            })
            .collect();
        let response = Response {
            version: request.version,
            state: State::Observed as i32,
            incomplete: epoch.life.incomplete.load(Relaxed) || self.missed_begin.load(Relaxed),
            records,
        };
        // Unknown internal state can only remove diagnostic availability.
        if response.validate_for(request).is_ok() {
            response
        } else {
            unavailable(request.version)
        }
    }

    pub(super) fn client(self: &Arc<Self>, uid: u32) -> Guard {
        self.begin(Role::Client, Some(uid))
    }

    pub(super) fn provider(self: &Arc<Self>) -> Guard {
        self.begin(Role::Provider, None)
    }

    fn begin(self: &Arc<Self>, role: Role, uid: Option<u32>) -> Guard {
        let Ok(mut bank) = self.bank.try_lock() else {
            // This flag is reset only while creating a new epoch. Missing an incoming
            // observation during contention must never look like proven absence.
            self.missed_begin.store(true, Relaxed);
            return Guard::default();
        };
        bank.expire(Instant::now());
        let Some(epoch) = &bank.epoch else {
            return Guard::default();
        };
        if uid.is_some_and(|uid| uid != epoch.owner) {
            return Guard::default();
        }
        let index = epoch.records.iter().position(Option::is_none).or_else(|| {
            epoch
                .records
                .iter()
                .enumerate()
                .filter_map(|(index, record)| {
                    let record = record.as_ref()?;
                    record.finished.map(|at| (index, at, record.token))
                })
                .min_by_key(|(_, at, token)| (*at, *token))
                .map(|(index, _, _)| index)
        });
        let Some(index) = index else {
            epoch.life.incomplete.store(true, Relaxed);
            return Guard::default();
        };
        if epoch.records[index].is_some() {
            // Reclaim only the oldest terminal record. A full phase must still be
            // able to observe its later failure, without hiding lost history.
            epoch.life.incomplete.store(true, Relaxed);
        }
        let Some(token) = bank.next_token.checked_add(1) else {
            epoch.life.incomplete.store(true, Relaxed);
            return Guard::default();
        };
        bank.next_token = token;
        let Some(epoch) = &mut bank.epoch else {
            return Guard::default();
        };
        let prefix_valid = Arc::new(AtomicBool::new(true));
        let prefix_complete = Arc::new(AtomicBool::new(false));
        let acquire_valid = Arc::new(AtomicBool::new(false));
        let request_valid = Arc::new(AtomicBool::new(true));
        let mut hash = Sha256::new();
        hash.update(DOMAIN);
        hash.update(epoch.bytes);
        epoch.records[index] = Some(Record {
            token,
            role,
            phase: if role == Role::Client {
                Phase::FlowAcquire
            } else {
                Phase::TlsHandshake
            },
            terminal: Terminal::Active,
            finished: None,
            fingerprint: None,
            prefix_valid: Arc::clone(&prefix_valid),
            prefix_complete: Arc::clone(&prefix_complete),
            hash: Some(hash),
            bytes: 0,
            flow_acquire: None,
            acquire_valid: Arc::clone(&acquire_valid),
            request_valid: Arc::clone(&request_valid),
            request: RequestRecord::default(),
        });
        Guard(Some(Tracking {
            owner: Arc::clone(self),
            life: Arc::clone(&epoch.life),
            prefix_valid,
            prefix_complete,
            index,
            token,
            version: epoch.version,
            acquire_valid,
            request_valid,
            terminal_recorded: AtomicBool::new(false),
        }))
    }
}

fn empty(state: State, version: u32) -> Response {
    Response {
        version,
        state: state as i32,
        incomplete: false,
        records: Vec::new(),
    }
}

fn unavailable(version: u32) -> Response {
    Response {
        version,
        ..Response::unavailable()
    }
}

/// Affine session ownership. A late guard cannot update a reused slot or a new epoch.
#[derive(Default)]
pub(super) struct Guard(Option<Tracking>);

struct Tracking {
    version: u32,
    acquire_valid: Arc<AtomicBool>,
    terminal_recorded: AtomicBool,
    request_valid: Arc<AtomicBool>,
    owner: Arc<Correlation>,
    life: Arc<Life>,
    prefix_valid: Arc<AtomicBool>,
    prefix_complete: Arc<AtomicBool>,
    index: usize,
    token: u64,
}

impl Guard {
    fn update(&self, update: impl FnOnce(&mut Record)) -> bool {
        let Some(track) = &self.0 else {
            return false;
        };
        if !track.life.alive.load(Relaxed) {
            return false;
        }
        let Ok(mut bank) = track.owner.bank.try_lock() else {
            track.life.incomplete.store(true, Relaxed);
            return false;
        };
        bank.expire(Instant::now());
        let Some(epoch) = &mut bank.epoch else {
            return false;
        };
        if !Arc::ptr_eq(&epoch.life, &track.life) {
            return false;
        }
        let Some(record) = &mut epoch.records[track.index] else {
            return false;
        };
        if record.token != track.token || record.finished.is_some() {
            return false;
        }
        update(record);
        true
    }

    pub(super) fn start_operation(&self, started: Option<Instant>, duration: Duration) {
        if self.0.as_ref().is_none_or(|track| track.version != 3) {
            return;
        }
        self.update(|record| {
            record.request.started = started;
            record.request.deadline = started.map(|at| at + duration);
        });
    }

    pub(super) fn bind_request(&self, request: &VerifiedStorageRequest, flushed: bool) {
        let Some(track) = self.0.as_ref().filter(|track| track.version == 3) else {
            return;
        };
        let Ok(mut bank) = track.owner.bank.try_lock() else {
            track.request_valid.store(false, Relaxed);
            track.life.incomplete.store(true, Relaxed);
            return;
        };
        bank.expire(Instant::now());
        let Some(epoch) = &mut bank.epoch else {
            return;
        };
        if !Arc::ptr_eq(&epoch.life, &track.life) || !track.life.alive.load(Relaxed) {
            return;
        }
        let Some(record) = &mut epoch.records[track.index] else {
            return;
        };
        if record.token != track.token || record.finished.is_some() {
            return;
        }
        let target = StorageFixtureTarget {
            archive_id: request.target().archive_id.to_vec(),
            provider_key: request.grant().provider_key().as_bytes().to_vec(),
            operation: operation(request.operation()) as i32,
        };
        let target = target_digest(&epoch.bytes, &target);
        if record
            .request
            .target
            .is_some_and(|previous| previous != target)
        {
            track.request_valid.store(false, Relaxed);
            track.life.incomplete.store(true, Relaxed);
            return;
        }
        if epoch.target_scope != Some(target) {
            // The verified request proves this connection is deliberately outside this
            // one target, not lost history. Erase its hashes and invalidate every callback.
            track.request_valid.store(false, Relaxed);
            track.prefix_valid.store(false, Relaxed);
            epoch.records[track.index] = None;
            return;
        }
        record.request.target = Some(target);
        record.request.operation = operation(request.operation()) as i32;
        let mut hash = Sha256::new();
        hash.update(b"volparossa-storage-fixture-request-v3\0");
        hash.update(epoch.bytes);
        hash.update(request.id());
        let digest = hash.finalize().into();
        if record
            .request
            .verified_digest
            .is_some_and(|previous| previous != digest)
        {
            track.request_valid.store(false, Relaxed);
            track.life.incomplete.store(true, Relaxed);
            return;
        }
        record.request.verified_digest = Some(digest);
        if record.role == Role::Provider || flushed {
            record.request.digest = Some(digest);
        }
        if record.role == Role::Provider {
            record.request.provider_stage = ProviderStage::RequestVerified as i32;
        }
    }

    pub(super) fn bridge_phase(
        &self,
        phase: volparossa_content::private_storage::wire::bridge_observation::Phase,
    ) {
        use volparossa_content::private_storage::wire::bridge_observation::Phase as Wire;
        if self.0.as_ref().is_none_or(|track| track.version != 3) {
            return;
        }
        let now = Instant::now();
        if !self.update(|record| {
            if record.request.operation != Operation::Reserve as i32 {
                return;
            }
            match phase {
                Wire::RemoteRequestWrite if record.request.write_started.is_none() => {
                    record.request.write_started = Some(now);
                }
                Wire::RemoteReceiptRead if record.request.receipt_started.is_none() => {
                    record.request.receipt_started = Some(now);
                }
                Wire::RemoteReceiptVerify
                    if record.request.receipt_started.is_some()
                        && record.request.receipt_ended.is_none() =>
                {
                    record.request.receipt_ended = Some(now);
                }
                _ => {}
            }
        })
            && let Some(track) = &self.0 {
                track.request_valid.store(false, Relaxed);
            }
    }

    fn request_stage(&self, stage: RequestStage) {
        if self.0.as_ref().is_none_or(|track| track.version != 3) {
            return;
        }
        let stage = match stage {
            RequestStage::ReceiptWriteEntered => ProviderStage::ReceiptWriteEntered,
            RequestStage::ReceiptFlushReturned => ProviderStage::ReceiptFlushReturned,
        } as i32;
        if !self.update(|record| {
            record.request.provider_stage = stage;
        })
            && let Some(track) = &self.0 {
                track.request_valid.store(false, Relaxed);
            }
    }

    fn worker(&self) -> Option<Arc<dyn WorkerObserver>> {
        let track = self.0.as_ref().filter(|track| {
            track.version == 3
                && track.request_valid.load(Relaxed)
                && track.life.alive.load(Relaxed)
        })?;
        Some(Arc::new(Worker {
            owner: Arc::downgrade(&track.owner),
            life: Arc::downgrade(&track.life),
            index: track.index,
            token: track.token,
        }))
    }

    pub(super) fn enter(&self, phase: Phase) {
        self.invalidate_acquire();
        self.update(|record| {
            record.phase = phase;
            record.flow_acquire = None;
        });
    }

    pub(super) fn flow_acquire(&self, summary: Option<StorageFixtureAcquireSummary>) {
        if self.0.as_ref().is_none_or(|track| track.version < 2) {
            return;
        }
        self.invalidate_acquire();
        self.update(|record| {
            if record.role == Role::Client && record.phase == Phase::FlowAcquire {
                record.flow_acquire = summary;
                record.acquire_valid.store(summary.is_some(), Relaxed);
            }
        });
    }

    fn invalidate_acquire(&self) {
        if let Some(track) = &self.0 {
            // Missing the bank lock must not leave a previously recorded detail exportable.
            track.acquire_valid.store(false, Relaxed);
        }
    }

    pub(super) fn finish(&self, terminal: Terminal) {
        let Some(track) = &self.0 else {
            return;
        };
        if track.terminal_recorded.load(Relaxed) {
            return;
        }
        if terminal != Terminal::OperationError {
            self.invalidate_acquire();
        }
        if self.update(|record| {
            record.terminal = terminal;
            if terminal != Terminal::OperationError {
                record.flow_acquire = None;
            }
            record.finished = Some(Instant::now());
            record.hash = None;
        }) {
            track.terminal_recorded.store(true, Relaxed);
        }
    }

    fn bytes(&self, bytes: &[u8]) {
        let Some(track) = &self.0 else {
            return;
        };
        if bytes.is_empty()
            || !track.prefix_valid.load(Relaxed)
            || track.prefix_complete.load(Relaxed)
        {
            return;
        }
        if !self.update(|record| {
            let amount = bytes.len().min(PREFIX_BYTES - record.bytes);
            if let Some(hash) = &mut record.hash {
                hash.update(&bytes[..amount]);
                record.bytes += amount;
                if record.bytes == PREFIX_BYTES {
                    record.fingerprint = record.hash.take().map(|hash| hash.finalize().into());
                    record.prefix_complete.store(true, Relaxed);
                }
            }
        }) {
            // Missing even one successful prefix write/read forbids a later digest.
            track.prefix_valid.store(false, Relaxed);
        }
    }
}

impl Drop for Guard {
    fn drop(&mut self) {
        self.finish(Terminal::Cancelled);
    }
}

pub(super) struct ProviderObserver<'a> {
    pub(super) activity: &'a provider_activity::Session,
    pub(super) fixture: &'a Guard,
}

impl Observer for ProviderObserver<'_> {
    fn enter(&self, stage: Stage) {
        self.activity.enter(stage);
        self.fixture.enter(match stage {
            Stage::TlsHandshake => Phase::TlsHandshake,
            Stage::RegistrySnapshot => Phase::RegistrySnapshot,
            Stage::SelectorRead => Phase::SelectorRead,
            Stage::StorageGrantReadVerify => Phase::StorageGrantReadVerify,
            Stage::StorageChallengeWriteFlush => Phase::StorageChallengeWriteFlush,
            Stage::StorageRequestReadVerify => Phase::StorageRequestReadVerify,
            Stage::StorageOperation => Phase::StorageOperation,
            Stage::OtherProtocol => Phase::OtherProtocol,
            Stage::Closing => Phase::Closing,
        });
    }
    fn verified_request(&self, request: &VerifiedStorageRequest) {
        self.fixture.bind_request(request, false);
    }

    fn request_stage(&self, stage: RequestStage) {
        self.fixture.request_stage(stage);
    }

    fn worker(&self) -> Option<Arc<dyn WorkerObserver>> {
        self.fixture.worker()
    }
}

// No strong collector/lifetime reference, target, payload, key or digest survives in the worker.
struct Worker {
    owner: Weak<Correlation>,
    life: Weak<Life>,
    index: usize,
    token: u64,
}

impl Worker {
    fn update(&self, returned: Option<bool>) {
        let (Some(owner), Some(life)) = (self.owner.upgrade(), self.life.upgrade()) else {
            return;
        };
        if !life.alive.load(Relaxed) {
            return;
        }
        let Ok(mut bank) = owner.bank.try_lock() else {
            life.incomplete.store(true, Relaxed);
            return;
        };
        bank.expire(Instant::now());
        let Some(epoch) = &mut bank.epoch else {
            return;
        };
        if !Arc::ptr_eq(&epoch.life, &life) {
            return;
        }
        let Some(record) = &mut epoch.records[self.index] else {
            return;
        };
        if record.token != self.token || !record.request_valid.load(Relaxed) {
            return;
        }
        let valid = match returned {
            None => record.request.worker_state == WorkerState::Unobserved as i32,
            Some(_) => record.request.worker_state == WorkerState::Entered as i32,
        };
        if !valid {
            record.request_valid.store(false, Relaxed);
            life.incomplete.store(true, Relaxed);
            return;
        }
        record.request.worker_state = match returned {
            None => WorkerState::Entered,
            Some(true) => WorkerState::ReturnedOk,
            Some(false) => WorkerState::ReturnedError,
        } as i32;
        if record.finished.is_none() {
            record.request.provider_stage = if returned.is_none() {
                ProviderStage::BackendEntered
            } else {
                ProviderStage::BackendReturned
            } as i32;
        } else if returned.is_some() {
            record.request.returned_after_terminal = true;
        }
    }
}

impl WorkerObserver for Worker {
    fn entered(&self) {
        self.update(None);
    }
    fn returned(&self, success: bool) {
        self.update(Some(success));
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod request_tests;
