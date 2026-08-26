//! Authenticated helper-v3 worker process and generation-safe transaction foundation.
//!
//! This module is deliberately disconnected from the production helper engine. It proves a
//! fail-closed child lifecycle and cancellation-safe plan/call/commit discipline without making
//! route network changes. The disconnected production entry applies and proves narrow NEWNET,
//! capability, descriptor, credential, dedicated non-root identity and post-install clone/fork
//! confinement before the parent could register it. Retirement owns only the exact leader, and this
//! bootstrap does not independently attest descendant absence before filter installation. The child
//! still implements only in-memory initialise/destroy.

use std::{
    collections::{HashMap, VecDeque},
    fs,
    future::Future,
    io,
    num::{NonZeroU32, NonZeroU64},
    os::fd::{AsRawFd, OwnedFd},
    process::{Child, Command, Stdio},
    sync::{
        Arc, Condvar, Mutex, OnceLock,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

#[cfg(test)]
use std::sync::atomic::AtomicUsize;

#[cfg(test)]
use nix::unistd::dup;
use nix::{
    errno::Errno,
    fcntl::{FcntlArg, FdFlag, fcntl},
    sys::{
        prctl,
        signal::Signal,
        socket::{SockType, getsockopt, sockopt},
    },
    unistd::{close, getegid, geteuid, getpid, getppid},
};
use rand_core::{OsRng, RngCore};
use rustix::io::fcntl_dupfd_cloexec;
use socket2::{Domain, Socket};
use thiserror::Error;
use tokio::{
    sync::{Notify, oneshot},
    task::JoinHandle,
};

use crate::{
    deadline::HardDeadline,
    internal_protocol::{
        ContextDestroyed, ContextInitialised, INTERNAL_WORKER_MAGIC,
        INTERNAL_WORKER_PROTOCOL_VERSION, InternalWorkerRequest, InternalWorkerResponse,
        InternalWorkerResult, encode_request, internal_worker_request, internal_worker_response,
        validate_response_for_request,
    },
    ownership_journal::{
        DurableArmOutcome, DurableIntentRegistration, DurableMayOwnPrepare, DurableOwnershipActor,
        DurableOwnershipError, DurableOwnershipKey, DurableRegistrationOutcome,
    },
    worker_sandbox::validate_post_exec_descriptor_allowlist,
    worker_transport::{
        CredentialedWorkerExecution, ExpectedUnixCredentials, WorkerTransportError,
        enable_passcred_receiver, private_credential_worker_channel, receive_credential_record,
        receive_credential_record_with_deadline, receive_credential_worker_request,
        receive_credential_worker_response_with_deadline, send_credential_record,
        send_credential_record_with_deadline, send_credential_worker_request_with_deadline,
        send_credential_worker_response, validate_adopted_transport_socket,
    },
};
use volparossa_linux_uapi::install_close_range_on_exec;

pub(crate) const INTERNAL_WORKER_V3_ARGUMENT: &str = "--internal-worker-v3";
pub(crate) const INTERNAL_WORKER_V3_LIVE_PROOF_ARGUMENT: &str = "--internal-worker-v3-live-proof";

#[cfg(test)]
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(5);
const SPAWN_TIMEOUT: Duration = Duration::from_secs(30);
const LIVE_FDSTORE_PUBLICATION_TIMEOUT: Duration = Duration::from_secs(5);
const TERMINATION_POLL_INTERVAL: Duration = Duration::from_millis(5);
const TERMINATION_TIMEOUT: Duration = Duration::from_millis(250);
const DEFAULT_MAX_WORKERS: usize = 64;
const DEFAULT_MAX_CACHE_ENTRIES: usize = 1_024;
const DEFAULT_MAX_TTL: Duration = Duration::from_secs(15 * 60);
const MAX_PROCESS_OWNERS: usize = DEFAULT_MAX_WORKERS;
const MAX_SUPERVISORS: usize = DEFAULT_MAX_WORKERS;
static WORKER_SPAWN_LOCK: Mutex<()> = Mutex::new(());

const LIVE_PROOF_CUSTODY_FD_NAME: &str =
    "volparossa-custody-v1-4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c4c";

type ContextId = [u8; 16];

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InitialProcessIdentity {
    uid: u32,
    gid: u32,
}

#[derive(Clone, Copy)]
struct WorkerSpawnBinding<'a> {
    parent_identity: InitialProcessIdentity,
    worker_identity: crate::worker_sandbox::WorkerIdentity,
    context_id: ContextId,
    generation: u64,
    retained_environment: Option<(&'a str, &'a str)>,
    deadline: HardDeadline,
}

#[derive(Debug, Error)]
enum WorkerV3Error {
    #[error("worker authentication failed")]
    Authentication,
    #[error("invalid worker lifecycle request")]
    Invalid,
    #[error("worker lifecycle conflict")]
    Conflict,
    #[error("worker registry capacity reached")]
    Capacity,
    #[error("worker is not alive")]
    Dead,
    #[error("worker generation is quarantined")]
    Quarantined,
    #[error("worker IPC result is ambiguous")]
    Ambiguous,
    #[error("stale worker completion")]
    Stale,
    #[error("worker operation already in flight")]
    Busy,
    #[error("worker coordinator is shutting down")]
    ShuttingDown,
    #[error("worker async runtime is unavailable")]
    RuntimeUnavailable,
    #[error("worker operation hard deadline elapsed")]
    Deadline,
    #[error("worker I/O failed")]
    Io(#[from] io::Error),
    #[error("worker transport failed")]
    Transport(#[from] WorkerTransportError),
    #[error("worker sandbox failed")]
    Sandbox(#[from] crate::worker_sandbox::WorkerSandboxError),
    #[error("worker systemd custody input is invalid")]
    SystemdCustodyInput(#[from] crate::systemd_fdstore::FdStoreError),
    #[error("worker systemd custody publication failed")]
    SystemdCustodyPublication(#[from] crate::systemd_fdstore::PublicationFailure),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum HandshakeKind {
    ParentHello = 1,
    NamespaceReady = 2,
    NamespacePinned = 3,
    ChildHello = 4,
    SandboxAccepted = 5,
    SandboxReady = 6,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct HandshakeRecord {
    kind: HandshakeKind,
    context_id: ContextId,
    generation: u64,
    challenge: [u8; 32],
    parent_pid: u32,
    child_pid: u32,
    proof_hash: [u8; 32],
    worker_uid: u32,
    worker_gid: u32,
}

impl HandshakeRecord {
    const LENGTH: usize = 120;

    fn encode(self) -> [u8; Self::LENGTH] {
        let mut encoded = [0_u8; Self::LENGTH];
        encoded[0..8].copy_from_slice(INTERNAL_WORKER_MAGIC);
        encoded[8..12].copy_from_slice(&INTERNAL_WORKER_PROTOCOL_VERSION.to_be_bytes());
        encoded[12] = self.kind as u8;
        encoded[16..32].copy_from_slice(&self.context_id);
        encoded[32..40].copy_from_slice(&self.generation.to_be_bytes());
        encoded[40..72].copy_from_slice(&self.challenge);
        encoded[72..76].copy_from_slice(&self.parent_pid.to_be_bytes());
        encoded[76..80].copy_from_slice(&self.child_pid.to_be_bytes());
        encoded[80..112].copy_from_slice(&self.proof_hash);
        encoded[112..116].copy_from_slice(&self.worker_uid.to_be_bytes());
        encoded[116..120].copy_from_slice(&self.worker_gid.to_be_bytes());
        encoded
    }

    fn decode(encoded: &[u8]) -> Result<Self, WorkerV3Error> {
        if encoded.len() != Self::LENGTH
            || encoded.get(0..8) != Some(INTERNAL_WORKER_MAGIC.as_slice())
            || encoded.get(13..16) != Some([0_u8; 3].as_slice())
        {
            return Err(WorkerV3Error::Authentication);
        }
        let version = u32::from_be_bytes(read_array(encoded, 8)?);
        if version != INTERNAL_WORKER_PROTOCOL_VERSION {
            return Err(WorkerV3Error::Authentication);
        }
        let kind = match encoded[12] {
            1 => HandshakeKind::ParentHello,
            2 => HandshakeKind::NamespaceReady,
            3 => HandshakeKind::NamespacePinned,
            4 => HandshakeKind::ChildHello,
            5 => HandshakeKind::SandboxAccepted,
            6 => HandshakeKind::SandboxReady,
            _ => return Err(WorkerV3Error::Authentication),
        };
        let record = Self {
            kind,
            context_id: read_array(encoded, 16)?,
            generation: u64::from_be_bytes(read_array(encoded, 32)?),
            challenge: read_array(encoded, 40)?,
            parent_pid: u32::from_be_bytes(read_array(encoded, 72)?),
            child_pid: u32::from_be_bytes(read_array(encoded, 76)?),
            proof_hash: read_array(encoded, 80)?,
            worker_uid: u32::from_be_bytes(read_array(encoded, 112)?),
            worker_gid: u32::from_be_bytes(read_array(encoded, 116)?),
        };
        if record.context_id.iter().all(|byte| *byte == 0)
            || record.generation == 0
            || record.challenge.iter().all(|byte| *byte == 0)
            || record.parent_pid <= 1
            || record.child_pid == 0
            || crate::worker_sandbox::WorkerIdentity::new(record.worker_uid, record.worker_gid)
                .is_err()
            || (matches!(
                record.kind,
                HandshakeKind::ParentHello
                    | HandshakeKind::NamespaceReady
                    | HandshakeKind::NamespacePinned
                    | HandshakeKind::ChildHello
            ) && record.proof_hash != [0; 32])
            || (matches!(
                record.kind,
                HandshakeKind::SandboxAccepted | HandshakeKind::SandboxReady
            ) && record.proof_hash == [0; 32])
        {
            return Err(WorkerV3Error::Authentication);
        }
        Ok(record)
    }

    fn namespace_ready(self) -> Self {
        Self {
            kind: HandshakeKind::NamespaceReady,
            ..self
        }
    }

    fn namespace_pinned(self) -> Self {
        Self {
            kind: HandshakeKind::NamespacePinned,
            ..self
        }
    }

    fn child_reply(self) -> Self {
        Self {
            kind: HandshakeKind::ChildHello,
            ..self
        }
    }

    fn sandbox_accepted(self, proof_hash: [u8; 32]) -> Self {
        Self {
            kind: HandshakeKind::SandboxAccepted,
            proof_hash,
            ..self
        }
    }

    fn sandbox_ready(self) -> Self {
        Self {
            kind: HandshakeKind::SandboxReady,
            ..self
        }
    }
}

fn read_array<const LENGTH: usize>(
    encoded: &[u8],
    offset: usize,
) -> Result<[u8; LENGTH], WorkerV3Error> {
    encoded
        .get(offset..offset.saturating_add(LENGTH))
        .ok_or(WorkerV3Error::Authentication)?
        .try_into()
        .map_err(|_| WorkerV3Error::Authentication)
}

fn validate_parent_snapshot(
    initial_parent: i32,
    observed_parent: i32,
    current_uid: u32,
    required_user: u32,
) -> Result<(), WorkerV3Error> {
    if initial_parent <= 1 || observed_parent != initial_parent || current_uid != required_user {
        return Err(WorkerV3Error::Authentication);
    }
    Ok(())
}

fn validate_connected_socket(socket: &Socket) -> Result<(), WorkerV3Error> {
    if socket.domain()? != Domain::UNIX
        || getsockopt(socket, sockopt::SockType).map_err(nix_io)? != SockType::SeqPacket
        || getsockopt(socket, sockopt::AcceptConn).map_err(nix_io)?
    {
        return Err(WorkerV3Error::Authentication);
    }
    let descriptor_flags =
        FdFlag::from_bits_truncate(fcntl(socket, FcntlArg::F_GETFD).map_err(nix_io)?);
    if !descriptor_flags.contains(FdFlag::FD_CLOEXEC) {
        return Err(WorkerV3Error::Authentication);
    }
    Ok(())
}

fn validate_child_descriptor_contract(channel: &Socket) -> Result<(), WorkerV3Error> {
    validate_post_exec_descriptor_allowlist(&[
        libc::STDOUT_FILENO,
        libc::STDERR_FILENO,
        channel.as_raw_fd(),
    ])
    .map_err(|_| WorkerV3Error::Authentication)?;
    for descriptor in [libc::STDOUT_FILENO, libc::STDERR_FILENO] {
        if fs::read_link(format!("/proc/self/fd/{descriptor}"))?
            != std::path::Path::new("/dev/null")
        {
            return Err(WorkerV3Error::Authentication);
        }
    }
    validate_connected_socket(channel)
}

fn random_challenge() -> Result<[u8; 32], WorkerV3Error> {
    let mut challenge = [0_u8; 32];
    OsRng
        .try_fill_bytes(&mut challenge)
        .map_err(|_| WorkerV3Error::Authentication)?;
    if challenge.iter().all(|byte| *byte == 0) {
        return Err(WorkerV3Error::Authentication);
    }
    Ok(challenge)
}

#[derive(Clone, Copy)]
enum SandboxObservationMode {
    Production {
        parent_network_namespace: crate::worker_sandbox::NetworkNamespaceIdentity,
    },
    #[cfg(test)]
    Fixture(crate::worker_sandbox::WorkerSandboxSnapshot),
}

#[derive(Clone, Copy)]
struct CapturedSandboxObservation {
    mode: SandboxObservationMode,
    parent_seccomp_baseline: crate::worker_sandbox::LinuxSeccompState,
}

impl SandboxObservationMode {
    fn capture_parent_seccomp_baseline(self) -> Result<CapturedSandboxObservation, WorkerV3Error> {
        let parent_seccomp_baseline = match self {
            Self::Production { .. } => crate::worker_sandbox::current_thread_seccomp_state()?,
            #[cfg(test)]
            Self::Fixture(snapshot) => snapshot.fixture_seccomp_baseline()?,
        };
        Ok(CapturedSandboxObservation {
            mode: self,
            parent_seccomp_baseline,
        })
    }
}

impl CapturedSandboxObservation {
    fn pin_network_namespace_before_identity_drop(
        self,
        pins: &mut crate::worker_sandbox::WorkerKernelPins,
        required_group: u32,
        parent_pid: u32,
        child_pid: u32,
    ) -> Result<(), WorkerV3Error> {
        match self.mode {
            SandboxObservationMode::Production {
                parent_network_namespace,
            } => {
                pins.pin_network_namespace_before_identity_drop(
                    parent_network_namespace,
                    self.parent_seccomp_baseline,
                    required_group,
                    parent_pid,
                    child_pid,
                )?;
            }
            #[cfg(test)]
            SandboxObservationMode::Fixture(_) => {
                pins.pin_network_namespace_before_identity_drop_fixture(parent_pid, child_pid)?;
            }
        }
        Ok(())
    }

    fn observe(
        self,
        pins: &mut crate::worker_sandbox::WorkerKernelPins,
        parent_pid: u32,
        child_pid: u32,
        identity: crate::worker_sandbox::WorkerIdentity,
    ) -> Result<crate::worker_sandbox::WorkerSandboxSnapshot, WorkerV3Error> {
        match self.mode {
            SandboxObservationMode::Production {
                parent_network_namespace,
            } => Ok(pins.observe_and_pin(
                parent_network_namespace,
                self.parent_seccomp_baseline,
                parent_pid,
                child_pid,
                identity,
            )?),
            #[cfg(test)]
            SandboxObservationMode::Fixture(snapshot) => Ok(pins.observe_and_pin_fixture(
                parent_pid,
                child_pid,
                snapshot,
                self.parent_seccomp_baseline,
            )?),
        }
    }
}

fn spawn_after_seccomp_baseline(
    command: &mut Command,
    observation_mode: SandboxObservationMode,
    deadline: HardDeadline,
    lifetime: &WorkerLifetime,
) -> Result<(u32, CapturedSandboxObservation), WorkerV3Error> {
    let mut child_slot = lifetime
        .child_slot()
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner);
    ensure_worker_deadline(deadline)?;
    // Read the spawning thread, not a process-wide alias. The immediately spawned child inherits
    // this exact filter chain and must prove one additional fixed worker filter.
    let sandbox_observation = observation_mode.capture_parent_seccomp_baseline()?;
    ensure_worker_deadline(deadline)?;
    let child = command.spawn()?;
    *child_slot = Some(child);
    let child_pid = child_slot
        .as_ref()
        .map_or_else(|| std::process::abort(), Child::id);
    Ok((child_pid, sandbox_observation))
}

fn parent_handshake(
    process: &WorkerProcess,
    sandbox_observation: CapturedSandboxObservation,
    challenge: [u8; 32],
    binding: WorkerSpawnBinding<'_>,
) -> Result<(), WorkerV3Error> {
    let WorkerSpawnBinding {
        worker_identity,
        context_id,
        generation,
        retained_environment: _,
        deadline,
        ..
    } = binding;
    ensure_worker_deadline(deadline)?;
    let parent_pid = std::process::id();
    let hello = HandshakeRecord {
        kind: HandshakeKind::ParentHello,
        context_id,
        generation,
        challenge,
        parent_pid,
        child_pid: process.child_pid,
        proof_hash: [0; 32],
        worker_uid: worker_identity.uid(),
        worker_gid: worker_identity.gid(),
    };
    let expected_after_drop =
        parent_handshake_before_drop(process, sandbox_observation, hello, binding)?;
    parent_handshake_after_drop(
        process,
        sandbox_observation,
        hello,
        challenge,
        binding,
        expected_after_drop,
    )
}

fn parent_handshake_before_drop(
    process: &WorkerProcess,
    sandbox_observation: CapturedSandboxObservation,
    hello: HandshakeRecord,
    binding: WorkerSpawnBinding<'_>,
) -> Result<ExpectedUnixCredentials, WorkerV3Error> {
    let WorkerSpawnBinding {
        parent_identity,
        worker_identity,
        deadline,
        ..
    } = binding;
    let parent_pid = std::process::id();
    send_credential_record_with_deadline(&process.channel, &hello.encode(), deadline)?;
    let expected_before_drop =
        ExpectedUnixCredentials::new(process.child_pid, parent_identity.uid, parent_identity.gid)?;
    let encoded = receive_credential_record_with_deadline(
        &process.channel,
        HandshakeRecord::LENGTH,
        expected_before_drop,
        deadline,
    )?;
    if HandshakeRecord::decode(&encoded)? != hello.namespace_ready()
        || !process.liveness().probe_alive_until(deadline)?
    {
        return Err(WorkerV3Error::Authentication);
    }
    process.pin_worker_network_namespace_before_identity_drop(
        sandbox_observation,
        parent_identity.gid,
        parent_pid,
        process.child_pid,
    )?;
    ensure_worker_deadline(deadline)?;
    process.ensure_pinned_child_alive()?;
    send_credential_record_with_deadline(
        &process.channel,
        &hello.namespace_pinned().encode(),
        deadline,
    )?;
    let expected_after_drop = ExpectedUnixCredentials::new(
        process.child_pid,
        worker_identity.uid(),
        worker_identity.gid(),
    )?;
    Ok(expected_after_drop)
}

fn parent_handshake_after_drop(
    process: &WorkerProcess,
    sandbox_observation: CapturedSandboxObservation,
    hello: HandshakeRecord,
    challenge: [u8; 32],
    binding: WorkerSpawnBinding<'_>,
    expected_after_drop: ExpectedUnixCredentials,
) -> Result<(), WorkerV3Error> {
    let WorkerSpawnBinding {
        worker_identity,
        context_id,
        generation,
        deadline,
        ..
    } = binding;
    let parent_pid = std::process::id();
    let encoded = receive_credential_record_with_deadline(
        &process.channel,
        HandshakeRecord::LENGTH,
        expected_after_drop,
        deadline,
    )?;
    if HandshakeRecord::decode(&encoded)? != hello.child_reply()
        || !process.liveness().probe_alive_until(deadline)?
    {
        return Err(WorkerV3Error::Authentication);
    }

    let proof = receive_credential_record_with_deadline(
        &process.channel,
        crate::worker_sandbox::SandboxProofRecord::LENGTH,
        expected_after_drop,
        deadline,
    )?;
    // Receipt of the credential-bound proof is the child's post-apply completion barrier.
    // Only now may the parent independently sample and pin the final per-thread kernel state.
    let observed = process.observe_and_pin_sandbox(
        sandbox_observation,
        parent_pid,
        process.child_pid,
        worker_identity,
    )?;
    ensure_worker_deadline(deadline)?;
    crate::worker_sandbox::SandboxProofExpectation::new(
        context_id,
        generation,
        challenge,
        parent_pid,
        process.child_pid,
        observed,
    )
    .verify_once(
        &proof,
        crate::worker_sandbox::WorkerSandboxPlan::production(
            sandbox_observation.parent_seccomp_baseline,
            worker_identity,
        )?,
    )?;
    let proof_hash = *blake3::hash(&proof).as_bytes();
    if proof_hash == [0; 32] {
        return Err(WorkerV3Error::Authentication);
    }
    process.ensure_pinned_child_alive()?;
    let accepted = hello.sandbox_accepted(proof_hash);
    send_credential_record_with_deadline(&process.channel, &accepted.encode(), deadline)?;
    let encoded = receive_credential_record_with_deadline(
        &process.channel,
        HandshakeRecord::LENGTH,
        expected_after_drop,
        deadline,
    )?;
    if HandshakeRecord::decode(&encoded)? != accepted.sandbox_ready() {
        return Err(WorkerV3Error::Authentication);
    }
    process.ensure_pinned_child_alive()?;
    if !process.liveness().probe_alive_until(deadline)? {
        return Err(WorkerV3Error::Authentication);
    }
    ensure_worker_deadline(deadline)?;
    Ok(())
}

fn finish_unconstructed_launch_failure(
    mut retirement: ProcessRetirement,
    error: WorkerV3Error,
) -> WorkerV3Error {
    if retirement.terminate_bounded(TERMINATION_TIMEOUT) {
        error
    } else {
        escalate_retirement(retirement);
        WorkerV3Error::Ambiguous
    }
}

fn finish_launch_failure(process: WorkerProcess, error: WorkerV3Error) -> WorkerV3Error {
    let outcome = if process.terminate_bounded(TERMINATION_TIMEOUT) {
        error
    } else {
        process.transfer_retirement_to_reaper();
        WorkerV3Error::Ambiguous
    };
    drop(process);
    outcome
}

fn spawn_with_command(
    command: Command,
    parent_identity: InitialProcessIdentity,
    worker_identity: crate::worker_sandbox::WorkerIdentity,
    context_id: ContextId,
    generation: u64,
    retained_environment: Option<(&str, &str)>,
) -> Result<AuthenticatedWorker, WorkerV3Error> {
    let deadline = HardDeadline::after(SPAWN_TIMEOUT).map_err(WorkerV3Error::Io)?;
    spawn_with_command_until(
        command,
        parent_identity,
        worker_identity,
        context_id,
        generation,
        retained_environment,
        deadline,
    )
}

fn spawn_with_command_until(
    command: Command,
    parent_identity: InitialProcessIdentity,
    worker_identity: crate::worker_sandbox::WorkerIdentity,
    context_id: ContextId,
    generation: u64,
    retained_environment: Option<(&str, &str)>,
    deadline: HardDeadline,
) -> Result<AuthenticatedWorker, WorkerV3Error> {
    ensure_worker_deadline(deadline)?;
    let parent_network_namespace = crate::worker_sandbox::current_network_namespace_identity()?;
    let binding = WorkerSpawnBinding {
        parent_identity,
        worker_identity,
        context_id,
        generation,
        retained_environment,
        deadline,
    };
    spawn_with_command_mode(
        command,
        binding,
        SandboxObservationMode::Production {
            parent_network_namespace,
        },
    )
}

#[cfg(test)]
fn spawn_with_command_fixture(
    command: Command,
    parent_identity: InitialProcessIdentity,
    worker_identity: crate::worker_sandbox::WorkerIdentity,
    context_id: ContextId,
    generation: u64,
    retained_environment: Option<(&str, &str)>,
    snapshot: crate::worker_sandbox::WorkerSandboxSnapshot,
) -> Result<AuthenticatedWorker, WorkerV3Error> {
    let deadline = HardDeadline::after(SPAWN_TIMEOUT).map_err(WorkerV3Error::Io)?;
    let binding = WorkerSpawnBinding {
        parent_identity,
        worker_identity,
        context_id,
        generation,
        retained_environment,
        deadline,
    };
    spawn_with_command_mode(command, binding, SandboxObservationMode::Fixture(snapshot))
}

fn spawn_with_command_mode(
    command: Command,
    binding: WorkerSpawnBinding<'_>,
    observation_mode: SandboxObservationMode,
) -> Result<AuthenticatedWorker, WorkerV3Error> {
    ensure_worker_deadline(binding.deadline)?;
    if geteuid().as_raw() != binding.parent_identity.uid
        || getegid().as_raw() != binding.parent_identity.gid
        || binding.context_id.iter().all(|byte| *byte == 0)
        || binding.generation == 0
    {
        return Err(WorkerV3Error::Authentication);
    }
    let _spawn_guard = lock_worker_spawn_until(binding.deadline)?;
    ensure_worker_deadline(binding.deadline)?;
    spawn_with_command_locked(command, binding, observation_mode)
}

fn lock_worker_spawn_until(
    deadline: HardDeadline,
) -> Result<std::sync::MutexGuard<'static, ()>, WorkerV3Error> {
    loop {
        ensure_worker_deadline(deadline)?;
        match WORKER_SPAWN_LOCK.try_lock() {
            Ok(guard) => {
                ensure_worker_deadline(deadline)?;
                return Ok(guard);
            }
            Err(std::sync::TryLockError::Poisoned(error)) => {
                ensure_worker_deadline(deadline)?;
                return Ok(error.into_inner());
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                let remaining = deadline.remaining().map_err(|error| {
                    if error.kind() == io::ErrorKind::TimedOut {
                        WorkerV3Error::Deadline
                    } else {
                        WorkerV3Error::Io(error)
                    }
                })?;
                thread::sleep(remaining.min(TERMINATION_POLL_INTERVAL));
            }
        }
    }
}

/// Spawns only while the caller holds `WORKER_SPAWN_LOCK`.
fn spawn_with_command_locked(
    mut command: Command,
    binding: WorkerSpawnBinding<'_>,
    observation_mode: SandboxObservationMode,
) -> Result<AuthenticatedWorker, WorkerV3Error> {
    let WorkerSpawnBinding {
        parent_identity: _,
        worker_identity,
        context_id,
        generation,
        retained_environment,
        deadline,
    } = binding;
    ensure_worker_deadline(deadline)?;
    let challenge = random_challenge()?;
    let (parent, worker) = private_credential_worker_channel()?;
    validate_connected_socket(&parent)?;
    validate_connected_socket(&worker)?;
    let inherited: OwnedFd = worker.into();
    command
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(inherited))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    if let Some((name, value)) = retained_environment {
        command.env(name, value);
    }
    let retirement_permit = acquire_retirement_permit()?;
    let lifetime = Arc::new(WorkerLifetime::Child(Mutex::new(None)));
    let alive_hint = Arc::new(AtomicBool::new(false));
    let mut retirement = ProcessRetirement {
        liveness: WorkerLiveness {
            lifetime: Arc::clone(&lifetime),
            alive_hint: Arc::clone(&alive_hint),
        },
        permit: Some(retirement_permit),
        kernel_pins: None,
        armed: true,
    };
    // This is deliberately the final user pre-exec hook installed on the command.
    install_close_range_on_exec(&mut command);
    // Command::spawn is a blocking OS boundary and cannot itself be interrupted. Once it returns,
    // the exact child is immediately moved into the already-armed linear retirement owner.
    let launched =
        spawn_after_seccomp_baseline(&mut command, observation_mode, deadline, lifetime.as_ref());
    let (child_pid, observation) = match launched {
        Ok(launched) => launched,
        Err(error) => {
            retirement.confirm_reaped();
            return Err(error);
        }
    };
    alive_hint.store(true, Ordering::SeqCst);
    let kernel_pins = {
        let child_slot = lifetime
            .child_slot()
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let child = child_slot.as_ref().unwrap_or_else(|| std::process::abort());
        crate::worker_sandbox::WorkerKernelPins::pin_process(child)
    };
    let kernel_pins = match kernel_pins {
        Ok(kernel_pins) => kernel_pins,
        Err(error) => {
            return Err(finish_unconstructed_launch_failure(
                retirement,
                error.into(),
            ));
        }
    };
    retirement.kernel_pins = Some(kernel_pins);
    let expected_peer =
        match ExpectedUnixCredentials::new(child_pid, worker_identity.uid(), worker_identity.gid())
        {
            Ok(expected_peer) => expected_peer,
            Err(error) => {
                return Err(finish_unconstructed_launch_failure(
                    retirement,
                    error.into(),
                ));
            }
        };
    let process = WorkerProcess {
        child_pid,
        binding: Some((context_id, generation)),
        expected_peer,
        channel: parent,
        lifetime,
        alive_hint,
        retirement: Mutex::new(Some(retirement)),
    };
    if let Err(error) = ensure_worker_deadline(deadline) {
        return Err(finish_launch_failure(process, error));
    }
    if !process.probe_alive() {
        return Err(finish_launch_failure(process, WorkerV3Error::Dead));
    }
    if let Err(error) = parent_handshake(&process, observation, challenge, binding) {
        return Err(finish_launch_failure(process, error));
    }
    Ok(AuthenticatedWorker {
        process,
        bootstrap_challenge: BootstrapChallenge(challenge),
    })
}

fn spawn_worker_v3(
    reservation: GenerationReservation,
) -> Result<SpawnedWorker, WorkerSpawnFailure> {
    let deadline = match HardDeadline::after(SPAWN_TIMEOUT) {
        Ok(deadline) => deadline,
        Err(error) => {
            return Err(WorkerSpawnFailure {
                error: WorkerV3Error::Io(error),
                reservation,
            });
        }
    };
    spawn_worker_v3_until(reservation, deadline)
}

fn spawn_worker_v3_until(
    reservation: GenerationReservation,
    deadline: HardDeadline,
) -> Result<SpawnedWorker, WorkerSpawnFailure> {
    let result = (|| {
        ensure_worker_deadline(deadline)?;
        if !geteuid().is_root() {
            return Err(WorkerV3Error::Authentication);
        }
        // Linux `/proc/self/exe` reopens the exact running image inode, avoiding pathname replacement
        // and parent/child image skew across package updates.
        let mut command = Command::new("/proc/self/exe");
        command.arg(INTERNAL_WORKER_V3_ARGUMENT);
        let account = crate::runtime::pinned_production_worker_identity()?;
        let worker_identity =
            crate::worker_sandbox::WorkerIdentity::new(account.uid(), account.gid())?;
        spawn_with_command_until(
            command,
            InitialProcessIdentity {
                uid: 0,
                gid: getegid().as_raw(),
            },
            worker_identity,
            reservation.context_id,
            reservation.generation,
            None,
            deadline,
        )
    })();
    match result {
        Ok(authenticated) => Ok(SpawnedWorker {
            reservation,
            process: authenticated.process,
            bootstrap_challenge: authenticated.bootstrap_challenge,
        }),
        Err(error) => Err(WorkerSpawnFailure { error, reservation }),
    }
}

/// Runs one fixed production-image bootstrap without exposing a production engine operation.
pub(crate) fn run_internal_worker_v3_live_proof() -> bool {
    run_internal_worker_v3_live_proof_inner().is_ok()
}

fn run_internal_worker_v3_live_proof_inner() -> Result<(), WorkerV3Error> {
    let effective_group = getegid().as_raw();
    crate::worker_sandbox::validate_live_proof_parent_contract(effective_group)?;
    let runtime = crate::runtime::prepare_production_runtime()?;
    if runtime.agent_gid != effective_group {
        return Err(WorkerV3Error::Authentication);
    }

    let mut registry = WorkerRegistry::new(1, 1, Duration::from_secs(30));
    let reservation =
        registry.reserve_generation([0x4c; 16], Duration::from_secs(30), Instant::now())?;
    let spawned = match spawn_worker_v3(reservation) {
        Ok(spawned) => spawned,
        Err(WorkerSpawnFailure { error, reservation }) => {
            registry.abandon_generation(reservation)?;
            return Err(error);
        }
    };
    let SpawnedWorker {
        reservation,
        process,
        bootstrap_challenge: _bootstrap_challenge,
    } = spawned;
    let ready_and_pinned = process.probe_alive() && process.has_complete_kernel_pins();

    // Capture every publication error inside this closure. Nothing may return from the outer live
    // proof until the exact worker has received a bounded termination attempt and its reservation
    // has received a settlement attempt.
    let publication_result = (|| -> Result<(), WorkerV3Error> {
        if !ready_and_pinned {
            return Err(WorkerV3Error::Authentication);
        }
        let deadline = HardDeadline::after(LIVE_FDSTORE_PUBLICATION_TIMEOUT)?;
        let coordinates = WorkerGenerationCoordinates {
            context_id: reservation.context_id,
            worker_generation: NonZeroU64::new(reservation.generation)
                .ok_or(WorkerV3Error::Authentication)?,
        };
        let recovery_identity =
            process.duplicate_recovery_identity_source_until(coordinates, deadline)?;
        let (anchor, restart_custody) = recovery_identity
            .authenticated_pins
            .verified_anchor_with_restart_custody()?;
        if anchor.pid != recovery_identity.expected_child_pid {
            return Err(WorkerV3Error::Authentication);
        }
        restart_custody.ensure_live_and_namespace_matches_anchor(anchor)?;
        deadline.ensure_remaining()?;

        let custody_name =
            crate::systemd_fdstore::CustodyFdName::parse(LIVE_PROOF_CUSTODY_FD_NAME)?;
        let custody = crate::systemd_fdstore::BorrowedCustodyPair::new(
            restart_custody.borrowed_pidfd(),
            restart_custody.borrowed_network_namespace(),
        )?;
        let publication_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_io()
            .enable_time()
            .build()?;
        let attestation = publication_runtime.block_on(
            crate::systemd_fdstore::publish_current_process_custody(
                custody_name,
                custody,
                deadline,
            ),
        )?;
        drop(attestation);
        drop(publication_runtime);
        drop(restart_custody);
        drop(recovery_identity);
        Ok(())
    })();

    let reaped = process.terminate_bounded(TERMINATION_TIMEOUT);
    let released = process.retirement_released_after_confirmed_reap() && !process.probe_alive();
    let registry_cleanup = registry.abandon_generation(reservation);
    drop(runtime);
    let local_cleanup_result = registry_cleanup.and_then(|()| {
        if reaped && released {
            Ok(())
        } else {
            Err(WorkerV3Error::Ambiguous)
        }
    });
    publication_result.and(local_cleanup_result)
}

pub(crate) fn run_internal_worker_v3_entry() -> bool {
    geteuid().is_root() && run_child(0, getegid().as_raw()).is_ok()
}

fn run_child(required_user: u32, required_group: u32) -> Result<(), WorkerV3Error> {
    run_child_with_sandbox(
        required_user,
        required_group,
        |parent_network_namespace| {
            Ok(crate::worker_sandbox::begin_production_sandbox(
                parent_network_namespace,
            )?)
        },
        |prepared, identity| Ok(prepared.finish(identity)?),
    )
}

#[cfg(test)]
fn run_child_with_fixture_sandbox(
    required_user: u32,
    required_group: u32,
    snapshot: crate::worker_sandbox::WorkerSandboxSnapshot,
) -> Result<(), WorkerV3Error> {
    run_child_with_sandbox(
        required_user,
        required_group,
        |_| Ok(()),
        move |(), _| Ok(snapshot),
    )
}

fn prepare_child_channel(
    required_user: u32,
) -> Result<
    (
        Socket,
        i32,
        u32,
        crate::worker_sandbox::NetworkNamespaceIdentity,
    ),
    WorkerV3Error,
> {
    let initial_parent = getppid().as_raw();
    validate_parent_snapshot(
        initial_parent,
        getppid().as_raw(),
        geteuid().as_raw(),
        required_user,
    )?;
    prctl::set_pdeathsig(Some(Signal::SIGKILL)).map_err(nix_io)?;
    validate_parent_snapshot(
        initial_parent,
        getppid().as_raw(),
        geteuid().as_raw(),
        required_user,
    )?;

    match close(3) {
        Ok(()) | Err(Errno::EBADF) => {}
        Err(error) => return Err(WorkerV3Error::Io(nix_io(error))),
    }
    let inherited = fcntl_dupfd_cloexec(io::stdin(), 3).map_err(rustix_io)?;
    if inherited.as_raw_fd() != 3 {
        return Err(WorkerV3Error::Authentication);
    }
    close(libc::STDIN_FILENO).map_err(nix_io)?;
    let channel = Socket::from(inherited);
    validate_child_descriptor_contract(&channel)?;
    let child_pid = u32::try_from(getpid().as_raw()).map_err(|_| WorkerV3Error::Authentication)?;
    Ok((
        channel,
        initial_parent,
        child_pid,
        crate::worker_sandbox::current_network_namespace_identity()?,
    ))
}

fn run_child_with_sandbox<P, B, F>(
    required_user: u32,
    required_group: u32,
    begin_sandbox: B,
    finish_sandbox: F,
) -> Result<(), WorkerV3Error>
where
    B: FnOnce(crate::worker_sandbox::NetworkNamespaceIdentity) -> Result<P, WorkerV3Error>,
    F: FnOnce(
        P,
        crate::worker_sandbox::WorkerIdentity,
    ) -> Result<crate::worker_sandbox::WorkerSandboxSnapshot, WorkerV3Error>,
{
    let (channel, initial_parent, child_pid, parent_network_namespace) =
        prepare_child_channel(required_user)?;
    let prepared_sandbox = begin_sandbox(parent_network_namespace)?;
    validate_child_descriptor_contract(&channel)?;
    enable_passcred_receiver(&channel)?;

    let parent_pid = u32::try_from(initial_parent).map_err(|_| WorkerV3Error::Authentication)?;
    let expected_parent = ExpectedUnixCredentials::new(parent_pid, required_user, required_group)?;
    let encoded = receive_credential_record(&channel, HandshakeRecord::LENGTH, expected_parent)?;
    let hello = HandshakeRecord::decode(&encoded)?;
    if hello.kind != HandshakeKind::ParentHello
        || hello.parent_pid != parent_pid
        || hello.child_pid != child_pid
    {
        return Err(WorkerV3Error::Authentication);
    }
    let worker_identity =
        crate::worker_sandbox::WorkerIdentity::new(hello.worker_uid, hello.worker_gid)?;
    send_credential_record(&channel, &hello.namespace_ready().encode())?;
    let encoded = receive_credential_record(&channel, HandshakeRecord::LENGTH, expected_parent)?;
    if HandshakeRecord::decode(&encoded)? != hello.namespace_pinned() {
        return Err(WorkerV3Error::Authentication);
    }

    let sandbox_snapshot = finish_sandbox(prepared_sandbox, worker_identity)?;
    // Linux clears PR_SET_PDEATHSIG during a credential transition. Restore it before the child
    // performs any post-drop IPC, then recheck both the signal and exact parent relationship.
    prctl::set_pdeathsig(Some(Signal::SIGKILL)).map_err(nix_io)?;
    if prctl::get_pdeathsig().map_err(nix_io)? != Some(Signal::SIGKILL) {
        return Err(WorkerV3Error::Authentication);
    }
    validate_parent_snapshot(
        initial_parent,
        getppid().as_raw(),
        geteuid().as_raw(),
        worker_identity.uid(),
    )?;
    if getegid().as_raw() != worker_identity.gid() {
        return Err(WorkerV3Error::Authentication);
    }
    validate_child_descriptor_contract(&channel)?;
    send_credential_record(&channel, &hello.child_reply().encode())?;
    let proof = crate::worker_sandbox::SandboxProofRecord::new(
        hello.context_id,
        hello.generation,
        hello.challenge,
        hello.parent_pid,
        hello.child_pid,
        sandbox_snapshot,
    )
    .encode();
    send_credential_record(&channel, &proof)?;
    let proof_hash = *blake3::hash(&proof).as_bytes();
    if proof_hash == [0; 32] {
        return Err(WorkerV3Error::Authentication);
    }
    let accepted = hello.sandbox_accepted(proof_hash);
    let encoded = receive_credential_record(&channel, HandshakeRecord::LENGTH, expected_parent)?;
    if HandshakeRecord::decode(&encoded)? != accepted {
        return Err(WorkerV3Error::Authentication);
    }
    prctl::set_dumpable(false).map_err(nix_io)?;
    if prctl::get_dumpable().map_err(nix_io)? {
        return Err(WorkerV3Error::Authentication);
    }
    validate_parent_snapshot(
        initial_parent,
        getppid().as_raw(),
        geteuid().as_raw(),
        worker_identity.uid(),
    )?;
    if getegid().as_raw() != worker_identity.gid()
        || prctl::get_pdeathsig().map_err(nix_io)? != Some(Signal::SIGKILL)
    {
        return Err(WorkerV3Error::Authentication);
    }
    send_credential_record(&channel, &accepted.sandbox_ready().encode())?;
    child_loop(&channel, expected_parent, hello.context_id)
}

fn child_loop(
    channel: &Socket,
    expected_parent: ExpectedUnixCredentials,
    bound_context: ContextId,
) -> Result<(), WorkerV3Error> {
    let mut context: Option<ContextId> = None;
    loop {
        let request = receive_credential_worker_request(channel, expected_parent)?;
        let operation = request.operation.as_ref().ok_or(WorkerV3Error::Invalid)?;
        let (result, outcome, exit) = match operation {
            internal_worker_request::Operation::Initialise(initialise) => {
                let route_context_id = context_id(&initialise.route_context_id)?;
                if context.is_none() && route_context_id == bound_context {
                    context = Some(route_context_id);
                    (
                        InternalWorkerResult::Ok,
                        Some(internal_worker_response::Outcome::Initialised(
                            ContextInitialised {
                                route_context_id: route_context_id.to_vec(),
                            },
                        )),
                        false,
                    )
                } else {
                    (InternalWorkerResult::Conflict, None, false)
                }
            }
            internal_worker_request::Operation::DestroyContext(destroy) => {
                let route_context_id = context_id(&destroy.route_context_id)?;
                if context == Some(route_context_id) {
                    context = None;
                    (
                        InternalWorkerResult::Ok,
                        Some(internal_worker_response::Outcome::Destroyed(
                            ContextDestroyed {},
                        )),
                        true,
                    )
                } else {
                    (InternalWorkerResult::NotFound, None, false)
                }
            }
            _ => (InternalWorkerResult::Invalid, None, false),
        };
        let response = correlated_response(&request, result, outcome)?;
        send_credential_worker_response(channel, &request, &response, None)?;
        if exit {
            return Ok(());
        }
    }
}

fn correlated_response(
    request: &InternalWorkerRequest,
    result: InternalWorkerResult,
    outcome: Option<internal_worker_response::Outcome>,
) -> Result<InternalWorkerResponse, WorkerV3Error> {
    let encoded = encode_request(request).map_err(|_| WorkerV3Error::Invalid)?;
    let response = InternalWorkerResponse {
        protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
        magic: INTERNAL_WORKER_MAGIC.to_vec(),
        request_id: request.request_id.clone(),
        result: result as i32,
        request_digest: blake3::hash(encoded.as_slice()).as_bytes().to_vec(),
        outcome,
    };
    validate_response_for_request(request, &response).map_err(|_| WorkerV3Error::Invalid)?;
    Ok(response)
}

fn context_id(bytes: &[u8]) -> Result<ContextId, WorkerV3Error> {
    let value: ContextId = bytes.try_into().map_err(|_| WorkerV3Error::Invalid)?;
    if value.iter().all(|byte| *byte == 0) {
        return Err(WorkerV3Error::Invalid);
    }
    Ok(value)
}

fn request_context(request: &InternalWorkerRequest) -> Result<ContextId, WorkerV3Error> {
    use internal_worker_request::Operation;

    let bytes = match request.operation.as_ref().ok_or(WorkerV3Error::Invalid)? {
        Operation::Initialise(value) => &value.route_context_id,
        Operation::PrepareLeases(value) => &value.route_context_id,
        Operation::ActivateLeases(value) => &value.route_context_id,
        Operation::ProbeCommitLeases(value) => &value.route_context_id,
        Operation::AddMptcpEndpoint(value) => &value.route_context_id,
        Operation::RemoveMptcpEndpoint(value) => &value.route_context_id,
        Operation::AcquireTransportSocket(value) => &value.route_context_id,
        Operation::DestroyContext(value) => &value.route_context_id,
    };
    context_id(bytes)
}

fn nix_io(error: Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

fn rustix_io(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

enum WorkerLifetime {
    Child(Mutex<Option<Child>>),
    #[cfg(test)]
    Fake {
        termination_results: Mutex<VecDeque<TerminationOutcome>>,
        default_result: TerminationOutcome,
        attempts: Arc<AtomicUsize>,
        termination_delay: Duration,
        probe_delay: Duration,
    },
}

impl WorkerLifetime {
    fn child_slot(&self) -> &Mutex<Option<Child>> {
        match self {
            Self::Child(child) => child,
            #[cfg(test)]
            Self::Fake { .. } => std::process::abort(),
        }
    }
}

#[cfg(test)]
#[derive(Clone, Copy, Default)]
struct FakeWorkerDelays {
    termination: Duration,
    probe: Duration,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ChildWaitObservation {
    Reaped,
    Running,
    Fatal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum TerminationOutcome {
    Reaped,
    TimedOut,
    Fatal,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RetirementEscalationAction {
    Complete,
    Requeue,
    Abort,
}

fn classify_child_wait(
    result: &io::Result<Option<std::process::ExitStatus>>,
) -> ChildWaitObservation {
    match result {
        Ok(Some(_)) => ChildWaitObservation::Reaped,
        Ok(None) => ChildWaitObservation::Running,
        Err(_) => ChildWaitObservation::Fatal,
    }
}

const fn outcome_after_kill_error(observation: ChildWaitObservation) -> TerminationOutcome {
    match observation {
        ChildWaitObservation::Reaped => TerminationOutcome::Reaped,
        ChildWaitObservation::Running | ChildWaitObservation::Fatal => TerminationOutcome::Fatal,
    }
}

const fn retirement_escalation_action(outcome: TerminationOutcome) -> RetirementEscalationAction {
    match outcome {
        TerminationOutcome::Reaped => RetirementEscalationAction::Complete,
        TerminationOutcome::TimedOut => RetirementEscalationAction::Requeue,
        TerminationOutcome::Fatal => RetirementEscalationAction::Abort,
    }
}

fn enforce_termination_outcome(outcome: TerminationOutcome) -> bool {
    match outcome {
        TerminationOutcome::Reaped => true,
        TerminationOutcome::TimedOut => false,
        TerminationOutcome::Fatal => std::process::abort(),
    }
}

#[must_use = "a worker process must be registered or explicitly retired"]
struct WorkerProcess {
    child_pid: u32,
    binding: Option<(ContextId, u64)>,
    expected_peer: ExpectedUnixCredentials,
    channel: Socket,
    lifetime: Arc<WorkerLifetime>,
    alive_hint: Arc<AtomicBool>,
    retirement: Mutex<Option<ProcessRetirement>>,
}

#[derive(Clone)]
struct WorkerLiveness {
    lifetime: Arc<WorkerLifetime>,
    alive_hint: Arc<AtomicBool>,
}

/// Linear retirement ownership for the exact worker leader only.
///
/// Before the namespace-pin acknowledgement, the production bootstrap installs the structurally
/// fixed seccomp filter and proves that filter mode/count increased by one. The filter monotonically
/// returns `EPERM` for later `clone`, `clone3`, `fork`, `vfork`, `setns`, and `unshare` calls,
/// including after exec. This does not independently attest descendant absence before filter
/// installation.
#[must_use = "process retirement ownership must be confirmed or transferred to the reaper"]
struct ProcessRetirement {
    liveness: WorkerLiveness,
    permit: Option<ReaperPermit>,
    kernel_pins: Option<crate::worker_sandbox::WorkerKernelPins>,
    armed: bool,
}

impl ProcessRetirement {
    fn termination_outcome(&mut self, timeout: Duration) -> TerminationOutcome {
        let outcome = self.liveness.termination_outcome(timeout);
        if outcome == TerminationOutcome::Reaped {
            self.confirm_reaped();
        }
        outcome
    }

    fn terminate_bounded(&mut self, timeout: Duration) -> bool {
        enforce_termination_outcome(self.termination_outcome(timeout))
    }

    fn confirm_reaped(&mut self) {
        self.armed = false;
        drop(self.kernel_pins.take());
    }
}

impl Drop for ProcessRetirement {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        let Some(permit) = self.permit.take() else {
            std::process::abort();
        };
        let kernel_pins = self.kernel_pins.take();
        self.armed = false;
        escalate_retirement(Self {
            liveness: self.liveness.clone(),
            permit: Some(permit),
            kernel_pins,
            armed: true,
        });
    }
}

struct RetirementEscalation {
    queue: Mutex<VecDeque<ProcessRetirement>>,
    available_permits: Mutex<usize>,
    ready: Condvar,
}

impl RetirementEscalation {
    fn state() -> Arc<Self> {
        Arc::new(Self {
            queue: Mutex::new(VecDeque::with_capacity(MAX_PROCESS_OWNERS)),
            available_permits: Mutex::new(MAX_PROCESS_OWNERS),
            ready: Condvar::new(),
        })
    }

    fn new() -> io::Result<Arc<Self>> {
        let escalation = Self::state();
        let reaper = Arc::clone(&escalation);
        let handle = thread::Builder::new()
            .name("volparossa-worker-reaper".to_owned())
            .spawn(move || {
                let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| reaper.run()));
                std::process::abort();
            })?;
        drop(handle);
        Ok(escalation)
    }

    fn try_acquire(self: &Arc<Self>) -> Option<ReaperPermit> {
        let mut available = self
            .available_permits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *available == 0 {
            return None;
        }
        *available -= 1;
        Some(ReaperPermit {
            escalation: Arc::downgrade(self),
        })
    }

    fn enqueue(&self, retirement: ProcessRetirement) {
        if retirement
            .permit
            .as_ref()
            .map(|permit| permit.escalation.as_ptr())
            != Some(std::ptr::from_ref(self))
        {
            std::process::abort();
        }
        let mut queue = self
            .queue
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if queue.len() >= MAX_PROCESS_OWNERS {
            std::process::abort();
        }
        queue.push_back(retirement);
        drop(queue);
        self.ready.notify_one();
    }

    fn run(&self) {
        loop {
            let mut retirement = {
                let mut queue = self
                    .queue
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                while queue.is_empty() {
                    queue = self
                        .ready
                        .wait(queue)
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                }
                let Some(retirement) = queue.pop_front() else {
                    continue;
                };
                retirement
            };
            match retirement_escalation_action(retirement.termination_outcome(TERMINATION_TIMEOUT))
            {
                RetirementEscalationAction::Complete => {}
                RetirementEscalationAction::Requeue => {
                    thread::sleep(TERMINATION_POLL_INTERVAL);
                    self.enqueue(retirement);
                }
                RetirementEscalationAction::Abort => std::process::abort(),
            }
        }
    }

    #[cfg(test)]
    fn drain_for_test(&self) -> VecDeque<ProcessRetirement> {
        std::mem::take(
            &mut *self
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
        )
    }
}

struct ReaperPermit {
    escalation: std::sync::Weak<RetirementEscalation>,
}

impl Drop for ReaperPermit {
    fn drop(&mut self) {
        let Some(escalation) = self.escalation.upgrade() else {
            std::process::abort();
        };
        let mut available = escalation
            .available_permits
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if *available >= MAX_PROCESS_OWNERS {
            std::process::abort();
        }
        *available += 1;
    }
}

fn retirement_escalation() -> Result<Arc<RetirementEscalation>, WorkerV3Error> {
    static ESCALATION: OnceLock<Option<Arc<RetirementEscalation>>> = OnceLock::new();
    ESCALATION
        .get_or_init(|| RetirementEscalation::new().ok())
        .clone()
        .ok_or_else(|| WorkerV3Error::Io(io::Error::other("worker reaper failed to start")))
}

fn acquire_retirement_permit() -> Result<ReaperPermit, WorkerV3Error> {
    retirement_escalation()?
        .try_acquire()
        .ok_or(WorkerV3Error::Capacity)
}

fn escalate_retirement(retirement: ProcessRetirement) {
    let Some(escalation) = retirement
        .permit
        .as_ref()
        .and_then(|permit| permit.escalation.upgrade())
    else {
        std::process::abort();
    };
    escalation.enqueue(retirement);
}

impl WorkerLiveness {
    fn known_alive(&self) -> bool {
        self.alive_hint.load(Ordering::SeqCst)
    }

    /// Performs the potentially blocking child-status probe outside the registry mutex.
    fn probe_alive(&self) -> bool {
        if !self.known_alive() {
            return false;
        }
        match self.lifetime.as_ref() {
            WorkerLifetime::Child(child) => {
                let Ok(mut child) = child.lock() else {
                    return false;
                };
                let Some(process) = child.as_mut() else {
                    self.alive_hint.store(false, Ordering::SeqCst);
                    return false;
                };
                match classify_child_wait(&process.try_wait()) {
                    ChildWaitObservation::Reaped => {
                        *child = None;
                        self.alive_hint.store(false, Ordering::SeqCst);
                        false
                    }
                    ChildWaitObservation::Running => true,
                    ChildWaitObservation::Fatal => false,
                }
            }
            #[cfg(test)]
            WorkerLifetime::Fake { .. } => self.known_alive(),
        }
    }

    /// Probe liveness without waiting past the caller's absolute transaction deadline.
    fn probe_alive_until(&self, deadline: HardDeadline) -> Result<bool, WorkerV3Error> {
        ensure_worker_deadline(deadline)?;
        if !self.known_alive() {
            return Ok(false);
        }
        match self.lifetime.as_ref() {
            WorkerLifetime::Child(child) => loop {
                ensure_worker_deadline(deadline)?;
                match child.try_lock() {
                    Ok(mut child) => {
                        let Some(process) = child.as_mut() else {
                            self.alive_hint.store(false, Ordering::SeqCst);
                            return Ok(false);
                        };
                        let alive = match classify_child_wait(&process.try_wait()) {
                            ChildWaitObservation::Reaped => {
                                *child = None;
                                self.alive_hint.store(false, Ordering::SeqCst);
                                false
                            }
                            ChildWaitObservation::Running => true,
                            ChildWaitObservation::Fatal => false,
                        };
                        ensure_worker_deadline(deadline)?;
                        return Ok(alive);
                    }
                    Err(std::sync::TryLockError::WouldBlock) => {
                        let remaining = deadline.remaining().map_err(|error| {
                            if error.kind() == io::ErrorKind::TimedOut {
                                WorkerV3Error::Deadline
                            } else {
                                WorkerV3Error::Io(error)
                            }
                        })?;
                        thread::sleep(remaining.min(TERMINATION_POLL_INTERVAL));
                    }
                    Err(std::sync::TryLockError::Poisoned(_)) => return Ok(false),
                }
            },
            #[cfg(test)]
            WorkerLifetime::Fake { probe_delay, .. } => {
                thread::sleep(*probe_delay);
                ensure_worker_deadline(deadline)?;
                Ok(self.known_alive())
            }
        }
    }

    /// Requests termination and proves reaping within one fixed bound.
    ///
    /// This is called only for an unregistered launch failure or after the owning process
    /// record is detached from the registry.
    fn termination_outcome(&self, timeout: Duration) -> TerminationOutcome {
        match self.lifetime.as_ref() {
            WorkerLifetime::Child(child) => {
                let Ok(mut child) = child.lock() else {
                    return TerminationOutcome::Fatal;
                };
                let Some(process) = child.as_mut() else {
                    self.alive_hint.store(false, Ordering::SeqCst);
                    return TerminationOutcome::Reaped;
                };
                match classify_child_wait(&process.try_wait()) {
                    ChildWaitObservation::Reaped => {
                        *child = None;
                        self.alive_hint.store(false, Ordering::SeqCst);
                        return TerminationOutcome::Reaped;
                    }
                    ChildWaitObservation::Running => {}
                    ChildWaitObservation::Fatal => return TerminationOutcome::Fatal,
                }

                if process.kill().is_err() {
                    let outcome =
                        outcome_after_kill_error(classify_child_wait(&process.try_wait()));
                    if outcome == TerminationOutcome::Reaped {
                        *child = None;
                        self.alive_hint.store(false, Ordering::SeqCst);
                    }
                    return outcome;
                }
                let Some(deadline) = Instant::now().checked_add(timeout) else {
                    return TerminationOutcome::Fatal;
                };
                loop {
                    match classify_child_wait(&process.try_wait()) {
                        ChildWaitObservation::Reaped => {
                            *child = None;
                            self.alive_hint.store(false, Ordering::SeqCst);
                            return TerminationOutcome::Reaped;
                        }
                        ChildWaitObservation::Running => {}
                        ChildWaitObservation::Fatal => return TerminationOutcome::Fatal,
                    }
                    let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                        return TerminationOutcome::TimedOut;
                    };
                    if remaining.is_zero() {
                        return TerminationOutcome::TimedOut;
                    }
                    thread::sleep(remaining.min(TERMINATION_POLL_INTERVAL));
                }
            }
            #[cfg(test)]
            WorkerLifetime::Fake {
                termination_results,
                default_result,
                attempts,
                termination_delay: _,
                probe_delay: _,
            } => {
                let outcome = termination_results
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .pop_front()
                    .unwrap_or(*default_result);
                if outcome == TerminationOutcome::Reaped {
                    self.alive_hint.store(false, Ordering::SeqCst);
                }
                attempts.fetch_add(1, Ordering::SeqCst);
                outcome
            }
        }
    }

    fn terminate_bounded(&self, timeout: Duration) -> bool {
        enforce_termination_outcome(self.termination_outcome(timeout))
    }

    fn termination_outcome_until(&self, deadline: HardDeadline) -> TerminationOutcome {
        if deadline.ensure_remaining().is_err() {
            return TerminationOutcome::TimedOut;
        }
        match self.lifetime.as_ref() {
            WorkerLifetime::Child(child) => self.child_termination_outcome_until(child, deadline),
            #[cfg(test)]
            WorkerLifetime::Fake {
                termination_results,
                default_result,
                attempts,
                termination_delay,
                probe_delay: _,
            } => {
                let outcome = termination_results
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .pop_front()
                    .unwrap_or(*default_result);
                attempts.fetch_add(1, Ordering::SeqCst);
                thread::sleep(*termination_delay);
                if outcome == TerminationOutcome::Reaped {
                    self.alive_hint.store(false, Ordering::SeqCst);
                }
                if outcome == TerminationOutcome::Fatal {
                    TerminationOutcome::Fatal
                } else if deadline.ensure_remaining().is_err() {
                    TerminationOutcome::TimedOut
                } else {
                    outcome
                }
            }
        }
    }

    fn child_termination_outcome_until(
        &self,
        child: &Mutex<Option<Child>>,
        deadline: HardDeadline,
    ) -> TerminationOutcome {
        let mut child = loop {
            if deadline.ensure_remaining().is_err() {
                return TerminationOutcome::TimedOut;
            }
            match child.try_lock() {
                Ok(child) => break child,
                Err(std::sync::TryLockError::Poisoned(_)) => return TerminationOutcome::Fatal,
                Err(std::sync::TryLockError::WouldBlock) => {
                    let Ok(remaining) = deadline.remaining() else {
                        return TerminationOutcome::TimedOut;
                    };
                    thread::sleep(remaining.min(TERMINATION_POLL_INTERVAL));
                }
            }
        };
        let Some(process) = child.as_mut() else {
            self.alive_hint.store(false, Ordering::SeqCst);
            return if deadline.ensure_remaining().is_ok() {
                TerminationOutcome::Reaped
            } else {
                TerminationOutcome::TimedOut
            };
        };
        match classify_child_wait(&process.try_wait()) {
            ChildWaitObservation::Reaped => {
                *child = None;
                self.alive_hint.store(false, Ordering::SeqCst);
                return if deadline.ensure_remaining().is_ok() {
                    TerminationOutcome::Reaped
                } else {
                    TerminationOutcome::TimedOut
                };
            }
            ChildWaitObservation::Running => {}
            ChildWaitObservation::Fatal => return TerminationOutcome::Fatal,
        }
        if deadline.ensure_remaining().is_err() {
            return TerminationOutcome::TimedOut;
        }
        if process.kill().is_err() {
            let outcome = outcome_after_kill_error(classify_child_wait(&process.try_wait()));
            if outcome == TerminationOutcome::Reaped {
                *child = None;
                self.alive_hint.store(false, Ordering::SeqCst);
            }
            return if outcome == TerminationOutcome::Fatal {
                TerminationOutcome::Fatal
            } else if deadline.ensure_remaining().is_ok() {
                outcome
            } else {
                TerminationOutcome::TimedOut
            };
        }
        loop {
            if deadline.ensure_remaining().is_err() {
                return TerminationOutcome::TimedOut;
            }
            match classify_child_wait(&process.try_wait()) {
                ChildWaitObservation::Reaped => {
                    *child = None;
                    self.alive_hint.store(false, Ordering::SeqCst);
                    return if deadline.ensure_remaining().is_ok() {
                        TerminationOutcome::Reaped
                    } else {
                        TerminationOutcome::TimedOut
                    };
                }
                ChildWaitObservation::Running => {}
                ChildWaitObservation::Fatal => return TerminationOutcome::Fatal,
            }
            let Ok(remaining) = deadline.remaining() else {
                return TerminationOutcome::TimedOut;
            };
            thread::sleep(remaining.min(TERMINATION_POLL_INTERVAL));
        }
    }
}

impl WorkerProcess {
    fn liveness(&self) -> WorkerLiveness {
        WorkerLiveness {
            lifetime: Arc::clone(&self.lifetime),
            alive_hint: Arc::clone(&self.alive_hint),
        }
    }

    fn probe_alive(&self) -> bool {
        self.liveness().probe_alive()
    }

    fn terminate_bounded(&self, timeout: Duration) -> bool {
        let confirmed = self.liveness().terminate_bounded(timeout);
        if confirmed {
            self.disarm_retirement();
        }
        confirmed
    }

    fn pin_worker_network_namespace_before_identity_drop(
        &self,
        sandbox_observation: CapturedSandboxObservation,
        required_group: u32,
        parent_pid: u32,
        child_pid: u32,
    ) -> Result<(), WorkerV3Error> {
        let mut retirement = self
            .retirement
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let retirement = retirement.as_mut().ok_or(WorkerV3Error::Authentication)?;
        let pins = retirement
            .kernel_pins
            .as_mut()
            .ok_or(WorkerV3Error::Authentication)?;
        sandbox_observation.pin_network_namespace_before_identity_drop(
            pins,
            required_group,
            parent_pid,
            child_pid,
        )
    }

    fn observe_and_pin_sandbox(
        &self,
        sandbox_observation: CapturedSandboxObservation,
        parent_pid: u32,
        child_pid: u32,
        identity: crate::worker_sandbox::WorkerIdentity,
    ) -> Result<crate::worker_sandbox::WorkerSandboxSnapshot, WorkerV3Error> {
        let mut retirement = self
            .retirement
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let retirement = retirement.as_mut().ok_or(WorkerV3Error::Authentication)?;
        let pins = retirement
            .kernel_pins
            .as_mut()
            .ok_or(WorkerV3Error::Authentication)?;
        sandbox_observation.observe(pins, parent_pid, child_pid, identity)
    }

    fn ensure_pinned_child_alive(&self) -> Result<(), WorkerV3Error> {
        let retirement = self
            .retirement
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let pins = retirement
            .as_ref()
            .and_then(|retirement| retirement.kernel_pins.as_ref())
            .ok_or(WorkerV3Error::Authentication)?;
        pins.ensure_alive()?;
        Ok(())
    }

    fn has_complete_kernel_pins(&self) -> bool {
        self.retirement
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
            .and_then(|retirement| retirement.kernel_pins.as_ref())
            .is_some_and(crate::worker_sandbox::WorkerKernelPins::has_complete_pins)
    }

    fn retirement_released_after_confirmed_reap(&self) -> bool {
        self.retirement
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .is_none()
    }

    fn take_retirement(&self) -> Option<ProcessRetirement> {
        self.retirement
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take()
    }

    fn disarm_retirement(&self) {
        if let Some(mut retirement) = self.take_retirement() {
            retirement.confirm_reaped();
        }
    }

    fn disarm_retirement_for_shutdown(&self, deadline: HardDeadline) -> Result<(), WorkerV3Error> {
        let mut owner = match self.retirement.try_lock() {
            Ok(owner) => owner,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => return Err(WorkerV3Error::Deadline),
        };
        ensure_worker_deadline(deadline)?;
        let Some(retirement) = owner.as_mut() else {
            return Err(WorkerV3Error::Stale);
        };
        retirement.confirm_reaped();
        *owner = None;
        Ok(())
    }

    fn transfer_retirement_to_reaper(&self) {
        if let Some(retirement) = self.take_retirement() {
            escalate_retirement(retirement);
        }
    }

    fn clone_channel(&self) -> Result<Socket, WorkerV3Error> {
        Ok(self.channel.try_clone()?)
    }

    fn duplicate_network_namespace_pin(
        &self,
        deadline: HardDeadline,
    ) -> Result<crate::worker_sandbox::PinnedWorkerNetworkNamespace, WorkerV3Error> {
        ensure_worker_deadline(deadline)?;
        let retirement = match self.retirement.try_lock() {
            Ok(retirement) => retirement,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                ensure_worker_deadline(deadline)?;
                return Err(WorkerV3Error::Ambiguous);
            }
        };
        ensure_worker_deadline(deadline)?;
        let pins = retirement
            .as_ref()
            .and_then(|retirement| retirement.kernel_pins.as_ref())
            .ok_or(WorkerV3Error::Authentication)?;
        let duplicate = pins.duplicate_network_namespace_pin()?;
        ensure_worker_deadline(deadline)?;
        Ok(duplicate)
    }

    fn duplicate_recovery_identity_source_until(
        &self,
        coordinates: WorkerGenerationCoordinates,
        deadline: HardDeadline,
    ) -> Result<PendingWorkerRecoveryIdentity, WorkerV3Error> {
        ensure_worker_deadline(deadline)?;
        let expected_binding = (coordinates.context_id, coordinates.worker_generation.get());
        if self.binding != Some(expected_binding) {
            return Err(WorkerV3Error::Stale);
        }
        let retirement = match self.retirement.try_lock() {
            Ok(retirement) => retirement,
            Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
            Err(std::sync::TryLockError::WouldBlock) => {
                ensure_worker_deadline(deadline)?;
                return Err(WorkerV3Error::Ambiguous);
            }
        };
        ensure_worker_deadline(deadline)?;
        let pins = retirement
            .as_ref()
            .and_then(|retirement| retirement.kernel_pins.as_ref())
            .ok_or(WorkerV3Error::Authentication)?;
        let authenticated_pins = pins.duplicate_recovery_identity_pins()?;
        ensure_worker_deadline(deadline)?;
        let expected_child_pid =
            NonZeroU32::new(self.child_pid).ok_or(WorkerV3Error::Authentication)?;
        Ok(PendingWorkerRecoveryIdentity {
            coordinates,
            expected_child_pid,
            process_identity: Arc::clone(&self.lifetime),
            authenticated_pins,
        })
    }

    #[cfg(test)]
    fn fake(channel: Socket, child_pid: u32, alive: Arc<AtomicBool>) -> Self {
        Self::fake_with_termination(channel, child_pid, alive, true)
    }

    #[cfg(test)]
    fn fake_with_termination(
        channel: Socket,
        child_pid: u32,
        alive: Arc<AtomicBool>,
        termination_confirmed: bool,
    ) -> Self {
        Self::fake_with_termination_results(
            channel,
            child_pid,
            alive,
            VecDeque::new(),
            termination_confirmed,
            Arc::new(AtomicUsize::new(0)),
        )
    }

    #[cfg(test)]
    fn fake_with_termination_results(
        channel: Socket,
        child_pid: u32,
        alive: Arc<AtomicBool>,
        termination_results: VecDeque<bool>,
        default_result: bool,
        attempts: Arc<AtomicUsize>,
    ) -> Self {
        Self::fake_with_delayed_termination_results(
            channel,
            child_pid,
            alive,
            termination_results,
            default_result,
            attempts,
            FakeWorkerDelays::default(),
        )
    }

    #[cfg(test)]
    fn fake_with_delayed_termination_results(
        channel: Socket,
        child_pid: u32,
        alive: Arc<AtomicBool>,
        termination_results: VecDeque<bool>,
        default_result: bool,
        attempts: Arc<AtomicUsize>,
        delays: FakeWorkerDelays,
    ) -> Self {
        let lifetime = Arc::new(WorkerLifetime::Fake {
            termination_results: Mutex::new(
                termination_results
                    .into_iter()
                    .map(|confirmed| {
                        if confirmed {
                            TerminationOutcome::Reaped
                        } else {
                            TerminationOutcome::TimedOut
                        }
                    })
                    .collect(),
            ),
            default_result: if default_result {
                TerminationOutcome::Reaped
            } else {
                TerminationOutcome::TimedOut
            },
            attempts,
            termination_delay: delays.termination,
            probe_delay: delays.probe,
        });
        let retirement = ProcessRetirement {
            liveness: WorkerLiveness {
                lifetime: Arc::clone(&lifetime),
                alive_hint: Arc::clone(&alive),
            },
            permit: Some(acquire_retirement_permit().expect("test process retirement permit")),
            kernel_pins: Some(crate::worker_sandbox::WorkerKernelPins::fixture()),
            armed: true,
        };
        Self {
            child_pid,
            binding: None,
            expected_peer: ExpectedUnixCredentials::new(
                std::process::id(),
                geteuid().as_raw(),
                getegid().as_raw(),
            )
            .expect("current test process credentials"),
            channel,
            lifetime,
            alive_hint: alive,
            retirement: Mutex::new(Some(retirement)),
        }
    }
}

impl Drop for WorkerProcess {
    fn drop(&mut self) {
        self.transfer_retirement_to_reaper();
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum StablePhase {
    Starting,
    Initialised,
    Prepared,
    Activated,
    Committed,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum VisiblePhase {
    Stable(StablePhase),
    DurableHandoffPending,
    InFlight,
    Quarantined,
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct CacheKey {
    context_id: ContextId,
    generation: u64,
    request_id: [u8; 16],
    request_digest: [u8; 32],
}

#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq)]
struct TombstoneKey {
    context_id: ContextId,
    generation: u64,
    request_id: [u8; 16],
}

#[derive(Clone, Copy)]
struct Tombstone {
    request_digest: [u8; 32],
    expires_at: Instant,
}

#[derive(Clone)]
struct CacheEntry {
    response: InternalWorkerResponse,
    expires_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct InFlight {
    key: CacheKey,
    prior_phase: StablePhase,
    success_phase: StablePhase,
    terminal: bool,
    deadline: HardDeadline,
}

#[cfg(test)]
#[derive(Clone)]
struct FinishCommitHook {
    reached: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum WorkerDispatchFence {
    Open,
    DurableHandoffPending,
}

impl std::fmt::Debug for WorkerDispatchFence {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Open => formatter.write_str("Open"),
            Self::DurableHandoffPending => formatter.write_str("DurableHandoffPending"),
        }
    }
}

#[must_use = "the exact pending dispatch fence must remain paired with its worker owner"]
struct DurableHandoffFenceOwner {
    coordinates: WorkerGenerationCoordinates,
}

impl std::fmt::Debug for DurableHandoffFenceOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DurableHandoffFenceOwner(<redacted>)")
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum WorkerDispatchRegistration {
    Open,
    DurableHandoffPending,
}

struct WorkerRecord {
    generation: u64,
    dispatch_fence: WorkerDispatchFence,
    stable_phase: StablePhase,
    in_flight: Option<InFlight>,
    quarantined: bool,
    expires_at: Instant,
    alive_hint: Arc<AtomicBool>,
    process: Option<WorkerProcess>,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PlanToken {
    context_id: ContextId,
    generation: u64,
    in_flight: InFlight,
}

struct PlannedCall {
    token: PlanToken,
    channel: Socket,
    liveness: WorkerLiveness,
    expected_peer: ExpectedUnixCredentials,
    pinned_network_namespace: Option<crate::worker_sandbox::PinnedWorkerNetworkNamespace>,
}

struct CachedCall {
    token: CacheKey,
    response: InternalWorkerResponse,
    liveness: WorkerLiveness,
    deadline: HardDeadline,
}

enum RegistryPlan {
    Cached(CachedCall),
    Call(PlannedCall),
}

#[must_use = "detached worker ownership must be retired or reattached by a supervisor"]
struct DetachedWorker {
    context_id: ContextId,
    generation: u64,
    process: WorkerProcess,
}

impl DetachedWorker {
    fn escalate_to_reaper(self) {
        self.process.transfer_retirement_to_reaper();
    }
}

#[must_use = "finish outcomes can carry detached worker retirement ownership"]
enum FinishOutcome {
    Committed,
    Terminal(DetachedWorker),
    Rejected {
        error: WorkerV3Error,
        detached: Option<DetachedWorker>,
    },
}

#[must_use = "registration failure returns worker process ownership for explicit retirement"]
struct RegistrationFailure {
    error: WorkerV3Error,
    process: Box<WorkerProcess>,
    reservation: Option<GenerationReservation>,
}

impl std::fmt::Debug for RegistrationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("RegistrationFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

#[must_use = "reattach failure returns detached worker retirement ownership"]
struct ReattachFailure {
    error: WorkerV3Error,
    detached: Box<DetachedWorker>,
}

struct BootstrapChallenge([u8; 32]);

impl BootstrapChallenge {
    #[cfg(test)]
    fn into_bytes(self) -> [u8; 32] {
        self.0
    }
}

#[must_use = "authenticated worker ownership must be registered or explicitly retired"]
struct AuthenticatedWorker {
    process: WorkerProcess,
    bootstrap_challenge: BootstrapChallenge,
}

#[must_use = "spawned worker ownership must be committed or explicitly retired"]
struct SpawnedWorker {
    reservation: GenerationReservation,
    process: WorkerProcess,
    bootstrap_challenge: BootstrapChallenge,
}

#[must_use = "spawn failure returns the generation reservation for exact abandon"]
struct WorkerSpawnFailure {
    error: WorkerV3Error,
    reservation: GenerationReservation,
}

impl std::fmt::Debug for WorkerSpawnFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerSpawnFailure")
            .field("error", &self.error)
            .field("reservation", &self.reservation)
            .finish()
    }
}

#[derive(Debug, Eq, PartialEq)]
struct LinearReservationToken;

#[derive(Debug, Eq, PartialEq)]
struct GenerationReservation {
    context_id: ContextId,
    generation: u64,
    expires_at: Instant,
    linear: LinearReservationToken,
}

impl GenerationReservation {
    fn binding(&self) -> (ContextId, u64) {
        (self.context_id, self.generation)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct WorkerGenerationCoordinates {
    context_id: ContextId,
    worker_generation: NonZeroU64,
}

enum WorkerGenerationPlacement {
    LifecycleReservation(GenerationReservation),
    SpawnAmbiguous(GenerationReservation),
    Spawned(Box<SpawnedWorker>),
    Registered,
    Detached(Box<LifecycleDetachedOwnership>),
    ReapedPendingPurge(Box<LifecycleDetachedOwnership>),
}

#[must_use = "detached lifecycle ownership must retain both process and pending reservation"]
struct LifecycleDetachedOwnership {
    worker: DetachedWorker,
    reservation: Option<GenerationReservation>,
}

/// Affine authority for one coordinator-owned worker generation.
///
/// `worker_generation` is allocated by `WorkerRegistry`; it is deliberately not accepted from an
/// engine/backend generation. A retained detached placement owns the exact process retirement
/// pins and can therefore be retried after a bounded, ambiguous reap attempt.
#[must_use = "worker generation ownership must be reaped or remain fail-closed in the coordinator"]
struct WorkerGenerationOwnership {
    registry: Arc<Mutex<WorkerRegistry>>,
    coordinates: WorkerGenerationCoordinates,
    dispatch_registration: WorkerDispatchRegistration,
    handoff_fence: Option<DurableHandoffFenceOwner>,
    placement: Option<WorkerGenerationPlacement>,
}

impl WorkerGenerationOwnership {
    fn has_valid_dispatch_fence_shape(&self) -> bool {
        match (
            self.dispatch_registration,
            self.handoff_fence.as_ref(),
            self.placement.as_ref(),
        ) {
            (WorkerDispatchRegistration::Open, None, Some(_))
            | (
                WorkerDispatchRegistration::DurableHandoffPending,
                None,
                Some(
                    WorkerGenerationPlacement::LifecycleReservation(_)
                    | WorkerGenerationPlacement::SpawnAmbiguous(_)
                    | WorkerGenerationPlacement::Spawned(_),
                ),
            ) => true,
            (
                WorkerDispatchRegistration::DurableHandoffPending,
                None,
                Some(
                    WorkerGenerationPlacement::Detached(detached)
                    | WorkerGenerationPlacement::ReapedPendingPurge(detached),
                ),
            ) => detached.reservation.is_some(),
            (
                WorkerDispatchRegistration::DurableHandoffPending,
                Some(fence),
                Some(WorkerGenerationPlacement::Registered),
            ) => fence.coordinates == self.coordinates,
            (
                WorkerDispatchRegistration::DurableHandoffPending,
                Some(fence),
                Some(
                    WorkerGenerationPlacement::Detached(detached)
                    | WorkerGenerationPlacement::ReapedPendingPurge(detached),
                ),
            ) => detached.reservation.is_none() && fence.coordinates == self.coordinates,
            _ => false,
        }
    }
}

impl std::fmt::Debug for WorkerGenerationOwnership {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("WorkerGenerationOwnership")
            .field("worker_generation", &self.coordinates.worker_generation)
            .field("dispatch_registration", &self.dispatch_registration)
            .field(
                "handoff_fence",
                &self.handoff_fence.as_ref().map(|_| "<redacted>"),
            )
            .field(
                "placement",
                &self.placement.as_ref().map(|placement| match placement {
                    WorkerGenerationPlacement::LifecycleReservation(_) => "reservation",
                    WorkerGenerationPlacement::SpawnAmbiguous(_) => "spawn-ambiguous",
                    WorkerGenerationPlacement::Spawned(_) => "spawned",
                    WorkerGenerationPlacement::Registered => "registered",
                    WorkerGenerationPlacement::Detached(_) => "detached",
                    WorkerGenerationPlacement::ReapedPendingPurge(_) => "reaped-pending-purge",
                }),
            )
            .finish_non_exhaustive()
    }
}

/// Affine source for the recovery coordinates which current authenticated pins actually prove.
///
/// The namespace descriptor remains owned here. The numeric nsfs coordinates must never be used
/// after this value is dropped as though they were independent ownership evidence.
#[must_use = "the authenticated recovery pin must remain alive while its coordinates are used"]
struct PendingWorkerRecoveryIdentity {
    coordinates: WorkerGenerationCoordinates,
    expected_child_pid: NonZeroU32,
    process_identity: Arc<WorkerLifetime>,
    authenticated_pins: crate::worker_sandbox::PinnedWorkerRecoveryIdentity,
}

/// Affine source whose complete durable anchor was proven before final registry revalidation.
#[must_use = "the authenticated recovery pin must remain alive during durable ownership handoff"]
struct WorkerRecoveryIdentitySource {
    pending: PendingWorkerRecoveryIdentity,
    durable_prepare_anchor: crate::ownership_journal::DurablePrepareAnchor,
    restart_custody: crate::worker_sandbox::PinnedWorkerRestartCustody,
}

impl WorkerRecoveryIdentitySource {
    fn durable_prepare_anchor(&self) -> crate::ownership_journal::DurablePrepareAnchor {
        self.durable_prepare_anchor
    }
}

fn durable_prepare_anchor_from_worker_parts(
    parts: crate::worker_sandbox::WorkerRecoveryAnchorParts,
) -> Result<crate::ownership_journal::DurablePrepareAnchor, WorkerV3Error> {
    crate::ownership_journal::durable_prepare_anchor_from_parts(
        crate::ownership_journal::DurablePrepareAnchorParts {
            boot_id: parts.boot_id,
            pid: parts.pid,
            process_start_ticks: parts.process_start_ticks,
            network_namespace_device: parts.network_namespace_device,
            network_namespace_inode: parts.network_namespace_inode,
            executable_device: parts.executable_device,
            executable_inode: parts.executable_inode,
            service_cgroup_inode: parts.service_cgroup_inode,
        },
    )
    .ok_or(WorkerV3Error::Authentication)
}

impl std::fmt::Debug for WorkerRecoveryIdentitySource {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("WorkerRecoveryIdentitySource(<redacted>)")
    }
}

/// The exact registered, passive `Starting` worker paired with its durable Intent authority.
///
/// Neither owner is independently recoverable from this value. In particular, the coordinator's
/// generation is unrelated to the durable journal generation and remains encapsulated in the
/// worker owner.
#[must_use = "durable Intent and registered worker ownership must remain paired"]
struct DurableRegisteredStartingWorker {
    key: DurableOwnershipKey,
    worker: WorkerGenerationOwnership,
}

impl std::fmt::Debug for DurableRegisteredStartingWorker {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DurableRegisteredStartingWorker(<redacted>)")
    }
}

/// Pre-arm handoff retaining the exact, revalidated recovery-pin source.
///
/// Construction is possible only after the registered generation was observed as a passive
/// `Starting` worker both before and after deriving its durable recovery anchor.
#[must_use = "the pre-arm worker handoff must be armed or explicitly retained"]
struct DurableWorkerPrepareHandoff {
    registered: DurableRegisteredStartingWorker,
    source: WorkerRecoveryIdentitySource,
}

impl std::fmt::Debug for DurableWorkerPrepareHandoff {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DurableWorkerPrepareHandoff(<redacted>)")
    }
}

/// Conservative owner of one durable worker custody publication boundary.
///
/// This affine value deliberately retains the original absolute deadline, durable key, registered
/// worker, authenticated recovery pins, pidfd and network-namespace descriptor. Its existence does
/// not prove whether systemd owns the descriptors: a later non-cancellable supervisor must retain
/// this exact owner across publication and reconciliation. There is no transition back to a
/// retryable or definitely-unpublished state.
#[must_use = "durable publication authority must remain retained until exact attestation or reconciliation"]
struct DurableWorkerCustodyPublicationOwner {
    custody_name: crate::systemd_fdstore::CustodyFdName,
    deadline: HardDeadline,
    handoff: DurableWorkerPrepareHandoff,
}

impl std::fmt::Debug for DurableWorkerCustodyPublicationOwner {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DurableWorkerCustodyPublicationOwner(<redacted>)")
    }
}

/// Durable `MayOwnPrepare` authority bound to the exact generation observed passive pre-arm.
///
/// The retained owner and recovery pins preserve identity, not continued presence or liveness.
/// This dormant token keeps dispatch pending, permits no child request and exposes no operation or
/// kernel mutation seam.
#[must_use = "MayOwnPrepare authority and passive worker ownership must remain paired"]
struct DurableWorkerMayOwnPrepare {
    durable: DurableMayOwnPrepare,
    worker: WorkerGenerationOwnership,
    source: WorkerRecoveryIdentitySource,
    custody_name: crate::systemd_fdstore::CustodyFdName,
    attestation: crate::systemd_fdstore::InventoryAttestation,
}

impl std::fmt::Debug for DurableWorkerMayOwnPrepare {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("DurableWorkerMayOwnPrepare(<redacted>)")
    }
}

/// Affine result of the dormant durable-Intent-to-passive-worker handoff.
///
/// Every failure variant returns every owner which exists at that point. A rejected worker
/// admission can prove that no worker owner exists, while an ambiguous admission necessarily
/// retains both the durable key and the coordinator-local generation owner.
#[must_use = "every handoff outcome contains authority which must be settled or retained"]
enum DurableWorkerPrepareOutcome {
    CustodyPublication(DurableWorkerCustodyPublicationOwner),
    RegistrationRetained {
        error: DurableOwnershipError,
        registration: DurableIntentRegistration,
    },
    KeyRetained {
        error: WorkerV3Error,
        key: DurableOwnershipKey,
    },
    WorkerAdmissionRetained {
        error: WorkerV3Error,
        key: DurableOwnershipKey,
        worker: WorkerGenerationOwnership,
    },
    RegisteredWorkerRetained {
        error: WorkerV3Error,
        registered: DurableRegisteredStartingWorker,
    },
    HandoffWorkerRetained {
        error: WorkerV3Error,
        handoff: DurableWorkerPrepareHandoff,
    },
}

impl std::fmt::Debug for DurableWorkerPrepareOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CustodyPublication(_) => formatter.write_str("CustodyPublication(<redacted>)"),
            Self::RegistrationRetained { error, .. } => formatter
                .debug_struct("RegistrationRetained")
                .field("error", error)
                .finish_non_exhaustive(),
            Self::KeyRetained { error, .. } => formatter
                .debug_struct("KeyRetained")
                .field("error", error)
                .finish_non_exhaustive(),
            Self::WorkerAdmissionRetained { error, .. } => formatter
                .debug_struct("WorkerAdmissionRetained")
                .field("error", error)
                .finish_non_exhaustive(),
            Self::RegisteredWorkerRetained { error, .. } => formatter
                .debug_struct("RegisteredWorkerRetained")
                .field("error", error)
                .finish_non_exhaustive(),
            Self::HandoffWorkerRetained { error, .. } => formatter
                .debug_struct("HandoffWorkerRetained")
                .field("error", error)
                .finish_non_exhaustive(),
        }
    }
}

/// Affine result of attempting the only post-attestation transition to `MayOwnPrepare`.
///
/// Evidence validation and worker revalidation failures retain the complete conservative
/// publication owner and the supplied attestation. Durable actor failures reconstruct that same
/// owner around the returned key. Once arming succeeds, the `MayOwn` token retains the exact custody
/// name and inventory attestation, including on the defensive context-mismatch path.
#[must_use = "every post-attestation outcome retains all durable worker and custody authority"]
enum DurableWorkerPostAttestationOutcome {
    MayOwn(DurableWorkerMayOwnPrepare),
    PublicationUnresolved {
        error: WorkerV3Error,
        publication: DurableWorkerCustodyPublicationOwner,
        attestation: crate::systemd_fdstore::InventoryAttestation,
    },
    ArmRetained {
        error: DurableOwnershipError,
        publication: DurableWorkerCustodyPublicationOwner,
        attestation: crate::systemd_fdstore::InventoryAttestation,
    },
    ContextMismatch(DurableWorkerMayOwnPrepare),
}

impl std::fmt::Debug for DurableWorkerPostAttestationOutcome {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::MayOwn(_) => formatter.write_str("MayOwn(<redacted>)"),
            Self::PublicationUnresolved { error, .. } => formatter
                .debug_struct("PublicationUnresolved")
                .field("error", error)
                .finish_non_exhaustive(),
            Self::ArmRetained { error, .. } => formatter
                .debug_struct("ArmRetained")
                .field("error", error)
                .finish_non_exhaustive(),
            Self::ContextMismatch(_) => formatter.write_str("ContextMismatch(<redacted>)"),
        }
    }
}

/// Affine proof that the exact worker generation was reaped and removed from every registry index.
#[must_use = "confirmed absence is the only result which may release durable worker ownership"]
struct ConfirmedWorkerGenerationAbsent {
    coordinates: WorkerGenerationCoordinates,
}

impl std::fmt::Debug for ConfirmedWorkerGenerationAbsent {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ConfirmedWorkerGenerationAbsent")
            .field("worker_generation", &self.coordinates.worker_generation)
            .finish_non_exhaustive()
    }
}

#[must_use = "an ambiguous reap result retains affine worker ownership for an exact retry"]
enum WorkerGenerationReap {
    Confirmed(ConfirmedWorkerGenerationAbsent),
    Retained {
        error: WorkerV3Error,
        ownership: Box<WorkerGenerationOwnership>,
    },
}

#[must_use = "registered worker ownership must be detached, confirmed absent, or retained"]
enum RegisteredGenerationTransition {
    Confirmed(ConfirmedWorkerGenerationAbsent),
    Detached(Box<LifecycleDetachedOwnership>),
    Retained(WorkerV3Error),
}

fn retained_worker_generation(
    error: WorkerV3Error,
    ownership: WorkerGenerationOwnership,
) -> WorkerGenerationReap {
    WorkerGenerationReap::Retained {
        error,
        ownership: Box::new(ownership),
    }
}

#[must_use = "retained lifecycle admission ownership must be settled explicitly"]
enum WorkerLifecycleAdmission {
    Registered(WorkerGenerationOwnership),
    Rejected(WorkerV3Error),
    Retained {
        error: WorkerV3Error,
        ownership: WorkerGenerationOwnership,
    },
}

#[must_use = "retained lifecycle ownership must be retried or remain fail-closed"]
enum WorkerLifecycleSettlement {
    Registered(WorkerGenerationOwnership),
    ConfirmedAbsent(ConfirmedWorkerGenerationAbsent),
    Retained {
        error: WorkerV3Error,
        ownership: WorkerGenerationOwnership,
    },
}

#[must_use = "a successful pending-fence commit returns the unique affine fence owner"]
enum WorkerRegistrationCommit {
    Open(u64),
    DurableHandoffPending {
        generation: u64,
        fence: DurableHandoffFenceOwner,
    },
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PendingGenerationPhase {
    Reserved,
    LifecycleOwned,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PendingGeneration {
    generation: u64,
    expires_at: Instant,
    phase: PendingGenerationPhase,
}

#[must_use = "a populated worker registry requires explicit supervisor shutdown"]
struct WorkerRegistry {
    records: HashMap<ContextId, WorkerRecord>,
    reservations: HashMap<ContextId, PendingGeneration>,
    cache: HashMap<CacheKey, CacheEntry>,
    cache_order: VecDeque<CacheKey>,
    tombstones: HashMap<TombstoneKey, Tombstone>,
    tombstone_order: VecDeque<TombstoneKey>,
    next_generation: u64,
    maximum_workers: usize,
    maximum_cache_entries: usize,
    maximum_ttl: Duration,
    shutting_down: bool,
    #[cfg(test)]
    finish_commit_hook: Option<FinishCommitHook>,
}

impl Default for WorkerRegistry {
    fn default() -> Self {
        Self::new(
            DEFAULT_MAX_WORKERS,
            DEFAULT_MAX_CACHE_ENTRIES,
            DEFAULT_MAX_TTL,
        )
    }
}

impl WorkerRegistry {
    fn new(maximum_workers: usize, maximum_cache_entries: usize, maximum_ttl: Duration) -> Self {
        Self {
            records: HashMap::new(),
            reservations: HashMap::new(),
            cache: HashMap::new(),
            cache_order: VecDeque::new(),
            tombstones: HashMap::new(),
            tombstone_order: VecDeque::new(),
            next_generation: 0,
            maximum_workers,
            maximum_cache_entries,
            maximum_ttl,
            shutting_down: false,
            #[cfg(test)]
            finish_commit_hook: None,
        }
    }

    fn reserve_generation(
        &mut self,
        context_id: ContextId,
        ttl: Duration,
        now: Instant,
    ) -> Result<GenerationReservation, WorkerV3Error> {
        self.expire_reservations(now);
        if self.shutting_down {
            return Err(WorkerV3Error::ShuttingDown);
        }
        if context_id.iter().all(|byte| *byte == 0)
            || ttl.is_zero()
            || ttl > self.maximum_ttl
            || self.maximum_workers == 0
            || self.maximum_cache_entries == 0
        {
            return Err(WorkerV3Error::Invalid);
        }
        if self.records.contains_key(&context_id) || self.reservations.contains_key(&context_id) {
            return Err(WorkerV3Error::Conflict);
        }
        if self
            .records
            .len()
            .checked_add(self.reservations.len())
            .is_none_or(|count| count >= self.maximum_workers)
        {
            return Err(WorkerV3Error::Capacity);
        }
        let Some(generation) = self.next_generation.checked_add(1) else {
            return Err(WorkerV3Error::Capacity);
        };
        let Some(expires_at) = now.checked_add(ttl) else {
            return Err(WorkerV3Error::Invalid);
        };
        self.next_generation = generation;
        self.reservations.insert(
            context_id,
            PendingGeneration {
                generation,
                expires_at,
                phase: PendingGenerationPhase::Reserved,
            },
        );
        Ok(GenerationReservation {
            context_id,
            generation,
            expires_at,
            linear: LinearReservationToken,
        })
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "successful abandonment deliberately consumes the affine reservation token"
    )]
    fn abandon_generation(
        &mut self,
        reservation: GenerationReservation,
    ) -> Result<(), WorkerV3Error> {
        self.abandon_generation_ref(&reservation)
    }

    fn abandon_generation_ref(
        &mut self,
        reservation: &GenerationReservation,
    ) -> Result<(), WorkerV3Error> {
        if self
            .reservations
            .get(&reservation.context_id)
            .is_none_or(|pending| {
                pending.generation != reservation.generation
                    || pending.expires_at != reservation.expires_at
            })
        {
            return Err(WorkerV3Error::Stale);
        }
        self.reservations.remove(&reservation.context_id);
        Ok(())
    }

    fn exact_lifecycle_reservation_present(&self, reservation: &GenerationReservation) -> bool {
        self.reservations
            .get(&reservation.context_id)
            .is_some_and(|pending| {
                pending.generation == reservation.generation
                    && pending.expires_at == reservation.expires_at
                    && pending.phase == PendingGenerationPhase::LifecycleOwned
            })
    }

    fn retain_generation_for_lifecycle(
        &mut self,
        reservation: &GenerationReservation,
    ) -> Result<(), WorkerV3Error> {
        let pending = self
            .reservations
            .get_mut(&reservation.context_id)
            .ok_or(WorkerV3Error::Stale)?;
        if pending.generation != reservation.generation
            || pending.expires_at != reservation.expires_at
            || pending.phase != PendingGenerationPhase::Reserved
        {
            return Err(WorkerV3Error::Stale);
        }
        pending.phase = PendingGenerationPhase::LifecycleOwned;
        Ok(())
    }

    fn commit_reserved_with_dispatch(
        &mut self,
        reservation: GenerationReservation,
        process: WorkerProcess,
        now: Instant,
        dispatch_registration: WorkerDispatchRegistration,
    ) -> Result<WorkerRegistrationCommit, RegistrationFailure> {
        let context_id = reservation.context_id;
        let generation = reservation.generation;
        let expires_at = reservation.expires_at;
        let exact_reservation_phase = self
            .reservations
            .get(&context_id)
            .filter(|pending| pending.generation == generation && pending.expires_at == expires_at)
            .map(|pending| pending.phase);
        let exact_reservation = exact_reservation_phase.is_some();
        let error = if !exact_reservation {
            Some(WorkerV3Error::Stale)
        } else if self.shutting_down {
            Some(WorkerV3Error::ShuttingDown)
        } else if now >= expires_at {
            Some(WorkerV3Error::Dead)
        } else if self.records.contains_key(&context_id)
            || process.binding != Some((context_id, generation))
        {
            Some(WorkerV3Error::Conflict)
        } else {
            None
        };
        if let Some(error) = error {
            // An ordinary short-lived reservation can be released on registration failure. A
            // LifecycleOwned reservation is also the shutdown-visible fence for the returned
            // process owner and must survive until exact reap and purge.
            if exact_reservation_phase == Some(PendingGenerationPhase::Reserved) {
                self.reservations.remove(&context_id);
            }
            return Err(RegistrationFailure {
                error,
                process: Box::new(process),
                reservation: Some(reservation),
            });
        }

        self.reservations.remove(&context_id);
        let alive_hint = Arc::clone(&process.alive_hint);
        let coordinates = WorkerGenerationCoordinates {
            context_id,
            worker_generation: NonZeroU64::new(generation).unwrap_or_else(|| std::process::abort()),
        };
        let (dispatch_fence, commit) = match dispatch_registration {
            WorkerDispatchRegistration::Open => (
                WorkerDispatchFence::Open,
                WorkerRegistrationCommit::Open(generation),
            ),
            WorkerDispatchRegistration::DurableHandoffPending => (
                WorkerDispatchFence::DurableHandoffPending,
                WorkerRegistrationCommit::DurableHandoffPending {
                    generation,
                    fence: DurableHandoffFenceOwner { coordinates },
                },
            ),
        };
        self.records.insert(
            context_id,
            WorkerRecord {
                generation,
                dispatch_fence,
                stable_phase: StablePhase::Starting,
                in_flight: None,
                quarantined: false,
                expires_at,
                alive_hint,
                process: Some(process),
            },
        );
        Ok(commit)
    }

    fn commit_reserved(
        &mut self,
        reservation: GenerationReservation,
        process: WorkerProcess,
        now: Instant,
    ) -> Result<u64, RegistrationFailure> {
        match self.commit_reserved_with_dispatch(
            reservation,
            process,
            now,
            WorkerDispatchRegistration::Open,
        )? {
            WorkerRegistrationCommit::Open(generation) => Ok(generation),
            WorkerRegistrationCommit::DurableHandoffPending { .. } => std::process::abort(),
        }
    }

    fn commit_spawned(
        &mut self,
        spawned: SpawnedWorker,
        now: Instant,
    ) -> Result<u64, RegistrationFailure> {
        let SpawnedWorker {
            reservation,
            process,
            bootstrap_challenge: _,
        } = spawned;
        self.commit_reserved(reservation, process, now)
    }

    fn commit_spawned_with_dispatch(
        &mut self,
        spawned: SpawnedWorker,
        now: Instant,
        dispatch_registration: WorkerDispatchRegistration,
    ) -> Result<WorkerRegistrationCommit, RegistrationFailure> {
        let SpawnedWorker {
            reservation,
            process,
            bootstrap_challenge: _,
        } = spawned;
        self.commit_reserved_with_dispatch(reservation, process, now, dispatch_registration)
    }

    #[cfg(test)]
    fn register(
        &mut self,
        context_id: ContextId,
        mut process: WorkerProcess,
        ttl: Duration,
        now: Instant,
    ) -> Result<u64, RegistrationFailure> {
        let reservation = match self.reserve_generation(context_id, ttl, now) {
            Ok(reservation) => reservation,
            Err(error) => {
                return Err(RegistrationFailure {
                    error,
                    process: Box::new(process),
                    reservation: None,
                });
            }
        };
        if process.binding.is_none() {
            process.binding = Some(reservation.binding());
        }
        self.commit_reserved(reservation, process, now)
    }

    fn prepare_call_owners(
        &self,
        context_id: ContextId,
        generation: u64,
        request: &InternalWorkerRequest,
        deadline: HardDeadline,
    ) -> Result<
        (
            Socket,
            Option<crate::worker_sandbox::PinnedWorkerNetworkNamespace>,
        ),
        WorkerV3Error,
    > {
        let record = self.records.get(&context_id).ok_or(WorkerV3Error::Dead)?;
        if record.generation != generation {
            return Err(WorkerV3Error::Stale);
        }
        if matches!(
            record.dispatch_fence,
            WorkerDispatchFence::DurableHandoffPending
        ) {
            return Err(WorkerV3Error::Busy);
        }
        if record.quarantined {
            return Err(WorkerV3Error::Quarantined);
        }
        let process = record.process.as_ref().ok_or(WorkerV3Error::Dead)?;
        let pinned_network_namespace = matches!(
            request.operation.as_ref(),
            Some(internal_worker_request::Operation::AcquireTransportSocket(
                _
            ))
        )
        .then(|| process.duplicate_network_namespace_pin(deadline))
        .transpose()?;
        ensure_worker_deadline(deadline)?;
        Ok((process.clone_channel()?, pinned_network_namespace))
    }

    fn recovery_identity_owners(
        &self,
        coordinates: WorkerGenerationCoordinates,
        deadline: HardDeadline,
    ) -> Result<PendingWorkerRecoveryIdentity, WorkerV3Error> {
        ensure_worker_deadline(deadline)?;
        let process = self.recovery_identity_process(coordinates)?;
        let source = process.duplicate_recovery_identity_source_until(coordinates, deadline)?;
        ensure_worker_deadline(deadline)?;
        Ok(source)
    }

    fn recovery_identity_process(
        &self,
        coordinates: WorkerGenerationCoordinates,
    ) -> Result<&WorkerProcess, WorkerV3Error> {
        let record = self
            .records
            .get(&coordinates.context_id)
            .ok_or(WorkerV3Error::Dead)?;
        if record.generation != coordinates.worker_generation.get() {
            return Err(WorkerV3Error::Stale);
        }
        if Instant::now() >= record.expires_at {
            return Err(WorkerV3Error::Dead);
        }
        if record.quarantined || record.in_flight.is_some() {
            return Err(WorkerV3Error::Quarantined);
        }
        if record.stable_phase != StablePhase::Starting {
            return Err(WorkerV3Error::Conflict);
        }
        record.process.as_ref().ok_or(WorkerV3Error::Dead)
    }

    fn confirm_recovery_identity_source(
        &self,
        source: &PendingWorkerRecoveryIdentity,
    ) -> Result<(), WorkerV3Error> {
        let process = self.recovery_identity_process(source.coordinates)?;
        if process.binding
            != Some((
                source.coordinates.context_id,
                source.coordinates.worker_generation.get(),
            ))
            || process.child_pid != source.expected_child_pid.get()
            || !Arc::ptr_eq(&process.lifetime, &source.process_identity)
        {
            return Err(WorkerV3Error::Stale);
        }
        Ok(())
    }

    fn confirm_durable_handoff_pending(
        &self,
        coordinates: WorkerGenerationCoordinates,
        fence: &DurableHandoffFenceOwner,
    ) -> Result<(), WorkerV3Error> {
        if fence.coordinates != coordinates {
            return Err(WorkerV3Error::Stale);
        }
        let record = self
            .records
            .get(&coordinates.context_id)
            .ok_or(WorkerV3Error::Dead)?;
        if record.generation != coordinates.worker_generation.get()
            || record.dispatch_fence != WorkerDispatchFence::DurableHandoffPending
        {
            return Err(WorkerV3Error::Stale);
        }
        if record.quarantined || record.in_flight.is_some() {
            return Err(WorkerV3Error::Quarantined);
        }
        if record.stable_phase != StablePhase::Starting
            || self.cache.keys().any(|key| {
                key.context_id == coordinates.context_id
                    && key.generation == coordinates.worker_generation.get()
            })
            || self.cache_order.iter().any(|key| {
                key.context_id == coordinates.context_id
                    && key.generation == coordinates.worker_generation.get()
            })
            || self.tombstones.keys().any(|key| {
                key.context_id == coordinates.context_id
                    && key.generation == coordinates.worker_generation.get()
            })
            || self.tombstone_order.iter().any(|key| {
                key.context_id == coordinates.context_id
                    && key.generation == coordinates.worker_generation.get()
            })
        {
            return Err(WorkerV3Error::Conflict);
        }
        Ok(())
    }

    fn reject_pending_durable_handoff_dispatch(
        &self,
        context_id: ContextId,
        generation: u64,
    ) -> Result<(), WorkerV3Error> {
        if self.records.get(&context_id).is_some_and(|record| {
            record.generation == generation
                && matches!(
                    record.dispatch_fence,
                    WorkerDispatchFence::DurableHandoffPending
                )
        }) {
            Err(WorkerV3Error::Busy)
        } else {
            Ok(())
        }
    }

    fn plan_until(
        &mut self,
        context_id: ContextId,
        generation: u64,
        request: &InternalWorkerRequest,
        now: Instant,
        deadline: HardDeadline,
    ) -> Result<RegistryPlan, WorkerV3Error> {
        ensure_worker_deadline(deadline)?;
        self.reject_pending_durable_handoff_dispatch(context_id, generation)?;
        self.expire_cache(now);
        self.expire_tombstones(now);
        if self.shutting_down {
            return Err(WorkerV3Error::ShuttingDown);
        }
        if request_context(request)? != context_id {
            return Err(WorkerV3Error::Invalid);
        }
        let key = request_key(context_id, generation, request)?;
        let tombstone_key = TombstoneKey {
            context_id,
            generation,
            request_id: key.request_id,
        };

        let (phase, expires_at, liveness, expected_peer, in_flight) = {
            let record = self.records.get(&context_id).ok_or(WorkerV3Error::Dead)?;
            if record.generation != generation {
                return Err(WorkerV3Error::Stale);
            }
            if record.quarantined {
                return Err(WorkerV3Error::Quarantined);
            }
            let process = record.process.as_ref().ok_or(WorkerV3Error::Dead)?;
            (
                record.stable_phase,
                record.expires_at,
                process.liveness(),
                process.expected_peer,
                record.in_flight,
            )
        };
        if now >= expires_at {
            self.quarantine(context_id, generation)?;
            return Err(WorkerV3Error::Dead);
        }

        if let Some(existing) = self.tombstones.get(&tombstone_key) {
            if existing.request_digest != key.request_digest {
                self.quarantine(context_id, generation)?;
                return Err(WorkerV3Error::Conflict);
            }
            if let Some(entry) = self.cache.get(&key) {
                ensure_worker_deadline(deadline)?;
                return Ok(RegistryPlan::Cached(CachedCall {
                    token: key,
                    response: entry.response.clone(),
                    liveness,
                    deadline,
                }));
            }
            return Err(if in_flight.is_some_and(|value| value.key == key) {
                WorkerV3Error::Busy
            } else {
                WorkerV3Error::Conflict
            });
        }
        if in_flight.is_some() {
            return Err(WorkerV3Error::Busy);
        }
        if self.tombstones.len() >= self.maximum_cache_entries {
            return Err(WorkerV3Error::Capacity);
        }

        let (success_phase, terminal) = transition(phase, request)?;
        let (channel, pinned_network_namespace) =
            self.prepare_call_owners(context_id, generation, request, deadline)?;
        ensure_worker_deadline(deadline)?;
        let in_flight = InFlight {
            key,
            prior_phase: phase,
            success_phase,
            terminal,
            deadline,
        };
        ensure_worker_deadline(deadline)?;
        self.tombstones.insert(
            tombstone_key,
            Tombstone {
                request_digest: key.request_digest,
                expires_at,
            },
        );
        self.tombstone_order.push_back(tombstone_key);
        self.records
            .get_mut(&context_id)
            .ok_or(WorkerV3Error::Dead)?
            .in_flight = Some(in_flight);
        Ok(RegistryPlan::Call(PlannedCall {
            token: PlanToken {
                context_id,
                generation,
                in_flight,
            },
            channel,
            liveness,
            expected_peer,
            pinned_network_namespace,
        }))
    }

    #[cfg(test)]
    fn plan(
        &mut self,
        context_id: ContextId,
        generation: u64,
        request: &InternalWorkerRequest,
        now: Instant,
    ) -> Result<RegistryPlan, WorkerV3Error> {
        let deadline = HardDeadline::after(CHANNEL_TIMEOUT).map_err(WorkerV3Error::Io)?;
        self.plan_until(context_id, generation, request, now, deadline)
    }

    fn finish(
        &mut self,
        token: PlanToken,
        request: &InternalWorkerRequest,
        response: &InternalWorkerResponse,
        now: Instant,
        worker_alive: bool,
    ) -> FinishOutcome {
        let valid = validate_response_for_request(request, response).is_ok()
            && request_key(token.context_id, token.generation, request)
                .is_ok_and(|key| key == token.in_flight.key);
        let deadline_live = ensure_worker_deadline(token.in_flight.deadline).is_ok();
        #[cfg(test)]
        if let Some(hook) = self.finish_commit_hook.clone() {
            hook.reached.wait();
            hook.release.wait();
        }
        let shutting_down = self.shutting_down;
        let mut should_cache = false;
        let mut cache_expiry = now;
        let outcome = {
            let Some(record) = self.records.get_mut(&token.context_id) else {
                return FinishOutcome::Rejected {
                    error: WorkerV3Error::Stale,
                    detached: None,
                };
            };
            if record.generation != token.generation {
                return FinishOutcome::Rejected {
                    error: WorkerV3Error::Stale,
                    detached: None,
                };
            }
            if record.dispatch_fence == WorkerDispatchFence::DurableHandoffPending {
                return FinishOutcome::Rejected {
                    error: WorkerV3Error::Busy,
                    detached: None,
                };
            }
            if record.in_flight != Some(token.in_flight)
                || record.stable_phase != token.in_flight.prior_phase
            {
                return FinishOutcome::Rejected {
                    error: WorkerV3Error::Stale,
                    detached: None,
                };
            }

            let alive_at_commit = token.in_flight.terminal
                || (worker_alive && record.alive_hint.load(Ordering::SeqCst));
            if !valid
                || !deadline_live
                || shutting_down
                || now >= record.expires_at
                || !alive_at_commit
            {
                let error = if !valid {
                    WorkerV3Error::Invalid
                } else if !deadline_live {
                    WorkerV3Error::Deadline
                } else if shutting_down {
                    WorkerV3Error::ShuttingDown
                } else {
                    WorkerV3Error::Dead
                };
                Self::reject_finish(record, token, error)
            } else if ensure_worker_deadline(token.in_flight.deadline).is_err() {
                Self::reject_finish(record, token, WorkerV3Error::Deadline)
            } else if response.result == InternalWorkerResult::CleanupIncomplete as i32 {
                Self::reject_finish(record, token, WorkerV3Error::Ambiguous)
            } else if let Ok(result) = InternalWorkerResult::try_from(response.result) {
                record.in_flight = None;
                if result == InternalWorkerResult::Ok {
                    record.stable_phase = token.in_flight.success_phase;
                }
                if result == InternalWorkerResult::Ok && token.in_flight.terminal {
                    record.quarantined = true;
                    record.process.take().map_or(
                        FinishOutcome::Rejected {
                            error: WorkerV3Error::Dead,
                            detached: None,
                        },
                        |process| {
                            FinishOutcome::Terminal(DetachedWorker {
                                context_id: token.context_id,
                                generation: token.generation,
                                process,
                            })
                        },
                    )
                } else {
                    should_cache = !matches!(
                        request.operation,
                        Some(internal_worker_request::Operation::AcquireTransportSocket(
                            _
                        ))
                    );
                    cache_expiry = record.expires_at;
                    FinishOutcome::Committed
                }
            } else {
                Self::reject_finish(record, token, WorkerV3Error::Invalid)
            }
        };

        self.apply_finish_outcome(token, response, outcome, should_cache, cache_expiry)
    }

    fn reject_finish(
        record: &mut WorkerRecord,
        token: PlanToken,
        error: WorkerV3Error,
    ) -> FinishOutcome {
        record.in_flight = None;
        record.quarantined = true;
        let detached = record.process.take().map(|process| DetachedWorker {
            context_id: token.context_id,
            generation: token.generation,
            process,
        });
        FinishOutcome::Rejected { error, detached }
    }

    fn apply_finish_outcome(
        &mut self,
        token: PlanToken,
        response: &InternalWorkerResponse,
        outcome: FinishOutcome,
        should_cache: bool,
        cache_expiry: Instant,
    ) -> FinishOutcome {
        if matches!(&outcome, FinishOutcome::Committed) {
            if should_cache {
                self.insert_cache(token.in_flight.key, response.clone(), cache_expiry);
            }
        } else {
            self.purge_cache_generation(token.context_id, token.generation);
        }
        outcome
    }

    fn validate_cached(
        &mut self,
        call: &CachedCall,
        now: Instant,
        worker_alive: bool,
    ) -> FinishOutcome {
        let cache_present = self.cache.contains_key(&call.token);
        let deadline_live = ensure_worker_deadline(call.deadline).is_ok();
        #[cfg(test)]
        if let Some(hook) = self.finish_commit_hook.clone() {
            hook.reached.wait();
            hook.release.wait();
        }
        let shutting_down = self.shutting_down;
        let mut purge = false;
        let outcome = {
            let Some(record) = self.records.get_mut(&call.token.context_id) else {
                return FinishOutcome::Rejected {
                    error: WorkerV3Error::Stale,
                    detached: None,
                };
            };
            if record.generation != call.token.generation {
                return FinishOutcome::Rejected {
                    error: WorkerV3Error::Stale,
                    detached: None,
                };
            }
            if record.dispatch_fence == WorkerDispatchFence::DurableHandoffPending {
                return FinishOutcome::Rejected {
                    error: WorkerV3Error::Busy,
                    detached: None,
                };
            }
            if !record.quarantined
                && record.in_flight.is_none()
                && cache_present
                && deadline_live
                && !shutting_down
                && now < record.expires_at
                && worker_alive
                && record.alive_hint.load(Ordering::SeqCst)
                && ensure_worker_deadline(call.deadline).is_ok()
            {
                FinishOutcome::Committed
            } else {
                record.in_flight = None;
                record.quarantined = true;
                purge = true;
                let detached = record.process.take().map(|process| DetachedWorker {
                    context_id: call.token.context_id,
                    generation: call.token.generation,
                    process,
                });
                FinishOutcome::Rejected {
                    error: if shutting_down {
                        WorkerV3Error::ShuttingDown
                    } else if !deadline_live || ensure_worker_deadline(call.deadline).is_err() {
                        WorkerV3Error::Deadline
                    } else {
                        WorkerV3Error::Dead
                    },
                    detached,
                }
            }
        };
        if purge {
            self.purge_cache_generation(call.token.context_id, call.token.generation);
        }
        outcome
    }

    fn mark_ambiguous(
        &mut self,
        token: PlanToken,
    ) -> Result<Option<DetachedWorker>, WorkerV3Error> {
        let detached = {
            let record = self
                .records
                .get_mut(&token.context_id)
                .ok_or(WorkerV3Error::Stale)?;
            if record.generation != token.generation {
                return Err(WorkerV3Error::Stale);
            }
            if record.dispatch_fence == WorkerDispatchFence::DurableHandoffPending {
                return Err(WorkerV3Error::Busy);
            }
            if record.in_flight != Some(token.in_flight) {
                return Err(WorkerV3Error::Stale);
            }
            record.in_flight = None;
            record.quarantined = true;
            record.process.take().map(|process| DetachedWorker {
                context_id: token.context_id,
                generation: token.generation,
                process,
            })
        };
        self.purge_cache_generation(token.context_id, token.generation);
        Ok(detached)
    }

    fn report_dead(
        &mut self,
        context_id: ContextId,
        generation: u64,
    ) -> Result<Option<DetachedWorker>, WorkerV3Error> {
        self.quarantine(context_id, generation)?;
        self.detach_quarantined(context_id, generation)
    }

    fn quarantine(&mut self, context_id: ContextId, generation: u64) -> Result<(), WorkerV3Error> {
        {
            let record = self
                .records
                .get_mut(&context_id)
                .ok_or(WorkerV3Error::Stale)?;
            if record.generation != generation {
                return Err(WorkerV3Error::Stale);
            }
            record.quarantined = true;
            record.in_flight = None;
        }
        self.purge_cache_generation(context_id, generation);
        Ok(())
    }

    fn detach_quarantined(
        &mut self,
        context_id: ContextId,
        generation: u64,
    ) -> Result<Option<DetachedWorker>, WorkerV3Error> {
        let record = self
            .records
            .get_mut(&context_id)
            .ok_or(WorkerV3Error::Stale)?;
        if record.generation != generation || !record.quarantined {
            return Err(WorkerV3Error::Stale);
        }
        Ok(record.process.take().map(|process| DetachedWorker {
            context_id,
            generation,
            process,
        }))
    }

    fn reattach_uncertain(&mut self, detached: DetachedWorker) -> Result<(), ReattachFailure> {
        if self.shutting_down {
            return Err(ReattachFailure {
                error: WorkerV3Error::ShuttingDown,
                detached: Box::new(detached),
            });
        }
        let can_reattach = self
            .records
            .get(&detached.context_id)
            .is_some_and(|record| {
                record.generation == detached.generation
                    && record.quarantined
                    && record.process.is_none()
            });
        if !can_reattach {
            return Err(ReattachFailure {
                error: WorkerV3Error::Stale,
                detached: Box::new(detached),
            });
        }
        self.records
            .get_mut(&detached.context_id)
            .expect("record was validated without releasing the registry")
            .process = Some(detached.process);
        Ok(())
    }

    fn reap(&mut self, now: Instant) -> Vec<DetachedWorker> {
        self.expire_reservations(now);
        let expired = self
            .records
            .iter()
            .filter_map(|(context_id, record)| {
                (now >= record.expires_at).then_some((*context_id, record.generation))
            })
            .collect::<Vec<_>>();
        let mut detached = Vec::with_capacity(expired.len());
        for (context_id, generation) in expired {
            if self.quarantine(context_id, generation).is_ok() {
                if let Ok(Some(worker)) = self.detach_quarantined(context_id, generation) {
                    detached.push(worker);
                }
            }
        }
        detached
    }

    fn purge_confirmed(
        &mut self,
        context_id: ContextId,
        generation: u64,
    ) -> Result<(), WorkerV3Error> {
        let record = self.records.get(&context_id).ok_or(WorkerV3Error::Stale)?;
        if record.generation != generation {
            return Err(WorkerV3Error::Stale);
        }
        if !record.quarantined || record.process.is_some() {
            return Err(WorkerV3Error::Conflict);
        }
        self.records.remove(&context_id);
        self.purge_generation(context_id, generation);
        Ok(())
    }

    fn purge_or_confirm_generation_absent(
        &mut self,
        coordinates: WorkerGenerationCoordinates,
    ) -> Result<(), WorkerV3Error> {
        match self.records.get(&coordinates.context_id) {
            Some(record) if record.generation == coordinates.worker_generation.get() => {
                if !record.quarantined || record.process.is_some() {
                    return Err(WorkerV3Error::Conflict);
                }
                self.records.remove(&coordinates.context_id);
            }
            Some(_) | None => {}
        }
        self.purge_generation(coordinates.context_id, coordinates.worker_generation.get());
        if self.exact_generation_absent(coordinates) {
            Ok(())
        } else {
            Err(WorkerV3Error::Ambiguous)
        }
    }

    fn purge_and_abandon_unspawned_lifecycle_generation(
        &mut self,
        reservation: &GenerationReservation,
        coordinates: WorkerGenerationCoordinates,
        deadline: HardDeadline,
    ) -> Result<(), WorkerV3Error> {
        if reservation.context_id != coordinates.context_id
            || reservation.generation != coordinates.worker_generation.get()
        {
            return Err(WorkerV3Error::Stale);
        }
        if !self.exact_lifecycle_reservation_present(reservation) {
            return Err(WorkerV3Error::Stale);
        }
        if self
            .records
            .get(&coordinates.context_id)
            .is_some_and(|record| record.generation == coordinates.worker_generation.get())
        {
            return Err(WorkerV3Error::Conflict);
        }
        ensure_worker_deadline(deadline)?;
        // Purge every exact secondary index while the non-expiring admission fence is still
        // visible to shutdown. The affine reservation is consumed only as the last mutation.
        self.purge_generation(coordinates.context_id, coordinates.worker_generation.get());
        self.abandon_generation_ref(reservation)?;
        if !self.exact_generation_absent(coordinates) {
            // The registry mutex remained held across validation, purge and abandon, so residue
            // here would be an internal ownership invariant violation, not retryable ambiguity.
            std::process::abort();
        }
        Ok(())
    }

    fn exact_generation_absent(&self, coordinates: WorkerGenerationCoordinates) -> bool {
        self.records
            .get(&coordinates.context_id)
            .is_none_or(|record| record.generation != coordinates.worker_generation.get())
            && self
                .reservations
                .get(&coordinates.context_id)
                .is_none_or(|pending| pending.generation != coordinates.worker_generation.get())
            && self.cache.keys().all(|key| {
                key.context_id != coordinates.context_id
                    || key.generation != coordinates.worker_generation.get()
            })
            && self.cache_order.iter().all(|key| {
                key.context_id != coordinates.context_id
                    || key.generation != coordinates.worker_generation.get()
            })
            && self.tombstones.keys().all(|key| {
                key.context_id != coordinates.context_id
                    || key.generation != coordinates.worker_generation.get()
            })
            && self.tombstone_order.iter().all(|key| {
                key.context_id != coordinates.context_id
                    || key.generation != coordinates.worker_generation.get()
            })
    }

    fn begin_shutdown(&mut self) -> Vec<DetachedWorker> {
        self.shutting_down = true;
        self.reservations
            .retain(|_, pending| pending.phase == PendingGenerationPhase::LifecycleOwned);
        let identities = self
            .records
            .iter()
            .map(|(context_id, record)| (*context_id, record.generation))
            .collect::<Vec<_>>();
        let mut detached = Vec::with_capacity(identities.len());
        for (context_id, generation) in identities {
            if self.quarantine(context_id, generation).is_ok() {
                if let Ok(Some(worker)) = self.detach_quarantined(context_id, generation) {
                    detached.push(worker);
                }
            }
        }
        detached
    }

    fn visible_phase(
        &self,
        context_id: ContextId,
        generation: u64,
    ) -> Result<VisiblePhase, WorkerV3Error> {
        let record = self.records.get(&context_id).ok_or(WorkerV3Error::Stale)?;
        if record.generation != generation {
            return Err(WorkerV3Error::Stale);
        }
        Ok(if record.quarantined {
            VisiblePhase::Quarantined
        } else if record.dispatch_fence == WorkerDispatchFence::DurableHandoffPending {
            VisiblePhase::DurableHandoffPending
        } else if record.in_flight.is_some() {
            VisiblePhase::InFlight
        } else {
            VisiblePhase::Stable(record.stable_phase)
        })
    }

    fn insert_cache(
        &mut self,
        key: CacheKey,
        response: InternalWorkerResponse,
        expires_at: Instant,
    ) {
        self.cache.insert(
            key,
            CacheEntry {
                response,
                expires_at,
            },
        );
        self.cache_order.push_back(key);
        while self.cache.len() > self.maximum_cache_entries {
            if let Some(oldest) = self.cache_order.pop_front() {
                self.cache.remove(&oldest);
            } else {
                break;
            }
        }
    }

    fn expire_cache(&mut self, now: Instant) {
        self.cache.retain(|_, entry| now < entry.expires_at);
        self.cache_order.retain(|key| self.cache.contains_key(key));
    }

    fn expire_tombstones(&mut self, now: Instant) {
        self.tombstones.retain(|_, entry| now < entry.expires_at);
        self.tombstone_order
            .retain(|key| self.tombstones.contains_key(key));
    }

    fn expire_reservations(&mut self, now: Instant) {
        self.reservations.retain(|_, reservation| {
            reservation.phase == PendingGenerationPhase::LifecycleOwned
                || now < reservation.expires_at
        });
    }

    fn purge_cache_generation(&mut self, context_id: ContextId, generation: u64) {
        self.cache
            .retain(|key, _| key.context_id != context_id || key.generation != generation);
        self.cache_order
            .retain(|key| key.context_id != context_id || key.generation != generation);
    }

    fn purge_generation(&mut self, context_id: ContextId, generation: u64) {
        self.purge_cache_generation(context_id, generation);
        self.tombstones
            .retain(|key, _| key.context_id != context_id || key.generation != generation);
        self.tombstone_order
            .retain(|key| key.context_id != context_id || key.generation != generation);
    }
}

fn request_key(
    context_id: ContextId,
    generation: u64,
    request: &InternalWorkerRequest,
) -> Result<CacheKey, WorkerV3Error> {
    let request_id = request
        .request_id
        .as_slice()
        .try_into()
        .map_err(|_| WorkerV3Error::Invalid)?;
    let encoded = encode_request(request).map_err(|_| WorkerV3Error::Invalid)?;
    Ok(CacheKey {
        context_id,
        generation,
        request_id,
        request_digest: *blake3::hash(encoded.as_slice()).as_bytes(),
    })
}

fn transition(
    phase: StablePhase,
    request: &InternalWorkerRequest,
) -> Result<(StablePhase, bool), WorkerV3Error> {
    use internal_worker_request::Operation;

    match (phase, request.operation.as_ref()) {
        (StablePhase::Starting, Some(Operation::Initialise(_))) => {
            Ok((StablePhase::Initialised, false))
        }
        (StablePhase::Initialised, Some(Operation::PrepareLeases(_))) => {
            Ok((StablePhase::Prepared, false))
        }
        (StablePhase::Prepared, Some(Operation::ActivateLeases(_))) => {
            Ok((StablePhase::Activated, false))
        }
        (StablePhase::Activated, Some(Operation::ProbeCommitLeases(_))) => {
            Ok((StablePhase::Committed, false))
        }
        (
            StablePhase::Committed,
            Some(
                Operation::AddMptcpEndpoint(_)
                | Operation::RemoveMptcpEndpoint(_)
                | Operation::AcquireTransportSocket(_),
            ),
        ) => Ok((StablePhase::Committed, false)),
        (_, Some(Operation::DestroyContext(_))) => Ok((phase, true)),
        _ => Err(WorkerV3Error::Conflict),
    }
}

fn lock_worker_registry(
    registry: &Mutex<WorkerRegistry>,
) -> std::sync::MutexGuard<'_, WorkerRegistry> {
    registry
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn lock_worker_registry_until(
    registry: &Mutex<WorkerRegistry>,
    deadline: HardDeadline,
) -> Result<std::sync::MutexGuard<'_, WorkerRegistry>, WorkerV3Error> {
    loop {
        ensure_worker_deadline(deadline)?;
        match registry.try_lock() {
            Ok(guard) => {
                ensure_worker_deadline(deadline)?;
                return Ok(guard);
            }
            Err(std::sync::TryLockError::Poisoned(error)) => {
                ensure_worker_deadline(deadline)?;
                return Ok(error.into_inner());
            }
            Err(std::sync::TryLockError::WouldBlock) => {
                let remaining = deadline.remaining().map_err(|error| {
                    if error.kind() == io::ErrorKind::TimedOut {
                        WorkerV3Error::Deadline
                    } else {
                        WorkerV3Error::Io(error)
                    }
                })?;
                thread::sleep(remaining.min(TERMINATION_POLL_INTERVAL));
            }
        }
    }
}

fn ensure_worker_deadline(deadline: HardDeadline) -> Result<(), WorkerV3Error> {
    match deadline.ensure_remaining() {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == io::ErrorKind::TimedOut => Err(WorkerV3Error::Deadline),
        Err(error) => Err(WorkerV3Error::Io(error)),
    }
}

struct SupervisorSettlements {
    shutdown_owners: Vec<DetachedWorker>,
    unresolved: bool,
    #[cfg(test)]
    retirement_hook: Option<RetirementHook>,
    #[cfg(test)]
    shutdown_hook: Option<ShutdownHook>,
    #[cfg(test)]
    supervisor_hook: Option<SupervisorHook>,
}

impl SupervisorSettlements {
    fn new() -> Self {
        Self {
            shutdown_owners: Vec::with_capacity(MAX_PROCESS_OWNERS),
            unresolved: false,
            #[cfg(test)]
            retirement_hook: None,
            #[cfg(test)]
            shutdown_hook: None,
            #[cfg(test)]
            supervisor_hook: None,
        }
    }

    fn capture_shutdown_owner(&mut self, detached: DetachedWorker) {
        if self.unresolved {
            detached.escalate_to_reaper();
            return;
        }
        if self.shutdown_owners.len() >= MAX_PROCESS_OWNERS {
            std::process::abort();
        }
        self.shutdown_owners.push(detached);
    }

    fn mark_unresolved(&mut self) {
        self.unresolved = true;
        for detached in self.shutdown_owners.drain(..) {
            detached.escalate_to_reaper();
        }
    }

    fn take_for_shutdown(&mut self) -> (Vec<DetachedWorker>, bool) {
        (std::mem::take(&mut self.shutdown_owners), !self.unresolved)
    }
}

struct SupervisorSettlementGuard {
    settlements: Arc<Mutex<SupervisorSettlements>>,
    _permit: SupervisorPermit,
    settled: bool,
}

impl SupervisorSettlementGuard {
    fn new(settlements: Arc<Mutex<SupervisorSettlements>>, permit: SupervisorPermit) -> Self {
        Self {
            settlements,
            _permit: permit,
            settled: false,
        }
    }

    fn settle(mut self) {
        self.settled = true;
    }
}

impl Drop for SupervisorSettlementGuard {
    fn drop(&mut self) {
        if !self.settled {
            self.settlements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .mark_unresolved();
        }
    }
}

#[derive(Clone)]
struct WorkerSupervisor {
    registry: Arc<Mutex<WorkerRegistry>>,
    settlements: Arc<Mutex<SupervisorSettlements>>,
}

#[must_use = "shutdown retirement must retain retryable worker ownership"]
enum ShutdownRetirement {
    Confirmed,
    Retryable(Box<DetachedWorker>),
    Unresolved,
}

impl WorkerSupervisor {
    async fn run(
        &self,
        plan: RegistryPlan,
        request: InternalWorkerRequest,
    ) -> Result<CredentialedWorkerExecution, WorkerV3Error> {
        match plan {
            RegistryPlan::Cached(call) => self.run_cached(call).await,
            RegistryPlan::Call(call) => self.run_call(call, request).await,
        }
    }

    async fn run_cached(
        &self,
        call: CachedCall,
    ) -> Result<CredentialedWorkerExecution, WorkerV3Error> {
        let deadline = call.deadline;
        let liveness = call.liveness.clone();
        let worker_alive =
            tokio::task::spawn_blocking(move || liveness.probe_alive_until(deadline))
                .await
                .ok()
                .and_then(Result::ok)
                .unwrap_or(false);
        let outcome = lock_worker_registry(&self.registry).validate_cached(
            &call,
            Instant::now(),
            worker_alive,
        );
        let execution = CredentialedWorkerExecution {
            response: call.response,
            descriptor: None,
        };
        self.resolve_finish(outcome, execution).await
    }

    async fn run_call(
        &self,
        call: PlannedCall,
        request: InternalWorkerRequest,
    ) -> Result<CredentialedWorkerExecution, WorkerV3Error> {
        let PlannedCall {
            token,
            channel,
            liveness,
            expected_peer,
            pinned_network_namespace,
        } = call;
        let deadline = token.in_flight.deadline;
        let io_request = request.clone();
        let result = tokio::task::spawn_blocking(move || {
            send_credential_worker_request_with_deadline(&channel, &io_request, deadline)?;
            let mut execution = receive_credential_worker_response_with_deadline(
                &channel,
                &io_request,
                expected_peer,
                deadline,
            )?;
            let worker_alive = liveness.probe_alive_until(deadline)?;
            ensure_worker_deadline(deadline)?;
            if !worker_alive {
                return Ok((execution, false));
            }
            match io_request.operation.as_ref() {
                Some(internal_worker_request::Operation::AcquireTransportSocket(acquire))
                    if execution.response.result == InternalWorkerResult::Ok as i32 =>
                {
                    let expected_namespace = pinned_network_namespace
                        .as_ref()
                        .ok_or(WorkerV3Error::Authentication)?;
                    let descriptor = execution.descriptor.take().ok_or(WorkerV3Error::Invalid)?;
                    execution.descriptor = Some(validate_adopted_transport_socket(
                        expected_namespace,
                        acquire,
                        descriptor,
                    )?);
                }
                Some(internal_worker_request::Operation::AcquireTransportSocket(_)) => {
                    if pinned_network_namespace.is_none() || execution.descriptor.is_some() {
                        return Err(WorkerV3Error::Invalid);
                    }
                }
                _ => {
                    if pinned_network_namespace.is_some() || execution.descriptor.is_some() {
                        return Err(WorkerV3Error::Invalid);
                    }
                }
            }
            ensure_worker_deadline(deadline)?;
            let worker_alive = liveness.probe_alive_until(deadline)?;
            ensure_worker_deadline(deadline)?;
            Ok::<_, WorkerV3Error>((execution, worker_alive))
        })
        .await;
        let Ok(Ok((execution, worker_alive))) = result else {
            let deadline_elapsed = ensure_worker_deadline(deadline).is_err();
            return self.finish_ambiguous(token, deadline_elapsed).await;
        };
        let outcome = lock_worker_registry(&self.registry).finish(
            token,
            &request,
            &execution.response,
            Instant::now(),
            worker_alive,
        );
        self.resolve_finish(outcome, execution).await
    }

    async fn finish_ambiguous(
        &self,
        token: PlanToken,
        deadline_elapsed: bool,
    ) -> Result<CredentialedWorkerExecution, WorkerV3Error> {
        let detached = lock_worker_registry(&self.registry)
            .mark_ambiguous(token)
            .ok()
            .flatten();
        if let Some(worker) = detached {
            if !self.retire(worker).await {
                return Err(WorkerV3Error::Ambiguous);
            }
        }
        Err(if deadline_elapsed {
            WorkerV3Error::Deadline
        } else {
            WorkerV3Error::Ambiguous
        })
    }

    async fn resolve_finish(
        &self,
        outcome: FinishOutcome,
        execution: CredentialedWorkerExecution,
    ) -> Result<CredentialedWorkerExecution, WorkerV3Error> {
        match outcome {
            FinishOutcome::Committed => Ok(execution),
            FinishOutcome::Terminal(worker) => {
                if self.retire(worker).await {
                    Ok(execution)
                } else {
                    drop(execution);
                    Err(WorkerV3Error::Ambiguous)
                }
            }
            FinishOutcome::Rejected { error, detached } => {
                drop(execution);
                if let Some(worker) = detached {
                    if !self.retire(worker).await {
                        return Err(WorkerV3Error::Ambiguous);
                    }
                }
                Err(error)
            }
        }
    }

    async fn retire(&self, detached: DetachedWorker) -> bool {
        let liveness = detached.process.liveness();
        let stopped =
            tokio::task::spawn_blocking(move || liveness.terminate_bounded(TERMINATION_TIMEOUT))
                .await
                .unwrap_or(false);
        if stopped {
            detached.process.disarm_retirement();
            let purged = {
                let mut registry = lock_worker_registry(&self.registry);
                registry
                    .purge_confirmed(detached.context_id, detached.generation)
                    .is_ok()
            };
            drop(detached);
            return purged;
        }

        #[cfg(test)]
        {
            let hook = self
                .settlements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .retirement_hook
                .clone();
            if let Some(hook) = hook {
                hook.failed.wait();
                hook.release.wait();
            }
        }

        let reattached = {
            let mut registry = lock_worker_registry(&self.registry);
            registry.reattach_uncertain(detached)
        };
        match reattached {
            Ok(()) => false,
            Err(ReattachFailure {
                error: WorkerV3Error::ShuttingDown,
                detached,
            }) => {
                self.settlements
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .capture_shutdown_owner(*detached);
                false
            }
            Err(ReattachFailure { error: _, detached }) => {
                self.settlements
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .mark_unresolved();
                (*detached).escalate_to_reaper();
                false
            }
        }
    }

    async fn retire_for_shutdown_until(
        &self,
        detached: DetachedWorker,
        deadline: HardDeadline,
    ) -> ShutdownRetirement {
        let liveness = detached.process.liveness();
        match tokio::task::spawn_blocking(move || liveness.termination_outcome_until(deadline))
            .await
        {
            Ok(TerminationOutcome::Reaped) => {
                if ensure_worker_deadline(deadline).is_err() {
                    return ShutdownRetirement::Retryable(Box::new(detached));
                }
                let mut registry = match self.registry.try_lock() {
                    Ok(registry) => registry,
                    Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => {
                        return ShutdownRetirement::Retryable(Box::new(detached));
                    }
                };
                if ensure_worker_deadline(deadline).is_err() {
                    return ShutdownRetirement::Retryable(Box::new(detached));
                }
                if detached
                    .process
                    .disarm_retirement_for_shutdown(deadline)
                    .is_err()
                {
                    return ShutdownRetirement::Retryable(Box::new(detached));
                }
                let purged = registry
                    .purge_confirmed(detached.context_id, detached.generation)
                    .is_ok();
                drop(registry);
                drop(detached);
                if purged {
                    ShutdownRetirement::Confirmed
                } else {
                    ShutdownRetirement::Unresolved
                }
            }
            Ok(TerminationOutcome::TimedOut) => ShutdownRetirement::Retryable(Box::new(detached)),
            Ok(TerminationOutcome::Fatal) | Err(_) => {
                detached.escalate_to_reaper();
                ShutdownRetirement::Unresolved
            }
        }
    }

    async fn retire_quarantined(
        &self,
        context_id: ContextId,
        generation: u64,
        error: WorkerV3Error,
    ) -> Result<CredentialedWorkerExecution, WorkerV3Error> {
        let detached = lock_worker_registry(&self.registry)
            .detach_quarantined(context_id, generation)
            .ok()
            .flatten();
        if let Some(worker) = detached {
            if !self.retire(worker).await {
                return Err(WorkerV3Error::Ambiguous);
            }
        }
        Err(error)
    }
}

#[derive(Clone)]
struct ShutdownCompletion {
    inner: Arc<ShutdownCompletionInner>,
}

struct ShutdownCompletionInner {
    result: Mutex<Option<TimedShutdownStatus>>,
    completed: Notify,
}

#[derive(Clone, Copy)]
struct TimedShutdownStatus {
    status: ShutdownStatus,
    completed_at: Instant,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ShutdownStatus {
    Pending,
    Confirmed,
    Retryable,
    Unresolved,
}

enum ShutdownWaitTarget {
    Immediate(ShutdownStatus),
    Attempt(ShutdownCompletion),
}

impl ShutdownCompletion {
    fn new() -> Self {
        Self {
            inner: Arc::new(ShutdownCompletionInner {
                result: Mutex::new(None),
                completed: Notify::new(),
            }),
        }
    }

    fn complete(&self, status: ShutdownStatus) {
        if status == ShutdownStatus::Pending {
            std::process::abort();
        }
        let mut result = self
            .inner
            .result
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if result.is_none() {
            *result = Some(TimedShutdownStatus {
                status,
                completed_at: Instant::now(),
            });
            drop(result);
            self.inner.completed.notify_waiters();
        }
    }

    async fn wait_until(&self, deadline: HardDeadline) -> ShutdownStatus {
        loop {
            let notified = self.inner.completed.notified();
            if let Some(result) = *self
                .inner
                .result
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
            {
                return if result.completed_at < deadline.expires_at() {
                    result.status
                } else {
                    ShutdownStatus::Pending
                };
            }
            if deadline.ensure_remaining().is_err() {
                return ShutdownStatus::Pending;
            }
            tokio::select! {
                () = notified => {}
                () = tokio::time::sleep_until(deadline.expires_at().into()) => {
                    return ShutdownStatus::Pending;
                }
            }
        }
    }
}

struct ShutdownPublicationGuard {
    supervisors: Arc<Mutex<SupervisorState>>,
    settlements: Arc<Mutex<SupervisorSettlements>>,
    attempt_id: u64,
    completion: Option<ShutdownCompletion>,
}

impl ShutdownPublicationGuard {
    fn new(
        supervisors: Arc<Mutex<SupervisorState>>,
        settlements: Arc<Mutex<SupervisorSettlements>>,
        attempt_id: u64,
        completion: ShutdownCompletion,
    ) -> Self {
        Self {
            supervisors,
            settlements,
            attempt_id,
            completion: Some(completion),
        }
    }

    fn publish(mut self, status: ShutdownStatus, mut owners: ShutdownAttemptOwners) {
        if status == ShutdownStatus::Pending {
            std::process::abort();
        }
        if status == ShutdownStatus::Unresolved {
            self.settlements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .mark_unresolved();
        }
        let (workers, handles) = owners.release();
        {
            let mut state = self
                .supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if state.shutdown_attempt != self.attempt_id
                || state.shutdown_status != Some(ShutdownStatus::Pending)
                || state.shutdown_completion.as_ref().is_none_or(|current| {
                    self.completion
                        .as_ref()
                        .is_none_or(|completion| !Arc::ptr_eq(&current.inner, &completion.inner))
                })
            {
                std::process::abort();
            }
            if matches!(
                status,
                ShutdownStatus::Confirmed | ShutdownStatus::Unresolved
            ) && (!workers.is_empty() || !handles.is_empty())
            {
                std::process::abort();
            }
            state.shutdown_workers = workers;
            state.handles = handles;
            state.shutdown_status = Some(status);
            state.shutdown_completion = None;
        }
        if let Some(completion) = self.completion.take() {
            completion.complete(status);
        }
    }
}

impl Drop for ShutdownPublicationGuard {
    fn drop(&mut self) {
        if let Some(completion) = self.completion.take() {
            self.settlements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .mark_unresolved();
            let (workers, handles) = {
                let mut state = self
                    .supervisors
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                if state.shutdown_attempt == self.attempt_id
                    && state.shutdown_status == Some(ShutdownStatus::Pending)
                {
                    state.shutdown_status = Some(ShutdownStatus::Unresolved);
                    state.shutdown_completion = None;
                    (
                        std::mem::take(&mut state.shutdown_workers),
                        std::mem::take(&mut state.handles),
                    )
                } else {
                    (Vec::new(), Vec::new())
                }
            };
            for worker in workers {
                worker.escalate_to_reaper();
            }
            for handle in handles {
                handle.abort();
            }
            completion.complete(ShutdownStatus::Unresolved);
        }
    }
}

#[must_use = "shutdown attempt owners must be published or escalated"]
struct ShutdownAttemptOwners {
    workers: Vec<DetachedWorker>,
    handles: Vec<JoinHandle<()>>,
    armed: bool,
}

impl ShutdownAttemptOwners {
    fn new(workers: Vec<DetachedWorker>, handles: Vec<JoinHandle<()>>) -> Self {
        Self {
            workers,
            handles,
            armed: true,
        }
    }

    fn release(&mut self) -> (Vec<DetachedWorker>, Vec<JoinHandle<()>>) {
        self.armed = false;
        (
            std::mem::take(&mut self.workers),
            std::mem::take(&mut self.handles),
        )
    }

    fn escalate_all(&mut self) {
        for handle in self.handles.drain(..) {
            handle.abort();
        }
        for worker in self.workers.drain(..) {
            worker.escalate_to_reaper();
        }
    }
}

impl Drop for ShutdownAttemptOwners {
    fn drop(&mut self) {
        if !self.armed {
            return;
        }
        for handle in self.handles.drain(..) {
            handle.abort();
        }
        for worker in self.workers.drain(..) {
            worker.escalate_to_reaper();
        }
    }
}

struct SupervisorState {
    shutting_down: bool,
    active_permits: usize,
    pending_admissions: usize,
    handles: Vec<JoinHandle<()>>,
    shutdown_workers: Vec<DetachedWorker>,
    shutdown_attempt: u64,
    shutdown_status: Option<ShutdownStatus>,
    shutdown_completion: Option<ShutdownCompletion>,
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum SupervisorPermitStage {
    Pending,
    Task,
}

#[must_use = "a supervisor admission permit must be consumed by an owned task or released"]
struct SupervisorPermit {
    supervisors: Arc<Mutex<SupervisorState>>,
    stage: SupervisorPermitStage,
}

impl SupervisorPermit {
    fn bind_to_task(&mut self, state: &mut SupervisorState) {
        if self.stage != SupervisorPermitStage::Pending || state.pending_admissions == 0 {
            std::process::abort();
        }
        state.pending_admissions -= 1;
        self.stage = SupervisorPermitStage::Task;
    }
}

impl Drop for SupervisorPermit {
    fn drop(&mut self) {
        let mut state = self
            .supervisors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.active_permits == 0 {
            std::process::abort();
        }
        state.active_permits -= 1;
        if self.stage == SupervisorPermitStage::Pending {
            if state.pending_admissions == 0 {
                std::process::abort();
            }
            state.pending_admissions -= 1;
        }
    }
}

#[cfg(test)]
#[derive(Clone)]
struct RegistrationHook {
    planned: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

#[cfg(test)]
#[derive(Clone)]
struct BeforePlanHook {
    reached: Arc<Notify>,
    release: Arc<tokio::sync::Semaphore>,
}

#[cfg(test)]
#[derive(Clone)]
struct RetirementHook {
    failed: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

#[cfg(test)]
#[derive(Clone)]
struct ShutdownHook {
    started: Arc<AtomicBool>,
    release: Arc<Notify>,
}

#[cfg(test)]
#[derive(Clone)]
struct SupervisorHook {
    planned: Arc<AtomicUsize>,
    started: Arc<AtomicUsize>,
    release: Arc<tokio::sync::Semaphore>,
}

#[cfg(test)]
#[derive(Clone)]
struct LifecycleReapedHook {
    reached: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

#[cfg(test)]
#[derive(Clone, Copy, Eq, PartialEq)]
enum LifecycleMutationPoint {
    Commit,
    Settlement,
    Detach,
    PostAbsenceObservation,
    Purge,
}

#[cfg(test)]
#[derive(Clone)]
struct LifecycleMutationHook {
    point: LifecycleMutationPoint,
    reached: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

#[cfg(test)]
#[derive(Clone)]
struct LifecycleRecoveryHook {
    pinned: Arc<std::sync::Barrier>,
    release: Arc<std::sync::Barrier>,
}

#[cfg(test)]
#[derive(Clone)]
struct DurableHandoffSourceHook {
    derived: std::sync::mpsc::SyncSender<()>,
    release: Arc<(Mutex<bool>, Condvar)>,
}

#[derive(Clone)]
#[must_use = "call shutdown to retire registered workers before dropping the coordinator"]
struct WorkerCoordinator {
    registry: Arc<Mutex<WorkerRegistry>>,
    supervisors: Arc<Mutex<SupervisorState>>,
    settlements: Arc<Mutex<SupervisorSettlements>>,
    #[cfg(test)]
    registration_hook: Arc<Mutex<Option<RegistrationHook>>>,
    #[cfg(test)]
    before_plan_hook: Arc<Mutex<Option<BeforePlanHook>>>,
    #[cfg(test)]
    lifecycle_post_reservation_delay: Arc<Mutex<Option<Duration>>>,
    #[cfg(test)]
    lifecycle_reaped_hook: Arc<Mutex<Option<LifecycleReapedHook>>>,
    #[cfg(test)]
    lifecycle_mutation_hook: Arc<Mutex<Option<LifecycleMutationHook>>>,
    #[cfg(test)]
    lifecycle_recovery_hook: Arc<Mutex<Option<LifecycleRecoveryHook>>>,
    #[cfg(test)]
    durable_handoff_source_hook: Arc<Mutex<Option<DurableHandoffSourceHook>>>,
}

impl WorkerCoordinator {
    fn new(registry: WorkerRegistry) -> Self {
        Self {
            registry: Arc::new(Mutex::new(registry)),
            supervisors: Arc::new(Mutex::new(SupervisorState {
                shutting_down: false,
                active_permits: 0,
                pending_admissions: 0,
                handles: Vec::with_capacity(MAX_SUPERVISORS),
                shutdown_workers: Vec::with_capacity(MAX_PROCESS_OWNERS),
                shutdown_attempt: 0,
                shutdown_status: None,
                shutdown_completion: None,
            })),
            settlements: Arc::new(Mutex::new(SupervisorSettlements::new())),
            #[cfg(test)]
            registration_hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            before_plan_hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            lifecycle_post_reservation_delay: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            lifecycle_reaped_hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            lifecycle_mutation_hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            lifecycle_recovery_hook: Arc::new(Mutex::new(None)),
            #[cfg(test)]
            durable_handoff_source_hook: Arc::new(Mutex::new(None)),
        }
    }

    /// Dormant production handoff from one unique durable Prepare intent to one authenticated,
    /// passive worker generation.
    ///
    /// The caller's absolute deadline is carried unchanged through journal registration, worker
    /// admission and recovery-anchor derivation/revalidation into the affine custody-publication
    /// owner. This seam stops before publication or durable arming; only the separate attested seam
    /// may arm under that same deadline. It sends no child protocol request and performs no
    /// `WireGuard` link/address, route, firewall or dataplane configuration; worker launch still
    /// creates the deliberately isolated process and anonymous NEWNET.
    #[allow(dead_code)] // Connected only after the durable production coordinator is installed.
    fn durable_passive_prepare_handoff_until(
        &self,
        actor: &DurableOwnershipActor,
        registration: DurableIntentRegistration,
        worker_ttl: Duration,
        deadline: HardDeadline,
    ) -> DurableWorkerPrepareOutcome {
        self.durable_passive_prepare_handoff_with_until(
            actor,
            registration,
            worker_ttl,
            deadline,
            spawn_worker_v3_until,
        )
    }

    fn durable_passive_prepare_handoff_with_until<Spawn>(
        &self,
        actor: &DurableOwnershipActor,
        registration: DurableIntentRegistration,
        worker_ttl: Duration,
        deadline: HardDeadline,
        spawn: Spawn,
    ) -> DurableWorkerPrepareOutcome
    where
        Spawn: FnOnce(
            GenerationReservation,
            HardDeadline,
        ) -> Result<SpawnedWorker, WorkerSpawnFailure>,
    {
        // Crossing the durable Intent boundary must precede even a local generation reservation,
        // so cancellation can never leave an unjournalled authenticated worker generation.
        let context_id = registration.context_id();
        let key = match actor.register_until(registration, deadline) {
            DurableRegistrationOutcome::Registered(key) => key,
            DurableRegistrationOutcome::Retained {
                error,
                registration,
            } => {
                return DurableWorkerPrepareOutcome::RegistrationRetained {
                    error,
                    registration,
                };
            }
        };

        let worker = match self.reserve_spawn_register_durable_handoff_with_until(
            context_id, worker_ttl, deadline, spawn,
        ) {
            WorkerLifecycleAdmission::Registered(worker) => worker,
            WorkerLifecycleAdmission::Rejected(error) => {
                return DurableWorkerPrepareOutcome::KeyRetained { error, key };
            }
            WorkerLifecycleAdmission::Retained { error, ownership } => {
                return DurableWorkerPrepareOutcome::WorkerAdmissionRetained {
                    error,
                    key,
                    worker: ownership,
                };
            }
        };
        self.finish_durable_registered_worker_handoff_until(context_id, key, worker, deadline)
    }

    fn finish_durable_registered_worker_handoff_until(
        &self,
        context_id: ContextId,
        key: DurableOwnershipKey,
        worker: WorkerGenerationOwnership,
        deadline: HardDeadline,
    ) -> DurableWorkerPrepareOutcome {
        if worker.coordinates.context_id != context_id
            || !worker.has_valid_dispatch_fence_shape()
            || worker.dispatch_registration != WorkerDispatchRegistration::DurableHandoffPending
            || !matches!(
                worker.placement.as_ref(),
                Some(WorkerGenerationPlacement::Registered)
            )
        {
            return DurableWorkerPrepareOutcome::WorkerAdmissionRetained {
                error: WorkerV3Error::Conflict,
                key,
                worker,
            };
        }
        let registered = DurableRegisteredStartingWorker { key, worker };

        let source = match self
            .durable_handoff_recovery_identity_source_until(&registered.worker, deadline)
        {
            Ok(source) => source,
            Err(error) => {
                return DurableWorkerPrepareOutcome::RegisteredWorkerRetained { error, registered };
            }
        };
        if source.pending.coordinates != registered.worker.coordinates {
            return DurableWorkerPrepareOutcome::HandoffWorkerRetained {
                error: WorkerV3Error::Stale,
                handoff: DurableWorkerPrepareHandoff { registered, source },
            };
        }
        let handoff = DurableWorkerPrepareHandoff { registered, source };
        #[cfg(test)]
        if let Some(hook) = self
            .durable_handoff_source_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            let _ = hook.derived.send(());
            let (released, changed) = hook.release.as_ref();
            let mut released = released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            while !*released {
                released = changed
                    .wait(released)
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
            }
        }
        if let Err(error) = self.revalidate_durable_recovery_identity_until(
            &handoff.registered.worker,
            &handoff.source,
            deadline,
        ) {
            return DurableWorkerPrepareOutcome::HandoffWorkerRetained { error, handoff };
        }
        let custody_name = crate::systemd_fdstore::CustodyFdName::from_durable_digest(
            handoff.registered.key.custody_name_digest(),
        );
        DurableWorkerPrepareOutcome::CustodyPublication(DurableWorkerCustodyPublicationOwner {
            custody_name,
            deadline,
            handoff,
        })
    }

    /// Dormant synchronous transition from exact systemd inventory evidence to durable arming.
    ///
    /// The publication owner supplies its original absolute deadline. This seam performs no
    /// publication, retry, reconciliation, child request or kernel mutation; it accepts only an
    /// opaque attestation produced by the descriptor-store adapter and retains every affine owner
    /// plus that evidence on every failure.
    #[allow(dead_code)] // Connected only after a non-cancellable publication supervisor exists.
    fn arm_attested_durable_worker(
        &self,
        actor: &DurableOwnershipActor,
        publication: DurableWorkerCustodyPublicationOwner,
        attestation: crate::systemd_fdstore::InventoryAttestation,
    ) -> DurableWorkerPostAttestationOutcome {
        if let Err(error) = ensure_worker_deadline(publication.deadline) {
            return DurableWorkerPostAttestationOutcome::PublicationUnresolved {
                error,
                publication,
                attestation,
            };
        }
        let custody_verification = crate::systemd_fdstore::BorrowedCustodyPair::new(
            publication.handoff.source.restart_custody.borrowed_pidfd(),
            publication
                .handoff
                .source
                .restart_custody
                .borrowed_network_namespace(),
        )
        .and_then(|custody| attestation.verify_exact_custody(publication.custody_name, custody));
        if let Err(error) = custody_verification {
            return DurableWorkerPostAttestationOutcome::PublicationUnresolved {
                error: WorkerV3Error::SystemdCustodyInput(error),
                publication,
                attestation,
            };
        }
        if let Err(error) = ensure_worker_deadline(publication.deadline) {
            return DurableWorkerPostAttestationOutcome::PublicationUnresolved {
                error,
                publication,
                attestation,
            };
        }
        if let Err(error) = self.revalidate_durable_recovery_identity_until(
            &publication.handoff.registered.worker,
            &publication.handoff.source,
            publication.deadline,
        ) {
            return DurableWorkerPostAttestationOutcome::PublicationUnresolved {
                error,
                publication,
                attestation,
            };
        }
        let anchor = publication.handoff.source.durable_prepare_anchor();
        let DurableWorkerCustodyPublicationOwner {
            custody_name,
            deadline,
            handoff,
        } = publication;
        let DurableWorkerPrepareHandoff { registered, source } = handoff;
        let DurableRegisteredStartingWorker { key, worker } = registered;

        match actor.arm_until(key, anchor, deadline) {
            DurableArmOutcome::Armed(durable) => {
                let may_own = DurableWorkerMayOwnPrepare {
                    durable,
                    worker,
                    source,
                    custody_name,
                    attestation,
                };
                if may_own.durable.context_id() == may_own.worker.coordinates.context_id {
                    DurableWorkerPostAttestationOutcome::MayOwn(may_own)
                } else {
                    DurableWorkerPostAttestationOutcome::ContextMismatch(may_own)
                }
            }
            DurableArmOutcome::Retained { error, key } => {
                DurableWorkerPostAttestationOutcome::ArmRetained {
                    error,
                    publication: DurableWorkerCustodyPublicationOwner {
                        custody_name,
                        deadline,
                        handoff: DurableWorkerPrepareHandoff {
                            registered: DurableRegisteredStartingWorker { key, worker },
                            source,
                        },
                    },
                    attestation,
                }
            }
        }
    }

    /// Dormant production seam: reserves a coordinator-local worker generation, authenticates one
    /// worker, then commits that exact reservation without issuing any child operation.
    #[allow(dead_code)] // Connected only after durable recovery identity is complete.
    fn reserve_spawn_register_until(
        &self,
        context_id: ContextId,
        ttl: Duration,
        deadline: HardDeadline,
    ) -> WorkerLifecycleAdmission {
        self.reserve_spawn_register_with_until(context_id, ttl, deadline, spawn_worker_v3_until)
    }

    fn reserve_spawn_register_with_until<Spawn>(
        &self,
        context_id: ContextId,
        ttl: Duration,
        deadline: HardDeadline,
        spawn: Spawn,
    ) -> WorkerLifecycleAdmission
    where
        Spawn: FnOnce(
            GenerationReservation,
            HardDeadline,
        ) -> Result<SpawnedWorker, WorkerSpawnFailure>,
    {
        self.reserve_spawn_register_with_dispatch_until(
            context_id,
            ttl,
            deadline,
            WorkerDispatchRegistration::Open,
            spawn,
        )
    }

    fn reserve_spawn_register_durable_handoff_with_until<Spawn>(
        &self,
        context_id: ContextId,
        ttl: Duration,
        deadline: HardDeadline,
        spawn: Spawn,
    ) -> WorkerLifecycleAdmission
    where
        Spawn: FnOnce(
            GenerationReservation,
            HardDeadline,
        ) -> Result<SpawnedWorker, WorkerSpawnFailure>,
    {
        self.reserve_spawn_register_with_dispatch_until(
            context_id,
            ttl,
            deadline,
            WorkerDispatchRegistration::DurableHandoffPending,
            spawn,
        )
    }

    fn reserve_spawn_register_with_dispatch_until<Spawn>(
        &self,
        context_id: ContextId,
        ttl: Duration,
        deadline: HardDeadline,
        dispatch_registration: WorkerDispatchRegistration,
        spawn: Spawn,
    ) -> WorkerLifecycleAdmission
    where
        Spawn: FnOnce(
            GenerationReservation,
            HardDeadline,
        ) -> Result<SpawnedWorker, WorkerSpawnFailure>,
    {
        if let Err(error) = ensure_worker_deadline(deadline) {
            return WorkerLifecycleAdmission::Rejected(error);
        }
        let reservation = {
            let mut registry = match lock_worker_registry_until(&self.registry, deadline) {
                Ok(registry) => registry,
                Err(error) => return WorkerLifecycleAdmission::Rejected(error),
            };
            let reservation = match registry.reserve_generation(context_id, ttl, Instant::now()) {
                Ok(reservation) => reservation,
                Err(error) => return WorkerLifecycleAdmission::Rejected(error),
            };
            if let Err(error) = registry.retain_generation_for_lifecycle(&reservation) {
                let coordinates = WorkerGenerationCoordinates {
                    context_id: reservation.context_id,
                    worker_generation: NonZeroU64::new(reservation.generation)
                        .unwrap_or_else(|| std::process::abort()),
                };
                return WorkerLifecycleAdmission::Retained {
                    error,
                    ownership: WorkerGenerationOwnership {
                        registry: Arc::clone(&self.registry),
                        coordinates,
                        dispatch_registration,
                        handoff_fence: None,
                        placement: Some(WorkerGenerationPlacement::LifecycleReservation(
                            reservation,
                        )),
                    },
                };
            }
            reservation
        };
        let coordinates = WorkerGenerationCoordinates {
            context_id: reservation.context_id,
            worker_generation: NonZeroU64::new(reservation.generation)
                .unwrap_or_else(|| std::process::abort()),
        };
        let mut ownership = WorkerGenerationOwnership {
            registry: Arc::clone(&self.registry),
            coordinates,
            dispatch_registration,
            handoff_fence: None,
            placement: Some(WorkerGenerationPlacement::LifecycleReservation(reservation)),
        };

        #[cfg(test)]
        if let Some(delay) = *self
            .lifecycle_post_reservation_delay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
        {
            thread::sleep(delay);
        }
        if let Err(error) = ensure_worker_deadline(deadline) {
            return WorkerLifecycleAdmission::Retained { error, ownership };
        }
        let Some(WorkerGenerationPlacement::LifecycleReservation(reservation)) =
            ownership.placement.take()
        else {
            std::process::abort();
        };

        match spawn(reservation, deadline) {
            Ok(spawned) => {
                ownership.placement = Some(WorkerGenerationPlacement::Spawned(Box::new(spawned)));
                self.commit_spawned_lifecycle_until(ownership, deadline)
            }
            Err(WorkerSpawnFailure {
                error: WorkerV3Error::Ambiguous,
                reservation,
            }) => {
                ownership.placement = Some(WorkerGenerationPlacement::SpawnAmbiguous(reservation));
                WorkerLifecycleAdmission::Retained {
                    error: WorkerV3Error::Ambiguous,
                    ownership,
                }
            }
            Err(WorkerSpawnFailure { error, reservation }) => {
                ownership.placement =
                    Some(WorkerGenerationPlacement::LifecycleReservation(reservation));
                match self.settle_lifecycle_ownership_until(ownership, deadline) {
                    WorkerLifecycleSettlement::ConfirmedAbsent(_) => {
                        WorkerLifecycleAdmission::Rejected(error)
                    }
                    WorkerLifecycleSettlement::Retained {
                        error: settlement_error,
                        ownership,
                    } => WorkerLifecycleAdmission::Retained {
                        error: settlement_error,
                        ownership,
                    },
                    WorkerLifecycleSettlement::Registered(ownership) => {
                        WorkerLifecycleAdmission::Retained {
                            error: WorkerV3Error::Ambiguous,
                            ownership,
                        }
                    }
                }
            }
        }
    }

    fn commit_spawned_lifecycle_until(
        &self,
        mut ownership: WorkerGenerationOwnership,
        deadline: HardDeadline,
    ) -> WorkerLifecycleAdmission {
        if !Arc::ptr_eq(&ownership.registry, &self.registry) {
            return WorkerLifecycleAdmission::Retained {
                error: WorkerV3Error::Stale,
                ownership,
            };
        }
        if !ownership.has_valid_dispatch_fence_shape() {
            return WorkerLifecycleAdmission::Retained {
                error: WorkerV3Error::Conflict,
                ownership,
            };
        }
        let Some(WorkerGenerationPlacement::Spawned(spawned)) = ownership.placement.take() else {
            return WorkerLifecycleAdmission::Retained {
                error: WorkerV3Error::Conflict,
                ownership,
            };
        };
        let mut registry = match lock_worker_registry_until(&self.registry, deadline) {
            Ok(registry) => registry,
            Err(error) => {
                ownership.placement = Some(WorkerGenerationPlacement::Spawned(spawned));
                return WorkerLifecycleAdmission::Retained { error, ownership };
            }
        };
        #[cfg(test)]
        self.reach_lifecycle_mutation_hook(LifecycleMutationPoint::Commit);
        if let Err(error) = ensure_worker_deadline(deadline) {
            ownership.placement = Some(WorkerGenerationPlacement::Spawned(spawned));
            return WorkerLifecycleAdmission::Retained { error, ownership };
        }
        match registry.commit_spawned_with_dispatch(
            *spawned,
            Instant::now(),
            ownership.dispatch_registration,
        ) {
            Ok(commit) => {
                let (worker_generation, handoff_fence) = match commit {
                    WorkerRegistrationCommit::Open(worker_generation) => {
                        if ownership.dispatch_registration != WorkerDispatchRegistration::Open {
                            std::process::abort();
                        }
                        (worker_generation, None)
                    }
                    WorkerRegistrationCommit::DurableHandoffPending { generation, fence } => {
                        if ownership.dispatch_registration
                            != WorkerDispatchRegistration::DurableHandoffPending
                        {
                            std::process::abort();
                        }
                        (generation, Some(fence))
                    }
                };
                if worker_generation != ownership.coordinates.worker_generation.get() {
                    std::process::abort();
                }
                ownership.handoff_fence = handoff_fence;
                ownership.placement = Some(WorkerGenerationPlacement::Registered);
                WorkerLifecycleAdmission::Registered(ownership)
            }
            Err(RegistrationFailure {
                error,
                process,
                reservation,
            }) => {
                drop(registry);
                ownership.placement = Some(WorkerGenerationPlacement::Detached(Box::new(
                    LifecycleDetachedOwnership {
                        worker: DetachedWorker {
                            context_id: ownership.coordinates.context_id,
                            generation: ownership.coordinates.worker_generation.get(),
                            process: *process,
                        },
                        reservation,
                    },
                )));
                WorkerLifecycleAdmission::Retained { error, ownership }
            }
        }
    }

    fn settle_lifecycle_ownership_until(
        &self,
        ownership: WorkerGenerationOwnership,
        deadline: HardDeadline,
    ) -> WorkerLifecycleSettlement {
        if !Arc::ptr_eq(&ownership.registry, &self.registry) {
            return WorkerLifecycleSettlement::Retained {
                error: WorkerV3Error::Stale,
                ownership,
            };
        }
        if !ownership.has_valid_dispatch_fence_shape() {
            return WorkerLifecycleSettlement::Retained {
                error: WorkerV3Error::Conflict,
                ownership,
            };
        }
        match ownership.placement.as_ref() {
            Some(WorkerGenerationPlacement::Registered) => {
                return WorkerLifecycleSettlement::Registered(ownership);
            }
            Some(WorkerGenerationPlacement::SpawnAmbiguous(_)) => {
                return WorkerLifecycleSettlement::Retained {
                    error: WorkerV3Error::Ambiguous,
                    ownership,
                };
            }
            Some(
                WorkerGenerationPlacement::Detached(_)
                | WorkerGenerationPlacement::ReapedPendingPurge(_),
            )
            | None => {
                return WorkerLifecycleSettlement::Retained {
                    error: WorkerV3Error::Conflict,
                    ownership,
                };
            }
            Some(WorkerGenerationPlacement::LifecycleReservation(_)) => {}
            Some(WorkerGenerationPlacement::Spawned(_)) => {
                return match self.commit_spawned_lifecycle_until(ownership, deadline) {
                    WorkerLifecycleAdmission::Registered(ownership) => {
                        WorkerLifecycleSettlement::Registered(ownership)
                    }
                    WorkerLifecycleAdmission::Retained { error, ownership } => {
                        WorkerLifecycleSettlement::Retained { error, ownership }
                    }
                    WorkerLifecycleAdmission::Rejected(_) => std::process::abort(),
                };
            }
        }

        let registry_result = lock_worker_registry_until(&self.registry, deadline);
        let mut registry = match registry_result {
            Ok(registry) => registry,
            Err(error) => {
                return WorkerLifecycleSettlement::Retained { error, ownership };
            }
        };
        let Some(WorkerGenerationPlacement::LifecycleReservation(reservation)) =
            ownership.placement.as_ref()
        else {
            std::process::abort();
        };
        #[cfg(test)]
        self.reach_lifecycle_mutation_hook(LifecycleMutationPoint::Settlement);
        if let Err(error) = registry.purge_and_abandon_unspawned_lifecycle_generation(
            reservation,
            ownership.coordinates,
            deadline,
        ) {
            return WorkerLifecycleSettlement::Retained { error, ownership };
        }
        drop(registry);
        WorkerLifecycleSettlement::ConfirmedAbsent(ConfirmedWorkerGenerationAbsent {
            coordinates: ownership.coordinates,
        })
    }

    /// Returns only identity material re-derived from the exact registered worker's retained,
    /// authenticated namespace pin. Process liveness is checked outside the registry mutex.
    fn recovery_identity_source_until(
        &self,
        ownership: &WorkerGenerationOwnership,
        deadline: HardDeadline,
    ) -> Result<WorkerRecoveryIdentitySource, WorkerV3Error> {
        if ownership.dispatch_registration != WorkerDispatchRegistration::Open
            || ownership.handoff_fence.is_some()
        {
            return Err(WorkerV3Error::Stale);
        }
        self.recovery_identity_source_with_dispatch_fence_until(ownership, None, deadline)
    }

    fn durable_handoff_recovery_identity_source_until(
        &self,
        ownership: &WorkerGenerationOwnership,
        deadline: HardDeadline,
    ) -> Result<WorkerRecoveryIdentitySource, WorkerV3Error> {
        if ownership.dispatch_registration != WorkerDispatchRegistration::DurableHandoffPending {
            return Err(WorkerV3Error::Stale);
        }
        let fence = ownership
            .handoff_fence
            .as_ref()
            .ok_or(WorkerV3Error::Stale)?;
        self.recovery_identity_source_with_dispatch_fence_until(ownership, Some(fence), deadline)
    }

    fn recovery_identity_source_with_dispatch_fence_until(
        &self,
        ownership: &WorkerGenerationOwnership,
        handoff_fence: Option<&DurableHandoffFenceOwner>,
        deadline: HardDeadline,
    ) -> Result<WorkerRecoveryIdentitySource, WorkerV3Error> {
        ensure_worker_deadline(deadline)?;
        let dispatch_pair_exact = match (
            ownership.dispatch_registration,
            ownership.handoff_fence.as_ref(),
            handoff_fence,
        ) {
            (WorkerDispatchRegistration::Open, None, None) => true,
            (WorkerDispatchRegistration::DurableHandoffPending, Some(retained), Some(supplied)) => {
                retained.coordinates == ownership.coordinates
                    && supplied.coordinates == ownership.coordinates
            }
            _ => false,
        };
        if !Arc::ptr_eq(&ownership.registry, &self.registry)
            || !dispatch_pair_exact
            || !matches!(
                ownership.placement.as_ref(),
                Some(WorkerGenerationPlacement::Registered)
            )
        {
            return Err(WorkerV3Error::Stale);
        }
        let registry = lock_worker_registry_until(&self.registry, deadline)?;
        if let Some(fence) = handoff_fence {
            registry.confirm_durable_handoff_pending(ownership.coordinates, fence)?;
        } else {
            let record = registry
                .records
                .get(&ownership.coordinates.context_id)
                .ok_or(WorkerV3Error::Dead)?;
            if record.generation != ownership.coordinates.worker_generation.get()
                || record.dispatch_fence != WorkerDispatchFence::Open
            {
                return Err(WorkerV3Error::Stale);
            }
        }
        let pending = registry.recovery_identity_owners(ownership.coordinates, deadline)?;
        drop(registry);
        ensure_worker_deadline(deadline)?;
        let proof = pending
            .authenticated_pins
            .verified_anchor_with_restart_custody();
        ensure_worker_deadline(deadline)?;
        let (parts, restart_custody) = proof?;
        if parts.pid != pending.expected_child_pid {
            return Err(WorkerV3Error::Authentication);
        }
        let durable_prepare_anchor = durable_prepare_anchor_from_worker_parts(parts)?;
        ensure_worker_deadline(deadline)?;
        #[cfg(test)]
        if let Some(hook) = self
            .lifecycle_recovery_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone()
        {
            hook.pinned.wait();
            hook.release.wait();
        }
        let registry = lock_worker_registry_until(&self.registry, deadline)?;
        if let Some(fence) = handoff_fence {
            registry.confirm_durable_handoff_pending(ownership.coordinates, fence)?;
        } else {
            let record = registry
                .records
                .get(&ownership.coordinates.context_id)
                .ok_or(WorkerV3Error::Dead)?;
            if record.generation != ownership.coordinates.worker_generation.get()
                || record.dispatch_fence != WorkerDispatchFence::Open
            {
                return Err(WorkerV3Error::Stale);
            }
        }
        registry.confirm_recovery_identity_source(&pending)?;
        ensure_worker_deadline(deadline)?;
        drop(registry);
        ensure_worker_deadline(deadline)?;
        Ok(WorkerRecoveryIdentitySource {
            pending,
            durable_prepare_anchor,
            restart_custody,
        })
    }

    /// Revalidates the complete pinned identity immediately before an audited custody boundary.
    ///
    /// Potentially blocking pidfd and process-liveness observations happen without the registry
    /// mutex. A second exact registry observation then fences replacement, phase changes, expiry,
    /// quarantine, in-flight work and binding/lifetime changes before this method returns. The
    /// caller may cross only its next audited publication or journal boundary after the final
    /// registry guard is dropped.
    fn revalidate_durable_recovery_identity_until(
        &self,
        ownership: &WorkerGenerationOwnership,
        source: &WorkerRecoveryIdentitySource,
        deadline: HardDeadline,
    ) -> Result<(), WorkerV3Error> {
        ensure_worker_deadline(deadline)?;
        if !Arc::ptr_eq(&ownership.registry, &self.registry)
            || ownership.dispatch_registration != WorkerDispatchRegistration::DurableHandoffPending
            || !matches!(
                ownership.placement.as_ref(),
                Some(WorkerGenerationPlacement::Registered)
            )
            || ownership.coordinates != source.pending.coordinates
        {
            return Err(WorkerV3Error::Stale);
        }
        let fence = ownership
            .handoff_fence
            .as_ref()
            .ok_or(WorkerV3Error::Stale)?;

        source.pending.authenticated_pins.ensure_alive()?;
        let anchor = source
            .pending
            .authenticated_pins
            .verified_recovery_anchor_parts()?;
        if durable_prepare_anchor_from_worker_parts(anchor)? != source.durable_prepare_anchor {
            return Err(WorkerV3Error::Authentication);
        }
        source
            .restart_custody
            .ensure_live_and_namespace_matches_anchor(anchor)?;
        ensure_worker_deadline(deadline)?;
        let liveness = {
            let registry = lock_worker_registry_until(&self.registry, deadline)?;
            registry.confirm_durable_handoff_pending(ownership.coordinates, fence)?;
            registry.confirm_recovery_identity_source(&source.pending)?;
            let liveness = registry
                .recovery_identity_process(ownership.coordinates)?
                .liveness();
            ensure_worker_deadline(deadline)?;
            liveness
        };
        if !liveness.probe_alive_until(deadline)? {
            return Err(WorkerV3Error::Dead);
        }
        ensure_worker_deadline(deadline)?;
        let registry = lock_worker_registry_until(&self.registry, deadline)?;
        registry.confirm_durable_handoff_pending(ownership.coordinates, fence)?;
        registry.confirm_recovery_identity_source(&source.pending)?;
        ensure_worker_deadline(deadline)?;
        drop(registry);
        ensure_worker_deadline(deadline)
    }

    fn transition_registered_generation_until(
        &self,
        coordinates: WorkerGenerationCoordinates,
        deadline: HardDeadline,
    ) -> RegisteredGenerationTransition {
        let mut registry = match lock_worker_registry_until(&self.registry, deadline) {
            Ok(registry) => registry,
            Err(error) => return RegisteredGenerationTransition::Retained(error),
        };
        #[cfg(test)]
        self.reach_lifecycle_mutation_hook(LifecycleMutationPoint::Detach);
        if let Err(error) = ensure_worker_deadline(deadline) {
            return RegisteredGenerationTransition::Retained(error);
        }
        let generation_absent = registry.exact_generation_absent(coordinates);
        #[cfg(test)]
        self.reach_lifecycle_mutation_hook(LifecycleMutationPoint::PostAbsenceObservation);
        if let Err(error) = ensure_worker_deadline(deadline) {
            return RegisteredGenerationTransition::Retained(error);
        }
        if generation_absent {
            return RegisteredGenerationTransition::Confirmed(ConfirmedWorkerGenerationAbsent {
                coordinates,
            });
        }
        match registry.report_dead(coordinates.context_id, coordinates.worker_generation.get()) {
            Ok(Some(worker)) => {
                RegisteredGenerationTransition::Detached(Box::new(LifecycleDetachedOwnership {
                    worker,
                    reservation: None,
                }))
            }
            Ok(None) => RegisteredGenerationTransition::Retained(WorkerV3Error::Ambiguous),
            Err(error) => RegisteredGenerationTransition::Retained(error),
        }
    }

    /// Makes one hard-deadline-bounded attempt to reap exactly the owned worker generation.
    ///
    /// Timeout, fatal observation, registry contention and proof mismatch all return the same
    /// affine owner. A caller may retry that exact generation with a fresh deadline; no ambiguous
    /// result can be converted into confirmed absence.
    fn terminate_generation_until(
        &self,
        mut ownership: WorkerGenerationOwnership,
        deadline: HardDeadline,
    ) -> WorkerGenerationReap {
        if !Arc::ptr_eq(&ownership.registry, &self.registry) {
            return retained_worker_generation(WorkerV3Error::Stale, ownership);
        }
        if !ownership.has_valid_dispatch_fence_shape() {
            return retained_worker_generation(WorkerV3Error::Conflict, ownership);
        }
        let Some(placement) = ownership.placement.take() else {
            std::process::abort();
        };
        let detached = match placement {
            WorkerGenerationPlacement::LifecycleReservation(reservation) => {
                ownership.placement =
                    Some(WorkerGenerationPlacement::LifecycleReservation(reservation));
                return retained_worker_generation(WorkerV3Error::Conflict, ownership);
            }
            WorkerGenerationPlacement::SpawnAmbiguous(reservation) => {
                ownership.placement = Some(WorkerGenerationPlacement::SpawnAmbiguous(reservation));
                return retained_worker_generation(WorkerV3Error::Ambiguous, ownership);
            }
            WorkerGenerationPlacement::Spawned(spawned) => {
                ownership.placement = Some(WorkerGenerationPlacement::Spawned(spawned));
                return retained_worker_generation(WorkerV3Error::Conflict, ownership);
            }
            WorkerGenerationPlacement::Registered => {
                match self.transition_registered_generation_until(ownership.coordinates, deadline) {
                    RegisteredGenerationTransition::Confirmed(proof) => {
                        return WorkerGenerationReap::Confirmed(proof);
                    }
                    RegisteredGenerationTransition::Detached(detached) => detached,
                    RegisteredGenerationTransition::Retained(error) => {
                        ownership.placement = Some(WorkerGenerationPlacement::Registered);
                        return retained_worker_generation(error, ownership);
                    }
                }
            }
            WorkerGenerationPlacement::Detached(detached) => detached,
            WorkerGenerationPlacement::ReapedPendingPurge(detached) => {
                ownership.placement = Some(WorkerGenerationPlacement::ReapedPendingPurge(detached));
                return self.finish_reaped_generation_until(ownership, deadline);
            }
        };

        let outcome = detached
            .worker
            .process
            .liveness()
            .termination_outcome_until(deadline);
        match outcome {
            TerminationOutcome::Reaped => {
                ownership.placement = Some(WorkerGenerationPlacement::ReapedPendingPurge(detached));
                #[cfg(test)]
                if let Some(hook) = self
                    .lifecycle_reaped_hook
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .clone()
                {
                    hook.reached.wait();
                    hook.release.wait();
                }
                self.finish_reaped_generation_until(ownership, deadline)
            }
            TerminationOutcome::TimedOut => {
                ownership.placement = Some(WorkerGenerationPlacement::Detached(detached));
                retained_worker_generation(
                    if ensure_worker_deadline(deadline).is_err() {
                        WorkerV3Error::Deadline
                    } else {
                        WorkerV3Error::Ambiguous
                    },
                    ownership,
                )
            }
            TerminationOutcome::Fatal => {
                ownership.placement = Some(WorkerGenerationPlacement::Detached(detached));
                retained_worker_generation(WorkerV3Error::Ambiguous, ownership)
            }
        }
    }

    fn finish_reaped_generation_until(
        &self,
        mut ownership: WorkerGenerationOwnership,
        deadline: HardDeadline,
    ) -> WorkerGenerationReap {
        if !ownership.has_valid_dispatch_fence_shape() {
            return retained_worker_generation(WorkerV3Error::Conflict, ownership);
        }
        let Some(WorkerGenerationPlacement::ReapedPendingPurge(detached)) =
            ownership.placement.take()
        else {
            return retained_worker_generation(WorkerV3Error::Conflict, ownership);
        };
        let mut registry = match lock_worker_registry_until(&self.registry, deadline) {
            Ok(registry) => registry,
            Err(error) => {
                ownership.placement = Some(WorkerGenerationPlacement::ReapedPendingPurge(detached));
                return retained_worker_generation(error, ownership);
            }
        };
        #[cfg(test)]
        self.reach_lifecycle_mutation_hook(LifecycleMutationPoint::Purge);
        if let Err(error) = ensure_worker_deadline(deadline) {
            ownership.placement = Some(WorkerGenerationPlacement::ReapedPendingPurge(detached));
            return retained_worker_generation(error, ownership);
        }
        if let Some(reservation) = detached.reservation.as_ref() {
            if registry.exact_lifecycle_reservation_present(reservation)
                && registry.abandon_generation_ref(reservation).is_err()
            {
                ownership.placement = Some(WorkerGenerationPlacement::ReapedPendingPurge(detached));
                return retained_worker_generation(WorkerV3Error::Ambiguous, ownership);
            }
        }
        if let Err(error) = registry.purge_or_confirm_generation_absent(ownership.coordinates) {
            ownership.placement = Some(WorkerGenerationPlacement::ReapedPendingPurge(detached));
            return retained_worker_generation(error, ownership);
        }
        // Exact registry absence is proven while pidfd, proc-directory and netns pins are still
        // owned by `detached`. A retry after this point observes the already-absent state
        // idempotently and does not signal or wait for the worker again.
        drop(registry);
        if let Err(error) = detached
            .worker
            .process
            .disarm_retirement_for_shutdown(deadline)
        {
            ownership.placement = Some(WorkerGenerationPlacement::ReapedPendingPurge(detached));
            return retained_worker_generation(error, ownership);
        }
        drop(detached);
        WorkerGenerationReap::Confirmed(ConfirmedWorkerGenerationAbsent {
            coordinates: ownership.coordinates,
        })
    }

    fn acquire_supervisor_permit(&self) -> Result<SupervisorPermit, WorkerV3Error> {
        let mut state = self
            .supervisors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if state.shutting_down {
            return Err(WorkerV3Error::ShuttingDown);
        }
        state.handles.retain(|handle| !handle.is_finished());
        let Some(occupied_slots) = state.handles.len().checked_add(state.pending_admissions) else {
            std::process::abort();
        };
        if occupied_slots > MAX_SUPERVISORS
            || state.active_permits > occupied_slots
            || state.active_permits > MAX_SUPERVISORS
        {
            std::process::abort();
        }
        if occupied_slots == MAX_SUPERVISORS || state.active_permits == MAX_SUPERVISORS {
            return Err(WorkerV3Error::Capacity);
        }
        let Some(active_permits) = state.active_permits.checked_add(1) else {
            std::process::abort();
        };
        let Some(pending_admissions) = state.pending_admissions.checked_add(1) else {
            std::process::abort();
        };
        state.active_permits = active_permits;
        state.pending_admissions = pending_admissions;
        Ok(SupervisorPermit {
            supervisors: Arc::clone(&self.supervisors),
            stage: SupervisorPermitStage::Pending,
        })
    }

    async fn execute(
        &self,
        context_id: ContextId,
        generation: u64,
        request: InternalWorkerRequest,
    ) -> Result<CredentialedWorkerExecution, WorkerV3Error> {
        let deadline = HardDeadline::after(CHANNEL_TIMEOUT).map_err(WorkerV3Error::Io)?;
        self.execute_until(context_id, generation, request, deadline)
            .await
    }

    async fn execute_until(
        &self,
        context_id: ContextId,
        generation: u64,
        request: InternalWorkerRequest,
        deadline: HardDeadline,
    ) -> Result<CredentialedWorkerExecution, WorkerV3Error> {
        ensure_worker_deadline(deadline)?;
        let runtime =
            tokio::runtime::Handle::try_current().map_err(|_| WorkerV3Error::RuntimeUnavailable)?;
        let supervisor_permit = self.acquire_supervisor_permit()?;
        #[cfg(test)]
        {
            let hook = self
                .before_plan_hook
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(hook) = hook {
                hook.reached.notify_one();
                let permit = hook
                    .release
                    .acquire()
                    .await
                    .expect("before-plan test release semaphore");
                drop(permit);
            }
        }
        // The pre-plan check is repeated after every await. Expiry here releases the admission
        // permit without creating a tombstone, in-flight token, or registry mutation.
        ensure_worker_deadline(deadline)?;
        let (plan, cleanup_required) = {
            let mut registry = lock_worker_registry(&self.registry);
            let plan =
                registry.plan_until(context_id, generation, &request, Instant::now(), deadline);
            let cleanup_required = plan.is_err()
                && matches!(
                    registry.visible_phase(context_id, generation),
                    Ok(VisiblePhase::Quarantined)
                );
            (plan, cleanup_required)
        };

        #[cfg(test)]
        if plan.is_ok() {
            let hook = self
                .settlements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .supervisor_hook
                .clone();
            if let Some(hook) = hook {
                hook.planned.fetch_add(1, Ordering::SeqCst);
            }
        }

        #[cfg(test)]
        if plan.is_ok() {
            let hook = self
                .registration_hook
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone();
            if let Some(hook) = hook {
                hook.planned.wait();
                hook.release.wait();
            }
        }

        let receiver = match plan {
            Ok(plan) => {
                let failure_token = match &plan {
                    RegistryPlan::Call(call) => Some(call.token),
                    RegistryPlan::Cached(_) => None,
                };
                let supervisor = WorkerSupervisor {
                    registry: Arc::clone(&self.registry),
                    settlements: Arc::clone(&self.settlements),
                };
                self.spawn_supervisor(
                    &runtime,
                    async move { supervisor.run(plan, request).await },
                    supervisor_permit,
                    failure_token,
                )?
            }
            Err(error) if cleanup_required => {
                let supervisor = WorkerSupervisor {
                    registry: Arc::clone(&self.registry),
                    settlements: Arc::clone(&self.settlements),
                };
                self.spawn_supervisor(
                    &runtime,
                    async move {
                        supervisor
                            .retire_quarantined(context_id, generation, error)
                            .await
                    },
                    supervisor_permit,
                    None,
                )?
            }
            Err(error) => return Err(error),
        };
        receiver.await.unwrap_or(Err(WorkerV3Error::Ambiguous))
    }

    fn spawn_supervisor<F>(
        &self,
        runtime: &tokio::runtime::Handle,
        work: F,
        mut permit: SupervisorPermit,
        failure_token: Option<PlanToken>,
    ) -> Result<oneshot::Receiver<Result<CredentialedWorkerExecution, WorkerV3Error>>, WorkerV3Error>
    where
        F: Future<Output = Result<CredentialedWorkerExecution, WorkerV3Error>> + Send + 'static,
    {
        if !Arc::ptr_eq(&permit.supervisors, &self.supervisors)
            || permit.stage != SupervisorPermitStage::Pending
        {
            std::process::abort();
        }

        #[cfg(test)]
        let supervisor_hook = self
            .settlements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .supervisor_hook
            .clone();
        let (sender, receiver) = oneshot::channel();
        let (activation_sender, activation_receiver) = oneshot::channel();
        let settlements = Arc::clone(&self.settlements);
        let supervisor_task = async move {
            let Ok(permit) = activation_receiver.await else {
                return;
            };
            let settlement = SupervisorSettlementGuard::new(settlements, permit);
            #[cfg(test)]
            if let Some(hook) = supervisor_hook {
                hook.started.fetch_add(1, Ordering::SeqCst);
                let release = hook
                    .release
                    .acquire()
                    .await
                    .expect("supervisor test release semaphore");
                drop(release);
            }
            let result = work.await;
            let _ = sender.send(result);
            settlement.settle();
        };
        let Ok(handle) = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            runtime.spawn(supervisor_task)
        })) else {
            drop(permit);
            self.record_supervisor_start_failure(failure_token);
            return Err(WorkerV3Error::RuntimeUnavailable);
        };

        let mut supervisors = self
            .supervisors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if supervisors.shutting_down {
            drop(supervisors);
            drop(activation_sender);
            handle.abort();
            drop(handle);
            drop(permit);
            return Err(WorkerV3Error::ShuttingDown);
        }
        supervisors.handles.retain(|handle| !handle.is_finished());
        let Some(reserved_slots) = supervisors
            .handles
            .len()
            .checked_add(supervisors.pending_admissions)
        else {
            std::process::abort();
        };
        if reserved_slots > MAX_SUPERVISORS
            || supervisors.pending_admissions == 0
            || supervisors.active_permits == 0
            || supervisors.active_permits > MAX_SUPERVISORS
        {
            std::process::abort();
        }
        permit.bind_to_task(&mut supervisors);
        let Some(slots_before_registration) = supervisors
            .handles
            .len()
            .checked_add(supervisors.pending_admissions)
        else {
            std::process::abort();
        };
        if slots_before_registration >= MAX_SUPERVISORS {
            std::process::abort();
        }

        if let Err(permit) = activation_sender.send(permit) {
            drop(supervisors);
            handle.abort();
            drop(handle);
            drop(permit);
            self.record_supervisor_start_failure(failure_token);
            return Err(WorkerV3Error::RuntimeUnavailable);
        }
        supervisors.handles.push(handle);
        if supervisors.handles.len() > MAX_SUPERVISORS {
            std::process::abort();
        }
        Ok(receiver)
    }

    fn record_supervisor_start_failure(&self, token: Option<PlanToken>) {
        let detached = token.and_then(|token| {
            lock_worker_registry(&self.registry)
                .mark_ambiguous(token)
                .ok()
                .flatten()
        });
        if let Some(detached) = detached {
            self.settlements
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .mark_unresolved();
            detached.escalate_to_reaper();
        }
    }

    fn phase(&self, context_id: ContextId, generation: u64) -> Result<VisiblePhase, WorkerV3Error> {
        lock_worker_registry(&self.registry).visible_phase(context_id, generation)
    }

    #[cfg(test)]
    fn set_registration_hook(&self, hook: RegistrationHook) {
        *self
            .registration_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(hook);
    }

    #[cfg(test)]
    fn set_before_plan_hook(&self, hook: BeforePlanHook) {
        *self
            .before_plan_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(hook);
    }

    #[cfg(test)]
    fn set_retirement_hook(&self, hook: RetirementHook) {
        self.settlements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .retirement_hook = Some(hook);
    }

    #[cfg(test)]
    fn set_shutdown_hook(&self, hook: ShutdownHook) {
        self.settlements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .shutdown_hook = Some(hook);
    }

    #[cfg(test)]
    fn set_supervisor_hook(&self, hook: SupervisorHook) {
        self.settlements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .supervisor_hook = Some(hook);
    }

    #[cfg(test)]
    fn set_lifecycle_post_reservation_delay(&self, delay: Duration) {
        *self
            .lifecycle_post_reservation_delay
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(delay);
    }

    #[cfg(test)]
    fn set_lifecycle_reaped_hook(&self, hook: LifecycleReapedHook) {
        *self
            .lifecycle_reaped_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(hook);
    }

    #[cfg(test)]
    fn set_lifecycle_mutation_hook(&self, hook: Option<LifecycleMutationHook>) {
        *self
            .lifecycle_mutation_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    #[cfg(test)]
    fn reach_lifecycle_mutation_hook(&self, point: LifecycleMutationPoint) {
        let hook = self
            .lifecycle_mutation_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        if let Some(hook) = hook.filter(|hook| hook.point == point) {
            hook.reached.wait();
            hook.release.wait();
        }
    }

    #[cfg(test)]
    fn set_lifecycle_recovery_hook(&self, hook: Option<LifecycleRecoveryHook>) {
        *self
            .lifecycle_recovery_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    #[cfg(test)]
    fn set_durable_handoff_source_hook(&self, hook: Option<DurableHandoffSourceHook>) {
        *self
            .durable_handoff_source_hook
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = hook;
    }

    fn shutdown(&self) -> impl Future<Output = bool> + Send + 'static {
        let deadline = HardDeadline::after(CHANNEL_TIMEOUT);
        let shutdown = deadline.ok().map(|deadline| self.shutdown_until(deadline));
        async move {
            let Some(shutdown) = shutdown else {
                return false;
            };
            shutdown.await == ShutdownStatus::Confirmed
        }
    }

    fn shutdown_until(
        &self,
        deadline: HardDeadline,
    ) -> impl Future<Output = ShutdownStatus> + Send + 'static {
        let target = self.shutdown_wait_target(deadline);

        async move {
            match target {
                ShutdownWaitTarget::Immediate(status) => status,
                ShutdownWaitTarget::Attempt(completion) => completion.wait_until(deadline).await,
            }
        }
    }

    fn shutdown_wait_target(&self, deadline: HardDeadline) -> ShutdownWaitTarget {
        let supervisors = self
            .supervisors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        match supervisors.shutdown_status {
            Some(ShutdownStatus::Confirmed) => {
                ShutdownWaitTarget::Immediate(ShutdownStatus::Confirmed)
            }
            Some(ShutdownStatus::Unresolved) => {
                ShutdownWaitTarget::Immediate(ShutdownStatus::Unresolved)
            }
            Some(ShutdownStatus::Pending) => supervisors.shutdown_completion.clone().map_or(
                ShutdownWaitTarget::Immediate(ShutdownStatus::Unresolved),
                ShutdownWaitTarget::Attempt,
            ),
            None | Some(ShutdownStatus::Retryable) => {
                if ensure_worker_deadline(deadline).is_err() {
                    return ShutdownWaitTarget::Immediate(ShutdownStatus::Retryable);
                }
                let runtime = tokio::runtime::Handle::try_current().ok();
                self.begin_shutdown_attempt(supervisors, runtime, deadline)
            }
        }
    }

    fn begin_shutdown_attempt(
        &self,
        mut state: std::sync::MutexGuard<'_, SupervisorState>,
        runtime: Option<tokio::runtime::Handle>,
        deadline: HardDeadline,
    ) -> ShutdownWaitTarget {
        state.shutting_down = true;
        let Some(reserved_slots) = state.handles.len().checked_add(state.pending_admissions) else {
            std::process::abort();
        };
        if reserved_slots > MAX_SUPERVISORS
            || state.active_permits > MAX_SUPERVISORS
            || state.shutdown_workers.len() > MAX_PROCESS_OWNERS
        {
            std::process::abort();
        }

        let mut workers = std::mem::take(&mut state.shutdown_workers);
        workers.append(&mut lock_worker_registry(&self.registry).begin_shutdown());
        if workers.len() > MAX_PROCESS_OWNERS {
            std::process::abort();
        }
        let handles = std::mem::take(&mut state.handles);
        let Some(attempt_id) = state.shutdown_attempt.checked_add(1) else {
            std::process::abort();
        };
        state.shutdown_attempt = attempt_id;
        state.shutdown_status = Some(ShutdownStatus::Pending);
        let completion = ShutdownCompletion::new();
        state.shutdown_completion = Some(completion.clone());
        drop(state);

        let owners = ShutdownAttemptOwners::new(workers, handles);
        let publication = ShutdownPublicationGuard::new(
            Arc::clone(&self.supervisors),
            Arc::clone(&self.settlements),
            attempt_id,
            completion.clone(),
        );
        self.launch_shutdown_attempt(runtime, publication, owners, deadline);
        ShutdownWaitTarget::Attempt(completion)
    }

    fn launch_shutdown_attempt(
        &self,
        runtime: Option<tokio::runtime::Handle>,
        publication: ShutdownPublicationGuard,
        owners: ShutdownAttemptOwners,
        deadline: HardDeadline,
    ) {
        let Some(runtime) = runtime else {
            drop(owners);
            drop(publication);
            return;
        };
        let supervisor = WorkerSupervisor {
            registry: Arc::clone(&self.registry),
            settlements: Arc::clone(&self.settlements),
        };
        let settlements = Arc::clone(&self.settlements);
        let supervisors = Arc::clone(&self.supervisors);
        #[cfg(test)]
        let shutdown_hook = settlements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .shutdown_hook
            .clone();
        let task = async move {
            Self::run_shutdown_attempt(
                supervisor,
                supervisors,
                settlements,
                publication,
                owners,
                deadline,
                #[cfg(test)]
                shutdown_hook,
            )
            .await;
        };
        if let Ok(handle) =
            std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| runtime.spawn(task)))
        {
            drop(handle);
        }
        // A rejected spawn drops the still-owned future: exact process owners escalate and the
        // publication guard makes Unresolved sticky.
    }

    async fn run_shutdown_attempt(
        supervisor: WorkerSupervisor,
        supervisors: Arc<Mutex<SupervisorState>>,
        settlements: Arc<Mutex<SupervisorSettlements>>,
        publication: ShutdownPublicationGuard,
        mut owners: ShutdownAttemptOwners,
        deadline: HardDeadline,
        #[cfg(test)] shutdown_hook: Option<ShutdownHook>,
    ) {
        #[cfg(test)]
        if let Some(hook) = shutdown_hook {
            let released = hook.release.notified();
            tokio::pin!(released);
            hook.started.store(true, Ordering::SeqCst);
            tokio::select! {
                () = &mut released => {}
                () = tokio::time::sleep_until(deadline.expires_at().into()) => {
                    publication.publish(ShutdownStatus::Retryable, owners);
                    return;
                }
            }
        }

        loop {
            if let Err(status) =
                Self::retire_shutdown_workers(&supervisor, &mut owners, deadline).await
            {
                Self::publish_shutdown_status(publication, owners, status);
                return;
            }
            if let Err(status) = Self::await_shutdown_handles(&mut owners, deadline).await {
                Self::publish_shutdown_status(publication, owners, status);
                return;
            }
            if Self::wait_for_shutdown_permits(&supervisors, deadline)
                .await
                .is_err()
            {
                publication.publish(ShutdownStatus::Retryable, owners);
                return;
            }
            match Self::collect_shutdown_sweep(&supervisor, &settlements, &mut owners) {
                Ok(true) => continue,
                Ok(false) => {}
                Err(status) => {
                    Self::publish_shutdown_status(publication, owners, status);
                    return;
                }
            }

            let registry_empty = {
                let registry = lock_worker_registry(&supervisor.registry);
                registry.records.is_empty() && registry.reservations.is_empty()
            };
            let exact_supervisor_state = {
                let state = supervisors
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.active_permits == 0
                    && state.pending_admissions == 0
                    && state.handles.is_empty()
                    && state.shutdown_workers.is_empty()
            };
            if registry_empty
                && exact_supervisor_state
                && owners.workers.is_empty()
                && owners.handles.is_empty()
            {
                let status = if ensure_worker_deadline(deadline).is_ok() {
                    ShutdownStatus::Confirmed
                } else {
                    ShutdownStatus::Retryable
                };
                publication.publish(status, owners);
            } else if exact_supervisor_state
                && (!owners.workers.is_empty() || !owners.handles.is_empty())
            {
                publication.publish(ShutdownStatus::Retryable, owners);
            } else {
                Self::publish_shutdown_status(publication, owners, ShutdownStatus::Unresolved);
            }
            return;
        }
    }

    async fn retire_shutdown_workers(
        supervisor: &WorkerSupervisor,
        owners: &mut ShutdownAttemptOwners,
        deadline: HardDeadline,
    ) -> Result<(), ShutdownStatus> {
        let mut retryable = Vec::new();
        while let Some(worker) = owners.workers.pop() {
            if ensure_worker_deadline(deadline).is_err() {
                retryable.push(worker);
                retryable.append(&mut owners.workers);
                owners.workers = retryable;
                return Err(ShutdownStatus::Retryable);
            }
            match supervisor.retire_for_shutdown_until(worker, deadline).await {
                ShutdownRetirement::Confirmed => {}
                ShutdownRetirement::Retryable(worker) => retryable.push(*worker),
                ShutdownRetirement::Unresolved => {
                    owners.workers.append(&mut retryable);
                    return Err(ShutdownStatus::Unresolved);
                }
            }
        }
        owners.workers = retryable;
        Ok(())
    }

    async fn await_shutdown_handles(
        owners: &mut ShutdownAttemptOwners,
        deadline: HardDeadline,
    ) -> Result<(), ShutdownStatus> {
        let mut pending = Vec::new();
        while let Some(mut handle) = owners.handles.pop() {
            if ensure_worker_deadline(deadline).is_err() {
                pending.push(handle);
                pending.append(&mut owners.handles);
                owners.handles = pending;
                return Err(ShutdownStatus::Retryable);
            }
            match tokio::time::timeout_at(deadline.expires_at().into(), &mut handle).await {
                Ok(Ok(())) => {}
                Ok(Err(_)) => {
                    handle.abort();
                    owners.handles.append(&mut pending);
                    return Err(ShutdownStatus::Unresolved);
                }
                Err(_) => {
                    pending.push(handle);
                    pending.append(&mut owners.handles);
                    owners.handles = pending;
                    return Err(ShutdownStatus::Retryable);
                }
            }
        }
        owners.handles = pending;
        Ok(())
    }

    async fn wait_for_shutdown_permits(
        supervisors: &Mutex<SupervisorState>,
        deadline: HardDeadline,
    ) -> Result<(), ShutdownStatus> {
        loop {
            let settled = {
                let state = supervisors
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner);
                state.active_permits == 0 && state.pending_admissions == 0
            };
            if settled {
                return Ok(());
            }
            ensure_worker_deadline(deadline).map_err(|_| ShutdownStatus::Retryable)?;
            tokio::task::yield_now().await;
        }
    }

    fn collect_shutdown_sweep(
        supervisor: &WorkerSupervisor,
        settlements: &Mutex<SupervisorSettlements>,
        owners: &mut ShutdownAttemptOwners,
    ) -> Result<bool, ShutdownStatus> {
        let (mut settlement_owners, supervisors_settled) = settlements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take_for_shutdown();
        if !supervisors_settled {
            owners.workers.append(&mut settlement_owners);
            return Err(ShutdownStatus::Unresolved);
        }
        settlement_owners.append(&mut lock_worker_registry(&supervisor.registry).begin_shutdown());
        if owners
            .workers
            .len()
            .checked_add(settlement_owners.len())
            .is_none_or(|count| count > MAX_PROCESS_OWNERS)
        {
            std::process::abort();
        }
        let found = !settlement_owners.is_empty();
        owners.workers.append(&mut settlement_owners);
        Ok(found)
    }

    fn publish_shutdown_status(
        publication: ShutdownPublicationGuard,
        mut owners: ShutdownAttemptOwners,
        status: ShutdownStatus,
    ) {
        if status == ShutdownStatus::Unresolved {
            owners.escalate_all();
        }
        publication.publish(status, owners);
    }
}

#[cfg(test)]
mod tests {
    use std::{
        env, fs,
        io::Read,
        os::unix::process::ExitStatusExt,
        process,
        sync::atomic::{AtomicBool, Ordering},
        thread,
    };

    use socket2::{Protocol, Type};
    use tempfile::tempdir;
    use volparossa_routing::{
        ClosedPreparePlan, ContextRole as WireContextRole, LeasePlan, PrepareIntent,
        WireguardRole as WireRole,
    };

    use super::*;
    use crate::{
        internal_protocol::{
            AcquireTransportSocket, DestroyContext, INTERNAL_WORKER_MAGIC,
            INTERNAL_WORKER_PROTOCOL_VERSION, InitialiseContext, InternalContextRole,
            InternalEndpointRole, InternalSocketAddress, InternalTransportSocketKind,
            TransportSocketReady,
        },
        worker_sandbox::{
            LinuxCapabilitySnapshot, LinuxSeccompState, NetworkNamespaceIdentity,
            SandboxProofRecord, WorkerIdentity, WorkerSandboxSnapshot,
        },
        worker_transport::{
            private_credential_worker_channel, receive_credential_worker_request,
            send_credential_worker_response,
        },
    };

    const CHILD_FIXTURE_ENVIRONMENT: &str = "VOLPAROSSA_TEST_WORKER_V3_CHILD";
    const CLEARED_ENVIRONMENT_SENTINEL: &str = "VOLPAROSSA_TEST_MUST_BE_CLEARED";

    fn current_credentials() -> ExpectedUnixCredentials {
        ExpectedUnixCredentials::new(process::id(), geteuid().as_raw(), getegid().as_raw())
            .expect("current credentials")
    }

    fn current_worker_identity() -> WorkerIdentity {
        WorkerIdentity::fixture(geteuid().as_raw(), getegid().as_raw())
    }

    fn current_initial_identity() -> InitialProcessIdentity {
        InitialProcessIdentity {
            uid: geteuid().as_raw(),
            gid: getegid().as_raw(),
        }
    }

    fn durable_worker_registration(context_id: ContextId, seed: u8) -> DurableIntentRegistration {
        let intent = PrepareIntent {
            route_context_id: context_id.to_vec(),
            prepare_request_id: vec![seed; 16],
            prepare_operation_digest: vec![seed.wrapping_add(1); 32],
            setup_expires_at_unix: 100,
            hard_expires_at_unix: 200,
            closed_plan: Some(ClosedPreparePlan {
                context_role: WireContextRole::Client as i32,
                leases: vec![LeasePlan {
                    path_id: 1,
                    role: WireRole::Client as i32,
                }],
            }),
        };
        DurableIntentRegistration::try_from_wire([seed.wrapping_add(2); 32], &intent)
            .expect("valid durable worker registration")
    }

    fn request(
        request_id: u8,
        operation: internal_worker_request::Operation,
    ) -> InternalWorkerRequest {
        InternalWorkerRequest {
            protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
            magic: INTERNAL_WORKER_MAGIC.to_vec(),
            request_id: vec![request_id; 16],
            operation: Some(operation),
        }
    }

    fn initialise(context_id: ContextId, request_id: u8) -> InternalWorkerRequest {
        request(
            request_id,
            internal_worker_request::Operation::Initialise(InitialiseContext {
                route_context_id: context_id.to_vec(),
                role: InternalContextRole::Client as i32,
                mptcp_accepted_addrs: 4,
                mptcp_subflows: 4,
            }),
        )
    }

    fn acquire(context_id: ContextId, request_id: u8) -> InternalWorkerRequest {
        request(
            request_id,
            internal_worker_request::Operation::AcquireTransportSocket(AcquireTransportSocket {
                route_context_id: context_id.to_vec(),
                path_id: 1,
                role: InternalEndpointRole::Client as i32,
                descriptor_kind: InternalTransportSocketKind::MptcpConnected as i32,
                expected_local: Some(InternalSocketAddress {
                    address: vec![10, 77, 0, 2],
                    port: 42_000,
                }),
                expected_remote: Some(InternalSocketAddress {
                    address: vec![10, 77, 0, 3],
                    port: 443,
                }),
            }),
        )
    }

    fn destroy(context_id: ContextId, request_id: u8) -> InternalWorkerRequest {
        request(
            request_id,
            internal_worker_request::Operation::DestroyContext(DestroyContext {
                route_context_id: context_id.to_vec(),
            }),
        )
    }

    fn initialised_response(
        request: &InternalWorkerRequest,
        context_id: ContextId,
    ) -> InternalWorkerResponse {
        correlated_response(
            request,
            InternalWorkerResult::Ok,
            Some(internal_worker_response::Outcome::Initialised(
                ContextInitialised {
                    route_context_id: context_id.to_vec(),
                },
            )),
        )
        .expect("initialised response")
    }

    const SUPERVISOR_CAP_CONTEXT_ID: ContextId = [42; 16];

    struct CachedSupervisorFixture {
        coordinator: WorkerCoordinator,
        generation: u64,
        request: InternalWorkerRequest,
        alive: Arc<AtomicBool>,
    }

    async fn cached_supervisor_fixture() -> CachedSupervisorFixture {
        let request = initialise(SUPERVISOR_CAP_CONTEXT_ID, 33);
        let mut registry = WorkerRegistry::new(1, 8, Duration::from_secs(10));
        let (process, peer, alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(
                SUPERVISOR_CAP_CONTEXT_ID,
                process,
                Duration::from_secs(5),
                Instant::now(),
            )
            .expect("register");
        let coordinator = WorkerCoordinator::new(registry);
        let worker_request = request.clone();
        let worker = thread::spawn(move || {
            let received =
                receive_credential_worker_request(&peer, current_credentials()).expect("request");
            assert_eq!(received.request_id, worker_request.request_id);
            let response = initialised_response(&received, SUPERVISOR_CAP_CONTEXT_ID);
            send_credential_worker_response(&peer, &received, &response, None).expect("response");
        });
        let initial = coordinator
            .execute(SUPERVISOR_CAP_CONTEXT_ID, generation, request.clone())
            .await
            .expect("initial response");
        assert_eq!(initial.response.result, InternalWorkerResult::Ok as i32);
        assert!(initial.descriptor.is_none());
        worker.join().expect("worker join");
        wait_for_supervisors_to_finish(&coordinator).await;
        CachedSupervisorFixture {
            coordinator,
            generation,
            request,
            alive,
        }
    }

    async fn wait_for_supervisors_to_finish(coordinator: &WorkerCoordinator) {
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let completed = {
                    let supervisors = coordinator
                        .supervisors
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    supervisors.active_permits == 0
                        && supervisors.handles.iter().all(JoinHandle::is_finished)
                };
                if completed {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("supervisor completion");
    }

    fn acquire_response(request: &InternalWorkerRequest) -> InternalWorkerResponse {
        let Some(internal_worker_request::Operation::AcquireTransportSocket(acquire)) =
            request.operation.as_ref()
        else {
            panic!("Acquire request")
        };
        correlated_response(
            request,
            InternalWorkerResult::Ok,
            Some(internal_worker_response::Outcome::TransportSocketReady(
                TransportSocketReady {
                    path_id: acquire.path_id,
                    role: acquire.role,
                    descriptor_kind: acquire.descriptor_kind,
                    local: acquire.expected_local.clone(),
                    remote: acquire.expected_remote.clone(),
                },
            )),
        )
        .expect("Acquire response")
    }

    fn child_command(mode: &str) -> Command {
        // Reopen the exact running Linux test image even if Cargo replaces its hashed path.
        let mut command = Command::new("/proc/self/exe");
        command
            .arg("--exact")
            .arg("worker_v3::tests::child_process_entry_fixture")
            .arg("--nocapture")
            .env(CHILD_FIXTURE_ENVIRONMENT, mode)
            .env(CLEARED_ENVIRONMENT_SENTINEL, "must-not-survive");
        command
    }

    fn spawn_fixture(
        mode: &str,
        context_id: ContextId,
        generation: u64,
    ) -> Result<WorkerProcess, WorkerV3Error> {
        spawn_authenticated_fixture(mode, context_id, generation)
            .map(|authenticated| authenticated.process)
    }

    fn timed_spawn_fixture_after_lock(
        mode: &str,
        context_id: ContextId,
        generation: u64,
    ) -> (Result<WorkerProcess, WorkerV3Error>, Duration) {
        let _spawn_guard = WORKER_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let started = Instant::now();
        let result = spawn_with_command_locked(
            child_command(mode),
            WorkerSpawnBinding {
                parent_identity: current_initial_identity(),
                worker_identity: current_worker_identity(),
                context_id,
                generation,
                retained_environment: Some((CHILD_FIXTURE_ENVIRONMENT, mode)),
                deadline: HardDeadline::after(HANDSHAKE_TIMEOUT).expect("spawn deadline"),
            },
            SandboxObservationMode::Fixture(fake_production_sandbox_snapshot()),
        )
        .map(|authenticated| authenticated.process);
        (result, started.elapsed())
    }

    fn spawn_authenticated_fixture(
        mode: &str,
        context_id: ContextId,
        generation: u64,
    ) -> Result<AuthenticatedWorker, WorkerV3Error> {
        spawn_authenticated_fixture_with_observation(
            mode,
            context_id,
            generation,
            fake_production_sandbox_snapshot(),
        )
    }

    fn spawn_authenticated_fixture_with_observation(
        mode: &str,
        context_id: ContextId,
        generation: u64,
        observed_snapshot: WorkerSandboxSnapshot,
    ) -> Result<AuthenticatedWorker, WorkerV3Error> {
        let timeout = if matches!(mode, "wrong-ready" | "unexpected-fd" | "wrong-challenge") {
            HANDSHAKE_TIMEOUT
        } else {
            SPAWN_TIMEOUT
        };
        spawn_with_command_mode(
            child_command(mode),
            WorkerSpawnBinding {
                parent_identity: current_initial_identity(),
                worker_identity: current_worker_identity(),
                context_id,
                generation,
                retained_environment: Some((CHILD_FIXTURE_ENVIRONMENT, mode)),
                deadline: HardDeadline::after(timeout).expect("fixture spawn deadline"),
            },
            SandboxObservationMode::Fixture(observed_snapshot),
        )
    }

    fn spawn_reserved_fixture(
        mode: &str,
        reservation: GenerationReservation,
    ) -> Result<SpawnedWorker, WorkerSpawnFailure> {
        let result = spawn_with_command_fixture(
            child_command(mode),
            current_initial_identity(),
            current_worker_identity(),
            reservation.context_id,
            reservation.generation,
            Some((CHILD_FIXTURE_ENVIRONMENT, mode)),
            fake_production_sandbox_snapshot(),
        );
        match result {
            Ok(authenticated) => Ok(SpawnedWorker {
                reservation,
                process: authenticated.process,
                bootstrap_challenge: authenticated.bootstrap_challenge,
            }),
            Err(error) => Err(WorkerSpawnFailure { error, reservation }),
        }
    }

    fn inherited_fixture_channel() -> Result<Socket, WorkerV3Error> {
        let inherited = dup(io::stdin()).map_err(nix_io)?;
        fcntl(&inherited, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC)).map_err(nix_io)?;
        close(libc::STDIN_FILENO).map_err(nix_io)?;
        let channel = Socket::from(inherited);
        validate_connected_socket(&channel)?;
        enable_passcred_receiver(&channel)?;
        Ok(channel)
    }

    fn wrong_challenge_fixture() -> Result<(), WorkerV3Error> {
        let channel = inherited_fixture_channel()?;
        let parent_pid =
            u32::try_from(getppid().as_raw()).map_err(|_| WorkerV3Error::Authentication)?;
        let expected =
            ExpectedUnixCredentials::new(parent_pid, geteuid().as_raw(), getegid().as_raw())?;
        let encoded = receive_credential_record(&channel, HandshakeRecord::LENGTH, expected)?;
        let hello = HandshakeRecord::decode(&encoded)?;
        send_credential_record(&channel, &hello.namespace_ready().encode())?;
        let encoded = receive_credential_record(&channel, HandshakeRecord::LENGTH, expected)?;
        if HandshakeRecord::decode(&encoded)? != hello.namespace_pinned() {
            return Err(WorkerV3Error::Authentication);
        }
        let mut wrong_hello = hello;
        wrong_hello.challenge[0] ^= 1;
        send_credential_record(&channel, &wrong_hello.child_reply().encode())?;
        Ok(())
    }

    fn credential_sender_fixture() -> Result<(), WorkerV3Error> {
        let channel = inherited_fixture_channel()?;
        send_credential_record(&channel, &[42]).map_err(WorkerV3Error::Io)
    }

    fn fake_production_sandbox_snapshot() -> WorkerSandboxSnapshot {
        let net_admin = 1_u64 << 12;
        WorkerSandboxSnapshot::fixture(
            NetworkNamespaceIdentity::fixture(1, 10),
            NetworkNamespaceIdentity::fixture(1, 11),
            current_worker_identity(),
            true,
            true,
            LinuxSeccompState::fixture(
                u8::try_from(libc::SECCOMP_MODE_FILTER).expect("seccomp mode fits u8"),
                4,
            ),
            LinuxCapabilitySnapshot::fixture(0, net_admin, net_admin, net_admin, 0),
        )
    }

    fn proof_completion_fixture(
        send_wrong_ready: bool,
        retain_post_pin_descriptor: bool,
    ) -> Result<(), WorkerV3Error> {
        let channel = inherited_fixture_channel()?;
        let parent_pid =
            u32::try_from(getppid().as_raw()).map_err(|_| WorkerV3Error::Authentication)?;
        let child_pid =
            u32::try_from(getpid().as_raw()).map_err(|_| WorkerV3Error::Authentication)?;
        let expected_parent =
            ExpectedUnixCredentials::new(parent_pid, geteuid().as_raw(), getegid().as_raw())?;
        let encoded =
            receive_credential_record(&channel, HandshakeRecord::LENGTH, expected_parent)?;
        let hello = HandshakeRecord::decode(&encoded)?;
        if hello.kind != HandshakeKind::ParentHello
            || hello.parent_pid != parent_pid
            || hello.child_pid != child_pid
        {
            return Err(WorkerV3Error::Authentication);
        }
        send_credential_record(&channel, &hello.namespace_ready().encode())?;
        let encoded =
            receive_credential_record(&channel, HandshakeRecord::LENGTH, expected_parent)?;
        if HandshakeRecord::decode(&encoded)? != hello.namespace_pinned() {
            return Err(WorkerV3Error::Authentication);
        }
        let _post_pin_descriptor = retain_post_pin_descriptor
            .then(|| fs::File::open("/dev/null"))
            .transpose()?;
        send_credential_record(&channel, &hello.child_reply().encode())?;
        let proof = SandboxProofRecord::fixture(
            hello.context_id,
            hello.generation,
            hello.challenge,
            hello.parent_pid,
            hello.child_pid,
            fake_production_sandbox_snapshot(),
        );
        let proof = proof.encode();
        send_credential_record(&channel, &proof)?;
        if !send_wrong_ready && !retain_post_pin_descriptor {
            return Ok(());
        }
        let encoded =
            receive_credential_record(&channel, HandshakeRecord::LENGTH, expected_parent)?;
        let accepted = HandshakeRecord::decode(&encoded)?;
        if accepted != hello.sandbox_accepted(*blake3::hash(&proof).as_bytes()) {
            return Err(WorkerV3Error::Authentication);
        }
        let mut ready = accepted.sandbox_ready();
        if send_wrong_ready {
            ready.proof_hash[0] ^= 1;
        }
        send_credential_record(&channel, &ready.encode())?;
        if retain_post_pin_descriptor {
            thread::sleep(Duration::from_secs(30));
        }
        Ok(())
    }

    fn hardened_child_environment() -> bool {
        env::var_os(CLEARED_ENVIRONMENT_SENTINEL).is_none()
            && env::current_dir().is_ok_and(|path| path == std::path::Path::new("/"))
            && fs::read_link("/proc/self/fd/1")
                .is_ok_and(|path| path == std::path::Path::new("/dev/null"))
            && fs::read_link("/proc/self/fd/2")
                .is_ok_and(|path| path == std::path::Path::new("/dev/null"))
    }

    fn inheritable_parent_descriptor_is_confined_by_exec_fence_fixture() -> bool {
        let _spawn_guard = WORKER_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let sentinel_source = fs::File::open("/dev/null").expect("sentinel source");
        // The child deliberately normalises raw fd 3, so the sentinel must sit above it to prove
        // that the general close-range fence, rather than fd-3 setup, prevents inheritance.
        let sentinel =
            fcntl_dupfd_cloexec(&sentinel_source, 4).expect("sentinel above worker channel");
        assert!(
            sentinel.as_raw_fd() >= 4,
            "sentinel must exercise the general non-standard descriptor fence"
        );
        fcntl(&sentinel, FcntlArg::F_SETFD(FdFlag::empty())).expect("make sentinel inheritable");
        let result = spawn_with_command_locked(
            child_command("connect"),
            WorkerSpawnBinding {
                parent_identity: current_initial_identity(),
                worker_identity: current_worker_identity(),
                context_id: [15; 16],
                generation: 1,
                retained_environment: Some((CHILD_FIXTURE_ENVIRONMENT, "connect")),
                deadline: HardDeadline::after(SPAWN_TIMEOUT).expect("spawn deadline"),
            },
            SandboxObservationMode::Fixture(fake_production_sandbox_snapshot()),
        );
        let parent_flags = FdFlag::from_bits_truncate(
            fcntl(&sentinel, FcntlArg::F_GETFD).expect("sentinel flags"),
        );
        fcntl(&sentinel, FcntlArg::F_SETFD(FdFlag::FD_CLOEXEC))
            .expect("restore sentinel close-on-exec");
        let Ok(AuthenticatedWorker {
            process,
            bootstrap_challenge,
        }) = result
        else {
            return false;
        };
        let child_authenticated =
            bootstrap_challenge.into_bytes() != [0; 32] && process.has_complete_kernel_pins();
        let child_reaped = process.terminate_bounded(TERMINATION_TIMEOUT);
        parent_flags == FdFlag::empty() && child_authenticated && child_reaped
    }

    #[test]
    fn child_process_entry_fixture() {
        let failed = match env::var(CHILD_FIXTURE_ENVIRONMENT).ok().as_deref() {
            Some("connect") => {
                !hardened_child_environment()
                    || run_child_with_fixture_sandbox(
                        geteuid().as_raw(),
                        getegid().as_raw(),
                        fake_production_sandbox_snapshot(),
                    )
                    .is_err()
            }
            Some("wrong-challenge") => wrong_challenge_fixture().is_err(),
            Some("credential-sender") => credential_sender_fixture().is_err(),
            Some("wrong-ready") => proof_completion_fixture(true, false).is_err(),
            Some("exit-after-proof") => proof_completion_fixture(false, false).is_err(),
            Some("extra-fd-after-pin") => proof_completion_fixture(false, true).is_err(),
            Some("extra-fd-connect") => {
                let _normalised_fd_three =
                    fs::File::open("/dev/null").expect("occupied child fd three");
                let _unexpected_fd_four =
                    fs::File::open("/dev/null").expect("unexpected child fd four");
                run_child_with_fixture_sandbox(
                    geteuid().as_raw(),
                    getegid().as_raw(),
                    fake_production_sandbox_snapshot(),
                )
                .is_ok()
            }
            Some("fd-fence") => !inheritable_parent_descriptor_is_confined_by_exec_fence_fixture(),
            Some("hold") => {
                thread::sleep(Duration::from_secs(30));
                false
            }
            _ => false,
        };
        if failed {
            process::exit(1);
        }
    }

    fn fake_process_with_termination_results(
        read_timeout: Duration,
        termination_results: VecDeque<bool>,
        default_result: bool,
    ) -> (WorkerProcess, Socket, Arc<AtomicBool>, Arc<AtomicUsize>) {
        let (parent, peer) = private_credential_worker_channel().expect("private channel");
        parent
            .set_read_timeout(Some(read_timeout))
            .expect("read timeout");
        parent
            .set_write_timeout(Some(read_timeout))
            .expect("write timeout");
        peer.set_read_timeout(Some(read_timeout))
            .expect("peer read timeout");
        peer.set_write_timeout(Some(read_timeout))
            .expect("peer write timeout");
        let alive = Arc::new(AtomicBool::new(true));
        let attempts = Arc::new(AtomicUsize::new(0));
        (
            WorkerProcess::fake_with_termination_results(
                parent,
                process::id(),
                Arc::clone(&alive),
                termination_results,
                default_result,
                Arc::clone(&attempts),
            ),
            peer,
            alive,
            attempts,
        )
    }

    fn fake_process_with_delayed_termination(
        termination_delay: Duration,
    ) -> (WorkerProcess, Socket, Arc<AtomicBool>, Arc<AtomicUsize>) {
        let (parent, peer) = private_credential_worker_channel().expect("private channel");
        let alive = Arc::new(AtomicBool::new(true));
        let attempts = Arc::new(AtomicUsize::new(0));
        (
            WorkerProcess::fake_with_delayed_termination_results(
                parent,
                process::id(),
                Arc::clone(&alive),
                VecDeque::from([true]),
                true,
                Arc::clone(&attempts),
                FakeWorkerDelays {
                    termination: termination_delay,
                    probe: Duration::ZERO,
                },
            ),
            peer,
            alive,
            attempts,
        )
    }

    fn fake_process_with_probe_delay(
        probe_delay: Duration,
    ) -> (WorkerProcess, Socket, Arc<AtomicBool>) {
        let (parent, peer) = private_credential_worker_channel().expect("private channel");
        let alive = Arc::new(AtomicBool::new(true));
        let process = WorkerProcess::fake_with_delayed_termination_results(
            parent,
            process::id(),
            Arc::clone(&alive),
            VecDeque::new(),
            true,
            Arc::new(AtomicUsize::new(0)),
            FakeWorkerDelays {
                termination: Duration::ZERO,
                probe: probe_delay,
            },
        );
        (process, peer, alive)
    }

    fn fake_process_with_termination(
        read_timeout: Duration,
        termination_confirmed: bool,
    ) -> (WorkerProcess, Socket, Arc<AtomicBool>) {
        let (process, peer, alive, _attempts) = fake_process_with_termination_results(
            read_timeout,
            VecDeque::new(),
            termination_confirmed,
        );
        (process, peer, alive)
    }

    fn fake_process(read_timeout: Duration) -> (WorkerProcess, Socket, Arc<AtomicBool>) {
        fake_process_with_termination(read_timeout, true)
    }

    fn wait_for_termination_attempts(attempts: &AtomicUsize, minimum: usize) {
        let deadline = Instant::now() + Duration::from_secs(1);
        while attempts.load(Ordering::SeqCst) < minimum {
            assert!(
                Instant::now() < deadline,
                "retirement reaper did not make progress"
            );
            thread::sleep(Duration::from_millis(1));
        }
    }

    fn call(plan: RegistryPlan) -> PlannedCall {
        match plan {
            RegistryPlan::Call(call) => call,
            RegistryPlan::Cached(_) => panic!("expected a fresh worker call"),
        }
    }

    fn registered_lifecycle(admission: WorkerLifecycleAdmission) -> WorkerGenerationOwnership {
        match admission {
            WorkerLifecycleAdmission::Registered(ownership) => ownership,
            WorkerLifecycleAdmission::Rejected(error) => {
                panic!("lifecycle admission was rejected: {error}")
            }
            WorkerLifecycleAdmission::Retained { error, ownership } => {
                drop(ownership);
                panic!("lifecycle admission remained unresolved: {error}")
            }
        }
    }

    fn assert_durable_handoff_fence_owner(worker: &WorkerGenerationOwnership) {
        assert!(worker.has_valid_dispatch_fence_shape());
        assert_eq!(
            worker.dispatch_registration,
            WorkerDispatchRegistration::DurableHandoffPending
        );
        let fence = worker
            .handoff_fence
            .as_ref()
            .expect("retained affine dispatch fence");
        assert_eq!(fence.coordinates, worker.coordinates);
        assert_eq!(format!("{fence:?}"), "DurableHandoffFenceOwner(<redacted>)");
    }

    fn exact_custody_attestation(
        publication: &DurableWorkerCustodyPublicationOwner,
    ) -> crate::systemd_fdstore::InventoryAttestation {
        let custody = crate::systemd_fdstore::BorrowedCustodyPair::new(
            publication.handoff.source.restart_custody.borrowed_pidfd(),
            publication
                .handoff
                .source
                .restart_custody
                .borrowed_network_namespace(),
        )
        .expect("distinct durable publication custody roles");
        crate::systemd_fdstore::InventoryAttestation::for_test_exact_custody(
            publication.custody_name,
            custody,
        )
        .expect("exact durable publication attestation")
    }

    fn different_custody_name(
        custody_name: crate::systemd_fdstore::CustodyFdName,
    ) -> crate::systemd_fdstore::CustodyFdName {
        [
            "volparossa-custody-v1-0000000000000000000000000000000000000000000000000000000000000000",
            "volparossa-custody-v1-ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
        ]
        .into_iter()
        .map(|name| {
            crate::systemd_fdstore::CustodyFdName::parse(name)
                .expect("fixed valid alternative custody name")
        })
        .find(|name| *name != custody_name)
        .expect("one fixed custody name differs from the durable digest")
    }

    fn retain_and_reap_durable_publication(
        coordinator: &WorkerCoordinator,
        publication: DurableWorkerCustodyPublicationOwner,
    ) {
        let DurableWorkerCustodyPublicationOwner {
            custody_name,
            deadline: _,
            handoff,
        } = publication;
        let DurableWorkerPrepareHandoff { registered, source } = handoff;
        let DurableRegisteredStartingWorker { key, worker } = registered;
        let _ = custody_name;
        drop(key);
        drop(source);
        reap_durable_handoff_worker(coordinator, worker);
    }

    struct DurablePendingLifecycleFixture {
        coordinator: WorkerCoordinator,
        worker: WorkerGenerationOwnership,
        peer: Socket,
        alive: Arc<AtomicBool>,
        attempts: Arc<AtomicUsize>,
    }

    fn durable_pending_lifecycle_fixture(
        context_id: ContextId,
        termination_results: VecDeque<bool>,
        default_termination_result: bool,
    ) -> DurablePendingLifecycleFixture {
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let (mut process, peer, alive, attempts) = fake_process_with_termination_results(
            Duration::from_secs(1),
            termination_results,
            default_termination_result,
        );
        let worker = registered_lifecycle(
            coordinator.reserve_spawn_register_durable_handoff_with_until(
                context_id,
                Duration::from_secs(5),
                HardDeadline::after(Duration::from_secs(5))
                    .expect("pending worker registration deadline"),
                move |reservation, _deadline| {
                    process.binding = Some(reservation.binding());
                    Ok(SpawnedWorker {
                        reservation,
                        process,
                        bootstrap_challenge: BootstrapChallenge([0xd0; 32]),
                    })
                },
            ),
        );
        assert_durable_handoff_fence_owner(&worker);
        DurablePendingLifecycleFixture {
            coordinator,
            worker,
            peer,
            alive,
            attempts,
        }
    }

    fn assert_no_worker_request_bytes(peer: &Socket) {
        peer.set_nonblocking(true)
            .expect("set passive worker peer nonblocking");
        let mut byte = [0_u8; 1];
        let mut peer = peer;
        let error = peer
            .read(&mut byte)
            .expect_err("the passive handoff must send zero child-request bytes");
        assert_eq!(error.kind(), io::ErrorKind::WouldBlock);
    }

    fn assert_durable_handoff_registry_pristine(
        coordinator: &WorkerCoordinator,
        context_id: ContextId,
        generation: u64,
    ) {
        let registry = lock_worker_registry(&coordinator.registry);
        let record = registry
            .records
            .get(&context_id)
            .expect("durable handoff worker record");
        assert_eq!(record.generation, generation);
        assert_eq!(
            record.dispatch_fence,
            WorkerDispatchFence::DurableHandoffPending
        );
        assert_eq!(record.stable_phase, StablePhase::Starting);
        assert!(record.in_flight.is_none());
        assert!(!record.quarantined);
        assert!(
            registry
                .cache
                .keys()
                .all(|key| { key.context_id != context_id || key.generation != generation })
        );
        assert!(
            registry
                .cache_order
                .iter()
                .all(|key| { key.context_id != context_id || key.generation != generation })
        );
        assert!(
            registry
                .tombstones
                .keys()
                .all(|key| { key.context_id != context_id || key.generation != generation })
        );
        assert!(
            registry
                .tombstone_order
                .iter()
                .all(|key| { key.context_id != context_id || key.generation != generation })
        );
    }

    fn reap_durable_handoff_worker(
        coordinator: &WorkerCoordinator,
        worker: WorkerGenerationOwnership,
    ) {
        assert_durable_handoff_fence_owner(&worker);
        match coordinator.terminate_generation_until(
            worker,
            HardDeadline::after(Duration::from_secs(1)).expect("durable handoff cleanup deadline"),
        ) {
            WorkerGenerationReap::Confirmed(_) => {}
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("durable handoff worker cleanup remained unresolved: {error}")
            }
        }
    }

    struct FencedDurableHandoffFixture {
        actor: DurableOwnershipActor,
        coordinator: WorkerCoordinator,
        outcome: DurableWorkerPrepareOutcome,
        peer: Socket,
        directory: tempfile::TempDir,
    }

    fn fenced_durable_handoff_fixture<Mutation>(
        context_id: ContextId,
        deadline: HardDeadline,
        mutation: Mutation,
    ) -> FencedDurableHandoffFixture
    where
        Mutation: FnOnce(&WorkerCoordinator, ContextId, u64),
    {
        let directory = tempdir().expect("durable handoff directory");
        let actor = crate::ownership_journal::spawn_test_durable_ownership_actor_until(
            directory.path(),
            HardDeadline::after(Duration::from_secs(5)).expect("actor fixture deadline"),
        )
        .expect("durable ownership actor fixture");
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let (derived_sender, derived_receiver) = std::sync::mpsc::sync_channel(1);
        let release = Arc::new((Mutex::new(false), Condvar::new()));
        coordinator.set_durable_handoff_source_hook(Some(DurableHandoffSourceHook {
            derived: derived_sender,
            release: Arc::clone(&release),
        }));
        let registration = durable_worker_registration(context_id, context_id[0]);
        let (mut process, peer, _alive) = fake_process(Duration::from_secs(1));
        let thread_coordinator = coordinator.clone();
        let handoff = thread::spawn(move || {
            let outcome = thread_coordinator.durable_passive_prepare_handoff_with_until(
                &actor,
                registration,
                Duration::from_secs(5),
                deadline,
                move |reservation, _deadline| {
                    process.binding = Some(reservation.binding());
                    Ok(SpawnedWorker {
                        reservation,
                        process,
                        bootstrap_challenge: BootstrapChallenge([0xc1; 32]),
                    })
                },
            );
            (actor, outcome)
        });

        let reached = derived_receiver.recv_timeout(Duration::from_secs(5));
        if reached.is_err() {
            let (released, changed) = release.as_ref();
            *released
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
            changed.notify_all();
            let _ = handoff.join();
            panic!("durable handoff did not reach its pre-arm source fence")
        }
        let mutation = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            mutation(&coordinator, context_id, 1);
        }));
        let (released, changed) = release.as_ref();
        *released
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = true;
        changed.notify_all();
        let joined = handoff.join();
        if let Err(payload) = mutation {
            let _ = joined;
            std::panic::resume_unwind(payload);
        }
        let (actor, outcome) = joined.expect("durable handoff thread");
        coordinator.set_durable_handoff_source_hook(None);
        FencedDurableHandoffFixture {
            actor,
            coordinator,
            outcome,
            peer,
            directory,
        }
    }

    struct RegisteredLifecycleFixture {
        coordinator: WorkerCoordinator,
        ownership: WorkerGenerationOwnership,
        alive: Arc<AtomicBool>,
        attempts: Arc<AtomicUsize>,
    }

    fn registered_lifecycle_fixture(
        context_id: ContextId,
        maximum_workers: usize,
        termination_results: VecDeque<bool>,
        default_result: bool,
    ) -> RegisteredLifecycleFixture {
        let coordinator = WorkerCoordinator::new(WorkerRegistry::new(
            maximum_workers,
            8,
            Duration::from_secs(10),
        ));
        let (mut process, _peer, alive, attempts) = fake_process_with_termination_results(
            Duration::from_secs(1),
            termination_results,
            default_result,
        );
        let ownership = registered_lifecycle(coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(5),
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xb0; 32]),
                })
            },
        ));
        RegisteredLifecycleFixture {
            coordinator,
            ownership,
            alive,
            attempts,
        }
    }

    fn terminal_lifecycle_finish(
        coordinator: &WorkerCoordinator,
        coordinates: WorkerGenerationCoordinates,
        request_id: u8,
    ) -> (FinishOutcome, CredentialedWorkerExecution) {
        let request = destroy(coordinates.context_id, request_id);
        let response = correlated_response(
            &request,
            InternalWorkerResult::Ok,
            Some(internal_worker_response::Outcome::Destroyed(
                ContextDestroyed {},
            )),
        )
        .expect("canonical terminal response");
        let outcome = {
            let mut registry = lock_worker_registry(&coordinator.registry);
            let planned = call(
                registry
                    .plan(
                        coordinates.context_id,
                        coordinates.worker_generation.get(),
                        &request,
                        Instant::now(),
                    )
                    .expect("terminal lifecycle plan"),
            );
            registry.finish(planned.token, &request, &response, Instant::now(), true)
        };
        assert!(matches!(&outcome, FinishOutcome::Terminal(_)));
        (
            outcome,
            CredentialedWorkerExecution {
                response,
                descriptor: None,
            },
        )
    }

    fn lifecycle_supervisor(coordinator: &WorkerCoordinator) -> WorkerSupervisor {
        WorkerSupervisor {
            registry: Arc::clone(&coordinator.registry),
            settlements: Arc::clone(&coordinator.settlements),
        }
    }

    fn retained_registered_lifecycle(
        coordinator: &WorkerCoordinator,
        ownership: WorkerGenerationOwnership,
    ) -> WorkerGenerationOwnership {
        let ownership = match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("retained settlement deadline"),
        ) {
            WorkerGenerationReap::Retained { ownership, .. } => *ownership,
            WorkerGenerationReap::Confirmed(_) => {
                panic!("incomplete generation state falsely confirmed absence")
            }
        };
        assert!(matches!(
            ownership.placement.as_ref(),
            Some(WorkerGenerationPlacement::Registered)
        ));
        ownership
    }

    #[derive(Clone, Copy)]
    enum ExactGenerationResidue {
        Record,
        Reservation,
        Cache,
        CacheOrder,
        Tombstone,
        TombstoneOrder,
    }

    impl ExactGenerationResidue {
        fn cache_key(coordinates: WorkerGenerationCoordinates) -> CacheKey {
            CacheKey {
                context_id: coordinates.context_id,
                generation: coordinates.worker_generation.get(),
                request_id: [1; 16],
                request_digest: [2; 32],
            }
        }

        fn tombstone_key(coordinates: WorkerGenerationCoordinates) -> TombstoneKey {
            TombstoneKey {
                context_id: coordinates.context_id,
                generation: coordinates.worker_generation.get(),
                request_id: [3; 16],
            }
        }

        fn insert(
            self,
            registry: &mut WorkerRegistry,
            coordinates: WorkerGenerationCoordinates,
            expires_at: Instant,
        ) {
            assert!(registry.exact_generation_absent(coordinates));
            let context_id = coordinates.context_id;
            let generation = coordinates.worker_generation.get();
            match self {
                Self::Record => {
                    registry.records.insert(
                        context_id,
                        WorkerRecord {
                            generation,
                            dispatch_fence: WorkerDispatchFence::Open,
                            stable_phase: StablePhase::Starting,
                            in_flight: None,
                            quarantined: true,
                            expires_at,
                            alive_hint: Arc::new(AtomicBool::new(false)),
                            process: None,
                        },
                    );
                }
                Self::Reservation => {
                    registry.reservations.insert(
                        context_id,
                        PendingGeneration {
                            generation,
                            expires_at,
                            phase: PendingGenerationPhase::LifecycleOwned,
                        },
                    );
                }
                Self::Cache => {
                    registry.cache.insert(
                        Self::cache_key(coordinates),
                        CacheEntry {
                            response: initialised_response(&initialise(context_id, 90), context_id),
                            expires_at,
                        },
                    );
                }
                Self::CacheOrder => registry.cache_order.push_back(Self::cache_key(coordinates)),
                Self::Tombstone => {
                    registry.tombstones.insert(
                        Self::tombstone_key(coordinates),
                        Tombstone {
                            request_digest: [4; 32],
                            expires_at,
                        },
                    );
                }
                Self::TombstoneOrder => registry
                    .tombstone_order
                    .push_back(Self::tombstone_key(coordinates)),
            }
            assert!(!registry.exact_generation_absent(coordinates));
        }

        fn assert_unchanged_and_remove(
            self,
            registry: &mut WorkerRegistry,
            coordinates: WorkerGenerationCoordinates,
            expires_at: Instant,
        ) {
            let context_id = coordinates.context_id;
            let generation = coordinates.worker_generation.get();
            match self {
                Self::Record => {
                    let record = registry
                        .records
                        .remove(&context_id)
                        .expect("record residue retained");
                    assert_eq!(record.generation, generation);
                    assert_eq!(record.stable_phase, StablePhase::Starting);
                    assert!(record.in_flight.is_none() && record.quarantined);
                    assert_eq!(record.expires_at, expires_at);
                    assert!(!record.alive_hint.load(Ordering::SeqCst));
                    assert!(record.process.is_none());
                }
                Self::Reservation => {
                    assert_eq!(
                        registry.reservations.remove(&context_id),
                        Some(PendingGeneration {
                            generation,
                            expires_at,
                            phase: PendingGenerationPhase::LifecycleOwned,
                        })
                    );
                }
                Self::Cache => {
                    let entry = registry
                        .cache
                        .remove(&Self::cache_key(coordinates))
                        .expect("cache residue retained");
                    assert_eq!(
                        entry.response,
                        initialised_response(&initialise(context_id, 90), context_id)
                    );
                    assert_eq!(entry.expires_at, expires_at);
                }
                Self::CacheOrder => {
                    assert_eq!(
                        registry.cache_order.pop_front(),
                        Some(Self::cache_key(coordinates))
                    );
                    assert!(registry.cache_order.is_empty());
                }
                Self::Tombstone => {
                    let entry = registry
                        .tombstones
                        .remove(&Self::tombstone_key(coordinates))
                        .expect("tombstone residue retained");
                    assert_eq!(entry.request_digest, [4; 32]);
                    assert_eq!(entry.expires_at, expires_at);
                }
                Self::TombstoneOrder => {
                    assert_eq!(
                        registry.tombstone_order.pop_front(),
                        Some(Self::tombstone_key(coordinates))
                    );
                    assert!(registry.tombstone_order.is_empty());
                }
            }
        }
    }

    fn wait_until_deadline_elapsed(deadline: HardDeadline) {
        if let Some(remaining) = deadline.expires_at().checked_duration_since(Instant::now()) {
            thread::sleep(remaining);
        }
        while ensure_worker_deadline(deadline).is_ok() {
            thread::yield_now();
        }
    }

    fn stop_and_purge(registry: &mut WorkerRegistry, detached: DetachedWorker) {
        assert!(
            detached.process.terminate_bounded(TERMINATION_TIMEOUT),
            "test worker termination must be confirmed outside the registry"
        );
        registry
            .purge_confirmed(detached.context_id, detached.generation)
            .expect("confirmed purge");
        drop(detached);
    }

    #[test]
    fn handshake_record_is_canonical_and_binds_every_identity_field() {
        let record = HandshakeRecord {
            kind: HandshakeKind::ParentHello,
            context_id: [7; 16],
            generation: 9,
            challenge: [11; 32],
            parent_pid: 42,
            child_pid: 43,
            proof_hash: [0; 32],
            worker_uid: 1_001,
            worker_gid: 1_002,
        };
        let encoded = record.encode();
        assert_eq!(
            HandshakeRecord::decode(&encoded).expect("canonical"),
            record
        );
        assert_eq!(record.namespace_ready().kind, HandshakeKind::NamespaceReady);
        assert_eq!(
            record.namespace_pinned().kind,
            HandshakeKind::NamespacePinned
        );
        assert_eq!(record.child_reply().kind, HandshakeKind::ChildHello);
        let accepted = record.sandbox_accepted([13; 32]);
        assert_eq!(
            HandshakeRecord::decode(&accepted.encode()).expect("accepted"),
            accepted
        );
        assert_eq!(
            HandshakeRecord::decode(&accepted.sandbox_ready().encode()).expect("ready"),
            accepted.sandbox_ready()
        );

        let mut invalid = vec![encoded[..encoded.len() - 1].to_vec()];
        for index in [0, 8, 12, 13] {
            let mut changed = encoded.to_vec();
            changed[index] ^= 0xff;
            invalid.push(changed);
        }
        for range in [16..32, 32..40, 40..72, 72..76, 76..80, 112..116, 116..120] {
            let mut changed = encoded.to_vec();
            changed[range].fill(0);
            invalid.push(changed);
        }
        let mut hello_with_hash = encoded;
        hello_with_hash[80] = 1;
        assert!(HandshakeRecord::decode(&hello_with_hash).is_err());
        let mut accepted_without_hash = accepted.encode();
        accepted_without_hash[80..112].fill(0);
        assert!(HandshakeRecord::decode(&accepted_without_hash).is_err());
        for encoded in invalid {
            assert!(HandshakeRecord::decode(&encoded).is_err());
        }
        for range in [112..116, 116..120] {
            let mut reserved = encoded;
            reserved[range]
                .copy_from_slice(&crate::worker_sandbox::SYSTEMD_RESERVED_ID.to_be_bytes());
            assert!(HandshakeRecord::decode(&reserved).is_err());
        }
        for index in [16, 32, 40, 72, 76, 112, 116] {
            let mut changed = encoded;
            changed[index] ^= 1;
            assert_ne!(
                HandshakeRecord::decode(&changed).expect("canonical changed binding"),
                record
            );
        }
        assert!(validate_parent_snapshot(42, 42, 0, 0).is_ok());
        assert!(validate_parent_snapshot(1, 1, 0, 0).is_err());
        assert!(validate_parent_snapshot(42, 43, 0, 0).is_err());
        assert!(validate_parent_snapshot(42, 42, 1, 0).is_err());
    }

    #[test]
    fn accepted_and_ready_bind_every_field_exactly() {
        let hello = HandshakeRecord {
            kind: HandshakeKind::ParentHello,
            context_id: [7; 16],
            generation: 9,
            challenge: [11; 32],
            parent_pid: 42,
            child_pid: 43,
            proof_hash: [0; 32],
            worker_uid: 1_001,
            worker_gid: 1_002,
        };
        let accepted = hello.sandbox_accepted([13; 32]);
        for expected in [accepted, accepted.sandbox_ready()] {
            for index in [12, 16, 32, 40, 72, 76, 80, 112, 116] {
                let mut mutated = expected.encode();
                mutated[index] ^= 1;
                match HandshakeRecord::decode(&mutated) {
                    Ok(decoded) => assert_ne!(decoded, expected),
                    Err(WorkerV3Error::Authentication) => {}
                    Err(error) => panic!("unexpected mutated-record error: {error}"),
                }
            }
        }
    }

    #[test]
    fn inheritable_parent_descriptor_is_confined_to_the_parent() {
        let mut command = child_command("fd-fence");
        let status = command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .expect("isolated inherited-descriptor fixture");
        assert!(status.success());
    }

    #[test]
    fn source_uses_no_abstract_listener_or_socketpair_peercred_proof() {
        let source = include_str!("worker_v3.rs");
        for retired in [
            ["Peer", "Credentials"].concat(),
            ["new_", "abstract"].concat(),
            ["private_", "listener"].concat(),
        ] {
            assert!(!source.contains(&retired));
        }
        assert!(source.contains("#[cfg(test)]\nfn spawn_with_command_fixture"));
        assert!(source.contains("#[cfg(test)]\nfn run_child_with_fixture_sandbox"));
        let close_range_hook = ["install_close_range_on_", "exec(&mut command);"].concat();
        assert_eq!(
            source.matches(&close_range_hook).count(),
            1,
            "the production spawn path owns one exact inherited-descriptor fence"
        );
        let production_spawn_symbol = ["spawn_worker_", "v3("].concat();
        assert_eq!(
            source.matches(&production_spawn_symbol).count(),
            2,
            "the production spawn has one definition and only the fixed live-proof caller"
        );
        assert!(source.contains("Command::new(\"/proc/self/exe\")"));
        let replaceable_path_lookup = ["current_", "exe("].concat();
        assert!(!source.contains(&replaceable_path_lookup));
    }

    #[test]
    fn live_proof_custody_name_is_fixed_and_valid() {
        assert_eq!(LIVE_FDSTORE_PUBLICATION_TIMEOUT, Duration::from_secs(5));
        assert_eq!(
            LIVE_PROOF_CUSTODY_FD_NAME.len(),
            crate::systemd_custody::CUSTODY_FD_NAME_BYTES
        );
        assert!(crate::systemd_fdstore::CustodyFdName::parse(LIVE_PROOF_CUSTODY_FD_NAME).is_ok());
    }

    #[test]
    fn live_proof_uses_only_the_production_spawn_and_confirmed_retirement_path() {
        let source = include_str!("worker_v3.rs");
        let start = source
            .find("fn run_internal_worker_v3_live_proof_inner()")
            .expect("live proof boundary");
        let end = source[start..]
            .find("\npub(crate) fn run_internal_worker_v3_entry()")
            .map(|offset| start + offset)
            .expect("worker entry boundary");
        let proof = &source[start..end];
        for required in [
            "validate_live_proof_parent_contract(effective_group)?",
            "prepare_production_runtime()?",
            "process.has_complete_kernel_pins()",
            "let publication_result = (|| -> Result<(), WorkerV3Error> {",
            "HardDeadline::after(LIVE_FDSTORE_PUBLICATION_TIMEOUT)?",
            "process.duplicate_recovery_identity_source_until(coordinates, deadline)?",
            ".verified_anchor_with_restart_custody()?",
            "restart_custody.ensure_live_and_namespace_matches_anchor(anchor)?",
            "crate::systemd_fdstore::BorrowedCustodyPair::new(",
            "tokio::runtime::Builder::new_current_thread()",
            "crate::systemd_fdstore::publish_current_process_custody(",
            "drop(restart_custody)",
            "drop(recovery_identity)",
            "process.terminate_bounded(TERMINATION_TIMEOUT)",
            "process.retirement_released_after_confirmed_reap()",
            "let registry_cleanup = registry.abandon_generation(reservation)",
            "publication_result.and(local_cleanup_result)",
        ] {
            assert!(
                proof.contains(required),
                "missing live-proof step: {required}"
            );
        }
        let production_spawn = ["spawn_worker_", "v3(reservation)"].concat();
        assert!(proof.contains(&production_spawn));
        assert_eq!(
            proof.matches("HardDeadline::after(").count(),
            1,
            "the live FD-store transaction owns one absolute publication deadline"
        );
        assert!(!proof.contains("Command::new"));
        assert!(!proof.contains("spawn_with_command_fixture"));
        let pinned = proof
            .find("process.has_complete_kernel_pins()")
            .expect("pin observation");
        let publication = proof
            .find("crate::systemd_fdstore::publish_current_process_custody(")
            .expect("custody publication");
        let local_custody_drop = proof
            .find("drop(restart_custody)")
            .expect("local custody release after attestation");
        let reaped = proof
            .find("process.terminate_bounded(TERMINATION_TIMEOUT)")
            .expect("confirmed reap");
        let released = proof
            .find("process.retirement_released_after_confirmed_reap()")
            .expect("retirement release");
        let registry_cleanup = proof
            .find("let registry_cleanup = registry.abandon_generation(reservation)")
            .expect("reservation cleanup");
        let result_propagation = proof
            .find("publication_result.and(local_cleanup_result)")
            .expect("publication result after cleanup attempts");
        assert!(
            pinned < publication
                && publication < local_custody_drop
                && local_custody_drop < reaped
                && reaped < released
                && released < registry_cleanup
                && registry_cleanup < result_propagation
        );
    }

    #[test]
    fn confirmed_reap_disarms_retirement_before_success_can_be_reported() {
        let (process, _peer, _alive) = fake_process(Duration::from_millis(10));
        assert!(!process.retirement_released_after_confirmed_reap());
        assert!(process.terminate_bounded(TERMINATION_TIMEOUT));
        assert!(process.retirement_released_after_confirmed_reap());
        assert!(!process.probe_alive());
    }

    #[test]
    fn parent_seccomp_baseline_is_locked_and_immediately_precedes_spawn() {
        let source = include_str!("worker_v3.rs");
        let mode_start = source
            .find("fn spawn_with_command_mode(")
            .expect("spawn mode function");
        let locked_start = source[mode_start..]
            .find("fn spawn_with_command_locked(")
            .map(|offset| mode_start + offset)
            .expect("locked spawn function");
        let mode_body = &source[mode_start..locked_start];
        let lock = mode_body
            .find("lock_worker_spawn_until(binding.deadline)?")
            .expect("deadline-bounded spawn lock");
        let locked_call = mode_body
            .rfind("spawn_with_command_locked(")
            .expect("locked spawn call");
        assert!(lock < locked_call);

        let production_spawn_boundary = ["\nfn spawn_worker_", "v3("].concat();
        let locked_end = source[locked_start..]
            .find(&production_spawn_boundary)
            .map(|offset| locked_start + offset)
            .expect("locked spawn boundary");
        let body = &source[locked_start..locked_end];
        let permit = body
            .find("acquire_retirement_permit()?")
            .expect("retirement permit");
        let close_range = body
            .find("install_close_range_on_exec(&mut command)")
            .expect("pre-exec fd fence");
        let secured_spawn = body
            .find("spawn_after_seccomp_baseline(")
            .expect("baseline-bound spawn helper");
        let armed_retirement = body
            .find("let mut retirement = ProcessRetirement")
            .expect("pre-spawn armed retirement owner");
        assert!(permit < armed_retirement && armed_retirement < close_range);
        assert!(close_range < secured_spawn);
        assert!(!body.contains("/proc/self/fd"));
        assert!(!body.contains("fdinfo"));

        let helper_start = source
            .find("fn spawn_after_seccomp_baseline(")
            .expect("baseline-bound spawn helper");
        let helper_end = source[helper_start..]
            .find("\nfn parent_handshake(")
            .map(|offset| helper_start + offset)
            .expect("spawn helper boundary");
        let helper_body = &source[helper_start..helper_end];
        let baseline = helper_body
            .find("observation_mode.capture_parent_seccomp_baseline()?")
            .expect("thread-self seccomp baseline");
        let deadline_gate = helper_body
            .find(
                "observation_mode.capture_parent_seccomp_baseline()?;\n    ensure_worker_deadline(deadline)?;\n    let child = command.spawn()?;",
            )
            .expect("deadline gate must be the only operation between baseline and spawn");
        assert_eq!(baseline, deadline_gate);
        assert!(
            helper_body.contains("let child = command.spawn()?;\n    *child_slot = Some(child);")
        );
    }

    #[test]
    fn spawn_until_times_out_while_lock_is_held_and_never_calls_command_spawn() {
        let spawn_guard = WORKER_SPAWN_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        let (started_sender, started_receiver) = std::sync::mpsc::sync_channel(0);
        let (result_sender, result_receiver) = std::sync::mpsc::sync_channel(0);
        let worker = thread::spawn(move || {
            let deadline =
                HardDeadline::after(Duration::from_millis(40)).expect("short spawn deadline");
            started_sender.send(()).expect("start signal");
            let started = Instant::now();
            let result = spawn_with_command_mode(
                Command::new("/volparossa-test-must-never-be-spawned"),
                WorkerSpawnBinding {
                    parent_identity: current_initial_identity(),
                    worker_identity: current_worker_identity(),
                    context_id: [45; 16],
                    generation: 1,
                    retained_environment: None,
                    deadline,
                },
                SandboxObservationMode::Fixture(fake_production_sandbox_snapshot()),
            );
            result_sender
                .send((result, started.elapsed()))
                .expect("result signal");
        });
        started_receiver.recv().expect("spawn attempt started");
        let (result, elapsed) = result_receiver
            .recv_timeout(Duration::from_secs(2))
            .expect("spawn lock acquisition must obey its hard deadline");
        assert!(matches!(result, Err(WorkerV3Error::Deadline)));
        assert!(elapsed < Duration::from_secs(2));
        drop(spawn_guard);
        worker.join().expect("spawn waiter");
    }

    #[tokio::test]
    async fn authenticated_child_uses_hardened_exec_and_only_memory_operations() {
        let context_id = [1; 16];
        let mut registry = WorkerRegistry::new(1, 8, Duration::from_secs(10));
        let reservation = registry
            .reserve_generation(context_id, Duration::from_secs(5), Instant::now())
            .expect("generation reserved before child spawn");
        let spawned =
            spawn_reserved_fixture("connect", reservation).expect("authenticated bound child");
        assert_ne!(spawned.process.child_pid, process::id());
        let generation = registry
            .commit_spawned(spawned, Instant::now())
            .expect("commit exact pre-spawn reservation");
        assert_eq!(generation, 1);
        let coordinator = WorkerCoordinator::new(registry);

        let execution = coordinator
            .execute(context_id, generation, initialise(context_id, 7))
            .await
            .expect("initialise");
        assert_eq!(execution.response.result, InternalWorkerResult::Ok as i32);
        assert!(execution.descriptor.is_none());

        let execution = coordinator
            .execute(context_id, generation, destroy(context_id, 8))
            .await
            .expect("destroy");
        assert_eq!(execution.response.result, InternalWorkerResult::Ok as i32);
        assert!(execution.descriptor.is_none());
        assert!(matches!(
            coordinator.phase(context_id, generation),
            Err(WorkerV3Error::Stale)
        ));
        assert!(coordinator.shutdown().await);
    }

    #[test]
    fn worker_recovery_parts_map_to_the_exact_durable_anchor_fields() {
        let parts = crate::worker_sandbox::WorkerRecoveryAnchorParts {
            boot_id: [1; 16],
            pid: NonZeroU32::new(2).expect("pid"),
            process_start_ticks: NonZeroU64::new(3).expect("start ticks"),
            network_namespace_device: NonZeroU64::new(4).expect("namespace device"),
            network_namespace_inode: NonZeroU64::new(5).expect("namespace inode"),
            executable_device: NonZeroU64::new(6).expect("executable device"),
            executable_inode: NonZeroU64::new(7).expect("executable inode"),
            service_cgroup_inode: NonZeroU64::new(8).expect("cgroup inode"),
        };
        let actual = durable_prepare_anchor_from_worker_parts(parts).expect("mapped anchor");
        let expected = crate::ownership_journal::durable_prepare_anchor_from_parts(
            crate::ownership_journal::DurablePrepareAnchorParts {
                boot_id: [1; 16],
                pid: NonZeroU32::new(2).expect("pid"),
                process_start_ticks: NonZeroU64::new(3).expect("start ticks"),
                network_namespace_device: NonZeroU64::new(4).expect("namespace device"),
                network_namespace_inode: NonZeroU64::new(5).expect("namespace inode"),
                executable_device: NonZeroU64::new(6).expect("executable device"),
                executable_inode: NonZeroU64::new(7).expect("executable inode"),
                service_cgroup_inode: NonZeroU64::new(8).expect("cgroup inode"),
            },
        )
        .expect("expected anchor");
        assert!(actual == expected);
    }

    #[test]
    fn durable_passive_handoff_journals_before_spawn_and_sends_zero_request_bytes() {
        let context_id = [90; 16];
        let directory = tempdir().expect("durable handoff directory");
        let actor = crate::ownership_journal::spawn_test_durable_ownership_actor_until(
            directory.path(),
            HardDeadline::after(Duration::from_secs(5)).expect("actor fixture deadline"),
        )
        .expect("durable ownership actor fixture");
        let journal_path = directory.path().join("helper.ownership-v3");
        assert!(!journal_path.exists());
        let journal_advanced_before_spawn = Arc::new(AtomicBool::new(false));
        let observed_advance = Arc::clone(&journal_advanced_before_spawn);
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let registration = durable_worker_registration(context_id, 90);
        let (mut process, peer, _alive) = fake_process(Duration::from_secs(1));
        let deadline =
            HardDeadline::after(Duration::from_secs(5)).expect("durable handoff deadline");
        let outcome = coordinator.durable_passive_prepare_handoff_with_until(
            &actor,
            registration,
            Duration::from_secs(5),
            deadline,
            move |reservation, _deadline| {
                let durable_before_spawn =
                    fs::read(&journal_path).is_ok_and(|current| !current.is_empty());
                observed_advance.store(durable_before_spawn, Ordering::SeqCst);
                process.binding = Some(reservation.binding());
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xc0; 32]),
                })
            },
        );

        let DurableWorkerPrepareOutcome::CustodyPublication(publication) = outcome else {
            panic!("durable passive handoff did not retain publication authority: {outcome:?}")
        };
        assert!(journal_advanced_before_spawn.load(Ordering::SeqCst));
        assert_eq!(publication.deadline, deadline);
        assert_eq!(
            publication.handoff.registered.worker.coordinates.context_id,
            context_id
        );
        assert_eq!(
            publication
                .handoff
                .registered
                .worker
                .coordinates
                .worker_generation
                .get(),
            1
        );
        assert_durable_handoff_fence_owner(&publication.handoff.registered.worker);
        assert_eq!(
            publication.handoff.source.pending.coordinates,
            publication.handoff.registered.worker.coordinates
        );
        assert_eq!(
            coordinator
                .phase(context_id, 1)
                .expect("passive worker remains registered"),
            VisiblePhase::DurableHandoffPending
        );
        assert_no_worker_request_bytes(&peer);

        let attestation = exact_custody_attestation(&publication);
        let outcome = coordinator.arm_attested_durable_worker(&actor, publication, attestation);
        let DurableWorkerPostAttestationOutcome::MayOwn(may_own) = outcome else {
            panic!("exact custody attestation did not arm durable ownership: {outcome:?}")
        };
        assert_eq!(may_own.durable.context_id(), context_id);
        assert_eq!(may_own.durable.resources().len(), 1);
        assert_eq!(may_own.worker.coordinates.context_id, context_id);
        assert_eq!(may_own.worker.coordinates.worker_generation.get(), 1);
        assert_durable_handoff_fence_owner(&may_own.worker);
        assert_eq!(
            may_own.source.pending.coordinates,
            may_own.worker.coordinates
        );
        assert_eq!(
            format!("{:?}", may_own.attestation),
            "InventoryAttestation(<redacted>)"
        );

        let DurableWorkerMayOwnPrepare {
            durable,
            worker,
            source,
            custody_name: _,
            attestation,
        } = may_own;
        drop(durable);
        drop(source);
        drop(attestation);
        reap_durable_handoff_worker(&coordinator, worker);
        drop(actor);
        drop(directory);
    }

    #[test]
    fn durable_dispatch_fence_blocks_execute_before_arm_and_after_may_own() {
        let context_id = [97; 16];
        let fixture = fenced_durable_handoff_fixture(
            context_id,
            HardDeadline::after(Duration::from_secs(5)).expect("dispatch-fence deadline"),
            |coordinator, context_id, generation| {
                assert_durable_handoff_registry_pristine(coordinator, context_id, generation);
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_time()
                    .build()
                    .expect("dispatch-fence runtime");
                let result = runtime.block_on(coordinator.execute_until(
                    context_id,
                    generation,
                    initialise(context_id, 97),
                    HardDeadline::after(Duration::from_secs(1)).expect("pre-arm execute deadline"),
                ));
                assert!(matches!(result, Err(WorkerV3Error::Busy)));
                assert_durable_handoff_registry_pristine(coordinator, context_id, generation);
            },
        );
        assert_no_worker_request_bytes(&fixture.peer);
        assert_durable_handoff_registry_pristine(&fixture.coordinator, context_id, 1);

        let DurableWorkerPrepareOutcome::CustodyPublication(publication) = fixture.outcome else {
            panic!("dispatch-fenced handoff did not retain custody publication authority")
        };
        assert_durable_handoff_fence_owner(&publication.handoff.registered.worker);
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("pre-attestation dispatch-fence runtime");
        let result = runtime.block_on(fixture.coordinator.execute_until(
            context_id,
            1,
            initialise(context_id, 98),
            HardDeadline::after(Duration::from_secs(1)).expect("pre-attestation execute deadline"),
        ));
        assert!(matches!(result, Err(WorkerV3Error::Busy)));
        assert_no_worker_request_bytes(&fixture.peer);
        assert_durable_handoff_registry_pristine(&fixture.coordinator, context_id, 1);

        let attestation = exact_custody_attestation(&publication);
        let outcome = fixture.coordinator.arm_attested_durable_worker(
            &fixture.actor,
            publication,
            attestation,
        );
        let DurableWorkerPostAttestationOutcome::MayOwn(may_own) = outcome else {
            panic!("dispatch-fenced attestation did not reach durable MayOwnPrepare")
        };
        assert_durable_handoff_fence_owner(&may_own.worker);
        let result = runtime.block_on(fixture.coordinator.execute_until(
            context_id,
            1,
            initialise(context_id, 99),
            HardDeadline::after(Duration::from_secs(1)).expect("post-arm execute deadline"),
        ));
        assert!(matches!(result, Err(WorkerV3Error::Busy)));
        assert_no_worker_request_bytes(&fixture.peer);
        assert_durable_handoff_registry_pristine(&fixture.coordinator, context_id, 1);

        let DurableWorkerMayOwnPrepare {
            durable,
            worker,
            source,
            custody_name: _,
            attestation,
        } = may_own;
        drop(durable);
        drop(source);
        drop(attestation);
        reap_durable_handoff_worker(&fixture.coordinator, worker);
        drop(fixture.actor);
        drop(fixture.directory);
    }

    #[test]
    fn mismatched_custody_attestation_retains_every_publication_owner() {
        let context_id = [104; 16];
        let fixture = fenced_durable_handoff_fixture(
            context_id,
            HardDeadline::after(Duration::from_secs(5)).expect("attestation mismatch deadline"),
            |_coordinator, _context_id, _generation| {},
        );
        let DurableWorkerPrepareOutcome::CustodyPublication(publication) = fixture.outcome else {
            panic!("durable handoff did not retain publication authority")
        };
        let custody = crate::systemd_fdstore::BorrowedCustodyPair::new(
            publication.handoff.source.restart_custody.borrowed_pidfd(),
            publication
                .handoff
                .source
                .restart_custody
                .borrowed_network_namespace(),
        )
        .expect("distinct attestation-mismatch custody roles");
        let wrong_name = different_custody_name(publication.custody_name);
        let attestation = crate::systemd_fdstore::InventoryAttestation::for_test_exact_custody(
            wrong_name, custody,
        )
        .expect("well-formed mismatched custody attestation");

        let outcome = fixture.coordinator.arm_attested_durable_worker(
            &fixture.actor,
            publication,
            attestation,
        );
        let DurableWorkerPostAttestationOutcome::PublicationUnresolved {
            error: WorkerV3Error::SystemdCustodyInput(_),
            publication,
            attestation,
        } = outcome
        else {
            panic!("mismatched attestation did not retain every owner: {outcome:?}")
        };
        assert_eq!(
            publication.handoff.source.pending.coordinates,
            publication.handoff.registered.worker.coordinates
        );
        assert_durable_handoff_fence_owner(&publication.handoff.registered.worker);
        assert_eq!(
            format!("{attestation:?}"),
            "InventoryAttestation(<redacted>)"
        );
        assert_no_worker_request_bytes(&fixture.peer);
        retain_and_reap_durable_publication(&fixture.coordinator, publication);
        drop(attestation);
        drop(fixture.actor);
        drop(fixture.directory);
    }

    #[test]
    fn post_attestation_worker_change_retains_every_owner_before_arm() {
        let context_id = [105; 16];
        let fixture = fenced_durable_handoff_fixture(
            context_id,
            HardDeadline::after(Duration::from_secs(5)).expect("post-attestation fence deadline"),
            |_coordinator, _context_id, _generation| {},
        );
        let DurableWorkerPrepareOutcome::CustodyPublication(publication) = fixture.outcome else {
            panic!("durable handoff did not retain publication authority")
        };
        let attestation = exact_custody_attestation(&publication);
        lock_worker_registry(&fixture.coordinator.registry)
            .records
            .get_mut(&context_id)
            .expect("registered publication worker")
            .stable_phase = StablePhase::Initialised;

        let outcome = fixture.coordinator.arm_attested_durable_worker(
            &fixture.actor,
            publication,
            attestation,
        );
        let DurableWorkerPostAttestationOutcome::PublicationUnresolved {
            error: WorkerV3Error::Conflict,
            publication,
            attestation,
        } = outcome
        else {
            panic!("post-attestation phase change did not retain every owner: {outcome:?}")
        };
        assert_eq!(
            publication.handoff.source.pending.coordinates,
            publication.handoff.registered.worker.coordinates
        );
        assert_durable_handoff_fence_owner(&publication.handoff.registered.worker);
        assert_eq!(
            format!("{attestation:?}"),
            "InventoryAttestation(<redacted>)"
        );
        assert_no_worker_request_bytes(&fixture.peer);
        lock_worker_registry(&fixture.coordinator.registry)
            .records
            .get_mut(&context_id)
            .expect("registered publication worker")
            .stable_phase = StablePhase::Starting;
        retain_and_reap_durable_publication(&fixture.coordinator, publication);
        drop(attestation);
        drop(fixture.actor);
        drop(fixture.directory);
    }

    #[test]
    fn expired_attested_arm_fences_identity_io_and_cannot_refresh_the_original_deadline() {
        let context_id = [106; 16];
        let deadline =
            HardDeadline::after(Duration::from_secs(1)).expect("retained publication deadline");
        let fixture = fenced_durable_handoff_fixture(
            context_id,
            deadline,
            |_coordinator, _context_id, _generation| {},
        );
        let DurableWorkerPrepareOutcome::CustodyPublication(publication) = fixture.outcome else {
            panic!("durable handoff did not retain publication authority")
        };
        assert_eq!(publication.deadline, deadline);
        let custody = crate::systemd_fdstore::BorrowedCustodyPair::new(
            publication.handoff.source.restart_custody.borrowed_pidfd(),
            publication
                .handoff
                .source
                .restart_custody
                .borrowed_network_namespace(),
        )
        .expect("distinct expired-publication custody roles");
        let attestation = crate::systemd_fdstore::InventoryAttestation::for_test_exact_custody(
            different_custody_name(publication.custody_name),
            custody,
        )
        .expect("well-formed mismatched attestation behind the deadline fence");
        wait_until_deadline_elapsed(deadline);

        let outcome = fixture.coordinator.arm_attested_durable_worker(
            &fixture.actor,
            publication,
            attestation,
        );
        let DurableWorkerPostAttestationOutcome::PublicationUnresolved {
            error: WorkerV3Error::Deadline,
            publication,
            attestation,
        } = outcome
        else {
            panic!("expired original deadline did not retain every owner: {outcome:?}")
        };
        assert_eq!(publication.deadline, deadline);
        assert_durable_handoff_fence_owner(&publication.handoff.registered.worker);
        assert_eq!(
            format!("{attestation:?}"),
            "InventoryAttestation(<redacted>)"
        );
        assert_no_worker_request_bytes(&fixture.peer);
        retain_and_reap_durable_publication(&fixture.coordinator, publication);
        drop(attestation);
        drop(fixture.actor);
        drop(fixture.directory);
    }

    #[test]
    fn durable_arm_failure_reconstructs_publication_owner_with_attestation() {
        let context_id = [107; 16];
        let mut fixture = fenced_durable_handoff_fixture(
            context_id,
            HardDeadline::after(Duration::from_secs(5)).expect("arm failure deadline"),
            |_coordinator, _context_id, _generation| {},
        );
        let DurableWorkerPrepareOutcome::CustodyPublication(publication) = fixture.outcome else {
            panic!("durable handoff did not retain publication authority")
        };
        let attestation = exact_custody_attestation(&publication);
        assert!(matches!(
            fixture.actor.shutdown_for_test(
                HardDeadline::after(Duration::from_secs(1)).expect("actor shutdown deadline"),
            ),
            Err(DurableOwnershipError::RecoveryNotConfirmed)
        ));

        let outcome = fixture.coordinator.arm_attested_durable_worker(
            &fixture.actor,
            publication,
            attestation,
        );
        let DurableWorkerPostAttestationOutcome::ArmRetained {
            error: DurableOwnershipError::Unavailable,
            publication,
            attestation,
        } = outcome
        else {
            panic!("actor failure did not reconstruct every owner: {outcome:?}")
        };
        assert_eq!(
            format!("{:?}", publication.handoff.registered.key),
            "DurableOwnershipKey(<redacted>)"
        );
        assert_eq!(
            publication.handoff.source.pending.coordinates,
            publication.handoff.registered.worker.coordinates
        );
        assert_durable_handoff_fence_owner(&publication.handoff.registered.worker);
        assert_eq!(
            format!("{attestation:?}"),
            "InventoryAttestation(<redacted>)"
        );
        assert_no_worker_request_bytes(&fixture.peer);
        retain_and_reap_durable_publication(&fixture.coordinator, publication);
        drop(attestation);
        drop(fixture.actor);
        drop(fixture.directory);
    }

    #[test]
    fn ordinary_open_worker_registration_remains_plannable() {
        let context_id = [98; 16];
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, peer, _alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("ordinary Open registration");
        assert_eq!(
            registry
                .records
                .get(&context_id)
                .expect("ordinary worker record")
                .dispatch_fence,
            WorkerDispatchFence::Open
        );
        let planned = call(
            registry
                .plan(
                    context_id,
                    generation,
                    &initialise(context_id, 99),
                    Instant::now(),
                )
                .expect("ordinary Open worker remains plannable"),
        );
        assert_no_worker_request_bytes(&peer);
        let detached = registry
            .mark_ambiguous(planned.token)
            .expect("ordinary plan can be retired")
            .expect("ordinary plan owns exact worker");
        assert!(detached.process.terminate_bounded(TERMINATION_TIMEOUT));
    }

    #[test]
    fn durable_handoff_expired_registration_retains_intent_and_never_starts_spawn() {
        let context_id = [94; 16];
        let directory = tempdir().expect("expired registration directory");
        let actor = crate::ownership_journal::spawn_test_durable_ownership_actor_until(
            directory.path(),
            HardDeadline::after(Duration::from_secs(5)).expect("actor fixture deadline"),
        )
        .expect("durable ownership actor fixture");
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let spawn_calls = Arc::new(AtomicUsize::new(0));
        let observed_spawn_calls = Arc::clone(&spawn_calls);
        let deadline =
            HardDeadline::after(Duration::from_millis(20)).expect("expired registration deadline");
        wait_until_deadline_elapsed(deadline);
        let outcome = coordinator.durable_passive_prepare_handoff_with_until(
            &actor,
            durable_worker_registration(context_id, 94),
            Duration::from_secs(5),
            deadline,
            move |_reservation, _deadline| {
                observed_spawn_calls.fetch_add(1, Ordering::SeqCst);
                panic!("expired durable registration must not start worker spawn")
            },
        );
        let DurableWorkerPrepareOutcome::RegistrationRetained {
            error,
            registration,
        } = outcome
        else {
            panic!("expired durable registration did not retain its affine owner")
        };
        assert!(matches!(error, DurableOwnershipError::DeadlineElapsed));
        assert_eq!(registration.context_id(), context_id);
        assert_eq!(spawn_calls.load(Ordering::SeqCst), 0);
        drop(registration);
        drop(actor);
        drop(directory);
    }

    #[test]
    fn durable_handoff_invalid_worker_ttl_retains_key_and_never_starts_spawn() {
        let context_id = [95; 16];
        let directory = tempdir().expect("invalid TTL directory");
        let actor = crate::ownership_journal::spawn_test_durable_ownership_actor_until(
            directory.path(),
            HardDeadline::after(Duration::from_secs(5)).expect("actor fixture deadline"),
        )
        .expect("durable ownership actor fixture");
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let spawn_calls = Arc::new(AtomicUsize::new(0));
        let observed_spawn_calls = Arc::clone(&spawn_calls);
        let outcome = coordinator.durable_passive_prepare_handoff_with_until(
            &actor,
            durable_worker_registration(context_id, 95),
            Duration::ZERO,
            HardDeadline::after(Duration::from_secs(5)).expect("invalid TTL deadline"),
            move |_reservation, _deadline| {
                observed_spawn_calls.fetch_add(1, Ordering::SeqCst);
                panic!("invalid worker TTL must not start worker spawn")
            },
        );
        let DurableWorkerPrepareOutcome::KeyRetained { error, key } = outcome else {
            panic!("invalid worker TTL did not retain its durable key")
        };
        assert!(matches!(error, WorkerV3Error::Invalid));
        assert_eq!(format!("{key:?}"), "DurableOwnershipKey(<redacted>)");
        assert_eq!(spawn_calls.load(Ordering::SeqCst), 0);
        drop(key);
        drop(actor);
        drop(directory);
    }

    #[test]
    fn durable_handoff_ambiguous_spawn_retains_key_and_worker_generation_owner() {
        let context_id = [96; 16];
        let directory = tempdir().expect("ambiguous spawn directory");
        let actor = crate::ownership_journal::spawn_test_durable_ownership_actor_until(
            directory.path(),
            HardDeadline::after(Duration::from_secs(5)).expect("actor fixture deadline"),
        )
        .expect("durable ownership actor fixture");
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let spawn_calls = Arc::new(AtomicUsize::new(0));
        let observed_spawn_calls = Arc::clone(&spawn_calls);
        let outcome = coordinator.durable_passive_prepare_handoff_with_until(
            &actor,
            durable_worker_registration(context_id, 96),
            Duration::from_secs(5),
            HardDeadline::after(Duration::from_secs(5)).expect("ambiguous spawn deadline"),
            move |reservation, _deadline| {
                observed_spawn_calls.fetch_add(1, Ordering::SeqCst);
                Err(WorkerSpawnFailure {
                    error: WorkerV3Error::Ambiguous,
                    reservation,
                })
            },
        );
        let DurableWorkerPrepareOutcome::WorkerAdmissionRetained { error, key, worker } = outcome
        else {
            panic!("ambiguous spawn did not retain both affine owners")
        };
        assert!(matches!(error, WorkerV3Error::Ambiguous));
        assert_eq!(spawn_calls.load(Ordering::SeqCst), 1);
        assert_eq!(worker.coordinates.context_id, context_id);
        assert_eq!(worker.coordinates.worker_generation.get(), 1);
        assert!(matches!(
            worker.placement.as_ref(),
            Some(WorkerGenerationPlacement::SpawnAmbiguous(_))
        ));
        assert!(worker.has_valid_dispatch_fence_shape());
        assert_eq!(
            worker.dispatch_registration,
            WorkerDispatchRegistration::DurableHandoffPending
        );
        assert!(worker.handoff_fence.is_none());
        assert_eq!(format!("{key:?}"), "DurableOwnershipKey(<redacted>)");
        drop(key);
        drop(worker);
        drop(actor);
        drop(directory);
    }

    #[test]
    fn durable_handoff_phase_fence_retains_key_worker_and_source_before_arm() {
        let context_id = [91; 16];
        let fixture = fenced_durable_handoff_fixture(
            context_id,
            HardDeadline::after(Duration::from_secs(5)).expect("phase-fence deadline"),
            |coordinator, context_id, _generation| {
                lock_worker_registry(&coordinator.registry)
                    .records
                    .get_mut(&context_id)
                    .expect("registered passive worker")
                    .stable_phase = StablePhase::Initialised;
            },
        );
        assert_no_worker_request_bytes(&fixture.peer);
        let DurableWorkerPrepareOutcome::HandoffWorkerRetained { error, handoff } = fixture.outcome
        else {
            panic!("phase change did not retain the complete pre-arm handoff")
        };
        assert!(matches!(error, WorkerV3Error::Conflict));
        assert_eq!(handoff.source.pending.coordinates.context_id, context_id);
        assert_durable_handoff_fence_owner(&handoff.registered.worker);
        assert_eq!(
            format!("{:?}", handoff.registered.key),
            "DurableOwnershipKey(<redacted>)"
        );
        lock_worker_registry(&fixture.coordinator.registry)
            .records
            .get_mut(&context_id)
            .expect("registered passive worker")
            .stable_phase = StablePhase::Starting;
        let DurableWorkerPrepareHandoff { registered, source } = handoff;
        let DurableRegisteredStartingWorker { key, worker } = registered;
        drop(key);
        drop(source);
        reap_durable_handoff_worker(&fixture.coordinator, worker);
        drop(fixture.actor);
        drop(fixture.directory);
    }

    #[test]
    fn durable_handoff_binding_fence_retains_key_worker_and_source_before_arm() {
        let context_id = [92; 16];
        let fixture = fenced_durable_handoff_fixture(
            context_id,
            HardDeadline::after(Duration::from_secs(5)).expect("binding-fence deadline"),
            |coordinator, context_id, generation| {
                lock_worker_registry(&coordinator.registry)
                    .records
                    .get_mut(&context_id)
                    .and_then(|record| record.process.as_mut())
                    .expect("registered passive worker")
                    .binding = Some(([0xfe; 16], generation));
            },
        );
        assert_no_worker_request_bytes(&fixture.peer);
        let DurableWorkerPrepareOutcome::HandoffWorkerRetained { error, handoff } = fixture.outcome
        else {
            panic!("binding change did not retain the complete pre-arm handoff")
        };
        assert!(matches!(error, WorkerV3Error::Stale));
        assert_eq!(handoff.source.pending.coordinates.context_id, context_id);
        assert_durable_handoff_fence_owner(&handoff.registered.worker);
        lock_worker_registry(&fixture.coordinator.registry)
            .records
            .get_mut(&context_id)
            .and_then(|record| record.process.as_mut())
            .expect("registered passive worker")
            .binding = Some((context_id, 1));
        let DurableWorkerPrepareHandoff { registered, source } = handoff;
        let DurableRegisteredStartingWorker { key, worker } = registered;
        drop(key);
        drop(source);
        reap_durable_handoff_worker(&fixture.coordinator, worker);
        drop(fixture.actor);
        drop(fixture.directory);
    }

    #[test]
    fn durable_handoff_deadline_fence_retains_key_worker_and_source_before_arm() {
        let context_id = [93; 16];
        let deadline =
            HardDeadline::after(Duration::from_secs(2)).expect("deadline-fence deadline");
        let fixture = fenced_durable_handoff_fixture(
            context_id,
            deadline,
            |_coordinator, _context_id, _generation| wait_until_deadline_elapsed(deadline),
        );
        assert_no_worker_request_bytes(&fixture.peer);
        let DurableWorkerPrepareOutcome::HandoffWorkerRetained { error, handoff } = fixture.outcome
        else {
            panic!("elapsed deadline did not retain the complete pre-arm handoff")
        };
        assert!(matches!(error, WorkerV3Error::Deadline));
        assert_eq!(handoff.source.pending.coordinates.context_id, context_id);
        assert_durable_handoff_fence_owner(&handoff.registered.worker);
        let DurableWorkerPrepareHandoff { registered, source } = handoff;
        let DurableRegisteredStartingWorker { key, worker } = registered;
        drop(key);
        drop(source);
        reap_durable_handoff_worker(&fixture.coordinator, worker);
        drop(fixture.actor);
        drop(fixture.directory);
    }

    #[test]
    fn durable_pending_fence_survives_ambiguous_reap_and_exact_retry() {
        let context_id = [99; 16];
        let fixture =
            durable_pending_lifecycle_fixture(context_id, VecDeque::from([false, true]), true);
        assert_durable_handoff_registry_pristine(&fixture.coordinator, context_id, 1);
        assert_no_worker_request_bytes(&fixture.peer);

        let retained = match fixture.coordinator.terminate_generation_until(
            fixture.worker,
            HardDeadline::after(Duration::from_secs(1)).expect("first reap deadline"),
        ) {
            WorkerGenerationReap::Retained {
                error: WorkerV3Error::Ambiguous,
                ownership,
            } => *ownership,
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected pending reap result: {error}")
            }
            WorkerGenerationReap::Confirmed(_) => {
                panic!("ambiguous pending worker was falsely confirmed absent")
            }
        };
        assert_durable_handoff_fence_owner(&retained);
        assert!(matches!(
            retained.placement.as_ref(),
            Some(WorkerGenerationPlacement::Detached(detached))
                if detached.reservation.is_none()
        ));
        assert_eq!(fixture.attempts.load(Ordering::SeqCst), 1);
        assert!(fixture.alive.load(Ordering::SeqCst));
        {
            let registry = lock_worker_registry(&fixture.coordinator.registry);
            let record = registry.records.get(&context_id).expect("pending record");
            assert_eq!(
                record.dispatch_fence,
                WorkerDispatchFence::DurableHandoffPending
            );
            assert!(record.quarantined);
            assert!(record.process.is_none());
        }

        match fixture.coordinator.terminate_generation_until(
            retained,
            HardDeadline::after(Duration::from_secs(1)).expect("retry reap deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => {
                assert_eq!(proof.coordinates.context_id, context_id);
            }
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("pending reap retry remained unresolved: {error}")
            }
        }
        assert_eq!(fixture.attempts.load(Ordering::SeqCst), 2);
        assert!(!fixture.alive.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn durable_pending_timeout_reattach_preserves_gate_and_affine_owner() {
        let context_id = [100; 16];
        let fixture =
            durable_pending_lifecycle_fixture(context_id, VecDeque::from([false, true]), true);
        let detached = lock_worker_registry(&fixture.coordinator.registry)
            .report_dead(context_id, 1)
            .expect("exact pending detach")
            .expect("pending worker process owner");
        let supervisor = WorkerSupervisor {
            registry: Arc::clone(&fixture.coordinator.registry),
            settlements: Arc::clone(&fixture.coordinator.settlements),
        };
        assert!(!supervisor.retire(detached).await);
        assert_eq!(fixture.attempts.load(Ordering::SeqCst), 1);
        assert!(fixture.alive.load(Ordering::SeqCst));
        assert_durable_handoff_fence_owner(&fixture.worker);
        {
            let registry = lock_worker_registry(&fixture.coordinator.registry);
            let record = registry
                .records
                .get(&context_id)
                .expect("reattached record");
            assert_eq!(
                record.dispatch_fence,
                WorkerDispatchFence::DurableHandoffPending
            );
            assert!(record.quarantined);
            assert!(record.in_flight.is_none());
            assert!(record.process.is_some());
        }
        assert_no_worker_request_bytes(&fixture.peer);

        reap_durable_handoff_worker(&fixture.coordinator, fixture.worker);
        assert_eq!(fixture.attempts.load(Ordering::SeqCst), 2);
        assert!(!fixture.alive.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn durable_pending_shutdown_preserves_owner_until_exact_absence_proof() {
        let context_id = [101; 16];
        let fixture = durable_pending_lifecycle_fixture(context_id, VecDeque::new(), true);
        assert_no_worker_request_bytes(&fixture.peer);
        assert!(fixture.coordinator.shutdown().await);
        assert_eq!(fixture.attempts.load(Ordering::SeqCst), 1);
        assert!(!fixture.alive.load(Ordering::SeqCst));
        assert_durable_handoff_fence_owner(&fixture.worker);
        assert!(matches!(
            fixture.coordinator.phase(context_id, 1),
            Err(WorkerV3Error::Stale)
        ));

        match fixture.coordinator.terminate_generation_until(
            fixture.worker,
            HardDeadline::after(Duration::from_secs(1)).expect("absence proof deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => {
                assert_eq!(proof.coordinates.context_id, context_id);
            }
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("shutdown did not leave exact pending absence: {error}")
            }
        }
    }

    #[tokio::test]
    async fn stale_durable_pending_owner_cannot_touch_replacement_generation() {
        let context_id = [102; 16];
        let fixture = durable_pending_lifecycle_fixture(context_id, VecDeque::new(), true);
        let detached = lock_worker_registry(&fixture.coordinator.registry)
            .report_dead(context_id, 1)
            .expect("detach old pending generation")
            .expect("old pending process owner");
        let supervisor = WorkerSupervisor {
            registry: Arc::clone(&fixture.coordinator.registry),
            settlements: Arc::clone(&fixture.coordinator.settlements),
        };
        assert!(supervisor.retire(detached).await);
        assert_durable_handoff_fence_owner(&fixture.worker);

        let (replacement, replacement_peer, replacement_alive) =
            fake_process(Duration::from_secs(1));
        let replacement_generation = lock_worker_registry(&fixture.coordinator.registry)
            .register(
                context_id,
                replacement,
                Duration::from_secs(5),
                Instant::now(),
            )
            .expect("replacement Open generation");
        assert_eq!(replacement_generation, 2);

        match fixture.coordinator.terminate_generation_until(
            fixture.worker,
            HardDeadline::after(Duration::from_secs(1)).expect("stale owner deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => {
                assert_eq!(proof.coordinates.worker_generation.get(), 1);
            }
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("old pending owner did not observe exact absence: {error}")
            }
        }
        {
            let registry = lock_worker_registry(&fixture.coordinator.registry);
            let replacement = registry
                .records
                .get(&context_id)
                .expect("replacement record");
            assert_eq!(replacement.generation, replacement_generation);
            assert_eq!(replacement.dispatch_fence, WorkerDispatchFence::Open);
            assert_eq!(replacement.stable_phase, StablePhase::Starting);
            assert!(!replacement.quarantined);
            assert!(replacement.process.is_some());
        }
        assert!(replacement_alive.load(Ordering::SeqCst));
        assert_no_worker_request_bytes(&replacement_peer);

        let detached = lock_worker_registry(&fixture.coordinator.registry)
            .report_dead(context_id, replacement_generation)
            .expect("detach replacement")
            .expect("replacement process owner");
        assert!(supervisor.retire(detached).await);
        assert!(!replacement_alive.load(Ordering::SeqCst));
    }

    #[test]
    fn durable_pending_spawned_retry_commits_pending_with_exact_fence() {
        let context_id = [103; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        coordinator.set_lifecycle_mutation_hook(Some(LifecycleMutationHook {
            point: LifecycleMutationPoint::Commit,
            reached: Arc::clone(&reached),
            release: Arc::clone(&release),
        }));
        let (mut process, peer, alive) = fake_process(Duration::from_secs(1));
        let worker_coordinator = coordinator.clone();
        let deadline = HardDeadline::after(Duration::from_secs(2)).expect("commit fence deadline");
        let admission = thread::spawn(move || {
            worker_coordinator.reserve_spawn_register_durable_handoff_with_until(
                context_id,
                Duration::from_secs(5),
                deadline,
                move |reservation, _deadline| {
                    process.binding = Some(reservation.binding());
                    Ok(SpawnedWorker {
                        reservation,
                        process,
                        bootstrap_challenge: BootstrapChallenge([0xd1; 32]),
                    })
                },
            )
        });
        reached.wait();
        wait_until_deadline_elapsed(deadline);
        release.wait();
        let retained = match admission.join().expect("pending commit thread") {
            WorkerLifecycleAdmission::Retained {
                error: WorkerV3Error::Deadline,
                ownership,
            } => ownership,
            WorkerLifecycleAdmission::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected pending commit result: {error}")
            }
            WorkerLifecycleAdmission::Registered(ownership) => {
                drop(ownership);
                panic!("expired pending commit registered a worker")
            }
            WorkerLifecycleAdmission::Rejected(error) => {
                panic!("expired pending commit lost its spawned owner: {error}")
            }
        };
        assert!(retained.has_valid_dispatch_fence_shape());
        assert_eq!(
            retained.dispatch_registration,
            WorkerDispatchRegistration::DurableHandoffPending
        );
        assert!(retained.handoff_fence.is_none());
        assert!(matches!(
            retained.placement.as_ref(),
            Some(WorkerGenerationPlacement::Spawned(_))
        ));
        assert!(
            lock_worker_registry(&coordinator.registry)
                .records
                .is_empty()
        );
        assert!(alive.load(Ordering::SeqCst));
        assert_no_worker_request_bytes(&peer);

        coordinator.set_lifecycle_mutation_hook(None);
        let registered = match coordinator.settle_lifecycle_ownership_until(
            retained,
            HardDeadline::after(Duration::from_secs(1)).expect("pending commit retry deadline"),
        ) {
            WorkerLifecycleSettlement::Registered(worker) => worker,
            WorkerLifecycleSettlement::Retained { error, ownership } => {
                drop(ownership);
                panic!("pending commit retry remained unresolved: {error}")
            }
            WorkerLifecycleSettlement::ConfirmedAbsent(_) => {
                panic!("spawned pending worker was falsely absent")
            }
        };
        assert_durable_handoff_fence_owner(&registered);
        assert_durable_handoff_registry_pristine(&coordinator, context_id, 1);
        assert_no_worker_request_bytes(&peer);
        reap_durable_handoff_worker(&coordinator, registered);
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[test]
    fn durable_publication_and_attested_arm_boundaries_are_static_and_dispatch_free() {
        let source = include_str!("worker_v3.rs");
        let start = source
            .find("    fn durable_passive_prepare_handoff_with_until<Spawn>(")
            .expect("durable handoff implementation");
        let arm_start = source[start..]
            .find("    fn arm_attested_durable_worker(")
            .map(|offset| start + offset)
            .expect("post-attestation arm implementation");
        let prepare = &source[start..arm_start];
        let register = prepare
            .find("actor.register_until(registration, deadline)")
            .expect("durable Intent registration");
        let worker = prepare
            .find("self.reserve_spawn_register_durable_handoff_with_until")
            .expect("passive worker admission");
        let source_identity = prepare
            .find(".durable_handoff_recovery_identity_source_until")
            .expect("recovery identity source");
        let revalidation = prepare
            .find("self.revalidate_durable_recovery_identity_until")
            .expect("pre-publication source fence");
        let custody_name = prepare
            .find("handoff.registered.key.custody_name_digest()")
            .expect("durable custody-name binding");
        let publication = prepare
            .find("DurableWorkerPrepareOutcome::CustodyPublication(")
            .expect("conservative publication owner");
        assert!(
            register < worker
                && worker < source_identity
                && source_identity < revalidation
                && revalidation < custody_name
                && custody_name < publication
        );
        assert!(!prepare.contains("actor.arm_until("));
        assert!(!prepare.contains("publish_current_process_custody("));

        let arm_end = source[arm_start..]
            .find("\n    /// Dormant production seam: reserves")
            .map(|offset| arm_start + offset)
            .expect("post-attestation arm implementation boundary");
        let arm = &source[arm_start..arm_end];
        let attestation = arm
            .find("attestation.verify_exact_custody(")
            .expect("exact custody attestation binding");
        let first_deadline = arm
            .find("ensure_worker_deadline(publication.deadline)")
            .expect("pre-attestation absolute deadline fence");
        let second_deadline = arm[attestation + 1..]
            .find("ensure_worker_deadline(publication.deadline)")
            .map(|offset| attestation + 1 + offset)
            .expect("post-attestation absolute deadline fence");
        let final_revalidation = arm
            .find("self.revalidate_durable_recovery_identity_until(")
            .expect("post-attestation worker identity fence");
        let anchor = arm
            .find("publication.handoff.source.durable_prepare_anchor()")
            .expect("durable recovery anchor");
        let durable_arm = arm
            .find("actor.arm_until(key, anchor, deadline)")
            .expect("durable MayOwnPrepare arm");
        assert!(
            first_deadline < attestation
                && attestation < second_deadline
                && second_deadline < final_revalidation
                && final_revalidation < anchor
                && anchor < durable_arm
        );
        assert!(!arm.contains("async fn"));
        assert!(!arm.contains(".await"));
        assert!(!arm[final_revalidation..durable_arm].contains("lock_worker_registry"));
        for forbidden in [
            "InternalWorkerRequest",
            "send_credential_worker_request",
            ".execute(",
            ".plan_until(",
            "AcquireTransportSocket",
        ] {
            assert!(
                !prepare.contains(forbidden) && !arm.contains(forbidden),
                "durable custody transition gained a child dispatch seam: {forbidden}"
            );
        }
    }

    #[test]
    fn durable_dispatch_fence_statically_precedes_every_dispatch_mutation() {
        let source = include_str!("worker_v3.rs");
        let plan_start = source
            .find("    fn plan_until(")
            .expect("registry planning implementation");
        let plan_end = source[plan_start..]
            .find("\n    #[cfg(test)]\n    fn plan(")
            .map(|offset| plan_start + offset)
            .expect("registry planning implementation boundary");
        let plan = &source[plan_start..plan_end];
        let pending_rejection = plan
            .find("self.reject_pending_durable_handoff_dispatch(context_id, generation)?")
            .expect("pending durable handoff rejection");
        for mutation in [
            "self.expire_cache(now)",
            "self.expire_tombstones(now)",
            "self.prepare_call_owners",
            ".in_flight = Some(in_flight)",
        ] {
            assert!(
                pending_rejection < plan.find(mutation).expect("dispatch mutation seam"),
                "pending durable handoff rejection must precede {mutation}"
            );
        }

        let prepare_start = source
            .find("    fn prepare_call_owners(")
            .expect("call-owner preparation implementation");
        let prepare_end = source[prepare_start..]
            .find("\n    fn recovery_identity_owners(")
            .map(|offset| prepare_start + offset)
            .expect("call-owner preparation boundary");
        let prepare = &source[prepare_start..prepare_end];
        let pending_rejection = prepare
            .find("WorkerDispatchFence::DurableHandoffPending")
            .expect("defensive pending durable handoff rejection");
        for owner_exposure in [
            "process.duplicate_network_namespace_pin(deadline)",
            "process.clone_channel()",
        ] {
            assert!(
                pending_rejection < prepare.find(owner_exposure).expect("call-owner exposure"),
                "pending durable handoff rejection must precede {owner_exposure}"
            );
        }

        let commit_start = source
            .find("    fn commit_reserved_with_dispatch(")
            .expect("dispatch-aware registration commit");
        let commit_end = source[commit_start..]
            .find("\n    fn commit_reserved(")
            .map(|offset| commit_start + offset)
            .expect("dispatch-aware registration boundary");
        let commit = &source[commit_start..commit_end];
        assert!(
            commit
                .find("WorkerDispatchFence::DurableHandoffPending")
                .expect("pending record state")
                < commit
                    .find("self.records.insert(")
                    .expect("atomic record insertion")
        );
    }

    #[test]
    fn dormant_lifecycle_registers_without_dispatch_and_exposes_only_pinned_identity() {
        let context_id = [70; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let deadline = HardDeadline::after(Duration::from_secs(5)).expect("lifecycle deadline");
        let ownership = registered_lifecycle(coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(4),
            deadline,
            |reservation, _deadline| spawn_reserved_fixture("connect", reservation),
        ));
        let coordinates = ownership.coordinates;
        assert_eq!(coordinates.context_id, context_id);
        assert_eq!(coordinates.worker_generation.get(), 1);
        assert_eq!(
            coordinator
                .phase(context_id, coordinates.worker_generation.get())
                .expect("no child request was dispatched"),
            VisiblePhase::Stable(StablePhase::Starting)
        );

        let source = coordinator
            .recovery_identity_source_until(
                &ownership,
                HardDeadline::after(Duration::from_secs(1)).expect("identity deadline"),
            )
            .expect("source from exact authenticated pins");
        assert_eq!(source.pending.coordinates, coordinates);
        assert_ne!(source.pending.expected_child_pid.get(), process::id());
        let durable_anchor = source.durable_prepare_anchor();
        assert_eq!(
            format!("{durable_anchor:?}"),
            "DurablePrepareAnchor(<redacted>)"
        );
        let network_namespace_identity = source
            .pending
            .authenticated_pins
            .network_namespace_pin_for_test()
            .verified_identity_parts()
            .expect("complete source retains exact namespace ownership");

        let proof = match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(2)).expect("reap deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => proof,
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("exact lifecycle reap was not confirmed: {error}")
            }
        };
        assert_eq!(proof.coordinates, coordinates);
        assert!(lock_worker_registry(&coordinator.registry).exact_generation_absent(coordinates));
        assert!(
            source.pending.authenticated_pins.ensure_alive().is_err(),
            "the retained real pidfd must observe exact child exit"
        );
        assert_eq!(
            source
                .pending
                .authenticated_pins
                .network_namespace_pin_for_test()
                .verified_identity_parts()
                .expect("affine source keeps exact namespace pinned"),
            network_namespace_identity
        );
    }

    #[test]
    fn ambiguous_lifecycle_reap_retains_exact_owner_for_bounded_retry() {
        let context_id = [71; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let (mut process, _peer, alive, attempts) = fake_process_with_termination_results(
            Duration::from_secs(1),
            VecDeque::from([false, true]),
            true,
        );
        let ownership = registered_lifecycle(coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(5),
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xa5; 32]),
                })
            },
        ));
        let coordinates = ownership.coordinates;

        let retained = match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("first reap deadline"),
        ) {
            WorkerGenerationReap::Confirmed(_) => {
                panic!("an ambiguous termination observation cannot prove absence")
            }
            WorkerGenerationReap::Retained { error, ownership } => {
                assert!(matches!(error, WorkerV3Error::Ambiguous));
                ownership
            }
        };
        assert!(alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(!lock_worker_registry(&coordinator.registry).exact_generation_absent(coordinates));
        assert!(matches!(
            retained.placement.as_ref(),
            Some(WorkerGenerationPlacement::Detached(_))
        ));

        let proof = match coordinator.terminate_generation_until(
            *retained,
            HardDeadline::after(Duration::from_secs(1)).expect("retry reap deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => proof,
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("exact retry did not prove absence: {error}")
            }
        };
        assert_eq!(proof.coordinates, coordinates);
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert!(lock_worker_registry(&coordinator.registry).exact_generation_absent(coordinates));
    }

    #[tokio::test]
    async fn terminal_supervisor_purge_settles_registered_owner_without_second_retirement() {
        let context_id = [86; 16];
        let RegisteredLifecycleFixture {
            coordinator,
            ownership,
            alive,
            attempts,
        } = registered_lifecycle_fixture(context_id, 1, VecDeque::from([true]), true);
        let coordinates = ownership.coordinates;
        let (outcome, execution) = terminal_lifecycle_finish(&coordinator, coordinates, 86);

        let execution = lifecycle_supervisor(&coordinator)
            .resolve_finish(outcome, execution)
            .await
            .expect("terminal supervisor retirement");
        assert_eq!(execution.response.result, InternalWorkerResult::Ok as i32);
        drop(execution);
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(lock_worker_registry(&coordinator.registry).exact_generation_absent(coordinates));

        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("settlement deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => assert_eq!(proof.coordinates, coordinates),
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("terminal purge did not settle registered owner: {error}")
            }
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn registered_owner_between_terminal_finish_and_purge_retries_without_second_retirement()
    {
        let context_id = [87; 16];
        let RegisteredLifecycleFixture {
            coordinator,
            ownership,
            alive,
            attempts,
        } = registered_lifecycle_fixture(context_id, 1, VecDeque::from([true]), true);
        let coordinates = ownership.coordinates;
        let (outcome, execution) = terminal_lifecycle_finish(&coordinator, coordinates, 87);

        let ownership = match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("pre-purge deadline"),
        ) {
            WorkerGenerationReap::Retained {
                error: WorkerV3Error::Ambiguous,
                ownership,
            } => *ownership,
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected pre-purge settlement result: {error}")
            }
            WorkerGenerationReap::Confirmed(_) => {
                panic!("record still present before terminal supervisor purge")
            }
        };
        assert!(matches!(
            ownership.placement.as_ref(),
            Some(WorkerGenerationPlacement::Registered)
        ));
        assert!(alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 0);

        drop(
            lifecycle_supervisor(&coordinator)
                .resolve_finish(outcome, execution)
                .await
                .expect("terminal supervisor retirement"),
        );
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("post-purge deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => assert_eq!(proof.coordinates, coordinates),
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("post-purge settlement remained unresolved: {error}")
            }
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn terminal_retirement_timeout_preserves_registered_owner_for_exact_retry() {
        let context_id = [88; 16];
        let RegisteredLifecycleFixture {
            coordinator,
            ownership,
            alive,
            attempts,
        } = registered_lifecycle_fixture(context_id, 1, VecDeque::from([false, true]), true);
        let coordinates = ownership.coordinates;
        let (outcome, execution) = terminal_lifecycle_finish(&coordinator, coordinates, 88);

        assert!(matches!(
            lifecycle_supervisor(&coordinator)
                .resolve_finish(outcome, execution)
                .await,
            Err(WorkerV3Error::Ambiguous)
        ));
        assert!(alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        {
            let registry = lock_worker_registry(&coordinator.registry);
            let record = registry
                .records
                .get(&context_id)
                .expect("timed-out retirement reattached exact worker");
            assert!(record.quarantined && record.process.is_some());
        }

        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("exact retry deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => assert_eq!(proof.coordinates, coordinates),
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("reattached terminal owner did not settle: {error}")
            }
        }
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn registered_absence_confirmation_requires_each_of_six_indexes_to_be_absent() {
        let context_id = [89; 16];
        let RegisteredLifecycleFixture {
            coordinator,
            mut ownership,
            alive,
            attempts,
        } = registered_lifecycle_fixture(context_id, 1, VecDeque::from([true]), true);
        let coordinates = ownership.coordinates;
        let (outcome, execution) = terminal_lifecycle_finish(&coordinator, coordinates, 89);
        drop(
            lifecycle_supervisor(&coordinator)
                .resolve_finish(outcome, execution)
                .await
                .expect("terminal supervisor retirement"),
        );
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        let expires_at = Instant::now() + Duration::from_secs(5);
        for residue in [
            ExactGenerationResidue::Record,
            ExactGenerationResidue::Reservation,
            ExactGenerationResidue::Cache,
            ExactGenerationResidue::CacheOrder,
            ExactGenerationResidue::Tombstone,
            ExactGenerationResidue::TombstoneOrder,
        ] {
            residue.insert(
                &mut lock_worker_registry(&coordinator.registry),
                coordinates,
                expires_at,
            );
            ownership = retained_registered_lifecycle(&coordinator, ownership);
            let mut registry = lock_worker_registry(&coordinator.registry);
            residue.assert_unchanged_and_remove(&mut registry, coordinates, expires_at);
            assert!(registry.exact_generation_absent(coordinates));
        }

        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("clean retry deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => assert_eq!(proof.coordinates, coordinates),
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("clean exact-absence retry remained unresolved: {error}")
            }
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn post_observation_deadline_retains_absent_registered_owner() {
        let context_id = [90; 16];
        let RegisteredLifecycleFixture {
            coordinator,
            ownership,
            alive,
            attempts,
        } = registered_lifecycle_fixture(context_id, 1, VecDeque::from([true]), true);
        let coordinates = ownership.coordinates;
        let (outcome, execution) = terminal_lifecycle_finish(&coordinator, coordinates, 91);
        drop(
            lifecycle_supervisor(&coordinator)
                .resolve_finish(outcome, execution)
                .await
                .expect("terminal supervisor retirement"),
        );
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        coordinator.set_lifecycle_mutation_hook(Some(LifecycleMutationHook {
            point: LifecycleMutationPoint::PostAbsenceObservation,
            reached: Arc::clone(&reached),
            release: Arc::clone(&release),
        }));
        let worker_coordinator = coordinator.clone();
        let deadline =
            HardDeadline::after(Duration::from_millis(60)).expect("confirmation deadline");
        let settlement = thread::spawn(move || {
            worker_coordinator.terminate_generation_until(ownership, deadline)
        });
        reached.wait();
        wait_until_deadline_elapsed(deadline);
        release.wait();
        let ownership = match settlement.join().expect("confirmation deadline thread") {
            WorkerGenerationReap::Retained {
                error: WorkerV3Error::Deadline,
                ownership,
            } => *ownership,
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected expired confirmation result: {error}")
            }
            WorkerGenerationReap::Confirmed(_) => {
                panic!("expired exact-absence observation consumed the owner")
            }
        };
        assert!(matches!(
            ownership.placement.as_ref(),
            Some(WorkerGenerationPlacement::Registered)
        ));
        assert!(lock_worker_registry(&coordinator.registry).exact_generation_absent(coordinates));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        coordinator.set_lifecycle_mutation_hook(None);
        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("confirmation retry deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => assert_eq!(proof.coordinates, coordinates),
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("fresh exact-absence confirmation failed: {error}")
            }
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn post_observation_deadline_preserves_present_registered_generation() {
        let context_id = [93; 16];
        let RegisteredLifecycleFixture {
            coordinator,
            ownership,
            alive,
            attempts,
        } = registered_lifecycle_fixture(context_id, 1, VecDeque::from([true]), true);
        let coordinates = ownership.coordinates;
        let original_expiry = {
            let registry = lock_worker_registry(&coordinator.registry);
            registry
                .records
                .get(&context_id)
                .expect("registered worker record")
                .expires_at
        };

        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        coordinator.set_lifecycle_mutation_hook(Some(LifecycleMutationHook {
            point: LifecycleMutationPoint::PostAbsenceObservation,
            reached: Arc::clone(&reached),
            release: Arc::clone(&release),
        }));
        let worker_coordinator = coordinator.clone();
        let deadline = HardDeadline::after(Duration::from_millis(60))
            .expect("present-generation observation deadline");
        let settlement = thread::spawn(move || {
            worker_coordinator.terminate_generation_until(ownership, deadline)
        });
        reached.wait();
        wait_until_deadline_elapsed(deadline);
        release.wait();
        let ownership = match settlement
            .join()
            .expect("present-generation deadline thread")
        {
            WorkerGenerationReap::Retained {
                error: WorkerV3Error::Deadline,
                ownership,
            } => *ownership,
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected present-generation deadline result: {error}")
            }
            WorkerGenerationReap::Confirmed(_) => {
                panic!("present generation was falsely confirmed absent")
            }
        };
        assert!(matches!(
            ownership.placement.as_ref(),
            Some(WorkerGenerationPlacement::Registered)
        ));
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
        assert!(alive.load(Ordering::SeqCst));
        {
            let registry = lock_worker_registry(&coordinator.registry);
            let record = registry
                .records
                .get(&context_id)
                .expect("deadline retained exact worker record");
            assert_eq!(record.generation, coordinates.worker_generation.get());
            assert_eq!(record.stable_phase, StablePhase::Starting);
            assert!(record.in_flight.is_none());
            assert!(!record.quarantined);
            assert_eq!(record.expires_at, original_expiry);
            assert!(Arc::ptr_eq(&record.alive_hint, &alive));
            assert!(record.process.is_some());
            assert!(registry.reservations.is_empty());
            assert!(registry.cache.is_empty() && registry.cache_order.is_empty());
            assert!(registry.tombstones.is_empty() && registry.tombstone_order.is_empty());
        }

        coordinator.set_lifecycle_mutation_hook(None);
        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("present-generation retry deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => assert_eq!(proof.coordinates, coordinates),
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("present-generation retry did not settle: {error}")
            }
        }
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn exact_absent_old_owner_does_not_touch_newer_generation() {
        let context_id = [91; 16];
        let RegisteredLifecycleFixture {
            coordinator,
            ownership,
            alive,
            attempts,
        } = registered_lifecycle_fixture(context_id, 1, VecDeque::from([true]), true);
        let coordinates = ownership.coordinates;
        let (outcome, execution) = terminal_lifecycle_finish(&coordinator, coordinates, 92);
        drop(
            lifecycle_supervisor(&coordinator)
                .resolve_finish(outcome, execution)
                .await
                .expect("old-generation terminal retirement"),
        );
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        let (replacement, _peer, replacement_alive) = fake_process(Duration::from_secs(1));
        let replacement_generation = lock_worker_registry(&coordinator.registry)
            .register(
                context_id,
                replacement,
                Duration::from_secs(5),
                Instant::now(),
            )
            .expect("newer replacement generation");
        assert!(replacement_generation > coordinates.worker_generation.get());

        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("old-owner settlement deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => assert_eq!(proof.coordinates, coordinates),
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("exact absent old owner did not settle: {error}")
            }
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            coordinator
                .phase(context_id, replacement_generation)
                .expect("replacement remains registered"),
            VisiblePhase::Stable(StablePhase::Starting)
        );
        assert!(replacement_alive.load(Ordering::SeqCst));

        let detached = lock_worker_registry(&coordinator.registry)
            .report_dead(context_id, replacement_generation)
            .expect("quarantine replacement")
            .expect("detach replacement");
        assert!(detached.process.terminate_bounded(TERMINATION_TIMEOUT));
        lock_worker_registry(&coordinator.registry)
            .purge_confirmed(context_id, replacement_generation)
            .expect("purge replacement");
        drop(detached);
        assert!(!replacement_alive.load(Ordering::SeqCst));
    }

    #[test]
    fn registered_termination_rejects_wrong_coordinator_without_mutation() {
        let context_id = [92; 16];
        let RegisteredLifecycleFixture {
            coordinator,
            ownership,
            alive,
            attempts,
        } = registered_lifecycle_fixture(context_id, 1, VecDeque::from([true]), true);
        let coordinates = ownership.coordinates;
        let other = WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));

        let ownership = match other.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("wrong-coordinator deadline"),
        ) {
            WorkerGenerationReap::Retained {
                error: WorkerV3Error::Stale,
                ownership,
            } => *ownership,
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected wrong-coordinator result: {error}")
            }
            WorkerGenerationReap::Confirmed(_) => {
                panic!("wrong coordinator falsely confirmed absence")
            }
        };
        assert!(matches!(
            ownership.placement.as_ref(),
            Some(WorkerGenerationPlacement::Registered)
        ));
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
        assert!(alive.load(Ordering::SeqCst));
        assert_eq!(
            coordinator
                .phase(context_id, coordinates.worker_generation.get())
                .expect("original registration remains intact"),
            VisiblePhase::Stable(StablePhase::Starting)
        );

        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("cleanup deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => assert_eq!(proof.coordinates, coordinates),
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("wrong-coordinator fixture cleanup failed: {error}")
            }
        }
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn ambiguous_spawn_returns_exact_owner_and_never_confirms_absence() {
        let context_id = [72; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let result = coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(5),
            HardDeadline::after(Duration::from_secs(1)).expect("spawn deadline"),
            |reservation, _deadline| {
                Err(WorkerSpawnFailure {
                    error: WorkerV3Error::Ambiguous,
                    reservation,
                })
            },
        );
        let ownership = match result {
            WorkerLifecycleAdmission::Retained {
                error: WorkerV3Error::Ambiguous,
                ownership,
            } => ownership,
            WorkerLifecycleAdmission::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected retained spawn result: {error}")
            }
            WorkerLifecycleAdmission::Registered(ownership) => {
                drop(ownership);
                panic!("ambiguous spawn registered")
            }
            WorkerLifecycleAdmission::Rejected(error) => {
                panic!("ambiguous spawn was rejected without ownership: {error}")
            }
        };
        assert!(matches!(
            ownership.placement.as_ref(),
            Some(WorkerGenerationPlacement::SpawnAmbiguous(_))
        ));
        let mut registry = lock_worker_registry(&coordinator.registry);
        let pending = registry
            .reservations
            .get(&context_id)
            .expect("ambiguous spawn keeps its exact admission fence");
        assert_eq!(pending.generation, 1);
        assert_eq!(pending.phase, PendingGenerationPhase::LifecycleOwned);
        assert!(Instant::now() < pending.expires_at);
        registry.expire_reservations(Instant::now() + Duration::from_secs(60));
        assert!(
            !registry.exact_generation_absent(WorkerGenerationCoordinates {
                context_id,
                worker_generation: NonZeroU64::new(1).expect("nonzero fixture generation"),
            })
        );
        drop(registry);
        let ownership = match coordinator.settle_lifecycle_ownership_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("ambiguous retry deadline"),
        ) {
            WorkerLifecycleSettlement::Retained {
                error: WorkerV3Error::Ambiguous,
                ownership,
            } => ownership,
            WorkerLifecycleSettlement::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected ambiguous retry result: {error}")
            }
            WorkerLifecycleSettlement::Registered(ownership) => {
                drop(ownership);
                panic!("ambiguous spawn retry registered")
            }
            WorkerLifecycleSettlement::ConfirmedAbsent(_) => {
                panic!("ambiguous spawn retry falsely proved absence")
            }
        };
        drop(ownership);
    }

    #[test]
    fn post_reservation_deadline_retains_nonexpiring_owner_until_exact_abandon_retry() {
        let context_id = [74; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        coordinator.set_lifecycle_post_reservation_delay(Duration::from_millis(30));
        let spawn_called = Arc::new(AtomicBool::new(false));
        let called = Arc::clone(&spawn_called);
        let admission = coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_millis(5),
            HardDeadline::after(Duration::from_millis(10)).expect("short admission deadline"),
            move |_reservation, _deadline| {
                called.store(true, Ordering::SeqCst);
                panic!("expired post-reservation admission must not spawn")
            },
        );
        let ownership = match admission {
            WorkerLifecycleAdmission::Retained {
                error: WorkerV3Error::Deadline,
                ownership,
            } => ownership,
            WorkerLifecycleAdmission::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected post-reservation result: {error}")
            }
            WorkerLifecycleAdmission::Registered(ownership) => {
                drop(ownership);
                panic!("expired admission registered")
            }
            WorkerLifecycleAdmission::Rejected(error) => {
                panic!("post-reservation owner was lost: {error}")
            }
        };
        assert!(!spawn_called.load(Ordering::SeqCst));
        assert!(matches!(
            ownership.placement.as_ref(),
            Some(WorkerGenerationPlacement::LifecycleReservation(_))
        ));
        {
            let mut registry = lock_worker_registry(&coordinator.registry);
            registry.expire_reservations(Instant::now() + Duration::from_secs(30));
            assert!(registry.reservations.contains_key(&context_id));
        }
        let proof = match coordinator.settle_lifecycle_ownership_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("abandon retry deadline"),
        ) {
            WorkerLifecycleSettlement::ConfirmedAbsent(proof) => proof,
            WorkerLifecycleSettlement::Retained { error, ownership } => {
                drop(ownership);
                panic!("reservation abandon retry remained unresolved: {error}")
            }
            WorkerLifecycleSettlement::Registered(ownership) => {
                drop(ownership);
                panic!("unspawned reservation registered")
            }
        };
        assert_eq!(proof.coordinates.context_id, context_id);
        assert!(
            lock_worker_registry(&coordinator.registry).exact_generation_absent(proof.coordinates)
        );
    }

    #[test]
    fn failed_abandon_registry_reacquire_returns_owner_for_exact_retry() {
        let context_id = [75; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let registry = Arc::clone(&coordinator.registry);
        let (start_sender, start_receiver) = std::sync::mpsc::sync_channel(0);
        let (locked_sender, locked_receiver) = std::sync::mpsc::sync_channel(0);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
        let locker = thread::spawn(move || {
            start_receiver.recv().expect("lock start");
            let guard = lock_worker_registry(&registry);
            locked_sender.send(()).expect("registry locked");
            release_receiver.recv().expect("lock release");
            drop(guard);
        });
        let admission = coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(1),
            HardDeadline::after(Duration::from_millis(40)).expect("settlement deadline"),
            move |reservation, _deadline| {
                start_sender.send(()).expect("start registry locker");
                locked_receiver.recv().expect("registry lock acquired");
                Err(WorkerSpawnFailure {
                    error: WorkerV3Error::Authentication,
                    reservation,
                })
            },
        );
        let ownership = match admission {
            WorkerLifecycleAdmission::Retained {
                error: WorkerV3Error::Deadline,
                ownership,
            } => ownership,
            WorkerLifecycleAdmission::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected failed-abandon result: {error}")
            }
            WorkerLifecycleAdmission::Registered(ownership) => {
                drop(ownership);
                panic!("failed spawn registered")
            }
            WorkerLifecycleAdmission::Rejected(error) => {
                panic!("failed registry reacquire lost ownership: {error}")
            }
        };
        release_sender.send(()).expect("release registry locker");
        locker.join().expect("registry locker");
        assert!(matches!(
            ownership.placement.as_ref(),
            Some(WorkerGenerationPlacement::LifecycleReservation(_))
        ));

        let exact_expiry = match ownership.placement.as_ref() {
            Some(WorkerGenerationPlacement::LifecycleReservation(reservation)) => {
                reservation.expires_at
            }
            _ => unreachable!(),
        };
        lock_worker_registry(&coordinator.registry)
            .reservations
            .get_mut(&context_id)
            .expect("retained reservation")
            .expires_at = exact_expiry + Duration::from_millis(1);
        let ownership = match coordinator.settle_lifecycle_ownership_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("mismatched abandon deadline"),
        ) {
            WorkerLifecycleSettlement::Retained {
                error: WorkerV3Error::Stale,
                ownership,
            } => ownership,
            WorkerLifecycleSettlement::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected mismatched-abandon result: {error}")
            }
            WorkerLifecycleSettlement::Registered(ownership) => {
                drop(ownership);
                panic!("mismatched reservation registered")
            }
            WorkerLifecycleSettlement::ConfirmedAbsent(_) => {
                panic!("mismatched reservation falsely confirmed absent")
            }
        };
        lock_worker_registry(&coordinator.registry)
            .reservations
            .get_mut(&context_id)
            .expect("retained reservation")
            .expires_at = exact_expiry;
        assert!(matches!(
            coordinator.settle_lifecycle_ownership_until(
                ownership,
                HardDeadline::after(Duration::from_secs(1)).expect("retry deadline"),
            ),
            WorkerLifecycleSettlement::ConfirmedAbsent(_)
        ));
    }

    #[test]
    fn spawned_worker_registry_timeout_returns_process_and_reservation_for_registration_retry() {
        let context_id = [76; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let (mut process, _peer, alive) = fake_process(Duration::from_secs(1));
        let registry = Arc::clone(&coordinator.registry);
        let (start_sender, start_receiver) = std::sync::mpsc::sync_channel(0);
        let (locked_sender, locked_receiver) = std::sync::mpsc::sync_channel(0);
        let (release_sender, release_receiver) = std::sync::mpsc::sync_channel(0);
        let locker = thread::spawn(move || {
            start_receiver.recv().expect("lock start");
            let guard = lock_worker_registry(&registry);
            locked_sender.send(()).expect("registry locked");
            release_receiver.recv().expect("lock release");
            drop(guard);
        });
        let admission = coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(1),
            HardDeadline::after(Duration::from_millis(40)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                start_sender.send(()).expect("start registry locker");
                locked_receiver.recv().expect("registry lock acquired");
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xa7; 32]),
                })
            },
        );
        let ownership = match admission {
            WorkerLifecycleAdmission::Retained {
                error: WorkerV3Error::Deadline,
                ownership,
            } => ownership,
            WorkerLifecycleAdmission::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected registration contention result: {error}")
            }
            WorkerLifecycleAdmission::Registered(ownership) => {
                drop(ownership);
                panic!("contended registration unexpectedly completed")
            }
            WorkerLifecycleAdmission::Rejected(error) => {
                panic!("spawned ownership was lost: {error}")
            }
        };
        assert!(matches!(
            ownership.placement.as_ref(),
            Some(WorkerGenerationPlacement::Spawned(_))
        ));
        assert!(alive.load(Ordering::SeqCst));
        release_sender.send(()).expect("release registry locker");
        locker.join().expect("registry locker");

        let ownership = match coordinator.settle_lifecycle_ownership_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("registration retry deadline"),
        ) {
            WorkerLifecycleSettlement::Registered(ownership) => ownership,
            WorkerLifecycleSettlement::Retained { error, ownership } => {
                drop(ownership);
                panic!("registration retry remained unresolved: {error}")
            }
            WorkerLifecycleSettlement::ConfirmedAbsent(_) => {
                panic!("spawned worker was falsely reported absent")
            }
        };
        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("cleanup deadline"),
        ) {
            WorkerGenerationReap::Confirmed(_) => {}
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("registered retry cleanup failed: {error}")
            }
        }
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[test]
    fn shutdown_during_spawn_keeps_lifecycle_fence_until_detached_reap() {
        let context_id = [80; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let registry = Arc::clone(&coordinator.registry);
        let (start_sender, start_receiver) = std::sync::mpsc::sync_channel(0);
        let (finished_sender, finished_receiver) = std::sync::mpsc::sync_channel(0);
        let shutdown = thread::spawn(move || {
            start_receiver.recv().expect("shutdown race start");
            let mut registry = lock_worker_registry(&registry);
            assert!(registry.begin_shutdown().is_empty());
            assert!(registry.records.is_empty());
            assert_eq!(registry.reservations.len(), 1);
            finished_sender.send(()).expect("shutdown race complete");
        });
        let (mut process, _peer, alive) = fake_process(Duration::from_secs(1));
        let admission = coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(2),
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                start_sender.send(()).expect("begin concurrent shutdown");
                finished_receiver.recv().expect("shutdown began");
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xab; 32]),
                })
            },
        );
        shutdown.join().expect("shutdown race thread");
        let ownership = match admission {
            WorkerLifecycleAdmission::Retained {
                error: WorkerV3Error::ShuttingDown,
                ownership,
            } => ownership,
            WorkerLifecycleAdmission::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected shutdown-race admission result: {error}")
            }
            WorkerLifecycleAdmission::Registered(ownership) => {
                drop(ownership);
                panic!("worker registered after shutdown began")
            }
            WorkerLifecycleAdmission::Rejected(error) => {
                panic!("shutdown race lost spawned ownership: {error}")
            }
        };
        assert!(alive.load(Ordering::SeqCst));
        assert!(matches!(
            ownership.placement.as_ref(),
            Some(WorkerGenerationPlacement::Detached(detached))
                if detached.reservation.is_some()
        ));
        {
            let registry = lock_worker_registry(&coordinator.registry);
            assert!(registry.records.is_empty());
            assert!(
                registry.exact_lifecycle_reservation_present(match ownership.placement.as_ref() {
                    Some(WorkerGenerationPlacement::Detached(detached)) => detached
                        .reservation
                        .as_ref()
                        .expect("detached lifecycle reservation"),
                    _ => unreachable!(),
                })
            );
            assert!(
                !(registry.records.is_empty() && registry.reservations.is_empty()),
                "shutdown must not observe an empty registry while the detached child is alive"
            );
        }
        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("detached reap deadline"),
        ) {
            WorkerGenerationReap::Confirmed(_) => {}
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("shutdown-race owner did not settle: {error}")
            }
        }
        assert!(!alive.load(Ordering::SeqCst));
        let registry = lock_worker_registry(&coordinator.registry);
        assert!(registry.records.is_empty() && registry.reservations.is_empty());
    }

    #[test]
    fn post_lock_commit_deadline_retains_spawned_owner_without_registry_mutation() {
        let context_id = [81; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        coordinator.set_lifecycle_mutation_hook(Some(LifecycleMutationHook {
            point: LifecycleMutationPoint::Commit,
            reached: Arc::clone(&reached),
            release: Arc::clone(&release),
        }));
        let (mut process, _peer, alive) = fake_process(Duration::from_secs(1));
        let worker_coordinator = coordinator.clone();
        let deadline = HardDeadline::after(Duration::from_millis(60)).expect("commit deadline");
        let admission = thread::spawn(move || {
            worker_coordinator.reserve_spawn_register_with_until(
                context_id,
                Duration::from_secs(2),
                deadline,
                move |reservation, _deadline| {
                    process.binding = Some(reservation.binding());
                    Ok(SpawnedWorker {
                        reservation,
                        process,
                        bootstrap_challenge: BootstrapChallenge([0xac; 32]),
                    })
                },
            )
        });
        reached.wait();
        wait_until_deadline_elapsed(deadline);
        release.wait();
        let ownership = match admission.join().expect("commit deadline thread") {
            WorkerLifecycleAdmission::Retained {
                error: WorkerV3Error::Deadline,
                ownership,
            } => ownership,
            WorkerLifecycleAdmission::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected late-commit result: {error}")
            }
            WorkerLifecycleAdmission::Registered(ownership) => {
                drop(ownership);
                panic!("expired commit registered a worker")
            }
            WorkerLifecycleAdmission::Rejected(error) => {
                panic!("expired commit lost spawned ownership: {error}")
            }
        };
        assert!(matches!(
            ownership.placement.as_ref(),
            Some(WorkerGenerationPlacement::Spawned(_))
        ));
        {
            let registry = lock_worker_registry(&coordinator.registry);
            assert!(registry.records.is_empty());
            assert_eq!(registry.reservations.len(), 1);
        }
        assert!(alive.load(Ordering::SeqCst));
        coordinator.set_lifecycle_mutation_hook(None);
        let ownership = match coordinator.settle_lifecycle_ownership_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("commit retry deadline"),
        ) {
            WorkerLifecycleSettlement::Registered(ownership) => ownership,
            WorkerLifecycleSettlement::Retained { error, ownership } => {
                drop(ownership);
                panic!("commit retry remained unresolved: {error}")
            }
            WorkerLifecycleSettlement::ConfirmedAbsent(_) => {
                panic!("spawned worker was falsely absent")
            }
        };
        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("cleanup deadline"),
        ) {
            WorkerGenerationReap::Confirmed(_) => {}
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("commit-deadline fixture cleanup failed: {error}")
            }
        }
    }

    #[test]
    fn unspawned_settlement_deadline_preserves_fence_then_purges_order_residue() {
        let context_id = [82; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let reservation = {
            let mut registry = lock_worker_registry(&coordinator.registry);
            let reservation = registry
                .reserve_generation(context_id, Duration::from_secs(2), Instant::now())
                .expect("reserve lifecycle generation");
            registry
                .retain_generation_for_lifecycle(&reservation)
                .expect("retain lifecycle fence");
            registry.cache_order.push_back(CacheKey {
                context_id,
                generation: reservation.generation,
                request_id: [1; 16],
                request_digest: [2; 32],
            });
            registry.tombstone_order.push_back(TombstoneKey {
                context_id,
                generation: reservation.generation,
                request_id: [3; 16],
            });
            reservation
        };
        let coordinates = WorkerGenerationCoordinates {
            context_id,
            worker_generation: NonZeroU64::new(reservation.generation)
                .expect("nonzero reservation generation"),
        };
        let ownership = WorkerGenerationOwnership {
            registry: Arc::clone(&coordinator.registry),
            coordinates,
            dispatch_registration: WorkerDispatchRegistration::Open,
            handoff_fence: None,
            placement: Some(WorkerGenerationPlacement::LifecycleReservation(reservation)),
        };
        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        coordinator.set_lifecycle_mutation_hook(Some(LifecycleMutationHook {
            point: LifecycleMutationPoint::Settlement,
            reached: Arc::clone(&reached),
            release: Arc::clone(&release),
        }));
        let worker_coordinator = coordinator.clone();
        let deadline = HardDeadline::after(Duration::from_millis(60)).expect("settlement deadline");
        let settlement = thread::spawn(move || {
            worker_coordinator.settle_lifecycle_ownership_until(ownership, deadline)
        });
        reached.wait();
        wait_until_deadline_elapsed(deadline);
        release.wait();
        let ownership = match settlement.join().expect("settlement deadline thread") {
            WorkerLifecycleSettlement::Retained {
                error: WorkerV3Error::Deadline,
                ownership,
            } => ownership,
            WorkerLifecycleSettlement::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected late-settlement result: {error}")
            }
            WorkerLifecycleSettlement::Registered(ownership) => {
                drop(ownership);
                panic!("unspawned generation registered")
            }
            WorkerLifecycleSettlement::ConfirmedAbsent(_) => {
                panic!("expired settlement mutated the registry")
            }
        };
        {
            let registry = lock_worker_registry(&coordinator.registry);
            let Some(WorkerGenerationPlacement::LifecycleReservation(reservation)) =
                ownership.placement.as_ref()
            else {
                unreachable!()
            };
            assert!(registry.exact_lifecycle_reservation_present(reservation));
            assert!(!registry.exact_generation_absent(coordinates));
            assert_eq!(registry.cache_order.len(), 1);
            assert_eq!(registry.tombstone_order.len(), 1);
        }
        coordinator.set_lifecycle_mutation_hook(None);
        match coordinator.settle_lifecycle_ownership_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("settlement retry deadline"),
        ) {
            WorkerLifecycleSettlement::ConfirmedAbsent(proof) => {
                assert_eq!(proof.coordinates, coordinates);
            }
            WorkerLifecycleSettlement::Retained { error, ownership } => {
                drop(ownership);
                panic!("residue settlement retry remained unresolved: {error}")
            }
            WorkerLifecycleSettlement::Registered(ownership) => {
                drop(ownership);
                panic!("unspawned residue retry registered")
            }
        }
        assert!(lock_worker_registry(&coordinator.registry).exact_generation_absent(coordinates));
    }

    #[test]
    fn recovery_deadline_after_proof_preserves_registered_ownership() {
        let context_id = [82; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let (mut process, _peer, _alive) = fake_process(Duration::from_secs(1));
        let ownership = registered_lifecycle(coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(5),
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xac; 32]),
                })
            },
        ));
        let coordinates = ownership.coordinates;

        let proof_complete = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        coordinator.set_lifecycle_recovery_hook(Some(LifecycleRecoveryHook {
            pinned: Arc::clone(&proof_complete),
            release: Arc::clone(&release),
        }));
        let worker_coordinator = coordinator.clone();
        let deadline = HardDeadline::after(Duration::from_millis(60)).expect("recovery deadline");
        let recovery = thread::spawn(move || {
            let result = worker_coordinator.recovery_identity_source_until(&ownership, deadline);
            (result, ownership)
        });
        proof_complete.wait();
        let registry = coordinator
            .registry
            .try_lock()
            .expect("full recovery proof must run without the registry lock");
        let record = registry
            .records
            .get(&context_id)
            .expect("registered worker");
        assert_eq!(record.stable_phase, StablePhase::Starting);
        assert!(!record.quarantined);
        assert!(record.in_flight.is_none());
        drop(registry);
        wait_until_deadline_elapsed(deadline);
        release.wait();
        let (result, ownership) = recovery.join().expect("deadline recovery thread");
        assert!(matches!(result, Err(WorkerV3Error::Deadline)));
        assert_eq!(ownership.coordinates, coordinates);
        assert!(matches!(
            ownership.placement,
            Some(WorkerGenerationPlacement::Registered)
        ));
        assert_eq!(
            coordinator
                .phase(context_id, coordinates.worker_generation.get())
                .expect("deadline leaves registered worker untouched"),
            VisiblePhase::Stable(StablePhase::Starting)
        );

        coordinator.set_lifecycle_recovery_hook(None);
        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("cleanup deadline"),
        ) {
            WorkerGenerationReap::Confirmed(_) => {}
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("deadline recovery fixture cleanup failed: {error}")
            }
        }
    }

    #[test]
    fn recovery_source_revalidates_ttl_and_phase_after_pin_duplication() {
        let context_id = [83; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let (mut process, _peer, _alive) = fake_process(Duration::from_secs(1));
        let ownership = registered_lifecycle(coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(2),
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xad; 32]),
                })
            },
        ));

        let pinned = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        coordinator.set_lifecycle_recovery_hook(Some(LifecycleRecoveryHook {
            pinned: Arc::clone(&pinned),
            release: Arc::clone(&release),
        }));
        let worker_coordinator = coordinator.clone();
        let recovery = thread::spawn(move || {
            let result = worker_coordinator.recovery_identity_source_until(
                &ownership,
                HardDeadline::after(Duration::from_secs(1)).expect("recovery deadline"),
            );
            (result, ownership)
        });
        pinned.wait();
        drop(
            coordinator
                .registry
                .try_lock()
                .expect("TTL proof must not hold the registry lock"),
        );
        let expires_at = {
            let expires_at = Instant::now() + Duration::from_millis(40);
            lock_worker_registry(&coordinator.registry)
                .records
                .get_mut(&context_id)
                .expect("registered worker")
                .expires_at = expires_at;
            expires_at
        };
        if let Some(remaining) = expires_at.checked_duration_since(Instant::now()) {
            thread::sleep(remaining);
        }
        while Instant::now() < expires_at {
            thread::yield_now();
        }
        release.wait();
        let (result, ownership) = recovery.join().expect("TTL recovery thread");
        assert!(matches!(result, Err(WorkerV3Error::Dead)));

        lock_worker_registry(&coordinator.registry)
            .records
            .get_mut(&context_id)
            .expect("worker record")
            .expires_at = Instant::now() + Duration::from_secs(1);
        coordinator.set_lifecycle_recovery_hook(None);
        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("cleanup deadline"),
        ) {
            WorkerGenerationReap::Confirmed(_) => {}
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("recovery revalidation fixture cleanup failed: {error}")
            }
        }
    }

    #[test]
    fn recovery_source_revalidates_phase_and_process_binding_after_proof() {
        let context_id = [84; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let (mut process, _peer, _alive) = fake_process(Duration::from_secs(1));
        let ownership = registered_lifecycle(coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(5),
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xae; 32]),
                })
            },
        ));

        let proof_complete = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        coordinator.set_lifecycle_recovery_hook(Some(LifecycleRecoveryHook {
            pinned: Arc::clone(&proof_complete),
            release: Arc::clone(&release),
        }));
        let worker_coordinator = coordinator.clone();
        let recovery = thread::spawn(move || {
            let result = worker_coordinator.recovery_identity_source_until(
                &ownership,
                HardDeadline::after(Duration::from_secs(1)).expect("phase recovery deadline"),
            );
            (result, ownership)
        });
        proof_complete.wait();
        drop(
            coordinator
                .registry
                .try_lock()
                .expect("phase proof must not hold the registry lock"),
        );
        lock_worker_registry(&coordinator.registry)
            .records
            .get_mut(&context_id)
            .expect("worker record")
            .stable_phase = StablePhase::Initialised;
        release.wait();
        let (result, ownership) = recovery.join().expect("phase recovery thread");
        assert!(matches!(result, Err(WorkerV3Error::Conflict)));

        lock_worker_registry(&coordinator.registry)
            .records
            .get_mut(&context_id)
            .expect("worker record")
            .stable_phase = StablePhase::Starting;
        let proof_complete = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        coordinator.set_lifecycle_recovery_hook(Some(LifecycleRecoveryHook {
            pinned: Arc::clone(&proof_complete),
            release: Arc::clone(&release),
        }));
        let worker_coordinator = coordinator.clone();
        let generation = ownership.coordinates.worker_generation.get();
        let recovery = thread::spawn(move || {
            let result = worker_coordinator.recovery_identity_source_until(
                &ownership,
                HardDeadline::after(Duration::from_secs(1)).expect("binding recovery deadline"),
            );
            (result, ownership)
        });
        proof_complete.wait();
        lock_worker_registry(&coordinator.registry)
            .records
            .get_mut(&context_id)
            .and_then(|record| record.process.as_mut())
            .expect("registered process")
            .binding = Some(([0xff; 16], generation));
        release.wait();
        let (result, ownership) = recovery.join().expect("binding recovery thread");
        assert!(matches!(result, Err(WorkerV3Error::Stale)));
        lock_worker_registry(&coordinator.registry)
            .records
            .get_mut(&context_id)
            .and_then(|record| record.process.as_mut())
            .expect("registered process")
            .binding = Some((context_id, generation));

        coordinator.set_lifecycle_recovery_hook(None);
        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("cleanup deadline"),
        ) {
            WorkerGenerationReap::Confirmed(_) => {}
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("binding recovery fixture cleanup failed: {error}")
            }
        }
    }

    #[test]
    fn recovery_source_revalidates_process_lifetime_after_proof() {
        let context_id = [85; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let (mut process, _peer, _alive) = fake_process(Duration::from_secs(1));
        let ownership = registered_lifecycle(coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(5),
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xaf; 32]),
                })
            },
        ));

        let proof_complete = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        coordinator.set_lifecycle_recovery_hook(Some(LifecycleRecoveryHook {
            pinned: Arc::clone(&proof_complete),
            release: Arc::clone(&release),
        }));
        let worker_coordinator = coordinator.clone();
        let recovery = thread::spawn(move || {
            let result = worker_coordinator.recovery_identity_source_until(
                &ownership,
                HardDeadline::after(Duration::from_secs(1)).expect("lifetime recovery deadline"),
            );
            (result, ownership)
        });
        proof_complete.wait();
        let original_lifetime = {
            let mut registry = lock_worker_registry(&coordinator.registry);
            let process = registry
                .records
                .get_mut(&context_id)
                .and_then(|record| record.process.as_mut())
                .expect("registered process");
            let original = Arc::clone(&process.lifetime);
            process.lifetime = Arc::new(WorkerLifetime::Fake {
                termination_results: Mutex::new(VecDeque::new()),
                default_result: TerminationOutcome::Reaped,
                attempts: Arc::new(AtomicUsize::new(0)),
                termination_delay: Duration::ZERO,
                probe_delay: Duration::ZERO,
            });
            original
        };
        release.wait();
        let (result, ownership) = recovery.join().expect("lifetime recovery thread");
        assert!(matches!(result, Err(WorkerV3Error::Stale)));
        lock_worker_registry(&coordinator.registry)
            .records
            .get_mut(&context_id)
            .and_then(|record| record.process.as_mut())
            .expect("registered process")
            .lifetime = original_lifetime;

        coordinator.set_lifecycle_recovery_hook(None);
        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("cleanup deadline"),
        ) {
            WorkerGenerationReap::Confirmed(_) => {}
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("lifetime recovery fixture cleanup failed: {error}")
            }
        }
    }

    #[test]
    fn post_lock_detach_deadline_preserves_registered_placement() {
        let context_id = [84; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let (mut process, _peer, alive, attempts) = fake_process_with_termination_results(
            Duration::from_secs(1),
            VecDeque::from([true]),
            true,
        );
        let ownership = registered_lifecycle(coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(2),
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xae; 32]),
                })
            },
        ));
        let coordinates = ownership.coordinates;

        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        coordinator.set_lifecycle_mutation_hook(Some(LifecycleMutationHook {
            point: LifecycleMutationPoint::Detach,
            reached: Arc::clone(&reached),
            release: Arc::clone(&release),
        }));
        let worker_coordinator = coordinator.clone();
        let deadline = HardDeadline::after(Duration::from_millis(60)).expect("detach deadline");
        let reap = thread::spawn(move || {
            worker_coordinator.terminate_generation_until(ownership, deadline)
        });
        reached.wait();
        wait_until_deadline_elapsed(deadline);
        release.wait();
        let ownership = match reap.join().expect("detach deadline thread") {
            WorkerGenerationReap::Retained {
                error: WorkerV3Error::Deadline,
                ownership,
            } => *ownership,
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected late-detach result: {error}")
            }
            WorkerGenerationReap::Confirmed(_) => {
                panic!("expired detach falsely confirmed absence")
            }
        };
        assert!(matches!(
            ownership.placement.as_ref(),
            Some(WorkerGenerationPlacement::Registered)
        ));
        assert!(alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 0);
        {
            let registry = lock_worker_registry(&coordinator.registry);
            let record = registry
                .records
                .get(&context_id)
                .expect("registered worker");
            assert!(!record.quarantined && record.process.is_some());
        }

        coordinator.set_lifecycle_mutation_hook(None);
        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("cleanup deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => assert_eq!(proof.coordinates, coordinates),
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("detach-deadline fixture cleanup failed: {error}")
            }
        }
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn post_lock_reaped_purge_deadline_preserves_reaped_placement() {
        let context_id = [85; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let (mut process, _peer, alive, attempts) = fake_process_with_termination_results(
            Duration::from_secs(1),
            VecDeque::from([true]),
            true,
        );
        let ownership = registered_lifecycle(coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(2),
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xaf; 32]),
                })
            },
        ));
        let coordinates = ownership.coordinates;

        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        coordinator.set_lifecycle_mutation_hook(Some(LifecycleMutationHook {
            point: LifecycleMutationPoint::Purge,
            reached: Arc::clone(&reached),
            release: Arc::clone(&release),
        }));
        let worker_coordinator = coordinator.clone();
        let deadline = HardDeadline::after(Duration::from_millis(60)).expect("purge deadline");
        let reap = thread::spawn(move || {
            worker_coordinator.terminate_generation_until(ownership, deadline)
        });
        reached.wait();
        wait_until_deadline_elapsed(deadline);
        release.wait();
        let ownership = match reap.join().expect("purge deadline thread") {
            WorkerGenerationReap::Retained {
                error: WorkerV3Error::Deadline,
                ownership,
            } => *ownership,
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected late-purge result: {error}")
            }
            WorkerGenerationReap::Confirmed(_) => {
                panic!("expired purge falsely confirmed absence")
            }
        };
        assert!(matches!(
            ownership.placement.as_ref(),
            Some(WorkerGenerationPlacement::ReapedPendingPurge(_))
        ));
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(!lock_worker_registry(&coordinator.registry).exact_generation_absent(coordinates));

        coordinator.set_lifecycle_mutation_hook(None);
        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("purge retry deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => assert_eq!(proof.coordinates, coordinates),
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("purge retry remained unresolved: {error}")
            }
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn registry_contention_after_reap_retains_pins_and_retry_skips_termination() {
        let context_id = [77; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let (mut process, _peer, alive, attempts) = fake_process_with_termination_results(
            Duration::from_secs(1),
            VecDeque::from([true]),
            true,
        );
        let ownership = registered_lifecycle(coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(2),
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xa8; 32]),
                })
            },
        ));
        let coordinates = ownership.coordinates;
        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        coordinator.set_lifecycle_reaped_hook(LifecycleReapedHook {
            reached: Arc::clone(&reached),
            release: Arc::clone(&release),
        });
        let worker_coordinator = coordinator.clone();
        let reap = thread::spawn(move || {
            worker_coordinator.terminate_generation_until(
                ownership,
                HardDeadline::after(Duration::from_millis(80)).expect("reap deadline"),
            )
        });
        reached.wait();
        let registry_guard = lock_worker_registry(&coordinator.registry);
        release.wait();
        let retained = match reap.join().expect("reap thread") {
            WorkerGenerationReap::Retained {
                error: WorkerV3Error::Deadline,
                ownership,
            } => ownership,
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("unexpected post-reap contention result: {error}")
            }
            WorkerGenerationReap::Confirmed(_) => {
                panic!("registry contention cannot confirm absence")
            }
        };
        assert!(matches!(
            retained.placement.as_ref(),
            Some(WorkerGenerationPlacement::ReapedPendingPurge(_))
        ));
        let Some(WorkerGenerationPlacement::ReapedPendingPurge(detached)) =
            retained.placement.as_ref()
        else {
            unreachable!()
        };
        assert!(
            detached
                .worker
                .process
                .retirement
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .as_ref()
                .and_then(|retirement| retirement.kernel_pins.as_ref())
                .is_some()
        );
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(!registry_guard.exact_generation_absent(coordinates));
        drop(registry_guard);

        match coordinator.terminate_generation_until(
            *retained,
            HardDeadline::after(Duration::from_secs(1)).expect("purge retry deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => assert_eq!(proof.coordinates, coordinates),
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("reaped-purge retry remained unresolved: {error}")
            }
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[test]
    fn reaped_partial_purge_is_idempotent_and_removes_order_only_residue() {
        let context_id = [78; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let (mut process, _peer, _alive, attempts) = fake_process_with_termination_results(
            Duration::from_secs(1),
            VecDeque::from([true]),
            true,
        );
        let mut ownership = registered_lifecycle(coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(2),
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xa9; 32]),
                })
            },
        ));
        let coordinates = ownership.coordinates;
        assert!(matches!(
            ownership.placement.take(),
            Some(WorkerGenerationPlacement::Registered)
        ));
        let detached = {
            let mut registry = lock_worker_registry(&coordinator.registry);
            let detached = registry
                .report_dead(context_id, coordinates.worker_generation.get())
                .expect("detach exact generation")
                .expect("registered process owner");
            assert_eq!(
                detached.process.liveness().termination_outcome_until(
                    HardDeadline::after(Duration::from_secs(1)).expect("termination deadline"),
                ),
                TerminationOutcome::Reaped
            );
            registry.records.remove(&context_id);
            registry.cache_order.push_back(CacheKey {
                context_id,
                generation: coordinates.worker_generation.get(),
                request_id: [1; 16],
                request_digest: [2; 32],
            });
            registry.tombstone_order.push_back(TombstoneKey {
                context_id,
                generation: coordinates.worker_generation.get(),
                request_id: [3; 16],
            });
            assert!(!registry.exact_generation_absent(coordinates));
            detached
        };
        ownership.placement = Some(WorkerGenerationPlacement::ReapedPendingPurge(Box::new(
            LifecycleDetachedOwnership {
                worker: detached,
                reservation: None,
            },
        )));
        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("partial purge deadline"),
        ) {
            WorkerGenerationReap::Confirmed(proof) => assert_eq!(proof.coordinates, coordinates),
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("partial purge did not settle: {error}")
            }
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        let mut registry = lock_worker_registry(&coordinator.registry);
        assert!(registry.exact_generation_absent(coordinates));
        registry
            .purge_or_confirm_generation_absent(coordinates)
            .expect("already-absent retry is idempotent");
    }

    #[test]
    fn recovery_source_rejects_wrong_coordinator_phase_and_expired_ttl() {
        let context_id = [79; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let other = WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let (mut process, _peer, _alive) = fake_process(Duration::from_secs(1));
        let ownership = registered_lifecycle(coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(2),
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xaa; 32]),
                })
            },
        ));
        assert!(matches!(
            other.recovery_identity_source_until(
                &ownership,
                HardDeadline::after(Duration::from_secs(1)).expect("wrong-owner deadline"),
            ),
            Err(WorkerV3Error::Stale)
        ));
        {
            let mut registry = lock_worker_registry(&coordinator.registry);
            let record = registry
                .records
                .get_mut(&context_id)
                .expect("worker record");
            record.stable_phase = StablePhase::Initialised;
        }
        assert!(matches!(
            coordinator.recovery_identity_source_until(
                &ownership,
                HardDeadline::after(Duration::from_secs(1)).expect("wrong-phase deadline"),
            ),
            Err(WorkerV3Error::Conflict)
        ));
        {
            let mut registry = lock_worker_registry(&coordinator.registry);
            let record = registry
                .records
                .get_mut(&context_id)
                .expect("worker record");
            record.stable_phase = StablePhase::Starting;
            record.expires_at = Instant::now();
        }
        assert!(matches!(
            coordinator.recovery_identity_source_until(
                &ownership,
                HardDeadline::after(Duration::from_secs(1)).expect("expired-source deadline"),
            ),
            Err(WorkerV3Error::Dead)
        ));
        {
            let mut registry = lock_worker_registry(&coordinator.registry);
            registry
                .records
                .get_mut(&context_id)
                .expect("worker record")
                .expires_at = Instant::now() + Duration::from_secs(1);
        }
        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("cleanup deadline"),
        ) {
            WorkerGenerationReap::Confirmed(_) => {}
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("recovery-source fixture cleanup failed: {error}")
            }
        }
    }

    #[test]
    fn recovery_source_rejects_a_registered_process_without_authenticated_pins() {
        let context_id = [73; 16];
        let coordinator =
            WorkerCoordinator::new(WorkerRegistry::new(1, 4, Duration::from_secs(10)));
        let (mut process, _peer, _alive) = fake_process(Duration::from_secs(1));
        process
            .retirement
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
            .expect("armed retirement")
            .kernel_pins = None;
        let ownership = registered_lifecycle(coordinator.reserve_spawn_register_with_until(
            context_id,
            Duration::from_secs(5),
            HardDeadline::after(Duration::from_secs(1)).expect("registration deadline"),
            move |reservation, _deadline| {
                process.binding = Some(reservation.binding());
                Ok(SpawnedWorker {
                    reservation,
                    process,
                    bootstrap_challenge: BootstrapChallenge([0xa6; 32]),
                })
            },
        ));
        assert!(matches!(
            coordinator.recovery_identity_source_until(
                &ownership,
                HardDeadline::after(Duration::from_secs(1)).expect("identity deadline"),
            ),
            Err(WorkerV3Error::Authentication | WorkerV3Error::Sandbox(_))
        ));
        match coordinator.terminate_generation_until(
            ownership,
            HardDeadline::after(Duration::from_secs(1)).expect("cleanup deadline"),
        ) {
            WorkerGenerationReap::Confirmed(_) => {}
            WorkerGenerationReap::Retained { error, ownership } => {
                drop(ownership);
                panic!("pinless fixture cleanup was not confirmed: {error}")
            }
        }
    }

    #[test]
    fn wrong_challenge_fails_closed_and_child_is_boundedly_reaped() {
        let (result, elapsed) = timed_spawn_fixture_after_lock("wrong-challenge", [2; 16], 1);
        assert!(matches!(result, Err(WorkerV3Error::Authentication)));
        assert!(elapsed < HANDSHAKE_TIMEOUT + Duration::from_secs(1));
    }

    #[test]
    fn unexpected_post_exec_child_descriptor_fails_before_handshake() {
        let (result, elapsed) = timed_spawn_fixture_after_lock("extra-fd-connect", [30; 16], 1);
        assert!(result.is_err());
        assert!(elapsed < HANDSHAKE_TIMEOUT + Duration::from_secs(1));
    }

    #[test]
    fn final_parent_descriptor_audit_rejects_a_post_pin_open() {
        match spawn_fixture("extra-fd-after-pin", [35; 16], 1) {
            Err(
                WorkerV3Error::Authentication | WorkerV3Error::Deadline | WorkerV3Error::Sandbox(_),
            ) => {}
            Err(error) => panic!("unexpected post-pin descriptor error: {error}"),
            Ok(process) => {
                assert!(process.terminate_bounded(TERMINATION_TIMEOUT));
                panic!("post-pin descriptor escaped final parent audit");
            }
        }
    }

    #[test]
    fn sandbox_proof_is_observed_pinned_and_ready_before_spawn_returns() {
        let context_id = [31; 16];
        let generation = 7;
        let authenticated =
            spawn_authenticated_fixture("connect", context_id, generation).expect("proof child");
        let process = authenticated.process;
        let challenge = authenticated.bootstrap_challenge.into_bytes();
        assert_ne!(challenge, [0; 32]);
        assert!(process.has_complete_kernel_pins());
        assert!(process.terminate_bounded(TERMINATION_TIMEOUT));
    }

    #[test]
    fn wrong_sandbox_ready_hash_fails_closed_and_is_reaped() {
        match spawn_fixture("wrong-ready", [32; 16], 1) {
            Err(WorkerV3Error::Authentication | WorkerV3Error::Deadline | WorkerV3Error::Io(_)) => {
            }
            Err(error) => panic!("unexpected wrong-ready error: {error}"),
            Ok(process) => {
                assert!(process.terminate_bounded(TERMINATION_TIMEOUT));
                panic!("wrong-ready worker authenticated")
            }
        }
    }

    #[test]
    fn parent_mismatch_and_pid_death_after_proof_never_authenticate() {
        let net_admin = 1_u64 << 12;
        let invalid_observation = WorkerSandboxSnapshot::fixture(
            NetworkNamespaceIdentity::fixture(1, 10),
            NetworkNamespaceIdentity::fixture(1, 11),
            current_worker_identity(),
            true,
            false,
            LinuxSeccompState::fixture(
                u8::try_from(libc::SECCOMP_MODE_FILTER).expect("seccomp mode fits u8"),
                4,
            ),
            LinuxCapabilitySnapshot::fixture(0, net_admin, net_admin, net_admin, 0),
        );
        assert!(
            spawn_authenticated_fixture_with_observation(
                "connect",
                [33; 16],
                1,
                invalid_observation,
            )
            .is_err()
        );
        assert!(spawn_fixture("exit-after-proof", [34; 16], 1).is_err());
    }

    #[test]
    fn source_enters_child_loop_only_after_sandbox_ready_is_sent() {
        let source = include_str!("worker_v3.rs");
        let child_start = source
            .find("fn run_child_with_sandbox")
            .expect("child bootstrap");
        let child_end = source[child_start..]
            .find("\nfn child_loop(")
            .map(|offset| child_start + offset)
            .expect("child loop boundary");
        let bootstrap = &source[child_start..child_end];
        let proof = bootstrap
            .find("send_credential_record(&channel, &proof)")
            .expect("proof send");
        let accepted = bootstrap
            .find("if HandshakeRecord::decode(&encoded)? != accepted")
            .expect("accepted verification");
        let ready = bootstrap
            .find("accepted.sandbox_ready().encode()")
            .expect("ready send");
        let dumpable = bootstrap
            .find("prctl::set_dumpable(false)")
            .expect("post-observation core-dump disablement");
        let loop_entry = bootstrap
            .rfind("child_loop(&channel")
            .expect("child-loop entry");
        assert!(proof < accepted && accepted < dumpable && dumpable < ready && ready < loop_entry);
    }

    #[test]
    fn source_pins_newnet_before_identity_drop_and_rebinds_parent_death_signal() {
        let source = include_str!("worker_v3.rs");
        let child_start = source
            .find("fn run_child_with_sandbox")
            .expect("child bootstrap");
        let child_end = source[child_start..]
            .find("\nfn child_loop(")
            .map(|offset| child_start + offset)
            .expect("child loop boundary");
        let child = &source[child_start..child_end];
        let begin = child
            .find("begin_sandbox(parent_network_namespace)?")
            .expect("child NEWNET begin");
        let namespace_ready = child
            .find("hello.namespace_ready().encode()")
            .expect("child namespace-ready barrier");
        let namespace_pinned = child
            .find("hello.namespace_pinned()")
            .expect("child namespace-pin acknowledgement");
        let finish = child
            .find("finish_sandbox(prepared_sandbox, worker_identity)?")
            .expect("child identity drop");
        let pdeath_restore = child[finish..]
            .find("prctl::set_pdeathsig(Some(Signal::SIGKILL))")
            .map(|offset| finish + offset)
            .expect("post-drop parent-death signal restore");
        let pdeath_readback = child[pdeath_restore..]
            .find("prctl::get_pdeathsig()")
            .map(|offset| pdeath_restore + offset)
            .expect("post-drop parent-death signal readback");
        let child_hello = child
            .find("hello.child_reply().encode()")
            .expect("post-drop child hello");
        assert!(
            begin < namespace_ready
                && namespace_ready < namespace_pinned
                && namespace_pinned < finish
                && finish < pdeath_restore
                && pdeath_restore < pdeath_readback
                && pdeath_readback < child_hello
        );

        let parent_start = source
            .find("fn parent_handshake(")
            .expect("parent handshake");
        let parent_end = source[parent_start..]
            .find("\nfn finish_unconstructed_launch_failure(")
            .map(|offset| parent_start + offset)
            .expect("parent handshake boundary");
        let parent = &source[parent_start..parent_end];
        let ready_receive = parent
            .find("hello.namespace_ready()")
            .expect("parent namespace-ready verification");
        let pin = parent
            .find("process.pin_worker_network_namespace_before_identity_drop(")
            .expect("parent namespace pin");
        let pin_ack = parent
            .find("hello.namespace_pinned().encode()")
            .expect("parent namespace-pin acknowledgement");
        let final_credentials = parent
            .find("let expected_after_drop = ExpectedUnixCredentials::new(")
            .expect("parent final worker credentials");
        let child_hello_receive = parent[final_credentials..]
            .find("hello.child_reply()")
            .map(|offset| final_credentials + offset)
            .expect("parent post-drop child hello");
        assert!(
            ready_receive < pin
                && pin < pin_ack
                && pin_ack < final_credentials
                && final_credentials < child_hello_receive
        );
        let before_drop_start = parent
            .find("fn parent_handshake_before_drop(")
            .expect("pre-drop helper");
        let before_pin = &parent[before_drop_start..pin];
        assert_eq!(before_pin.matches("expected_before_drop").count(), 2);
        assert!(!before_pin.contains("expected_after_drop"));
        let after_pin_ack = &parent[pin_ack..];
        assert!(!after_pin_ack.contains("expected_before_drop"));
        assert_eq!(after_pin_ack.matches("expected_after_drop").count(), 6);
    }

    #[test]
    fn source_observes_only_after_proof_and_requires_accepted_then_ready() {
        let source = include_str!("worker_v3.rs");
        let parent_start = source
            .find("fn parent_handshake(")
            .expect("parent handshake");
        let parent_end = source[parent_start..]
            .find("\nfn finish_unconstructed_launch_failure(")
            .map(|offset| parent_start + offset)
            .expect("parent handshake boundary");
        let handshake = &source[parent_start..parent_end];
        let proof = handshake
            .find("    let proof = receive_credential_record_with_deadline(")
            .expect("credential-bound proof receipt");
        let observe = handshake
            .find("process.observe_and_pin_sandbox(")
            .expect("independent observation");
        let verify = handshake
            .find("    .verify_once(")
            .expect("proof verification");
        let accepted = handshake
            .find(
                "    send_credential_record_with_deadline(&process.channel, &accepted.encode(), deadline)?;",
            )
            .expect("Accepted send");
        let ready_receive = handshake[accepted..]
            .find("    let encoded = receive_credential_record_with_deadline(")
            .map(|offset| accepted + offset)
            .expect("Ready receipt");
        let ready_verify = handshake
            .find("accepted.sandbox_ready()")
            .expect("Ready verification");
        assert!(
            proof < observe
                && observe < verify
                && verify < accepted
                && accepted < ready_receive
                && ready_receive < ready_verify
        );
    }

    #[test]
    fn inherited_socketpair_record_is_authenticated_as_exec_child_not_creator() {
        let (parent, worker) = private_credential_worker_channel().expect("credential channel");
        let inherited: OwnedFd = worker.into();
        let mut command = child_command("credential-sender");
        command
            .stdin(Stdio::from(inherited))
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let retirement_permit =
            acquire_retirement_permit().expect("credential sender retirement permit");
        let child = command.spawn().expect("credential sender");
        let child_pid = child.id();
        let creator =
            ExpectedUnixCredentials::new(process::id(), geteuid().as_raw(), getegid().as_raw())
                .expect("creator credentials");
        assert!(
            receive_credential_record(&parent, 1, creator).is_err(),
            "a pre-spawn socketpair creator PID must not authenticate an exec child record"
        );
        let lifetime = Arc::new(WorkerLifetime::Child(Mutex::new(Some(child))));
        let alive_hint = Arc::new(AtomicBool::new(true));
        let retirement = ProcessRetirement {
            liveness: WorkerLiveness {
                lifetime: Arc::clone(&lifetime),
                alive_hint: Arc::clone(&alive_hint),
            },
            permit: Some(retirement_permit),
            kernel_pins: None,
            armed: true,
        };
        let process = WorkerProcess {
            child_pid,
            binding: None,
            expected_peer: ExpectedUnixCredentials::new(
                child_pid,
                geteuid().as_raw(),
                getegid().as_raw(),
            )
            .expect("child credentials"),
            channel: parent,
            lifetime,
            alive_hint,
            retirement: Mutex::new(Some(retirement)),
        };
        assert!(process.terminate_bounded(TERMINATION_TIMEOUT));
    }

    #[test]
    fn registry_caps_expiry_detach_and_generation_aba_are_fail_closed() {
        let now = Instant::now();
        let context_id = [3; 16];
        let mut registry = WorkerRegistry::new(1, 8, Duration::from_secs(10));
        let (first, _peer, first_alive) = fake_process(Duration::from_secs(1));
        let first_generation = registry
            .register(context_id, first, Duration::from_secs(2), now)
            .expect("first generation");

        let (second, _peer, second_alive) = fake_process(Duration::from_secs(1));
        let RegistrationFailure {
            error,
            process: second,
            ..
        } = registry
            .register([4; 16], second, Duration::from_secs(2), now)
            .expect_err("capacity rejection");
        assert!(matches!(error, WorkerV3Error::Capacity));
        assert!(
            second_alive.load(Ordering::SeqCst),
            "registry rejection must return ownership without process work"
        );
        assert!(second.terminate_bounded(TERMINATION_TIMEOUT));
        assert!(!second_alive.load(Ordering::SeqCst));

        let stale_request = initialise(context_id, 9);
        let stale = call(
            registry
                .plan(context_id, first_generation, &stale_request, now)
                .expect("old plan"),
        );
        let mut detached = registry.reap(now + Duration::from_secs(3));
        assert_eq!(detached.len(), 1);
        let detached = detached.pop().expect("expired worker");
        assert_eq!(
            (detached.context_id, detached.generation),
            (context_id, first_generation)
        );
        assert!(
            first_alive.load(Ordering::SeqCst),
            "reap must only detach under the registry lock"
        );
        stop_and_purge(&mut registry, detached);

        let (replacement, _peer, _alive) = fake_process(Duration::from_secs(1));
        let replacement_generation = registry
            .register(context_id, replacement, Duration::from_secs(5), now)
            .expect("replacement");
        assert!(replacement_generation > first_generation);
        let response = initialised_response(&stale_request, context_id);
        assert!(matches!(
            registry.finish(stale.token, &stale_request, &response, now, true,),
            FinishOutcome::Rejected {
                error: WorkerV3Error::Stale,
                detached: None,
            }
        ));
        assert_eq!(
            registry
                .visible_phase(context_id, replacement_generation)
                .expect("replacement phase"),
            VisiblePhase::Stable(StablePhase::Starting)
        );
    }

    #[test]
    fn pre_spawn_generation_reservations_are_bounded_fail_atomic_and_never_reused() {
        let now = Instant::now();
        let context_id = [32; 16];
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));

        let first = registry
            .reserve_generation(context_id, Duration::from_secs(2), now)
            .expect("first pre-spawn reservation");
        assert_eq!(first.binding(), (context_id, 1));
        assert!(matches!(
            registry.reserve_generation(context_id, Duration::from_secs(2), now),
            Err(WorkerV3Error::Conflict)
        ));
        assert!(matches!(
            registry.reserve_generation([33; 16], Duration::from_secs(2), now),
            Err(WorkerV3Error::Capacity)
        ));
        let WorkerSpawnFailure {
            error,
            reservation: first,
        } = match spawn_reserved_fixture("wrong-challenge", first) {
            Err(failure) => failure,
            Ok(spawned) => {
                assert!(spawned.process.terminate_bounded(TERMINATION_TIMEOUT));
                panic!("wrong challenge must fail before registration")
            }
        };
        assert!(matches!(error, WorkerV3Error::Authentication));
        registry
            .abandon_generation(first)
            .expect("failed spawn abandon releases capacity");

        let second = registry
            .reserve_generation(context_id, Duration::from_secs(2), now)
            .expect("second reservation");
        assert_eq!(second.generation, 2, "abandon must burn its generation");
        let (mut mismatched, _peer, mismatched_alive) = fake_process(Duration::from_secs(1));
        mismatched.binding = Some((context_id, 99));
        let RegistrationFailure {
            error,
            process: mismatched,
            ..
        } = registry
            .commit_reserved(second, mismatched, now)
            .expect_err("post-spawn binding mismatch");
        assert!(matches!(error, WorkerV3Error::Conflict));
        assert!(mismatched_alive.load(Ordering::SeqCst));
        assert!(mismatched.terminate_bounded(TERMINATION_TIMEOUT));

        let expired = registry
            .reserve_generation(context_id, Duration::from_secs(1), now)
            .expect("bounded pending generation");
        assert_eq!(expired.generation, 3);
        let replacement = registry
            .reserve_generation(
                context_id,
                Duration::from_secs(2),
                now + Duration::from_secs(2),
            )
            .expect("expired reservation releases capacity");
        assert_eq!(replacement.generation, 4);

        let (mut stale, _peer, stale_alive) = fake_process(Duration::from_secs(1));
        stale.binding = Some(expired.binding());
        let RegistrationFailure {
            error,
            process: stale,
            ..
        } = registry
            .commit_reserved(expired, stale, now + Duration::from_secs(2))
            .expect_err("expired token cannot consume replacement");
        assert!(matches!(error, WorkerV3Error::Stale));
        assert!(stale.terminate_bounded(TERMINATION_TIMEOUT));
        assert!(!stale_alive.load(Ordering::SeqCst));

        let replacement_generation = replacement.generation;
        let (mut exact, _peer, exact_alive) = fake_process(Duration::from_secs(1));
        exact.binding = Some(replacement.binding());
        assert_eq!(
            registry
                .commit_reserved(replacement, exact, now + Duration::from_secs(2))
                .expect("exact reserved binding"),
            replacement_generation
        );
        let detached = registry
            .report_dead(context_id, replacement_generation)
            .expect("quarantine committed fake")
            .expect("detached fake");
        stop_and_purge(&mut registry, detached);
        assert!(!exact_alive.load(Ordering::SeqCst));

        registry.next_generation = u64::MAX;
        assert!(matches!(
            registry.reserve_generation([34; 16], Duration::from_secs(1), now),
            Err(WorkerV3Error::Capacity)
        ));
        assert!(registry.reservations.is_empty());
    }

    #[test]
    fn every_rejected_registration_returns_ownership_for_outside_lock_retirement() {
        let now = Instant::now();

        let mut invalid_registry = WorkerRegistry::new(1, 2, Duration::from_secs(10));
        let (invalid, _peer, invalid_alive) = fake_process(Duration::from_secs(1));
        let RegistrationFailure {
            error,
            process: invalid,
            ..
        } = invalid_registry
            .register([21; 16], invalid, Duration::ZERO, now)
            .expect_err("invalid rejection");
        assert!(matches!(error, WorkerV3Error::Invalid));
        assert!(invalid_alive.load(Ordering::SeqCst));
        assert!(invalid.terminate_bounded(TERMINATION_TIMEOUT));
        assert!(!invalid_alive.load(Ordering::SeqCst));

        let mut occupied_registry = WorkerRegistry::new(1, 2, Duration::from_secs(10));
        let (occupant, _peer, _occupant_alive) = fake_process(Duration::from_secs(1));
        occupied_registry
            .register([22; 16], occupant, Duration::from_secs(1), now)
            .expect("occupant");
        let (conflict, _peer, conflict_alive) = fake_process(Duration::from_secs(1));
        let RegistrationFailure {
            error,
            process: conflict,
            ..
        } = occupied_registry
            .register([22; 16], conflict, Duration::from_secs(1), now)
            .expect_err("conflict rejection");
        assert!(matches!(error, WorkerV3Error::Conflict));
        assert!(conflict_alive.load(Ordering::SeqCst));
        assert!(conflict.terminate_bounded(TERMINATION_TIMEOUT));
        assert!(!conflict_alive.load(Ordering::SeqCst));

        let (excess, _peer, excess_alive) = fake_process(Duration::from_secs(1));
        let RegistrationFailure {
            error,
            process: excess,
            ..
        } = occupied_registry
            .register([23; 16], excess, Duration::from_secs(1), now)
            .expect_err("capacity rejection");
        assert!(matches!(error, WorkerV3Error::Capacity));
        assert!(excess_alive.load(Ordering::SeqCst));
        assert!(excess.terminate_bounded(TERMINATION_TIMEOUT));
        assert!(!excess_alive.load(Ordering::SeqCst));

        let mut binding_registry = WorkerRegistry::new(1, 2, Duration::from_secs(10));
        let (mut mismatched, _peer, mismatched_alive) = fake_process(Duration::from_secs(1));
        mismatched.binding = Some(([24; 16], 1));
        let RegistrationFailure {
            error,
            process: mismatched,
            ..
        } = binding_registry
            .register([25; 16], mismatched, Duration::from_secs(1), now)
            .expect_err("binding rejection");
        assert!(matches!(error, WorkerV3Error::Conflict));
        assert!(mismatched_alive.load(Ordering::SeqCst));
        assert!(mismatched.terminate_bounded(TERMINATION_TIMEOUT));
        assert!(!mismatched_alive.load(Ordering::SeqCst));
    }

    #[test]
    fn rejected_reattach_returns_process_ownership_unchanged() {
        let mut registry = WorkerRegistry::new(1, 2, Duration::from_secs(10));
        let (process, _peer, alive) = fake_process(Duration::from_secs(1));
        let failure = registry
            .reattach_uncertain(DetachedWorker {
                context_id: [29; 16],
                generation: 1,
                process,
            })
            .expect_err("missing generation must reject reattach");
        assert!(matches!(failure.error, WorkerV3Error::Stale));
        assert!(alive.load(Ordering::SeqCst));
        assert!(
            failure
                .detached
                .process
                .terminate_bounded(TERMINATION_TIMEOUT)
        );
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[test]
    fn registry_methods_contain_no_process_probe_or_termination() {
        let source = include_str!("worker_v3.rs");
        let start = source.find("impl WorkerRegistry {").expect("registry impl");
        let end = source[start..]
            .find("\nfn request_key(")
            .map(|offset| start + offset)
            .expect("registry impl end");
        let registry_source = &source[start..end];
        for forbidden in [
            ".probe_alive(",
            ".terminate_bounded(",
            ".try_wait(",
            ".kill(",
            "thread::sleep(",
        ] {
            assert!(
                !registry_source.contains(forbidden),
                "registry process-operation regression: {forbidden}"
            );
        }

        let duplicate_start = source
            .find("    fn duplicate_network_namespace_pin(\n")
            .expect("worker-process namespace-pin duplicator");
        let duplicate_end = source[duplicate_start..]
            .find("\n    #[cfg(test)]\n    fn fake(")
            .map(|offset| duplicate_start + offset)
            .expect("worker-process namespace-pin duplicator end");
        let duplicate_source = &source[duplicate_start..duplicate_end];
        for forbidden in [
            "ensure_pinned_child_alive",
            ".ensure_alive(",
            ".probe_alive(",
            ".probe_alive_until(",
        ] {
            assert!(
                !duplicate_source.contains(forbidden),
                "registry-locked namespace duplication must not probe the process: {forbidden}"
            );
        }
    }

    #[test]
    fn finish_rechecks_process_liveness_at_commit() {
        let now = Instant::now();
        let context_id = [26; 16];
        let request = initialise(context_id, 20);
        let mut registry = WorkerRegistry::new(1, 2, Duration::from_secs(10));
        let (process, _peer, alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), now)
            .expect("register");
        let planned = call(
            registry
                .plan(context_id, generation, &request, now)
                .expect("plan"),
        );
        let response = initialised_response(&request, context_id);
        alive.store(false, Ordering::SeqCst);

        let FinishOutcome::Rejected {
            error: WorkerV3Error::Dead,
            detached: Some(detached),
        } = registry.finish(planned.token, &request, &response, now, true)
        else {
            panic!("commit must recheck process liveness after a stale positive snapshot")
        };
        stop_and_purge(&mut registry, detached);
    }

    #[test]
    fn cleanup_incomplete_worker_result_quarantines_and_detaches_exact_generation() {
        let now = Instant::now();
        let context_id = [52; 16];
        let request = initialise(context_id, 47);
        let mut registry = WorkerRegistry::new(1, 8, Duration::from_secs(10));
        let (process, _peer, _alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), now)
            .expect("register");
        let planned = call(
            registry
                .plan(context_id, generation, &request, now)
                .expect("plan"),
        );
        let response = correlated_response(&request, InternalWorkerResult::CleanupIncomplete, None)
            .expect("cleanup-incomplete response");

        let FinishOutcome::Rejected {
            error: WorkerV3Error::Ambiguous,
            detached: Some(detached),
        } = registry.finish(planned.token, &request, &response, now, true)
        else {
            panic!("uncertain cleanup must retire the exact worker generation")
        };
        assert!(registry.cache.is_empty());
        assert_eq!(
            registry
                .visible_phase(context_id, generation)
                .expect("quarantined phase"),
            VisiblePhase::Quarantined
        );
        stop_and_purge(&mut registry, detached);
    }

    #[test]
    fn expired_operation_deadline_rejects_normal_commit_boundary() {
        let context_id = [49; 16];
        let request = initialise(context_id, 43);
        let mut registry = WorkerRegistry::new(1, 8, Duration::from_secs(10));
        let (process, _peer, _alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        let deadline = HardDeadline::after(Duration::from_millis(200)).expect("commit deadline");
        let planned = call(
            registry
                .plan_until(context_id, generation, &request, Instant::now(), deadline)
                .expect("plan"),
        );
        let response = initialised_response(&request, context_id);
        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        registry.finish_commit_hook = Some(FinishCommitHook {
            reached: Arc::clone(&reached),
            release: Arc::clone(&release),
        });
        let finisher = thread::spawn(move || {
            let outcome = registry.finish(planned.token, &request, &response, Instant::now(), true);
            (registry, outcome)
        });
        reached.wait();
        assert!(deadline.ensure_remaining().is_ok());
        thread::sleep(
            deadline.remaining().expect("remaining commit budget") + Duration::from_millis(20),
        );
        release.wait();
        let (mut registry, outcome) = finisher.join().expect("finish thread");
        let FinishOutcome::Rejected {
            error: WorkerV3Error::Deadline,
            detached: Some(detached),
        } = outcome
        else {
            panic!("expired normal completion must reject exact generation")
        };
        assert!(registry.cache.is_empty());
        assert_eq!(
            registry
                .visible_phase(context_id, generation)
                .expect("phase"),
            VisiblePhase::Quarantined,
        );
        stop_and_purge(&mut registry, detached);
    }

    #[test]
    fn expired_operation_deadline_rejects_cached_commit_boundary() {
        let mut registry = WorkerRegistry::new(1, 8, Duration::from_secs(10));
        let cached_context = [50; 16];
        let (process, _peer, _alive) = fake_process(Duration::from_secs(1));
        let cached_generation = registry
            .register(
                cached_context,
                process,
                Duration::from_secs(5),
                Instant::now(),
            )
            .expect("cached register");
        let cached_request = initialise(cached_context, 44);
        let first = call(
            registry
                .plan(
                    cached_context,
                    cached_generation,
                    &cached_request,
                    Instant::now(),
                )
                .expect("first plan"),
        );
        let cached_response = initialised_response(&cached_request, cached_context);
        assert!(matches!(
            registry.finish(
                first.token,
                &cached_request,
                &cached_response,
                Instant::now(),
                true,
            ),
            FinishOutcome::Committed,
        ));
        let cached_deadline =
            HardDeadline::after(Duration::from_millis(200)).expect("cached deadline");
        let RegistryPlan::Cached(cached) = registry
            .plan_until(
                cached_context,
                cached_generation,
                &cached_request,
                Instant::now(),
                cached_deadline,
            )
            .expect("cached plan")
        else {
            panic!("exact cached plan")
        };
        let reached = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        registry.finish_commit_hook = Some(FinishCommitHook {
            reached: Arc::clone(&reached),
            release: Arc::clone(&release),
        });
        let validator = thread::spawn(move || {
            let outcome = registry.validate_cached(&cached, Instant::now(), true);
            (registry, outcome)
        });
        reached.wait();
        assert!(cached_deadline.ensure_remaining().is_ok());
        thread::sleep(
            cached_deadline
                .remaining()
                .expect("remaining cached commit budget")
                + Duration::from_millis(20),
        );
        release.wait();
        let (mut registry, outcome) = validator.join().expect("cached validator");
        let FinishOutcome::Rejected {
            error: WorkerV3Error::Deadline,
            detached: Some(detached),
        } = outcome
        else {
            panic!("expired cached completion must reject exact generation")
        };
        assert!(registry.cache.is_empty());
        stop_and_purge(&mut registry, detached);
    }

    #[test]
    fn exact_cache_never_masks_liveness_and_collision_quarantines() {
        let now = Instant::now();
        let context_id = [5; 16];
        let request = initialise(context_id, 10);
        let mut registry = WorkerRegistry::new(1, 8, Duration::from_secs(10));
        let (process, _peer, alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), now)
            .expect("register");
        let planned = call(
            registry
                .plan(context_id, generation, &request, now)
                .expect("plan"),
        );
        let response = initialised_response(&request, context_id);
        assert!(matches!(
            registry.finish(planned.token, &request, &response, now, true),
            FinishOutcome::Committed
        ));
        let cached = match registry
            .plan(context_id, generation, &request, now)
            .expect("cached")
        {
            RegistryPlan::Cached(cached) => cached,
            RegistryPlan::Call(_) => panic!("expected cache"),
        };
        alive.store(false, Ordering::SeqCst);
        let FinishOutcome::Rejected {
            error: WorkerV3Error::Dead,
            detached: Some(detached),
        } = registry.validate_cached(&cached, now, true)
        else {
            panic!("dead cached worker must be rejected and detached")
        };
        assert!(registry.cache.is_empty());
        stop_and_purge(&mut registry, detached);

        let (process, _peer, _alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), now)
            .expect("new worker");
        let request = initialise(context_id, 11);
        let planned = call(
            registry
                .plan(context_id, generation, &request, now)
                .expect("plan"),
        );
        let response = initialised_response(&request, context_id);
        assert!(matches!(
            registry.finish(planned.token, &request, &response, now, true),
            FinishOutcome::Committed
        ));
        let mut changed = request;
        let Some(internal_worker_request::Operation::Initialise(initialise)) =
            changed.operation.as_mut()
        else {
            panic!("initialise operation")
        };
        initialise.mptcp_subflows = 3;
        assert!(matches!(
            registry.plan(context_id, generation, &changed, now),
            Err(WorkerV3Error::Conflict)
        ));
        assert_eq!(
            registry
                .visible_phase(context_id, generation)
                .expect("quarantined phase"),
            VisiblePhase::Quarantined
        );
    }

    #[test]
    fn execute_without_runtime_fails_before_admission_plan_or_spawn() {
        struct NoopWake;

        impl std::task::Wake for NoopWake {
            fn wake(self: Arc<Self>) {}
        }

        let source = include_str!("worker_v3.rs");
        let execute_start = source
            .find("    async fn execute(")
            .expect("coordinator execute");
        let execute_end = source[execute_start..]
            .find("    fn spawn_supervisor")
            .map(|offset| execute_start + offset)
            .expect("coordinator execute end");
        let execute_source = &source[execute_start..execute_end];
        let runtime_gate = execute_source
            .find("Handle::try_current()")
            .expect("runtime gate");
        let admission = execute_source
            .find("acquire_supervisor_permit()")
            .expect("supervisor admission");
        let plan = execute_source
            .find("registry.plan_until(")
            .expect("registry PLAN");
        assert!(runtime_gate < admission && admission < plan);
        let spawn_end = source[execute_end..]
            .find("    fn record_supervisor_start_failure")
            .map(|offset| execute_end + offset)
            .expect("supervisor spawn end");
        let spawn_source = &source[execute_end..spawn_end];
        let spawn_call = spawn_source.find("runtime.spawn(").expect("runtime spawn");
        let supervisor_lock = spawn_source
            .find("let mut supervisors = self")
            .expect("supervisor mutex");
        assert!(spawn_call < supervisor_lock);

        let context_id = [43; 16];
        let request = initialise(context_id, 34);
        let mut registry = WorkerRegistry::new(1, 8, Duration::from_secs(10));
        let (process, _peer, alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        let coordinator = WorkerCoordinator::new(registry);
        let mut execution = Box::pin(coordinator.execute(context_id, generation, request));
        let waker = std::task::Waker::from(Arc::new(NoopWake));
        let mut task_context = std::task::Context::from_waker(&waker);
        assert!(matches!(
            Future::poll(execution.as_mut(), &mut task_context),
            std::task::Poll::Ready(Err(WorkerV3Error::RuntimeUnavailable))
        ));
        drop(execution);

        {
            let registry = lock_worker_registry(&coordinator.registry);
            assert!(!registry.shutting_down);
            assert_eq!(registry.records.len(), 1);
            let record = registry.records.get(&context_id).expect("worker record");
            assert_eq!(record.generation, generation);
            assert_eq!(record.stable_phase, StablePhase::Starting);
            assert!(record.in_flight.is_none());
            assert!(!record.quarantined);
            assert!(record.process.is_some());
        }
        {
            let supervisors = coordinator
                .supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(!supervisors.shutting_down);
            assert_eq!(supervisors.active_permits, 0);
            assert_eq!(supervisors.pending_admissions, 0);
            assert!(supervisors.handles.is_empty());
        }
        assert!(alive.load(Ordering::SeqCst));

        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("shutdown runtime");
        assert!(runtime.block_on(async { coordinator.shutdown().await }));
        assert!(!alive.load(Ordering::SeqCst));
        assert!(matches!(
            coordinator.phase(context_id, generation),
            Err(WorkerV3Error::Stale)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn supervisor_admission_bounds_parallel_exact_cache_hits_before_plan() {
        const EXCESS_REQUESTS: usize = 16;

        let CachedSupervisorFixture {
            coordinator,
            generation,
            request,
            alive,
        } = cached_supervisor_fixture().await;
        let context_id = SUPERVISOR_CAP_CONTEXT_ID;
        let planned = Arc::new(AtomicUsize::new(0));
        let started = Arc::new(AtomicUsize::new(0));
        let rejected = Arc::new(AtomicUsize::new(0));
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        coordinator.set_supervisor_hook(SupervisorHook {
            planned: Arc::clone(&planned),
            started: Arc::clone(&started),
            release: Arc::clone(&release),
        });

        let mut callers = Vec::with_capacity(MAX_SUPERVISORS + EXCESS_REQUESTS);
        for _ in 0..MAX_SUPERVISORS + EXCESS_REQUESTS {
            let caller = coordinator.clone();
            let request = request.clone();
            let rejected = Arc::clone(&rejected);
            callers.push(tokio::spawn(async move {
                let result = caller.execute(context_id, generation, request).await;
                if matches!(&result, Err(WorkerV3Error::Capacity)) {
                    rejected.fetch_add(1, Ordering::SeqCst);
                }
                result
            }));
        }

        tokio::time::timeout(Duration::from_secs(1), async {
            while started.load(Ordering::SeqCst) != MAX_SUPERVISORS
                || rejected.load(Ordering::SeqCst) != EXCESS_REQUESTS
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("bounded admission result");
        assert_eq!(planned.load(Ordering::SeqCst), MAX_SUPERVISORS);
        {
            let supervisors = coordinator
                .supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(supervisors.active_permits, MAX_SUPERVISORS);
            assert_eq!(supervisors.pending_admissions, 0);
            assert_eq!(supervisors.handles.len(), MAX_SUPERVISORS);
        }

        release.add_permits(MAX_SUPERVISORS);
        let mut successes = 0;
        let mut capacity_failures = 0;
        for caller in callers {
            match caller.await.expect("caller task") {
                Ok(execution) => {
                    successes += 1;
                    assert_eq!(execution.response.result, InternalWorkerResult::Ok as i32);
                    assert!(execution.descriptor.is_none());
                }
                Err(WorkerV3Error::Capacity) => capacity_failures += 1,
                Err(error) => panic!("unexpected execution result: {error}"),
            }
        }
        assert_eq!(successes, MAX_SUPERVISORS);
        assert_eq!(capacity_failures, EXCESS_REQUESTS);
        wait_for_supervisors_to_finish(&coordinator).await;
        {
            let supervisors = coordinator
                .supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(supervisors.pending_admissions, 0);
            assert!(supervisors.handles.len() <= MAX_SUPERVISORS);
        }
        assert!(
            tokio::time::timeout(Duration::from_secs(1), coordinator.shutdown())
                .await
                .expect("bounded shutdown")
        );
        assert!(!alive.load(Ordering::SeqCst));
        let supervisors = coordinator
            .supervisors
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert_eq!(supervisors.active_permits, 0);
        assert_eq!(supervisors.pending_admissions, 0);
        assert!(supervisors.handles.is_empty());
    }

    #[test]
    fn only_acquire_requires_a_worker_namespace_pin_during_planning() {
        let now = Instant::now();
        let context_id = [59; 16];
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, _peer, alive) = fake_process(Duration::from_secs(1));
        process
            .retirement
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
            .expect("armed fake retirement")
            .kernel_pins = None;
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), now)
            .expect("register");

        let planned = call(
            registry
                .plan(context_id, generation, &initialise(context_id, 44), now)
                .expect("non-Acquire plan without network namespace pins"),
        );
        assert!(planned.pinned_network_namespace.is_none());
        let token = planned.token;
        drop(planned);
        let detached = registry
            .mark_ambiguous(token)
            .expect("retire planned fixture")
            .expect("owned fake worker");
        stop_and_purge(&mut registry, detached);
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[test]
    fn acquire_pin_failure_precedes_request_tombstone_and_inflight_mutation() {
        let now = Instant::now();
        let context_id = [60; 16];
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, peer, alive) = fake_process(Duration::from_secs(1));
        process
            .retirement
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_mut()
            .expect("armed fake retirement")
            .kernel_pins = None;
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), now)
            .expect("register");
        registry
            .records
            .get_mut(&context_id)
            .expect("record")
            .stable_phase = StablePhase::Committed;

        assert!(matches!(
            registry.plan(context_id, generation, &acquire(context_id, 45), now),
            Err(WorkerV3Error::Authentication)
        ));
        let record = registry.records.get(&context_id).expect("unchanged record");
        assert_eq!(record.stable_phase, StablePhase::Committed);
        assert!(record.in_flight.is_none());
        assert!(!record.quarantined);
        assert!(record.process.is_some());
        assert!(registry.tombstones.is_empty());
        assert!(registry.tombstone_order.is_empty());
        assert!(registry.cache.is_empty());
        let mut byte = [0_u8; 1];
        assert_eq!(
            nix::sys::socket::recv(
                peer.as_raw_fd(),
                &mut byte,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            ),
            Err(Errno::EAGAIN),
            "failed pre-mutation pinning must not write the worker channel",
        );

        let detached = registry
            .report_dead(context_id, generation)
            .expect("quarantine fixture")
            .expect("owned fake worker");
        stop_and_purge(&mut registry, detached);
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[test]
    fn fd_operation_tombstone_is_bounded_and_never_replayed() {
        let now = Instant::now();
        let context_id = [6; 16];
        let mut registry = WorkerRegistry::new(1, 1, Duration::from_secs(10));
        let (process, _peer, _alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), now)
            .expect("register");
        registry
            .records
            .get_mut(&context_id)
            .expect("record")
            .stable_phase = StablePhase::Committed;
        let request = acquire(context_id, 12);
        let planned = call(
            registry
                .plan(context_id, generation, &request, now)
                .expect("Acquire plan"),
        );
        assert!(planned.pinned_network_namespace.is_some());
        let response = acquire_response(&request);
        assert!(matches!(
            registry.finish(planned.token, &request, &response, now, true),
            FinishOutcome::Committed
        ));
        assert!(registry.cache.is_empty());
        assert_eq!(registry.tombstones.len(), 1);
        assert!(matches!(
            registry.plan(context_id, generation, &acquire(context_id, 13), now,),
            Err(WorkerV3Error::Capacity)
        ));
        assert!(matches!(
            registry.plan(context_id, generation, &request, now),
            Err(WorkerV3Error::Conflict)
        ));

        let mut collision = request;
        let Some(internal_worker_request::Operation::AcquireTransportSocket(acquire)) =
            collision.operation.as_mut()
        else {
            panic!("Acquire operation")
        };
        acquire.path_id = 2;
        assert!(matches!(
            registry.plan(context_id, generation, &collision, now),
            Err(WorkerV3Error::Conflict)
        ));
        assert_eq!(
            registry
                .visible_phase(context_id, generation)
                .expect("phase"),
            VisiblePhase::Quarantined
        );
    }

    #[test]
    fn retirement_permit_pool_is_hard_bounded_and_poison_preserves_ownership() {
        let escalation = RetirementEscalation::state();

        let poisoned_available = Arc::clone(&escalation);
        assert!(
            thread::spawn(move || {
                let _guard = poisoned_available
                    .available_permits
                    .lock()
                    .expect("available permit mutex");
                panic!("poison available permit mutex");
            })
            .join()
            .is_err()
        );

        let poisoned_queue = Arc::clone(&escalation);
        assert!(
            thread::spawn(move || {
                let _guard = poisoned_queue.queue.lock().expect("retirement queue mutex");
                panic!("poison retirement queue mutex");
            })
            .join()
            .is_err()
        );

        for _ in 0..MAX_PROCESS_OWNERS {
            let alive_hint = Arc::new(AtomicBool::new(true));
            let retirement = ProcessRetirement {
                liveness: WorkerLiveness {
                    lifetime: Arc::new(WorkerLifetime::Fake {
                        termination_results: Mutex::new(VecDeque::new()),
                        default_result: TerminationOutcome::Reaped,
                        attempts: Arc::new(AtomicUsize::new(0)),
                        termination_delay: Duration::ZERO,
                        probe_delay: Duration::ZERO,
                    }),
                    alive_hint,
                },
                permit: Some(
                    escalation
                        .try_acquire()
                        .expect("one permit for every admitted owner"),
                ),
                kernel_pins: None,
                armed: true,
            };
            escalation.enqueue(retirement);
        }

        assert!(
            escalation.try_acquire().is_none(),
            "the fixed pool must reject before an additional process can spawn"
        );
        assert_eq!(
            escalation
                .queue
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .len(),
            MAX_PROCESS_OWNERS
        );

        for mut retirement in escalation.drain_for_test() {
            assert!(retirement.terminate_bounded(Duration::ZERO));
        }
        assert_eq!(
            *escalation
                .available_permits
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            MAX_PROCESS_OWNERS
        );
    }

    #[test]
    fn drop_is_process_work_free_and_transfers_every_owner_to_the_reaper() {
        let source = include_str!("worker_v3.rs");
        let drop_signature = ["impl Drop for ", "WorkerProcess"].concat();
        let start = source.find(&drop_signature).expect("WorkerProcess Drop");
        let end = source[start..]
            .find("\n}\n\n#[derive")
            .map(|offset| start + offset)
            .expect("WorkerProcess Drop end");
        let drop_source = &source[start..end];
        assert!(drop_source.contains("transfer_retirement_to_reaper"));
        for forbidden in [
            ".probe_alive(",
            ".terminate_bounded(",
            ".try_wait(",
            ".kill(",
            "thread::sleep(",
        ] {
            assert!(
                !drop_source.contains(forbidden),
                "Drop process-operation regression: {forbidden}"
            );
        }

        let (unregistered, _peer, unregistered_alive, unregistered_attempts) =
            fake_process_with_termination_results(Duration::from_secs(1), VecDeque::new(), true);
        drop(unregistered);
        wait_for_termination_attempts(&unregistered_attempts, 1);
        assert!(!unregistered_alive.load(Ordering::SeqCst));

        let (process, _peer, registered_alive, registered_attempts) =
            fake_process_with_termination_results(Duration::from_secs(1), VecDeque::new(), true);
        let mut registry = WorkerRegistry::new(1, 2, Duration::from_secs(10));
        registry
            .register([7; 16], process, Duration::from_secs(5), Instant::now())
            .expect("register");
        drop(registry);
        wait_for_termination_attempts(&registered_attempts, 1);
        assert!(!registered_alive.load(Ordering::SeqCst));
    }

    #[test]
    fn launch_cleanup_timeout_transfers_owner_until_the_reaper_confirms() {
        let source = include_str!("worker_v3.rs");
        let locked_start = source
            .find("fn spawn_with_command_locked(")
            .expect("locked spawn function");
        let production_spawn_boundary = ["\nfn spawn_worker_", "v3("].concat();
        let locked_end = source[locked_start..]
            .find(&production_spawn_boundary)
            .map(|offset| locked_start + offset)
            .expect("locked spawn boundary");
        let locked_source = &source[locked_start..locked_end];
        let permit_start = locked_source
            .find("    let retirement_permit = acquire_retirement_permit()?;")
            .expect("pre-spawn retirement permit");
        let launch_start = locked_source
            .find("spawn_after_seccomp_baseline(")
            .expect("baseline-bound launch section");
        let armed_retirement = locked_source
            .find("    let mut retirement = ProcessRetirement {")
            .expect("pre-spawn retirement owner");
        let close_range_hook = ["    install_close_range_on_", "exec(&mut command);"].concat();
        let close_range = locked_source
            .find(&close_range_hook)
            .expect("final user pre-exec hook");
        assert!(permit_start < armed_retirement && armed_retirement < launch_start);
        assert!(permit_start < close_range && close_range < launch_start);
        let after_close_range = locked_source[close_range..]
            .find('\n')
            .map(|offset| close_range + offset + 1)
            .expect("close-range hook line end");
        assert!(
            !locked_source[after_close_range..launch_start].contains("command."),
            "no command mutation or later user hook may follow close_range installation"
        );
        let launch_end = locked_source[launch_start..]
            .find("    Ok(AuthenticatedWorker {")
            .map(|offset| launch_start + offset)
            .expect("successful launch end");
        let launch_source = &locked_source[launch_start..launch_end];
        assert!(launch_source.contains("finish_unconstructed_launch_failure"));
        assert_eq!(
            launch_source
                .matches("finish_launch_failure(process,")
                .count(),
            3,
            "every constructed post-spawn error must transfer ownership"
        );

        let (mut process, _peer, alive, attempts) = fake_process_with_termination_results(
            Duration::from_secs(1),
            VecDeque::from([false, true]),
            true,
        );
        process.binding = Some(([36; 16], 1));

        assert!(matches!(
            finish_launch_failure(process, WorkerV3Error::Authentication),
            WorkerV3Error::Ambiguous
        ));
        wait_for_termination_attempts(&attempts, 2);
        assert!(!alive.load(Ordering::SeqCst));

        let (unconstructed, _peer, alive, attempts) = fake_process_with_termination_results(
            Duration::from_secs(1),
            VecDeque::from([false, true]),
            true,
        );
        let retirement = unconstructed
            .take_retirement()
            .expect("unconstructed process retirement owner");
        drop(unconstructed);
        assert!(matches!(
            finish_unconstructed_launch_failure(retirement, WorkerV3Error::Authentication),
            WorkerV3Error::Ambiguous
        ));
        wait_for_termination_attempts(&attempts, 2);
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[test]
    fn termination_errors_are_fatal_and_only_timeouts_are_requeueable() {
        assert_eq!(
            classify_child_wait(&Ok(Some(process::ExitStatus::from_raw(0)))),
            ChildWaitObservation::Reaped
        );
        assert_eq!(
            classify_child_wait(&Ok(None)),
            ChildWaitObservation::Running
        );
        assert_eq!(
            classify_child_wait(&Err(io::Error::other("injected wait failure"))),
            ChildWaitObservation::Fatal
        );
        assert_eq!(
            outcome_after_kill_error(ChildWaitObservation::Reaped),
            TerminationOutcome::Reaped,
            "the one post-kill-error wait closes the already-dead race"
        );
        for observation in [ChildWaitObservation::Running, ChildWaitObservation::Fatal] {
            assert_eq!(
                outcome_after_kill_error(observation),
                TerminationOutcome::Fatal,
                "a kill error without confirmed reap is process-fatal"
            );
        }
        assert_eq!(
            retirement_escalation_action(TerminationOutcome::Reaped),
            RetirementEscalationAction::Complete
        );
        assert_eq!(
            retirement_escalation_action(TerminationOutcome::TimedOut),
            RetirementEscalationAction::Requeue
        );
        assert_eq!(
            retirement_escalation_action(TerminationOutcome::Fatal),
            RetirementEscalationAction::Abort
        );
    }

    #[test]
    fn kernel_pins_survive_uncertainty_and_drop_only_after_confirmed_reap() {
        let attempts = Arc::new(AtomicUsize::new(0));
        let alive_hint = Arc::new(AtomicBool::new(true));
        let mut retirement = ProcessRetirement {
            liveness: WorkerLiveness {
                lifetime: Arc::new(WorkerLifetime::Fake {
                    termination_results: Mutex::new(VecDeque::from([
                        TerminationOutcome::TimedOut,
                        TerminationOutcome::Fatal,
                        TerminationOutcome::Reaped,
                    ])),
                    default_result: TerminationOutcome::Reaped,
                    attempts: Arc::clone(&attempts),
                    termination_delay: Duration::ZERO,
                    probe_delay: Duration::ZERO,
                }),
                alive_hint,
            },
            permit: Some(acquire_retirement_permit().expect("pin retention permit")),
            kernel_pins: Some(crate::worker_sandbox::WorkerKernelPins::fixture()),
            armed: true,
        };
        assert!(!retirement.terminate_bounded(TERMINATION_TIMEOUT));
        assert!(retirement.armed);
        assert!(retirement.liveness.known_alive());
        assert!(
            retirement
                .kernel_pins
                .as_ref()
                .is_some_and(crate::worker_sandbox::WorkerKernelPins::has_complete_pins)
        );
        assert_eq!(
            retirement.termination_outcome(TERMINATION_TIMEOUT),
            TerminationOutcome::Fatal
        );
        assert!(retirement.armed);
        assert!(retirement.liveness.known_alive());
        assert!(
            retirement
                .kernel_pins
                .as_ref()
                .is_some_and(crate::worker_sandbox::WorkerKernelPins::has_complete_pins)
        );
        assert!(retirement.terminate_bounded(TERMINATION_TIMEOUT));
        assert!(!retirement.armed);
        assert!(retirement.kernel_pins.is_none());
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
    }

    #[test]
    fn retirement_drop_moves_kernel_pins_through_the_escalation_queue() {
        let escalation = RetirementEscalation::state();
        let permit = escalation.try_acquire().expect("local escalation permit");
        let retirement = ProcessRetirement {
            liveness: WorkerLiveness {
                lifetime: Arc::new(WorkerLifetime::Fake {
                    termination_results: Mutex::new(VecDeque::from([TerminationOutcome::Reaped])),
                    default_result: TerminationOutcome::Reaped,
                    attempts: Arc::new(AtomicUsize::new(0)),
                    termination_delay: Duration::ZERO,
                    probe_delay: Duration::ZERO,
                }),
                alive_hint: Arc::new(AtomicBool::new(true)),
            },
            permit: Some(permit),
            kernel_pins: Some(crate::worker_sandbox::WorkerKernelPins::fixture()),
            armed: true,
        };

        drop(retirement);
        let mut queued = escalation.drain_for_test();
        assert_eq!(queued.len(), 1);
        let mut moved = queued.pop_front().expect("moved retirement owner");
        assert!(
            moved
                .kernel_pins
                .as_ref()
                .is_some_and(crate::worker_sandbox::WorkerKernelPins::has_complete_pins)
        );
        assert!(moved.terminate_bounded(TERMINATION_TIMEOUT));
        assert!(moved.kernel_pins.is_none());
        drop(moved);
        assert_eq!(
            *escalation
                .available_permits
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner),
            MAX_PROCESS_OWNERS
        );
    }

    #[tokio::test]
    async fn reattach_failure_escalates_owner_until_confirmed_reap() {
        let registry = Arc::new(Mutex::new(WorkerRegistry::new(
            1,
            2,
            Duration::from_secs(10),
        )));
        let (mut process, _peer, alive, attempts) = fake_process_with_termination_results(
            Duration::from_secs(1),
            VecDeque::from([false, true]),
            true,
        );
        let context_id = [37; 16];
        process.binding = Some((context_id, 1));
        let supervisor = WorkerSupervisor {
            registry: Arc::clone(&registry),
            settlements: Arc::new(Mutex::new(SupervisorSettlements::new())),
        };

        assert!(
            !supervisor
                .retire(DetachedWorker {
                    context_id,
                    generation: 1,
                    process,
                })
                .await
        );
        wait_for_termination_attempts(&attempts, 2);
        assert!(!alive.load(Ordering::SeqCst));
        assert!(lock_worker_registry(&registry).records.is_empty());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_captures_retire_failure_and_final_sweep_confirms_owner() {
        let context_id = [40; 16];
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, peer, alive, attempts) = fake_process_with_termination_results(
            Duration::from_secs(1),
            VecDeque::from([false, true]),
            true,
        );
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        drop(peer);
        let coordinator = WorkerCoordinator::new(registry);
        let failed = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        coordinator.set_retirement_hook(RetirementHook {
            failed: Arc::clone(&failed),
            release: Arc::clone(&release),
        });

        let executing = coordinator.clone();
        let execution = tokio::spawn(async move {
            executing
                .execute(context_id, generation, initialise(context_id, 32))
                .await
        });
        tokio::task::spawn_blocking(move || failed.wait())
            .await
            .expect("failed retirement barrier");

        let shutdown = coordinator.shutdown();
        {
            let registry = lock_worker_registry(&coordinator.registry);
            let record = registry
                .records
                .get(&context_id)
                .expect("fenced detached record");
            assert!(registry.shutting_down);
            assert!(record.quarantined);
            assert!(record.process.is_none());
        }
        tokio::task::spawn_blocking(move || release.wait())
            .await
            .expect("failed retirement release");

        assert!(
            tokio::time::timeout(Duration::from_secs(1), shutdown)
                .await
                .expect("bounded shutdown")
        );
        assert!(matches!(
            execution.await.expect("execution task"),
            Err(WorkerV3Error::Ambiguous)
        ));
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert!(!alive.load(Ordering::SeqCst));
        assert!(
            lock_worker_registry(&coordinator.registry)
                .records
                .is_empty()
        );
    }

    #[test]
    fn runtime_cancellation_publishes_shared_bounded_shutdown_failure() {
        let context_id = [41; 16];
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, _peer, alive, attempts) =
            fake_process_with_termination_results(Duration::from_secs(1), VecDeque::new(), true);
        registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        let coordinator = WorkerCoordinator::new(registry);
        let started = Arc::new(AtomicBool::new(false));
        let release = Arc::new(Notify::new());
        coordinator.set_shutdown_hook(ShutdownHook {
            started: Arc::clone(&started),
            release,
        });

        let runtime = tokio::runtime::Builder::new_multi_thread()
            .worker_threads(2)
            .enable_time()
            .build()
            .expect("temporary runtime");
        runtime.block_on(async {
            drop(coordinator.shutdown());
        });

        let deadline = Instant::now() + Duration::from_secs(1);
        while !started.load(Ordering::SeqCst) {
            assert!(
                Instant::now() < deadline,
                "owned shutdown task did not start"
            );
            thread::sleep(Duration::from_millis(1));
        }
        runtime.shutdown_timeout(Duration::from_millis(100));

        let next_runtime = tokio::runtime::Builder::new_current_thread()
            .enable_time()
            .build()
            .expect("next runtime");
        let confirmed = next_runtime.block_on(async {
            tokio::time::timeout(Duration::from_secs(1), coordinator.shutdown())
                .await
                .expect("shared completion must be bounded")
        });
        assert!(!confirmed);
        wait_for_termination_attempts(&attempts, 1);
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn explicit_coordinator_shutdown_retires_and_purges_every_worker() {
        let mut registry = WorkerRegistry::new(1, 2, Duration::from_secs(10));
        let (process, _peer, alive) = fake_process(Duration::from_secs(1));
        let context_id = [35; 16];
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        let coordinator = WorkerCoordinator::new(registry);

        assert!(alive.load(Ordering::SeqCst));
        assert!(coordinator.shutdown().await);
        assert!(!alive.load(Ordering::SeqCst));
        assert!(matches!(
            coordinator.phase(context_id, generation),
            Err(WorkerV3Error::Stale)
        ));
        assert!(
            coordinator.registry.try_lock().is_ok(),
            "explicit teardown must finish with the registry mutex available"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn aborting_shutdown_waiter_cannot_cancel_owned_teardown() {
        let context_id = [38; 16];
        let request = initialise(context_id, 30);
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, peer, alive, attempts) =
            fake_process_with_termination_results(Duration::from_secs(1), VecDeque::new(), true);
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        let coordinator = WorkerCoordinator::new(registry);
        let received = Arc::new(AtomicBool::new(false));
        let worker_received = Arc::clone(&received);
        let worker = thread::spawn(move || {
            let request =
                receive_credential_worker_request(&peer, current_credentials()).expect("request");
            worker_received.store(true, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(75));
            let response = initialised_response(&request, context_id);
            send_credential_worker_response(&peer, &request, &response, None).expect("response");
        });
        let executing = coordinator.clone();
        let execution =
            tokio::spawn(async move { executing.execute(context_id, generation, request).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !received.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker received request");

        let shutdown_started = Arc::new(AtomicBool::new(false));
        let shutdown_release = Arc::new(Notify::new());
        coordinator.set_shutdown_hook(ShutdownHook {
            started: Arc::clone(&shutdown_started),
            release: Arc::clone(&shutdown_release),
        });

        let waiter = coordinator.shutdown();
        tokio::time::timeout(Duration::from_secs(1), async {
            while !shutdown_started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("shutdown task started");
        {
            let registry = lock_worker_registry(&coordinator.registry);
            let record = registry.records.get(&context_id).expect("shutdown record");
            assert!(registry.shutting_down);
            assert!(record.quarantined);
            assert!(record.process.is_none());
        }
        let cancelled = tokio::spawn(waiter);
        cancelled.abort();
        assert!(
            cancelled
                .await
                .expect_err("waiter cancelled")
                .is_cancelled()
        );
        shutdown_release.notify_one();
        assert!(coordinator.shutdown().await);
        assert!(execution.await.expect("execution task").is_err());
        worker.join().expect("worker join");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_shutdown_callers_share_one_completion_and_retirement() {
        let context_id = [39; 16];
        let request = initialise(context_id, 31);
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, peer, alive, attempts) =
            fake_process_with_termination_results(Duration::from_secs(1), VecDeque::new(), true);
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        let coordinator = WorkerCoordinator::new(registry);
        let received = Arc::new(AtomicBool::new(false));
        let worker_received = Arc::clone(&received);
        let worker = thread::spawn(move || {
            let request =
                receive_credential_worker_request(&peer, current_credentials()).expect("request");
            worker_received.store(true, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(75));
            let response = initialised_response(&request, context_id);
            send_credential_worker_response(&peer, &request, &response, None).expect("response");
        });
        let executing = coordinator.clone();
        let execution =
            tokio::spawn(async move { executing.execute(context_id, generation, request).await });
        tokio::time::timeout(Duration::from_secs(1), async {
            while !received.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("worker received request");

        let first = tokio::spawn(coordinator.shutdown());
        let second = tokio::spawn(coordinator.shutdown());
        assert!(first.await.expect("first shutdown waiter"));
        assert!(second.await.expect("second shutdown waiter"));
        assert!(coordinator.shutdown().await);
        assert!(execution.await.expect("execution task").is_err());
        worker.join().expect("worker join");
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn concurrent_callers_share_retryable_attempt_and_one_exact_confirming_retry() {
        let context_id = [51; 16];
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, _peer, alive, attempts) = fake_process_with_termination_results(
            Duration::from_secs(1),
            VecDeque::from([false, true]),
            true,
        );
        registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        let coordinator = WorkerCoordinator::new(registry);

        let first_started = Arc::new(AtomicBool::new(false));
        let first_release = Arc::new(Notify::new());
        coordinator.set_shutdown_hook(ShutdownHook {
            started: Arc::clone(&first_started),
            release: Arc::clone(&first_release),
        });
        let first = coordinator.shutdown_until(
            HardDeadline::after(Duration::from_secs(2)).expect("first caller deadline"),
        );
        let second = coordinator.shutdown_until(
            HardDeadline::after(Duration::from_secs(2)).expect("second caller deadline"),
        );
        let first = tokio::spawn(first);
        let second = tokio::spawn(second);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !first_started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("first attempt starts");
        assert_eq!(
            coordinator
                .supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .shutdown_attempt,
            1,
        );
        first_release.notify_one();
        assert_eq!(
            first.await.expect("first caller"),
            ShutdownStatus::Retryable
        );
        assert_eq!(
            second.await.expect("second caller"),
            ShutdownStatus::Retryable
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 1);

        let retry_started = Arc::new(AtomicBool::new(false));
        let retry_release = Arc::new(Notify::new());
        coordinator.set_shutdown_hook(ShutdownHook {
            started: Arc::clone(&retry_started),
            release: Arc::clone(&retry_release),
        });
        let retry_one = coordinator.shutdown_until(
            HardDeadline::after(Duration::from_secs(2)).expect("retry one deadline"),
        );
        let retry_two = coordinator.shutdown_until(
            HardDeadline::after(Duration::from_secs(2)).expect("retry two deadline"),
        );
        let retry_one = tokio::spawn(retry_one);
        let retry_two = tokio::spawn(retry_two);
        tokio::time::timeout(Duration::from_secs(1), async {
            while !retry_started.load(Ordering::SeqCst) {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("retry attempt starts");
        assert_eq!(
            coordinator
                .supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .shutdown_attempt,
            2,
        );
        retry_release.notify_one();
        assert_eq!(
            retry_one.await.expect("retry one"),
            ShutdownStatus::Confirmed
        );
        assert_eq!(
            retry_two.await.expect("retry two"),
            ShutdownStatus::Confirmed
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[test]
    fn terminal_unresolved_drains_existing_and_late_settlement_owners_exactly_once() {
        let (queued_process, _queued_peer, _queued_alive, queued_attempts) =
            fake_process_with_termination_results(Duration::from_secs(1), VecDeque::new(), true);
        let (late_process, _late_peer, _late_alive, late_attempts) =
            fake_process_with_termination_results(Duration::from_secs(1), VecDeque::new(), true);
        let queued = DetachedWorker {
            context_id: [52; 16],
            generation: 1,
            process: queued_process,
        };
        let late = DetachedWorker {
            context_id: [53; 16],
            generation: 2,
            process: late_process,
        };
        let settlements = Arc::new(Mutex::new(SupervisorSettlements::new()));
        settlements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .capture_shutdown_owner(queued);
        let completion = ShutdownCompletion::new();
        let supervisors = Arc::new(Mutex::new(SupervisorState {
            shutting_down: true,
            active_permits: 0,
            pending_admissions: 0,
            handles: Vec::new(),
            shutdown_workers: Vec::new(),
            shutdown_attempt: 1,
            shutdown_status: Some(ShutdownStatus::Pending),
            shutdown_completion: Some(completion.clone()),
        }));
        ShutdownPublicationGuard::new(
            Arc::clone(&supervisors),
            Arc::clone(&settlements),
            1,
            completion,
        )
        .publish(
            ShutdownStatus::Unresolved,
            ShutdownAttemptOwners::new(Vec::new(), Vec::new()),
        );
        settlements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .capture_shutdown_owner(late);

        wait_for_termination_attempts(&queued_attempts, 1);
        wait_for_termination_attempts(&late_attempts, 1);
        let settlements = settlements
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(settlements.unresolved);
        assert!(settlements.shutdown_owners.is_empty());
        assert_eq!(queued_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(late_attempts.load(Ordering::SeqCst), 1);
        assert_eq!(
            supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .shutdown_status,
            Some(ShutdownStatus::Unresolved),
        );
    }

    #[test]
    fn real_child_termination_is_bounded_and_reaped() {
        let (channel, _peer) = private_credential_worker_channel().expect("channel");
        let mut command = child_command("hold");
        command
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null());
        let retirement_permit =
            acquire_retirement_permit().expect("holding child retirement permit");
        let child = command.spawn().expect("holding child");
        let child_pid = child.id();
        let lifetime = Arc::new(WorkerLifetime::Child(Mutex::new(Some(child))));
        let alive_hint = Arc::new(AtomicBool::new(true));
        let retirement = ProcessRetirement {
            liveness: WorkerLiveness {
                lifetime: Arc::clone(&lifetime),
                alive_hint: Arc::clone(&alive_hint),
            },
            permit: Some(retirement_permit),
            kernel_pins: None,
            armed: true,
        };
        let process = WorkerProcess {
            child_pid,
            binding: None,
            expected_peer: ExpectedUnixCredentials::new(
                child_pid,
                geteuid().as_raw(),
                getegid().as_raw(),
            )
            .expect("child credentials"),
            channel,
            lifetime,
            alive_hint,
            retirement: Mutex::new(Some(retirement)),
        };
        let started = Instant::now();
        assert!(process.terminate_bounded(TERMINATION_TIMEOUT));
        assert!(started.elapsed() < TERMINATION_TIMEOUT + Duration::from_secs(1));
        assert!(!process.probe_alive());
    }

    #[tokio::test]
    async fn eof_with_uncertain_termination_is_retained_for_explicit_shutdown_retry() {
        let context_id = [8; 16];
        let request = initialise(context_id, 13);
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, peer, alive, attempts) = fake_process_with_termination_results(
            Duration::from_millis(50),
            VecDeque::from([false, false, true]),
            true,
        );
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        drop(peer);
        let coordinator = WorkerCoordinator::new(registry);
        assert!(matches!(
            coordinator.execute(context_id, generation, request).await,
            Err(WorkerV3Error::Ambiguous)
        ));
        assert!(alive.load(Ordering::SeqCst));
        assert_eq!(
            coordinator.phase(context_id, generation).expect("phase"),
            VisiblePhase::Quarantined
        );
        let first_deadline = HardDeadline::after(Duration::from_secs(1)).expect("first deadline");
        assert_eq!(
            coordinator.shutdown_until(first_deadline).await,
            ShutdownStatus::Retryable
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert!(alive.load(Ordering::SeqCst));
        {
            let state = coordinator
                .supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(state.shutdown_status, Some(ShutdownStatus::Retryable));
            assert_eq!(state.shutdown_workers.len(), 1);
            assert!(state.handles.is_empty());
        }
        let retry_deadline = HardDeadline::after(Duration::from_secs(1)).expect("retry deadline");
        assert_eq!(
            coordinator.shutdown_until(retry_deadline).await,
            ShutdownStatus::Confirmed
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 3);
        assert!(!alive.load(Ordering::SeqCst));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn reap_observed_after_shutdown_deadline_is_retryable_and_owner_remains_retained() {
        let context_id = [47; 16];
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, _peer, alive, attempts) =
            fake_process_with_delayed_termination(Duration::from_millis(60));
        registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        let coordinator = WorkerCoordinator::new(registry);
        let deadline = HardDeadline::after(Duration::from_millis(20)).expect("short deadline");
        assert_eq!(
            coordinator.shutdown_until(deadline).await,
            ShutdownStatus::Pending,
        );
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let retryable = coordinator
                    .supervisors
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .shutdown_status
                    == Some(ShutdownStatus::Retryable);
                if retryable {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("owned shutdown attempt settles retryably");
        {
            let state = coordinator
                .supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(state.shutdown_workers.len(), 1);
            assert_eq!(state.shutdown_attempt, 1);
        }
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
        assert!(!alive.load(Ordering::SeqCst));

        let retry = HardDeadline::after(Duration::from_secs(1)).expect("retry deadline");
        assert_eq!(
            coordinator.shutdown_until(retry).await,
            ShutdownStatus::Confirmed,
        );
        assert_eq!(attempts.load(Ordering::SeqCst), 2);
        assert_eq!(
            coordinator
                .supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .shutdown_attempt,
            2,
        );
        let expired = HardDeadline::after(Duration::from_millis(10)).expect("expiring deadline");
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(
            coordinator.shutdown_until(expired).await,
            ShutdownStatus::Confirmed,
        );
        assert_eq!(
            coordinator
                .supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .shutdown_attempt,
            2,
        );
    }

    #[tokio::test]
    async fn expired_initial_shutdown_deadline_is_a_zero_mutation_retryable_noop() {
        let context_id = [58; 16];
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, _peer, alive, attempts) =
            fake_process_with_termination_results(Duration::from_secs(1), VecDeque::new(), true);
        registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register live worker");
        let coordinator = WorkerCoordinator::new(registry);
        let expired = HardDeadline::after(Duration::from_millis(10)).expect("short deadline");
        tokio::time::sleep(Duration::from_millis(20)).await;

        assert_eq!(
            coordinator.shutdown_until(expired).await,
            ShutdownStatus::Retryable,
        );
        {
            let state = coordinator
                .supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert!(!state.shutting_down);
            assert_eq!(state.shutdown_attempt, 0);
            assert_eq!(state.shutdown_status, None);
            assert!(state.shutdown_completion.is_none());
            assert!(state.shutdown_workers.is_empty());
            assert!(state.handles.is_empty());
        }
        {
            let registry = lock_worker_registry(&coordinator.registry);
            assert!(!registry.shutting_down);
            let record = registry.records.get(&context_id).expect("live record");
            assert!(record.process.is_some());
            assert!(!record.quarantined);
        }
        assert!(alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 0);

        let retry = HardDeadline::after(Duration::from_secs(1)).expect("valid retry deadline");
        assert_eq!(
            coordinator.shutdown_until(retry).await,
            ShutdownStatus::Confirmed,
        );
        assert!(!alive.load(Ordering::SeqCst));
        assert_eq!(attempts.load(Ordering::SeqCst), 1);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn multiple_delayed_shutdown_owners_share_one_absolute_attempt_budget() {
        let mut registry = WorkerRegistry::new(3, 8, Duration::from_secs(10));
        let mut peers = Vec::new();
        let mut alive = Vec::new();
        let mut attempts = Vec::new();
        for marker in 54_u8..57 {
            let (process, peer, worker_alive, worker_attempts) =
                fake_process_with_delayed_termination(Duration::from_millis(250));
            registry
                .register(
                    [marker; 16],
                    process,
                    Duration::from_secs(5),
                    Instant::now(),
                )
                .expect("register delayed worker");
            peers.push(peer);
            alive.push(worker_alive);
            attempts.push(worker_attempts);
        }
        let coordinator = WorkerCoordinator::new(registry);
        let deadline = HardDeadline::after(Duration::from_millis(200)).expect("shared deadline");
        let shutdown = coordinator.shutdown_until(deadline);
        tokio::time::timeout(Duration::from_secs(1), async {
            while attempts
                .iter()
                .map(|count| count.load(Ordering::SeqCst))
                .sum::<usize>()
                == 0
            {
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("one retirement starts inside the shared budget");
        assert_eq!(shutdown.await, ShutdownStatus::Pending);
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let retryable = coordinator
                    .supervisors
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .shutdown_status
                    == Some(ShutdownStatus::Retryable);
                if retryable {
                    break;
                }
                tokio::task::yield_now().await;
            }
        })
        .await
        .expect("late first owner settles retryably");
        let first_attempts = attempts
            .iter()
            .map(|count| count.load(Ordering::SeqCst))
            .sum::<usize>();
        assert_eq!(first_attempts, 1, "the deadline is not reset per owner");
        assert_eq!(
            coordinator
                .supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .shutdown_workers
                .len(),
            3,
        );

        let retry = HardDeadline::after(Duration::from_secs(2)).expect("retry deadline");
        assert_eq!(
            coordinator.shutdown_until(retry).await,
            ShutdownStatus::Confirmed
        );
        assert_eq!(
            attempts
                .iter()
                .map(|count| count.load(Ordering::SeqCst))
                .sum::<usize>(),
            first_attempts + 3,
        );
        assert!(alive.iter().all(|flag| !flag.load(Ordering::SeqCst)));
        drop(peers);
    }

    #[tokio::test]
    async fn shutdown_waiter_accepts_only_completion_linearized_before_its_own_deadline() {
        let late = ShutdownCompletion::new();
        let short = HardDeadline::after(Duration::from_millis(20)).expect("short waiter deadline");
        tokio::time::sleep(Duration::from_millis(40)).await;
        late.complete(ShutdownStatus::Confirmed);
        assert_eq!(late.wait_until(short).await, ShutdownStatus::Pending);

        let timely = ShutdownCompletion::new();
        let long = HardDeadline::after(Duration::from_secs(1)).expect("long waiter deadline");
        timely.complete(ShutdownStatus::Retryable);
        assert_eq!(timely.wait_until(long).await, ShutdownStatus::Retryable);
    }

    #[tokio::test]
    async fn timeout_is_ambiguous_and_confirmed_cleanup_purges_generation() {
        let context_id = [9; 16];
        let request = initialise(context_id, 14);
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, _peer, alive) = fake_process(Duration::from_millis(25));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        let coordinator = WorkerCoordinator::new(registry);
        let deadline = HardDeadline::after(Duration::from_millis(25)).expect("call deadline");
        assert!(matches!(
            coordinator
                .execute_until(context_id, generation, request, deadline)
                .await,
            Err(WorkerV3Error::Deadline)
        ));
        assert!(!alive.load(Ordering::SeqCst));
        assert!(matches!(
            coordinator.phase(context_id, generation),
            Err(WorkerV3Error::Stale)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn caller_abort_after_plan_cannot_leave_inflight_and_registry_is_unlocked_during_io() {
        let context_id = [10; 16];
        let request = initialise(context_id, 15);
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, peer, _alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        let coordinator = WorkerCoordinator::new(registry);
        let received = Arc::new(AtomicBool::new(false));
        let worker_received = Arc::clone(&received);
        let worker = thread::spawn(move || {
            let request =
                receive_credential_worker_request(&peer, current_credentials()).expect("request");
            worker_received.store(true, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(75));
            let response = initialised_response(&request, context_id);
            send_credential_worker_response(&peer, &request, &response, None).expect("response");
        });

        let task_coordinator = coordinator.clone();
        let task = tokio::spawn(async move {
            task_coordinator
                .execute(context_id, generation, request)
                .await
        });
        while !received.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        assert!(coordinator.registry.try_lock().is_ok());
        task.abort();
        let _ = task.await;
        worker.join().expect("worker join");

        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            match coordinator.phase(context_id, generation) {
                Ok(VisiblePhase::Stable(StablePhase::Initialised)) => break,
                Ok(VisiblePhase::InFlight) if Instant::now() < deadline => {
                    tokio::task::yield_now().await;
                }
                phase => panic!("supervisor did not finish after caller abort: {phase:?}"),
            }
        }
        assert!(coordinator.shutdown().await);
    }

    #[tokio::test]
    async fn caller_abort_before_plan_leaves_registry_unchanged() {
        let context_id = [11; 16];
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, _peer, _alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        let coordinator = WorkerCoordinator::new(registry);
        let reached = Arc::new(Notify::new());
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        coordinator.set_before_plan_hook(BeforePlanHook {
            reached: Arc::clone(&reached),
            release: Arc::clone(&release),
        });
        let task_coordinator = coordinator.clone();
        let task = tokio::spawn(async move {
            task_coordinator
                .execute(context_id, generation, initialise(context_id, 16))
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), reached.notified())
            .await
            .expect("execute reached the test-only pre-plan cancellation point");
        task.abort();
        let Err(error) = task.await else {
            panic!("caller task unexpectedly completed");
        };
        assert!(error.is_cancelled());
        release.add_permits(1);
        assert_eq!(
            coordinator.phase(context_id, generation).expect("phase"),
            VisiblePhase::Stable(StablePhase::Starting)
        );
        assert!(coordinator.shutdown().await);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn deadline_expiry_before_plan_leaves_every_registry_and_admission_field_unchanged() {
        let context_id = [46; 16];
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, peer, alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        let coordinator = WorkerCoordinator::new(registry);
        let reached = Arc::new(Notify::new());
        let release = Arc::new(tokio::sync::Semaphore::new(0));
        coordinator.set_before_plan_hook(BeforePlanHook {
            reached: Arc::clone(&reached),
            release: Arc::clone(&release),
        });
        let deadline = HardDeadline::after(Duration::from_millis(30)).expect("short deadline");
        let executing = coordinator.clone();
        let task = tokio::spawn(async move {
            executing
                .execute_until(context_id, generation, initialise(context_id, 41), deadline)
                .await
        });
        tokio::time::timeout(Duration::from_secs(1), reached.notified())
            .await
            .expect("pre-plan hook reached");
        tokio::time::sleep(Duration::from_millis(60)).await;
        release.add_permits(1);
        assert!(matches!(
            task.await.expect("execute task"),
            Err(WorkerV3Error::Deadline)
        ));
        {
            let registry = lock_worker_registry(&coordinator.registry);
            let record = registry.records.get(&context_id).expect("original record");
            assert_eq!(record.stable_phase, StablePhase::Starting);
            assert!(record.in_flight.is_none());
            assert!(!record.quarantined);
            assert!(record.process.is_some());
            assert!(registry.tombstones.is_empty());
            assert!(registry.cache.is_empty());
        }
        {
            let state = coordinator
                .supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(state.active_permits, 0);
            assert_eq!(state.pending_admissions, 0);
            assert!(state.handles.is_empty());
        }
        let mut byte = [0_u8; 1];
        assert_eq!(
            nix::sys::socket::recv(
                peer.as_raw_fd(),
                &mut byte,
                nix::sys::socket::MsgFlags::MSG_DONTWAIT,
            ),
            Err(Errno::EAGAIN),
            "expiry before PLAN must not write the worker channel",
        );
        assert!(alive.load(Ordering::SeqCst));
        assert!(coordinator.shutdown().await);
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn expired_completion_is_rejected_after_blocking_call() {
        let context_id = [12; 16];
        let request = initialise(context_id, 17);
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(1));
        let (process, peer, _alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(
                context_id,
                process,
                Duration::from_millis(20),
                Instant::now(),
            )
            .expect("register");
        let worker = thread::spawn(move || {
            let request =
                receive_credential_worker_request(&peer, current_credentials()).expect("request");
            thread::sleep(Duration::from_millis(60));
            let response = initialised_response(&request, context_id);
            send_credential_worker_response(&peer, &request, &response, None).expect("response");
        });
        let coordinator = WorkerCoordinator::new(registry);
        assert!(matches!(
            coordinator.execute(context_id, generation, request).await,
            Err(WorkerV3Error::Dead)
        ));
        worker.join().expect("worker join");
        assert!(matches!(
            coordinator.phase(context_id, generation),
            Err(WorkerV3Error::Stale)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn dead_worker_completion_rejects_and_closes_received_descriptor() {
        let context_id = [13; 16];
        let request = acquire(context_id, 18);
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, peer, alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        registry
            .records
            .get_mut(&context_id)
            .expect("record")
            .stable_phase = StablePhase::Committed;
        let (sent, observer) = Socket::pair(Domain::UNIX, Type::STREAM.cloexec(), None::<Protocol>)
            .expect("descriptor pair");
        observer
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("observer timeout");
        let sent: OwnedFd = sent.into();
        let worker_alive = Arc::clone(&alive);
        let worker = thread::spawn(move || {
            let request =
                receive_credential_worker_request(&peer, current_credentials()).expect("request");
            let response = acquire_response(&request);
            worker_alive.store(false, Ordering::SeqCst);
            send_credential_worker_response(&peer, &request, &response, Some(sent))
                .expect("FD response");
        });

        let coordinator = WorkerCoordinator::new(registry);
        assert!(matches!(
            coordinator.execute(context_id, generation, request).await,
            Err(WorkerV3Error::Dead)
        ));
        worker.join().expect("worker join");
        let mut byte = [0_u8; 1];
        assert_eq!(
            (&observer).read(&mut byte).expect("observer EOF"),
            0,
            "the rejected credentialed descriptor must close before returning"
        );
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn invalid_adopted_descriptor_is_closed_and_generation_is_retired() {
        let context_id = [61; 16];
        let request = acquire(context_id, 46);
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, peer, alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        registry
            .records
            .get_mut(&context_id)
            .expect("record")
            .stable_phase = StablePhase::Committed;
        let (sent, observer) = Socket::pair(Domain::UNIX, Type::STREAM.cloexec(), None::<Protocol>)
            .expect("descriptor pair");
        observer
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("observer timeout");
        let sent: OwnedFd = sent.into();
        let worker = thread::spawn(move || {
            let request =
                receive_credential_worker_request(&peer, current_credentials()).expect("request");
            let response = acquire_response(&request);
            send_credential_worker_response(&peer, &request, &response, Some(sent))
                .expect("invalid FD response");
        });

        let coordinator = WorkerCoordinator::new(registry);
        assert!(matches!(
            coordinator.execute(context_id, generation, request).await,
            Err(WorkerV3Error::Ambiguous)
        ));
        worker.join().expect("worker join");
        let mut byte = [0_u8; 1];
        assert_eq!(
            (&observer).read(&mut byte).expect("observer EOF"),
            0,
            "namespace or shape rejection must consume and close the descriptor"
        );
        assert!(!alive.load(Ordering::SeqCst));
        assert!(matches!(
            coordinator.phase(context_id, generation),
            Err(WorkerV3Error::Stale)
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn response_and_fd_before_deadline_cannot_commit_after_liveness_crosses_deadline() {
        let context_id = [48; 16];
        let request = acquire(context_id, 42);
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, peer, alive) = fake_process_with_probe_delay(Duration::from_millis(70));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        registry
            .records
            .get_mut(&context_id)
            .expect("record")
            .stable_phase = StablePhase::Committed;
        let (sent, observer) = Socket::pair(Domain::UNIX, Type::STREAM.cloexec(), None::<Protocol>)
            .expect("descriptor pair");
        observer
            .set_read_timeout(Some(Duration::from_secs(1)))
            .expect("observer timeout");
        let sent: OwnedFd = sent.into();
        let response = acquire_response(&request);
        send_credential_worker_response(&peer, &request, &response, Some(sent))
            .expect("response and FD queued before execute");
        let coordinator = WorkerCoordinator::new(registry);
        let deadline = HardDeadline::after(Duration::from_millis(30)).expect("commit deadline");
        assert!(matches!(
            coordinator
                .execute_until(context_id, generation, request, deadline)
                .await,
            Err(WorkerV3Error::Deadline),
        ));
        let mut byte = [0_u8; 1];
        assert_eq!((&observer).read(&mut byte).expect("observer EOF"), 0);
        assert!(!alive.load(Ordering::SeqCst));
        assert!(matches!(
            coordinator.phase(context_id, generation),
            Err(WorkerV3Error::Stale),
        ));
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_fence_cannot_miss_a_planned_supervisor() {
        let context_id = [27; 16];
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, _peer, _alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        let coordinator = WorkerCoordinator::new(registry);
        let planned = Arc::new(std::sync::Barrier::new(2));
        let release = Arc::new(std::sync::Barrier::new(2));
        coordinator.set_registration_hook(RegistrationHook {
            planned: Arc::clone(&planned),
            release: Arc::clone(&release),
        });

        let execute_coordinator = coordinator.clone();
        let execute = tokio::spawn(async move {
            execute_coordinator
                .execute(context_id, generation, initialise(context_id, 21))
                .await
        });
        tokio::task::spawn_blocking(move || planned.wait())
            .await
            .expect("planned barrier");
        {
            let supervisors = coordinator
                .supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(supervisors.active_permits, 1);
            assert_eq!(supervisors.pending_admissions, 1);
            assert!(supervisors.handles.is_empty());
        }

        let shutdown_coordinator = coordinator.clone();
        let shutdown = tokio::spawn(async move { shutdown_coordinator.shutdown().await });
        let deadline = Instant::now() + Duration::from_secs(1);
        loop {
            let fenced = coordinator
                .supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .shutting_down;
            if fenced {
                break;
            }
            assert!(
                Instant::now() < deadline,
                "shutdown fence was not installed"
            );
            tokio::task::yield_now().await;
        }
        tokio::task::spawn_blocking(move || release.wait())
            .await
            .expect("release barrier");

        assert!(matches!(
            execute.await.expect("execute task"),
            Err(WorkerV3Error::ShuttingDown)
        ));
        assert!(shutdown.await.expect("shutdown task"));
        assert!(matches!(
            coordinator.phase(context_id, generation),
            Err(WorkerV3Error::Stale)
        ));
        {
            let supervisors = coordinator
                .supervisors
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            assert_eq!(supervisors.active_permits, 0);
            assert_eq!(supervisors.pending_admissions, 0);
            assert!(supervisors.handles.is_empty());
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn shutdown_during_call_rejects_commit_and_waits_for_supervisor() {
        let context_id = [14; 16];
        let request = initialise(context_id, 19);
        let mut registry = WorkerRegistry::new(1, 4, Duration::from_secs(10));
        let (process, peer, _alive) = fake_process(Duration::from_secs(1));
        let generation = registry
            .register(context_id, process, Duration::from_secs(5), Instant::now())
            .expect("register");
        let coordinator = WorkerCoordinator::new(registry);
        let received = Arc::new(AtomicBool::new(false));
        let worker_received = Arc::clone(&received);
        let worker = thread::spawn(move || {
            let request =
                receive_credential_worker_request(&peer, current_credentials()).expect("request");
            worker_received.store(true, Ordering::SeqCst);
            thread::sleep(Duration::from_millis(50));
            let response = initialised_response(&request, context_id);
            send_credential_worker_response(&peer, &request, &response, None).expect("response");
        });
        let task_coordinator = coordinator.clone();
        let task = tokio::spawn(async move {
            task_coordinator
                .execute(context_id, generation, request)
                .await
        });
        while !received.load(Ordering::SeqCst) {
            tokio::task::yield_now().await;
        }
        assert!(coordinator.shutdown().await);
        assert!(task.await.expect("caller task").is_err());
        worker.join().expect("worker join");
        assert!(matches!(
            coordinator.phase(context_id, generation),
            Err(WorkerV3Error::Stale)
        ));
    }
}
