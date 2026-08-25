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
    worker_sandbox::validate_post_exec_descriptor_allowlist,
    worker_transport::{
        CredentialedWorkerExecution, ExpectedUnixCredentials, WorkerTransportError,
        enable_passcred_receiver, private_credential_worker_channel, receive_credential_record,
        receive_credential_record_with_deadline, receive_credential_worker_request,
        receive_credential_worker_response_with_deadline, send_credential_record,
        send_credential_record_with_deadline, send_credential_worker_request_with_deadline,
        send_credential_worker_response,
    },
};
use volparossa_linux_uapi::install_close_range_on_exec;

pub(crate) const INTERNAL_WORKER_V3_ARGUMENT: &str = "--internal-worker-v3";
pub(crate) const INTERNAL_WORKER_V3_LIVE_PROOF_ARGUMENT: &str = "--internal-worker-v3-live-proof";

#[cfg(test)]
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(5);
const CHANNEL_TIMEOUT: Duration = Duration::from_secs(5);
const SPAWN_TIMEOUT: Duration = Duration::from_secs(30);
const TERMINATION_POLL_INTERVAL: Duration = Duration::from_millis(5);
const TERMINATION_TIMEOUT: Duration = Duration::from_millis(250);
const DEFAULT_MAX_WORKERS: usize = 64;
const DEFAULT_MAX_CACHE_ENTRIES: usize = 1_024;
const DEFAULT_MAX_TTL: Duration = Duration::from_secs(15 * 60);
const MAX_PROCESS_OWNERS: usize = DEFAULT_MAX_WORKERS;
const MAX_SUPERVISORS: usize = DEFAULT_MAX_WORKERS;
static WORKER_SPAWN_LOCK: Mutex<()> = Mutex::new(());

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
    let reaped = process.terminate_bounded(TERMINATION_TIMEOUT);
    let released = process.retirement_released_after_confirmed_reap() && !process.probe_alive();
    registry.abandon_generation(reservation)?;
    drop(runtime);
    if ready_and_pinned && reaped && released {
        Ok(())
    } else {
        Err(WorkerV3Error::Ambiguous)
    }
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
            kernel_pins: None,
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

struct WorkerRecord {
    generation: u64,
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
struct PendingGeneration {
    generation: u64,
    expires_at: Instant,
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
            },
        );
        Ok(GenerationReservation {
            context_id,
            generation,
            expires_at,
            linear: LinearReservationToken,
        })
    }

    fn abandon_generation(
        &mut self,
        reservation: GenerationReservation,
    ) -> Result<(), WorkerV3Error> {
        let GenerationReservation {
            context_id,
            generation,
            expires_at,
            linear: _linear,
        } = reservation;
        if self.reservations.get(&context_id)
            != Some(&PendingGeneration {
                generation,
                expires_at,
            })
        {
            return Err(WorkerV3Error::Stale);
        }
        self.reservations.remove(&context_id);
        Ok(())
    }

    fn commit_reserved(
        &mut self,
        reservation: GenerationReservation,
        process: WorkerProcess,
        now: Instant,
    ) -> Result<u64, RegistrationFailure> {
        let GenerationReservation {
            context_id,
            generation,
            expires_at,
            linear: _linear,
        } = reservation;
        let pending = PendingGeneration {
            generation,
            expires_at,
        };
        let exact_reservation = self.reservations.get(&context_id) == Some(&pending);
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
            if exact_reservation {
                self.reservations.remove(&context_id);
            }
            return Err(RegistrationFailure {
                error,
                process: Box::new(process),
            });
        }

        self.reservations.remove(&context_id);
        let alive_hint = Arc::clone(&process.alive_hint);
        self.records.insert(
            context_id,
            WorkerRecord {
                generation,
                stable_phase: StablePhase::Starting,
                in_flight: None,
                quarantined: false,
                expires_at,
                alive_hint,
                process: Some(process),
            },
        );
        Ok(generation)
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
                });
            }
        };
        if process.binding.is_none() {
            process.binding = Some(reservation.binding());
        }
        self.commit_reserved(reservation, process, now)
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

        let (phase, expires_at, liveness, channel, expected_peer, in_flight) = {
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
                process.clone_channel()?,
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
            if record.generation != token.generation
                || record.in_flight != Some(token.in_flight)
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
            if record.generation != token.generation || record.in_flight != Some(token.in_flight) {
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

    fn begin_shutdown(&mut self) -> Vec<DetachedWorker> {
        self.shutting_down = true;
        self.reservations.clear();
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
        self.reservations
            .retain(|_, reservation| now < reservation.expires_at);
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
    Retryable(DetachedWorker),
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
        let token = call.token;
        let deadline = token.in_flight.deadline;
        let io_request = request.clone();
        let result = tokio::task::spawn_blocking(move || {
            send_credential_worker_request_with_deadline(&call.channel, &io_request, deadline)?;
            let execution = receive_credential_worker_response_with_deadline(
                &call.channel,
                &io_request,
                call.expected_peer,
                deadline,
            )?;
            let worker_alive = call.liveness.probe_alive_until(deadline)?;
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
                    return ShutdownRetirement::Retryable(detached);
                }
                let mut registry = match self.registry.try_lock() {
                    Ok(registry) => registry,
                    Err(std::sync::TryLockError::Poisoned(error)) => error.into_inner(),
                    Err(std::sync::TryLockError::WouldBlock) => {
                        return ShutdownRetirement::Retryable(detached);
                    }
                };
                if ensure_worker_deadline(deadline).is_err() {
                    return ShutdownRetirement::Retryable(detached);
                }
                if detached
                    .process
                    .disarm_retirement_for_shutdown(deadline)
                    .is_err()
                {
                    return ShutdownRetirement::Retryable(detached);
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
            Ok(TerminationOutcome::TimedOut) => ShutdownRetirement::Retryable(detached),
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
        }
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

            let registry_empty = lock_worker_registry(&supervisor.registry)
                .records
                .is_empty();
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
                ShutdownRetirement::Retryable(worker) => retryable.push(worker),
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
            "process.terminate_bounded(TERMINATION_TIMEOUT)",
            "process.retirement_released_after_confirmed_reap()",
            "registry.abandon_generation(reservation)?",
        ] {
            assert!(
                proof.contains(required),
                "missing live-proof step: {required}"
            );
        }
        let production_spawn = ["spawn_worker_", "v3(reservation)"].concat();
        assert!(proof.contains(&production_spawn));
        assert!(!proof.contains("Command::new"));
        assert!(!proof.contains("spawn_with_command_fixture"));
        let pinned = proof
            .find("process.has_complete_kernel_pins()")
            .expect("pin observation");
        let reaped = proof
            .find("process.terminate_bounded(TERMINATION_TIMEOUT)")
            .expect("confirmed reap");
        let released = proof
            .find("process.retirement_released_after_confirmed_reap()")
            .expect("retirement release");
        assert!(pinned < reaped && reaped < released);
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
        let loop_entry = bootstrap
            .rfind("child_loop(&channel")
            .expect("child-loop entry");
        assert!(proof < accepted && accepted < ready && ready < loop_entry);
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
            send_credential_worker_response(&peer, &request, &response, Some(&sent))
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
        send_credential_worker_response(&peer, &request, &response, Some(&sent))
            .expect("response and FD queued before execute");
        drop(sent);
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
