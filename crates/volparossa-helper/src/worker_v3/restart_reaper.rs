//! Fixed self-exec cleanup child for one pre-dispatch restart target.

use std::{
    io,
    num::NonZeroU64,
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    process::{Child, Command, Stdio},
    thread,
    time::Duration,
};

use nix::{
    errno::Errno,
    sched::{CloneFlags, setns},
    sys::{
        prctl,
        signal::Signal,
        wait::{Id, WaitPidFlag, WaitStatus, waitid},
    },
    unistd::{getegid, geteuid, getppid},
};
use rustix::fs::{Mode, OFlags, open};
use socket2::Socket;
use thiserror::Error;
use volparossa_linux_uapi::{
    ensure_default_lifecycle_signal_dispositions, ensure_waitable_sigchld_disposition,
    install_close_range_on_exec,
};

use crate::{
    deadline::{HardDeadline, wait_for_process_pidfd_exit},
    kernel::NamespaceKernel,
    ownership_journal::{RestartNetworkPlan, StartupRestartPlan},
    worker_sandbox::{
        SandboxProofExpectation, SandboxProofRecord, WorkerKernelPins, WorkerSandboxPlan,
        begin_restart_reaper_sandbox_after_setns, current_boot_and_executable_identity,
        current_network_namespace_identity, open_child_pidfd, typed_network_namespace_identity,
    },
    worker_transport::{
        ExpectedUnixCredentials, enable_passcred_receiver, private_credential_worker_channel,
        receive_credential_fd_record_with_deadline, receive_credential_record_with_deadline,
        send_credential_fd_record_with_deadline, send_credential_record_with_deadline,
    },
};

use super::{
    HandshakeKind, HandshakeRecord, SPAWN_TIMEOUT, SandboxObservationMode, WorkerV3Error,
    decode_handshake_context_role, encode_handshake_context_role, ensure_worker_deadline,
    ipv6_forwarding, random_challenge, relay_fence, validate_child_descriptor_contract,
    validate_parent_snapshot,
};

pub(crate) const INTERNAL_RESTART_REAPER_ARGUMENT: &str = "--internal-restart-reaper-v1";
pub(crate) const INTERNAL_RESTART_REAPER_FAIL_STOP_LIVE_PROOF_ARGUMENT: &str =
    "--internal-restart-reaper-fail-stop-live-proof-v1";

const REAPER_GENERATION: u64 = 1;
const REAPER_PLAN_DOMAIN: &[u8; 32] = b"volparossa/restart-reaper/plan1\0";
const REAPER_PHASE_DOMAIN: &[u8; 32] = b"volparossa/restart-reaper/msg-v1";
const REAPER_PLAN_VERSION: u32 = 1;
const REAPER_PLAN_LENGTH: usize = 88;
const REAPER_PHASE_LENGTH: usize = 72;
const REAPER_REAP_TIMEOUT: Duration = Duration::from_secs(2);
const REAPER_DIRECT_CHILD_POLL_INTERVAL: Duration = Duration::from_millis(5);
const REAPER_FAIL_STOP_EXIT_STATUS: i32 = 70;
const REAPER_LIVE_PROOF_SETUP_FAIL_STOP_EXIT_STATUS: i32 = 71;

#[derive(Debug, Error)]
pub(crate) enum RestartReaperError {
    #[error("restart reaper input was rejected")]
    Invalid,
    #[error("restart reaper authentication failed")]
    Authentication,
    #[error("restart reaper cleanup remained incomplete")]
    CleanupIncomplete,
    #[error("restart reaper I/O failed")]
    Io(#[from] io::Error),
}

impl From<WorkerV3Error> for RestartReaperError {
    fn from(_: WorkerV3Error) -> Self {
        Self::Authentication
    }
}

/// Opaque affine proof that one exact self-exec reaper completed and was reaped.
#[must_use = "restart cleanup proof must reach the retained startup actor"]
pub(crate) struct ExactRestartReaperCleanupProof {
    plan: StartupRestartPlan,
}

impl ExactRestartReaperCleanupProof {
    pub(crate) fn matches_plan(&self, plan: StartupRestartPlan) -> bool {
        self.plan.context_id() == plan.context_id()
            && self.plan.context_role() as i32 == plan.context_role() as i32
            && self.plan.path_id() == plan.path_id()
            && self.plan.boot_id() == plan.boot_id()
            && self.plan.network_namespace_identity() == plan.network_namespace_identity()
            && self.plan.executable_identity() == plan.executable_identity()
    }

    #[cfg(test)]
    pub(crate) const fn for_test(plan: StartupRestartPlan) -> Self {
        Self { plan }
    }
}

impl std::fmt::Debug for ExactRestartReaperCleanupProof {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ExactRestartReaperCleanupProof(<redacted>)")
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct ReaperPlanRecord {
    hello_hash: [u8; 32],
    namespace_device: NonZeroU64,
    namespace_inode: NonZeroU64,
}

impl ReaperPlanRecord {
    fn new(hello: &HandshakeRecord, plan: StartupRestartPlan) -> Result<Self, RestartReaperError> {
        let (namespace_device, namespace_inode) = plan.network_namespace_identity();
        let hello_hash = *blake3::hash(&hello.encode()).as_bytes();
        if hello_hash == [0; 32] {
            return Err(RestartReaperError::Invalid);
        }
        Ok(Self {
            hello_hash,
            namespace_device,
            namespace_inode,
        })
    }

    fn encode(self) -> [u8; REAPER_PLAN_LENGTH] {
        let mut encoded = [0_u8; REAPER_PLAN_LENGTH];
        encoded[..32].copy_from_slice(REAPER_PLAN_DOMAIN);
        encoded[32..36].copy_from_slice(&REAPER_PLAN_VERSION.to_be_bytes());
        encoded[36..68].copy_from_slice(&self.hello_hash);
        encoded[68..76].copy_from_slice(&self.namespace_device.get().to_be_bytes());
        encoded[76..84].copy_from_slice(&self.namespace_inode.get().to_be_bytes());
        encoded
    }

    fn decode(encoded: &[u8], hello: &HandshakeRecord) -> Result<Self, RestartReaperError> {
        if encoded.len() != REAPER_PLAN_LENGTH
            || encoded.get(..32) != Some(REAPER_PLAN_DOMAIN.as_slice())
            || encoded.get(84..88) != Some([0_u8; 4].as_slice())
            || u32::from_be_bytes(read_array(encoded, 32)?) != REAPER_PLAN_VERSION
        {
            return Err(RestartReaperError::Invalid);
        }
        let record = Self {
            hello_hash: read_array(encoded, 36)?,
            namespace_device: NonZeroU64::new(u64::from_be_bytes(read_array(encoded, 68)?))
                .ok_or(RestartReaperError::Invalid)?,
            namespace_inode: NonZeroU64::new(u64::from_be_bytes(read_array(encoded, 76)?))
                .ok_or(RestartReaperError::Invalid)?,
        };
        if record.hello_hash != *blake3::hash(&hello.encode()).as_bytes() {
            return Err(RestartReaperError::Authentication);
        }
        Ok(record)
    }

    fn fd_binding(self) -> [u8; 32] {
        let mut hasher = blake3::Hasher::new_derive_key(
            "VOLPAROSSA restart reaper namespace descriptor binding v1",
        );
        hasher.update(&self.encode());
        *hasher.finalize().as_bytes()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
enum ReaperPhase {
    Proceed = 1,
    Complete = 2,
}

fn phase_record(
    phase: ReaperPhase,
    hello: &HandshakeRecord,
    plan: ReaperPlanRecord,
) -> [u8; REAPER_PHASE_LENGTH] {
    let mut encoded = [0_u8; REAPER_PHASE_LENGTH];
    encoded[..32].copy_from_slice(REAPER_PHASE_DOMAIN);
    encoded[32] = phase as u8;
    let mut hasher = blake3::Hasher::new_derive_key("VOLPAROSSA restart reaper phase v1");
    hasher.update(&hello.encode());
    hasher.update(&plan.encode());
    hasher.update(&[phase as u8]);
    encoded[40..72].copy_from_slice(hasher.finalize().as_bytes());
    encoded
}

fn read_array<const LENGTH: usize>(
    encoded: &[u8],
    offset: usize,
) -> Result<[u8; LENGTH], RestartReaperError> {
    encoded
        .get(offset..offset.saturating_add(LENGTH))
        .ok_or(RestartReaperError::Invalid)?
        .try_into()
        .map_err(|_| RestartReaperError::Invalid)
}

fn open_pidfd_reserve() -> io::Result<OwnedFd> {
    open(
        "/dev/null",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(super::rustix_io)
}

fn acquire_child_pidfd_with_reserve<Open>(
    reserve: &mut Option<OwnedFd>,
    deadline: HardDeadline,
    mut open_pidfd: Open,
) -> io::Result<OwnedFd>
where
    Open: FnMut() -> io::Result<OwnedFd>,
{
    loop {
        deadline.ensure_remaining()?;
        match open_pidfd() {
            Ok(pidfd) => return Ok(pidfd),
            Err(error) if error.raw_os_error() == Some(libc::EINTR) => continue,
            Err(error)
                if matches!(
                    error.raw_os_error(),
                    Some(code) if code == libc::EMFILE || code == libc::ENFILE
                ) && reserve.take().is_some() =>
            {
                // Exactly one pre-reserved descriptor makes one resource-exhaustion retry
                // possible without dropping any child owner or IPC evidence.
            }
            Err(error) => return Err(error),
        }
    }
}

/// Retain one unpinned direct child after closing its only parent IPC endpoint.
///
/// `ensure_waitable_sigchld_disposition` ran immediately before spawn and is revalidated here.
/// Consequently a still-unreaped direct `Child` prevents PID reuse without numeric-PID signaling.
/// The fixed child normally observes EOF and exits. If it is stopped, stuck, stolen by an
/// unexpected competing waiter, or the signal contract changed, process-fatal termination is the
/// only bounded outcome: returning would detach a privileged process. The fixed fail-stop uses
/// `exit_group` with status 70 directly, so it runs no cleanup/atexit handlers and emits no core. It makes no
/// exact-reap or cleanup claim. Production reaches this path only after the startup join has
/// stable-bookended the exact `Type=simple`, `RemainAfterExit=no`, `ExitType=main`,
/// no additional success statuses, `Restart=on-failure`, `RestartMode=normal`,
/// `RestartUSec=3s`, no forced-restart statuses, exact status-only
/// `RestartPreventExitStatus={70,71}`, `KillMode=control-group`, `SendSIGKILL=yes`,
/// `FinalKillSignal=SIGKILL`, finite 45-second `TimeoutStopUSec` and
/// `TimeoutStopFailureMode=terminate` manager contract. Consequently the service failure cannot
/// publish the helper socket or enter an automatic restart loop, and PID 1 owns bounded
/// whole-cgroup retirement.
fn reap_direct_child_after_channel_close_or_fail_stop(child: &mut Child) {
    if ensure_waitable_sigchld_disposition().is_err() {
        restart_reaper_fail_stop();
    }
    let Ok(deadline) = HardDeadline::after(REAPER_REAP_TIMEOUT) else {
        restart_reaper_fail_stop();
    };
    loop {
        match child.try_wait() {
            Ok(Some(_status)) => return,
            Ok(None) => {}
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(_) => restart_reaper_fail_stop(),
        }
        let Ok(remaining) = deadline.remaining() else {
            restart_reaper_fail_stop();
        };
        thread::sleep(remaining.min(REAPER_DIRECT_CHILD_POLL_INTERVAL));
    }
}

#[cold]
fn restart_reaper_fail_stop() -> ! {
    // This is deliberately the safe rustix `exit_group(2)` wrapper rather than `abort(3)` or
    // `std::process::exit`: it cannot dump core and cannot run cleanup or atexit handlers. The
    // fixed nonzero status is also the live manager test's payload-free terminal witness.
    rustix::runtime::exit_group(REAPER_FAIL_STOP_EXIT_STATUS)
}

/// Spawn, authenticate, attest and exactly reap one fixed cleanup child.
pub(crate) fn execute_single_restart_reaper(
    plan: StartupRestartPlan,
    network_namespace: BorrowedFd<'_>,
    deadline: HardDeadline,
) -> Result<ExactRestartReaperCleanupProof, RestartReaperError> {
    deadline.ensure_remaining()?;
    let (boot_id, executable_device, executable_inode) =
        current_boot_and_executable_identity().map_err(|_| RestartReaperError::Invalid)?;
    if plan.path_id() == 0
        || plan.context_id().iter().all(|byte| *byte == 0)
        || plan.boot_id() != boot_id
        || plan.executable_identity() != (executable_device, executable_inode)
    {
        return Err(RestartReaperError::Invalid);
    }
    let inherited_identity = typed_network_namespace_identity(&network_namespace)
        .map_err(|_| RestartReaperError::Invalid)?;
    let (expected_device, expected_inode) = plan.network_namespace_identity();
    if inherited_identity.parts() != (expected_device.get(), expected_inode.get()) {
        return Err(RestartReaperError::Invalid);
    }

    let parent_network_namespace =
        current_network_namespace_identity().map_err(|_| RestartReaperError::Authentication)?;
    if parent_network_namespace == inherited_identity {
        return Err(RestartReaperError::Invalid);
    }
    let observation = SandboxObservationMode::Production {
        parent_network_namespace,
    }
    .capture_parent_seccomp_baseline()?;
    let worker_account = crate::runtime::pinned_production_worker_identity()
        .map_err(|_| RestartReaperError::Authentication)?;
    let worker_identity =
        crate::worker_sandbox::WorkerIdentity::new(worker_account.uid(), worker_account.gid())
            .map_err(|_| RestartReaperError::Authentication)?;
    let challenge = random_challenge()?;
    let (parent, worker) = private_credential_worker_channel()?;
    let inherited: OwnedFd = worker.into();
    let mut command = Command::new("/proc/self/exe");
    command
        .arg(INTERNAL_RESTART_REAPER_ARGUMENT)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(inherited))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    let mut pidfd_reserve = Some(open_pidfd_reserve()?);
    ensure_default_lifecycle_signal_dispositions()
        .map_err(|_| RestartReaperError::Authentication)?;
    ensure_waitable_sigchld_disposition().map_err(|_| RestartReaperError::Authentication)?;
    install_close_range_on_exec(&mut command);
    ensure_worker_deadline(deadline)?;
    let mut child = command.spawn()?;
    let child_pid = child.id();
    let exact_pidfd = match acquire_child_pidfd_with_reserve(&mut pidfd_reserve, deadline, || {
        open_child_pidfd(&child)
    }) {
        Ok(pidfd) => pidfd,
        Err(pidfd_error) => {
            // The child has received no record and can perform no cleanup. Release every parent
            // endpoint, then keep the direct waitable Child owner until it exits or this helper
            // fails process-fatally. Returning while an unpinned privileged child exists is never
            // permitted.
            drop(pidfd_reserve.take());
            drop(parent);
            reap_direct_child_after_channel_close_or_fail_stop(&mut child);
            return Err(RestartReaperError::Io(pidfd_error));
        }
    };
    drop(pidfd_reserve.take());
    let mut pins = match WorkerKernelPins::pin_process_with_pidfd(&child, exact_pidfd) {
        Ok(pins) => pins,
        Err((_pin_error, exact_pidfd)) => {
            drop(parent);
            let reaped = reap_pidfd_exact(exact_pidfd.as_fd(), true);
            return match reaped {
                Ok(status) if wait_status_matches_child(status, child_pid) => {
                    Err(RestartReaperError::Authentication)
                }
                Ok(_) | Err(_) => Err(RestartReaperError::CleanupIncomplete),
            };
        }
    };

    let operation = parent_protocol(
        &parent,
        &mut pins,
        parent_network_namespace,
        observation,
        worker_identity,
        child_pid,
        challenge,
        plan,
        network_namespace,
        deadline,
    );
    let reaped = reap_child_exact(&mut child, &pins, operation.is_err());
    match (operation, reaped) {
        (Ok(()), Ok(WaitStatus::Exited(pid, 0)))
            if u32::try_from(pid.as_raw()).ok() == Some(child_pid) =>
        {
            Ok(ExactRestartReaperCleanupProof { plan })
        }
        (Err(error), Ok(status)) if wait_status_matches_child(status, child_pid) => Err(error),
        (_, Err(error)) => Err(error),
        _ => Err(RestartReaperError::CleanupIncomplete),
    }
}

fn wait_status_matches_child(status: WaitStatus, child_pid: u32) -> bool {
    match status {
        WaitStatus::Exited(pid, _) | WaitStatus::Signaled(pid, _, _) => {
            u32::try_from(pid.as_raw()).ok() == Some(child_pid)
        }
        _ => false,
    }
}

#[allow(clippy::too_many_arguments)]
#[expect(
    clippy::too_many_lines,
    reason = "the authenticated parent transcript is deliberately linear and phase ordered"
)]
fn parent_protocol(
    channel: &Socket,
    pins: &mut WorkerKernelPins,
    parent_network_namespace: crate::worker_sandbox::NetworkNamespaceIdentity,
    observation: super::CapturedSandboxObservation,
    worker_identity: crate::worker_sandbox::WorkerIdentity,
    child_pid: u32,
    challenge: [u8; 32],
    plan: StartupRestartPlan,
    network_namespace: BorrowedFd<'_>,
    deadline: HardDeadline,
) -> Result<(), RestartReaperError> {
    let parent_pid = std::process::id();
    let hello = HandshakeRecord {
        kind: HandshakeKind::ParentHello,
        context_id: plan.context_id(),
        context_role: plan.context_role(),
        path_id: plan.path_id(),
        generation: REAPER_GENERATION,
        challenge,
        parent_pid,
        child_pid,
        proof_hash: [0; 32],
        worker_uid: worker_identity.uid(),
        worker_gid: worker_identity.gid(),
        monotonic_deadline_ns: deadline.monotonic_expiry_nanos()?,
    };
    let plan_record = ReaperPlanRecord::new(&hello, plan)?;
    send_credential_record_with_deadline(channel, &hello.encode(), deadline)?;
    send_credential_record_with_deadline(channel, &plan_record.encode(), deadline)?;
    send_credential_fd_record_with_deadline(
        channel,
        &network_namespace,
        &plan_record.fd_binding(),
        deadline,
    )?;

    let expected_root = ExpectedUnixCredentials::new(child_pid, 0, getegid().as_raw())?;
    let ready = receive_credential_record_with_deadline(
        channel,
        HandshakeRecord::LENGTH,
        expected_root,
        deadline,
    )?;
    if HandshakeRecord::decode(&ready)? != hello.namespace_ready() {
        return Err(RestartReaperError::Authentication);
    }
    let pinned = pins
        .pin_network_namespace_before_identity_drop(
            parent_network_namespace,
            observation.parent_seccomp_baseline,
            getegid().as_raw(),
            parent_pid,
            child_pid,
        )
        .map_err(|_| RestartReaperError::Authentication)?;
    let (expected_device, expected_inode) = plan.network_namespace_identity();
    if pinned.parts() != (expected_device.get(), expected_inode.get()) {
        return Err(RestartReaperError::Authentication);
    }
    send_credential_record_with_deadline(channel, &hello.namespace_pinned().encode(), deadline)?;

    let expected_worker =
        ExpectedUnixCredentials::new(child_pid, worker_identity.uid(), worker_identity.gid())?;
    let child_reply = receive_credential_record_with_deadline(
        channel,
        HandshakeRecord::LENGTH,
        expected_worker,
        deadline,
    )?;
    if HandshakeRecord::decode(&child_reply)? != hello.child_reply() {
        return Err(RestartReaperError::Authentication);
    }
    let proof = receive_credential_record_with_deadline(
        channel,
        SandboxProofRecord::LENGTH,
        expected_worker,
        deadline,
    )?;
    let observed = pins
        .observe_and_pin(
            parent_network_namespace,
            observation.parent_seccomp_baseline,
            parent_pid,
            child_pid,
            worker_identity,
        )
        .map_err(|_| RestartReaperError::Authentication)?;
    SandboxProofExpectation::new(
        plan.context_id(),
        REAPER_GENERATION,
        challenge,
        parent_pid,
        child_pid,
        observed,
    )
    .verify_once(
        &proof,
        WorkerSandboxPlan::production(observation.parent_seccomp_baseline, worker_identity)
            .map_err(|_| RestartReaperError::Authentication)?,
    )
    .map_err(|_| RestartReaperError::Authentication)?;
    let proof_hash = *blake3::hash(&proof).as_bytes();
    let accepted = hello.sandbox_accepted(proof_hash);
    send_credential_record_with_deadline(channel, &accepted.encode(), deadline)?;
    let sandbox_ready = receive_credential_record_with_deadline(
        channel,
        HandshakeRecord::LENGTH,
        expected_worker,
        deadline,
    )?;
    if HandshakeRecord::decode(&sandbox_ready)? != accepted.sandbox_ready() {
        return Err(RestartReaperError::Authentication);
    }
    let proceed = phase_record(ReaperPhase::Proceed, &hello, plan_record);
    send_credential_record_with_deadline(channel, &proceed, deadline)?;
    let complete = receive_credential_record_with_deadline(
        channel,
        REAPER_PHASE_LENGTH,
        expected_worker,
        deadline,
    )?;
    if complete != phase_record(ReaperPhase::Complete, &hello, plan_record) {
        return Err(RestartReaperError::Authentication);
    }
    Ok(())
}

fn reap_child_exact(
    _child: &mut Child,
    pins: &WorkerKernelPins,
    terminate: bool,
) -> Result<WaitStatus, RestartReaperError> {
    reap_pidfd_exact(pins.borrowed_pidfd(), terminate)
}

fn reap_pidfd_exact(
    pidfd: BorrowedFd<'_>,
    terminate: bool,
) -> Result<WaitStatus, RestartReaperError> {
    if terminate {
        match rustix::process::pidfd_send_signal(pidfd, rustix::process::Signal::KILL) {
            Ok(()) | Err(rustix::io::Errno::SRCH) => {}
            Err(_) => return Err(RestartReaperError::CleanupIncomplete),
        }
    }
    let deadline = HardDeadline::after(REAPER_REAP_TIMEOUT)?;
    wait_for_process_pidfd_exit(&pidfd, deadline)
        .map_err(|_| RestartReaperError::CleanupIncomplete)?;
    loop {
        deadline.ensure_remaining()?;
        match waitid(Id::PIDFd(pidfd), WaitPidFlag::WEXITED) {
            Ok(status) => return Ok(status),
            Err(Errno::EINTR) => continue,
            Err(_) => return Err(RestartReaperError::CleanupIncomplete),
        }
    }
}

/// Child-side fixed entry. It accepts no command, path, name or environment input.
pub(crate) fn run_internal_restart_reaper_entry() -> bool {
    run_child().is_ok()
}

/// Exercise the production pidfd-acquisition fail-stop window under the real helper image.
///
/// This fixed root-only diagnostic accepts no path, environment or protocol input. It spawns the
/// real restart-reaper selector over the real private `SOCK_SEQPACKET` channel, pins the direct
/// child, stops that exact pidfd before sending the first handshake record, observes the stop via
/// `waitid(P_PIDFD, WSTOPPED | WNOWAIT)`, deliberately drops the pin and parent endpoint, and then
/// enters the same bounded production fallback. Success therefore terminates this process with
/// [`REAPER_FAIL_STOP_EXIT_STATUS`]; returning `false` means setup failed before that witness.
pub(crate) fn run_internal_restart_reaper_fail_stop_live_proof() -> bool {
    run_restart_reaper_fail_stop_live_proof().is_ok()
}

fn run_restart_reaper_fail_stop_live_proof() -> Result<(), RestartReaperError> {
    let parent_gid = getegid();
    if !geteuid().is_root() || parent_gid.as_raw() == 0 {
        return Err(RestartReaperError::Authentication);
    }
    ensure_default_lifecycle_signal_dispositions()
        .map_err(|_| RestartReaperError::Authentication)?;
    ensure_waitable_sigchld_disposition().map_err(|_| RestartReaperError::Authentication)?;

    let (parent, worker) = private_credential_worker_channel()?;
    let inherited: OwnedFd = worker.into();
    let mut command = Command::new("/proc/self/exe");
    command
        .arg(INTERNAL_RESTART_REAPER_ARGUMENT)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(inherited))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    install_close_range_on_exec(&mut command);
    let mut child = command.spawn()?;
    if !geteuid().is_root() || getegid() != parent_gid {
        drop(parent);
        reap_direct_child_after_channel_close_or_fail_stop(&mut child);
        return Err(RestartReaperError::Authentication);
    }

    let pidfd = match open_child_pidfd(&child) {
        Ok(pidfd) => pidfd,
        Err(error) => {
            drop(parent);
            reap_direct_child_after_channel_close_or_fail_stop(&mut child);
            return Err(RestartReaperError::Io(error));
        }
    };
    if rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::STOP).is_err() {
        return reject_fail_stop_live_proof_child(parent, &mut child, pidfd);
    }

    let Ok(expected_pid) = i32::try_from(child.id()) else {
        return reject_fail_stop_live_proof_child(parent, &mut child, pidfd);
    };
    let Ok(deadline) = HardDeadline::after(REAPER_REAP_TIMEOUT) else {
        return reject_fail_stop_live_proof_child(parent, &mut child, pidfd);
    };
    loop {
        if deadline.ensure_remaining().is_err() {
            return reject_fail_stop_live_proof_child(parent, &mut child, pidfd);
        }
        match waitid(
            Id::PIDFd(pidfd.as_fd()),
            WaitPidFlag::WSTOPPED | WaitPidFlag::WNOWAIT | WaitPidFlag::WNOHANG,
        ) {
            Ok(WaitStatus::Stopped(observed_pid, Signal::SIGSTOP))
                if observed_pid.as_raw() == expected_pid =>
            {
                break;
            }
            Ok(WaitStatus::StillAlive) => {
                let Ok(remaining) = deadline.remaining() else {
                    return reject_fail_stop_live_proof_child(parent, &mut child, pidfd);
                };
                thread::sleep(remaining.min(REAPER_DIRECT_CHILD_POLL_INTERVAL));
            }
            Ok(_) | Err(_) => {
                return reject_fail_stop_live_proof_child(parent, &mut child, pidfd);
            }
        }
    }

    // This is the deliberate live reproduction of the only unpinned-child failure window. The
    // endpoint remained open until the exact stopped state was observed, so the child cannot have
    // received even the first handshake record. Dropping both exact kernel pins before invoking
    // the production fallback proves that only systemd cgroup retirement can resolve the stopped
    // real reaper once the parent emits its fixed non-coredumping fail-stop status.
    drop(pidfd);
    drop(parent);
    reap_direct_child_after_channel_close_or_fail_stop(&mut child);
    Err(RestartReaperError::CleanupIncomplete)
}

fn reject_fail_stop_live_proof_child(
    parent: Socket,
    child: &mut Child,
    pidfd: OwnedFd,
) -> Result<(), RestartReaperError> {
    drop(parent);
    let reaped = reap_pidfd_exact(pidfd.as_fd(), true);
    drop(pidfd);
    match reaped {
        Ok(status) if wait_status_matches_child(status, child.id()) => {
            Err(RestartReaperError::Authentication)
        }
        Ok(_) | Err(_) => {
            // A diagnostic setup failure may report ordinary status 1 only after exact reap.
            // Ambiguous retirement is a distinct non-coredumping fail-stop so it cannot be
            // mistaken for the status-70 witness and cannot return with a detached child.
            rustix::runtime::exit_group(REAPER_LIVE_PROOF_SETUP_FAIL_STOP_EXIT_STATUS)
        }
    }
}

#[expect(
    clippy::too_many_lines,
    reason = "the fixed child transcript is deliberately linear and phase ordered"
)]
fn run_child() -> Result<(), RestartReaperError> {
    if !geteuid().is_root() {
        return Err(RestartReaperError::Authentication);
    }
    let (channel, initial_parent, child_pid, parent_network_namespace) =
        super::prepare_child_channel(0)?;
    enable_passcred_receiver(&channel)?;
    let parent_pid =
        u32::try_from(initial_parent).map_err(|_| RestartReaperError::Authentication)?;
    let expected_parent = ExpectedUnixCredentials::new(parent_pid, 0, getegid().as_raw())?;
    let encoded = receive_credential_record_with_deadline(
        &channel,
        HandshakeRecord::LENGTH,
        expected_parent,
        HardDeadline::after(SPAWN_TIMEOUT)?,
    )?;
    let hello = HandshakeRecord::decode(&encoded)?;
    if hello.kind != HandshakeKind::ParentHello
        || hello.parent_pid != parent_pid
        || hello.child_pid != child_pid
        || hello.generation != REAPER_GENERATION
        || hello.context_role
            != decode_handshake_context_role(encode_handshake_context_role(hello.context_role))?
    {
        return Err(RestartReaperError::Authentication);
    }
    let deadline =
        HardDeadline::from_monotonic_expiry_nanos(hello.monotonic_deadline_ns, SPAWN_TIMEOUT)?;
    let plan_encoded = receive_credential_record_with_deadline(
        &channel,
        REAPER_PLAN_LENGTH,
        expected_parent,
        deadline,
    )?;
    let plan_record = ReaperPlanRecord::decode(&plan_encoded, &hello)?;
    let namespace = receive_credential_fd_record_with_deadline(
        &channel,
        &plan_record.fd_binding(),
        expected_parent,
        deadline,
    )?;
    let before = typed_network_namespace_identity(&namespace)
        .map_err(|_| RestartReaperError::Authentication)?;
    if before.parts()
        != (
            plan_record.namespace_device.get(),
            plan_record.namespace_inode.get(),
        )
    {
        return Err(RestartReaperError::Authentication);
    }
    setns(&namespace, CloneFlags::CLONE_NEWNET).map_err(|_| RestartReaperError::Authentication)?;
    drop(namespace);
    let target_network_namespace =
        current_network_namespace_identity().map_err(|_| RestartReaperError::Authentication)?;
    if target_network_namespace != before {
        return Err(RestartReaperError::Authentication);
    }
    let prepared = begin_restart_reaper_sandbox_after_setns(
        parent_network_namespace,
        target_network_namespace,
    )
    .map_err(|_| RestartReaperError::Authentication)?;
    validate_child_descriptor_contract(&channel)?;
    send_credential_record_with_deadline(&channel, &hello.namespace_ready().encode(), deadline)?;
    let pinned = receive_credential_record_with_deadline(
        &channel,
        HandshakeRecord::LENGTH,
        expected_parent,
        deadline,
    )?;
    if HandshakeRecord::decode(&pinned)? != hello.namespace_pinned() {
        return Err(RestartReaperError::Authentication);
    }
    let worker_identity =
        crate::worker_sandbox::WorkerIdentity::new(hello.worker_uid, hello.worker_gid)
            .map_err(|_| RestartReaperError::Authentication)?;
    let snapshot = prepared
        .finish(worker_identity)
        .map_err(|_| RestartReaperError::Authentication)?;
    prctl::set_pdeathsig(Some(Signal::SIGKILL)).map_err(|_| RestartReaperError::Authentication)?;
    if prctl::get_pdeathsig().map_err(|_| RestartReaperError::Authentication)?
        != Some(Signal::SIGKILL)
    {
        return Err(RestartReaperError::Authentication);
    }
    validate_parent_snapshot(
        initial_parent,
        getppid().as_raw(),
        geteuid().as_raw(),
        worker_identity.uid(),
    )?;
    if getegid().as_raw() != worker_identity.gid() {
        return Err(RestartReaperError::Authentication);
    }
    validate_child_descriptor_contract(&channel)?;
    send_credential_record_with_deadline(&channel, &hello.child_reply().encode(), deadline)?;
    let proof = SandboxProofRecord::new(
        hello.context_id,
        REAPER_GENERATION,
        hello.challenge,
        hello.parent_pid,
        hello.child_pid,
        snapshot,
    )
    .encode();
    send_credential_record_with_deadline(&channel, &proof, deadline)?;
    let proof_hash = *blake3::hash(&proof).as_bytes();
    let accepted = hello.sandbox_accepted(proof_hash);
    let accepted_record = receive_credential_record_with_deadline(
        &channel,
        HandshakeRecord::LENGTH,
        expected_parent,
        deadline,
    )?;
    if HandshakeRecord::decode(&accepted_record)? != accepted {
        return Err(RestartReaperError::Authentication);
    }
    prctl::set_dumpable(false).map_err(|_| RestartReaperError::Authentication)?;
    if prctl::get_dumpable().map_err(|_| RestartReaperError::Authentication)? {
        return Err(RestartReaperError::Authentication);
    }
    send_credential_record_with_deadline(&channel, &accepted.sandbox_ready().encode(), deadline)?;
    let proceed = receive_credential_record_with_deadline(
        &channel,
        REAPER_PHASE_LENGTH,
        expected_parent,
        deadline,
    )?;
    if proceed != phase_record(ReaperPhase::Proceed, &hello, plan_record) {
        return Err(RestartReaperError::Authentication);
    }

    let plan = child_restart_plan(&hello)?;
    perform_cleanup(
        parent_network_namespace,
        target_network_namespace,
        plan,
        deadline,
    )?;
    send_credential_record_with_deadline(
        &channel,
        &phase_record(ReaperPhase::Complete, &hello, plan_record),
        deadline,
    )?;
    Ok(())
}

fn child_restart_plan(hello: &HandshakeRecord) -> Result<RestartNetworkPlan, RestartReaperError> {
    // The child needs only the journal-derived operational subset. Boot and executable identity
    // were independently joined by the parent before this process was spawned.
    RestartNetworkPlan::from_authenticated_reaper(
        hello.context_id,
        hello.context_role,
        hello.path_id,
    )
    .ok_or(RestartReaperError::Invalid)
}

fn perform_cleanup(
    parent_network_namespace: crate::worker_sandbox::NetworkNamespaceIdentity,
    target_network_namespace: crate::worker_sandbox::NetworkNamespaceIdentity,
    plan: RestartNetworkPlan,
    deadline: HardDeadline,
) -> Result<(), RestartReaperError> {
    let mut kernel =
        NamespaceKernel::connect(deadline).map_err(|_| RestartReaperError::CleanupIncomplete)?;
    kernel
        .prove_restart_pre_dispatch_links_absent(plan, deadline)
        .map_err(|_| RestartReaperError::CleanupIncomplete)?;
    let namespace = relay_fence::RelayFenceNamespaceAuthority::new(
        parent_network_namespace,
        target_network_namespace,
    )
    .map_err(|_| RestartReaperError::CleanupIncomplete)?;
    match plan.context_role() {
        volparossa_routing::ContextRole::Client | volparossa_routing::ContextRole::Exit => {
            prove_forwarding(ipv6_forwarding::Ipv6ForwardingState::Disabled, deadline)?;
            let pristine = relay_fence::observe_pristine_relay_fence(namespace, deadline)
                .map_err(|_| RestartReaperError::CleanupIncomplete)?;
            drop(pristine);
            prove_forwarding(ipv6_forwarding::Ipv6ForwardingState::Disabled, deadline)?;
        }
        volparossa_routing::ContextRole::Relay => {
            prove_forwarding(ipv6_forwarding::Ipv6ForwardingState::Enabled, deadline)?;
            let identity = relay_fence::RelayFenceIdentity::derive(
                plan.context_id(),
                u32::from(plan.path_id()),
            )
            .map_err(|_| RestartReaperError::CleanupIncomplete)?;
            let retired =
                relay_fence::recover_and_retire_restart_relay_fence(namespace, identity, deadline)
                    .map_err(|_| RestartReaperError::CleanupIncomplete)?;
            relay_fence::verify_restart_relay_fence_retired(&retired, deadline)
                .map_err(|_| RestartReaperError::CleanupIncomplete)?;
            prove_forwarding(ipv6_forwarding::Ipv6ForwardingState::Enabled, deadline)?;
        }
        volparossa_routing::ContextRole::Unspecified => {
            return Err(RestartReaperError::Invalid);
        }
    }
    kernel
        .prove_restart_pre_dispatch_links_absent(plan, deadline)
        .map_err(|_| RestartReaperError::CleanupIncomplete)?;
    deadline.ensure_remaining()?;
    Ok(())
}

fn prove_forwarding(
    expected: ipv6_forwarding::Ipv6ForwardingState,
    deadline: HardDeadline,
) -> Result<(), RestartReaperError> {
    for selector in [
        ipv6_forwarding::Ipv6NetconfSelector::all(),
        ipv6_forwarding::Ipv6NetconfSelector::default(),
    ] {
        if ipv6_forwarding::observe_ipv6_forwarding(selector, deadline)
            .map_err(|_| RestartReaperError::CleanupIncomplete)?
            != expected
        {
            return Err(RestartReaperError::CleanupIncomplete);
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const DIRECT_CHILD_FAIL_STOP_FIXTURE: &str =
        "VOLPAROSSA_RESTART_REAPER_DIRECT_CHILD_FAIL_STOP_FIXTURE";

    fn restart_plan(role: volparossa_routing::ContextRole, path_id: u8) -> StartupRestartPlan {
        StartupRestartPlan::for_test(
            [0x11; 16],
            role,
            path_id,
            [0x22; 16],
            (
                NonZeroU64::new(31).expect("namespace device"),
                NonZeroU64::new(37).expect("namespace inode"),
            ),
            (
                NonZeroU64::new(41).expect("executable device"),
                NonZeroU64::new(43).expect("executable inode"),
            ),
        )
    }

    fn hello(role: volparossa_routing::ContextRole, path_id: u8) -> HandshakeRecord {
        HandshakeRecord {
            kind: HandshakeKind::ParentHello,
            context_id: [0x11; 16],
            context_role: role,
            path_id,
            generation: REAPER_GENERATION,
            challenge: [0x55; 32],
            parent_pid: 101,
            child_pid: 102,
            proof_hash: [0; 32],
            worker_uid: 103,
            worker_gid: 104,
            monotonic_deadline_ns: 105,
        }
    }

    #[test]
    fn plan_record_is_canonical_hello_bound_and_fd_identity_complete() {
        let hello = hello(volparossa_routing::ContextRole::Relay, 3);
        let plan = restart_plan(volparossa_routing::ContextRole::Relay, 3);
        let record = ReaperPlanRecord::new(&hello, plan).expect("canonical plan record");
        let encoded = record.encode();
        assert_eq!(encoded.len(), REAPER_PLAN_LENGTH);
        assert!(ReaperPlanRecord::decode(&encoded, &hello).is_ok_and(|value| value == record));
        assert_eq!(&encoded[..32], REAPER_PLAN_DOMAIN);
        assert_eq!(&encoded[84..], &[0; 4]);
        assert_ne!(record.fd_binding(), [0; 32]);

        for length in 0..REAPER_PLAN_LENGTH {
            assert!(ReaperPlanRecord::decode(&encoded[..length], &hello).is_err());
        }
        for index in (0..68).chain(84..88) {
            let mut corrupt = encoded;
            corrupt[index] ^= 0x80;
            assert!(
                ReaperPlanRecord::decode(&corrupt, &hello).is_err(),
                "corruption at byte {index}"
            );
        }
        for index in 68..84 {
            let mut substituted = encoded;
            substituted[index] ^= 1;
            let substituted = ReaperPlanRecord::decode(&substituted, &hello)
                .expect("nonzero descriptor identity remains structurally valid");
            assert!(substituted != record);
            assert_ne!(substituted.fd_binding(), record.fd_binding());
        }
        let mut wrong_hello = hello;
        wrong_hello.challenge[0] ^= 1;
        assert!(matches!(
            ReaperPlanRecord::decode(&encoded, &wrong_hello),
            Err(RestartReaperError::Authentication)
        ));
    }

    #[test]
    fn phase_records_bind_challenge_plan_and_direction_with_zero_reserved_bytes() {
        let hello = hello(volparossa_routing::ContextRole::Client, 1);
        let plan = ReaperPlanRecord::new(
            &hello,
            restart_plan(volparossa_routing::ContextRole::Client, 1),
        )
        .expect("phase plan");
        let proceed = phase_record(ReaperPhase::Proceed, &hello, plan);
        let complete = phase_record(ReaperPhase::Complete, &hello, plan);
        assert_ne!(proceed, complete);
        assert_eq!(&proceed[..32], REAPER_PHASE_DOMAIN);
        assert_eq!(&proceed[33..40], &[0; 7]);

        let mut challenged = hello;
        challenged.challenge[0] ^= 1;
        assert_ne!(
            proceed,
            phase_record(ReaperPhase::Proceed, &challenged, plan)
        );
        let other_plan = ReaperPlanRecord {
            namespace_inode: NonZeroU64::new(47).expect("other inode"),
            ..plan
        };
        assert_ne!(
            proceed,
            phase_record(ReaperPhase::Proceed, &hello, other_plan)
        );
    }

    #[test]
    fn authenticated_network_plan_rejects_every_unscoped_shape() {
        for role in [
            volparossa_routing::ContextRole::Client,
            volparossa_routing::ContextRole::Relay,
            volparossa_routing::ContextRole::Exit,
        ] {
            let hello = hello(role, 8);
            let plan = child_restart_plan(&hello).expect("bounded role plan");
            assert_eq!(plan.context_id(), hello.context_id);
            assert_eq!(plan.context_role(), role);
            assert_eq!(plan.path_id(), 8);
        }
        let mut invalid = hello(volparossa_routing::ContextRole::Client, 1);
        invalid.context_id = [0; 16];
        assert!(child_restart_plan(&invalid).is_err());
        invalid.context_id = [1; 16];
        invalid.context_role = volparossa_routing::ContextRole::Unspecified;
        assert!(child_restart_plan(&invalid).is_err());
        invalid.context_role = volparossa_routing::ContextRole::Client;
        for path_id in [0, 9, u8::MAX] {
            invalid.path_id = path_id;
            assert!(child_restart_plan(&invalid).is_err());
        }
    }

    #[test]
    fn pidfd_acquisition_retries_eintr_and_one_reserved_descriptor_exhaustion() {
        for exhaustion in [libc::EMFILE, libc::ENFILE] {
            let mut reserve = Some(open_pidfd_reserve().expect("descriptor reserve"));
            let mut attempt = 0_u8;
            let acquired = acquire_child_pidfd_with_reserve(
                &mut reserve,
                HardDeadline::after(Duration::from_secs(1)).expect("pidfd deadline"),
                || {
                    attempt = attempt.saturating_add(1);
                    match attempt {
                        1 => Err(io::Error::from_raw_os_error(libc::EINTR)),
                        2 => Err(io::Error::from_raw_os_error(exhaustion)),
                        3 => open_pidfd_reserve(),
                        _ => panic!("unexpected pidfd-open attempt"),
                    }
                },
            )
            .expect("reserved retry succeeds");
            assert_eq!(attempt, 3);
            assert!(reserve.is_none());
            drop(acquired);
        }
    }

    #[test]
    fn pidfd_acquisition_consumes_reserve_only_once_and_preserves_it_for_other_errors() {
        let mut reserve = Some(open_pidfd_reserve().expect("descriptor reserve"));
        let mut attempt = 0_u8;
        let error = acquire_child_pidfd_with_reserve(
            &mut reserve,
            HardDeadline::after(Duration::from_secs(1)).expect("pidfd deadline"),
            || {
                attempt = attempt.saturating_add(1);
                Err(io::Error::from_raw_os_error(libc::EMFILE))
            },
        )
        .expect_err("second exhaustion has no reserve");
        assert_eq!(error.raw_os_error(), Some(libc::EMFILE));
        assert_eq!(attempt, 2);
        assert!(reserve.is_none());

        let mut reserve = Some(open_pidfd_reserve().expect("second descriptor reserve"));
        let error = acquire_child_pidfd_with_reserve(
            &mut reserve,
            HardDeadline::after(Duration::from_secs(1)).expect("pidfd deadline"),
            || Err(io::Error::from_raw_os_error(libc::EINVAL)),
        )
        .expect_err("unclassified pidfd error");
        assert_eq!(error.raw_os_error(), Some(libc::EINVAL));
        assert!(reserve.is_some());
    }

    #[test]
    fn direct_child_fail_stop_fixture() {
        use nix::{
            sys::{
                prctl,
                signal::{Signal, raise},
                wait::{WaitPidFlag, WaitStatus, waitpid},
            },
            unistd::{Pid, getppid},
        };

        let Some(mode) = std::env::var_os(DIRECT_CHILD_FAIL_STOP_FIXTURE) else {
            return;
        };
        match mode.to_str() {
            Some("stopped-child") => {
                let parent = getppid();
                prctl::set_pdeathsig(Some(Signal::SIGKILL)).expect("fixture parent-death signal");
                assert_eq!(getppid(), parent, "fixture parent remained exact");
                raise(Signal::SIGSTOP).expect("stop direct child fixture");
                loop {
                    thread::park();
                }
            }
            Some("fail-stop-parent") => {
                ensure_waitable_sigchld_disposition().expect("waitable fixture SIGCHLD");
                let mut child = Command::new("/proc/self/exe")
                    .arg("--exact")
                    .arg("worker_v3::restart_reaper::tests::direct_child_fail_stop_fixture")
                    .arg("--test-threads=1")
                    .env(DIRECT_CHILD_FAIL_STOP_FIXTURE, "stopped-child")
                    .stdin(Stdio::null())
                    .stdout(Stdio::null())
                    .stderr(Stdio::null())
                    .spawn()
                    .expect("spawn stopped direct child fixture");
                let pid = Pid::from_raw(i32::try_from(child.id()).expect("fixture PID"));
                let deadline =
                    HardDeadline::after(Duration::from_secs(2)).expect("stop observation deadline");
                loop {
                    match waitpid(pid, Some(WaitPidFlag::WNOHANG | WaitPidFlag::WUNTRACED)) {
                        Ok(WaitStatus::Stopped(observed, Signal::SIGSTOP)) if observed == pid => {
                            break;
                        }
                        Ok(WaitStatus::StillAlive) => {
                            let remaining = deadline
                                .remaining()
                                .expect("direct child reached stopped state");
                            thread::sleep(remaining.min(REAPER_DIRECT_CHILD_POLL_INTERVAL));
                        }
                        status => panic!("unexpected stopped-child observation: {status:?}"),
                    }
                }
                reap_direct_child_after_channel_close_or_fail_stop(&mut child);
                panic!("stopped direct child must fail process-fatally");
            }
            _ => panic!("unexpected direct-child fail-stop fixture mode"),
        }
    }

    #[test]
    fn stopped_unpinned_direct_child_is_bounded_process_fatal() {
        use std::os::unix::process::ExitStatusExt as _;

        let mut fixture = Command::new("/proc/self/exe")
            .arg("--exact")
            .arg("worker_v3::restart_reaper::tests::direct_child_fail_stop_fixture")
            .arg("--test-threads=1")
            .env(DIRECT_CHILD_FAIL_STOP_FIXTURE, "fail-stop-parent")
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .expect("spawn isolated fail-stop-parent fixture");
        let pidfd = open_child_pidfd(&fixture).expect("pin fail-stop-parent fixture");
        let deadline =
            HardDeadline::after(Duration::from_secs(6)).expect("bounded fail-stop deadline");
        if let Err(wait_error) = wait_for_process_pidfd_exit(&pidfd, deadline) {
            rustix::process::pidfd_send_signal(&pidfd, rustix::process::Signal::KILL)
                .expect("terminate timed-out fail-stop fixture");
            let cleanup_deadline = HardDeadline::after(Duration::from_secs(2))
                .expect("fail-stop fixture cleanup deadline");
            wait_for_process_pidfd_exit(&pidfd, cleanup_deadline)
                .expect("reapable timed-out fail-stop fixture");
            let _status = fixture.wait().expect("reap timed-out fail-stop fixture");
            panic!("fail-stop fixture exceeded its hard bound: {wait_error}");
        }
        let status = fixture.wait().expect("reap fail-stop-parent fixture");
        assert_eq!(status.code(), Some(REAPER_FAIL_STOP_EXIT_STATUS));
        assert_eq!(status.signal(), None);
    }

    #[test]
    fn fixed_reaper_source_has_one_fd_one_setns_bounded_fail_stop_and_terminal_proofs() {
        let source = include_str!("restart_reaper.rs");
        let production = &source[..source
            .rfind("#[cfg(test)]\nmod tests")
            .expect("test module")];
        assert!(production.contains("Command::new(\"/proc/self/exe\")"));
        assert!(production.contains(".arg(INTERNAL_RESTART_REAPER_ARGUMENT)"));
        assert!(production.contains(".env_clear()"));
        assert!(production.contains("install_close_range_on_exec(&mut command)"));
        assert!(production.contains("receive_credential_fd_record_with_deadline("));
        assert!(production.contains("setns(&namespace, CloneFlags::CLONE_NEWNET)"));
        assert!(production.contains("drop(namespace);"));
        assert!(production.contains("pidfd_send_signal("));
        assert!(production.contains("waitid(Id::PIDFd("));
        assert!(production.contains("ensure_waitable_sigchld_disposition()"));
        assert!(production.contains("open_pidfd_reserve()"));
        assert!(production.contains("child.try_wait()"));
        assert!(production.contains("rustix::runtime::exit_group(REAPER_FAIL_STOP_EXIT_STATUS)"));
        assert!(!production.contains("std::process::abort()"));
        assert!(!production.contains("child.wait()"));
        assert!(!production.contains("child.kill()"));
        assert!(!production.contains("kill(Pid"));
        assert!(!production.contains("kill(NixPid"));
        assert!(!production.contains("set_ipv6_forwarding"));
        assert!(!production.contains("write_ipv6_forwarding"));

        let reserve = production
            .find("let mut pidfd_reserve = Some(open_pidfd_reserve()?)")
            .expect("pre-spawn descriptor reserve");
        let waitable = production[reserve..]
            .find("ensure_waitable_sigchld_disposition()")
            .map(|offset| reserve + offset)
            .expect("pre-spawn waitability proof");
        let lifecycle = production[reserve..]
            .find("ensure_default_lifecycle_signal_dispositions()")
            .map(|offset| reserve + offset)
            .expect("pre-spawn lifecycle-disposition proof");
        let spawn = production[waitable..]
            .find("let mut child = command.spawn()?")
            .map(|offset| waitable + offset)
            .expect("fixed child spawn");
        let acquire = production[spawn..]
            .find("acquire_child_pidfd_with_reserve(")
            .map(|offset| spawn + offset)
            .expect("post-spawn pidfd acquisition");
        let close = production[acquire..]
            .find("drop(parent);")
            .map(|offset| acquire + offset)
            .expect("failure channel close");
        let fail_stop = production[close..]
            .find("reap_direct_child_after_channel_close_or_fail_stop(&mut child)")
            .map(|offset| close + offset)
            .expect("bounded direct-child fail-stop");
        assert!(reserve < lifecycle && lifecycle < waitable);
        assert!(waitable < spawn && spawn < acquire);
        assert!(acquire < close && close < fail_stop);

        let child_start = source.find("fn run_child()").expect("child transcript");
        let child_end = source[child_start..]
            .find("fn child_restart_plan")
            .map(|offset| child_start + offset)
            .expect("child transcript end");
        let child = &source[child_start..child_end];
        let join = child
            .find("setns(&namespace")
            .expect("single namespace join");
        let close = child.find("drop(namespace)").expect("namespace fd close");
        let sandbox = child
            .find("begin_restart_reaper_sandbox_after_setns")
            .expect("sandbox install");
        let proceed = child
            .find("ReaperPhase::Proceed")
            .expect("cleanup release challenge");
        let cleanup = child.find("perform_cleanup(").expect("fixed cleanup");
        let complete = child.find("ReaperPhase::Complete").expect("terminal reply");
        assert!(join < close && close < sandbox && sandbox < proceed);
        assert!(proceed < cleanup && cleanup < complete);
        assert_eq!(child.matches("setns(&namespace").count(), 1);
    }

    #[test]
    fn live_fail_stop_selector_stops_real_reaper_before_first_record_and_reuses_fallback() {
        let source = include_str!("restart_reaper.rs");
        let production = &source[..source
            .rfind("#[cfg(test)]\nmod tests")
            .expect("test module")];
        let start = production
            .find("fn run_restart_reaper_fail_stop_live_proof()")
            .expect("fixed live fail-stop proof");
        let end = production[start..]
            .find("fn reject_fail_stop_live_proof_child(")
            .map(|offset| start + offset)
            .expect("live proof rejection helper");
        let proof = &production[start..end];

        assert!(proof.contains("!geteuid().is_root() || parent_gid.as_raw() == 0"));
        assert!(proof.contains("ensure_default_lifecycle_signal_dispositions()"));
        assert!(proof.contains("ensure_waitable_sigchld_disposition()"));
        assert!(proof.contains("Command::new(\"/proc/self/exe\")"));
        assert!(proof.contains(".arg(INTERNAL_RESTART_REAPER_ARGUMENT)"));
        assert!(proof.contains(".env_clear()"));
        assert!(proof.contains("install_close_range_on_exec(&mut command)"));
        assert!(!proof.contains("send_credential_"));

        let spawn = proof
            .find("let mut child = command.spawn()?")
            .expect("exec-confirmed spawn");
        let pidfd = proof[spawn..]
            .find("open_child_pidfd(&child)")
            .map(|offset| spawn + offset)
            .expect("exact child pin");
        let stop = proof[pidfd..]
            .find("pidfd_send_signal(&pidfd, rustix::process::Signal::STOP)")
            .map(|offset| pidfd + offset)
            .expect("pidfd stop");
        let observation = proof[stop..]
            .find("WaitPidFlag::WSTOPPED | WaitPidFlag::WNOWAIT | WaitPidFlag::WNOHANG")
            .map(|offset| stop + offset)
            .expect("non-reaping exact stop observation");
        let drop_pin = proof[observation..]
            .find("drop(pidfd);")
            .map(|offset| observation + offset)
            .expect("deliberate exact-pin drop");
        let drop_channel = proof[drop_pin..]
            .find("drop(parent);")
            .map(|offset| drop_pin + offset)
            .expect("deliberate channel close");
        let fallback = proof[drop_channel..]
            .find("reap_direct_child_after_channel_close_or_fail_stop(&mut child)")
            .map(|offset| drop_channel + offset)
            .expect("production fail-stop reuse");
        assert!(spawn < pidfd && pidfd < stop && stop < observation);
        assert!(observation < drop_pin && drop_pin < drop_channel && drop_channel < fallback);
    }

    #[test]
    fn cleanup_source_never_deletes_links_or_disables_relay_forwarding() {
        let source = include_str!("restart_reaper.rs");
        let start = source.find("fn perform_cleanup(").expect("cleanup source");
        let end = source[start..]
            .find("fn prove_forwarding(")
            .map(|offset| start + offset)
            .expect("cleanup source end");
        let cleanup = &source[start..end];
        assert!(cleanup.contains("prove_restart_pre_dispatch_links_absent"));
        assert!(cleanup.contains("recover_and_retire_restart_relay_fence"));
        assert!(cleanup.contains("verify_restart_relay_fence_retired"));
        assert_eq!(cleanup.matches("Ipv6ForwardingState::Enabled").count(), 2);
        assert_eq!(cleanup.matches("Ipv6ForwardingState::Disabled").count(), 2);
        for forbidden in [
            "delete_wireguard",
            "remove_wireguard",
            "set_ipv6_forwarding",
            "Ipv6ForwardingState::Disabled, deadline)?;\n            let identity",
            "Command::new",
        ] {
            assert!(
                !cleanup.contains(forbidden),
                "cleanup unexpectedly contains {forbidden}"
            );
        }
    }
}
