use std::{
    env, fs, io,
    os::unix::{fs::MetadataExt, process::ExitStatusExt},
    path::Path,
    process::ExitCode,
    time::Duration,
};

use nix::{
    sys::{
        prctl::{get_pdeathsig, set_pdeathsig},
        signal::Signal,
    },
    unistd::{getegid, geteuid, getpid, getppid, getresgid, getresuid},
};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use volparossa_test_support::{
    LaunchContext, LifecycleEofDisposition, NetnsLifecycleError, OuterLifecycleState, RunId,
};

use crate::{
    control::{BootstrapControlError, LauncherBootstrapControl, OuterBootstrapControl},
    isolation::{
        IsolationAttempt, LauncherIsolation, create_launcher_namespaces, has_exact_single_task,
    },
    namespace::NamespaceSnapshot,
    pid1::{LauncherPidOneControl, PidOneControl, PidOneControlError, PidOneProvision},
    process::{
        FixedChild, FixedPidOne, INTERNAL_PID_ONE_ARGUMENT, inherited_control_channel_from_stdout,
        inherited_lifecycle_channel_from_stderr, inherited_pid_one_bootstrap_channel_from_stdin,
        inherited_pid_one_lifecycle_channel_from_stdout, inherited_provisioning_channel_from_stdin,
    },
};

/// Conventional process result for a deliberately blocked acceptance prerequisite.
pub const BLOCKED_EXIT_CODE: u8 = 77;
/// Process result for an internal runner or invariant failure.
pub const INTERNAL_ERROR_EXIT_CODE: u8 = 70;

const BOOTSTRAP_RECORD_TIMEOUT: Duration = Duration::from_secs(2);

/// Honest outcome of the current pre-`GO` isolation supervisor slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleOutcome {
    /// The fixed child accepted provisioning, but kernel policy denied a safe bootstrap proof.
    BlockedBeforeIsolation,
    /// Anonymous namespaces exist, but kernel policy denied required outer proof or ID mapping.
    BlockedAfterIsolation,
    /// Exact mappings exist, but kernel policy hid the required outer PID-1 proof.
    BlockedAtPidOneProof,
    /// A real self-reexecuted PID 1 was independently proven and reaped without `GO`.
    BlockedAfterPidOneProof,
}

/// Failure of the fixed process supervisor or one of its invariants.
#[derive(Debug, Error)]
pub enum RunnerError {
    /// A namespace identity could not be captured.
    #[error("failed to capture process namespace identity: {0}")]
    Namespace(#[source] io::Error),
    /// Namespace creation violated a fixed child-side invariant.
    #[error("isolated launcher namespace creation failed: {0}")]
    IsolationCreation(#[source] io::Error),
    /// Child-side mapping verification violated a fixed invariant.
    #[error("isolated launcher mapping verification failed: {0}")]
    Isolation(#[source] io::Error),
    /// Outer kernel observation or mapping installation violated a fixed invariant.
    #[error("isolated launcher kernel proof failed: {0}")]
    KernelProof(#[source] io::Error),
    /// The operating-system CSPRNG could not create the run identifier.
    #[error("failed to generate lifecycle run identifier")]
    Random,
    /// The strict lifecycle or provisioning protocol rejected local state.
    #[error("lifecycle protocol rejected supervisor state: {0}")]
    Protocol(#[from] NetnsLifecycleError),
    /// The strict internal namespace-mapping control exchange was rejected.
    #[error("bootstrap control rejected supervisor state")]
    Control,
    /// The private launcher-to-PID-1 control exchange was rejected.
    #[error("PID-1 control rejected supervisor state")]
    PidOneControl,
    /// The fixed child could not be launched or retired exactly.
    #[error("fixed child process operation failed: {0}")]
    Process(#[source] io::Error),
    /// The inherited private channel failed.
    #[error("fixed lifecycle channel failed: {0}")]
    Channel(#[source] io::Error),
    /// A lifecycle record appeared before the complete bootstrap attestation existed.
    #[error("inner child emitted a lifecycle record before BOOTSTRAP_READY existed")]
    UnexpectedLifecycleRecord,
    /// The fixed child did not return the sole blocked-before-isolation exit status.
    #[error("inner child returned unexpected process status code={code:?} signal={signal:?}")]
    UnexpectedChildStatus {
        /// Conventional child exit code, when it exited normally.
        code: Option<i32>,
        /// Terminating signal, when the kernel killed the child.
        signal: Option<i32>,
    },
    /// The supervisor process moved namespaces during a non-mutating run.
    #[error("supervisor namespace identities changed during a non-mutating run")]
    SupervisorNamespaceChanged,
    /// The child did not begin in the exact provisioned parent namespaces.
    #[error("child namespace identity did not match launch provisioning")]
    ChildNamespaceChanged,
    /// The inherited channel or process metadata did not identify the exact fixed outer runner.
    #[error("internal child could not authenticate the fixed outer runner")]
    ParentAuthentication,
    /// Kernel policy hid parent metadata required before any namespace operation may begin.
    #[error("kernel policy denied the fixed outer-runner authentication proof")]
    ParentAuthenticationUnavailable,
    /// More than one transport-provisioning record was supplied.
    #[error("internal child received duplicate launch provisioning")]
    DuplicateLaunchContext,
}

impl From<BootstrapControlError> for RunnerError {
    fn from(_: BootstrapControlError) -> Self {
        Self::Control
    }
}

impl From<PidOneControlError> for RunnerError {
    fn from(_: PidOneControlError) -> Self {
        Self::PidOneControl
    }
}

/// Run the sole fixed pre-`GO` isolation supervisor slice.
///
/// A random launch context is sent to an exact self-reexecuted child through an
/// unnamed inherited seqpacket channel. The child creates only anonymous user,
/// mount, network, and pending child PID namespaces, then blocks until the outer
/// installs and verifies one exact UID/GID mapping extent. The launcher makes
/// exactly one second self-reexec, whose PID-1 placement is independently pinned
/// and proven by the outer before it is reaped. No lifecycle frame or `GO` is
/// emitted. The outer verifies that its own namespace identities remain unchanged.
/// The caller must enter with exactly one task; child creation also requires the
/// default `SIGCHLD` disposition without `SA_NOCLDWAIT`.
///
/// # Errors
///
/// Returns an error for every launch, IPC, protocol, process-status, reaping,
/// randomness, initial task-count, signal-disposition, or namespace-identity
/// discrepancy.
pub fn run_fixed_lifecycle() -> Result<LifecycleOutcome, RunnerError> {
    if !has_exact_single_task().map_err(RunnerError::Process)? {
        return Err(RunnerError::Process(io::Error::new(
            io::ErrorKind::InvalidInput,
            "fixed supervisor must start with exactly one task",
        )));
    }
    let before = NamespaceSnapshot::capture().map_err(RunnerError::Namespace)?;
    let run_id = random_run_id()?;
    let context = LaunchContext::new(run_id.clone(), before.network, before.mount, before.pid)?;
    let mut outer =
        OuterLifecycleState::new(run_id.clone(), before.network, before.mount, before.pid);
    let mut bootstrap = OuterBootstrapControl::new(run_id);
    let mut child = FixedChild::spawn().map_err(RunnerError::Process)?;
    child
        .control_channel()
        .map_err(RunnerError::Channel)?
        .set_read_timeout(BOOTSTRAP_RECORD_TIMEOUT)
        .map_err(RunnerError::Channel)?;
    child
        .lifecycle_channel()
        .map_err(RunnerError::Channel)?
        .set_read_timeout(BOOTSTRAP_RECORD_TIMEOUT)
        .map_err(RunnerError::Channel)?;
    child
        .provisioning_channel()
        .map_err(RunnerError::Channel)?
        .send(context.encode()?.as_bytes())
        .map_err(RunnerError::Channel)?;
    child
        .provisioning_channel()
        .map_err(RunnerError::Channel)?
        .finish_sending()
        .map_err(RunnerError::Channel)?;

    let namespaces_created = match child
        .control_channel()
        .map_err(RunnerError::Channel)?
        .receive()
    {
        Ok(record) => record,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            return finish_blocked_run(
                child,
                &mut outer,
                before,
                LifecycleOutcome::BlockedBeforeIsolation,
            );
        }
        Err(error) => return Err(RunnerError::Channel(error)),
    };
    bootstrap.accept_namespaces_created(&namespaces_created)?;
    if !complete_mapping_barrier(&mut child, before, &mut bootstrap)? {
        return finish_blocked_run(
            child,
            &mut outer,
            before,
            LifecycleOutcome::BlockedAfterIsolation,
        );
    }
    if !complete_pid_one_barrier(&mut child, &mut bootstrap)? {
        return finish_blocked_run(
            child,
            &mut outer,
            before,
            LifecycleOutcome::BlockedAtPidOneProof,
        );
    }
    finish_blocked_run(
        child,
        &mut outer,
        before,
        LifecycleOutcome::BlockedAfterPidOneProof,
    )
}

fn complete_mapping_barrier(
    child: &mut FixedChild,
    before: NamespaceSnapshot,
    bootstrap: &mut OuterBootstrapControl,
) -> Result<bool, RunnerError> {
    let outer_user_id = geteuid().as_raw();
    let outer_group_id = getegid().as_raw();
    if let Err(error) = child
        .kernel_pins_mut()
        .map_err(RunnerError::KernelProof)?
        .pin_launcher_before_pid_one(before, std::process::id())
    {
        if !is_outer_proof_unavailable(&error) {
            return Err(RunnerError::KernelProof(error));
        }
        finish_bootstrap_control(child)?;
        return Ok(false);
    }
    if let Err(error) = child
        .kernel_pins_mut()
        .map_err(RunnerError::KernelProof)?
        .write_single_extent_mappings(outer_user_id, outer_group_id)
    {
        if !error.is_policy_denial() {
            return Err(RunnerError::KernelProof(error.into_io()));
        }
        finish_bootstrap_control(child)?;
        return Ok(false);
    }
    let mappings_installed = bootstrap.mappings_installed()?;
    child
        .control_channel()
        .map_err(RunnerError::Channel)?
        .send(mappings_installed.as_bytes())
        .map_err(RunnerError::Channel)?;
    let mappings_verified = child
        .control_channel()
        .map_err(RunnerError::Channel)?
        .receive()
        .map_err(RunnerError::Channel)?;
    bootstrap.accept_mappings_verified(&mappings_verified)?;
    if let Err(error) = child
        .kernel_pins_mut()
        .map_err(RunnerError::KernelProof)?
        .verify_single_extent_mappings(outer_user_id, outer_group_id)
    {
        if !is_outer_proof_unavailable(&error) {
            return Err(RunnerError::KernelProof(error));
        }
        finish_bootstrap_control(child)?;
        return Ok(false);
    }
    Ok(true)
}

fn complete_pid_one_barrier(
    child: &mut FixedChild,
    bootstrap: &mut OuterBootstrapControl,
) -> Result<bool, RunnerError> {
    let outer_user_id = geteuid().as_raw();
    let outer_group_id = getegid().as_raw();
    let spawned = child
        .control_channel()
        .map_err(RunnerError::Channel)?
        .receive()
        .map_err(RunnerError::Channel)?;
    let pid = bootstrap.accept_pid1_spawned(&spawned)?;
    let pid_one = match child
        .kernel_pins_mut()
        .map_err(RunnerError::KernelProof)?
        .pin_pid_one(
            pid,
            INTERNAL_PID_ONE_ARGUMENT,
            outer_user_id,
            outer_group_id,
        ) {
        Ok(pid_one) => pid_one,
        Err(error) if is_outer_proof_unavailable(&error) => {
            child
                .lifecycle_channel()
                .map_err(RunnerError::Channel)?
                .finish_sending()
                .map_err(RunnerError::Channel)?;
            finish_bootstrap_control(child)?;
            return Ok(false);
        }
        Err(error) => return Err(RunnerError::KernelProof(error)),
    };
    let pinned = bootstrap.pid1_pinned(pid)?;
    child
        .control_channel()
        .map_err(RunnerError::Channel)?
        .send(pinned.as_bytes())
        .map_err(RunnerError::Channel)?;
    child
        .lifecycle_channel()
        .map_err(RunnerError::Channel)?
        .finish_sending()
        .map_err(RunnerError::Channel)?;
    let reaped = child
        .control_channel()
        .map_err(RunnerError::Channel)?
        .receive()
        .map_err(RunnerError::Channel)?;
    bootstrap.accept_pid1_reaped(&reaped)?;
    child
        .kernel_pins_mut()
        .map_err(RunnerError::KernelProof)?
        .verify_pid_one_reaped(&pid_one, outer_user_id, outer_group_id)
        .map_err(RunnerError::KernelProof)?;
    finish_bootstrap_control(child)?;
    Ok(true)
}

fn finish_bootstrap_control(child: &FixedChild) -> Result<(), RunnerError> {
    child
        .control_channel()
        .map_err(RunnerError::Channel)?
        .finish_sending()
        .map_err(RunnerError::Channel)?;
    match child
        .control_channel()
        .map_err(RunnerError::Channel)?
        .receive()
    {
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(error) => return Err(RunnerError::Channel(error)),
        Ok(_) => return Err(RunnerError::Control),
    }
    Ok(())
}

fn is_outer_proof_unavailable(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
}

fn finish_blocked_run(
    child: FixedChild,
    outer: &mut OuterLifecycleState,
    before: NamespaceSnapshot,
    outcome: LifecycleOutcome,
) -> Result<LifecycleOutcome, RunnerError> {
    match child
        .lifecycle_channel()
        .map_err(RunnerError::Channel)?
        .receive()
    {
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(error) => {
            return Err(RunnerError::Channel(error));
        }
        Ok(_) => {
            return Err(RunnerError::UnexpectedLifecycleRecord);
        }
    }
    if outer.observe_inner_eof()? != LifecycleEofDisposition::NoMutationAuthorized {
        return Err(RunnerError::UnexpectedLifecycleRecord);
    }
    let status = child.wait_and_reap().map_err(RunnerError::Process)?;
    if status.code() != Some(i32::from(BLOCKED_EXIT_CODE)) {
        return Err(RunnerError::UnexpectedChildStatus {
            code: status.code(),
            signal: status.signal(),
        });
    }
    let after = NamespaceSnapshot::capture().map_err(RunnerError::Namespace)?;
    if after != before {
        return Err(RunnerError::SupervisorNamespaceChanged);
    }
    Ok(outcome)
}

fn errno_runner(error: nix::errno::Errno) -> RunnerError {
    RunnerError::Process(io::Error::from_raw_os_error(error as i32))
}

/// Run the exact hidden child entry selected and authenticated by the fixed process owner.
///
/// The child validates one launch context, creates anonymous user, mount,
/// network, and pending child PID namespaces, and blocks on an outer-owned ID
/// mapping barrier. It then owns exactly one fixed self-reexecuted PID 1 until
/// the outer proves and retires it. It emits no lifecycle frame or `GO`.
#[doc(hidden)]
#[must_use]
pub fn run_internal_child() -> ExitCode {
    match internal_child() {
        Ok(()) => ExitCode::from(BLOCKED_EXIT_CODE),
        Err(_) => ExitCode::from(INTERNAL_ERROR_EXIT_CODE),
    }
}

fn internal_child() -> Result<(), RunnerError> {
    let provisioning_channel =
        inherited_provisioning_channel_from_stdin().map_err(RunnerError::Channel)?;
    let control_channel = inherited_control_channel_from_stdout().map_err(RunnerError::Channel)?;
    let lifecycle_channel =
        inherited_lifecycle_channel_from_stderr().map_err(RunnerError::Channel)?;
    let parent = match authenticate_outer_parent(
        &provisioning_channel,
        &control_channel,
        &lifecycle_channel,
    ) {
        Ok(parent) => parent,
        Err(RunnerError::ParentAuthenticationUnavailable) => {
            drop(lifecycle_channel);
            return Ok(());
        }
        Err(error) => return Err(error),
    };
    let current = NamespaceSnapshot::capture().map_err(RunnerError::Namespace)?;
    let context = receive_launch_context(&provisioning_channel, current, BOOTSTRAP_RECORD_TIMEOUT)?;
    control_channel
        .set_read_timeout(BOOTSTRAP_RECORD_TIMEOUT)
        .map_err(RunnerError::Channel)?;
    let isolation = match create_launcher_namespaces().map_err(RunnerError::IsolationCreation)? {
        IsolationAttempt::Created(isolation) => isolation,
        IsolationAttempt::Unavailable => {
            drop(lifecycle_channel);
            return Ok(());
        }
    };
    let mut bootstrap = LauncherBootstrapControl::new(context.run_id().clone());
    control_channel
        .send(bootstrap.namespaces_created()?.as_bytes())
        .map_err(RunnerError::Channel)?;
    let mappings_installed = match control_channel.receive() {
        Ok(record) => record,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            drop(lifecycle_channel);
            return Ok(());
        }
        Err(error) => return Err(RunnerError::Channel(error)),
    };
    bootstrap.accept_mappings_installed(&mappings_installed)?;
    isolation
        .verify_installed_mappings()
        .map_err(RunnerError::Isolation)?;
    if get_pdeathsig().map_err(errno_runner)? != Some(Signal::SIGKILL) || getppid() != parent {
        return Err(RunnerError::ParentAuthentication);
    }
    control_channel
        .send(bootstrap.mappings_verified()?.as_bytes())
        .map_err(RunnerError::Channel)?;
    complete_internal_pid_one(
        lifecycle_channel,
        &control_channel,
        &mut bootstrap,
        &context,
        &isolation,
    )
}

fn complete_internal_pid_one(
    lifecycle_channel: crate::ipc::LifecycleChannel,
    control_channel: &crate::ipc::LifecycleChannel,
    bootstrap: &mut LauncherBootstrapControl,
    context: &LaunchContext,
    isolation: &LauncherIsolation,
) -> Result<(), RunnerError> {
    // Linux intentionally leaves `pid_for_children` unopenable after
    // `unshare(CLONE_NEWPID)` until the first child exists. Create the exact
    // blocked self-reexec only after both sides have pinned and verified the
    // mapping-stage launcher; then capture the complete namespace set.
    let pid_one = FixedPidOne::spawn(lifecycle_channel).map_err(RunnerError::Process)?;
    pid_one
        .bootstrap_channel()
        .map_err(RunnerError::Channel)?
        .set_read_timeout(BOOTSTRAP_RECORD_TIMEOUT)
        .map_err(RunnerError::Channel)?;
    let isolated = NamespaceSnapshot::capture().map_err(RunnerError::Namespace)?;
    let provision = PidOneProvision::new(
        context.run_id().clone(),
        isolated.user,
        isolated.network,
        isolated.mount,
        isolated.pid_for_children,
        isolation.outer_user_id(),
        isolation.outer_group_id(),
    )?;
    let mut pid_one_control = LauncherPidOneControl::new(provision);
    pid_one
        .bootstrap_channel()
        .map_err(RunnerError::Channel)?
        .send(pid_one_control.provision()?.as_bytes())
        .map_err(RunnerError::Channel)?;
    let parent_death_armed = pid_one
        .bootstrap_channel()
        .map_err(RunnerError::Channel)?
        .receive()
        .map_err(RunnerError::Channel)?;
    pid_one_control.accept_parent_death_armed(&parent_death_armed)?;
    pid_one
        .bootstrap_channel()
        .map_err(RunnerError::Channel)?
        .send(pid_one_control.parent_alive()?.as_bytes())
        .map_err(RunnerError::Channel)?;
    let executed = pid_one
        .bootstrap_channel()
        .map_err(RunnerError::Channel)?
        .receive()
        .map_err(RunnerError::Channel)?;
    pid_one_control.accept_executed(&executed)?;
    let pid = pid_one.id().map_err(RunnerError::Process)?;
    control_channel
        .send(bootstrap.pid1_spawned(pid)?.as_bytes())
        .map_err(RunnerError::Channel)?;
    let pinned = match control_channel.receive() {
        Ok(record) => record,
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
            finish_pid_one(pid_one, &mut pid_one_control)?;
            return Ok(());
        }
        Err(error) => return Err(RunnerError::Channel(error)),
    };
    bootstrap.accept_pid1_pinned(&pinned)?;
    let status = finish_pid_one(pid_one, &mut pid_one_control)?;
    control_channel
        .send(bootstrap.pid1_reaped(pid, status)?.as_bytes())
        .map_err(RunnerError::Channel)?;
    match control_channel.receive() {
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(error) => return Err(RunnerError::Channel(error)),
        Ok(_) => return Err(RunnerError::Control),
    }
    Ok(())
}

fn finish_pid_one(
    pid_one: FixedPidOne,
    control: &mut LauncherPidOneControl,
) -> Result<i32, RunnerError> {
    pid_one
        .bootstrap_channel()
        .map_err(RunnerError::Channel)?
        .send(control.expect_lifecycle_eof()?.as_bytes())
        .map_err(RunnerError::Channel)?;
    let lifecycle_eof = pid_one
        .bootstrap_channel()
        .map_err(RunnerError::Channel)?
        .receive()
        .map_err(RunnerError::Channel)?;
    control.accept_lifecycle_eof(&lifecycle_eof)?;
    let status = pid_one.wait_and_reap().map_err(RunnerError::Process)?;
    if status.code() != Some(i32::from(BLOCKED_EXIT_CODE)) {
        return Err(RunnerError::UnexpectedChildStatus {
            code: status.code(),
            signal: status.signal(),
        });
    }
    control.complete()?;
    Ok(i32::from(BLOCKED_EXIT_CODE))
}

/// Run the exact hidden second self-reexec which must be PID 1.
///
/// The entry verifies its fixed inherited channels, PID-1 placement, mapped
/// credentials, namespace membership, empty environment, root cwd, and armed
/// parent-death signal. It reports only over the launcher-private control
/// channel and proves lifecycle EOF without accepting any frame.
#[doc(hidden)]
#[must_use]
pub fn run_internal_pid_one() -> ExitCode {
    match internal_pid_one() {
        Ok(()) => ExitCode::from(BLOCKED_EXIT_CODE),
        Err(_) => ExitCode::from(INTERNAL_ERROR_EXIT_CODE),
    }
}

fn internal_pid_one() -> Result<(), RunnerError> {
    let bootstrap_channel =
        inherited_pid_one_bootstrap_channel_from_stdin().map_err(RunnerError::Channel)?;
    let lifecycle_channel =
        inherited_pid_one_lifecycle_channel_from_stdout().map_err(RunnerError::Channel)?;
    set_pdeathsig(Signal::SIGKILL).map_err(errno_runner)?;
    bootstrap_channel
        .set_read_timeout(BOOTSTRAP_RECORD_TIMEOUT)
        .map_err(RunnerError::Channel)?;
    lifecycle_channel
        .set_read_timeout(BOOTSTRAP_RECORD_TIMEOUT)
        .map_err(RunnerError::Channel)?;
    let mut control = PidOneControl::new();
    let provision_record = bootstrap_channel.receive().map_err(RunnerError::Channel)?;
    let provision = control.accept_provision(&provision_record)?.clone();
    verify_pid_one_runtime(&provision)?;
    bootstrap_channel
        .send(control.parent_death_armed()?.as_bytes())
        .map_err(RunnerError::Channel)?;
    let parent_alive = bootstrap_channel.receive().map_err(RunnerError::Channel)?;
    control.accept_parent_alive(&parent_alive)?;
    verify_pid_one_runtime(&provision)?;
    bootstrap_channel
        .send(control.executed()?.as_bytes())
        .map_err(RunnerError::Channel)?;
    let expect_eof = bootstrap_channel.receive().map_err(RunnerError::Channel)?;
    control.accept_expect_lifecycle_eof(&expect_eof)?;
    match lifecycle_channel.receive() {
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(error) => return Err(RunnerError::Channel(error)),
        Ok(_) => return Err(RunnerError::UnexpectedLifecycleRecord),
    }
    bootstrap_channel
        .send(control.lifecycle_eof()?.as_bytes())
        .map_err(RunnerError::Channel)?;
    Ok(())
}

fn verify_pid_one_runtime(provision: &PidOneProvision) -> Result<(), RunnerError> {
    let snapshot = NamespaceSnapshot::capture().map_err(RunnerError::Namespace)?;
    let user_ids = getresuid().map_err(errno_runner)?;
    let group_ids = getresgid().map_err(errno_runner)?;
    crate::evidence::verify_current_single_extent_mappings(
        provision.outer_user_id(),
        provision.outer_group_id(),
    )
    .map_err(RunnerError::Isolation)?;
    if getpid().as_raw() != 1
        || getppid().as_raw() != 0
        || get_pdeathsig().map_err(errno_runner)? != Some(Signal::SIGKILL)
        || user_ids.real.as_raw() != 0
        || user_ids.effective.as_raw() != 0
        || user_ids.saved.as_raw() != 0
        || group_ids.real.as_raw() != 0
        || group_ids.effective.as_raw() != 0
        || group_ids.saved.as_raw() != 0
        || snapshot.user != provision.user_namespace()
        || snapshot.network != provision.network_namespace()
        || snapshot.mount != provision.mount_namespace()
        || snapshot.pid != provision.pid_namespace()
        || snapshot.pid_for_children != provision.pid_namespace()
        || !has_exact_single_task().map_err(RunnerError::Isolation)?
        || env::vars_os().next().is_some()
        || env::current_dir().map_err(RunnerError::Isolation)? != Path::new("/")
    {
        return Err(RunnerError::Isolation(io::Error::new(
            io::ErrorKind::InvalidData,
            "PID-1 runtime did not match its fixed isolated provision",
        )));
    }
    Ok(())
}

fn authenticate_outer_parent(
    provisioning_channel: &crate::ipc::LifecycleChannel,
    control_channel: &crate::ipc::LifecycleChannel,
    lifecycle_channel: &crate::ipc::LifecycleChannel,
) -> Result<nix::unistd::Pid, RunnerError> {
    let parent = getppid();
    if parent.as_raw() <= 1 {
        return Err(RunnerError::ParentAuthentication);
    }
    set_pdeathsig(Signal::SIGKILL).map_err(errno_runner)?;
    if get_pdeathsig().map_err(errno_runner)? != Some(Signal::SIGKILL) || getppid() != parent {
        return Err(RunnerError::ParentAuthentication);
    }
    let provisioning_credentials = provisioning_channel
        .peer_credentials()
        .map_err(RunnerError::Channel)?;
    let control_credentials = control_channel
        .peer_credentials()
        .map_err(RunnerError::Channel)?;
    let lifecycle_credentials = lifecycle_channel
        .peer_credentials()
        .map_err(RunnerError::Channel)?;
    if provisioning_credentials.pid() != parent.as_raw()
        || provisioning_credentials.uid() != geteuid().as_raw()
        || provisioning_credentials.gid() != getegid().as_raw()
        || control_credentials.pid() != parent.as_raw()
        || control_credentials.uid() != geteuid().as_raw()
        || control_credentials.gid() != getegid().as_raw()
        || lifecycle_credentials.pid() != parent.as_raw()
        || lifecycle_credentials.uid() != geteuid().as_raw()
        || lifecycle_credentials.gid() != getegid().as_raw()
    {
        return Err(RunnerError::ParentAuthentication);
    }
    let self_executable = fs::metadata("/proc/self/exe").map_err(RunnerError::Namespace)?;
    let parent_executable = fs::metadata(format!("/proc/{parent}/exe")).map_err(|error| {
        if is_parent_proof_unavailable(&error) {
            RunnerError::ParentAuthenticationUnavailable
        } else {
            RunnerError::ParentAuthentication
        }
    })?;
    if self_executable.dev() != parent_executable.dev()
        || self_executable.ino() != parent_executable.ino()
    {
        return Err(RunnerError::ParentAuthentication);
    }
    let command_line = fs::read(format!("/proc/{parent}/cmdline")).map_err(|error| {
        if is_parent_proof_unavailable(&error) {
            RunnerError::ParentAuthenticationUnavailable
        } else {
            RunnerError::ParentAuthentication
        }
    })?;
    let mut arguments = command_line.split(|byte| *byte == 0);
    let executable_argument = arguments.next();
    if executable_argument.is_none_or(<[u8]>::is_empty)
        || arguments.next() != Some(b"--run")
        || arguments.next() != Some(b"")
        || arguments.next().is_some()
        || getppid() != parent
    {
        return Err(RunnerError::ParentAuthentication);
    }
    Ok(parent)
}

fn receive_launch_context(
    channel: &crate::ipc::LifecycleChannel,
    current: NamespaceSnapshot,
    timeout: Duration,
) -> Result<LaunchContext, RunnerError> {
    channel
        .set_read_timeout(timeout)
        .map_err(RunnerError::Channel)?;
    let record = channel.receive().map_err(RunnerError::Channel)?;
    let context = LaunchContext::parse(&record)?;
    if current.network != context.host_network_namespace()
        || current.mount != context.host_mount_namespace()
        || current.pid != context.host_pid_namespace()
    {
        return Err(RunnerError::ChildNamespaceChanged);
    }
    match channel.receive() {
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(context),
        Err(error) => Err(RunnerError::Channel(error)),
        Ok(_) => Err(RunnerError::DuplicateLaunchContext),
    }
}

fn is_parent_proof_unavailable(error: &io::Error) -> bool {
    error.kind() == io::ErrorKind::PermissionDenied
}

fn random_run_id() -> Result<RunId, RunnerError> {
    let mut bytes = [0_u8; 16];
    OsRng
        .try_fill_bytes(&mut bytes)
        .map_err(|_| RunnerError::Random)?;
    run_id_from_bytes(bytes)
}

fn run_id_from_bytes(bytes: [u8; 16]) -> Result<RunId, RunnerError> {
    RunId::parse(&format!("{:032x}", u128::from_be_bytes(bytes))).map_err(RunnerError::from)
}

#[cfg(test)]
mod tests {
    use std::os::fd::AsRawFd;

    use nix::sys::socket::{Shutdown, shutdown};
    use volparossa_linux_uapi::send_seqpacket_without_fd;
    use volparossa_test_support::{MAX_LIFECYCLE_FRAME_BYTES, NamespaceIdentity};

    use super::*;

    fn context(snapshot: NamespaceSnapshot) -> LaunchContext {
        LaunchContext::new(
            RunId::parse("0123456789abcdef0123456789abcdef").expect("run ID"),
            snapshot.network,
            snapshot.mount,
            snapshot.pid,
        )
        .expect("distinct namespace identities")
    }

    #[test]
    fn run_id_encoding_is_deterministic_and_random_output_is_canonical() {
        assert_eq!(
            run_id_from_bytes([0_u8; 16]).expect("zero run ID").as_str(),
            "00000000000000000000000000000000"
        );
        assert_eq!(
            run_id_from_bytes([0xff_u8; 16])
                .expect("maximum run ID")
                .as_str(),
            "ffffffffffffffffffffffffffffffff"
        );
        let generated = random_run_id().expect("random run ID");
        assert_eq!(generated.as_str().len(), 32);
        assert!(
            generated
                .as_str()
                .bytes()
                .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        );
    }

    #[test]
    fn public_supervisor_rejects_a_multitask_caller_before_spawn() {
        let (ready_sender, ready_receiver) = std::sync::mpsc::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let guard = std::thread::spawn(move || {
            ready_sender.send(()).expect("announce guard task");
            release_receiver.recv().expect("release guard task");
        });
        ready_receiver.recv().expect("wait for guard task");

        let result = run_fixed_lifecycle();
        release_sender.send(()).expect("release guard task");
        guard.join().expect("join guard task");

        assert!(matches!(
            result,
            Err(RunnerError::Process(error))
                if error.kind() == io::ErrorKind::InvalidInput
                    && error.to_string() == "fixed supervisor must start with exactly one task"
        ));
    }

    #[test]
    fn only_permission_denial_makes_parent_proof_unavailable() {
        assert!(is_parent_proof_unavailable(
            &io::ErrorKind::PermissionDenied.into()
        ));
        for kind in [
            io::ErrorKind::InvalidData,
            io::ErrorKind::NotFound,
            io::ErrorKind::OutOfMemory,
            io::ErrorKind::UnexpectedEof,
        ] {
            assert!(!is_parent_proof_unavailable(&kind.into()));
        }
    }

    #[test]
    fn launch_provisioning_accepts_exactly_one_matching_record_then_eof() {
        let snapshot = NamespaceSnapshot::capture().expect("namespace snapshot");
        let expected = context(snapshot);
        let (receiver, sender) = crate::ipc::LifecycleChannel::pair().expect("channel");
        sender
            .send(expected.encode().expect("context encode").as_bytes())
            .expect("context send");
        sender.finish_sending().expect("finish provisioning");

        let observed = receive_launch_context(&receiver, snapshot, Duration::from_millis(20))
            .expect("launch context");
        assert_eq!(observed, expected);
    }

    #[test]
    fn launch_provisioning_rejects_missing_malformed_duplicate_and_wrong_identity() {
        let snapshot = NamespaceSnapshot::capture().expect("namespace snapshot");

        let (missing_receiver, missing_sender) =
            crate::ipc::LifecycleChannel::pair().expect("missing channel");
        missing_sender
            .finish_sending()
            .expect("finish missing provisioning");
        assert!(matches!(
            receive_launch_context(
                &missing_receiver,
                snapshot,
                Duration::from_millis(20)
            ),
            Err(RunnerError::Channel(error)) if error.kind() == io::ErrorKind::UnexpectedEof
        ));

        let (malformed_receiver, malformed_sender) =
            crate::ipc::LifecycleChannel::pair().expect("malformed channel");
        malformed_sender
            .send(b"NOT_A_LAUNCH_CONTEXT\n")
            .expect("malformed send");
        malformed_sender
            .finish_sending()
            .expect("finish malformed provisioning");
        assert!(matches!(
            receive_launch_context(&malformed_receiver, snapshot, Duration::from_millis(20)),
            Err(RunnerError::Protocol(_))
        ));

        let encoded = context(snapshot).encode().expect("context encode");
        let (duplicate_receiver, duplicate_sender) =
            crate::ipc::LifecycleChannel::pair().expect("duplicate channel");
        duplicate_sender
            .send(encoded.as_bytes())
            .expect("first context send");
        duplicate_sender
            .send(encoded.as_bytes())
            .expect("duplicate context send");
        duplicate_sender
            .finish_sending()
            .expect("finish duplicate provisioning");
        assert!(matches!(
            receive_launch_context(&duplicate_receiver, snapshot, Duration::from_millis(20)),
            Err(RunnerError::DuplicateLaunchContext)
        ));

        let wrong_network = NamespaceIdentity::new(u64::MAX, snapshot.network.inode())
            .expect("wrong network identity");
        let wrong = LaunchContext::new(
            RunId::parse("fedcba9876543210fedcba9876543210").expect("run ID"),
            wrong_network,
            snapshot.mount,
            snapshot.pid,
        )
        .expect("distinct wrong identity");
        let (wrong_receiver, wrong_sender) =
            crate::ipc::LifecycleChannel::pair().expect("wrong-identity channel");
        wrong_sender
            .send(wrong.encode().expect("wrong context encode").as_bytes())
            .expect("wrong context send");
        wrong_sender
            .finish_sending()
            .expect("finish wrong provisioning");
        assert!(matches!(
            receive_launch_context(&wrong_receiver, snapshot, Duration::from_millis(20)),
            Err(RunnerError::ChildNamespaceChanged)
        ));
    }

    #[test]
    fn launch_provisioning_times_out_and_rejects_kernel_truncation() {
        let snapshot = NamespaceSnapshot::capture().expect("namespace snapshot");
        let (timeout_receiver, _timeout_sender) =
            crate::ipc::LifecycleChannel::pair().expect("timeout channel");
        assert!(matches!(
            receive_launch_context(
                &timeout_receiver,
                snapshot,
                Duration::from_millis(5)
            ),
            Err(RunnerError::Channel(error))
                if matches!(error.kind(), io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut)
        ));

        let (truncated_receiver, truncated_sender) =
            crate::ipc::LifecycleChannel::pair().expect("truncated channel");
        let descriptor = truncated_sender.into_owned_fd();
        send_seqpacket_without_fd(&descriptor, &vec![b'x'; MAX_LIFECYCLE_FRAME_BYTES + 1])
            .expect("oversized kernel record");
        shutdown(descriptor.as_raw_fd(), Shutdown::Write).expect("finish oversized provisioning");
        assert!(matches!(
            receive_launch_context(
                &truncated_receiver,
                snapshot,
                Duration::from_millis(20)
            ),
            Err(RunnerError::Channel(error)) if error.kind() == io::ErrorKind::InvalidData
        ));
    }

    #[test]
    fn only_permission_denial_makes_outer_kernel_proof_unavailable() {
        assert!(is_outer_proof_unavailable(&io::Error::from(
            io::ErrorKind::PermissionDenied
        )));
        for kind in [
            io::ErrorKind::InvalidData,
            io::ErrorKind::NotFound,
            io::ErrorKind::Unsupported,
            io::ErrorKind::OutOfMemory,
        ] {
            assert!(!is_outer_proof_unavailable(&io::Error::from(kind)));
        }
    }
}
