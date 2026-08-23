use std::{fs, io, os::unix::fs::MetadataExt, process::ExitCode, time::Duration};

use nix::unistd::{getegid, geteuid, getppid};
use rand_core::{OsRng, RngCore};
use thiserror::Error;
use volparossa_test_support::{
    LaunchContext, LifecycleEofDisposition, NetnsLifecycleError, OuterLifecycleState, RunId,
};

use crate::{
    namespace::NamespaceSnapshot,
    process::{
        FixedChild, inherited_lifecycle_channel_from_stderr,
        inherited_provisioning_channel_from_stdin,
    },
};

/// Conventional process result for a deliberately blocked acceptance prerequisite.
pub const BLOCKED_EXIT_CODE: u8 = 77;
/// Process result for an internal runner or invariant failure.
pub const INTERNAL_ERROR_EXIT_CODE: u8 = 70;

const BOOTSTRAP_RECORD_TIMEOUT: Duration = Duration::from_secs(2);

/// Honest outcome of the current non-mutating supervisor slice.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum LifecycleOutcome {
    /// The fixed child accepted launch provisioning, no `GO` was emitted, and it was reaped.
    BlockedBeforeIsolation,
}

/// Failure of the fixed process supervisor or one of its invariants.
#[derive(Debug, Error)]
pub enum RunnerError {
    /// A namespace identity could not be captured.
    #[error("failed to capture process namespace identity: {0}")]
    Namespace(#[source] io::Error),
    /// The operating-system CSPRNG could not create the run identifier.
    #[error("failed to generate lifecycle run identifier")]
    Random,
    /// The strict lifecycle or provisioning protocol rejected local state.
    #[error("lifecycle protocol rejected supervisor state: {0}")]
    Protocol(#[from] NetnsLifecycleError),
    /// The fixed child could not be launched or retired exactly.
    #[error("fixed child process operation failed: {0}")]
    Process(#[source] io::Error),
    /// The inherited private channel failed.
    #[error("fixed lifecycle channel failed: {0}")]
    Channel(#[source] io::Error),
    /// A lifecycle record appeared even though isolated bootstrap is not implemented yet.
    #[error("inner child emitted a lifecycle record before isolated bootstrap existed")]
    UnexpectedLifecycleRecord,
    /// The fixed child did not return the sole blocked-before-isolation exit status.
    #[error("inner child returned an unexpected process status")]
    UnexpectedChildStatus,
    /// The supervisor process moved namespaces during a non-mutating run.
    #[error("supervisor namespace identities changed during a non-mutating run")]
    SupervisorNamespaceChanged,
    /// The non-isolated child did not remain in the provisioned parent namespaces.
    #[error("non-isolated child namespace identity did not match launch provisioning")]
    ChildNamespaceChanged,
    /// The inherited channel or process metadata did not identify the exact fixed outer runner.
    #[error("internal child could not authenticate the fixed outer runner")]
    ParentAuthentication,
    /// More than one transport-provisioning record was supplied.
    #[error("internal child received duplicate launch provisioning")]
    DuplicateLaunchContext,
}

/// Run the sole fixed, non-mutating supervisor slice.
///
/// A random launch context is sent to an exact self-reexecuted child through an
/// unnamed inherited seqpacket channel. Because isolated bootstrap is not part
/// of this slice, the child emits no lifecycle frame and exits with status 77.
/// The outer state therefore records EOF before `GO`, reaps the exact child,
/// and verifies that its own namespace identities remained unchanged.
///
/// # Errors
///
/// Returns an error for every launch, IPC, protocol, process-status, reaping,
/// randomness, or namespace-identity discrepancy.
pub fn run_fixed_lifecycle() -> Result<LifecycleOutcome, RunnerError> {
    let before = NamespaceSnapshot::capture().map_err(RunnerError::Namespace)?;
    let run_id = random_run_id()?;
    let context = LaunchContext::new(run_id.clone(), before.network, before.mount, before.pid)?;
    let mut outer = OuterLifecycleState::new(run_id, before.network, before.mount, before.pid);
    let child = FixedChild::spawn().map_err(RunnerError::Process)?;
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

    match child
        .lifecycle_channel()
        .map_err(RunnerError::Channel)?
        .receive()
    {
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {}
        Err(error) => {
            child.terminate_and_reap().map_err(RunnerError::Process)?;
            return Err(RunnerError::Channel(error));
        }
        Ok(_) => {
            child.terminate_and_reap().map_err(RunnerError::Process)?;
            return Err(RunnerError::UnexpectedLifecycleRecord);
        }
    }
    if outer.observe_inner_eof()? != LifecycleEofDisposition::NoMutationAuthorized {
        child.terminate_and_reap().map_err(RunnerError::Process)?;
        return Err(RunnerError::UnexpectedLifecycleRecord);
    }
    let status = child.wait_and_reap().map_err(RunnerError::Process)?;
    if status.code() != Some(i32::from(BLOCKED_EXIT_CODE)) {
        return Err(RunnerError::UnexpectedChildStatus);
    }
    let after = NamespaceSnapshot::capture().map_err(RunnerError::Namespace)?;
    if after != before {
        return Err(RunnerError::SupervisorNamespaceChanged);
    }
    Ok(LifecycleOutcome::BlockedBeforeIsolation)
}

/// Run the exact hidden child entry selected and authenticated by the fixed process owner.
///
/// The child validates one launch context and proves that it is still in the
/// three provisioned namespaces. It emits no lifecycle frame, authorizes no
/// mutation, and returns status 77 because real isolated bootstrap is absent.
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
    let lifecycle_channel =
        inherited_lifecycle_channel_from_stderr().map_err(RunnerError::Channel)?;
    authenticate_outer_parent(&provisioning_channel, &lifecycle_channel)?;
    let current = NamespaceSnapshot::capture().map_err(RunnerError::Namespace)?;
    let _context =
        receive_launch_context(&provisioning_channel, current, BOOTSTRAP_RECORD_TIMEOUT)?;
    drop(lifecycle_channel);
    Ok(())
}

fn authenticate_outer_parent(
    provisioning_channel: &crate::ipc::LifecycleChannel,
    lifecycle_channel: &crate::ipc::LifecycleChannel,
) -> Result<(), RunnerError> {
    let parent = getppid();
    if parent.as_raw() <= 1 {
        return Err(RunnerError::ParentAuthentication);
    }
    let provisioning_credentials = provisioning_channel
        .peer_credentials()
        .map_err(RunnerError::Channel)?;
    let lifecycle_credentials = lifecycle_channel
        .peer_credentials()
        .map_err(RunnerError::Channel)?;
    if provisioning_credentials.pid() != parent.as_raw()
        || provisioning_credentials.uid() != geteuid().as_raw()
        || provisioning_credentials.gid() != getegid().as_raw()
        || lifecycle_credentials.pid() != parent.as_raw()
        || lifecycle_credentials.uid() != geteuid().as_raw()
        || lifecycle_credentials.gid() != getegid().as_raw()
    {
        return Err(RunnerError::ParentAuthentication);
    }
    let self_executable = fs::metadata("/proc/self/exe").map_err(RunnerError::Namespace)?;
    let parent_executable = fs::metadata(format!("/proc/{parent}/exe"))
        .map_err(|_| RunnerError::ParentAuthentication)?;
    if self_executable.dev() != parent_executable.dev()
        || self_executable.ino() != parent_executable.ino()
    {
        return Err(RunnerError::ParentAuthentication);
    }
    let command_line = fs::read(format!("/proc/{parent}/cmdline"))
        .map_err(|_| RunnerError::ParentAuthentication)?;
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
    Ok(())
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
}
