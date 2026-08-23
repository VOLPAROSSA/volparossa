use std::{
    io,
    os::fd::{AsFd, OwnedFd},
    process::{Child, Command, ExitStatus, Stdio},
    sync::{
        OnceLock,
        atomic::{AtomicBool, Ordering},
        mpsc::{self, Sender},
    },
    thread,
    time::{Duration, Instant},
};

use nix::unistd::{close, getppid};
use rustix::io::fcntl_dupfd_cloexec;
use volparossa_linux_uapi::install_close_range_on_exec;

use crate::ipc::LifecycleChannel;

/// Exact private selector used when the runner re-executes its own image.
///
/// A future executable entry point must accept this value only as a solitary
/// internal invocation and must authenticate the inherited channel before work.
#[doc(hidden)]
pub const INTERNAL_CHILD_ARGUMENT: &str = "--internal-netns-lifecycle-child-v1";

const MINIMUM_CHILD_CHANNEL_DESCRIPTOR: i32 = 3;
const TERMINATION_TIMEOUT: Duration = Duration::from_secs(1);
const TERMINATION_POLL_INTERVAL: Duration = Duration::from_millis(5);

static CHILD_SLOT_IN_USE: AtomicBool = AtomicBool::new(false);
static REAPER: OnceLock<Sender<Retirement>> = OnceLock::new();
#[cfg(test)]
const TEST_CHILD_ENVIRONMENT: &str = "VOLPAROSSA_NETNS_RUNNER_TEST_CHILD_V1";
#[cfg(test)]
const TEST_CHILD_ENVIRONMENT_VALUE: &str = "fixed";

/// Affine owner of the fixed re-executed child and its private channel.
///
/// At most one such child can exist in a process. Dropping this value closes
/// the channel, sends `SIGKILL` to the exact unreaped child when necessary, and
/// waits for a fixed bound. A child that cannot be reaped within that bound is
/// moved, together with the sole spawn permit, to a dedicated exact-child
/// reaper; it is never detached by dropping its [`Child`] handle.
pub(crate) struct FixedChild {
    child: Option<Child>,
    provisioning_channel: Option<LifecycleChannel>,
    lifecycle_channel: Option<LifecycleChannel>,
    permit: Option<SpawnPermit>,
}

impl FixedChild {
    /// Re-execute `/proc/self/exe` with the sole fixed internal selector.
    ///
    /// The command receives the unnamed provisioning socket as stdin and the
    /// separate unnamed lifecycle socket as stderr. Its environment is empty,
    /// cwd is `/`, and stdout is `/dev/null`.
    /// The audited close-range hook is installed last so every unrelated
    /// descriptor at 3 or above becomes close-on-exec before this child starts.
    ///
    /// # Errors
    ///
    /// Returns an error when a child is already owned, reaper initialization or
    /// channel creation fails, or the fixed self-exec cannot be spawned.
    pub(crate) fn spawn() -> io::Result<Self> {
        spawn_with_fixed_arguments(&[INTERNAL_CHILD_ARGUMENT], None)
    }

    /// Kernel PID of the exact still-owned child.
    #[must_use]
    #[cfg(test)]
    pub(crate) fn id(&self) -> u32 {
        self.child.as_ref().map_or(0, Child::id)
    }

    /// Borrow the one-record transport-provisioning endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error after retirement has begun and the endpoint was closed.
    pub(crate) fn provisioning_channel(&self) -> io::Result<&LifecycleChannel> {
        self.provisioning_channel
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "child channel is closed"))
    }

    /// Borrow the private five-frame lifecycle endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error after retirement has begun and the endpoint was closed.
    pub(crate) fn lifecycle_channel(&self) -> io::Result<&LifecycleChannel> {
        self.lifecycle_channel
            .as_ref()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "child channel is closed"))
    }

    /// Close IPC, terminate the exact child if it remains alive, and reap it.
    ///
    /// This operation consumes the owner. If the kernel does not make the child
    /// waitable within the fixed one-second bound, ownership is transferred to
    /// the background exact-child reaper and a timeout is returned.
    ///
    /// # Errors
    ///
    /// Returns a process error, or `TimedOut` after safe ownership transfer.
    pub(crate) fn terminate_and_reap(mut self) -> io::Result<ExitStatus> {
        self.retire()
    }

    /// Wait for a normally exiting child and reap it without first signalling it.
    ///
    /// This operation consumes the owner and closes its IPC endpoint. A child
    /// which has not exited within the fixed one-second bound is terminated and
    /// reaped through the same exact-child retirement path; `TimedOut` then
    /// distinguishes that forced retirement from a normal completion.
    ///
    /// # Errors
    ///
    /// Returns a wait error, or `TimedOut` after bounded forced retirement.
    pub(crate) fn wait_and_reap(mut self) -> io::Result<ExitStatus> {
        let (mut child, permit) = self.take_retirement()?;
        let Some(deadline) = Instant::now().checked_add(TERMINATION_TIMEOUT) else {
            defer_retirement(child, permit);
            return Err(io::Error::other("fixed child wait deadline overflow"));
        };
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    drop(permit);
                    return Ok(status);
                }
                Ok(None) => {}
                Err(error) => {
                    defer_retirement(child, permit);
                    return Err(error);
                }
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return retire_after_natural_wait_timeout(child, permit);
            };
            if remaining.is_zero() {
                return retire_after_natural_wait_timeout(child, permit);
            }
            thread::sleep(remaining.min(TERMINATION_POLL_INTERVAL));
        }
    }

    fn retire(&mut self) -> io::Result<ExitStatus> {
        let (child, permit) = self.take_retirement()?;
        terminate_owned_child(child, permit)
    }

    fn take_retirement(&mut self) -> io::Result<(Child, SpawnPermit)> {
        drop(self.provisioning_channel.take());
        drop(self.lifecycle_channel.take());
        let Some(child) = self.child.take() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fixed child was already retired",
            ));
        };
        let permit = self.permit.take().unwrap_or_else(|| {
            std::process::abort();
        });
        Ok((child, permit))
    }

    #[cfg(test)]
    fn spawn_fixture() -> io::Result<Self> {
        spawn_with_fixed_arguments(
            &[
                "--exact",
                "process::tests::fixed_child_fixture_entry",
                "--test-threads=1",
                "--nocapture",
            ],
            Some((TEST_CHILD_ENVIRONMENT, TEST_CHILD_ENVIRONMENT_VALUE)),
        )
    }

    #[cfg(test)]
    fn spawn_hanging_fixture() -> io::Result<Self> {
        spawn_with_fixed_arguments(
            &[
                "--exact",
                "process::tests::fixed_hanging_child_fixture_entry",
                "--test-threads=1",
                "--nocapture",
            ],
            Some((TEST_CHILD_ENVIRONMENT, TEST_CHILD_ENVIRONMENT_VALUE)),
        )
    }
}

impl Drop for FixedChild {
    fn drop(&mut self) {
        if self.child.is_some() && self.retire().is_err() && self.child.is_some() {
            std::process::abort();
        }
    }
}

struct SpawnPermit;

impl SpawnPermit {
    fn acquire() -> io::Result<Self> {
        CHILD_SLOT_IN_USE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| io::Error::new(io::ErrorKind::WouldBlock, "fixed child already exists"))?;
        Ok(Self)
    }
}

impl Drop for SpawnPermit {
    fn drop(&mut self) {
        if CHILD_SLOT_IN_USE
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            std::process::abort();
        }
    }
}

struct Retirement {
    child: Child,
    _permit: SpawnPermit,
}

fn terminate_owned_child(mut child: Child, permit: SpawnPermit) -> io::Result<ExitStatus> {
    match child.try_wait() {
        Ok(Some(status)) => {
            drop(permit);
            return Ok(status);
        }
        Ok(None) => {}
        Err(error) => {
            defer_retirement(child, permit);
            return Err(error);
        }
    }
    let kill_error = child.kill().err();
    let Some(deadline) = Instant::now().checked_add(TERMINATION_TIMEOUT) else {
        defer_retirement(child, permit);
        return Err(io::Error::other(
            "fixed child termination deadline overflow",
        ));
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                drop(permit);
                return Ok(status);
            }
            Ok(None) => {}
            Err(error) => {
                defer_retirement(child, permit);
                return Err(error);
            }
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            defer_retirement(child, permit);
            return Err(kill_error.unwrap_or_else(termination_timeout));
        };
        if remaining.is_zero() {
            defer_retirement(child, permit);
            return Err(kill_error.unwrap_or_else(termination_timeout));
        }
        thread::sleep(remaining.min(TERMINATION_POLL_INTERVAL));
    }
}

fn retire_after_natural_wait_timeout(child: Child, permit: SpawnPermit) -> io::Result<ExitStatus> {
    match terminate_owned_child(child, permit) {
        Ok(_) => Err(io::Error::new(
            io::ErrorKind::TimedOut,
            "fixed child did not exit normally before forced retirement",
        )),
        Err(error) => Err(error),
    }
}

fn termination_timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "fixed child termination timed out; exact reaping continues",
    )
}

fn spawn_with_fixed_arguments(
    arguments: &[&str],
    retained_environment: Option<(&str, &str)>,
) -> io::Result<FixedChild> {
    let _ = reaper()?;
    let permit = SpawnPermit::acquire()?;
    let (provisioning_parent, provisioning_child) = LifecycleChannel::pair()?;
    let (lifecycle_parent, lifecycle_child) = LifecycleChannel::pair()?;
    let inherited_provisioning: OwnedFd = provisioning_child.into_owned_fd();
    let inherited_lifecycle: OwnedFd = lifecycle_child.into_owned_fd();
    let mut command = Command::new("/proc/self/exe");
    command
        .args(arguments)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(inherited_provisioning))
        .stdout(Stdio::null())
        .stderr(Stdio::from(inherited_lifecycle));
    if let Some((name, value)) = retained_environment {
        command.env(name, value);
    }
    // This must remain the final user-installed pre-exec hook.
    install_close_range_on_exec(&mut command);
    let child = command.spawn()?;
    Ok(FixedChild {
        child: Some(child),
        provisioning_channel: Some(provisioning_parent),
        lifecycle_channel: Some(lifecycle_parent),
        permit: Some(permit),
    })
}

fn reaper() -> io::Result<&'static Sender<Retirement>> {
    if let Some(sender) = REAPER.get() {
        return Ok(sender);
    }
    let (sender, receiver) = mpsc::channel::<Retirement>();
    thread::Builder::new()
        .name("volparossa-netns-child-reaper".to_owned())
        .spawn(move || {
            for mut retirement in receiver {
                loop {
                    let _ = retirement.child.kill();
                    match retirement.child.wait() {
                        Ok(_) => break,
                        Err(error)
                            if error.raw_os_error() == Some(nix::errno::Errno::ECHILD as i32) =>
                        {
                            break;
                        }
                        Err(_) => thread::sleep(TERMINATION_POLL_INTERVAL),
                    }
                }
            }
        })?;
    match REAPER.set(sender) {
        Ok(()) => Ok(REAPER.get().unwrap_or_else(|| std::process::abort())),
        Err(_) => Ok(REAPER.get().unwrap_or_else(|| std::process::abort())),
    }
}

fn defer_retirement(child: Child, permit: SpawnPermit) {
    if reaper()
        .and_then(|sender| {
            sender
                .send(Retirement {
                    child,
                    _permit: permit,
                })
                .map_err(|_| io::Error::other("fixed child reaper stopped"))
        })
        .is_err()
    {
        std::process::abort();
    }
}

/// Duplicate the inherited provisioning socket from stdin to a private descriptor.
///
/// This is process substrate for the future internal child entry. It records the
/// parent PID on both sides of the duplication and rejects a parent change. No
/// namespace, mount, or network operation is performed.
///
/// # Errors
///
/// Returns an error for a parent race, close failure, or substituted/nonconforming
/// stdin channel.
#[doc(hidden)]
pub(crate) fn inherited_provisioning_channel_from_stdin() -> io::Result<LifecycleChannel> {
    inherited_channel_from_standard_descriptor(io::stdin(), 0)
}

/// Duplicate the inherited lifecycle socket from stderr to a private descriptor.
///
/// # Errors
///
/// Returns an error for a parent race, close failure, or substituted/nonconforming
/// stderr channel.
pub(crate) fn inherited_lifecycle_channel_from_stderr() -> io::Result<LifecycleChannel> {
    inherited_channel_from_standard_descriptor(io::stderr(), 2)
}

fn inherited_channel_from_standard_descriptor<S: AsFd>(
    descriptor: S,
    standard_descriptor: i32,
) -> io::Result<LifecycleChannel> {
    let initial_parent = getppid();
    if initial_parent.as_raw() <= 1 {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "internal child has no live parent",
        ));
    }
    let inherited = fcntl_dupfd_cloexec(descriptor, MINIMUM_CHILD_CHANNEL_DESCRIPTOR)
        .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
    if getppid() != initial_parent {
        return Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "internal child parent or channel descriptor changed",
        ));
    }
    close(standard_descriptor).map_err(errno_io)?;
    LifecycleChannel::from_owned_fd(inherited)
}

fn errno_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        ffi::OsStr,
        fs,
        os::fd::AsRawFd,
        sync::{Mutex, MutexGuard},
    };

    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use nix::{
        errno::Errno,
        sys::wait::{WaitPidFlag, waitpid},
        unistd::Pid,
    };
    use socket2::{Domain, Protocol, Socket, Type};

    use super::*;

    const READY: &[u8] = b"VOLPAROSSA_NETNS_PROCESS_TEST_READY_V1";
    const STOP: &[u8] = b"VOLPAROSSA_NETNS_PROCESS_TEST_STOP_V1";
    const FINISHED: &[u8] = b"VOLPAROSSA_NETNS_PROCESS_TEST_FINISHED_V1";
    static PROCESS_TEST_LOCK: Mutex<()> = Mutex::new(());

    fn process_test_lock() -> MutexGuard<'static, ()> {
        PROCESS_TEST_LOCK
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    fn is_spawned_fixture() -> bool {
        env::var_os(TEST_CHILD_ENVIRONMENT).as_deref()
            == Some(OsStr::new(TEST_CHILD_ENVIRONMENT_VALUE))
    }

    fn assert_reaped(child_pid: u32) {
        let child_pid = i32::try_from(child_pid).expect("Linux child PID fits i32");
        assert_eq!(
            waitpid(Pid::from_raw(child_pid), Some(WaitPidFlag::WNOHANG)),
            Err(Errno::ECHILD)
        );
    }

    #[test]
    fn fixed_child_fixture_entry() {
        if !is_spawned_fixture() {
            return;
        }
        let channel = inherited_lifecycle_channel_from_stderr().expect("inherited channel");
        channel.send(READY).expect("fixture ready");
        assert_eq!(channel.receive().expect("fixture stop"), STOP);
        channel.send(FINISHED).expect("fixture finished");
    }

    #[test]
    fn fixed_hanging_child_fixture_entry() {
        if !is_spawned_fixture() {
            return;
        }
        let channel = inherited_lifecycle_channel_from_stderr().expect("inherited channel");
        channel.send(READY).expect("fixture ready");
        loop {
            thread::park();
        }
    }

    #[test]
    fn fixed_spawn_fences_inheritable_fd_and_reaps_exact_child() {
        let _test_guard = process_test_lock();
        let (sentinel, _sentinel_peer) =
            Socket::pair(Domain::UNIX, Type::SEQPACKET.cloexec(), None::<Protocol>)
                .expect("sentinel pair");
        fcntl(&sentinel, FcntlArg::F_SETFD(FdFlag::empty()))
            .expect("make sentinel deliberately inheritable");
        let sentinel_target = fs::read_link(format!("/proc/self/fd/{}", sentinel.as_raw_fd()))
            .expect("sentinel link");

        let child = FixedChild::spawn_fixture().expect("spawn fixture");
        assert_ne!(child.id(), 0);
        assert_eq!(
            child
                .lifecycle_channel()
                .expect("channel")
                .receive()
                .expect("ready"),
            READY
        );

        let child_fd_directory = format!("/proc/{}/fd", child.id());
        let leaked = fs::read_dir(child_fd_directory)
            .expect("child descriptor directory")
            .filter_map(Result::ok)
            .filter_map(|entry| fs::read_link(entry.path()).ok())
            .any(|target| target == sentinel_target);
        assert!(
            !leaked,
            "close-range fence must remove inheritable sentinel"
        );

        child
            .lifecycle_channel()
            .expect("channel")
            .send(STOP)
            .expect("stop");
        assert_eq!(
            child
                .lifecycle_channel()
                .expect("channel")
                .receive()
                .expect("finished"),
            FINISHED
        );
        let status = child.wait_and_reap().expect("reap fixture");
        assert!(status.success());
    }

    #[test]
    fn drop_terminates_and_releases_the_single_child_slot() {
        let _test_guard = process_test_lock();
        let first = FixedChild::spawn_fixture().expect("first fixture");
        assert_eq!(
            first
                .lifecycle_channel()
                .expect("channel")
                .receive()
                .expect("ready"),
            READY
        );
        assert_eq!(
            FixedChild::spawn_fixture()
                .err()
                .expect("second child must fail")
                .kind(),
            io::ErrorKind::WouldBlock
        );
        let first_pid = first.id();
        drop(first);
        assert_reaped(first_pid);

        let second = FixedChild::spawn_fixture().expect("slot released");
        assert_eq!(
            second
                .lifecycle_channel()
                .expect("channel")
                .receive()
                .expect("ready"),
            READY
        );
        drop(second);
    }

    #[test]
    fn natural_wait_timeout_forces_kill_reap_and_releases_permit() {
        let _test_guard = process_test_lock();
        let child = FixedChild::spawn_hanging_fixture().expect("hanging fixture");
        assert_eq!(
            child
                .lifecycle_channel()
                .expect("channel")
                .receive()
                .expect("ready"),
            READY
        );
        let child_pid = child.id();
        assert_eq!(
            child
                .wait_and_reap()
                .expect_err("hanging child must time out")
                .kind(),
            io::ErrorKind::TimedOut
        );
        assert_reaped(child_pid);

        let replacement = FixedChild::spawn_fixture().expect("permit released after reap");
        assert_eq!(
            replacement
                .lifecycle_channel()
                .expect("channel")
                .receive()
                .expect("ready"),
            READY
        );
        drop(replacement);
    }
}
