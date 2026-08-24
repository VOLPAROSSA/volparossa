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
use rustix::process::{
    Pid as RustixPid, PidfdFlags, Signal as RustixSignal, pidfd_open, pidfd_send_signal,
};
use volparossa_linux_uapi::{ensure_waitable_sigchld_disposition, install_close_range_on_exec};

use crate::{evidence::LauncherKernelPins, ipc::LifecycleChannel};

/// Exact private selector used when the runner re-executes its own image.
///
/// A future executable entry point must accept this value only as a solitary
/// internal invocation and must authenticate the inherited channel before work.
#[doc(hidden)]
pub const INTERNAL_CHILD_ARGUMENT: &str = "--internal-netns-lifecycle-child-v1";

/// Exact private selector used for the launcher's sole second self-reexec.
///
/// The launcher must already have selected a new PID namespace for its next
/// child before using this selector. The executable entry point must still
/// prove independently that the resulting process is PID 1 before doing work.
#[doc(hidden)]
pub const INTERNAL_PID_ONE_ARGUMENT: &str = "--internal-netns-pid-one-v1";

const MINIMUM_CHILD_CHANNEL_DESCRIPTOR: i32 = 3;
const TERMINATION_TIMEOUT: Duration = Duration::from_secs(1);
const TERMINATION_POLL_INTERVAL: Duration = Duration::from_millis(5);

static CHILD_SLOT_IN_USE: AtomicBool = AtomicBool::new(false);
static PID_ONE_SLOT_IN_USE: AtomicBool = AtomicBool::new(false);
static REAPER: OnceLock<Sender<Retirement>> = OnceLock::new();
#[cfg(test)]
const TEST_CHILD_ENVIRONMENT: &str = "VOLPAROSSA_NETNS_RUNNER_TEST_CHILD_V1";
#[cfg(test)]
const TEST_CHILD_ENVIRONMENT_VALUE: &str = "fixed";
#[cfg(test)]
const TEST_PID_ONE_ENVIRONMENT: &str = "VOLPAROSSA_NETNS_RUNNER_TEST_PID_ONE_V1";
#[cfg(test)]
const TEST_PID_ONE_ENVIRONMENT_VALUE: &str = "fixed";

/// Affine owner of the fixed re-executed child and its private channel.
///
/// At most one such child can exist in a process. Dropping this value closes
/// the channel, sends `SIGKILL` to the exact unreaped child when necessary, and
/// waits for a fixed bound. A child that cannot be reaped within that bound is
/// moved, together with the sole spawn permit, to a dedicated exact-child
/// reaper; it is never detached by dropping its [`Child`] handle.
pub(crate) struct FixedChild {
    child: Option<Child>,
    termination_pidfd: Option<OwnedFd>,
    provisioning_channel: Option<LifecycleChannel>,
    control_channel: Option<LifecycleChannel>,
    lifecycle_channel: Option<LifecycleChannel>,
    kernel_pins: Option<LauncherKernelPins>,
    permit: Option<SpawnPermit>,
}

impl FixedChild {
    /// Re-execute `/proc/self/exe` with the sole fixed internal selector.
    ///
    /// The command receives the unnamed provisioning socket as stdin, a strict
    /// bootstrap-control socket as stdout, and the separate lifecycle socket
    /// as stderr. Its environment is empty and cwd is `/`.
    /// The audited close-range hook is installed last so every unrelated
    /// descriptor at 3 or above becomes close-on-exec before this child starts.
    ///
    /// # Errors
    ///
    /// Returns an error when a child is already owned, reaper initialization or
    /// channel creation fails, or the fixed self-exec cannot be spawned.
    pub(crate) fn spawn() -> io::Result<Self> {
        spawn_with_fixed_arguments(&[INTERNAL_CHILD_ARGUMENT], None, true)
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

    /// Borrow the private namespace-bootstrap control endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error after retirement has begun and the endpoint was closed.
    pub(crate) fn control_channel(&self) -> io::Result<&LifecycleChannel> {
        self.control_channel
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

    /// Borrow the live pidfd, anchored proc directory, and namespace pins.
    ///
    /// # Errors
    ///
    /// Returns an error after retirement has begun and ownership was transferred.
    pub(crate) fn kernel_pins_mut(&mut self) -> io::Result<&mut LauncherKernelPins> {
        self.kernel_pins
            .as_mut()
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "child pins are closed"))
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
        let (mut child, termination_pidfd, pins, permit) = self.take_retirement()?;
        let Some(deadline) = Instant::now().checked_add(TERMINATION_TIMEOUT) else {
            defer_retirement(child, termination_pidfd, pins, permit);
            return Err(io::Error::other("fixed child wait deadline overflow"));
        };
        loop {
            match child.try_wait() {
                Ok(Some(status)) => {
                    drop(pins);
                    drop(permit);
                    return Ok(status);
                }
                Ok(None) => {}
                Err(error) => {
                    defer_retirement(child, termination_pidfd, pins, permit);
                    return Err(error);
                }
            }
            let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
                return retire_after_natural_wait_timeout(child, termination_pidfd, pins, permit);
            };
            if remaining.is_zero() {
                return retire_after_natural_wait_timeout(child, termination_pidfd, pins, permit);
            }
            thread::sleep(remaining.min(TERMINATION_POLL_INTERVAL));
        }
    }

    fn retire(&mut self) -> io::Result<ExitStatus> {
        let (child, termination_pidfd, pins, permit) = self.take_retirement()?;
        terminate_owned_child(child, termination_pidfd, pins, permit)
    }

    fn take_retirement(&mut self) -> io::Result<(Child, OwnedFd, LauncherKernelPins, SpawnPermit)> {
        drop(self.provisioning_channel.take());
        drop(self.control_channel.take());
        drop(self.lifecycle_channel.take());
        let Some(child) = self.child.take() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "fixed child was already retired",
            ));
        };
        let termination_pidfd = self.termination_pidfd.take().unwrap_or_else(|| {
            std::process::abort();
        });
        let pins = self.kernel_pins.take().unwrap_or_else(|| {
            std::process::abort();
        });
        let permit = self.permit.take().unwrap_or_else(|| {
            std::process::abort();
        });
        Ok((child, termination_pidfd, pins, permit))
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
            false,
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
            false,
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

/// Affine launcher-side owner of the sole fixed PID-namespace self-reexec.
///
/// This substrate does not create or attest a PID namespace. Its caller must
/// arrange that the next child enters an already selected PID namespace and
/// must prove the child's PID-1 placement independently. The child receives a
/// new launcher-private bootstrap socket as stdin and sole ownership of the
/// supplied outer lifecycle endpoint as stdout. No reaper thread is created:
/// the launcher remains single-threaded until after the child has been spawned.
pub(crate) struct FixedPidOne {
    child: Option<Child>,
    termination_pidfd: Option<OwnedFd>,
    bootstrap_channel: Option<LifecycleChannel>,
    permit: Option<PidOneSpawnPermit>,
}

impl FixedPidOne {
    /// Spawn the sole fixed second `/proc/self/exe` invocation.
    ///
    /// The inherited bootstrap endpoint is stdin, the transferred lifecycle
    /// endpoint is stdout, and stderr is `/dev/null`. The environment is empty,
    /// cwd is `/`, and the audited close-range hook is installed last.
    ///
    /// # Errors
    ///
    /// Returns an error when another PID-one child is already owned, channel
    /// creation fails, or the fixed self-exec cannot be spawned.
    pub(crate) fn spawn(lifecycle_channel: LifecycleChannel) -> io::Result<Self> {
        spawn_pid_one_with_fixed_arguments(lifecycle_channel, &[INTERNAL_PID_ONE_ARGUMENT], None)
    }

    /// Kernel PID visible to the launcher for the exact still-owned child.
    ///
    /// # Errors
    ///
    /// Returns an error after retirement has consumed the child handle.
    pub(crate) fn id(&self) -> io::Result<u32> {
        self.child
            .as_ref()
            .map(Child::id)
            .ok_or_else(|| io::Error::new(io::ErrorKind::BrokenPipe, "PID-one child is closed"))
    }

    /// Borrow the launcher side of the private PID-one bootstrap channel.
    ///
    /// # Errors
    ///
    /// Returns an error after retirement has closed the channel.
    pub(crate) fn bootstrap_channel(&self) -> io::Result<&LifecycleChannel> {
        self.bootstrap_channel.as_ref().ok_or_else(|| {
            io::Error::new(
                io::ErrorKind::BrokenPipe,
                "PID-one bootstrap channel is closed",
            )
        })
    }

    /// Wait for the exact child to exit normally and reap it.
    ///
    /// The private bootstrap endpoint is closed before waiting. A child which
    /// does not exit within the fixed bound is killed and reaped; `TimedOut`
    /// then distinguishes forced retirement from normal completion.
    ///
    /// # Errors
    ///
    /// Returns a wait error only after a subsequent forced reap succeeds, or
    /// `TimedOut` after the exact child had to be killed and reaped.
    pub(crate) fn wait_and_reap(mut self) -> io::Result<ExitStatus> {
        let (child, termination_pidfd, permit) = self.take_retirement()?;
        wait_for_pid_one(child, &termination_pidfd, permit)
    }

    fn retire(&mut self) -> io::Result<ExitStatus> {
        let (child, termination_pidfd, permit) = self.take_retirement()?;
        terminate_owned_pid_one(child, &termination_pidfd, permit)
    }

    fn take_retirement(&mut self) -> io::Result<(Child, OwnedFd, PidOneSpawnPermit)> {
        drop(self.bootstrap_channel.take());
        let Some(child) = self.child.take() else {
            return Err(io::Error::new(
                io::ErrorKind::InvalidInput,
                "PID-one child was already retired",
            ));
        };
        let termination_pidfd = self.termination_pidfd.take().unwrap_or_else(|| {
            std::process::abort();
        });
        let permit = self.permit.take().unwrap_or_else(|| {
            std::process::abort();
        });
        Ok((child, termination_pidfd, permit))
    }

    #[cfg(test)]
    fn spawn_fixture(lifecycle_channel: LifecycleChannel) -> io::Result<Self> {
        spawn_pid_one_with_fixed_arguments(
            lifecycle_channel,
            &[
                "--exact",
                "process::tests::fixed_pid_one_fixture_entry",
                "--test-threads=1",
                "--nocapture",
            ],
            Some((TEST_PID_ONE_ENVIRONMENT, TEST_PID_ONE_ENVIRONMENT_VALUE)),
        )
    }

    #[cfg(test)]
    fn spawn_hanging_fixture(lifecycle_channel: LifecycleChannel) -> io::Result<Self> {
        spawn_pid_one_with_fixed_arguments(
            lifecycle_channel,
            &[
                "--exact",
                "process::tests::fixed_hanging_pid_one_fixture_entry",
                "--test-threads=1",
                "--nocapture",
            ],
            Some((TEST_PID_ONE_ENVIRONMENT, TEST_PID_ONE_ENVIRONMENT_VALUE)),
        )
    }
}

impl Drop for FixedPidOne {
    fn drop(&mut self) {
        if self.child.is_some() && self.retire().is_err() {
            // The launcher must never continue after losing exact ownership of
            // the namespace init. Its outer parent still owns the launcher and
            // can then complete its own fail-closed retirement path.
            std::process::abort();
        }
    }
}

struct PidOneSpawnPermit;

impl PidOneSpawnPermit {
    fn acquire() -> io::Result<Self> {
        PID_ONE_SLOT_IN_USE
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .map_err(|_| {
                io::Error::new(
                    io::ErrorKind::WouldBlock,
                    "fixed PID-one child already exists",
                )
            })?;
        Ok(Self)
    }
}

impl Drop for PidOneSpawnPermit {
    fn drop(&mut self) {
        if PID_ONE_SLOT_IN_USE
            .compare_exchange(true, false, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
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
    termination_pidfd: OwnedFd,
    _pins: LauncherKernelPins,
    _permit: SpawnPermit,
}

fn terminate_owned_child(
    mut child: Child,
    termination_pidfd: OwnedFd,
    pins: LauncherKernelPins,
    permit: SpawnPermit,
) -> io::Result<ExitStatus> {
    match child.try_wait() {
        Ok(Some(status)) => {
            drop(pins);
            drop(permit);
            return Ok(status);
        }
        Ok(None) => {}
        Err(error) => {
            defer_retirement(child, termination_pidfd, pins, permit);
            return Err(error);
        }
    }
    let kill_error = pidfd_send_signal(&termination_pidfd, RustixSignal::KILL)
        .err()
        .map(rustix_io);
    let Some(deadline) = Instant::now().checked_add(TERMINATION_TIMEOUT) else {
        defer_retirement(child, termination_pidfd, pins, permit);
        return Err(io::Error::other(
            "fixed child termination deadline overflow",
        ));
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                drop(pins);
                drop(permit);
                return Ok(status);
            }
            Ok(None) => {}
            Err(error) => {
                defer_retirement(child, termination_pidfd, pins, permit);
                return Err(error);
            }
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            defer_retirement(child, termination_pidfd, pins, permit);
            return Err(kill_error.unwrap_or_else(termination_timeout));
        };
        if remaining.is_zero() {
            defer_retirement(child, termination_pidfd, pins, permit);
            return Err(kill_error.unwrap_or_else(termination_timeout));
        }
        thread::sleep(remaining.min(TERMINATION_POLL_INTERVAL));
    }
}

fn retire_after_natural_wait_timeout(
    child: Child,
    termination_pidfd: OwnedFd,
    pins: LauncherKernelPins,
    permit: SpawnPermit,
) -> io::Result<ExitStatus> {
    match terminate_owned_child(child, termination_pidfd, pins, permit) {
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

fn wait_for_pid_one(
    mut child: Child,
    termination_pidfd: &OwnedFd,
    permit: PidOneSpawnPermit,
) -> io::Result<ExitStatus> {
    let Some(deadline) = Instant::now().checked_add(TERMINATION_TIMEOUT) else {
        terminate_owned_pid_one(child, termination_pidfd, permit)
            .unwrap_or_else(|_| std::process::abort());
        return Err(io::Error::other("PID-one wait deadline overflow"));
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                drop(permit);
                return Ok(status);
            }
            Ok(None) => {}
            Err(error) => {
                terminate_owned_pid_one(child, termination_pidfd, permit)
                    .unwrap_or_else(|_| std::process::abort());
                return Err(error);
            }
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            terminate_owned_pid_one(child, termination_pidfd, permit)
                .unwrap_or_else(|_| std::process::abort());
            return Err(pid_one_wait_timeout());
        };
        if remaining.is_zero() {
            terminate_owned_pid_one(child, termination_pidfd, permit)
                .unwrap_or_else(|_| std::process::abort());
            return Err(pid_one_wait_timeout());
        }
        thread::sleep(remaining.min(TERMINATION_POLL_INTERVAL));
    }
}

fn terminate_owned_pid_one(
    mut child: Child,
    termination_pidfd: &OwnedFd,
    permit: PidOneSpawnPermit,
) -> io::Result<ExitStatus> {
    match child.try_wait() {
        Ok(Some(status)) => {
            drop(permit);
            return Ok(status);
        }
        Ok(None) => {}
        Err(error) => return Err(error),
    }
    let kill_error = pidfd_send_signal(termination_pidfd, RustixSignal::KILL)
        .err()
        .map(rustix_io);
    let Some(deadline) = Instant::now().checked_add(TERMINATION_TIMEOUT) else {
        return Err(io::Error::other("PID-one termination deadline overflow"));
    };
    loop {
        match child.try_wait() {
            Ok(Some(status)) => {
                drop(permit);
                return Ok(status);
            }
            Ok(None) => {}
            Err(error) => return Err(error),
        }
        let Some(remaining) = deadline.checked_duration_since(Instant::now()) else {
            return Err(kill_error.unwrap_or_else(pid_one_termination_timeout));
        };
        if remaining.is_zero() {
            return Err(kill_error.unwrap_or_else(pid_one_termination_timeout));
        }
        thread::sleep(remaining.min(TERMINATION_POLL_INTERVAL));
    }
}

fn pid_one_wait_timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "PID-one child did not exit normally before forced retirement",
    )
}

fn pid_one_termination_timeout() -> io::Error {
    io::Error::new(
        io::ErrorKind::TimedOut,
        "PID-one child termination timed out",
    )
}

fn require_waitable_children() -> io::Result<()> {
    ensure_waitable_sigchld_disposition()
}

fn open_child_pidfd(child: &Child) -> io::Result<OwnedFd> {
    pidfd_open(RustixPid::from_child(child), PidfdFlags::empty()).map_err(rustix_io)
}

fn rustix_io(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

fn spawn_pid_one_with_fixed_arguments(
    lifecycle_channel: LifecycleChannel,
    arguments: &[&str],
    retained_environment: Option<(&str, &str)>,
) -> io::Result<FixedPidOne> {
    require_waitable_children()?;
    // Do not initialize the outer launcher's fallback reaper here. This
    // process must remain single-threaded while `CLONE_NEWPID` selects the
    // namespace of its next child.
    let permit = PidOneSpawnPermit::acquire()?;
    let (bootstrap_parent, bootstrap_child) = LifecycleChannel::pair()?;
    let inherited_bootstrap: OwnedFd = bootstrap_child.into_owned_fd();
    let inherited_lifecycle: OwnedFd = lifecycle_channel.into_owned_fd();
    let mut command = Command::new("/proc/self/exe");
    command
        .args(arguments)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(inherited_bootstrap))
        .stdout(Stdio::from(inherited_lifecycle))
        .stderr(Stdio::null());
    if let Some((name, value)) = retained_environment {
        command.env(name, value);
    }
    // This must remain the final user-installed pre-exec hook.
    install_close_range_on_exec(&mut command);
    let mut child = command.spawn()?;
    let termination_pidfd = match open_child_pidfd(&child) {
        Ok(pidfd) => pidfd,
        Err(pidfd_error) => {
            drop(bootstrap_parent);
            let _ = child.kill();
            child.wait()?;
            return Err(pidfd_error);
        }
    };
    Ok(FixedPidOne {
        child: Some(child),
        termination_pidfd: Some(termination_pidfd),
        bootstrap_channel: Some(bootstrap_parent),
        permit: Some(permit),
    })
}

fn spawn_with_fixed_arguments(
    arguments: &[&str],
    retained_environment: Option<(&str, &str)>,
    inherit_control_channel: bool,
) -> io::Result<FixedChild> {
    require_waitable_children()?;
    let _ = reaper()?;
    let permit = SpawnPermit::acquire()?;
    let (provisioning_parent, provisioning_child) = LifecycleChannel::pair()?;
    let (control_parent, control_child) = LifecycleChannel::pair()?;
    let (lifecycle_parent, lifecycle_child) = LifecycleChannel::pair()?;
    let inherited_provisioning: OwnedFd = provisioning_child.into_owned_fd();
    let inherited_control: OwnedFd = control_child.into_owned_fd();
    let inherited_lifecycle: OwnedFd = lifecycle_child.into_owned_fd();
    let mut command = Command::new("/proc/self/exe");
    let child_stdout = if inherit_control_channel {
        Stdio::from(inherited_control)
    } else {
        drop(inherited_control);
        Stdio::null()
    };
    command
        .args(arguments)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(inherited_provisioning))
        .stdout(child_stdout)
        .stderr(Stdio::from(inherited_lifecycle));
    if let Some((name, value)) = retained_environment {
        command.env(name, value);
    }
    // This must remain the final user-installed pre-exec hook.
    install_close_range_on_exec(&mut command);
    let mut child = command.spawn()?;
    let termination_pidfd = match open_child_pidfd(&child) {
        Ok(pidfd) => pidfd,
        Err(pidfd_error) => {
            drop(provisioning_parent);
            drop(control_parent);
            drop(lifecycle_parent);
            let _ = child.kill();
            child.wait()?;
            drop(permit);
            return Err(pidfd_error);
        }
    };
    let kernel_pins = match LauncherKernelPins::pin_child(&child) {
        Ok(pins) => pins,
        Err(pin_error) => {
            let _ = pidfd_send_signal(&termination_pidfd, RustixSignal::KILL);
            if let Err(wait_error) = child.wait() {
                drop(permit);
                return Err(wait_error);
            }
            drop(permit);
            return Err(pin_error);
        }
    };
    Ok(FixedChild {
        child: Some(child),
        termination_pidfd: Some(termination_pidfd),
        provisioning_channel: Some(provisioning_parent),
        control_channel: Some(control_parent),
        lifecycle_channel: Some(lifecycle_parent),
        kernel_pins: Some(kernel_pins),
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
                    let _ = pidfd_send_signal(&retirement.termination_pidfd, RustixSignal::KILL);
                    match retirement.child.wait() {
                        Ok(_) => break,
                        Err(error)
                            if error.raw_os_error() == Some(nix::errno::Errno::ECHILD as i32) =>
                        {
                            std::process::abort();
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

fn defer_retirement(
    child: Child,
    termination_pidfd: OwnedFd,
    pins: LauncherKernelPins,
    permit: SpawnPermit,
) {
    if reaper()
        .and_then(|sender| {
            sender
                .send(Retirement {
                    child,
                    termination_pidfd,
                    _pins: pins,
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

/// Duplicate the inherited bootstrap-control socket from stdout to a private descriptor.
///
/// # Errors
///
/// Returns an error for a parent race, close failure, or substituted/nonconforming
/// stdout channel.
pub(crate) fn inherited_control_channel_from_stdout() -> io::Result<LifecycleChannel> {
    inherited_channel_from_standard_descriptor(io::stdout(), 1)
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

/// Duplicate the PID-one launcher's private bootstrap socket from stdin.
///
/// A real namespace init has a parent outside its PID namespace, so Linux
/// deliberately reports `getppid() == 0`. This helper requires that condition
/// on both sides of the duplication instead of applying the ordinary internal
/// child's visible-parent contract.
///
/// # Errors
///
/// Returns an error unless the parent remains invisible, or for a close,
/// duplication, or channel-shape failure.
pub(crate) fn inherited_pid_one_bootstrap_channel_from_stdin() -> io::Result<LifecycleChannel> {
    inherited_pid_one_channel_from_standard_descriptor(io::stdin(), 0)
}

/// Duplicate the outer lifecycle socket inherited by PID one from stdout.
///
/// # Errors
///
/// Returns an error unless the parent remains invisible, or for a close,
/// duplication, or channel-shape failure.
pub(crate) fn inherited_pid_one_lifecycle_channel_from_stdout() -> io::Result<LifecycleChannel> {
    inherited_pid_one_channel_from_standard_descriptor(io::stdout(), 1)
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

fn inherited_pid_one_channel_from_standard_descriptor<S: AsFd>(
    descriptor: S,
    standard_descriptor: i32,
) -> io::Result<LifecycleChannel> {
    let initial_parent = getppid();
    require_invisible_pid_one_parent(initial_parent, initial_parent)?;
    let inherited = fcntl_dupfd_cloexec(descriptor, MINIMUM_CHILD_CHANNEL_DESCRIPTOR)
        .map_err(|error| io::Error::from_raw_os_error(error.raw_os_error()))?;
    require_invisible_pid_one_parent(initial_parent, getppid())?;
    close(standard_descriptor).map_err(errno_io)?;
    LifecycleChannel::from_owned_fd(inherited)
}

fn require_invisible_pid_one_parent(
    initial_parent: nix::unistd::Pid,
    current_parent: nix::unistd::Pid,
) -> io::Result<()> {
    if initial_parent.as_raw() == 0 && current_parent == initial_parent {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::PermissionDenied,
            "PID-one parent must remain outside the child PID namespace",
        ))
    }
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
    const PID_ONE_READY: &[u8] = b"VOLPAROSSA_NETNS_PID_ONE_TEST_READY_V1";
    const PID_ONE_LIFECYCLE_READY: &[u8] = b"VOLPAROSSA_NETNS_PID_ONE_TEST_LIFECYCLE_READY_V1";
    const TEST_HARNESS_BANNER: &[u8] = b"\nrunning 1 test\n";
    const PID_ONE_FIXTURE_PREFIX: &[u8] = b"test process::tests::fixed_pid_one_fixture_entry ... ";
    const HANGING_PID_ONE_FIXTURE_PREFIX: &[u8] =
        b"test process::tests::fixed_hanging_pid_one_fixture_entry ... ";
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

    fn is_spawned_pid_one_fixture() -> bool {
        env::var_os(TEST_PID_ONE_ENVIRONMENT).as_deref()
            == Some(OsStr::new(TEST_PID_ONE_ENVIRONMENT_VALUE))
    }

    fn assert_reaped(child_pid: u32) {
        let child_pid = i32::try_from(child_pid).expect("Linux child PID fits i32");
        assert_eq!(
            waitpid(Pid::from_raw(child_pid), Some(WaitPidFlag::WNOHANG)),
            Err(Errno::ECHILD)
        );
    }

    fn consume_pid_one_test_harness_prelude(channel: &LifecycleChannel, expected_prefix: &[u8]) {
        // The libtest executable writes these two records to stdout before the
        // selected fixture duplicates and closes that descriptor. Production
        // uses the dedicated internal selector and therefore has no prelude.
        assert_eq!(
            channel.receive().expect("libtest stdout banner"),
            TEST_HARNESS_BANNER
        );
        assert_eq!(
            channel.receive().expect("libtest test-name prefix"),
            expected_prefix
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
    fn fixed_pid_one_fixture_entry() {
        if !is_spawned_pid_one_fixture() {
            return;
        }
        let bootstrap =
            inherited_provisioning_channel_from_stdin().expect("inherited bootstrap channel");
        let lifecycle =
            inherited_control_channel_from_stdout().expect("inherited lifecycle channel");
        bootstrap.send(PID_ONE_READY).expect("PID-one ready");
        lifecycle
            .send(PID_ONE_LIFECYCLE_READY)
            .expect("PID-one lifecycle ready");
        assert_eq!(bootstrap.receive().expect("PID-one stop"), STOP);
        bootstrap
            .send(FINISHED)
            .expect("PID-one bootstrap finished");
        lifecycle
            .send(FINISHED)
            .expect("PID-one lifecycle finished");
    }

    #[test]
    fn fixed_hanging_pid_one_fixture_entry() {
        if !is_spawned_pid_one_fixture() {
            return;
        }
        let bootstrap =
            inherited_provisioning_channel_from_stdin().expect("inherited bootstrap channel");
        let _lifecycle =
            inherited_control_channel_from_stdout().expect("inherited lifecycle channel");
        bootstrap.send(PID_ONE_READY).expect("PID-one ready");
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
        assert!(status.success(), "fixture status was {status:?}");
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

    #[test]
    fn fixed_pid_one_spawn_transfers_lifecycle_fences_fds_and_reaps() {
        let _test_guard = process_test_lock();
        let (sentinel, _sentinel_peer) =
            Socket::pair(Domain::UNIX, Type::SEQPACKET.cloexec(), None::<Protocol>)
                .expect("sentinel pair");
        fcntl(&sentinel, FcntlArg::F_SETFD(FdFlag::empty()))
            .expect("make sentinel deliberately inheritable");
        let sentinel_target = fs::read_link(format!("/proc/self/fd/{}", sentinel.as_raw_fd()))
            .expect("sentinel link");
        let (lifecycle_parent, lifecycle_child) = LifecycleChannel::pair().expect("lifecycle pair");

        let pid_one = FixedPidOne::spawn_fixture(lifecycle_child).expect("spawn PID-one fixture");
        let child_pid = pid_one.id().expect("owned child PID");
        assert_eq!(
            pid_one
                .bootstrap_channel()
                .expect("bootstrap channel")
                .receive()
                .expect("PID-one ready"),
            PID_ONE_READY
        );
        consume_pid_one_test_harness_prelude(&lifecycle_parent, PID_ONE_FIXTURE_PREFIX);
        assert_eq!(
            lifecycle_parent.receive().expect("lifecycle ready"),
            PID_ONE_LIFECYCLE_READY
        );

        let leaked = fs::read_dir(format!("/proc/{child_pid}/fd"))
            .expect("PID-one descriptor directory")
            .filter_map(Result::ok)
            .filter_map(|entry| fs::read_link(entry.path()).ok())
            .any(|target| target == sentinel_target);
        assert!(
            !leaked,
            "close-range fence must remove inheritable sentinel"
        );

        pid_one
            .bootstrap_channel()
            .expect("bootstrap channel")
            .send(STOP)
            .expect("stop PID-one fixture");
        assert_eq!(
            pid_one
                .bootstrap_channel()
                .expect("bootstrap channel")
                .receive()
                .expect("bootstrap finished"),
            FINISHED
        );
        assert_eq!(
            lifecycle_parent.receive().expect("lifecycle finished"),
            FINISHED
        );
        let status = pid_one.wait_and_reap().expect("reap PID-one fixture");
        assert!(status.success(), "PID-one fixture status was {status:?}");
        assert_reaped(child_pid);
    }

    #[test]
    fn fixed_pid_one_drop_kills_reaps_and_releases_affine_slot() {
        let _test_guard = process_test_lock();
        let (first_lifecycle_parent, first_lifecycle_child) =
            LifecycleChannel::pair().expect("first lifecycle pair");
        let first =
            FixedPidOne::spawn_hanging_fixture(first_lifecycle_child).expect("first PID-one");
        assert_eq!(
            first
                .bootstrap_channel()
                .expect("bootstrap channel")
                .receive()
                .expect("PID-one ready"),
            PID_ONE_READY
        );
        let first_pid = first.id().expect("first PID-one PID");

        let (_rejected_parent, rejected_child) =
            LifecycleChannel::pair().expect("rejected lifecycle pair");
        assert_eq!(
            FixedPidOne::spawn_fixture(rejected_child)
                .err()
                .expect("second PID-one must fail")
                .kind(),
            io::ErrorKind::WouldBlock
        );

        drop(first);
        assert_reaped(first_pid);
        consume_pid_one_test_harness_prelude(
            &first_lifecycle_parent,
            HANGING_PID_ONE_FIXTURE_PREFIX,
        );
        assert_eq!(
            first_lifecycle_parent
                .receive()
                .expect_err("transferred lifecycle must close")
                .kind(),
            io::ErrorKind::UnexpectedEof
        );

        let (replacement_lifecycle_parent, replacement_lifecycle_child) =
            LifecycleChannel::pair().expect("replacement lifecycle pair");
        let replacement =
            FixedPidOne::spawn_fixture(replacement_lifecycle_child).expect("replacement PID-one");
        assert_eq!(
            replacement
                .bootstrap_channel()
                .expect("replacement bootstrap")
                .receive()
                .expect("replacement ready"),
            PID_ONE_READY
        );
        consume_pid_one_test_harness_prelude(&replacement_lifecycle_parent, PID_ONE_FIXTURE_PREFIX);
        replacement
            .bootstrap_channel()
            .expect("replacement bootstrap")
            .send(STOP)
            .expect("stop replacement");
        assert_eq!(
            replacement
                .bootstrap_channel()
                .expect("replacement bootstrap")
                .receive()
                .expect("replacement finished"),
            FINISHED
        );
        assert_eq!(
            replacement_lifecycle_parent
                .receive()
                .expect("replacement lifecycle ready"),
            PID_ONE_LIFECYCLE_READY
        );
        assert_eq!(
            replacement_lifecycle_parent
                .receive()
                .expect("replacement lifecycle finished"),
            FINISHED
        );
        replacement.wait_and_reap().expect("reap replacement");
    }

    #[test]
    fn pid_one_inherited_channel_requires_an_invisible_stable_parent() {
        let invisible = Pid::from_raw(0);
        require_invisible_pid_one_parent(invisible, invisible).expect("invisible parent");
        for (initial, current) in [
            (Pid::from_raw(1), Pid::from_raw(1)),
            (Pid::from_raw(7), Pid::from_raw(7)),
            (Pid::from_raw(0), Pid::from_raw(7)),
        ] {
            assert_eq!(
                require_invisible_pid_one_parent(initial, current)
                    .expect_err("visible or changed parent must fail")
                    .kind(),
                io::ErrorKind::PermissionDenied
            );
        }
    }
}
