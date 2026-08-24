use std::{
    io,
    marker::PhantomData,
    os::fd::AsFd,
    rc::Rc,
    time::{Duration, Instant},
};

use nix::{
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    poll::{PollFd, PollFlags, PollTimeout, poll},
    sys::{
        signal::{SigSet, SigmaskHow, Signal},
        signalfd::{SfdFlags, SignalFd},
    },
};
use volparossa_linux_uapi::{
    ensure_default_lifecycle_signal_dispositions, ensure_waitable_sigchld_disposition,
    install_pid_one_lifecycle_signal_handlers, verify_pid_one_lifecycle_signal_handlers,
};

use crate::ipc::LifecycleChannel;

/// Fixed termination signals accepted by the bounded lifecycle supervisor.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ManagedSignal {
    Hup,
    Int,
    Term,
}

impl ManagedSignal {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            Self::Hup => "HUP",
            Self::Int => "INT",
            Self::Term => "TERM",
        }
    }

    pub(crate) fn parse(value: &str) -> io::Result<Self> {
        match value {
            "HUP" => Ok(Self::Hup),
            "INT" => Ok(Self::Int),
            "TERM" => Ok(Self::Term),
            _ => Err(invalid_data("managed signal name is invalid")),
        }
    }

    fn from_raw(raw: u32) -> io::Result<Option<Self>> {
        let raw = i32::try_from(raw).map_err(|_| invalid_data("signal number does not fit i32"))?;
        match Signal::try_from(raw).map_err(errno_io)? {
            Signal::SIGHUP => Ok(Some(Self::Hup)),
            Signal::SIGINT => Ok(Some(Self::Int)),
            Signal::SIGTERM => Ok(Some(Self::Term)),
            Signal::SIGCHLD => Ok(None),
            _ => Err(invalid_data("signalfd returned an unmanaged signal")),
        }
    }
}

/// One monotonic absolute deadline shared by a fixed protocol phase.
#[derive(Clone, Copy, Debug)]
pub(crate) struct AbsoluteDeadline(Instant);

impl AbsoluteDeadline {
    pub(crate) fn after(duration: Duration) -> io::Result<Self> {
        Instant::now()
            .checked_add(duration)
            .map(Self)
            .ok_or_else(|| invalid_data("signal deadline overflowed"))
    }

    fn poll_timeout(self) -> io::Result<PollTimeout> {
        let remaining = self
            .0
            .checked_duration_since(Instant::now())
            .ok_or_else(|| io::Error::new(io::ErrorKind::TimedOut, "signal deadline expired"))?;
        let whole_millis = remaining.as_millis();
        let rounded_millis = if remaining.subsec_nanos() % 1_000_000 == 0 {
            whole_millis
        } else {
            whole_millis
                .checked_add(1)
                .ok_or_else(|| invalid_data("poll timeout overflowed"))?
        };
        PollTimeout::try_from(rounded_millis)
            .map_err(|_| invalid_data("poll timeout exceeds the kernel bound"))
    }

    fn ensure_unexpired(self) -> io::Result<()> {
        if Instant::now() < self.0 {
            Ok(())
        } else {
            Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "signal deadline expired",
            ))
        }
    }
}

/// Signal-aware result of waiting for one outer protocol record.
#[derive(Debug)]
pub(crate) enum SupervisedReceiveError {
    Io(io::Error),
    Termination(ManagedSignal),
    UnexpectedChildSignal,
}

impl From<io::Error> for SupervisedReceiveError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

#[derive(Default)]
struct PendingSignals {
    termination: Option<ManagedSignal>,
    child: bool,
}

/// Single-thread signal owner used by either the outer or namespace PID 1.
///
/// The outer instance restores its previous thread mask on drop. The PID-1
/// instance requires the exact mask inherited from the outer, installs the
/// fixed emergency dispositions, and keeps them plus its signalfd alive until
/// process exit. `Rc` in the marker prevents moving the thread-bound owner.
pub(crate) struct FixedSignalSupervisor {
    descriptor: SignalFd,
    previous_mask: Option<SigSet>,
    pid_one_handlers: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

impl FixedSignalSupervisor {
    /// Block the complete managed set before any child or fallback-reaper thread exists.
    pub(crate) fn install_outer() -> io::Result<Self> {
        ensure_default_lifecycle_signal_dispositions()?;
        ensure_waitable_sigchld_disposition()?;
        let inherited_mask = SigSet::thread_get_mask().map_err(errno_io)?;
        if inherited_mask != SigSet::empty() {
            return Err(invalid_data(
                "outer thread inherited an unexpected blocked signal",
            ));
        }
        let mask = managed_mask();
        let previous_mask = mask
            .thread_swap_mask(SigmaskHow::SIG_BLOCK)
            .map_err(errno_io)?;
        if previous_mask != inherited_mask {
            restore_thread_mask_or_abort(&previous_mask);
            return Err(invalid_data(
                "outer signal mask changed during supervisor installation",
            ));
        }
        let descriptor =
            match SignalFd::with_flags(&mask, SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK) {
                Ok(descriptor) => descriptor,
                Err(error) => {
                    restore_thread_mask_or_abort(&previous_mask);
                    return Err(errno_io(error));
                }
            };
        let supervisor = Self {
            descriptor,
            previous_mask: Some(previous_mask),
            pid_one_handlers: false,
            _thread_bound: PhantomData,
        };
        supervisor.verify_outer()?;
        if !supervisor.drain()?.is_empty() {
            return Err(invalid_data(
                "managed signal was pending before supervisor admission",
            ));
        }
        Ok(supervisor)
    }

    /// Adopt the exact inherited mask and arm real namespace-PID-1 dispositions.
    pub(crate) fn install_pid_one() -> io::Result<Self> {
        if SigSet::thread_get_mask().map_err(errno_io)? != managed_mask() {
            return Err(invalid_data(
                "PID 1 did not inherit the exact managed signal mask",
            ));
        }
        ensure_waitable_sigchld_disposition()?;
        install_pid_one_lifecycle_signal_handlers()?;
        verify_pid_one_lifecycle_signal_handlers()?;
        let descriptor = SignalFd::with_flags(
            &managed_mask(),
            SfdFlags::SFD_CLOEXEC | SfdFlags::SFD_NONBLOCK,
        )
        .map_err(errno_io)?;
        let supervisor = Self {
            descriptor,
            previous_mask: None,
            pid_one_handlers: true,
            _thread_bound: PhantomData,
        };
        supervisor.verify_pid_one_quiescent()?;
        Ok(supervisor)
    }

    pub(crate) fn verify_outer(&self) -> io::Result<()> {
        self.verify_descriptor()?;
        if self.pid_one_handlers || SigSet::thread_get_mask().map_err(errno_io)? != managed_mask() {
            return Err(invalid_data("outer managed signal state changed"));
        }
        ensure_default_lifecycle_signal_dispositions()
    }

    pub(crate) fn verify_pid_one(&self) -> io::Result<()> {
        self.verify_descriptor()?;
        if !self.pid_one_handlers || SigSet::thread_get_mask().map_err(errno_io)? != managed_mask()
        {
            return Err(invalid_data("PID-1 managed signal mask changed"));
        }
        verify_pid_one_lifecycle_signal_handlers()
    }

    /// Revalidate the PID-1 actions and mask and require its fixed signal queue to be empty.
    pub(crate) fn verify_pid_one_quiescent(&self) -> io::Result<()> {
        self.verify_pid_one()?;
        if !self.drain()?.is_empty() {
            return Err(invalid_data("PID-1 managed signal queue is not quiescent"));
        }
        self.verify_pid_one()
    }

    /// Receive one outer protocol record while termination and child exit take priority.
    pub(crate) fn receive_outer(
        &self,
        channel: &LifecycleChannel,
        deadline: AbsoluteDeadline,
    ) -> Result<Vec<u8>, SupervisedReceiveError> {
        let mut descriptors = [
            PollFd::new(self.descriptor.as_fd(), PollFlags::POLLIN),
            PollFd::new(channel.as_fd(), PollFlags::POLLIN),
        ];
        let ready = poll(&mut descriptors, deadline.poll_timeout()?).map_err(errno_io)?;
        deadline.ensure_unexpired()?;
        if ready == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "supervised protocol receive timed out",
            )
            .into());
        }
        validate_poll_events(&descriptors)?;
        reject_outer_pending(&self.drain()?)?;
        let channel_events = descriptors[1].revents().unwrap_or_else(PollFlags::empty);
        if channel_events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
            let received = channel.receive();
            reject_outer_pending(&self.drain()?)?;
            deadline.ensure_unexpired()?;
            received.map_err(SupervisedReceiveError::Io)
        } else {
            Err(invalid_data("poll returned without a protocol or signal event").into())
        }
    }

    /// Require final lifecycle EOF while allowing one co-occurring launcher `SIGCHLD`.
    ///
    /// A managed termination always wins over EOF. `SIGCHLD` is tolerated only in this final
    /// receive and at most once; a protocol record remains an error.
    pub(crate) fn receive_outer_final_eof(
        &self,
        channel: &LifecycleChannel,
        deadline: AbsoluteDeadline,
    ) -> Result<(), SupervisedReceiveError> {
        let mut child_observed = false;
        loop {
            self.verify_outer()?;
            let mut descriptors = [
                PollFd::new(self.descriptor.as_fd(), PollFlags::POLLIN),
                PollFd::new(channel.as_fd(), PollFlags::POLLIN),
            ];
            let ready = poll(&mut descriptors, deadline.poll_timeout()?).map_err(errno_io)?;
            deadline.ensure_unexpired()?;
            if ready == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "final supervised protocol receive timed out",
                )
                .into());
            }
            validate_poll_events(&descriptors)?;
            observe_final_outer_pending(&self.drain()?, &mut child_observed)?;

            let channel_events = descriptors[1].revents().unwrap_or_else(PollFlags::empty);
            if !channel_events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
                if descriptors[0]
                    .revents()
                    .unwrap_or_else(PollFlags::empty)
                    .contains(PollFlags::POLLIN)
                {
                    continue;
                }
                return Err(
                    invalid_data("poll returned without a final protocol or signal event").into(),
                );
            }

            let received = channel.receive();
            observe_final_outer_pending(&self.drain()?, &mut child_observed)?;
            deadline.ensure_unexpired()?;
            self.verify_outer()?;
            return match received {
                Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
                Err(error) => Err(SupervisedReceiveError::Io(error)),
                Ok(_) => {
                    Err(invalid_data("final lifecycle channel carried a protocol record").into())
                }
            };
        }
    }

    /// Ensure no termination is pending immediately before an outer proceed-send.
    pub(crate) fn before_outer_send(&self) -> Result<(), SupervisedReceiveError> {
        self.verify_outer()?;
        reject_outer_pending(&self.drain()?)
    }

    /// Receive exactly one PID-1 lifecycle record while both parent channels stay quiet.
    ///
    /// This is the sole pre-mutation admission wait. A managed termination, `SIGCHLD`,
    /// bootstrap-parent record/EOF, lifecycle EOF, or an already-pending second lifecycle
    /// record fails closed. The returned record is therefore the only lifecycle input observed
    /// under the supplied absolute deadline.
    pub(crate) fn receive_pid_one_lifecycle_record(
        &self,
        bootstrap: &LifecycleChannel,
        lifecycle: &LifecycleChannel,
        deadline: AbsoluteDeadline,
    ) -> io::Result<Vec<u8>> {
        self.verify_pid_one()?;
        let mut descriptors = [
            PollFd::new(self.descriptor.as_fd(), PollFlags::POLLIN),
            PollFd::new(bootstrap.as_fd(), PollFlags::POLLIN),
            PollFd::new(lifecycle.as_fd(), PollFlags::POLLIN),
        ];
        let ready = poll(&mut descriptors, deadline.poll_timeout()?).map_err(errno_io)?;
        deadline.ensure_unexpired()?;
        if ready == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "PID-1 lifecycle receive timed out",
            ));
        }
        validate_poll_events(&descriptors)?;
        reject_pid_one_pending(&self.drain()?)?;

        let bootstrap_events = descriptors[1].revents().unwrap_or_else(PollFlags::empty);
        if bootstrap_events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
            return Err(invalid_data(
                "bootstrap-parent event arrived before PID-1 lifecycle authorization",
            ));
        }

        let lifecycle_events = descriptors[2].revents().unwrap_or_else(PollFlags::empty);
        if !lifecycle_events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
            return Err(invalid_data(
                "poll returned without a PID-1 lifecycle authorization event",
            ));
        }
        let record = lifecycle.receive().map_err(|error| {
            if error.kind() == io::ErrorKind::UnexpectedEof {
                invalid_data("lifecycle EOF arrived before PID-1 authorization")
            } else {
                error
            }
        })?;

        reject_pid_one_pending(&self.drain()?)?;
        reject_immediate_pid_one_lifecycle_races(bootstrap, lifecycle)?;
        self.verify_pid_one_quiescent()?;
        deadline.ensure_unexpired()?;
        Ok(record)
    }

    /// Wait for exactly one managed PID-1 termination while also watching both parents.
    pub(crate) fn wait_pid_one_termination(
        &self,
        bootstrap: &LifecycleChannel,
        lifecycle: &LifecycleChannel,
        expected: ManagedSignal,
        deadline: AbsoluteDeadline,
    ) -> io::Result<()> {
        self.verify_pid_one()?;
        let mut descriptors = [
            PollFd::new(self.descriptor.as_fd(), PollFlags::POLLIN),
            PollFd::new(bootstrap.as_fd(), PollFlags::POLLIN),
            PollFd::new(lifecycle.as_fd(), PollFlags::POLLIN),
        ];
        let ready = poll(&mut descriptors, deadline.poll_timeout()?).map_err(errno_io)?;
        deadline.ensure_unexpired()?;
        if ready == 0 {
            return Err(io::Error::new(
                io::ErrorKind::TimedOut,
                "PID-1 signal observation timed out",
            ));
        }
        validate_poll_events(&descriptors)?;
        let pending = self.drain()?;
        if pending.child {
            return Err(invalid_data(
                "PID 1 observed SIGCHLD without an admitted child",
            ));
        }
        if pending.termination != Some(expected) {
            return Err(invalid_data(
                "PID 1 did not observe the exact managed termination signal",
            ));
        }
        if descriptors[1]
            .revents()
            .unwrap_or_else(PollFlags::empty)
            .intersects(PollFlags::POLLIN | PollFlags::POLLHUP)
            || descriptors[2]
                .revents()
                .unwrap_or_else(PollFlags::empty)
                .intersects(PollFlags::POLLIN | PollFlags::POLLHUP)
        {
            return Err(invalid_data(
                "parent or lifecycle event raced the managed signal observation",
            ));
        }
        self.verify_pid_one_quiescent()?;
        deadline.ensure_unexpired()
    }

    /// Receive the private retire instruction and lifecycle EOF in either cross-channel order.
    pub(crate) fn wait_pid_one_retire_barrier(
        &self,
        bootstrap: &LifecycleChannel,
        lifecycle: &LifecycleChannel,
        deadline: AbsoluteDeadline,
    ) -> io::Result<Vec<u8>> {
        let mut instruction = None;
        let mut lifecycle_eof = false;
        while instruction.is_none() || !lifecycle_eof {
            self.verify_pid_one()?;
            let mut descriptors = Vec::with_capacity(3);
            descriptors.push(PollFd::new(self.descriptor.as_fd(), PollFlags::POLLIN));
            let bootstrap_index = if instruction.is_none() {
                let index = descriptors.len();
                descriptors.push(PollFd::new(bootstrap.as_fd(), PollFlags::POLLIN));
                Some(index)
            } else {
                None
            };
            let lifecycle_index = if lifecycle_eof {
                None
            } else {
                let index = descriptors.len();
                descriptors.push(PollFd::new(lifecycle.as_fd(), PollFlags::POLLIN));
                Some(index)
            };
            let ready = poll(&mut descriptors, deadline.poll_timeout()?).map_err(errno_io)?;
            deadline.ensure_unexpired()?;
            if ready == 0 {
                return Err(io::Error::new(
                    io::ErrorKind::TimedOut,
                    "PID-1 retire barrier timed out",
                ));
            }
            validate_poll_events(&descriptors)?;
            if !self.drain()?.is_empty() {
                return Err(invalid_data(
                    "unexpected managed signal arrived during PID-1 retirement",
                ));
            }
            let mut progressed = false;
            let bootstrap_events = bootstrap_index
                .and_then(|index| descriptors[index].revents())
                .unwrap_or_else(PollFlags::empty);
            if bootstrap_events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
                instruction = Some(bootstrap.receive()?);
                require_no_immediate_extra_retire_record(bootstrap)?;
                progressed = true;
            }
            let lifecycle_events = lifecycle_index
                .and_then(|index| descriptors[index].revents())
                .unwrap_or_else(PollFlags::empty);
            if lifecycle_events.intersects(PollFlags::POLLIN | PollFlags::POLLHUP) {
                match lifecycle.receive() {
                    Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => {
                        lifecycle_eof = true;
                    }
                    Err(error) => return Err(error),
                    Ok(_) => {
                        return Err(invalid_data(
                            "unexpected lifecycle record arrived during PID-1 retirement",
                        ));
                    }
                }
                progressed = true;
            }
            if !progressed {
                return Err(invalid_data(
                    "poll returned without an unresolved PID-1 retire event",
                ));
            }
        }
        self.verify_pid_one_quiescent()?;
        deadline.ensure_unexpired()?;
        instruction.ok_or_else(|| invalid_data("PID-1 retire instruction is missing"))
    }

    fn verify_descriptor(&self) -> io::Result<()> {
        let descriptor_flags = FdFlag::from_bits_truncate(
            fcntl(&self.descriptor, FcntlArg::F_GETFD).map_err(errno_io)?,
        );
        let status_flags = OFlag::from_bits_truncate(
            fcntl(&self.descriptor, FcntlArg::F_GETFL).map_err(errno_io)?,
        );
        if descriptor_flags != FdFlag::FD_CLOEXEC || !status_flags.contains(OFlag::O_NONBLOCK) {
            return Err(invalid_data("managed signalfd properties changed"));
        }
        Ok(())
    }

    fn drain(&self) -> io::Result<PendingSignals> {
        let mut pending = PendingSignals::default();
        for _ in 0..4 {
            let Some(record) = self.descriptor.read_signal().map_err(errno_io)? else {
                return Ok(pending);
            };
            if let Some(signal) = ManagedSignal::from_raw(record.ssi_signo)? {
                if pending.termination.replace(signal).is_some() {
                    return Err(invalid_data(
                        "more than one managed termination signal was pending",
                    ));
                }
            } else {
                if pending.child {
                    return Err(invalid_data("duplicate SIGCHLD observation"));
                }
                pending.child = true;
            }
        }
        if self.descriptor.read_signal().map_err(errno_io)?.is_some() {
            return Err(invalid_data(
                "managed signal queue exceeded its fixed bound",
            ));
        }
        Ok(pending)
    }
}

impl Drop for FixedSignalSupervisor {
    fn drop(&mut self) {
        if let Some(previous_mask) = self.previous_mask.take() {
            restore_thread_mask_or_abort(&previous_mask);
        }
    }
}

impl PendingSignals {
    const fn is_empty(&self) -> bool {
        self.termination.is_none() && !self.child
    }
}

fn managed_mask() -> SigSet {
    [
        Signal::SIGHUP,
        Signal::SIGINT,
        Signal::SIGTERM,
        Signal::SIGCHLD,
    ]
    .into_iter()
    .collect()
}

fn reject_outer_pending(pending: &PendingSignals) -> Result<(), SupervisedReceiveError> {
    if let Some(signal) = pending.termination {
        return Err(SupervisedReceiveError::Termination(signal));
    }
    if pending.child {
        return Err(SupervisedReceiveError::UnexpectedChildSignal);
    }
    Ok(())
}

fn observe_final_outer_pending(
    pending: &PendingSignals,
    child_observed: &mut bool,
) -> Result<(), SupervisedReceiveError> {
    if let Some(signal) = pending.termination {
        return Err(SupervisedReceiveError::Termination(signal));
    }
    if pending.child {
        if *child_observed {
            return Err(invalid_data("duplicate final launcher SIGCHLD observation").into());
        }
        *child_observed = true;
    }
    Ok(())
}

fn reject_pid_one_pending(pending: &PendingSignals) -> io::Result<()> {
    if pending.termination.is_some() {
        return Err(invalid_data(
            "managed termination arrived before PID-1 lifecycle authorization",
        ));
    }
    if pending.child {
        return Err(invalid_data(
            "SIGCHLD arrived before PID-1 lifecycle authorization",
        ));
    }
    Ok(())
}

fn reject_immediate_pid_one_lifecycle_races(
    bootstrap: &LifecycleChannel,
    lifecycle: &LifecycleChannel,
) -> io::Result<()> {
    let mut descriptors = [
        PollFd::new(bootstrap.as_fd(), PollFlags::POLLIN),
        PollFd::new(lifecycle.as_fd(), PollFlags::POLLIN),
    ];
    let ready = poll(&mut descriptors, PollTimeout::ZERO).map_err(errno_io)?;
    validate_poll_events(&descriptors)?;
    if ready == 0 {
        return Ok(());
    }
    if descriptors[0]
        .revents()
        .unwrap_or_else(PollFlags::empty)
        .intersects(PollFlags::POLLIN | PollFlags::POLLHUP)
    {
        return Err(invalid_data(
            "bootstrap-parent event raced PID-1 lifecycle authorization",
        ));
    }
    if descriptors[1]
        .revents()
        .unwrap_or_else(PollFlags::empty)
        .intersects(PollFlags::POLLIN | PollFlags::POLLHUP)
    {
        return Err(invalid_data(
            "second lifecycle record or EOF raced PID-1 authorization",
        ));
    }
    Err(invalid_data(
        "poll returned without an immediate PID-1 lifecycle event",
    ))
}

fn require_no_immediate_extra_retire_record(channel: &LifecycleChannel) -> io::Result<()> {
    let mut descriptor = [PollFd::new(channel.as_fd(), PollFlags::POLLIN)];
    let ready = poll(&mut descriptor, PollTimeout::ZERO).map_err(errno_io)?;
    validate_poll_events(&descriptor)?;
    if ready == 0
        || !descriptor[0]
            .revents()
            .unwrap_or_else(PollFlags::empty)
            .intersects(PollFlags::POLLIN | PollFlags::POLLHUP)
    {
        return Ok(());
    }
    match channel.receive() {
        Err(error) if error.kind() == io::ErrorKind::UnexpectedEof => Ok(()),
        Err(error) => Err(error),
        Ok(_) => Err(invalid_data("duplicate PID-1 retire instruction")),
    }
}

fn restore_thread_mask_or_abort(previous_mask: &SigSet) {
    if previous_mask.thread_set_mask().is_err() {
        std::process::abort();
    }
}

fn validate_poll_events(descriptors: &[PollFd<'_>]) -> io::Result<()> {
    if descriptors.iter().any(|descriptor| {
        descriptor
            .revents()
            .is_none_or(|events| events.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL))
    }) {
        Err(invalid_data(
            "supervised descriptor reported an invalid poll event",
        ))
    } else {
        Ok(())
    }
}

fn invalid_data(message: &'static str) -> io::Error {
    io::Error::new(io::ErrorKind::InvalidData, message)
}

fn errno_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

#[cfg(test)]
mod tests {
    use std::{
        env,
        process::{Command, Stdio},
    };

    use nix::sys::signal::raise;

    use super::*;

    const SUPERVISOR_CHILD_ENV: &str = "VOLPAROSSA_NETNS_SIGNAL_SUPERVISOR_CHILD";

    #[test]
    fn managed_signal_names_are_exact() {
        for (name, signal) in [
            ("HUP", ManagedSignal::Hup),
            ("INT", ManagedSignal::Int),
            ("TERM", ManagedSignal::Term),
        ] {
            assert_eq!(ManagedSignal::parse(name).expect("managed signal"), signal);
            assert_eq!(signal.as_str(), name);
        }
        for invalid in ["", "SIGTERM", "term", "CHLD", "TIMEOUT"] {
            assert!(ManagedSignal::parse(invalid).is_err());
        }
    }

    #[test]
    fn raw_managed_signal_classification_is_closed() {
        assert_eq!(
            ManagedSignal::from_raw(u32::try_from(Signal::SIGHUP as i32).expect("HUP"))
                .expect("HUP classification"),
            Some(ManagedSignal::Hup)
        );
        assert_eq!(
            ManagedSignal::from_raw(u32::try_from(Signal::SIGCHLD as i32).expect("CHLD"))
                .expect("CHLD classification"),
            None
        );
        assert!(ManagedSignal::from_raw(9).is_err());
        assert!(ManagedSignal::from_raw(u32::MAX).is_err());
    }

    #[test]
    fn absolute_deadline_rejects_expiry() {
        let deadline = AbsoluteDeadline(Instant::now());
        assert_eq!(
            deadline.ensure_unexpired().expect_err("expired").kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn pending_signal_policy_prioritizes_termination_and_bounds_final_child() {
        let both = PendingSignals {
            termination: Some(ManagedSignal::Term),
            child: true,
        };
        assert!(matches!(
            reject_outer_pending(&both),
            Err(SupervisedReceiveError::Termination(ManagedSignal::Term))
        ));
        assert!(matches!(
            reject_outer_pending(&PendingSignals {
                termination: None,
                child: true,
            }),
            Err(SupervisedReceiveError::UnexpectedChildSignal)
        ));

        let mut child_observed = false;
        observe_final_outer_pending(
            &PendingSignals {
                termination: None,
                child: true,
            },
            &mut child_observed,
        )
        .expect("one final child signal");
        assert!(child_observed);
        assert!(
            observe_final_outer_pending(
                &PendingSignals {
                    termination: None,
                    child: true,
                },
                &mut child_observed,
            )
            .is_err()
        );
    }

    #[test]
    fn supervisors_use_kernel_masks_signalfd_and_cross_channel_barriers_in_subprocesses() {
        if let Some(mode) = env::var_os(SUPERVISOR_CHILD_ENV) {
            match mode.to_str() {
                Some("reject-inherited") => test_reject_inherited_mask_child(),
                Some("outer") => test_outer_supervisor_child(),
                Some("pid-one") => test_pid_one_supervisor_child(),
                Some("pid-one-lifecycle") => test_pid_one_lifecycle_record_child(),
                _ => panic!("unexpected signal-supervisor child mode"),
            }
            return;
        }

        let executable = env::current_exe().expect("current test executable");
        for mode in ["reject-inherited", "outer", "pid-one", "pid-one-lifecycle"] {
            let status = Command::new(&executable)
                .arg("--exact")
                .arg(
                    "signals::tests::supervisors_use_kernel_masks_signalfd_and_cross_channel_barriers_in_subprocesses",
                )
                .arg("--test-threads=1")
                .arg("--nocapture")
                .env(SUPERVISOR_CHILD_ENV, mode)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .status()
                .expect("spawn isolated signal-supervisor test");
            assert!(status.success(), "signal-supervisor mode {mode}");
        }
    }

    fn test_reject_inherited_mask_child() {
        assert_eq!(
            SigSet::thread_get_mask().expect("initial signal mask"),
            SigSet::empty()
        );
        let mut inherited = SigSet::empty();
        inherited.add(Signal::SIGUSR1);
        inherited
            .thread_set_mask()
            .expect("set inherited test mask");
        let error = match FixedSignalSupervisor::install_outer() {
            Ok(_) => panic!("inherited mask must fail"),
            Err(error) => error,
        };
        assert_eq!(error.kind(), io::ErrorKind::InvalidData);
        assert_eq!(
            SigSet::thread_get_mask().expect("unchanged inherited mask"),
            inherited
        );
        SigSet::empty()
            .thread_set_mask()
            .expect("restore child test mask");
    }

    fn test_outer_supervisor_child() {
        let supervisor = FixedSignalSupervisor::install_outer().expect("outer supervisor");
        supervisor.verify_outer().expect("outer signal state");
        let (sender, receiver) = LifecycleChannel::pair().expect("protocol channel");
        sender.send(b"protocol").expect("queued protocol record");
        raise(Signal::SIGTERM).expect("queue termination");
        assert!(matches!(
            supervisor.receive_outer(
                &receiver,
                AbsoluteDeadline::after(Duration::from_secs(2)).expect("deadline"),
            ),
            Err(SupervisedReceiveError::Termination(ManagedSignal::Term))
        ));
        assert_eq!(
            supervisor
                .receive_outer(
                    &receiver,
                    AbsoluteDeadline::after(Duration::from_secs(2)).expect("deadline"),
                )
                .expect("record after prioritized termination"),
            b"protocol"
        );

        let (final_sender, final_receiver) = LifecycleChannel::pair().expect("final channel");
        raise(Signal::SIGCHLD).expect("queue final child signal");
        final_sender.finish_sending().expect("final lifecycle EOF");
        supervisor
            .receive_outer_final_eof(
                &final_receiver,
                AbsoluteDeadline::after(Duration::from_secs(2)).expect("deadline"),
            )
            .expect("final EOF permits one SIGCHLD");
        drop(supervisor);
        assert_eq!(
            SigSet::thread_get_mask().expect("restored outer mask"),
            SigSet::empty()
        );
    }

    fn test_pid_one_supervisor_child() {
        managed_mask()
            .thread_set_mask()
            .expect("install inherited PID-1 mask");
        let supervisor = FixedSignalSupervisor::install_pid_one().expect("PID-1 supervisor");
        let (bootstrap, bootstrap_parent) = LifecycleChannel::pair().expect("bootstrap channel");
        let (lifecycle, lifecycle_parent) = LifecycleChannel::pair().expect("lifecycle channel");
        raise(Signal::SIGHUP).expect("queue exact PID-1 signal");
        supervisor
            .wait_pid_one_termination(
                &bootstrap,
                &lifecycle,
                ManagedSignal::Hup,
                AbsoluteDeadline::after(Duration::from_secs(2)).expect("deadline"),
            )
            .expect("exact PID-1 signal");

        bootstrap_parent
            .send(b"RETIRE")
            .expect("retire instruction");
        lifecycle_parent.finish_sending().expect("lifecycle EOF");
        assert_eq!(
            supervisor
                .wait_pid_one_retire_barrier(
                    &bootstrap,
                    &lifecycle,
                    AbsoluteDeadline::after(Duration::from_secs(2)).expect("deadline"),
                )
                .expect("PID-1 retire barrier"),
            b"RETIRE"
        );
        supervisor
            .verify_pid_one_quiescent()
            .expect("quiescent PID-1 state");
    }

    fn test_pid_one_lifecycle_record_child() {
        managed_mask()
            .thread_set_mask()
            .expect("install inherited PID-1 mask");
        let supervisor = FixedSignalSupervisor::install_pid_one().expect("PID-1 supervisor");

        assert_pid_one_lifecycle_success(&supervisor);
        assert_pid_one_signal_races_fail(&supervisor);
        assert_pid_one_bootstrap_events_fail(&supervisor);
        assert_pid_one_lifecycle_eof_fails(&supervisor);
        assert_pid_one_duplicate_lifecycle_fails(&supervisor);
        assert_pid_one_post_record_eof_fails(&supervisor);
        assert_pid_one_expired_deadline_fails(&supervisor);
        supervisor
            .verify_pid_one_quiescent()
            .expect("final quiescent PID-1 state");
    }

    fn assert_pid_one_lifecycle_success(supervisor: &FixedSignalSupervisor) {
        let (bootstrap, _bootstrap_parent) =
            LifecycleChannel::pair().expect("success bootstrap channel");
        let (lifecycle, lifecycle_parent) =
            LifecycleChannel::pair().expect("success lifecycle channel");
        lifecycle_parent.send(b"GO").expect("queue GO record");
        assert_eq!(
            receive_pid_one_record(supervisor, &bootstrap, &lifecycle)
                .expect("exact lifecycle record"),
            b"GO"
        );
    }

    fn assert_pid_one_signal_races_fail(supervisor: &FixedSignalSupervisor) {
        for signal in [
            Signal::SIGHUP,
            Signal::SIGINT,
            Signal::SIGTERM,
            Signal::SIGCHLD,
        ] {
            let (bootstrap, _bootstrap_parent) =
                LifecycleChannel::pair().expect("signal bootstrap channel");
            let (lifecycle, lifecycle_parent) =
                LifecycleChannel::pair().expect("signal lifecycle channel");
            lifecycle_parent.send(b"GO").expect("queue raced GO record");
            raise(signal).expect("queue pre-GO signal");
            assert_invalid_receive(
                receive_pid_one_record(supervisor, &bootstrap, &lifecycle),
                "pre-GO signal must fail",
            );
            supervisor
                .verify_pid_one_quiescent()
                .expect("signal failure drains fixed queue");
        }
    }

    fn assert_pid_one_bootstrap_events_fail(supervisor: &FixedSignalSupervisor) {
        let (bootstrap, bootstrap_parent) =
            LifecycleChannel::pair().expect("bootstrap-record channel");
        let (lifecycle, lifecycle_parent) =
            LifecycleChannel::pair().expect("bootstrap-record lifecycle");
        bootstrap_parent
            .send(b"UNEXPECTED")
            .expect("queue bootstrap record");
        lifecycle_parent.send(b"GO").expect("queue raced GO");
        assert_invalid_receive(
            receive_pid_one_record(supervisor, &bootstrap, &lifecycle),
            "bootstrap record must fail",
        );

        let (bootstrap, bootstrap_parent) =
            LifecycleChannel::pair().expect("bootstrap-EOF channel");
        let (lifecycle, lifecycle_parent) =
            LifecycleChannel::pair().expect("bootstrap-EOF lifecycle");
        bootstrap_parent
            .finish_sending()
            .expect("queue bootstrap EOF");
        lifecycle_parent.send(b"GO").expect("queue GO beside EOF");
        assert_invalid_receive(
            receive_pid_one_record(supervisor, &bootstrap, &lifecycle),
            "bootstrap EOF must fail",
        );
    }

    fn assert_pid_one_lifecycle_eof_fails(supervisor: &FixedSignalSupervisor) {
        let (bootstrap, _bootstrap_parent) =
            LifecycleChannel::pair().expect("lifecycle-EOF bootstrap");
        let (lifecycle, lifecycle_parent) =
            LifecycleChannel::pair().expect("lifecycle-EOF channel");
        lifecycle_parent
            .finish_sending()
            .expect("queue lifecycle EOF");
        assert_invalid_receive(
            receive_pid_one_record(supervisor, &bootstrap, &lifecycle),
            "lifecycle EOF must fail",
        );
    }

    fn assert_pid_one_duplicate_lifecycle_fails(supervisor: &FixedSignalSupervisor) {
        let (bootstrap, _bootstrap_parent) = LifecycleChannel::pair().expect("duplicate bootstrap");
        let (lifecycle, lifecycle_parent) = LifecycleChannel::pair().expect("duplicate lifecycle");
        lifecycle_parent.send(b"GO").expect("queue first record");
        lifecycle_parent
            .send(b"DUPLICATE")
            .expect("queue second record");
        assert_invalid_receive(
            receive_pid_one_record(supervisor, &bootstrap, &lifecycle),
            "second lifecycle record must fail",
        );
    }

    fn assert_pid_one_post_record_eof_fails(supervisor: &FixedSignalSupervisor) {
        let (bootstrap, _bootstrap_parent) =
            LifecycleChannel::pair().expect("post-record EOF bootstrap");
        let (lifecycle, lifecycle_parent) =
            LifecycleChannel::pair().expect("post-record EOF lifecycle");
        lifecycle_parent
            .send(b"GO")
            .expect("queue record before EOF");
        lifecycle_parent
            .finish_sending()
            .expect("queue EOF after record");
        assert_invalid_receive(
            receive_pid_one_record(supervisor, &bootstrap, &lifecycle),
            "already-pending lifecycle EOF must fail",
        );
    }

    fn assert_pid_one_expired_deadline_fails(supervisor: &FixedSignalSupervisor) {
        let (bootstrap, _bootstrap_parent) = LifecycleChannel::pair().expect("expired bootstrap");
        let (lifecycle, lifecycle_parent) = LifecycleChannel::pair().expect("expired lifecycle");
        lifecycle_parent
            .send(b"GO")
            .expect("queue record before expiry");
        assert_eq!(
            supervisor
                .receive_pid_one_lifecycle_record(
                    &bootstrap,
                    &lifecycle,
                    AbsoluteDeadline(Instant::now()),
                )
                .expect_err("expired lifecycle admission must fail")
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    fn receive_pid_one_record(
        supervisor: &FixedSignalSupervisor,
        bootstrap: &LifecycleChannel,
        lifecycle: &LifecycleChannel,
    ) -> io::Result<Vec<u8>> {
        supervisor.receive_pid_one_lifecycle_record(
            bootstrap,
            lifecycle,
            AbsoluteDeadline::after(Duration::from_secs(2)).expect("PID-1 lifecycle deadline"),
        )
    }

    fn assert_invalid_receive(result: io::Result<Vec<u8>>, expectation: &str) {
        let error = result.expect_err(expectation);
        assert_eq!(error.kind(), io::ErrorKind::InvalidData, "{error}");
    }
}
