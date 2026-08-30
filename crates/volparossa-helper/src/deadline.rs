//! Shared monotone hard deadlines for blocking helper kernel transactions.
//!
//! A caller creates one deadline at the outer operation boundary and passes the same value through
//! every send, acknowledgement, dump frame and proof read. Waiting never creates a fresh timeout.

use std::{
    io,
    os::fd::AsFd,
    time::{Duration, Instant},
};

use nix::poll::{PollFd, PollFlags, poll};
use rustix::time::{ClockId, clock_gettime};

const NANOSECONDS_PER_SECOND: u64 = 1_000_000_000;

/// One absolute monotonic deadline which can be copied through a complete kernel transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HardDeadline {
    expires_at: Instant,
    monotonic_expires_at_ns: u64,
}

impl HardDeadline {
    /// Construct a deadline relative to the current monotonic clock.
    pub(crate) fn after(duration: Duration) -> io::Result<Self> {
        if duration.is_zero() {
            return Err(timed_out());
        }
        let monotonic_now = monotonic_now_nanos()?;
        let monotonic_expires_at_ns = monotonic_now
            .checked_add(duration_nanos(duration)?)
            .ok_or_else(deadline_overflow)?;
        let expires_at = Instant::now()
            .checked_add(duration)
            .ok_or_else(deadline_overflow)?;
        Ok(Self {
            expires_at,
            monotonic_expires_at_ns,
        })
    }

    /// Construct a deadline from one already-established monotonic instant.
    ///
    /// This rejects an instant which is already at or behind the current clock. Callers can
    /// therefore copy the returned value through a transaction without silently reviving an
    /// expired operation by creating a new relative timeout.
    pub(crate) fn at(expires_at: Instant) -> io::Result<Self> {
        // Sample CLOCK_MONOTONIC before `Instant`. Adding the subsequently observed remaining
        // budget therefore projects an absolute wire deadline no later than this caller's
        // original `Instant` deadline on the Debian/Linux target.
        let monotonic_now = monotonic_now_nanos()?;
        let remaining = expires_at
            .checked_duration_since(Instant::now())
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(timed_out)?;
        let monotonic_expires_at_ns = monotonic_now
            .checked_add(duration_nanos(remaining)?)
            .ok_or_else(deadline_overflow)?;
        let deadline = Self {
            expires_at,
            monotonic_expires_at_ns,
        };
        deadline.ensure_remaining()?;
        Ok(deadline)
    }

    /// Reconstruct a local deadline from one parent-supplied Linux `CLOCK_MONOTONIC` expiry.
    ///
    /// `Instant` is sampled before `CLOCK_MONOTONIC`, so the local projection cannot extend the
    /// transmitted absolute boundary. Equality, elapsed values and a budget above the operation's
    /// fixed maximum fail closed.
    pub(crate) fn from_monotonic_expiry_nanos(
        monotonic_expires_at_ns: u64,
        maximum_budget: Duration,
    ) -> io::Result<Self> {
        if monotonic_expires_at_ns == 0 || maximum_budget.is_zero() {
            return Err(invalid_deadline());
        }
        let instant_now = Instant::now();
        let monotonic_now = monotonic_now_nanos()?;
        let remaining_ns = monotonic_expires_at_ns
            .checked_sub(monotonic_now)
            .filter(|remaining| *remaining != 0)
            .ok_or_else(timed_out)?;
        if remaining_ns > duration_nanos(maximum_budget)? {
            return Err(invalid_deadline());
        }
        let expires_at = instant_now
            .checked_add(Duration::from_nanos(remaining_ns))
            .ok_or_else(deadline_overflow)?;
        let deadline = Self {
            expires_at,
            monotonic_expires_at_ns,
        };
        deadline.ensure_remaining()?;
        Ok(deadline)
    }

    /// Return the fixed cross-process Linux `CLOCK_MONOTONIC` expiry without refreshing it.
    pub(crate) fn monotonic_expiry_nanos(self) -> io::Result<u64> {
        self.ensure_remaining()?;
        if monotonic_now_nanos()? >= self.monotonic_expires_at_ns {
            return Err(timed_out());
        }
        Ok(self.monotonic_expires_at_ns)
    }

    /// Return the exact monotonic expiry carried by this deadline.
    pub(crate) const fn expires_at(self) -> Instant {
        self.expires_at
    }

    /// Derive an earlier absolute deadline while preserving a tail of the original budget.
    ///
    /// Mutation code uses this to leave bounded reconciliation and cleanup time inside the one
    /// caller-supplied operation deadline. The returned deadline never refreshes either clock.
    pub(crate) fn before_tail(self, tail: Duration) -> io::Result<Self> {
        if tail.is_zero() {
            return Err(invalid_deadline());
        }
        let tail_ns = duration_nanos(tail)?;
        let expires_at = self.expires_at.checked_sub(tail).ok_or_else(timed_out)?;
        let monotonic_expires_at_ns = self
            .monotonic_expires_at_ns
            .checked_sub(tail_ns)
            .ok_or_else(timed_out)?;
        let deadline = Self {
            expires_at,
            monotonic_expires_at_ns,
        };
        deadline.ensure_remaining()?;
        Ok(deadline)
    }

    /// Return the remaining budget without extending the absolute deadline.
    pub(crate) fn remaining(self) -> io::Result<Duration> {
        self.remaining_at(Instant::now())
    }

    /// Fail before performing another I/O operation once the absolute deadline has elapsed.
    pub(crate) fn ensure_remaining(self) -> io::Result<()> {
        self.remaining_at(Instant::now()).map(|_| ())
    }

    /// Return a completed value only while the transaction deadline is still live.
    pub(crate) fn complete<T>(self, value: T) -> io::Result<T> {
        self.ensure_remaining()?;
        Ok(value)
    }

    fn poll_timeout(self) -> io::Result<u16> {
        self.poll_timeout_at(Instant::now())
    }

    fn remaining_at(self, now: Instant) -> io::Result<Duration> {
        self.expires_at
            .checked_duration_since(now)
            .filter(|remaining| !remaining.is_zero())
            .ok_or_else(timed_out)
    }

    fn poll_timeout_at(self, now: Instant) -> io::Result<u16> {
        let remaining = self.remaining_at(now)?;
        let whole_milliseconds = remaining.as_millis();
        let has_fraction = remaining.subsec_nanos() % 1_000_000 != 0;
        let rounded_up = whole_milliseconds.saturating_add(u128::from(has_fraction));
        u16::try_from(rounded_up.clamp(1, u128::from(u16::MAX)))
            .map_err(|_| io::Error::new(io::ErrorKind::InvalidInput, "deadline is invalid"))
    }
}

/// Wait for one exact readiness class without ever resetting `deadline`.
pub(crate) fn wait_for_fd<F: AsFd>(
    descriptor: &F,
    required: PollFlags,
    deadline: HardDeadline,
) -> io::Result<()> {
    wait_for_fd_inner(descriptor, required, deadline, false)
}

/// Wait for readable data while permitting a simultaneous peer hangup.
///
/// Linux reports `POLLIN | POLLHUP` when a seqpacket peer queues its terminal record and exits.
/// The record must still be consumed and authenticated. A bare hangup, `POLLERR`, and `POLLNVAL`
/// remain terminal errors.
pub(crate) fn wait_for_readable_fd<F: AsFd>(
    descriptor: &F,
    deadline: HardDeadline,
) -> io::Result<()> {
    wait_for_fd_inner(descriptor, PollFlags::POLLIN, deadline, true)
}

/// Wait for terminal readiness from one exact Linux process pidfd.
///
/// A process pidfd created without `PIDFD_THREAD` reports `POLLIN` only after the last thread in
/// the thread group exits. Reaping may additionally report `POLLHUP`. No other readiness bit is
/// accepted, and a bare hangup is not enough to construct exit evidence.
pub(crate) fn wait_for_process_pidfd_exit<F: AsFd>(
    descriptor: &F,
    deadline: HardDeadline,
) -> io::Result<()> {
    wait_for_fd_events(
        descriptor,
        PollFlags::POLLIN,
        deadline,
        exact_process_pidfd_exit_events,
    )
}

fn wait_for_fd_inner<F: AsFd>(
    descriptor: &F,
    required: PollFlags,
    deadline: HardDeadline,
    allow_hangup_with_readiness: bool,
) -> io::Result<()> {
    if required.is_empty()
        || required.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
    {
        return Err(io::Error::new(
            io::ErrorKind::InvalidInput,
            "invalid readiness class",
        ));
    }

    wait_for_fd_events(descriptor, required, deadline, move |events| {
        let terminal = events.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL)
            || (events.contains(PollFlags::POLLHUP)
                && (!allow_hangup_with_readiness || !events.contains(required)));
        !terminal && events.contains(required)
    })
}

fn wait_for_fd_events<F: AsFd>(
    descriptor: &F,
    required: PollFlags,
    deadline: HardDeadline,
    events_are_valid: impl Fn(PollFlags) -> bool,
) -> io::Result<()> {
    loop {
        deadline.ensure_remaining()?;
        let mut descriptors = [PollFd::new(descriptor.as_fd(), required)];
        let ready = match poll(&mut descriptors, deadline.poll_timeout()?) {
            Ok(ready) => ready,
            Err(nix::errno::Errno::EINTR) => continue,
            Err(error) => return Err(io::Error::from_raw_os_error(error as i32)),
        };
        if ready == 0 {
            continue;
        }
        let events = descriptors[0]
            .revents()
            .ok_or_else(|| io::Error::other("poll returned no readiness state"))?;
        if !events_are_valid(events) {
            return Err(io::Error::other("descriptor readiness is invalid"));
        }
        deadline.ensure_remaining()?;
        return Ok(());
    }
}

fn exact_process_pidfd_exit_events(events: PollFlags) -> bool {
    events == PollFlags::POLLIN || events == (PollFlags::POLLIN | PollFlags::POLLHUP)
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "helper operation deadline elapsed")
}

fn invalid_deadline() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "helper deadline is invalid")
}

fn deadline_overflow() -> io::Error {
    io::Error::new(io::ErrorKind::InvalidInput, "deadline overflow")
}

fn duration_nanos(duration: Duration) -> io::Result<u64> {
    u64::try_from(duration.as_nanos()).map_err(|_| deadline_overflow())
}

fn monotonic_now_nanos() -> io::Result<u64> {
    let now = clock_gettime(ClockId::Monotonic);
    let seconds = u64::try_from(now.tv_sec).map_err(|_| invalid_deadline())?;
    let nanoseconds = u64::try_from(now.tv_nsec).map_err(|_| invalid_deadline())?;
    if nanoseconds >= NANOSECONDS_PER_SECOND {
        return Err(invalid_deadline());
    }
    seconds
        .checked_mul(NANOSECONDS_PER_SECOND)
        .and_then(|value| value.checked_add(nanoseconds))
        .ok_or_else(deadline_overflow)
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
        process::Command,
    };

    use rustix::process::{PidfdFlags, pidfd_open};

    use super::*;

    #[test]
    fn timeout_is_absolute_and_never_resets_between_steps() {
        let start = Instant::now();
        let deadline = HardDeadline {
            expires_at: start + Duration::from_secs(3),
            monotonic_expires_at_ns: monotonic_now_nanos().expect("monotonic clock")
                + 3_000_000_000,
        };
        assert_eq!(
            deadline.poll_timeout_at(start).expect("initial budget"),
            3_000
        );
        assert_eq!(
            deadline
                .poll_timeout_at(start + Duration::from_secs(2))
                .expect("remaining budget"),
            1_000
        );
        assert_eq!(
            deadline
                .poll_timeout_at(start + Duration::from_micros(2_999_500))
                .expect("sub-millisecond budget"),
            1
        );
        assert_eq!(
            deadline
                .poll_timeout_at(start + Duration::from_secs(3))
                .expect_err("expired deadline")
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn earlier_deadline_reserves_an_exact_tail_without_refreshing_outer_budget() {
        let outer = HardDeadline::after(Duration::from_secs(2)).expect("outer deadline");
        let inner = outer
            .before_tail(Duration::from_millis(400))
            .expect("reserved tail");
        assert_eq!(
            outer.expires_at().duration_since(inner.expires_at()),
            Duration::from_millis(400)
        );
        assert!(inner.remaining().expect("inner remaining") < outer.remaining().expect("outer"));
        assert!(outer.before_tail(Duration::ZERO).is_err());
        assert!(outer.before_tail(Duration::from_secs(3)).is_err());
    }

    #[test]
    fn completion_cannot_report_success_after_expiry() {
        let expired = HardDeadline {
            expires_at: Instant::now(),
            monotonic_expires_at_ns: monotonic_now_nanos().expect("monotonic clock"),
        };
        assert_eq!(
            expired
                .complete(7_u8)
                .expect_err("expired completion")
                .kind(),
            io::ErrorKind::TimedOut
        );

        let live = HardDeadline::after(Duration::from_secs(1)).expect("live deadline");
        assert_eq!(live.complete(7_u8).expect("live completion"), 7);
    }

    #[test]
    fn socketpair_wait_obeys_readiness_and_expired_wait_consumes_nothing() {
        let (mut sender, mut receiver) = UnixStream::pair().expect("socketpair");
        sender.write_all(b"x").expect("one byte");
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("deadline");
        wait_for_fd(&receiver, PollFlags::POLLIN, deadline).expect("readable");

        let expired = HardDeadline {
            expires_at: Instant::now(),
            monotonic_expires_at_ns: monotonic_now_nanos().expect("monotonic clock"),
        };
        assert_eq!(
            wait_for_fd(&receiver, PollFlags::POLLIN, expired)
                .expect_err("expired before poll")
                .kind(),
            io::ErrorKind::TimedOut
        );
        let mut byte = [0_u8; 1];
        receiver.read_exact(&mut byte).expect("byte remains queued");
        assert_eq!(byte, *b"x");
    }

    #[test]
    fn exact_constructor_preserves_identity_and_rejects_equality() {
        let expires_at = Instant::now() + Duration::from_secs(1);
        let deadline = HardDeadline::at(expires_at).expect("future absolute deadline");
        assert_eq!(deadline.expires_at(), expires_at);
        assert!(deadline.remaining().expect("remaining budget") <= Duration::from_secs(1));

        assert_eq!(
            HardDeadline::at(Instant::now())
                .expect_err("equality is expired")
                .kind(),
            io::ErrorKind::TimedOut
        );
    }

    #[test]
    fn monotonic_wire_expiry_is_fixed_and_child_projection_never_refreshes_it() {
        let parent = HardDeadline::after(Duration::from_millis(200)).expect("parent deadline");
        let wire = parent.monotonic_expiry_nanos().expect("wire deadline");
        std::thread::sleep(Duration::from_millis(5));
        assert_eq!(
            parent
                .monotonic_expiry_nanos()
                .expect("same fixed wire deadline"),
            wire
        );

        let child = HardDeadline::from_monotonic_expiry_nanos(wire, Duration::from_secs(1))
            .expect("bounded child deadline");
        assert_eq!(
            child.monotonic_expiry_nanos().expect("child wire identity"),
            wire
        );
        assert!(child.expires_at() <= parent.expires_at());
        assert!(
            child.remaining().expect("child remaining")
                <= parent.remaining().expect("parent remaining")
        );
    }

    #[test]
    fn monotonic_wire_expiry_rejects_zero_elapsed_equality_and_excess_budget() {
        assert_eq!(
            HardDeadline::from_monotonic_expiry_nanos(0, Duration::from_secs(1))
                .expect_err("zero wire deadline")
                .kind(),
            io::ErrorKind::InvalidInput
        );
        let now = monotonic_now_nanos().expect("monotonic clock");
        for elapsed in [now.saturating_sub(1), now] {
            assert_eq!(
                HardDeadline::from_monotonic_expiry_nanos(elapsed, Duration::from_secs(1))
                    .expect_err("elapsed wire deadline")
                    .kind(),
                io::ErrorKind::TimedOut
            );
        }
        assert_eq!(
            HardDeadline::from_monotonic_expiry_nanos(now + 2_000_000_000, Duration::from_secs(1),)
                .expect_err("overlong wire deadline")
                .kind(),
            io::ErrorKind::InvalidInput
        );
    }

    #[test]
    fn process_pidfd_exit_mask_requires_pollin_and_permits_only_paired_hangup() {
        for accepted in [PollFlags::POLLIN, PollFlags::POLLIN | PollFlags::POLLHUP] {
            assert!(exact_process_pidfd_exit_events(accepted));
        }
        for rejected in [
            PollFlags::empty(),
            PollFlags::POLLHUP,
            PollFlags::POLLERR,
            PollFlags::POLLNVAL,
            PollFlags::POLLIN | PollFlags::POLLERR,
            PollFlags::POLLIN | PollFlags::POLLNVAL,
            PollFlags::POLLPRI,
            PollFlags::POLLIN | PollFlags::POLLPRI,
            PollFlags::POLLHUP | PollFlags::POLLPRI,
        ] {
            assert!(!exact_process_pidfd_exit_events(rejected));
        }
    }

    #[test]
    fn exact_process_pidfd_reports_running_zombie_and_reaped_states() {
        let mut child = Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn live child");
        let pidfd = pidfd_open(
            rustix::process::Pid::from_child(&child),
            PidfdFlags::empty(),
        )
        .expect("open exact process pidfd without PIDFD_THREAD");

        assert_eq!(
            wait_for_process_pidfd_exit(
                &pidfd,
                HardDeadline::after(Duration::from_millis(20)).expect("brief deadline"),
            )
            .expect_err("running process must not report exit")
            .kind(),
            io::ErrorKind::TimedOut
        );

        child.kill().expect("terminate child without reaping");
        let mut zombie = [PollFd::new(pidfd.as_fd(), PollFlags::POLLIN)];
        assert_eq!(poll(&mut zombie, 1_000_u16).expect("poll zombie"), 1);
        assert_eq!(
            zombie[0].revents().expect("zombie readiness"),
            PollFlags::POLLIN
        );

        child.wait().expect("reap child");
        let mut reaped = [PollFd::new(pidfd.as_fd(), PollFlags::POLLIN)];
        assert_eq!(poll(&mut reaped, 1_000_u16).expect("poll reaped"), 1);
        assert_eq!(
            reaped[0].revents().expect("reaped readiness"),
            PollFlags::POLLIN | PollFlags::POLLHUP
        );
    }
}
