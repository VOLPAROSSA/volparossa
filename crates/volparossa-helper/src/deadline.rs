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

/// One absolute monotonic deadline which can be copied through a complete kernel transaction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct HardDeadline {
    expires_at: Instant,
}

impl HardDeadline {
    /// Construct a deadline relative to the current monotonic clock.
    pub(crate) fn after(duration: Duration) -> io::Result<Self> {
        if duration.is_zero() {
            return Err(timed_out());
        }
        let expires_at = Instant::now()
            .checked_add(duration)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidInput, "deadline overflow"))?;
        Ok(Self { expires_at })
    }

    /// Construct a deadline from one already-established monotonic instant.
    ///
    /// This rejects an instant which is already at or behind the current clock. Callers can
    /// therefore copy the returned value through a transaction without silently reviving an
    /// expired operation by creating a new relative timeout.
    pub(crate) fn at(expires_at: Instant) -> io::Result<Self> {
        let deadline = Self { expires_at };
        deadline.ensure_remaining()?;
        Ok(deadline)
    }

    /// Return the exact monotonic expiry carried by this deadline.
    pub(crate) const fn expires_at(self) -> Instant {
        self.expires_at
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
        let terminal = events.intersects(PollFlags::POLLERR | PollFlags::POLLNVAL)
            || (events.contains(PollFlags::POLLHUP)
                && (!allow_hangup_with_readiness || !events.contains(required)));
        if terminal || !events.contains(required) {
            return Err(io::Error::other("descriptor readiness is invalid"));
        }
        deadline.ensure_remaining()?;
        return Ok(());
    }
}

fn timed_out() -> io::Error {
    io::Error::new(io::ErrorKind::TimedOut, "helper operation deadline elapsed")
}

#[cfg(test)]
mod tests {
    use std::{
        io::{Read, Write},
        os::unix::net::UnixStream,
    };

    use super::*;

    #[test]
    fn timeout_is_absolute_and_never_resets_between_steps() {
        let start = Instant::now();
        let deadline = HardDeadline {
            expires_at: start + Duration::from_secs(3),
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
    fn completion_cannot_report_success_after_expiry() {
        let expired = HardDeadline {
            expires_at: Instant::now(),
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
}
