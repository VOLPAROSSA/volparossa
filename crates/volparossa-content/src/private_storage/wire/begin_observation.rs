//! Request-local grant/challenge progress, without input, output or extra I/O.

/// Last existing boundary actually entered by the grant/challenge exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Write and flush the original selector frame.
    SelectorWriteFlush,
    /// Write and flush the original signed grant frame.
    GrantWriteFlush,
    /// Read and verify the original signed challenge frame.
    ChallengeReadVerify,
}

/// Synchronous observation only: implementations must not block or change I/O.
pub trait Observer: Sync {
    /// Enter a boundary without exposing its bytes or any runtime identifier.
    fn phase(&self, phase: Phase);
}

pub(super) struct Unobserved;

impl Observer for Unobserved {
    fn phase(&self, _: Phase) {}
}
