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

/// Steps of the original bounded challenge frame read.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadStep {
    /// Read the original four-byte length.
    LengthRead,
    /// Read the bounded body.
    BodyRead,
    /// Decode and verify synchronously, without adding a timeout.
    Verification,
}

/// Only errors actually returned by the original wire exchange.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReadFailure {
    /// `UnexpectedEof` from the original read.
    IoEof,
    /// Another returned I/O error.
    IoOther,
    /// Invalid original frame or clock input.
    Invalid,
    /// Challenge decoding or authentication rejected the original frame.
    VerificationRejected,
    /// The original wire timeout returned.
    WireTimeout,
}

/// Synchronous observation only: implementations must not block or change I/O.
pub trait Observer: Sync {
    /// Enter a boundary without exposing its bytes or any runtime identifier.
    fn phase(&self, phase: Phase);
    /// Observe an original frame-read step; old observers remain unchanged.
    fn read_step(&self, _: ReadStep) {}
    /// Observe a returned error without exposing its text; absence implies no cause.
    fn read_failure(&self, _: ReadFailure) {}
}

pub(super) struct Unobserved;

impl Observer for Unobserved {
    fn phase(&self, _: Phase) {}
}
