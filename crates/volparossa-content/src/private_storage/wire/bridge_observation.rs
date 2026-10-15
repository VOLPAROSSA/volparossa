//! Closed local bridge boundaries; no wire bytes, runtime IDs or inferred remote causes.

/// Last boundary actually polled by the bridge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Phase {
    /// Read owner request framing.
    LocalRequestRead,
    /// Verify owner signature and connection binding.
    LocalRequestVerify,
    /// Read append ciphertext.
    LocalPayloadRead,
    /// Verify append bytes.
    LocalPayloadVerify,
    /// Await existing byte admission.
    Admission,
    /// Reverify request before remote write.
    RemoteRequestVerify,
    /// Write signed provider request.
    RemoteRequestWrite,
    /// Write append bytes to provider.
    RemotePayloadWrite,
    /// Read provider receipt framing.
    RemoteReceiptRead,
    /// Verify provider receipt.
    RemoteReceiptVerify,
    /// Read authorized range.
    RemotePayloadRead,
    /// Verify range and current request validity.
    RemotePayloadVerify,
    /// Write original verified receipt to owner.
    LocalReceiptWrite,
    /// Write authorized range to owner.
    LocalPayloadWrite,
}

/// A timeout observed in the existing wire implementation.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Deadline {
    /// Whole local bridge budget.
    Bridge,
    /// Inner protected-provider exchange budget.
    RemoteWire,
}

/// Synchronous observation only: implementors must not block or alter stream behavior.
pub trait Observer: Sync {
    /// Enter a boundary without recording input or output data.
    fn phase(&self, phase: Phase);
    /// An existing timeout elapsed; this does not imply that custody did not commit.
    fn deadline(&self, deadline: Deadline);
}

pub(super) struct Unobserved;

impl Observer for Unobserved {
    fn phase(&self, _: Phase) {}
    fn deadline(&self, _: Deadline) {}
}
