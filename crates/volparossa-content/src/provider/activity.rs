//! Optional, synchronous receiving-side progress observations. No request data or authority.

/// Last entered server boundary, not evidence that a peer reached the same boundary.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Stage {
    /// Accepting application TLS.
    TlsHandshake,
    /// Obtaining the bounded publication registry snapshot.
    RegistrySnapshot,
    /// Reading the protocol selector.
    SelectorRead,
    /// Reading and verifying the private-storage grant.
    StorageGrantReadVerify,
    /// Writing and flushing the signed challenge.
    StorageChallengeWriteFlush,
    /// Reading and verifying the owner's signed request after the challenge flush.
    StorageRequestReadVerify,
    /// Processing a verified storage request, including its receipt.
    StorageOperation,
    /// Serving a selector other than private storage.
    OtherProtocol,
    /// Closing the application exchange or recording its terminal failure.
    Closing,
}

/// Implementations must be bounded, nonblocking, infallible and must not change the protocol.
pub trait Observer: Send + Sync {
    /// Record only the newly entered finite boundary.
    fn enter(&self, stage: Stage);
}

impl Observer for () {
    fn enter(&self, _stage: Stage) {}
}
