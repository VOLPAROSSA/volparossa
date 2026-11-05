//! Optional synchronous observations. Verified request references grant no tracing or operation authority.

use crate::private_storage::protocol::VerifiedStorageRequest;
use std::sync::Arc;

/// Receipt boundaries separate from the legacy connection-stage observer.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum RequestStage {
    /// Enter the exact signed receipt frame write/flush.
    ReceiptWriteEntered,
    /// That frame's write/flush actually returned success.
    ReceiptFlushReturned,
}

/// Optional owned observation of the existing blocking worker, never operation authority.
pub trait WorkerObserver: Send + Sync {
    /// Immediately before the actual backend call (not queueing or permit acquisition).
    fn entered(&self);
    /// Only after that backend call returns normally, with its original result unchanged.
    fn returned(&self, success: bool);
}

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
    /// Optional fixture-only verified binding; implementations must not retain request data.
    fn verified_request(&self, _request: &VerifiedStorageRequest) {}
    /// Optional finite receipt boundary.
    fn request_stage(&self, _stage: RequestStage) {}
    /// Default-off owned observer; no worker task or I/O is created by this hook.
    fn worker(&self) -> Option<Arc<dyn WorkerObserver>> {
        None
    }
}

impl Observer for () {
    fn enter(&self, _stage: Stage) {}
}
