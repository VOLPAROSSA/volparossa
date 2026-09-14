//! Publisher-authorized public custody on an independently authenticated provider stream.
//!
//! A receipt describes this exact operation, not future provider availability. Original
//! manifest expiry never moves. Payload uses the existing bounded chunk protocol; paths and
//! private keys are never accepted from the remote caller.

mod protocol;
mod session;
#[cfg(test)]
mod tests;

use std::{future::Future, pin::Pin, sync::Arc};

use ed25519_dalek::SigningKey;

use crate::{ChunkStore, SignedManifest, VerifiedManifest};

pub use protocol::{CustodyAuthorization, CustodyChallenge, CustodyOperation, CustodyReceipt};
pub use session::{begin, bridge, execute};

/// Additive selector version; no older protocol or direct socket fallback is implied.
pub const SELECTOR_VERSION: u32 = 1;
/// Explicit public custody, separate from mailbox and opportunistic uptake.
pub const SELECTOR_OPERATION: u32 = 4;

/// Bounded operation errors never become committed custody receipts.
#[derive(Debug, thiserror::Error)]
pub enum CustodyError {
    /// Protected stream I/O failed.
    #[error("public custody stream failed")]
    Io(#[from] std::io::Error),
    /// Canonical framing, field bounds, operation or original manifest is invalid.
    #[error("invalid public custody message")]
    Invalid,
    /// The expected publisher/provider did not authorize this exact connection/request.
    #[error("public custody authorization failed")]
    Unauthorized,
    /// Original validity or a connection challenge has expired.
    #[error("public custody authorization expired")]
    Expired,
    /// Operating-system nonce generation failed.
    #[error("public custody randomness unavailable")]
    Entropy,
    /// Original bounded operation deadline elapsed.
    #[error("public custody operation timed out")]
    Timeout,
    /// Configured storage, quota, admission or ready serving is unavailable.
    #[error("public custody storage unavailable")]
    Store,
    /// Existing authenticated chunk transfer failed.
    #[error(transparent)]
    Transfer(#[from] crate::transfer::TransferError),
}

/// Current actual complete custody, not a cached historical receipt.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum CustodyState {
    /// No complete, currently usable stored/served publication was found.
    Missing = 1,
    /// All original chunks/hash and original expiry were checked and serving is ready.
    Complete = 2,
}

/// Object-safe, caller-owned asynchronous admission; cancellation drops its actual owners.
pub type CustodyFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, CustodyError>> + Send + 'a>>;

/// One owned private staging cache and its original local admission/foreground leases.
pub trait CustodyAdmission: Send {
    /// Existing owned staging cache receiving verified chunks; never a remote-supplied path.
    fn store(&mut self) -> &mut ChunkStore;

    /// Consume staged bytes into the configured non-evicting replica journal and register
    /// ready serving. Return success only after complete object/hash verification and durable
    /// admission. A failed or cancelled operation may retain verified prefixes, not a receipt.
    fn commit(self: Box<Self>) -> CustodyFuture<'static, ()>;
}

/// Production adapter to the existing configured contribution store and serving registry.
/// Implementations must not retain a strong registry/service reference cycle.
pub trait CustodyBackend: Send + Sync {
    /// Authenticate local policy/quota and create one owned staging/admission transaction.
    fn begin_deposit(
        &self,
        signed: SignedManifest,
        manifest: VerifiedManifest,
    ) -> CustodyFuture<'_, Box<dyn CustodyAdmission>>;

    /// Revalidate actual retained chunks, complete hash, original journal and ready serving.
    /// Cached receipt metadata alone cannot produce `Complete`.
    fn inspect(
        &self,
        signed: SignedManifest,
        manifest: VerifiedManifest,
    ) -> CustodyFuture<'_, CustodyState>;
}

/// Existing provider signer plus its explicitly enabled, owned storage adapter.
pub struct CustodyService {
    signer: Arc<SigningKey>,
    backend: Arc<dyn CustodyBackend>,
}

impl CustodyService {
    /// Attach public custody to an existing authenticated service; no listener is opened.
    pub fn new(signer: Arc<SigningKey>, backend: Arc<dyn CustodyBackend>) -> Self {
        Self { signer, backend }
    }
}
