//! Provider-authorized private ciphertext custody, separate from public content and mailboxes.
//!
//! Trust in a provider key comes from the caller, never from a key found in a message.
//! A provider grants a known application owner bounded custody rights. Each owner operation
//! signs a fresh provider challenge and the exact immutable archive, lease and operation.
//! This module checks bounded canonical metadata and signatures only: the service must
//! consume challenges once on their original connection, persist capability/lease ownership,
//! enforce aggregate quota (including every physical copy), and actually execute operations.
//! A signed receipt is a request-bound provider statement, not proof of available disk,
//! future retention, independent replicas or network-wide reciprocal contribution.
//!
//! Ciphertext is transferred separately: at most one 256 KiB append chunk or 16 MiB read
//! range. No plaintext, URLs, filesystem paths, decryption keys or training permissions occur
//! in these messages. Supplying ciphertext does not itself prove that it was encrypted.

mod envelope;
mod grant;
mod receipt;
mod request;

pub use grant::{GrantLimits, SignedStorageGrant, StorageRights, VerifiedStorageGrant};
pub use receipt::{ReceiptResult, ReceiptState, SignedStorageReceipt};
pub use request::{
    SignedStorageRequest, StorageChallenge, StorageOperation, StorageTarget, VerifiedStorageRequest,
};

/// Largest canonical provider grant, checked before protobuf decoding.
pub const MAX_GRANT_BYTES: usize = 2048;
/// Largest fresh provider challenge, checked before protobuf decoding.
pub const MAX_CHALLENGE_BYTES: usize = 1024;
/// Largest signed operation metadata; ciphertext is never embedded in this frame.
pub const MAX_REQUEST_BYTES: usize = 4096;
/// Largest signed result metadata; read payload is transferred separately.
pub const MAX_RECEIPT_BYTES: usize = 2048;
/// Maximum challenge, operation or receipt validity interval in seconds.
pub const MAX_AUTH_SECONDS: u64 = 120;

/// Bounded authentication failure, without private paths or payloads in its display text.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum ProtocolError {
    /// Noncanonical, unsupported, missing, oversized or internally contradictory fields.
    #[error("invalid private storage protocol message")]
    Invalid,
    /// The independently trusted key or exact grant/challenge/request scope does not agree.
    #[error("private storage authorization failed")]
    Unauthorized,
    /// A signed validity window has not begun or has elapsed.
    #[error("private storage authorization is not current")]
    Expired,
    /// The operating system did not supply secure randomness.
    #[error("private storage secure randomness unavailable")]
    Entropy,
}

#[cfg(test)]
mod tests;
