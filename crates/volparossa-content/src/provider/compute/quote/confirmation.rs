//! Explicit, same-connection key confirmation after reference evidence verification.
//!
//! This profile sends only a fresh internally generated random probe. Key possession
//! is not approved key origin, complete appraisal, private-input release or execution.
//! Existing selector-v1 quote-only/refusal bytes are unchanged. These private in-memory
//! records contain identifying evidence and must never be logged or published.

mod client;
mod server;
mod transport;
mod wire;

pub use client::{ConfirmedSession, PreparedConfirmation};
pub use transport::{
    RelayConnection, begin, read_offer, read_probe, read_reply, write_offer, write_probe,
    write_reply,
};
pub use wire::{ConfirmationReply, Offer, Probe};

/// Explicit confirmation version; the original quote-only selector is version one.
pub const SELECTOR_VERSION: u32 = 2;
/// Maximum canonical HPKE probe. The actual ciphertext is exactly 48 bytes.
pub const MAX_PROBE_BYTES: usize = 272;
/// Original three signed records, never a public/exportable transcript.
pub const MAX_OFFER_BYTES: usize = 4096;
/// Signed probe/request and matching signed response; no raw arbitrary plaintext.
pub const MAX_REPLY_BYTES: usize = 2048;

#[cfg(test)]
mod tests;
