//! Bounded owner-private `CometBFT` ABCI socket adapter for fictitious TEST units.
//!
//! This does not start `CometBFT`, certify consensus, expose a public financial API,
//! implement external settlement, or hide commands from a validator's administrator.
#![forbid(unsafe_code)]

mod application;
mod config;
mod server;

/// Types generated directly from the pinned upstream schemas, not hand-written wire types.
// Upstream-generated identifiers and documentation are not local style decisions.
#[allow(missing_docs, clippy::all, clippy::pedantic)]
pub mod proto {
    include!(concat!(env!("OUT_DIR"), "/comet.rs"));
}

pub use application::Application;
pub use config::{Account, Genesis, consensus_params};
pub use server::{MAX_CONNECTIONS, MAX_FRAME_BYTES, Server, read_frame, write_frame};

/// Closed failure classes; responses never include database paths, commands or secrets.
#[derive(Debug, thiserror::Error)]
pub enum Error {
    /// Invalid or mismatching explicit TEST genesis configuration.
    #[error("abci_test_configuration")]
    Configuration,
    /// Unsupported method, invalid framing or impossible consensus lifecycle.
    #[error("abci_test_protocol")]
    Protocol,
    /// A local storage failure stops execution; never a deterministic transaction code.
    #[error("abci_test_store")]
    Store(#[from] volparossa_transaction::Error),
    /// Socket or filesystem error; it is not evidence of transaction failure or success.
    #[error("abci_test_io")]
    Io(#[from] std::io::Error),
}

#[cfg(test)]
mod tests;
