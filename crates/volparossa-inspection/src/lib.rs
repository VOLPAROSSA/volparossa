//! Fail-closed inspection of visible TLS and QUIC destination metadata.
//!
//! This crate authenticates and decrypts client QUIC v1 Initial packets and
//! parses bounded TLS `ClientHello` messages. It only reports a normalized,
//! plaintext SNI. It does not authorize that name against a manifest and does
//! not itself enforce an egress decision.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

mod error;
mod quic;
mod tls;

pub use error::InspectionError;
pub use quic::{QuicInitialInspector, QuicInspection};
pub use tls::{
    InspectedServerName, InspectionProgress, TlsClientHelloInspector, inspect_client_hello,
};
