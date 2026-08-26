//! Minimal privileged service boundary for VOLPAROSSA network operations.
//!
//! Production requests arrive over a fixed root-owned Unix socket and are authenticated with
//! Linux peer credentials. The v3 production lease backend currently fails closed with
//! `Unavailable` and spawns no worker. The private worker entry can now bootstrap and prove narrow
//! network-namespace, capability, descriptor, credential and dedicated non-root identity
//! confinement, but that lifecycle, kernel preparation, transaction-wide cleanup and disposable
//! live-root proof are not yet connected to the engine. Production does own the canonical durable
//! journal actor as a startup/shutdown barrier, but deliberately refuses `MayOwnPrepare` recovery;
//! it has no request-path issuance/arming writer or restart-stable pidfd/network-namespace custody.
//! Leader retirement still does not own descendants.

#![cfg(target_os = "linux")]

#[allow(dead_code)] // Shared hard-deadline substrate; production backend remains disconnected.
mod deadline;
#[path = "engine_v3.rs"]
mod engine;
#[allow(dead_code)] // Secret-free v3 worker API foundation; no production spawn path exists yet.
mod internal_protocol;
#[allow(dead_code)] // V3 link primitives remain isolated until the production backend is wired.
mod kernel;
#[allow(dead_code)] // Secret-free topology derivation used by the future v3 worker.
mod lease_spec;
#[allow(dead_code)] // V3 endpoint ownership remains isolated until worker-v3 wiring lands.
mod mptcp_endpoint;
mod ownership_journal;
#[allow(dead_code)] // Secret-free v3 relay fences remain fail-closed until worker-v3 wiring.
mod relay_fence;
mod runtime;
mod server;
mod systemd_custody;
#[allow(dead_code)] // Dormant exact FD-store adapter; no production handoff caller exists yet.
mod systemd_fdstore;
#[allow(dead_code)] // Pure phase-1 policy; rtnetlink collection is wired in helper v3 phase 2.
mod underlay;
#[allow(dead_code)] // Narrow sandbox bootstrap; production engine still never spawns it.
mod worker_sandbox;
#[allow(dead_code)] // V3 transport foundation; production worker lifecycle remains unavailable.
mod worker_transport;
#[allow(dead_code)] // Authenticated lifecycle foundation; production engine remains unavailable.
mod worker_v3;

pub use engine::HelperEngine;
#[doc(hidden)]
pub use relay_fence::{INTERNAL_NFT_FRONTEND_ARGUMENT, run_internal_nft_frontend};
pub use runtime::{AGENT_ACCOUNT, RUNTIME_DIRECTORY, SOCKET_PATH, TOKEN_PATH, WORKER_ACCOUNT};
pub use server::{ServerError, run_production_server};

/// Fixed private child-process selector; it is not an agent-facing helper operation.
#[doc(hidden)]
pub const INTERNAL_WORKER_V3_ARGUMENT: &str = worker_v3::INTERNAL_WORKER_V3_ARGUMENT;

/// Fixed private live-proof selector; it accepts no path, environment, or agent input.
#[doc(hidden)]
pub const INTERNAL_WORKER_V3_LIVE_PROOF_ARGUMENT: &str =
    worker_v3::INTERNAL_WORKER_V3_LIVE_PROOF_ARGUMENT;

/// Runs the isolated worker-v3 child entry after its parent-authentication checks.
#[doc(hidden)]
#[must_use]
pub fn run_internal_worker_v3_entry() -> bool {
    worker_v3::run_internal_worker_v3_entry()
}

/// Runs one fixed production-image worker bootstrap and proves bounded retirement.
#[doc(hidden)]
#[must_use]
pub fn run_internal_worker_v3_live_proof() -> bool {
    worker_v3::run_internal_worker_v3_live_proof()
}
