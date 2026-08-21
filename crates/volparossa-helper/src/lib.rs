//! Minimal privileged service boundary for VOLPAROSSA network operations.
//!
//! Production requests arrive over a fixed root-owned Unix socket and are authenticated with
//! Linux peer credentials. The v3 production lease backend currently fails closed with
//! `Unavailable` and spawns no worker. The private worker entry can now bootstrap and prove narrow
//! network-namespace, capability, descriptor, and credential confinement, but that lifecycle,
//! kernel preparation, and transaction-wide cleanup are not yet connected to the engine. It is not
//! full worker isolation: the effective-UID-0 child retains same-UID signal authority over the
//! parent and access to root-owned runtime socket/token paths; leader retirement does not own
//! descendants.

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
pub use runtime::{AGENT_ACCOUNT, RUNTIME_DIRECTORY, SOCKET_PATH, TOKEN_PATH};
pub use server::{AllowedPeer, ServerError, bind_production_socket, run_server};

/// Fixed private child-process selector; it is not an agent-facing helper operation.
#[doc(hidden)]
pub const INTERNAL_WORKER_V3_ARGUMENT: &str = worker_v3::INTERNAL_WORKER_V3_ARGUMENT;

/// Runs the isolated worker-v3 child entry after its parent-authentication checks.
#[doc(hidden)]
#[must_use]
pub fn run_internal_worker_v3_entry() -> bool {
    worker_v3::run_internal_worker_v3_entry()
}
