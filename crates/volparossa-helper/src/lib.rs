//! Minimal privileged service boundary for VOLPAROSSA network operations.
//!
//! Production requests arrive over a fixed root-owned Unix socket and are authenticated with
//! Linux peer credentials. The crate-internal production engine executes an authenticated
//! Prepare/Activate/Probe-Commit/Destroy lifecycle for one process-owned functional-alpha Client,
//! Exit, or atomic Relay endpoint pair. Workers use private network namespaces, kernel `WireGuard`
//! UAPI and, for Relay contexts, an exact namespace-local forwarding fence. This is not yet a
//! complete client-to-destination datapath or crash/restart recovery path. The public
//! [`HelperEngine::new`] constructor remains fail-closed with `Unavailable`, so only the production
//! server selects the functional backend. Production owns the canonical durable journal actor as a
//! startup/shutdown barrier but still refuses `MayOwnPrepare` recovery; it has no restart-stable
//! pidfd/network-namespace custody or restart reaper. It can only retire an already durable
//! `CleanupConfirmed` restart set after exact present-pair removals and a fresh exact-empty manager
//! observation. Leader retirement still does not own descendants.

#![cfg(target_os = "linux")]

#[allow(dead_code)] // Shared hard-deadline substrate; later operation kinds remain disconnected.
mod deadline;
#[path = "engine_v3.rs"]
mod engine;
#[allow(dead_code)] // Functional-alpha uses one request shape; later worker operations remain.
mod internal_protocol;
#[allow(dead_code)] // Functional-alpha uses a subset; activation and datapath primitives remain.
mod kernel;
#[allow(dead_code)] // Secret-free topology derivation; broader roles remain disconnected.
mod lease_spec;
#[allow(dead_code)] // V3 endpoint ownership remains isolated until worker-v3 wiring lands.
mod mptcp_endpoint;
mod ownership_journal;
mod runtime;
mod server;
mod systemd_custody;
#[allow(dead_code)] // Production observes inventory; publication and removal remain disconnected.
mod systemd_fdstore;
#[allow(dead_code)] // Functional-alpha selects one direct underlay; broader policy remains.
mod underlay;
#[allow(dead_code)] // Narrow sandbox bootstrap; broader lifecycle operations remain unavailable.
mod worker_sandbox;
#[allow(dead_code)] // V3 transport foundation; descriptor/datapath operations remain unavailable.
mod worker_transport;
#[allow(dead_code)] // Functional-alpha uses one lease; broader authenticated lifecycle remains.
mod worker_v3;

pub use engine::HelperEngine;
pub use runtime::{AGENT_ACCOUNT, RUNTIME_DIRECTORY, SOCKET_PATH, TOKEN_PATH, WORKER_ACCOUNT};
pub use server::{ServerError, run_production_server};
#[doc(hidden)]
pub use worker_v3::WorkerV3LiveProofFailureStage;

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

/// Runs the fixed production-image live proof and exposes only its payload-free failure phase.
#[doc(hidden)]
pub fn run_internal_worker_v3_live_proof_staged() -> Result<(), WorkerV3LiveProofFailureStage> {
    worker_v3::run_internal_worker_v3_live_proof_staged()
}

/// Read-only fixed-path proof that the three functional KVM cycles left only exact Absent
/// tombstones. This grants no journal mutation or restart-cleanup authority.
#[doc(hidden)]
#[must_use]
pub fn production_functional_journal_is_exactly_settled() -> bool {
    ownership_journal::production_functional_journal_is_exactly_settled()
}

/// Read-only fixed-path proof that the singleton KVM restart target is durably
/// `CleanupConfirmed` while its exact systemd custody is still present.
#[doc(hidden)]
#[must_use]
pub fn production_functional_journal_is_exactly_restart_cleanup_confirmed() -> bool {
    ownership_journal::production_functional_journal_is_exactly_restart_cleanup_confirmed()
}

/// Read-only fixed-path proof that the singleton KVM restart target joined the three earlier
/// functional tombstones as one exact recovered `Absent` tombstone.
#[doc(hidden)]
#[must_use]
pub fn production_functional_journal_is_exactly_restart_settled() -> bool {
    ownership_journal::production_functional_journal_is_exactly_restart_settled()
}

#[cfg(test)]
mod tests {
    use std::mem::{needs_drop, size_of};

    use super::*;

    #[test]
    fn staged_live_proof_api_exposes_exactly_five_payload_free_phases() {
        let stages = [
            WorkerV3LiveProofFailureStage::ParentContract,
            WorkerV3LiveProofFailureStage::RuntimePreparation,
            WorkerV3LiveProofFailureStage::WorkerSpawn,
            WorkerV3LiveProofFailureStage::Publication,
            WorkerV3LiveProofFailureStage::RetirementCleanup,
        ];
        assert_eq!(stages.len(), 5);
        assert_eq!(size_of::<WorkerV3LiveProofFailureStage>(), 1);
        assert!(!needs_drop::<WorkerV3LiveProofFailureStage>());
    }

    #[test]
    fn legacy_boolean_live_proof_api_remains_available() {
        let api: fn() -> bool = run_internal_worker_v3_live_proof;
        let staged_api: fn() -> Result<(), WorkerV3LiveProofFailureStage> =
            run_internal_worker_v3_live_proof_staged;
        let _ = (api, staged_api);
    }
}
