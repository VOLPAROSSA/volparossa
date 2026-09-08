//! Resource-derived admission for actual discovery/control connections, on every underlay.
//!
//! This grants room, not a target to fill: only the existing discovery, route, contribution,
//! content and DNS protocols initiate connections. It neither dials speculative peers nor
//! changes selection, per-message bounds or the number of WireGuard/MPTCP/MPQUIC paths.

use volparossa_discovery::DiscoveryService;

use crate::resource_headroom::{self, ResourceHeadroom};

// Advisory units, not kernel reservations or a promise about a malicious peer's peak memory.
// Preserve most currently free resources for the owner's applications and real payload flows.
const MEMORY_BYTES_PER_CONNECTION: u64 = 1024 * 1024;
const FDS_PER_CONNECTION: u64 = 4;
const MEMORY_HEADROOM_DIVISOR: u64 = 32;
const FD_HEADROOM_DIVISOR: u64 = 4;
const PRESSURE_ADMISSION_DIVISOR: u64 = 16;

/// Called before initial dialing and on the actor's existing one-second maintenance tick.
pub(super) fn refresh(service: &mut DiscoveryService) {
    let counters = service.connection_counters();
    let capacity = admission_capacity(
        counters.num_established(),
        counters.num_pending(),
        resource_headroom::capture(),
    );
    service.set_connection_capacity(capacity);
}

fn admission_capacity(established: u32, pending: u32, headroom: Option<ResourceHeadroom>) -> u32 {
    let Some(headroom) = headroom else {
        // Unknown RAM/FD availability authorizes no additional established connections.
        // Existing affine route/control owners survive; a later good sample can reopen admission.
        return established;
    };
    let memory = headroom.memory_bytes / MEMORY_HEADROOM_DIVISOR / MEMORY_BYTES_PER_CONNECTION;
    let fds = headroom.available_fds / FD_HEADROOM_DIVISOR / FDS_PER_CONNECTION;
    let mut additional = memory.min(fds);
    if headroom.pressured {
        // Slow new admission markedly without demanding an idle CPU before bootstrap/recovery.
        // This is a smaller resource allowance, not a universal one-/four-/384-peer ceiling.
        additional /= PRESSURE_ADMISSION_DIVISOR;
    }
    // A pending handshake can become established after this sample. Do not offer its complete
    // connection unit again to a different dial. The existing separate pending limits still apply.
    let additional = additional.saturating_sub(u64::from(pending));
    established.saturating_add(u32::try_from(additional).unwrap_or(u32::MAX))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn resources(units: u64, pressured: bool) -> ResourceHeadroom {
        ResourceHeadroom {
            memory_bytes: units * MEMORY_HEADROOM_DIVISOR * MEMORY_BYTES_PER_CONNECTION,
            available_fds: units * FD_HEADROOM_DIVISOR * FDS_PER_CONNECTION,
            pressured,
        }
    }

    #[test]
    fn admission_grows_beyond_old_counts_and_reserves_pending_handshakes() {
        assert_eq!(admission_capacity(0, 0, Some(resources(600, false))), 600);
        assert_eq!(admission_capacity(385, 0, Some(resources(600, false))), 985);
        assert_eq!(
            admission_capacity(385, 64, Some(resources(600, false))),
            921
        );
        assert_eq!(admission_capacity(385, 64, Some(resources(63, false))), 385);
        let mut constrained = resources(600, false);
        constrained.available_fds = 3 * FD_HEADROOM_DIVISOR * FDS_PER_CONNECTION;
        assert_eq!(admission_capacity(385, 1, Some(constrained)), 387);
    }

    #[test]
    fn pressure_slows_new_admission_without_invalidating_existing_owners() {
        assert_eq!(admission_capacity(385, 0, Some(resources(600, true))), 422);
        assert_eq!(admission_capacity(385, 32, Some(resources(600, true))), 390);
        assert_eq!(admission_capacity(385, 0, Some(resources(0, true))), 385);
        assert_eq!(admission_capacity(385, 64, None), 385);
        assert_eq!(admission_capacity(0, 0, None), 0);
        assert_eq!(admission_capacity(0, 0, Some(resources(32, true))), 2);
        assert_eq!(admission_capacity(385, 0, Some(resources(600, false))), 985);
    }

    #[test]
    fn finite_integer_capacity_does_not_wrap_into_an_unbounded_limit() {
        let huge = Some(ResourceHeadroom {
            memory_bytes: u64::MAX,
            available_fds: u64::MAX,
            pressured: false,
        });
        assert_eq!(admission_capacity(385, 0, huge), u32::MAX);
        let mut exhausted = resources(600, false);
        exhausted.memory_bytes = MEMORY_HEADROOM_DIVISOR * MEMORY_BYTES_PER_CONNECTION - 1;
        assert_eq!(admission_capacity(385, 0, Some(exhausted)), 385);
    }
}
