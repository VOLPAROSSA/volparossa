//! Live admission capacity; changing a ceiling never revokes connection provenance.

use libp2p::swarm::ConnectionCounters;

use crate::{DiscoveryBehaviour, DiscoveryService};

impl DiscoveryBehaviour {
    fn set_connection_capacity(&mut self, total: u32) {
        // Retain every previously admissible lineage before increasing admission. The passive
        // registry has no independently dialable surface and allocates only for actual events.
        self.connection_provenance.retain_connection_capacity(total);
        let limits = self.connection_limits.limits_mut();
        *limits = limits
            .clone()
            .with_max_established(Some(total))
            .with_max_established_incoming(Some(total))
            .with_max_established_outgoing(Some(total));
    }
}

impl DiscoveryService {
    /// Apply the caller's current, finite resource-derived established-connection capacity.
    ///
    /// Either direction may use the total budget. Pending-handshake and per-peer guards remain
    /// unchanged. Zero denies new established connections; lowering a ceiling neither closes
    /// existing connections nor invalidates their witnesses, including already-admitted events.
    /// No storage is preallocated for the supplied ceiling. This does not resize the separately
    /// bounded discovery address cache or promise more than 1,024 indexed peers.
    pub fn set_connection_capacity(&mut self, total: u32) {
        self.swarm.behaviour_mut().set_connection_capacity(total);
    }

    /// Snapshot actual pending and established swarm counts, not available admission slots.
    ///
    /// Counts may exceed a newly lowered capacity while previously admitted connections live.
    #[must_use]
    pub fn connection_counters(&self) -> ConnectionCounters {
        self.swarm.network_info().connection_counters().clone()
    }
}

#[cfg(test)]
mod tests;
