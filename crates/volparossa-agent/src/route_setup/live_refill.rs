//! Route-owned automatic MPTCP refill, separate from the fast native-health task.

#[allow(
    clippy::wildcard_imports,
    reason = "route-owned maintenance shares its parent's private authority types"
)]
use super::*;

fn advertised_capacity_can_nominate(
    capacity: &volparossa_core::CapacitySnapshot,
    required: Bandwidth,
) -> bool {
    // Only reject an obviously insufficient claim. This is not a local measurement, a
    // reservation, reachability proof or permission to skip normal A1/native sampling.
    capacity.free_relay_slots > 0
        && capacity
            .estimated_free
            .component_min(capacity.relay_limit)
            .satisfies(required)
}

fn next_nomination<T: Copy>(candidates: &[T], cursor: &mut usize) -> Option<T> {
    let index = (*cursor).checked_rem(candidates.len())?;
    *cursor = (index + 1) % candidates.len();
    Some(candidates[index])
}

impl ClientRouteControl {
    /// Add at most one freshly sampled Relay when the existing flow observations require it.
    /// A clean failed attempt leaves the original flow alone. Ambiguous remote commitment is
    /// reported to the daemon owner, which retires the exact parent rather than admitting new
    /// flows under an authority view that might disagree with the Exit.
    #[allow(
        clippy::too_many_lines,
        reason = "one route-owned nomination transaction preserves original flow and cleanup ownership"
    )]
    pub(crate) async fn maintain_mptcp_capacity(
        &self,
        config: &Config,
        discovery: &DiscoveryControlHandle,
    ) -> Result<ClientPathMaintenance, ClientRouteConnectError> {
        let Ok(mut state) = self.state.try_lock() else {
            return Ok(ClientPathMaintenance::Unchanged);
        };
        let ClientRouteControlState::Established(established) = &mut *state else {
            return Ok(ClientPathMaintenance::Unchanged);
        };
        let now_ms = crate::unix_millis();
        if established.is_expired(now_ms, Instant::now()) {
            return Ok(ClientPathMaintenance::Unchanged);
        }
        let ClientTransportState::TcpMptcp(transport) = &mut established.transport else {
            return Ok(ClientPathMaintenance::Unchanged);
        };
        let Some(route) = established.route.as_mut() else {
            return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
        };
        if route.established.pending_extension.is_some() {
            return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
        }
        if route.established.request.parameters.expires_at_ms
            <= now_ms.saturating_add(MAXIMUM_PHASE_LIFETIME_MS)
            || route.established.exit_bundle.path_count()
                + route.established.attempted_extension_paths.len()
                >= 8
            || !transport.refill_needed(Instant::now())
        {
            return Ok(ClientPathMaintenance::Unchanged);
        }
        if let Some(agent) = &self.agent_state {
            let agent = agent.read().await;
            if !agent.roles().client
                || agent.active_policy(now_ms).is_none_or(|policy| {
                    *policy.policy_hash() != route.established.request.parameters.policy_hash
                })
            {
                return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
            }
        }
        let Ok(snapshot) = discovery
            .route_candidate_snapshot(config.network.candidate_pool_size)
            .await
        else {
            return Ok(ClientPathMaintenance::Unchanged);
        };
        let owned = &route.established;
        if snapshot.policy().hash() != owned.request.parameters.policy_hash {
            return Err(ClientRouteConnectError::TransportRuntimeUnavailable);
        }
        let available = snapshot.direct_relays();
        let Some(buddy) = owned.relay_authorities.iter().find(|peer| {
            available.iter().any(|candidate| {
                candidate.capability().node_id == peer.node_id
                    && candidate.capability().peer_id == peer.peer_id
            })
        }) else {
            return Ok(ClientPathMaintenance::Unchanged);
        };
        let buddy = (buddy.node_id, buddy.peer_id);
        // RouteSetupRequest already checked this exact minimum against its signed reserved
        // up/down Mbps. Current configuration changes cannot relax an established reservation.
        let minimum_capacity = owned
            .request
            .parameters
            .post_probe_policy
            .requirements
            .minimum_capacity;
        let mut candidates = available
            .iter()
            .filter_map(|candidate| {
                let cap = candidate.capability();
                (advertised_capacity_can_nominate(
                    &candidate.advertisement().advertisement().capacity,
                    minimum_capacity,
                ) && cap.node_id != owned.request.exit.wire_node_id
                    && cap.peer_id != owned.request.exit.peer_id
                    && cap.node_id != owned.request.control.identity.wire_node_id
                    && cap.peer_id != owned.request.control.identity.peer_id
                    && !owned
                        .relay_authorities
                        .iter()
                        .any(|peer| peer.node_id == cap.node_id || peer.peer_id == cap.peer_id))
                .then_some((cap.node_id, cap.peer_id))
            })
            .collect::<Vec<_>>();
        candidates.sort_unstable();
        // Rotate nominations after failed attempts. The actor-owned snapshot is only a
        // nomination: exact lineage, diversity and new real measurements are checked below.
        // Advance BEFORE preselection; failures there have not allocated an attempted path ID.
        let Some(candidate) =
            next_nomination(&candidates, &mut route.established.refill_nomination_cursor)
        else {
            return Ok(ClientPathMaintenance::Unchanged);
        };
        match Box::pin(route.extend_mptcp_relay(
            config,
            discovery,
            &established.helper,
            candidate,
            buddy,
        ))
        .await
        {
            Ok(CommittedMptcpExtension {
                path_id,
                selected_path_ids,
            }) => {
                transport
                    .register_extension(path_id, &selected_path_ids)
                    .map_err(|_| ClientRouteConnectError::TransportRuntimeUnavailable)?;
                Ok(ClientPathMaintenance::Reconfigured)
            }
            Err(_) if route.established.pending_extension.is_none() => {
                Ok(ClientPathMaintenance::Unchanged)
            }
            Err(error) => Err(error),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn capacity(limit: Bandwidth, free: Bandwidth) -> volparossa_core::CapacitySnapshot {
        volparossa_core::CapacitySnapshot {
            relay_limit: limit,
            exit_limit: Bandwidth::default(),
            currently_reserved: Bandwidth::default(),
            estimated_free: free,
            active_relay_sessions: 0,
            active_exit_sessions: 0,
            free_relay_slots: 1,
            free_exit_slots: 0,
            sample_window_seconds: 30,
        }
    }

    #[test]
    fn mptcp_refill_nomination_filters_under_capacity_and_not_other_role_bandwidth() {
        let minimum = Bandwidth::new(8, 16).unwrap();
        assert!(advertised_capacity_can_nominate(
            &capacity(minimum, minimum),
            minimum
        ));
        assert!(!advertised_capacity_can_nominate(
            &capacity(Bandwidth::new(1, 1).unwrap(), minimum),
            minimum
        ));
        assert!(!advertised_capacity_can_nominate(
            &capacity(minimum, Bandwidth::new(8, 15).unwrap()),
            minimum
        ));
        let mut no_slots = capacity(minimum, minimum);
        no_slots.free_relay_slots = 0;
        assert!(!advertised_capacity_can_nominate(&no_slots, minimum));
    }

    #[test]
    fn mptcp_refill_nomination_rotates_before_any_path_id_is_allocated() {
        let mut cursor = 0;
        assert_eq!(next_nomination::<u8>(&[], &mut cursor), None);
        assert_eq!(next_nomination(&[4, 5, 6], &mut cursor), Some(4));
        // The first nominee failed A1/diversity before allocating a helper path: the next
        // tick still nominates a different candidate instead of starving it indefinitely.
        assert_eq!(next_nomination(&[4, 5, 6], &mut cursor), Some(5));
        assert_eq!(next_nomination(&[4, 5, 6], &mut cursor), Some(6));
        assert_eq!(cursor, 0);
        // Changed snapshots remain bounded and don't invalidate the cursor.
        cursor = 2;
        assert_eq!(next_nomination(&[7], &mut cursor), Some(7));
        assert_eq!(cursor, 0);
    }
}
