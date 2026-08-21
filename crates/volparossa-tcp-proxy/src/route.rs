use std::collections::HashSet;

use subtle::ConstantTimeEq;
use volparossa_protocol::{
    ExitReservation, RelayReservation, ReplayCache, TimePolicy, Transport, VerifiedControlMessage,
    verify_control_message, verify_relay_reservation,
};

use crate::TcpProxyError;

const ID_BYTES: usize = 16;
const NODE_ID_BYTES: usize = 32;

/// Minimum number of distinct relay paths accepted for the v1 TCP datapath.
pub const MINIMUM_MPTCP_PATHS: usize = 2;

/// Cryptographic proof that one exit and multiple distinct relays authorized a
/// TCP MPTCP route context.
///
/// Constructing this token consumes signed reservation nonces in the shared
/// replay cache. It contains no direct-client-to-exit construction path.
pub struct VerifiedMptcpRoute {
    reservation_id: [u8; ID_BYTES],
    route_context_id: [u8; ID_BYTES],
    exit_node_id: [u8; NODE_ID_BYTES],
    client_ephemeral_id: [u8; NODE_ID_BYTES],
    relay_node_ids: Vec<[u8; NODE_ID_BYTES]>,
    expires_at_ms: u64,
}

impl VerifiedMptcpRoute {
    /// Verify the exit reservation plus two to eight distinct relay grants.
    ///
    /// # Errors
    ///
    /// Fails closed for invalid signatures, replay, expiry, missing TCP-MPTCP
    /// permission, inconsistent route fields, duplicate relays/path IDs, or an
    /// invalid path count.
    pub fn verify(
        exit_reservation: &[u8],
        relay_reservations: &[&[u8]],
        now_ms: u64,
        time_policy: TimePolicy,
        replay_cache: &mut ReplayCache,
    ) -> Result<Self, TcpProxyError> {
        if !(MINIMUM_MPTCP_PATHS..=usize::from(volparossa_mptcp::MAX_PATHS))
            .contains(&relay_reservations.len())
        {
            return Err(TcpProxyError::InvalidBinding("MPTCP relay path count"));
        }

        let mut replay_transaction = ReplayTransaction::new(replay_cache);
        let exit = verify_control_message::<ExitReservation>(
            exit_reservation,
            now_ms,
            time_policy,
            replay_transaction.cache(),
        )?;
        replay_transaction.record(&exit);
        let exit_message = exit.message();
        if !exit_message
            .allowed_transports
            .contains(&(Transport::TcpMptcp as i32))
        {
            return Err(TcpProxyError::InvalidBinding("TCP-MPTCP transport grant"));
        }
        let maximum_paths = usize::try_from(exit_message.maximum_paths)
            .map_err(|_| TcpProxyError::InvalidBinding("maximum paths"))?;
        if relay_reservations.len() != maximum_paths {
            return Err(TcpProxyError::InvalidBinding("exit exact path count"));
        }

        let mut relay_ids = HashSet::with_capacity(relay_reservations.len());
        let mut relay_peer_ids = HashSet::with_capacity(relay_reservations.len());
        let mut path_ids = HashSet::with_capacity(relay_reservations.len());
        let mut relay_node_ids = Vec::with_capacity(relay_reservations.len());
        let mut expires_at_ms = exit.expires_at_ms();

        for encoded in relay_reservations {
            let (relay, exit_authorization) =
                verify_relay_reservation(encoded, now_ms, time_policy, replay_transaction.cache())?;
            replay_transaction.record(&relay);
            replay_transaction.record(&exit_authorization);
            let message = relay.message();
            verify_finalized_scope(message, exit_message)?;
            let relay_id: [u8; NODE_ID_BYTES] = message
                .relay_node_id
                .as_slice()
                .try_into()
                .map_err(|_| TcpProxyError::InvalidBinding("relay identity"))?;
            if !relay_ids.insert(relay_id) {
                return Err(TcpProxyError::InvalidBinding("duplicate relay identity"));
            }
            if !relay_peer_ids.insert(message.relay_peer_id.clone()) {
                return Err(TcpProxyError::InvalidBinding(
                    "duplicate relay peer identity",
                ));
            }
            if !path_ids.insert(message.path_id) {
                return Err(TcpProxyError::InvalidBinding("duplicate relay path id"));
            }
            relay_node_ids.push(relay_id);
            expires_at_ms = expires_at_ms.min(relay.expires_at_ms());
        }
        relay_node_ids.sort_unstable();

        let route = Self {
            reservation_id: array(&exit_message.reservation_id, "reservation id")?,
            route_context_id: array(&exit_message.route_context_id, "route context")?,
            exit_node_id: array(&exit_message.exit_node_id, "exit identity")?,
            client_ephemeral_id: array(&exit_message.client_session_id, "client session identity")?,
            relay_node_ids,
            expires_at_ms,
        };
        replay_transaction.commit();
        Ok(route)
    }

    /// Return the exit reservation identifier.
    #[must_use]
    pub const fn reservation_id(&self) -> &[u8; ID_BYTES] {
        &self.reservation_id
    }

    /// Return the route context identifier shared by every path.
    #[must_use]
    pub const fn route_context_id(&self) -> &[u8; ID_BYTES] {
        &self.route_context_id
    }

    /// Return the selected exit identity.
    #[must_use]
    pub const fn exit_node_id(&self) -> &[u8; NODE_ID_BYTES] {
        &self.exit_node_id
    }

    /// Return the route's ephemeral client identity.
    #[must_use]
    pub const fn client_ephemeral_id(&self) -> &[u8; NODE_ID_BYTES] {
        &self.client_ephemeral_id
    }

    /// Return the sorted, distinct relay identities used by the route.
    #[must_use]
    pub fn relay_node_ids(&self) -> &[[u8; NODE_ID_BYTES]] {
        &self.relay_node_ids
    }

    /// Return the number of authorized relay paths.
    #[must_use]
    pub fn path_count(&self) -> usize {
        self.relay_node_ids.len()
    }

    /// Return the earliest signed expiry of the exit and relay grants.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Fail closed before opening a new flow on an expired route.
    ///
    /// # Errors
    ///
    /// Returns [`TcpProxyError::Expired`] at or after the earliest expiry.
    pub fn ensure_active_at(&self, now_ms: u64) -> Result<(), TcpProxyError> {
        if now_ms >= self.expires_at_ms {
            return Err(TcpProxyError::Expired);
        }
        Ok(())
    }
}

fn verify_finalized_scope(
    relay: &RelayReservation,
    exit: &ExitReservation,
) -> Result<(), TcpProxyError> {
    same(
        &relay.reservation_id,
        &exit.reservation_id,
        "reservation id",
    )?;
    same(
        &relay.route_context_id,
        &exit.route_context_id,
        "route context",
    )?;
    same(&relay.exit_node_id, &exit.exit_node_id, "exit identity")?;
    same(
        &relay.client_session_id,
        &exit.client_session_id,
        "client session identity",
    )?;
    same(&relay.policy_hash, &exit.policy_hash, "policy hash")?;
    if relay.allowed_transports != exit.allowed_transports {
        return Err(TcpProxyError::InvalidBinding("allowed transports"));
    }
    if relay.maximum_up_mbps != exit.reserved_up_mbps {
        return Err(TcpProxyError::InvalidBinding("reserved upload capacity"));
    }
    if relay.maximum_down_mbps != exit.reserved_down_mbps {
        return Err(TcpProxyError::InvalidBinding("reserved download capacity"));
    }
    if relay.created_at_ms != exit.created_at_ms {
        return Err(TcpProxyError::InvalidBinding("grant creation time"));
    }
    if relay.expires_at_ms != exit.expires_at_ms {
        return Err(TcpProxyError::InvalidBinding("grant expiry"));
    }
    same(&relay.capability_id, &exit.capability_id, "capability id")?;
    same(
        &relay.client_session_public_key,
        &exit.client_session_public_key,
        "client session public key",
    )?;
    same(&relay.exit_boot_id, &exit.exit_boot_id, "exit boot id")?;
    same(&relay.hold_id, &exit.hold_id, "hold id")?;
    same(&relay.finalize_id, &exit.finalize_id, "finalize id")?;
    same(
        &relay.control_relay_node_id,
        &exit.control_relay_node_id,
        "control relay identity",
    )?;
    same(
        &relay.control_relay_peer_id,
        &exit.control_relay_peer_id,
        "control relay peer identity",
    )?;
    same(
        &relay.exit_peer_id,
        &exit.exit_peer_id,
        "exit peer identity",
    )
}

struct ReplayTransaction<'a> {
    cache: &'a mut ReplayCache,
    accepted: Vec<([u8; NODE_ID_BYTES], [u8; NODE_ID_BYTES])>,
    committed: bool,
}

impl<'a> ReplayTransaction<'a> {
    fn new(cache: &'a mut ReplayCache) -> Self {
        Self {
            cache,
            accepted: Vec::new(),
            committed: false,
        }
    }

    fn cache(&mut self) -> &mut ReplayCache {
        self.cache
    }

    fn record<T>(&mut self, message: &VerifiedControlMessage<T>) {
        self.accepted.push((*message.sender_id(), *message.nonce()));
    }

    fn commit(mut self) {
        self.committed = true;
    }
}

impl Drop for ReplayTransaction<'_> {
    fn drop(&mut self) {
        if self.committed {
            return;
        }
        for (sender_id, nonce) in &self.accepted {
            let _ = self.cache.rollback(sender_id, nonce);
        }
    }
}

fn same(left: &[u8], right: &[u8], field: &'static str) -> Result<(), TcpProxyError> {
    if left.len() != right.len() || left.ct_eq(right).unwrap_u8() != 1 {
        return Err(TcpProxyError::InvalidBinding(field));
    }
    Ok(())
}

fn array<const N: usize>(value: &[u8], field: &'static str) -> Result<[u8; N], TcpProxyError> {
    value
        .try_into()
        .map_err(|_| TcpProxyError::InvalidBinding(field))
}
