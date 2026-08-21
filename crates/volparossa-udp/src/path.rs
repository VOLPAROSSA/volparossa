use subtle::ConstantTimeEq;
use volparossa_protocol::{
    ExitReservation, RelayReservation, ReplayCache, TimePolicy, Transport, VerifiedControlMessage,
    verify_control_message, verify_relay_reservation,
};

use crate::UdpError;

const ID_BYTES: usize = 16;
const NODE_ID_BYTES: usize = 32;

/// Proof of exactly one client-to-relay-to-exit UDP path.
///
/// The only constructor verifies both the exit's relay authorization and the
/// selected relay's independent acceptance. There is no zero-relay or direct
/// client-to-exit constructor.
pub struct VerifiedSingleRelayPath {
    reservation_id: [u8; ID_BYTES],
    route_context_id: [u8; ID_BYTES],
    path_id: u32,
    relay_node_id: [u8; NODE_ID_BYTES],
    exit_node_id: [u8; NODE_ID_BYTES],
    client_ephemeral_id: [u8; NODE_ID_BYTES],
    expires_at_ms: u64,
}

impl VerifiedSingleRelayPath {
    /// Verify one exit reservation and exactly one relay reservation.
    ///
    /// # Errors
    ///
    /// Fails for invalid signatures, replay, expiry, missing single-path UDP
    /// permission, inconsistent route fields, or a relay grant outliving the
    /// exit reservation.
    pub fn verify(
        exit_reservation: &[u8],
        relay_reservation: &[u8],
        now_ms: u64,
        time_policy: TimePolicy,
        replay_cache: &mut ReplayCache,
    ) -> Result<Self, UdpError> {
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
            .contains(&(Transport::UdpSinglePath as i32))
        {
            return Err(UdpError::InvalidBinding("single-path UDP transport grant"));
        }
        if exit_message.maximum_paths != 1 {
            return Err(UdpError::InvalidBinding("exit exact path count"));
        }

        let (relay, exit_authorization) = verify_relay_reservation(
            relay_reservation,
            now_ms,
            time_policy,
            replay_transaction.cache(),
        )?;
        replay_transaction.record(&relay);
        replay_transaction.record(&exit_authorization);
        let relay_message = relay.message();
        verify_finalized_scope(relay_message, exit_message)?;

        let path = Self {
            reservation_id: array(&exit_message.reservation_id, "reservation id")?,
            route_context_id: array(&exit_message.route_context_id, "route context")?,
            path_id: relay_message.path_id,
            relay_node_id: array(&relay_message.relay_node_id, "relay identity")?,
            exit_node_id: array(&exit_message.exit_node_id, "exit identity")?,
            client_ephemeral_id: array(&exit_message.client_session_id, "client session identity")?,
            expires_at_ms: exit.expires_at_ms().min(relay.expires_at_ms()),
        };
        replay_transaction.commit();
        Ok(path)
    }

    /// Return the shared reservation identifier.
    #[must_use]
    pub const fn reservation_id(&self) -> &[u8; ID_BYTES] {
        &self.reservation_id
    }

    /// Return the fixed route context.
    #[must_use]
    pub const fn route_context_id(&self) -> &[u8; ID_BYTES] {
        &self.route_context_id
    }

    /// Return the one non-zero context-local path identifier.
    #[must_use]
    pub const fn path_id(&self) -> u32 {
        self.path_id
    }

    /// Return the sole selected relay identity.
    #[must_use]
    pub const fn relay_node_id(&self) -> &[u8; NODE_ID_BYTES] {
        &self.relay_node_id
    }

    /// Return the selected exit identity.
    #[must_use]
    pub const fn exit_node_id(&self) -> &[u8; NODE_ID_BYTES] {
        &self.exit_node_id
    }

    /// Return the ephemeral client identity.
    #[must_use]
    pub const fn client_ephemeral_id(&self) -> &[u8; NODE_ID_BYTES] {
        &self.client_ephemeral_id
    }

    /// Return the earliest signed route expiry.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Fail closed before opening an association on a stale path.
    ///
    /// # Errors
    ///
    /// Returns [`UdpError::Expired`] at or after signed expiry.
    pub fn ensure_active_at(&self, now_ms: u64) -> Result<(), UdpError> {
        if now_ms >= self.expires_at_ms {
            return Err(UdpError::Expired);
        }
        Ok(())
    }

    #[cfg(test)]
    pub(crate) fn test_path(expires_at_ms: u64) -> Self {
        Self {
            reservation_id: [1; ID_BYTES],
            route_context_id: [2; ID_BYTES],
            path_id: 1,
            relay_node_id: [3; NODE_ID_BYTES],
            exit_node_id: [4; NODE_ID_BYTES],
            client_ephemeral_id: [5; NODE_ID_BYTES],
            expires_at_ms,
        }
    }
}

fn verify_finalized_scope(
    relay: &RelayReservation,
    exit: &ExitReservation,
) -> Result<(), UdpError> {
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
        return Err(UdpError::InvalidBinding("allowed transports"));
    }
    if relay.maximum_up_mbps != exit.reserved_up_mbps {
        return Err(UdpError::InvalidBinding("reserved upload capacity"));
    }
    if relay.maximum_down_mbps != exit.reserved_down_mbps {
        return Err(UdpError::InvalidBinding("reserved download capacity"));
    }
    if relay.created_at_ms != exit.created_at_ms {
        return Err(UdpError::InvalidBinding("grant creation time"));
    }
    if relay.expires_at_ms != exit.expires_at_ms {
        return Err(UdpError::InvalidBinding("grant expiry"));
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

fn same(left: &[u8], right: &[u8], field: &'static str) -> Result<(), UdpError> {
    if left.len() != right.len() || left.ct_eq(right).unwrap_u8() != 1 {
        return Err(UdpError::InvalidBinding(field));
    }
    Ok(())
}

fn array<const N: usize>(value: &[u8], field: &'static str) -> Result<[u8; N], UdpError> {
    value
        .try_into()
        .map_err(|_| UdpError::InvalidBinding(field))
}
