use std::collections::HashSet;

use subtle::ConstantTimeEq;
use volparossa_protocol::{
    ClientSessionCapability, ExitReservation, RelayReservation, ReplayCache, RouteExtension,
    RouteExtensionPhase, TimePolicy, Transport, VerifiedControlMessage,
    finalized_reservation_bundle_hash, verify_control_message, verify_relay_reservation,
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
        Self::verify_inner(
            exit_reservation,
            relay_reservations,
            None,
            now_ms,
            time_policy,
            replay_cache,
        )
    }

    /// Verify an immutable original route plus a contiguous Exit-signed sequence of one-path
    /// commits. This creates an effective view for later `OPEN_TCP` without reissuing old grants.
    ///
    /// # Errors
    /// Rejects missing/extra paths, reordered or substituted commits, another original bundle,
    /// changed session/native identity/expiry or exceeding the original signed capacity limit.
    #[allow(
        clippy::too_many_arguments,
        reason = "original authority and additive proofs are separate"
    )]
    pub fn verify_with_extensions(
        exit_reservation: &[u8],
        relay_reservations: &[&[u8]],
        signed_extensions: &[&[u8]],
        signed_capability: &[u8],
        now_ms: u64,
        time_policy: TimePolicy,
        replay_cache: &mut ReplayCache,
    ) -> Result<Self, TcpProxyError> {
        Self::verify_inner(
            exit_reservation,
            relay_reservations,
            Some((signed_extensions, signed_capability)),
            now_ms,
            time_policy,
            replay_cache,
        )
    }

    #[allow(
        clippy::too_many_lines,
        reason = "single replay-atomic complete route verification"
    )]
    fn verify_inner(
        exit_reservation: &[u8],
        relay_reservations: &[&[u8]],
        extension_proofs: Option<(&[&[u8]], &[u8])>,
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
        let extension_count = extension_proofs.map_or(0, |(proofs, _)| proofs.len());
        if extension_count > 8
            || relay_reservations.len() != maximum_paths.saturating_add(extension_count)
        {
            return Err(TcpProxyError::InvalidBinding("exit exact path count"));
        }

        let mut relay_ids = HashSet::with_capacity(relay_reservations.len());
        let mut relay_peer_ids = HashSet::with_capacity(relay_reservations.len());
        let mut path_ids = HashSet::with_capacity(relay_reservations.len());
        let mut relay_node_ids = Vec::with_capacity(relay_reservations.len());
        let mut expires_at_ms = exit.expires_at_ms();
        let mut grants = Vec::with_capacity(relay_reservations.len());

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
            grants.push(message.clone());
        }
        relay_node_ids.sort_unstable();
        if let Some((proofs, capability)) = extension_proofs {
            verify_extensions(
                exit_reservation,
                exit_message,
                &grants,
                proofs,
                capability,
                now_ms,
                time_policy,
                &mut replay_transaction,
            )?;
        }

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

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "original immutable authority and all additive path proofs checked atomically"
)]
fn verify_extensions(
    signed_parent: &[u8],
    parent: &ExitReservation,
    grants: &[RelayReservation],
    signed_extensions: &[&[u8]],
    signed_capability: &[u8],
    now_ms: u64,
    time_policy: TimePolicy,
    replay: &mut ReplayTransaction<'_>,
) -> Result<(), TcpProxyError> {
    let capability = verify_control_message::<ClientSessionCapability>(
        signed_capability,
        now_ms,
        time_policy,
        replay.cache(),
    )?;
    replay.record(&capability);
    let c = capability.message();
    if c.reservation_id != parent.reservation_id
        || c.route_context_id != parent.route_context_id
        || c.client_session_id != parent.client_session_id
        || c.client_session_public_key != parent.client_session_public_key
        || c.exit_node_id != parent.exit_node_id
        || c.exit_peer_id != parent.exit_peer_id
        || c.exit_boot_id != parent.exit_boot_id
        || c.capability_id != parent.capability_id
        || c.control_relay_node_id != parent.control_relay_node_id
        || c.control_relay_peer_id != parent.control_relay_peer_id
        || c.policy_hash != parent.policy_hash
        || c.allowed_transports != parent.allowed_transports
        || c.reserved_up_mbps != parent.reserved_up_mbps
        || c.reserved_down_mbps != parent.reserved_down_mbps
        || c.created_at_ms != parent.created_at_ms
        || c.expires_at_ms != parent.expires_at_ms
        || capability.sender_id().as_slice() != parent.exit_node_id
        || grants.len() > usize::try_from(c.maximum_paths).unwrap_or(0)
    {
        return Err(TcpProxyError::InvalidBinding(
            "extension original capability",
        ));
    }
    let mut extensions = Vec::with_capacity(signed_extensions.len());
    let mut added = HashSet::new();
    let mut extension_ids = HashSet::new();
    for encoded in signed_extensions {
        let verified =
            verify_control_message::<RouteExtension>(encoded, now_ms, time_policy, replay.cache())?;
        replay.record(&verified);
        let message = verified.message();
        let scope = message
            .scope
            .as_ref()
            .ok_or(TcpProxyError::InvalidBinding("extension scope"))?;
        if message.phase != RouteExtensionPhase::Commit as i32
            || scope.signed_exit_reservation != signed_parent
            || verified.sender_id().as_slice() != parent.exit_node_id
            || message.hard_expires_at_ms != parent.expires_at_ms
            || scope.path_id > c.probe_permit_limit
            || !added.insert(scope.path_id)
            || !extension_ids.insert(scope.extension_id.clone())
        {
            return Err(TcpProxyError::InvalidBinding("extension committed scope"));
        }
        let grant = grants.iter().find(|g| g.path_id == scope.path_id).ok_or(
            TcpProxyError::InvalidBinding("extension missing Relay grant"),
        )?;
        if grant.exit_authorization != message.signed_relay_authorization
            || grant.relay_node_id != scope.relay_node_id
            || grant.relay_peer_id != scope.relay_peer_id
        {
            return Err(TcpProxyError::InvalidBinding("extension Relay binding"));
        }
        extensions.push(message.clone());
    }
    let mut originals = grants
        .iter()
        .filter(|g| !added.contains(&g.path_id))
        .collect::<Vec<_>>();
    originals.sort_unstable_by_key(|g| g.path_id);
    if originals.len() != usize::try_from(parent.maximum_paths).unwrap_or(0) {
        return Err(TcpProxyError::InvalidBinding(
            "extension original path count",
        ));
    }
    let authorizations = originals
        .iter()
        .map(|g| g.exit_authorization.clone())
        .collect::<Vec<_>>();
    let original_hash = finalized_reservation_bundle_hash(signed_parent, &authorizations)?;
    let mut selected = originals.iter().map(|g| g.path_id).collect::<Vec<_>>();
    for extension in extensions {
        let scope = extension
            .scope
            .as_ref()
            .ok_or(TcpProxyError::InvalidBinding("extension scope"))?;
        if scope.finalized_bundle_hash.as_slice() != original_hash {
            return Err(TcpProxyError::InvalidBinding("extension parent bundle"));
        }
        selected.push(scope.path_id);
        selected.sort_unstable();
        if extension.selected_path_ids != selected {
            return Err(TcpProxyError::InvalidBinding(
                "extension contiguous path set",
            ));
        }
    }
    Ok(())
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
