//! Authorization and capacity accounting for an explicitly enabled relay.
//!
//! This crate never opens an Internet socket and exposes no destination field.
//! It verifies an exit-signed, short-lived path grant, atomically consumes relay
//! capacity, and emits the relay's independent signature. Applying `WireGuard`,
//! route and nftables state remains the typed privileged helper's job.

#![forbid(unsafe_code)]
#![deny(missing_docs)]

use std::{
    collections::{HashMap, HashSet},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
};

use sha2::{Digest, Sha256};
use thiserror::Error;
use volparossa_core::{
    Bandwidth, ClientEphemeralId, NodeId, ReservationId, RouteContextId, ServiceRole,
    Transport as CoreTransport, UnixTime,
};
use volparossa_metrics::MetricsRegistry;
use volparossa_protocol::{
    ClientSessionCapability, ExitReservation, ProtocolError, RelayAuthorization, RelayReservation,
    RelayReservationRequest, ReplayCache, TimePolicy, WireguardEndpoint, generate_nonce,
    node_id_from_public_key, sign_control_message_with, verify_control_message,
};
use volparossa_reservation::{
    AuthorizedReservation, AvailableCapacity, CapacityLedger, LedgerLimits, ReservationError,
};
use volparossa_wireguard::{PublicWireGuardEndpoint, RelayEndpointLease, WireGuardPublicKey};

const ID_BYTES: usize = 16;
const NODE_ID_BYTES: usize = 32;
const MAX_SESSIONS: u32 = 100_000;
const MAX_TTL_SECONDS: u64 = 15 * 60;
const MAX_IDEMPOTENCY_ENTRIES: usize = 4_096;

/// Immutable operator limits for one relay role.
#[derive(Clone, Debug)]
pub struct RelayServiceConfig {
    enabled: bool,
    node_id: [u8; NODE_ID_BYTES],
    bandwidth: Bandwidth,
    maximum_sessions: u32,
    maximum_reservation_ttl_seconds: u64,
    tunnel_setup_timeout_seconds: u64,
    replay_capacity: usize,
}

impl RelayServiceConfig {
    /// Construct the safe disabled default for one local node.
    #[must_use]
    pub const fn disabled(node_id: [u8; NODE_ID_BYTES]) -> Self {
        Self {
            enabled: false,
            node_id,
            bandwidth: Bandwidth {
                up_mbps: 0,
                down_mbps: 0,
            },
            maximum_sessions: 0,
            maximum_reservation_ttl_seconds: MAX_TTL_SECONDS,
            tunnel_setup_timeout_seconds: 30,
            replay_capacity: 65_536,
        }
    }

    /// Construct explicitly enabled relay limits.
    #[must_use]
    pub const fn enabled(
        node_id: [u8; NODE_ID_BYTES],
        bandwidth: Bandwidth,
        maximum_sessions: u32,
        maximum_reservation_ttl_seconds: u64,
        tunnel_setup_timeout_seconds: u64,
        replay_capacity: usize,
    ) -> Self {
        Self {
            enabled: true,
            node_id,
            bandwidth,
            maximum_sessions,
            maximum_reservation_ttl_seconds,
            tunnel_setup_timeout_seconds,
            replay_capacity,
        }
    }

    /// Return whether the operator explicitly enabled relay service.
    #[must_use]
    pub const fn is_enabled(&self) -> bool {
        self.enabled
    }
}

/// A bounded relay admission service with replay and capacity state.
pub struct RelayService {
    config: RelayServiceConfig,
    request_replay: ReplayCache,
    authorization_replay: ReplayCache,
    ledger: Option<CapacityLedger>,
    endpoint_states: HashMap<ReservationId, RelayPathState>,
    metrics: Option<MetricsRegistry>,
    response_cache: HashMap<[u8; NODE_ID_BYTES], CachedRelayResponse>,
    response_cache_capacity: usize,
}

impl RelayService {
    /// Validate configuration and construct an empty service.
    ///
    /// Disabled configuration creates no capacity ledger and will reject every
    /// authorization. Enabled configuration requires finite non-zero limits.
    ///
    /// # Errors
    ///
    /// Returns an error for zero/oversized bounds or an invalid ledger.
    pub fn new(
        config: RelayServiceConfig,
        metrics: Option<MetricsRegistry>,
    ) -> Result<Self, RelayError> {
        if config.replay_capacity == 0 {
            return Err(RelayError::InvalidConfig("replay capacity"));
        }
        let ledger = if config.enabled {
            if config.bandwidth.up_mbps == 0
                || config.bandwidth.down_mbps == 0
                || config.maximum_sessions == 0
                || config.maximum_sessions > MAX_SESSIONS
                || config.maximum_reservation_ttl_seconds == 0
                || config.maximum_reservation_ttl_seconds > MAX_TTL_SECONDS
                || config.tunnel_setup_timeout_seconds == 0
                || config.tunnel_setup_timeout_seconds > config.maximum_reservation_ttl_seconds
            {
                return Err(RelayError::InvalidConfig("relay limits"));
            }
            Some(CapacityLedger::new(LedgerLimits {
                service_node_id: text_id::<NodeId>(&config.node_id)?,
                role: ServiceRole::Relay,
                bandwidth: config.bandwidth,
                maximum_sessions: config.maximum_sessions,
                maximum_reservation_ttl_seconds: config.maximum_reservation_ttl_seconds,
                tunnel_setup_timeout_seconds: config.tunnel_setup_timeout_seconds,
            })?)
        } else {
            None
        };
        let request_replay = ReplayCache::new(config.replay_capacity)?;
        let authorization_replay = ReplayCache::new(config.replay_capacity)?;
        let response_cache_capacity = config.replay_capacity.min(MAX_IDEMPOTENCY_ENTRIES);
        let service = Self {
            config,
            request_replay,
            authorization_replay,
            ledger,
            endpoint_states: HashMap::new(),
            metrics,
            response_cache: HashMap::with_capacity(response_cache_capacity),
            response_cache_capacity,
        };
        service.sync_metrics();
        Ok(service)
    }

    /// Verify a fresh client-session request and all embedded exit-signed grants.
    ///
    /// Capacity remains unchanged until the request signature, session capability,
    /// finalized exit grant, per-path authorization, exact `WireGuard` scope and local
    /// relay identity all validate. No permanent client identity enters this API.
    ///
    /// # Errors
    ///
    /// Fails closed for disabled mode, malformed/replayed/expired or cross-scoped
    /// grants, exhausted capacity, unavailable helper leases, or signing failure.
    pub fn accept_request_with<E, F>(
        &mut self,
        encoded_request: &[u8],
        now_ms: u64,
        local_public_key: [u8; NODE_ID_BYTES],
        endpoint_provider: E,
        signer: F,
    ) -> Result<AcceptedRelayReservation, RelayError>
    where
        E: FnOnce(u32) -> Option<RelayEndpointLease>,
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        if !self.config.enabled {
            return Err(RelayError::Disabled);
        }
        if node_id_from_public_key(&local_public_key) != self.config.node_id {
            return Err(RelayError::LocalIdentityMismatch);
        }
        self.purge_expired(now_ms);
        let request_hash: [u8; NODE_ID_BYTES] = Sha256::digest(encoded_request).into();
        if let Some(cached) = self.response_cache.get(&request_hash) {
            if cached.request != encoded_request {
                return Err(RelayError::InvalidGrant(
                    "idempotency request hash collision",
                ));
            }
            return Ok(cached.response.clone());
        }
        if self.response_cache.len() >= self.response_cache_capacity {
            return Err(RelayError::IdempotencyCapacity);
        }

        let verified = verify_control_message::<RelayReservationRequest>(
            encoded_request,
            now_ms,
            TimePolicy::default(),
            &mut self.request_replay,
        )?;
        let request_replay_entry = (*verified.sender_id(), *verified.nonce());
        let request_public_key = *verified.sender_public_key();
        let request = verified.into_message();
        let request_expires_at_ms = request.expires_at_ms;
        let outcome = self.accept_verified_request_with(
            &request,
            request_public_key,
            now_ms,
            local_public_key,
            endpoint_provider,
            signer,
        );
        match outcome {
            Ok(response) => {
                self.response_cache.insert(
                    request_hash,
                    CachedRelayResponse {
                        request: encoded_request.to_vec(),
                        response: response.clone(),
                        expires_at_ms: request_expires_at_ms.min(response.expires_at_ms),
                    },
                );
                Ok(response)
            }
            Err(error) => {
                let _ = self
                    .request_replay
                    .rollback(&request_replay_entry.0, &request_replay_entry.1);
                Err(error)
            }
        }
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the fail-closed verify, reserve, sign and helper-lease commit transaction is reviewed as one unit"
    )]
    fn accept_verified_request_with<E, F>(
        &mut self,
        request: &RelayReservationRequest,
        request_public_key: [u8; NODE_ID_BYTES],
        now_ms: u64,
        local_public_key: [u8; NODE_ID_BYTES],
        endpoint_provider: E,
        signer: F,
    ) -> Result<AcceptedRelayReservation, RelayError>
    where
        E: FnOnce(u32) -> Option<RelayEndpointLease>,
        F: FnOnce(&[u8]) -> Option<[u8; 64]>,
    {
        let mut nested_replay_entries = Vec::with_capacity(3);
        let outcome = (|| {
            let verified_capability = verify_control_message::<ClientSessionCapability>(
                &request.client_session_capability,
                now_ms,
                TimePolicy::default(),
                &mut self.authorization_replay,
            )?;
            nested_replay_entries.push((
                *verified_capability.sender_id(),
                *verified_capability.nonce(),
            ));
            let capability_public_key = *verified_capability.sender_public_key();
            let capability = verified_capability.into_message();

            let verified_exit = verify_control_message::<ExitReservation>(
                &request.exit_reservation,
                now_ms,
                TimePolicy::default(),
                &mut self.authorization_replay,
            )?;
            nested_replay_entries.push((*verified_exit.sender_id(), *verified_exit.nonce()));
            let exit_public_key = *verified_exit.sender_public_key();
            let exit_reservation = verified_exit.into_message();

            let verified_authorization = verify_control_message::<RelayAuthorization>(
                &request.exit_authorization,
                now_ms,
                TimePolicy::default(),
                &mut self.authorization_replay,
            )?;
            nested_replay_entries.push((
                *verified_authorization.sender_id(),
                *verified_authorization.nonce(),
            ));
            let authorization_public_key = *verified_authorization.sender_public_key();
            let authorization = verified_authorization.into_message();

            if authorization.relay_node_id.as_slice() != self.config.node_id {
                return Err(RelayError::WrongRelay);
            }
            if authorization.relay_peer_id != peer_id_from_public_key(&local_public_key)? {
                return Err(RelayError::PeerIdentityMismatch);
            }
            validate_relay_scope(&VerifiedRelayScope {
                request,
                request_public_key,
                capability: &capability,
                capability_public_key,
                exit: &exit_reservation,
                exit_public_key,
                authorization: &authorization,
                authorization_public_key,
            })?;

            let authorized = relay_allocation(&authorization, now_ms)?;
            let route_context_id = fixed(&authorization.route_context_id, "route context")?;
            let reservation_key = authorized.reservation_id.clone();
            if self.endpoint_states.contains_key(&reservation_key) {
                return Err(RelayError::LeaseInvariant);
            }
            let client_public = public_key(
                &authorization.client_wireguard_public_key,
                "client WireGuard public key",
            )?;
            let client_endpoint = public_endpoint(
                request
                    .client_wireguard_endpoint
                    .as_ref()
                    .ok_or(RelayError::ClientScopeMismatch)?,
                "client WireGuard endpoint",
            )?;
            if client_endpoint.public_key() != client_public {
                return Err(RelayError::ClientScopeMismatch);
            }
            let exit_endpoint = public_endpoint(
                authorization
                    .exit_wireguard_endpoint
                    .as_ref()
                    .ok_or(RelayError::InvalidGrant("exit WireGuard endpoint"))?,
                "exit WireGuard endpoint",
            )?;
            let endpoint =
                endpoint_provider(authorization.path_id).ok_or(RelayError::EndpointUnavailable)?;
            if endpoint.route_context_id() != &route_context_id
                || endpoint.path_id() != authorization.path_id
            {
                return Err(RelayError::InvalidGrant("relay helper lease binding"));
            }
            let mut helper_handles = self
                .endpoint_states
                .values()
                .flat_map(|state| {
                    [
                        *state.endpoint.context_handle().as_bytes(),
                        *state.endpoint.client_facing_handle().as_bytes(),
                        *state.endpoint.exit_facing_handle().as_bytes(),
                    ]
                })
                .collect::<HashSet<_>>();
            for handle in [
                *endpoint.context_handle().as_bytes(),
                *endpoint.client_facing_handle().as_bytes(),
                *endpoint.exit_facing_handle().as_bytes(),
            ] {
                if !helper_handles.insert(handle) {
                    return Err(RelayError::InvalidGrant("relay helper handle uniqueness"));
                }
            }
            let relay_client = endpoint.client_facing_endpoint();
            let relay_exit = endpoint.exit_facing_endpoint();
            let keys = [
                client_public,
                exit_endpoint.public_key(),
                relay_client.public_key(),
                relay_exit.public_key(),
            ];
            if keys
                .iter()
                .enumerate()
                .any(|(index, key)| keys[index + 1..].contains(key))
            {
                return Err(RelayError::InvalidGrant("distinct WireGuard endpoint keys"));
            }
            let mut active_ports = self
                .endpoint_states
                .values()
                .flat_map(|state| {
                    [
                        state.endpoint.client_facing_endpoint().listen_port(),
                        state.endpoint.exit_facing_endpoint().listen_port(),
                    ]
                })
                .collect::<HashSet<_>>();
            if !active_ports.insert(relay_client.listen_port())
                || !active_ports.insert(relay_exit.listen_port())
            {
                return Err(RelayError::InvalidGrant(
                    "relay endpoint listen-port uniqueness",
                ));
            }
            let reservation_id = fixed(&authorization.reservation_id, "reservation id")?;
            let exit_node_id = fixed(&authorization.exit_node_id, "exit node id")?;
            self.ledger_mut()?
                .reserve(authorized, unix_seconds(now_ms))?;

            let signed_nonce = generate_nonce();
            let payload = RelayReservation {
                reservation_id: authorization.reservation_id.clone(),
                route_context_id: authorization.route_context_id.clone(),
                path_id: authorization.path_id,
                relay_node_id: authorization.relay_node_id.clone(),
                exit_node_id: authorization.exit_node_id.clone(),
                client_session_id: authorization.client_session_id.clone(),
                allowed_transports: authorization.allowed_transports.clone(),
                maximum_up_mbps: authorization.maximum_up_mbps,
                maximum_down_mbps: authorization.maximum_down_mbps,
                client_wireguard_public_key: authorization.client_wireguard_public_key.clone(),
                relay_client_wireguard_endpoint: Some(wire_endpoint(relay_client)),
                relay_exit_wireguard_endpoint: Some(wire_endpoint(relay_exit)),
                exit_wireguard_endpoint: authorization.exit_wireguard_endpoint.clone(),
                policy_hash: authorization.policy_hash.clone(),
                created_at_ms: authorization.created_at_ms,
                expires_at_ms: authorization.expires_at_ms,
                nonce: signed_nonce.to_vec(),
                exit_authorization: request.exit_authorization.clone(),
                relay_peer_id: authorization.relay_peer_id.clone(),
                capability_id: authorization.capability_id.clone(),
                client_session_public_key: authorization.client_session_public_key.clone(),
                exit_boot_id: authorization.exit_boot_id.clone(),
                hold_id: authorization.hold_id.clone(),
                finalize_id: authorization.finalize_id.clone(),
                control_relay_node_id: authorization.control_relay_node_id.clone(),
                control_relay_peer_id: authorization.control_relay_peer_id.clone(),
                exit_peer_id: authorization.exit_peer_id.clone(),
            };
            let encoded = match sign_control_message_with(
                &payload,
                local_public_key,
                authorization.created_at_ms,
                authorization.expires_at_ms,
                signed_nonce,
                TimePolicy::default(),
                signer,
            ) {
                Ok(encoded) => encoded,
                Err(error) => {
                    if self.ledger_mut()?.release(&reservation_key).is_err() {
                        return Err(RelayError::LedgerInvariant);
                    }
                    self.sync_metrics();
                    return Err(error.into());
                }
            };
            self.endpoint_states.insert(
                reservation_key,
                RelayPathState {
                    endpoint,
                    client_endpoint,
                    exit_endpoint,
                },
            );
            self.sync_metrics();

            Ok(AcceptedRelayReservation {
                encoded,
                reservation_id,
                route_context_id,
                path_id: payload.path_id,
                exit_node_id,
                expires_at_ms: payload.expires_at_ms,
            })
        })();
        if outcome.is_err() {
            rollback_replay(&mut self.authorization_replay, &nested_replay_entries);
        }
        outcome
    }

    /// Mark the helper-confirmed tunnel for a reservation as established.
    ///
    /// # Errors
    ///
    /// Unknown, expired, disabled, or setup-expired reservations are rejected.
    pub fn mark_tunnel_established(
        &mut self,
        reservation_id: &[u8; ID_BYTES],
        now_ms: u64,
    ) -> Result<(), RelayError> {
        let key = text_id::<ReservationId>(reservation_id)?;
        if !self.endpoint_states.contains_key(&key) {
            return Err(RelayError::LeaseInvariant);
        }
        self.ledger_mut()?
            .mark_tunnel_established(&key, unix_seconds(now_ms))?;
        Ok(())
    }

    /// Explicitly release one relay allocation.
    ///
    /// # Errors
    ///
    /// Disabled or unknown reservations are rejected.
    pub fn release(&mut self, reservation_id: &[u8; ID_BYTES]) -> Result<(), RelayError> {
        let key = text_id::<ReservationId>(reservation_id)?;
        self.ledger_mut()?.release(&key)?;
        self.endpoint_states.remove(&key);
        self.sync_metrics();
        self.response_cache
            .retain(|_, cached| cached.response.reservation_id() != reservation_id);
        Ok(())
    }

    /// Release expired or never-established allocations and return their count.
    pub fn purge_expired(&mut self, now_ms: u64) -> usize {
        let expired = self.ledger.as_mut().map_or_else(Vec::new, |ledger| {
            ledger.purge_expired(unix_seconds(now_ms))
        });
        let expired_reservation_ids = expired
            .iter()
            .map(|allocation| allocation.reservation_id.as_str())
            .collect::<HashSet<_>>();
        for allocation in &expired {
            self.endpoint_states.remove(&allocation.reservation_id);
        }
        self.response_cache.retain(|_, cached| {
            let reservation_id = hex::encode(cached.response.reservation_id());
            cached.expires_at_ms > now_ms
                && !expired_reservation_ids.contains(reservation_id.as_str())
        });
        self.sync_metrics();
        expired.len()
    }

    /// Return the public endpoint pair and its opaque helper capabilities.
    #[must_use]
    pub fn endpoint_lease(&self, reservation_id: &[u8; ID_BYTES]) -> Option<RelayEndpointLease> {
        let key = text_id::<ReservationId>(reservation_id).ok()?;
        self.endpoint_states.get(&key).map(|state| state.endpoint)
    }

    /// Return the public endpoint tuples committed to signed control messages.
    ///
    /// The opaque lease capabilities, not these tuples, authorize helper operations.
    #[must_use]
    pub fn endpoints(
        &self,
        reservation_id: &[u8; ID_BYTES],
    ) -> Option<(PublicWireGuardEndpoint, PublicWireGuardEndpoint)> {
        let key = text_id::<ReservationId>(reservation_id).ok()?;
        let state = self.endpoint_states.get(&key)?;
        Some((
            state.endpoint.client_facing_endpoint(),
            state.endpoint.exit_facing_endpoint(),
        ))
    }

    /// Return current free relay capacity, or `None` while disabled.
    pub fn available(&mut self, now_ms: u64) -> Option<AvailableCapacity> {
        let result = self
            .ledger
            .as_mut()
            .map(|ledger| ledger.available(unix_seconds(now_ms)));
        self.sync_metrics();
        result
    }

    fn ledger_mut(&mut self) -> Result<&mut CapacityLedger, RelayError> {
        self.ledger.as_mut().ok_or(RelayError::Disabled)
    }

    fn sync_metrics(&self) {
        if let (Some(metrics), Some(ledger)) = (&self.metrics, &self.ledger) {
            let result = metrics.set_relay_reservations(ledger.allocation_count());
            debug_assert!(result.is_ok(), "validated relay metric bound");
        }
    }
}

/// A relay-signed acceptance safe to return to the requesting client.
#[derive(Clone)]
pub struct AcceptedRelayReservation {
    encoded: Vec<u8>,
    reservation_id: [u8; ID_BYTES],
    route_context_id: [u8; ID_BYTES],
    path_id: u32,
    exit_node_id: [u8; NODE_ID_BYTES],
    expires_at_ms: u64,
}

impl AcceptedRelayReservation {
    /// Return the canonical signed relay envelope.
    #[must_use]
    pub fn encoded(&self) -> &[u8] {
        &self.encoded
    }

    /// Return the short-lived reservation identifier.
    #[must_use]
    pub const fn reservation_id(&self) -> &[u8; ID_BYTES] {
        &self.reservation_id
    }

    /// Return the temporary route context identifier.
    #[must_use]
    pub const fn route_context_id(&self) -> &[u8; ID_BYTES] {
        &self.route_context_id
    }

    /// Return the non-zero path number within the route context.
    #[must_use]
    pub const fn path_id(&self) -> u32 {
        self.path_id
    }

    /// Return the exit identity visible to this relay.
    #[must_use]
    pub const fn exit_node_id(&self) -> &[u8; NODE_ID_BYTES] {
        &self.exit_node_id
    }

    /// Return the exclusive signed expiry in Unix milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }
}

impl fmt::Debug for AcceptedRelayReservation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AcceptedRelayReservation")
            .field("path_id", &self.path_id)
            .field("expires_at_ms", &self.expires_at_ms)
            .field("wireguard_keys", &"<redacted>")
            .finish_non_exhaustive()
    }
}

struct CachedRelayResponse {
    request: Vec<u8>,
    response: AcceptedRelayReservation,
    expires_at_ms: u64,
}

struct VerifiedRelayScope<'a> {
    request: &'a RelayReservationRequest,
    request_public_key: [u8; NODE_ID_BYTES],
    capability: &'a ClientSessionCapability,
    capability_public_key: [u8; NODE_ID_BYTES],
    exit: &'a ExitReservation,
    exit_public_key: [u8; NODE_ID_BYTES],
    authorization: &'a RelayAuthorization,
    authorization_public_key: [u8; NODE_ID_BYTES],
}

fn validate_relay_scope(scope: &VerifiedRelayScope<'_>) -> Result<(), RelayError> {
    let request = scope.request;
    let capability = scope.capability;
    let exit = scope.exit;
    let authorization = scope.authorization;
    if scope.request_public_key.as_slice() != capability.client_session_public_key
        || scope.capability_public_key != scope.exit_public_key
        || scope.exit_public_key != scope.authorization_public_key
        || peer_id_from_public_key(&scope.exit_public_key)? != exit.exit_peer_id
        || request.client_session_id != capability.client_session_id
        || request.created_at_ms < capability.created_at_ms
        || request.expires_at_ms > capability.expires_at_ms
        || request.created_at_ms < authorization.created_at_ms
        || request.expires_at_ms > authorization.expires_at_ms
        || !same_capability_and_exit_scope(capability, exit)
        || !same_authorization_and_exit_scope(authorization, exit, capability)
    {
        return Err(RelayError::ClientScopeMismatch);
    }
    Ok(())
}

fn same_capability_and_exit_scope(
    capability: &ClientSessionCapability,
    exit: &ExitReservation,
) -> bool {
    capability.reservation_id == exit.reservation_id
        && capability.route_context_id == exit.route_context_id
        && capability.client_session_id == exit.client_session_id
        && capability.client_session_public_key == exit.client_session_public_key
        && capability.exit_node_id == exit.exit_node_id
        && capability.exit_peer_id == exit.exit_peer_id
        && capability.exit_boot_id == exit.exit_boot_id
        && capability.control_relay_node_id == exit.control_relay_node_id
        && capability.control_relay_peer_id == exit.control_relay_peer_id
        && capability.policy_hash == exit.policy_hash
        && capability.allowed_transports == exit.allowed_transports
        && capability.reserved_up_mbps == exit.reserved_up_mbps
        && capability.reserved_down_mbps == exit.reserved_down_mbps
        && capability.maximum_paths >= exit.maximum_paths
        && capability.created_at_ms == exit.created_at_ms
        && capability.expires_at_ms == exit.expires_at_ms
        && capability.capability_id == exit.capability_id
}

fn same_authorization_and_exit_scope(
    authorization: &RelayAuthorization,
    exit: &ExitReservation,
    capability: &ClientSessionCapability,
) -> bool {
    authorization.reservation_id == exit.reservation_id
        && authorization.route_context_id == exit.route_context_id
        && authorization.path_id <= capability.probe_permit_limit
        && authorization.exit_node_id == exit.exit_node_id
        && authorization.exit_peer_id == exit.exit_peer_id
        && authorization.client_session_id == exit.client_session_id
        && authorization.client_session_public_key == exit.client_session_public_key
        && authorization.allowed_transports == exit.allowed_transports
        && authorization.maximum_up_mbps == exit.reserved_up_mbps
        && authorization.maximum_down_mbps == exit.reserved_down_mbps
        && authorization.policy_hash == exit.policy_hash
        && authorization.created_at_ms == exit.created_at_ms
        && authorization.expires_at_ms == exit.expires_at_ms
        && authorization.capability_id == exit.capability_id
        && authorization.exit_boot_id == exit.exit_boot_id
        && authorization.hold_id == exit.hold_id
        && authorization.finalize_id == exit.finalize_id
        && authorization.control_relay_node_id == exit.control_relay_node_id
        && authorization.control_relay_peer_id == exit.control_relay_peer_id
}

fn rollback_replay(
    cache: &mut ReplayCache,
    entries: &[([u8; NODE_ID_BYTES], [u8; NODE_ID_BYTES])],
) {
    for (sender, nonce) in entries.iter().rev() {
        let _ = cache.rollback(sender, nonce);
    }
}

fn relay_allocation(
    authorization: &RelayAuthorization,
    now_ms: u64,
) -> Result<AuthorizedReservation, RelayError> {
    AuthorizedReservation {
        reservation_id: text_id::<ReservationId>(&authorization.reservation_id)?,
        route_context_id: text_id::<RouteContextId>(&authorization.route_context_id)?,
        service_node_id: text_id::<NodeId>(&authorization.relay_node_id)?,
        client_ephemeral_id: text_id::<ClientEphemeralId>(&authorization.client_session_id)?,
        role: ServiceRole::Relay,
        allowed_transports: core_transports(&authorization.allowed_transports)?,
        bandwidth: Bandwidth::new(
            u32::try_from(authorization.maximum_up_mbps)
                .map_err(|_| RelayError::InvalidGrant("upload rate"))?,
            u32::try_from(authorization.maximum_down_mbps)
                .map_err(|_| RelayError::InvalidGrant("download rate"))?,
        )
        .map_err(|_| RelayError::InvalidGrant("bandwidth"))?,
        maximum_paths: 1,
        created_at: unix_milliseconds_floor(authorization.created_at_ms),
        expires_at: unix_milliseconds_floor(authorization.expires_at_ms),
    }
    .checked_at(now_ms)
}

trait CheckedReservation {
    fn checked_at(self, now_ms: u64) -> Result<Self, RelayError>
    where
        Self: Sized;
}

impl CheckedReservation for AuthorizedReservation {
    fn checked_at(self, now_ms: u64) -> Result<Self, RelayError> {
        if self.expires_at <= self.created_at || self.expires_at.is_expired_at(unix_seconds(now_ms))
        {
            return Err(RelayError::InvalidGrant("millisecond lifetime"));
        }
        Ok(self)
    }
}

fn core_transports(transports: &[i32]) -> Result<Vec<CoreTransport>, RelayError> {
    transports
        .iter()
        .map(
            |transport| match volparossa_protocol::Transport::try_from(*transport) {
                Ok(volparossa_protocol::Transport::TcpMptcp) => Ok(CoreTransport::TcpMptcp),
                Ok(volparossa_protocol::Transport::UdpSinglePath) => {
                    Ok(CoreTransport::UdpSinglePath)
                }
                Ok(volparossa_protocol::Transport::MultipathQuic) => {
                    Ok(CoreTransport::MultipathQuic)
                }
                Ok(volparossa_protocol::Transport::Unspecified) | Err(_) => {
                    Err(RelayError::InvalidGrant("transport"))
                }
            },
        )
        .collect()
}

fn public_key(bytes: &[u8], field: &'static str) -> Result<WireGuardPublicKey, RelayError> {
    let bytes = fixed(bytes, field)?;
    if bytes == [0; NODE_ID_BYTES] {
        return Err(RelayError::InvalidGrant(field));
    }
    Ok(WireGuardPublicKey::from_bytes(bytes))
}

fn unix_seconds(milliseconds: u64) -> UnixTime {
    UnixTime::from_secs(milliseconds / 1_000)
}

fn unix_milliseconds_floor(milliseconds: u64) -> UnixTime {
    unix_seconds(milliseconds)
}

fn text_id<T>(bytes: &[u8]) -> Result<T, RelayError>
where
    T: TryFrom<String>,
{
    T::try_from(hex::encode(bytes)).map_err(|_| RelayError::InvalidGrant("identifier"))
}

fn fixed<const N: usize>(bytes: &[u8], name: &'static str) -> Result<[u8; N], RelayError> {
    bytes.try_into().map_err(|_| RelayError::InvalidGrant(name))
}

fn peer_id_from_public_key(public_key: &[u8; 32]) -> Result<Vec<u8>, RelayError> {
    let ed25519 = libp2p_identity::ed25519::PublicKey::try_from_bytes(public_key)
        .map_err(|_| RelayError::LocalIdentityMismatch)?;
    Ok(libp2p_identity::PublicKey::from(ed25519)
        .to_peer_id()
        .to_bytes())
}

fn wire_endpoint(endpoint: PublicWireGuardEndpoint) -> WireguardEndpoint {
    let underlay_ip = match endpoint.underlay_ip() {
        IpAddr::V4(address) => address.octets().to_vec(),
        IpAddr::V6(address) => address.octets().to_vec(),
    };
    WireguardEndpoint {
        public_key: endpoint.public_key().as_bytes().to_vec(),
        underlay_ip,
        listen_port: u32::from(endpoint.listen_port()),
    }
}

fn public_endpoint(
    endpoint: &WireguardEndpoint,
    name: &'static str,
) -> Result<PublicWireGuardEndpoint, RelayError> {
    endpoint.validate(name)?;
    let key = public_key(&endpoint.public_key, name)?;
    let address = match endpoint.underlay_ip.as_slice() {
        [a, b, c, d] => IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d)),
        bytes => IpAddr::V6(Ipv6Addr::from(fixed::<16>(bytes, name)?)),
    };
    let port = u16::try_from(endpoint.listen_port).map_err(|_| RelayError::InvalidGrant(name))?;
    PublicWireGuardEndpoint::new(key, address, port).map_err(|_| RelayError::InvalidGrant(name))
}

struct RelayPathState {
    endpoint: RelayEndpointLease,
    client_endpoint: PublicWireGuardEndpoint,
    exit_endpoint: PublicWireGuardEndpoint,
}

impl fmt::Debug for RelayPathState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RelayPathState")
            .field("endpoint", &self.endpoint)
            .field("client_endpoint", &self.client_endpoint)
            .field("exit_endpoint", &self.exit_endpoint)
            .finish()
    }
}

/// Fail-closed relay admission errors.
#[derive(Debug, Error)]
pub enum RelayError {
    /// The operator has not explicitly enabled the relay role.
    #[error("relay role is disabled")]
    Disabled,
    /// The bounded exact-response cache is full of still-live reservations.
    #[error("relay idempotency cache is full")]
    IdempotencyCapacity,

    /// Configuration exceeded a fixed safe bound.
    #[error("invalid relay configuration: {0}")]
    InvalidConfig(&'static str),
    /// Signed control verification or signing failed.
    #[error("relay control authorization failed: {0}")]
    Protocol(#[from] ProtocolError),
    /// The authorization targets a different relay.
    #[error("relay authorization targets another node")]
    WrongRelay,
    /// The supplied local signer is not this configured relay.
    #[error("local signing identity does not match configured relay")]
    LocalIdentityMismatch,
    /// The signed relay Peer ID is not derived from the local Ed25519 identity.
    #[error("relay Peer ID does not match the local signing identity")]
    PeerIdentityMismatch,
    /// The signed session request and embedded exit grants do not share one exact scope.
    #[error("client reservation request does not match the exit-authorized scope")]
    ClientScopeMismatch,
    /// No helper/orchestrator-confirmed local endpoint lease was available.
    #[error("route-specific WireGuard endpoint is unavailable")]
    EndpointUnavailable,
    /// An authenticated grant could not be mapped into bounded local state.
    #[error("invalid relay grant: {0}")]
    InvalidGrant(&'static str),
    /// Atomic capacity admission or lifecycle accounting failed.
    #[error("relay reservation accounting failed: {0}")]
    Reservation(#[from] ReservationError),
    /// A rollback contradicted the capacity-ledger invariant.
    #[error("relay capacity-ledger invariant failed")]
    LedgerInvariant,
    /// Local helper lease state contradicted an authenticated reservation.
    #[error("relay helper-lease state invariant failed")]
    LeaseInvariant,
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};

    use ed25519_dalek::Signer as _;
    use volparossa_core::Bandwidth;
    use volparossa_metrics::MetricsRegistry;
    use volparossa_protocol::{
        ClientSessionCapability, MAX_CONTROL_MESSAGE_SIZE, MAX_CONTROL_PAYLOAD_SIZE, ProtocolError,
        RelayReservationRequest, ReplayCache, SignedEnvelope, TimePolicy, Transport,
        decode_canonical, sign_control_message, verify_relay_reservation,
    };
    use volparossa_test_support::SignedRouteFixture;
    use volparossa_wireguard::{
        EndpointRole, HelperContextHandle, HelperLeaseHandle, PublicWireGuardEndpoint,
        RelayEndpointLease, WireGuardPublicKey,
    };

    use super::{RelayError, RelayService, RelayServiceConfig};

    const NOW_MS: u64 = 1_700_000_000_000;

    fn service_for(fixture: &SignedRouteFixture, metrics: MetricsRegistry) -> RelayService {
        RelayService::new(
            RelayServiceConfig::enabled(
                fixture.relay_node_id(0).unwrap(),
                Bandwidth::new(200, 200).unwrap(),
                2,
                900,
                5,
                64,
            ),
            Some(metrics),
        )
        .unwrap()
    }

    #[test]
    fn verifies_v4_grants_reserves_capacity_and_signs_exact_acceptance() {
        let fixture = SignedRouteFixture::new(1, &[Transport::UdpSinglePath], NOW_MS).unwrap();
        let metrics = MetricsRegistry::new();
        let mut service = service_for(&fixture, metrics.clone());
        let relay_key = fixture.relay_key(0).unwrap();
        let accepted = service
            .accept_request_with(
                fixture.relay_request(0).unwrap(),
                NOW_MS,
                relay_key.verifying_key().to_bytes(),
                |path_id| relay_endpoint(*fixture.route_context_id(), path_id),
                |message| Some(relay_key.sign(message).to_bytes()),
            )
            .unwrap();

        let mut replay_cache = ReplayCache::new(8).unwrap();
        let (relay_message, exit_message) = verify_relay_reservation(
            accepted.encoded(),
            NOW_MS,
            TimePolicy::default(),
            &mut replay_cache,
        )
        .unwrap();
        assert_eq!(relay_message.message().path_id, 1);
        assert_eq!(
            relay_message.message().client_session_id,
            fixture.client_session_id()
        );
        assert_eq!(
            relay_message.message().exit_boot_id,
            exit_message.message().exit_boot_id
        );
        assert_eq!(
            relay_message.message().finalize_id,
            exit_message.message().finalize_id
        );
        assert_eq!(metrics.snapshot().active_reservations, 1);
        assert_eq!(service.available(NOW_MS).unwrap().bandwidth.up_mbps, 100);
        assert!(service.endpoint_lease(accepted.reservation_id()).is_some());

        service
            .mark_tunnel_established(accepted.reservation_id(), NOW_MS)
            .unwrap();
        service.release(accepted.reservation_id()).unwrap();
        assert_eq!(metrics.snapshot().active_reservations, 0);
        assert!(service.endpoint_lease(accepted.reservation_id()).is_none());
    }

    #[test]
    fn noncontiguous_authorization_uses_probe_limit_and_exact_final_count() {
        let fixture =
            SignedRouteFixture::new_with_path_ids(&[8], 3, 8, &[Transport::UdpSinglePath], NOW_MS)
                .unwrap();
        let relay_key = fixture.relay_key(0).unwrap();
        let mut service = service_for(&fixture, MetricsRegistry::new());

        let reduced_probe_scope = rewrite_request(&fixture, |request| {
            let envelope: SignedEnvelope =
                decode_canonical(&request.client_session_capability, MAX_CONTROL_MESSAGE_SIZE)
                    .unwrap();
            let mut capability: ClientSessionCapability =
                decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
            capability.probe_permit_limit = 7;
            let nonce = capability.nonce.as_slice().try_into().unwrap();
            request.client_session_capability = sign_control_message(
                &capability,
                fixture.exit_key(),
                capability.created_at_ms,
                capability.expires_at_ms,
                nonce,
                TimePolicy::default(),
            )
            .unwrap();
        });
        assert!(matches!(
            service.accept_request_with(
                &reduced_probe_scope,
                NOW_MS,
                relay_key.verifying_key().to_bytes(),
                |_path_id| panic!("out-of-probe-scope authorization reached helper allocation"),
                |_message| panic!("out-of-probe-scope authorization reached relay signing"),
            ),
            Err(RelayError::ClientScopeMismatch)
        ));

        let accepted = service
            .accept_request_with(
                fixture.relay_request(0).unwrap(),
                NOW_MS,
                relay_key.verifying_key().to_bytes(),
                |path_id| relay_endpoint(*fixture.route_context_id(), path_id),
                |message| Some(relay_key.sign(message).to_bytes()),
            )
            .unwrap();
        assert_eq!(accepted.path_id(), 8);
    }

    #[test]
    fn signing_failure_rolls_back_capacity_replay_and_helper_lease() {
        let fixture = SignedRouteFixture::new(1, &[Transport::UdpSinglePath], NOW_MS).unwrap();
        let relay_key = fixture.relay_key(0).unwrap();
        let mut service = service_for(&fixture, MetricsRegistry::new());
        assert!(matches!(
            service.accept_request_with(
                fixture.relay_request(0).unwrap(),
                NOW_MS,
                relay_key.verifying_key().to_bytes(),
                |path_id| relay_endpoint(*fixture.route_context_id(), path_id),
                |_message| None,
            ),
            Err(RelayError::Protocol(ProtocolError::SigningFailed))
        ));
        let available = service.available(NOW_MS).unwrap();
        assert_eq!(available.bandwidth, Bandwidth::new(200, 200).unwrap());
        assert_eq!(available.free_slots, 2);
        assert!(service.endpoint_lease(fixture.reservation_id()).is_none());

        service
            .accept_request_with(
                fixture.relay_request(0).unwrap(),
                NOW_MS,
                relay_key.verifying_key().to_bytes(),
                |path_id| relay_endpoint(*fixture.route_context_id(), path_id),
                |message| Some(relay_key.sign(message).to_bytes()),
            )
            .expect("failed local transaction must not burn request or nested grant replay state");
    }

    #[test]
    fn exact_retry_wrong_signer_and_disabled_role_fail_closed() {
        let fixture = SignedRouteFixture::new(1, &[Transport::UdpSinglePath], NOW_MS).unwrap();
        let relay_key = fixture.relay_key(0).unwrap();
        let mut service = service_for(&fixture, MetricsRegistry::new());
        let accepted = service
            .accept_request_with(
                fixture.relay_request(0).unwrap(),
                NOW_MS,
                relay_key.verifying_key().to_bytes(),
                |path_id| relay_endpoint(*fixture.route_context_id(), path_id),
                |message| Some(relay_key.sign(message).to_bytes()),
            )
            .unwrap();
        let expected = accepted.encoded().to_vec();
        assert!(matches!(
            service.accept_request_with(
                fixture.relay_request(0).unwrap(),
                NOW_MS,
                fixture.exit_key().verifying_key().to_bytes(),
                |_path_id| None,
                |_message| None,
            ),
            Err(RelayError::LocalIdentityMismatch)
        ));
        let replay = service.accept_request_with(
            fixture.relay_request(0).unwrap(),
            NOW_MS,
            relay_key.verifying_key().to_bytes(),
            |_path_id| panic!("exact retry must not allocate another helper lease"),
            |_message| panic!("exact retry must return the cached signed response"),
        );
        assert_eq!(replay.unwrap().encoded(), expected);

        let mut disabled = RelayService::new(
            RelayServiceConfig::disabled(fixture.relay_node_id(0).unwrap()),
            None,
        )
        .unwrap();
        assert!(matches!(
            disabled.accept_request_with(
                fixture.relay_request(0).unwrap(),
                NOW_MS,
                relay_key.verifying_key().to_bytes(),
                |_path_id| None,
                |_message| None,
            ),
            Err(RelayError::Disabled)
        ));
    }

    #[test]
    fn substituted_capability_rolls_back_the_whole_transaction() {
        let fixture = SignedRouteFixture::new(1, &[Transport::UdpSinglePath], NOW_MS).unwrap();
        let substitute = SignedRouteFixture::new(1, &[Transport::UdpSinglePath], NOW_MS).unwrap();
        let relay_key = fixture.relay_key(0).unwrap();
        let mut service = service_for(&fixture, MetricsRegistry::new());
        let cross_scoped = rewrite_request(&fixture, |request| {
            request.client_session_capability = substitute.client_session_capability().to_vec();
        });
        assert!(matches!(
            service.accept_request_with(
                &cross_scoped,
                NOW_MS,
                relay_key.verifying_key().to_bytes(),
                |_path_id| panic!("cross-scoped grants reached endpoint allocation"),
                |_message| panic!("cross-scoped grants reached signing"),
            ),
            Err(RelayError::ClientScopeMismatch)
        ));
        let available = service.available(NOW_MS).unwrap();
        assert_eq!(available.bandwidth, Bandwidth::new(200, 200).unwrap());
        assert_eq!(available.free_slots, 2);
        assert!(service.response_cache.is_empty());

        service
            .accept_request_with(
                fixture.relay_request(0).unwrap(),
                NOW_MS,
                relay_key.verifying_key().to_bytes(),
                |path_id| relay_endpoint(*fixture.route_context_id(), path_id),
                |message| Some(relay_key.sign(message).to_bytes()),
            )
            .expect("cross-scoped attempt must roll back the shared request nonce");
    }

    #[test]
    fn exact_retry_cache_never_outlives_the_short_request() {
        let fixture = SignedRouteFixture::new(1, &[Transport::UdpSinglePath], NOW_MS).unwrap();
        let relay_key = fixture.relay_key(0).unwrap();
        let mut service = service_for(&fixture, MetricsRegistry::new());
        let accepted = service
            .accept_request_with(
                fixture.relay_request(0).unwrap(),
                NOW_MS,
                relay_key.verifying_key().to_bytes(),
                |path_id| relay_endpoint(*fixture.route_context_id(), path_id),
                |message| Some(relay_key.sign(message).to_bytes()),
            )
            .unwrap();
        service
            .mark_tunnel_established(accepted.reservation_id(), NOW_MS)
            .unwrap();

        assert_eq!(service.purge_expired(NOW_MS + 21_000), 0);
        assert!(service.response_cache.is_empty());
        assert!(matches!(
            service.accept_request_with(
                fixture.relay_request(0).unwrap(),
                NOW_MS + 21_000,
                relay_key.verifying_key().to_bytes(),
                |_path_id| None,
                |_message| None,
            ),
            Err(RelayError::Protocol(ProtocolError::Expired))
        ));
        assert!(service.endpoint_lease(accepted.reservation_id()).is_some());
    }

    #[test]
    fn pending_tunnel_is_released_after_setup_deadline() {
        let fixture = SignedRouteFixture::new(1, &[Transport::UdpSinglePath], NOW_MS).unwrap();
        let metrics = MetricsRegistry::new();
        let mut service = service_for(&fixture, metrics.clone());
        let relay_key = fixture.relay_key(0).unwrap();
        let accepted = service
            .accept_request_with(
                fixture.relay_request(0).unwrap(),
                NOW_MS,
                relay_key.verifying_key().to_bytes(),
                |path_id| relay_endpoint(*fixture.route_context_id(), path_id),
                |message| Some(relay_key.sign(message).to_bytes()),
            )
            .unwrap();
        assert!(service.endpoint_lease(accepted.reservation_id()).is_some());
        assert_eq!(service.purge_expired(NOW_MS + 6_000), 1);
        assert_eq!(metrics.snapshot().active_reservations, 0);
        assert!(service.endpoint_lease(accepted.reservation_id()).is_none());
        let available = service.available(NOW_MS + 6_000).unwrap();
        assert_eq!(available.bandwidth, Bandwidth::new(200, 200).unwrap());
        assert_eq!(available.free_slots, 2);
        assert!(service.response_cache.is_empty());
    }

    fn rewrite_request(
        fixture: &SignedRouteFixture,
        edit: impl FnOnce(&mut RelayReservationRequest),
    ) -> Vec<u8> {
        let envelope: SignedEnvelope =
            decode_canonical(fixture.relay_request(0).unwrap(), MAX_CONTROL_MESSAGE_SIZE).unwrap();
        let mut request: RelayReservationRequest =
            decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE).unwrap();
        edit(&mut request);
        let nonce = request.nonce.as_slice().try_into().unwrap();
        sign_control_message(
            &request,
            fixture.client_key(),
            request.created_at_ms,
            request.expires_at_ms,
            nonce,
            TimePolicy::default(),
        )
        .unwrap()
    }

    fn relay_endpoint(route_context_id: [u8; 16], path_id: u32) -> Option<RelayEndpointLease> {
        let offset = u16::try_from(path_id).ok()?.checked_mul(2)?;
        let path_seed = u8::try_from(path_id).ok()?.checked_mul(2)?;
        let client_facing = PublicWireGuardEndpoint::new(
            WireGuardPublicKey::from_bytes([50_u8.checked_add(path_seed)?; 32]),
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 20)),
            40_000_u16.checked_add(offset)?,
        )
        .ok()?;
        let exit_facing = PublicWireGuardEndpoint::new(
            WireGuardPublicKey::from_bytes([51_u8.checked_add(path_seed)?; 32]),
            IpAddr::V4(Ipv4Addr::new(8, 8, 4, 21)),
            40_001_u16.checked_add(offset)?,
        )
        .ok()?;
        RelayEndpointLease::new(
            route_context_id,
            HelperContextHandle::from_bytes([202; 32]).ok()?,
            HelperLeaseHandle::from_bytes([230_u8.checked_add(path_seed)?; 32]).ok()?,
            HelperLeaseHandle::from_bytes([231_u8.checked_add(path_seed)?; 32]).ok()?,
            path_id,
            EndpointRole::RelayClient,
            EndpointRole::RelayExit,
            client_facing,
            exit_facing,
        )
        .ok()
    }
}
