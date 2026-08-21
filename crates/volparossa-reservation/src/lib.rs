//! Atomic, expiring reservation accounting.
//!
//! Signature, nonce/replay and exit-authorization verification happen in the
//! protocol layer before an [`AuthorizedReservation`] reaches this ledger.
//! Acceptance immediately consumes both bandwidth and one session slot.  A
//! pending allocation is released automatically if its tunnel is not
//! established by the shorter setup deadline.

mod coordinator;

pub use coordinator::{
    CoordinatorError, ExitReservationIntent, RelayPathIntent, ReservationCoordinator,
    SignedExitFinalizeRequest, SignedProbePermitRequest, VerifiedExitCapacityHold,
    VerifiedFinalizedExitBundle, VerifiedProbePermit, VerifiedRelayGrant, VerifiedRelayProbe,
};

use serde::{Deserialize, Serialize};
use std::collections::{HashMap, HashSet};
use thiserror::Error;
use volparossa_core::{
    Bandwidth, ClientEphemeralId, NodeId, ReservationId, RouteContextId, ServiceRole, Transport,
    UnixTime,
};

/// Maximum number of distinct transport values in one reservation.
const MAX_ALLOWED_TRANSPORTS: usize = 3;

/// A request after control-message authentication, replay and policy checks.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct AuthorizedReservation {
    /// Globally unguessable, signed short-lived identifier.
    pub reservation_id: ReservationId,
    /// Route context to which the allocation is scoped.
    pub route_context_id: RouteContextId,
    /// Local relay or exit node accepting this allocation.
    pub service_node_id: NodeId,
    /// Ephemeral client identity, never an account identity.
    pub client_ephemeral_id: ClientEphemeralId,
    /// Relay or exit ledger to consume.
    pub role: ServiceRole,
    /// Exact transports authorized by policy.
    pub allowed_transports: Vec<Transport>,
    /// Bidirectional reserved bandwidth.
    pub bandwidth: Bandwidth,
    /// Maximum path count authorized by an exit reservation.
    pub maximum_paths: u8,
    /// Signed creation timestamp.
    pub created_at: UnixTime,
    /// Signed hard expiry.
    pub expires_at: UnixTime,
}

impl AuthorizedReservation {
    fn validate(&self, limits: &LedgerLimits, now: UnixTime) -> Result<(), ReservationError> {
        if self.role != limits.role || self.service_node_id != limits.service_node_id {
            return Err(ReservationError::WrongLedger);
        }
        self.bandwidth
            .validate()
            .map_err(|_| ReservationError::InvalidBandwidth)?;
        if self.bandwidth.up_mbps == 0 || self.bandwidth.down_mbps == 0 {
            return Err(ReservationError::InvalidBandwidth);
        }
        if self.allowed_transports.is_empty()
            || self.allowed_transports.len() > MAX_ALLOWED_TRANSPORTS
        {
            return Err(ReservationError::InvalidTransports);
        }
        let unique: HashSet<Transport> = self.allowed_transports.iter().copied().collect();
        if unique.len() != self.allowed_transports.len() {
            return Err(ReservationError::InvalidTransports);
        }
        if self.maximum_paths == 0
            || self.maximum_paths > 8
            || (self.role == ServiceRole::Relay && self.maximum_paths != 1)
        {
            return Err(ReservationError::InvalidMaximumPaths);
        }
        if self.created_at > now
            || self.expires_at <= self.created_at
            || self.expires_at.is_expired_at(now)
        {
            return Err(ReservationError::InvalidLifetime);
        }
        if self.expires_at.as_secs() - self.created_at.as_secs()
            > limits.maximum_reservation_ttl_seconds
        {
            return Err(ReservationError::LifetimeTooLong);
        }
        Ok(())
    }
}

/// Fixed per-role operator limits for one local service node.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LedgerLimits {
    /// Local service node identity.
    pub service_node_id: NodeId,
    /// Independently enabled role accounted by this ledger.
    pub role: ServiceRole,
    /// Operator-configured bandwidth ceiling.
    pub bandwidth: Bandwidth,
    /// Operator-configured concurrent session ceiling.
    pub maximum_sessions: u32,
    /// Maximum accepted signed reservation lifetime.
    pub maximum_reservation_ttl_seconds: u64,
    /// Time allowed to establish the reserved tunnel.
    pub tunnel_setup_timeout_seconds: u64,
}

impl LedgerLimits {
    fn validate(&self) -> Result<(), ReservationError> {
        self.bandwidth
            .validate()
            .map_err(|_| ReservationError::InvalidLimits)?;
        if self.bandwidth.up_mbps == 0
            || self.bandwidth.down_mbps == 0
            || self.maximum_sessions == 0
            || self.maximum_reservation_ttl_seconds == 0
            || self.tunnel_setup_timeout_seconds == 0
            || self.tunnel_setup_timeout_seconds > self.maximum_reservation_ttl_seconds
        {
            return Err(ReservationError::InvalidLimits);
        }
        Ok(())
    }
}

/// Pending-tunnel or active allocation state.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum AllocationState {
    /// Capacity is consumed while tunnel establishment is awaited.
    PendingTunnel,
    /// Tunnel establishment completed before its deadline.
    Active,
}

/// Accepted reservation metadata returned to the service.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ReservationGrant {
    /// Accepted authenticated request.
    pub reservation: AuthorizedReservation,
    /// Acceptance instant.
    pub accepted_at: UnixTime,
    /// Deadline for marking tunnel establishment.
    pub tunnel_setup_deadline: UnixTime,
    /// Current allocation state.
    pub state: AllocationState,
}

/// Capacity and slots available after all accepted allocations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct AvailableCapacity {
    /// Remaining bidirectional bandwidth.
    pub bandwidth: Bandwidth,
    /// Remaining concurrent reservation slots.
    pub free_slots: u32,
}

/// Why an allocation was automatically released.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ExpiryReason {
    /// Signed hard expiry was reached.
    ReservationExpired,
    /// The tunnel was not established by the shorter setup deadline.
    TunnelNotEstablished,
}

/// One automatically released allocation.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct ExpiredAllocation {
    /// Released reservation identifier.
    pub reservation_id: ReservationId,
    /// Auditable release reason.
    pub reason: ExpiryReason,
}

/// In-memory, per-role capacity ledger.
#[derive(Debug)]
pub struct CapacityLedger {
    limits: LedgerLimits,
    reserved: Bandwidth,
    grants: HashMap<ReservationId, ReservationGrant>,
}

impl CapacityLedger {
    /// Constructs an empty ledger after validating that its role is enabled
    /// with finite non-zero capacity and slots.
    ///
    /// # Errors
    ///
    /// Returns an error when the bandwidth, session, reservation-lifetime, or tunnel-setup limits
    /// are zero, inconsistent, or outside defensive bounds.
    pub fn new(limits: LedgerLimits) -> Result<Self, ReservationError> {
        limits.validate()?;
        Ok(Self {
            limits,
            reserved: Bandwidth::default(),
            grants: HashMap::new(),
        })
    }

    /// Atomically accepts a request, immediately reducing advertised free capacity.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid, expired, or duplicate reservation, exhausted bandwidth or
    /// session capacity, arithmetic overflow, or an invalid setup deadline. The ledger is not
    /// partially updated on failure.
    pub fn reserve(
        &mut self,
        reservation: AuthorizedReservation,
        now: UnixTime,
    ) -> Result<ReservationGrant, ReservationError> {
        self.purge_expired(now);
        reservation.validate(&self.limits, now)?;
        if self.grants.contains_key(&reservation.reservation_id) {
            return Err(ReservationError::DuplicateReservation);
        }
        let next_up = self
            .reserved
            .up_mbps
            .checked_add(reservation.bandwidth.up_mbps)
            .ok_or(ReservationError::CapacityOverflow)?;
        let next_down = self
            .reserved
            .down_mbps
            .checked_add(reservation.bandwidth.down_mbps)
            .ok_or(ReservationError::CapacityOverflow)?;
        if next_up > self.limits.bandwidth.up_mbps || next_down > self.limits.bandwidth.down_mbps {
            return Err(ReservationError::InsufficientCapacity);
        }
        let session_count =
            u32::try_from(self.grants.len()).map_err(|_| ReservationError::CapacityOverflow)?;
        if session_count >= self.limits.maximum_sessions {
            return Err(ReservationError::NoFreeSlot);
        }
        let setup_deadline = now
            .checked_add(self.limits.tunnel_setup_timeout_seconds)
            .map_err(|_| ReservationError::InvalidLifetime)?;
        let tunnel_setup_deadline = setup_deadline.min(reservation.expires_at);
        let grant = ReservationGrant {
            reservation,
            accepted_at: now,
            tunnel_setup_deadline,
            state: AllocationState::PendingTunnel,
        };
        self.reserved =
            Bandwidth::new(next_up, next_down).map_err(|_| ReservationError::CapacityOverflow)?;
        self.grants
            .insert(grant.reservation.reservation_id.clone(), grant.clone());
        Ok(grant)
    }

    /// Marks successful tunnel establishment before the setup deadline.
    ///
    /// # Errors
    ///
    /// Returns an error when the reservation is unknown or expired, including expiry caused by a
    /// missed tunnel-setup deadline.
    pub fn mark_tunnel_established(
        &mut self,
        reservation_id: &ReservationId,
        now: UnixTime,
    ) -> Result<(), ReservationError> {
        let expired = self.purge_expired(now);
        if expired
            .iter()
            .any(|allocation| &allocation.reservation_id == reservation_id)
        {
            return Err(ReservationError::ReservationExpired);
        }
        let grant = self
            .grants
            .get_mut(reservation_id)
            .ok_or(ReservationError::UnknownReservation)?;
        grant.state = AllocationState::Active;
        Ok(())
    }

    /// Explicitly releases an allocation and returns the removed grant.
    ///
    /// # Errors
    ///
    /// Returns an error when the reservation is unknown or the internal reserved-bandwidth
    /// accounting is inconsistent.
    pub fn release(
        &mut self,
        reservation_id: &ReservationId,
    ) -> Result<ReservationGrant, ReservationError> {
        let grant = self
            .grants
            .remove(reservation_id)
            .ok_or(ReservationError::UnknownReservation)?;
        self.subtract_bandwidth(grant.reservation.bandwidth)?;
        Ok(grant)
    }

    /// Releases every hard-expired or setup-expired allocation at `now`.
    pub fn purge_expired(&mut self, now: UnixTime) -> Vec<ExpiredAllocation> {
        let expired: Vec<(ReservationId, ExpiryReason)> = self
            .grants
            .iter()
            .filter_map(|(id, grant)| {
                if grant.reservation.expires_at.is_expired_at(now) {
                    Some((id.clone(), ExpiryReason::ReservationExpired))
                } else if grant.state == AllocationState::PendingTunnel
                    && grant.tunnel_setup_deadline.is_expired_at(now)
                {
                    Some((id.clone(), ExpiryReason::TunnelNotEstablished))
                } else {
                    None
                }
            })
            .collect();
        let mut released = Vec::with_capacity(expired.len());
        for (reservation_id, reason) in expired {
            if let Some(grant) = self.grants.remove(&reservation_id) {
                let subtraction = self.subtract_bandwidth(grant.reservation.bandwidth);
                debug_assert!(subtraction.is_ok(), "ledger bandwidth invariant");
                released.push(ExpiredAllocation {
                    reservation_id,
                    reason,
                });
            }
        }
        released
    }

    /// Returns free capacity after first releasing allocations expired at `now`.
    pub fn available(&mut self, now: UnixTime) -> AvailableCapacity {
        self.purge_expired(now);
        let session_count = u32::try_from(self.grants.len()).unwrap_or(u32::MAX);
        AvailableCapacity {
            bandwidth: Bandwidth {
                up_mbps: self.limits.bandwidth.up_mbps - self.reserved.up_mbps,
                down_mbps: self.limits.bandwidth.down_mbps - self.reserved.down_mbps,
            },
            free_slots: self.limits.maximum_sessions.saturating_sub(session_count),
        }
    }

    /// Returns an accepted allocation without extending its lifetime.
    #[must_use]
    pub fn grant(&self, reservation_id: &ReservationId) -> Option<&ReservationGrant> {
        self.grants.get(reservation_id)
    }

    /// Returns the number of accepted pending and active allocations.
    #[must_use]
    pub fn allocation_count(&self) -> usize {
        self.grants.len()
    }

    fn subtract_bandwidth(&mut self, bandwidth: Bandwidth) -> Result<(), ReservationError> {
        self.reserved = Bandwidth {
            up_mbps: self
                .reserved
                .up_mbps
                .checked_sub(bandwidth.up_mbps)
                .ok_or(ReservationError::LedgerInvariantViolation)?,
            down_mbps: self
                .reserved
                .down_mbps
                .checked_sub(bandwidth.down_mbps)
                .ok_or(ReservationError::LedgerInvariantViolation)?,
        };
        Ok(())
    }
}

/// Reservation validation, resource or replay failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum ReservationError {
    /// Operator limits are disabled or internally inconsistent.
    #[error("invalid capacity-ledger limits")]
    InvalidLimits,
    /// Request targets another node or role ledger.
    #[error("reservation targets the wrong service ledger")]
    WrongLedger,
    /// Reserved bandwidth is zero, implausible or invalid.
    #[error("invalid reserved bandwidth")]
    InvalidBandwidth,
    /// Transport list is empty, duplicated or oversized.
    #[error("invalid allowed transport list")]
    InvalidTransports,
    /// Path count is outside 1 through 8 or not one for a relay.
    #[error("invalid maximum path count")]
    InvalidMaximumPaths,
    /// Timestamps are inverted, future-created or already expired.
    #[error("invalid reservation lifetime")]
    InvalidLifetime,
    /// Signed lifetime exceeds the configured hard maximum.
    #[error("reservation lifetime exceeds hard maximum")]
    LifetimeTooLong,
    /// A reservation identifier was replayed while accepted.
    #[error("duplicate reservation identifier")]
    DuplicateReservation,
    /// One or both bandwidth directions exceed remaining capacity.
    #[error("insufficient reservation capacity")]
    InsufficientCapacity,
    /// The concurrent session limit was reached.
    #[error("no free reservation slot")]
    NoFreeSlot,
    /// Checked resource arithmetic overflowed.
    #[error("capacity accounting overflow")]
    CapacityOverflow,
    /// The identifier is not currently accepted.
    #[error("unknown reservation")]
    UnknownReservation,
    /// The allocation expired before tunnel establishment.
    #[error("reservation expired")]
    ReservationExpired,
    /// Internal subtraction would underflow, indicating corrupted state.
    #[error("capacity ledger invariant violation")]
    LedgerInvariantViolation,
}
