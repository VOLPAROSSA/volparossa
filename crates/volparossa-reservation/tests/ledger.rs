//! Integration tests for expiring reservation and capacity accounting.

use volparossa_core::{
    Bandwidth, ClientEphemeralId, NodeId, ReservationId, RouteContextId, ServiceRole, Transport,
    UnixTime,
};
use volparossa_reservation::{
    AllocationState, AuthorizedReservation, CapacityLedger, ExpiryReason, LedgerLimits,
    ReservationError,
};

fn bandwidth(value: u32) -> Bandwidth {
    Bandwidth::new(value, value).expect("bounded")
}

fn limits(maximum_sessions: u32) -> LedgerLimits {
    LedgerLimits {
        service_node_id: NodeId::new("exit-a").expect("valid"),
        role: ServiceRole::Exit,
        bandwidth: bandwidth(100),
        maximum_sessions,
        maximum_reservation_ttl_seconds: 300,
        tunnel_setup_timeout_seconds: 20,
    }
}

fn request(id: &str, bandwidth_value: u32, expires_at: u64) -> AuthorizedReservation {
    AuthorizedReservation {
        reservation_id: ReservationId::new(id).expect("valid"),
        route_context_id: RouteContextId::new(format!("route-{id}")).expect("valid"),
        service_node_id: NodeId::new("exit-a").expect("valid"),
        client_ephemeral_id: ClientEphemeralId::new(format!("client-{id}")).expect("valid"),
        role: ServiceRole::Exit,
        allowed_transports: vec![Transport::TcpMptcp, Transport::MultipathQuic],
        bandwidth: bandwidth(bandwidth_value),
        maximum_paths: 4,
        created_at: UnixTime::from_secs(1_000),
        expires_at: UnixTime::from_secs(expires_at),
    }
}

#[test]
fn acceptance_immediately_consumes_capacity_and_is_atomic_on_failure() {
    let mut ledger = CapacityLedger::new(limits(4)).expect("ledger");
    let first = ledger
        .reserve(request("one", 70, 1_200), UnixTime::from_secs(1_010))
        .expect("reserve");
    assert_eq!(first.state, AllocationState::PendingTunnel);
    assert_eq!(
        ledger.available(UnixTime::from_secs(1_011)).bandwidth,
        bandwidth(30)
    );

    assert_eq!(
        ledger.reserve(request("two", 40, 1_200), UnixTime::from_secs(1_012)),
        Err(ReservationError::InsufficientCapacity)
    );
    assert_eq!(ledger.allocation_count(), 1);
    assert_eq!(
        ledger.available(UnixTime::from_secs(1_013)).bandwidth,
        bandwidth(30)
    );
}

#[test]
fn pending_tunnel_expires_at_setup_deadline() {
    let mut ledger = CapacityLedger::new(limits(2)).expect("ledger");
    let grant = ledger
        .reserve(request("one", 40, 1_200), UnixTime::from_secs(1_010))
        .expect("reserve");
    assert_eq!(grant.tunnel_setup_deadline, UnixTime::from_secs(1_030));
    assert!(ledger.purge_expired(UnixTime::from_secs(1_029)).is_empty());
    let expired = ledger.purge_expired(UnixTime::from_secs(1_030));
    assert_eq!(expired.len(), 1);
    assert_eq!(expired[0].reason, ExpiryReason::TunnelNotEstablished);
    assert_eq!(
        ledger.available(UnixTime::from_secs(1_031)).bandwidth,
        bandwidth(100)
    );
}

#[test]
fn established_tunnel_survives_setup_deadline_but_not_hard_expiry() {
    let mut ledger = CapacityLedger::new(limits(2)).expect("ledger");
    let request = request("one", 40, 1_100);
    let id = request.reservation_id.clone();
    ledger
        .reserve(request, UnixTime::from_secs(1_010))
        .expect("reserve");
    ledger
        .mark_tunnel_established(&id, UnixTime::from_secs(1_020))
        .expect("activate");
    assert_eq!(
        ledger.grant(&id).expect("grant").state,
        AllocationState::Active
    );
    assert!(ledger.purge_expired(UnixTime::from_secs(1_050)).is_empty());
    assert_eq!(
        ledger.purge_expired(UnixTime::from_secs(1_100))[0].reason,
        ExpiryReason::ReservationExpired
    );
}

#[test]
fn duplicate_ids_and_slot_exhaustion_fail_closed() {
    let mut ledger = CapacityLedger::new(limits(1)).expect("ledger");
    let first = request("one", 20, 1_200);
    ledger
        .reserve(first.clone(), UnixTime::from_secs(1_010))
        .expect("reserve");
    assert_eq!(
        ledger.reserve(first, UnixTime::from_secs(1_011)),
        Err(ReservationError::DuplicateReservation)
    );
    assert_eq!(
        ledger.reserve(request("two", 20, 1_200), UnixTime::from_secs(1_012)),
        Err(ReservationError::NoFreeSlot)
    );
}

#[test]
fn relay_reservation_is_exactly_one_path() {
    let relay_limits = LedgerLimits {
        service_node_id: NodeId::new("relay-a").expect("valid"),
        role: ServiceRole::Relay,
        bandwidth: bandwidth(100),
        maximum_sessions: 2,
        maximum_reservation_ttl_seconds: 300,
        tunnel_setup_timeout_seconds: 20,
    };
    let mut ledger = CapacityLedger::new(relay_limits).expect("ledger");
    let mut relay_request = request("relay", 20, 1_200);
    relay_request.service_node_id = NodeId::new("relay-a").expect("valid");
    relay_request.role = ServiceRole::Relay;
    assert_eq!(
        ledger.reserve(relay_request.clone(), UnixTime::from_secs(1_010)),
        Err(ReservationError::InvalidMaximumPaths)
    );
    relay_request.maximum_paths = 1;
    ledger
        .reserve(relay_request, UnixTime::from_secs(1_010))
        .expect("single relay path");
}
