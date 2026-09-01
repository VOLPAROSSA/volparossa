//! Connection-scoped transport observations for A1c owners.

use std::{
    collections::HashMap,
    num::NonZeroU64,
    sync::Arc,
    task::{Context, Poll},
};

use libp2p::{
    Multiaddr, PeerId,
    core::{ConnectedPoint, Endpoint, transport::PortUse},
    multiaddr::Protocol,
    swarm::{
        ConnectionDenied, ConnectionId, FromSwarm, NetworkBehaviour, THandler, THandlerInEvent,
        THandlerOutEvent, ToSwarm, dummy,
    },
};
use volparossa_core::{IpFamily, ObservedNetworkPrefix};
use volparossa_protocol::{ObservationAddressFamily, ObservationNetworkPrefix};

use crate::{MAX_ESTABLISHED_CONNECTIONS, MAX_ESTABLISHED_CONNECTIONS_PER_PEER};

/// Impossible output of the passive connection-provenance behaviour.
pub enum ConnectionProvenanceEvent {}

enum NativePrefixBytes {
    Ipv4([u8; 3]),
    Ipv6([u8; 6]),
}

struct NativeNetworkPrefix {
    normalized: ObservedNetworkPrefix,
    bytes: NativePrefixBytes,
}

impl NativeNetworkPrefix {
    fn ipv4(bytes: [u8; 3]) -> Self {
        Self {
            normalized: ObservedNetworkPrefix::ipv4_24(bytes),
            bytes: NativePrefixBytes::Ipv4(bytes),
        }
    }

    fn ipv6(bytes: [u8; 6]) -> Self {
        Self {
            normalized: ObservedNetworkPrefix::ipv6_48(bytes),
            bytes: NativePrefixBytes::Ipv6(bytes),
        }
    }

    fn is_consistent(&self) -> bool {
        match &self.bytes {
            NativePrefixBytes::Ipv4(bytes) => {
                self.normalized == ObservedNetworkPrefix::ipv4_24(*bytes)
            }
            NativePrefixBytes::Ipv6(bytes) => {
                self.normalized == ObservedNetworkPrefix::ipv6_48(*bytes)
            }
        }
    }

    fn same_as(&self, other: &Self) -> bool {
        self.normalized == other.normalized
            && match (&self.bytes, &other.bytes) {
                (NativePrefixBytes::Ipv4(left), NativePrefixBytes::Ipv4(right)) => left == right,
                (NativePrefixBytes::Ipv6(left), NativePrefixBytes::Ipv6(right)) => left == right,
                (NativePrefixBytes::Ipv4(_), NativePrefixBytes::Ipv6(_))
                | (NativePrefixBytes::Ipv6(_), NativePrefixBytes::Ipv4(_)) => false,
            }
    }

    fn for_witness(&self) -> Self {
        match &self.bytes {
            NativePrefixBytes::Ipv4(bytes) => Self::ipv4(*bytes),
            NativePrefixBytes::Ipv6(bytes) => Self::ipv6(*bytes),
        }
    }
}

fn same_optional_prefix(
    left: Option<&NativeNetworkPrefix>,
    right: Option<&NativeNetworkPrefix>,
) -> bool {
    match (left, right) {
        (Some(left), Some(right)) => left.same_as(right),
        (None, None) => true,
        (Some(_), None) | (None, Some(_)) => false,
    }
}

struct ConnectionRecord {
    peer_id: PeerId,
    generation: NonZeroU64,
    prefix: Option<NativeNetworkPrefix>,
}

/// Affine proof that exactly one connection to one peer had the requested native family.
#[must_use = "a connection witness must be consumed by its registry"]
pub(super) struct ConnectionWitness {
    peer_id: PeerId,
    connection_id: ConnectionId,
    generation: NonZeroU64,
    prefix: NativeNetworkPrefix,
}

/// Affine observation rebound to the still-current registry generation.
#[must_use = "a bound connection observation must stay in its owning A1c transaction"]
#[allow(
    dead_code,
    reason = "fields remain sealed inside the opaque bound A1c3 transport proof"
)]
pub(super) struct BoundConnectionObservation {
    peer_id: PeerId,
    connection_id: ConnectionId,
    generation: NonZeroU64,
    prefix: NativeNetworkPrefix,
}

/// Affine proof that one native Exit-permit request arrived over an exact authenticated
/// control-Relay connection.
///
/// Multiple connections and relayed control-plane connectivity remain valid: this is connection
/// provenance, not native datapath or public-prefix evidence. The value exposes no peer,
/// address, prefix, generation, or connection identifier. It can be consumed only by
/// [`crate::DiscoveryService`] while sending the corresponding native Permit response. Creating
/// it neither verifies a signed request nor mutates Exit replay state.
#[must_use = "a bound native-probe control connection must gate one response or be dropped"]
pub struct BoundNativeProbeControlConnection {
    instance: Arc<ConnectionProvenanceInstance>,
    peer_id: PeerId,
    connection_id: ConnectionId,
    generation: NonZeroU64,
}

/// Affine proof that one native authorization chain arrived over an exact authenticated
/// data-Relay connection.
///
/// This token is deliberately distinct from [`BoundNativeProbeControlConnection`]: a control
/// Relay may request an endpoint-free Permit, while only the selected data Relay may request the
/// standard endpoint-bearing reservation authorization. It can be consumed only while sending
/// the corresponding response through the originating discovery service.
#[must_use = "a bound native-probe data-Relay connection must gate one response or be dropped"]
pub struct BoundNativeProbeDataRelayConnection {
    instance: Arc<ConnectionProvenanceInstance>,
    peer_id: PeerId,
    connection_id: ConnectionId,
    generation: NonZeroU64,
}

struct ConnectionProvenanceInstance;

impl BoundConnectionObservation {
    /// Consume one exact client connection proof into its freshness-safe public prefix.
    ///
    /// The expected family comes from the caller-owned canonical preselection request. This
    /// terminal projection drops peer, connection and generation authority and emits only the
    /// normalized public /24 or /48 needed by the later private freshness owner.
    pub(super) fn consume_into_client_preselection_prefix(
        self,
        expected_family: IpFamily,
    ) -> Option<ObservedNetworkPrefix> {
        let Self {
            peer_id: _,
            connection_id: _,
            generation: _,
            prefix,
        } = self;
        if !prefix.is_consistent()
            || !prefix.normalized.is_public_routable()
            || prefix.normalized.family() != expected_family
        {
            return None;
        }
        Some(prefix.normalized)
    }

    /// Consume one exact upstream connection proof into only the prefix a control Relay may sign.
    ///
    /// This is deliberately not a generic prefix accessor: it consumes the complete affine proof,
    /// emits only the endpoint-free protocol /24 or /48, and is used solely by the forwarded
    /// preselection attestation owner.
    pub(super) fn consume_into_forwarded_preselection_prefix(
        self,
    ) -> Option<ObservationNetworkPrefix> {
        let Self {
            peer_id: _,
            connection_id: _,
            generation: _,
            prefix,
        } = self;
        if !prefix.is_consistent() || !prefix.normalized.is_public_routable() {
            return None;
        }
        match prefix.bytes {
            NativePrefixBytes::Ipv4(bytes) => Some(ObservationNetworkPrefix {
                address_family: ObservationAddressFamily::Ipv4 as i32,
                network_prefix: bytes.to_vec(),
            }),
            NativePrefixBytes::Ipv6(bytes) => Some(ObservationNetworkPrefix {
                address_family: ObservationAddressFamily::Ipv6 as i32,
                network_prefix: bytes.to_vec(),
            }),
        }
    }
}

struct ConnectionRegistry {
    records: HashMap<ConnectionId, ConnectionRecord>,
    max_total: usize,
    max_per_peer: usize,
    poisoned: bool,
}

impl ConnectionRegistry {
    fn with_limits(max_total: usize, max_per_peer: usize) -> Self {
        Self {
            records: HashMap::with_capacity(max_total),
            max_total,
            max_per_peer,
            poisoned: false,
        }
    }

    fn poison(&mut self) {
        self.records.clear();
        self.poisoned = true;
    }

    fn established(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        endpoint: &ConnectedPoint,
        other_established: usize,
    ) {
        if self.poisoned {
            return;
        }

        let peer_connections = self
            .records
            .values()
            .filter(|record| record.peer_id == peer_id)
            .count();
        if self.records.contains_key(&connection_id)
            || other_established != peer_connections
            || self.records.len() >= self.max_total
            || peer_connections >= self.max_per_peer
        {
            self.poison();
            return;
        }

        let prefix = direct_public_prefix(peer_id, endpoint);
        if self
            .records
            .insert(
                connection_id,
                ConnectionRecord {
                    peer_id,
                    // libp2p Swarm guarantees ConnectionIds are unique and never reused. The
                    // generation therefore advances only inside this connection's own lineage.
                    generation: NonZeroU64::MIN,
                    prefix,
                },
            )
            .is_some()
        {
            self.poison();
        }
    }

    fn address_changed(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        old: &ConnectedPoint,
        new: &ConnectedPoint,
    ) {
        if self.poisoned {
            return;
        }
        let Some(record) = self.records.get_mut(&connection_id) else {
            self.poison();
            return;
        };
        if record.peer_id != peer_id {
            self.poison();
            return;
        }

        // Increment before parsing either address so every accepted swarm address-change event
        // invalidates all earlier witnesses, including a same-prefix change.
        let Some(generation) = record
            .generation
            .get()
            .checked_add(1)
            .and_then(NonZeroU64::new)
        else {
            self.poison();
            return;
        };
        record.generation = generation;
        let old_prefix = direct_public_prefix(peer_id, old);
        let new_prefix = direct_public_prefix(peer_id, new);
        if !same_optional_prefix(record.prefix.as_ref(), old_prefix.as_ref()) {
            self.poison();
            return;
        }
        record.prefix = new_prefix;
    }

    fn closed(
        &mut self,
        peer_id: PeerId,
        connection_id: ConnectionId,
        endpoint: &ConnectedPoint,
        remaining_established: usize,
    ) {
        if self.poisoned {
            return;
        }
        let Some(record) = self.records.get(&connection_id) else {
            self.poison();
            return;
        };
        let peer_connections = self
            .records
            .values()
            .filter(|record| record.peer_id == peer_id)
            .count();
        let closed_prefix = direct_public_prefix(peer_id, endpoint);
        if record.peer_id != peer_id
            || !same_optional_prefix(record.prefix.as_ref(), closed_prefix.as_ref())
            || peer_connections.checked_sub(1) != Some(remaining_established)
        {
            self.poison();
            return;
        }
        if self.records.remove(&connection_id).is_none() {
            self.poison();
        }
    }

    fn unique_witness(&self, peer_id: PeerId, family: IpFamily) -> Option<ConnectionWitness> {
        if self.poisoned {
            return None;
        }
        let mut records = self
            .records
            .iter()
            .filter(|(_, record)| record.peer_id == peer_id);
        let (connection_id, record) = records.next()?;
        if records.next().is_some() {
            return None;
        }
        let prefix = record.prefix.as_ref()?;
        if prefix.normalized.family() != family || !prefix.is_consistent() {
            return None;
        }
        Some(ConnectionWitness {
            peer_id,
            connection_id: *connection_id,
            generation: record.generation,
            prefix: prefix.for_witness(),
        })
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "the affine witness must be consumed exactly once at the binding boundary"
    )]
    fn bind(
        &self,
        witness: ConnectionWitness,
        expected_peer_id: PeerId,
        expected_connection_id: ConnectionId,
    ) -> Option<BoundConnectionObservation> {
        let ConnectionWitness {
            peer_id: witness_peer_id,
            connection_id: witness_connection_id,
            generation: witness_generation,
            prefix: witness_prefix,
        } = witness;
        let peer_connections = self
            .records
            .values()
            .filter(|record| record.peer_id == expected_peer_id)
            .count();
        if self.poisoned
            || peer_connections != 1
            || witness_peer_id != expected_peer_id
            || witness_connection_id != expected_connection_id
        {
            return None;
        }
        let record = self.records.get(&expected_connection_id)?;
        let record_prefix = record.prefix.as_ref()?;
        if record.peer_id != expected_peer_id
            || record.generation != witness_generation
            || !record_prefix.same_as(&witness_prefix)
            || !witness_prefix.is_consistent()
            || !record_prefix.is_consistent()
        {
            return None;
        }
        Some(BoundConnectionObservation {
            peer_id: expected_peer_id,
            connection_id: expected_connection_id,
            generation: witness_generation,
            prefix: witness_prefix,
        })
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "ownership is the affine one-response authority; borrowing would permit reuse"
    )]
    fn consume_bound_native_probe_control(
        &self,
        bound: BoundNativeProbeControlConnection,
        expected_peer_id: PeerId,
    ) -> bool {
        let BoundNativeProbeControlConnection {
            instance: _,
            peer_id,
            connection_id,
            generation,
        } = bound;
        if self.poisoned || peer_id != expected_peer_id {
            return false;
        }
        self.records.get(&connection_id).is_some_and(|record| {
            record.peer_id == expected_peer_id && record.generation == generation
        })
    }

    #[allow(
        clippy::needless_pass_by_value,
        reason = "ownership is the affine one-response authority; borrowing would permit reuse"
    )]
    fn consume_bound_native_probe_data_relay(
        &self,
        bound: BoundNativeProbeDataRelayConnection,
        expected_peer_id: PeerId,
    ) -> bool {
        let BoundNativeProbeDataRelayConnection {
            instance: _,
            peer_id,
            connection_id,
            generation,
        } = bound;
        if self.poisoned || peer_id != expected_peer_id {
            return false;
        }
        self.records.get(&connection_id).is_some_and(|record| {
            record.peer_id == expected_peer_id && record.generation == generation
        })
    }
}

impl Default for ConnectionRegistry {
    fn default() -> Self {
        Self::with_limits(
            usize::try_from(MAX_ESTABLISHED_CONNECTIONS)
                .expect("the connection ceiling fits usize"),
            usize::try_from(MAX_ESTABLISHED_CONNECTIONS_PER_PEER)
                .expect("the per-peer connection ceiling fits usize"),
        )
    }
}

/// Passive private behaviour that owns the complete connection lineage registry.
// This item and its empty event must be syntactically public for the generated handler associated
// type of public DiscoveryBehaviour. Their containing module is private and neither is re-exported.
pub struct ConnectionProvenanceBehaviour {
    instance: Arc<ConnectionProvenanceInstance>,
    registry: ConnectionRegistry,
}

impl ConnectionProvenanceBehaviour {
    pub(super) fn new() -> Self {
        Self {
            instance: Arc::new(ConnectionProvenanceInstance),
            registry: ConnectionRegistry::default(),
        }
    }

    pub(super) fn unique_witness(
        &self,
        peer_id: PeerId,
        family: IpFamily,
    ) -> Option<ConnectionWitness> {
        self.registry.unique_witness(peer_id, family)
    }

    pub(super) fn bind(
        &self,
        witness: ConnectionWitness,
        expected_peer_id: PeerId,
        expected_connection_id: ConnectionId,
    ) -> Option<BoundConnectionObservation> {
        self.registry
            .bind(witness, expected_peer_id, expected_connection_id)
    }

    pub(super) fn bind_native_probe_control(
        &self,
        peer_id: PeerId,
        connection_id: ConnectionId,
    ) -> Option<BoundNativeProbeControlConnection> {
        if self.registry.poisoned {
            return None;
        }
        let record = self.registry.records.get(&connection_id)?;
        if record.peer_id != peer_id {
            return None;
        }
        Some(BoundNativeProbeControlConnection {
            instance: Arc::clone(&self.instance),
            peer_id,
            connection_id,
            generation: record.generation,
        })
    }

    pub(super) fn consume_bound_native_probe_control(
        &self,
        bound: BoundNativeProbeControlConnection,
        expected_peer_id: PeerId,
    ) -> bool {
        if !Arc::ptr_eq(&bound.instance, &self.instance) {
            return false;
        }
        self.registry
            .consume_bound_native_probe_control(bound, expected_peer_id)
    }

    pub(super) fn bind_native_probe_data_relay(
        &self,
        peer_id: PeerId,
        connection_id: ConnectionId,
    ) -> Option<BoundNativeProbeDataRelayConnection> {
        if self.registry.poisoned {
            return None;
        }
        let record = self.registry.records.get(&connection_id)?;
        if record.peer_id != peer_id {
            return None;
        }
        Some(BoundNativeProbeDataRelayConnection {
            instance: Arc::clone(&self.instance),
            peer_id,
            connection_id,
            generation: record.generation,
        })
    }

    pub(super) fn consume_bound_native_probe_data_relay(
        &self,
        bound: BoundNativeProbeDataRelayConnection,
        expected_peer_id: PeerId,
    ) -> bool {
        if !Arc::ptr_eq(&bound.instance, &self.instance) {
            return false;
        }
        self.registry
            .consume_bound_native_probe_data_relay(bound, expected_peer_id)
    }
}

impl NetworkBehaviour for ConnectionProvenanceBehaviour {
    type ConnectionHandler = dummy::ConnectionHandler;
    type ToSwarm = ConnectionProvenanceEvent;

    fn handle_established_inbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _local_addr: &Multiaddr,
        _remote_addr: &Multiaddr,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn handle_established_outbound_connection(
        &mut self,
        _connection_id: ConnectionId,
        _peer: PeerId,
        _addr: &Multiaddr,
        _role_override: Endpoint,
        _port_use: PortUse,
    ) -> Result<THandler<Self>, ConnectionDenied> {
        Ok(dummy::ConnectionHandler)
    }

    fn on_swarm_event(&mut self, event: FromSwarm<'_>) {
        match event {
            FromSwarm::ConnectionEstablished(event) => self.registry.established(
                event.peer_id,
                event.connection_id,
                event.endpoint,
                event.other_established,
            ),
            FromSwarm::AddressChange(event) => self.registry.address_changed(
                event.peer_id,
                event.connection_id,
                event.old,
                event.new,
            ),
            FromSwarm::ConnectionClosed(event) => self.registry.closed(
                event.peer_id,
                event.connection_id,
                event.endpoint,
                event.remaining_established,
            ),
            _ => {}
        }
    }

    fn on_connection_handler_event(
        &mut self,
        _peer_id: PeerId,
        _connection_id: ConnectionId,
        event: THandlerOutEvent<Self>,
    ) {
        match event {}
    }

    fn poll(
        &mut self,
        _cx: &mut Context<'_>,
    ) -> Poll<ToSwarm<Self::ToSwarm, THandlerInEvent<Self>>> {
        Poll::Pending
    }
}

fn direct_public_prefix(
    expected_peer_id: PeerId,
    endpoint: &ConnectedPoint,
) -> Option<NativeNetworkPrefix> {
    if endpoint.is_relayed() {
        return None;
    }
    direct_public_multiaddr_prefix(expected_peer_id, endpoint.get_remote_address())
}

fn direct_public_multiaddr_prefix(
    expected_peer_id: PeerId,
    address: &Multiaddr,
) -> Option<NativeNetworkPrefix> {
    let mut protocols = address.iter();
    let prefix = match protocols.next()? {
        Protocol::Ip4(address) => {
            let [first, second, third, _] = address.octets();
            let bytes = [first, second, third];
            NativeNetworkPrefix::ipv4(bytes)
        }
        Protocol::Ip6(address) => {
            let octets = address.octets();
            let bytes = [
                octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
            ];
            NativeNetworkPrefix::ipv6(bytes)
        }
        _ => return None,
    };
    if !prefix.normalized.is_public_routable() || !prefix.is_consistent() {
        return None;
    }

    match protocols.next()? {
        Protocol::Tcp(port) if port != 0 => {}
        Protocol::Udp(port) if port != 0 => {
            if !matches!(protocols.next(), Some(Protocol::QuicV1)) {
                return None;
            }
        }
        _ => return None,
    }

    match protocols.next() {
        None => Some(prefix),
        Some(Protocol::P2p(peer_id))
            if peer_id == expected_peer_id && protocols.next().is_none() =>
        {
            Some(prefix)
        }
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libp2p::swarm::{AddressChange, ConnectionClosed, behaviour::ConnectionEstablished};

    fn address(value: &str) -> Multiaddr {
        value.parse().expect("test multiaddr")
    }

    fn dialer(value: &str) -> ConnectedPoint {
        ConnectedPoint::Dialer {
            address: address(value),
            role_override: Endpoint::Dialer,
            port_use: PortUse::New,
        }
    }

    fn listener(local: &str, remote: &str) -> ConnectedPoint {
        ConnectedPoint::Listener {
            local_addr: address(local),
            send_back_addr: address(remote),
        }
    }

    fn established(
        behaviour: &mut ConnectionProvenanceBehaviour,
        peer_id: PeerId,
        connection_id: usize,
        endpoint: &ConnectedPoint,
        other_established: usize,
    ) {
        behaviour.on_swarm_event(FromSwarm::ConnectionEstablished(ConnectionEstablished {
            peer_id,
            connection_id: ConnectionId::new_unchecked(connection_id),
            endpoint,
            failed_addresses: &[],
            other_established,
        }));
    }

    fn source_item_body<'a>(source: &'a str, declaration: &str) -> &'a str {
        assert_eq!(source.matches(declaration).count(), 1, "{declaration}");
        source
            .split(declaration)
            .nth(1)
            .expect("item declaration")
            .split('}')
            .next()
            .expect("item body")
    }

    fn compact_source(value: &str) -> String {
        value.split_whitespace().collect()
    }

    fn change(
        behaviour: &mut ConnectionProvenanceBehaviour,
        peer_id: PeerId,
        connection_id: usize,
        old: &ConnectedPoint,
        new: &ConnectedPoint,
    ) {
        behaviour.on_swarm_event(FromSwarm::AddressChange(AddressChange {
            peer_id,
            connection_id: ConnectionId::new_unchecked(connection_id),
            old,
            new,
        }));
    }

    fn closed(
        behaviour: &mut ConnectionProvenanceBehaviour,
        peer_id: PeerId,
        connection_id: usize,
        endpoint: &ConnectedPoint,
        remaining_established: usize,
    ) {
        behaviour.on_swarm_event(FromSwarm::ConnectionClosed(ConnectionClosed {
            peer_id,
            connection_id: ConnectionId::new_unchecked(connection_id),
            endpoint,
            cause: None,
            remaining_established,
        }));
    }

    #[test]
    fn exact_direct_public_tcp_and_quic_v1_shapes_are_accepted() {
        let peer = PeerId::random();
        let peer_suffix = format!("/p2p/{peer}");
        let cases = [
            "/ip4/1.1.1.8/tcp/443".to_owned(),
            format!("/ip4/1.1.1.8/tcp/443{peer_suffix}"),
            "/ip6/2606:4700:4700::1111/tcp/443".to_owned(),
            format!("/ip6/2606:4700:4700::1111/tcp/443{peer_suffix}"),
            "/ip4/9.9.9.9/udp/443/quic-v1".to_owned(),
            format!("/ip4/9.9.9.9/udp/443/quic-v1{peer_suffix}"),
            "/ip6/2606:4700:4700::1111/udp/443/quic-v1".to_owned(),
            format!("/ip6/2606:4700:4700::1111/udp/443/quic-v1{peer_suffix}"),
        ];
        for value in cases {
            assert!(
                direct_public_multiaddr_prefix(peer, &address(&value)).is_some(),
                "expected accepted address {value}"
            );
        }
    }

    #[test]
    fn indirect_special_zero_or_extra_multiaddrs_are_rejected() {
        let peer = PeerId::random();
        let other = PeerId::random();
        let cases = [
            "/dns4/example.com/tcp/443".to_owned(),
            "/dns/example.com/tcp/443".to_owned(),
            "/dns6/example.com/tcp/443".to_owned(),
            "/memory/7".to_owned(),
            "/ip4/10.0.0.1/tcp/443".to_owned(),
            "/ip4/192.0.2.1/tcp/443".to_owned(),
            "/ip6/2001:db8::1/tcp/443".to_owned(),
            "/ip4/1.1.1.1/tcp/0".to_owned(),
            "/ip4/1.1.1.1/udp/0/quic-v1".to_owned(),
            "/ip4/1.1.1.1/udp/443".to_owned(),
            "/ip4/1.1.1.1/udp/443/quic".to_owned(),
            "/ip4/1.1.1.1/tcp/443/ws".to_owned(),
            format!("/ip4/1.1.1.1/tcp/443/p2p/{other}"),
            format!("/ip4/1.1.1.1/tcp/443/p2p/{peer}/tls"),
            format!("/ip4/1.1.1.1/tcp/443/p2p/{peer}/p2p-circuit"),
            format!("/ip4/1.1.1.1/tcp/443/p2p-circuit/p2p/{peer}"),
        ];
        for value in cases {
            assert!(
                direct_public_multiaddr_prefix(peer, &address(&value)).is_none(),
                "expected rejected address {value}"
            );
        }
        let relayed = listener(
            &format!("/ip4/8.8.8.8/tcp/443/p2p/{other}/p2p-circuit"),
            "/ip4/1.1.1.1/tcp/443",
        );
        assert!(direct_public_multiaddr_prefix(peer, relayed.get_remote_address()).is_some());
        assert!(direct_public_prefix(peer, &relayed).is_none());
    }

    #[test]
    fn one_total_connection_for_peer_mints_family_native_affine_binding() {
        let peer = PeerId::random();
        let another_peer = PeerId::random();
        let endpoint = dialer("/ip4/1.1.1.8/tcp/443");
        let another_endpoint = dialer("/ip6/2606:4700:4700::1111/udp/443/quic-v1");
        let mut behaviour = ConnectionProvenanceBehaviour::new();
        established(&mut behaviour, peer, 1, &endpoint, 0);
        established(&mut behaviour, another_peer, 2, &another_endpoint, 0);

        assert!(behaviour.unique_witness(peer, IpFamily::Ipv6).is_none());
        let witness = behaviour
            .unique_witness(peer, IpFamily::Ipv4)
            .expect("unique native-family connection");
        let bound = behaviour
            .bind(witness, peer, ConnectionId::new_unchecked(1))
            .expect("current exact binding");
        assert_eq!(bound.peer_id, peer);
        assert_eq!(bound.connection_id, ConnectionId::new_unchecked(1));
        assert_eq!(bound.generation.get(), 1);
        assert!(bound.prefix.normalized == ObservedNetworkPrefix::ipv4_24([1, 1, 1]));
        assert!(matches!(
            bound.prefix.bytes,
            NativePrefixBytes::Ipv4([1, 1, 1])
        ));
    }

    #[test]
    fn native_permit_control_binding_is_exact_but_allows_multiple_and_relayed_connections() {
        let peer = PeerId::random();
        let relay = PeerId::random();
        let first = dialer("/ip4/1.1.1.8/tcp/443");
        let second = listener(
            &format!("/ip4/8.8.8.8/tcp/443/p2p/{relay}/p2p-circuit"),
            "/memory/17",
        );
        let mut behaviour = ConnectionProvenanceBehaviour::new();
        established(&mut behaviour, peer, 1, &first, 0);
        established(&mut behaviour, peer, 2, &second, 1);

        let first_bound = behaviour
            .bind_native_probe_control(peer, ConnectionId::new_unchecked(1))
            .expect("first exact authenticated connection");
        assert!(behaviour.consume_bound_native_probe_control(first_bound, peer));

        let relayed_bound = behaviour
            .bind_native_probe_control(peer, ConnectionId::new_unchecked(2))
            .expect("relayed control connection remains valid provenance");
        assert!(behaviour.consume_bound_native_probe_control(relayed_bound, peer));

        let cross_service = behaviour
            .bind_native_probe_control(peer, ConnectionId::new_unchecked(1))
            .expect("originating service binding");
        let mut other_service = ConnectionProvenanceBehaviour::new();
        established(&mut other_service, peer, 1, &first, 0);
        assert!(!other_service.consume_bound_native_probe_control(cross_service, peer));

        let stale = behaviour
            .bind_native_probe_control(peer, ConnectionId::new_unchecked(1))
            .expect("pre-change binding");
        let changed = dialer("/ip4/1.1.1.9/tcp/443");
        change(&mut behaviour, peer, 1, &first, &changed);
        assert!(!behaviour.consume_bound_native_probe_control(stale, peer));

        let foreign = behaviour
            .bind_native_probe_control(peer, ConnectionId::new_unchecked(1))
            .expect("post-change binding");
        assert!(!behaviour.consume_bound_native_probe_control(foreign, PeerId::random()));

        let closed_bound = behaviour
            .bind_native_probe_control(peer, ConnectionId::new_unchecked(1))
            .expect("pre-close binding");
        closed(&mut behaviour, peer, 1, &changed, 1);
        assert!(!behaviour.consume_bound_native_probe_control(closed_bound, peer));
    }

    #[test]
    fn native_authorization_data_relay_binding_is_affine_and_service_local() {
        let peer = PeerId::random();
        let endpoint = dialer("/ip4/1.1.1.8/tcp/443");
        let mut behaviour = ConnectionProvenanceBehaviour::new();
        established(&mut behaviour, peer, 1, &endpoint, 0);

        let bound = behaviour
            .bind_native_probe_data_relay(peer, ConnectionId::new_unchecked(1))
            .expect("exact authenticated data Relay");
        assert!(behaviour.consume_bound_native_probe_data_relay(bound, peer));

        let cross_service = behaviour
            .bind_native_probe_data_relay(peer, ConnectionId::new_unchecked(1))
            .expect("originating service binding");
        let mut other_service = ConnectionProvenanceBehaviour::new();
        established(&mut other_service, peer, 1, &endpoint, 0);
        assert!(!other_service.consume_bound_native_probe_data_relay(cross_service, peer));

        let stale = behaviour
            .bind_native_probe_data_relay(peer, ConnectionId::new_unchecked(1))
            .expect("pre-change binding");
        let changed = dialer("/ip4/1.1.1.9/tcp/443");
        change(&mut behaviour, peer, 1, &endpoint, &changed);
        assert!(!behaviour.consume_bound_native_probe_data_relay(stale, peer));
    }

    #[test]
    fn purpose_specific_forwarded_projection_consumes_exact_native_ipv4_and_ipv6_prefixes() {
        for (endpoint, family, expected_family, expected_prefix) in [
            (
                dialer("/ip4/8.8.8.8/tcp/443"),
                IpFamily::Ipv4,
                ObservationAddressFamily::Ipv4,
                vec![8, 8, 8],
            ),
            (
                dialer("/ip6/2606:4700:4700::1111/udp/443/quic-v1"),
                IpFamily::Ipv6,
                ObservationAddressFamily::Ipv6,
                vec![0x26, 0x06, 0x47, 0x00, 0x47, 0x00],
            ),
        ] {
            let peer = PeerId::random();
            let mut behaviour = ConnectionProvenanceBehaviour::new();
            established(&mut behaviour, peer, 1, &endpoint, 0);
            let witness = behaviour
                .unique_witness(peer, family)
                .expect("unique native witness");
            let bound = behaviour
                .bind(witness, peer, ConnectionId::new_unchecked(1))
                .expect("exact affine observation");
            let projected = bound
                .consume_into_forwarded_preselection_prefix()
                .expect("public purpose-specific projection");
            assert_eq!(projected.address_family, expected_family as i32);
            assert_eq!(projected.network_prefix, expected_prefix);
        }
    }

    #[test]
    fn purpose_specific_client_projection_consumes_only_matching_normalized_prefixes() {
        for (endpoint, family, expected_prefix) in [
            (
                dialer("/ip4/8.8.8.8/tcp/443"),
                IpFamily::Ipv4,
                ObservedNetworkPrefix::ipv4_24([8, 8, 8]),
            ),
            (
                dialer("/ip6/2606:4700:4700::1111/udp/443/quic-v1"),
                IpFamily::Ipv6,
                ObservedNetworkPrefix::ipv6_48([0x26, 0x06, 0x47, 0x00, 0x47, 0x00]),
            ),
        ] {
            let peer = PeerId::random();
            let mut behaviour = ConnectionProvenanceBehaviour::new();
            established(&mut behaviour, peer, 1, &endpoint, 0);
            let witness = behaviour
                .unique_witness(peer, family)
                .expect("unique native witness");
            let bound = behaviour
                .bind(witness, peer, ConnectionId::new_unchecked(1))
                .expect("exact affine observation");
            let projected = bound
                .consume_into_client_preselection_prefix(family)
                .expect("matching public normalized prefix");
            assert!(projected == expected_prefix);

            let witness = behaviour
                .unique_witness(peer, family)
                .expect("replacement unique native witness");
            let bound = behaviour
                .bind(witness, peer, ConnectionId::new_unchecked(1))
                .expect("replacement exact affine observation");
            let wrong_family = match family {
                IpFamily::Ipv4 => IpFamily::Ipv6,
                IpFamily::Ipv6 => IpFamily::Ipv4,
            };
            assert!(
                bound
                    .consume_into_client_preselection_prefix(wrong_family)
                    .is_none(),
                "the caller cannot relabel a native prefix"
            );
        }
    }

    #[test]
    fn invalid_sibling_still_blocks_unique_witness() {
        let peer = PeerId::random();
        let public = dialer("/ip4/1.1.1.8/tcp/443");
        let invalid = dialer("/ip4/10.0.0.8/tcp/443");
        let mut behaviour = ConnectionProvenanceBehaviour::new();
        established(&mut behaviour, peer, 1, &public, 0);
        established(&mut behaviour, peer, 2, &invalid, 1);
        assert!(behaviour.unique_witness(peer, IpFamily::Ipv4).is_none());
        closed(&mut behaviour, peer, 2, &invalid, 1);
        assert!(behaviour.unique_witness(peer, IpFamily::Ipv4).is_some());
    }

    #[test]
    fn bind_rechecks_every_exact_component() {
        let peer = PeerId::random();
        let other = PeerId::random();
        let endpoint = dialer("/ip4/1.1.1.8/tcp/443");

        for mismatch in 0..2 {
            let mut behaviour = ConnectionProvenanceBehaviour::new();
            established(&mut behaviour, peer, 1, &endpoint, 0);
            let witness = behaviour
                .unique_witness(peer, IpFamily::Ipv4)
                .expect("witness");
            let result = match mismatch {
                0 => behaviour.bind(witness, other, ConnectionId::new_unchecked(1)),
                _ => behaviour.bind(witness, peer, ConnectionId::new_unchecked(2)),
            };
            assert!(result.is_none());
        }
    }

    #[test]
    fn bind_rechecks_current_native_prefix_and_total_connection_count() {
        let peer = PeerId::random();
        let public = dialer("/ip4/1.1.1.8/tcp/443");
        let invalid = dialer("/ip4/10.0.0.8/tcp/443");

        let mut changed_prefix = ConnectionProvenanceBehaviour::new();
        established(&mut changed_prefix, peer, 1, &public, 0);
        let stale_prefix = changed_prefix
            .unique_witness(peer, IpFamily::Ipv4)
            .expect("witness");
        changed_prefix
            .registry
            .records
            .get_mut(&ConnectionId::new_unchecked(1))
            .expect("record")
            .prefix = direct_public_prefix(peer, &dialer("/ip4/8.8.8.8/tcp/443"));
        assert!(
            changed_prefix
                .bind(stale_prefix, peer, ConnectionId::new_unchecked(1))
                .is_none()
        );

        let mut added_sibling = ConnectionProvenanceBehaviour::new();
        established(&mut added_sibling, peer, 1, &public, 0);
        let stale_unique = added_sibling
            .unique_witness(peer, IpFamily::Ipv4)
            .expect("witness");
        established(&mut added_sibling, peer, 2, &invalid, 1);
        assert!(
            added_sibling
                .bind(stale_unique, peer, ConnectionId::new_unchecked(1))
                .is_none()
        );
    }

    #[test]
    fn every_address_change_invalidates_old_witness_even_with_same_prefix() {
        let peer = PeerId::random();
        let old = dialer("/ip4/1.1.1.8/tcp/443");
        let same_prefix = dialer("/ip4/1.1.1.9/udp/443/quic-v1");
        let mut behaviour = ConnectionProvenanceBehaviour::new();
        established(&mut behaviour, peer, 1, &old, 0);
        let stale = behaviour
            .unique_witness(peer, IpFamily::Ipv4)
            .expect("initial witness");
        change(&mut behaviour, peer, 1, &old, &same_prefix);
        assert!(
            behaviour
                .bind(stale, peer, ConnectionId::new_unchecked(1))
                .is_none()
        );
        let current = behaviour
            .unique_witness(peer, IpFamily::Ipv4)
            .expect("replacement witness");
        let bound = behaviour
            .bind(current, peer, ConnectionId::new_unchecked(1))
            .expect("replacement binding");
        assert_eq!(bound.generation.get(), 2);
    }

    #[test]
    fn address_change_to_other_prefix_family_or_invalid_shape_rebinds_exactly() {
        let peer = PeerId::random();
        let ipv4 = dialer("/ip4/1.1.1.8/tcp/443");
        let other_ipv4 = dialer("/ip4/8.8.8.8/tcp/443");
        let ipv6 = dialer("/ip6/2606:4700:4700::1111/udp/443/quic-v1");
        let invalid = dialer("/dns4/example.com/tcp/443");
        let mut behaviour = ConnectionProvenanceBehaviour::new();

        established(&mut behaviour, peer, 1, &ipv4, 0);
        let old_ipv4 = behaviour
            .unique_witness(peer, IpFamily::Ipv4)
            .expect("initial IPv4 witness");
        change(&mut behaviour, peer, 1, &ipv4, &other_ipv4);
        assert!(
            behaviour
                .bind(old_ipv4, peer, ConnectionId::new_unchecked(1))
                .is_none()
        );
        let other_prefix = behaviour
            .unique_witness(peer, IpFamily::Ipv4)
            .expect("other IPv4 prefix witness");
        let bound = behaviour
            .bind(other_prefix, peer, ConnectionId::new_unchecked(1))
            .expect("other IPv4 prefix binding");
        assert!(matches!(
            bound.prefix.bytes,
            NativePrefixBytes::Ipv4([8, 8, 8])
        ));

        let old_family = behaviour
            .unique_witness(peer, IpFamily::Ipv4)
            .expect("pre-family-change witness");
        change(&mut behaviour, peer, 1, &other_ipv4, &ipv6);
        assert!(
            behaviour
                .bind(old_family, peer, ConnectionId::new_unchecked(1))
                .is_none()
        );
        assert!(behaviour.unique_witness(peer, IpFamily::Ipv4).is_none());
        assert!(behaviour.unique_witness(peer, IpFamily::Ipv6).is_some());

        let old_valid = behaviour
            .unique_witness(peer, IpFamily::Ipv6)
            .expect("pre-invalid-change witness");
        change(&mut behaviour, peer, 1, &ipv6, &invalid);
        assert!(
            behaviour
                .bind(old_valid, peer, ConnectionId::new_unchecked(1))
                .is_none()
        );
        assert!(behaviour.unique_witness(peer, IpFamily::Ipv4).is_none());
        assert!(behaviour.unique_witness(peer, IpFamily::Ipv6).is_none());
    }

    #[test]
    fn close_removes_the_only_record_before_a_witness_can_bind() {
        let peer = PeerId::random();
        let endpoint = dialer("/ip4/1.1.1.8/tcp/443");
        let mut behaviour = ConnectionProvenanceBehaviour::new();
        established(&mut behaviour, peer, 1, &endpoint, 0);
        let stale = behaviour
            .unique_witness(peer, IpFamily::Ipv4)
            .expect("initial witness");
        closed(&mut behaviour, peer, 1, &endpoint, 0);
        assert!(
            behaviour
                .bind(stale, peer, ConnectionId::new_unchecked(1))
                .is_none()
        );
    }

    #[test]
    fn ambiguous_swarm_events_poison_and_clear_permanently() {
        let peer = PeerId::random();
        let endpoint = dialer("/ip4/1.1.1.8/tcp/443");
        let mut behaviour = ConnectionProvenanceBehaviour::new();
        established(&mut behaviour, peer, 1, &endpoint, 0);
        established(&mut behaviour, peer, 1, &endpoint, 1);
        assert!(behaviour.registry.poisoned);
        assert!(behaviour.registry.records.is_empty());

        closed(&mut behaviour, peer, 1, &endpoint, 0);
        established(&mut behaviour, peer, 2, &endpoint, 0);
        assert!(behaviour.registry.poisoned);
        assert!(behaviour.registry.records.is_empty());
        assert!(behaviour.unique_witness(peer, IpFamily::Ipv4).is_none());
    }

    #[test]
    fn inconsistent_counts_old_address_and_unknown_ids_poison() {
        let peer = PeerId::random();
        let endpoint = dialer("/ip4/1.1.1.8/tcp/443");
        let changed = dialer("/ip4/8.8.8.8/tcp/443");

        let mut bad_established_count = ConnectionProvenanceBehaviour::new();
        established(&mut bad_established_count, peer, 1, &endpoint, 1);
        assert!(bad_established_count.registry.poisoned);

        let mut bad_old = ConnectionProvenanceBehaviour::new();
        established(&mut bad_old, peer, 1, &endpoint, 0);
        change(&mut bad_old, peer, 1, &changed, &endpoint);
        assert!(bad_old.registry.poisoned);

        let mut unknown_change = ConnectionProvenanceBehaviour::new();
        change(&mut unknown_change, peer, 1, &endpoint, &changed);
        assert!(unknown_change.registry.poisoned);

        let mut unknown_close = ConnectionProvenanceBehaviour::new();
        closed(&mut unknown_close, peer, 1, &endpoint, 0);
        assert!(unknown_close.registry.poisoned);

        let mut wrong_peer = ConnectionProvenanceBehaviour::new();
        established(&mut wrong_peer, peer, 1, &endpoint, 0);
        change(&mut wrong_peer, PeerId::random(), 1, &endpoint, &changed);
        assert!(wrong_peer.registry.poisoned);

        let mut wrong_close_address = ConnectionProvenanceBehaviour::new();
        established(&mut wrong_close_address, peer, 1, &endpoint, 0);
        closed(&mut wrong_close_address, peer, 1, &changed, 0);
        assert!(wrong_close_address.registry.poisoned);

        let mut wrong_close_count = ConnectionProvenanceBehaviour::new();
        established(&mut wrong_close_count, peer, 1, &endpoint, 0);
        closed(&mut wrong_close_count, peer, 1, &endpoint, 1);
        assert!(wrong_close_count.registry.poisoned);
    }

    #[test]
    fn duplicate_connection_id_across_peers_poison_and_clear() {
        let endpoint = dialer("/ip4/1.1.1.8/tcp/443");
        let mut behaviour = ConnectionProvenanceBehaviour::new();
        established(&mut behaviour, PeerId::random(), 1, &endpoint, 0);
        established(&mut behaviour, PeerId::random(), 1, &endpoint, 0);
        assert!(behaviour.registry.poisoned);
        assert!(behaviour.registry.records.is_empty());
    }

    #[test]
    fn per_peer_and_global_overflow_poison_and_clear() {
        let endpoint = dialer("/ip4/1.1.1.8/tcp/443");
        let peer = PeerId::random();
        let mut per_peer = ConnectionProvenanceBehaviour::new();
        for index in 0..MAX_ESTABLISHED_CONNECTIONS_PER_PEER {
            established(
                &mut per_peer,
                peer,
                usize::try_from(index + 1).expect("connection ID"),
                &endpoint,
                usize::try_from(index).expect("connection count"),
            );
        }
        assert!(!per_peer.registry.poisoned);
        established(&mut per_peer, peer, 5, &endpoint, 4);
        assert!(per_peer.registry.poisoned);
        assert!(per_peer.registry.records.is_empty());

        let mut global = ConnectionProvenanceBehaviour::new();
        for index in 0..MAX_ESTABLISHED_CONNECTIONS {
            established(
                &mut global,
                PeerId::random(),
                usize::try_from(index + 1).expect("connection ID"),
                &endpoint,
                0,
            );
        }
        assert_eq!(global.registry.records.len(), 384);
        assert!(!global.registry.poisoned);
        established(&mut global, PeerId::random(), 385, &endpoint, 0);
        assert!(global.registry.poisoned);
        assert!(global.registry.records.is_empty());
    }

    #[test]
    fn generation_exhaustion_poison_is_permanent() {
        let peer = PeerId::random();
        let endpoint = dialer("/ip4/1.1.1.8/tcp/443");
        let changed = dialer("/ip4/1.1.1.9/tcp/443");
        let mut behaviour = ConnectionProvenanceBehaviour::new();
        established(&mut behaviour, peer, 1, &endpoint, 0);
        behaviour
            .registry
            .records
            .get_mut(&ConnectionId::new_unchecked(1))
            .expect("record")
            .generation = NonZeroU64::new(u64::MAX).expect("maximum is non-zero");
        change(&mut behaviour, peer, 1, &endpoint, &changed);
        assert!(behaviour.registry.poisoned);
        assert!(behaviour.registry.records.is_empty());
        established(&mut behaviour, peer, 2, &endpoint, 0);
        assert!(behaviour.registry.records.is_empty());
    }

    #[test]
    fn production_types_retain_no_full_address_and_expose_no_escape_hatch() {
        let source = include_str!("connection_provenance.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        let native_bytes_declaration = concat!("enum NativePrefix", "Bytes {");
        let native_declaration = concat!("struct NativeNetwork", "Prefix {");
        let record_declaration = concat!("struct Connection", "Record {");
        let witness_declaration = concat!("struct Connection", "Witness {");
        let bound_declaration = concat!("struct BoundConnection", "Observation {");

        assert_eq!(
            compact_source(source_item_body(source, native_bytes_declaration)),
            "Ipv4([u8;3]),Ipv6([u8;6]),"
        );
        assert_eq!(
            compact_source(source_item_body(source, native_declaration)),
            "normalized:ObservedNetworkPrefix,bytes:NativePrefixBytes,"
        );
        assert_eq!(
            compact_source(source_item_body(source, record_declaration)),
            "peer_id:PeerId,generation:NonZeroU64,prefix:Option<NativeNetworkPrefix>,"
        );
        for declaration in [witness_declaration, bound_declaration] {
            assert_eq!(
                compact_source(source_item_body(source, declaration)),
                "peer_id:PeerId,connection_id:ConnectionId,generation:NonZeroU64,prefix:NativeNetworkPrefix,"
            );
        }

        let native_start = source
            .find(native_bytes_declaration)
            .expect("native prefix bytes");
        let native_end = source.find(record_declaration).expect("record declaration");
        let native = &source[native_start..native_end];
        assert!(!native.contains("#[derive"));
        let affine_start = source.find("/// Affine proof").expect("affine proof");
        let affine_end = source
            .find(concat!("struct Connection", "Registry {"))
            .expect("registry declaration");
        let affine = &source[affine_start..affine_end];
        assert!(!affine.contains("#[derive"));

        for name in [
            "NativePrefixBytes",
            "NativeNetworkPrefix",
            "ConnectionWitness",
            "BoundConnectionObservation",
        ] {
            for trait_name in ["Clone", "Copy", "Debug", "Serialize", "Deserialize"] {
                assert!(!source.contains(&format!("impl {trait_name} for {name}")));
            }
        }
        let snapshot_helper = concat!("fn for_", "witness(&self) -> Self");
        assert_eq!(production.matches(snapshot_helper).count(), 1);
        for getter in [
            concat!("fn normalized", "("),
            concat!("fn bytes", "("),
            concat!("fn into_", "prefix("),
            concat!("fn as_", "prefix("),
        ] {
            assert!(!production.contains(getter), "forbidden getter {getter}");
        }
        assert!(!production.contains("into_observed_prefix"));
    }

    #[test]
    fn production_registry_has_exact_bounds_and_no_authority_escape() {
        let source = include_str!("connection_provenance.rs");
        let production = source
            .split("#[cfg(test)]")
            .next()
            .expect("production source");
        for forbidden in [
            concat!("send_", "request"),
            concat!("Fresh", "Evidence"),
            concat!("BoundPreselection", "TranscriptBatch"),
            concat!("Candidate", "Evidence"),
            concat!("RouteSession", "Authority"),
            concat!("Reservation", "Session"),
            concat!("Generate", "Event"),
            concat!("observed_", "endpoints"),
            concat!("ser", "de"),
            concat!("pub ", "fn"),
        ] {
            assert!(
                !production.contains(forbidden),
                "forbidden production surface {forbidden}"
            );
        }
        assert_eq!(
            production
                .matches(concat!("HashMap<ConnectionId, Connection", "Record>"))
                .count(),
            1
        );
        assert_eq!(production.matches(concat!("checked_", "add(1)")).count(), 1);
        assert_eq!(production.matches(concat!("pub ", "struct ")).count(), 3);
        assert_eq!(production.matches(concat!("pub ", "enum ")).count(), 1);
        assert!(production.contains(concat!("pub struct ConnectionProvenance", "Behaviour {")));
        assert!(production.contains(concat!("pub enum ConnectionProvenance", "Event {}")));
        assert!(production.contains(concat!(
            "pub struct BoundNativeProbeControl",
            "Connection {"
        )));
        for (declaration, description) in [
            (
                concat!("pub struct BoundNativeProbeControl", "Connection {"),
                "native Permit connection token",
            ),
            (
                concat!("pub struct BoundNativeProbeDataRelay", "Connection {"),
                "native authorization connection token",
            ),
        ] {
            let token = production
                .split(declaration)
                .nth(1)
                .unwrap_or_else(|| panic!("{description}"))
                .split('}')
                .next()
                .expect("native connection token body");
            assert!(!token.contains("pub "));
        }
        assert!(production.contains("Swarm guarantees ConnectionIds are unique and never reused"));
        let defaults = production
            .split("impl Default for ConnectionRegistry")
            .nth(1)
            .expect("registry defaults")
            .split("/// Passive private behaviour")
            .next()
            .expect("registry defaults end");
        assert!(defaults.contains("MAX_ESTABLISHED_CONNECTIONS"));
        assert!(defaults.contains("MAX_ESTABLISHED_CONNECTIONS_PER_PEER"));
    }

    #[test]
    fn private_composition_has_no_generic_registry_or_address_escape() {
        let crate_source = include_str!("lib.rs");
        let private_module = concat!("mod connection_", "provenance;");
        let behaviour_field = concat!("connection_provenance: ConnectionProvenance", "Behaviour");
        let behaviour_new = concat!("ConnectionProvenance", "Behaviour::new()");
        let event_from = concat!(
            "impl From<ConnectionProvenance",
            "Event> for BehaviourEvent"
        );
        assert_eq!(crate_source.matches(private_module).count(), 1);
        assert_eq!(crate_source.matches(behaviour_field).count(), 1);
        assert_eq!(crate_source.matches(behaviour_new).count(), 1);
        assert_eq!(crate_source.matches(event_from).count(), 1);
        assert!(!crate_source.contains(concat!("pub mod connection_", "provenance")));
        assert!(!crate_source.contains(concat!("pub ", "fn connection_", "provenance")));
        assert!(crate_source.contains("BoundNativeProbeControlConnection"));
        assert!(crate_source.contains("BoundNativeProbeDataRelayConnection"));
        assert!(!crate_source.contains(concat!(
            "ConnectionProvenance(ConnectionProvenance",
            "Event)"
        )));
    }
}
