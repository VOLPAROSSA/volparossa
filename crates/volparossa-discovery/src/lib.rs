//! Decentralised libp2p discovery for VOLPAROSSA.

mod advertisement_budget;
#[cfg(test)]
mod advertisement_tests;
mod advertisements;
mod connection_provenance;
mod forwarding;
mod mpquic_session;
mod mptcp_session;
mod peerlink;
mod preselection_forwarder;
mod preselection_responder;
mod preselection_transaction;
mod preselection_wire;
mod reservations;
mod udp_session;

use std::{
    collections::HashMap,
    convert::Infallible,
    time::{Duration, Instant},
};

use futures::StreamExt;
use libp2p::{
    Multiaddr, PeerId, StreamProtocol, Swarm, SwarmBuilder, Transport as _, autonat,
    connection_limits,
    core::{transport::MemoryTransport, upgrade},
    dcutr, identify, identity,
    kad::{self, store::MemoryStore},
    mdns, noise, ping, relay, request_response,
    swarm::NetworkBehaviour,
    tcp, yamux,
};
use thiserror::Error;

use advertisement_budget::AdvertisementBudgets;
pub use advertisements::{
    ADVERTISEMENT_PROTOCOL, ADVERTISEMENT_RPC_VERSION, AdvertisementRequest, AdvertisementResponse,
    AdvertisementRpcError, LEGACY_ADVERTISEMENT_PROTOCOL_V1, LEGACY_ADVERTISEMENT_PROTOCOL_V2,
    MAX_ADVERTISEMENT_BYTES, MAX_ADVERTISEMENT_REQUEST_FRAME_BYTES,
    MAX_ADVERTISEMENT_RESPONSE_FRAME_BYTES, MAX_CONCURRENT_ADVERTISEMENT_STREAMS,
    advertisement_envelope_matches_peer,
};
use advertisements::{AdvertisementCodec, advertisement_behaviour};
pub use connection_provenance::{
    BoundNativeProbeControlConnection, BoundNativeProbeDataRelayConnection,
};
use connection_provenance::{ConnectionProvenanceBehaviour, ConnectionProvenanceEvent};
pub use forwarding::{
    EXIT_FORWARD_PROTOCOL, EXIT_FORWARD_REQUEST_TIMEOUT, EXIT_FORWARD_UPSTREAM_PROTOCOL,
    EXIT_FORWARD_UPSTREAM_TIMEOUT, ExitForwardOperation, ExitForwardRequest, ExitForwardResponse,
    FORWARDING_RPC_VERSION, ForwardStatus, ForwardingRpcError, MAX_CONCURRENT_FORWARDING_STREAMS,
    MAX_FORWARDING_FRAME_BYTES, NativeProbeReadyForwardRequest, UpstreamExitForwardRequest,
    UpstreamExitForwardResponse,
};
use forwarding::{
    ExitForwardCodec, UpstreamExitForwardCodec, exit_forward_behaviour,
    exit_forward_upstream_behaviour,
};
pub use mpquic_session::{
    ExitMpquicSessionSignal, MpquicSessionFrameError, MpquicSessionPathProof,
    MpquicSessionStartRequest,
};
pub use mptcp_session::{
    ExitMptcpSessionSignal, MptcpSessionFrameError, MptcpSessionPathProof, MptcpSessionStartRequest,
};
pub use peerlink::{PeerLink, PeerLinkError};
use preselection_forwarder::PreselectionForwarderState;
use preselection_responder::PreselectionResponderState;
pub use preselection_responder::{
    DirectPreselectionResponderError, LocalPreselectionPolicy, UpstreamPreselectionResponderError,
};
pub use preselection_transaction::{
    BoundClientPreselectionTransport, BoundUpstreamPreselectionTransport,
    ClientPreselectionBindFailure, ClientPreselectionCancelFailure, ClientPreselectionDispatch,
    ClientPreselectionDispatchFailure, ClientPreselectionResponseArrival,
    ClientPreselectionTransaction, ClientPreselectionTransportFreshnessProof,
    PreselectionDispatchError, UpstreamPreselectionDispatch, UpstreamPreselectionResponseArrival,
    UpstreamPreselectionTransaction, consume_bound_client_preselection_transport_for_freshness,
};
use preselection_transaction::{
    PreselectionTransactionState, client_request_has_local_target_from_distinct_sender,
    upstream_request_has_authenticated_target,
};
use preselection_wire::{
    ClientPreselectionObservationCodec, UpstreamPreselectionObservationCodec,
    client_preselection_observation_behaviour, upstream_preselection_observation_behaviour,
};
pub use preselection_wire::{
    ClientPreselectionObservationRequest, ClientPreselectionObservationResponse,
    MAX_CONCURRENT_PRESELECTION_OBSERVATION_STREAMS, MAX_FORWARDED_ATTESTATION_SIZE,
    MAX_PRESELECTION_RECEIPT_SIZE, MAX_PRESELECTION_REQUEST_SIZE,
    PRESELECTION_OBSERVATION_PROTOCOL, PRESELECTION_OBSERVATION_REQUEST_TIMEOUT,
    PRESELECTION_OBSERVATION_UPSTREAM_PROTOCOL, PreselectionObservationRpcError,
    UpstreamPreselectionObservationRequest, UpstreamPreselectionObservationResponse,
};
pub use reservations::{
    DATAPATH_RELAY_PROTOCOL, DATAPATH_RELAY_REQUEST_TIMEOUT, DATAPATH_RELAY_RPC_VERSION,
    DatapathRelayOperation, DatapathRelayRequest, DatapathRelayResponse, DatapathRelayRpcError,
    LEGACY_EXIT_CONFIRMATION_PROTOCOL_V2, LEGACY_EXIT_RESERVATION_PROTOCOL_V2,
    LEGACY_RELAY_RESERVATION_PROTOCOL_V2, MAX_CONCURRENT_DATAPATH_RELAY_STREAMS,
    MAX_DATAPATH_RELAY_FRAME_BYTES,
};
use reservations::{DatapathRelayCodec, datapath_relay_behaviour};
pub use udp_session::{UdpExitSessionSignal, UdpSessionFrameError, UdpSessionStartRequest};
use volparossa_protocol::{
    MAX_CONTROL_MESSAGE_SIZE, SignedEnvelope, decode_canonical, node_id_from_public_key,
};

/// Private DHT protocol prevents record mixing with unrelated IPFS/libp2p networks.
pub const KADEMLIA_PROTOCOL: &str = "/volparossa/kad/1";

/// Maximum number of raw discovery addresses inspected from one untrusted event.
pub const MAX_DISCOVERY_ADDRESSES_PER_EVENT: usize = 64;
/// Maximum number of distinct Kademlia addresses retained for one peer.
pub const MAX_DISCOVERY_ADDRESSES_PER_PEER: usize = 16;
/// Maximum encoded size of a Kademlia address admitted from discovery.
pub const MAX_DISCOVERY_ADDRESS_BYTES: usize = 1_024;
/// Maximum number of peers tracked by the discovery address admission layer.
pub const MAX_TRACKED_DISCOVERY_PEERS: usize = 1_024;
/// Maximum accepted private-Kademlia packet size.
pub const MAX_KADEMLIA_PACKET_BYTES: usize = 16 * 1_024;
/// Maximum concurrent inbound connection attempts.
pub const MAX_PENDING_INBOUND_CONNECTIONS: u32 = 64;
/// Maximum concurrent outbound connection attempts.
pub const MAX_PENDING_OUTBOUND_CONNECTIONS: u32 = 64;
/// Maximum established inbound connections.
pub const MAX_ESTABLISHED_INBOUND_CONNECTIONS: u32 = 256;
/// Maximum established outbound connections.
pub const MAX_ESTABLISHED_OUTBOUND_CONNECTIONS: u32 = 256;
/// Maximum established connections in both directions.
pub const MAX_ESTABLISHED_CONNECTIONS: u32 = 384;
/// Maximum established connections to one authenticated peer.
pub const MAX_ESTABLISHED_CONNECTIONS_PER_PEER: u32 = 4;

/// Immutable local-role gates for every discovery request-response direction.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct DiscoveryProtocolRoles {
    client: bool,
    relay: bool,
    exit: bool,
}

impl DiscoveryProtocolRoles {
    /// Construct an exact role combination.
    #[must_use]
    pub const fn new(client: bool, relay: bool, exit: bool) -> Self {
        Self {
            client,
            relay,
            exit,
        }
    }

    /// Whether client-facing outbound protocols are enabled.
    #[must_use]
    pub const fn client(self) -> bool {
        self.client
    }

    /// Whether relay-facing protocol directions are enabled.
    #[must_use]
    pub const fn relay(self) -> bool {
        self.relay
    }

    /// Whether exit-facing inbound protocols are enabled.
    #[must_use]
    pub const fn exit(self) -> bool {
        self.exit
    }
}

impl Default for DiscoveryProtocolRoles {
    fn default() -> Self {
        Self::new(true, false, false)
    }
}

const fn advertisement_protocol_directions(roles: DiscoveryProtocolRoles) -> (bool, bool) {
    // Exit advertisements are served only through the upstream forwarding hop.
    // Exit nodes still dial direct relay advertisements to authenticate that hop.
    (roles.client() || roles.exit(), roles.relay())
}

const fn client_preselection_protocol_directions(roles: DiscoveryProtocolRoles) -> (bool, bool) {
    (roles.client(), roles.relay())
}

const fn upstream_preselection_protocol_directions(roles: DiscoveryProtocolRoles) -> (bool, bool) {
    (roles.relay(), roles.exit())
}

fn protocol_support(outbound: bool, inbound: bool) -> Option<request_response::ProtocolSupport> {
    match (outbound, inbound) {
        (true, true) => Some(request_response::ProtocolSupport::Full),
        (true, false) => Some(request_response::ProtocolSupport::Outbound),
        (false, true) => Some(request_response::ProtocolSupport::Inbound),
        (false, false) => None,
    }
}
/// Capability provider indexes. None is an all-node catalogue.
pub mod capability {
    /// Generic voluntary relay providers.
    pub const RELAY: &str = "/volparossa/v1/provider/relay";
    /// Explicitly enabled exit providers.
    pub const EXIT: &str = "/volparossa/v1/provider/exit";
    /// Kernel-MPTCP-capable providers.
    pub const MPTCP: &str = "/volparossa/v1/provider/mptcp";
    /// Genuine Multipath-QUIC-capable providers.
    pub const MPQUIC: &str = "/volparossa/v1/provider/mpquic";

    /// Builds a bounded region capability key.
    pub fn region(role: &str, region: &str) -> Option<String> {
        if !matches!(role, "relay" | "exit")
            || region.is_empty()
            || region.len() > 32
            || !region
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return None;
        }
        Some(format!("/volparossa/v1/provider/{role}/{region}"))
    }

    /// Builds the exact-policy capability key.
    #[must_use]
    pub fn policy(policy_hash: &[u8; 32]) -> String {
        let mut value = String::with_capacity(96);
        value.push_str("/volparossa/v1/provider/policy/");
        for byte in policy_hash {
            use std::fmt::Write as _;
            let _ = write!(value, "{byte:02x}");
        }
        value
    }
}

fn connection_limits_behaviour() -> connection_limits::Behaviour {
    connection_limits::Behaviour::new(
        connection_limits::ConnectionLimits::default()
            .with_max_pending_incoming(Some(MAX_PENDING_INBOUND_CONNECTIONS))
            .with_max_pending_outgoing(Some(MAX_PENDING_OUTBOUND_CONNECTIONS))
            .with_max_established_incoming(Some(MAX_ESTABLISHED_INBOUND_CONNECTIONS))
            .with_max_established_outgoing(Some(MAX_ESTABLISHED_OUTBOUND_CONNECTIONS))
            .with_max_established(Some(MAX_ESTABLISHED_CONNECTIONS))
            .with_max_established_per_peer(Some(MAX_ESTABLISHED_CONNECTIONS_PER_PEER)),
    )
}

#[derive(NetworkBehaviour)]
/// Combined control-plane behaviour. Circuit relay is control-plane only.
#[behaviour(to_swarm = "BehaviourEvent")]
pub struct DiscoveryBehaviour {
    /// Closed global and per-peer connection budgets; no peer bypasses these limits.
    connection_limits: connection_limits::Behaviour,
    /// Private, passive lineage for exact authenticated connection observations.
    connection_provenance: ConnectionProvenanceBehaviour,
    /// Client-hop A1c behaviour; the client-side outbound attempt owner remains absent.
    preselection_observation: request_response::Behaviour<ClientPreselectionObservationCodec>,
    /// Affine control-relay-to-exit A1c transport behaviour.
    preselection_observation_upstream:
        request_response::Behaviour<UpstreamPreselectionObservationCodec>,
    /// Peer protocol/address metadata.
    pub identify: identify::Behaviour,
    /// Lightweight liveness.
    pub ping: ping::Behaviour,
    /// Private capability-index DHT.
    pub kademlia: kad::Behaviour<MemoryStore>,
    /// LAN bootstrap with no authority.
    pub mdns: mdns::tokio::Behaviour,
    /// External-address reachability estimation.
    pub autonat: autonat::Behaviour,
    /// Direct connection upgrade/hole punching.
    pub dcutr: dcutr::Behaviour,
    /// Circuit Relay v2 client for control-plane reachability.
    pub relay_client: relay::client::Behaviour,
    /// Voluntary Circuit Relay v2 service for other control-plane peers.
    pub relay_server: relay::Behaviour,
    /// Direct relay/control-relay advertisement retrieval.
    pub advertisements: request_response::Behaviour<AdvertisementCodec>,
    /// Client-to-control-relay forwarding hop.
    pub exit_forward: request_response::Behaviour<ExitForwardCodec>,
    /// Control-relay-to-exit forwarding hop.
    pub exit_forward_upstream: request_response::Behaviour<UpstreamExitForwardCodec>,
    /// Direct client-to-selected-datapath-relay hop.
    pub datapath_relay: request_response::Behaviour<DatapathRelayCodec>,
}

impl DiscoveryBehaviour {
    fn new(
        keypair: &identity::Keypair,
        relay_client: relay::client::Behaviour,
        mdns: mdns::tokio::Behaviour,
        protocol_roles: DiscoveryProtocolRoles,
    ) -> Self {
        let local_peer_id = keypair.public().to_peer_id();
        let connection_limits = connection_limits_behaviour();
        let connection_provenance = ConnectionProvenanceBehaviour::new();
        let (preselection_outbound, preselection_inbound) =
            client_preselection_protocol_directions(protocol_roles);
        let preselection_observation = client_preselection_observation_behaviour(protocol_support(
            preselection_outbound,
            preselection_inbound,
        ));
        let (preselection_upstream_outbound, preselection_upstream_inbound) =
            upstream_preselection_protocol_directions(protocol_roles);
        let preselection_observation_upstream =
            upstream_preselection_observation_behaviour(protocol_support(
                preselection_upstream_outbound,
                preselection_upstream_inbound,
            ));
        let identify = identify::Behaviour::new(
            identify::Config::new("/volparossa/1.0.0".into(), keypair.public())
                .with_agent_version("volparossa/0.1.0".into()),
        );
        let ping = ping::Behaviour::new(
            ping::Config::new()
                .with_interval(Duration::from_secs(30))
                .with_timeout(Duration::from_secs(10)),
        );
        let mut kad_config = kad::Config::new(StreamProtocol::new(KADEMLIA_PROTOCOL));
        kad_config.set_query_timeout(Duration::from_secs(30));
        kad_config.set_max_packet_size(MAX_KADEMLIA_PACKET_BYTES);
        kad_config.set_kbucket_inserts(kad::BucketInserts::Manual);
        kad_config.set_record_ttl(Some(Duration::from_secs(300)));
        kad_config.set_provider_record_ttl(Some(Duration::from_secs(300)));
        // Retry capability publication inside the same bounded window as LAN discovery. A
        // successful initial AddProvider exchange can still precede full routing convergence.
        kad_config.set_provider_publication_interval(Some(Duration::from_secs(10)));
        let mut kademlia =
            kad::Behaviour::with_config(local_peer_id, MemoryStore::new(local_peer_id), kad_config);
        // Voluntary service nodes and role-less bootstrap contacts are explicit private-overlay
        // DHT servers. Waiting for libp2p's public external-address heuristic leaves a
        // disposable/private topology permanently in client mode, while making bootstrap-only
        // contacts clients leaves Relay and Exit provider records with no shared storage hop.
        // Bootstrap contacts still carry no authority: they store signed capability indexes only.
        kademlia.set_mode(Some(kademlia_mode_for_roles(protocol_roles)));
        let autonat = autonat::Behaviour::new(local_peer_id, autonat::Config::default());
        let dcutr = dcutr::Behaviour::new(local_peer_id);
        let relay_server = relay::Behaviour::new(local_peer_id, relay::Config::default());
        let (advertisement_outbound, advertisement_inbound) =
            advertisement_protocol_directions(protocol_roles);
        let advertisements = advertisement_behaviour(protocol_support(
            advertisement_outbound,
            advertisement_inbound,
        ));
        let exit_forward = exit_forward_behaviour(protocol_support(
            protocol_roles.client(),
            protocol_roles.relay(),
        ));
        let exit_forward_upstream = exit_forward_upstream_behaviour(protocol_support(
            protocol_roles.relay(),
            protocol_roles.exit(),
        ));
        let datapath_relay = datapath_relay_behaviour(protocol_support(
            protocol_roles.client(),
            protocol_roles.relay(),
        ));
        Self {
            connection_limits,
            connection_provenance,
            preselection_observation,
            preselection_observation_upstream,
            identify,
            ping,
            kademlia,
            mdns,
            autonat,
            dcutr,
            relay_client,
            relay_server,
            advertisements,
            exit_forward,
            exit_forward_upstream,
            datapath_relay,
        }
    }
}

const fn kademlia_mode_for_roles(roles: DiscoveryProtocolRoles) -> kad::Mode {
    if roles.relay() || roles.exit() || !roles.client() {
        kad::Mode::Server
    } else {
        kad::Mode::Client
    }
}

/// Event generated by one of the composed behaviours.
// This public event mirrors the concrete event types required by libp2p's `NetworkBehaviour`
// derive. Boxing a subset would complicate every generated conversion and swarm match arm.
#[allow(clippy::large_enum_variant, reason = "libp2p behaviour event API")]
#[derive(Debug)]
pub enum BehaviourEvent {
    /// Identify event.
    Identify(identify::Event),
    /// Impossible marker from the connection-limits behaviour.
    ConnectionLimits(Infallible),
    /// Ping event.
    Ping(ping::Event),
    /// Kademlia event.
    Kademlia(kad::Event),
    /// mDNS event.
    Mdns(mdns::Event),
    /// `AutoNAT` event.
    Autonat(autonat::Event),
    /// `DCUtR` event.
    Dcutr(dcutr::Event),
    /// Relay client event.
    RelayClient(relay::client::Event),
    /// Relay server event.
    RelayServer(relay::Event),
    /// Advertisement protocol event.
    Advertisements(request_response::Event<AdvertisementRequest, AdvertisementResponse>),
    /// Client-hop A1c event; the client-side outbound attempt owner remains absent.
    PreselectionObservation(
        request_response::Event<
            ClientPreselectionObservationRequest,
            ClientPreselectionObservationResponse,
        >,
    ),
    /// Affine control-relay-to-exit preselection transport event.
    PreselectionObservationUpstream(
        request_response::Event<
            UpstreamPreselectionObservationRequest,
            UpstreamPreselectionObservationResponse,
        >,
    ),
    /// Client-to-control-relay forwarding event.
    ExitForward(request_response::Event<ExitForwardRequest, ExitForwardResponse>),
    /// Control-relay-to-exit forwarding event.
    ExitForwardUpstream(
        request_response::Event<UpstreamExitForwardRequest, UpstreamExitForwardResponse>,
    ),
    /// Direct client-to-datapath-relay event.
    DatapathRelay(request_response::Event<DatapathRelayRequest, DatapathRelayResponse>),
}

/// Detail-free reason exact authenticated connection provenance could not be bound.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    missing_docs,
    reason = "variant names are the complete privacy-neutral diagnostic contract"
)]
#[non_exhaustive]
pub enum PreselectionProvenanceReject {
    RegistryPoisoned,
    ExactConnectionMissing,
    MultipleSiblingConnections,
    FamilyPrefix,
    BindGeneration,
}

/// Detail-free class emitted when an owned preselection responder rejects a request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[allow(
    missing_docs,
    reason = "variant names are the complete privacy-neutral diagnostic contract"
)]
#[non_exhaustive]
pub enum PreselectionResponderReject {
    DirectRole,
    DirectRequest,
    DirectAuthority,
    DirectProvenance(PreselectionProvenanceReject),
    DirectReplay,
    DirectResourceLimit,
    DirectTime,
    DirectSigning,
    DirectResponseChannel,
    ForwardedRequest,
    ForwardedAuthority,
    ForwardedTransaction,
    ForwardedProof,
    ForwardedReplay,
    ForwardedResourceLimit,
    ForwardedTime,
    ForwardedSigning,
    ForwardedResponseChannel,
    ForwardedUpstreamTransport,
    UpstreamRole,
    UpstreamRequest,
    UpstreamAuthority,
    UpstreamProvenance(PreselectionProvenanceReject),
    UpstreamReplay,
    UpstreamResourceLimit,
    UpstreamTime,
    UpstreamSigning,
    UpstreamResponseChannel,
}

impl PreselectionResponderReject {
    /// Stable privacy-neutral event code. No peer, address, request, or payload detail is exposed.
    #[must_use]
    pub const fn event_code(self) -> &'static str {
        match self {
            Self::DirectRole => "PRESELECTION_RESPONDER_DIRECT_ROLE_REJECTED",
            Self::DirectRequest => "PRESELECTION_RESPONDER_DIRECT_REQUEST_REJECTED",
            Self::DirectAuthority => "PRESELECTION_RESPONDER_DIRECT_AUTHORITY_REJECTED",
            Self::DirectProvenance(PreselectionProvenanceReject::RegistryPoisoned) => {
                "PRESELECTION_RESPONDER_DIRECT_PROVENANCE_REGISTRY_POISONED"
            }
            Self::DirectProvenance(PreselectionProvenanceReject::ExactConnectionMissing) => {
                "PRESELECTION_RESPONDER_DIRECT_PROVENANCE_CONNECTION_MISSING"
            }
            Self::DirectProvenance(PreselectionProvenanceReject::MultipleSiblingConnections) => {
                "PRESELECTION_RESPONDER_DIRECT_PROVENANCE_MULTIPLE_CONNECTIONS"
            }
            Self::DirectProvenance(PreselectionProvenanceReject::FamilyPrefix) => {
                "PRESELECTION_RESPONDER_DIRECT_PROVENANCE_FAMILY_PREFIX"
            }
            Self::DirectProvenance(PreselectionProvenanceReject::BindGeneration) => {
                "PRESELECTION_RESPONDER_DIRECT_PROVENANCE_BIND_GENERATION"
            }
            Self::DirectReplay => "PRESELECTION_RESPONDER_DIRECT_REPLAY_REJECTED",
            Self::DirectResourceLimit => "PRESELECTION_RESPONDER_DIRECT_RESOURCE_LIMIT_REJECTED",
            Self::DirectTime => "PRESELECTION_RESPONDER_DIRECT_TIME_REJECTED",
            Self::DirectSigning => "PRESELECTION_RESPONDER_DIRECT_SIGNING_REJECTED",
            Self::DirectResponseChannel => {
                "PRESELECTION_RESPONDER_DIRECT_RESPONSE_CHANNEL_REJECTED"
            }
            Self::ForwardedRequest => "PRESELECTION_RESPONDER_FORWARDED_REQUEST_REJECTED",
            Self::ForwardedAuthority => "PRESELECTION_RESPONDER_FORWARDED_AUTHORITY_REJECTED",
            Self::ForwardedTransaction => "PRESELECTION_RESPONDER_FORWARDED_TRANSACTION_REJECTED",
            Self::ForwardedProof => "PRESELECTION_RESPONDER_FORWARDED_PROOF_REJECTED",
            Self::ForwardedReplay => "PRESELECTION_RESPONDER_FORWARDED_REPLAY_REJECTED",
            Self::ForwardedResourceLimit => {
                "PRESELECTION_RESPONDER_FORWARDED_RESOURCE_LIMIT_REJECTED"
            }
            Self::ForwardedTime => "PRESELECTION_RESPONDER_FORWARDED_TIME_REJECTED",
            Self::ForwardedSigning => "PRESELECTION_RESPONDER_FORWARDED_SIGNING_REJECTED",
            Self::ForwardedResponseChannel => {
                "PRESELECTION_RESPONDER_FORWARDED_RESPONSE_CHANNEL_REJECTED"
            }
            Self::ForwardedUpstreamTransport => {
                "PRESELECTION_RESPONDER_FORWARDED_UPSTREAM_TRANSPORT_REJECTED"
            }
            Self::UpstreamRole => "PRESELECTION_RESPONDER_UPSTREAM_ROLE_REJECTED",
            Self::UpstreamRequest => "PRESELECTION_RESPONDER_UPSTREAM_REQUEST_REJECTED",
            Self::UpstreamAuthority => "PRESELECTION_RESPONDER_UPSTREAM_AUTHORITY_REJECTED",
            Self::UpstreamProvenance(PreselectionProvenanceReject::RegistryPoisoned) => {
                "PRESELECTION_RESPONDER_UPSTREAM_PROVENANCE_REGISTRY_POISONED"
            }
            Self::UpstreamProvenance(PreselectionProvenanceReject::ExactConnectionMissing) => {
                "PRESELECTION_RESPONDER_UPSTREAM_PROVENANCE_CONNECTION_MISSING"
            }
            Self::UpstreamProvenance(PreselectionProvenanceReject::MultipleSiblingConnections) => {
                "PRESELECTION_RESPONDER_UPSTREAM_PROVENANCE_MULTIPLE_CONNECTIONS"
            }
            Self::UpstreamProvenance(PreselectionProvenanceReject::FamilyPrefix) => {
                "PRESELECTION_RESPONDER_UPSTREAM_PROVENANCE_FAMILY_PREFIX"
            }
            Self::UpstreamProvenance(PreselectionProvenanceReject::BindGeneration) => {
                "PRESELECTION_RESPONDER_UPSTREAM_PROVENANCE_BIND_GENERATION"
            }
            Self::UpstreamReplay => "PRESELECTION_RESPONDER_UPSTREAM_REPLAY_REJECTED",
            Self::UpstreamResourceLimit => {
                "PRESELECTION_RESPONDER_UPSTREAM_RESOURCE_LIMIT_REJECTED"
            }
            Self::UpstreamTime => "PRESELECTION_RESPONDER_UPSTREAM_TIME_REJECTED",
            Self::UpstreamSigning => "PRESELECTION_RESPONDER_UPSTREAM_SIGNING_REJECTED",
            Self::UpstreamResponseChannel => {
                "PRESELECTION_RESPONDER_UPSTREAM_RESPONSE_CHANNEL_REJECTED"
            }
        }
    }
}

/// Sanitized public discovery event.
///
/// Preselection request messages remain entirely service-owned. Responses for the exact active
/// dispatch are replaced at the private swarm boundary by opaque, instance-bound arrival values;
/// stale or unowned responses are dropped. Raw request/response events are never returned by a
/// public event pump. All unrelated swarm events, including typed outbound failures, remain
/// available unchanged through [`Self::Other`].
#[non_exhaustive]
pub enum DiscoveryEvent {
    /// Service-sealed response to an outbound client-to-relay observation request.
    ClientPreselectionResponse(ClientPreselectionResponseArrival),
    /// Service-sealed response to an outbound relay-to-exit observation request.
    UpstreamPreselectionResponse(UpstreamPreselectionResponseArrival),
    /// Detail-free reason an owned preselection request was rejected before response handoff.
    PreselectionResponderRejected(PreselectionResponderReject),
    /// Any event other than a preselection request or response message.
    Other(libp2p::swarm::SwarmEvent<BehaviourEvent>),
}

impl From<identify::Event> for BehaviourEvent {
    fn from(value: identify::Event) -> Self {
        Self::Identify(value)
    }
}
impl From<Infallible> for BehaviourEvent {
    fn from(value: Infallible) -> Self {
        match value {}
    }
}
impl From<ConnectionProvenanceEvent> for BehaviourEvent {
    fn from(value: ConnectionProvenanceEvent) -> Self {
        match value {}
    }
}
impl From<ping::Event> for BehaviourEvent {
    fn from(value: ping::Event) -> Self {
        Self::Ping(value)
    }
}
impl From<kad::Event> for BehaviourEvent {
    fn from(value: kad::Event) -> Self {
        Self::Kademlia(value)
    }
}
impl From<mdns::Event> for BehaviourEvent {
    fn from(value: mdns::Event) -> Self {
        Self::Mdns(value)
    }
}
impl From<autonat::Event> for BehaviourEvent {
    fn from(value: autonat::Event) -> Self {
        Self::Autonat(value)
    }
}
impl From<dcutr::Event> for BehaviourEvent {
    fn from(value: dcutr::Event) -> Self {
        Self::Dcutr(value)
    }
}
impl From<relay::client::Event> for BehaviourEvent {
    fn from(value: relay::client::Event) -> Self {
        Self::RelayClient(value)
    }
}
impl From<relay::Event> for BehaviourEvent {
    fn from(value: relay::Event) -> Self {
        Self::RelayServer(value)
    }
}
impl From<request_response::Event<AdvertisementRequest, AdvertisementResponse>> for BehaviourEvent {
    fn from(value: request_response::Event<AdvertisementRequest, AdvertisementResponse>) -> Self {
        Self::Advertisements(value)
    }
}
impl
    From<
        request_response::Event<
            ClientPreselectionObservationRequest,
            ClientPreselectionObservationResponse,
        >,
    > for BehaviourEvent
{
    fn from(
        value: request_response::Event<
            ClientPreselectionObservationRequest,
            ClientPreselectionObservationResponse,
        >,
    ) -> Self {
        Self::PreselectionObservation(value)
    }
}
impl
    From<
        request_response::Event<
            UpstreamPreselectionObservationRequest,
            UpstreamPreselectionObservationResponse,
        >,
    > for BehaviourEvent
{
    fn from(
        value: request_response::Event<
            UpstreamPreselectionObservationRequest,
            UpstreamPreselectionObservationResponse,
        >,
    ) -> Self {
        Self::PreselectionObservationUpstream(value)
    }
}
impl From<request_response::Event<ExitForwardRequest, ExitForwardResponse>> for BehaviourEvent {
    fn from(value: request_response::Event<ExitForwardRequest, ExitForwardResponse>) -> Self {
        Self::ExitForward(value)
    }
}
impl From<request_response::Event<UpstreamExitForwardRequest, UpstreamExitForwardResponse>>
    for BehaviourEvent
{
    fn from(
        value: request_response::Event<UpstreamExitForwardRequest, UpstreamExitForwardResponse>,
    ) -> Self {
        Self::ExitForwardUpstream(value)
    }
}
impl From<request_response::Event<DatapathRelayRequest, DatapathRelayResponse>> for BehaviourEvent {
    fn from(value: request_response::Event<DatapathRelayRequest, DatapathRelayResponse>) -> Self {
        Self::DatapathRelay(value)
    }
}

/// Discovery construction and validation failures.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// libp2p transport/behaviour construction failed.
    #[error("cannot build discovery swarm: {0}")]
    Build(String),
    /// A listen/dial operation failed.
    #[error("libp2p swarm operation failed: {0}")]
    Swarm(String),
    /// Provider key is not one of the bounded VOLPAROSSA namespaces.
    #[error("invalid VOLPAROSSA capability key")]
    Capability,
    /// Advertisement envelope is empty or oversized.
    #[error("invalid signed advertisement length")]
    AdvertisementLength,
    /// A fixed discovery query or request budget is exhausted.
    #[error("discovery resource limit reached")]
    ResourceLimit,
    /// A peer address is empty, oversized, self-referential, or identity-inconsistent.
    #[error("invalid discovery peer address")]
    PeerAddress,
    /// A direct-advertisement frame violates its canonical v4 bounds.
    #[error(transparent)]
    AdvertisementRpc(#[from] AdvertisementRpcError),
    /// A forwarding-hop frame violates its canonical v4 bounds.
    #[error(transparent)]
    ForwardingRpc(#[from] ForwardingRpcError),
    /// A datapath-relay frame violates its canonical v4 bounds.
    #[error(transparent)]
    DatapathRelayRpc(#[from] DatapathRelayRpcError),
    /// The requested protocol direction is disabled for the immutable local roles.
    #[error("discovery protocol direction is disabled for local roles")]
    ProtocolRole,
    /// A wrapper identity does not match the authenticated transport peer or local node.
    #[error("discovery protocol wrapper peer mismatch")]
    ProtocolPeer,
    /// Peerlink is malformed.
    #[error(transparent)]
    PeerLink(#[from] PeerLinkError),
}

#[derive(Clone, Copy)]
enum AddressSource {
    Known,
    Mdns,
    Identify,
}

impl AddressSource {
    const fn mask(self) -> u8 {
        match self {
            Self::Known => 0b001,
            Self::Mdns => 0b010,
            Self::Identify => 0b100,
        }
    }
}

struct AdmittedAddress {
    address: Multiaddr,
    sources: u8,
}

struct AddressAdmissions {
    by_peer: HashMap<PeerId, Vec<AdmittedAddress>>,
    max_peers: usize,
    max_addresses_per_peer: usize,
}

impl Default for AddressAdmissions {
    fn default() -> Self {
        Self::new(
            MAX_TRACKED_DISCOVERY_PEERS,
            MAX_DISCOVERY_ADDRESSES_PER_PEER,
        )
    }
}

impl AddressAdmissions {
    fn new(max_peers: usize, max_addresses_per_peer: usize) -> Self {
        Self {
            by_peer: HashMap::new(),
            max_peers,
            max_addresses_per_peer,
        }
    }

    fn admit_prepared(
        &mut self,
        peer: PeerId,
        address: Multiaddr,
        source: AddressSource,
    ) -> Result<bool, DiscoveryError> {
        if let Some(addresses) = self.by_peer.get_mut(&peer) {
            if let Some(existing) = addresses
                .iter_mut()
                .find(|existing| existing.address == address)
            {
                existing.sources |= source.mask();
                return Ok(false);
            }
            if addresses.len() >= self.max_addresses_per_peer {
                return Err(DiscoveryError::ResourceLimit);
            }
            addresses.push(AdmittedAddress {
                address,
                sources: source.mask(),
            });
            return Ok(true);
        }
        if self.by_peer.len() >= self.max_peers {
            return Err(DiscoveryError::ResourceLimit);
        }
        self.by_peer.insert(
            peer,
            vec![AdmittedAddress {
                address,
                sources: source.mask(),
            }],
        );
        Ok(true)
    }

    fn withdraw_prepared(
        &mut self,
        peer: PeerId,
        address: &Multiaddr,
        source: AddressSource,
    ) -> Option<Multiaddr> {
        let addresses = self.by_peer.get_mut(&peer)?;
        let position = addresses
            .iter()
            .position(|existing| existing.address == *address)?;
        addresses[position].sources &= !source.mask();
        if addresses[position].sources != 0 {
            return None;
        }
        let removed = addresses.remove(position).address;
        if addresses.is_empty() {
            self.by_peer.remove(&peer);
        }
        Some(removed)
    }

    fn withdraw_unlisted(
        &mut self,
        peer: PeerId,
        source: AddressSource,
        retained: &[Multiaddr],
    ) -> Vec<Multiaddr> {
        let Some(addresses) = self.by_peer.get_mut(&peer) else {
            return Vec::new();
        };
        let mut removed = Vec::new();
        let mut index = 0;
        while index < addresses.len() {
            if addresses[index].sources & source.mask() != 0
                && !retained.contains(&addresses[index].address)
            {
                addresses[index].sources &= !source.mask();
            }
            if addresses[index].sources == 0 {
                removed.push(addresses.remove(index).address);
            } else {
                index += 1;
            }
        }
        if addresses.is_empty() {
            self.by_peer.remove(&peer);
        }
        removed
    }
    fn contains_peer(&self, peer: &PeerId) -> bool {
        self.by_peer.contains_key(peer)
    }
}

/// Running decentralised discovery service.
pub struct DiscoveryService {
    swarm: Swarm<DiscoveryBehaviour>,
    local_advertisement: Option<Vec<u8>>,
    advertisement_budgets: AdvertisementBudgets,
    address_admissions: AddressAdmissions,
    protocol_roles: DiscoveryProtocolRoles,
    preselection_forwarder: PreselectionForwarderState,
    preselection_responder: PreselectionResponderState,
    preselection_transaction: PreselectionTransactionState,
}

impl DiscoveryService {
    /// Builds TCP+Noise/Yamux and QUIC transports with Relay v2 control-plane support.
    ///
    /// # Errors
    ///
    /// Returns an error when mDNS, a transport, DNS, relay-client support, or the composed
    /// behaviour cannot be constructed.
    pub fn new(keypair: identity::Keypair) -> Result<Self, DiscoveryError> {
        Self::new_with_protocol_roles(keypair, DiscoveryProtocolRoles::default())
    }

    /// Builds discovery with one immutable, explicit local role combination.
    ///
    /// # Errors
    ///
    /// Returns an error when any required transport or behaviour cannot be constructed.
    pub fn new_with_protocol_roles(
        keypair: identity::Keypair,
        protocol_roles: DiscoveryProtocolRoles,
    ) -> Result<Self, DiscoveryError> {
        let local_peer_id = keypair.public().to_peer_id();
        // A lost startup multicast must not leave a directly attached Relay undiscoverable for
        // libp2p-mDNS's five-minute default interval.
        let mdns_config = mdns::Config {
            query_interval: Duration::from_secs(10),
            ..mdns::Config::default()
        };
        let mdns = mdns::tokio::Behaviour::new(mdns_config, local_peer_id)
            .map_err(|error| DiscoveryError::Build(error.to_string()))?;
        let memory_noise = noise::Config::new(&keypair)
            .map_err(|error| DiscoveryError::Build(error.to_string()))?;
        let swarm = SwarmBuilder::with_existing_identity(keypair)
            .with_tokio()
            .with_tcp(
                tcp::Config::default().nodelay(true),
                noise::Config::new,
                yamux::Config::default,
            )
            .map_err(|error| DiscoveryError::Build(error.to_string()))?
            .with_quic()
            .with_other_transport(move |_| {
                MemoryTransport::default()
                    .upgrade(upgrade::Version::V1)
                    .authenticate(memory_noise)
                    .multiplex(yamux::Config::default())
            })
            .map_err(|never| -> DiscoveryError { match never {} })?
            .with_dns()
            .map_err(|error| DiscoveryError::Build(error.to_string()))?
            .with_relay_client(noise::Config::new, yamux::Config::default)
            .map_err(|error| DiscoveryError::Build(error.to_string()))?
            .with_behaviour(move |keypair, relay_client| {
                DiscoveryBehaviour::new(keypair, relay_client, mdns, protocol_roles)
            })
            .map_err(|error| DiscoveryError::Build(error.to_string()))?
            .with_swarm_config(|config| {
                config.with_idle_connection_timeout(Duration::from_secs(120))
            })
            .build();
        Ok(Self {
            swarm,
            protocol_roles,
            local_advertisement: None,
            advertisement_budgets: AdvertisementBudgets::new(),
            address_admissions: AddressAdmissions::default(),
            preselection_forwarder: PreselectionForwarderState::new()
                .map_err(|error| DiscoveryError::Build(error.to_string()))?,
            preselection_responder: PreselectionResponderState::new(),
            preselection_transaction: PreselectionTransactionState::new(),
        })
    }

    /// Returns the permanent local libp2p Peer ID.
    #[must_use]
    pub fn local_peer_id(&self) -> &PeerId {
        self.swarm.local_peer_id()
    }

    /// Returns the immutable local protocol roles.
    #[must_use]
    pub const fn protocol_roles(&self) -> DiscoveryProtocolRoles {
        self.protocol_roles
    }

    /// Starts listening on a validated multiaddress.
    ///
    /// # Errors
    ///
    /// Returns an error when libp2p rejects the listen address.
    pub fn listen_on(&mut self, address: Multiaddr) -> Result<(), DiscoveryError> {
        self.swarm
            .listen_on(address)
            .map(|_| ())
            .map_err(|error| DiscoveryError::Swarm(error.to_string()))
    }

    /// Dials a peerlink whose address is cryptographically bound to its expected Peer ID.
    ///
    /// # Errors
    ///
    /// Returns an error when libp2p rejects the peer-bound dial address.
    pub fn dial_peerlink(&mut self, peerlink: &PeerLink) -> Result<(), DiscoveryError> {
        self.swarm
            .dial(peerlink.dial_address())
            .map_err(|error| DiscoveryError::Swarm(error.to_string()))
    }

    /// Adds a remembered or user-imported peer address to the private DHT routing table.
    ///
    /// # Errors
    ///
    /// Returns an error when the address is invalid or the fixed address budget is exhausted.
    pub fn add_known_peer(
        &mut self,
        peer_id: PeerId,
        address: &Multiaddr,
    ) -> Result<(), DiscoveryError> {
        self.add_kademlia_address(peer_id, address, AddressSource::Known)
            .map(|_| ())
    }

    fn add_kademlia_address(
        &mut self,
        peer_id: PeerId,
        address: &Multiaddr,
        source: AddressSource,
    ) -> Result<Multiaddr, DiscoveryError> {
        let canonical = prepare_discovery_address(self.swarm.local_peer_id(), peer_id, address)?;
        self.add_prepared_kademlia_address(peer_id, canonical, source)
    }

    fn add_prepared_kademlia_address(
        &mut self,
        peer_id: PeerId,
        canonical: Multiaddr,
        source: AddressSource,
    ) -> Result<Multiaddr, DiscoveryError> {
        let is_new = self
            .address_admissions
            .admit_prepared(peer_id, canonical.clone(), source)?;
        if is_new
            && matches!(
                self.swarm
                    .behaviour_mut()
                    .kademlia
                    .add_address(&peer_id, canonical.clone()),
                kad::RoutingUpdate::Failed
            )
        {
            let _ = self
                .address_admissions
                .withdraw_prepared(peer_id, &canonical, source);
            return Err(DiscoveryError::ResourceLimit);
        }
        Ok(canonical)
    }

    fn withdraw_kademlia_address(
        &mut self,
        peer_id: PeerId,
        address: &Multiaddr,
        source: AddressSource,
    ) {
        let Ok(canonical) = prepare_discovery_address(self.swarm.local_peer_id(), peer_id, address)
        else {
            return;
        };
        if let Some(removed) = self
            .address_admissions
            .withdraw_prepared(peer_id, &canonical, source)
        {
            let kademlia = &mut self.swarm.behaviour_mut().kademlia;
            if self.address_admissions.contains_peer(&peer_id) {
                let _ = kademlia.remove_address(&peer_id, &removed);
            } else {
                let _ = kademlia.remove_peer(&peer_id);
            }
        }
    }

    fn refresh_identify_addresses(&mut self, peer_id: PeerId, info: &identify::Info) {
        let mut retained = Vec::new();
        if identify_supports_private_kademlia(peer_id, info) {
            for address in bounded_prefix(&info.listen_addrs, MAX_DISCOVERY_ADDRESSES_PER_EVENT) {
                if retained.len() >= MAX_DISCOVERY_ADDRESSES_PER_PEER {
                    break;
                }
                if let Ok(canonical) =
                    prepare_discovery_address(self.swarm.local_peer_id(), peer_id, address)
                {
                    if !retained.contains(&canonical) {
                        retained.push(canonical);
                    }
                }
            }
        }
        let removed =
            self.address_admissions
                .withdraw_unlisted(peer_id, AddressSource::Identify, &retained);
        let kademlia = &mut self.swarm.behaviour_mut().kademlia;
        if self.address_admissions.contains_peer(&peer_id) {
            for address in removed {
                let _ = kademlia.remove_address(&peer_id, &address);
            }
        } else {
            let _ = kademlia.remove_peer(&peer_id);
        }
        for canonical in retained {
            let _ = self.add_prepared_kademlia_address(peer_id, canonical, AddressSource::Identify);
        }
    }

    fn enforce_kademlia_routing_addresses(&mut self, peer_id: PeerId, addresses: &kad::Addresses) {
        if !self.address_admissions.contains_peer(&peer_id) {
            let _ = self.swarm.behaviour_mut().kademlia.remove_peer(&peer_id);
            return;
        }
        let mut valid_count = 0;
        let mut rejected = Vec::new();
        for address in addresses.iter() {
            let valid = valid_count < MAX_DISCOVERY_ADDRESSES_PER_PEER
                && prepare_discovery_address(self.swarm.local_peer_id(), peer_id, address)
                    .is_ok_and(|canonical| canonical == *address);
            if valid {
                valid_count += 1;
            } else {
                rejected.push(address.clone());
            }
        }
        for address in rejected {
            let _ = self
                .swarm
                .behaviour_mut()
                .kademlia
                .remove_address(&peer_id, &address);
        }
    }

    /// Starts providing one recognised capability key.
    ///
    /// # Errors
    ///
    /// Returns an error when the capability key is outside VOLPAROSSA's bounded namespaces or
    /// Kademlia rejects the provider operation.
    pub fn provide(&mut self, capability_key: &str) -> Result<kad::QueryId, DiscoveryError> {
        validate_capability_key(capability_key)?;
        self.swarm
            .behaviour_mut()
            .kademlia
            .start_providing(kad::RecordKey::new(&capability_key))
            .map_err(|error| DiscoveryError::Swarm(error.to_string()))
    }

    /// Stops publishing one recognised capability provider record.
    ///
    /// # Errors
    ///
    /// Returns an error when the capability key is outside VOLPAROSSA's bounded namespaces.
    pub fn stop_providing(&mut self, capability_key: &str) -> Result<(), DiscoveryError> {
        validate_capability_key(capability_key)?;
        self.swarm
            .behaviour_mut()
            .kademlia
            .stop_providing(&kad::RecordKey::new(&capability_key));
        Ok(())
    }

    /// Queries providers without downloading a global node list.
    ///
    /// # Errors
    ///
    /// Returns an error when the capability key is outside VOLPAROSSA's bounded namespaces or
    /// the fixed provider-query budget is exhausted. An already-running query for the exact same
    /// capability is returned rather than duplicated.
    pub fn find_providers(&mut self, capability_key: &str) -> Result<kad::QueryId, DiscoveryError> {
        validate_capability_key(capability_key)?;
        let swarm = &mut self.swarm;
        self.advertisement_budgets
            .provider_query_or_insert(capability_key, || {
                swarm
                    .behaviour_mut()
                    .kademlia
                    .get_providers(kad::RecordKey::new(&capability_key))
            })
            .ok_or(DiscoveryError::ResourceLimit)
    }

    /// Begins Kademlia bootstrap using every currently known routing peer.
    ///
    /// # Errors
    ///
    /// Returns an error when no bootstrap peer is known or Kademlia rejects the query.
    pub fn bootstrap(&mut self) -> Result<kad::QueryId, DiscoveryError> {
        self.swarm
            .behaviour_mut()
            .kademlia
            .bootstrap()
            .map_err(|error| DiscoveryError::Swarm(error.to_string()))
    }

    /// Sets the short-lived signed advertisement served by an enabled role path.
    ///
    /// # Errors
    ///
    /// Returns an error when the local role cannot serve advertisements or the
    /// envelope is not a canonical signed v4 node advertisement.
    pub fn set_local_advertisement(&mut self, envelope: Vec<u8>) -> Result<(), DiscoveryError> {
        if !self.protocol_roles.relay() && !self.protocol_roles.exit() {
            return Err(DiscoveryError::ProtocolRole);
        }
        AdvertisementResponse::new(envelope.clone())?;
        self.preselection_responder
            .install_local_advertisement(&mut self.local_advertisement, envelope);
        Ok(())
    }

    /// Stops serving a previously configured local advertisement immediately.
    pub fn clear_local_advertisement(&mut self) {
        self.preselection_responder
            .clear_local_advertisements(&mut self.local_advertisement);
    }

    /// Reports whether a signed local advertisement is installed.
    #[must_use]
    pub fn is_serving_local_advertisement(&self) -> bool {
        self.local_advertisement.is_some()
    }

    /// Requests a selected relay's current signed advertisement.
    ///
    /// Concurrent requests to one peer are deduplicated and the total number of outstanding
    /// requests is fixed. Exit advertisements use the forwarding hops instead; callers must
    /// verify that a successful direct response advertises the relay role.
    ///
    /// # Errors
    ///
    /// Returns an error when neither client nor exit role is enabled, the target is local,
    /// or the outstanding-request budget is exhausted.
    pub fn request_relay_advertisement(
        &mut self,
        peer_id: &PeerId,
    ) -> Result<request_response::OutboundRequestId, DiscoveryError> {
        if !self.protocol_roles.client() && !self.protocol_roles.exit() {
            return Err(DiscoveryError::ProtocolRole);
        }
        if *peer_id == *self.local_peer_id() {
            return Err(DiscoveryError::ProtocolPeer);
        }
        let swarm = &mut self.swarm;
        self.advertisement_budgets
            .outbound_request_or_insert(peer_id, || {
                swarm
                    .behaviour_mut()
                    .advertisements
                    .send_request(peer_id, AdvertisementRequest::new())
            })
            .ok_or(DiscoveryError::ResourceLimit)
    }

    /// Sends one canonical client hop to the selected control relay.
    ///
    /// This API cannot dial the exit: the authenticated transport target must
    /// equal the control-relay identity embedded in the wrapper.
    ///
    /// # Errors
    ///
    /// Returns an error for a disabled client role, invalid frame, self-target,
    /// or wrapper/transport peer mismatch.
    pub fn request_exit_forward(
        &mut self,
        control_relay_peer: &PeerId,
        request: ExitForwardRequest,
    ) -> Result<request_response::OutboundRequestId, DiscoveryError> {
        if !self.protocol_roles.client() {
            return Err(DiscoveryError::ProtocolRole);
        }
        request.validate()?;
        let wrapper_relay = peer_id_from_wire(request.control_relay_peer_id())?;
        let wrapper_exit = peer_id_from_wire(request.exit_peer_id())?;
        if wrapper_relay != *control_relay_peer
            || wrapper_relay == *self.local_peer_id()
            || wrapper_exit == *self.local_peer_id()
        {
            return Err(DiscoveryError::ProtocolPeer);
        }
        Ok(self
            .swarm
            .behaviour_mut()
            .exit_forward
            .send_request(control_relay_peer, request))
    }

    /// Sends a canonical control-relay response to the authenticated client.
    ///
    /// # Errors
    ///
    /// Returns an error for a disabled relay role, invalid response, local exit
    /// identity, or a closed response channel.
    pub fn send_exit_forward_response(
        &mut self,
        channel: request_response::ResponseChannel<ExitForwardResponse>,
        response: ExitForwardResponse,
    ) -> Result<(), DiscoveryError> {
        if !self.protocol_roles.relay() {
            return Err(DiscoveryError::ProtocolRole);
        }
        response.validate()?;
        if peer_id_from_wire(response.exit_peer_id())? == *self.local_peer_id() {
            return Err(DiscoveryError::ProtocolPeer);
        }
        self.swarm
            .behaviour_mut()
            .exit_forward
            .send_response(channel, response)
            .map_err(|_| DiscoveryError::Swarm("exit-forward response channel closed".into()))
    }

    /// Sends one unchanged forwarding wrapper from this control relay to the exit.
    ///
    /// # Errors
    ///
    /// Returns an error for a disabled relay role, invalid frame, non-local
    /// control-relay provenance, direct/self target, or peer mismatch.
    pub fn request_exit_forward_upstream(
        &mut self,
        exit_peer: &PeerId,
        request: UpstreamExitForwardRequest,
    ) -> Result<request_response::OutboundRequestId, DiscoveryError> {
        if !self.protocol_roles.relay() {
            return Err(DiscoveryError::ProtocolRole);
        }
        request.validate()?;
        let canonical = request.as_forward_request();
        let wrapper_relay = peer_id_from_wire(canonical.control_relay_peer_id())?;
        let wrapper_exit = peer_id_from_wire(canonical.exit_peer_id())?;
        if wrapper_relay != *self.local_peer_id()
            || wrapper_exit != *exit_peer
            || wrapper_exit == *self.local_peer_id()
        {
            return Err(DiscoveryError::ProtocolPeer);
        }
        Ok(self
            .swarm
            .behaviour_mut()
            .exit_forward_upstream
            .send_request(exit_peer, request))
    }

    /// Bind one native-Permit request to the exact authenticated inbound control connection.
    ///
    /// This is control-plane provenance only. It deliberately permits multiple peer connections
    /// and relayed libp2p connectivity and grants no native-address or datapath authority.
    ///
    /// # Errors
    ///
    /// Returns an error for a disabled Exit role, a self connection, or stale, closed, foreign,
    /// or otherwise untracked connection lineage.
    pub fn bind_native_probe_control_connection(
        &self,
        authenticated_control_relay: PeerId,
        connection_id: libp2p::swarm::ConnectionId,
    ) -> Result<BoundNativeProbeControlConnection, DiscoveryError> {
        if !self.protocol_roles.exit() {
            return Err(DiscoveryError::ProtocolRole);
        }
        if authenticated_control_relay == *self.local_peer_id() {
            return Err(DiscoveryError::ProtocolPeer);
        }
        self.swarm
            .behaviour()
            .connection_provenance
            .bind_native_probe_control(authenticated_control_relay, connection_id)
            .ok_or(DiscoveryError::ProtocolPeer)
    }

    /// Bind the exact authenticated data-Relay connection carrying a native authorization chain.
    ///
    /// This is distinct from control-Relay Permit provenance and grants no datapath authority.
    /// The affine token can be consumed only while replying through this service.
    ///
    /// # Errors
    ///
    /// Returns an error for a disabled Exit role, self connection, or stale, closed, foreign, or
    /// otherwise untracked connection lineage.
    pub fn bind_native_probe_data_relay_connection(
        &self,
        authenticated_data_relay: PeerId,
        connection_id: libp2p::swarm::ConnectionId,
    ) -> Result<BoundNativeProbeDataRelayConnection, DiscoveryError> {
        if !self.protocol_roles.exit() {
            return Err(DiscoveryError::ProtocolRole);
        }
        if authenticated_data_relay == *self.local_peer_id() {
            return Err(DiscoveryError::ProtocolPeer);
        }
        self.swarm
            .behaviour()
            .connection_provenance
            .bind_native_probe_data_relay(authenticated_data_relay, connection_id)
            .ok_or(DiscoveryError::ProtocolPeer)
    }

    /// Sends one canonical exit response to the authenticated control relay.
    ///
    /// # Errors
    ///
    /// Returns an error for a disabled exit role, invalid response, non-local
    /// exit identity, or a closed response channel.
    pub fn send_exit_forward_upstream_response(
        &mut self,
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
        response: UpstreamExitForwardResponse,
    ) -> Result<(), DiscoveryError> {
        if !self.protocol_roles.exit() {
            return Err(DiscoveryError::ProtocolRole);
        }
        response.validate()?;
        if peer_id_from_wire(response.as_forward_response().exit_peer_id())?
            != *self.local_peer_id()
        {
            return Err(DiscoveryError::ProtocolPeer);
        }
        self.swarm
            .behaviour_mut()
            .exit_forward_upstream
            .send_response(channel, response)
            .map_err(|_| {
                DiscoveryError::Swarm("exit-forward-upstream response channel closed".into())
            })
    }

    /// Consume exact authenticated connection lineage while handing one native Permit response
    /// back to the originating request-response channel.
    ///
    /// # Errors
    ///
    /// Returns an error for a disabled Exit role, a non-native-Permit response, stale connection
    /// lineage, non-local Exit identity, or a closed response channel.
    pub fn send_native_probe_permit_response(
        &mut self,
        connection: BoundNativeProbeControlConnection,
        authenticated_control_relay: PeerId,
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
        response: UpstreamExitForwardResponse,
    ) -> Result<(), DiscoveryError> {
        if !self.protocol_roles.exit() {
            return Err(DiscoveryError::ProtocolRole);
        }
        response.validate()?;
        let canonical = response.as_forward_response();
        if canonical.validated_operation()? != ExitForwardOperation::NativeProbePermit
            || peer_id_from_wire(canonical.exit_peer_id())? != *self.local_peer_id()
            || !self
                .swarm
                .behaviour()
                .connection_provenance
                .consume_bound_native_probe_control(connection, authenticated_control_relay)
        {
            return Err(DiscoveryError::ProtocolPeer);
        }
        self.swarm
            .behaviour_mut()
            .exit_forward_upstream
            .send_response(channel, response)
            .map_err(|_| {
                DiscoveryError::Swarm("native-probe Permit response channel closed".into())
            })
    }

    /// Consume exact authenticated data-Relay lineage while returning one native authorization.
    ///
    /// # Errors
    ///
    /// Returns an error for a disabled Exit role, a non-authorization response, stale connection
    /// lineage, non-local Exit identity, or a closed response channel.
    pub fn send_native_probe_authorization_response(
        &mut self,
        connection: BoundNativeProbeDataRelayConnection,
        authenticated_data_relay: PeerId,
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
        response: UpstreamExitForwardResponse,
    ) -> Result<(), DiscoveryError> {
        if !self.protocol_roles.exit() {
            return Err(DiscoveryError::ProtocolRole);
        }
        response.validate()?;
        let canonical = response.as_forward_response();
        if canonical.validated_operation()? != ExitForwardOperation::NativeProbeAuthorize
            || peer_id_from_wire(canonical.exit_peer_id())? != *self.local_peer_id()
            || !self
                .swarm
                .behaviour()
                .connection_provenance
                .consume_bound_native_probe_data_relay(connection, authenticated_data_relay)
        {
            return Err(DiscoveryError::ProtocolPeer);
        }
        self.swarm
            .behaviour_mut()
            .exit_forward_upstream
            .send_response(channel, response)
            .map_err(|_| {
                DiscoveryError::Swarm("native-probe authorization response channel closed".into())
            })
    }

    /// Consume exact authenticated data-Relay lineage while returning one native Exit result.
    ///
    /// # Errors
    ///
    /// Returns an error for a disabled Exit role, a non-result response, stale connection
    /// lineage, non-local Exit identity, or a closed response channel.
    pub fn send_native_probe_result_response(
        &mut self,
        connection: BoundNativeProbeDataRelayConnection,
        authenticated_data_relay: PeerId,
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
        response: UpstreamExitForwardResponse,
    ) -> Result<(), DiscoveryError> {
        if !self.protocol_roles.exit() {
            return Err(DiscoveryError::ProtocolRole);
        }
        response.validate()?;
        let canonical = response.as_forward_response();
        if canonical.validated_operation()? != ExitForwardOperation::NativeProbeResult
            || peer_id_from_wire(canonical.exit_peer_id())? != *self.local_peer_id()
            || !self
                .swarm
                .behaviour()
                .connection_provenance
                .consume_bound_native_probe_data_relay(connection, authenticated_data_relay)
        {
            return Err(DiscoveryError::ProtocolPeer);
        }
        self.swarm
            .behaviour_mut()
            .exit_forward_upstream
            .send_response(channel, response)
            .map_err(|_| {
                DiscoveryError::Swarm("native-probe result response channel closed".into())
            })
    }

    /// Consume exact authenticated data-Relay lineage while returning one native Exit readiness.
    ///
    /// # Errors
    ///
    /// Returns an error for a disabled Exit role, a non-readiness response, stale connection
    /// lineage, non-local Exit identity, or a closed response channel.
    pub fn send_native_probe_ready_response(
        &mut self,
        connection: BoundNativeProbeDataRelayConnection,
        authenticated_data_relay: PeerId,
        channel: request_response::ResponseChannel<UpstreamExitForwardResponse>,
        response: UpstreamExitForwardResponse,
    ) -> Result<(), DiscoveryError> {
        if !self.protocol_roles.exit() {
            return Err(DiscoveryError::ProtocolRole);
        }
        response.validate()?;
        let canonical = response.as_forward_response();
        if canonical.validated_operation()? != ExitForwardOperation::NativeProbeReady
            || peer_id_from_wire(canonical.exit_peer_id())? != *self.local_peer_id()
            || !self
                .swarm
                .behaviour()
                .connection_provenance
                .consume_bound_native_probe_data_relay(connection, authenticated_data_relay)
        {
            return Err(DiscoveryError::ProtocolPeer);
        }
        self.swarm
            .behaviour_mut()
            .exit_forward_upstream
            .send_response(channel, response)
            .map_err(|_| DiscoveryError::Swarm("native-probe Ready response channel closed".into()))
    }

    /// Sends one canonical request directly to a selected datapath relay.
    ///
    /// # Errors
    ///
    /// Returns an error for a disabled client role, invalid frame, self-target,
    /// or wrapper/transport peer mismatch.
    pub fn request_datapath_relay(
        &mut self,
        relay_peer: &PeerId,
        request: DatapathRelayRequest,
    ) -> Result<request_response::OutboundRequestId, DiscoveryError> {
        if !self.protocol_roles.client() {
            return Err(DiscoveryError::ProtocolRole);
        }
        request.validate()?;
        let wrapper_relay = peer_id_from_wire(request.relay_peer_id())?;
        if wrapper_relay != *relay_peer || wrapper_relay == *self.local_peer_id() {
            return Err(DiscoveryError::ProtocolPeer);
        }
        Ok(self
            .swarm
            .behaviour_mut()
            .datapath_relay
            .send_request(relay_peer, request))
    }

    /// Sends one canonical datapath-relay response to the authenticated client.
    ///
    /// # Errors
    ///
    /// Returns an error for a disabled relay role, invalid response, non-local
    /// relay identity, or a closed response channel.
    pub fn send_datapath_relay_response(
        &mut self,
        channel: request_response::ResponseChannel<DatapathRelayResponse>,
        response: DatapathRelayResponse,
    ) -> Result<(), DiscoveryError> {
        if !self.protocol_roles.relay() {
            return Err(DiscoveryError::ProtocolRole);
        }
        response.validate()?;
        if peer_id_from_wire(response.relay_peer_id())? != *self.local_peer_id() {
            return Err(DiscoveryError::ProtocolPeer);
        }
        self.swarm
            .behaviour_mut()
            .datapath_relay
            .send_response(channel, response)
            .map_err(|_| DiscoveryError::Swarm("datapath-relay response channel closed".into()))
    }

    /// Advances the real libp2p swarm and performs safe automatic protocol plumbing.
    ///
    /// Inbound preselection request events are service-owned and dropped. Responses for the exact
    /// active outbound dispatch are sealed into opaque arrivals whose private instance identity
    /// and arrival clocks are captured here; stale or unowned responses are dropped. Thus neither
    /// raw request nor raw response messages cross the `DiscoveryService` boundary. Call
    /// [`Self::next_event_with_preselection_responders`] to enable the role-gated direct-Relay and
    /// upstream-Exit responders.
    pub async fn next_event(&mut self) -> DiscoveryEvent {
        // The generic pump cannot complete a role/policy-bound Relay forward. Cancel its affine
        // owner before consuming or sanitising any later upstream response.
        self.cancel_preselection_forwarding();
        loop {
            let event = self.next_internal_event().await;
            if let Some(event) = self.sanitize_public_event(event) {
                return event;
            }
        }
    }

    fn sanitize_public_event(
        &self,
        event: libp2p::swarm::SwarmEvent<BehaviourEvent>,
    ) -> Option<DiscoveryEvent> {
        match event {
            libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::PreselectionObservation(
                request_response::Event::Message {
                    peer,
                    connection_id,
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                },
            )) => self
                .seal_client_preselection_response(peer, connection_id, request_id, response)
                .ok()
                .map(DiscoveryEvent::ClientPreselectionResponse),
            libp2p::swarm::SwarmEvent::Behaviour(
                BehaviourEvent::PreselectionObservationUpstream(request_response::Event::Message {
                    peer,
                    connection_id,
                    message:
                        request_response::Message::Response {
                            request_id,
                            response,
                        },
                }),
            ) => self
                .seal_upstream_preselection_response(peer, connection_id, request_id, response)
                .ok()
                .map(DiscoveryEvent::UpstreamPreselectionResponse),
            event if inbound_preselection_request(&event) => None,
            event => Some(DiscoveryEvent::Other(event)),
        }
    }

    /// Private event pump for service-owned protocol handlers and transport-only unit proofs.
    ///
    /// Unlike [`Self::next_event`], this may yield inbound preselection request channels and raw
    /// outbound preselection responses. It must therefore never become a public API or be called
    /// by application owners.
    #[allow(clippy::too_many_lines, reason = "single composed swarm event pump")]
    async fn next_internal_event(&mut self) -> libp2p::swarm::SwarmEvent<BehaviourEvent> {
        loop {
            let event = self.swarm.select_next_some().await;
            match event {
                libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Advertisements(
                    request_response::Event::Message {
                        peer,
                        message:
                            request_response::Message::Request {
                                request, channel, ..
                            },
                        ..
                    },
                )) => {
                    if self.protocol_roles.relay()
                        && self
                            .advertisement_budgets
                            .allow_inbound_request(peer, Instant::now())
                        && request.validate().is_ok()
                    {
                        if let Some(envelope) = self.local_advertisement.clone() {
                            if let Ok(response) = AdvertisementResponse::new(envelope) {
                                let _ = self
                                    .swarm
                                    .behaviour_mut()
                                    .advertisements
                                    .send_response(channel, response);
                            }
                        }
                    }
                }
                libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::DatapathRelay(
                    request_response::Event::Message {
                        peer,
                        connection_id,
                        message:
                            request_response::Message::Request {
                                request_id,
                                request,
                                channel,
                            },
                    },
                )) => {
                    if !self.protocol_roles.relay()
                        || !datapath_request_targets_local_relay(&request, self.local_peer_id())
                    {
                        continue;
                    }
                    if request.validated_operation() == Ok(DatapathRelayOperation::ExecuteProbe) {
                        if let Ok(response) = DatapathRelayResponse::unavailable(
                            request.request_id().to_vec(),
                            DatapathRelayOperation::ExecuteProbe,
                            request.relay_node_id().to_vec(),
                            request.relay_peer_id().to_vec(),
                        ) {
                            let _ = self.send_datapath_relay_response(channel, response);
                        }
                        continue;
                    }
                    return libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::DatapathRelay(
                        request_response::Event::Message {
                            peer,
                            connection_id,
                            message: request_response::Message::Request {
                                request_id,
                                request,
                                channel,
                            },
                        },
                    ));
                }
                event => {
                    match &event {
                        libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::ExitForward(
                            request_response::Event::Message {
                                message: request_response::Message::Request { request, .. },
                                ..
                            },
                        )) if !forward_request_targets_local_relay(
                            request,
                            self.local_peer_id(),
                        ) =>
                        {
                            continue;
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(
                            BehaviourEvent::ExitForwardUpstream(request_response::Event::Message {
                                peer,
                                message: request_response::Message::Request { request, .. },
                                ..
                            }),
                        ) if !upstream_request_has_authenticated_relay(
                            request,
                            peer,
                            self.local_peer_id(),
                        ) =>
                        {
                            continue;
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(
                            BehaviourEvent::PreselectionObservation(
                                request_response::Event::Message {
                                    peer,
                                    message: request_response::Message::Request { request, .. },
                                    ..
                                },
                            ),
                        ) if !client_request_has_local_target_from_distinct_sender(
                            request,
                            peer,
                            self.local_peer_id(),
                        ) =>
                        {
                            continue;
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(
                            BehaviourEvent::PreselectionObservationUpstream(
                                request_response::Event::Message {
                                    peer,
                                    message: request_response::Message::Request { request, .. },
                                    ..
                                },
                            ),
                        ) if !upstream_request_has_authenticated_target(
                            request,
                            peer,
                            self.local_peer_id(),
                        ) =>
                        {
                            continue;
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
                            kad::Event::OutboundQueryProgressed { id, step, .. },
                        )) if step.last => {
                            self.advertisement_budgets.finish_provider_query(*id);
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Kademlia(
                            kad::Event::RoutingUpdated {
                                peer, addresses, ..
                            },
                        )) => {
                            self.enforce_kademlia_routing_addresses(*peer, addresses);
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Advertisements(
                            request_response::Event::Message {
                                peer,
                                message: request_response::Message::Response { request_id, .. },
                                ..
                            }
                            | request_response::Event::OutboundFailure {
                                peer, request_id, ..
                            },
                        )) => {
                            self.advertisement_budgets
                                .finish_outbound_request(peer, *request_id);
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Mdns(
                            mdns::Event::Discovered(peers),
                        )) => {
                            for (peer, address) in
                                bounded_prefix(peers, MAX_DISCOVERY_ADDRESSES_PER_EVENT)
                            {
                                let _ =
                                    self.add_kademlia_address(*peer, address, AddressSource::Mdns);
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Mdns(
                            mdns::Event::Expired(peers),
                        )) => {
                            for (peer, address) in
                                bounded_prefix(peers, MAX_DISCOVERY_ADDRESSES_PER_EVENT)
                            {
                                self.withdraw_kademlia_address(*peer, address, AddressSource::Mdns);
                            }
                        }
                        libp2p::swarm::SwarmEvent::Behaviour(BehaviourEvent::Identify(
                            identify::Event::Received { peer_id, info, .. },
                        )) => {
                            self.refresh_identify_addresses(*peer_id, info);
                        }
                        _ => {}
                    }
                    return event;
                }
            }
        }
    }
}

fn inbound_preselection_request(event: &libp2p::swarm::SwarmEvent<BehaviourEvent>) -> bool {
    matches!(
        event,
        libp2p::swarm::SwarmEvent::Behaviour(
            BehaviourEvent::PreselectionObservation(request_response::Event::Message {
                message: request_response::Message::Request { .. },
                ..
            }) | BehaviourEvent::PreselectionObservationUpstream(
                request_response::Event::Message {
                    message: request_response::Message::Request { .. },
                    ..
                }
            )
        )
    )
}

fn forward_request_targets_local_relay(request: &ExitForwardRequest, local_peer: &PeerId) -> bool {
    peer_id_from_wire(request.control_relay_peer_id()).is_ok_and(|peer| peer == *local_peer)
}

fn upstream_request_has_authenticated_relay(
    request: &UpstreamExitForwardRequest,
    authenticated_peer: &PeerId,
    local_peer: &PeerId,
) -> bool {
    let request = request.as_forward_request();
    peer_id_from_wire(request.control_relay_peer_id()).is_ok_and(|peer| peer == *authenticated_peer)
        && peer_id_from_wire(request.exit_peer_id()).is_ok_and(|peer| peer == *local_peer)
}

fn datapath_request_targets_local_relay(
    request: &DatapathRelayRequest,
    local_peer: &PeerId,
) -> bool {
    peer_id_from_wire(request.relay_peer_id()).is_ok_and(|peer| peer == *local_peer)
}

fn peer_id_from_wire(value: &[u8]) -> Result<PeerId, DiscoveryError> {
    PeerId::from_bytes(value).map_err(|_| DiscoveryError::ProtocolPeer)
}

fn bounded_prefix<T>(values: &[T], maximum: usize) -> &[T] {
    &values[..values.len().min(maximum)]
}

fn prepare_discovery_address(
    local_peer_id: &PeerId,
    peer_id: PeerId,
    address: &Multiaddr,
) -> Result<Multiaddr, DiscoveryError> {
    if peer_id == *local_peer_id
        || address.is_empty()
        || address.len() > MAX_DISCOVERY_ADDRESS_BYTES
    {
        return Err(DiscoveryError::PeerAddress);
    }
    let canonical = address
        .clone()
        .with_p2p(peer_id)
        .map_err(|_| DiscoveryError::PeerAddress)?;
    if canonical.len() > MAX_DISCOVERY_ADDRESS_BYTES
        || !supported_discovery_address_shape(&canonical, peer_id)
    {
        return Err(DiscoveryError::PeerAddress);
    }
    Ok(canonical)
}

fn supported_discovery_address_shape(address: &Multiaddr, expected_peer: PeerId) -> bool {
    use libp2p::multiaddr::Protocol;

    let protocols = address.iter().collect::<Vec<_>>();
    match protocols.as_slice() {
        [Protocol::Memory(_), Protocol::P2p(peer)] => *peer == expected_peer,
        [host, Protocol::Tcp(port), Protocol::P2p(peer)] => {
            supported_network_host(host) && *port != 0 && *peer == expected_peer
        }
        [
            host,
            Protocol::Udp(port),
            Protocol::QuicV1,
            Protocol::P2p(peer),
        ] => supported_network_host(host) && *port != 0 && *peer == expected_peer,
        [
            Protocol::Memory(_),
            Protocol::P2p(relay),
            Protocol::P2pCircuit,
            Protocol::P2p(peer),
        ] => *relay != expected_peer && *peer == expected_peer,
        [
            host,
            Protocol::Tcp(port),
            Protocol::P2p(relay),
            Protocol::P2pCircuit,
            Protocol::P2p(peer),
        ]
        | [
            host,
            Protocol::Udp(port),
            Protocol::QuicV1,
            Protocol::P2p(relay),
            Protocol::P2pCircuit,
            Protocol::P2p(peer),
        ] => {
            supported_network_host(host)
                && *port != 0
                && *relay != expected_peer
                && *peer == expected_peer
        }
        _ => false,
    }
}

fn supported_network_host(protocol: &libp2p::multiaddr::Protocol<'_>) -> bool {
    use libp2p::multiaddr::Protocol;

    matches!(
        protocol,
        Protocol::Ip4(_)
            | Protocol::Ip6(_)
            | Protocol::Dns(_)
            | Protocol::Dns4(_)
            | Protocol::Dns6(_)
    )
}

fn identify_supports_private_kademlia(peer_id: PeerId, info: &identify::Info) -> bool {
    info.public_key.to_peer_id() == peer_id
        && info
            .protocols
            .iter()
            .any(|protocol| protocol.as_ref() == KADEMLIA_PROTOCOL)
}

/// Returns whether the canonical envelope's Ed25519 sender derives the authenticated peer ID.
///
/// This establishes identity binding only. Callers must additionally verify the control-message
/// signature, lifetime, replay state and typed payload with `volparossa-protocol`.
#[must_use]
pub fn signed_envelope_matches_peer(envelope: &[u8], peer_id: &PeerId) -> bool {
    if envelope.is_empty() || envelope.len() > MAX_CONTROL_MESSAGE_SIZE {
        return false;
    }
    let Ok(envelope) = decode_canonical::<SignedEnvelope>(envelope, MAX_CONTROL_MESSAGE_SIZE)
    else {
        return false;
    };
    let Ok(public_key) = identity::ed25519::PublicKey::try_from_bytes(&envelope.sender_public_key)
    else {
        return false;
    };
    if envelope.sender_id != node_id_from_public_key(&public_key.to_bytes()) {
        return false;
    }
    identity::PublicKey::from(public_key).to_peer_id() == *peer_id
}

fn validate_capability_key(value: &str) -> Result<(), DiscoveryError> {
    if value.len() > 160
        || !value.starts_with("/volparossa/v1/provider/")
        || !value.bytes().all(|byte| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'/' | b'-' | b'_')
        })
    {
        return Err(DiscoveryError::Capability);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_and_bootstrap_roles_are_private_kademlia_servers() {
        assert_eq!(
            kademlia_mode_for_roles(DiscoveryProtocolRoles::new(true, false, false)),
            kad::Mode::Client
        );
        for roles in [
            DiscoveryProtocolRoles::new(false, true, false),
            DiscoveryProtocolRoles::new(false, false, true),
            DiscoveryProtocolRoles::new(false, false, false),
            DiscoveryProtocolRoles::new(true, true, true),
        ] {
            assert_eq!(kademlia_mode_for_roles(roles), kad::Mode::Server);
        }
    }

    #[test]
    fn advertisement_protocol_matrix_never_serves_an_exit_only_node_directly() {
        assert_eq!(
            advertisement_protocol_directions(DiscoveryProtocolRoles::new(true, false, false)),
            (true, false)
        );
        assert_eq!(
            advertisement_protocol_directions(DiscoveryProtocolRoles::new(false, true, false)),
            (false, true)
        );
        assert_eq!(
            advertisement_protocol_directions(DiscoveryProtocolRoles::new(false, false, true)),
            (true, false)
        );
        assert_eq!(
            advertisement_protocol_directions(DiscoveryProtocolRoles::new(true, true, true)),
            (true, true)
        );
    }

    #[test]
    fn preselection_protocol_matrix_is_exact_for_all_role_combinations() {
        let matrix = [
            ((false, false, false), ((false, false), (false, false))),
            ((true, false, false), ((true, false), (false, false))),
            ((false, true, false), ((false, true), (true, false))),
            ((false, false, true), ((false, false), (false, true))),
            ((true, true, false), ((true, true), (true, false))),
            ((true, false, true), ((true, false), (false, true))),
            ((false, true, true), ((false, true), (true, true))),
            ((true, true, true), ((true, true), (true, true))),
        ];
        for ((client, relay, exit), (client_hop, upstream)) in matrix {
            let roles = DiscoveryProtocolRoles::new(client, relay, exit);
            assert_eq!(client_preselection_protocol_directions(roles), client_hop);
            assert_eq!(upstream_preselection_protocol_directions(roles), upstream);
        }
    }

    #[test]
    fn only_private_capability_namespace_is_accepted() {
        assert!(validate_capability_key(capability::RELAY).is_ok());
        assert!(validate_capability_key("/ipfs/provider/all").is_err());
        assert!(validate_capability_key("/volparossa/v1/provider/relay\0evil").is_err());
    }

    #[test]
    fn region_keys_are_canonical_and_bounded() {
        assert_eq!(
            capability::region("relay", "eu-west").as_deref(),
            Some("/volparossa/v1/provider/relay/eu-west")
        );
        assert!(capability::region("exit", "EU West").is_none());
    }

    fn test_address(port: u16) -> Multiaddr {
        format!("/ip4/192.0.2.10/tcp/{port}")
            .parse()
            .expect("test multiaddr")
    }

    fn identify_info(
        keypair: &identity::Keypair,
        protocols: Vec<StreamProtocol>,
    ) -> identify::Info {
        identify::Info {
            public_key: keypair.public(),
            protocol_version: "/volparossa/1.0.0".into(),
            agent_version: "volparossa/test".into(),
            listen_addrs: vec![test_address(4_001)],
            protocols,
            observed_addr: test_address(4_002),
            signed_peer_record: None,
        }
    }

    #[test]
    fn untrusted_event_prefix_is_strictly_bounded() {
        let values: Vec<usize> = (0..MAX_DISCOVERY_ADDRESSES_PER_EVENT + 5).collect();
        assert_eq!(
            bounded_prefix(&values, MAX_DISCOVERY_ADDRESSES_PER_EVENT).len(),
            MAX_DISCOVERY_ADDRESSES_PER_EVENT
        );
        assert!(bounded_prefix(&values, 0).is_empty());
    }

    #[test]
    fn discovery_addresses_are_peer_bound_nonempty_and_bounded() {
        let local = identity::Keypair::generate_ed25519().public().to_peer_id();
        let remote = identity::Keypair::generate_ed25519().public().to_peer_id();
        let other = identity::Keypair::generate_ed25519().public().to_peer_id();
        let address = test_address(4_001);
        assert!(prepare_discovery_address(&local, remote, &address).is_ok());
        let quic: Multiaddr = "/ip6/2001:db8::10/udp/4001/quic-v1"
            .parse()
            .expect("QUIC address");
        assert!(prepare_discovery_address(&local, remote, &quic).is_ok());
        let relay: Multiaddr = format!("/ip4/192.0.2.11/tcp/4001/p2p/{other}/p2p-circuit")
            .parse()
            .expect("Circuit Relay address");
        assert!(prepare_discovery_address(&local, remote, &relay).is_ok());

        let unsupported_udp: Multiaddr = "/ip4/192.0.2.10/udp/4001"
            .parse()
            .expect("unsupported UDP address");
        assert!(matches!(
            prepare_discovery_address(&local, remote, &unsupported_udp),
            Err(DiscoveryError::PeerAddress)
        ));
        let zero_port: Multiaddr = "/ip4/192.0.2.10/tcp/0".parse().expect("zero-port address");
        assert!(matches!(
            prepare_discovery_address(&local, remote, &zero_port),
            Err(DiscoveryError::PeerAddress)
        ));
        assert!(matches!(
            prepare_discovery_address(&local, local, &address),
            Err(DiscoveryError::PeerAddress)
        ));
        assert!(matches!(
            prepare_discovery_address(&local, remote, &Multiaddr::empty()),
            Err(DiscoveryError::PeerAddress)
        ));

        let mismatch: Multiaddr = format!("/ip4/192.0.2.10/tcp/4001/p2p/{other}")
            .parse()
            .expect("mismatched identity address");
        assert!(matches!(
            prepare_discovery_address(&local, remote, &mismatch),
            Err(DiscoveryError::PeerAddress)
        ));
        let nonterminal: Multiaddr = format!("/ip4/192.0.2.10/tcp/4001/p2p/{remote}/tcp/4002")
            .parse()
            .expect("nonterminal identity address");
        assert!(matches!(
            prepare_discovery_address(&local, remote, &nonterminal),
            Err(DiscoveryError::PeerAddress)
        ));

        let mut oversized = Multiaddr::empty();
        while oversized.len() <= MAX_DISCOVERY_ADDRESS_BYTES {
            oversized.push(libp2p::multiaddr::Protocol::P2pCircuit);
        }
        assert!(matches!(
            prepare_discovery_address(&local, remote, &oversized),
            Err(DiscoveryError::PeerAddress)
        ));
    }

    #[test]
    fn address_admission_caps_and_reclaims_without_cross_source_removal() {
        let local = identity::Keypair::generate_ed25519().public().to_peer_id();
        let remote = identity::Keypair::generate_ed25519().public().to_peer_id();
        let peer_two = identity::Keypair::generate_ed25519().public().to_peer_id();
        let peer_three = identity::Keypair::generate_ed25519().public().to_peer_id();
        let first =
            prepare_discovery_address(&local, remote, &test_address(4_001)).expect("first address");
        let second = prepare_discovery_address(&local, remote, &test_address(4_002))
            .expect("second address");
        let third =
            prepare_discovery_address(&local, remote, &test_address(4_003)).expect("third address");
        let mut admissions = AddressAdmissions::new(2, 2);

        assert!(
            admissions
                .admit_prepared(remote, first.clone(), AddressSource::Known)
                .expect("first admission")
        );
        assert!(
            !admissions
                .admit_prepared(remote, first.clone(), AddressSource::Mdns)
                .expect("duplicate source admission")
        );
        assert!(
            admissions
                .admit_prepared(remote, second, AddressSource::Mdns)
                .expect("second admission")
        );
        assert!(matches!(
            admissions.admit_prepared(remote, third.clone(), AddressSource::Identify),
            Err(DiscoveryError::ResourceLimit)
        ));
        assert_eq!(
            admissions.withdraw_prepared(remote, &first, AddressSource::Mdns),
            None
        );
        assert_eq!(
            admissions.withdraw_prepared(remote, &first, AddressSource::Known),
            Some(first)
        );
        assert!(
            admissions
                .admit_prepared(remote, third, AddressSource::Identify)
                .expect("reclaimed per-peer slot")
        );

        let peer_two_address =
            prepare_discovery_address(&local, peer_two, &test_address(5_001)).expect("second peer");
        admissions
            .admit_prepared(peer_two, peer_two_address.clone(), AddressSource::Mdns)
            .expect("second tracked peer");
        let peer_three_address =
            prepare_discovery_address(&local, peer_three, &test_address(6_001))
                .expect("third peer");
        assert!(matches!(
            admissions.admit_prepared(peer_three, peer_three_address.clone(), AddressSource::Mdns),
            Err(DiscoveryError::ResourceLimit)
        ));
        assert_eq!(
            admissions.withdraw_prepared(peer_two, &peer_two_address, AddressSource::Mdns),
            Some(peer_two_address)
        );
        assert!(
            admissions
                .admit_prepared(peer_three, peer_three_address, AddressSource::Mdns)
                .expect("reclaimed peer slot")
        );
    }

    #[test]
    fn identify_admission_requires_authenticated_peer_and_private_kademlia_protocol() {
        let keypair = identity::Keypair::generate_ed25519();
        let peer_id = keypair.public().to_peer_id();
        let supported = identify_info(&keypair, vec![StreamProtocol::new(KADEMLIA_PROTOCOL)]);
        assert!(identify_supports_private_kademlia(peer_id, &supported));
        let other = identity::Keypair::generate_ed25519().public().to_peer_id();
        assert!(!identify_supports_private_kademlia(other, &supported));
        let unsupported =
            identify_info(&keypair, vec![StreamProtocol::new("/volparossa/not-kad/1")]);
        assert!(!identify_supports_private_kademlia(peer_id, &unsupported));
    }
    #[test]
    fn connection_limits_reject_excess_pending_inbound_without_bypasses() {
        let mut behaviour = connection_limits_behaviour();
        let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
        assert!(!behaviour.is_bypassed(&peer));
        let address: Multiaddr = "/memory/4100".parse().expect("memory address");

        for identifier in 0..MAX_PENDING_INBOUND_CONNECTIONS {
            let identifier = usize::try_from(identifier).expect("u32 fits usize");
            assert!(
                NetworkBehaviour::handle_pending_inbound_connection(
                    &mut behaviour,
                    libp2p::swarm::ConnectionId::new_unchecked(identifier),
                    &address,
                    &address,
                )
                .is_ok()
            );
        }
        assert!(
            NetworkBehaviour::handle_pending_inbound_connection(
                &mut behaviour,
                libp2p::swarm::ConnectionId::new_unchecked(usize::MAX),
                &address,
                &address,
            )
            .is_err()
        );
    }
}
