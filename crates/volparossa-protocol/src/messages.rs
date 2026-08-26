use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use prost::Message;
use sha2::{Digest, Sha256};
use volparossa_core::{OperatorId, is_public_routable_ip};

use crate::envelope::fixed_array;
use crate::{
    ControlPayload, MAX_CONTROL_MESSAGE_SIZE, MAX_CONTROL_PAYLOAD_SIZE, PROTOCOL_VERSION,
    ProtocolError, ReplayCache, SignedEnvelope, TimePolicy, VerifiedControlMessage,
    decode_canonical, verify_control_message,
};

const ID_LENGTH: usize = 16;
const HASH_LENGTH: usize = 32;
const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 32;
const MAX_RATE_MBPS: u64 = 1_000_000;
const MAX_RESERVATION_LIFETIME_MS: u64 = 15 * 60 * 1_000;
const MAX_PHASE_LIFETIME_MS: u64 = 30 * 1_000;
const FINALIZED_BUNDLE_DOMAIN: &[u8] = b"volparossa/finalized-reservation-bundle/v4\0";
const CONFIRMATION_ENVELOPE_DOMAIN: &[u8] = b"volparossa/exit-confirmation-envelope/v4\0";
const MAX_ADVERTISEMENT_LIFETIME_MS: u64 = 15 * 60 * 1_000;
const MAX_CONTROL_ADDRESSES: usize = 16;
const MAX_TRANSPORTS: usize = 3;

/// Discriminator for signed v4 control-plane payloads.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, prost::Enumeration)]
#[repr(i32)]
pub enum ControlMessageType {
    Unspecified = 0,
    NodeAdvertisement = 1,
    ExitReservation = 2,
    RelayAuthorization = 3,
    RelayReservation = 4,
    OpenTcp = 5,
    UdpFlowAuthorization = 6,
    /// Client-session-signed intent to hold exit capacity without relay selection.
    ExitCapacityHoldRequest = 7,
    /// Client-signed submission of one exit-authorized relay path.
    RelayReservationRequest = 8,
    /// Client-signed confirmation of one verified relay grant to the exit.
    ExitReservationConfirmation = 9,
    /// Exit-signed proof binding one fresh client session to a bounded scope.
    ClientSessionCapability = 10,
    /// Exit-signed proof that capacity is held without selecting relays.
    ExitCapacityHold = 11,
    /// Client-session-signed request for one relay probe permit.
    RelayProbePermitRequest = 12,
    /// Exit-signed authorization for one bounded relay probe.
    RelayProbePermit = 13,
    /// Relay-signed result for one exact probe permit.
    RelayProbeResult = 14,
    /// Client-session-signed exact relay-set finalization request.
    ExitReservationFinalizeRequest = 15,
    /// Exit-signed positive acknowledgement of one exact relay confirmation.
    ExitConfirmationReceipt = 16,
    /// Actor-signed response to one exact preselection observation challenge.
    PreselectionObservationReceipt = 17,
    /// Control-signed upstream-prefix attestation containing one exact exit receipt.
    ForwardedPreselectionAttestation = 18,
}

/// Data transport authorized by a reservation.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, prost::Enumeration)]
#[repr(i32)]
pub enum Transport {
    Unspecified = 0,
    TcpMptcp = 1,
    UdpSinglePath = 2,
    MultipathQuic = 3,
}

/// Independently enabled node roles.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct AdvertisementRoles {
    #[prost(bool, tag = "1")]
    pub client: bool,
    #[prost(bool, tag = "2")]
    pub relay: bool,
    #[prost(bool, tag = "3")]
    pub exit: bool,
}

/// Advertised dataplane and network capabilities.
#[allow(missing_docs)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "fixed protobuf capability bitmap"
)]
#[derive(Clone, PartialEq, Message)]
pub struct AdvertisementCapabilities {
    #[prost(bool, tag = "1")]
    pub tcp_mptcp: bool,
    #[prost(bool, tag = "2")]
    pub udp_single_path: bool,
    #[prost(bool, tag = "3")]
    pub multipath_quic: bool,
    #[prost(bool, tag = "4")]
    pub ipv4: bool,
    #[prost(bool, tag = "5")]
    pub ipv6: bool,
    #[prost(bool, tag = "6")]
    pub udp_hole_punching: bool,
}

/// Signed route-specific `WireGuard` underlay endpoint.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct WireguardEndpoint {
    #[prost(bytes = "vec", tag = "1")]
    pub public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub underlay_ip: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub listen_port: u32,
}

impl WireguardEndpoint {
    /// Validate the fixed key, publicly routable address and explicit non-zero port.
    ///
    /// # Errors
    ///
    /// Returns an invalid-field error for a zero/incorrect key, non-canonical
    /// IP bytes, an IANA special-purpose/non-public address, or invalid port.
    pub fn validate(&self, field: &'static str) -> Result<(), ProtocolError> {
        require_nonzero_length::<KEY_LENGTH>(&self.public_key, field)?;
        let address =
            parse_ip_bytes(&self.underlay_ip).ok_or(ProtocolError::InvalidField(field))?;
        if !is_public_routable_ip(address) {
            return Err(ProtocolError::InvalidField(field));
        }
        validate_port(self.listen_port, field)
    }
}

/// Bounded capacity statement used only for inexpensive preselection.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct AdvertisementCapacity {
    #[prost(uint64, tag = "1")]
    pub operator_relay_limit_up_mbps: u64,
    #[prost(uint64, tag = "2")]
    pub operator_relay_limit_down_mbps: u64,
    #[prost(uint64, tag = "3")]
    pub operator_exit_limit_up_mbps: u64,
    #[prost(uint64, tag = "4")]
    pub operator_exit_limit_down_mbps: u64,
    #[prost(uint64, tag = "5")]
    pub currently_reserved_up_mbps: u64,
    #[prost(uint64, tag = "6")]
    pub currently_reserved_down_mbps: u64,
    #[prost(uint64, tag = "7")]
    pub estimated_free_up_mbps: u64,
    #[prost(uint64, tag = "8")]
    pub estimated_free_down_mbps: u64,
    #[prost(uint32, tag = "9")]
    pub active_relay_sessions: u32,
    #[prost(uint32, tag = "10")]
    pub active_exit_sessions: u32,
    #[prost(uint32, tag = "11")]
    pub free_relay_slots: u32,
    #[prost(uint32, tag = "12")]
    pub free_exit_slots: u32,
    #[prost(uint32, tag = "13")]
    pub sample_window_seconds: u32,
}

/// Coarse network hints; exact addresses remain in control multiaddresses.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct AdvertisementNetwork {
    #[prost(string, tag = "1")]
    pub region: String,
    #[prost(string, tag = "2")]
    pub country_code: String,
    #[prost(uint32, tag = "3")]
    pub asn: u32,
    #[prost(string, tag = "4")]
    pub ipv4_prefix_hint: String,
    #[prost(string, tag = "5")]
    pub ipv6_prefix_hint: String,
    #[prost(string, tag = "6")]
    pub operator_id: String,
}

/// Locally observed quality claims represented in integer parts per million.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct AdvertisementQuality {
    #[prost(uint64, tag = "1")]
    pub local_uptime_seconds: u64,
    #[prost(uint32, tag = "2")]
    pub historical_uptime_ppm: u32,
    #[prost(uint32, tag = "3")]
    pub historical_delivery_ratio_p25_ppm: u32,
}

/// Whitelist version and hash enforced by the advertising node.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct AdvertisementPolicy {
    #[prost(uint64, tag = "1")]
    pub whitelist_version: u64,
    #[prost(bytes = "vec", tag = "2")]
    pub whitelist_hash: Vec<u8>,
}

/// Signed, short-lived node advertisement fetched directly from a provider.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct NodeAdvertisement {
    #[prost(bytes = "vec", tag = "1")]
    pub node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub peer_id: Vec<u8>,
    #[prost(uint64, tag = "3")]
    pub sequence_number: u64,
    #[prost(message, optional, tag = "4")]
    pub roles: Option<AdvertisementRoles>,
    #[prost(message, optional, tag = "5")]
    pub capabilities: Option<AdvertisementCapabilities>,
    #[prost(string, repeated, tag = "6")]
    pub control_addresses: Vec<String>,
    #[prost(message, optional, tag = "8")]
    pub capacity: Option<AdvertisementCapacity>,
    #[prost(message, optional, tag = "9")]
    pub network: Option<AdvertisementNetwork>,
    #[prost(message, optional, tag = "10")]
    pub quality: Option<AdvertisementQuality>,
    #[prost(message, optional, tag = "11")]
    pub policy: Option<AdvertisementPolicy>,
    #[prost(uint64, tag = "12")]
    pub measured_at_ms: u64,
    #[prost(uint64, tag = "13")]
    pub expires_at_ms: u64,
}

/// Exit-signed finalized capacity and exact relay-set grant.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct ExitReservation {
    #[prost(bytes = "vec", tag = "1")]
    pub reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub exit_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub client_session_id: Vec<u8>,
    // Tag 5 permanently reserved: v2 client_peer_id.
    #[prost(enumeration = "Transport", repeated, tag = "6")]
    pub allowed_transports: Vec<i32>,
    #[prost(uint64, tag = "7")]
    pub reserved_up_mbps: u64,
    #[prost(uint64, tag = "8")]
    pub reserved_down_mbps: u64,
    #[prost(uint32, tag = "9")]
    pub maximum_paths: u32,
    #[prost(bytes = "vec", tag = "10")]
    pub policy_hash: Vec<u8>,
    #[prost(uint64, tag = "11")]
    pub created_at_ms: u64,
    #[prost(uint64, tag = "12")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "13")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "14")]
    pub capability_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "15")]
    pub client_session_public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "16")]
    pub exit_boot_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "17")]
    pub hold_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "18")]
    pub finalize_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "19")]
    pub control_relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "20")]
    pub control_relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "21")]
    pub exit_peer_id: Vec<u8>,
    #[prost(message, optional, tag = "22")]
    pub native_route_identity: Option<NativeRouteIdentity>,
}

/// Exit-signed identity and authentication commitment for one native route.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct NativeRouteIdentity {
    #[prost(bytes = "vec", tag = "1")]
    pub auth_commitment: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub certificate_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub spki_sha256: Vec<u8>,
    #[prost(string, tag = "4")]
    pub tls_server_name: String,
    #[prost(uint64, tag = "5")]
    pub masque_context_id: u64,
    #[prost(bytes = "vec", tag = "6")]
    pub client_native_instance_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub exit_native_instance_id: Vec<u8>,
}

/// Exit-signed authorization for one relay path.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct RelayAuthorization {
    #[prost(bytes = "vec", tag = "1")]
    pub reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub route_context_id: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub path_id: u32,
    #[prost(bytes = "vec", tag = "4")]
    pub relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub exit_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub client_session_id: Vec<u8>,
    // Tag 7 permanently reserved: v2 client_peer_id.
    #[prost(enumeration = "Transport", repeated, tag = "8")]
    pub allowed_transports: Vec<i32>,
    #[prost(uint64, tag = "9")]
    pub maximum_up_mbps: u64,
    #[prost(uint64, tag = "10")]
    pub maximum_down_mbps: u64,
    #[prost(bytes = "vec", tag = "11")]
    pub client_wireguard_public_key: Vec<u8>,
    #[prost(message, optional, tag = "12")]
    pub exit_wireguard_endpoint: Option<WireguardEndpoint>,
    // Tag 13 permanently reserved: retired overlay-prefix material.
    #[prost(bytes = "vec", tag = "14")]
    pub policy_hash: Vec<u8>,
    #[prost(uint64, tag = "15")]
    pub created_at_ms: u64,
    #[prost(uint64, tag = "16")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "17")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "18")]
    pub relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "19")]
    pub capability_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "20")]
    pub client_session_public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "21")]
    pub exit_boot_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "22")]
    pub hold_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "23")]
    pub finalize_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "24")]
    pub control_relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "25")]
    pub control_relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "26")]
    pub exit_peer_id: Vec<u8>,
}

/// Relay-signed acceptance carrying the exit's independently signed grant.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct RelayReservation {
    #[prost(bytes = "vec", tag = "1")]
    pub reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub route_context_id: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub path_id: u32,
    #[prost(bytes = "vec", tag = "4")]
    pub relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub exit_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub client_session_id: Vec<u8>,
    // Tag 7 permanently reserved: v2 client_peer_id.
    #[prost(enumeration = "Transport", repeated, tag = "8")]
    pub allowed_transports: Vec<i32>,
    #[prost(uint64, tag = "9")]
    pub maximum_up_mbps: u64,
    #[prost(uint64, tag = "10")]
    pub maximum_down_mbps: u64,
    #[prost(bytes = "vec", tag = "11")]
    pub client_wireguard_public_key: Vec<u8>,
    #[prost(message, optional, tag = "12")]
    pub relay_client_wireguard_endpoint: Option<WireguardEndpoint>,
    #[prost(message, optional, tag = "13")]
    pub relay_exit_wireguard_endpoint: Option<WireguardEndpoint>,
    #[prost(message, optional, tag = "14")]
    pub exit_wireguard_endpoint: Option<WireguardEndpoint>,
    // Tag 15 permanently reserved: retired overlay-prefix material.
    #[prost(bytes = "vec", tag = "16")]
    pub policy_hash: Vec<u8>,
    #[prost(uint64, tag = "17")]
    pub created_at_ms: u64,
    #[prost(uint64, tag = "18")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "19")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "20")]
    pub exit_authorization: Vec<u8>,
    #[prost(bytes = "vec", tag = "21")]
    pub relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "22")]
    pub capability_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "23")]
    pub client_session_public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "24")]
    pub exit_boot_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "25")]
    pub hold_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "26")]
    pub finalize_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "27")]
    pub control_relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "28")]
    pub control_relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "29")]
    pub exit_peer_id: Vec<u8>,
}

/// Client-session-signed return of one verified relay grant to the selected exit.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct ExitReservationConfirmation {
    #[prost(bytes = "vec", tag = "1")]
    pub reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub route_context_id: Vec<u8>,
    #[prost(uint32, tag = "3")]
    pub path_id: u32,
    #[prost(bytes = "vec", tag = "4")]
    pub relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub exit_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub client_session_id: Vec<u8>,
    // Tag 7 permanently reserved: v2 client_peer_id.
    #[prost(bytes = "vec", tag = "8")]
    pub policy_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub relay_reservation: Vec<u8>,
    #[prost(uint64, tag = "10")]
    pub created_at_ms: u64,
    #[prost(uint64, tag = "11")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "12")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "13")]
    pub capability_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "14")]
    pub client_session_public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "15")]
    pub exit_boot_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "16")]
    pub hold_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "17")]
    pub finalize_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "18")]
    pub control_relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "19")]
    pub control_relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "20")]
    pub exit_peer_id: Vec<u8>,
}

/// Exit-signed positive acknowledgement for one exact confirmation frame.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct ExitConfirmationReceipt {
    #[prost(bytes = "vec", tag = "1")]
    pub reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub client_session_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub capability_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub hold_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub finalize_id: Vec<u8>,
    #[prost(uint32, tag = "7")]
    pub path_id: u32,
    #[prost(bytes = "vec", tag = "8")]
    pub finalized_bundle_hash: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub control_relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "10")]
    pub control_relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "11")]
    pub exit_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "12")]
    pub exit_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "13")]
    pub exit_boot_id: Vec<u8>,
    #[prost(uint64, tag = "14")]
    pub created_at_ms: u64,
    #[prost(uint64, tag = "15")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "16")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "17")]
    pub confirmation_envelope_hash: Vec<u8>,
}
/// Client-signed authorization to open one policy-bound TCP flow.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct OpenTcp {
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub flow_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub client_ephemeral_id: Vec<u8>,
    #[prost(string, tag = "4")]
    pub hostname: String,
    #[prost(uint32, tag = "5")]
    pub port: u32,
    #[prost(bytes = "vec", tag = "6")]
    pub policy_hash: Vec<u8>,
    #[prost(uint64, tag = "7")]
    pub timestamp_ms: u64,
    #[prost(uint64, tag = "8")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "9")]
    pub nonce: Vec<u8>,
}

/// Client-signed authorization pinning one UDP flow to one destination tuple.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct UdpFlowAuthorization {
    #[prost(bytes = "vec", tag = "1")]
    pub route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub flow_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub client_ephemeral_id: Vec<u8>,
    #[prost(string, tag = "4")]
    pub hostname: String,
    #[prost(bytes = "vec", tag = "5")]
    pub destination_ip: Vec<u8>,
    #[prost(uint32, tag = "6")]
    pub port: u32,
    #[prost(bytes = "vec", tag = "7")]
    pub policy_hash: Vec<u8>,
    #[prost(uint32, tag = "8")]
    pub idle_timeout_ms: u32,
    #[prost(uint64, tag = "9")]
    pub timestamp_ms: u64,
    #[prost(uint64, tag = "10")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "11")]
    pub nonce: Vec<u8>,
}

impl ControlPayload for NodeAdvertisement {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::NodeAdvertisement;

    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_length::<HASH_LENGTH>(&self.node_id, "advertisement.node_id")?;
        if self.peer_id.is_empty() || self.peer_id.len() > 64 {
            return Err(ProtocolError::InvalidField("advertisement.peer_id"));
        }
        let roles = self
            .roles
            .as_ref()
            .ok_or(ProtocolError::InvalidField("advertisement.roles"))?;
        if !(roles.client || roles.relay || roles.exit) {
            return Err(ProtocolError::InvalidField("advertisement.roles"));
        }
        let capabilities = self
            .capabilities
            .as_ref()
            .ok_or(ProtocolError::InvalidField("advertisement.capabilities"))?;
        if !(capabilities.ipv4 || capabilities.ipv6)
            || ((roles.relay || roles.exit)
                && !(capabilities.tcp_mptcp
                    || capabilities.udp_single_path
                    || capabilities.multipath_quic))
        {
            return Err(ProtocolError::InvalidField("advertisement.capabilities"));
        }
        validate_control_addresses(&self.control_addresses)?;
        let capacity = self
            .capacity
            .as_ref()
            .ok_or(ProtocolError::InvalidField("advertisement.capacity"))?;
        validate_capacity(capacity, roles)?;
        validate_network(
            self.network
                .as_ref()
                .ok_or(ProtocolError::InvalidField("advertisement.network"))?,
        )?;
        validate_quality(
            self.quality
                .as_ref()
                .ok_or(ProtocolError::InvalidField("advertisement.quality"))?,
        )?;
        let policy = self
            .policy
            .as_ref()
            .ok_or(ProtocolError::InvalidField("advertisement.policy"))?;
        if policy.whitelist_version == 0 {
            return Err(ProtocolError::InvalidField(
                "advertisement.policy.whitelist_version",
            ));
        }
        require_nonzero_length::<HASH_LENGTH>(
            &policy.whitelist_hash,
            "advertisement.policy.whitelist_hash",
        )?;
        validate_lifetime(
            self.measured_at_ms,
            self.expires_at_ms,
            MAX_ADVERTISEMENT_LIFETIME_MS,
            "advertisement lifetime",
        )
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        if self.node_id != envelope.sender_id
            || self.measured_at_ms != envelope.timestamp_ms
            || self.expires_at_ms != envelope.expires_at_ms
        {
            return Err(ProtocolError::InvalidField(
                "advertisement envelope binding",
            ));
        }
        Ok(())
    }
}

impl ControlPayload for ExitReservation {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::ExitReservation;

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_reservation_ids(
            &self.reservation_id,
            &self.route_context_id,
            &self.client_session_id,
        )?;
        require_nonzero_length::<HASH_LENGTH>(&self.exit_node_id, "exit_reservation.exit_node_id")?;
        validate_peer_id(&self.exit_peer_id, "exit_reservation.exit_peer_id")?;
        validate_session_binding(&self.client_session_id, &self.client_session_public_key)?;
        validate_reservation_binding(
            &self.capability_id,
            &self.exit_boot_id,
            &self.hold_id,
            &self.finalize_id,
            &self.control_relay_node_id,
            &self.control_relay_peer_id,
        )?;
        self.native_route_identity
            .as_ref()
            .ok_or(ProtocolError::InvalidField(
                "exit_reservation.native_route_identity",
            ))?
            .validate()?;
        validate_transports(&self.allowed_transports)?;
        validate_rate(self.reserved_up_mbps, "exit_reservation.reserved_up_mbps")?;
        validate_rate(
            self.reserved_down_mbps,
            "exit_reservation.reserved_down_mbps",
        )?;
        if !(1..=8).contains(&self.maximum_paths) {
            return Err(ProtocolError::InvalidField(
                "exit_reservation.maximum_paths",
            ));
        }
        require_nonzero_length::<HASH_LENGTH>(&self.policy_hash, "exit_reservation.policy_hash")?;
        require_nonzero_length::<NONCE_LENGTH>(&self.nonce, "exit_reservation.nonce")?;
        validate_lifetime(
            self.created_at_ms,
            self.expires_at_ms,
            MAX_RESERVATION_LIFETIME_MS,
            "exit_reservation lifetime",
        )
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        validate_signed_fields(
            &self.exit_node_id,
            self.created_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "exit_reservation envelope binding",
        )
    }
}

impl NativeRouteIdentity {
    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_length::<HASH_LENGTH>(
            &self.auth_commitment,
            "native_route_identity.auth_commitment",
        )?;
        require_nonzero_length::<HASH_LENGTH>(
            &self.certificate_sha256,
            "native_route_identity.certificate_sha256",
        )?;
        require_nonzero_length::<HASH_LENGTH>(
            &self.spki_sha256,
            "native_route_identity.spki_sha256",
        )?;
        validate_canonical_dns_name(
            &self.tls_server_name,
            "native_route_identity.tls_server_name",
        )?;
        if self.masque_context_id == 0 || self.masque_context_id > crate::MAX_MASQUE_CONTEXT_ID {
            return Err(ProtocolError::InvalidField(
                "native_route_identity.masque_context_id",
            ));
        }
        require_nonzero_length::<KEY_LENGTH>(
            &self.client_native_instance_id,
            "native_route_identity.client_native_instance_id",
        )?;
        require_nonzero_length::<KEY_LENGTH>(
            &self.exit_native_instance_id,
            "native_route_identity.exit_native_instance_id",
        )?;
        Ok(())
    }
}

impl ControlPayload for RelayAuthorization {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::RelayAuthorization;

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_relay_fields(
            &self.reservation_id,
            &self.route_context_id,
            self.path_id,
            &self.relay_node_id,
            &self.exit_node_id,
            &self.client_session_id,
            &self.relay_peer_id,
            &self.allowed_transports,
            self.maximum_up_mbps,
            self.maximum_down_mbps,
            &self.client_wireguard_public_key,
            self.exit_wireguard_endpoint.as_ref(),
            &self.policy_hash,
            self.created_at_ms,
            self.expires_at_ms,
            &self.nonce,
            &self.capability_id,
            &self.client_session_public_key,
            &self.exit_boot_id,
            &self.hold_id,
            &self.finalize_id,
            &self.control_relay_node_id,
            &self.control_relay_peer_id,
            &self.exit_peer_id,
        )
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        validate_signed_fields(
            &self.exit_node_id,
            self.created_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "relay_authorization envelope binding",
        )
    }
}

impl ControlPayload for RelayReservation {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::RelayReservation;

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_relay_fields(
            &self.reservation_id,
            &self.route_context_id,
            self.path_id,
            &self.relay_node_id,
            &self.exit_node_id,
            &self.client_session_id,
            &self.relay_peer_id,
            &self.allowed_transports,
            self.maximum_up_mbps,
            self.maximum_down_mbps,
            &self.client_wireguard_public_key,
            self.exit_wireguard_endpoint.as_ref(),
            &self.policy_hash,
            self.created_at_ms,
            self.expires_at_ms,
            &self.nonce,
            &self.capability_id,
            &self.client_session_public_key,
            &self.exit_boot_id,
            &self.hold_id,
            &self.finalize_id,
            &self.control_relay_node_id,
            &self.control_relay_peer_id,
            &self.exit_peer_id,
        )?;
        let relay_client =
            self.relay_client_wireguard_endpoint
                .as_ref()
                .ok_or(ProtocolError::InvalidField(
                    "relay_client_wireguard_endpoint",
                ))?;
        relay_client.validate("relay_client_wireguard_endpoint")?;
        let relay_exit = self
            .relay_exit_wireguard_endpoint
            .as_ref()
            .ok_or(ProtocolError::InvalidField("relay_exit_wireguard_endpoint"))?;
        relay_exit.validate("relay_exit_wireguard_endpoint")?;
        let exit = self
            .exit_wireguard_endpoint
            .as_ref()
            .ok_or(ProtocolError::InvalidField("exit_wireguard_endpoint"))?;
        validate_distinct_wireguard_keys(&[
            &self.client_wireguard_public_key,
            &relay_client.public_key,
            &relay_exit.public_key,
            &exit.public_key,
        ])?;
        if relay_client.listen_port == relay_exit.listen_port {
            return Err(ProtocolError::InvalidField("relay unique listen ports"));
        }
        let nested: SignedEnvelope =
            decode_canonical(&self.exit_authorization, MAX_CONTROL_MESSAGE_SIZE)?;
        if nested.message_type != ControlMessageType::RelayAuthorization as i32 {
            return Err(ProtocolError::InvalidField(
                "relay_reservation.exit_authorization type",
            ));
        }
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        validate_signed_fields(
            &self.relay_node_id,
            self.created_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "relay_reservation envelope binding",
        )
    }
}

impl ControlPayload for ExitReservationConfirmation {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::ExitReservationConfirmation;

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_reservation_ids(
            &self.reservation_id,
            &self.route_context_id,
            &self.client_session_id,
        )?;
        if !(1..=8).contains(&self.path_id) {
            return Err(ProtocolError::InvalidField("exit_confirmation.path_id"));
        }
        require_nonzero_length::<HASH_LENGTH>(
            &self.relay_node_id,
            "exit_confirmation.relay_node_id",
        )?;
        require_nonzero_length::<HASH_LENGTH>(
            &self.exit_node_id,
            "exit_confirmation.exit_node_id",
        )?;
        validate_peer_id(&self.exit_peer_id, "exit_confirmation.exit_peer_id")?;
        validate_session_binding(&self.client_session_id, &self.client_session_public_key)?;
        validate_reservation_binding(
            &self.capability_id,
            &self.exit_boot_id,
            &self.hold_id,
            &self.finalize_id,
            &self.control_relay_node_id,
            &self.control_relay_peer_id,
        )?;
        require_nonzero_length::<HASH_LENGTH>(&self.policy_hash, "exit_confirmation.policy_hash")?;
        let nested: SignedEnvelope =
            decode_canonical(&self.relay_reservation, MAX_CONTROL_MESSAGE_SIZE)?;
        if nested.message_type != ControlMessageType::RelayReservation as i32 {
            return Err(ProtocolError::InvalidField(
                "exit_confirmation.relay_reservation type",
            ));
        }
        require_nonzero_length::<NONCE_LENGTH>(&self.nonce, "exit_confirmation.nonce")?;
        validate_lifetime(
            self.created_at_ms,
            self.expires_at_ms,
            MAX_PHASE_LIFETIME_MS,
            "exit confirmation lifetime",
        )
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        validate_signed_fields(
            &self.client_session_id,
            self.created_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "exit_confirmation envelope binding",
        )
    }
}

impl ControlPayload for ExitConfirmationReceipt {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::ExitConfirmationReceipt;

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_reservation_ids(
            &self.reservation_id,
            &self.route_context_id,
            &self.client_session_id,
        )?;
        validate_reservation_binding(
            &self.capability_id,
            &self.exit_boot_id,
            &self.hold_id,
            &self.finalize_id,
            &self.control_relay_node_id,
            &self.control_relay_peer_id,
        )?;
        if !(1..=8).contains(&self.path_id) {
            return Err(ProtocolError::InvalidField("confirmation_receipt.path_id"));
        }
        require_nonzero_length::<HASH_LENGTH>(
            &self.finalized_bundle_hash,
            "confirmation_receipt.finalized_bundle_hash",
        )?;
        require_nonzero_length::<HASH_LENGTH>(
            &self.confirmation_envelope_hash,
            "confirmation_receipt.confirmation_envelope_hash",
        )?;
        require_nonzero_length::<HASH_LENGTH>(
            &self.exit_node_id,
            "confirmation_receipt.exit_node_id",
        )?;
        validate_peer_id(&self.exit_peer_id, "confirmation_receipt.exit_peer_id")?;
        require_nonzero_length::<NONCE_LENGTH>(&self.nonce, "confirmation_receipt.nonce")?;
        validate_lifetime(
            self.created_at_ms,
            self.expires_at_ms,
            MAX_PHASE_LIFETIME_MS,
            "confirmation receipt lifetime",
        )
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        validate_signed_fields(
            &self.exit_node_id,
            self.created_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "confirmation_receipt envelope binding",
        )
    }
}
impl ControlPayload for OpenTcp {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::OpenTcp;

    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_length::<ID_LENGTH>(&self.route_context_id, "open_tcp.route_context_id")?;
        require_nonzero_length::<ID_LENGTH>(&self.flow_id, "open_tcp.flow_id")?;
        require_nonzero_length::<HASH_LENGTH>(
            &self.client_ephemeral_id,
            "open_tcp.client_ephemeral_id",
        )?;
        validate_canonical_hostname(&self.hostname)?;
        validate_port(self.port, "open_tcp.port")?;
        require_nonzero_length::<HASH_LENGTH>(&self.policy_hash, "open_tcp.policy_hash")?;
        require_nonzero_length::<NONCE_LENGTH>(&self.nonce, "open_tcp.nonce")?;
        validate_lifetime(
            self.timestamp_ms,
            self.expires_at_ms,
            MAX_RESERVATION_LIFETIME_MS,
            "open_tcp lifetime",
        )
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        validate_signed_fields(
            &self.client_ephemeral_id,
            self.timestamp_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "open_tcp envelope binding",
        )
    }
}

impl ControlPayload for UdpFlowAuthorization {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::UdpFlowAuthorization;

    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero_length::<ID_LENGTH>(
            &self.route_context_id,
            "udp_authorization.route_context_id",
        )?;
        require_nonzero_length::<ID_LENGTH>(&self.flow_id, "udp_authorization.flow_id")?;
        require_nonzero_length::<HASH_LENGTH>(
            &self.client_ephemeral_id,
            "udp_authorization.client_ephemeral_id",
        )?;
        match (self.hostname.is_empty(), self.destination_ip.is_empty()) {
            (false, true) => validate_canonical_hostname(&self.hostname)?,
            (true, false) => {
                parse_ip_bytes(&self.destination_ip).ok_or(ProtocolError::InvalidField(
                    "udp_authorization.destination_ip",
                ))?;
            }
            _ => {
                return Err(ProtocolError::InvalidField("udp_authorization destination"));
            }
        }
        validate_port(self.port, "udp_authorization.port")?;
        require_nonzero_length::<HASH_LENGTH>(&self.policy_hash, "udp_authorization.policy_hash")?;
        if !(1_000..=300_000).contains(&self.idle_timeout_ms) {
            return Err(ProtocolError::InvalidField(
                "udp_authorization.idle_timeout_ms",
            ));
        }
        require_nonzero_length::<NONCE_LENGTH>(&self.nonce, "udp_authorization.nonce")?;
        validate_lifetime(
            self.timestamp_ms,
            self.expires_at_ms,
            MAX_RESERVATION_LIFETIME_MS,
            "udp_authorization lifetime",
        )
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        validate_signed_fields(
            &self.client_ephemeral_id,
            self.timestamp_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "udp_authorization envelope binding",
        )
    }
}

/// Verify both signatures on a relay reservation and compare every granted
/// route, endpoint, key, capacity, and lifetime field.
///
/// # Errors
///
/// Returns an error when either envelope is invalid or replayed, or when the
/// relay's accepted parameters differ from the exit-signed authorization.
pub fn verify_relay_reservation(
    encoded: &[u8],
    now_ms: u64,
    time_policy: TimePolicy,
    replay_cache: &mut ReplayCache,
) -> Result<
    (
        VerifiedControlMessage<RelayReservation>,
        VerifiedControlMessage<RelayAuthorization>,
    ),
    ProtocolError,
> {
    let relay =
        verify_control_message::<RelayReservation>(encoded, now_ms, time_policy, replay_cache)?;
    let relay_sender = *relay.sender_id();
    let relay_nonce = *relay.nonce();
    let exit = match verify_control_message::<RelayAuthorization>(
        &relay.message().exit_authorization,
        now_ms,
        time_policy,
        replay_cache,
    ) {
        Ok(exit) => exit,
        Err(error) => {
            let _ = replay_cache.rollback(&relay_sender, &relay_nonce);
            return Err(error);
        }
    };
    if !same_relay_grant(relay.message(), exit.message()) {
        let exit_sender = *exit.sender_id();
        let exit_nonce = *exit.nonce();
        let _ = replay_cache.rollback(&relay_sender, &relay_nonce);
        let _ = replay_cache.rollback(&exit_sender, &exit_nonce);
        return Err(ProtocolError::InvalidField(
            "relay reservation differs from exit authorization",
        ));
    }
    Ok((relay, exit))
}

/// Hash one exact canonical client-signed exit-confirmation envelope.
///
/// The digest is SHA-256 over a fixed v4 domain, one unsigned 32-bit
/// big-endian byte length, and the exact canonical `SignedEnvelope` bytes.
/// Signature verification remains the caller's mandatory preceding step.
///
/// # Errors
///
/// Returns an error for non-canonical, wrong-version, or wrong-type input.
pub fn exit_confirmation_envelope_hash(
    signed_confirmation: &[u8],
) -> Result<[u8; HASH_LENGTH], ProtocolError> {
    let envelope: SignedEnvelope = decode_canonical(signed_confirmation, MAX_CONTROL_MESSAGE_SIZE)?;
    if envelope.protocol_version != PROTOCOL_VERSION
        || envelope.message_type != ControlMessageType::ExitReservationConfirmation as i32
    {
        return Err(ProtocolError::InvalidField(
            "exit confirmation envelope hash",
        ));
    }
    let mut hasher = Sha256::new();
    hasher.update(CONFIRMATION_ENVELOPE_DOMAIN);
    hash_bundle_member(&mut hasher, signed_confirmation)?;
    Ok(hasher.finalize().into())
}

/// Hash one canonical finalized exit grant and its exact ordered authorization set.
///
/// The digest is SHA-256 over the fixed v4 domain followed by each canonical
/// envelope framed with one unsigned 32-bit big-endian byte length. The exit
/// grant is first and the authorizations follow in strictly increasing path order.
///
/// # Errors
///
/// Returns an error for non-canonical, wrong-version, wrong-type, unordered,
/// incomplete, or scope-inconsistent bundle members.
pub fn finalized_reservation_bundle_hash(
    signed_exit_reservation: &[u8],
    relay_authorizations: &[Vec<u8>],
) -> Result<[u8; HASH_LENGTH], ProtocolError> {
    let exit_envelope: SignedEnvelope =
        decode_canonical(signed_exit_reservation, MAX_CONTROL_MESSAGE_SIZE)?;
    if exit_envelope.protocol_version != PROTOCOL_VERSION
        || exit_envelope.message_type != ControlMessageType::ExitReservation as i32
    {
        return Err(ProtocolError::InvalidField("finalized bundle exit grant"));
    }
    let exit: ExitReservation = decode_canonical(&exit_envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)?;
    exit.validate()?;
    exit.validate_envelope(&exit_envelope)?;
    let expected_paths = usize::try_from(exit.maximum_paths)
        .map_err(|_| ProtocolError::InvalidField("finalized bundle path count"))?;
    if relay_authorizations.len() != expected_paths || !(1..=8).contains(&expected_paths) {
        return Err(ProtocolError::InvalidField("finalized bundle path count"));
    }

    let mut hasher = Sha256::new();
    hasher.update(FINALIZED_BUNDLE_DOMAIN);
    hash_bundle_member(&mut hasher, signed_exit_reservation)?;
    let mut previous_path_id = 0;
    for encoded in relay_authorizations {
        let envelope: SignedEnvelope = decode_canonical(encoded, MAX_CONTROL_MESSAGE_SIZE)?;
        if envelope.protocol_version != PROTOCOL_VERSION
            || envelope.message_type != ControlMessageType::RelayAuthorization as i32
        {
            return Err(ProtocolError::InvalidField(
                "finalized bundle relay authorization",
            ));
        }
        let authorization: RelayAuthorization =
            decode_canonical(&envelope.payload, MAX_CONTROL_PAYLOAD_SIZE)?;
        authorization.validate()?;
        authorization.validate_envelope(&envelope)?;
        if authorization.path_id <= previous_path_id || !same_finalized_scope(&exit, &authorization)
        {
            return Err(ProtocolError::InvalidField(
                "finalized bundle authorization scope",
            ));
        }
        previous_path_id = authorization.path_id;
        hash_bundle_member(&mut hasher, encoded)?;
    }
    Ok(hasher.finalize().into())
}

fn hash_bundle_member(hasher: &mut Sha256, encoded: &[u8]) -> Result<(), ProtocolError> {
    let length = u32::try_from(encoded.len())
        .map_err(|_| ProtocolError::InvalidField("finalized bundle member length"))?;
    hasher.update(length.to_be_bytes());
    hasher.update(encoded);
    Ok(())
}

fn same_finalized_scope(exit: &ExitReservation, path: &RelayAuthorization) -> bool {
    path.reservation_id == exit.reservation_id
        && path.route_context_id == exit.route_context_id
        && path.exit_node_id == exit.exit_node_id
        && path.client_session_id == exit.client_session_id
        && path.allowed_transports == exit.allowed_transports
        && path.maximum_up_mbps == exit.reserved_up_mbps
        && path.maximum_down_mbps == exit.reserved_down_mbps
        && path.policy_hash == exit.policy_hash
        && path.created_at_ms == exit.created_at_ms
        && path.expires_at_ms == exit.expires_at_ms
        && path.capability_id == exit.capability_id
        && path.client_session_public_key == exit.client_session_public_key
        && path.exit_boot_id == exit.exit_boot_id
        && path.hold_id == exit.hold_id
        && path.finalize_id == exit.finalize_id
        && path.control_relay_node_id == exit.control_relay_node_id
        && path.control_relay_peer_id == exit.control_relay_peer_id
        && path.exit_peer_id == exit.exit_peer_id
}

fn same_relay_grant(relay: &RelayReservation, exit: &RelayAuthorization) -> bool {
    relay.reservation_id == exit.reservation_id
        && relay.route_context_id == exit.route_context_id
        && relay.path_id == exit.path_id
        && relay.relay_node_id == exit.relay_node_id
        && relay.exit_node_id == exit.exit_node_id
        && relay.client_session_id == exit.client_session_id
        && relay.relay_peer_id == exit.relay_peer_id
        && relay.allowed_transports == exit.allowed_transports
        && relay.maximum_up_mbps == exit.maximum_up_mbps
        && relay.maximum_down_mbps == exit.maximum_down_mbps
        && relay.client_wireguard_public_key == exit.client_wireguard_public_key
        && relay.exit_wireguard_endpoint == exit.exit_wireguard_endpoint
        && relay.policy_hash == exit.policy_hash
        && relay.created_at_ms == exit.created_at_ms
        && relay.expires_at_ms == exit.expires_at_ms
        && relay.capability_id == exit.capability_id
        && relay.client_session_public_key == exit.client_session_public_key
        && relay.exit_boot_id == exit.exit_boot_id
        && relay.hold_id == exit.hold_id
        && relay.finalize_id == exit.finalize_id
        && relay.control_relay_node_id == exit.control_relay_node_id
        && relay.control_relay_peer_id == exit.control_relay_peer_id
        && relay.exit_peer_id == exit.exit_peer_id
}

fn validate_reservation_ids(
    reservation_id: &[u8],
    route_context_id: &[u8],
    client_session_id: &[u8],
) -> Result<(), ProtocolError> {
    require_nonzero_length::<ID_LENGTH>(reservation_id, "reservation_id")?;
    require_nonzero_length::<ID_LENGTH>(route_context_id, "route_context_id")?;
    require_nonzero_length::<HASH_LENGTH>(client_session_id, "client_session_id")?;
    Ok(())
}

#[allow(clippy::too_many_arguments)]
fn validate_relay_fields(
    reservation_id: &[u8],
    route_context_id: &[u8],
    path_id: u32,
    relay_node_id: &[u8],
    exit_node_id: &[u8],
    client_session_id: &[u8],
    relay_peer_id: &[u8],
    allowed_transports: &[i32],
    maximum_up_mbps: u64,
    maximum_down_mbps: u64,
    client_wireguard_public_key: &[u8],
    exit_wireguard_endpoint: Option<&WireguardEndpoint>,
    policy_hash: &[u8],
    created_at_ms: u64,
    expires_at_ms: u64,
    nonce: &[u8],
    capability_id: &[u8],
    client_session_public_key: &[u8],
    exit_boot_id: &[u8],
    hold_id: &[u8],
    finalize_id: &[u8],
    control_relay_node_id: &[u8],
    control_relay_peer_id: &[u8],
    exit_peer_id: &[u8],
) -> Result<(), ProtocolError> {
    validate_reservation_ids(reservation_id, route_context_id, client_session_id)?;
    if !(1..=8).contains(&path_id) {
        return Err(ProtocolError::InvalidField("relay path_id"));
    }
    require_nonzero_length::<HASH_LENGTH>(relay_node_id, "relay_node_id")?;
    require_nonzero_length::<HASH_LENGTH>(exit_node_id, "exit_node_id")?;
    if relay_node_id == exit_node_id {
        return Err(ProtocolError::InvalidField("relay equals exit"));
    }
    validate_peer_id(relay_peer_id, "relay relay_peer_id")?;
    validate_peer_id(exit_peer_id, "relay exit_peer_id")?;
    validate_session_binding(client_session_id, client_session_public_key)?;
    validate_reservation_binding(
        capability_id,
        exit_boot_id,
        hold_id,
        finalize_id,
        control_relay_node_id,
        control_relay_peer_id,
    )?;
    validate_transports(allowed_transports)?;
    validate_rate(maximum_up_mbps, "relay maximum_up_mbps")?;
    validate_rate(maximum_down_mbps, "relay maximum_down_mbps")?;
    require_nonzero_length::<KEY_LENGTH>(
        client_wireguard_public_key,
        "client_wireguard_public_key",
    )?;
    let exit_endpoint =
        exit_wireguard_endpoint.ok_or(ProtocolError::InvalidField("exit_wireguard_endpoint"))?;
    exit_endpoint.validate("exit_wireguard_endpoint")?;
    validate_distinct_wireguard_keys(&[client_wireguard_public_key, &exit_endpoint.public_key])?;
    require_nonzero_length::<HASH_LENGTH>(policy_hash, "relay policy_hash")?;
    require_nonzero_length::<NONCE_LENGTH>(nonce, "relay nonce")?;
    validate_lifetime(
        created_at_ms,
        expires_at_ms,
        MAX_RESERVATION_LIFETIME_MS,
        "relay lifetime",
    )
}

fn validate_session_binding(
    client_session_id: &[u8],
    client_session_public_key: &[u8],
) -> Result<(), ProtocolError> {
    require_nonzero_length::<KEY_LENGTH>(client_session_public_key, "client_session_public_key")?;
    let key: [u8; KEY_LENGTH] = client_session_public_key
        .try_into()
        .map_err(|_| ProtocolError::InvalidField("client_session_public_key"))?;
    if client_session_id != crate::node_id_from_public_key(&key) {
        return Err(ProtocolError::InvalidField("client session key binding"));
    }
    Ok(())
}

fn validate_reservation_binding(
    capability_id: &[u8],
    exit_boot_id: &[u8],
    hold_id: &[u8],
    finalize_id: &[u8],
    control_relay_node_id: &[u8],
    control_relay_peer_id: &[u8],
) -> Result<(), ProtocolError> {
    require_nonzero_length::<ID_LENGTH>(capability_id, "capability_id")?;
    require_nonzero_length::<ID_LENGTH>(exit_boot_id, "exit_boot_id")?;
    require_nonzero_length::<ID_LENGTH>(hold_id, "hold_id")?;
    require_nonzero_length::<ID_LENGTH>(finalize_id, "finalize_id")?;
    require_nonzero_length::<HASH_LENGTH>(control_relay_node_id, "control_relay_node_id")?;
    validate_peer_id(control_relay_peer_id, "control_relay_peer_id")
}

fn validate_distinct_wireguard_keys(keys: &[&[u8]]) -> Result<(), ProtocolError> {
    for (index, key) in keys.iter().enumerate() {
        if keys[index + 1..].contains(key) {
            return Err(ProtocolError::InvalidField(
                "distinct WireGuard public keys",
            ));
        }
    }
    Ok(())
}

fn validate_peer_id(peer_id: &[u8], field: &'static str) -> Result<(), ProtocolError> {
    if peer_id.is_empty() || peer_id.len() > 64 {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn validate_signed_fields(
    expected_sender_id: &[u8],
    timestamp_ms: u64,
    expires_at_ms: u64,
    nonce: &[u8],
    envelope: &SignedEnvelope,
    field: &'static str,
) -> Result<(), ProtocolError> {
    if expected_sender_id != envelope.sender_id
        || timestamp_ms != envelope.timestamp_ms
        || expires_at_ms != envelope.expires_at_ms
        || nonce != envelope.nonce
    {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn validate_transports(transports: &[i32]) -> Result<(), ProtocolError> {
    if transports.is_empty() || transports.len() > MAX_TRANSPORTS {
        return Err(ProtocolError::InvalidField(
            "exit_reservation.allowed_transports",
        ));
    }
    let mut previous = None;
    for value in transports {
        let transport = Transport::try_from(*value)
            .map_err(|_| ProtocolError::InvalidField("exit_reservation.allowed_transports"))?;
        if transport == Transport::Unspecified || previous.is_some_and(|old| old >= *value) {
            return Err(ProtocolError::InvalidField(
                "exit_reservation.allowed_transports",
            ));
        }
        previous = Some(*value);
    }
    Ok(())
}

fn validate_control_addresses(addresses: &[String]) -> Result<(), ProtocolError> {
    if addresses.is_empty()
        || addresses.len() > MAX_CONTROL_ADDRESSES
        || !is_strictly_sorted(addresses)
    {
        return Err(ProtocolError::InvalidField(
            "advertisement.control_addresses",
        ));
    }
    for address in addresses {
        if address.len() > 256
            || !address.starts_with('/')
            || !address.bytes().all(|byte| (0x21..=0x7e).contains(&byte))
        {
            return Err(ProtocolError::InvalidField("advertisement.control_address"));
        }
    }
    Ok(())
}

fn validate_capacity(
    capacity: &AdvertisementCapacity,
    roles: &AdvertisementRoles,
) -> Result<(), ProtocolError> {
    let rates = [
        capacity.operator_relay_limit_up_mbps,
        capacity.operator_relay_limit_down_mbps,
        capacity.operator_exit_limit_up_mbps,
        capacity.operator_exit_limit_down_mbps,
        capacity.currently_reserved_up_mbps,
        capacity.currently_reserved_down_mbps,
        capacity.estimated_free_up_mbps,
        capacity.estimated_free_down_mbps,
    ];
    let total_up = capacity
        .operator_relay_limit_up_mbps
        .saturating_add(capacity.operator_exit_limit_up_mbps);
    let total_down = capacity
        .operator_relay_limit_down_mbps
        .saturating_add(capacity.operator_exit_limit_down_mbps);
    let role_fields_consistent = (roles.relay
        || (capacity.operator_relay_limit_up_mbps == 0
            && capacity.operator_relay_limit_down_mbps == 0
            && capacity.active_relay_sessions == 0
            && capacity.free_relay_slots == 0))
        && (roles.exit
            || (capacity.operator_exit_limit_up_mbps == 0
                && capacity.operator_exit_limit_down_mbps == 0
                && capacity.active_exit_sessions == 0
                && capacity.free_exit_slots == 0));
    if rates.into_iter().any(|rate| rate > MAX_RATE_MBPS)
        || !(1..=300).contains(&capacity.sample_window_seconds)
        || capacity
            .currently_reserved_up_mbps
            .saturating_add(capacity.estimated_free_up_mbps)
            > total_up
        || capacity
            .currently_reserved_down_mbps
            .saturating_add(capacity.estimated_free_down_mbps)
            > total_down
        || !role_fields_consistent
    {
        return Err(ProtocolError::InvalidField("advertisement.capacity"));
    }
    Ok(())
}

fn validate_network(network: &AdvertisementNetwork) -> Result<(), ProtocolError> {
    validate_ascii_text(&network.region, 32, "advertisement.network.region")?;
    OperatorId::new(network.operator_id.clone())
        .map_err(|_| ProtocolError::InvalidField("advertisement.network.operator_id"))?;
    if !network.country_code.is_empty()
        && (network.country_code.len() != 2
            || !network
                .country_code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase()))
    {
        return Err(ProtocolError::InvalidField(
            "advertisement.network.country_code",
        ));
    }
    if !network.ipv4_prefix_hint.is_empty() {
        validate_prefix_hint(
            &network.ipv4_prefix_hint,
            false,
            "advertisement.network.ipv4_prefix_hint",
        )?;
    }
    if !network.ipv6_prefix_hint.is_empty() {
        validate_prefix_hint(
            &network.ipv6_prefix_hint,
            true,
            "advertisement.network.ipv6_prefix_hint",
        )?;
    }
    Ok(())
}

fn validate_prefix_hint(hint: &str, ipv6: bool, field: &'static str) -> Result<(), ProtocolError> {
    let (address, prefix_length) = hint
        .split_once('/')
        .ok_or(ProtocolError::InvalidField(field))?;
    let address: IpAddr = address
        .parse()
        .map_err(|_| ProtocolError::InvalidField(field))?;
    let prefix_length: u8 = prefix_length
        .parse()
        .map_err(|_| ProtocolError::InvalidField(field))?;
    let expected_length = if ipv6 { 48 } else { 24 };
    if prefix_length != expected_length
        || address.is_ipv6() != ipv6
        || !is_network_address(address, prefix_length)
        || format!("{address}/{prefix_length}") != hint
    {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn validate_quality(quality: &AdvertisementQuality) -> Result<(), ProtocolError> {
    if quality.historical_uptime_ppm > 1_000_000
        || quality.historical_delivery_ratio_p25_ppm > 1_000_000
    {
        return Err(ProtocolError::InvalidField("advertisement.quality"));
    }
    Ok(())
}

fn is_network_address(address: IpAddr, prefix_length: u8) -> bool {
    match address {
        IpAddr::V4(address) if prefix_length <= 32 => {
            let bits = u32::from(address);
            let mask = if prefix_length == 0 {
                0
            } else {
                u32::MAX << (32 - prefix_length)
            };
            bits & mask == bits
        }
        IpAddr::V6(address) if prefix_length <= 128 => {
            let bits = u128::from(address);
            let mask = if prefix_length == 0 {
                0
            } else {
                u128::MAX << (128 - prefix_length)
            };
            bits & mask == bits
        }
        _ => false,
    }
}

fn validate_canonical_hostname(hostname: &str) -> Result<(), ProtocolError> {
    validate_canonical_dns_name(hostname, "hostname")
}

fn validate_canonical_dns_name(hostname: &str, field: &'static str) -> Result<(), ProtocolError> {
    if hostname.is_empty()
        || hostname.len() > 253
        || hostname.ends_with('.')
        || hostname.bytes().any(|byte| byte.is_ascii_uppercase())
        || hostname.parse::<IpAddr>().is_ok()
    {
        return Err(ProtocolError::InvalidField(field));
    }
    let labels_valid = hostname.split('.').all(|label| {
        !label.is_empty()
            && label.len() <= 63
            && !label.starts_with('-')
            && !label.ends_with('-')
            && label
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
    });
    if !labels_valid || !hostname.contains('.') {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn validate_ascii_text(
    text: &str,
    maximum: usize,
    field: &'static str,
) -> Result<(), ProtocolError> {
    if text.is_empty()
        || text.len() > maximum
        || !text
            .bytes()
            .all(|byte| byte == b' ' || (0x21..=0x7e).contains(&byte))
    {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn validate_rate(rate: u64, field: &'static str) -> Result<(), ProtocolError> {
    if rate == 0 || rate > MAX_RATE_MBPS {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn validate_port(port: u32, field: &'static str) -> Result<(), ProtocolError> {
    if !(1..=u32::from(u16::MAX)).contains(&port) {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn validate_lifetime(
    created_at_ms: u64,
    expires_at_ms: u64,
    maximum: u64,
    field: &'static str,
) -> Result<(), ProtocolError> {
    let lifetime = expires_at_ms
        .checked_sub(created_at_ms)
        .ok_or(ProtocolError::InvalidField(field))?;
    if lifetime == 0 || lifetime > maximum {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn require_nonzero_length<const LENGTH: usize>(
    bytes: &[u8],
    field: &'static str,
) -> Result<[u8; LENGTH], ProtocolError> {
    let value = fixed_array(bytes, field)?;
    if value.iter().all(|byte| *byte == 0) {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(value)
}

fn is_strictly_sorted(values: &[String]) -> bool {
    values.windows(2).all(|window| window[0] < window[1])
}

fn parse_ip_bytes(bytes: &[u8]) -> Option<IpAddr> {
    match bytes {
        [a, b, c, d] => Some(IpAddr::V4(Ipv4Addr::new(*a, *b, *c, *d))),
        bytes if bytes.len() == 16 => {
            let array: [u8; 16] = bytes.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(array)))
        }
        _ => None,
    }
}
