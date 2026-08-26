//! Hard-incompatible v4 reservation intents and proof-carrying phase messages.

use std::collections::HashSet;

use prost::Message;

use crate::{
    ControlMessageType, ControlPayload, MAX_CONTROL_MESSAGE_SIZE, ProtocolError, SignedEnvelope,
    Transport, WireguardEndpoint, decode_canonical, node_id_from_public_key,
};

const ID_LENGTH: usize = 16;
const KEY_LENGTH: usize = 32;
const NONCE_LENGTH: usize = 32;
const MAX_PEER_ID_LENGTH: usize = 64;
const MAX_PATHS: usize = 8;
const MAX_TRANSPORTS: usize = 3;
const MAX_RATE_MBPS: u64 = 1_000_000;
const MAX_RESERVATION_LIFETIME_MS: u64 = 15 * 60 * 1_000;
const MAX_PROBE_LIFETIME_MS: u64 = 30 * 1_000;
const MAX_PROBE_WINDOW_MS: u64 = 10 * 1_000;
const MAX_PROBE_RTT_US: u64 = 60 * 1_000 * 1_000;

/// Network family measured by one bounded relay probe.
#[allow(missing_docs)]
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, prost::Enumeration)]
#[repr(i32)]
pub enum ProbeAddressFamily {
    Unspecified = 0,
    Ipv4 = 1,
    Ipv6 = 2,
}

/// Client-session-signed request to hold exit capacity before relay selection.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct ExitCapacityHoldRequest {
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
    // Tag 10 permanently reserved: v2 relay_paths.
    #[prost(bytes = "vec", tag = "11")]
    pub policy_hash: Vec<u8>,
    #[prost(uint64, tag = "12")]
    pub created_at_ms: u64,
    #[prost(uint64, tag = "13")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "14")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "15")]
    pub client_session_public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "16")]
    pub control_relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "17")]
    pub control_relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "18")]
    pub exit_peer_id: Vec<u8>,
    #[prost(uint64, tag = "19")]
    pub reservation_expires_at_ms: u64,
    #[prost(uint32, tag = "20")]
    pub probe_permit_limit: u32,
}

/// Exit-signed bounded proof of possession for one fresh route-attempt key.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct ClientSessionCapability {
    #[prost(bytes = "vec", tag = "1")]
    pub capability_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub client_session_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub client_session_public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub exit_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub exit_boot_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub control_relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub control_relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "10")]
    pub policy_hash: Vec<u8>,
    #[prost(enumeration = "Transport", repeated, tag = "11")]
    pub allowed_transports: Vec<i32>,
    #[prost(uint64, tag = "12")]
    pub reserved_up_mbps: u64,
    #[prost(uint64, tag = "13")]
    pub reserved_down_mbps: u64,
    #[prost(uint32, tag = "14")]
    pub maximum_paths: u32,
    #[prost(uint64, tag = "15")]
    pub created_at_ms: u64,
    #[prost(uint64, tag = "16")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "17")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "18")]
    pub exit_peer_id: Vec<u8>,
    #[prost(uint32, tag = "19")]
    pub probe_permit_limit: u32,
}

/// Exit-signed proof that capacity is held without committing to relays.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct ExitCapacityHold {
    #[prost(bytes = "vec", tag = "1")]
    pub hold_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub client_session_capability: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub exit_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub exit_boot_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub client_session_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub policy_hash: Vec<u8>,
    #[prost(enumeration = "Transport", repeated, tag = "9")]
    pub allowed_transports: Vec<i32>,
    #[prost(uint64, tag = "10")]
    pub reserved_up_mbps: u64,
    #[prost(uint64, tag = "11")]
    pub reserved_down_mbps: u64,
    #[prost(uint32, tag = "12")]
    pub maximum_paths: u32,
    #[prost(uint64, tag = "13")]
    pub created_at_ms: u64,
    #[prost(uint64, tag = "14")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "15")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "16")]
    pub exit_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "17")]
    pub control_relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "18")]
    pub control_relay_peer_id: Vec<u8>,
    #[prost(uint64, tag = "19")]
    pub reservation_expires_at_ms: u64,
    #[prost(uint32, tag = "20")]
    pub probe_permit_limit: u32,
}

/// Client-session-signed request for one exit-issued bounded probe permit.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct RelayProbePermitRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub probe_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub exit_capacity_hold: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub client_session_capability: Vec<u8>,
    #[prost(uint32, tag = "4")]
    pub path_id: u32,
    #[prost(bytes = "vec", tag = "5")]
    pub relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub client_session_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub control_relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub control_relay_peer_id: Vec<u8>,
    #[prost(uint64, tag = "10")]
    pub created_at_ms: u64,
    #[prost(uint64, tag = "11")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "12")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "13")]
    pub exit_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "14")]
    pub exit_peer_id: Vec<u8>,
    #[prost(enumeration = "Transport", tag = "15")]
    pub transport: i32,
    #[prost(enumeration = "ProbeAddressFamily", tag = "16")]
    pub address_family: i32,
}

/// Exit-signed authorization for one exact, short, bounded relay probe.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct RelayProbePermit {
    #[prost(bytes = "vec", tag = "1")]
    pub probe_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub hold_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub capability_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub client_session_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub exit_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub exit_boot_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub control_relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "10")]
    pub control_relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "11")]
    pub relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "12")]
    pub relay_peer_id: Vec<u8>,
    #[prost(uint32, tag = "13")]
    pub path_id: u32,
    #[prost(uint64, tag = "14")]
    pub created_at_ms: u64,
    #[prost(uint64, tag = "15")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "16")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "17")]
    pub exit_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "18")]
    pub policy_hash: Vec<u8>,
    #[prost(enumeration = "Transport", tag = "19")]
    pub transport: i32,
    #[prost(enumeration = "ProbeAddressFamily", tag = "20")]
    pub address_family: i32,
}

/// One required directional leg measurement inside a controlled probe window.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct ProbeLegEvidence {
    #[prost(uint64, tag = "1")]
    pub up_capacity_mbps: u64,
    #[prost(uint64, tag = "2")]
    pub down_capacity_mbps: u64,
    #[prost(uint64, tag = "3")]
    pub rtt_micros: u64,
    #[prost(uint64, tag = "4")]
    pub transmitted_bytes: u64,
    #[prost(uint64, tag = "5")]
    pub received_bytes: u64,
    #[prost(uint64, tag = "6")]
    pub window_started_at_ms: u64,
    #[prost(uint64, tag = "7")]
    pub window_ended_at_ms: u64,
    #[prost(uint64, tag = "8")]
    pub measured_at_ms: u64,
}

/// Relay-signed structured observations for one exact probe permit.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct RelayProbeResult {
    #[prost(bytes = "vec", tag = "1")]
    pub probe_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub relay_probe_permit: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub exit_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub exit_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub exit_boot_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    pub hold_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub capability_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "10")]
    pub reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "11")]
    pub route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "12")]
    pub client_session_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "13")]
    pub policy_hash: Vec<u8>,
    #[prost(enumeration = "Transport", tag = "14")]
    pub transport: i32,
    #[prost(enumeration = "ProbeAddressFamily", tag = "15")]
    pub address_family: i32,
    #[prost(message, optional, tag = "16")]
    pub client_relay: Option<ProbeLegEvidence>,
    #[prost(message, optional, tag = "17")]
    pub relay_exit: Option<ProbeLegEvidence>,
    #[prost(uint64, tag = "18")]
    pub measured_at_ms: u64,
    #[prost(uint64, tag = "19")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "20")]
    pub nonce: Vec<u8>,
}

/// One exact relay path submitted only during finalization.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct FinalizedRelayPath {
    #[prost(uint32, tag = "1")]
    pub path_id: u32,
    #[prost(bytes = "vec", tag = "2")]
    pub relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub client_wireguard_public_key: Vec<u8>,
    // Tag 5 permanently reserved: retired overlay-prefix material.
    #[prost(bytes = "vec", tag = "6")]
    pub relay_probe_permit: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    pub relay_probe_result: Vec<u8>,
}

/// Client-session-signed request to finalize one held capacity allocation.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct ExitReservationFinalizeRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub reservation_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    pub route_context_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    pub exit_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    pub client_session_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    pub client_session_capability: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    pub exit_capacity_hold: Vec<u8>,
    #[prost(message, repeated, tag = "7")]
    pub relay_paths: Vec<FinalizedRelayPath>,
    #[prost(uint64, tag = "8")]
    pub created_at_ms: u64,
    #[prost(uint64, tag = "9")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "10")]
    pub nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "11")]
    pub control_relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "12")]
    pub control_relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "13")]
    pub finalize_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "14")]
    pub exit_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "15")]
    pub auth_commitment: Vec<u8>,
    #[prost(uint64, tag = "16")]
    pub masque_context_id: u64,
    #[prost(bytes = "vec", tag = "17")]
    pub client_native_instance_id: Vec<u8>,
}

/// Client-session-signed relay request carrying exit capability and final grants.
#[allow(missing_docs)]
#[derive(Clone, PartialEq, Message)]
pub struct RelayReservationRequest {
    #[prost(bytes = "vec", tag = "1")]
    pub client_session_id: Vec<u8>,
    // Tag 2 permanently reserved: v2 client_peer_id.
    #[prost(bytes = "vec", tag = "3")]
    pub exit_authorization: Vec<u8>,
    #[prost(uint64, tag = "4")]
    pub created_at_ms: u64,
    #[prost(uint64, tag = "5")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", tag = "6")]
    pub nonce: Vec<u8>,
    #[prost(message, optional, tag = "7")]
    pub client_wireguard_endpoint: Option<WireguardEndpoint>,
    #[prost(bytes = "vec", tag = "8")]
    pub client_session_capability: Vec<u8>,
    #[prost(bytes = "vec", tag = "9")]
    pub exit_reservation: Vec<u8>,
}

impl ControlPayload for ExitCapacityHoldRequest {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::ExitCapacityHoldRequest;

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_base_ids(
            &self.reservation_id,
            &self.route_context_id,
            &self.client_session_id,
        )?;
        validate_session_key(&self.client_session_id, &self.client_session_public_key)?;
        require_nonzero::<KEY_LENGTH>(&self.exit_node_id, "hold_request.exit_node_id")?;
        validate_peer_id(&self.exit_peer_id, "hold_request.exit_peer_id")?;
        validate_control_relay(&self.control_relay_node_id, &self.control_relay_peer_id)?;
        validate_scope(
            &self.allowed_transports,
            self.reserved_up_mbps,
            self.reserved_down_mbps,
            self.maximum_paths,
            self.probe_permit_limit,
            &self.policy_hash,
        )?;
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "hold_request.nonce")?;
        validate_lifetime(
            self.created_at_ms,
            self.expires_at_ms,
            MAX_PROBE_LIFETIME_MS,
        )?;
        validate_lifetime(
            self.created_at_ms,
            self.reservation_expires_at_ms,
            MAX_RESERVATION_LIFETIME_MS,
        )?;
        if self.reservation_expires_at_ms < self.expires_at_ms {
            return Err(ProtocolError::InvalidLifetime);
        }
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        validate_session_envelope(
            &self.client_session_id,
            self.created_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "hold_request envelope binding",
        )
    }
}

impl ControlPayload for ClientSessionCapability {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::ClientSessionCapability;

    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero::<ID_LENGTH>(&self.capability_id, "session_capability.capability_id")?;
        validate_base_ids(
            &self.reservation_id,
            &self.route_context_id,
            &self.client_session_id,
        )?;
        validate_session_key(&self.client_session_id, &self.client_session_public_key)?;
        require_nonzero::<KEY_LENGTH>(&self.exit_node_id, "session_capability.exit_node_id")?;
        validate_peer_id(&self.exit_peer_id, "session_capability.exit_peer_id")?;
        require_nonzero::<ID_LENGTH>(&self.exit_boot_id, "session_capability.exit_boot_id")?;
        validate_control_relay(&self.control_relay_node_id, &self.control_relay_peer_id)?;
        validate_scope(
            &self.allowed_transports,
            self.reserved_up_mbps,
            self.reserved_down_mbps,
            self.maximum_paths,
            self.probe_permit_limit,
            &self.policy_hash,
        )?;
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "session_capability.nonce")?;
        validate_lifetime(
            self.created_at_ms,
            self.expires_at_ms,
            MAX_RESERVATION_LIFETIME_MS,
        )
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        validate_signed_envelope(
            &self.exit_node_id,
            self.created_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "session_capability envelope binding",
        )
    }
}

impl ControlPayload for ExitCapacityHold {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::ExitCapacityHold;

    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero::<ID_LENGTH>(&self.hold_id, "capacity_hold.hold_id")?;
        validate_nested(
            &self.client_session_capability,
            ControlMessageType::ClientSessionCapability,
            "capacity_hold.client_session_capability",
        )?;
        validate_base_ids(
            &self.reservation_id,
            &self.route_context_id,
            &self.client_session_id,
        )?;
        require_nonzero::<KEY_LENGTH>(&self.exit_node_id, "capacity_hold.exit_node_id")?;
        validate_peer_id(&self.exit_peer_id, "capacity_hold.exit_peer_id")?;
        require_nonzero::<ID_LENGTH>(&self.exit_boot_id, "capacity_hold.exit_boot_id")?;
        validate_control_relay(&self.control_relay_node_id, &self.control_relay_peer_id)?;
        validate_scope(
            &self.allowed_transports,
            self.reserved_up_mbps,
            self.reserved_down_mbps,
            self.maximum_paths,
            self.probe_permit_limit,
            &self.policy_hash,
        )?;
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "capacity_hold.nonce")?;
        validate_lifetime(
            self.created_at_ms,
            self.expires_at_ms,
            MAX_PROBE_LIFETIME_MS,
        )?;
        validate_lifetime(
            self.created_at_ms,
            self.reservation_expires_at_ms,
            MAX_RESERVATION_LIFETIME_MS,
        )?;
        if self.reservation_expires_at_ms < self.expires_at_ms {
            return Err(ProtocolError::InvalidLifetime);
        }
        Ok(())
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        validate_signed_envelope(
            &self.exit_node_id,
            self.created_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "capacity_hold envelope binding",
        )
    }
}

impl ControlPayload for RelayProbePermitRequest {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::RelayProbePermitRequest;

    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero::<ID_LENGTH>(&self.probe_id, "probe_request.probe_id")?;
        validate_nested(
            &self.exit_capacity_hold,
            ControlMessageType::ExitCapacityHold,
            "probe_request.exit_capacity_hold",
        )?;
        validate_nested(
            &self.client_session_capability,
            ControlMessageType::ClientSessionCapability,
            "probe_request.client_session_capability",
        )?;
        validate_path_id(self.path_id, "probe_request.path_id")?;
        require_nonzero::<KEY_LENGTH>(&self.relay_node_id, "probe_request.relay_node_id")?;
        validate_peer_id(&self.relay_peer_id, "probe_request.relay_peer_id")?;
        require_nonzero::<KEY_LENGTH>(&self.client_session_id, "probe_request.client_session_id")?;
        require_nonzero::<KEY_LENGTH>(&self.exit_node_id, "probe_request.exit_node_id")?;
        validate_peer_id(&self.exit_peer_id, "probe_request.exit_peer_id")?;
        validate_control_relay(&self.control_relay_node_id, &self.control_relay_peer_id)?;
        validate_transport(self.transport, "probe_request.transport")?;
        validate_family(self.address_family, "probe_request.address_family")?;
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "probe_request.nonce")?;
        validate_lifetime(
            self.created_at_ms,
            self.expires_at_ms,
            MAX_PROBE_LIFETIME_MS,
        )
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        validate_session_envelope(
            &self.client_session_id,
            self.created_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "probe_request envelope binding",
        )
    }
}

impl ControlPayload for RelayProbePermit {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::RelayProbePermit;

    fn validate(&self) -> Result<(), ProtocolError> {
        for (value, field) in [
            (&self.probe_id, "probe_permit.probe_id"),
            (&self.hold_id, "probe_permit.hold_id"),
            (&self.capability_id, "probe_permit.capability_id"),
            (&self.reservation_id, "probe_permit.reservation_id"),
            (&self.route_context_id, "probe_permit.route_context_id"),
            (&self.exit_boot_id, "probe_permit.exit_boot_id"),
        ] {
            require_nonzero::<ID_LENGTH>(value, field)?;
        }
        for (value, field) in [
            (&self.client_session_id, "probe_permit.client_session_id"),
            (&self.exit_node_id, "probe_permit.exit_node_id"),
            (
                &self.control_relay_node_id,
                "probe_permit.control_relay_node_id",
            ),
            (&self.relay_node_id, "probe_permit.relay_node_id"),
            (&self.policy_hash, "probe_permit.policy_hash"),
        ] {
            require_nonzero::<KEY_LENGTH>(value, field)?;
        }
        validate_peer_id(&self.exit_peer_id, "probe_permit.exit_peer_id")?;
        validate_peer_id(
            &self.control_relay_peer_id,
            "probe_permit.control_relay_peer_id",
        )?;
        validate_peer_id(&self.relay_peer_id, "probe_permit.relay_peer_id")?;
        validate_path_id(self.path_id, "probe_permit.path_id")?;
        validate_transport(self.transport, "probe_permit.transport")?;
        validate_family(self.address_family, "probe_permit.address_family")?;
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "probe_permit.nonce")?;
        validate_lifetime(
            self.created_at_ms,
            self.expires_at_ms,
            MAX_PROBE_LIFETIME_MS,
        )
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        validate_signed_envelope(
            &self.exit_node_id,
            self.created_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "probe_permit envelope binding",
        )
    }
}

impl ControlPayload for RelayProbeResult {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::RelayProbeResult;

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_nested(
            &self.relay_probe_permit,
            ControlMessageType::RelayProbePermit,
            "probe_result.relay_probe_permit",
        )?;
        for (value, field) in [
            (&self.probe_id, "probe_result.probe_id"),
            (&self.hold_id, "probe_result.hold_id"),
            (&self.capability_id, "probe_result.capability_id"),
            (&self.reservation_id, "probe_result.reservation_id"),
            (&self.route_context_id, "probe_result.route_context_id"),
            (&self.exit_boot_id, "probe_result.exit_boot_id"),
        ] {
            require_nonzero::<ID_LENGTH>(value, field)?;
        }
        for (value, field) in [
            (&self.relay_node_id, "probe_result.relay_node_id"),
            (&self.exit_node_id, "probe_result.exit_node_id"),
            (&self.client_session_id, "probe_result.client_session_id"),
            (&self.policy_hash, "probe_result.policy_hash"),
        ] {
            require_nonzero::<KEY_LENGTH>(value, field)?;
        }
        validate_peer_id(&self.relay_peer_id, "probe_result.relay_peer_id")?;
        validate_peer_id(&self.exit_peer_id, "probe_result.exit_peer_id")?;
        validate_transport(self.transport, "probe_result.transport")?;
        validate_family(self.address_family, "probe_result.address_family")?;
        let client_relay = self
            .client_relay
            .as_ref()
            .ok_or(ProtocolError::InvalidField("probe_result.client_relay"))?;
        let relay_exit = self
            .relay_exit
            .as_ref()
            .ok_or(ProtocolError::InvalidField("probe_result.relay_exit"))?;
        validate_leg(client_relay, "probe_result.client_relay")?;
        validate_leg(relay_exit, "probe_result.relay_exit")?;
        if client_relay.window_started_at_ms != relay_exit.window_started_at_ms
            || client_relay.window_ended_at_ms != relay_exit.window_ended_at_ms
            || self.measured_at_ms < client_relay.window_started_at_ms
            || self.measured_at_ms > client_relay.window_ended_at_ms
        {
            return Err(ProtocolError::InvalidField(
                "probe_result controlled window",
            ));
        }
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "probe_result.nonce")?;
        validate_lifetime(
            self.measured_at_ms,
            self.expires_at_ms,
            MAX_PROBE_LIFETIME_MS,
        )
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        validate_signed_envelope(
            &self.relay_node_id,
            self.measured_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "probe_result envelope binding",
        )
    }
}

impl ControlPayload for ExitReservationFinalizeRequest {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::ExitReservationFinalizeRequest;

    fn validate(&self) -> Result<(), ProtocolError> {
        validate_base_ids(
            &self.reservation_id,
            &self.route_context_id,
            &self.client_session_id,
        )?;
        require_nonzero::<KEY_LENGTH>(&self.exit_node_id, "finalize_request.exit_node_id")?;
        validate_peer_id(&self.exit_peer_id, "finalize_request.exit_peer_id")?;
        validate_control_relay(&self.control_relay_node_id, &self.control_relay_peer_id)?;
        require_nonzero::<ID_LENGTH>(&self.finalize_id, "finalize_request.finalize_id")?;
        validate_nested(
            &self.client_session_capability,
            ControlMessageType::ClientSessionCapability,
            "finalize_request.client_session_capability",
        )?;
        validate_nested(
            &self.exit_capacity_hold,
            ControlMessageType::ExitCapacityHold,
            "finalize_request.exit_capacity_hold",
        )?;
        validate_finalized_paths(&self.relay_paths)?;
        require_nonzero::<KEY_LENGTH>(&self.auth_commitment, "finalize_request.auth_commitment")?;
        validate_masque_context(self.masque_context_id)?;
        require_nonzero::<KEY_LENGTH>(
            &self.client_native_instance_id,
            "finalize_request.client_native_instance_id",
        )?;
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "finalize_request.nonce")?;
        validate_lifetime(
            self.created_at_ms,
            self.expires_at_ms,
            MAX_PROBE_LIFETIME_MS,
        )
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        validate_session_envelope(
            &self.client_session_id,
            self.created_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "finalize_request envelope binding",
        )
    }
}

impl ControlPayload for RelayReservationRequest {
    const MESSAGE_TYPE: ControlMessageType = ControlMessageType::RelayReservationRequest;

    fn validate(&self) -> Result<(), ProtocolError> {
        require_nonzero::<KEY_LENGTH>(&self.client_session_id, "relay_request.client_session_id")?;
        validate_nested(
            &self.exit_authorization,
            ControlMessageType::RelayAuthorization,
            "relay_request.exit_authorization",
        )?;
        validate_nested(
            &self.client_session_capability,
            ControlMessageType::ClientSessionCapability,
            "relay_request.client_session_capability",
        )?;
        validate_nested(
            &self.exit_reservation,
            ControlMessageType::ExitReservation,
            "relay_request.exit_reservation",
        )?;
        self.client_wireguard_endpoint
            .as_ref()
            .ok_or(ProtocolError::InvalidField(
                "relay_request.client_wireguard_endpoint",
            ))?
            .validate("relay_request.client_wireguard_endpoint")?;
        require_nonzero::<NONCE_LENGTH>(&self.nonce, "relay_request.nonce")?;
        validate_lifetime(
            self.created_at_ms,
            self.expires_at_ms,
            MAX_PROBE_LIFETIME_MS,
        )
    }

    fn validate_envelope(&self, envelope: &SignedEnvelope) -> Result<(), ProtocolError> {
        validate_session_envelope(
            &self.client_session_id,
            self.created_at_ms,
            self.expires_at_ms,
            &self.nonce,
            envelope,
            "relay_request envelope binding",
        )
    }
}

fn validate_finalized_paths(paths: &[FinalizedRelayPath]) -> Result<(), ProtocolError> {
    if paths.is_empty() || paths.len() > MAX_PATHS {
        return Err(ProtocolError::InvalidField("finalize_request.relay_paths"));
    }
    let mut previous_path_id = 0;
    let mut relays = HashSet::with_capacity(paths.len());
    let mut relay_peers = HashSet::with_capacity(paths.len());
    let mut keys = HashSet::with_capacity(paths.len());
    for path in paths {
        validate_path_id(path.path_id, "finalize_request.path_id")?;
        if path.path_id <= previous_path_id {
            return Err(ProtocolError::InvalidField("finalize_request path order"));
        }
        previous_path_id = path.path_id;
        require_nonzero::<KEY_LENGTH>(&path.relay_node_id, "finalize_request.relay_node_id")?;
        if !relays.insert(path.relay_node_id.as_slice()) {
            return Err(ProtocolError::InvalidField(
                "finalize_request distinct relays",
            ));
        }
        validate_peer_id(&path.relay_peer_id, "finalize_request.relay_peer_id")?;
        if !relay_peers.insert(path.relay_peer_id.as_slice()) {
            return Err(ProtocolError::InvalidField(
                "finalize_request distinct relay peers",
            ));
        }
        require_nonzero::<KEY_LENGTH>(
            &path.client_wireguard_public_key,
            "finalize_request.client_wireguard_public_key",
        )?;
        if !keys.insert(path.client_wireguard_public_key.as_slice()) {
            return Err(ProtocolError::InvalidField(
                "finalize_request distinct client keys",
            ));
        }
        validate_nested(
            &path.relay_probe_permit,
            ControlMessageType::RelayProbePermit,
            "finalize_request.relay_probe_permit",
        )?;
        validate_nested(
            &path.relay_probe_result,
            ControlMessageType::RelayProbeResult,
            "finalize_request.relay_probe_result",
        )?;
    }
    Ok(())
}

fn validate_leg(evidence: &ProbeLegEvidence, field: &'static str) -> Result<(), ProtocolError> {
    validate_rate(evidence.up_capacity_mbps, field)?;
    validate_rate(evidence.down_capacity_mbps, field)?;
    if evidence.rtt_micros == 0
        || evidence.rtt_micros > MAX_PROBE_RTT_US
        || evidence.transmitted_bytes == 0
        || evidence.received_bytes == 0
        || evidence.measured_at_ms < evidence.window_started_at_ms
        || evidence.measured_at_ms > evidence.window_ended_at_ms
    {
        return Err(ProtocolError::InvalidField(field));
    }
    validate_lifetime(
        evidence.window_started_at_ms,
        evidence.window_ended_at_ms,
        MAX_PROBE_WINDOW_MS,
    )
}

fn validate_scope(
    transports: &[i32],
    up_mbps: u64,
    down_mbps: u64,
    maximum_paths: u32,
    probe_permit_limit: u32,
    policy_hash: &[u8],
) -> Result<(), ProtocolError> {
    validate_transports(transports)?;
    validate_rate(up_mbps, "reservation_scope.up_mbps")?;
    validate_rate(down_mbps, "reservation_scope.down_mbps")?;
    if !(1..=u32::try_from(MAX_PATHS).unwrap_or(u32::MAX)).contains(&maximum_paths) {
        return Err(ProtocolError::InvalidField(
            "reservation_scope.maximum_paths",
        ));
    }
    if !(maximum_paths..=u32::try_from(MAX_PATHS).unwrap_or(u32::MAX)).contains(&probe_permit_limit)
    {
        return Err(ProtocolError::InvalidField(
            "reservation_scope.probe_permit_limit",
        ));
    }
    require_nonzero::<KEY_LENGTH>(policy_hash, "reservation_scope.policy_hash")
}

fn validate_base_ids(
    reservation_id: &[u8],
    route_context_id: &[u8],
    client_session_id: &[u8],
) -> Result<(), ProtocolError> {
    require_nonzero::<ID_LENGTH>(reservation_id, "reservation_id")?;
    require_nonzero::<ID_LENGTH>(route_context_id, "route_context_id")?;
    if reservation_id == route_context_id {
        return Err(ProtocolError::InvalidField("distinct reservation ids"));
    }
    require_nonzero::<KEY_LENGTH>(client_session_id, "client_session_id")
}

fn validate_session_key(session_id: &[u8], public_key: &[u8]) -> Result<(), ProtocolError> {
    require_nonzero::<KEY_LENGTH>(public_key, "client_session_public_key")?;
    let public_key: [u8; KEY_LENGTH] = public_key
        .try_into()
        .map_err(|_| ProtocolError::InvalidField("client_session_public_key"))?;
    if session_id != node_id_from_public_key(&public_key) {
        return Err(ProtocolError::InvalidField("client session key binding"));
    }
    Ok(())
}

fn validate_control_relay(node_id: &[u8], peer_id: &[u8]) -> Result<(), ProtocolError> {
    require_nonzero::<KEY_LENGTH>(node_id, "control_relay_node_id")?;
    validate_peer_id(peer_id, "control_relay_peer_id")
}

fn validate_masque_context(value: u64) -> Result<(), ProtocolError> {
    if value == 0 || value > crate::MAX_MASQUE_CONTEXT_ID {
        return Err(ProtocolError::InvalidField(
            "finalize_request.masque_context_id",
        ));
    }
    Ok(())
}

fn validate_nested(
    encoded: &[u8],
    expected: ControlMessageType,
    field: &'static str,
) -> Result<(), ProtocolError> {
    if encoded.is_empty() || encoded.len() > MAX_CONTROL_MESSAGE_SIZE {
        return Err(ProtocolError::InvalidField(field));
    }
    let envelope: SignedEnvelope = decode_canonical(encoded, MAX_CONTROL_MESSAGE_SIZE)?;
    if envelope.message_type != expected as i32 {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn validate_session_envelope(
    session_id: &[u8],
    timestamp_ms: u64,
    expires_at_ms: u64,
    nonce: &[u8],
    envelope: &SignedEnvelope,
    field: &'static str,
) -> Result<(), ProtocolError> {
    validate_signed_envelope(
        session_id,
        timestamp_ms,
        expires_at_ms,
        nonce,
        envelope,
        field,
    )
}

fn validate_signed_envelope(
    sender_id: &[u8],
    timestamp_ms: u64,
    expires_at_ms: u64,
    nonce: &[u8],
    envelope: &SignedEnvelope,
    field: &'static str,
) -> Result<(), ProtocolError> {
    if sender_id != envelope.sender_id
        || timestamp_ms != envelope.timestamp_ms
        || expires_at_ms != envelope.expires_at_ms
        || nonce != envelope.nonce
    {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn validate_peer_id(peer_id: &[u8], field: &'static str) -> Result<(), ProtocolError> {
    if peer_id.is_empty() || peer_id.len() > MAX_PEER_ID_LENGTH {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn validate_transports(transports: &[i32]) -> Result<(), ProtocolError> {
    if transports.is_empty() || transports.len() > MAX_TRANSPORTS {
        return Err(ProtocolError::InvalidField("allowed_transports"));
    }
    let mut previous = None;
    for value in transports {
        validate_transport(*value, "allowed_transports")?;
        if previous.is_some_and(|old| old >= *value) {
            return Err(ProtocolError::InvalidField("allowed_transports"));
        }
        previous = Some(*value);
    }
    Ok(())
}

fn validate_transport(value: i32, field: &'static str) -> Result<(), ProtocolError> {
    let transport = Transport::try_from(value).map_err(|_| ProtocolError::InvalidField(field))?;
    if transport == Transport::Unspecified {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn validate_family(value: i32, field: &'static str) -> Result<(), ProtocolError> {
    let family =
        ProbeAddressFamily::try_from(value).map_err(|_| ProtocolError::InvalidField(field))?;
    if family == ProbeAddressFamily::Unspecified {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}

fn validate_path_id(path_id: u32, field: &'static str) -> Result<(), ProtocolError> {
    if !(1..=u32::try_from(MAX_PATHS).unwrap_or(u32::MAX)).contains(&path_id) {
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

fn validate_lifetime(
    created_at_ms: u64,
    expires_at_ms: u64,
    maximum_ms: u64,
) -> Result<(), ProtocolError> {
    let lifetime = expires_at_ms
        .checked_sub(created_at_ms)
        .ok_or(ProtocolError::InvalidLifetime)?;
    if lifetime == 0 || lifetime > maximum_ms {
        return Err(ProtocolError::InvalidLifetime);
    }
    Ok(())
}

fn require_nonzero<const N: usize>(value: &[u8], field: &'static str) -> Result<(), ProtocolError> {
    if value.len() != N || value.iter().all(|byte| *byte == 0) {
        return Err(ProtocolError::InvalidField(field));
    }
    Ok(())
}
