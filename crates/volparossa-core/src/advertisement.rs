use crate::{
    CapacityError, CapacitySnapshot, IpFamily, NodeId, OperatorId, PROTOCOL_VERSION, PeerId,
    PolicyHash, ServiceRole, Transport, UnixTime,
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;
use thiserror::Error;

/// Maximum accepted lifetime for an advertisement.
pub const MAX_ADVERTISEMENT_TTL_SECONDS: u64 = 900;
/// Maximum number of control-plane endpoints in one advertisement.
pub const MAX_ADVERTISEMENT_ENDPOINTS: usize = 16;
const MAX_ENDPOINT_BYTES: usize = 512;

/// Independently enabled node roles.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeRoles {
    /// Whether the node operates as a normal client.
    pub client: bool,
    /// Whether voluntary forwarding is explicitly enabled.
    pub relay: bool,
    /// Whether policy-enforcing Internet egress is explicitly enabled.
    pub exit: bool,
}

impl NodeRoles {
    /// Returns whether a service role is enabled.
    #[must_use]
    pub const fn supports(self, role: ServiceRole) -> bool {
        match role {
            ServiceRole::Relay => self.relay,
            ServiceRole::Exit => self.exit,
        }
    }
}

/// Dataplane and address-family capabilities.
// Each flag is an independently advertised stable wire capability; collapsing them into a state
// enum would prevent representing valid combinations across transports and address families.
#[allow(clippy::struct_excessive_bools, reason = "stable capability schema")]
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct NodeCapabilities {
    /// Genuine Linux MPTCP transport support.
    pub tcp_mptcp: bool,
    /// Protected single-path UDP-over-QUIC support.
    pub udp_single_path: bool,
    /// Genuine Multipath QUIC support.
    pub multipath_quic: bool,
    /// IPv4 dataplane support.
    pub ipv4: bool,
    /// IPv6 dataplane support.
    pub ipv6: bool,
    /// Coordinated UDP hole-punching support.
    pub udp_hole_punching: bool,
}

impl NodeCapabilities {
    /// Returns whether the exact requested transport is supported.
    #[must_use]
    pub const fn supports_transport(self, transport: Transport) -> bool {
        match transport {
            Transport::TcpMptcp => self.tcp_mptcp,
            Transport::UdpSinglePath => self.udp_single_path,
            Transport::MultipathQuic => self.multipath_quic,
        }
    }

    /// Returns whether an address family is supported.
    #[must_use]
    pub const fn supports_family(self, family: IpFamily) -> bool {
        match family {
            IpFamily::Ipv4 => self.ipv4,
            IpFamily::Ipv6 => self.ipv6,
        }
    }
}

/// Operator-declared uplink capability, never proof of runtime reachability.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum NetworkUplink {
    /// Operator-declared independent Internet connectivity; not a runtime reachability proof.
    #[default]
    IndependentInternet,
    /// Only local peer links are available, so offering Exit egress is forbidden.
    LocalOnly,
}

/// Network-origin metadata used only as fallible anti-Sybil evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct NetworkMetadata {
    /// Declared uplink capability, distinct from observed transport origin.
    #[serde(default)]
    pub uplink: NetworkUplink,
    /// Operator identity claimed by the node.
    pub operator_id: OperatorId,
    /// Region label, such as `eu-west`.
    pub region: String,
    /// Upper-case ISO 3166-1 alpha-2 country code.
    pub country_code: String,
    /// Autonomous system number when known.
    pub asn: Option<u32>,
    /// Untrusted advertised IPv4 prefix hint used only for cheap discovery.
    pub ipv4_prefix_hint: Option<String>,
    /// Untrusted advertised IPv6 prefix hint used only for cheap discovery.
    pub ipv6_prefix_hint: Option<String>,
}

/// A network origin derived from an endpoint observed by the local node.
///
/// This is deliberately separate from signed [`NetworkMetadata`], because a
/// self-advertised prefix is not evidence for diversity enforcement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct ObservedNetworkOrigin {
    /// Locally observed public peer address.
    pub address: IpAddr,
}

impl ObservedNetworkOrigin {
    /// Returns the observed IPv4 /24 key used by diversity enforcement.
    #[must_use]
    pub fn ipv4_24(&self) -> Option<[u8; 3]> {
        match self.address {
            IpAddr::V4(address) => {
                let octets = address.octets();
                Some([octets[0], octets[1], octets[2]])
            }
            IpAddr::V6(_) => None,
        }
    }

    /// Returns the observed IPv6 /48 key used by diversity enforcement.
    #[must_use]
    pub fn ipv6_48(&self) -> Option<[u8; 6]> {
        match self.address {
            IpAddr::V6(address) => {
                let octets = address.octets();
                Some([
                    octets[0], octets[1], octets[2], octets[3], octets[4], octets[5],
                ])
            }
            IpAddr::V4(_) => None,
        }
    }
}

/// Short-lived quality claims from an advertisement.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct NodeQuality {
    /// Local uptime at measurement time.
    pub local_uptime_seconds: u64,
    /// Historical uptime ratio in the inclusive range 0 through 1.
    pub historical_uptime_score: f64,
    /// Historical p25 delivery ratio in the inclusive range 0 through 1.
    pub historical_delivery_ratio_p25: f64,
}

/// A bounded unsigned advertisement body after wire decoding.
///
/// Signature bytes and signature verification live in the protocol layer.  A
/// selection candidate separately records that verification succeeded so this
/// self-asserted body can never mark itself as verified.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct NodeAdvertisement {
    /// Protocol version used to encode this advertisement.
    pub protocol_version: u16,
    /// Permanent node identity.
    pub node_id: NodeId,
    /// Derived libp2p peer identity.
    pub peer_id: PeerId,
    /// Strictly increasing per-node sequence number.
    pub sequence_number: u64,
    /// Explicitly enabled roles.
    pub roles: NodeRoles,
    /// Supported transports and address families.
    pub capabilities: NodeCapabilities,
    /// Claimed short-lived capacity.
    pub capacity: CapacitySnapshot,
    /// Fallible network-origin metadata.
    pub network: NetworkMetadata,
    /// Fallible short-lived quality claims.
    pub quality: NodeQuality,
    /// Exact active whitelist manifest hash.
    pub policy_hash: PolicyHash,
    /// Control-plane multiaddresses, bounded before persistence.
    pub control_endpoints: Vec<String>,
    /// Measurement timestamp.
    pub measured_at: UnixTime,
    /// Hard advertisement expiry.
    pub expires_at: UnixTime,
}

impl NodeAdvertisement {
    /// Validates bounds, consistency, version and expiry at a given instant.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported versions, invalid lifetimes, malformed bounded metadata,
    /// invalid quality ratios, or inconsistent capacity claims.
    pub fn validate_at(&self, now: UnixTime) -> Result<(), AdvertisementError> {
        if self.protocol_version != PROTOCOL_VERSION {
            return Err(AdvertisementError::UnsupportedProtocolVersion);
        }
        if self.expires_at.is_expired_at(now) {
            return Err(AdvertisementError::Expired);
        }
        if self.expires_at <= self.measured_at
            || self.expires_at.as_secs() - self.measured_at.as_secs()
                > MAX_ADVERTISEMENT_TTL_SECONDS
        {
            return Err(AdvertisementError::InvalidLifetime);
        }
        if self.control_endpoints.is_empty()
            || self.control_endpoints.len() > MAX_ADVERTISEMENT_ENDPOINTS
            || self.control_endpoints.iter().any(|endpoint| {
                endpoint.is_empty()
                    || endpoint.len() > MAX_ENDPOINT_BYTES
                    || endpoint.bytes().any(|byte| byte == 0 || !byte.is_ascii())
            })
        {
            return Err(AdvertisementError::InvalidEndpoint);
        }
        if self.network.region.is_empty()
            || self.network.region.len() > 32
            || !self.network.region.bytes().all(|byte| {
                byte.is_ascii_lowercase() || byte.is_ascii_digit() || matches!(byte, b'-' | b'_')
            })
        {
            return Err(AdvertisementError::InvalidRegion);
        }
        if self.network.country_code.len() != 2
            || !self
                .network
                .country_code
                .bytes()
                .all(|byte| byte.is_ascii_uppercase())
        {
            return Err(AdvertisementError::InvalidCountryCode);
        }
        if self.network.uplink == NetworkUplink::LocalOnly
            && (self.roles.exit
                || self.network.asn.is_some()
                || self.network.ipv4_prefix_hint.is_some()
                || self.network.ipv6_prefix_hint.is_some())
        {
            return Err(AdvertisementError::InvalidUplinkCapability);
        }
        for prefix_hint in [
            self.network.ipv4_prefix_hint.as_deref(),
            self.network.ipv6_prefix_hint.as_deref(),
        ]
        .into_iter()
        .flatten()
        {
            if prefix_hint.is_empty()
                || prefix_hint.len() > 64
                || !prefix_hint.bytes().all(|byte| byte.is_ascii_graphic())
            {
                return Err(AdvertisementError::InvalidPrefixHint);
            }
        }
        validate_ratio(self.quality.historical_uptime_score)?;
        validate_ratio(self.quality.historical_delivery_ratio_p25)?;
        self.capacity.validate()?;
        Ok(())
    }
}

fn validate_ratio(value: f64) -> Result<(), AdvertisementError> {
    if !value.is_finite() || !(0.0..=1.0).contains(&value) {
        return Err(AdvertisementError::InvalidQuality);
    }
    Ok(())
}

/// An advertisement validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AdvertisementError {
    /// A local-only advertisement claims an Internet Exit or invented public origin metadata.
    #[error("invalid uplink capability metadata")]
    InvalidUplinkCapability,
    /// The advertisement uses an unsupported protocol version.
    #[error("unsupported advertisement protocol version")]
    UnsupportedProtocolVersion,
    /// The advertisement has expired at the caller's current time.
    #[error("advertisement has expired")]
    Expired,
    /// The advertisement lifetime is inverted, empty or too long.
    #[error("invalid advertisement lifetime")]
    InvalidLifetime,
    /// The endpoint set is empty, oversized or contains unsafe text.
    #[error("invalid control endpoint")]
    InvalidEndpoint,
    /// The region label is not bounded canonical text.
    #[error("invalid region")]
    InvalidRegion,
    /// The country code is not two upper-case ASCII letters.
    #[error("invalid country code")]
    InvalidCountryCode,
    /// A self-advertised prefix hint is empty, oversized or unsafe text.
    #[error("invalid network prefix hint")]
    InvalidPrefixHint,
    /// A quality ratio is non-finite or outside 0 through 1.
    #[error("invalid quality ratio")]
    InvalidQuality,
    /// The capacity claim is inconsistent or implausible.
    #[error(transparent)]
    Capacity(#[from] CapacityError),
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Bandwidth;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    fn advertisement() -> NodeAdvertisement {
        NodeAdvertisement {
            protocol_version: PROTOCOL_VERSION,
            node_id: NodeId::new("node-1").expect("valid"),
            peer_id: PeerId::new("peer-1").expect("valid"),
            sequence_number: 7,
            roles: NodeRoles {
                client: true,
                relay: true,
                exit: false,
            },
            capabilities: NodeCapabilities {
                tcp_mptcp: true,
                udp_single_path: true,
                multipath_quic: true,
                ipv4: true,
                ipv6: true,
                udp_hole_punching: true,
            },
            capacity: CapacitySnapshot {
                relay_limit: Bandwidth::new(100, 100).expect("valid"),
                exit_limit: Bandwidth::default(),
                currently_reserved: Bandwidth::new(10, 10).expect("valid"),
                estimated_free: Bandwidth::new(80, 80).expect("valid"),
                active_relay_sessions: 1,
                active_exit_sessions: 0,
                free_relay_slots: 4,
                free_exit_slots: 0,
                sample_window_seconds: 15,
            },
            network: NetworkMetadata {
                uplink: NetworkUplink::IndependentInternet,
                operator_id: OperatorId::new("operator-a").expect("valid"),
                region: "eu-west".to_owned(),
                country_code: "NL".to_owned(),
                asn: Some(64500),
                ipv4_prefix_hint: Some("192.0.2.0/24".to_owned()),
                ipv6_prefix_hint: None,
            },
            quality: NodeQuality {
                local_uptime_seconds: 10_000,
                historical_uptime_score: 0.9,
                historical_delivery_ratio_p25: 0.8,
            },
            policy_hash: PolicyHash::from_bytes([7; 32]),
            control_endpoints: vec!["/ip4/192.0.2.10/udp/443/quic-v1".to_owned()],
            measured_at: UnixTime::from_secs(1_000),
            expires_at: UnixTime::from_secs(1_300),
        }
    }

    #[test]
    fn validates_well_formed_advertisement() {
        advertisement()
            .validate_at(UnixTime::from_secs(1_100))
            .expect("valid advertisement");
    }

    #[test]
    fn local_only_advertisement_has_no_exit_or_invented_origin() {
        let mut local = advertisement();
        local.network.uplink = NetworkUplink::LocalOnly;
        local.network.asn = None;
        local.network.ipv4_prefix_hint = None;
        local.network.ipv6_prefix_hint = None;
        local
            .validate_at(UnixTime::from_secs(1_100))
            .expect("truthful local relay");
        for mutation in 0..4 {
            let mut invalid = local.clone();
            match mutation {
                0 => invalid.roles.exit = true,
                1 => invalid.network.asn = Some(0),
                2 => invalid.network.ipv4_prefix_hint = Some("8.8.8.0/24".to_owned()),
                _ => invalid.network.ipv6_prefix_hint = Some("2606:4700:4700::/48".to_owned()),
            }
            assert_eq!(
                invalid.validate_at(UnixTime::from_secs(1_100)),
                Err(AdvertisementError::InvalidUplinkCapability)
            );
        }
    }

    #[test]
    fn expiry_is_fail_closed_at_boundary() {
        assert_eq!(
            advertisement().validate_at(UnixTime::from_secs(1_300)),
            Err(AdvertisementError::Expired)
        );
    }

    #[test]
    fn prefix_keys_are_derived_from_observed_addresses() {
        let ipv4 = ObservedNetworkOrigin {
            address: IpAddr::V4(Ipv4Addr::new(192, 0, 2, 10)),
        };
        assert_eq!(ipv4.ipv4_24(), Some([192, 0, 2]));
        let ipv6 = ObservedNetworkOrigin {
            address: IpAddr::V6("2001:db8:abcd:1234::1".parse::<Ipv6Addr>().expect("valid")),
        };
        assert_eq!(ipv6.ipv6_48(), Some([0x20, 0x01, 0x0d, 0xb8, 0xab, 0xcd]));
    }
}
