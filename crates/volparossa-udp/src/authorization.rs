use std::{
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};

use subtle::ConstantTimeEq;
use tokio::net::lookup_host;
use volparossa_policy::{TransportProtocol, VerifiedManifest};
use volparossa_protocol::{
    ReplayCache, TimePolicy, UdpFlowAuthorization, VerifiedControlMessage, verify_control_message,
};

use crate::{UdpError, VerifiedSingleRelayPath};

const ROUTE_CONTEXT_BYTES: usize = 16;
const CLIENT_ID_BYTES: usize = 32;
const FLOW_ID_BYTES: usize = 16;
const MAX_RESOLUTION_RESULTS: usize = 16;

/// Route and whitelist scope for one client-signed UDP flow grant.
pub struct UdpAuthorizationScope<'a> {
    route_context_id: [u8; ROUTE_CONTEXT_BYTES],
    client_ephemeral_id: [u8; CLIENT_ID_BYTES],
    route_expires_at_ms: u64,
    policy: &'a VerifiedManifest,
}

impl<'a> UdpAuthorizationScope<'a> {
    /// Bind authorization to one verified relay path and active policy.
    #[must_use]
    pub fn new(path: &VerifiedSingleRelayPath, policy: &'a VerifiedManifest) -> Self {
        Self {
            route_context_id: *path.route_context_id(),
            client_ephemeral_id: *path.client_ephemeral_id(),
            route_expires_at_ms: path.expires_at_ms(),
            policy,
        }
    }

    /// Bind authorization to a previously verified multipath route and active policy.
    ///
    /// This constructor exists for CONNECT-IP transports whose route proof is an exact set of
    /// relay grants rather than a [`VerifiedSingleRelayPath`]. Callers must derive all three
    /// values from the same retained verified route owner; the signed flow is still checked
    /// against the ephemeral Client identity, route context, expiry and policy below.
    ///
    /// # Errors
    ///
    /// Rejects zero identities or a zero route expiry.
    pub fn new_multipath(
        route_context_id: [u8; ROUTE_CONTEXT_BYTES],
        client_ephemeral_id: [u8; CLIENT_ID_BYTES],
        route_expires_at_ms: u64,
        policy: &'a VerifiedManifest,
    ) -> Result<Self, UdpError> {
        if route_context_id.iter().all(|byte| *byte == 0)
            || client_ephemeral_id.iter().all(|byte| *byte == 0)
            || route_expires_at_ms == 0
        {
            return Err(UdpError::InvalidBinding("multipath route scope"));
        }
        Ok(Self {
            route_context_id,
            client_ephemeral_id,
            route_expires_at_ms,
            policy,
        })
    }

    /// Verify a signed, replay-protected flow and its exact policy hash and
    /// domain-or-IP/UDP/port tuple.
    ///
    /// # Errors
    ///
    /// Fails closed for malformed input, invalid signature, replay, expiry,
    /// route/client mismatch, stale policy, hash mismatch, or denied tuple.
    pub fn verify(
        &self,
        encoded: &[u8],
        now_ms: u64,
        time_policy: TimePolicy,
        replay_cache: &mut ReplayCache,
    ) -> Result<AuthorizedUdpFlow, UdpError> {
        let verified = verify_control_message::<UdpFlowAuthorization>(
            encoded,
            now_ms,
            time_policy,
            replay_cache,
        )?;
        let replay_key = (*verified.sender_id(), *verified.nonce());
        let authorized = self.authorize_verified(&verified, now_ms);
        if authorized.is_err() {
            let _ = replay_cache.rollback(&replay_key.0, &replay_key.1);
        }
        authorized
    }

    fn authorize_verified(
        &self,
        verified: &VerifiedControlMessage<UdpFlowAuthorization>,
        now_ms: u64,
    ) -> Result<AuthorizedUdpFlow, UdpError> {
        let message = verified.message();
        same(
            &message.route_context_id,
            &self.route_context_id,
            "route context",
        )?;
        same(
            &message.client_ephemeral_id,
            &self.client_ephemeral_id,
            "client session identity",
        )?;
        same(
            verified.sender_id(),
            &self.client_ephemeral_id,
            "signed client identity",
        )?;
        same(
            &message.policy_hash,
            self.policy.policy_hash(),
            "policy hash",
        )?;
        let port = u16::try_from(message.port)
            .map_err(|_| UdpError::InvalidBinding("destination port"))?;

        let destination = if message.hostname.is_empty() {
            let address = parse_ip(&message.destination_ip)?;
            self.policy
                .authorize_ip(now_ms, address, TransportProtocol::Udp, port)?;
            AuthorizedDestination::Ip(address)
        } else if port == 53 {
            let hostname = self.policy.authorize_dns_name(now_ms, &message.hostname)?;
            AuthorizedDestination::DnsHostname(hostname)
        } else {
            self.policy.authorize_domain(
                now_ms,
                &message.hostname,
                TransportProtocol::Udp,
                port,
            )?;
            AuthorizedDestination::Hostname(message.hostname.clone())
        };

        Ok(AuthorizedUdpFlow {
            route_context_id: array(&message.route_context_id, "route context")?,
            flow_id: array(&message.flow_id, "flow id")?,
            client_ephemeral_id: array(&message.client_ephemeral_id, "client session identity")?,
            destination,
            port,
            idle_timeout: Duration::from_millis(u64::from(message.idle_timeout_ms)),
            expires_at_ms: verified.expires_at_ms().min(self.route_expires_at_ms),
        })
    }
}

enum AuthorizedDestination {
    Hostname(String),
    DnsHostname(String),
    Ip(IpAddr),
}

/// A signed, policy-approved UDP flow whose tuple and idle timeout cannot be
/// changed after construction.
pub struct AuthorizedUdpFlow {
    route_context_id: [u8; ROUTE_CONTEXT_BYTES],
    flow_id: [u8; FLOW_ID_BYTES],
    client_ephemeral_id: [u8; CLIENT_ID_BYTES],
    destination: AuthorizedDestination,
    port: u16,
    idle_timeout: Duration,
    expires_at_ms: u64,
}

impl AuthorizedUdpFlow {
    /// Return the fixed route context.
    #[must_use]
    pub const fn route_context_id(&self) -> &[u8; ROUTE_CONTEXT_BYTES] {
        &self.route_context_id
    }

    /// Return the short-lived flow identifier used in every datagram frame.
    #[must_use]
    pub const fn flow_id(&self) -> &[u8; FLOW_ID_BYTES] {
        &self.flow_id
    }

    /// Return the signed ephemeral client identity.
    #[must_use]
    pub const fn client_ephemeral_id(&self) -> &[u8; CLIENT_ID_BYTES] {
        &self.client_ephemeral_id
    }

    /// Return the exact allowed destination port without exposing the name.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Return the immutable association idle timeout.
    #[must_use]
    pub const fn idle_timeout(&self) -> Duration {
        self.idle_timeout
    }

    /// Return the earliest signed flow/route expiry.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Return whether this authorization pins one exact raw-IP destination tuple.
    ///
    /// The method intentionally reveals no stored destination. It lets transparent ingress prove
    /// that the signed authorization exactly matches kernel original-destination evidence before
    /// a protected association is activated.
    #[must_use]
    pub fn matches_exact_ip_destination(&self, destination: SocketAddr) -> bool {
        self.port == destination.port()
            && matches!(self.destination, AuthorizedDestination::Ip(address) if address == destination.ip())
    }

    /// Return whether this is the dedicated protected DNS service for one exact signed name.
    #[must_use]
    pub fn matches_dns_name(&self, hostname: &str) -> bool {
        self.port == 53
            && matches!(&self.destination, AuthorizedDestination::DnsHostname(name) if name == hostname)
    }

    pub(crate) fn dns_name(&self) -> Option<&str> {
        match &self.destination {
            AuthorizedDestination::DnsHostname(name) => Some(name),
            AuthorizedDestination::Hostname(_) | AuthorizedDestination::Ip(_) => None,
        }
    }

    /// Fail closed before creating an association from a stale authorization.
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

    /// Resolve an authorized hostname at the exit and pin one acceptable
    /// address for the complete association. Exact-IP grants are pinned without
    /// DNS. No destination mutation API is exposed afterward.
    ///
    /// # Errors
    ///
    /// Returns an error when resolution fails, exceeds its scan bound before
    /// finding an Internet-unicast result, or yields only loopback, private,
    /// link-local, multicast, documentation, or reserved addresses.
    pub async fn resolve_and_pin(&self, now_ms: u64) -> Result<PinnedUdpFlow, UdpError> {
        self.ensure_active_at(now_ms)?;
        let address = match &self.destination {
            AuthorizedDestination::Ip(address) => {
                if !is_permitted_egress(*address) {
                    return Err(UdpError::ResolutionFailed);
                }
                *address
            }
            AuthorizedDestination::Hostname(hostname) => {
                let addresses = lookup_host((hostname.as_str(), self.port)).await?;
                addresses
                    .take(MAX_RESOLUTION_RESULTS)
                    .map(|socket| socket.ip())
                    .find(|address| is_permitted_egress(*address))
                    .ok_or(UdpError::ResolutionFailed)?
            }
            AuthorizedDestination::DnsHostname(_) => {
                return Err(UdpError::InvalidBinding("DNS flow cannot open UDP egress"));
            }
        };
        Ok(PinnedUdpFlow {
            flow_id: self.flow_id,
            destination: SocketAddr::new(address, self.port),
            expires_at_ms: self.expires_at_ms,
        })
    }

    #[cfg(test)]
    pub(crate) fn test_flow(idle_timeout: Duration, expires_at_ms: u64) -> Self {
        Self::test_flow_to(
            SocketAddr::new(IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34)), 12_345),
            idle_timeout,
            expires_at_ms,
        )
    }

    #[cfg(test)]
    pub(crate) fn test_flow_to(
        destination: SocketAddr,
        idle_timeout: Duration,
        expires_at_ms: u64,
    ) -> Self {
        Self {
            route_context_id: [2; ROUTE_CONTEXT_BYTES],
            flow_id: [6; FLOW_ID_BYTES],
            client_ephemeral_id: [5; CLIENT_ID_BYTES],
            destination: AuthorizedDestination::Ip(destination.ip()),
            port: destination.port(),
            idle_timeout,
            expires_at_ms,
        }
    }
}

impl fmt::Debug for AuthorizedUdpFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedUdpFlow")
            .field("destination", &"<redacted>")
            .field("idle_timeout", &self.idle_timeout)
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

/// Exit-side immutable socket tuple derived from an authorized flow.
///
/// The address is intentionally omitted from `Debug` output.
pub struct PinnedUdpFlow {
    flow_id: [u8; FLOW_ID_BYTES],
    destination: SocketAddr,
    expires_at_ms: u64,
}

impl PinnedUdpFlow {
    /// Return the flow identifier shared with the QUIC datagram association.
    #[must_use]
    pub const fn flow_id(&self) -> &[u8; FLOW_ID_BYTES] {
        &self.flow_id
    }

    /// Return the exit-only connected-socket tuple. Callers must not persist or
    /// log this value.
    #[must_use]
    pub const fn destination(&self) -> SocketAddr {
        self.destination
    }

    /// Return the signed exclusive expiry.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    #[cfg(test)]
    pub(crate) fn test_pin(flow: &AuthorizedUdpFlow, destination: SocketAddr) -> Self {
        Self {
            flow_id: *flow.flow_id(),
            destination,
            expires_at_ms: flow.expires_at_ms(),
        }
    }
}

impl fmt::Debug for PinnedUdpFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PinnedUdpFlow")
            .field("destination", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
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

fn parse_ip(bytes: &[u8]) -> Result<IpAddr, UdpError> {
    match bytes.len() {
        4 => Ok(IpAddr::V4(Ipv4Addr::new(
            bytes[0], bytes[1], bytes[2], bytes[3],
        ))),
        16 => {
            let octets: [u8; 16] = bytes
                .try_into()
                .map_err(|_| UdpError::InvalidBinding("destination IP"))?;
            Ok(IpAddr::V6(Ipv6Addr::from(octets)))
        }
        _ => Err(UdpError::InvalidBinding("destination IP")),
    }
}

pub(crate) fn is_permitted_egress(address: IpAddr) -> bool {
    match address {
        IpAddr::V4(address) => permitted_v4(address),
        IpAddr::V6(address) => permitted_v6(address),
    }
}

fn permitted_v4(address: Ipv4Addr) -> bool {
    let [first, second, _, _] = address.octets();
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_private()
        || address.is_link_local()
        || address.is_multicast()
        || address.is_broadcast()
        || address.is_documentation()
        || first == 0
        || first >= 240
        || (first == 100 && (64..=127).contains(&second))
        || (first == 198 && (18..=19).contains(&second)))
}

fn permitted_v6(address: Ipv6Addr) -> bool {
    if let Some(mapped) = address.to_ipv4_mapped() {
        return permitted_v4(mapped);
    }
    !(address.is_unspecified()
        || address.is_loopback()
        || address.is_multicast()
        || address.is_unique_local()
        || address.is_unicast_link_local()
        || address.segments()[..2] == [0x2001, 0x0db8])
}

#[cfg(test)]
mod tests {
    use super::is_permitted_egress;
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

    #[test]
    fn egress_address_filter_rejects_host_and_reserved_ranges() {
        assert!(!is_permitted_egress(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(!is_permitted_egress(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))));
        assert!(!is_permitted_egress(IpAddr::V4(Ipv4Addr::new(
            192, 0, 2, 1
        ))));
        assert!(!is_permitted_egress(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        assert!(is_permitted_egress(IpAddr::V4(Ipv4Addr::new(
            93, 184, 216, 34
        ))));
    }
}
