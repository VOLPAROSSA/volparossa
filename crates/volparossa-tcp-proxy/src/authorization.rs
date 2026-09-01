use std::{fmt, net::IpAddr};

use subtle::ConstantTimeEq;
use volparossa_policy::{TransportProtocol, VerifiedManifest};
use volparossa_protocol::{
    OpenTcp, ReplayCache, TimePolicy, VerifiedControlMessage, verify_control_message,
};

use crate::{TcpProxyError, VerifiedMptcpRoute};

const ROUTE_CONTEXT_BYTES: usize = 16;
const CLIENT_ID_BYTES: usize = 32;
const FLOW_ID_BYTES: usize = 16;

/// Exact route, client, and whitelist scope for one incoming `OPEN_TCP`.
pub struct TcpAuthorizationScope<'a> {
    route_context_id: [u8; ROUTE_CONTEXT_BYTES],
    client_ephemeral_id: [u8; CLIENT_ID_BYTES],
    policy: &'a VerifiedManifest,
}

impl<'a> TcpAuthorizationScope<'a> {
    /// Bind authorization to an already verified multipath route and policy.
    #[must_use]
    pub fn new(route: &VerifiedMptcpRoute, policy: &'a VerifiedManifest) -> Self {
        Self {
            route_context_id: *route.route_context_id(),
            client_ephemeral_id: *route.client_ephemeral_id(),
            policy,
        }
    }

    /// Verify a signed, replay-protected `OPEN_TCP` and apply the exact active
    /// policy hash and exact DNS-or-raw-IP/TCP/port rule.
    ///
    /// # Errors
    ///
    /// Fails closed for a protocol error, replay, scope mismatch, stale policy,
    /// hash mismatch, or denied destination tuple.
    pub fn verify(
        &self,
        encoded: &[u8],
        now_ms: u64,
        time_policy: TimePolicy,
        replay_cache: &mut ReplayCache,
    ) -> Result<AuthorizedTcpFlow, TcpProxyError> {
        let verified =
            verify_control_message::<OpenTcp>(encoded, now_ms, time_policy, replay_cache)?;
        let replay_key = (*verified.sender_id(), *verified.nonce());
        let authorized = self.authorize_verified(&verified, now_ms);
        if authorized.is_err() {
            let _ = replay_cache.rollback(&replay_key.0, &replay_key.1);
        }
        authorized
    }

    fn authorize_verified(
        &self,
        verified: &VerifiedControlMessage<OpenTcp>,
        now_ms: u64,
    ) -> Result<AuthorizedTcpFlow, TcpProxyError> {
        let message = verified.message();
        require_equal(
            &message.route_context_id,
            &self.route_context_id,
            "route context",
        )?;
        require_equal(
            &message.client_ephemeral_id,
            &self.client_ephemeral_id,
            "client session identity",
        )?;
        require_equal(
            verified.sender_id(),
            &self.client_ephemeral_id,
            "signed client identity",
        )?;
        require_equal(
            &message.policy_hash,
            self.policy.policy_hash(),
            "policy hash",
        )?;

        let port = u16::try_from(message.port)
            .map_err(|_| TcpProxyError::InvalidBinding("destination port"))?;
        let (hostname, destination_ip) = if !message.hostname.is_empty() {
            self.policy.authorize_domain(
                now_ms,
                &message.hostname,
                TransportProtocol::Tcp,
                port,
            )?;
            let destination_ip = if message.destination_ip.is_empty() {
                None
            } else {
                Some(
                    parse_ip_bytes(&message.destination_ip)
                        .ok_or(TcpProxyError::InvalidBinding("destination IP"))?,
                )
            };
            (Some(message.hostname.clone()), destination_ip)
        } else {
            let destination_ip = parse_ip_bytes(&message.destination_ip)
                .ok_or(TcpProxyError::InvalidBinding("destination IP"))?;
            self.policy
                .authorize_ip(now_ms, destination_ip, TransportProtocol::Tcp, port)?;
            (None, Some(destination_ip))
        };

        Ok(AuthorizedTcpFlow {
            route_context_id: to_array(&message.route_context_id, "route context")?,
            flow_id: to_array(&message.flow_id, "flow id")?,
            client_ephemeral_id: to_array(&message.client_ephemeral_id, "client session identity")?,
            hostname,
            destination_ip,
            port,
            expires_at_ms: verified.expires_at_ms(),
        })
    }
}

/// A short-lived TCP destination approved by signatures and the active policy.
///
/// This type deliberately redacts the destination from its `Debug` output.
pub struct AuthorizedTcpFlow {
    route_context_id: [u8; ROUTE_CONTEXT_BYTES],
    flow_id: [u8; FLOW_ID_BYTES],
    client_ephemeral_id: [u8; CLIENT_ID_BYTES],
    hostname: Option<String>,
    destination_ip: Option<IpAddr>,
    port: u16,
    expires_at_ms: u64,
}

impl AuthorizedTcpFlow {
    /// Return the fixed route context.
    #[must_use]
    pub const fn route_context_id(&self) -> &[u8; ROUTE_CONTEXT_BYTES] {
        &self.route_context_id
    }

    /// Return the short-lived flow identifier.
    #[must_use]
    pub const fn flow_id(&self) -> &[u8; FLOW_ID_BYTES] {
        &self.flow_id
    }

    /// Return the ephemeral client identity bound by the signature.
    #[must_use]
    pub const fn client_ephemeral_id(&self) -> &[u8; CLIENT_ID_BYTES] {
        &self.client_ephemeral_id
    }

    /// Return the canonical policy-approved hostname, when this is a DNS flow.
    /// Callers must not persist or log this value.
    #[must_use]
    pub fn hostname(&self) -> Option<&str> {
        self.hostname.as_deref()
    }

    /// Return the exact destination IP, when this is a raw-IP flow or a hostname flow pinned by
    /// transparent-ingress evidence. Callers must not persist or log this value.
    #[must_use]
    pub const fn destination_ip(&self) -> Option<IpAddr> {
        self.destination_ip
    }

    /// Return the exact policy-approved TCP port.
    #[must_use]
    pub const fn port(&self) -> u16 {
        self.port
    }

    /// Return the signed exclusive expiry time in Unix milliseconds.
    #[must_use]
    pub const fn expires_at_ms(&self) -> u64 {
        self.expires_at_ms
    }

    /// Fail closed if the flow may no longer be opened.
    ///
    /// # Errors
    ///
    /// Returns [`TcpProxyError::Expired`] at or after signed expiry.
    pub fn ensure_active_at(&self, now_ms: u64) -> Result<(), TcpProxyError> {
        if now_ms >= self.expires_at_ms {
            return Err(TcpProxyError::Expired);
        }
        Ok(())
    }
}

impl fmt::Debug for AuthorizedTcpFlow {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("AuthorizedTcpFlow")
            .field("destination", &"<redacted>")
            .field("expires_at_ms", &self.expires_at_ms)
            .finish_non_exhaustive()
    }
}

fn require_equal(left: &[u8], right: &[u8], field: &'static str) -> Result<(), TcpProxyError> {
    if left.len() != right.len() || left.ct_eq(right).unwrap_u8() != 1 {
        return Err(TcpProxyError::InvalidBinding(field));
    }
    Ok(())
}

fn to_array<const N: usize>(value: &[u8], field: &'static str) -> Result<[u8; N], TcpProxyError> {
    value
        .try_into()
        .map_err(|_| TcpProxyError::InvalidBinding(field))
}

fn parse_ip_bytes(value: &[u8]) -> Option<IpAddr> {
    match value.len() {
        4 => Some(IpAddr::V4(std::net::Ipv4Addr::new(
            value[0], value[1], value[2], value[3],
        ))),
        16 => {
            let octets: [u8; 16] = value.try_into().ok()?;
            Some(IpAddr::V6(std::net::Ipv6Addr::from(octets)))
        }
        _ => None,
    }
}
