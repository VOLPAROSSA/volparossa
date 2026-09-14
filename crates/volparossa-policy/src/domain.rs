use std::net::IpAddr;

use url::Host;

use crate::{
    MAX_DOMAIN_INPUT_BYTES, MAX_DOMAIN_NAME_BYTES, MAX_PERMISSIONS_PER_DESTINATION, PolicyError,
};

/// An Internet transport protocol that can be authorized by a policy rule.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub enum TransportProtocol {
    /// Transmission Control Protocol.
    Tcp,
    /// User Datagram Protocol, including QUIC carried over UDP.
    Udp,
}

impl TransportProtocol {
    pub(crate) const fn wire_value(self) -> i32 {
        match self {
            Self::Tcp => 1,
            Self::Udp => 2,
        }
    }

    pub(crate) fn from_wire(value: i32) -> Result<Self, PolicyError> {
        match value {
            1 => Ok(Self::Tcp),
            2 => Ok(Self::Udp),
            _ => Err(PolicyError::InvalidField("transport protocol")),
        }
    }
}

/// One exact protocol and destination-port combination.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub struct ProtocolPort {
    protocol: TransportProtocol,
    port: u16,
}

impl ProtocolPort {
    /// Construct a protocol/port permission.
    ///
    /// # Errors
    ///
    /// Port zero is rejected because it cannot identify a remote service.
    pub fn new(protocol: TransportProtocol, port: u16) -> Result<Self, PolicyError> {
        if port == 0 {
            return Err(PolicyError::InvalidPort(u32::from(port)));
        }
        Ok(Self { protocol, port })
    }

    /// Return the authorized transport protocol.
    #[must_use]
    pub const fn protocol(self) -> TransportProtocol {
        self.protocol
    }

    /// Return the exact authorized destination port.
    #[must_use]
    pub const fn port(self) -> u16 {
        self.port
    }

    pub(crate) fn from_wire(protocol: i32, port: u32) -> Result<Self, PolicyError> {
        let protocol = TransportProtocol::from_wire(protocol)?;
        let port = u16::try_from(port).map_err(|_| PolicyError::InvalidPort(port))?;
        Self::new(protocol, port)
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Destination {
    ExactDomain(String),
    WildcardDomain(String),
    ExactIp(IpAddr),
}

/// A normalized destination selector and its exact protocol/port permissions.
///
/// Exact domain rules match only the named host. Wildcard rules match one or
/// more complete labels below their suffix and never match the suffix apex.
/// IP rules match one exact address; domain rules never authorize a raw IP.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct DestinationRule {
    destination: Destination,
    permissions: Vec<ProtocolPort>,
}

impl DestinationRule {
    /// Construct an exact-domain rule after applying safe IDNA normalization.
    ///
    /// # Errors
    ///
    /// Returns an error for an invalid domain, an empty or oversized permission
    /// set, or a duplicate permission.
    pub fn exact_domain<I>(domain: &str, permissions: I) -> Result<Self, PolicyError>
    where
        I: IntoIterator<Item = ProtocolPort>,
    {
        Ok(Self {
            destination: Destination::ExactDomain(normalize_domain(domain)?),
            permissions: normalize_permissions(permissions)?,
        })
    }

    /// Construct a wildcard-domain rule such as `*.example.com`.
    ///
    /// The wildcard occupies exactly the complete left-most label. The suffix
    /// must itself contain at least two labels, preventing TLD-wide patterns.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed or overly broad wildcard syntax, an
    /// invalid suffix, or an invalid permission set.
    pub fn wildcard_domain<I>(pattern: &str, permissions: I) -> Result<Self, PolicyError>
    where
        I: IntoIterator<Item = ProtocolPort>,
    {
        let suffix = wildcard_suffix(pattern)?;
        Ok(Self {
            destination: Destination::WildcardDomain(suffix),
            permissions: normalize_permissions(permissions)?,
        })
    }

    /// Construct a rule for one exact IPv4 or IPv6 destination.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty, oversized, or duplicate permission set.
    pub fn exact_ip<I>(address: IpAddr, permissions: I) -> Result<Self, PolicyError>
    where
        I: IntoIterator<Item = ProtocolPort>,
    {
        Ok(Self {
            destination: Destination::ExactIp(address),
            permissions: normalize_permissions(permissions)?,
        })
    }

    /// Return the canonical ASCII name for an exact-domain rule.
    #[must_use]
    pub fn exact_domain_name(&self) -> Option<&str> {
        match &self.destination {
            Destination::ExactDomain(domain) => Some(domain),
            Destination::WildcardDomain(_) | Destination::ExactIp(_) => None,
        }
    }

    /// Return the canonical ASCII wildcard pattern, without allocating.
    ///
    /// The returned suffix excludes the leading `*.`. For example, a rule
    /// constructed from `*.example.com` returns `example.com`.
    #[must_use]
    pub fn wildcard_domain_suffix(&self) -> Option<&str> {
        match &self.destination {
            Destination::WildcardDomain(suffix) => Some(suffix),
            Destination::ExactDomain(_) | Destination::ExactIp(_) => None,
        }
    }

    /// Return the address for an exact-IP rule.
    #[must_use]
    pub fn exact_ip_address(&self) -> Option<IpAddr> {
        match &self.destination {
            Destination::ExactIp(address) => Some(*address),
            Destination::ExactDomain(_) | Destination::WildcardDomain(_) => None,
        }
    }

    /// Return the sorted, duplicate-free permissions for this destination.
    #[must_use]
    pub fn permissions(&self) -> &[ProtocolPort] {
        &self.permissions
    }

    pub(crate) fn matches_dns_name(&self, normalized: &str) -> bool {
        match &self.destination {
            Destination::ExactDomain(domain) => domain == normalized,
            Destination::WildcardDomain(suffix) => wildcard_matches(normalized, suffix),
            Destination::ExactIp(_) => false,
        }
    }

    pub(crate) fn is_allowed(&self, request: &NormalizedRequest) -> bool {
        if self.permissions.binary_search(&request.permission).is_err() {
            return false;
        }

        match (&self.destination, &request.destination) {
            (Destination::ExactDomain(rule), RequestDestination::Domain(requested)) => {
                rule == requested
            }
            (Destination::WildcardDomain(suffix), RequestDestination::Domain(requested)) => {
                wildcard_matches(requested, suffix)
            }
            (Destination::ExactIp(rule), RequestDestination::Ip(requested)) => rule == requested,
            (
                Destination::ExactDomain(_) | Destination::WildcardDomain(_),
                RequestDestination::Ip(_),
            )
            | (Destination::ExactIp(_), RequestDestination::Domain(_)) => false,
        }
    }

    pub(crate) fn destination_cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.destination.cmp(&other.destination)
    }

    pub(crate) fn exact_domain_wire(&self) -> Option<&str> {
        self.exact_domain_name()
    }

    pub(crate) fn wildcard_domain_wire(&self) -> Option<String> {
        self.wildcard_domain_suffix()
            .map(|suffix| format!("*.{suffix}"))
    }

    pub(crate) fn ip_wire(&self) -> Option<IpAddr> {
        self.exact_ip_address()
    }

    pub(crate) fn from_wire_exact_domain(
        domain: &str,
        permissions: Vec<ProtocolPort>,
    ) -> Result<Self, PolicyError> {
        let normalized = normalize_domain(domain)?;
        if normalized != domain {
            return Err(PolicyError::NonCanonicalSemantic("exact domain"));
        }
        Self::exact_domain(domain, permissions)
    }

    pub(crate) fn from_wire_wildcard_domain(
        pattern: &str,
        permissions: Vec<ProtocolPort>,
    ) -> Result<Self, PolicyError> {
        let suffix = wildcard_suffix(pattern)?;
        if pattern != format!("*.{suffix}") {
            return Err(PolicyError::NonCanonicalSemantic("wildcard domain"));
        }
        Self::wildcard_domain(pattern, permissions)
    }

    pub(crate) fn from_wire_ip(
        address: IpAddr,
        permissions: Vec<ProtocolPort>,
    ) -> Result<Self, PolicyError> {
        Self::exact_ip(address, permissions)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
enum RequestDestination {
    Domain(String),
    Ip(IpAddr),
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct NormalizedRequest {
    destination: RequestDestination,
    permission: ProtocolPort,
}

impl NormalizedRequest {
    pub(crate) fn domain(
        domain: &str,
        protocol: TransportProtocol,
        port: u16,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            destination: RequestDestination::Domain(normalize_domain(domain)?),
            permission: ProtocolPort::new(protocol, port)?,
        })
    }

    pub(crate) fn ip(
        address: IpAddr,
        protocol: TransportProtocol,
        port: u16,
    ) -> Result<Self, PolicyError> {
        Ok(Self {
            destination: RequestDestination::Ip(address),
            permission: ProtocolPort::new(protocol, port)?,
        })
    }
}

/// Normalize a DNS name to its lower-case ASCII IDNA representation.
///
/// A single trailing root dot is accepted and removed. URL syntax, wildcard
/// characters, raw IP spellings, empty labels, non-LDH output, and overlong
/// names or labels are rejected. The result is suitable for exact comparison.
///
/// # Errors
///
/// Returns [`PolicyError::InvalidDomain`] when the input is not a bounded DNS
/// hostname, and [`PolicyError::RawIpAsDomain`] when URL/IDNA host parsing
/// recognizes an IP address instead.
pub fn normalize_domain(input: &str) -> Result<String, PolicyError> {
    if input.is_empty() || input.len() > MAX_DOMAIN_INPUT_BYTES {
        return Err(PolicyError::InvalidDomain);
    }
    if input.chars().any(|character| {
        character.is_whitespace()
            || character.is_control()
            || matches!(
                character,
                '*' | '%' | '/' | '\\' | '@' | ':' | '#' | '?' | '[' | ']'
            )
    }) {
        return Err(PolicyError::InvalidDomain);
    }

    let mut domain = match Host::parse(input).map_err(|_| PolicyError::InvalidDomain)? {
        Host::Domain(domain) => domain,
        Host::Ipv4(_) | Host::Ipv6(_) => return Err(PolicyError::RawIpAsDomain),
    };
    domain.make_ascii_lowercase();
    if domain.ends_with('.') {
        domain.pop();
    }

    if domain.is_empty()
        || domain.len() > MAX_DOMAIN_NAME_BYTES
        || domain.starts_with('.')
        || domain.ends_with('.')
    {
        return Err(PolicyError::InvalidDomain);
    }

    for label in domain.split('.') {
        if label.is_empty()
            || label.len() > 63
            || label.starts_with('-')
            || label.ends_with('-')
            || !label
                .bytes()
                .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
        {
            return Err(PolicyError::InvalidDomain);
        }
    }

    Ok(domain)
}

fn wildcard_suffix(pattern: &str) -> Result<String, PolicyError> {
    let suffix = pattern
        .strip_prefix("*.")
        .ok_or(PolicyError::InvalidWildcard)?;
    if suffix.contains('*') {
        return Err(PolicyError::InvalidWildcard);
    }
    let suffix = normalize_domain(suffix).map_err(|_| PolicyError::InvalidWildcard)?;
    if !suffix.contains('.') {
        return Err(PolicyError::InvalidWildcard);
    }
    Ok(suffix)
}

fn normalize_permissions<I>(permissions: I) -> Result<Vec<ProtocolPort>, PolicyError>
where
    I: IntoIterator<Item = ProtocolPort>,
{
    let mut normalized = Vec::new();
    for permission in permissions {
        if normalized.len() == MAX_PERMISSIONS_PER_DESTINATION {
            return Err(PolicyError::TooManyItems {
                what: "protocol/port permissions per destination",
                maximum: MAX_PERMISSIONS_PER_DESTINATION,
            });
        }
        normalized.push(permission);
    }
    if normalized.is_empty() {
        return Err(PolicyError::InvalidField("empty permission set"));
    }
    normalized.sort_unstable();
    if normalized.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(PolicyError::DuplicateItem("protocol/port permission"));
    }
    Ok(normalized)
}

fn wildcard_matches(domain: &str, suffix: &str) -> bool {
    domain
        .strip_suffix(suffix)
        .is_some_and(|prefix| prefix.ends_with('.') && prefix.len() > 1)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn normalizes_idna_case_and_root_dot() {
        assert_eq!(
            normalize_domain("BÜCHER.Example.").unwrap(),
            "xn--bcher-kva.example"
        );
    }

    #[test]
    fn domain_parser_rejects_ip_and_url_syntax() {
        assert!(matches!(
            normalize_domain("127.0.0.1"),
            Err(PolicyError::RawIpAsDomain)
        ));
        assert!(matches!(
            normalize_domain("127.1"),
            Err(PolicyError::RawIpAsDomain)
        ));
        assert!(normalize_domain("https://example.com").is_err());
        assert!(normalize_domain("user@example.com").is_err());
        assert!(normalize_domain("example.com/path").is_err());
        assert!(normalize_domain("example%2ecom").is_err());
    }

    #[test]
    fn wildcard_uses_label_boundary_and_excludes_apex() {
        assert!(wildcard_matches("www.example.com", "example.com"));
        assert!(wildcard_matches("deep.www.example.com", "example.com"));
        assert!(!wildcard_matches("example.com", "example.com"));
        assert!(!wildcard_matches("badexample.com", "example.com"));
    }
}
