use std::{fmt, future::Future, net::IpAddr, pin::Pin};

use hickory_proto::{
    op::Query,
    rr::{DNSClass, Name, RecordType},
};
use prost::Message;
use tokio::time::Instant;

use super::super::DnsQueryType;

/// Maximum canonical peer proof, including all embedded DNS messages.
pub const MAX_DNS_PROOF_BYTES: usize = 128 * 1024;
pub(super) const MAX_MESSAGES: usize = 32;
pub(super) const MAX_MESSAGE_BYTES: usize = 4096;

/// Fixed, privacy-safe resolution errors. No names or remote parser text are retained.
#[derive(Clone, Copy, Debug, Eq, PartialEq, thiserror::Error)]
pub enum DnsResolverError {
    /// The normalized question was not an IN/A or IN/AAAA name.
    #[error("DNS question invalid")]
    InvalidQuestion,
    /// Exclusion provenance is malformed or exceeds fixed bounds.
    #[error("DNS scope invalid")]
    InvalidScope,
    /// The proof was malformed, unsupported, incomplete, or not independently secure.
    #[error("DNS proof invalid")]
    InvalidProof,
    /// No permitted answer was available within the fixed time/resource bounds.
    #[error("DNS resolution unavailable")]
    Unavailable,
}

/// One normalized positive address question; debug output deliberately omits its name.
#[derive(Clone, Eq, PartialEq)]
pub struct DnsQuestion {
    name: String,
    kind: DnsQueryType,
}

impl fmt::Debug for DnsQuestion {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DnsQuestion")
            .field("kind", &self.kind)
            .finish_non_exhaustive()
    }
}

impl DnsQuestion {
    /// Normalize a hostname and bind its requested address family.
    /// # Errors
    /// Rejects malformed names and IP literals using the existing policy normalizer.
    pub fn new(name: &str, kind: DnsQueryType) -> Result<Self, DnsResolverError> {
        let name = volparossa_policy::normalize_domain(name)
            .map_err(|_| DnsResolverError::InvalidQuestion)?;
        Ok(Self { name, kind })
    }

    /// Canonical lower-case name without a root dot; never log it.
    pub fn name(&self) -> &str {
        &self.name
    }
    /// Requested address family.
    pub const fn query_type(&self) -> DnsQueryType {
        self.kind
    }

    pub(super) fn query(&self) -> Result<Query, DnsResolverError> {
        let name = Name::from_ascii(format!("{}.", self.name))
            .map_err(|_| DnsResolverError::InvalidQuestion)?;
        let mut query = Query::query(name, self.record_type());
        query.set_query_class(DNSClass::IN);
        Ok(query)
    }
    pub(super) const fn record_type(&self) -> RecordType {
        match self.kind {
            DnsQueryType::A => RecordType::A,
            DnsQueryType::Aaaa => RecordType::AAAA,
        }
    }
    pub(super) const fn matches_address(&self, ip: IpAddr) -> bool {
        matches!(
            (self.kind, ip),
            (DnsQueryType::A, IpAddr::V4(_)) | (DnsQueryType::Aaaa, IpAddr::V6(_))
        )
    }
}

/// Current policy and complete route-peer exclusions supplied by the authorized caller.
#[derive(Clone)]
pub struct DnsResolutionScope {
    policy: [u8; 32],
    exclusions: Vec<Vec<u8>>,
}

impl DnsResolutionScope {
    /// Permit peer exchange only with a nonempty bounded exclusion list.
    /// The caller must provide every involved control/data relay, not merely one peer.
    /// # Errors
    /// Rejects empty, oversized, duplicate, or malformed opaque peer encodings.
    pub fn new(
        policy_hash: [u8; 32],
        mut excluded_peers: Vec<Vec<u8>>,
    ) -> Result<Self, DnsResolverError> {
        if excluded_peers.is_empty()
            || excluded_peers.len() > 32
            || excluded_peers
                .iter()
                .any(|peer| peer.is_empty() || peer.len() > 128)
        {
            return Err(DnsResolverError::InvalidScope);
        }
        excluded_peers.sort();
        if excluded_peers.windows(2).any(|pair| pair[0] == pair[1]) {
            return Err(DnsResolverError::InvalidScope);
        }
        Ok(Self {
            policy: policy_hash,
            exclusions: excluded_peers,
        })
    }
    /// Retain local cache/upstream/OS resolution, but prohibit every peer request.
    pub const fn without_peers(policy_hash: [u8; 32]) -> Self {
        Self {
            policy: policy_hash,
            exclusions: Vec::new(),
        }
    }
    /// Current policy partition; DNS evidence does not grant policy authority.
    pub const fn policy_hash(&self) -> &[u8; 32] {
        &self.policy
    }
    /// Opaque authenticated peer IDs that must not receive the DNS question.
    pub fn excluded_peers(&self) -> &[Vec<u8>] {
        &self.exclusions
    }
    /// Whether complete exclusion provenance permits calling the peer backend.
    pub fn permits_peers(&self) -> bool {
        !self.exclusions.is_empty()
    }
}

/// Bounded authenticated-transport callback. Its output remains untrusted DNS evidence.
pub type DnsPeerFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Option<DnsProofBundle>, DnsResolverError>> + Send + 'a>>;

/// Implemented by the discovery actor; it must enforce all opaque exclusions.
pub trait DnsPeerBackend: Send + Sync {
    /// Query at most the backend's fixed peer bound; never publish names in the DHT.
    fn fetch<'a>(
        &'a self,
        question: &'a DnsQuestion,
        scope: &'a DnsResolutionScope,
    ) -> DnsPeerFuture<'a>;
}

#[derive(Clone, PartialEq, Message)]
pub(super) struct BundleWire {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    #[prost(string, tag = "2")]
    pub name: String,
    #[prost(uint32, tag = "3")]
    pub rrtype: u32,
    #[prost(uint64, tag = "4")]
    pub expires_at_ms: u64,
    #[prost(bytes = "vec", repeated, tag = "5")]
    pub messages: Vec<Vec<u8>>,
}

/// A canonical bounded proof envelope, not yet independently validated.
#[derive(Clone)]
pub struct DnsProofBundle {
    pub(super) wire: BundleWire,
    question: DnsQuestion,
}

impl DnsProofBundle {
    /// Decode bounded canonical protobuf and bounded DNS message shapes.
    /// # Errors
    /// Rejects oversized, noncanonical, unsupported, or malformed bundles.
    pub fn decode(bytes: &[u8]) -> Result<Self, DnsResolverError> {
        if bytes.is_empty() || bytes.len() > MAX_DNS_PROOF_BYTES {
            return Err(DnsResolverError::InvalidProof);
        }
        let wire = BundleWire::decode(bytes).map_err(|_| DnsResolverError::InvalidProof)?;
        if wire.encode_to_vec() != bytes {
            return Err(DnsResolverError::InvalidProof);
        }
        Self::from_wire(wire)
    }
    pub(super) fn from_wire(wire: BundleWire) -> Result<Self, DnsResolverError> {
        if wire.version != 1
            || wire.expires_at_ms == 0
            || wire.messages.is_empty()
            || wire.messages.len() > MAX_MESSAGES
            || wire.encoded_len() > MAX_DNS_PROOF_BYTES
        {
            return Err(DnsResolverError::InvalidProof);
        }
        let kind = match wire.rrtype {
            1 => DnsQueryType::A,
            28 => DnsQueryType::Aaaa,
            _ => return Err(DnsResolverError::InvalidProof),
        };
        let question = DnsQuestion::new(&wire.name, kind)?;
        if question.name() != wire.name {
            return Err(DnsResolverError::InvalidProof);
        }
        let mut count = 0;
        for bytes in &wire.messages {
            let message = super::proof::parse_message(bytes)?;
            count += message.answers().len()
                + message.name_servers().len()
                + message.additionals().len();
            if count > 256 {
                return Err(DnsResolverError::InvalidProof);
            }
        }
        Ok(Self { wire, question })
    }
    /// Canonical bounded bytes; contents must not be logged or persisted as browsing history.
    pub fn encode(&self) -> Vec<u8> {
        self.wire.encode_to_vec()
    }
    /// Exact question to which this untrusted evidence claims to answer.
    pub const fn question(&self) -> &DnsQuestion {
        &self.question
    }
    /// Immutable forwarding deadline, further constrained by independent DNSSEC validation.
    pub const fn expires_at_unix_ms(&self) -> u64 {
        self.wire.expires_at_ms
    }
    pub(super) fn bound_expiry(&mut self, limit: u64) {
        self.wire.expires_at_ms = self.wire.expires_at_ms.min(limit);
    }
}

/// How a usable answer was obtained; fallback is never labelled DNSSEC-validated.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsAnswerSource {
    /// Locally retained independently validated evidence.
    LocalValidated,
    /// Freshly and independently validated evidence from a peer.
    PeerValidated,
    /// Freshly validated evidence collected from the configured recursive resolver.
    UpstreamValidated,
    /// Existing trusted OS resolver semantics, without a shared DNSSEC-proof claim.
    TrustedFallback,
}

/// Usable addresses with a monotone remaining TTL and explicit proof/fallback provenance.
#[derive(Clone)]
pub struct ValidatedDnsAnswer {
    addresses: Vec<IpAddr>,
    deadline: Instant,
    source: DnsAnswerSource,
}

impl ValidatedDnsAnswer {
    pub(super) const fn new(
        addresses: Vec<IpAddr>,
        deadline: Instant,
        source: DnsAnswerSource,
    ) -> Self {
        Self {
            addresses,
            deadline,
            source,
        }
    }
    /// Complete bounded usable address list, not new egress authority.
    pub fn addresses(&self) -> &[IpAddr] {
        &self.addresses
    }
    /// Remaining complete seconds, never rounded up or renewed after expiration.
    pub fn ttl_seconds(&self) -> u32 {
        u32::try_from(
            self.deadline
                .saturating_duration_since(Instant::now())
                .as_secs(),
        )
        .unwrap_or(u32::MAX)
    }
    /// Distinguishes actual validation from the preserved trusted resolver fallback.
    pub const fn source(&self) -> DnsAnswerSource {
        self.source
    }
}
