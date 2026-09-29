use std::{collections::BTreeSet, net::IpAddr, sync::Arc};

use crate::{
    AuthorizedUdpFlow, DatagramLimits, QuicUdpAssociation, UdpBridgeStats, UdpError,
    authorization::is_permitted_egress,
};
use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{
        DNSClass, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};

pub mod resolver;
use resolver::{DnsQuestion, DnsResolutionScope, DnsResolverError, ExitResolver};

/// Largest DNS request or response accepted by the protected DNS vertical.
pub const MAX_DNS_MESSAGE_BYTES: usize = 4_096;
/// Maximum sequential DNS queries on one originally authorized association.
pub const MAX_DNS_ASSOCIATION_QUERIES: u8 = 16;
const MAX_DNS_ANSWERS: usize = 16;
const MAX_DNS_BINDING_TTL_SECONDS: u32 = 30;

/// Resolve both address families using the same policy and complete route privacy exclusions.
/// Each family remains bounded by the resolver's common collection/fallback deadline.
///
/// # Errors
/// Rejects invalid names or a result without any permitted Internet-unicast address.
pub async fn resolve_hostname_addresses(
    resolver: &ExitResolver,
    scope: &DnsResolutionScope,
    hostname: &str,
) -> Result<Vec<IpAddr>, UdpError> {
    let v4 = DnsQuestion::new(hostname, DnsQueryType::A).map_err(|_| UdpError::ResolutionFailed)?;
    let v6 =
        DnsQuestion::new(hostname, DnsQueryType::Aaaa).map_err(|_| UdpError::ResolutionFailed)?;
    let (v4, v6) = tokio::join!(resolver.resolve(&v4, scope), resolver.resolve(&v6, scope));
    let addresses: BTreeSet<_> = v4
        .into_iter()
        .chain(v6)
        .flat_map(|answer| answer.addresses().to_vec())
        .filter(|address| is_permitted_egress(*address))
        .collect();
    if addresses.is_empty() {
        return Err(UdpError::ResolutionFailed);
    }
    Ok(addresses.into_iter().take(MAX_DNS_ANSWERS).collect())
}

/// DNS address-family question accepted by the protected resolver.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum DnsQueryType {
    /// IPv4 address records.
    A,
    /// IPv6 address records.
    Aaaa,
}

/// One bounded, single-question DNS request parsed from application wire bytes.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct BoundedDnsQuery {
    name: String,
    query_type: DnsQueryType,
}

impl BoundedDnsQuery {
    /// Return the canonical lower-case ASCII query name without a trailing root dot.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// Return whether this request asks for A or AAAA records.
    #[must_use]
    pub const fn query_type(&self) -> DnsQueryType {
        self.query_type
    }
}

/// Parse exactly one bounded IN/A or IN/AAAA query.
///
/// # Errors
///
/// Rejects oversized, malformed, response, update, multi-question, non-IN and non-address input.
pub fn parse_dns_query(payload: &[u8]) -> Result<BoundedDnsQuery, UdpError> {
    let (_, query) = parse_query_message(payload)?;
    Ok(query)
}

/// Correlate one protected DNS response with its sole outstanding request.
///
/// # Errors
/// Rejects a different transaction/name/type, malformed shape or oversized response.
pub fn validate_dns_response(request: &[u8], response: &[u8]) -> Result<(), UdpError> {
    let (request, _) = parse_query_message(request)?;
    if !(12..=MAX_DNS_MESSAGE_BYTES).contains(&response.len()) {
        return Err(UdpError::ResourceLimit);
    }
    let response =
        Message::from_vec(response).map_err(|_| UdpError::InvalidBinding("DNS response wire"))?;
    if response.id() != request.id()
        || response.message_type() != MessageType::Response
        || response.op_code() != OpCode::Query
        || response.truncated()
        || response.queries() != request.queries()
        || !matches!(
            response.response_code(),
            ResponseCode::NoError | ResponseCode::NXDomain
        )
        || !response.name_servers().is_empty()
        || !response.additionals().is_empty()
        || response.answers().len() > MAX_DNS_ANSWERS
    {
        return Err(UdpError::InvalidBinding("DNS response correlation"));
    }
    Ok(())
}

fn parse_query_message(payload: &[u8]) -> Result<(Message, BoundedDnsQuery), UdpError> {
    if !(12..=MAX_DNS_MESSAGE_BYTES).contains(&payload.len()) {
        return Err(UdpError::ResourceLimit);
    }
    let message = Message::from_vec(payload).map_err(|_| UdpError::InvalidBinding("DNS wire"))?;
    if message.message_type() != MessageType::Query
        || message.op_code() != OpCode::Query
        || message.response_code() != ResponseCode::NoError
        || message.truncated()
        || message.queries().len() != 1
        || !message.answers().is_empty()
        || !message.name_servers().is_empty()
        || !message.additionals().is_empty()
    {
        return Err(UdpError::InvalidBinding("DNS query shape"));
    }
    let question = &message.queries()[0];
    if question.query_class() != DNSClass::IN {
        return Err(UdpError::InvalidBinding("DNS query class"));
    }
    let query_type = match question.query_type() {
        RecordType::A => DnsQueryType::A,
        RecordType::AAAA => DnsQueryType::Aaaa,
        _ => return Err(UdpError::InvalidBinding("DNS query type")),
    };
    let name = volparossa_policy::normalize_domain(&question.name().to_ascii())?;
    Ok((message, BoundedDnsQuery { name, query_type }))
}

pub(crate) struct ExitDnsBridge {
    association: QuicUdpAssociation,
    expected_name: String,
    expires_at_ms: u64,
    limits: DatagramLimits,
    resolver: Arc<ExitResolver>,
    resolution_scope: DnsResolutionScope,
}

impl ExitDnsBridge {
    pub(crate) fn new(
        association: QuicUdpAssociation,
        flow: &AuthorizedUdpFlow,
        now_ms: u64,
        limits: DatagramLimits,
        resolver: Arc<ExitResolver>,
        resolution_scope: DnsResolutionScope,
    ) -> Result<Self, UdpError> {
        flow.ensure_active_at(now_ms)?;
        let expected_name = flow
            .dns_name()
            .ok_or(UdpError::InvalidBinding("DNS flow"))?
            .to_owned();
        Ok(Self {
            association,
            expected_name,
            expires_at_ms: flow.expires_at_ms(),
            limits,
            resolver,
            resolution_scope,
        })
    }

    pub(crate) async fn run(self) -> Result<UdpBridgeStats, UdpError> {
        let Self {
            association,
            expected_name,
            expires_at_ms,
            limits,
            resolver,
            resolution_scope,
        } = self;
        let result = async {
            let mut stats = UdpBridgeStats::default();
            for _ in 0..MAX_DNS_ASSOCIATION_QUERIES {
                let request = match association.receive_payload().await {
                    Ok(request) => request,
                    Err(UdpError::QuicConnection(quinn::ConnectionError::ApplicationClosed(
                        close,
                    ))) if close.error_code == quinn::VarInt::from_u32(0)
                        && stats.destination_to_tunnel_datagrams > 0 =>
                    {
                        return Ok(stats);
                    }
                    Err(UdpError::IdleTimeout) if stats.destination_to_tunnel_datagrams > 0 => {
                        return Ok(stats);
                    }
                    Err(error) => return Err(error),
                };
                if unix_millis()? >= expires_at_ms {
                    return Err(UdpError::Expired);
                }
                if request.len() > limits.maximum_payload_bytes() {
                    return Err(UdpError::ResourceLimit);
                }
                let query = parse_dns_query(&request)?;
                if query.name() != expected_name {
                    return Err(UdpError::InvalidBinding("signed DNS name"));
                }
                let question = DnsQuestion::new(query.name(), query.query_type())
                    .map_err(|_| UdpError::ResolutionFailed)?;
                let answer = resolver.resolve(&question, &resolution_scope).await;
                let now_ms = unix_millis()?;
                if now_ms >= expires_at_ms {
                    return Err(UdpError::Expired);
                }
                let response = match answer {
                    Ok(answer) => {
                        let remaining_seconds = expires_at_ms.saturating_sub(now_ms) / 1_000;
                        let ttl = u32::try_from(remaining_seconds)
                            .unwrap_or(u32::MAX)
                            .min(MAX_DNS_BINDING_TTL_SECONDS)
                            .min(answer.ttl_seconds());
                        // Never round an expired proof or sub-second route lifetime up to a fresh second.
                        if ttl == 0 {
                            return Err(UdpError::Expired);
                        }
                        build_response(&request, &expected_name, answer.addresses(), ttl)?
                    }
                    Err(DnsResolverError::NameNotFound) => {
                        build_negative_response(&request, &expected_name, ResponseCode::NXDomain)?
                    }
                    Err(DnsResolverError::NoData) => {
                        build_negative_response(&request, &expected_name, ResponseCode::NoError)?
                    }
                    Err(_) => return Err(UdpError::ResolutionFailed),
                };
                if response.len() > limits.maximum_payload_bytes() {
                    return Err(UdpError::ResourceLimit);
                }
                association.send_payload(&response)?;
                // At most 16 payloads of at most 4096 bytes, without an unbounded queue.
                stats.tunnel_to_destination_datagrams += 1;
                stats.destination_to_tunnel_datagrams += 1;
                stats.tunnel_to_destination_bytes +=
                    u64::try_from(request.len()).map_err(|_| UdpError::ResourceLimit)?;
                stats.destination_to_tunnel_bytes +=
                    u64::try_from(response.len()).map_err(|_| UdpError::ResourceLimit)?;
            }
            // Keep the last reply deliverable; the original signed/idle guard still closes
            // this association. No seventeenth request is read or resolved.
            association.wait_closed().await;
            Ok(stats)
        }
        .await;
        association.close();
        result
    }
}

// A trusted fallback denial is not a portable DNSSEC proof. No SOA/AD/cache lifetime is
// invented; retain the exact policy-bound question and transaction ID in this one reply.
fn build_negative_response(
    request: &[u8],
    expected_name: &str,
    code: ResponseCode,
) -> Result<Vec<u8>, UdpError> {
    if !matches!(code, ResponseCode::NXDomain | ResponseCode::NoError) {
        return Err(UdpError::InvalidBinding("DNS negative response"));
    }
    let (message, query) = parse_query_message(request)?;
    if query.name() != expected_name {
        return Err(UdpError::InvalidBinding("signed DNS name"));
    }
    let mut response = Message::new();
    response
        .set_id(message.id())
        .set_message_type(MessageType::Response)
        .set_recursion_desired(message.recursion_desired())
        .set_recursion_available(true)
        .set_response_code(code)
        .add_query(message.queries()[0].clone());
    response
        .to_vec()
        .map_err(|_| UdpError::InvalidBinding("DNS response wire"))
}

fn build_response(
    request: &[u8],
    expected_name: &str,
    addresses: &[IpAddr],
    ttl: u32,
) -> Result<Vec<u8>, UdpError> {
    if ttl == 0 || addresses.len() > MAX_DNS_ANSWERS {
        return Err(UdpError::ResourceLimit);
    }
    let (query_message, query) = parse_query_message(request)?;
    if query.name() != expected_name {
        return Err(UdpError::InvalidBinding("signed DNS name"));
    }
    let question = query_message.queries()[0].clone();
    let mut response = Message::new();
    response
        .set_id(query_message.id())
        .set_message_type(MessageType::Response)
        .set_op_code(OpCode::Query)
        .set_recursion_desired(query_message.recursion_desired())
        .set_recursion_available(true)
        .set_response_code(ResponseCode::NoError)
        .add_query(question.clone());
    for address in addresses {
        let data = match (query.query_type(), address) {
            (DnsQueryType::A, IpAddr::V4(address)) => RData::A(A::from(*address)),
            (DnsQueryType::Aaaa, IpAddr::V6(address)) => RData::AAAA(AAAA::from(*address)),
            _ => return Err(UdpError::InvalidBinding("DNS answer family")),
        };
        response.add_answer(Record::from_rdata(question.name().clone(), ttl, data));
    }
    let encoded = response
        .to_vec()
        .map_err(|_| UdpError::InvalidBinding("DNS response wire"))?;
    if encoded.len() > MAX_DNS_MESSAGE_BYTES {
        return Err(UdpError::ResourceLimit);
    }
    Ok(encoded)
}

fn unix_millis() -> Result<u64, UdpError> {
    use std::time::{SystemTime, UNIX_EPOCH};

    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| UdpError::InvalidBinding("system clock"))?
            .as_millis(),
    )
    .map_err(|_| UdpError::InvalidBinding("system clock"))
}

#[cfg(test)]
mod tests {
    use std::{
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        str::FromStr as _,
    };

    use hickory_proto::{
        op::{Message, MessageType, Query, ResponseCode},
        rr::{Name, RData, RecordType},
    };

    use super::{
        DnsQueryType, build_negative_response, build_response, parse_dns_query,
        validate_dns_response,
    };

    #[test]
    fn dns_reuse_response_requires_exact_pending_transaction_and_question() {
        let mut a = Message::new();
        a.set_id(7).add_query(Query::query(
            Name::from_str("allowed.example.").unwrap(),
            RecordType::A,
        ));
        let mut aaaa = Message::new();
        aaaa.set_id(8).add_query(Query::query(
            Name::from_str("allowed.example.").unwrap(),
            RecordType::AAAA,
        ));
        let a = a.to_vec().unwrap();
        let aaaa = aaaa.to_vec().unwrap();
        let a_reply =
            build_response(&a, "allowed.example", &["192.0.43.8".parse().unwrap()], 30).unwrap();
        let aaaa_reply = build_response(
            &aaaa,
            "allowed.example",
            &["2001:500:88:200::8".parse().unwrap()],
            30,
        )
        .unwrap();
        validate_dns_response(&a, &a_reply).unwrap();
        validate_dns_response(&aaaa, &aaaa_reply).unwrap();
        assert!(validate_dns_response(&aaaa, &a_reply).is_err());
        let mut same_id_wrong_family = a_reply.clone();
        same_id_wrong_family[..2].copy_from_slice(&8_u16.to_be_bytes());
        assert!(validate_dns_response(&aaaa, &same_id_wrong_family).is_err());
        assert!(validate_dns_response(&a, &a).is_err());
        assert!(validate_dns_response(&a, &vec![0; 4097]).is_err());
        let negative =
            build_negative_response(&a, "allowed.example", ResponseCode::NXDomain).unwrap();
        validate_dns_response(&a, &negative).unwrap();
    }

    #[test]
    fn bounded_dns_a_and_aaaa_roundtrip_preserves_question_and_short_binding() {
        for (record_type, address, expected_type) in [
            (
                RecordType::A,
                IpAddr::V4(Ipv4Addr::new(47, 163, 4, 2)),
                DnsQueryType::A,
            ),
            (
                RecordType::AAAA,
                IpAddr::V6(Ipv6Addr::from_str("2606:2800:220:1:248:1893:25c8:1946").unwrap()),
                DnsQueryType::Aaaa,
            ),
        ] {
            let name = Name::from_str("allowed.example.").unwrap();
            let mut request = Message::new();
            request
                .set_id(0x1234)
                .set_message_type(MessageType::Query)
                .set_recursion_desired(true)
                .add_query(Query::query(name.clone(), record_type));
            let request = request.to_vec().unwrap();
            let parsed = parse_dns_query(&request).unwrap();
            assert_eq!(parsed.name(), "allowed.example");
            assert_eq!(parsed.query_type(), expected_type);

            let encoded = build_response(&request, parsed.name(), &[address], 30).unwrap();
            let response = Message::from_vec(&encoded).unwrap();
            assert_eq!(response.id(), 0x1234);
            assert_eq!(response.message_type(), MessageType::Response);
            assert_eq!(response.queries(), request_message(&request).queries());
            assert_eq!(response.answers().len(), 1);
            assert_eq!(response.answers()[0].ttl(), 30);
            assert!(matches!(
                (expected_type, response.answers()[0].data()),
                (DnsQueryType::A, RData::A(_)) | (DnsQueryType::Aaaa, RData::AAAA(_))
            ));
        }
    }

    fn request_message(bytes: &[u8]) -> Message {
        Message::from_vec(bytes).unwrap()
    }

    #[test]
    fn dns_parser_rejects_multiple_questions_and_non_address_types() {
        let name = Name::from_str("allowed.example.").unwrap();
        let mut multiple = Message::new();
        multiple
            .add_query(Query::query(name.clone(), RecordType::A))
            .add_query(Query::query(name.clone(), RecordType::AAAA));
        assert!(parse_dns_query(&multiple.to_vec().unwrap()).is_err());

        let mut txt = Message::new();
        txt.add_query(Query::query(name, RecordType::TXT));
        assert!(parse_dns_query(&txt.to_vec().unwrap()).is_err());
    }

    #[test]
    fn trusted_negative_replies_keep_question_without_invented_dnssec_or_cache_ttl() {
        let mut request = Message::new();
        request.set_id(17).add_query(Query::query(
            Name::from_str("allowed.example.").unwrap(),
            RecordType::A,
        ));
        let raw = request.to_vec().unwrap();
        for code in [ResponseCode::NXDomain, ResponseCode::NoError] {
            let response =
                Message::from_vec(&build_negative_response(&raw, "allowed.example", code).unwrap())
                    .unwrap();
            assert_eq!(response.id(), 17);
            assert_eq!(response.queries(), request.queries());
            assert_eq!(response.response_code(), code);
            assert!(!response.authentic_data());
            assert!(response.answers().is_empty() && response.name_servers().is_empty());
        }
        assert!(
            build_negative_response(&raw, "different.example", ResponseCode::NXDomain).is_err()
        );
    }
}
