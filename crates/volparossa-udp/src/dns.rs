use std::{collections::BTreeSet, net::IpAddr, time::Duration};

use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{
        DNSClass, RData, Record, RecordType,
        rdata::{A, AAAA},
    },
};
use tokio::{net::lookup_host, time::timeout};

use crate::{
    AuthorizedUdpFlow, DatagramLimits, QuicUdpAssociation, UdpBridgeStats, UdpError,
    authorization::is_permitted_egress,
};

/// Largest DNS request or response accepted by the protected DNS vertical.
pub const MAX_DNS_MESSAGE_BYTES: usize = 4_096;
const MAX_DNS_ANSWERS: usize = 16;
const DNS_RESOLUTION_TIMEOUT: Duration = Duration::from_secs(5);
const MAX_DNS_BINDING_TTL_SECONDS: u32 = 30;

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
}

impl ExitDnsBridge {
    pub(crate) fn new(
        association: QuicUdpAssociation,
        flow: &AuthorizedUdpFlow,
        now_ms: u64,
        limits: DatagramLimits,
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
        })
    }

    pub(crate) async fn run(self) -> Result<UdpBridgeStats, UdpError> {
        let Self {
            association,
            expected_name,
            expires_at_ms,
            limits,
        } = self;
        let result = async {
            let request = association.receive_payload().await?;
            if request.len() > limits.maximum_payload_bytes() {
                return Err(UdpError::ResourceLimit);
            }
            let query = parse_dns_query(&request)?;
            if query.name() != expected_name {
                return Err(UdpError::InvalidBinding("signed DNS name"));
            }
            let addresses = resolve_addresses(&query).await?;
            let now_ms = unix_millis()?;
            if now_ms >= expires_at_ms {
                return Err(UdpError::Expired);
            }
            let remaining_seconds = expires_at_ms.saturating_sub(now_ms) / 1_000;
            let ttl = u32::try_from(remaining_seconds)
                .unwrap_or(u32::MAX)
                .clamp(1, MAX_DNS_BINDING_TTL_SECONDS);
            let response = build_response(&request, &expected_name, &addresses, ttl)?;
            if response.len() > limits.maximum_payload_bytes() {
                return Err(UdpError::ResourceLimit);
            }
            association.send_payload(&response)?;
            association.wait_closed().await;
            Ok(UdpBridgeStats {
                tunnel_to_destination_datagrams: 1,
                destination_to_tunnel_datagrams: 1,
                tunnel_to_destination_bytes: u64::try_from(request.len())
                    .map_err(|_| UdpError::ResourceLimit)?,
                destination_to_tunnel_bytes: u64::try_from(response.len())
                    .map_err(|_| UdpError::ResourceLimit)?,
            })
        }
        .await;
        association.close();
        result
    }
}

async fn resolve_addresses(query: &BoundedDnsQuery) -> Result<Vec<IpAddr>, UdpError> {
    let absolute_name = format!("{}.", query.name());
    let resolved = timeout(
        DNS_RESOLUTION_TIMEOUT,
        lookup_host((absolute_name.as_str(), 0)),
    )
    .await
    .map_err(|_| UdpError::ResolutionFailed)??;
    let addresses = resolved
        .take(MAX_DNS_ANSWERS)
        .map(|socket| socket.ip())
        .filter(|address| {
            is_permitted_egress(*address)
                && matches!(
                    (query.query_type(), address),
                    (DnsQueryType::A, IpAddr::V4(_)) | (DnsQueryType::Aaaa, IpAddr::V6(_))
                )
        })
        .collect::<BTreeSet<_>>();
    Ok(addresses.into_iter().collect())
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
        op::{Message, MessageType, Query},
        rr::{Name, RData, RecordType},
    };

    use super::{DnsQueryType, build_response, parse_dns_query};

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
}
