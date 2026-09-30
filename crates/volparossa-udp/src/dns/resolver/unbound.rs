//! Bounded wire fallback to an explicitly trusted, operator-provisioned Exit-side validator.
//! No OS resolver, discovery, process spawning, listener or persistent query state is used here.

use std::{
    collections::BTreeSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};

use hickory_proto::{
    op::{Message, MessageType, OpCode, ResponseCode},
    rr::{DNSClass, RData, RecordType},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::Instant,
};

use super::{
    DnsAnswerSource, DnsQuestion, DnsResolverError, ValidatedDnsAnswer, types::MAX_MESSAGE_BYTES,
};
use crate::authorization::is_permitted_egress;

const MAX_RECORDS: usize = 64;
const MAX_ALIASES: usize = 8;

pub(super) async fn resolve(
    question: &DnsQuestion,
    endpoint: SocketAddr,
) -> Result<ValidatedDnsAnswer, DnsResolverError> {
    if !endpoint.ip().is_loopback() || endpoint.port() <= 1024 {
        return Err(DnsResolverError::InvalidScope);
    }
    let mut nonce = [0; 2];
    getrandom::fill(&mut nonce).map_err(|_| DnsResolverError::Unavailable)?;
    let id = u16::from_be_bytes(nonce);
    let mut request = Message::new();
    request
        .set_id(id)
        .set_recursion_desired(true)
        .set_checking_disabled(false)
        .set_authentic_data(true)
        .add_query(question.query()?);
    request
        .extensions_mut()
        .get_or_insert_with(Default::default)
        .set_dnssec_ok(true);
    let bytes = request
        .to_vec()
        .map_err(|_| DnsResolverError::InvalidQuestion)?;
    let mut connection = TcpStream::connect(endpoint)
        .await
        .map_err(|_| DnsResolverError::Unavailable)?;
    connection
        .write_u16(u16::try_from(bytes.len()).map_err(|_| DnsResolverError::InvalidQuestion)?)
        .await
        .map_err(|_| DnsResolverError::Unavailable)?;
    connection
        .write_all(&bytes)
        .await
        .map_err(|_| DnsResolverError::Unavailable)?;
    let length = usize::from(
        connection
            .read_u16()
            .await
            .map_err(|_| DnsResolverError::Unavailable)?,
    );
    if !(12..=MAX_MESSAGE_BYTES).contains(&length) {
        return Err(DnsResolverError::InvalidProof);
    }
    let mut bytes = vec![0; length];
    connection
        .read_exact(&mut bytes)
        .await
        .map_err(|_| DnsResolverError::Unavailable)?;
    parse_answer(question, id, &bytes, Instant::now())
}

fn parse_answer(
    question: &DnsQuestion,
    id: u16,
    bytes: &[u8],
    received: Instant,
) -> Result<ValidatedDnsAnswer, DnsResolverError> {
    if !(12..=MAX_MESSAGE_BYTES).contains(&bytes.len()) {
        return Err(DnsResolverError::InvalidProof);
    }
    let message = Message::from_vec(bytes).map_err(|_| DnsResolverError::InvalidProof)?;
    if message.id() != id
        || message.message_type() != MessageType::Response
        || message.op_code() != OpCode::Query
        || message.truncated()
        || message.checking_disabled()
        || !message.recursion_available()
        || message.queries() != [question.query()?]
        || message.answers().len() + message.name_servers().len() + message.additionals().len()
            > MAX_RECORDS
    {
        return Err(DnsResolverError::InvalidProof);
    }
    // SERVFAIL includes validation failures; do not turn it into unsigned data or OS fallback.
    if !matches!(
        message.response_code(),
        ResponseCode::NoError | ResponseCode::NXDomain
    ) {
        return Err(DnsResolverError::Unavailable);
    }
    let mut current = question.query()?.name().clone();
    let mut visited = BTreeSet::new();
    let mut ttl = u32::MAX;
    let mut addresses = Vec::new();
    for depth in 0..=MAX_ALIASES {
        if !visited.insert(current.clone()) {
            return Err(DnsResolverError::InvalidProof);
        }
        let mut alias = None;
        for record in message
            .answers()
            .iter()
            .filter(|record| record.name() == &current)
        {
            if record.dns_class() != DNSClass::IN || record.ttl() == 0 {
                return Err(DnsResolverError::InvalidProof);
            }
            match record.data() {
                RData::CNAME(target) => {
                    if alias.replace(target.0.clone()).is_some() {
                        return Err(DnsResolverError::InvalidProof);
                    }
                    ttl = ttl.min(record.ttl());
                }
                RData::A(value) if question.record_type() == RecordType::A => {
                    addresses.push(IpAddr::V4(value.0));
                    ttl = ttl.min(record.ttl());
                }
                RData::AAAA(value) if question.record_type() == RecordType::AAAA => {
                    addresses.push(IpAddr::V6(value.0));
                    ttl = ttl.min(record.ttl());
                }
                RData::DNSSEC(_) if record.record_type() == RecordType::RRSIG => {}
                _ => return Err(DnsResolverError::InvalidProof),
            }
        }
        if let Some(alias) = alias {
            if !addresses.is_empty() || depth == MAX_ALIASES {
                return Err(DnsResolverError::InvalidProof);
            }
            current = alias;
        } else {
            break;
        }
    }
    if message
        .answers()
        .iter()
        .any(|record| !visited.contains(record.name()))
        || addresses.len() > 16
        || addresses
            .iter()
            .any(|address| !is_permitted_egress(*address))
    {
        return Err(DnsResolverError::InvalidProof);
    }
    if message.response_code() == ResponseCode::NXDomain {
        return if addresses.is_empty() {
            Err(DnsResolverError::NameNotFound)
        } else {
            Err(DnsResolverError::InvalidProof)
        };
    }
    if addresses.is_empty() {
        return Err(DnsResolverError::NoData);
    }
    addresses.sort_unstable();
    addresses.dedup();
    // The validator's AD flag is provenance for this trusted local response only. It is
    // never sufficient to retain/share a DNSSEC proof, and no synthetic TTL is substituted.
    Ok(ValidatedDnsAnswer::new(
        addresses,
        received + Duration::from_secs(u64::from(ttl)),
        DnsAnswerSource::TrustedUnbound {
            authenticated_data: message.authentic_data(),
        },
    ))
}

#[cfg(test)]
mod tests;
