use std::{
    collections::BTreeMap,
    net::{IpAddr, SocketAddr},
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};

use futures::{Stream, StreamExt, stream};
use hickory_proto::{
    ProtoError,
    dnssec::{DnssecDnsHandle, Proof, PublicKey, TrustAnchors, rdata::DNSSECRData},
    op::{Message, MessageType, OpCode, Query, ResponseCode},
    rr::{DNSClass, RData, RecordType},
    xfer::{DnsHandle, DnsRequest, DnsRequestOptions, DnsResponse},
};
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
};

use super::{
    DnsProofBundle, DnsQuestion, DnsResolverError,
    types::{BundleWire, MAX_MESSAGE_BYTES, MAX_MESSAGES},
};
use crate::authorization::is_permitted_egress;

pub(super) struct ValidatedProof {
    pub bundle: DnsProofBundle,
    pub addresses: Vec<IpAddr>,
    pub digest: [u8; 32],
    pub signature_expiry_ms: u64,
}

pub(super) fn unix_millis() -> Result<u64, DnsResolverError> {
    u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| DnsResolverError::Unavailable)?
            .as_millis(),
    )
    .map_err(|_| DnsResolverError::Unavailable)
}

pub(super) fn parse_message(bytes: &[u8]) -> Result<Message, DnsResolverError> {
    if !(12..=MAX_MESSAGE_BYTES).contains(&bytes.len()) {
        return Err(DnsResolverError::InvalidProof);
    }
    let message = Message::from_vec(bytes).map_err(|_| DnsResolverError::InvalidProof)?;
    if message.message_type() != MessageType::Response
        || message.op_code() != OpCode::Query
        || message.response_code() != ResponseCode::NoError
        || message.truncated()
        || message.queries().len() != 1
        || message.answers().is_empty()
        || message.answers().len() > 32
        || !message.name_servers().is_empty()
        || !message.additionals().is_empty()
    {
        return Err(DnsResolverError::InvalidProof);
    }
    let query = &message.queries()[0];
    check_query(query)?;
    let mut signatures = 0;
    for record in message.answers() {
        if record.dns_class() != DNSClass::IN || record.name() != query.name() || record.ttl() == 0
        {
            return Err(DnsResolverError::InvalidProof);
        }
        match record.data() {
            RData::DNSSEC(DNSSECRData::RRSIG(sig)) => {
                signatures += 1;
                if signatures > 4
                    || sig.type_covered() != query.query_type()
                    || sig.num_labels() != record.name().num_labels()
                    || !sig.signer_name().zone_of(record.name())
                    || sig.sig().len() > 1024
                {
                    return Err(DnsResolverError::InvalidProof);
                }
            }
            RData::DNSSEC(DNSSECRData::DNSKEY(key)) => {
                if query.query_type() != RecordType::DNSKEY
                    || key.public_key().public_bytes().len() > 1024
                {
                    return Err(DnsResolverError::InvalidProof);
                }
            }
            RData::A(_) | RData::AAAA(_) | RData::DNSSEC(DNSSECRData::DS(_)) => {
                if record.record_type() != query.query_type() {
                    return Err(DnsResolverError::InvalidProof);
                }
            }
            _ => return Err(DnsResolverError::InvalidProof),
        }
    }
    Ok(message)
}

fn check_query(query: &Query) -> Result<(), DnsResolverError> {
    if query.query_class() != DNSClass::IN
        || !matches!(
            query.query_type(),
            RecordType::A | RecordType::AAAA | RecordType::DNSKEY | RecordType::DS
        )
    {
        return Err(DnsResolverError::InvalidProof);
    }
    Ok(())
}

type QueryKey = (String, u16);
type ProofStream = Pin<Box<dyn Stream<Item = Result<DnsResponse, ProtoError>> + Send>>;

#[derive(Clone)]
struct RecordedMessage {
    message: Message,
    received_at_ms: u64,
}

#[derive(Clone)]
struct EvidenceHandle {
    records: Arc<Mutex<BTreeMap<QueryKey, RecordedMessage>>>,
    recursive: Option<SocketAddr>,
    calls: Arc<AtomicUsize>,
}

impl EvidenceHandle {
    fn empty(recursive: Option<SocketAddr>) -> Self {
        Self {
            records: Arc::default(),
            recursive,
            calls: Arc::default(),
        }
    }
    fn key(query: &Query) -> QueryKey {
        (
            query.name().to_lowercase().to_ascii(),
            query.query_type().into(),
        )
    }

    async fn response(&self, request: DnsRequest) -> Result<DnsResponse, DnsResolverError> {
        if self.calls.fetch_add(1, Ordering::Relaxed) >= 64
            || request.queries().len() != 1
            || request.op_code() != OpCode::Query
        {
            return Err(DnsResolverError::InvalidProof);
        }
        let query = &request.queries()[0];
        check_query(query)?;
        let key = Self::key(query);
        let existing = self
            .records
            .lock()
            .map_err(|_| DnsResolverError::Unavailable)?
            .get(&key)
            .cloned();
        let mut message = if let Some(existing) = existing {
            existing.message
        } else {
            let remote = self.recursive.ok_or(DnsResolverError::InvalidProof)?;
            let message = query_recursive(request.clone(), remote).await?;
            let received_at_ms = unix_millis()?;
            let mut records = self
                .records
                .lock()
                .map_err(|_| DnsResolverError::Unavailable)?;
            if records.len() >= MAX_MESSAGES {
                return Err(DnsResolverError::InvalidProof);
            }
            if records
                .values()
                .map(|item| item.message.answers().len())
                .sum::<usize>()
                + message.answers().len()
                > 256
            {
                return Err(DnsResolverError::InvalidProof);
            }
            records.insert(
                key,
                RecordedMessage {
                    message: message.clone(),
                    received_at_ms,
                },
            );
            message
        };
        message.set_id(request.id());
        // AD is not evidence. Record proof annotations were never present on the wire.
        message.set_authentic_data(false);
        DnsResponse::from_message(message).map_err(|_| DnsResolverError::InvalidProof)
    }
}

impl DnsHandle for EvidenceHandle {
    type Response = ProofStream;
    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&self, request: R) -> Self::Response {
        let handle = self.clone();
        let request = request.into();
        Box::pin(stream::once(async move {
            handle
                .response(request)
                .await
                .map_err(|_| ProtoError::from("bounded DNS proof unavailable"))
        }))
    }
}

// TCP avoids partial UDP DNSSEC answers. It connects only to the configured recursive
// endpoint, never to an address from a peer proof. The parent operation supplies the deadline.
async fn query_recursive(
    request: DnsRequest,
    remote: SocketAddr,
) -> Result<Message, DnsResolverError> {
    if remote.port() == 0 || remote.ip().is_unspecified() || remote.ip().is_multicast() {
        return Err(DnsResolverError::Unavailable);
    }
    let (mut message, _) = request.into_parts();
    let mut nonce = [0_u8; 2];
    getrandom::fill(&mut nonce).map_err(|_| DnsResolverError::Unavailable)?;
    message.set_id(u16::from_be_bytes(nonce));
    let bytes = message
        .to_vec()
        .map_err(|_| DnsResolverError::InvalidProof)?;
    if bytes.len() > MAX_MESSAGE_BYTES {
        return Err(DnsResolverError::InvalidProof);
    }
    let mut stream = TcpStream::connect(remote)
        .await
        .map_err(|_| DnsResolverError::Unavailable)?;
    stream
        .write_u16(u16::try_from(bytes.len()).map_err(|_| DnsResolverError::InvalidProof)?)
        .await
        .map_err(|_| DnsResolverError::Unavailable)?;
    stream
        .write_all(&bytes)
        .await
        .map_err(|_| DnsResolverError::Unavailable)?;
    let length = usize::from(
        stream
            .read_u16()
            .await
            .map_err(|_| DnsResolverError::Unavailable)?,
    );
    if !(12..=MAX_MESSAGE_BYTES).contains(&length) {
        return Err(DnsResolverError::InvalidProof);
    }
    let mut bytes = vec![0_u8; length];
    stream
        .read_exact(&mut bytes)
        .await
        .map_err(|_| DnsResolverError::Unavailable)?;
    let response = parse_message(&bytes)?;
    if response.id() != message.id() || response.queries() != message.queries() {
        return Err(DnsResolverError::InvalidProof);
    }
    Ok(response)
}

async fn verified_response(
    handle: EvidenceHandle,
    question: &DnsQuestion,
    anchors: Arc<TrustAnchors>,
) -> Result<DnsResponse, DnsResolverError> {
    let mut options = DnsRequestOptions::default();
    options.max_request_depth = 8;
    DnssecDnsHandle::with_trust_anchor(handle, anchors)
        .lookup(question.query()?, options)
        .next()
        .await
        .ok_or(DnsResolverError::InvalidProof)?
        .map_err(|_| DnsResolverError::InvalidProof)
}

pub(super) async fn validate(bundle: DnsProofBundle) -> Result<ValidatedProof, DnsResolverError> {
    validate_with_anchors(bundle, Arc::new(TrustAnchors::default())).await
}

async fn validate_with_anchors(
    bundle: DnsProofBundle,
    anchors: Arc<TrustAnchors>,
) -> Result<ValidatedProof, DnsResolverError> {
    let now = unix_millis()?;
    if bundle.expires_at_unix_ms() <= now {
        return Err(DnsResolverError::InvalidProof);
    }
    let handle = EvidenceHandle::empty(None);
    {
        let mut records = handle
            .records
            .lock()
            .map_err(|_| DnsResolverError::Unavailable)?;
        for raw in &bundle.wire.messages {
            let message = parse_message(raw)?;
            if records
                .insert(
                    EvidenceHandle::key(&message.queries()[0]),
                    RecordedMessage {
                        message,
                        received_at_ms: now,
                    },
                )
                .is_some()
            {
                return Err(DnsResolverError::InvalidProof);
            }
        }
    }
    let response = verified_response(handle, bundle.question(), anchors).await?;
    finish(bundle, &response)
}

pub(super) async fn collect(
    question: &DnsQuestion,
    recursive: SocketAddr,
) -> Result<ValidatedProof, DnsResolverError> {
    collect_with_anchors(question, recursive, Arc::new(TrustAnchors::default())).await
}

async fn collect_with_anchors(
    question: &DnsQuestion,
    recursive: SocketAddr,
    anchors: Arc<TrustAnchors>,
) -> Result<ValidatedProof, DnsResolverError> {
    let handle = EvidenceHandle::empty(Some(recursive));
    let response = verified_response(handle.clone(), question, anchors).await?;
    let mut expires_at_ms = u64::MAX;
    let mut messages = Vec::new();
    for recorded in handle
        .records
        .lock()
        .map_err(|_| DnsResolverError::Unavailable)?
        .values()
    {
        expires_at_ms = expires_at_ms.min(raw_expiry(&recorded.message, recorded.received_at_ms));
        messages.push(
            recorded
                .message
                .to_vec()
                .map_err(|_| DnsResolverError::InvalidProof)?,
        );
    }
    let bundle = DnsProofBundle::from_wire(BundleWire {
        version: 1,
        name: question.name().to_owned(),
        rrtype: u32::from(u16::from(question.record_type())),
        expires_at_ms,
        messages,
    })?;
    finish(bundle, &response)
}

fn raw_expiry(message: &Message, received_at_ms: u64) -> u64 {
    message
        .answers()
        .iter()
        .map(|record| {
            let mut expiry = received_at_ms.saturating_add(u64::from(record.ttl()) * 1000);
            if let RData::DNSSEC(DNSSECRData::RRSIG(sig)) = record.data() {
                expiry = expiry
                    .min(received_at_ms.saturating_add(u64::from(sig.original_ttl()) * 1000))
                    .min(u64::from(sig.sig_expiration().get()) * 1000);
            }
            expiry
        })
        .min()
        .unwrap_or(0)
}

fn finish(
    mut bundle: DnsProofBundle,
    response: &DnsResponse,
) -> Result<ValidatedProof, DnsResolverError> {
    let now = unix_millis()?;
    let question = bundle.question();
    let expected = question.query()?;
    let mut addresses = Vec::new();
    let mut signatures = Vec::new();
    let mut signature_expiry_ms = u64::MAX;
    let mut ttl = u32::MAX;
    for record in response.answers() {
        if record.name() != expected.name() || record.dns_class() != DNSClass::IN {
            return Err(DnsResolverError::InvalidProof);
        }
        match record.data() {
            RData::A(address) if question.record_type() == RecordType::A => {
                if record.proof() != Proof::Secure {
                    return Err(DnsResolverError::InvalidProof);
                }
                addresses.push(IpAddr::V4(address.0));
                ttl = ttl.min(record.ttl());
            }
            RData::AAAA(address) if question.record_type() == RecordType::AAAA => {
                if record.proof() != Proof::Secure {
                    return Err(DnsResolverError::InvalidProof);
                }
                addresses.push(IpAddr::V6(address.0));
                ttl = ttl.min(record.ttl());
            }
            RData::DNSSEC(DNSSECRData::RRSIG(sig))
                if sig.type_covered() == question.record_type() =>
            {
                if record.proof() == Proof::Secure {
                    signatures.push(sig.sig().to_vec());
                    signature_expiry_ms =
                        signature_expiry_ms.min(u64::from(sig.sig_expiration().get()) * 1000);
                }
            }
            _ => return Err(DnsResolverError::InvalidProof),
        }
    }
    if addresses.is_empty()
        || addresses.len() > 16
        || signatures.is_empty()
        || addresses
            .iter()
            .any(|address| !is_permitted_egress(*address))
    {
        return Err(DnsResolverError::InvalidProof);
    }
    addresses.sort_unstable();
    addresses.dedup();
    signatures.sort();
    let mut digest = Sha256::new();
    digest.update(question.name().as_bytes());
    digest.update(u16::from(question.record_type()).to_be_bytes());
    for address in &addresses {
        match address {
            IpAddr::V4(ip) => digest.update(ip.octets()),
            IpAddr::V6(ip) => digest.update(ip.octets()),
        }
    }
    for signature in signatures {
        digest.update(signature);
    }
    let mut expiry = bundle
        .expires_at_unix_ms()
        .min(now.saturating_add(u64::from(ttl) * 1000));
    // Preserve received RRSIG TTL: Hickory's authenticated_ttl helper does not include
    // that distinct record TTL, and replaces it on the validated response.
    for raw in &bundle.wire.messages {
        expiry = expiry.min(raw_expiry(&parse_message(raw)?, now));
    }
    if expiry <= now || expiry - now < 1000 {
        return Err(DnsResolverError::InvalidProof);
    }
    bundle.bound_expiry(expiry);
    Ok(ValidatedProof {
        bundle,
        addresses,
        digest: digest.finalize().into(),
        signature_expiry_ms,
    })
}

#[cfg(test)]
mod tests;
