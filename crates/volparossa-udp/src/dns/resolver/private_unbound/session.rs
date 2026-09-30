//! Version-2 private native session. Only the original address question and its
//! ancestor DNSKEY/DS evidence can traverse this inherited, bounded pipe.

use std::{
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    pin::Pin,
    sync::atomic::{AtomicBool, Ordering},
    time::Duration,
};

use hickory_proto::{
    op::{OpCode, Query},
    rr::{DNSClass, RecordType},
    xfer::DnsRequest,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, ChildStdin, ChildStdout},
    sync::Mutex,
    time::Instant,
};

use super::super::{DnsAnswerSource, DnsQuestion, DnsResolverError, ValidatedDnsAnswer, proof};
use crate::authorization::is_permitted_egress;

pub(super) const MAGIC: &[u8; 8] = b"VPDNS002";
pub(super) const REQUEST_HEADER_BYTES: usize = 32;
pub(super) const HEADER_BYTES: usize = 44;
const MAX_NAME_BYTES: usize = 253;
const MAX_ADDRESSES: usize = 16;
const MAX_PACKET_BYTES: usize = 4096;
const MAX_QUERIES: u32 = 32;
pub(super) const MAX_REPLY_BYTES: usize =
    HEADER_BYTES + MAX_NAME_BYTES + MAX_ADDRESSES * 16 + MAX_PACKET_BYTES;

struct Pipes {
    input: Option<ChildStdin>,
    output: ChildStdout,
    sequence: u32,
}

pub(super) struct Session {
    pipes: Mutex<Pipes>,
    original: DnsQuestion,
    nonce: [u8; 16],
    malformed: AtomicBool,
    bogus: AtomicBool,
    broken: AtomicBool,
}

pub(super) struct NativeReply {
    pub answer: Option<ValidatedDnsAnswer>,
    pub raw: Option<proof::RawEvidence>,
}

impl Session {
    pub(super) fn new(
        child: &mut Child,
        original: DnsQuestion,
        nonce: [u8; 16],
    ) -> Result<Self, DnsResolverError> {
        Ok(Self {
            pipes: Mutex::new(Pipes {
                input: Some(child.stdin.take().ok_or(DnsResolverError::Unavailable)?),
                output: child.stdout.take().ok_or(DnsResolverError::Unavailable)?,
                sequence: 0,
            }),
            original,
            nonce,
            malformed: AtomicBool::new(false),
            bogus: AtomicBool::new(false),
            broken: AtomicBool::new(false),
        })
    }

    pub(super) fn integrity_error(&self) -> Option<DnsResolverError> {
        if self.bogus.load(Ordering::Acquire) {
            Some(DnsResolverError::Bogus)
        } else if self.malformed.load(Ordering::Acquire) {
            Some(DnsResolverError::InvalidProof)
        } else if self.broken.load(Ordering::Acquire) {
            Some(DnsResolverError::Unavailable)
        } else {
            None
        }
    }

    fn broken_pipe(&self) -> DnsResolverError {
        self.broken.store(true, Ordering::Release);
        DnsResolverError::Unavailable
    }

    pub(super) async fn request(&self, query: Query) -> Result<NativeReply, DnsResolverError> {
        let mut pipes = self.pipes.lock().await;
        if pipes.sequence >= MAX_QUERIES {
            return Err(DnsResolverError::Unavailable);
        }
        let sequence = pipes.sequence;
        let name = permitted_question(&self.original, &query, sequence)?;
        let request = encode_request(&name, query.query_type(), self.nonce, sequence)?;
        pipes.sequence += 1;
        let started = Instant::now();
        let started_at_ms = proof::unix_millis()?;
        let exchange = async {
            pipes
                .input
                .as_mut()
                .ok_or(DnsResolverError::Unavailable)?
                .write_all(&request)
                .await
                .map_err(|_| self.broken_pipe())?;
            let mut header = [0; HEADER_BYTES];
            pipes
                .output
                .read_exact(&mut header)
                .await
                .map_err(|_| self.broken_pipe())?;
            let length = frame_length(&header, &name, query.query_type(), self.nonce, sequence)?;
            let mut bytes = header.to_vec();
            bytes.resize(length, 0);
            pipes
                .output
                .read_exact(&mut bytes[HEADER_BYTES..])
                .await
                .map_err(|_| self.broken_pipe())?;
            decode_reply(
                &name,
                query.query_type(),
                self.nonce,
                sequence,
                &bytes,
                started,
                started_at_ms,
            )
        }
        .await;
        match &exchange {
            Err(DnsResolverError::Bogus) => self.bogus.store(true, Ordering::Release),
            Err(DnsResolverError::InvalidProof) => self.malformed.store(true, Ordering::Release),
            _ => (),
        }
        exchange
    }

    pub(super) async fn finish(&self) -> Result<(), DnsResolverError> {
        let mut pipes = self.pipes.lock().await;
        let mut input = pipes.input.take().ok_or(DnsResolverError::Unavailable)?;
        input.shutdown().await.map_err(|_| self.broken_pipe())?;
        drop(input);
        let mut extra = [0];
        if pipes
            .output
            .read(&mut extra)
            .await
            .map_err(|_| self.broken_pipe())?
            != 0
        {
            self.malformed.store(true, Ordering::Release);
            return Err(DnsResolverError::InvalidProof);
        }
        Ok(())
    }
}

impl proof::EvidenceSource for Session {
    fn query<'a>(
        &'a self,
        request: DnsRequest,
    ) -> Pin<Box<dyn Future<Output = Result<proof::RawEvidence, DnsResolverError>> + Send + 'a>>
    {
        Box::pin(async move {
            if request.op_code() != OpCode::Query || request.queries().len() != 1 {
                return Err(DnsResolverError::InvalidProof);
            }
            self.request(request.queries()[0].clone())
                .await?
                .raw
                .ok_or(DnsResolverError::InvalidProof)
        })
    }
}

pub(super) fn permitted_question(
    original: &DnsQuestion,
    query: &Query,
    sequence: u32,
) -> Result<String, DnsResolverError> {
    let dotted = query.name().to_lowercase().to_ascii();
    let name = if dotted == "." {
        "."
    } else {
        dotted.trim_end_matches('.')
    };
    let allowed = if sequence == 0 {
        query.query_type() == original.record_type() && name == original.name()
    } else if !matches!(query.query_type(), RecordType::DNSKEY | RecordType::DS) {
        false
    } else if name == "." {
        query.query_type() == RecordType::DNSKEY
    } else {
        name == original.name()
            || original
                .name()
                .strip_suffix(name)
                .is_some_and(|prefix| prefix.ends_with('.'))
    };
    if !allowed
        || query.query_class() != DNSClass::IN
        || name.is_empty()
        || name.len() > MAX_NAME_BYTES
    {
        return Err(DnsResolverError::InvalidProof);
    }
    Ok(name.to_owned())
}

pub(super) fn encode_request(
    name: &str,
    kind: RecordType,
    nonce: [u8; 16],
    sequence: u32,
) -> Result<Vec<u8>, DnsResolverError> {
    if name.is_empty() || name.len() > MAX_NAME_BYTES || sequence >= MAX_QUERIES {
        return Err(DnsResolverError::InvalidProof);
    }
    let mut bytes = vec![0; REQUEST_HEADER_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&u16::from(kind).to_be_bytes());
    bytes[10..12].copy_from_slice(
        &u16::try_from(name.len())
            .map_err(|_| DnsResolverError::InvalidProof)?
            .to_be_bytes(),
    );
    bytes[12..16].copy_from_slice(&sequence.to_be_bytes());
    bytes[16..32].copy_from_slice(&nonce);
    bytes.extend_from_slice(name.as_bytes());
    Ok(bytes)
}

fn frame_length(
    header: &[u8; HEADER_BYTES],
    name: &str,
    kind: RecordType,
    nonce: [u8; 16],
    sequence: u32,
) -> Result<usize, DnsResolverError> {
    if header[..8] != *MAGIC
        || header[16..32] != nonce
        || header[9] > 1
        || u32::from_be_bytes(header[32..36].try_into().expect("fixed header")) != sequence
        || u16::from_be_bytes([header[40], header[41]]) != u16::from(kind)
        || usize::from(u16::from_be_bytes([header[42], header[43]])) != name.len()
    {
        return Err(DnsResolverError::InvalidProof);
    }
    let count = usize::from(u16::from_be_bytes([header[10], header[11]]));
    let packet = usize::try_from(u32::from_be_bytes(
        header[36..40].try_into().expect("fixed header"),
    ))
    .map_err(|_| DnsResolverError::InvalidProof)?;
    let size = match kind {
        RecordType::A => 4,
        RecordType::AAAA => 16,
        _ => 0,
    };
    if count > MAX_ADDRESSES || (size == 0 && count != 0) || packet > MAX_PACKET_BYTES {
        return Err(DnsResolverError::InvalidProof);
    }
    Ok(HEADER_BYTES + name.len() + count * size + packet)
}

pub(super) fn decode_reply(
    name: &str,
    kind: RecordType,
    nonce: [u8; 16],
    sequence: u32,
    bytes: &[u8],
    started: Instant,
    started_at_ms: u64,
) -> Result<NativeReply, DnsResolverError> {
    if !(HEADER_BYTES..=MAX_REPLY_BYTES).contains(&bytes.len()) {
        return Err(DnsResolverError::InvalidProof);
    }
    let header: &[u8; HEADER_BYTES] = bytes[..HEADER_BYTES].try_into().expect("checked length");
    if frame_length(header, name, kind, nonce, sequence)? != bytes.len()
        || &bytes[HEADER_BYTES..HEADER_BYTES + name.len()] != name.as_bytes()
    {
        return Err(DnsResolverError::InvalidProof);
    }
    let ttl = u32::from_be_bytes(header[12..16].try_into().expect("fixed header"));
    let count = usize::from(u16::from_be_bytes([header[10], header[11]]));
    if header[8] != 0 {
        if header[9..16] != [0; 7] || header[36..40] != [0; 4] {
            return Err(DnsResolverError::InvalidProof);
        }
        return Err(match header[8] {
            1 => DnsResolverError::Unavailable,
            2 => DnsResolverError::NameNotFound,
            3 => DnsResolverError::NoData,
            4 => DnsResolverError::Bogus,
            _ => DnsResolverError::InvalidProof,
        });
    }
    if ttl == 0 {
        return Err(DnsResolverError::InvalidProof);
    }
    let size = match kind {
        RecordType::A => 4,
        RecordType::AAAA => 16,
        _ => 0,
    };
    let begin = HEADER_BYTES + name.len();
    let end = begin + count * size;
    let answer = if size == 0 {
        None
    } else {
        if count == 0 {
            return Err(DnsResolverError::InvalidProof);
        }
        let mut addresses = Vec::with_capacity(count);
        for octets in bytes[begin..end].chunks_exact(size) {
            let address = if kind == RecordType::A {
                IpAddr::V4(Ipv4Addr::from(
                    <[u8; 4]>::try_from(octets).expect("fixed address"),
                ))
            } else {
                IpAddr::V6(Ipv6Addr::from(
                    <[u8; 16]>::try_from(octets).expect("fixed address"),
                ))
            };
            if !is_permitted_egress(address) {
                return Err(DnsResolverError::InvalidProof);
            }
            addresses.push(address);
        }
        addresses.sort_unstable();
        addresses.dedup();
        Some(ValidatedDnsAnswer::new(
            addresses,
            started + Duration::from_secs(u64::from(ttl)),
            DnsAnswerSource::PrivateUnbound {
                dnssec_secure: header[9] != 0,
            },
        ))
    };
    let raw = (end < bytes.len()).then(|| proof::RawEvidence {
        packet: bytes[end..].to_vec(),
        started_at_ms,
    });
    Ok(NativeReply { answer, raw })
}
