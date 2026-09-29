//! Private inherited-pipe adapter; authorization remains with the existing Exit callers.
//! The supervised child is the only libunbound FFI boundary. No local DNS listener,
//! resolver setting, UID exception, persistent query store, or OS fallback is created.

use std::{
    fs,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    os::unix::fs::MetadataExt,
    process::Stdio,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    process::{Child, Command},
    sync::{Semaphore, oneshot},
    time::{Instant, timeout_at},
};

use super::{DnsAnswerSource, DnsQuestion, DnsResolverError, ValidatedDnsAnswer};
use crate::{DnsQueryType, authorization::is_permitted_egress};

const EXECUTABLE: &str = "/usr/libexec/volparossa-dns-worker";
const MAGIC: &[u8; 8] = b"VPDNS001";
const HEADER_BYTES: usize = 32;
const MAX_NAME_BYTES: usize = 253;
const MAX_ADDRESSES: usize = 16;
const MAX_REPLY_BYTES: usize = HEADER_BYTES + MAX_ADDRESSES * 16;
const CLEANUP_RESERVE: Duration = Duration::from_millis(500);

pub(super) fn assets_installed() -> bool {
    [
        (EXECUTABLE, true),
        ("/usr/share/dns/root.key", false),
        ("/usr/share/dns/root.hints", false),
    ]
    .into_iter()
    .all(|(path, executable)| {
        fs::symlink_metadata(path).is_ok_and(|metadata| {
            metadata.is_file()
                && metadata.uid() == 0
                && metadata.mode() & 0o022 == 0
                && if executable {
                    metadata.mode() & 0o111 != 0
                } else {
                    metadata.mode() & 0o444 != 0
                }
        })
    })
}

type Answer = Result<ValidatedDnsAnswer, DnsResolverError>;

struct State {
    permits: Arc<Semaphore>,
    quarantined: AtomicBool,
}

/// Shared process bound, not a claim of a persistent libunbound cache.
#[derive(Clone)]
pub(super) struct PrivateUnbound(Arc<State>);

impl PrivateUnbound {
    pub(super) fn new() -> Self {
        Self(Arc::new(State {
            permits: Arc::new(Semaphore::new(2)),
            quarantined: AtomicBool::new(false),
        }))
    }

    pub(super) async fn resolve(&self, question: &DnsQuestion, deadline: Instant) -> Answer {
        if self.0.quarantined.load(Ordering::Acquire) {
            return Err(DnsResolverError::CleanupUnconfirmed);
        }
        if deadline.saturating_duration_since(Instant::now()) <= CLEANUP_RESERVE {
            return Err(DnsResolverError::Unavailable);
        }
        let permit = Arc::clone(&self.0.permits)
            .try_acquire_owned()
            .map_err(|_| DnsResolverError::Unavailable)?;
        let mut nonce = [0; 16];
        getrandom::fill(&mut nonce).map_err(|_| DnsResolverError::Unavailable)?;
        let request = encode_request(question, nonce)?;
        let question = question.clone();
        let state = Arc::clone(&self.0);
        let (mut reply, result) = oneshot::channel();
        // This owner outlives a cancelled caller. It retains the exact Child and
        // concurrency permit until reaping, never a guessed PID or process group.
        tokio::spawn(async move {
            let mut command = Command::new(EXECUTABLE);
            command
                .env_clear()
                .stdin(Stdio::piped())
                .stdout(Stdio::piped())
                .stderr(Stdio::null())
                .kill_on_drop(true);
            let answer = match command.spawn() {
                Ok(mut child) => {
                    match supervise(&mut child, &request, deadline, &mut reply).await {
                        Ok((bytes, received)) => decode_reply(&question, nonce, &bytes, received),
                        Err(DnsResolverError::CleanupUnconfirmed) => {
                            state.quarantined.store(true, Ordering::Release);
                            let _ = reply.send(Err(DnsResolverError::CleanupUnconfirmed));
                            // A kernel task can be temporarily unkillable. Do not call
                            // this cleanup complete or release capacity for replacements.
                            while child.wait().await.is_err() {
                                tokio::time::sleep(Duration::from_secs(1)).await;
                            }
                            drop(permit);
                            return;
                        }
                        Err(error) => Err(error),
                    }
                }
                Err(_) => Err(DnsResolverError::Unavailable),
            };
            drop(permit);
            let _ = reply.send(answer);
        });
        result.await.map_err(|_| DnsResolverError::Unavailable)?
    }
}

async fn supervise(
    child: &mut Child,
    request: &[u8],
    deadline: Instant,
    reply: &mut oneshot::Sender<Answer>,
) -> Result<(Vec<u8>, Instant), DnsResolverError> {
    let exchange = async {
        // A conservative TTL origin: never extend validity by time spent in
        // native validation, pipe transfer, or child cleanup.
        let started = Instant::now();
        let mut input = child.stdin.take().ok_or(DnsResolverError::Unavailable)?;
        let output = child.stdout.take().ok_or(DnsResolverError::Unavailable)?;
        input
            .write_all(request)
            .await
            .map_err(|_| DnsResolverError::Unavailable)?;
        input
            .shutdown()
            .await
            .map_err(|_| DnsResolverError::Unavailable)?;
        drop(input);
        // One extra byte distinguishes an oversized reply without unbounded reads.
        let mut bytes = Vec::new();
        output
            .take(u64::try_from(MAX_REPLY_BYTES + 1).expect("fixed small reply"))
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| DnsResolverError::Unavailable)?;
        if bytes.len() > MAX_REPLY_BYTES {
            return Err(DnsResolverError::InvalidProof);
        }
        let status = child
            .wait()
            .await
            .map_err(|_| DnsResolverError::Unavailable)?;
        if !status.success() {
            return Err(DnsResolverError::Unavailable);
        }
        Ok((bytes, started))
    };
    let result = tokio::select! {
        () = reply.closed() => Err(DnsResolverError::Unavailable),
        result = timeout_at(deadline - CLEANUP_RESERVE, exchange) => {
            result.unwrap_or(Err(DnsResolverError::Unavailable))
        }
    };
    if result.is_ok() {
        return result;
    }
    // Child::wait is cancellation-safe. No result (including a negative DNS
    // reply) crosses this boundary while an owned worker is still unconfirmed.
    let _ = child.start_kill();
    match timeout_at(deadline, child.wait()).await {
        Ok(Ok(_)) => result,
        _ => Err(DnsResolverError::CleanupUnconfirmed),
    }
}

fn encode_request(question: &DnsQuestion, nonce: [u8; 16]) -> Result<Vec<u8>, DnsResolverError> {
    let name = question.name().as_bytes();
    if name.is_empty() || name.len() > MAX_NAME_BYTES {
        return Err(DnsResolverError::InvalidQuestion);
    }
    let mut bytes = vec![0; HEADER_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8..10].copy_from_slice(&u16::from(question.record_type()).to_be_bytes());
    bytes[10..12].copy_from_slice(
        &u16::try_from(name.len())
            .map_err(|_| DnsResolverError::InvalidQuestion)?
            .to_be_bytes(),
    );
    bytes[16..32].copy_from_slice(&nonce);
    bytes.extend_from_slice(name);
    Ok(bytes)
}

fn decode_reply(
    question: &DnsQuestion,
    nonce: [u8; 16],
    bytes: &[u8],
    received: Instant,
) -> Answer {
    if !(HEADER_BYTES..=MAX_REPLY_BYTES).contains(&bytes.len())
        || bytes[..8] != *MAGIC
        || bytes[16..32] != nonce
        || bytes[9] > 1
    {
        return Err(DnsResolverError::InvalidProof);
    }
    let count = usize::from(u16::from_be_bytes([bytes[10], bytes[11]]));
    let ttl = u32::from_be_bytes([bytes[12], bytes[13], bytes[14], bytes[15]]);
    if bytes[8] != 0 {
        if bytes.len() != HEADER_BYTES || bytes[9..16] != [0; 7] {
            return Err(DnsResolverError::InvalidProof);
        }
        return Err(match bytes[8] {
            1 => DnsResolverError::Unavailable,
            2 => DnsResolverError::NameNotFound,
            3 => DnsResolverError::NoData,
            4 => DnsResolverError::Bogus,
            _ => DnsResolverError::InvalidProof,
        });
    }
    let address_size = match question.query_type() {
        DnsQueryType::A => 4,
        DnsQueryType::Aaaa => 16,
    };
    if count == 0
        || count > MAX_ADDRESSES
        || ttl == 0
        || bytes.len() != HEADER_BYTES + count * address_size
    {
        return Err(DnsResolverError::InvalidProof);
    }
    let mut addresses = Vec::with_capacity(count);
    for octets in bytes[HEADER_BYTES..].chunks_exact(address_size) {
        let address = match question.query_type() {
            DnsQueryType::A => IpAddr::V4(Ipv4Addr::from(
                <[u8; 4]>::try_from(octets).map_err(|_| DnsResolverError::InvalidProof)?,
            )),
            DnsQueryType::Aaaa => IpAddr::V6(Ipv6Addr::from(
                <[u8; 16]>::try_from(octets).map_err(|_| DnsResolverError::InvalidProof)?,
            )),
        };
        if !is_permitted_egress(address) {
            return Err(DnsResolverError::InvalidProof);
        }
        addresses.push(address);
    }
    addresses.sort_unstable();
    addresses.dedup();
    Ok(ValidatedDnsAnswer::new(
        addresses,
        received + Duration::from_secs(u64::from(ttl)),
        DnsAnswerSource::PrivateUnbound {
            dnssec_secure: bytes[9] != 0,
        },
    ))
}

#[cfg(test)]
mod tests;
