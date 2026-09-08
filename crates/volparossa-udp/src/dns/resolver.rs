//! Independently validated positive DNSSEC sharing with a trusted local fallback.
//!
//! Peer messages are evidence, never policy or trust-anchor authority. Cache state is
//! RAM-only. DNSSEC proves signature validity, not a remote observer's first-seen time.

mod proof;
mod types;

pub use types::{
    DnsAnswerSource, DnsPeerBackend, DnsPeerFuture, DnsProofBundle, DnsQuestion,
    DnsResolutionScope, DnsResolverError, MAX_DNS_PROOF_BYTES, ValidatedDnsAnswer,
};

use std::{
    collections::BTreeMap,
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};

use tokio::{
    net::lookup_host,
    sync::Semaphore,
    time::{Instant, timeout_at},
};

use super::DnsQueryType;
use crate::authorization::is_permitted_egress;
use proof::{ValidatedProof, unix_millis};

const RESOLUTION_TIMEOUT: Duration = Duration::from_secs(5);
const PEER_TIMEOUT: Duration = Duration::from_millis(500);
const COLLECT_TIMEOUT: Duration = Duration::from_secs(3);
const MAX_CACHE_ENTRIES: usize = 256;
const MAX_DEADLINES: usize = 4096;

type CacheKey = ([u8; 32], String, u16);

struct Entry {
    proof: ValidatedProof,
    deadline: Instant,
}

#[derive(Default)]
struct Cache {
    entries: BTreeMap<CacheKey, Entry>,
    // Do not evict live first-seen pins merely to admit a replay of the same proof.
    first_seen: BTreeMap<([u8; 32], [u8; 32]), (Instant, Instant)>,
}

/// Process-local totals only: no question, address, peer or route label can be retained.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct DnsResolutionCounts {
    /// Completed resolutions from independently validated local evidence.
    pub local_validated: u64,
    /// Completed resolutions from newly validated peer evidence.
    pub peer_validated: u64,
    /// Completed resolutions from newly validated recursive evidence.
    pub upstream_validated: u64,
    /// Completed existing-resolver fallbacks, never a DNSSEC validation claim.
    pub trusted_fallback: u64,
}

#[derive(Default)]
struct ResolutionCounters {
    local: AtomicU64,
    peer: AtomicU64,
    upstream: AtomicU64,
    fallback: AtomicU64,
}

/// One shared in-memory resolver. Clones retain the same cache and replay deadlines.
#[derive(Clone)]
pub struct ExitResolver {
    recursive: Option<SocketAddr>,
    peers: Option<Arc<dyn DnsPeerBackend>>,
    cache: Arc<Mutex<Cache>>,
    pending: Arc<Semaphore>,
    counts: Arc<ResolutionCounters>,
}

impl Default for ExitResolver {
    fn default() -> Self {
        Self::new(None, None)
    }
}

impl ExitResolver {
    /// Configure an existing trusted recursive endpoint; `None` retains OS-only fallback.
    /// No resolver settings, routes, or host files are changed by this constructor.
    pub fn new(recursive: Option<SocketAddr>, peers: Option<Arc<dyn DnsPeerBackend>>) -> Self {
        Self {
            recursive,
            peers,
            cache: Arc::default(),
            pending: Arc::new(Semaphore::new(32)),
            counts: Arc::default(),
        }
    }

    /// Snapshot successful resolution sources without any browsing history or identifiers.
    pub fn counts(&self) -> DnsResolutionCounts {
        DnsResolutionCounts {
            local_validated: self.counts.local.load(Ordering::Relaxed),
            peer_validated: self.counts.peer.load(Ordering::Relaxed),
            upstream_validated: self.counts.upstream.load(Ordering::Relaxed),
            trusted_fallback: self.counts.fallback.load(Ordering::Relaxed),
        }
    }

    fn record(&self, answer: ValidatedDnsAnswer) -> ValidatedDnsAnswer {
        let counter = match answer.source() {
            DnsAnswerSource::LocalValidated => &self.counts.local,
            DnsAnswerSource::PeerValidated => &self.counts.peer,
            DnsAnswerSource::UpstreamValidated => &self.counts.upstream,
            DnsAnswerSource::TrustedFallback => &self.counts.fallback,
        };
        let _ = counter.fetch_update(Ordering::Relaxed, Ordering::Relaxed, |count| {
            Some(count.saturating_add(1))
        });
        answer
    }

    /// Resolve one positive address family within one five-second deadline.
    ///
    /// Invalid, missing, unsigned, and unsupported peer proofs are ignored, then the
    /// configured recursive collector or existing OS resolver is used independently.
    /// # Errors
    /// Returns a detail-free error if no permitted address is resolved within the bound.
    pub async fn resolve(
        &self,
        question: &DnsQuestion,
        scope: &DnsResolutionScope,
    ) -> Result<ValidatedDnsAnswer, DnsResolverError> {
        let deadline = Instant::now() + RESOLUTION_TIMEOUT;
        if let Some(answer) = self.cached_answer(question, scope.policy_hash()) {
            return Ok(self.record(answer));
        }
        let _permit = self
            .pending
            .try_acquire()
            .map_err(|_| DnsResolverError::Unavailable)?;
        if scope.permits_peers() {
            if let Some(peers) = &self.peers {
                if let Ok(Ok(Some(bundle))) = timeout_at(
                    deadline.min(Instant::now() + PEER_TIMEOUT),
                    peers.fetch(question, scope),
                )
                .await
                {
                    if bundle.question() == question {
                        if let Ok(Ok(proof)) = timeout_at(deadline, proof::validate(bundle)).await {
                            if let Some(answer) = self.retain(
                                proof,
                                scope.policy_hash(),
                                DnsAnswerSource::PeerValidated,
                            ) {
                                return Ok(self.record(answer));
                            }
                        }
                    }
                }
            }
        }
        if let Some(recursive) = self.recursive {
            if let Ok(Ok(proof)) = timeout_at(
                deadline.min(Instant::now() + COLLECT_TIMEOUT),
                proof::collect(question, recursive),
            )
            .await
            {
                if let Some(answer) = self.retain(
                    proof,
                    scope.policy_hash(),
                    DnsAnswerSource::UpstreamValidated,
                ) {
                    return Ok(self.record(answer));
                }
            }
        }
        let name = format!("{}.", question.name());
        let resolved = timeout_at(deadline, lookup_host((name.as_str(), 0)))
            .await
            .map_err(|_| DnsResolverError::Unavailable)?
            .map_err(|_| DnsResolverError::Unavailable)?;
        let mut addresses: Vec<_> = resolved
            .take(64)
            .map(|socket| socket.ip())
            .filter(|ip| is_permitted_egress(*ip) && question.matches_address(*ip))
            .collect();
        addresses.sort_unstable();
        addresses.dedup();
        addresses.truncate(16);
        Ok(self.record(ValidatedDnsAnswer::new(
            addresses,
            Instant::now() + Duration::from_secs(30),
            DnsAnswerSource::TrustedFallback,
        )))
    }

    /// Whether this RAM cache can currently share a verified proof under exactly this policy.
    /// This reveals no question or answer, performs no resolution and never renews a deadline.
    pub fn has_shareable_proof(&self, policy_hash: &[u8; 32]) -> bool {
        let Ok(mut cache) = self.cache.lock() else {
            return false;
        };
        Self::prune(&mut cache);
        cache
            .entries
            .keys()
            .any(|(policy, _, _)| policy == policy_hash)
    }

    /// Return only independently validated, unexpired cached evidence. Never resolves a miss.
    pub fn cached_bundle(
        &self,
        question: &DnsQuestion,
        policy_hash: &[u8; 32],
    ) -> Option<DnsProofBundle> {
        let mut cache = self.cache.lock().ok()?;
        Self::prune(&mut cache);
        let entry = cache.entries.get(&Self::key(question, policy_hash))?;
        let mut bundle = entry.proof.bundle.clone();
        // A monotone local deadline also bounds forwarding after wall-clock rollback.
        bundle.bound_expiry(
            unix_millis().ok()?.saturating_add(
                u64::try_from(
                    entry
                        .deadline
                        .saturating_duration_since(Instant::now())
                        .as_millis(),
                )
                .ok()?,
            ),
        );
        Some(bundle)
    }

    fn cached_answer(
        &self,
        question: &DnsQuestion,
        policy: &[u8; 32],
    ) -> Option<ValidatedDnsAnswer> {
        let mut cache = self.cache.lock().ok()?;
        Self::prune(&mut cache);
        let entry = cache.entries.get(&Self::key(question, policy))?;
        Some(ValidatedDnsAnswer::new(
            entry.proof.addresses.clone(),
            entry.deadline,
            DnsAnswerSource::LocalValidated,
        ))
    }

    fn retain(
        &self,
        mut proof: ValidatedProof,
        policy: &[u8; 32],
        source: DnsAnswerSource,
    ) -> Option<ValidatedDnsAnswer> {
        let now_ms = unix_millis().ok()?;
        let now = Instant::now();
        let mut cache = self.cache.lock().ok()?;
        Self::prune(&mut cache);
        let pin_key = (*policy, proof.digest);
        let candidate =
            now + Duration::from_millis(proof.bundle.expires_at_unix_ms().checked_sub(now_ms)?);
        let deadline = if let Some((original, _)) = cache.first_seen.get(&pin_key) {
            candidate.min(*original)
        } else {
            if cache.first_seen.len() >= MAX_DEADLINES {
                return None;
            }
            cache.first_seen.insert(
                pin_key,
                (
                    candidate,
                    now + Duration::from_millis(proof.signature_expiry_ms.checked_sub(now_ms)?),
                ),
            );
            candidate
        };
        if deadline <= now {
            return None;
        }
        proof.bundle.bound_expiry(
            now_ms.saturating_add(u64::try_from(deadline.duration_since(now).as_millis()).ok()?),
        );
        let answer = ValidatedDnsAnswer::new(proof.addresses.clone(), deadline, source);
        let key = Self::key(proof.bundle.question(), policy);
        if cache.entries.len() >= MAX_CACHE_ENTRIES && !cache.entries.contains_key(&key) {
            // Keep existing entries and first-seen pins; fallback remains available.
            return None;
        }
        cache.entries.insert(key, Entry { proof, deadline });
        Some(answer)
    }

    fn key(question: &DnsQuestion, policy: &[u8; 32]) -> CacheKey {
        (
            *policy,
            question.name().to_owned(),
            match question.query_type() {
                DnsQueryType::A => 1,
                DnsQueryType::Aaaa => 28,
            },
        )
    }

    fn prune(cache: &mut Cache) {
        let now = Instant::now();
        let now_ms = unix_millis().unwrap_or(u64::MAX);
        cache.entries.retain(|_, entry| {
            entry.deadline > now && entry.proof.bundle.expires_at_unix_ms() > now_ms
        });
        cache.first_seen.retain(|_, (_, expiry)| *expiry > now);
    }
}
