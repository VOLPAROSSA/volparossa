//! Owner-local finite challenges; no task input, transport or worker lease.

use std::{
    sync::atomic::{AtomicBool, AtomicU8, AtomicU16, Ordering},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};

use prost::Message;
use sha2::{Digest as _, Sha256, Sha512};
use subtle::ConstantTimeEq as _;

use super::{
    BOUND_OUTSTANDING, EvidenceError, LocalPolicy, OutstandingAppraisal, SignatureFacts,
    VendorCrlFacts, collateral,
};

const MAX_OWNER_SECONDS: u64 = 600;
const CHALLENGE_SECONDS: u64 = 30;
const MAX_PENDING: u8 = 8;
const MAX_ATTEMPTS: u16 = 64;
const MAX_CHALLENGE_BYTES: usize = 256;
const BINDING_DOMAIN: &[u8] = b"VOLPAROSSA/SNP-MILAN-V2/SESSION-EVIDENCE/2\0";

/// Owner limits, not worker resources or permission to run a private task.
/// All are fixed at construction and cannot be refreshed by a peer response.
#[derive(Clone, Copy)]
pub struct SessionLimits {
    /// Absolute owner deadline in Unix seconds; at most 600 seconds from creation.
    pub expires_at: u64,
    /// Simultaneous pending verifications, in 1..=8.
    pub maximum_pending: u8,
    /// Total challenges over this owner's lifetime, in 1..=64; never refunded.
    pub maximum_attempts: u16,
}

#[derive(Clone, PartialEq, Message)]
struct Challenge {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    public_policy_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    expected_measurement: Vec<u8>,
    #[prost(uint32, tag = "5")]
    minimum_guest_svn: u32,
    #[prost(uint64, tag = "6")]
    created_at: u64,
    #[prost(uint64, tag = "7")]
    expires_at: u64,
    #[prost(bytes = "vec", tag = "8")]
    local_policy: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct Binding {
    #[prost(bytes = "vec", tag = "1")]
    challenge: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    proposed_session_key: Vec<u8>,
}

/// Compute the exact guest `REPORT_DATA` convention from a canonical challenge and
/// a proposed 32-byte ephemeral key. Does not verify freshness, key possession,
/// key origin, or signatures. The key is not used to encrypt anything here.
///
/// SHA-512 is domain separated and covers the entire protobuf, including times,
/// all explicit local policy fields and random nonce. Challenge version two and
/// the `/2` domain do not accept or reinterpret version-one challenges. There is
/// no private-content hash field. The public policy ID is only an identifier;
/// it cannot replace the complete bound expectations.
///
/// # Errors
/// Rejects noncanonical, oversize, unsupported, malformed or empty-key input.
pub fn session_report_data(
    challenge: &[u8],
    proposed_session_key: &[u8; 32],
) -> Result<[u8; 64], EvidenceError> {
    if *proposed_session_key == [0; 32] {
        return Err(EvidenceError::Encoding);
    }
    decode_challenge(challenge)?;
    let binding = Binding {
        challenge: challenge.to_vec(),
        proposed_session_key: proposed_session_key.to_vec(),
    };
    let mut digest = Sha512::new();
    digest.update(BINDING_DOMAIN);
    digest.update(binding.encode_to_vec());
    Ok(digest.finalize().into())
}

// Guest collection shares the exact verifier-side canonical parser. These times
// are untrusted request fields; the guest must still compare both to its clock.
pub(in crate::provider::compute) fn challenge_window(
    challenge: &[u8],
) -> Result<(u64, u64), EvidenceError> {
    let parsed = decode_challenge(challenge)?;
    Ok((parsed.created_at, parsed.expires_at))
}

fn decode_challenge(challenge: &[u8]) -> Result<Challenge, EvidenceError> {
    if challenge.is_empty() || challenge.len() > MAX_CHALLENGE_BYTES {
        return Err(EvidenceError::Encoding);
    }
    let parsed = Challenge::decode(challenge).map_err(|_| EvidenceError::Encoding)?;
    if parsed.encode_to_vec() != challenge
        || parsed.version != 2
        || parsed.nonce.len() != 32
        || parsed.nonce.iter().all(|byte| *byte == 0)
        || parsed.public_policy_id.len() != 32
        || parsed.public_policy_id.iter().all(|byte| *byte == 0)
        || parsed.expected_measurement.len() != 48
        || parsed.expected_measurement.iter().all(|byte| *byte == 0)
        || !LocalPolicy::valid_restriction_bytes(&parsed.local_policy)
        || parsed.expires_at <= parsed.created_at
        || parsed.expires_at - parsed.created_at > CHALLENGE_SECONDS
    {
        return Err(EvidenceError::Encoding);
    }
    Ok(parsed)
}

#[derive(Clone, Copy)]
pub(super) struct Stamp {
    pub(super) unix: u64,
    pub(super) monotonic: Instant,
}

impl Stamp {
    fn now() -> Result<Self, EvidenceError> {
        Ok(Self {
            unix: SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_err(|_| EvidenceError::Unavailable)?
                .as_secs(),
            monotonic: Instant::now(),
        })
    }
}

/// One local owner's finite attempt budget and public session expectations.
/// No deserialization/clone, no process-global replay state and no network I/O.
/// Supplying expectations does not authorize their roots or workload for release.
pub struct SessionOwner {
    public_policy_id: [u8; 32],
    policy: LocalPolicy,
    limits: SessionLimits,
    created: Stamp,
    deadline: Instant,
    pending: AtomicU8,
    remaining: AtomicU16,
    cancelled: AtomicBool,
}

impl SessionOwner {
    /// Create a finite verifier owner from local public expectations. In
    /// particular, `public_policy_id` must never be a private task/content hash.
    ///
    /// # Errors
    /// Rejects zero expectations, unavailable time, expired/overflowing limits,
    /// more than ten minutes, more than eight pending or more than 64 attempts.
    pub fn new(
        public_policy_id: [u8; 32],
        policy: LocalPolicy,
        limits: SessionLimits,
    ) -> Result<Self, EvidenceError> {
        Self::new_at(public_policy_id, policy, limits, Stamp::now()?)
    }

    pub(super) fn new_at(
        public_policy_id: [u8; 32],
        policy: LocalPolicy,
        limits: SessionLimits,
        now: Stamp,
    ) -> Result<Self, EvidenceError> {
        let seconds = limits
            .expires_at
            .checked_sub(now.unix)
            .ok_or(EvidenceError::Configuration)?;
        if public_policy_id == [0; 32]
            || !(1..=MAX_OWNER_SECONDS).contains(&seconds)
            || !(1..=MAX_PENDING).contains(&limits.maximum_pending)
            || !(1..=MAX_ATTEMPTS).contains(&limits.maximum_attempts)
        {
            return Err(EvidenceError::Configuration);
        }
        let deadline = now
            .monotonic
            .checked_add(Duration::from_secs(seconds))
            .ok_or(EvidenceError::Configuration)?;
        Ok(Self {
            public_policy_id,
            policy,
            limits,
            created: now,
            deadline,
            pending: AtomicU8::new(0),
            remaining: AtomicU16::new(limits.maximum_attempts),
            cancelled: AtomicBool::new(false),
        })
    }

    /// Permanently invalidate pending and future challenges. Dropped challenges
    /// release their slots but never refund an attempt or extend the owner expiry.
    pub fn cancel(&self) {
        self.cancelled.store(true, Ordering::SeqCst);
    }

    /// Allocate one fresh challenge. A pending value is not cloneable and is
    /// consumed by a single verification attempt, including every failure path.
    ///
    /// # Errors
    /// Rejects cancellation, exhausted budget, expiry, clock rollback or entropy failure.
    pub fn begin(&self) -> Result<PendingSession<'_>, EvidenceError> {
        self.begin_at(Stamp::now()?)
    }

    pub(super) fn begin_at(&self, now: Stamp) -> Result<PendingSession<'_>, EvidenceError> {
        self.check_time(&now)?;
        self.pending
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                (count < self.limits.maximum_pending).then_some(count + 1)
            })
            .map_err(|_| EvidenceError::Budget)?;
        let slot = Slot(self);
        self.remaining
            .fetch_update(Ordering::SeqCst, Ordering::SeqCst, |count| {
                count.checked_sub(1)
            })
            .map_err(|_| EvidenceError::Budget)?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| EvidenceError::Unavailable)?;
        if nonce == [0; 32] {
            return Err(EvidenceError::Unavailable);
        }
        let expires_at = now
            .unix
            .checked_add(CHALLENGE_SECONDS)
            .ok_or(EvidenceError::Expired)?
            .min(self.limits.expires_at);
        let deadline = now
            .monotonic
            .checked_add(Duration::from_secs(expires_at - now.unix))
            .ok_or(EvidenceError::Expired)?
            .min(self.deadline);
        let challenge = Challenge {
            version: 2,
            nonce: nonce.to_vec(),
            public_policy_id: self.public_policy_id.to_vec(),
            expected_measurement: self.policy.expected_measurement.to_vec(),
            minimum_guest_svn: self.policy.minimum_guest_svn,
            created_at: now.unix,
            expires_at,
            local_policy: self.policy.restriction_bytes().to_vec(),
        }
        .encode_to_vec();
        Ok(PendingSession {
            slot,
            challenge,
            created: now,
            expires_at,
            deadline,
        })
    }

    fn check_time(&self, now: &Stamp) -> Result<(), EvidenceError> {
        if self.cancelled.load(Ordering::SeqCst) {
            return Err(EvidenceError::Cancelled);
        }
        if now.unix < self.created.unix
            || now.unix >= self.limits.expires_at
            || now.monotonic < self.created.monotonic
            || now.monotonic >= self.deadline
        {
            return Err(EvidenceError::Expired);
        }
        Ok(())
    }
}

struct Slot<'a>(&'a SessionOwner);

impl Drop for Slot<'_> {
    fn drop(&mut self) {
        self.0.pending.fetch_sub(1, Ordering::SeqCst);
    }
}

/// In-memory, owner-borrowed, one-attempt challenge. Cannot outlive its owner.
/// Dropping/cancelling never creates evidence or releases private input.
pub struct PendingSession<'a> {
    slot: Slot<'a>,
    challenge: Vec<u8>,
    created: Stamp,
    expires_at: u64,
    deadline: Instant,
}

impl<'a> PendingSession<'a> {
    /// Canonical public-only context. No task identifier or private content digest.
    pub fn challenge_bytes(&self) -> &[u8] {
        &self.challenge
    }

    /// Original owner/challenge deadline for local I/O, never a new timeout.
    ///
    /// # Errors
    /// Rejects cancellation, original expiry or a clock before owner creation.
    pub fn deadline(&self) -> Result<tokio::time::Instant, EvidenceError> {
        self.check_time(&Stamp::now()?)?;
        Ok(tokio::time::Instant::from_std(self.deadline))
    }

    /// Discard this challenge; its total attempt remains consumed.
    pub fn cancel(self) {}

    /// Consume a still-live challenge without authenticating evidence or accepting a key.
    /// A caller handling refusal uses this after its final transport handoff, so a
    /// delayed acknowledgement cannot extend the original owner/challenge lifetime.
    /// This checks only local lifecycle; it does not authenticate a provider's claim.
    ///
    /// # Errors
    /// Consumes the attempt on cancellation, original expiry, clock rollback or
    /// unavailable time. Success returns no evidence, capability or worker permit.
    pub fn finish_without_evidence(self) -> Result<(), EvidenceError> {
        self.finish_without_evidence_at(Stamp::now()?)
    }

    fn finish_without_evidence_at(self, now: Stamp) -> Result<(), EvidenceError> {
        self.check_time(&now)
    }

    /// Verify reference signatures, the supported Milan path and the supplied
    /// complete ARK CRL for that ASK. Check certificate/CRL validity at the owner's current
    /// clock, explicit local TCB/SMT/measurement/SVN policy, no debug/migration,
    /// and exact fresh key binding. A bound result still cannot admit a worker
    /// or release any input.
    ///
    /// # Errors
    /// Consumes the challenge even on malformed data, mismatch, cancellation,
    /// certificate-time failure or expiration during synchronous verification.
    pub fn verify_and_bind(
        self,
        report: &[u8],
        vcek_der: &[u8],
        vendor_crl_der: &[u8],
        proposed_session_key: [u8; 32],
    ) -> Result<BoundSessionEvidence, EvidenceError> {
        let started = Stamp::now()?;
        self.check_time(&started)?;
        let (facts, collateral) =
            collateral::verify(report, vcek_der, vendor_crl_der, started.unix)?;
        self.bind_at(facts, collateral, proposed_session_key, Stamp::now()?)
    }

    fn check_time(&self, now: &Stamp) -> Result<(), EvidenceError> {
        self.slot.0.check_time(now)?;
        if now.unix < self.created.unix
            || now.unix >= self.expires_at
            || now.monotonic < self.created.monotonic
            || now.monotonic >= self.deadline
        {
            return Err(EvidenceError::Expired);
        }
        Ok(())
    }

    pub(super) fn bind_at(
        self,
        facts: SignatureFacts,
        collateral: VendorCrlFacts,
        proposed_session_key: [u8; 32],
        now: Stamp,
    ) -> Result<BoundSessionEvidence, EvidenceError> {
        self.binding_at(facts, collateral, proposed_session_key, now)
    }

    fn binding_at(
        &self,
        facts: SignatureFacts,
        collateral: VendorCrlFacts,
        proposed_session_key: [u8; 32],
        now: Stamp,
    ) -> Result<BoundSessionEvidence, EvidenceError> {
        self.check_time(&now)?;
        facts.check_time(now.unix)?;
        collateral.check_time(now.unix)?;
        let expires_at = facts.validity.iter().fold(
            self.expires_at.min(collateral.next_update()),
            |end, &(_, certificate_end)| end.min(certificate_end),
        );
        if expires_at <= now.unix {
            return Err(EvidenceError::CertificateTime);
        }
        let expected = session_report_data(&self.challenge, &proposed_session_key)?;
        facts.check_local_policy(&self.slot.0.policy)?;
        if !bool::from(facts.report_data.ct_eq(&expected)) {
            return Err(EvidenceError::Binding);
        }
        Ok(BoundSessionEvidence {
            facts,
            collateral,
            challenge_sha256: Sha256::digest(&self.challenge).into(),
            proposed_session_key,
            expires_at,
            observed_at: now.unix,
        })
    }

    pub(in crate::provider::compute) fn verify_live(
        self,
        report: &[u8],
        vcek_der: &[u8],
        vendor_crl_der: &[u8],
        key: [u8; 32],
    ) -> Result<LiveSession<'a>, EvidenceError> {
        let started = Stamp::now()?;
        self.check_time(&started)?;
        let (facts, collateral) =
            collateral::verify(report, vcek_der, vendor_crl_der, started.unix)?;
        let now = Stamp::now()?;
        let evidence = self.binding_at(facts, collateral, key, now)?;
        let deadline = self
            .deadline
            .min(now.monotonic + Duration::from_secs(evidence.expires_at - now.unix));
        Ok(LiveSession {
            pending: self,
            evidence,
            deadline,
        })
    }
}

/// Internal continuation, never reconstructible from historical evidence.
pub(in crate::provider::compute) struct LiveSession<'a> {
    pending: PendingSession<'a>,
    evidence: BoundSessionEvidence,
    deadline: Instant,
}

impl LiveSession<'_> {
    pub(in crate::provider::compute) fn constrain(
        &mut self,
        expires_at: u64,
        deadline: Instant,
    ) -> Result<(), EvidenceError> {
        self.check()?;
        self.evidence.expires_at = self.evidence.expires_at.min(expires_at);
        self.deadline = self.deadline.min(deadline);
        self.check()
    }

    pub(in crate::provider::compute) fn check(&self) -> Result<(), EvidenceError> {
        let now = Stamp::now()?;
        self.pending.check_time(&now)?;
        if now.unix >= self.evidence.expires_at || now.monotonic >= self.deadline {
            return Err(EvidenceError::Expired);
        }
        Ok(())
    }

    pub(in crate::provider::compute) fn evidence(&self) -> &BoundSessionEvidence {
        &self.evidence
    }

    pub(in crate::provider::compute) const fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(in crate::provider::compute) fn finish(
        self,
    ) -> Result<BoundSessionEvidence, EvidenceError> {
        self.check()?;
        Ok(self.evidence)
    }
}

// Synthetic software-lifecycle fixture only. No feature enables this in a built
// library, and production verify_live always verifies the real signatures first.
#[cfg(test)]
pub(in crate::provider::compute) fn synthetic_confirmation_lifetime(
    pending: PendingSession<'_>,
    key: [u8; 32],
) -> LiveSession<'_> {
    let now = Stamp::now().unwrap();
    let facts = SignatureFacts {
        report_sha256: [3; 32],
        vcek_sha256: [4; 32],
        measurement: pending.slot.0.policy.expected_measurement,
        report_data: session_report_data(pending.challenge_bytes(), &key).unwrap(),
        guest_svn: pending.slot.0.policy.minimum_guest_svn,
        guest_policy: 1 << 17,
        tcb: [super::MilanTcb {
            bootloader: 0,
            tee: 0,
            snp: 0,
            microcode: 0,
        }; 4],
        platform_smt_enabled: false,
        validity: [(now.unix - 1, now.unix + 600); 3],
    };
    let collateral = VendorCrlFacts {
        sha256: [7; 32],
        number: 0,
        this_update: now.unix - 1,
        next_update: now.unix + 600,
    };
    let evidence = pending.binding_at(facts, collateral, key, now).unwrap();
    let deadline = pending.deadline;
    LiveSession {
        pending,
        evidence,
        deadline,
    }
}

/// Historical observation of a fresh signed binding, **not** a live capability,
/// full appraisal, key-possession proof, worker permit or task admission.
/// It has no serializer, raw Debug, Clone, public constructor or release method.
/// A subsequent owner cancellation does not turn this observation into authority.
pub struct BoundSessionEvidence {
    facts: SignatureFacts,
    collateral: VendorCrlFacts,
    challenge_sha256: [u8; 32],
    proposed_session_key: [u8; 32],
    expires_at: u64,
    observed_at: u64,
}

impl BoundSessionEvidence {
    /// The original immutable cryptographic facts, still incompletely appraised.
    pub const fn signature_facts(&self) -> &SignatureFacts {
        &self.facts
    }

    /// Authenticated complete ARK CRL for the fixed ASK, not individual VCEKs.
    pub const fn vendor_crl(&self) -> &VendorCrlFacts {
        &self.collateral
    }

    /// Public-only challenge digest, not a task/content digest.
    pub const fn challenge_sha256(&self) -> &[u8; 32] {
        &self.challenge_sha256
    }

    /// Signed proposed key bytes. Ownership, origin and possession remain unproven.
    pub const fn proposed_session_key(&self) -> &[u8; 32] {
        &self.proposed_session_key
    }

    /// Challenge deadline capped by certificate/CRL validity; never extended.
    pub const fn expires_at(&self) -> u64 {
        self.expires_at
    }

    /// Local observation time, not a trusted external timestamp or task result.
    pub const fn observed_at(&self) -> u64 {
        self.observed_at
    }

    /// Outstanding requirements cannot be cleared by constructing a boolean.
    pub const fn outstanding_appraisal(&self) -> &'static [OutstandingAppraisal] {
        &BOUND_OUTSTANDING
    }
}

#[cfg(test)]
mod outcome_tests {
    use super::*;
    use crate::provider::compute::attestation::{MilanTcb, SmtPolicy, TcbMinimums};

    fn fixture(at: Stamp) -> SessionOwner {
        let minimum = MilanTcb {
            bootloader: 0,
            tee: 0,
            snp: 0,
            microcode: 0,
        };
        let policy = LocalPolicy::new(
            [3; 48],
            0,
            TcbMinimums {
                current: minimum,
                reported: minimum,
                committed: minimum,
                launch: minimum,
            },
            SmtPolicy::Allow,
        )
        .unwrap();
        SessionOwner::new_at(
            [4; 32],
            policy,
            SessionLimits {
                expires_at: at.unix + 60,
                maximum_pending: 1,
                maximum_attempts: 1,
            },
            at,
        )
        .unwrap()
    }

    #[test]
    fn quote_refusal_completion_releases_slot_without_refunding_attempt() {
        let at = Stamp {
            unix: 100,
            monotonic: Instant::now(),
        };
        let owner = fixture(at);
        let pending = owner.begin_at(at).unwrap();
        assert_eq!(owner.pending.load(Ordering::SeqCst), 1);
        assert!(pending.finish_without_evidence_at(at).is_ok());
        assert_eq!(owner.pending.load(Ordering::SeqCst), 0);
        assert_eq!(owner.remaining.load(Ordering::SeqCst), 0);
        assert!(matches!(owner.begin_at(at), Err(EvidenceError::Budget)));
    }

    #[test]
    fn quote_refusal_completion_rejects_delayed_terminal_and_clock_rollback() {
        let at = Stamp {
            unix: 100,
            monotonic: Instant::now(),
        };
        let cases = [
            Stamp {
                unix: 130,
                monotonic: at.monotonic + Duration::from_secs(1),
            },
            Stamp {
                unix: 101,
                monotonic: at.monotonic + Duration::from_secs(30),
            },
            Stamp {
                unix: 99,
                monotonic: at.monotonic + Duration::from_secs(1),
            },
            Stamp {
                unix: 101,
                monotonic: at.monotonic.checked_sub(Duration::from_secs(1)).unwrap(),
            },
        ];
        for terminal in cases {
            let owner = fixture(at);
            let pending = owner.begin_at(at).unwrap();
            assert!(matches!(
                pending.finish_without_evidence_at(terminal),
                Err(EvidenceError::Expired)
            ));
            assert_eq!(owner.pending.load(Ordering::SeqCst), 0);
            assert_eq!(owner.remaining.load(Ordering::SeqCst), 0);
        }
    }

    #[test]
    fn quote_refusal_completion_rejects_owner_cancellation() {
        let at = Stamp::now().unwrap();
        let owner = fixture(at);
        let pending = owner.begin().unwrap();
        owner.cancel();
        assert!(pending.finish_without_evidence().is_err());
        assert_eq!(owner.pending.load(Ordering::SeqCst), 0);
        assert_eq!(owner.remaining.load(Ordering::SeqCst), 0);
    }
}
