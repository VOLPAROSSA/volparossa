//! One explicitly authorized PUBLIC fixture task on one guest-terminated TLS channel.
//!
//! This is not attestation, production workload approval or private-input authority.
//! The caller independently chooses the public workload and both exact input hashes.
//! No quote/evidence type converts into a grant. No socket, worker or scheduler is
//! started here; the adapter must retain ownership, cancellation and joined cleanup.

#[cfg(test)]
mod tests;
mod wire;

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{SigningKey, VerifyingKey};
use subtle::ConstantTimeEq as _;
use tokio::time::Instant;

/// Maximum encoded grant, checked before protobuf allocation.
pub const MAX_GRANT_BYTES: usize = 1024;
/// Original task lifetime ceiling, independent of the short quote protocol.
pub const MAX_GRANT_SECONDS: u64 = 2400;

/// The sole initially supported public model profile, not a caller-selected path.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantModel {
    /// The independently pinned Qwen3-4B-Instruct-2507 workload.
    Qwen3FourBInstruct2507,
}

/// The sole initially supported backend; the workload digest binds its exact build.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GrantBackend {
    /// The existing source-built BF16 native CPU backend.
    LlamaCppBf16V1,
}

/// Finite ceilings, not worker admission or evidence of available resources.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GrantLimits {
    /// One or two ordered input submissions, never renewed by another frame.
    pub maximum_requests: u16,
    /// Per-turn ceiling in seconds, at most the existing 600 seconds.
    pub maximum_turn_seconds: u16,
    /// At most the existing two worker threads.
    pub threads: u16,
}

impl GrantLimits {
    fn validate(self) -> Result<(), GrantError> {
        if !(1..=2).contains(&self.maximum_requests)
            || !(1..=600).contains(&self.maximum_turn_seconds)
            || !(1..=2).contains(&self.threads)
        {
            return Err(GrantError::Invalid);
        }
        Ok(())
    }

    fn fits(self, ceiling: Self) -> bool {
        self.maximum_requests <= ceiling.maximum_requests
            && self.maximum_turn_seconds <= ceiling.maximum_turn_seconds
            && self.threads <= ceiling.threads
    }
}

/// Caller-signed public fixture specification. Deliberately no `Debug` or `Clone`.
/// The TLS exporter is channel-binding material, not an exportable worker key.
pub struct GrantSpec {
    /// Exact independently authorized requester signing key.
    pub requester_key: [u8; 32],
    /// SHA-256 of the guest TLS certificate's exact DER `SubjectPublicKeyInfo`.
    pub guest_tls_spki_sha256: [u8; 32],
    /// Digest of the independently selected immutable public workload descriptor.
    pub workload_sha256: [u8; 32],
    /// Closed model profile; exact assets remain bound by the workload digest.
    pub model: GrantModel,
    /// Closed backend profile; no executable path or download instruction.
    pub backend: GrantBackend,
    /// Fresh guest-generated nonce for this single-use verifier.
    pub nonce: [u8; 32],
    /// Exact 32-byte exporter from the same completed TLS connection.
    pub tls_exporter: [u8; 32],
    /// Original issuance time, in milliseconds since the Unix epoch.
    pub issued_at_ms: u64,
    /// Exclusive expiry, no more than 2400 seconds after issuance.
    pub expires_at_ms: u64,
    /// Signed ceilings, independently capped again by the guest's expectations.
    pub limits: GrantLimits,
    /// The two exact public input digests in submission order; not arbitrary input.
    pub public_input_sha256: [[u8; 32]; 2],
}

impl GrantSpec {
    fn validate(&self) -> Result<(), GrantError> {
        self.limits.validate()?;
        if self.issued_at_ms == 0
            || self.expires_at_ms <= self.issued_at_ms
            || self.expires_at_ms - self.issued_at_ms > MAX_GRANT_SECONDS * 1000
            || self.nonce == [0; 32]
        {
            return Err(GrantError::Invalid);
        }
        VerifyingKey::from_bytes(&self.requester_key).map_err(|_| GrantError::Authentication)?;
        Ok(())
    }
}

/// Independently configured PUBLIC fixture expectations, not data trusted from a grant.
/// No constructor accepts attestation evidence or a private-task scope boolean.
pub struct GrantExpectations {
    /// The sole requester permitted by the owner of this public fixture.
    pub requester_key: [u8; 32],
    /// SHA-256 of the actual guest TLS certificate's DER `SubjectPublicKeyInfo`.
    pub guest_tls_spki_sha256: [u8; 32],
    /// Exact independently selected public workload descriptor digest.
    pub workload_sha256: [u8; 32],
    /// Locally selected model profile.
    pub model: GrantModel,
    /// Locally selected backend profile.
    pub backend: GrantBackend,
    /// Exporter obtained locally from this same completed TLS connection.
    pub tls_exporter: [u8; 32],
    /// Independent limits, never enlarged by the signed request.
    pub limits: GrantLimits,
    /// Two owner-approved public inputs, in exact submission order.
    pub public_input_sha256: [[u8; 32]; 2],
}

impl GrantExpectations {
    fn validate(&self) -> Result<(), GrantError> {
        self.limits.validate()?;
        VerifyingKey::from_bytes(&self.requester_key).map_err(|_| GrantError::Authentication)?;
        Ok(())
    }

    fn matches(&self, grant: &GrantSpec) -> bool {
        self.requester_key == grant.requester_key
            && self.guest_tls_spki_sha256 == grant.guest_tls_spki_sha256
            && self.workload_sha256 == grant.workload_sha256
            && self.model == grant.model
            && self.backend == grant.backend
            && bool::from(self.tls_exporter.ct_eq(&grant.tls_exporter))
            && self.public_input_sha256 == grant.public_input_sha256
            && grant.limits.fits(self.limits)
    }
}

/// Closed failures contain no input, exporter, signature, identifier or path.
#[derive(Debug, PartialEq, Eq, thiserror::Error)]
pub enum GrantError {
    /// Malformed, noncanonical, unsupported or out-of-bounds public grant.
    #[error("invalid public resident task grant")]
    Invalid,
    /// Signature, requester, workload or original channel binding did not match.
    #[error("public resident task grant authentication failed")]
    Authentication,
    /// Original challenge/grant time has expired or is not yet valid.
    #[error("public resident task grant expired")]
    Expired,
    /// No request slots remain; there is no retry or renewal operation.
    #[error("public resident task grant exhausted")]
    Exhausted,
    /// Exact next public input did not match; the allowance is exhausted.
    #[error("public resident task input not authorized")]
    Input,
    /// Operating-system randomness is unavailable; no deterministic fallback.
    #[error("public resident task randomness unavailable")]
    Entropy,
}

struct Stamp {
    monotonic: Instant,
    wall_ms: u64,
}

impl Stamp {
    fn now() -> Result<Self, GrantError> {
        let monotonic = Instant::now();
        let wall_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map_err(|_| GrantError::Expired)?
            .as_millis()
            .try_into()
            .map_err(|_| GrantError::Expired)?;
        Ok(Self { monotonic, wall_ms })
    }
}

/// One fresh challenge for one TLS connection, consumed even on verification error.
/// It cannot be cloned, restored, renewed or reconstructed from a supplied nonce.
pub struct GrantVerifier {
    expected: GrantExpectations,
    nonce: [u8; 32],
    started: Stamp,
    deadline: Instant,
    maximum_expires_at_ms: u64,
}

impl GrantVerifier {
    /// Create before writing the challenge; all waiting consumes the original budget.
    ///
    /// # Errors
    /// Rejects invalid local ceilings, clocks, requester keys or unavailable entropy.
    pub fn new(expected: GrantExpectations) -> Result<Self, GrantError> {
        let started = Stamp::now()?;
        expected.validate()?;
        let mut nonce = [0; 32];
        getrandom::fill(&mut nonce).map_err(|_| GrantError::Entropy)?;
        if nonce == [0; 32] {
            return Err(GrantError::Entropy);
        }
        let maximum_expires_at_ms = started
            .wall_ms
            .checked_add(MAX_GRANT_SECONDS * 1000)
            .ok_or(GrantError::Expired)?;
        Ok(Self {
            deadline: started.monotonic + Duration::from_secs(MAX_GRANT_SECONDS),
            expected,
            nonce,
            started,
            maximum_expires_at_ms,
        })
    }

    /// Public challenge nonce, not a reconnect token.
    pub const fn nonce(&self) -> &[u8; 32] {
        &self.nonce
    }

    /// Original guest time; the requester may copy this into the signed specification.
    pub const fn issued_at_ms(&self) -> u64 {
        self.started.wall_ms
    }

    /// Maximum signed expiry; a shorter expiry only reduces the original budget.
    pub const fn maximum_expires_at_ms(&self) -> u64 {
        self.maximum_expires_at_ms
    }

    /// Bound challenge I/O to this already running deadline.
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Authenticate and consume this exact challenge, without starting any worker.
    ///
    /// # Errors
    /// Rejects canonicality, signature, replay/new-channel binding, limits and expiry.
    pub fn verify(self, bytes: &[u8]) -> Result<GrantAllowance, GrantError> {
        let grant = wire::decode(bytes)?;
        self.finish(&grant, &Stamp::now()?)
    }

    fn finish(self, grant: &GrantSpec, now: &Stamp) -> Result<GrantAllowance, GrantError> {
        if grant.nonce != self.nonce || !self.expected.matches(grant) {
            return Err(GrantError::Authentication);
        }
        if now.monotonic >= self.deadline
            || now.wall_ms < self.started.wall_ms
            || grant.issued_at_ms < self.started.wall_ms
            || grant.issued_at_ms > now.wall_ms
            || grant.expires_at_ms <= now.wall_ms
            || grant.expires_at_ms > self.maximum_expires_at_ms
        {
            return Err(GrantError::Expired);
        }
        let deadline = self.started.monotonic
            + Duration::from_millis(grant.expires_at_ms - self.started.wall_ms);
        if now.monotonic >= deadline {
            return Err(GrantError::Expired);
        }
        Ok(GrantAllowance {
            deadline,
            limits: grant.limits,
            public_input_sha256: grant.public_input_sha256,
            next: 0,
        })
    }
}

/// A non-cloneable PUBLIC-only allowance with the original fixed monotonic deadline.
/// Pass ownership to one resident adapter; never turn it into private-input authority.
pub struct GrantAllowance {
    deadline: Instant,
    limits: GrantLimits,
    public_input_sha256: [[u8; 32]; 2],
    next: u16,
}

impl GrantAllowance {
    /// Original deadline, directly usable by the existing resident `SessionBudget`.
    pub const fn deadline(&self) -> Instant {
        self.deadline
    }

    /// Authenticated limits already capped by the guest's independent expectations.
    pub const fn limits(&self) -> GrantLimits {
        self.limits
    }

    /// Check execution freshness without refreshing or serializing the allowance.
    ///
    /// # Errors
    /// Rejects the original deadline; cleanup remains the adapter's mandatory duty.
    pub fn check(&self) -> Result<(), GrantError> {
        if Instant::now() >= self.deadline {
            return Err(GrantError::Expired);
        }
        Ok(())
    }

    /// Consume exactly the next pre-authorized PUBLIC byte-hash before submission.
    /// A wrong input exhausts the allowance, rather than permitting probing/retries.
    ///
    /// # Errors
    /// Rejects expiry, exhausted request count or a different/out-of-order input.
    pub fn consume_input(&mut self, sha256: &[u8; 32]) -> Result<(), GrantError> {
        self.check()?;
        if self.next >= self.limits.maximum_requests {
            return Err(GrantError::Exhausted);
        }
        if self.public_input_sha256[usize::from(self.next)] != *sha256 {
            self.next = self.limits.maximum_requests;
            return Err(GrantError::Input);
        }
        self.next += 1;
        Ok(())
    }
}

/// Sign only the explicitly supplied public fixture specification.
/// No network, attestation, clock authority or private-input release is implied.
///
/// # Errors
/// Rejects invalid fields, bounds and a different requester signing key.
pub fn sign(key: &SigningKey, spec: &GrantSpec) -> Result<Vec<u8>, GrantError> {
    spec.validate()?;
    if key.verifying_key().to_bytes() != spec.requester_key {
        return Err(GrantError::Authentication);
    }
    wire::sign(key, spec)
}
