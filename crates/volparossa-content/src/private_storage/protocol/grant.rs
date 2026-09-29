use ed25519_dalek::{SigningKey, VerifyingKey};
use prost::Message;

use super::{MAX_GRANT_BYTES, ProtocolError, StorageOperation, envelope};
use crate::{
    Validity,
    private_storage::{MAX_CAPACITY_BYTES, MAX_LEASE_SECONDS, MAX_LEASES},
};

/// Explicit least-authority operation set; unknown bits are never granted implicitly.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageRights(u32);

impl StorageRights {
    /// Allocate a separately charged immutable archive reservation.
    pub const RESERVE: Self = Self(1);
    /// Append or identically retry a ciphertext chunk in an owned lease.
    pub const APPEND: Self = Self(1 << 1);
    /// Inspect the durable upload prefix, without claiming fresh integrity proof.
    pub const PROGRESS: Self = Self(1 << 2);
    /// Verify and commit a complete immutable ciphertext archive.
    pub const FINALIZE: Self = Self(1 << 3);
    /// Retrieve a bounded range from an owned committed archive.
    pub const READ_RANGE: Self = Self(1 << 4);
    /// Explicitly extend an owned finite lease, subject to provider retention limits.
    pub const RENEW: Self = Self(1 << 5);
    /// Explicitly delete an owned lease/copy; reads are never acknowledgements.
    pub const DELETE: Self = Self(1 << 6);
    /// Every currently defined private-storage operation, not future unknown operations.
    pub const ALL: Self = Self((1 << 7) - 1);

    /// Combine known rights without granting any undeclared operation.
    #[must_use]
    pub const fn union(self, other: Self) -> Self {
        Self(self.0 | other.0)
    }

    /// Original bounded wire representation.
    #[must_use]
    pub const fn bits(self) -> u32 {
        self.0
    }

    /// Parse an explicit nonempty set of known permissions.
    ///
    /// # Errors
    /// Rejects empty permissions and unknown future bits.
    pub fn from_bits(bits: u32) -> Result<Self, ProtocolError> {
        if bits == 0 || bits & !Self::ALL.0 != 0 {
            return Err(ProtocolError::Invalid);
        }
        Ok(Self(bits))
    }

    /// Whether this provider-granted set permits the specified operation kind.
    #[must_use]
    pub const fn allows(self, operation: StorageOperation) -> bool {
        let required = match operation {
            StorageOperation::Reserve { .. } => Self::RESERVE,
            StorageOperation::Append { .. } => Self::APPEND,
            StorageOperation::Progress => Self::PROGRESS,
            StorageOperation::Finalize => Self::FINALIZE,
            StorageOperation::ReadRange { .. } => Self::READ_RANGE,
            StorageOperation::Renew { .. } => Self::RENEW,
            StorageOperation::Delete => Self::DELETE,
        };
        self.0 & required.0 != 0
    }
}

/// Provider-issued bounds, not an owner assertion of contributed network capacity.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct GrantLimits {
    /// Maximum sum of charged ciphertext payload, counting every retained copy/reservation.
    /// Database/filesystem overhead is additional; aggregate admission is a service duty.
    pub max_payload_bytes: u64,
    /// Maximum simultaneous leases/copies under this capability, independently of byte quota.
    pub max_leases: u32,
    /// Exact allowed operations; no unspecified right is inferred.
    pub rights: StorageRights,
    /// Maximum requested retention interval from an authorization's creation time.
    pub max_retention_seconds: u64,
}

#[derive(Clone, PartialEq, Message)]
struct GrantPayload {
    #[prost(bytes = "vec", tag = "1")]
    capability_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    provider: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    owner: Vec<u8>,
    #[prost(uint64, tag = "4")]
    max_payload_bytes: u64,
    #[prost(uint32, tag = "5")]
    max_leases: u32,
    #[prost(uint32, tag = "6")]
    rights: u32,
    #[prost(uint64, tag = "7")]
    max_retention_seconds: u64,
}

/// Original provider-signed grant; decoding alone establishes no trust or disk reservation.
#[derive(Clone, Debug)]
pub struct SignedStorageGrant {
    envelope: envelope::Envelope,
    payload: GrantPayload,
}

/// Grant authenticated against an independently selected provider, with immutable limits.
#[derive(Clone, Debug)]
pub struct VerifiedStorageGrant {
    signed: SignedStorageGrant,
    provider: VerifyingKey,
    owner: VerifyingKey,
    capability_id: [u8; 32],
    limits: GrantLimits,
    validity: Validity,
}

impl SignedStorageGrant {
    /// Issue a fresh random capability to a separately known application owner.
    ///
    /// Only the provider signs. This is authorization, not proof of reciprocal contribution,
    /// actual quota availability or successful enrollment in a service's durable grant ledger.
    ///
    /// # Errors
    /// Rejects invalid keys/limits/validity and operating-system randomness failure.
    pub fn issue(
        provider: &SigningKey,
        owner: &VerifyingKey,
        limits: GrantLimits,
        validity: Validity,
    ) -> Result<Self, ProtocolError> {
        let payload = GrantPayload {
            capability_id: envelope::random_id()?.to_vec(),
            provider: provider.verifying_key().to_bytes().to_vec(),
            owner: owner.to_bytes().to_vec(),
            max_payload_bytes: limits.max_payload_bytes,
            max_leases: limits.max_leases,
            rights: limits.rights.bits(),
            max_retention_seconds: limits.max_retention_seconds,
        };
        let envelope = envelope::sign(
            provider,
            envelope::GRANT,
            payload.encode_to_vec(),
            validity,
            MAX_LEASE_SECONDS,
        )?;
        let signed = Self { envelope, payload };
        signed.verify(&provider.verifying_key(), validity.created)?;
        Ok(signed)
    }

    /// Exact canonical signed bytes; neither encoding nor reading renews the capability.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.envelope.encode_to_vec()
    }

    /// Decode bounded metadata without accepting its embedded provider as a trust root.
    ///
    /// # Errors
    /// Rejects noncanonical, unsupported, malformed or oversized envelopes and limits.
    pub fn decode(bytes: &[u8]) -> Result<Self, ProtocolError> {
        let envelope = envelope::decode(bytes, MAX_GRANT_BYTES)?;
        let body = envelope::body(&envelope, envelope::GRANT, MAX_LEASE_SECONDS)?;
        let payload = envelope::decode(&body.payload, MAX_GRANT_BYTES)?;
        let signed = Self { envelope, payload };
        signed.validate()?;
        Ok(signed)
    }

    /// Authenticate the grant against a provider selected independently of untrusted bytes.
    ///
    /// # Errors
    /// Rejects wrong providers, invalid signatures, stale grants or invalid bounded fields.
    pub fn verify(
        &self,
        trusted_provider: &VerifyingKey,
        now: u64,
    ) -> Result<VerifiedStorageGrant, ProtocolError> {
        let body = envelope::verify(
            &self.envelope,
            trusted_provider,
            envelope::GRANT,
            MAX_LEASE_SECONDS,
            now,
        )?;
        let limits = self.validate()?;
        Ok(VerifiedStorageGrant {
            signed: self.clone(),
            provider: *trusted_provider,
            owner: envelope::key(&self.payload.owner)?,
            capability_id: envelope::identifier(&self.payload.capability_id)?,
            limits,
            validity: envelope::validity(body),
        })
    }

    fn validate(&self) -> Result<GrantLimits, ProtocolError> {
        let body = envelope::body(&self.envelope, envelope::GRANT, MAX_LEASE_SECONDS)?;
        envelope::key(&self.payload.owner)?;
        envelope::identifier::<32>(&self.payload.capability_id)?;
        if self.payload.provider != body.sender
            || !(1..=MAX_CAPACITY_BYTES).contains(&self.payload.max_payload_bytes)
            || !(1..=MAX_LEASES).contains(&u64::from(self.payload.max_leases))
            || !(1..=MAX_LEASE_SECONDS).contains(&self.payload.max_retention_seconds)
        {
            return Err(ProtocolError::Invalid);
        }
        Ok(GrantLimits {
            max_payload_bytes: self.payload.max_payload_bytes,
            max_leases: self.payload.max_leases,
            rights: StorageRights::from_bits(self.payload.rights)?,
            max_retention_seconds: self.payload.max_retention_seconds,
        })
    }
}

impl VerifiedStorageGrant {
    /// Original provider authorization for transmission or durable grant registration.
    #[must_use]
    pub const fn signed(&self) -> &SignedStorageGrant {
        &self.signed
    }
    /// Independently authenticated provider identity, not discovered trust from its payload.
    #[must_use]
    pub const fn provider_key(&self) -> &VerifyingKey {
        &self.provider
    }
    /// Application owner whose signatures can authorize operations under this capability.
    #[must_use]
    pub const fn owner_key(&self) -> &VerifyingKey {
        &self.owner
    }
    /// Fresh random provider capability identifier, not a transferable bearer secret.
    #[must_use]
    pub const fn capability_id(&self) -> &[u8; 32] {
        &self.capability_id
    }
    /// Exact digest of the original signed grant; operations bind this as well as its ID.
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        envelope::digest(&self.signed.encode())
    }
    /// Original finite authorization window.
    #[must_use]
    pub const fn validity(&self) -> Validity {
        self.validity
    }
    /// Provider-issued per-capability limits; actual aggregate usage is enforced by storage.
    #[must_use]
    pub const fn limits(&self) -> GrantLimits {
        self.limits
    }

    /// Recheck this original grant without extending its finite authorization window.
    ///
    /// # Errors
    /// Rejects invalid signatures, changed provider scope and elapsed or future validity.
    pub fn current(&self, now: u64) -> Result<(), ProtocolError> {
        self.signed.verify(&self.provider, now).map(|_| ())
    }
}
