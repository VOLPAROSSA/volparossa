use ed25519_dalek::SigningKey;
use prost::Message;

use super::{
    MAX_AUTH_SECONDS, MAX_CHALLENGE_BYTES, MAX_REQUEST_BYTES, ProtocolError, VerifiedStorageGrant,
    envelope,
};
use crate::{
    CHUNK_BYTES, Validity,
    private_storage::{LeaseId, MAX_ARCHIVE_BYTES, MAX_RANGE_BYTES},
};

/// Immutable archive identity and, after reservation, the exact independently owned copy.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct StorageTarget {
    /// Owner-generated random archive identifier; retrying Reserve reuses this exact ID.
    /// Providers must durably map capability/ID to one exact identity and reservation.
    pub archive_id: [u8; 32],
    /// Absent only for Reserve; all other operations name the exact provider-issued lease.
    pub lease_id: Option<LeaseId>,
    /// Full immutable ciphertext length, not just this operation's chunk/range length.
    pub ciphertext_bytes: u64,
    /// SHA-256 of the complete ordered ciphertext, pinned independently by the owner.
    pub sha256: [u8; 32],
}

/// Narrow ciphertext operations; none authorizes execution, plaintext access or publication.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum StorageOperation {
    /// Reserve the entire physical copy's payload quota before accepting any chunk.
    Reserve {
        /// Exact requested finite lease deadline, bounded by grant expiry and retention.
        expires_at: u64,
    },
    /// Append or identically retry one exact chunk; all nonfinal chunks are 256 KiB.
    Append {
        /// Zero-based byte offset, aligned to the fixed ciphertext chunk size.
        offset: u64,
        /// Exact chunk length, at most 256 KiB; the final length follows full archive size.
        length: u32,
        /// SHA-256 of the separately transferred exact ciphertext chunk.
        sha256: [u8; 32],
    },
    /// Inspect persisted upload position without downloading or consuming the archive.
    Progress,
    /// Verify every ordered chunk and the full original digest before marking committed.
    Finalize,
    /// Read 1–64 complete chunks, with a shorter final chunk at exact archive EOF.
    ReadRange {
        /// Zero-based byte offset, aligned to the fixed ciphertext chunk size.
        offset: u64,
        /// Exact byte count, at most 16 MiB; request and receipt bind the same range.
        length: u64,
    },
    /// Extend one finite lease; the service also checks monotonicity against stored expiry.
    Renew {
        /// Exact new deadline; it never changes archive identity or grant permissions.
        expires_at: u64,
    },
    /// Delete only the exact owned lease/copy; no message-delivery acknowledgement exists.
    Delete,
}

#[derive(Clone, PartialEq, Message)]
struct ChallengePayload {
    #[prost(bytes = "vec", tag = "1")]
    provider: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    owner: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    capability_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    grant_id: Vec<u8>,
}

/// Fresh signed provider challenge for one exact grant, not reusable authorization.
/// The service must remember and consume its ID once on the issuing connection.
#[derive(Clone, Debug)]
pub struct StorageChallenge {
    envelope: envelope::Envelope,
    validity: Validity,
}

impl StorageChallenge {
    /// Issue a fresh random signed challenge for one current provider-granted capability.
    ///
    /// # Errors
    /// Rejects a wrong provider, stale grant, invalid validity or failed secure randomness.
    pub fn issue(
        provider: &SigningKey,
        grant: &VerifiedStorageGrant,
        validity: Validity,
    ) -> Result<Self, ProtocolError> {
        grant.current(validity.created)?;
        if provider.verifying_key() != *grant.provider_key() {
            return Err(ProtocolError::Unauthorized);
        }
        envelope::within(validity, grant.validity())?;
        let payload = ChallengePayload {
            provider: grant.provider_key().as_bytes().to_vec(),
            owner: grant.owner_key().as_bytes().to_vec(),
            capability_id: grant.capability_id().to_vec(),
            grant_id: grant.id().to_vec(),
        };
        Ok(Self {
            envelope: envelope::sign(
                provider,
                envelope::CHALLENGE,
                payload.encode_to_vec(),
                validity,
                MAX_AUTH_SECONDS,
            )?,
            validity,
        })
    }

    /// Exact original signed challenge, without extending validity or issuing another nonce.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.envelope.encode_to_vec()
    }

    /// Digest used to correlate and consume the challenge once in the external service.
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        envelope::digest(&self.encode())
    }

    /// Original signed challenge interval; deriving a request must never extend it.
    #[must_use]
    pub const fn validity(&self) -> Validity {
        self.validity
    }

    /// Verify against the independently authenticated provider in the exact supplied grant.
    ///
    /// # Errors
    /// Rejects malformed bytes, invalid signatures, stale challenges or changed grant scope.
    pub fn decode_and_verify(
        bytes: &[u8],
        grant: &VerifiedStorageGrant,
        now: u64,
    ) -> Result<Self, ProtocolError> {
        let envelope = envelope::decode(bytes, MAX_CHALLENGE_BYTES)?;
        let validity = envelope::validity(envelope::body(
            &envelope,
            envelope::CHALLENGE,
            MAX_AUTH_SECONDS,
        )?);
        let challenge = Self { envelope, validity };
        challenge.verify(grant, now)?;
        Ok(challenge)
    }

    fn verify(&self, grant: &VerifiedStorageGrant, now: u64) -> Result<Validity, ProtocolError> {
        grant.current(now)?;
        let body = envelope::verify(
            &self.envelope,
            grant.provider_key(),
            envelope::CHALLENGE,
            MAX_AUTH_SECONDS,
            now,
        )?;
        let payload: ChallengePayload = envelope::decode(&body.payload, MAX_CHALLENGE_BYTES)?;
        if payload.provider.as_slice() != grant.provider_key().as_bytes()
            || payload.owner.as_slice() != grant.owner_key().as_bytes()
            || payload.capability_id.as_slice() != grant.capability_id()
            || payload.grant_id.as_slice() != grant.id()
        {
            return Err(ProtocolError::Unauthorized);
        }
        let validity = envelope::validity(body);
        envelope::within(validity, grant.validity())?;
        Ok(validity)
    }
}

#[derive(Clone, PartialEq, Message)]
struct Command {
    #[prost(uint32, tag = "1")]
    kind: u32,
    #[prost(uint64, tag = "2")]
    offset: u64,
    #[prost(uint64, tag = "3")]
    length: u64,
    #[prost(bytes = "vec", tag = "4")]
    sha256: Vec<u8>,
    #[prost(uint64, tag = "5")]
    expires_at: u64,
}

impl From<StorageOperation> for Command {
    fn from(operation: StorageOperation) -> Self {
        let mut command = Self::default();
        match operation {
            StorageOperation::Reserve { expires_at } => {
                command.kind = 1;
                command.expires_at = expires_at;
            }
            StorageOperation::Append {
                offset,
                length,
                sha256,
            } => {
                command.kind = 2;
                command.offset = offset;
                command.length = u64::from(length);
                command.sha256 = sha256.to_vec();
            }
            StorageOperation::Progress => command.kind = 3,
            StorageOperation::Finalize => command.kind = 4,
            StorageOperation::ReadRange { offset, length } => {
                command.kind = 5;
                command.offset = offset;
                command.length = length;
            }
            StorageOperation::Renew { expires_at } => {
                command.kind = 6;
                command.expires_at = expires_at;
            }
            StorageOperation::Delete => command.kind = 7,
        }
        command
    }
}

impl Command {
    fn operation(&self) -> Result<StorageOperation, ProtocolError> {
        let operation = match self.kind {
            1 => StorageOperation::Reserve {
                expires_at: self.expires_at,
            },
            2 => StorageOperation::Append {
                offset: self.offset,
                length: u32::try_from(self.length).map_err(|_| ProtocolError::Invalid)?,
                sha256: envelope::fixed(&self.sha256)?,
            },
            3 => StorageOperation::Progress,
            4 => StorageOperation::Finalize,
            5 => StorageOperation::ReadRange {
                offset: self.offset,
                length: self.length,
            },
            6 => StorageOperation::Renew {
                expires_at: self.expires_at,
            },
            7 => StorageOperation::Delete,
            _ => return Err(ProtocolError::Invalid),
        };
        // No irrelevant field can silently change meaning across operation kinds.
        if *self != Self::from(operation) {
            return Err(ProtocolError::Invalid);
        }
        Ok(operation)
    }
}

#[derive(Clone, PartialEq, Message)]
struct RequestPayload {
    #[prost(bytes = "vec", tag = "1")]
    provider: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    capability_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    grant_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    challenge_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    archive_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    lease_id: Vec<u8>,
    #[prost(uint64, tag = "7")]
    ciphertext_bytes: u64,
    #[prost(bytes = "vec", tag = "8")]
    sha256: Vec<u8>,
    #[prost(message, optional, tag = "9")]
    command: Option<Command>,
}

/// Owner-signed authorization bytes. It is not a bearer grant or evidence of storage.
#[derive(Clone, Debug)]
pub struct SignedStorageRequest {
    envelope: envelope::Envelope,
}

/// Exact signed operation after independently trusted grant and fresh challenge checks.
/// Verification is stateless: the service must consume the original connection's challenge
/// once before side effects and must verify persisted capability/archive/lease ownership.
#[derive(Clone, Debug)]
pub struct VerifiedStorageRequest {
    signed: SignedStorageRequest,
    grant: VerifiedStorageGrant,
    challenge_id: [u8; 32],
    target: StorageTarget,
    operation: StorageOperation,
    validity: Validity,
}

impl SignedStorageRequest {
    /// Sign one exact operation, with no ciphertext embedded in authentication metadata.
    ///
    /// # Errors
    /// Rejects wrong owner, stale/mismatched grant or challenge, missing rights and invalid
    /// archive/chunk/range/lease bounds. Signing does not reserve space or consume a challenge.
    pub fn sign(
        owner: &SigningKey,
        grant: &VerifiedStorageGrant,
        challenge: &StorageChallenge,
        target: StorageTarget,
        operation: StorageOperation,
        validity: Validity,
    ) -> Result<Self, ProtocolError> {
        if owner.verifying_key() != *grant.owner_key() {
            return Err(ProtocolError::Unauthorized);
        }
        envelope::within(validity, challenge.verify(grant, validity.created)?)?;
        validate(target, operation, grant, validity.created, validity.created)?;
        let payload = RequestPayload {
            provider: grant.provider_key().as_bytes().to_vec(),
            capability_id: grant.capability_id().to_vec(),
            grant_id: grant.id().to_vec(),
            challenge_id: challenge.id().to_vec(),
            archive_id: target.archive_id.to_vec(),
            lease_id: target
                .lease_id
                .map(|id| id.as_bytes().to_vec())
                .unwrap_or_default(),
            ciphertext_bytes: target.ciphertext_bytes,
            sha256: target.sha256.to_vec(),
            command: Some(operation.into()),
        };
        Ok(Self {
            envelope: envelope::sign(
                owner,
                envelope::REQUEST,
                payload.encode_to_vec(),
                validity,
                MAX_AUTH_SECONDS,
            )?,
        })
    }

    /// Original canonical owner signature and exact operation scope.
    #[must_use]
    pub fn encode(&self) -> Vec<u8> {
        self.envelope.encode_to_vec()
    }

    /// Decode and authenticate one bounded request against the connection's exact challenge.
    ///
    /// # Errors
    /// Rejects stale, noncanonical, unauthorized or mismatched metadata. Calling this twice
    /// does not consume the challenge: connection replay state is deliberately a service duty.
    pub fn decode_and_verify(
        bytes: &[u8],
        grant: &VerifiedStorageGrant,
        challenge: &StorageChallenge,
        now: u64,
    ) -> Result<VerifiedStorageRequest, ProtocolError> {
        let signed = Self {
            envelope: envelope::decode(bytes, MAX_REQUEST_BYTES)?,
        };
        signed.verify(grant, challenge, now)
    }

    /// Authenticate already decoded local request bytes against current grant/challenge scope.
    ///
    /// # Errors
    /// Rejects wrong owner/provider/capability/challenge, missing rights or invalid bounds.
    pub fn verify(
        &self,
        grant: &VerifiedStorageGrant,
        challenge: &StorageChallenge,
        now: u64,
    ) -> Result<VerifiedStorageRequest, ProtocolError> {
        let challenge_validity = challenge.verify(grant, now)?;
        let body = envelope::verify(
            &self.envelope,
            grant.owner_key(),
            envelope::REQUEST,
            MAX_AUTH_SECONDS,
            now,
        )?;
        let validity = envelope::validity(body);
        envelope::within(validity, challenge_validity)?;
        let payload: RequestPayload = envelope::decode(&body.payload, MAX_REQUEST_BYTES)?;
        if payload.provider.as_slice() != grant.provider_key().as_bytes()
            || payload.capability_id.as_slice() != grant.capability_id()
            || payload.grant_id.as_slice() != grant.id()
            || payload.challenge_id.as_slice() != challenge.id()
        {
            return Err(ProtocolError::Unauthorized);
        }
        let target = StorageTarget {
            archive_id: envelope::identifier(&payload.archive_id)?,
            lease_id: if payload.lease_id.is_empty() {
                None
            } else {
                Some(LeaseId::from_bytes(envelope::identifier(
                    &payload.lease_id,
                )?))
            },
            ciphertext_bytes: payload.ciphertext_bytes,
            sha256: envelope::fixed(&payload.sha256)?,
        };
        let operation = payload
            .command
            .as_ref()
            .ok_or(ProtocolError::Invalid)?
            .operation()?;
        validate(target, operation, grant, validity.created, now)?;
        Ok(VerifiedStorageRequest {
            signed: self.clone(),
            grant: grant.clone(),
            challenge_id: challenge.id(),
            target,
            operation,
            validity,
        })
    }
}

impl VerifiedStorageRequest {
    /// Recheck the signed validity, grant, rights and immutable bounds immediately before
    /// execution. This does not replace the service's one-use connection challenge ledger.
    ///
    /// # Errors
    /// Rejects expired authorization or invalid scope; a previously verified value is not
    /// perpetual permission to operate on the provider's stored bytes.
    pub fn current(&self, now: u64) -> Result<(), ProtocolError> {
        self.grant.current(now)?;
        envelope::verify(
            &self.signed.envelope,
            self.grant.owner_key(),
            envelope::REQUEST,
            MAX_AUTH_SECONDS,
            now,
        )?;
        validate(
            self.target,
            self.operation,
            &self.grant,
            self.validity.created,
            now,
        )
    }

    /// Exact original signed bytes, retaining original operation and nonce correlation.
    #[must_use]
    pub const fn signed(&self) -> &SignedStorageRequest {
        &self.signed
    }
    /// Digest of the entire canonical signed request used by every successful receipt.
    #[must_use]
    pub fn id(&self) -> [u8; 32] {
        envelope::digest(&self.signed.encode())
    }
    /// Challenge to consume once on the original connection before any side effect.
    #[must_use]
    pub const fn challenge_id(&self) -> &[u8; 32] {
        &self.challenge_id
    }
    /// Independently authenticated provider grant authorizing this operation.
    #[must_use]
    pub const fn grant(&self) -> &VerifiedStorageGrant {
        &self.grant
    }
    /// Exact immutable identity and original lease, requiring a matching durable mapping.
    #[must_use]
    pub const fn target(&self) -> StorageTarget {
        self.target
    }
    /// Narrow authorized operation; no implicit read, renewal or deletion is permitted.
    #[must_use]
    pub const fn operation(&self) -> StorageOperation {
        self.operation
    }
    /// Original operation validity, never extended by local verification or retry.
    #[must_use]
    pub const fn validity(&self) -> Validity {
        self.validity
    }
}

fn validate(
    target: StorageTarget,
    operation: StorageOperation,
    grant: &VerifiedStorageGrant,
    created: u64,
    now: u64,
) -> Result<(), ProtocolError> {
    envelope::identifier::<32>(&target.archive_id)?;
    if let Some(lease) = target.lease_id {
        envelope::identifier::<16>(lease.as_bytes())?;
    }
    if !(1..=MAX_ARCHIVE_BYTES.min(grant.limits().max_payload_bytes))
        .contains(&target.ciphertext_bytes)
        || target.lease_id.is_none() != matches!(operation, StorageOperation::Reserve { .. })
    {
        return Err(ProtocolError::Invalid);
    }
    if !grant.limits().rights.allows(operation) {
        return Err(ProtocolError::Unauthorized);
    }
    match operation {
        StorageOperation::Reserve { expires_at } | StorageOperation::Renew { expires_at } => {
            if expires_at <= now
                || expires_at <= created
                || expires_at > grant.validity().expires
                || expires_at - created > grant.limits().max_retention_seconds
            {
                return Err(ProtocolError::Invalid);
            }
        }
        StorageOperation::Append { offset, length, .. } => {
            if offset % CHUNK_BYTES as u64 != 0
                || offset >= target.ciphertext_bytes
                || u64::from(length) != (target.ciphertext_bytes - offset).min(CHUNK_BYTES as u64)
            {
                return Err(ProtocolError::Invalid);
            }
        }
        StorageOperation::ReadRange { offset, length } => {
            let end = offset.checked_add(length).ok_or(ProtocolError::Invalid)?;
            if offset % CHUNK_BYTES as u64 != 0
                || !(1..=MAX_RANGE_BYTES).contains(&length)
                || end > target.ciphertext_bytes
                || (end != target.ciphertext_bytes && end % CHUNK_BYTES as u64 != 0)
            {
                return Err(ProtocolError::Invalid);
            }
        }
        StorageOperation::Progress | StorageOperation::Finalize | StorageOperation::Delete => {}
    }
    Ok(())
}
