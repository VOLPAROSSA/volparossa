//! One authenticated mailbox operation over an already protected provider TLS stream.
//!
//! A fresh signed challenge is consumed once on this connection. The client's signature binds
//! the provider, invitation, operation and exact object; replay on a new connection fails even
//! after a provider restart. Original HPKE ciphertext is copied, never decrypted by providers.

use std::{
    sync::Arc,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{SigningKey, VerifyingKey};
use prost::Message;
use sha2::{Digest, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    sync::Mutex,
    time::timeout,
};

use super::store::MailboxStore;
use super::{
    Envelope, MAX_GRANT_BYTES, MailboxError, SignedMailboxGrant, VerifiedMailboxGrant,
    decode_canonical, fixed, sign_envelope, verify_envelope,
};
use crate::{CHUNK_BYTES, SignedManifest, Validity, private_message::MAX_PRIVATE_MESSAGE_BYTES};

/// Additive provider selector; old peers refuse it without a direct transport fallback.
pub const SELECTOR_VERSION: u32 = 5;
/// Explicit mailbox service, separate from public-name lookup and opportunistic replication.
pub const SELECTOR_OPERATION: u32 = 3;
const CHALLENGE_TYPE: u32 = 2;
const AUTH_TYPE: u32 = 3;
const RECEIPT_TYPE: u32 = 4;
const AUTH_LIFETIME: u64 = 120;
const IO_TIMEOUT: Duration = Duration::from_secs(120);
/// Bound all mailbox message manifests before their decoder runs.
pub const MAX_MESSAGE_MANIFEST_BYTES: usize = 4096;
/// Bound one exact existing HPKE envelope, not an arbitrary unencrypted upload.
pub const MAX_CIPHERTEXT_BYTES: usize = MAX_PRIVATE_MESSAGE_BYTES + 64;
/// Maximum framed operation metadata, including original manifests for at most 64 messages.
pub const MAX_WIRE_FRAME: usize = 64 * MAX_MESSAGE_MANIFEST_BYTES + 16 * 1024;
const MAX_AUTH_BYTES: usize = MAX_GRANT_BYTES + MAX_MESSAGE_MANIFEST_BYTES + 2048;

/// One operation consumes one fresh challenge; no arbitrary command or filesystem path exists.
#[derive(Clone, Copy, Debug, Eq, PartialEq, prost::Enumeration)]
#[repr(i32)]
pub enum MailboxOperation {
    /// Recipient authorizes initial immutable mailbox registration.
    Register = 1,
    /// The invitation's known sender deposits one complete encrypted publication.
    Deposit = 2,
    /// Only the recipient reads the current bounded inbox metadata.
    List = 3,
    /// Only the recipient retrieves one exact encrypted publication.
    Get = 4,
    /// Recipient confirms local successful delivery of one exact object.
    Acknowledge = 5,
}

#[derive(Clone, PartialEq, Message)]
struct Selector {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    manifest_id: Vec<u8>,
    #[prost(uint32, tag = "3")]
    operation: u32,
}

#[derive(Clone, PartialEq, Message)]
struct ChallengePayload {
    #[prost(bytes = "vec", tag = "1")]
    random: Vec<u8>,
}

/// Original provider-signed one-connection challenge. No client private key reaches the agent.
#[derive(Clone, Debug)]
pub struct MailboxChallenge {
    envelope: Envelope,
    provider: [u8; 32],
}

impl MailboxChallenge {
    /// Original canonical signed bytes, suitable for the authorized local control handoff.
    pub fn encode(&self) -> Vec<u8> {
        self.envelope.encode_to_vec()
    }
    /// Independently verify the challenge against the selected authenticated provider.
    ///
    /// # Errors
    /// Rejects stale, malformed or wrong-provider challenges.
    pub fn decode(bytes: &[u8], provider: &[u8; 32], now: u64) -> Result<Self, MailboxError> {
        let envelope: Envelope = decode_canonical(bytes, MAX_GRANT_BYTES)?;
        let key = VerifyingKey::from_bytes(provider).map_err(|_| MailboxError::Invalid)?;
        let body = verify_envelope(&envelope, &key, CHALLENGE_TYPE, AUTH_LIFETIME, now)?;
        let payload: ChallengePayload = decode_canonical(&body.payload, 128)?;
        fixed(&payload.random)?;
        Ok(Self {
            envelope,
            provider: *provider,
        })
    }
    /// Provider key already authenticated outside this protocol, not an invitation trust root.
    pub const fn provider_key(&self) -> &[u8; 32] {
        &self.provider
    }
    fn id(&self) -> [u8; 32] {
        Sha256::digest(self.encode()).into()
    }
}

#[derive(Clone, PartialEq, Message)]
struct RequestPayload {
    #[prost(bytes = "vec", tag = "1")]
    challenge_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    provider: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    grant: Vec<u8>,
    #[prost(enumeration = "MailboxOperation", tag = "4")]
    operation: i32,
    #[prost(bytes = "vec", tag = "5")]
    manifest: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    message_id: Vec<u8>,
}

/// Public operation input. Any ciphertext remains encrypted for the independent recipient.
#[derive(Clone, Debug)]
pub struct MailboxCommand {
    /// Exact typed operation; no inferred upload or acknowledgement.
    pub operation: MailboxOperation,
    /// Original private-message manifest for Deposit only.
    pub manifest: Option<SignedManifest>,
    /// Exact object identity for Get/Acknowledge only.
    pub message_id: Option<[u8; 32]>,
}

impl MailboxCommand {
    fn payload(
        &self,
        grant: &VerifiedMailboxGrant,
        challenge: &MailboxChallenge,
    ) -> Result<RequestPayload, MailboxError> {
        let request = RequestPayload {
            challenge_id: challenge.id().to_vec(),
            provider: challenge.provider.to_vec(),
            grant: grant.signed().encode(),
            operation: self.operation as i32,
            manifest: self
                .manifest
                .as_ref()
                .map(SignedManifest::encode)
                .unwrap_or_default(),
            message_id: self.message_id.map(|id| id.to_vec()).unwrap_or_default(),
        };
        validate_request(&request, grant, unix_now()?)?;
        Ok(request)
    }
}

#[derive(Clone, PartialEq, Message)]
struct ReceiptPayload {
    #[prost(bytes = "vec", tag = "1")]
    request_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    grant_id: Vec<u8>,
    #[prost(enumeration = "MailboxOperation", tag = "3")]
    operation: i32,
    #[prost(bytes = "vec", repeated, tag = "4")]
    manifests: Vec<Vec<u8>>,
    #[prost(bytes = "vec", tag = "5")]
    message_id: Vec<u8>,
    #[prost(uint64, tag = "6")]
    retained_until: u64,
    #[prost(bool, tag = "7")]
    acknowledged: bool,
    #[prost(uint64, tag = "8")]
    ciphertext_bytes: u64,
}

/// Provider-signed statement of this exact operation's result, not proof of future reachability.
#[derive(Clone, Debug)]
pub struct MailboxReceipt {
    envelope: Envelope,
    payload: ReceiptPayload,
    provider: [u8; 32],
}

impl MailboxReceipt {
    /// Original provider signature, retaining exact request and grant correlation.
    pub fn encode(&self) -> Vec<u8> {
        self.envelope.encode_to_vec()
    }
    /// Provider that signed this storage/delivery observation.
    pub const fn provider_key(&self) -> &[u8; 32] {
        &self.provider
    }
    /// Original object/grant retention bound; no cache hit extends it.
    pub const fn retained_until(&self) -> u64 {
        self.payload.retained_until
    }
    /// Whether the exact message has already been acknowledged, including an idempotent retry.
    pub const fn acknowledged(&self) -> bool {
        self.payload.acknowledged
    }
    /// Exact transferred ciphertext length for Deposit/Get, zero for metadata-only operations.
    pub const fn ciphertext_bytes(&self) -> u64 {
        self.payload.ciphertext_bytes
    }
    /// Independently verified original inbox manifests, not public-name lookup.
    ///
    /// # Errors
    /// Rejects changed sender, expiry, non-private messages or malformed original bytes.
    pub fn manifests(
        &self,
        grant: &VerifiedMailboxGrant,
        now: u64,
    ) -> Result<Vec<SignedManifest>, MailboxError> {
        self.payload
            .manifests
            .iter()
            .map(|bytes| verify_message(bytes, grant, now).map(|(signed, _)| signed))
            .collect()
    }
}

/// Verified remote result. Ciphertext is present only for Get, and is bounded before allocation.
pub struct MailboxReply {
    /// Authenticated metadata and exact provider storage receipt.
    pub receipt: MailboxReceipt,
    /// Complete authenticated original ciphertext for Get; never recipient plaintext.
    pub ciphertext: Vec<u8>,
}

/// Independently retained unprivileged mailbox storage and existing provider signer.
pub struct MailboxService {
    signer: Arc<SigningKey>,
    store: Mutex<MailboxStore>,
}

impl MailboxService {
    /// Attach an explicitly created/reopened owned store to an existing provider service.
    pub fn new(signer: Arc<SigningKey>, store: MailboxStore) -> Self {
        Self {
            signer,
            store: Mutex::new(store),
        }
    }

    /// Serve exactly one operation after the enclosing provider selector has been validated.
    ///
    /// # Errors
    /// Refuses malformed/authentication/replay failures, expired grants, quota and timeouts.
    pub async fn serve<S>(&self, stream: &mut S) -> Result<(), MailboxError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        timeout(IO_TIMEOUT, self.serve_inner(stream))
            .await
            .map_err(|_| MailboxError::Timeout)?
    }

    async fn serve_inner<S>(&self, stream: &mut S) -> Result<(), MailboxError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let created = unix_now()?;
        let mut random = [0; 32];
        getrandom::fill(&mut random).map_err(|_| MailboxError::Entropy)?;
        let envelope = sign_envelope(
            &self.signer,
            CHALLENGE_TYPE,
            ChallengePayload {
                random: random.to_vec(),
            }
            .encode_to_vec(),
            Validity {
                created,
                expires: created + AUTH_LIFETIME,
            },
        )?;
        let challenge = MailboxChallenge {
            envelope,
            provider: self.signer.verifying_key().to_bytes(),
        };
        write_frame(stream, &challenge.encode()).await?;
        let auth_bytes = read_frame(stream, MAX_AUTH_BYTES).await?;
        let (auth, request, grant) = verify_authorization(&auth_bytes, &challenge, unix_now()?)?;
        let operation =
            MailboxOperation::try_from(request.operation).map_err(|_| MailboxError::Invalid)?;
        if !grant.provider_keys().contains(&challenge.provider) {
            return Err(MailboxError::Unauthorized);
        }
        if operation != MailboxOperation::Register {
            let saved = self
                .store
                .lock()
                .await
                .grant(grant.mailbox_id(), unix_now()?)
                .map_err(|_| MailboxError::Store)?
                .ok_or(MailboxError::Unauthorized)?;
            if saved.grant_id() != grant.grant_id() {
                return Err(MailboxError::Unauthorized);
            }
        }
        let mut result = ReceiptPayload {
            request_id: Sha256::digest(auth.encode_to_vec()).to_vec(),
            grant_id: grant.grant_id().to_vec(),
            operation: request.operation,
            manifests: Vec::new(),
            message_id: request.message_id.clone(),
            retained_until: grant.validity().expires,
            acknowledged: false,
            ciphertext_bytes: 0,
        };
        let ciphertext = self.operate(stream, &request, &grant, &mut result).await?;
        grant.check_time(unix_now()?)?;
        let now = unix_now()?;
        let receipt = sign_envelope(
            &self.signer,
            RECEIPT_TYPE,
            result.encode_to_vec(),
            Validity {
                created: now,
                expires: (now + AUTH_LIFETIME).min(grant.validity().expires),
            },
        )?;
        write_frame(stream, &receipt.encode_to_vec()).await?;
        if !ciphertext.is_empty() {
            write_ciphertext(stream, &ciphertext).await?;
        }
        Ok(())
    }

    async fn operate<S>(
        &self,
        stream: &mut S,
        request: &RequestPayload,
        grant: &VerifiedMailboxGrant,
        result: &mut ReceiptPayload,
    ) -> Result<Vec<u8>, MailboxError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut ciphertext = Vec::new();
        match MailboxOperation::try_from(request.operation).map_err(|_| MailboxError::Invalid)? {
            MailboxOperation::Register => self
                .store
                .lock()
                .await
                .register(grant, unix_now()?)
                .map_err(|_| MailboxError::Store)?,
            MailboxOperation::Deposit => {
                let (signed, manifest) = verify_message(&request.manifest, grant, unix_now()?)?;
                // Ready is only permission to transfer the exact signed object, not storage success.
                write_frame(stream, manifest.manifest_id()).await?;
                let body = read_ciphertext(stream, manifest.length()).await?;
                verify_ciphertext(&manifest, &body)?;
                let stored = self
                    .store
                    .lock()
                    .await
                    .deposit(grant.mailbox_id(), &signed, &body, unix_now()?)
                    .map_err(|_| MailboxError::Store)?;
                result.message_id = stored.message_id.to_vec();
                result.retained_until = stored.expires_at;
                result.acknowledged = stored.acknowledged;
                result.ciphertext_bytes = manifest.length();
            }
            MailboxOperation::List => {
                result.manifests = self
                    .store
                    .lock()
                    .await
                    .list(grant.mailbox_id(), unix_now()?)
                    .map_err(|_| MailboxError::Store)?
                    .into_iter()
                    .map(|entry| entry.signed.encode())
                    .collect();
            }
            MailboxOperation::Get => {
                let stored = self
                    .store
                    .lock()
                    .await
                    .get(
                        grant.mailbox_id(),
                        &fixed(&request.message_id)?,
                        unix_now()?,
                    )
                    .map_err(|_| MailboxError::Store)?
                    .ok_or(MailboxError::Store)?;
                result.manifests.push(stored.entry.signed.encode());
                result.retained_until = stored.entry.expires_at;
                result.ciphertext_bytes = stored.ciphertext.len() as u64;
                ciphertext = stored.ciphertext;
            }
            MailboxOperation::Acknowledge => {
                result.acknowledged = self
                    .store
                    .lock()
                    .await
                    .acknowledge(
                        grant.mailbox_id(),
                        &fixed(&request.message_id)?,
                        unix_now()?,
                    )
                    .map_err(|_| MailboxError::Store)?;
                if !result.acknowledged {
                    return Err(MailboxError::Store);
                }
            }
        }
        Ok(ciphertext)
    }
}

/// Begin one operation on an independently authenticated protected provider stream.
///
/// # Errors
/// Rejects expired/wrong-provider challenges and bounded I/O failures.
pub async fn begin<S>(stream: &mut S, provider: &[u8; 32]) -> Result<MailboxChallenge, MailboxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(IO_TIMEOUT, async {
        write_frame(
            stream,
            &Selector {
                version: SELECTOR_VERSION,
                manifest_id: Vec::new(),
                operation: SELECTOR_OPERATION,
            }
            .encode_to_vec(),
        )
        .await?;
        let bytes = read_frame(stream, MAX_GRANT_BYTES).await?;
        MailboxChallenge::decode(&bytes, provider, unix_now()?)
    })
    .await
    .map_err(|_| MailboxError::Timeout)?
}

/// Complete an operation after challenge handoff, retaining the signing key only in the caller.
///
/// This also works on the existing authorized local socket when the agent forwards this exact
/// operation to the independently selected provider. No untyped proxy or alternate dial occurs.
///
/// # Errors
/// Rejects changed challenges/grants/operations, unauthorized keys, invalid objects or receipts.
pub async fn execute<S>(
    stream: &mut S,
    challenge: &MailboxChallenge,
    grant: &VerifiedMailboxGrant,
    command: &MailboxCommand,
    signer: &SigningKey,
    ciphertext: &[u8],
) -> Result<MailboxReply, MailboxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(
        IO_TIMEOUT,
        execute_inner(stream, challenge, grant, command, signer, ciphertext),
    )
    .await
    .map_err(|_| MailboxError::Timeout)?
}

/// Forward only the exact authorized typed operation over an already selected provider stream.
///
/// The application signs the fresh challenge on its authorized local connection. This bridge
/// validates all signed scope and data before forwarding; it never sees private signing or
/// decryption keys and cannot be turned into a general byte-stream proxy.
///
/// # Errors
/// Rejects a different grant/command/provider, invalid signatures, data, receipts or deadlines.
pub async fn bridge<L, R>(
    local: &mut L,
    remote: &mut R,
    challenge: &MailboxChallenge,
    grant: &VerifiedMailboxGrant,
    command: &MailboxCommand,
) -> Result<MailboxReceipt, MailboxError>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    timeout(IO_TIMEOUT, async {
        let auth_bytes = read_frame(local, MAX_AUTH_BYTES).await?;
        let (auth, request, observed) = verify_authorization(&auth_bytes, challenge, unix_now()?)?;
        let expected = command.payload(grant, challenge)?;
        if observed.grant_id() != grant.grant_id() || request != expected {
            return Err(MailboxError::Unauthorized);
        }
        let request_id: [u8; 32] = Sha256::digest(auth.encode_to_vec()).into();
        write_frame(remote, &auth_bytes).await?;
        if command.operation == MailboxOperation::Deposit {
            let (_, manifest) = verify_message(&request.manifest, grant, unix_now()?)?;
            let ready = read_frame(remote, 32).await?;
            if ready.as_slice() != manifest.manifest_id() {
                return Err(MailboxError::Invalid);
            }
            write_frame(local, &ready).await?;
            let ciphertext = read_ciphertext(local, manifest.length()).await?;
            verify_ciphertext(&manifest, &ciphertext)?;
            write_ciphertext(remote, &ciphertext).await?;
        }
        let bytes = read_frame(remote, MAX_WIRE_FRAME).await?;
        let receipt = decode_receipt(
            &bytes,
            &request_id,
            grant,
            command,
            &challenge.provider,
            unix_now()?,
        )?;
        let ciphertext = if command.operation == MailboxOperation::Get {
            let ciphertext = read_ciphertext(remote, receipt.payload.ciphertext_bytes).await?;
            let (_, manifest) = verify_message(&receipt.payload.manifests[0], grant, unix_now()?)?;
            verify_ciphertext(&manifest, &ciphertext)?;
            ciphertext
        } else {
            Vec::new()
        };
        grant.check_time(unix_now()?)?;
        write_frame(local, &bytes).await?;
        if !ciphertext.is_empty() {
            write_ciphertext(local, &ciphertext).await?;
        }
        Ok(receipt)
    })
    .await
    .map_err(|_| MailboxError::Timeout)?
}

async fn execute_inner<S>(
    stream: &mut S,
    challenge: &MailboxChallenge,
    grant: &VerifiedMailboxGrant,
    command: &MailboxCommand,
    signer: &SigningKey,
    ciphertext: &[u8],
) -> Result<MailboxReply, MailboxError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let now = unix_now()?;
    grant.check_time(now)?;
    let challenge = MailboxChallenge::decode(&challenge.encode(), &challenge.provider, now)?;
    if !grant.provider_keys().contains(&challenge.provider) {
        return Err(MailboxError::Unauthorized);
    }
    let request = command.payload(grant, &challenge)?;
    let expected = if command.operation == MailboxOperation::Deposit {
        grant.sender_key()
    } else {
        grant.owner_key()
    };
    if signer.verifying_key().as_bytes() != expected {
        return Err(MailboxError::Unauthorized);
    }
    let auth = sign_envelope(
        signer,
        AUTH_TYPE,
        request.encode_to_vec(),
        Validity {
            created: now,
            expires: (now + AUTH_LIFETIME).min(grant.validity().expires),
        },
    )?;
    let request_id: [u8; 32] = Sha256::digest(auth.encode_to_vec()).into();
    if command.operation == MailboxOperation::Deposit {
        let (_, manifest) = verify_message(&request.manifest, grant, now)?;
        verify_ciphertext(&manifest, ciphertext)?;
    } else if !ciphertext.is_empty() {
        return Err(MailboxError::Invalid);
    }
    write_frame(stream, &auth.encode_to_vec()).await?;
    if command.operation == MailboxOperation::Deposit {
        let (_, manifest) = verify_message(&request.manifest, grant, unix_now()?)?;
        if read_frame(stream, 32).await?.as_slice() != manifest.manifest_id() {
            return Err(MailboxError::Invalid);
        }
        write_ciphertext(stream, ciphertext).await?;
    }
    let receipt = decode_receipt(
        &read_frame(stream, MAX_WIRE_FRAME).await?,
        &request_id,
        grant,
        command,
        &challenge.provider,
        unix_now()?,
    )?;
    let ciphertext = if command.operation == MailboxOperation::Get {
        let bytes = read_ciphertext(stream, receipt.payload.ciphertext_bytes).await?;
        let (_, manifest) = verify_message(&receipt.payload.manifests[0], grant, unix_now()?)?;
        verify_ciphertext(&manifest, &bytes)?;
        bytes
    } else {
        Vec::new()
    };
    grant.check_time(unix_now()?)?;
    Ok(MailboxReply {
        receipt,
        ciphertext,
    })
}

fn verify_authorization(
    bytes: &[u8],
    challenge: &MailboxChallenge,
    now: u64,
) -> Result<(Envelope, RequestPayload, VerifiedMailboxGrant), MailboxError> {
    let auth: Envelope = decode_canonical(bytes, MAX_AUTH_BYTES)?;
    let body = auth.body.as_ref().ok_or(MailboxError::Invalid)?;
    let request: RequestPayload = decode_canonical(&body.payload, MAX_AUTH_BYTES)?;
    let signed = SignedMailboxGrant::decode(&request.grant)?;
    let owner =
        VerifyingKey::from_bytes(&signed.owner_key_hint()?).map_err(|_| MailboxError::Invalid)?;
    let grant = signed.verify(&owner, now)?;
    let op = MailboxOperation::try_from(request.operation).map_err(|_| MailboxError::Invalid)?;
    let expected = if op == MailboxOperation::Deposit {
        grant.sender_key()
    } else {
        grant.owner_key()
    };
    let key = VerifyingKey::from_bytes(expected).map_err(|_| MailboxError::Invalid)?;
    verify_envelope(&auth, &key, AUTH_TYPE, AUTH_LIFETIME, now)?;
    MailboxChallenge::decode(&challenge.encode(), &challenge.provider, now)?;
    if request.challenge_id.as_slice() != challenge.id()
        || request.provider.as_slice() != challenge.provider
    {
        return Err(MailboxError::Unauthorized);
    }
    validate_request(&request, &grant, now)?;
    Ok((auth, request, grant))
}

fn validate_request(
    request: &RequestPayload,
    grant: &VerifiedMailboxGrant,
    now: u64,
) -> Result<(), MailboxError> {
    let op = MailboxOperation::try_from(request.operation).map_err(|_| MailboxError::Invalid)?;
    if request.grant.len() > MAX_GRANT_BYTES
        || !grant.provider_keys().contains(&fixed(&request.provider)?)
    {
        return Err(MailboxError::Invalid);
    }
    fixed(&request.challenge_id)?;
    match op {
        MailboxOperation::Deposit => {
            verify_message(&request.manifest, grant, now)?;
            if !request.message_id.is_empty() {
                return Err(MailboxError::Invalid);
            }
        }
        MailboxOperation::Get | MailboxOperation::Acknowledge => {
            fixed(&request.message_id)?;
            if !request.manifest.is_empty() {
                return Err(MailboxError::Invalid);
            }
        }
        MailboxOperation::List | MailboxOperation::Register => {
            if !request.message_id.is_empty() || !request.manifest.is_empty() {
                return Err(MailboxError::Invalid);
            }
        }
    }
    Ok(())
}

fn verify_message(
    bytes: &[u8],
    grant: &VerifiedMailboxGrant,
    now: u64,
) -> Result<(SignedManifest, crate::VerifiedManifest), MailboxError> {
    if bytes.len() > MAX_MESSAGE_MANIFEST_BYTES {
        return Err(MailboxError::Invalid);
    }
    let signed = SignedManifest::decode(bytes).map_err(|_| MailboxError::Invalid)?;
    let key = VerifyingKey::from_bytes(grant.sender_key()).map_err(|_| MailboxError::Invalid)?;
    let manifest = signed
        .verify(&key, now)
        .map_err(|_| MailboxError::Unauthorized)?;
    if manifest.metadata().content_type != crate::private_message::PRIVATE_MESSAGE_CONTENT_TYPE
        || manifest.length() == 0
        || manifest.length() > MAX_CIPHERTEXT_BYTES as u64
        || manifest.validity().expires > grant.validity().expires
    {
        return Err(MailboxError::Invalid);
    }
    Ok((signed, manifest))
}

fn verify_ciphertext(manifest: &crate::VerifiedManifest, bytes: &[u8]) -> Result<(), MailboxError> {
    if bytes.len() as u64 != manifest.length()
        || bytes.len() > MAX_CIPHERTEXT_BYTES
        || Sha256::digest(bytes).as_slice() != manifest.object_sha256()
    {
        return Err(MailboxError::Invalid);
    }
    let mut offset = 0;
    for chunk in manifest.chunks() {
        let end = offset + chunk.length() as usize;
        let part = bytes.get(offset..end).ok_or(MailboxError::Invalid)?;
        if crate::ChunkId::digest(part) != *chunk.id() {
            return Err(MailboxError::Invalid);
        }
        offset = end;
    }
    if offset != bytes.len() {
        return Err(MailboxError::Invalid);
    }
    Ok(())
}

fn decode_receipt(
    bytes: &[u8],
    request_id: &[u8; 32],
    grant: &VerifiedMailboxGrant,
    command: &MailboxCommand,
    provider: &[u8; 32],
    now: u64,
) -> Result<MailboxReceipt, MailboxError> {
    let envelope: Envelope = decode_canonical(bytes, MAX_WIRE_FRAME)?;
    let key = VerifyingKey::from_bytes(provider).map_err(|_| MailboxError::Invalid)?;
    let body = verify_envelope(&envelope, &key, RECEIPT_TYPE, AUTH_LIFETIME, now)?;
    let payload: ReceiptPayload = decode_canonical(&body.payload, MAX_WIRE_FRAME)?;
    if payload.request_id.as_slice() != request_id
        || payload.grant_id.as_slice() != grant.grant_id()
        || payload.operation != command.operation as i32
        || payload.retained_until > grant.validity().expires
        || payload.retained_until <= now
        || payload.manifests.len() > grant.max_messages() as usize
    {
        return Err(MailboxError::Invalid);
    }
    let receipt = MailboxReceipt {
        envelope,
        payload,
        provider: *provider,
    };
    let manifests = receipt.manifests(grant, now)?;
    let p = &receipt.payload;
    match command.operation {
        MailboxOperation::Register => {
            if !manifests.is_empty()
                || !p.message_id.is_empty()
                || p.acknowledged
                || p.ciphertext_bytes != 0
            {
                return Err(MailboxError::Invalid);
            }
        }
        MailboxOperation::List => {
            if !p.message_id.is_empty() || p.acknowledged || p.ciphertext_bytes != 0 {
                return Err(MailboxError::Invalid);
            }
        }
        MailboxOperation::Deposit => {
            let signed = command.manifest.as_ref().ok_or(MailboxError::Invalid)?;
            let (_, manifest) = verify_message(&signed.encode(), grant, now)?;
            if !manifests.is_empty()
                || p.message_id.as_slice() != manifest.manifest_id()
                || p.ciphertext_bytes != manifest.length()
                || p.retained_until != manifest.validity().expires
            {
                return Err(MailboxError::Invalid);
            }
        }
        MailboxOperation::Get => {
            let id = command.message_id.ok_or(MailboxError::Invalid)?;
            if manifests.len() != 1 || p.message_id.as_slice() != id || p.acknowledged {
                return Err(MailboxError::Invalid);
            }
            let (_, manifest) = verify_message(&manifests[0].encode(), grant, now)?;
            if manifest.manifest_id() != &id
                || p.ciphertext_bytes != manifest.length()
                || p.retained_until != manifest.validity().expires
            {
                return Err(MailboxError::Invalid);
            }
        }
        MailboxOperation::Acknowledge => {
            if !manifests.is_empty()
                || p.message_id.as_slice() != command.message_id.ok_or(MailboxError::Invalid)?
                || !p.acknowledged
                || p.ciphertext_bytes != 0
            {
                return Err(MailboxError::Invalid);
            }
        }
    }
    Ok(receipt)
}

async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    maximum: usize,
) -> Result<Vec<u8>, MailboxError> {
    let size = stream.read_u32().await? as usize;
    if size == 0 || size > maximum || size > MAX_WIRE_FRAME {
        return Err(MailboxError::Invalid);
    }
    let mut bytes = vec![0; size];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}
async fn write_frame<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
) -> Result<(), MailboxError> {
    if bytes.is_empty() || bytes.len() > MAX_WIRE_FRAME {
        return Err(MailboxError::Invalid);
    }
    stream
        .write_u32(u32::try_from(bytes.len()).map_err(|_| MailboxError::Invalid)?)
        .await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}
async fn read_ciphertext<S: AsyncRead + Unpin>(
    stream: &mut S,
    length: u64,
) -> Result<Vec<u8>, MailboxError> {
    let length = usize::try_from(length).map_err(|_| MailboxError::Invalid)?;
    if length == 0 || length > MAX_CIPHERTEXT_BYTES {
        return Err(MailboxError::Invalid);
    }
    let mut result = Vec::with_capacity(length);
    while result.len() < length {
        let remaining = length - result.len();
        let chunk = read_frame(stream, remaining.min(CHUNK_BYTES)).await?;
        if chunk.len() != remaining.min(CHUNK_BYTES) {
            return Err(MailboxError::Invalid);
        }
        result.extend_from_slice(&chunk);
    }
    Ok(result)
}
async fn write_ciphertext<S: AsyncWrite + Unpin>(
    stream: &mut S,
    bytes: &[u8],
) -> Result<(), MailboxError> {
    if bytes.is_empty() || bytes.len() > MAX_CIPHERTEXT_BYTES {
        return Err(MailboxError::Invalid);
    }
    for chunk in bytes.chunks(CHUNK_BYTES) {
        write_frame(stream, chunk).await?;
    }
    Ok(())
}
fn unix_now() -> Result<u64, MailboxError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .map_err(|_| MailboxError::Expired)
}

#[cfg(test)]
mod tests;
