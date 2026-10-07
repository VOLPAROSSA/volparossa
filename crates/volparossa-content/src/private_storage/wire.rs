//! One provider-authorized private custody operation on an already protected stream.
//!
//! The surrounding transport must independently authenticate the provider and preserve the
//! normal relay/exit privacy boundary. This module never opens a socket or discovers trust.
//! A session issues one fresh challenge, executes at most one exact signed operation and
//! ends. Reconnection obtains a new challenge; durable idempotency belongs to the provider.

#[cfg(test)]
mod tests;

use std::{
    sync::{Arc, Mutex},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use prost::Message;
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _},
    sync::Semaphore,
    time::timeout,
};

use super::{
    StorageAdmissionStatus,
    protocol::{
        MAX_AUTH_SECONDS, MAX_CHALLENGE_BYTES, MAX_GRANT_BYTES, MAX_RECEIPT_BYTES,
        MAX_REQUEST_BYTES, ProtocolError, SignedStorageGrant, SignedStorageReceipt,
        SignedStorageRequest, StorageChallenge, StorageOperation, VerifiedStorageGrant,
        VerifiedStorageRequest,
    },
    provider::PrivateStorageProvider,
};
use crate::{CHUNK_BYTES, Validity};

/// Additive private-storage selector; it is not the mailbox or public-cache protocol.
pub const SELECTOR_VERSION: u32 = 1;
/// Explicit private-storage operation in the existing protected publication multiplexor.
pub const SELECTOR_OPERATION: u32 = 6;
const IO_TIMEOUT: Duration = Duration::from_secs(MAX_AUTH_SECONDS);

/// Fixed-scope error; no plaintext, key, local path or peer-supplied diagnostic is displayed.
#[derive(Debug, thiserror::Error)]
pub enum WireError {
    /// The supplied protected stream failed; no alternative transport is authorized.
    #[error("private storage stream failed")]
    Io(#[from] std::io::Error),
    /// Signed metadata does not authorize this exact operation.
    #[error("private storage authentication failed")]
    Protocol(#[from] ProtocolError),
    /// A frame or separately transferred payload violates the original bounded scope.
    #[error("invalid private storage frame or payload")]
    Invalid,
    /// The provider disk slot or the caller's transfer budget refuses admission.
    #[error("private storage provider busy")]
    Busy,
    /// The actual owned durable store could not complete the operation.
    #[error("private storage operation failed")]
    Store,
    /// The original finite exchange deadline expired; side effects may need reconciliation.
    #[error("private storage operation timed out")]
    Timeout,
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

/// A verified request-bound provider statement and, only for `ReadRange`, opaque ciphertext.
/// Reading does not consume a copy. Reassembly must still verify the original whole hash.
pub struct StorageTransfer {
    /// Original signed receipt; not a global contribution or future-availability guarantee.
    pub receipt: SignedStorageReceipt,
    /// Exact requested range, at most 16 MiB; empty for all other operations.
    pub ciphertext: Vec<u8>,
}

/// Exact remote statement retained after the bounded local handoff; no payload copy remains.
pub struct StorageBridgeReceipt {
    /// Original signed provider receipt, verified against the owner's exact request.
    pub receipt: SignedStorageReceipt,
    /// Number of range bytes forwarded to the local owner, zero for other operations.
    pub ciphertext_bytes: u64,
}

/// Explicit service owner. Synchronous database/hash work never runs on the async reactor.
/// No listener, advertisement, grant issuance or automatic contribution is started here.
pub struct StorageService {
    signer: Arc<SigningKey>,
    provider: Arc<Mutex<PrivateStorageProvider>>,
    disk_slot: Arc<Semaphore>,
}

impl StorageService {
    /// Attach the already owned backend to this independently configured provider identity.
    /// Backend authorization also rejects requests for a different pinned provider.
    #[must_use]
    pub fn new(signer: Arc<SigningKey>, provider: PrivateStorageProvider) -> Self {
        Self {
            signer,
            provider: Arc::new(Mutex::new(provider)),
            disk_slot: Arc::new(Semaphore::new(1)),
        }
    }

    /// Inspect or set the local provider owner's admission target on the existing disk slot.
    /// `None` inspects; `Some` persists a target without revoking any lease. The enclosing
    /// local control API must authenticate the service owner; this is not a remote operation.
    /// A cancelled caller cannot release an in-flight blocking operation's disk permit.
    ///
    /// # Errors
    /// Rejects a busy disk slot, invalid target/accounting or database failure. A lost reply
    /// does not undo a durable update: inspect the same store to reconcile it.
    pub async fn admission(
        &self,
        target: Option<u64>,
    ) -> Result<StorageAdmissionStatus, WireError> {
        let permit = Arc::clone(&self.disk_slot)
            .try_acquire_owned()
            .map_err(|_| WireError::Busy)?;
        let provider = Arc::clone(&self.provider);
        tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut provider = provider.lock().map_err(|_| WireError::Store)?;
            match target {
                Some(bytes) => provider.set_admission_target(bytes),
                None => provider.admission_status(),
            }
            .map_err(|_| WireError::Store)
        })
        .await
        .map_err(|_| WireError::Store)?
    }

    /// Execute exactly one operation after the enclosing selector has been validated.
    ///
    /// A dropped/timed-out exchange cannot release an in-flight synchronous disk operation's
    /// permit: its blocking closure owns the permit until completion. No unbounded work queue
    /// or implicit operation retry is created. The caller bounds transport connections.
    ///
    /// # Errors
    /// Rejects unauthorized/stale metadata, wrong payload, exhausted admission or disk failure.
    /// A missing receipt never proves that an operation did not commit; reconcile on reconnect.
    pub async fn serve<S>(&self, stream: &mut S) -> Result<(), WireError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        timeout(IO_TIMEOUT, self.serve_inner(stream))
            .await
            .map_err(|_| WireError::Timeout)?
    }

    async fn serve_inner<S>(&self, stream: &mut S) -> Result<(), WireError>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let grant = SignedStorageGrant::decode(&read_frame(stream, MAX_GRANT_BYTES).await?)?
            .verify(&self.signer.verifying_key(), unix_now()?)?;
        let created = unix_now()?;
        let challenge = StorageChallenge::issue(
            &self.signer,
            &grant,
            Validity {
                created,
                expires: created
                    .saturating_add(MAX_AUTH_SECONDS)
                    .min(grant.validity().expires),
            },
        )?;
        write_frame(stream, &challenge.encode()).await?;
        let request = SignedStorageRequest::decode_and_verify(
            &read_frame(stream, MAX_REQUEST_BYTES).await?,
            &grant,
            &challenge,
            unix_now()?,
        )?;
        // There is no loop back to this challenge: after this point the connection can
        // authorize exactly this operation once. A fresh connection receives a new nonce.
        let payload = if matches!(request.operation(), StorageOperation::Append { .. }) {
            read_frame(stream, CHUNK_BYTES).await?
        } else {
            Vec::new()
        };
        validate_append(&request, &payload)?;
        request.current(unix_now()?)?;
        let permit = Arc::clone(&self.disk_slot)
            .try_acquire_owned()
            .map_err(|_| WireError::Busy)?;
        let provider = Arc::clone(&self.provider);
        let owned_request = request.clone();
        let result = tokio::task::spawn_blocking(move || {
            let _permit = permit;
            let mut provider = provider.lock().map_err(|_| WireError::Store)?;
            provider
                .apply(&owned_request, &payload, unix_now()?)
                .map_err(|_| WireError::Store)
        })
        .await
        .map_err(|_| WireError::Store)??;
        let created = unix_now()?;
        request.current(created)?;
        let receipt = SignedStorageReceipt::sign(
            &self.signer,
            &request,
            result.receipt,
            Validity {
                created,
                expires: request.validity().expires,
            },
        )?;
        validate_range(&request, &receipt, &result.payload)?;
        write_frame(stream, &receipt.encode()).await?;
        if !result.payload.is_empty() {
            write_frame(stream, &result.payload).await?;
        }
        Ok(())
    }
}

/// Select private storage and obtain a fresh challenge for an independently verified grant.
/// The caller must already have authenticated the provider on the protected stream.
///
/// # Errors
/// Rejects unavailable streams, stale grants, wrong providers and malformed challenges.
pub async fn begin<S>(
    stream: &mut S,
    grant: &VerifiedStorageGrant,
) -> Result<StorageChallenge, WireError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(IO_TIMEOUT, async {
        grant.current(unix_now()?)?;
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
        write_frame(stream, &grant.signed().encode()).await?;
        Ok(StorageChallenge::decode_and_verify(
            &read_frame(stream, MAX_CHALLENGE_BYTES).await?,
            grant,
            unix_now()?,
        )?)
    })
    .await
    .map_err(|_| WireError::Timeout)?
}

/// Finish the sole owner-signed operation on the connection that issued this challenge.
/// The original provider grant must already have been independently authenticated.
///
/// # Errors
/// Rejects changed metadata, wrong upload bytes, unrelated/invalid receipts or corrupt ranges.
/// A lost response does not authorize creating a replacement archive or a second quota charge.
pub async fn finish<S>(
    stream: &mut S,
    grant: &VerifiedStorageGrant,
    challenge: &StorageChallenge,
    signed: &SignedStorageRequest,
    append_payload: &[u8],
) -> Result<StorageTransfer, WireError>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    timeout(IO_TIMEOUT, async {
        let request = signed.verify(grant, challenge, unix_now()?)?;
        validate_append(&request, append_payload)?;
        write_frame(stream, &signed.encode()).await?;
        if !append_payload.is_empty() {
            write_frame(stream, append_payload).await?;
        }
        let receipt = SignedStorageReceipt::decode_and_verify(
            &read_frame(stream, MAX_RECEIPT_BYTES).await?,
            &request,
            unix_now()?,
        )?;
        let ciphertext = if let StorageOperation::ReadRange { length, .. } = request.operation() {
            let maximum = usize::try_from(length).map_err(|_| WireError::Invalid)?;
            read_frame(stream, maximum).await?
        } else {
            Vec::new()
        };
        validate_range(&request, &receipt, &ciphertext)?;
        request.current(unix_now()?)?;
        Ok(StorageTransfer {
            receipt,
            ciphertext,
        })
    })
    .await
    .map_err(|_| WireError::Timeout)?
}

/// Forward one owner-authorized operation on the two original, already protected streams.
///
/// The agent passes the provider challenge to its local caller before entering this bridge.
/// The caller signs it without sending an owner key to the agent. Only canonical signed
/// metadata and bounded ciphertext cross this handoff; no commands or local paths occur.
/// A verified provider receipt is forwarded unchanged, not replaced with an agent statement.
/// The surrounding agent must still finish its TLS/route checks before local terminal success.
///
/// # Errors
/// Rejects changed grants/challenges, invalid owner signatures, oversized/corrupt payloads,
/// unrelated provider receipts and incomplete transfers. Missing success requires reconciliation.
pub async fn bridge<L, R>(
    local: &mut L,
    remote: &mut R,
    grant: &VerifiedStorageGrant,
    challenge: &StorageChallenge,
) -> Result<StorageBridgeReceipt, WireError>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
{
    bridge_admitted(local, remote, grant, challenge, |_| async { true }).await
}

/// Bridge the same authenticated request, admitting its validated byte demand before
/// forwarding any operation. The caller owns cancellation and shared resource accounting.
/// The charge is the signed read-range length or verified append payload length, plus
/// 8192 bytes for bounded protocol metadata/framing; it is not measured transport overhead.
/// A rejected admission writes nothing to the remote stream and creates no provider state.
///
/// # Errors
/// Returns the ordinary bridge errors, or `Busy` when the resource admission declines.
pub async fn bridge_admitted<L, R, A, F>(
    local: &mut L,
    remote: &mut R,
    grant: &VerifiedStorageGrant,
    challenge: &StorageChallenge,
    admit: A,
) -> Result<StorageBridgeReceipt, WireError>
where
    L: AsyncRead + AsyncWrite + Unpin,
    R: AsyncRead + AsyncWrite + Unpin,
    A: FnOnce(u64) -> F,
    F: Future<Output = bool>,
{
    timeout(IO_TIMEOUT, async {
        let request = SignedStorageRequest::decode_and_verify(
            &read_frame(local, MAX_REQUEST_BYTES).await?,
            grant,
            challenge,
            unix_now()?,
        )?;
        let payload = if matches!(request.operation(), StorageOperation::Append { .. }) {
            read_frame(local, CHUNK_BYTES).await?
        } else {
            Vec::new()
        };
        validate_append(&request, &payload)?;
        let incoming = match request.operation() {
            StorageOperation::ReadRange { length, .. } => length,
            _ => 0,
        };
        // Exact authenticated payload lengths plus conservative bounded metadata/framing.
        let charged = incoming
            .saturating_add(payload.len() as u64)
            .saturating_add(8192);
        if !admit(charged).await {
            return Err(WireError::Busy);
        }
        let transfer = finish(remote, grant, challenge, request.signed(), &payload).await?;
        let ciphertext_bytes =
            u64::try_from(transfer.ciphertext.len()).map_err(|_| WireError::Invalid)?;
        write_frame(local, &transfer.receipt.encode()).await?;
        if !transfer.ciphertext.is_empty() {
            write_frame(local, &transfer.ciphertext).await?;
        }
        Ok(StorageBridgeReceipt {
            receipt: transfer.receipt,
            ciphertext_bytes,
        })
    })
    .await
    .map_err(|_| WireError::Timeout)?
}

fn validate_append(request: &VerifiedStorageRequest, payload: &[u8]) -> Result<(), WireError> {
    match request.operation() {
        StorageOperation::Append { length, sha256, .. }
            if u64::try_from(payload.len()).ok() == Some(u64::from(length))
                && <[u8; 32]>::from(Sha256::digest(payload)) == sha256 =>
        {
            Ok(())
        }
        StorageOperation::Append { .. } => Err(WireError::Invalid),
        _ if payload.is_empty() => Ok(()),
        _ => Err(WireError::Invalid),
    }
}

fn validate_range(
    request: &VerifiedStorageRequest,
    receipt: &SignedStorageReceipt,
    payload: &[u8],
) -> Result<(), WireError> {
    match request.operation() {
        StorageOperation::ReadRange { length, .. }
            if u64::try_from(payload.len()).ok() == Some(length)
                && receipt.result().range_sha256 == Some(Sha256::digest(payload).into()) =>
        {
            Ok(())
        }
        StorageOperation::ReadRange { .. } => Err(WireError::Invalid),
        _ if payload.is_empty() => Ok(()),
        _ => Err(WireError::Invalid),
    }
}

async fn read_frame<S: AsyncRead + Unpin>(
    stream: &mut S,
    maximum: usize,
) -> Result<Vec<u8>, WireError> {
    let length = stream.read_u32().await? as usize;
    if length == 0 || length > maximum {
        return Err(WireError::Invalid);
    }
    let mut bytes = vec![0; length];
    stream.read_exact(&mut bytes).await?;
    Ok(bytes)
}

async fn write_frame<S: AsyncWrite + Unpin>(stream: &mut S, bytes: &[u8]) -> Result<(), WireError> {
    let length = u32::try_from(bytes.len()).map_err(|_| WireError::Invalid)?;
    if length == 0 {
        return Err(WireError::Invalid);
    }
    stream.write_u32(length).await?;
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}

fn unix_now() -> Result<u64, WireError> {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|value| value.as_secs())
        .map_err(|_| WireError::Invalid)
}
