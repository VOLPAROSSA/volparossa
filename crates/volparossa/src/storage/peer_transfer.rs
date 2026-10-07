//! Bounded streaming transfers, each operation retaining its exact protected agent connection.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    path::Path,
    time::Duration,
};

use anyhow::{Context as _, Result, bail, ensure};
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use volparossa_content::{
    CHUNK_BYTES, Validity,
    private_storage::{
        MAX_ARCHIVE_BYTES, MAX_RANGE_BYTES,
        protocol::{
            MAX_GRANT_BYTES, ReceiptState, SignedStorageGrant, SignedStorageRequest,
            StorageChallenge, StorageOperation, StorageTarget, VerifiedStorageGrant,
        },
        wire::{self, StorageTransfer},
    },
};
use volparossa_local_control::{
    ContentReceipt, PrivateStorageRemoteRequest, control_request::Operation,
    control_response::Payload,
};

use super::{
    Deposit, Existing, Restore,
    state::{self, Journal, LockedJournal},
};

tokio::task_local! {
    static MAINTENANCE_TURN: Vec<u8>;
}

/// Background reads grant at most one upload-sized chunk; ordinary range reads are unchanged.
pub(super) fn range_bytes() -> u64 {
    if MAINTENANCE_TURN.try_with(|_| ()).is_ok() {
        CHUNK_BYTES as u64
    } else {
        MAX_RANGE_BYTES
    }
}

/// One core-admitted owner operation, without changing the foreground CLI's transport.
pub(super) async fn with_maintenance_turn<F: Future>(token: Vec<u8>, work: F) -> F::Output {
    MAINTENANCE_TURN.scope(token, work).await
}

pub(super) async fn deposit(args: Deposit, socket: &Path) -> Result<serde_json::Value> {
    ensure!(
        args.already_encrypted,
        "already-encrypted acknowledgement is required"
    );
    let signer = args.existing.unlock.signer()?;
    let encoded = state::read_private(&args.grant, MAX_GRANT_BYTES as u64)?;
    let grant = SignedStorageGrant::decode(&encoded)?
        .verify(&args.existing.provider_key, super::super::now()?)?;
    ensure!(
        grant.owner_key() == &signer.verifying_key(),
        "grant does not authorize this unlocked owner"
    );
    let expected = super::super::parse_hash(&args.sha256)?;
    let (mut input, length) = checked_input(&args.input, expected)?;
    let mut retained = if args.resume {
        let retained = LockedJournal::open(&args.existing.state)?;
        let original = retained
            .journal
            .grant(&args.existing.provider_key, &signer.verifying_key())?;
        ensure!(
            original.signed().encode() == encoded
                && retained.journal.ciphertext_bytes == length
                && retained.journal.sha256 == expected,
            "resume requires the exact original grant and ciphertext identity"
        );
        retained
    } else {
        let expires = requested_expiry(&grant, args.lifetime_seconds)?;
        LockedJournal::create(
            &args.existing.state,
            Journal::new(&grant, length, expected, expires)?,
        )?
    };
    deposit_retained(socket, &grant, &signer, &mut retained, &mut input).await?;
    Ok(report("deposit", &retained.journal))
}

/// Reuse one unlocked owner and the exact original journal; never allocate a new archive on retry.
pub(super) async fn deposit_retained(
    socket: &Path,
    grant: &VerifiedStorageGrant,
    signer: &SigningKey,
    retained: &mut LockedJournal,
    input: &mut File,
) -> Result<()> {
    let length = retained.journal.ciphertext_bytes;
    ensure!(
        retained.journal.last_state != Some(ReceiptState::Deleted as i32),
        "this archive was explicitly deleted; resume cannot resurrect it"
    );
    let initial = observe_or_reserve(socket, grant, signer, retained).await?;
    if initial == ReceiptState::Committed {
        return Ok(());
    }
    let mut offset = retained.journal.last_stored_bytes;
    ensure!(
        offset <= length && (offset == length || offset % CHUNK_BYTES as u64 == 0),
        "invalid provider upload position"
    );
    input.seek(SeekFrom::Start(offset))?;
    let mut chunk = vec![0; CHUNK_BYTES];
    while offset < length {
        let count = usize::try_from((length - offset).min(CHUNK_BYTES as u64))?;
        input
            .read_exact(&mut chunk[..count])
            .context("ciphertext changed or became truncated during upload")?;
        let operation = StorageOperation::Append {
            offset,
            length: u32::try_from(count)?,
            sha256: Sha256::digest(&chunk[..count]).into(),
        };
        let reply = remote(
            socket,
            grant,
            signer,
            retained.journal.target()?,
            operation,
            &chunk[..count],
        )
        .await?;
        let result = reply.receipt.result();
        ensure!(
            result.stored_bytes == offset + count as u64,
            "provider did not retain the exact appended prefix"
        );
        retained.journal.apply(result)?;
        retained.save()?;
        offset = result.stored_bytes;
    }
    let reply = remote(
        socket,
        grant,
        signer,
        retained.journal.target()?,
        StorageOperation::Finalize,
        &[],
    )
    .await?;
    ensure!(
        reply.receipt.result().state == ReceiptState::Committed,
        "provider did not commit the verified archive"
    );
    retained.journal.apply(reply.receipt.result())?;
    retained.save()?;
    Ok(())
}

pub(super) async fn existing(
    args: Existing,
    socket: &Path,
    renewal: Option<u64>,
    delete: bool,
) -> Result<serde_json::Value> {
    let signer = args.unlock.signer()?;
    let mut retained = LockedJournal::open(&args.state)?;
    let grant = retained
        .journal
        .grant(&args.provider_key, &signer.verifying_key())?;
    // Only explicit deposit --resume may repeat Reserve to reconcile a lost first reply.
    // Progress, renewal and deletion must not allocate an unseen initial reservation.
    let (name, operation) = if delete {
        ("delete", StorageOperation::Delete)
    } else if let Some(lifetime) = renewal {
        (
            "renew",
            StorageOperation::Renew {
                expires_at: requested_expiry(&grant, lifetime)?,
            },
        )
    } else {
        ("progress", StorageOperation::Progress)
    };
    operate_retained(socket, &grant, &signer, &mut retained, operation).await?;
    Ok(report(name, &retained.journal))
}

pub(super) async fn operate_retained(
    socket: &Path,
    grant: &VerifiedStorageGrant,
    signer: &SigningKey,
    retained: &mut LockedJournal,
    operation: StorageOperation,
) -> Result<()> {
    let target = known_target(&retained.journal)?;
    let reply = remote(socket, grant, signer, target, operation, &[]).await?;
    retained.journal.apply(reply.receipt.result())?;
    retained.save()
}

pub(super) fn known_target(journal: &Journal) -> Result<StorageTarget> {
    let target = journal.target()?;
    ensure!(
        target.lease_id.is_some(),
        "unknown initial reservation; use deposit --resume to reconcile it first"
    );
    Ok(target)
}

pub(super) async fn restore(args: Restore, socket: &Path) -> Result<serde_json::Value> {
    state::new_output(&args.output)?;
    let signer = args.existing.unlock.signer()?;
    let mut retained = LockedJournal::open(&args.existing.state)?;
    let grant = retained
        .journal
        .grant(&args.existing.provider_key, &signer.verifying_key())?;
    restore_retained(socket, &grant, &signer, &mut retained, &args.output).await?;
    Ok(report("restore", &retained.journal))
}

pub(super) async fn restore_retained(
    socket: &Path,
    grant: &VerifiedStorageGrant,
    signer: &SigningKey,
    retained: &mut LockedJournal,
    destination: &Path,
) -> Result<()> {
    state::new_output(destination)?;
    let target = known_target(&retained.journal)?;
    let reply = remote(
        socket,
        grant,
        signer,
        target,
        StorageOperation::Progress,
        &[],
    )
    .await?;
    ensure!(
        reply.receipt.result().state == ReceiptState::Committed,
        "archive is not committed and readable"
    );
    retained.journal.apply(reply.receipt.result())?;
    retained.save()?;
    let parent = destination
        .parent()
        .context("missing restore output parent")?;
    let mut output = tempfile::NamedTempFile::new_in(parent)?;
    output
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    let mut hash = Sha256::new();
    let mut offset = 0;
    while offset < retained.journal.ciphertext_bytes {
        let length = (retained.journal.ciphertext_bytes - offset).min(range_bytes());
        let reply = remote(
            socket,
            grant,
            signer,
            retained.journal.target()?,
            StorageOperation::ReadRange { offset, length },
            &[],
        )
        .await?;
        ensure!(
            reply.ciphertext.len() as u64 == length,
            "provider returned an incomplete restore range"
        );
        output.write_all(&reply.ciphertext)?;
        hash.update(&reply.ciphertext);
        offset += length;
    }
    let digest: [u8; 32] = hash.finalize().into();
    ensure!(
        offset == retained.journal.ciphertext_bytes && digest == retained.journal.sha256,
        "restored ciphertext does not match the original full archive identity"
    );
    output.as_file().sync_all()?;
    output
        .persist_noclobber(destination)
        .map_err(|error| error.error)
        .context("cannot expose verified restore without overwriting an existing file")?;
    File::open(parent)?.sync_all()?;
    Ok(())
}

async fn observe_or_reserve(
    socket: &Path,
    grant: &VerifiedStorageGrant,
    signer: &SigningKey,
    retained: &mut LockedJournal,
) -> Result<ReceiptState> {
    let operation = if retained.journal.lease.is_some() {
        StorageOperation::Progress
    } else {
        StorageOperation::Reserve {
            expires_at: retained.journal.requested_expiry,
        }
    };
    let reply = remote(
        socket,
        grant,
        signer,
        retained.journal.target()?,
        operation,
        &[],
    )
    .await?;
    retained.journal.apply(reply.receipt.result())?;
    retained.save()?;
    Ok(reply.receipt.result().state)
}

pub(super) fn requested_expiry(grant: &VerifiedStorageGrant, lifetime: u64) -> Result<u64> {
    ensure!(
        lifetime <= grant.limits().max_retention_seconds,
        "requested lease exceeds provider retention permission"
    );
    let expires = super::super::expiry(super::super::now()?, lifetime)?;
    ensure!(
        expires <= grant.validity().expires,
        "requested lease outlives the original provider grant"
    );
    Ok(expires)
}

pub(super) fn checked_input(path: &Path, expected: [u8; 32]) -> Result<(File, u64)> {
    super::super::require_absolute(path)?;
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
        .open(path)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.is_file() && (1..=MAX_ARCHIVE_BYTES).contains(&metadata.len()),
        "ciphertext must be a bounded nonempty regular file"
    );
    let length = metadata.len();
    let mut hash = Sha256::new();
    let mut buffer = vec![0; CHUNK_BYTES];
    let mut read = 0;
    loop {
        let count = file.read(&mut buffer)?;
        if count == 0 {
            break;
        }
        read += count as u64;
        ensure!(
            read <= length,
            "ciphertext grew while verifying its identity"
        );
        hash.update(&buffer[..count]);
    }
    let actual: [u8; 32] = hash.finalize().into();
    ensure!(
        read == length && actual == expected,
        "ciphertext does not match the pinned full SHA-256 and length"
    );
    file.rewind()?;
    Ok((file, length))
}

pub(super) async fn remote(
    socket: &Path,
    grant: &VerifiedStorageGrant,
    signer: &SigningKey,
    target: StorageTarget,
    operation: StorageOperation,
    payload: &[u8],
) -> Result<StorageTransfer> {
    tokio::time::timeout(Duration::from_secs(600), async {
        grant.current(super::super::now()?)?;
        ensure!(
            grant.owner_key() == &signer.verifying_key() && grant.limits().rights.allows(operation),
            "owner operation is not granted"
        );
        let request = PrivateStorageRemoteRequest {
            provider_key: grant.provider_key().to_bytes().to_vec(),
            grant: grant.signed().encode(),
            maintenance_turn: MAINTENANCE_TURN.try_with(Clone::clone).unwrap_or_default(),
        };
        let (mut stream, request_id, response) =
            crate::control::begin_request(socket, Operation::PrivateStorageRemote(request)).await?;
        ensure!(
            response.diagnostic_code == "PRIVATE_STORAGE_READY",
            "missing explicit private storage readiness"
        );
        let Some(Payload::PrivateStorageReady(ready)) = response.payload else {
            bail!("wrong private storage readiness payload")
        };
        ensure!(
            ready.provider_key == grant.provider_key().as_bytes(),
            "agent selected a different private storage provider"
        );
        let now = super::super::now()?;
        let challenge = StorageChallenge::decode_and_verify(&ready.challenge, grant, now)?;
        let request = SignedStorageRequest::sign(
            signer,
            grant,
            &challenge,
            target,
            operation,
            Validity {
                created: now,
                expires: challenge.validity().expires,
            },
        )?;
        let result = wire::finish(&mut stream, grant, &challenge, &request, payload).await?;
        let response = crate::control::finish_request(&mut stream, &request_id).await?;
        let Some(Payload::Content(receipt)) = response.payload else {
            bail!("missing final private storage transfer receipt")
        };
        ensure!(
            response.diagnostic_code == "CONTENT_OK",
            "private storage transfer did not finish normally"
        );
        accounting(&receipt, grant, result.ciphertext.len() as u64)?;
        Ok(result)
    })
    .await
    .context("private storage operation exceeded its deadline; journal retained for retry")?
}

fn accounting(receipt: &ContentReceipt, grant: &VerifiedStorageGrant, bytes: u64) -> Result<()> {
    let mut key = vec![8, 1, 18, 32];
    key.extend_from_slice(grant.provider_key().as_bytes());
    let peer = volparossa_identity::PublicKey::try_decode_protobuf(&key)?
        .to_peer_id()
        .to_string();
    ensure!(
        receipt.bytes == bytes
            && receipt.peer_bytes == bytes
            && receipt.providers_used == 1
            && receipt.provider_peer_ids == [peer]
            && !receipt.control_relay_peer_id.is_empty()
            && !receipt.origin_authenticated
            && receipt.origin_body_bytes == 0
            && receipt.origin_range_requests == 0
            && !receipt.network_publication,
        "final private storage accounting differs from the authenticated protected transfer"
    );
    Ok(())
}

fn report(operation: &str, journal: &Journal) -> serde_json::Value {
    let state = journal
        .last_state
        .and_then(|value| ReceiptState::try_from(value).ok());
    serde_json::json!({
        "operation": format!("private_storage_peer_{operation}"),
        "state": state.map(|value| format!("{value:?}")),
        "ciphertext_bytes": journal.ciphertext_bytes,
        "stored_bytes": journal.last_stored_bytes,
        "expires_unix_seconds": journal.last_expiry,
        "committed": state == Some(ReceiptState::Committed),
        "restored": operation == "restore", "read_consumes_archive": false,
        "provider_copies_addressed": 1, "independent_replication_proven": false,
        "automatic_replication": false, "network_contribution_credit": false
    })
}
