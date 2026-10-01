//! Owner-coordinated A/B -> B/C handoff over the existing protected storage operations.
//!
//! Replacement is not permission for a provider to move somebody else's lease. The owner
//! stays online and signs every request. Full readback proves current retrievability, not
//! independent physical failure domains or future availability. Uncertainty remains charged.

use std::{fs::File, path::Path};

use anyhow::{Result, ensure};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use volparossa_content::private_storage::protocol::{
    ReceiptState, StorageOperation, StorageRights, VerifiedStorageGrant,
};

use super::{
    retained::{Charge, HandoffPhase, LockedSet},
    state::LockedJournal,
    transfer,
};

fn copy_for_owner(
    set: &LockedSet,
    index: usize,
    signer: &SigningKey,
) -> Result<(LockedJournal, VerifiedStorageGrant)> {
    let copy = set.copy(index)?;
    let provider = VerifyingKey::from_bytes(&set.data.copies[index].provider_key)?;
    let grant = copy.journal.grant(&provider, &signer.verifying_key())?;
    Ok((copy, grant))
}

fn report(set: &LockedSet, stage: &str) -> Result<serde_json::Value> {
    let mut report = set.report("replace")?;
    report["operation_complete"] = (stage == "complete").into();
    report["handoff_stage"] = stage.into();
    report["pending_handoff"] = (stage != "complete").into();
    report["automatic_contribution_resize"] = false.into();
    Ok(report)
}

/// Retry the exact retained replacement; no retry creates another archive or implicit trust.
pub(super) async fn replace(
    set: &mut LockedSet,
    socket: &Path,
    signer: &SigningKey,
    from: VerifyingKey,
    replacement: &VerifiedStorageGrant,
    lifetime: u64,
) -> Result<serde_json::Value> {
    set.check_owner(signer)?;
    let required = StorageRights::RESERVE
        .union(StorageRights::APPEND)
        .union(StorageRights::PROGRESS)
        .union(StorageRights::FINALIZE)
        .union(StorageRights::READ_RANGE);
    ensure!(
        replacement.limits().rights.bits() & required.bits() == required.bits(),
        "replacement grant must permit resumable upload and full readback"
    );
    let (from_index, to_index) = set.prepare_handoff(&from, replacement, lifetime)?;
    if set
        .data
        .handoff
        .as_ref()
        .is_some_and(|intent| intent.phase == HandoffPhase::Complete)
    {
        return report(set, "complete");
    }
    // The source is a surviving owner-authorized copy, never the provider being drained.
    // One private ciphertext staging file reuses the existing resumable upload implementation.
    let staging = set.handoff_staging()?;
    let Some((survivor, mut input)) =
        read_survivor(set, socket, signer, from_index, to_index, staging.path()).await?
    else {
        return report(set, "survivor_unavailable");
    };
    let (mut target, grant) = copy_for_owner(set, to_index, signer)?;
    set.begin(to_index)?;
    if transfer::deposit_retained(socket, &grant, signer, &mut target, &mut input)
        .await
        .is_err()
    {
        drop(target);
        return report(set, "replacement_upload_pending");
    }
    // A Committed receipt is not sufficient: retrieve every byte from the new provider.
    // On EVERY incomplete retry this is repeated before any source deletion, even if a
    // previous process recorded DeletePending or uploaded the complete replacement.
    if verify_copy(socket, &grant, signer, &mut target)
        .await
        .is_err()
    {
        drop(target);
        return report(set, "replacement_verification_pending");
    }
    let target_expires = target.journal.last_expiry;
    set.confirm(to_index, &target.journal)?;
    drop(target);
    if !refresh_survivor(set, socket, signer, survivor).await? {
        return report(set, "survivor_unavailable");
    }
    if target_expires <= crate::storage::now()? || grant.current(crate::storage::now()?).is_err() {
        return report(set, "replacement_verification_pending");
    }
    // Another owner operation may have renewed the old copy since this intent was
    // planned. A retry must not retire that longer obligation onto a shorter lease.
    let original_expiry = {
        let original = set.copy(from_index)?;
        original
            .journal
            .last_expiry
            .max(original.journal.requested_expiry)
    };
    if target_expires < original_expiry {
        return report(set, "replacement_retention_insufficient");
    }
    set.handoff_phase(HandoffPhase::DeletePending)?;
    let Ok((mut original, original_grant)) = copy_for_owner(set, from_index, signer) else {
        return report(set, "source_delete_unconfirmed");
    };
    set.begin(from_index)?;
    if transfer::operate_retained(
        socket,
        &original_grant,
        signer,
        &mut original,
        StorageOperation::Delete,
    )
    .await
    .is_err()
    {
        drop(original);
        return report(set, "source_delete_unconfirmed");
    }
    ensure!(
        original.journal.last_state == Some(ReceiptState::Deleted as i32),
        "source deletion was not explicitly confirmed"
    );
    set.confirm(from_index, &original.journal)?;
    drop(original);
    set.handoff_phase(HandoffPhase::Complete)?;
    report(set, "complete")
}

async fn read_survivor(
    set: &mut LockedSet,
    socket: &Path,
    signer: &SigningKey,
    from: usize,
    to: usize,
    staging: &Path,
) -> Result<Option<(usize, File)>> {
    for index in 0..set.data.copies.len() {
        if index == from
            || index == to
            || matches!(
                set.data.copies[index].charge,
                Charge::Deleted | Charge::Unattempted
            )
        {
            continue;
        }
        let Ok((mut copy, grant)) = copy_for_owner(set, index, signer) else {
            continue;
        };
        if copy.journal.lease.is_none() {
            continue;
        }
        let output = staging.join(format!("survivor-{index}"));
        set.begin(index)?;
        if transfer::restore_retained(socket, &grant, signer, &mut copy, &output)
            .await
            .is_ok()
        {
            set.confirm(index, &copy.journal)?;
            return Ok(Some((index, File::open(output)?)));
        }
    }
    Ok(None)
}

async fn verify_copy(
    socket: &Path,
    grant: &VerifiedStorageGrant,
    signer: &SigningKey,
    copy: &mut LockedJournal,
) -> Result<()> {
    transfer::operate_retained(socket, grant, signer, copy, StorageOperation::Progress).await?;
    ensure!(
        copy.journal.last_state == Some(ReceiptState::Committed as i32),
        "replacement is not committed"
    );
    let mut hasher = Sha256::new();
    let mut offset = 0;
    let total = copy.journal.ciphertext_bytes;
    while offset < total {
        let length = (total - offset).min(transfer::range_bytes());
        let reply = transfer::remote(
            socket,
            grant,
            signer,
            transfer::known_target(&copy.journal)?,
            StorageOperation::ReadRange { offset, length },
            &[],
        )
        .await?;
        ensure!(
            reply.ciphertext.len() as u64 == length,
            "replacement readback is truncated"
        );
        hasher.update(&reply.ciphertext);
        copy.journal.apply(reply.receipt.result())?;
        copy.save()?;
        offset += length;
    }
    let actual: [u8; 32] = hasher.finalize().into();
    ensure!(
        offset == total && actual == copy.journal.sha256,
        "replacement full readback differs from the original archive"
    );
    Ok(())
}

async fn refresh_survivor(
    set: &mut LockedSet,
    socket: &Path,
    signer: &SigningKey,
    index: usize,
) -> Result<bool> {
    let Ok((mut copy, grant)) = copy_for_owner(set, index, signer) else {
        return Ok(false);
    };
    set.begin(index)?;
    if transfer::operate_retained(
        socket,
        &grant,
        signer,
        &mut copy,
        StorageOperation::Progress,
    )
    .await
    .is_err()
        || copy.journal.last_state != Some(ReceiptState::Committed as i32)
    {
        return Ok(false);
    }
    set.confirm(index, &copy.journal)?;
    Ok(true)
}
