//! Sequential copies and restore failover; no automatic deletion, provider discovery or new trust.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    path::Path,
};

use anyhow::{Result, ensure};
use ed25519_dalek::{SigningKey, VerifyingKey};
use volparossa_content::private_storage::protocol::{StorageOperation, VerifiedStorageGrant};

use super::{
    super::{
        state::{self, LockedJournal},
        transfer,
    },
    retained::{Charge, LockedSet},
};

fn copy_for_owner(
    set: &LockedSet,
    index: usize,
    signer: &SigningKey,
) -> Result<(LockedJournal, VerifiedStorageGrant)> {
    let retained = set.copy(index)?;
    let key = VerifyingKey::from_bytes(&set.data.copies[index].provider_key)?;
    let grant = retained.journal.grant(&key, &signer.verifying_key())?;
    Ok((retained, grant))
}

fn finish_report(
    set: &LockedSet,
    operation: &str,
    outcomes: &[&str],
    complete: bool,
) -> Result<serde_json::Value> {
    let mut report = set.report(operation)?;
    report["operation_complete"] = complete.into();
    report["copy_outcomes"] = serde_json::json!(outcomes);
    Ok(report)
}

pub(super) async fn deposit(
    set: &mut LockedSet,
    socket: &Path,
    signer: &SigningKey,
    input: &mut File,
) -> Result<serde_json::Value> {
    deposit_selected(set, socket, signer, input, &BTreeSet::new()).await
}

pub(super) async fn deposit_selected(
    set: &mut LockedSet,
    socket: &Path,
    signer: &SigningKey,
    input: &mut File,
    retiring: &BTreeSet<usize>,
) -> Result<serde_json::Value> {
    set.check_owner(signer)?;
    let mut outcomes = Vec::new();
    let mut completed = 0;
    let mut eligible = 0;
    for index in 0..set.data.copies.len() {
        if retiring.contains(&index) {
            outcomes.push("retiring_not_deposited");
            continue;
        }
        if set.data.copies[index].charge == Charge::Deleted {
            outcomes.push("explicitly_deleted");
            continue;
        }
        eligible += 1;
        let Ok((mut retained, grant)) = copy_for_owner(set, index, signer) else {
            outcomes.push("unavailable_or_grant_invalid");
            continue;
        };
        set.begin(index)?;
        if transfer::deposit_retained(socket, &grant, signer, &mut retained, input)
            .await
            .is_ok()
        {
            set.confirm(index, &retained.journal)?;
            completed += 1;
            outcomes.push("committed");
        } else {
            // Last acknowledged prefixes remain in archive.json; retries reuse that same archive.
            outcomes.push("incomplete_retained_for_retry");
        }
    }
    finish_report(
        set,
        "deposit",
        &outcomes,
        eligible != 0 && completed == eligible,
    )
}

pub(super) async fn refresh(
    set: &mut LockedSet,
    socket: &Path,
    signer: &SigningKey,
    renewal: Option<u64>,
) -> Result<serde_json::Value> {
    refresh_selected(set, socket, signer, renewal, &BTreeSet::new()).await
}

pub(super) async fn refresh_selected(
    set: &mut LockedSet,
    socket: &Path,
    signer: &SigningKey,
    renewal: Option<u64>,
    retiring: &BTreeSet<usize>,
) -> Result<serde_json::Value> {
    refresh_selected_inner(set, socket, signer, renewal, retiring, false).await
}

/// Autonomous renewal first observes current retention, including an earlier lost reply.
/// It never turns a healthy longer-lived copy into an uncertain shorter-renewal attempt.
pub(super) async fn refresh_maintenance(
    set: &mut LockedSet,
    socket: &Path,
    signer: &SigningKey,
    renewal: Option<u64>,
    retiring: &BTreeSet<usize>,
) -> Result<serde_json::Value> {
    refresh_selected_inner(set, socket, signer, renewal, retiring, true).await
}

async fn refresh_selected_inner(
    set: &mut LockedSet,
    socket: &Path,
    signer: &SigningKey,
    renewal: Option<u64>,
    retiring: &BTreeSet<usize>,
    only_extend: bool,
) -> Result<serde_json::Value> {
    set.check_owner(signer)?;
    let mut outcomes = Vec::new();
    let mut complete = true;
    for index in 0..set.data.copies.len() {
        if renewal.is_some() && retiring.contains(&index) {
            outcomes.push("retiring_not_renewed");
            continue;
        }
        if set.data.copies[index].charge == Charge::Deleted {
            outcomes.push("explicitly_deleted");
            continue;
        }
        let Ok((mut retained, grant)) = copy_for_owner(set, index, signer) else {
            complete = false;
            outcomes.push("unavailable_or_grant_invalid");
            continue;
        };
        if retained.journal.lease.is_none() {
            complete = false;
            outcomes.push("unknown_reservation_use_deposit_retry");
            continue;
        }
        if only_extend && renewal.is_some() {
            set.begin(index)?;
            if transfer::operate_retained(
                socket,
                &grant,
                signer,
                &mut retained,
                StorageOperation::Progress,
            )
            .await
            .is_err()
            {
                complete = false;
                outcomes.push("unconfirmed_retained");
                continue;
            }
            set.confirm(index, &retained.journal)?;
            if set.data.copies[index].charge == Charge::Deleted {
                outcomes.push("explicitly_deleted");
                continue;
            }
        }
        let operation = if let Some(lifetime) = renewal {
            let Ok(expires_at) = transfer::requested_expiry(&grant, lifetime) else {
                complete = false;
                outcomes.push("renewal_outside_original_grant");
                continue;
            };
            if only_extend && expires_at <= retained.journal.last_expiry {
                outcomes.push("existing_retention_sufficient");
                continue;
            }
            StorageOperation::Renew { expires_at }
        } else {
            StorageOperation::Progress
        };
        set.begin(index)?;
        let result = refresh_one(
            socket,
            &grant,
            signer,
            &mut retained,
            operation,
            renewal.is_some(),
        )
        .await;
        if result.is_ok() {
            set.confirm(index, &retained.journal)?;
            outcomes.push("confirmed");
        } else {
            complete = false;
            outcomes.push("unconfirmed_retained");
        }
    }
    finish_report(
        set,
        if renewal.is_some() {
            "renew"
        } else {
            "progress"
        },
        &outcomes,
        complete,
    )
}

async fn refresh_one(
    socket: &Path,
    grant: &VerifiedStorageGrant,
    signer: &SigningKey,
    retained: &mut LockedJournal,
    operation: StorageOperation,
    renewal: bool,
) -> Result<()> {
    transfer::operate_retained(socket, grant, signer, retained, operation).await?;
    if renewal {
        // Renewed reports retention, not whether Finalize ever committed the original payload.
        transfer::operate_retained(socket, grant, signer, retained, StorageOperation::Progress)
            .await?;
    }
    Ok(())
}

pub(super) async fn restore(
    set: &mut LockedSet,
    socket: &Path,
    signer: &SigningKey,
    output: &Path,
) -> Result<serde_json::Value> {
    state::new_output(output)?;
    set.check_owner(signer)?;
    let mut outcomes = Vec::new();
    for index in 0..set.data.copies.len() {
        if set.data.copies[index].charge == Charge::Deleted {
            outcomes.push("explicitly_deleted");
            continue;
        }
        let Ok((mut retained, grant)) = copy_for_owner(set, index, signer) else {
            outcomes.push("unavailable_or_grant_invalid");
            continue;
        };
        if retained.journal.lease.is_none() {
            outcomes.push("unknown_reservation");
            continue;
        }
        set.begin(index)?;
        let result =
            transfer::restore_retained(socket, &grant, signer, &mut retained, output).await;
        if result.is_ok() {
            set.confirm(index, &retained.journal)?;
            outcomes.push("restored_and_retained");
            drop(retained);
            let mut report = finish_report(set, "restore", &outcomes, true)?;
            report["restored"] = true.into();
            report["restored_from_provider_key"] =
                hex::encode(set.data.copies[index].provider_key).into();
            return Ok(report);
        }
        // A successfully published file followed by a local fsync error must never be overwritten.
        ensure!(
            matches!(fs::symlink_metadata(output), Err(error) if error.kind() == std::io::ErrorKind::NotFound),
            "restore output now exists or cannot be inspected; refusing another publication attempt"
        );
        outcomes.push("unavailable_or_restore_unverified");
    }
    let mut report = finish_report(set, "restore", &outcomes, false)?;
    report["restored"] = false.into();
    Ok(report)
}

pub(super) async fn delete(
    set: &mut LockedSet,
    socket: &Path,
    signer: &SigningKey,
    provider: VerifyingKey,
) -> Result<serde_json::Value> {
    set.check_owner(signer)?;
    let index = set
        .data
        .copies
        .iter()
        .position(|copy| copy.provider_key == provider.to_bytes())
        .ok_or_else(|| anyhow::anyhow!("selected provider does not belong to this replica set"))?;
    if set.data.copies[index].charge == Charge::Deleted {
        return finish_report(set, "delete", &["already_confirmed_deleted"], true);
    }
    let (mut retained, grant) = copy_for_owner(set, index, signer)?;
    transfer::known_target(&retained.journal)?;
    set.begin(index)?;
    let complete = transfer::operate_retained(
        socket,
        &grant,
        signer,
        &mut retained,
        StorageOperation::Delete,
    )
    .await
    .is_ok();
    if complete {
        set.confirm(index, &retained.journal)?;
    }
    drop(retained);
    let mut report = finish_report(
        set,
        "delete",
        &[if complete {
            "deleted"
        } else {
            "unconfirmed_retained"
        }],
        complete,
    )?;
    report["deleted_provider_key"] = hex::encode(provider.to_bytes()).into();
    Ok(report)
}
