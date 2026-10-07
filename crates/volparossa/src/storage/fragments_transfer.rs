//! Existing replica transfers composed over an immutable signed fragmentation plan.

use std::{
    fs::{self, File},
    io::{Read as _, Seek as _, SeekFrom, Write as _},
    os::unix::fs::PermissionsExt as _,
    path::Path,
};

use anyhow::{Context as _, Result, ensure};
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use volparossa_content::CHUNK_BYTES;

use super::{
    super::{
        super::{state, transfer},
        operations as replicas,
        retained::Charge,
    },
    retained::LockedFragments,
};

fn finish(
    set: &LockedFragments,
    operation: &str,
    outcomes: Vec<serde_json::Value>,
    complete: bool,
) -> Result<serde_json::Value> {
    let mut report = set.report(operation)?;
    report["operation_complete"] = complete.into();
    report["fragment_outcomes"] = outcomes.into();
    Ok(report)
}

pub(super) async fn deposit(
    set: &LockedFragments,
    socket: &Path,
    signer: &SigningKey,
    input: &mut File,
) -> Result<serde_json::Value> {
    set.check_owner(signer)?;
    let mut complete = true;
    let mut outcomes = Vec::new();
    let mut buffer = vec![0; CHUNK_BYTES];
    for (index, fragment) in set.data.fragments.iter().enumerate() {
        let staging = set.staging()?;
        let mut staged = tempfile::NamedTempFile::new_in(staging.path())?;
        input.seek(SeekFrom::Start(fragment.offset))?;
        let mut remaining = fragment.length;
        let mut digest = Sha256::new();
        while remaining != 0 {
            let amount = usize::try_from(remaining.min(CHUNK_BYTES as u64))?;
            input.read_exact(&mut buffer[..amount])?;
            digest.update(&buffer[..amount]);
            staged.write_all(&buffer[..amount])?;
            remaining -= amount as u64;
        }
        let actual: [u8; 32] = digest.finalize().into();
        ensure!(
            actual == fragment.sha256,
            "input fragment changed from signed original identity"
        );
        let mut copies = set.fragment(index)?;
        let retiring = super::placement::retired(set, index);
        let result = replicas::deposit_selected(
            &mut copies,
            socket,
            signer,
            staged.as_file_mut(),
            &retiring,
        )
        .await?;
        // Existing replica deposit deliberately skips explicitly deleted copies. Fragment
        // deposit may not present reduced redundancy as its original requested completion.
        let committed = copies
            .data
            .copies
            .iter()
            .enumerate()
            .filter(|(index, copy)| !retiring.contains(index) && copy.charge == Charge::Committed)
            .count()
            >= set.data.copies_per_fragment;
        complete &= result["operation_complete"] == true && committed;
        outcomes.push(serde_json::json!({"index": index, "operation_complete": result["operation_complete"] == true && committed,
            "copy_outcomes": result["copy_outcomes"]}));
    }
    finish(set, "deposit", outcomes, complete)
}

pub(super) async fn refresh(
    set: &LockedFragments,
    socket: &Path,
    signer: &SigningKey,
    renewal: Option<u64>,
) -> Result<serde_json::Value> {
    set.check_owner(signer)?;
    let mut complete = true;
    let mut outcomes = Vec::new();
    for index in 0..set.data.fragments.len() {
        let result = refresh_fragment(set, index, socket, signer, renewal, false).await?;
        complete &= result["operation_complete"] == true;
        outcomes.push(
            serde_json::json!({"index": index, "operation_complete": result["operation_complete"],
            "copy_outcomes": result["copy_outcomes"]}),
        );
    }
    finish(
        set,
        if renewal.is_some() {
            "renew"
        } else {
            "progress"
        },
        outcomes,
        complete,
    )
}

/// One bounded maintenance unit using exactly the same signed renewal/reconciliation engine.
pub(super) async fn refresh_fragment(
    set: &LockedFragments,
    index: usize,
    socket: &Path,
    signer: &SigningKey,
    renewal: Option<u64>,
    maintenance: bool,
) -> Result<serde_json::Value> {
    set.check_owner(signer)?;
    let mut copies = set.fragment(index)?;
    let mut retiring = super::placement::retired(set, index);
    if let Some(intent) = &copies.data.handoff {
        if intent.phase == super::super::retained::HandoffPhase::Copying {
            retiring.remove(&intent.from);
        }
    }
    if maintenance {
        replicas::refresh_maintenance(&mut copies, socket, signer, renewal, &retiring).await
    } else {
        replicas::refresh_selected(&mut copies, socket, signer, renewal, &retiring).await
    }
}

pub(super) async fn restore(
    set: &LockedFragments,
    socket: &Path,
    signer: &SigningKey,
    output: &Path,
) -> Result<serde_json::Value> {
    state::new_output(output)?;
    set.check_owner(signer)?;
    let parent = output
        .parent()
        .context("missing reconstructed output parent")?;
    let mut restored = tempfile::NamedTempFile::new_in(parent)?;
    restored
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    let mut whole = Sha256::new();
    let mut written = 0_u64;
    let mut buffer = vec![0; CHUNK_BYTES];
    let mut outcomes = Vec::new();
    for (index, fragment) in set.data.fragments.iter().enumerate() {
        let staging = set.staging()?;
        let path = staging.path().join("restored-fragment");
        let mut copies = set.fragment(index)?;
        let result = replicas::restore(&mut copies, socket, signer, &path).await?;
        drop(copies);
        outcomes.push(serde_json::json!({"index": index, "restored": result["restored"],
            "provider_key": result["restored_from_provider_key"], "copy_outcomes": result["copy_outcomes"]}));
        if result["operation_complete"] != true {
            let mut report = finish(set, "restore", outcomes, false)?;
            report["restored"] = false.into();
            report["unavailable_fragment"] = index.into();
            return Ok(report);
        }
        let (mut source, length) = transfer::checked_input(&path, fragment.sha256)?;
        ensure!(
            length == fragment.length && written == fragment.offset,
            "restored fragment range differs from signed plan"
        );
        let mut remaining = length;
        while remaining != 0 {
            let amount = usize::try_from(remaining.min(CHUNK_BYTES as u64))?;
            source.read_exact(&mut buffer[..amount])?;
            restored.write_all(&buffer[..amount])?;
            whole.update(&buffer[..amount]);
            written += amount as u64;
            remaining -= amount as u64;
        }
    }
    let actual: [u8; 32] = whole.finalize().into();
    ensure!(
        written == set.data.ciphertext_bytes && actual == set.data.sha256,
        "reconstructed archive differs from signed original hash and length"
    );
    restored.as_file().sync_all()?;
    restored
        .persist_noclobber(output)
        .map_err(|error| error.error)?;
    File::open(parent)?.sync_all()?;
    let mut report = finish(set, "restore", outcomes, true)?;
    report["restored"] = true.into();
    report["whole_archive_sha256_verified"] = true.into();
    Ok(report)
}

pub(super) async fn delete(
    set: &LockedFragments,
    socket: &Path,
    signer: &SigningKey,
) -> Result<serde_json::Value> {
    set.check_owner(signer)?;
    let mut complete = true;
    let mut outcomes = Vec::new();
    for index in 0..set.data.fragments.len() {
        let mut copies = set.fragment(index)?;
        let mut results = Vec::new();
        for copy in 0..copies.data.copies.len() {
            let record = &copies.data.copies[copy];
            if record.charge == Charge::Unattempted {
                // There can be no remote reservation: begin() is durable before any send.
                // Do not mark this absent copy deleted or allocate a lease to delete it.
                results.push("never_reserved");
                continue;
            }
            let provider = VerifyingKey::from_bytes(&record.provider_key)?;
            match replicas::delete(&mut copies, socket, signer, provider).await {
                Ok(result) if result["operation_complete"] == true => results.push("deleted"),
                _ => {
                    complete = false;
                    results.push("unconfirmed_retained");
                }
            }
        }
        outcomes.push(serde_json::json!({"index": index, "copy_outcomes": results}));
    }
    finish(set, "delete", outcomes, complete)
}
