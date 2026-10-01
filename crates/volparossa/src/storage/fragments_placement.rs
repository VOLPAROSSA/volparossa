//! Owner-signed placement extensions; the original reconstruction root never changes.
//! This is authorization, not another accounting ledger. Existing replica journals retain
//! every reservation/lease and conservative charge, including pending source retirement.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::Path,
};

use anyhow::{Context as _, Result, ensure};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use volparossa_content::private_storage::protocol::{
    MAX_GRANT_BYTES, StorageRights, VerifiedStorageGrant,
};

use super::{
    super::{
        super::state,
        handoff,
        retained::{Handoff, HandoffPhase, LockedSet, MAX_COPIES},
    },
    retained::LockedFragments,
};

const FILE: &str = "placement-authorizations.json";
const DOMAIN: &[u8] = b"VOLPAROSSA/private-storage-fragment-placement/v1\0";
const MAX_BYTES: u64 = 8 * 1024 * 1024;
const MAX_PLACEMENTS: usize = 256 * (MAX_COPIES - 2);

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Placement {
    fragment: usize,
    handoff: Handoff,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Authority {
    version: u32,
    root_sha256: [u8; 32],
    placements: Vec<Placement>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedAuthority {
    authority: Authority,
    signature: String,
}

fn signing_bytes(authority: &Authority) -> Result<Vec<u8>> {
    let mut result = DOMAIN.to_vec();
    result.extend(serde_json::to_vec(authority)?);
    ensure!(
        result.len() as u64 <= MAX_BYTES,
        "placement authority too large"
    );
    Ok(result)
}

pub(super) fn load(
    directory: &File,
    root_sha256: [u8; 32],
    owner: &VerifyingKey,
) -> Result<Vec<Placement>> {
    let path = state::anchored(directory).join(FILE);
    match fs::symlink_metadata(&path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(error) => return Err(error.into()),
        Ok(_) => {}
    }
    let encoded = state::read_private(&path, MAX_BYTES)?;
    let signed: SignedAuthority = serde_json::from_slice(&encoded)?;
    ensure!(
        signed.authority.version == 1
            && signed.authority.root_sha256 == root_sha256
            && !signed.authority.placements.is_empty()
            && signed.authority.placements.len() <= MAX_PLACEMENTS
            && signed.signature.len() == 128,
        "invalid fragment placement authority"
    );
    let signature = Signature::from_slice(&hex::decode(&signed.signature)?)?;
    owner
        .verify_strict(&signing_bytes(&signed.authority)?, &signature)
        .context("fragment placement owner signature does not verify")?;
    Ok(signed.authority.placements)
}

fn save(set: &LockedFragments, signer: &SigningKey) -> Result<()> {
    set.check_owner(signer)?;
    validate(set)?;
    let authority = Authority {
        version: 1,
        root_sha256: set.root_sha256,
        placements: set.placements.clone(),
    };
    let signature = hex::encode(signer.sign(&signing_bytes(&authority)?).to_bytes());
    let encoded = serde_json::to_vec(&SignedAuthority {
        authority,
        signature,
    })?;
    ensure!(
        encoded.len() as u64 <= MAX_BYTES,
        "signed placement authority too large"
    );
    let mut staged = tempfile::NamedTempFile::new_in(state::anchored(&set.directory))?;
    staged
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    staged.write_all(&encoded)?;
    staged.as_file().sync_all()?;
    staged
        .persist(state::anchored(&set.directory).join(FILE))
        .map_err(|error| error.error)?;
    set.directory.sync_all()?;
    Ok(())
}

pub(super) fn validate(set: &LockedFragments) -> Result<()> {
    ensure!(
        set.placements.len() <= MAX_PLACEMENTS,
        "too many retained placement authorizations"
    );
    let mut providers: Vec<BTreeSet<_>> = Vec::new();
    for fragment in &set.data.fragments {
        let mut keys = BTreeSet::new();
        for copy in &fragment.copies {
            keys.insert(
                set.data
                    .providers
                    .get(copy.provider)
                    .context("unknown initial provider")?
                    .key,
            );
        }
        providers.push(keys);
    }
    let mut counts: Vec<_> = set
        .data
        .fragments
        .iter()
        .map(|fragment| fragment.copies.len())
        .collect();
    let mut archives: BTreeSet<_> = set
        .data
        .fragments
        .iter()
        .flat_map(|fragment| fragment.copies.iter().map(|copy| copy.archive_id))
        .collect();
    for placement in &set.placements {
        let fragment = set
            .data
            .fragments
            .get(placement.fragment)
            .context("unknown authorized fragment")?;
        let intent = &placement.handoff;
        let journal = &intent.initial_journal;
        VerifyingKey::from_bytes(&journal.provider_key)?;
        ensure!(
            intent.phase == HandoffPhase::Copying
                && intent.from < intent.to
                && intent.to == counts[placement.fragment]
                && intent.to < MAX_COPIES
                && journal.owner_key == set.data.owner_key
                && journal.provider_key != journal.owner_key
                && providers[placement.fragment].insert(journal.provider_key)
                && journal.archive_id != [0; 32]
                && archives.insert(journal.archive_id)
                && journal.ciphertext_bytes == fragment.length
                && journal.sha256 == fragment.sha256
                && journal.grant_hex.len() <= 2 * MAX_GRANT_BYTES
                && journal.requested_expiry > 0
                && journal.lease.is_none()
                && journal.last_state.is_none()
                && journal.last_expiry == 0
                && journal.last_stored_bytes == 0,
            "invalid signed fragment replacement binding"
        );
        counts[placement.fragment] += 1;
    }
    Ok(())
}

pub(super) fn providers(set: &LockedFragments) -> Vec<[u8; 32]> {
    let mut keys: Vec<_> = set
        .data
        .providers
        .iter()
        .map(|provider| provider.key)
        .collect();
    for placement in &set.placements {
        let key = placement.handoff.initial_journal.provider_key;
        if !keys.contains(&key) {
            keys.push(key);
        }
    }
    keys
}

pub(super) fn retired(set: &LockedFragments, fragment: usize) -> BTreeSet<usize> {
    set.placements
        .iter()
        .filter(|p| p.fragment == fragment)
        .map(|p| p.handoff.from)
        .collect()
}

/// Validate every unsigned child record BEFORE recovering any missing journal.
pub(super) fn authorize_child(
    set: &LockedFragments,
    index: usize,
    copies: &mut LockedSet,
) -> Result<()> {
    let fragment = &set.data.fragments[index];
    let intents: Vec<_> = set
        .placements
        .iter()
        .filter(|p| p.fragment == index)
        .map(|p| &p.handoff)
        .collect();
    let original_count = fragment.copies.len();
    let expected_count = original_count + intents.len();
    ensure!(
        copies.data.copies.len() >= original_count
            && copies.data.copies.len() <= expected_count
            && expected_count - copies.data.copies.len() <= 1,
        "unauthorized or missing child copy history"
    );
    for (copy, record) in copies.data.copies.iter().enumerate() {
        let (provider, archive, grant_hash) = if copy < original_count {
            let binding = &fragment.copies[copy];
            let provider = &set.data.providers[binding.provider];
            (provider.key, binding.archive_id, provider.grant_sha256)
        } else {
            let journal = &intents[copy - original_count].initial_journal;
            (
                journal.provider_key,
                journal.archive_id,
                Sha256::digest(hex::decode(&journal.grant_hex)?).into(),
            )
        };
        ensure!(
            record.provider_key == provider
                && record.archive_id == archive
                && record.grant_sha256 == grant_hash,
            "child copy lacks exact signed placement authority"
        );
        if copies.copy_present(copy)? {
            let retained = copies.copy(copy)?;
            ensure!(
                retained.journal.owner_key == set.data.owner_key,
                "child journal has another owner"
            );
            if copy >= original_count {
                ensure!(
                    retained.journal.requested_expiry
                        == intents[copy - original_count]
                            .initial_journal
                            .requested_expiry,
                    "replacement initial expiry differs from signed authority"
                );
            }
        } else {
            ensure!(
                copy >= original_count && copy + 1 == copies.data.copies.len(),
                "missing original or historical copy journal"
            );
        }
    }
    let installed = copies.data.copies.len() - original_count;
    if installed == 0 {
        ensure!(
            copies.data.handoff.is_none(),
            "unsigned initial child handoff"
        );
    } else {
        let current = copies
            .data
            .handoff
            .as_ref()
            .context("authorized child handoff missing")?;
        ensure!(
            current.same_identity(intents[installed - 1]),
            "child handoff differs from signed intent"
        );
        ensure!(
            current.phase != HandoffPhase::Complete
                || copies.data.copies[current.from].charge
                    == super::super::retained::Charge::Deleted,
            "completed retirement lacks retained deletion confirmation"
        );
        copies.recover_handoff_copy()?;
    }
    if installed < intents.len() {
        copies.apply_handoff(intents[installed])?;
    }
    for copy in 0..copies.data.copies.len() {
        let retained = copies.copy(copy)?;
        if copy >= original_count {
            let expected = &intents[copy - original_count].initial_journal;
            ensure!(
                retained.journal.requested_expiry == expected.requested_expiry,
                "replacement initial expiry differs from signed authority"
            );
        }
    }
    Ok(())
}

pub(super) fn authorize(
    set: &mut LockedFragments,
    signer: &SigningKey,
    index: usize,
    from: &VerifyingKey,
    grant: &VerifiedStorageGrant,
    lifetime: u64,
) -> Result<()> {
    set.check_owner(signer)?;
    let required = StorageRights::RESERVE
        .union(StorageRights::APPEND)
        .union(StorageRights::PROGRESS)
        .union(StorageRights::FINALIZE)
        .union(StorageRights::READ_RANGE);
    ensure!(
        grant.limits().rights.bits() & required.bits() == required.bits(),
        "fragment replacement requires resumable upload and full readback rights"
    );
    let copies = set.fragment(index)?;
    let planned = copies.plan_handoff(from, grant, lifetime)?;
    if set
        .placements
        .iter()
        .any(|placement| placement.fragment == index && placement.handoff.same_identity(&planned))
    {
        return Ok(());
    }
    ensure!(
        planned.phase == HandoffPhase::Copying,
        "replacement is not a new exact intent"
    );
    set.placements.push(Placement {
        fragment: index,
        handoff: planned,
    });
    // Persist parent authority before touching the child. A crash at either boundary
    // reopens the same archive/grant/expiry; no remote operation has occurred here.
    save(set, signer)?;
    drop(copies);
    set.fragment(index)?;
    Ok(())
}

pub(super) async fn replace(
    set: &mut LockedFragments,
    socket: &Path,
    signer: &SigningKey,
    index: usize,
    from: VerifyingKey,
    grant: &VerifiedStorageGrant,
    lifetime: u64,
) -> Result<serde_json::Value> {
    authorize(set, signer, index, &from, grant, lifetime)?;
    let mut copies = set.fragment(index)?;
    let result = handoff::replace(&mut copies, socket, signer, from, grant, lifetime).await?;
    drop(copies);
    let mut report = set.report("replace")?;
    report["operation_complete"] = result["operation_complete"].clone();
    report["fragment_index"] = index.into();
    report["handoff_stage"] = result["handoff_stage"].clone();
    report["pending_handoff"] = result["pending_handoff"].clone();
    report["replacement_readback_required_before_source_delete"] = true.into();
    Ok(report)
}

#[cfg(test)]
#[path = "fragments_placement_tests.rs"]
mod tests;
