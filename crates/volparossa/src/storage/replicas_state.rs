//! Bounded owner-local replica intent journal, separate from immutable per-provider identities.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::Write as _,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use volparossa_content::private_storage::{
    ARCHIVE_COPY_TARGET, MAX_ARCHIVE_BYTES,
    protocol::{MAX_GRANT_BYTES, ReceiptState, VerifiedStorageGrant},
};

use super::super::{
    state::{self, Journal, LockedJournal},
    transfer,
};

pub(super) const MAX_COPIES: usize = 8;
const MANIFEST: &str = "replicas.json";
const MAX_MANIFEST_BYTES: u64 = 32 * 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Charge {
    Unattempted,
    Reserved,
    Committed,
    Uncertain,
    Deleted,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CopyRecord {
    pub(super) provider_key: [u8; 32],
    archive_id: [u8; 32],
    grant_sha256: [u8; 32],
    pub(super) charge: Charge,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    version: u32,
    owner_key: [u8; 32],
    pub(super) ciphertext_bytes: u64,
    pub(super) sha256: [u8; 32],
    pub(super) copies: Vec<CopyRecord>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) handoff: Option<Handoff>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum HandoffPhase {
    Copying,
    DeletePending,
    Complete,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Handoff {
    pub(super) from: usize,
    pub(super) to: usize,
    pub(super) phase: HandoffPhase,
    /// Durable intent precedes creation of the per-copy journal and all remote operations.
    initial_journal: Journal,
}

pub(super) struct LockedSet {
    directory: File,
    pub(super) data: Manifest,
}

impl LockedSet {
    pub(super) fn create(
        path: &Path,
        owner: &VerifyingKey,
        length: u64,
        sha256: [u8; 32],
        grants: &[VerifiedStorageGrant],
        lifetime: u64,
    ) -> Result<Self> {
        ensure!(
            grants.len() == ARCHIVE_COPY_TARGET,
            "new storage archives require the core-owned {ARCHIVE_COPY_TARGET}-copy target"
        );
        state::new_output(path)?;
        ensure!(
            (1..=MAX_ARCHIVE_BYTES).contains(&length),
            "invalid replica ciphertext length"
        );
        let mut seen = BTreeSet::new();
        let mut journals = Vec::with_capacity(grants.len());
        for grant in grants {
            grant.current(crate::storage::now()?)?;
            ensure!(
                grant.owner_key() == owner,
                "replica grant has a different owner"
            );
            ensure!(
                grant.provider_key() != owner && seen.insert(grant.provider_key().to_bytes()),
                "replica providers must be distinct independently pinned identities, not the owner"
            );
            ensure!(
                grant.limits().max_payload_bytes >= length,
                "replica exceeds provider grant quota"
            );
            let expires = transfer::requested_expiry(grant, lifetime)?;
            journals.push(Journal::new(grant, length, sha256, expires)?);
        }
        let parent = path.parent().context("missing replica state parent")?;
        let staging = tempfile::Builder::new()
            .prefix(".replicas-")
            .tempdir_in(parent)?;
        fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))?;
        let mut retained = Self {
            directory: state::directory(staging.path())?,
            data: Manifest {
                version: 1,
                owner_key: owner.to_bytes(),
                ciphertext_bytes: length,
                sha256,
                copies: Vec::new(),
                handoff: None,
            },
        };
        for (index, journal) in journals.into_iter().enumerate() {
            let record = CopyRecord {
                provider_key: journal.provider_key,
                archive_id: journal.archive_id,
                grant_sha256: Sha256::digest(hex::decode(&journal.grant_hex)?).into(),
                charge: Charge::Unattempted,
            };
            LockedJournal::create(&retained.copy_path(index), journal)?;
            retained.data.copies.push(record);
        }
        retained.save()?;
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            staging.path(),
            rustix::fs::CWD,
            path,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        // The temporary-path guard no longer owns the published directory.
        drop(staging);
        File::open(parent)?.sync_all()?;
        Ok(retained)
    }

    pub(super) fn open(path: &Path) -> Result<Self> {
        crate::storage::require_absolute(path)?;
        let directory = state::directory(path)?;
        let bytes = state::read_private(
            &state::anchored(&directory).join(MANIFEST),
            MAX_MANIFEST_BYTES,
        )?;
        let data: Manifest = serde_json::from_slice(&bytes).context("invalid replica manifest")?;
        ensure!(
            matches!(data.version, 1 | 2)
                && (2..=MAX_COPIES).contains(&data.copies.len())
                && (1..=MAX_ARCHIVE_BYTES).contains(&data.ciphertext_bytes),
            "invalid replica manifest scope"
        );
        VerifyingKey::from_bytes(&data.owner_key)?;
        let mut seen = BTreeSet::new();
        for copy in &data.copies {
            VerifyingKey::from_bytes(&copy.provider_key)?;
            ensure!(
                copy.provider_key != data.owner_key && seen.insert(copy.provider_key),
                "duplicate replica provider"
            );
        }
        let retained = Self { directory, data };
        retained.recover_handoff_copy()?;
        for index in 0..retained.data.copies.len() {
            retained.copy(index)?;
        }
        Ok(retained)
    }

    pub(super) fn save(&self) -> Result<()> {
        let bytes = serde_json::to_vec(&self.data)?;
        ensure!(
            bytes.len() as u64 <= MAX_MANIFEST_BYTES,
            "replica manifest too large"
        );
        let mut file = tempfile::NamedTempFile::new_in(state::anchored(&self.directory))?;
        file.as_file()
            .set_permissions(fs::Permissions::from_mode(0o600))?;
        file.write_all(&bytes)?;
        file.as_file().sync_all()?;
        file.persist(state::anchored(&self.directory).join(MANIFEST))
            .map_err(|error| error.error)?;
        self.directory.sync_all()?;
        Ok(())
    }

    pub(super) fn check_owner(&self, signer: &SigningKey) -> Result<()> {
        ensure!(
            self.data.owner_key == signer.verifying_key().to_bytes(),
            "replica set belongs to a different owner"
        );
        Ok(())
    }

    /// Publish the replacement identity before its first possible remote reservation.
    pub(super) fn prepare_handoff(
        &mut self,
        from: &VerifyingKey,
        grant: &VerifiedStorageGrant,
        lifetime: u64,
    ) -> Result<(usize, usize)> {
        grant.current(crate::storage::now()?)?;
        ensure!(
            grant.owner_key().as_bytes() == &self.data.owner_key,
            "replacement has a different owner"
        );
        if let Some(pending) = &self.data.handoff {
            let matches = self.data.copies[pending.from].provider_key == from.to_bytes()
                && self.data.copies[pending.to].provider_key == grant.provider_key().to_bytes()
                && pending.initial_journal.grant_hex == hex::encode(grant.signed().encode());
            if matches {
                self.recover_handoff_copy()?;
                return Ok((pending.from, pending.to));
            }
            ensure!(
                pending.phase == HandoffPhase::Complete,
                "another handoff is still pending"
            );
        }
        ensure!(
            self.data.copies.len() < MAX_COPIES,
            "retained replica history has no replacement slot"
        );
        let from_index = self
            .data
            .copies
            .iter()
            .position(|copy| copy.provider_key == from.to_bytes())
            .context("source provider is not in this replica set")?;
        ensure!(
            self.data.copies[from_index].charge != Charge::Deleted,
            "source copy was explicitly deleted"
        );
        ensure!(
            grant.provider_key().as_bytes() != &self.data.owner_key
                && !self
                    .data
                    .copies
                    .iter()
                    .any(|copy| copy.provider_key == grant.provider_key().to_bytes()),
            "replacement must be a new independently pinned provider"
        );
        ensure!(
            grant.limits().max_payload_bytes >= self.data.ciphertext_bytes,
            "replacement grant cannot hold the complete archive"
        );
        let original = self.copy(from_index)?;
        transfer::known_target(&original.journal)?;
        let expires = transfer::requested_expiry(grant, lifetime)?;
        ensure!(
            expires
                >= original
                    .journal
                    .last_expiry
                    .max(original.journal.requested_expiry),
            "replacement retention would shorten the source lease"
        );
        let journal = Journal::new(grant, self.data.ciphertext_bytes, self.data.sha256, expires)?;
        let to_index = self.data.copies.len();
        self.data.copies.push(CopyRecord {
            provider_key: journal.provider_key,
            archive_id: journal.archive_id,
            grant_sha256: Sha256::digest(hex::decode(&journal.grant_hex)?).into(),
            charge: Charge::Unattempted,
        });
        self.data.handoff = Some(Handoff {
            from: from_index,
            to: to_index,
            phase: HandoffPhase::Copying,
            initial_journal: journal,
        });
        self.data.version = 2;
        self.save()?;
        self.recover_handoff_copy()?;
        Ok((from_index, to_index))
    }

    fn recover_handoff_copy(&self) -> Result<()> {
        let Some(handoff) = &self.data.handoff else {
            return Ok(());
        };
        ensure!(
            self.data.version == 2
                && handoff.from < handoff.to
                && handoff.to < self.data.copies.len(),
            "invalid handoff identity"
        );
        let record = &self.data.copies[handoff.to];
        let initial = &handoff.initial_journal;
        let grant_sha256: [u8; 32] = Sha256::digest(hex::decode(&initial.grant_hex)?).into();
        ensure!(
            initial.owner_key == self.data.owner_key
                && initial.provider_key == record.provider_key
                && initial.archive_id == record.archive_id
                && grant_sha256 == record.grant_sha256
                && initial.ciphertext_bytes == self.data.ciphertext_bytes
                && initial.sha256 == self.data.sha256
                && initial.lease.is_none()
                && initial.last_state.is_none()
                && initial.last_stored_bytes == 0
                && initial.last_expiry == 0,
            "handoff creation intent differs from replacement identity"
        );
        let path = self.copy_path(handoff.to);
        match fs::symlink_metadata(&path) {
            Ok(_) => return Ok(()), // copy() checks the exact private journal below.
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
            Err(error) => return Err(error.into()),
        }
        ensure!(
            record.charge == Charge::Unattempted && handoff.phase == HandoffPhase::Copying,
            "attempted handoff lost its replacement journal"
        );
        let staging = tempfile::Builder::new()
            .prefix(".handoff-journal-")
            .tempdir_in(state::anchored(&self.directory))?;
        let staged = staging.path().join("copy");
        let retained = LockedJournal::create(&staged, initial.clone())?;
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            &staged,
            rustix::fs::CWD,
            &path,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        self.directory.sync_all()?;
        drop(retained);
        Ok(())
    }

    pub(super) fn handoff_phase(&mut self, phase: HandoffPhase) -> Result<()> {
        self.data
            .handoff
            .as_mut()
            .context("missing handoff intent")?
            .phase = phase;
        self.save()
    }

    /// One owner-private ciphertext staging copy; no plaintext or original pathname is retained.
    pub(super) fn handoff_staging(&self) -> Result<tempfile::TempDir> {
        Ok(tempfile::Builder::new()
            .prefix(".handoff-transfer-")
            .tempdir_in(state::anchored(&self.directory))?)
    }

    fn copy_path(&self, index: usize) -> PathBuf {
        state::anchored(&self.directory).join(format!("copy-{index}"))
    }

    pub(super) fn copy(&self, index: usize) -> Result<LockedJournal> {
        let record = self
            .data
            .copies
            .get(index)
            .context("unknown replica copy")?;
        let retained = LockedJournal::open(&self.copy_path(index))?;
        let journal = &retained.journal;
        ensure!(
            journal.grant_hex.len() <= 2 * MAX_GRANT_BYTES,
            "oversized retained replica grant"
        );
        let grant_sha256: [u8; 32] = Sha256::digest(hex::decode(&journal.grant_hex)?).into();
        ensure!(
            journal.provider_key == record.provider_key
                && journal.owner_key == self.data.owner_key
                && journal.archive_id == record.archive_id
                && journal.archive_id != [0; 32]
                && grant_sha256 == record.grant_sha256
                && journal.ciphertext_bytes == self.data.ciphertext_bytes
                && journal.sha256 == self.data.sha256
                && journal.last_stored_bytes <= self.data.ciphertext_bytes,
            "replica journal differs from its original owner/provider/archive binding"
        );
        journal.target()?;
        let valid_charge = match record.charge {
            Charge::Unattempted => journal.lease.is_none() && journal.last_state.is_none(),
            Charge::Reserved => {
                matches!(journal.last_state, Some(value) if value == ReceiptState::Reserved as i32 || value == ReceiptState::Partial as i32)
            }
            Charge::Committed => journal.last_state == Some(ReceiptState::Committed as i32),
            Charge::Deleted => journal.last_state == Some(ReceiptState::Deleted as i32),
            Charge::Uncertain => true,
        };
        ensure!(
            valid_charge,
            "replica accounting conflicts with its retained receipt"
        );
        Ok(retained)
    }

    /// Persist uncertainty BEFORE any operation; a lost reply or process crash cannot erase charge.
    pub(super) fn begin(&mut self, index: usize) -> Result<()> {
        self.data.copies[index].charge = Charge::Uncertain;
        self.save()
    }

    pub(super) fn confirm(&mut self, index: usize, journal: &Journal) -> Result<()> {
        self.data.copies[index].charge = match journal.last_state {
            Some(value) if value == ReceiptState::Committed as i32 => Charge::Committed,
            Some(value) if value == ReceiptState::Deleted as i32 => Charge::Deleted,
            Some(value)
                if value == ReceiptState::Reserved as i32
                    || value == ReceiptState::Partial as i32 =>
            {
                Charge::Reserved
            }
            _ => Charge::Uncertain,
        };
        self.save()
    }

    pub(super) fn report(&self, operation: &str) -> Result<serde_json::Value> {
        let mut reserved = 0_u64;
        let mut committed = 0_u64;
        let mut uncertain = 0_u64;
        let mut copies = Vec::with_capacity(self.data.copies.len());
        for (index, record) in self.data.copies.iter().enumerate() {
            let retained = self.copy(index)?;
            match record.charge {
                Charge::Reserved => reserved += self.data.ciphertext_bytes,
                Charge::Committed => committed += self.data.ciphertext_bytes,
                Charge::Uncertain => uncertain += self.data.ciphertext_bytes,
                Charge::Unattempted | Charge::Deleted => {}
            }
            copies.push(serde_json::json!({
                "provider_key": hex::encode(record.provider_key), "charge": record.charge,
                "last_confirmed_stored_bytes": retained.journal.last_stored_bytes,
                "last_confirmed_expiry": retained.journal.last_expiry,
                "last_confirmed_state": retained.journal.last_state.and_then(|state| ReceiptState::try_from(state).ok()).map(|state| format!("{state:?}")),
            }));
        }
        Ok(serde_json::json!({
            "operation": format!("private_storage_replicas_{operation}"),
            "logical_ciphertext_bytes": self.data.ciphertext_bytes,
            "reserved_payload_bytes": reserved, "committed_payload_bytes": committed,
            "uncertain_payload_bytes": uncertain,
            "physical_payload_charge_upper_bound": reserved + committed + uncertain,
            "metadata_overhead_measured": false, "expired_copies_remain_charged": true,
            "distinct_provider_identities": copies.len(), "copies": copies,
            "read_consumes_archive": false, "independent_failure_domains_proven": false,
            "network_contribution_credit": false, "automatic_repair": false,
            "handoff": self.data.handoff.as_ref().map(|handoff| serde_json::json!({
                "from_provider_key": hex::encode(self.data.copies[handoff.from].provider_key),
                "replacement_provider_key": hex::encode(self.data.copies[handoff.to].provider_key),
                "phase": handoff.phase,
                "replacement_readback_required_before_source_delete": true,
                "automatic_contribution_resize": false,
            })),
        }))
    }
}
