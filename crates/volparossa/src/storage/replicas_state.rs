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
    MAX_ARCHIVE_BYTES,
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
        state::new_output(path)?;
        ensure!(
            (2..=MAX_COPIES).contains(&grants.len()),
            "replica set requires 2..8 providers"
        );
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
            data.version == 1
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
        }))
    }
}
