//! Immutable owner-signed reconstruction root over existing mutable per-copy journals.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{Read as _, Seek as _},
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use ed25519_dalek::{Signature, Signer as _, SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest as _, Sha256};
use volparossa_content::{
    CHUNK_BYTES,
    private_storage::{
        ARCHIVE_COPY_TARGET, MAX_ARCHIVE_BYTES,
        protocol::{ReceiptState, VerifiedStorageGrant},
    },
};

use super::super::{
    super::{state, transfer},
    retained::{Charge, LockedSet},
};
use super::placement::{self, Placement};

pub(super) const MAX_FRAGMENT_BYTES: u64 = 1024 * 1024 * 1024;
const MAX_FRAGMENTS: usize = 256;
const MAX_MANIFEST_BYTES: u64 = 1024 * 1024;
const MANIFEST: &str = "fragments.json";
const DOMAIN: &[u8] = b"VOLPAROSSA/private-storage-fragments/v1\0";

#[cfg(test)]
#[path = "storage_uniform_policy_tests.rs"]
mod uniform_tests;

#[derive(Clone, Copy)]
pub(super) struct Plan {
    pub(super) ciphertext_bytes: u64,
    pub(super) sha256: [u8; 32],
    pub(super) fragment_bytes: u64,
    pub(super) copies: usize,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Provider {
    pub(super) key: [u8; 32],
    pub(super) grant_sha256: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct CopyBinding {
    pub(super) provider: usize,
    pub(super) archive_id: [u8; 32],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Fragment {
    pub(super) offset: u64,
    pub(super) length: u64,
    pub(super) sha256: [u8; 32],
    pub(super) copies: Vec<CopyBinding>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Manifest {
    version: u32,
    pub(super) owner_key: [u8; 32],
    pub(super) ciphertext_bytes: u64,
    pub(super) sha256: [u8; 32],
    fragment_bytes: u64,
    pub(super) copies_per_fragment: usize,
    pub(super) providers: Vec<Provider>,
    pub(super) fragments: Vec<Fragment>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct SignedManifest {
    manifest: Manifest,
    signature: String,
}

pub(super) struct LockedFragments {
    pub(super) directory: File,
    pub(super) data: Manifest,
    pub(super) root_sha256: [u8; 32],
    pub(super) placements: Vec<Placement>,
}

fn signing_bytes(data: &Manifest) -> Result<Vec<u8>> {
    let encoded = serde_json::to_vec(data)?;
    ensure!(
        encoded.len() as u64 <= MAX_MANIFEST_BYTES,
        "fragment manifest too large"
    );
    let mut bytes = DOMAIN.to_vec();
    bytes.extend_from_slice(&encoded);
    Ok(bytes)
}

fn plan_fragments(
    input: &mut File,
    plan: Plan,
    grants: &[VerifiedStorageGrant],
    fragment_bytes: u64,
) -> Result<Vec<Fragment>> {
    let mut planned_bytes = vec![0_u64; grants.len()];
    let mut planned_leases = vec![0_u32; grants.len()];
    input.rewind()?;
    let mut whole = Sha256::new();
    let mut buffer = vec![0; CHUNK_BYTES];
    let mut fragments = Vec::new();
    let mut offset = 0;
    while offset < plan.ciphertext_bytes {
        let length = fragment_bytes.min(plan.ciphertext_bytes - offset);
        let mut remaining = length;
        let mut hash = Sha256::new();
        while remaining != 0 {
            let amount = usize::try_from(remaining.min(CHUNK_BYTES as u64))?;
            input.read_exact(&mut buffer[..amount])?;
            hash.update(&buffer[..amount]);
            whole.update(&buffer[..amount]);
            remaining -= amount as u64;
        }
        let index = fragments.len();
        for copy in 0..plan.copies {
            let provider = (index + copy) % grants.len();
            planned_bytes[provider] += length;
            planned_leases[provider] += 1;
        }
        fragments.push(Fragment {
            offset,
            length,
            sha256: hash.finalize().into(),
            copies: Vec::new(),
        });
        offset += length;
    }
    let actual: [u8; 32] = whole.finalize().into();
    ensure!(
        actual == plan.sha256 && input.read(&mut buffer[..1])? == 0,
        "ciphertext changed while preparing fragment identities"
    );
    for (index, grant) in grants.iter().enumerate() {
        ensure!(
            planned_bytes[index] <= grant.limits().max_payload_bytes
                && planned_leases[index] <= grant.limits().max_leases,
            "aggregate fragment copies exceed a provider's original bytes or leases grant"
        );
    }
    Ok(fragments)
}

impl LockedFragments {
    pub(super) fn create(
        path: &Path,
        signer: &SigningKey,
        input: &mut File,
        plan: Plan,
        grants: &[VerifiedStorageGrant],
        lifetime: u64,
    ) -> Result<Self> {
        ensure!(
            plan.copies == ARCHIVE_COPY_TARGET && (3..=8).contains(&grants.len()),
            "new fragment archives require 3..8 providers and the core-owned {ARCHIVE_COPY_TARGET}-copy target"
        );
        state::new_output(path)?;
        ensure!(
            (grants.len() as u64..=MAX_ARCHIVE_BYTES).contains(&plan.ciphertext_bytes)
                && (1..=MAX_FRAGMENT_BYTES).contains(&plan.fragment_bytes),
            "invalid fragment plan size"
        );
        let fragment_bytes = plan
            .fragment_bytes
            .min(plan.ciphertext_bytes / grants.len() as u64);
        let count = usize::try_from(plan.ciphertext_bytes.div_ceil(fragment_bytes))?;
        ensure!(
            (grants.len()..=MAX_FRAGMENTS).contains(&count),
            "fragment plan exceeds 256 fragments; select a larger --fragment-bytes bound"
        );
        let owner = signer.verifying_key();
        let mut keys = BTreeSet::new();
        for grant in grants {
            grant.current(crate::storage::now()?)?;
            ensure!(
                grant.owner_key() == &owner
                    && grant.provider_key() != &owner
                    && keys.insert(grant.provider_key().to_bytes()),
                "providers must be distinct and bound to this owner"
            );
            transfer::requested_expiry(grant, lifetime)?;
        }
        let fragments = plan_fragments(input, plan, grants, fragment_bytes)?;
        let parent = path.parent().context("missing fragment state parent")?;
        let staging = tempfile::Builder::new()
            .prefix(".fragments-")
            .tempdir_in(parent)?;
        fs::set_permissions(staging.path(), fs::Permissions::from_mode(0o700))?;
        let mut set = Self {
            directory: state::directory(staging.path())?,
            root_sha256: [0; 32],
            placements: Vec::new(),
            data: Manifest {
                version: 1,
                owner_key: owner.to_bytes(),
                ciphertext_bytes: plan.ciphertext_bytes,
                sha256: plan.sha256,
                fragment_bytes,
                copies_per_fragment: plan.copies,
                providers: grants
                    .iter()
                    .map(|grant| Provider {
                        key: grant.provider_key().to_bytes(),
                        grant_sha256: Sha256::digest(grant.signed().encode()).into(),
                    })
                    .collect(),
                fragments,
            },
        };
        for index in 0..count {
            let selected: Vec<_> = (0..plan.copies)
                .map(|copy| grants[(index + copy) % grants.len()].clone())
                .collect();
            let fragment = &set.data.fragments[index];
            let copies = LockedSet::create(
                &set.fragment_path(index),
                &owner,
                fragment.length,
                fragment.sha256,
                &selected,
                lifetime,
            )?;
            for copy in 0..plan.copies {
                let retained = copies.copy(copy)?;
                set.data.fragments[index].copies.push(CopyBinding {
                    provider: (index + copy) % grants.len(),
                    archive_id: retained.journal.archive_id,
                });
            }
        }
        let signature = hex::encode(signer.sign(&signing_bytes(&set.data)?).to_bytes());
        let encoded = serde_json::to_vec(&SignedManifest {
            manifest: set.data,
            signature,
        })?;
        ensure!(
            encoded.len() as u64 <= MAX_MANIFEST_BYTES,
            "signed fragment manifest too large"
        );
        state::private_output(&state::anchored(&set.directory).join(MANIFEST), &encoded)?;
        rustix::fs::renameat_with(
            rustix::fs::CWD,
            staging.path(),
            rustix::fs::CWD,
            path,
            rustix::fs::RenameFlags::NOREPLACE,
        )?;
        drop(staging);
        drop(set.directory);
        File::open(parent)?.sync_all()?;
        Self::open(path)
    }

    pub(super) fn open(path: &Path) -> Result<Self> {
        crate::storage::require_absolute(path)?;
        let directory = state::directory(path)?;
        let bytes = state::read_private(
            &state::anchored(&directory).join(MANIFEST),
            MAX_MANIFEST_BYTES,
        )?;
        let signed: SignedManifest =
            serde_json::from_slice(&bytes).context("invalid signed fragment manifest")?;
        ensure!(
            signed.signature.len() == 128,
            "invalid reconstruction signature length"
        );
        let signature = Signature::from_slice(&hex::decode(&signed.signature)?)?;
        let owner = VerifyingKey::from_bytes(&signed.manifest.owner_key)?;
        owner
            .verify_strict(&signing_bytes(&signed.manifest)?, &signature)
            .context("owner reconstruction signature does not verify")?;
        let data = signed.manifest;
        ensure!(
            data.version == 1
                && (3..=8).contains(&data.providers.len())
                && (2..data.providers.len()).contains(&data.copies_per_fragment)
                && (data.providers.len()..=MAX_FRAGMENTS).contains(&data.fragments.len())
                && (1..=MAX_ARCHIVE_BYTES).contains(&data.ciphertext_bytes)
                && (1..=MAX_FRAGMENT_BYTES).contains(&data.fragment_bytes),
            "invalid reconstruction scope"
        );
        ensure!(
            data.ciphertext_bytes.div_ceil(data.fragment_bytes) == data.fragments.len() as u64,
            "noncanonical fragment count"
        );
        let mut providers = BTreeSet::new();
        for provider in &data.providers {
            VerifyingKey::from_bytes(&provider.key)?;
            ensure!(
                provider.key != data.owner_key && providers.insert(provider.key),
                "duplicate fragment provider"
            );
        }
        let root_sha256 = Sha256::digest(&bytes).into();
        let placements = placement::load(&directory, root_sha256, &owner)?;
        let set = Self {
            directory,
            data,
            root_sha256,
            placements,
        };
        placement::validate(&set)?;
        let mut offset = 0_u64;
        let mut archives = BTreeSet::new();
        for (index, fragment) in set.data.fragments.iter().enumerate() {
            ensure!(
                fragment.offset == offset
                    && offset < set.data.ciphertext_bytes
                    && fragment.length
                        == set
                            .data
                            .fragment_bytes
                            .min(set.data.ciphertext_bytes - offset)
                    && fragment.copies.len() == set.data.copies_per_fragment,
                "fragment range or copies changed"
            );
            for (copy, binding) in fragment.copies.iter().enumerate() {
                ensure!(
                    binding.provider == (index + copy) % set.data.providers.len()
                        && binding.archive_id != [0; 32]
                        && archives.insert(binding.archive_id),
                    "noncanonical fragment placement or duplicate archive identity"
                );
            }
            set.fragment(index)?;
            offset += fragment.length;
        }
        ensure!(
            offset == set.data.ciphertext_bytes,
            "fragment plan does not cover original archive"
        );
        Ok(set)
    }

    fn fragment_path(&self, index: usize) -> PathBuf {
        state::anchored(&self.directory).join(format!("fragment-{index:04}"))
    }

    pub(super) fn fragment(&self, index: usize) -> Result<LockedSet> {
        let fragment = self.data.fragments.get(index).context("unknown fragment")?;
        // No unsigned child recovery may occur before its signed parent authorization.
        let mut copies = LockedSet::open_without_recovery(&self.fragment_path(index))?;
        ensure!(
            copies.data.ciphertext_bytes == fragment.length
                && copies.data.sha256 == fragment.sha256,
            "fragment set differs from signed reconstruction root"
        );
        placement::authorize_child(self, index, &mut copies)?;
        for (copy, binding) in fragment.copies.iter().enumerate() {
            let provider = self
                .data
                .providers
                .get(binding.provider)
                .context("unknown fragment provider")?;
            let retained = copies.copy(copy)?;
            let journal = &retained.journal;
            let grant_digest: [u8; 32] = Sha256::digest(hex::decode(&journal.grant_hex)?).into();
            ensure!(
                journal.owner_key == self.data.owner_key
                    && journal.provider_key == provider.key
                    && journal.archive_id == binding.archive_id
                    && grant_digest == provider.grant_sha256,
                "fragment journal differs from signed owner/provider/archive/grant binding"
            );
        }
        Ok(copies)
    }

    pub(super) fn check_owner(&self, signer: &SigningKey) -> Result<()> {
        ensure!(
            self.data.owner_key == signer.verifying_key().to_bytes(),
            "reconstruction manifest belongs to another owner"
        );
        Ok(())
    }

    pub(super) fn staging(&self) -> Result<tempfile::TempDir> {
        Ok(tempfile::Builder::new()
            .prefix(".fragment-transfer-")
            .tempdir_in(state::anchored(&self.directory))?)
    }

    pub(super) fn report(&self, operation: &str) -> Result<serde_json::Value> {
        let mut reserved = 0_u64;
        let mut committed = 0_u64;
        let mut uncertain = 0_u64;
        let mut recoverable = 0;
        let mut redundant = 0;
        let mut fragments = Vec::with_capacity(self.data.fragments.len());
        let providers = placement::providers(self);
        let mut provider_bytes = vec![0_u64; providers.len()];
        let mut retained_copies = 0;
        let mut pending_retirements = 0;
        let now = crate::storage::now()?;
        for (index, fragment) in self.data.fragments.iter().enumerate() {
            let copies = self.fragment(index)?;
            retained_copies += copies.data.copies.len();
            pending_retirements +=
                usize::from(copies.data.handoff.as_ref().is_some_and(|intent| {
                    intent.phase != super::super::retained::HandoffPhase::Complete
                }));
            let mut confirmed = 0;
            for (copy, record) in copies.data.copies.iter().enumerate() {
                let retained = copies.copy(copy)?;
                match record.charge {
                    Charge::Reserved => reserved += fragment.length,
                    Charge::Committed => {
                        committed += fragment.length;
                        if retained.journal.last_state == Some(ReceiptState::Committed as i32)
                            && retained.journal.last_expiry > now
                        {
                            confirmed += 1;
                        }
                    }
                    Charge::Uncertain => uncertain += fragment.length,
                    Charge::Unattempted | Charge::Deleted => {}
                }
                if !matches!(record.charge, Charge::Unattempted | Charge::Deleted) {
                    let provider = providers
                        .iter()
                        .position(|key| key == &record.provider_key)
                        .context("authorized copy provider missing from accounting")?;
                    provider_bytes[provider] += fragment.length;
                }
            }
            recoverable += usize::from(confirmed > 0);
            redundant += usize::from(confirmed >= self.data.copies_per_fragment);
            fragments.push(
                serde_json::json!({"index": index, "offset": fragment.offset,
                "ciphertext_bytes": fragment.length, "confirmed_unexpired_copies": confirmed,
                "copies": copies.report("status")?["copies"]}),
            );
        }
        let mut report = serde_json::json!({
            "operation": format!("private_storage_fragments_{operation}"),
            "logical_ciphertext_bytes": self.data.ciphertext_bytes, "fragment_count": self.data.fragments.len(),
            "copies_per_fragment": self.data.copies_per_fragment,
            "distinct_provider_identities": providers.len(),
            "reserved_payload_bytes": reserved, "committed_payload_bytes": committed,
            "uncertain_payload_bytes": uncertain, "physical_payload_charge_upper_bound": reserved + committed + uncertain,
            "metadata_overhead_measured": false, "expired_copies_remain_charged": true,
            "fragments_with_confirmed_unexpired_copy": recoverable,
            "fully_redundant_from_retained_receipts": redundant == self.data.fragments.len(),
            "current_remote_availability_proven": false, "independent_failure_domains_proven": false,
            "network_contribution_credit": false, "automatic_repair": false, "automatic_handoff": false,
            "read_consumes_archive": false, "erasure_coding": false, "owner_signature_verified": true,
            "providers": providers.iter().zip(provider_bytes).map(|(provider, charge)|
                serde_json::json!({"provider_key": hex::encode(provider),
                    "physical_payload_charge_upper_bound": charge})).collect::<Vec<_>>(),
            "fragments": fragments,
        });
        if !self.placements.is_empty() {
            report["report_version"] = 2.into();
            report["placement_authorizations"] = self.placements.len().into();
            report["retained_copy_records"] = retained_copies.into();
            report["pending_retirements"] = pending_retirements.into();
            report["desired_copies_per_fragment"] = self.data.copies_per_fragment.into();
            report["replacement_overhead_included"] = true.into();
        }
        Ok(report)
    }
}
