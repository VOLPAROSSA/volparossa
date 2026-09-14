//! Explicitly trusted public adapter channels, with independently selected dataset authority.
//! Imports are inert data. Fixed-worker tensor validation and owner-authorized evaluation
//! remain necessary before adoption; neither publication nor import proves model quality.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::{
        DirBuilderExt as _, FileExt as _, MetadataExt as _, OpenOptionsExt as _,
        PermissionsExt as _,
    },
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use ed25519_dalek::VerifyingKey;
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use volparossa_content::{
    CHUNK_BYTES, ChunkId, MAX_MANIFEST_BYTES, SignedManifest, VerifiedManifest,
    agent_artifact::{ADAPTER_CONTENT_TYPE, AdapterBundle, MAX_ADAPTER_BYTES},
    provider::compute::dataset,
};

use super::{FetchName, Limits, ensure_new_output, named_download, now_seconds, output_parent};

const MAX_PROVENANCE: usize = 128 * 1024;
const MAX_RECEIPT: usize = 32 * 1024;
const PENDING_FILES: [&str; 3] = ["adapter.bundle", "adapter.manifest", "provenance.json"];
const IMPORT_FILES: [&str; 6] = [
    "adapter",
    "adapter.bundle",
    "adapter.manifest",
    "dataset.json",
    "dataset.manifest",
    "provenance.json",
];
const ADAPTER_FILES: [&str; 3] = [
    "README.md",
    "adapter_config.json",
    "adapter_model.safetensors",
];

pub(crate) struct Fetch {
    pub(crate) publisher_key: VerifyingKey,
    pub(crate) name: String,
    pub(crate) min_revision: Option<u64>,
    pub(crate) cache: PathBuf,
    pub(crate) limits: Limits,
}

/// Authority comes from the coordinator's enrollment/catalog, never the adapter's bytes.
pub(crate) struct DatasetSource {
    pub(crate) publisher_key: VerifyingKey,
    pub(crate) name: String,
    pub(crate) revision: u64,
    pub(crate) manifest_id: [u8; 32],
}

pub(crate) struct VerifiedUpdate {
    manifest: VerifiedManifest,
    signed_manifest: Vec<u8>,
    bundle: AdapterBundle,
    dataset_manifest_id: [u8; 32],
    receipt: Value,
}

impl VerifiedUpdate {
    pub(crate) fn revision(&self) -> u64 {
        self.manifest.metadata().revision
    }

    pub(crate) fn manifest_id(&self) -> &[u8; 32] {
        self.manifest.manifest_id()
    }

    pub(crate) fn dataset_manifest_id(&self) -> &[u8; 32] {
        &self.dataset_manifest_id
    }

    pub(crate) fn expires(&self) -> u64 {
        self.manifest.validity().expires
    }

    pub(crate) fn signed_manifest(&self) -> &[u8] {
        &self.signed_manifest
    }

    pub(crate) fn bundle(&self) -> &[u8] {
        self.bundle.encoded()
    }

    pub(crate) const fn receipt(&self) -> &Value {
        &self.receipt
    }
}

pub(crate) struct ImportedUpdate {
    update: VerifiedUpdate,
    provenance: Value,
    expires: u64,
}

impl ImportedUpdate {
    pub(crate) const fn provenance(&self) -> &Value {
        &self.provenance
    }

    pub(crate) const fn expires(&self) -> u64 {
        self.expires
    }

    pub(crate) fn revision(&self) -> u64 {
        self.update.revision()
    }

    pub(crate) fn manifest_id(&self) -> &[u8; 32] {
        self.update.manifest_id()
    }

    pub(crate) fn dataset_manifest_id(&self) -> &[u8; 32] {
        self.update.dataset_manifest_id()
    }
}

/// Refresh metadata for exactly this enrolled channel; cached chunks may still be reused.
pub(crate) async fn fetch(args: &Fetch, socket: &Path, parent: &Path) -> Result<VerifiedUpdate> {
    private_directory(parent)?;
    let query = query(
        args,
        args.publisher_key,
        &args.name,
        args.min_revision,
        parent,
    );
    let download = named_download::prepare_bounded_refresh(
        &query,
        socket,
        parent,
        &named_download::Requirement {
            content_type: ADAPTER_CONTENT_TYPE,
            maximum_bytes: MAX_ADAPTER_BYTES as u64,
            manifest_id: None,
        },
    )
    .await?;
    let bundle = read_download(download.as_file(), MAX_ADAPTER_BYTES)?;
    let update = verify(
        args,
        &download.signed_manifest().encode(),
        &bundle,
        download.report(),
        now_seconds()?,
    )?;
    download.check_live()?;
    Ok(update)
}

/// Reusable original-object verification; does not infer dataset trust or activate weights.
pub(crate) fn verify(
    args: &Fetch,
    signed: &[u8],
    bytes: &[u8],
    receipt: Value,
    now: u64,
) -> Result<VerifiedUpdate> {
    let manifest = SignedManifest::decode(signed)?.verify(&args.publisher_key, now)?;
    ensure!(
        manifest.metadata().name == args.name
            && manifest.metadata().revision >= args.min_revision.unwrap_or(1)
            && manifest.metadata().content_type == ADAPTER_CONTENT_TYPE,
        "peer_update_channel"
    );
    verify_bytes(&manifest, bytes, MAX_ADAPTER_BYTES)?;
    verify_receipt(&manifest, &receipt)?;
    let bundle = AdapterBundle::decode(bytes.to_vec())?;
    Ok(VerifiedUpdate {
        manifest,
        signed_manifest: signed.to_vec(),
        dataset_manifest_id: bundle.dataset_manifest_id(),
        bundle,
        receipt,
    })
}

/// Retain an unknown-dataset candidate without repeated downloads or partial import claims.
pub(crate) fn save_pending(update: &VerifiedUpdate, output: &Path) -> Result<()> {
    ensure!(now_seconds()? < update.expires(), "peer_update_expired");
    let staging = staging(output)?;
    write_adapter_original(staging.path(), update)?;
    write_json(
        &staging.path().join("provenance.json"),
        &pending_provenance(update),
    )?;
    publish(staging, output)
}

pub(crate) fn open_pending(output: &Path, args: &Fetch, now: u64) -> Result<VerifiedUpdate> {
    exact_directory(output, &PENDING_FILES)?;
    let provenance = read_json(&output.join("provenance.json"))?;
    let update = read_update(output, args, &provenance, now)?;
    ensure!(
        provenance == pending_provenance(&update),
        "peer_update_pending_provenance"
    );
    Ok(update)
}

/// Import only after independently resolving the exact bundled dataset identity.
pub(crate) async fn import(
    args: &Fetch,
    update: &VerifiedUpdate,
    source: &DatasetSource,
    socket: &Path,
    output: &Path,
) -> Result<ImportedUpdate> {
    check_source_id(update, source)?;
    // Recheck authority/expiry before any new output or local-control request.
    let current = verify(
        args,
        update.signed_manifest(),
        update.bundle(),
        update.receipt().clone(),
        now_seconds()?,
    )?;
    let staging = staging(output)?;
    let query = query(
        args,
        source.publisher_key,
        &source.name,
        Some(source.revision),
        staging.path(),
    );
    let download = named_download::prepare_bounded(
        &query,
        socket,
        staging.path(),
        &named_download::Requirement {
            content_type: dataset::CONTENT_TYPE,
            maximum_bytes: dataset::MAX_DATASET_BYTES as u64,
            manifest_id: Some(source.manifest_id),
        },
    )
    .await?;
    let bytes = read_download(download.as_file(), dataset::MAX_DATASET_BYTES)?;
    let signed = download.signed_manifest().encode();
    let imported = assemble(
        &current,
        source,
        &signed,
        &bytes,
        download.report(),
        now_seconds()?,
    )?;
    write_import(
        staging.path(),
        &current,
        &signed,
        &bytes,
        &imported.provenance,
    )?;
    download.check_live()?;
    ensure!(now_seconds()? < imported.expires(), "peer_update_expired");
    drop(download); // Its temporary must not become an extra retained import file.
    publish(staging, output)?;
    Ok(imported)
}

/// Original signatures, exact selected revision, bundle and every extracted file are rechecked.
pub(crate) fn reopen(
    output: &Path,
    args: &Fetch,
    source: &DatasetSource,
    now: u64,
) -> Result<ImportedUpdate> {
    exact_directory(output, &IMPORT_FILES)?;
    exact_directory(&output.join("adapter"), &ADAPTER_FILES)?;
    let provenance = read_json(&output.join("provenance.json"))?;
    let update = read_update(output, args, &provenance, now)?;
    let signed = read_file(&output.join("dataset.manifest"), MAX_MANIFEST_BYTES)?;
    let bytes = read_file(&output.join("dataset.json"), dataset::MAX_DATASET_BYTES)?;
    let imported = assemble(
        &update,
        source,
        &signed,
        &bytes,
        provenance["dataset_receipt"].clone(),
        now,
    )?;
    ensure!(
        provenance == imported.provenance,
        "peer_update_import_provenance"
    );
    for (name, expected) in adapter_files(&update) {
        ensure!(
            read_file(&output.join("adapter").join(name), expected.len())? == expected,
            "peer_update_extracted_bytes"
        );
    }
    Ok(imported)
}

fn query(
    args: &Fetch,
    publisher_key: VerifyingKey,
    name: &str,
    min_revision: Option<u64>,
    parent: &Path,
) -> FetchName {
    FetchName {
        publisher_key,
        name: name.into(),
        min_revision,
        cache: args.cache.clone(),
        reuse_cache: true,
        cache_only: false,
        local_output: parent.join("unused-peer-update-output"),
        limits: args.limits.clone(),
    }
}

fn check_source_id(update: &VerifiedUpdate, source: &DatasetSource) -> Result<()> {
    ensure!(
        source.revision > 0
            && source.manifest_id != [0; 32]
            && update.dataset_manifest_id() == &source.manifest_id,
        "peer_update_dataset_not_selected"
    );
    Ok(())
}

fn assemble(
    update: &VerifiedUpdate,
    source: &DatasetSource,
    signed: &[u8],
    bytes: &[u8],
    receipt: Value,
    now: u64,
) -> Result<ImportedUpdate> {
    check_source_id(update, source)?;
    let verified = dataset::verify_source(
        signed,
        &source.publisher_key,
        std::str::from_utf8(bytes)?,
        now,
    )?;
    let manifest = SignedManifest::decode(signed)?.verify(&source.publisher_key, now)?;
    ensure!(
        !verified.is_document()
            && manifest.metadata().content_type == dataset::CONTENT_TYPE
            && manifest.metadata().name == source.name
            && manifest.metadata().revision == source.revision
            && manifest.manifest_id() == &source.manifest_id,
        "peer_update_dataset_authority"
    );
    verify_receipt(&manifest, &receipt)?;
    let expires = update.expires().min(verified.expires());
    ensure!(now < expires, "peer_update_expired");
    let mut provenance = pending_provenance(update);
    provenance["operation"] = "peer_update_import".into();
    provenance["dataset"] = json!({"publisher_key":hex::encode(source.publisher_key.as_bytes()),
        "name":source.name,"revision":source.revision,"manifest_id":hex::encode(source.manifest_id),
        "manifest_sha256":hex::encode(Sha256::digest(signed)),"sha256":hex::encode(manifest.object_sha256()),
        "bytes":manifest.length(),"expires_unix_seconds":verified.expires()});
    provenance["dataset_receipt"] = receipt;
    provenance["expires_unix_seconds"] = expires.into();
    Ok(ImportedUpdate {
        update: VerifiedUpdate {
            manifest: update.manifest.clone(),
            signed_manifest: update.signed_manifest.clone(),
            bundle: AdapterBundle::decode(update.bundle().to_vec())?,
            receipt: update.receipt.clone(),
            dataset_manifest_id: *update.dataset_manifest_id(),
        },
        provenance,
        expires,
    })
}

fn pending_provenance(update: &VerifiedUpdate) -> Value {
    json!({"version":1,"operation":"peer_update_pending",
        "adapter":{"publisher_key":hex::encode(update.manifest.publisher()),
            "name":update.manifest.metadata().name,"revision":update.revision(),
            "manifest_id":hex::encode(update.manifest_id()),
            "manifest_sha256":hex::encode(Sha256::digest(update.signed_manifest())),
            "sha256":hex::encode(update.manifest.object_sha256()),"bytes":update.manifest.length(),
            "dataset_manifest_id":hex::encode(update.dataset_manifest_id()),
            "expires_unix_seconds":update.expires()},
        "adapter_receipt":update.receipt(),"expires_unix_seconds":update.expires(),
        "model_activated":false,"model_quality_proven":false,"private_data_supported":false})
}

fn verify_bytes(manifest: &VerifiedManifest, bytes: &[u8], maximum: usize) -> Result<()> {
    ensure!(
        !bytes.is_empty()
            && bytes.len() <= maximum
            && manifest.length() == bytes.len() as u64
            && manifest.object_sha256() == &<[u8; 32]>::from(Sha256::digest(bytes)),
        "peer_update_original_bytes"
    );
    ensure!(
        bytes.chunks(CHUNK_BYTES).len() == manifest.chunks().len(),
        "peer_update_original_chunks"
    );
    for (part, chunk) in bytes.chunks(CHUNK_BYTES).zip(manifest.chunks()) {
        ensure!(
            chunk.id() == &ChunkId::digest(part) && chunk.length() as usize == part.len(),
            "peer_update_original_chunks"
        );
    }
    Ok(())
}

fn verify_receipt(manifest: &VerifiedManifest, receipt: &Value) -> Result<()> {
    ensure!(
        serde_json::to_vec(receipt)?.len() <= MAX_RECEIPT
            && receipt["manifest_id"] == hex::encode(manifest.manifest_id())
            && receipt["sha256"] == hex::encode(manifest.object_sha256())
            && receipt["bytes"].as_u64() == Some(manifest.length())
            && receipt["chunks"].as_u64() == Some(manifest.chunks().len() as u64),
        "peer_update_receipt_binding"
    );
    Ok(())
}

fn read_update(root: &Path, args: &Fetch, provenance: &Value, now: u64) -> Result<VerifiedUpdate> {
    verify(
        args,
        &read_file(&root.join("adapter.manifest"), MAX_MANIFEST_BYTES)?,
        &read_file(&root.join("adapter.bundle"), MAX_ADAPTER_BYTES)?,
        provenance["adapter_receipt"].clone(),
        now,
    )
}

fn adapter_files(update: &VerifiedUpdate) -> [(&'static str, &[u8]); 3] {
    [
        ("README.md", update.bundle.readme()),
        ("adapter_config.json", update.bundle.config()),
        ("adapter_model.safetensors", update.bundle.weights()),
    ]
}

fn write_adapter_original(root: &Path, update: &VerifiedUpdate) -> Result<()> {
    write_new(&root.join("adapter.manifest"), update.signed_manifest())?;
    write_new(&root.join("adapter.bundle"), update.bundle())
}

fn write_import(
    root: &Path,
    update: &VerifiedUpdate,
    signed: &[u8],
    bytes: &[u8],
    provenance: &Value,
) -> Result<()> {
    write_adapter_original(root, update)?;
    let adapter = root.join("adapter");
    fs::DirBuilder::new().mode(0o700).create(&adapter)?;
    for (name, bytes) in adapter_files(update) {
        write_new(&adapter.join(name), bytes)?;
    }
    File::open(adapter)?.sync_all()?;
    write_new(&root.join("dataset.manifest"), signed)?;
    write_new(&root.join("dataset.json"), bytes)?;
    write_json(&root.join("provenance.json"), provenance)
}

fn private_directory(path: &Path) -> Result<()> {
    let metadata = fs::symlink_metadata(path)?;
    ensure!(
        metadata.is_dir()
            && metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.mode() & 0o777 == 0o700,
        "peer_update_private_directory"
    );
    Ok(())
}

fn exact_directory(path: &Path, expected: &[&str]) -> Result<()> {
    private_directory(path)?;
    let mut names = Vec::new();
    for entry in fs::read_dir(path)?.take(expected.len() + 1) {
        names.push(entry?.file_name());
    }
    names.sort();
    ensure!(
        names
            == expected
                .iter()
                .map(std::ffi::OsString::from)
                .collect::<Vec<_>>(),
        "peer_update_file_set"
    );
    Ok(())
}

fn read_download(file: &File, maximum: usize) -> Result<Vec<u8>> {
    let length = usize::try_from(file.metadata()?.len())?;
    ensure!(length > 0 && length <= maximum, "peer_update_file_bound");
    let mut bytes = vec![0; length];
    file.read_exact_at(&mut bytes, 0)?;
    Ok(bytes)
}

fn read_file(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    let mut file = super::open_regular(path, maximum as u64)?;
    let metadata = file.metadata()?;
    ensure!(
        metadata.uid() == nix::unistd::geteuid().as_raw()
            && metadata.nlink() == 1
            && metadata.mode() & 0o777 == 0o600,
        "peer_update_file_owner"
    );
    let mut bytes = Vec::new();
    (&mut file)
        .take(maximum as u64 + 1)
        .read_to_end(&mut bytes)?;
    ensure!(
        !bytes.is_empty() && bytes.len() <= maximum,
        "peer_update_file_bound"
    );
    Ok(bytes)
}

fn read_json(path: &Path) -> Result<Value> {
    Ok(serde_json::from_slice(&read_file(path, MAX_PROVENANCE)?)?)
}

fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(path)?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn write_json(path: &Path, value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= MAX_PROVENANCE,
        "peer_update_provenance_bound"
    );
    write_new(path, &bytes)
}

fn staging(output: &Path) -> Result<tempfile::TempDir> {
    ensure_new_output(output)?;
    let parent = output_parent(output);
    private_directory(parent)?;
    tempfile::Builder::new()
        .prefix(".peer-update-")
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)
        .context("peer_update_staging")
}

fn publish(staging: tempfile::TempDir, output: &Path) -> Result<()> {
    File::open(staging.path())?.sync_all()?;
    rustix::fs::renameat_with(
        rustix::fs::CWD,
        staging.path(),
        rustix::fs::CWD,
        output,
        rustix::fs::RenameFlags::NOREPLACE,
    )?;
    drop(staging); // Consume the old staging-path owner; the published directory is retained.
    File::open(output_parent(output))?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests;
