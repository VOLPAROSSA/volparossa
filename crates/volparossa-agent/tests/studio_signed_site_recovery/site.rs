// SPDX-License-Identifier: GPL-3.0-only
use std::{
    ffi::OsString,
    path::PathBuf,
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use sha2::{Digest, Sha256};
use tokio::time::Instant;
use volparossa_content::{
    MAX_MANIFEST_BYTES, SignedManifest, VerifiedManifest,
    site::{SITE_CONTENT_TYPE, SiteBundle},
};

use super::{
    Progress, Result,
    fixture::{Fixture, read_inventory, read_private},
    process::cli,
};

pub(super) const MAX_BYTES: u64 = 32 * 1024 * 1024;
pub(super) const NAME: &str = "public-silex-signed-recovery-fixture";

pub(super) struct Packed {
    pub(super) bytes: Vec<u8>,
    pub(super) sha: [u8; 32],
    pub(super) assets: Vec<Value>,
}

pub(super) fn now() -> Result<u64> {
    Ok(SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| "clock")?
        .as_secs())
}
pub(super) fn limits(args: &mut Vec<OsString>) {
    args.extend(["--quota-bytes", "33554432", "--max-entries", "128"].map(OsString::from));
}

pub(super) async fn pack(
    f: &Fixture,
    p: &Progress,
    work: Instant,
    total: Instant,
) -> Result<Packed> {
    let directory = PathBuf::from(
        std::env::var_os("VOLPAROSSA_STUDIO_EXPORT_DIRECTORY").ok_or("export_input")?,
    );
    let inventory = PathBuf::from(
        std::env::var_os("VOLPAROSSA_STUDIO_EXPORT_INVENTORY").ok_or("export_inventory")?,
    );
    let inventory: Value =
        serde_json::from_slice(&read_inventory(&inventory)?).map_err(|_| "inventory_shape")?;
    if inventory["schema"] != 1 {
        return Err("inventory_version");
    }
    let assets = inventory["assets"]
        .as_array()
        .ok_or("inventory_assets")?
        .clone();
    let value = cli(
        f,
        vec![
            "site".into(),
            "pack".into(),
            "--directory".into(),
            directory.into_os_string(),
            "--output".into(),
            f.path("site.bundle").into_os_string(),
        ],
        p,
        work,
        total,
        false,
    )
    .await?
    .json()?;
    let bytes = read_private(&f.path("site.bundle"), MAX_BYTES)?;
    if value["operation"] != "site_pack"
        || value["network_published"] != false
        || value["symlinks_followed"] != false
        || value["content_type"] != SITE_CONTENT_TYPE
        || value["bytes"].as_u64() != u64::try_from(bytes.len()).ok()
        || value["assets"].as_u64() != u64::try_from(assets.len()).ok()
    {
        return Err("pack_receipt");
    }
    verify_assets(&bytes, &assets)?;
    Ok(Packed {
        sha: Sha256::digest(&bytes).into(),
        bytes,
        assets,
    })
}

pub(super) fn verify_assets(bytes: &[u8], assets: &[Value]) -> Result<()> {
    if !(2..=256).contains(&assets.len()) {
        return Err("inventory_count");
    }
    let bundle = SiteBundle::decode(bytes.to_vec()).map_err(|_| "bundle_shape")?;
    if bundle.asset_count() != assets.len() {
        return Err("bundle_inventory_count");
    }
    let mut paths = std::collections::BTreeSet::new();
    for row in assets {
        let path = row["path"].as_str().ok_or("inventory_path")?;
        if !paths.insert(path) {
            return Err("duplicate_inventory_path");
        }
        let asset = bundle.asset(path).ok_or("missing_inventory_asset")?;
        if row["bytes"].as_u64() != u64::try_from(asset.bytes.len()).ok()
            || row["sha256"].as_str() != Some(hex::encode(Sha256::digest(asset.bytes)).as_str())
        {
            return Err("inventory_asset_binding");
        }
    }
    let edited = bundle.asset("/studio-export.html").ok_or("edited_page")?;
    if edited.content_type != "text/html"
        || !edited
            .bytes
            .windows(b"VOLPAROSSA Studio manual export 20261022".len())
            .any(|w| w == b"VOLPAROSSA Studio manual export 20261022")
    {
        return Err("edited_marker");
    }
    Ok(())
}

pub(super) async fn publish(
    f: &Fixture,
    p: &Progress,
    packed: &Packed,
    work: Instant,
    total: Instant,
) -> Result<(Vec<u8>, VerifiedManifest)> {
    let mut args = vec![
        "publish".into(),
        "--input".into(),
        f.path("site.bundle").into_os_string(),
        "--expected-input-sha256".into(),
        hex::encode(packed.sha).into(),
        "--expected-publisher-key".into(),
        hex::encode(f.publisher.as_bytes()).into(),
        "--cache".into(),
        f.path("source-cache").into_os_string(),
        "--manifest".into(),
        f.path("manifest.pb").into_os_string(),
        "--name".into(),
        NAME.into(),
        "--revision".into(),
        "1".into(),
        "--content-type".into(),
        SITE_CONTENT_TYPE.into(),
        "--lifetime-seconds".into(),
        "600".into(),
        "--identity".into(),
        f.path("state/identity.key").into_os_string(),
        "--passphrase-file".into(),
        f.path("credentials/identity-passphrase").into_os_string(),
    ];
    limits(&mut args);
    let value = cli(f, args, p, work, total, false).await?.json()?;
    let encoded = read_private(
        &f.path("manifest.pb"),
        u64::try_from(MAX_MANIFEST_BYTES).map_err(|_| "manifest_limit")?,
    )?;
    let manifest = SignedManifest::decode(&encoded)
        .map_err(|_| "manifest_shape")?
        .verify(&f.publisher, now()?)
        .map_err(|_| "manifest_auth")?;
    if manifest.length() != u64::try_from(packed.bytes.len()).map_err(|_| "bundle_length")?
        || manifest.object_sha256() != &packed.sha
        || manifest.metadata().name != NAME
        || manifest.metadata().revision != 1
        || manifest.metadata().content_type != SITE_CONTENT_TYPE
        || manifest
            .validity()
            .expires
            .checked_sub(manifest.validity().created)
            != Some(600)
        || value["operation"] != "offline_content_publish"
        || value["network_publication"] != false
        || value["publisher_key_hex"] != hex::encode(f.publisher.as_bytes())
        || value["manifest_id"] != hex::encode(manifest.manifest_id())
        || value["bytes"].as_u64() != Some(manifest.length())
        || value["chunks"].as_u64() != u64::try_from(manifest.chunks().len()).ok()
        || value["expires_unix_seconds"].as_u64() != Some(manifest.validity().expires)
    {
        return Err("publication_binding");
    }
    Ok((encoded, manifest))
}

pub(super) async fn handoff(
    f: &Fixture,
    p: &Progress,
    operation: &str,
    manifest: &VerifiedManifest,
    work: Instant,
    total: Instant,
) -> Result<()> {
    let cache = if operation == "import" {
        "source-cache"
    } else {
        "export-cache"
    };
    let mut args = vec![
        operation.into(),
        "--manifest".into(),
        f.path("manifest.pb").into_os_string(),
        "--publisher-key".into(),
        hex::encode(f.publisher.as_bytes()).into(),
        "--cache".into(),
        f.path(cache).into_os_string(),
        "--agent-cache".into(),
        f.path("agent-cache").into_os_string(),
        "--public-content".into(),
    ];
    limits(&mut args);
    let value = cli(f, args, p, work, total, false).await?.json()?;
    if value["operation"] != format!("content_{operation}")
        || value["manifest_id"] != hex::encode(manifest.manifest_id())
        || value["content_bytes"].as_u64() != Some(manifest.length())
        || value["chunks"].as_u64() != u64::try_from(manifest.chunks().len()).ok()
        || value["complete"] != true
        || value["public_content"] != true
        || value["network_transfer"] != false
        || value["ownership_changed"] != false
        || value["private_keys_transferred"] != false
        || value["origin_authenticated"] != false
    {
        return Err("handoff_binding");
    }
    Ok(())
}

pub(super) async fn assemble(
    f: &Fixture,
    p: &Progress,
    packed: &Packed,
    manifest: &VerifiedManifest,
    work: Instant,
    total: Instant,
) -> Result<()> {
    let mut args = vec![
        "assemble".into(),
        "--manifest".into(),
        f.path("manifest.pb").into_os_string(),
        "--publisher-key".into(),
        hex::encode(f.publisher.as_bytes()).into(),
        "--cache".into(),
        f.path("export-cache").into_os_string(),
        "--output".into(),
        f.path("reconstructed.bundle").into_os_string(),
    ];
    limits(&mut args);
    let value = cli(f, args, p, work, total, false).await?.json()?;
    let bytes = read_private(&f.path("reconstructed.bundle"), MAX_BYTES)?;
    if bytes != packed.bytes
        || <[u8; 32]>::from(Sha256::digest(&bytes)) != packed.sha
        || value["operation"] != "offline_content_assemble"
        || value["network_retrieval"] != false
        || value["bytes"].as_u64() != Some(manifest.length())
        || value["chunks"].as_u64() != u64::try_from(manifest.chunks().len()).ok()
    {
        return Err("assemble_binding");
    }
    verify_assets(&bytes, &packed.assets)
}
