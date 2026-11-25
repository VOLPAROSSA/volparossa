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
    process::{Invocation, cli},
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
            "--review-receipt".into(),
        ],
        p,
        work,
        total,
        Invocation::Plain,
    )
    .await?
    .json()?;
    let bytes = read_private(&f.path("site.bundle"), MAX_BYTES)?;
    verify_preparation(&value, &bytes, &assets)?;
    Ok(Packed {
        sha: Sha256::digest(&bytes).into(),
        bytes,
        assets,
    })
}

pub(super) fn verify_assets(bytes: &[u8], assets: &[Value]) -> Result<()> {
    let bundle = SiteBundle::decode(bytes.to_vec()).map_err(|_| "bundle_shape")?;
    verify_bundle_assets(&bundle, assets)
}

fn verify_bundle_assets(bundle: &SiteBundle, assets: &[Value]) -> Result<()> {
    if !(2..=256).contains(&assets.len()) {
        return Err("inventory_count");
    }
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

fn has_keys(value: &Value, expected: &[&str]) -> bool {
    value.as_object().is_some_and(|object| {
        object.len() == expected.len() && expected.iter().all(|key| object.contains_key(*key))
    })
}

fn verify_preparation_scope(value: &Value) -> Result<()> {
    if !has_keys(
        value,
        &[
            "schema_version",
            "operation",
            "source",
            "content_type",
            "bundle_sha256",
            "bundle_bytes",
            "asset_count",
            "assets",
            "symlinks_followed",
            "hidden_entries_excluded",
            "native_consent_granted",
            "publication_signed",
            "network_published",
            "publisher_authority_granted",
            "permission_authority_granted",
            "input_files_modified",
            "bundle_output_created",
            "review_required",
        ],
    ) || value["schema_version"].as_u64() != Some(1)
        || value["operation"] != "site_pack_preparation"
        || value["source"] != "explicit_local_directory"
        || value["content_type"] != SITE_CONTENT_TYPE
    {
        return Err("pack_receipt_shape");
    }
    for key in [
        "symlinks_followed",
        "native_consent_granted",
        "publication_signed",
        "network_published",
        "publisher_authority_granted",
        "permission_authority_granted",
        "input_files_modified",
    ] {
        if value[key].as_bool() != Some(false) {
            return Err("pack_receipt_scope");
        }
    }
    for key in [
        "hidden_entries_excluded",
        "bundle_output_created",
        "review_required",
    ] {
        if value[key].as_bool() != Some(true) {
            return Err("pack_receipt_scope");
        }
    }
    Ok(())
}

/// Validate actual persisted pack bytes against both the producer receipt and fresh ZIP inventory.
/// A preparation receipt grants no native consent, signing, publisher or network authority.
pub(super) fn verify_preparation(value: &Value, bytes: &[u8], assets: &[Value]) -> Result<()> {
    verify_preparation_scope(value)?;
    if value["bundle_sha256"] != hex::encode(Sha256::digest(bytes))
        || value["bundle_bytes"].as_u64() != u64::try_from(bytes.len()).ok()
        || value["asset_count"].as_u64() != u64::try_from(assets.len()).ok()
    {
        return Err("pack_receipt_binding");
    }
    let bundle = SiteBundle::decode(bytes.to_vec()).map_err(|_| "bundle_shape")?;
    verify_bundle_assets(&bundle, assets)?;
    let rows = value["assets"].as_array().ok_or("pack_receipt_assets")?;
    if rows.len() != assets.len() {
        return Err("pack_receipt_assets");
    }
    let mut previous = None;
    for row in rows {
        if !has_keys(row, &["path", "content_type", "bytes", "sha256"]) {
            return Err("pack_receipt_asset_shape");
        }
        let path = row["path"].as_str().ok_or("pack_receipt_asset_path")?;
        if previous.is_some_and(|last| last >= path) {
            return Err("pack_receipt_asset_order");
        }
        previous = Some(path);
        let asset = bundle.asset(path).ok_or("pack_receipt_asset_missing")?;
        if row["content_type"].as_str() != Some(asset.content_type)
            || row["bytes"].as_u64() != u64::try_from(asset.bytes.len()).ok()
            || row["sha256"] != hex::encode(Sha256::digest(asset.bytes))
        {
            return Err("pack_receipt_asset_binding");
        }
    }
    Ok(())
}

pub(super) fn reviewed_digest(sha: &[u8; 32], selected: Option<OsString>) -> Result<OsString> {
    let packed = hex::encode(sha);
    match selected {
        Some(reviewed) if reviewed == packed.as_str() => Ok(reviewed),
        Some(_) => Err("native_owner_review_digest"),
        None => Ok(packed.into()),
    }
}

pub(super) async fn publish(
    f: &Fixture,
    p: &Progress,
    packed: &Packed,
    work: Instant,
    total: Instant,
) -> Result<(Vec<u8>, VerifiedManifest)> {
    let lifetime: u64 = if super::topology::enabled()? {
        7200
    } else {
        600
    };
    let native_review = std::env::var_os("VOLPAROSSA_STUDIO_NATIVE_REVIEW_SHA256");
    let has_native_review = native_review.is_some();
    let reviewed = reviewed_digest(&packed.sha, native_review)?;
    let mut args = vec![
        "publish".into(),
        "--input".into(),
        f.path("site.bundle").into_os_string(),
        "--expected-input-sha256".into(),
        reviewed,
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
        lifetime.to_string().into(),
        "--identity".into(),
        f.path("state/identity.key").into_os_string(),
    ];
    let mode = if has_native_review {
        args.push("--review-site".into());
        Invocation::Owner(packed, lifetime)
    } else {
        args.extend([
            "--passphrase-file".into(),
            f.path("credentials/identity-passphrase").into_os_string(),
        ]);
        Invocation::Plain
    };
    limits(&mut args);
    let result = cli(f, args, p, work, total, mode).await?;
    let value = result.json()?;
    let encoded = read_private(
        &f.path("manifest.pb"),
        u64::try_from(MAX_MANIFEST_BYTES).map_err(|_| "manifest_limit")?,
    )?;
    let manifest = SignedManifest::decode(&encoded)
        .map_err(|_| "manifest_shape")?
        .verify(&f.publisher, now()?)
        .map_err(|_| "manifest_auth")?;
    let validity = manifest.validity();
    let signed_lifetime = validity.expires.checked_sub(validity.created);
    let bound_deadline = match result.approved_expiry {
        Some(expires) => {
            expires == validity.expires
                && value["terminal_reviewed_bundle_sha256"] == hex::encode(packed.sha)
                && signed_lifetime.is_some_and(|seconds| (1..=lifetime).contains(&seconds))
        }
        None => !has_native_review && signed_lifetime == Some(lifetime),
    };
    if !bound_deadline
        || manifest.length() != u64::try_from(packed.bytes.len()).map_err(|_| "bundle_length")?
        || manifest.object_sha256() != &packed.sha
        || manifest.metadata().name != NAME
        || manifest.metadata().revision != 1
        || manifest.metadata().content_type != SITE_CONTENT_TYPE
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
    if let Some(expires) = result.approved_expiry {
        println!("\nSTUDIO_NATIVE_OWNER_REVIEW {}", hex::encode(packed.sha));
        println!(
            "STUDIO_NATIVE_TERMINAL_APPROVAL {} {expires}",
            hex::encode(manifest.manifest_id())
        );
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
    let value = cli(f, args, p, work, total, Invocation::Plain)
        .await?
        .json()?;
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
    let value = cli(f, args, p, work, total, Invocation::Plain)
        .await?
        .json()?;
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
