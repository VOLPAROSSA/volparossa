// SPDX-License-Identifier: GPL-3.0-only
//! Real Silex ZIP output is supplied only by the opt-in hosted browser fixture.
//! Ephemeral local signing/viewing proves neither provider discovery nor network publication.

#[path = "studio_site_pack/viewer.rs"]
mod viewer;

use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
};

use sha2::{Digest as _, Sha256};
use volparossa_content::site::{SITE_CONTENT_TYPE, SiteBundle};

#[test]
#[ignore = "requires the real pinned Silex browser/export hosted fixture"]
fn actual_silex_export_packs_and_decodes_without_publication() {
    viewer::diagnostic(viewer::Stage::Pack);
    let directory = PathBuf::from(
        std::env::var_os("VOLPAROSSA_STUDIO_EXPORT_DIRECTORY")
            .expect("explicit real DownloadConnector extraction directory"),
    );
    let inventory = PathBuf::from(
        std::env::var_os("VOLPAROSSA_STUDIO_EXPORT_INVENTORY")
            .expect("explicit inventory of the actual ZIP extraction"),
    );
    let metadata = fs::symlink_metadata(&inventory).expect("inventory metadata");
    assert!(metadata.is_file() && metadata.len() <= 128 * 1024);
    let inventory: serde_json::Value =
        serde_json::from_slice(&fs::read(inventory).expect("inventory")).expect("inventory JSON");
    assert_eq!(inventory["schema"], 1);
    let assets = inventory["assets"].as_array().expect("asset inventory");
    assert!((2..=256).contains(&assets.len()));
    let temporary = tempfile::tempdir().expect("private output directory");
    let output = temporary.path().join("site.bundle");
    let result = Command::new(env!("CARGO_BIN_EXE_volparossa"))
        .args(["content", "site", "pack", "--directory"])
        .arg(&directory)
        .arg("--output")
        .arg(&output)
        .output()
        .expect("actual Core site pack process");
    assert!(result.status.success(), "real CLI pack failed");
    assert!(result.stdout.len() <= 4096 && result.stderr.len() <= 4096);
    let report: serde_json::Value =
        serde_json::from_slice(&result.stdout).expect("CLI JSON receipt");
    assert_eq!(report["operation"], "site_pack");
    assert_eq!(report["network_published"], false);
    assert_eq!(report["content_type"], SITE_CONTENT_TYPE);
    assert_eq!(report["symlinks_followed"], false);
    assert_eq!(report["assets"].as_u64(), Some(assets.len() as u64));
    let bytes = fs::read(&output).expect("actual packed bytes");
    assert_eq!(report["bytes"].as_u64(), Some(bytes.len() as u64));
    viewer::diagnostic(viewer::Stage::Decode);
    let bundle =
        SiteBundle::decode(bytes.clone()).expect("production canonical SiteBundle decoder");
    assert_eq!(bundle.asset_count(), assets.len());
    assert_eq!(
        bundle
            .asset("/index.html")
            .expect("entry point")
            .content_type,
        "text/html"
    );
    let mut edited_html = false;
    let mut edited_style = false;
    let mut stylesheets = 0;
    for expected in assets {
        let path = expected["path"].as_str().expect("actual ZIP path");
        let asset = bundle.asset(path).expect("every extracted asset packed");
        assert_eq!(expected["bytes"].as_u64(), Some(asset.bytes.len() as u64));
        assert_eq!(
            expected["sha256"].as_str(),
            Some(hex::encode(Sha256::digest(asset.bytes)).as_str())
        );
        if Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("html"))
        {
            assert_eq!(asset.content_type, "text/html");
            edited_html |= String::from_utf8_lossy(asset.bytes)
                .contains("VOLPAROSSA Studio manual export 20261022");
        }
        if Path::new(path)
            .extension()
            .is_some_and(|extension| extension.eq_ignore_ascii_case("css"))
        {
            assert_eq!(asset.content_type, "text/css");
            stylesheets += 1;
            edited_style |= String::from_utf8_lossy(asset.bytes).contains("37px");
        }
    }
    assert!(edited_html && edited_style && stylesheets > 0);
    // No-clobber remains an actual CLI property at the adapter boundary.
    let retry = Command::new(env!("CARGO_BIN_EXE_volparossa"))
        .args(["content", "site", "pack", "--directory"])
        .arg(&directory)
        .arg("--output")
        .arg(&output)
        .output()
        .expect("repeat CLI pack process");
    assert!(!retry.status.success());
    let viewer = viewer::verify(&bytes, assets);
    println!(
        "STUDIO_SITE_PACK_PROOF {}",
        serde_json::json!({"schema":2,"status":"passed","actual_cli_pack":true,
            "production_site_bundle_decoded":true,"all_zip_assets_verified":true,
            "edited_html_verified":true,"edited_css_verified":true,"no_clobber_verified":true,
            "content_type":SITE_CONTENT_TYPE,"asset_count":assets.len(),
            "network_published":false,"signing_authority_exercised":false,
            "ephemeral_fixture_signing":true,"local_viewer":viewer})
    );
}
