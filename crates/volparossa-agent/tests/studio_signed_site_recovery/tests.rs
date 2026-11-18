// SPDX-License-Identifier: GPL-3.0-only
//! Bounded controls; real child processes/browser execute only in the ignored hosted case.
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use volparossa_content::site::{SiteAsset, SiteBundle};

use super::{
    Counts,
    browser::{checked_url, verify_receipt},
    process::CliResult,
    site::{Packed, verify_assets, verify_preparation},
};

fn packed() -> Packed {
    let assets = vec![
        SiteAsset {
            path: "/index.html".into(),
            content_type: "text/html".into(),
            bytes: b"<h1>Original index</h1>".to_vec(),
        },
        SiteAsset {
            path: "/studio-export.html".into(),
            content_type: "text/html".into(),
            bytes: b"<h1>VOLPAROSSA Studio manual export 20261022</h1>".to_vec(),
        },
        SiteAsset {
            path: "/style.css".into(),
            content_type: "text/css".into(),
            bytes: b"h1{font-size:37px}".to_vec(),
        },
    ];
    let inventory=assets.iter().map(|asset|json!({"path":asset.path,"bytes":asset.bytes.len(),"sha256":hex::encode(Sha256::digest(&asset.bytes))})).collect();
    let bytes = SiteBundle::encode(assets).unwrap();
    Packed {
        sha: Sha256::digest(&bytes).into(),
        bytes,
        assets: inventory,
    }
}
fn browser(p: &Packed) -> Value {
    json!({"schema":1,"status":"passed","bundle_sha256":hex::encode(p.sha),"bundle_bytes":p.bytes.len(),"asset_count":p.assets.len(),"visible_marker":true,"computed_37px":true,"all_assets_verified":true,"security_headers_preserved":true,"independent_browser":true,"browser_closed":true,"rendered_http_requests":3})
}

fn preparation(p: &Packed) -> Value {
    let bundle = SiteBundle::decode(p.bytes.clone()).unwrap();
    let mut assets = p.assets.clone();
    for row in &mut assets {
        let asset = bundle.asset(row["path"].as_str().unwrap()).unwrap();
        row["content_type"] = json!(asset.content_type);
    }
    assets.sort_unstable_by(|left, right| {
        left["path"]
            .as_str()
            .unwrap()
            .cmp(right["path"].as_str().unwrap())
    });
    json!({
        "schema_version": 1, "operation": "site_pack_preparation", "source": "explicit_local_directory",
        "content_type": volparossa_content::site::SITE_CONTENT_TYPE,
        "bundle_sha256": hex::encode(p.sha), "bundle_bytes": p.bytes.len(), "asset_count": assets.len(),
        "assets": assets, "symlinks_followed": false, "hidden_entries_excluded": true,
        "native_consent_granted": false, "publication_signed": false, "network_published": false,
        "publisher_authority_granted": false, "permission_authority_granted": false,
        "input_files_modified": false, "bundle_output_created": true, "review_required": true,
    })
}

#[test]
fn pack_preparation_requires_closed_non_authorizing_schema_and_refuses_legacy_output() {
    let p = packed();
    let value = preparation(&p);
    assert!(verify_preparation(&value, &p.bytes, &p.assets).is_ok());
    for key in value.as_object().unwrap().keys() {
        let mut changed = value.clone();
        changed.as_object_mut().unwrap().remove(key);
        assert!(verify_preparation(&changed, &p.bytes, &p.assets).is_err());
    }
    for key in ["input", "output", "private_path", "credentials"] {
        let mut changed = value.clone();
        changed[key] = json!("/private/not-a-receipt-field");
        assert!(verify_preparation(&changed, &p.bytes, &p.assets).is_err());
    }
    for key in [
        "symlinks_followed",
        "native_consent_granted",
        "publication_signed",
        "network_published",
        "publisher_authority_granted",
        "permission_authority_granted",
        "input_files_modified",
        "hidden_entries_excluded",
        "bundle_output_created",
        "review_required",
    ] {
        for bad in [
            json!(!value[key].as_bool().unwrap()),
            json!(0),
            json!("false"),
        ] {
            let mut changed = value.clone();
            changed[key] = bad;
            assert!(verify_preparation(&changed, &p.bytes, &p.assets).is_err());
        }
    }
    for (key, bad) in [
        ("schema_version", json!(true)),
        ("schema_version", json!(2)),
        ("operation", json!("site_pack")),
        ("source", json!("named_download")),
    ] {
        let mut changed = value.clone();
        changed[key] = bad;
        assert!(verify_preparation(&changed, &p.bytes, &p.assets).is_err());
    }
    let legacy = json!({
        "operation":"site_pack", "assets":p.assets.len(), "bytes":p.bytes.len(),
        "content_type":volparossa_content::site::SITE_CONTENT_TYPE, "output":"legacy.bundle",
        "network_published":false, "hidden_entries_excluded":true, "symlinks_followed":false,
    });
    assert!(verify_preparation(&legacy, &p.bytes, &p.assets).is_err());
}

#[test]
fn pack_preparation_binds_sorted_rows_mime_and_bytes_to_bundle_and_fresh_zip_inventory() {
    let p = packed();
    let value = preparation(&p);
    for (key, bad) in [
        ("bundle_sha256", json!(hex::encode([0; 32]))),
        ("bundle_bytes", json!(p.bytes.len() + 1)),
        ("bundle_bytes", json!(true)),
        ("asset_count", json!(p.assets.len() + 1)),
        ("content_type", json!("text/html")),
    ] {
        let mut changed = value.clone();
        changed[key] = bad;
        assert!(verify_preparation(&changed, &p.bytes, &p.assets).is_err());
    }
    for (key, bad) in [
        ("path", json!("/not-in-bundle")),
        ("content_type", json!("text/plain")),
        ("bytes", json!(0)),
        ("bytes", json!(true)),
        ("sha256", json!(hex::encode([0; 32]))),
        ("payload", json!("not permitted")),
    ] {
        let mut changed = value.clone();
        changed["assets"][0][key] = bad;
        assert!(verify_preparation(&changed, &p.bytes, &p.assets).is_err());
    }
    let mut changed = value.clone();
    changed["assets"].as_array_mut().unwrap().reverse();
    assert!(verify_preparation(&changed, &p.bytes, &p.assets).is_err());
    let mut changed = value.clone();
    changed["assets"][1] = changed["assets"][0].clone();
    assert!(verify_preparation(&changed, &p.bytes, &p.assets).is_err());
    let mut changed = value.clone();
    changed["assets"].as_array_mut().unwrap().pop();
    assert!(verify_preparation(&changed, &p.bytes, &p.assets).is_err());
    let mut inventory = p.assets.clone();
    inventory[0]["sha256"] = json!(hex::encode([0; 32]));
    assert!(verify_preparation(&value, &p.bytes, &inventory).is_err());
    let mut bytes = p.bytes.clone();
    *bytes.last_mut().unwrap() ^= 1;
    assert!(verify_preparation(&value, &bytes, &p.assets).is_err());
}

#[test]
fn exact_observed_counts_refuse_missing_join_and_failure_cleanup() {
    let complete = Counts {
        positive_cli_started: 6,
        positive_cli_joined: 6,
        daemon_started: 2,
        crash_joined: 1,
        graceful_joined: 1,
        negative_cli_started: 2,
        negative_cli_joined: 2,
        cli_rejections: 2,
        agent_rejections: 0,
        failure_joined: 0,
    };
    assert!(complete.complete());
    for changed in [
        Counts {
            positive_cli_joined: 5,
            ..complete
        },
        Counts {
            negative_cli_joined: 1,
            ..complete
        },
        Counts {
            crash_joined: 0,
            ..complete
        },
        Counts {
            graceful_joined: 0,
            ..complete
        },
        Counts {
            failure_joined: 1,
            ..complete
        },
        Counts {
            agent_rejections: 1,
            ..complete
        },
    ] {
        assert!(!changed.complete());
    }
    assert_eq!(
        serde_json::to_value(complete)
            .unwrap()
            .as_object()
            .unwrap()
            .len(),
        9
    );
}
#[test]
fn normal_nonzero_with_closed_reason_is_required_for_preview_denial() {
    let expected = b"local site reviewed input digest differs";
    let result = CliResult {
        success: false,
        normal_exit: true,
        stdout: vec![],
        stderr: expected.to_vec(),
    };
    assert!(result.rejection(expected).is_ok());
    for changed in [
        CliResult {
            normal_exit: false,
            ..result
        },
        CliResult {
            success: true,
            normal_exit: true,
            stdout: vec![],
            stderr: expected.to_vec(),
        },
        CliResult {
            success: false,
            normal_exit: true,
            stdout: b"ready".to_vec(),
            stderr: expected.to_vec(),
        },
        CliResult {
            success: false,
            normal_exit: true,
            stdout: vec![],
            stderr: b"other failure".to_vec(),
        },
    ] {
        assert!(changed.rejection(expected).is_err());
    }
}
#[test]
fn preview_origin_allows_only_canonical_random_localhost_and_nonzero_port() {
    let host = "vp0123456789abcdef0123456789abcdef.localhost";
    assert_eq!(checked_url(&format!("http://{host}:1234/")), Ok(1234));
    for url in [
        format!("https://{host}:1234/"),
        format!("http://{host}:0/"),
        format!("http://{host}:01234/"),
        format!("http://{host}:1234/studio-export.html"),
        format!("http://{host}:1234/?private"),
        format!("http://user@{host}:1234/"),
        "http://127.0.0.1:1234/".into(),
        "http://vpBAD.localhost:1234/".into(),
    ] {
        assert!(checked_url(&url).is_err());
    }
}
#[test]
fn full_zip_inventory_requires_every_unique_unchanged_asset_and_actual_edited_page() {
    let p = packed();
    assert!(verify_assets(&p.bytes, &p.assets).is_ok());
    let mut inventory = p.assets.clone();
    inventory[0]["sha256"] = json!(hex::encode([0; 32]));
    assert!(verify_assets(&p.bytes, &inventory).is_err());
    assert!(verify_assets(&p.bytes, &p.assets[..2]).is_err());
    let mut inventory = p.assets.clone();
    inventory[1] = inventory[0].clone();
    assert!(verify_assets(&p.bytes, &inventory).is_err());
    let mut changed = p.bytes.clone();
    *changed.last_mut().unwrap() ^= 1;
    assert!(verify_assets(&changed, &p.assets).is_err());
}
#[test]
fn browser_receipt_binds_hash_length_assets_and_preserves_all_six_observations() {
    let p = packed();
    let value = browser(&p);
    assert!(verify_receipt(&value, &p).is_ok());
    for key in [
        "visible_marker",
        "computed_37px",
        "all_assets_verified",
        "security_headers_preserved",
        "independent_browser",
        "browser_closed",
    ] {
        let mut changed = value.clone();
        changed[key] = json!(false);
        assert!(verify_receipt(&changed, &p).is_err());
    }
    for (key, bad) in [
        ("bundle_sha256", json!(hex::encode([0; 32]))),
        ("bundle_bytes", json!(p.bytes.len() + 1)),
        ("asset_count", json!(p.assets.len() + 1)),
        ("rendered_http_requests", json!(0)),
        ("rendered_http_requests", json!(1025)),
        ("schema", json!(true)),
    ] {
        let mut changed = value.clone();
        changed[key] = bad;
        assert!(verify_receipt(&changed, &p).is_err());
    }
}
#[test]
fn browser_receipt_rejects_extra_private_fields_and_missing_required_flags() {
    let p = packed();
    let mut value = browser(&p);
    value["private_path"] = json!("/private/value");
    assert!(verify_receipt(&value, &p).is_err());
    let mut value = browser(&p);
    value.as_object_mut().unwrap().remove("browser_closed");
    assert!(verify_receipt(&value, &p).is_err());
}

#[test]
fn public_inventory_profile_never_widens_private_receipt_or_signing_input_reads() {
    use super::fixture::{private_file, read_inventory, read_private};
    use std::{
        fs,
        os::unix::fs::{PermissionsExt, symlink},
    };
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("public-inventory");
    private_file(&path, b"{\"schema\":1}").unwrap();
    assert!(read_inventory(&path).is_ok());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_inventory(&path).is_ok());
    assert!(read_private(&path, 128 * 1024).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o666)).unwrap();
    assert!(read_inventory(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    let link = root.path().join("alias");
    fs::hard_link(&path, &link).unwrap();
    assert!(read_inventory(&path).is_err());
    fs::remove_file(&link).unwrap();
    symlink(&path, &link).unwrap();
    assert!(read_inventory(&link).is_err());
    fs::OpenOptions::new()
        .write(true)
        .open(&path)
        .unwrap()
        .set_len(128 * 1024 + 1)
        .unwrap();
    assert!(read_inventory(&path).is_err());
}
