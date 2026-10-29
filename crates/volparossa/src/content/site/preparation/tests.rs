// SPDX-License-Identifier: GPL-3.0-only
use std::{
    collections::BTreeSet,
    fs,
    os::unix::fs::{PermissionsExt as _, symlink},
};

use clap::Parser as _;

use super::*;
use crate::content::site::{Command, Pack, pack};

fn fixture() -> (tempfile::TempDir, Pack) {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("private-source-location");
    fs::create_dir(&directory).unwrap();
    fs::create_dir(directory.join("assets")).unwrap();
    fs::write(directory.join("index.html"), b"<h1>public example</h1>").unwrap();
    fs::write(directory.join("assets/z.css"), b"h1{color:red}").unwrap();
    fs::write(directory.join(".env"), b"PRIVATE_NOT_SELECTED").unwrap();
    let args = Pack {
        directory,
        output: root.path().join("private-output-location.vps"),
        review_receipt: true,
    };
    (root, args)
}

fn keys(value: &Value) -> BTreeSet<&str> {
    value
        .as_object()
        .unwrap()
        .keys()
        .map(String::as_str)
        .collect()
}

#[test]
fn preparation_matches_persisted_bundle_and_exact_canonical_asset_snapshots() {
    let (_root, args) = fixture();
    let receipt = pack(&args).unwrap();
    let bytes = fs::read(&args.output).unwrap();
    assert_eq!(
        receipt["bundle_sha256"],
        hex::encode(Sha256::digest(&bytes))
    );
    assert_eq!(receipt["bundle_bytes"], bytes.len());
    let bundle = SiteBundle::decode(bytes).unwrap();
    let rows = receipt["assets"].as_array().unwrap();
    assert_eq!(receipt["asset_count"], bundle.asset_count());
    let paths: Vec<_> = rows
        .iter()
        .map(|row| row["path"].as_str().unwrap())
        .collect();
    assert_eq!(paths, ["/assets/z.css", "/index.html"]);
    for row in rows {
        assert_eq!(
            keys(row),
            BTreeSet::from(["path", "content_type", "bytes", "sha256"])
        );
        let asset = bundle.asset(row["path"].as_str().unwrap()).unwrap();
        assert_eq!(row["content_type"], asset.content_type);
        assert_eq!(row["bytes"], asset.bytes.len());
        assert_eq!(row["sha256"], hex::encode(Sha256::digest(asset.bytes)));
    }
    assert_eq!(
        fs::read(args.directory.join("index.html")).unwrap(),
        b"<h1>public example</h1>"
    );
    assert_eq!(
        fs::read(args.directory.join(".env")).unwrap(),
        b"PRIVATE_NOT_SELECTED"
    );
    assert_eq!(
        fs::metadata(&args.output).unwrap().permissions().mode() & 0o777,
        0o600
    );
}

#[test]
fn preparation_receipt_closes_scope_and_omits_source_paths_and_payloads() {
    let (root, args) = fixture();
    let receipt = pack(&args).unwrap();
    assert_eq!(
        keys(&receipt),
        BTreeSet::from([
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
        ])
    );
    assert_eq!(receipt["schema_version"].as_u64(), Some(1));
    assert_eq!(receipt["operation"], "site_pack_preparation");
    assert_eq!(receipt["source"], "explicit_local_directory");
    assert_eq!(receipt["content_type"], SITE_CONTENT_TYPE);
    for key in [
        "symlinks_followed",
        "native_consent_granted",
        "publication_signed",
        "network_published",
        "publisher_authority_granted",
        "permission_authority_granted",
        "input_files_modified",
    ] {
        assert_eq!(receipt[key].as_bool(), Some(false));
    }
    for key in [
        "hidden_entries_excluded",
        "bundle_output_created",
        "review_required",
    ] {
        assert_eq!(receipt[key].as_bool(), Some(true));
    }
    let serialized = serde_json::to_vec(&receipt).unwrap();
    assert!(serialized.len() <= MAX_RECEIPT_BYTES);
    let text = String::from_utf8(serialized).unwrap();
    for forbidden in [
        root.path().to_str().unwrap(),
        "private-source-location",
        "private-output-location",
        ".env",
        "PRIVATE_NOT_SELECTED",
        "<h1>public example</h1>",
    ] {
        assert!(!text.contains(forbidden));
    }
}

#[test]
fn later_source_mutation_changes_only_the_new_preparation_bindings() {
    let (_root, mut args) = fixture();
    let first = pack(&args).unwrap();
    let first_bundle = fs::read(&args.output).unwrap();
    fs::write(args.directory.join("assets/z.css"), b"h1{color:tan}").unwrap();
    args.output.set_file_name("second.vps");
    let second = pack(&args).unwrap();
    assert_ne!(first["bundle_sha256"], second["bundle_sha256"]);
    assert_ne!(first["assets"][0]["sha256"], second["assets"][0]["sha256"]);
    assert_eq!(first["assets"][1], second["assets"][1]);
    assert_eq!(first["bundle_bytes"], second["bundle_bytes"]);
    let original = SiteBundle::decode(first_bundle).unwrap();
    assert_eq!(
        original.asset("/assets/z.css").unwrap().bytes,
        b"h1{color:red}"
    );
    let retained = fs::read(&args.output).unwrap();
    assert!(pack(&args).is_err());
    assert_eq!(fs::read(&args.output).unwrap(), retained);
}

#[test]
fn cli_opt_in_preserves_the_complete_legacy_default_report() {
    let (_root, mut args) = fixture();
    for (extra, expected) in [(None, false), (Some("--review-receipt"), true)] {
        let parsed = crate::Cli::try_parse_from(
            [
                "volparossa",
                "content",
                "site",
                "pack",
                "--directory",
                "source",
                "--output",
                "new.vps",
            ]
            .into_iter()
            .chain(extra),
        )
        .unwrap();
        let crate::CliCommand::Content { command } = parsed.command else {
            panic!("content expected")
        };
        let crate::content::Command::Site(Command::Pack(pack)) = *command else {
            panic!("pack expected")
        };
        assert_eq!(pack.review_receipt, expected);
    }
    args.review_receipt = false;
    let report = pack(&args).unwrap();
    assert_eq!(
        report,
        json!({
            "operation": "site_pack", "assets": 2, "bytes": fs::metadata(&args.output).unwrap().len(),
            "content_type": SITE_CONTENT_TYPE, "output": args.output,
            "network_published": false, "hidden_entries_excluded": true, "symlinks_followed": false,
        })
    );
}

#[test]
fn json_escaping_bound_rejects_valid_large_inventory_before_output_effects() {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("site");
    fs::create_dir(&directory).unwrap();
    fs::write(directory.join("index.html"), b"public").unwrap();
    let mut nested = directory.clone();
    for _ in 0..3 {
        nested.push("\"".repeat(240));
        fs::create_dir(&nested).unwrap();
    }
    for index in 0..255 {
        fs::write(nested.join(format!("{}{index:03}", "\"".repeat(244))), b"").unwrap();
    }
    let mut args = Pack {
        directory,
        output: root.path().join("reference.vps"),
        review_receipt: false,
    };
    pack(&args).unwrap();
    let reference = fs::read(&args.output).unwrap();
    assert_eq!(
        SiteBundle::decode(reference.clone()).unwrap().asset_count(),
        256
    );
    args.review_receipt = true;
    args.output.set_file_name("must-not-exist.vps");
    let entries_before = fs::read_dir(root.path()).unwrap().count();
    let error = pack(&args).unwrap_err();
    assert_eq!(
        error.to_string(),
        "site preparation receipt exceeds 512 KiB"
    );
    assert!(!args.output.exists());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), entries_before);
    assert_eq!(
        fs::read(root.path().join("reference.vps")).unwrap(),
        reference
    );
}

#[test]
fn review_mode_retains_symlink_and_invalid_bundle_refusal_before_output() {
    let (root, args) = fixture();
    let target = root.path().join("outside");
    fs::write(&target, b"not selected").unwrap();
    let link = args.directory.join("linked.txt");
    symlink(target, &link).unwrap();
    assert!(pack(&args).is_err());
    assert!(!args.output.exists());
    fs::remove_file(link).unwrap();
    fs::remove_file(args.directory.join("index.html")).unwrap();
    assert!(pack(&args).is_err());
    assert!(!args.output.exists());
}
