// SPDX-License-Identifier: GPL-3.0-only
//! Offline, normal CLI publication and restore of two ordinary static site directories.
use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Output},
    time::{SystemTime, UNIX_EPOCH},
};

use serde_json::Value;
use sha2::{Digest as _, Sha256};
use volparossa_content::{
    CacheLimits, ChunkStore,
    site::{SITE_CONTENT_TYPE, SiteBundle},
};
use volparossa_identity::{IdentityStore, Passphrase};

const SITE: &str = "public-editions";

fn command(root: &Path, args: &[&str]) -> Command {
    let mut command = Command::new(env!("CARGO_BIN_EXE_volparossa"));
    command
        .current_dir(root)
        .env_clear()
        .env("HOME", root)
        .args(["--control-socket", "absent.sock", "content"])
        .args(args);
    command
}

fn success(output: &Output) -> Value {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("CLI JSON receipt")
}

fn pack(root: &Path, directory: &str, destination: &str, html: &[u8]) -> String {
    let source = root.join(directory);
    fs::create_dir(&source).unwrap();
    fs::write(source.join("index.html"), html).unwrap();
    fs::write(source.join("style.css"), b"h1 { color: teal }").unwrap();
    let report = success(
        &command(
            root,
            &[
                "site",
                "pack",
                "--directory",
                directory,
                "--output",
                destination,
                "--review-receipt",
            ],
        )
        .output()
        .unwrap(),
    );
    assert_eq!(report["operation"], "site_pack_preparation");
    assert_eq!(report["asset_count"], 2);
    let digest = hex::encode(Sha256::digest(fs::read(root.join(destination)).unwrap()));
    assert_eq!(report["bundle_sha256"], digest);
    digest
}

fn publish(
    root: &Path,
    key: &str,
    bundle: &str,
    digest: &str,
    manifest: &str,
    revision: &str,
) -> String {
    let mut cli = command(
        root,
        &[
            "publish",
            "--input",
            bundle,
            "--expected-input-sha256",
            digest,
            "--cache",
            "owner-cache",
            "--manifest",
            manifest,
            "--name",
            SITE,
            "--revision",
            revision,
            "--content-type",
            SITE_CONTENT_TYPE,
            "--identity",
            "identity.key",
            "--passphrase-file",
            "passphrase",
            "--expected-publisher-key",
            key,
            "--min-free-bytes",
            "0",
        ],
    );
    if revision != "1" {
        cli.arg("--reuse-cache");
    }
    let report = success(&cli.output().unwrap());
    assert_eq!(report["operation"], "offline_content_publish");
    assert_eq!(report["network_publication"], false);
    assert_eq!(report["publisher_key_hex"], key);
    let id = hex::encode(Sha256::digest(fs::read(root.join(manifest)).unwrap()));
    assert_eq!(report["manifest_id"], id);
    id
}

#[test]
fn publisher_restores_previous_site_bytes_as_a_new_local_revision() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let password = b"public synthetic site restore test passphrase";
    fs::write(root.join("passphrase"), password).unwrap();
    fs::set_permissions(root.join("passphrase"), fs::Permissions::from_mode(0o600)).unwrap();
    let identity = IdentityStore::new(root.join("identity.key"))
        .create(&Passphrase::new(password).unwrap())
        .unwrap();
    let key = identity.ed25519_public_key_bytes().unwrap();
    let key_hex = hex::encode(key);
    drop(identity);

    let first_html = b"<link rel='stylesheet' href='style.css'><h1>First edition</h1>";
    let second_html = b"<link rel='stylesheet' href='style.css'><h1>New edition</h1>";
    let first_sha = pack(root, "first", "first.vps", first_html);
    let second_sha = pack(root, "second", "second.vps", second_html);
    assert_ne!(first_sha, second_sha);
    let original = publish(root, &key_hex, "first.vps", &first_sha, "1.pb", "1");
    let previous = publish(root, &key_hex, "second.vps", &second_sha, "2.pb", "2");
    let candidate = publish(root, &key_hex, "first.vps", &first_sha, "3.pb", "3");
    let competing = publish(root, &key_hex, "first.vps", &first_sha, "other-3.pb", "3");
    assert_ne!(candidate, competing);
    fs::remove_file(root.join("identity.key")).unwrap();
    fs::remove_file(root.join("passphrase")).unwrap();

    let restore = |path: &str, id: &str| {
        command(
            root,
            &[
                "site",
                "restore",
                "--cache",
                "owner-cache",
                "--publisher-key",
                &key_hex,
                "--name",
                SITE,
                "--source-manifest",
                "1.pb",
                "--expected-source-id",
                &original,
                "--current-manifest",
                "2.pb",
                "--expected-current-id",
                &previous,
                "--candidate-manifest",
                path,
                "--expected-candidate-id",
                id,
                "--min-free-bytes",
                "0",
            ],
        )
    };

    let missing_head = restore("3.pb", &candidate).output().unwrap();
    assert!(!missing_head.status.success());
    let activated = success(
        &restore("3.pb", &candidate)
            .arg("--initialize-from-reviewed-current")
            .output()
            .unwrap(),
    );
    assert_eq!(activated["operation"], "local_site_restore");
    assert_eq!(activated["state"], "activated");
    assert_eq!(activated["source_manifest_id"], original);
    assert_eq!(activated["previous_manifest_id"], previous);
    assert_eq!(activated["manifest_id"], candidate);
    assert_eq!(activated["revision"], 3);
    assert_eq!(activated["bundle_sha256"], first_sha);
    assert_eq!(activated["network_publication"], false);

    let repeated = success(&restore("3.pb", &candidate).output().unwrap());
    assert_eq!(repeated["state"], "already_current");
    assert_eq!(repeated["manifest_id"], candidate);
    let conflict = restore("other-3.pb", &competing).output().unwrap();
    assert!(!conflict.status.success());
    assert!(String::from_utf8_lossy(&conflict.stderr).contains("retained site revision differs"));

    assert_contribution_rejects_original(root, &key_hex, &candidate);
    assert_restored_site(root, &key, &candidate, first_html);
}

fn assert_contribution_rejects_original(root: &Path, key: &str, candidate: &str) {
    // Both releases authorize identical bytes under the same name and publisher.
    let wrong_release = command(
        root,
        &[
            "contribute",
            "--manifest",
            "1.pb",
            "--publisher-key",
            key,
            "--expected-manifest-id",
            candidate,
            "--input",
            "first.vps",
        ],
    )
    .output()
    .unwrap();
    assert!(!wrong_release.status.success());
    assert!(String::from_utf8_lossy(&wrong_release.stderr).contains("pinned manifest identity"));
}

fn assert_restored_site(root: &Path, key: &[u8; 32], candidate: &str, first_html: &[u8]) {
    // Read the retained name record independently, so assembly cannot silently use an
    // unrelated signed manifest passed by the test or an older cached website.
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let cache = ChunkStore::open(
        &root.join("owner-cache"),
        CacheLimits {
            max_bytes: 1_048_576,
            max_entries: 8,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let head = cache.name_revision_floor(key, SITE).unwrap().unwrap();
    assert_eq!(head.revision(), 3);
    assert_eq!(hex::encode(head.manifest_id()), candidate);
    assert!(!head.conflicted());
    let retained = cache
        .cached_named_manifest(key, SITE, 3, now)
        .unwrap()
        .unwrap();
    assert_eq!(retained.encode(), fs::read(root.join("3.pb")).unwrap());
    fs::write(root.join("retained.pb"), retained.encode()).unwrap();
    drop(cache);

    let assembled = success(
        &command(
            root,
            &[
                "assemble",
                "--manifest",
                "retained.pb",
                "--publisher-key",
                &hex::encode(key),
                "--cache",
                "owner-cache",
                "--output",
                "restored.vps",
                "--min-free-bytes",
                "0",
            ],
        )
        .output()
        .unwrap(),
    );
    assert_eq!(assembled["operation"], "offline_content_assemble");
    let restored = fs::read(root.join("restored.vps")).unwrap();
    assert_eq!(restored, fs::read(root.join("first.vps")).unwrap());
    let site = SiteBundle::decode(restored).unwrap();
    assert_eq!(site.asset("/index.html").unwrap().bytes, first_html);
    assert!(!root.join("absent.sock").exists());
}

#[test]
fn independent_terminal_reviews_and_signs_the_displayed_site_snapshot() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let identity = IdentityStore::new(root.join("identity.key"))
        .create(&Passphrase::new("owner-review-fixture-password").unwrap())
        .unwrap();
    let key = identity.ed25519_public_key_bytes().unwrap();
    let digest = pack(root, "first", "tested.vps", b"<h1>Reviewed page</h1>");
    let status = Command::new("python3")
        .current_dir(root)
        .args([
            "-I",
            "-B",
            "-c",
            include_str!("studio_site_restore/owner_review.py"),
            env!("CARGO_BIN_EXE_volparossa"),
            &hex::encode(key),
            &digest,
        ])
        .status()
        .unwrap();
    assert!(status.success());
    let signed = volparossa_content::SignedManifest::decode(
        &fs::read(root.join("reviewed.manifest")).unwrap(),
    )
    .unwrap();
    let publisher = ed25519_dalek::VerifyingKey::from_bytes(&key).unwrap();
    let verified = signed
        .verify(
            &publisher,
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs(),
        )
        .unwrap();
    assert_eq!(hex::encode(verified.object_sha256()), digest);
    assert_eq!(verified.metadata().revision, 5);
    assert_eq!(verified.metadata().name, "site-review-fixture");
    assert_eq!(verified.metadata().content_type, SITE_CONTENT_TYPE);
}
