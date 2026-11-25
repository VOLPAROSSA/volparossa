// SPDX-License-Identifier: GPL-3.0-only
//! Exercise the public reader through the regular CLI in a separate empty directory.
use super::SITE;
use super::{command, success};
use std::{
    fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};
use volparossa_content::{
    CacheLimits, ChunkStore, Metadata, Publication, Validity, site::SITE_CONTENT_TYPE,
};

pub(super) fn check(root: &Path, key: &str, bundle: &str, source: &str, candidate: &str) {
    // This reader only receives signed envelopes. Its HOME and control socket are empty.
    let public = root.join("public-manifests");
    fs::create_dir(&public).unwrap();
    for path in ["1.pb", "3.pb"] {
        fs::copy(root.join(path), public.join(path)).unwrap();
    }
    let inspect = |file: &str, publisher: &str| {
        command(
            &public,
            &[
                "site",
                "inspect",
                "--manifest",
                file,
                "--publisher-key",
                publisher,
            ],
        )
    };
    for (file, revision, pin) in [("1.pb", 1, source), ("3.pb", 3, candidate)] {
        let input = fs::read(public.join(file)).unwrap();
        let signed = volparossa_content::SignedManifest::decode(&input).unwrap();
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let publisher =
            ed25519_dalek::VerifyingKey::from_bytes(&hex::decode(key).unwrap().try_into().unwrap())
                .unwrap();
        let verified = signed.verify(&publisher, now).unwrap();
        let result = success(
            &inspect(file, key)
                .args(["--expected-manifest-id", pin])
                .output()
                .unwrap(),
        );
        assert_eq!(
            result,
            serde_json::json!({
                "schema_version": 1, "operation": "offline_site_inspect", "publisher_key": key,
                "name": SITE, "revision": revision, "content_type": SITE_CONTENT_TYPE, "manifest_id": pin,
                "bundle_sha256": bundle, "bundle_bytes": verified.length(), "chunks": verified.chunks().len(),
                "created_unix_seconds": verified.validity().created, "expires_unix_seconds": verified.validity().expires,
                "bundle_bytes_verified": false, "network_retrieval": false,
            })
        );
        assert_eq!(success(&inspect(file, key).output().unwrap()), result);
    }
    let other = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[7; 32])
            .verifying_key()
            .to_bytes(),
    );
    let mut tampered = fs::read(public.join("1.pb")).unwrap();
    *tampered.last_mut().unwrap() ^= 1;
    fs::write(public.join("tampered.pb"), tampered).unwrap();
    for rejected in [
        inspect("3.pb", key)
            .args(["--expected-manifest-id", source])
            .output()
            .unwrap(),
        inspect("1.pb", &other).output().unwrap(),
        inspect("tampered.pb", key).output().unwrap(),
    ] {
        assert!(!rejected.status.success() && rejected.stdout.is_empty());
    }
    assert_eq!(fs::read_dir(public).unwrap().count(), 3);
}

#[test]
fn current_time_and_native_site_type_are_checked_before_reporting() {
    let root = tempfile::tempdir().unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[19; 32]);
    let public = hex::encode(key.verifying_key().to_bytes());
    let mut cache = ChunkStore::open(
        &root.path().join("test-store"),
        CacheLimits {
            max_bytes: 4096,
            max_entries: 4,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    for (content_type, created, expires) in [
        ("application/octet-stream", now - 10, now + 600),
        (SITE_CONTENT_TYPE, now - 100, now - 50),
        (SITE_CONTENT_TYPE, now + 300, now + 600),
    ] {
        let manifest = volparossa_content::publish(
            &mut &b"x"[..],
            Publication {
                metadata: Metadata {
                    name: SITE.into(),
                    revision: 1,
                    content_type: content_type.into(),
                },
                length: 1,
                validity: Validity { created, expires },
            },
            &key,
            &mut cache,
        )
        .unwrap();
        fs::write(root.path().join("site.pb"), manifest.encode()).unwrap();
        let output = command(
            root.path(),
            &[
                "site",
                "inspect",
                "--manifest",
                "site.pb",
                "--publisher-key",
                &public,
            ],
        )
        .output()
        .unwrap();
        assert!(!output.status.success() && output.stdout.is_empty());
    }
}
