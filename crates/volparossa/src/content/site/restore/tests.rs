// SPDX-License-Identifier: GPL-3.0-only
use std::{fs, os::unix::fs::PermissionsExt, path::Path};

use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use volparossa_content::{
    ChunkStore, Error, Metadata, Publication, SignedManifest, Validity, publish, reassemble,
    site::{SITE_CONTENT_TYPE, SiteAsset, SiteBundle},
};

use super::{Restore, activate, activate_with_clock};
use crate::content::Limits;

const NOW: u64 = 1_000;
const NAME: &str = "studio-site";

fn site(html: &[u8]) -> Vec<u8> {
    SiteBundle::encode(vec![SiteAsset {
        path: "/index.html".into(),
        content_type: "text/html".into(),
        bytes: html.to_vec(),
    }])
    .unwrap()
}

fn limits() -> Limits {
    Limits {
        quota_bytes: 1_048_576,
        max_entries: 8,
        min_free_bytes: 0,
    }
}

fn publish_site(
    store: &mut ChunkStore,
    signer: &SigningKey,
    revision: u64,
    bytes: &[u8],
) -> SignedManifest {
    publish(
        &mut &*bytes,
        Publication {
            metadata: Metadata {
                name: NAME.into(),
                revision,
                content_type: SITE_CONTENT_TYPE.into(),
            },
            length: bytes.len() as u64,
            validity: Validity {
                created: NOW - 1,
                expires: NOW + 600,
            },
        },
        signer,
        store,
    )
    .unwrap()
}

fn write_manifest(path: &Path, signed: &SignedManifest) -> [u8; 32] {
    let bytes = signed.encode();
    fs::write(path, &bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    Sha256::digest(bytes).into()
}

struct Fixture {
    directory: tempfile::TempDir,
    args: Restore,
    source: Vec<u8>,
    current: Vec<u8>,
    current_envelope: SignedManifest,
    candidate: SignedManifest,
    owner: SigningKey,
}

impl Fixture {
    fn new(retain_source: bool) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let cache = directory.path().join("owned");
        let mut release_store =
            ChunkStore::create(&cache, limits().cache_limits().unwrap()).unwrap();
        let mut signing_cache = ChunkStore::create(
            &directory.path().join("signing-cache"),
            limits().cache_limits().unwrap(),
        )
        .unwrap();
        let owner = SigningKey::from_bytes(&[21; 32]);
        let publisher_key = owner.verifying_key();
        let source = site(b"<h1>First edition</h1>");
        let current = site(b"<h1>Revised edition</h1>");
        let original = publish_site(&mut signing_cache, &owner, 1, &source);
        let current_envelope = publish_site(&mut release_store, &owner, 2, &current);
        let candidate = publish_site(&mut signing_cache, &owner, 3, &source);
        if retain_source {
            release_store.put(&source).unwrap();
            release_store
                .remember_named_manifest(&original, &publisher_key, NOW)
                .unwrap();
        }
        release_store
            .remember_named_manifest(&current_envelope, &publisher_key, NOW)
            .unwrap();

        let source_manifest = directory.path().join("v1.pb");
        let current_manifest = directory.path().join("v2.pb");
        let candidate_manifest = directory.path().join("v3.pb");
        let args = Restore {
            publisher_key,
            name: NAME.into(),
            expected_source_id: write_manifest(&source_manifest, &original),
            expected_current_id: write_manifest(&current_manifest, &current_envelope),
            expected_candidate_id: write_manifest(&candidate_manifest, &candidate),
            initialize_from_reviewed_current: false,
            source_manifest,
            current_manifest,
            candidate_manifest,
            cache,
            limits: limits(),
        };
        Self {
            directory,
            args,
            source,
            current,
            current_envelope,
            candidate,
            owner,
        }
    }

    fn open(&self) -> ChunkStore {
        ChunkStore::open(&self.args.cache, limits().cache_limits().unwrap()).unwrap()
    }

    fn sign_variant(&self, revision: u64, bytes: &[u8]) -> SignedManifest {
        let mut signing_cache = ChunkStore::open(
            &self.directory.path().join("signing-cache"),
            limits().cache_limits().unwrap(),
        )
        .unwrap();
        publish_site(&mut signing_cache, &self.owner, revision, bytes)
    }

    fn assert_current(&self, revision: u64, bytes: &[u8], expected_id: &[u8; 32]) {
        let mut reopened = self.open();
        let key = self.owner.verifying_key();
        let pin = reopened
            .name_revision_floor(key.as_bytes(), NAME)
            .unwrap()
            .unwrap();
        assert_eq!(pin.revision(), revision);
        assert_eq!(pin.manifest_id(), expected_id);
        assert!(!pin.conflicted());
        let retained = reopened
            .cached_named_manifest(key.as_bytes(), NAME, revision, NOW)
            .unwrap()
            .unwrap();
        let checked = retained.verify(&key, NOW).unwrap();
        let mut reconstructed = Vec::new();
        reassemble(&checked, &mut [&mut reopened], NOW, &mut reconstructed).unwrap();
        assert_eq!(reconstructed, bytes);
    }
}

#[test]
fn exact_owner_signed_successor_restores_original_site_and_replays_without_advancing_again() {
    let f = Fixture::new(true);
    let usage = f.open().usage();
    let report = activate(&f.args, NOW).unwrap();
    assert_eq!(report["operation"], "local_site_restore");
    assert_eq!(report["state"], "activated");
    assert_eq!(report["source_revision"], 1);
    assert_eq!(report["previous_revision"], 2);
    assert_eq!(report["revision"], 3);
    assert_eq!(
        report["source_manifest_id"],
        hex::encode(f.args.expected_source_id)
    );
    assert_eq!(
        report["previous_manifest_id"],
        hex::encode(f.args.expected_current_id)
    );
    assert_eq!(
        report["manifest_id"],
        hex::encode(f.args.expected_candidate_id)
    );
    assert_eq!(
        report["bundle_sha256"],
        hex::encode(Sha256::digest(&f.source))
    );
    assert_eq!(report["network_publication"], false);
    assert_eq!(report["globally_latest"], false);
    f.assert_current(3, &f.source, &f.args.expected_candidate_id);

    let replay = activate(&f.args, NOW + 1).unwrap();
    assert_eq!(replay["state"], "already_current");
    assert_eq!(replay["manifest_id"], report["manifest_id"]);
    let mut cache = f.open();
    assert_eq!(cache.usage().bytes, usage.bytes);
    assert_eq!(cache.usage().entries, usage.entries);
    assert!(matches!(
        cache.remember_named_manifest(&f.current_envelope, &f.args.publisher_key, NOW + 1),
        Err(Error::NameRollback)
    ));
    assert_eq!(
        fs::read(&f.args.candidate_manifest).unwrap(),
        f.candidate.encode()
    );
}

#[test]
fn wrong_owner_name_or_selected_envelope_is_rejected_before_local_activation() {
    for field in ["key", "name", "source", "current", "candidate"] {
        let mut f = Fixture::new(true);
        let head = f.args.expected_current_id;
        match field {
            "key" => f.args.publisher_key = SigningKey::from_bytes(&[9; 32]).verifying_key(),
            "name" => f.args.name = "another-site".into(),
            "source" => f.args.expected_source_id[0] ^= 1,
            "current" => f.args.expected_current_id[0] ^= 1,
            _ => f.args.expected_candidate_id[0] ^= 1,
        }
        assert!(
            activate(&f.args, NOW).is_err(),
            "accepted mismatched {field}"
        );
        f.assert_current(2, &f.current, &head);
    }
}

#[test]
fn candidate_must_restore_the_selected_site_bytes_at_the_immediate_successor_revision() {
    let mut f = Fixture::new(true);
    let head = f.args.expected_current_id;
    for (revision, bytes) in [(3, &f.current), (2, &f.source), (4, &f.source)] {
        let variant = f.sign_variant(revision, bytes);
        f.args.expected_candidate_id = write_manifest(&f.args.candidate_manifest, &variant);
        assert!(activate(&f.args, NOW).is_err());
        f.assert_current(2, &f.current, &head);
    }
}

#[test]
fn missing_retained_bytes_or_busy_cache_preserves_the_current_site() {
    let f = Fixture::new(false);
    assert!(activate(&f.args, NOW).is_err());
    f.assert_current(2, &f.current, &f.args.expected_current_id);
    let f = Fixture::new(true);
    let locked = f.open();
    assert!(activate(&f.args, NOW).is_err());
    drop(locked);
    f.assert_current(2, &f.current, &f.args.expected_current_id);
}

#[test]
fn competing_restore_cannot_poison_an_existing_equal_revision_floor() {
    let mut f = Fixture::new(true);
    activate(&f.args, NOW).unwrap();
    let committed = f.args.expected_candidate_id;
    let alternate = f.sign_variant(3, &f.source);
    f.args.expected_candidate_id = write_manifest(&f.args.candidate_manifest, &alternate);
    assert_ne!(committed, f.args.expected_candidate_id);
    assert!(activate(&f.args, NOW).is_err());
    f.assert_current(3, &f.source, &committed);
}

#[test]
fn previously_observed_equivocation_denies_activation_even_for_one_of_the_signed_heads() {
    let f = Fixture::new(true);
    let alternate = f.sign_variant(2, &f.current);
    let key = f.owner.verifying_key();
    let mut cache = f.open();
    assert!(matches!(
        cache.observe_name_revision(&alternate.verify(&key, NOW).unwrap(), NOW),
        Err(Error::NameConflict)
    ));
    drop(cache);
    assert!(activate(&f.args, NOW).is_err());
    let cache = f.open();
    let pin = cache
        .name_revision_floor(key.as_bytes(), NAME)
        .unwrap()
        .unwrap();
    assert!(pin.conflicted());
    assert_eq!(pin.manifest_id(), &f.args.expected_current_id);
}

#[test]
fn interrupted_floor_write_completes_only_from_the_original_signed_successor() {
    let f = Fixture::new(true);
    let key = f.owner.verifying_key();
    let mut cache = f.open();
    cache
        .observe_name_revision(&f.candidate.verify(&key, NOW).unwrap(), NOW)
        .unwrap();
    assert!(matches!(
        cache.cached_named_manifest(key.as_bytes(), NAME, 0, NOW),
        Err(Error::NameRollback)
    ));
    drop(cache);
    let repaired = activate(&f.args, NOW).unwrap();
    assert_eq!(
        repaired["manifest_id"],
        hex::encode(f.args.expected_candidate_id)
    );
    f.assert_current(3, &f.source, &f.args.expected_candidate_id);
}

#[test]
fn first_use_requires_explicit_initialization_and_rejects_a_bad_request_before_pinning() {
    let mut f = Fixture::new(true);
    f.args.cache = f.directory.path().join("new-owner-cache");
    let mut owner = ChunkStore::create(&f.args.cache, limits().cache_limits().unwrap()).unwrap();
    owner.put(&f.source).unwrap();
    owner.put(&f.current).unwrap();
    drop(owner);
    assert!(activate(&f.args, NOW).is_err());
    let key = f.owner.verifying_key();
    assert!(
        f.open()
            .name_revision_floor(key.as_bytes(), NAME)
            .unwrap()
            .is_none()
    );
    f.args.initialize_from_reviewed_current = true;
    let correct = f.args.expected_candidate_id;
    f.args.expected_candidate_id[0] ^= 1;
    assert!(activate(&f.args, NOW).is_err());
    assert!(
        f.open()
            .name_revision_floor(key.as_bytes(), NAME)
            .unwrap()
            .is_none()
    );
    f.args.expected_candidate_id = correct;
    assert_eq!(activate(&f.args, NOW).unwrap()["state"], "activated");
    f.assert_current(3, &f.source, &correct);
}

#[test]
fn expiry_during_site_verification_preserves_the_previous_head() {
    let f = Fixture::new(true);
    let checks = std::cell::Cell::new(0);
    let result = activate_with_clock(&f.args, || {
        let count = checks.get();
        checks.set(count + 1);
        Ok(if count == 0 { NOW } else { NOW + 600 })
    });
    assert!(result.is_err());
    assert_eq!(checks.get(), 2);
    f.assert_current(2, &f.current, &f.args.expected_current_id);
}

#[test]
fn first_use_flag_cannot_replace_a_different_existing_exact_revision() {
    let mut f = Fixture::new(true);
    let head = f.args.expected_current_id;
    let alternate = f.sign_variant(2, &f.current);
    f.args.expected_current_id = write_manifest(&f.args.current_manifest, &alternate);
    assert_ne!(f.args.expected_current_id, head);
    f.args.initialize_from_reviewed_current = true;
    assert!(activate(&f.args, NOW).is_err());
    f.assert_current(2, &f.current, &head);
}
