// SPDX-License-Identifier: GPL-3.0-only
use std::{
    fs,
    io::{Seek, SeekFrom, Write},
    os::unix::fs::{PermissionsExt, symlink},
};

use ed25519_dalek::SigningKey;
use volparossa_content::{
    CacheLimits, ChunkStore, Metadata as ContentMetadata, Publication, Validity, publish,
    site::SiteAsset,
};

use super::*;

struct Fixture {
    directory: tempfile::TempDir,
    args: Preview,
}
impl Fixture {
    fn new(bytes: &[u8], content_type: &str, created: u64, expires: u64) -> Self {
        let directory = tempfile::tempdir().unwrap();
        let signer = SigningKey::from_bytes(&[29; 32]);
        let mut cache = ChunkStore::create(
            &directory.path().join("cache"),
            CacheLimits {
                max_bytes: 1_048_576,
                max_entries: 8,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let mut reader = bytes;
        let manifest = publish(
            &mut reader,
            Publication {
                length: u64::try_from(bytes.len()).unwrap(),
                metadata: ContentMetadata {
                    name: "selected-original-site".into(),
                    revision: 7,
                    content_type: content_type.into(),
                },
                validity: Validity { created, expires },
            },
            &signer,
            &mut cache,
        )
        .unwrap();
        drop(cache);
        let input = directory.path().join("input.vps");
        let path = directory.path().join("manifest.pb");
        owned(&input, bytes);
        owned(&path, &manifest.encode());
        Self {
            args: Preview {
                input,
                manifest: path,
                publisher_key: signer.verifying_key(),
                expected_input_sha256: Sha256::digest(bytes).into(),
                lifetime_seconds: 60,
            },
            directory,
        }
    }
    fn site() -> Self {
        let now = now_seconds().unwrap();
        Self::new(&bundle(), SITE_CONTENT_TYPE, now - 1, now + 600)
    }
    fn prepare(self) -> Result<Prepared> {
        prepare_blocking(
            &self.args,
            Instant::now(),
            now_seconds().unwrap(),
            Arc::new(AtomicBool::new(false)),
        )
    }
}
fn owned(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}
fn bundle() -> Vec<u8> {
    SiteBundle::encode(vec![
        SiteAsset {
            path: "/index.html".into(),
            content_type: "text/html".into(),
            bytes: b"<h1>public preview fixture</h1>".to_vec(),
        },
        SiteAsset {
            path: "/style.css".into(),
            content_type: "text/css".into(),
            bytes: b"h1{color:red}".to_vec(),
        },
    ])
    .unwrap()
}
fn control() -> Control {
    Control {
        cancel: Arc::new(AtomicBool::new(false)),
        deadline: Instant::now() + Duration::from_secs(60),
    }
}

#[test]
fn authenticated_snapshot_keeps_original_manifest_and_files_read_only() {
    let fixture = Fixture::site();
    let input = fs::read(&fixture.args.input).unwrap();
    let manifest = fs::read(&fixture.args.manifest).unwrap();
    let names = fs::read_dir(fixture.directory.path())
        .unwrap()
        .map(|entry| entry.unwrap().file_name())
        .collect::<Vec<_>>();
    let prepared = prepare_blocking(
        &fixture.args,
        Instant::now(),
        now_seconds().unwrap(),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    assert_eq!(prepared.bundle.asset_count(), 2);
    assert_eq!(
        prepared.bundle.asset("/index.html").unwrap().bytes,
        b"<h1>public preview fixture</h1>"
    );
    let report = prepared.authority.report();
    assert_eq!(report["source"], "local_signed_bundle");
    assert_eq!(report["publisher_signature_verified"], true);
    assert_eq!(report["reviewed_input_sha256_matched"], true);
    assert_eq!(report["name"], "selected-original-site");
    assert_eq!(report["revision"], 7);
    for field in [
        "network_retrieval_performed",
        "named_lookup_performed",
        "origin_authenticated",
        "https_origin_authenticated",
        "globally_latest",
        "publisher_name_authority_verified",
        "internet_policy_permission_granted",
        "private_spool_created",
        "input_files_modified",
    ] {
        assert_eq!(report[field], false);
    }
    for absent in [
        "peer_bytes",
        "providers_used",
        "provider_peer_ids",
        "control_relay_peer_id",
        "cache_only",
        "private_spool_removed",
        "input",
        "manifest",
        "private_key",
    ] {
        assert!(report.get(absent).is_none());
    }
    assert_eq!(
        fs::read(fixture.directory.path().join("input.vps")).unwrap(),
        input
    );
    assert_eq!(
        fs::read(fixture.directory.path().join("manifest.pb")).unwrap(),
        manifest
    );
    assert_eq!(
        fs::read_dir(fixture.directory.path())
            .unwrap()
            .map(|entry| entry.unwrap().file_name())
            .collect::<Vec<_>>(),
        names
    );
}

#[test]
fn wrong_reviewed_sha_or_expected_publisher_is_rejected() {
    let mut fixture = Fixture::site();
    fixture.args.expected_input_sha256 = [0; 32];
    assert!(matches!(fixture.prepare(), Err(Failure::Digest)));
    let mut fixture = Fixture::site();
    fixture.args.publisher_key = SigningKey::from_bytes(&[31; 32]).verifying_key();
    assert!(matches!(fixture.prepare(), Err(Failure::Publisher)));
}

#[test]
fn changed_signature_noncanonical_manifest_and_wrong_content_type_are_rejected() {
    let fixture = Fixture::site();
    let mut bytes = fs::read(&fixture.args.manifest).unwrap();
    *bytes.last_mut().unwrap() ^= 1;
    owned(&fixture.args.manifest, &bytes);
    assert!(matches!(fixture.prepare(), Err(Failure::Manifest)));
    let fixture = Fixture::site();
    let mut bytes = fs::read(&fixture.args.manifest).unwrap();
    bytes.extend_from_slice(&[0xf8, 0x07, 0x01]);
    owned(&fixture.args.manifest, &bytes);
    assert!(matches!(fixture.prepare(), Err(Failure::Manifest)));
    let now = now_seconds().unwrap();
    assert!(matches!(
        Fixture::new(&bundle(), "application/octet-stream", now - 1, now + 600).prepare(),
        Err(Failure::ContentType)
    ));
}

#[test]
fn signed_but_unknown_or_noncanonical_bundle_never_becomes_a_viewer() {
    let now = now_seconds().unwrap();
    assert!(matches!(
        Fixture::new(b"unknown bundle", SITE_CONTENT_TYPE, now - 1, now + 600).prepare(),
        Err(Failure::Bundle)
    ));
    let mut unknown = bundle();
    assert_eq!(unknown[4], 8);
    unknown[5] = 2;
    assert!(matches!(
        Fixture::new(&unknown, SITE_CONTENT_TYPE, now - 1, now + 600).prepare(),
        Err(Failure::Bundle)
    ));
}

#[test]
fn original_signed_expiry_and_before_preparation_monotonic_cap_never_restart() {
    let now = now_seconds().unwrap();
    assert!(matches!(
        Fixture::new(&bundle(), SITE_CONTENT_TYPE, now - 20, now - 1).prepare(),
        Err(Failure::Expired)
    ));
    let fixture = Fixture::new(&bundle(), SITE_CONTENT_TYPE, now - 1, now + 30);
    let prepared = fixture.prepare().unwrap();
    assert_eq!(prepared.expires, now + 30);
    let fixture = Fixture::site();
    let start = Instant::now() - Duration::from_secs(2);
    let prepared = prepare_blocking(
        &fixture.args,
        start,
        now - 2,
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    assert!(prepared.deadline <= start + Duration::from_secs(60));
    assert_eq!(prepared.expires, now + 58);
    let fixture = Fixture::site();
    assert!(matches!(
        prepare_blocking(
            &fixture.args,
            Instant::now() - Duration::from_secs(61),
            now,
            Arc::new(AtomicBool::new(false))
        ),
        Err(Failure::Deadline)
    ));
}

#[test]
fn payload_truncation_growth_and_byte_mutation_reject_signed_binding() {
    let fixture = Fixture::site();
    let file = fs::OpenOptions::new()
        .write(true)
        .open(&fixture.args.input)
        .unwrap();
    file.set_len(1).unwrap();
    assert!(matches!(fixture.prepare(), Err(Failure::Length)));
    let fixture = Fixture::site();
    let mut file = fs::OpenOptions::new()
        .write(true)
        .open(&fixture.args.input)
        .unwrap();
    file.seek(SeekFrom::Start(0)).unwrap();
    file.write_all(b"X").unwrap();
    assert!(matches!(fixture.prepare(), Err(Failure::Digest)));
    let fixture = Fixture::site();
    let mut file = fs::OpenOptions::new()
        .append(true)
        .open(&fixture.args.input)
        .unwrap();
    file.write_all(b"X").unwrap();
    assert!(matches!(fixture.prepare(), Err(Failure::Length)));
}

#[test]
fn each_input_refuses_symlinks_hardlinks_wide_mode_and_directory() {
    for is_manifest in [false, true] {
        for fault in ["symlink", "hardlink", "mode", "directory"] {
            let fixture = Fixture::site();
            let path = if is_manifest {
                &fixture.args.manifest
            } else {
                &fixture.args.input
            };
            match fault {
                "symlink" => {
                    let renamed = path.with_extension("original");
                    fs::rename(path, &renamed).unwrap();
                    symlink(renamed, path).unwrap();
                }
                "hardlink" => fs::hard_link(path, fixture.directory.path().join("alias")).unwrap(),
                "mode" => fs::set_permissions(path, fs::Permissions::from_mode(0o644)).unwrap(),
                _ => {
                    fs::remove_file(path).unwrap();
                    fs::create_dir(path).unwrap();
                }
            }
            assert!(fixture.prepare().is_err());
        }
    }
}

#[test]
fn metadata_oversize_is_rejected_before_any_large_read_or_allocation() {
    for (is_manifest, maximum) in [
        (false, MAX_OBJECT_BYTES),
        (true, u64::try_from(MAX_MANIFEST_BYTES).unwrap()),
    ] {
        let fixture = Fixture::site();
        let path = if is_manifest {
            &fixture.args.manifest
        } else {
            &fixture.args.input
        };
        fs::OpenOptions::new()
            .write(true)
            .open(path)
            .unwrap()
            .set_len(maximum + 1)
            .unwrap();
        assert!(matches!(fixture.prepare(), Err(Failure::Bounds)));
    }
}

#[test]
fn descriptor_snapshot_refuses_changes_after_open_and_stops_at_one_extra_byte() {
    for replacement in [b"ab".as_slice(), b"abcd", b"a much longer growth"] {
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("owned");
        owned(&path, b"abc");
        let control = control();
        let opened = Opened::open(&path, 3, &control).unwrap();
        owned(&path, replacement);
        assert!(matches!(opened.read(&control), Err(Failure::Changed)));
    }
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("owned");
    owned(&path, b"abc");
    let control = control();
    let opened = Opened::open(&path, 3, &control).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640)).unwrap();
    assert!(matches!(opened.read(&control), Err(Failure::Changed)));
}

#[test]
fn cancellation_guard_and_expired_budget_deny_preparation_without_side_effects() {
    let fixture = Fixture::site();
    let flag = Arc::new(AtomicBool::new(false));
    let guard = Cancel(Arc::clone(&flag));
    drop(guard);
    assert!(matches!(
        prepare_blocking(&fixture.args, Instant::now(), now_seconds().unwrap(), flag),
        Err(Failure::Cancelled)
    ));
    let mut fixture = Fixture::site();
    fixture.args.lifetime_seconds = 0;
    assert!(matches!(fixture.prepare(), Err(Failure::Bounds)));
}

#[test]
fn each_original_signed_chunk_binding_is_checked_with_the_existing_content_hash() {
    let fixture = Fixture::site();
    let mut bytes = fs::read(&fixture.args.input).unwrap();
    let prepared = fixture.prepare().unwrap();
    bytes[0] ^= 1;
    assert!(matches!(
        verify_chunks(&bytes, &prepared.authority.manifest, &control()),
        Err(Failure::Chunk)
    ));
    bytes.truncate(1);
    assert!(matches!(
        verify_chunks(&bytes, &prepared.authority.manifest, &control()),
        Err(Failure::Chunk)
    ));
}

#[test]
fn later_source_mutation_never_changes_the_reviewed_served_snapshot() {
    let fixture = Fixture::site();
    let input = fixture.args.input.clone();
    let prepared = prepare_blocking(
        &fixture.args,
        Instant::now(),
        now_seconds().unwrap(),
        Arc::new(AtomicBool::new(false)),
    )
    .unwrap();
    owned(&input, b"different bytes after completed preparation");
    assert_eq!(
        prepared.bundle.asset("/index.html").unwrap().bytes,
        b"<h1>public preview fixture</h1>"
    );
    assert!(prepared.authority.check_live().is_ok());
}

#[test]
fn cli_requires_independent_key_reviewed_sha_and_keeps_preview_separate_from_named_or_signing_options()
 {
    use clap::Parser as _;
    let key = hex::encode(SigningKey::from_bytes(&[41; 32]).verifying_key().as_bytes());
    let hash = hex::encode([3; 32]);
    let base = [
        "volparossa",
        "content",
        "site",
        "preview",
        "--input",
        "owned.vps",
        "--manifest",
        "original.pb",
        "--publisher-key",
        &key,
        "--expected-input-sha256",
        &hash,
    ];
    let parsed = crate::Cli::try_parse_from(base).unwrap();
    let crate::CliCommand::Content { command } = parsed.command else {
        panic!("content expected")
    };
    let super::super::super::Command::Site(super::super::Command::Preview(args)) = *command else {
        panic!("preview expected")
    };
    assert_eq!(args.lifetime_seconds, 60);
    assert!(crate::Cli::try_parse_from(&base[..10]).is_err());
    for extra in [
        ["--identity", "private.key"],
        ["--cache", "cache"],
        ["--name", "publisher-name"],
        ["--min-revision", "1"],
        ["--lifetime-seconds", "0"],
        ["--lifetime-seconds", "86401"],
    ] {
        assert!(crate::Cli::try_parse_from(base.into_iter().chain(extra)).is_err());
    }
}

#[tokio::test]
async fn dropped_preparation_guard_cancels_and_joins_the_owned_blocking_worker() {
    let fixture = Fixture::site();
    let flag = Arc::new(AtomicBool::new(false));
    let guard = Cancel(Arc::clone(&flag));
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let released = Arc::clone(&barrier);
    let (started, ready) = tokio::sync::oneshot::channel();
    let job = tokio::task::spawn_blocking(move || {
        started.send(()).unwrap();
        released.wait();
        prepare_blocking(&fixture.args, Instant::now(), now_seconds().unwrap(), flag)
    });
    tokio::time::timeout(Duration::from_secs(2), ready)
        .await
        .unwrap()
        .unwrap();
    drop(guard);
    barrier.wait();
    assert!(matches!(
        tokio::time::timeout(Duration::from_secs(2), job)
            .await
            .unwrap()
            .unwrap(),
        Err(Failure::Cancelled)
    ));
}
