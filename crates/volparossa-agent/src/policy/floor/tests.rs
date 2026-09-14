//! Separate verifier processes reopen one real durable store; no network or agent-role changes.

use std::{os::unix::fs::PermissionsExt as _, path::PathBuf, process::Command};

use ed25519_dalek::SigningKey;
use serde_json::json;
use volparossa_config::{Config, RuntimeMode};
use volparossa_policy::{ManifestSpec, TrustedMaintainer, sign_manifest};

use super::*;
use crate::policy::{PolicyLoadError, load_active_policy};

const NOW: u64 = 1_900_000_000_000;
const CHILD_ROOT: &str = "VOLPAROSSA_POLICY_FLOOR_TEST_DIRECTORY";
const CHILD_RESULT: &str = "VOLPAROSSA_POLICY_FLOOR_TEST_RESULT";
const CHILD_MODE: &str = "VOLPAROSSA_POLICY_FLOOR_TEST_MODE";
const CHILD_TEST: &str = "policy::floor::tests::policy_floor_child_process";

struct Fixture {
    directory: tempfile::TempDir,
    keys: [SigningKey; 5],
}

impl Fixture {
    fn new() -> Self {
        let fixture = Self {
            directory: tempfile::Builder::new()
                .permissions(fs::Permissions::from_mode(0o700))
                .tempdir()
                .unwrap(),
            keys: std::array::from_fn(|_| SigningKey::generate(&mut rand_core::OsRng)),
        };
        fixture.trust(false, false);
        fixture
    }

    fn trust(&self, development: bool, reversed: bool) {
        let mut keys: Vec<_> = self.keys.iter().collect();
        if reversed {
            keys.reverse();
        }
        let bytes = serde_json::to_vec_pretty(&json!({
            "schema_version": 1,
            "maintainers": keys.into_iter().map(|key| json!({
                "public_key_hex": hex::encode(key.verifying_key().to_bytes()),
                "environment": if development { "development" } else { "production" },
            })).collect::<Vec<_>>(),
        }))
        .unwrap();
        write(&self.directory.path().join("trust.json"), &bytes);
    }

    fn manifest(&self, version: u64, changed: bool, development: bool) -> Vec<u8> {
        let anchors = self
            .keys
            .iter()
            .map(|key| {
                TrustedMaintainer::new(
                    key.verifying_key(),
                    if development {
                        MaintainerEnvironment::Development
                    } else {
                        MaintainerEnvironment::Production
                    },
                )
            })
            .collect();
        let trust = TrustStore::new(
            if development {
                PolicyMode::Development
            } else {
                PolicyMode::Production
            },
            anchors,
        )
        .unwrap();
        let spec = ManifestSpec::new(
            version,
            POLICY_PROTOCOL_VERSION,
            NOW - 1000,
            NOW - 1000,
            NOW + 60_000 + u64::from(changed),
        )
        .unwrap();
        let bytes =
            sign_manifest(&spec, &trust, &self.keys[..3].iter().collect::<Vec<_>>()).unwrap();
        write(&self.directory.path().join("manifest.pb"), &bytes);
        bytes
    }

    fn child(&self, mode: &str, expected: &str) {
        let output = Command::new(std::env::current_exe().unwrap())
            .args(["--exact", CHILD_TEST, "--nocapture"])
            .env(CHILD_ROOT, self.directory.path())
            .env(CHILD_MODE, mode)
            .env(CHILD_RESULT, expected)
            .output()
            .unwrap();
        assert!(
            output.status.success(),
            "policy verifier child failed: {}{}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
    }

    fn floor(&self) -> Vec<u8> {
        fs::read(self.directory.path().join(FLOOR_FILE)).unwrap()
    }
}

fn write(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
    file.sync_all().unwrap();
}

#[test]
fn policy_floor_child_process() {
    let Some(root) = std::env::var_os(CHILD_ROOT) else {
        return;
    };
    let root = PathBuf::from(root);
    let mode = std::env::var(CHILD_MODE).unwrap();
    let mut config = Config {
        runtime_mode: match mode.as_str() {
            "production" => RuntimeMode::Production,
            "development" => RuntimeMode::Development,
            _ => panic!("unsupported isolated fixture mode"),
        },
        ..Config::default()
    };
    config.policy.manifest_path = root.join("manifest.pb").to_string_lossy().into_owned();
    let result = load_active_policy(&config, &root.join("trust.json"), &root, NOW);
    match std::env::var(CHILD_RESULT).unwrap().as_str() {
        "accepted" => assert!(result.unwrap().is_some()),
        "rollback" => assert!(matches!(
            result,
            Err(PolicyLoadError::Floor(FloorError::Rollback))
        )),
        "conflict" => assert!(matches!(
            result,
            Err(PolicyLoadError::Floor(FloorError::Conflict))
        )),
        "floor-failure" => assert!(matches!(result, Err(PolicyLoadError::Floor(_)))),
        "trust-failure" => assert!(matches!(
            result,
            Err(PolicyLoadError::DevelopmentKey | PolicyLoadError::Policy(_))
        )),
        _ => panic!("unsupported isolated fixture expectation"),
    }
}

#[test]
fn signed_policy_floor_is_monotonic_across_real_processes_and_authority_namespaces() {
    let mut fixture = Fixture::new();
    let original_keys = fixture.keys.clone();
    let original = fixture.manifest(7, false, false);
    fixture.child("production", "accepted");
    let retained = fixture.floor();
    let inode = fs::metadata(fixture.directory.path().join(FLOOR_FILE))
        .unwrap()
        .ino();
    fixture.trust(false, true); // Canonical actual anchors, not trust JSON order/format.
    fixture.child("production", "accepted");
    assert_eq!(fixture.floor(), retained);
    assert_eq!(
        fs::metadata(fixture.directory.path().join(FLOOR_FILE))
            .unwrap()
            .ino(),
        inode,
        "identical activation does not rewrite the durable floor"
    );
    fixture.manifest(6, false, false);
    fixture.child("production", "rollback");
    fixture.manifest(7, true, false);
    fixture.child("production", "conflict");
    assert_eq!(fixture.floor(), retained);
    fixture.manifest(8, false, false);
    fixture.child("production", "accepted");
    write(&fixture.directory.path().join("manifest.pb"), &original);
    fixture.child("production", "rollback");

    // The same keys in an explicitly different verifier mode are separately scoped.
    fixture.manifest(1, false, false);
    fixture.child("development", "accepted");
    fixture.child("production", "rollback");
    // Environment labels are also authority identity, not merely presentation metadata.
    fixture.trust(true, false);
    fixture.manifest(1, false, true);
    fixture.child("development", "accepted");
    fixture.child("production", "trust-failure");
    // Independently configured new keys establish a separate authority, not authorized
    // rotation of the old one. Returning to old anchors must recover their original floor.
    fixture.keys = std::array::from_fn(|_| SigningKey::generate(&mut rand_core::OsRng));
    fixture.trust(false, false);
    fixture.manifest(1, false, false);
    fixture.child("production", "accepted");
    fixture.keys = original_keys;
    fixture.trust(false, false);
    fixture.manifest(7, false, false);
    fixture.child("production", "rollback");
    let state: State = serde_json::from_slice(&fixture.floor()).unwrap();
    assert_eq!(state.authorities.len(), 4);
    assert_eq!(
        state.authorities.iter().map(|record| record.version).max(),
        Some(8)
    );
    let json: serde_json::Value = serde_json::from_slice(&fixture.floor()).unwrap();
    for record in json["authorities"].as_array().unwrap() {
        assert_eq!(record.as_object().unwrap().len(), 3);
        assert!(record.get("namespace").is_some());
        assert!(record.get("version").is_some());
        assert!(record.get("body_hash").is_some());
    }
}

#[test]
fn corrupt_missing_or_busy_floor_never_reinitializes_or_advances_before_verification() {
    let fixture = Fixture::new();
    fixture.manifest(7, false, false);
    fixture.child("production", "accepted");
    let retained = fixture.floor();
    let (file, created) = lock_file(fixture.directory.path()).unwrap();
    assert!(!created);
    let held = Flock::lock(file, FlockArg::LockExclusiveNonblock).unwrap();
    fixture.manifest(8, false, false);
    fixture.child("production", "floor-failure");
    assert_eq!(fixture.floor(), retained);
    drop(held);

    // Invalid signatures are rejected before floor mutation, even with an enormous version.
    let mut invalid = fixture.manifest(u64::MAX, false, false);
    *invalid.last_mut().unwrap() ^= 1;
    write(&fixture.directory.path().join("manifest.pb"), &invalid);
    fixture.child("production", "trust-failure");
    assert_eq!(fixture.floor(), retained);
    fixture.manifest(8, false, false);
    let floor_path = fixture.directory.path().join(FLOOR_FILE);
    write(&floor_path, b"{broken durable state");
    fixture.child("production", "floor-failure");
    assert_eq!(fixture.floor(), b"{broken durable state");
    fs::remove_file(&floor_path).unwrap(); // Only this explicit disposable test record.
    fixture.child("production", "floor-failure");
    assert!(
        !floor_path.exists(),
        "an existing authority must never reset silently"
    );

    // An empty configuration means no policy, not deletion/reset of any retained state.
    let config = Config::default();
    assert!(
        load_active_policy(
            &config,
            &fixture.directory.path().join("absent-trust"),
            fixture.directory.path(),
            NOW,
        )
        .unwrap()
        .is_none()
    );
    assert!(!floor_path.exists());
}
