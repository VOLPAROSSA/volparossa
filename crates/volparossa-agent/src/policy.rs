//! Root-provisioned trust anchors and fail-closed policy activation.

use std::{
    fs::{self, OpenOptions},
    io::Read,
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
};

use ed25519_dalek::VerifyingKey;
use serde::Deserialize;
use thiserror::Error;
use volparossa_config::{Config, RuntimeMode};
use volparossa_policy::{
    DEFAULT_MAINTAINER_COUNT, DEFAULT_MAXIMUM_CLOCK_SKEW_MS, DEFAULT_MAXIMUM_MANIFEST_LIFETIME_MS,
    MAX_SIGNED_MANIFEST_BYTES, MaintainerEnvironment, PolicyMode, TrustStore, TrustedMaintainer,
    VerificationPolicy, VerifiedManifest, verify_manifest,
};

const TRUST_SCHEMA_VERSION: u32 = 1;
const MAX_TRUST_FILE_BYTES: u64 = 64 * 1024;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustFile {
    schema_version: u32,
    maintainers: Vec<TrustKey>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TrustKey {
    public_key_hex: String,
    environment: TrustEnvironment,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "snake_case")]
enum TrustEnvironment {
    Production,
    Development,
}

/// Loads and threshold-verifies the configured manifest. An empty manifest
/// path intentionally yields no active policy rather than an allow-all policy.
pub fn load_active_policy(
    config: &Config,
    trust_path: &Path,
    now_ms: u64,
) -> Result<Option<VerifiedManifest>, PolicyLoadError> {
    if config.policy.manifest_path.trim().is_empty() {
        return Ok(None);
    }
    let trust_bytes = read_integrity_file(trust_path, MAX_TRUST_FILE_BYTES)?;
    let trust_file: TrustFile =
        serde_json::from_slice(&trust_bytes).map_err(|_| PolicyLoadError::TrustSyntax)?;
    if trust_file.schema_version != TRUST_SCHEMA_VERSION {
        return Err(PolicyLoadError::TrustVersion);
    }
    let mode = match config.runtime_mode {
        RuntimeMode::Production => PolicyMode::Production,
        RuntimeMode::Development => PolicyMode::Development,
    };
    if mode == PolicyMode::Production && trust_file.maintainers.len() != DEFAULT_MAINTAINER_COUNT {
        return Err(PolicyLoadError::TrustCount);
    }
    let maintainers = trust_file
        .maintainers
        .into_iter()
        .map(|entry| trusted_maintainer(entry, mode))
        .collect::<Result<Vec<_>, _>>()?;
    let expected = maintainers.len();
    let trust_store = TrustStore::new(mode, maintainers).map_err(PolicyLoadError::Policy)?;
    let verification = VerificationPolicy::new(
        usize::from(config.policy.minimum_signatures),
        expected,
        DEFAULT_MAXIMUM_MANIFEST_LIFETIME_MS,
        DEFAULT_MAXIMUM_CLOCK_SKEW_MS,
    )
    .map_err(PolicyLoadError::Policy)?;
    let manifest_path = Path::new(&config.policy.manifest_path);
    if !manifest_path.is_absolute() {
        return Err(PolicyLoadError::ManifestPath);
    }
    let manifest = read_integrity_file(
        manifest_path,
        u64::try_from(MAX_SIGNED_MANIFEST_BYTES).expect("small bound"),
    )?;
    verify_manifest(&manifest, now_ms, &trust_store, verification)
        .map(Some)
        .map_err(PolicyLoadError::Policy)
}

fn trusted_maintainer(
    entry: TrustKey,
    mode: PolicyMode,
) -> Result<TrustedMaintainer, PolicyLoadError> {
    if entry.public_key_hex.len() != 64 {
        return Err(PolicyLoadError::TrustKey);
    }
    let decoded = hex::decode(entry.public_key_hex).map_err(|_| PolicyLoadError::TrustKey)?;
    let bytes: [u8; 32] = decoded.try_into().map_err(|_| PolicyLoadError::TrustKey)?;
    let key = VerifyingKey::from_bytes(&bytes).map_err(|_| PolicyLoadError::TrustKey)?;
    let environment = match entry.environment {
        TrustEnvironment::Production => MaintainerEnvironment::Production,
        TrustEnvironment::Development => MaintainerEnvironment::Development,
    };
    if mode == PolicyMode::Production && environment != MaintainerEnvironment::Production {
        return Err(PolicyLoadError::DevelopmentKey);
    }
    Ok(TrustedMaintainer::new(key, environment))
}

fn read_integrity_file(path: &Path, maximum: u64) -> Result<Vec<u8>, PolicyLoadError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| PolicyLoadError::Io {
        path: path.to_owned(),
        source,
    })?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || metadata.mode() & 0o022 != 0
    {
        return Err(PolicyLoadError::UnsafeFile(path.to_owned()));
    }
    if metadata.len() == 0 || metadata.len() > maximum {
        return Err(PolicyLoadError::Length);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(|source| PolicyLoadError::Io {
            path: path.to_owned(),
            source,
        })?;
    let mut bytes =
        Vec::with_capacity(usize::try_from(metadata.len()).map_err(|_| PolicyLoadError::Length)?);
    file.by_ref()
        .take(maximum.saturating_add(1))
        .read_to_end(&mut bytes)
        .map_err(|source| PolicyLoadError::Io {
            path: path.to_owned(),
            source,
        })?;
    if bytes.is_empty() || bytes.len() > usize::try_from(maximum).unwrap_or(usize::MAX) {
        return Err(PolicyLoadError::Length);
    }
    Ok(bytes)
}

/// Policy provisioning, trust, or verification failure.
#[derive(Debug, Error)]
pub enum PolicyLoadError {
    /// Integrity-protected input could not be read.
    #[error("cannot read policy input at {path}")]
    Io {
        /// Affected public path.
        path: PathBuf,
        /// Underlying I/O failure.
        #[source]
        source: std::io::Error,
    },
    /// File type or write permissions permit unsafe substitution.
    #[error("policy input is not a safe non-writable regular file: {0}")]
    UnsafeFile(PathBuf),
    /// Input exceeds a hard resource bound.
    #[error("policy input length is invalid")]
    Length,
    /// Trust file JSON is malformed or ambiguous.
    #[error("policy trust file syntax is invalid")]
    TrustSyntax,
    /// Trust file schema is unsupported.
    #[error("policy trust file version is unsupported")]
    TrustVersion,
    /// Production uses the fixed three-of-five maintainer trust model.
    #[error("production policy trust requires exactly five maintainers")]
    TrustCount,
    /// Maintainer public key is malformed.
    #[error("policy trust file contains an invalid maintainer key")]
    TrustKey,
    /// A development key appeared in production.
    #[error("development policy key is forbidden in production")]
    DevelopmentKey,
    /// Manifest path must be explicit and absolute.
    #[error("policy manifest path must be absolute")]
    ManifestPath,
    /// Canonical threshold verification failed.
    #[error("policy manifest verification failed")]
    Policy(#[source] volparossa_policy::PolicyError),
}

#[cfg(test)]
mod tests {
    use ed25519_dalek::SigningKey;
    use serde_json::json;
    use tempfile::tempdir;
    use volparossa_policy::{ManifestSpec, sign_manifest};

    use super::*;

    #[test]
    fn separately_provisioned_threshold_policy_becomes_active() {
        let directory = tempdir().expect("tempdir");
        let trust_path = directory.path().join("policy-maintainers.json");
        let manifest_path = directory.path().join("policy.manifest");
        let keys = [
            SigningKey::from_bytes(&[1; 32]),
            SigningKey::from_bytes(&[2; 32]),
            SigningKey::from_bytes(&[3; 32]),
            SigningKey::from_bytes(&[4; 32]),
            SigningKey::from_bytes(&[5; 32]),
        ];
        let maintainers = keys
            .iter()
            .map(|key| TrustedMaintainer::production(key.verifying_key()))
            .collect::<Vec<_>>();
        let trust_store =
            TrustStore::new(PolicyMode::Production, maintainers).expect("trust store");
        let now_ms = 1_750_000_000_000_u64;
        let specification = ManifestSpec::new(
            7,
            volparossa_policy::POLICY_PROTOCOL_VERSION,
            now_ms - 1_000,
            now_ms - 1_000,
            now_ms + 60_000,
        )
        .expect("manifest spec");
        let signing_keys = keys[..3].iter().collect::<Vec<_>>();
        let manifest =
            sign_manifest(&specification, &trust_store, &signing_keys).expect("signed manifest");
        let mut manifest_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&manifest_path)
            .expect("private manifest file");
        std::io::Write::write_all(&mut manifest_file, &manifest)
            .expect("write private manifest file");
        let trust_json = json!({
            "schema_version": TRUST_SCHEMA_VERSION,
            "maintainers": keys.iter().map(|key| json!({
                "public_key_hex": hex::encode(key.verifying_key().to_bytes()),
                "environment": "production"
            })).collect::<Vec<_>>()
        });
        let trust_bytes = serde_json::to_vec(&trust_json).expect("trust JSON");
        let mut trust_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&trust_path)
            .expect("private trust file");
        std::io::Write::write_all(&mut trust_file, &trust_bytes).expect("write private trust file");

        let mut config = Config::default();
        config.policy.manifest_path = manifest_path.to_string_lossy().into_owned();
        let verified = load_active_policy(&config, &trust_path, now_ms)
            .expect("verify")
            .expect("active policy");
        assert_eq!(verified.manifest_version(), 7);
        assert_eq!(verified.verified_signatures(), 3);
        verified.ensure_active_at(now_ms).expect("active");
    }

    #[test]
    fn production_rejects_a_reduced_trust_set_before_manifest_read() {
        let directory = tempdir().expect("tempdir");
        let trust_path = directory.path().join("policy-maintainers.json");
        let keys = [
            SigningKey::from_bytes(&[11; 32]),
            SigningKey::from_bytes(&[12; 32]),
            SigningKey::from_bytes(&[13; 32]),
        ];
        let trust_json = json!({
            "schema_version": TRUST_SCHEMA_VERSION,
            "maintainers": keys.iter().map(|key| json!({
                "public_key_hex": hex::encode(key.verifying_key().to_bytes()),
                "environment": "production"
            })).collect::<Vec<_>>()
        });
        let mut trust_file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&trust_path)
            .expect("private trust file");
        std::io::Write::write_all(
            &mut trust_file,
            &serde_json::to_vec(&trust_json).expect("trust JSON"),
        )
        .expect("write private trust file");

        let mut config = Config::default();
        config.policy.manifest_path = directory
            .path()
            .join("unread-manifest")
            .to_string_lossy()
            .into_owned();
        assert!(matches!(
            load_active_policy(&config, &trust_path, 1),
            Err(PolicyLoadError::TrustCount)
        ));
    }

    #[test]
    fn empty_policy_path_is_fail_closed_without_trust_file() {
        let config = Config::default();
        assert!(
            load_active_policy(&config, Path::new("/does/not/exist"), 1)
                .expect("inactive")
                .is_none()
        );
    }
}
