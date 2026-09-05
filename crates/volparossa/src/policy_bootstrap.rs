use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, File, OpenOptions},
    io::Write as _,
    net::IpAddr,
    os::unix::fs::{DirBuilderExt as _, OpenOptionsExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore as _};
use rustix::fs::{RenameFlags, renameat_with};
use serde::Serialize;
use volparossa_policy::{
    DEFAULT_MAINTAINER_COUNT, DEFAULT_MAXIMUM_MANIFEST_LIFETIME_MS, DEFAULT_MINIMUM_SIGNATURES,
    DestinationRule, ManifestSpec, POLICY_PROTOCOL_VERSION, PolicyMode, ProtocolPort,
    TransportProtocol, TrustStore, TrustedMaintainer, VerificationPolicy, normalize_domain,
    sign_manifest, verify_manifest,
};
use zeroize::Zeroizing;

const MANIFEST_FILE: &str = "policy.manifest";
const TRUST_FILE: &str = "policy-maintainers.json";
const KEYS_DIRECTORY: &str = "maintainer-keys";
const WARNING_FILE: &str = "LOCAL-KEYS-WARNING.txt";
const TRUST_SCHEMA_VERSION: u32 = 1;
const PRIVATE_KEY_SCHEMA_VERSION: u32 = 1;
const MILLIS_PER_HOUR: u64 = 60 * 60 * 1_000;

pub(crate) struct BootstrapOutput {
    pub(crate) manifest: PathBuf,
    pub(crate) trust_store: PathBuf,
    pub(crate) keys_directory: PathBuf,
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
enum Selector {
    Domain(String),
    Ip(IpAddr),
}

#[derive(Serialize)]
struct TrustFile {
    schema_version: u32,
    maintainers: Vec<TrustKey>,
}

#[derive(Serialize)]
struct TrustKey {
    public_key_hex: String,
    environment: &'static str,
}

#[derive(Serialize)]
struct PrivateKeyFile {
    schema_version: u32,
    warning: &'static str,
    public_key_hex: String,
    private_key_hex: String,
}

pub(crate) fn bootstrap_local(
    output_directory: &Path,
    domain_rules: &[String],
    ip_rules: &[String],
    lifetime_hours: u16,
) -> Result<BootstrapOutput> {
    let now_ms = u64::try_from(
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .context("system clock predates Unix epoch")?
            .as_millis(),
    )
    .context("system time does not fit policy timestamp")?;
    bootstrap_local_at(
        output_directory,
        domain_rules,
        ip_rules,
        lifetime_hours,
        now_ms,
    )
}

fn bootstrap_local_at(
    output_directory: &Path,
    domain_rules: &[String],
    ip_rules: &[String],
    lifetime_hours: u16,
    now_ms: u64,
) -> Result<BootstrapOutput> {
    let rules = parse_rules(domain_rules, ip_rules)?;
    let lifetime_ms = u64::from(lifetime_hours)
        .checked_mul(MILLIS_PER_HOUR)
        .filter(|lifetime| *lifetime > 0 && *lifetime <= DEFAULT_MAXIMUM_MANIFEST_LIFETIME_MS)
        .context("policy lifetime must be between 1 and 168 hours")?;
    let expires_at_ms = now_ms
        .checked_add(lifetime_ms)
        .context("policy expiry overflows its timestamp")?;

    let keys =
        std::array::from_fn::<_, DEFAULT_MAINTAINER_COUNT, _>(|_| SigningKey::generate(&mut OsRng));
    let trust_store = TrustStore::new(
        PolicyMode::Production,
        keys.iter()
            .map(|key| TrustedMaintainer::production(key.verifying_key()))
            .collect(),
    )
    .context("generated production trust store is invalid")?;
    let mut specification =
        ManifestSpec::new(1, POLICY_PROTOCOL_VERSION, now_ms, now_ms, expires_at_ms)?
            .with_required_signatures(DEFAULT_MINIMUM_SIGNATURES)?;
    for rule in rules {
        specification.add_rule(rule)?;
    }
    let signers = keys
        .iter()
        .take(DEFAULT_MINIMUM_SIGNATURES)
        .collect::<Vec<_>>();
    let manifest = sign_manifest(&specification, &trust_store, &signers)
        .context("could not threshold-sign local policy")?;
    verify_manifest(
        &manifest,
        now_ms,
        &trust_store,
        VerificationPolicy::default(),
    )
    .context("generated policy did not verify")?;

    publish(
        output_directory,
        &manifest,
        &keys,
        trust_store.maintainers(),
    )?;
    Ok(BootstrapOutput {
        manifest: output_directory.join(MANIFEST_FILE),
        trust_store: output_directory.join(TRUST_FILE),
        keys_directory: output_directory.join(KEYS_DIRECTORY),
    })
}

fn parse_rules(domain_rules: &[String], ip_rules: &[String]) -> Result<Vec<DestinationRule>> {
    let mut permissions = BTreeMap::<Selector, BTreeSet<ProtocolPort>>::new();
    for encoded in domain_rules {
        let (destination, rule_permissions) = split_rule(encoded)?;
        let domain = normalize_domain(destination).context("invalid exact-domain rule")?;
        permissions
            .entry(Selector::Domain(domain))
            .or_default()
            .extend(rule_permissions);
    }
    for encoded in ip_rules {
        let (destination, rule_permissions) = split_rule(encoded)?;
        let address = destination
            .parse::<IpAddr>()
            .context("invalid exact-IP rule")?;
        permissions
            .entry(Selector::Ip(address))
            .or_default()
            .extend(rule_permissions);
    }
    if permissions.is_empty() {
        bail!("at least one --allow-domain or --allow-ip rule is required");
    }
    permissions
        .into_iter()
        .map(|(selector, permissions)| match selector {
            Selector::Domain(domain) => DestinationRule::exact_domain(&domain, permissions),
            Selector::Ip(address) => DestinationRule::exact_ip(address, permissions),
        })
        .collect::<Result<Vec<_>, _>>()
        .context("policy allow-rule set is invalid")
}

fn split_rule(encoded: &str) -> Result<(&str, Vec<ProtocolPort>)> {
    if encoded.trim() != encoded {
        bail!("policy rule must not contain surrounding whitespace");
    }
    let (destination, permissions) = encoded
        .split_once('=')
        .filter(|(destination, permissions)| !destination.is_empty() && !permissions.is_empty())
        .context("policy rule must use DESTINATION=PROTOCOL:PORT[,PROTOCOL:PORT...]")?;
    if permissions.contains('=') {
        bail!("policy rule contains more than one '=' separator");
    }
    let permissions = permissions
        .split(',')
        .map(|permission| {
            let (protocol, port) = permission
                .split_once(':')
                .filter(|(protocol, port)| !protocol.is_empty() && !port.is_empty())
                .context("permission must use tcp:PORT or udp:PORT")?;
            if port.contains(':') {
                bail!("permission contains more than one ':' separator");
            }
            let protocol = match protocol {
                "tcp" => TransportProtocol::Tcp,
                "udp" => TransportProtocol::Udp,
                _ => bail!("permission protocol must be exactly 'tcp' or 'udp'"),
            };
            let port = port
                .parse::<u16>()
                .context("permission port must be an integer from 1 through 65535")?;
            ProtocolPort::new(protocol, port).context("permission port must be nonzero")
        })
        .collect::<Result<Vec<_>>>()?;
    if permissions.is_empty() {
        bail!("policy rule must contain at least one permission");
    }
    Ok((destination, permissions))
}

fn publish(
    output_directory: &Path,
    manifest: &[u8],
    keys: &[SigningKey; DEFAULT_MAINTAINER_COUNT],
    trusted: &[TrustedMaintainer],
) -> Result<()> {
    if !output_directory.is_absolute() {
        bail!("policy output directory must be absolute");
    }
    match fs::symlink_metadata(output_directory) {
        Ok(_) => bail!("policy output directory already exists; refusing to overwrite it"),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {}
        Err(error) => return Err(error).context("cannot inspect policy output directory"),
    }
    let parent = output_directory
        .parent()
        .context("policy output directory has no parent")?;
    let leaf = output_directory
        .file_name()
        .context("policy output directory has no final component")?;
    let canonical_parent =
        fs::canonicalize(parent).context("cannot resolve policy output parent")?;
    if canonical_parent != parent {
        bail!("policy output parent must be an absolute canonical path without symlinks");
    }
    let metadata = fs::symlink_metadata(parent).context("cannot inspect policy output parent")?;
    if !metadata.is_dir() || metadata.file_type().is_symlink() {
        bail!("policy output parent must be a real directory");
    }

    let (staging_path, staging_leaf) = create_staging_directory(parent)?;
    let staged = (|| -> Result<()> {
        write_private(&staging_path.join(MANIFEST_FILE), manifest)?;
        let trust = TrustFile {
            schema_version: TRUST_SCHEMA_VERSION,
            maintainers: trusted
                .iter()
                .map(|maintainer| TrustKey {
                    public_key_hex: hex::encode(maintainer.verifying_key().to_bytes()),
                    environment: "production",
                })
                .collect(),
        };
        write_private(
            &staging_path.join(TRUST_FILE),
            &serde_json::to_vec_pretty(&trust).context("cannot encode production trust store")?,
        )?;
        let keys_directory = staging_path.join(KEYS_DIRECTORY);
        fs::DirBuilder::new()
            .mode(0o700)
            .create(&keys_directory)
            .context("cannot create local maintainer-key directory")?;
        fs::set_permissions(&keys_directory, fs::Permissions::from_mode(0o700))?;
        for (index, key) in keys.iter().enumerate() {
            let private = PrivateKeyFile {
                schema_version: PRIVATE_KEY_SCHEMA_VERSION,
                warning: "LOCAL ALPHA BOOTSTRAP KEY; co-located production-labeled keys are not operational key separation",
                public_key_hex: hex::encode(key.verifying_key().to_bytes()),
                private_key_hex: hex::encode(key.to_bytes()),
            };
            let encoded = Zeroizing::new(
                serde_json::to_vec_pretty(&private).context("cannot encode maintainer key")?,
            );
            write_private(
                &keys_directory.join(format!("maintainer-{}.json", index + 1)),
                &encoded,
            )?;
        }
        write_private(
            &staging_path.join(WARNING_FILE),
            b"All five production-labeled signing keys are co-located for a personal functional alpha.\nSeparate independent maintainer custody before operational use. Never commit these files.\n",
        )?;
        File::open(&keys_directory)?.sync_all()?;
        File::open(&staging_path)?.sync_all()?;
        Ok(())
    })();
    if let Err(error) = staged {
        let _ = fs::remove_dir_all(&staging_path);
        return Err(error);
    }

    let parent_file = File::open(parent).context("cannot open policy output parent")?;
    if let Err(error) = renameat_with(
        &parent_file,
        &staging_leaf,
        &parent_file,
        leaf,
        RenameFlags::NOREPLACE,
    ) {
        let _ = fs::remove_dir_all(&staging_path);
        return Err(std::io::Error::from_raw_os_error(error.raw_os_error()))
            .context("cannot atomically publish policy directory without overwrite");
    }
    parent_file
        .sync_all()
        .context("cannot sync published policy directory entry")
}

fn create_staging_directory(parent: &Path) -> Result<(PathBuf, String)> {
    for _ in 0..32 {
        let mut random = [0_u8; 16];
        OsRng.fill_bytes(&mut random);
        let leaf = format!(".volparossa-policy-{}.pending", hex::encode(random));
        let path = parent.join(&leaf);
        match fs::DirBuilder::new().mode(0o700).create(&path) {
            Ok(()) => {
                fs::set_permissions(&path, fs::Permissions::from_mode(0o700))?;
                return Ok((path, leaf));
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(error) => return Err(error).context("cannot create policy staging directory"),
        }
    }
    bail!("could not allocate a unique policy staging directory")
}

fn write_private(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .mode(0o600)
        .open(path)
        .with_context(|| format!("cannot create private policy file {}", path.display()))?;
    file.set_permissions(fs::Permissions::from_mode(0o600))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::os::unix::fs::{PermissionsExt as _, symlink};

    use serde::Deserialize;
    use tempfile::tempdir;

    use super::*;

    #[derive(Deserialize)]
    struct DecodedTrust {
        schema_version: u32,
        maintainers: Vec<DecodedTrustKey>,
    }

    #[derive(Deserialize)]
    struct DecodedTrustKey {
        public_key_hex: String,
        environment: String,
    }

    #[test]
    fn repeated_rules_merge_exact_permissions_and_reject_ambiguous_syntax() {
        let rules = parse_rules(
            &[
                "Example.COM=tcp:443".to_owned(),
                "example.com=udp:443,tcp:443".to_owned(),
            ],
            &["93.184.216.34=tcp:8443".to_owned()],
        )
        .expect("merged rules");
        assert_eq!(rules.len(), 2);
        let domain = rules
            .iter()
            .find(|rule| rule.exact_domain_name() == Some("example.com"))
            .expect("domain rule");
        assert_eq!(domain.permissions().len(), 2);
        assert!(parse_rules(&[], &[]).is_err());
        for invalid in ["example.com", "example.com=sctp:443", "example.com=tcp:0"] {
            assert!(parse_rules(&[invalid.to_owned()], &[]).is_err());
        }
    }

    #[test]
    fn bootstrap_publishes_verified_private_three_of_five_policy() {
        let parent = tempdir().expect("output parent");
        let output_directory = parent.path().join("policy");
        let output = bootstrap_local_at(
            &output_directory,
            &["example.com=tcp:443,udp:443".to_owned()],
            &["93.184.216.34=tcp:8443".to_owned()],
            24,
            1_900_000_000_000,
        )
        .expect("bootstrap policy");
        assert_eq!(output.manifest, output_directory.join(MANIFEST_FILE));
        assert_eq!(
            fs::metadata(&output_directory)
                .expect("output metadata")
                .permissions()
                .mode()
                & 0o777,
            0o700
        );
        let trust: DecodedTrust =
            serde_json::from_slice(&fs::read(&output.trust_store).expect("trust store bytes"))
                .expect("trust JSON");
        assert_eq!(trust.schema_version, 1);
        assert_eq!(trust.maintainers.len(), 5);
        assert!(
            trust
                .maintainers
                .iter()
                .all(|key| key.environment == "production")
        );
        let maintainers = trust
            .maintainers
            .iter()
            .map(|key| {
                let bytes: [u8; 32] = hex::decode(&key.public_key_hex)
                    .expect("public key hex")
                    .try_into()
                    .expect("public key bytes");
                TrustedMaintainer::production(
                    ed25519_dalek::VerifyingKey::from_bytes(&bytes).expect("verifying key"),
                )
            })
            .collect();
        let store = TrustStore::new(PolicyMode::Production, maintainers).expect("production trust");
        let verified = verify_manifest(
            &fs::read(&output.manifest).expect("manifest bytes"),
            1_900_000_000_000,
            &store,
            VerificationPolicy::default(),
        )
        .expect("threshold verification");
        assert_eq!(verified.verified_signatures(), 3);
        assert_eq!(verified.rules().len(), 2);
        for entry in fs::read_dir(&output.keys_directory).expect("key directory") {
            let path = entry.expect("key entry").path();
            assert_eq!(
                fs::metadata(path)
                    .expect("key metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
        for path in [
            output.manifest,
            output.trust_store,
            output_directory.join(WARNING_FILE),
        ] {
            assert_eq!(
                fs::metadata(path)
                    .expect("output metadata")
                    .permissions()
                    .mode()
                    & 0o777,
                0o600
            );
        }
    }

    #[test]
    fn bootstrap_refuses_relative_existing_and_symlink_destinations() {
        assert!(
            bootstrap_local_at(
                Path::new("relative"),
                &["example.com=tcp:443".to_owned()],
                &[],
                1,
                1_900_000_000_000,
            )
            .is_err()
        );
        let parent = tempdir().expect("output parent");
        let existing = parent.path().join("existing");
        fs::create_dir(&existing).expect("existing directory");
        assert!(
            bootstrap_local_at(
                &existing,
                &["example.com=tcp:443".to_owned()],
                &[],
                1,
                1_900_000_000_000,
            )
            .is_err()
        );
        let linked = parent.path().join("linked");
        symlink("missing", &linked).expect("output symlink");
        assert!(
            bootstrap_local_at(
                &linked,
                &["example.com=tcp:443".to_owned()],
                &[],
                1,
                1_900_000_000_000,
            )
            .is_err()
        );
    }
}
