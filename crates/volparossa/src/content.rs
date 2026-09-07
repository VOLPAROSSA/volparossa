//! Explicit native-content operations; networking is delegated to the protected agent runtime.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read as _, Write as _},
    os::unix::fs::OpenOptionsExt as _,
    path::{Path, PathBuf},
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context as _, Result, bail};
use clap::{Args, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use volparossa_content::{
    CacheLimits, ChunkStore, MAX_MANIFEST_BYTES, MAX_OBJECT_BYTES, MAX_SOURCES,
    MAX_VALIDITY_SECONDS, Metadata, Publication, SignedManifest, Validity,
};
use volparossa_identity::IdentityStore;
use zeroize::Zeroizing;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Chunk and sign an explicit local file; does NOT distribute it to any network.
    Publish(Publish),
    /// Verify and reconstruct from explicitly supplied local caches; no network retrieval.
    Assemble(Assemble),
    /// Register a publication with the agent and explicitly start its public content service.
    Serve(Serve),
    /// Ask the agent to discover providers and retrieve through real protected MPTCP routes.
    Fetch(Fetch),
    /// Authenticate HTTPS origin metadata, fetch peer chunks and fill missing ranges via origin.
    FetchHttps(FetchHttps),
    /// Withdraw and stop the agent's content service, retaining owned cache files.
    Stop,
    /// Inspect explicit content service and the current route's control Relay; no network I/O.
    Status,
}

#[derive(Debug, Args)]
pub(crate) struct Serve {
    /// Exact canonical signed manifest to serve; never captured browser traffic.
    #[arg(long)]
    manifest: PathBuf,
    /// Independently trusted 32-byte publisher public key in hexadecimal.
    #[arg(long, value_parser = parse_publisher_key)]
    publisher_key: VerifyingKey,
    /// Existing cache owned by the agent account, potentially holding only some chunks.
    #[arg(long)]
    cache: PathBuf,
    /// Explicit application bind address; no listener is started without this command.
    #[arg(long)]
    bind: std::net::SocketAddr,
    /// DNS hostname for this service, which must already be allowed by the signed Exit policy.
    #[arg(long)]
    advertised_hostname: String,
    #[command(flatten)]
    limits: Limits,
    #[command(flatten)]
    replication: Replication,
}

#[derive(Debug, Args)]
struct Replication {
    /// Explicitly enable opportunistic uptake/re-serving in a NEW private agent-owned cache.
    /// Omit this option to start no background replication job.
    #[arg(long = "replica-cache", id = "replica_cache")]
    cache: Option<PathBuf>,
    /// Shared replica-store payload quota, at most 256 MiB (not a quota per publication).
    #[arg(long = "replica-quota-bytes", id = "replica_quota_bytes", default_value_t = 64 * 1024 * 1024, requires = "replica_cache",
          value_parser = clap::value_parser!(u64).range(1..=MAX_OBJECT_BYTES))]
    quota_bytes: u64,
    /// Shared replica-store maximum indexed chunks (1 through 65536).
    #[arg(long = "replica-max-entries", id = "replica_max_entries", default_value_t = 256, requires = "replica_cache",
          value_parser = clap::value_parser!(u32).range(1..=65_536))]
    max_entries: u32,
    /// Maximum encoded replication bytes per exchange, from 64 bytes through 1 MiB.
    #[arg(long = "replica-max-bytes", id = "replica_max_bytes", default_value_t = 1024 * 1024, requires = "replica_cache",
          value_parser = clap::value_parser!(u64).range(64..=1_048_576))]
    max_bytes: u64,
    /// Maximum accepted chunks per exchange (1 through 4).
    #[arg(long = "replica-max-chunks", id = "replica_max_chunks", default_value_t = 4, requires = "replica_cache",
          value_parser = clap::value_parser!(u32).range(1..=4))]
    max_chunks: u32,
}

impl Replication {
    fn wire_config(
        &self,
        primary_cache: &Path,
        min_free_bytes: u64,
    ) -> Result<Option<volparossa_local_control::ContentReplicationConfig>> {
        let Some(path) = &self.cache else {
            return Ok(None);
        };
        let replica_cache = absolute_path(path)?;
        if replica_cache == absolute_path(primary_cache)? {
            bail!("replica cache must differ from the primary publication cache");
        }
        Ok(Some(volparossa_local_control::ContentReplicationConfig {
            replica_cache,
            limits: Some(volparossa_local_control::ContentCacheLimits {
                quota_bytes: self.quota_bytes,
                max_entries: self.max_entries,
                min_free_bytes,
            }),
            max_bytes: self.max_bytes,
            max_chunks: self.max_chunks,
        }))
    }
}

#[derive(Debug, Args)]
pub(crate) struct Fetch {
    /// Exact signed manifest; provider discovery does not establish publisher trust.
    #[arg(long)]
    manifest: PathBuf,
    /// Independently trusted 32-byte publisher public key in hexadecimal.
    #[arg(long, value_parser = parse_publisher_key)]
    publisher_key: VerifyingKey,
    /// New cache directory created by the agent account; no existing-directory adoption.
    #[arg(long)]
    cache: PathBuf,
    /// New output path writable by the agent account; no existing entry is overwritten.
    #[arg(long)]
    output: PathBuf,
    #[command(flatten)]
    limits: Limits,
}

#[derive(Debug, Args)]
pub(crate) struct FetchHttps {
    /// Exact canonical HTTPS resource URL; credentials and fragments are rejected.
    #[arg(long, value_parser = parse_origin_url)]
    url: String,
    /// Explicit canonical metadata path on the same HTTPS origin.
    #[arg(long, value_parser = parse_metadata_path)]
    metadata_path: String,
    /// New cache directory created by the agent account; no existing-directory adoption.
    #[arg(long)]
    cache: PathBuf,
    /// New output path writable by the agent account; no existing entry is overwritten.
    #[arg(long)]
    output: PathBuf,
    /// Explicit public PEM trust roots (at most 128 KiB); otherwise Debian system roots.
    /// Used only for this request: no installation, interception CA, or TLS bypass.
    #[arg(long)]
    ca_file: Option<PathBuf>,
    #[command(flatten)]
    limits: Limits,
}

#[derive(Debug, Args)]
pub(crate) struct Publish {
    /// Explicit regular local file (at most 256 MiB); symlinks/devices are rejected.
    #[arg(long)]
    input: PathBuf,
    /// New private cache directory, unless --reuse-cache opens an existing owned cache.
    #[arg(long)]
    cache: PathBuf,
    /// Reuse only a verified owned cache; quota enforcement may evict its older chunks.
    #[arg(long)]
    reuse_cache: bool,
    /// New canonical manifest file; existing entries are never overwritten.
    #[arg(long)]
    manifest: PathBuf,
    /// Explicit publisher-local label, not a DNS name or HTTPS authority.
    #[arg(long)]
    name: String,
    /// Publisher-defined nonzero revision; this does not provide latest-version discovery.
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    revision: u64,
    /// Authenticated media type, such as application/octet-stream.
    #[arg(long, default_value = "application/octet-stream")]
    content_type: String,
    /// Signed lifetime in seconds (at most 31 days); reading never extends validity.
    #[arg(long, default_value_t = 86_400, value_parser = clap::value_parser!(u64).range(1..=MAX_VALIDITY_SECONDS))]
    lifetime_seconds: u64,
    /// Existing encrypted identity file; defaults to the normal node identity path.
    #[arg(long)]
    identity: Option<PathBuf>,
    /// Existing strict 0600 passphrase file; otherwise prompt without echo.
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
    #[command(flatten)]
    limits: Limits,
}

#[derive(Debug, Args)]
pub(crate) struct Assemble {
    /// Exact bounded canonical signed manifest, not a URL or name lookup.
    #[arg(long)]
    manifest: PathBuf,
    /// Independently trusted 32-byte Ed25519 public key as 64 hex characters.
    /// Do not obtain this trust anchor from an untrusted manifest/provider.
    #[arg(long, value_parser = parse_publisher_key)]
    publisher_key: VerifyingKey,
    /// Repeat for 1 through 16 explicitly owned local cache directories.
    #[arg(long, required = true)]
    cache: Vec<PathBuf>,
    /// New output file, exposed atomically only after complete verification.
    #[arg(long)]
    output: PathBuf,
    #[command(flatten)]
    limits: Limits,
}

#[derive(Debug, Args)]
struct Limits {
    /// Maximum chunk payload bytes in each cache; opening never evicts to fit.
    #[arg(long, default_value_t = MAX_OBJECT_BYTES, value_parser = clap::value_parser!(u64).range(1..))]
    quota_bytes: u64,
    /// Maximum indexed chunks per cache (1 through 65536).
    #[arg(long, default_value_t = 4096, value_parser = clap::value_parser!(u32).range(1..=65_536))]
    max_entries: u32,
    /// Free filesystem bytes to preserve before insertion; zero explicitly disables the floor.
    #[arg(long, default_value_t = 64 * 1024 * 1024)]
    min_free_bytes: u64,
}

impl Limits {
    fn cache_limits(&self) -> Result<CacheLimits> {
        Ok(CacheLimits {
            max_bytes: self.quota_bytes,
            max_entries: usize::try_from(self.max_entries)
                .context("cache entry count exceeds this platform")?,
            min_free_bytes: self.min_free_bytes,
        })
    }
}

pub(crate) async fn run(command: Command, socket: &Path) -> Result<()> {
    use volparossa_local_control::{
        ContentFetchRequest, ContentServeRequest, Empty, control_request::Operation,
    };
    let report = match command {
        Command::Publish(args) => publish(&args)?,
        Command::Assemble(args) => assemble(&args)?,
        Command::Serve(args) => {
            let replication = args
                .replication
                .wire_config(&args.cache, args.limits.min_free_bytes)?;
            let operation = Operation::ContentServe(ContentServeRequest {
                manifest: verified_manifest_bytes(&args.manifest, &args.publisher_key)?,
                publisher_key: args.publisher_key.to_bytes().to_vec(),
                cache: absolute_path(&args.cache)?,
                bind_address: args.bind.to_string(),
                advertised_hostname: args.advertised_hostname,
                limits: Some(args.limits.wire_limits()),
                replication,
            });
            return super::print_response(super::control::request(socket, operation).await?);
        }
        Command::Fetch(args) => {
            let operation = Operation::ContentFetch(ContentFetchRequest {
                manifest: verified_manifest_bytes(&args.manifest, &args.publisher_key)?,
                publisher_key: args.publisher_key.to_bytes().to_vec(),
                cache: absolute_path(&args.cache)?,
                output: absolute_path(&args.output)?,
                limits: Some(args.limits.wire_limits()),
            });
            return super::print_response(super::control::request(socket, operation).await?);
        }
        Command::FetchHttps(args) => {
            let operation = Operation::ContentFetchHttps(https_fetch_request(&args)?);
            return super::print_response(super::control::request(socket, operation).await?);
        }
        Command::Stop => {
            return super::print_response(
                super::control::request(socket, Operation::ContentStop(Empty {})).await?,
            );
        }
        Command::Status => {
            return super::print_response(
                super::control::request(socket, Operation::ContentStatus(Empty {})).await?,
            );
        }
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn parse_origin_url(value: &str) -> Result<String, String> {
    volparossa_content::origin_https::OriginRequest::new(value, "/")
        .map_err(|_| "expected a canonical HTTPS URL without credentials or fragment".to_owned())?;
    Ok(value.to_owned())
}

fn parse_metadata_path(value: &str) -> Result<String, String> {
    volparossa_content::origin_https::OriginRequest::new("https://metadata.invalid/", value)
        .map_err(|_| "expected an exact canonical same-origin metadata path".to_owned())?;
    Ok(value.to_owned())
}

fn https_fetch_request(
    args: &FetchHttps,
) -> Result<volparossa_local_control::HttpsContentFetchRequest> {
    const MAX_CA_BYTES: u64 = 128 * 1024;
    volparossa_content::origin_https::OriginRequest::new(&args.url, &args.metadata_path)
        .context("invalid canonical HTTPS resource or same-origin metadata path")?;
    let mut ca_certificates_pem = Vec::new();
    if let Some(path) = args.ca_file.as_deref() {
        open_regular(path, MAX_CA_BYTES)?
            .take(MAX_CA_BYTES + 1)
            .read_to_end(&mut ca_certificates_pem)?;
        if ca_certificates_pem.is_empty() || ca_certificates_pem.len() > 128 * 1024 {
            bail!("explicit CA file must contain 1 through 131072 bytes of public PEM roots");
        }
        validate_public_ca_pem(&ca_certificates_pem)?;
    }
    Ok(volparossa_local_control::HttpsContentFetchRequest {
        resource_url: args.url.clone(),
        metadata_path: args.metadata_path.clone(),
        cache: absolute_path(&args.cache)?,
        output: absolute_path(&args.output)?,
        limits: Some(args.limits.wire_limits()),
        ca_certificates_pem,
    })
}

fn validate_public_ca_pem(bytes: &[u8]) -> Result<()> {
    let text = std::str::from_utf8(bytes).context("public CA PEM must be UTF-8")?;
    let mut found_certificate = false;
    for line in text.lines().map(str::trim) {
        if line.contains("-----BEGIN") || line.contains("-----END") {
            match line {
                "-----BEGIN CERTIFICATE-----" => found_certificate = true,
                "-----END CERTIFICATE-----" => {}
                _ => bail!("CA file may contain only public CERTIFICATE PEM blocks"),
            }
        }
    }
    if !found_certificate {
        bail!("CA file contains no public CERTIFICATE PEM block");
    }
    // The agent independently parses certificate DER and checks TLS trust; this is only a
    // bounded local-file preflight so an accidentally selected private-key PEM is not sent.
    Ok(())
}

impl Limits {
    fn wire_limits(&self) -> volparossa_local_control::ContentCacheLimits {
        volparossa_local_control::ContentCacheLimits {
            quota_bytes: self.quota_bytes,
            max_entries: self.max_entries,
            min_free_bytes: self.min_free_bytes,
        }
    }
}

fn absolute_path(path: &Path) -> Result<String> {
    std::path::absolute(path)?
        .into_os_string()
        .into_string()
        .map_err(|_| anyhow::anyhow!("content path must be UTF-8"))
}

fn verified_manifest_bytes(path: &Path, publisher: &VerifyingKey) -> Result<Vec<u8>> {
    let mut bytes = Vec::new();
    open_regular(path, MAX_MANIFEST_BYTES as u64)?
        .take(MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    SignedManifest::decode(&bytes)?.verify(publisher, now_seconds()?)?;
    Ok(bytes)
}

fn publish(args: &Publish) -> Result<serde_json::Value> {
    ensure_new_output(&args.manifest)?;
    let mut input = open_regular(&args.input, MAX_OBJECT_BYTES)?;
    let length = input.metadata()?.len();
    let now = now_seconds()?;
    let expires = now
        .checked_add(args.lifetime_seconds)
        .context("content expiry overflows its timestamp")?;
    let identity_path = args
        .identity
        .clone()
        .unwrap_or_else(super::default_identity_path);
    let passphrase = super::secret::read_passphrase(args.passphrase_file.as_deref(), false)?;
    let identity = IdentityStore::new(identity_path)
        .load(&passphrase)
        .context("cannot unlock existing publisher identity; content publish never creates one")?;
    drop(passphrase);
    let expected_public = identity.ed25519_public_key_bytes()?;
    // libp2p-identity 0.2.14 documents this exact 64-byte encoding as dalek's
    // keypair format. Consume the unlocked keypair, keep the only encoded
    // intermediate zeroizing and in memory, and never call secret(). Both
    // keypair wrappers use dalek SigningKey with its zeroize-on-drop feature.
    let keypair = identity.into_keypair().try_into_ed25519()?;
    let encoded = Zeroizing::new(keypair.to_bytes());
    let signer = SigningKey::from_keypair_bytes(&encoded)
        .context("existing publisher keypair has invalid Ed25519 encoding")?;
    drop(encoded);
    drop(keypair);
    if signer.verifying_key().to_bytes() != expected_public {
        bail!("publisher public key changed during signing-key conversion");
    }
    let mut manifest_output = tempfile::NamedTempFile::new_in(output_parent(&args.manifest))?;
    let limits = args.limits.cache_limits()?;
    let mut cache = if args.reuse_cache {
        ChunkStore::open(&args.cache, limits)
    } else {
        ChunkStore::create(&args.cache, limits)
    }
    .context("cannot create/open the explicitly selected owned content cache")?;
    let manifest = volparossa_content::publish(
        &mut input,
        Publication {
            metadata: Metadata {
                name: args.name.clone(),
                revision: args.revision,
                content_type: args.content_type.clone(),
            },
            length,
            validity: Validity {
                created: now,
                expires,
            },
        },
        &signer,
        &mut cache,
    )?;
    let verified = manifest.verify(&signer.verifying_key(), now)?;
    drop(signer);
    manifest_output.write_all(&manifest.encode())?;
    manifest_output.as_file().sync_all()?;
    manifest_output
        .persist_noclobber(&args.manifest)
        .map_err(|error| error.error)
        .context("cannot publish new manifest without overwriting an existing entry")?;
    Ok(serde_json::json!({
        "operation": "offline_content_publish",
        "network_publication": false,
        "manifest": args.manifest,
        "cache": args.cache,
        "publisher_key_hex": hex::encode(expected_public),
        "bytes": verified.length(),
        "chunks": verified.chunks().len(),
        "expires_unix_seconds": expires,
    }))
}

fn assemble(args: &Assemble) -> Result<serde_json::Value> {
    if args.cache.is_empty() || args.cache.len() > MAX_SOURCES {
        bail!("content assemble requires 1 through {MAX_SOURCES} explicit cache paths");
    }
    ensure_new_output(&args.output)?;
    let input = open_regular(&args.manifest, MAX_MANIFEST_BYTES as u64)?;
    let mut encoded = Vec::new();
    input
        .take(MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut encoded)?;
    let now = now_seconds()?;
    let manifest = SignedManifest::decode(&encoded)?.verify(&args.publisher_key, now)?;
    let limits = args.limits.cache_limits()?;
    let mut caches = args
        .cache
        .iter()
        .map(|path| ChunkStore::open(path, limits))
        .collect::<Result<Vec<_>, _>>()?;
    let bytes = volparossa_content::reassemble_to_file(
        &manifest,
        &mut caches.iter_mut().collect::<Vec<_>>(),
        now,
        &args.output,
    )?;
    Ok(serde_json::json!({
        "operation": "offline_content_assemble",
        "network_retrieval": false,
        "output": args.output,
        "publisher_key_hex": hex::encode(manifest.publisher()),
        "bytes": bytes,
        "chunks": manifest.chunks().len(),
    }))
}

fn parse_publisher_key(value: &str) -> Result<VerifyingKey, String> {
    let mut bytes = [0; 32];
    if value.len() != 64 {
        return Err("publisher key must be exactly 64 hexadecimal characters".to_owned());
    }
    hex::decode_to_slice(value, &mut bytes).map_err(|error| error.to_string())?;
    VerifyingKey::from_bytes(&bytes).map_err(|error| error.to_string())
}

fn now_seconds() -> Result<u64> {
    Ok(SystemTime::now().duration_since(UNIX_EPOCH)?.as_secs())
}

fn open_regular(path: &Path, maximum: u64) -> Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK | libc::O_CLOEXEC)
        .open(path)
        .with_context(|| format!("cannot open local file {}", path.display()))?;
    let metadata = file.metadata()?;
    if !metadata.is_file() || metadata.len() > maximum {
        bail!("input must be a bounded regular file (maximum {maximum} bytes)");
    }
    Ok(file)
}

fn output_parent(path: &Path) -> &Path {
    path.parent()
        .filter(|parent| !parent.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."))
}

fn ensure_new_output(path: &Path) -> Result<()> {
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(error) => Err(error.into()),
        Ok(_) => bail!(
            "output already exists; nothing will be overwritten: {}",
            path.display()
        ),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use std::os::unix::fs::PermissionsExt as _;
    use volparossa_content::CHUNK_BYTES;
    use volparossa_identity::Passphrase;

    fn limits() -> Limits {
        Limits {
            quota_bytes: 1024 * 1024,
            max_entries: 16,
            min_free_bytes: 0,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One CLI fixture covers opt-in, inherited defaults and bounds.
    fn content_replication_requires_an_explicit_distinct_cache_and_bounded_options() {
        let key = hex::encode(
            SigningKey::generate(&mut rand_core::OsRng)
                .verifying_key()
                .to_bytes(),
        );
        let base = [
            "volparossa",
            "content",
            "serve",
            "--manifest",
            "exact.pb",
            "--publisher-key",
            &key,
            "--cache",
            "primary",
            "--bind",
            "127.0.0.1:18080",
            "--advertised-hostname",
            "provider.example",
        ];
        let parse = |extra: &[&str]| {
            let parsed =
                crate::Cli::try_parse_from(base.iter().copied().chain(extra.iter().copied()))?;
            let crate::CliCommand::Content { command } = parsed.command else {
                panic!("content command expected");
            };
            let Command::Serve(serve) = *command else {
                panic!("serve expected")
            };
            Ok::<_, clap::Error>(serve)
        };
        let inert = parse(&[]).expect("existing serve command remains inert");
        assert!(
            inert
                .replication
                .wire_config(&inert.cache, inert.limits.min_free_bytes)
                .unwrap()
                .is_none()
        );
        let enabled = parse(&["--replica-cache", "new-replicas"]).expect("explicit opt-in");
        let configuration = enabled
            .replication
            .wire_config(&enabled.cache, enabled.limits.min_free_bytes)
            .unwrap()
            .expect("replication requested");
        assert_eq!(
            configuration.replica_cache,
            absolute_path(Path::new("new-replicas")).unwrap()
        );
        assert_eq!(
            (configuration.max_bytes, configuration.max_chunks),
            (1024 * 1024, 4)
        );
        assert_eq!(
            configuration.limits.unwrap(),
            volparossa_local_control::ContentCacheLimits {
                quota_bytes: 64 * 1024 * 1024,
                max_entries: 256,
                min_free_bytes: 64 * 1024 * 1024,
            }
        );
        let same = parse(&["--replica-cache", "primary"]).expect("path checked before dispatch");
        assert!(same.replication.wire_config(&same.cache, 0).is_err());
        let floor = parse(&[
            "--replica-cache",
            "new-replicas",
            "--min-free-bytes",
            "1234",
        ])
        .expect("explicit inherited free-space floor");
        assert_eq!(
            floor
                .replication
                .wire_config(&floor.cache, floor.limits.min_free_bytes)
                .unwrap()
                .unwrap()
                .limits
                .unwrap()
                .min_free_bytes,
            1234
        );
        for (name, invalid) in [
            ("--replica-quota-bytes", "268435457"),
            ("--replica-max-entries", "65537"),
            ("--replica-max-bytes", "1048577"),
            ("--replica-max-chunks", "5"),
            ("--replica-max-bytes", "0"),
            ("--replica-max-bytes", "63"),
            ("--replica-max-chunks", "0"),
        ] {
            assert!(
                parse(&["--replica-cache", "new-replicas", name, invalid]).is_err(),
                "{name}"
            );
        }
        for option in [
            "--replica-quota-bytes",
            "--replica-max-entries",
            "--replica-max-bytes",
            "--replica-max-chunks",
        ] {
            assert!(
                parse(&[option, "1"]).is_err(),
                "limits alone must not silently enable replication"
            );
        }
    }

    #[test]
    fn https_fetch_cli_parses_canonical_origin_without_a_publisher_key() {
        let args = [
            "volparossa",
            "content",
            "fetch-https",
            "--url",
            "https://origin.example/object.bin",
            "--metadata-path",
            "/.well-known/volparossa/object",
            "--cache",
            "new-cache",
            "--output",
            "new.bin",
        ];
        assert!(crate::Cli::try_parse_from(args).is_ok());
        let mut explicit_ca = args.to_vec();
        explicit_ca.extend(["--ca-file", "explicit-public-roots.pem"]);
        assert!(crate::Cli::try_parse_from(explicit_ca).is_ok());
        for url in [
            "http://origin.example/object.bin",
            "https://user:pass@origin.example/object.bin",
            "https://origin.example/object.bin#fragment",
            "https://127.0.0.1/object.bin",
            "https://ORIGIN.example/object.bin",
            "https://origin.example/a/../object.bin",
        ] {
            let mut invalid = args;
            invalid[4] = url;
            assert!(crate::Cli::try_parse_from(invalid).is_err(), "{url}");
        }
        for metadata in [
            "//elsewhere.example/metadata",
            "/a/../metadata",
            "/metadata#fragment",
            "/metadata\r\n",
        ] {
            let mut invalid = args;
            invalid[6] = metadata;
            assert!(crate::Cli::try_parse_from(invalid).is_err());
        }
        let mut independent_key = args.to_vec();
        independent_key.extend(["--publisher-key", "not-origin-authority"]);
        assert!(crate::Cli::try_parse_from(independent_key).is_err());
    }

    #[test]
    fn https_fetch_request_uses_explicit_bounded_regular_ca_file_without_creating_outputs() {
        let directory = tempfile::tempdir().expect("private fixture directory");
        let root = directory.path();
        let mut args = FetchHttps {
            url: "https://origin.example/object.bin".into(),
            metadata_path: "/metadata".into(),
            cache: root.join("new-cache"),
            output: root.join("new.bin"),
            ca_file: None,
            limits: limits(),
        };
        let default = https_fetch_request(&args).expect("Debian system roots selection");
        assert!(default.ca_certificates_pem.is_empty());
        assert_eq!(default.resource_url, args.url);
        assert_eq!(default.metadata_path, args.metadata_path);
        assert!(!args.cache.exists() && !args.output.exists());
        let pem = b"-----BEGIN CERTIFICATE-----\nZmFrZSBwdWJsaWMgdGVzdCBjZXJ0\n-----END CERTIFICATE-----\n";
        let path = root.join("roots.pem");
        fs::write(&path, pem).expect("public parser fixture only, not a TLS test");
        args.ca_file = Some(path.clone());
        assert_eq!(
            https_fetch_request(&args)
                .expect("bounded PEM")
                .ca_certificates_pem,
            pem
        );
        fs::write(&path, []).expect("empty explicit roots");
        assert!(https_fetch_request(&args).is_err());
        fs::write(
            &path,
            b"-----BEGIN PRIVATE KEY-----\nfixture-only\n-----END PRIVATE KEY-----\n",
        )
        .expect("non-secret invalid PEM fixture");
        assert!(https_fetch_request(&args).is_err());
        fs::write(&path, vec![0; 128 * 1024 + 1]).expect("oversized explicit roots");
        assert!(https_fetch_request(&args).is_err());
        let symlink = root.join("linked.pem");
        std::os::unix::fs::symlink(&path, &symlink).expect("fixture symlink");
        args.ca_file = Some(symlink);
        assert!(https_fetch_request(&args).is_err());
        args.ca_file = Some(root.into());
        assert!(https_fetch_request(&args).is_err());
        assert!(!args.cache.exists() && !args.output.exists());
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One fixture lifecycle includes its negative/no-clobber checks.
    fn offline_content_roundtrip_two_partial_caches_reuse_and_rejections() {
        let directory = tempfile::tempdir().expect("private fixture directory");
        let root = directory.path();
        let identity_path = root.join("identity.key");
        let password_file = root.join("passphrase");
        let password = b"explicit offline CLI fixture only";
        fs::write(&password_file, password).expect("fixture password");
        fs::set_permissions(&password_file, fs::Permissions::from_mode(0o600)).expect("private");
        let identity = IdentityStore::new(&identity_path)
            .create(&Passphrase::new(password).expect("fixture passphrase"))
            .expect("existing fixture identity");
        let public = VerifyingKey::from_bytes(&identity.ed25519_public_key_bytes().expect("key"))
            .expect("verification key");
        let encrypted_identity = fs::read(&identity_path).expect("encrypted identity");
        let mut bytes = vec![7; CHUNK_BYTES];
        bytes.extend_from_slice(&[9; 37]);
        let mut publish_args = Publish {
            input: root.join("input.bin"),
            cache: root.join("publisher-cache"),
            reuse_cache: false,
            manifest: root.join("manifest.pb"),
            name: "offline fixture".into(),
            revision: 1,
            content_type: "application/octet-stream".into(),
            lifetime_seconds: 300,
            identity: Some(identity_path.clone()),
            passphrase_file: Some(password_file),
            limits: limits(),
        };
        fs::write(&publish_args.input, &bytes).expect("fixture content");
        let report = publish(&publish_args).expect("offline publication");
        assert_eq!(report["network_publication"], false);
        assert_eq!(report["publisher_key_hex"], hex::encode(public.to_bytes()));
        let manifest_bytes = fs::read(&publish_args.manifest).expect("manifest");
        let manifest = SignedManifest::decode(&manifest_bytes)
            .expect("decode")
            .verify(&public, now_seconds().expect("clock"))
            .expect("identity signed");
        let cache_limits = limits().cache_limits().expect("limits");
        let first_path = root.join("first-cache");
        let second_path = root.join("second-cache");
        {
            let mut publisher =
                ChunkStore::open(&publish_args.cache, cache_limits).expect("reopen");
            let mut first = ChunkStore::create(&first_path, cache_limits).expect("first");
            let mut second = ChunkStore::create(&second_path, cache_limits).expect("second");
            first
                .put(
                    &publisher
                        .get(manifest.chunks()[0].id())
                        .expect("read")
                        .expect("chunk"),
                )
                .expect("first partial replica");
            second
                .put(
                    &publisher
                        .get(manifest.chunks()[1].id())
                        .expect("read")
                        .expect("chunk"),
                )
                .expect("second partial replica");
        }
        // Only this test's original input is removed; neither cache holds the whole object.
        fs::remove_file(&publish_args.input).expect("remove fixture original");
        let mut assemble_args = Assemble {
            manifest: publish_args.manifest.clone(),
            publisher_key: public,
            cache: vec![first_path, second_path],
            output: root.join("assembled.bin"),
            limits: limits(),
        };
        let result = assemble(&assemble_args).expect("two partial caches reconstruct");
        assert_eq!(result["bytes"], bytes.len());
        assert_eq!(fs::read(&assemble_args.output).expect("assembled"), bytes);
        assert_eq!(
            fs::metadata(&assemble_args.output)
                .expect("metadata")
                .permissions()
                .mode()
                & 0o777,
            0o600
        );
        assert!(
            assemble(&assemble_args)
                .expect_err("do not overwrite")
                .to_string()
                .contains("already exists")
        );
        assert_eq!(fs::read(&assemble_args.output).expect("preserved"), bytes);
        assert!(
            publish(&publish_args)
                .expect_err("manifest no-clobber")
                .to_string()
                .contains("already exists")
        );
        assert_eq!(
            fs::read(&publish_args.manifest).expect("preserved"),
            manifest_bytes
        );

        assemble_args.output = root.join("rejected.bin");
        assemble_args.publisher_key = SigningKey::from_bytes(&[13; 32]).verifying_key();
        assert!(matches!(
            assemble(&assemble_args)
                .expect_err("wrong publisher")
                .downcast_ref::<volparossa_content::Error>(),
            Some(volparossa_content::Error::WrongPublisher)
        ));
        assert!(!assemble_args.output.exists());
        assemble_args.publisher_key = public;
        let empty = root.join("empty-cache");
        drop(ChunkStore::create(&empty, cache_limits).expect("owned empty cache"));
        assemble_args.cache = vec![empty];
        assert!(matches!(
            assemble(&assemble_args)
                .expect_err("missing chunks")
                .downcast_ref::<volparossa_content::Error>(),
            Some(volparossa_content::Error::MissingChunk(_))
        ));
        assert!(!assemble_args.output.exists());
        assemble_args.cache = vec![root.join("not-opened"); MAX_SOURCES + 1];
        assert!(
            assemble(&assemble_args)
                .expect_err("bounded cache paths")
                .to_string()
                .contains("1 through 16")
        );

        fs::write(&publish_args.input, b"next explicit revision").expect("next input");
        publish_args.reuse_cache = true;
        publish_args.manifest = root.join("next-manifest.pb");
        publish_args.revision = 2;
        publish(&publish_args).expect("reuse an existing owned cache");
        assert_eq!(
            fs::read(&identity_path).expect("identity unchanged"),
            encrypted_identity
        );
        publish_args.manifest = root.join("foreign-cache-manifest.pb");
        publish_args.cache = root.join("unrelated-directory");
        fs::create_dir(&publish_args.cache).expect("foreign directory");
        let sentinel = publish_args.cache.join("unrelated.txt");
        fs::write(&sentinel, b"leave unchanged").expect("sentinel");
        assert!(publish(&publish_args).is_err());
        assert_eq!(
            fs::read(sentinel).expect("preserved unrelated file"),
            b"leave unchanged"
        );
        assert!(!publish_args.manifest.exists());
        publish_args.identity = Some(root.join("must-not-create-identity.key"));
        assert!(publish(&publish_args).is_err());
        assert!(!publish_args.identity.as_ref().expect("path").exists());
    }

    #[test]
    fn network_content_commands_parse_without_unlocking_a_publisher_identity() {
        let key = hex::encode(SigningKey::from_bytes(&[17; 32]).verifying_key().to_bytes());
        for action in ["serve", "fetch"] {
            let mut args = vec![
                "volparossa",
                "content",
                action,
                "--manifest",
                "exact.pb",
                "--publisher-key",
                &key,
                "--cache",
                "owned",
            ];
            if action == "serve" {
                args.extend([
                    "--bind",
                    "127.0.0.1:18080",
                    "--advertised-hostname",
                    "provider.example",
                ]);
            } else {
                args.extend(["--output", "new.bin"]);
            }
            assert!(crate::Cli::try_parse_from(args).is_ok());
        }
        assert!(crate::Cli::try_parse_from(["volparossa", "content", "stop"]).is_ok());
        assert!(crate::Cli::try_parse_from(["volparossa", "content", "status"]).is_ok());
        assert!(
            crate::Cli::try_parse_from([
                "volparossa",
                "content",
                "serve",
                "--manifest",
                "exact.pb",
                "--cache",
                "owned",
                "--bind",
                "127.0.0.1:18080",
                "--advertised-hostname",
                "provider.example"
            ])
            .is_err()
        );
    }

    #[test]
    fn content_cli_requires_independent_trust_and_rejects_unbounded_lifetime() {
        assert!(
            crate::Cli::try_parse_from([
                "volparossa",
                "content",
                "assemble",
                "--manifest",
                "exact.pb",
                "--cache",
                "owned",
                "--output",
                "new.bin",
            ])
            .is_err()
        );
        assert!(parse_publisher_key("00").is_err());
        assert!(parse_publisher_key(&"x".repeat(64)).is_err());
        assert!(
            crate::Cli::try_parse_from([
                "volparossa",
                "content",
                "publish",
                "--input",
                "input.bin",
                "--cache",
                "owned",
                "--manifest",
                "new.pb",
                "--name",
                "example",
                "--revision",
                "1",
                "--lifetime-seconds",
                "2678401",
            ])
            .is_err()
        );
    }
}
