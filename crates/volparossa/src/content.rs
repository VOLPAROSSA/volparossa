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
            let operation = Operation::ContentServe(ContentServeRequest {
                manifest: verified_manifest_bytes(&args.manifest, &args.publisher_key)?,
                publisher_key: args.publisher_key.to_bytes().to_vec(),
                cache: absolute_path(&args.cache)?,
                bind_address: args.bind.to_string(),
                advertised_hostname: args.advertised_hostname,
                limits: Some(args.limits.wire_limits()),
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
