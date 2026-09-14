//! Normal CLI access to recipient-encrypted publications; never starts networking implicitly.

use super::{
    Args, ChunkStore, Limits, MAX_SOURCES, MAX_VALIDITY_SECONDS, PathBuf, Result, SignedManifest,
    Validity, VerifyingKey, Zeroizing, bail, ensure_new_output, now_seconds, open_regular,
    output_parent, parse_publisher_key, unlock_signer, verified_manifest_bytes,
};
use anyhow::Context as _;
use std::{
    io::{Read as _, Write as _},
    os::unix::fs::PermissionsExt as _,
};
use volparossa_content::private_message::{
    MAX_PRIVATE_MESSAGE_BYTES, RecipientKeyPair, open_private_message, publish_private_message,
};

#[derive(Debug, Args)]
pub(crate) struct Unlock {
    /// Existing encrypted node identity; never creates or exports a private key.
    #[arg(long)]
    identity: Option<PathBuf>,
    /// Existing strict 0600 passphrase file; otherwise prompt without echo.
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
}

impl Unlock {
    pub(super) fn signer(&self) -> Result<ed25519_dalek::SigningKey> {
        unlock_signer(self.identity.as_deref(), self.passphrase_file.as_deref())
    }
}

#[derive(Debug, Args)]
pub(crate) struct PublishMessage {
    /// Explicit plaintext regular file, at most 4 MiB; not stored in the content cache.
    #[arg(long)]
    input: PathBuf,
    /// Independently authenticated recipient X25519 public key, not their Ed25519 key.
    #[arg(long, value_parser = parse_recipient_key)]
    recipient_key: [u8; 32],
    /// New private cache directory, unless --reuse-cache opens an existing owned cache.
    #[arg(long)]
    cache: PathBuf,
    /// Explicitly reuse an owned cache; quota enforcement may evict older chunks.
    #[arg(long)]
    reuse_cache: bool,
    /// New signed manifest file; never overwritten. Share this and the sender key separately.
    #[arg(long)]
    manifest: PathBuf,
    /// Signed lifetime in seconds; reads and replication never extend it.
    #[arg(long, default_value_t = 86_400, value_parser = clap::value_parser!(u64).range(1..=MAX_VALIDITY_SECONDS))]
    lifetime_seconds: u64,
    #[command(flatten)]
    unlock: Unlock,
    #[command(flatten)]
    limits: Limits,
}

#[derive(Debug, Args)]
pub(crate) struct OpenMessage {
    /// Exact signed private-message manifest, supplied separately from storage peers.
    #[arg(long)]
    manifest: PathBuf,
    /// Independently trusted sender Ed25519 public key; never inferred from cached metadata.
    #[arg(long, value_parser = parse_publisher_key)]
    sender_key: VerifyingKey,
    /// Repeat for 1 through 16 owned caches containing the retrieved ciphertext chunks.
    #[arg(long, required = true)]
    cache: Vec<PathBuf>,
    /// Explicit new plaintext output; atomically exposed at mode 0600 after decryption.
    #[arg(long)]
    output: PathBuf,
    #[command(flatten)]
    unlock: Unlock,
    #[command(flatten)]
    limits: Limits,
}

pub(super) fn recipient_key(args: &Unlock) -> Result<serde_json::Value> {
    let signer = args.signer()?;
    let recipient = RecipientKeyPair::from_node_identity(&signer)?;
    Ok(serde_json::json!({
        "operation": "message_recipient_key",
        "profile": "volparossa/message-recipient/v1",
        "recipient_public_key_hex": hex::encode(recipient.public_key()),
        "identity_public_key_hex": hex::encode(signer.verifying_key().to_bytes()),
        "private_key_exported": false,
        "network_publication": false,
    }))
}

pub(super) fn publish_message(args: &PublishMessage) -> Result<serde_json::Value> {
    ensure_new_output(&args.manifest)?;
    let mut plaintext = Zeroizing::new(Vec::new());
    open_regular(&args.input, MAX_PRIVATE_MESSAGE_BYTES as u64)?
        .take(MAX_PRIVATE_MESSAGE_BYTES as u64 + 1)
        .read_to_end(&mut plaintext)?;
    if plaintext.len() > MAX_PRIVATE_MESSAGE_BYTES {
        bail!("private message grew beyond the 4 MiB limit");
    }
    let signer = args.unlock.signer()?;
    let now = now_seconds()?;
    let expires = now
        .checked_add(args.lifetime_seconds)
        .context("message expiry overflow")?;
    let mut output = tempfile::NamedTempFile::new_in(output_parent(&args.manifest))?;
    let limits = args.limits.cache_limits()?;
    let mut cache = if args.reuse_cache {
        ChunkStore::open(&args.cache, limits)
    } else {
        ChunkStore::create(&args.cache, limits)
    }
    .context("cannot create/open the explicitly selected owned message cache")?;
    let manifest = publish_private_message(
        &plaintext,
        &args.recipient_key,
        &signer,
        Validity {
            created: now,
            expires,
        },
        &mut cache,
    )?;
    drop(plaintext);
    let verified = manifest.verify(&signer.verifying_key(), now)?;
    drop(signer);
    output.write_all(&manifest.encode())?;
    output.as_file().sync_all()?;
    output
        .persist_noclobber(&args.manifest)
        .map_err(|error| error.error)
        .context("cannot publish message manifest without overwriting an existing entry")?;
    Ok(serde_json::json!({
        "operation": "offline_private_message_publish",
        "network_publication": false,
        "manifest": args.manifest,
        "cache": args.cache,
        "publisher_key_hex": hex::encode(verified.publisher()),
        "ciphertext_bytes": verified.length(),
        "chunks": verified.chunks().len(),
        "expires_unix_seconds": expires,
    }))
}

pub(super) fn open_message(args: &OpenMessage) -> Result<serde_json::Value> {
    if args.cache.is_empty() || args.cache.len() > MAX_SOURCES {
        bail!("message opening requires 1 through {MAX_SOURCES} explicit cache paths");
    }
    ensure_new_output(&args.output)?;
    let encoded = verified_manifest_bytes(&args.manifest, &args.sender_key)?;
    let signer = args.unlock.signer()?;
    let recipient = RecipientKeyPair::from_node_identity(&signer)?;
    drop(signer);
    let now = now_seconds()?;
    let manifest = SignedManifest::decode(&encoded)?.verify(&args.sender_key, now)?;
    let limits = args.limits.cache_limits()?;
    let mut caches = args
        .cache
        .iter()
        .map(|path| ChunkStore::open(path, limits))
        .collect::<Result<Vec<_>, _>>()?;
    let plaintext = open_private_message(
        &manifest,
        &mut caches.iter_mut().collect::<Vec<_>>(),
        now,
        &recipient,
    )?;
    let mut output = tempfile::NamedTempFile::new_in(output_parent(&args.output))?;
    output
        .as_file()
        .set_permissions(std::fs::Permissions::from_mode(0o600))?;
    output.write_all(&plaintext)?;
    let bytes = plaintext.len();
    drop(plaintext);
    output.as_file().sync_all()?;
    output
        .persist_noclobber(&args.output)
        .map_err(|error| error.error)
        .context("cannot expose message plaintext without overwriting an existing entry")?;
    Ok(serde_json::json!({
        "operation": "offline_private_message_open",
        "network_retrieval": false,
        "output": args.output,
        "bytes": bytes,
    }))
}

fn parse_recipient_key(value: &str) -> Result<[u8; 32], String> {
    let mut key = [0; 32];
    if value.len() != 64 {
        return Err("recipient key must be exactly 64 hexadecimal characters".into());
    }
    hex::decode_to_slice(value, &mut key).map_err(|error| error.to_string())?;
    Ok(key)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;
    use std::fs;
    use volparossa_content::CHUNK_BYTES;
    use volparossa_identity::{IdentityStore, Passphrase};

    fn limits() -> Limits {
        Limits {
            quota_bytes: 1024 * 1024,
            max_entries: 16,
            min_free_bytes: 0,
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)] // One real encrypted-identity lifecycle and split-cache CLI smoke.
    fn private_message_cli_restarts_reconstructs_and_rejects_wrong_identity() {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let pass = root.join("passphrase");
        let password = b"private message CLI fixture password";
        fs::write(&pass, password).unwrap();
        fs::set_permissions(&pass, fs::Permissions::from_mode(0o600)).unwrap();
        let unlock = |name: &str| Unlock {
            identity: Some(root.join(name)),
            passphrase_file: Some(pass.clone()),
        };
        for name in ["sender", "recipient", "wrong"] {
            IdentityStore::new(root.join(name))
                .create(&Passphrase::new(password).unwrap())
                .unwrap();
        }
        let encrypted_identity = fs::read(root.join("recipient")).unwrap();
        let first_key = recipient_key(&unlock("recipient")).unwrap();
        assert_eq!(first_key, recipient_key(&unlock("recipient")).unwrap());
        let key = first_key["recipient_public_key_hex"].as_str().unwrap();
        let sender = unlock("sender").signer().unwrap().verifying_key();
        let mut bytes = vec![0x6d; CHUNK_BYTES];
        bytes.extend_from_slice(b"only the intended recipient receives this plaintext");
        let args = PublishMessage {
            input: root.join("plaintext"),
            recipient_key: parse_recipient_key(key).unwrap(),
            cache: root.join("ciphertext"),
            reuse_cache: false,
            manifest: root.join("manifest.pb"),
            lifetime_seconds: 300,
            unlock: unlock("sender"),
            limits: limits(),
        };
        fs::write(&args.input, &bytes).unwrap();
        assert!(
            crate::Cli::try_parse_from([
                "volparossa",
                "content",
                "publish-message",
                "--input",
                "plaintext",
                "--recipient-key",
                key,
                "--cache",
                "ciphertext",
                "--manifest",
                "manifest.pb",
            ])
            .is_ok()
        );
        let published = publish_message(&args).unwrap();
        assert_eq!(published["network_publication"], false);
        assert_eq!(published["chunks"], 2);
        let manifest_bytes = fs::read(&args.manifest).unwrap();
        let manifest = SignedManifest::decode(&manifest_bytes)
            .unwrap()
            .verify(&sender, now_seconds().unwrap())
            .unwrap();
        let partials = [root.join("partial-a"), root.join("partial-b")];
        let cache_limits = limits().cache_limits().unwrap();
        {
            let mut source = ChunkStore::open(&args.cache, cache_limits).unwrap();
            for (chunk, path) in manifest.chunks().iter().zip(&partials) {
                let ciphertext = source.get(chunk.id()).unwrap().unwrap();
                assert!(!ciphertext.windows(32).any(|window| window == &bytes[..32]));
                ChunkStore::create(path, cache_limits)
                    .unwrap()
                    .put(&ciphertext)
                    .unwrap();
            }
        }
        fs::remove_file(&args.input).unwrap(); // Only this fixture's explicit original.
        let mut open = OpenMessage {
            manifest: args.manifest.clone(),
            sender_key: sender,
            cache: partials.to_vec(),
            output: root.join("decrypted"),
            unlock: unlock("wrong"),
            limits: limits(),
        };
        assert!(open_message(&open).is_err());
        assert!(!open.output.exists());
        open.unlock = unlock("recipient");
        open.sender_key = unlock("wrong").signer().unwrap().verifying_key();
        assert!(open_message(&open).is_err());
        assert!(!open.output.exists());
        open.sender_key = sender;
        open_message(&open).unwrap();
        assert_eq!(fs::read(&open.output).unwrap(), bytes);
        assert_eq!(
            fs::metadata(&open.output).unwrap().permissions().mode() & 0o777,
            0o600
        );
        assert!(open_message(&open).is_err());
        assert_eq!(fs::read(&open.output).unwrap(), bytes);
        assert_eq!(
            fs::read(root.join("recipient")).unwrap(),
            encrypted_identity
        );
        assert_eq!(fs::read(&args.manifest).unwrap(), manifest_bytes);

        let changed_password = b"changed message CLI fixture password";
        IdentityStore::new(root.join("recipient"))
            .change_passphrase(
                &Passphrase::new(password).unwrap(),
                &Passphrase::new(changed_password).unwrap(),
            )
            .unwrap();
        fs::write(&pass, changed_password).unwrap();
        assert_eq!(recipient_key(&unlock("recipient")).unwrap(), first_key);
        open.output = root.join("decrypted-after-passphrase-change");
        open_message(&open).unwrap();
        assert_eq!(fs::read(&open.output).unwrap(), bytes);
    }
}
