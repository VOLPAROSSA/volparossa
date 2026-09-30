//! Private local fetch/import handoff; the application, not this CLI, proves its own import.

use std::{
    fs,
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, MetadataExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use sha2::{Digest as _, Sha256};
use volparossa_content::{
    mailbox::{
        import::{MAX_IMPORT_RECEIPT_BYTES, SignedImportReceipt},
        wire::MailboxOperation,
    },
    private_message::RecipientKeyPair,
};
use zeroize::Zeroizing;

use super::{Receive, ensure_new_output, now_seconds, open_regular, output_parent, private_file};
use crate::content::private_message::Unlock;

#[derive(Debug, Args)]
pub(crate) struct Confirm {
    /// Original owner-signed pending.pb in its private per-message handoff directory.
    #[arg(long)]
    pending: PathBuf,
    /// Original private import-token from the same handoff directory; never a command-line secret.
    #[arg(long)]
    import_token_file: PathBuf,
    /// SHA-256 of exact bytes durably imported by the consumer, not an email Message-ID.
    #[arg(long, value_parser = parse_digest)]
    imported_sha256: [u8; 32],
    #[command(flatten)]
    unlock: Unlock,
}

fn parse_digest(value: &str) -> std::result::Result<[u8; 32], String> {
    let mut digest = [0; 32];
    if value.len() != 64 {
        return Err("import digest must be 64 hexadecimal characters".into());
    }
    hex::decode_to_slice(value, &mut digest).map_err(|_| "invalid import digest".to_owned())?;
    Ok(digest)
}

fn owned_directory(path: &Path) -> Result<PathBuf> {
    let canonical = fs::canonicalize(path)?;
    let info = fs::symlink_metadata(path)?;
    ensure!(
        info.is_dir()
            && info.uid() == nix::unistd::geteuid().as_raw()
            && info.mode() & 0o777 == 0o700,
        "handoff directory must be private and owned"
    );
    Ok(canonical)
}

fn private_read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    let file = open_regular(path, maximum)?;
    let info = file.metadata()?;
    ensure!(
        info.uid() == nix::unistd::geteuid().as_raw()
            && info.mode() & 0o777 == 0o600
            && info.nlink() == 1,
        "handoff file must be private, owned and unaliased"
    );
    let mut bytes = Vec::new();
    file.take(maximum + 1).read_to_end(&mut bytes)?;
    ensure!(bytes.len() as u64 <= maximum, "handoff file exceeds bound");
    Ok(bytes)
}

pub(super) async fn fetch(args: &Receive, socket: &Path) -> Result<serde_json::Value> {
    ensure_new_output(&args.output_dir)?;
    let signer = args.unlock.signer()?;
    let grant = super::read_grant(&args.invitation, &signer.verifying_key())?;
    let recipient = RecipientKeyPair::from_node_identity(&signer)?;
    ensure!(
        recipient.public_key() == grant.recipient_key(),
        "wrong mailbox recipient encryption key"
    );
    let inbox = super::inbox(socket, &grant, &signer).await?;
    let mut total = 0_u64;
    for publication in inbox.messages.values() {
        let manifest = publication.verify(
            &ed25519_dalek::VerifyingKey::from_bytes(grant.sender_key())?,
            now_seconds()?,
        )?;
        total = total
            .checked_add(manifest.length())
            .context("handoff size overflow")?;
    }
    ensure!(
        total <= grant.max_bytes().min(args.limits.cache_limits()?.max_bytes),
        "aggregate handoff exceeds explicit mailbox/cache byte quota"
    );
    fs::DirBuilder::new().mode(0o700).create(&args.output_dir)?;
    fs::File::open(output_parent(&args.output_dir))?.sync_all()?;
    let root = owned_directory(&args.output_dir)?;
    let mut pending = Vec::new();
    for (id, publication) in &inbox.messages {
        let plaintext =
            super::fetch_plaintext(args, socket, &grant, &signer, &recipient, *id, publication)
                .await?;
        let mut token = Zeroizing::new([0_u8; 32]);
        getrandom::fill(token.as_mut())
            .map_err(|_| anyhow::anyhow!("mailbox handoff randomness unavailable"))?;
        let receipt = SignedImportReceipt::sign(
            &signer,
            &grant,
            publication,
            &plaintext,
            &token,
            now_seconds()?,
        )?;
        let directory = root.join(hex::encode(id));
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        fs::File::open(&root)?.sync_all()?;
        private_file(&directory.join("payload"), &plaintext)?;
        private_file(&directory.join("import-token"), token.as_ref())?;
        // Published last: pending.pb exists only after payload and token are durably present.
        private_file(&directory.join("pending.pb"), &receipt.encode())?;
        pending.push(serde_json::json!({"message_id":hex::encode(id),
            "payload":directory.join("payload"), "pending":directory.join("pending.pb"),
            "import_token_file":directory.join("import-token")}));
    }
    Ok(
        serde_json::json!({"operation":"mailbox_fetch", "messages_fetched":pending.len(),
        "messages_discovered":inbox.messages.len(), "listed_providers":inbox.listed_providers,
        "degraded":inbox.listed_providers != 2, "output_dir":root, "pending":pending,
        "acknowledged_providers_per_message":0, "consumer_import_attested":false,
        "application_import_proven":false, "provider_custody_consumed":false}),
    )
}

fn replace_progress(path: &Path, value: &serde_json::Value) -> Result<()> {
    if fs::symlink_metadata(path).is_ok() {
        // Existing progress is diagnostic only: no ACK is skipped on its authority.
        private_read(path, 32768)?;
    }
    let mut temporary = tempfile::NamedTempFile::new_in(output_parent(path))?;
    temporary
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    temporary.write_all(&serde_json::to_vec(value)?)?;
    temporary.as_file().sync_all()?;
    temporary.persist(path).map_err(|error| error.error)?;
    fs::File::open(output_parent(path))?.sync_all()?;
    Ok(())
}

pub(super) async fn confirm(args: &Confirm, socket: &Path) -> Result<serde_json::Value> {
    let signer = args.unlock.signer()?;
    let root = owned_directory(output_parent(&args.pending))?;
    ensure!(
        args.pending
            .file_name()
            .is_some_and(|name| name == "pending.pb")
            && fs::canonicalize(&args.pending)? == root.join("pending.pb")
            && args
                .import_token_file
                .file_name()
                .is_some_and(|name| name == "import-token")
            && fs::canonicalize(&args.import_token_file)? == root.join("import-token"),
        "confirmation must use the exact handoff receipt and token"
    );
    let bytes = private_read(&args.pending, MAX_IMPORT_RECEIPT_BYTES as u64)?;
    let checked =
        SignedImportReceipt::decode(&bytes)?.verify(&signer.verifying_key(), now_seconds()?)?;
    let token = Zeroizing::new(private_read(&args.import_token_file, 32)?);
    let token: &[u8; 32] = token
        .as_slice()
        .try_into()
        .context("invalid confirmation token length")?;
    checked.confirm(token, &args.imported_sha256)?;
    ensure!(
        root.file_name()
            .is_some_and(|name| name == hex::encode(checked.message_id()).as_str()),
        "pending receipt belongs to a different message directory"
    );
    // The consumer may retain/move its imported copy; pending payload is intentionally kept.
    // Verify it too so a substituted local handoff cannot consume the original remote message.
    let payload = Zeroizing::new(private_read(
        &root.join("payload"),
        checked.plaintext_bytes(),
    )?);
    ensure!(
        payload.len() as u64 == checked.plaintext_bytes()
            && Sha256::digest(payload.as_slice()).as_slice() == checked.plaintext_sha256(),
        "local handoff payload differs from signed original bytes"
    );
    drop(payload);
    let command = super::simple(MailboxOperation::Acknowledge, Some(*checked.message_id()));
    let mut receipts = Vec::new();
    for provider in checked.grant().provider_keys() {
        let reply = super::remote(socket, provider, checked.grant(), &command, &signer, &[])
            .await
            .context(
                "consumer-confirmed mailbox ACK incomplete; retained handoff permits exact retry",
            )?;
        ensure!(
            reply.receipt.acknowledged(),
            "provider did not acknowledge exact message"
        );
        let observation = serde_json::json!({"version":1, "message_id":hex::encode(checked.message_id()),
            "provider_key":hex::encode(provider), "receipt":hex::encode(reply.receipt.encode()),
            "observed_unix_seconds":now_seconds()?, "original_expires_unix_seconds":checked.expires()});
        replace_progress(
            &root.join(format!("ack-{}.json", hex::encode(provider))),
            &observation,
        )?;
        receipts.push(observation);
    }
    let report = serde_json::json!({"operation":"mailbox_confirm_import", "message_id":hex::encode(checked.message_id()),
        "consumer_import_attested":true, "application_import_proven":false,
        "acknowledged_providers":2, "acknowledgement_receipts":receipts,
        "original_expires_unix_seconds":checked.expires(), "local_handoff_retained":true,
        "global_peer_erasure_claimed":false});
    replace_progress(&root.join("confirmed.json"), &report)?;
    Ok(report)
}
