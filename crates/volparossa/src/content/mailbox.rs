//! Explicit private inbox discovery and delivery; no public name lookup or sender plaintext relay.

use std::{
    collections::BTreeMap,
    fs,
    io::{Read as _, Write as _},
    os::unix::fs::{DirBuilderExt as _, PermissionsExt as _},
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, bail, ensure};
use clap::{Args, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use tokio::time::timeout;
use volparossa_content::{
    ChunkStore, SignedManifest, Validity,
    mailbox::{
        MAX_GRANT_BYTES, MAX_MAILBOX_BYTES, MAX_MAILBOX_MESSAGES, MailboxQuota, SignedMailboxGrant,
        VerifiedMailboxGrant,
        wire::{MailboxChallenge, MailboxCommand, MailboxOperation, MailboxReply, execute},
    },
    private_message::{
        MAX_PRIVATE_MESSAGE_BYTES, RecipientKeyPair, open_private_message, publish_private_message,
        validate_private_message_envelope,
    },
    reassemble,
};
use volparossa_local_control::{
    MailboxRemoteRequest, MailboxServeRequest, control_request::Operation,
    control_response::Payload,
};
use zeroize::Zeroizing;

use super::{
    Limits, absolute_path, ensure_new_output, now_seconds, open_regular, output_parent,
    parse_publisher_key, private_message::Unlock,
};

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Sign an invitation for one known sender and two independently trusted storage providers.
    Invite(Invite),
    /// Register this invitation at both providers and require two actual signed confirmations.
    Enroll(Enrollment),
    /// Encrypt and deposit one message at both providers; preserve local ciphertext for retries.
    Send(Send),
    /// Discover the private inbox and decrypt messages into a NEW private directory, then acknowledge.
    Receive(Receive),
    /// Explicitly start the agent's durable mailbox service; content stop stops it again.
    Serve(Serve),
}

#[derive(Debug, Args)]
pub(crate) struct Invite {
    /// Independently authenticated sender Ed25519 public key.
    #[arg(long, value_parser = parse_publisher_key)]
    sender_key: VerifyingKey,
    /// Repeat exactly twice for independently authenticated provider Ed25519 keys.
    #[arg(long, required = true, num_args = 1, value_parser = parse_publisher_key)]
    provider_key: Vec<VerifyingKey>,
    /// New signed invitation file; share privately with this known sender.
    #[arg(long)]
    invitation: PathBuf,
    /// Original invitation lifetime, at most 31 days; storage does not renew it.
    #[arg(long, default_value_t = 604_800, value_parser = clap::value_parser!(u64).range(1..=2_678_400))]
    lifetime_seconds: u64,
    /// Maximum retained message bytes per provider; registration does not reserve future space.
    #[arg(long, default_value_t = MAX_MAILBOX_BYTES, value_parser = clap::value_parser!(u64).range(1..=MAX_MAILBOX_BYTES))]
    max_bytes: u64,
    /// Maximum current messages plus unexpired acknowledgement records.
    #[arg(long, default_value_t = MAX_MAILBOX_MESSAGES, value_parser = clap::value_parser!(u32).range(1..=i64::from(MAX_MAILBOX_MESSAGES)))]
    max_messages: u32,
    #[command(flatten)]
    unlock: Unlock,
}

#[derive(Debug, Args)]
pub(crate) struct Enrollment {
    /// Original invitation signed by this unlocked recipient identity.
    #[arg(long)]
    invitation: PathBuf,
    #[command(flatten)]
    unlock: Unlock,
}

#[derive(Debug, Args)]
pub(crate) struct Send {
    /// Original privately received invitation, verified against --owner-key.
    #[arg(long)]
    invitation: PathBuf,
    /// Independently authenticated recipient Ed25519 key, not inferred from the invitation.
    #[arg(long, value_parser = parse_publisher_key)]
    owner_key: VerifyingKey,
    /// Explicit plaintext file; required for a new message, never sent to the agent/provider.
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    input: Option<PathBuf>,
    /// New encrypted chunk cache; --resume opens this same owned cache without publishing again.
    #[arg(long)]
    cache: PathBuf,
    /// New original encrypted-message manifest; --resume uses this unchanged file.
    #[arg(long)]
    manifest: PathBuf,
    /// Retry the exact retained manifest/cache after a partial deposit; do not create another message.
    #[arg(long)]
    resume: bool,
    /// New-message lifetime; also bounded by the invitation's original expiry.
    #[arg(long, default_value_t = 86_400, value_parser = clap::value_parser!(u64).range(1..=2_678_400))]
    lifetime_seconds: u64,
    #[command(flatten)]
    unlock: Unlock,
    #[command(flatten)]
    limits: Limits,
}

#[derive(Debug, Args)]
pub(crate) struct Receive {
    /// Original invitation signed by this unlocked recipient identity.
    #[arg(long)]
    invitation: PathBuf,
    /// NEW directory for verified plaintext; opaque message IDs are the only filenames.
    #[arg(long)]
    output_dir: PathBuf,
    #[command(flatten)]
    unlock: Unlock,
    #[command(flatten)]
    limits: Limits,
}

#[derive(Debug, Args)]
pub(crate) struct Serve {
    /// Explicit unprivileged listener address; no listener is started on boot by this command.
    #[arg(long)]
    bind: std::net::SocketAddr,
    /// Exact DNS hostname already authorized by the signed Exit policy.
    #[arg(long)]
    advertised_hostname: String,
    /// New agent-owned durable mailbox cache.
    #[arg(long)]
    cache: PathBuf,
    /// Reopen only a previously owned mailbox cache, preserving original invitations/messages.
    #[arg(long)]
    reuse_cache: bool,
    #[command(flatten)]
    limits: Limits,
}

pub(super) async fn run(command: Command, socket: &Path) -> Result<()> {
    let report = match command {
        Command::Invite(args) => invite(&args)?,
        Command::Enroll(args) => enroll(&args, socket).await?,
        Command::Send(args) => send(&args, socket).await?,
        Command::Receive(args) => receive(&args, socket).await?,
        Command::Serve(args) => {
            let request = MailboxServeRequest {
                bind_address: args.bind.to_string(),
                advertised_hostname: args.advertised_hostname,
                cache: absolute_path(&args.cache)?,
                limits: Some(args.limits.wire_limits()),
                reuse_cache: args.reuse_cache,
            };
            return crate::print_response(
                crate::control::request(socket, Operation::MailboxServe(request)).await?,
            );
        }
    };
    println!("{}", serde_json::to_string(&report)?);
    Ok(())
}

fn invite(args: &Invite) -> Result<serde_json::Value> {
    ensure!(
        args.provider_key.len() == 2,
        "exactly two independent provider keys are required"
    );
    ensure_new_output(&args.invitation)?;
    let signer = args.unlock.signer()?;
    let recipient = RecipientKeyPair::from_node_identity(&signer)?;
    let now = now_seconds()?;
    let grant = SignedMailboxGrant::sign(
        &signer,
        args.sender_key.to_bytes(),
        *recipient.public_key(),
        [
            args.provider_key[0].to_bytes(),
            args.provider_key[1].to_bytes(),
        ],
        Validity {
            created: now,
            expires: now
                .checked_add(args.lifetime_seconds)
                .context("invitation expiry overflow")?,
        },
        MailboxQuota {
            max_bytes: args.max_bytes,
            max_messages: args.max_messages,
        },
    )?;
    let verified = grant.verify(&signer.verifying_key(), now)?;
    private_file(&args.invitation, &grant.encode())?;
    Ok(
        serde_json::json!({ "operation":"mailbox_invite", "invitation":args.invitation,
        "mailbox_id":hex::encode(verified.mailbox_id()), "owner_key_hex":hex::encode(verified.owner_key()),
        "expires_unix_seconds":verified.validity().expires, "registered_providers":0, "private_key_exported":false }),
    )
}

fn read_grant(path: &Path, owner: &VerifyingKey) -> Result<VerifiedMailboxGrant> {
    let mut bytes = Vec::new();
    open_regular(path, MAX_GRANT_BYTES as u64)?
        .take(MAX_GRANT_BYTES as u64 + 1)
        .read_to_end(&mut bytes)?;
    Ok(SignedMailboxGrant::decode(&bytes)?.verify(owner, now_seconds()?)?)
}

fn simple(operation: MailboxOperation, id: Option<[u8; 32]>) -> MailboxCommand {
    MailboxCommand {
        operation,
        manifest: None,
        message_id: id,
    }
}

async fn enroll(args: &Enrollment, socket: &Path) -> Result<serde_json::Value> {
    let signer = args.unlock.signer()?;
    let grant = read_grant(&args.invitation, &signer.verifying_key())?;
    let receipts = both(
        socket,
        &grant,
        &simple(MailboxOperation::Register, None),
        &signer,
        &[],
    )
    .await?;
    Ok(
        serde_json::json!({ "operation":"mailbox_enroll", "mailbox_id":hex::encode(grant.mailbox_id()),
        "registered_providers":2, "storage_receipts":receipts.encoded, "message_capacity_reserved":false }),
    )
}

async fn send(args: &Send, socket: &Path) -> Result<serde_json::Value> {
    let signer = args.unlock.signer()?;
    let grant = read_grant(&args.invitation, &args.owner_key)?;
    ensure!(
        signer.verifying_key().as_bytes() == grant.sender_key(),
        "unlocked identity is not the invitation's allowed sender"
    );
    let (publication, ciphertext) = prepare_message(args, &grant, &signer)?;
    let verified = publication.verify(&signer.verifying_key(), now_seconds()?)?;
    let id = *verified.manifest_id();
    let command = MailboxCommand {
        operation: MailboxOperation::Deposit,
        manifest: Some(publication),
        message_id: None,
    };
    let receipts = both(socket, &grant, &command, &signer, &ciphertext).await
        .context("deposit incomplete; keep the original manifest/cache and use --resume for this exact message")?;
    Ok(
        serde_json::json!({ "operation":"mailbox_send", "message_id":hex::encode(id),
        "confirmed_providers":2, "storage_receipts":receipts.encoded, "manifest":args.manifest,
        "retained_providers":2 - receipts.acknowledged, "already_acknowledged_providers":receipts.acknowledged,
        "cache":args.cache, "ciphertext_bytes":verified.length(), "plaintext_uploaded":false }),
    )
}

fn prepare_message(
    args: &Send,
    grant: &VerifiedMailboxGrant,
    signer: &SigningKey,
) -> Result<(SignedManifest, Vec<u8>)> {
    let now = now_seconds()?;
    let limits = args.limits.cache_limits()?;
    let (publication, mut cache) = if args.resume {
        let mut bytes = Vec::new();
        open_regular(&args.manifest, 4096)?
            .take(4097)
            .read_to_end(&mut bytes)?;
        (
            SignedManifest::decode(&bytes)?,
            ChunkStore::open(&args.cache, limits)?,
        )
    } else {
        ensure_new_output(&args.manifest)?;
        let mut plaintext = Zeroizing::new(Vec::new());
        open_regular(
            args.input
                .as_deref()
                .context("new message requires --input")?,
            MAX_PRIVATE_MESSAGE_BYTES as u64,
        )?
        .take(MAX_PRIVATE_MESSAGE_BYTES as u64 + 1)
        .read_to_end(&mut plaintext)?;
        ensure!(
            plaintext.len() <= MAX_PRIVATE_MESSAGE_BYTES,
            "private message exceeds 4 MiB"
        );
        let mut cache = ChunkStore::create(&args.cache, limits)?;
        let expires = now
            .checked_add(args.lifetime_seconds)
            .context("message expiry overflow")?
            .min(grant.validity().expires);
        let publication = publish_private_message(
            &plaintext,
            grant.recipient_key(),
            signer,
            Validity {
                created: now,
                expires,
            },
            &mut cache,
        )?;
        drop(plaintext);
        ensure!(
            publication.encode().len() <= 4096,
            "mailbox message manifest exceeds bound"
        );
        private_file(&args.manifest, &publication.encode())?;
        (publication, cache)
    };
    let checked = publication.verify(&signer.verifying_key(), now)?;
    ensure!(
        checked.validity().expires <= grant.validity().expires,
        "message outlives invitation"
    );
    validate_private_message_envelope(&checked, &mut [&mut cache], now)?;
    let mut ciphertext = Vec::new();
    reassemble(&checked, &mut [&mut cache], now, &mut ciphertext)?;
    Ok((publication, ciphertext))
}

async fn remote(
    socket: &Path,
    provider: &[u8; 32],
    grant: &VerifiedMailboxGrant,
    command: &MailboxCommand,
    signer: &SigningKey,
    ciphertext: &[u8],
) -> Result<MailboxReply> {
    timeout(Duration::from_secs(600), async {
        let request = MailboxRemoteRequest {
            provider_key: provider.to_vec(),
            grant: grant.signed().encode(),
            operation: command.operation as i32,
            manifest: command
                .manifest
                .as_ref()
                .map(SignedManifest::encode)
                .unwrap_or_default(),
            message_id: command.message_id.map(|id| id.to_vec()).unwrap_or_default(),
        };
        let (mut stream, request_id, response) =
            crate::control::begin_request(socket, Operation::MailboxRemote(request)).await?;
        ensure!(
            response.diagnostic_code == "MAILBOX_READY",
            "missing explicit mailbox readiness"
        );
        let Some(Payload::MailboxReady(ready)) = response.payload else {
            bail!("wrong mailbox readiness payload")
        };
        ensure!(
            ready.provider_key == provider,
            "mailbox readiness selected a different provider"
        );
        let challenge = MailboxChallenge::decode(&ready.challenge, provider, now_seconds()?)?;
        let reply = execute(&mut stream, &challenge, grant, command, signer, ciphertext).await?;
        let response = crate::control::finish_request(&mut stream, &request_id).await?;
        let Some(Payload::Content(receipt)) = response.payload else {
            bail!("missing final mailbox receipt")
        };
        ensure!(
            response.diagnostic_code == "CONTENT_OK"
                && !receipt.origin_authenticated
                && receipt.bytes == reply.receipt.ciphertext_bytes(),
            "invalid final mailbox transfer accounting"
        );
        Ok(reply)
    })
    .await
    .context("mailbox operation exceeded its deadline")?
}

struct Confirmed {
    encoded: Vec<String>,
    acknowledged: u32,
}

async fn both(
    socket: &Path,
    grant: &VerifiedMailboxGrant,
    command: &MailboxCommand,
    signer: &SigningKey,
    ciphertext: &[u8],
) -> Result<Confirmed> {
    let mut receipts = Vec::with_capacity(2);
    let mut acknowledged = 0;
    for provider in grant.provider_keys() {
        match remote(socket, provider, grant, command, signer, ciphertext).await {
            Ok(reply) => {
                acknowledged += u32::from(reply.receipt.acknowledged());
                receipts.push(hex::encode(reply.receipt.encode()));
            }
            Err(error) => {
                eprintln!(
                    "mailbox operation partial: {} of 2 signed provider confirmations; prior custody/acknowledgements are retained",
                    receipts.len()
                );
                return Err(error);
            }
        }
    }
    Ok(Confirmed {
        encoded: receipts,
        acknowledged,
    })
}

async fn receive(args: &Receive, socket: &Path) -> Result<serde_json::Value> {
    ensure_new_output(&args.output_dir)?;
    let signer = args.unlock.signer()?;
    let grant = read_grant(&args.invitation, &signer.verifying_key())?;
    let recipient = RecipientKeyPair::from_node_identity(&signer)?;
    ensure!(
        recipient.public_key() == grant.recipient_key(),
        "invitation belongs to a different recipient encryption key"
    );
    let inbox = inbox(socket, &grant, &signer).await?;
    fs::DirBuilder::new().mode(0o700).create(&args.output_dir)?;
    fs::File::open(output_parent(&args.output_dir))?.sync_all()?;
    let mut delivered = 0_u32;
    let mut acknowledgement_receipts = Vec::new();
    for (id, publication) in &inbox.messages {
        match receive_one(args, socket, &grant, &signer, &recipient, *id, publication).await {
            Ok(receipts) => acknowledgement_receipts
                .push(serde_json::json!({"message_id":hex::encode(id),"receipts":receipts})),
            Err(error) => {
                eprintln!(
                    "mailbox receive incomplete after {delivered} fully acknowledged messages; any verified files already written in the new output directory are preserved"
                );
                return Err(error);
            }
        }
        delivered += 1;
    }
    Ok(
        serde_json::json!({ "operation":"mailbox_receive", "messages_discovered":inbox.messages.len(),
        "messages_delivered":delivered, "output_dir":args.output_dir, "output_mode":"0600",
        "directory_mode":"0700", "acknowledged_providers_per_message":2, "sender_manifest_supplied":false,
        "listed_providers":inbox.listed_providers, "degraded":inbox.listed_providers != 2,
        "acknowledgement_receipts":acknowledgement_receipts }),
    )
}

struct Inbox {
    messages: BTreeMap<[u8; 32], SignedManifest>,
    listed_providers: u32,
}

async fn inbox(socket: &Path, grant: &VerifiedMailboxGrant, signer: &SigningKey) -> Result<Inbox> {
    let mut messages = BTreeMap::new();
    let mut listed_providers = 0;
    for provider in grant.provider_keys() {
        let Ok(reply) = remote(
            socket,
            provider,
            grant,
            &simple(MailboxOperation::List, None),
            signer,
            &[],
        )
        .await
        else {
            continue;
        };
        listed_providers += 1;
        for publication in reply.receipt.manifests(grant, now_seconds()?)? {
            let checked = publication.verify(
                &VerifyingKey::from_bytes(grant.sender_key())?,
                now_seconds()?,
            )?;
            let id = *checked.manifest_id();
            if let Some(previous) = messages.insert(id, publication.clone()) {
                ensure!(
                    previous.encode() == publication.encode(),
                    "providers returned conflicting message bytes"
                );
            }
            ensure!(
                messages.len() <= grant.max_messages() as usize,
                "combined inbox exceeds the invitation's message bound"
            );
        }
    }
    ensure!(
        listed_providers != 0,
        "neither provider supplied an authenticated inbox list"
    );
    Ok(Inbox {
        messages,
        listed_providers,
    })
}

async fn receive_one(
    args: &Receive,
    socket: &Path,
    grant: &VerifiedMailboxGrant,
    signer: &SigningKey,
    recipient: &RecipientKeyPair,
    id: [u8; 32],
    publication: &SignedManifest,
) -> Result<Vec<String>> {
    let command = simple(MailboxOperation::Get, Some(id));
    let reply = match remote(
        socket,
        &grant.provider_keys()[0],
        grant,
        &command,
        signer,
        &[],
    )
    .await
    {
        Ok(reply) => reply,
        Err(_) => {
            remote(
                socket,
                &grant.provider_keys()[1],
                grant,
                &command,
                signer,
                &[],
            )
            .await?
        }
    };
    let originals = reply.receipt.manifests(grant, now_seconds()?)?;
    ensure!(
        originals.len() == 1 && originals[0].encode() == publication.encode(),
        "retrieved message differs from authenticated inbox manifest"
    );
    let temporary = tempfile::Builder::new()
        .prefix(".mailbox-ciphertext-")
        .tempdir_in(&args.output_dir)?;
    let mut cache =
        ChunkStore::create(&temporary.path().join("cache"), args.limits.cache_limits()?)?;
    let checked = publication.verify(
        &VerifyingKey::from_bytes(grant.sender_key())?,
        now_seconds()?,
    )?;
    let mut remaining = reply.ciphertext.as_slice();
    for chunk in checked.chunks() {
        let length = usize::try_from(chunk.length())?;
        ensure!(remaining.len() >= length, "truncated mailbox ciphertext");
        let (part, rest) = remaining.split_at(length);
        cache.put_verified(*chunk.id(), part)?;
        remaining = rest;
    }
    ensure!(remaining.is_empty(), "unexpected mailbox ciphertext tail");
    let plaintext = open_private_message(&checked, &mut [&mut cache], now_seconds()?, recipient)?;
    private_file(&args.output_dir.join(hex::encode(id)), &plaintext)?;
    drop(plaintext);
    drop(cache);
    temporary.close()?;
    both(
        socket,
        grant,
        &simple(MailboxOperation::Acknowledge, Some(id)),
        signer,
        &[],
    )
    .await
    .map(|confirmed| confirmed.encoded)
}

fn private_file(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure_new_output(path)?;
    let mut output = tempfile::NamedTempFile::new_in(output_parent(path))?;
    output
        .as_file()
        .set_permissions(fs::Permissions::from_mode(0o600))?;
    output.write_all(bytes)?;
    output.as_file().sync_all()?;
    output
        .persist_noclobber(path)
        .map_err(|error| error.error)?;
    fs::File::open(output_parent(path))?.sync_all()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use clap::Parser as _;

    #[test]
    fn mailbox_commands_require_explicit_invitation_trust_and_new_output() {
        let key = "01".repeat(32);
        for args in [
            vec![
                "invite",
                "--sender-key",
                &key,
                "--provider-key",
                &key,
                "--provider-key",
                &key,
                "--invitation",
                "invite",
            ],
            vec!["enroll", "--invitation", "invite"],
            vec![
                "send",
                "--invitation",
                "invite",
                "--owner-key",
                &key,
                "--input",
                "input",
                "--manifest",
                "manifest",
                "--cache",
                "cache",
            ],
            vec![
                "send",
                "--invitation",
                "invite",
                "--owner-key",
                &key,
                "--resume",
                "--manifest",
                "manifest",
                "--cache",
                "cache",
            ],
            vec![
                "receive",
                "--invitation",
                "invite",
                "--output-dir",
                "new-output",
            ],
            vec![
                "serve",
                "--bind",
                "127.0.0.1:18080",
                "--advertised-hostname",
                "provider.example",
                "--cache",
                "cache",
                "--reuse-cache",
            ],
        ] {
            assert!(
                crate::Cli::try_parse_from(
                    ["volparossa", "content", "mailbox"].into_iter().chain(args)
                )
                .is_ok()
            );
        }
        assert!(
            crate::Cli::try_parse_from([
                "volparossa",
                "content",
                "mailbox",
                "send",
                "--invitation",
                "invite",
                "--owner-key",
                &key,
                "--cache",
                "cache",
                "--manifest",
                "manifest"
            ])
            .is_err()
        );
    }
}
