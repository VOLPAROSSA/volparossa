//! Explicit native-content transfer between independently owned user and agent stores.
//! Recipient-encrypted messages remain the default; ordinary native objects require opt-in.

use std::{collections::BTreeMap, path::Path, time::Duration};

use anyhow::{Context as _, Result, bail};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use tokio::time::timeout;
use volparossa_content::{
    ChunkStore, SignedManifest, VerifiedManifest,
    private_message::{
        MAX_PRIVATE_MESSAGE_BYTES, PRIVATE_MESSAGE_CONTENT_TYPE, validate_private_message_envelope,
    },
    reassemble,
    transfer::{TransferLimits, pull_from_peer, serve_peer},
};
use volparossa_local_control::{
    ContentExportRequest, ContentImportRequest, ControlResponse, control_request::Operation,
    control_response::Payload,
};

use super::{
    Limits, PathBuf, absolute_path, now_seconds, parse_publisher_key, verified_manifest_bytes,
};

#[derive(Debug, Args)]
pub(crate) struct Handoff {
    /// Exact signed manifest; defaults to recipient-encrypted messages, never browser capture.
    #[arg(long)]
    manifest: PathBuf,
    /// Independently trusted sender Ed25519 public key, not the recipient encryption key.
    #[arg(long, value_parser = parse_publisher_key)]
    publisher_key: VerifyingKey,
    /// Your owned source cache for import; a new private destination cache for export.
    /// Existing export destinations are never adopted or overwritten.
    #[arg(long)]
    cache: PathBuf,
    /// Explicit absolute agent-owned cache path: new for import, existing for export.
    /// The CLI never opens this path, changes ownership or grants filesystem permissions.
    #[arg(long)]
    agent_cache: PathBuf,
    /// Explicitly allow this ordinary native publication. Does not authenticate an HTTPS origin
    /// or enable network serving. Private-message content still requires its encrypted envelope.
    #[arg(long, default_value_t = false)]
    public_content: bool,
    #[command(flatten)]
    limits: Limits,
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Direction {
    Import,
    Export,
}

pub(super) async fn run(
    args: &Handoff,
    socket: &Path,
    direction: Direction,
) -> Result<serde_json::Value> {
    if !args.agent_cache.is_absolute() {
        bail!("agent cache must be an explicit absolute path owned by the agent account");
    }
    let encoded = verified_manifest_bytes(&args.manifest, &args.publisher_key)?;
    let manifest = SignedManifest::decode(&encoded)?.verify(&args.publisher_key, now_seconds()?)?;
    validate_manifest(&manifest, args.public_content)?;
    let mut source = match direction {
        Direction::Import => {
            let mut store = ChunkStore::open(&args.cache, args.limits.cache_limits()?)
                .context("cannot open your owned source cache")?;
            verify_complete(&manifest, &mut store)?;
            Some(store)
        }
        Direction::Export => {
            super::ensure_new_output(&args.cache)?;
            None
        }
    };
    let operation = match direction {
        Direction::Import => Operation::ContentImport(ContentImportRequest {
            manifest: encoded,
            publisher_key: args.publisher_key.to_bytes().to_vec(),
            cache: absolute_path(&args.agent_cache)?,
            limits: Some(args.limits.wire_limits()),
            allow_public_content: args.public_content,
        }),
        Direction::Export => Operation::ContentExport(ContentExportRequest {
            manifest: encoded,
            publisher_key: args.publisher_key.to_bytes().to_vec(),
            cache: absolute_path(&args.agent_cache)?,
            limits: Some(args.limits.wire_limits()),
            allow_public_content: args.public_content,
        }),
    };
    let transfer = async {
        let (mut stream, request_id, ready) =
            crate::control::begin_request(socket, operation).await?;
        validate_ready(&ready, &manifest)?;
        let limits = TransferLimits {
            exchange_timeout: Duration::from_secs(5),
            session_timeout: Duration::from_secs(30),
            // Empty native objects exchange only the normal finish frame, no chunk body.
            max_requests: manifest.chunks().len().max(1),
            max_bytes: manifest.length().max(1),
        };
        let progress = match direction {
            Direction::Import => {
                serve_peer(
                    &mut stream,
                    &manifest,
                    source.as_mut().context("content source unavailable")?,
                    limits,
                )
                .await?
            }
            Direction::Export => {
                // Do not create a local destination before the exact agent accepted this manifest.
                let mut destination = ChunkStore::create(&args.cache, args.limits.cache_limits()?)
                    .context("cannot create your new private destination cache")?;
                let progress =
                    pull_from_peer(&mut stream, &manifest, &mut destination, limits).await?;
                verify_complete(&manifest, &mut destination)?;
                progress
            }
        };
        let complete = crate::control::finish_request(&mut stream, &request_id).await?;
        validate_complete(&complete, &manifest)?;
        let unique_chunks: BTreeMap<_, _> = manifest
            .chunks()
            .iter()
            .map(|chunk| (*chunk.id(), u64::from(chunk.length())))
            .collect();
        if progress.bytes != unique_chunks.values().sum::<u64>()
            || progress.chunks != unique_chunks.len()
            || progress.missing != 0
        {
            bail!("content handoff did not transfer the complete verified object");
        }
        Ok::<(), anyhow::Error>(())
    };
    timeout(Duration::from_secs(30), transfer)
        .await
        .context("content handoff deadline exceeded; verified partial content may remain")?
        .context("content handoff failed; verified partial content may remain, no permissions or ownership were changed")?;
    Ok(receipt(args, &manifest, direction))
}

fn receipt(args: &Handoff, manifest: &VerifiedManifest, direction: Direction) -> serde_json::Value {
    let private = manifest.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE;
    let mut receipt = serde_json::json!({
        "operation": match direction { Direction::Import => "content_import", Direction::Export => "content_export" },
        "manifest_id": hex::encode(manifest.manifest_id()),
        "content_bytes": manifest.length(), "chunks": manifest.chunks().len(),
        "cache": args.cache, "agent_cache": args.agent_cache,
        "complete": true, "network_transfer": false, "ownership_changed": false,
        "recipient_decryption_performed": false, "private_keys_transferred": false,
        "public_content": !private, "ciphertext_format_verified": private,
        "origin_authenticated": false,
    });
    if private {
        receipt["ciphertext_bytes"] = manifest.length().into();
    }
    receipt
}

fn validate_manifest(manifest: &VerifiedManifest, allow_public_content: bool) -> Result<()> {
    let metadata = manifest.metadata();
    if metadata.content_type != PRIVATE_MESSAGE_CONTENT_TYPE {
        if !allow_public_content {
            bail!("ordinary native publication requires explicit --public-content");
        }
        return Ok(());
    }
    // Opt-in cannot reinterpret a private-message envelope as a generic native object.
    if metadata.revision != 1
        || metadata.name.len() != 64
        || !metadata
            .name
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
        || !(54..=MAX_PRIVATE_MESSAGE_BYTES as u64 + 64).contains(&manifest.length())
        || manifest.chunks().len() > 17
    {
        bail!("private-message handoff requires the bounded recipient-encrypted message profile");
    }
    Ok(())
}

fn verify_complete(manifest: &VerifiedManifest, store: &mut ChunkStore) -> Result<()> {
    if manifest.metadata().content_type == PRIVATE_MESSAGE_CONTENT_TYPE {
        validate_private_message_envelope(manifest, &mut [store], now_seconds()?).context(
            "ciphertext source is incomplete or fails the signed whole-object hash/envelope format",
        )?;
    } else {
        reassemble(manifest, &mut [store], now_seconds()?, &mut std::io::sink())
            .context("native source is incomplete or fails the signed whole-object hash")?;
    }
    Ok(())
}

fn validate_ready(response: &ControlResponse, manifest: &VerifiedManifest) -> Result<()> {
    let Some(Payload::ContentTransferReady(ready)) = &response.payload else {
        bail!("agent did not explicitly accept the content stream handoff");
    };
    if response.diagnostic_code != "CONTENT_TRANSFER_READY"
        || ready.manifest_id != manifest.manifest_id()
        || ready.bytes != manifest.length()
        || usize::try_from(ready.chunks)? != manifest.chunks().len()
    {
        bail!("agent content handoff does not match the exact trusted manifest");
    }
    Ok(())
}

fn validate_complete(response: &ControlResponse, manifest: &VerifiedManifest) -> Result<()> {
    let Some(Payload::Content(receipt)) = &response.payload else {
        bail!("agent returned no final content transfer receipt");
    };
    if response.diagnostic_code != "CONTENT_OK"
        || receipt.bytes != manifest.length()
        || usize::try_from(receipt.chunks)? != manifest.chunks().len()
    {
        bail!("agent final receipt does not confirm the complete content object");
    }
    Ok(())
}
