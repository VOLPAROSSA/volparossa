//! Original public publication custody through the agent's protected route, never direct dialing.

use std::{
    collections::BTreeSet,
    path::{Path, PathBuf},
    time::Duration,
};

use anyhow::{Context as _, Result, bail, ensure};
use clap::{Args, Subcommand};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use volparossa_content::{
    CacheLimits, ChunkStore, SignedManifest, VerifiedManifest,
    private_message::PRIVATE_MESSAGE_CONTENT_TYPE,
    provider::custody::{
        CustodyAuthorization, CustodyChallenge, CustodyOperation, CustodyReceipt, CustodyState,
        execute,
    },
    reassemble,
    transfer::TransferLimits,
};
use volparossa_local_control::{
    ContentCustodyRequest, ContentReceipt, control_request::Operation, control_response::Payload,
};

use super::{
    Limits, now_seconds, parse_publisher_key, private_message::Unlock, verified_manifest_bytes,
};

// One explicit CLI batch bound, not a runtime connection/path count or a two-copy policy.
const MAX_PROVIDER_KEYS: usize = 64;

#[derive(Debug, Subcommand)]
pub(crate) enum Command {
    /// Deposit the exact original public object; retries preserve its original expiry.
    Deposit(Deposit),
    /// Obtain fresh signed complete/missing observations without uploading content.
    Inspect(Options),
}

#[derive(Debug, Args)]
pub(crate) struct Options {
    /// Original public manifest, signed by the unlocked publisher identity.
    #[arg(long)]
    manifest: PathBuf,
    /// Repeat for independently authenticated provider keys (1 through 64 per CLI batch).
    #[arg(long, required = true, num_args = 1, value_parser = parse_publisher_key)]
    provider_key: Vec<VerifyingKey>,
    #[command(flatten)]
    unlock: Unlock,
}

#[derive(Debug, Args)]
pub(crate) struct Deposit {
    #[command(flatten)]
    options: Options,
    /// Existing owned local cache containing the complete original object; never sent as a path.
    #[arg(long)]
    cache: PathBuf,
    #[command(flatten)]
    limits: Limits,
}

struct Prepared {
    signer: SigningKey,
    signed: SignedManifest,
    manifest: VerifiedManifest,
    source: Option<ChunkStore>,
    operation: CustodyOperation,
}

pub(super) async fn run(command: Command, socket: &Path) -> Result<()> {
    let report = run_report(&command, socket).await?;
    println!("{}", serde_json::to_string(&report)?);
    ensure!(
        report["complete"] == true,
        "public custody incomplete; signed observations above and original local content are retained"
    );
    Ok(())
}

/// Composition preserves incomplete signed observations for the enrolling owner.
pub(super) async fn deposit_existing(
    publication: &super::PolicyDecisionPublication,
    providers: Vec<VerifyingKey>,
    socket: &Path,
) -> Result<serde_json::Value> {
    run_report(
        &Command::Deposit(Deposit {
            options: Options {
                manifest: publication.manifest.clone(),
                provider_key: providers,
                unlock: Unlock::explicit(
                    publication.identity.clone(),
                    publication.passphrase_file.clone(),
                ),
            },
            cache: publication.cache.clone(),
            limits: publication.limits.clone(),
        }),
        socket,
    )
    .await
}

async fn run_report(command: &Command, socket: &Path) -> Result<serde_json::Value> {
    let (options, operation, source) = match &command {
        Command::Deposit(args) => (
            &args.options,
            CustodyOperation::Deposit,
            Some((args.cache.as_path(), args.limits.cache_limits()?)),
        ),
        Command::Inspect(args) => (args, CustodyOperation::Inspect, None),
    };
    let mut prepared = prepare(options, operation, source)?;
    let mut observations = Vec::new();
    let mut complete = 0;
    let mut failed = 0;
    for provider in &options.provider_key {
        // Retain even an authenticated receipt followed by a broken local final response.
        // It is reported separately, never counted as a completed agent handoff.
        let mut signed_receipt = None;
        let mut original = None;
        let result = timeout(
            Duration::from_secs(600),
            prepared.remote(socket, provider, &mut signed_receipt, false, &mut original),
        )
        .await
        .context("public custody operation exceeded its deadline")
        .and_then(std::convert::identity);
        let handoff_complete = result.is_ok();
        let state_complete = signed_receipt
            .as_ref()
            .is_some_and(|receipt| receipt.state() == CustodyState::Complete);
        complete += usize::from(handoff_complete && state_complete);
        failed += usize::from(!handoff_complete);
        observations.push(serde_json::json!({
            "provider_key_hex": hex::encode(provider.as_bytes()),
            "agent_handoff_complete": handoff_complete,
            "state": signed_receipt.as_ref().map(|receipt| match receipt.state() { CustodyState::Complete => "complete", CustodyState::Missing => "missing" }),
            "signed_receipt_hex": signed_receipt.as_ref().map(|receipt| hex::encode(receipt.encode())),
            "original_expiry_unix_seconds": signed_receipt.as_ref().map(CustodyReceipt::original_expiry),
            "object_bytes": signed_receipt.as_ref().map(CustodyReceipt::object_bytes),
            "unique_chunks": signed_receipt.as_ref().map(CustodyReceipt::unique_chunks),
            "error": result.err().map(|error| format!("{error:#}")),
        }));
    }
    let report = serde_json::json!({
        "operation": match operation { CustodyOperation::Deposit => "content_custody_deposit", CustodyOperation::Inspect => "content_custody_inspect" },
        "manifest_id": hex::encode(prepared.manifest.manifest_id()),
        "publisher_key_hex": hex::encode(prepared.manifest.publisher()),
        "object_bytes": prepared.manifest.length(),
        "original_expiry_unix_seconds": prepared.manifest.validity().expires,
        "requested_providers": options.provider_key.len(),
        "confirmed_complete_providers": complete,
        "failed_providers": failed,
        "complete": complete == options.provider_key.len(),
        "observations": observations,
        "private_keys_transferred": false,
        "direct_provider_dial": false,
        "origin_authenticated": false,
        "future_availability_guaranteed": false,
    });
    Ok(report)
}

fn validate_providers(providers: &[VerifyingKey], publisher: Option<&VerifyingKey>) -> Result<()> {
    ensure!(
        (1..=MAX_PROVIDER_KEYS).contains(&providers.len()),
        "public custody requires 1 through {MAX_PROVIDER_KEYS} explicit provider keys per batch"
    );
    let mut unique = BTreeSet::new();
    for provider in providers {
        ensure!(
            unique.insert(provider.to_bytes()),
            "duplicate custody provider key"
        );
        ensure!(
            publisher != Some(provider),
            "the publisher cannot count itself as a remote custody provider"
        );
    }
    Ok(())
}

fn prepare(
    options: &Options,
    operation: CustodyOperation,
    source: Option<(&Path, CacheLimits)>,
) -> Result<Prepared> {
    validate_providers(&options.provider_key, None)?;
    let publisher = options.unlock.signer()?;
    validate_providers(&options.provider_key, Some(&publisher.verifying_key()))?;
    let bytes = verified_manifest_bytes(&options.manifest, &publisher.verifying_key())?;
    let signed = SignedManifest::decode(&bytes)?;
    let manifest = signed.verify(&publisher.verifying_key(), now_seconds()?)?;
    ensure!(
        manifest.metadata().content_type != PRIVATE_MESSAGE_CONTENT_TYPE,
        "private messages require the separate encrypted mailbox workflow"
    );
    let source = source
        .map(|(path, limits)| {
            let mut cache = ChunkStore::open(path, limits)
                .context("cannot open the existing owned public source cache")?;
            reassemble(
                &manifest,
                &mut [&mut cache],
                now_seconds()?,
                &mut std::io::sink(),
            )
            .context("public source must contain the complete original verified object")?;
            Ok::<_, anyhow::Error>(cache)
        })
        .transpose()?;
    Ok(Prepared {
        signer: publisher,
        signed,
        manifest,
        source,
        operation,
    })
}

impl Prepared {
    async fn remote(
        &mut self,
        socket: &Path,
        provider: &VerifyingKey,
        signed_receipt: &mut Option<CustodyReceipt>,
        background: bool,
        original: &mut Option<RetainedExchange>,
    ) -> Result<()> {
        let validity = self.manifest.validity();
        ensure!(
            (validity.created..validity.expires).contains(&now_seconds()?),
            "the original publication has expired or is not yet valid"
        );
        let request = ContentCustodyRequest {
            provider_key: provider.to_bytes().to_vec(),
            manifest: self.signed.encode(),
            publisher_key: self.manifest.publisher().to_vec(),
            operation: self.operation as i32,
            background,
        };
        let (mut stream, request_id, response) =
            crate::control::begin_request(socket, Operation::ContentCustody(request)).await?;
        ensure!(
            response.diagnostic_code == "CONTENT_CUSTODY_READY",
            "missing explicit public custody readiness"
        );
        let Some(Payload::ContentCustodyReady(ready)) = response.payload else {
            bail!("wrong public custody readiness payload");
        };
        ensure!(
            ready.provider_key == provider.as_bytes(),
            "custody readiness selected a different provider"
        );
        let challenge =
            CustodyChallenge::decode(&ready.challenge, provider.as_bytes(), now_seconds()?)?;
        let authorization = CustodyAuthorization::sign(
            &challenge,
            self.operation,
            self.signed.clone(),
            &self.signer,
            now_seconds()?,
        )?;
        let receipt = execute(
            &mut stream,
            &challenge,
            &authorization,
            self.source.as_mut(),
            TransferLimits::default(),
        )
        .await?;
        *original = Some(RetainedExchange {
            verified_at: now_seconds()?,
            challenge_hex: hex::encode(challenge.encode()),
            authorization_hex: hex::encode(authorization.encode()),
            receipt_hex: hex::encode(receipt.encode()),
            handoff_complete: false,
        });
        *signed_receipt = Some(receipt);
        let response = crate::control::finish_request(&mut stream, &request_id).await?;
        ensure!(
            response.diagnostic_code == "CONTENT_OK",
            "missing final public custody confirmation"
        );
        let Some(Payload::Content(accounting)) = response.payload else {
            bail!("wrong final public custody payload");
        };
        validate_accounting(
            &accounting,
            signed_receipt
                .as_ref()
                .context("missing verified custody receipt")?,
        )?;
        if let Some(record) = original {
            record.handoff_complete = true;
        }
        Ok(())
    }
}

/// Exact original protocol evidence. Reopening verifies signatures at its original
/// observation time; it never converts historical evidence into current availability.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct RetainedExchange {
    pub(super) verified_at: u64,
    pub(super) challenge_hex: String,
    pub(super) authorization_hex: String,
    pub(super) receipt_hex: String,
    pub(super) handoff_complete: bool,
}

impl RetainedExchange {
    pub(super) fn verify(
        &self,
        provider: &VerifyingKey,
        original: &[u8],
        operation: CustodyOperation,
    ) -> Result<CustodyReceipt> {
        ensure!(
            self.challenge_hex.len() <= 4096
                && self.receipt_hex.len() <= 4096
                && self.authorization_hex.len()
                    <= 2 * (volparossa_content::MAX_MANIFEST_BYTES + 2048),
            "content_retain_exchange_bound"
        );
        let challenge = CustodyChallenge::decode(
            &hex::decode(&self.challenge_hex)?,
            provider.as_bytes(),
            self.verified_at,
        )?;
        let authorization = CustodyAuthorization::decode(
            &hex::decode(&self.authorization_hex)?,
            &challenge,
            self.verified_at,
        )?;
        ensure!(
            authorization.signed_manifest().encode() == original
                && authorization.operation() == operation,
            "content_retain_exchange_substitution"
        );
        Ok(CustodyReceipt::decode(
            &hex::decode(&self.receipt_hex)?,
            &authorization,
            self.verified_at,
        )?)
    }
}

/// One local owner key, never exported. The source cache is opened only while a
/// budget-reserved deposit is in progress, not held throughout the maintenance loop.
pub(super) struct RetentionOwner {
    prepared: Prepared,
}

impl RetentionOwner {
    pub(super) fn new(signer: SigningKey, original: &[u8], at: u64) -> Result<Self> {
        let publication = SignedManifest::decode(original)?;
        let manifest = publication.verify(&signer.verifying_key(), at)?;
        ensure!(
            manifest.metadata().content_type != PRIVATE_MESSAGE_CONTENT_TYPE,
            "content_retain_public_only"
        );
        Ok(Self {
            prepared: Prepared {
                signer,
                signed: publication,
                manifest,
                source: None,
                operation: CustodyOperation::Inspect,
            },
        })
    }

    pub(super) fn manifest(&self) -> &VerifiedManifest {
        &self.prepared.manifest
    }

    pub(super) async fn exchange(
        &mut self,
        socket: &Path,
        provider: &VerifyingKey,
        source: Option<(&Path, CacheLimits)>,
        original: &mut Option<RetainedExchange>,
    ) -> Result<()> {
        self.prepared.operation = if source.is_some() {
            CustodyOperation::Deposit
        } else {
            CustodyOperation::Inspect
        };
        self.prepared.source = source
            .map(|(path, limits)| {
                let mut cache = ChunkStore::open(path, limits)?;
                reassemble(
                    &self.prepared.manifest,
                    &mut [&mut cache],
                    now_seconds()?,
                    &mut std::io::sink(),
                )?;
                Ok::<_, anyhow::Error>(cache)
            })
            .transpose()?;
        let result = self
            .prepared
            .remote(socket, provider, &mut None, true, original)
            .await;
        self.prepared.source = None;
        result
    }

    pub(super) fn release_source(&mut self) {
        self.prepared.source = None;
    }
}

fn validate_accounting(accounting: &ContentReceipt, receipt: &CustodyReceipt) -> Result<()> {
    let complete = receipt.state() == CustodyState::Complete;
    // The public Ed25519 libp2p key's canonical protobuf envelope, decoded by the pinned library.
    let mut key = vec![8, 1, 18, 32];
    key.extend_from_slice(receipt.provider_key());
    let peer = volparossa_identity::PublicKey::try_decode_protobuf(&key)?
        .to_peer_id()
        .to_string();
    ensure!(
        accounting.network_publication == complete
            && accounting.bytes == if complete { receipt.object_bytes() } else { 0 }
            && accounting.chunks == if complete { receipt.unique_chunks() } else { 0 }
            && accounting.providers_used == 1
            && accounting.provider_peer_ids == [peer]
            && accounting.peer_bytes == 0
            && !accounting.origin_authenticated
            && accounting.origin_body_bytes == 0
            && accounting.origin_range_requests == 0,
        "final custody accounting does not match the independently verified provider observation"
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser as _;

    #[test]
    fn custody_parser_is_explicit_and_providers_are_distinct_not_fixed_to_two() {
        let key = SigningKey::from_bytes(&[17; 32]).verifying_key();
        let peer = SigningKey::from_bytes(&[29; 32]).verifying_key();
        let key_hex = hex::encode(key.as_bytes());
        assert!(
            crate::Cli::try_parse_from([
                "volparossa",
                "content",
                "custody",
                "inspect",
                "--manifest",
                "original.pb",
                "--provider-key",
                &key_hex
            ])
            .is_ok()
        );
        assert!(
            crate::Cli::try_parse_from([
                "volparossa",
                "content",
                "custody",
                "deposit",
                "--manifest",
                "original.pb",
                "--provider-key",
                &key_hex
            ])
            .is_err()
        );
        assert!(
            crate::Cli::try_parse_from([
                "volparossa",
                "content",
                "custody",
                "inspect",
                "--manifest",
                "original.pb",
                "--provider-key",
                &key_hex,
                "--cache",
                "private-cache"
            ])
            .is_err()
        );
        assert!(validate_providers(&[key], None).is_ok());
        assert!(validate_providers(&[key, peer], None).is_ok());
        assert!(validate_providers(&[key, key], None).is_err());
        assert!(validate_providers(&[key], Some(&key)).is_err());
        assert!(validate_providers(&[], None).is_err());
        assert!(validate_providers(&vec![key; MAX_PROVIDER_KEYS + 1], None).is_err());
    }
}
