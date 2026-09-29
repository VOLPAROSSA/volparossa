//! One independently enrolled authority owner. Inbox contents are data, never signing commands.

mod journal;

use anyhow::{Result, ensure};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use serde_json::{Value, json};
use std::{
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::signal::unix::{SignalKind, signal};
use volparossa_policy::object::{
    SignedObjectDecision, exchange::DecisionRequest, verify_object_endorsement,
};

use super::super::{
    ModelProfile, Selection, evidence_from_replay, milliseconds, open_output, parse_key,
    parse_manifest, policy_context, retain, sha, storage, task, transfer, validate_body,
};
use crate::content::{self, policy_exchange};

#[derive(Debug, Args)]
pub(crate) struct Options {
    #[arg(long)]
    policy_config: PathBuf,
    /// Existing encrypted authority identity, separate from the public content identity.
    #[arg(long)]
    authority_identity: PathBuf,
    #[arg(long)]
    authority_passphrase_file: PathBuf,
    #[arg(long, value_parser=parse_key)]
    authority_key: VerifyingKey,
    #[arg(long)]
    identity: PathBuf,
    #[arg(long)]
    passphrase_file: PathBuf,
    #[arg(long, value_parser=parse_key)]
    publication_key: VerifyingKey,
    #[arg(long, value_parser=content::parse_content_name)]
    reply_name: String,
    /// Selected transport publisher, not an authority imported from its request.
    #[arg(long, value_parser=parse_key)]
    request_publisher_key: VerifyingKey,
    #[arg(long, value_parser=content::parse_content_name)]
    request_name: String,
    #[arg(long, default_value_t=1, value_parser=clap::value_parser!(u64).range(1..))]
    min_revision: u64,
    #[arg(long, value_parser=parse_key)]
    requester_key: VerifyingKey,
    #[arg(long, value_parser=parse_key)]
    source_publisher_key: VerifyingKey,
    #[arg(long, value_parser=parse_manifest)]
    source_manifest_id: [u8; 32],
    #[arg(long, required=true, value_parser=parse_key)]
    provider_key: Vec<VerifyingKey>,
    #[arg(long, default_value = "smollm2-360m-v1")]
    model_profile: ModelProfile,
    #[arg(long)]
    directory: PathBuf,
    #[arg(long, default_value_t=60, value_parser=clap::value_parser!(u16).range(1..=3600))]
    poll_seconds: u16,
    #[arg(long)]
    execute: bool,
    #[arg(long, requires = "execute")]
    resume: bool,
    #[command(flatten)]
    limits: content::Limits,
}

fn enrollment(args: &Options) -> Value {
    json!({"version":1,"scope":"selected_public_object_authority_inbox",
        "policy_config":args.policy_config,"authority_key":hex::encode(args.authority_key.as_bytes()),
        "authority_identity":args.authority_identity,"authority_passphrase_file":args.authority_passphrase_file,
        "identity":args.identity,"passphrase_file":args.passphrase_file,
        "publication_key":hex::encode(args.publication_key.as_bytes()),"reply_name":args.reply_name,
        "request_publisher_key":hex::encode(args.request_publisher_key.as_bytes()),
        "request_name":args.request_name,"min_revision":args.min_revision,
        "requester_key":hex::encode(args.requester_key.as_bytes()),
        "source_publisher_key":hex::encode(args.source_publisher_key.as_bytes()),
        "source_manifest_id":hex::encode(args.source_manifest_id),
        "providers":args.provider_key.iter().map(|key|hex::encode(key.as_bytes())).collect::<Vec<_>>(),
        "model_profile":args.model_profile,"poll_seconds":args.poll_seconds,
        "limits":args.limits.configuration()})
}

pub(in crate::compute::peer) async fn run(args: &Options, socket: &Path) -> Result<()> {
    ensure!(
        [
            &args.policy_config,
            &args.authority_identity,
            &args.authority_passphrase_file,
            &args.identity,
            &args.passphrase_file,
            &args.directory
        ]
        .iter()
        .all(|p| p.is_absolute()),
        "policy_authority_absolute_paths"
    );
    ensure!(
        args.provider_key.len() == 2
            && args.provider_key[0] != args.provider_key[1]
            && args.model_profile.supports_rich_inference(),
        "policy_authority_selected_assessors"
    );
    ensure!(
        args.authority_key != args.publication_key && args.authority_identity != args.identity,
        "policy_authority_separate_transport_identity"
    );
    if !args.execute {
        println!(
            "{}",
            json!({"operation":"compute_policy_authority","execute":false,
            "enrollment":enrollment(args),"model_execution":false,"network_policy_activation":false})
        );
        return Ok(());
    }
    let mut interrupt = signal(SignalKind::interrupt())?;
    let mut terminate = signal(SignalKind::terminate())?;
    let _context = authority_context(args)?;
    drop(unlock_authority(args)?);
    let _lock = task::open_directory(&args.directory, args.resume)?;
    retain(
        &args.directory.join("enrollment.json"),
        &serde_json::to_vec(&enrollment(args))?,
    )?;
    let mut last = None;
    loop {
        let result = tokio::select! { biased;
            _=interrupt.recv()=>break, _=terminate.recv()=>break,
            result=tick(args,socket,&mut last)=>result,
        };
        let status = match result {
            Ok(value) => value,
            // Do not persist received content or detailed parser errors in ordinary status.
            Err(_) => json!({"operation":"compute_policy_authority","ready":false,
                "state":"awaiting_valid_request_or_transport","network_policy_activation":false}),
        };
        task::write_bytes(
            &args.directory.join("status.json"),
            &serde_json::to_vec(&status)?,
            true,
        )?;
        tokio::select! {
            _=interrupt.recv()=>break, _=terminate.recv()=>break,
            ()=tokio::time::sleep(Duration::from_secs(u64::from(args.poll_seconds)))=>{},
        }
    }
    println!(
        "{}",
        json!({"operation":"compute_policy_authority","stopped":true,
        "network_policy_activation":false,"shared_routes_disconnected":false})
    );
    Ok(())
}

async fn tick(args: &Options, socket: &Path, last: &mut Option<String>) -> Result<Value> {
    let download = policy_exchange::local_request(
        &args.request_publisher_key,
        &args.request_name,
        args.min_revision,
        socket,
        &args.directory,
    )
    .await?;
    let request = DecisionRequest::decode(&download.bytes)?;
    let proposal = SignedObjectDecision::decode(request.proposal())?;
    let body = proposal.body();
    let context = authority_context(args)?;
    ensure!(
        download.manifest.metadata().revision == body.decision_revision
            && download.manifest.validity().expires <= body.expires_at_ms / 1000
            && body.policy_hash == *context.manifest.policy_hash()
            && body.policy_version == context.manifest.manifest_version(),
        "policy_authority_request_scope"
    );
    let request_hash = sha(&download.bytes);
    if last.as_ref() == Some(&request_hash) {
        ensure!(
            milliseconds()? < body.expires_at_ms,
            "policy_authority_request_expired"
        );
        return Ok(status(body.decision_revision, &request_hash, true));
    }
    let output = args.directory.join(format!("round-{request_hash}"));
    // Bound retained inbox history independently of an untrusted publisher's revisions.
    let round_count = std::fs::read_dir(&args.directory)?
        .filter_map(Result::ok)
        .filter(|entry| entry.file_name().to_string_lossy().starts_with("round-"))
        .count();
    ensure!(
        storage::exists(&output)? || round_count < 64,
        "policy_authority_round_storage_bound"
    );
    let selection = selected(args, &output);
    let at = milliseconds()?;
    let context = policy_context(&selection, at)?;
    let (enrolled, result) = transfer::replay_bundle(
        request.assessment_bundle(),
        &args.requester_key,
        &args.directory,
    )?;
    let evidence = evidence_from_replay(
        &selection,
        &enrolled,
        &result,
        request.assessment_bundle(),
        at,
    )?;
    validate_body(body, &evidence, &context, milliseconds()?)?;
    let _round_lock = open_output(&output)?;
    retain(&output.join("request.bin"), &download.bytes)?;
    retain(&output.join("request.manifest"), &download.signed_manifest)?;
    retain(
        &output.join("assessment.bundle"),
        request.assessment_bundle(),
    )?;
    retain(&output.join("proposal.bin"), request.proposal())?;
    let signer = unlock_authority(args)?;
    // Commit a same-identity, same-epoch revision reservation before releasing a signature.
    journal::reserve(
        &args.authority_identity,
        &args.authority_key,
        &proposal,
        milliseconds()?,
    )?;
    let mut endorsement = SignedObjectDecision::new(body.clone())?;
    endorsement.endorse(&signer)?;
    drop(signer);
    let bytes = endorsement.encode()?;
    let context = policy_context(&selection, milliseconds()?)?;
    validate_body(body, &evidence, &context, milliseconds()?)?;
    verify_object_endorsement(
        &bytes,
        milliseconds()?,
        &args.authority_key,
        &context.trust,
        context.verification,
        &context.manifest,
    )?;
    retain(&output.join("endorsement.bin"), &bytes)?;
    let contribution = publish_reply(args, &output, body, socket).await?;
    task::write_bytes(
        &output.join("transport.json"),
        &serde_json::to_vec(&json!({
        "local_inbox":download.receipt,"contribution":contribution,
        "private_keys_transferred":false,"quorum_verified":false}))?,
        true,
    )?;
    *last = Some(request_hash.clone());
    Ok(status(body.decision_revision, &request_hash, false))
}

async fn publish_reply(
    args: &Options,
    output: &Path,
    body: &volparossa_policy::object::ObjectDecision,
    socket: &Path,
) -> Result<Value> {
    let cache = output.join("cache");
    let manifest = policy_exchange::publish(
        content::PolicyDecisionPublication {
            input: output.join("endorsement.bin"),
            reuse_cache: storage::exists(&cache)?,
            cache: cache.clone(),
            manifest: output.join("publication.manifest"),
            name: args.reply_name.clone(),
            revision: body.decision_revision,
            expires_not_after: body.expires_at_ms / 1000,
            identity: args.identity.clone(),
            passphrase_file: args.passphrase_file.clone(),
            limits: args.limits.clone(),
        },
        &args.publication_key,
        policy_exchange::Kind::Endorsement,
        socket,
    )
    .await?;
    content::contribute_existing(
        &content::Contribute::existing(
            output.join("publication.manifest"),
            args.publication_key,
            cache,
            args.limits.clone(),
        )
        .expect_manifest_id(*manifest.manifest_id()),
        socket,
    )
    .await
}

fn selected(args: &Options, output: &Path) -> Selection {
    Selection {
        assessment_bundle: output.join("assessment.bundle"),
        policy_config: args.policy_config.clone(),
        requester_key: args.requester_key,
        source_publisher_key: args.source_publisher_key,
        source_manifest_id: args.source_manifest_id,
        provider_key: args.provider_key.clone(),
        model_profile: args.model_profile,
    }
}

fn unlock_authority(args: &Options) -> Result<ed25519_dalek::SigningKey> {
    let signer = content::unlock_signer(
        Some(&args.authority_identity),
        Some(&args.authority_passphrase_file),
    )?;
    ensure!(
        signer.verifying_key() == args.authority_key,
        "policy_authority_identity_changed"
    );
    Ok(signer)
}

fn authority_context(args: &Options) -> Result<crate::doctor::PolicyContext> {
    let config = volparossa_config::Config::from_path(&args.policy_config)?;
    let context =
        crate::doctor::load_policy_context(&config, &args.policy_config, milliseconds()?)?;
    ensure!(
        context
            .trust
            .maintainers()
            .iter()
            .any(|key| key.verifying_key() == &args.authority_key),
        "policy_authority_not_current_maintainer"
    );
    Ok(context)
}

fn status(revision: u64, request_hash: &str, unchanged: bool) -> Value {
    json!({"operation":"compute_policy_authority","ready":true,"decision_revision":revision,
        "request_sha256":request_hash,"unchanged":unchanged,"endorsements":1,
        "provider_signed_claims_replayed":4,"threshold_verified":false,
        "network_policy_activation":false,"model_execution":false,
        "semantic_correctness_proven":false,"legal_status":"not_determined"})
}
