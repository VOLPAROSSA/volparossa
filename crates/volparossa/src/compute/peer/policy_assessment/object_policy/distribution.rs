//! Share original policy-quorum bytes as inert content; receiving never imports publisher trust.

#[cfg(test)]
mod tests;

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use serde_json::{Value, json};
use volparossa_content::{ChunkStore, SignedManifest, VerifiedManifest};
use volparossa_policy::object::{ObjectSubject, VerifiedObjectDecision, verify_object_decision};

use super::{
    MAX_DECISION_BYTES, apply_decision, milliseconds, open_output, parse_key, parse_manifest,
    retain, sha, storage,
};
use crate::{content, doctor::PolicyContext};

#[derive(Clone, Debug, Args)]
pub(super) struct Selection {
    /// Exact quorum envelope, received through explicitly selected public content or retained locally.
    #[arg(long)]
    pub(super) decision: PathBuf,
    /// This node's independently configured current authority; never supplied by the content wrapper.
    #[arg(long)]
    pub(super) policy_config: PathBuf,
    #[arg(long, value_parser = parse_key)]
    pub(super) subject_publisher_key: VerifyingKey,
    #[arg(long, value_parser = parse_manifest)]
    pub(super) subject_manifest_id: [u8; 32],
    #[arg(long, value_parser = parse_manifest)]
    pub(super) subject_sha256: [u8; 32],
    /// Independently selected original canonical decision-body hash.
    #[arg(long, value_parser = parse_manifest)]
    pub(super) decision_hash: [u8; 32],
    #[arg(long, value_parser = parse_manifest)]
    pub(super) evidence_sha256: [u8; 32],
}

#[derive(Debug, Args)]
pub(crate) struct Publish {
    #[command(flatten)]
    pub(super) selection: Selection,
    /// Native content publisher only, never an additional policy maintainer.
    #[arg(long, value_parser = parse_key)]
    pub(super) publication_key: VerifyingKey,
    #[arg(long, value_parser = content::parse_content_name)]
    pub(super) name: String,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    pub(super) revision: u64,
    #[arg(long)]
    pub(super) identity: PathBuf,
    #[arg(long)]
    pub(super) passphrase_file: PathBuf,
    /// Private directory containing original decision.bin, publication.manifest and cache/.
    #[arg(long)]
    pub(super) output: PathBuf,
    /// Publish locally only. Existing content custody/contribute operations perform explicit sharing.
    #[arg(long)]
    pub(super) execute: bool,
    #[command(flatten)]
    pub(super) limits: content::Limits,
}

#[derive(Debug, Args)]
pub(crate) struct Import {
    #[command(flatten)]
    selection: Selection,
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    execute: bool,
    /// Apply to this node after checking its current quorum, not to the whole network.
    #[arg(long, requires = "execute")]
    apply: bool,
}

fn preview(
    args: &Selection,
    output: &Path,
    operation: &str,
    execute: bool,
) -> Result<Option<Value>> {
    ensure!(
        args.decision.is_absolute() && args.policy_config.is_absolute() && output.is_absolute(),
        "compute_policy_distribution_absolute_paths"
    );
    if !execute {
        return Ok(Some(
            json!({"operation":operation,"execute":false,"model_execution":false,
            "network_policy_activation":false,"local_object_policy_applied":false,
            "wrapper_publisher_is_policy_authority":false}),
        ));
    }
    Ok(None)
}

fn context(args: &Selection, at: u64) -> Result<PolicyContext> {
    let config = volparossa_config::Config::from_path(&args.policy_config)?;
    crate::doctor::load_policy_context(&config, &args.policy_config, at)
}

fn verify_selected(
    args: &Selection,
    bytes: &[u8],
    context: &PolicyContext,
    at: u64,
) -> Result<VerifiedObjectDecision> {
    let verified = verify_object_decision(
        bytes,
        at,
        &context.trust,
        context.verification,
        &context.manifest,
    )?;
    let expected = ObjectSubject {
        publisher_key: args.subject_publisher_key.to_bytes(),
        manifest_id: args.subject_manifest_id,
        object_sha256: args.subject_sha256,
    };
    ensure!(
        verified.body().subject == expected
            && verified.decision_hash() == &args.decision_hash
            && verified.body().evidence_sha256 == args.evidence_sha256,
        "compute_policy_distribution_original_selection_changed"
    );
    Ok(verified)
}

fn selection(args: &Selection, bytes: &[u8]) -> Value {
    json!({"version":1,"policy_config":args.policy_config,
        "subject_publisher_key":hex::encode(args.subject_publisher_key.as_bytes()),
        "subject_manifest_id":hex::encode(args.subject_manifest_id),"subject_sha256":hex::encode(args.subject_sha256),
        "decision_hash":hex::encode(args.decision_hash),"evidence_sha256":hex::encode(args.evidence_sha256),
        "decision_sha256":sha(bytes)})
}

fn reopen(args: &Selection) -> Result<(Vec<u8>, VerifiedObjectDecision)> {
    let bytes = storage::read(&args.decision, MAX_DECISION_BYTES)?;
    let at = milliseconds()?;
    let verified = verify_selected(args, &bytes, &context(args, at)?, at)?;
    Ok((bytes, verified))
}

fn wrapper_expiry(verified: &VerifiedObjectDecision, at_ms: u64) -> Result<u64> {
    let expires = verified.body().expires_at_ms / 1000;
    ensure!(
        expires
            .checked_mul(1000)
            .context("compute_policy_distribution_time")?
            >= at_ms
                .checked_add(1000)
                .context("compute_policy_distribution_time")?,
        "compute_policy_distribution_wrapper_lifetime_unavailable"
    );
    Ok(expires)
}

fn publication_binding(
    args: &Publish,
    raw: &[u8],
    decision: &VerifiedObjectDecision,
    at: u64,
) -> Result<(Vec<u8>, VerifiedManifest)> {
    let manifest_bytes = storage::read(&args.output.join("publication.manifest"), 64 * 1024)?;
    let manifest = SignedManifest::decode(&manifest_bytes)?.verify(&args.publication_key, at)?;
    ensure!(
        manifest.metadata().name == args.name
            && manifest.metadata().revision == args.revision
            && manifest.metadata().content_type == content::POLICY_DECISION_CONTENT_TYPE
            && manifest.length() == raw.len() as u64
            && hex::encode(manifest.object_sha256()) == sha(raw)
            && manifest.validity().expires == decision.body().expires_at_ms / 1000,
        "compute_policy_distribution_original_publication_changed"
    );
    let mut cache = ChunkStore::open(&args.output.join("cache"), args.limits.cache_limits()?)?;
    let mut reconstructed = Vec::with_capacity(raw.len());
    volparossa_content::reassemble(&manifest, &mut [&mut cache], at, &mut reconstructed)?;
    ensure!(
        reconstructed == raw,
        "compute_policy_distribution_cached_decision_changed"
    );
    Ok((manifest_bytes, manifest))
}

pub(in crate::compute::peer) async fn publish(args: &Publish, socket: &Path) -> Result<()> {
    println!("{}", publish_value(args, socket).await?);
    Ok(())
}

pub(in crate::compute::peer) async fn publish_value(
    args: &Publish,
    socket: &Path,
) -> Result<Value> {
    const OP: &str = "compute_policy_publish";
    ensure!(
        args.identity.is_absolute() && args.passphrase_file.is_absolute(),
        "compute_policy_distribution_identity_paths"
    );
    if let Some(planned) = preview(&args.selection, &args.output, OP, args.execute)? {
        return Ok(planned);
    }
    let (bytes, approved) = reopen(&args.selection)?;
    let _lock = open_output(&args.output)?;
    let mut request = selection(&args.selection, &bytes);
    request["publication"] = json!({"publisher_key":hex::encode(args.publication_key.as_bytes()),
        "name":args.name,"revision":args.revision,"limits":args.limits.configuration()});
    retain(
        &args.output.join("selection.json"),
        &serde_json::to_vec(&request)?,
    )?;
    retain(&args.output.join("decision.bin"), &bytes)?;
    let manifest_path = args.output.join("publication.manifest");
    if !storage::exists(&manifest_path)? {
        let signer = content::unlock_signer(Some(&args.identity), Some(&args.passphrase_file))?;
        ensure!(
            signer.verifying_key() == args.publication_key,
            "compute_policy_distribution_publisher_identity_changed"
        );
        drop(signer);
        let expires = wrapper_expiry(&approved, milliseconds()?)?;
        let cache = args.output.join("cache");
        content::publish_command(
            &content::Publish::policy_decision(content::PolicyDecisionPublication {
                input: args.output.join("decision.bin"),
                reuse_cache: storage::exists(&cache)?,
                cache,
                manifest: manifest_path.clone(),
                name: args.name.clone(),
                revision: args.revision,
                expires_not_after: expires,
                identity: args.identity.clone(),
                passphrase_file: args.passphrase_file.clone(),
                limits: args.limits.clone(),
            }),
            socket,
        )
        .await?;
    }
    let at = milliseconds()?;
    let approved = verify_selected(&args.selection, &bytes, &context(&args.selection, at)?, at)?;
    let (manifest_bytes, manifest) = publication_binding(args, &bytes, &approved, at / 1000)?;
    let publication = json!({"manifest_id":hex::encode(manifest.manifest_id()),
        "manifest_sha256":sha(&manifest_bytes),"created":manifest.validity().created,
        "expires":manifest.validity().expires});
    retain(
        &args.output.join("publication.json"),
        &serde_json::to_vec(&publication)?,
    )?;
    let mut output = result(OP, &bytes, &approved, false);
    output["name"] = args.name.clone().into();
    output["manifest_id"] = hex::encode(manifest.manifest_id()).into();
    output["publisher_key"] = hex::encode(manifest.publisher()).into();
    output["manifest"] = serde_json::to_value(manifest_path)?;
    output["cache"] = serde_json::to_value(args.output.join("cache"))?;
    output["content_type"] = content::POLICY_DECISION_CONTENT_TYPE.into();
    output["publication_expires_unix_seconds"] = manifest.validity().expires.into();
    output["network_publication"] = false.into();
    Ok(output)
}

pub(in crate::compute::peer) async fn import(args: &Import, socket: &Path) -> Result<()> {
    const OP: &str = "compute_policy_import";
    ensure!(
        !args.apply || args.execute,
        "compute_object_policy_apply_requires_execute"
    );
    if let Some(planned) = preview(&args.selection, &args.output, OP, args.execute)? {
        println!("{planned}");
        return Ok(());
    }
    let (bytes, _) = reopen(&args.selection)?;
    let _lock = open_output(&args.output)?;
    retain(
        &args.output.join("selection.json"),
        &serde_json::to_vec(&selection(&args.selection, &bytes))?,
    )?;
    retain(&args.output.join("decision.bin"), &bytes)?;
    let at = milliseconds()?;
    let verified = verify_selected(&args.selection, &bytes, &context(&args.selection, at)?, at)?;
    if args.apply {
        apply_decision(&bytes, &verified, &args.output, socket).await?;
    }
    println!("{}", result(OP, &bytes, &verified, args.apply));
    Ok(())
}

fn result(operation: &str, raw: &[u8], verified: &VerifiedObjectDecision, applied: bool) -> Value {
    let body = verified.body();
    let outcome = match body.outcome {
        super::ObjectOutcome::Allow => "allow",
        super::ObjectOutcome::Deny => "deny",
        super::ObjectOutcome::Undetermined => "undetermined",
    };
    json!({"operation":operation,"complete":true,"decision_sha256":sha(raw),
        "decision_hash":hex::encode(verified.decision_hash()),"evidence_sha256":hex::encode(body.evidence_sha256),
        "subject":{"publisher_key":hex::encode(body.subject.publisher_key),
            "manifest_id":hex::encode(body.subject.manifest_id),"object_sha256":hex::encode(body.subject.object_sha256)},
        "policy_hash":hex::encode(body.policy_hash),"policy_version":body.policy_version,
        "decision_revision":body.decision_revision,"issued_at_ms":body.issued_at_ms,"expires_at_ms":body.expires_at_ms,
        "outcome":outcome,"threshold_verified":true,"network_policy_activation":false,
        "local_object_policy_applied":applied,"wrapper_publisher_is_policy_authority":false,
        "provider_signed_claims_replayed":0,"model_execution":false,"semantic_correctness_proven":false})
}
