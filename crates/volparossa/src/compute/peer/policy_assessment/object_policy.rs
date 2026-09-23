//! Automatic object-scoped policy decisions under the existing, separate authority quorum.
//! Compute peers provide signed judgments; they never become policy maintainers.

pub(in crate::compute::peer) mod distribution;
pub(in crate::compute::peer) mod follow;
pub(in crate::compute::peer) mod round;

#[cfg(test)]
mod tests;

use std::{
    fs::File,
    path::Path,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::Context as _;
use nix::fcntl::Flock;
use rand_core::{OsRng, RngCore as _};
use volparossa_config::Config;
use volparossa_policy::object::{
    ObjectDecision, ObjectOutcome, ObjectSubject, SignedObjectDecision, VerifiedObjectDecision,
    verify_object_decision,
};

use super::{
    Args, Enrollment, ModelProfile, PathBuf, Result, Value, VerifyingKey, ensure, json, parse_key,
    parse_manifest, sha, storage, task, transfer,
};
use crate::doctor::PolicyContext;

const MAX_DECISION_BYTES: u64 = 8192;

#[derive(Debug, Args)]
pub(crate) struct Selection {
    /// Existing portable four-transcript assessment package; never a caller-supplied verdict.
    #[arg(long)]
    assessment_bundle: PathBuf,
    /// Existing node configuration. Trust and current policy are loaded through its normal loader.
    #[arg(long)]
    policy_config: PathBuf,
    #[arg(long, value_parser = parse_key)]
    requester_key: VerifyingKey,
    #[arg(long, value_parser = parse_key)]
    source_publisher_key: VerifyingKey,
    #[arg(long, value_parser = parse_manifest)]
    source_manifest_id: [u8; 32],
    /// The two selected assessors, in their original order. Not policy signing authorities.
    #[arg(long, required = true, value_parser = parse_key)]
    provider_key: Vec<VerifyingKey>,
    #[arg(long, default_value = "smollm2-360m-v1")]
    model_profile: ModelProfile,
}

#[derive(Debug, Args)]
pub(crate) struct Propose {
    #[command(flatten)]
    selection: Selection,
    /// Private retained proposal directory. Repeating this command reopens identical bytes.
    #[arg(long)]
    output: PathBuf,
    #[arg(long, value_parser = clap::value_parser!(u64).range(1..))]
    decision_revision: u64,
    #[arg(long)]
    execute: bool,
}

#[derive(Debug, Args)]
pub(crate) struct Endorse {
    #[command(flatten)]
    selection: Selection,
    #[arg(long)]
    proposal: PathBuf,
    /// Each authority retains its own immutable endorsement in a separate private directory.
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    identity: Option<PathBuf>,
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
    #[arg(long)]
    execute: bool,
}

#[derive(Debug, Args)]
pub(crate) struct Combine {
    #[command(flatten)]
    selection: Selection,
    #[arg(long)]
    proposal: PathBuf,
    #[arg(long, required = true)]
    endorsement: Vec<PathBuf>,
    /// Receives decision.bin only after current threshold verification; does not activate it.
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    execute: bool,
    /// Apply the verified exact-object decision through this node's protected local control API.
    #[arg(long, requires = "execute")]
    apply: bool,
}

struct AssessmentEvidence {
    subject: ObjectSubject,
    framework_sha256: [u8; 32],
    evidence_sha256: [u8; 32],
    outcome: ObjectOutcome,
    selected_at_ms: u64,
    expires_at_ms: u64,
}

fn milliseconds() -> Result<u64> {
    Ok(u64::try_from(
        SystemTime::now().duration_since(UNIX_EPOCH)?.as_millis(),
    )?)
}

fn hash_bytes(value: &str) -> Result<[u8; 32]> {
    parse_manifest(value).map_err(anyhow::Error::msg)
}

fn selection_record(args: &Selection) -> Value {
    json!({"version":1,"requester_key":hex::encode(args.requester_key.as_bytes()),
        "source_publisher_key":hex::encode(args.source_publisher_key.as_bytes()),
        "source_manifest_id":hex::encode(args.source_manifest_id),
        "providers":args.provider_key.iter().map(|key|hex::encode(key.as_bytes())).collect::<Vec<_>>(),
        "model_profile":args.model_profile})
}

fn preview(
    args: &Selection,
    output: &Path,
    operation: &str,
    execute: bool,
) -> Result<Option<Value>> {
    ensure!(
        args.assessment_bundle.is_absolute()
            && args.policy_config.is_absolute()
            && output.is_absolute(),
        "compute_object_policy_absolute_paths"
    );
    ensure!(
        args.provider_key.len() == 2
            && args.provider_key[0] != args.provider_key[1]
            && args.model_profile.supports_rich_inference(),
        "compute_object_policy_selected_assessors"
    );
    if !execute {
        return Ok(Some(json!({"operation":operation,"execute":false,
            "subject_scope":"exact_native_object","automatic_judgment":true,
            "human_approval_required":false,"compute_providers_are_authorities":false,
            "network_policy_activation":false,"model_execution":false})));
    }
    Ok(None)
}

fn retain(path: &Path, bytes: &[u8]) -> Result<()> {
    if storage::exists(path)? {
        ensure!(
            storage::read(path, bytes.len() as u64)? == bytes,
            "compute_object_policy_immutable_output_changed"
        );
        Ok(())
    } else {
        task::write_bytes(path, bytes, false)
    }
}

fn open_output(output: &Path) -> Result<Flock<File>> {
    task::open_directory(output, storage::exists(output)?)
}

fn policy_context(args: &Selection, at: u64) -> Result<PolicyContext> {
    let config = Config::from_path(&args.policy_config)?;
    crate::doctor::load_policy_context(&config, &args.policy_config, at)
}

fn evidence_from_replay(
    args: &Selection,
    enrolled: &Enrollment,
    result: &Value,
    bytes: &[u8],
    at: u64,
) -> Result<AssessmentEvidence> {
    ensure!(
        enrolled.providers
            == [
                hex::encode(args.provider_key[0].as_bytes()),
                hex::encode(args.provider_key[1].as_bytes())
            ]
            && enrolled.scope.source_publisher_key
                == hex::encode(args.source_publisher_key.as_bytes())
            && enrolled.scope.source_manifest_id == hex::encode(args.source_manifest_id)
            && enrolled.profile()? == args.model_profile
            && result["complete"] == true,
        "compute_object_policy_selected_evidence_changed"
    );
    let selected_at_ms = enrolled
        .selected_at
        .checked_mul(1000)
        .context("compute_object_policy_time")?;
    let expires_at_ms = enrolled
        .expires
        .checked_mul(1000)
        .context("compute_object_policy_time")?;
    ensure!(
        selected_at_ms <= at && at < expires_at_ms,
        "compute_object_policy_original_source_expired"
    );
    let outcome = match serde_json::from_value::<super::assessment::Outcome>(
        result["decision"]["outcome"].clone(),
    )? {
        super::assessment::Outcome::Allow => ObjectOutcome::Allow,
        super::assessment::Outcome::Deny => ObjectOutcome::Deny,
        super::assessment::Outcome::Undetermined => ObjectOutcome::Undetermined,
    };
    Ok(AssessmentEvidence {
        subject: ObjectSubject {
            publisher_key: args.source_publisher_key.to_bytes(),
            manifest_id: args.source_manifest_id,
            object_sha256: hash_bytes(&enrolled.scope.source_sha256)?,
        },
        framework_sha256: hash_bytes(&enrolled.scope.framework_sha256)?,
        evidence_sha256: hash_bytes(&sha(bytes))?,
        outcome,
        selected_at_ms,
        expires_at_ms,
    })
}

fn reopen_evidence(args: &Selection, output: &Path, at: u64) -> Result<AssessmentEvidence> {
    let bytes = storage::read(
        &args.assessment_bundle,
        crate::content::policy_bundle::MAX_BYTES,
    )?;
    let (enrolled, result) = transfer::replay_bundle(&bytes, &args.requester_key, output)?;
    let evidence = evidence_from_replay(args, &enrolled, &result, &bytes, at)?;
    retain(&output.join("assessment.bundle"), &bytes)?;
    retain(
        &output.join("selection.json"),
        &serde_json::to_vec(&selection_record(args))?,
    )?;
    Ok(evidence)
}

fn expiry(evidence: &AssessmentEvidence, context: &PolicyContext, issued: u64) -> Result<u64> {
    Ok(evidence
        .expires_at_ms
        .min(context.manifest.expires_at_ms())
        .min(
            issued
                .checked_add(context.verification.maximum_lifetime_ms())
                .context("compute_object_policy_time")?,
        ))
}

fn validate_body(
    body: &ObjectDecision,
    evidence: &AssessmentEvidence,
    context: &PolicyContext,
    at: u64,
) -> Result<()> {
    context.manifest.ensure_active_at(at)?;
    ensure!(
        body.policy_hash == *context.manifest.policy_hash()
            && body.policy_version == context.manifest.manifest_version()
            && body.subject == evidence.subject
            && body.framework_sha256 == evidence.framework_sha256
            && body.evidence_sha256 == evidence.evidence_sha256
            && body.outcome == evidence.outcome,
        "compute_object_policy_proposal_evidence_changed"
    );
    ensure!(
        body.decision_revision > 0
            && body.nonce != [0; 32]
            && body.issued_at_ms >= context.manifest.valid_from_ms()
            && body.issued_at_ms >= evidence.selected_at_ms
            && body.issued_at_ms <= at
            && at < body.expires_at_ms
            && body.expires_at_ms == expiry(evidence, context, body.issued_at_ms)?,
        "compute_object_policy_original_proposal_expired_or_changed"
    );
    Ok(())
}

fn proposal(
    path: &Path,
    evidence: &AssessmentEvidence,
    context: &PolicyContext,
    at: u64,
) -> Result<(Vec<u8>, SignedObjectDecision)> {
    let bytes = storage::read(path, MAX_DECISION_BYTES)?;
    let original = SignedObjectDecision::decode(&bytes)?;
    validate_body(original.body(), evidence, context, at)?;
    Ok((bytes, original))
}

fn report(
    operation: &str,
    body: &ObjectDecision,
    output: &Path,
    threshold: bool,
    applied: bool,
) -> Value {
    let outcome = match body.outcome {
        ObjectOutcome::Allow => "allow",
        ObjectOutcome::Deny => "deny",
        ObjectOutcome::Undetermined => "undetermined",
    };
    json!({"operation":operation,"complete":true,"decision_revision":body.decision_revision,
        "subject":{"publisher_key":hex::encode(body.subject.publisher_key),
            "manifest_id":hex::encode(body.subject.manifest_id),"object_sha256":hex::encode(body.subject.object_sha256)},
        "outcome":outcome,"policy_hash":hex::encode(body.policy_hash),"policy_version":body.policy_version,
        "evidence_sha256":hex::encode(body.evidence_sha256),"issued_at_ms":body.issued_at_ms,
        "expires_at_ms":body.expires_at_ms,"output":output,"threshold_verified":threshold,
        "provider_signed_claims_replayed":4,"network_policy_activation":false,
        "local_object_policy_applied":applied,
        "legal_status":"not_determined","semantic_correctness_proven":false})
}

pub(in crate::compute::peer) fn propose(args: &Propose) -> Result<()> {
    println!("{}", propose_value(args)?);
    Ok(())
}

pub(in crate::compute::peer) fn propose_value(args: &Propose) -> Result<Value> {
    const OP: &str = "compute_policy_propose";
    if let Some(planned) = preview(&args.selection, &args.output, OP, args.execute)? {
        return Ok(planned);
    }
    let _lock = open_output(&args.output)?;
    let at = milliseconds()?;
    let context = policy_context(&args.selection, at)?;
    let evidence = reopen_evidence(&args.selection, &args.output, at)?;
    let path = args.output.join("proposal.bin");
    let original = if storage::exists(&path)? {
        proposal(&path, &evidence, &context, milliseconds()?)?.1
    } else {
        let mut nonce = [0; 32];
        OsRng.fill_bytes(&mut nonce);
        let body = ObjectDecision {
            policy_hash: *context.manifest.policy_hash(),
            policy_version: context.manifest.manifest_version(),
            decision_revision: args.decision_revision,
            subject: evidence.subject,
            framework_sha256: evidence.framework_sha256,
            evidence_sha256: evidence.evidence_sha256,
            outcome: evidence.outcome,
            issued_at_ms: at,
            expires_at_ms: expiry(&evidence, &context, at)?,
            nonce,
        };
        validate_body(&body, &evidence, &context, milliseconds()?)?;
        let original = SignedObjectDecision::new(body)?;
        retain(&path, &original.encode()?)?;
        original
    };
    ensure!(
        original.body().decision_revision == args.decision_revision,
        "compute_object_policy_revision_changed"
    );
    Ok(report(OP, original.body(), &path, false, false))
}

pub(in crate::compute::peer) fn endorse(args: &Endorse) -> Result<()> {
    println!("{}", endorse_value(args)?);
    Ok(())
}

pub(in crate::compute::peer) fn endorse_value(args: &Endorse) -> Result<Value> {
    const OP: &str = "compute_policy_endorse";
    ensure!(
        args.proposal.is_absolute(),
        "compute_object_policy_absolute_paths"
    );
    if let Some(planned) = preview(&args.selection, &args.output, OP, args.execute)? {
        return Ok(planned);
    }
    let _lock = open_output(&args.output)?;
    let at = milliseconds()?;
    let context = policy_context(&args.selection, at)?;
    let evidence = reopen_evidence(&args.selection, &args.output, at)?;
    let (bytes, original) = proposal(&args.proposal, &evidence, &context, milliseconds()?)?;
    retain(&args.output.join("proposal.bin"), &bytes)?;
    let signer =
        crate::content::unlock_signer(args.identity.as_deref(), args.passphrase_file.as_deref())?;
    let context = policy_context(&args.selection, milliseconds()?)?;
    ensure!(
        context
            .trust
            .maintainers()
            .iter()
            .any(|authority| authority.verifying_key() == &signer.verifying_key()),
        "compute_object_policy_signer_not_configured_authority"
    );
    validate_body(original.body(), &evidence, &context, milliseconds()?)?;
    let mut endorsement = SignedObjectDecision::new(original.body().clone())?;
    endorsement.endorse(&signer)?;
    drop(signer);
    let path = args.output.join("endorsement.bin");
    retain(&path, &endorsement.encode()?)?;
    Ok(report(OP, endorsement.body(), &path, false, false))
}

pub(in crate::compute::peer) async fn combine(args: &Combine, socket: &Path) -> Result<()> {
    println!("{}", combine_value(args, socket).await?);
    Ok(())
}

pub(in crate::compute::peer) async fn combine_value(
    args: &Combine,
    socket: &Path,
) -> Result<Value> {
    const OP: &str = "compute_policy_combine";
    ensure!(
        !args.apply || args.execute,
        "compute_object_policy_apply_requires_execute"
    );
    ensure!(
        args.proposal.is_absolute()
            && (1..=32).contains(&args.endorsement.len())
            && args.endorsement.iter().all(|path| path.is_absolute()),
        "compute_object_policy_endorsement_inputs"
    );
    if let Some(planned) = preview(&args.selection, &args.output, OP, args.execute)? {
        return Ok(planned);
    }
    let _lock = open_output(&args.output)?;
    let at = milliseconds()?;
    let context = policy_context(&args.selection, at)?;
    let evidence = reopen_evidence(&args.selection, &args.output, at)?;
    let (bytes, original) = proposal(&args.proposal, &evidence, &context, milliseconds()?)?;
    let mut combined = SignedObjectDecision::new(original.body().clone())?;
    for path in &args.endorsement {
        let endorsed = SignedObjectDecision::decode(&storage::read(path, MAX_DECISION_BYTES)?)?;
        combined.merge(&endorsed)?;
    }
    let bytes_verified = combined.encode()?;
    let context = policy_context(&args.selection, milliseconds()?)?;
    validate_body(combined.body(), &evidence, &context, milliseconds()?)?;
    let verified = verify_object_decision(
        &bytes_verified,
        milliseconds()?,
        &context.trust,
        context.verification,
        &context.manifest,
    )?;
    retain(&args.output.join("proposal.bin"), &bytes)?;
    let path = args.output.join("decision.bin");
    retain(&path, &bytes_verified)?;
    if args.apply {
        apply_decision(&bytes_verified, &verified, &args.output, socket).await?;
    }
    Ok(report(OP, combined.body(), &path, true, args.apply))
}

async fn apply_decision(
    bytes: &[u8],
    verified: &VerifiedObjectDecision,
    output: &Path,
    socket: &Path,
) -> Result<()> {
    let receipt = request_apply_decision(bytes, verified, socket).await?;
    retain(
        &output.join("apply-receipt.json"),
        &serde_json::to_vec(&receipt)?,
    )
}

async fn request_apply_decision(
    bytes: &[u8],
    verified: &VerifiedObjectDecision,
    socket: &Path,
) -> Result<volparossa_local_control::ContentPolicyReceipt> {
    use volparossa_local_control::{
        ContentPolicyApplyRequest, control_request::Operation, control_response::Payload,
    };
    let response = crate::control::request(
        socket,
        Operation::ContentPolicyApply(ContentPolicyApplyRequest {
            envelope: bytes.to_vec(),
        }),
    )
    .await?;
    ensure!(
        response.diagnostic_code == "CONTENT_POLICY_APPLIED",
        "compute_object_policy_apply_receipt"
    );
    let Some(Payload::ContentPolicy(receipt)) = response.payload else {
        anyhow::bail!("compute_object_policy_apply_receipt");
    };
    let body = verified.body();
    ensure!(
        receipt.version == 1
            && receipt.manifest_id == body.subject.manifest_id
            && receipt.decision_hash.as_slice() == verified.decision_hash().as_slice()
            && receipt.decision_revision == body.decision_revision
            && receipt.policy_hash == body.policy_hash
            && receipt.outcome == body.outcome as i32,
        "compute_object_policy_apply_receipt"
    );
    Ok(receipt)
}
