//! Portable public concept judgments: exact original signatures, no new enforcement authority.

mod bundle;
use super::*;
use crate::content::policy_bundle;
use std::os::unix::fs::PermissionsExt as _;
use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity};

#[derive(Debug, Args)]
pub(crate) struct Pack {
    /// Existing complete workflow enrolled with --portable-receipts.
    #[arg(long)]
    assessment: PathBuf,
    /// New private package directory. No serving, advertising or uploading is automatic.
    #[arg(long)]
    output: PathBuf,
    #[arg(long)]
    identity: Option<PathBuf>,
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
    /// Independently selected original requester identity, not the bundle publisher key.
    #[arg(long, value_parser = parse_key)]
    requester_key: VerifyingKey,
    #[arg(long)]
    execute: bool,
}

#[derive(Debug, Args)]
pub(crate) struct Fetch {
    #[arg(long, value_parser = parse_key)]
    publisher_key: VerifyingKey,
    #[arg(long, value_parser = crate::content::parse_content_name)]
    name: String,
    #[arg(long, value_parser = parse_manifest)]
    manifest_id: [u8; 32],
    #[arg(long)]
    cache: PathBuf,
    #[arg(long)]
    reuse_cache: bool,
    #[arg(long)]
    output: PathBuf,
    /// Original requester; never inferred as trusted from the package.
    #[arg(long, value_parser = parse_key)]
    requester_key: VerifyingKey,
    /// Original native subject authority and exact version.
    #[arg(long, value_parser = parse_key)]
    source_publisher_key: VerifyingKey,
    #[arg(long, value_parser = parse_manifest)]
    source_manifest_id: [u8; 32],
    /// Two selected assessors, in the original assessment order.
    #[arg(long, required = true, value_parser = parse_key)]
    provider_key: Vec<VerifyingKey>,
    #[command(flatten)]
    limits: crate::content::Limits,
    #[arg(long)]
    execute: bool,
}

pub(in crate::compute::peer) fn pack(args: &Pack) -> Result<()> {
    ensure!(
        args.assessment.is_absolute() && args.output.is_absolute(),
        "compute_policy_paths_absolute"
    );
    if !args.execute {
        println!(
            "{}",
            json!({"operation":"compute_policy_pack","execute":false,
            "network_policy_activation":false,"automatic_publication":false})
        );
        return Ok(());
    }
    let _original = task::open_directory(&args.assessment, true)?;
    let requester = hex::encode(args.requester_key.as_bytes());
    let (enrolled, _) = storage::load(&args.assessment)?;
    let verified = replay(&args.assessment, &requester)?;
    let package = bundle::collect(&args.assessment, &requester)?;
    let bytes = serde_json::to_vec(&package)?;
    ensure!(
        bytes.len() as u64 <= policy_bundle::MAX_BYTES,
        "compute_policy_bundle_bound"
    );
    let signer =
        crate::content::unlock_signer(args.identity.as_deref(), args.passphrase_file.as_deref())?;
    let created = now()?;
    ensure!(
        created < enrolled.expires,
        "compute_policy_original_subject_expired"
    );
    let _output = task::open_directory(&args.output, false)?;
    // Verify precisely the transferable projection, not only the original directory.
    let check = private_temporary(&args.output)?;
    package.materialize(check.path())?;
    ensure!(
        replay(check.path(), &requester)? == verified,
        "compute_policy_projection_changed"
    );
    check.close()?;
    let mut cache = ChunkStore::create(
        &args.output.join("cache"),
        CacheLimits {
            max_bytes: 8 * 1024 * 1024,
            max_entries: 128,
            min_free_bytes: 0,
        },
    )?;
    let name = format!("assessment-{}", &sha(&bytes)[..32]);
    let manifest = volparossa_content::publish(
        &mut bytes.as_slice(),
        Publication {
            metadata: Metadata {
                name: name.clone(),
                revision: 1,
                content_type: policy_bundle::CONTENT_TYPE.into(),
            },
            length: bytes.len() as u64,
            validity: Validity {
                created,
                expires: enrolled.expires,
            },
        },
        &signer,
        &mut cache,
    )?;
    task::write_bytes(&args.output.join("assessment.bundle"), &bytes, false)?;
    task::write_bytes(
        &args.output.join("assessment.manifest"),
        &manifest.encode(),
        false,
    )?;
    let id = hex::encode(
        manifest
            .verify(&signer.verifying_key(), now()?)?
            .manifest_id(),
    );
    println!(
        "{}",
        json!({"operation":"compute_policy_pack","complete":true,"name":name,
        "manifest_id":id,"publisher_key":hex::encode(signer.verifying_key().as_bytes()),
        "expires":enrolled.expires,"network_policy_activation":false,
        "provider_signed_claims_verified":true,"independent_execution_proven":false})
    );
    Ok(())
}

pub(in crate::compute::peer) async fn fetch(args: &Fetch, socket: &Path) -> Result<()> {
    ensure!(
        args.output.is_absolute() && args.cache.is_absolute(),
        "compute_policy_paths_absolute"
    );
    ensure!(
        args.provider_key.len() == 2 && args.provider_key[0] != args.provider_key[1],
        "compute_policy_two_distinct_peers"
    );
    if !args.execute {
        println!(
            "{}",
            json!({"operation":"compute_policy_fetch","execute":false,
            "network_policy_activation":false,"model_execution":false})
        );
        return Ok(());
    }
    let _output = task::open_directory(&args.output, false)?;
    let downloaded = policy_bundle::fetch(
        &policy_bundle::Selection {
            publisher: args.publisher_key,
            name: args.name.clone(),
            manifest_id: args.manifest_id,
            cache: args.cache.clone(),
            reuse_cache: args.reuse_cache,
            limits: args.limits.clone(),
        },
        socket,
        &args.output,
    )
    .await?;
    let package = bundle::decode(&downloaded.bytes)?;
    let requester = hex::encode(args.requester_key.as_bytes());
    ensure!(
        package.requester_key == requester,
        "compute_policy_bundle_requester"
    );
    let retained = private_temporary(&args.output)?;
    package.materialize(retained.path())?;
    let (enrolled, _) = storage::load(retained.path())?;
    ensure!(
        enrolled.scope.source_publisher_key == hex::encode(args.source_publisher_key.as_bytes())
            && enrolled.scope.source_manifest_id == hex::encode(args.source_manifest_id)
            && enrolled.providers
                == [
                    hex::encode(args.provider_key[0].as_bytes()),
                    hex::encode(args.provider_key[1].as_bytes())
                ]
            && downloaded.expires <= enrolled.expires
            && now()? < downloaded.expires,
        "compute_policy_bundle_selected_authorities"
    );
    let result = replay(retained.path(), &requester)?;
    retained.close()?;
    ensure!(now()? < downloaded.expires, "compute_policy_bundle_expired");
    task::write_bytes(
        &args.output.join("assessment.bundle"),
        &downloaded.bytes,
        false,
    )?;
    task::write_bytes(
        &args.output.join("assessment.manifest"),
        &downloaded.signed_manifest,
        false,
    )?;
    storage::save(&args.output.join("download.json"), &downloaded.receipt)?;
    storage::save(&args.output.join("result.json"), &result)?;
    println!(
        "{}",
        json!({"operation":"compute_policy_fetch","complete":true,
        "decision":result["decision"],"provider_signed_claims_verified":true,
        "independent_execution_proven":false,"network_policy_activation":false})
    );
    Ok(())
}

fn private_temporary(parent: &Path) -> Result<tempfile::TempDir> {
    Ok(tempfile::Builder::new()
        .prefix("assessment-check-")
        .permissions(std::fs::Permissions::from_mode(0o700))
        .tempdir_in(parent)?)
}

fn replay(root: &Path, requester: &str) -> Result<Value> {
    let (enrolled, subject) = storage::load(root)?;
    ensure!(
        enrolled.portable_receipts,
        "compute_policy_portable_enrollment_required"
    );
    let mut stages = Vec::new();
    let mut assessments = Vec::new();
    for index in 0..2 {
        let stage = execution::replay(
            root,
            &enrolled,
            &format!("assessment-{index}"),
            index,
            &assessment::assessment_context(&subject)?,
            assessment::assessment_question(),
            requester,
        )?;
        let (text, evidence) = stage
            .answer
            .as_ref()
            .context("compute_policy_complete_answer_required")?;
        assessments.push(assessment::decode_assessment(
            text.as_bytes(),
            &enrolled.scope,
            evidence,
            &subject,
        )?);
        stages.push(stage.summary(true));
    }
    let assessments: [assessment::Assessment; 2] = assessments
        .try_into()
        .map_err(|_| anyhow::anyhow!("compute_policy_assessments"))?;
    let mut reviews = Vec::new();
    for index in 0..2 {
        let original = &assessments[1 - index];
        let stage = execution::replay(
            root,
            &enrolled,
            &format!("review-{index}"),
            index,
            &assessment::review_context(&subject, original)?,
            assessment::review_question(),
            requester,
        )?;
        let (text, evidence) = stage
            .answer
            .as_ref()
            .context("compute_policy_complete_review_required")?;
        reviews.push(assessment::decode_review(
            text.as_bytes(),
            &enrolled.scope,
            evidence,
            original,
            &subject,
        )?);
        stages.push(stage.summary(true));
    }
    let reviews: [assessment::Review; 2] = reviews
        .try_into()
        .map_err(|_| anyhow::anyhow!("compute_policy_reviews"))?;
    let result = completed_result(
        &enrolled,
        &assessment::resolve(&enrolled.scope, &subject, &assessments, &reviews)?,
        &stages,
    );
    let original: Value =
        serde_json::from_slice(&storage::read(&root.join("result.json"), 256 * 1024)?)?;
    ensure!(original == result, "compute_policy_bundle_verdict_changed");
    Ok(result)
}

#[cfg(test)]
mod tests;
