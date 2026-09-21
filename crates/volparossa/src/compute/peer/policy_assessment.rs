//! Explicit public concept judgments, not whitelist-signing or enforcement authority.

mod execution;
mod storage;

use std::path::{Path, PathBuf};

use anyhow::{Context as _, Result, ensure};
use clap::Args;
use ed25519_dalek::VerifyingKey;
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use tokio::sync::watch;
use volparossa_content::model_profile::ModelProfile;

use super::{Cancellation, batch, now, parse_key, rpc, sha, task};
use crate::compute::policy_assessment as assessment;

#[derive(Debug, Args)]
pub(crate) struct Options {
    /// Private retained workflow directory; new unless --resume is selected.
    #[arg(long)]
    output: PathBuf,
    /// Replay exact original handles. Never resubmit or replace a leased job.
    #[arg(long)]
    resume: bool,
    /// Select an explicitly public native text/plain object, not a cache-selected subject.
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume", value_parser = parse_key)]
    source_publisher_key: Option<VerifyingKey>,
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    source_name: Option<String>,
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume", value_parser = parse_manifest)]
    source_manifest_id: Option<[u8; 32]>,
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume")]
    cache: Option<PathBuf>,
    #[arg(long, requires = "cache")]
    reuse_cache: bool,
    /// Owner authorized to publish the assessment context, not the original subject publisher.
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume", value_parser = parse_key)]
    publisher_key: Option<VerifyingKey>,
    #[arg(long)]
    identity: Option<PathBuf>,
    #[arg(long)]
    passphrase_file: Option<PathBuf>,
    /// Exactly two independently selected distinct public compute providers.
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume", value_parser = parse_key)]
    provider_key: Vec<VerifyingKey>,
    /// Explicit authorization to republish the complete selected public subject in these tasks.
    #[arg(long, required_unless_present = "resume", conflicts_with = "resume",
        value_parser = ["GPL-3.0-only", "CC0-1.0", "CC-BY-4.0", "CC-BY-SA-4.0"])]
    license: Option<String>,
    #[arg(long, default_value_t = 600, value_parser = clap::value_parser!(u16).range(1..=600))]
    max_seconds: u16,
    #[command(flatten)]
    limits: crate::content::Limits,
    /// Without this flag there is no source acquisition, publication, directory creation or RPC.
    #[arg(long)]
    execute: bool,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Enrollment {
    version: u32,
    scope: assessment::Scope,
    source_name: String,
    source_download_sha256: String,
    publisher_key: String,
    providers: [String; 2],
    model_fingerprints: [String; 2],
    license: String,
    selected_at: u64,
    expires: u64,
    max_seconds: u16,
}

fn parse_manifest(value: &str) -> Result<[u8; 32], String> {
    let mut id = [0; 32];
    if !crate::compute::is_hex(value, 64)
        || hex::decode_to_slice(value, &mut id).is_err()
        || id == [0; 32]
    {
        return Err("compute_policy_source_manifest".into());
    }
    Ok(id)
}

fn preview(args: &Options) -> Result<Value> {
    ensure!(args.output.is_absolute(), "compute_policy_output_absolute");
    if !args.resume {
        ensure!(
            args.provider_key.len() == 2 && args.provider_key[0] != args.provider_key[1],
            "compute_policy_two_distinct_peers"
        );
        ensure!(
            args.source_name
                .as_ref()
                .is_some_and(|name| !name.trim().is_empty())
                && args.source_publisher_key.is_some()
                && args.source_manifest_id.is_some()
                && args.publisher_key.is_some()
                && args.license.is_some()
                && args.cache.as_ref().is_some_and(|path| path.is_absolute()),
            "compute_policy_explicit_native_subject"
        );
    }
    Ok(
        json!({"operation":"compute_peer_policy_assessment","execute":false,
        "network_policy_activation":false,"assessment_peers":2,"planned_jobs":4,
        "model_profile":"smollm2-360m-v1","resume":args.resume,
        "subject_limit_bytes":512,"prompt_limit_tokens":1024,"generation_limit_tokens":256,
        "framework":assessment::framework(),"private_data_supported":false,
        "independent_semantic_judgment_proven":false}),
    )
}

pub(super) async fn run(args: &Options, socket: &Path) -> Result<()> {
    let planned = preview(args)?;
    if !args.execute {
        println!("{}", serde_json::to_string_pretty(&planned)?);
        return Ok(());
    }
    let cancellation = Cancellation::new()?;
    let _lock = task::open_directory(&args.output, args.resume)?;
    if !args.resume {
        enroll(args, socket, &cancellation.activity).await?;
    }
    let (enrollment, subject) = storage::load(&args.output)?;
    let result = assess(args, socket, &enrollment, &subject, &cancellation.activity).await?;
    storage::retain_result(&args.output.join("result.json"), &result)?;
    println!("{}", serde_json::to_string_pretty(&result)?);
    ensure!(
        result["complete"] == true,
        "compute_policy_assessment_incomplete_retained"
    );
    Ok(())
}

async fn enroll(args: &Options, socket: &Path, cancelled: &watch::Receiver<bool>) -> Result<()> {
    let selection = crate::content::public_text::TextSource {
        publisher_key: args
            .source_publisher_key
            .context("compute_policy_source_publisher")?,
        name: args
            .source_name
            .clone()
            .context("compute_policy_source_name")?,
        manifest_id: args
            .source_manifest_id
            .context("compute_policy_source_manifest")?,
        cache: args.cache.clone().context("compute_policy_cache")?,
        reuse_cache: args.reuse_cache,
        limits: args.limits.clone(),
    };
    ensure!(!*cancelled.borrow(), "compute_policy_cancelled");
    let download =
        crate::content::public_text::fetch_text_source(&selection, socket, &args.output).await?;
    let scope = assessment::Scope::new(
        &hex::encode(selection.publisher_key.as_bytes()),
        &hex::encode(selection.manifest_id),
        &download.text,
    )?;
    let mut fingerprints = Vec::new();
    for key in &args.provider_key {
        ensure!(!*cancelled.borrow(), "compute_policy_cancelled");
        let caps = super::capabilities(socket, key).await?;
        ensure!(
            crate::compute::broker::profile_for_model(&caps.model)? == ModelProfile::Smol360
                && caps.document_inference_v2,
            "compute_policy_requires_360_document_peer"
        );
        fingerprints.push(caps.model_fingerprint);
    }
    let download_bytes = serde_json::to_vec(&download.receipt)?;
    let enrollment = Enrollment {
        version: 1,
        scope,
        source_name: selection.name,
        source_download_sha256: sha(&download_bytes),
        publisher_key: hex::encode(
            args.publisher_key
                .context("compute_policy_publisher")?
                .as_bytes(),
        ),
        providers: [
            hex::encode(args.provider_key[0].as_bytes()),
            hex::encode(args.provider_key[1].as_bytes()),
        ],
        model_fingerprints: fingerprints
            .try_into()
            .map_err(|_| anyhow::anyhow!("compute_policy_peers"))?,
        license: args.license.clone().context("compute_policy_license")?,
        selected_at: download.verified_at,
        expires: download.expires,
        max_seconds: args.max_seconds,
    };
    task::write_bytes(
        &args.output.join("subject.txt"),
        download.text.as_bytes(),
        false,
    )?;
    task::write_bytes(
        &args.output.join("subject.manifest"),
        &download.signed_manifest,
        false,
    )?;
    task::write_bytes(
        &args.output.join("subject-download.json"),
        &download_bytes,
        false,
    )?;
    storage::save(&args.output.join("enrollment.json"), &enrollment)?;
    Ok(())
}

async fn assess(
    args: &Options,
    socket: &Path,
    enrolled: &Enrollment,
    subject: &str,
    cancelled: &watch::Receiver<bool>,
) -> Result<Value> {
    let mut stages = Vec::new();
    let mut assessments = Vec::new();
    for index in 0..2 {
        let stage = execution::run(
            args,
            socket,
            enrolled,
            &format!("assessment-{index}"),
            index,
            &assessment::assessment_context(subject)?,
            assessment::assessment_question(),
            cancelled,
        )
        .await?;
        let decoded = stage.answer.as_ref().and_then(|(text, evidence)| {
            assessment::decode_assessment(text.as_bytes(), &enrolled.scope, evidence, subject).ok()
        });
        stages.push(stage.summary(decoded.is_some()));
        if let Some(value) = decoded {
            assessments.push(value);
        }
    }
    let Ok(assessments): Result<[assessment::Assessment; 2], _> = assessments.try_into() else {
        return Ok(incomplete(enrolled, &stages));
    };
    let mut reviews = Vec::new();
    for index in 0..2 {
        let reviewed = &assessments[1 - index];
        let stage = execution::run(
            args,
            socket,
            enrolled,
            &format!("review-{index}"),
            index,
            &assessment::review_context(subject, reviewed)?,
            assessment::review_question(),
            cancelled,
        )
        .await?;
        let decoded = stage.answer.as_ref().and_then(|(text, evidence)| {
            assessment::decode_review(
                text.as_bytes(),
                &enrolled.scope,
                evidence,
                reviewed,
                subject,
            )
            .ok()
        });
        stages.push(stage.summary(decoded.is_some()));
        if let Some(value) = decoded {
            reviews.push(value);
        }
    }
    let Ok(reviews): Result<[assessment::Review; 2], _> = reviews.try_into() else {
        return Ok(incomplete(enrolled, &stages));
    };
    let decision = assessment::resolve(&enrolled.scope, subject, &assessments, &reviews)?;
    Ok(
        json!({"version":1,"operation":"compute_peer_policy_assessment","complete":true,
        "network_policy_activation":false,"decision":decision,"stages":stages,
        "receipt_scope":"locally_retained_authenticated_rpc_not_portable_attestation"}),
    )
}

fn incomplete(enrolled: &Enrollment, stages: &[Value]) -> Value {
    json!({"version":1,"operation":"compute_peer_policy_assessment","complete":false,
        "network_policy_activation":false,"decision":{"scope":enrolled.scope,
            "outcome":"undetermined","reason":"incomplete_or_invalid_assessment_or_review",
            "enforcement_authority":false,"legal_status":"not_determined"},"stages":stages})
}

#[cfg(test)]
mod tests;
