//! Exact native publications and local receipt joins for an explicitly public document.
//! Only the coordinator has the original bytes needed to check every signed excerpt.

use std::{collections::BTreeSet, fs, os::unix::fs::DirBuilderExt, path::Path};

use anyhow::{Context as _, Result, ensure};
use ed25519_dalek::{SigningKey, VerifyingKey};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkId, ChunkStore, MAX_MANIFEST_BYTES, Metadata, Publication,
    SignedManifest, Validity, VerifiedManifest,
    provider::compute::dataset::{
        DOCUMENT_CONTENT_TYPE, DocumentDataset, DocumentQuestion, verify_source,
    },
};

use super::{
    Input, MAX_DOCUMENT_BYTES, MAX_SAVED_BYTES, Plan, now, parse_key, private_directory, rpc,
};
use super::{save, task, workflow};

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Enrollment {
    version: u32,
    pub(super) source_manifest_id: String,
    source_sha256: String,
    source_bytes: u64,
    publisher_key: String,
    pub(super) provider_keys: Vec<String>,
    selected_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    license: String,
    public_question: String,
    plan_sha256: String,
    pub(super) packages: Vec<Package>,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Package {
    pub(super) manifest_id: String,
    dataset_sha256: String,
    pub(super) first_part: usize,
    pub(super) rows: usize,
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read(path: &Path, limit: usize) -> Result<Vec<u8>> {
    crate::compute::read_file(path, u64::try_from(limit)?)
}

fn instruction(input: &Input) -> rpc::PublicTask {
    rpc::PublicTask::AnswerPublicQuestionV1 {
        question: input.question.clone(),
    }
}

fn workflow_plan(root: &Path, publisher: &str, input: &Input) -> Value {
    json!({"version":1,"packages":[{
        "dataset":root.join("dataset.json"),
        "dataset_manifest":root.join("dataset.manifest"),
        "publisher_key":publisher,"task":instruction(input)}]})
}

fn publish_object(
    bytes: &[u8],
    name: String,
    content_type: &str,
    validity: Validity,
    signer: &SigningKey,
    cache: &mut ChunkStore,
) -> Result<SignedManifest> {
    let mut reader = bytes;
    Ok(volparossa_content::publish(
        &mut reader,
        Publication {
            metadata: Metadata {
                name,
                revision: 1,
                content_type: content_type.into(),
            },
            length: bytes.len() as u64,
            validity,
        },
        signer,
        cache,
    )?)
}

fn dataset(
    input: &Input,
    plan: &Plan,
    source_hex: &str,
    first: usize,
    rows: usize,
) -> Result<DocumentDataset> {
    let parts = plan
        .parts
        .get(
            first
                ..first
                    .checked_add(rows)
                    .context("compute_document_part_overflow")?,
        )
        .context("compute_document_package_range")?;
    let inference = parts
        .iter()
        .map(|part| {
            let range = usize::try_from(part.start)?..usize::try_from(part.end)?;
            let context = input
                .document
                .get(range)
                .context("compute_document_original_excerpt")?;
            Ok(DocumentQuestion {
                question: input.question.clone(),
                context: context.into(),
                start: part.start,
                end: part.end,
            })
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(DocumentDataset {
        version: 2,
        visibility: "public".into(),
        license: input.license.clone(),
        source_manifest_hex: source_hex.into(),
        inference,
    })
}

fn admission(
    root: &Path,
    input: &Input,
    plan: &Plan,
    providers: &[VerifyingKey],
    at: u64,
    lifetime: u64,
    cancelled: &watch::Receiver<bool>,
) -> Result<Validity> {
    private_directory(root)?;
    plan.validate(input)?;
    ensure!(
        at > 0
            && at <= now()?
            && (1..=volparossa_content::MAX_VALIDITY_SECONDS).contains(&lifetime),
        "compute_document_publication_time"
    );
    ensure!(
        (2..=4).contains(&providers.len())
            && providers
                .iter()
                .map(VerifyingKey::to_bytes)
                .collect::<BTreeSet<_>>()
                .len()
                == providers.len(),
        "compute_document_provider_selection"
    );
    ensure!(
        read(&root.join("source.txt"), MAX_DOCUMENT_BYTES)? == input.document.as_bytes(),
        "compute_document_original_file_changed"
    );
    let saved_input: Input =
        serde_json::from_slice(&read(&root.join("planner-input.json"), MAX_SAVED_BYTES)?)?;
    ensure!(
        serde_json::to_vec(&saved_input)? == serde_json::to_vec(input)?,
        "compute_document_input_changed"
    );
    ensure!(
        !*cancelled.borrow(),
        "compute_document_publication_cancelled"
    );
    Ok(Validity {
        created: at,
        expires: at
            .checked_add(lifetime)
            .context("compute_document_expiry")?,
    })
}

// One synchronous publication boundary keeps the unlocked signer out of all peer awaits.
#[allow(clippy::too_many_arguments)]
pub(super) fn publish(
    root: &Path,
    input: &Input,
    plan: &Plan,
    signer: &SigningKey,
    providers: &[VerifyingKey],
    at: u64,
    lifetime: u64,
    cancelled: &watch::Receiver<bool>,
) -> Result<Enrollment> {
    let validity = admission(root, input, plan, providers, at, lifetime, cancelled)?;
    let mut cache = ChunkStore::create(
        &root.join("publication-cache"),
        CacheLimits {
            max_bytes: 64 * 1024 * 1024,
            max_entries: 65_536,
            min_free_bytes: 64 * 1024 * 1024,
        },
    )?;
    let source = publish_object(
        input.document.as_bytes(),
        "document-source".into(),
        "text/plain",
        validity,
        signer,
        &mut cache,
    )?;
    let source_bytes = source.encode();
    task::write_bytes(&root.join("source.manifest"), &source_bytes, false)?;
    save(root, "document-plan.json", plan, false)?;
    let source_hex = hex::encode(&source_bytes);
    let publisher_key = hex::encode(signer.verifying_key().as_bytes());
    let mut packages = Vec::new();
    for (index, parts) in plan.parts.chunks(4).enumerate() {
        ensure!(
            !*cancelled.borrow(),
            "compute_document_publication_cancelled"
        );
        let directory = root.join(format!("package-{index:04}"));
        fs::DirBuilder::new().mode(0o700).create(&directory)?;
        let package = dataset(input, plan, &source_hex, index * 4, parts.len())?;
        package.validate_shape()?;
        let bytes = serde_json::to_vec(&package)?;
        let publication = publish_object(
            &bytes,
            format!("document-package-{index:04}"),
            DOCUMENT_CONTENT_TYPE,
            validity,
            signer,
            &mut cache,
        )?;
        let manifest = publication.encode();
        task::write_bytes(&directory.join("dataset.json"), &bytes, false)?;
        task::write_bytes(&directory.join("dataset.manifest"), &manifest, false)?;
        save(
            &directory,
            "workflow-plan.json",
            &workflow_plan(&directory, &publisher_key, input),
            false,
        )?;
        packages.push(Package {
            manifest_id: sha(&manifest),
            dataset_sha256: sha(&bytes),
            first_part: index * 4,
            rows: parts.len(),
        });
    }
    Ok(Enrollment {
        version: 1,
        source_manifest_id: sha(&source_bytes),
        source_sha256: plan.source_sha256.clone(),
        source_bytes: plan.source_bytes,
        publisher_key,
        provider_keys: providers
            .iter()
            .map(|key| hex::encode(key.as_bytes()))
            .collect(),
        selected_at_unix_seconds: at,
        expires_at_unix_seconds: validity.expires,
        license: input.license.clone(),
        public_question: input.question.clone(),
        plan_sha256: sha(&serde_json::to_vec(plan)?),
        packages,
    })
}

fn verified_manifest(bytes: &[u8], enrollment: &Enrollment) -> Result<VerifiedManifest> {
    let key = parse_key(&enrollment.publisher_key).map_err(anyhow::Error::msg)?;
    let verified =
        SignedManifest::decode(bytes)?.verify(&key, enrollment.selected_at_unix_seconds)?;
    ensure!(
        verified.validity().created == enrollment.selected_at_unix_seconds
            && verified.validity().expires == enrollment.expires_at_unix_seconds
            && verified.metadata().revision == 1,
        "compute_document_original_publication_changed"
    );
    Ok(verified)
}

fn verify_original(root: &Path, enrollment: &Enrollment, input: &Input) -> Result<Vec<u8>> {
    let bytes = read(&root.join("source.manifest"), MAX_MANIFEST_BYTES)?;
    let verified = verified_manifest(&bytes, enrollment)?;
    ensure!(
        sha(&bytes) == enrollment.source_manifest_id
            && verified.metadata().name == "document-source"
            && verified.metadata().content_type == "text/plain"
            && verified.length() == input.document.len() as u64
            && hex::encode(verified.object_sha256()) == enrollment.source_sha256,
        "compute_document_original_manifest"
    );
    let chunks = input.document.as_bytes().chunks(CHUNK_BYTES);
    ensure!(
        chunks.len() == verified.chunks().len()
            && chunks.zip(verified.chunks()).all(|(bytes, chunk)| {
                ChunkId::digest(bytes) == *chunk.id() && bytes.len() == chunk.length() as usize
            }),
        "compute_document_original_chunk_bytes"
    );
    ensure!(
        read(&root.join("source.txt"), MAX_DOCUMENT_BYTES)? == input.document.as_bytes(),
        "compute_document_original_file_changed"
    );
    Ok(bytes)
}

pub(super) fn load(root: &Path) -> Result<(Enrollment, Input, Plan)> {
    private_directory(root)?;
    let enrollment: Enrollment =
        serde_json::from_slice(&read(&root.join("document.json"), MAX_SAVED_BYTES)?)?;
    let input: Input =
        serde_json::from_slice(&read(&root.join("planner-input.json"), MAX_SAVED_BYTES)?)?;
    let plan_bytes = read(&root.join("document-plan.json"), MAX_SAVED_BYTES)?;
    let plan: Plan = serde_json::from_slice(&plan_bytes)?;
    plan.validate(&input)?;
    ensure!(
        enrollment.version == 1
            && enrollment.selected_at_unix_seconds > 0
            && enrollment.selected_at_unix_seconds <= now()?
            && enrollment.expires_at_unix_seconds > enrollment.selected_at_unix_seconds
            && enrollment.source_sha256 == plan.source_sha256
            && enrollment.source_bytes == plan.source_bytes
            && enrollment.license == input.license
            && enrollment.public_question == input.question
            && enrollment.plan_sha256 == sha(&plan_bytes)
            && enrollment.packages.len() == plan.parts.len().div_ceil(4),
        "compute_document_enrollment_changed"
    );
    ensure!(
        (2..=4).contains(&enrollment.provider_keys.len())
            && enrollment
                .provider_keys
                .iter()
                .collect::<BTreeSet<_>>()
                .len()
                == enrollment.provider_keys.len(),
        "compute_document_provider_selection"
    );
    for provider in &enrollment.provider_keys {
        parse_key(provider).map_err(anyhow::Error::msg)?;
    }
    verify_original(root, &enrollment, &input)?;
    let mut ids = BTreeSet::new();
    for (index, package) in enrollment.packages.iter().enumerate() {
        ensure!(
            package.first_part == index * 4
                && package.rows == (plan.parts.len() - package.first_part).min(4)
                && rpc::nonzero_hex(&package.manifest_id, 64)
                && rpc::nonzero_hex(&package.dataset_sha256, 64)
                && ids.insert(&package.manifest_id),
            "compute_document_package_coverage"
        );
    }
    Ok((enrollment, input, plan))
}

pub(super) fn expected(
    root: &Path,
    enrollment: &Enrollment,
    package: &Package,
    input: &Input,
    plan: &Plan,
) -> Result<workflow::ExpectedTask> {
    private_directory(root)?;
    ensure!(
        input.license == enrollment.license && input.question == enrollment.public_question,
        "compute_document_task_changed"
    );
    let document_root = root.parent().context("compute_document_package_parent")?;
    let source = read(&document_root.join("source.manifest"), MAX_MANIFEST_BYTES)?;
    ensure!(
        sha(&source) == enrollment.source_manifest_id,
        "compute_document_source_identity_changed"
    );
    let bytes = read(&root.join("dataset.json"), rpc::MAX_DATASET_BYTES)?;
    let manifest = read(&root.join("dataset.manifest"), MAX_MANIFEST_BYTES)?;
    let key = parse_key(&enrollment.publisher_key).map_err(anyhow::Error::msg)?;
    let json = std::str::from_utf8(&bytes)?;
    let verified = verify_source(&manifest, &key, json, enrollment.selected_at_unix_seconds)?;
    let native = verified_manifest(&manifest, enrollment)?;
    let desired = dataset(
        input,
        plan,
        &hex::encode(&source),
        package.first_part,
        package.rows,
    )?;
    ensure!(
        sha(&bytes) == package.dataset_sha256
            && hex::encode(verified.manifest_id()) == package.manifest_id
            && verified.is_document()
            && verified.row_count() == package.rows
            && native.metadata().name == format!("document-package-{:04}", package.first_part / 4)
            && serde_json::from_str::<DocumentDataset>(json)? == desired,
        "compute_document_signed_excerpt_changed"
    );
    let saved_plan: Value =
        serde_json::from_slice(&read(&root.join("workflow-plan.json"), 64 * 1024)?)?;
    ensure!(
        saved_plan == workflow_plan(root, &enrollment.publisher_key, input),
        "compute_document_workflow_plan_changed"
    );
    Ok(workflow::ExpectedTask {
        publisher_key: enrollment.publisher_key.clone(),
        manifest_id: package.manifest_id.clone(),
        dataset_sha256: package.dataset_sha256.clone(),
        rows: package.rows,
        task: instruction(input),
        provider_keys: enrollment.provider_keys.clone(),
        selected_at_unix_seconds: enrollment.selected_at_unix_seconds,
    })
}

pub(super) fn present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => {
            private_directory(path)?;
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

/// Join only the full-receipt-validated output of `workflow::task_snapshot`, never an aggregate flag.
pub(super) fn join_answers(
    snapshot: &Value,
    package: &Package,
    input: &Input,
    plan: &Plan,
    answers: &mut Vec<Value>,
) -> Result<()> {
    ensure!(
        snapshot["dataset_manifest_id"] == package.manifest_id
            && snapshot["task"] == serde_json::to_value(instruction(input))?
            && snapshot["complete"].is_boolean(),
        "compute_document_snapshot_source"
    );
    let outputs = snapshot["outputs"]
        .as_array()
        .context("compute_document_snapshot_outputs")?;
    ensure!(
        outputs.len() <= package.rows
            && (snapshot["complete"] != true || outputs.len() == package.rows),
        "compute_document_snapshot_completion"
    );
    let mut seen = BTreeSet::new();
    let mut joined = Vec::new();
    for output in outputs {
        let row = usize::try_from(
            output["sample_index"]
                .as_u64()
                .context("compute_document_output_row")?,
        )?;
        ensure!(
            row < package.rows && seen.insert(row),
            "compute_document_duplicate_output"
        );
        let index = package
            .first_part
            .checked_add(row)
            .context("compute_document_output_overflow")?;
        let part = plan
            .parts
            .get(index)
            .context("compute_document_output_part")?;
        let context = input
            .document
            .get(usize::try_from(part.start)?..usize::try_from(part.end)?)
            .context("compute_document_output_context")?;
        ensure!(
            output["text"].is_string()
                && output["report_sha256"]
                    .as_str()
                    .is_some_and(|s| rpc::nonzero_hex(s, 64))
                && output["job_id"]
                    .as_str()
                    .is_some_and(|s| rpc::nonzero_hex(s, 32)),
            "compute_document_actual_report_required"
        );
        parse_key(
            output["provider_key"]
                .as_str()
                .context("compute_document_result_provider")?,
        )
        .map_err(anyhow::Error::msg)?;
        joined.push(
            json!({"source_part":index,"start":part.start,"end":part.end,
            "context_sha256":sha(context.as_bytes()),"package_manifest_id":package.manifest_id,
            "text":output["text"],"provider_key":output["provider_key"],"job_id":output["job_id"],
            "report_sha256":output["report_sha256"]}),
        );
    }
    joined.sort_by_key(|value| value["source_part"].as_u64());
    ensure!(
        answers
            .last()
            .zip(joined.first())
            .is_none_or(
                |(previous, next)| previous["source_part"].as_u64() < next["source_part"].as_u64()
            ),
        "compute_document_result_order"
    );
    answers.extend(joined);
    Ok(())
}

#[cfg(test)]
mod tests;
