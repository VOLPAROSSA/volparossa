//! Deterministic reduction inputs and original-authorized derived publications.

use std::{fs, os::unix::fs::DirBuilderExt, path::Path};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use volparossa_content::provider::compute::dataset::{
    DERIVED_CLAIM_SCOPE, DERIVED_CONTENT_TYPE, DerivedDataset, DerivedInput, DerivedQuestion,
    verify_source,
};
use volparossa_content::{CacheLimits, ChunkStore, MAX_MANIFEST_BYTES, SignedManifest, Validity};

use super::super::{Input, MAX_RESULT_BYTES, MAX_SAVED_BYTES, Plan, task, tokenize};
use super::{Answer, Options, document_storage, now, parse_key, private_directory, rpc, workflow};

pub(super) fn directory(path: &Path) -> Result<()> {
    if !document_storage::present(path)? {
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    private_directory(path)
}

fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

fn read(path: &Path, maximum: usize) -> Result<Vec<u8>> {
    crate::compute::read_file(path, u64::try_from(maximum)?)
}

fn retain_bytes(path: &Path, bytes: &[u8], maximum: usize) -> Result<()> {
    ensure!(bytes.len() <= maximum, "compute_synthesis_retained_size");
    if path.try_exists()? {
        ensure!(
            read(path, maximum)? == bytes,
            "compute_synthesis_retained_input_changed"
        );
        Ok(())
    } else {
        task::write_bytes(path, bytes, false)
    }
}

pub(super) fn retain_json(root: &Path, name: &str, value: &impl Serialize) -> Result<()> {
    retain_bytes(
        &root.join(name),
        &serde_json::to_vec(value)?,
        if name.ends_with("-result.json") {
            MAX_RESULT_BYTES
        } else {
            MAX_SAVED_BYTES
        },
    )
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Group {
    version: u32,
    level: u16,
    parent_offset: usize,
    parents_sha256: String,
    source_manifest_id: String,
    created_at_unix_seconds: u64,
}

pub(super) struct Prepared {
    pub(super) datasets: Vec<DerivedDataset>,
    pub(super) input_sha256: String,
    pub(super) parts: usize,
    group: Group,
}

fn group(
    root: &Path,
    enrollment: &document_storage::Enrollment,
    parents: &[Answer],
    offset: usize,
    level: u16,
) -> Result<Group> {
    let digest = sha(&serde_json::to_vec(parents)?);
    let file = root.join("group.json");
    if file.try_exists()? {
        let saved: Group = serde_json::from_slice(&read(&file, MAX_SAVED_BYTES)?)?;
        ensure!(
            saved.version == 1
                && saved.level == level
                && saved.parent_offset == offset
                && saved.parents_sha256 == digest
                && saved.source_manifest_id == enrollment.source_manifest_id
                && saved.created_at_unix_seconds >= enrollment.selected_at_unix_seconds
                && saved.created_at_unix_seconds < enrollment.expires_at_unix_seconds
                && saved.created_at_unix_seconds <= now()?,
            "compute_synthesis_group_changed"
        );
        return Ok(saved);
    }
    let at = now()?;
    ensure!(
        at < enrollment.expires_at_unix_seconds,
        "compute_synthesis_original_source_expired"
    );
    let group = Group {
        version: 1,
        level,
        parent_offset: offset,
        parents_sha256: digest,
        source_manifest_id: enrollment.source_manifest_id.clone(),
        created_at_unix_seconds: at,
    };
    retain_json(root, "group.json", &group)?;
    Ok(group)
}

fn combined(parents: &[Answer]) -> String {
    let mut text = String::new();
    for parent in parents {
        text.push_str(&parent.text);
        text.push('\n');
    }
    text
}

fn row(
    input: &Input,
    part: &crate::compute::document_plan::Part,
    parents: &[Answer],
    offset: usize,
) -> Result<DerivedQuestion> {
    let start = usize::try_from(part.start)?;
    let end = usize::try_from(part.end)?;
    let context = input
        .document
        .get(start..end)
        .context("compute_synthesis_part_utf8")?
        .to_owned();
    let mut inputs = Vec::new();
    let mut base = 0;
    for (index, parent) in parents.iter().enumerate() {
        let length = parent
            .text
            .len()
            .checked_add(1)
            .context("compute_synthesis_segment_size")?;
        let segment_end = base + length;
        if start < segment_end && end > base {
            inputs.push(DerivedInput {
                text: parent.text.clone(),
                provider_key: parent.provider_key.clone(),
                job_id: parent.job_id.clone(),
                report_sha256: parent.report_sha256.clone(),
                package_manifest_id: parent.package_manifest_id.clone(),
                model_fingerprint: parent.model_fingerprint.clone(),
                output_index: parent.output_index,
                parent_index: u32::try_from(
                    offset
                        .checked_add(index)
                        .context("compute_synthesis_parent_index")?,
                )?,
                source_start: parent.source_start,
                source_end: parent.source_end,
                piece_start: u64::try_from(start.saturating_sub(base))?,
                piece_end: u64::try_from(end.min(segment_end) - base)?,
            });
        }
        base = segment_end;
    }
    ensure!(
        base == input.document.len(),
        "compute_synthesis_parent_text_changed"
    );
    Ok(DerivedQuestion {
        question: input.question.clone(),
        context,
        inputs,
    })
}

#[allow(clippy::too_many_arguments)]
pub(super) async fn prepare(
    args: &Options,
    root: &Path,
    enrollment: &document_storage::Enrollment,
    original: &Input,
    parents: &[Answer],
    offset: usize,
    level: u16,
    cancelled: &watch::Receiver<bool>,
) -> Result<Prepared> {
    ensure!(
        (1..=super::MAX_LEVELS).contains(&level)
            && (1..=super::PARENTS_PER_GROUP).contains(&parents.len())
            && super::unusable(parents).is_none(),
        "compute_synthesis_parent_budget"
    );
    directory(root)?;
    let group = group(root, enrollment, parents, offset, level)?;
    retain_json(root, "parents.json", &parents)?;
    let input = Input {
        version: 1,
        visibility: "public".into(),
        license: original.license.clone(),
        document: combined(parents),
        question: original.question.clone(),
        synthesis: true,
    };
    input.validate()?;
    retain_json(root, "planner-input.json", &input)?;
    let plan: Plan = if root.join("document-plan.json").try_exists()? {
        serde_json::from_slice(&read(&root.join("document-plan.json"), MAX_SAVED_BYTES)?)?
    } else {
        ensure!(
            now()? < enrollment.expires_at_unix_seconds,
            "compute_synthesis_original_source_expired"
        );
        ensure!(
            args.runtime_root.is_some() && args.model_root.is_some(),
            "compute_synthesis_new_level_requires_runtime_root_and_model_root_on_resume"
        );
        let plan = tokenize(args, root, &input, cancelled).await?;
        retain_json(root, "document-plan.json", &plan)?;
        plan
    };
    plan.validate(&input)?;
    let source = read(&args.directory.join("source.manifest"), MAX_MANIFEST_BYTES)?;
    ensure!(
        sha(&source) == enrollment.source_manifest_id,
        "compute_synthesis_original_source_changed"
    );
    let rows = plan
        .parts
        .iter()
        .map(|part| row(&input, part, parents, offset))
        .collect::<Result<Vec<_>>>()?;
    let datasets = rows
        .chunks(4)
        .map(|rows| {
            let dataset = DerivedDataset {
                version: 3,
                visibility: "public".into(),
                license: input.license.clone(),
                source_manifest_hex: hex::encode(&source),
                level,
                claim_scope: DERIVED_CLAIM_SCOPE.into(),
                inference: rows.to_vec(),
            };
            dataset.validate_shape()?;
            Ok(dataset)
        })
        .collect::<Result<Vec<_>>>()?;
    let prepared = Prepared {
        datasets,
        input_sha256: plan.source_sha256,
        parts: plan.parts.len(),
        group,
    };
    publications(args, root, enrollment, &prepared, cancelled)?;
    Ok(prepared)
}

fn workflow_plan(root: &Path, publisher: &str, question: &str) -> Value {
    json!({"version":1,"packages":[{"dataset":root.join("dataset.json"),
        "dataset_manifest":root.join("dataset.manifest"),"publisher_key":publisher,
        "task":rpc::PublicTask::AnswerPublicQuestionV1 { question: question.into() }}]})
}

fn publication_name(prepared: &Prepared, index: usize) -> String {
    format!(
        "derived-l{:02}-g{:04}-p{index:04}",
        prepared.group.level,
        prepared.group.parent_offset / super::PARENTS_PER_GROUP
    )
}

fn publications(
    args: &Options,
    root: &Path,
    enrollment: &document_storage::Enrollment,
    prepared: &Prepared,
    cancelled: &watch::Receiver<bool>,
) -> Result<()> {
    let mut signer = None;
    let mut cache = None;
    for (index, dataset) in prepared.datasets.iter().enumerate() {
        let package = root.join(format!("package-{index:04}"));
        directory(&package)?;
        let bytes = serde_json::to_vec(dataset)?;
        retain_bytes(
            &package.join("dataset.json"),
            &bytes,
            rpc::MAX_DATASET_BYTES,
        )?;
        retain_json(
            &package,
            "workflow-plan.json",
            &workflow_plan(
                &package,
                &enrollment.publisher_key,
                &dataset.inference[0].question,
            ),
        )?;
        if package.join("dataset.manifest").try_exists()? {
            continue;
        }
        ensure!(
            !*cancelled.borrow(),
            "compute_synthesis_cancelled_before_publication"
        );
        ensure!(
            now()? < enrollment.expires_at_unix_seconds,
            "compute_synthesis_original_source_expired"
        );
        if signer.is_none() {
            ensure!(
                args.identity.is_some() && args.passphrase_file.is_some(),
                "compute_synthesis_new_publication_requires_identity_and_passphrase_file_on_resume"
            );
            let key = crate::content::unlock_signer(
                args.identity.as_deref(),
                args.passphrase_file.as_deref(),
            )?;
            ensure!(
                hex::encode(key.verifying_key().as_bytes()) == enrollment.publisher_key,
                "compute_synthesis_publisher_identity_changed"
            );
            signer = Some(key);
            let limits = CacheLimits {
                max_bytes: 64 * 1024 * 1024,
                max_entries: 65_536,
                min_free_bytes: 64 * 1024 * 1024,
            };
            let directory = root.join("publication-cache");
            cache = Some(if document_storage::present(&directory)? {
                ChunkStore::open(&directory, limits)?
            } else {
                ChunkStore::create(&directory, limits)?
            });
        }
        let manifest = document_storage::publish_object(
            &bytes,
            publication_name(prepared, index),
            DERIVED_CONTENT_TYPE,
            Validity {
                created: prepared.group.created_at_unix_seconds,
                expires: enrollment.expires_at_unix_seconds,
            },
            signer.as_ref().context("compute_synthesis_signer")?,
            cache.as_mut().context("compute_synthesis_cache")?,
        )?;
        retain_bytes(
            &package.join("dataset.manifest"),
            &manifest.encode(),
            MAX_MANIFEST_BYTES,
        )?;
    }
    // Synchronous boundary: the unlocked key is dropped before any peer await.
    Ok(())
}

pub(super) fn expected(
    root: &Path,
    enrollment: &document_storage::Enrollment,
    prepared: &Prepared,
    dataset: &DerivedDataset,
    index: usize,
) -> Result<workflow::ExpectedTask> {
    let bytes = read(&root.join("dataset.json"), rpc::MAX_DATASET_BYTES)?;
    ensure!(
        bytes == serde_json::to_vec(dataset)?,
        "compute_synthesis_signed_parent_changed"
    );
    let manifest = read(&root.join("dataset.manifest"), MAX_MANIFEST_BYTES)?;
    let key = parse_key(&enrollment.publisher_key).map_err(anyhow::Error::msg)?;
    let at = prepared.group.created_at_unix_seconds;
    let verified = verify_source(&manifest, &key, std::str::from_utf8(&bytes)?, at)?;
    let native = SignedManifest::decode(&manifest)?.verify(&key, at)?;
    ensure!(
        verified.is_derived()
            && verified.row_count() == dataset.inference.len()
            && native.validity().created == at
            && native.validity().expires == enrollment.expires_at_unix_seconds
            && native.metadata().name == publication_name(prepared, index)
            && native.metadata().revision == 1,
        "compute_synthesis_publication_binding"
    );
    let question = dataset.inference[0].question.clone();
    ensure!(
        serde_json::from_slice::<Value>(&read(&root.join("workflow-plan.json"), MAX_SAVED_BYTES)?)?
            == workflow_plan(root, &enrollment.publisher_key, &question),
        "compute_synthesis_workflow_changed"
    );
    Ok(workflow::ExpectedTask {
        publisher_key: enrollment.publisher_key.clone(),
        manifest_id: sha(&manifest),
        dataset_sha256: sha(&bytes),
        rows: dataset.inference.len(),
        task: rpc::PublicTask::AnswerPublicQuestionV1 { question },
        provider_keys: enrollment.provider_keys.clone(),
        model_fingerprint: enrollment.model_fingerprint.clone(),
        replace_peers: enrollment.replace_peers,
        selected_at_unix_seconds: at,
    })
}

#[cfg(test)]
mod tests;
