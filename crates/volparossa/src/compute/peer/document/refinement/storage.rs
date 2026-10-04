//! Immutable source/receipt-bound repair intent and ordinary signed document jobs.

use std::{
    fs,
    os::unix::fs::DirBuilderExt,
    path::{Path, PathBuf},
};

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use tokio::sync::watch;
use volparossa_content::{
    CacheLimits, ChunkStore, MAX_MANIFEST_BYTES, SignedManifest, Validity,
    provider::compute::dataset::{
        DOCUMENT_CONTENT_TYPE, DocumentDataset, DocumentQuestion, verify_source,
    },
};

use super::super::storage::{self as document_storage, Enrollment};
use super::super::{
    Input, MAX_SAVED_BYTES, Options, Plan, now, parse_key, private_directory, read_file, rpc, task,
    tokenize, workflow,
};
use super::synthesis::Answer;

pub(super) fn sha(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

pub(super) fn present(path: &Path) -> Result<bool> {
    document_storage::present(path)
}

fn directory(path: &Path) -> Result<()> {
    if !present(path)? {
        fs::DirBuilder::new().mode(0o700).create(path)?;
    }
    private_directory(path)
}

fn file_present(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(info) => {
            ensure!(info.is_file(), "compute_refinement_regular_file");
            Ok(true)
        }
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn has_intent(root: &Path) -> Result<bool> {
    if !present(root)? {
        return Ok(false);
    }
    file_present(&root.join("intent.json"))
}

fn read(path: &Path) -> Result<Vec<u8>> {
    read_file(path, MAX_SAVED_BYTES)
}

fn retain(path: &Path, bytes: &[u8]) -> Result<()> {
    ensure!(
        bytes.len() <= MAX_SAVED_BYTES,
        "compute_refinement_retained_size"
    );
    if file_present(path)? {
        ensure!(
            read(path)? == bytes,
            "compute_refinement_retained_input_changed"
        );
        Ok(())
    } else {
        task::write_bytes(path, bytes, false)
    }
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Intent {
    version: u32,
    part_index: usize,
    parent_sha256: String,
    parent_report_sha256: String,
    parent_job_id: String,
    parent_source_start: u64,
    parent_source_end: u64,
    source_manifest_id: String,
    source_sha256: String,
    source_bytes: u64,
    model_profile: crate::compute::ModelProfile,
    model_fingerprint: String,
    publisher_key: String,
    provider_keys: Vec<String>,
    selected_at_unix_seconds: u64,
    expires_at_unix_seconds: u64,
    license: String,
    question_sha256: String,
    children: [Child; 2],
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Child {
    start: u64,
    end: u64,
    source_sha256: String,
}

#[allow(clippy::too_many_arguments)]
pub(super) fn intent(
    root: &Path,
    enrollment: &Enrollment,
    input: &Input,
    parent: &Answer,
    index: usize,
    ranges: [(u64, u64); 2],
) -> Result<Intent> {
    ensure!(
        super::eligible(parent)
            && parent
                .generation
                .is_some_and(|g| g.model_profile == input.model_profile)
            && enrollment
                .model_fingerprint
                .as_ref()
                .is_none_or(|f| *f == parent.model_fingerprint),
        "compute_refinement_parent_profile"
    );
    ensure!(
        ranges[0].0 == parent.source_start
            && ranges[0].1 == ranges[1].0
            && ranges[1].1 == parent.source_end,
        "compute_refinement_intent_coverage"
    );
    let children = ranges.map(|(start, end)| {
        let text = input
            .document
            .get(usize::try_from(start)?..usize::try_from(end)?)
            .context("compute_refinement_intent_range")?;
        ensure!(!text.trim().is_empty(), "compute_refinement_empty_child");
        Ok::<_, anyhow::Error>(Child {
            start,
            end,
            source_sha256: sha(text.as_bytes()),
        })
    });
    let [left, right] = children;
    let intent = Intent {
        version: 1,
        part_index: index,
        parent_sha256: sha(&serde_json::to_vec(parent)?),
        parent_report_sha256: parent.report_sha256.clone(),
        parent_job_id: parent.job_id.clone(),
        parent_source_start: parent.source_start,
        parent_source_end: parent.source_end,
        source_manifest_id: enrollment.source_manifest_id.clone(),
        source_sha256: sha(input.document.as_bytes()),
        source_bytes: input.document.len() as u64,
        model_profile: input.model_profile,
        model_fingerprint: parent.model_fingerprint.clone(),
        publisher_key: enrollment.publisher_key.clone(),
        provider_keys: enrollment.provider_keys.clone(),
        selected_at_unix_seconds: enrollment.selected_at_unix_seconds,
        expires_at_unix_seconds: enrollment.expires_at_unix_seconds,
        license: input.license.clone(),
        question_sha256: sha(input.question.as_bytes()),
        children: [left?, right?],
    };
    directory(
        root.parent()
            .context("compute_refinement_parent_directory")?,
    )?;
    directory(root)?;
    // This must precede all tokenizer workers, signatures, or new remote jobs.
    retain(&root.join("intent.json"), &serde_json::to_vec(&intent)?)?;
    Ok(intent)
}

pub(super) struct Prepared {
    pub(super) root: PathBuf,
    pub(super) range: (u64, u64),
    pub(super) expected: workflow::ExpectedTask,
}

fn child_input(original: &Input, range: (u64, u64)) -> Result<Input> {
    let text = original
        .document
        .get(usize::try_from(range.0)?..usize::try_from(range.1)?)
        .context("compute_refinement_child_range")?;
    let input = Input {
        version: 1,
        model_profile: original.model_profile,
        visibility: original.visibility.clone(),
        license: original.license.clone(),
        document: text.into(),
        question: original.question.clone(),
        synthesis: false,
        original_source: None,
    };
    input.validate()?;
    Ok(input)
}

fn workflow_plan(root: &Path, enrollment: &Enrollment, input: &Input) -> Value {
    json!({"version":1,"packages":[{"dataset":root.join("dataset.json"),
        "dataset_manifest":root.join("dataset.manifest"),"publisher_key":enrollment.publisher_key,
        "task":rpc::PublicTask::AnswerPublicQuestionV1 { question:input.question.clone() }}]})
}

fn publication_name(intent: &Intent, child: usize) -> String {
    format!("refined-leaf-{:04}-child-{child}", intent.part_index)
}

fn publication(
    args: &Options,
    root: &Path,
    enrollment: &Enrollment,
    intent: &Intent,
    child: usize,
    bytes: &[u8],
) -> Result<()> {
    ensure!(
        now()? < enrollment.expires_at_unix_seconds,
        "compute_refinement_source_expired"
    );
    ensure!(
        args.identity.is_some() && args.passphrase_file.is_some(),
        "compute_refinement_new_publication_requires_identity_and_passphrase_file"
    );
    let signer =
        crate::content::unlock_signer(args.identity.as_deref(), args.passphrase_file.as_deref())?;
    ensure!(
        hex::encode(signer.verifying_key().as_bytes()) == enrollment.publisher_key,
        "compute_refinement_publisher_changed"
    );
    let limits = CacheLimits {
        max_bytes: 64 * 1024 * 1024,
        max_entries: 65_536,
        min_free_bytes: 64 * 1024 * 1024,
    };
    let cache_root = root.join("publication-cache");
    let mut cache = if present(&cache_root)? {
        ChunkStore::open(&cache_root, limits)?
    } else {
        ChunkStore::create(&cache_root, limits)?
    };
    let manifest = document_storage::publish_object(
        bytes,
        publication_name(intent, child),
        DOCUMENT_CONTENT_TYPE,
        Validity {
            created: enrollment.selected_at_unix_seconds,
            expires: enrollment.expires_at_unix_seconds,
        },
        &signer,
        &mut cache,
    )?;
    retain(&root.join("dataset.manifest"), &manifest.encode())?;
    // No unlocked key survives this synchronous scope, or crosses a peer await.
    Ok(())
}

#[allow(clippy::too_many_arguments, clippy::too_many_lines)]
pub(super) async fn prepare_child(
    args: &Options,
    root: &Path,
    enrollment: &Enrollment,
    original: &Input,
    intent: &Intent,
    child: usize,
    range: (u64, u64),
    cancelled: &watch::Receiver<bool>,
    allow_new: bool,
) -> Result<Option<Prepared>> {
    if !present(root)? && !allow_new {
        return Ok(None);
    }
    directory(root)?;
    let input = child_input(original, range)?;
    let authorized = intent
        .children
        .get(child)
        .context("compute_refinement_child_index")?;
    ensure!(
        authorized.start == range.0
            && authorized.end == range.1
            && authorized.source_sha256 == sha(input.document.as_bytes()),
        "compute_refinement_child_changed"
    );
    let planner_input = root.join("planner-input.json");
    if !file_present(&planner_input)? && !allow_new {
        return Ok(None);
    }
    retain(&planner_input, &serde_json::to_vec(&input)?)?;
    let plan: Plan = if file_present(&root.join("document-plan.json"))? {
        serde_json::from_slice(&read(&root.join("document-plan.json"))?)?
    } else {
        if !allow_new || *cancelled.borrow() || now()? >= enrollment.expires_at_unix_seconds {
            return Ok(None);
        }
        let plan = tokenize(args, root, &input, cancelled).await?;
        retain(
            &root.join("document-plan.json"),
            &serde_json::to_vec(&plan)?,
        )?;
        plan
    };
    plan.validate(&input)?;
    // Halves are still measured using the pinned tokenizer. Never silently add
    // deeper splits, hide bytes, or substitute an approximate token count.
    if plan.parts.len() != 1 {
        return Ok(None);
    }
    let source = read_file(&args.directory.join("source.manifest"), MAX_MANIFEST_BYTES)?;
    ensure!(
        sha(&source) == enrollment.source_manifest_id,
        "compute_refinement_original_source_changed"
    );
    let dataset = DocumentDataset {
        version: 2,
        visibility: "public".into(),
        license: input.license.clone(),
        source_manifest_hex: hex::encode(source),
        inference: vec![DocumentQuestion {
            question: input.question.clone(),
            context: input.document.clone(),
            start: range.0,
            end: range.1,
        }],
    };
    dataset.validate_shape()?;
    let bytes = serde_json::to_vec(&dataset)?;
    ensure!(
        bytes.len() <= rpc::MAX_DATASET_BYTES,
        "compute_refinement_dataset_size"
    );
    for (name, value) in [
        ("dataset.json", bytes.clone()),
        (
            "workflow-plan.json",
            serde_json::to_vec(&workflow_plan(root, enrollment, &input))?,
        ),
    ] {
        if !file_present(&root.join(name))? && !allow_new {
            return Ok(None);
        }
        retain(&root.join(name), &value)?;
    }
    if !file_present(&root.join("dataset.manifest"))? {
        if !allow_new || *cancelled.borrow() || now()? >= enrollment.expires_at_unix_seconds {
            return Ok(None);
        }
        publication(args, root, enrollment, intent, child, &bytes)?;
    }
    let manifest = read_file(&root.join("dataset.manifest"), MAX_MANIFEST_BYTES)?;
    let key = parse_key(&enrollment.publisher_key).map_err(anyhow::Error::msg)?;
    let at = enrollment.selected_at_unix_seconds;
    let verified = verify_source(&manifest, &key, std::str::from_utf8(&bytes)?, at)?;
    let native = SignedManifest::decode(&manifest)?.verify(&key, at)?;
    ensure!(
        verified.is_document()
            && verified.row_count() == 1
            && native.validity()
                == (Validity {
                    created: at,
                    expires: enrollment.expires_at_unix_seconds
                })
            && native.metadata().name == publication_name(intent, child)
            && native.metadata().revision == 1,
        "compute_refinement_publication_binding"
    );
    Ok(Some(Prepared {
        root: root.into(),
        range,
        expected: workflow::ExpectedTask {
            publisher_key: enrollment.publisher_key.clone(),
            manifest_id: sha(&manifest),
            dataset_sha256: sha(&bytes),
            rows: 1,
            task: rpc::PublicTask::AnswerPublicQuestionV1 {
                question: input.question,
            },
            provider_keys: enrollment.provider_keys.clone(),
            model_fingerprint: Some(intent.model_fingerprint.clone()),
            replace_peers: enrollment.replace_peers,
            scheduling: enrollment.scheduling,
            selected_at_unix_seconds: at,
        },
    }))
}

pub(super) fn snapshot(prepared: &Prepared) -> Result<Option<Value>> {
    let work = prepared.root.join("work");
    if !present(&work)? {
        return Ok(None);
    }
    Ok(Some(workflow::task_snapshot_detailed(
        &work,
        &prepared.expected,
    )?))
}
