//! Immutable native subject and owner-compiled contexts; no transferred publisher authority.

use std::{fs, os::unix::fs::DirBuilderExt as _, path::Path};

use ed25519_dalek::SigningKey;
use volparossa_content::{
    CacheLimits, ChunkStore, Metadata, Publication, SignedManifest, Validity,
    provider::compute::dataset::{
        DOCUMENT_CONTENT_TYPE, DocumentDataset, DocumentQuestion, PRINCIPLE_CONTENT_TYPE,
        PrincipleDataset, verify_source,
    },
};

use super::{
    Enrollment, Options, Result, Serialize, Value, ensure, now, parse_key, rpc, sha, task,
};

pub(super) fn read(path: &Path, maximum: u64) -> Result<Vec<u8>> {
    crate::compute::read_file(path, maximum)
}

pub(super) fn save(path: &Path, value: &impl Serialize) -> Result<()> {
    task::write_bytes(path, &serde_json::to_vec(value)?, false)
}

pub(super) fn directory(path: &Path) -> Result<()> {
    fs::DirBuilder::new().mode(0o700).create(path)?;
    crate::compute::private_directory(path)
}

pub(super) fn exists(path: &Path) -> Result<bool> {
    match fs::symlink_metadata(path) {
        Ok(_) => Ok(true),
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(false),
        Err(error) => Err(error.into()),
    }
}

pub(super) fn retain_result(path: &Path, value: &Value) -> Result<()> {
    if exists(path)? {
        let previous: Value = serde_json::from_slice(&read(path, 256 * 1024)?)?;
        if previous == *value {
            return Ok(());
        }
        ensure!(
            previous["complete"] != true,
            "compute_policy_completed_result_changed"
        );
    }
    task::write_bytes(path, &serde_json::to_vec(value)?, true)
}

pub(super) fn load(root: &Path) -> Result<(Enrollment, String)> {
    let enrolled: Enrollment =
        serde_json::from_slice(&read(&root.join("enrollment.json"), 16 * 1024)?)?;
    ensure!(
        matches!(enrolled.version, 1 | 2)
            && enrolled.providers[0] != enrolled.providers[1]
            && (1..=600).contains(&enrolled.max_seconds)
            && enrolled.selected_at < enrolled.expires
            && matches!(
                enrolled.license.as_str(),
                "GPL-3.0-only" | "CC0-1.0" | "CC-BY-4.0" | "CC-BY-SA-4.0"
            ),
        "compute_policy_enrollment"
    );
    for key in enrolled.providers.iter().chain([&enrolled.publisher_key]) {
        parse_key(key).map_err(anyhow::Error::msg)?;
    }
    let subject = String::from_utf8(read(&root.join("subject.txt"), 512)?)?;
    enrolled.scope.validate(&subject)?;
    let publisher = parse_key(&enrolled.scope.source_publisher_key).map_err(anyhow::Error::msg)?;
    let signed = SignedManifest::decode(&read(&root.join("subject.manifest"), 64 * 1024)?)?;
    let manifest = signed.verify(&publisher, enrolled.selected_at)?;
    ensure!(
        hex::encode(manifest.manifest_id()) == enrolled.scope.source_manifest_id
            && manifest.metadata().name == enrolled.source_name
            && manifest.metadata().content_type == "text/plain"
            && manifest.length() == subject.len() as u64
            && hex::encode(manifest.object_sha256()) == sha(subject.as_bytes())
            && manifest.validity().expires == enrolled.expires
            && enrolled.source_download_sha256
                == sha(&read(&root.join("subject-download.json"), 64 * 1024)?),
        "compute_policy_native_subject_binding"
    );
    ensure!(
        enrolled
            .model_fingerprints
            .iter()
            .all(|hash| crate::compute::is_hex(hash, 64)),
        "compute_policy_model_fingerprint"
    );
    Ok((enrolled, subject))
}

fn publication(
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

fn dataset(enrolled: &Enrollment, context: &str, question: &str, source: &[u8]) -> Result<Vec<u8>> {
    let document = DocumentDataset {
        version: 2,
        visibility: "public".into(),
        license: enrolled.license.clone(),
        source_manifest_hex: hex::encode(source),
        inference: vec![DocumentQuestion {
            question: question.into(),
            context: context.into(),
            start: 0,
            end: context.len() as u64,
        }],
    };
    let Some(output_contract) = enrolled.output_contract(question)? else {
        return Ok(serde_json::to_vec(&document)?);
    };
    Ok(serde_json::to_vec(&PrincipleDataset {
        version: 4,
        visibility: document.visibility,
        license: document.license,
        source_manifest_hex: document.source_manifest_hex,
        inference: document.inference,
        output_contract,
    })?)
}

pub(super) fn prepare(
    args: &Options,
    enrolled: &Enrollment,
    name: &str,
    context: &str,
    question: &str,
) -> Result<super::super::Source> {
    let root = args.output.join(name);
    if !exists(&root)? {
        ensure!(
            now()? < enrolled.expires,
            "compute_policy_original_subject_expired"
        );
        let signer = crate::content::unlock_signer(
            args.identity.as_deref(),
            args.passphrase_file.as_deref(),
        )?;
        ensure!(
            hex::encode(signer.verifying_key().as_bytes()) == enrolled.publisher_key,
            "compute_policy_context_publisher"
        );
        directory(&root)?;
        let temporary = tempfile::tempdir_in(&root)?;
        let mut cache = ChunkStore::create(
            &temporary.path().join("cache"),
            CacheLimits {
                max_bytes: 2 * 1024 * 1024,
                max_entries: 8,
                min_free_bytes: 0,
            },
        )?;
        let validity = Validity {
            created: enrolled.selected_at,
            expires: enrolled.expires,
        };
        let source = publication(
            context.as_bytes(),
            format!("policy-{name}-context"),
            "text/plain",
            validity,
            &signer,
            &mut cache,
        )?;
        let bytes = dataset(enrolled, context, question, &source.encode())?;
        let package_manifest = publication(
            &bytes,
            format!("policy-{name}-dataset"),
            if enrolled.version == 1 {
                DOCUMENT_CONTENT_TYPE
            } else {
                PRINCIPLE_CONTENT_TYPE
            },
            validity,
            &signer,
            &mut cache,
        )?;
        task::write_bytes(&root.join("context.txt"), context.as_bytes(), false)?;
        task::write_bytes(&root.join("context.manifest"), &source.encode(), false)?;
        task::write_bytes(&root.join("dataset.json"), &bytes, false)?;
        task::write_bytes(
            &root.join("dataset.manifest"),
            &package_manifest.encode(),
            false,
        )?;
        drop(cache);
        temporary.close()?;
    }
    check_stage(&root, enrolled, context, question)
}

pub(super) fn check_stage(
    root: &Path,
    enrolled: &Enrollment,
    context: &str,
    question: &str,
) -> Result<super::super::Source> {
    crate::compute::private_directory(root)?;
    let publisher = parse_key(&enrolled.publisher_key).map_err(anyhow::Error::msg)?;
    let source_bytes = read(&root.join("context.manifest"), 64 * 1024)?;
    let source = SignedManifest::decode(&source_bytes)?.verify(&publisher, enrolled.selected_at)?;
    ensure!(
        read(&root.join("context.txt"), 4096)? == context.as_bytes()
            && source.metadata().content_type == "text/plain"
            && source.length() == context.len() as u64
            && hex::encode(source.object_sha256()) == sha(context.as_bytes())
            && source.validity().expires == enrolled.expires,
        "compute_policy_exact_framework_context"
    );
    let bytes = read(&root.join("dataset.json"), rpc::MAX_DATASET_BYTES as u64)?;
    ensure!(
        bytes == dataset(enrolled, context, question, &source_bytes)?,
        "compute_policy_context_dataset"
    );
    let signed = read(&root.join("dataset.manifest"), 64 * 1024)?;
    let verified = verify_source(
        &signed,
        &publisher,
        std::str::from_utf8(&bytes)?,
        enrolled.selected_at,
    )?;
    ensure!(
        verified.expires() == enrolled.expires && verified.row_count() == 1,
        "compute_policy_dataset_expiry"
    );
    Ok(super::super::Source {
        dataset: root.join("dataset.json"),
        dataset_manifest: root.join("dataset.manifest"),
        publisher_key: publisher,
    })
}
