//! One explicitly public source file, one core-selected peer, one inert proposal.
//! There is no local planner/model, remote edit authority, shell or output repair.

use anyhow::{Context as _, Result, ensure};
use serde_json::{Value, json};
use tokio::sync::watch;
use volparossa_content::provider::compute::dataset::{
    CODE_PROPOSAL_CONTENT_TYPE, CodeProposalDataset, CodeProposalOutputContract, DocumentQuestion,
};
use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity};

use super::{Path, Source, batch, discovery, document::public, now, read_file, rpc, sha, task};

pub(in crate::compute) async fn execute(
    config: &public::Config,
    root: &Path,
    socket: &Path,
    question: String,
    context: String,
    license: String,
    cancelled: &watch::Receiver<bool>,
) -> public::Execution {
    let result = async {
        config.validate_code()?;
        ensure!(!*cancelled.borrow(), "compute_code_cancelled");
        let query = rpc::EligibilityQuery {
            model_profile: Some(config.model_profile.to_string()),
            publisher_keys: vec![hex::encode(config.publisher_key.as_bytes())],
            model_fingerprint: config.model_fingerprint.clone(),
            require_task_derivation_v1: false,
            require_document_inference_v2: false,
            require_derived_inference_v3: false,
            require_principle_inference_v4: false,
            require_code_proposal_v6: true,
        };
        query.validate()?;
        let selected = if config.discover_peers {
            discovery::select_query(socket, query.clone(), cancelled, 1, 1).await?
        } else {
            let provider = config.provider_key[0];
            let caps = super::readiness::capabilities(socket, &provider, cancelled.clone()).await?;
            ensure!(query.matches(&caps), "compute_code_ineligible_provider");
            discovery::Selected {
                providers: vec![provider],
                model_fingerprint: caps.model_fingerprint,
            }
        };
        ensure!(!*cancelled.borrow(), "compute_code_cancelled");
        let source = publish(config, root, question, context, license)?;
        let output = root.join("execution");
        let options = batch::Options::workflow(
            source.clone(),
            selected.providers.clone(),
            output.clone(),
            config.max_seconds,
            None,
        )
        .with_model_fingerprint(Some(selected.model_fingerprint.clone()))
        .allow_single_provider(true);
        let _ = batch::report_with_activity(&options, socket, cancelled).await?;
        Ok((source, selected))
    }
    .await;
    // Every submitted job is already durably recorded by batch before Submit.
    // Reuse document service's exact-handle reconciliation even after failure/cancel.
    let cleanup_confirmed = public::reconcile_code(root, socket).await;
    let result = result.and_then(|(source, selected)| {
        ensure!(cleanup_confirmed, "compute_code_cleanup_unconfirmed");
        compact(config, root, &source, &selected)
    });
    public::Execution {
        result,
        cleanup_confirmed,
    }
}

fn publish(
    config: &public::Config,
    root: &Path,
    question: String,
    context: String,
    license: String,
) -> Result<Source> {
    let signer =
        crate::content::unlock_signer(Some(&config.identity), Some(&config.passphrase_file))?;
    ensure!(
        signer.verifying_key() == config.publisher_key,
        "compute_code_publisher"
    );
    publish_signed(
        root,
        config.model_profile,
        question,
        context,
        license,
        &signer,
    )
}

fn publish_signed(
    root: &Path,
    profile: crate::compute::ModelProfile,
    question: String,
    context: String,
    license: String,
    signer: &ed25519_dalek::SigningKey,
) -> Result<Source> {
    let at = now()?;
    let validity = Validity {
        created: at,
        expires: at.checked_add(3600).context("compute_code_expiry")?,
    };
    let mut cache = ChunkStore::create(
        &root.join("publication-cache"),
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 64,
            min_free_bytes: 64 * 1024 * 1024,
        },
    )?;
    let mut input = context.as_bytes();
    let original = volparossa_content::publish(
        &mut input,
        Publication {
            metadata: Metadata {
                name: "public-code-source".into(),
                revision: 1,
                content_type: "text/plain".into(),
            },
            length: context.len() as u64,
            validity,
        },
        signer,
        &mut cache,
    )?;
    let source_bytes = original.encode();
    let data = CodeProposalDataset {
        version: 6,
        visibility: "public".into(),
        purpose: "code_proposal".into(),
        license,
        model_profile: profile,
        source_manifest_hex: hex::encode(&source_bytes),
        inference: vec![DocumentQuestion {
            question,
            start: 0,
            end: context.len() as u64,
            context,
        }],
        output_contract: CodeProposalOutputContract::SingleFileReplacementV1,
    };
    data.validate_shape()?;
    let raw = serde_json::to_vec(&data)?;
    let mut input = raw.as_slice();
    let manifest = volparossa_content::publish(
        &mut input,
        Publication {
            metadata: Metadata {
                name: "public-code-proposal".into(),
                revision: 1,
                content_type: CODE_PROPOSAL_CONTENT_TYPE.into(),
            },
            length: raw.len() as u64,
            validity,
        },
        signer,
        &mut cache,
    )?;
    task::write_bytes(&root.join("source.manifest"), &source_bytes, false)?;
    task::write_bytes(&root.join("dataset.json"), &raw, false)?;
    task::write_bytes(&root.join("dataset.manifest"), &manifest.encode(), false)?;
    let source = Source {
        dataset: root.join("dataset.json"),
        dataset_manifest: root.join("dataset.manifest"),
        publisher_key: signer.verifying_key(),
    };
    let _ = super::source(&source)?;
    Ok(source)
}

fn compact(
    config: &public::Config,
    root: &Path,
    source: &Source,
    selected: &discovery::Selected,
) -> Result<Value> {
    let (publication, verified) = super::source(source)?;
    let handle: super::JobHandle =
        serde_json::from_slice(&read_file(&root.join("execution/job-0.json"), 65536)?)?;
    ensure!(
        handle.version == 1
            && handle.binding.row_indices == [0]
            && handle.binding.task.is_none()
            && handle.binding.dataset_sha256 == sha(publication.dataset_json.as_bytes())
            && handle.binding.dataset_manifest_id == hex::encode(verified.manifest_id())
            && handle.binding.model_fingerprint == selected.model_fingerprint
            && handle.provider_key == hex::encode(selected.providers[0].as_bytes())
            && super::super::broker::profile_for_model(&handle.capabilities.model)?
                == config.model_profile,
        "compute_code_handle_binding"
    );
    let receipt: Value = serde_json::from_slice(&read_file(
        &root.join(format!("execution/receipt-{}.json", handle.binding.job_id)),
        rpc::MAX_RESPONSE_BYTES + 32768,
    )?)?;
    ensure!(
        receipt["version"] == 1
            && receipt["handle"] == serde_json::to_value(&handle)?
            && receipt["verified_at_unix_seconds"]
                .as_u64()
                .is_some_and(|time| time <= now().unwrap_or(0)),
        "compute_code_receipt_binding"
    );
    let status: rpc::JobStatus = serde_json::from_value(receipt["status"].clone())?;
    let status = super::job(rpc::Outcome::Job(status), &handle)?;
    ensure!(
        status.state == rpc::JobState::Complete && !status.cancellation_requested,
        "compute_code_incomplete_execution"
    );
    let report: Value = serde_json::from_str(
        status
            .report_json
            .as_deref()
            .context("compute_code_report")?,
    )?;
    super::super::public_code::validate_report(
        &report,
        publication.dataset_json.as_bytes(),
        config.model_profile,
    )?;
    Ok(
        json!({"version":1,"operation":"public_code_proposal","purpose":"code_proposal",
        "output_contract":"single_file_replacement_v1","visibility":"public",
        "model_profile":config.model_profile,"source_sha256":report["dataset"]["source_sha256"],
        "source_bytes":report["dataset"]["source_bytes"],
        "source_manifest_id":report["dataset"]["source_manifest_sha256"],
        "dataset_sha256":handle.binding.dataset_sha256,
        "dataset_manifest_id":handle.binding.dataset_manifest_id,
        "provider_keys":[handle.provider_key],"model_fingerprint":selected.model_fingerprint,
        "execution_complete":true,"proposal_complete":report["proposal_complete"],
        "cleanup_confirmed":true,"private_data_supported":false,"remote_erasure_guaranteed":false,
        "outputs":report["outputs"],"receipt":receipt}),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::compute::ModelProfile;
    use std::os::unix::fs::PermissionsExt as _;

    #[test]
    fn public_code_publication_binds_complete_source_question_and_purpose() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[19; 32]);
        let source = publish_signed(
            root.path(),
            ModelProfile::Qwen600,
            "Add a checked sum.".into(),
            "pub fn sum() {}\n".into(),
            "CC0-1.0".into(),
            &signer,
        )
        .unwrap();
        let (publication, verified) = super::super::source(&source).unwrap();
        assert!(verified.is_code_proposal());
        assert_eq!(verified.code_model_profile(), Some(ModelProfile::Qwen600));
        assert_eq!(verified.derive(&[0]).unwrap(), publication.dataset_json);
        assert!(verified.derive(&[1]).is_err());
        let mut changed: Value = serde_json::from_str(&publication.dataset_json).unwrap();
        changed["inference"][0]["context"] = "private replacement".into();
        task::write_bytes(&source.dataset, changed.to_string().as_bytes(), true).unwrap();
        assert!(super::super::source(&source).is_err());
    }

    #[test]
    fn public_code_publication_does_not_accept_a_document_model() {
        let root = tempfile::tempdir().unwrap();
        std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let signer = ed25519_dalek::SigningKey::from_bytes(&[20; 32]);
        assert!(
            publish_signed(
                root.path(),
                ModelProfile::default(),
                "Change code.".into(),
                "public source".into(),
                "CC0-1.0".into(),
                &signer
            )
            .is_err()
        );
    }
}
