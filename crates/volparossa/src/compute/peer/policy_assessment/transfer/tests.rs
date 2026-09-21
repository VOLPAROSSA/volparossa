//! Real signatures over synthetic transport fixtures, not model execution or semantic evidence.

use std::{os::unix::fs::PermissionsExt as _, sync::Arc};

use ed25519_dalek::SigningKey;
use volparossa_content::{
    SignedManifest,
    provider::{
        PublicationRegistry,
        compute::{
            self as wire, ComputeBackend, ComputeFuture, ComputeService,
            dataset::{
                DOCUMENT_CONTENT_TYPE, DocumentDataset, DocumentQuestion, PRINCIPLE_CONTENT_TYPE,
                PrincipleDataset, PrincipleOutputContract, verify_source,
            },
        },
        serve_publication,
    },
    transfer::TransferLimits,
};

use super::*;
use crate::compute::peer::{JobHandle, transcript};

const SUBJECT: &str = "People help each other by voluntarily sharing spare capacity.";

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn key(signer: &SigningKey) -> String {
    hex::encode(signer.verifying_key().as_bytes())
}

fn capabilities() -> rpc::Capabilities {
    let profile = ModelProfile::Smol360.spec();
    let model = rpc::ModelIdentity {
        model_id: profile.model_id.into(),
        model_revision: profile.revision.into(),
        base_weights: rpc::FileIdentity {
            bytes: profile.weights_bytes,
            sha256: profile.weights_sha256.into(),
        },
        adapter_files: None,
    };
    rpc::Capabilities {
        model_fingerprint: sha(&serde_json::to_vec(&model).unwrap()),
        model,
        accepting_work: true,
        public_inference_only: true,
        runtime_slots: 1,
        max_threads: 2,
        max_job_seconds: 600,
        max_dataset_bytes: rpc::MAX_DATASET_BYTES as u64,
        max_rows: 1,
        task_derivation_v1: true,
        document_inference_v2: true,
        principle_inference_v4: false,
        derived_inference_v3: true,
        successor_activation_v1: false,
    }
}

fn publication(
    bytes: &[u8],
    content_type: &str,
    signer: &SigningKey,
    validity: Validity,
) -> SignedManifest {
    let temporary = private_root();
    let mut cache = ChunkStore::create(
        &temporary.path().join("cache"),
        CacheLimits {
            max_bytes: 2 * 1024 * 1024,
            max_entries: 8,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let mut reader = bytes;
    volparossa_content::publish(
        &mut reader,
        Publication {
            metadata: Metadata {
                name: "synthetic-transport-fixture".into(),
                revision: 1,
                content_type: content_type.into(),
            },
            length: bytes.len() as u64,
            validity,
        },
        signer,
        &mut cache,
    )
    .unwrap()
}

fn enrollment(
    root: &Path,
    owner: &SigningKey,
    providers: &[SigningKey; 2],
    version: u32,
) -> Enrollment {
    let original_publisher = SigningKey::from_bytes(&[21; 32]);
    let selected_at = now().unwrap() - 1;
    let expires = selected_at + 7200;
    let source = publication(
        SUBJECT.as_bytes(),
        "text/plain",
        &original_publisher,
        Validity {
            created: selected_at,
            expires,
        },
    );
    let source_id = hex::encode(
        source
            .verify(&original_publisher.verifying_key(), selected_at)
            .unwrap()
            .manifest_id(),
    );
    let receipt = br#"{"synthetic_transport_fixture":true,"protected_retrieval_claimed":false}"#;
    let fingerprint = capabilities().model_fingerprint;
    let enrollment = Enrollment {
        version,
        scope: assessment::Scope::new(&key(&original_publisher), &source_id, SUBJECT).unwrap(),
        source_name: "synthetic-transport-fixture".into(),
        source_download_sha256: sha(receipt),
        publisher_key: key(owner),
        providers: [key(&providers[0]), key(&providers[1])],
        model_fingerprints: [fingerprint.clone(), fingerprint],
        license: "CC0-1.0".into(),
        selected_at,
        expires,
        max_seconds: 600,
        portable_receipts: true,
    };
    task::write_bytes(&root.join("subject.txt"), SUBJECT.as_bytes(), false).unwrap();
    task::write_bytes(&root.join("subject.manifest"), &source.encode(), false).unwrap();
    task::write_bytes(&root.join("subject-download.json"), receipt, false).unwrap();
    storage::save(&root.join("enrollment.json"), &enrollment).unwrap();
    enrollment
}

struct SyntheticPoll {
    requester: [u8; 32],
    request: Vec<u8>,
    response: Vec<u8>,
}

impl ComputeBackend for SyntheticPoll {
    fn exchange(&self, requester: [u8; 32], request: Vec<u8>) -> ComputeFuture<'_> {
        Box::pin(async move {
            if requester != self.requester || request != self.request {
                return Err(wire::ComputeError::Authentication);
            }
            Ok(self.response.clone())
        })
    }
}

async fn signed_poll(
    provider: &SigningKey,
    requester: &SigningKey,
    handle: &JobHandle,
    status: &rpc::JobStatus,
) -> transcript::Retained {
    let request = rpc::Request {
        version: rpc::VERSION,
        request_id: "7".repeat(32),
        requester_key: key(requester),
        operation: rpc::Operation::Poll(handle.binding.clone()),
    };
    let request_bytes = serde_json::to_vec(&request).unwrap();
    let response = rpc::Response {
        version: rpc::VERSION,
        request_id: request.request_id,
        outcome: rpc::Outcome::Job(status.clone()),
    };
    let mut registry = PublicationRegistry::new();
    registry.set_compute(Arc::new(ComputeService::new(
        Arc::new(provider.clone()),
        Arc::new(SyntheticPoll {
            requester: requester.verifying_key().to_bytes(),
            request: request_bytes.clone(),
            response: serde_json::to_vec(&response).unwrap(),
        }),
    )));
    let (mut client, mut server) = tokio::io::duplex(4096);
    let serving = serve_publication(&mut server, &registry, TransferLimits::default());
    let requesting = async {
        let challenge = wire::begin(&mut client, provider.verifying_key().as_bytes())
            .await
            .unwrap();
        wire::exchange_attested(&mut client, challenge, requester, request_bytes)
            .await
            .unwrap()
    };
    let (service_result, attested) = tokio::join!(serving, requesting);
    service_result.unwrap();
    serde_json::from_value(json!({"version":1,"requester_key":key(requester),
        "transcript_hex":hex::encode(attested.transcript_bytes())}))
    .unwrap()
}

fn payload(review: bool) -> Value {
    let mut payload = json!({"version":1,"outcome":"allow",
        "reasoning":[{"principle":"Humanitas","quote":"help each other",
            "reason":"Synthetic parser fixture about cooperation; not model-produced reasoning."}],
        "counterargument":"This is test data, not proof of a model's correctness.",
        "uncertainty":{"material":false,"reason":"The asserted fields exercise transport validation only."}});
    if review {
        payload["verdict"] = "support".into();
    }
    payload
}

fn stage_dataset(
    enrolled: &Enrollment,
    context: &str,
    question: &str,
    context_manifest: &SignedManifest,
) -> (Vec<u8>, &'static str) {
    let dataset = DocumentDataset {
        version: 2,
        visibility: "public".into(),
        license: enrolled.license.clone(),
        source_manifest_hex: hex::encode(context_manifest.encode()),
        inference: vec![DocumentQuestion {
            question: question.into(),
            context: context.into(),
            start: 0,
            end: context.len() as u64,
        }],
    };
    let contract = enrolled.output_contract(question).unwrap();
    if let Some(output_contract) = contract {
        (
            serde_json::to_vec(&PrincipleDataset {
                version: 4,
                visibility: dataset.visibility,
                license: dataset.license,
                source_manifest_hex: dataset.source_manifest_hex,
                inference: dataset.inference,
                output_contract,
            })
            .unwrap(),
            PRINCIPLE_CONTENT_TYPE,
        )
    } else {
        (serde_json::to_vec(&dataset).unwrap(), DOCUMENT_CONTENT_TYPE)
    }
}

#[allow(
    clippy::too_many_arguments,
    reason = "Each synthetic stage binds the actual selected signers and its exact compiled context"
)]
async fn stage(
    root: &Path,
    enrolled: &Enrollment,
    owner: &SigningKey,
    provider: &SigningKey,
    requester: &SigningKey,
    ordinal: u8,
    context: &str,
    question: &str,
    output: &Value,
) -> assessment::Evidence {
    let name = ["assessment-0", "assessment-1", "review-0", "review-1"][usize::from(ordinal)];
    let directory = root.join(name);
    storage::directory(&directory).unwrap();
    storage::directory(&directory.join("work")).unwrap();
    let validity = Validity {
        created: enrolled.selected_at,
        expires: enrolled.expires,
    };
    let context_manifest = publication(context.as_bytes(), "text/plain", owner, validity);
    let (dataset_bytes, mime) = stage_dataset(enrolled, context, question, &context_manifest);
    let contract = enrolled.output_contract(question).unwrap();
    let dataset_manifest = publication(&dataset_bytes, mime, owner, validity);
    let verified = verify_source(
        &dataset_manifest.encode(),
        &owner.verifying_key(),
        std::str::from_utf8(&dataset_bytes).unwrap(),
        enrolled.selected_at,
    )
    .unwrap();
    let mut caps = capabilities();
    caps.principle_inference_v4 = enrolled.version == 2;
    let handle = JobHandle {
        version: 1,
        provider_key: key(provider),
        binding: rpc::JobBinding {
            job_id: hex::encode([ordinal + 10; 16]),
            dataset_manifest_id: hex::encode(verified.manifest_id()),
            dataset_sha256: sha(verified.derive(&[0]).unwrap().as_bytes()),
            model_fingerprint: caps.model_fingerprint.clone(),
            row_indices: vec![0],
            expires_unix_seconds: enrolled.selected_at + 600,
            task: None,
        },
        capabilities: caps,
    };
    // Required broker schema only: these fabricated worker fields are deliberately not
    // presented as execution evidence. The provider authentically signs this TEST statement.
    let mut report = json!({"mode":"infer","status":"ok","updates_completed":0,
        "dataset":{"sha256":handle.binding.dataset_sha256,"visibility":"public","inference_examples":1},
        "model":{"id":handle.capabilities.model.model_id,"revision":handle.capabilities.model.model_revision,
            "files":{"model.safetensors":handle.capabilities.model.base_weights}},
        "supervisor":{"child_reaped":true,"network_access":false},
        "outputs":[{"sample_index":0,"text":output.to_string(),"text_truncated":false,"generated_tokens":1,
            "generation":{"version":1,"model_profile":"smollm2-360m-v1","stop_reason":"eos","max_new_tokens":256}}]});
    if let Some(contract) = contract {
        report["dataset"]["version"] = 4.into();
        report["dataset"]["output_contract"] = serde_json::to_value(contract).unwrap();
        report["outputs"][0]["generation"]["version"] = 3.into();
        report["outputs"][0]["generation"]["max_new_tokens"] = 512.into();
        report["outputs"][0]["generated_tokens"] = 400.into();
        report["outputs"][0]["generation"]["stop_reason"] = "json_boundary".into();
        report["outputs"][0]["generation"]["output_contract"] =
            serde_json::to_value(contract).unwrap();
    }
    let report_json = report.to_string();
    let status = rpc::JobStatus {
        binding: handle.binding.clone(),
        state: rpc::JobState::Complete,
        cancellation_requested: false,
        report_sha256: Some(sha(report_json.as_bytes())),
        report_json: Some(report_json),
        error: None,
    };
    let proof = signed_poll(provider, requester, &handle, &status).await;
    assert_eq!(
        proof
            .check(&handle, enrolled.selected_at, &key(requester))
            .unwrap(),
        status
    );
    for (name, bytes) in [
        ("context.txt", context.as_bytes().to_vec()),
        ("context.manifest", context_manifest.encode()),
        ("dataset.json", dataset_bytes),
        ("dataset.manifest", dataset_manifest.encode()),
    ] {
        task::write_bytes(&directory.join(name), &bytes, false).unwrap();
    }
    storage::save(&directory.join("work/job-0.json"), &handle).unwrap();
    batch::save_status(&directory.join("work"), &handle, &status).unwrap();
    storage::save(&directory.join("provider-transcript.json"), &proof).unwrap();
    assessment::Evidence {
        provider_key: handle.provider_key,
        job_id: handle.binding.job_id,
        report_sha256: status.report_sha256.unwrap(),
        model_fingerprint: handle.binding.model_fingerprint,
        package_manifest_id: handle.binding.dataset_manifest_id,
    }
}

async fn fixture(root: &Path, requester: &SigningKey, version: u32) -> Value {
    let owner = SigningKey::from_bytes(&[22; 32]);
    let providers = [
        SigningKey::from_bytes(&[23; 32]),
        SigningKey::from_bytes(&[24; 32]),
    ];
    let enrolled = enrollment(root, &owner, &providers, version);
    let mut assessments = Vec::new();
    let mut stages = Vec::new();
    for index in 0..2_u8 {
        let output = payload(false);
        let evidence = stage(
            root,
            &enrolled,
            &owner,
            &providers[usize::from(index)],
            requester,
            index,
            &assessment::assessment_context(SUBJECT).unwrap(),
            enrolled.question(false),
            &output,
        )
        .await;
        assessments.push(
            assessment::decode_assessment(
                output.to_string().as_bytes(),
                &enrolled.scope,
                &evidence,
                SUBJECT,
            )
            .unwrap(),
        );
        stages.push(json!({"stage":format!("assessment-{index}"),"state":"complete","execution_complete":true,
            "answer_complete":true,"structured_judgment_valid":true}));
    }
    let assessments: [assessment::Assessment; 2] = assessments.try_into().unwrap();
    let mut reviews = Vec::new();
    for index in 0..2_u8 {
        let output = payload(true);
        let target = &assessments[usize::from(1 - index)];
        let evidence = stage(
            root,
            &enrolled,
            &owner,
            &providers[usize::from(index)],
            requester,
            index + 2,
            &assessment::review_context(SUBJECT, target).unwrap(),
            enrolled.question(true),
            &output,
        )
        .await;
        reviews.push(
            assessment::decode_review(
                output.to_string().as_bytes(),
                &enrolled.scope,
                &evidence,
                target,
                SUBJECT,
            )
            .unwrap(),
        );
        stages.push(
            json!({"stage":format!("review-{index}"),"state":"complete","execution_complete":true,
            "answer_complete":true,"structured_judgment_valid":true}),
        );
    }
    let reviews: [assessment::Review; 2] = reviews.try_into().unwrap();
    let result = completed_result(
        &enrolled,
        &assessment::resolve(&enrolled.scope, SUBJECT, &assessments, &reviews).unwrap(),
        &stages,
    );
    storage::save(&root.join("result.json"), &result).unwrap();
    result
}

fn change_json(encoded: &mut Value, change: impl FnOnce(&mut Value)) {
    let mut value: Value =
        serde_json::from_slice(&hex::decode(encoded.as_str().unwrap()).unwrap()).unwrap();
    change(&mut value);
    *encoded = hex::encode(serde_json::to_vec(&value).unwrap()).into();
}

fn projected(value: &Value, requester: &str) -> Result<Value> {
    let package = bundle::decode(&serde_json::to_vec(value)?)?;
    let parent = private_root();
    let output = private_temporary(parent.path())?;
    assert_eq!(
        std::fs::metadata(output.path())?.permissions().mode() & 0o777,
        0o700
    );
    package.materialize(output.path())?;
    replay(output.path(), requester)
}

#[tokio::test]
async fn four_provider_signed_poll_statements_survive_projection_and_reject_changed_bindings() {
    let root = private_root();
    let requester = SigningKey::from_bytes(&[25; 32]);
    let requester_key = key(&requester);
    let original = fixture(root.path(), &requester, 1).await;
    assert_eq!(replay(root.path(), &requester_key).unwrap(), original);
    let package =
        serde_json::to_value(bundle::collect(root.path(), &requester_key).unwrap()).unwrap();
    assert_eq!(projected(&package, &requester_key).unwrap(), original);
    assert_eq!(original["network_policy_activation"], false);
    assert_eq!(original["decision"]["independent_evidence_proven"], false);

    for alteration in [
        "receipt",
        "proof",
        "provider",
        "requester",
        "subject",
        "review_target",
        "expiry",
    ] {
        let mut changed = package.clone();
        match alteration {
            "receipt" => change_json(&mut changed["stages"][0]["receipt"], |receipt| {
                let mut report: Value =
                    serde_json::from_str(receipt["status"]["report_json"].as_str().unwrap())
                        .unwrap();
                report["outputs"][0]["text"] = payload(true).to_string().into();
                let raw = report.to_string();
                receipt["status"]["report_sha256"] = sha(raw.as_bytes()).into();
                receipt["status"]["report_json"] = raw.into();
            }),
            "proof" => change_json(&mut changed["stages"][0]["provider_transcript"], |proof| {
                let mut bytes = hex::decode(proof["transcript_hex"].as_str().unwrap()).unwrap();
                *bytes.last_mut().unwrap() ^= 1;
                proof["transcript_hex"] = hex::encode(bytes).into();
            }),
            "provider" => change_json(&mut changed["enrollment"], |enrolled| {
                enrolled["providers"][0] = key(&SigningKey::from_bytes(&[26; 32])).into();
            }),
            "requester" => {
                changed["requester_key"] = key(&SigningKey::from_bytes(&[27; 32])).into();
            }
            "subject" => changed["subject"] = hex::encode(b"Changed public subject.").into(),
            "review_target" => change_json(&mut changed["result"], |result| {
                result["decision"]["reviews"][0]["reviewed_assessment_sha256"] =
                    "a".repeat(64).into();
            }),
            "expiry" => change_json(&mut changed["enrollment"], |enrolled| {
                enrolled["expires"] = (enrolled["expires"].as_u64().unwrap() + 1).into();
            }),
            _ => unreachable!(),
        }
        assert!(
            projected(&changed, &requester_key).is_err(),
            "accepted changed {alteration}"
        );
    }
}

#[tokio::test]
async fn structured_four_stage_projection_rejects_an_authentic_but_wrong_stage_contract() {
    let root = private_root();
    let requester = SigningKey::from_bytes(&[25; 32]);
    let requester_key = key(&requester);
    let original = fixture(root.path(), &requester, 2).await;
    assert_eq!(replay(root.path(), &requester_key).unwrap(), original);
    let mut package =
        serde_json::to_value(bundle::collect(root.path(), &requester_key).unwrap()).unwrap();
    assert_eq!(projected(&package, &requester_key).unwrap(), original);
    assert_eq!(original["network_policy_activation"], false);
    assert_eq!(original["decision"]["independent_evidence_proven"], false);

    // Both the signature and this review-shaped response are valid. They still cannot
    // satisfy the immutable assessment input. This is a synthetic signed claim, not ML.
    let stage = &mut package["stages"][0];
    let handle: JobHandle =
        serde_json::from_slice(&hex::decode(stage["handle"].as_str().unwrap()).unwrap()).unwrap();
    let mut receipt: Value =
        serde_json::from_slice(&hex::decode(stage["receipt"].as_str().unwrap()).unwrap()).unwrap();
    let mut report: Value =
        serde_json::from_str(receipt["status"]["report_json"].as_str().unwrap()).unwrap();
    report["outputs"][0]["text"] = payload(true).to_string().into();
    report["outputs"][0]["generation"]["output_contract"] =
        serde_json::to_value(PrincipleOutputContract::PrincipleReviewV1).unwrap();
    let raw = report.to_string();
    receipt["status"]["report_sha256"] = sha(raw.as_bytes()).into();
    receipt["status"]["report_json"] = raw.into();
    let status: rpc::JobStatus = serde_json::from_value(receipt["status"].clone()).unwrap();
    let provider = SigningKey::from_bytes(&[23; 32]);
    let proof = signed_poll(&provider, &requester, &handle, &status).await;
    assert_eq!(proof.check(&handle, 1, &requester_key).unwrap(), status);
    stage["receipt"] = hex::encode(serde_json::to_vec(&receipt).unwrap()).into();
    stage["provider_transcript"] = hex::encode(serde_json::to_vec(&proof).unwrap()).into();
    assert_eq!(
        projected(&package, &requester_key).unwrap_err().to_string(),
        "compute_policy_output_contract"
    );
}
