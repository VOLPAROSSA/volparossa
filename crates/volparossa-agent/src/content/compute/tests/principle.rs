//! Signed v4 dataset admission only; these tests do not execute a model or activate policy.

use super::*;

fn principle_capabilities() -> Capabilities {
    let mut caps = capabilities();
    let spec = ModelProfile::Smol360.spec();
    caps.model.model_id = spec.model_id.into();
    caps.model.model_revision = spec.revision.into();
    caps.model.base_weights = FileIdentity {
        bytes: spec.weights_bytes,
        sha256: spec.weights_sha256.into(),
    };
    caps.model_fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&caps.model).unwrap()));
    caps.max_rows = spec.max_rows;
    caps.principle_inference_v4 = true;
    caps
}

fn signed(
    cache: &mut ChunkStore,
    signer: &SigningKey,
    bytes: &str,
    mime: &str,
    expires: u64,
) -> Vec<u8> {
    publish(
        &mut bytes.as_bytes(),
        Publication {
            metadata: Metadata {
                name: "public-principle-fixture".into(),
                revision: 1,
                content_type: mime.into(),
            },
            length: bytes.len() as u64,
            validity: Validity {
                created: now() - 1,
                expires,
            },
        },
        signer,
        cache,
    )
    .unwrap()
    .encode()
}

fn principle_request(root: &Path, publisher: &SigningKey, requester: &SigningKey) -> Request {
    let mut request = request(root, publisher, requester);
    let mut cache = ChunkStore::create(
        &root.join("principle-cache"),
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 8,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let context = "A signed public principle context.";
    let expires = now() + 500;
    let source = signed(&mut cache, publisher, context, "text/plain", expires);
    let original = dataset::PrincipleDataset {
        version: 4,
        visibility: "public".into(),
        license: "CC0-1.0".into(),
        source_manifest_hex: hex::encode(source),
        inference: vec![dataset::DocumentQuestion {
            question: "Assess this public context.".into(),
            context: context.into(),
            start: 0,
            end: context.len() as u64,
        }],
        output_contract: dataset::PrincipleOutputContract::PrincipleAssessmentV1,
    };
    let json = serde_json::to_string(&original).unwrap();
    let manifest = signed(
        &mut cache,
        publisher,
        &json,
        dataset::PRINCIPLE_CONTENT_TYPE,
        expires,
    );
    let verified =
        dataset::verify_source(&manifest, &publisher.verifying_key(), &json, now()).unwrap();
    let Operation::Submit(submit) = &mut request.operation else {
        panic!("submit")
    };
    submit.publication.manifest_hex = hex::encode(manifest);
    submit.publication.dataset_json = json;
    submit.binding.dataset_manifest_id = hex::encode(verified.manifest_id());
    submit.binding.model_fingerprint = principle_capabilities().model_fingerprint;
    submit.binding.row_indices = vec![0];
    submit.dataset_json = derive_submission(&verified, &submit.binding).unwrap();
    submit.binding.dataset_sha256 = hex::encode(Sha256::digest(submit.dataset_json.as_bytes()));
    request
}

#[test]
fn principle_capability_requires_exact_360_profile_and_remains_attachment_pinned() {
    let caps = principle_capabilities();
    validate_capabilities(&caps).unwrap();
    let mut legacy = capabilities();
    legacy.principle_inference_v4 = true;
    assert!(validate_capabilities(&legacy).is_err());
    let root = tempfile::tempdir().unwrap();
    let publisher = SigningKey::from_bytes(&[45; 32]);
    let service = Arc::new(Mutex::new(None));
    let registry = Arc::new(Mutex::new(PublicationRegistry::new()));
    let mut backend = attachment(
        BrokerSocket {
            path: root.path().join("unused.sock"),
            device: 0,
            inode: 0,
            uid: nix::unistd::geteuid().as_raw(),
        },
        &service,
        &registry,
        &publisher,
    );
    let mutable = Arc::get_mut(&mut backend).unwrap();
    mutable
        .model_fingerprint
        .clone_from(&caps.model_fingerprint);
    mutable.principle_inference_v4 = true;
    let request = Request {
        version: rpc::VERSION,
        request_id: "a".repeat(32),
        requester_key: "b".repeat(64),
        operation: Operation::Capabilities,
    };
    let mut response = Response {
        version: rpc::VERSION,
        request_id: request.request_id.clone(),
        outcome: Outcome::Capabilities(caps),
    };
    backend
        .validate_broker_response(&request, &response)
        .unwrap();
    let Outcome::Capabilities(changed) = &mut response.outcome else {
        panic!("capabilities")
    };
    changed.principle_inference_v4 = false;
    assert!(
        backend
            .validate_broker_response(&request, &response)
            .is_err()
    );
}

#[test]
fn principle_admission_requires_opt_in_and_preserves_signed_contract_at_both_boundaries() {
    let root = tempfile::tempdir().unwrap();
    let publisher = SigningKey::from_bytes(&[45; 32]);
    let requester = SigningKey::from_bytes(&[46; 32]);
    let original = principle_request(root.path(), &publisher, &requester);
    let service = Arc::new(Mutex::new(None));
    let registry = Arc::new(Mutex::new(PublicationRegistry::new()));
    let mut backend = attachment(
        BrokerSocket {
            path: root.path().join("unused.sock"),
            device: 0,
            inode: 0,
            uid: nix::unistd::geteuid().as_raw(),
        },
        &service,
        &registry,
        &publisher,
    );
    let mutable = Arc::get_mut(&mut backend).unwrap();
    mutable.model_fingerprint = principle_capabilities().model_fingerprint;
    mutable.document_inference_v2 = true;
    assert!(
        backend
            .validate(requester.verifying_key().as_bytes(), &original)
            .is_err()
    );
    let mutable = Arc::get_mut(&mut backend).unwrap();
    mutable.document_inference_v2 = false;
    mutable.principle_inference_v4 = true;
    backend
        .validate(requester.verifying_key().as_bytes(), &original)
        .unwrap();
    super::super::super::compute_remote::validate_request(&original, &requester).unwrap();
    for alteration in ["contract", "question", "task"] {
        let mut changed = original.clone();
        let Operation::Submit(submit) = &mut changed.operation else {
            panic!("submit")
        };
        let mut data: serde_json::Value = serde_json::from_str(&submit.dataset_json).unwrap();
        match alteration {
            "contract" => data["output_contract"] = "principle_review_v1".into(),
            "question" => data["inference"][0]["question"] = "A replaced question?".into(),
            _ => {
                submit.binding.task = Some(rpc::PublicTask::AnswerPublicQuestionV1 {
                    question: "A requester override?".into(),
                });
            }
        }
        submit.dataset_json = data.to_string();
        submit.binding.dataset_sha256 = hex::encode(Sha256::digest(submit.dataset_json.as_bytes()));
        assert!(
            backend
                .validate(requester.verifying_key().as_bytes(), &changed)
                .is_err(),
            "{alteration}"
        );
        assert!(
            super::super::super::compute_remote::validate_request(&changed, &requester).is_err(),
            "{alteration}"
        );
    }
    assert!(!root.path().join("unused.sock").exists());
}
