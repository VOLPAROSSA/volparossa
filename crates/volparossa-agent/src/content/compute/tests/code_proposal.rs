//! Signed public-source admission, not evidence of remote model execution.

use super::*;

fn code_capabilities(profile: ModelProfile) -> Capabilities {
    let spec = profile.spec();
    let mut caps = capabilities();
    caps.model = ModelIdentity {
        model_id: spec.model_id.into(),
        model_revision: spec.revision.into(),
        base_weights: FileIdentity {
            bytes: spec.weights_bytes,
            sha256: spec.weights_sha256.into(),
        },
        adapter_files: None,
    };
    caps.model_fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&caps.model).unwrap()));
    caps.max_rows = 1;
    caps.task_derivation_v1 = false;
    caps.code_proposal_v6 = true;
    caps
}

fn signed(cache: &mut ChunkStore, publisher: &SigningKey, text: &str, mime: &str) -> Vec<u8> {
    publish(
        &mut text.as_bytes(),
        Publication {
            metadata: Metadata {
                name: "public-code-fixture".into(),
                revision: 1,
                content_type: mime.into(),
            },
            length: text.len() as u64,
            validity: Validity {
                created: now() - 1,
                expires: now() + 500,
            },
        },
        publisher,
        cache,
    )
    .unwrap()
    .encode()
}

fn code_request(root: &Path, publisher: &SigningKey, requester: &SigningKey) -> Request {
    let mut request = request(root, publisher, requester);
    let mut cache = ChunkStore::create(
        &root.join("code-cache"),
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 8,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let context = "pub fn sum(a: u32, b: u32) -> u32 { a - b }\n";
    let manifest = signed(&mut cache, publisher, context, "text/plain");
    let json = serde_json::to_string(&dataset::CodeProposalDataset {
        version: 6,
        visibility: "public".into(),
        purpose: "code_proposal".into(),
        license: "GPL-3.0-only".into(),
        model_profile: ModelProfile::Qwen600,
        source_manifest_hex: hex::encode(manifest),
        inference: vec![dataset::DocumentQuestion {
            question: "Correct addition; return replacement source only.".into(),
            context: context.into(),
            start: 0,
            end: context.len() as u64,
        }],
        output_contract: dataset::CodeProposalOutputContract::SingleFileReplacementV1,
    })
    .unwrap();
    let manifest = signed(
        &mut cache,
        publisher,
        &json,
        dataset::CODE_PROPOSAL_CONTENT_TYPE,
    );
    let source =
        dataset::verify_source(&manifest, &publisher.verifying_key(), &json, now()).unwrap();
    let Operation::Submit(submit) = &mut request.operation else {
        panic!("submit")
    };
    submit.publication.manifest_hex = hex::encode(manifest);
    submit.publication.dataset_json = json;
    submit.binding.dataset_manifest_id = hex::encode(source.manifest_id());
    submit.binding.model_fingerprint = code_capabilities(ModelProfile::Qwen600).model_fingerprint;
    submit.binding.row_indices = vec![0];
    submit.dataset_json = derive_submission(&source, &submit.binding).unwrap();
    submit.binding.dataset_sha256 = hex::encode(Sha256::digest(submit.dataset_json.as_bytes()));
    request
}

#[test]
fn code_capability_is_separate_exact_and_never_generic_qa_or_training() {
    for profile in [ModelProfile::Qwen600, ModelProfile::Qwen4bInstruct2507] {
        let caps = code_capabilities(profile);
        validate_capabilities(&caps).unwrap();
        for change in 0..9 {
            let mut invalid = caps.clone();
            match change {
                0 => invalid.code_proposal_v6 = false,
                1 => invalid.task_derivation_v1 = true,
                2 => invalid.document_inference_v2 = true,
                3 => invalid.derived_inference_v3 = true,
                4 => invalid.principle_inference_v4 = true,
                5 => invalid.successor_activation_v1 = true,
                6 => invalid.max_rows = 2,
                7 => invalid.model.adapter_files = Some(std::collections::BTreeMap::default()),
                _ => invalid.model.base_weights.sha256 = "a".repeat(64),
            }
            invalid.model_fingerprint =
                hex::encode(Sha256::digest(serde_json::to_vec(&invalid.model).unwrap()));
            assert!(
                validate_capabilities(&invalid).is_err(),
                "{profile:?}/{change}"
            );
        }
    }
    let mut legacy = capabilities();
    legacy.code_proposal_v6 = true;
    assert!(validate_capabilities(&legacy).is_err());
}

#[test]
fn both_agent_boundaries_pin_public_code_source_and_refuse_requester_overrides() {
    let root = tempfile::tempdir().unwrap();
    let publisher = SigningKey::from_bytes(&[45; 32]);
    let requester = SigningKey::from_bytes(&[46; 32]);
    let original = code_request(root.path(), &publisher, &requester);
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
    assert!(
        backend
            .validate(requester.verifying_key().as_bytes(), &original)
            .is_err()
    );
    let mutable = Arc::get_mut(&mut backend).unwrap();
    mutable.model_fingerprint = code_capabilities(ModelProfile::Qwen600).model_fingerprint;
    mutable.task_derivation_v1 = false;
    mutable.code_proposal_v6 = true;
    mutable.code_model_profile = Some(ModelProfile::Qwen600);
    backend
        .validate(requester.verifying_key().as_bytes(), &original)
        .unwrap();
    super::super::super::compute_remote::validate_request(&original, &requester).unwrap();
    for change in [
        "question", "source", "private", "profile", "history", "task",
    ] {
        let mut changed = original.clone();
        let Operation::Submit(submit) = &mut changed.operation else {
            panic!("submit")
        };
        let mut json: serde_json::Value = serde_json::from_str(&submit.dataset_json).unwrap();
        match change {
            "question" => json["inference"][0]["question"] = "A different request".into(),
            "source" => json["inference"][0]["context"] = "Private unapproved code".into(),
            "private" => json["visibility"] = "private".into(),
            "profile" => json["model_profile"] = "qwen3_4b_instruct_2507".into(),
            "history" => json["history"] = serde_json::json!(["private history"]),
            _ => {
                submit.binding.task = Some(rpc::PublicTask::AnswerPublicQuestionV1 {
                    question: "Override?".into(),
                });
            }
        }
        submit.dataset_json = json.to_string();
        submit.binding.dataset_sha256 = hex::encode(Sha256::digest(submit.dataset_json.as_bytes()));
        assert!(
            backend
                .validate(requester.verifying_key().as_bytes(), &changed)
                .is_err(),
            "{change}"
        );
        assert!(
            super::super::super::compute_remote::validate_request(&changed, &requester).is_err(),
            "{change}"
        );
    }
    let generic_root = tempfile::tempdir().unwrap();
    let mut generic = request(generic_root.path(), &publisher, &requester);
    let Operation::Submit(submit) = &mut generic.operation else {
        panic!("submit")
    };
    submit.binding.model_fingerprint = code_capabilities(ModelProfile::Qwen600).model_fingerprint;
    assert!(
        backend
            .validate(requester.verifying_key().as_bytes(), &generic)
            .is_err()
    );
    Arc::get_mut(&mut backend).unwrap().code_model_profile = Some(ModelProfile::Qwen4bInstruct2507);
    assert!(
        backend
            .validate(requester.verifying_key().as_bytes(), &original)
            .is_err()
    );
    assert!(!root.path().join("unused.sock").exists());
}
