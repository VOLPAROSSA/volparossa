//! Synthetic lineage with real signatures and both production agent admission boundaries.

use super::*;

fn signed(
    cache: &mut ChunkStore,
    publisher: &SigningKey,
    bytes: &str,
    mime: &str,
    expires: u64,
) -> Vec<u8> {
    publish(
        &mut bytes.as_bytes(),
        Publication {
            metadata: Metadata {
                name: "public-synthesis-fixture".into(),
                revision: 1,
                content_type: mime.into(),
            },
            length: bytes.len() as u64,
            validity: Validity {
                created: now() - 1,
                expires,
            },
        },
        publisher,
        cache,
    )
    .unwrap()
    .encode()
}

fn derived_request(root: &Path, publisher: &SigningKey, requester: &SigningKey) -> Request {
    let mut request = request(root, publisher, requester);
    let mut cache = ChunkStore::create(
        &root.join("derived-cache"),
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 8,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let expires = now() + 500;
    let original = signed(
        &mut cache,
        publisher,
        "Original public source.",
        "text/plain",
        expires,
    );
    let dataset = dataset::DerivedDataset {
        version: 3,
        visibility: "public".into(),
        license: "GPL-3.0-only".into(),
        source_manifest_hex: hex::encode(original),
        level: 1,
        claim_scope: dataset::DERIVED_CLAIM_SCOPE.into(),
        inference: vec![dataset::DerivedQuestion {
            question: "What does the public intermediate answer say?".into(),
            context: "A synthetic parent answer.\n".into(),
            inputs: vec![dataset::DerivedInput {
                text: "A synthetic parent answer.".into(),
                provider_key: hex::encode(requester.verifying_key().as_bytes()),
                job_id: "1".repeat(32),
                report_sha256: "2".repeat(64),
                package_manifest_id: "3".repeat(64),
                model_fingerprint: capabilities().model_fingerprint,
                output_index: 0,
                parent_index: 0,
                source_start: 0,
                source_end: 23,
                piece_start: 0,
                piece_end: 27,
            }],
        }],
    };
    let json = serde_json::to_string(&dataset).unwrap();
    let manifest = signed(
        &mut cache,
        publisher,
        &json,
        dataset::DERIVED_CONTENT_TYPE,
        expires,
    );
    let source =
        dataset::verify_source(&manifest, &publisher.verifying_key(), &json, now()).unwrap();
    let Operation::Submit(submit) = &mut request.operation else {
        panic!("submit")
    };
    submit.publication.manifest_hex = hex::encode(manifest);
    submit.publication.dataset_json = json;
    submit.binding.dataset_manifest_id = hex::encode(source.manifest_id());
    submit.binding.row_indices = vec![0];
    submit.binding.task = Some(rpc::PublicTask::AnswerPublicQuestionV1 {
        question: "A different explicitly public requester question?".into(),
    });
    submit.dataset_json = derive_submission(&source, &submit.binding).unwrap();
    submit.binding.dataset_sha256 = hex::encode(Sha256::digest(submit.dataset_json.as_bytes()));
    request
}

#[tokio::test]
async fn derived_admission_requires_v3_and_exact_signed_parent_context_on_both_boundaries() {
    let root = tempfile::tempdir().unwrap();
    let publisher = SigningKey::from_bytes(&[45; 32]);
    let requester = SigningKey::from_bytes(&[46; 32]);
    let original = derived_request(root.path(), &publisher, &requester);
    let service = Arc::new(Mutex::new(None));
    let registry = Arc::new(Mutex::new(PublicationRegistry::new()));
    let mut backend = attachment(
        BrokerSocket {
            path: root.path().join("never-used.sock"),
            device: 0,
            inode: 0,
            uid: nix::unistd::geteuid().as_raw(),
        },
        &service,
        &registry,
        &publisher,
    );
    // v2 support never silently implies support for model-generated inputs.
    Arc::get_mut(&mut backend).unwrap().document_inference_v2 = true;
    assert!(
        backend
            .validate(requester.verifying_key().as_bytes(), &original)
            .is_err()
    );
    let mutable = Arc::get_mut(&mut backend).unwrap();
    mutable.document_inference_v2 = false;
    mutable.derived_inference_v3 = true;
    backend
        .validate(requester.verifying_key().as_bytes(), &original)
        .unwrap();
    super::super::super::compute_remote::validate_request(&original, &requester).unwrap();
    for field in ["context", "report_sha256"] {
        let mut changed = original.clone();
        let Operation::Submit(submit) = &mut changed.operation else {
            panic!("submit")
        };
        let mut value: serde_json::Value = serde_json::from_str(&submit.dataset_json).unwrap();
        if field == "context" {
            value["inference"][0][field] = "Unpublished synthesis context".into();
        } else {
            value["inference"][0]["inputs"][0][field] = "9".repeat(64).into();
        }
        submit.dataset_json = value.to_string();
        submit.binding.dataset_sha256 = hex::encode(Sha256::digest(submit.dataset_json.as_bytes()));
        assert!(
            backend
                .validate(requester.verifying_key().as_bytes(), &changed)
                .is_err()
        );
        assert!(
            super::super::super::compute_remote::validate_request(&changed, &requester).is_err()
        );
    }
    assert!(!root.path().join("never-used.sock").exists());
}
