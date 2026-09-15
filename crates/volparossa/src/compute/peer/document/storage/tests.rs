use super::*;
use std::os::unix::fs::PermissionsExt as _;
use volparossa_content::agent_artifact::{MODEL_ID, MODEL_REVISION};

struct Fixture {
    root: tempfile::TempDir,
    signer: SigningKey,
    input: Input,
    plan: Plan,
    enrollment: Enrollment,
}

fn limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 64 * 1024 * 1024,
        max_entries: 65_536,
        min_free_bytes: 64 * 1024 * 1024,
    }
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let input = Input {
        version: 1,
        synthesis: false,
        visibility: "public".into(),
        license: "CC0-1.0".into(),
        document: "één\ntwo\nthree\nfour\nfive\n".into(),
        question: "What does the public text say?".into(),
    };
    let mut offset = 0;
    let parts: Vec<_> = input
        .document
        .split_inclusive('\n')
        .map(|text| {
            let start = offset;
            offset += text.len();
            // Parser fixture only: this count is not actual tokenizer or model evidence.
            json!({"start":start,"end":offset,"prompt_tokens":80})
        })
        .collect();
    let plan: Plan = serde_json::from_value(json!({"version":1,
        "source_sha256":sha(input.document.as_bytes()),"source_bytes":input.document.len(),
        "question_sha256":sha(input.question.as_bytes()),"model_id":MODEL_ID,"model_revision":MODEL_REVISION,
        "tokenizer_sha256":"9ca9acddb6525a194ec8ac7a87f24fbba7232a9a15ffa1af0c1224fcd888e47c",
        "prompt_limit":192,"parts":parts})).unwrap();
    task::write_bytes(
        &root.path().join("source.txt"),
        input.document.as_bytes(),
        false,
    )
    .unwrap();
    save(root.path(), "planner-input.json", &input, false).unwrap();
    let signer = SigningKey::from_bytes(&[23; 32]);
    let providers = [
        SigningKey::from_bytes(&[24; 32]).verifying_key(),
        SigningKey::from_bytes(&[25; 32]).verifying_key(),
    ];
    let (_owner, cancelled) = watch::channel(false);
    let enrollment = publish(
        root.path(),
        &input,
        &plan,
        &signer,
        &providers,
        now().unwrap() - 1000,
        600,
        &cancelled,
        false,
    )
    .unwrap();
    save(root.path(), "document.json", &enrollment, false).unwrap();
    Fixture {
        root,
        signer,
        input,
        plan,
        enrollment,
    }
}

#[test]
fn native_document_roundtrip_covers_every_part_and_preserves_original_expired_identity() {
    let fixture = fixture();
    let root = fixture.root.path();
    let (enrollment, input, plan) = load(root).unwrap();
    assert_eq!(enrollment.packages.len(), 2);
    assert_eq!(enrollment.packages[0].rows, 4);
    assert_eq!(enrollment.packages[1].rows, 1);
    assert_eq!(
        enrollment.source_manifest_id,
        fixture.enrollment.source_manifest_id
    );
    assert_eq!(
        enrollment.expires_at_unix_seconds,
        fixture.enrollment.expires_at_unix_seconds
    );
    let original = read(&root.join("source.manifest"), MAX_MANIFEST_BYTES).unwrap();
    let signed = SignedManifest::decode(&original).unwrap();
    assert!(
        signed
            .verify(&fixture.signer.verifying_key(), now().unwrap())
            .is_err()
    );
    let verified = signed
        .verify(
            &fixture.signer.verifying_key(),
            enrollment.selected_at_unix_seconds,
        )
        .unwrap();
    let mut cache = ChunkStore::open(&root.join("publication-cache"), limits()).unwrap();
    let mut body = Vec::new();
    volparossa_content::reassemble(
        &verified,
        &mut [&mut cache],
        enrollment.selected_at_unix_seconds,
        &mut body,
    )
    .unwrap();
    assert_eq!(body, input.document.as_bytes());
    for (index, package) in enrollment.packages.iter().enumerate() {
        let directory = root.join(format!("package-{index:04}"));
        let expected = expected(&directory, &enrollment, package, &input, &plan).unwrap();
        assert_eq!(expected.rows, package.rows);
        assert_eq!(expected.manifest_id, package.manifest_id);
        let manifest = verified_manifest(
            &read(&directory.join("dataset.manifest"), MAX_MANIFEST_BYTES).unwrap(),
            &enrollment,
        )
        .unwrap();
        body.clear();
        volparossa_content::reassemble(
            &manifest,
            &mut [&mut cache],
            enrollment.selected_at_unix_seconds,
            &mut body,
        )
        .unwrap();
        assert_eq!(
            body,
            read(&directory.join("dataset.json"), rpc::MAX_DATASET_BYTES).unwrap()
        );
        assert!(!present(&directory.join("work")).unwrap());
    }
    drop(cache);
    let providers = enrollment
        .provider_keys
        .iter()
        .map(|key| parse_key(key).unwrap())
        .collect::<Vec<_>>();
    let (_owner, cancelled) = watch::channel(false);
    assert!(
        publish(
            root,
            &input,
            &plan,
            &fixture.signer,
            &providers,
            enrollment.selected_at_unix_seconds,
            600,
            &cancelled,
            false
        )
        .is_err()
    );
    assert_eq!(
        read(&root.join("source.manifest"), MAX_MANIFEST_BYTES).unwrap(),
        original
    );
}

#[test]
fn changed_original_gap_and_validly_signed_false_excerpt_are_rejected_before_dispatch() {
    let mut fixture = fixture();
    let root = fixture.root.path();
    task::write_bytes(&root.join("source.txt"), b"changed original", true).unwrap();
    assert!(load(root).is_err());
    task::write_bytes(
        &root.join("source.txt"),
        fixture.input.document.as_bytes(),
        true,
    )
    .unwrap();
    fixture.enrollment.packages[1].first_part = 3;
    save(root, "document.json", &fixture.enrollment, true).unwrap();
    assert!(load(root).is_err());
    fixture.enrollment.packages[1].first_part = 4;
    save(root, "document.json", &fixture.enrollment, true).unwrap();
    let directory = root.join("package-0000");
    let mut dataset: DocumentDataset = serde_json::from_slice(
        &read(&directory.join("dataset.json"), rpc::MAX_DATASET_BYTES).unwrap(),
    )
    .unwrap();
    dataset.inference[0].context = "x".repeat(dataset.inference[0].context.len());
    let bytes = serde_json::to_vec(&dataset).unwrap();
    let mut cache = ChunkStore::open(&root.join("publication-cache"), limits()).unwrap();
    let signed = publish_object(
        &bytes,
        "document-package-0000".into(),
        DOCUMENT_CONTENT_TYPE,
        Validity {
            created: fixture.enrollment.selected_at_unix_seconds,
            expires: fixture.enrollment.expires_at_unix_seconds,
        },
        &fixture.signer,
        &mut cache,
    )
    .unwrap();
    drop(cache);
    let manifest = signed.encode();
    assert!(
        verify_source(
            &manifest,
            &fixture.signer.verifying_key(),
            std::str::from_utf8(&bytes).unwrap(),
            fixture.enrollment.selected_at_unix_seconds
        )
        .is_ok()
    );
    task::write_bytes(&directory.join("dataset.json"), &bytes, true).unwrap();
    task::write_bytes(&directory.join("dataset.manifest"), &manifest, true).unwrap();
    fixture.enrollment.packages[0].manifest_id = sha(&manifest);
    fixture.enrollment.packages[0].dataset_sha256 = sha(&bytes);
    // Unlike the remote signed assertion check above, the coordinator has the original.
    assert!(
        expected(
            &directory,
            &fixture.enrollment,
            &fixture.enrollment.packages[0],
            &fixture.input,
            &fixture.plan
        )
        .is_err()
    );
}

#[test]
fn ordered_join_requires_exact_task_source_rows_and_non_null_original_report_hashes() {
    let fixture = fixture();
    let package = &fixture.enrollment.packages[1];
    // Synthetic already-validated snapshot shape; not remote execution or ML evidence.
    let snapshot = json!({"dataset_manifest_id":package.manifest_id,"task":instruction(&fixture.input),
        "complete":true,"outputs":[{"sample_index":0,"text":"fixture answer",
        "provider_key":fixture.enrollment.provider_keys[0],"job_id":"01".repeat(16),"report_sha256":"02".repeat(32)}]});
    let mut answers = Vec::new();
    join_answers(
        &snapshot,
        package,
        &fixture.input,
        &fixture.plan,
        &mut answers,
    )
    .unwrap();
    assert_eq!(answers[0]["source_part"], 4);
    assert_eq!(answers[0]["start"], fixture.plan.parts[4].start);
    assert_eq!(answers[0]["context_sha256"], sha(b"five\n"));
    assert_eq!(
        answers[0]["report_sha256"],
        snapshot["outputs"][0]["report_sha256"]
    );
    for (field, value) in [
        ("task", json!({"kind":"summarize_contexts_v1"})),
        ("dataset_manifest_id", json!("ff".repeat(32))),
        ("outputs", json!([])),
    ] {
        let mut changed = snapshot.clone();
        changed[field] = value;
        assert!(
            join_answers(
                &changed,
                package,
                &fixture.input,
                &fixture.plan,
                &mut Vec::new()
            )
            .is_err()
        );
    }
    let mut missing_hash = snapshot;
    missing_hash["outputs"][0]["report_sha256"] = Value::Null;
    assert!(
        join_answers(
            &missing_hash,
            package,
            &fixture.input,
            &fixture.plan,
            &mut Vec::new()
        )
        .is_err()
    );
}
