//! Signed source reuse controls only; synthetic token counts are not tokenizer/model evidence.

use std::os::unix::fs::PermissionsExt as _;

use volparossa_content::agent_artifact::{MODEL_ID, MODEL_REVISION};

use super::*;
use crate::compute::ModelProfile;

const TEXT: &str = "Public network notes.\nEvery route retains its original source.\n";

struct Prepared {
    root: tempfile::TempDir,
    input: Input,
    plan: Plan,
}

fn prepare(document: &str, question: &str) -> Prepared {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let input = Input {
        model_profile: ModelProfile::default(),
        version: 1,
        visibility: "public".into(),
        license: "CC0-1.0".into(),
        document: document.into(),
        question: question.into(),
        synthesis: false,
    };
    let mut offset = 0;
    let parts: Vec<_> = document
        .split_inclusive('\n')
        .map(|part| {
            let start = offset;
            offset += part.len();
            json!({"start":start,"end":offset,"prompt_tokens":64})
        })
        .collect();
    let plan: Plan = serde_json::from_value(json!({
        "version":1,"source_sha256":sha(document.as_bytes()),"source_bytes":document.len(),
        "question_sha256":sha(question.as_bytes()),"model_id":MODEL_ID,"model_revision":MODEL_REVISION,
        "tokenizer_sha256":"9ca9acddb6525a194ec8ac7a87f24fbba7232a9a15ffa1af0c1224fcd888e47c",
        "prompt_limit":192,"parts":parts
    })).unwrap();
    task::write_bytes(&root.path().join("source.txt"), document.as_bytes(), false).unwrap();
    save(root.path(), "planner-input.json", &input, false).unwrap();
    Prepared { root, input, plan }
}

fn peers() -> [VerifyingKey; 2] {
    [
        SigningKey::from_bytes(&[92; 32]).verifying_key(),
        SigningKey::from_bytes(&[93; 32]).verifying_key(),
    ]
}

fn publication(
    document: &str,
    key: &SigningKey,
    validity: Validity,
    name: &str,
    profile: &str,
    revision: u64,
) -> SignedManifest {
    let root = tempfile::tempdir().unwrap();
    let mut cache = ChunkStore::create(
        &root.path().join("native"),
        CacheLimits {
            max_bytes: 2 * 1024 * 1024,
            max_entries: 32,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    volparossa_content::publish(
        &mut document.as_bytes(),
        Publication {
            metadata: Metadata {
                name: name.into(),
                revision,
                content_type: profile.into(),
            },
            length: document.len() as u64,
            validity,
        },
        key,
        &mut cache,
    )
    .unwrap()
}

fn save_enrollment(prepared: &Prepared, mut enrolled: Enrollment) -> Enrollment {
    enrolled.scheduling = workflow::Scheduling::ReadyRowsV1;
    save(prepared.root.path(), "document.json", &enrolled, false).unwrap();
    enrolled
}

#[test]
fn different_leaf_questions_retain_one_exact_original_source_and_restore_normally() {
    let key = SigningKey::from_bytes(&[91; 32]);
    let at = now().unwrap() - 10;
    let (owner, cancelled) = watch::channel(false);
    let first = prepare(TEXT, "What is the networking rule?");
    let original = publish(
        first.root.path(),
        &first.input,
        &first.plan,
        &key,
        &peers(),
        at,
        600,
        &cancelled,
        true,
    )
    .unwrap();
    let first_enrollment = save_enrollment(&first, original);
    let source_bytes = read(
        &first.root.path().join("source.manifest"),
        MAX_MANIFEST_BYTES,
    )
    .unwrap();
    let source = SignedManifest::decode(&source_bytes).unwrap();
    let second = prepare(TEXT, "What must remain unchanged?");
    let reused = publish_with_source(
        second.root.path(),
        &second.input,
        &second.plan,
        &key,
        &peers(),
        at,
        600,
        &cancelled,
        true,
        &source,
    )
    .unwrap();
    let second_enrollment = save_enrollment(&second, reused);
    assert_eq!(
        first_enrollment.source_manifest_id,
        second_enrollment.source_manifest_id
    );
    assert_eq!(
        first_enrollment.selected_at_unix_seconds,
        second_enrollment.selected_at_unix_seconds
    );
    assert_eq!(
        first_enrollment.expires_at_unix_seconds,
        second_enrollment.expires_at_unix_seconds
    );
    assert_ne!(
        first_enrollment.packages[0].manifest_id,
        second_enrollment.packages[0].manifest_id
    );
    assert_eq!(
        source_bytes,
        read(
            &second.root.path().join("source.manifest"),
            MAX_MANIFEST_BYTES
        )
        .unwrap()
    );
    let mut questions = Vec::new();
    for prepared in [&first, &second] {
        let (enrollment, input, plan) = load(prepared.root.path()).unwrap();
        assert!(enrollment.synthesize);
        assert_eq!(enrollment.scheduling, workflow::Scheduling::ReadyRowsV1);
        for (index, package) in enrollment.packages.iter().enumerate() {
            let directory = prepared.root.path().join(format!("package-{index:04}"));
            let expected = expected(&directory, &enrollment, package, &input, &plan).unwrap();
            assert_eq!(expected.task, instruction(&input));
            let data: DocumentDataset = serde_json::from_slice(
                &read(&directory.join("dataset.json"), MAX_SAVED_BYTES).unwrap(),
            )
            .unwrap();
            assert_eq!(data.source_manifest_hex, hex::encode(&source_bytes));
            assert!(
                data.inference
                    .iter()
                    .all(|row| row.question == input.question)
            );
        }
        questions.push(input.question);
    }
    assert_ne!(questions[0], questions[1]);
    drop(owner);
}

#[test]
fn reused_source_rejects_changed_text_publisher_profile_revision_and_signature_before_writing() {
    let key = SigningKey::from_bytes(&[91; 32]);
    let at = now().unwrap() - 10;
    let validity = Validity {
        created: at,
        expires: at + 600,
    };
    let valid = publication(TEXT, &key, validity, "document-source", "text/plain", 1);
    let different_key = SigningKey::from_bytes(&[94; 32]);
    let mut corrupted = valid.encode();
    *corrupted.last_mut().unwrap() ^= 1;
    let candidates = [
        publication(
            "Different original text.\n",
            &key,
            validity,
            "document-source",
            "text/plain",
            1,
        ),
        publication(
            TEXT,
            &different_key,
            validity,
            "document-source",
            "text/plain",
            1,
        ),
        publication(TEXT, &key, validity, "another-source", "text/plain", 1),
        publication(
            TEXT,
            &key,
            validity,
            "document-source",
            "application/octet-stream",
            1,
        ),
        publication(TEXT, &key, validity, "document-source", "text/plain", 2),
        SignedManifest::decode(&corrupted).unwrap(),
    ];
    let (_owner, cancelled) = watch::channel(false);
    for original in candidates {
        let prepared = prepare(TEXT, "What does this public source say?");
        assert!(
            publish_with_source(
                prepared.root.path(),
                &prepared.input,
                &prepared.plan,
                &key,
                &peers(),
                at,
                600,
                &cancelled,
                true,
                &original
            )
            .is_err()
        );
        assert!(!prepared.root.path().join("publication-cache").exists());
        assert!(!prepared.root.path().join("source.manifest").exists());
    }
}

#[test]
fn shared_original_authority_cannot_be_shifted_renewed_or_used_after_expiry() {
    let key = SigningKey::from_bytes(&[91; 32]);
    let at = now().unwrap() - 10;
    let validity = Validity {
        created: at,
        expires: at + 600,
    };
    let source = publication(TEXT, &key, validity, "document-source", "text/plain", 1);
    let (_owner, cancelled) = watch::channel(false);
    for (changed_at, lifetime) in [(at + 1, 599), (at, 601), (at, 599)] {
        let prepared = prepare(TEXT, "Which source was selected?");
        assert!(
            publish_with_source(
                prepared.root.path(),
                &prepared.input,
                &prepared.plan,
                &key,
                &peers(),
                changed_at,
                lifetime,
                &cancelled,
                true,
                &source
            )
            .is_err()
        );
        assert!(!prepared.root.path().join("publication-cache").exists());
    }
    let expired = publication(
        TEXT,
        &key,
        Validity {
            created: 100,
            expires: 700,
        },
        "document-source",
        "text/plain",
        1,
    );
    let prepared = prepare(TEXT, "May expired authority start another leaf?");
    assert!(
        publish_with_source(
            prepared.root.path(),
            &prepared.input,
            &prepared.plan,
            &key,
            &peers(),
            100,
            600,
            &cancelled,
            true,
            &expired
        )
        .is_err()
    );
    assert!(!prepared.root.path().join("publication-cache").exists());
    // Existing document publication semantics remain unchanged for historical parser fixtures.
    assert!(
        publish(
            prepared.root.path(),
            &prepared.input,
            &prepared.plan,
            &key,
            &peers(),
            100,
            600,
            &cancelled,
            false
        )
        .is_ok()
    );
}

#[test]
fn shared_source_validation_covers_real_chunk_boundary_and_cancellation_still_stops_enrollment() {
    let key = SigningKey::from_bytes(&[91; 32]);
    let at = now().unwrap() - 10;
    let validity = Validity {
        created: at,
        expires: at + 600,
    };
    let document = "é".repeat(CHUNK_BYTES / 2 + 10);
    let mut input = Input {
        model_profile: ModelProfile::default(),
        version: 1,
        visibility: "public".into(),
        license: "CC0-1.0".into(),
        document: document.clone(),
        question: "What does this public text say?".into(),
        synthesis: false,
    };
    let source = publication(
        &document,
        &key,
        validity,
        "document-source",
        "text/plain",
        1,
    );
    validate_shared_source(&source, &input, &key, validity).unwrap();
    input.document.push('x');
    assert!(validate_shared_source(&source, &input, &key, validity).is_err());
    let source = publication(TEXT, &key, validity, "document-source", "text/plain", 1);
    let prepared = prepare(TEXT, "Will this cancelled leaf start?");
    let (_owner, cancelled) = watch::channel(true);
    assert!(
        publish_with_source(
            prepared.root.path(),
            &prepared.input,
            &prepared.plan,
            &key,
            &peers(),
            at,
            600,
            &cancelled,
            true,
            &source
        )
        .is_err()
    );
    assert!(!prepared.root.path().join("publication-cache").exists());
}
