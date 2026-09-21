//! Signed-source/synthetic-report fixtures; never evidence that a model or worker ran.

use std::os::unix::fs::PermissionsExt as _;

use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity};

use super::*;

#[allow(clippy::too_many_lines)] // One inert, source-bound baseline/candidate evidence fixture.
fn fixture() -> (tempfile::TempDir, Value, u64) {
    let temporary = tempfile::tempdir().unwrap();
    fs::set_permissions(temporary.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let base = temporary.path();
    for name in [
        "import",
        "import/adapter",
        "comparison",
        "comparison/baseline",
        "comparison/candidate",
    ] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(base.join(name))
            .unwrap();
    }
    let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let at = now().unwrap();
    let dataset = json!({"version":1,"visibility":"public","license":"GPL-3.0-only", "train":[],
        "heldout":[{"question":"Was this model executed?","context":"Pure parsing fixture.","answer":"No."}],
        "inference":[{"question":"What is this?","context":"Pure parsing fixture."}]}).to_string();
    let cache_root = tempfile::tempdir().unwrap();
    let mut cache = ChunkStore::create(
        &cache_root.path().join("cache"),
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 8,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let signed = volparossa_content::publish(
        &mut dataset.as_bytes(),
        Publication {
            metadata: Metadata {
                name: "quarantine-validation".into(),
                revision: 1,
                content_type: volparossa_content::provider::compute::dataset::CONTENT_TYPE.into(),
            },
            length: dataset.len() as u64,
            validity: Validity {
                created: at - 60,
                expires: at + 1200,
            },
        },
        &key,
        &mut cache,
    )
    .unwrap();
    let manifest = signed.encode();
    let verified = signed.verify(&key.verifying_key(), at).unwrap();
    let source = Source {
        publisher_key: hex::encode(key.verifying_key().as_bytes()),
        name: "quarantine-validation".into(),
        min_revision: Some(1),
        manifest_id: Some(hex::encode(verified.manifest_id())),
    };
    let root = base.join("comparison");
    write_new(&root.join("dataset.json"), dataset.as_bytes()).unwrap();
    write_new(&root.join("dataset.manifest"), &manifest).unwrap();
    write_json(
        &root.join("provenance.json"),
        &json!({"synthetic_fixture":true}),
    )
    .unwrap();
    for (name, _) in ADAPTER_FILES {
        write_new(
            &base.join("import/adapter").join(name),
            b"opaque parser fixture, not executable weights",
        )
        .unwrap();
    }
    for name in [
        "adapter.bundle",
        "adapter.manifest",
        "dataset.json",
        "dataset.manifest",
        "provenance.json",
    ] {
        write_new(
            &base.join("import").join(name),
            b"opaque original import binding fixture",
        )
        .unwrap();
    }
    let selection = json!({"version":1,"validation_source":source,"validation_sha256":identity(dataset.as_bytes()),
        "validation_manifest":identity(&manifest),"baseline_origin":{"kind":"pinned_base"},"baseline_adapter":null,
        "baseline_files":null,"candidate_adapter":base.join("import/adapter"),
        "candidate_files":adapter_files(&base.join("import/adapter")).unwrap(),
        "import_proof":{"synthetic_fixture":true,"expires_unix_seconds":at+1200},
        "expires":at+1200,"max_seconds":10,"threads":2,"policy":super::super::POLICY,"scope":super::super::SCOPE});
    write_json(&root.join("selection.json"), &selection).unwrap();
    let mut report = json!({"version":1,"kind":"result","id":"cd".repeat(16),"status":"ok","mode":"infer","device":"cpu",
        "threads":2,"updates_completed":0,"artifacts":[],"elapsed_ms":5,
        "model":{"id":MODEL_ID,"revision":MODEL_REVISION,"files":{"model.safetensors":{"sha256":hex::encode(BASE_MODEL_SHA256),"bytes":269_060_552}}},
        "dataset":{"sha256":identity(dataset.as_bytes()).sha256,"bytes":dataset.len(),"training_examples":0},
        "baseline_evaluation":{"loss":0.4,"target_tokens":8}});
    write_json(&root.join("baseline/report.json"), &report).unwrap();
    report["supervisor"] = json!({"deadline_seconds":10,"child_reaped":true,"network_access":false,"spare_capacity":true});
    let stage = Stage {
        version: 1,
        started_at: at - 1,
        completed_at: at,
        deadline: at + 9,
        report,
    };
    write_json(&root.join("baseline-report.json"), &stage).unwrap();
    checked_stage(&root, &selection, "baseline").unwrap();
    (temporary, selection, at)
}

#[test]
fn only_reaped_candidate_adapter_failures_authorize_quarantine() {
    let codes = [
        "INVALID_ADAPTER_WEIGHTS",
        "INVALID_ADAPTER_HEADER",
        "INVALID_ADAPTER_METADATA",
        "UNSUPPORTED_ADAPTER_TENSOR_KEYS",
        "UNSUPPORTED_ADAPTER_TENSOR_FORMAT",
        "INVALID_ADAPTER_TENSOR_OFFSETS",
        "INVALID_ADAPTER_TENSOR_LAYOUT",
        "NONFINITE_ADAPTER_WEIGHTS",
        "UNSUPPORTED_ADAPTER_CONFIG",
        "INVALID_ADAPTER_README",
    ];
    for code in codes {
        let error = crate::compute::supervise::test_worker_failure(code);
        let (request, _) = fault("candidate", &error).unwrap();
        assert_eq!(request, "ab".repeat(16));
        assert!(fault("baseline", &error).is_none());
        assert!(fault("unknown", &error).is_none());
        assert!(fault("candidate", &anyhow::anyhow!(error.to_string())).is_none());
    }
    for code in [
        "JOB_MEMORY_EXHAUSTED",
        "BACKEND_EXECUTION_FAILED",
        "JOB_INPUT_NOT_FOUND",
        "JOB_PATH_PERMISSION_DENIED",
        "UNKNOWN_FIXED_FAILURE",
    ] {
        assert!(
            fault(
                "candidate",
                &crate::compute::supervise::test_worker_failure(code)
            )
            .is_none()
        );
    }
    for code in [
        "compute_deadline",
        "compute_owner_busy",
        "compute_runtime_busy",
        "source_unavailable",
        "peer_import_deferred",
    ] {
        assert!(fault("candidate", &anyhow::anyhow!(code)).is_none());
    }
}

#[test]
fn immutable_local_evidence_reopens_and_rejects_hash_scope_or_source_changes() {
    let (temporary, selection, at) = fixture();
    let root = temporary.path().join("comparison");
    let error = crate::compute::supervise::test_worker_failure("NONFINITE_ADAPTER_WEIGHTS");
    assert!(record_failure(&root, &selection, "candidate", at, at + 10, &error).unwrap());
    let saved = verify(&root).unwrap();
    assert_eq!(saved.request_id, "ab".repeat(16));
    assert_eq!(saved.code, Code::NonfiniteAdapterWeights);
    assert!(record_failure(&root, &selection, "candidate", at, at + 10, &error).is_err());
    let path = root.join(FILE);
    let original = read_file(&path, 256 * 1024).unwrap();
    for (field, value) in [
        ("scope", json!("network-wide-publisher-ban")),
        ("stage", json!("baseline")),
        ("code", json!("JOB_MEMORY_EXHAUSTED")),
        ("request_id", json!("cd".repeat(16))),
        ("source_expires", json!(at + 2400)),
        ("deadline", json!(at + 601)),
        (
            "baseline_origin",
            json!({"kind":"different_accepted_model"}),
        ),
        ("validation_manifest_id", json!("00".repeat(32))),
    ] {
        let mut changed: Value = serde_json::from_slice(&original).unwrap();
        changed[field] = value;
        fs::write(&path, serde_json::to_vec(&changed).unwrap()).unwrap();
        assert!(verify(&root).is_err(), "accepted changed {field}");
    }
    fs::write(&path, &original).unwrap();
    assert_eq!(verify(&root).unwrap(), saved);
    let weights = temporary
        .path()
        .join("import/adapter/adapter_model.safetensors");
    let before = fs::read(&weights).unwrap();
    fs::write(&weights, b"changed artifact").unwrap();
    assert!(verify(&root).is_err());
    fs::write(&weights, before).unwrap();
    assert_eq!(verify(&root).unwrap(), saved);
    write_json(&root.join("decision.json"), &json!({"approved":true})).unwrap();
    assert!(verify(&root).is_err());
}

#[test]
fn baseline_or_operational_failure_never_creates_artifact_evidence() {
    let (temporary, selection, at) = fixture();
    let root = temporary.path().join("comparison");
    let bad = crate::compute::supervise::test_worker_failure("NONFINITE_ADAPTER_WEIGHTS");
    assert!(!record_failure(&root, &selection, "baseline", at, at + 10, &bad).unwrap());
    let resource = crate::compute::supervise::test_worker_failure("JOB_MEMORY_EXHAUSTED");
    assert!(!record_failure(&root, &selection, "candidate", at, at + 10, &resource).unwrap());
    assert!(!root.join(FILE).exists());
    let candidate = temporary
        .path()
        .join("import/adapter/adapter_model.safetensors");
    fs::write(candidate, b"different from selected original").unwrap();
    assert!(record_failure(&root, &selection, "candidate", at, at + 10, &bad).is_err());
    assert!(!root.join(FILE).exists());
}
