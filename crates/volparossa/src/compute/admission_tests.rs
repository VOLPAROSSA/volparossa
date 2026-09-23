//! Pure admission regression: native signed source, no tokenizer/backend or model execution.

use super::*;
use serde_json::json;
use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity, publish};

fn source_manifest() -> String {
    let root = tempfile::tempdir().unwrap();
    let mut cache = ChunkStore::create(
        &root.path().join("cache"),
        CacheLimits {
            max_bytes: 4096,
            max_entries: 8,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let content = "An explicitly public source.";
    let signer = ed25519_dalek::SigningKey::from_bytes(&[71; 32]);
    hex::encode(
        publish(
            &mut content.as_bytes(),
            Publication {
                metadata: Metadata {
                    name: "admission-fixture".into(),
                    revision: 1,
                    content_type: "text/plain".into(),
                },
                length: content.len() as u64,
                validity: Validity {
                    created: 1000,
                    expires: 2000,
                },
            },
            &signer,
            &mut cache,
        )
        .unwrap()
        .encode(),
    )
}

fn derived() -> Value {
    json!({"version":3,"visibility":"public","license":"CC0-1.0",
        "source_manifest_hex":source_manifest(),"level":1,
        "claim_scope":volparossa_content::provider::compute::dataset::DERIVED_CLAIM_SCOPE,
        "inference":[{"question":"What do the public answers say?","context":"Public answer.\n",
            "inputs":[{"text":"Public answer.",
                "provider_key":hex::encode(ed25519_dalek::SigningKey::from_bytes(&[72;32]).verifying_key().as_bytes()),
                "job_id":"1".repeat(32),"report_sha256":"2".repeat(64),
                "package_manifest_id":"3".repeat(64),"model_fingerprint":"4".repeat(64),
                "output_index":0,"parent_index":0,"source_start":0,"source_end":8,
                "piece_start":0,"piece_end":15}]}]})
}

#[test]
fn worker_admission_accepts_strict_derived_inference_but_never_derived_training() {
    let mut data = derived();
    for rows in 1..=4 {
        let bytes = serde_json::to_vec(&data).unwrap();
        assert!(
            validate_dataset(Mode::Infer, false, &bytes).is_ok(),
            "{rows} rows"
        );
        assert!(validate_dataset(Mode::Infer, true, &bytes).is_ok());
        assert_eq!(
            validate_dataset(Mode::Train, false, &bytes)
                .unwrap_err()
                .to_string(),
            "compute_document_training_not_supported"
        );
        assert!(validate_dataset(Mode::PlanDocument, false, &bytes).is_err());
        let row = data["inference"][0].clone();
        data["inference"].as_array_mut().unwrap().push(row);
    }
    assert!(validate_dataset(Mode::Infer, false, &serde_json::to_vec(&data).unwrap()).is_err());
}

#[test]
fn derived_preworker_gate_keeps_private_unknown_and_altered_profiles_out() {
    let original = derived();
    for (pointer, value) in [
        ("/visibility", json!("private")),
        ("/version", json!(4)),
        ("/level", json!(0)),
        ("/claim_scope", json!("portable_execution_attestation")),
        ("/inference/0/context", json!("Replaced context")),
        ("/inference/0/inputs/0/piece_end", json!(10000)),
        ("/source_manifest_hex", json!("00")),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            validate_dataset(Mode::Infer, false, &serde_json::to_vec(&changed).unwrap()).is_err(),
            "{pointer}"
        );
    }
    let mut training = original;
    training["train"] = json!([]);
    assert!(validate_dataset(Mode::Infer, false, &serde_json::to_vec(&training).unwrap()).is_err());
}

#[test]
fn original_document_and_repository_admission_profiles_stay_distinct() {
    let document = json!({"version":2,"visibility":"public","license":"CC0-1.0",
        "source_manifest_hex":source_manifest(),"inference":[{
            "question":"What is public?","context":"An explicitly public source.","start":0,"end":28}]});
    let bytes = serde_json::to_vec(&document).unwrap();
    assert!(validate_dataset(Mode::Infer, false, &bytes).is_ok());
    assert!(validate_dataset(Mode::Train, false, &bytes).is_err());
    let repository = json!({"version":1,"visibility":"public","license":"GPL-3.0-only",
        "source_revision":"a".repeat(40)});
    let bytes = serde_json::to_vec(&repository).unwrap();
    // This pre-worker v1 gate is unchanged; the worker still checks its full Q/A schema.
    assert!(validate_dataset(Mode::Train, false, &bytes).is_ok());
    assert!(validate_dataset(Mode::Infer, false, &bytes).is_ok());
}

#[test]
fn principle_input_requires_explicit_fixed_contract_inference_profile() {
    let mut document = json!({"version":4,"visibility":"public","license":"CC0-1.0",
        "source_manifest_hex":source_manifest(),"output_contract":"principle_assessment_v1",
        "inference":[{"question":"Assess this source.","context":"An explicitly public source.","start":0,"end":28}]});
    for contract in ["principle_assessment_v1", "principle_review_v1"] {
        document["output_contract"] = contract.into();
        let bytes = serde_json::to_vec(&document).unwrap();
        assert!(
            validate_profile_dataset(Mode::Infer, false, &bytes, ModelProfile::default()).is_err()
        );
        for profile in [ModelProfile::Smol360, ModelProfile::Smol1700] {
            assert!(validate_profile_dataset(Mode::Infer, false, &bytes, profile).is_ok());
            assert!(validate_profile_dataset(Mode::Train, false, &bytes, profile).is_err());
            assert!(validate_profile_dataset(Mode::Infer, true, &bytes, profile).is_err());
            assert!(validate_profile_dataset(Mode::PrivateInfer, false, &bytes, profile).is_err());
            for (field, value) in [
                ("output_contract", json!("arbitrary_schema")),
                ("visibility", json!("private")),
                ("version", json!(2)),
                ("model_profile", json!("smollm2-1.7b-v1")),
                ("schema", json!({"type":"object"})),
            ] {
                let mut changed = document.clone();
                changed[field] = value;
                assert!(
                    validate_profile_dataset(
                        Mode::Infer,
                        false,
                        &serde_json::to_vec(&changed).unwrap(),
                        profile
                    )
                    .is_err(),
                    "{contract}: {profile}: {field}"
                );
            }
        }
    }
}

#[test]
fn grounded_inference_admission_and_report_bind_original_source_without_training_fallback() {
    use sha2::{Digest as _, Sha256};
    let mut dataset = derived();
    dataset["version"] = 5.into();
    dataset["model_profile"] = "smollm2-360m-v1".into();
    dataset["original_source"] = "An explicitly public source.".into();
    let bytes = serde_json::to_vec(&dataset).unwrap();
    assert!(validate_profile_dataset(Mode::Infer, false, &bytes, ModelProfile::Smol360).is_ok());
    for (mode, adapter, profile) in [
        (Mode::Train, false, ModelProfile::Smol360),
        (Mode::Infer, true, ModelProfile::Smol360),
        (Mode::Infer, false, ModelProfile::default()),
    ] {
        assert!(validate_profile_dataset(mode, adapter, &bytes, profile).is_err());
    }
    let source = dataset["original_source"].as_str().unwrap();
    // Only this report's source-binding seam is exercised, not model execution.
    let report = json!({"dataset":{"sha256":hex::encode(Sha256::digest(&bytes)),"version":5,
        "original_source_sha256":hex::encode(Sha256::digest(source.as_bytes())),"original_source_bytes":source.len()},"outputs":[]});
    inference_output::check_dataset_contract(&report, &bytes).unwrap();
    for (field, bad) in [
        ("version", json!(3)),
        ("original_source_sha256", json!("0".repeat(64))),
        ("original_source_bytes", json!(1)),
    ] {
        let mut changed = report.clone();
        changed["dataset"][field] = bad;
        assert!(inference_output::check_dataset_contract(&changed, &bytes).is_err());
    }
}
