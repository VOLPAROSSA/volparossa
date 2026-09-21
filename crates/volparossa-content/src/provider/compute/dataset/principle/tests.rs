use super::*;
use crate::provider::compute::dataset::{DOCUMENT_CONTENT_TYPE, verify_source};
use crate::{CacheLimits, ChunkStore, Metadata, Publication, Validity, publish};
use ed25519_dalek::SigningKey;
use serde_json::json;

const CONTEXT: &str = "An explicitly public principle fixture.";

fn signed(bytes: &str, mime: &str, signer: &SigningKey, expires: u64) -> Vec<u8> {
    let root = tempfile::tempdir().unwrap();
    let mut cache = ChunkStore::create(
        &root.path().join("cache"),
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 8,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    publish(
        &mut bytes.as_bytes(),
        Publication {
            metadata: Metadata {
                name: "public-principle".into(),
                revision: 1,
                content_type: mime.into(),
            },
            length: bytes.len() as u64,
            validity: Validity {
                created: 1000,
                expires,
            },
        },
        signer,
        &mut cache,
    )
    .unwrap()
    .encode()
}

fn dataset(source: &[u8]) -> PrincipleDataset {
    PrincipleDataset {
        version: 4,
        visibility: "public".into(),
        license: "CC0-1.0".into(),
        source_manifest_hex: hex::encode(source),
        inference: vec![DocumentQuestion {
            question: "Assess this public source using the signed framework.".into(),
            context: CONTEXT.into(),
            start: 0,
            end: CONTEXT.len() as u64,
        }],
        output_contract: PrincipleOutputContract::PrincipleAssessmentV1,
    }
}

#[test]
fn signed_principle_contract_is_retained_and_question_derivation_is_forbidden() {
    let signer = SigningKey::from_bytes(&[23; 32]);
    let source = signed(CONTEXT, "text/plain", &signer, 2000);
    let mut original = dataset(&source);
    for contract in [
        PrincipleOutputContract::PrincipleAssessmentV1,
        PrincipleOutputContract::PrincipleReviewV1,
    ] {
        original.output_contract = contract;
        let raw = serde_json::to_string(&original).unwrap();
        let manifest = signed(&raw, PRINCIPLE_CONTENT_TYPE, &signer, 1900);
        let verified = verify_source(&manifest, &signer.verifying_key(), &raw, 1100).unwrap();
        assert!(verified.is_principle() && verified.is_document() && !verified.is_derived());
        assert_eq!(verified.output_contract(), Some(contract));
        assert_eq!(verified.row_count(), 1);
        assert_eq!(verified.expires(), 1900);
        assert_eq!(verified.derive(&[0]).unwrap(), raw);
        validate_principle_json(&raw, 1).unwrap();
        assert!(
            verified
                .derive_question(&[0], &original.inference[0].question)
                .is_err()
        );
        for rows in [&[][..], &[1], &[0, 0]] {
            assert!(verified.derive(rows).is_err());
        }
        let changed = raw.replace("principle_", "different_");
        assert!(verify_source(&manifest, &signer.verifying_key(), &changed, 1100).is_err());
    }
}

#[test]
fn principle_reuses_original_publisher_type_expiry_and_source_range_bindings() {
    let signer = SigningKey::from_bytes(&[23; 32]);
    let other = SigningKey::from_bytes(&[24; 32]);
    for source in [
        signed(CONTEXT, "text/plain", &other, 2000),
        signed(CONTEXT, "application/octet-stream", &signer, 2000),
        signed(CONTEXT, "text/plain", &signer, 1800),
        signed("Short", "text/plain", &signer, 2000),
    ] {
        let raw = serde_json::to_string(&dataset(&source)).unwrap();
        let manifest = signed(&raw, PRINCIPLE_CONTENT_TYPE, &signer, 1900);
        assert!(verify_source(&manifest, &signer.verifying_key(), &raw, 1100).is_err());
    }
    let source = signed(CONTEXT, "text/plain", &signer, 2000);
    let raw = serde_json::to_string(&dataset(&source)).unwrap();
    let manifest = signed(&raw, PRINCIPLE_CONTENT_TYPE, &signer, 1900);
    assert!(verify_source(&manifest, &other.verifying_key(), &raw, 1100).is_err());
    assert!(verify_source(&manifest, &signer.verifying_key(), &raw, 1900).is_err());
    let wrong_type = signed(&raw, DOCUMENT_CONTENT_TYPE, &signer, 1900);
    assert!(verify_source(&wrong_type, &signer.verifying_key(), &raw, 1100).is_err());
}

#[test]
fn principle_admission_rejects_ambiguous_contract_private_training_and_extra_rows() {
    let signer = SigningKey::from_bytes(&[23; 32]);
    let source = signed(CONTEXT, "text/plain", &signer, 2000);
    let original = serde_json::to_value(dataset(&source)).unwrap();
    for (field, value) in [
        ("version", json!(2)),
        ("visibility", json!("private")),
        ("license", json!("unspecified")),
        ("output_contract", json!("arbitrary_schema")),
        ("output_contract", json!(null)),
        ("train", json!([])),
        ("heldout", json!([])),
        (
            "inference",
            json!([
                original["inference"][0].clone(),
                original["inference"][0].clone()
            ]),
        ),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        assert!(
            validate_principle_json(&changed.to_string(), 1).is_err(),
            "{field}"
        );
    }
    let mut changed = original.clone();
    changed["inference"][0]["end"] = json!(CONTEXT.len() - 1);
    assert!(validate_principle_json(&changed.to_string(), 1).is_err());
    let raw = original.to_string();
    let duplicate = raw.replacen("\"version\":4", "\"version\":4,\"version\":4", 1);
    assert!(validate_principle_json(&duplicate, 1).is_err());
    for expected_rows in [0, 2, 4] {
        assert!(validate_principle_json(&raw, expected_rows).is_err());
    }
}
