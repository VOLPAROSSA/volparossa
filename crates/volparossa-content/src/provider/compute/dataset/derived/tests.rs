//! Synthetic public lineage fixtures exercise real native signatures, never model execution.

use super::*;
use crate::provider::compute::dataset::{DOCUMENT_CONTENT_TYPE, verify_source};
use crate::{CacheLimits, ChunkStore, Metadata, Publication, Validity, publish};
use ed25519_dalek::SigningKey;
use serde_json::json;

fn signed(bytes: &str, mime: &str, signer: &SigningKey, expires: u64) -> Vec<u8> {
    let root = tempfile::tempdir().unwrap();
    let mut store = ChunkStore::create(
        &root.path().join("cache"),
        CacheLimits {
            max_bytes: 2 * 1024 * 1024,
            max_entries: 8,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    publish(
        &mut bytes.as_bytes(),
        Publication {
            metadata: Metadata {
                name: "public-derived-test".into(),
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
        &mut store,
    )
    .unwrap()
    .encode()
}

fn dataset(source: &[u8]) -> DerivedDataset {
    let input = DerivedInput {
        text: "Één".into(),
        provider_key: hex::encode(SigningKey::from_bytes(&[26; 32]).verifying_key().as_bytes()),
        job_id: "1".repeat(32),
        report_sha256: "2".repeat(64),
        package_manifest_id: "3".repeat(64),
        model_fingerprint: "4".repeat(64),
        output_index: 1,
        parent_index: 0,
        source_start: 0,
        source_end: 8,
        piece_start: 0,
        piece_end: 2,
    };
    let mut second = input.clone();
    second.piece_start = 2;
    second.piece_end = 6;
    DerivedDataset {
        version: 3,
        visibility: "public".into(),
        license: "CC0-1.0".into(),
        source_manifest_hex: hex::encode(source),
        level: 1,
        claim_scope: DERIVED_CLAIM_SCOPE.into(),
        inference: vec![DerivedQuestion {
            question: "What do the public answers establish?".into(),
            context: "Één\n".into(),
            inputs: vec![input, second],
        }],
    }
}

#[test]
fn native_derived_authentication_and_singleton_subset_preserve_explicit_lineage() {
    let signer = SigningKey::from_bytes(&[25; 32]);
    let source = signed("Original public source text.", "text/plain", &signer, 2000);
    let mut original = dataset(&source);
    original.inference.push(original.inference[0].clone());
    let json = serde_json::to_string(&original).unwrap();
    let package = signed(&json, DERIVED_CONTENT_TYPE, &signer, 1900);
    let verified = verify_source(&package, &signer.verifying_key(), &json, 1100).unwrap();
    assert!(verified.is_document() && verified.is_derived());
    assert_eq!(verified.row_count(), 2);
    assert_eq!(verified.expires(), 1900);
    assert_eq!(verified.derive(&[0, 1]).unwrap(), json);
    let selected = verified
        .derive_question(&[1], "  A public replacement?  ")
        .unwrap();
    let actual: DerivedDataset = serde_json::from_str(&selected).unwrap();
    let mut expected = original.clone();
    expected.inference = vec![original.inference[1].clone()];
    expected.inference[0].question = "  A public replacement?  ".into();
    assert_eq!(actual, expected);
    assert!(validate_derived_json(&selected, 1).is_ok());
    assert!(validate_derived_json(&selected, 2).is_err());
    for rows in [&[][..], &[1, 1], &[1, 0], &[2]] {
        assert!(verified.derive(rows).is_err());
    }
    let value = serde_json::to_value(&actual).unwrap();
    for field in ["train", "heldout", "source_revision"] {
        assert!(value.get(field).is_none());
    }
    // Authenticated output assertions may differ from original text and overlap in coverage.
    // Neither these synthetic hashes nor the native publisher signature proves worker execution.
    assert_eq!(
        actual.inference[0].inputs[0].source_start,
        actual.inference[0].inputs[1].source_start
    );
    assert_ne!(actual.inference[0].context, "Original");
}

#[test]
fn native_original_authority_profile_expiry_and_ranges_remain_required() {
    let signer = SigningKey::from_bytes(&[25; 32]);
    let other = SigningKey::from_bytes(&[27; 32]);
    for source in [
        signed("Original public source text.", "text/plain", &other, 2000),
        signed(
            "Original public source text.",
            "application/octet-stream",
            &signer,
            2000,
        ),
        signed("Original public source text.", "text/plain", &signer, 1800),
        signed("short", "text/plain", &signer, 2000),
    ] {
        let json = serde_json::to_string(&dataset(&source)).unwrap();
        let package = signed(&json, DERIVED_CONTENT_TYPE, &signer, 1900);
        assert!(verify_source(&package, &signer.verifying_key(), &json, 1100).is_err());
    }
    let source = signed("Original public source text.", "text/plain", &signer, 2000);
    let json = serde_json::to_string(&dataset(&source)).unwrap();
    let package = signed(&json, DERIVED_CONTENT_TYPE, &signer, 1900);
    assert!(verify_source(&package, &other.verifying_key(), &json, 1100).is_err());
    assert!(verify_source(&package, &signer.verifying_key(), &json, 1900).is_err());
    assert!(
        verify_source(
            &package,
            &signer.verifying_key(),
            &(json.clone() + " "),
            1100
        )
        .is_err()
    );
    let mislabeled = signed(&json, DOCUMENT_CONTENT_TYPE, &signer, 1900);
    assert!(verify_source(&mislabeled, &signer.verifying_key(), &json, 1100).is_err());
}

#[test]
fn strict_derived_profile_rejects_changed_claims_context_identities_and_split_utf8() {
    let signer = SigningKey::from_bytes(&[25; 32]);
    let source = signed("Original public source text.", "text/plain", &signer, 2000);
    let original = serde_json::to_value(dataset(&source)).unwrap();
    for (field, value) in [
        ("version", json!(2)),
        ("visibility", json!("private")),
        ("license", json!("unspecified")),
        ("level", json!(0)),
        ("level", json!(17)),
        ("level", json!(1.0)),
        ("claim_scope", json!("portable_executor_attestation")),
        ("train", json!([])),
        (
            "source_manifest_hex",
            json!(hex::encode(&source).to_uppercase()),
        ),
        ("inference", json!([])),
    ] {
        let mut changed = original.clone();
        changed[field] = value;
        assert!(
            validate_derived_json(&changed.to_string(), 1).is_err(),
            "{field}"
        );
    }
    for (field, value) in [
        ("text", json!("Other parent output")),
        ("piece_start", json!(1)),
        ("piece_end", json!(1)),
        ("piece_end", json!(7)),
        ("piece_end", json!(2.0)),
        ("source_end", json!(0)),
        ("source_end", json!(MAX_DATASET_BYTES + 1)),
        ("provider_key", json!("0".repeat(64))),
        ("job_id", json!("A".repeat(32))),
        ("report_sha256", json!("2".repeat(63))),
        ("package_manifest_id", json!("0".repeat(64))),
        ("model_fingerprint", json!("0".repeat(64))),
        ("output_index", json!(65_536)),
        ("parent_index", json!(4_294_967_296_u64)),
        ("executor_signature", json!("not-a-supported-proof")),
    ] {
        let mut changed = original.clone();
        changed["inference"][0]["inputs"][0][field] = value;
        assert!(
            validate_derived_json(&changed.to_string(), 1).is_err(),
            "{field}"
        );
    }
    let mut changed = original.clone();
    changed["inference"][0]["context"] = json!("É\nén\n");
    assert!(validate_derived_json(&changed.to_string(), 1).is_err());
    let encoded = serde_json::to_string(&dataset(&source)).unwrap();
    let duplicate = encoded.replacen("\"version\":3", "\"version\":3,\"version\":3", 1);
    assert!(validate_derived_json(&duplicate, 1).is_err());
}
