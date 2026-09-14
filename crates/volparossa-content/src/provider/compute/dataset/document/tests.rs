use super::*;
use crate::provider::compute::dataset::{CONTENT_TYPE, verify_source};
use crate::{CacheLimits, ChunkStore, Metadata, Publication, Validity, publish};
use ed25519_dalek::SigningKey;
use serde_json::json;

const FIRST: &str = "Één openbaar fragment.";
const SECOND: &str = "A second public context, unchanged.";

fn source_text() -> String {
    format!("{FIRST}\n{SECOND}")
}

fn signed(bytes: &str, content_type: &str, signer: &SigningKey, expires: u64) -> Vec<u8> {
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
                name: "public-document".into(),
                revision: 1,
                content_type: content_type.into(),
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

fn document(source: &[u8]) -> DocumentDataset {
    DocumentDataset {
        version: 2,
        visibility: "public".into(),
        license: "CC-BY-4.0".into(),
        source_manifest_hex: hex::encode(source),
        inference: vec![
            DocumentQuestion {
                question: "Summarize the provided public context.".into(),
                context: FIRST.into(),
                start: 0,
                end: FIRST.len() as u64,
            },
            DocumentQuestion {
                question: "Summarize the provided public context.".into(),
                context: SECOND.into(),
                start: FIRST.len() as u64 + 1,
                end: source_text().len() as u64,
            },
        ],
    }
}

fn verify_document(document: &DocumentDataset, signer: &SigningKey) -> bool {
    let json = serde_json::to_string(document).unwrap();
    let package = signed(&json, DOCUMENT_CONTENT_TYPE, signer, 1900);
    verify_source(&package, &signer.verifying_key(), &json, 1100).is_ok()
}

#[test]
fn signed_document_derivation_preserves_source_byte_ranges_without_training_fields() {
    let signer = SigningKey::from_bytes(&[23; 32]);
    let source = signed(&source_text(), "text/plain", &signer, 2000);
    let mut original = document(&source);
    for license in ["GPL-3.0-only", "CC0-1.0", "CC-BY-4.0", "CC-BY-SA-4.0"] {
        original.license = license.into();
        let json = serde_json::to_string(&original).unwrap();
        let package = signed(&json, DOCUMENT_CONTENT_TYPE, &signer, 1900);
        let verified = verify_source(&package, &signer.verifying_key(), &json, 1100).unwrap();
        assert!(verified.is_document());
        assert_eq!(verified.row_count(), 2);
        assert_eq!(verified.expires(), 1900);
        let derived = verified
            .derive_question(&[1], "  What does this say?  ")
            .unwrap();
        let actual: DocumentDataset = serde_json::from_str(&derived).unwrap();
        let mut expected = original.clone();
        expected.inference = vec![original.inference[1].clone()];
        expected.inference[0].question = "  What does this say?  ".into();
        assert_eq!(actual, expected);
        assert_eq!(
            derived,
            verified
                .derive_question(&[1], "  What does this say?  ")
                .unwrap()
        );
        assert_eq!(verified.derive(&[0, 1]).unwrap(), json);
        assert!(validate_document_json(&derived, 1).is_ok());
        let value: serde_json::Value = serde_json::from_str(&derived).unwrap();
        for field in ["train", "heldout", "source_revision"] {
            assert!(value.get(field).is_none());
        }
        for rows in [&[][..], &[1, 1], &[1, 0], &[2]] {
            assert!(verified.derive(rows).is_err());
        }
    }
}

#[test]
fn original_requires_same_independent_publisher_type_expiry_and_source_bounds() {
    let signer = SigningKey::from_bytes(&[23; 32]);
    let other = SigningKey::from_bytes(&[24; 32]);
    let text = source_text();
    let source = signed(&text, "text/plain", &signer, 2000);
    let original = document(&source);
    assert!(verify_document(&original, &signer));
    for source in [
        signed(&text, "text/plain", &other, 2000),
        signed(&text, "application/octet-stream", &signer, 2000),
        signed(&text, "text/plain", &signer, 1800),
        signed(&text, "text/plain", &signer, 1050),
        signed(FIRST, "text/plain", &signer, 2000),
        signed(
            &"x".repeat(MAX_DATASET_BYTES + 1),
            "text/plain",
            &signer,
            2000,
        ),
    ] {
        assert!(!verify_document(&document(&source), &signer));
    }
    let json = serde_json::to_string(&original).unwrap();
    let package = signed(&json, DOCUMENT_CONTENT_TYPE, &signer, 1900);
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
    let wrong_profile = signed(&json, CONTENT_TYPE, &signer, 1900);
    assert!(verify_source(&wrong_profile, &signer.verifying_key(), &json, 1100).is_err());
}

#[test]
fn strict_document_schema_rejects_private_training_unknown_and_invalid_byte_ranges() {
    let signer = SigningKey::from_bytes(&[23; 32]);
    let source = signed(&source_text(), "text/plain", &signer, 2000);
    let document = document(&source);
    let original = serde_json::to_value(&document).unwrap();
    for (field, value) in [
        ("version", json!(1)),
        ("visibility", json!("private")),
        ("license", json!("unspecified")),
        ("train", json!([])),
        ("heldout", json!([])),
        ("source_revision", json!("a".repeat(40))),
        (
            "source_manifest_hex",
            json!(hex::encode(&source).to_uppercase()),
        ),
        (
            "source_manifest_hex",
            json!(format!("{}00", hex::encode(&source))),
        ),
        ("inference", json!([])),
        ("inference", json!(vec![document.inference[0].clone(); 5])),
    ] {
        let mut malformed = original.clone();
        malformed[field] = value;
        assert!(
            validate_document_json(&malformed.to_string(), 2).is_err(),
            "{field}"
        );
    }
    for (field, value) in [
        ("question", json!(" \n ")),
        ("question", json!("nul\0")),
        ("question", json!("é".repeat(257))),
        ("context", json!("x".repeat(4097))),
        ("start", json!(-1)),
        ("start", json!(true)),
        ("start", json!(1.0)),
        ("end", json!(FIRST.chars().count())),
        ("end", json!(0)),
        ("answer", json!("No invented evaluation answer")),
    ] {
        let mut malformed = original.clone();
        malformed["inference"][0][field] = value;
        assert!(
            validate_document_json(&malformed.to_string(), 2).is_err(),
            "{field}"
        );
    }
    let mut overlapping = document.clone();
    overlapping.inference[1].start -= 2;
    overlapping.inference[1].end -= 2;
    assert!(overlapping.validate_shape().is_err());
    let mut excessive = document.clone();
    excessive.inference[1].start = MAX_DATASET_BYTES as u64;
    excessive.inference[1].end = excessive.inference[1].start + SECOND.len() as u64;
    assert!(excessive.validate_shape().is_err());
    let json = serde_json::to_string(&document).unwrap();
    let duplicate = json.replacen("\"version\":2", "\"version\":2,\"version\":2", 1);
    assert!(validate_document_json(&duplicate, 2).is_err());
    assert!(validate_document_json(&json, 1).is_err());
}

#[test]
fn excerpt_is_an_authenticated_publisher_assertion_not_an_unavailable_byte_proof() {
    let signer = SigningKey::from_bytes(&[23; 32]);
    let source = signed(&source_text(), "text/plain", &signer, 2000);
    let mut assertion = document(&source);
    assertion.inference[0].context = "x".repeat(FIRST.len());
    // Deliberately different bytes of the same signed-source range length. The trusted
    // publisher authenticates this assertion, but this API never has original text.
    // Only the document coordinator's exact original-byte comparison can reject it.
    assert_ne!(assertion.inference[0].context.as_bytes(), FIRST.as_bytes());
    assert!(verify_document(&assertion, &signer));
}
