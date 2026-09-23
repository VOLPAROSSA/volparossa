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
        original_source: None,
        level: 1,
        claim_scope: DERIVED_CLAIM_SCOPE.into(),
        model_profile: ModelProfile::default(),
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
fn omitted_default_profile_preserves_legacy_canonical_bytes() {
    let signer = SigningKey::from_bytes(&[25; 32]);
    let source = signed("Original public source text.", "text/plain", &signer, 2000);
    let original = dataset(&source);
    let encoded = serde_json::to_string(&original).unwrap();
    assert!(!encoded.contains("model_profile"));
    assert!(!encoded.contains("original_source"));
    let decoded: DerivedDataset = serde_json::from_str(&encoded).unwrap();
    assert!(decoded.model_profile.is_default());
    assert_eq!(serde_json::to_string(&decoded).unwrap(), encoded);
    let explicit = encoded.replacen(
        "\"version\":3",
        "\"version\":3,\"model_profile\":\"smollm2-135m-v1\"",
        1,
    );
    assert_eq!(
        serde_json::from_str::<DerivedDataset>(&explicit).unwrap(),
        original
    );
    assert_eq!(
        serde_json::to_string(&serde_json::from_str::<DerivedDataset>(&explicit).unwrap()).unwrap(),
        encoded
    );
    for value in [
        json!("smollm2-360m"),
        json!("unrestricted"),
        json!(null),
        json!(true),
    ] {
        let mut invalid = serde_json::to_value(&original).unwrap();
        invalid["model_profile"] = value;
        assert!(serde_json::from_value::<DerivedDataset>(invalid).is_err());
    }
}

#[test]
fn larger_profile_binds_parent_bound_without_changing_signed_package_capacity() {
    let signer = SigningKey::from_bytes(&[25; 32]);
    let source = signed("Original public source text.", "text/plain", &signer, 2000);
    let mut original = dataset(&source);
    original.model_profile = ModelProfile::Smol360;
    let row = &mut original.inference[0];
    row.inputs.truncate(1);
    row.inputs[0].text = "é".repeat(2048);
    row.inputs[0].piece_end = 4096;
    row.context.clone_from(&row.inputs[0].text);
    original.inference = vec![original.inference[0].clone(); 4];
    original.validate_shape().unwrap();
    let encoded = serde_json::to_string(&original).unwrap();
    assert!(encoded.contains("\"model_profile\":\"smollm2-360m-v1\""));
    let package = signed(&encoded, DERIVED_CONTENT_TYPE, &signer, 1900);
    let verified = verify_source(&package, &signer.verifying_key(), &encoded, 1100).unwrap();
    assert_eq!(verified.row_count(), 4);
    let selected = verified.derive(&[3]).unwrap();
    let subset: DerivedDataset = serde_json::from_str(&selected).unwrap();
    assert_eq!(subset.model_profile, ModelProfile::Smol360);
    assert_eq!(subset.inference, vec![original.inference[3].clone()]);
    assert_eq!(subset.source_manifest_hex, original.source_manifest_hex);
    assert_eq!(subset.claim_scope, original.claim_scope);
    validate_derived_json(&selected, 1).unwrap();
    original.model_profile = ModelProfile::default();
    assert!(original.validate_shape().is_err());
    original.model_profile = ModelProfile::Smol360;
    original.inference[0].inputs[0].text.push('x');
    assert!(original.validate_shape().is_err());
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

fn grounded(source: &[u8], original: &str) -> DerivedDataset {
    let mut value = dataset(source);
    value.version = 5;
    value.model_profile = ModelProfile::Smol360;
    value.original_source = Some(original.into());
    value
}

#[test]
fn grounded_source_authentication_and_selection_keep_original_separate_from_generated_text() {
    let signer = SigningKey::from_bytes(&[25; 32]);
    let original = "Original public source with UTF-8: café.\n";
    let source = signed(original, "text/plain", &signer, 2000);
    let mut value = grounded(&source, original);
    value.inference.push(value.inference[0].clone());
    let encoded = serde_json::to_string(&value).unwrap();
    assert_eq!(value.content_type().unwrap(), GROUNDED_DERIVED_CONTENT_TYPE);
    let package = signed(&encoded, value.content_type().unwrap(), &signer, 1900);
    let verified = verify_source(&package, &signer.verifying_key(), &encoded, 1100).unwrap();
    assert!(verified.is_derived() && verified.is_document());
    assert_eq!(verified.expires(), 1900);
    assert_eq!(verified.derive(&[0, 1]).unwrap(), encoded);
    let selected = verified
        .derive_question(&[1], "Does the source contradict the generated answer?")
        .unwrap();
    let selected: DerivedDataset = serde_json::from_str(&selected).unwrap();
    assert_eq!(selected.original_source.as_deref(), Some(original));
    assert_eq!(selected.source_manifest_hex, value.source_manifest_hex);
    assert_eq!(selected.inference[0].context, value.inference[1].context);
    assert_eq!(selected.inference[0].inputs, value.inference[1].inputs);
    assert_eq!(selected.claim_scope, DERIVED_CLAIM_SCOPE);
    assert!(verify_source(&package, &signer.verifying_key(), &encoded, 1900).is_err());

    // The bound is UTF-8 bytes, not characters; a complete 4096-byte source fits.
    let boundary = "é".repeat(2048);
    let source = signed(&boundary, "text/plain", &signer, 2000);
    let exact = grounded(&source, &boundary);
    let encoded = serde_json::to_string(&exact).unwrap();
    let package = signed(&encoded, exact.content_type().unwrap(), &signer, 1900);
    verify_source(&package, &signer.verifying_key(), &encoded, 1100).unwrap();
}

#[test]
fn grounded_requires_exact_original_bytes_signer_expiry_and_ranges() {
    let signer = SigningKey::from_bytes(&[25; 32]);
    let original = "Original public source text.";
    let source = signed(original, "text/plain", &signer, 2000);
    for changed in [
        "Altered! public source text.",
        "Original public source text. ",
    ] {
        assert_eq!(
            changed.len(),
            original.len() + usize::from(changed.ends_with(' '))
        );
        let encoded = serde_json::to_string(&grounded(&source, changed)).unwrap();
        let package = signed(&encoded, GROUNDED_DERIVED_CONTENT_TYPE, &signer, 1900);
        assert!(verify_source(&package, &signer.verifying_key(), &encoded, 1100).is_err());
    }
    for source in [
        signed(
            original,
            "text/plain",
            &SigningKey::from_bytes(&[27; 32]),
            2000,
        ),
        signed(original, "application/octet-stream", &signer, 2000),
        signed(original, "text/plain", &signer, 1800),
    ] {
        let encoded = serde_json::to_string(&grounded(&source, original)).unwrap();
        let package = signed(&encoded, GROUNDED_DERIVED_CONTENT_TYPE, &signer, 1900);
        assert!(verify_source(&package, &signer.verifying_key(), &encoded, 1100).is_err());
    }
    let mut invalid = grounded(&source, original);
    invalid.inference[0].inputs[0].source_end = original.len() as u64 + 1;
    let encoded = serde_json::to_string(&invalid).unwrap();
    let package = signed(&encoded, GROUNDED_DERIVED_CONTENT_TYPE, &signer, 1900);
    assert!(verify_source(&package, &signer.verifying_key(), &encoded, 1100).is_err());
}

#[test]
fn grounded_checks_signed_whole_hash_chunk_hash_and_length_independently() {
    let signer = SigningKey::from_bytes(&[25; 32]);
    let original = "Original public source text.";
    for fault in 0..3 {
        let length = original.len() as u64 + u64::from(fault == 2);
        let source = crate::SignedManifest::sign(
            Publication {
                metadata: Metadata {
                    name: "source".into(),
                    revision: 1,
                    content_type: "text/plain".into(),
                },
                length,
                validity: Validity {
                    created: 1000,
                    expires: 2000,
                },
            },
            vec![crate::Chunk {
                id: if fault == 1 {
                    ChunkId::digest(b"different")
                } else {
                    ChunkId::digest(original.as_bytes())
                },
                length: u32::try_from(length).unwrap(),
            }],
            if fault == 0 {
                Sha256::digest(b"different").into()
            } else {
                Sha256::digest(original.as_bytes()).into()
            },
            &signer,
        )
        .unwrap();
        // This is a real valid signature over internally inconsistent advertised content.
        // Authentication alone cannot establish that these are the complete original bytes.
        source.verify(&signer.verifying_key(), 1100).unwrap();
        let encoded = serde_json::to_string(&grounded(&source.encode(), original)).unwrap();
        let package = signed(&encoded, GROUNDED_DERIVED_CONTENT_TYPE, &signer, 1900);
        assert!(
            verify_source(&package, &signer.verifying_key(), &encoded, 1100).is_err(),
            "fault {fault}"
        );
    }
}

#[test]
fn grounded_and_legacy_versions_require_distinct_mime_and_strict_inference_only_profiles() {
    let signer = SigningKey::from_bytes(&[25; 32]);
    let original = "Original public source text.";
    let source = signed(original, "text/plain", &signer, 2000);
    let legacy = dataset(&source);
    let current = grounded(&source, original);
    assert_eq!(legacy.content_type().unwrap(), DERIVED_CONTENT_TYPE);
    for (value, wrong_mime) in [
        (&legacy, GROUNDED_DERIVED_CONTENT_TYPE),
        (&current, DERIVED_CONTENT_TYPE),
    ] {
        let encoded = serde_json::to_string(value).unwrap();
        let package = signed(&encoded, wrong_mime, &signer, 1900);
        assert!(verify_source(&package, &signer.verifying_key(), &encoded, 1100).is_err());
    }
    let current = serde_json::to_value(&current).unwrap();
    for (field, replacement) in [
        ("version", json!(3)),
        ("version", json!(4)),
        ("original_source", json!(null)),
        ("original_source", json!("")),
        ("original_source", json!("text\0text")),
        ("original_source", json!("é".repeat(2049))),
        ("model_profile", json!("smollm2-135m-v1")),
        ("train", json!([])),
        ("heldout", json!([])),
    ] {
        let mut invalid = current.clone();
        invalid[field] = replacement;
        assert!(
            validate_derived_json(&invalid.to_string(), 1).is_err(),
            "{field}"
        );
    }
    let mut missing = current;
    missing.as_object_mut().unwrap().remove("original_source");
    assert!(validate_derived_json(&missing.to_string(), 1).is_err());
    let mut invalid_version = legacy;
    invalid_version.version = 4;
    assert!(invalid_version.content_type().is_err());
}
