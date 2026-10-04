use super::*;
use crate::provider::compute::dataset::{DOCUMENT_CONTENT_TYPE, verify_source};
use crate::{CacheLimits, ChunkStore, Metadata, Publication, Validity, publish};
use ed25519_dalek::SigningKey;
use serde_json::json;

const CODE: &str = "// Café: public fixture\npub fn sum(a: i32, b: i32) -> i32 { a - b }\n";

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
                name: "public-code".into(),
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

fn dataset(source: &[u8]) -> CodeProposalDataset {
    CodeProposalDataset {
        version: 6,
        visibility: "public".into(),
        purpose: "code_proposal".into(),
        license: "GPL-3.0-only".into(),
        model_profile: ModelProfile::Qwen600,
        source_manifest_hex: hex::encode(source),
        inference: vec![DocumentQuestion {
            question: "Correct the sum function. Return only the complete replacement source."
                .into(),
            context: CODE.into(),
            start: 0,
            end: CODE.len() as u64,
        }],
        output_contract: CodeProposalOutputContract::SingleFileReplacementV1,
    }
}

#[test]
fn signed_code_purpose_model_and_whole_source_survive_exact_derivation() {
    let signer = SigningKey::from_bytes(&[23; 32]);
    let source = signed(CODE, "text/plain", &signer, 2000);
    let mut input = dataset(&source);
    for profile in [ModelProfile::Qwen600, ModelProfile::Qwen4bInstruct2507] {
        input.model_profile = profile;
        let raw = serde_json::to_string(&input).unwrap();
        let manifest = signed(&raw, CODE_PROPOSAL_CONTENT_TYPE, &signer, 1900);
        let verified = verify_source(&manifest, &signer.verifying_key(), &raw, 1100).unwrap();
        assert!(verified.is_code_proposal() && verified.is_document());
        assert!(!verified.is_principle() && !verified.is_derived());
        assert_eq!(verified.code_model_profile(), Some(profile));
        assert_eq!(verified.output_contract(), None);
        assert_eq!(verified.row_count(), 1);
        assert_eq!(verified.derive(&[0]).unwrap(), raw);
        validate_code_proposal_json(&raw, 1).unwrap();
        assert!(
            verified
                .derive_question(&[0], &input.inference[0].question)
                .is_err()
        );
        for rows in [&[][..], &[1], &[0, 0]] {
            assert!(verified.derive(rows).is_err());
        }
        assert!(
            verify_source(
                &manifest,
                &signer.verifying_key(),
                &raw.replace("sum", "add"),
                1100
            )
            .is_err()
        );
        let wrong_type = signed(&raw, DOCUMENT_CONTENT_TYPE, &signer, 1900);
        assert!(verify_source(&wrong_type, &signer.verifying_key(), &raw, 1100).is_err());
    }
}

#[test]
fn code_rejects_changed_or_partial_whole_source_even_with_a_valid_outer_signature() {
    let signer = SigningKey::from_bytes(&[23; 32]);
    let other = SigningKey::from_bytes(&[24; 32]);
    for source in [
        signed(CODE, "text/plain", &other, 2000),
        signed(CODE, "application/octet-stream", &signer, 2000),
        signed(CODE, "text/plain", &signer, 1800),
        signed(&CODE.replace("a - b", "a + b"), "text/plain", &signer, 2000),
        signed(&format!("{CODE}extra"), "text/plain", &signer, 2000),
    ] {
        let raw = serde_json::to_string(&dataset(&source)).unwrap();
        let manifest = signed(&raw, CODE_PROPOSAL_CONTENT_TYPE, &signer, 1900);
        assert!(verify_source(&manifest, &signer.verifying_key(), &raw, 1100).is_err());
    }
    let source = signed(CODE, "text/plain", &signer, 2000);
    let raw = serde_json::to_string(&dataset(&source)).unwrap();
    let manifest = signed(&raw, CODE_PROPOSAL_CONTENT_TYPE, &signer, 1900);
    assert!(verify_source(&manifest, &other.verifying_key(), &raw, 1100).is_err());
    assert!(verify_source(&manifest, &signer.verifying_key(), &raw, 1900).is_err());
}

#[test]
fn code_shape_has_no_private_history_training_tools_paths_or_question_override() {
    let signer = SigningKey::from_bytes(&[23; 32]);
    let source = signed(CODE, "text/plain", &signer, 2000);
    let original = serde_json::to_value(dataset(&source)).unwrap();
    for (field, value) in [
        ("version", json!(2)),
        ("visibility", json!("private")),
        ("purpose", json!("private_conversation")),
        ("license", json!("unspecified")),
        ("model_profile", json!("smollm2-360m-v1")),
        ("model_profile", json!("arbitrary-model")),
        ("output_contract", json!("execute_shell")),
        ("train", json!([])),
        ("heldout", json!([])),
        ("history", json!([])),
        ("tools", json!([])),
        ("path", json!("/private/workspace")),
        ("adapter_root", json!("/adapter")),
        ("inference", json!([])),
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
            validate_code_proposal_json(&changed.to_string(), 1).is_err(),
            "{field}"
        );
    }
    for (field, value) in [
        ("question", json!(" ")),
        ("question", json!("x".repeat(513))),
        ("context", json!("x".repeat(4097))),
        ("context", json!("bad\0code")),
        ("start", json!(1)),
        ("end", json!(CODE.chars().count())),
    ] {
        let mut changed = original.clone();
        changed["inference"][0][field] = value;
        assert!(
            validate_code_proposal_json(&changed.to_string(), 1).is_err(),
            "{field}"
        );
    }
    let raw = original.to_string();
    assert!(
        validate_code_proposal_json(
            &raw.replace("\"version\":6", "\"version\":6,\"version\":6"),
            1
        )
        .is_err()
    );
    for rows in [0, 2, 4] {
        assert!(validate_code_proposal_json(&raw, rows).is_err());
    }
}
