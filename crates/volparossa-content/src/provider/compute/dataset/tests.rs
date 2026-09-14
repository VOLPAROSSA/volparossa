use super::*;
use crate::{CacheLimits, ChunkStore, Metadata, Publication, Validity, publish};
use ed25519_dalek::SigningKey;

fn source() -> String {
    serde_json::json!({"version":1,"visibility":"public","license":"GPL-3.0-only",
        "source_revision":"a".repeat(40),"train":[],
        "heldout":[{"question":"What is this?","context":"Public repository documentation.","answer":"A protocol fixture."}],
        "inference":[{"question":"Question zero?","context":"Public first input."},
            {"question":"Question one?","context":"Public second input."},
            {"question":"Question two?","context":"Public third input."}]
    }).to_string()
}

fn signed(json: &str, content_type: &str, signer: &SigningKey) -> Vec<u8> {
    let root = tempfile::tempdir().unwrap();
    let mut store = ChunkStore::create(
        &root.path().join("cache"),
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 8,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    publish(
        &mut json.as_bytes(),
        Publication {
            metadata: Metadata {
                name: "public-qa".into(),
                revision: 1,
                content_type: content_type.into(),
            },
            length: json.len() as u64,
            validity: Validity {
                created: 1000,
                expires: 2000,
            },
        },
        signer,
        &mut store,
    )
    .unwrap()
    .encode()
}

#[test]
fn signed_original_deterministically_derives_disjoint_exact_public_rows() {
    let signer = SigningKey::from_bytes(&[23; 32]);
    let json = source();
    let manifest = signed(&json, CONTENT_TYPE, &signer);
    let verified = verify_source(&manifest, &signer.verifying_key(), &json, 1001).unwrap();
    assert_eq!(
        verified.manifest_id(),
        SignedManifest::decode(&manifest)
            .unwrap()
            .verify(&signer.verifying_key(), 1001)
            .unwrap()
            .manifest_id()
    );
    assert_eq!(verified.row_count(), 3);
    assert_eq!(verified.expires(), 2000);
    let first = verified.derive(&[0, 2]).unwrap();
    assert_eq!(first, verified.derive(&[0, 2]).unwrap());
    let first: serde_json::Value = serde_json::from_str(&first).unwrap();
    let second: serde_json::Value = serde_json::from_str(&verified.derive(&[1]).unwrap()).unwrap();
    let original: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(
        first["inference"],
        serde_json::json!([original["inference"][0], original["inference"][2]])
    );
    assert_eq!(
        second["inference"],
        serde_json::json!([original["inference"][1]])
    );
    assert_eq!(first["heldout"], original["heldout"]);
    assert_eq!(second["source_revision"], original["source_revision"]);
    for rows in [&[][..], &[1, 1], &[2, 0], &[3]] {
        assert!(verified.derive(rows).is_err());
    }
}

#[test]
fn authority_exact_bytes_expiry_type_and_private_schema_cannot_be_substituted() {
    let signer = SigningKey::from_bytes(&[23; 32]);
    let json = source();
    let manifest = signed(&json, CONTENT_TYPE, &signer);
    assert!(
        verify_source(
            &manifest,
            &SigningKey::from_bytes(&[24; 32]).verifying_key(),
            &json,
            1001
        )
        .is_err()
    );
    assert!(
        verify_source(
            &manifest,
            &signer.verifying_key(),
            &(json.clone() + " "),
            1001
        )
        .is_err()
    );
    assert!(verify_source(&manifest, &signer.verifying_key(), &json, 2000).is_err());
    let wrong_type = signed(&json, "application/octet-stream", &signer);
    assert!(verify_source(&wrong_type, &signer.verifying_key(), &json, 1001).is_err());
    for malformed in [
        json.replace("\"public\"", "\"private\""),
        json.replacen("\"version\":1", "\"version\":1,\"version\":1", 1),
    ] {
        let manifest = signed(&malformed, CONTENT_TYPE, &signer);
        assert!(verify_source(&manifest, &signer.verifying_key(), &malformed, 1001).is_err());
    }
}
