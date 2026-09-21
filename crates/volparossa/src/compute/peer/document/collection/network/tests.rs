//! Real native signature and retained-byte validation only; no retrieval or model execution.

use ed25519_dalek::SigningKey;
use serde_json::json;
use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity};

use super::*;

const CREATED: u64 = 150;
const EXPIRES: u64 = 400;

fn publication(text: &str, name: &str, seed: u8) -> (Selection, SignedManifest) {
    let root = tempfile::tempdir().unwrap();
    let mut store = ChunkStore::create(
        &root.path().join("native"),
        CacheLimits {
            max_bytes: 2 * 1024 * 1024,
            max_entries: 32,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let publisher = SigningKey::from_bytes(&[seed; 32]);
    let signed = volparossa_content::publish(
        &mut text.as_bytes(),
        Publication {
            metadata: Metadata {
                name: name.into(),
                revision: 3,
                content_type: "text/plain".into(),
            },
            length: text.len() as u64,
            validity: Validity {
                created: 100,
                expires: 600,
            },
        },
        &publisher,
        &mut store,
    )
    .unwrap();
    let selection = Selection {
        publisher_key: hex::encode(publisher.verifying_key().to_bytes()),
        name: name.into(),
        manifest_id: hash(&signed.encode()),
    };
    (selection, signed)
}

fn receipt(selection: &Selection, manifest: &VerifiedManifest) -> Value {
    json!({
        "operation":"named_content_download", "bytes":manifest.length(),
        "chunks":manifest.chunks().len(), "publisher_key":selection.publisher_key,
        "name":selection.name, "revision":3, "manifest_id":selection.manifest_id,
        "publication_expires_unix_seconds":600,
        "sha256":hex::encode(manifest.object_sha256()),
        "local_delivery":true, "output_mode":"0600", "ownership_changed":false,
        "origin_authenticated":false, "globally_latest":false,
        "peer_bytes":0, "providers_used":0, "origin_body_bytes":0,
        "origin_range_requests":0, "provider_peer_ids":[], "control_relay_peer_id":"",
        "cache_only":false
    })
}

struct Fixture {
    document: String,
    ledger: Ledger,
    proofs: Proofs,
}

impl Fixture {
    fn new() -> Self {
        // Cross the real content chunk boundary while preserving valid UTF-8.
        let first = "é".repeat(CHUNK_BYTES / 2 + 9);
        let last = "Another explicitly selected public source.\n";
        let (selected_a, signed_a) = publication(&first, "north", 62);
        let (selected_b, signed_b) = publication(last, "south", 63);
        let prepared = super::super::compile(
            2,
            vec![
                ("North".into(), first, Some(selected_a.clone())),
                ("Local".into(), "Local public source.\n".into(), None),
                ("South".into(), last.into(), Some(selected_b.clone())),
            ],
        )
        .unwrap();
        let mut sources = Vec::new();
        for (index, selection, signed) in [(0, selected_a, signed_a), (2, selected_b, signed_b)] {
            let key = parse_publisher_key(&selection.publisher_key).unwrap();
            let manifest = signed.verify(&key, 120).unwrap();
            sources.push(Proof {
                source_index: index,
                receipt: receipt(&selection, &manifest),
                selection,
                verified_at: 120,
                expires: 600,
                signed_manifest_hex: hex::encode(signed.encode()),
                sha256: hex::encode(manifest.object_sha256()),
                bytes: manifest.length(),
            });
        }
        Self {
            document: prepared.document,
            ledger: prepared.ledger,
            proofs: Proofs {
                version: 1,
                sources,
            },
        }
    }

    fn check(&self, proofs: &Proofs) -> Result<()> {
        proofs.validate(&self.ledger, &self.document, CREATED, EXPIRES)
    }

    fn first_text(&self) -> &[u8] {
        self.ledger.sources[0]
            .content
            .slice(&self.document)
            .unwrap()
            .as_bytes()
    }
}

#[test]
fn signed_multi_chunk_sources_bind_exact_compilation_and_restore_historically() {
    let fixture = Fixture::new();
    fixture.check(&fixture.proofs).unwrap();
    let encoded = serde_json::to_vec(&fixture.proofs).unwrap();
    assert_eq!(fixture.proofs.sha256().unwrap(), hash(&encoded));
    let restored: Proofs = serde_json::from_slice(&encoded).unwrap();
    assert_eq!(restored, fixture.proofs);
    // This intentionally authenticates retained history without consulting current wall time.
    fixture.check(&restored).unwrap();
    let mut wrong = fixture.document.clone();
    let offset = usize::try_from(fixture.ledger.sources[2].content.start).unwrap();
    wrong.replace_range(offset..=offset, "X");
    assert!(
        restored
            .validate(&fixture.ledger, &wrong, CREATED, EXPIRES)
            .is_err()
    );
}

#[test]
fn each_native_entry_needs_one_ordered_proof_and_local_entries_cannot_claim_one() {
    let fixture = Fixture::new();
    let mut variants = Vec::new();
    let mut changed = fixture.proofs.clone();
    changed.sources.pop();
    variants.push(changed);
    let mut changed = fixture.proofs.clone();
    changed.sources.swap(0, 1);
    variants.push(changed);
    let mut changed = fixture.proofs.clone();
    changed.sources[1] = changed.sources[0].clone();
    variants.push(changed);
    let mut changed = fixture.proofs.clone();
    changed.sources[0].source_index = 1;
    variants.push(changed);
    let mut changed = fixture.proofs.clone();
    changed.sources.push(changed.sources[0].clone());
    variants.push(changed);
    let mut changed = fixture.proofs.clone();
    changed.version = 2;
    variants.push(changed);
    for changed in variants {
        assert!(fixture.check(&changed).is_err());
    }
    let local = super::super::compile(
        1,
        vec![
            ("A".into(), "Public A".into(), None),
            ("B".into(), "Public B".into(), None),
        ],
    )
    .unwrap();
    assert!(
        fixture
            .proofs
            .validate(&local.ledger, &local.document, CREATED, EXPIRES)
            .is_err()
    );
}

#[test]
fn preselected_publisher_name_exact_manifest_and_original_bytes_cannot_be_rebound() {
    let fixture = Fixture::new();
    let original = &fixture.proofs.sources[0];
    let mut variants = Vec::new();
    let mut wrong = original.clone();
    wrong.selection.publisher_key =
        hex::encode(SigningKey::from_bytes(&[65; 32]).verifying_key().to_bytes());
    variants.push(wrong);
    let mut wrong = original.clone();
    wrong.selection.name = "another-name".into();
    variants.push(wrong);
    let mut wrong = original.clone();
    wrong.selection.manifest_id = "ab".repeat(32);
    variants.push(wrong);
    let mut wrong = original.clone();
    wrong.sha256 = "ab".repeat(32);
    variants.push(wrong);
    let mut wrong = original.clone();
    wrong.bytes -= 1;
    variants.push(wrong);
    let mut wrong = original.clone();
    let mut manifest = hex::decode(&wrong.signed_manifest_hex).unwrap();
    *manifest.last_mut().unwrap() ^= 1;
    wrong.signed_manifest_hex = hex::encode(manifest);
    variants.push(wrong);
    for wrong in variants {
        assert!(
            wrong
                .validate(fixture.first_text(), CREATED, EXPIRES)
                .is_err()
        );
    }
    let mut wrong_bytes = fixture.first_text().to_vec();
    *wrong_bytes.last_mut().unwrap() ^= 1;
    assert!(original.validate(&wrong_bytes, CREATED, EXPIRES).is_err());
}

#[test]
fn compilation_and_observation_never_extend_original_signed_validity() {
    let fixture = Fixture::new();
    let mut changed = fixture.proofs.clone();
    changed.sources[0].verified_at = 99;
    assert!(fixture.check(&changed).is_err());
    changed.sources[0].verified_at = CREATED + 1;
    assert!(fixture.check(&changed).is_err());
    let mut changed = fixture.proofs.clone();
    changed.sources[0].expires += 1;
    assert!(fixture.check(&changed).is_err());
    assert!(
        fixture
            .proofs
            .validate(&fixture.ledger, &fixture.document, CREATED, 601)
            .is_err()
    );
    assert!(
        fixture
            .proofs
            .validate(&fixture.ledger, &fixture.document, 600, 601)
            .is_err()
    );
    assert!(
        fixture
            .proofs
            .validate(&fixture.ledger, &fixture.document, CREATED, CREATED)
            .is_err()
    );
    fixture
        .proofs
        .validate(&fixture.ledger, &fixture.document, CREATED, 600)
        .unwrap();
}

#[test]
fn local_receipts_accept_cache_and_partial_peer_delivery_without_origin_attestation() {
    let fixture = Fixture::new();
    let mut cache = fixture.proofs.clone();
    cache.sources[0].receipt["cache_only"] = true.into();
    fixture.check(&cache).unwrap();
    let mut peer = fixture.proofs.clone();
    peer.sources[0].receipt["peer_bytes"] = 20.into();
    peer.sources[0].receipt["providers_used"] = 1.into();
    peer.sources[0].receipt["provider_peer_ids"] = json!(["localProtocolFixturePeer"]);
    peer.sources[0].receipt["control_relay_peer_id"] = "localProtocolFixtureRelay".into();
    fixture.check(&peer).unwrap();
    assert_ne!(peer.sha256().unwrap(), fixture.proofs.sha256().unwrap());
    for (field, value) in [
        ("operation", json!("https_content_download")),
        ("publisher_key", json!("ab".repeat(32))),
        ("name", json!("different")),
        ("revision", json!(4)),
        ("manifest_id", json!("ab".repeat(32))),
        ("publication_expires_unix_seconds", json!(601)),
        ("sha256", json!("ab".repeat(32))),
        ("bytes", json!(1)),
        ("chunks", json!(1)),
        ("local_delivery", json!(false)),
        ("output_mode", json!("0644")),
        ("ownership_changed", json!(true)),
        ("origin_authenticated", json!(true)),
        ("globally_latest", json!(true)),
        ("origin_body_bytes", json!(1)),
        ("origin_range_requests", json!(1)),
        ("peer_bytes", json!(fixture.proofs.sources[0].bytes + 1)),
        ("providers_used", json!(0)),
        ("cache_only", json!(true)),
        ("provider_peer_ids", json!(["p", "p"])),
        ("control_relay_peer_id", json!("")),
        ("unexpected", json!(true)),
    ] {
        let mut wrong = peer.clone();
        wrong.sources[0].receipt[field] = value;
        assert!(
            fixture.check(&wrong).is_err(),
            "accepted changed receipt {field}"
        );
    }
}

#[test]
fn selection_and_retained_records_reject_noncanonical_or_unbounded_metadata() {
    let fixture = Fixture::new();
    let selected = &fixture.proofs.sources[0].selection;
    for (field, value) in [
        ("manifest_id", "00".repeat(32)),
        ("manifest_id", "AB".repeat(32)),
        ("publisher_key", selected.publisher_key.to_ascii_uppercase()),
        ("name", "bad\nname".into()),
    ] {
        let mut encoded = serde_json::to_value(selected).unwrap();
        encoded[field] = value.into();
        let changed: Selection = serde_json::from_value(encoded).unwrap();
        assert!(changed.validate().is_err());
    }
    let mut changed = fixture.proofs.clone();
    changed.sources[0].receipt["control_relay_peer_id"] = "x".repeat(MAX_RECEIPT_BYTES).into();
    assert!(fixture.check(&changed).is_err());
    changed.sources[0].signed_manifest_hex = "00".repeat(MAX_MANIFEST_BYTES + 1);
    assert!(fixture.check(&changed).is_err());
    let mut encoded = serde_json::to_value(&fixture.proofs).unwrap();
    encoded["unexpected"] = true.into();
    assert!(serde_json::from_value::<Proofs>(encoded).is_err());
}
