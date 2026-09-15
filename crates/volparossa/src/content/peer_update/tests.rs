//! Real native signatures and owned disk bytes; the tiny bundle is not model execution proof.

use ed25519_dalek::SigningKey;
use volparossa_content::{
    CacheLimits, ChunkStore, Metadata, Publication, Validity,
    agent_artifact::{AdapterFiles, MODEL_ID},
};

use super::*;

struct Fixture {
    root: tempfile::TempDir,
    store: ChunkStore,
    owner: SigningKey,
    publisher: SigningKey,
    now: u64,
    dataset: Vec<u8>,
    dataset_manifest: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let store = ChunkStore::create(
            &root.path().join("source"),
            CacheLimits {
                max_bytes: 16 * 1024 * 1024,
                max_entries: 64,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let mut result = Self {
            root, store, owner: SigningKey::from_bytes(&[91; 32]),
            publisher: SigningKey::from_bytes(&[92; 32]), now: now_seconds().unwrap(),
            dataset: serde_json::to_vec(&json!({"version":1,"visibility":"public","license":"GPL-3.0-only",
                "source_revision":"a".repeat(40),
                "train":[{"question":"Which role forwards?","context":"Relays forward traffic.","answer":"Relay."}],
                "heldout":[{"question":"Does a relay forward?","context":"Relays forward traffic.","answer":"Yes."}],
                "inference":[{"question":"Who forwards?","context":"Relays forward traffic."}]})).unwrap(),
            dataset_manifest: Vec::new(),
        };
        result.dataset_manifest = result.sign(
            &result.dataset.clone(),
            "source",
            7,
            dataset::CONTENT_TYPE,
            false,
        );
        result
    }

    fn args(&self) -> Fetch {
        Fetch {
            publisher_key: self.owner.verifying_key(),
            name: "updates".into(),
            min_revision: Some(2),
            cache: self.root.path().join("agent-cache"),
            limits: Limits {
                quota_bytes: 16 * 1024 * 1024,
                max_entries: 64,
                min_free_bytes: 0,
            },
        }
    }

    fn source(&self) -> DatasetSource {
        DatasetSource {
            publisher_key: self.publisher.verifying_key(),
            name: "source".into(),
            revision: 7,
            manifest_id: Sha256::digest(&self.dataset_manifest).into(),
        }
    }

    fn sign(
        &mut self,
        bytes: &[u8],
        name: &str,
        revision: u64,
        mime: &str,
        adapter: bool,
    ) -> Vec<u8> {
        let mut input = bytes;
        volparossa_content::publish(
            &mut input,
            Publication {
                metadata: Metadata {
                    name: name.into(),
                    revision,
                    content_type: mime.into(),
                },
                length: bytes.len() as u64,
                validity: Validity {
                    created: self.now,
                    expires: self.now + if adapter { 600 } else { 400 },
                },
            },
            if adapter {
                &self.owner
            } else {
                &self.publisher
            },
            &mut self.store,
        )
        .unwrap()
        .encode()
    }

    fn update(&mut self) -> VerifiedUpdate {
        let bytes = AdapterBundle::encode(
            self.source().manifest_id,
            AdapterFiles {
                config: br#"{"r":4}"#.to_vec(),
                weights: b"codec-only-safetensors-placeholder".to_vec(),
                readme: b"test model card".to_vec(),
            },
        )
        .unwrap();
        let signed = self.sign(&bytes, "updates", 2, ADAPTER_CONTENT_TYPE, true);
        verify(
            &self.args(),
            &signed,
            &bytes,
            receipt(&signed, &self.owner.verifying_key(), self.now),
            self.now,
        )
        .unwrap()
    }
}

fn receipt(signed: &[u8], publisher: &VerifyingKey, now: u64) -> Value {
    let manifest = SignedManifest::decode(signed)
        .unwrap()
        .verify(publisher, now)
        .unwrap();
    json!({"manifest_id":hex::encode(manifest.manifest_id()),"sha256":hex::encode(manifest.object_sha256()),
        "bytes":manifest.length(),"chunks":manifest.chunks().len(),"peer_bytes":0,"providers_used":0})
}

#[test]
fn unknown_dataset_candidate_survives_reopen_without_new_authority_or_download() {
    let mut fixture = Fixture::new();
    let update = fixture.update();
    let output = fixture.root.path().join("pending");
    save_pending(&update, &output).unwrap();
    let retained = open_pending(&output, &fixture.args(), fixture.now + 1).unwrap();
    assert_eq!(retained.bundle(), update.bundle());
    assert_eq!(retained.signed_manifest(), update.signed_manifest());
    assert_eq!(
        retained.dataset_manifest_id(),
        &fixture.source().manifest_id
    );
    assert_eq!(retained.expires(), fixture.now + 600);
    assert_eq!(retained.revision(), 2);
    assert!(!output.join("dataset.json").exists());
    assert!(save_pending(&update, &output).is_err());
    assert!(open_pending(&output, &fixture.args(), fixture.now + 600).is_err());
    let mut wrong = fixture.args();
    wrong.publisher_key = fixture.publisher.verifying_key();
    assert!(open_pending(&output, &wrong, fixture.now).is_err());
    wrong = fixture.args();
    wrong.min_revision = Some(3);
    assert!(open_pending(&output, &wrong, fixture.now).is_err());
}

#[test]
fn imported_originals_and_extracted_files_reverify_against_independent_dataset_selection() {
    let mut fixture = Fixture::new();
    let update = fixture.update();
    let source = fixture.source();
    assert_ne!(fixture.args().publisher_key, source.publisher_key);
    let data_receipt = receipt(
        &fixture.dataset_manifest,
        &source.publisher_key,
        fixture.now,
    );
    let imported = assemble(
        &update,
        &source,
        &fixture.dataset_manifest,
        &fixture.dataset,
        data_receipt.clone(),
        fixture.now,
    )
    .unwrap();
    assert_eq!(imported.expires(), fixture.now + 400);
    assert_eq!(imported.manifest_id(), update.manifest_id());
    assert_eq!(imported.dataset_manifest_id(), &source.manifest_id);
    assert_eq!(imported.revision(), 2);
    assert_eq!(imported.provenance()["model_activated"], false);
    let output = fixture.root.path().join("import");
    let temporary = staging(&output).unwrap();
    write_import(
        temporary.path(),
        &update,
        &fixture.dataset_manifest,
        &fixture.dataset,
        imported.provenance(),
    )
    .unwrap();
    publish(temporary, &output).unwrap();
    assert_eq!(
        reopen(&output, &fixture.args(), &source, fixture.now + 1)
            .unwrap()
            .provenance(),
        imported.provenance()
    );
    for change in 0..4 {
        let mut wrong = fixture.source();
        match change {
            0 => wrong.publisher_key = fixture.owner.verifying_key(),
            1 => wrong.name = "another-source".into(),
            2 => wrong.revision += 1,
            _ => wrong.manifest_id = [77; 32],
        }
        assert!(reopen(&output, &fixture.args(), &wrong, fixture.now).is_err());
    }
    assert!(reopen(&output, &fixture.args(), &source, fixture.now + 400).is_err());
    let mut changed = fixture.dataset.clone();
    changed[0] ^= 1;
    assert!(
        assemble(
            &update,
            &source,
            &fixture.dataset_manifest,
            &changed,
            data_receipt,
            fixture.now
        )
        .is_err()
    );
    // Alter the actually extracted file in this test-owned temporary tree.
    let mut file = OpenOptions::new()
        .write(true)
        .open(output.join("adapter/README.md"))
        .unwrap();
    file.write_all(b"different card").unwrap();
    assert!(reopen(&output, &fixture.args(), &source, fixture.now).is_err());
}

#[tokio::test]
async fn unknown_dataset_is_rejected_before_socket_or_output_and_bundle_profile_is_fixed() {
    let mut fixture = Fixture::new();
    let update = fixture.update();
    let mut unknown = fixture.source();
    unknown.manifest_id = [51; 32];
    let output = fixture.root.path().join("not-created");
    let error = import(
        &fixture.args(),
        &update,
        &unknown,
        &fixture.root.path().join("absent.sock"),
        &output,
    )
    .await;
    assert_eq!(
        error.err().unwrap().to_string(),
        "peer_update_dataset_not_selected"
    );
    assert!(!output.exists());
    let mut bytes = update.bundle().to_vec();
    let index = bytes
        .windows(MODEL_ID.len())
        .position(|part| part == MODEL_ID.as_bytes())
        .unwrap();
    bytes[index] ^= 1;
    let signed = fixture.sign(&bytes, "updates", 2, ADAPTER_CONTENT_TYPE, true);
    assert!(
        verify(
            &fixture.args(),
            &signed,
            &bytes,
            receipt(&signed, &fixture.owner.verifying_key(), fixture.now),
            fixture.now
        )
        .is_err()
    );
    let mut changed_receipt = update.receipt().clone();
    changed_receipt["bytes"] = 1.into();
    assert!(
        verify(
            &fixture.args(),
            update.signed_manifest(),
            update.bundle(),
            changed_receipt,
            fixture.now
        )
        .is_err()
    );
}
