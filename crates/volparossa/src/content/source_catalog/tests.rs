//! Native signature/disk and typed local-stream checks, not overlay or training evidence.

use ed25519_dalek::SigningKey;
use serde_json::json;
use tokio::net::UnixListener;
use volparossa_content::{
    CacheLimits, ChunkStore, Metadata, Publication, Validity,
    transfer::{TransferLimits, serve_peer},
};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentReceipt, ControlResponse, ControlResult,
    NamedContentTransferReady, control_request::Operation, control_response::Payload, read_request,
    write_response,
};

use super::*;

struct Fixture {
    root: tempfile::TempDir,
    store: ChunkStore,
    authority: SigningKey,
    now: u64,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        let store = ChunkStore::create(
            &root.path().join("source"),
            CacheLimits {
                max_bytes: 1024 * 1024,
                max_entries: 64,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        Self {
            root,
            store,
            authority: SigningKey::from_bytes(&[83; 32]),
            now: now_seconds().unwrap(),
        }
    }

    fn publication(&mut self, body: &[u8], revision: u64, mime: &str) -> Vec<u8> {
        let mut input = body;
        volparossa_content::publish(
            &mut input,
            Publication {
                metadata: Metadata {
                    name: "public-training-catalog".into(),
                    revision,
                    content_type: mime.into(),
                },
                length: body.len() as u64,
                validity: Validity {
                    created: self.now,
                    expires: self.now + 600,
                },
            },
            &self.authority,
            &mut self.store,
        )
        .unwrap()
        .encode()
    }

    fn check(&mut self, value: &Value) -> Result<Vec<Entry>> {
        let body = serde_json::to_vec(value)?;
        let publication = self.publication(&body, 1, CONTENT_TYPE);
        verify(
            &publication,
            &body,
            &self.authority.verifying_key(),
            self.now,
        )
    }
}

fn catalog() -> Value {
    json!({"version":1,"visibility":"public","purpose":"agent_training",
        "dataset_profile":dataset::CONTENT_TYPE,"license":"GPL-3.0-only",
        "sources":[{"name":"unlisted-dataset","revision":7,"manifest_id":"ab".repeat(32)}]})
}

#[test]
fn verifies_exact_public_authority_and_accepts_explicit_empty_withdrawal() {
    let mut fixture = Fixture::new();
    let entries = fixture.check(&catalog()).unwrap();
    assert_eq!(
        entries,
        [Entry {
            name: "unlisted-dataset".into(),
            revision: 7,
            manifest_id: [0xab; 32]
        }]
    );
    let mut empty = catalog();
    empty["sources"] = json!([]);
    assert!(fixture.check(&empty).unwrap().is_empty());
}

#[test]
fn wrong_publisher_expiry_signature_body_and_content_type_are_rejected() {
    let mut fixture = Fixture::new();
    let body = serde_json::to_vec(&catalog()).unwrap();
    let publication = fixture.publication(&body, 1, CONTENT_TYPE);
    let key = fixture.authority.verifying_key();
    assert!(
        verify(
            &publication,
            &body,
            &SigningKey::from_bytes(&[84; 32]).verifying_key(),
            fixture.now
        )
        .is_err()
    );
    assert!(verify(&publication, &body, &key, fixture.now + 600).is_err());
    let mut corrupted = publication.clone();
    *corrupted.last_mut().unwrap() ^= 1;
    assert!(verify(&corrupted, &body, &key, fixture.now).is_err());
    let mut changed = body.clone();
    *changed.last_mut().unwrap() = b' ';
    assert!(verify(&publication, &changed, &key, fixture.now).is_err());
    let wrong_mime = fixture.publication(&body, 1, dataset::CONTENT_TYPE);
    assert!(verify(&wrong_mime, &body, &key, fixture.now).is_err());
    assert!(verify(&publication, &vec![b' '; MAX_BYTES + 1], &key, fixture.now).is_err());
}

#[test]
fn refuses_private_scope_delegation_duplicates_and_unbounded_rows() {
    let mut fixture = Fixture::new();
    for (field, value) in [
        ("version", json!(2)),
        ("visibility", json!("private")),
        ("purpose", json!("browsing_capture")),
        ("license", json!("unspecified")),
        ("dataset_profile", json!("arbitrary-model")),
        ("unknown", json!(true)),
    ] {
        let mut invalid = catalog();
        invalid[field] = value;
        assert!(fixture.check(&invalid).is_err(), "accepted {field}");
    }
    for (field, value) in [
        ("name", json!("bad\nname")),
        ("revision", json!(0)),
        ("manifest_id", json!("0".repeat(64))),
        ("manifest_id", json!("AB".repeat(32))),
        ("publisher_key", json!("ac".repeat(32))),
    ] {
        let mut invalid = catalog();
        invalid["sources"][0][field] = value;
        assert!(fixture.check(&invalid).is_err(), "accepted source {field}");
    }
    let mut duplicate = catalog();
    duplicate["sources"] = json!([
        duplicate["sources"][0].clone(),
        duplicate["sources"][0].clone()
    ]);
    assert!(fixture.check(&duplicate).is_err());
    let mut maximum = catalog();
    maximum["sources"] = Value::Array((0..MAX_ENTRIES).map(|index|
        json!({"name":format!("dataset-{index}"),"revision":1,"manifest_id":"ab".repeat(32)})).collect());
    assert_eq!(fixture.check(&maximum).unwrap().len(), MAX_ENTRIES);
    maximum["sources"]
        .as_array_mut()
        .unwrap()
        .push(json!({"name":"extra","revision":1,"manifest_id":"cd".repeat(32)}));
    assert!(fixture.check(&maximum).is_err());
}

fn response(id: Vec<u8>, code: &str, payload: Payload) -> ControlResponse {
    ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: id,
        result: ControlResult::Ok as i32,
        diagnostic_code: code.into(),
        payload: Some(payload),
    }
}

async fn serve_refresh(listener: &UnixListener, fixture: &mut Fixture, body: &[u8], revision: u64) {
    let publication = fixture.publication(body, revision, CONTENT_TYPE);
    let manifest = SignedManifest::decode(&publication)
        .unwrap()
        .verify(&fixture.authority.verifying_key(), fixture.now)
        .unwrap();
    let (mut stream, _) = listener.accept().await.unwrap();
    let request = read_request(&mut stream).await.unwrap();
    let Some(Operation::ContentFetchName(parameters)) = request.operation else {
        panic!("wrong typed catalog operation");
    };
    assert!(!parameters.prefer_cached && !parameters.cache_only && parameters.reuse_cache);
    assert_eq!(
        parameters.expected_content_type.as_deref(),
        Some(CONTENT_TYPE)
    );
    assert_eq!(parameters.max_object_bytes, Some(MAX_BYTES as u64));
    assert_eq!(
        parameters.publisher_key,
        fixture.authority.verifying_key().to_bytes()
    );
    assert_eq!(parameters.name, "public-training-catalog");
    assert_eq!(parameters.min_revision, Some(1));
    assert_eq!(parameters.expected_manifest_id, None);
    write_response(
        &mut stream,
        &response(
            request.request_id.clone(),
            "NAMED_CONTENT_TRANSFER_READY",
            Payload::NamedContentTransferReady(NamedContentTransferReady {
                manifest: publication,
                cache_only: false,
            }),
        ),
    )
    .await
    .unwrap();
    let progress = serve_peer(
        &mut stream,
        &manifest,
        &mut fixture.store,
        TransferLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(progress.bytes, body.len() as u64);
    write_response(
        &mut stream,
        &response(
            request.request_id,
            "CONTENT_OK",
            Payload::Content(ContentReceipt {
                bytes: manifest.length(),
                chunks: u32::try_from(manifest.chunks().len()).unwrap(),
                // Only a local typed delivery is exercised here; no fictional overlay peer bytes.
                ..ContentReceipt::default()
            }),
        ),
    )
    .await
    .unwrap();
}

#[tokio::test]
async fn typed_local_refresh_reads_two_real_signed_revisions_without_a_cache_shortcut() {
    let mut fixture = Fixture::new();
    let socket = fixture.root.path().join("control.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let private_parent = fixture.root.path().to_path_buf();
    let args = Fetch {
        publisher_key: fixture.authority.verifying_key(),
        name: "public-training-catalog".into(),
        min_revision: Some(1),
        manifest_id: None,
        cache: fixture.root.path().join("source"),
        limits: Limits {
            quota_bytes: 1024 * 1024,
            max_entries: 64,
            min_free_bytes: 0,
        },
    };
    let body = serde_json::to_vec(&catalog()).unwrap();
    let (first, ()) = tokio::join!(
        fetch(&args, &socket, &private_parent),
        serve_refresh(&listener, &mut fixture, &body, 1)
    );
    let first = first.unwrap();
    let mut changed = catalog();
    changed["sources"][0]["name"] = json!("newly-listed-dataset");
    let updated = serde_json::to_vec(&changed).unwrap();
    let (second, ()) = tokio::join!(
        fetch(&args, &socket, &private_parent),
        serve_refresh(&listener, &mut fixture, &updated, 2)
    );
    let second = second.unwrap();
    assert_eq!((first.revision(), second.revision()), (1, 2));
    assert_ne!(first.manifest_id(), second.manifest_id());
    assert_eq!(second.expires(), fixture.now + 600);
    assert_eq!(first.body(), body);
    assert_eq!(second.body(), updated);
    assert_eq!(second.rows()[0].name, "newly-listed-dataset");
    assert_eq!(second.receipt()["revision"], 2);
    assert_eq!(second.receipt()["peer_bytes"], 0);
    assert_eq!(second.receipt()["globally_latest"], false);
    assert_eq!(
        verify(
            second.signed_manifest(),
            second.body(),
            &args.publisher_key,
            fixture.now
        )
        .unwrap(),
        second.rows()
    );
    assert!(!private_parent.join("unused-catalog-output").exists());
}
