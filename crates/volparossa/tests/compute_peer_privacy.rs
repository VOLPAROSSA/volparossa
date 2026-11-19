// SPDX-License-Identifier: GPL-3.0-only
//! A signed private-marked source must be refused before the owner CLI asks any agent for work.

use std::{
    fs,
    io::ErrorKind,
    os::unix::net::UnixListener,
    path::Path,
    process::Output,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use serde_json::json;
use tokio::{process::Command, time::timeout};
use volparossa_content::{
    CacheLimits, ChunkStore, Metadata, Publication, Validity,
    provider::compute::dataset::CONTENT_TYPE, publish,
};
use volparossa_local_control::{control_request::Operation, read_request};

const MARKER: &str = "Synthetic visibility-check question";

fn signed_source(root: &Path, visibility: &str, signer: &SigningKey, validity: Validity) {
    let bytes = serde_json::to_vec(&json!({
        "version": 1, "visibility": visibility, "license": "GPL-3.0-only",
        "source_revision": "a".repeat(40), "train": [],
        "heldout": [{"question": "Which fixture?", "context": "Example", "answer": "This one."}],
        "inference": [{"question": MARKER, "context": "Public synthetic text."}]
    }))
    .unwrap();
    let mut store = ChunkStore::create(
        &root.join(format!("cache-{visibility}")),
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 8,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let manifest = publish(
        &mut bytes.as_slice(),
        Publication {
            metadata: Metadata {
                name: "synthetic-visibility".into(),
                revision: 1,
                content_type: CONTENT_TYPE.into(),
            },
            length: bytes.len() as u64,
            validity,
        },
        signer,
        &mut store,
    )
    .unwrap();
    fs::write(root.join("dataset.json"), bytes).unwrap();
    fs::write(root.join("manifest.pb"), manifest.encode()).unwrap();
}

async fn submit(root: &Path, publisher: &SigningKey, provider: &SigningKey) -> Output {
    timeout(
        Duration::from_secs(10),
        Command::new(env!("CARGO_BIN_EXE_volparossa"))
            .arg("--control-socket")
            .arg(root.join("owner.sock"))
            .args(["compute", "peer", "submit", "--execute", "--row", "0"])
            .arg("--provider-key")
            .arg(hex::encode(provider.verifying_key().as_bytes()))
            .arg("--publisher-key")
            .arg(hex::encode(publisher.verifying_key().as_bytes()))
            .arg("--dataset")
            .arg(root.join("dataset.json"))
            .arg("--dataset-manifest")
            .arg(root.join("manifest.pb"))
            .arg("--handle")
            .arg(root.join("job-handle"))
            .kill_on_drop(true)
            .output(),
    )
    .await
    .unwrap()
    .unwrap()
}

#[tokio::test]
async fn private_marked_source_stops_before_the_owner_socket_or_handle() {
    let fixture = tempfile::tempdir().unwrap();
    let root = fixture.path();
    let publisher = SigningKey::from_bytes(&[11; 32]);
    let provider = SigningKey::from_bytes(&[37; 32]);
    let listener = UnixListener::bind(root.join("owner.sock")).unwrap();
    listener.set_nonblocking(true).unwrap();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let validity = Validity {
        created: now,
        expires: now + 600,
    };
    signed_source(root, "private", &publisher, validity);

    let refusal = submit(root, &publisher, &provider).await;
    assert_eq!(refusal.status.code(), Some(1));
    assert!(refusal.stdout.is_empty());
    let error = String::from_utf8(refusal.stderr).unwrap();
    assert!(error.contains("invalid compute control record"), "{error}");
    assert!(!error.contains(MARKER));
    assert_eq!(listener.accept().unwrap_err().kind(), ErrorKind::WouldBlock);
    assert!(!root.join("job-handle").exists());

    // Same listener, keys, request and row. Only source visibility and its signature change.
    signed_source(root, "public", &publisher, validity);
    let listener = tokio::net::UnixListener::from_std(listener).unwrap();
    let witness = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        read_request(&mut stream).await.unwrap()
    };
    let (stopped, request) = tokio::join!(
        submit(root, &publisher, &provider),
        timeout(Duration::from_secs(10), witness)
    );
    let Some(Operation::ComputeRemote(remote)) = request.unwrap().operation else {
        panic!("expected the owner's compute route request");
    };
    assert_eq!(remote.provider_key, provider.verifying_key().as_bytes());
    assert!(!remote.retain_transcript);
    assert_eq!(stopped.status.code(), Some(1));
    assert!(!root.join("job-handle").exists());
}
