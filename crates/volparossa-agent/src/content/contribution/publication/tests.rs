use ed25519_dalek::SigningKey;
use volparossa_content::provider::{pull_publication, serve_publication};
use volparossa_content::transfer::TransferLimits;
use volparossa_content::{CHUNK_BYTES, reassemble};

use super::super::tests::{fixture, publication};
use super::*;
use crate::content::replication_budget::Foreground;

async fn admission(
    runtime: Arc<ContributionRuntime>,
    registry: Arc<Mutex<PublicationRegistry>>,
    foreground: &Arc<Foreground>,
    signed: SignedManifest,
    manifest: VerifiedManifest,
) -> (PublicationAdmission, watch::Sender<bool>) {
    let owner = foreground.enter();
    let slot = runtime.replication.publication_slot().await.unwrap();
    let (source, staging) = stage(&runtime.config, &manifest).unwrap();
    let (stop, receiver) = watch::channel(false);
    (
        PublicationAdmission {
            source,
            staging,
            runtime,
            registry,
            endpoint: ProviderEndpoint::new("provider.example", 443).unwrap(),
            stop: receiver,
            signed,
            manifest,
            _slot: slot,
            _foreground: owner,
        },
        stop,
    )
}

#[tokio::test]
async fn public_publication_admission_owns_writer_restores_and_serves_original_content() {
    for payload in [vec![43; CHUNK_BYTES + 73], Vec::new()] {
        admitted(&payload).await;
    }
}

async fn admitted(payload: &[u8]) {
    let directory = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let root = directory.path().join("contribution");
    let (runtime, registry, limits) = fixture(&root);
    let mut source = ChunkStore::create(&directory.path().join("local"), limits).unwrap();
    let key = SigningKey::from_bytes(&[64; 32]);
    let signed = publication(&mut source, &key, payload, "application/octet-stream");
    let manifest = signed.verify(&key.verifying_key(), now()).unwrap();
    let foreground = Arc::new(Foreground::default());
    let registry = Arc::new(Mutex::new(registry));
    let (mut transaction, _stop) = admission(
        Arc::clone(&runtime),
        Arc::clone(&registry),
        &foreground,
        signed,
        manifest.clone(),
    )
    .await;
    let staging = transaction.staging.path().to_path_buf();
    assert_eq!(fs::metadata(&staging).unwrap().mode() & 0o777, 0o700);
    assert!(foreground.active());
    assert!(runtime.replication.try_background_slot().is_none());
    for chunk in manifest.chunks() {
        transaction
            .source()
            .put_verified(*chunk.id(), &source.get(chunk.id()).unwrap().unwrap())
            .unwrap();
    }
    transaction.commit().await.unwrap();
    transaction.commit().await.unwrap(); // Same original envelope is an idempotent retry.
    assert!(
        registry
            .lock()
            .await
            .contains_at(manifest.manifest_id(), &root)
    );
    drop(transaction);
    assert!(!staging.exists());
    assert!(!foreground.active());
    assert!(runtime.replication.try_background_slot().is_some());
    let (_, registry, _) = fixture(&root);
    assert!(registry.has_live_publications(now()));
    let mut receiver = ChunkStore::create(&directory.path().join("receiver"), limits).unwrap();
    let (mut client, mut server) = tokio::io::duplex(4096);
    let (pulled, sent) = tokio::join!(
        pull_publication(
            &mut client,
            &manifest,
            &mut receiver,
            TransferLimits::default()
        ),
        serve_publication(&mut server, &registry, TransferLimits::default()),
    );
    assert_eq!(pulled.unwrap(), sent.unwrap());
    let mut actual = Vec::new();
    reassemble(&manifest, &mut [&mut receiver], now(), &mut actual).unwrap();
    assert_eq!(actual, payload);
    assert!(!registry.has_live_publications(manifest.validity().expires));
}

#[tokio::test]
async fn public_publication_admission_quota_failure_releases_staging_and_private_never_stages() {
    let directory = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let root = directory.path().join("contribution");
    let (runtime, registry, limits) = fixture(&root);
    let mut destination = ChunkStore::open(&root, limits).unwrap();
    let key = SigningKey::from_bytes(&[66; 32]);
    let retained_bytes = [8, 9, 10]
        .into_iter()
        .flat_map(|byte| vec![byte; CHUNK_BYTES])
        .collect::<Vec<_>>();
    let retained = publication(
        &mut destination,
        &key,
        &retained_bytes,
        "application/octet-stream",
    );
    let retained = retained.verify(&key.verifying_key(), now()).unwrap();
    drop(destination);
    let mut source = ChunkStore::create(&directory.path().join("source"), limits).unwrap();
    let payload = vec![20; CHUNK_BYTES + 1];
    let signed = publication(&mut source, &key, &payload, "application/octet-stream");
    let manifest = signed.verify(&key.verifying_key(), now()).unwrap();
    let foreground = Arc::new(Foreground::default());
    let (mut transaction, _stop) = admission(
        Arc::clone(&runtime),
        Arc::new(Mutex::new(registry)),
        &foreground,
        signed,
        manifest.clone(),
    )
    .await;
    let staging = transaction.staging.path().to_path_buf();
    for chunk in manifest.chunks() {
        transaction
            .source()
            .put_verified(*chunk.id(), &source.get(chunk.id()).unwrap().unwrap())
            .unwrap();
    }
    assert!(transaction.commit().await.is_err());
    drop(transaction);
    assert!(!staging.exists());
    assert!(!foreground.active());
    assert!(runtime.replication.try_background_slot().is_some());
    let mut destination = ChunkStore::open(&root, limits).unwrap();
    for chunk in retained.chunks() {
        assert!(
            destination.get(chunk.id()).unwrap().is_some(),
            "no live eviction"
        );
    }
    let private = publication(
        &mut source,
        &key,
        b"private sentinel",
        PRIVATE_MESSAGE_CONTENT_TYPE,
    );
    let private = private.verify(&key.verifying_key(), now()).unwrap();
    assert!(stage(&runtime.config, &private).is_err());
    assert!(!fs::read_dir(directory.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .as_encoded_bytes()
            .starts_with(b".volparossa-publication-")
    }));
}
