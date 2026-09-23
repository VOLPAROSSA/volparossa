//! Real bounded duplex deposits into the existing journaled contribution backend.

use std::{
    path::PathBuf,
    sync::{Arc, Weak},
};

use ed25519_dalek::SigningKey;
use tokio::{
    io::duplex,
    sync::{Mutex, oneshot},
};

use super::*;
use crate::{
    CHUNK_BYTES, CacheLimits, Metadata, Publication, Validity,
    provider::{PublicationRegistry, custody_storage::PublicCustodyStore, serve_publication},
    publish,
    transfer::{TransferLimits, TransferProgress},
};

#[derive(Clone)]
struct DiskBackend {
    storage: PublicCustodyStore,
    staging_parent: PathBuf,
    registry: Weak<Mutex<PublicationRegistry>>,
}

struct Admission {
    source: ChunkStore,
    temporary: tempfile::TempDir,
    backend: DiskBackend,
    signed: SignedManifest,
    manifest: VerifiedManifest,
}

impl CustodyAdmission for Admission {
    fn store(&mut self) -> &mut ChunkStore {
        &mut self.source
    }
    fn commit(self: Box<Self>) -> CustodyFuture<'static, ()> {
        Box::pin(async move {
            let Self {
                mut source,
                temporary,
                backend,
                signed,
                manifest,
            } = *self;
            backend
                .storage
                .admit(&signed, &manifest, &mut source, protocol::now()?)
                .map_err(|_| CustodyError::Store)?;
            drop(source);
            temporary.close().map_err(|_| CustodyError::Store)?;
            let owner = backend.registry.upgrade().ok_or(CustodyError::Store)?;
            backend
                .storage
                .register_complete(&mut *owner.lock().await, protocol::now()?)
                .map_err(|_| CustodyError::Store)?;
            Ok(())
        })
    }
}

impl CustodyBackend for DiskBackend {
    fn begin_deposit(
        &self,
        signed: SignedManifest,
        manifest: VerifiedManifest,
    ) -> CustodyFuture<'_, Box<dyn CustodyAdmission>> {
        Box::pin(async move {
            let temporary =
                tempfile::tempdir_in(&self.staging_parent).map_err(|_| CustodyError::Store)?;
            let source = ChunkStore::create(&temporary.path().join("payload"), limits(16))
                .map_err(|_| CustodyError::Store)?;
            Ok(Box::new(Admission {
                source,
                temporary,
                backend: self.clone(),
                signed,
                manifest,
            }) as Box<dyn CustodyAdmission>)
        })
    }
    fn inspect(
        &self,
        _signed: SignedManifest,
        manifest: VerifiedManifest,
    ) -> CustodyFuture<'_, CustodyState> {
        Box::pin(async move {
            let complete = self
                .storage
                .inspect_complete(manifest.manifest_id(), protocol::now()?)
                .map_err(|_| CustodyError::Store)?
                .is_some();
            let owner = self.registry.upgrade().ok_or(CustodyError::Store)?;
            let ready = owner.lock().await.contains(manifest.manifest_id());
            Ok(if complete && ready {
                CustodyState::Complete
            } else {
                CustodyState::Missing
            })
        })
    }
}

fn limits(entries: usize) -> CacheLimits {
    CacheLimits {
        max_bytes: entries as u64 * CHUNK_BYTES as u64,
        max_entries: entries,
        min_free_bytes: 0,
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    source: ChunkStore,
    publisher: SigningKey,
    provider: Arc<SigningKey>,
    signed: SignedManifest,
    manifest: VerifiedManifest,
    registry: Arc<Mutex<PublicationRegistry>>,
    backend: DiskBackend,
}

async fn fixture(quota: usize, content_type: &str) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let mut source = ChunkStore::create(&directory.path().join("source"), limits(16)).unwrap();
    let publisher = SigningKey::generate(&mut rand_core::OsRng);
    let provider = Arc::new(SigningKey::generate(&mut rand_core::OsRng));
    let bytes: Vec<_> = [7, 13, 7]
        .into_iter()
        .flat_map(|byte| vec![byte; CHUNK_BYTES])
        .chain([9; 123])
        .collect();
    let at = protocol::now().unwrap();
    let signed = publish(
        &mut bytes.as_slice(),
        Publication {
            metadata: Metadata {
                name: "custody-wire".into(),
                revision: 1,
                content_type: content_type.into(),
            },
            length: bytes.len() as u64,
            validity: Validity {
                created: at,
                expires: at + 600,
            },
        },
        &publisher,
        &mut source,
    )
    .unwrap();
    let manifest = signed.verify(&publisher.verifying_key(), at).unwrap();
    let root = directory.path().join("custody");
    drop(ChunkStore::create(&root, limits(quota)).unwrap());
    let registry = Arc::new(Mutex::new(PublicationRegistry::new()));
    let backend = DiskBackend {
        storage: PublicCustodyStore::open(root, limits(quota)).unwrap(),
        staging_parent: directory.path().to_owned(),
        registry: Arc::downgrade(&registry),
    };
    registry
        .lock()
        .await
        .set_custody(Arc::new(CustodyService::new(
            Arc::clone(&provider),
            Arc::new(backend.clone()),
        )));
    Fixture {
        directory,
        source,
        publisher,
        provider,
        signed,
        manifest,
        registry,
        backend,
    }
}

async fn exchange(
    fixture: &mut Fixture,
    operation: CustodyOperation,
) -> (
    Result<CustodyReceipt, CustodyError>,
    Result<CustodyReceipt, CustodyError>,
    Result<TransferProgress, super::super::ProviderError>,
) {
    exchange_admitted(fixture, operation, TransferLimits::default(), |_| async {
        true
    })
    .await
}

async fn exchange_admitted<F, Fut>(
    fixture: &mut Fixture,
    operation: CustodyOperation,
    limits: TransferLimits,
    admit: F,
) -> (
    Result<CustodyReceipt, CustodyError>,
    Result<CustodyReceipt, CustodyError>,
    Result<TransferProgress, super::super::ProviderError>,
)
where
    F: FnMut(u64) -> Fut,
    Fut: Future<Output = bool>,
{
    let (mut application, mut local) = duplex(1024);
    let (mut remote, mut server) = duplex(1024);
    let registry = fixture.registry.lock().await.clone();
    let (send, receive) = oneshot::channel();
    let provider = fixture.provider.verifying_key().to_bytes();
    let signed = fixture.signed.clone();
    let publisher = &fixture.publisher;
    let source = &mut fixture.source;
    let client = async move {
        let challenge = receive.await.map_err(|_| CustodyError::Invalid)?;
        let authorization =
            CustodyAuthorization::sign(&challenge, operation, signed, publisher, protocol::now()?)?;
        execute(
            &mut application,
            &challenge,
            &authorization,
            (operation == CustodyOperation::Deposit).then_some(source),
            limits,
        )
        .await
    };
    let signed = fixture.signed.clone();
    let agent = async move {
        let challenge = begin(&mut remote, &provider).await?;
        send.send(challenge.clone())
            .map_err(|_| CustodyError::Invalid)?;
        bridge_with_admission(
            &mut local,
            &mut remote,
            &challenge,
            &signed,
            operation,
            limits,
            admit,
        )
        .await
    };
    let provider = async move { serve_publication(&mut server, &registry, limits).await };
    tokio::join!(client, agent, provider)
}

#[tokio::test]
async fn custody_chunk_admission_charges_actual_unique_requests_and_can_withhold() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let mut fixture = fixture(16, "application/octet-stream").await;
    let admitted = AtomicU64::new(0);
    let (client, agent, provider) = exchange_admitted(
        &mut fixture,
        CustodyOperation::Deposit,
        TransferLimits::default(),
        |bytes| {
            admitted.fetch_add(bytes, Ordering::SeqCst);
            async { false }
        },
    )
    .await;
    assert!(client.is_err() && agent.is_err() && provider.is_err());
    assert_eq!(admitted.load(Ordering::SeqCst), CHUNK_BYTES as u64);
    assert!(
        !fixture
            .registry
            .lock()
            .await
            .contains(fixture.manifest.manifest_id())
    );
    assert!(
        fixture
            .backend
            .storage
            .inspect_complete(fixture.manifest.manifest_id(), protocol::now().unwrap())
            .unwrap()
            .is_none()
    );

    admitted.store(0, Ordering::SeqCst);
    let (client, agent, provider) = exchange_admitted(
        &mut fixture,
        CustodyOperation::Deposit,
        TransferLimits::default(),
        |bytes| {
            admitted.fetch_add(bytes, Ordering::SeqCst);
            async { true }
        },
    )
    .await;
    assert_eq!(client.unwrap().encode(), agent.unwrap().encode());
    assert!(provider.is_ok());
    assert_eq!(
        admitted.load(Ordering::SeqCst),
        (2 * CHUNK_BYTES + 123) as u64
    );
}

#[tokio::test]
async fn custody_waiting_chunk_admission_keeps_original_deadline() {
    use std::{
        future::pending,
        sync::atomic::{AtomicBool, Ordering},
        time::Duration,
    };
    let mut fixture = fixture(16, "application/octet-stream").await;
    let called = AtomicBool::new(false);
    let limits = TransferLimits {
        exchange_timeout: Duration::from_millis(150),
        session_timeout: Duration::from_secs(1),
        ..TransferLimits::default()
    };
    let (client, agent, provider) = tokio::time::timeout(
        Duration::from_secs(3),
        exchange_admitted(&mut fixture, CustodyOperation::Deposit, limits, |_| {
            called.store(true, Ordering::SeqCst);
            pending::<bool>()
        }),
    )
    .await
    .unwrap();
    assert!(called.load(Ordering::SeqCst));
    assert!(client.is_err() && agent.is_err() && provider.is_err());
    assert!(
        !fixture
            .registry
            .lock()
            .await
            .contains(fixture.manifest.manifest_id())
    );
}

#[tokio::test]
async fn signed_deposit_inspect_bridge_reopens_actual_journal_without_renewal() {
    let mut fixture = fixture(16, "application/octet-stream").await;
    let (client, bridge, provider) = exchange(&mut fixture, CustodyOperation::Inspect).await;
    assert_eq!(client.unwrap().state(), CustodyState::Missing);
    assert_eq!(bridge.unwrap().state(), CustodyState::Missing);
    assert_eq!(provider.unwrap().bytes, 0);
    for _ in 0..2 {
        let (client, bridge, provider) = exchange(&mut fixture, CustodyOperation::Deposit).await;
        let receipt = client.unwrap();
        assert_eq!(receipt.encode(), bridge.unwrap().encode());
        assert_eq!(receipt.state(), CustodyState::Complete);
        assert_eq!(receipt.manifest_id(), fixture.manifest.manifest_id());
        assert_eq!(
            receipt.original_expiry(),
            fixture.manifest.validity().expires
        );
        assert_eq!(receipt.object_bytes(), 3 * CHUNK_BYTES as u64 + 123);
        assert_eq!(receipt.unique_chunks(), 3);
        assert_eq!(
            provider.unwrap().bytes,
            2 * CHUNK_BYTES as u64 + 123,
            "unique actual uploaded chunks, not repeated logical references"
        );
    }
    // Drop the active service owner and reconstruct ready serving from its original journal.
    let registry = Arc::new(Mutex::new(PublicationRegistry::new()));
    let storage =
        PublicCustodyStore::open(fixture.directory.path().join("custody"), limits(16)).unwrap();
    storage
        .register_complete(&mut *registry.lock().await, protocol::now().unwrap())
        .unwrap();
    fixture.backend = DiskBackend {
        storage,
        staging_parent: fixture.directory.path().to_owned(),
        registry: Arc::downgrade(&registry),
    };
    registry
        .lock()
        .await
        .set_custody(Arc::new(CustodyService::new(
            Arc::clone(&fixture.provider),
            Arc::new(fixture.backend.clone()),
        )));
    fixture.registry = registry;
    let (client, bridge, provider) = exchange(&mut fixture, CustodyOperation::Inspect).await;
    let receipt = client.unwrap();
    assert_eq!(receipt.state(), CustodyState::Complete);
    assert_eq!(
        receipt.original_expiry(),
        fixture.manifest.validity().expires
    );
    assert_eq!(receipt.encode(), bridge.unwrap().encode());
    assert_eq!(provider.unwrap().bytes, 0);
    // Actual retained data is re-read on Inspect; the earlier valid receipt cannot hide loss.
    let root = fixture.directory.path().join("custody");
    let mut store = ChunkStore::open(&root, limits(16)).unwrap();
    store
        .remove_owned_chunk(*fixture.manifest.chunks()[0].id())
        .unwrap();
    drop(store);
    let (client, bridge, provider) = exchange(&mut fixture, CustodyOperation::Inspect).await;
    assert!(client.is_err() && bridge.is_err() && provider.is_err());
}

#[tokio::test]
async fn failed_partial_quota_or_private_deposit_never_yields_committed_receipt() {
    for mode in ["quota", "partial", "private"] {
        let mut fixture = fixture(
            if mode == "quota" { 1 } else { 16 },
            if mode == "private" {
                crate::private_message::PRIVATE_MESSAGE_CONTENT_TYPE
            } else {
                "application/octet-stream"
            },
        )
        .await;
        if mode == "partial" {
            fixture
                .source
                .remove_owned_chunk(*fixture.manifest.chunks()[1].id())
                .unwrap();
        }
        let (client, bridge, provider) = exchange(&mut fixture, CustodyOperation::Deposit).await;
        assert!(
            client.is_err() && bridge.is_err() && provider.is_err(),
            "{mode}"
        );
        assert!(
            !fixture
                .registry
                .lock()
                .await
                .contains(fixture.manifest.manifest_id())
        );
        assert!(
            fixture
                .backend
                .storage
                .inspect_complete(fixture.manifest.manifest_id(), protocol::now().unwrap())
                .unwrap()
                .is_none()
        );
    }
}

#[tokio::test]
async fn challenges_authorizations_and_receipts_reject_replay_substitution_and_expiry() {
    let fixture = fixture(16, "application/octet-stream").await;
    let at = protocol::now().unwrap();
    let first = CustodyChallenge::new(&fixture.provider, at).unwrap();
    let second = CustodyChallenge::new(&fixture.provider, at).unwrap();
    let auth = CustodyAuthorization::sign(
        &first,
        CustodyOperation::Inspect,
        fixture.signed.clone(),
        &fixture.publisher,
        at,
    )
    .unwrap();
    assert!(CustodyAuthorization::decode(&auth.encode(), &second, at).is_err());
    assert!(
        CustodyAuthorization::decode(&auth.encode(), &first, fixture.manifest.validity().expires)
            .is_err()
    );
    let other = SigningKey::generate(&mut rand_core::OsRng);
    assert!(
        CustodyChallenge::decode(&first.encode(), other.verifying_key().as_bytes(), at).is_err()
    );
    assert!(
        CustodyAuthorization::sign(
            &first,
            CustodyOperation::Deposit,
            fixture.signed.clone(),
            &other,
            at
        )
        .is_err()
    );
    let mut unsupported = auth.encode();
    unsupported.extend_from_slice(&[0x98, 0x06, 1]);
    assert!(CustodyAuthorization::decode(&unsupported, &first, at).is_err());
    let receipt = CustodyReceipt::new(&fixture.provider, &auth, CustodyState::Missing, at).unwrap();
    let next = CustodyAuthorization::sign(
        &second,
        CustodyOperation::Inspect,
        fixture.signed.clone(),
        &fixture.publisher,
        at,
    )
    .unwrap();
    assert!(CustodyReceipt::decode(&receipt.encode(), &next, at).is_err());
    assert!(CustodyReceipt::new(&other, &auth, CustodyState::Missing, at).is_err());
    let deposit = CustodyAuthorization::sign(
        &first,
        CustodyOperation::Deposit,
        fixture.signed,
        &fixture.publisher,
        at,
    )
    .unwrap();
    assert!(CustodyReceipt::new(&fixture.provider, &deposit, CustodyState::Missing, at).is_err());
}
