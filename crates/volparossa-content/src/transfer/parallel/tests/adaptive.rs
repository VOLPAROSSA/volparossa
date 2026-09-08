//! Actual v1 provider selectors and bounded chunk streams, created only after assignment.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

mod stream;

use super::{
    CHUNK_BYTES, CacheLimits, ChunkStore, ChunkWorker, Duration, Metadata, OsRng, ParallelDownload,
    Publication, PublicationRegistry, SigningKey, SystemTime, TransferLimits, TransferProgress,
    UNIX_EPOCH, Validity, VerifiedManifest, publish, pull_publication_worker, reassemble,
    serve_publication,
};
use crate::SignedManifest;

#[derive(Clone, Copy)]
enum Case {
    Complementary,
    Failed,
    Serial,
    NoResources,
    Many,
    Pressure,
}

struct Fixture {
    _directory: tempfile::TempDir,
    manifest: VerifiedManifest,
    transports: Vec<VerifiedManifest>,
    providers: Vec<PublicationRegistry>,
    output: ChunkStore,
    bytes: Vec<u8>,
}

fn fixture(case: Case) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let cache_limits = CacheLimits {
        max_bytes: 16 * CHUNK_BYTES as u64,
        max_entries: 16,
        min_free_bytes: 0,
    };
    let mut source = ChunkStore::create(&directory.path().join("source"), cache_limits).unwrap();
    let bytes: Vec<_> = (1_u8..=9)
        .chain([1])
        .flat_map(|b| vec![b; CHUNK_BYTES])
        .collect();
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let publisher = SigningKey::generate(&mut OsRng);
    let publication = Publication {
        metadata: Metadata {
            name: "adaptive-public".into(),
            content_type: "application/octet-stream".into(),
            revision: 1,
        },
        length: bytes.len() as u64,
        validity: Validity {
            created: now,
            expires: now + 120,
        },
    };
    let signed = publish(
        &mut bytes.as_slice(),
        publication.clone(),
        &publisher,
        &mut source,
    )
    .unwrap();
    let manifest = signed.verify(&publisher.verifying_key(), now).unwrap();
    let count = if matches!(case, Case::Many) { 10 } else { 3 };
    let mut providers = Vec::new();
    let mut transports = Vec::new();
    for index in 0..count {
        let key = SigningKey::generate(&mut OsRng);
        let signed = SignedManifest::sign(
            publication.clone(),
            manifest.chunks().to_vec(),
            *manifest.object_sha256(),
            &key,
        )
        .unwrap();
        let transport = signed.verify(&key.verifying_key(), now).unwrap();
        assert_ne!(manifest.manifest_id(), transport.manifest_id());
        let path = directory.path().join(format!("peer-{index}"));
        let mut store = ChunkStore::create(&path, cache_limits).unwrap();
        for (position, chunk) in manifest.chunks().iter().take(9).enumerate() {
            let owns = match case {
                Case::Failed => index > 0,
                Case::Pressure => true,
                Case::Many => index == 9,
                _ => position % 3 == index,
            };
            if owns {
                store
                    .put_verified(*chunk.id(), &source.get(chunk.id()).unwrap().unwrap())
                    .unwrap();
            }
        }
        drop(store);
        let mut registry = PublicationRegistry::new();
        registry
            .register_signed(signed, &key.verifying_key(), path, cache_limits, now)
            .unwrap();
        providers.push(registry);
        transports.push(transport);
    }
    let output = ChunkStore::create(&directory.path().join("receiver"), cache_limits).unwrap();
    Fixture {
        _directory: directory,
        manifest,
        transports,
        providers,
        output,
        bytes,
    }
}

struct Active(Arc<AtomicUsize>);
impl Drop for Active {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

#[derive(Clone, Default)]
struct Counters {
    active: Arc<AtomicUsize>,
    maximum: Arc<AtomicUsize>,
    opened: Arc<AtomicUsize>,
    allowance: Arc<AtomicUsize>,
    drained_payload: Arc<AtomicUsize>,
}

#[tokio::test]
async fn adaptive_original_indexes_use_three_providers_and_preserve_progress_under_resource_limits()
{
    for case in [
        Case::Complementary,
        Case::Failed,
        Case::Serial,
        Case::NoResources,
        Case::Many,
        Case::Pressure,
    ] {
        tokio::time::timeout(Duration::from_secs(10), transfer(case))
            .await
            .expect("bounded adaptive proof");
    }
}

async fn transfer(case: Case) {
    let Fixture {
        _directory,
        manifest,
        transports,
        providers,
        mut output,
        bytes,
    } = fixture(case);
    let allowance = match case {
        Case::NoResources => 0,
        Case::Serial | Case::Many => 1,
        _ => 3,
    };
    let limits = TransferLimits {
        session_timeout: Duration::from_secs(8),
        ..TransferLimits::default()
    };
    let refs: Vec<_> = transports.iter().collect();
    let (download, workers) = ParallelDownload::new_adaptive_with_transport_manifests(
        &manifest,
        &refs,
        &mut output,
        limits,
        allowance,
    )
    .unwrap();
    assert!(
        download
            .peers
            .iter()
            .filter(|p| p.state == super::super::adaptive::PeerState::Active)
            .count()
            <= 2
    );
    let counters = Counters::default();
    counters.allowance.store(allowance, Ordering::SeqCst);
    let mut drivers = Vec::new();
    for (index, (worker, provider)) in workers.into_iter().zip(providers).enumerate() {
        drivers.push(tokio::spawn(drive(
            worker,
            provider,
            counters.clone(),
            limits,
            case,
            index,
        )));
    }
    let mut progress = vec![TransferProgress::default(); transports.len()];
    download
        .run_with_allowance(&mut output, &mut progress, || {
            counters.allowance.load(Ordering::SeqCst)
        })
        .await
        .unwrap();
    let mut sent = 0;
    for driver in drivers {
        sent += driver.await.unwrap().bytes;
    }
    assert_eq!(counters.active.load(Ordering::SeqCst), 0);
    assert_eq!(sent, progress.iter().map(|p| p.bytes).sum::<u64>());
    if matches!(case, Case::Pressure) {
        assert_eq!(counters.maximum.load(Ordering::SeqCst), 3);
        assert_eq!(counters.allowance.load(Ordering::SeqCst), 1);
        assert!(
            counters.drained_payload.load(Ordering::SeqCst) > CHUNK_BYTES,
            "actual payload continued after surplus streams closed: drained={} progress={progress:?}",
            counters.drained_payload.load(Ordering::SeqCst)
        );
    }
    if matches!(case, Case::NoResources) {
        assert_eq!(counters.opened.load(Ordering::SeqCst), 0);
        assert_eq!(sent, 0);
    } else {
        check_progress(
            case,
            &progress,
            sent,
            counters.maximum.load(Ordering::SeqCst),
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut reconstructed = Vec::new();
        reassemble(&manifest, &mut [&mut output], now, &mut reconstructed).unwrap();
        assert_eq!(reconstructed, bytes);
    }
}

async fn drive(
    mut worker: ChunkWorker,
    provider: PublicationRegistry,
    counters: Counters,
    limits: TransferLimits,
    case: Case,
    index: usize,
) -> TransferProgress {
    if !worker.wait_for_assignment().await.unwrap() {
        return TransferProgress::default();
    }
    let running = counters.active.fetch_add(1, Ordering::SeqCst) + 1;
    let _lease = Active(counters.active.clone());
    assert!(
        running <= counters.allowance.load(Ordering::SeqCst),
        "no socket without resource capacity"
    );
    counters.maximum.fetch_max(running, Ordering::SeqCst);
    counters.opened.fetch_add(1, Ordering::SeqCst);
    let (client, mut server) = tokio::io::duplex(1024);
    if matches!(case, Case::Pressure) && running == 3 {
        counters.allowance.store(1, Ordering::SeqCst);
    }
    let mut client = stream::MeasuredStream {
        inner: client,
        active: counters.active,
        allowance: counters.allowance,
        drained_payload: counters.drained_payload,
    };
    if matches!(case, Case::Failed) && index == 0 {
        drop(server);
        assert!(
            pull_publication_worker(&mut client, &mut worker)
                .await
                .is_err()
        );
        return TransferProgress::default();
    }
    let (pulled, sent) = tokio::join!(
        pull_publication_worker(&mut client, &mut worker),
        serve_publication(&mut server, &provider, limits),
    );
    pulled.unwrap();
    sent.unwrap()
}

fn check_progress(case: Case, progress: &[TransferProgress], sent: u64, maximum: usize) {
    assert_eq!(
        progress.iter().map(|p| p.chunks).sum::<usize>(),
        9,
        "one claim for each unique chunk"
    );
    assert_eq!(sent, 9 * CHUNK_BYTES as u64);
    if matches!(case, Case::Complementary) {
        assert_eq!(maximum, 3);
        assert!(progress.iter().all(|p| p.bytes > 0));
    }
    if matches!(case, Case::Many) {
        assert_eq!(progress[9].chunks, 9);
    }
}
