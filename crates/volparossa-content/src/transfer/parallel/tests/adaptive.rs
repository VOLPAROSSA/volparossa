//! Actual v1 provider selectors and bounded chunk streams, created only after assignment.

use std::sync::{
    Arc,
    atomic::{AtomicUsize, Ordering},
};

mod retirement;
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
    PressureComplementary,
    RetiredCoverage,
    RetiredDuplicate,
    PressureCoverage,
}

impl Case {
    fn allowance(self) -> usize {
        match self {
            Self::NoResources => 0,
            Self::Serial | Self::Many => 1,
            _ => 3,
        }
    }
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
                Case::Pressure | Case::RetiredDuplicate => true,
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

#[test]
fn admitted_probe_gets_missing_assignment_before_established_peer_refills() {
    let Fixture {
        _directory,
        manifest,
        mut output,
        ..
    } = fixture(Case::Complementary);
    let (mut download, mut workers) =
        ParallelDownload::new_adaptive(&manifest, 3, &mut output, TransferLimits::default(), 3)
            .unwrap();
    download.assign_ready().unwrap();
    let initial = [
        workers[0].requests.try_recv(),
        workers[1].requests.try_recv(),
    ];
    assert!(initial.iter().all(Result::is_ok));
    assert!(
        workers[2].requests.try_recv().is_err(),
        "dormant until useful work"
    );
    let mut progress = vec![TransferProgress::default(); 3];
    download
        .accept(1, Some(Ok(None)), &mut output, &mut progress)
        .unwrap();
    download
        .accept(
            0,
            Some(Ok(Some(vec![1; CHUNK_BYTES]))),
            &mut output,
            &mut progress,
        )
        .unwrap();
    download.adjust_width(3);
    assert!(download.peers[2].probing);
    download.assign_ready().unwrap();
    assert_eq!(
        download.peers[2].pending,
        Some(1),
        "probe tests observed missing coverage"
    );
    assert_eq!(
        download.peers[1].pending,
        Some(3),
        "missing provider tries a different chunk"
    );
    assert_eq!(
        download.peers[0].pending,
        Some(2),
        "established peer continues useful work"
    );
    assert_eq!(download.chunks[1].owner, Some(2));
    assert_eq!(
        download.chunks[1]
            .attempted
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        [1, 2]
    );
    download.assign_ready().unwrap();
    assert_eq!(
        download.peers[2].pending,
        Some(1),
        "never duplicate or replace in-flight work"
    );
}

#[test]
fn probe_prioritizes_observed_miss_over_unattempted_manifest_membership() {
    let Fixture {
        _directory,
        manifest,
        mut output,
        ..
    } = fixture(Case::Complementary);
    let (mut download, _workers) =
        ParallelDownload::new_adaptive(&manifest, 3, &mut output, TransferLimits::default(), 3)
            .unwrap();
    // A prior provider's completed miss is known, but a manifest reference alone says
    // nothing about which cache owns any of the earlier, still-unattempted chunks.
    download.chunks[4].attempted.insert(0);
    download.explore = true;
    download.adjust_width(3);
    download.assign_ready().unwrap();
    assert_eq!(download.peers[2].pending, Some(4));
    assert_eq!(download.peers[0].pending, Some(0));
    assert_eq!(download.peers[1].pending, Some(1));
    assert_eq!(
        download.chunks[4]
            .attempted
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        [0, 2]
    );
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

#[tokio::test]
async fn slow_probe_retirement_must_not_discard_later_complementary_chunks() {
    tokio::time::timeout(Duration::from_secs(10), transfer(Case::RetiredCoverage))
        .await
        .expect("bounded complementary coverage after an unsuccessful rate probe");
}

#[tokio::test]
async fn unsuccessful_probe_gets_no_speculative_credits_when_other_peers_cover_the_object() {
    tokio::time::timeout(Duration::from_secs(10), transfer(Case::RetiredDuplicate))
        .await
        .expect("bounded transfer without unnecessary probe payload");
}

#[tokio::test]
async fn hard_pressure_preserves_partial_progress_but_does_not_claim_full_object_success() {
    tokio::time::timeout(Duration::from_secs(10), transfer(Case::PressureCoverage))
        .await
        .expect("hard resource pressure takes precedence over complementary coverage");
}

#[tokio::test]
async fn dynamic_pressure_preserves_disjoint_provider_coverage_with_serial_continuation() {
    tokio::time::timeout(
        Duration::from_secs(10),
        transfer(Case::PressureComplementary),
    )
    .await
    .expect("bounded disjoint coverage after three streams drain to one");
}

fn reject_speed_probe(download: &mut ParallelDownload) {
    // Fix only the performance history, not any content/transport response:
    // a third admitted probe did not improve the preceding aggregate rate.
    // Its untested complementary shards still need the actual v1 streams.
    // No wall-clock race decides whether this branch is exercised.
    download.peers[2].state = super::super::adaptive::PeerState::Active;
    download.peers[2].probing = true;
    download.probe_baseline = Some(u64::MAX);
    for index in 0..3 {
        download.record_sample(index, 1, false);
    }
    assert!(download.growth_blocked);
    assert!(download.peers[2].coverage_only);
    assert!(!download.peers[2].probing);
}

#[test]
fn coverage_only_peer_waits_for_alternative_misses_and_never_duplicates_an_assignment() {
    let Fixture {
        _directory,
        manifest,
        mut output,
        ..
    } = fixture(Case::Complementary);
    let (mut download, mut workers) =
        ParallelDownload::new_adaptive(&manifest, 3, &mut output, TransferLimits::default(), 3)
            .unwrap();
    reject_speed_probe(&mut download);
    download.assign_ready().unwrap();
    assert_eq!(download.peers[0].pending, Some(0));
    assert_eq!(download.peers[1].pending, Some(1));
    assert_eq!(download.peers[2].pending, None);
    assert!(workers[2].requests.try_recv().is_err());
    let mut progress = vec![TransferProgress::default(); 3];
    // A completed miss releases a chunk, but the other ordinary peer still gets
    // its own attempt first. Remove only the consumed queue credit each time.
    for index in [0, 1, 1] {
        workers[index].requests.try_recv().unwrap();
        download
            .accept(index, Some(Ok(None)), &mut output, &mut progress)
            .unwrap();
        download.assign_ready().unwrap();
    }
    assert_eq!(download.peers[2].pending, Some(0));
    assert_eq!(download.chunks[0].owner, Some(2));
    assert_eq!(
        download.chunks[0]
            .attempted
            .iter()
            .copied()
            .collect::<Vec<_>>(),
        [0, 1, 2]
    );
    workers[2].requests.try_recv().unwrap();
    download.assign_ready().unwrap();
    assert!(workers[2].requests.try_recv().is_err());
    assert_eq!(download.peers[2].pending, Some(0));
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
    let allowance = case.allowance();
    let limits = TransferLimits {
        session_timeout: Duration::from_secs(8),
        ..TransferLimits::default()
    };
    let refs: Vec<_> = transports.iter().collect();
    let (mut download, workers) = ParallelDownload::new_adaptive_with_transport_manifests(
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
    if matches!(case, Case::RetiredCoverage | Case::RetiredDuplicate) {
        reject_speed_probe(&mut download);
    }
    if matches!(case, Case::PressureCoverage) {
        reject_speed_probe(&mut download);
        // Pressure also closes a coverage-only peer; it cannot bypass a hard
        // allowance just because it might own the only remaining fragments.
        download.adjust_width(1);
    }
    let counters = Counters::default();
    counters.allowance.store(
        if matches!(case, Case::PressureCoverage) {
            1
        } else {
            allowance
        },
        Ordering::SeqCst,
    );
    let mut drivers = Vec::new();
    let providers = providers.into_iter().map(Arc::new).collect::<Vec<_>>();
    for (index, (worker, provider)) in workers
        .into_iter()
        .zip(providers.iter().cloned())
        .enumerate()
    {
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
    let retired = download
        .run_with_allowance_retired(&mut output, &mut progress, || {
            counters.allowance.load(Ordering::SeqCst)
        })
        .await
        .unwrap();
    let mut sent = 0;
    for driver in drivers {
        sent += driver.await.unwrap().bytes;
    }
    if matches!(case, Case::PressureComplementary) {
        assert!(!retired.is_empty());
        assert!(progress.iter().map(|part| part.chunks).sum::<usize>() < 9);
        sent += retirement::continue_streams(
            retired,
            &manifest,
            &transports,
            &providers,
            &mut output,
            &mut progress,
            &counters,
        )
        .await;
        assert!(counters.opened.load(Ordering::SeqCst) <= 6);
    }
    check_result(
        case,
        &counters,
        &progress,
        sent,
        &manifest,
        &mut output,
        &bytes,
    );
}

fn check_result(
    case: Case,
    counters: &Counters,
    progress: &[TransferProgress],
    sent: u64,
    manifest: &VerifiedManifest,
    output: &mut ChunkStore,
    bytes: &[u8],
) {
    assert_eq!(counters.active.load(Ordering::SeqCst), 0);
    assert_eq!(sent, progress.iter().map(|p| p.bytes).sum::<u64>());
    if matches!(case, Case::RetiredDuplicate) {
        assert_eq!(progress[2], TransferProgress::default());
        assert_eq!(counters.opened.load(Ordering::SeqCst), 2);
    }
    if matches!(case, Case::PressureCoverage) {
        assert_eq!(counters.opened.load(Ordering::SeqCst), 1);
        assert_eq!(counters.maximum.load(Ordering::SeqCst), 1);
        assert_eq!(progress.iter().map(|p| p.chunks).sum::<usize>(), 3);
        assert_eq!(sent, 3 * CHUNK_BYTES as u64);
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let result = reassemble(manifest, &mut [output], now, &mut Vec::new());
        assert!(matches!(result, Err(crate::Error::MissingChunk(_))));
        return;
    }
    if matches!(case, Case::Pressure | Case::PressureComplementary) {
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
            progress,
            sent,
            counters.maximum.load(Ordering::SeqCst),
        );
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs();
        let mut reconstructed = Vec::new();
        reassemble(manifest, &mut [output], now, &mut reconstructed).unwrap();
        assert_eq!(reconstructed, bytes);
    }
}

async fn drive(
    mut worker: ChunkWorker,
    provider: Arc<PublicationRegistry>,
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
    if matches!(case, Case::Pressure | Case::PressureComplementary) && running == 3 {
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
