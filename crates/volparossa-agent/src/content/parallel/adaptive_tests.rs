//! Actual v1 selector/chunk streams through the production assignment/lease driver gate.

use std::{
    sync::atomic::{AtomicUsize, Ordering},
    time::Duration,
};

use ed25519_dalek::SigningKey;
use tokio::io::duplex;
use tokio::time::Instant;
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkStore, Metadata, Publication, Validity, VerifiedManifest,
    provider::{PublicationRegistry, pull_publication_worker, serve_publication},
    publish, reassemble,
    transfer::{TransferLimits, parallel::ParallelDownload},
};

use super::{ContentError, drivers, now, receive_workers};
use crate::content::worker_budget::WorkerBudget;

struct Fixture {
    _directory: tempfile::TempDir,
    manifest: VerifiedManifest,
    cache: ChunkStore,
    registries: Vec<PublicationRegistry>,
    bytes: Vec<u8>,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let limits = CacheLimits {
        max_bytes: 12 * CHUNK_BYTES as u64,
        max_entries: 12,
        min_free_bytes: 0,
    };
    let bytes = (1..=12_u8)
        .flat_map(|value| vec![value; CHUNK_BYTES])
        .collect::<Vec<_>>();
    let signer = SigningKey::from_bytes(&[63; 32]);
    let root = directory.path().join("source");
    let mut source = ChunkStore::create(&root, limits).unwrap();
    let envelope = publish(
        &mut bytes.as_slice(),
        Publication {
            length: bytes.len() as u64,
            metadata: Metadata {
                name: "adaptive-worker-proof".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            validity: Validity {
                created: now(),
                expires: now() + 60,
            },
        },
        &signer,
        &mut source,
    )
    .unwrap();
    let manifest = envelope.verify(&signer.verifying_key(), now()).unwrap();
    let mut registries = Vec::new();
    for provider in 0..4 {
        let root = directory.path().join(format!("provider-{provider}"));
        let mut store = ChunkStore::create(&root, limits).unwrap();
        for chunk in manifest.chunks() {
            store
                .put_verified(*chunk.id(), &source.get(chunk.id()).unwrap().unwrap())
                .unwrap();
        }
        drop(store);
        let mut registry = PublicationRegistry::new();
        registry
            .register(manifest.clone(), root, limits, now())
            .unwrap();
        registries.push(registry);
    }
    let cache = ChunkStore::create(&directory.path().join("receiver"), limits).unwrap();
    Fixture {
        _directory: directory,
        manifest,
        cache,
        registries,
        bytes,
    }
}

#[tokio::test]
async fn adaptive_workers_open_three_real_provider_streams_with_resource_leases_and_exact_hash() {
    tokio::time::timeout(Duration::from_secs(15), actual_streams())
        .await
        .expect("all driver and writer owners finish within one deadline");
}

async fn actual_streams() {
    let Fixture {
        _directory,
        manifest,
        mut cache,
        registries,
        bytes,
    } = fixture();
    // Three stream allowances come from explicit memory/FD headroom, not a product count cap.
    let budget = WorkerBudget::for_test(3 * 32 * 8 * 1024 * 1024, 3 * 4 * 8, false);
    let active = AtomicUsize::new(0);
    let peak = AtomicUsize::new(0);
    let opened = AtomicUsize::new(0);
    let limits = TransferLimits {
        max_requests: 12,
        max_bytes: bytes.len() as u64,
        exchange_timeout: Duration::from_secs(5),
        session_timeout: Duration::from_secs(10),
    };
    let deadline = Instant::now() + limits.session_timeout;
    let (download, workers) = ParallelDownload::new_adaptive(
        &manifest,
        registries.len(),
        &mut cache,
        limits,
        budget.allowance(0),
    )
    .unwrap();
    let active = &active;
    let peak = &peak;
    let opened = &opened;
    let tasks = workers
        .into_iter()
        .zip(&registries)
        .map(|(worker, registry)| {
            drivers::assigned(
                worker,
                deadline,
                active,
                || budget.try_acquire(),
                move |mut worker| async move {
                    opened.fetch_add(1, Ordering::SeqCst);
                    peak.fetch_max(active.load(Ordering::SeqCst), Ordering::SeqCst);
                    // The actual connection is created only inside the assignment+lease gate.
                    let (mut client, mut server) = duplex(4096);
                    let (received, sent) = tokio::join!(
                        pull_publication_worker(&mut client, &mut worker),
                        serve_publication(&mut server, registry, limits)
                    );
                    received.map_err(|_| ContentError::Unavailable)?;
                    sent.map_err(|_| ContentError::Unavailable)?;
                    Ok(true)
                },
            )
        })
        .collect();
    let (progress, measurements, timed_out) = receive_workers(
        download,
        &mut cache,
        tasks,
        || budget.allowance(active.load(Ordering::Acquire)),
        deadline,
    )
    .await
    .unwrap();
    assert!(!timed_out);
    assert_eq!(peak.load(Ordering::SeqCst), 3);
    assert!(opened.load(Ordering::SeqCst) >= 3);
    assert!(progress.iter().filter(|item| item.bytes > 0).count() >= 3);
    assert_eq!(
        progress.iter().map(|item| item.bytes).sum::<u64>(),
        bytes.len() as u64
    );
    assert_eq!(progress.iter().map(|item| item.chunks).sum::<usize>(), 12);
    assert!(
        measurements
            .iter()
            .filter(|item| item.elapsed.is_some())
            .count()
            >= 3
    );
    assert_eq!(active.load(Ordering::SeqCst), 0);
    assert_eq!(budget.available_workers(), 3);
    let mut output = Vec::new();
    reassemble(&manifest, &mut [&mut cache], now(), &mut output).unwrap();
    assert_eq!(output, bytes);
}

#[tokio::test]
async fn adaptive_worker_lease_race_and_dormant_completion_never_open_a_stream() {
    let Fixture {
        _directory,
        manifest,
        mut cache,
        ..
    } = fixture();
    let budget = WorkerBudget::for_test(0, 0, false);
    let active = AtomicUsize::new(0);
    let deadline = Instant::now() + Duration::from_secs(2);
    // The initial advisory allowance existed, but the last-moment resource lease is gone.
    let (download, workers) =
        ParallelDownload::new_adaptive(&manifest, 3, &mut cache, TransferLimits::default(), 1)
            .unwrap();
    let tasks = workers
        .into_iter()
        .map(|worker| {
            drivers::assigned(
                worker,
                deadline,
                &active,
                || budget.try_acquire(),
                |_| async { panic!("no protected stream without an actual resource lease") },
            )
        })
        .collect();
    let (progress, measurements, timed_out) =
        receive_workers(download, &mut cache, tasks, || 1, deadline)
            .await
            .unwrap();
    assert!(
        !timed_out,
        "closed/dormant workers do not wait for the deadline"
    );
    assert!(progress.iter().all(|item| item.bytes == 0));
    assert!(
        measurements
            .iter()
            .all(|item| !item.attempted && item.elapsed.is_none())
    );
    assert_eq!(active.load(Ordering::SeqCst), 0);
}
