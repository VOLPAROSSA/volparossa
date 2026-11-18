//! The production serial coordinator and lease driver over actual disjoint v1 streams.

use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::{
    io::duplex,
    sync::Notify,
    time::{Duration, Instant},
};
use volparossa_content::{
    ChunkStore, VerifiedManifest,
    provider::{pull_publication_worker, serve_publication},
    reassemble,
    transfer::{
        TransferLimits, TransferProgress,
        parallel::{ChunkWorker, ParallelDownload, ResourceRetired},
    },
};

use super::{Fixture, fixture_with_disjoint};
use crate::content::{
    ContentError, now,
    parallel::{
        continuation::{
            RetiredBatch, Sources,
            diagnostics::{Diagnostics, tests::Capture},
        },
        drivers, receive_workers_retired,
    },
    worker_budget::{BatchBudget, WorkerBudget},
};

struct Prepared {
    fixture: Fixture,
    progress: Vec<TransferProgress>,
    measurements: Vec<drivers::Measurement>,
    retired: Vec<ResourceRetired>,
    deadline: Instant,
}

async fn prepare() -> Prepared {
    let mut fixture = fixture_with_disjoint(true);
    let budget = WorkerBudget::for_test(3 * 32 * 8 * 1024 * 1024, 3 * 4 * 8, false);
    let batch = budget.for_test_batch();
    let active = AtomicUsize::new(0);
    let opened = AtomicUsize::new(0);
    let allowance = AtomicUsize::new(3);
    let limits = TransferLimits {
        max_requests: 12,
        max_bytes: fixture.bytes.len() as u64,
        exchange_timeout: Duration::from_secs(5),
        session_timeout: Duration::from_secs(10),
    };
    let deadline = Instant::now() + limits.session_timeout;
    let (download, workers) =
        ParallelDownload::new_adaptive(&fixture.manifest, 3, &mut fixture.cache, limits, 3)
            .unwrap();
    let opened = &opened;
    let allowance = &allowance;
    let tasks = workers
        .into_iter()
        .zip(&fixture.registries)
        .map(|(worker, registry)| {
            drivers::assigned(
                worker,
                deadline,
                &active,
                || batch.try_acquire(),
                move |mut worker| async move {
                    if opened.fetch_add(1, Ordering::SeqCst) == 2 {
                        allowance.store(1, Ordering::SeqCst);
                    }
                    let (mut client, mut server) = duplex(4096);
                    let (received, sent) = tokio::join!(
                        pull_publication_worker(&mut client, &mut worker),
                        serve_publication(&mut server, registry, limits),
                    );
                    received.map_err(|_| ContentError::Unavailable)?;
                    sent.map_err(|_| ContentError::Unavailable)?;
                    Ok(true)
                },
            )
        })
        .collect();
    let (progress, measurements, expired, retired) = receive_workers_retired(
        download,
        &mut fixture.cache,
        tasks,
        || {
            batch
                .allowance(active.load(Ordering::Acquire))
                .min(allowance.load(Ordering::SeqCst))
        },
        deadline,
    )
    .await
    .unwrap();
    assert!(!expired);
    assert_eq!(opened.load(Ordering::SeqCst), 3);
    assert_eq!(
        active.load(Ordering::SeqCst),
        0,
        "join original leases before continuation"
    );
    assert!(!retired.is_empty());
    assert!(progress.iter().map(|part| part.bytes).sum::<u64>() < fixture.bytes.len() as u64);
    assert!(
        measurements
            .iter()
            .all(|measurement| measurement.elapsed.is_some())
    );
    assert_eq!(batch.snapshot_for_test().unwrap()["peak_leases"], 3);
    Prepared {
        fixture,
        progress,
        measurements,
        retired,
        deadline,
    }
}

#[derive(Clone, Copy)]
enum Mode {
    Complete,
    Failed,
    Cancel,
    PolicyAfterProgress,
}

struct ActualSources<'a> {
    fixture_manifest: &'a VerifiedManifest,
    registries: &'a [volparossa_content::provider::PublicationRegistry],
    budget: &'a BatchBudget<'a>,
    deadline: Instant,
    active: AtomicUsize,
    opened: [AtomicUsize; 3],
    mode: Mode,
    started: Notify,
}

impl Sources for ActualSources<'_> {
    fn available(&self) -> bool {
        self.budget.available_workers() > 0
    }
    fn active_workers(&self) -> &AtomicUsize {
        &self.active
    }
    fn transport(&self, _: usize) -> &VerifiedManifest {
        self.fixture_manifest
    }
    async fn receive(
        &self,
        index: usize,
        download: ParallelDownload,
        worker: ChunkWorker,
        store: &mut ChunkStore,
        diagnostic: &Diagnostics<'_>,
    ) -> Result<(TransferProgress, bool), ContentError> {
        assert_eq!(self.active.load(Ordering::SeqCst), 0, "serial continuation");
        let driver = drivers::assigned(
            worker,
            self.deadline,
            &self.active,
            || self.budget.try_acquire(),
            |mut worker| async {
                diagnostic.admitted();
                assert_eq!(
                    self.opened[index].fetch_add(1, Ordering::SeqCst),
                    0,
                    "single-use retirement"
                );
                assert_eq!(self.active.load(Ordering::SeqCst), 1);
                if matches!(self.mode, Mode::Cancel) {
                    self.started.notify_one();
                    let result = std::future::pending::<Result<bool, ContentError>>().await;
                    drop(worker);
                    return result;
                }
                let (mut client, mut server) = duplex(4096);
                if matches!(self.mode, Mode::Failed) {
                    drop(server);
                    return pull_publication_worker(&mut client, &mut worker)
                        .await
                        .map(|()| true)
                        .map_err(|_| ContentError::Unavailable);
                }
                let (received, sent) = tokio::join!(
                    pull_publication_worker(&mut client, &mut worker),
                    serve_publication(
                        &mut server,
                        &self.registries[index],
                        TransferLimits::default()
                    ),
                );
                received.map_err(|_| ContentError::Unavailable)?;
                sent.map_err(|_| ContentError::Unavailable)?;
                Ok(true)
            },
        );
        let (progress, _, expired, retired) = receive_workers_retired(
            download,
            store,
            vec![driver],
            || self.budget.allowance(self.active.load(Ordering::Acquire)),
            self.deadline,
        )
        .await?;
        assert!(
            retired.is_empty(),
            "a continuation cannot authorize another one"
        );
        assert_eq!(self.active.load(Ordering::SeqCst), 0);
        if matches!(self.mode, Mode::PolicyAfterProgress) {
            assert!(progress[0].bytes > 0);
            return Err(ContentError::Policy);
        }
        Ok((progress[0], expired))
    }
}

#[derive(Clone, Copy)]
enum Case {
    Complete,
    NoResources,
    Failed,
    Expired,
    Unclean,
    Cancel,
    PolicyAfterProgress,
}

async fn exercise(case: Case) {
    let Prepared {
        mut fixture,
        mut progress,
        mut measurements,
        retired,
        deadline,
    } = prepare().await;
    let initial_bytes = progress.iter().map(|part| part.bytes).sum::<u64>();
    let initial_chunks = progress.iter().map(|part| part.chunks).sum::<usize>();
    let retired_count = retired.len();
    let capacity = usize::from(!matches!(case, Case::NoResources)) as u64;
    let budget = WorkerBudget::for_test(capacity * 32 * 8 * 1024 * 1024, capacity * 4 * 8, true);
    let batch = budget.for_test_batch();
    if matches!(case, Case::Unclean) {
        for measurement in &mut measurements {
            measurement.elapsed = None;
        }
    }
    let sources = ActualSources {
        fixture_manifest: &fixture.manifest,
        registries: &fixture.registries,
        budget: &batch,
        deadline,
        active: AtomicUsize::new(0),
        opened: std::array::from_fn(|_| AtomicUsize::new(0)),
        mode: match case {
            Case::Failed => Mode::Failed,
            Case::Cancel => Mode::Cancel,
            Case::PolicyAfterProgress => Mode::PolicyAfterProgress,
            _ => Mode::Complete,
        },
        started: Notify::new(),
    };
    let retired = RetiredBatch {
        manifest: &fixture.manifest,
        progress: &mut progress,
        measurements: &measurements,
        retired,
        deadline: if matches!(case, Case::Expired) {
            Instant::now()
        } else {
            deadline
        },
    };
    let capture = observe_resume(case, retired, &mut fixture.cache, &sources).await;
    assert_eq!(sources.active.load(Ordering::SeqCst), 0);
    let opened = sources
        .opened
        .iter()
        .map(|value| value.load(Ordering::SeqCst))
        .sum::<usize>();
    assert!(opened <= retired_count);
    check_diagnostic(
        case,
        &capture,
        retired_count,
        opened,
        (
            fixture.bytes.len() as u64 - initial_bytes,
            12 - initial_chunks,
        ),
    );
    if matches!(case, Case::PolicyAfterProgress) {
        assert!(
            fixture.cache.usage().bytes > initial_bytes,
            "failed receive can still have verified writes"
        );
    }
    let diagnosis = batch.snapshot_for_test().unwrap();
    assert_eq!(diagnosis["active_leases"], 0);
    assert!(diagnosis["peak_leases"].as_u64().unwrap() <= 1);
    let mut output = Vec::new();
    let result = reassemble(
        &fixture.manifest,
        &mut [&mut fixture.cache],
        now(),
        &mut output,
    );
    if matches!(case, Case::Complete) {
        result.unwrap();
        assert_eq!(output, fixture.bytes);
        assert_eq!(
            progress.iter().map(|part| part.bytes).sum::<u64>(),
            fixture.bytes.len() as u64
        );
        assert_eq!(progress.iter().map(|part| part.chunks).sum::<usize>(), 12);
        assert_eq!(opened, retired_count);
    } else {
        assert!(result.is_err());
        assert_eq!(
            progress.iter().map(|part| part.bytes).sum::<u64>(),
            initial_bytes
        );
    }
}

async fn observe_resume(
    case: Case,
    retired: RetiredBatch<'_>,
    cache: &mut ChunkStore,
    sources: &ActualSources<'_>,
) -> Capture {
    let capture = Capture::default();
    // These Tokio tests use the current-thread runtime; capture also covers Drop.
    let _subscriber = tracing::subscriber::set_default(capture.subscriber(tracing::Level::DEBUG));
    let mut work = Box::pin(retired.resume(cache, sources));
    if matches!(case, Case::Cancel) {
        tokio::select! {
            () = sources.started.notified() => {},
            _ = &mut work => panic!("continuation must remain owned until cancellation"),
        }
        assert_eq!(sources.active.load(Ordering::SeqCst), 1);
    } else if matches!(case, Case::PolicyAfterProgress) {
        assert!(matches!(work.as_mut().await, Err(ContentError::Policy)));
    } else {
        let outcome = work.as_mut().await.unwrap();
        assert_eq!(
            outcome.attempted,
            matches!(case, Case::Complete | Case::Failed)
        );
        assert_eq!(outcome.timed_out, matches!(case, Case::Expired));
    }
    drop(work);
    capture
}

fn check_diagnostic(
    case: Case,
    capture: &Capture,
    retired: usize,
    opened: usize,
    remaining: (u64, usize),
) {
    let summaries = capture.summaries();
    assert_eq!(summaries.len(), 1, "one Drop event per retired batch");
    let summary = &summaries[0];
    assert_eq!(summary.as_object().unwrap().len(), 11);
    assert_eq!(summary["schema_version"], 1);
    assert_eq!(summary["retired_candidates"], retired);
    assert_eq!(
        summary["outcome"],
        match case {
            Case::Cancel => "interrupted",
            Case::PolicyAfterProgress => "failed",
            _ => "returned",
        }
    );
    assert_eq!(summary["prepared_continuations"], opened);
    assert_eq!(summary["admitted_continuations"], opened);
    assert_eq!(summary["initial_active_workers"], 0);
    assert_eq!(summary["peak_active_workers"], usize::from(opened > 0));
    assert_eq!(
        summary["final_active_workers"], 0,
        "emission follows owned driver drain, including cancellation"
    );
    if matches!(case, Case::Complete) {
        assert_eq!(summary["returned_useful_continuations"], retired);
        assert_eq!(summary["returned_verified_bytes"], remaining.0);
        assert_eq!(summary["returned_verified_chunks"], remaining.1);
    } else {
        // Includes post-write policy error: only returned progress is measured.
        assert_eq!(summary["returned_useful_continuations"], 0);
        assert_eq!(summary["returned_verified_chunks"], 0);
        assert_eq!(summary["returned_verified_bytes"], 0);
    }
}

#[tokio::test]
async fn production_continuation_completes_disjoint_coverage_after_dynamic_pressure() {
    tokio::time::timeout(Duration::from_secs(15), exercise(Case::Complete))
        .await
        .unwrap();
}

#[tokio::test]
async fn production_continuation_never_renews_failed_unclean_or_unavailable_work() {
    for case in [
        Case::NoResources,
        Case::Failed,
        Case::Expired,
        Case::Unclean,
        Case::Cancel,
    ] {
        tokio::time::timeout(Duration::from_secs(15), exercise(case))
            .await
            .unwrap();
    }
}

#[tokio::test]
async fn production_continuation_diagnostic_excludes_unreturned_policy_error_progress() {
    tokio::time::timeout(Duration::from_secs(15), exercise(Case::PolicyAfterProgress))
        .await
        .unwrap();
}
