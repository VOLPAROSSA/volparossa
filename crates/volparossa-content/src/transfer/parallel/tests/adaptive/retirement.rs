//! Sealed continuation authority: reason, original identity/time and spent work remain binding.

use super::{Case, Fixture, fixture};
use crate::transfer::{
    TransferError, TransferLimits,
    parallel::{ParallelDownload, ResourceRetired, adaptive::PeerState},
};
use tokio::time::Instant;

pub(super) async fn continue_streams(
    retired: Vec<ResourceRetired>,
    manifest: &super::VerifiedManifest,
    transports: &[super::VerifiedManifest],
    providers: &[super::Arc<super::PublicationRegistry>],
    output: &mut super::ChunkStore,
    progress: &mut [super::TransferProgress],
    counters: &super::Counters,
) -> u64 {
    let mut sent = 0;
    for token in retired {
        assert_eq!(counters.active.load(super::Ordering::SeqCst), 0);
        let index = token.worker_index();
        let deadline = token.deadline;
        let remaining_requests = token.limits.max_requests;
        let remaining_bytes = token.limits.max_bytes;
        let attempted = token.attempted.clone();
        let (download, worker) = token
            .prepare_continuation(manifest, &transports[index], output)
            .unwrap();
        assert_eq!(download.deadline, deadline);
        assert_eq!(worker.deadline, deadline);
        assert_eq!(worker.session.deadline, deadline);
        assert_eq!(worker.limits.max_requests, remaining_requests);
        assert_eq!(worker.limits.max_bytes, remaining_bytes);
        for chunk in &download.chunks {
            assert_eq!(
                chunk.attempted.contains(&0),
                attempted.contains(chunk.chunk.id())
            );
        }
        let limits = worker.limits;
        let driver = tokio::spawn(super::drive(
            worker,
            super::Arc::clone(&providers[index]),
            counters.clone(),
            limits,
            Case::PressureComplementary,
            index,
        ));
        let mut part = [super::TransferProgress::default()];
        let repeated = download
            .run_with_allowance_retired(output, &mut part, || 1)
            .await
            .unwrap();
        assert!(
            repeated.is_empty(),
            "retirement cannot mint a second continuation"
        );
        sent += driver.await.unwrap().bytes;
        progress[index].bytes += part[0].bytes;
        progress[index].chunks += part[0].chunks;
        progress[index].missing += part[0].missing;
    }
    sent
}

fn prepared() -> (Fixture, ParallelDownload) {
    let mut fixture = fixture(Case::Complementary);
    let limits = TransferLimits {
        max_requests: 9,
        max_bytes: 9 * super::CHUNK_BYTES as u64,
        ..TransferLimits::default()
    };
    let refs = fixture.transports.iter().collect::<Vec<_>>();
    let (mut download, workers) = ParallelDownload::new_adaptive_with_transport_manifests(
        &fixture.manifest,
        &refs,
        &mut fixture.output,
        limits,
        3,
    )
    .unwrap();
    // A completed explicit miss consumes a request and requested-byte budget, even
    // though it inserted no payload. Resource closure is a distinct terminal reason.
    download.chunks[0].attempted.insert(1);
    download.peers[1].resource_retired = true;
    download.peers[1].state = PeerState::Finished;
    drop(workers);
    (fixture, download)
}

fn token(download: &ParallelDownload) -> ResourceRetired {
    let mut retired = download.resource_retirements();
    assert_eq!(retired.len(), 1);
    retired.pop().unwrap()
}

#[test]
fn pressure_token_preserves_misses_budgets_deadline_and_original_transport() {
    let (mut fixture, download) = prepared();
    let token = token(&download);
    assert_eq!(token.worker_index(), 1);
    assert_eq!(token.limits.max_requests, 8);
    assert_eq!(token.limits.max_bytes, 8 * super::CHUNK_BYTES as u64);
    let original_deadline = download.deadline;
    let known_miss = download.chunks[0].chunk.id();
    let (mut continued, worker) = token
        .prepare_continuation(
            &fixture.manifest,
            &fixture.transports[1],
            &mut fixture.output,
        )
        .unwrap();
    assert_eq!(continued.deadline, original_deadline);
    assert_eq!(worker.deadline, original_deadline);
    assert_eq!(worker.session.deadline, original_deadline);
    assert_eq!(worker.session.limits.max_requests, 8);
    assert_eq!(
        worker.session.limits.max_bytes,
        8 * super::CHUNK_BYTES as u64
    );
    assert_eq!(
        worker.manifest().manifest_id(),
        fixture.transports[1].manifest_id()
    );
    let miss = continued
        .chunks
        .iter()
        .find(|chunk| chunk.chunk.id() == known_miss)
        .unwrap();
    assert!(miss.attempted.contains(&0));
    continued.assign_ready().unwrap();
    assert_ne!(
        continued.peers[0].pending,
        Some(0),
        "known misses receive no new request"
    );
    continued.peers[0].pending = None;
    continued.peers[0].resource_retired = true;
    continued.peers[0].state = PeerState::Finished;
    assert!(
        continued.resource_retirements().is_empty(),
        "single-use even if pressure flaps again"
    );
}

#[test]
fn pressure_token_rejects_different_authority_and_expired_original_deadline() {
    let (mut fixture, download) = prepared();
    assert!(matches!(
        token(&download).prepare_continuation(
            &fixture.manifest,
            &fixture.transports[0],
            &mut fixture.output,
        ),
        Err(TransferError::Protocol)
    ));
    assert!(matches!(
        token(&download).prepare_continuation(
            &fixture.transports[1],
            &fixture.transports[1],
            &mut fixture.output,
        ),
        Err(TransferError::Protocol)
    ));
    let mut expired = token(&download);
    expired.deadline = Instant::now();
    assert!(matches!(
        expired.prepare_continuation(
            &fixture.manifest,
            &fixture.transports[1],
            &mut fixture.output,
        ),
        Err(TransferError::Timeout)
    ));
}

#[test]
fn failed_exhausted_active_and_budget_spent_peers_never_get_pressure_tokens() {
    let (_, mut download) = prepared();
    download.peers[1].resource_retired = false;
    assert!(download.resource_retirements().is_empty());
    download.peers[1].resource_retired = true;
    download.peers[1].state = PeerState::Active;
    assert!(download.resource_retirements().is_empty());
    download.peers[1].state = PeerState::Finished;
    download.limits.max_requests = 1;
    assert!(download.resource_retirements().is_empty());
    download.limits.max_requests = 9;
    download.limits.max_bytes = super::CHUNK_BYTES as u64;
    assert!(download.resource_retirements().is_empty());
    download.limits.max_bytes = 9 * super::CHUNK_BYTES as u64;
    for chunk in &mut download.chunks {
        chunk.attempted.insert(1);
    }
    assert!(download.resource_retirements().is_empty());
}
