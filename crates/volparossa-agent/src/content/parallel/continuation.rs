//! Single-use serial coverage after locally pressure-retired streams have drained.

use std::future::Future;
use std::sync::atomic::AtomicUsize;

pub(super) mod diagnostics;
use diagnostics::Diagnostics;

use tokio::time::Instant;
use volparossa_content::{
    ChunkStore, VerifiedManifest,
    transfer::{
        TransferError, TransferProgress,
        parallel::{ChunkWorker, ParallelDownload, ResourceRetired},
    },
};

use super::{ContentError, complete, drivers};

pub(super) trait Sources {
    fn available(&self) -> bool;
    fn active_workers(&self) -> &AtomicUsize;
    fn transport(&self, index: usize) -> &VerifiedManifest;
    fn receive(
        &self,
        index: usize,
        download: ParallelDownload,
        worker: ChunkWorker,
        store: &mut ChunkStore,
        diagnostic: &Diagnostics<'_>,
    ) -> impl Future<Output = Result<(TransferProgress, bool), ContentError>> + Send;
}

#[derive(Default)]
pub(super) struct Outcome {
    pub attempted: bool,
    pub timed_out: bool,
}

pub(super) struct RetiredBatch<'a> {
    pub manifest: &'a VerifiedManifest,
    pub progress: &'a mut [TransferProgress],
    pub measurements: &'a [drivers::Measurement],
    pub retired: Vec<ResourceRetired>,
    pub deadline: Instant,
}

impl RetiredBatch<'_> {
    // The caller must join the original batch before entering this coordinator. Each
    // awaited receive owns its writer/driver/lease until they all terminate; no two
    // continuations overlap and no failed/partial continuation is queued again.
    pub async fn resume(
        self,
        store: &mut ChunkStore,
        sources: &impl Sources,
    ) -> Result<Outcome, ContentError> {
        let diagnostic = Diagnostics::new(self.retired.len(), sources.active_workers());
        // The awaited future owns every driver and borrows this diagnostic. On
        // cancellation it drops first, before the final active-worker observation.
        let result = self.resume_observed(store, sources, &diagnostic).await;
        diagnostic.finish(result.is_ok());
        result
    }

    async fn resume_observed(
        self,
        store: &mut ChunkStore,
        sources: &impl Sources,
        diagnostic: &Diagnostics<'_>,
    ) -> Result<Outcome, ContentError> {
        let mut outcome = Outcome::default();
        for retirement in self.retired {
            if Instant::now() >= self.deadline {
                outcome.timed_out = true;
                break;
            }
            if complete(self.manifest, store)? {
                break;
            }
            let index = retirement.worker_index();
            // A transport retry may spend requests invisible to the single writer.
            // Only a clean first-attempt close preserves the token's budget proof.
            if self.measurements[index].elapsed.is_none() || !sources.available() {
                continue;
            }
            let (download, worker) = match retirement.prepare_continuation(
                self.manifest,
                sources.transport(index),
                store,
            ) {
                Ok(prepared) => prepared,
                Err(TransferError::Timeout) => {
                    outcome.timed_out = true;
                    break;
                }
                Err(_) => return Err(ContentError::Invalid),
            };
            outcome.attempted = true;
            diagnostic.prepared();
            let (part, expired) = sources
                .receive(index, download, worker, store, diagnostic)
                .await?;
            // Only returned writer progress is observed here. A cancelled or
            // failed receive may have cached bytes that this summary cannot see.
            diagnostic.returned_progress(part);
            let progress = &mut self.progress[index];
            progress.bytes = progress
                .bytes
                .checked_add(part.bytes)
                .ok_or(ContentError::Invalid)?;
            progress.chunks = progress
                .chunks
                .checked_add(part.chunks)
                .ok_or(ContentError::Invalid)?;
            progress.missing = progress
                .missing
                .checked_add(part.missing)
                .ok_or(ContentError::Invalid)?;
            if expired {
                outcome.timed_out = true;
                break;
            }
        }
        Ok(outcome)
    }
}
