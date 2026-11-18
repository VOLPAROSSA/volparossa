//! Opt-in evidence of token preparation, real admission and returned writer progress.
//!
//! Returned progress excludes writes from a receive that fails or is cancelled before
//! returning. Zero here is not a zero-traffic/cache-write claim. No resource is sampled.

use std::sync::{
    Mutex,
    atomic::{AtomicUsize, Ordering},
};

use serde::Serialize;
use volparossa_content::transfer::TransferProgress;

#[derive(Clone, Copy, Default, Serialize)]
#[serde(rename_all = "snake_case")]
enum Outcome {
    Returned,
    Failed,
    #[default]
    Interrupted,
}

#[derive(Clone, Default, Serialize)]
struct Summary {
    schema_version: u8,
    outcome: Outcome,
    retired_candidates: u32,
    prepared_continuations: u32,
    admitted_continuations: u32,
    returned_useful_continuations: u32,
    returned_verified_chunks: u32,
    returned_verified_bytes: u64,
    initial_active_workers: u32,
    peak_active_workers: u32,
    final_active_workers: u32,
}

fn bounded(value: usize) -> u32 {
    u32::try_from(value).unwrap_or(u32::MAX)
}

pub(in crate::content::parallel) struct Diagnostics<'a> {
    summary: Option<Mutex<Summary>>,
    active: &'a AtomicUsize,
}

impl<'a> Diagnostics<'a> {
    pub(super) fn new(retired: usize, active: &'a AtomicUsize) -> Self {
        let enabled = retired > 0
            && tracing::enabled!(target: "volparossa_agent::content::parallel::continuation", tracing::Level::DEBUG);
        Self {
            summary: enabled.then(|| {
                let initial = bounded(active.load(Ordering::Acquire));
                Mutex::new(Summary {
                    schema_version: 1,
                    retired_candidates: bounded(retired),
                    initial_active_workers: initial,
                    peak_active_workers: initial,
                    ..Summary::default()
                })
            }),
            active,
        }
    }

    fn update(&self, update: impl FnOnce(&mut Summary)) {
        if let Some(summary) = &self.summary {
            update(
                &mut summary
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner),
            );
        }
    }

    pub(super) fn prepared(&self) {
        self.update(|summary| {
            summary.prepared_continuations = summary.prepared_continuations.saturating_add(1);
        });
    }

    /// Invoked inside the real assigned-driver callback, after its lease is acquired.
    pub(in crate::content::parallel) fn admitted(&self) {
        self.update(|summary| {
            summary.admitted_continuations = summary.admitted_continuations.saturating_add(1);
            summary.peak_active_workers = summary
                .peak_active_workers
                .max(bounded(self.active.load(Ordering::Acquire)));
        });
    }

    pub(super) fn returned_progress(&self, progress: TransferProgress) {
        self.update(|summary| {
            summary.returned_verified_bytes = summary
                .returned_verified_bytes
                .saturating_add(progress.bytes);
            summary.returned_verified_chunks = summary
                .returned_verified_chunks
                .saturating_add(bounded(progress.chunks));
            if progress.bytes > 0 {
                summary.returned_useful_continuations =
                    summary.returned_useful_continuations.saturating_add(1);
            }
        });
    }

    pub(super) fn finish(&self, returned: bool) {
        self.update(|summary| {
            summary.outcome = if returned {
                Outcome::Returned
            } else {
                Outcome::Failed
            };
        });
    }
}

impl Drop for Diagnostics<'_> {
    fn drop(&mut self) {
        let Some(summary) = &self.summary else { return };
        let mut summary = summary
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        summary.final_active_workers = bounded(self.active.load(Ordering::Acquire));
        summary.peak_active_workers = summary
            .peak_active_workers
            .max(summary.final_active_workers);
        // No log sink runs while the diagnostic mutex is held.
        if let Ok(continuation) = serde_json::to_string(&summary) {
            tracing::debug!(target: "volparossa_agent::content::parallel::continuation",
                code = "CONTENT_PROVIDER_CONTINUATION_SUMMARY", continuation = %continuation);
        }
    }
}

#[cfg(test)]
pub(in crate::content::parallel) mod tests {
    use std::{io::Write, sync::Arc};

    use super::*;

    #[derive(Clone, Default)]
    pub(in crate::content::parallel) struct Capture(Arc<Mutex<Vec<u8>>>);

    impl Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    impl Capture {
        pub(in crate::content::parallel) fn subscriber(
            &self,
            level: tracing::Level,
        ) -> impl tracing::Subscriber + Send + Sync {
            let capture = self.clone();
            tracing_subscriber::fmt()
                .json()
                .with_max_level(level)
                .with_writer(move || capture.clone())
                .finish()
        }

        pub(in crate::content::parallel) fn summaries(&self) -> Vec<serde_json::Value> {
            self.0
                .lock()
                .unwrap()
                .split(|byte| *byte == b'\n')
                .filter(|line| !line.is_empty())
                .filter_map(|line| {
                    let value: serde_json::Value = serde_json::from_slice(line).unwrap();
                    if value["target"] != "volparossa_agent::content::parallel::continuation" {
                        return None;
                    }
                    assert_eq!(value["level"], "DEBUG");
                    let fields = value["fields"].as_object().unwrap();
                    assert_eq!(fields.len(), 2);
                    assert_eq!(fields["code"], "CONTENT_PROVIDER_CONTINUATION_SUMMARY");
                    Some(serde_json::from_str(fields["continuation"].as_str().unwrap()).unwrap())
                })
                .collect()
        }
    }

    #[test]
    fn continuation_diagnostics_are_opt_in_closed_and_saturating() {
        let active = AtomicUsize::new(0);
        let capture = Capture::default();
        tracing::subscriber::with_default(capture.subscriber(tracing::Level::INFO), || {
            let disabled = Diagnostics::new(2, &active);
            assert!(disabled.summary.is_none());
            disabled.prepared();
            disabled.admitted();
        });
        assert!(capture.summaries().is_empty());
        tracing::subscriber::with_default(capture.subscriber(tracing::Level::DEBUG), || {
            let absent = Diagnostics::new(0, &active);
            assert!(absent.summary.is_none());
            let diagnostic = Diagnostics::new(usize::MAX, &active);
            diagnostic.update(|value| {
                value.prepared_continuations = u32::MAX;
                value.admitted_continuations = u32::MAX;
                value.returned_useful_continuations = u32::MAX;
                value.returned_verified_chunks = u32::MAX;
                value.returned_verified_bytes = u64::MAX;
            });
            diagnostic.prepared();
            diagnostic.admitted();
            diagnostic.returned_progress(TransferProgress {
                bytes: 1,
                chunks: 1,
                missing: 0,
            });
        });
        let summaries = capture.summaries();
        assert_eq!(summaries.len(), 1);
        let value = &summaries[0];
        assert_eq!(value.as_object().unwrap().len(), 11);
        for key in [
            "retired_candidates",
            "prepared_continuations",
            "admitted_continuations",
            "returned_useful_continuations",
            "returned_verified_chunks",
        ] {
            assert_eq!(value[key], u32::MAX);
        }
        assert_eq!(value["returned_verified_bytes"], u64::MAX);
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["outcome"], "interrupted");
        assert_eq!(value["initial_active_workers"], 0);
        assert_eq!(value["peak_active_workers"], 0);
        assert_eq!(value["final_active_workers"], 0);
    }

    #[test]
    fn continuation_diagnostics_retain_unexpected_active_workers_without_admission() {
        let active = AtomicUsize::new(2);
        let capture = Capture::default();
        tracing::subscriber::with_default(capture.subscriber(tracing::Level::DEBUG), || {
            let diagnostic = Diagnostics::new(1, &active);
            diagnostic.finish(false);
            active.store(3, Ordering::Release);
        });
        let summaries = capture.summaries();
        assert_eq!(summaries.len(), 1);
        assert_eq!(summaries[0]["outcome"], "failed");
        assert_eq!(summaries[0]["admitted_continuations"], 0);
        assert_eq!(summaries[0]["initial_active_workers"], 2);
        assert_eq!(summaries[0]["peak_active_workers"], 3);
        assert_eq!(summaries[0]["final_active_workers"], 3);
    }
}
