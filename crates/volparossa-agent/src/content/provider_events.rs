//! Volatile, bounded provider diagnostics. Logging never owns a session admission slot.
//!
//! Accepted batches retain all closed historical/V1/APPEND categories. On overflow the newest batch is omitted; a later successful drain records
//! that loss. Stopping discards undrained batches and reports only their counts to tracing.
//! Neither a stopped drain nor an overflow permits an event-absence or delivery claim.

use std::{collections::VecDeque, sync::Arc};

use tokio::sync::RwLock;
use volparossa_local_control::LogLevel;

use crate::{state::AgentState, unix_millis};

const CAPACITY: usize = 64;
const OMITTED: &str = "CONTENT_PROVIDER_EVENTS_OMITTED";

pub(super) struct Batch {
    codes: [Option<&'static str>; 3],
}

impl Batch {
    pub(super) fn one(code: &'static str) -> Self {
        Self::new([Some(code), None, None])
    }

    pub(super) fn new(codes: [Option<&'static str>; 3]) -> Self {
        Self { codes }
    }

    pub(super) fn log(self, state: &mut AgentState) {
        // Preserve the historical post-lock timestamp semantics and chronological ring.
        for code in self.codes.into_iter().flatten() {
            state.log(LogLevel::Info, code, unix_millis());
        }
    }
}

pub(super) struct Drain {
    pending: VecDeque<Batch>,
    omitted: u64,
}

impl Default for Drain {
    fn default() -> Self {
        Self {
            pending: VecDeque::with_capacity(CAPACITY),
            omitted: 0,
        }
    }
}

impl Drain {
    pub(super) fn enqueue(&mut self, batch: Batch) {
        if self.pending.len() == CAPACITY {
            self.omitted = self.omitted.saturating_add(1);
        } else {
            self.pending.push_back(batch);
        }
    }

    pub(super) fn has_pending(&self) -> bool {
        !self.pending.is_empty() || self.omitted != 0
    }

    // All mutation follows lock acquisition: select cancellation retains every accepted batch.
    // Once acquired, the bounded drain has no await and cannot be partially cancelled.
    pub(super) async fn flush(&mut self, events: Option<&Arc<RwLock<AgentState>>>) {
        if let Some(events) = events {
            let mut state = events.write().await;
            for batch in self.pending.drain(..) {
                batch.log(&mut state);
            }
            if self.omitted != 0 {
                state.log(LogLevel::Info, OMITTED, unix_millis());
            }
        } else {
            // Test/explicitly disabled event sink: no retained delivery is claimed.
            self.pending.clear();
        }
        self.omitted = 0;
    }
}

impl Drop for Drain {
    fn drop(&mut self) {
        if self.has_pending() {
            tracing::warn!(
                event_code = "CONTENT_PROVIDER_EVENT_DRAIN_CANCELLED",
                pending_batches = self.pending.len(),
                omitted_batches = self.omitted,
                "volatile provider diagnostics discarded on service stop"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use volparossa_config::Config;
    use volparossa_metrics::MetricsRegistry;

    fn state() -> Arc<RwLock<AgentState>> {
        let config = Config::default();
        Arc::new(RwLock::new(
            AgentState::new(&config, config.roles, None, MetricsRegistry::new()).unwrap(),
        ))
    }

    #[tokio::test]
    async fn overflow_preserves_accepted_batches_and_reports_omission_after_drain() {
        let state = state();
        let mut drain = Drain::default();
        for index in 0..CAPACITY {
            let historical = match index {
                0 => "FIRST",
                value if value == CAPACITY - 1 => "LAST",
                _ => "HISTORICAL",
            };
            drain.enqueue(Batch::new([Some(historical), Some("V1"), Some("APPEND")]));
        }
        for _ in 0..3 {
            drain.enqueue(Batch::one("OMITTED_CANARY"));
        }
        assert_eq!(drain.pending.len(), CAPACITY);
        assert_eq!(drain.omitted, 3);
        drain.flush(Some(&state)).await;
        assert!(!drain.has_pending());
        let records = state.read().await.logs(400).records;
        assert_eq!(records.len(), CAPACITY * 3 + 1);
        assert!(
            records
                .windows(2)
                .all(|pair| pair[0].timestamp_ms <= pair[1].timestamp_ms)
        );
        for (index, batch) in records[..CAPACITY * 3].chunks_exact(3).enumerate() {
            let historical = match index {
                0 => "FIRST",
                value if value == CAPACITY - 1 => "LAST",
                _ => "HISTORICAL",
            };
            assert_eq!(batch[0].event_code, historical);
            assert_eq!(batch[1].event_code, "V1");
            assert_eq!(batch[2].event_code, "APPEND");
        }
        assert_eq!(records.last().unwrap().event_code, OMITTED);
        assert!(records.iter().all(|record| record.session_id.is_empty()));
        // A successful drain consumes the omission marker exactly once.
        drain.flush(Some(&state)).await;
        assert_eq!(state.read().await.logs(400).records.len(), records.len());
    }

    #[tokio::test]
    async fn cancelled_drain_lock_wait_keeps_accepted_batches() {
        let state = state();
        let lock = state.write().await;
        let mut drain = Drain::default();
        drain.enqueue(Batch::one("RETAINED"));
        {
            let flush = drain.flush(Some(&state));
            tokio::pin!(flush);
            std::future::poll_fn(|context| {
                use std::{future::Future, task::Poll};
                assert!(flush.as_mut().poll(context).is_pending());
                Poll::Ready(())
            })
            .await;
        }
        assert_eq!(drain.pending.len(), 1);
        assert!(lock.logs(10).records.is_empty());
        drop(lock);
        drain.flush(Some(&state)).await;
        assert_eq!(
            state.read().await.logs(10).records[0].event_code,
            "RETAINED"
        );
        assert!(!drain.has_pending());
    }
}
