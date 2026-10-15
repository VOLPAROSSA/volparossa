//! First-failure local timing, never exported as timestamps or raw durations.

use std::{sync::Mutex, time::Duration};

use tokio::time::Instant;
use volparossa_local_control::{
    PrivateStorageAppendTiming, PrivateStorageElapsedBucket as Bucket,
    PrivateStorageOutcomePhase as Phase,
};

#[derive(Default)]
pub(super) struct Progress(Mutex<State>);

#[derive(Default)]
struct State {
    operation_started: Option<Instant>,
    payload_started: Option<Instant>,
    receipt_started: Option<Instant>,
    failed_at: Option<Instant>,
}

impl Progress {
    pub(super) fn start_operation(&self, started: Option<Instant>) {
        if let Ok(mut state) = self.0.lock() {
            if state.operation_started.is_none() && state.failed_at.is_none() {
                state.operation_started = started;
            }
        }
    }

    pub(super) fn phase(&self, phase: Phase) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        if state.operation_started.is_none() || state.failed_at.is_some() {
            return;
        }
        match phase {
            Phase::RemotePayloadWrite if state.payload_started.is_none() => {
                state.payload_started = Some(Instant::now());
            }
            Phase::RemoteReceiptRead
                if state.payload_started.is_some() && state.receipt_started.is_none() =>
            {
                state.receipt_started = Some(Instant::now());
            }
            _ => {}
        }
    }

    pub(super) fn fail(&self) {
        if let Ok(mut state) = self.0.lock() {
            if state.failed_at.is_none() {
                state.failed_at = Some(Instant::now());
            }
        }
    }

    pub(super) fn detail(&self, phase: i32) -> Option<PrivateStorageAppendTiming> {
        let state = self.0.lock().ok()?;
        let started = state.operation_started?;
        let payload = state.payload_started?;
        let failed = state.failed_at?;
        let receipt = state.receipt_started;
        let detail = PrivateStorageAppendTiming {
            before_payload: bucket(payload.saturating_duration_since(started)) as i32,
            in_payload_write_flush: bucket(
                receipt.unwrap_or(failed).saturating_duration_since(payload),
            ) as i32,
            in_receipt_read: receipt
                .map(|entered| bucket(failed.saturating_duration_since(entered)) as i32),
        };
        detail.validate(Phase::try_from(phase).ok()?).ok()?;
        Some(detail)
    }
}

fn bucket(elapsed: Duration) -> Bucket {
    match elapsed.as_secs() {
        0 => Bucket::Under1s,
        1..=4 => Bucket::S1To5,
        5..=14 => Bucket::S5To15,
        15..=29 => Bucket::S15To30,
        30..=59 => Bucket::S30To60,
        60..=89 => Bucket::S60To90,
        90..=119 => Bucket::S90To120,
        _ => Bucket::AtLeast120s,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn append_timing_buckets_have_the_original_eight_exact_edges() {
        for (seconds, expected) in [
            (0, Bucket::Under1s),
            (1, Bucket::S1To5),
            (4, Bucket::S1To5),
            (5, Bucket::S5To15),
            (14, Bucket::S5To15),
            (15, Bucket::S15To30),
            (29, Bucket::S15To30),
            (30, Bucket::S30To60),
            (59, Bucket::S30To60),
            (60, Bucket::S60To90),
            (89, Bucket::S60To90),
            (90, Bucket::S90To120),
            (119, Bucket::S90To120),
            (120, Bucket::AtLeast120s),
            (u64::MAX, Bucket::AtLeast120s),
        ] {
            assert_eq!(bucket(Duration::from_secs(seconds)), expected);
        }
    }

    #[tokio::test(start_paused = true)]
    async fn append_timing_freezes_first_failure_and_distinguishes_payload_flush_return() {
        let progress = Progress::default();
        progress.start_operation(Some(Instant::now()));
        tokio::time::advance(Duration::from_secs(30)).await;
        progress.phase(Phase::RemotePayloadWrite);
        tokio::time::advance(Duration::from_secs(5)).await;
        progress.phase(Phase::RemoteReceiptRead);
        tokio::time::advance(Duration::from_secs(60)).await;
        progress.fail();
        let expected = PrivateStorageAppendTiming {
            before_payload: Bucket::S30To60 as i32,
            in_payload_write_flush: Bucket::S5To15 as i32,
            in_receipt_read: Some(Bucket::S60To90 as i32),
        };
        assert_eq!(
            progress.detail(Phase::RemoteReceiptRead as i32),
            Some(expected)
        );
        tokio::time::advance(Duration::from_secs(300)).await;
        progress.start_operation(Some(Instant::now()));
        progress.phase(Phase::RemotePayloadWrite);
        progress.phase(Phase::RemoteReceiptRead);
        progress.fail();
        assert_eq!(
            progress.detail(Phase::RemoteReceiptRead as i32),
            Some(expected)
        );
        assert!(progress.detail(Phase::RemotePayloadWrite as i32).is_none());
        assert!(progress.detail(Phase::TerminalWrite as i32).is_none());
    }

    #[tokio::test(start_paused = true)]
    async fn append_timing_does_not_invent_flush_or_unobserved_start() {
        let missing = Progress::default();
        missing.start_operation(None);
        missing.phase(Phase::RemotePayloadWrite);
        missing.phase(Phase::RemoteReceiptRead);
        missing.fail();
        missing.start_operation(Some(Instant::now()));
        assert!(missing.detail(Phase::RemoteReceiptRead as i32).is_none());
        let progress = Progress::default();
        progress.start_operation(Some(Instant::now()));
        progress.phase(Phase::RemoteReceiptRead); // Non-APPEND receipt, no payload entry.
        progress.fail();
        assert!(progress.detail(Phase::RemoteReceiptRead as i32).is_none());
        let progress = Progress::default();
        progress.start_operation(Some(Instant::now()));
        progress.phase(Phase::RemotePayloadWrite);
        assert!(progress.detail(Phase::RemotePayloadWrite as i32).is_none());
        tokio::time::advance(Duration::from_secs(15)).await;
        progress.fail();
        progress.phase(Phase::RemoteReceiptRead); // Later cleanup cannot invent a flush return.
        assert_eq!(
            progress.detail(Phase::RemotePayloadWrite as i32),
            Some(PrivateStorageAppendTiming {
                before_payload: Bucket::Under1s as i32,
                in_payload_write_flush: Bucket::S15To30 as i32,
                in_receipt_read: None,
            })
        );
        assert!(progress.detail(Phase::RemoteReceiptRead as i32).is_none());
    }
}
