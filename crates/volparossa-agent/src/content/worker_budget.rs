//! Shared advisory RAM/descriptor reservations for protected foreground cache workers.
//!
//! Counts follow current resource headroom, not a configured peer-count target. A lease
//! precedes socket/TLS setup and survives its complete close/drop. This is a conservative
//! admission/pressure guard, not a kernel memory reservation or an owner-goodput guarantee.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

use crate::resource_headroom::{PressureObservation, PressureState};

mod diagnostics;
use diagnostics::{Diagnostics, Outcome};

const BYTES_PER_WORKER: u64 = 8 * 1024 * 1024;
const FDS_PER_WORKER: u64 = 8;
const MEMORY_HEADROOM_DIVISOR: u64 = 32;
const FD_HEADROOM_DIVISOR: u64 = 4;
const SAMPLE_AGE: Duration = Duration::from_millis(100);

#[derive(Clone, Default)]
pub(super) struct WorkerBudget(Arc<Mutex<State>>);

#[derive(Default)]
struct State {
    held: usize,
    sampled: Option<(Instant, Option<Snapshot>)>,
    #[cfg(test)]
    fixed: Option<Snapshot>,
}

#[derive(Clone, Copy)]
struct Snapshot {
    memory: u64,
    fds: u64,
    pressure: PressureObservation,
}

impl Snapshot {
    fn memory_workers(self) -> u64 {
        self.memory / MEMORY_HEADROOM_DIVISOR / BYTES_PER_WORKER
    }

    fn fd_workers(self) -> u64 {
        self.fds / FD_HEADROOM_DIVISOR / FDS_PER_WORKER
    }

    fn capacity(self) -> usize {
        usize::try_from(self.memory_workers().min(self.fd_workers())).unwrap_or(usize::MAX)
    }
}

impl State {
    fn snapshot(&mut self) -> Option<Snapshot> {
        #[cfg(test)]
        if let Some(fixed) = self.fixed {
            return Some(fixed);
        }
        let at = Instant::now();
        if let Some((sampled, value)) = self.sampled
            && at.saturating_duration_since(sampled) < SAMPLE_AGE {
                return value;
            }
        let value = crate::resource_headroom::capture_with_pressure().map(|observed| Snapshot {
            memory: observed.headroom.memory_bytes,
            fds: observed.headroom.available_fds,
            pressure: observed.pressure,
        });
        self.sampled = Some((at, value));
        value
    }
}

impl WorkerBudget {
    /// Opt-in aggregate diagnostics share the exact decisions and samples below.
    /// With this debug target disabled, no aggregate allocation or log is made.
    pub(super) fn for_batch(&self) -> BatchBudget<'_> {
        BatchBudget::new(
            self,
            tracing::enabled!(target: "volparossa_agent::content::worker_budget", tracing::Level::DEBUG),
        )
    }

    /// Currently unreserved worker units; this does not authorize a future socket open.
    pub(super) fn available_workers(&self) -> usize {
        self.available_workers_observed(None)
    }

    fn available_workers_observed(&self, diagnostic: Option<&Diagnostics>) -> usize {
        let Ok(mut state) = self.0.lock() else {
            if let Some(diagnostic) = diagnostic {
                diagnostic.observe(None, None, Some(0));
            }
            return 0;
        };
        let Some(snapshot) = state.snapshot() else {
            if let Some(diagnostic) = diagnostic {
                diagnostic.observe(None, Some(state.held), Some(0));
            }
            return 0;
        };
        let capacity = if snapshot.pressure.pressured() {
            snapshot.capacity().min(1)
        } else {
            snapshot.capacity()
        };
        let available = capacity.saturating_sub(state.held);
        if let Some(diagnostic) = diagnostic {
            diagnostic.observe(Some(snapshot), Some(state.held), Some(available));
        }
        available
    }

    /// Absolute allowance for one download, including its existing reservations.
    /// Pressure drains each existing download to one worker while new shared admission stays
    /// closed. This preserves existing foreground progress; it is not a one-stream global
    /// eviction policy. Actual RAM/descriptor capacity remains shared across all downloads.
    pub(super) fn allowance(&self, local_active: usize) -> usize {
        self.allowance_observed(local_active, None)
    }

    fn allowance_observed(&self, local_active: usize, diagnostic: Option<&Diagnostics>) -> usize {
        let Ok(mut state) = self.0.lock() else {
            if let Some(diagnostic) = diagnostic {
                diagnostic.observe(None, None, Some(0));
            }
            return 0;
        };
        let Some(snapshot) = state.snapshot() else {
            if let Some(diagnostic) = diagnostic {
                diagnostic.observe(None, Some(state.held), Some(0));
            }
            return 0;
        };
        let others = state.held.saturating_sub(local_active);
        let available = snapshot.capacity().saturating_sub(others);
        let allowance = if snapshot.pressure.pressured() {
            available.min(1)
        } else {
            available
        };
        if let Some(diagnostic) = diagnostic {
            diagnostic.observe(Some(snapshot), Some(state.held), Some(allowance));
        }
        allowance
    }

    /// Atomically reserve shared accounting before allocating a new protected worker flow.
    pub(super) fn try_acquire(&self) -> Option<WorkerLease> {
        self.try_acquire_observed(None)
    }

    fn try_acquire_observed(&self, diagnostic: Option<&Diagnostics>) -> Option<WorkerLease> {
        let Ok(mut state) = self.0.lock() else {
            if let Some(diagnostic) = diagnostic {
                diagnostic.observe(None, None, None);
                diagnostic.admission(false);
            }
            return None;
        };
        let Some(snapshot) = state.snapshot() else {
            if let Some(diagnostic) = diagnostic {
                diagnostic.observe(None, Some(state.held), None);
                diagnostic.admission(false);
            }
            return None;
        };
        let capacity = if snapshot.pressure.pressured() {
            snapshot.capacity().min(1)
        } else {
            snapshot.capacity()
        };
        if state.held >= capacity {
            if let Some(diagnostic) = diagnostic {
                diagnostic.observe(Some(snapshot), Some(state.held), None);
                diagnostic.admission(false);
            }
            return None;
        }
        state.held = state.held.checked_add(1)?;
        if let Some(diagnostic) = diagnostic {
            diagnostic.observe(Some(snapshot), Some(state.held), None);
            diagnostic.admission(true);
        }
        Some(WorkerLease(Some(Arc::clone(&self.0))))
    }

    #[cfg(test)]
    pub(super) fn for_test_batch(&self) -> BatchBudget<'_> {
        BatchBudget::new(self, true)
    }

    #[cfg(test)]
    pub(super) fn for_test(memory: u64, fds: u64, pressured: bool) -> Self {
        Self(Arc::new(Mutex::new(State {
            fixed: Some(Snapshot {
                memory,
                fds,
                pressure: PressureObservation {
                    cpu: if pressured {
                        PressureState::AtOrAboveThreshold
                    } else {
                        PressureState::BelowThreshold
                    },
                    memory: PressureState::BelowThreshold,
                    io: PressureState::BelowThreshold,
                },
            }),
            ..State::default()
        })))
    }
}

/// A diagnostic owner, not an additional reservation or provider-count policy.
pub(super) struct BatchBudget<'a> {
    budget: &'a WorkerBudget,
    diagnostic: Option<Diagnostics>,
}

impl<'a> BatchBudget<'a> {
    fn new(budget: &'a WorkerBudget, enabled: bool) -> Self {
        Self {
            budget,
            diagnostic: enabled.then(Diagnostics::new),
        }
    }

    pub(super) fn available_workers(&self) -> usize {
        match &self.diagnostic {
            Some(diagnostic) => self.budget.available_workers_observed(Some(diagnostic)),
            None => self.budget.available_workers(),
        }
    }

    pub(super) fn allowance(&self, local_active: usize) -> usize {
        match &self.diagnostic {
            Some(diagnostic) => self
                .budget
                .allowance_observed(local_active, Some(diagnostic)),
            None => self.budget.allowance(local_active),
        }
    }

    pub(super) fn try_acquire(&self) -> Option<DiagnosticLease> {
        let lease = match &self.diagnostic {
            Some(diagnostic) => self.budget.try_acquire_observed(Some(diagnostic)),
            None => self.budget.try_acquire(),
        };
        lease.map(|lease| DiagnosticLease {
            lease: Some(lease),
            diagnostic: self.diagnostic.clone(),
        })
    }

    /// `returned` only means the caller returned Ok, never that transfer was complete.
    pub(super) fn finish(&self, success: bool) {
        if let Some(diagnostic) = &self.diagnostic {
            diagnostic.set_outcome(if success {
                Outcome::Returned
            } else {
                Outcome::Failed
            });
        }
    }

    #[cfg(test)]
    pub(super) fn snapshot_for_test(&self) -> Option<serde_json::Value> {
        self.diagnostic.as_ref().map(Diagnostics::snapshot_for_test)
    }
}

impl Drop for BatchBudget<'_> {
    fn drop(&mut self) {
        if let Some(diagnostic) = &self.diagnostic {
            diagnostic.emit();
        }
    }
}

pub(super) struct DiagnosticLease {
    lease: Option<WorkerLease>,
    diagnostic: Option<Diagnostics>,
}

impl Drop for DiagnosticLease {
    fn drop(&mut self) {
        // Release both counts under the same budget -> diagnostics lock order.
        // A new acquire cannot inflate the local peak before this release is counted.
        if let Some(mut lease) = self.lease.take() {
            lease.release(self.diagnostic.as_ref());
        }
    }
}

/// Not cloneable: one live worker owns one shared reservation until its flow has closed.
pub(super) struct WorkerLease(Option<Arc<Mutex<State>>>);

impl WorkerLease {
    fn release(&mut self, diagnostic: Option<&Diagnostics>) {
        let Some(owner) = self.0.take() else {
            return;
        };
        if let Ok(mut state) = owner.lock() {
            state.held = state.held.saturating_sub(1);
            if let Some(diagnostic) = diagnostic {
                diagnostic.release();
            }
        } else if let Some(diagnostic) = diagnostic {
            diagnostic.observe(None, None, None);
            diagnostic.release();
        }
    }
}

impl Drop for WorkerLease {
    fn drop(&mut self) {
        self.release(None);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn worker_budget_uses_resource_units_shared_leases_and_drains_under_pressure() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<WorkerLease>();
        let unit = BYTES_PER_WORKER * MEMORY_HEADROOM_DIVISOR;
        let fds = FDS_PER_WORKER * FD_HEADROOM_DIVISOR;
        let budget = WorkerBudget::for_test(3 * unit, 3 * fds, false);
        let other = budget.clone();
        let first = budget.try_acquire().unwrap();
        let second = other.try_acquire().unwrap();
        assert_eq!(budget.available_workers(), 1);
        assert_eq!(
            budget.allowance(2),
            3,
            "own active leases are not subtracted twice"
        );
        let third = budget.try_acquire().unwrap();
        assert!(other.try_acquire().is_none(), "no concurrent overcommit");
        budget
            .0
            .lock()
            .unwrap()
            .fixed
            .as_mut()
            .unwrap()
            .pressure
            .cpu = PressureState::AtOrAboveThreshold;
        assert_eq!(budget.allowance(3), 1);
        assert!(other.try_acquire().is_none());
        drop((second, third));
        assert_eq!(
            budget.available_workers(),
            0,
            "one foreground flow remains, no expansion"
        );
        drop(first);
        assert_eq!(budget.available_workers(), 1);
        let budget = WorkerBudget::for_test(12 * unit, 12 * fds, false);
        assert_eq!(
            budget.available_workers(),
            12,
            "no replacement hard ceiling of two or eight"
        );
        assert_eq!(
            WorkerBudget::for_test(3 * unit, fds - 1, false).available_workers(),
            0
        );
    }

    #[test]
    fn worker_budget_pressure_preserves_existing_downloads_without_admitting_more() {
        let unit = BYTES_PER_WORKER * MEMORY_HEADROOM_DIVISOR;
        let fds = FDS_PER_WORKER * FD_HEADROOM_DIVISOR;
        let budget = WorkerBudget::for_test(3 * unit, 3 * fds, false);
        let first = budget.try_acquire().unwrap();
        let surplus = budget.try_acquire().unwrap();
        let other_download = budget.try_acquire().unwrap();
        budget
            .0
            .lock()
            .unwrap()
            .fixed
            .as_mut()
            .unwrap()
            .pressure
            .cpu = PressureState::AtOrAboveThreshold;
        assert_eq!(budget.allowance(2), 1);
        assert_eq!(budget.allowance(1), 1);
        drop(surplus);
        assert_eq!(
            budget.allowance(1),
            1,
            "both existing downloads keep progress"
        );
        assert_eq!(budget.available_workers(), 0);
        assert!(
            budget.try_acquire().is_none(),
            "no additional pressured streams"
        );
        // Real resource loss is still global even while graceful pressure draining is local.
        budget.0.lock().unwrap().fixed.as_mut().unwrap().memory = unit;
        assert_eq!(budget.allowance(1), 0);
        drop(other_download);
        assert_eq!(budget.allowance(1), 1);
        assert!(budget.try_acquire().is_none());
        drop(first);
        assert_eq!(budget.available_workers(), 1);
    }

    #[test]
    fn batch_diagnostics_use_actual_shared_decisions_without_reducing_planner_allowance_on_acquire()
    {
        let budget = WorkerBudget::for_test(
            3 * BYTES_PER_WORKER * MEMORY_HEADROOM_DIVISOR,
            3 * FDS_PER_WORKER * FD_HEADROOM_DIVISOR,
            false,
        );
        let batch = budget.for_test_batch();
        assert_eq!(budget.available_workers(), 3);
        assert_eq!(batch.available_workers(), 3);
        let first = batch.try_acquire().unwrap();
        let other_batch = budget.try_acquire().unwrap();
        assert_eq!(batch.allowance(1), 2);
        let second = batch.try_acquire().unwrap();
        assert!(batch.try_acquire().is_none());
        assert_eq!(batch.snapshot_for_test().unwrap()["min_allowance"], 2);
        drop(other_batch);
        assert_eq!(batch.allowance(2), 3);
        budget.0.lock().unwrap().fixed.as_mut().unwrap().pressure = PressureObservation {
            cpu: PressureState::AtOrAboveThreshold,
            memory: PressureState::Unavailable,
            io: PressureState::AtOrAboveThreshold,
        };
        assert_eq!(batch.allowance(2), 1);
        drop((first, second));
        batch.finish(true);
        let value = batch.snapshot_for_test().unwrap();
        for (key, expected) in [
            ("initial_allowance", 3),
            ("min_allowance", 1),
            ("max_allowance", 3),
            ("min_memory_workers", 3),
            ("min_fd_workers", 3),
            ("peak_shared_held", 3),
            ("admitted_leases", 2),
            ("denied_leases", 1),
            ("peak_leases", 2),
            ("active_leases", 0),
        ] {
            assert_eq!(value[key], expected, "{key}");
        }
        let causes = value["causes"].as_object().unwrap();
        assert!(causes.iter().all(|(key, value)| value
            == matches!(
                key.as_str(),
                "cpu_pressure" | "memory_unavailable" | "io_pressure"
            )));
        assert_eq!(value["outcome"], "returned");
        assert_eq!(budget.available_workers(), 1);
    }

    #[test]
    fn batch_diagnostics_are_absent_when_disabled_and_default_to_interrupted() {
        fn send_sync<T: Send + Sync>() {}
        send_sync::<BatchBudget<'_>>();
        send_sync::<DiagnosticLease>();
        let budget = WorkerBudget::for_test(
            BYTES_PER_WORKER * MEMORY_HEADROOM_DIVISOR,
            FDS_PER_WORKER * FD_HEADROOM_DIVISOR,
            false,
        );
        {
            let batch = BatchBudget::new(&budget, false);
            assert_eq!(batch.available_workers(), 1);
            let lease = batch.try_acquire().unwrap();
            assert!(batch.try_acquire().is_none());
            drop(lease);
            batch.finish(true);
            assert!(batch.snapshot_for_test().is_none());
        }
        let batch = budget.for_test_batch();
        let diagnostic = batch.diagnostic.clone().unwrap();
        let lease = batch.try_acquire().unwrap();
        drop(lease);
        drop(batch);
        let value = diagnostic.snapshot_for_test();
        assert_eq!(value["outcome"], "interrupted");
        assert_eq!(value["admitted_leases"], 1);
        assert_eq!(value["active_leases"], 0);
        assert!(value["initial_allowance"].is_null());
        assert!(value["min_allowance"].is_null());
        assert!(value["max_allowance"].is_null());
        assert_eq!(budget.available_workers(), 1);
        let failed = budget.for_test_batch();
        failed.finish(false);
        assert_eq!(failed.snapshot_for_test().unwrap()["outcome"], "failed");
    }

    #[test]
    fn batch_drop_emits_exactly_one_closed_event_only_when_debug_is_enabled() {
        #[derive(Clone)]
        struct Capture(Arc<Mutex<Vec<u8>>>);

        impl std::io::Write for Capture {
            fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
                self.0.lock().unwrap().extend_from_slice(bytes);
                Ok(bytes.len())
            }

            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }

        for level in [tracing::Level::INFO, tracing::Level::DEBUG] {
            let bytes = Arc::new(Mutex::new(Vec::new()));
            let writer = Capture(Arc::clone(&bytes));
            let subscriber = tracing_subscriber::fmt()
                .json()
                .without_time()
                .with_max_level(level)
                .with_writer(move || writer.clone())
                .finish();
            tracing::subscriber::with_default(subscriber, || {
                let budget = WorkerBudget::for_test(
                    BYTES_PER_WORKER * MEMORY_HEADROOM_DIVISOR,
                    FDS_PER_WORKER * FD_HEADROOM_DIVISOR,
                    false,
                );
                for outcome in [Some(true), Some(false), None] {
                    let before = bytes.lock().unwrap().len();
                    let batch = budget.for_batch();
                    assert_eq!(
                        batch.snapshot_for_test().is_some(),
                        level == tracing::Level::DEBUG
                    );
                    assert_eq!(batch.available_workers(), 1);
                    let lease = batch.try_acquire().unwrap();
                    drop(lease);
                    if let Some(success) = outcome {
                        batch.finish(success);
                    }
                    assert_eq!(bytes.lock().unwrap().len(), before, "only Drop emits");
                    drop(batch);
                    assert_eq!(budget.available_workers(), 1);
                }
            });
            let output = String::from_utf8(bytes.lock().unwrap().clone()).unwrap();
            if level == tracing::Level::INFO {
                assert!(output.is_empty());
                continue;
            }
            let events: Vec<serde_json::Value> = output
                .lines()
                .map(|line| serde_json::from_str(line).unwrap())
                .collect();
            assert_eq!(events.len(), 3);
            for (event, outcome) in events.iter().zip(["returned", "failed", "interrupted"]) {
                assert_eq!(event["target"], "volparossa_agent::content::worker_budget");
                assert_eq!(event["level"], "DEBUG");
                let fields = event["fields"].as_object().unwrap();
                assert_eq!(fields.len(), 2);
                assert_eq!(fields["code"], "CONTENT_WORKER_BUDGET_SUMMARY");
                let summary: serde_json::Value =
                    serde_json::from_str(fields["budget"].as_str().unwrap()).unwrap();
                assert_eq!(summary.as_object().unwrap().len(), 13);
                assert_eq!(summary["outcome"], outcome);
                assert_eq!(summary["admitted_leases"], 1);
                assert_eq!(summary["peak_leases"], 1);
                assert_eq!(summary["active_leases"], 0);
                assert_eq!(summary["causes"].as_object().unwrap().len(), 8);
            }
        }
    }
}
