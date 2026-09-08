//! Shared advisory RAM/descriptor reservations for protected foreground cache workers.
//!
//! Counts follow current resource headroom, not a configured peer-count target. A lease
//! precedes socket/TLS setup and survives its complete close/drop. This is a conservative
//! admission/pressure guard, not a kernel memory reservation or an owner-goodput guarantee.

use std::{
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};

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
    pressured: bool,
}

impl Snapshot {
    fn capacity(self) -> usize {
        let memory = self.memory / MEMORY_HEADROOM_DIVISOR / BYTES_PER_WORKER;
        let fds = self.fds / FD_HEADROOM_DIVISOR / FDS_PER_WORKER;
        usize::try_from(memory.min(fds)).unwrap_or(usize::MAX)
    }
}

impl State {
    fn snapshot(&mut self) -> Option<Snapshot> {
        #[cfg(test)]
        if let Some(fixed) = self.fixed {
            return Some(fixed);
        }
        let at = Instant::now();
        if let Some((sampled, value)) = self.sampled {
            if at.saturating_duration_since(sampled) < SAMPLE_AGE {
                return value;
            }
        }
        let value = crate::resource_headroom::capture().map(|snapshot| Snapshot {
            memory: snapshot.memory_bytes,
            fds: snapshot.available_fds,
            pressured: snapshot.pressured,
        });
        self.sampled = Some((at, value));
        value
    }
}

impl WorkerBudget {
    /// Currently unreserved worker units; this does not authorize a future socket open.
    pub(super) fn available_workers(&self) -> usize {
        let Ok(mut state) = self.0.lock() else {
            return 0;
        };
        let Some(snapshot) = state.snapshot() else {
            return 0;
        };
        let capacity = if snapshot.pressured {
            snapshot.capacity().min(1)
        } else {
            snapshot.capacity()
        };
        capacity.saturating_sub(state.held)
    }

    /// Absolute allowance for one download, including its existing reservations.
    /// Pressure drains each existing download to one worker while new shared admission stays
    /// closed. This preserves existing foreground progress; it is not a one-stream global
    /// eviction policy. Actual RAM/descriptor capacity remains shared across all downloads.
    pub(super) fn allowance(&self, local_active: usize) -> usize {
        let Ok(mut state) = self.0.lock() else {
            return 0;
        };
        let Some(snapshot) = state.snapshot() else {
            return 0;
        };
        let others = state.held.saturating_sub(local_active);
        let available = snapshot.capacity().saturating_sub(others);
        if snapshot.pressured {
            available.min(1)
        } else {
            available
        }
    }

    /// Atomically reserve shared accounting before allocating a new protected worker flow.
    pub(super) fn try_acquire(&self) -> Option<WorkerLease> {
        let mut state = self.0.lock().ok()?;
        let snapshot = state.snapshot()?;
        let capacity = if snapshot.pressured {
            snapshot.capacity().min(1)
        } else {
            snapshot.capacity()
        };
        if state.held >= capacity {
            return None;
        }
        state.held = state.held.checked_add(1)?;
        Some(WorkerLease(Arc::clone(&self.0)))
    }

    #[cfg(test)]
    pub(super) fn for_test(memory: u64, fds: u64, pressured: bool) -> Self {
        Self(Arc::new(Mutex::new(State {
            fixed: Some(Snapshot {
                memory,
                fds,
                pressured,
            }),
            ..State::default()
        })))
    }
}

/// Not cloneable: one live worker owns one shared reservation until its flow has closed.
pub(super) struct WorkerLease(Arc<Mutex<State>>);

impl Drop for WorkerLease {
    fn drop(&mut self) {
        if let Ok(mut state) = self.0.lock() {
            state.held = state.held.saturating_sub(1);
        }
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
        budget.0.lock().unwrap().fixed.as_mut().unwrap().pressured = true;
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
        budget.0.lock().unwrap().fixed.as_mut().unwrap().pressured = true;
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
}
