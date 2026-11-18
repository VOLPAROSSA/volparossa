//! One opt-in, bounded batch summary; never raw resource data or peer/user identifiers.

use std::sync::{Arc, Mutex};

use serde::Serialize;

use super::{PressureState, Snapshot};

#[derive(Clone, Copy, Default, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Outcome {
    Returned,
    Failed,
    #[default]
    Interrupted,
}

#[derive(Clone, Copy, Default, Serialize)]
// Independent, cumulative observations in a closed diagnostic schema, not exclusive states.
#[allow(clippy::struct_excessive_bools)]
struct Causes {
    cpu_pressure: bool,
    memory_pressure: bool,
    io_pressure: bool,
    cpu_unavailable: bool,
    memory_unavailable: bool,
    io_unavailable: bool,
    resource_unavailable: bool,
    lock_unavailable: bool,
}

/// Counts saturate at `u32::MAX`; this never clamps the actual resource decision.
#[derive(Clone, Serialize)]
struct Summary {
    schema_version: u8,
    outcome: Outcome,
    initial_allowance: Option<u32>,
    min_allowance: Option<u32>,
    max_allowance: Option<u32>,
    min_memory_workers: Option<u32>,
    min_fd_workers: Option<u32>,
    peak_shared_held: u32,
    admitted_leases: u32,
    denied_leases: u32,
    peak_leases: u32,
    active_leases: u32,
    causes: Causes,
}

impl Default for Summary {
    fn default() -> Self {
        Self {
            schema_version: 1,
            outcome: Outcome::Interrupted,
            initial_allowance: None,
            min_allowance: None,
            max_allowance: None,
            min_memory_workers: None,
            min_fd_workers: None,
            peak_shared_held: 0,
            admitted_leases: 0,
            denied_leases: 0,
            peak_leases: 0,
            active_leases: 0,
            causes: Causes::default(),
        }
    }
}

#[derive(Clone)]
pub(super) struct Diagnostics(Arc<Mutex<Summary>>);

fn bounded(value: impl TryInto<u32>) -> u32 {
    value.try_into().unwrap_or(u32::MAX)
}

fn minimum(current: &mut Option<u32>, value: u32) {
    *current = Some(current.map_or(value, |prior| prior.min(value)));
}

impl Diagnostics {
    pub(super) fn new() -> Self {
        Self(Arc::new(Mutex::new(Summary::default())))
    }

    pub(super) fn observe(
        &self,
        snapshot: Option<Snapshot>,
        held: Option<usize>,
        allowance: Option<usize>,
    ) {
        let mut summary = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(allowance) = allowance {
            let allowance = bounded(allowance);
            summary.initial_allowance.get_or_insert(allowance);
            minimum(&mut summary.min_allowance, allowance);
            summary.max_allowance = Some(
                summary
                    .max_allowance
                    .map_or(allowance, |prior| prior.max(allowance)),
            );
        }
        let Some(held) = held else {
            summary.causes.lock_unavailable = true;
            return;
        };
        summary.peak_shared_held = summary.peak_shared_held.max(bounded(held));
        let Some(snapshot) = snapshot else {
            summary.causes.resource_unavailable = true;
            return;
        };
        minimum(
            &mut summary.min_memory_workers,
            bounded(snapshot.memory_workers()),
        );
        minimum(&mut summary.min_fd_workers, bounded(snapshot.fd_workers()));
        let causes = &mut summary.causes;
        causes.cpu_pressure |= snapshot.pressure.cpu == PressureState::AtOrAboveThreshold;
        causes.memory_pressure |= snapshot.pressure.memory == PressureState::AtOrAboveThreshold;
        causes.io_pressure |= snapshot.pressure.io == PressureState::AtOrAboveThreshold;
        causes.cpu_unavailable |= snapshot.pressure.cpu == PressureState::Unavailable;
        causes.memory_unavailable |= snapshot.pressure.memory == PressureState::Unavailable;
        causes.io_unavailable |= snapshot.pressure.io == PressureState::Unavailable;
    }

    pub(super) fn admission(&self, admitted: bool) {
        let mut summary = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if admitted {
            summary.admitted_leases = summary.admitted_leases.saturating_add(1);
            summary.active_leases = summary.active_leases.saturating_add(1);
            summary.peak_leases = summary.peak_leases.max(summary.active_leases);
        } else {
            summary.denied_leases = summary.denied_leases.saturating_add(1);
        }
    }

    pub(super) fn release(&self) {
        let mut summary = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        summary.active_leases = summary.active_leases.saturating_sub(1);
    }

    pub(super) fn set_outcome(&self, outcome: Outcome) {
        self.0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .outcome = outcome;
    }

    pub(super) fn emit(&self) {
        let summary = self
            .0
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .clone();
        // Serialization is closed and fixed-size; no errors or raw data are interpolated.
        if let Ok(budget) = serde_json::to_string(&summary) {
            tracing::debug!(target: "volparossa_agent::content::worker_budget",
                code = "CONTENT_WORKER_BUDGET_SUMMARY", budget = %budget);
        }
    }

    #[cfg(test)]
    pub(super) fn snapshot_for_test(&self) -> serde_json::Value {
        serde_json::to_value(
            self.0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner)
                .clone(),
        )
        .unwrap()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::resource_headroom::PressureObservation;

    #[test]
    fn missing_resource_and_lock_do_not_invent_psi_observations() {
        for (held, reason) in [
            (None, "lock_unavailable"),
            (Some(0), "resource_unavailable"),
        ] {
            let diagnostic = Diagnostics::new();
            diagnostic.observe(None, held, Some(0));
            let value = diagnostic.snapshot_for_test();
            assert!(value["min_memory_workers"].is_null());
            assert!(value["min_fd_workers"].is_null());
            assert_eq!(value["initial_allowance"], 0);
            let causes = value["causes"].as_object().unwrap();
            assert_eq!(causes.len(), 8);
            assert!(causes.iter().all(|(key, value)| value == (key == reason)));
        }
    }

    #[test]
    fn diagnostic_counts_are_finite_saturating_and_schema_is_closed() {
        let diagnostic = Diagnostics::new();
        diagnostic.observe(
            Some(Snapshot {
                memory: u64::MAX,
                fds: u64::MAX,
                pressure: PressureObservation::default(),
            }),
            Some(usize::MAX),
            Some(usize::MAX),
        );
        {
            let mut summary = diagnostic.0.lock().unwrap();
            summary.admitted_leases = u32::MAX;
            summary.denied_leases = u32::MAX;
            summary.active_leases = u32::MAX;
        }
        diagnostic.admission(true);
        diagnostic.admission(false);
        let value = diagnostic.snapshot_for_test();
        assert_eq!(value.as_object().unwrap().len(), 13);
        for key in [
            "initial_allowance",
            "min_allowance",
            "max_allowance",
            "min_memory_workers",
            "min_fd_workers",
            "peak_shared_held",
            "admitted_leases",
            "denied_leases",
            "peak_leases",
            "active_leases",
        ] {
            assert_eq!(value[key], u32::MAX);
        }
        assert_eq!(value["outcome"], "interrupted");
    }
}
