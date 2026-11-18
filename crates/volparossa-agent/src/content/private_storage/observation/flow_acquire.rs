//! One request's opt-in closed projection. No I/O, locks, identifiers or error strings.

use std::sync::atomic::{AtomicI32, Ordering};

use volparossa_local_control::{
    PrivateStorageFlowAcquireDetail as Detail, PrivateStorageFlowAcquireFailure as Failure,
    PrivateStorageFlowAcquireReason as Reason, PrivateStorageFlowAcquireStage as Stage,
};

use crate::mptcp_transport::acquire_diagnostic as source;

#[derive(Default)]
pub(super) struct Progress {
    enabled: bool,
    // One atomic snapshot: rounds(4), first stage(4)/reason(5), last stage(4)/reason(5).
    // Zero means no observation. All fields are validated before packing; this is
    // private in-memory state, not an additional wire encoding or task owner.
    snapshot: AtomicI32,
}

impl Progress {
    pub(super) fn new(enabled: bool) -> Self {
        Self {
            enabled,
            ..Self::default()
        }
    }

    pub(super) fn reset(&self) {
        self.snapshot.store(0, Ordering::Relaxed);
    }

    pub(super) fn record(&self, summary: Option<source::Summary>) {
        if !self.enabled {
            return;
        }
        self.reset();
        let Some(summary) = summary else {
            return;
        };
        let first = failure(summary.first);
        let last = failure(summary.last);
        let detail = Detail {
            rounds: u32::from(summary.rounds),
            first: Some(first),
            last: Some(last),
        };
        if detail.validate().is_err() {
            return;
        }
        let snapshot = (i32::from(summary.rounds) << 18)
            | (first.stage << 14)
            | (first.reason << 9)
            | (last.stage << 5)
            | last.reason;
        self.snapshot.store(snapshot, Ordering::Relaxed);
    }

    pub(super) fn detail(&self) -> Option<Detail> {
        if !self.enabled {
            return None;
        }
        let snapshot = self.snapshot.load(Ordering::Relaxed);
        let detail = Detail {
            rounds: u32::try_from(snapshot >> 18).ok()?,
            first: Some(Failure {
                stage: (snapshot >> 14) & 15,
                reason: (snapshot >> 9) & 31,
            }),
            last: Some(Failure {
                stage: (snapshot >> 5) & 15,
                reason: snapshot & 31,
            }),
        };
        detail.validate().is_ok().then_some(detail)
    }
}

fn failure(value: source::Failure) -> Failure {
    let stage = match value.stage {
        source::Stage::SourcePort => Stage::SourcePort,
        source::Stage::RetirementDrain => Stage::RetirementDrain,
        source::Stage::Material => Stage::Material,
        source::Stage::SlotReservation => Stage::SlotReservation,
        source::Stage::HelperAcquire => Stage::HelperAcquire,
        source::Stage::DescriptorClone => Stage::DescriptorClone,
        source::Stage::DescriptorAdoption => Stage::DescriptorAdoption,
        source::Stage::FlowMetadata => Stage::FlowMetadata,
    };
    let reason = match value.reason {
        source::Reason::Entropy => Reason::Entropy,
        source::Reason::Metadata => Reason::Metadata,
        source::Reason::LocalCapacity => Reason::LocalCapacity,
        source::Reason::LocalUnavailable => Reason::LocalUnavailable,
        source::Reason::Unconfirmed => Reason::Unconfirmed,
        source::Reason::Io => Reason::Io,
        source::Reason::Topology => Reason::Topology,
        source::Reason::HelperKernel => Reason::HelperKernel,
        source::Reason::HelperCapacity => Reason::HelperCapacity,
        source::Reason::HelperUnavailable => Reason::HelperUnavailable,
        source::Reason::HelperNotFound => Reason::HelperNotFound,
        source::Reason::HelperCleanupIncomplete => Reason::HelperCleanupIncomplete,
        source::Reason::HelperOtherRejection => Reason::HelperOtherRejection,
        source::Reason::HelperTimeout => Reason::HelperTimeout,
        source::Reason::HelperIo => Reason::HelperIo,
        source::Reason::HelperValidation => Reason::HelperValidation,
        source::Reason::HelperAuthority => Reason::HelperAuthority,
        source::Reason::HelperCorrelation => Reason::HelperCorrelation,
        source::Reason::HelperRuntimeChanged => Reason::HelperRuntimeChanged,
    };
    Failure {
        stage: stage as i32,
        reason: reason as i32,
    }
}

pub(super) fn fixture_detail(
    value: source::Summary,
) -> volparossa_local_control::StorageFixtureAcquireSummary {
    use volparossa_local_control::{StorageFixtureAcquireFailure, StorageFixtureAcquireSummary};
    let project = |value: source::Failure| StorageFixtureAcquireFailure {
        failure: Some(failure(value)),
        helper_diagnostic: value.helper_diagnostic.map(|code| code as i32),
    };
    StorageFixtureAcquireSummary {
        rounds: u32::from(value.rounds),
        first: Some(project(value.first)),
        last: Some(project(value.last)),
    }
}

#[cfg(test)]
mod tests;
