//! Closed observations of existing acquisition failures, not transport or cleanup authority.

use volparossa_routing::HelperResult;

use super::MptcpTransportError;
use crate::helper::HelperClientError;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Stage {
    SourcePort,
    RetirementDrain,
    Material,
    SlotReservation,
    HelperAcquire,
    DescriptorClone,
    DescriptorAdoption,
    FlowMetadata,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum Reason {
    Entropy,
    Metadata,
    LocalCapacity,
    LocalUnavailable,
    Unconfirmed,
    Io,
    Topology,
    HelperKernel,
    HelperCapacity,
    HelperUnavailable,
    HelperNotFound,
    HelperCleanupIncomplete,
    HelperOtherRejection,
    HelperTimeout,
    HelperIo,
    HelperValidation,
    HelperAuthority,
    HelperCorrelation,
    HelperRuntimeChanged,
}

impl Reason {
    pub(super) const fn helper(error: &HelperClientError) -> Self {
        match error {
            HelperClientError::Io(_) => Self::HelperIo,
            HelperClientError::UnsafeToken | HelperClientError::UntrustedServer => {
                Self::HelperAuthority
            }
            HelperClientError::Protocol(_)
            | HelperClientError::DescriptorHandoff(_)
            | HelperClientError::DescriptorValidation(_)
            | HelperClientError::CapabilityAlreadyUsed => Self::HelperValidation,
            HelperClientError::Timeout => Self::HelperTimeout,
            HelperClientError::Correlation => Self::HelperCorrelation,
            HelperClientError::RuntimeChanged => Self::HelperRuntimeChanged,
            HelperClientError::Rejected(result) => match result {
                HelperResult::Kernel => Self::HelperKernel,
                HelperResult::Capacity => Self::HelperCapacity,
                HelperResult::Unavailable => Self::HelperUnavailable,
                HelperResult::NotFound => Self::HelperNotFound,
                HelperResult::CleanupIncomplete => Self::HelperCleanupIncomplete,
                HelperResult::Unspecified
                | HelperResult::Ok
                | HelperResult::InvalidRequest
                | HelperResult::UnauthorisedPeer
                | HelperResult::AlreadyExists
                | HelperResult::Expired => Self::HelperOtherRejection,
            },
        }
    }

    const fn transport(error: &MptcpTransportError) -> Self {
        match error {
            MptcpTransportError::AcquireUnconfirmed => Self::Unconfirmed,
            MptcpTransportError::InvalidMetadata | MptcpTransportError::InsufficientPaths => {
                Self::Metadata
            }
            MptcpTransportError::Helper(error) => Self::helper(error),
            MptcpTransportError::Topology(_) => Self::Topology,
            MptcpTransportError::Io(_) => Self::Io,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Failure {
    pub(crate) stage: Stage,
    pub(crate) reason: Reason,
    pub(crate) helper_diagnostic: Option<volparossa_local_control::StorageFixtureHelperDiagnostic>,
}

/// This stack-local observer never retains the original error or any runtime identifier.
#[derive(Default)]
pub(crate) struct Observation(Option<Failure>);

impl Observation {
    pub(super) fn reset(&mut self) {
        self.0 = None;
    }

    pub(super) fn record(&mut self, stage: Stage, reason: Reason) {
        // Capture before the original error is propagated or mapped by cleanup ownership.
        // A later observation must not replace the first returned failing boundary.
        self.0.get_or_insert(Failure {
            stage,
            reason,
            helper_diagnostic: None,
        });
    }

    pub(super) fn helper_diagnostic(
        &mut self,
        diagnostic: Option<volparossa_local_control::StorageFixtureHelperDiagnostic>,
    ) {
        if let Some(failure) = &mut self.0 {
            if failure.stage == Stage::HelperAcquire {
                failure.helper_diagnostic = diagnostic;
            }
        }
    }

    pub(super) fn transport_error(
        &mut self,
        stage: Stage,
        error: MptcpTransportError,
    ) -> MptcpTransportError {
        self.record(stage, Reason::transport(&error));
        error
    }

    pub(super) fn required<T>(
        &mut self,
        stage: Stage,
        value: Option<T>,
    ) -> Result<T, MptcpTransportError> {
        value.ok_or_else(|| self.transport_error(stage, MptcpTransportError::InvalidMetadata))
    }

    pub(crate) const fn failure(&self) -> Option<Failure> {
        self.0
    }
}

/// First and last returned failures of this request's original bounded acquisition loop.
/// `rounds` counts loop iterations, not helper requests, flow slots or remote operations.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Summary {
    pub(crate) rounds: u8,
    pub(crate) first: Failure,
    pub(crate) last: Failure,
}

#[derive(Default)]
pub(crate) struct History {
    rounds: u8,
    first: Option<Failure>,
    last: Option<Failure>,
    incomplete: bool,
}

impl History {
    pub(crate) fn record_round(&mut self, failure: Option<Failure>) {
        // This bound does not control retries. The original caller still owns its 0..8 loop.
        if self.rounds == 8 {
            self.incomplete = true;
            return;
        }
        self.rounds += 1;
        if let Some(failure) = failure {
            self.first.get_or_insert(failure);
            self.last = Some(failure);
        } else {
            // A future uninstrumented branch may omit a diagnostic, never invent one.
            self.incomplete = true;
        }
    }

    pub(crate) fn summary(&self) -> Option<Summary> {
        if self.incomplete {
            return None;
        }
        Some(Summary {
            rounds: self.rounds,
            first: self.first?,
            last: self.last?,
        })
    }
}

#[cfg(test)]
mod tests;
