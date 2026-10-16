//! Request-local pre-READY boundaries; no strings or inferred remote causes.

use std::{
    future::Future,
    sync::atomic::{AtomicI32, Ordering},
    time::Duration,
};

use tokio::{
    net::UnixStream,
    time::{Instant, timeout_at},
};
use volparossa_content::private_storage::wire::begin_observation::{self, Observer};
use volparossa_local_control::{
    PrivateStorageChallengePhase, PrivateStorageDeadlineScope as Deadline,
    PrivateStorageRemoteDetail, PrivateStorageRemoteStage as Stage, PrivateStorageStreamFailure,
    PrivateStorageTlsFailure, StorageFixtureCorrelationPhase as FixturePhase,
    StorageFixtureCorrelationTerminal as FixtureTerminal,
};

use super::{ContentError, until_requester_closed};
use crate::route_setup::ContentStreamOpenCause;

mod challenge;
mod flow_acquire;

pub(super) const fn stream_failure(cause: ContentStreamOpenCause) -> PrivateStorageStreamFailure {
    match cause {
        ContentStreamOpenCause::Policy => PrivateStorageStreamFailure::Policy,
        ContentStreamOpenCause::RouteState => PrivateStorageStreamFailure::RouteState,
        ContentStreamOpenCause::RouteMaterial => PrivateStorageStreamFailure::RouteMaterial,
        ContentStreamOpenCause::FlowAcquire => PrivateStorageStreamFailure::FlowAcquire,
        ContentStreamOpenCause::TransportCertificate => {
            PrivateStorageStreamFailure::TransportCertificate
        }
        ContentStreamOpenCause::TransportTls => PrivateStorageStreamFailure::TransportTls,
        ContentStreamOpenCause::InitialPaths => PrivateStorageStreamFailure::InitialPaths,
        ContentStreamOpenCause::OpenTcpWrite => PrivateStorageStreamFailure::OpenTcpWrite,
        ContentStreamOpenCause::SubflowReadiness => PrivateStorageStreamFailure::SubflowReadiness,
        ContentStreamOpenCause::StreamAttachment => PrivateStorageStreamFailure::StreamAttachment,
    }
}

#[derive(Default)]
pub(super) struct Observation {
    // Shared references remain Send across the existing asynchronous control task.
    // All access belongs to that one task; no observer task or runtime identifiers.
    stage: AtomicI32,
    deadline: AtomicI32,
    tls_failure: AtomicI32,
    stream_failure: AtomicI32,
    challenge: challenge::Progress,
    flow_acquire: flow_acquire::Progress,
    fixture: super::super::fixture_correlation::Guard,
}

impl Observation {
    pub(super) fn with_fixture(
        mut self,
        fixture: super::super::fixture_correlation::Guard,
    ) -> Self {
        self.fixture = fixture;
        self
    }

    pub(super) const fn fixture(&self) -> &super::super::fixture_correlation::Guard {
        &self.fixture
    }

    pub(super) fn new(include_flow_acquire_detail: bool) -> Self {
        Self {
            flow_acquire: flow_acquire::Progress::new(include_flow_acquire_detail),
            ..Self::default()
        }
    }

    pub(super) fn operation_started(&self) -> Option<Instant> {
        self.challenge.operation_started()
    }

    pub(super) fn deadline(&self) -> Deadline {
        Deadline::try_from(self.deadline.load(Ordering::Relaxed)).unwrap_or(Deadline::None)
    }

    pub(super) fn reset(&self) {
        self.challenge.reset();
        self.flow_acquire.reset();
        self.stage
            .store(Stage::Unobserved as i32, Ordering::Relaxed);
        self.deadline
            .store(Deadline::None as i32, Ordering::Relaxed);
        self.tls_failure.store(
            PrivateStorageTlsFailure::Unobserved as i32,
            Ordering::Relaxed,
        );
        self.stream_failure.store(
            PrivateStorageStreamFailure::Unobserved as i32,
            Ordering::Relaxed,
        );
    }

    pub(super) fn record_tls_failure(&self, failure: PrivateStorageTlsFailure) {
        if self.stage.load(Ordering::Relaxed) == Stage::TlsHandshake as i32
            && self.deadline.load(Ordering::Relaxed) == Deadline::None as i32
            && failure != PrivateStorageTlsFailure::Unobserved
        {
            self.tls_failure.store(failure as i32, Ordering::Relaxed);
            self.fixture.finish(match failure {
                PrivateStorageTlsFailure::HandshakeDeadline => FixtureTerminal::TlsTimeout,
                PrivateStorageTlsFailure::Authentication
                | PrivateStorageTlsFailure::TlsOther
                | PrivateStorageTlsFailure::Io => FixtureTerminal::TlsError,
                _ => FixtureTerminal::OperationError,
            });
        }
    }

    pub(super) fn record_stream_failure(&self, failure: PrivateStorageStreamFailure) {
        if self.stage.load(Ordering::Relaxed) == Stage::StreamOpen as i32
            && self.deadline.load(Ordering::Relaxed) == Deadline::None as i32
            && failure != PrivateStorageStreamFailure::Unobserved
        {
            self.stream_failure.store(failure as i32, Ordering::Relaxed);
        }
    }

    pub(super) fn record_flow_acquire(
        &self,
        summary: Option<crate::mptcp_transport::acquire_diagnostic::Summary>,
    ) {
        if self.stage.load(Ordering::Relaxed) == Stage::StreamOpen as i32
            && self.deadline.load(Ordering::Relaxed) == Deadline::None as i32
            && self.stream_failure.load(Ordering::Relaxed)
                == PrivateStorageStreamFailure::FlowAcquire as i32
        {
            self.flow_acquire.record(summary);
        }
    }

    pub(super) fn detail(&self) -> Option<PrivateStorageRemoteDetail> {
        let stage = self.stage.load(Ordering::Relaxed);
        let deadline_scope = self.deadline.load(Ordering::Relaxed);
        let failure = self.tls_failure.load(Ordering::Relaxed);
        let stream_failure = self.stream_failure.load(Ordering::Relaxed);
        let detail = PrivateStorageRemoteDetail {
            stage,
            deadline_scope,
            tls_failure: (failure != PrivateStorageTlsFailure::Unobserved as i32)
                .then_some(failure),
            stream_failure: (stream_failure != PrivateStorageStreamFailure::Unobserved as i32)
                .then_some(stream_failure),
            challenge: self.challenge.detail(),
            flow_acquire: self.flow_acquire.detail(),
        };
        // No observation for policy/resource/cancel, or an inner deadline while
        // awaiting an uninstrumented policy recheck. Never invent that boundary.
        detail.validate().is_ok().then_some(detail)
    }

    pub(super) async fn boundary<T>(
        &self,
        stage: Stage,
        preparation: impl Future<Output = Result<T, ContentError>>,
    ) -> Result<T, ContentError> {
        self.reset();
        self.stage.store(stage as i32, Ordering::Relaxed);
        self.fixture.enter(match stage {
            Stage::TlsHandshake => FixturePhase::TlsHandshake,
            Stage::Challenge => FixturePhase::ClientChallenge,
            _ => FixturePhase::FlowAcquire,
        });
        if stage == Stage::Challenge {
            self.challenge.enter();
        }
        let result = preparation.await;
        if result.is_ok() {
            self.reset();
        } else {
            self.challenge.fail();
        }
        result
    }

    pub(super) async fn requester_boundary<T>(
        &self,
        stage: Stage,
        local: &mut UnixStream,
        preparation: impl Future<Output = Result<T, ContentError>>,
    ) -> Result<T, ContentError> {
        self.reset();
        let mut completed = false;
        let result = until_requester_closed(local, async {
            // Set the stage only if the existing biased cancellation gate actually
            // polls this future. An already closed requester starts no boundary.
            let result = self.boundary(stage, preparation).await;
            completed = true;
            result
        })
        .await;
        if !completed {
            self.fixture.finish(FixtureTerminal::Cancelled);
            self.reset();
        }
        result
    }

    pub(super) fn budget<T>(
        &self,
        scope: Deadline,
        duration: Duration,
        operation: impl Future<Output = Result<T, ContentError>>,
    ) -> impl Future<Output = Result<T, ContentError>> {
        // Construct the original timeout now, not lazily on our first poll: the
        // diagnostic wrapper must not shift the existing absolute deadline.
        let started = Instant::now();
        let operation = timeout_at(started + duration, operation);
        if scope == Deadline::Operation {
            // The observation and deadline share this same construction-time instant,
            // not a second clock reading or the first poll after admission waiting.
            self.challenge.start_operation(started);
        }
        async move {
            if let Ok(result) = operation.await {
                result
            } else {
                self.fixture.finish(FixtureTerminal::OperationError);
                self.challenge.fail();
                self.flow_acquire.reset();
                self.tls_failure.store(
                    PrivateStorageTlsFailure::Unobserved as i32,
                    Ordering::Relaxed,
                );
                self.stream_failure.store(
                    PrivateStorageStreamFailure::Unobserved as i32,
                    Ordering::Relaxed,
                );
                self.deadline.store(scope as i32, Ordering::Relaxed);
                Err(ContentError::Unavailable)
            }
        }
    }
}

impl Observer for Observation {
    fn phase(&self, phase: begin_observation::Phase) {
        if self.stage.load(Ordering::Relaxed) == Stage::Challenge as i32 {
            self.fixture.enter(FixturePhase::ClientChallenge);
            self.challenge.phase(match phase {
                begin_observation::Phase::SelectorWriteFlush => {
                    PrivateStorageChallengePhase::SelectorWriteFlush
                }
                begin_observation::Phase::GrantWriteFlush => {
                    PrivateStorageChallengePhase::GrantWriteFlush
                }
                begin_observation::Phase::ChallengeReadVerify => {
                    PrivateStorageChallengePhase::ChallengeReadVerify
                }
            });
        }
    }
}

#[cfg(test)]
mod tests;

#[cfg(test)]
mod fixture_correlation_tests;
