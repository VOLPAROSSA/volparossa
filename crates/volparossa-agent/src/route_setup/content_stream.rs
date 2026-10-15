//! Request-local, detail-free classification of a protected content stream opening.

use super::ClientRouteConnectError;
use crate::mptcp_flow_runtime::{
    ProductionMptcpClientActivationStage, ProductionMptcpClientFailure,
};
use crate::mptcp_transport::acquire_diagnostic::Summary;

/// Stages describe local control flow, not a new protocol or evidence of remote acceptance.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum ContentStreamOpenCause {
    Policy,
    RouteState,
    RouteMaterial,
    FlowAcquire,
    TransportCertificate,
    TransportTls,
    InitialPaths,
    OpenTcpWrite,
    SubflowReadiness,
    StreamAttachment,
}

/// Contains no peer-controlled error, hostname, socket address, path or key material.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct ContentStreamOpenFailure {
    cause: ContentStreamOpenCause,
    route_error: ClientRouteConnectError,
    flow_acquire: Option<Summary>,
}

impl ContentStreamOpenFailure {
    pub(super) const fn new(
        cause: ContentStreamOpenCause,
        route_error: ClientRouteConnectError,
    ) -> Self {
        Self {
            cause,
            route_error,
            flow_acquire: None,
        }
    }

    pub(super) const fn from_flow_acquire(
        route_error: ClientRouteConnectError,
        flow_acquire: Option<Summary>,
    ) -> Self {
        Self {
            cause: ContentStreamOpenCause::FlowAcquire,
            route_error,
            flow_acquire,
        }
    }

    pub(crate) const fn flow_acquire(self) -> Option<Summary> {
        self.flow_acquire
    }

    pub(crate) const fn cause(self) -> ContentStreamOpenCause {
        self.cause
    }

    pub(super) const fn into_route_error(self) -> ClientRouteConnectError {
        self.route_error
    }

    pub(super) fn from_activation(failure: &ProductionMptcpClientFailure) -> Self {
        Self::new(
            activation_cause(failure.stage()),
            ClientRouteConnectError::TransportRuntimeUnavailable,
        )
    }
}

const fn activation_cause(stage: ProductionMptcpClientActivationStage) -> ContentStreamOpenCause {
    match stage {
        ProductionMptcpClientActivationStage::Certificate => {
            ContentStreamOpenCause::TransportCertificate
        }
        ProductionMptcpClientActivationStage::Tls => ContentStreamOpenCause::TransportTls,
        ProductionMptcpClientActivationStage::InitialPaths => ContentStreamOpenCause::InitialPaths,
        ProductionMptcpClientActivationStage::OpenTcp => ContentStreamOpenCause::OpenTcpWrite,
        ProductionMptcpClientActivationStage::SubflowReadiness => {
            ContentStreamOpenCause::SubflowReadiness
        }
        ProductionMptcpClientActivationStage::StreamAttachment => {
            ContentStreamOpenCause::StreamAttachment
        }
    }
}

#[cfg(test)]
mod tests {
    use super::super::{ClientRouteControl, ClientTcpDestination};
    use super::*;
    use std::path::PathBuf;
    use volparossa_test_support::verified_development_manifest;

    #[test]
    fn content_flow_acquire_detail_preserves_original_cause_and_route_error() {
        use crate::mptcp_transport::acquire_diagnostic::{Failure, History, Reason, Stage};

        let mut history = History::default();
        history.record_round(Some(Failure {
            stage: Stage::HelperAcquire,
            reason: Reason::HelperCapacity,
        }));
        history.record_round(Some(Failure {
            stage: Stage::RetirementDrain,
            reason: Reason::Unconfirmed,
        }));
        let original = ClientRouteConnectError::TransportRuntimeUnavailable;
        let failure = ContentStreamOpenFailure::from_flow_acquire(original, history.summary());
        assert_eq!(failure.cause(), ContentStreamOpenCause::FlowAcquire);
        assert_eq!(failure.into_route_error(), original);
        assert_eq!(failure.flow_acquire(), history.summary());
        let no_detail = ContentStreamOpenFailure::from_flow_acquire(original, None);
        assert_eq!(no_detail.into_route_error(), original);
        assert_eq!(no_detail.flow_acquire(), None);
        assert_eq!(
            ContentStreamOpenFailure::new(ContentStreamOpenCause::Policy, original).flow_acquire(),
            None,
        );
    }

    #[test]
    fn content_flow_acquire_classification_does_not_change_route_loss_decisions() {
        use crate::helper::HelperClientError;
        use crate::mptcp_transport::MptcpTransportError;
        use volparossa_routing::HelperResult;

        for (error, lost) in [
            (MptcpTransportError::AcquireUnconfirmed, true),
            (MptcpTransportError::InvalidMetadata, false),
            (
                MptcpTransportError::Io(std::io::Error::other("private-canary")),
                false,
            ),
            (
                MptcpTransportError::Helper(HelperClientError::Rejected(HelperResult::Kernel)),
                false,
            ),
            (
                MptcpTransportError::Helper(HelperClientError::Rejected(HelperResult::Capacity)),
                false,
            ),
            (
                MptcpTransportError::Helper(HelperClientError::Rejected(HelperResult::Unavailable)),
                false,
            ),
            (
                MptcpTransportError::Helper(HelperClientError::Rejected(HelperResult::NotFound)),
                true,
            ),
            (
                MptcpTransportError::Helper(HelperClientError::Rejected(
                    HelperResult::CleanupIncomplete,
                )),
                true,
            ),
        ] {
            assert_eq!(
                super::super::mptcp_acquire_failure_lost_helper_route(&error),
                lost,
            );
        }
    }

    #[test]
    fn content_stream_activation_causes_are_exhaustively_distinct() {
        for (stage, cause) in [
            (
                ProductionMptcpClientActivationStage::Certificate,
                ContentStreamOpenCause::TransportCertificate,
            ),
            (
                ProductionMptcpClientActivationStage::Tls,
                ContentStreamOpenCause::TransportTls,
            ),
            (
                ProductionMptcpClientActivationStage::InitialPaths,
                ContentStreamOpenCause::InitialPaths,
            ),
            (
                ProductionMptcpClientActivationStage::OpenTcp,
                ContentStreamOpenCause::OpenTcpWrite,
            ),
            (
                ProductionMptcpClientActivationStage::SubflowReadiness,
                ContentStreamOpenCause::SubflowReadiness,
            ),
            (
                ProductionMptcpClientActivationStage::StreamAttachment,
                ContentStreamOpenCause::StreamAttachment,
            ),
        ] {
            assert_eq!(activation_cause(stage), cause);
        }
    }

    #[test]
    fn content_stream_failures_retain_only_finite_request_local_values() {
        let denied = ContentStreamOpenFailure::new(
            ContentStreamOpenCause::Policy,
            ClientRouteConnectError::TransportRuntimeUnavailable,
        );
        let busy = ContentStreamOpenFailure::new(
            ContentStreamOpenCause::RouteState,
            ClientRouteConnectError::Busy,
        );
        assert_eq!(busy.cause(), ContentStreamOpenCause::RouteState);
        assert_eq!(denied.cause(), ContentStreamOpenCause::Policy);
        assert_eq!(busy.into_route_error(), ClientRouteConnectError::Busy);
        assert_eq!(
            denied.into_route_error(),
            ClientRouteConnectError::TransportRuntimeUnavailable,
        );
        assert_eq!(
            format!("{denied:?}"),
            "ContentStreamOpenFailure { cause: Policy, route_error: TransportRuntimeUnavailable, \
             flow_acquire: None }",
        );
    }

    #[tokio::test]
    async fn content_stream_policy_denial_precedes_route_access_and_erases_private_inputs() {
        const NOW_MS: u64 = 1_700_000_000_000;
        let policy = verified_development_manifest(NOW_MS, Vec::new()).unwrap();
        let routes = ClientRouteControl::new(PathBuf::from("/private-control-canary.sock"));
        let denied = routes
            .open_content_stream_diagnosed(&policy, "private-host-canary.invalid", 443, NOW_MS)
            .await
            .err()
            .expect("empty policy rejects before any transport work");
        assert_eq!(denied.cause(), ContentStreamOpenCause::Policy);
        let diagnostic = format!("{denied:?}");
        assert!(!diagnostic.contains("private-host-canary"));
        assert!(!diagnostic.contains("private-control-canary"));
        assert_eq!(
            routes
                .open_content_stream(&policy, "private-host-canary.invalid", 443, NOW_MS)
                .await
                .err(),
            Some(ClientRouteConnectError::TransportRuntimeUnavailable),
        );
        assert!(routes.state.try_lock().is_ok());
    }

    #[tokio::test]
    async fn content_stream_idle_route_retains_busy_without_transport_work() {
        const NOW_MS: u64 = 1_700_000_000_000;
        let policy = verified_development_manifest(NOW_MS, Vec::new()).unwrap();
        let routes = ClientRouteControl::new(PathBuf::from("/private-control-canary.sock"));
        let destination = ClientTcpDestination::Hostname("private-host-canary.invalid".into());
        let failed = routes
            .acquire_tcp_flow_transport_diagnosed(&policy, &destination, 443, NOW_MS)
            .await
            .err()
            .expect("idle controller has no transport");
        assert_eq!(failed.cause(), ContentStreamOpenCause::RouteState);
        assert_eq!(failed.into_route_error(), ClientRouteConnectError::Busy);
        assert_eq!(
            routes
                .acquire_tcp_flow_transport(&policy, &destination, 443, NOW_MS)
                .await
                .err(),
            Some(ClientRouteConnectError::Busy),
        );
        assert!(routes.state.try_lock().is_ok());
    }
}
