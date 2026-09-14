//! Fixed, identity-free terminal stages; these observations never change route authority.

use super::ClientRouteConnectError;

#[derive(Clone, Copy, Debug)]
pub(super) enum BrowserFailureStage {
    RouteState,
    RouteAuthority,
    PacketScope,
    FlowBinding,
    FlowAuthorization,
    PacketSend,
    ActivityBinding,
    TelemetryNative,
    TelemetryProjection,
    TelemetryPublication,
}

impl BrowserFailureStage {
    pub(super) fn report(self) {
        // No error formatting: error values can carry identifiers or peer-controlled text.
        eprintln!("MPQUIC_BROWSER_FAILURE_STAGE={self:?}");
    }

    pub(super) fn reject(self) -> ClientRouteConnectError {
        self.report();
        ClientRouteConnectError::TransportRuntimeUnavailable
    }
}

#[cfg(test)]
mod tests {
    use super::{BrowserFailureStage, ClientRouteConnectError};

    #[test]
    fn browser_failure_stages_preserve_the_existing_terminal_error() {
        for stage in [
            BrowserFailureStage::RouteAuthority,
            BrowserFailureStage::PacketScope,
            BrowserFailureStage::FlowBinding,
            BrowserFailureStage::FlowAuthorization,
            BrowserFailureStage::PacketSend,
            BrowserFailureStage::ActivityBinding,
            BrowserFailureStage::TelemetryNative,
            BrowserFailureStage::TelemetryProjection,
            BrowserFailureStage::TelemetryPublication,
        ] {
            assert!(matches!(
                stage.reject(),
                ClientRouteConnectError::TransportRuntimeUnavailable
            ));
        }
        let ingress = include_str!("../lib.rs");
        let gate = ingress
            .split_once("MPQUIC_BROWSER_FAILURE_STAGE=GateReauthorization")
            .unwrap()
            .1;
        assert!(
            gate.find("routes.disconnect().await").unwrap()
                < gate.find("INGRESS_MPQUIC_DATAGRAM_REJECTED").unwrap()
        );
        let source = include_str!("../route_setup.rs");
        let send = source
            .split_once("pub(crate) async fn send_browser_quic_ingress(")
            .unwrap()
            .1
            .split_once("pub(crate) async fn receive_browser_quic_response(")
            .unwrap()
            .0;
        assert!(
            send.find(".record_sent(").unwrap()
                < send.find(".sample_path_summaries(false).await?").unwrap()
        );
        assert!(send.contains("BrowserFailureStage::PacketSend.reject()"));
        assert!(send.contains("BrowserFailureStage::ActivityBinding.reject()"));
        assert!(send.contains("BrowserFailureStage::TelemetryPublication.report()"));
    }
}
