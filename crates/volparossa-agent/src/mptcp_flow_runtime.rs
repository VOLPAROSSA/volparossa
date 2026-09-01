//! One-flow TLS 1.3 and signed `OPEN_TCP` runtime over committed MPTCP routes.

use std::time::Duration;

use pem::parse;
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::time;
use volparossa_exit::{
    ActiveTcpEgressRoute, ActiveTcpRoute, ExitNativeRouteAuthorization, ExitService,
    TcpEgressLimits,
};
use volparossa_tcp_proxy::{
    StreamTransferLimits, StreamTransferStats, Tls13MptcpClient, Tls13MptcpServer,
    Tls13MptcpStream, VerifiedMptcpRoute, write_open_tcp,
};

use crate::{
    helper::{HelperClient, RuntimeBoundPreparedLeaseBatch},
    mptcp_transport::{
        ClientMptcpEndpointCleanup, ClientMptcpTransport, ExitMptcpTransport, MptcpTransportError,
    },
    udp_exit_provider::route_certificate_der,
    unix_millis,
};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(12);
const OPEN_TCP_TIMEOUT: Duration = Duration::from_secs(12);
const EXIT_ACCEPT_TIMEOUT: Duration = Duration::from_secs(30);
const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const STREAM_BUFFER_BYTES: usize = 64 * 1_024;
const MAXIMUM_DIRECTIONAL_BYTES: u64 = 512 * 1_024 * 1_024;

/// A one-shot Exit listener, TLS identity, signed-flow verifier and Internet egress owner.
///
/// Construction consumes the activated TCP route and helper owner. `run` accepts only genuine
/// MPTCP, negotiates TLS 1.3 with the route certificate, verifies one bounded `OPEN_TCP`, and only
/// then opens policy-approved ordinary TCP at the Exit.
#[must_use = "the active MPTCP Exit runtime must be run or shut down"]
pub(crate) struct ProductionMptcpExitRuntime {
    helper: HelperClient,
    helper_owner: RuntimeBoundPreparedLeaseBatch,
    transport: ExitMptcpTransport,
    tls: Tls13MptcpServer,
    egress: ActiveTcpEgressRoute,
    limits: TcpEgressLimits,
}

impl ProductionMptcpExitRuntime {
    #[allow(
        clippy::too_many_arguments,
        reason = "affine production route ownership transfer"
    )]
    pub(crate) fn new(
        helper: HelperClient,
        helper_owner: RuntimeBoundPreparedLeaseBatch,
        transport: ExitMptcpTransport,
        tcp_route: ActiveTcpRoute,
        authorization: ExitNativeRouteAuthorization,
        exit_service: &ExitService,
        now_ms: u64,
    ) -> Result<Self, ProductionMptcpExitFailure> {
        macro_rules! fail {
            ($cause:expr) => {
                return Err(ProductionMptcpExitFailure::new(
                    $cause,
                    ProductionMptcpExitCleanup {
                        helper,
                        helper_owner,
                        transport: Some(transport),
                    },
                ))
            };
        }
        let Ok(certificate_der) = route_certificate_der(&authorization) else {
            fail!(ProductionMptcpExitError::TlsIdentity);
        };
        let Ok(private_key) = parse(authorization.tls_private_key_pem()) else {
            fail!(ProductionMptcpExitError::TlsIdentity);
        };
        let private_key =
            PrivateKeyDer::from(PrivatePkcs8KeyDer::from(private_key.into_contents()));
        drop(authorization);
        let Ok(tls) =
            Tls13MptcpServer::new(vec![CertificateDer::from(certificate_der)], private_key)
        else {
            fail!(ProductionMptcpExitError::TlsIdentity);
        };
        let Ok(egress) = exit_service.detach_tcp_egress_route(tcp_route, now_ms) else {
            fail!(ProductionMptcpExitError::Authorization);
        };
        let Ok(limits) = production_tcp_limits() else {
            fail!(ProductionMptcpExitError::Egress);
        };
        Ok(Self {
            helper,
            helper_owner,
            transport,
            tls,
            egress,
            limits,
        })
    }

    pub(crate) fn reservation_id(&self) -> [u8; 16] {
        *self.egress.reservation_id()
    }

    /// Run one complete `MPTCP/TLS/OPEN_TCP/egress` flow and always attempt exact helper cleanup.
    pub(crate) async fn run(self) -> ProductionMptcpExitCompletion {
        let reservation_id = self.reservation_id();
        let Self {
            helper,
            helper_owner,
            transport,
            tls,
            mut egress,
            limits,
        } = self;
        let flow_result = async {
            let (mptcp, _peer) = time::timeout(EXIT_ACCEPT_TIMEOUT, transport.listener().accept())
                .await
                .map_err(|_| ProductionMptcpExitError::Accept)?
                .map_err(|_| ProductionMptcpExitError::Accept)?;
            let mut protected = tls
                .accept(mptcp, TLS_HANDSHAKE_TIMEOUT)
                .await
                .map_err(|_| ProductionMptcpExitError::TlsHandshake)?;
            let authorized = egress
                .read_authorized_open_tcp(&mut protected, unix_millis(), OPEN_TCP_TIMEOUT)
                .await
                .map_err(|_| ProductionMptcpExitError::Authorization)?;
            egress
                .run_tcp_egress(&authorized, protected, unix_millis(), limits)
                .await
                .map_err(|_| ProductionMptcpExitError::Egress)
        }
        .await;

        let _ = transport.shutdown(&helper).await;
        let cleanup = ProductionMptcpExitCleanup {
            helper,
            helper_owner,
            transport: None,
        };
        match cleanup.destroy().await {
            Ok(()) => ProductionMptcpExitCompletion {
                reservation_id,
                result: flow_result,
                cleanup: None,
            },
            Err(cleanup) => ProductionMptcpExitCompletion {
                reservation_id,
                result: Err(ProductionMptcpExitError::CleanupPending),
                cleanup: Some(cleanup),
            },
        }
    }

    pub(crate) async fn shutdown(self) -> Result<(), ProductionMptcpExitCleanup> {
        let Self {
            helper,
            helper_owner,
            transport,
            ..
        } = self;
        let _ = transport.shutdown(&helper).await;
        ProductionMptcpExitCleanup {
            helper,
            helper_owner,
            transport: None,
        }
        .destroy()
        .await
    }
}

/// Completion returned to the actor so it can release the exact reservation.
pub(crate) struct ProductionMptcpExitCompletion {
    reservation_id: [u8; 16],
    result: Result<StreamTransferStats, ProductionMptcpExitError>,
    cleanup: Option<ProductionMptcpExitCleanup>,
}

impl ProductionMptcpExitCompletion {
    pub(crate) const fn reservation_id(&self) -> &[u8; 16] {
        &self.reservation_id
    }

    pub(crate) const fn succeeded(&self) -> bool {
        self.result.is_ok()
    }

    pub(crate) fn into_cleanup(self) -> Option<ProductionMptcpExitCleanup> {
        self.cleanup
    }
}

/// Exact helper owner retained when asynchronous Exit cleanup needs retry.
#[must_use = "pending MPTCP Exit cleanup must be retried"]
pub(crate) struct ProductionMptcpExitCleanup {
    helper: HelperClient,
    helper_owner: RuntimeBoundPreparedLeaseBatch,
    transport: Option<ExitMptcpTransport>,
}

impl ProductionMptcpExitCleanup {
    pub(crate) async fn destroy(mut self) -> Result<(), Self> {
        if let Some(transport) = self.transport.take() {
            let _ = transport.shutdown(&self.helper).await;
        }
        if self
            .helper
            .destroy_context(&self.helper_owner)
            .await
            .is_ok()
        {
            Ok(())
        } else {
            Err(self)
        }
    }
}

/// Activation failure that preserves every still-live helper cleanup capability.
#[must_use = "failed MPTCP Exit activation may still require helper cleanup"]
pub(crate) struct ProductionMptcpExitFailure {
    cause: ProductionMptcpExitError,
    cleanup: Option<ProductionMptcpExitCleanup>,
}

impl ProductionMptcpExitFailure {
    fn new(cause: ProductionMptcpExitError, cleanup: ProductionMptcpExitCleanup) -> Self {
        Self {
            cause,
            cleanup: Some(cleanup),
        }
    }

    pub(crate) const fn cause(&self) -> ProductionMptcpExitError {
        self.cause
    }

    pub(crate) fn into_cleanup(mut self) -> ProductionMptcpExitCleanup {
        self.cleanup.take().expect("MPTCP Exit cleanup owner")
    }
}

/// Detail-free stage at which one production MPTCP flow failed.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ProductionMptcpExitError {
    #[error("route TLS identity is unavailable")]
    TlsIdentity,
    #[error("MPTCP accept failed or timed out")]
    Accept,
    #[error("TLS 1.3 handshake failed")]
    TlsHandshake,
    #[error("signed OPEN_TCP authorization failed")]
    Authorization,
    #[error("authorized Exit TCP egress failed")]
    Egress,
    #[error("exact helper cleanup remains pending")]
    CleanupPending,
}

/// Live TLS 1.3 stream plus endpoint cleanup after a client `OPEN_TCP` was written.
#[must_use = "the active MPTCP client flow must be used or shut down"]
pub(crate) struct ActiveProductionMptcpClientFlow {
    stream: Tls13MptcpStream,
    endpoint_cleanup: ClientMptcpEndpointCleanup,
}

impl ActiveProductionMptcpClientFlow {
    pub(crate) fn stream_mut(&mut self) -> &mut Tls13MptcpStream {
        &mut self.stream
    }

    pub(crate) async fn shutdown(self, helper: &HelperClient) -> Result<(), MptcpTransportError> {
        drop(self.stream);
        self.endpoint_cleanup.shutdown(helper).await
    }
}

/// Wrap one helper-owned genuine MPTCP connection in pinned TLS 1.3 and write `OPEN_TCP`.
#[allow(
    clippy::too_many_arguments,
    reason = "complete authenticated client flow scope"
)]
pub(crate) async fn activate_production_mptcp_client_flow(
    transport: ClientMptcpTransport,
    route: &VerifiedMptcpRoute,
    expected_certificate_sha256: &[u8],
    tls_server_name: &str,
    signed_open_tcp: &[u8],
    now_ms: u64,
) -> Result<ActiveProductionMptcpClientFlow, ProductionMptcpClientFailure> {
    let (mptcp, certificate_der, endpoint_cleanup) = transport
        .into_tls_parts()
        .map_err(|error| ProductionMptcpClientFailure::without_cleanup(error.into()))?;
    if expected_certificate_sha256.len() != 32
        || Sha256::digest(&certificate_der).as_slice() != expected_certificate_sha256
    {
        return Err(ProductionMptcpClientFailure::with_cleanup(
            ProductionMptcpClientError::Certificate,
            endpoint_cleanup,
        ));
    }
    let mut roots = RootCertStore::empty();
    if roots.add(CertificateDer::from(certificate_der)).is_err() {
        return Err(ProductionMptcpClientFailure::with_cleanup(
            ProductionMptcpClientError::Certificate,
            endpoint_cleanup,
        ));
    }
    let Ok(server_name) = ServerName::try_from(tls_server_name.to_owned()) else {
        return Err(ProductionMptcpClientFailure::with_cleanup(
            ProductionMptcpClientError::Certificate,
            endpoint_cleanup,
        ));
    };
    let Ok(client) = Tls13MptcpClient::new(roots) else {
        return Err(ProductionMptcpClientFailure::with_cleanup(
            ProductionMptcpClientError::Tls,
            endpoint_cleanup,
        ));
    };
    let Ok(mut stream) = client
        .connect_preconnected(route, mptcp, server_name, now_ms, TLS_HANDSHAKE_TIMEOUT)
        .await
    else {
        return Err(ProductionMptcpClientFailure::with_cleanup(
            ProductionMptcpClientError::Tls,
            endpoint_cleanup,
        ));
    };
    if write_open_tcp(&mut stream, signed_open_tcp, OPEN_TCP_TIMEOUT)
        .await
        .is_err()
    {
        return Err(ProductionMptcpClientFailure::with_cleanup(
            ProductionMptcpClientError::OpenTcp,
            endpoint_cleanup,
        ));
    }
    Ok(ActiveProductionMptcpClientFlow {
        stream,
        endpoint_cleanup,
    })
}

#[must_use = "failed MPTCP client activation may still require endpoint cleanup"]
pub(crate) struct ProductionMptcpClientFailure {
    cause: ProductionMptcpClientError,
    endpoint_cleanup: Option<ClientMptcpEndpointCleanup>,
}

impl ProductionMptcpClientFailure {
    fn with_cleanup(
        cause: ProductionMptcpClientError,
        endpoint_cleanup: ClientMptcpEndpointCleanup,
    ) -> Self {
        Self {
            cause,
            endpoint_cleanup: Some(endpoint_cleanup),
        }
    }

    fn without_cleanup(cause: ProductionMptcpClientError) -> Self {
        Self {
            cause,
            endpoint_cleanup: None,
        }
    }

    pub(crate) const fn cause(&self) -> ProductionMptcpClientError {
        self.cause
    }

    pub(crate) async fn cleanup(self, helper: &HelperClient) {
        if let Some(cleanup) = self.endpoint_cleanup {
            let _ = cleanup.shutdown(helper).await;
        }
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ProductionMptcpClientError {
    #[error("helper MPTCP transport metadata is invalid")]
    Transport,
    #[error("Exit route certificate binding is invalid")]
    Certificate,
    #[error("TLS 1.3 activation failed")]
    Tls,
    #[error("signed OPEN_TCP transmission failed")]
    OpenTcp,
}

impl From<MptcpTransportError> for ProductionMptcpClientError {
    fn from(_: MptcpTransportError) -> Self {
        Self::Transport
    }
}

fn production_tcp_limits() -> Result<TcpEgressLimits, volparossa_exit::ExitError> {
    let transfer = StreamTransferLimits::new(
        STREAM_BUFFER_BYTES,
        MAXIMUM_DIRECTIONAL_BYTES,
        MAXIMUM_DIRECTIONAL_BYTES,
        STREAM_IDLE_TIMEOUT,
    )?;
    TcpEgressLimits::new(DNS_TIMEOUT, CONNECT_TIMEOUT, CLIENT_HELLO_TIMEOUT, transfer)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn production_tcp_limits_are_bounded_and_nonzero() {
        let limits = production_tcp_limits().expect("limits");
        assert_eq!(limits.transfer().buffer_bytes(), STREAM_BUFFER_BYTES);
        assert_eq!(
            limits.transfer().maximum_client_to_exit_bytes(),
            MAXIMUM_DIRECTIONAL_BYTES
        );
        assert_eq!(limits.idle_timeout(), STREAM_IDLE_TIMEOUT);
    }
}
