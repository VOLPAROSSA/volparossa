//! Concurrent TLS 1.3 and signed `OPEN_TCP` flows over committed MPTCP routes.

use std::{future::Future, sync::Arc, time::Duration};

use pem::parse;
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{net::TcpStream, task::JoinSet, time};
use volparossa_exit::{
    ActiveTcpEgressRoute, ActiveTcpRoute, ExitNativeRouteAuthorization, ExitService,
    TcpEgressLimits,
};
use volparossa_tcp_proxy::{
    StreamTransferLimits, StreamTransferStats, Tls13MptcpClient, Tls13MptcpServer,
    Tls13MptcpStream, VerifiedMptcpRoute, proxy_bidirectional, write_open_tcp,
};

use crate::{
    helper::{HelperClient, RuntimeBoundPreparedLeaseBatch},
    mptcp_transport::{ClientMptcpFlowTransport, ExitMptcpTransport},
    udp_exit_provider::route_certificate_der,
    unix_millis,
};

const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(12);
const OPEN_TCP_TIMEOUT: Duration = Duration::from_secs(12);
const DNS_TIMEOUT: Duration = Duration::from_secs(10);
const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const CLIENT_HELLO_TIMEOUT: Duration = Duration::from_secs(10);
const STREAM_IDLE_TIMEOUT: Duration = Duration::from_secs(60);
const STREAM_BUFFER_BYTES: usize = 64 * 1_024;
const MAXIMUM_DIRECTIONAL_BYTES: u64 = 512 * 1_024 * 1_024;
const MAXIMUM_CONCURRENT_MPTCP_FLOWS: usize = 64;

async fn report_exit_flow_result<T, E, F, Fut>(
    result: Result<Result<T, E>, tokio::task::JoinError>,
    failed: &mut bool,
    flow_completed: &mut F,
) where
    F: FnMut(bool) -> Fut,
    Fut: Future<Output = ()>,
{
    let succeeded = matches!(result, Ok(Ok(_)));
    *failed |= !succeeded;
    flow_completed(succeeded).await;
}

/// A reusable Exit listener, TLS identity, signed-flow verifier and Internet egress owner.
///
/// Construction consumes the activated TCP route and helper owner. `run` accepts only genuine
/// MPTCP, negotiates TLS 1.3 with the route certificate, verifies each bounded `OPEN_TCP`, and only
/// then opens policy-approved ordinary TCP at the Exit.
#[must_use = "the active MPTCP Exit runtime must be run or shut down"]
pub(crate) struct ProductionMptcpExitRuntime {
    helper: HelperClient,
    helper_owner: RuntimeBoundPreparedLeaseBatch,
    transport: ExitMptcpTransport,
    tls: Tls13MptcpServer,
    egress: ActiveTcpEgressRoute,
    limits: TcpEgressLimits,
    expires_at_ms: u64,
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
        let expires_at_ms = authorization.expires_at_ms();
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
            expires_at_ms,
        })
    }

    pub(crate) fn reservation_id(&self) -> [u8; 16] {
        *self.egress.reservation_id()
    }

    /// Accept independent `MPTCP/TLS/OPEN_TCP/egress` flows until route expiry.
    ///
    /// `flow_completed` reports each independently settled flow while this reusable listener
    /// remains active. Route completion alone cannot represent flow completion because a valid
    /// route commonly outlives its first stream by several minutes.
    pub(crate) async fn run<F, Fut>(self, mut flow_completed: F) -> ProductionMptcpExitCompletion
    where
        F: FnMut(bool) -> Fut,
        Fut: Future<Output = ()>,
    {
        let reservation_id = self.reservation_id();
        let Self {
            helper,
            helper_owner,
            transport,
            tls,
            egress,
            limits,
            expires_at_ms,
        } = self;
        let egress = Arc::new(egress);
        let mut flows = JoinSet::new();
        let mut accepted_any = false;
        let mut failed = false;
        loop {
            if flows.len() >= MAXIMUM_CONCURRENT_MPTCP_FLOWS {
                if let Some(result) = flows.join_next().await {
                    report_exit_flow_result(result, &mut failed, &mut flow_completed).await;
                }
                continue;
            }
            let remaining = expires_at_ms.saturating_sub(unix_millis());
            if remaining == 0 {
                break;
            }
            match time::timeout(
                Duration::from_millis(remaining),
                transport.listener().accept(),
            )
            .await
            {
                Ok(Ok((mptcp, _peer))) => {
                    accepted_any = true;
                    let tls = tls.clone();
                    let egress = Arc::clone(&egress);
                    flows.spawn(async move {
                        let mut protected = tls
                            .accept(mptcp, TLS_HANDSHAKE_TIMEOUT)
                            .await
                            .map_err(|_| ProductionMptcpExitError::TlsHandshake)?;
                        let authorized = egress
                            .read_authorized_open_tcp(
                                &mut protected,
                                unix_millis(),
                                OPEN_TCP_TIMEOUT,
                            )
                            .await
                            .map_err(|_| ProductionMptcpExitError::Authorization)?;
                        egress
                            .run_tcp_egress(&authorized, protected, unix_millis(), limits)
                            .await
                            .map_err(|_| ProductionMptcpExitError::Egress)
                    });
                }
                Ok(Err(_)) => {
                    failed = true;
                    break;
                }
                Err(_) => break,
            }
            while let Some(result) = flows.try_join_next() {
                report_exit_flow_result(result, &mut failed, &mut flow_completed).await;
            }
        }
        while let Some(result) = flows.join_next().await {
            report_exit_flow_result(result, &mut failed, &mut flow_completed).await;
        }
        let flow_result = if accepted_any && !failed {
            Ok(())
        } else {
            Err(ProductionMptcpExitError::Accept)
        };

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
    result: Result<(), ProductionMptcpExitError>,
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

/// Live TLS 1.3 stream after a client `OPEN_TCP` was written.
#[must_use = "the active MPTCP client flow must be used or shut down"]
pub(crate) struct ActiveProductionMptcpClientFlow {
    stream: Tls13MptcpStream,
}

impl ActiveProductionMptcpClientFlow {
    pub(crate) fn stream_mut(&mut self) -> &mut Tls13MptcpStream {
        &mut self.stream
    }

    pub(crate) fn shutdown(self) {
        drop(self.stream);
    }

    /// Proxy one accepted local application stream over the already authenticated MPTCP/TLS
    /// connection with the same fixed buffer, byte and idle limits enforced at the Exit.
    pub(crate) async fn proxy_application(
        self,
        application: TcpStream,
    ) -> Result<StreamTransferStats, ProductionMptcpClientError> {
        let limits = StreamTransferLimits::new(
            STREAM_BUFFER_BYTES,
            MAXIMUM_DIRECTIONAL_BYTES,
            MAXIMUM_DIRECTIONAL_BYTES,
            STREAM_IDLE_TIMEOUT,
        )
        .map_err(|_| ProductionMptcpClientError::Stream)?;
        proxy_bidirectional(application, self.stream, limits)
            .await
            .map_err(|_| ProductionMptcpClientError::Stream)
    }
}

/// Wrap one helper-owned genuine MPTCP connection in pinned TLS 1.3 and write `OPEN_TCP`.
#[allow(
    clippy::too_many_arguments,
    reason = "complete authenticated client flow scope"
)]
pub(crate) async fn activate_production_mptcp_client_flow(
    transport: ClientMptcpFlowTransport,
    route: &VerifiedMptcpRoute,
    expected_certificate_sha256: &[u8],
    tls_server_name: &str,
    signed_open_tcp: &[u8],
    now_ms: u64,
) -> Result<ActiveProductionMptcpClientFlow, ProductionMptcpClientFailure> {
    let (mptcp, certificate_der) = transport.into_tls_parts();
    if expected_certificate_sha256.len() != 32
        || Sha256::digest(&certificate_der).as_slice() != expected_certificate_sha256
    {
        return Err(ProductionMptcpClientFailure::new(
            ProductionMptcpClientError::Certificate,
        ));
    }
    let mut roots = RootCertStore::empty();
    if roots.add(CertificateDer::from(certificate_der)).is_err() {
        return Err(ProductionMptcpClientFailure::new(
            ProductionMptcpClientError::Certificate,
        ));
    }
    let Ok(server_name) = ServerName::try_from(tls_server_name.to_owned()) else {
        return Err(ProductionMptcpClientFailure::new(
            ProductionMptcpClientError::Certificate,
        ));
    };
    let Ok(client) = Tls13MptcpClient::new(roots) else {
        return Err(ProductionMptcpClientFailure::new(
            ProductionMptcpClientError::Tls,
        ));
    };
    let Ok(mut stream) = client
        .connect_preconnected(route, mptcp, server_name, now_ms, TLS_HANDSHAKE_TIMEOUT)
        .await
    else {
        return Err(ProductionMptcpClientFailure::new(
            ProductionMptcpClientError::Tls,
        ));
    };
    if write_open_tcp(&mut stream, signed_open_tcp, OPEN_TCP_TIMEOUT)
        .await
        .is_err()
    {
        return Err(ProductionMptcpClientFailure::new(
            ProductionMptcpClientError::OpenTcp,
        ));
    }
    Ok(ActiveProductionMptcpClientFlow { stream })
}

#[must_use = "failed MPTCP client activation must be handled"]
pub(crate) struct ProductionMptcpClientFailure {
    cause: ProductionMptcpClientError,
}

impl ProductionMptcpClientFailure {
    const fn new(cause: ProductionMptcpClientError) -> Self {
        Self { cause }
    }

    pub(crate) const fn cause(&self) -> ProductionMptcpClientError {
        self.cause
    }
}

#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ProductionMptcpClientError {
    #[error("Exit route certificate binding is invalid")]
    Certificate,
    #[error("TLS 1.3 activation failed")]
    Tls,
    #[error("signed OPEN_TCP transmission failed")]
    OpenTcp,
    #[error("bounded application stream proxy failed")]
    Stream,
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
