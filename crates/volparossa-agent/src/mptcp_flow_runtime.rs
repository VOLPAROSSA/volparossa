//! Concurrent TLS 1.3 and signed `OPEN_TCP` flows over committed MPTCP routes.

use std::{future::Future, io, sync::Arc, time::Duration};

use pem::parse;
use rustls::RootCertStore;
use rustls_pki_types::{CertificateDer, PrivateKeyDer, PrivatePkcs8KeyDer, ServerName};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::{io::AsyncWrite, net::TcpStream, sync::watch, task::JoinSet, time};
use volparossa_exit::{
    ActiveTcpEgressRoute, ActiveTcpRoute, ExitNativeRouteAuthorization, ExitService,
    TcpEgressLimits,
};
use volparossa_mptcp::MptcpInfo;
use volparossa_tcp_proxy::{
    StreamTransferLimits, StreamTransferStats, Tls13MptcpClient, Tls13MptcpServer,
    Tls13MptcpStream, VerifiedMptcpRoute, proxy_bidirectional, write_open_tcp,
};

use crate::{
    helper::{HelperClient, RuntimeBoundPreparedLeaseBatch},
    mptcp_transport::{ClientMptcpFlowTransport, ExitMptcpTransport, wait_for_selected_subflows},
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

async fn until_exit_shutdown<T>(
    mut shutdown: watch::Receiver<bool>,
    work: impl Future<Output = T>,
) -> Option<T> {
    let stopped = async {
        while !*shutdown.borrow_and_update() {
            if shutdown.changed().await.is_err() {
                break;
            }
        }
    };
    tokio::select! {
        biased;
        () = stopped => None,
        result = work => Some(result),
    }
}

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

enum ExitRuntimeEvent<A, T> {
    RouteExpired,
    Accepted(A),
    FlowCompleted(Result<T, tokio::task::JoinError>),
}

async fn next_exit_runtime_event<A, T: 'static>(
    remaining: Duration,
    accepting: bool,
    accept: impl Future<Output = A>,
    flows: &mut JoinSet<T>,
) -> ExitRuntimeEvent<A, T> {
    tokio::select! {
        () = time::sleep(remaining) => ExitRuntimeEvent::RouteExpired,
        accepted = accept, if accepting => ExitRuntimeEvent::Accepted(accepted),
        completed = flows.join_next(), if !flows.is_empty() => {
            ExitRuntimeEvent::FlowCompleted(
                completed.expect("a non-empty exit flow set must yield a completion"),
            )
        }
    }
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
    pub(crate) fn retain_cleanup_authority(&self) -> crate::helper::RuntimeBoundContextCleanup {
        self.helper_owner.retain_cleanup_authority()
    }

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
    pub(crate) async fn run_until_shutdown<F, Fut>(
        self,
        shutdown: watch::Receiver<bool>,
        mut flow_completed: F,
    ) -> ProductionMptcpExitCompletion
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
            let remaining = expires_at_ms.saturating_sub(unix_millis());
            if remaining == 0 {
                break;
            }
            let accepting = flows.len() < MAXIMUM_CONCURRENT_MPTCP_FLOWS;
            let event = until_exit_shutdown(
                shutdown.clone(),
                next_exit_runtime_event(
                    Duration::from_millis(remaining),
                    accepting,
                    transport.listener().accept(),
                    &mut flows,
                ),
            )
            .await;
            let Some(event) = event else {
                failed = true;
                break;
            };
            match event {
                ExitRuntimeEvent::Accepted(Ok((mptcp, _peer))) => {
                    accepted_any = true;
                    let tls = tls.clone();
                    let egress = Arc::clone(&egress);
                    let flow_shutdown = shutdown.clone();
                    flows.spawn(async move {
                        Box::pin(until_exit_shutdown(flow_shutdown, async move {
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
                        }))
                        .await
                        .unwrap_or(Err(ProductionMptcpExitError::Accept))
                    });
                }
                ExitRuntimeEvent::Accepted(Err(_)) => {
                    failed = true;
                    break;
                }
                ExitRuntimeEvent::FlowCompleted(result) => {
                    report_exit_flow_result(result, &mut failed, &mut flow_completed).await;
                }
                ExitRuntimeEvent::RouteExpired => break,
            }
        }
        while let Some(result) = flows.join_next().await {
            report_exit_flow_result(result, &mut failed, &mut flow_completed).await;
        }
        let flow_result = (accepted_any && !failed)
            .then_some(())
            .ok_or(ProductionMptcpExitError::Accept);

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
    let (mptcp, certificate_der, required_subflows) = transport.into_tls_parts();
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
    if let Err(cause) = prime_open_tcp_and_wait_for_subflows(
        &mut stream,
        signed_open_tcp,
        required_subflows,
        Tls13MptcpStream::negotiation_info,
    )
    .await
    {
        return Err(ProductionMptcpClientFailure::new(cause));
    }
    Ok(ActiveProductionMptcpClientFlow { stream })
}

async fn prime_open_tcp_and_wait_for_subflows<W, F>(
    stream: &mut W,
    signed_open_tcp: &[u8],
    required_subflows: usize,
    mut observe: F,
) -> Result<(), ProductionMptcpClientError>
where
    W: AsyncWrite + Unpin,
    F: FnMut(&W) -> io::Result<MptcpInfo>,
{
    write_open_tcp(stream, signed_open_tcp, OPEN_TCP_TIMEOUT)
        .await
        .map_err(|_| ProductionMptcpClientError::OpenTcp)?;
    wait_for_selected_subflows(|| observe(&*stream), required_subflows)
        .await
        .map_err(|_| ProductionMptcpClientError::Multipath)?;
    Ok(())
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
    #[error("every selected MPTCP subflow did not become active")]
    Multipath,
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

    #[tokio::test]
    async fn independent_egress_withdrawal_cancels_pending_exit_work() {
        let (shutdown, receiver) = watch::channel(false);
        let work = tokio::spawn(until_exit_shutdown(receiver, std::future::pending::<()>()));
        tokio::task::yield_now().await;
        assert!(!work.is_finished());
        shutdown.send(true).expect("live owner");
        assert_eq!(
            time::timeout(Duration::from_secs(1), work)
                .await
                .unwrap()
                .unwrap(),
            None
        );

        let (shutdown, receiver) = watch::channel(false);
        drop(shutdown);
        assert_eq!(
            until_exit_shutdown(receiver, std::future::ready(7)).await,
            None
        );
        let (_shutdown, receiver) = watch::channel(false);
        assert_eq!(
            until_exit_shutdown(receiver, std::future::ready(7)).await,
            Some(7)
        );
    }

    #[tokio::test]
    async fn open_tcp_primes_the_connection_before_the_multipath_barrier() {
        let signed_open_tcp = b"bounded-signed-open-tcp";
        let mut written = Vec::new();
        let mut observations = 0_u8;

        prime_open_tcp_and_wait_for_subflows(&mut written, signed_open_tcp, 2, |primed| {
            assert!(
                primed.ends_with(signed_open_tcp),
                "OPEN_TCP must be flushed before subflow readiness is observed"
            );
            observations = observations.saturating_add(1);
            Ok(MptcpInfo {
                fallback: false,
                remote_key_received: true,
                additional_subflows: observations.saturating_sub(1),
                total_subflows: observations.min(2),
                bytes_sent: 0,
                bytes_received: 0,
                bytes_retransmitted: 0,
            })
        })
        .await
        .expect("TLS control traffic can prime the second selected subflow");

        assert_eq!(observations, 2);
    }

    #[tokio::test]
    async fn completed_exit_flow_is_reported_while_next_accept_waits() {
        let mut flows = JoinSet::new();
        flows.spawn(async { Ok::<(), ProductionMptcpExitError>(()) });

        let event = time::timeout(
            Duration::from_secs(1),
            next_exit_runtime_event(
                Duration::from_secs(60),
                true,
                std::future::pending::<()>(),
                &mut flows,
            ),
        )
        .await
        .expect("completed flow must be observed before route expiry");
        let ExitRuntimeEvent::FlowCompleted(result) = event else {
            panic!("flow completion must win while the next accept is pending");
        };
        let mut failed = false;
        let mut reports = Vec::new();
        report_exit_flow_result(result, &mut failed, &mut |succeeded| {
            reports.push(succeeded);
            std::future::ready(())
        })
        .await;

        assert_eq!(reports, [true]);
        assert!(!failed);
    }

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
