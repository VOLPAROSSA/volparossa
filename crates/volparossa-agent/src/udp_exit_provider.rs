//! Route-scoped production TLS ownership shared by UDP and MPTCP Exit transports.

#![allow(
    dead_code,
    reason = "the discovery responder owns this affine provider and its transport-specific consumers"
)]

use std::time::Duration;

use pem::parse;
use rcgen::generate_simple_self_signed;
use rustls_pki_types::{CertificateDer, PrivatePkcs8KeyDer};
use sha2::{Digest, Sha256};
use thiserror::Error;
use tokio::sync::watch;
use volparossa_discovery::UdpExitSessionSignal;
use volparossa_exit::{
    ExitNativeRouteAuthorization, ExitNativeRouteIdentityError, ExitNativeRouteIdentityOwner,
    ExitNativeRouteIdentityProvider, ExitNativeRouteIdentityRequest,
};
use volparossa_linux_uapi::IndependentEgress;
use volparossa_policy::VerifiedManifest;
use volparossa_protocol::NativeRouteIdentity;
use volparossa_protocol::{ReplayCache, TimePolicy};
use volparossa_routing::{CommitLeaseBatch, ContextRole, WireguardRole};
use volparossa_udp::{
    CommittedQuicUdpTransport, CommittedUdpRole, DatagramLimits, SINGLE_RELAY_UDP_EXIT_PORT,
    SingleRelayUdpExitListener, UdpBridgeStats, VerifiedSingleRelayPath,
    committed_quic_udp_socket_request,
};

use crate::helper::{HelperClient, RuntimeBoundPreparedLeaseBatch};

const EXIT_FLOW_REPLAY_CAPACITY: usize = 4_096;

/// Generates a fresh self-signed route certificate and retains its private key only in the
/// affine Exit reservation owner. No certificate or key is persisted.
pub(crate) struct ProductionExitNativeRouteIdentityProvider;

impl ExitNativeRouteIdentityProvider for ProductionExitNativeRouteIdentityProvider {
    fn provide(
        &mut self,
        request: &ExitNativeRouteIdentityRequest,
    ) -> Result<ExitNativeRouteIdentityOwner, ExitNativeRouteIdentityError> {
        let server_name = format!(
            "{}.route.volparossa.invalid",
            hex::encode(request.route_context_id())
        );
        let certified = generate_simple_self_signed(vec![server_name.clone()])
            .map_err(|_| ExitNativeRouteIdentityError::Unavailable)?;
        let certificate_der = certified.cert.der();
        let public_identity = NativeRouteIdentity {
            auth_commitment: request.auth_commitment().to_vec(),
            certificate_sha256: Sha256::digest(certificate_der.as_ref()).to_vec(),
            spki_sha256: Sha256::digest(certified.key_pair.public_key_der()).to_vec(),
            tls_server_name: server_name,
            masque_context_id: request.masque_context_id(),
            client_native_instance_id: request.client_native_instance_id().to_vec(),
            exit_native_instance_id: request.exit_native_instance_id().to_vec(),
            credential_hpke_public_key: Vec::new(),
        };
        ExitNativeRouteIdentityOwner::new(
            *request,
            public_identity,
            certified.cert.pem().into_bytes(),
            certified.key_pair.serialize_pem().into_bytes(),
        )
    }
}

/// Convert the exact retained PEM owner into Quinn server material and its public DER signal.
pub(crate) fn udp_server_config(
    authorization: &ExitNativeRouteAuthorization,
) -> Result<(quinn::ServerConfig, Vec<u8>), ExitNativeRouteIdentityError> {
    let certificate_der = route_certificate_der(authorization)?;
    let private_key = parse(authorization.tls_private_key_pem())
        .map_err(|_| ExitNativeRouteIdentityError::Rejected("invalid retained private-key PEM"))?;
    let config = quinn::ServerConfig::with_single_cert(
        vec![CertificateDer::from(certificate_der.clone())],
        PrivatePkcs8KeyDer::from(private_key.into_contents()).into(),
    )
    .map_err(|_| ExitNativeRouteIdentityError::Rejected("invalid retained TLS key pair"))?;
    Ok((config, certificate_der))
}

/// Parse the retained public certificate and re-check its signed route digest.
pub(crate) fn route_certificate_der(
    authorization: &ExitNativeRouteAuthorization,
) -> Result<Vec<u8>, ExitNativeRouteIdentityError> {
    let certificate = parse(authorization.tls_certificate_pem())
        .map_err(|_| ExitNativeRouteIdentityError::Rejected("invalid retained certificate PEM"))?;
    let certificate_der = certificate.into_contents();
    let certificate_hash = Sha256::digest(&certificate_der);
    if authorization.public_identity().certificate_sha256 != certificate_hash.as_slice() {
        return Err(ExitNativeRouteIdentityError::Rejected(
            "retained certificate contradicts signed identity",
        ));
    }
    Ok(certificate_der)
}

/// Exact reason why an activated Exit helper route could not become a listener.
#[derive(Clone, Copy, Debug, Error, Eq, PartialEq)]
pub(crate) enum ProductionUdpExitError {
    #[error("UDP Exit route scope is inconsistent")]
    InvalidScope,
    #[error("UDP Exit helper Commit failed")]
    HelperCommit,
    #[error("UDP Exit helper socket handoff failed")]
    HelperSocket,
    #[error("UDP Exit TLS identity is unavailable or inconsistent")]
    TlsIdentity,
    #[error("UDP Exit listener or authorized association failed")]
    Association,
    #[error("UDP Exit helper cleanup remains pending")]
    CleanupPending,
}

/// Affine cleanup capability retained whenever an activated/committed Exit route cannot continue.
#[must_use = "an Exit helper cleanup owner must be destroyed or retained for retry"]
pub(crate) struct ProductionUdpExitCleanup {
    helper: HelperClient,
    owner: RuntimeBoundPreparedLeaseBatch,
}

impl ProductionUdpExitCleanup {
    /// Retry exact same-runtime Destroy without losing the owner on failure.
    pub(crate) async fn destroy(self) -> Result<(), Self> {
        if self.helper.destroy_context(&self.owner).await.is_ok() {
            Ok(())
        } else {
            Err(self)
        }
    }
}

/// Failure with any still-live helper cleanup capability kept affine.
#[must_use = "a failed Exit activation may still own helper state requiring cleanup"]
pub(crate) struct ProductionUdpExitFailure {
    cause: ProductionUdpExitError,
    cleanup: Option<ProductionUdpExitCleanup>,
}

impl ProductionUdpExitFailure {
    #[must_use]
    pub(crate) const fn cause(&self) -> ProductionUdpExitError {
        self.cause
    }

    pub(crate) fn into_cleanup(self) -> Option<ProductionUdpExitCleanup> {
        self.cleanup
    }
}

/// Bound production listener plus exact helper route owner.
///
/// The listener already owns the helper-provided Exit socket. The public session signal may be
/// forwarded to the Client only while this value remains owned. `run` accepts one independently
/// authorized flow and destroys the route after its real QUIC DATAGRAM bridge ends.
#[must_use = "the active UDP Exit route must be run or shut down"]
pub(crate) struct ActiveProductionUdpExitRoute {
    listener: SingleRelayUdpExitListener,
    cleanup: ProductionUdpExitCleanup,
    policy: VerifiedManifest,
    authorization_timeout: Duration,
    limits: DatagramLimits,
    independent_egress: Option<IndependentEgress>,
}

impl ActiveProductionUdpExitRoute {
    pub(crate) async fn run_until_shutdown(
        self,
        mut shutdown: watch::Receiver<bool>,
        now_ms: u64,
    ) -> Result<UdpBridgeStats, ProductionUdpExitFailure> {
        let Self {
            listener,
            cleanup,
            policy,
            authorization_timeout,
            limits,
            independent_egress,
        } = self;
        let Ok(mut replay) = ReplayCache::new(EXIT_FLOW_REPLAY_CAPACITY) else {
            listener.shutdown().await;
            return Err(failed_after_cleanup(cleanup, ProductionUdpExitError::Association).await);
        };
        let association = listener
            .accept_with_egress_until_shutdown(
                &policy,
                &mut replay,
                TimePolicy::default(),
                authorization_timeout,
                limits,
                now_ms,
                independent_egress.as_ref(),
                &mut shutdown,
            )
            .await;
        let result = match association {
            Ok(accepted) => accepted.run_until_shutdown(&mut shutdown).await,
            Err(_) => Err(volparossa_udp::UdpError::InvalidBinding(
                "authorized Exit association",
            )),
        };
        let cleanup_result = cleanup.destroy().await;
        match (result, cleanup_result) {
            (Ok(stats), Ok(())) => Ok(stats),
            (_, Err(cleanup)) => Err(ProductionUdpExitFailure {
                cause: ProductionUdpExitError::CleanupPending,
                cleanup: Some(cleanup),
            }),
            (Err(_), Ok(())) => Err(ProductionUdpExitFailure {
                cause: ProductionUdpExitError::Association,
                cleanup: None,
            }),
        }
    }

    pub(crate) async fn shutdown(self) -> Result<(), ProductionUdpExitCleanup> {
        self.listener.shutdown().await;
        self.cleanup.destroy().await
    }
}

/// Commit one already Activated Exit helper route, adopt its exact UDP descriptor and bind a real
/// QUIC listener before returning public certificate readiness.
#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    dead_code,
    reason = "the discovery Exit responder consumes this typed seam after native identity provenance is available"
)]
pub(crate) async fn start_production_udp_exit(
    helper: HelperClient,
    mut owner: RuntimeBoundPreparedLeaseBatch,
    commit: CommitLeaseBatch,
    path: VerifiedSingleRelayPath,
    authorization: ExitNativeRouteAuthorization,
    policy: VerifiedManifest,
    authorization_timeout: Duration,
    limits: DatagramLimits,
    independent_egress: Option<IndependentEgress>,
    now_ms: u64,
) -> Result<(ActiveProductionUdpExitRoute, UdpExitSessionSignal), ProductionUdpExitFailure> {
    let scope = authorization.scope();
    let request = scope.request();
    let prepare = owner.prepare();
    let context_handle = owner.prepared().context_handle.clone();
    let exact_exit_lease = prepare.leases.as_slice()
        == [volparossa_routing::LeasePlan {
            path_id: path.path_id(),
            role: WireguardRole::Exit as i32,
        }];
    if request.reservation_id() != path.reservation_id()
        || request.route_context_id() != path.route_context_id()
        || authorization.expires_at_ms() <= now_ms
        || path.expires_at_ms() <= now_ms
        || ContextRole::try_from(prepare.role).ok() != Some(ContextRole::Exit)
        || prepare.route_context_id != path.route_context_id()
        || !exact_exit_lease
        || commit.route_context_id != prepare.route_context_id
        || commit.context_handle != context_handle
        || commit.leases.len() != 1
        || commit.leases[0].path_id != path.path_id()
        || commit.leases[0].role != WireguardRole::Exit as i32
    {
        return Err(failed_after_cleanup(
            ProductionUdpExitCleanup { helper, owner },
            ProductionUdpExitError::InvalidScope,
        )
        .await);
    }
    if helper.commit_lease_batch(&mut owner, commit).await.is_err() {
        return Err(failed_after_cleanup(
            ProductionUdpExitCleanup { helper, owner },
            ProductionUdpExitError::HelperCommit,
        )
        .await);
    }
    let Ok(socket_request) = committed_quic_udp_socket_request(
        &context_handle,
        &path,
        CommittedUdpRole::Exit,
        SINGLE_RELAY_UDP_EXIT_PORT,
    ) else {
        return Err(failed_after_cleanup(
            ProductionUdpExitCleanup { helper, owner },
            ProductionUdpExitError::InvalidScope,
        )
        .await);
    };
    let Ok(acquired) = helper.acquire_transport_socket(socket_request).await else {
        return Err(failed_after_cleanup(
            ProductionUdpExitCleanup { helper, owner },
            ProductionUdpExitError::HelperSocket,
        )
        .await);
    };
    let (descriptor, metadata) = acquired.into_parts();
    let Ok(transport) = CommittedQuicUdpTransport::from_helper_handoff(
        descriptor,
        &metadata,
        &path,
        CommittedUdpRole::Exit,
    ) else {
        return Err(failed_after_cleanup(
            ProductionUdpExitCleanup { helper, owner },
            ProductionUdpExitError::HelperSocket,
        )
        .await);
    };
    let Ok((server_config, certificate_der)) = udp_server_config(&authorization) else {
        return Err(failed_after_cleanup(
            ProductionUdpExitCleanup { helper, owner },
            ProductionUdpExitError::TlsIdentity,
        )
        .await);
    };
    let Ok(exit_native_instance_id): Result<[u8; 32], _> = authorization
        .public_identity()
        .exit_native_instance_id
        .as_slice()
        .try_into()
    else {
        return Err(failed_after_cleanup(
            ProductionUdpExitCleanup { helper, owner },
            ProductionUdpExitError::TlsIdentity,
        )
        .await);
    };
    let Ok(signal) = UdpExitSessionSignal::new(
        *path.reservation_id(),
        *path.route_context_id(),
        path.path_id(),
        certificate_der,
        exit_native_instance_id,
    ) else {
        return Err(failed_after_cleanup(
            ProductionUdpExitCleanup { helper, owner },
            ProductionUdpExitError::TlsIdentity,
        )
        .await);
    };
    let Ok(listener) = SingleRelayUdpExitListener::listen(transport, server_config, path) else {
        return Err(failed_after_cleanup(
            ProductionUdpExitCleanup { helper, owner },
            ProductionUdpExitError::Association,
        )
        .await);
    };
    Ok((
        ActiveProductionUdpExitRoute {
            listener,
            cleanup: ProductionUdpExitCleanup { helper, owner },
            policy,
            authorization_timeout,
            limits,
            independent_egress,
        },
        signal,
    ))
}

async fn failed_after_cleanup(
    cleanup: ProductionUdpExitCleanup,
    cause: ProductionUdpExitError,
) -> ProductionUdpExitFailure {
    match cleanup.destroy().await {
        Ok(()) => ProductionUdpExitFailure {
            cause,
            cleanup: None,
        },
        Err(cleanup) => ProductionUdpExitFailure {
            cause: ProductionUdpExitError::CleanupPending,
            cleanup: Some(cleanup),
        },
    }
}

#[cfg(test)]
mod tests {
    use volparossa_exit::{ExitNativeRouteIdentityProvider, ExitNativeRouteIdentityRequest};

    use super::ProductionExitNativeRouteIdentityProvider;

    #[test]
    fn production_identity_binds_certificate_name_and_native_scope() {
        let request = ExitNativeRouteIdentityRequest::new(
            [1; 16], [2; 16], [3; 16], [4; 32], 7, [5; 32], [6; 32],
        )
        .expect("identity request");
        let owner = ProductionExitNativeRouteIdentityProvider
            .provide(&request)
            .expect("route identity");
        let identity = owner.public_identity();

        assert_eq!(identity.auth_commitment, [4; 32]);
        assert_eq!(identity.certificate_sha256.len(), 32);
        assert_eq!(identity.spki_sha256.len(), 32);
        assert_eq!(
            identity.tls_server_name,
            "02020202020202020202020202020202.route.volparossa.invalid"
        );
        assert_eq!(identity.masque_context_id, 7);
        assert_eq!(identity.client_native_instance_id, [5; 32]);
        assert_eq!(identity.exit_native_instance_id, [6; 32]);
    }
}
