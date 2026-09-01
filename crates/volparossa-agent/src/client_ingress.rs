//! Process-owned client ingress capabilities.

use rand_core::{OsRng, RngCore as _};
use thiserror::Error;
use volparossa_routing::{PrepareClientIngress, REQUIRED_INGRESS_SOCKETS};

use crate::{
    helper::{
        AcquiredIngressSocket, ActiveClientIngress, HelperClient, HelperClientError,
        PreparedClientIngress,
    },
    unix_seconds,
};

const INGRESS_SETUP_TTL_SECONDS: u64 = 30;
const INGRESS_HARD_TTL_SECONDS: u64 = 15 * 60;

/// Affine owner of the complete activated ingress descriptor set.
pub(crate) struct ClientIngressRuntime {
    helper: HelperClient,
    active: ActiveClientIngress,
}

impl ClientIngressRuntime {
    pub(crate) async fn start(helper: HelperClient) -> Result<Self, ClientIngressRuntimeError> {
        let client_runtime_id = random_runtime_id()?;
        let now = unix_seconds();
        let mut prepared = helper
            .prepare_client_ingress(PrepareClientIngress {
                client_runtime_id: client_runtime_id.to_vec(),
                setup_expires_at_unix: now
                    .checked_add(INGRESS_SETUP_TTL_SECONDS)
                    .ok_or(ClientIngressRuntimeError::Clock)?,
                hard_expires_at_unix: now
                    .checked_add(INGRESS_HARD_TTL_SECONDS)
                    .ok_or(ClientIngressRuntimeError::Clock)?,
            })
            .await
            .map_err(ClientIngressRuntimeError::Prepare)?;

        let identities = prepared.socket_identities().collect::<Vec<_>>();
        let mut sockets = Vec::with_capacity(REQUIRED_INGRESS_SOCKETS);
        for identity in identities {
            match helper.acquire_ingress_socket(&mut prepared, identity).await {
                Ok(socket) => sockets.push(socket),
                Err(error) => {
                    return Err(cleanup_prepared_failure(
                        &helper,
                        &prepared,
                        ClientIngressRuntimeError::Acquire(error),
                    )
                    .await);
                }
            }
        }
        let sockets: [AcquiredIngressSocket; REQUIRED_INGRESS_SOCKETS] = match sockets.try_into() {
            Ok(sockets) => sockets,
            Err(_sockets) => {
                return Err(cleanup_prepared_failure(
                    &helper,
                    &prepared,
                    ClientIngressRuntimeError::IncompleteDescriptorSet,
                )
                .await);
            }
        };
        let active = match helper.activate_client_ingress(prepared, sockets).await {
            Ok(active) => active,
            Err(failure) => {
                let (error, prepared, _sockets) = failure.into_parts();
                return Err(cleanup_prepared_failure(
                    &helper,
                    &prepared,
                    ClientIngressRuntimeError::Activate(error),
                )
                .await);
            }
        };
        Ok(Self { helper, active })
    }

    pub(crate) async fn shutdown(self) -> Result<(), ClientIngressRuntimeError> {
        self.helper
            .destroy_active_client_ingress(&self.active)
            .await
            .map(|_| ())
            .map_err(ClientIngressRuntimeError::Destroy)
    }
}

async fn cleanup_prepared_failure(
    helper: &HelperClient,
    prepared: &PreparedClientIngress,
    original: ClientIngressRuntimeError,
) -> ClientIngressRuntimeError {
    match helper.destroy_prepared_client_ingress(prepared).await {
        Ok(_) => original,
        Err(error) => ClientIngressRuntimeError::Rollback(error),
    }
}

fn random_runtime_id() -> Result<[u8; 16], ClientIngressRuntimeError> {
    let mut runtime_id = [0; 16];
    OsRng
        .try_fill_bytes(&mut runtime_id)
        .map_err(|_| ClientIngressRuntimeError::Random)?;
    if runtime_id.iter().all(|byte| *byte == 0) {
        return Err(ClientIngressRuntimeError::Random);
    }
    Ok(runtime_id)
}

#[derive(Debug, Error)]
pub(crate) enum ClientIngressRuntimeError {
    #[error("secure client runtime identity generation failed")]
    Random,
    #[error("system clock cannot represent the client ingress deadline")]
    Clock,
    #[error("client ingress prepare failed")]
    Prepare(#[source] HelperClientError),
    #[error("client ingress descriptor acquisition failed")]
    Acquire(#[source] HelperClientError),
    #[error("client ingress descriptor set was incomplete")]
    IncompleteDescriptorSet,
    #[error("client ingress activation failed")]
    Activate(#[source] HelperClientError),
    #[error("client ingress rollback could not be confirmed")]
    Rollback(#[source] HelperClientError),
    #[error("client ingress destruction could not be confirmed")]
    Destroy(#[source] HelperClientError),
}
