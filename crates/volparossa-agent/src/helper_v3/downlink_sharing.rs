//! Count-only receiver ownership and an update-only capability for one Exit sender queue.

use subtle::ConstantTimeEq as _;
use tokio::{io::AsyncWriteExt as _, time::timeout};
use volparossa_routing::{
    AppliedDownlinkBudget, ApplyDownlinkBudget, DestroyReceiveAccounting, HELPER_PROTOCOL_VERSION,
    HelperRequest, HelperResult, HelperRuntime, InspectReceiveAccounting, InstallReceiveAccounting,
    ReceiveAccountingSnapshot, WireguardRole, encode_request, helper_request, helper_response,
    read_response, validate_downlink_response,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use super::{
    HELPER_TIMEOUT, HelperClient, HelperClientError, RuntimeBoundPreparedLeaseBatch,
    exchange_request, random_request_id, runtime_bind_frame,
};

#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct RuntimeBoundReceiveAccounting {
    helper_runtime_id: [u8; 32],
    accounting_runtime_id: [u8; 16],
    accounting_handle: [u8; 32],
}

/// A deliberately restricted delegation: it cannot create, activate, commit or destroy a route.
/// The affine full route owner remains in the transport runtime after this capability is issued.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct RuntimeBoundDownlinkBudgetTarget {
    helper_runtime_id: [u8; 32],
    route_context_id: [u8; 16],
    context_handle: [u8; 32],
    lease_handle: [u8; 32],
}

impl RuntimeBoundPreparedLeaseBatch {
    pub(crate) fn downlink_budget_target(
        &self,
        path_id: u32,
    ) -> Result<RuntimeBoundDownlinkBudgetTarget, HelperClientError> {
        let mut leases =
            self.prepared.leases.iter().filter(|lease| {
                lease.path_id == path_id && lease.role == WireguardRole::Exit as i32
            });
        let lease = leases.next().ok_or(HelperClientError::Correlation)?;
        if leases.next().is_some() {
            return Err(HelperClientError::Correlation);
        }
        Ok(RuntimeBoundDownlinkBudgetTarget {
            helper_runtime_id: self.helper_runtime_id,
            route_context_id: self
                .prepare
                .route_context_id
                .as_slice()
                .try_into()
                .map_err(|_| HelperClientError::Correlation)?,
            context_handle: self
                .prepared
                .context_handle
                .as_slice()
                .try_into()
                .map_err(|_| HelperClientError::Correlation)?,
            lease_handle: lease
                .lease_handle
                .as_slice()
                .try_into()
                .map_err(|_| HelperClientError::Correlation)?,
        })
    }
}

impl HelperClient {
    pub(crate) async fn install_receive_accounting(
        &self,
        value: InstallReceiveAccounting,
    ) -> Result<RuntimeBoundReceiveAccounting, HelperClientError> {
        let accounting_runtime_id = value
            .accounting_runtime_id
            .as_slice()
            .try_into()
            .map_err(|_| HelperClientError::Correlation)?;
        let (helper_runtime_id, outcome) = self
            .execute_downlink(
                None,
                helper_request::Operation::InstallReceiveAccounting(value),
            )
            .await?;
        let helper_response::Outcome::InstalledReceiveAccounting(value) = outcome else {
            return Err(HelperClientError::Correlation);
        };
        Ok(RuntimeBoundReceiveAccounting {
            helper_runtime_id,
            accounting_runtime_id,
            accounting_handle: value
                .accounting_handle
                .as_slice()
                .try_into()
                .map_err(|_| HelperClientError::Correlation)?,
        })
    }

    pub(crate) async fn inspect_receive_accounting(
        &self,
        owner: &RuntimeBoundReceiveAccounting,
    ) -> Result<ReceiveAccountingSnapshot, HelperClientError> {
        let (_, outcome) = self
            .execute_downlink(
                Some(&owner.helper_runtime_id),
                helper_request::Operation::InspectReceiveAccounting(InspectReceiveAccounting {
                    accounting_runtime_id: owner.accounting_runtime_id.to_vec(),
                    accounting_handle: owner.accounting_handle.to_vec(),
                }),
            )
            .await?;
        match outcome {
            helper_response::Outcome::ReceiveAccountingSnapshot(value) => Ok(value),
            _ => Err(HelperClientError::Correlation),
        }
    }

    pub(crate) async fn destroy_receive_accounting(
        &self,
        owner: &RuntimeBoundReceiveAccounting,
    ) -> Result<(), HelperClientError> {
        self.execute_downlink(
            Some(&owner.helper_runtime_id),
            helper_request::Operation::DestroyReceiveAccounting(DestroyReceiveAccounting {
                accounting_runtime_id: owner.accounting_runtime_id.to_vec(),
                accounting_handle: owner.accounting_handle.to_vec(),
            }),
        )
        .await
        .map(|_| ())
    }

    pub(crate) async fn apply_downlink_budget(
        &self,
        owner: &RuntimeBoundDownlinkBudgetTarget,
        signed_budget: Vec<u8>,
    ) -> Result<AppliedDownlinkBudget, HelperClientError> {
        let (_, outcome) = self
            .execute_downlink(
                Some(&owner.helper_runtime_id),
                helper_request::Operation::ApplyDownlinkBudget(ApplyDownlinkBudget {
                    route_context_id: owner.route_context_id.to_vec(),
                    context_handle: owner.context_handle.to_vec(),
                    lease_handle: owner.lease_handle.to_vec(),
                    signed_budget,
                }),
            )
            .await?;
        match outcome {
            helper_response::Outcome::AppliedDownlinkBudget(value) => Ok(value),
            _ => Err(HelperClientError::Correlation),
        }
    }

    async fn execute_downlink(
        &self,
        expected_runtime: Option<&[u8; 32]>,
        operation: helper_request::Operation,
    ) -> Result<([u8; 32], helper_response::Outcome), HelperClientError> {
        let bind_request_id = random_request_id(&[]);
        let (bind_frame, bind_digest) = runtime_bind_frame(bind_request_id)?;
        let request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: random_request_id(&[bind_request_id]).to_vec(),
            operation: Some(operation),
        };
        let frame = Zeroizing::new(encode_request(&request).map_err(HelperClientError::Protocol)?);
        timeout(HELPER_TIMEOUT, async {
            let mut stream = self.connect_authenticated().await?;
            let outcome = exchange_request(
                &mut stream,
                bind_frame.as_slice(),
                &bind_request_id,
                &bind_digest,
            )
            .await?;
            let helper_response::Outcome::HelperRuntime(HelperRuntime { helper_runtime_id }) =
                outcome
            else {
                return Err(HelperClientError::Correlation);
            };
            let runtime: [u8; 32] = helper_runtime_id
                .as_slice()
                .try_into()
                .map_err(|_| HelperClientError::Correlation)?;
            if expected_runtime.is_some_and(|expected| expected.ct_eq(&runtime).unwrap_u8() != 1) {
                return Err(HelperClientError::RuntimeChanged);
            }
            stream
                .write_all(&frame)
                .await
                .map_err(HelperClientError::Io)?;
            stream.flush().await.map_err(HelperClientError::Io)?;
            let response = read_response(&mut stream)
                .await
                .map_err(HelperClientError::Protocol)?;
            validate_downlink_response(&request, &response).map_err(HelperClientError::Protocol)?;
            let result = HelperResult::try_from(response.result)
                .map_err(|_| HelperClientError::Correlation)?;
            if result != HelperResult::Ok {
                return Err(HelperClientError::Rejected(result));
            }
            Ok((
                runtime,
                response.outcome.ok_or(HelperClientError::Correlation)?,
            ))
        })
        .await
        .map_err(|_| HelperClientError::Timeout)?
    }
}
