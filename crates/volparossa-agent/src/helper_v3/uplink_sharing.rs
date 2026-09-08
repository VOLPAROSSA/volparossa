//! One daemon-long upload scheduler, independent of route/ingress capabilities.

use subtle::ConstantTimeEq as _;
use tokio::{io::AsyncWriteExt as _, time::timeout};
use volparossa_routing::{
    DestroyUplinkSharing, HELPER_PROTOCOL_VERSION, HelperRequest, HelperResult, HelperRuntime,
    InspectUplinkSharing, InstallUplinkSharing, SharingCounters, encode_request, helper_request,
    helper_response, read_response, validate_uplink_sharing_response,
};
use zeroize::Zeroizing;

use super::{
    HELPER_TIMEOUT, HelperClient, HelperClientError, exchange_request, random_request_id,
    runtime_bind_frame,
};

/// Local capability for exactly one queue owner in exactly one authenticated helper process.
/// It deliberately cannot be cloned, serialized or logged.
pub(crate) struct RuntimeBoundUplinkSharing {
    helper_runtime_id: [u8; 32],
    sharing_runtime_id: [u8; 16],
    sharing_handle: [u8; 32],
}

impl HelperClient {
    pub(crate) async fn install_uplink_sharing(
        &self,
        value: InstallUplinkSharing,
    ) -> Result<RuntimeBoundUplinkSharing, HelperClientError> {
        let sharing_runtime_id = value
            .sharing_runtime_id
            .as_slice()
            .try_into()
            .map_err(|_| HelperClientError::Correlation)?;
        let (helper_runtime_id, outcome) = self
            .execute_sharing(None, helper_request::Operation::InstallUplinkSharing(value))
            .await?;
        let helper_response::Outcome::InstalledUplinkSharing(value) = outcome else {
            return Err(HelperClientError::Correlation);
        };
        Ok(RuntimeBoundUplinkSharing {
            helper_runtime_id,
            sharing_runtime_id,
            sharing_handle: value
                .sharing_handle
                .as_slice()
                .try_into()
                .map_err(|_| HelperClientError::Correlation)?,
        })
    }

    pub(crate) async fn inspect_uplink_sharing(
        &self,
        owner: &RuntimeBoundUplinkSharing,
    ) -> Result<SharingCounters, HelperClientError> {
        let (_, outcome) = self
            .execute_sharing(
                Some(&owner.helper_runtime_id),
                helper_request::Operation::InspectUplinkSharing(InspectUplinkSharing {
                    sharing_runtime_id: owner.sharing_runtime_id.to_vec(),
                    sharing_handle: owner.sharing_handle.to_vec(),
                }),
            )
            .await?;
        match outcome {
            helper_response::Outcome::SharingCounters(counters) => Ok(counters),
            _ => Err(HelperClientError::Correlation),
        }
    }

    pub(crate) async fn destroy_uplink_sharing(
        &self,
        owner: &RuntimeBoundUplinkSharing,
    ) -> Result<(), HelperClientError> {
        let (_, outcome) = self
            .execute_sharing(
                Some(&owner.helper_runtime_id),
                helper_request::Operation::DestroyUplinkSharing(DestroyUplinkSharing {
                    sharing_runtime_id: owner.sharing_runtime_id.to_vec(),
                    sharing_handle: owner.sharing_handle.to_vec(),
                }),
            )
            .await?;
        match outcome {
            helper_response::Outcome::DestroyedSharing(_) => Ok(()),
            _ => Err(HelperClientError::Correlation),
        }
    }

    async fn execute_sharing(
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
            validate_uplink_sharing_response(&request, &response)
                .map_err(HelperClientError::Protocol)?;
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

#[cfg(test)]
mod tests {
    use std::time::Duration;

    use nix::unistd::geteuid;
    use tokio::{
        io::AsyncReadExt as _,
        net::{UnixListener, UnixStream},
    };
    use volparossa_routing::{
        BindHelperRuntime, DestroyedSharing, HelperResponse, InstalledUplinkSharing,
        SharingQueueCounters, encode_response, operation_digest, read_request,
    };

    use super::*;

    async fn respond(
        stream: &mut UnixStream,
        request: &HelperRequest,
        outcome: helper_response::Outcome,
    ) {
        let response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            operation_digest: operation_digest(request).expect("digest").to_vec(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "OK".to_owned(),
            outcome: Some(outcome),
        };
        stream
            .write_all(&encode_response(&response).expect("response"))
            .await
            .expect("write");
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one socket peer checks the complete sharing lifecycle and changed-runtime refusal"
    )]
    async fn uplink_sharing_lifecycle_binds_runtime_and_exact_owner() {
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = directory.path().join("helper.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let server = tokio::spawn(async move {
            for step in 0..4 {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let bind = read_request(&mut stream).await.expect("Bind");
                assert!(matches!(
                    bind.operation,
                    Some(helper_request::Operation::BindHelperRuntime(
                        BindHelperRuntime {
                            prepare_intent: None,
                        }
                    ))
                ));
                respond(
                    &mut stream,
                    &bind,
                    helper_response::Outcome::HelperRuntime(HelperRuntime {
                        helper_runtime_id: vec![if step == 3 { 0xb6 } else { 0xa5 }; 32],
                    }),
                )
                .await;
                if step == 3 {
                    let mut byte = [0];
                    assert_eq!(
                        timeout(Duration::from_secs(1), stream.read(&mut byte))
                            .await
                            .expect("no changed-runtime write")
                            .expect("read"),
                        0,
                    );
                    break;
                }
                let request = read_request(&mut stream).await.expect("sharing operation");
                let outcome = match (step, request.operation.as_ref().expect("operation")) {
                    (0, helper_request::Operation::InstallUplinkSharing(value)) => {
                        assert_eq!(value.sharing_runtime_id, vec![7; 16]);
                        assert_eq!(value.interface, "uplink0");
                        assert_eq!(value.total_upload_mbps, 10);
                        assert_eq!(value.contribution_upload_ceiling_mbps, 8);
                        helper_response::Outcome::InstalledUplinkSharing(InstalledUplinkSharing {
                            sharing_runtime_id: value.sharing_runtime_id.clone(),
                            sharing_handle: vec![3; 32],
                            egress_ifindex: 2,
                        })
                    }
                    (1, helper_request::Operation::InspectUplinkSharing(value)) => {
                        assert_eq!(value.sharing_runtime_id, vec![7; 16]);
                        assert_eq!(value.sharing_handle, vec![3; 32]);
                        helper_response::Outcome::SharingCounters(SharingCounters {
                            sharing_runtime_id: value.sharing_runtime_id.clone(),
                            sharing_handle: value.sharing_handle.clone(),
                            total: Some(SharingQueueCounters {
                                bytes: 30,
                                ..Default::default()
                            }),
                            owner: Some(SharingQueueCounters {
                                bytes: 20,
                                ..Default::default()
                            }),
                            contribution: Some(SharingQueueCounters {
                                bytes: 10,
                                ..Default::default()
                            }),
                        })
                    }
                    (2, helper_request::Operation::DestroyUplinkSharing(value)) => {
                        assert_eq!(value.sharing_runtime_id, vec![7; 16]);
                        assert_eq!(value.sharing_handle, vec![3; 32]);
                        helper_response::Outcome::DestroyedSharing(DestroyedSharing {
                            existed: true,
                        })
                    }
                    _ => panic!("wrong sharing operation"),
                };
                respond(&mut stream, &request, outcome).await;
            }
        });
        let client = HelperClient::new_for_test(
            socket,
            directory.path().join("unused-token"),
            geteuid().as_raw(),
        );
        let owner = client
            .install_uplink_sharing(InstallUplinkSharing {
                sharing_runtime_id: vec![7; 16],
                interface: "uplink0".to_owned(),
                total_upload_mbps: 10,
                contribution_upload_ceiling_mbps: 8,
            })
            .await
            .expect("install");
        let counters = client
            .inspect_uplink_sharing(&owner)
            .await
            .expect("inspect");
        assert_eq!(counters.total.expect("total").bytes, 30);
        assert_eq!(counters.contribution.expect("contribution").bytes, 10);
        client
            .destroy_uplink_sharing(&owner)
            .await
            .expect("destroy");
        assert!(matches!(
            client.destroy_uplink_sharing(&owner).await,
            Err(HelperClientError::RuntimeChanged)
        ));
        server.await.expect("server");
    }
}
