//! Daemon-long capability for a separately owned direct radio interface.

use subtle::ConstantTimeEq as _;
use tokio::{io::AsyncWriteExt as _, time::timeout};
use volparossa_routing::{
    DestroyWifiMesh, HELPER_PROTOCOL_VERSION, HelperRequest, HelperResult, HelperRuntime,
    InspectWifiMesh, InstallWifiMesh, WifiMeshSnapshot, encode_request, helper_request,
    helper_response, read_response, validate_wifi_mesh_response,
};
use zeroize::Zeroizing;

use super::{
    HELPER_TIMEOUT, HelperClient, HelperClientError, exchange_request, random_request_id,
    runtime_bind_frame,
};

/// Not cloneable or serializable: an exact owner in one authenticated helper runtime.
pub(crate) struct RuntimeBoundWifiMesh {
    helper_runtime_id: [u8; 32],
    mesh_runtime_id: [u8; 16],
    mesh_handle: [u8; 32],
    ifindex: u32,
    wiphy: u32,
    frequency_mhz: u32,
}

impl HelperClient {
    pub(crate) async fn install_wifi_mesh(
        &self,
        value: InstallWifiMesh,
    ) -> Result<RuntimeBoundWifiMesh, HelperClientError> {
        let mesh_runtime_id = value
            .mesh_runtime_id
            .as_slice()
            .try_into()
            .map_err(|_| HelperClientError::Correlation)?;
        let frequency_mhz = value.frequency_mhz;
        let (helper_runtime_id, outcome) = self
            .execute_mesh(None, helper_request::Operation::InstallWifiMesh(value))
            .await?;
        let helper_response::Outcome::InstalledWifiMesh(value) = outcome else {
            return Err(HelperClientError::Correlation);
        };
        Ok(RuntimeBoundWifiMesh {
            helper_runtime_id,
            mesh_runtime_id,
            frequency_mhz,
            mesh_handle: value
                .mesh_handle
                .as_slice()
                .try_into()
                .map_err(|_| HelperClientError::Correlation)?,
            ifindex: value.ifindex,
            wiphy: value.wiphy,
        })
    }

    pub(crate) async fn inspect_wifi_mesh(
        &self,
        owner: &RuntimeBoundWifiMesh,
    ) -> Result<WifiMeshSnapshot, HelperClientError> {
        let (_, outcome) = self
            .execute_mesh(
                Some(&owner.helper_runtime_id),
                helper_request::Operation::InspectWifiMesh(InspectWifiMesh {
                    mesh_runtime_id: owner.mesh_runtime_id.to_vec(),
                    mesh_handle: owner.mesh_handle.to_vec(),
                }),
            )
            .await?;
        match outcome {
            helper_response::Outcome::WifiMeshSnapshot(value)
                if value.ifindex == owner.ifindex
                    && value.wiphy == owner.wiphy
                    && value.frequency_mhz == owner.frequency_mhz
                    && value.joined =>
            {
                Ok(value)
            }
            _ => Err(HelperClientError::Correlation),
        }
    }

    pub(crate) async fn destroy_wifi_mesh(
        &self,
        owner: &RuntimeBoundWifiMesh,
    ) -> Result<(), HelperClientError> {
        let (_, outcome) = self
            .execute_mesh(
                Some(&owner.helper_runtime_id),
                helper_request::Operation::DestroyWifiMesh(DestroyWifiMesh {
                    mesh_runtime_id: owner.mesh_runtime_id.to_vec(),
                    mesh_handle: owner.mesh_handle.to_vec(),
                }),
            )
            .await?;
        match outcome {
            helper_response::Outcome::DestroyedWifiMesh(_) => Ok(()),
            _ => Err(HelperClientError::Correlation),
        }
    }

    async fn execute_mesh(
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
            validate_wifi_mesh_response(&request, &response)
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
    use super::*;
    use nix::unistd::geteuid;
    use tokio::{io::AsyncReadExt as _, net::UnixListener};
    use volparossa_routing::{
        DestroyedWifiMesh, HelperResponse, InstalledWifiMesh, encode_response, operation_digest,
        read_request,
    };

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one socket peer verifies the exact mesh lifecycle and helper-restart refusal"
    )]
    async fn wifi_mesh_owner_rejects_a_restarted_helper_before_sending_capability() {
        let directory = tempfile::tempdir().unwrap();
        let socket = directory.path().join("helper.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let server = tokio::spawn(async move {
            for step in 0..4 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let bind = read_request(&mut stream).await.unwrap();
                assert!(matches!(
                    bind.operation,
                    Some(helper_request::Operation::BindHelperRuntime(_))
                ));
                let response = HelperResponse {
                    protocol_version: HELPER_PROTOCOL_VERSION,
                    request_id: bind.request_id.clone(),
                    operation_digest: operation_digest(&bind).unwrap().to_vec(),
                    result: HelperResult::Ok as i32,
                    diagnostic_code: "OK".into(),
                    outcome: Some(helper_response::Outcome::HelperRuntime(HelperRuntime {
                        helper_runtime_id: vec![if step == 3 { 4 } else { 2 }; 32],
                    })),
                };
                stream
                    .write_all(&encode_response(&response).unwrap())
                    .await
                    .unwrap();
                if step == 3 {
                    assert_eq!(
                        timeout(HELPER_TIMEOUT, stream.read(&mut [0]))
                            .await
                            .unwrap()
                            .unwrap(),
                        0
                    );
                    return;
                }
                let request = read_request(&mut stream).await.unwrap();
                let outcome = match request.operation.as_ref().unwrap() {
                    helper_request::Operation::InstallWifiMesh(value) if step == 0 => {
                        assert_eq!(value.parent_interface, "wlan0");
                        helper_response::Outcome::InstalledWifiMesh(InstalledWifiMesh {
                            mesh_runtime_id: value.mesh_runtime_id.clone(),
                            mesh_handle: vec![3; 32],
                            interface: "vw1234".into(),
                            ifindex: 2,
                            wiphy: 0,
                        })
                    }
                    helper_request::Operation::InspectWifiMesh(value) if step == 1 => {
                        assert_eq!(value.mesh_handle, vec![3; 32]);
                        helper_response::Outcome::WifiMeshSnapshot(WifiMeshSnapshot {
                            mesh_runtime_id: value.mesh_runtime_id.clone(),
                            mesh_handle: value.mesh_handle.clone(),
                            ifindex: 2,
                            wiphy: 0,
                            frequency_mhz: 2412,
                            joined: true,
                            peers: vec![],
                        })
                    }
                    helper_request::Operation::DestroyWifiMesh(value) if step == 2 => {
                        assert_eq!(value.mesh_handle, vec![3; 32]);
                        helper_response::Outcome::DestroyedWifiMesh(DestroyedWifiMesh {
                            existed: true,
                        })
                    }
                    _ => panic!("unexpected mesh lifecycle operation"),
                };
                let response = HelperResponse {
                    protocol_version: HELPER_PROTOCOL_VERSION,
                    request_id: request.request_id.clone(),
                    operation_digest: operation_digest(&request).unwrap().to_vec(),
                    result: HelperResult::Ok as i32,
                    diagnostic_code: "OK".into(),
                    outcome: Some(outcome),
                };
                stream
                    .write_all(&encode_response(&response).unwrap())
                    .await
                    .unwrap();
            }
        });
        let client = HelperClient::new_for_test(
            socket,
            directory.path().join("unused-token"),
            geteuid().as_raw(),
        );
        let owner = client
            .install_wifi_mesh(InstallWifiMesh {
                mesh_runtime_id: vec![7; 16],
                parent_interface: "wlan0".into(),
                mesh_id: b"VOLPAROSSA-local".to_vec(),
                frequency_mhz: 2412,
                local_address: vec![192, 168, 247, 1],
                prefix_len: 24,
                maximum_peers: 8,
            })
            .await
            .unwrap();
        assert!(
            client
                .inspect_wifi_mesh(&owner)
                .await
                .unwrap()
                .peers
                .is_empty()
        );
        client.destroy_wifi_mesh(&owner).await.unwrap();
        assert!(matches!(
            client.inspect_wifi_mesh(&owner).await,
            Err(HelperClientError::RuntimeChanged)
        ));
        server.await.unwrap();
    }
}
