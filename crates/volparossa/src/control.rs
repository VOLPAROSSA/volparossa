//! Client for the bounded local agent control socket.

use std::path::Path;

use anyhow::{Context, Result, bail};
use rand_core::{OsRng, RngCore};
use tokio::net::UnixStream;
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, ControlResult,
    PrivateStorageRemoteDetail, control_request::Operation, read_response, write_request,
};

/// Typed rejection retained for closed, caller-owned diagnostics. The peer supplied
/// code must be allowlisted before being included in a machine-readable report.
#[derive(Debug)]
pub(crate) struct AgentRejected {
    pub(crate) diagnostic_code: String,
    pub(crate) private_storage_remote_detail: Option<PrivateStorageRemoteDetail>,
    result: ControlResult,
}

impl std::fmt::Display for AgentRejected {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "agent rejected request: {} ({:?})",
            self.diagnostic_code, self.result
        )
    }
}

impl std::error::Error for AgentRejected {}

/// Sends one typed operation and validates correlation and result metadata.
pub async fn request(socket: &Path, operation: Operation) -> Result<ControlResponse> {
    let (_, _, response) = begin_request(socket, operation).await?;
    Ok(response)
}

/// Begin one operation while retaining its exact connection for an explicit stream handoff.
pub(crate) async fn begin_request(
    socket: &Path,
    operation: Operation,
) -> Result<(UnixStream, Vec<u8>, ControlResponse)> {
    let mut request_id = [0_u8; 16];
    OsRng.fill_bytes(&mut request_id);
    let request = ControlRequest {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: request_id.to_vec(),
        operation: Some(operation),
    };
    let mut stream = UnixStream::connect(socket)
        .await
        .with_context(|| format!("cannot connect to agent socket {}", socket.display()))?;
    write_request(&mut stream, &request)
        .await
        .context("cannot send request to agent")?;
    let response = finish_scoped_request(
        &mut stream,
        &request.request_id,
        matches!(request.operation, Some(Operation::PrivateStorageRemote(_))),
    )
    .await?;
    Ok((stream, request.request_id, response))
}

/// Read a bounded response correlated to the same operation and validate its result.
pub(crate) async fn finish_request(
    stream: &mut UnixStream,
    request_id: &[u8],
) -> Result<ControlResponse> {
    // A terminal receipt cannot carry a pre-READY observation.
    finish_scoped_request(stream, request_id, false).await
}

async fn finish_scoped_request(
    stream: &mut UnixStream,
    request_id: &[u8],
    private_storage_initial: bool,
) -> Result<ControlResponse> {
    let response = read_response(stream)
        .await
        .context("cannot read response from agent")?;
    if response.request_id != request_id {
        bail!("agent response correlation ID does not match");
    }
    if response.private_storage_remote_detail.is_some() && !private_storage_initial {
        bail!("agent private storage detail does not match response operation");
    }
    let result = ControlResult::try_from(response.result)
        .map_err(|_| anyhow::anyhow!("agent returned an unknown result"))?;
    if result != ControlResult::Ok {
        return Err(AgentRejected {
            diagnostic_code: response.diagnostic_code,
            private_storage_remote_detail: response.private_storage_remote_detail,
            result,
        }
        .into());
    }
    Ok(response)
}

#[cfg(test)]
#[path = "control_tests.rs"]
mod tests;
