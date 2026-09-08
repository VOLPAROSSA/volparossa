//! Client for the bounded local agent control socket.

use std::path::Path;

use anyhow::{Context, Result, bail};
use rand_core::{OsRng, RngCore};
use tokio::net::UnixStream;
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ControlRequest, ControlResponse, ControlResult,
    control_request::Operation, read_response, write_request,
};

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
    let response = finish_request(&mut stream, &request.request_id).await?;
    Ok((stream, request.request_id, response))
}

/// Read a bounded response correlated to the same operation and validate its result.
pub(crate) async fn finish_request(
    stream: &mut UnixStream,
    request_id: &[u8],
) -> Result<ControlResponse> {
    let response = read_response(stream)
        .await
        .context("cannot read response from agent")?;
    if response.request_id != request_id {
        bail!("agent response correlation ID does not match");
    }
    let result = ControlResult::try_from(response.result)
        .map_err(|_| anyhow::anyhow!("agent returned an unknown result"))?;
    if result != ControlResult::Ok {
        bail!(
            "agent rejected request: {} ({result:?})",
            response.diagnostic_code
        );
    }
    Ok(response)
}
