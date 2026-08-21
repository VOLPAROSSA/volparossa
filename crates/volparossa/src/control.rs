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
    let response = read_response(&mut stream)
        .await
        .context("cannot read response from agent")?;
    if response.request_id != request.request_id {
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
