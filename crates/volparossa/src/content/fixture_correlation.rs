//! Private development-fixture pipe; no fingerprints or epochs in command arguments or logs.

use std::{
    io::{Read, Write as _},
    path::Path,
};

use anyhow::{Result, anyhow, bail};
use serde::Deserialize;
use serde_json::{Value, json};
use volparossa_local_control::{
    StorageFixtureCorrelationAction as Action, StorageFixtureCorrelationPhase as Phase,
    StorageFixtureCorrelationRequest, StorageFixtureCorrelationResponse,
    StorageFixtureCorrelationRole as Role, StorageFixtureCorrelationState as State,
    StorageFixtureCorrelationTerminal as Terminal, control_request::Operation,
    control_response::Payload,
};

const MAX_REQUEST_BYTES: usize = 4096;
const MAX_REPLY_BYTES: usize = 32 * 1024;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Input {
    version: u32,
    action: InputAction,
    epoch: String,
    fingerprints: Vec<String>,
}

#[derive(Deserialize)]
#[serde(rename_all = "snake_case")]
enum InputAction {
    Arm,
    Clients,
    Providers,
    Disarm,
}

pub(super) async fn run(socket: &Path) -> Result<()> {
    let request = read_input(std::io::stdin().lock())?;
    let value = query(socket, &request).await?;
    let output = render(&value)?;
    std::io::stdout()
        .lock()
        .write_all(&output)
        .map_err(|_| anyhow!("cannot write private fixture correlation response"))
}

fn read_input(reader: impl Read) -> Result<StorageFixtureCorrelationRequest> {
    let mut bytes = Vec::new();
    reader
        .take((MAX_REQUEST_BYTES + 1) as u64)
        .read_to_end(&mut bytes)
        .map_err(|_| invalid_input())?;
    if bytes.len() > MAX_REQUEST_BYTES {
        return Err(invalid_input());
    }
    // Typed serde decoding rejects duplicate keys, unknown fields, nulls and trailing values.
    // Never attach the parser error: it may contain private input text.
    let input: Input = serde_json::from_slice(&bytes).map_err(|_| invalid_input())?;
    let request = StorageFixtureCorrelationRequest {
        version: input.version,
        action: match input.action {
            InputAction::Arm => Action::Arm,
            InputAction::Clients => Action::Clients,
            InputAction::Providers => Action::Providers,
            InputAction::Disarm => Action::Disarm,
        } as i32,
        epoch: decode_hex(&input.epoch, 16)?,
        fingerprints: input
            .fingerprints
            .iter()
            .map(|value| decode_hex(value, 32))
            .collect::<Result<_>>()?,
    };
    request.validate().map_err(|_| invalid_input())?;
    Ok(request)
}

fn decode_hex(value: &str, length: usize) -> Result<Vec<u8>> {
    if value.len() != length * 2
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
    {
        return Err(invalid_input());
    }
    hex::decode(value).map_err(|_| invalid_input())
}

fn invalid_input() -> anyhow::Error {
    anyhow!("invalid private fixture correlation input")
}

async fn query(socket: &Path, request: &StorageFixtureCorrelationRequest) -> Result<Value> {
    let response = crate::control::request(
        socket,
        Operation::StorageFixtureCorrelation(request.clone()),
    )
    .await
    .map_err(|_| anyhow!("private fixture correlation request unavailable"))?;
    let Some(Payload::StorageFixtureCorrelation(snapshot)) = response.payload else {
        bail!("agent returned no private fixture correlation response");
    };
    project(&snapshot, request)
}

fn project(
    response: &StorageFixtureCorrelationResponse,
    request: &StorageFixtureCorrelationRequest,
) -> Result<Value> {
    response.validate_for(request)?;
    let records = response
        .records
        .iter()
        .map(|record| {
            Ok(json!({
                "role": Role::try_from(record.role)?,
                "fingerprint": record.fingerprint.as_ref().map(hex::encode),
                "phase": Phase::try_from(record.phase)?,
                "terminal": Terminal::try_from(record.terminal)?,
            }))
        })
        .collect::<Result<Vec<_>>>()?;
    Ok(json!({
        "version": 1,
        "kind": "storage-fixture-correlation",
        "state": State::try_from(response.state)?,
        "incomplete": response.incomplete,
        "records": records,
        "diagnostic_only": true,
        "acceptance_evidence": false,
    }))
}

fn render(value: &Value) -> Result<Vec<u8>> {
    let mut bytes = serde_json::to_vec(value)
        .map_err(|_| anyhow!("cannot encode private fixture correlation response"))?;
    bytes.push(b'\n');
    if bytes.len() > MAX_REPLY_BYTES {
        bail!("private fixture correlation response exceeds bound");
    }
    Ok(bytes)
}

#[cfg(test)]
#[path = "fixture_correlation_tests.rs"]
mod tests;
