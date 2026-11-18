//! Bounded same-owner IPC. See WIRE.md for the local-only JSON exception.

use std::time::Duration;

use anyhow::{Result, ensure};
use serde::Deserialize;
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

pub(super) const VERSION: u8 = 1;
pub(super) const MAX_REQUEST: usize = 512;
pub(super) const MAX_RESPONSE: usize = 2 * 1024 * 1024;
pub(super) const MAX_REQUESTS: usize = 32;

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub version: u8,
    pub id: String,
    pub operation: Operation,
}

#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Operation {
    Capabilities {},
    Status {},
    Fetch {},
}

pub(super) fn parse(bytes: &[u8]) -> Result<Request> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_REQUEST,
        "invalid_request"
    );
    // Do not format serde errors or unrecognized caller-controlled field names.
    let request: Request =
        serde_json::from_slice(bytes).map_err(|_| anyhow::anyhow!("invalid_request"))?;
    ensure!(
        request.version == VERSION
            && request.id.len() == 32
            && request
                .id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "invalid_request"
    );
    Ok(request)
}

pub(super) async fn read(stream: &mut (impl AsyncRead + Unpin)) -> Result<Option<Request>> {
    // Even an idle/partial client has a finite lifetime; no unbounded reader tasks.
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut header = [0; 4];
        if stream.read(&mut header[..1]).await? == 0 {
            return Ok(None);
        }
        stream.read_exact(&mut header[1..]).await?;
        let length = u32::from_be_bytes(header) as usize;
        ensure!(length > 0 && length <= MAX_REQUEST, "invalid_request");
        let mut body = vec![0; length];
        stream.read_exact(&mut body).await?;
        parse(&body).map(Some)
    })
    .await
    .map_err(|_| anyhow::anyhow!("invalid_request"))?
}

pub(super) fn encode(value: &Value) -> Result<Vec<u8>> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(bytes.len() <= MAX_RESPONSE, "response_bound");
    Ok(bytes)
}

pub(super) async fn write(
    stream: &mut (impl AsyncWrite + Unpin),
    bytes: &[u8],
    mut live: impl FnMut() -> Result<()>,
) -> Result<()> {
    ensure!(
        !bytes.is_empty() && bytes.len() <= MAX_RESPONSE,
        "response_bound"
    );
    tokio::time::timeout(Duration::from_secs(3), async {
        live()?;
        stream
            .write_all(&u32::try_from(bytes.len())?.to_be_bytes())
            .await?;
        for chunk in bytes.chunks(16 * 1024) {
            live()?;
            stream.write_all(chunk).await?;
        }
        live()?;
        stream.flush().await?;
        Ok(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("write_timeout"))?
}

pub(super) fn error(id: Option<&str>, code: &'static str) -> Value {
    json!({"version":VERSION,"id":id,"event":"error","code":code})
}
