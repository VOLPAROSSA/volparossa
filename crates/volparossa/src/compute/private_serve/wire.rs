//! Same-owner local IPC only: bounded length-prefixed JSON, never a network protocol.

use anyhow::{Result, ensure};
use serde::{Deserialize, de::DeserializeOwned};
use serde_json::{Value, json};
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};

pub(super) const VERSION: u8 = 1;
pub(super) const MAX_REQUEST_BYTES: usize = 32 * 1024;
pub(super) const MAX_RESPONSE_BYTES: usize = 64 * 1024;
pub(super) const MAX_REQUESTS: usize = 256;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Request {
    pub version: u8,
    pub id: String,
    pub operation: Operation,
}

#[derive(Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub(super) enum Operation {
    Capabilities {},
    Submit { question: String, context: String },
    Cancel { task_id: String },
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl Request {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == VERSION && valid_id(&self.id),
            "private_ipc_invalid_request"
        );
        if let Operation::Cancel { task_id } = &self.operation {
            ensure!(valid_id(task_id), "private_ipc_invalid_request");
        }
        if let Operation::Submit { question, context } = &self.operation {
            super::super::private_task::validate_input(&input_bytes(question, context)?)?;
        }
        Ok(())
    }
}

pub(super) fn input_bytes(question: &str, context: &str) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&json!({
        "version":1, "visibility":"private_local", "question":question, "context":context,
    }))?)
}

pub(super) async fn read<T: DeserializeOwned>(
    stream: &mut (impl AsyncRead + Unpin),
    maximum: usize,
) -> Result<Option<T>> {
    // Waiting for a first byte is distinct from finishing a frame. A running job
    // requires no heartbeat, but a partial length/body cannot occupy a reader forever.
    let mut header = [0_u8; 4];
    if stream.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        stream.read_exact(&mut header[1..]).await?;
        let length = u32::from_be_bytes(header) as usize;
        ensure!(length > 0 && length <= maximum, "private_ipc_frame_bound");
        let mut payload = vec![0; length];
        stream.read_exact(&mut payload).await?;
        // Never forward parser diagnostics: field names can contain private text.
        let value = serde_json::from_slice(&payload)
            .map_err(|_| anyhow::anyhow!("private_ipc_invalid_request"))?;
        Ok(Some(value))
    })
    .await
    .map_err(|_| anyhow::anyhow!("private_ipc_frame_timeout"))?
}

pub(super) async fn write(stream: &mut (impl AsyncWrite + Unpin), value: &Value) -> Result<()> {
    let payload = serde_json::to_vec(value)?;
    ensure!(
        payload.len() <= MAX_RESPONSE_BYTES,
        "private_ipc_response_bound"
    );
    let length = u32::try_from(payload.len())?;
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(&payload).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| anyhow::anyhow!("private_ipc_write_timeout"))??;
    Ok(())
}

pub(super) fn response(id: &str, event: &str) -> Value {
    json!({"version":VERSION,"id":id,"event":event})
}

pub(super) fn error(id: Option<&str>, code: &'static str) -> Value {
    json!({"version":VERSION,"id":id,"event":"error","code":code})
}
