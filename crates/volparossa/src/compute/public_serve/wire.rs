//! Separate public-sharing protocol; never accepts a private-service request.

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
    Submit {
        question: String,
        context: String,
        license: String,
        public_content: bool,
        rights_confirmed: bool,
    },
    Cancel {
        task_id: String,
    },
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

impl Request {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == VERSION && valid_id(&self.id),
            "public_ipc_invalid_request"
        );
        match &self.operation {
            Operation::Capabilities {} => {}
            Operation::Cancel { task_id } => {
                ensure!(valid_id(task_id), "public_ipc_invalid_request")
            }
            Operation::Submit {
                question,
                context,
                license,
                public_content,
                rights_confirmed,
            } => {
                ensure!(
                    *public_content && *rights_confirmed,
                    "public_ipc_explicit_consent_required"
                );
                for (text, bound) in [(question, 512), (context, 4096)] {
                    ensure!(
                        !text.trim().is_empty() && text.len() <= bound && !text.contains('\0'),
                        "public_ipc_input_bound"
                    );
                }
                ensure!(
                    matches!(
                        license.as_str(),
                        "GPL-3.0-only" | "CC0-1.0" | "CC-BY-4.0" | "CC-BY-SA-4.0"
                    ),
                    "public_ipc_explicit_license_required"
                );
            }
        }
        Ok(())
    }
}

pub(super) async fn read<T: DeserializeOwned>(
    stream: &mut (impl AsyncRead + Unpin),
) -> Result<Option<T>> {
    let mut header = [0_u8; 4];
    if stream.read(&mut header[..1]).await? == 0 {
        return Ok(None);
    }
    tokio::time::timeout(std::time::Duration::from_secs(5), async {
        stream.read_exact(&mut header[1..]).await?;
        let length = u32::from_be_bytes(header) as usize;
        ensure!(
            length > 0 && length <= MAX_REQUEST_BYTES,
            "public_ipc_frame_bound"
        );
        let mut bytes = vec![0; length];
        stream.read_exact(&mut bytes).await?;
        serde_json::from_slice(&bytes)
            .map(Some)
            .map_err(|_| anyhow::anyhow!("public_ipc_invalid_request"))
    })
    .await
    .map_err(|_| anyhow::anyhow!("public_ipc_frame_timeout"))?
}

pub(super) async fn write(stream: &mut (impl AsyncWrite + Unpin), value: &Value) -> Result<()> {
    let bytes = serde_json::to_vec(value)?;
    ensure!(
        bytes.len() <= MAX_RESPONSE_BYTES,
        "public_ipc_response_bound"
    );
    let length = u32::try_from(bytes.len())?;
    tokio::time::timeout(std::time::Duration::from_secs(3), async {
        stream.write_all(&length.to_be_bytes()).await?;
        stream.write_all(&bytes).await?;
        stream.flush().await
    })
    .await
    .map_err(|_| anyhow::anyhow!("public_ipc_write_timeout"))??;
    Ok(())
}

pub(super) fn response(id: &str, event: &str) -> Value {
    json!({"version":VERSION,"id":id,"event":event})
}
pub(super) fn error(id: Option<&str>, code: &'static str) -> Value {
    json!({"version":VERSION,"id":id,"event":"error","code":code})
}
