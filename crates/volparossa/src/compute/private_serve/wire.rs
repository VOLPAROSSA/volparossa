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
    Submit {
        question: String,
        context: String,
    },
    ConversationCapabilities {
        #[serde(default, deserialize_with = "present_version")]
        generation_policy_version: Option<u8>,
        #[serde(default, deserialize_with = "present_version")]
        execution_error_version: Option<u8>,
    },
    SubmitConversation {
        conversation: super::super::private_conversation::Input,
    },
    Cancel {
        task_id: String,
    },
}

fn present_version<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<u8>, D::Error> {
    u8::deserialize(deserializer).map(Some)
}

fn valid_id(id: &str) -> bool {
    id.len() == 32
        && id
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

impl Request {
    #[cfg(test)]
    pub(super) fn validate(&self) -> Result<()> {
        self.validate_profile(super::super::ModelProfile::Smol360)
    }

    pub(super) fn validate_profile(&self, profile: super::super::ModelProfile) -> Result<()> {
        ensure!(
            !profile.is_native_conversation()
                || !matches!(
                    self.operation,
                    Operation::Capabilities { .. } | Operation::Submit { .. }
                ),
            "private_ipc_unsupported_mode"
        );
        ensure!(
            self.version == VERSION && valid_id(&self.id),
            "private_ipc_invalid_request"
        );
        if let Operation::ConversationCapabilities {
            generation_policy_version,
            execution_error_version,
        } = &self.operation
        {
            ensure!(
                generation_policy_version.is_none_or(|version| version == 1),
                "private_ipc_generation_policy_version"
            );
            ensure!(
                execution_error_version.is_none_or(|version| version == 1),
                "private_ipc_execution_error_version"
            );
        }
        if let Operation::Cancel { task_id } = &self.operation {
            ensure!(valid_id(task_id), "private_ipc_invalid_request");
        }
        if let Operation::Submit { question, context } = &self.operation {
            ensure!(
                !profile.is_native_conversation(),
                "private_ipc_unsupported_mode"
            );
            super::super::private_task::validate_input(&input_bytes(question, context)?)?;
        }
        if let Operation::SubmitConversation { conversation } = &self.operation {
            conversation.bytes_profile(profile)?;
        }
        Ok(())
    }
}

pub(super) fn input_bytes(question: &str, context: &str) -> Result<Vec<u8>> {
    Ok(serde_json::to_vec(&json!({
        "version":1, "visibility":"private_local", "question":question, "context":context,
    }))?)
}

#[cfg(test)]
pub(super) async fn read<T: DeserializeOwned>(
    stream: &mut (impl AsyncRead + Unpin),
    maximum: usize,
) -> Result<Option<T>> {
    read_checked(stream, maximum, |_, _| true).await
}

pub(super) async fn read_request(
    stream: &mut (impl AsyncRead + Unpin),
    profile: super::super::ModelProfile,
) -> Result<Option<Request>> {
    read_checked(
        stream,
        super::super::private_conversation::request_frame(profile),
        |request: &Request, size| {
            (size <= MAX_REQUEST_BYTES
                || matches!(request.operation, Operation::SubmitConversation { .. }))
                && request.validate_profile(profile).is_ok()
        },
    )
    .await
}

async fn read_checked<T: DeserializeOwned>(
    stream: &mut (impl AsyncRead + Unpin),
    maximum: usize,
    valid: impl Fn(&T, usize) -> bool,
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
        ensure!(valid(&value, length), "private_ipc_invalid_request");
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
