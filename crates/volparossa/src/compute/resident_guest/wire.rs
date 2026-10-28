//! Versioned, canonical protobuf frames inside the guest-terminated TLS channel.

use anyhow::{Result, ensure};
use prost::Message as _;
use tokio::io::{AsyncRead, AsyncReadExt as _, AsyncWrite, AsyncWriteExt as _};
use tokio::time::{Instant, timeout_at};

pub(super) const MAX_FRAME: usize = 256 * 1024;
pub(super) const CHALLENGE: u32 = 1;
pub(super) const GRANT: u32 = 2;
pub(super) const ACCEPTED: u32 = 3;
pub(super) const SUBMIT: u32 = 4;
pub(super) const ADMITTED: u32 = 5;
pub(super) const RESULT: u32 = 6;
pub(super) const CLOSE: u32 = 7;
pub(super) const CLOSED: u32 = 8;
// Terminal public-fixture diagnostic, never a RESULT or successful CLOSED receipt.
pub(super) const FAILURE: u32 = 9;
pub(super) const MAX_FAILURE: usize = 1024;

#[derive(Debug)]
pub(super) enum ReadFailure {
    Deadline,
    Bound,
    Encoding,
}

impl std::fmt::Display for ReadFailure {
    fn fmt(&self, output: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        output.write_str(match self {
            Self::Deadline => "resident_read_deadline",
            Self::Bound => "resident_frame_bound",
            Self::Encoding => "resident_frame",
        })
    }
}
impl std::error::Error for ReadFailure {}

pub(super) fn failure(sequence: u32, detail: &serde_json::Value) -> Result<Frame> {
    let body = serde_json::to_vec(&serde_json::json!({"version":1,
        "scope":"public_fixture_native_session","detail":detail,
        "cleanup":{"version":1,"child_reaped":true,"private_state_removed":true}}))?;
    let frame = frame(FAILURE, sequence, body);
    failure_body(&frame, sequence)?;
    Ok(frame)
}

pub(super) fn failure_body(frame: &Frame, sequence: u32) -> Result<serde_json::Value> {
    use serde_json::json;
    ensure!(
        frame.version == 1
            && frame.kind == FAILURE
            && frame.sequence == sequence
            && (1..=2).contains(&sequence)
            && frame.body.len() <= MAX_FAILURE,
        "resident_failure_frame"
    );
    let value: serde_json::Value = serde_json::from_slice(&frame.body)
        .map_err(|_| anyhow::anyhow!("resident_failure_frame"))?;
    ensure!(
        value.as_object().is_some_and(|object| object.len() == 4)
            && value["version"] == 1
            && value["scope"] == "public_fixture_native_session"
            && crate::compute::supervise::diagnostic::public_fixture_detail(&value["detail"])
            && value["cleanup"]
                == json!({"version":1,"child_reaped":true,"private_state_removed":true})
            && serde_json::to_vec(&value)? == frame.body,
        "resident_failure_frame"
    );
    Ok(value)
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Frame {
    #[prost(uint32, tag = "1")]
    pub version: u32,
    #[prost(uint32, tag = "2")]
    pub kind: u32,
    #[prost(uint32, tag = "3")]
    pub sequence: u32,
    #[prost(bytes = "vec", tag = "4")]
    pub body: Vec<u8>,
}

#[derive(Clone, PartialEq, prost::Message)]
pub(super) struct Challenge {
    #[prost(bytes = "vec", tag = "1")]
    pub nonce: Vec<u8>,
    #[prost(uint64, tag = "2")]
    pub issued_at_ms: u64,
    #[prost(uint64, tag = "3")]
    pub maximum_expires_at_ms: u64,
}

pub(super) async fn read(
    reader: &mut (impl AsyncRead + Unpin),
    deadline: Instant,
) -> Result<Frame> {
    ensure!(Instant::now() < deadline, ReadFailure::Deadline);
    timeout_at(deadline, async {
        let length = reader.read_u32().await? as usize;
        ensure!((1..=MAX_FRAME).contains(&length), ReadFailure::Bound);
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes).await?;
        let frame = Frame::decode(bytes.as_slice()).map_err(|_| ReadFailure::Encoding)?;
        ensure!(
            frame.version == 1 && frame.encode_to_vec() == bytes,
            ReadFailure::Encoding
        );
        ensure!(Instant::now() < deadline, ReadFailure::Deadline);
        Ok(frame)
    })
    .await
    .map_err(|_| anyhow::anyhow!(ReadFailure::Deadline))?
}

pub(super) async fn write(
    writer: &mut (impl AsyncWrite + Unpin),
    frame: Frame,
    deadline: Instant,
) -> Result<()> {
    let deadline = deadline.min(Instant::now() + std::time::Duration::from_secs(3));
    ensure!(Instant::now() < deadline, "resident_write_deadline");
    let bytes = frame.encode_to_vec();
    ensure!(bytes.len() <= MAX_FRAME, "resident_frame_bound");
    timeout_at(deadline, async {
        writer.write_u32(u32::try_from(bytes.len())?).await?;
        writer.write_all(&bytes).await?;
        writer.flush().await?;
        ensure!(Instant::now() < deadline, "resident_write_deadline");
        Ok(())
    })
    .await
    .map_err(|_| anyhow::anyhow!("resident_write_deadline"))?
}

pub(super) fn frame(kind: u32, sequence: u32, body: Vec<u8>) -> Frame {
    Frame {
        version: 1,
        kind,
        sequence,
        body,
    }
}
