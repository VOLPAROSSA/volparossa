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
    ensure!(Instant::now() < deadline, "resident_read_deadline");
    timeout_at(deadline, async {
        let length = reader.read_u32().await? as usize;
        ensure!((1..=MAX_FRAME).contains(&length), "resident_frame_bound");
        let mut bytes = vec![0; length];
        reader.read_exact(&mut bytes).await?;
        let frame =
            Frame::decode(bytes.as_slice()).map_err(|_| anyhow::anyhow!("resident_frame"))?;
        ensure!(
            frame.version == 1 && frame.encode_to_vec() == bytes,
            "resident_frame"
        );
        ensure!(Instant::now() < deadline, "resident_read_deadline");
        Ok(frame)
    })
    .await
    .map_err(|_| anyhow::anyhow!("resident_read_deadline"))?
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
