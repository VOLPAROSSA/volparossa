//! Typed exact-publication chunk bridge; no free-form stream proxy or extra wire schema.

use std::collections::BTreeSet;

use super::*;

pub(crate) async fn bridge_peer<R, S>(
    receiver: &mut R,
    source: &mut S,
    manifest: &VerifiedManifest,
    limits: TransferLimits,
) -> Result<TransferProgress, TransferError>
where
    R: AsyncRead + AsyncWrite + Unpin,
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut session = Session::new(limits)?;
    let allowed: BTreeMap<_, _> = manifest
        .chunks()
        .iter()
        .map(|chunk| (*chunk.id(), chunk.length()))
        .collect();
    let mut seen = BTreeSet::new();
    let mut progress = TransferProgress::default();
    loop {
        session.check_deadline()?;
        check_time(manifest)?;
        let deadline = session.exchange_deadline();
        let done = timeout_at(deadline, async {
            let request: Request = read_frame(receiver, MAX_REQUEST_BYTES).await?;
            if request.version != VERSION {
                return Err(TransferError::Protocol);
            }
            if request.finish {
                if !request.hash.is_empty() || request.length != 0 {
                    return Err(TransferError::Protocol);
                }
                write_frame(source, &request, MAX_REQUEST_BYTES).await?;
                return Ok(true);
            }
            let id = ChunkId(
                request
                    .hash
                    .as_slice()
                    .try_into()
                    .map_err(|_| TransferError::Protocol)?,
            );
            if allowed.get(&id).copied() != Some(request.length) || !seen.insert(id) {
                return Err(TransferError::Protocol);
            }
            session.reserve(request.length)?;
            write_frame(source, &request, MAX_REQUEST_BYTES).await?;
            let response: Response = read_frame(source, MAX_RESPONSE_BYTES).await?;
            if response.version != VERSION
                || response.hash != request.hash
                || response.length != request.length
                || (!response.found && !response.data.is_empty())
                || (response.found
                    && (response.data.len() as u64 != u64::from(request.length)
                        || ChunkId::digest(&response.data) != id))
            {
                return Err(TransferError::Protocol);
            }
            write_frame(receiver, &response, MAX_RESPONSE_BYTES).await?;
            if response.found {
                progress.chunks += 1;
                progress.bytes += u64::from(response.length);
            } else {
                progress.missing += 1;
            }
            Ok(false)
        })
        .await
        .map_err(|_| TransferError::Timeout)??;
        session.check_deadline()?;
        check_time(manifest)?;
        if done {
            return Ok(progress);
        }
    }
}
