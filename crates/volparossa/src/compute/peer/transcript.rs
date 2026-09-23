//! Preserve original peer signatures, not a coordinator-created execution attestation.

use super::*;
use volparossa_content::provider::compute as wire;

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Retained {
    version: u32,
    pub(super) requester_key: String,
    transcript_hex: String,
}

/// Poll only: no new job, source publication or renewed lease is authorized here.
pub(super) async fn poll(socket: &Path, handle: &JobHandle) -> Result<Retained> {
    timeout(Duration::from_secs(150), async {
        let provider = parse_key(&handle.provider_key).map_err(anyhow::Error::msg)?;
        let (mut stream, id, ready) = crate::control::begin_request(
            socket,
            Operation::ComputeRemote(ComputeRemoteRequest {
                provider_key: provider.to_bytes().to_vec(),
                retain_transcript: true,
            }),
        )
        .await?;
        ensure!(
            ready.diagnostic_code == "COMPUTE_RPC_READY",
            "compute_transcript_ready"
        );
        let Some(Payload::ComputeReady(ready)) = ready.payload else {
            anyhow::bail!("compute_transcript_ready_payload")
        };
        ensure!(
            ready.provider_key == provider.as_bytes(),
            "compute_transcript_provider"
        );
        let request = rpc::Request {
            version: rpc::VERSION,
            request_id: nonce()?,
            requester_key: hex::encode(ready.requester_key),
            operation: rpc::Operation::Poll(handle.binding.clone()),
        };
        request.validate(now()?)?;
        rpc::write_request(&mut stream, &request).await?;
        let response = rpc::read_response(&mut stream, &request.request_id).await?;
        let final_response = crate::control::finish_request(&mut stream, &id).await?;
        ensure!(
            final_response.diagnostic_code == "COMPUTE_RPC_OK",
            "compute_transcript_final"
        );
        let Some(Payload::ComputeTranscript(proof)) = final_response.payload else {
            anyhow::bail!("compute_transcript_not_retained")
        };
        let retained = Retained {
            version: 1,
            requester_key: request.requester_key.clone(),
            transcript_hex: hex::encode(proof.transcript),
        };
        let verified = retained.verified(&provider)?;
        ensure!(
            serde_json::from_slice::<rpc::Request>(verified.request_payload())? == request
                && serde_json::from_slice::<rpc::Response>(verified.response_payload())?
                    == response,
            "compute_transcript_exact_exchange"
        );
        retained.check(handle, 1, &request.requester_key)?;
        Ok(retained)
    })
    .await
    .context("compute_transcript_poll_timeout")?
}

impl Retained {
    fn verified(&self, provider: &VerifyingKey) -> Result<wire::VerifiedTranscript> {
        ensure!(
            self.version == 1
                && !self.transcript_hex.is_empty()
                && self.transcript_hex.len() <= 2 * wire::MAX_TRANSCRIPT_BYTES,
            "compute_transcript_bound"
        );
        let requester = parse_key(&self.requester_key).map_err(anyhow::Error::msg)?;
        Ok(wire::verify_transcript(
            &hex::decode(&self.transcript_hex)?,
            provider.as_bytes(),
            requester.as_bytes(),
        )?)
    }

    /// Verifies a historical signed claim, never authorizes a fresh job or policy change.
    pub(super) fn check(
        &self,
        handle: &JobHandle,
        selected_at: u64,
        requester: &str,
    ) -> Result<rpc::JobStatus> {
        ensure!(
            self.requester_key == requester,
            "compute_transcript_requester"
        );
        let provider = parse_key(&handle.provider_key).map_err(anyhow::Error::msg)?;
        let verified = self.verified(&provider)?;
        let request: rpc::Request = serde_json::from_slice(verified.request_payload())?;
        let response: rpc::Response = serde_json::from_slice(verified.response_payload())?;
        request.validate(verified.signed_created())?;
        ensure!(
            request.requester_key == requester
                && request.operation == rpc::Operation::Poll(handle.binding.clone())
                && response.version == rpc::VERSION
                && response.request_id == request.request_id
                && selected_at <= verified.signed_created()
                && verified.signed_created() < handle.binding.expires_unix_seconds,
            "compute_transcript_historical_poll_binding"
        );
        let status = job(response.outcome, handle)?;
        ensure!(
            status.state == rpc::JobState::Complete,
            "compute_transcript_complete_only"
        );
        Ok(status)
    }
}
