//! Owner-side confirmation on the original connection, never a worker permit.

use anyhow::{Context as _, Result, ensure};
use serde::Serialize;
use tokio::{
    net::UnixStream,
    time::{Instant, timeout_at},
};
use volparossa_content::provider::compute::{
    attestation::PendingSession, guest::QuoteRequest, quote::confirmation as wire,
};
use volparossa_local_control::{ControlResponse, QuoteReady, control_response::Payload};

use super::{RefusalReport, VerifyReport, obligation};

#[derive(Serialize)]
#[allow(
    clippy::struct_excessive_bools,
    reason = "Possession, evidence and ungranted authority remain separate closed claims"
)]
pub(super) struct Report {
    version: u32,
    quote_exchange: bool,
    bound_reference_evidence: bool,
    key_confirmation: bool,
    complete_appraisal: bool,
    worker_admission: bool,
    private_input_released: bool,
    outstanding_appraisal: Vec<&'static str>,
}

fn check_terminal(finished: &ControlResponse, refusal: bool) -> Result<()> {
    let expected = if refusal {
        "QUOTE_DEVICE_UNAVAILABLE"
    } else {
        "QUOTE_KEY_CONFIRMED"
    };
    ensure!(
        finished.diagnostic_code == expected && matches!(finished.payload, Some(Payload::Ack(_))),
        "quote_confirmation_final_handoff"
    );
    Ok(())
}

async fn finish(
    stream: &mut UnixStream,
    id: &[u8],
    deadline: Instant,
    refusal: bool,
) -> Result<()> {
    ensure!(
        Instant::now() < deadline,
        "quote_confirmation_handoff_deadline"
    );
    let finished = timeout_at(deadline, crate::control::finish_request(stream, id))
        .await
        .context("quote_confirmation_handoff_deadline")??;
    ensure!(
        Instant::now() < deadline,
        "quote_confirmation_handoff_deadline"
    );
    check_terminal(&finished, refusal)
}

pub(super) async fn verify(
    ready: &QuoteReady,
    pending: PendingSession<'_>,
    stream: &mut UnixStream,
    id: &[u8],
    vcek: &[u8],
    crl: &[u8],
) -> Result<VerifyReport> {
    let provider = ready.provider_key.as_slice().try_into()?;
    let requester = ready.requester_key.as_slice().try_into()?;
    let request = QuoteRequest::from_challenge(pending.challenge_bytes())?;
    // The CLI authenticates all original records itself, not an agent-projected boolean.
    let offer = timeout_at(pending.deadline()?, async {
        super::wire::write_request(stream, &request).await?;
        wire::read_offer(stream, provider, requester, &request).await
    })
    .await
    .context("quote_confirmation_offer_deadline")??;
    if offer.is_device_unavailable() {
        finish(stream, id, offer.deadline().min(pending.deadline()?), true).await?;
        pending.finish_without_evidence()?;
        // Retain the conservative historical refusal report, never success/authority.
        return Ok(VerifyReport::ProviderRefusal(
            RefusalReport::device_unavailable(),
        ));
    }
    let prepared = tokio::task::block_in_place(|| pending.prepare_confirmation(offer, vcek, crl))
        .context("quote_confirmation_reference_evidence_rejected")?;
    let confirmed = timeout_at(prepared.deadline(), async {
        wire::write_probe(stream, prepared.probe()?).await?;
        prepared.confirm(wire::read_reply(stream).await?)
    })
    .await
    .context("quote_confirmation_probe_deadline")??;
    finish(stream, id, confirmed.deadline(), false).await?;
    // The borrowed owner remains live through the correlated terminal ACK. The
    // resulting evidence is historical and cannot release private input or work.
    let bound = confirmed.finish()?;
    Ok(VerifyReport::Confirmed(Report {
        version: 3,
        quote_exchange: true,
        bound_reference_evidence: true,
        key_confirmation: true,
        complete_appraisal: false,
        worker_admission: false,
        private_input_released: false,
        outstanding_appraisal: bound
            .outstanding_appraisal()
            .iter()
            .copied()
            .map(obligation)
            .collect(),
    }))
}

#[cfg(test)]
mod tests;
