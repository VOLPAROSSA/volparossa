//! Explicitly public code proposals are data, never private conversations or execution authority.

use anyhow::{Context as _, Result, ensure};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use volparossa_content::provider::compute::dataset::CodeProposalDataset;

use super::{ModelProfile, inference_output::Generation};

pub(super) fn validate_report(report: &Value, raw: &[u8], profile: ModelProfile) -> Result<()> {
    let input: CodeProposalDataset = serde_json::from_slice(raw)?;
    input.validate_shape()?;
    ensure!(
        input.model_profile == profile && profile.is_native_conversation(),
        "compute_public_code_model_profile"
    );
    let row = &input.inference[0];
    ensure!(
        report["mode"] == "public_code_proposal"
            && report["status"] == "ok"
            && report["purpose"] == "code_proposal"
            && report["output_contract"] == "single_file_replacement_v1"
            && report["updates_completed"] == 0
            && report["artifacts"] == json!([])
            && report["public_data_only"] == true
            && report["private_data_supported"] == false
            && report["model_weights_loaded"] == true
            && report["better_answers_claimed"] == false
            && report["network_policy_changed"] == false
            && report["generation_policy"] == "greedy_v1"
            && report.get("input_adapter").is_none()
            && report.get("conversation").is_none()
            && report.get("conversation_limits").is_none()
            && report.get("baseline_evaluation").is_none(),
        "compute_public_code_report_scope"
    );
    ensure!(
        report["dataset"]
            == json!({
        "sha256":hex::encode(Sha256::digest(raw)),"bytes":raw.len(),"visibility":"public",
        "license":input.license,"version":6,"purpose":"code_proposal",
        "output_contract":"single_file_replacement_v1",
        "source_manifest_sha256":hex::encode(Sha256::digest(hex::decode(&input.source_manifest_hex)?)),
        "source_sha256":hex::encode(Sha256::digest(row.context.as_bytes())),
        "source_bytes":row.context.len(),"inference_examples":1}),
        "compute_public_code_source_binding"
    );
    let spec = profile.spec();
    ensure!(
        report["model"]["id"] == spec.model_id
            && report["model"]["revision"] == spec.revision
            && report["model_parameter_dtype"] == "bfloat16"
            && report["model_attention_backend"] == "sdpa"
            && report["prompt_tokens"]
                .as_u64()
                .is_some_and(|tokens| (1..=u64::from(spec.prompt_tokens)).contains(&tokens)),
        "compute_public_code_model_binding"
    );
    super::private_task::validate_model_weights(&report["model"], profile)?;
    let outputs = report["outputs"]
        .as_array()
        .context("compute_public_code_outputs")?;
    ensure!(outputs.len() == 1, "compute_public_code_outputs");
    let output = &outputs[0];
    let text = output["text"]
        .as_str()
        .context("compute_public_code_output_text")?;
    ensure!(
        output["sample_index"] == 0
            && text.len() <= spec.max_output_bytes
            && output["text_truncated"].is_boolean(),
        "compute_public_code_output_shape"
    );
    let generation =
        Generation::from_output(output, true)?.context("compute_public_code_generation")?;
    ensure!(
        generation.model_profile == profile && generation.output_contract.is_none(),
        "compute_public_code_generation"
    );
    ensure!(
        report["proposal_complete"]
            == (generation.is_eos()
                && output["text_truncated"] == false
                && !text.trim().is_empty()),
        "compute_public_code_completion"
    );
    Ok(())
}

#[cfg(test)]
mod tests;
