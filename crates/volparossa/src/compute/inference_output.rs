//! Generation termination is independent of job completion and answer correctness.

use super::ModelProfile;
use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use volparossa_content::provider::compute::dataset::PrincipleOutputContract;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub(super) enum StopReason {
    Eos,
    TokenLimit,
    JsonBoundary,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Generation {
    pub(super) version: u8,
    pub(super) stop_reason: StopReason,
    pub(super) max_new_tokens: u16,
    #[serde(default, skip_serializing_if = "ModelProfile::is_default")]
    pub(super) model_profile: ModelProfile,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) output_contract: Option<PrincipleOutputContract>,
}

impl Generation {
    /// Missing metadata in an original historical receipt is unknown, never inferred EOS.
    /// Fresh results from this binary's fixed worker must carry the current contract.
    pub(super) fn from_output(output: &Value, require_current: bool) -> Result<Option<Self>> {
        let Some(metadata) = output.get("generation") else {
            ensure!(!require_current, "compute_generation_metadata_missing");
            return Ok(None);
        };
        let generation: Self = serde_json::from_value(metadata.clone())
            .map_err(|_| anyhow::anyhow!("compute_generation_metadata_invalid"))?;
        let tokens = output["generated_tokens"]
            .as_u64()
            .context("compute_generation_token_count")?;
        let limit = generation.model_profile.spec().max_new_tokens;
        ensure!(
            ((generation.version == 1
                && generation.output_contract.is_none()
                && generation.stop_reason != StopReason::JsonBoundary)
                || (generation.version == 2
                    && generation.output_contract.is_some()
                    && generation.model_profile == ModelProfile::Smol360))
                && generation.max_new_tokens == limit
                && (1..=u64::from(limit)).contains(&tokens)
                && (generation.stop_reason != StopReason::TokenLimit || tokens == u64::from(limit)),
            "compute_generation_termination_invalid"
        );
        if generation.stop_reason == StopReason::JsonBoundary {
            ensure!(
                output["text_truncated"] == false,
                "compute_generation_boundary_truncated"
            );
            super::policy_assessment::validate_output_shape(
                output["text"]
                    .as_str()
                    .context("compute_generation_boundary_text")?
                    .as_bytes(),
                generation
                    .output_contract
                    .context("compute_generation_boundary_contract")?,
            )?;
        }
        Ok(Some(generation))
    }

    /// EOS is a token-level termination observation, not a semantic quality guarantee.
    pub(super) fn is_eos(self) -> bool {
        self.stop_reason == StopReason::Eos
    }

    pub(super) fn is_json_boundary(self) -> bool {
        self.stop_reason == StopReason::JsonBoundary
    }
}

/// The constrained decoder is authorized by the actual input, never inferred
/// from model output or from the contents of a natural-language question.
pub(super) fn check_dataset_contract(report: &Value, dataset: &[u8]) -> Result<()> {
    use sha2::{Digest as _, Sha256};
    let input: Value = serde_json::from_slice(dataset)?;
    let expected = if input["version"] == 4 {
        let input: volparossa_content::provider::compute::dataset::PrincipleDataset =
            serde_json::from_slice(dataset)?;
        input.validate_shape()?;
        ensure!(
            report["dataset"]["sha256"] == hex::encode(Sha256::digest(dataset))
                && report["dataset"]["version"] == 4
                && report["dataset"]["output_contract"]
                    == serde_json::to_value(input.output_contract)?,
            "compute_generation_input_binding"
        );
        Some(input.output_contract)
    } else {
        None
    };
    for output in report["outputs"]
        .as_array()
        .context("compute_generation_outputs")?
    {
        ensure!(
            Generation::from_output(output, true)?
                .is_some_and(|generation| generation.output_contract == expected),
            "compute_generation_unrequested_contract"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::{Generation, StopReason};
    use serde_json::{Value, json};

    fn output(tokens: u16, reason: &str) -> Value {
        json!({"generated_tokens":tokens,
            "generation":{"version":1,"stop_reason":reason,"max_new_tokens":64}})
    }

    #[test]
    fn eos_at_the_budget_is_not_a_token_limit_and_wire_truncation_is_independent() {
        for tokens in [1, 12, 64] {
            let mut row = output(tokens, "eos");
            row["text_truncated"] = true.into();
            let generation = Generation::from_output(&row, true).unwrap().unwrap();
            assert!(generation.is_eos());
            assert_eq!(generation.stop_reason, StopReason::Eos);
        }
        let limited = Generation::from_output(&output(64, "token_limit"), true)
            .unwrap()
            .unwrap();
        assert!(!limited.is_eos());
    }

    #[test]
    fn larger_budget_requires_its_explicit_pinned_profile() {
        let mut row = output(256, "eos");
        row["generation"]["max_new_tokens"] = 256.into();
        assert!(Generation::from_output(&row, true).is_err());
        row["generation"]["model_profile"] = "smollm2-360m-v1".into();
        let generation = Generation::from_output(&row, true).unwrap().unwrap();
        assert!(generation.is_eos());
        row["generation"]["stop_reason"] = "token_limit".into();
        assert!(
            !Generation::from_output(&row, true)
                .unwrap()
                .unwrap()
                .is_eos()
        );
        row["generated_tokens"] = 255.into();
        assert!(Generation::from_output(&row, true).is_err());
        row["generation"]["model_profile"] = "unapproved".into();
        assert!(Generation::from_output(&row, true).is_err());
    }

    #[test]
    fn legacy_absence_is_unknown_and_never_valid_for_new_local_execution() {
        let legacy = json!({"generated_tokens":12,"text_truncated":false});
        assert_eq!(Generation::from_output(&legacy, false).unwrap(), None);
        assert!(Generation::from_output(&legacy, true).is_err());
        assert!(Generation::from_output(&json!({"generation":null}), false).is_err());
    }

    #[test]
    fn malformed_or_unbound_budget_is_not_an_accepted_termination() {
        for row in [
            output(0, "eos"),
            output(65, "eos"),
            output(63, "token_limit"),
            output(1, "stopped"),
        ] {
            assert!(Generation::from_output(&row, false).is_err());
        }
        for (key, value) in [
            ("version", json!(2)),
            ("version", json!(true)),
            ("max_new_tokens", json!(256)),
            ("max_new_tokens", json!(63)),
            ("unexpected", json!("untrusted text")),
        ] {
            let mut row = output(64, "token_limit");
            row["generation"][key] = value;
            assert!(Generation::from_output(&row, false).is_err());
        }
        let mut row = output(1, "eos");
        row["generated_tokens"] = true.into();
        assert!(Generation::from_output(&row, false).is_err());
    }

    #[test]
    fn structured_boundary_is_complete_json_not_invented_eos_or_a_budget_extension() {
        let text = json!({"version":1,"outcome":"undetermined",
            "reasoning":[{"principle":"Humilitas","quote":"public","reason":"Evidence is limited."}],
            "counterargument":"Further context could change this.",
            "uncertainty":{"material":true,"reason":"Insufficient context."}}).to_string();
        let row = json!({"text":text,"text_truncated":false,"generated_tokens":100,
            "generation":{"version":2,"stop_reason":"json_boundary","max_new_tokens":256,
            "model_profile":"smollm2-360m-v1","output_contract":"principle_assessment_v1"}});
        let generation = Generation::from_output(&row, true).unwrap().unwrap();
        assert!(generation.is_json_boundary());
        assert!(!generation.is_eos());
        for (pointer, value) in [
            ("/text", json!("{\"version\":1")),
            ("/text_truncated", json!(true)),
            ("/generation/version", json!(1)),
            ("/generation/output_contract", json!("principle_review_v1")),
            ("/generation/stop_reason", json!("token_limit")),
            ("/generation/max_new_tokens", json!(512)),
            ("/generated_tokens", json!(257)),
        ] {
            let mut changed = row.clone();
            *changed.pointer_mut(pointer).unwrap() = value;
            assert!(
                Generation::from_output(&changed, true).is_err(),
                "{pointer}"
            );
        }
        let mut at_limit = row.clone();
        at_limit["generated_tokens"] = 256.into();
        assert!(
            Generation::from_output(&at_limit, true)
                .unwrap()
                .unwrap()
                .is_json_boundary()
        );
        assert!(
            super::check_dataset_contract(&json!({"outputs":[row]}), br#"{"version":2}"#).is_err()
        );
    }
}
