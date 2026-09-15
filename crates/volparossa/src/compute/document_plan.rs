//! Exact byte coverage from the isolated, pinned tokenizer; never a host-side approximation.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sha2::{Digest, Sha256};
use volparossa_content::agent_artifact::{MODEL_ID, MODEL_REVISION};

pub(super) const MAX_DOCUMENT_BYTES: usize = 1024 * 1024;
pub(super) const MAX_PARTS: usize = 16_384;
const TOKENIZER_SHA256: &str = "9ca9acddb6525a194ec8ac7a87f24fbba7232a9a15ffa1af0c1224fcd888e47c";

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    pub(super) version: u32,
    pub(super) visibility: String,
    pub(super) license: String,
    pub(super) document: String,
    pub(super) question: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) synthesis: bool,
}

impl Input {
    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.visibility == "public",
            "compute_document_public_required"
        );
        ensure!(
            matches!(
                self.license.as_str(),
                "GPL-3.0-only" | "CC0-1.0" | "CC-BY-4.0" | "CC-BY-SA-4.0"
            ),
            "compute_document_explicit_license"
        );
        ensure!(
            !self.document.trim().is_empty()
                && self.document.len() <= MAX_DOCUMENT_BYTES
                && !self.document.contains('\0'),
            "compute_document_text_bound"
        );
        volparossa_local_control::compute::PublicTask::AnswerPublicQuestionV1 {
            question: self.question.clone(),
        }
        .question()?;
        Ok(())
    }
}

pub(super) fn validate_input(value: &Value) -> Result<()> {
    serde_json::from_value::<Input>(value.clone())?.validate()
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Part {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) prompt_tokens: u16,
}

#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Plan {
    pub(super) version: u32,
    pub(super) source_sha256: String,
    pub(super) source_bytes: u64,
    pub(super) question_sha256: String,
    pub(super) model_id: String,
    pub(super) model_revision: String,
    pub(super) tokenizer_sha256: String,
    pub(super) prompt_limit: u16,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub(super) synthesis: bool,
    pub(super) parts: Vec<Part>,
}

impl Plan {
    pub(super) fn validate(&self, input: &Input) -> Result<()> {
        input.validate()?;
        ensure!(
            self.version == 1
                && self.source_bytes == input.document.len() as u64
                && self.source_sha256 == hex::encode(Sha256::digest(input.document.as_bytes()))
                && self.question_sha256 == hex::encode(Sha256::digest(input.question.as_bytes()))
                && self.model_id == MODEL_ID
                && self.model_revision == MODEL_REVISION
                && self.tokenizer_sha256 == TOKENIZER_SHA256
                && self.prompt_limit == 192
                && self.synthesis == input.synthesis,
            "compute_document_plan_source_or_tokenizer"
        );
        ensure!(
            (1..=MAX_PARTS).contains(&self.parts.len()),
            "compute_document_part_budget"
        );
        let mut next = 0;
        for part in &self.parts {
            ensure!(
                part.start == next
                    && part.end > part.start
                    && part.end <= self.source_bytes
                    && part.end - part.start <= 4096
                    && (1..=self.prompt_limit).contains(&part.prompt_tokens),
                "compute_document_incomplete_or_oversized_part"
            );
            ensure!(
                input
                    .document
                    .is_char_boundary(usize::try_from(part.start)?)
                    && input.document.is_char_boundary(usize::try_from(part.end)?),
                "compute_document_utf8_split"
            );
            next = part.end;
        }
        ensure!(next == self.source_bytes, "compute_document_tail_missing");
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exact_unicode_coverage_refuses_gaps_overlaps_truncation_and_changed_task() {
        let input = Input {
            version: 1,
            visibility: "public".into(),
            license: "CC0-1.0".into(),
            document: "één\nwereld".into(),
            question: "What does it say?".into(),
            synthesis: false,
        };
        let mut plan = Plan {
            version: 1,
            source_sha256: hex::encode(Sha256::digest(input.document.as_bytes())),
            source_bytes: input.document.len() as u64,
            question_sha256: hex::encode(Sha256::digest(input.question.as_bytes())),
            model_id: MODEL_ID.into(),
            model_revision: MODEL_REVISION.into(),
            tokenizer_sha256: TOKENIZER_SHA256.into(),
            prompt_limit: 192,
            synthesis: false,
            parts: vec![
                Part {
                    start: 0,
                    end: 5,
                    prompt_tokens: 80,
                },
                Part {
                    start: 5,
                    end: input.document.len() as u64,
                    prompt_tokens: 90,
                },
            ],
        };
        plan.validate(&input).unwrap(); // Counts are a parser fixture, not actual tokenizer proof.
        for start in [0, 4, 6] {
            plan.parts[1].start = start;
            assert!(plan.validate(&input).is_err());
        }
        plan.parts[1].start = 5;
        plan.parts[0].end = 1;
        plan.parts[1].start = 1;
        assert!(plan.validate(&input).is_err());
        plan.parts[0].end = 5;
        plan.parts[1].start = 5;
        plan.parts[1].prompt_tokens = 193;
        assert!(plan.validate(&input).is_err());
        plan.parts[1].prompt_tokens = 90;
        plan.parts[1].end -= 1;
        assert!(plan.validate(&input).is_err());
        plan.parts[1].end += 1;
        plan.question_sha256 = "0".repeat(64);
        assert!(plan.validate(&input).is_err());
    }

    #[test]
    fn synthesis_prompt_profile_is_bound_and_legacy_json_stays_unchanged() {
        let legacy = serde_json::json!({"version":1,"visibility":"public","license":"CC0-1.0",
            "document":"Public generated notes.","question":"What is stated?"});
        let mut input: Input = serde_json::from_value(legacy.clone()).unwrap();
        assert!(!input.synthesis);
        assert_eq!(serde_json::to_value(&input).unwrap(), legacy);
        let legacy_plan = serde_json::json!({"version":1,
            "source_sha256":hex::encode(Sha256::digest(input.document.as_bytes())),
            "source_bytes":input.document.len(),
            "question_sha256":hex::encode(Sha256::digest(input.question.as_bytes())),
            "model_id":MODEL_ID,"model_revision":MODEL_REVISION,
            "tokenizer_sha256":TOKENIZER_SHA256,"prompt_limit":192,
            "parts":[{"start":0,"end":input.document.len(),"prompt_tokens":30}]});
        let mut plan: Plan = serde_json::from_value(legacy_plan.clone()).unwrap();
        plan.validate(&input).unwrap(); // Synthetic counts, not a tokenizer-execution proof.
        assert_eq!(serde_json::to_value(&plan).unwrap(), legacy_plan);
        input.synthesis = true;
        assert!(plan.validate(&input).is_err());
        plan.synthesis = true;
        plan.validate(&input).unwrap();
        assert_eq!(serde_json::to_value(&input).unwrap()["synthesis"], true);
        assert_eq!(serde_json::to_value(&plan).unwrap()["synthesis"], true);
        input.synthesis = false;
        assert!(plan.validate(&input).is_err());
    }
}
