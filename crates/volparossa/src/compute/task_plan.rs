//! Bounded model-generated public subquestions, never executable tool authority.

use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
use volparossa_content::agent_artifact::{BASE_MODEL_SHA256, MODEL_ID, MODEL_REVISION};
use volparossa_local_control::compute::PublicTask;

pub(super) const MAX_ARTIFACT_BYTES: u64 = 16 * 1024;
const MAX_INPUT_BYTES: usize = 16 * 1024;

mod recovery;
pub(super) use recovery::PlanningDiagnostic;

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    pub(super) version: u32,
    pub(super) visibility: String,
    pub(super) license: String,
    pub(super) question: String,
    /// The planner sees the goal only. This binds the later source, not source understanding.
    pub(super) source_sha256: String,
    pub(super) source_bytes: u64,
}

impl Input {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() <= MAX_INPUT_BYTES,
            "compute_task_plan_input_bound"
        );
        let input: Self = serde_json::from_slice(bytes)?;
        input.validate()?;
        Ok(input)
    }

    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && self.visibility == "public",
            "compute_task_plan_public_required"
        );
        ensure!(
            matches!(
                self.license.as_str(),
                "GPL-3.0-only" | "CC0-1.0" | "CC-BY-4.0" | "CC-BY-SA-4.0"
            ),
            "compute_task_plan_license"
        );
        question(&self.question)?;
        ensure!(
            (1..=super::MAX_DATASET_BYTES).contains(&self.source_bytes)
                && super::is_hex(&self.source_sha256, 64)
                && self.source_sha256.bytes().any(|byte| byte != b'0'),
            "compute_task_plan_source"
        );
        Ok(())
    }
}

fn question(text: &str) -> Result<()> {
    PublicTask::AnswerPublicQuestionV1 {
        question: text.into(),
    }
    .question()?;
    Ok(())
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Questions {
    pub(super) version: u32,
    pub(super) questions: Vec<String>,
}

impl Questions {
    pub(super) fn decode(bytes: &[u8]) -> Result<Self> {
        ensure!(
            bytes.len() as u64 <= MAX_ARTIFACT_BYTES,
            "compute_task_plan_artifact_bound"
        );
        let questions: Self = serde_json::from_slice(bytes)?;
        questions.validate()?;
        Ok(questions)
    }

    pub(super) fn validate(&self) -> Result<()> {
        ensure!(
            self.version == 1 && (2..=4).contains(&self.questions.len()),
            "compute_task_plan_question_count"
        );
        let mut seen = BTreeSet::new();
        for text in &self.questions {
            question(text)?;
            ensure!(
                seen.insert(text.trim()),
                "compute_task_plan_duplicate_question"
            );
        }
        Ok(())
    }
}

fn digest(bytes: &[u8]) -> String {
    hex::encode(Sha256::digest(bytes))
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct QuestionStats {
    prompt_tokens: u64,
    generated_tokens: u64,
    stop_reason: String,
}

fn validate_question_stats(report: &Value, questions: &Questions) -> Result<()> {
    let stats: Vec<QuestionStats> =
        serde_json::from_value(report["planner_question_stats"].clone())?;
    ensure!(
        matches!(
            report["planner_strategy"].as_str(),
            Some("model_questions_scaffold_v1" | recovery::STRATEGY)
        ) && report["planner_structure_generated_by"] == "local_schema"
            && report["planner_stop_reason"] == "two_questions"
            && stats.len() == 2
            && questions.questions.len() == 2,
        "compute_task_plan_strategy"
    );
    for (stat, question) in stats.iter().zip(&questions.questions) {
        ensure!(
            (1..=512).contains(&stat.prompt_tokens)
                && (1..192).contains(&stat.generated_tokens)
                && match stat.stop_reason.as_str() {
                    "question_boundary" => question.trim_end().ends_with('?'),
                    "eos" => true,
                    _ => false,
                },
            "compute_task_plan_question_budget"
        );
    }
    if report["planner_strategy"] == recovery::STRATEGY {
        return recovery::validate_success(report, questions, &stats);
    }
    ensure!(
        report.get("planner_attempts").is_none(),
        "compute_task_plan_legacy_attempts"
    );
    ensure!(
        report["planner_prompt_tokens"].as_u64()
            == stats.iter().map(|stat| stat.prompt_tokens).max()
            && report["planner_generated_tokens"].as_u64()
                == Some(stats.iter().map(|stat| stat.generated_tokens).sum()),
        "compute_task_plan_total_budget"
    );
    Ok(())
}

/// Correlate the actual isolated worker's retained result. This is a local execution
/// record, not independent remote attestation or evidence of meaningful decomposition.
pub(super) fn validate_report(
    report: &Value,
    input: &Input,
    input_bytes: &[u8],
    artifact: &[u8],
) -> Result<Questions> {
    ensure!(
        Input::decode(input_bytes)? == *input,
        "compute_task_plan_input_changed"
    );
    let questions = Questions::decode(artifact)?;
    validate_question_stats(report, &questions)?;
    ensure!(
        report["version"] == 1
            && report["kind"] == "result"
            && report["status"] == "ok"
            && report["mode"] == "plan_tasks"
            && report["id"]
                .as_str()
                .is_some_and(|id| super::is_hex(id, 32))
            && report["device"] == "cpu"
            && report["threads"]
                .as_u64()
                .is_some_and(|n| (1..=2).contains(&n))
            && report["updates_completed"] == 0
            && report["model_weights_loaded"] == true
            && report["goal_only_planning"] == true
            && report["generation_limit_reached"] == false
            && report["model_answer_correctness_proven"] == false
            && report["planner_prompt_tokens"]
                .as_u64()
                .is_some_and(|n| (1..=512).contains(&n))
            && report["planner_generated_tokens"]
                .as_u64()
                .is_some_and(|n| (1..384).contains(&n))
            && report.get("outputs").is_none()
            && report.get("baseline_evaluation").is_none()
            && report.get("input_adapter").is_none(),
        "compute_task_plan_worker_result"
    );
    ensure!(
        report["model"]["id"] == MODEL_ID
            && report["model"]["revision"] == MODEL_REVISION
            && report["model"]["files"]["model.safetensors"]["sha256"]
                == hex::encode(BASE_MODEL_SHA256)
            && report["dataset"]
                == json!({
                    "version":1,"sha256":digest(input_bytes),"bytes":input_bytes.len(),
                    "visibility":"public","license":input.license,
                    "question_sha256":digest(input.question.as_bytes()),
                    "source_sha256":input.source_sha256,"source_bytes":input.source_bytes
                })
            && report["artifacts"]
                == json!([{
                    "relative_path":"task-questions.json","bytes":artifact.len(),"sha256":digest(artifact)
                }])
            && report["supervisor"]["child_reaped"] == true
            && report["supervisor"]["network_access"] == false,
        "compute_task_plan_worker_binding"
    );
    Ok(questions)
}

#[cfg(test)]
mod tests;
