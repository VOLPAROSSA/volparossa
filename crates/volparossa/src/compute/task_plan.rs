//! Bounded model-generated public subquestions, never executable tool authority.

use std::collections::BTreeSet;

use super::ModelProfile;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};
use sha2::{Digest as _, Sha256};
#[cfg(test)]
use volparossa_content::agent_artifact::{BASE_MODEL_SHA256, MODEL_ID, MODEL_REVISION};
use volparossa_local_control::compute::PublicTask;

pub(super) const MAX_ARTIFACT_BYTES: u64 = 16 * 1024;
pub(super) const CURRENT_STRATEGY: &str = "model_questions_source_recovery_v4";
pub(super) const GRAPH_STRATEGY: &str = "model_task_graph_v1";
pub(super) const CONSTRAINED_GRAPH_STRATEGY: &str = "model_task_graph_constrained_v2";
pub(super) const GUARDED_GRAPH_STRATEGY: &str = "model_task_graph_constrained_v3";
pub(super) const GRAPH_ARTIFACT_NAME: &str = "task-graph.json";
pub(super) const GENERATED_GRAPH_QUESTION_BYTES: usize = 192;
const MAX_INPUT_BYTES: usize = 16 * 1024;
const MAX_EXCERPT_BYTES: usize = 1024;

mod graph;
mod recovery;
#[cfg(test)]
pub(super) use graph::ModelTask;
pub(super) use graph::{ModelTaskGraph, validate_graph_report};
pub(super) use recovery::PlanningDiagnostic;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, clap::ValueEnum)]
#[serde(rename_all = "snake_case")]
pub(super) enum PlanRequirement {
    /// At least one model-selected task consumes another task's result.
    #[value(name = "dependent")]
    DependentAnalysisV1,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    pub(super) version: u32,
    #[serde(default, skip_serializing_if = "ModelProfile::is_default")]
    pub(super) model_profile: ModelProfile,
    pub(super) visibility: String,
    pub(super) license: String,
    pub(super) question: String,
    /// The entire retained public source, not only the bounded planner excerpt.
    pub(super) source_sha256: String,
    pub(super) source_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub(super) source_excerpt: Option<SourceExcerpt>,
    /// Explicit owner-selected workflow shape; absence preserves historical input bytes.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_requirement"
    )]
    pub(super) plan_requirement: Option<PlanRequirement>,
}

fn present_requirement<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<PlanRequirement>, D::Error> {
    PlanRequirement::deserialize(deserializer).map(Some)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct SourceExcerpt {
    pub(super) start: u64,
    pub(super) end: u64,
    pub(super) text: String,
    pub(super) sha256: String,
}

impl SourceExcerpt {
    pub(super) fn prefix(source: &str) -> Self {
        let mut end = MAX_EXCERPT_BYTES.min(source.len());
        while !source.is_char_boundary(end) {
            end -= 1;
        }
        let text = source[..end].to_owned();
        Self {
            start: 0,
            end: end as u64,
            sha256: digest(text.as_bytes()),
            text,
        }
    }
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
            matches!(self.version, 1..=3) && self.visibility == "public",
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
            self.plan_requirement.is_none() || self.version == 3,
            "compute_task_plan_requirement_version"
        );
        ensure!(
            (1..=super::MAX_DATASET_BYTES).contains(&self.source_bytes)
                && super::is_hex(&self.source_sha256, 64)
                && self.source_sha256.bytes().any(|byte| byte != b'0'),
            "compute_task_plan_source"
        );
        match (self.version, &self.source_excerpt) {
            (1, None) => (), // Retained historical reports only, never new execution.
            (2 | 3, Some(excerpt)) => ensure!(
                excerpt.start == 0
                    && (1..=MAX_EXCERPT_BYTES).contains(&excerpt.text.len())
                    && !excerpt.text.contains('\0')
                    && excerpt.end == excerpt.text.len() as u64
                    && excerpt.end <= self.source_bytes
                    && excerpt.sha256 == digest(excerpt.text.as_bytes())
                    && (excerpt.end != self.source_bytes || excerpt.sha256 == self.source_sha256),
                "compute_task_plan_excerpt"
            ),
            _ => anyhow::bail!("compute_task_plan_excerpt_version"),
        }
        Ok(())
    }

    pub(super) fn validate_execution(&self) -> Result<()> {
        self.validate()?;
        ensure!(
            matches!(self.version, 2 | 3),
            "compute_task_plan_source_required"
        );
        Ok(())
    }

    fn descriptor(&self, bytes: &[u8]) -> Value {
        let mut descriptor = json!({
            "version":self.version,"sha256":digest(bytes),"bytes":bytes.len(),
            "visibility":"public","license":self.license,
            "question_sha256":digest(self.question.as_bytes()),
            "source_sha256":self.source_sha256,"source_bytes":self.source_bytes
        });
        if let Some(excerpt) = &self.source_excerpt {
            descriptor["source_excerpt"] = json!({
                "start":excerpt.start,"end":excerpt.end,"sha256":excerpt.sha256,
                "bytes":excerpt.text.len()
            });
        }
        if let Some(requirement) = self.plan_requirement {
            descriptor["plan_requirement"] = json!(requirement);
        }
        descriptor
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
            matches!(self.version, 1 | 2) && (2..=4).contains(&self.questions.len()),
            "compute_task_plan_question_count"
        );
        let mut seen = BTreeSet::new();
        for text in &self.questions {
            question(text)?;
            ensure!(
                self.version == 1 || text.trim_end().ends_with('?'),
                "compute_task_plan_not_a_question"
            );
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
            Some(
                "model_questions_scaffold_v1"
                    | recovery::STRATEGY
                    | recovery::SOURCE_STRATEGY
                    | CURRENT_STRATEGY
            )
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
    ensure!(
        (questions.version == 2)
            == matches!(
                report["planner_strategy"].as_str(),
                Some(recovery::SOURCE_STRATEGY | CURRENT_STRATEGY)
            ),
        "compute_task_plan_strategy_version"
    );
    questions.validate()?;
    if report["planner_strategy"] == recovery::STRATEGY
        || report["planner_strategy"] == recovery::SOURCE_STRATEGY
        || report["planner_strategy"] == CURRENT_STRATEGY
    {
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
    let profile = input.model_profile.spec();
    ensure!(
        questions.version == input.version,
        "compute_task_plan_artifact_version"
    );
    validate_question_stats(report, &questions)?;
    if report["planner_strategy"] == CURRENT_STRATEGY {
        recovery::validate_goal_binding(report, &questions, &input.question)?;
    }
    if let Some(excerpt) = &input.source_excerpt {
        ensure!(
            report["source_contents_read_by_planner"] == true
                && report["source_excerpt_complete"] == (excerpt.end == input.source_bytes),
            "compute_task_plan_source_coverage"
        );
    } else {
        ensure!(
            report.get("source_contents_read_by_planner").is_none()
                && report.get("source_excerpt_complete").is_none(),
            "compute_task_plan_legacy_source_claim"
        );
    }
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
            && report["goal_only_planning"] == (input.version == 1)
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
        report["model"]["id"] == profile.model_id
            && report["model"]["revision"] == profile.revision
            && report["model"]["files"]["model.safetensors"]["sha256"] == profile.weights_sha256
            && report["dataset"] == input.descriptor(input_bytes)
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
