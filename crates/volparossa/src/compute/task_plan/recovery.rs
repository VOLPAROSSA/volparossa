//! Account for rejected generations without renewing the original owner or budget.

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

use super::{CURRENT_STRATEGY, QuestionStats, Questions, digest};

pub(super) const STRATEGY: &str = "model_questions_scaffold_recovery_v2";
pub(super) const SOURCE_STRATEGY: &str = "model_questions_source_recovery_v3";

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GenerationAttempt {
    question_index: u64,
    attempt: u64,
    prompt_tokens: u64,
    generated_tokens: u64,
    max_new_tokens: u64,
    stop_reason: String,
    accepted: bool,
    rejection_code: Option<String>,
    text_bytes: u64,
    text_sha256: String,
}

/// Diagnostic data only; neither a task plan nor remote execution attestation.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::compute) struct QuestionDiagnostic {
    strategy: String,
    attempts: Vec<GenerationAttempt>,
    incomplete_attempt: bool,
}

/// Both variants retain the original external JSON shape, without a new tag.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(untagged)]
pub(in crate::compute) enum PlanningDiagnostic {
    Questions(QuestionDiagnostic),
    Graph(super::graph::GraphDiagnostic),
}

impl PlanningDiagnostic {
    pub(in crate::compute) fn from_value(value: &Value) -> Result<Self> {
        if matches!(
            value["strategy"].as_str(),
            Some(super::GRAPH_STRATEGY | super::CONSTRAINED_GRAPH_STRATEGY)
        ) {
            super::graph::GraphDiagnostic::from_value(value).map(Self::Graph)
        } else {
            QuestionDiagnostic::from_value(value).map(Self::Questions)
        }
    }
}

impl QuestionDiagnostic {
    pub(in crate::compute) fn from_value(value: &Value) -> Result<Self> {
        check_shape(&value["attempts"], 0)?;
        let diagnostic: Self = serde_json::from_value(value.clone())?;
        ensure!(
            matches!(
                diagnostic.strategy.as_str(),
                STRATEGY | SOURCE_STRATEGY | CURRENT_STRATEGY
            ),
            "compute_task_plan_strategy"
        );
        let summary = checked_attempts(&diagnostic.attempts, &diagnostic.strategy)?;
        if diagnostic.incomplete_attempt {
            // No fabricated token count for a generation whose result was not validated.
            ensure!(
                diagnostic.attempts.len() < 4 && summary.accepted.len() < 2 && summary.tokens < 384,
                "compute_task_plan_incomplete_attempt"
            );
        }
        Ok(diagnostic)
    }
}

fn check_shape(value: &Value, minimum: usize) -> Result<()> {
    ensure!(
        value.as_array().is_some_and(|attempts| {
            (minimum..=4).contains(&attempts.len())
                && attempts
                    .iter()
                    .all(|attempt| attempt.get("rejection_code").is_some())
        }),
        "compute_task_plan_attempt_shape"
    );
    Ok(())
}

struct Summary<'a> {
    accepted: Vec<&'a GenerationAttempt>,
    tokens: u64,
    prompt: u64,
}

fn rejection(attempt: &GenerationAttempt, strategy: &str) -> Result<()> {
    ensure!(
        matches!(attempt.rejection_code.as_deref(),
            Some("EMPTY_TEXT") if attempt.text_bytes <= 512
        ) || matches!(attempt.rejection_code.as_deref(),
            Some("TEXT_TOO_LONG") if attempt.text_bytes > 512
        ) || matches!(attempt.rejection_code.as_deref(),
            Some("NUL_TEXT") if (1..=512).contains(&attempt.text_bytes)
        ) || matches!(attempt.rejection_code.as_deref(),
            Some("DUPLICATE_TEXT") if attempt.question_index == 1 && (1..=512).contains(&attempt.text_bytes)
        ) || matches!(attempt.rejection_code.as_deref(),
            Some("NOT_A_QUESTION") if matches!(strategy, SOURCE_STRATEGY | CURRENT_STRATEGY)
                && attempt.stop_reason == "eos" && (1..=512).contains(&attempt.text_bytes)
        ) || matches!(attempt.rejection_code.as_deref(),
            Some("GOAL_COPY") if strategy == CURRENT_STRATEGY && (1..=512).contains(&attempt.text_bytes)
        ) || matches!(attempt.rejection_code.as_deref(),
            Some("GENERATION_LIMIT") if attempt.stop_reason == "token_limit"
        ),
        "compute_task_plan_rejection"
    );
    Ok(())
}

fn checked_attempts<'a>(attempts: &'a [GenerationAttempt], strategy: &str) -> Result<Summary<'a>> {
    ensure!(attempts.len() <= 4, "compute_task_plan_attempt_bound");
    let mut summary = Summary {
        accepted: Vec::new(),
        tokens: 0,
        prompt: 0,
    };
    for (index, attempt) in attempts.iter().enumerate() {
        ensure!(
            summary.accepted.len() < 2
                && attempt.question_index == summary.accepted.len() as u64
                && attempt.attempt == index as u64 + 1
                && (1..=512).contains(&attempt.prompt_tokens)
                && attempt.max_new_tokens == 192.min(384 - summary.tokens)
                && (1..=attempt.max_new_tokens).contains(&attempt.generated_tokens)
                && crate::compute::is_hex(&attempt.text_sha256, 64),
            "compute_task_plan_attempt_sequence_or_budget"
        );
        match attempt.stop_reason.as_str() {
            "token_limit" => ensure!(
                attempt.generated_tokens == attempt.max_new_tokens
                    && !attempt.accepted
                    && attempt.rejection_code.as_deref() == Some("GENERATION_LIMIT"),
                "compute_task_plan_limit_attempt"
            ),
            "eos" | "question_boundary" => {
                ensure!(
                    attempt.generated_tokens < attempt.max_new_tokens
                        && attempt.rejection_code.as_deref() != Some("GENERATION_LIMIT"),
                    "compute_task_plan_attempt_stop"
                );
                if attempt.stop_reason == "question_boundary" {
                    ensure!(
                        (1..=512).contains(&attempt.text_bytes)
                            && (attempt.accepted
                                || attempt.rejection_code.as_deref() == Some("DUPLICATE_TEXT")
                                || (strategy == CURRENT_STRATEGY
                                    && attempt.rejection_code.as_deref() == Some("GOAL_COPY"))),
                        "compute_task_plan_question_boundary"
                    );
                }
            }
            _ => anyhow::bail!("compute_task_plan_attempt_stop"),
        }
        if attempt.accepted {
            ensure!(
                attempt.rejection_code.is_none() && (1..=512).contains(&attempt.text_bytes),
                "compute_task_plan_accepted_text"
            );
            summary.accepted.push(attempt);
        } else {
            rejection(attempt, strategy)?;
        }
        summary.tokens += attempt.generated_tokens;
        summary.prompt = summary.prompt.max(attempt.prompt_tokens);
    }
    Ok(summary)
}

pub(super) fn validate_success(
    report: &Value,
    questions: &Questions,
    stats: &[QuestionStats],
) -> Result<()> {
    check_shape(&report["planner_attempts"], 2)?;
    let attempts: Vec<GenerationAttempt> =
        serde_json::from_value(report["planner_attempts"].clone())?;
    let summary = checked_attempts(
        &attempts,
        report["planner_strategy"].as_str().unwrap_or_default(),
    )?;
    ensure!(
        summary.accepted.len() == 2
            && summary.tokens < 384
            && report["planner_prompt_tokens"].as_u64() == Some(summary.prompt)
            && report["planner_generated_tokens"].as_u64() == Some(summary.tokens),
        "compute_task_plan_total_budget"
    );
    for ((attempt, question), stats) in summary.accepted.iter().zip(&questions.questions).zip(stats)
    {
        ensure!(
            attempt.text_bytes == question.len() as u64
                && attempt.text_sha256 == digest(question.as_bytes())
                && stats.prompt_tokens == attempt.prompt_tokens
                && stats.generated_tokens == attempt.generated_tokens
                && stats.stop_reason == attempt.stop_reason,
            "compute_task_plan_attempt_artifact_binding"
        );
    }
    Ok(())
}

/// Only v4 successful reports apply this rule. Historical artifacts remain readable;
/// a failure diagnostic alone neither certifies its rejected text nor enrolls work.
pub(super) fn validate_goal_binding(
    report: &Value,
    questions: &Questions,
    goal: &str,
) -> Result<()> {
    ensure!(
        questions
            .questions
            .iter()
            .all(|question| question.as_bytes() != goal.as_bytes()),
        "compute_task_plan_goal_copy"
    );
    let attempts: Vec<GenerationAttempt> =
        serde_json::from_value(report["planner_attempts"].clone())?;
    for attempt in attempts {
        if attempt.rejection_code.as_deref() == Some("GOAL_COPY") {
            ensure!(
                attempt.text_bytes == goal.len() as u64
                    && attempt.text_sha256 == digest(goal.as_bytes()),
                "compute_task_plan_goal_copy_binding"
            );
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
