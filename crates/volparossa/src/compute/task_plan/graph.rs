//! Bounded model-selected task dependencies, never tools or execution authority.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{GRAPH_ARTIFACT_NAME, GRAPH_STRATEGY, Input, MAX_ARTIFACT_BYTES, digest, question};

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::compute) struct ModelTaskGraph {
    pub(in crate::compute) version: u32,
    pub(in crate::compute) tasks: Vec<ModelTask>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(in crate::compute) struct ModelTask {
    pub(in crate::compute) question: String,
    pub(in crate::compute) depends_on: Vec<usize>,
}

impl ModelTaskGraph {
    pub(in crate::compute) fn decode(raw: &[u8], goal: &str) -> Result<Self> {
        ensure!(
            raw.len() as u64 <= MAX_ARTIFACT_BYTES,
            "compute_task_graph_artifact_bound"
        );
        let graph: Self = serde_json::from_slice(raw)?;
        graph.validate(goal)?;
        Ok(graph)
    }

    pub(in crate::compute) fn validate(&self, goal: &str) -> Result<()> {
        ensure!(
            self.version == 3 && (1..=4).contains(&self.tasks.len()),
            "compute_task_graph_task_bound"
        );
        let mut questions = BTreeSet::new();
        for (index, task) in self.tasks.iter().enumerate() {
            question(&task.question)?;
            ensure!(
                task.question.trim_end().ends_with('?'),
                "compute_task_graph_not_a_question"
            );
            ensure!(
                task.question.as_bytes() != goal.as_bytes(),
                "compute_task_graph_goal_copy"
            );
            ensure!(
                questions.insert(task.question.trim()),
                "compute_task_graph_duplicate_question"
            );
            let mut dependencies = BTreeSet::new();
            ensure!(
                task.depends_on
                    .iter()
                    .all(|&parent| parent < index && dependencies.insert(parent)),
                "compute_task_graph_dependency"
            );
        }
        Ok(())
    }

    pub(in crate::compute) fn dependency_count(&self) -> usize {
        self.tasks.iter().map(|task| task.depends_on.len()).sum()
    }
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct GraphAttempt {
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

/// A validated failure trace is diagnostic data, not proof of a usable graph.
#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(in crate::compute) struct GraphDiagnostic {
    strategy: String,
    attempts: Vec<GraphAttempt>,
    incomplete_attempt: bool,
}

impl GraphDiagnostic {
    pub(super) fn from_value(value: &Value) -> Result<Self> {
        check_shape(&value["attempts"], 0)?;
        let diagnostic: Self = serde_json::from_value(value.clone())?;
        ensure!(
            diagnostic.strategy == GRAPH_STRATEGY,
            "compute_task_graph_strategy"
        );
        let summary = checked_attempts(&diagnostic.attempts)?;
        if diagnostic.incomplete_attempt {
            ensure!(
                diagnostic.attempts.len() < 4 && summary.accepted.is_none() && summary.tokens < 384,
                "compute_task_graph_incomplete_attempt"
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
        "compute_task_graph_attempt_shape"
    );
    Ok(())
}

struct Summary<'a> {
    accepted: Option<&'a GraphAttempt>,
    tokens: u64,
    prompt: u64,
}

fn checked_attempts(attempts: &[GraphAttempt]) -> Result<Summary<'_>> {
    ensure!(attempts.len() <= 4, "compute_task_graph_attempt_bound");
    let mut summary = Summary {
        accepted: None,
        tokens: 0,
        prompt: 0,
    };
    for (index, attempt) in attempts.iter().enumerate() {
        ensure!(
            summary.accepted.is_none()
                && summary.tokens < 384
                && attempt.attempt == index as u64 + 1
                && (1..=512).contains(&attempt.prompt_tokens)
                && attempt.max_new_tokens == 384 - summary.tokens
                && (1..=attempt.max_new_tokens).contains(&attempt.generated_tokens)
                && crate::compute::is_hex(&attempt.text_sha256, 64),
            "compute_task_graph_attempt_sequence_or_budget"
        );
        match attempt.stop_reason.as_str() {
            "token_limit" => ensure!(
                attempt.generated_tokens == attempt.max_new_tokens
                    && !attempt.accepted
                    && attempt.rejection_code.as_deref() == Some("GENERATION_LIMIT"),
                "compute_task_graph_limit_attempt"
            ),
            "graph_boundary" | "eos" => {
                if attempt.accepted {
                    ensure!(
                        attempt.rejection_code.is_none()
                            && (1..=MAX_ARTIFACT_BYTES).contains(&attempt.text_bytes),
                        "compute_task_graph_accepted_text"
                    );
                    summary.accepted = Some(attempt);
                } else {
                    ensure!(
                        attempt.rejection_code.as_deref() == Some("INVALID_GRAPH")
                            || (attempt.stop_reason == "eos"
                                && attempt.rejection_code.as_deref() == Some("INVALID_JSON")),
                        "compute_task_graph_rejection"
                    );
                }
            }
            _ => anyhow::bail!("compute_task_graph_attempt_stop"),
        }
        summary.tokens += attempt.generated_tokens;
        summary.prompt = summary.prompt.max(attempt.prompt_tokens);
    }
    Ok(summary)
}

/// Bind exact unmodified model JSON to its original input, execution and budget.
pub(in crate::compute) fn validate_graph_report(
    report: &Value,
    input: &Input,
    input_bytes: &[u8],
    artifact: &[u8],
) -> Result<ModelTaskGraph> {
    ensure!(
        Input::decode(input_bytes)? == *input && input.version == 3,
        "compute_task_graph_input_changed"
    );
    let graph = ModelTaskGraph::decode(artifact, &input.question)?;
    let excerpt = input
        .source_excerpt
        .as_ref()
        .context("compute_task_graph_source_required")?;
    ensure!(
        report["planner_strategy"] == GRAPH_STRATEGY
            && report["planner_structure_generated_by"] == "model"
            && report["planner_stop_reason"] == "task_graph"
            && report["planner_task_count"] == graph.tasks.len()
            && report["planner_dependency_count"] == graph.dependency_count()
            && report.get("planner_question_stats").is_none(),
        "compute_task_graph_strategy"
    );
    check_shape(&report["planner_attempts"], 1)?;
    let attempts: Vec<GraphAttempt> = serde_json::from_value(report["planner_attempts"].clone())?;
    let summary = checked_attempts(&attempts)?;
    let accepted = summary
        .accepted
        .context("compute_task_graph_no_accepted_attempt")?;
    ensure!(
        accepted.text_bytes == artifact.len() as u64
            && accepted.text_sha256 == digest(artifact)
            && report["planner_prompt_tokens"] == summary.prompt
            && report["planner_generated_tokens"] == summary.tokens,
        "compute_task_graph_attempt_artifact_binding"
    );
    ensure!(
        report["version"] == 1
            && report["kind"] == "result"
            && report["status"] == "ok"
            && report["mode"] == "plan_tasks"
            && report["id"]
                .as_str()
                .is_some_and(|id| crate::compute::is_hex(id, 32))
            && report["device"] == "cpu"
            && report["threads"]
                .as_u64()
                .is_some_and(|n| (1..=2).contains(&n))
            && report["updates_completed"] == 0
            && report["model_weights_loaded"] == true
            && report["goal_only_planning"] == false
            && report["source_contents_read_by_planner"] == true
            && report["source_excerpt_complete"] == (excerpt.end == input.source_bytes)
            && report["generation_limit_reached"] == false
            && report["model_answer_correctness_proven"] == false
            && report.get("outputs").is_none()
            && report.get("baseline_evaluation").is_none()
            && report.get("input_adapter").is_none(),
        "compute_task_graph_worker_result"
    );
    let profile = input.model_profile.spec();
    ensure!(
        report["model"]["id"] == profile.model_id
            && report["model"]["revision"] == profile.revision
            && report["model"]["files"]["model.safetensors"]["sha256"] == profile.weights_sha256
            && report["dataset"] == input.descriptor(input_bytes)
            && report["artifacts"]
                == json!([{"relative_path":GRAPH_ARTIFACT_NAME,"bytes":artifact.len(),"sha256":digest(artifact)}])
            && report["supervisor"]["child_reaped"] == true
            && report["supervisor"]["network_access"] == false,
        "compute_task_graph_worker_binding"
    );
    Ok(graph)
}

#[cfg(test)]
mod tests;
