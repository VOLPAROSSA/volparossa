//! Bounded model-selected task dependencies, never tools or execution authority.

use std::collections::BTreeSet;

use anyhow::{Context as _, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{
    CONSTRAINED_GRAPH_STRATEGY, GRAPH_ARTIFACT_NAME, GRAPH_STRATEGY, Input, MAX_ARTIFACT_BYTES,
    digest, question,
};

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

    pub(in crate::compute) fn validate_requirement(&self, input: &Input) -> Result<()> {
        self.validate(&input.question)?;
        ensure!(
            input.plan_requirement.is_none()
                || (self.tasks.len() >= 2 && self.dependency_count() > 0),
            "compute_task_graph_dependency_required"
        );
        Ok(())
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
    #[serde(default, skip_serializing_if = "Option::is_none")]
    planner_decoder: Option<Value>,
}

impl GraphDiagnostic {
    pub(super) fn from_value(value: &Value) -> Result<Self> {
        check_shape(&value["attempts"], 0)?;
        let diagnostic: Self = serde_json::from_value(value.clone())?;
        validate_decoder(&diagnostic.strategy, value.get("planner_decoder"))?;
        let summary = checked_attempts(&diagnostic.attempts, &diagnostic.strategy)?;
        if diagnostic.incomplete_attempt {
            ensure!(
                diagnostic.attempts.len() < 4 && summary.accepted.is_none() && summary.tokens < 384,
                "compute_task_graph_incomplete_attempt"
            );
        }
        Ok(diagnostic)
    }
}

/// A pinned decoder declaration does not replace graph, source or budget checks.
fn validate_decoder(strategy: &str, decoder: Option<&Value>) -> Result<()> {
    match strategy {
        GRAPH_STRATEGY => ensure!(decoder.is_none(), "compute_task_graph_legacy_decoder"),
        CONSTRAINED_GRAPH_STRATEGY => ensure!(
            decoder
                == Some(&json!({
                    "implementation":"lm-format-enforcer","version":"0.11.3",
                    "adapter_version":1,"schema_version":3,
                    "dependencies":{"interegular":"0.3.3","pydantic":"1.10.24"}
                })),
            "compute_task_graph_decoder"
        ),
        _ => anyhow::bail!("compute_task_graph_strategy"),
    }
    Ok(())
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

fn semantic_rejection(attempt: &GraphAttempt, strategy: &str) -> bool {
    let code = attempt.rejection_code.as_deref();
    // Older v1 and early constrained-v2 records used this generic category.
    // Their source-exact history remains readable; new workers emit fixed detail.
    if code == Some("INVALID_GRAPH") {
        return true;
    }
    if strategy != CONSTRAINED_GRAPH_STRATEGY {
        return false;
    }
    if code == Some("GRAPH_OUTPUT_TOO_LARGE") {
        // The online boundary checker never records an oversized JSON boundary.
        return attempt.stop_reason == "eos" && attempt.text_bytes > MAX_ARTIFACT_BYTES;
    }
    (1..=MAX_ARTIFACT_BYTES).contains(&attempt.text_bytes)
        && matches!(
            code,
            Some(
                "GRAPH_FIELDS"
                    | "GRAPH_TASK_COUNT"
                    | "GRAPH_TASK_FIELDS"
                    | "GRAPH_QUESTION_TEXT"
                    | "GRAPH_QUESTION_FORM"
                    | "GRAPH_GOAL_COPY"
                    | "GRAPH_DUPLICATE_QUESTION"
                    | "GRAPH_DEPENDENCIES"
                    | "GRAPH_DEPENDENCY_REQUIRED"
            )
        )
}

fn checked_attempts<'a>(attempts: &'a [GraphAttempt], strategy: &str) -> Result<Summary<'a>> {
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
                        semantic_rejection(attempt, strategy)
                            || (attempt.stop_reason == "eos"
                                && attempt.rejection_code.as_deref() == Some("INVALID_JSON")
                                && (strategy == GRAPH_STRATEGY
                                    || attempt.text_bytes <= MAX_ARTIFACT_BYTES)),
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
    graph.validate_requirement(input)?;
    let excerpt = input
        .source_excerpt
        .as_ref()
        .context("compute_task_graph_source_required")?;
    validate_decoder(
        report["planner_strategy"].as_str().unwrap_or_default(),
        report.get("planner_decoder"),
    )?;
    ensure!(
        report["planner_structure_generated_by"] == "model"
            && report["planner_stop_reason"] == "task_graph"
            && report["planner_task_count"] == graph.tasks.len()
            && report["planner_dependency_count"] == graph.dependency_count()
            && report.get("planner_question_stats").is_none(),
        "compute_task_graph_strategy"
    );
    check_shape(&report["planner_attempts"], 1)?;
    let attempts: Vec<GraphAttempt> = serde_json::from_value(report["planner_attempts"].clone())?;
    let summary = checked_attempts(
        &attempts,
        report["planner_strategy"].as_str().unwrap_or_default(),
    )?;
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
