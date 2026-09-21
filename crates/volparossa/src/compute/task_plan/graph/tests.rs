//! Inert protocol/retention fixtures, not evidence of model-selected execution.

use super::*;
use crate::compute::ModelProfile;
use crate::compute::task_plan::{PlanningDiagnostic, Questions, SourceExcerpt};

fn input() -> Input {
    let source = "An explicitly public project describes its requirements and risks.";
    Input {
        version: 3,
        model_profile: ModelProfile::Smol360,
        visibility: "public".into(),
        license: "CC0-1.0".into(),
        question: "How do these public requirements relate to their risks?".into(),
        source_sha256: digest(source.as_bytes()),
        source_bytes: source.len() as u64,
        source_excerpt: Some(SourceExcerpt::prefix(source)),
    }
}

fn artifact() -> Vec<u8> {
    br#"{ "version":3, "tasks":[
        {"question":"What is required?","depends_on":[]},
        {"question":"What risks are described?","depends_on":[]},
        {"question":"Which requirements address which risks?","depends_on":[0,1]}] }"#
        .to_vec()
}

fn attempt(raw: &[u8], accepted: bool, code: Option<&str>) -> Value {
    json!({"attempt":1,"prompt_tokens":200,"generated_tokens":100,"max_new_tokens":384,
        "stop_reason":"graph_boundary","accepted":accepted,"rejection_code":code,
        "text_bytes":raw.len(),"text_sha256":digest(raw)})
}

fn report(input: &Input, input_bytes: &[u8], raw: &[u8]) -> Value {
    let graph = ModelTaskGraph::decode(raw, &input.question).unwrap();
    let profile = input.model_profile.spec();
    json!({
        "version":1,"id":"ab".repeat(16),"kind":"result","status":"ok","mode":"plan_tasks",
        "device":"cpu","threads":2,"updates_completed":0,"model_weights_loaded":true,
        "goal_only_planning":false,"source_contents_read_by_planner":true,"source_excerpt_complete":true,
        "generation_limit_reached":false,"model_answer_correctness_proven":false,
        "planner_strategy":GRAPH_STRATEGY,"planner_structure_generated_by":"model","planner_stop_reason":"task_graph",
        "planner_task_count":graph.tasks.len(),"planner_dependency_count":graph.dependency_count(),
        "planner_prompt_tokens":200,"planner_generated_tokens":100,
        "planner_attempts":[attempt(raw,true,None)],
        "model":{"id":profile.model_id,"revision":profile.revision,
            "files":{"model.safetensors":{"bytes":profile.weights_bytes,"sha256":profile.weights_sha256}}},
        "dataset":input.descriptor(input_bytes),
        "artifacts":[{"relative_path":GRAPH_ARTIFACT_NAME,"bytes":raw.len(),"sha256":digest(raw)}],
        "supervisor":{"child_reaped":true,"network_access":false}
    })
}

#[test]
fn model_graph_preserves_selected_edges_and_rejects_hidden_or_invalid_work() {
    let goal = input().question;
    let graph = ModelTaskGraph::decode(&artifact(), &goal).unwrap();
    assert_eq!(graph.tasks.len(), 3);
    assert_eq!(graph.tasks[2].depends_on, [0, 1]);
    assert_eq!(graph.dependency_count(), 2);
    for count in [1, 4] {
        let value = json!({"version":3,"tasks":(0..count).map(|index| {
            json!({"question":format!("Question {index}?"),"depends_on":(0..index).collect::<Vec<_>>()})
        }).collect::<Vec<_>>()});
        ModelTaskGraph::decode(&serde_json::to_vec(&value).unwrap(), &goal).unwrap();
    }
    let original = serde_json::to_value(&graph).unwrap();
    for (pointer, value) in [
        ("/version", json!(2)),
        ("/tasks", json!([])),
        ("/tasks/0/question", json!(&goal)),
        ("/tasks/0/question", json!("A statement.")),
        ("/tasks/0/question", json!("\0?")),
        ("/tasks/0/question", json!("é".repeat(256) + "?")),
        ("/tasks/1/question", json!(" What is required? ")),
        ("/tasks/0/depends_on", json!([0])),
        ("/tasks/0/depends_on", json!([1])),
        ("/tasks/2/depends_on", json!([0, 0])),
        ("/tasks/2/depends_on", json!([3])),
        ("/tasks/2/depends_on", json!([-1])),
        ("/tasks/2/depends_on", json!([true])),
    ] {
        let mut changed = original.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            ModelTaskGraph::decode(&serde_json::to_vec(&changed).unwrap(), &goal).is_err(),
            "{pointer}"
        );
    }
    for raw in [
        br#"{"version":3,"version":3,"tasks":[]}"#.as_slice(),
        br#"{"version":3,"tasks":[{"question":"Q?","depends_on":[],"tool":"shell"}]}"#,
        br#"```json {"version":3,"tasks":[]} ```"#,
        br#"{"version":3,"tasks":[{"question":"Q?","depends_on":[]}]} trailing"#,
    ] {
        assert!(ModelTaskGraph::decode(raw, &goal).is_err());
    }
    let mut changed = graph;
    changed.tasks = vec![changed.tasks[0].clone(); 5];
    assert!(changed.validate(&goal).is_err());
}

#[test]
fn graph_mode_requires_opt_in_but_retains_exact_source_and_raw_artifact() {
    let input = input();
    let bytes = serde_json::to_vec(&input).unwrap();
    assert_eq!(Input::decode(&bytes).unwrap(), input);
    input.validate_execution().unwrap();
    let raw = artifact();
    let report = report(&input, &bytes, &raw);
    let graph = validate_graph_report(&report, &input, &bytes, &raw).unwrap();
    assert!(Questions::decode(&raw).is_err());
    assert!(super::super::validate_report(&report, &input, &bytes, &raw).is_err());
    let canonical = serde_json::to_vec(&graph).unwrap();
    assert_ne!(canonical, raw);
    assert!(validate_graph_report(&report, &input, &bytes, &canonical).is_err());
    let mut legacy = input.clone();
    legacy.version = 2;
    let legacy_bytes = serde_json::to_vec(&legacy).unwrap();
    assert!(validate_graph_report(&report, &legacy, &legacy_bytes, &raw).is_err());
    let mut missing = input.clone();
    missing.source_excerpt = None;
    assert!(missing.validate_execution().is_err());
    for (pointer, value) in [
        ("/planner_task_count", json!(2)),
        ("/planner_dependency_count", json!(0)),
        ("/planner_structure_generated_by", json!("local_schema")),
        ("/planner_strategy", json!(super::super::CURRENT_STRATEGY)),
        ("/dataset/source_excerpt/sha256", json!("b".repeat(64))),
        ("/model/revision", json!("b".repeat(40))),
        ("/supervisor/child_reaped", json!(false)),
        ("/source_contents_read_by_planner", json!(false)),
        ("/artifacts/0/relative_path", json!("task-questions.json")),
        ("/planner_attempts/0/text_sha256", json!("b".repeat(64))),
    ] {
        let mut changed = report.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            validate_graph_report(&changed, &input, &bytes, &raw).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn graph_recovery_charges_prior_rejections_and_accepts_a_real_boundary_at_remaining_cap() {
    let input = input();
    let bytes = serde_json::to_vec(&input).unwrap();
    let raw = artifact();
    let mut report = report(&input, &bytes, &raw);
    let mut rejected = attempt(b"not json", false, Some("INVALID_JSON"));
    rejected["stop_reason"] = "eos".into();
    rejected["generated_tokens"] = 27.into();
    let mut accepted = report["planner_attempts"][0].clone();
    accepted["attempt"] = 2.into();
    accepted["max_new_tokens"] = 357.into();
    accepted["generated_tokens"] = 357.into();
    report["planner_generated_tokens"] = 384.into();
    report["planner_attempts"] = json!([rejected, accepted]);
    for stop in ["eos", "graph_boundary"] {
        report["planner_attempts"][1]["stop_reason"] = stop.into();
        validate_graph_report(&report, &input, &bytes, &raw).unwrap();
    }
    for (pointer, value) in [
        ("/planner_generated_tokens", json!(357)),
        ("/planner_attempts/1/max_new_tokens", json!(384)),
        ("/planner_attempts/1/generated_tokens", json!(358)),
        ("/planner_attempts/1/stop_reason", json!("token_limit")),
        ("/planner_attempts/0/stop_reason", json!("graph_boundary")),
        ("/planner_attempts/0/rejection_code", json!("GOAL_COPY")),
    ] {
        let mut changed = report.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            validate_graph_report(&changed, &input, &bytes, &raw).is_err(),
            "{pointer}"
        );
    }
    let mut followed = report.clone();
    followed["planner_attempts"]
        .as_array_mut()
        .unwrap()
        .push(accepted);
    assert!(validate_graph_report(&followed, &input, &bytes, &raw).is_err());
    report["planner_attempts"][0]["question_index"] = 0.into();
    assert!(validate_graph_report(&report, &input, &bytes, &raw).is_err());
}

#[test]
fn graph_failure_diagnostics_preserve_shape_without_creating_graph_authority() {
    let mut rejected = attempt(b"{}", false, Some("INVALID_GRAPH"));
    let mut diagnostic =
        json!({"strategy":GRAPH_STRATEGY,"attempts":[rejected],"incomplete_attempt":true});
    let checked = PlanningDiagnostic::from_value(&diagnostic).unwrap();
    assert_eq!(serde_json::to_value(checked).unwrap(), diagnostic);
    rejected["generated_tokens"] = 384.into();
    rejected["stop_reason"] = "token_limit".into();
    rejected["rejection_code"] = "GENERATION_LIMIT".into();
    diagnostic["attempts"] = json!([rejected]);
    assert!(PlanningDiagnostic::from_value(&diagnostic).is_err());
    diagnostic["incomplete_attempt"] = false.into();
    PlanningDiagnostic::from_value(&diagnostic).unwrap();
    diagnostic["attempts"] = json!([attempt(&artifact(), true, None)]);
    PlanningDiagnostic::from_value(&diagnostic).unwrap(); // Later I/O/integrity failure is still possible.
    diagnostic["incomplete_attempt"] = true.into();
    assert!(PlanningDiagnostic::from_value(&diagnostic).is_err());
    diagnostic["attempts"] = json!([]);
    PlanningDiagnostic::from_value(&diagnostic).unwrap();
    diagnostic["attempts"] = json!([attempt(b"{}", false, Some("INVALID_GRAPH"))]);
    diagnostic["attempts"][0]
        .as_object_mut()
        .unwrap()
        .remove("rejection_code");
    assert!(PlanningDiagnostic::from_value(&diagnostic).is_err());
}

fn decoder() -> Value {
    json!({"implementation":"lm-format-enforcer","version":"0.11.3",
        "adapter_version":1,"schema_version":3,
        "dependencies":{"interegular":"0.3.3","pydantic":"1.10.24"}})
}

#[test]
fn constrained_graph_pins_decoder_without_changing_raw_graph_or_original_budget() {
    let input = input();
    let bytes = serde_json::to_vec(&input).unwrap();
    let raw = artifact();
    let legacy = report(&input, &bytes, &raw);
    let expected = validate_graph_report(&legacy, &input, &bytes, &raw).unwrap();
    let mut current = legacy.clone();
    current["planner_strategy"] = CONSTRAINED_GRAPH_STRATEGY.into();
    assert!(validate_graph_report(&current, &input, &bytes, &raw).is_err());
    current["planner_decoder"] = decoder();
    assert_eq!(
        validate_graph_report(&current, &input, &bytes, &raw).unwrap(),
        expected
    );
    for (pointer, replacement) in [
        ("/planner_decoder", Value::Null),
        ("/planner_decoder/version", json!("0.11.2")),
        ("/planner_decoder/adapter_version", json!(2)),
        ("/planner_decoder/schema_version", json!(2)),
        ("/planner_decoder/dependencies/interegular", json!("0.3.2")),
        ("/planner_decoder/dependencies/pydantic", json!("2.0.0")),
        ("/planner_attempts/0/max_new_tokens", json!(512)),
        ("/planner_attempts/0/generated_tokens", json!(385)),
        ("/planner_attempts/0/prompt_tokens", json!(513)),
        ("/planner_attempts/0/text_sha256", json!("f".repeat(64))),
        ("/planner_structure_generated_by", json!("local_schema")),
    ] {
        let mut changed = current.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            validate_graph_report(&changed, &input, &bytes, &raw).is_err(),
            "{pointer}"
        );
    }
    let mut extra = current.clone();
    extra["planner_decoder"]["fallback"] = true.into();
    assert!(validate_graph_report(&extra, &input, &bytes, &raw).is_err());
    for claim in [decoder(), Value::Null] {
        let mut changed = legacy.clone();
        changed["planner_decoder"] = claim;
        assert!(validate_graph_report(&changed, &input, &bytes, &raw).is_err());
    }
    let mut copied = serde_json::from_slice::<Value>(&raw).unwrap();
    copied["tasks"][0]["question"] = input.question.clone().into();
    assert!(
        ModelTaskGraph::decode(&serde_json::to_vec(&copied).unwrap(), &input.question).is_err()
    );
}

#[test]
fn constrained_graph_diagnostic_requires_decoder_and_preserves_legacy_shape() {
    let legacy = json!({"strategy":GRAPH_STRATEGY,
        "attempts":[attempt(b"{}",false,Some("INVALID_GRAPH"))],"incomplete_attempt":true});
    let checked = PlanningDiagnostic::from_value(&legacy).unwrap();
    assert_eq!(serde_json::to_value(checked).unwrap(), legacy);
    let mut current = legacy.clone();
    current["strategy"] = CONSTRAINED_GRAPH_STRATEGY.into();
    assert!(PlanningDiagnostic::from_value(&current).is_err());
    current["planner_decoder"] = decoder();
    let checked = PlanningDiagnostic::from_value(&current).unwrap();
    assert_eq!(serde_json::to_value(checked).unwrap(), current);
    for (pointer, replacement) in [
        ("/planner_decoder", Value::Null),
        ("/planner_decoder/implementation", json!("unknown")),
        ("/planner_decoder/dependencies", json!({})),
        ("/strategy", json!(GRAPH_STRATEGY)),
        ("/attempts/0/max_new_tokens", json!(512)),
        ("/attempts/0/prompt_tokens", json!(513)),
    ] {
        let mut changed = current.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            PlanningDiagnostic::from_value(&changed).is_err(),
            "{pointer}"
        );
    }
    current["attempts"] = json!([]);
    PlanningDiagnostic::from_value(&current).unwrap();
    let mut changed = legacy;
    changed["planner_decoder"] = Value::Null;
    assert!(PlanningDiagnostic::from_value(&changed).is_err());
}
