//! Pure protocol fixtures, not evidence of real model generation or cleanup.

use super::*;
use serde_json::json;

fn fixture() -> (Value, Questions) {
    let questions = Questions {
        version: 1,
        questions: vec![
            "What are the opportunities?".into(),
            "What are the constraints?".into(),
        ],
    };
    let accepted = |index: usize, attempt, prompt, generated| {
        json!({
            "question_index":index,"attempt":attempt,"prompt_tokens":prompt,
            "generated_tokens":generated,"max_new_tokens":192,"stop_reason":"question_boundary",
            "accepted":true,"rejection_code":null,"text_bytes":questions.questions[index].len(),
            "text_sha256":digest(questions.questions[index].as_bytes())
        })
    };
    let report = json!({
        "planner_strategy":STRATEGY,"planner_structure_generated_by":"local_schema",
        "planner_stop_reason":"two_questions","planner_prompt_tokens":512,"planner_generated_tokens":47,
        "planner_question_stats":[
            {"prompt_tokens":40,"generated_tokens":10,"stop_reason":"question_boundary"},
            {"prompt_tokens":96,"generated_tokens":20,"stop_reason":"question_boundary"}],
        "planner_attempts":[accepted(0, 1, 40, 10),
            {"question_index":1,"attempt":2,"prompt_tokens":512,"generated_tokens":17,
             "max_new_tokens":192,"stop_reason":"eos","accepted":false,
             "rejection_code":"TEXT_TOO_LONG","text_bytes":600,"text_sha256":digest(&[b'x';600])},
            accepted(1, 3, 96, 20)]
    });
    (report, questions)
}

fn check(report: &Value, questions: &Questions) -> Result<()> {
    super::super::validate_question_stats(report, questions)
}

#[test]
fn recovery_charges_rejected_tokens_and_prompts_and_binds_accepted_text_exactly() {
    let (report, questions) = fixture();
    check(&report, &questions).unwrap();
    for pointer in [
        "/planner_generated_tokens",
        "/planner_prompt_tokens",
        "/planner_attempts/2/attempt",
        "/planner_attempts/2/question_index",
        "/planner_attempts/2/text_bytes",
        "/planner_attempts/2/generated_tokens",
        "/planner_question_stats/1/prompt_tokens",
    ] {
        let mut changed = report.clone();
        *changed.pointer_mut(pointer).unwrap() = 0.into();
        assert!(check(&changed, &questions).is_err(), "{pointer}");
    }
    let mut changed = report.clone();
    changed["planner_attempts"][2]["text_sha256"] = digest(b"Different question?").into();
    assert!(check(&changed, &questions).is_err());
    let mut changed = questions.clone();
    changed.questions[1].push(' ');
    assert!(check(&report, &changed).is_err());
}

#[test]
fn later_attempt_cap_is_remaining_original_budget_not_a_new_budget() {
    let (mut report, questions) = fixture();
    let mut first = report["planner_attempts"][1].clone();
    first["question_index"] = 0.into();
    first["attempt"] = 1.into();
    first["generated_tokens"] = 192.into();
    first["stop_reason"] = "token_limit".into();
    first["rejection_code"] = "GENERATION_LIMIT".into();
    report["planner_attempts"][0]["attempt"] = 2.into();
    report["planner_attempts"][2]["max_new_tokens"] = 182.into();
    report["planner_attempts"] = json!([
        first,
        report["planner_attempts"][0],
        report["planner_attempts"][2]
    ]);
    report["planner_generated_tokens"] = 222.into();
    check(&report, &questions).unwrap();
    report["planner_attempts"][2]["max_new_tokens"] = 192.into();
    assert!(check(&report, &questions).is_err());
}

#[test]
fn traces_require_exact_fields_and_real_stop_categories() {
    let (report, questions) = fixture();
    for (pointer, value) in [
        ("/planner_attempts/0/rejection_code", json!("EMPTY_TEXT")),
        ("/planner_attempts/1/rejection_code", json!("INVENTED_TEXT")),
        (
            "/planner_attempts/1/stop_reason",
            json!("question_boundary"),
        ),
        ("/planner_attempts/1/text_bytes", json!(512)),
        ("/planner_attempts/0/generated_tokens", json!(192)),
        ("/planner_attempts/0/accepted", json!(false)),
        ("/planner_attempts/0/text_sha256", json!("AB".repeat(32))),
    ] {
        let mut changed = report.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(check(&changed, &questions).is_err(), "{pointer}");
    }
    let mut changed = report.clone();
    changed["planner_attempts"][0]
        .as_object_mut()
        .unwrap()
        .remove("rejection_code");
    assert!(check(&changed, &questions).is_err());
    let mut changed = report.clone();
    changed["planner_attempts"][0]["raw_text"] = "No diagnostic payload".into();
    assert!(check(&changed, &questions).is_err());
    let mut changed = report.clone();
    changed["planner_strategy"] = "model_questions_scaffold_v1".into();
    assert!(check(&changed, &questions).is_err());
}

#[test]
fn failure_trace_may_be_incomplete_but_cannot_invent_completed_costs() {
    let (report, _) = fixture();
    let mut diagnostic = json!({"strategy":STRATEGY,
        "attempts":[report["planner_attempts"][0]],"incomplete_attempt":true});
    let checked = PlanningDiagnostic::from_value(&diagnostic).unwrap();
    assert_eq!(serde_json::to_value(checked).unwrap(), diagnostic);
    diagnostic["attempts"] = report["planner_attempts"].clone();
    assert!(PlanningDiagnostic::from_value(&diagnostic).is_err());
    diagnostic["incomplete_attempt"] = false.into();
    PlanningDiagnostic::from_value(&diagnostic).unwrap();
    diagnostic["attempts"] = json!([]);
    diagnostic["incomplete_attempt"] = true.into();
    PlanningDiagnostic::from_value(&diagnostic).unwrap();
    diagnostic["attempts"] = Value::Array(vec![report["planner_attempts"][0].clone(); 5]);
    assert!(PlanningDiagnostic::from_value(&diagnostic).is_err());
}

#[test]
fn nonquestion_retry_requires_source_strategy_and_is_charged_without_renewal() {
    let (mut report, mut questions) = fixture();
    report["planner_strategy"] = SOURCE_STRATEGY.into();
    questions.version = 2;
    report["planner_attempts"][1]["rejection_code"] = "NOT_A_QUESTION".into();
    report["planner_attempts"][1]["text_bytes"] = 90.into();
    check(&report, &questions).unwrap();
    let diagnostic = json!({"strategy":SOURCE_STRATEGY,
        "attempts":report["planner_attempts"],"incomplete_attempt":false});
    PlanningDiagnostic::from_value(&diagnostic).unwrap();
    let mut old = diagnostic.clone();
    old["strategy"] = STRATEGY.into();
    assert!(PlanningDiagnostic::from_value(&old).is_err());
    for replacement in [json!("question_boundary"), json!("token_limit")] {
        let mut changed = diagnostic.clone();
        changed["attempts"][1]["stop_reason"] = replacement;
        assert!(PlanningDiagnostic::from_value(&changed).is_err());
    }
    report["planner_generated_tokens"] = 30.into(); // The rejected generation still costs 17.
    assert!(check(&report, &questions).is_err());
}
