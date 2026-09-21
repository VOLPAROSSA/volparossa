use super::*;
use crate::compute::ModelProfile;

fn input() -> Input {
    Input {
        model_profile: ModelProfile::default(),
        version: 1,
        visibility: "public".into(),
        license: "GPL-3.0-only".into(),
        question: "Compare the public requirements and their risks.".into(),
        source_sha256: "a".repeat(64),
        source_bytes: 128,
        source_excerpt: None,
    }
}

#[test]
fn task_input_requires_explicit_public_source_and_original_question() {
    let input = input();
    let bytes = serde_json::to_vec(&input).unwrap();
    assert_eq!(Input::decode(&bytes).unwrap(), input);
    // Legacy receipts stay readable, but goal-only inputs cannot start new work.
    assert!(
        crate::compute::validate_dataset(super::super::Mode::PlanTasks, false, &bytes).is_err()
    );
    assert!(crate::compute::validate_dataset(super::super::Mode::PlanTasks, true, &bytes).is_err());
    let original = serde_json::to_value(&input).unwrap();
    for (key, value) in [
        ("visibility", json!("private")),
        ("license", json!("invented")),
        ("question", json!(" \n")),
        ("question", json!("x\0y")),
        ("question", json!("é".repeat(257))),
        ("source_sha256", json!("0".repeat(64))),
        ("source_sha256", json!("A".repeat(64))),
        ("source_bytes", json!(0)),
        ("source_bytes", json!(1_048_577)),
        ("tool", json!("not execution authority")),
    ] {
        let mut changed = original.clone();
        changed[key] = value;
        assert!(
            Input::decode(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "{key}"
        );
    }
    let repeated = serde_json::to_string(&input)
        .unwrap()
        .replace("\"version\":1", "\"version\":1,\"version\":1");
    assert!(Input::decode(repeated.as_bytes()).is_err());
}

#[test]
fn generated_questions_are_bounded_data_not_a_repaired_or_executable_plan() {
    let questions = br#"{"version":1,"questions":["What is required?","What are the risks?"]}"#;
    assert_eq!(Questions::decode(questions).unwrap().questions.len(), 2);
    for invalid in [
        br#"{"version":1,"questions":["One?"]}"#.as_slice(),
        br#"{"version":1,"questions":["Same?"," Same? "]}"#,
        br#"{"version":1,"questions":["What?","Why?"],"command":"not allowed"}"#,
        br#"{"version":1,"version":1,"questions":["What?","Why?"]}"#,
        br#"{"version":1,"questions":["What?","Why?"]} trailing text"#,
        b"```json\n{\"version\":1,\"questions\":[\"What?\",\"Why?\"]}\n```",
    ] {
        assert!(Questions::decode(invalid).is_err());
    }
    for count in [0, 1, 5] {
        let value = json!({"version":1,"questions":(0..count).map(|n| format!("Question {n}?")).collect::<Vec<_>>()});
        assert!(Questions::decode(&serde_json::to_vec(&value).unwrap()).is_err());
    }
}

#[test]
fn grounded_execution_requires_exact_bounded_utf8_source_excerpt() {
    let source = format!("{}é末", "a".repeat(1023));
    let excerpt = SourceExcerpt::prefix(&source);
    assert_eq!(excerpt.end, 1023);
    assert_eq!(excerpt.text, "a".repeat(1023));
    let mut grounded = input();
    grounded.version = 2;
    grounded.source_sha256 = digest(source.as_bytes());
    grounded.source_bytes = source.len() as u64;
    grounded.source_excerpt = Some(excerpt);
    let value = serde_json::to_value(&grounded).unwrap();
    let bytes = serde_json::to_vec(&grounded).unwrap();
    crate::compute::validate_dataset(super::super::Mode::PlanTasks, false, &bytes).unwrap();
    for (pointer, replacement) in [
        ("/version", json!(1)),
        ("/source_excerpt", json!(null)),
        ("/source_excerpt/start", json!(1)),
        ("/source_excerpt/end", json!(1024)),
        ("/source_excerpt/text", json!("Unrelated source")),
        ("/source_excerpt/sha256", json!("a".repeat(64))),
        ("/source_bytes", json!(1)),
    ] {
        let mut changed = value.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            Input::decode(&serde_json::to_vec(&changed).unwrap()).is_err(),
            "{pointer}"
        );
    }
    grounded.source_bytes = 1023;
    assert!(grounded.validate_execution().is_err()); // Now full coverage, but wrong full hash.
    grounded.source_sha256 = digest(grounded.source_excerpt.as_ref().unwrap().text.as_bytes());
    grounded.validate_execution().unwrap();
    for source in [String::new(), "\0".into(), "x".repeat(1025)] {
        let mut excerpt = SourceExcerpt::prefix(&source);
        // Validate the hard bound independently of the safe prefix constructor.
        excerpt.text = source.clone();
        excerpt.end = source.len() as u64;
        excerpt.sha256 = digest(source.as_bytes());
        grounded.source_bytes = source.len().max(1) as u64;
        grounded.source_sha256 = digest(source.as_bytes());
        grounded.source_excerpt = Some(excerpt);
        assert!(grounded.validate_execution().is_err());
    }
}

fn grounded_report() -> (Input, Vec<u8>, Questions, Vec<u8>, Value) {
    let source = "An explicitly public source for an inert validation fixture.";
    let mut input = input();
    input.version = 2;
    input.source_bytes = source.len() as u64;
    input.source_sha256 = digest(source.as_bytes());
    input.source_excerpt = Some(SourceExcerpt::prefix(source));
    let bytes = serde_json::to_vec(&input).unwrap();
    let questions = Questions {
        version: 2,
        questions: vec![
            "What is required?".into(),
            "What constraints are stated?".into(),
        ],
    };
    let artifact = serde_json::to_vec(&questions).unwrap();
    let attempts: Vec<_> = questions
        .questions
        .iter()
        .enumerate()
        .map(|(index, text)| {
            json!({
                "question_index":index,"attempt":index+1,"prompt_tokens":100,"generated_tokens":20,
                "max_new_tokens":192,"stop_reason":"eos","accepted":true,"rejection_code":null,
                "text_bytes":text.len(),"text_sha256":digest(text.as_bytes())
            })
        })
        .collect();
    let report = json!({
        "version":1,"id":"ab".repeat(16),"kind":"result","status":"ok","mode":"plan_tasks",
        "device":"cpu","threads":2,"updates_completed":0,"model_weights_loaded":true,
        "goal_only_planning":false,"source_contents_read_by_planner":true,"source_excerpt_complete":true,
        "generation_limit_reached":false,"model_answer_correctness_proven":false,
        "planner_prompt_tokens":100,"planner_generated_tokens":40,"planner_stop_reason":"two_questions",
        "planner_strategy":recovery::SOURCE_STRATEGY,"planner_structure_generated_by":"local_schema",
        "planner_question_stats":[
            {"prompt_tokens":100,"generated_tokens":20,"stop_reason":"eos"},
            {"prompt_tokens":100,"generated_tokens":20,"stop_reason":"eos"}],
        "planner_attempts":attempts,
        "model":{"id":MODEL_ID,"revision":MODEL_REVISION,"files":{"model.safetensors":{"sha256":hex::encode(BASE_MODEL_SHA256)}}},
        "dataset":input.descriptor(&bytes),
        "artifacts":[{"relative_path":"task-questions.json","bytes":artifact.len(),"sha256":digest(&artifact)}],
        "supervisor":{"child_reaped":true,"network_access":false}
    });
    (input, bytes, questions, artifact, report)
}

#[test]
fn grounded_report_binds_actual_excerpt_and_never_accepts_eos_prose_as_a_question() {
    let (input, bytes, questions, artifact, report) = grounded_report();
    validate_report(&report, &input, &bytes, &artifact).unwrap();
    for (pointer, replacement) in [
        ("/goal_only_planning", json!(true)),
        ("/source_contents_read_by_planner", json!(false)),
        ("/source_excerpt_complete", json!(false)),
        ("/dataset/source_excerpt/end", json!(0)),
        ("/dataset/source_excerpt/sha256", json!("b".repeat(64))),
        ("/dataset/version", json!(1)),
        ("/planner_strategy", json!(recovery::STRATEGY)),
    ] {
        let mut changed = report.clone();
        *changed.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            validate_report(&changed, &input, &bytes, &artifact).is_err(),
            "{pointer}"
        );
    }
    let mut prose = questions;
    prose.questions[0] = "An unrelated statement, not a question.".into();
    assert!(prose.validate().is_err());
    assert!(validate_question_stats(&report, &prose).is_err());
    // Reading an old result must not retroactively label it source-grounded.
    prose.version = 1;
    prose.validate().unwrap();
    assert!(validate_question_stats(&report, &prose).is_err());
}

#[test]
fn v4_rejects_literal_goal_copies_without_reinterpreting_v3_history() {
    let (mut input, _, questions, artifact, mut report) = grounded_report();
    input.question.clone_from(&questions.questions[0]);
    let bytes = serde_json::to_vec(&input).unwrap();
    report["dataset"] = input.descriptor(&bytes);
    let historical = serde_json::to_vec(&report).unwrap();
    validate_report(&report, &input, &bytes, &artifact).unwrap();
    report["planner_strategy"] = CURRENT_STRATEGY.into();
    assert_eq!(
        validate_report(&report, &input, &bytes, &artifact)
            .unwrap_err()
            .to_string(),
        "compute_task_plan_goal_copy"
    );
    // Exact means exact UTF-8 bytes: no new normalization or inferred semantic equivalence.
    input.question = format!(" {}", input.question);
    let bytes = serde_json::to_vec(&input).unwrap();
    report["dataset"] = input.descriptor(&bytes);
    validate_report(&report, &input, &bytes, &artifact).unwrap();
    let saved: Value = serde_json::from_slice(&historical).unwrap();
    assert_eq!(saved["planner_strategy"], recovery::SOURCE_STRATEGY);
}

#[test]
fn v4_binds_charged_rejected_goal_copy_to_the_original_question() {
    let (mut input, _, _, artifact, mut report) = grounded_report();
    input.question = "What requirements and risks does this public source describe?".into();
    let bytes = serde_json::to_vec(&input).unwrap();
    report["dataset"] = input.descriptor(&bytes);
    report["planner_strategy"] = CURRENT_STRATEGY.into();
    let mut attempts = report["planner_attempts"].as_array().unwrap().clone();
    attempts[0]["attempt"] = 2.into();
    attempts[1]["attempt"] = 3.into();
    let rejected = json!({"question_index":0,"attempt":1,"prompt_tokens":100,"generated_tokens":9,
        "max_new_tokens":192,"stop_reason":"eos","accepted":false,"rejection_code":"GOAL_COPY",
        "text_bytes":input.question.len(),"text_sha256":digest(input.question.as_bytes())});
    attempts.insert(0, rejected);
    report["planner_attempts"] = attempts.into();
    report["planner_generated_tokens"] = 49.into();
    validate_report(&report, &input, &bytes, &artifact).unwrap();
    for (pointer, value) in [
        (
            "/planner_attempts/0/text_sha256",
            json!(digest(b"Different text?")),
        ),
        ("/planner_attempts/0/text_bytes", json!(1)),
        ("/planner_generated_tokens", json!(40)),
        ("/planner_strategy", json!(recovery::SOURCE_STRATEGY)),
    ] {
        let mut changed = report.clone();
        *changed.pointer_mut(pointer).unwrap() = value;
        assert!(
            validate_report(&changed, &input, &bytes, &artifact).is_err(),
            "{pointer}"
        );
    }
}

#[test]
fn retained_planner_report_binds_original_input_artifact_model_and_cleanup() {
    // Inert parser fixture only. No model is loaded and no execution proof is claimed.
    let input = input();
    let bytes = serde_json::to_vec(&input).unwrap();
    let artifact = br#"{"version":1,"questions":["What is required?","What are the risks?"]}"#;
    let report = json!({
        "version":1,"id":"ab".repeat(16),"kind":"result","status":"ok","mode":"plan_tasks",
        "device":"cpu","threads":2,"updates_completed":0,"model_weights_loaded":true,
        "goal_only_planning":true,"generation_limit_reached":false,"model_answer_correctness_proven":false,
        "planner_prompt_tokens":100,"planner_generated_tokens":40,"planner_stop_reason":"two_questions",
        "planner_strategy":"model_questions_scaffold_v1","planner_structure_generated_by":"local_schema",
        "planner_question_stats":[
            {"prompt_tokens":80,"generated_tokens":20,"stop_reason":"question_boundary"},
            {"prompt_tokens":100,"generated_tokens":20,"stop_reason":"eos"}],
        "model":{"id":MODEL_ID,"revision":MODEL_REVISION,"files":{"model.safetensors":{"sha256":hex::encode(BASE_MODEL_SHA256)}}},
        "dataset":{"version":1,"sha256":digest(&bytes),"bytes":bytes.len(),"visibility":"public","license":input.license,
            "question_sha256":digest(input.question.as_bytes()),"source_sha256":input.source_sha256,"source_bytes":input.source_bytes},
        "artifacts":[{"relative_path":"task-questions.json","bytes":artifact.len(),"sha256":digest(artifact)}],
        "supervisor":{"child_reaped":true,"network_access":false}
    });
    validate_report(&report, &input, &bytes, artifact).unwrap();
    let mut question_boundary = report.clone();
    question_boundary["planner_question_stats"][1]["stop_reason"] = json!("question_boundary");
    validate_report(&question_boundary, &input, &bytes, artifact).unwrap();
    let mut unchanged_text = Questions::decode(artifact).unwrap();
    unchanged_text.questions[0].push_str(" \n");
    validate_question_stats(&question_boundary, &unchanged_text).unwrap();
    unchanged_text.questions[0].push_str("continuation");
    assert!(validate_question_stats(&question_boundary, &unchanged_text).is_err());
    for (path, value) in [
        ("/mode", json!("infer")),
        ("/updates_completed", json!(1)),
        ("/model_weights_loaded", json!(false)),
        ("/goal_only_planning", json!(false)),
        ("/generation_limit_reached", json!(true)),
        ("/planner_stop_reason", json!("length")),
        ("/planner_stop_reason", json!(null)),
        ("/planner_generated_tokens", json!(384)),
        ("/planner_prompt_tokens", json!(513)),
        ("/planner_generated_tokens", json!(39)),
        ("/planner_prompt_tokens", json!(99)),
        ("/planner_strategy", json!("whole_json")),
        ("/planner_structure_generated_by", json!("model")),
        ("/planner_question_stats", json!([])),
        ("/planner_question_stats/0/prompt_tokens", json!(513)),
        ("/planner_question_stats/0/generated_tokens", json!(192)),
        ("/planner_question_stats/0/generated_tokens", json!(0)),
        (
            "/planner_question_stats/0/stop_reason",
            json!("complete_json"),
        ),
        ("/dataset/source_sha256", json!("b".repeat(64))),
        ("/dataset/question_sha256", json!("b".repeat(64))),
        ("/model/revision", json!("b".repeat(40))),
        ("/artifacts/0/sha256", json!("b".repeat(64))),
        ("/supervisor/child_reaped", json!(false)),
        ("/supervisor/network_access", json!(true)),
    ] {
        let mut changed = report.clone();
        *changed.pointer_mut(path).unwrap() = value;
        assert!(
            validate_report(&changed, &input, &bytes, artifact).is_err(),
            "{path}"
        );
    }
    let mut changed = input.clone();
    changed.question = "Another goal?".into();
    assert!(validate_report(&report, &changed, &bytes, artifact).is_err());
    let mut changed = report;
    changed["outputs"] = json!([]);
    assert!(validate_report(&changed, &input, &bytes, artifact).is_err());
}
