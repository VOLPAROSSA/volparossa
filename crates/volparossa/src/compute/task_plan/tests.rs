use super::*;

fn input() -> Input {
    Input {
        version: 1,
        visibility: "public".into(),
        license: "GPL-3.0-only".into(),
        question: "Compare the public requirements and their risks.".into(),
        source_sha256: "a".repeat(64),
        source_bytes: 128,
    }
}

#[test]
fn task_input_requires_explicit_public_source_and_original_question() {
    let input = input();
    let bytes = serde_json::to_vec(&input).unwrap();
    assert_eq!(Input::decode(&bytes).unwrap(), input);
    crate::compute::validate_dataset(super::super::Mode::PlanTasks, false, &bytes).unwrap();
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
fn retained_planner_report_binds_original_input_artifact_model_and_cleanup() {
    // Inert parser fixture only. No model is loaded and no execution proof is claimed.
    let input = input();
    let bytes = serde_json::to_vec(&input).unwrap();
    let artifact = br#"{"version":1,"questions":["What is required?","What are the risks?"]}"#;
    let report = json!({
        "version":1,"id":"ab".repeat(16),"kind":"result","status":"ok","mode":"plan_tasks",
        "device":"cpu","threads":2,"updates_completed":0,"model_weights_loaded":true,
        "goal_only_planning":true,"generation_limit_reached":false,"model_answer_correctness_proven":false,
        "planner_prompt_tokens":100,"planner_generated_tokens":40,
        "model":{"id":MODEL_ID,"revision":MODEL_REVISION,"files":{"model.safetensors":{"sha256":hex::encode(BASE_MODEL_SHA256)}}},
        "dataset":{"version":1,"sha256":digest(&bytes),"bytes":bytes.len(),"visibility":"public","license":input.license,
            "question_sha256":digest(input.question.as_bytes()),"source_sha256":input.source_sha256,"source_bytes":input.source_bytes},
        "artifacts":[{"relative_path":"task-questions.json","bytes":artifact.len(),"sha256":digest(artifact)}],
        "supervisor":{"child_reaped":true,"network_access":false}
    });
    validate_report(&report, &input, &bytes, artifact).unwrap();
    for (path, value) in [
        ("/mode", json!("infer")),
        ("/updates_completed", json!(1)),
        ("/model_weights_loaded", json!(false)),
        ("/goal_only_planning", json!(false)),
        ("/generation_limit_reached", json!(true)),
        ("/planner_generated_tokens", json!(384)),
        ("/planner_prompt_tokens", json!(513)),
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
