//! Admission/report tests only; none assert model inference or tool-use quality.
use super::*;

fn input() -> Value {
    json!({"version":1,"visibility":"private_local","instructions":"Review the supplied code.",
        "tools":[{"type":"function","name":"read_file","description":"Read an approved file.",
            "parameters":{"type":"object","properties":{"name":{"type":"string"}}}}],
        "history":[{"type":"message","role":"user","text":"Read demo.rs first."}]})
}

fn decode(value: &Value) -> Result<Input> {
    Input::decode(&serde_json::to_vec(value).unwrap())
}

fn output(value: &Value) -> Value {
    json!({"sample_index":0,"text":value.to_string(),"text_truncated":false,"generated_tokens":12,
        "generation":{"version":1,"stop_reason":"eos","max_new_tokens":256,"model_profile":"smollm2-360m-v1"}})
}

#[test]
fn ordered_tool_results_require_exact_prior_call_and_offered_identity() {
    let mut value = input();
    let call = json!({"type":"function_call","call_id":"c1","name":"read_file","arguments":{"name":"demo.rs"}});
    value["history"].as_array_mut().unwrap().extend([
        call.clone(),
        json!({"type":"tool_result","call_id":"c1","output":"fn main() {}"}),
    ]);
    let valid = decode(&value).unwrap();
    assert_eq!(
        Input::decode(&valid.bytes().unwrap())
            .unwrap()
            .history
            .len(),
        3
    );
    for invalid in [
        {
            let mut bad = value.clone();
            bad["history"][2]["call_id"] = "other".into();
            bad
        },
        {
            let mut bad = value.clone();
            bad["history"][1]["name"] = "shell".into();
            bad
        },
        {
            let mut bad = value.clone();
            bad["history"][1]["namespace"] = "other".into();
            bad
        },
        {
            let mut bad = value.clone();
            bad["history"].as_array_mut().unwrap().pop();
            bad
        },
        {
            let mut bad = value.clone();
            bad["history"].as_array_mut().unwrap().push(call.clone());
            bad
        },
        {
            let mut bad = value.clone();
            bad["visibility"] = "public".into();
            bad
        },
    ] {
        assert!(decode(&invalid).is_err());
    }
}

#[test]
fn complete_model_output_is_required_and_invalid_calls_stay_incomplete() {
    let input = decode(&input()).unwrap();
    let call = json!({"type":"function_call","call_id":"c1","name":"read_file","namespace":null,"arguments":{"name":"demo.rs"}});
    assert_eq!(turn(&input, &output(&call)).unwrap(), call);
    let answer = json!({"type":"assistant","text":"Done."});
    assert_eq!(turn(&input, &output(&answer)).unwrap(), answer);
    for invalid in [
        {
            let mut bad = call.clone();
            bad["name"] = "execute".into();
            output(&bad)
        },
        {
            let mut bad = output(&call);
            bad["text"] = "```json\n{}\n```".into();
            bad
        },
        {
            let mut bad = output(&call);
            bad["text"] = r#"{"type":"assistant","text":"a","text":"b"}"#.into();
            bad
        },
        {
            let mut bad = output(&call);
            bad["text"] = r#"{"type":"function_call","call_id":"c1","name":"read_file","arguments":{"name":"a","name":"b"}}"#.into();
            bad
        },
    ] {
        assert_eq!(
            turn(&input, &invalid).unwrap(),
            json!({"type":"incomplete","reason":"invalid_output"})
        );
    }
    let mut partial = output(&call);
    partial["generation"]["stop_reason"] = "token_limit".into();
    partial["generated_tokens"] = 256.into();
    assert_eq!(turn(&input, &partial).unwrap()["reason"], "token_limit");
    partial["text_truncated"] = true.into();
    assert_eq!(turn(&input, &partial).unwrap()["reason"], "wire_truncated");
}

#[test]
fn private_modes_cannot_be_public_cli_or_accept_adapters() {
    use clap::ValueEnum as _;
    let bytes = serde_json::to_vec(&input()).unwrap();
    assert!(
        !super::super::Mode::value_variants().contains(&super::super::Mode::PrivateConversation)
    );
    assert!(
        super::super::validate_dataset(super::super::Mode::PrivateConversation, false, &bytes)
            .is_ok()
    );
    assert!(
        super::super::validate_dataset(super::super::Mode::PrivateConversation, true, &bytes)
            .is_err()
    );
    assert!(super::super::private_task::validate_input(&bytes).is_err());
    let mut invalid = input();
    invalid["command"] = "not executable".into();
    assert!(decode(&invalid).is_err());
    invalid = input();
    invalid["instructions"] = "a".repeat(4097).into();
    assert!(decode(&invalid).is_err());
}

#[test]
fn report_binds_real_token_count_limits_and_parsed_model_output() {
    let raw = serde_json::to_vec(&input()).unwrap();
    let profile = ModelProfile::Smol360;
    let answer = json!({"type":"assistant","text":"The function returns one."});
    let valid = json!({"outputs":[output(&answer)],"prompt_tokens":128,
        "conversation":answer,"conversation_limits":capabilities(profile)});
    validate_report(&valid, &raw, profile).unwrap();
    for invalid in [
        {
            let mut bad = valid.clone();
            bad["prompt_tokens"] = 1025.into();
            bad
        },
        {
            let mut bad = valid.clone();
            bad["conversation_limits"]["max_prompt_tokens"] = 8192.into();
            bad
        },
        {
            let mut bad = valid.clone();
            bad["conversation"]["text"] = "fabricated answer".into();
            bad
        },
    ] {
        assert!(validate_report(&invalid, &raw, profile).is_err());
    }
}

#[test]
fn qwen_explicit_limits_accept_codex_sized_instructions_not_other_modes() {
    let mut value = input();
    value["instructions"] = "i".repeat(20_903).into();
    value["history"].as_array_mut().unwrap().insert(
        0,
        json!({"type":"message","role":"developer","text":"Preserve ordered instructions."}),
    );
    let bytes = serde_json::to_vec(&value).unwrap();
    assert!(Input::decode(&bytes).is_err());
    let input = Input::decode_profile(&bytes, ModelProfile::Qwen600).unwrap();
    assert!(input.bytes_profile(ModelProfile::Qwen600).is_ok());
    for mode in [
        super::super::Mode::Infer,
        super::super::Mode::PrivateInfer,
        super::super::Mode::Train,
    ] {
        assert!(
            super::super::validate_profile_dataset(mode, false, &bytes, ModelProfile::Qwen600)
                .is_err()
        );
    }
    assert!(
        super::super::validate_profile_dataset(
            super::super::Mode::PrivateConversation,
            false,
            &bytes,
            ModelProfile::Qwen600
        )
        .is_ok()
    );
    let caps = capabilities(ModelProfile::Qwen600);
    assert_eq!(caps["max_prompt_tokens"], 12288);
    assert_eq!(caps["max_new_tokens"], 1024);
    assert_eq!(caps["model_context_tokens"], 32768);
    assert_eq!(caps["conversation_template"], "qwen3-tools-nonthinking-v1");
    assert_eq!(caps["native_tool_template"], true);
}

fn native_output(raw: &str) -> Value {
    let mut output = output(&Value::Null);
    output["text"] = raw.into();
    output["generation"]["model_profile"] = "qwen3-0.6b-v1".into();
    output["generation"]["max_new_tokens"] = 1024.into();
    output
}

#[test]
fn qwen4b_explicit_profile_keeps_native_boundaries_and_truthful_upstream_context() {
    let profile = ModelProfile::Qwen4bInstruct2507;
    let mut value = input();
    value["instructions"] = "i".repeat(20_903).into();
    value["generation_policy"] = "greedy_v1".into();
    value["history"].as_array_mut().unwrap().insert(
        0,
        json!({"type":"message","role":"developer","text":"Keep the owner's instruction."}),
    );
    let raw = serde_json::to_vec(&value).unwrap();
    let decoded = Input::decode_profile(&raw, profile).unwrap();
    assert!(decoded.requires_generation_policy_handshake());
    assert_eq!(
        decoded.bytes_profile(profile).unwrap(),
        Input::decode_profile(&raw, ModelProfile::Qwen600)
            .unwrap()
            .bytes_profile(ModelProfile::Qwen600)
            .unwrap()
    );
    for mode in [
        super::super::Mode::Infer,
        super::super::Mode::PrivateInfer,
        super::super::Mode::Train,
        super::super::Mode::PlanTasks,
        super::super::Mode::PlanDocument,
    ] {
        assert!(super::super::validate_profile_dataset(mode, false, &raw, profile).is_err());
    }
    let mut expected = capabilities(ModelProfile::Qwen600);
    expected["model_profile"] = profile.to_string().into();
    expected["model_context_tokens"] = 262_144.into();
    expected["conversation_template"] = "qwen3-tools-instruct-2507-v1".into();
    assert_eq!(capabilities(profile), expected);
    let mut output = native_output("Unforced model output.");
    output["generation"]["model_profile"] = profile.to_string().into();
    let report = json!({"id":"ab".repeat(16),"outputs":[output],
        "conversation":{"type":"assistant","text":"Unforced model output."},
        "generation_policy":"greedy_v1","prompt_tokens":128,"conversation_limits":capabilities(profile)});
    validate_report(&report, &raw, profile).unwrap();
    assert!(validate_report(&report, &raw, ModelProfile::Qwen600).is_err());
}

#[test]
fn generation_policy_is_explicit_qwen_only_and_preserves_legacy_bytes() {
    let legacy = br#"{"version":1,"visibility":"private_local","instructions":"Review.","history":[{"type":"message","role":"user","text":"Read first."}],"tools":[]}"#;
    for profile in [ModelProfile::Smol360, ModelProfile::Qwen600] {
        let decoded = Input::decode_profile(legacy, profile).unwrap();
        assert_eq!(decoded.bytes_profile(profile).unwrap(), legacy);
        assert!(!decoded.requires_generation_policy_handshake());
        assert!(
            capabilities(profile)
                .get("generation_policy_version")
                .is_none()
        );
        assert!(capabilities(profile).get("generation_policies").is_none());
    }
    let mut selected: Value = serde_json::from_slice(legacy).unwrap();
    selected["generation_policy"] = "greedy_v1".into();
    let raw = serde_json::to_vec(&selected).unwrap();
    let decoded = Input::decode_profile(&raw, ModelProfile::Qwen600).unwrap();
    assert!(decoded.requires_generation_policy_handshake());
    let roundtrip: Value =
        serde_json::from_slice(&decoded.bytes_profile(ModelProfile::Qwen600).unwrap()).unwrap();
    assert_eq!(roundtrip, selected);
    for profile in [
        ModelProfile::Default135,
        ModelProfile::Smol360,
        ModelProfile::Smol1700,
    ] {
        assert!(Input::decode_profile(&raw, profile).is_err());
    }
    for invalid in [
        Value::Null,
        json!(1),
        json!(true),
        json!("sampled_v2"),
        json!([]),
    ] {
        selected["generation_policy"] = invalid;
        assert!(
            Input::decode_profile(
                &serde_json::to_vec(&selected).unwrap(),
                ModelProfile::Qwen600
            )
            .is_err()
        );
    }
    let duplicate = String::from_utf8(raw).unwrap().replace(
        "\"generation_policy\":\"greedy_v1\"",
        "\"generation_policy\":\"greedy_v1\",\"generation_policy\":\"greedy_v1\"",
    );
    assert!(Input::decode_profile(duplicate.as_bytes(), ModelProfile::Qwen600).is_err());
}

#[test]
fn generation_policy_report_must_match_request_before_summary() {
    let profile = ModelProfile::Qwen600;
    let mut selected = input();
    let legacy_raw = serde_json::to_vec(&selected).unwrap();
    selected["generation_policy"] = "greedy_v1".into();
    let raw = serde_json::to_vec(&selected).unwrap();
    let mut report = json!({"id":"ab".repeat(16),"outputs":[native_output("Ready.")],
        "conversation":{"type":"assistant","text":"Ready."},
        "prompt_tokens":128,"conversation_limits":capabilities(profile)});
    validate_report(&report, &legacy_raw, profile).unwrap();
    let legacy_summary = summary(&report, profile);
    assert!(legacy_summary.get("generation_policy").is_none());
    assert!(validate_report(&report, &raw, profile).is_err());
    report["generation_policy"] = "greedy_v1".into();
    validate_report(&report, &raw, profile).unwrap();
    assert!(validate_report(&report, &legacy_raw, profile).is_err());
    let mut result = summary(&report, profile);
    assert_eq!(
        result.as_object_mut().unwrap().remove("generation_policy"),
        Some(json!("greedy_v1"))
    );
    assert_eq!(
        serde_json::to_vec(&result).unwrap(),
        serde_json::to_vec(&legacy_summary).unwrap()
    );
    for invalid in [Value::Null, json!(true), json!(1), json!("sampled_v2")] {
        report["generation_policy"] = invalid;
        assert!(validate_report(&report, &raw, profile).is_err());
        assert!(validate_report(&report, &legacy_raw, profile).is_err());
    }
}

#[test]
fn worker_policy_report_duplicate_keys_are_rejected_before_value_projection() {
    let id = "ab".repeat(16);
    let legacy = json!({"version":1,"id":id,"kind":"result","status":"ok"});
    let raw = serde_json::to_vec(&legacy).unwrap();
    assert_eq!(super::super::check_message(&raw, &id).unwrap(), legacy);
    for duplicate in [
        r#""generation_policy":"greedy_v1","generation_policy":"greedy_v1""#,
        r#""generation_policy":null,"generation_policy":"greedy_v1""#,
        r#""generation_policy":"other","generation_policy":"greedy_v1""#,
    ] {
        let malformed =
            format!(r#"{{"version":1,"id":"{id}","kind":"result","status":"ok",{duplicate}}}"#);
        assert!(super::super::check_message(malformed.as_bytes(), &id).is_err());
    }
}

#[test]
fn qwen_native_aliases_strictly_bind_real_output_and_owner_assigned_ids() {
    let mut value = input();
    value["tools"][0]["namespace"] = "files".into();
    let input =
        Input::decode_profile(&serde_json::to_vec(&value).unwrap(), ModelProfile::Qwen600).unwrap();
    let id = "abcd".repeat(8);
    let raw = r#"<tool_call>{"name":"vp_0","arguments":{"name":"demo.rs"}}</tool_call>"#;
    let proposal = qwen::turn(&input, &native_output(raw), &id).unwrap();
    assert_eq!(
        proposal,
        json!({"type":"function_call","call_id":format!("vp-{id}"),
        "name":"read_file","namespace":"files","arguments":{"name":"demo.rs"}})
    );
    for malformed in [
        format!("{raw}{raw}"),
        format!("prefix{raw}"),
        raw.replace("vp_0", "shell"),
        "<tool_call>{\"name\":\"vp_0\",\"arguments\":{\"x\":1,\"x\":2}}</tool_call>".into(),
        "<think>hidden</think>answer".into(),
    ] {
        assert_eq!(
            qwen::turn(&input, &native_output(&malformed), &id).unwrap()["reason"],
            "invalid_output"
        );
    }
    let mut report = json!({"id":id,"outputs":[native_output(raw)],"conversation":proposal,
        "prompt_tokens":12288,"conversation_limits":capabilities(ModelProfile::Qwen600)});
    validate_report(
        &report,
        &serde_json::to_vec(&value).unwrap(),
        ModelProfile::Qwen600,
    )
    .unwrap();
    report["prompt_tokens"] = 12289.into();
    assert!(
        validate_report(
            &report,
            &serde_json::to_vec(&value).unwrap(),
            ModelProfile::Qwen600
        )
        .is_err()
    );
}

#[test]
fn qwen_custom_wrapper_preserves_namespace_and_rejects_partial_turns() {
    let mut value = input();
    value["tools"] = json!([{"type":"custom","name":"patch","namespace":"local","description":"Propose patch."}]);
    let input =
        Input::decode_profile(&serde_json::to_vec(&value).unwrap(), ModelProfile::Qwen600).unwrap();
    let id = "ab".repeat(16);
    let mut output = native_output(
        r#"<tool_call>{"name":"vp_0","arguments":{"input":"patch text"}}</tool_call>"#,
    );
    assert_eq!(
        qwen::turn(&input, &output, &id).unwrap(),
        json!({"type":"custom_tool_call",
        "call_id":format!("vp-{id}"),"name":"patch","namespace":"local","input":"patch text"})
    );
    output["generation"]["stop_reason"] = "token_limit".into();
    output["generated_tokens"] = 1024.into();
    assert_eq!(
        qwen::turn(&input, &output, &id).unwrap()["reason"],
        "token_limit"
    );
    output["text_truncated"] = true.into();
    assert_eq!(
        qwen::turn(&input, &output, &id).unwrap()["reason"],
        "wire_truncated"
    );
}

#[test]
fn qwen_native_preface_preserves_exact_call_and_rejects_ambiguous_framing() {
    let value = input();
    let id = "ab".repeat(16);
    let raw = r#"<tool_call>{"name":"vp_0","arguments":{"name":"demo.rs"}}</tool_call>"#;
    for profile in [ModelProfile::Qwen600, ModelProfile::Qwen4bInstruct2507] {
        let input = Input::decode_profile(&serde_json::to_vec(&value).unwrap(), profile).unwrap();
        let expected = qwen::turn(&input, &native_output(raw), &id).unwrap();
        for prefix in [
            "I will inspect the file.\n",
            "First inspect `demo.rs`.\n\n",
            "Let me check.\r\n",
        ] {
            let output = native_output(&format!("{prefix}{raw}"));
            assert_eq!(qwen::turn(&input, &output, &id).unwrap(), expected);
            let report = json!({"id":id,"outputs":[output],"conversation":expected,
                "prompt_tokens":128,"conversation_limits":capabilities(profile)});
            validate_report(&report, &serde_json::to_vec(&value).unwrap(), profile).unwrap();
        }
        let literal = r#"<tool_call>{"name":"vp_0","arguments":{"text":"literal <tool_call> and </tool_call>"}}</tool_call>"#;
        assert_eq!(
            qwen::turn(
                &input,
                &native_output(&format!("Read this literal.\n{literal}")),
                &id
            )
            .unwrap(),
            qwen::turn(&input, &native_output(literal), &id).unwrap()
        );
        for text in [
            format!("no boundary{raw}"),
            format!("```xml\n{raw}"),
            format!("~~~xml\n{raw}"),
            format!("<tool_call malformed\n{raw}"),
            format!("</tool_call>\n{raw}"),
            format!("bad\0prefix\n{raw}"),
            format!("{}\n{raw}", "x".repeat(4096)),
            format!("First.\n{raw}\n{raw}"),
            format!("First.\n{raw} trailing"),
            format!("First.\n{}", raw.replace("vp_0", "vp_99")),
            format!(
                "First.\n{}",
                raw.replace("\"demo.rs\"", "\"demo.rs\",\"name\":\"other\"")
            ),
        ] {
            assert_eq!(
                qwen::turn(&input, &native_output(&text), &id).unwrap()["reason"],
                "invalid_output"
            );
        }
        let mut partial = native_output(&format!("First.\n{raw}"));
        partial["generation"]["stop_reason"] = "token_limit".into();
        partial["generated_tokens"] = 1024.into();
        assert_eq!(
            qwen::turn(&input, &partial, &id).unwrap()["reason"],
            "token_limit"
        );
        partial["text_truncated"] = true.into();
        assert_eq!(
            qwen::turn(&input, &partial, &id).unwrap()["reason"],
            "wire_truncated"
        );
    }
}

#[test]
fn qwen_json_categories_preserve_strict_turns_and_literal_argument_delimiters() {
    let value = input();
    let id = "ab".repeat(16);
    for profile in [ModelProfile::Qwen600, ModelProfile::Qwen4bInstruct2507] {
        let input = Input::decode_profile(&serde_json::to_vec(&value).unwrap(), profile).unwrap();
        for (body, code) in [
            (
                r#"{"name":"vp_0","arguments":{"PRIVATE_CANARY":!}}"#,
                "conversation_native_json_syntax",
            ),
            (
                r#"{"name":false,"arguments":{"PRIVATE_CANARY":0}}"#,
                "conversation_native_json_data",
            ),
            (
                r#"{"name":"vp_0","arguments":{},"PRIVATE_CANARY":0}"#,
                "conversation_native_json_data",
            ),
            (
                r#"{"name":"vp_0","arguments":{"PRIVATE_CANARY":0,"PRIVATE_CANARY":1}}"#,
                "conversation_native_json_data",
            ),
            (
                r#"{"name":"vp_0","arguments":{"PRIVATE_CANARY":"unfinished"#,
                "conversation_native_json_eof",
            ),
        ] {
            let output = native_output(&format!("<tool_call>{body}</tool_call>"));
            let turn = qwen::turn(&input, &output, &id).unwrap();
            assert_eq!(turn, json!({"type":"incomplete","reason":"invalid_output"}));
            assert_eq!(qwen::rejection_code(&input, &output, &id), code);
            assert!(!code.contains("PRIVATE_CANARY"));
            let report = json!({"id":id,"outputs":[output],"conversation":turn,
                "prompt_tokens":128,"conversation_limits":capabilities(profile)});
            validate_report(&report, &serde_json::to_vec(&value).unwrap(), profile).unwrap();
        }
        let literal = r#"<tool_call>{"name":"vp_0","arguments":{"text":"PRIVATE_CANARY <tool_call> and </tool_call>"}}</tool_call>"#;
        let output = native_output(literal);
        assert_eq!(
            qwen::turn(&input, &output, &id).unwrap()["arguments"],
            json!({"text":"PRIVATE_CANARY <tool_call> and </tool_call>"})
        );
        assert_eq!(
            qwen::rejection_code(&input, &output, &id),
            "conversation_native_output_other"
        );
        let mut partial = native_output("<tool_call>{</tool_call>");
        partial["generation"]["stop_reason"] = "token_limit".into();
        partial["generated_tokens"] = 1024.into();
        assert_eq!(
            qwen::turn(&input, &partial, &id).unwrap()["reason"],
            "token_limit"
        );
        partial["text_truncated"] = true.into();
        assert_eq!(
            qwen::turn(&input, &partial, &id).unwrap()["reason"],
            "wire_truncated"
        );
    }
}

#[test]
fn qwen_rejection_diagnostics_are_closed_and_keep_incomplete_wire_output() {
    let mut value = input();
    let id = "ab".repeat(16);
    let input =
        Input::decode_profile(&serde_json::to_vec(&value).unwrap(), ModelProfile::Qwen600).unwrap();
    for (raw, code) in [
        ("<think>PRIVATE_CANARY", "conversation_native_marker"),
        ("<tool_call>{}", "conversation_native_call"),
        (
            "PRIVATE_CANARY<tool_call>{}</tool_call>",
            "conversation_native_preface",
        ),
        (
            r#"<tool_call>{"PRIVATE_CANARY":0}</tool_call>"#,
            "conversation_native_json_data",
        ),
        (
            r#"<tool_call>{"name":"PRIVATE_CANARY","arguments":{}}</tool_call>"#,
            "conversation_unknown_tool",
        ),
        (
            r#"<tool_call>{"name":"vp_0","arguments":[]}</tool_call>"#,
            "conversation_arguments",
        ),
        (" ", "conversation_empty_answer"),
    ] {
        let output = native_output(raw);
        assert_eq!(
            qwen::turn(&input, &output, &id).unwrap(),
            json!({"type":"incomplete","reason":"invalid_output"})
        );
        assert_eq!(qwen::rejection_code(&input, &output, &id), code);
        assert!(!code.contains("PRIVATE_CANARY"));
    }
    let call = native_output(r#"<tool_call>{"name":"vp_0","arguments":{}}</tool_call>"#);
    assert_eq!(
        qwen::rejection_code(&input, &call, "PRIVATE_CANARY"),
        "conversation_request_id"
    );
    value["history"].as_array_mut().unwrap().extend([
        json!({"type":"function_call","call_id":format!("vp-{id}"),"name":"read_file","arguments":{}}),
        json!({"type":"tool_result","call_id":format!("vp-{id}"),"output":"PRIVATE_CANARY"}),
    ]);
    let replay =
        Input::decode_profile(&serde_json::to_vec(&value).unwrap(), ModelProfile::Qwen600).unwrap();
    assert_eq!(
        qwen::rejection_code(&replay, &call, &id),
        "conversation_call_id"
    );
    value["history"].as_array_mut().unwrap().truncate(1);
    value["tools"] = json!([{"type":"custom","name":"patch","description":"PRIVATE_CANARY"}]);
    let custom =
        Input::decode_profile(&serde_json::to_vec(&value).unwrap(), ModelProfile::Qwen600).unwrap();
    assert_eq!(
        qwen::rejection_code(&custom, &call, &id),
        "conversation_custom_input"
    );
    assert_eq!(
        qwen::rejection_code(&input, &json!({}), &id),
        "conversation_native_output_other"
    );
}

#[test]
fn qwen_diagnostic_requires_bound_report_and_explicit_private_debug_target() {
    use std::sync::{Arc, Mutex};
    #[derive(Clone)]
    struct Capture(Arc<Mutex<Vec<u8>>>);
    impl std::io::Write for Capture {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }
    let value = input();
    let raw = serde_json::to_vec(&value).unwrap();
    let profile = ModelProfile::Qwen4bInstruct2507;
    let id = "ab".repeat(16);
    let output = native_output(r#"<tool_call>{"PRIVATE_CANARY":0}</tool_call>"#);
    let report = json!({"id":id,"outputs":[output],"conversation":{"type":"incomplete","reason":"invalid_output"},
        "prompt_tokens":128,"conversation_limits":capabilities(profile)});
    for enabled in [false, true] {
        let captured = Capture(Arc::new(Mutex::new(Vec::new())));
        let writer = captured.clone();
        let subscriber = tracing_subscriber::fmt()
            .with_env_filter(if enabled {
                "off,volparossa::compute::private_diagnostic=debug"
            } else {
                "off"
            })
            .with_ansi(false)
            .without_time()
            .with_writer(move || writer.clone())
            .finish();
        tracing::subscriber::with_default(subscriber, || {
            let mut invalid = report.clone();
            invalid["conversation"]["reason"] = "token_limit".into();
            assert!(validate_report(&invalid, &raw, profile).is_err());
            invalid = report.clone();
            invalid["prompt_tokens"] = 0.into();
            assert!(validate_report(&invalid, &raw, profile).is_err());
            invalid = report.clone();
            invalid["generation_policy"] = "greedy_v1".into();
            assert!(validate_report(&invalid, &raw, profile).is_err());
            assert!(captured.0.lock().unwrap().is_empty());
            validate_report(&report, &raw, profile).unwrap();
        });
        let bytes = captured.0.lock().unwrap();
        if !enabled {
            assert!(bytes.is_empty());
            continue;
        }
        let text = std::str::from_utf8(&bytes).unwrap();
        assert!(
            !text.contains("PRIVATE_CANARY") && !text.contains(&id) && !text.contains("demo.rs")
        );
        assert_eq!(text.lines().count(), 1);
        let (_, record) = text.split_once("private_execution_diagnostic ").unwrap();
        assert_eq!(
            serde_json::from_str::<Value>(record.trim()).unwrap(),
            json!({"version":1,"phase":"execution",
            "detail":{"code":"conversation_native_json_data","io_kind":"none","exit_code":null,"signal":null,"stderr_class":null}})
        );
    }
}

#[test]
fn qwen_standalone_json_requires_exact_proposal_and_keeps_owner_authority() {
    let mut value = input();
    let input =
        Input::decode_profile(&serde_json::to_vec(&value).unwrap(), ModelProfile::Qwen600).unwrap();
    let id = "abcd".repeat(8);
    let raw = r#"{"name": "vp_0", "arguments": {"path": "fixture.js"}}"#;
    let proposal = qwen::turn(&input, &native_output(raw), &id).unwrap();
    assert_eq!(proposal["type"], "function_call");
    assert_eq!(proposal["name"], "read_file");
    assert_eq!(proposal["arguments"], json!({"path":"fixture.js"}));
    assert_eq!(proposal["call_id"], format!("vp-{id}"));
    let wrapped = format!("<tool_call>{raw}</tool_call>");
    assert_eq!(
        proposal,
        qwen::turn(&input, &native_output(&wrapped), &id).unwrap()
    );
    for text in [
        format!("```json\n{raw}\n```"),
        format!("Example: {raw}"),
        format!("{raw} done"),
        format!("{raw}{raw}"),
        raw[..raw.len() - 1].into(),
        raw.replace("\"vp_0\"", "\"vp_0\", \"name\": \"vp_0\""),
        raw.replace("\"fixture.js\"", "\"fixture.js\", \"path\": \"other\""),
        raw.replace("\"name\": \"vp_0\"", "\"name\": \"vp_0\", \"extra\": 1"),
    ] {
        assert_eq!(
            qwen::turn(&input, &native_output(&text), &id).unwrap(),
            json!({"type":"assistant","text":text})
        );
    }
    assert_eq!(
        qwen::turn(&input, &native_output(&raw.replace("vp_0", "vp_99")), &id).unwrap()["reason"],
        "invalid_output"
    );
    let report = json!({"id":id,"outputs":[native_output(raw)],"conversation":proposal,
        "prompt_tokens":279,"conversation_limits":capabilities(ModelProfile::Qwen600)});
    validate_report(
        &report,
        &serde_json::to_vec(&value).unwrap(),
        ModelProfile::Qwen600,
    )
    .unwrap();
    value["tools"] = json!([]);
    let no_tools =
        Input::decode_profile(&serde_json::to_vec(&value).unwrap(), ModelProfile::Qwen600).unwrap();
    assert_eq!(
        qwen::turn(&no_tools, &native_output(raw), &id).unwrap(),
        json!({"type":"assistant","text":raw})
    );
}
