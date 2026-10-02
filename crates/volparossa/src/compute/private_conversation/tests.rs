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
