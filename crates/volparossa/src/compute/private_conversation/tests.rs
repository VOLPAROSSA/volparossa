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
