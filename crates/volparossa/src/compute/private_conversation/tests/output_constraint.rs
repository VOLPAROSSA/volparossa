//! Pure wire and original-text validation; no model execution or grammar quality claim.
use super::*;

const CONSTRAINT: &str = "qwen_tagged_tool_json_v1";
const PROFILE: ModelProfile = ModelProfile::Qwen4bInstruct2507;

fn selected() -> Value {
    let mut value = input();
    value["tools"][0]["namespace"] = Value::Null;
    value["generation_policy"] = "greedy_v1".into();
    value["output_constraint"] = CONSTRAINT.into();
    value
}

fn decode_selected(value: &Value) -> Result<Input> {
    Input::decode_profile(&serde_json::to_vec(value).unwrap(), PROFILE)
}

fn report(text: &str) -> Value {
    let mut output = native_output(text);
    output["generation"]["model_profile"] = PROFILE.to_string().into();
    output["generation"]["max_new_tokens"] = PROFILE.spec().max_new_tokens.into();
    let input = decode_selected(&selected()).unwrap();
    let id = "ab".repeat(16);
    json!({"id":id,"outputs":[output],"conversation":qwen::turn(&input,&output,&id).unwrap(),
        "prompt_tokens":128,"conversation_limits":capabilities(PROFILE),
        "generation_policy":"greedy_v1","output_constraint":CONSTRAINT})
}

#[test]
fn constraint_is_explicit_nonnull_qwen4b_greedy_with_offered_tools_only() {
    let value = selected();
    let decoded = decode_selected(&value).unwrap();
    assert_eq!(decoded.output_constraint_tools(), Some(vec!["vp_0".into()]));
    assert_eq!(
        serde_json::from_slice::<Value>(&decoded.bytes_profile(PROFILE).unwrap()).unwrap(),
        value
    );
    for invalid in [
        Value::Null,
        json!(true),
        json!(1),
        json!([]),
        json!("other"),
    ] {
        let mut bad = value.clone();
        bad["output_constraint"] = invalid;
        assert!(decode_selected(&bad).is_err());
    }
    for profile in [ModelProfile::Smol360, ModelProfile::Qwen600] {
        assert!(Input::decode_profile(&serde_json::to_vec(&value).unwrap(), profile).is_err());
    }
    let mut no_policy = value.clone();
    no_policy
        .as_object_mut()
        .unwrap()
        .remove("generation_policy");
    assert!(decode_selected(&no_policy).is_err());
    let mut no_tools = value.clone();
    no_tools["tools"] = json!([]);
    assert!(decode_selected(&no_tools).is_err());
    let mut client_aliases = value;
    client_aliases["output_constraint_tools"] = json!(["vp_0"]);
    assert!(decode_selected(&client_aliases).is_err());
}

#[test]
fn constraint_aliases_are_core_derived_bounded_and_contiguous() {
    let mut value = selected();
    let tool = value["tools"][0].clone();
    value["tools"] = (0..32)
        .map(|index| {
            let mut tool = tool.clone();
            tool["name"] = format!("private_tool_{index}").into();
            tool
        })
        .collect::<Vec<_>>()
        .into();
    let aliases = decode_selected(&value)
        .unwrap()
        .output_constraint_tools()
        .unwrap();
    assert_eq!(
        aliases,
        (0..32)
            .map(|index| format!("vp_{index}"))
            .collect::<Vec<_>>()
    );
    assert!(
        !serde_json::to_string(&aliases)
            .unwrap()
            .contains("private_tool")
    );
    let mut extra = tool;
    extra["name"] = "extra".into();
    value["tools"].as_array_mut().unwrap().push(extra);
    assert!(decode_selected(&value).is_err());
}

#[test]
fn absent_constraint_preserves_legacy_bytes_and_report_shape() {
    let raw = br#"{"version":1,"visibility":"private_local","instructions":"Reply.","history":[{"type":"message","role":"user","text":"Hello"}],"tools":[],"generation_policy":"greedy_v1"}"#;
    let input = Input::decode_profile(raw, PROFILE).unwrap();
    assert!(input.output_constraint().is_none());
    assert!(input.output_constraint_tools().is_none());
    assert_eq!(input.bytes_profile(PROFILE).unwrap(), raw.to_vec());
    let mut result = report("Plain answer.");
    result.as_object_mut().unwrap().remove("output_constraint");
    validate_report(&result, raw, PROFILE).unwrap();
    assert!(summary(&result, PROFILE).get("output_constraint").is_none());
    result["output_constraint"] = CONSTRAINT.into();
    assert!(validate_report(&result, raw, PROFILE).is_err());
}

#[test]
fn constrained_result_is_exactly_bound_and_never_forces_a_tool() {
    let raw = serde_json::to_vec(&selected()).unwrap();
    for text in [
        "Plain answer, without calling a tool.",
        "<tool_call>{\"name\":\"vp_0\",\"arguments\":{\"name\":\"demo.rs\"}}</tool_call>",
    ] {
        let result = report(text);
        validate_report(&result, &raw, PROFILE).unwrap();
        assert_eq!(summary(&result, PROFILE)["output_constraint"], CONSTRAINT);
        for invalid in [Value::Null, json!(true), json!("other")] {
            let mut bad = result.clone();
            bad["output_constraint"] = invalid;
            assert!(validate_report(&bad, &raw, PROFILE).is_err());
        }
        let mut absent = result;
        absent.as_object_mut().unwrap().remove("output_constraint");
        assert!(validate_report(&absent, &raw, PROFILE).is_err());
    }
}

#[test]
fn constraint_claim_does_not_repair_or_authorize_invalid_original_output() {
    let raw = serde_json::to_vec(&selected()).unwrap();
    for text in [
        "<tool_call>{\"name\":\"vp_0\",\"arguments\":{broken}}</tool_call>",
        "<tool_call>{\"name\":\"vp_31\",\"arguments\":{}}</tool_call>",
        "<tool_call>{\"name\":\"vp_0\",\"arguments\":{},\"PRIVATE_CANARY\":1}</tool_call>",
    ] {
        let result = report(text);
        assert_eq!(result["conversation"]["reason"], "invalid_output");
        validate_report(&result, &raw, PROFILE).unwrap();
        assert_eq!(summary(&result, PROFILE)["turn_complete"], false);
        let mut forged = result;
        forged["conversation"] = json!({"type":"assistant","text":"repaired"});
        assert!(validate_report(&forged, &raw, PROFILE).is_err());
    }
}

#[test]
fn duplicate_constraint_keys_are_rejected_before_binding() {
    let raw = serde_json::to_string(&selected()).unwrap();
    let field = format!("\"output_constraint\":\"{CONSTRAINT}\"");
    let duplicate = raw.replace(&field, &format!("{field},{field}"));
    assert!(Input::decode_profile(duplicate.as_bytes(), PROFILE).is_err());
    for value in ["null", "\"other\"", "\"qwen_tagged_tool_json_v1\""] {
        let raw = format!("{{{field},\"output_constraint\":{value}}}");
        assert!(decode_worker_message(raw.as_bytes()).is_err());
    }
}

#[test]
fn constrained_argument_nesting_limit_is_exact_and_does_not_change_legacy() {
    let mut nested = json!({});
    for depth in 1..=17 {
        let text = format!("<tool_call>{{\"name\":\"vp_0\",\"arguments\":{nested}}}</tool_call>");
        let result = report(&text);
        assert_eq!(
            result["conversation"]["type"] == "function_call",
            depth <= 16
        );
        let mut legacy = selected();
        legacy.as_object_mut().unwrap().remove("output_constraint");
        let input = decode_selected(&legacy).unwrap();
        assert_eq!(
            qwen::turn(&input, &result["outputs"][0], &"ab".repeat(16)).unwrap()["type"],
            "function_call"
        );
        nested = json!({"x":nested});
    }
    let mut arrays = json!(0);
    for _ in 0..15 {
        arrays = json!([arrays]);
    }
    assert!(constrained_argument_depth(&json!({"x":arrays}), 1));
    assert!(!constrained_argument_depth(&json!({"x":[arrays]}), 1));
}
