use super::{super::super::private_conversation::Input, *};

const CONSTRAINT: &str = "qwen_tagged_tool_json_v1";
const PROFILE: ModelProfile = ModelProfile::Qwen4bInstruct2507;

fn constrained_manifest() -> Value {
    let mut value = manifest();
    value["version"] = 2.into();
    value["output_constraints"] = json!([CONSTRAINT]);
    value
}

fn input() -> Vec<u8> {
    serde_json::to_vec(
        &json!({"version":1,"visibility":"private_local","instructions":"Reply.",
        "history":[{"type":"message","role":"user","text":"Read."}],
        "tools":[{"type":"custom","name":"PRIVATE_CANARY","description":"Read."}],
        "generation_policy":"greedy_v1","output_constraint":CONSTRAINT}),
    )
    .unwrap()
}

fn constrained_fixture() -> (tempfile::TempDir, Options) {
    let (root, mut options) = fixture();
    let raw = serde_json::to_vec(&constrained_manifest()).unwrap();
    fs::write(root.path().join("backend.json"), &raw).unwrap();
    options.native_backend_sha256 = Some(hex::encode(Sha256::digest(raw)));
    (root, options)
}

#[test]
fn manifest_version_binds_exact_constraint_capability_without_legacy_widening() {
    for (version, constraints, accepted) in [
        (1, None, true),
        (1, Some(Value::Null), false),
        (1, Some(json!([])), false),
        (2, None, false),
        (1, Some(json!([CONSTRAINT])), false),
        (2, Some(json!([CONSTRAINT])), true),
        (3, Some(json!([CONSTRAINT])), false),
        (2, Some(Value::Null), false),
        (2, Some(json!([])), false),
        (2, Some(json!([CONSTRAINT, CONSTRAINT])), false),
        (2, Some(json!(["other"])), false),
        (2, Some(json!([true])), false),
    ] {
        let mut value = manifest();
        value["version"] = version.into();
        if let Some(constraints) = constraints {
            value["output_constraints"] = constraints;
        }
        let valid = serde_json::from_value::<Manifest>(value)
            .is_ok_and(|manifest| manifest.validate().is_ok());
        assert_eq!(valid, accepted);
    }
}

#[test]
fn constrained_worker_request_requires_authorized_manifest_and_core_aliases() {
    let raw = input();
    let (_old_root, legacy) = fixture();
    assert!(!legacy.supports_output_constraint(PROFILE));
    assert!(
        legacy
            .validate_input(Mode::PrivateConversation, &raw, PROFILE)
            .is_err()
    );
    assert!(
        Options::default()
            .validate_input(Mode::PrivateConversation, &raw, PROFILE)
            .is_err()
    );
    let (root, mut options) = constrained_fixture();
    assert!(options.supports_output_constraint(PROFILE));
    assert!(!options.supports_output_constraint(ModelProfile::Qwen600));
    options
        .validate_input(Mode::PrivateConversation, &raw, PROFILE)
        .unwrap();
    let dataset = root.path().join("input.json");
    fs::write(&dataset, raw).unwrap();
    let request = options
        .request_for_dataset(PROFILE, Mode::PrivateConversation, &dataset)
        .unwrap();
    let value = serde_json::to_value(&request).unwrap();
    assert_eq!(value.as_object().unwrap().len(), 5);
    assert_eq!(value["output_constraint"], CONSTRAINT);
    assert_eq!(value["output_constraint_tools"], json!(["vp_0"]));
    assert!(!value.to_string().contains("PRIVATE_CANARY"));
    assert!(!value.to_string().contains(root.path().to_str().unwrap()));
    options.native_backend_sha256 = Some("0".repeat(64));
    assert!(!options.supports_output_constraint(PROFILE));
}

#[test]
fn support_does_not_select_constraint_and_result_cannot_claim_unrequested_support() {
    let (_root, options) = constrained_fixture();
    let mut request = options.request(PROFILE).unwrap();
    let legacy = serde_json::to_value(&request).unwrap();
    assert_eq!(legacy.as_object().unwrap().len(), 3);
    let mut result = json!({"inference_backend":request.expected_report,
        "model_parameter_dtype":"bf16_with_exact_f32_norms","model_attention_backend":"llama_cpp_cpu"});
    request.check_report(&result).unwrap();
    result["output_constraint"] = CONSTRAINT.into();
    assert!(request.check_report(&result).is_err());
    let input = Input::decode_profile(&input(), PROFILE).unwrap();
    request.select_constraint(&input).unwrap();
    request.check_report(&result).unwrap();
    let mut extra = result.clone();
    extra["output_constraint_tools"] = json!(["vp_0"]);
    assert!(request.check_report(&extra).is_err());
    for invalid in [Value::Null, json!(false), json!("other")] {
        result["output_constraint"] = invalid;
        assert!(request.check_report(&result).is_err());
    }
    result.as_object_mut().unwrap().remove("output_constraint");
    assert!(request.check_report(&result).is_err());
    let value = serde_json::to_value(&request).unwrap();
    let mut restored = value.as_object().unwrap().clone();
    restored.remove("output_constraint");
    restored.remove("output_constraint_tools");
    assert_eq!(Value::Object(restored), legacy);
}
