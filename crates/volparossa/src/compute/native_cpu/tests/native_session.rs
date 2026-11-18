//! Manifest authorization only; no executable backend is loaded by these tests.

use super::*;

#[test]
fn native_session_capability_requires_owner_hash_and_exact_new_manifest() {
    let (root, mut options) = fixture();
    let profile = ModelProfile::Qwen4bInstruct2507;
    assert!(!options.supports_native_session(profile));
    let mut value = manifest();
    value["version"] = json!(3);
    value["output_constraints"] = json!(["qwen_tagged_tool_json_v1"]);
    value["native_sessions"] = json!(["connection_bound_v1"]);
    let bytes = serde_json::to_vec(&value).unwrap();
    fs::write(root.path().join("backend.json"), &bytes).unwrap();
    assert!(!options.supports_native_session(profile));
    options.native_backend_sha256 = Some(hex::encode(Sha256::digest(&bytes)));
    assert!(options.supports_native_session(profile));
    assert!(options.supports_output_constraint(profile));
    assert!(!options.supports_native_session(ModelProfile::Qwen600));
    let wire = serde_json::to_value(options.request(profile).unwrap()).unwrap();
    assert!(wire.get("native_session").is_none());
    assert!(wire.get("native_sessions").is_none());
}

#[test]
fn historical_manifests_cannot_claim_sessions_and_new_capability_is_closed() {
    let mut modern = manifest();
    modern["version"] = json!(3);
    modern["output_constraints"] = json!(["qwen_tagged_tool_json_v1"]);
    modern["native_sessions"] = json!(["connection_bound_v1"]);
    for invalid in [
        Value::Null,
        json!([]),
        json!(["other"]),
        json!(["connection_bound_v1", "connection_bound_v1"]),
    ] {
        let mut bad = modern.clone();
        bad["native_sessions"] = invalid;
        let decoded = serde_json::from_value::<Manifest>(bad);
        assert!(decoded.is_err() || decoded.unwrap().validate().is_err());
    }
    for version in [1, 2] {
        let mut bad = modern.clone();
        bad["version"] = json!(version);
        assert!(
            serde_json::from_value::<Manifest>(bad)
                .unwrap()
                .validate()
                .is_err()
        );
    }
}
