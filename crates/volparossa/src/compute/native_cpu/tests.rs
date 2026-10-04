//! Inert admission/binding fixtures only: no executable library or model is loaded.
use std::os::unix::fs::{PermissionsExt as _, symlink};

use super::*;

fn manifest() -> Value {
    json!({"version":1,"kind":KIND,"abi_version":1,"source_commit":SOURCE,
        "model_profile":"qwen3-4b-instruct-2507-v1","source_weights_sha256":WEIGHTS,
        "source_weights_bytes":8_044_982_000_u64,
        "library":{"path":"libvolparossa_llama_cpu.so","sha256":"a".repeat(64),"bytes":1},
        "gguf":{"path":"model.gguf","sha256":"b".repeat(64),"bytes":1},
        "verification":{"tensor_count":398,"tensor_values_equal":true,"tokenizer_equal":true,
            "chat_template_sha256":"c".repeat(64)},"build_manifest_sha256":"d".repeat(64)})
}

fn fixture() -> (tempfile::TempDir, Options) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let raw = serde_json::to_vec(&manifest()).unwrap();
    fs::write(root.path().join("backend.json"), &raw).unwrap();
    for name in ["libvolparossa_llama_cpu.so", "model.gguf"] {
        let path = root.path().join(name);
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let options = Options {
        native_backend_root: Some(root.path().to_owned()),
        native_backend_sha256: Some(hex::encode(Sha256::digest(raw))),
    };
    (root, options)
}

#[test]
fn legacy_request_shape_is_unchanged_and_no_backend_report_is_accepted() {
    let request = Options::default().request(ModelProfile::default()).unwrap();
    assert_eq!(serde_json::to_value(&request).unwrap(), json!({}));
    assert!(!request.enabled());
    assert!(request.check_report(&json!({})).is_ok());
    assert!(
        request
            .check_report(&json!({"inference_backend":null}))
            .is_err()
    );
}

#[test]
fn manifest_requires_exact_source_profile_conversion_and_fixed_artifacts() {
    let good = manifest();
    assert!(
        serde_json::from_value::<Manifest>(good.clone())
            .unwrap()
            .validate()
            .is_ok()
    );
    for (pointer, replacement) in [
        ("/kind", json!("peer_selected")),
        ("/abi_version", json!(2)),
        ("/source_commit", json!("0".repeat(40))),
        ("/source_weights_sha256", json!("0".repeat(64))),
        ("/source_weights_bytes", json!(1)),
        ("/model_profile", json!("smollm2-360m-instruct-v1")),
        ("/library/path", json!("../arbitrary.so")),
        ("/gguf/path", json!("/other/model.gguf")),
        ("/library/sha256", json!("A".repeat(64))),
        ("/gguf/bytes", json!(10_u64 * 1024 * 1024 * 1024)),
        ("/verification/tensor_count", json!(397)),
        ("/verification/tensor_values_equal", json!(false)),
        ("/verification/tokenizer_equal", json!(false)),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = replacement;
        assert!(
            serde_json::from_value::<Manifest>(bad)
                .and_then(|value| value.validate().map_err(serde::de::Error::custom))
                .is_err(),
            "{pointer}"
        );
    }
    let mut extra = good;
    extra["command"] = json!("arbitrary");
    assert!(serde_json::from_value::<Manifest>(extra).is_err());
}

#[test]
fn owner_authorization_binds_manifest_and_never_serializes_host_paths() {
    let (_root, mut options) = fixture();
    let request = options.request(ModelProfile::Qwen4bInstruct2507).unwrap();
    let fields = serde_json::to_value(&request).unwrap();
    assert_eq!(fields.as_object().unwrap().len(), 3);
    assert_eq!(fields["inference_backend"], KIND);
    assert_eq!(fields["native_backend_root"], "/native-backend");
    assert!(options.request(ModelProfile::Qwen600).is_err());
    options.native_backend_sha256 = Some("0".repeat(64));
    assert!(options.request(ModelProfile::Qwen4bInstruct2507).is_err());
    options.native_backend_sha256 = None;
    assert!(options.request(ModelProfile::Qwen4bInstruct2507).is_err());
}

#[test]
fn executable_symlink_shared_file_and_changed_length_are_rejected() {
    let (root, options) = fixture();
    let path = root.path().join("libvolparossa_llama_cpu.so");
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(options.request(ModelProfile::Qwen4bInstruct2507).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(&path, b"changed").unwrap();
    assert!(options.request(ModelProfile::Qwen4bInstruct2507).is_err());
    fs::remove_file(&path).unwrap();
    symlink(root.path().join("model.gguf"), path).unwrap();
    assert!(options.request(ModelProfile::Qwen4bInstruct2507).is_err());
}

#[test]
fn result_must_bind_authorized_native_identity_and_honest_precision() {
    let (_root, options) = fixture();
    let request = options.request(ModelProfile::Qwen4bInstruct2507).unwrap();
    let good = json!({"inference_backend":request.expected_report,
        "model_parameter_dtype":"bf16_with_exact_f32_norms","model_attention_backend":"llama_cpp_cpu"});
    assert!(request.check_report(&good).is_ok());
    for (pointer, replacement) in [
        ("/inference_backend/manifest_sha256", json!("0".repeat(64))),
        ("/inference_backend/library_sha256", json!("0".repeat(64))),
        ("/inference_backend/gguf_sha256", json!("0".repeat(64))),
        ("/model_parameter_dtype", json!("bfloat16")),
        ("/model_attention_backend", json!("sdpa")),
    ] {
        let mut bad = good.clone();
        *bad.pointer_mut(pointer).unwrap() = replacement;
        assert!(request.check_report(&bad).is_err());
    }
}

#[test]
fn native_backend_requires_explicit_greedy_conversation_only() {
    let (_root, options) = fixture();
    let mut input = json!({"version":1,"visibility":"private_local","instructions":"Reply.",
        "history":[{"type":"message","role":"user","text":"Hello"}],"tools":[]});
    let profile = ModelProfile::Qwen4bInstruct2507;
    assert!(
        options
            .validate_input(
                Mode::PrivateConversation,
                &serde_json::to_vec(&input).unwrap(),
                profile
            )
            .is_err()
    );
    input["generation_policy"] = json!("greedy_v1");
    let bytes = serde_json::to_vec(&input).unwrap();
    assert!(
        options
            .validate_input(Mode::PrivateConversation, &bytes, profile)
            .is_ok()
    );
    assert!(
        options
            .validate_input(Mode::PublicCodeProposal, &bytes, profile)
            .is_err()
    );
    assert!(
        options
            .validate_input(Mode::PrivateConversation, &bytes, ModelProfile::Qwen600)
            .is_err()
    );
}
