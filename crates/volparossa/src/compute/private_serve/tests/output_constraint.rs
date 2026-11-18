//! Inert owner-manifest and IPC negotiation only; no worker or model is started.
use super::*;

use sha2::{Digest as _, Sha256};

const CONSTRAINT: &str = "qwen_tagged_tool_json_v1";

pub(super) fn native_config(
    root: &std::path::Path,
    extended: bool,
) -> private_task::ExecutionConfig {
    let mut config = config(root);
    config.model_profile = ModelProfile::Qwen4bInstruct2507;
    let backend = root.join("backend");
    fs::create_dir(&backend).unwrap();
    fs::set_permissions(&backend, fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["libvolparossa_llama_cpu.so", "model.gguf"] {
        let path = backend.join(name);
        fs::write(&path, b"x").unwrap();
        fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut manifest = json!({"version":1,"kind":"llama_cpp_bf16_v1","abi_version":1,
        "source_commit":"7fe450e19305b828c199d602c23a8337aaa1f03b",
        "model_profile":"qwen3-4b-instruct-2507-v1",
        "source_weights_sha256":"79f6bbc34572c0063d12022f0f93074d90bbcd5dfd82134423bf892f7f8df3cf",
        "source_weights_bytes":8_044_982_000_u64,
        "library":{"path":"libvolparossa_llama_cpu.so","sha256":"a".repeat(64),"bytes":1},
        "gguf":{"path":"model.gguf","sha256":"b".repeat(64),"bytes":1},
        "verification":{"tensor_count":398,"tensor_values_equal":true,"tokenizer_equal":true,
            "chat_template_sha256":"c".repeat(64)},"build_manifest_sha256":"d".repeat(64)});
    if extended {
        manifest["version"] = 2.into();
        manifest["output_constraints"] = json!([CONSTRAINT]);
    }
    let raw = serde_json::to_vec(&manifest).unwrap();
    fs::write(backend.join("backend.json"), &raw).unwrap();
    config.native_backend.native_backend_root = Some(backend);
    config.native_backend.native_backend_sha256 = Some(hex::encode(Sha256::digest(raw)));
    config
}

fn conversation() -> Value {
    json!({"version":1,"visibility":"private_local","instructions":"Reply.",
        "history":[{"type":"message","role":"user","text":"Read."}],
        "tools":[{"type":"custom","name":"tool","description":"Read."}],
        "generation_policy":"greedy_v1","output_constraint":CONSTRAINT})
}

#[test]
fn constraint_negotiation_rejects_invalid_null_and_duplicate_versions() {
    for version in [
        json!(1),
        json!(0),
        json!(2),
        Value::Null,
        json!(true),
        json!("1"),
    ] {
        let request = request(
            FIRST,
            json!({"type":"conversation_capabilities","output_constraint_version":version}),
        );
        let valid = serde_json::from_value::<wire::Request>(request).is_ok_and(|request| {
            request
                .validate_profile(ModelProfile::Qwen4bInstruct2507)
                .is_ok()
        });
        assert_eq!(valid, version == json!(1));
    }
    let raw = format!(
        r#"{{"version":1,"id":"{FIRST}","operation":{{"type":"conversation_capabilities","output_constraint_version":1,"output_constraint_version":1}}}}"#
    );
    assert!(serde_json::from_str::<wire::Request>(&raw).is_err());
}

#[test]
fn capability_is_opt_in_and_requires_verified_owner_manifest_support() {
    for supported in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let config = native_config(root.path(), supported);
        let gate = Semaphore::new(1);
        let mut handshakes = Handshakes::default();
        let original = conversation_capabilities(&config, &gate, &handshakes);
        assert!(original.get("output_constraint_version").is_none());
        assert!(original.get("output_constraints").is_none());
        handshakes.output_constraint = Some(1);
        let mut caps = conversation_capabilities(&config, &gate, &handshakes);
        assert_eq!(
            caps.as_object_mut()
                .unwrap()
                .remove("output_constraint_version"),
            Some(json!(1))
        );
        assert_eq!(
            caps.as_object_mut().unwrap().remove("output_constraints"),
            Some(if supported {
                json!([CONSTRAINT])
            } else {
                json!([])
            })
        );
        assert_eq!(caps, original);
        let mut changed = config;
        changed.native_backend.native_backend_sha256 = Some("0".repeat(64));
        assert_eq!(
            conversation_capabilities(&changed, &gate, &handshakes)["output_constraints"],
            json!([])
        );
        changed.native_backend = super::super::super::native_cpu::Options::default();
        assert_eq!(
            conversation_capabilities(&changed, &gate, &handshakes)["output_constraints"],
            json!([])
        );
    }
}

#[test]
fn constrained_admission_requires_current_connection_handshake_and_manifest() {
    for supported in [false, true] {
        let root = tempfile::tempdir().unwrap();
        let config = Arc::new(native_config(root.path(), supported));
        let gate = Arc::new(Semaphore::new(1));
        // Occupy the only slot: a correctly admitted shape returns busy, never starts a worker.
        let _occupied = gate.try_acquire().unwrap();
        let mut active = None;
        let mut handshakes = Handshakes::default();
        for selected in [false, true, false] {
            let mut operation =
                json!({"type":"conversation_capabilities","generation_policy_version":1});
            if selected {
                operation["output_constraint_version"] = 1.into();
            }
            let query = serde_json::from_value(request(FIRST, operation)).unwrap();
            respond(query, &config, &gate, &mut active, &mut handshakes);
            assert_eq!(handshakes.output_constraint, selected.then_some(1));
            let submit = serde_json::from_value(request(
                SECOND,
                json!({"type":"submit_conversation","conversation":conversation()}),
            ))
            .unwrap();
            let result = respond(submit, &config, &gate, &mut active, &mut handshakes);
            let expected = if !selected {
                "handshake_required"
            } else if !supported {
                "invalid_request"
            } else {
                "busy"
            };
            assert_eq!(result, wire::error(Some(SECOND), expected));
            assert!(active.is_none());
        }
        let mut other_connection = Handshakes::default();
        let submit = serde_json::from_value(request(
            THIRD,
            json!({"type":"submit_conversation","conversation":conversation()}),
        ))
        .unwrap();
        assert_eq!(
            respond(submit, &config, &gate, &mut active, &mut other_connection),
            wire::error(Some(THIRD), "handshake_required")
        );
    }
}
