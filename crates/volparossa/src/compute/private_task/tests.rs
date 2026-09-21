//! Pure contracts and owned-file lifecycle; no model or networking is executed.

use super::*;
use clap::ValueEnum as _;

fn input() -> Vec<u8> {
    serde_json::to_vec(&json!({"version":1,"visibility":"private_local",
        "question":"What is the private canary?","context":"The private canary is inert-test-only."})).unwrap()
}

fn args(root: &Path) -> Options {
    Options {
        input: root.join("secret-input.json"),
        runtime_root: root.join("secret-runtime"),
        model_root: root.join("secret-model"),
        work_parent: root.to_path_buf(),
        model_profile: ModelProfile::Smol360,
        threads: 2,
        max_seconds: 600,
        execute: true,
    }
}

fn directory() -> tempfile::TempDir {
    tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap()
}

#[test]
fn private_input_is_strict_and_never_admitted_as_a_public_job() {
    let bytes = input();
    validate_input(&bytes).unwrap();
    for mode in [
        Mode::Infer,
        Mode::Train,
        Mode::PlanDocument,
        Mode::PlanTasks,
    ] {
        assert!(super::super::validate_dataset(mode, false, &bytes).is_err());
    }
    assert!(super::super::validate_dataset(Mode::PrivateInfer, true, &bytes).is_err());
    assert!(!Mode::value_variants().contains(&Mode::PrivateInfer));
    for (field, value) in [
        ("version", json!(2)),
        ("visibility", json!("public")),
        ("question", json!(" ")),
        ("context", json!("\0")),
        ("context", json!("x".repeat(4097))),
        ("question", json!("é".repeat(257))),
        ("license", json!("GPL-3.0-only")),
        ("model_profile", json!("smollm2-360m-v1")),
    ] {
        let mut invalid: Value = serde_json::from_slice(&bytes).unwrap();
        invalid[field] = value;
        assert!(validate_input(&serde_json::to_vec(&invalid).unwrap()).is_err());
    }
    assert!(validate_input(br#"{"version":1,"version":1,"visibility":"private_local","question":"Q?","context":"C"}"#).is_err());
}

#[test]
fn preview_never_serializes_paths_or_private_input() {
    let root = directory();
    let preview = preview(&args(root.path())).to_string();
    assert!(!preview.contains("secret") && !preview.contains("inert-test-only"));
    assert!(!preview.contains(root.path().to_str().unwrap()));
    assert!(!preview.contains("private_local"));
}

#[test]
fn owned_snapshot_is_private_and_cleanup_preserves_original_and_sibling() {
    let root = directory();
    let args = args(root.path());
    let original = input();
    fs::write(&args.input, &original).unwrap();
    fs::set_permissions(&args.input, fs::Permissions::from_mode(0o600)).unwrap();
    fs::write(root.path().join("unrelated"), b"preserve").unwrap();
    assert_eq!(read_input(&args.input).unwrap(), original);
    for success in [true, false] {
        let staged = Staged::new(&args, &original).unwrap();
        let path = staged.directory.path().to_path_buf();
        assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
        assert_eq!(
            fs::metadata(&staged.options.dataset).unwrap().mode() & 0o777,
            0o600
        );
        assert_eq!(fs::read(&staged.options.dataset).unwrap(), original);
        let result = if success {
            Ok(json!({"inert":true}))
        } else {
            Err(anyhow::anyhow!("inert error"))
        };
        assert_eq!(staged.finish(result).is_ok(), success);
        assert!(!path.exists());
    }
    assert_eq!(fs::read(&args.input).unwrap(), original);
    assert_eq!(
        fs::read(root.path().join("unrelated")).unwrap(),
        b"preserve"
    );
    fs::set_permissions(&args.input, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(read_input(&args.input).is_err());
}

#[test]
fn unconfirmed_process_cleanup_keeps_only_the_owned_snapshot_and_never_an_answer() {
    let root = directory();
    let staged = Staged::new(&args(root.path()), &input()).unwrap();
    let path = staged.directory.path().to_path_buf();
    let result = staged.finish(Err(CleanupUnconfirmed.into()));
    assert!(
        result
            .unwrap_err()
            .downcast_ref::<CleanupUnconfirmed>()
            .is_some()
    );
    assert_eq!(fs::read(path.join("input.json")).unwrap(), input());
    // The enclosing owned fixture removes this retained directory at test end;
    // no real child was created and no production cleanup claim is manufactured.
}

fn report(raw: &[u8]) -> Value {
    let spec = ModelProfile::Smol360.spec();
    json!({"mode":"private_infer","status":"ok","updates_completed":0,
        "private_data_supported":true,"distributed_execution_claimed":false,"private_training_claimed":false,
        "supervisor":{"child_reaped":true,"network_access":false},"artifacts":[],"model_weights_loaded":true,
        "dataset":{"sha256":hex::encode(Sha256::digest(raw)),"bytes":raw.len(),"visibility":"private_local"},
        "model":{"id":spec.model_id,"revision":spec.revision,
            "files":{"model.safetensors":{"bytes":spec.weights_bytes,"sha256":spec.weights_sha256}}},
        "outputs":[{"sample_index":0,"text":"Inert answer.","text_truncated":false,"generated_tokens":256,
            "generation":{"version":1,"stop_reason":"eos","max_new_tokens":256,"model_profile":"smollm2-360m-v1"}}]})
}

#[test]
fn private_report_binds_input_model_and_distinguishes_incomplete_answers() {
    let raw = input();
    let complete = report(&raw);
    validate_report(&complete, &raw, ModelProfile::Smol360).unwrap();
    assert_eq!(
        summary(&complete, ModelProfile::Smol360).unwrap()["answer_complete"],
        true
    );
    assert!(validate_report(&complete, b"different private input", ModelProfile::Smol360).is_err());
    assert!(validate_report(&complete, &raw, ModelProfile::Default135).is_err());
    for (field, value) in [
        ("private_training_claimed", json!(true)),
        ("distributed_execution_claimed", json!(true)),
        ("artifacts", json!([{}])),
        ("input_adapter", json!({})),
    ] {
        let mut invalid = complete.clone();
        invalid[field] = value;
        assert!(validate_report(&invalid, &raw, ModelProfile::Smol360).is_err());
    }
    for status in ["token_limit", "wire_truncated", "empty"] {
        let mut partial = complete.clone();
        match status {
            "token_limit" => {
                partial["outputs"][0]["generation"]["stop_reason"] = "token_limit".into();
            }
            "wire_truncated" => partial["outputs"][0]["text_truncated"] = true.into(),
            _ => partial["outputs"][0]["text"] = " ".into(),
        }
        validate_report(&partial, &raw, ModelProfile::Smol360).unwrap();
        let result = summary(&partial, ModelProfile::Smol360).unwrap();
        assert_eq!(result["execution_complete"], true);
        assert_eq!(result["answer_complete"], false);
        assert_eq!(result["answer_status"], status);
        assert_eq!(result["output"], partial["outputs"][0]);
    }
}
