//! Signed inert fixtures test purpose/report binding, never model quality or peer execution.
use super::*;
use crate::compute::{Mode, validate_profile_dataset};
use ed25519_dalek::SigningKey;
use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity, publish};

fn fixture(profile: ModelProfile) -> (Vec<u8>, Value) {
    let source = "// Public café\nfn sum(a: i32, b: i32) -> i32 { a - b }\n";
    let root = tempfile::tempdir().unwrap();
    let mut cache = ChunkStore::create(
        &root.path().join("cache"),
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 8,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let manifest = publish(
        &mut source.as_bytes(),
        Publication {
            metadata: Metadata {
                name: "public.rs".into(),
                revision: 1,
                content_type: "text/plain".into(),
            },
            length: source.len() as u64,
            validity: Validity {
                created: 1000,
                expires: 2000,
            },
        },
        &SigningKey::from_bytes(&[27; 32]),
        &mut cache,
    )
    .unwrap()
    .encode();
    let raw = serde_json::to_vec(&json!({"version":6,"visibility":"public","purpose":"code_proposal",
        "license":"GPL-3.0-only","model_profile":profile,"source_manifest_hex":hex::encode(&manifest),
        "inference":[{"question":"Correct this public source.","context":source,"start":0,"end":source.len()}],
        "output_contract":"single_file_replacement_v1"})).unwrap();
    let spec = profile.spec();
    let mut model = json!({"id":spec.model_id,"revision":spec.revision,"files":{}});
    if let Some(files) = profile.sharded_weight_files() {
        for file in files {
            model["files"][file.name] = json!({"bytes":file.bytes,"sha256":file.sha256});
        }
        model["weights"] = json!({"layout":"safetensors_shards_concat_v1","bytes":spec.weights_bytes,
            "sha256":spec.weights_sha256,"files":files[1..].iter().map(|file|file.name).collect::<Vec<_>>()});
    } else {
        model["files"]["model.safetensors"] =
            json!({"bytes":spec.weights_bytes,"sha256":spec.weights_sha256});
    }
    let report = json!({"mode":"public_code_proposal","status":"ok","purpose":"code_proposal",
        "output_contract":"single_file_replacement_v1","proposal_complete":true,"updates_completed":0,
        "artifacts":[],"public_data_only":true,"private_data_supported":false,"model_weights_loaded":true,
        "better_answers_claimed":false,"network_policy_changed":false,"generation_policy":"greedy_v1",
        "dataset":{"sha256":hex::encode(Sha256::digest(&raw)),"bytes":raw.len(),"visibility":"public",
            "license":"GPL-3.0-only","version":6,"purpose":"code_proposal",
            "output_contract":"single_file_replacement_v1",
            "source_manifest_sha256":hex::encode(Sha256::digest(&manifest)),
            "source_sha256":hex::encode(Sha256::digest(source.as_bytes())),"source_bytes":source.len(),"inference_examples":1},
        "model":model,"model_parameter_dtype":"bfloat16","model_attention_backend":"sdpa","prompt_tokens":25,
        "outputs":[{"sample_index":0,"text":"inert unmodified model output","text_truncated":false,
            "generated_tokens":9,"generation":{"version":1,"stop_reason":"eos","max_new_tokens":1024,"model_profile":profile}}]});
    (raw, report)
}

#[test]
fn explicit_public_code_purpose_never_opens_private_or_generic_inference() {
    for profile in [ModelProfile::Qwen600, ModelProfile::Qwen4bInstruct2507] {
        let (raw, report) = fixture(profile);
        validate_profile_dataset(Mode::PublicCodeProposal, false, &raw, profile).unwrap();
        validate_report(&report, &raw, profile).unwrap();
        assert!(validate_profile_dataset(Mode::PublicCodeProposal, true, &raw, profile).is_err());
        assert!(
            validate_profile_dataset(Mode::PublicCodeProposal, false, &raw, ModelProfile::Smol360)
                .is_err()
        );
        for mode in [
            Mode::Infer,
            Mode::PrivateConversation,
            Mode::PrivateInfer,
            Mode::Train,
            Mode::PlanDocument,
            Mode::PlanTasks,
            Mode::AggregateAdapter,
        ] {
            assert!(validate_profile_dataset(mode, false, &raw, profile).is_err());
        }
        let private = br#"{"version":1,"visibility":"private_local","question":"Q?","context":"private canary"}"#;
        assert!(
            validate_profile_dataset(Mode::PublicCodeProposal, false, private, profile).is_err()
        );
    }
}

#[test]
fn public_result_binds_exact_source_profile_purpose_and_original_weights() {
    for profile in [ModelProfile::Qwen600, ModelProfile::Qwen4bInstruct2507] {
        let (raw, report) = fixture(profile);
        for (field, value) in [
            ("mode", json!("private_conversation")),
            ("purpose", json!("question")),
            ("output_contract", json!("execute_shell")),
            ("proposal_complete", json!(false)),
            ("private_data_supported", json!(true)),
            ("public_data_only", json!(false)),
            ("updates_completed", json!(1)),
            ("artifacts", json!(["file"])),
            ("conversation", json!({})),
            ("conversation_limits", json!({})),
            ("baseline_evaluation", json!({})),
            ("input_adapter", json!({})),
            ("generation_policy", json!("sample")),
            ("prompt_tokens", json!(12289)),
            ("model_parameter_dtype", json!("float32")),
            ("model_attention_backend", json!("eager")),
        ] {
            let mut changed = report.clone();
            changed[field] = value;
            assert!(validate_report(&changed, &raw, profile).is_err(), "{field}");
        }
        for field in [
            "sha256",
            "source_sha256",
            "source_manifest_sha256",
            "source_bytes",
            "inference_examples",
        ] {
            let mut changed = report.clone();
            changed["dataset"][field] = json!("wrong");
            assert!(validate_report(&changed, &raw, profile).is_err(), "{field}");
        }
        let mut changed = report.clone();
        changed["model"]["files"] = json!({});
        assert!(validate_report(&changed, &raw, profile).is_err());
        if profile == ModelProfile::Qwen4bInstruct2507 {
            let mut changed = report.clone();
            changed["model"]["weights"]["sha256"] =
                changed["model"]["files"]["model.safetensors.index.json"]["sha256"].clone();
            assert!(validate_report(&changed, &raw, profile).is_err());
        }
    }
}

#[test]
fn incomplete_original_output_is_observable_but_cannot_claim_completion() {
    let profile = ModelProfile::Qwen600;
    let (raw, report) = fixture(profile);
    for variant in ["token_limit", "wire_truncated", "empty"] {
        let mut changed = report.clone();
        match variant {
            "token_limit" => {
                changed["outputs"][0]["generation"]["stop_reason"] = json!("token_limit");
                changed["outputs"][0]["generated_tokens"] = json!(1024);
            }
            "wire_truncated" => changed["outputs"][0]["text_truncated"] = json!(true),
            _ => changed["outputs"][0]["text"] = json!(" \n"),
        }
        assert!(validate_report(&changed, &raw, profile).is_err());
        changed["proposal_complete"] = json!(false);
        validate_report(&changed, &raw, profile).unwrap();
    }
    let mut raw_fenced = report.clone();
    raw_fenced["outputs"][0]["text"] = json!("```rust\nunmodified model output\n```");
    validate_report(&raw_fenced, &raw, profile).unwrap();
    assert_eq!(
        raw_fenced["outputs"][0]["text"],
        "```rust\nunmodified model output\n```"
    );
    raw_fenced["outputs"][0]["text"] = json!("x".repeat(4097));
    assert!(validate_report(&raw_fenced, &raw, profile).is_err());
}
