//! Native signed-source and synthetic report fixtures, not model execution proof.

use clap::Parser;
use serde_json::json;
use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity};

use super::*;

fn owner() -> (tempfile::TempDir, Options, Store) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let mut arguments = vec![
        "volparossa".to_owned(),
        "compute".into(),
        "train-loop".into(),
    ];
    for (flag, name) in [
        ("--plan", "plan.json"),
        ("--directory", "coordinator"),
        ("--runtime-root", "absent-runtime"),
        ("--model-root", "absent-model"),
        ("--cache", "absent-cache"),
    ] {
        arguments.push(flag.into());
        arguments.push(root.path().join(name).to_str().unwrap().into());
    }
    let cli = crate::Cli::try_parse_from(arguments).unwrap();
    let crate::CliCommand::Compute {
        command: crate::compute::Command::TrainLoop(options),
    } = cli.command
    else {
        panic!("loop args")
    };
    let store = Store::open(
        &options.directory,
        &json!({"synthetic_validation_fixture":true}),
        false,
    )
    .unwrap();
    (root, *options, store)
}

fn source_fixture(root: &Path) -> PublicInput {
    make_directory(root).unwrap();
    let key = ed25519_dalek::SigningKey::from_bytes(&[42; 32]);
    let dataset=json!({"version":1,"visibility":"public","license":"GPL-3.0-only","source_revision":"b".repeat(40),
        "train":[],"heldout":[{"question":"What is this separate source?","context":"This is synthetic validation data.","answer":"A public fixture."}],
        "inference":[{"question":"Was a model run by this test?","context":"No model is run by these pure tests."}]}).to_string();
    let temporary = tempfile::tempdir().unwrap();
    let mut cache = ChunkStore::create(
        &temporary.path().join("cache"),
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 8,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let at = now().unwrap();
    let signed = volparossa_content::publish(
        &mut dataset.as_bytes(),
        Publication {
            metadata: Metadata {
                name: "explicit-validation".into(),
                revision: 1,
                content_type: volparossa_content::provider::compute::dataset::CONTENT_TYPE.into(),
            },
            length: dataset.len() as u64,
            validity: Validity {
                created: at - 60,
                expires: at + 1200,
            },
        },
        &key,
        &mut cache,
    )
    .unwrap();
    let verified = signed.verify(&key.verifying_key(), at).unwrap();
    let manifest = signed.encode();
    let provenance = Provenance {
        version: 1,
        selection: Source {
            publisher_key: hex::encode(key.verifying_key().as_bytes()),
            name: "explicit-validation".into(),
            min_revision: Some(1),
            manifest_id: Some(hex::encode(verified.manifest_id())),
        },
        manifest_id: hex::encode(verified.manifest_id()),
        verified_at_unix_seconds: at - 1,
        expires_unix_seconds: at + 1200,
        dataset: identity(dataset.as_bytes()),
        manifest: identity(&manifest),
        source_receipt: json!({"synthetic_fixture_only":true}),
    };
    write_new(&root.join("dataset.json"), dataset.as_bytes()).unwrap();
    write_new(&root.join("dataset.manifest"), &manifest).unwrap();
    write_json(&root.join("provenance.json"), &provenance).unwrap();
    load_input(root).unwrap()
}

fn stage_fixture(cycle: &Path, input: &PublicInput, name: &str, loss: f64) -> Stage {
    make_directory(&cycle.join("validation").join(name)).unwrap();
    let training: Value = serde_json::from_slice(
        &read_owned(&cycle.join("training-report.json"), 32 * 1024).unwrap(),
    )
    .unwrap();
    let mut report = json!({"version":1,"kind":"result","id":hex::encode([8;16]),"status":"ok","mode":"infer","device":"cpu",
        "updates_completed":0,"artifacts":[],"elapsed_ms":5,
        "model":{"id":MODEL_ID,"revision":MODEL_REVISION,"files":{"model.safetensors":{"sha256":hex::encode(BASE_MODEL_SHA256),"bytes":269_060_552}}},
        "dataset":{"sha256":input.provenance.dataset.sha256,"bytes":input.provenance.dataset.bytes,"source_revision":input.source_revision,
        "visibility":"public","license":"GPL-3.0-only"},"baseline_evaluation":{"loss":loss,"target_tokens":8}});
    if name == "candidate" {
        let files: Files = ADAPTER_FILES
            .into_iter()
            .map(|(name, limit)| {
                (
                    name.into(),
                    identity(
                        &read_owned(&cycle.join("training/adapter").join(name), limit).unwrap(),
                    ),
                )
            })
            .collect();
        report["input_adapter"] = json!({"model_id":MODEL_ID,"model_revision":MODEL_REVISION,"applied":true,"files":files,
            "applied_parameters":training["adapter_after"],"base_parameters_before_apply":training["base_before"],"base_parameters_after_apply":training["base_before"]});
    }
    write_json(
        &cycle.join(format!("validation/{name}/report.json")),
        &report,
    )
    .unwrap();
    report["supervisor"] = json!({"deadline_seconds":10,"child_reaped":true,"network_access":false,"spare_capacity":true});
    let at = now().unwrap();
    let stage = Stage {
        version: 1,
        started_at_unix_seconds: at - 1,
        verified_at_unix_seconds: at,
        deadline_unix_seconds: at + 9,
        report,
    };
    write_json(&cycle.join(format!("{name}-report.json")), &stage).unwrap();
    stage
}

fn overwrite(path: &Path, value: &impl Serialize) {
    // Test-only tampering of a known fixture; production always writes once.
    fs::write(path, serde_json::to_vec(value).unwrap()).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

#[test]
fn signed_second_source_and_exact_inference_receipts_survive_store_reopen() {
    let (_root, args, store) = owner();
    super::super::evaluation::fixture(&store, 1, true);
    let cycle = store.cycle_path(1).unwrap();
    let input = source_fixture(&cycle.join("validation"));
    stage_fixture(&cycle, &input, "baseline", 2.0);
    stage_fixture(&cycle, &input, "candidate", 1.5);
    let record = recompute(&store, 1).unwrap();
    assert!(record.approved);
    assert_eq!(record.files.len(), 13);
    store
        .write_cycle_json(
            1,
            "validation.json",
            &serde_json::to_value(&record).unwrap(),
        )
        .unwrap();
    drop(store);
    let reopened = Store::open(
        &args.directory,
        &json!({"synthetic_validation_fixture":true}),
        true,
    )
    .unwrap();
    assert_eq!(verify(&reopened, 1).unwrap(), record);
    let mut changed = record.clone();
    changed.approved = false;
    overwrite(&cycle.join("validation.json"), &changed);
    assert!(verify(&reopened, 1).is_err());
    overwrite(&cycle.join("validation.json"), &record);
    let mut data: Value = serde_json::from_slice(&input.bytes).unwrap();
    data["heldout"][0]["answer"] = "changed public answer".into();
    overwrite(&cycle.join("validation/dataset.json"), &data);
    assert!(verify(&reopened, 1).is_err());
}

#[tokio::test]
async fn completed_stage_is_reused_without_runtime_and_partial_stage_is_retained() {
    let (_root, args, store) = owner();
    super::super::evaluation::fixture(&store, 1, true);
    let cycle = store.cycle_path(1).unwrap();
    let input = source_fixture(&cycle.join("validation"));
    stage_fixture(&cycle, &input, "baseline", 2.0);
    let expiry = store.read_cycle_json(1, "result.json").unwrap()["source_expires_unix_seconds"]
        .as_u64()
        .unwrap();
    let (_sender, activity) = watch::channel(true);
    run_stage(&args, &cycle, &input, expiry, "baseline", None, &activity)
        .await
        .unwrap();
    assert!(!args.runtime_root.exists() && !args.model_root.exists());
    let partial = cycle.join("validation/candidate");
    make_directory(&partial).unwrap();
    let error = run_stage(
        &args,
        &cycle,
        &input,
        expiry,
        "candidate",
        Some(&cycle.join("training/adapter")),
        &activity,
    )
    .await
    .unwrap_err()
    .to_string();
    assert_eq!(error, "train_validation_interrupted_stage_retained");
    assert!(partial.is_dir() && !cycle.join("candidate-report.json").exists());
    assert!(!args.runtime_root.exists() && !args.model_root.exists());
}

#[tokio::test]
async fn inherited_authority_bounds_validation_even_when_both_signed_sources_live_longer() {
    let (_root, args, store) = owner();
    super::super::evaluation::fixture(&store, 1, true);
    let cycle = store.cycle_path(1).unwrap();
    let input = source_fixture(&cycle.join("validation"));
    let prepared = args.directory.join("validation-input");
    make_directory(&prepared).unwrap();
    for (name, limit) in SOURCE_FILES {
        write_new(
            &prepared.join(name),
            &read_owned(&cycle.join("validation").join(name), limit).unwrap(),
        )
        .unwrap();
    }
    let mut state = State::new(1);
    state.validation = Some(snapshot(&prepared).unwrap());
    let baseline = stage_fixture(&cycle, &input, "baseline", 2.0);
    let candidate = stage_fixture(&cycle, &input, "candidate", 1.5);
    // Legacy receipts fit both original signed sources. These are inert reports,
    // not model execution or proof that any adapter improves actual answers.
    assert!(recompute(&store, 1).unwrap().approved);
    let authority = baseline
        .deadline_unix_seconds
        .min(candidate.deadline_unix_seconds)
        - 1;
    assert!(baseline.verified_at_unix_seconds < authority);
    assert!(candidate.verified_at_unix_seconds < authority);
    let mut result = store.read_cycle_json(1, "result.json").unwrap();
    assert!(authority < result["source_expires_unix_seconds"].as_u64().unwrap());
    assert!(authority < input.provenance.expires_unix_seconds);
    result["authority_expires_unix_seconds"] = authority.into();
    overwrite(&cycle.join("result.json"), &result);
    assert_eq!(
        recompute(&store, 1).unwrap_err().to_string(),
        "train_validation_stage_expiry"
    );
    let (_sender, activity) = watch::channel(true);
    assert_eq!(
        assess(&args, &store, &state, 1, &activity)
            .await
            .unwrap_err()
            .to_string(),
        "train_validation_stage_expiry"
    );
    assert!(!cycle.join("validation.json").exists());
    // The same completed byte-bound receipts are accepted with stage deadlines
    // actually inside the inherited authority, without starting a worker.
    for (name, mut stage) in [("baseline", baseline), ("candidate", candidate)] {
        stage.deadline_unix_seconds = authority;
        stage.report["supervisor"]["deadline_seconds"] =
            (authority - stage.started_at_unix_seconds).into();
        overwrite(&cycle.join(format!("{name}-report.json")), &stage);
    }
    assert!(
        assess(&args, &store, &state, 1, &activity)
            .await
            .unwrap()
            .approved
    );
    assert!(verify(&store, 1).unwrap().approved);
    assert!(!args.runtime_root.exists() && !args.model_root.exists());
}

#[test]
fn missing_manifest_training_rows_invalid_metrics_and_changed_candidate_are_rejected() {
    let (_root, _args, store) = owner();
    super::super::evaluation::fixture(&store, 1, true);
    let cycle = store.cycle_path(1).unwrap();
    let input = source_fixture(&cycle.join("validation"));
    let mut selected = input.provenance.selection.clone();
    selected.manifest_id = None;
    assert!(validate_selection(&selected).is_err());
    let mut source = input.provenance.clone();
    source.selection.publisher_key = hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[9; 32])
            .verifying_key()
            .as_bytes(),
    );
    assert!(validate_source(&input.bytes, &input.manifest, &source).is_err());
    for value in [
        json!({"loss":-1.0,"target_tokens":8}),
        json!({"loss":null,"target_tokens":8}),
        json!({"loss":2.0,"target_tokens":0}),
        json!({"loss":2.0,"target_tokens":8,"extra":0}),
    ] {
        assert!(metric(&value).is_err());
    }
    assert!(metric(&json!({"loss":0.0,"target_tokens":8})).is_ok());
    stage_fixture(&cycle, &input, "baseline", 2.0);
    let mut candidate = stage_fixture(&cycle, &input, "candidate", 2.0);
    assert!(!recompute(&store, 1).unwrap().approved);
    candidate.report["baseline_evaluation"]["target_tokens"] = 9.into();
    overwrite(&cycle.join("candidate-report.json"), &candidate);
    let mut raw = candidate.report.clone();
    raw.as_object_mut().unwrap().remove("supervisor");
    overwrite(&cycle.join("validation/candidate/report.json"), &raw);
    assert!(recompute(&store, 1).is_err());
    candidate.report["baseline_evaluation"]["target_tokens"] = 8.into();
    candidate.report["input_adapter"]["applied_parameters"]["sha256"] = hex::encode([8; 32]).into();
    overwrite(&cycle.join("candidate-report.json"), &candidate);
    let mut raw = candidate.report.clone();
    raw.as_object_mut().unwrap().remove("supervisor");
    overwrite(&cycle.join("validation/candidate/report.json"), &raw);
    assert!(recompute(&store, 1).is_err());
}
