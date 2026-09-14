//! Synthetic loss/checkpoint fixtures, never evidence that a model ran or improved.

use std::{
    fs,
    os::unix::fs::{DirBuilderExt, PermissionsExt},
    path::PathBuf,
};

use serde_json::json;
use volparossa_content::{
    CacheLimits, ChunkStore, Metadata, Publication, Validity, agent_artifact::AdapterFiles,
};

use super::*;

fn write(path: &Path, bytes: &[u8]) {
    fs::write(path, bytes).unwrap();
    fs::set_permissions(path, fs::Permissions::from_mode(0o600)).unwrap();
}

fn write_json(path: &Path, value: &Value) {
    write(path, &serde_json::to_vec(value).unwrap());
}

/// Create native signed source/bundle and structurally realistic local reports.
/// Adapter bytes and metrics are explicit parser fixtures, not executable weights.
pub(in crate::compute::train_loop) fn fixture(store: &Store, sequence: u64, approved: bool) {
    fixture_input(store, sequence, approved, None, None);
}

struct PublicSource {
    publisher: String,
    at: u64,
    dataset: String,
    manifest: Vec<u8>,
    manifest_id: [u8; 32],
    provenance: Value,
}

fn public_source(sequence: u64) -> PublicSource {
    let authority = ed25519_dalek::SigningKey::from_bytes(&[43; 32]);
    let publisher = hex::encode(authority.verifying_key().as_bytes());
    let at = now().unwrap();
    let dataset = json!({"version":1,"visibility":"public","license":"GPL-3.0-only","source_revision":"a".repeat(40),
        "train":[{"question":"What is this?","context":"Public synthetic fixture only.","answer":"A fixture."}],
        "heldout":[{"question":"Was a model run?","context":"No model is run by this test.","answer":"No."}],
        "inference":[{"question":"What is tested?","context":"Pure receipt binding."}]}).to_string();
    let cache_root = tempfile::tempdir().unwrap();
    let mut cache = ChunkStore::create(
        &cache_root.path().join("cache"),
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 8,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let publication = volparossa_content::publish(
        &mut dataset.as_bytes(),
        Publication {
            metadata: Metadata {
                name: "public-a".into(),
                revision: sequence,
                content_type: volparossa_content::provider::compute::dataset::CONTENT_TYPE.into(),
            },
            length: dataset.len() as u64,
            validity: Validity {
                created: at,
                expires: at + 1200,
            },
        },
        &authority,
        &mut cache,
    )
    .unwrap();
    let verified = publication.verify(&authority.verifying_key(), at).unwrap();
    let id = hex::encode(verified.manifest_id());
    let manifest = publication.encode();
    let provenance = json!({"version":1,"publisher_key":publisher,"dataset_name":"public-a","dataset_manifest_id":id,
        "signed_manifest_sha256":identity(&manifest).sha256,"dataset_sha256":identity(dataset.as_bytes()).sha256,
        "dataset_bytes":dataset.len(),"expires_unix_seconds":at+1200,"verified_at_unix_seconds":at,
        "source_receipt":{"synthetic_fixture_only":true}});
    PublicSource {
        publisher,
        at,
        dataset,
        manifest,
        manifest_id: *verified.manifest_id(),
        provenance,
    }
}

pub(in crate::compute::train_loop) fn fixture_input(
    store: &Store,
    sequence: u64,
    approved: bool,
    predecessor: Option<u64>,
    input: Option<&Path>,
) {
    let root = store.cycle_path(sequence).unwrap();
    for path in [
        &root,
        &root.join("training"),
        &root.join("training/adapter"),
    ] {
        fs::DirBuilder::new().mode(0o700).create(path).unwrap();
    }
    let PublicSource {
        publisher,
        at,
        dataset,
        manifest,
        manifest_id,
        provenance: source,
    } = public_source(sequence);
    let id = hex::encode(manifest_id);
    let config = b"{\"opaque_adapter_fixture_not_executable\":true}";
    let weights = format!("opaque weight fixture for cycle {sequence}, not a model").into_bytes();
    let readme = b"Synthetic parser fixture; no model training performed.\n";
    let bundle = AdapterBundle::encode(
        manifest_id,
        AdapterFiles {
            config: config.to_vec(),
            weights: weights.clone(),
            readme: readme.to_vec(),
        },
    )
    .unwrap();
    let base = json!({"sha256":hex::encode([4;32]),"parameters":134_000_000});
    let mut before = json!({"sha256":hex::encode([5;32]),"parameters":230_400});
    let after = json!({"sha256":identity(&weights).sha256,"parameters":230_400});
    let mut input_report = None;
    if let Some(path) = input {
        let mut files = Identities::new();
        for (name, limit) in ADAPTER_FILES {
            files.insert(
                name.into(),
                identity(&read_file(&path.join(name), limit).unwrap()),
            );
        }
        before = json!({"sha256":files["adapter_model.safetensors"].sha256,"parameters":230_400});
        input_report = Some(
            json!({"model_id":MODEL_ID,"model_revision":MODEL_REVISION,"files":files,
            "applied_parameters":before,"base_parameters_before_apply":base,"base_parameters_after_apply":base,"applied":true}),
        );
    }
    let artifacts = [("README.md", readme.as_slice()), ("adapter_config.json", config.as_slice()),
        ("adapter_model.safetensors", weights.as_slice())].into_iter().map(|(name, bytes)|
        json!({"relative_path":format!("adapter/{name}"),"bytes":bytes.len(),"sha256":identity(bytes).sha256})).collect::<Vec<_>>();
    let mut report = json!({"version":1,"kind":"result","id":hex::encode([7;16]),"status":"ok","mode":"train",
        "model":{"id":MODEL_ID,"revision":MODEL_REVISION,"files":{"model.safetensors":{"sha256":hex::encode(BASE_MODEL_SHA256),"bytes":269_060_552}}},
        "dataset":{"sha256":identity(dataset.as_bytes()).sha256,"bytes":dataset.len(),"source_revision":"a".repeat(40),"visibility":"public","license":"GPL-3.0-only"},
        "updates_completed":8,"base_before":base,"base_after":base,"reloaded_base":base,
        "adapter_before":before,"adapter_after":after,"reloaded_adapter":after,
        "base_weights_unchanged":true,"adapter_weights_changed":true,"checkpoint_reloaded":true,
        "baseline_evaluation":{"loss":2.0,"target_tokens":8},
        "adapted_evaluation":{"loss":if approved {1.5} else {2.1},"target_tokens":8},
        "reloaded_evaluation":{"loss":if approved {1.5} else {2.1},"target_tokens":8},"artifacts":artifacts});
    if let Some(value) = &input_report {
        report["input_adapter"] = value.clone();
    }
    write_json(&root.join("training/report.json"), &report);
    report["supervisor"] = json!({"child_reaped":true,"network_access":false});
    let raw_report = serde_json::to_vec(&report).unwrap();
    let result = json!({"version":1,"operation":"compute_train_cycle","complete":true,
        "dataset_manifest_id":id,"dataset_sha256":identity(dataset.as_bytes()).sha256,"source_receipt":source["source_receipt"],
        "source_expires_unix_seconds":at+1200,"updates_completed":8,"input_adapter_applied":input.is_some(),"input_adapter":input_report,
        "training_report_sha256":identity(&raw_report).sha256,
        "bundle":{"dataset_manifest_id":id,"sha256":identity(&bundle).sha256,"bytes":bundle.len()}});
    write_json(
        &root.join("selection.json"),
        &json!({"publisher_key":publisher,"dataset_name":"public-a","adapter_root":input}),
    );
    write(&root.join("dataset.json"), dataset.as_bytes());
    write(&root.join("dataset.manifest"), &manifest);
    write_json(&root.join("source-provenance.json"), &source);
    write(&root.join("training-report.json"), &raw_report);
    write_json(&root.join("result.json"), &result);
    write(&root.join("adapter.bundle"), &bundle);
    write(&root.join("training/adapter/adapter_config.json"), config);
    write(
        &root.join("training/adapter/adapter_model.safetensors"),
        &weights,
    );
    write(&root.join("training/adapter/README.md"), readme);
    let record = assess(store, sequence, predecessor, input).unwrap();
    assert_eq!(record.approved, approved);
    store
        .write_cycle_json(
            sequence,
            "evaluation.json",
            &serde_json::to_value(record).unwrap(),
        )
        .unwrap();
}

fn owner() -> (tempfile::TempDir, PathBuf, Store) {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("coordinator");
    let store = Store::open(&path, &json!({"synthetic_evaluation_fixture":1}), false).unwrap();
    (root, path, store)
}

#[test]
fn approved_and_rejected_structured_checkpoints_survive_real_store_reopen() {
    let (_root, path, store) = owner();
    fixture(&store, 1, true);
    fixture(&store, 2, false);
    assert!(verify(&store, 1).unwrap().approved);
    assert!(!verify(&store, 2).unwrap().approved);
    let snapshot = store.snapshot_cycle(1).unwrap();
    drop(store);
    let reopened = Store::open(&path, &json!({"synthetic_evaluation_fixture":1}), true).unwrap();
    assert!(verify(&reopened, 1).unwrap().approved);
    reopened.validate_snapshot(1, &snapshot).unwrap();
    let result_path = reopened.cycle_path(1).unwrap().join("result.json");
    let mut result = reopened.read_cycle_json(1, "result.json").unwrap();
    result["dataset_sha256"] = hex::encode([9; 32]).into();
    write_json(&result_path, &result);
    assert!(verify(&reopened, 1).is_err());
}

#[test]
fn warmstart_binds_actual_input_and_verifies_after_predecessor_pruning() {
    let (_root, _path, store) = owner();
    fixture(&store, 1, true);
    let adapter = store.cycle_path(1).unwrap().join("training/adapter");
    fixture_input(&store, 2, true, Some(1), Some(&adapter));
    assert_eq!(verify(&store, 2).unwrap().predecessor, Some(1));
    assert!(assess(&store, 2, Some(1), None).is_err());
    write(
        &adapter.join("adapter_config.json"),
        b"changed input fixture",
    );
    assert!(assess(&store, 2, Some(1), Some(&adapter)).is_err());
    assert!(store.prune_sequence(1).unwrap());
    assert!(verify(&store, 2).unwrap().approved);
    let root = store.cycle_path(2).unwrap();
    let mut changed = store.read_cycle_json(2, "evaluation.json").unwrap();
    changed["predecessor"] = 2.into();
    write_json(&root.join("evaluation.json"), &changed);
    assert!(verify(&store, 2).is_err());
}

#[test]
fn finite_equal_heldout_tokens_and_actual_reloaded_improvement_are_required() {
    let metric = |loss| Metric {
        loss,
        target_tokens: 8,
    };
    assert!(improvement(metric(2.0), metric(1.5), metric(1.5)).unwrap());
    assert!(!improvement(metric(2.0), metric(2.0), metric(2.0)).unwrap());
    assert!(!improvement(metric(2.0), metric(2.1), metric(2.1)).unwrap());
    assert!(!improvement(metric(2.0), metric(2.0 - 2e-6), metric(2.0)).unwrap());
    assert!(!improvement(metric(0.0), metric(0.0), metric(0.0)).unwrap());
    assert!(improvement(metric(2.0), metric(0.0), metric(0.0)).unwrap());
    for bad in [f64::NAN, f64::INFINITY, f64::NEG_INFINITY, -0.1] {
        assert!(improvement(metric(2.0), metric(bad), metric(bad)).is_err());
    }
    assert!(improvement(metric(2.0), metric(1.5), metric(1.4)).is_err());
    assert!(
        improvement(
            metric(2.0),
            metric(1.5),
            Metric {
                loss: 1.5,
                target_tokens: 7
            }
        )
        .is_err()
    );
    assert!(
        improvement(
            Metric {
                loss: 2.0,
                target_tokens: 0
            },
            metric(1.5),
            metric(1.5)
        )
        .is_err()
    );
}

#[test]
fn edited_decision_or_retained_candidate_bytes_cannot_reuse_a_receipt() {
    let (_root, _path, store) = owner();
    fixture(&store, 1, false);
    let root = store.cycle_path(1).unwrap();
    let original = store.read_cycle_json(1, "evaluation.json").unwrap();
    let mut changed = original.clone();
    changed["approved"] = true.into();
    write_json(&root.join("evaluation.json"), &changed);
    assert!(verify(&store, 1).is_err());
    write_json(&root.join("evaluation.json"), &original);
    write(
        &root.join("training/adapter/adapter_model.safetensors"),
        b"different opaque parser fixture",
    );
    assert!(verify(&store, 1).is_err());
}
