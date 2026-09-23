//! Local CLI packaging and typed local-stream checks: opaque bytes and synthetic reports
//! do not prove actual training, safe tensors, useful models or overlay retrieval.

use clap::Parser;
use ed25519_dalek::SigningKey;
use tokio::net::UnixListener;
use volparossa_content::agent_artifact::{BASE_MODEL_SHA256, MODEL_ID, MODEL_REVISION};
use volparossa_content::transfer::{TransferLimits, serve_peer};
use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentReceipt, ControlResponse, ControlResult,
    NamedContentTransferReady, control_request::Operation, control_response::Payload, read_request,
    write_response,
};

use super::*;

const CONFIG: &[u8] = br#"{"synthetic_pack_fixture":true}"#;
const WEIGHTS: &[u8] = b"opaque pack fixture, not actual model tensors";
const README: &[u8] = b"Synthetic package test; no training or model execution occurred.\n";

struct Fixture {
    _root: tempfile::TempDir,
    args: Pack,
    report: Value,
    manifest_id: [u8; 32],
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    let directory = root.path().join("adapter");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    let artifacts = [
        ("README.md", README),
        ("adapter_config.json", CONFIG),
        ("adapter_model.safetensors", WEIGHTS),
    ]
    .map(|(name, bytes)| {
        write_new(&directory.join(name), bytes).unwrap();
        serde_json::json!({"relative_path":format!("adapter/{name}"),
                          "bytes":bytes.len(), "sha256":hex::encode(Sha256::digest(bytes))})
    });
    let source_revision = "d".repeat(40);
    let dataset = serde_json::to_vec(&serde_json::json!({
        "version":1, "visibility":"public", "license":"GPL-3.0-only",
        "source_revision":source_revision,
        "train":[{"question":"What is this?", "answer":"A public fixture.",
                  "context":"This is a public fixture."}],
        "heldout":[{"question":"Is this a private input?", "answer":"No.",
                    "context":"This is a public fixture."}],
        "inference":[{"question":"What is this?", "context":"This is a public fixture."}]
    }))
    .unwrap();
    let signer = SigningKey::from_bytes(&[31; 32]);
    let mut cache = ChunkStore::create(
        &root.path().join("cache"),
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 16,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let now = now_seconds().unwrap();
    let envelope = volparossa_content::publish(
        &mut dataset.as_slice(),
        Publication {
            metadata: Metadata {
                name: "public-dataset-fixture".to_owned(),
                revision: 1,
                content_type: DATASET_CONTENT_TYPE.to_owned(),
            },
            length: u64::try_from(dataset.len()).unwrap(),
            validity: Validity {
                created: now,
                expires: now + 3600,
            },
        },
        &signer,
        &mut cache,
    )
    .unwrap();
    let verified = envelope.verify(&signer.verifying_key(), now).unwrap();
    let manifest_path = root.path().join("dataset.manifest");
    write_new(&manifest_path, &envelope.encode()).unwrap();
    let report = serde_json::json!({
        "version":1,"id":"1".repeat(32),"kind":"result","status":"ok","mode":"train","device":"cpu",
        "updates_completed":8, "base_weights_unchanged":true,"adapter_weights_changed":true,
        "checkpoint_reloaded":true,"model":{"id":MODEL_ID,"revision":MODEL_REVISION,
          "files":{"model.safetensors":{"bytes":269_060_552,"sha256":hex::encode(BASE_MODEL_SHA256)}}},
        "dataset":{"visibility":"public","license":"GPL-3.0-only", "source_revision":source_revision,
                   "bytes":dataset.len(),"sha256":hex::encode(Sha256::digest(&dataset))},
        "artifacts":artifacts,
        "synthetic_test_report_not_training_evidence":true
    });
    let report_path = root.path().join("synthetic-report.json");
    write_new(&report_path, &serde_json::to_vec(&report).unwrap()).unwrap();
    let args = Pack {
        directory,
        training_report: report_path,
        dataset_manifest: manifest_path,
        publisher_key: signer.verifying_key(),
        output: root.path().join("adapter.bundle"),
    };
    Fixture {
        _root: root,
        args,
        report,
        manifest_id: *verified.manifest_id(),
    }
}

#[test]
fn packs_exact_files_bound_to_real_signed_dataset_without_overwriting() {
    let fixture = fixture();
    let report = pack(&fixture.args).unwrap();
    let encoded = fs::read(&fixture.args.output).unwrap();
    let bundle = AdapterBundle::decode(encoded.clone()).unwrap();
    assert_eq!(bundle.dataset_manifest_id(), fixture.manifest_id);
    assert_eq!(bundle.config(), CONFIG);
    assert_eq!(bundle.weights(), WEIGHTS);
    assert_eq!(bundle.readme(), README);
    assert_eq!(report["bytes"], encoded.len());
    assert_eq!(report["sha256"], hex::encode(Sha256::digest(&encoded)));
    assert_eq!(
        report["dataset_manifest_id"],
        hex::encode(fixture.manifest_id)
    );
    assert_eq!(report["content_type"], ADAPTER_CONTENT_TYPE);
    assert_eq!(report["network_published"], false);
    assert_eq!(report["model_activated"], false);
    assert_eq!(report["model_quality_proven"], false);
    assert_eq!(report["training_report_is_publisher_supplied"], true);
    assert_eq!(
        fs::metadata(&fixture.args.output).unwrap().mode() & 0o777,
        0o600
    );
    assert!(pack(&fixture.args).is_err());
    assert_eq!(fs::read(&fixture.args.output).unwrap(), encoded);
}

#[test]
fn wrong_dataset_report_or_publisher_cannot_produce_a_bundle() {
    let mut fixture = fixture();
    for field in ["bytes", "sha256"] {
        let mut invalid = fixture.report.clone();
        invalid["dataset"][field] = if field == "bytes" {
            serde_json::json!(1)
        } else {
            serde_json::json!("0".repeat(64))
        };
        fs::write(
            &fixture.args.training_report,
            serde_json::to_vec(&invalid).unwrap(),
        )
        .unwrap();
        let error = pack(&fixture.args).unwrap_err().to_string();
        assert_eq!(error, "agent_artifact_training_dataset_mismatch");
        assert!(!fixture.args.output.exists());
    }
    fs::write(
        &fixture.args.training_report,
        serde_json::to_vec(&fixture.report).unwrap(),
    )
    .unwrap();
    fixture.args.publisher_key = SigningKey::from_bytes(&[32; 32]).verifying_key();
    assert!(pack(&fixture.args).is_err());
    assert!(!fixture.args.output.exists());
}

#[test]
fn changed_file_or_extra_file_cannot_match_the_supplied_training_report() {
    let fixture = fixture();
    fs::write(
        fixture.args.directory.join("adapter_model.safetensors"),
        b"changed fixture weights",
    )
    .unwrap();
    assert_eq!(
        pack(&fixture.args).unwrap_err().to_string(),
        "agent_artifact_report_hash"
    );
    assert!(!fixture.args.output.exists());
    fs::write(
        fixture.args.directory.join("adapter_model.safetensors"),
        WEIGHTS,
    )
    .unwrap();
    write_new(
        &fixture.args.directory.join("worker.py"),
        b"not an accepted artifact member",
    )
    .unwrap();
    assert_eq!(
        pack(&fixture.args).unwrap_err().to_string(),
        "agent_artifact_file_set"
    );
    assert!(!fixture.args.output.exists());
}

#[test]
fn another_base_model_report_cannot_be_relabelled_as_the_fixed_profile() {
    let fixture = fixture();
    for field in ["id", "revision", "weight_sha256"] {
        let mut invalid = fixture.report.clone();
        if field == "weight_sha256" {
            invalid["model"]["files"]["model.safetensors"]["sha256"] = "0".repeat(64).into();
        } else {
            invalid["model"][field] = "another-model-or-revision".into();
        }
        fs::write(
            &fixture.args.training_report,
            serde_json::to_vec(&invalid).unwrap(),
        )
        .unwrap();
        assert_eq!(
            pack(&fixture.args).unwrap_err().to_string(),
            "agent_artifact_training_base_model"
        );
        assert!(!fixture.args.output.exists());
    }
}

#[test]
fn fetch_does_not_force_offline_cache_and_explicit_cache_only_requires_reopen() {
    let publisher = hex::encode(SigningKey::from_bytes(&[31; 32]).verifying_key().to_bytes());
    let base = [
        "volparossa",
        "content",
        "agent",
        "fetch",
        "--publisher-key",
        &publisher,
        "--name",
        "public-adapter",
        "--dataset-name",
        "public-data",
        "--cache",
        "cache",
        "--output",
        "new-output",
    ];
    let parsed = crate::Cli::try_parse_from(base).unwrap();
    let crate::CliCommand::Content { command } = parsed.command else {
        panic!("content expected")
    };
    let crate::content::Command::Agent(Command::Fetch(options)) = *command else {
        panic!("agent fetch expected")
    };
    assert!(!options.cache_only);
    assert!(!options.reuse_cache);
    assert!(!options.query(false, false, Path::new("parent")).cache_only);
    assert!(crate::Cli::try_parse_from(base.into_iter().chain(["--cache-only"])).is_err());
    let parsed =
        crate::Cli::try_parse_from(base.into_iter().chain(["--cache-only", "--reuse-cache"]))
            .unwrap();
    let crate::CliCommand::Content { command } = parsed.command else {
        panic!("content expected")
    };
    let crate::content::Command::Agent(Command::Fetch(options)) = *command else {
        panic!("agent fetch expected")
    };
    assert!(options.cache_only && options.reuse_cache);
}

async fn serve_import_object(
    listener: &UnixListener,
    store: &mut ChunkStore,
    args: &Fetch,
    signed: &SignedManifest,
    dataset_id: Option<[u8; 32]>,
    mismatched: bool,
) {
    let dataset = dataset_id.is_some();
    let key = if dataset {
        args.dataset_publisher()
    } else {
        args.publisher_key
    };
    let manifest = signed.verify(&key, now_seconds().unwrap()).unwrap();
    let (mut stream, _) = listener.accept().await.unwrap();
    let request = read_request(&mut stream).await.unwrap();
    let Some(Operation::ContentFetchName(parameters)) = request.operation else {
        panic!("expected typed adapter/dataset query");
    };
    assert!(parameters.prefer_cached && parameters.reuse_cache);
    assert_eq!(parameters.cache_only, args.cache_only);
    assert_eq!(parameters.publisher_key, key.to_bytes());
    assert_eq!(
        parameters.name,
        if dataset {
            &args.dataset_name
        } else {
            &args.name
        }
        .as_str()
    );
    assert_eq!(
        parameters.min_revision,
        if dataset { None } else { Some(9) }
    );
    assert_eq!(
        parameters.expected_manifest_id,
        dataset_id.map(|id| id.to_vec())
    );
    assert_eq!(
        parameters.expected_content_type.as_deref(),
        Some(if dataset {
            DATASET_CONTENT_TYPE
        } else {
            ADAPTER_CONTENT_TYPE
        })
    );
    assert_eq!(
        parameters.max_object_bytes,
        Some(if dataset {
            MAX_DATASET
        } else {
            MAX_ADAPTER_BYTES as u64
        })
    );
    let response = |code: &str, payload| ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        result: ControlResult::Ok as i32,
        diagnostic_code: code.into(),
        payload: Some(payload),
    };
    write_response(
        &mut stream,
        &response(
            "NAMED_CONTENT_TRANSFER_READY",
            Payload::NamedContentTransferReady(NamedContentTransferReady {
                manifest: signed.encode(),
                cache_only: args.cache_only,
            }),
        ),
    )
    .await
    .unwrap();
    if mismatched {
        // The consumer must reject a different signed dataset before receiving its body.
        return;
    }
    let progress = serve_peer(&mut stream, &manifest, store, TransferLimits::default())
        .await
        .unwrap();
    assert_eq!(progress.bytes, manifest.length());
    write_response(
        &mut stream,
        &response(
            "CONTENT_OK",
            Payload::Content(ContentReceipt {
                bytes: manifest.length(),
                chunks: u32::try_from(manifest.chunks().len()).unwrap(),
                // Actual local Unix delivery only: do not invent network/provider byte receipts.
                ..ContentReceipt::default()
            }),
        ),
    )
    .await
    .unwrap();
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "Keep signed fixtures and both typed stream exchanges together"
)]
async fn typed_import_prefers_valid_cache_without_forcing_offline_and_pins_exact_dataset() {
    for (cache_only, wrong_dataset) in [(false, false), (true, false), (false, true)] {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let limits = CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 16,
            min_free_bytes: 0,
        };
        let mut store = ChunkStore::create(&root.path().join("source"), limits).unwrap();
        let dataset_key = SigningKey::from_bytes(&[31; 32]);
        let adapter_key = SigningKey::from_bytes(&[32; 32]);
        let now = now_seconds().unwrap();
        let mut publish =
            |name: &str, content_type: &str, revision, mut bytes: &[u8], key: &SigningKey| {
                let length = bytes.len() as u64;
                volparossa_content::publish(
                    &mut bytes,
                    Publication {
                        metadata: Metadata {
                            name: name.into(),
                            revision,
                            content_type: content_type.into(),
                        },
                        length,
                        validity: Validity {
                            created: now,
                            expires: now + 300,
                        },
                    },
                    key,
                    &mut store,
                )
                .unwrap()
            };
        let bytes = serde_json::to_vec(&serde_json::json!({"version":1,"visibility":"public",
            "license":"GPL-3.0-only","source_revision":"d".repeat(40)}))
        .unwrap();
        let original = publish("public-data", DATASET_CONTENT_TYPE, 1, &bytes, &dataset_key);
        let dataset_id = *original
            .verify(&dataset_key.verifying_key(), now)
            .unwrap()
            .manifest_id();
        let offered = if wrong_dataset {
            publish("public-data", DATASET_CONTENT_TYPE, 2, &bytes, &dataset_key)
        } else {
            original
        };
        let bundle = AdapterBundle::encode(
            dataset_id,
            AdapterFiles {
                config: CONFIG.to_vec(),
                weights: WEIGHTS.to_vec(),
                readme: README.to_vec(),
            },
        )
        .unwrap();
        let signed_adapter = publish(
            "public-adapter",
            ADAPTER_CONTENT_TYPE,
            9,
            &bundle,
            &adapter_key,
        );
        let socket = root.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let args = Fetch {
            publisher_key: adapter_key.verifying_key(),
            dataset_publisher_key: Some(dataset_key.verifying_key()),
            name: "public-adapter".into(),
            dataset_name: "public-data".into(),
            min_revision: Some(9),
            cache: root.path().join("consumer-cache"),
            reuse_cache: true,
            cache_only,
            output: root.path().join("import"),
            limits: Limits {
                quota_bytes: 1024 * 1024,
                max_entries: 16,
                min_free_bytes: 0,
            },
        };
        let result = tokio::time::timeout(std::time::Duration::from_secs(10), async {
            tokio::try_join!(fetch(&args, &socket), async {
                serve_import_object(&listener, &mut store, &args, &signed_adapter, None, false)
                    .await;
                serve_import_object(
                    &listener,
                    &mut store,
                    &args,
                    &offered,
                    Some(dataset_id),
                    wrong_dataset,
                )
                .await;
                Ok::<(), anyhow::Error>(())
            })
        })
        .await
        .expect("bounded typed import fixture")
        .map(|(report, ())| report);
        if wrong_dataset {
            assert!(
                result
                    .unwrap_err()
                    .to_string()
                    .contains("explicitly selected bounded object")
            );
            assert!(!args.output.exists());
            continue;
        }
        let result = result.unwrap();
        assert_eq!(result["cache_only"], cache_only);
        assert_eq!(result["expires_unix_seconds"], now + 300);
        assert_eq!(result["dataset_manifest_id"], hex::encode(dataset_id));
        for receipt in ["adapter_receipt", "dataset_receipt"] {
            assert_eq!(result[receipt]["peer_bytes"], 0);
            assert_eq!(result[receipt]["cache_only"], cache_only);
            assert_eq!(result[receipt]["globally_latest"], false);
        }
        assert_eq!(
            fs::read(args.output.join("adapter/adapter_model.safetensors")).unwrap(),
            WEIGHTS
        );
        assert_eq!(fs::read(args.output.join("dataset.json")).unwrap(), bytes);
    }
}
