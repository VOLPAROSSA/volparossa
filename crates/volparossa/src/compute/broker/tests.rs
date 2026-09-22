//! DTO/lifecycle tests use no model execution and never manufacture a successful model result.

use super::*;
use tokio::io::AsyncWriteExt as _;

#[test]
fn execution_failure_diagnostic_preserves_known_typed_and_supervisor_classes() {
    let worker = super::super::supervise::test_worker_failure("BACKEND_IMPORT_FAILED");
    assert_eq!(
        execution_failure_class(&worker),
        ("worker", "BACKEND_IMPORT_FAILED")
    );
    for code in [
        "compute_control_ack_deadline",
        "compute_memory_budget",
        "compute_deadline",
    ] {
        assert_eq!(
            execution_failure_class(&anyhow::anyhow!(code)),
            ("supervisor", code)
        );
    }
}

#[test]
fn execution_failure_diagnostic_redacts_unknown_text_and_unlisted_worker_codes() {
    let private = anyhow::anyhow!("private /home/example/source.json secret prompt");
    assert_eq!(
        execution_failure_class(&private),
        ("supervisor", "supervisor_unknown")
    );
    let disguised = anyhow::anyhow!("compute_backend_failed: BACKEND_IMPORT_FAILED");
    assert_eq!(
        execution_failure_class(&disguised),
        ("supervisor", "supervisor_unknown")
    );
    let worker = super::super::supervise::test_worker_failure("PRIVATE_CONTENT_IN_UPPERCASE");
    assert_eq!(
        execution_failure_class(&worker),
        ("worker", "worker_unknown")
    );
}

#[test]
fn execution_failure_diagnostic_preserves_only_literal_principle_and_decoder_codes() {
    for code in [
        "TASK_GRAPH_DECODER_UNAVAILABLE",
        "TASK_GRAPH_DECODER_VERSION_MISMATCH",
        "TASK_GRAPH_DECODER_NO_ALLOWED_TOKENS",
        "TASK_GRAPH_DECODER_PARSER_FAILED",
        "TASK_GRAPH_DECODER_TOKENIZATION_CHANGED",
        "TASK_GRAPH_DECODER_TOKENIZER_INVALID",
        "TASK_GRAPH_DECODER_ATTEMPT_INVALID",
        "TASK_GRAPH_DECODER_PREFIX_CHANGED",
        "TASK_GRAPH_DECODER_ALLOWED_TOKENS_INVALID",
        "PRINCIPLE_CONTEXT_INVALID",
        "PRINCIPLE_CONTRACT_INVALID",
        "PRINCIPLE_DATASET_FIELDS",
        "PRINCIPLE_GENERATION_FRAMING",
        "PRINCIPLE_GENERATION_PREFIX_CHANGED",
        "PRINCIPLE_OUTPUT_BOUND",
        "PRINCIPLE_OUTPUT_FIELDS",
        "PRINCIPLE_OUTPUT_INVALID",
        "PRINCIPLE_OUTPUT_OUTCOME",
        "PRINCIPLE_OUTPUT_REASONING",
        "PRINCIPLE_OUTPUT_SOURCE_QUOTE",
        "PRINCIPLE_OUTPUT_TEXT",
        "PRINCIPLE_OUTPUT_UNCERTAINTY",
        "PRINCIPLE_PROFILE_INFERENCE_ONLY",
        "PRINCIPLE_QUOTE_BOUND",
    ] {
        let worker = super::super::supervise::test_worker_failure(code);
        assert_eq!(execution_failure_class(&worker), ("worker", code));
        // Matching text without a correlated, reaped worker reply is not typed evidence.
        assert_eq!(
            execution_failure_class(&anyhow::anyhow!(code)),
            ("supervisor", "supervisor_unknown")
        );
    }
    for code in [
        "PRINCIPLE_PRIVATE_PAYLOAD",
        "TASK_GRAPH_DECODER_SECRET_SOURCE",
        "PRINCIPLE_OUTPUT_INVALID_PRIVATE_TEXT",
    ] {
        let worker = super::super::supervise::test_worker_failure(code);
        assert_eq!(
            execution_failure_class(&worker),
            ("worker", "worker_unknown")
        );
    }
}

fn data() -> String {
    serde_json::json!({"version":1,"visibility":"public","license":"GPL-3.0-only",
        "source_revision":"a".repeat(40),"train":[],
        "heldout":[{"question":"What is tested?","context":"This is a protocol fixture, not an ML result.","answer":"The local protocol."}],
        "inference":[{"question":"What is tested?","context":"This is a protocol fixture."}]
    }).to_string()
}

// These protocol-only tests do not claim publication authenticity; the network
// provider verifies the real original signed source before forwarding a Submit.
fn publication() -> compute::PublicDataset {
    compute::PublicDataset {
        publisher_key: "c".repeat(64),
        manifest_hex: "ab".repeat(64),
        dataset_json: data(),
    }
}

fn binding() -> JobBinding {
    JobBinding {
        job_id: "1".repeat(32),
        dataset_manifest_id: "2".repeat(64),
        dataset_sha256: sha(data().as_bytes()),
        model_fingerprint: "3".repeat(64),
        row_indices: vec![2],
        expires_unix_seconds: 1600,
        task: None,
    }
}

pub(super) fn request(operation: Operation) -> Request {
    Request {
        version: compute::VERSION,
        request_id: "a".repeat(32),
        requester_key: "b".repeat(64),
        operation,
    }
}

pub(super) fn broker(root: &Path) -> Broker {
    Broker {
        options: Serve {
            model_profile: ModelProfile::default(),
            principle_inference_v4: false,
            runtime_root: root.join("runtime"),
            model_root: root.join("model"),
            adapter_root: None,
            serving_directory: None,
            work_root: root.to_owned(),
            socket: root.join("broker.sock"),
            execute: false,
        },
        capabilities: Capabilities {
            model: ModelIdentity {
                model_id: MODEL_ID.into(),
                model_revision: MODEL_REVISION.into(),
                base_weights: FileIdentity {
                    bytes: 269_060_552,
                    sha256: hex::encode(BASE_MODEL_SHA256),
                },
                adapter_files: None,
            },
            model_fingerprint: binding().model_fingerprint,
            accepting_work: true,
            public_inference_only: true,
            runtime_slots: 1,
            max_threads: 2,
            max_job_seconds: 600,
            max_dataset_bytes: compute::MAX_DATASET_BYTES as u64,
            max_rows: 4,
            task_derivation_v1: true,
            document_inference_v2: false,
            principle_inference_v4: false,
            derived_inference_v3: false,
            successor_activation_v1: false,
        },
        jobs: VecDeque::new(),
        budget: Budget::fixed_for_test(Decision::Run),
        successor: None,
        initial_base: successors::InitialBase::Unknown,
        next_successor_check: tokio::time::Instant::now(),
    }
}

#[test]
fn larger_profile_rejects_multiple_rows_before_creating_a_job() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    broker.options.model_profile = ModelProfile::Smol360;
    broker.capabilities.max_rows = 1;
    let spec = ModelProfile::Smol360.spec();
    broker.capabilities.model = ModelIdentity {
        model_id: spec.model_id.into(),
        model_revision: spec.revision.into(),
        base_weights: FileIdentity {
            bytes: spec.weights_bytes,
            sha256: spec.weights_sha256.into(),
        },
        adapter_files: None,
    };
    broker.capabilities.model_fingerprint =
        sha(&serde_json::to_vec(&broker.capabilities.model).unwrap());
    let mut submit = Submit {
        binding: binding(),
        dataset_json: data(),
        publication: publication(),
    };
    submit.binding.model_fingerprint = broker.capabilities.model_fingerprint.clone();
    let mut dataset: Value = serde_json::from_str(&submit.dataset_json).unwrap();
    dataset["inference"].as_array_mut().unwrap().push(serde_json::json!({"question":"Second question?","context":"Another public protocol fixture."}));
    submit.dataset_json = dataset.to_string();
    submit.binding.dataset_sha256 = sha(submit.dataset_json.as_bytes());
    submit.binding.row_indices = vec![0, 1];
    assert_eq!(
        broker.submit("b", &submit, 1000),
        Outcome::Error(ErrorCode::Invalid)
    );
    assert!(broker.jobs.is_empty());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[test]
fn larger_profile_rejects_135m_successor_directory_before_service_start() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    broker.options.model_profile = ModelProfile::Smol360;
    broker.options.serving_directory = Some(root.path().join("selected"));
    assert_eq!(
        validate_roots(&broker.options).unwrap_err().to_string(),
        "compute_profile_inference_only"
    );
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

// Retention fixtures are cancelled protocol jobs, never manufactured model results.
pub(super) fn terminal_job(index: usize) -> Job {
    let mut original = binding();
    original.job_id = format!("{:032x}", index + 1);
    let (activity, _) = watch::channel(false);
    Job {
        requester: "b".repeat(64),
        status: JobStatus {
            binding: original,
            state: JobState::Cancelled,
            cancellation_requested: true,
            report_json: None,
            report_sha256: None,
            error: None,
        },
        activity,
        execution: None,
        terminal_retain_until: Some(1600),
        directory: None,
        retained_bytes: JOB_RECORD_BYTES,
    }
}

#[tokio::test]
async fn sixteen_terminal_receipts_do_not_block_new_work_or_change_original_leases() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    broker.jobs.extend((0..16).map(terminal_job));
    let originals: Vec<_> = broker.jobs.iter().map(|job| job.status.clone()).collect();
    let caps = broker.handle(request(Operation::Capabilities), 1000).await;
    assert!(matches!(caps.outcome, Outcome::Capabilities(caps) if caps.accepting_work));
    for original in &originals {
        assert_eq!(
            broker
                .handle(request(Operation::Poll(original.binding.clone())), 1500)
                .await
                .outcome,
            Outcome::Job(original.clone())
        );
    }
    let mut next = binding();
    next.job_id = "4".repeat(32);
    // Admission passes history checks, then fails at the deliberately absent runtime.
    // No host model is invoked and no successful inference receipt is fabricated.
    assert!(matches!(
        broker
            .handle(
                request(Operation::Submit(Submit {
                    binding: next,
                    dataset_json: data(),
                    publication: publication(),
                })),
                1500,
            )
            .await
            .outcome,
        Outcome::Error(ErrorCode::Unavailable)
    ));
    assert_eq!(broker.jobs.len(), 16);
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    assert_eq!(
        broker
            .handle(
                request(Operation::Submit(Submit {
                    binding: originals[0].binding.clone(),
                    dataset_json: data(),
                    publication: publication(),
                })),
                1599,
            )
            .await
            .outcome,
        Outcome::Job(originals[0].clone())
    );
    assert!(broker.jobs.iter().all(|job| {
        job.terminal_retain_until == Some(1600) && job.status.binding.expires_unix_seconds == 1600
    }));
    broker.refresh(1600).await;
    assert!(broker.jobs.is_empty());
}

#[tokio::test]
async fn retained_count_and_bytes_reserve_the_next_job_and_fail_closed() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    broker.jobs.extend((0..RETAINED_JOBS).map(terminal_job));
    let original = broker.jobs[0].status.clone();
    let caps = broker.handle(request(Operation::Capabilities), 1000).await;
    assert!(matches!(caps.outcome, Outcome::Capabilities(caps) if !caps.accepting_work));
    let submit = request(Operation::Submit(Submit {
        binding: binding(),
        dataset_json: data(),
        publication: publication(),
    }));
    assert!(matches!(
        broker.handle(submit.clone(), 1000).await.outcome,
        Outcome::Error(ErrorCode::Busy)
    ));
    assert_eq!(
        broker
            .handle(request(Operation::Poll(original.binding.clone())), 1000)
            .await
            .outcome,
        Outcome::Job(original)
    );
    broker.jobs.truncate(1);
    broker.jobs[0].retained_bytes = MAX_RETAINED_BYTES - JOB_RESERVATION_BYTES;
    assert!(broker.available());
    broker.jobs[0].retained_bytes += 1;
    assert!(!broker.available());
    assert!(matches!(
        broker.handle(submit, 1000).await.outcome,
        Outcome::Error(ErrorCode::Busy)
    ));
    broker.jobs[0].retained_bytes = u64::MAX;
    assert!(!broker.available());
    assert_eq!(broker.jobs[0].terminal_retain_until, Some(1600));
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn reaped_accounting_keeps_owned_files_and_releases_only_unused_reservation() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    let directory = tempfile::tempdir_in(root.path()).unwrap();
    let path = directory.path().to_owned();
    fs::write(path.join("dataset.json"), b"retained public input").unwrap();
    fs::create_dir(path.join("output")).unwrap();
    fs::write(path.join("output/diagnostic"), b"bounded diagnostic").unwrap();
    let mut job = terminal_job(0);
    job.status.state = JobState::Running;
    job.status.cancellation_requested = false;
    job.terminal_retain_until = None;
    job.directory = Some(directory);
    job.retained_bytes = JOB_RESERVATION_BYTES;
    job.execution = Some(tokio::spawn(async {
        anyhow::bail!("protocol task failed")
    }));
    broker.jobs.push_back(job);
    assert!(!broker.available());
    tokio::task::yield_now().await;
    broker.refresh(1000).await;
    assert_eq!(broker.jobs[0].status.state, JobState::Failed);
    assert_eq!(
        broker.jobs[0].retained_bytes,
        JOB_RECORD_BYTES
            + b"retained public input".len() as u64
            + b"bounded diagnostic".len() as u64
    );
    assert!(broker.available());
    assert!(path.join("dataset.json").is_file());
    assert!(path.join("output/diagnostic").is_file());
    assert_eq!(broker.jobs[0].terminal_retain_until, Some(1600));
    broker.refresh(1600).await;
    assert!(broker.jobs.is_empty());
    assert!(!path.exists());
}

#[test]
fn retained_accounting_does_not_follow_unknown_file_types() {
    let root = tempfile::tempdir().unwrap();
    let directory = tempfile::tempdir_in(root.path()).unwrap();
    std::os::unix::fs::symlink(root.path(), directory.path().join("outside")).unwrap();
    let mut job = terminal_job(0);
    job.directory = Some(directory);
    assert!(retained_job_bytes(&job).is_err());
    job.retained_bytes = retained_job_bytes(&job).unwrap_or(MAX_RETAINED_BYTES);
    let mut broker = broker(root.path());
    broker.jobs.push_back(job);
    assert!(!broker.available());
    assert_eq!(broker.jobs[0].terminal_retain_until, Some(1600));
}

#[tokio::test]
async fn pressure_admission_refuses_work_without_spawning_or_touching_job_files() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    for decision in [Decision::Pause, Decision::Cancel] {
        broker.budget = Budget::fixed_for_test(decision);
        let caps = broker.handle(request(Operation::Capabilities), 1000).await;
        assert!(matches!(caps.outcome, Outcome::Capabilities(caps) if !caps.accepting_work));
        let result = broker
            .handle(
                request(Operation::Submit(Submit {
                    binding: binding(),
                    dataset_json: data(),
                    publication: publication(),
                })),
                1000,
            )
            .await;
        assert!(matches!(result.outcome, Outcome::Error(ErrorCode::Busy)));
        assert!(broker.jobs.is_empty());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    }
    broker.budget = Budget::fixed_for_test(Decision::Run);
    let caps = broker.handle(request(Operation::Capabilities), 1000).await;
    assert!(matches!(caps.outcome, Outcome::Capabilities(caps) if caps.accepting_work));
}

#[tokio::test]
async fn derived_task_requires_advertised_capability_and_exact_bound_inference_question() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    let caps = broker.handle(request(Operation::Capabilities), 1000).await;
    assert!(matches!(caps.outcome, Outcome::Capabilities(caps) if caps.task_derivation_v1));
    let mut submit = Submit {
        binding: binding(),
        dataset_json: data(),
        publication: publication(),
    };
    submit.binding.task = Some(compute::PublicTask::AnswerPublicQuestionV1 {
        question: "What is tested?".into(),
    });
    broker.capabilities.task_derivation_v1 = false;
    assert!(matches!(
        broker
            .handle(request(Operation::Submit(submit.clone())), 1000)
            .await
            .outcome,
        Outcome::Error(ErrorCode::Invalid)
    ));
    broker.capabilities.task_derivation_v1 = true;
    submit.binding.task = Some(compute::PublicTask::SummarizeContextsV1 {});
    assert!(matches!(
        broker
            .handle(request(Operation::Submit(submit.clone())), 1000)
            .await
            .outcome,
        Outcome::Error(ErrorCode::Invalid)
    ));
    submit.binding.task = Some(compute::PublicTask::AnswerPublicQuestionV1 {
        question: "What is tested?".into(),
    });
    // Exact public instructions pass cheap admission, but no absent runtime becomes a fake model result.
    assert!(matches!(
        broker
            .handle(request(Operation::Submit(submit)), 1000)
            .await
            .outcome,
        Outcome::Error(ErrorCode::Unavailable)
    ));
    assert!(broker.jobs.is_empty());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn strict_rpc_roundtrip_rejects_extra_fields_oversize_and_wrong_correlation() {
    let expected = request(Operation::Submit(Submit {
        binding: binding(),
        dataset_json: data(),
        publication: publication(),
    }));
    expected.validate(1000).unwrap();
    let (mut client, mut server) = tokio::io::duplex(4096);
    let sending = expected.clone();
    let sender = tokio::spawn(async move {
        compute::write_request(&mut client, &sending).await.unwrap();
        client
    });
    assert_eq!(compute::read_request(&mut server).await.unwrap(), expected);
    let mut client = sender.await.unwrap();
    let response = Response {
        version: compute::VERSION,
        request_id: expected.request_id.clone(),
        outcome: Outcome::Error(ErrorCode::Busy),
    };
    compute::write_response(&mut server, &response)
        .await
        .unwrap();
    assert_eq!(
        compute::read_response(&mut client, &expected.request_id)
            .await
            .unwrap(),
        response
    );
    compute::write_response(&mut server, &response)
        .await
        .unwrap();
    assert!(
        compute::read_response(&mut client, &"c".repeat(32))
            .await
            .is_err()
    );
    let mut invalid = serde_json::to_value(&expected).unwrap();
    invalid["command"] = "must never execute".into();
    assert!(serde_json::from_value::<Request>(invalid).is_err());
    let duplicate = serde_json::to_string(&expected).unwrap().replacen(
        "\"version\":1",
        "\"version\":1,\"version\":1",
        1,
    );
    assert!(serde_json::from_str::<Request>(&duplicate).is_err());
    let mut invalid = expected;
    invalid.requester_key = "0".repeat(64);
    assert!(invalid.validate(1000).is_err());
    server
        .write_u32(u32::try_from(compute::MAX_RESPONSE_BYTES + 1).unwrap())
        .await
        .unwrap();
    assert!(
        compute::read_response(&mut client, &response.request_id)
            .await
            .is_err()
    );
}

fn signed_document_fixture() -> (String, String, String) {
    use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity, publish};

    let source_root = tempfile::tempdir().unwrap();
    let mut cache = ChunkStore::create(
        &source_root.path().join("cache"),
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 8,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let publisher = ed25519_dalek::SigningKey::from_bytes(&[31; 32]);
    let context = "One explicitly public document excerpt.";
    let signed = publish(
        &mut context.as_bytes(),
        Publication {
            metadata: Metadata {
                name: "broker-document".into(),
                revision: 1,
                content_type: "text/plain".into(),
            },
            length: context.len() as u64,
            validity: Validity {
                created: 1000,
                expires: 2000,
            },
        },
        &publisher,
        &mut cache,
    )
    .unwrap();
    (
        context.into(),
        hex::encode(signed.encode()),
        hex::encode(publisher.verifying_key().as_bytes()),
    )
}

#[tokio::test]
async fn document_profile_requires_explicit_capability_before_any_worker_admission() {
    let (context, manifest, _) = signed_document_fixture();
    let document = serde_json::json!({"version":2,"visibility":"public","license":"CC0-1.0",
        "source_manifest_hex":manifest,"inference":[{
            "question":"What is tested?","context":context,"start":0,"end":context.len()}]})
    .to_string();
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    let mut submit = Submit {
        binding: binding(),
        dataset_json: document.clone(),
        publication: publication(),
    };
    submit.binding.dataset_sha256 = sha(document.as_bytes());
    submit.publication.dataset_json = document;
    // The broker trusts only its same-UID agent boundary for the outer publication;
    // this checks actual local admission without claiming network authentication or ML.
    assert!(!broker.capabilities.document_inference_v2);
    assert!(matches!(
        broker
            .handle(request(Operation::Submit(submit.clone())), 1000)
            .await
            .outcome,
        Outcome::Error(ErrorCode::Invalid)
    ));
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    broker.capabilities.document_inference_v2 = true;
    assert!(matches!(
        broker
            .handle(request(Operation::Submit(submit)), 1000)
            .await
            .outcome,
        Outcome::Error(ErrorCode::Unavailable)
    ));
    assert!(broker.jobs.is_empty());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn synthesis_requires_its_own_capability_and_exact_generated_context_before_any_worker() {
    let (original, manifest, provider) = signed_document_fixture();
    let text = "Generated summary, not an original-source quotation.";
    let derived = serde_json::json!({"version":3,"visibility":"public","license":"CC0-1.0",
        "source_manifest_hex":manifest,"level":1,
        "claim_scope":volparossa_content::provider::compute::dataset::DERIVED_CLAIM_SCOPE,
        "inference":[{"question":"What is tested?","context":format!("{text}\n"),"inputs":[{
            "text":text,"provider_key":provider,"job_id":"1".repeat(32),"report_sha256":"2".repeat(64),
            "package_manifest_id":"3".repeat(64),"model_fingerprint":"4".repeat(64),
            "output_index":0,"parent_index":0,"source_start":0,"source_end":original.len(),
            "piece_start":0,"piece_end":text.len()+1}]}]});
    let json = derived.to_string();
    dataset::validate(&json, 1).unwrap();
    assert!(dataset::validate(&json, 2).is_err());
    let mut changed = derived.clone();
    changed["inference"][0]["context"] = "Invented context".into();
    assert!(dataset::validate(&changed.to_string(), 1).is_err());
    changed = derived;
    changed["train"] = serde_json::json!([]);
    assert!(dataset::validate(&changed.to_string(), 1).is_err());
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    broker.capabilities.document_inference_v2 = true;
    let mut submit = Submit {
        binding: binding(),
        dataset_json: json.clone(),
        publication: publication(),
    };
    submit.binding.dataset_sha256 = sha(json.as_bytes());
    submit.publication.dataset_json = json;
    assert!(!broker.capabilities.derived_inference_v3);
    assert!(matches!(
        broker
            .handle(request(Operation::Submit(submit.clone())), 1000)
            .await
            .outcome,
        Outcome::Error(ErrorCode::Invalid)
    ));
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    broker.capabilities.derived_inference_v3 = true;
    // Only the fixed Infer path is admitted. Its deliberately absent runtime must
    // remain unavailable; this protocol test never invents a model result.
    assert!(matches!(
        broker
            .handle(request(Operation::Submit(submit)), 1000)
            .await
            .outcome,
        Outcome::Error(ErrorCode::Unavailable)
    ));
    assert!(broker.jobs.is_empty());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[tokio::test]
async fn public_admission_refuses_bad_hash_private_rows_wrong_model_and_expired_job() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    let mut submit = Submit {
        binding: binding(),
        dataset_json: data(),
        publication: publication(),
    };
    submit.binding.dataset_sha256 = "d".repeat(64);
    assert!(matches!(
        broker
            .handle(request(Operation::Submit(submit.clone())), 1000)
            .await
            .outcome,
        Outcome::Error(ErrorCode::Invalid)
    ));
    submit.dataset_json = submit.dataset_json.replace("\"public\"", "\"private\"");
    submit.binding.dataset_sha256 = sha(submit.dataset_json.as_bytes());
    assert!(matches!(
        broker
            .handle(request(Operation::Submit(submit.clone())), 1000)
            .await
            .outcome,
        Outcome::Error(ErrorCode::Invalid)
    ));
    submit.dataset_json = data();
    submit.binding.dataset_sha256 = sha(submit.dataset_json.as_bytes());
    submit.binding.model_fingerprint = "e".repeat(64);
    assert!(matches!(
        broker
            .handle(request(Operation::Submit(submit.clone())), 1000)
            .await
            .outcome,
        Outcome::Error(ErrorCode::ModelMismatch)
    ));
    submit.binding = binding();
    assert!(matches!(
        broker
            .handle(request(Operation::Submit(submit.clone())), 1600)
            .await
            .outcome,
        Outcome::Error(ErrorCode::Expired)
    ));
    assert!(
        request(Operation::Submit(submit.clone()))
            .validate(999)
            .is_err()
    );
    submit.binding.row_indices = vec![2, 1];
    assert!(request(Operation::Submit(submit)).validate(1000).is_err());
    // Correctly typed public work cannot produce a success when the configured runtime
    // is absent. This fails before execute/spawn and performs no host model execution.
    assert!(matches!(
        broker
            .handle(
                request(Operation::Submit(Submit {
                    binding: binding(),
                    dataset_json: data(),
                    publication: publication(),
                })),
                1000
            )
            .await
            .outcome,
        Outcome::Error(ErrorCode::Unavailable)
    ));
    assert!(broker.jobs.is_empty());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One task-ownership lifecycle preserves admission, cancellation and cleanup ordering"
)]
async fn owner_and_full_binding_gate_cancel_slot_and_cleanup_after_task_returns() {
    let root = tempfile::tempdir().unwrap();
    let sentinel = root.path().join("unrelated-owner-file");
    fs::write(&sentinel, b"keep").unwrap();
    let mut broker = broker(root.path());
    let directory = tempfile::Builder::new()
        .prefix("compute-job-")
        .tempdir_in(root.path())
        .unwrap();
    let directory_path = directory.path().to_owned();
    let (activity, mut receiver) = watch::channel(true);
    // This tests ownership of a cancellable task only, not subprocess/model execution.
    let execution = tokio::spawn(async move {
        while *receiver.borrow() {
            receiver.changed().await?;
        }
        anyhow::bail!("compute_owner_busy")
    });
    broker.jobs.push_back(Job {
        requester: "b".repeat(64),
        status: JobStatus {
            binding: binding(),
            state: JobState::Running,
            cancellation_requested: false,
            report_json: None,
            report_sha256: None,
            error: None,
        },
        activity,
        execution: Some(execution),
        terminal_retain_until: None,
        directory: Some(directory),
        retained_bytes: JOB_RESERVATION_BYTES,
    });
    let caps = broker.handle(request(Operation::Capabilities), 1000).await;
    assert!(matches!(
        caps.outcome,
        Outcome::Capabilities(Capabilities {
            accepting_work: false,
            ..
        })
    ));
    let mut foreign = request(Operation::Cancel(binding()));
    foreign.requester_key = "c".repeat(64);
    assert!(matches!(
        broker.handle(foreign, 1000).await.outcome,
        Outcome::Error(ErrorCode::Missing)
    ));
    let mut wrong = binding();
    wrong.row_indices = vec![1];
    assert!(matches!(
        broker
            .handle(request(Operation::Cancel(wrong)), 1000)
            .await
            .outcome,
        Outcome::Error(ErrorCode::Missing)
    ));
    assert!(*broker.jobs[0].activity.borrow());
    let mut changed_task = binding();
    changed_task.task = Some(compute::PublicTask::AnswerPublicQuestionV1 {
        question: "What is tested?".into(),
    });
    for operation in [
        Operation::Poll(changed_task.clone()),
        Operation::Cancel(changed_task),
    ] {
        assert!(matches!(
            broker.handle(request(operation), 1000).await.outcome,
            Outcome::Error(ErrorCode::Missing)
        ));
    }
    assert!(*broker.jobs[0].activity.borrow());
    let repeated = broker
        .handle(
            request(Operation::Submit(Submit {
                binding: binding(),
                dataset_json: data(),
                publication: publication(),
            })),
            1000,
        )
        .await;
    assert!(matches!(
        repeated.outcome,
        Outcome::Job(JobStatus {
            state: JobState::Running,
            ..
        })
    ));
    assert_eq!(broker.jobs.len(), 1);
    let mut another = binding();
    another.job_id = "4".repeat(32);
    let competing = request(Operation::Submit(Submit {
        binding: another,
        dataset_json: data(),
        publication: publication(),
    }));
    assert!(matches!(
        broker.handle(competing, 1000).await.outcome,
        Outcome::Error(ErrorCode::Busy)
    ));
    let response = broker
        .handle(request(Operation::Cancel(binding())), 1000)
        .await;
    assert!(matches!(
        response.outcome,
        Outcome::Job(JobStatus {
            state: JobState::Running,
            cancellation_requested: true,
            ..
        })
    ));
    assert!(!broker.available());
    tokio::task::yield_now().await;
    broker.refresh(1001).await;
    assert_eq!(broker.jobs[0].status.state, JobState::Cancelled);
    assert!(broker.jobs[0].status.report_json.is_none());
    assert!(broker.available());
    assert!(directory_path.exists());
    broker.refresh(1600).await;
    assert!(broker.jobs.is_empty());
    assert!(!directory_path.exists());
    assert_eq!(fs::read(&sentinel).unwrap(), b"keep");
}

#[test]
fn shutdown_socket_guard_never_unlinks_an_operator_replacement() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("broker.sock");
    let listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let info = fs::symlink_metadata(&path).unwrap();
    let guard = SocketGuard {
        path: path.clone(),
        device: info.dev(),
        inode: info.ino(),
    };
    drop(listener);
    fs::remove_file(&path).unwrap();
    fs::write(&path, b"replacement owned by the operator").unwrap();
    drop(guard);
    assert_eq!(
        fs::read(path).unwrap(),
        b"replacement owned by the operator"
    );
}

#[tokio::test]
async fn expired_owner_can_observe_cancel_while_task_is_still_being_reaped() {
    let root = tempfile::tempdir().unwrap();
    let mut broker = broker(root.path());
    let directory = tempfile::Builder::new()
        .prefix("compute-job-")
        .tempdir_in(root.path())
        .unwrap();
    let path = directory.path().to_owned();
    let (activity, mut receiver) = watch::channel(true);
    let (release, terminated) = tokio::sync::oneshot::channel();
    // A controlled task-lifecycle sentinel, not a model process or successful inference.
    let execution = tokio::spawn(async move {
        while *receiver.borrow() {
            receiver.changed().await?;
        }
        terminated.await?;
        anyhow::bail!("compute_owner_busy")
    });
    broker.jobs.push_back(Job {
        requester: "b".repeat(64),
        status: JobStatus {
            binding: binding(),
            state: JobState::Running,
            cancellation_requested: false,
            report_json: None,
            report_sha256: None,
            error: None,
        },
        activity,
        execution: Some(execution),
        terminal_retain_until: None,
        directory: Some(directory),
        retained_bytes: JOB_RESERVATION_BYTES,
    });
    for operation in [Operation::Poll(binding()), Operation::Cancel(binding())] {
        let response = broker.handle(request(operation), 1600).await;
        assert!(matches!(
            response.outcome,
            Outcome::Job(JobStatus {
                state: JobState::Running,
                cancellation_requested: true,
                report_json: None,
                ..
            })
        ));
    }
    assert!(path.exists());
    assert!(!broker.available());
    let mut foreign = request(Operation::Cancel(binding()));
    foreign.requester_key = "c".repeat(64);
    assert!(matches!(
        broker.handle(foreign, 1600).await.outcome,
        Outcome::Error(ErrorCode::Missing)
    ));
    release.send(()).unwrap();
    tokio::task::yield_now().await;
    broker.refresh(1601).await;
    let expected = broker.jobs[0].status.clone();
    assert_eq!(expected.state, JobState::Cancelled);
    assert_eq!(expected.binding, binding());
    assert!(expected.report_json.is_none());
    assert_eq!(broker.jobs[0].terminal_retain_until, Some(1661));
    assert!(path.exists());
    assert!(broker.available());
    for operation in [Operation::Poll(binding()), Operation::Cancel(binding())] {
        assert_eq!(
            broker.handle(request(operation), 1660).await.outcome,
            Outcome::Job(expected.clone())
        );
        assert_eq!(broker.jobs[0].terminal_retain_until, Some(1661));
    }
    assert!(matches!(
        broker
            .handle(
                request(Operation::Submit(Submit {
                    binding: binding(),
                    dataset_json: data(),
                    publication: publication(),
                })),
                1660
            )
            .await
            .outcome,
        Outcome::Error(ErrorCode::Expired)
    ));
    assert!(matches!(
        broker
            .handle(request(Operation::Poll(binding())), 1661)
            .await
            .outcome,
        Outcome::Error(ErrorCode::Missing)
    ));
    assert!(!path.exists());
}
