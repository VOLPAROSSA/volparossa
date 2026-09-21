//! Real signed provider framing and protected Unix I/O; no model execution is simulated.

mod derived;
mod eligibility;

use super::*;
use ed25519_dalek::SigningKey;
use std::{os::unix::fs::PermissionsExt as _, time::Duration};
use tokio::{net::UnixListener, sync::watch};
use volparossa_config::{Config, RolesConfig, RuntimeMode};
use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity, publish};
use volparossa_local_control::compute::{
    ErrorCode, FileIdentity, JobBinding, ModelIdentity, PublicDataset, Submit,
};
use volparossa_metrics::MetricsRegistry;
use volparossa_policy::{DestinationRule, ProtocolPort, TransportProtocol};
use volparossa_test_support::verified_development_manifest;

fn capabilities() -> Capabilities {
    let model = ModelIdentity {
        model_id: MODEL_ID.into(),
        model_revision: MODEL_REVISION.into(),
        base_weights: FileIdentity {
            bytes: 269_060_552,
            sha256: hex::encode(BASE_MODEL_SHA256),
        },
        adapter_files: None,
    };
    let model_fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&model).unwrap()));
    Capabilities {
        model,
        model_fingerprint,
        accepting_work: true,
        public_inference_only: true,
        runtime_slots: 1,
        max_threads: 2,
        max_job_seconds: 600,
        max_dataset_bytes: 1024 * 1024,
        max_rows: 4,
        task_derivation_v1: true,
        document_inference_v2: false,
        derived_inference_v3: false,
    }
}

fn original() -> String {
    serde_json::json!({"version":1,"visibility":"public","license":"GPL-3.0-only","source_revision":"a".repeat(40),"train":[],
        "heldout":[{"question":"What is this?","context":"Public test data.","answer":"A protocol fixture."}],
        "inference":[{"question":"First?","context":"Public first sample."},{"question":"Second?","context":"Public second sample."}]
    }).to_string()
}

fn request(root: &Path, publisher: &SigningKey, requester: &SigningKey) -> Request {
    let json = original();
    let mut cache = ChunkStore::create(
        &root.join("cache"),
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 8,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let signed = publish(
        &mut json.as_bytes(),
        Publication {
            metadata: Metadata {
                name: "public-agent-test".into(),
                revision: 1,
                content_type: dataset::CONTENT_TYPE.into(),
            },
            length: json.len() as u64,
            validity: Validity {
                created: now() - 1,
                expires: now() + 600,
            },
        },
        publisher,
        &mut cache,
    )
    .unwrap();
    let source =
        dataset::verify_source(&signed.encode(), &publisher.verifying_key(), &json, now()).unwrap();
    let derived = source.derive(&[1]).unwrap();
    Request {
        version: rpc::VERSION,
        request_id: "a".repeat(32),
        requester_key: hex::encode(requester.verifying_key().as_bytes()),
        operation: Operation::Submit(Submit {
            binding: JobBinding {
                job_id: "b".repeat(32),
                dataset_manifest_id: hex::encode(source.manifest_id()),
                dataset_sha256: hex::encode(Sha256::digest(derived.as_bytes())),
                model_fingerprint: capabilities().model_fingerprint,
                row_indices: vec![1],
                expires_unix_seconds: now() + 300,
                task: None,
            },
            dataset_json: derived,
            publication: PublicDataset {
                publisher_key: hex::encode(publisher.verifying_key().as_bytes()),
                manifest_hex: hex::encode(signed.encode()),
                dataset_json: json,
            },
        }),
    }
}

fn state() -> Arc<RwLock<AgentState>> {
    let roles = RolesConfig {
        client: false,
        relay: true,
        exit: false,
    };
    let config = Config {
        runtime_mode: RuntimeMode::Development,
        roles,
        ..Config::default()
    };
    let policy = verified_development_manifest(
        unix_millis(),
        vec![
            DestinationRule::exact_domain(
                "provider.example",
                [ProtocolPort::new(TransportProtocol::Tcp, 18080).unwrap()],
            )
            .unwrap(),
        ],
    )
    .unwrap();
    Arc::new(RwLock::new(
        AgentState::new(&config, roles, Some(policy), MetricsRegistry::new()).unwrap(),
    ))
}

fn attachment(
    socket: BrokerSocket,
    service: &Arc<Mutex<Option<Service>>>,
    registry: &Arc<Mutex<PublicationRegistry>>,
    publisher: &SigningKey,
) -> Arc<Attachment> {
    let backend = Arc::new(Attachment {
        socket,
        service: Arc::downgrade(service),
        registry: OnceLock::new(),
        state: state(),
        endpoint: ProviderEndpoint::new("provider.example", 18080).unwrap(),
        trusted_publishers: BTreeSet::from([publisher.verifying_key().to_bytes()]),
        model_fingerprint: capabilities().model_fingerprint,
        task_derivation_v1: true,
        document_inference_v2: false,
        derived_inference_v3: false,
        enabled: AtomicBool::new(true),
    });
    backend.registry.set(Arc::downgrade(registry)).unwrap();
    backend
}

#[tokio::test]
async fn public_task_binds_original_context_and_exact_question_at_both_agent_boundaries() {
    let root = tempfile::tempdir().unwrap();
    let publisher = SigningKey::from_bytes(&[45; 32]);
    let requester = SigningKey::from_bytes(&[46; 32]);
    let original_request = request(root.path(), &publisher, &requester);
    let service = Arc::new(Mutex::new(None));
    let registry = Arc::new(Mutex::new(PublicationRegistry::new()));
    let mut backend = attachment(
        BrokerSocket {
            path: root.path().join("missing.sock"),
            device: 0,
            inode: 0,
            uid: nix::unistd::geteuid().as_raw(),
        },
        &service,
        &registry,
        &publisher,
    );
    for task in [
        rpc::PublicTask::SummarizeContextsV1 {},
        rpc::PublicTask::AnswerPublicQuestionV1 {
            question: "What does the public sample describe?".into(),
        },
    ] {
        let mut request = original_request.clone();
        let Operation::Submit(submit) = &mut request.operation else {
            panic!("submit")
        };
        let source = dataset::verify_source(
            &hex::decode(&submit.publication.manifest_hex).unwrap(),
            &publisher.verifying_key(),
            &submit.publication.dataset_json,
            now(),
        )
        .unwrap();
        submit.binding.task = Some(task);
        submit.dataset_json = derive_submission(&source, &submit.binding).unwrap();
        submit.binding.dataset_sha256 = hex::encode(Sha256::digest(submit.dataset_json.as_bytes()));
        backend
            .validate(requester.verifying_key().as_bytes(), &request)
            .unwrap();
        super::super::compute_remote::validate_request(&request, &requester).unwrap();

        let mut changed = request.clone();
        let Operation::Submit(submit) = &mut changed.operation else {
            panic!("submit")
        };
        let mut json: serde_json::Value = serde_json::from_str(&submit.dataset_json).unwrap();
        json["inference"][0]["context"] = "Unpublished replacement text".into();
        submit.dataset_json = json.to_string();
        submit.binding.dataset_sha256 = hex::encode(Sha256::digest(submit.dataset_json.as_bytes()));
        assert!(
            backend
                .validate(requester.verifying_key().as_bytes(), &changed)
                .is_err()
        );
        assert!(super::super::compute_remote::validate_request(&changed, &requester).is_err());

        let mut changed = request.clone();
        let Operation::Submit(submit) = &mut changed.operation else {
            panic!("submit")
        };
        submit.binding.task = None;
        assert!(
            backend
                .validate(requester.verifying_key().as_bytes(), &changed)
                .is_err()
        );
        assert!(super::super::compute_remote::validate_request(&changed, &requester).is_err());
        Arc::get_mut(&mut backend).unwrap().task_derivation_v1 = false;
        assert!(
            backend
                .validate(requester.verifying_key().as_bytes(), &request)
                .is_err()
        );
        Arc::get_mut(&mut backend).unwrap().task_derivation_v1 = true;
    }
}

#[tokio::test]
async fn signed_public_request_reaches_only_pinned_same_uid_broker_and_stale_owner_fails() {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("broker.sock");
    let listener = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let publisher = SigningKey::from_bytes(&[45; 32]);
    let requester = SigningKey::from_bytes(&[46; 32]);
    let provider = Arc::new(SigningKey::from_bytes(&[47; 32]));
    let request = request(root.path(), &publisher, &requester);
    let expected = request.clone();
    let broker = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        assert_eq!(
            stream.peer_cred().unwrap().uid(),
            nix::unistd::geteuid().as_raw()
        );
        let actual = rpc::read_request(&mut stream).await.unwrap();
        assert_eq!(actual, expected);
        // A real bounded refusal proves the bridge; no successful model result is invented.
        rpc::write_response(
            &mut stream,
            &Response {
                version: rpc::VERSION,
                request_id: actual.request_id,
                outcome: Outcome::Error(ErrorCode::Busy),
            },
        )
        .await
        .unwrap();
    });
    let registry = Arc::new(Mutex::new(PublicationRegistry::new()));
    let (stop, mut receiver) = watch::channel(false);
    // This ownership sentinel does not pretend to be a network listener or model worker.
    let task = tokio::spawn(async move {
        let _ = receiver.changed().await;
    });
    let service = Arc::new(Mutex::new(Some(Service {
        registry: Arc::clone(&registry),
        endpoint: ProviderEndpoint::new("provider.example", 18080).unwrap(),
        bind: "127.0.0.1:18080".parse().unwrap(),
        stop: stop.clone(),
        task,
        replication: None,
        name_lookup: false,
        mailbox: false,
    })));
    let backend = attachment(
        BrokerSocket::inspect(&path).unwrap(),
        &service,
        &registry,
        &publisher,
    );
    let compute = Arc::new(ComputeService::new(Arc::clone(&provider), backend.clone()));
    registry.lock().await.set_compute(Arc::clone(&compute));
    let (mut client, mut server) = tokio::io::duplex(8192);
    let serving = tokio::spawn(async move {
        volparossa_content::provider::serve_publication(
            &mut server,
            &registry.lock().await.clone(),
            volparossa_content::transfer::TransferLimits::default(),
        )
        .await
    });
    let challenge = volparossa_content::provider::compute::begin(
        &mut client,
        provider.verifying_key().as_bytes(),
    )
    .await
    .unwrap();
    let response = volparossa_content::provider::compute::exchange(
        &mut client,
        challenge,
        &requester,
        serde_json::to_vec(&request).unwrap(),
    )
    .await
    .unwrap();
    let response: Response = serde_json::from_slice(&response).unwrap();
    assert_eq!(response.outcome, Outcome::Error(ErrorCode::Busy));
    timeout(Duration::from_secs(2), broker)
        .await
        .unwrap()
        .unwrap();
    serving.await.unwrap().unwrap();
    backend.deactivate();
    assert!(
        backend
            .exchange(
                requester.verifying_key().to_bytes(),
                serde_json::to_vec(&request).unwrap()
            )
            .await
            .is_err()
    );
    let _ = stop.send(true);
    let owner = service.lock().await.take().unwrap();
    owner.task.await.unwrap();
}

#[tokio::test]
async fn public_schema_provenance_subset_and_requester_are_checked_before_unix_io() {
    let root = tempfile::tempdir().unwrap();
    let publisher = SigningKey::from_bytes(&[45; 32]);
    let requester = SigningKey::from_bytes(&[46; 32]);
    let mut request = request(root.path(), &publisher, &requester);
    let original_request = request.clone();
    let service = Arc::new(Mutex::new(None));
    let registry = Arc::new(Mutex::new(PublicationRegistry::new()));
    let socket = BrokerSocket {
        path: root.path().join("missing.sock"),
        device: 0,
        inode: 0,
        uid: nix::unistd::geteuid().as_raw(),
    };
    let backend = attachment(socket, &service, &registry, &publisher);
    backend
        .validate(requester.verifying_key().as_bytes(), &request)
        .unwrap();
    assert!(
        backend
            .validate(publisher.verifying_key().as_bytes(), &request)
            .is_err()
    );
    let Operation::Submit(submit) = &mut request.operation else {
        panic!("submit")
    };
    submit.binding.row_indices = vec![0];
    assert!(
        backend
            .validate(requester.verifying_key().as_bytes(), &request)
            .is_err()
    );
    let Operation::Submit(submit) = &mut request.operation else {
        panic!("submit")
    };
    submit.binding.row_indices = vec![1];
    submit.publication.publisher_key = hex::encode(requester.verifying_key().as_bytes());
    assert!(
        backend
            .validate(requester.verifying_key().as_bytes(), &request)
            .is_err()
    );
    assert!(!root.path().join("missing.sock").exists());
    let Operation::Submit(mut original) = original_request.operation else {
        panic!("submit")
    };
    original.binding.expires_unix_seconds = now() - 1;
    request.operation = Operation::Submit(original.clone());
    assert!(matches!(
        backend.validate(requester.verifying_key().as_bytes(), &request),
        Err(ComputeError::Expired)
    ));
    for operation in [
        Operation::Poll(original.binding.clone()),
        Operation::Cancel(original.binding),
    ] {
        request.operation = operation;
        backend
            .validate(requester.verifying_key().as_bytes(), &request)
            .unwrap();
    }
}
