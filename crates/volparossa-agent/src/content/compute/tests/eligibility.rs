//! Actual owned Unix capability exchange; no model execution or capacity reservation.

use super::*;

struct Fixture {
    _root: tempfile::TempDir,
    listener: UnixListener,
    service: Arc<Mutex<Option<Service>>>,
    backend: Arc<Attachment>,
    request: Request,
    requester: SigningKey,
}

fn fixture() -> Fixture {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = root.path().join("broker.sock");
    let listener = UnixListener::bind(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let publisher = SigningKey::from_bytes(&[75; 32]);
    let requester = SigningKey::from_bytes(&[76; 32]);
    let registry = Arc::new(Mutex::new(PublicationRegistry::new()));
    let (stop, mut receiver) = watch::channel(false);
    // Ownership sentinel only; it is not a simulated network or model service.
    let task = tokio::spawn(async move {
        let _ = receiver.changed().await;
    });
    let service = Arc::new(Mutex::new(Some(Service {
        registry: Arc::clone(&registry),
        endpoint: ProviderEndpoint::new("provider.example", 18080).unwrap(),
        bind: "127.0.0.1:18080".parse().unwrap(),
        stop,
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
    let request = Request {
        version: rpc::VERSION,
        request_id: "a".repeat(32),
        requester_key: hex::encode(requester.verifying_key().as_bytes()),
        operation: Operation::Eligibility(rpc::EligibilityQuery {
            publisher_keys: vec![hex::encode(publisher.verifying_key().as_bytes())],
            model_fingerprint: Some(capabilities().model_fingerprint),
            require_task_derivation_v1: true,
            require_document_inference_v2: false,
            require_derived_inference_v3: false,
        }),
    };
    Fixture {
        _root: root,
        listener,
        service,
        backend,
        request,
        requester,
    }
}

async fn serve_capability_hints(
    listener: &UnixListener,
    attached: &Attachment,
    expected_requester: &str,
    count: usize,
) {
    for index in 0..=count {
        let (mut socket, _) = listener.accept().await.unwrap();
        let request = rpc::read_request(&mut socket).await.unwrap();
        request.validate(now()).unwrap();
        assert_eq!(request.operation, Operation::Capabilities);
        assert_eq!(request.requester_key, expected_requester);
        let mut observed = capabilities();
        observed.accepting_work = index != count - 1;
        if index == count {
            attached.deactivate(); // Withdrawal while the broker exchange is pending.
        }
        rpc::write_response(
            &mut socket,
            &Response {
                version: rpc::VERSION,
                request_id: request.request_id,
                outcome: Outcome::Capabilities(observed),
            },
        )
        .await
        .unwrap();
    }
}

#[tokio::test]
async fn eligibility_checks_all_publishers_profiles_capacity_and_live_attachment() {
    let Fixture {
        _root,
        listener,
        service,
        backend,
        request,
        requester,
    } = fixture();
    let original_query = match &request.operation {
        Operation::Eligibility(query) => query.clone(),
        _ => panic!("eligibility query"),
    };
    let mut cases = vec![(original_query.clone(), true)];
    let mut query = original_query.clone();
    query
        .publisher_keys
        .push(hex::encode(requester.verifying_key().as_bytes()));
    cases.push((query, false)); // Trusting one publisher cannot authorize the other.
    let mut query = original_query.clone();
    query.model_fingerprint = Some("b".repeat(64));
    cases.push((query, false));
    let mut query = original_query.clone();
    query.require_document_inference_v2 = true;
    cases.push((query, false));
    let mut query = original_query.clone();
    query.require_derived_inference_v3 = true;
    cases.push((query, false));
    cases.push((original_query, false)); // Last normal response reports actual Busy capacity.
    let count = cases.len();
    let attached = Arc::clone(&backend);
    let expected_requester = request.requester_key.clone();
    let broker = tokio::spawn(async move {
        serve_capability_hints(&listener, &attached, &expected_requester, count).await;
    });
    for (query, expected) in cases {
        let mut current = request.clone();
        current.operation = Operation::Eligibility(query);
        let bytes = backend
            .exchange(
                requester.verifying_key().to_bytes(),
                serde_json::to_vec(&current).unwrap(),
            )
            .await
            .unwrap();
        let response: Response = serde_json::from_slice(&bytes).unwrap();
        assert_eq!(response.request_id, current.request_id);
        let Outcome::Eligibility(observed) = response.outcome else {
            panic!("eligibility response")
        };
        assert_eq!(observed.eligible, expected);
        assert_eq!(
            observed.capabilities.model_fingerprint,
            capabilities().model_fingerprint
        );
    }
    assert!(
        backend
            .exchange(
                requester.verifying_key().to_bytes(),
                serde_json::to_vec(&request).unwrap()
            )
            .await
            .is_err()
    );
    timeout(Duration::from_secs(2), broker)
        .await
        .unwrap()
        .unwrap();
    // After withdrawal it must fail before any further Unix exchange as well.
    assert!(
        backend
            .exchange(
                requester.verifying_key().to_bytes(),
                serde_json::to_vec(&request).unwrap()
            )
            .await
            .is_err()
    );
    let owner = service.lock().await.take().unwrap();
    let _ = owner.stop.send(true);
    owner.task.await.unwrap();
}

#[tokio::test]
async fn eligibility_rejects_malformed_query_and_foreign_requester_before_broker_io() {
    let Fixture {
        _root,
        listener: _listener,
        service,
        backend,
        mut request,
        requester,
    } = fixture();
    let other = SigningKey::from_bytes(&[77; 32]);
    assert!(matches!(
        backend.validate(other.verifying_key().as_bytes(), &request),
        Err(ComputeError::Authentication)
    ));
    let Operation::Eligibility(query) = &mut request.operation else {
        panic!("eligibility query")
    };
    query.publisher_keys.push(query.publisher_keys[0].clone());
    assert!(matches!(
        backend.validate(requester.verifying_key().as_bytes(), &request),
        Err(ComputeError::Invalid)
    ));
    let owner = service.lock().await.take().unwrap();
    let _ = owner.stop.send(true);
    owner.task.await.unwrap();
}
