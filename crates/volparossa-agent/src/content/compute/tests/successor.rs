//! Attachment rotation and real protected Unix forwarding, without model execution claims.

use super::*;

fn successor() -> Capabilities {
    let mut caps = capabilities();
    caps.successor_activation_v1 = true;
    caps.model.adapter_files = Some(std::collections::BTreeMap::from([
        (
            "README.md".into(),
            FileIdentity {
                bytes: 32,
                sha256: "a".repeat(64),
            },
        ),
        (
            "adapter_config.json".into(),
            FileIdentity {
                bytes: 64,
                sha256: "b".repeat(64),
            },
        ),
        (
            "adapter_model.safetensors".into(),
            FileIdentity {
                bytes: 128,
                sha256: "c".repeat(64),
            },
        ),
    ]));
    fingerprint(&mut caps);
    caps
}

fn fingerprint(caps: &mut Capabilities) {
    caps.model_fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&caps.model).unwrap()));
}

fn response(request: &Request, outcome: Outcome) -> Response {
    Response {
        version: rpc::VERSION,
        request_id: request.request_id.clone(),
        outcome,
    }
}

async fn cleanup(service: &Arc<Mutex<Option<Service>>>) {
    let owner = service.lock().await.take().unwrap();
    let _ = owner.stop.send(true);
    owner.task.await.unwrap();
}

#[tokio::test]
async fn successor_capabilities_require_opt_in_and_preserve_all_attachment_pins() {
    let mut fixture = eligibility::fixture();
    fixture.request.operation = Operation::Capabilities;
    let mut rotated = successor();
    rotated.successor_activation_v1 = false;
    assert!(
        fixture
            .backend
            .validate_broker_response(
                &fixture.request,
                &response(&fixture.request, Outcome::Capabilities(rotated.clone()))
            )
            .is_err()
    ); // Legacy attachment still pins the exact model.
    rotated.successor_activation_v1 = true;
    assert!(
        fixture
            .backend
            .validate_broker_response(
                &fixture.request,
                &response(&fixture.request, Outcome::Capabilities(rotated.clone()))
            )
            .is_err()
    ); // A broker cannot retroactively enable rotation on a legacy attachment.
    Arc::get_mut(&mut fixture.backend)
        .unwrap()
        .successor_activation_v1 = true;
    fixture
        .backend
        .validate_broker_response(
            &fixture.request,
            &response(&fixture.request, Outcome::Capabilities(rotated.clone())),
        )
        .unwrap();

    let mut cases = Vec::new();
    let mut altered = rotated.clone();
    altered.successor_activation_v1 = false;
    cases.push(altered);
    let mut altered = rotated.clone();
    altered.task_derivation_v1 = false;
    cases.push(altered);
    let mut altered = rotated.clone();
    altered.document_inference_v2 = true;
    cases.push(altered);
    let mut altered = rotated.clone();
    altered.derived_inference_v3 = true;
    cases.push(altered);
    let mut altered = rotated.clone();
    altered.model.base_weights.sha256 = "d".repeat(64);
    fingerprint(&mut altered);
    cases.push(altered);
    let mut altered = rotated.clone();
    altered
        .model
        .adapter_files
        .as_mut()
        .unwrap()
        .remove("README.md");
    fingerprint(&mut altered);
    cases.push(altered);
    let mut altered = rotated.clone();
    altered
        .model
        .adapter_files
        .as_mut()
        .unwrap()
        .get_mut("adapter_model.safetensors")
        .unwrap()
        .bytes = 2 * 1024 * 1024 + 1;
    fingerprint(&mut altered);
    cases.push(altered);
    rotated.model_fingerprint = "e".repeat(64);
    cases.push(rotated);
    for invalid in cases {
        assert!(
            fixture
                .backend
                .validate_broker_response(
                    &fixture.request,
                    &response(&fixture.request, Outcome::Capabilities(invalid))
                )
                .is_err()
        );
    }
    cleanup(&fixture.service).await;
}

fn retained_status(binding: JobBinding, state: rpc::JobState) -> Outcome {
    Outcome::Job(rpc::JobStatus {
        binding,
        state,
        cancellation_requested: state == rpc::JobState::Cancelled,
        report_json: None,
        report_sha256: None,
        error: (state == rpc::JobState::Failed).then_some(ErrorCode::WorkerFailed),
    })
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One owned broker transaction sequence proves selection and immutable historical forwarding"
)]
async fn successor_selection_and_historical_bindings_use_the_same_original_broker() {
    let mut fixture = eligibility::fixture();
    let rotated = successor();
    let old_submit = request(
        fixture.root.path(),
        &SigningKey::from_bytes(&[75; 32]),
        &fixture.requester,
    );
    let Operation::Submit(original) = &old_submit.operation else {
        panic!("submit")
    };
    let original_binding = original.binding.clone();
    let mut new_submit = old_submit.clone();
    let Operation::Submit(new) = &mut new_submit.operation else {
        panic!("submit")
    };
    new.binding
        .model_fingerprint
        .clone_from(&rotated.model_fingerprint);
    assert!(
        fixture
            .backend
            .validate(fixture.requester.verifying_key().as_bytes(), &new_submit)
            .is_err()
    );
    Arc::get_mut(&mut fixture.backend)
        .unwrap()
        .successor_activation_v1 = true;

    let mut current_query = fixture.request.clone();
    let Operation::Eligibility(query) = &mut current_query.operation else {
        panic!("query")
    };
    query.model_fingerprint = Some(rotated.model_fingerprint.clone());
    let mut poll = old_submit.clone();
    poll.operation = Operation::Poll(original_binding.clone());
    let mut cancel = poll.clone();
    cancel.operation = Operation::Cancel(original_binding.clone());
    let mut wrong_binding = original_binding.clone();
    wrong_binding.model_fingerprint = rotated.model_fingerprint.clone();
    let exchanges = vec![
        (current_query, Outcome::Capabilities(rotated.clone()), true),
        (
            fixture.request.clone(),
            Outcome::Capabilities(rotated),
            true,
        ),
        (new_submit, Outcome::Error(ErrorCode::Busy), true),
        (old_submit, Outcome::Error(ErrorCode::ModelMismatch), true),
        (
            poll.clone(),
            retained_status(original_binding.clone(), rpc::JobState::Failed),
            true,
        ),
        (
            cancel,
            retained_status(original_binding, rpc::JobState::Cancelled),
            true,
        ),
        (
            poll,
            retained_status(wrong_binding, rpc::JobState::Failed),
            false,
        ),
    ];
    let expected = exchanges.clone();
    let broker = tokio::spawn(async move {
        for (mut expected_request, outcome, _) in expected {
            if matches!(expected_request.operation, Operation::Eligibility(_)) {
                expected_request.operation = Operation::Capabilities;
            }
            let (mut socket, _) = fixture.listener.accept().await.unwrap();
            let actual = rpc::read_request(&mut socket).await.unwrap();
            assert_eq!(actual, expected_request); // No model or historical binding rewrite.
            rpc::write_response(&mut socket, &response(&actual, outcome))
                .await
                .unwrap();
        }
    });
    for (index, (request, expected_outcome, accepted)) in exchanges.into_iter().enumerate() {
        let result = fixture
            .backend
            .exchange(
                fixture.requester.verifying_key().to_bytes(),
                serde_json::to_vec(&request).unwrap(),
            )
            .await;
        assert_eq!(result.is_ok(), accepted);
        if let Ok(bytes) = result {
            let actual: Response = serde_json::from_slice(&bytes).unwrap();
            match actual.outcome {
                Outcome::Eligibility(observed) => assert_eq!(observed.eligible, index == 0),
                outcome => assert_eq!(outcome, expected_outcome),
            }
        }
    }
    timeout(Duration::from_secs(2), broker)
        .await
        .unwrap()
        .unwrap();
    cleanup(&fixture.service).await;
}

#[tokio::test]
async fn successor_job_responses_must_match_every_original_binding_field_and_operation() {
    let mut fixture = eligibility::fixture();
    Arc::get_mut(&mut fixture.backend)
        .unwrap()
        .successor_activation_v1 = true;
    let mut original = request(
        fixture.root.path(),
        &SigningKey::from_bytes(&[75; 32]),
        &fixture.requester,
    );
    let Operation::Submit(submit) = &original.operation else {
        panic!("submit")
    };
    let binding = submit.binding.clone();
    let mut altered = Vec::new();
    for field in [
        "job_id",
        "dataset_manifest_id",
        "dataset_sha256",
        "model_fingerprint",
        "row_indices",
        "expires_unix_seconds",
        "task",
    ] {
        let mut value = serde_json::to_value(&binding).unwrap();
        value[field] = match field {
            "job_id" => "f".repeat(32).into(),
            "row_indices" => serde_json::json!([0]),
            "expires_unix_seconds" => (binding.expires_unix_seconds + 1).into(),
            "task" => serde_json::json!({"kind":"summarize_contexts_v1"}),
            _ => "f".repeat(64).into(),
        };
        altered.push(serde_json::from_value::<JobBinding>(value).unwrap());
    }
    for operation in [
        original.operation.clone(),
        Operation::Poll(binding.clone()),
        Operation::Cancel(binding.clone()),
    ] {
        original.operation = operation;
        fixture
            .backend
            .validate_broker_response(
                &original,
                &response(
                    &original,
                    retained_status(binding.clone(), rpc::JobState::Failed),
                ),
            )
            .unwrap();
        for changed in &altered {
            assert!(
                fixture
                    .backend
                    .validate_broker_response(
                        &original,
                        &response(
                            &original,
                            retained_status(changed.clone(), rpc::JobState::Failed)
                        )
                    )
                    .is_err()
            );
        }
        assert!(
            fixture
                .backend
                .validate_broker_response(
                    &original,
                    &response(&original, Outcome::Capabilities(successor()))
                )
                .is_err()
        );
    }
    original.operation = Operation::Capabilities;
    assert!(
        fixture
            .backend
            .validate_broker_response(
                &original,
                &response(&original, retained_status(binding, rpc::JobState::Failed))
            )
            .is_err()
    );
    cleanup(&fixture.service).await;
}
