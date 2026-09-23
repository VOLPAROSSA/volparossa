//! Protocol fixtures only: no model, remote job, backend, tokenizer or Internet connection.

use super::*;
use volparossa_content::agent_artifact::{BASE_MODEL_SHA256, MODEL_ID, MODEL_REVISION};
use volparossa_local_control::{ComputeDiscovered, ComputeDiscoveredProvider};

fn fixture() -> (Options, rpc::EligibilityQuery, ComputeDiscovered) {
    let model = rpc::ModelIdentity {
        model_id: MODEL_ID.into(),
        model_revision: MODEL_REVISION.into(),
        base_weights: rpc::FileIdentity {
            bytes: 269_060_552,
            sha256: hex::encode(BASE_MODEL_SHA256),
        },
        adapter_files: None,
    };
    let caps = rpc::Capabilities {
        model_fingerprint: sha(&serde_json::to_vec(&model).unwrap()),
        model,
        accepting_work: true,
        public_inference_only: true,
        runtime_slots: 1,
        max_threads: 2,
        max_job_seconds: 600,
        max_dataset_bytes: 1024 * 1024,
        max_rows: 4,
        task_derivation_v1: true,
        document_inference_v2: true,
        principle_inference_v4: false,
        derived_inference_v3: true,
        successor_activation_v1: false,
    };
    let options = Options {
        discover_peers: true,
        ..Options::default()
    };
    let publisher = ed25519_dalek::SigningKey::from_bytes(&[91; 32]);
    let query = options
        .query(
            [hex::encode(publisher.verifying_key().as_bytes())],
            true,
            true,
            true,
        )
        .unwrap();
    let found = ComputeDiscovered {
        providers: [92, 93]
            .into_iter()
            .map(|byte| ComputeDiscoveredProvider {
                provider_key: ed25519_dalek::SigningKey::from_bytes(&[byte; 32])
                    .verifying_key()
                    .as_bytes()
                    .to_vec(),
                capabilities_json: serde_json::to_string(&caps).unwrap(),
            })
            .collect(),
    };
    (options, query, found)
}

#[test]
fn exact_compatible_available_group_is_required_before_enrollment() {
    let (_, query, found) = fixture();
    let selected = checked_selection(&found, &query, 2, 4).unwrap();
    assert_eq!(selected.providers.len(), 2);
    assert_eq!(selected.model_fingerprint.len(), 64);
    for field in [
        "accepting_work",
        "public_inference_only",
        "task_derivation_v1",
        "document_inference_v2",
        "derived_inference_v3",
    ] {
        let mut changed = found.clone();
        let mut caps: serde_json::Value =
            serde_json::from_str(&changed.providers[1].capabilities_json).unwrap();
        caps[field] = false.into();
        changed.providers[1].capabilities_json = caps.to_string();
        assert!(
            checked_selection(&changed, &query, 2, 4).is_err(),
            "{field}"
        );
    }
    let mut changed = found.clone();
    changed.providers[1] = changed.providers[0].clone();
    assert!(checked_selection(&changed, &query, 2, 4).is_err());
    changed.providers.pop();
    assert!(checked_selection(&changed, &query, 2, 4).is_err());
    let mut wrong_model = query;
    wrong_model.model_fingerprint = Some("1".repeat(64));
    assert!(checked_selection(&found, &wrong_model, 2, 4).is_err());
}

#[tokio::test]
async fn local_discovery_carries_only_public_publisher_and_profile_selection() {
    use volparossa_local_control::{
        CONTROL_PROTOCOL_VERSION, ControlResponse, ControlResult, read_request, write_response,
    };
    let (options, query, found) = fixture();
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let expected = query.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        let Some(Operation::ComputeDiscover(discover)) = request.operation else {
            panic!("not discovery")
        };
        assert_eq!(discover.eligibility().unwrap(), expected);
        assert_eq!(discover.maximum, 4);
        assert_eq!(discover.minimum, 0);
        assert_eq!(discover.effective_minimum(), 2);
        write_response(
            &mut stream,
            &ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: request.request_id,
                result: ControlResult::Ok.into(),
                diagnostic_code: "COMPUTE_DISCOVER_OK".into(),
                payload: Some(Payload::ComputeDiscovered(found)),
            },
        )
        .await
        .unwrap();
    });
    let (_owner, cancelled) = tokio::sync::watch::channel(false);
    assert_eq!(
        options
            .select(&socket, query.clone(), &cancelled)
            .await
            .unwrap()
            .providers
            .len(),
        2
    );
    server.await.unwrap();
    let (_, cancelled) = tokio::sync::watch::channel(true);
    let failure = options
        .select(&socket, query, &cancelled)
        .await
        .err()
        .unwrap();
    assert_eq!(failure.to_string(), "compute_discovery_cancelled");
}

#[tokio::test]
async fn recovery_uses_exact_model_and_explicit_singleton_without_submitting() {
    use volparossa_local_control::{
        CONTROL_PROTOCOL_VERSION, ControlResponse, ControlResult, read_request, write_response,
    };
    let (_, mut query, mut found) = fixture();
    found.providers.pop();
    let caps: rpc::Capabilities =
        serde_json::from_str(&found.providers[0].capabilities_json).unwrap();
    query.model_fingerprint = Some(caps.model_fingerprint);
    assert!(checked_selection(&found, &query, 2, 4).is_err());
    assert!(checked_selection(&found, &query, 1, 4).is_ok());
    let root = tempfile::tempdir().unwrap();
    let socket = root.path().join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let expected = query.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        let Some(Operation::ComputeDiscover(discover)) = request.operation else {
            panic!("not discovery")
        };
        assert_eq!(discover.minimum, 1);
        assert_eq!(discover.maximum, 4);
        assert_eq!(discover.eligibility().unwrap(), expected);
        write_response(
            &mut stream,
            &ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: request.request_id,
                result: ControlResult::Ok.into(),
                diagnostic_code: "COMPUTE_DISCOVERED".into(),
                payload: Some(Payload::ComputeDiscovered(found)),
            },
        )
        .await
        .unwrap();
    });
    let (_owner, cancelled) = tokio::sync::watch::channel(false);
    let selected = select_replacements(&socket, query.clone(), &cancelled)
        .await
        .unwrap();
    assert_eq!(selected.providers.len(), 1);
    assert_eq!(Some(selected.model_fingerprint), query.model_fingerprint);
    server.await.unwrap();
    query.model_fingerprint = None;
    let failure = select_replacements(&socket, query, &cancelled)
        .await
        .unwrap_err();
    assert_eq!(failure.to_string(), "compute_replacement_model_required");
}

#[test]
fn replacement_permission_is_explicit_at_new_discovery_enrollment() {
    use clap::Parser as _;

    assert!(!Options::default().replace_peers);
    let args = [
        "volparossa",
        "compute",
        "peer",
        "workflow",
        "--plan",
        "/public/plan.json",
        "--directory",
        "/public/work",
        "--discover-peers",
        "--replace-peers",
    ];
    assert!(crate::Cli::try_parse_from(args).is_ok());
    assert!(
        crate::Cli::try_parse_from(args.into_iter().filter(|arg| *arg != "--discover-peers"))
            .is_err()
    );
    assert!(
        crate::Cli::try_parse_from([
            "volparossa",
            "compute",
            "peer",
            "workflow",
            "--directory",
            "/public/work",
            "--resume",
            "--discover-peers",
            "--replace-peers"
        ])
        .is_err()
    );
}
