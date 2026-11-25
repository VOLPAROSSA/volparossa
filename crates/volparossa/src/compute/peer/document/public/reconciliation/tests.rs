//! Real local framed exchanges with controlled broker replies, not model/overlay proof.

use std::os::unix::fs::PermissionsExt as _;

use tokio::net::UnixListener;

use super::*;
use crate::compute::peer::status_test_peer::serve_one;

fn handle(id: u8) -> JobHandle {
    let key = ed25519_dalek::SigningKey::from_bytes(&[19; 32]).verifying_key();
    serde_json::from_value(serde_json::json!({
        "version":1,"provider_key":hex::encode(key.as_bytes()),
        "binding":{"job_id":hex::encode([id;16]),"dataset_manifest_id":"3".repeat(64),
            "dataset_sha256":"4".repeat(64),"model_fingerprint":"5".repeat(64),
            "row_indices":[0],"expires_unix_seconds":1,"task":null},
        "capabilities":{"model":{"model_id":"protocol-only-fixture","model_revision":"6".repeat(40),
            "base_weights":{"bytes":1,"sha256":"7".repeat(64)},"adapter_files":null},
            "model_fingerprint":"5".repeat(64),"accepting_work":false,"public_inference_only":true,
            "runtime_slots":1,"max_threads":2,"max_job_seconds":600,"max_dataset_bytes":1_048_576,
            "max_rows":4,"task_derivation_v1":true,"document_inference_v2":true,
            "principle_inference_v4":false,"derived_inference_v3":true,"successor_activation_v1":false}
    })).unwrap()
}

fn status(handle: &JobHandle, state: rpc::JobState) -> rpc::JobStatus {
    rpc::JobStatus {
        binding: handle.binding.clone(),
        state,
        cancellation_requested: true,
        report_json: None,
        report_sha256: None,
        error: None,
    }
}

fn root() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn retain(root: &Path, job: &JobHandle, terminal: bool) -> std::path::PathBuf {
    let directory = root.join(format!("attempt-{}", job.binding.job_id));
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&directory)
        .unwrap();
    peer::save_new(&directory.join("job-0.json"), job).unwrap();
    if terminal {
        peer::batch::save_status(&directory, job, &status(job, rpc::JobState::Failed)).unwrap();
    }
    directory
}

async fn serve(
    listener: UnixListener,
    handle: JobHandle,
    replies: Vec<(bool, rpc::Outcome, bool)>,
) {
    for (cancel, outcome, correct_final) in replies {
        serve_one(&listener, &handle, cancel, Some((outcome, correct_final))).await;
    }
}

#[tokio::test]
async fn abandoned_handle_requires_actual_terminal_after_cancel_and_preserves_all_originals() {
    let root = root();
    // Keep the socket outside the scanned task tree; production uses the agent socket.
    let sockets = tempfile::tempdir().unwrap();
    let socket = sockets.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    for id in 1..=5 {
        retain(root.path(), &handle(id), true);
    }
    let abandoned = handle(6);
    let attempt = retain(root.path(), &abandoned, false);
    let original = fs::read(attempt.join("job-0.json")).unwrap();
    let old_result = b"original incomplete workflow result";
    task::write_bytes(&attempt.join("result.json"), old_result, false).unwrap();
    let mut before = ReceiptObservation::default();
    assert!(!super::super::terminal_receipts(root.path(), &mut before).unwrap());
    assert_eq!(
        (before.handles, before.receipts, before.terminal),
        (6, 5, 5)
    );
    let server = tokio::spawn(serve(
        listener,
        abandoned.clone(),
        vec![
            (
                false,
                rpc::Outcome::Job(status(&abandoned, rpc::JobState::Running)),
                true,
            ),
            (
                true,
                rpc::Outcome::Job(status(&abandoned, rpc::JobState::Running)),
                true,
            ),
            (
                false,
                rpc::Outcome::Job(status(&abandoned, rpc::JobState::Cancelled)),
                true,
            ),
        ],
    ));
    let observed = run_until(
        root.path(),
        &socket,
        Instant::now() + Duration::from_secs(10),
    )
    .await;
    server.await.unwrap();
    assert_eq!((observed.attempted, observed.terminal_persisted), (1, 1));
    assert_eq!(observed.error, diagnostic::ErrorClass::None);
    assert_eq!(fs::read(attempt.join("job-0.json")).unwrap(), original);
    assert_eq!(fs::read(attempt.join("result.json")).unwrap(), old_result);
    assert!(
        !attempt
            .join(format!("receipt-{}.json", abandoned.binding.job_id))
            .exists()
    );
    let mut after = ReceiptObservation::default();
    assert!(super::super::terminal_receipts(root.path(), &mut after).unwrap());
    assert_eq!((after.handles, after.receipts, after.terminal), (6, 6, 6));
    // A second scan cannot issue another RPC or overwrite any receipt.
    assert_eq!(run(root.path(), &socket).await.attempted, 0);
}

#[tokio::test]
async fn missing_or_wrong_binding_or_final_correlation_cannot_release_expired_authority() {
    for kind in 0..3 {
        let root = root();
        let original = handle(1);
        retain(root.path(), &original, false);
        let sockets = tempfile::tempdir().unwrap();
        let socket = sockets.path().join("agent.sock");
        let listener = UnixListener::bind(&socket).unwrap();
        let mut reply = status(&original, rpc::JobState::Failed);
        if kind == 1 {
            reply.binding.job_id = hex::encode([9; 16]);
        }
        let outcome = if kind == 0 {
            rpc::Outcome::Error(rpc::ErrorCode::Missing)
        } else {
            rpc::Outcome::Job(reply)
        };
        let server = tokio::spawn(serve(listener, original, vec![(false, outcome, kind != 2)]));
        let observed = run(root.path(), &socket).await;
        server.await.unwrap();
        assert_eq!((observed.attempted, observed.terminal_persisted), (1, 0));
        assert_eq!(observed.error, diagnostic::ErrorClass::PeerRpc);
        assert!(
            !super::super::terminal_receipts(root.path(), &mut ReceiptObservation::default())
                .unwrap()
        );
        assert!(!root.path().join("cleanup-observations").exists());
    }
}

#[tokio::test]
async fn an_interrupted_poll_revisits_the_same_handle_after_other_original_jobs() {
    let root = root();
    let first = handle(1);
    let second = handle(2);
    retain(root.path(), &first, false);
    retain(root.path(), &second, false);
    let sockets = tempfile::tempdir().unwrap();
    let socket = sockets.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        serve_one(&listener, &first, false, None).await;
        for job in [&second, &first] {
            let terminal = rpc::Outcome::Job(status(job, rpc::JobState::Failed));
            serve_one(&listener, job, false, Some((terminal, true))).await;
        }
    });
    let observed = run_until(
        root.path(),
        &socket,
        Instant::now() + Duration::from_secs(10),
    )
    .await;
    server.await.unwrap();
    assert_eq!((observed.attempted, observed.terminal_persisted), (2, 2));
    assert!(!observed.deadline_reached);
    assert_eq!(observed.error, diagnostic::ErrorClass::None);
    assert!(
        super::super::terminal_receipts(root.path(), &mut ReceiptObservation::default()).unwrap()
    );
}

#[tokio::test]
async fn deadline_keeps_original_handle_without_terminal_receipt() {
    let root = root();
    retain(root.path(), &handle(1), false);
    let sockets = tempfile::tempdir().unwrap();
    let socket = sockets.path().join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let server = tokio::spawn(async move {
        let (_stream, _) = listener.accept().await.unwrap();
        std::future::pending::<()>().await;
    });
    let observed = run_until(
        root.path(),
        &socket,
        Instant::now() + Duration::from_millis(50),
    )
    .await;
    server.abort();
    assert!(server.await.unwrap_err().is_cancelled());
    assert!(observed.deadline_reached);
    assert_eq!(observed.terminal_persisted, 0);
    assert_eq!(observed.rpc.unwrap()["category"], "exchange_unconfirmed");
    assert!(
        !super::super::terminal_receipts(root.path(), &mut ReceiptObservation::default()).unwrap()
    );
}
