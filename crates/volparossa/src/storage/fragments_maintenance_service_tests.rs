//! Real owner loop and signed `SQLite` custody behind a fixture resource coordinator.
//! This is not evidence of protected overlay routing or the daemon's idle admission.

use super::*;
use std::{future::pending, sync::Arc};
use tokio::{net::UnixListener, sync::oneshot, task::JoinSet, time::timeout};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ControlResponse, PrivateStorageMaintenanceReady, read_request,
    write_request, write_response,
};

async fn fixture() -> (
    tempfile::TempDir,
    SigningKey,
    Enrollment,
    nix::fcntl::Flock<File>,
    LocalProviders,
) {
    let temp = tempfile::tempdir().unwrap();
    let (owner, providers, grants) = keys_and_grants(16);
    let bytes = vec![29; 3 * CHUNK_BYTES + 73];
    let source = temp.path().join("ciphertext");
    fs::write(&source, &bytes).unwrap();
    let (mut input, _) = transfer::checked_input(&source, plan(&bytes).sha256).unwrap();
    let archive = temp.path().join("fragments");
    let set =
        LockedFragments::create(&archive, &owner, &mut input, plan(&bytes), &grants, 600).unwrap();
    let peers = LocalProviders::start(temp.path(), &providers, &grants, true);
    assert_eq!(
        operations::deposit(&set, &peers.socket, &owner, &mut input)
            .await
            .unwrap()["operation_complete"],
        true
    );
    let (_, grant) = candidate(&owner);
    let enrollment = enrollment(&set, archive, &owner, &providers, &grant);
    let path = temp.path().join("maintenance");
    fs::DirBuilder::new().mode(0o700).create(&path).unwrap();
    let directory = state::directory(&path).unwrap();
    let signature = hex::encode(owner.sign(&signing(&enrollment).unwrap()).to_bytes());
    save(
        &directory,
        "enrollment.json",
        &SignedEnrollment {
            enrollment,
            signature,
        },
    )
    .unwrap();
    let enrollment = load(&directory).unwrap();
    checkpoint(&directory, "enrolled", 0, None).unwrap();
    drop((set, input));
    fs::remove_file(source).unwrap();
    (temp, owner, enrollment, directory, peers)
}

fn status(directory: &File) -> serde_json::Value {
    serde_json::from_slice(
        &state::read_private(
            &state::anchored(directory).join("checkpoint.json"),
            MAX_ENROLLMENT,
        )
        .unwrap(),
    )
    .unwrap()
}

async fn wait_for_stage(directory: &File, stage: &str) {
    timeout(Duration::from_secs(3), async {
        while status(directory)["stage"] != stage {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

/// The fixture grants only resource turns; original signed custody frames still go
/// through the real provider store and its immutable grants. No signing is mocked.
async fn coordinator(
    listener: UnixListener,
    backend: PathBuf,
    expected_owner: [u8; 32],
    expected_enrollment: [u8; 32],
    mut stop: oneshot::Receiver<()>,
) -> (u64, u64) {
    let mut children = JoinSet::new();
    let turns = Arc::new(std::sync::atomic::AtomicU64::new(0));
    let closed = Arc::new(std::sync::atomic::AtomicU64::new(0));
    loop {
        let mut local = tokio::select! {
            _ = &mut stop => break,
            accepted = listener.accept() => accepted.unwrap().0,
        };
        let backend = backend.clone();
        let turns = Arc::clone(&turns);
        let closed = Arc::clone(&closed);
        children.spawn(async move {
            let request = read_request(&mut local).await.unwrap();
            match request.operation.as_ref().unwrap() {
                Operation::PrivateStorageMaintenance(admission) => {
                    assert_eq!(admission.owner_key, expected_owner);
                    assert_eq!(admission.enrollment_id, expected_enrollment);
                    turns.fetch_add(1, Ordering::SeqCst);
                    write_response(
                        &mut local,
                        &ControlResponse {
                            protocol_version: CONTROL_PROTOCOL_VERSION,
                            request_id: request.request_id.clone(),
                            result: 0,
                            diagnostic_code: "PRIVATE_STORAGE_MAINTENANCE_READY".into(),
                            private_storage_remote_detail: None,
                            payload: Some(Payload::PrivateStorageMaintenanceReady(
                                PrivateStorageMaintenanceReady {
                                    turn: vec![9; 32],
                                    expires: crate::storage::now().unwrap() + 60,
                                    maximum_bytes: admission.maximum_bytes,
                                },
                            )),
                        },
                    )
                    .await
                    .unwrap();
                    assert_eq!(local.read(&mut [0]).await.unwrap(), 0);
                    closed.fetch_add(1, Ordering::SeqCst);
                }
                Operation::PrivateStorageRemote(remote) => {
                    assert_eq!(remote.maintenance_turn, [9; 32]);
                    let mut provider = tokio::net::UnixStream::connect(backend).await.unwrap();
                    write_request(&mut provider, &request).await.unwrap();
                    tokio::io::copy_bidirectional(&mut local, &mut provider)
                        .await
                        .unwrap();
                }
                // This fixture does not retain outcome observations. Query rejection
                // is diagnostic only, and is not another admitted maintenance turn.
                Operation::PrivateStorageOutcome(_) => {}
                _ => panic!("unexpected maintenance authority"),
            }
        });
    }
    while let Some(child) = children.join_next().await {
        child.unwrap();
    }
    (turns.load(Ordering::SeqCst), closed.load(Ordering::SeqCst))
}

#[tokio::test]
async fn owner_loop_reconnects_without_reenrollment_and_preserves_restart_cursor() {
    let (temp, owner, enrollment, directory, peers) = fixture().await;
    let immutable = fs::read(enrollment.archive.join("fragments.json")).unwrap();
    let signed = fs::read(temp.path().join("maintenance/enrollment.json")).unwrap();
    checkpoint(&directory, "working", 19, None).unwrap();
    drop(directory);
    let directory = state::directory(&temp.path().join("maintenance")).unwrap();
    let socket = temp.path().join("resource-core.sock");
    let (stop, stopping) = oneshot::channel();
    let server = async {
        wait_for_stage(&directory, "core_unavailable").await;
        assert_eq!(status(&directory)["turns"], 19);
        let listener = UnixListener::bind(&socket).unwrap();
        coordinator(
            listener,
            peers.socket.clone(),
            enrollment.owner,
            enrollment.id,
            stopping,
        )
        .await
    };
    let owner_loop = async {
        serve_enrolled(&directory, &enrollment, &socket, &owner, Some(2), pending())
            .await
            .unwrap();
        stop.send(()).unwrap();
    };
    let ((), observed) = timeout(Duration::from_secs(10), async {
        tokio::join!(owner_loop, server)
    })
    .await
    .unwrap();
    assert_eq!(
        observed,
        (2, 2),
        "both live resource connections are closed"
    );
    assert_eq!(status(&directory)["stage"], "turn_completed");
    assert_eq!(status(&directory)["turns"], 21);
    assert_eq!(
        status(&directory)["detail"]["refresh"]["operation_complete"],
        true
    );
    assert_eq!(
        fs::read(enrollment.archive.join("fragments.json")).unwrap(),
        immutable
    );
    assert_eq!(
        fs::read(temp.path().join("maintenance/enrollment.json")).unwrap(),
        signed
    );
    let set = LockedFragments::open(&enrollment.archive).unwrap();
    let report = set.report("status").unwrap();
    assert_eq!(
        report["physical_payload_charge_upper_bound"],
        2 * set.data.ciphertext_bytes
    );
    assert_eq!(report["uncertain_payload_bytes"], 0);
    drop(set);
    peers.stop().await;
}

#[tokio::test]
async fn shutdown_during_reconnect_keeps_authority_and_retained_charge_for_restart() {
    let (temp, owner, enrollment, directory, peers) = fixture().await;
    let before = LockedFragments::open(&enrollment.archive)
        .unwrap()
        .report("status")
        .unwrap();
    checkpoint(&directory, "working", 7, None).unwrap();
    let (stop, stopping) = oneshot::channel();
    let socket = temp.path().join("absent-core.sock");
    let owner_loop = serve_enrolled(&directory, &enrollment, &socket, &owner, None, async {
        stopping.await.unwrap();
    });
    let controller = async {
        wait_for_stage(&directory, "core_unavailable").await;
        stop.send(()).unwrap();
    };
    let (result, ()) = timeout(Duration::from_secs(3), async {
        tokio::join!(owner_loop, controller)
    })
    .await
    .unwrap();
    result.unwrap();
    assert_eq!(status(&directory)["stage"], "paused");
    assert_eq!(status(&directory)["turns"], 7);
    assert_eq!(
        LockedFragments::open(&enrollment.archive)
            .unwrap()
            .report("status")
            .unwrap(),
        before
    );
    peers.stop().await;
}

#[tokio::test]
async fn expired_enrollment_never_reconnects_or_advances_work() {
    let (temp, owner, mut enrollment, directory, peers) = fixture().await;
    enrollment.expires = crate::storage::now().unwrap();
    let socket = temp.path().join("no-authority.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    serve_enrolled(&directory, &enrollment, &socket, &owner, None, pending())
        .await
        .unwrap();
    assert_eq!(status(&directory)["stage"], "enrollment_expired");
    assert_eq!(status(&directory)["turns"], 0);
    assert!(
        timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
    peers.stop().await;
}

fn authorize(directory: &File, enrollment: Enrollment, owner: &SigningKey) -> Enrollment {
    let signature = hex::encode(owner.sign(&signing(&enrollment).unwrap()).to_bytes());
    save(
        directory,
        "enrollment.json",
        &SignedEnrollment {
            enrollment,
            signature,
        },
    )
    .unwrap();
    load(directory).unwrap()
}

fn targets(
    set: &LockedFragments,
) -> Vec<volparossa_content::private_storage::protocol::StorageTarget> {
    let mut result = Vec::new();
    for index in 0..set.data.fragments.len() {
        let copies = set.fragment(index).unwrap();
        for copy in 0..copies.data.copies.len() {
            result.push(copies.copy(copy).unwrap().journal.target().unwrap());
        }
    }
    result
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "Keep interruption, retained uncertainty, core return and original lease identity in one real owner-loop lifecycle."
)]
async fn live_turn_loss_reconnects_and_reconciles_original_journals_without_new_leases() {
    let (temp, owner, mut enrollment, directory, peers) = fixture().await;
    let set = LockedFragments::open(&enrollment.archive).unwrap();
    let original_targets = targets(&set);
    let original_charge = 2 * set.data.ciphertext_bytes;
    // Loss of an operation to the first provider must retain its unknown custody.
    // This enrollment permits replacing only the third provider, not creating an
    // unauthorized replacement for the interrupted original during reconnection.
    enrollment.source = set.data.providers[2].key;
    let enrollment = authorize(&directory, enrollment, &owner);
    drop(set);
    let socket = temp.path().join("restarting-core.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (stop, stopping) = oneshot::channel();
    let server = async {
        let mut control = listener.accept().await.unwrap().0;
        let request = read_request(&mut control).await.unwrap();
        let Some(Operation::PrivateStorageMaintenance(admission)) = request.operation else {
            panic!("expected owner maintenance admission");
        };
        assert_eq!(admission.owner_key, enrollment.owner);
        assert_eq!(admission.enrollment_id, enrollment.id);
        write_response(
            &mut control,
            &ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: request.request_id,
                result: 0,
                diagnostic_code: "PRIVATE_STORAGE_MAINTENANCE_READY".into(),
                private_storage_remote_detail: None,
                payload: Some(Payload::PrivateStorageMaintenanceReady(
                    PrivateStorageMaintenanceReady {
                        turn: vec![9; 32],
                        expires: crate::storage::now().unwrap() + 60,
                        maximum_bytes: admission.maximum_bytes,
                    },
                )),
            },
        )
        .await
        .unwrap();
        let mut operation = listener.accept().await.unwrap().0;
        let attempted = read_request(&mut operation).await.unwrap();
        assert!(matches!(
            attempted.operation,
            Some(Operation::PrivateStorageRemote(_))
        ));
        // The owner's begin marker is durable before this IPC request. Lose both
        // streams before completion, just as an unavailable core would do.
        drop((operation, control, listener));
        fs::remove_file(&socket).unwrap();
        wait_for_stage(&directory, "core_unavailable").await;
        assert_eq!(status(&directory)["turns"], 1);
        let set = LockedFragments::open(&enrollment.archive).unwrap();
        let retained = set.report("status").unwrap();
        assert_eq!(
            retained["physical_payload_charge_upper_bound"],
            original_charge
        );
        assert!(retained["uncertain_payload_bytes"].as_u64().unwrap() > 0);
        assert_eq!(targets(&set), original_targets);
        drop(set);
        let listener = UnixListener::bind(&socket).unwrap();
        coordinator(
            listener,
            peers.socket.clone(),
            enrollment.owner,
            enrollment.id,
            stopping,
        )
        .await
    };
    let owner_loop = async {
        serve_enrolled(&directory, &enrollment, &socket, &owner, Some(5), pending())
            .await
            .unwrap();
        stop.send(()).unwrap();
    };
    // Four resumed signed/SQLite turns need twice the two-turn fixture's
    // envelope, including reconnect and EOF joins. Hosted run 38254373355
    // completed only three resumed turns in 9.2 s before the old 10 s bound.
    // This bounds the test, not a production turn or authorization lifetime.
    let ((), observed) = timeout(Duration::from_secs(20), async {
        tokio::join!(owner_loop, server)
    })
    .await
    .unwrap();
    assert_eq!(observed, (4, 4));
    assert_eq!(status(&directory)["turns"], 5);
    let set = LockedFragments::open(&enrollment.archive).unwrap();
    assert_eq!(targets(&set), original_targets);
    let report = set.report("status").unwrap();
    assert_eq!(
        report["physical_payload_charge_upper_bound"],
        original_charge
    );
    assert_eq!(report["uncertain_payload_bytes"], 0);
    assert_eq!(report["placement_authorizations"], serde_json::Value::Null);
    drop(set);
    peers.stop().await;
}

#[tokio::test]
async fn finite_authority_expires_while_waiting_for_core_response_and_closes_connection() {
    let (temp, owner, mut enrollment, directory, peers) = fixture().await;
    // Keep one finite signed deadline clear of signing/fsync and socket setup.
    // Only after the real request arrives do we advance its derived Tokio timer;
    // this tests waiting-socket cancellation, not elapsed wall-clock time.
    enrollment.expires = crate::storage::now().unwrap() + 60;
    let enrollment = authorize(&directory, enrollment, &owner);
    let socket = temp.path().join("silent-core.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let admission = async {
        let mut control = listener.accept().await.unwrap().0;
        let request = read_request(&mut control).await.unwrap();
        let Some(Operation::PrivateStorageMaintenance(admission)) = request.operation else {
            panic!("owner did not request a maintenance allowance");
        };
        assert_eq!(admission.owner_key, enrollment.owner);
        assert_eq!(admission.enrollment_id, enrollment.id);
        assert_eq!(admission.maximum_bytes, enrollment.maximum_turn);
        control
    };
    let owner_loop = serve_enrolled(&directory, &enrollment, &socket, &owner, None, pending());
    tokio::pin!(owner_loop);
    let mut control = timeout(Duration::from_secs(3), async {
        tokio::select! {
            result = &mut owner_loop => panic!("owner returned before admission: {result:?}"),
            control = admission => control,
        }
    })
    .await
    .expect("owner admission request did not arrive");
    assert_eq!(status(&directory)["stage"], "waiting_for_core");
    assert_eq!(status(&directory)["turns"], 0);
    let remaining = enrollment
        .expires
        .checked_sub(crate::storage::now().unwrap())
        .filter(|remaining| *remaining > 0)
        .expect("signed authority expired before timer observation");
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(remaining + 1)).await;
    tokio::time::resume();
    // Do not carry the admission timeout across the virtual time jump. Poll the
    // owner to completion before checking the resulting checkpoint and real EOF.
    timeout(Duration::from_secs(3), &mut owner_loop)
        .await
        .expect("owner did not finish after its expiry timer")
        .expect("owner expiry failed");
    assert_eq!(
        timeout(Duration::from_secs(3), control.read(&mut [0]))
            .await
            .expect("expired owner did not close the waiting resource socket")
            .unwrap(),
        0,
        "expired owner closes the actual waiting resource connection"
    );
    assert_eq!(status(&directory)["stage"], "enrollment_expired");
    assert_eq!(status(&directory)["turns"], 0);
    peers.stop().await;
}
