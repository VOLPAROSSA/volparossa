use super::*;

fn failed(owner: &Arc<Outcomes>, uid: u32, id: &[u8]) {
    let guard = owner.begin(uid, id).unwrap();
    guard.enter(Phase::RemoteReceiptRead);
    guard.wire_error(&WireError::Io(std::io::Error::other("private-canary")));
    guard.finish(
        &Err(ContentError::Unavailable),
        PrivateStorageDeadlineScope::None,
    );
}

#[test]
fn exact_uid_and_request_binding_is_one_use_and_does_not_consume_siblings() {
    let owner = Arc::new(Outcomes::default());
    failed(&owner, 12, &[1; 16]);
    failed(&owner, 13, &[1; 16]);
    assert_eq!(owner.take(14, &[1; 16]).unwrap(), status(Status::Missing));
    assert_eq!(owner.take(12, &[2; 16]).unwrap(), status(Status::Missing));
    for uid in [12, 13] {
        let result = owner.take(uid, &[1; 16]).unwrap();
        result.validate().unwrap();
        assert_eq!(result.status, Status::Observed as i32);
        assert_eq!(result.phase, Phase::RemoteReceiptRead as i32);
        assert_eq!(result.category, Category::Io as i32);
        assert!(!format!("{result:?}").contains("private-canary"));
        assert_eq!(owner.take(uid, &[1; 16]).unwrap(), status(Status::Missing));
    }
}

#[test]
fn pending_and_duplicate_ids_do_not_replace_or_consume_the_owned_slot() {
    let owner = Arc::new(Outcomes::default());
    let guard = owner.begin(1, &[4; 16]).unwrap();
    for _ in 0..2 {
        assert_eq!(owner.take(1, &[4; 16]).unwrap(), status(Status::Pending));
        assert!(matches!(owner.begin(1, &[4; 16]), Err(ContentError::Busy)));
    }
    drop(guard);
    assert_eq!(owner.take(1, &[4; 16]).unwrap(), status(Status::Missing));
}

#[tokio::test(start_paused = true)]
async fn capacity_omission_never_gates_storage_or_evicts_live_results_and_expiry_is_exact() {
    let owner = Arc::new(Outcomes::default());
    let pending = owner.begin(1, &[255; 16]).unwrap();
    for id in 0..63 {
        failed(&owner, 1, &[id; 16]);
    }
    assert_eq!(owner.0.lock().unwrap().len(), CAPACITY);
    let omitted = owner.begin(1, &[254; 16]).unwrap();
    assert!(!omitted.tracked);
    omitted.enter(Phase::RemoteReceiptRead);
    assert_eq!(owner.take(1, &[254; 16]).unwrap(), status(Status::Missing));
    assert_eq!(owner.0.lock().unwrap().len(), CAPACITY);
    // Free one slot, then reuse the untracked operation's ID in a tracked operation.
    assert_eq!(
        owner.take(1, &[0; 16]).unwrap().status,
        Status::Observed as i32
    );
    let admitted = owner.begin(1, &[254; 16]).unwrap();
    assert!(admitted.tracked);
    drop(omitted);
    assert_eq!(owner.take(1, &[254; 16]).unwrap(), status(Status::Pending));
    tokio::time::advance(RETENTION).await;
    assert_eq!(owner.take(1, &[1; 16]).unwrap(), status(Status::Expired));
    let later = owner.begin(1, &[253; 16]).unwrap();
    assert_eq!(owner.0.lock().unwrap().len(), 3);
    assert_eq!(owner.take(1, &[255; 16]).unwrap(), status(Status::Pending));
    drop(later);
    drop(admitted);
    drop(pending);
    assert!(owner.0.lock().unwrap().is_empty());
}

#[test]
fn success_and_pre_ready_failure_leave_no_outcome_but_post_ready_cancel_is_explicit() {
    let owner = Arc::new(Outcomes::default());
    owner.begin(1, &[1; 16]).unwrap().finish(
        &Err(ContentError::Unavailable),
        PrivateStorageDeadlineScope::Operation,
    );
    assert_eq!(owner.take(1, &[1; 16]).unwrap(), status(Status::Missing));
    let success = owner.begin(1, &[2; 16]).unwrap();
    success.enter(Phase::TerminalWrite);
    success.finish(&Ok(()), PrivateStorageDeadlineScope::None);
    assert_eq!(owner.take(1, &[2; 16]).unwrap(), status(Status::Missing));
    let cancelled = owner.begin(1, &[3; 16]).unwrap();
    cancelled.enter(Phase::LocalRequestRead);
    drop(cancelled);
    let result = owner.take(1, &[3; 16]).unwrap();
    result.validate().unwrap();
    assert_eq!(result.category, Category::Cancelled as i32);
    assert_eq!(result.deadline, Deadline::None as i32);
}

#[tokio::test(start_paused = true)]
async fn actual_outer_timeouts_retain_entered_phase_and_exact_budget() {
    use crate::content::private_storage::observation::Observation;
    for (id, scope, expected) in [
        (
            1,
            PrivateStorageDeadlineScope::Operation,
            Deadline::Operation,
        ),
        (2, PrivateStorageDeadlineScope::Exchange, Deadline::Exchange),
    ] {
        let owner = Arc::new(Outcomes::default());
        let guard = owner.begin(1, &[id; 16]).unwrap();
        let observation = Observation::default();
        let result = observation
            .budget(scope, Duration::from_secs(1), async {
                guard.enter(Phase::LocalRequestRead);
                std::future::pending::<Result<(), ContentError>>().await
            })
            .await;
        guard.finish(&result, observation.deadline());
        let result = owner.take(1, &[id; 16]).unwrap();
        result.validate().unwrap();
        assert_eq!(result.phase, Phase::LocalRequestRead as i32);
        assert_eq!(result.category, Category::Timeout as i32);
        assert_eq!(result.deadline, expected as i32);
    }
}

#[tokio::test]
async fn task_abort_records_cancel_before_the_owned_stream_closes() {
    use tokio::{io::AsyncReadExt, net::UnixStream, sync::oneshot};
    let owner = Arc::new(Outcomes::default());
    let (mut client, server) = UnixStream::pair().unwrap();
    let guard = owner.begin(1, &[5; 16]).unwrap();
    let (send, started) = oneshot::channel();
    let task = tokio::spawn(async move {
        let stream = server;
        let retained = guard;
        retained.enter(Phase::RemoteReceiptRead);
        send.send(()).unwrap();
        std::future::pending::<()>().await;
        drop(retained);
        drop(stream);
    });
    started.await.unwrap();
    assert_eq!(
        client.try_read(&mut [0; 1]).unwrap_err().kind(),
        std::io::ErrorKind::WouldBlock
    );
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
    let result = owner.take(1, &[5; 16]).unwrap();
    result.validate().unwrap();
    assert_eq!(result.phase, Phase::RemoteReceiptRead as i32);
    assert_eq!(result.category, Category::Cancelled as i32);
    assert_eq!(result.deadline, Deadline::None as i32);
}

#[test]
fn wire_deadlines_and_explicit_turn_cancellation_are_not_counterfeit_outer_timeouts() {
    let owner = Arc::new(Outcomes::default());
    for (id, scope, expected) in [
        (1, bridge_observation::Deadline::Bridge, Deadline::Bridge),
        (
            2,
            bridge_observation::Deadline::RemoteWire,
            Deadline::RemoteWire,
        ),
    ] {
        let guard = owner.begin(1, &[id; 16]).unwrap();
        guard.enter(Phase::RemoteReceiptRead);
        guard.deadline(scope);
        guard.wire_error(&WireError::Timeout);
        guard.finish(
            &Err(ContentError::Unavailable),
            PrivateStorageDeadlineScope::None,
        );
        let result = owner.take(1, &[id; 16]).unwrap();
        result.validate().unwrap();
        assert_eq!(result.deadline, expected as i32);
        assert_eq!(result.category, Category::Timeout as i32);
    }
    let guard = owner.begin(1, &[3; 16]).unwrap();
    guard.enter(Phase::Admission);
    guard.cancelled();
    guard.finish(&Err(ContentError::Busy), PrivateStorageDeadlineScope::None);
    let result = owner.take(1, &[3; 16]).unwrap();
    result.validate().unwrap();
    assert_eq!(result.category, Category::Cancelled as i32);
    assert_eq!(result.deadline, Deadline::None as i32);
}

#[tokio::test(start_paused = true)]
async fn append_timing_reuses_original_operation_start_before_poll_and_outer_timeout() {
    use crate::content::private_storage::observation::Observation;
    use volparossa_local_control::PrivateStorageElapsedBucket as Bucket;

    let owner = Arc::new(Outcomes::default());
    let guard = owner.begin(1, &[11; 16]).unwrap();
    let observation = Observation::default();
    let operation = observation.budget(
        PrivateStorageDeadlineScope::Operation,
        Duration::from_secs(120),
        async {
            guard.enter(Phase::RemotePayloadWrite);
            tokio::time::sleep(Duration::from_secs(5)).await;
            guard.enter(Phase::RemoteReceiptRead);
            std::future::pending::<Result<(), ContentError>>().await
        },
    );
    guard.start_operation(observation.operation_started());
    // Includes time already spent before this future is first polled; no second clock origin.
    tokio::time::advance(Duration::from_secs(30)).await;
    let result = operation.await;
    assert!(matches!(result, Err(ContentError::Unavailable)));
    guard.finish(&result, observation.deadline());
    let outcome = owner.take(1, &[11; 16]).unwrap();
    outcome.validate().unwrap();
    assert_eq!(outcome.deadline, Deadline::Operation as i32);
    assert_eq!(outcome.category, Category::Timeout as i32);
    let timing = outcome.append_timing.unwrap();
    assert_eq!(timing.before_payload, Bucket::S30To60 as i32);
    assert_eq!(timing.in_payload_write_flush, Bucket::S5To15 as i32);
    assert_eq!(timing.in_receipt_read, Some(Bucket::S60To90 as i32));
}

#[tokio::test(start_paused = true)]
async fn append_timing_wire_failure_freezes_before_later_finish_and_success_has_no_record() {
    use volparossa_local_control::PrivateStorageElapsedBucket as Bucket;

    let owner = Arc::new(Outcomes::default());
    let guard = owner.begin(1, &[12; 16]).unwrap();
    guard.start_operation(Some(Instant::now()));
    guard.enter(Phase::RemotePayloadWrite);
    tokio::time::advance(Duration::from_secs(5)).await;
    guard.wire_error(&WireError::Io(std::io::Error::other(
        "/private/ciphertext-canary",
    )));
    tokio::time::advance(Duration::from_secs(60)).await;
    guard.finish(
        &Err(ContentError::Unavailable),
        PrivateStorageDeadlineScope::None,
    );
    let outcome = owner.take(1, &[12; 16]).unwrap();
    outcome.validate().unwrap();
    assert_eq!(outcome.category, Category::Io as i32);
    let timing = outcome.append_timing.unwrap();
    assert_eq!(timing.in_payload_write_flush, Bucket::S5To15 as i32);
    assert_eq!(timing.in_receipt_read, None);
    assert!(!format!("{outcome:?}").contains("canary"));
    let success = owner.begin(1, &[13; 16]).unwrap();
    success.start_operation(Some(Instant::now()));
    success.enter(Phase::RemotePayloadWrite);
    success.enter(Phase::RemoteReceiptRead);
    success.finish(&Ok(()), PrivateStorageDeadlineScope::None);
    assert_eq!(owner.take(1, &[13; 16]).unwrap(), status(Status::Missing));
}

#[tokio::test(start_paused = true)]
async fn append_timing_abort_is_retained_before_socket_close_without_a_timeout_claim() {
    use tokio::{io::AsyncReadExt, net::UnixStream, sync::oneshot};
    use volparossa_local_control::PrivateStorageElapsedBucket as Bucket;

    let owner = Arc::new(Outcomes::default());
    let (mut client, server) = UnixStream::pair().unwrap();
    let guard = owner.begin(1, &[14; 16]).unwrap();
    guard.start_operation(Some(Instant::now()));
    let (send, started) = oneshot::channel();
    let task = tokio::spawn(async move {
        let stream = server;
        let retained = guard;
        retained.enter(Phase::RemotePayloadWrite);
        send.send(()).unwrap();
        std::future::pending::<()>().await;
        drop(retained);
        drop(stream);
    });
    started.await.unwrap();
    tokio::time::advance(Duration::from_secs(15)).await;
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(client.read(&mut [0; 1]).await.unwrap(), 0);
    let outcome = owner.take(1, &[14; 16]).unwrap();
    outcome.validate().unwrap();
    assert_eq!(outcome.category, Category::Cancelled as i32);
    assert_eq!(outcome.deadline, Deadline::None as i32);
    let timing = outcome.append_timing.unwrap();
    assert_eq!(timing.in_payload_write_flush, Bucket::S15To30 as i32);
    assert_eq!(timing.in_receipt_read, None);
}
