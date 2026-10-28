//! Public in-memory/channel and private-directory fixtures, never model execution.
//! `run_owned` cases exercise the real idle/event/cleanup path without a submitted turn.

use std::{future::Future, pin::Pin};

use super::*;
use tokio::time::advance;

fn parent() -> tempfile::TempDir {
    let parent = tempfile::tempdir().unwrap();
    fs::set_permissions(parent.path(), fs::Permissions::from_mode(0o700)).unwrap();
    parent
}

fn config(parent: &Path) -> private_task::ExecutionConfig {
    private_task::ExecutionConfig {
        runtime_root: parent.join("runtime-not-provisioned"),
        model_root: parent.join("model-not-provisioned"),
        work_parent: parent.to_owned(),
        model_profile: crate::compute::ModelProfile::Qwen4bInstruct2507,
        native_backend: native_cpu::Options::default(),
        threads: 2,
        max_seconds: 600,
    }
}

fn resident(turn: u16) -> Resident {
    Resident {
        worker: None,
        hints: None,
        turn,
    }
}

fn input() -> Vec<u8> {
    serde_json::to_vec(&json!({
        "version":1,"visibility":"private_local","generation_policy":"greedy_v1",
        "instructions":"Public software fixture.","tools":[],
        "history":[{"type":"message","role":"user","text":"Hello."}]
    }))
    .unwrap()
}

fn is_deadline(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<super::super::ExecutionDeadline>()
        .is_some()
}

async fn opened<F: Future<Output = Result<Value>>>(
    task: &mut Pin<Box<F>>,
    events: &mut mpsc::Receiver<Event>,
) {
    tokio::select! {
        biased;
        _ = task.as_mut() => panic!("session ended before its opened event"),
        event = events.recv() => assert!(matches!(event, Some(Event::Opened))),
    }
}

#[tokio::test(start_paused = true)]
async fn budget_rejects_expired_excessive_lifetime_and_request_counts() {
    let now = Instant::now();
    for deadline in [now - Duration::from_secs(1), now] {
        let error = SessionBudget::new(deadline, 1).err().unwrap();
        assert!(is_deadline(&error));
        assert_eq!(cleanup(&error), None);
    }
    assert!(SessionBudget::new(now + Duration::from_secs(MAX_TASK_SECONDS + 1), 1).is_err());
    for count in [0, MAX_REQUESTS + 1, u16::MAX] {
        assert!(SessionBudget::new(now + Duration::from_secs(1), count).is_err());
    }
    for count in [1, MAX_REQUESTS] {
        let deadline = now + Duration::from_secs(MAX_TASK_SECONDS);
        let budget = SessionBudget::new(deadline, count).unwrap();
        assert_eq!(budget.deadline(), deadline);
        assert_eq!(budget.maximum_requests(), count);
    }
}

#[tokio::test(start_paused = true)]
async fn delayed_start_consumes_the_original_parent_lifetime() {
    let parent = parent();
    let config = config(parent.path());
    let root = PrivateRoot::new(parent.path()).unwrap();
    let root_path = root.path().to_owned();
    let deadline = Instant::now() + Duration::from_secs(20);
    let budget = SessionBudget::new(deadline, 1).unwrap();
    advance(Duration::from_secs(7)).await;
    let (_commands, commands) = mpsc::channel(1);
    let (events, mut received) = mpsc::channel(1);
    let (_owner, activity) = watch::channel(true);
    let mut task = Box::pin(run_owned(
        &config, root, commands, events, activity, &budget,
    ));
    opened(&mut task, &mut received).await;
    assert!(root_path.exists());
    assert_eq!(budget.deadline(), deadline);
    advance(Duration::from_secs(13)).await;
    // Quiet task expiry retains the historical normal-close behavior.
    assert_eq!(task.await.unwrap(), cleanup_record());
    assert_eq!(Instant::now(), deadline);
    assert!(!root_path.exists());
}

#[tokio::test(start_paused = true)]
async fn expired_budget_rejects_before_configuration_or_private_root_creation() {
    let parent = parent();
    let budget = SessionBudget::new(Instant::now() + Duration::from_secs(1), 1).unwrap();
    let (_commands, commands) = mpsc::channel(1);
    let (events, mut received) = mpsc::channel(1);
    let (_owner, activity) = watch::channel(true);
    // These deliberately unprovisioned paths cannot reach model/sandbox execution.
    let task = Box::pin(run_bounded(
        Arc::new(config(parent.path())),
        commands,
        events,
        activity,
        budget,
    ));
    advance(Duration::from_secs(1)).await;
    let error = task.await.unwrap_err();
    assert!(is_deadline(&error));
    assert_eq!(cleanup(&error), None);
    assert!(received.recv().await.is_none());
    assert_eq!(fs::read_dir(parent.path()).unwrap().count(), 0);
}

#[tokio::test(start_paused = true)]
async fn expiry_after_root_creation_still_uses_real_cleanup() {
    let parent = parent();
    let config = config(parent.path());
    let root = PrivateRoot::new(parent.path()).unwrap();
    let root_path = root.path().to_owned();
    fs::write(root_path.join("public-fixture"), b"public").unwrap();
    let budget = SessionBudget::new(Instant::now() + Duration::from_secs(1), 1).unwrap();
    let (_commands, commands) = mpsc::channel(1);
    let (events, mut received) = mpsc::channel(1);
    let (_owner, activity) = watch::channel(true);
    advance(Duration::from_secs(1)).await;
    let error = run_owned(&config, root, commands, events, activity, &budget)
        .await
        .unwrap_err();
    assert!(execution_deadline(&error));
    assert_eq!(cleanup(&error), Some(cleanup_record()));
    assert!(!root_path.exists());
    assert!(received.recv().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn turn_deadlines_keep_the_parent_cap_and_existing_six_hundred_second_limit() {
    let start = Instant::now();
    let budget = SessionBudget::new(start + Duration::from_secs(700), 2).unwrap();
    assert_eq!(
        budget.turn_deadline(600).unwrap(),
        start + Duration::from_secs(600)
    );
    assert!(budget.turn_deadline(0).is_err());
    assert!(budget.turn_deadline(601).is_err());
    advance(Duration::from_secs(200)).await;
    assert_eq!(budget.turn_deadline(600).unwrap(), budget.deadline());
    assert_eq!(
        budget.turn_deadline(20).unwrap(),
        start + Duration::from_secs(220)
    );
    advance(Duration::from_secs(500)).await;
    assert!(is_deadline(&budget.turn_deadline(600).unwrap_err()));
}

#[tokio::test(start_paused = true)]
async fn request_ceiling_rejects_before_parsing_staging_or_worker_start() {
    let parent = parent();
    let config = config(parent.path());
    let root = PrivateRoot::new(parent.path()).unwrap();
    let budget = SessionBudget::new(Instant::now() + Duration::from_secs(30), 1).unwrap();
    let mut resident = resident(1);
    let (_owner, mut activity) = watch::channel(true);
    let error = resident
        .submit(
            &config,
            root.path(),
            "public-fixture".into(),
            b"invalid",
            &budget,
            &mut activity,
        )
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "compute_native_session_request_bound");
    assert_eq!(resident.turn, 1);
    assert!(resident.worker.is_none() && resident.hints.is_none());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    root.close().unwrap();
}

#[tokio::test(start_paused = true)]
async fn expired_turn_rejects_before_staging_and_consuming_a_request() {
    let parent = parent();
    let config = config(parent.path());
    let root = PrivateRoot::new(parent.path()).unwrap();
    let budget = SessionBudget::new(Instant::now() + Duration::from_secs(1), 1).unwrap();
    let mut resident = resident(0);
    let (_owner, mut activity) = watch::channel(true);
    advance(Duration::from_secs(1)).await;
    let error = resident
        .submit(
            &config,
            root.path(),
            "public-fixture".into(),
            &input(),
            &budget,
            &mut activity,
        )
        .await
        .unwrap_err();
    assert!(is_deadline(&error));
    assert_eq!(resident.turn, 0);
    assert!(resident.worker.is_none() && resident.hints.is_none());
    assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
    root.close().unwrap();
}

#[tokio::test(start_paused = true)]
async fn cancelled_or_lost_owner_rejects_before_staging() {
    for disconnected in [false, true] {
        let parent = parent();
        let config = config(parent.path());
        let root = PrivateRoot::new(parent.path()).unwrap();
        let budget = SessionBudget::new(Instant::now() + Duration::from_secs(30), 1).unwrap();
        let mut resident = resident(0);
        let (owner, mut activity) = watch::channel(disconnected);
        if disconnected {
            drop(owner);
        }
        let error = resident
            .submit(
                &config,
                root.path(),
                "public-fixture".into(),
                &input(),
                &budget,
                &mut activity,
            )
            .await
            .unwrap_err();
        assert_eq!(error.to_string(), "compute_owner_busy");
        assert_eq!(resident.turn, 0);
        assert!(resident.worker.is_none() && resident.hints.is_none());
        assert_eq!(fs::read_dir(root.path()).unwrap().count(), 0);
        root.close().unwrap();
    }
}

#[tokio::test(start_paused = true)]
async fn opened_backpressure_expires_and_removes_the_owned_root() {
    let parent = parent();
    let config = config(parent.path());
    let root = PrivateRoot::new(parent.path()).unwrap();
    let root_path = root.path().to_owned();
    let deadline = Instant::now() + Duration::from_secs(5);
    let budget = SessionBudget::new(deadline, 1).unwrap();
    let (_commands, commands) = mpsc::channel(1);
    let (events, mut received) = mpsc::channel(1);
    assert!(events.try_send(Event::Opened).is_ok());
    let (_owner, activity) = watch::channel(true);
    let error = run_owned(&config, root, commands, events, activity, &budget)
        .await
        .unwrap_err();
    assert_eq!(Instant::now(), deadline);
    assert!(execution_deadline(&error));
    assert_eq!(cleanup(&error), Some(cleanup_record()));
    assert!(!root_path.exists());
    assert!(matches!(received.recv().await, Some(Event::Opened)));
    assert!(received.recv().await.is_none());
}

#[tokio::test(start_paused = true)]
async fn result_backpressure_cannot_extend_the_original_deadline() {
    let deadline = Instant::now() + Duration::from_secs(5);
    let (events, mut received) = mpsc::channel(1);
    assert!(events.try_send(Event::Opened).is_ok());
    let (_owner, mut activity) = watch::channel(true);
    let error = budget::send_event(
        &events,
        Event::Result {
            id: "public-fixture".into(),
            value: json!({"public":true}),
        },
        deadline,
        &mut activity,
    )
    .await
    .unwrap_err();
    assert_eq!(Instant::now(), deadline);
    assert!(is_deadline(&error));
    assert_eq!(cleanup(&error), None);
    assert!(matches!(received.try_recv(), Ok(Event::Opened)));
    assert!(received.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn ready_event_capacity_cannot_publish_after_expiry() {
    let deadline = Instant::now() + Duration::from_secs(1);
    let (events, mut received) = mpsc::channel(1);
    let (_owner, mut activity) = watch::channel(true);
    advance(Duration::from_secs(1)).await;
    let error = budget::send_event(&events, Event::Opened, deadline, &mut activity)
        .await
        .unwrap_err();
    assert!(is_deadline(&error));
    assert!(received.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn blocked_event_delivery_observes_owner_cancellation() {
    let deadline = Instant::now() + Duration::from_secs(30);
    let (events, mut received) = mpsc::channel(1);
    assert!(events.try_send(Event::Opened).is_ok());
    let (owner, mut activity) = watch::channel(true);
    let mut send = Box::pin(budget::send_event(
        &events,
        Event::Opened,
        deadline,
        &mut activity,
    ));
    tokio::select! {
        biased;
        _ = &mut send => panic!("full event channel unexpectedly completed"),
        () = tokio::task::yield_now() => {},
    }
    owner.send(false).unwrap();
    assert_eq!(send.await.unwrap_err().to_string(), "compute_owner_busy");
    assert!(Instant::now() < deadline);
    assert!(matches!(received.try_recv(), Ok(Event::Opened)));
    assert!(received.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn benign_owner_update_does_not_drop_a_waiting_result() {
    let deadline = Instant::now() + Duration::from_secs(30);
    let (events, mut received) = mpsc::channel(1);
    assert!(events.try_send(Event::Opened).is_ok());
    let (owner, mut activity) = watch::channel(true);
    let mut send = Box::pin(budget::send_event(
        &events,
        Event::Result {
            id: "public-fixture".into(),
            value: json!({"public":true}),
        },
        deadline,
        &mut activity,
    ));
    owner.send(true).unwrap();
    tokio::select! {
        biased;
        _ = &mut send => panic!("full event channel unexpectedly completed"),
        () = tokio::task::yield_now() => {},
    }
    assert!(matches!(received.recv().await, Some(Event::Opened)));
    send.await.unwrap();
    let Event::Result { id, value } = received.recv().await.unwrap() else {
        panic!("result changed to another event");
    };
    assert_eq!(id, "public-fixture");
    assert_eq!(value, json!({"public":true}));
    assert!(received.try_recv().is_err());
}

#[tokio::test(start_paused = true)]
async fn closed_event_receiver_preserves_failure_and_real_root_cleanup() {
    let parent = parent();
    let config = config(parent.path());
    let root = PrivateRoot::new(parent.path()).unwrap();
    let root_path = root.path().to_owned();
    let budget = SessionBudget::new(Instant::now() + Duration::from_secs(30), 1).unwrap();
    let (_commands, commands) = mpsc::channel(1);
    let (events, received) = mpsc::channel(1);
    drop(received);
    let (_owner, activity) = watch::channel(true);
    let error = run_owned(&config, root, commands, events, activity, &budget)
        .await
        .unwrap_err();
    assert!(!execution_deadline(&error));
    assert_eq!(cleanup(&error), Some(cleanup_record()));
    assert!(!root_path.exists());
}

#[tokio::test(start_paused = true)]
async fn idle_close_keeps_the_existing_three_hundred_second_ceiling() {
    let parent = parent();
    let config = config(parent.path());
    let root = PrivateRoot::new(parent.path()).unwrap();
    let root_path = root.path().to_owned();
    let start = Instant::now();
    let budget = SessionBudget::new(start + Duration::from_secs(400), MAX_REQUESTS).unwrap();
    let (_commands, commands) = mpsc::channel(1);
    let (events, mut received) = mpsc::channel(1);
    let (_owner, activity) = watch::channel(true);
    let mut task = Box::pin(run_owned(
        &config, root, commands, events, activity, &budget,
    ));
    opened(&mut task, &mut received).await;
    advance(Duration::from_secs(MAX_IDLE_SECONDS)).await;
    assert_eq!(task.await.unwrap(), cleanup_record());
    assert_eq!(Instant::now(), start + Duration::from_secs(300));
    assert!(!root_path.exists());
}

#[tokio::test(start_paused = true)]
async fn explicit_close_keeps_the_existing_cleanup_shape() {
    let parent = parent();
    let config = config(parent.path());
    let root = PrivateRoot::new(parent.path()).unwrap();
    let root_path = root.path().to_owned();
    let budget =
        SessionBudget::new(Instant::now() + Duration::from_secs(30), MAX_REQUESTS).unwrap();
    let (sender, commands) = mpsc::channel(1);
    assert!(sender.try_send(Command::Close).is_ok());
    let (events, mut received) = mpsc::channel(1);
    let (_owner, activity) = watch::channel(true);
    let result = run_owned(&config, root, commands, events, activity, &budget)
        .await
        .unwrap();
    assert_eq!(
        result,
        json!({"version":1,"child_reaped":true,"private_state_removed":true})
    );
    assert!(matches!(received.recv().await, Some(Event::Opened)));
    assert!(received.recv().await.is_none());
    assert!(!root_path.exists());
}

#[tokio::test(start_paused = true)]
async fn cleanup_failure_dominates_an_expired_execution_budget() {
    let parent = parent();
    let config = config(parent.path());
    let root = PrivateRoot::new(parent.path()).unwrap();
    let root_path = root.path().to_owned();
    // A real filesystem cleanup failure, not a fabricated cleanup status.
    fs::remove_dir(&root_path).unwrap();
    fs::write(&root_path, b"public cleanup-failure fixture").unwrap();
    let budget = SessionBudget::new(Instant::now() + Duration::from_secs(1), 1).unwrap();
    let (_commands, commands) = mpsc::channel(1);
    let (events, _received) = mpsc::channel(1);
    let (_owner, activity) = watch::channel(true);
    advance(Duration::from_secs(1)).await;
    let error = run_owned(&config, root, commands, events, activity, &budget)
        .await
        .unwrap_err();
    assert_eq!(error.to_string(), "compute_private_storage_cleanup_failed");
    assert_eq!(cleanup(&error), None);
    assert!(!execution_deadline(&error));
    assert!(root_path.is_file());
}

#[tokio::test(start_paused = true)]
async fn dropped_owner_future_does_not_fabricate_private_root_removal() {
    let parent = parent();
    let config = config(parent.path());
    let root = PrivateRoot::new(parent.path()).unwrap();
    let root_path = root.path().to_owned();
    let budget = SessionBudget::new(Instant::now() + Duration::from_secs(30), 1).unwrap();
    let (_commands, commands) = mpsc::channel(1);
    let (events, _received) = mpsc::channel(1);
    assert!(events.try_send(Event::Opened).is_ok());
    let (_owner, activity) = watch::channel(true);
    let mut task = Box::pin(run_owned(
        &config, root, commands, events, activity, &budget,
    ));
    tokio::select! {
        biased;
        _ = &mut task => panic!("full event channel unexpectedly completed"),
        () = tokio::task::yield_now() => {},
    }
    drop(task);
    assert!(root_path.is_dir());
}

#[tokio::test(start_paused = true)]
async fn expired_spawn_is_rejected_before_starting_a_sandbox() {
    let parent = parent();
    let config = config(parent.path());
    let root = PrivateRoot::new(parent.path()).unwrap();
    let options = stage(&config, root.path(), 1, &input()).unwrap();
    let error = worker::Live::spawn(&options, root.path(), Instant::now())
        .err()
        .unwrap();
    assert!(is_deadline(&error));
    assert_eq!(cleanup(&error), None);
    root.close().unwrap();
}
