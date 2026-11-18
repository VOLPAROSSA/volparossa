use std::future::pending;

use tokio::time::{advance, sleep};
use volparossa_content::private_storage::wire::begin_observation::{Observer, Phase as WirePhase};

use super::super::{ContentError, Deadline, Observation, Stage};
use super::*;

#[tokio::test(start_paused = true)]
async fn challenge_read_opt_in_retains_original_deadline_and_freezes_only_observed_steps() {
    use volparossa_content::private_storage::wire::begin_observation::ReadStep;
    for enabled in [false, true] {
        let observation = Observation::default().with_challenge_read(enabled);
        let started = Instant::now();
        let operation = observation.budget(Deadline::Operation, Duration::from_secs(120), async {
            observation
                .boundary(Stage::Challenge, async {
                    observation.phase(WirePhase::ChallengeReadVerify);
                    observation.read_step(ReadStep::BodyRead);
                    pending::<Result<(), ContentError>>().await
                })
                .await
        });
        advance(Duration::from_secs(3)).await;
        assert!(matches!(operation.await, Err(ContentError::Unavailable)));
        assert_eq!(started.elapsed(), Duration::from_secs(120));
        let detail = observation.detail().unwrap();
        assert_eq!(detail.deadline_scope, Deadline::Operation as i32);
        let challenge = detail.challenge.unwrap();
        assert_eq!(challenge.before_challenge, Bucket::S1To5 as i32);
        assert_eq!(challenge.in_challenge, Bucket::S90To120 as i32);
        assert_eq!(challenge.read.is_some(), enabled);
        if let Some(read) = challenge.read {
            assert_eq!(read.step, Step::BodyRead as i32);
            assert!(read.returned_outcome.is_none());
        }
        observation.read_failure(
            volparossa_content::private_storage::wire::begin_observation::ReadFailure::IoOther,
        );
        assert_eq!(observation.detail().unwrap(), detail);
        observation.reset();
        assert!(observation.detail().is_none());
    }
}

#[tokio::test]
async fn challenge_read_records_only_a_returned_wire_error_within_read_verify() {
    let observation = Observation::default().with_challenge_read(true);
    observation.challenge.start_operation(Instant::now());
    let result = observation
        .boundary(Stage::Challenge, async {
            observation.phase(WirePhase::ChallengeReadVerify);
            observation.read_step(
                volparossa_content::private_storage::wire::begin_observation::ReadStep::LengthRead,
            );
            observation.read_failure(
                volparossa_content::private_storage::wire::begin_observation::ReadFailure::IoEof,
            );
            Err::<(), _>(ContentError::Unavailable)
        })
        .await;
    assert!(result.is_err());
    let detail = observation.detail().unwrap();
    assert_eq!(detail.deadline_scope, Deadline::None as i32);
    assert_eq!(
        detail.challenge.unwrap().read.unwrap().returned_outcome,
        Some(Outcome::IoEof as i32)
    );
    observation.boundary(Stage::Challenge, async {
        observation.phase(WirePhase::ChallengeReadVerify);
        observation.read_step(volparossa_content::private_storage::wire::begin_observation::ReadStep::Verification);
        Ok(())
    }).await.unwrap();
    assert!(observation.detail().is_none());
}

#[test]
fn challenge_elapsed_bucket_boundaries_are_exact_and_finite() {
    let bounds = [
        (1, Bucket::Under1s, Bucket::S1To5),
        (5, Bucket::S1To5, Bucket::S5To15),
        (15, Bucket::S5To15, Bucket::S15To30),
        (30, Bucket::S15To30, Bucket::S30To60),
        (60, Bucket::S30To60, Bucket::S60To90),
        (90, Bucket::S60To90, Bucket::S90To120),
        (120, Bucket::S90To120, Bucket::AtLeast120s),
    ];
    assert_eq!(bucket(Duration::ZERO), Bucket::Under1s);
    for (seconds, before, at) in bounds {
        let boundary = Duration::from_secs(seconds);
        assert_eq!(bucket(boundary - Duration::from_nanos(1)), before);
        assert_eq!(bucket(boundary), at);
        assert_eq!(bucket(boundary + Duration::from_nanos(1)), at);
    }
    assert_eq!(bucket(Duration::MAX), Bucket::AtLeast120s);
}

#[tokio::test(start_paused = true)]
async fn challenge_progress_freezes_failure_time_and_never_exposes_unentered_steps() {
    let progress = Progress::default();
    progress.start_operation(Instant::now());
    advance(Duration::from_secs(95)).await;
    progress.enter();
    assert!(progress.detail().is_none());
    progress.phase(Phase::GrantWriteFlush);
    advance(Duration::from_secs(7)).await;
    progress.fail();
    let detail = progress.detail().unwrap();
    assert_eq!(detail.phase, Phase::GrantWriteFlush as i32);
    assert_eq!(detail.before_challenge, Bucket::S90To120 as i32);
    assert_eq!(detail.in_challenge, Bucket::S5To15 as i32);
    advance(Duration::from_secs(120)).await;
    progress.phase(Phase::ChallengeReadVerify);
    progress.fail();
    assert_eq!(progress.detail(), Some(detail));
    progress.reset();
    progress.phase(Phase::SelectorWriteFlush);
    progress.fail();
    assert!(progress.detail().is_none());
}

#[tokio::test(start_paused = true)]
async fn challenge_operation_budget_includes_preparation_without_restarting_deadline() {
    let observation = Observation::default();
    let started = Instant::now();
    let result = observation
        .budget(Deadline::Operation, Duration::from_secs(120), async {
            observation
                .boundary(Stage::RouteConnect, async {
                    sleep(Duration::from_secs(95)).await;
                    Ok(())
                })
                .await?;
            observation
                .boundary(Stage::Challenge, async {
                    observation.phase(WirePhase::ChallengeReadVerify);
                    pending::<Result<(), ContentError>>().await
                })
                .await
        })
        .await;
    assert!(matches!(result, Err(ContentError::Unavailable)));
    assert!(started.elapsed() >= Duration::from_secs(120));
    assert!(started.elapsed() < Duration::from_secs(121));
    let detail = observation.detail().unwrap();
    assert_eq!(detail.deadline_scope, Deadline::Operation as i32);
    let challenge = detail.challenge.unwrap();
    assert_eq!(challenge.phase, Phase::ChallengeReadVerify as i32);
    assert_eq!(challenge.before_challenge, Bucket::S90To120 as i32);
    assert_eq!(challenge.in_challenge, Bucket::S15To30 as i32);
}

#[tokio::test(start_paused = true)]
async fn challenge_operation_start_precedes_first_poll_and_preserves_inner_deadline() {
    let observation = Observation::default();
    let started = Instant::now();
    let operation = observation.budget(Deadline::Operation, Duration::from_secs(120), async {
        observation
            .budget(
                Deadline::Exchange,
                Duration::from_secs(10),
                observation.boundary(Stage::Challenge, async {
                    observation.phase(WirePhase::SelectorWriteFlush);
                    pending::<Result<(), ContentError>>().await
                }),
            )
            .await
    });
    advance(Duration::from_secs(90)).await;
    assert!(matches!(operation.await, Err(ContentError::Unavailable)));
    assert!(started.elapsed() >= Duration::from_secs(100));
    assert!(started.elapsed() < Duration::from_secs(101));
    let detail = observation.detail().unwrap();
    assert_eq!(detail.deadline_scope, Deadline::Exchange as i32);
    let challenge = detail.challenge.unwrap();
    assert_eq!(challenge.before_challenge, Bucket::S90To120 as i32);
    assert_eq!(challenge.in_challenge, Bucket::S5To15 as i32);
}

#[tokio::test(start_paused = true)]
async fn challenge_delayed_first_poll_does_not_restart_the_operation_deadline() {
    let observation = Observation::default();
    let started = Instant::now();
    let operation = observation.budget(
        Deadline::Operation,
        Duration::from_secs(120),
        observation.boundary(Stage::Challenge, async {
            observation.phase(WirePhase::GrantWriteFlush);
            pending::<Result<(), ContentError>>().await
        }),
    );
    advance(Duration::from_secs(90)).await;
    assert!(matches!(operation.await, Err(ContentError::Unavailable)));
    assert!(started.elapsed() >= Duration::from_secs(120));
    assert!(started.elapsed() < Duration::from_secs(121));
    let detail = observation.detail().unwrap();
    assert_eq!(detail.deadline_scope, Deadline::Operation as i32);
    let challenge = detail.challenge.unwrap();
    assert_eq!(challenge.before_challenge, Bucket::S90To120 as i32);
    assert_eq!(challenge.in_challenge, Bucket::S30To60 as i32);
}

#[tokio::test(start_paused = true)]
async fn challenge_success_and_other_boundaries_clear_request_local_progress() {
    let observation = Observation::default();
    observation
        .budget(Deadline::Operation, Duration::from_secs(120), async {
            observation
                .boundary(Stage::Challenge, async {
                    observation.phase(WirePhase::GrantWriteFlush);
                    Ok(())
                })
                .await
        })
        .await
        .unwrap();
    assert!(observation.detail().is_none());
    observation.phase(WirePhase::ChallengeReadVerify);
    assert!(observation.detail().is_none());
    let _ = observation
        .boundary(Stage::Challenge, async {
            observation.phase(WirePhase::SelectorWriteFlush);
            Err::<(), _>(ContentError::Unavailable)
        })
        .await;
    assert!(observation.detail().unwrap().challenge.is_some());
    let _ = observation
        .boundary(Stage::ProviderLookup, async {
            observation.phase(WirePhase::GrantWriteFlush);
            Err::<(), _>(ContentError::Unavailable)
        })
        .await;
    assert!(observation.detail().unwrap().challenge.is_none());
    assert!(Observation::default().detail().is_none());
}

#[tokio::test]
async fn challenge_requester_cancellation_clears_progress_without_failure_projection() {
    let (client, mut server) = tokio::net::UnixStream::pair().unwrap();
    let (started, running) = tokio::sync::oneshot::channel();
    let task = tokio::spawn(async move {
        let observation = Observation::default().with_challenge_read(true);
        let result = observation
            .budget(
                Deadline::Operation,
                Duration::from_secs(120),
                observation.requester_boundary(Stage::Challenge, &mut server, async {
                    observation.phase(WirePhase::ChallengeReadVerify);
                    observation.read_step(
                        volparossa_content::private_storage::wire::begin_observation::ReadStep::BodyRead,
                    );
                    started.send(()).unwrap();
                    pending::<Result<(), ContentError>>().await
                }),
            )
            .await;
        assert!(observation.detail().is_none());
        result
    });
    running.await.unwrap();
    drop(client);
    let result = tokio::time::timeout(Duration::from_secs(2), task)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(ContentError::Unavailable)));
}
