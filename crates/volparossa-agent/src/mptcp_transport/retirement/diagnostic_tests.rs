use super::*;
use crate::mptcp_transport::acquire_diagnostic::Failure;

fn queue_one(owner: &Retirements) -> std::os::unix::net::UnixStream {
    let (socket, peer) = std::os::unix::net::UnixStream::pair().unwrap();
    drop(owner.reserve().unwrap().bind(
        RetireMptcpFlow {
            route_context_id: vec![1; 16],
            context_handle: vec![2; 32],
            mptcp_flow_handle: vec![3; 32],
        },
        socket.into(),
    ));
    peer
}

#[test]
fn flow_acquire_reservation_classification_preserves_original_errors_and_slot_bound() {
    let owner = Retirements::new();
    let held = (0..MAX_FLOWS)
        .map(|_| owner.reserve().unwrap())
        .collect::<Vec<_>>();
    let original = owner.reserve().err().unwrap();
    let (classified, reason) = owner.reserve_classified().err().unwrap();
    assert_eq!(reason, Reason::LocalCapacity);
    assert_eq!(classified.kind(), original.kind());
    assert_eq!(classified.to_string(), original.to_string());
    assert_eq!(owner.0.slots.available_permits(), 0);
    drop(held);
    assert_eq!(owner.0.slots.available_permits(), 64);
    let mut unknown = owner.reserve().unwrap();
    unknown.begin_acquire();
    drop(unknown);
    let original = owner.reserve().err().unwrap();
    let (classified, reason) = owner.reserve_classified().err().unwrap();
    assert_eq!(reason, Reason::Unconfirmed);
    assert_eq!(classified.kind(), original.kind());
    assert_eq!(classified.to_string(), original.to_string());

    // Production never closes this private semaphore. A closed primitive must nevertheless
    // not acquire the stronger diagnostic meaning of an observed exhausted slot count.
    let unavailable = Retirements::new();
    unavailable.0.slots.close();
    let original = unavailable.reserve().err().unwrap();
    let (classified, reason) = unavailable.reserve_classified().err().unwrap();
    assert_eq!(reason, Reason::LocalUnavailable);
    assert_eq!(classified.kind(), original.kind());
    assert_eq!(classified.to_string(), original.to_string());
}

#[test]
fn flow_acquire_classification_precedes_ambiguous_mapping_without_clearing_poison() {
    for (error, reason, definite) in [
        (HelperClientError::Timeout, Reason::HelperTimeout, false),
        (
            HelperClientError::Correlation,
            Reason::HelperCorrelation,
            false,
        ),
        (
            HelperClientError::Rejected(HelperResult::NotFound),
            Reason::HelperNotFound,
            false,
        ),
        (
            HelperClientError::Rejected(HelperResult::CleanupIncomplete),
            Reason::HelperCleanupIncomplete,
            false,
        ),
        (
            HelperClientError::Rejected(HelperResult::Kernel),
            Reason::HelperKernel,
            true,
        ),
        (
            HelperClientError::Rejected(HelperResult::Capacity),
            Reason::HelperCapacity,
            true,
        ),
        (
            HelperClientError::Rejected(HelperResult::Unavailable),
            Reason::HelperUnavailable,
            true,
        ),
    ] {
        let owner = Retirements::new();
        let mut slot = owner.reserve().unwrap();
        slot.begin_acquire();
        let mut observation = Observation::default();
        let returned = slot.acquire_failed_classified(error, &mut observation);
        assert_eq!(
            observation.failure(),
            Some(Failure {
                stage: Stage::HelperAcquire,
                reason,
            }),
        );
        assert_eq!(
            matches!(&returned, MptcpTransportError::Helper(_)),
            definite
        );
        assert_eq!(
            matches!(&returned, MptcpTransportError::AcquireUnconfirmed),
            !definite,
        );
        drop(slot);
        assert_eq!(
            owner.0.acquire_unconfirmed.load(Ordering::Acquire),
            !definite
        );
        assert_eq!(owner.reserve().is_ok(), definite);
        assert_eq!(owner.0.slots.available_permits(), MAX_FLOWS);
    }
}

#[tokio::test]
async fn flow_acquire_classified_drain_keeps_pending_slot_and_not_found_still_retires() {
    let owner = Retirements::new();
    let _peer = queue_one(&owner);
    let mut observation = Observation::default();
    let failed = owner
        .drain_with(|_, _, _| async { Err(HelperClientError::Timeout) })
        .await
        .map_err(|error| observation.transport_error(Stage::RetirementDrain, error));
    assert!(matches!(
        failed,
        Err(MptcpTransportError::Helper(HelperClientError::Timeout)),
    ));
    assert_eq!(observation.failure().unwrap().reason, Reason::HelperTimeout);
    assert_eq!(owner.0.pending.lock().unwrap().len(), 1);
    assert_eq!(owner.0.slots.available_permits(), MAX_FLOWS - 1);
    observation.reset();
    owner
        .drain_with(|_, _, _| async { Err(HelperClientError::Rejected(HelperResult::NotFound)) })
        .await
        .map_err(|error| observation.transport_error(Stage::RetirementDrain, error))
        .unwrap();
    assert_eq!(observation.failure(), None);
    assert_eq!(owner.0.pending.lock().unwrap().len(), 0);
    assert_eq!(owner.0.slots.available_permits(), MAX_FLOWS);
}

#[tokio::test]
async fn flow_acquire_cancelled_drain_has_no_returned_failure_or_retirement_claim() {
    use std::task::Poll;

    let owner = Retirements::new();
    let _peer = queue_one(&owner);
    let mut observation = Observation::default();
    let mut work = Box::pin(async {
        owner
            .drain_with(|_, _, _| std::future::pending::<Result<(), HelperClientError>>())
            .await
            .map_err(|error| observation.transport_error(Stage::RetirementDrain, error))
    });
    std::future::poll_fn(|context| {
        assert!(work.as_mut().poll(context).is_pending());
        Poll::Ready(())
    })
    .await;
    drop(work);
    assert_eq!(observation.failure(), None);
    assert_eq!(owner.0.pending.lock().unwrap().len(), 1);
    assert_eq!(owner.0.slots.available_permits(), MAX_FLOWS - 1);
    owner.drain_with(|_, _, _| async { Ok(()) }).await.unwrap();
    assert_eq!(owner.0.slots.available_permits(), MAX_FLOWS);
}
