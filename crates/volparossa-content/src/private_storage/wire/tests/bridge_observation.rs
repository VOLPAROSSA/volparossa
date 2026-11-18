use super::*;
use crate::private_storage::wire::bridge_observation::{Deadline, Observer, Phase};

#[derive(Default)]
pub(super) struct Trace(pub(super) Mutex<(Vec<Phase>, Vec<Deadline>)>);

impl Observer for Trace {
    fn phase(&self, phase: Phase) {
        self.0.lock().unwrap().0.push(phase);
    }
    fn deadline(&self, deadline: Deadline) {
        self.0.lock().unwrap().1.push(deadline);
    }
}

#[tokio::test]
async fn observed_bridge_retains_original_provider_receipt_and_local_error_boundary() {
    let fixture = Fixture::new();
    let (mut remote, server, challenge) = fixture.session().await;
    let (mut owner, mut agent) = tokio::io::duplex(4096);
    let request = fixture.request(
        &challenge,
        target(b"opaque"),
        StorageOperation::Reserve {
            expires_at: unix_now().unwrap() + 60,
        },
    );
    let trace = Trace::default();
    let (owner_result, bridge_result) = tokio::join!(
        finish(&mut owner, &fixture.grant, &challenge, &request, &[]),
        bridge_admitted_observed(
            &mut agent,
            &mut remote,
            &fixture.grant,
            &challenge,
            |_| async { true },
            &trace,
        ),
    );
    assert_eq!(
        owner_result.unwrap().receipt.encode(),
        bridge_result.unwrap().receipt.encode()
    );
    assert_eq!(
        trace.0.lock().unwrap().0.last(),
        Some(&Phase::LocalReceiptWrite)
    );
    assert!(trace.0.lock().unwrap().1.is_empty());
    drop(remote);
    server.await.unwrap().unwrap();
    assert_eq!(fixture.usage().leases, 1);
}

#[tokio::test]
async fn observed_bridge_does_not_forward_invalid_owner_request_or_busy_admission() {
    for busy in [false, true] {
        let fixture = Fixture::new();
        let (mut remote, server, challenge) = fixture.session().await;
        let (mut owner, mut agent) = tokio::io::duplex(4096);
        let trace = Trace::default();
        let encoded = if busy {
            fixture
                .request(
                    &challenge,
                    target(b"opaque"),
                    StorageOperation::Reserve {
                        expires_at: unix_now().unwrap() + 60,
                    },
                )
                .encode()
        } else {
            vec![255]
        };
        write_frame(&mut owner, &encoded).await.unwrap();
        let result = bridge_admitted_observed(
            &mut agent,
            &mut remote,
            &fixture.grant,
            &challenge,
            |_| async { false },
            &trace,
        )
        .await;
        assert!(result.is_err());
        assert_eq!(
            trace.0.lock().unwrap().0.last(),
            Some(&if busy {
                Phase::Admission
            } else {
                Phase::LocalRequestVerify
            })
        );
        assert_eq!(fixture.usage().leases, 0);
        drop(remote);
        assert!(server.await.unwrap().is_err());
    }
}

#[tokio::test(start_paused = true)]
async fn original_bridge_deadline_preserves_pending_local_request_read() {
    let fixture = Fixture::new();
    let now = unix_now().unwrap();
    let challenge = StorageChallenge::issue(
        &fixture.signer,
        &fixture.grant,
        Validity {
            created: now,
            expires: now + 120,
        },
    )
    .unwrap();
    let (_owner, mut local) = tokio::io::duplex(4096);
    let (_provider, mut remote) = tokio::io::duplex(4096);
    let trace = Trace::default();
    let result = bridge_admitted_observed(
        &mut local,
        &mut remote,
        &fixture.grant,
        &challenge,
        |_| async { true },
        &trace,
    )
    .await;
    assert!(matches!(result, Err(WireError::Timeout)));
    let trace = trace.0.lock().unwrap();
    assert_eq!(trace.0, [Phase::LocalRequestRead]);
    assert_eq!(trace.1, [Deadline::Bridge]);
    assert_eq!(fixture.usage().leases, 0);
}

#[tokio::test(start_paused = true)]
async fn original_remote_wire_deadline_keeps_pending_receipt_phase_without_custody_claim() {
    let fixture = Fixture::new();
    let now = unix_now().unwrap();
    let challenge = StorageChallenge::issue(
        &fixture.signer,
        &fixture.grant,
        Validity {
            created: now,
            expires: now + 120,
        },
    )
    .unwrap();
    let signed = fixture.request(
        &challenge,
        target(b"opaque"),
        StorageOperation::Reserve {
            expires_at: now + 60,
        },
    );
    let (_provider, mut remote) = tokio::io::duplex(4096);
    let trace = Trace::default();
    let result = finish_observed(
        &mut remote,
        &fixture.grant,
        &challenge,
        &signed,
        &[],
        &trace,
    )
    .await;
    assert!(matches!(result, Err(WireError::Timeout)));
    let trace = trace.0.lock().unwrap();
    assert_eq!(trace.0.last(), Some(&Phase::RemoteReceiptRead));
    assert_eq!(trace.1, [Deadline::RemoteWire]);
}
