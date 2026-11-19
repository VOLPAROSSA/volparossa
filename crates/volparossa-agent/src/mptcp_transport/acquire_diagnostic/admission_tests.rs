use std::{cell::Cell, os::unix::net::UnixStream as StdUnixStream, task::Poll};

use nix::unistd::geteuid;
use tokio::{
    io::{AsyncWriteExt as _, Interest},
    net::{UnixListener, UnixStream},
};
use volparossa_routing::{
    Empty, HELPER_PROTOCOL_VERSION, HelperRequest, HelperResponse, HelperResult, RetireMptcpFlow,
    TransportSocketKind, WireguardRole, encode_response, helper_request::Operation,
    helper_response::Outcome, operation_digest, read_request, request_descriptor_fd_binding,
};

use super::unadopted_transport;
use crate::{
    helper::{HelperClient, HelperClientError},
    mptcp_transport::{
        ExitMptcpListenerSignal, MptcpTransportError,
        acquire_diagnostic::{Observation, Reason, Stage},
        retirement::{Guard, Retirements},
    },
};

const EXPIRES: u64 = 20;

fn prior_guard(owner: &Retirements, handle: u8) -> Guard {
    let (socket, _peer) = StdUnixStream::pair().unwrap();
    owner.reserve().unwrap().bind(
        RetireMptcpFlow {
            route_context_id: vec![1; 16],
            context_handle: vec![2; 32],
            mptcp_flow_handle: vec![handle; 32],
        },
        socket.into(),
    )
}

fn assert_all_slots_available(owner: &Retirements) {
    let slots: Vec<_> = (0..64).map(|_| owner.reserve().unwrap()).collect();
    assert!(owner.reserve().is_err());
    drop(slots);
}

async fn respond(stream: &mut UnixStream, request: &HelperRequest, result: HelperResult) {
    let response = HelperResponse {
        protocol_version: HELPER_PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        operation_digest: operation_digest(request).unwrap().to_vec(),
        result: result as i32,
        diagnostic_code: "TEST_RESPONSE".into(),
        outcome: (result == HelperResult::Ok).then_some(Outcome::Empty(Empty {})),
    };
    stream
        .write_all(&encode_response(&response).unwrap())
        .await
        .unwrap();
}

async fn retire_prior_flows(
    listener: &UnixListener,
    clock: &Cell<u64>,
    after: u64,
    checked: &Cell<bool>,
) {
    for handle in [3, 4] {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        let Some(Operation::RetireMptcpFlow(retirement)) = &request.operation else {
            panic!("expected prior retirement");
        };
        assert_eq!(retirement.route_context_id, [1; 16]);
        assert_eq!(retirement.context_handle, [2; 32]);
        assert_eq!(retirement.mptcp_flow_handle, [handle; 32]);
        let binding = request_descriptor_fd_binding(&request).unwrap();
        let _descriptor = stream
            .async_io(Interest::READABLE, || {
                volparossa_linux_uapi::receive_fd_with_binding(&stream, &binding)
            })
            .await
            .unwrap();
        assert!(!checked.get(), "admission sampled before retirement ACK");
        if handle == 4 {
            clock.set(after);
        }
        respond(&mut stream, &request, HelperResult::Ok).await;
    }
}

async fn reject_one_acquire(mut stream: UnixStream) {
    let request = read_request(&mut stream).await.unwrap();
    let Some(Operation::AcquireTransportSocket(acquire)) = &request.operation else {
        panic!("expected fresh transport acquisition");
    };
    assert_eq!(acquire.route_context_id, [1; 16]);
    assert_eq!(acquire.context_handle, [2; 32]);
    assert_eq!(acquire.path_id, 1);
    assert_eq!(acquire.role, WireguardRole::Client as i32);
    assert_eq!(
        acquire.descriptor_kind,
        TransportSocketKind::MptcpConnected as i32
    );
    assert_eq!(acquire.expected_local.as_ref().unwrap().port, 50_000);
    assert_eq!(acquire.expected_remote.as_ref().unwrap().port, 44_443);
    respond(&mut stream, &request, HelperResult::Capacity).await;
}

async fn check_after_retirement(after: u64) {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("helper.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let helper =
        HelperClient::new_for_test(socket, directory.path().join("unused"), geteuid().as_raw());
    let mut transport = unadopted_transport();
    transport.signal =
        Some(ExitMptcpListenerSignal::new([1; 16], 44_443, [1, 2], vec![1]).unwrap());
    // One flow is queued already. The unused initial capability joins the second drain.
    drop(prior_guard(&transport.retirements, 3));
    transport.initial_retirement = Some(prior_guard(&transport.retirements, 4));
    let clock = Cell::new(EXPIRES - 2);
    let checked = Cell::new(false);
    let mut observation = Observation::default();
    let retirements = transport.retirements.clone();

    let (result, requested) = {
        let acquire = transport.acquire_flow(&helper, 50_000, &mut observation, || {
            checked.set(true);
            assert_all_slots_available(&retirements);
            clock.get() < EXPIRES
        });
        tokio::pin!(acquire);
        tokio::select! {
            _ = &mut acquire => panic!("acquisition finished before the retirement ACKs"),
            () = retire_prior_flows(&listener, &clock, after, &checked) => {}
        }
        tokio::select! {
            result = &mut acquire => (result, false),
            accepted = listener.accept() => {
                let (stream, _) = accepted.unwrap();
                let (result, ()) = tokio::join!(acquire, reject_one_acquire(stream));
                (result, true)
            }
        }
    };
    assert!(checked.get());
    assert_eq!(requested, after < EXPIRES);
    if requested {
        assert!(matches!(
            result,
            Err(MptcpTransportError::Helper(HelperClientError::Rejected(
                HelperResult::Capacity
            )))
        ));
        let failure = observation.failure().unwrap();
        assert_eq!(
            (failure.stage, failure.reason),
            (Stage::HelperAcquire, Reason::HelperCapacity)
        );
    } else {
        assert!(matches!(result, Ok(None)));
        assert_eq!(observation.failure(), None);
    }
    // A completed admission leaves no queued helper request and every original slot is reusable.
    std::future::poll_fn(|cx| {
        assert!(listener.poll_accept(cx).is_pending());
        Poll::Ready(())
    })
    .await;
    assert_all_slots_available(&retirements);
}

#[tokio::test]
async fn expiry_at_retirement_ack_prevents_fresh_helper_acquisition() {
    check_after_retirement(EXPIRES).await;
}

#[tokio::test]
async fn live_route_after_retirement_ack_issues_normal_fresh_acquisition() {
    check_after_retirement(EXPIRES - 1).await;
}
