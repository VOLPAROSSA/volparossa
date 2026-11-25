//! Local framed peer for testing original-bound Poll and Cancel receipts.

use tokio::net::UnixListener;
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ComputeReady, ControlResponse, ControlResult, Empty,
    control_request::Operation, control_response::Payload,
};

use super::{JobHandle, rpc};

pub(super) async fn serve_one(
    listener: &UnixListener,
    handle: &JobHandle,
    cancel: bool,
    reply: Option<(rpc::Outcome, bool)>,
) {
    let (mut stream, _) = listener.accept().await.unwrap();
    let control = volparossa_local_control::read_request(&mut stream)
        .await
        .unwrap();
    let Some(Operation::ComputeRemote(remote)) = control.operation else {
        panic!("not a compute handoff");
    };
    assert_eq!(
        remote.provider_key,
        hex::decode(&handle.provider_key).unwrap()
    );
    assert!(!remote.retain_transcript);
    let mut response = ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: control.request_id.clone(),
        result: ControlResult::Ok as i32,
        diagnostic_code: "COMPUTE_RPC_READY".into(),
        private_storage_remote_detail: None,
        payload: Some(Payload::ComputeReady(ComputeReady {
            provider_key: remote.provider_key,
            requester_key: vec![23; 32],
        })),
    };
    volparossa_local_control::write_response(&mut stream, &response)
        .await
        .unwrap();
    let request = rpc::read_request(&mut stream).await.unwrap();
    request.validate(super::now().unwrap()).unwrap();
    assert_eq!(
        request.operation,
        if cancel {
            rpc::Operation::Cancel(handle.binding.clone())
        } else {
            rpc::Operation::Poll(handle.binding.clone())
        }
    );
    let Some((outcome, correct_final)) = reply else {
        // A real transport close after READY and the exact Poll, before its reply.
        return;
    };
    rpc::write_response(
        &mut stream,
        &rpc::Response {
            version: rpc::VERSION,
            request_id: request.request_id,
            outcome,
        },
    )
    .await
    .unwrap();
    response.diagnostic_code = "COMPUTE_RPC_OK".into();
    response.payload = Some(Payload::Ack(Empty {}));
    if !correct_final {
        response.request_id[0] ^= 1;
    }
    volparossa_local_control::write_response(&mut stream, &response)
        .await
        .unwrap();
}
