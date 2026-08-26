#![no_main]

//! Active datapath-relay-v4 canonical codec target.

mod support;

use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use prost::Message;
use volparossa_discovery::{
    DATAPATH_RELAY_RPC_VERSION, DatapathRelayOperation, DatapathRelayRequest,
    DatapathRelayResponse, ForwardStatus, MAX_DATAPATH_RELAY_FRAME_BYTES,
};
use volparossa_protocol::{
    ControlMessageType, MAX_CONTROL_MESSAGE_SIZE, PROTOCOL_VERSION, SignedEnvelope,
    encode_canonical,
};

#[derive(Clone, PartialEq, Message)]
struct RawDatapathRelayRequest {
    #[prost(uint32, tag = "1")]
    rpc_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    request_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    relay_peer_id: Vec<u8>,
    #[prost(uint64, tag = "5")]
    deadline_unix_ms: u64,
    #[prost(enumeration = "DatapathRelayOperation", tag = "6")]
    operation: i32,
    #[prost(bytes = "vec", tag = "7")]
    client_signed_request: Vec<u8>,
    #[prost(bytes = "vec", tag = "8")]
    exit_signed_authorization: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct RawDatapathRelayResponse {
    #[prost(uint32, tag = "1")]
    rpc_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    request_id: Vec<u8>,
    #[prost(enumeration = "DatapathRelayOperation", tag = "3")]
    operation: i32,
    #[prost(enumeration = "ForwardStatus", tag = "4")]
    status: i32,
    #[prost(bytes = "vec", tag = "5")]
    relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    signed_response: Vec<u8>,
}

fn frame_limit() -> usize {
    usize::try_from(MAX_DATAPATH_RELAY_FRAME_BYTES).expect("datapath limit fits usize")
}

fn exercise_request(data: &[u8]) {
    support::exercise_message::<DatapathRelayRequest, _>(data, frame_limit(), |request| {
        let validation = request.validate();
        if validation.is_ok() {
            let confused =
                volparossa_protocol::decode_canonical::<DatapathRelayResponse>(data, frame_limit());
            assert!(
                confused.is_err() || confused.is_ok_and(|response| response.validate().is_err())
            );
        }
    });
}

fn exercise_response(data: &[u8]) {
    support::exercise_message::<DatapathRelayResponse, _>(data, frame_limit(), |response| {
        let validation = response.validate();
        if validation.is_ok() {
            let confused =
                volparossa_protocol::decode_canonical::<DatapathRelayRequest>(data, frame_limit());
            assert!(confused.is_err() || confused.is_ok_and(|request| request.validate().is_err()));
        }
    });
}

fn peer_id(seed: u8) -> Vec<u8> {
    let public = SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes();
    let mut peer_id = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    peer_id.extend_from_slice(&public);
    peer_id
}

fn envelope(message_type: ControlMessageType) -> Vec<u8> {
    encode_canonical(
        &SignedEnvelope {
            protocol_version: PROTOCOL_VERSION,
            message_type: message_type as i32,
            ..SignedEnvelope::default()
        },
        MAX_CONTROL_MESSAGE_SIZE,
    )
    .expect("fixed structural signed envelope is bounded")
}

fn reserve_request() -> DatapathRelayRequest {
    DatapathRelayRequest::new(
        vec![1; 16],
        vec![2; 32],
        peer_id(9),
        1_750_000_005_000,
        DatapathRelayOperation::ReservePath,
        envelope(ControlMessageType::RelayReservationRequest),
        Vec::new(),
    )
    .expect("fixed reserve-path request is valid")
}

fn assert_invalid_request(raw: &RawDatapathRelayRequest) {
    let decoded = volparossa_protocol::decode_canonical::<DatapathRelayRequest>(
        &raw.encode_to_vec(),
        frame_limit(),
    )
    .expect("raw request mirror has exact wire tags");
    assert!(decoded.validate().is_err());
}

fn assert_invalid_response(raw: &RawDatapathRelayResponse) {
    let decoded = volparossa_protocol::decode_canonical::<DatapathRelayResponse>(
        &raw.encode_to_vec(),
        frame_limit(),
    )
    .expect("raw response mirror has exact wire tags");
    assert!(decoded.validate().is_err());
}

fuzz_target!(|data: &[u8]| {
    exercise_request(data);
    exercise_response(data);

    let reserve = reserve_request();
    let reserve_bytes = reserve.encode_to_vec();
    exercise_request(&reserve_bytes);
    let mut raw_request =
        RawDatapathRelayRequest::decode(reserve_bytes.as_slice()).expect("request mirror parity");
    for version in [0, 1, 2, 3, 5, u32::MAX] {
        raw_request.rpc_version = version;
        assert_invalid_request(&raw_request);
    }
    raw_request.rpc_version = DATAPATH_RELAY_RPC_VERSION;
    for operation in [0, -1, i32::MAX] {
        raw_request.operation = operation;
        assert_invalid_request(&raw_request);
    }

    let relay_peer_id = peer_id(9);
    let unavailable = DatapathRelayResponse::unavailable(
        vec![3; 16],
        DatapathRelayOperation::ExecuteProbe,
        vec![2; 32],
        relay_peer_id.clone(),
    )
    .expect("received Unavailable is a valid final fail-closed response frame");
    assert_eq!(
        unavailable.validated_status().expect("valid status"),
        ForwardStatus::Unavailable,
    );
    exercise_response(&unavailable.encode_to_vec());

    let mut raw_response = RawDatapathRelayResponse::decode(unavailable.encode_to_vec().as_slice())
        .expect("response mirror parity");
    for version in [0, 1, 2, 3, 5, u32::MAX] {
        raw_response.rpc_version = version;
        assert_invalid_response(&raw_response);
    }
    raw_response.rpc_version = DATAPATH_RELAY_RPC_VERSION;
    for operation in [0, -1, i32::MAX] {
        raw_response.operation = operation;
        assert_invalid_response(&raw_response);
    }
    raw_response.operation = DatapathRelayOperation::ExecuteProbe as i32;
    for status in [0, -1, i32::MAX] {
        raw_response.status = status;
        assert_invalid_response(&raw_response);
    }

    let granted_reservation = DatapathRelayResponse::granted(
        vec![4; 16],
        DatapathRelayOperation::ReservePath,
        vec![2; 32],
        relay_peer_id,
        envelope(ControlMessageType::RelayReservation),
    )
    .expect("structural reserve-path grant");
    exercise_response(&granted_reservation.encode_to_vec());
});
