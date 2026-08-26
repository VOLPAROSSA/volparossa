#![no_main]

//! Active two-hop forwarding-v4 canonical codec target.

mod support;

use ed25519_dalek::SigningKey;
use libfuzzer_sys::fuzz_target;
use prost::Message;
use volparossa_discovery::{
    ExitForwardOperation, ExitForwardRequest, ExitForwardResponse, FORWARDING_RPC_VERSION,
    ForwardStatus, MAX_FORWARDING_FRAME_BYTES, UpstreamExitForwardRequest,
    UpstreamExitForwardResponse,
};
use volparossa_protocol::{
    ControlMessageType, MAX_CONTROL_MESSAGE_SIZE, PROTOCOL_VERSION, SignedEnvelope,
    encode_canonical, node_id_from_public_key,
};

#[derive(Clone, PartialEq, Message)]
struct RawExitForwardRequest {
    #[prost(uint32, tag = "1")]
    rpc_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    forward_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    control_relay_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    control_relay_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "5")]
    control_relay_public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    exit_peer_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "7")]
    exit_node_id: Vec<u8>,
    #[prost(uint64, tag = "8")]
    deadline_unix_ms: u64,
    #[prost(enumeration = "ExitForwardOperation", tag = "9")]
    operation: i32,
    #[prost(bytes = "vec", tag = "10")]
    canonical_request: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct RawExitForwardResponse {
    #[prost(uint32, tag = "1")]
    rpc_version: u32,
    #[prost(bytes = "vec", tag = "2")]
    forward_id: Vec<u8>,
    #[prost(enumeration = "ExitForwardOperation", tag = "3")]
    operation: i32,
    #[prost(enumeration = "ForwardStatus", tag = "4")]
    status: i32,
    #[prost(bytes = "vec", tag = "5")]
    exit_node_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "6")]
    exit_peer_id: Vec<u8>,
    #[prost(bytes = "vec", repeated, tag = "7")]
    signed_responses: Vec<Vec<u8>>,
}

fn frame_limit() -> usize {
    usize::try_from(MAX_FORWARDING_FRAME_BYTES).expect("forwarding limit fits usize")
}

fn exercise_request(data: &[u8]) {
    support::exercise_message::<ExitForwardRequest, _>(data, frame_limit(), |request| {
        let validation = request.validate();
        let canonical = encode_canonical(request, frame_limit()).expect("bounded request");
        let upstream = UpstreamExitForwardRequest::from(request.clone());
        let upstream_wire = encode_canonical(upstream.as_forward_request(), frame_limit())
            .expect("bounded upstream request");
        assert_eq!(upstream_wire, canonical);
        let reparsed = volparossa_protocol::decode_canonical::<ExitForwardRequest>(
            &upstream_wire,
            frame_limit(),
        )
        .expect("wire-identical request reparses");
        assert_eq!(reparsed, request.clone());
        assert_eq!(
            ExitForwardRequest::from(upstream),
            request.clone(),
            "hop marker conversion must preserve every field",
        );

        if validation.is_ok() {
            let confused = volparossa_protocol::decode_canonical::<ExitForwardResponse>(
                &canonical,
                frame_limit(),
            );
            assert!(
                confused.is_err() || confused.is_ok_and(|response| response.validate().is_err())
            );
        }
    });
}

fn exercise_response(data: &[u8]) {
    support::exercise_message::<ExitForwardResponse, _>(data, frame_limit(), |response| {
        let validation = response.validate();
        let canonical = encode_canonical(response, frame_limit()).expect("bounded response");
        let upstream = UpstreamExitForwardResponse::from(response.clone());
        let upstream_wire = encode_canonical(upstream.as_forward_response(), frame_limit())
            .expect("bounded upstream response");
        assert_eq!(upstream_wire, canonical);
        let reparsed = volparossa_protocol::decode_canonical::<ExitForwardResponse>(
            &upstream_wire,
            frame_limit(),
        )
        .expect("wire-identical response reparses");
        assert_eq!(reparsed, response.clone());
        assert_eq!(
            ExitForwardResponse::from(upstream),
            response.clone(),
            "hop marker conversion must preserve every field",
        );

        if validation.is_ok() {
            let confused = volparossa_protocol::decode_canonical::<ExitForwardRequest>(
                &canonical,
                frame_limit(),
            );
            assert!(confused.is_err() || confused.is_ok_and(|request| request.validate().is_err()));
        }
    });
}

fn identity(seed: u8) -> (Vec<u8>, Vec<u8>, Vec<u8>) {
    let public = SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes();
    let mut peer_id = vec![0x00, 0x24, 0x08, 0x01, 0x12, 0x20];
    peer_id.extend_from_slice(&public);
    (
        node_id_from_public_key(&public).to_vec(),
        peer_id,
        public.to_vec(),
    )
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

fn fetch_request() -> ExitForwardRequest {
    let (relay_node_id, relay_peer_id, relay_public_key) = identity(7);
    let (_, exit_peer_id, _) = identity(8);
    ExitForwardRequest::new(
        vec![1; 16],
        relay_node_id,
        relay_peer_id,
        relay_public_key,
        exit_peer_id,
        Vec::new(),
        1_750_000_005_000,
        ExitForwardOperation::FetchExitAdvertisement,
        Vec::new(),
    )
    .expect("fixed fetch request is valid")
}

fn assert_invalid_request(raw: &RawExitForwardRequest) {
    let decoded = volparossa_protocol::decode_canonical::<ExitForwardRequest>(
        &raw.encode_to_vec(),
        frame_limit(),
    )
    .expect("raw request mirror has exact wire tags");
    assert!(decoded.validate().is_err());
}

fn assert_invalid_response(raw: &RawExitForwardResponse) {
    let decoded = volparossa_protocol::decode_canonical::<ExitForwardResponse>(
        &raw.encode_to_vec(),
        frame_limit(),
    )
    .expect("raw response mirror has exact wire tags");
    assert!(decoded.validate().is_err());
}

fuzz_target!(|data: &[u8]| {
    exercise_request(data);
    exercise_response(data);
    // Tag 7 is repeated bytes: another occurrence changes message semantics
    // instead of creating an alternate encoding of the same response.
    exercise_response(&[0x3a, 0x00]);

    let fetch = fetch_request();
    let fetch_bytes = fetch.encode_to_vec();
    exercise_request(&fetch_bytes);
    let mut raw_request =
        RawExitForwardRequest::decode(fetch_bytes.as_slice()).expect("request mirror parity");
    for version in [0, 1, 2, 3, 5, u32::MAX] {
        raw_request.rpc_version = version;
        assert_invalid_request(&raw_request);
    }
    raw_request.rpc_version = FORWARDING_RPC_VERSION;
    for operation in [0, -1, i32::MAX] {
        raw_request.operation = operation;
        assert_invalid_request(&raw_request);
    }

    let (_, exit_peer_id, _) = identity(8);
    let unavailable = ExitForwardResponse::unavailable(
        vec![1; 16],
        ExitForwardOperation::FetchExitAdvertisement,
        vec![9; 32],
        exit_peer_id.clone(),
    )
    .expect("received Unavailable is a valid final fail-closed response frame");
    assert_eq!(
        unavailable.validated_status().expect("valid status"),
        ForwardStatus::Unavailable,
    );
    exercise_response(&unavailable.encode_to_vec());

    let mut raw_response = RawExitForwardResponse::decode(unavailable.encode_to_vec().as_slice())
        .expect("response mirror parity");
    for version in [0, 1, 2, 3, 5, u32::MAX] {
        raw_response.rpc_version = version;
        assert_invalid_response(&raw_response);
    }
    raw_response.rpc_version = FORWARDING_RPC_VERSION;
    for operation in [0, -1, i32::MAX] {
        raw_response.operation = operation;
        assert_invalid_response(&raw_response);
    }
    raw_response.operation = ExitForwardOperation::FetchExitAdvertisement as i32;
    for status in [0, -1, i32::MAX] {
        raw_response.status = status;
        assert_invalid_response(&raw_response);
    }

    let hold = ExitForwardResponse::granted(
        vec![2; 16],
        ExitForwardOperation::CapacityHold,
        vec![9; 32],
        exit_peer_id,
        vec![
            envelope(ControlMessageType::ClientSessionCapability),
            envelope(ControlMessageType::ExitCapacityHold),
        ],
    )
    .expect("ordered hold response");
    let mut reordered =
        RawExitForwardResponse::decode(hold.encode_to_vec().as_slice()).expect("response mirror");
    reordered.signed_responses.reverse();
    assert_invalid_response(&reordered);
    reordered
        .signed_responses
        .push(envelope(ControlMessageType::ExitCapacityHold));
    assert_invalid_response(&reordered);
});
