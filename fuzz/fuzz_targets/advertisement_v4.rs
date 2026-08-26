#![no_main]

//! Active advertisement-v4 canonical codec target.

mod support;

use libfuzzer_sys::fuzz_target;
use prost::Message;
use volparossa_discovery::{
    ADVERTISEMENT_RPC_VERSION, AdvertisementRequest, AdvertisementResponse,
    MAX_ADVERTISEMENT_REQUEST_FRAME_BYTES, MAX_ADVERTISEMENT_RESPONSE_FRAME_BYTES,
};
use volparossa_protocol::{
    ControlMessageType, MAX_CONTROL_MESSAGE_SIZE, PROTOCOL_VERSION, SignedEnvelope,
    encode_canonical,
};

#[derive(Clone, PartialEq, Message)]
struct RawAdvertisementRequest {
    #[prost(uint32, tag = "1")]
    protocol_version: u32,
}

fn request_limit() -> usize {
    usize::try_from(MAX_ADVERTISEMENT_REQUEST_FRAME_BYTES).expect("request limit fits usize")
}

fn response_limit() -> usize {
    usize::try_from(MAX_ADVERTISEMENT_RESPONSE_FRAME_BYTES).expect("response limit fits usize")
}

fn exercise_request(data: &[u8]) {
    support::exercise_message::<AdvertisementRequest, _>(data, request_limit(), |request| {
        let _ = request.validate();
    });
}

fn structural_advertisement_envelope() -> Vec<u8> {
    encode_canonical(
        &SignedEnvelope {
            protocol_version: PROTOCOL_VERSION,
            message_type: ControlMessageType::NodeAdvertisement as i32,
            ..SignedEnvelope::default()
        },
        MAX_CONTROL_MESSAGE_SIZE,
    )
    .expect("fixed structural advertisement envelope is bounded")
}

fuzz_target!(|data: &[u8]| {
    exercise_request(data);
    support::exercise_message::<AdvertisementResponse, _>(data, response_limit(), |response| {
        let _ = response.validate();
    });

    for protocol_version in [0, 1, 2, 3, 5, u32::MAX] {
        exercise_request(&RawAdvertisementRequest { protocol_version }.encode_to_vec());
    }

    let request = AdvertisementRequest::new();
    assert_eq!(request.protocol_version(), ADVERTISEMENT_RPC_VERSION);
    let encoded = request.encode_to_vec();
    exercise_request(&encoded);
    assert!(
        volparossa_protocol::decode_canonical::<AdvertisementRequest>(&encoded, request_limit())
            .expect("canonical v4 request")
            .validate()
            .is_ok()
    );

    let response = AdvertisementResponse::new(structural_advertisement_envelope())
        .expect("structural advertisement response");
    support::exercise_message::<AdvertisementResponse, _>(
        &response.encode_to_vec(),
        response_limit(),
        |decoded| assert!(decoded.validate().is_ok()),
    );
});
