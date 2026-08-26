//! Direct-advertisement transport and resource-bound regressions.

use futures::io::Cursor;
use libp2p::{PeerId, StreamProtocol, identity, request_response::Codec as _};
use volparossa_protocol::{
    ControlMessageType, MAX_CONTROL_MESSAGE_SIZE, NodeAdvertisement, PROTOCOL_VERSION,
    SignedEnvelope, encode_canonical,
};

use crate::{
    ADVERTISEMENT_PROTOCOL, ADVERTISEMENT_RPC_VERSION, AdvertisementRequest, AdvertisementResponse,
    DiscoveryError, DiscoveryService, LEGACY_ADVERTISEMENT_PROTOCOL_V1,
    LEGACY_ADVERTISEMENT_PROTOCOL_V2, MAX_ADVERTISEMENT_BYTES,
    MAX_ADVERTISEMENT_REQUEST_FRAME_BYTES, MAX_ADVERTISEMENT_RESPONSE_FRAME_BYTES,
    advertisement_budget::{
        MAX_OUTSTANDING_ADVERTISEMENT_REQUESTS, MAX_OUTSTANDING_PROVIDER_QUERIES,
    },
    advertisements::advertisement_codec,
    capability,
};

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "complete adversarial codec matrix")]
async fn codec_is_canonical_v4_refuses_other_versions_and_enforces_exact_bounds() {
    let protocol = StreamProtocol::new(ADVERTISEMENT_PROTOCOL);
    let request_bound = usize::try_from(MAX_ADVERTISEMENT_REQUEST_FRAME_BYTES)
        .expect("request frame bound fits usize");
    let response_bound = usize::try_from(MAX_ADVERTISEMENT_RESPONSE_FRAME_BYTES)
        .expect("response frame bound fits usize");
    let mut codec = advertisement_codec();

    let mut oversized_request = Cursor::new(vec![0xff; request_bound + 1]);
    assert!(
        codec
            .read_request(&protocol, &mut oversized_request)
            .await
            .is_err()
    );
    assert_eq!(
        oversized_request.position(),
        MAX_ADVERTISEMENT_REQUEST_FRAME_BYTES + 1
    );

    let mut encoded_request = Cursor::new(Vec::new());
    codec
        .write_request(&protocol, &mut encoded_request, AdvertisementRequest::new())
        .await
        .expect("encode bounded request");
    assert_eq!(encoded_request.get_ref(), &[0x08, 0x04]);
    assert!(encoded_request.get_ref().len() <= request_bound);
    let mut encoded_request = Cursor::new(encoded_request.into_inner());
    assert_eq!(
        codec
            .read_request(&protocol, &mut encoded_request)
            .await
            .expect("decode bounded request")
            .protocol_version(),
        ADVERTISEMENT_RPC_VERSION
    );

    for raw in [
        vec![0x08, 0x01],
        vec![0x08, 0x02],
        vec![0x08, 0x03],
        vec![0x08, 0x84, 0x00],
        vec![0x08, 0x04, 0x10, 0x01],
        vec![0x08, 0x04, 0x08, 0x04],
    ] {
        assert!(
            codec
                .read_request(&protocol, &mut Cursor::new(raw))
                .await
                .is_err()
        );
    }
    for unsupported in [
        LEGACY_ADVERTISEMENT_PROTOCOL_V1,
        LEGACY_ADVERTISEMENT_PROTOCOL_V2,
        "/volparossa/advertisement/3",
    ] {
        assert!(
            codec
                .write_request(
                    &StreamProtocol::new(unsupported),
                    &mut Cursor::new(Vec::new()),
                    AdvertisementRequest::new(),
                )
                .await
                .is_err()
        );
    }

    let mut oversized_response = Cursor::new(vec![0xff; response_bound + 1]);
    assert!(
        codec
            .read_response(&protocol, &mut oversized_response)
            .await
            .is_err()
    );
    assert_eq!(
        oversized_response.position(),
        MAX_ADVERTISEMENT_RESPONSE_FRAME_BYTES + 1
    );

    let expected_envelope = canonical_advertisement_envelope();
    assert!(expected_envelope.len() <= MAX_ADVERTISEMENT_BYTES);
    let mut encoded_response = Cursor::new(Vec::new());
    codec
        .write_response(
            &protocol,
            &mut encoded_response,
            AdvertisementResponse::new(expected_envelope.clone()).expect("canonical response"),
        )
        .await
        .expect("encode bounded response");
    assert!(encoded_response.get_ref().len() <= response_bound);
    let raw_response = encoded_response.into_inner();
    let decoded = codec
        .read_response(&protocol, &mut Cursor::new(raw_response.clone()))
        .await
        .expect("decode bounded response");
    assert_eq!(decoded.signed_envelope(), expected_envelope);

    let mut unknown_response = raw_response;
    unknown_response.extend_from_slice(&[0x10, 0x01]);
    assert!(
        codec
            .read_response(&protocol, &mut Cursor::new(unknown_response))
            .await
            .is_err()
    );

    // A canonical protobuf response carrying an empty envelope is semantically invalid.
    assert!(
        codec
            .read_response(&protocol, &mut Cursor::new(vec![0x0a, 0x00]))
            .await
            .is_err()
    );
}

#[tokio::test]
async fn provider_queries_and_advertisement_requests_are_deduplicated_and_bounded() {
    let mut service =
        DiscoveryService::new(identity::Keypair::generate_ed25519()).expect("discovery service");

    let first_query = service
        .find_providers(capability::RELAY)
        .expect("first provider query");
    assert_eq!(
        service
            .find_providers(capability::RELAY)
            .expect("deduplicated provider query"),
        first_query
    );
    for index in 1..MAX_OUTSTANDING_PROVIDER_QUERIES {
        service
            .find_providers(&format!("/volparossa/v1/provider/budget-{index}"))
            .expect("provider query within budget");
    }
    assert!(matches!(
        service.find_providers("/volparossa/v1/provider/over-budget"),
        Err(DiscoveryError::ResourceLimit)
    ));
    service
        .advertisement_budgets
        .finish_provider_query(first_query);
    service
        .find_providers("/volparossa/v1/provider/reclaimed-query")
        .expect("provider slot reclaimed by exact completion");

    let first_peer = PeerId::random();
    let first_request = service
        .request_relay_advertisement(&first_peer)
        .expect("first advertisement request");
    assert_eq!(
        service
            .request_relay_advertisement(&first_peer)
            .expect("deduplicated advertisement request"),
        first_request
    );
    for _ in 1..MAX_OUTSTANDING_ADVERTISEMENT_REQUESTS {
        service
            .request_relay_advertisement(&PeerId::random())
            .expect("advertisement request within budget");
    }
    assert!(matches!(
        service.request_relay_advertisement(&PeerId::random()),
        Err(DiscoveryError::ResourceLimit)
    ));
    service
        .advertisement_budgets
        .finish_outbound_request(&first_peer, first_request);
    service
        .request_relay_advertisement(&PeerId::random())
        .expect("request slot reclaimed by exact completion");
}

fn canonical_advertisement_envelope() -> Vec<u8> {
    let payload =
        encode_canonical(&NodeAdvertisement::default(), MAX_CONTROL_MESSAGE_SIZE).expect("payload");
    encode_canonical(
        &SignedEnvelope {
            protocol_version: PROTOCOL_VERSION,
            sender_id: vec![1; 32],
            sender_public_key: vec![2; 32],
            timestamp_ms: 1,
            expires_at_ms: 2,
            nonce: vec![3; 32],
            message_type: ControlMessageType::NodeAdvertisement as i32,
            payload,
            payload_hash: vec![4; 32],
            signature: vec![5; 64],
        },
        MAX_CONTROL_MESSAGE_SIZE,
    )
    .expect("envelope")
}
