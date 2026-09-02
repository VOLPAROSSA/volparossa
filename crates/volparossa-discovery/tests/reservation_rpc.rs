//! In-memory privacy-v4 discovery transport regressions.

use std::time::Duration;

use libp2p::{Multiaddr, identity, request_response, swarm::SwarmEvent};
use tokio::time;
use volparossa_discovery::{
    BehaviourEvent, DatapathRelayOperation, DatapathRelayRequest, DiscoveryError, DiscoveryEvent,
    DiscoveryProtocolRoles, DiscoveryService, ExitForwardOperation, ExitForwardRequest,
    ExitForwardResponse, ForwardStatus, PeerLink,
};
use volparossa_protocol::{
    ControlMessageType, MAX_CONTROL_MESSAGE_SIZE, PROTOCOL_VERSION, SignedEnvelope,
    encode_canonical, node_id_from_public_key,
};

const DEADLINE_MS: u64 = 1_700_000_012_000;
const TEST_TIMEOUT: Duration = Duration::from_secs(10);

async fn next_other(service: &mut DiscoveryService) -> SwarmEvent<BehaviourEvent> {
    loop {
        if let DiscoveryEvent::Other(event) = service.next_event().await {
            return event;
        }
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "single end-to-end three-hop exchange"
)]
async fn exit_requests_cross_exactly_one_control_relay_without_direct_exit_fallback() {
    let client_key = identity::Keypair::generate_ed25519();
    let relay_key = identity::Keypair::generate_ed25519();
    let exit_key = identity::Keypair::generate_ed25519();
    let client_peer = client_key.public().to_peer_id();
    let relay_peer = relay_key.public().to_peer_id();
    let exit_peer = exit_key.public().to_peer_id();
    let relay_public = raw_public_key(&relay_key);
    let relay_node = node_id_from_public_key(&relay_public);

    let mut client = DiscoveryService::new_with_protocol_roles(
        client_key,
        DiscoveryProtocolRoles::new(true, false, false),
    )
    .expect("client discovery");
    let mut relay = DiscoveryService::new_with_protocol_roles(
        relay_key,
        DiscoveryProtocolRoles::new(false, true, false),
    )
    .expect("relay discovery");
    let mut exit = DiscoveryService::new_with_protocol_roles(
        exit_key,
        DiscoveryProtocolRoles::new(false, false, true),
    )
    .expect("exit discovery");

    connect(&mut client, &mut relay).await;
    connect(&mut relay, &mut exit).await;

    let request = ExitForwardRequest::new(
        vec![1; 16],
        relay_node.to_vec(),
        relay_peer.to_bytes(),
        relay_public.to_vec(),
        exit_peer.to_bytes(),
        Vec::new(),
        DEADLINE_MS,
        ExitForwardOperation::FetchExitAdvertisement,
        Vec::new(),
    )
    .expect("canonical forwarding request");

    assert!(matches!(
        client.request_exit_forward(&exit_peer, request.clone()),
        Err(DiscoveryError::ProtocolPeer)
    ));

    let downstream_request_id = client
        .request_exit_forward(&relay_peer, request.clone())
        .expect("client-to-control-relay request");
    let signed_advertisement = signed_envelope(ControlMessageType::NodeAdvertisement);
    let mut downstream_channel = None;
    let mut upstream_request_id = None;

    let response = time::timeout(TEST_TIMEOUT, async {
        loop {
            tokio::select! {
                event = next_other(&mut client) => {
                    match event {
                        SwarmEvent::Behaviour(BehaviourEvent::ExitForward(
                            request_response::Event::Message {
                                peer,
                                message: request_response::Message::Response {
                                    request_id,
                                    response,
                                },
                                ..
                            },
                        )) if request_id == downstream_request_id => {
                            assert_eq!(peer, relay_peer);
                            break response;
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::ExitForward(
                            request_response::Event::OutboundFailure {
                                request_id,
                                error,
                                ..
                            },
                        )) if request_id == downstream_request_id => {
                            panic!("client forwarding failed: {error}");
                        }
                        _ => {}
                    }
                }
                event = next_other(&mut relay) => {
                    match event {
                        SwarmEvent::Behaviour(BehaviourEvent::ExitForward(
                            request_response::Event::Message {
                                peer,
                                message: request_response::Message::Request {
                                    request: received,
                                    channel,
                                    ..
                                },
                                ..
                            },
                        )) => {
                            assert_eq!(peer, client_peer);
                            assert_eq!(received, request);
                            downstream_channel = Some(channel);
                            upstream_request_id = Some(
                                relay
                                    .request_exit_forward_upstream(
                                        &exit_peer,
                                        received.into(),
                                    )
                                    .expect("control-relay-to-exit request"),
                            );
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::ExitForwardUpstream(
                            request_response::Event::Message {
                                peer,
                                message: request_response::Message::Response {
                                    request_id,
                                    response,
                                },
                                ..
                            },
                        )) if Some(request_id) == upstream_request_id => {
                            assert_eq!(peer, exit_peer);
                            relay
                                .send_exit_forward_response(
                                    downstream_channel.take().expect("downstream channel"),
                                    response.into_forward_response(),
                                )
                                .expect("control-relay response");
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::ExitForwardUpstream(
                            request_response::Event::OutboundFailure {
                                request_id,
                                error,
                                ..
                            },
                        )) if Some(request_id) == upstream_request_id => {
                            panic!("upstream forwarding failed: {error}");
                        }
                        _ => {}
                    }
                }
                event = next_other(&mut exit) => {
                    if let SwarmEvent::Behaviour(BehaviourEvent::ExitForwardUpstream(
                        request_response::Event::Message {
                            peer,
                            message: request_response::Message::Request {
                                request: received,
                                channel,
                                ..
                            },
                            ..
                        },
                    )) = event
                    {
                        assert_eq!(peer, relay_peer);
                        assert_eq!(received.as_forward_request(), &request);
                        let canonical = received.as_forward_request();
                        let response = ExitForwardResponse::granted(
                            canonical.forward_id().to_vec(),
                            ExitForwardOperation::FetchExitAdvertisement,
                            vec![9; 32],
                            exit_peer.to_bytes(),
                            vec![signed_advertisement.clone()],
                        )
                        .expect("exit response");
                        exit
                            .send_exit_forward_upstream_response(channel, response.into())
                            .expect("exit-to-control-relay response");
                    }
                }
            }
        }
    })
    .await
    .expect("forwarding timeout");

    response.validate().expect("canonical client response");
    assert_eq!(
        response.validated_status().expect("status"),
        ForwardStatus::Granted
    );
    assert_eq!(
        response.validated_operation().expect("operation"),
        ExitForwardOperation::FetchExitAdvertisement
    );
    assert_eq!(response.signed_responses(), &[signed_advertisement]);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one exact connection-bound Relay-to-Exit Permit transport exchange"
)]
async fn native_permit_response_dials_kademlia_address_and_consumes_exact_connection() {
    let relay_key = identity::Keypair::generate_ed25519();
    let exit_key = identity::Keypair::generate_ed25519();
    let relay_peer = relay_key.public().to_peer_id();
    let exit_peer = exit_key.public().to_peer_id();
    let relay_public = raw_public_key(&relay_key);
    let relay_node = node_id_from_public_key(&relay_public);

    let mut relay = DiscoveryService::new_with_protocol_roles(
        relay_key,
        DiscoveryProtocolRoles::new(false, true, false),
    )
    .expect("relay discovery");
    let mut exit = DiscoveryService::new_with_protocol_roles(
        exit_key,
        DiscoveryProtocolRoles::new(false, false, true),
    )
    .expect("exit discovery");
    exit.listen_on("/memory/0".parse::<Multiaddr>().expect("memory address"))
        .expect("memory listener");
    let exit_address = time::timeout(TEST_TIMEOUT, async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = next_other(&mut exit).await {
                break address;
            }
        }
    })
    .await
    .expect("memory listener timeout");
    relay
        .add_known_peer(exit_peer, &exit_address)
        .expect("permit-bound Exit Kademlia address");

    let signed_request = signed_envelope(ControlMessageType::NativeProbePermitRequest);
    let request = ExitForwardRequest::new(
        vec![21; 16],
        relay_node.to_vec(),
        relay_peer.to_bytes(),
        relay_public.to_vec(),
        exit_peer.to_bytes(),
        vec![22; 32],
        DEADLINE_MS,
        ExitForwardOperation::NativeProbePermit,
        signed_request.clone(),
    )
    .expect("canonical native Permit forwarding request");
    let outbound = relay
        .request_exit_forward_upstream(&exit_peer, request.clone().into())
        .expect("control-Relay-to-Exit native Permit request");
    let signed_permit = signed_envelope(ControlMessageType::NativeProbePermit);

    let response = time::timeout(TEST_TIMEOUT, async {
        loop {
            tokio::select! {
                event = next_other(&mut relay) => {
                    match event {
                        SwarmEvent::Behaviour(BehaviourEvent::ExitForwardUpstream(
                            request_response::Event::Message {
                                peer,
                                message: request_response::Message::Response {
                                    request_id,
                                    response,
                                },
                                ..
                            },
                        )) if request_id == outbound => {
                            assert_eq!(peer, exit_peer);
                            break response;
                        }
                        SwarmEvent::Behaviour(BehaviourEvent::ExitForwardUpstream(
                            request_response::Event::OutboundFailure {
                                request_id,
                                error,
                                ..
                            },
                        )) if request_id == outbound => {
                            panic!("native Permit forwarding failed: {error}");
                        }
                        _ => {}
                    }
                }
                event = next_other(&mut exit) => {
                    if let SwarmEvent::Behaviour(BehaviourEvent::ExitForwardUpstream(
                        request_response::Event::Message {
                            peer,
                            connection_id,
                            message: request_response::Message::Request {
                                request: received,
                                channel,
                                ..
                            },
                        },
                    )) = event
                    {
                        assert_eq!(peer, relay_peer);
                        assert_eq!(received.as_forward_request(), &request);
                        let connection = exit
                            .bind_native_probe_control_connection(peer, connection_id)
                            .expect("exact inbound control connection");
                        let canonical = received.as_forward_request();
                        let response = ExitForwardResponse::granted(
                            canonical.forward_id().to_vec(),
                            ExitForwardOperation::NativeProbePermit,
                            canonical.exit_node_id().to_vec(),
                            exit_peer.to_bytes(),
                            vec![signed_permit.clone()],
                        )
                        .expect("native Permit response");
                        exit
                            .send_native_probe_permit_response(
                                connection,
                                peer,
                                channel,
                                response.into(),
                            )
                            .expect("connection-bound native Permit response");
                    }
                }
            }
        }
    })
    .await
    .expect("native Permit response timeout");

    response
        .validate()
        .expect("canonical native Permit response");
    assert_eq!(
        response
            .as_forward_response()
            .validated_operation()
            .expect("operation"),
        ExitForwardOperation::NativeProbePermit
    );
    assert_eq!(
        response.as_forward_response().signed_responses(),
        &[signed_permit]
    );
}

#[tokio::test]
async fn execute_probe_reaches_the_local_relay_handler() {
    let client_key = identity::Keypair::generate_ed25519();
    let relay_key = identity::Keypair::generate_ed25519();
    let relay_peer = relay_key.public().to_peer_id();
    let relay_node = node_id_from_public_key(&raw_public_key(&relay_key));

    let mut client = DiscoveryService::new_with_protocol_roles(
        client_key,
        DiscoveryProtocolRoles::new(true, false, false),
    )
    .expect("client discovery");
    let mut relay = DiscoveryService::new_with_protocol_roles(
        relay_key,
        DiscoveryProtocolRoles::new(false, true, false),
    )
    .expect("relay discovery");
    connect(&mut client, &mut relay).await;

    let request = DatapathRelayRequest::new(
        vec![6; 16],
        relay_node.to_vec(),
        relay_peer.to_bytes(),
        DEADLINE_MS,
        DatapathRelayOperation::ExecuteProbe,
        signed_envelope(ControlMessageType::RelayProbePermitRequest),
        signed_envelope(ControlMessageType::RelayProbePermit),
    )
    .expect("canonical probe frame");
    let expected = request.clone();
    let client_peer = *client.local_peer_id();
    let outbound = client
        .request_datapath_relay(&relay_peer, request)
        .expect("probe request");

    let (authenticated_client, received) = time::timeout(TEST_TIMEOUT, async {
        loop {
            tokio::select! {
                event = next_other(&mut client) => {
                    if let SwarmEvent::Behaviour(BehaviourEvent::DatapathRelay(
                        request_response::Event::OutboundFailure {
                            request_id,
                            error,
                            ..
                        },
                    )) = event
                    {
                        if request_id == outbound {
                            panic!("probe transport failed: {error}");
                        }
                    }
                }
                event = next_other(&mut relay) => {
                    if let SwarmEvent::Behaviour(BehaviourEvent::DatapathRelay(
                        request_response::Event::Message {
                            peer,
                            message: request_response::Message::Request { request, .. },
                            ..
                        },
                    )) = event
                    {
                        break (peer, request);
                    }
                }
            }
        }
    })
    .await
    .expect("probe delivery timeout");

    assert_eq!(authenticated_client, client_peer);
    assert_eq!(received, expected);
    received.validate().expect("canonical probe request");
    assert_eq!(
        received.validated_operation().expect("operation"),
        DatapathRelayOperation::ExecuteProbe
    );
}

async fn connect(dialer: &mut DiscoveryService, listener: &mut DiscoveryService) {
    listener
        .listen_on("/memory/0".parse::<Multiaddr>().expect("memory address"))
        .expect("memory listener");
    let address = time::timeout(TEST_TIMEOUT, async {
        loop {
            if let SwarmEvent::NewListenAddr { address, .. } = next_other(listener).await {
                break address;
            }
        }
    })
    .await
    .expect("memory listener timeout");

    let listener_peer = *listener.local_peer_id();
    let dialer_peer = *dialer.local_peer_id();
    dialer
        .dial_peerlink(&PeerLink::new(listener_peer, address).expect("memory peerlink"))
        .expect("memory dial");

    time::timeout(TEST_TIMEOUT, async {
        let mut dialer_connected = false;
        let mut listener_connected = false;
        while !dialer_connected || !listener_connected {
            tokio::select! {
                event = next_other(dialer) => {
                    if matches!(
                        event,
                        SwarmEvent::ConnectionEstablished { peer_id, .. }
                            if peer_id == listener_peer
                    ) {
                        dialer_connected = true;
                    }
                }
                event = next_other(listener) => {
                    if matches!(
                        event,
                        SwarmEvent::ConnectionEstablished { peer_id, .. }
                            if peer_id == dialer_peer
                    ) {
                        listener_connected = true;
                    }
                }
            }
        }
    })
    .await
    .expect("memory connection timeout");
}

fn raw_public_key(keypair: &identity::Keypair) -> [u8; 32] {
    keypair
        .clone()
        .try_into_ed25519()
        .expect("Ed25519 identity")
        .public()
        .to_bytes()
}

fn signed_envelope(message_type: ControlMessageType) -> Vec<u8> {
    encode_canonical(
        &SignedEnvelope {
            protocol_version: PROTOCOL_VERSION,
            sender_id: vec![10; 32],
            sender_public_key: vec![11; 32],
            timestamp_ms: 1,
            expires_at_ms: 2,
            nonce: vec![12; 32],
            message_type: message_type as i32,
            payload: Vec::new(),
            payload_hash: vec![13; 32],
            signature: vec![14; 64],
        },
        MAX_CONTROL_MESSAGE_SIZE,
    )
    .expect("canonical signed envelope")
}
