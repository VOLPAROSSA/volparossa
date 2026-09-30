//! Framing checks only; actors independently verify signatures and retained ownership.

use volparossa_protocol::{
    ControlMessageType, ControlPayload, MAX_ROUTE_RETIRE_BYTES, PROTOCOL_VERSION, ProtocolError,
    RetirementReceipt, SignedEnvelope, decode_canonical, route_retire_request_hash,
};

impl crate::DiscoveryService {
    pub(super) fn restore_retirement_exit_addresses(&mut self, peer: libp2p::PeerId) {
        // Kademlia removes individual addresses after transient transport failure. Our bounded
        // admission registry deliberately keeps their provenance, but duplicate admissions do
        // not reinsert them. A warm Relay whose QUIC connection died must be able to retry the
        // exact previously known Exit listener after connectivity recovers. This is only reached
        // for destruction, after the wrapper's exact Relay/Exit identity checks; it imports no
        // new address, selects no replacement Exit and grants no forwarding authority.
        let Some(addresses) = self.address_admissions.by_peer.get(&peer) else {
            return;
        };
        for admitted in addresses {
            if admitted.sources & crate::AddressSource::Known.mask() == 0
                || !crate::private_address_is_local(&admitted.address)
                || !crate::prepare_discovery_address(
                    self.swarm.local_peer_id(),
                    peer,
                    &admitted.address,
                )
                .is_ok_and(|canonical| canonical == admitted.address)
            {
                continue;
            }
            let _ = self
                .swarm
                .behaviour_mut()
                .kademlia
                .add_address(&peer, admitted.address.clone());
        }
    }
}

pub(super) fn validate_request(encoded: &[u8], deadline_ms: u64) -> Result<(), ProtocolError> {
    route_retire_request_hash(encoded)?;
    let envelope: SignedEnvelope = decode_canonical(encoded, MAX_ROUTE_RETIRE_BYTES)?;
    if deadline_ms <= envelope.timestamp_ms || deadline_ms > envelope.expires_at_ms {
        return Err(ProtocolError::InvalidField("retirement deadline"));
    }
    Ok(())
}

pub(super) fn validate_receipt(
    encoded: &[u8],
    node_id: &[u8],
    allow_nested: bool,
) -> Result<(), ProtocolError> {
    let envelope: SignedEnvelope = decode_canonical(encoded, MAX_ROUTE_RETIRE_BYTES)?;
    if envelope.protocol_version != PROTOCOL_VERSION
        || envelope.message_type != ControlMessageType::RetirementReceipt as i32
    {
        return Err(ProtocolError::InvalidField("retirement receipt type"));
    }
    let receipt: RetirementReceipt = decode_canonical(&envelope.payload, MAX_ROUTE_RETIRE_BYTES)?;
    receipt.validate()?;
    receipt.validate_envelope(&envelope)?;
    if receipt.provider_node_id != node_id
        || (!allow_nested && !receipt.signed_exit_receipt.is_empty())
    {
        return Err(ProtocolError::InvalidField("retirement receipt owner"));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use futures::io::Cursor;
    use libp2p::{StreamProtocol, identity, request_response::Codec as _};
    use volparossa_protocol::{
        RouteRetire, TimePolicy, node_id_from_public_key, sign_control_message_with,
    };

    use super::*;
    use crate::{
        DatapathRelayOperation, DatapathRelayRequest, DatapathRelayResponse, ExitForwardOperation,
        ExitForwardRequest, ExitForwardResponse,
        forwarding::{
            EXIT_FORWARD_PROTOCOL, EXIT_FORWARD_UPSTREAM_PROTOCOL, ExitForwardCodec,
            UpstreamExitForwardCodec,
        },
        reservations::{DATAPATH_RELAY_PROTOCOL, DatapathRelayCodec},
    };

    const NOW: u64 = 10_000;
    const DEADLINE: u64 = 20_000;

    #[tokio::test]
    async fn retirement_restores_only_retained_known_addresses_after_transport_loss() {
        use libp2p::{
            core::transport::TransportError,
            swarm::{ConnectionId, DialError, FromSwarm, NetworkBehaviour, behaviour::DialFailure},
        };

        let local = identity::Keypair::generate_ed25519();
        let peer = identity::Keypair::generate_ed25519().public().to_peer_id();
        let mut service = crate::DiscoveryService::new(local).unwrap();
        let known = format!("/ip4/46.162.3.1/udp/41000/quic-v1/p2p/{peer}")
            .parse::<libp2p::Multiaddr>()
            .unwrap();
        let identify = format!("/ip4/46.162.3.1/udp/41001/quic-v1/p2p/{peer}")
            .parse::<libp2p::Multiaddr>()
            .unwrap();
        let residual = format!("/ip4/46.162.3.1/udp/41002/quic-v1/p2p/{peer}")
            .parse::<libp2p::Multiaddr>()
            .unwrap();
        service.add_known_peer(peer, &known).unwrap();
        for address in [&identify, &residual] {
            service
                .add_prepared_kademlia_address(
                    peer,
                    address.clone(),
                    crate::AddressSource::Identify,
                )
                .unwrap();
        }
        let failure = DialError::Transport(
            [&known, &identify]
                .into_iter()
                .map(|address| {
                    (
                        address.clone(),
                        TransportError::Other(std::io::Error::from(std::io::ErrorKind::TimedOut)),
                    )
                })
                .collect(),
        );
        service
            .swarm
            .behaviour_mut()
            .kademlia
            .on_swarm_event(FromSwarm::DialFailure(DialFailure {
                peer_id: Some(peer),
                error: &failure,
                connection_id: ConnectionId::new_unchecked(1),
            }));
        fn contains(service: &mut crate::DiscoveryService, address: &libp2p::Multiaddr) -> bool {
            service
                .swarm
                .behaviour_mut()
                .kademlia
                .kbuckets()
                .any(|bucket| {
                    bucket
                        .iter()
                        .any(|entry| entry.node.value.iter().any(|value| value == address))
                })
        }
        assert!(!contains(&mut service, &known));
        assert!(!contains(&mut service, &identify));
        assert!(contains(&mut service, &residual));
        assert_eq!(service.address_admissions.by_peer[&peer].len(), 3);
        service.restore_retirement_exit_addresses(peer);
        assert!(contains(&mut service, &known));
        assert!(
            !contains(&mut service, &identify),
            "no discovery-only address resurrection"
        );
        assert!(contains(&mut service, &residual));
        service.restore_retirement_exit_addresses(peer);
        assert_eq!(service.address_admissions.by_peer[&peer].len(), 3);

        // An unsupported/private-DHT client purge is different from transport failure: removed
        // address authority must never be resurrected by destruction retries.
        service.address_admissions.forget_peer(&peer);
        service.swarm.behaviour_mut().kademlia.remove_peer(&peer);
        service.restore_retirement_exit_addresses(peer);
        assert!(!contains(&mut service, &known));
        assert!(!service.address_admissions.contains_peer(&peer));
    }

    fn sign<T: ControlPayload>(value: &T, key: &identity::Keypair) -> Vec<u8> {
        sign_control_message_with(
            value,
            key.public().try_into_ed25519().unwrap().to_bytes(),
            NOW,
            DEADLINE,
            [4; 32],
            TimePolicy::default(),
            |bytes| {
                key.sign(bytes)
                    .ok()
                    .and_then(|signature| signature.try_into().ok())
            },
        )
        .unwrap()
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one complete two-hop request and independently signed response transcript"
    )]
    async fn route_retire_real_codecs_keep_original_request_and_reject_client_exit_hop() {
        let client = identity::Keypair::generate_ed25519();
        let relay = identity::Keypair::generate_ed25519();
        let exit = identity::Keypair::generate_ed25519();
        let client_key = client.public().try_into_ed25519().unwrap().to_bytes();
        let relay_key = relay.public().try_into_ed25519().unwrap().to_bytes();
        let exit_key = exit.public().try_into_ed25519().unwrap().to_bytes();
        let relay_node = node_id_from_public_key(&relay_key).to_vec();
        let exit_node = node_id_from_public_key(&exit_key).to_vec();
        let request = RouteRetire {
            route_context_id: vec![1; 16],
            reservation_id: vec![2; 16],
            policy_hash: vec![3; 32],
            client_session_id: node_id_from_public_key(&client_key).to_vec(),
            client_session_public_key: client_key.to_vec(),
        };
        let signed_request = sign(&request, &client);
        let client_request = DatapathRelayRequest::new(
            vec![1; 16],
            relay_node.clone(),
            relay.public().to_peer_id().to_bytes(),
            DEADLINE,
            DatapathRelayOperation::RouteRetire,
            signed_request.clone(),
            Vec::new(),
        )
        .unwrap();
        let mut data = DatapathRelayCodec;
        let protocol = StreamProtocol::new(DATAPATH_RELAY_PROTOCOL);
        let mut wire = Cursor::new(Vec::new());
        data.write_request(&protocol, &mut wire, client_request.clone())
            .await
            .unwrap();
        assert_eq!(
            data.read_request(&protocol, &mut Cursor::new(wire.into_inner()))
                .await
                .unwrap(),
            client_request
        );
        let upstream_request = ExitForwardRequest::new(
            vec![2; 16],
            relay_node.clone(),
            relay.public().to_peer_id().to_bytes(),
            relay_key.to_vec(),
            exit.public().to_peer_id().to_bytes(),
            exit_node.clone(),
            DEADLINE,
            ExitForwardOperation::RouteRetire,
            signed_request.clone(),
        )
        .unwrap();
        let mut upstream = UpstreamExitForwardCodec;
        let upstream_protocol = StreamProtocol::new(EXIT_FORWARD_UPSTREAM_PROTOCOL);
        let mut wire = Cursor::new(Vec::new());
        upstream
            .write_request(
                &upstream_protocol,
                &mut wire,
                upstream_request.clone().into(),
            )
            .await
            .unwrap();
        let bytes = wire.into_inner();
        assert_eq!(
            upstream
                .read_request(&upstream_protocol, &mut Cursor::new(bytes.clone()))
                .await
                .unwrap()
                .as_forward_request()
                .canonical_request(),
            signed_request
        );
        let mut forbidden = ExitForwardCodec;
        let forbidden_protocol = StreamProtocol::new(EXIT_FORWARD_PROTOCOL);
        assert!(
            forbidden
                .read_request(&forbidden_protocol, &mut Cursor::new(bytes))
                .await
                .is_err()
        );
        assert!(
            forbidden
                .write_request(
                    &forbidden_protocol,
                    &mut Cursor::new(Vec::new()),
                    upstream_request
                )
                .await
                .is_err()
        );

        let exit_receipt = RetirementReceipt {
            route_context_id: request.route_context_id,
            reservation_id: request.reservation_id,
            request_hash: route_retire_request_hash(&signed_request).unwrap().to_vec(),
            provider_node_id: exit_node.clone(),
            confirmed_destroyed: true,
            signed_exit_receipt: Vec::new(),
        };
        let signed_exit = sign(&exit_receipt, &exit);
        let response = ExitForwardResponse::granted(
            vec![2; 16],
            ExitForwardOperation::RouteRetire,
            exit_node,
            exit.public().to_peer_id().to_bytes(),
            vec![signed_exit.clone()],
        )
        .unwrap();
        let mut wire = Cursor::new(Vec::new());
        upstream
            .write_response(&upstream_protocol, &mut wire, response.clone().into())
            .await
            .unwrap();
        let encoded_response = wire.into_inner();
        assert_eq!(
            upstream
                .read_response(
                    &upstream_protocol,
                    &mut Cursor::new(encoded_response.clone())
                )
                .await
                .unwrap()
                .as_forward_response(),
            &response
        );
        assert!(
            forbidden
                .read_response(&forbidden_protocol, &mut Cursor::new(encoded_response))
                .await
                .is_err()
        );
        assert!(
            forbidden
                .write_response(&forbidden_protocol, &mut Cursor::new(Vec::new()), response)
                .await
                .is_err()
        );
        let relay_receipt = RetirementReceipt {
            provider_node_id: relay_node.clone(),
            signed_exit_receipt: signed_exit,
            ..exit_receipt
        };
        let response = DatapathRelayResponse::granted(
            vec![1; 16],
            DatapathRelayOperation::RouteRetire,
            relay_node,
            relay.public().to_peer_id().to_bytes(),
            sign(&relay_receipt, &relay),
        )
        .unwrap();
        let mut wire = Cursor::new(Vec::new());
        data.write_response(&protocol, &mut wire, response.clone())
            .await
            .unwrap();
        assert_eq!(
            data.read_response(&protocol, &mut Cursor::new(wire.into_inner()))
                .await
                .unwrap(),
            response
        );

        assert!(validate_request(&signed_request, DEADLINE + 1).is_err());
        assert!(validate_request(&signed_request, NOW).is_err());
        assert!(validate_request(&vec![0; MAX_ROUTE_RETIRE_BYTES + 1], DEADLINE).is_err());
        assert!(
            validate_receipt(
                &sign(&relay_receipt, &relay),
                &relay_receipt.provider_node_id,
                false
            )
            .is_err()
        );
        assert!(validate_receipt(&sign(&relay_receipt, &relay), &[7; 32], true).is_err());
    }
}
