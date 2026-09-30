use super::*;
use crate::{helper::HelperClient, helper::RuntimeBoundPreparedLeaseBatch};
use libp2p::swarm::SwarmEvent;
use std::sync::Arc;
use tokio::{io::AsyncWriteExt, net::UnixListener, sync::RwLock};
use volparossa_discovery::{BehaviourEvent, DiscoveryEvent};
use volparossa_identity::Identity;
use volparossa_routing::{
    ContextRole, DestroyedContext, HELPER_PROTOCOL_VERSION, HelperRequest, HelperResponse,
    HelperResult, HelperRuntime, PrepareLeaseBatch, PreparedLeaseBatch, encode_response,
    helper_request, helper_response, operation_digest, read_request,
};

fn retirement(session: &Identity) -> RouteRetire {
    let key = session.ed25519_public_key_bytes().expect("session key");
    RouteRetire {
        route_context_id: vec![17; 16],
        reservation_id: vec![18; 16],
        policy_hash: vec![19; 32],
        client_session_id: node_id_from_public_key(&key).to_vec(),
        client_session_public_key: key.to_vec(),
    }
}

fn signed_retirement(session: &Identity, request: &RouteRetire) -> Vec<u8> {
    let now = unix_millis();
    sign_control_message_with(
        request,
        session.ed25519_public_key_bytes().expect("session key"),
        now,
        now + 15_000,
        generate_nonce(),
        TimePolicy::default(),
        |bytes| session.sign(bytes).ok(),
    )
    .expect("signed retirement")
}

async fn pump(
    runtime: &mut DiscoveryRuntime,
    state: &Arc<RwLock<crate::state::AgentState>>,
    event: DiscoveryEvent,
) {
    // Exercise the real dedicated actor ingress/response seams without unrelated advertisements.
    match event {
        DiscoveryEvent::Other(SwarmEvent::Behaviour(BehaviourEvent::DatapathRelay(event))) => {
            Box::pin(runtime.handle_datapath_event(event, state)).await;
        }
        DiscoveryEvent::Other(SwarmEvent::Behaviour(BehaviourEvent::ExitForwardUpstream(
            event,
        ))) => {
            Box::pin(runtime.handle_exit_forward_upstream_event(event, state)).await;
        }
        _ => {}
    }
}

async fn exchange(
    client: &mut DiscoveryRuntime,
    relay: &mut DiscoveryRuntime,
    exit: &mut DiscoveryRuntime,
    state: &Arc<RwLock<crate::state::AgentState>>,
    signed: Vec<u8>,
) -> Result<(), OutboundReservationError> {
    let (reply, mut response) = oneshot::channel();
    client.begin_route_retire(RetireCommand {
        relay: *relay.service.local_peer_id(),
        exit: *exit.service.local_peer_id(),
        signed,
        reply,
    });
    tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            tokio::select! {
                result = &mut response => return result.expect("client reply"),
                event = client.service.next_event() => pump(client, state, event).await,
                event = relay.service.next_event() => pump(relay, state, event).await,
                event = exit.service.next_event() => pump(exit, state, event).await,
            }
        }
    })
    .await
    .expect("bounded real two-hop retirement exchange")
}

#[test]
fn retirement_dial_diagnostics_are_closed_classes_not_remote_error_text() {
    use libp2p::{core::transport::TransportError, swarm::DialError};
    let address = "/memory/19331".parse().unwrap();
    assert_eq!(
        retirement_dial_failure_code(&DialError::NoAddresses),
        "ROUTE_RETIRE_DIAL_NO_ADDRESSES"
    );
    let mut failure = DialError::Transport(vec![(
        address,
        TransportError::Other(std::io::Error::from(std::io::ErrorKind::TimedOut)),
    )]);
    assert_eq!(
        retirement_dial_failure_code(&failure),
        "ROUTE_RETIRE_DIAL_TIMEOUT"
    );
    if let DialError::Transport(errors) = &mut failure {
        errors.push((
            "/memory/19332".parse().unwrap(),
            TransportError::Other(std::io::Error::other("private remote transport detail")),
        ));
    }
    assert_eq!(
        retirement_dial_failure_code(&failure),
        "ROUTE_RETIRE_DIAL_TRANSPORT_MIXED"
    );
    assert_eq!(
        retirement_dial_failure_code(&DialError::Transport(vec![(
            "/memory/19332".parse().unwrap(),
            TransportError::Other(std::io::Error::other("private remote transport detail")),
        )])),
        "ROUTE_RETIRE_DIAL_TRANSPORT_OTHER"
    );
}

#[tokio::test]
async fn scoped_retirement_crosses_real_relay_and_exit_and_rejects_wrong_scope() {
    let (mut client, state, _client_dir) = super::super::tests::retirement_runtime_fixture();
    let (mut relay, _, _relay_dir) = super::super::tests::retirement_runtime_fixture();
    let (mut exit, _, _exit_dir) = super::super::tests::retirement_runtime_fixture();
    super::super::tests::connect_runtime_client_to_control(&mut client, &mut relay.service).await;
    super::super::tests::connect_runtime_client_to_control(&mut relay, &mut exit.service).await;
    let session = Identity::generate();
    let request = retirement(&session);
    let context = fixed_bytes(&request.route_context_id).expect("context");
    // These retained scopes model an authenticated, now expired original Finalize. No helper
    // owner was created, so only this known scope may produce an idempotent absent-owner receipt.
    let original = RelayScope {
        request: request.clone(),
        client_peer: *client.service.local_peer_id(),
        exit_peer: *exit.service.local_peer_id(),
        exit_node: exit.local_node_id,
        expires_at_ms: unix_millis() - 60_000,
        retiring: false,
        complete: false,
    };
    assert!(relay.insert_relay_retirement(context, original.clone()));
    exit.route_retire.exit.insert(
        context,
        ExitScope {
            request: request.clone(),
            relays: BTreeSet::from([*relay.service.local_peer_id()]),
            extensions: BTreeMap::new(),
            expires_at_ms: original.expires_at_ms,
            retiring: false,
            complete: false,
        },
    );
    relay.roles = volparossa_config::RolesConfig {
        client: false,
        relay: false,
        exit: false,
    };
    exit.roles = relay.roles;
    let mut wrong = request.clone();
    wrong.policy_hash[0] ^= 1;
    assert!(
        Box::pin(exchange(
            &mut client,
            &mut relay,
            &mut exit,
            &state,
            signed_retirement(&session, &wrong)
        ))
        .await
        .is_err()
    );
    assert!(!relay.route_retire.relay[&context].retiring);
    assert!(!exit.route_retire.exit[&context].retiring);
    Box::pin(exchange(
        &mut client,
        &mut relay,
        &mut exit,
        &state,
        signed_retirement(&session, &request),
    ))
    .await
    .expect("real nested Exit and Relay receipts");
    assert!(relay.route_retire.relay[&context].complete);
    assert!(exit.route_retire.exit[&context].complete);
    relay.maintain_route_retirement(unix_millis() + 600_000);
    exit.maintain_route_retirement(unix_millis() + 600_000);
    assert!(
        !relay.insert_relay_retirement(context, original),
        "no late Prepare revival"
    );
    Box::pin(exchange(
        &mut client,
        &mut relay,
        &mut exit,
        &state,
        signed_retirement(&session, &request),
    ))
    .await
    .expect("fresh retry after original expiry");
    let other_session = Identity::generate();
    assert!(
        Box::pin(exchange(
            &mut client,
            &mut relay,
            &mut exit,
            &state,
            signed_retirement(&other_session, &retirement(&other_session))
        ))
        .await
        .is_err()
    );
}

fn extension_retirement_fixture(
    exit: &DiscoveryRuntime,
    relay: &DiscoveryRuntime,
    session: &Identity,
) -> (RouteExtensionScope, RouteExtension) {
    let route = volparossa_test_support::SignedRouteFixture::new_with_path_ids(
        &[1, 2, 3],
        4,
        4,
        &[volparossa_protocol::Transport::TcpMptcp],
        unix_millis(),
    )
    .unwrap();
    let request = retirement(session);
    let mut parent = decoded_signed_payload::<ExitReservation>(route.exit_reservation()).unwrap();
    parent.route_context_id = request.route_context_id;
    parent.reservation_id = request.reservation_id;
    parent.policy_hash = request.policy_hash;
    parent.client_session_id = request.client_session_id;
    parent.client_session_public_key = request.client_session_public_key;
    parent.exit_node_id = exit.local_node_id.to_vec();
    parent.exit_peer_id = exit.service.local_peer_id().to_bytes();
    let signed_parent = sign_control_message_with(
        &parent,
        exit.local_public_key,
        parent.created_at_ms,
        parent.expires_at_ms,
        parent.nonce.as_slice().try_into().unwrap(),
        TimePolicy::default(),
        |bytes| exit.identity.sign(bytes).ok(),
    )
    .unwrap();
    let scope = RouteExtensionScope {
        extension_id: generate_nonce()[..16].to_vec(),
        signed_exit_reservation: signed_parent,
        finalized_bundle_hash: route.finalized_bundle_hash().to_vec(),
        path_id: 4,
        relay_node_id: relay.local_node_id.to_vec(),
        relay_peer_id: relay.service.local_peer_id().to_bytes(),
        probe_id: generate_nonce()[..16].to_vec(),
        address_family: volparossa_protocol::ProbeAddressFamily::Ipv4 as i32,
    };
    // Model the Exit service's accepted Authorize result. This test exercises retained
    // destruction authority and actual relay transport, not native probe acceptance.
    let accepted = RouteExtension {
        scope: Some(scope.clone()),
        phase: RouteExtensionPhase::Authorize as i32,
        signed_probe_permit: vec![1],
        signed_relay_authorization: vec![1],
        signed_confirmation_receipt: Vec::new(),
        selected_path_ids: vec![1, 2, 3],
        hard_expires_at_ms: parent.expires_at_ms,
    };
    (scope, accepted)
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "one real two-hop retirement transition retains scope failures, late membership and idempotent receipts"
)]
async fn extension_relay_retirement_requires_exact_retained_authority_and_survives_cleanup() {
    let (mut client, state, _client_dir) = super::super::tests::retirement_runtime_fixture();
    let (mut relay, _, _relay_dir) = super::super::tests::retirement_runtime_fixture();
    let (mut exit, _, _exit_dir) = super::super::tests::retirement_runtime_fixture();
    super::super::tests::connect_runtime_client_to_control(&mut client, &mut relay.service).await;
    super::super::tests::connect_runtime_client_to_control(&mut relay, &mut exit.service).await;
    let session = Identity::generate();
    let request = retirement(&session);
    let context = fixed_bytes(&request.route_context_id).unwrap();
    let (extension, accepted) = extension_retirement_fixture(&exit, &relay, &session);
    let parent = extension.parent().unwrap();
    let original_relays =
        BTreeSet::from([Libp2pPeerId::from_bytes(&parent.control_relay_peer_id).unwrap()]);
    assert!(relay.insert_relay_retirement(
        context,
        RelayScope {
            request: request.clone(),
            client_peer: *client.service.local_peer_id(),
            exit_peer: *exit.service.local_peer_id(),
            exit_node: exit.local_node_id,
            expires_at_ms: parent.expires_at_ms,
            retiring: false,
            complete: false,
        }
    ));
    exit.route_retire.exit.insert(
        context,
        ExitScope {
            request: request.clone(),
            relays: original_relays.clone(),
            extensions: BTreeMap::new(),
            expires_at_ms: parent.expires_at_ms,
            retiring: false,
            complete: false,
        },
    );
    assert!(
        Box::pin(exchange(
            &mut client,
            &mut relay,
            &mut exit,
            &state,
            signed_retirement(&session, &request)
        ))
        .await
        .is_err(),
        "unknown new Relay denied"
    );
    let scope = exit.route_retire.exit.get_mut(&context).unwrap();
    let mut wrong = accepted.clone();
    wrong.scope.as_mut().unwrap().path_id = 5;
    assert!(scope.retain_extension(&extension, &wrong).is_none());
    wrong = accepted.clone();
    wrong.phase = RouteExtensionPhase::Probe as i32;
    assert!(scope.retain_extension(&extension, &wrong).is_none());
    wrong = accepted.clone();
    wrong.hard_expires_at_ms -= 1;
    assert!(scope.retain_extension(&extension, &wrong).is_none());
    scope.request.policy_hash[0] ^= 1;
    assert!(scope.retain_extension(&extension, &accepted).is_none());
    scope.request = request.clone();
    assert!(scope.extensions.is_empty());
    scope
        .retain_extension(&extension, &accepted)
        .expect("accepted new Relay retained");
    scope
        .retain_extension(&extension, &accepted)
        .expect("exact retry is idempotent");
    assert_eq!(
        scope.relays, original_relays,
        "original Finalize membership stays immutable"
    );
    assert_eq!(scope.extensions.len(), 1);
    let mut substituted = extension.clone();
    substituted.probe_id[0] ^= 1;
    wrong = accepted.clone();
    wrong.scope = Some(substituted.clone());
    assert!(scope.retain_extension(&substituted, &wrong).is_none());
    Box::pin(exchange(
        &mut client,
        &mut relay,
        &mut exit,
        &state,
        signed_retirement(&session, &request),
    ))
    .await
    .expect("new Relay receives real nested receipts");
    assert!(relay.route_retire.relay[&context].complete);
    assert!(exit.route_retire.exit[&context].complete);
    Box::pin(exchange(
        &mut client,
        &mut relay,
        &mut exit,
        &state,
        signed_retirement(&session, &request),
    ))
    .await
    .expect("retry after live owners disappeared");
    let scope = exit.route_retire.exit.get_mut(&context).unwrap();
    substituted.extension_id = generate_nonce()[..16].to_vec();
    substituted.path_id = 5;
    wrong.scope = Some(substituted.clone());
    assert!(
        scope.retain_extension(&substituted, &wrong).is_none(),
        "no new admission after retirement"
    );
}

fn insert_cleanup(runtime: &mut DiscoveryRuntime, context: [u8; 16]) -> oneshot::Sender<()> {
    let owner = RuntimeBoundPreparedLeaseBatch::for_test(
        PrepareLeaseBatch {
            route_context_id: context.to_vec(),
            role: ContextRole::Exit as i32,
            mptcp_accepted_addrs: 4,
            mptcp_subflows: 4,
            leases: Vec::new(),
            setup_expires_at_unix: 120,
            hard_expires_at_unix: 900,
            traversal_hints: Vec::new(),
        },
        PreparedLeaseBatch {
            context_handle: vec![3; 32],
            leases: Vec::new(),
        },
    );
    let (shutdown, _shutdown_receiver) = tokio::sync::watch::channel(false);
    let (done, completed) = oneshot::channel();
    runtime.exit_runtime_retirements.insert(
        context,
        super::super::ExitRuntimeRetirement {
            signed_exit_reservation: Vec::new(),
            shutdown,
            completed,
            cleanup: owner.retain_cleanup_authority(),
            cleanup_not_before_ms: 0,
        },
    );
    done
}

async fn respond(
    stream: &mut tokio::net::UnixStream,
    request: &HelperRequest,
    outcome: helper_response::Outcome,
) {
    let response = HelperResponse {
        protocol_version: HELPER_PROTOCOL_VERSION,
        request_id: request.request_id.clone(),
        result: HelperResult::Ok as i32,
        diagnostic_code: "TEST_RESPONSE".to_owned(),
        operation_digest: operation_digest(request).expect("request digest").to_vec(),
        outcome: Some(outcome),
    };
    stream
        .write_all(&encode_response(&response).expect("response"))
        .await
        .expect("reply");
}

#[tokio::test]
async fn exact_retirement_waits_for_join_and_retains_owner_after_helper_failure() {
    let (mut runtime, _, directory) = super::super::tests::content_runtime_fixture();
    let context = [17; 16];
    let other = [18; 16];
    let done = insert_cleanup(&mut runtime, context);
    let _other_done = insert_cleanup(&mut runtime, other);
    assert!(
        !runtime.retire_exact_exit_owners(context).await,
        "unjoined owner remains"
    );
    done.send(()).expect("joined runtime");
    assert!(
        !runtime.retire_exact_exit_owners(context).await,
        "missing helper is not success"
    );
    assert_eq!(runtime.exit_runtime_retirements.len(), 2);
    assert!(runtime.exit_runtime_retirements[&context].cleanup_not_before_ms > unix_millis());
    let socket = directory.path().join("retire-helper.sock");
    let listener = UnixListener::bind(&socket).expect("owned temporary socket");
    runtime.helper = HelperClient::new_for_test(
        socket,
        directory.path().join("unused.token"),
        nix::unistd::geteuid().as_raw(),
    );
    let server = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let bind = read_request(&mut stream).await.expect("Bind");
        assert!(matches!(
            bind.operation,
            Some(helper_request::Operation::BindHelperRuntime(_))
        ));
        respond(
            &mut stream,
            &bind,
            helper_response::Outcome::HelperRuntime(HelperRuntime {
                helper_runtime_id: vec![0xa5; 32],
            }),
        )
        .await;
        let request = read_request(&mut stream).await.expect("Destroy");
        let Some(helper_request::Operation::DestroyContext(value)) = request.operation.as_ref()
        else {
            panic!("only exact DestroyContext is permitted");
        };
        assert_eq!(value.route_context_id, context);
        assert_eq!(value.context_handle, vec![3; 32]);
        respond(
            &mut stream,
            &request,
            helper_response::Outcome::DestroyedContext(DestroyedContext { existed: true }),
        )
        .await;
    });
    runtime
        .exit_runtime_retirements
        .get_mut(&context)
        .expect("retained owner")
        .cleanup_not_before_ms = 0;
    assert!(runtime.retire_exact_exit_owners(context).await);
    server.await.expect("typed helper server");
    assert!(!runtime.exit_runtime_retirements.contains_key(&context));
    assert!(runtime.exit_runtime_retirements.contains_key(&other));
    assert!(
        runtime.retire_exact_exit_owners(context).await,
        "known absent owner is idempotent"
    );
}
