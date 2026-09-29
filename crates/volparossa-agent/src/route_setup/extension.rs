//! One fresh Relay added to the existing session, without rebuilding its Exit or TLS flow.
//!
//! The pending scope is retained in the parent before any mutation. Cancellation cannot erase
//! the helper extension ID or the remote cleanup target. Unconfirmed cleanup blocks another
//! extension; parent retirement remains the final owner of every attempted path.

#[allow(
    clippy::wildcard_imports,
    reason = "internal route transaction shares its parent's private authority types"
)]
use super::*;
use volparossa_protocol::{
    ClientSessionCapability, FinalizedRelayPath, RelayProbePermit, RelayProbeResult,
    RetirementReceipt, RouteExtensionPhase, RouteExtensionRelayCommit, RouteExtensionRequest,
    RouteExtensionScope, route_retire_request_hash, verify_control_message,
};
use volparossa_reservation::VerifiedRouteExtension;
use volparossa_routing::{ActivatePathExtension, CommitPathExtension, PreparePathExtension};

pub(crate) struct CommittedMptcpExtension {
    pub(crate) path_id: u32,
    pub(crate) selected_path_ids: Vec<u32>,
}

pub(super) struct PendingExtension {
    scope: RouteExtensionScope,
    deadline_ms: u64,
    prepared: bool,
    relay: DirectRelayCapability,
    authorization: Option<Vec<u8>>,
    relay_dispatched: bool,
}

impl ProductionRoute {
    /// Perform one complete +1 transaction. The caller adds the returned committed warm path to
    /// its live transport; this does not claim an active MPTCP subflow before packet observation.
    pub(crate) async fn extend_mptcp_relay(
        &mut self,
        config: &Config,
        discovery: &DiscoveryControlHandle,
        helper: &HelperClient,
        new_relay: ([u8; 32], Libp2pPeerId),
        sample_buddy: ([u8; 32], Libp2pPeerId),
    ) -> Result<CommittedMptcpExtension, ClientRouteConnectError> {
        if self.established.pending_extension.is_some() {
            cleanup(&mut self.established, discovery, helper).await?;
        }
        let result = Box::pin(extend(
            &mut self.established,
            config,
            discovery,
            helper,
            new_relay,
            sample_buddy,
        ))
        .await;
        if result.is_err() && self.established.pending_extension.is_some() {
            // A failed cleanup is not success: leave the scope owned for retry or full retirement.
            let _ = cleanup(&mut self.established, discovery, helper).await;
        }
        result
    }
}

fn unavailable() -> ClientRouteConnectError {
    ClientRouteConnectError::RouteAdmissionUnavailable
}

fn session(
    route: &mut EstablishedRoute<ReservationSession>,
) -> Result<&mut ReservationCoordinator, ClientRouteConnectError> {
    route
        .owner
        .as_mut()
        .and_then(PreparedContextOwner::protocol_mut)
        .map(|p| &mut p.coordinator)
        .ok_or_else(unavailable)
}

fn random_id() -> [u8; 16] {
    loop {
        let mut id = [0; 16];
        OsRng.fill_bytes(&mut id);
        if id != [0; 16] {
            return id;
        }
    }
}

fn next_path_id(
    original_count: usize,
    selected: &[u32],
    attempted: &BTreeSet<u32>,
    maximum_paths: u32,
    permit_limit: u32,
) -> Option<u32> {
    if !(2..=8).contains(&original_count)
        || !(2..=8).contains(&maximum_paths)
        || permit_limit < maximum_paths
        || permit_limit > 8
        || selected.len() >= usize::try_from(maximum_paths).ok()?
        || original_count.checked_add(attempted.len())? >= 8
    {
        return None;
    }
    (1..=permit_limit).find(|id| !selected.contains(id) && !attempted.contains(id))
}

async fn authorities(
    route: &EstablishedRoute<ReservationSession>,
    discovery: &DiscoveryControlHandle,
) -> Result<RouteSetupAuthorities, ClientRouteConnectError> {
    let c = &route.request.control.identity;
    let e = &route.request.exit;
    let control = discovery
        .resolve_direct_relay(c.wire_node_id, c.peer_id)
        .await
        .map_err(|_| unavailable())?;
    let exit = discovery
        .resolve_forwarded_exit(c.wire_node_id, c.peer_id, e.wire_node_id, e.peer_id)
        .await
        .map_err(|_| unavailable())?;
    if control.public_key != c.public_key
        || exit.exit_public_key != e.public_key
        || control.policy_hash != route.request.parameters.policy_hash
        || exit.policy_hash != route.request.parameters.policy_hash
        || !forwarded_control_lineage_matches_current(&control, &exit, crate::unix_millis())
    {
        return Err(unavailable());
    }
    Ok(RouteSetupAuthorities {
        control,
        exit,
        datapath_relays: Vec::new(),
    })
}

async fn exit_phase(
    route: &mut EstablishedRoute<ReservationSession>,
    discovery: &DiscoveryControlHandle,
    request: &RouteExtensionRequest,
    deadline_ms: u64,
) -> Result<(VerifiedRouteExtension, Vec<u8>), ClientRouteConnectError> {
    let now = crate::unix_millis();
    if deadline_ms <= now {
        return Err(unavailable());
    }
    let signed = session(route)?
        .sign_route_extension_request(request, now, deadline_ms)
        .map_err(|_| unavailable())?;
    let authority = authorities(route, discovery).await?;
    let rpc = exit_forward_request(
        &authority,
        ExitForwardOperation::ExtendRoute,
        signed.clone(),
        deadline_ms,
    )
    .map_err(|_| unavailable())?;
    let response = timeout(
        MAXIMUM_CALL_DURATION,
        discovery.request_exit_forward(authority.control.peer_id, rpc.clone()),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())?;
    let values = accepted_exit_response(
        &rpc,
        &response,
        &authority.exit,
        RouteSetupPhase::Finalizing,
    )
    .map_err(|_| unavailable())?;
    let [encoded]: [Vec<u8>; 1] = values.try_into().map_err(|_| unavailable())?;
    let original = &route.exit_bundle;
    let coordinator = &mut route
        .owner
        .as_mut()
        .and_then(PreparedContextOwner::protocol_mut)
        .ok_or_else(unavailable)?
        .coordinator;
    let verified = coordinator
        .verify_route_extension_response(original, request, &encoded, crate::unix_millis())
        .map_err(|_| unavailable())?;
    Ok((verified, signed))
}

async fn relay_phase(
    discovery: &DiscoveryControlHandle,
    relay: &DirectRelayCapability,
    operation: DatapathRelayOperation,
    client: Vec<u8>,
    exit: Vec<u8>,
    deadline_ms: u64,
) -> Result<Vec<u8>, ClientRouteConnectError> {
    let rpc =
        datapath_request(relay, operation, client, exit, deadline_ms).map_err(|_| unavailable())?;
    let response = timeout(
        MAXIMUM_CALL_DURATION,
        discovery.request_datapath_relay(relay.peer_id, rpc.clone()),
    )
    .await
    .map_err(|_| unavailable())?
    .map_err(|_| unavailable())?;
    accepted_datapath_response(&rpc, &response, relay, RouteSetupPhase::RelayReservations)
        .map_err(|_| unavailable())
}

#[allow(
    clippy::too_many_lines,
    reason = "one additive transaction retains parent cleanup ownership through every phase"
)]
async fn extend(
    route: &mut EstablishedRoute<ReservationSession>,
    config: &Config,
    discovery: &DiscoveryControlHandle,
    helper: &HelperClient,
    new_relay: ([u8; 32], Libp2pPeerId),
    buddy: ([u8; 32], Libp2pPeerId),
) -> Result<CommittedMptcpExtension, ClientRouteConnectError> {
    let now = crate::unix_millis();
    let params = &route.request.parameters;
    if params.allowed_transports != [Transport::TcpMptcp]
        || params.expires_at_ms <= now
        || route.pending_extension.is_some()
        || route
            .relay_authorities
            .iter()
            .any(|p| p.node_id == new_relay.0 || p.peer_id == new_relay.1)
        || !route
            .relay_authorities
            .iter()
            .any(|p| p.node_id == buddy.0 && p.peer_id == buddy.1)
        || new_relay == buddy
    {
        return Err(unavailable());
    }
    let cap_envelope: SignedEnvelope = decode_canonical(
        route.exit_bundle.signed_capability(),
        MAX_CONTROL_MESSAGE_SIZE,
    )
    .map_err(|_| unavailable())?;
    let cap: ClientSessionCapability =
        decode_canonical(&cap_envelope.payload, MAX_CONTROL_MESSAGE_SIZE)
            .map_err(|_| unavailable())?;
    let selected = route
        .relay_grants
        .iter()
        .map(VerifiedRelayGrant::path_id)
        .collect::<Vec<_>>();
    let path_id = next_path_id(
        route.exit_bundle.path_count(),
        &selected,
        &route.attempted_extension_paths,
        cap.maximum_paths,
        cap.probe_permit_limit,
    )
    .ok_or_else(unavailable)?;
    let mut sample_config = config.clone();
    sample_config.udp.enabled = false;
    sample_config.tcp.enabled = true;
    sample_config.selection.active_multipath_paths = 2;
    sample_config.selection.minimum_multipath_paths = 2;
    sample_config.selection.maximum_multipath_paths = 2;
    sample_config.selection.warm_backup_paths = 0;
    let prepared = discovery
        .prepare_client_preselection_for_route(
            client_preselection_parameters(&sample_config)?,
            route.request.exit.wire_node_id,
            route.request.exit.peer_id,
            route.request.control.identity.wire_node_id,
            route.request.control.identity.peer_id,
            vec![new_relay, buddy],
        )
        .await
        .map_err(map_preselection_error)?;
    let relay = discovery
        .resolve_direct_relay(new_relay.0, new_relay.1)
        .await
        .map_err(|_| unavailable())?;
    let extension_id = random_id();
    let scope = RouteExtensionScope {
        extension_id: extension_id.to_vec(),
        signed_exit_reservation: route.signed_exit_reservation.clone(),
        finalized_bundle_hash: route.exit_bundle.finalized_bundle_hash().to_vec(),
        path_id,
        relay_node_id: new_relay.0.to_vec(),
        relay_peer_id: new_relay.1.to_bytes(),
        probe_id: random_id().to_vec(),
        address_family: params.probe_address_family as i32,
    };
    let deadline_ms = crate::unix_millis()
        .saturating_add(MAXIMUM_PHASE_LIFETIME_MS)
        .min(params.expires_at_ms);
    route.attempted_extension_paths.insert(path_id);
    route.pending_extension = Some(PendingExtension {
        scope: scope.clone(),
        deadline_ms,
        prepared: false,
        relay: relay.clone(),
        authorization: None,
        relay_dispatched: false,
    });
    let mut request = RouteExtensionRequest {
        scope: Some(scope.clone()),
        phase: RouteExtensionPhase::Probe as i32,
        path: None,
        signed_confirmation: Vec::new(),
    };
    // Permit first. The following signed Native sampler must measure AFTER this permit's time.
    let (permit_response, signed_probe_request) =
        exit_phase(route, discovery, &request, deadline_ms).await?;
    let signed_permit = permit_response.message().signed_probe_permit.clone();
    let preselection = selection_bridge::begin_client_native_preselection(
        prepared,
        client_route_admission_profile(&sample_config)?,
        discovery,
    )
    .await
    .map_err(|_| unavailable())?;
    let ready = preselection
        .dispatch_relay_ready(discovery)
        .await
        .map_err(|_| unavailable())?;
    let count = ready.candidate_path_count();
    if count != 2 {
        return Err(unavailable());
    }
    let completed = complete_required_client_native_paths(ready, count, discovery, helper).await?;
    let proof = completed
        .into_extension_relay(&route.request, new_relay.0, new_relay.1)
        .map_err(|_| unavailable())?;
    let relay = proof.resolve(discovery).await.map_err(|_| unavailable())?;
    if !proof.capability_matches(
        &relay,
        route.request.parameters.policy_hash,
        deadline_ms,
        route.request.parameters.expires_at_ms,
    ) || crate::unix_millis() >= deadline_ms
    {
        return Err(unavailable());
    }
    route
        .pending_extension
        .as_mut()
        .ok_or_else(unavailable)?
        .relay = relay.clone();
    let signed_result = relay_phase(
        discovery,
        &relay,
        DatapathRelayOperation::ExtensionProbe,
        signed_probe_request,
        signed_permit.clone(),
        deadline_ms,
    )
    .await?;
    validate_measurement(
        &scope,
        &signed_permit,
        &signed_result,
        &route.request.parameters,
    )?;
    let owner = route
        .owner
        .as_ref()
        .and_then(PreparedContextOwner::runtime_owner)
        .ok_or_else(unavailable)?;
    let hints = discovery
        .endpoint_traversal_hints(vec![EndpointTraversalBinding {
            path_id,
            role: WireguardRole::Client,
            observer_id: new_relay.0,
            observer_peer_id: new_relay.1,
        }])
        .await
        .map_err(|_| unavailable())?;
    route
        .pending_extension
        .as_mut()
        .ok_or_else(unavailable)?
        .prepared = true;
    let prepared = helper
        .prepare_path_extension(
            &mut *owner.lock().await,
            PreparePathExtension {
                route_context_id: route.request.parameters.route_context_id.to_vec(),
                context_handle: route.commit_proof.context_handle.clone(),
                extension_id: extension_id.to_vec(),
                lease: Some(LeasePlan {
                    path_id,
                    role: WireguardRole::Client as i32,
                }),
                setup_expires_at_unix: deadline_ms / 1_000,
                traversal_hints: hints,
            },
        )
        .await
        .map_err(|_| unavailable())?;
    let endpoint = crate::endpoint_leases::bind_prepared_client_path_extension(
        route.request.parameters.route_context_id,
        extension_id,
        path_id,
        prepared,
    )
    .map_err(|_| unavailable())?;
    let lease_handle = endpoint.lease_handle().as_bytes().to_vec();
    request.phase = RouteExtensionPhase::Authorize as i32;
    request.path = Some(FinalizedRelayPath {
        path_id,
        relay_node_id: new_relay.0.to_vec(),
        relay_peer_id: new_relay.1.to_bytes(),
        client_wireguard_public_key: endpoint.public_endpoint().public_key().as_bytes().to_vec(),
        relay_probe_permit: signed_permit,
        relay_probe_result: signed_result,
    });
    let (authorized, _) = exit_phase(route, discovery, &request, deadline_ms).await?;
    route
        .pending_extension
        .as_mut()
        .ok_or_else(unavailable)?
        .authorization = Some(authorized.encoded().to_vec());
    let signed_relay_request = route
        .owner
        .as_mut()
        .and_then(PreparedContextOwner::protocol_mut)
        .ok_or_else(unavailable)?
        .coordinator
        .sign_extension_relay_request(
            &route.exit_bundle,
            &authorized,
            endpoint,
            crate::unix_millis(),
            deadline_ms,
        )
        .map_err(|_| unavailable())?;
    route
        .owner
        .as_mut()
        .ok_or_else(unavailable)?
        .retain_remote_relay(relay.peer_id)
        .map_err(|()| unavailable())?;
    route
        .pending_extension
        .as_mut()
        .ok_or_else(unavailable)?
        .relay_dispatched = true;
    let signed_grant = relay_phase(
        discovery,
        &relay,
        DatapathRelayOperation::ReservePath,
        signed_relay_request,
        Vec::new(),
        deadline_ms,
    )
    .await?;
    let grant = route
        .owner
        .as_mut()
        .and_then(PreparedContextOwner::protocol_mut)
        .ok_or_else(unavailable)?
        .coordinator
        .verify_extension_relay_response(
            &route.exit_bundle,
            &authorized,
            &signed_grant,
            &relay.peer_id.to_bytes(),
            crate::unix_millis(),
        )
        .map_err(|_| unavailable())?;
    let signed_confirmation = session(route)?
        .sign_exit_confirmation(&grant, crate::unix_millis(), deadline_ms)
        .map_err(|_| unavailable())?;
    let peer = grant.relay_client_endpoint();
    helper
        .activate_path_extension(
            &mut *owner.lock().await,
            ActivatePathExtension {
                route_context_id: route.request.parameters.route_context_id.to_vec(),
                context_handle: route.commit_proof.context_handle.clone(),
                extension_id: extension_id.to_vec(),
                lease: Some(LeaseActivation {
                    lease_handle: lease_handle.clone(),
                    path_id,
                    role: WireguardRole::Client as i32,
                    peer_public_key: peer.public_key().as_bytes().to_vec(),
                    peer_endpoint: Some(PublicUdpEndpoint {
                        address: ip_bytes(peer.underlay_ip()),
                        port: u32::from(peer.listen_port()),
                    }),
                    maximum_up_mbps: 0,
                    maximum_down_mbps: 0,
                    signed_relay_reservation: signed_grant,
                    signed_client_relay_request: Vec::new(),
                }),
                signed_route_extension: authorized.encoded().to_vec(),
            },
        )
        .await
        .map_err(|_| unavailable())?;
    request.phase = RouteExtensionPhase::Commit as i32;
    request.path = None;
    request.signed_confirmation.clone_from(&signed_confirmation);
    let local_commit = CommitPathExtension {
        route_context_id: route.request.parameters.route_context_id.to_vec(),
        context_handle: route.commit_proof.context_handle.clone(),
        extension_id: extension_id.to_vec(),
        lease: Some(LeaseCommit {
            lease_handle,
            path_id,
            role: WireguardRole::Client as i32,
        }),
    };
    // Activate before all three commit probes run. No side may wait for another commit's reply
    // before it emits/verifies the real WG traffic required by the helper.
    let (exit, relay_committed, local) = tokio::join!(
        exit_phase(route, discovery, &request, deadline_ms),
        relay_phase(
            discovery,
            &relay,
            DatapathRelayOperation::ExtensionCommit,
            signed_confirmation.clone(),
            authorized.encoded().to_vec(),
            deadline_ms
        ),
        async {
            helper
                .commit_path_extension(&mut *owner.lock().await, local_commit)
                .await
        },
    );
    let (committed, _) = exit?;
    validate_relay_commit(&scope, &authorized, &signed_confirmation, &relay_committed?)?;
    let local = local.map_err(|_| unavailable())?;
    let mut selected = route
        .relay_grants
        .iter()
        .map(VerifiedRelayGrant::path_id)
        .collect::<Vec<_>>();
    selected.push(path_id);
    selected.sort_unstable();
    if committed.message().selected_path_ids != selected {
        return Err(unavailable());
    }
    let mut extensions = route
        .signed_extensions
        .iter()
        .map(Vec::as_slice)
        .collect::<Vec<_>>();
    extensions.push(committed.encoded());
    let mut grants = route
        .relay_grants
        .iter()
        .map(VerifiedRelayGrant::signed_relay_reservation)
        .collect::<Vec<_>>();
    grants.push(grant.signed_relay_reservation());
    VerifiedMptcpRoute::verify_with_extensions(
        &route.signed_exit_reservation,
        &grants,
        &extensions,
        route.exit_bundle.signed_capability(),
        crate::unix_millis(),
        TimePolicy::default(),
        &mut ReplayCache::new(64).map_err(|_| unavailable())?,
    )
    .map_err(|_| unavailable())?;
    route
        .commit_proof
        .leases
        .push(local.lease.ok_or_else(unavailable)?);
    route.relay_grants.push(grant);
    route.relay_authorities.push(relay);
    route.confirmations.push(RelayConfirmationProof {
        signed_confirmation,
        signed_receipt: committed.message().signed_confirmation_receipt.clone(),
    });
    route.signed_extensions.push(committed.encoded().to_vec());
    route.warm_path_ids.push(path_id);
    route.warm_path_ids.sort_unstable();
    route.request.paths.retain(|p| p.path_id != path_id);
    route.request.paths.push(RouteSetupPath { path_id, proof });
    route.pending_extension = None;
    Ok(CommittedMptcpExtension {
        path_id,
        selected_path_ids: selected,
    })
}

fn validate_measurement(
    scope: &RouteExtensionScope,
    signed_permit: &[u8],
    signed_result: &[u8],
    params: &RouteSetupParameters,
) -> Result<(), ClientRouteConnectError> {
    let now = crate::unix_millis();
    let mut replay = ReplayCache::new(2).map_err(|_| unavailable())?;
    let permit = verify_control_message::<RelayProbePermit>(
        signed_permit,
        now,
        TimePolicy::default(),
        &mut replay,
    )
    .map_err(|_| unavailable())?;
    let measured = verify_control_message::<RelayProbeResult>(
        signed_result,
        now,
        TimePolicy::default(),
        &mut replay,
    )
    .map_err(|_| unavailable())?;
    let p = permit.message();
    let m = measured.message();
    if measured.sender_id().as_slice() != scope.relay_node_id
        || m.relay_peer_id != scope.relay_peer_id
        || m.relay_probe_permit != signed_permit
        || m.probe_id != scope.probe_id
        || p.path_id != scope.path_id
        || m.reservation_id != p.reservation_id
        || m.route_context_id != p.route_context_id
        || m.client_session_id != p.client_session_id
        || m.exit_node_id != p.exit_node_id
        || m.exit_peer_id != p.exit_peer_id
        || m.exit_boot_id != p.exit_boot_id
        || m.hold_id != p.hold_id
        || m.capability_id != p.capability_id
        || m.policy_hash != p.policy_hash
        || m.transport != Transport::TcpMptcp as i32
        || m.address_family != scope.address_family
        || m.measured_at_ms < p.created_at_ms
        || m.expires_at_ms > p.expires_at_ms
    {
        return Err(unavailable());
    }
    for leg in [&m.client_relay, &m.relay_exit] {
        let leg = leg.as_ref().ok_or_else(unavailable)?;
        if leg.up_capacity_mbps < params.reserved_up_mbps
            || leg.down_capacity_mbps < params.reserved_down_mbps
            || leg.measured_at_ms < p.created_at_ms
            || leg.transmitted_bytes == 0
            || leg.received_bytes == 0
        {
            return Err(unavailable());
        }
    }
    Ok(())
}

fn validate_relay_commit(
    scope: &RouteExtensionScope,
    authorization: &VerifiedRouteExtension,
    confirmation: &[u8],
    encoded: &[u8],
) -> Result<(), ClientRouteConnectError> {
    let mut replay = ReplayCache::new(1).map_err(|_| unavailable())?;
    let verified = verify_control_message::<RouteExtensionRelayCommit>(
        encoded,
        crate::unix_millis(),
        TimePolicy::default(),
        &mut replay,
    )
    .map_err(|_| unavailable())?;
    let parent = scope.parent().map_err(|_| unavailable())?;
    let m = verified.message();
    if verified.sender_id().as_slice() != scope.relay_node_id
        || m.extension_id != scope.extension_id
        || m.path_id != scope.path_id
        || m.route_context_id != parent.route_context_id
        || m.reservation_id != parent.reservation_id
        || m.hard_expires_at_ms != parent.expires_at_ms
        || m.authorization_sha256.as_slice() != Sha256::digest(authorization.encoded()).as_slice()
        || m.confirmation_sha256.as_slice() != Sha256::digest(confirmation).as_slice()
    {
        return Err(unavailable());
    }
    Ok(())
}

async fn cleanup(
    route: &mut EstablishedRoute<ReservationSession>,
    discovery: &DiscoveryControlHandle,
    helper: &HelperClient,
) -> Result<(), ClientRouteConnectError> {
    let pending = route.pending_extension.as_ref().ok_or_else(unavailable)?;
    let scope = pending.scope.clone();
    let relay = pending.relay.clone();
    let authorization = pending.authorization.clone();
    let prepared = pending.prepared;
    let dispatched = pending.relay_dispatched;
    let now = crate::unix_millis();
    let hard = route.request.parameters.expires_at_ms;
    let expires = now
        .saturating_add(volparossa_protocol::MAX_ROUTE_RETIRE_LIFETIME_MS)
        .min(hard);
    let local = if prepared {
        let owner = route
            .owner
            .as_ref()
            .and_then(PreparedContextOwner::runtime_owner)
            .ok_or_else(unavailable)?;
        let id = scope
            .extension_id
            .as_slice()
            .try_into()
            .map_err(|_| unavailable())?;
        helper
            .abort_path_extension(&mut *owner.lock().await, id)
            .await
            .map_err(|_| unavailable())
    } else {
        Ok(())
    };
    let relay_result = if dispatched {
        let retirement = RemoteRetirementScope {
            route_context_id: route.request.parameters.route_context_id,
            reservation_id: route.request.parameters.reservation_id,
            policy_hash: route.request.parameters.policy_hash,
            exit_peer_id: route.request.exit.peer_id,
        };
        let signed = route
            .owner
            .as_mut()
            .and_then(PreparedContextOwner::protocol_mut)
            .ok_or_else(unavailable)?
            .sign_route_retire(&retirement, now, expires)
            .map_err(|_| unavailable())?;
        let encoded = relay_phase(
            discovery,
            &relay,
            DatapathRelayOperation::ExtensionAbort,
            signed.clone(),
            authorization.ok_or_else(unavailable)?,
            expires,
        )
        .await;
        encoded.and_then(|encoded| {
            let mut seen = ReplayCache::new(1).map_err(|_| unavailable())?;
            let receipt = verify_control_message::<RetirementReceipt>(
                &encoded,
                crate::unix_millis(),
                TimePolicy::default(),
                &mut seen,
            )
            .map_err(|_| unavailable())?;
            let value = receipt.message();
            if receipt.sender_id() != &relay.node_id
                || value.route_context_id != retirement.route_context_id
                || value.reservation_id != retirement.reservation_id
                || value.request_hash.as_slice()
                    != route_retire_request_hash(&signed).map_err(|_| unavailable())?
                || !value.signed_exit_receipt.is_empty()
            {
                return Err(unavailable());
            }
            Ok(())
        })
    } else {
        Ok(())
    };
    let request = RouteExtensionRequest {
        scope: Some(scope),
        phase: RouteExtensionPhase::Abort as i32,
        path: None,
        signed_confirmation: Vec::new(),
    };
    let exit = exit_phase(route, discovery, &request, expires).await;
    local?;
    relay_result?;
    exit?;
    route.pending_extension = None;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::next_path_id;
    use std::collections::BTreeSet;

    #[test]
    fn refill_allocates_only_unused_ids_inside_original_authority() {
        let aborted = BTreeSet::from([3]);
        assert_eq!(next_path_id(2, &[2, 5], &aborted, 4, 8), Some(1));
        assert_eq!(
            next_path_id(2, &[1, 2], &BTreeSet::from([3, 4]), 4, 8),
            Some(5)
        );
        assert_eq!(next_path_id(2, &[1, 2, 4, 5], &aborted, 4, 8), None);
        assert_eq!(next_path_id(2, &[1, 2], &aborted, 8, 4), None);
    }

    #[test]
    fn refill_counts_committed_extensions_once_and_retains_aborted_budget() {
        assert_eq!(
            next_path_id(2, &[1, 2, 3, 4, 5], &BTreeSet::from([3, 4, 5]), 8, 8),
            Some(6)
        );
        assert_eq!(
            next_path_id(2, &[1, 2], &BTreeSet::from([3, 4, 5, 6, 7, 8]), 8, 8),
            None
        );
        assert_eq!(next_path_id(2, &[1, 2], &BTreeSet::new(), 2, 8), None);
    }
}
