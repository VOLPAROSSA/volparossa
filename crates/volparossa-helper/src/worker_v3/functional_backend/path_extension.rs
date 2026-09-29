//! Additive same-worker paths. Every birth is journaled and staged before kernel mutation.
use super::*;
use crate::internal_protocol::path_extension::{Action, PathExtension};
use crate::ownership_journal::DurablePathExtension;
use volparossa_routing::{
    AbortPathExtension, ActivatePathExtension, CommitPathExtension, PreparePathExtension,
};

pub(super) struct RouteIdentity {
    exit_key: [u8; 32],
    authorization: RelayAuthorization,
}

pub(super) fn original_identity(
    activations: &[volparossa_routing::LeaseActivation],
    now: u64,
) -> Result<RouteIdentity, BackendError> {
    let lease = activations.first().ok_or(BackendError::Invalid)?;
    let outer: SignedEnvelope =
        decode_canonical(&lease.signed_relay_reservation, MAX_CONTROL_MESSAGE_SIZE)
            .map_err(|_| BackendError::Invalid)?;
    let bytes = if outer.message_type == ControlMessageType::RelayReservation as i32 {
        let relay: RelayReservation = decode_canonical(&outer.payload, MAX_CONTROL_MESSAGE_SIZE)
            .map_err(|_| BackendError::Invalid)?;
        relay.exit_authorization
    } else {
        lease.signed_relay_reservation.clone()
    };
    let mut replay = ReplayCache::new(2).map_err(|_| BackendError::Unavailable)?;
    let verified = verify_control_message::<RelayAuthorization>(
        &bytes,
        now,
        TimePolicy::default(),
        &mut replay,
    )
    .map_err(|_| BackendError::Invalid)?;
    Ok(RouteIdentity {
        exit_key: *verified.sender_public_key(),
        authorization: verified.message().clone(),
    })
}

pub(super) struct OpenExtension {
    owner: LiveWireguardLeaseOwner,
    prepare: PrepareLeases,
    underlays: UnderlayBindings,
    prepared: Option<PreparedWorkerLease>,
    activated: Option<ActivatedWorkerLease>,
    activated_at_unix: u64,
    setup_boottime_ns: u64,
    birth_may_exist: bool,
    committed: bool,
    aborted: bool,
}

fn scope(
    binding: BackendBinding,
    context: &[u8],
    handle: &[u8],
    id: &[u8],
    action: BackendAction,
) -> Result<(OpenLineageKey, [u8; 16], HardDeadline), BackendError> {
    let id: [u8; 16] = id.try_into().map_err(|_| BackendError::Invalid)?;
    if id == [0; 16]
        || binding.action != action
        || binding.phase != BackendPhase::Committed
        || binding.prior_phase != Some(ContextPhase::Committed)
        || binding.operation_kind != OperationKind::PathExtension
        || binding.operation_sequence == 0
        || binding.operation_generation == 0
        || context != binding.lineage.context_id
        || handle.len() != HELPER_HANDLE_BYTES
        || handle.iter().all(|b| *b == 0)
    {
        return Err(BackendError::Invalid);
    }
    let key = OpenLineageKey::from(binding.lineage);
    if action != BackendAction::AbortPathExtension {
        ensure_hard_is_live(key)?;
    }
    Ok((key, id, prepare_deadline(binding)?))
}

fn live_extension(entry: &OpenLeaseEntry, id: [u8; 16]) -> Result<&OpenExtension, BackendError> {
    let extension = entry
        .extensions
        .get(&id)
        .filter(|extension| !extension.aborted)
        .ok_or(BackendError::Invalid)?;
    ensure_hard_is_live(entry.key)?;
    if current_boottime_nanos()? >= extension.setup_boottime_ns
        || unix_milliseconds()? / 1000 >= extension.owner.resource().setup_expires_at_unix()
    {
        return Err(BackendError::Invalid);
    }
    Ok(extension)
}

impl FunctionalAlphaLeaseBackend {
    async fn extension_call(
        &self,
        key: OpenLineageKey,
        id: [u8; 16],
        action: Action,
        binding: BackendBinding,
        stage: u8,
        deadline: HardDeadline,
    ) -> Result<crate::worker_transport::CredentialedWorkerExecution, BackendError> {
        let generation = entry_generation(&self.state, key)?;
        let mut digest =
            blake3::Hasher::new_derive_key("VOLPAROSSA helper path-extension worker request v1");
        digest.update(&worker_attempt_request_id(key, stage, binding));
        digest.update(&id);
        let request_id = digest.finalize().as_bytes()[..16]
            .try_into()
            .map_err(|_| BackendError::Invalid)?;
        self.coordinator
            .execute_until(
                key.context_id,
                generation,
                worker_request(
                    request_id,
                    internal_worker_request::Operation::PathExtension(PathExtension {
                        extension_id: id.to_vec(),
                        action: Some(action),
                    }),
                ),
                worker_operation_deadline(deadline)?,
            )
            .await
            .map_err(|_| BackendError::CleanupIncomplete)
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one affine prepare transaction retains every ownership handoff and cleanup"
    )]
    pub(super) async fn prepare_extension(
        &self,
        binding: BackendBinding,
        value: PreparePathExtension,
    ) -> Result<PreparedKernelLease, BackendError> {
        let (key, id, deadline) = scope(
            binding,
            &value.route_context_id,
            &value.context_handle,
            &value.extension_id,
            BackendAction::PreparePathExtension,
        )?;
        let lease = value.lease.as_ref().ok_or(BackendError::Invalid)?;
        let now = unix_milliseconds()? / 1000;
        let remaining = value
            .setup_expires_at_unix
            .checked_sub(now)
            .filter(|v| (1..=30).contains(v))
            .ok_or(BackendError::Invalid)?;
        if value.setup_expires_at_unix > key.hard_expires_at_unix {
            return Err(BackendError::Invalid);
        }
        let setup_boottime_ns = current_boottime_nanos()?
            .checked_add(remaining * 1_000_000_000)
            .ok_or(BackendError::Invalid)?
            .min(key.hard_expires_at_boottime_ns);
        let underlays = collect_consistent_underlays(
            deadline,
            std::slice::from_ref(lease),
            &value.traversal_hints,
        )
        .map_err(|_| BackendError::Unavailable)?;
        let prepare = {
            let mut state = lock_state(&self.state);
            let entry = exact_entry_mut(&mut state, key)?;
            if entry.phase != OpenLeasePhase::Committed
                || !matches!(entry.context_role, ContextRole::Client | ContextRole::Exit)
                || functional_lease_role(entry.context_role as i32, lease.role).is_none()
                || entry.extensions.contains_key(&id)
                || entry.prepare.leases.len() + entry.extensions.len() >= 8
                || entry
                    .prepare
                    .leases
                    .iter()
                    .any(|old| old.path_id == lease.path_id)
                || entry.extensions.values().any(|old| {
                    u32::from(old.owner.resource().key().0) == lease.path_id
                        || (!old.aborted && !old.committed)
                })
            {
                return Err(BackendError::Invalid);
            }
            let Some(DurableLeaseCustody {
                settlement: DurableJournalSettlement::MayOwn(original),
                ..
            }) = entry.durable.as_ref()
            else {
                return Err(BackendError::Unavailable);
            };
            let resource = self
                .durable_ownership
                .as_ref()
                .ok_or(BackendError::Unavailable)?
                .extend_path_until(
                    original,
                    DurablePathExtension {
                        extension_id: id,
                        path_id: u8::try_from(lease.path_id).map_err(|_| BackendError::Invalid)?,
                        setup_expires_at_unix: value.setup_expires_at_unix,
                    },
                    deadline,
                )
                .map_err(|_| BackendError::Unavailable)?;
            let prepare = PrepareLeases {
                route_context_id: key.context_id.to_vec(),
                leases: vec![
                    resource
                        .internal_lease_plan_v3()
                        .map_err(|_| BackendError::Invalid)?,
                ],
            };
            entry.extensions.insert(
                id,
                OpenExtension {
                    owner: LiveWireguardLeaseOwner::claim(resource),
                    prepare: prepare.clone(),
                    underlays,
                    prepared: None,
                    activated: None,
                    activated_at_unix: 0,
                    setup_boottime_ns,
                    birth_may_exist: false,
                    committed: false,
                    aborted: false,
                },
            );
            prepare
        };
        let staged = self
            .extension_call(
                key,
                id,
                Action::Stage(prepare.clone()),
                binding,
                30,
                deadline,
            )
            .await?;
        if !matches_initialised(Some(&staged), key.context_id) {
            return Err(BackendError::CleanupIncomplete);
        }
        {
            let mut state = lock_state(&self.state);
            let entry = exact_entry_mut(&mut state, key)?;
            let namespace = entry
                .recovery
                .as_ref()
                .ok_or(BackendError::CleanupIncomplete)?
                .restart_custody
                .borrowed_network_namespace()
                .as_raw_fd();
            let extension = entry
                .extensions
                .get_mut(&id)
                .ok_or(BackendError::CleanupIncomplete)?;
            extension.birth_may_exist = true;
            let mut kernel = BirthNamespaceKernel::connect(deadline)
                .map_err(|_| BackendError::CleanupIncomplete)?;
            match kernel.create_and_move_wireguard(&mut extension.owner, namespace, deadline) {
                Ok(()) => {}
                Err(BirthLinkError::Conflict | BirthLinkError::Kernel(_)) => {
                    extension.birth_may_exist = false;
                    return Err(BackendError::CleanupIncomplete);
                }
                Err(BirthLinkError::CleanupIncomplete) => {
                    return Err(BackendError::CleanupIncomplete);
                }
            }
        }
        let execution = self
            .extension_call(key, id, Action::Prepare(prepare), binding, 31, deadline)
            .await?;
        let prepared = matches_prepared_batch(Some(&execution), std::slice::from_ref(lease))
            .and_then(|mut values| values.pop())
            .ok_or(BackendError::CleanupIncomplete)?;
        let mut state = lock_state(&self.state);
        let entry = exact_entry_mut(&mut state, key)?;
        live_extension(entry, id)?;
        let extension = entry
            .extensions
            .get_mut(&id)
            .ok_or(BackendError::CleanupIncomplete)?;
        extension.prepared = Some(prepared);
        let underlay = extension
            .underlays
            .get(&(lease.path_id, lease.role))
            .ok_or(BackendError::Invalid)?
            .candidate;
        let result = PreparedKernelLease {
            path_id: prepared.path_id,
            role: prepared.role,
            public_key: prepared.public_key,
            public_endpoint: PublicUdpEndpoint {
                address: ip_bytes(underlay.address),
                port: u32::from(prepared.listen_port),
            },
            evidence: match underlay.evidence {
                crate::underlay::UnderlayEvidence::DirectAssigned => {
                    RoutingUnderlayEvidence::DirectAssigned
                }
                crate::underlay::UnderlayEvidence::ObservedUdpPunch => {
                    RoutingUnderlayEvidence::ObservedUdpPunch
                }
                crate::underlay::UnderlayEvidence::DirectOnLink => {
                    RoutingUnderlayEvidence::DirectOnLink
                }
            },
        };
        entry.prepared.push(prepared);
        entry.underlays.extend(extension.underlays.clone());
        Ok(result)
    }

    pub(super) async fn activate_extension(
        &self,
        binding: BackendBinding,
        value: ActivatePathExtension,
    ) -> Result<KernelCounters, BackendError> {
        let (key, id, deadline) = scope(
            binding,
            &value.route_context_id,
            &value.context_handle,
            &value.extension_id,
            BackendAction::ActivatePathExtension,
        )?;
        let lease = value.lease.as_ref().ok_or(BackendError::Invalid)?;
        {
            let state = lock_state(&self.state);
            let identity = exact_entry(&state, key)?
                .route_identity
                .as_ref()
                .ok_or(BackendError::Invalid)?;
            verify_extension_authority(key, id, identity, &value)?;
        }
        let (prepared, plan) = {
            let state = lock_state(&self.state);
            let entry = exact_entry(&state, key)?;
            let extension = live_extension(entry, id)?;
            let prepared = extension.prepared.ok_or(BackendError::Invalid)?;
            if extension.activated.is_some() || extension.committed {
                return Err(BackendError::Invalid);
            }
            revalidate_underlay_bindings(deadline, &extension.underlays)
                .map_err(|_| BackendError::Unavailable)?;
            let plan = verified_internal_activate_batch_plan(
                &self.relay_replay,
                std::slice::from_ref(&extension.owner),
                key,
                std::slice::from_ref(&prepared),
                &extension.underlays,
                std::slice::from_ref(lease),
                unix_milliseconds()?,
            )?;
            (prepared, plan)
        };
        let required_budget_paths = plan.receive_budget_required_paths.clone();
        self.register_receive_tuples(key, std::slice::from_ref(lease), deadline)?;
        let activated_at_unix = unix_milliseconds()? / 1000;
        let execution = self
            .extension_call(key, id, Action::Activate(plan), binding, 32, deadline)
            .await?;
        let baseline = matches_activated_batch(Some(&execution), std::slice::from_ref(&prepared))
            .and_then(|mut values| values.pop())
            .ok_or(BackendError::CleanupIncomplete)?;
        let mut state = lock_state(&self.state);
        let entry = exact_entry_mut(&mut state, key)?;
        let extension = entry
            .extensions
            .get_mut(&id)
            .ok_or(BackendError::CleanupIncomplete)?;
        extension.activated_at_unix = activated_at_unix;
        extension.activated = Some(ActivatedWorkerLease {
            prepared,
            baseline,
            peer_public_key: lease
                .peer_public_key
                .as_slice()
                .try_into()
                .map_err(|_| BackendError::Invalid)?,
        });
        entry
            .downlink
            .extend(downlink_sender::activated_budget_grants(
                std::slice::from_ref(lease),
                &required_budget_paths,
            ));
        Ok(baseline)
    }

    pub(super) async fn commit_extension(
        &self,
        binding: BackendBinding,
        value: CommitPathExtension,
    ) -> Result<KernelCounters, BackendError> {
        let (key, id, deadline) = scope(
            binding,
            &value.route_context_id,
            &value.context_handle,
            &value.extension_id,
            BackendAction::CommitPathExtension,
        )?;
        let lease = value.lease.as_ref().ok_or(BackendError::Invalid)?;
        let (activated, at) = {
            let state = lock_state(&self.state);
            let extension = live_extension(exact_entry(&state, key)?, id)?;
            let activated = extension.activated.ok_or(BackendError::Invalid)?;
            if (lease.path_id, lease.role) != (activated.prepared.path_id, activated.prepared.role)
            {
                return Err(BackendError::Invalid);
            }
            (activated, extension.activated_at_unix)
        };
        let execution = self
            .extension_call(
                key,
                id,
                Action::Commit(ProbeCommitLeases {
                    route_context_id: key.context_id.to_vec(),
                    leases: vec![LeaseProbe {
                        path_id: lease.path_id,
                        role: functional_lease_role_for_wireguard(lease.role)
                            .ok_or(BackendError::Invalid)?
                            .internal_endpoint as i32,
                        expected_peer_public_key: activated.peer_public_key.to_vec(),
                        not_before_unix: at,
                    }],
                }),
                binding,
                33,
                deadline,
            )
            .await?;
        let proof = matches_probed_batch(Some(&execution), std::slice::from_ref(&activated), at)
            .and_then(|mut values| values.pop())
            .ok_or(BackendError::CleanupIncomplete)?;
        let mut state = lock_state(&self.state);
        let entry = exact_entry_mut(&mut state, key)?;
        live_extension(entry, id)?;
        entry
            .extensions
            .get_mut(&id)
            .ok_or(BackendError::CleanupIncomplete)?
            .committed = true;
        Ok(proof)
    }

    pub(super) async fn abort_extension(
        &self,
        binding: BackendBinding,
        value: AbortPathExtension,
    ) -> Result<(), BackendError> {
        let (key, id, deadline) = scope(
            binding,
            &value.route_context_id,
            &value.context_handle,
            &value.extension_id,
            BackendAction::AbortPathExtension,
        )?;
        {
            let state = lock_state(&self.state);
            let entry = exact_entry(&state, key)?;
            if entry
                .extensions
                .get(&id)
                .is_none_or(|extension| extension.aborted)
            {
                return Ok(());
            }
        }
        let execution = self
            .extension_call(
                key,
                id,
                Action::Abort(DestroyContext {
                    route_context_id: key.context_id.to_vec(),
                }),
                binding,
                34,
                deadline,
            )
            .await?;
        if execution.response.result != InternalWorkerResult::Ok as i32
            || execution.descriptor.is_some()
            || !matches!(
                execution.response.outcome,
                Some(internal_worker_response::Outcome::Destroyed(_))
            )
        {
            return Err(BackendError::CleanupIncomplete);
        }
        let mut state = lock_state(&self.state);
        let entry = exact_entry_mut(&mut state, key)?;
        let extension = entry
            .extensions
            .get_mut(&id)
            .ok_or(BackendError::CleanupIncomplete)?;
        cleanup_parent(extension, deadline)?;
        extension.committed = false;
        let path = u32::from(extension.owner.resource().key().0);
        let role = extension.owner.resource().key().1;
        entry.downlink.remove(&path);
        drop(state);
        let mut slot = self
            .accounting_state
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some(accounting) = slot.as_mut() {
            accounting
                .owner
                .unregister(
                    key.context_id,
                    u8::try_from(path).map_err(|_| BackendError::Invalid)?,
                    WireguardRole::try_from(role).map_err(|_| BackendError::Invalid)?,
                    deadline,
                )
                .map_err(|_| BackendError::CleanupIncomplete)?;
        }
        drop(slot);
        exact_entry_mut(&mut lock_state(&self.state), key)?
            .extensions
            .get_mut(&id)
            .ok_or(BackendError::CleanupIncomplete)?
            .aborted = true;
        Ok(())
    }
}

fn verify_extension_authority(
    key: OpenLineageKey,
    id: [u8; 16],
    original: &RouteIdentity,
    value: &ActivatePathExtension,
) -> Result<(), BackendError> {
    use volparossa_protocol::{RouteExtension, RouteExtensionPhase};
    let now = unix_milliseconds()?;
    let mut signature_cache = ReplayCache::new(8).map_err(|_| BackendError::Unavailable)?;
    let verified = verify_control_message::<RouteExtension>(
        &value.signed_route_extension,
        now,
        TimePolicy::default(),
        &mut signature_cache,
    )
    .map_err(|_| BackendError::Invalid)?;
    let scope = verified
        .message()
        .scope
        .as_ref()
        .ok_or(BackendError::Invalid)?;
    let parent = verify_control_message::<ExitReservation>(
        &scope.signed_exit_reservation,
        now,
        TimePolicy::default(),
        &mut signature_cache,
    )
    .map_err(|_| BackendError::Invalid)?;
    let lease = value.lease.as_ref().ok_or(BackendError::Invalid)?;
    let (relay, authority) = verify_relay_reservation(
        &lease.signed_relay_reservation,
        now,
        TimePolicy::default(),
        &mut signature_cache,
    )
    .map_err(|_| BackendError::Invalid)?;
    if verified.message().phase != RouteExtensionPhase::Authorize as i32
        || scope.extension_id.as_slice() != id
        || scope.path_id != lease.path_id
        || parent.message().route_context_id.as_slice() != key.context_id
        || parent.sender_public_key() != verified.sender_public_key()
        || authority.sender_public_key() != verified.sender_public_key()
        || verified.sender_public_key() != &original.exit_key
        || !same_parent(parent.message(), &original.authorization)
        || !same_parent(parent.message(), authority.message())
        || verified.message().hard_expires_at_ms / 1000 != key.hard_expires_at_unix
        || authority.expires_at_ms() != parent.expires_at_ms()
        || authority.message().path_id != scope.path_id
        || authority.message().relay_node_id != scope.relay_node_id
        || authority.message().relay_peer_id != scope.relay_peer_id
        || relay.message().exit_authorization != verified.message().signed_relay_authorization
        || relay.message().relay_node_id != scope.relay_node_id
        || !lease.signed_client_relay_request.is_empty()
    {
        return Err(BackendError::Invalid);
    }
    Ok(())
}

fn same_parent(parent: &ExitReservation, authority: &RelayAuthorization) -> bool {
    parent.reservation_id == authority.reservation_id
        && parent.route_context_id == authority.route_context_id
        && parent.client_session_id == authority.client_session_id
        && parent.client_session_public_key == authority.client_session_public_key
        && parent.policy_hash == authority.policy_hash
        && parent.exit_boot_id == authority.exit_boot_id
        && parent.capability_id == authority.capability_id
        && parent.exit_node_id == authority.exit_node_id
        && parent.exit_peer_id == authority.exit_peer_id
        && parent.hold_id == authority.hold_id
        && parent.finalize_id == authority.finalize_id
        && parent.control_relay_node_id == authority.control_relay_node_id
        && parent.control_relay_peer_id == authority.control_relay_peer_id
        && parent.allowed_transports == authority.allowed_transports
        && parent.reserved_up_mbps == authority.maximum_up_mbps
        && parent.reserved_down_mbps == authority.maximum_down_mbps
        && parent.expires_at_ms == authority.expires_at_ms
}

fn cleanup_parent(
    extension: &mut OpenExtension,
    deadline: HardDeadline,
) -> Result<(), BackendError> {
    if extension.birth_may_exist {
        BirthNamespaceKernel::connect(deadline)
            .map_err(|_| BackendError::CleanupIncomplete)?
            .delete_owned_wireguard(&mut extension.owner, deadline)
            .map_err(|_| BackendError::CleanupIncomplete)?;
        extension.birth_may_exist = false;
    }
    Ok(())
}

pub(super) fn cleanup_plan(entry: &OpenLeaseEntry) -> PrepareLeases {
    let mut plan = entry.prepare.clone();
    plan.leases.extend(
        entry
            .extensions
            .values()
            .flat_map(|extension| extension.prepare.leases.clone()),
    );
    plan.leases
        .sort_unstable_by_key(|lease| (lease.path_id, lease.role));
    plan
}

pub(super) fn cleanup_parent_extensions(
    entry: &mut OpenLeaseEntry,
    deadline: HardDeadline,
) -> bool {
    entry
        .extensions
        .values_mut()
        .all(|extension| cleanup_parent(extension, deadline).is_ok())
}

pub(super) fn committed_path(entry: &OpenLeaseEntry, path_id: u32, role: i32) -> bool {
    entry.extensions.values().any(|extension| {
        !extension.aborted
            && extension.committed
            && extension.activated.is_some()
            && extension.prepared.is_some()
            && extension.owner.resource().key() == (u8::try_from(path_id).unwrap_or(0), role)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use volparossa_protocol::{
        ProbeAddressFamily, RouteExtension, RouteExtensionPhase, RouteExtensionScope, Transport,
        sign_control_message,
    };
    use volparossa_test_support::SignedRouteFixture;

    #[test]
    fn path_extension_activation_requires_exact_original_parent_with_real_signatures() {
        let now = unix_milliseconds().expect("clock");
        let route = SignedRouteFixture::new(2, &[Transport::TcpMptcp], now).expect("signed route");
        let identity = original_identity(
            &[volparossa_routing::LeaseActivation {
                signed_relay_reservation: route.relay_reservations()[0].clone(),
                ..Default::default()
            }],
            now,
        )
        .expect("retained initial route");
        let parent_envelope: SignedEnvelope =
            decode_canonical(route.exit_reservation(), MAX_CONTROL_MESSAGE_SIZE).unwrap();
        let original_parent: ExitReservation =
            decode_canonical(&parent_envelope.payload, MAX_CONTROL_MESSAGE_SIZE).unwrap();
        let relay_envelope: SignedEnvelope =
            decode_canonical(&route.relay_reservations()[1], MAX_CONTROL_MESSAGE_SIZE).unwrap();
        let relay: RelayReservation =
            decode_canonical(&relay_envelope.payload, MAX_CONTROL_MESSAGE_SIZE).unwrap();
        let boot = current_boottime_nanos().expect("monotonic clock");
        let key = OpenLineageKey {
            helper_runtime_id: [1; 32],
            context_id: *route.route_context_id(),
            backend_generation: 3,
            prepare_request_id: [4; 16],
            prepare_operation_digest: [5; 32],
            setup_expires_at_unix: now / 1_000 + 20,
            hard_expires_at_unix: original_parent.expires_at_ms / 1_000,
            setup_expires_at_boottime_ns: boot + 20_000_000_000,
            hard_expires_at_boottime_ns: boot + 120_000_000_000,
        };
        let id = [37; 16];
        let extension = RouteExtension {
            scope: Some(RouteExtensionScope {
                extension_id: id.to_vec(),
                signed_exit_reservation: route.exit_reservation().to_vec(),
                finalized_bundle_hash: vec![38; 32],
                path_id: 2,
                relay_node_id: relay.relay_node_id.clone(),
                relay_peer_id: relay.relay_peer_id.clone(),
                probe_id: vec![39; 16],
                address_family: ProbeAddressFamily::Ipv4 as i32,
            }),
            phase: RouteExtensionPhase::Authorize as i32,
            signed_probe_permit: vec![1],
            signed_relay_authorization: relay.exit_authorization,
            signed_confirmation_receipt: Vec::new(),
            selected_path_ids: vec![1],
            hard_expires_at_ms: original_parent.expires_at_ms,
        };
        // This tests helper authority verification, not an executed probe or kernel path.
        let activate = |extension: &RouteExtension| ActivatePathExtension {
            route_context_id: key.context_id.to_vec(),
            context_handle: vec![40; HELPER_HANDLE_BYTES],
            extension_id: id.to_vec(),
            lease: Some(volparossa_routing::LeaseActivation {
                path_id: 2,
                role: WireguardRole::Client as i32,
                signed_relay_reservation: route.relay_reservations()[1].clone(),
                ..Default::default()
            }),
            signed_route_extension: sign_control_message(
                extension,
                route.exit_key(),
                now,
                original_parent.expires_at_ms,
                [41; 32],
                TimePolicy::default(),
            )
            .expect("signed extension"),
        };
        assert!(verify_extension_authority(key, id, &identity, &activate(&extension)).is_ok());
        let mutations: [fn(&mut ExitReservation); 5] = [
            |parent| parent.reservation_id[0] ^= 1,
            |parent| parent.hold_id[0] ^= 1,
            |parent| parent.finalize_id[0] ^= 1,
            |parent| parent.control_relay_node_id[0] ^= 1,
            |parent| parent.reserved_up_mbps += 1,
        ];
        for mutation in mutations {
            let mut parent = original_parent.clone();
            mutation(&mut parent);
            let signed = sign_control_message(
                &parent,
                route.exit_key(),
                parent.created_at_ms,
                parent.expires_at_ms,
                parent.nonce.as_slice().try_into().unwrap(),
                TimePolicy::default(),
            )
            .expect("individually valid changed parent");
            let mut changed = extension.clone();
            changed.scope.as_mut().unwrap().signed_exit_reservation = signed;
            assert!(verify_extension_authority(key, id, &identity, &activate(&changed)).is_err());
        }
    }
}
