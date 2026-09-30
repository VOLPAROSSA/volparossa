//! Additive, independently revocable path authority inside one committed context.

use std::{collections::BTreeSet, sync::Arc};
use tokio::time::Instant;

use super::{
    BackendAction, BackendBinding, BackendCall, BackendCompletion, BackendError, BackendPhase,
    BackendRequest, CleanupOutcome, ContextPhase, ContextRecord, EngineState, ExpiryNow,
    HelperEngine, HelperExecution, LeaseRecord, OperationKind, OperationOwner, ResolvedCall,
    backend_response, begin_operation, context_backend_lineage, deadline_live, execution,
    expiry_now, fixed, freeze_deadlines, invalid_response, matches_handle, phase_result,
    prepared_matches, purge_context_cache, response,
};
use volparossa_routing::{
    AbortPathExtension, ActivatePathExtension, ActivatedPathExtension, CommitPathExtension,
    CommittedLease, CommittedPathExtension, Empty, HELPER_HANDLE_BYTES, HELPER_PROTOCOL_VERSION,
    HelperRequest, HelperResult, PrepareLeaseBatch, PreparePathExtension, PreparedLease,
    PreparedPathExtension, WireguardRole, helper_request, helper_response, operation_digest,
};

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum ExtensionPhase {
    Preparing,
    Prepared,
    Activated,
    Committed,
    Quarantined,
    Aborted,
}

pub(super) struct ExtensionRecord {
    path_id: u32,
    role: i32,
    pub(super) handle: [u8; HELPER_HANDLE_BYTES],
    setup_expires_at_unix: u64,
    setup_expires_at_boottime_ns: u64,
    phase: ExtensionPhase,
    lease: Option<LeaseRecord>,
    activated_at_unix: Option<u64>,
}

impl ExtensionRecord {
    /// The exact newly activated Exit sender needs a receiver budget before its connectivity
    /// proof can run. This grants no committed route authority and never covers other leases.
    pub(super) fn allows_precommit_downlink(&self, handle: &[u8], now: ExpiryNow) -> bool {
        self.phase == ExtensionPhase::Activated
            && self.role == WireguardRole::Exit as i32
            && self.setup_live(now)
            && matches_handle(&self.handle, handle)
            && self.lease.as_ref().is_some_and(|lease| {
                matches_handle(&lease.handle, handle)
                    && lease.baseline.is_some_and(|baseline| {
                        baseline.path_id == self.path_id && baseline.role == self.role
                    })
            })
    }

    fn pending(&self) -> bool {
        !matches!(
            self.phase,
            ExtensionPhase::Committed | ExtensionPhase::Aborted
        )
    }

    fn setup_live(&self, now: ExpiryNow) -> bool {
        deadline_live(
            now,
            self.setup_expires_at_unix,
            self.setup_expires_at_boottime_ns,
        )
    }
}

#[derive(Clone, Copy)]
struct ExtensionScope {
    context_id: [u8; 16],
    context_handle: [u8; HELPER_HANDLE_BYTES],
    extension_id: [u8; 16],
}

impl ExtensionScope {
    fn parse(context: &[u8], handle: &[u8], extension: &[u8]) -> Option<Self> {
        Some(Self {
            context_id: fixed(context)?,
            context_handle: fixed(handle)?,
            extension_id: fixed(extension)?,
        })
    }

    fn abort(self) -> AbortPathExtension {
        AbortPathExtension {
            route_context_id: self.context_id.to_vec(),
            context_handle: self.context_handle.to_vec(),
            extension_id: self.extension_id.to_vec(),
        }
    }
}

type ExtensionError = (HelperResult, &'static str);

#[cfg(test)]
#[test]
fn path_extension_precommit_downlink_requires_exact_live_activated_exit_lease() {
    let now = ExpiryNow {
        unix: 130,
        boottime_ns: 130_000_000_000,
    };
    let mut extension = ExtensionRecord {
        path_id: 4,
        role: WireguardRole::Exit as i32,
        handle: [4; HELPER_HANDLE_BYTES],
        setup_expires_at_unix: 150,
        setup_expires_at_boottime_ns: 150_000_000_000,
        phase: ExtensionPhase::Activated,
        lease: Some(LeaseRecord {
            handle: [4; HELPER_HANDLE_BYTES],
            public_key: [5; 32],
            public_endpoint: volparossa_routing::PublicUdpEndpoint {
                address: vec![8, 8, 8, 8],
                port: 51820,
            },
            baseline: Some(super::KernelCounters {
                path_id: 4,
                role: WireguardRole::Exit as i32,
                latest_handshake_unix: 0,
                received_bytes: 0,
                transmitted_bytes: 0,
            }),
        }),
        activated_at_unix: Some(130),
    };
    for phase in [
        ExtensionPhase::Preparing,
        ExtensionPhase::Prepared,
        ExtensionPhase::Activated,
        ExtensionPhase::Committed,
        ExtensionPhase::Quarantined,
        ExtensionPhase::Aborted,
    ] {
        extension.phase = phase;
        assert_eq!(
            extension.allows_precommit_downlink(&[4; HELPER_HANDLE_BYTES], now),
            phase == ExtensionPhase::Activated
        );
    }
    extension.phase = ExtensionPhase::Activated;
    assert!(!extension.allows_precommit_downlink(&[5; HELPER_HANDLE_BYTES], now));
    assert!(
        !extension
            .allows_precommit_downlink(&[4; HELPER_HANDLE_BYTES], ExpiryNow { unix: 150, ..now })
    );
    assert!(!extension.allows_precommit_downlink(
        &[4; HELPER_HANDLE_BYTES],
        ExpiryNow {
            boottime_ns: 150_000_000_000,
            ..now
        }
    ));
    extension.role = WireguardRole::Client as i32;
    assert!(!extension.allows_precommit_downlink(&[4; HELPER_HANDLE_BYTES], now));
    extension.role = WireguardRole::Exit as i32;
    extension.lease.as_mut().unwrap().baseline = None;
    assert!(!extension.allows_precommit_downlink(&[4; HELPER_HANDLE_BYTES], now));
}

#[allow(
    clippy::unnecessary_wraps,
    reason = "same optional response seam as asynchronously delivered ambiguity"
)]
fn failure(request: &HelperRequest, error: ExtensionError) -> Option<HelperExecution> {
    Some(execution(response(request, error.0, error.1, None), None))
}

fn extension_context(
    state: &EngineState,
    scope: ExtensionScope,
    now: ExpiryNow,
) -> Result<&ContextRecord, ExtensionError> {
    let context = state
        .contexts
        .get(&scope.context_id)
        .ok_or((HelperResult::NotFound, "CONTEXT_ABSENT"))?;
    if !matches_handle(&context.handle, &scope.context_handle) {
        return Err((HelperResult::InvalidRequest, "CONTEXT_HANDLE_INVALID"));
    }
    if context.phase != ContextPhase::Committed {
        return Err((
            phase_result(context.phase),
            "EXTENSION_REQUIRES_COMMITTED_CONTEXT",
        ));
    }
    if !deadline_live(
        now,
        context.hard_expires_at_unix,
        context.hard_expires_at_boottime_ns,
    ) {
        return Err((HelperResult::Expired, "CONTEXT_EXPIRED"));
    }
    Ok(context)
}

fn extension_owner(
    state: &mut EngineState,
    scope: ExtensionScope,
    request_id: [u8; 16],
    digest: [u8; 32],
    deadline: Instant,
) -> Option<OperationOwner> {
    let context = state.contexts.get(&scope.context_id)?;
    let generation = context.generation;
    let lineage = context_backend_lineage(scope.context_id, context);
    begin_operation(
        state,
        request_id,
        digest,
        scope.context_id,
        generation,
        Some(ContextPhase::Committed),
        OperationKind::PathExtension,
        lineage,
        deadline,
    )
}

fn exact_extension_owner(
    state: &EngineState,
    owner: &OperationOwner,
    scope: ExtensionScope,
) -> bool {
    let token = owner.token();
    state.in_flight == Some(token)
        && state
            .contexts
            .get(&scope.context_id)
            .is_some_and(|context| {
                context.generation == token.generation
                    && context.phase == ContextPhase::Committed
                    && context_backend_lineage(scope.context_id, context) == owner.lineage()
                    && matches_handle(&context.handle, &scope.context_handle)
                    && context.extensions.contains_key(&scope.extension_id)
            })
}

impl HelperEngine {
    #[allow(clippy::too_many_lines)] // One additive PLAN/CALL/COMMIT ownership boundary.
    pub(super) async fn prepare_path_extension_async(
        &self,
        request: &HelperRequest,
        request_id: [u8; 16],
        digest: [u8; 32],
        value: &PreparePathExtension,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<HelperExecution> {
        let Some(scope) = ExtensionScope::parse(
            &value.route_context_id,
            &value.context_handle,
            &value.extension_id,
        ) else {
            return Some(execution(invalid_response(request), None));
        };
        let Some(plan) = value.lease.as_ref() else {
            return Some(execution(invalid_response(request), None));
        };
        let owner = {
            let mut state = self.inner.state.lock().await;
            let context =
                match extension_context(&state, scope, expiry_now(self.inner.clock.as_ref())) {
                    Ok(context) => context,
                    Err(error) => return failure(request, error),
                };
            if context.extensions.contains_key(&scope.extension_id)
                || context.leases.keys().any(|(path, _)| *path == plan.path_id)
                || context
                    .extensions
                    .values()
                    .any(|extension| extension.path_id == plan.path_id)
            {
                return failure(
                    request,
                    (HelperResult::AlreadyExists, "EXTENSION_IDENTITY_RETAINED"),
                );
            }
            if !matches!(
                WireguardRole::try_from(plan.role),
                Ok(WireguardRole::Client | WireguardRole::Exit)
            ) || context.leases.is_empty()
                || context.leases.keys().any(|(_, role)| *role != plan.role)
            {
                return failure(
                    request,
                    (HelperResult::InvalidRequest, "EXTENSION_ROLE_MISMATCH"),
                );
            }
            let lifetime_paths: BTreeSet<_> = context
                .leases
                .keys()
                .map(|(path, _)| *path)
                .chain(
                    context
                        .extensions
                        .values()
                        .map(|extension| extension.path_id),
                )
                .collect();
            if lifetime_paths.len() >= 8
                || context.extensions.values().any(ExtensionRecord::pending)
            {
                return failure(request, (HelperResult::Capacity, "EXTENSION_CAPACITY"));
            }
            let Some(frozen) = freeze_deadlines(
                self.inner.clock.as_ref(),
                value.setup_expires_at_unix,
                context.hard_expires_at_unix,
            ) else {
                return failure(request, (HelperResult::Expired, "EXTENSION_SETUP_EXPIRED"));
            };
            let setup_boot = frozen
                .setup_boottime_ns
                .min(context.hard_expires_at_boottime_ns);
            let Some(handle) = self.unique_handle(&state, &BTreeSet::new()) else {
                return failure(request, (HelperResult::Capacity, "HANDLE_CAPACITY"));
            };
            let Some(owner) = extension_owner(
                &mut state,
                scope,
                request_id,
                digest,
                Instant::now() + self.inner.backend_timeout,
            ) else {
                return failure(request, (HelperResult::Capacity, "OPERATION_CAPACITY"));
            };
            state
                .contexts
                .get_mut(&scope.context_id)
                .expect("reserved context")
                .extensions
                .insert(
                    scope.extension_id,
                    ExtensionRecord {
                        path_id: plan.path_id,
                        role: plan.role,
                        handle,
                        setup_expires_at_unix: value.setup_expires_at_unix,
                        setup_expires_at_boottime_ns: setup_boot,
                        phase: ExtensionPhase::Preparing,
                        lease: None,
                        activated_at_unix: None,
                    },
                );
            owner
        };
        let binding = BackendBinding::for_owner(
            &owner,
            BackendPhase::Committed,
            BackendAction::PreparePathExtension,
            owner.call_deadline(),
        );
        let backend = Arc::clone(&self.inner.backend);
        let call = BackendRequest::new(binding, value.clone());
        let result = self
            .call_backend(binding.call_deadline, move || {
                backend.prepare_path_extension(call)
            })
            .await;
        let (owner, prepared) = match self
            .resolve_extension_call(result, owner, binding, scope, request, sender)
            .await?
        {
            ResolvedCall::Definite {
                owner,
                result: Ok(value),
            } => (*owner, value),
            ResolvedCall::Definite {
                owner,
                result: Err(error),
            } => {
                return self
                    .extension_failure(*owner, scope, request, sender, error, true)
                    .await;
            }
            ResolvedCall::Ambiguous => {
                return failure(
                    request,
                    (
                        HelperResult::CleanupIncomplete,
                        "EXTENSION_RESULT_AMBIGUOUS",
                    ),
                );
            }
        };
        let proof_request = PrepareLeaseBatch {
            leases: vec![plan.clone()],
            traversal_hints: value.traversal_hints.clone(),
            ..PrepareLeaseBatch::default()
        };
        let mut state = self.inner.state.lock().await;
        let now = expiry_now(self.inner.clock.as_ref());
        let valid = exact_extension_owner(&state, &owner, scope)
            && prepared_matches(&proof_request, std::slice::from_ref(&prepared))
            && extension_context(&state, scope, now).is_ok_and(|context| {
                let extension = &context.extensions[&scope.extension_id];
                extension.phase == ExtensionPhase::Preparing
                    && extension.setup_live(now)
                    && context.leases.values().all(|lease| {
                        lease.public_key != prepared.public_key
                            && lease.public_endpoint != prepared.public_endpoint
                    })
            });
        if !valid {
            drop(state);
            return self
                .extension_failure(
                    owner,
                    scope,
                    request,
                    sender,
                    BackendError::CleanupIncomplete,
                    false,
                )
                .await;
        }
        let extension = state
            .contexts
            .get_mut(&scope.context_id)
            .expect("exact context")
            .extensions
            .get_mut(&scope.extension_id)
            .expect("exact extension");
        extension.phase = ExtensionPhase::Prepared;
        extension.lease = Some(LeaseRecord {
            handle: extension.handle,
            public_key: prepared.public_key,
            public_endpoint: prepared.public_endpoint.clone(),
            baseline: None,
        });
        let output = PreparedPathExtension {
            context_handle: scope.context_handle.to_vec(),
            extension_id: scope.extension_id.to_vec(),
            lease: Some(PreparedLease {
                lease_handle: extension.handle.to_vec(),
                path_id: prepared.path_id,
                role: prepared.role,
                public_key: prepared.public_key.to_vec(),
                public_endpoint: Some(prepared.public_endpoint),
                underlay_evidence: prepared.evidence as i32,
            }),
        };
        state.in_flight = None;
        drop(state);
        let _ = owner.settle();
        Some(execution(
            response(
                request,
                HelperResult::Ok,
                "PATH_EXTENSION_PREPARED",
                Some(helper_response::Outcome::PreparedPathExtension(output)),
            ),
            None,
        ))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one additive PLAN/CALL/COMMIT ownership boundary"
    )]
    pub(super) async fn activate_path_extension_async(
        &self,
        request: &HelperRequest,
        request_id: [u8; 16],
        digest: [u8; 32],
        value: &ActivatePathExtension,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<HelperExecution> {
        let Some(scope) = ExtensionScope::parse(
            &value.route_context_id,
            &value.context_handle,
            &value.extension_id,
        ) else {
            return Some(execution(invalid_response(request), None));
        };
        let Some(activation) = value.lease.as_ref() else {
            return Some(execution(invalid_response(request), None));
        };
        let (owner, started_at) = {
            let mut state = self.inner.state.lock().await;
            let now = expiry_now(self.inner.clock.as_ref());
            let context = match extension_context(&state, scope, now) {
                Ok(v) => v,
                Err(e) => return failure(request, e),
            };
            let Some(extension) = context.extensions.get(&scope.extension_id) else {
                return failure(request, (HelperResult::NotFound, "EXTENSION_ABSENT"));
            };
            let valid = extension.phase == ExtensionPhase::Prepared
                && extension.setup_live(now)
                && (activation.path_id, activation.role) == (extension.path_id, extension.role)
                && extension.lease.as_ref().is_some_and(|lease| {
                    matches_handle(&lease.handle, &activation.lease_handle)
                        && activation.peer_public_key.as_slice() != lease.public_key
                        && activation
                            .peer_endpoint
                            .as_ref()
                            .is_some_and(|endpoint| *endpoint != lease.public_endpoint)
                });
            if !valid {
                return failure(
                    request,
                    (
                        HelperResult::InvalidRequest,
                        "EXTENSION_ACTIVATION_MISMATCH",
                    ),
                );
            }
            let Some(owner) = extension_owner(
                &mut state,
                scope,
                request_id,
                digest,
                Instant::now() + self.inner.backend_timeout,
            ) else {
                return failure(request, (HelperResult::Capacity, "OPERATION_CAPACITY"));
            };
            (owner, now.unix)
        };
        let binding = BackendBinding::for_owner(
            &owner,
            BackendPhase::Committed,
            BackendAction::ActivatePathExtension,
            owner.call_deadline(),
        );
        let backend = Arc::clone(&self.inner.backend);
        let call = BackendRequest::new(binding, value.clone());
        let result = self
            .call_backend(binding.call_deadline, move || {
                backend.activate_path_extension(call)
            })
            .await;
        let (owner, baseline) = match self
            .resolve_extension_call(result, owner, binding, scope, request, sender)
            .await?
        {
            ResolvedCall::Definite {
                owner,
                result: Ok(value),
            } => (*owner, value),
            ResolvedCall::Definite {
                owner,
                result: Err(error),
            } => {
                return self
                    .extension_failure(*owner, scope, request, sender, error, false)
                    .await;
            }
            ResolvedCall::Ambiguous => {
                return failure(
                    request,
                    (
                        HelperResult::CleanupIncomplete,
                        "EXTENSION_RESULT_AMBIGUOUS",
                    ),
                );
            }
        };
        let mut state = self.inner.state.lock().await;
        let now = expiry_now(self.inner.clock.as_ref());
        let valid = exact_extension_owner(&state, &owner, scope)
            && extension_context(&state, scope, now).is_ok_and(|context| {
                let extension = &context.extensions[&scope.extension_id];
                extension.phase == ExtensionPhase::Prepared
                    && extension.setup_live(now)
                    && (baseline.path_id, baseline.role) == (extension.path_id, extension.role)
            });
        if !valid {
            drop(state);
            return self
                .extension_failure(
                    owner,
                    scope,
                    request,
                    sender,
                    BackendError::CleanupIncomplete,
                    false,
                )
                .await;
        }
        let extension = state
            .contexts
            .get_mut(&scope.context_id)
            .expect("exact context")
            .extensions
            .get_mut(&scope.extension_id)
            .expect("exact extension");
        extension.phase = ExtensionPhase::Activated;
        extension.activated_at_unix = Some(started_at);
        extension.lease.as_mut().expect("prepared lease").baseline = Some(baseline);
        let output = ActivatedPathExtension {
            context_handle: scope.context_handle.to_vec(),
            extension_id: scope.extension_id.to_vec(),
            lease_handle: extension.handle.to_vec(),
        };
        state.in_flight = None;
        drop(state);
        let _ = owner.settle();
        Some(execution(
            response(
                request,
                HelperResult::Ok,
                "PATH_EXTENSION_ACTIVATED",
                Some(helper_response::Outcome::ActivatedPathExtension(output)),
            ),
            None,
        ))
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one additive PLAN/CALL/COMMIT ownership boundary"
    )]
    pub(super) async fn commit_path_extension_async(
        &self,
        request: &HelperRequest,
        request_id: [u8; 16],
        digest: [u8; 32],
        value: &CommitPathExtension,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<HelperExecution> {
        let Some(scope) = ExtensionScope::parse(
            &value.route_context_id,
            &value.context_handle,
            &value.extension_id,
        ) else {
            return Some(execution(invalid_response(request), None));
        };
        let Some(commit) = value.lease.as_ref() else {
            return Some(execution(invalid_response(request), None));
        };
        let owner = {
            let mut state = self.inner.state.lock().await;
            let now = expiry_now(self.inner.clock.as_ref());
            let context = match extension_context(&state, scope, now) {
                Ok(v) => v,
                Err(e) => return failure(request, e),
            };
            let Some(extension) = context.extensions.get(&scope.extension_id) else {
                return failure(request, (HelperResult::NotFound, "EXTENSION_ABSENT"));
            };
            if extension.phase != ExtensionPhase::Activated
                || !extension.setup_live(now)
                || (commit.path_id, commit.role) != (extension.path_id, extension.role)
                || !matches_handle(&extension.handle, &commit.lease_handle)
            {
                return failure(
                    request,
                    (HelperResult::InvalidRequest, "EXTENSION_COMMIT_MISMATCH"),
                );
            }
            let Some(owner) = extension_owner(
                &mut state,
                scope,
                request_id,
                digest,
                Instant::now() + self.inner.backend_timeout,
            ) else {
                return failure(request, (HelperResult::Capacity, "OPERATION_CAPACITY"));
            };
            owner
        };
        let binding = BackendBinding::for_owner(
            &owner,
            BackendPhase::Committed,
            BackendAction::CommitPathExtension,
            owner.call_deadline(),
        );
        let backend = Arc::clone(&self.inner.backend);
        let call = BackendRequest::new(binding, value.clone());
        let result = self
            .call_backend(binding.call_deadline, move || {
                backend.commit_path_extension(call)
            })
            .await;
        let (owner, proof) = match self
            .resolve_extension_call(result, owner, binding, scope, request, sender)
            .await?
        {
            ResolvedCall::Definite {
                owner,
                result: Ok(value),
            } => (*owner, value),
            ResolvedCall::Definite {
                owner,
                result: Err(error),
            } => {
                return self
                    .extension_failure(*owner, scope, request, sender, error, false)
                    .await;
            }
            ResolvedCall::Ambiguous => {
                return failure(
                    request,
                    (
                        HelperResult::CleanupIncomplete,
                        "EXTENSION_RESULT_AMBIGUOUS",
                    ),
                );
            }
        };
        let mut state = self.inner.state.lock().await;
        let now = expiry_now(self.inner.clock.as_ref());
        let valid = exact_extension_owner(&state, &owner, scope)
            && extension_context(&state, scope, now).is_ok_and(|context| {
                let extension = &context.extensions[&scope.extension_id];
                extension.phase == ExtensionPhase::Activated
                    && extension.setup_live(now)
                    && (proof.path_id, proof.role) == (extension.path_id, extension.role)
                    && extension
                        .lease
                        .as_ref()
                        .and_then(|lease| lease.baseline)
                        .is_some_and(|baseline| {
                            proof.latest_handshake_unix
                                >= extension.activated_at_unix.unwrap_or(u64::MAX)
                                && proof.latest_handshake_unix >= baseline.latest_handshake_unix
                                && proof.received_bytes > baseline.received_bytes
                                && proof.transmitted_bytes > baseline.transmitted_bytes
                        })
            });
        if !valid {
            drop(state);
            return self
                .extension_failure(
                    owner,
                    scope,
                    request,
                    sender,
                    BackendError::CleanupIncomplete,
                    false,
                )
                .await;
        }
        let context = state
            .contexts
            .get_mut(&scope.context_id)
            .expect("exact context");
        let extension = context
            .extensions
            .get_mut(&scope.extension_id)
            .expect("exact extension");
        extension.phase = ExtensionPhase::Committed;
        let lease = extension.lease.as_ref().expect("activated lease").clone();
        let output = CommittedPathExtension {
            context_handle: scope.context_handle.to_vec(),
            extension_id: scope.extension_id.to_vec(),
            lease: Some(CommittedLease {
                lease_handle: lease.handle.to_vec(),
                latest_handshake_unix: proof.latest_handshake_unix,
                received_bytes: proof.received_bytes,
                transmitted_bytes: proof.transmitted_bytes,
            }),
        };
        context
            .leases
            .insert((extension.path_id, extension.role), lease);
        state.in_flight = None;
        drop(state);
        let _ = owner.settle();
        Some(execution(
            response(
                request,
                HelperResult::Ok,
                "PATH_EXTENSION_COMMITTED",
                Some(helper_response::Outcome::CommittedPathExtension(output)),
            ),
            None,
        ))
    }

    pub(super) async fn abort_path_extension_async(
        &self,
        request: &HelperRequest,
        request_id: [u8; 16],
        digest: [u8; 32],
        value: &AbortPathExtension,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<HelperExecution> {
        let Some(scope) = ExtensionScope::parse(
            &value.route_context_id,
            &value.context_handle,
            &value.extension_id,
        ) else {
            return Some(execution(invalid_response(request), None));
        };
        let owner = {
            let mut state = self.inner.state.lock().await;
            let context =
                match extension_context(&state, scope, expiry_now(self.inner.clock.as_ref())) {
                    Ok(v) => v,
                    Err(e) => return failure(request, e),
                };
            let Some(extension) = context.extensions.get(&scope.extension_id) else {
                return failure(request, (HelperResult::NotFound, "EXTENSION_ABSENT"));
            };
            if extension.phase == ExtensionPhase::Aborted {
                return Some(execution(
                    response(
                        request,
                        HelperResult::Ok,
                        "PATH_EXTENSION_ABORTED",
                        Some(helper_response::Outcome::Empty(Empty {})),
                    ),
                    None,
                ));
            }
            let Some(owner) = extension_owner(
                &mut state,
                scope,
                request_id,
                digest,
                Instant::now() + self.inner.backend_timeout,
            ) else {
                return failure(request, (HelperResult::Capacity, "OPERATION_CAPACITY"));
            };
            owner
        };
        let outcome = self
            .abort_extension_owned(owner, scope, request, sender)
            .await;
        if outcome.response_sent {
            return None;
        }
        if !outcome.confirmed {
            return failure(
                request,
                (
                    HelperResult::CleanupIncomplete,
                    "EXTENSION_CLEANUP_INCOMPLETE",
                ),
            );
        }
        Some(execution(
            response(
                request,
                HelperResult::Ok,
                "PATH_EXTENSION_ABORTED",
                Some(helper_response::Outcome::Empty(Empty {})),
            ),
            None,
        ))
    }

    async fn extension_failure(
        &self,
        owner: OperationOwner,
        scope: ExtensionScope,
        request: &HelperRequest,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
        error: BackendError,
        failed_prepare: bool,
    ) -> Option<HelperExecution> {
        if error == BackendError::CleanupIncomplete {
            let cleanup = self
                .abort_extension_owned(owner, scope, request, sender)
                .await;
            if cleanup.response_sent {
                return None;
            }
            return failure(
                request,
                (
                    HelperResult::CleanupIncomplete,
                    if cleanup.confirmed {
                        "EXTENSION_FAILED_AND_ABORTED"
                    } else {
                        "EXTENSION_CLEANUP_INCOMPLETE"
                    },
                ),
            );
        }
        if failed_prepare {
            let mut state = self.inner.state.lock().await;
            if exact_extension_owner(&state, &owner, scope) {
                state
                    .contexts
                    .get_mut(&scope.context_id)
                    .expect("exact context")
                    .extensions
                    .get_mut(&scope.extension_id)
                    .expect("exact extension")
                    .phase = ExtensionPhase::Aborted;
            }
        }
        self.clear_operation(owner).await;
        Some(execution(
            backend_response(request, error, "PATH_EXTENSION_FAILED"),
            None,
        ))
    }

    async fn resolve_extension_call<T: Send + 'static>(
        &self,
        call: BackendCall<BackendCompletion<T>>,
        owner: OperationOwner,
        binding: BackendBinding,
        scope: ExtensionScope,
        request: &HelperRequest,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> Option<ResolvedCall<T>> {
        match call {
            BackendCall::Complete(completion) if completion.binding == binding => {
                return Some(ResolvedCall::Definite {
                    owner: Box::new(owner),
                    result: completion.result,
                });
            }
            BackendCall::TimedOut(task) => {
                self.send_ambiguous(request, sender).await;
                if let Ok(completion) = task.await {
                    drop(completion);
                }
                let _ = self
                    .abort_extension_owned(owner, scope, request, sender)
                    .await;
                return None;
            }
            BackendCall::Complete(completion) => drop(completion),
            BackendCall::Ambiguous => {}
        }
        let cleanup = self
            .abort_extension_owned(owner, scope, request, sender)
            .await;
        (!cleanup.response_sent).then_some(ResolvedCall::Ambiguous)
    }

    async fn abort_extension_owned(
        &self,
        owner: OperationOwner,
        scope: ExtensionScope,
        request: &HelperRequest,
        sender: &mut Option<tokio::sync::oneshot::Sender<HelperExecution>>,
    ) -> CleanupOutcome {
        let safe = {
            let mut state = self.inner.state.lock().await;
            let safe = exact_extension_owner(&state, &owner, scope);
            if safe {
                let context = state
                    .contexts
                    .get_mut(&scope.context_id)
                    .expect("exact context");
                let extension = context
                    .extensions
                    .get_mut(&scope.extension_id)
                    .expect("exact extension");
                extension.phase = ExtensionPhase::Quarantined;
                context.leases.remove(&(extension.path_id, extension.role));
                purge_context_cache(&mut state, scope.context_id);
            }
            safe
        };
        if !safe {
            self.clear_operation(owner).await;
            return CleanupOutcome {
                confirmed: false,
                response_sent: false,
            };
        }
        let binding = BackendBinding::for_owner(
            &owner,
            BackendPhase::Committed,
            BackendAction::AbortPathExtension,
            Instant::now() + self.inner.backend_timeout,
        );
        let backend = Arc::clone(&self.inner.backend);
        let call = BackendRequest::new(binding, scope.abort());
        let (confirmed, response_sent) = match self
            .call_backend(binding.call_deadline, move || {
                backend.abort_path_extension(call)
            })
            .await
        {
            BackendCall::Complete(completion) => (
                completion.binding == binding && completion.result.is_ok(),
                false,
            ),
            BackendCall::Ambiguous => (false, false),
            BackendCall::TimedOut(task) => {
                self.send_ambiguous(request, sender).await;
                (
                    matches!(task.await, Ok(BackendCompletion { binding: actual, result: Ok(()) }) if actual == binding),
                    true,
                )
            }
        };
        let mut state = self.inner.state.lock().await;
        let exact = exact_extension_owner(&state, &owner, scope);
        if exact {
            if confirmed {
                let extension = state
                    .contexts
                    .get_mut(&scope.context_id)
                    .expect("exact context")
                    .extensions
                    .get_mut(&scope.extension_id)
                    .expect("exact extension");
                extension.phase = ExtensionPhase::Aborted;
                extension.lease = None;
            }
            state.in_flight = None;
            purge_context_cache(&mut state, scope.context_id);
        }
        drop(state);
        let _ = owner.settle();
        CleanupOutcome {
            confirmed: confirmed && exact,
            response_sent,
        }
    }

    /// Maintenance revokes only expired/pending extension leases, not the old live paths.
    pub(super) async fn reap_path_extensions(&self) -> bool {
        loop {
            let candidate = {
                let state = self.inner.state.lock().await;
                let now = expiry_now(self.inner.clock.as_ref());
                state.contexts.iter().find_map(|(context_id, context)| {
                    if context.phase != ContextPhase::Committed {
                        return None;
                    }
                    context
                        .extensions
                        .iter()
                        .find_map(|(extension_id, extension)| {
                            (extension.phase == ExtensionPhase::Quarantined
                                || extension.pending() && !extension.setup_live(now))
                            .then_some(ExtensionScope {
                                context_id: *context_id,
                                context_handle: context.handle,
                                extension_id: *extension_id,
                            })
                        })
                })
            };
            let Some(scope) = candidate else {
                return true;
            };
            let mut hasher = blake3::Hasher::new();
            hasher.update(b"VOLPAROSSA path-extension reap v1");
            hasher.update(&self.inner.runtime_id);
            hasher.update(&scope.context_id);
            hasher.update(&scope.extension_id);
            let request_id: [u8; 16] = hasher.finalize().as_bytes()[..16]
                .try_into()
                .expect("fixed digest");
            let request = HelperRequest {
                protocol_version: HELPER_PROTOCOL_VERSION,
                request_id: request_id.to_vec(),
                operation: Some(helper_request::Operation::AbortPathExtension(scope.abort())),
            };
            let Ok(digest) = operation_digest(&request) else {
                return false;
            };
            let result = self
                .abort_path_extension_async(&request, request_id, digest, &scope.abort(), &mut None)
                .await;
            if result.is_none_or(|value| value.response.result != HelperResult::Ok as i32) {
                return false;
            }
        }
    }
}
