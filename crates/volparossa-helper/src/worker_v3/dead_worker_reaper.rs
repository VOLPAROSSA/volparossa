//! One-shot namespace cleanup for an exactly reaped functional worker.
//!
//! The ordinary worker remains the sole owner of live lifecycle operations. This fixed self-exec
//! child is used only after the parent has proven that exact worker generation absent while PID 1
//! still retains its anonymous network namespace. It accepts one canonical staged resource plan
//! and one credential-bound namespace descriptor, enters that namespace, removes only the exact
//! helper-derived resources, and exits. No agent request can select this entry directly.

use std::{
    io,
    os::fd::{BorrowedFd, OwnedFd},
    process::{Child, Command, Stdio},
};

use nix::{
    sched::{CloneFlags, setns},
    sys::{prctl, signal::Signal},
    unistd::{getegid, geteuid, getppid},
};
use socket2::Socket;
use thiserror::Error;
use volparossa_linux_uapi::install_close_range_on_exec;
use volparossa_routing::ContextRole;

use crate::{
    deadline::HardDeadline,
    internal_protocol::{
        ContextDestroyed, INTERNAL_WORKER_MAGIC, INTERNAL_WORKER_PROTOCOL_VERSION,
        InitialiseContext, InternalWorkerRequest, InternalWorkerResponse, InternalWorkerResult,
        MAX_INTERNAL_WORKER_FRAME, PrepareLeases, decode_request, decode_response, encode_request,
        encode_response, internal_worker_request, internal_worker_response,
    },
    kernel::NamespaceKernel,
    worker_sandbox::current_network_namespace_identity,
    worker_transport::{
        ExpectedUnixCredentials, private_credential_worker_channel,
        receive_credential_fd_record_with_deadline, receive_credential_record_with_deadline,
        send_credential_fd_record_with_deadline, send_credential_record_with_deadline,
    },
};

use super::{relay_fence, routing_context_role, validate_worker_prepare};

pub(crate) const INTERNAL_DEAD_WORKER_REAPER_ARGUMENT: &str = "--internal-dead-worker-reaper-v1";

const READY_RECORD: &[u8; 31] = b"volparossa/dead-reaper/ready-v1";
const REQUEST_ID_DOMAIN: &[u8] = b"VOLPAROSSA dead worker cleanup request v1";

#[derive(Debug, Error)]
pub(super) enum DeadWorkerReaperError {
    #[error("dead-worker cleanup plan was rejected")]
    Invalid,
    #[error("dead-worker cleanup authentication failed")]
    Authentication,
    #[error("dead-worker namespace cleanup remained incomplete")]
    CleanupIncomplete,
    #[error("dead-worker cleanup I/O failed")]
    Io(#[from] io::Error),
}

/// Complete parent-owned input for one dead worker's fixed cleanup child.
#[derive(Clone)]
pub(super) struct DeadWorkerCleanupPlan {
    context_id: [u8; 16],
    context_role: ContextRole,
    prepare: PrepareLeases,
}

impl DeadWorkerCleanupPlan {
    pub(super) fn new(
        context_id: [u8; 16],
        context_role: ContextRole,
        prepare: PrepareLeases,
    ) -> Result<Self, DeadWorkerReaperError> {
        if context_id.iter().all(|byte| *byte == 0)
            || matches!(context_role, ContextRole::Unspecified)
            || prepare.route_context_id.as_slice() != context_id
        {
            return Err(DeadWorkerReaperError::Invalid);
        }
        Ok(Self {
            context_id,
            context_role,
            prepare,
        })
    }

    fn request(&self) -> Result<InternalWorkerRequest, DeadWorkerReaperError> {
        let context_role = match self.context_role {
            ContextRole::Client => crate::internal_protocol::InternalContextRole::Client,
            ContextRole::Relay => crate::internal_protocol::InternalContextRole::Relay,
            ContextRole::Exit => crate::internal_protocol::InternalContextRole::Exit,
            ContextRole::Unspecified => return Err(DeadWorkerReaperError::Invalid),
        };
        let mut hasher = blake3::Hasher::new();
        hasher.update(REQUEST_ID_DOMAIN);
        hasher.update(&self.context_id);
        hasher.update(&(self.context_role as i32).to_be_bytes());
        let request_id: [u8; 16] = hasher.finalize().as_bytes()[..16]
            .try_into()
            .map_err(|_| DeadWorkerReaperError::Invalid)?;
        Ok(InternalWorkerRequest {
            protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
            magic: INTERNAL_WORKER_MAGIC.to_vec(),
            request_id: request_id.to_vec(),
            operation: Some(internal_worker_request::Operation::Initialise(
                InitialiseContext {
                    route_context_id: self.context_id.to_vec(),
                    role: context_role as i32,
                    mptcp_accepted_addrs: 0,
                    mptcp_subflows: 0,
                    prepare: Some(self.prepare.clone()),
                },
            )),
        })
    }
}

/// Affine proof that the fixed child removed and re-observed the exact namespace resource set.
#[must_use = "dead-worker namespace cleanup proof must join durable settlement"]
pub(super) struct ExactDeadWorkerNamespaceCleanup {
    context_id: [u8; 16],
}

impl ExactDeadWorkerNamespaceCleanup {
    pub(super) fn matches_context(&self, context_id: [u8; 16]) -> bool {
        self.context_id == context_id
    }

    #[cfg(test)]
    pub(super) const fn for_test(context_id: [u8; 16]) -> Self {
        Self { context_id }
    }
}

pub(super) trait DeadWorkerNamespaceReaper: Send + Sync {
    fn cleanup(
        &self,
        plan: &DeadWorkerCleanupPlan,
        network_namespace: BorrowedFd<'_>,
        deadline: HardDeadline,
    ) -> Result<ExactDeadWorkerNamespaceCleanup, DeadWorkerReaperError>;
}

pub(super) struct ProductionDeadWorkerNamespaceReaper;

impl DeadWorkerNamespaceReaper for ProductionDeadWorkerNamespaceReaper {
    fn cleanup(
        &self,
        plan: &DeadWorkerCleanupPlan,
        network_namespace: BorrowedFd<'_>,
        deadline: HardDeadline,
    ) -> Result<ExactDeadWorkerNamespaceCleanup, DeadWorkerReaperError> {
        execute(plan, network_namespace, deadline)
    }
}

fn execute(
    plan: &DeadWorkerCleanupPlan,
    network_namespace: BorrowedFd<'_>,
    deadline: HardDeadline,
) -> Result<ExactDeadWorkerNamespaceCleanup, DeadWorkerReaperError> {
    deadline.ensure_remaining()?;
    if !geteuid().is_root() {
        return Err(DeadWorkerReaperError::Authentication);
    }
    let request = plan.request()?;
    let encoded = encode_request(&request).map_err(|_| DeadWorkerReaperError::Invalid)?;
    let descriptor_binding = *blake3::hash(encoded.as_slice()).as_bytes();
    let (parent, child_channel) = private_credential_worker_channel()?;
    let inherited: OwnedFd = child_channel.into();
    let mut command = Command::new("/proc/self/exe");
    command
        .arg(INTERNAL_DEAD_WORKER_REAPER_ARGUMENT)
        .env_clear()
        .current_dir("/")
        .stdin(Stdio::from(inherited))
        .stdout(Stdio::null())
        .stderr(Stdio::null());
    install_close_range_on_exec(&mut command);
    let mut child = command.spawn()?;
    let expected_child = ExpectedUnixCredentials::new(child.id(), 0, getegid().as_raw())?;
    let operation = parent_protocol(
        &parent,
        &request,
        encoded.as_slice(),
        descriptor_binding,
        network_namespace,
        expected_child,
        deadline,
    );
    drop(parent);
    finish_child(&mut child, operation.is_err())?;
    operation?;
    Ok(ExactDeadWorkerNamespaceCleanup {
        context_id: plan.context_id,
    })
}

fn parent_protocol(
    channel: &Socket,
    request: &InternalWorkerRequest,
    encoded_request: &[u8],
    descriptor_binding: [u8; 32],
    network_namespace: BorrowedFd<'_>,
    expected_child: ExpectedUnixCredentials,
    deadline: HardDeadline,
) -> Result<(), DeadWorkerReaperError> {
    let ready = receive_credential_record_with_deadline(
        channel,
        READY_RECORD.len(),
        expected_child,
        deadline,
    )?;
    if ready != READY_RECORD {
        return Err(DeadWorkerReaperError::Authentication);
    }
    send_credential_record_with_deadline(channel, encoded_request, deadline)?;
    send_credential_fd_record_with_deadline(
        channel,
        &network_namespace,
        &descriptor_binding,
        deadline,
    )?;
    let response = receive_credential_record_with_deadline(
        channel,
        MAX_INTERNAL_WORKER_FRAME,
        expected_child,
        deadline,
    )?;
    let response = decode_response(&response).map_err(|_| DeadWorkerReaperError::Authentication)?;
    let expected_digest = blake3::hash(encoded_request);
    if response.request_id != request.request_id
        || response.request_digest.as_slice() != expected_digest.as_bytes()
        || response.result != InternalWorkerResult::Ok as i32
        || !matches!(
            response.outcome,
            Some(internal_worker_response::Outcome::Destroyed(
                ContextDestroyed {}
            ))
        )
    {
        return Err(DeadWorkerReaperError::CleanupIncomplete);
    }
    Ok(())
}

fn finish_child(child: &mut Child, terminate: bool) -> Result<(), DeadWorkerReaperError> {
    if terminate {
        match child.kill() {
            Ok(()) => {}
            Err(error) if error.kind() == io::ErrorKind::InvalidInput => {}
            Err(error) => return Err(DeadWorkerReaperError::Io(error)),
        }
    }
    let status = child.wait()?;
    if terminate || !status.success() {
        Err(DeadWorkerReaperError::CleanupIncomplete)
    } else {
        Ok(())
    }
}

/// Fixed child selector used only by the root helper's private self-exec protocol.
pub(crate) fn run_internal_dead_worker_reaper_entry() -> bool {
    geteuid().is_root() && run_child().is_ok()
}

fn run_child() -> Result<(), DeadWorkerReaperError> {
    let (channel, initial_parent, _child_pid, parent_network_namespace) =
        super::prepare_child_channel(0).map_err(|_| DeadWorkerReaperError::Authentication)?;
    crate::worker_transport::enable_passcred_receiver(&channel)?;
    prctl::set_pdeathsig(Some(Signal::SIGKILL))
        .map_err(|_| DeadWorkerReaperError::Authentication)?;
    if getppid().as_raw() != initial_parent {
        return Err(DeadWorkerReaperError::Authentication);
    }
    let parent_pid =
        u32::try_from(initial_parent).map_err(|_| DeadWorkerReaperError::Authentication)?;
    let expected_parent = ExpectedUnixCredentials::new(parent_pid, 0, getegid().as_raw())?;
    send_credential_record_with_deadline(
        &channel,
        READY_RECORD,
        HardDeadline::after(super::SPAWN_TIMEOUT)?,
    )?;
    let encoded = receive_credential_record_with_deadline(
        &channel,
        MAX_INTERNAL_WORKER_FRAME,
        expected_parent,
        HardDeadline::after(super::SPAWN_TIMEOUT)?,
    )?;
    let request = decode_request(&encoded).map_err(|_| DeadWorkerReaperError::Invalid)?;
    let deadline = HardDeadline::after(super::SPAWN_TIMEOUT)?;
    let binding = *blake3::hash(&encoded).as_bytes();
    let namespace =
        receive_credential_fd_record_with_deadline(&channel, &binding, expected_parent, deadline)?;
    setns(&namespace, CloneFlags::CLONE_NEWNET)
        .map_err(|_| DeadWorkerReaperError::Authentication)?;
    drop(namespace);
    let target_network_namespace =
        current_network_namespace_identity().map_err(|_| DeadWorkerReaperError::Authentication)?;
    if target_network_namespace == parent_network_namespace || getppid().as_raw() != initial_parent
    {
        return Err(DeadWorkerReaperError::Authentication);
    }
    prctl::set_dumpable(false).map_err(|_| DeadWorkerReaperError::Authentication)?;

    cleanup_request(
        &request,
        parent_network_namespace,
        target_network_namespace,
        deadline,
    )?;
    let response = cleanup_response(&request)?;
    let encoded_response =
        encode_response(&response).map_err(|_| DeadWorkerReaperError::Invalid)?;
    send_credential_record_with_deadline(&channel, encoded_response.as_slice(), deadline)?;
    Ok(())
}

fn cleanup_response(
    request: &InternalWorkerRequest,
) -> Result<InternalWorkerResponse, DeadWorkerReaperError> {
    let encoded = encode_request(request).map_err(|_| DeadWorkerReaperError::Invalid)?;
    Ok(InternalWorkerResponse {
        protocol_version: INTERNAL_WORKER_PROTOCOL_VERSION,
        magic: INTERNAL_WORKER_MAGIC.to_vec(),
        request_id: request.request_id.clone(),
        result: InternalWorkerResult::Ok as i32,
        request_digest: blake3::hash(encoded.as_slice()).as_bytes().to_vec(),
        outcome: Some(internal_worker_response::Outcome::Destroyed(
            ContextDestroyed {},
        )),
    })
}

fn cleanup_request(
    request: &InternalWorkerRequest,
    parent_network_namespace: crate::worker_sandbox::NetworkNamespaceIdentity,
    target_network_namespace: crate::worker_sandbox::NetworkNamespaceIdentity,
    deadline: HardDeadline,
) -> Result<(), DeadWorkerReaperError> {
    let Some(internal_worker_request::Operation::Initialise(initialise)) =
        request.operation.as_ref()
    else {
        return Err(DeadWorkerReaperError::Invalid);
    };
    let context_id: [u8; 16] = initialise
        .route_context_id
        .as_slice()
        .try_into()
        .map_err(|_| DeadWorkerReaperError::Invalid)?;
    let context_role =
        routing_context_role(initialise.role).ok_or(DeadWorkerReaperError::Invalid)?;
    let prepare = initialise
        .prepare
        .as_ref()
        .ok_or(DeadWorkerReaperError::Invalid)?;
    let resources = validate_worker_prepare(prepare, context_id, context_role)
        .ok_or(DeadWorkerReaperError::Invalid)?;
    let namespace = relay_fence::RelayFenceNamespaceAuthority::new(
        parent_network_namespace,
        target_network_namespace,
    )
    .map_err(|_| DeadWorkerReaperError::Authentication)?;
    match context_role {
        ContextRole::Relay => {
            let path_id = resources
                .first()
                .map(|resource| u32::from(resource.key().0))
                .ok_or(DeadWorkerReaperError::Invalid)?;
            let identity = relay_fence::RelayFenceIdentity::derive(context_id, path_id)
                .map_err(|_| DeadWorkerReaperError::Invalid)?;
            relay_fence::cleanup_dead_worker_relay_fence(namespace, &identity, deadline)
                .map_err(|_| DeadWorkerReaperError::CleanupIncomplete)?;
        }
        ContextRole::Client | ContextRole::Exit => {
            let pristine = relay_fence::observe_pristine_relay_fence(namespace, deadline)
                .map_err(|_| DeadWorkerReaperError::CleanupIncomplete)?;
            drop(pristine);
        }
        ContextRole::Unspecified => return Err(DeadWorkerReaperError::Invalid),
    }
    let mut kernel =
        NamespaceKernel::connect(deadline).map_err(|_| DeadWorkerReaperError::CleanupIncomplete)?;
    for resource in resources.iter().rev() {
        let _ = kernel.delete_exact_owned_wireguard_v3(resource, deadline);
    }
    for resource in resources.iter().rev() {
        kernel
            .prove_wireguard_absent_v3(resource, deadline)
            .map_err(|_| DeadWorkerReaperError::CleanupIncomplete)?;
    }
    deadline.ensure_remaining()?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::internal_protocol::{InternalEndpointRole, InternalIpPrefix, LeasePlan};
    use crate::lease_spec::{DURABLE_WIREGUARD_ALIAS_PREFIX, WireguardLeaseSpec};
    use volparossa_routing::WireguardRole;

    fn plan() -> DeadWorkerCleanupPlan {
        let context_id = [0x41; 16];
        let specification = WireguardLeaseSpec::derive(
            context_id,
            ContextRole::Client,
            1,
            WireguardRole::Client as i32,
        )
        .expect("client resource specification");
        DeadWorkerCleanupPlan::new(
            context_id,
            ContextRole::Client,
            PrepareLeases {
                route_context_id: context_id.to_vec(),
                leases: vec![LeasePlan {
                    path_id: 1,
                    role: InternalEndpointRole::Client as i32,
                    local_overlay_address: Some(InternalIpPrefix {
                        address: specification.local_address().octets().to_vec(),
                        prefix_length: 128,
                    }),
                    setup_expires_at_unix: 1,
                    hard_expires_at_unix: 2,
                    ownership_alias: format!(
                        "{DURABLE_WIREGUARD_ALIAS_PREFIX}{}:{}",
                        specification.interface(),
                        "a".repeat(64)
                    ),
                }],
            },
        )
        .expect("structural cleanup plan")
    }

    #[test]
    fn cleanup_request_is_canonical_and_context_bound() {
        let plan = plan();
        let request = plan.request().expect("cleanup request");
        let encoded = encode_request(&request).expect("canonical request");
        let decoded = decode_request(encoded.as_slice()).expect("decode request");
        assert_eq!(decoded, request);
        assert!(matches!(
            request.operation,
            Some(internal_worker_request::Operation::Initialise(InitialiseContext {
                route_context_id,
                role,
                mptcp_accepted_addrs: 0,
                mptcp_subflows: 0,
                prepare: Some(_),
            })) if route_context_id == [0x41; 16] && role == crate::internal_protocol::InternalContextRole::Client as i32
        ));
    }

    #[test]
    fn cleanup_plan_rejects_cross_context_and_unspecified_role() {
        let mut valid = plan();
        valid.prepare.route_context_id[0] ^= 1;
        assert!(
            DeadWorkerCleanupPlan::new(valid.context_id, valid.context_role, valid.prepare)
                .is_err()
        );
        assert!(
            DeadWorkerCleanupPlan::new(
                [0x42; 16],
                ContextRole::Unspecified,
                PrepareLeases {
                    route_context_id: vec![0x42; 16],
                    leases: Vec::new(),
                },
            )
            .is_err()
        );
    }

    #[test]
    fn cleanup_response_is_correlated_without_reinterpreting_the_cleanup_plan() {
        let request = plan().request().expect("cleanup request");
        let encoded = encode_request(&request).expect("canonical cleanup request");
        let response = cleanup_response(&request).expect("correlated cleanup response");
        assert_eq!(response.request_id, request.request_id);
        assert_eq!(
            response.request_digest.as_slice(),
            blake3::hash(encoded.as_slice()).as_bytes()
        );
        assert!(matches!(
            response.outcome,
            Some(internal_worker_response::Outcome::Destroyed(_))
        ));
    }
}
