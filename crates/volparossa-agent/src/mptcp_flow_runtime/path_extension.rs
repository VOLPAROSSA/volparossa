//! Bounded command handoff to the live MPTCP runtime's affine helper owner.

use std::time::Duration;

use tokio::{
    sync::{mpsc, oneshot},
    time::{Instant, timeout_at},
};
use volparossa_routing::{
    ActivatePathExtension, ActivatedPathExtension, CommitPathExtension, CommittedPathExtension,
    LeaseActivation, LeaseCommit, LeasePlan, PreparePathExtension, PreparedPathExtension,
    TraversalEndpointHint, WireguardRole,
};

use super::path_growth::WarmGrowth;
use crate::mptcp_transport::{ExitMptcpPathState, ExitMptcpTransport};
use crate::{
    helper::{
        HelperClient, HelperClientError, RuntimeBoundDownlinkBudgetTarget,
        RuntimeBoundPreparedLeaseBatch,
    },
    unix_millis,
};
use volparossa_exit::ActiveTcpEgressRoute;
use volparossa_protocol::{
    MAX_ROUTE_EXTENSION_BYTES, RouteExtension, SignedEnvelope, decode_canonical,
};

const COMMAND_TIMEOUT: Duration = Duration::from_secs(15);

/// In-process authority only: one sender does not transfer or clone the full route owner.
#[derive(Clone)]
pub(crate) struct MptcpExitPathControl {
    sender: mpsc::Sender<PathCommand>,
    context: Vec<u8>,
    handle: Vec<u8>,
    hard_expires_at_ms: u64,
    hard_deadline: Instant,
}

enum Operation {
    Snapshot,
    Prepare(PreparePathExtension),
    Activate(ActivatePathExtension),
    Commit(CommitPathExtension),
    Abort([u8; 16]),
    DownlinkTarget([u8; 16]),
    Install {
        signed_extension: Vec<u8>,
        signed_relay_grant: Vec<u8>,
        signed_capability: Vec<u8>,
    },
}

enum Response {
    Snapshot(ExitMptcpPathState),
    Prepared(PreparedPathExtension),
    Activated(ActivatedPathExtension),
    Committed(CommittedPathExtension),
    Aborted,
    DownlinkTarget(RuntimeBoundDownlinkBudgetTarget),
    Installed,
}

pub(super) struct PathCommand {
    operation: Operation,
    deadline: Instant,
    reply: oneshot::Sender<Result<Response, HelperClientError>>,
}

impl MptcpExitPathControl {
    pub(crate) async fn snapshot(&self) -> Result<ExitMptcpPathState, HelperClientError> {
        match tokio::time::timeout(Duration::from_secs(2), self.call(Operation::Snapshot))
            .await
            .map_err(|_| HelperClientError::Timeout)??
        {
            Response::Snapshot(value) => Ok(value),
            _ => Err(HelperClientError::Correlation),
        }
    }
    /// Export only queue-update authority after the exact new lease has activated.
    pub(crate) async fn downlink_budget_target(
        &self,
        extension_id: [u8; 16],
    ) -> Result<RuntimeBoundDownlinkBudgetTarget, HelperClientError> {
        match self.call(Operation::DownlinkTarget(extension_id)).await? {
            Response::DownlinkTarget(value) => Ok(value),
            _ => Err(HelperClientError::Correlation),
        }
    }

    pub(crate) async fn install(
        &self,
        signed_extension: Vec<u8>,
        signed_relay_grant: Vec<u8>,
        signed_capability: Vec<u8>,
    ) -> Result<(), HelperClientError> {
        match self
            .call(Operation::Install {
                signed_extension,
                signed_relay_grant,
                signed_capability,
            })
            .await?
        {
            Response::Installed => Ok(()),
            _ => Err(HelperClientError::Correlation),
        }
    }

    pub(super) fn new(
        owner: &RuntimeBoundPreparedLeaseBatch,
        hard_expires_at_ms: u64,
    ) -> (Self, mpsc::Receiver<PathCommand>) {
        let (sender, receiver) = mpsc::channel(1);
        (
            Self {
                sender,
                context: owner.prepare().route_context_id.clone(),
                handle: owner.prepared().context_handle.clone(),
                hard_expires_at_ms,
                hard_deadline: Instant::now()
                    + Duration::from_millis(hard_expires_at_ms.saturating_sub(unix_millis())),
            },
            receiver,
        )
    }

    pub(crate) async fn prepare(
        &self,
        extension_id: [u8; 16],
        path_id: u32,
        setup_expires_at_unix: u64,
        traversal_hints: Vec<TraversalEndpointHint>,
    ) -> Result<PreparedPathExtension, HelperClientError> {
        let request = PreparePathExtension {
            route_context_id: self.context.clone(),
            context_handle: self.handle.clone(),
            extension_id: extension_id.to_vec(),
            lease: Some(LeasePlan {
                path_id,
                role: WireguardRole::Exit as i32,
            }),
            setup_expires_at_unix,
            traversal_hints,
        };
        match self.call(Operation::Prepare(request)).await? {
            Response::Prepared(value) => Ok(value),
            _ => Err(HelperClientError::Correlation),
        }
    }

    pub(crate) async fn activate(
        &self,
        extension_id: [u8; 16],
        lease: LeaseActivation,
        signed_route_extension: Vec<u8>,
    ) -> Result<ActivatedPathExtension, HelperClientError> {
        let request = ActivatePathExtension {
            route_context_id: self.context.clone(),
            context_handle: self.handle.clone(),
            extension_id: extension_id.to_vec(),
            lease: Some(lease),
            signed_route_extension,
        };
        match self.call(Operation::Activate(request)).await? {
            Response::Activated(value) => Ok(value),
            _ => Err(HelperClientError::Correlation),
        }
    }

    pub(crate) async fn commit(
        &self,
        extension_id: [u8; 16],
        lease: LeaseCommit,
    ) -> Result<CommittedPathExtension, HelperClientError> {
        let request = CommitPathExtension {
            route_context_id: self.context.clone(),
            context_handle: self.handle.clone(),
            extension_id: extension_id.to_vec(),
            lease: Some(lease),
        };
        match self.call(Operation::Commit(request)).await? {
            Response::Committed(value) => Ok(value),
            _ => Err(HelperClientError::Correlation),
        }
    }

    pub(crate) async fn abort(&self, extension_id: [u8; 16]) -> Result<(), HelperClientError> {
        match self.call(Operation::Abort(extension_id)).await? {
            Response::Aborted => Ok(()),
            _ => Err(HelperClientError::Correlation),
        }
    }

    async fn call(&self, operation: Operation) -> Result<Response, HelperClientError> {
        let now = Instant::now();
        if now >= self.hard_deadline || unix_millis() >= self.hard_expires_at_ms {
            return Err(HelperClientError::Timeout);
        }
        let deadline = (now + COMMAND_TIMEOUT).min(self.hard_deadline);
        let (reply, result) = oneshot::channel();
        // No independent unbounded request queue while an extension is being prepared.
        self.sender
            .try_send(PathCommand {
                operation,
                deadline,
                reply,
            })
            .map_err(|_| HelperClientError::Correlation)?;
        timeout_at(deadline, result)
            .await
            .map_err(|_| HelperClientError::Timeout)?
            .map_err(|_| HelperClientError::Correlation)?
    }
}

impl PathCommand {
    pub(super) async fn execute(
        self,
        helper: &HelperClient,
        owner: &mut RuntimeBoundPreparedLeaseBatch,
        expires_at_ms: u64,
        egress: &ActiveTcpEgressRoute,
        transport: &mut ExitMptcpTransport,
        growth: &mut WarmGrowth,
    ) {
        if self.reply.is_closed()
            || Instant::now() >= self.deadline
            || unix_millis() >= expires_at_ms
        {
            return;
        }
        let result = match self.operation {
            Operation::Snapshot => transport
                .path_state()
                .map(Response::Snapshot)
                .ok_or(HelperClientError::Correlation),
            Operation::Prepare(value) => helper
                .prepare_path_extension(owner, value)
                .await
                .map(Response::Prepared),
            Operation::Activate(value) => helper
                .activate_path_extension(owner, value)
                .await
                .map(Response::Activated),
            Operation::Commit(value) => helper
                .commit_path_extension(owner, value)
                .await
                .map(Response::Committed),
            Operation::Abort(id) => helper
                .abort_path_extension(owner, id)
                .await
                .map(|()| Response::Aborted),
            Operation::DownlinkTarget(id) => owner
                .extension_downlink_budget_target(id)
                .map(Response::DownlinkTarget),
            Operation::Install {
                signed_extension,
                signed_relay_grant,
                signed_capability,
            } => install(
                &signed_extension,
                &signed_relay_grant,
                &signed_capability,
                owner,
                egress,
                transport,
                growth,
            )
            .await
            .map(|()| Response::Installed),
        };
        let _ = self.reply.send(result);
    }
}

async fn install(
    signed_extension: &[u8],
    signed_relay_grant: &[u8],
    signed_capability: &[u8],
    owner: &RuntimeBoundPreparedLeaseBatch,
    egress: &ActiveTcpEgressRoute,
    transport: &mut ExitMptcpTransport,
    growth: &mut WarmGrowth,
) -> Result<(), HelperClientError> {
    // Decode only to compare the local helper identity. Full signed parent/capability/extension
    // verification is performed by the retained Exit egress owner before its view is updated.
    let envelope: SignedEnvelope = decode_canonical(signed_extension, MAX_ROUTE_EXTENSION_BYTES)
        .map_err(|_| HelperClientError::Correlation)?;
    let extension: RouteExtension = decode_canonical(&envelope.payload, MAX_ROUTE_EXTENSION_BYTES)
        .map_err(|_| HelperClientError::Correlation)?;
    let scope = extension
        .scope
        .as_ref()
        .ok_or(HelperClientError::Correlation)?;
    let id = scope
        .extension_id
        .as_slice()
        .try_into()
        .map_err(|_| HelperClientError::Correlation)?;
    let replacement = transport
        .extension_growth_scope(scope.path_id, &extension.selected_path_ids)
        .ok_or(HelperClientError::Correlation)?;
    if owner.committed_extension_path(id) != Some(scope.path_id)
        || !growth.can_extend_scope(&replacement)
    {
        return Err(HelperClientError::Correlation);
    }
    egress
        .install_extension(
            signed_extension,
            signed_relay_grant,
            signed_capability,
            unix_millis(),
        )
        .await
        .map_err(|_| HelperClientError::Correlation)?;
    transport
        .register_extension(scope.path_id, &extension.selected_path_ids)
        .map_err(|_| HelperClientError::Correlation)?;
    if !growth.extend_scope(replacement) {
        return Err(HelperClientError::Correlation);
    }
    Ok(())
}
