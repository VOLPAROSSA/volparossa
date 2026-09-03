//! Typed client for the privileged helper-v3 lease protocol.

use std::{
    collections::{BTreeMap, BTreeSet},
    fs::{self, OpenOptions},
    io::Read,
    net::{SocketAddr, SocketAddrV4},
    os::fd::{AsFd, AsRawFd as _, BorrowedFd, OwnedFd},
    os::unix::fs::{MetadataExt, OpenOptionsExt},
    path::{Path, PathBuf},
    time::Duration,
};

use rand_core::{OsRng, RngCore};
use subtle::ConstantTimeEq;
use thiserror::Error;
use tokio::{
    io::{AsyncWriteExt, Interest},
    net::UnixStream,
    time::{Instant, timeout, timeout_at},
};
use volparossa_linux_uapi::{
    IngressSocketFamily as KernelIngressSocketFamily, IngressSocketKind as KernelIngressSocketKind,
    receive_fd_with_binding, validate_ingress_socket, validate_ingress_udp_reply_socket,
};
use volparossa_routing::{
    AcquireIngressReplySocket, AcquireIngressSocket, AcquireTransportSocket,
    ActivateClientIngress as ActivateClientIngressRequest, ActivateLeaseBatch, ActivatedLeaseBatch,
    AddMptcpEndpoint, BindHelperRuntime, CleanupOwned, CleanupScope, ClosedPreparePlan,
    CommitLeaseBatch, CommittedLeaseBatch, DestroyClientIngress as DestroyClientIngressRequest,
    DestroyContext, DestroyedContext, Empty, HELPER_PROTOCOL_VERSION, HelperRequest,
    HelperResponse, HelperResult, HelperRuntime, IngressAddressFamily as WireIngressSocketFamily,
    IngressReplySocketReady, IngressSocketAddress, IngressSocketKind as WireIngressSocketKind,
    IngressSocketReady, IngressSocketReceipt, PrepareClientIngress as PrepareClientIngressRequest,
    PrepareIntent, PrepareLeaseBatch, PreparedClientIngress as PreparedClientIngressResponse,
    PreparedIngressSocket, PreparedLeaseBatch, REQUIRED_INGRESS_SOCKETS, ReconcileExpiredPrepare,
    ReconciledExpiredPrepare, RemoveMptcpEndpoint, TransportSocketReady, descriptor_fd_binding,
    encode_request, helper_request, helper_response, operation_digest, read_response,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

const HELPER_TIMEOUT: Duration = Duration::from_secs(10);
const CLEANUP_TOKEN_BYTES: usize = 32;

/// One route-namespace descriptor plus the exact validated helper metadata that binds it.
///
/// This type intentionally implements neither serialization nor Debug: the owned descriptor is a
/// process-local capability and must not enter logs or wire formats.
pub struct AcquiredTransportSocket {
    descriptor: OwnedFd,
    metadata: TransportSocketReady,
}

impl AcquiredTransportSocket {
    /// Borrow the close-on-exec descriptor without exposing a serializable integer.
    #[must_use]
    pub fn descriptor(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }

    /// Return the exact helper-validated path, role, kind and address metadata.
    #[must_use]
    pub const fn metadata(&self) -> &TransportSocketReady {
        &self.metadata
    }

    /// Consume the capability into its owned descriptor and typed metadata.
    #[must_use]
    pub fn into_parts(self) -> (OwnedFd, TransportSocketReady) {
        (self.descriptor, self.metadata)
    }
}

/// Closed application meaning of one client-ingress descriptor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ClientIngressSocketKind {
    /// Transparent TCP listener for non-DNS flows.
    TransparentTcpListener,
    /// Transparent UDP ingress for non-DNS datagrams.
    TransparentUdp,
    /// Dedicated transparent TCP listener for DNS.
    DnsTcpListener,
    /// Dedicated transparent UDP ingress for DNS.
    DnsUdp,
}

/// Closed Internet family of one client-ingress descriptor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub enum ClientIngressSocketFamily {
    /// IPv4-only socket.
    Ipv4,
    /// IPv6-only socket.
    Ipv6,
}

/// Exact kind-by-family identity of one ingress descriptor.
#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ClientIngressSocketIdentity {
    kind: ClientIngressSocketKind,
    family: ClientIngressSocketFamily,
}

impl ClientIngressSocketIdentity {
    /// Construct one closed ingress descriptor identity.
    #[must_use]
    pub const fn new(kind: ClientIngressSocketKind, family: ClientIngressSocketFamily) -> Self {
        Self { kind, family }
    }

    /// Return the semantic descriptor kind.
    #[must_use]
    pub const fn kind(self) -> ClientIngressSocketKind {
        self.kind
    }

    /// Return the Internet address family.
    #[must_use]
    pub const fn family(self) -> ClientIngressSocketFamily {
        self.family
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
struct IngressAuthority {
    client_runtime_id: [u8; 16],
    ingress_handle: [u8; 32],
}

struct PreparedIngressSocketAuthority {
    socket_handle: [u8; 32],
    wire_local: IngressSocketAddress,
    local: SocketAddr,
    acquisition_started: bool,
}

/// Opaque prepared client-ingress capability returned before interception activation.
///
/// This type intentionally implements neither Clone, Debug nor serialization. Its helper-issued
/// handles cannot be copied into control-plane messages. Dropping it discards only local authority;
/// the helper hard expiry remains the final cleanup boundary while production ingress is disabled.
pub struct PreparedClientIngress {
    authority: IngressAuthority,
    hard_expires_at_unix: u64,
    sockets: BTreeMap<ClientIngressSocketIdentity, PreparedIngressSocketAuthority>,
}

impl PreparedClientIngress {
    /// Return the exact accepted helper hard expiry.
    #[must_use]
    pub const fn hard_expires_at_unix(&self) -> u64 {
        self.hard_expires_at_unix
    }

    /// Iterate the complete eight kind-by-family descriptor identities.
    pub fn socket_identities(
        &self,
    ) -> impl ExactSizeIterator<Item = ClientIngressSocketIdentity> + '_ {
        self.sockets.keys().copied()
    }

    /// Return the helper-selected wildcard bind tuple for one identity.
    #[must_use]
    pub fn local_address(&self, identity: ClientIngressSocketIdentity) -> Option<SocketAddr> {
        self.sockets.get(&identity).map(|socket| socket.local)
    }
}

/// One correlated, kernel-revalidated ingress descriptor and its private activation receipt.
///
/// This type intentionally implements neither `Clone`, `Debug` nor serialization. Its `OwnedFd` is
/// closed automatically on every rejection path and when the capability is dropped.
pub struct AcquiredIngressSocket {
    descriptor: OwnedFd,
    authority: IngressAuthority,
    socket_handle: [u8; 32],
    receipt_handle: [u8; 32],
    identity: ClientIngressSocketIdentity,
    local: SocketAddr,
}

/// One source-bound transparent UDP socket for an exact intercepted flow reply.
pub(crate) struct AcquiredIngressReplySocket {
    descriptor: OwnedFd,
    remote: SocketAddr,
    application: SocketAddr,
}

impl AcquiredIngressReplySocket {
    pub(crate) fn send(&self, payload: &[u8]) -> Result<(), std::io::Error> {
        let destination = nix::sys::socket::SockaddrStorage::from(self.application);
        let written = nix::sys::socket::sendto(
            self.descriptor.as_raw_fd(),
            payload,
            &destination,
            nix::sys::socket::MsgFlags::MSG_DONTWAIT | nix::sys::socket::MsgFlags::MSG_NOSIGNAL,
        )
        .map_err(|error| std::io::Error::from_raw_os_error(error as i32))?;
        if written != payload.len() {
            return Err(std::io::Error::new(
                std::io::ErrorKind::WriteZero,
                "kernel did not send the complete ingress UDP reply",
            ));
        }
        Ok(())
    }

    pub(crate) const fn remote(&self) -> SocketAddr {
        self.remote
    }

    pub(crate) const fn application(&self) -> SocketAddr {
        self.application
    }
}

impl AcquiredIngressSocket {
    /// Borrow the close-on-exec descriptor without exposing a serializable integer.
    #[must_use]
    pub fn descriptor(&self) -> BorrowedFd<'_> {
        self.descriptor.as_fd()
    }

    /// Return its exact semantic identity.
    #[must_use]
    pub const fn identity(&self) -> ClientIngressSocketIdentity {
        self.identity
    }

    /// Return the kernel-revalidated wildcard bind tuple.
    #[must_use]
    pub const fn local_address(&self) -> SocketAddr {
        self.local
    }
}

/// Activated client-ingress capability that keeps all eight descriptors alive.
///
/// The complete descriptor array is RAII-owned. Dropping this value closes every descriptor. The
/// helper-side runtime must additionally be destroyed explicitly or expire; no asynchronous work
/// is hidden in Drop.
pub struct ActiveClientIngress {
    authority: IngressAuthority,
    hard_expires_at_unix: u64,
    sockets: [AcquiredIngressSocket; REQUIRED_INGRESS_SOCKETS],
}

/// Failed activation together with every still-owned local capability needed for safe cleanup.
///
/// The contained handles and descriptors are intentionally not formatted. Callers can inspect the
/// stable error category and recover the complete prepared/descriptor set to retry destruction.
pub struct ClientIngressActivationFailure {
    error: HelperClientError,
    prepared: PreparedClientIngress,
    sockets: [AcquiredIngressSocket; REQUIRED_INGRESS_SOCKETS],
}

impl ClientIngressActivationFailure {
    /// Return the stable activation failure category without exposing any capability.
    #[must_use]
    pub const fn error(&self) -> &HelperClientError {
        &self.error
    }

    /// Recover all local capabilities after a failed or ambiguous activation attempt.
    #[must_use]
    pub fn into_parts(
        self,
    ) -> (
        HelperClientError,
        PreparedClientIngress,
        [AcquiredIngressSocket; REQUIRED_INGRESS_SOCKETS],
    ) {
        (self.error, self.prepared, self.sockets)
    }
}

impl std::fmt::Debug for ClientIngressActivationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("ClientIngressActivationFailure")
            .field("error", &self.error)
            .finish_non_exhaustive()
    }
}

impl std::fmt::Display for ClientIngressActivationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            formatter,
            "client ingress activation failed: {}",
            self.error
        )
    }
}

impl std::error::Error for ClientIngressActivationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.error)
    }
}

impl ActiveClientIngress {
    /// Return the exact accepted helper hard expiry.
    #[must_use]
    pub const fn hard_expires_at_unix(&self) -> u64 {
        self.hard_expires_at_unix
    }

    /// Borrow one exact active descriptor capability by identity.
    #[must_use]
    pub fn socket(&self, identity: ClientIngressSocketIdentity) -> Option<&AcquiredIngressSocket> {
        self.sockets
            .iter()
            .find(|socket| socket.identity == identity)
    }

    /// Iterate all eight active descriptor capabilities.
    pub fn sockets(&self) -> impl ExactSizeIterator<Item = &AcquiredIngressSocket> {
        self.sockets.iter()
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum DescriptorExpectation {
    None,
    Transport,
    Ingress,
    IngressReply,
}

struct ClientExecution {
    outcome: helper_response::Outcome,
    descriptor: Option<OwnedFd>,
}

/// Exact same-runtime authority retained only after a Prepare write may have been dispatched.
///
/// This capability intentionally implements neither serialization nor field-level formatting.
#[derive(Zeroize, ZeroizeOnDrop)]
pub(crate) struct PrepareReconciliationAuthority {
    helper_runtime_id: [u8; 32],
    route_context_id: [u8; 16],
    prepare_request_id: [u8; 16],
    prepare_operation_digest: [u8; 32],
    reconcile_request_id: [u8; 16],
    setup_expires_at_unix: u64,
    hard_expires_at_unix: u64,
}

impl std::fmt::Debug for PrepareReconciliationAuthority {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("PrepareReconciliationAuthority")
            .finish_non_exhaustive()
    }
}

impl PrepareReconciliationAuthority {
    pub(crate) fn matches_reconciled(&self, value: &ReconciledExpiredPrepare) -> bool {
        self.helper_runtime_id
            .ct_eq(&value.helper_runtime_id)
            .unwrap_u8()
            == 1
            && self
                .route_context_id
                .ct_eq(&value.route_context_id)
                .unwrap_u8()
                == 1
            && self
                .prepare_request_id
                .ct_eq(&value.prepare_request_id)
                .unwrap_u8()
                == 1
            && self
                .prepare_operation_digest
                .ct_eq(&value.prepare_operation_digest)
                .unwrap_u8()
                == 1
            && self.setup_expires_at_unix == value.setup_expires_at_unix
            && self.hard_expires_at_unix == value.hard_expires_at_unix
    }
}

#[cfg(test)]
impl PrepareReconciliationAuthority {
    pub(crate) fn for_test(value: &PrepareLeaseBatch) -> Self {
        let prepare_request_id = [0xb1; 16];
        let request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: prepare_request_id.to_vec(),
            operation: Some(helper_request::Operation::PrepareLeaseBatch(value.clone())),
        };
        Self {
            helper_runtime_id: [0xa5; 32],
            route_context_id: value
                .route_context_id
                .as_slice()
                .try_into()
                .expect("validated test context"),
            prepare_request_id,
            prepare_operation_digest: operation_digest(&request).expect("test Prepare digest"),
            reconcile_request_id: [0xc1; 16],
            setup_expires_at_unix: value.setup_expires_at_unix,
            hard_expires_at_unix: value.hard_expires_at_unix,
        }
    }

    pub(crate) fn reconciled_for_test(&self) -> ReconciledExpiredPrepare {
        ReconciledExpiredPrepare {
            helper_runtime_id: self.helper_runtime_id.to_vec(),
            route_context_id: self.route_context_id.to_vec(),
            prepare_request_id: self.prepare_request_id.to_vec(),
            prepare_operation_digest: self.prepare_operation_digest.to_vec(),
            setup_expires_at_unix: self.setup_expires_at_unix,
            hard_expires_at_unix: self.hard_expires_at_unix,
        }
    }
}

/// Prepare failure split at the first mutating-frame write attempt.
pub(crate) enum PrepareLeaseBatchFailure {
    Definitive(HelperClientError),
    Ambiguous {
        source: HelperClientError,
        authority: PrepareReconciliationAuthority,
    },
}

impl std::fmt::Debug for PrepareLeaseBatchFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Definitive(source) => formatter.debug_tuple("Definitive").field(source).finish(),
            Self::Ambiguous { source, .. } => formatter
                .debug_struct("Ambiguous")
                .field("source", source)
                .finish_non_exhaustive(),
        }
    }
}

enum PrepareDispatchState {
    PreDispatch,
    Armed(PrepareReconciliationAuthority),
    Dispatched(PrepareReconciliationAuthority),
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum RuntimeLeasePhase {
    Prepared,
    ActivationDispatched,
    Activated,
    CommitDispatched,
    Committed,
}

/// Affine owner of one exact helper-runtime Prepare result.
///
/// This value deliberately implements neither `Copy`, `Clone`, `Debug` nor serialization. It
/// retains the exact helper process identity, canonical Prepare plan, context capability and lease
/// capabilities needed to bind every later mutating lifecycle phase. A timeout or cancellation
/// must retain this owner and route it to explicit same-runtime destruction; dropping the value
/// alone does not claim helper-side cleanup.
pub(crate) struct RuntimeBoundPreparedLeaseBatch {
    helper_runtime_id: [u8; 32],
    prepare: PrepareLeaseBatch,
    prepared: PreparedLeaseBatch,
    phase: RuntimeLeasePhase,
}

impl RuntimeBoundPreparedLeaseBatch {
    fn new(
        helper_runtime_id: [u8; 32],
        prepare: PrepareLeaseBatch,
        prepared: PreparedLeaseBatch,
    ) -> Result<Self, HelperClientError> {
        let route_context: [u8; 16] = prepare
            .route_context_id
            .as_slice()
            .try_into()
            .map_err(|_| HelperClientError::Correlation)?;
        if helper_runtime_id.ct_eq(&[0; 32]).unwrap_u8() == 1
            || route_context.iter().all(|byte| *byte == 0)
            || prepared.context_handle.len() != 32
            || prepared.context_handle.iter().all(|byte| *byte == 0)
        {
            return Err(HelperClientError::Correlation);
        }
        Ok(Self {
            helper_runtime_id,
            prepare,
            prepared,
            phase: RuntimeLeasePhase::Prepared,
        })
    }

    /// Borrow the exact canonical Prepare plan used to create this owner.
    #[must_use]
    pub(crate) const fn prepare(&self) -> &PrepareLeaseBatch {
        &self.prepare
    }

    /// Borrow the helper response while retaining its affine lifecycle owner.
    #[must_use]
    pub(crate) const fn prepared(&self) -> &PreparedLeaseBatch {
        &self.prepared
    }

    /// Return the exact helper process identity retained by this affine owner.
    #[must_use]
    pub(crate) const fn helper_runtime_id(&self) -> [u8; 32] {
        self.helper_runtime_id
    }

    pub(crate) fn destroy_request(&self) -> DestroyContext {
        DestroyContext {
            route_context_id: self.prepare.route_context_id.clone(),
            context_handle: self.prepared.context_handle.clone(),
        }
    }

    pub(crate) fn begin_activation(
        &mut self,
        value: &ActivateLeaseBatch,
    ) -> Result<(), HelperClientError> {
        if self.phase != RuntimeLeasePhase::Prepared || !self.matches_activation(value) {
            return Err(HelperClientError::Correlation);
        }
        self.phase = RuntimeLeasePhase::ActivationDispatched;
        Ok(())
    }

    pub(crate) fn finish_activation(
        &mut self,
        value: &ActivatedLeaseBatch,
    ) -> Result<(), HelperClientError> {
        if self.phase != RuntimeLeasePhase::ActivationDispatched
            || value.context_handle != self.prepared.context_handle
            || value.lease_handles.len() != self.prepared.leases.len()
            || !self.prepared.leases.iter().all(|prepared| {
                value
                    .lease_handles
                    .iter()
                    .filter(|handle| *handle == &prepared.lease_handle)
                    .count()
                    == 1
            })
        {
            return Err(HelperClientError::Correlation);
        }
        self.phase = RuntimeLeasePhase::Activated;
        Ok(())
    }

    pub(crate) fn begin_commit(
        &mut self,
        value: &CommitLeaseBatch,
    ) -> Result<(), HelperClientError> {
        if self.phase != RuntimeLeasePhase::Activated || !self.matches_commit(value) {
            return Err(HelperClientError::Correlation);
        }
        self.phase = RuntimeLeasePhase::CommitDispatched;
        Ok(())
    }

    pub(crate) fn finish_commit(
        &mut self,
        value: &CommittedLeaseBatch,
    ) -> Result<(), HelperClientError> {
        if self.phase != RuntimeLeasePhase::CommitDispatched
            || value.context_handle != self.prepared.context_handle
            || value.leases.len() != self.prepared.leases.len()
            || !self.prepared.leases.iter().all(|prepared| {
                value
                    .leases
                    .iter()
                    .filter(|lease| lease.lease_handle == prepared.lease_handle)
                    .count()
                    == 1
            })
        {
            return Err(HelperClientError::Correlation);
        }
        self.phase = RuntimeLeasePhase::Committed;
        Ok(())
    }

    fn matches_activation(&self, value: &ActivateLeaseBatch) -> bool {
        value.route_context_id == self.prepare.route_context_id
            && value.context_handle == self.prepared.context_handle
            && value.leases.len() == self.prepared.leases.len()
            && self.prepared.leases.iter().all(|prepared| {
                value
                    .leases
                    .iter()
                    .filter(|lease| {
                        lease.lease_handle == prepared.lease_handle
                            && lease.path_id == prepared.path_id
                            && lease.role == prepared.role
                    })
                    .count()
                    == 1
            })
    }

    fn matches_commit(&self, value: &CommitLeaseBatch) -> bool {
        value.route_context_id == self.prepare.route_context_id
            && value.context_handle == self.prepared.context_handle
            && value.leases.len() == self.prepared.leases.len()
            && self.prepared.leases.iter().all(|prepared| {
                value
                    .leases
                    .iter()
                    .filter(|lease| {
                        lease.lease_handle == prepared.lease_handle
                            && lease.path_id == prepared.path_id
                            && lease.role == prepared.role
                    })
                    .count()
                    == 1
            })
    }

    #[cfg(test)]
    pub(crate) fn for_test(prepare: PrepareLeaseBatch, prepared: PreparedLeaseBatch) -> Self {
        Self::new([0xa5; 32], prepare, prepared).expect("valid test runtime-bound Prepare")
    }
}

impl Drop for RuntimeBoundPreparedLeaseBatch {
    fn drop(&mut self) {
        self.helper_runtime_id.zeroize();
        self.prepare.route_context_id.zeroize();
        self.prepared.context_handle.zeroize();
        for lease in &mut self.prepared.leases {
            lease.lease_handle.zeroize();
        }
    }
}

fn closed_plan_from_prepare(value: &PrepareLeaseBatch) -> ClosedPreparePlan {
    ClosedPreparePlan {
        context_role: value.role,
        leases: value.leases.clone(),
    }
}

/// Strict unprivileged client for helper version 3.
#[derive(Clone, Debug)]
pub struct HelperClient {
    socket: PathBuf,
    cleanup_token: PathBuf,
    expected_server_uid: u32,
}

impl HelperClient {
    /// Construct a client for packaging-controlled paths.
    #[must_use]
    pub fn new(socket: PathBuf, cleanup_token: PathBuf) -> Self {
        Self {
            socket,
            cleanup_token,
            expected_server_uid: 0,
        }
    }

    #[cfg(test)]
    fn new_for_test(socket: PathBuf, cleanup_token: PathBuf, expected_server_uid: u32) -> Self {
        Self {
            socket,
            cleanup_token,
            expected_server_uid,
        }
    }

    /// Prepare helper-owned local endpoint leases.
    ///
    /// # Errors
    ///
    /// Returns an error on framing, credentials, correlation, timeout or helper rejection.
    pub(crate) async fn prepare_lease_batch(
        &self,
        value: PrepareLeaseBatch,
    ) -> Result<RuntimeBoundPreparedLeaseBatch, PrepareLeaseBatchFailure> {
        self.prepare_lease_batch_bound(value).await
    }

    #[allow(
        clippy::too_many_lines,
        reason = "keep prebuilt Bind-plus-Prepare dispatch state and its single absolute deadline together"
    )]
    async fn prepare_lease_batch_bound(
        &self,
        value: PrepareLeaseBatch,
    ) -> Result<RuntimeBoundPreparedLeaseBatch, PrepareLeaseBatchFailure> {
        let prepare_request_id = random_request_id(&[]);
        let prepare_request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: prepare_request_id.to_vec(),
            operation: Some(helper_request::Operation::PrepareLeaseBatch(value.clone())),
        };
        let prepare_digest = operation_digest(&prepare_request)
            .map_err(HelperClientError::Protocol)
            .map_err(PrepareLeaseBatchFailure::Definitive)?;
        let prepare_frame = Zeroizing::new(
            encode_request(&prepare_request)
                .map_err(HelperClientError::Protocol)
                .map_err(PrepareLeaseBatchFailure::Definitive)?,
        );
        // `encode_request` above has validated the role-complete canonical lease order. Project
        // the durable closed plan only from that same immutable batch; there is no second topology
        // input which could diverge from the subsequently dispatched Prepare.
        let closed_plan = closed_plan_from_prepare(&value);
        let route_context_id =
            value.route_context_id.as_slice().try_into().map_err(|_| {
                PrepareLeaseBatchFailure::Definitive(HelperClientError::Correlation)
            })?;

        let bind_request_id = random_request_id(&[prepare_request_id]);
        let reconcile_request_id = random_request_id(&[prepare_request_id, bind_request_id]);
        let bind_request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: bind_request_id.to_vec(),
            operation: Some(helper_request::Operation::BindHelperRuntime(
                BindHelperRuntime {
                    prepare_intent: Some(PrepareIntent {
                        route_context_id: value.route_context_id.clone(),
                        prepare_request_id: prepare_request_id.to_vec(),
                        prepare_operation_digest: prepare_digest.to_vec(),
                        setup_expires_at_unix: value.setup_expires_at_unix,
                        hard_expires_at_unix: value.hard_expires_at_unix,
                        closed_plan: Some(closed_plan),
                    }),
                },
            )),
        };
        let bind_digest = operation_digest(&bind_request)
            .map_err(HelperClientError::Protocol)
            .map_err(PrepareLeaseBatchFailure::Definitive)?;
        let bind_frame = Zeroizing::new(
            encode_request(&bind_request)
                .map_err(HelperClientError::Protocol)
                .map_err(PrepareLeaseBatchFailure::Definitive)?,
        );

        let mut dispatch_state = PrepareDispatchState::PreDispatch;
        let deadline = Instant::now() + HELPER_TIMEOUT;
        let result = timeout_at(deadline, async {
            let mut stream = UnixStream::connect(&self.socket)
                .await
                .map_err(HelperClientError::Io)?;
            let credentials = stream.peer_cred().map_err(HelperClientError::Io)?;
            validate_server_uid(credentials.uid(), self.expected_server_uid)?;

            let bind_outcome = exchange_request(
                &mut stream,
                bind_frame.as_slice(),
                &bind_request_id,
                &bind_digest,
            )
            .await?;
            let helper_response::Outcome::HelperRuntime(HelperRuntime { helper_runtime_id }) =
                bind_outcome
            else {
                return Err(HelperClientError::Correlation);
            };
            let helper_runtime_id = helper_runtime_id
                .as_slice()
                .try_into()
                .map_err(|_| HelperClientError::Correlation)?;
            dispatch_state = PrepareDispatchState::Armed(PrepareReconciliationAuthority {
                helper_runtime_id,
                route_context_id,
                prepare_request_id,
                prepare_operation_digest: prepare_digest,
                reconcile_request_id,
                setup_expires_at_unix: value.setup_expires_at_unix,
                hard_expires_at_unix: value.hard_expires_at_unix,
            });

            let PrepareDispatchState::Armed(authority) =
                std::mem::replace(&mut dispatch_state, PrepareDispatchState::PreDispatch)
            else {
                return Err(HelperClientError::Correlation);
            };
            // The typed state becomes consumptive before the first mutating write future is
            // polled, so cancellation of the inner timed exchange cannot lose authority. Dropping
            // this crate-private outer future is safe only at its sole production call site: the
            // owned route-ticket supervisor retains that future through settlement.
            dispatch_state = PrepareDispatchState::Dispatched(authority);
            let prepare_outcome = exchange_request(
                &mut stream,
                prepare_frame.as_slice(),
                &prepare_request_id,
                &prepare_digest,
            )
            .await?;
            let helper_response::Outcome::PreparedLeaseBatch(prepared) = prepare_outcome else {
                return Err(HelperClientError::Correlation);
            };
            Ok((helper_runtime_id, prepared))
        })
        .await;

        match result {
            Ok(Ok((helper_runtime_id, prepared))) => {
                RuntimeBoundPreparedLeaseBatch::new(helper_runtime_id, value, prepared)
                    .map_err(PrepareLeaseBatchFailure::Definitive)
            }
            Ok(Err(error)) => Err(classify_prepare_failure(error, dispatch_state)),
            Err(_) => Err(classify_prepare_failure(
                HelperClientError::Timeout,
                dispatch_state,
            )),
        }
    }

    pub(crate) async fn reconcile_expired_prepare(
        &self,
        authority: &PrepareReconciliationAuthority,
    ) -> Result<ReconciledExpiredPrepare, HelperClientError> {
        let bind_request_id =
            random_request_id(&[authority.prepare_request_id, authority.reconcile_request_id]);
        let bind_request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: bind_request_id.to_vec(),
            operation: Some(helper_request::Operation::BindHelperRuntime(
                BindHelperRuntime {
                    prepare_intent: None,
                },
            )),
        };
        let bind_digest = operation_digest(&bind_request).map_err(HelperClientError::Protocol)?;
        let bind_frame =
            Zeroizing::new(encode_request(&bind_request).map_err(HelperClientError::Protocol)?);

        let reconcile_request_id = authority.reconcile_request_id;
        let reconcile_value = ReconcileExpiredPrepare {
            helper_runtime_id: authority.helper_runtime_id.to_vec(),
            route_context_id: authority.route_context_id.to_vec(),
            prepare_request_id: authority.prepare_request_id.to_vec(),
            prepare_operation_digest: authority.prepare_operation_digest.to_vec(),
            setup_expires_at_unix: authority.setup_expires_at_unix,
            hard_expires_at_unix: authority.hard_expires_at_unix,
        };
        let reconcile_request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: reconcile_request_id.to_vec(),
            operation: Some(helper_request::Operation::ReconcileExpiredPrepare(
                reconcile_value.clone(),
            )),
        };
        let reconcile_digest =
            operation_digest(&reconcile_request).map_err(HelperClientError::Protocol)?;
        let reconcile_frame = Zeroizing::new(
            encode_request(&reconcile_request).map_err(HelperClientError::Protocol)?,
        );

        timeout_at(Instant::now() + HELPER_TIMEOUT, async {
            let mut stream = UnixStream::connect(&self.socket)
                .await
                .map_err(HelperClientError::Io)?;
            let credentials = stream.peer_cred().map_err(HelperClientError::Io)?;
            validate_server_uid(credentials.uid(), self.expected_server_uid)?;
            let bind_outcome = exchange_request(
                &mut stream,
                bind_frame.as_slice(),
                &bind_request_id,
                &bind_digest,
            )
            .await?;
            let helper_response::Outcome::HelperRuntime(runtime) = bind_outcome else {
                return Err(HelperClientError::Correlation);
            };
            if runtime.helper_runtime_id.as_slice() != authority.helper_runtime_id {
                return Err(HelperClientError::RuntimeChanged);
            }
            let outcome = exchange_request(
                &mut stream,
                reconcile_frame.as_slice(),
                &reconcile_request_id,
                &reconcile_digest,
            )
            .await?;
            let helper_response::Outcome::ReconciledExpiredPrepare(reconciled) = outcome else {
                return Err(HelperClientError::Correlation);
            };
            if !authority.matches_reconciled(&reconciled) {
                return Err(HelperClientError::Correlation);
            }
            Ok(reconciled)
        })
        .await
        .map_err(|_| HelperClientError::Timeout)?
    }

    /// Activate prepared leases using only peer public data.
    ///
    /// # Errors
    ///
    /// Returns an error on framing, credentials, correlation, timeout or helper rejection.
    pub(crate) async fn activate_lease_batch(
        &self,
        owner: &mut RuntimeBoundPreparedLeaseBatch,
        value: ActivateLeaseBatch,
    ) -> Result<ActivatedLeaseBatch, HelperClientError> {
        let outcome = self
            .execute_runtime_bound(owner, helper_request::Operation::ActivateLeaseBatch(value))
            .await?;
        match outcome {
            helper_response::Outcome::ActivatedLeaseBatch(value) => {
                owner.finish_activation(&value)?;
                Ok(value)
            }
            _ => Err(HelperClientError::Correlation),
        }
    }

    /// Commit only after the helper proves handshakes and counter growth.
    ///
    /// # Errors
    ///
    /// Returns an error on framing, credentials, correlation, timeout or helper rejection.
    pub(crate) async fn commit_lease_batch(
        &self,
        owner: &mut RuntimeBoundPreparedLeaseBatch,
        value: CommitLeaseBatch,
    ) -> Result<CommittedLeaseBatch, HelperClientError> {
        let outcome = self
            .execute_runtime_bound(owner, helper_request::Operation::CommitLeaseBatch(value))
            .await?;
        match outcome {
            helper_response::Outcome::CommittedLeaseBatch(value) => {
                owner.finish_commit(&value)?;
                Ok(value)
            }
            _ => Err(HelperClientError::Correlation),
        }
    }

    /// Destroy one exact helper-owned context.
    ///
    /// # Errors
    ///
    /// Returns an error on framing, credentials, correlation, timeout or helper rejection.
    pub(crate) async fn destroy_context(
        &self,
        owner: &RuntimeBoundPreparedLeaseBatch,
    ) -> Result<DestroyedContext, HelperClientError> {
        let value = owner.destroy_request();
        match self
            .execute_runtime_bound_readonly(owner, helper_request::Operation::DestroyContext(value))
            .await?
        {
            helper_response::Outcome::DestroyedContext(value) => Ok(value),
            _ => Err(HelperClientError::Correlation),
        }
    }

    /// Prepare one helper-owned ingress runtime before any route context exists.
    ///
    /// The returned opaque handles are process-local capabilities and cannot be serialized or
    /// copied through the public API.
    ///
    /// # Errors
    ///
    /// Returns an error on framing, credentials, response correlation, invalid expiry or helper
    /// rejection.
    pub async fn prepare_client_ingress(
        &self,
        value: PrepareClientIngressRequest,
    ) -> Result<PreparedClientIngress, HelperClientError> {
        let expected_runtime: [u8; 16] = value
            .client_runtime_id
            .as_slice()
            .try_into()
            .map_err(|_| HelperClientError::Correlation)?;
        let setup_expires_at_unix = value.setup_expires_at_unix;
        let requested_hard_expires_at_unix = value.hard_expires_at_unix;
        let outcome = self
            .execute(helper_request::Operation::PrepareClientIngress(value))
            .await?;
        let helper_response::Outcome::PreparedClientIngress(prepared) = outcome else {
            return Err(HelperClientError::Correlation);
        };
        prepared_client_ingress(
            prepared,
            expected_runtime,
            setup_expires_at_unix,
            requested_hard_expires_at_unix,
        )
    }

    /// Acquire and revalidate exactly one prepared ingress descriptor.
    ///
    /// The helper response, descriptor binding, opaque receipt, kind, family and helper-selected
    /// local tuple are correlated before the Linux kernel descriptor properties are revalidated.
    ///
    /// # Errors
    ///
    /// Returns an error on framing, credentials, response/descriptor correlation, ancillary
    /// validation, kernel socket mismatch, timeout or helper rejection.
    pub async fn acquire_ingress_socket(
        &self,
        ingress: &mut PreparedClientIngress,
        identity: ClientIngressSocketIdentity,
    ) -> Result<AcquiredIngressSocket, HelperClientError> {
        let acquired = self
            .acquire_ingress_socket_protocol(ingress, identity)
            .await?;
        validate_ingress_socket(
            &acquired.descriptor,
            kernel_ingress_kind(identity.kind),
            kernel_ingress_family(identity.family),
            acquired.local.port(),
        )
        .map_err(HelperClientError::DescriptorValidation)?;
        Ok(acquired)
    }

    async fn acquire_ingress_socket_protocol(
        &self,
        ingress: &mut PreparedClientIngress,
        identity: ClientIngressSocketIdentity,
    ) -> Result<AcquiredIngressSocket, HelperClientError> {
        let authority = ingress.authority;
        let (socket_handle, expected_local, local) = {
            let prepared = ingress
                .sockets
                .get_mut(&identity)
                .ok_or(HelperClientError::Correlation)?;
            if prepared.acquisition_started {
                return Err(HelperClientError::CapabilityAlreadyUsed);
            }
            // One-shot even on timeout: after an ambiguous RPC result, a second descriptor transfer
            // could create two live capabilities for the same helper socket identity.
            prepared.acquisition_started = true;
            (
                prepared.socket_handle,
                prepared.wire_local.clone(),
                prepared.local,
            )
        };
        let operation = AcquireIngressSocket {
            client_runtime_id: authority.client_runtime_id.to_vec(),
            ingress_handle: authority.ingress_handle.to_vec(),
            socket_handle: socket_handle.to_vec(),
            descriptor_kind: wire_ingress_kind(identity.kind) as i32,
            address_family: wire_ingress_family(identity.family) as i32,
        };
        let execution = self
            .execute_operation(
                helper_request::Operation::AcquireIngressSocket(operation),
                DescriptorExpectation::Ingress,
            )
            .await?;
        let helper_response::Outcome::IngressSocketReady(ready) = execution.outcome else {
            return Err(HelperClientError::Correlation);
        };
        if !ingress_ready_matches(&ready, authority, socket_handle, identity, &expected_local) {
            return Err(HelperClientError::Correlation);
        }
        let receipt_handle = ready
            .receipt_handle
            .as_slice()
            .try_into()
            .map_err(|_| HelperClientError::Correlation)?;
        if receipt_handle == authority.ingress_handle || receipt_handle == socket_handle {
            return Err(HelperClientError::Correlation);
        }
        let descriptor = execution.descriptor.ok_or(HelperClientError::Correlation)?;
        Ok(AcquiredIngressSocket {
            descriptor,
            authority,
            socket_handle,
            receipt_handle,
            identity,
            local,
        })
    }

    /// Activate only with the complete eight-descriptor receipt set.
    ///
    /// The fixed-size array proves the count at the type boundary. Kind/family coverage, handles,
    /// receipts, runtime correlation and local tuples are checked before any activation request is
    /// sent.
    ///
    /// # Errors
    ///
    /// Returns an error before helper I/O for an incomplete, duplicated or substituted capability
    /// set, or on framing, credentials, timeout and helper rejection.
    pub async fn activate_client_ingress(
        &self,
        prepared: PreparedClientIngress,
        sockets: [AcquiredIngressSocket; REQUIRED_INGRESS_SOCKETS],
    ) -> Result<ActiveClientIngress, ClientIngressActivationFailure> {
        let receipts = match ingress_receipts(&prepared, &sockets) {
            Ok(receipts) => receipts,
            Err(error) => {
                return Err(ClientIngressActivationFailure {
                    error,
                    prepared,
                    sockets,
                });
            }
        };
        let authority = prepared.authority;
        let hard_expires_at_unix = prepared.hard_expires_at_unix;
        let outcome = match self
            .execute(helper_request::Operation::ActivateClientIngress(
                ActivateClientIngressRequest {
                    client_runtime_id: authority.client_runtime_id.to_vec(),
                    ingress_handle: authority.ingress_handle.to_vec(),
                    receipts,
                },
            ))
            .await
        {
            Ok(outcome) => outcome,
            Err(error) => {
                return Err(ClientIngressActivationFailure {
                    error,
                    prepared,
                    sockets,
                });
            }
        };
        let helper_response::Outcome::ActivatedClientIngress(activated) = outcome else {
            return Err(ClientIngressActivationFailure {
                error: HelperClientError::Correlation,
                prepared,
                sockets,
            });
        };
        if activated.client_runtime_id.as_slice() != authority.client_runtime_id
            || activated.ingress_handle.as_slice() != authority.ingress_handle
        {
            return Err(ClientIngressActivationFailure {
                error: HelperClientError::Correlation,
                prepared,
                sockets,
            });
        }
        Ok(ActiveClientIngress {
            authority,
            hard_expires_at_unix,
            sockets,
        })
    }

    /// Acquire one exact source-bound transparent IPv4 or IPv6 UDP reply descriptor for active ingress.
    pub(crate) async fn acquire_ingress_reply_socket(
        &self,
        ingress: &ActiveClientIngress,
        remote: SocketAddr,
        application: SocketAddr,
    ) -> Result<AcquiredIngressReplySocket, HelperClientError> {
        let authority = ingress.authority;
        let operation = AcquireIngressReplySocket {
            client_runtime_id: authority.client_runtime_id.to_vec(),
            ingress_handle: authority.ingress_handle.to_vec(),
            remote: Some(ingress_address(remote)),
            application: Some(ingress_address(application)),
        };
        let execution = self
            .execute_operation(
                helper_request::Operation::AcquireIngressReplySocket(operation),
                DescriptorExpectation::IngressReply,
            )
            .await?;
        let helper_response::Outcome::IngressReplySocketReady(ready) = execution.outcome else {
            return Err(HelperClientError::Correlation);
        };
        if !ingress_reply_ready_matches(&ready, authority, remote, application) {
            return Err(HelperClientError::Correlation);
        }
        let descriptor = execution.descriptor.ok_or(HelperClientError::Correlation)?;
        validate_ingress_udp_reply_socket(&descriptor, remote, application)
            .map_err(HelperClientError::DescriptorValidation)?;
        Ok(AcquiredIngressReplySocket {
            descriptor,
            remote,
            application,
        })
    }

    /// Idempotently destroy one prepared ingress capability.
    ///
    /// # Errors
    ///
    /// Returns an error on framing, credentials, timeout, correlation or helper rejection.
    pub async fn destroy_prepared_client_ingress(
        &self,
        ingress: &PreparedClientIngress,
    ) -> Result<bool, HelperClientError> {
        self.destroy_ingress_authority(ingress.authority).await
    }

    /// Idempotently destroy one activated ingress while retaining all local descriptors.
    ///
    /// This method borrows the capability so a timeout or ambiguous response cannot erase cleanup
    /// authority. After a definitive response, dropping the capability closes all descriptors.
    ///
    /// # Errors
    ///
    /// Returns an error on framing, credentials, timeout, correlation or helper rejection.
    pub async fn destroy_active_client_ingress(
        &self,
        ingress: &ActiveClientIngress,
    ) -> Result<bool, HelperClientError> {
        self.destroy_ingress_authority(ingress.authority).await
    }

    async fn destroy_ingress_authority(
        &self,
        authority: IngressAuthority,
    ) -> Result<bool, HelperClientError> {
        let outcome = self
            .execute(helper_request::Operation::DestroyClientIngress(
                DestroyClientIngressRequest {
                    client_runtime_id: authority.client_runtime_id.to_vec(),
                    ingress_handle: authority.ingress_handle.to_vec(),
                },
            ))
            .await?;
        match outcome {
            helper_response::Outcome::DestroyedClientIngress(value) => Ok(value.existed),
            _ => Err(HelperClientError::Correlation),
        }
    }

    /// Add one derived MPTCP endpoint for a committed path.
    ///
    /// # Errors
    ///
    /// Returns an error on framing, credentials, correlation, timeout or helper rejection.
    pub async fn add_mptcp_endpoint(
        &self,
        value: AddMptcpEndpoint,
    ) -> Result<(), HelperClientError> {
        self.execute_empty(helper_request::Operation::AddMptcpEndpoint(value))
            .await
    }

    /// Remove one exactly owned MPTCP endpoint.
    ///
    /// # Errors
    ///
    /// Returns an error on framing, credentials, correlation, timeout or helper rejection.
    pub async fn remove_mptcp_endpoint(
        &self,
        value: RemoveMptcpEndpoint,
    ) -> Result<(), HelperClientError> {
        self.execute_empty(helper_request::Operation::RemoveMptcpEndpoint(value))
            .await
    }

    /// Acquire one socket created inside an exact committed route namespace.
    ///
    /// The response frame and exactly one close-on-exec descriptor are jointly correlated by a
    /// canonical cryptographic binding. No raw descriptor number is logged or serialized.
    ///
    /// # Errors
    ///
    /// Returns an error on framing, credentials, response/descriptor correlation, ancillary
    /// validation, timeout or helper rejection.
    pub async fn acquire_transport_socket(
        &self,
        value: AcquireTransportSocket,
    ) -> Result<AcquiredTransportSocket, HelperClientError> {
        let expected = TransportSocketReady {
            path_id: value.path_id,
            role: value.role,
            descriptor_kind: value.descriptor_kind,
            local: value.expected_local.clone(),
            remote: value.expected_remote.clone(),
        };
        let execution = self
            .execute_operation(
                helper_request::Operation::AcquireTransportSocket(value),
                DescriptorExpectation::Transport,
            )
            .await?;
        if execution.outcome != helper_response::Outcome::TransportSocketReady(expected.clone()) {
            return Err(HelperClientError::Correlation);
        }
        let descriptor = execution.descriptor.ok_or(HelperClientError::Correlation)?;
        Ok(AcquiredTransportSocket {
            descriptor,
            metadata: expected,
        })
    }

    /// Request idempotent cleanup using the protected process-start token.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe token or helper transport/rejection failure.
    pub async fn cleanup_owned(&self) -> Result<(), HelperClientError> {
        self.cleanup(CleanupScope::AllOwnedResources).await
    }

    /// Destroy every route context while retaining the runtime-long Client ingress capability.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsafe token or helper transport/rejection failure.
    pub async fn cleanup_route_contexts(&self) -> Result<(), HelperClientError> {
        self.cleanup(CleanupScope::RouteContextsOnly).await
    }

    async fn cleanup(&self, scope: CleanupScope) -> Result<(), HelperClientError> {
        let mut token = read_cleanup_token(&self.cleanup_token)?;
        // Ownership moves directly from one zeroizing container into another. `CleanupOwned`
        // zeroizes on Drop, including when the nested async call is never polled or is cancelled.
        let operation = helper_request::Operation::CleanupOwned(CleanupOwned {
            cleanup_token: std::mem::take(&mut *token),
            scope: scope as i32,
        });
        self.execute_empty(operation).await
    }

    async fn execute_empty(
        &self,
        operation: helper_request::Operation,
    ) -> Result<(), HelperClientError> {
        match self.execute(operation).await? {
            helper_response::Outcome::Empty(Empty {}) => Ok(()),
            _ => Err(HelperClientError::Correlation),
        }
    }

    async fn execute(
        &self,
        operation: helper_request::Operation,
    ) -> Result<helper_response::Outcome, HelperClientError> {
        let execution = self
            .execute_operation(operation, DescriptorExpectation::None)
            .await?;
        if execution.descriptor.is_some() {
            return Err(HelperClientError::Correlation);
        }
        Ok(execution.outcome)
    }

    async fn execute_runtime_bound(
        &self,
        owner: &mut RuntimeBoundPreparedLeaseBatch,
        operation: helper_request::Operation,
    ) -> Result<helper_response::Outcome, HelperClientError> {
        self.execute_runtime_bound_inner(owner, operation).await
    }

    async fn execute_runtime_bound_readonly(
        &self,
        owner: &RuntimeBoundPreparedLeaseBatch,
        operation: helper_request::Operation,
    ) -> Result<helper_response::Outcome, HelperClientError> {
        let bind_request_id = random_request_id(&[]);
        let operation_request_id = random_request_id(&[bind_request_id]);
        let (bind_frame, bind_digest) = runtime_bind_frame(bind_request_id)?;
        let operation_request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: operation_request_id.to_vec(),
            operation: Some(operation),
        };
        let operation_digest =
            operation_digest(&operation_request).map_err(HelperClientError::Protocol)?;
        let operation_frame = Zeroizing::new(
            encode_request(&operation_request).map_err(HelperClientError::Protocol)?,
        );
        timeout_at(Instant::now() + HELPER_TIMEOUT, async {
            let mut stream = self.connect_authenticated().await?;
            self.bind_expected_runtime(
                &mut stream,
                owner,
                bind_frame.as_slice(),
                &bind_request_id,
                &bind_digest,
            )
            .await?;
            exchange_request(
                &mut stream,
                operation_frame.as_slice(),
                &operation_request_id,
                &operation_digest,
            )
            .await
        })
        .await
        .map_err(|_| HelperClientError::Timeout)?
    }

    async fn execute_runtime_bound_inner(
        &self,
        owner: &mut RuntimeBoundPreparedLeaseBatch,
        operation: helper_request::Operation,
    ) -> Result<helper_response::Outcome, HelperClientError> {
        let bind_request_id = random_request_id(&[]);
        let operation_request_id = random_request_id(&[bind_request_id]);
        let (bind_frame, bind_digest) = runtime_bind_frame(bind_request_id)?;
        let operation_request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: operation_request_id.to_vec(),
            operation: Some(operation),
        };
        let operation_digest =
            operation_digest(&operation_request).map_err(HelperClientError::Protocol)?;
        let operation_frame = Zeroizing::new(
            encode_request(&operation_request).map_err(HelperClientError::Protocol)?,
        );
        timeout_at(Instant::now() + HELPER_TIMEOUT, async {
            let mut stream = self.connect_authenticated().await?;
            self.bind_expected_runtime(
                &mut stream,
                owner,
                bind_frame.as_slice(),
                &bind_request_id,
                &bind_digest,
            )
            .await?;
            match operation_request.operation.as_ref() {
                Some(helper_request::Operation::ActivateLeaseBatch(value)) => {
                    owner.begin_activation(value)?;
                }
                Some(helper_request::Operation::CommitLeaseBatch(value)) => {
                    owner.begin_commit(value)?;
                }
                _ => return Err(HelperClientError::Correlation),
            }
            exchange_request(
                &mut stream,
                operation_frame.as_slice(),
                &operation_request_id,
                &operation_digest,
            )
            .await
        })
        .await
        .map_err(|_| HelperClientError::Timeout)?
    }

    async fn connect_authenticated(&self) -> Result<UnixStream, HelperClientError> {
        let stream = UnixStream::connect(&self.socket)
            .await
            .map_err(HelperClientError::Io)?;
        let credentials = stream.peer_cred().map_err(HelperClientError::Io)?;
        validate_server_uid(credentials.uid(), self.expected_server_uid)?;
        Ok(stream)
    }

    async fn bind_expected_runtime(
        &self,
        stream: &mut UnixStream,
        owner: &RuntimeBoundPreparedLeaseBatch,
        bind_frame: &[u8],
        bind_request_id: &[u8; 16],
        bind_digest: &[u8; 32],
    ) -> Result<(), HelperClientError> {
        let outcome = exchange_request(stream, bind_frame, bind_request_id, bind_digest).await?;
        let helper_response::Outcome::HelperRuntime(HelperRuntime { helper_runtime_id }) = outcome
        else {
            return Err(HelperClientError::Correlation);
        };
        if owner
            .helper_runtime_id
            .ct_eq(&helper_runtime_id)
            .unwrap_u8()
            != 1
        {
            return Err(HelperClientError::RuntimeChanged);
        }
        Ok(())
    }

    async fn execute_operation(
        &self,
        operation: helper_request::Operation,
        descriptor_expectation: DescriptorExpectation,
    ) -> Result<ClientExecution, HelperClientError> {
        let mut request_id = [0_u8; 16];
        OsRng.fill_bytes(&mut request_id);
        let mut request = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request_id.to_vec(),
            operation: Some(operation),
        };
        // A nested cleanup operation is itself a Drop guard, so either fallible call below may
        // return without leaving its request-owned token allocation unwiped.
        let expected_digest = operation_digest(&request).map_err(HelperClientError::Protocol)?;
        let mut frame =
            Zeroizing::new(encode_request(&request).map_err(HelperClientError::Protocol)?);
        zeroize_cleanup_token(&mut request);

        let execution = timeout(HELPER_TIMEOUT, async {
            let mut stream = UnixStream::connect(&self.socket)
                .await
                .map_err(HelperClientError::Io)?;
            let credentials = stream.peer_cred().map_err(HelperClientError::Io)?;
            validate_server_uid(credentials.uid(), self.expected_server_uid)?;
            stream
                .write_all(frame.as_slice())
                .await
                .map_err(HelperClientError::Io)?;
            stream.flush().await.map_err(HelperClientError::Io)?;
            let response = read_response(&mut stream)
                .await
                .map_err(HelperClientError::Protocol)?;
            validate_correlation(&response, &request_id, &expected_digest)?;
            let result = HelperResult::try_from(response.result)
                .map_err(|_| HelperClientError::Correlation)?;
            if result != HelperResult::Ok {
                return Err(HelperClientError::Rejected(result));
            }
            let actual_descriptor = match response.outcome.as_ref() {
                Some(helper_response::Outcome::TransportSocketReady(_)) => {
                    DescriptorExpectation::Transport
                }
                Some(helper_response::Outcome::IngressSocketReady(_)) => {
                    DescriptorExpectation::Ingress
                }
                Some(helper_response::Outcome::IngressReplySocketReady(_)) => {
                    DescriptorExpectation::IngressReply
                }
                _ => DescriptorExpectation::None,
            };
            if actual_descriptor != descriptor_expectation {
                return Err(HelperClientError::Correlation);
            }
            let descriptor = if descriptor_expectation == DescriptorExpectation::None {
                None
            } else {
                let binding =
                    descriptor_fd_binding(&response).map_err(HelperClientError::Protocol)?;
                Some(
                    receive_bound_descriptor(&stream, &binding)
                        .await
                        .map_err(HelperClientError::DescriptorHandoff)?,
                )
            };
            let outcome = response.outcome.ok_or(HelperClientError::Correlation)?;
            let _ = stream.shutdown().await;
            Ok(ClientExecution {
                outcome,
                descriptor,
            })
        })
        .await
        .map_err(|_| HelperClientError::Timeout)??;
        frame.zeroize();
        Ok(execution)
    }
}

fn runtime_bind_frame(
    request_id: [u8; 16],
) -> Result<(Zeroizing<Vec<u8>>, [u8; 32]), HelperClientError> {
    let request = HelperRequest {
        protocol_version: HELPER_PROTOCOL_VERSION,
        request_id: request_id.to_vec(),
        operation: Some(helper_request::Operation::BindHelperRuntime(
            BindHelperRuntime {
                prepare_intent: None,
            },
        )),
    };
    let digest = operation_digest(&request).map_err(HelperClientError::Protocol)?;
    let frame = Zeroizing::new(encode_request(&request).map_err(HelperClientError::Protocol)?);
    Ok((frame, digest))
}

fn random_request_id(excluded: &[[u8; 16]]) -> [u8; 16] {
    loop {
        let mut request_id = [0_u8; 16];
        OsRng.fill_bytes(&mut request_id);
        if request_id.iter().any(|byte| *byte != 0) && !excluded.contains(&request_id) {
            return request_id;
        }
    }
}

async fn exchange_request(
    stream: &mut UnixStream,
    frame: &[u8],
    request_id: &[u8; 16],
    expected_digest: &[u8; 32],
) -> Result<helper_response::Outcome, HelperClientError> {
    stream
        .write_all(frame)
        .await
        .map_err(HelperClientError::Io)?;
    stream.flush().await.map_err(HelperClientError::Io)?;
    let response = read_response(stream)
        .await
        .map_err(HelperClientError::Protocol)?;
    validate_correlation(&response, request_id, expected_digest)?;
    let result =
        HelperResult::try_from(response.result).map_err(|_| HelperClientError::Correlation)?;
    if result != HelperResult::Ok {
        return Err(HelperClientError::Rejected(result));
    }
    response.outcome.ok_or(HelperClientError::Correlation)
}

fn classify_prepare_failure(
    source: HelperClientError,
    dispatch_state: PrepareDispatchState,
) -> PrepareLeaseBatchFailure {
    match dispatch_state {
        PrepareDispatchState::PreDispatch | PrepareDispatchState::Armed(_) => {
            PrepareLeaseBatchFailure::Definitive(source)
        }
        PrepareDispatchState::Dispatched(authority) => {
            PrepareLeaseBatchFailure::Ambiguous { source, authority }
        }
    }
}

fn prepared_client_ingress(
    value: PreparedClientIngressResponse,
    expected_runtime: [u8; 16],
    setup_expires_at_unix: u64,
    requested_hard_expires_at_unix: u64,
) -> Result<PreparedClientIngress, HelperClientError> {
    if value.client_runtime_id.as_slice() != expected_runtime
        || value.hard_expires_at_unix < setup_expires_at_unix
        || value.hard_expires_at_unix > requested_hard_expires_at_unix
    {
        return Err(HelperClientError::Correlation);
    }
    let ingress_handle = value
        .ingress_handle
        .as_slice()
        .try_into()
        .map_err(|_| HelperClientError::Correlation)?;
    let mut handles = BTreeSet::from([ingress_handle]);
    let mut sockets = BTreeMap::new();
    for socket in value.sockets {
        let PreparedIngressSocket {
            socket_handle,
            descriptor_kind,
            address_family,
            local,
        } = socket;
        let identity = client_ingress_identity(descriptor_kind, address_family)?;
        let wire_local = local.ok_or(HelperClientError::Correlation)?;
        let local = client_ingress_local(&wire_local, identity.family)?;
        let socket_handle = socket_handle
            .as_slice()
            .try_into()
            .map_err(|_| HelperClientError::Correlation)?;
        if !handles.insert(socket_handle) {
            return Err(HelperClientError::Correlation);
        }
        if sockets
            .insert(
                identity,
                PreparedIngressSocketAuthority {
                    socket_handle,
                    wire_local,
                    local,
                    acquisition_started: false,
                },
            )
            .is_some()
        {
            return Err(HelperClientError::Correlation);
        }
    }
    if sockets.len() != REQUIRED_INGRESS_SOCKETS {
        return Err(HelperClientError::Correlation);
    }
    Ok(PreparedClientIngress {
        authority: IngressAuthority {
            client_runtime_id: expected_runtime,
            ingress_handle,
        },
        hard_expires_at_unix: value.hard_expires_at_unix,
        sockets,
    })
}

fn client_ingress_identity(
    descriptor_kind: i32,
    address_family: i32,
) -> Result<ClientIngressSocketIdentity, HelperClientError> {
    let kind = match WireIngressSocketKind::try_from(descriptor_kind)
        .map_err(|_| HelperClientError::Correlation)?
    {
        WireIngressSocketKind::TransparentTcpListener => {
            ClientIngressSocketKind::TransparentTcpListener
        }
        WireIngressSocketKind::TransparentUdp => ClientIngressSocketKind::TransparentUdp,
        WireIngressSocketKind::DnsTcpListener => ClientIngressSocketKind::DnsTcpListener,
        WireIngressSocketKind::DnsUdp => ClientIngressSocketKind::DnsUdp,
        WireIngressSocketKind::Unspecified => return Err(HelperClientError::Correlation),
    };
    let family = match WireIngressSocketFamily::try_from(address_family)
        .map_err(|_| HelperClientError::Correlation)?
    {
        WireIngressSocketFamily::Ipv4 => ClientIngressSocketFamily::Ipv4,
        WireIngressSocketFamily::Ipv6 => ClientIngressSocketFamily::Ipv6,
        WireIngressSocketFamily::Unspecified => return Err(HelperClientError::Correlation),
    };
    Ok(ClientIngressSocketIdentity::new(kind, family))
}

fn client_ingress_local(
    value: &IngressSocketAddress,
    family: ClientIngressSocketFamily,
) -> Result<SocketAddr, HelperClientError> {
    let port = u16::try_from(value.port).map_err(|_| HelperClientError::Correlation)?;
    if port == 0 {
        return Err(HelperClientError::Correlation);
    }
    match family {
        ClientIngressSocketFamily::Ipv4 => {
            let address: [u8; 4] = value
                .address
                .as_slice()
                .try_into()
                .map_err(|_| HelperClientError::Correlation)?;
            let address = std::net::Ipv4Addr::from(address);
            if !address.is_unspecified() {
                return Err(HelperClientError::Correlation);
            }
            Ok(SocketAddr::V4(SocketAddrV4::new(address, port)))
        }
        ClientIngressSocketFamily::Ipv6 => {
            let address: [u8; 16] = value
                .address
                .as_slice()
                .try_into()
                .map_err(|_| HelperClientError::Correlation)?;
            let address = std::net::Ipv6Addr::from(address);
            if !address.is_unspecified() {
                return Err(HelperClientError::Correlation);
            }
            Ok(SocketAddr::V6(std::net::SocketAddrV6::new(
                address, port, 0, 0,
            )))
        }
    }
}

fn ingress_ready_matches(
    ready: &IngressSocketReady,
    authority: IngressAuthority,
    socket_handle: [u8; 32],
    identity: ClientIngressSocketIdentity,
    expected_local: &IngressSocketAddress,
) -> bool {
    ready.client_runtime_id.as_slice() == authority.client_runtime_id
        && ready.ingress_handle.as_slice() == authority.ingress_handle
        && ready.socket_handle.as_slice() == socket_handle
        && ready.descriptor_kind == wire_ingress_kind(identity.kind) as i32
        && ready.address_family == wire_ingress_family(identity.family) as i32
        && ready.local.as_ref() == Some(expected_local)
}

fn ingress_address(value: SocketAddr) -> IngressSocketAddress {
    IngressSocketAddress {
        address: match value.ip() {
            std::net::IpAddr::V4(address) => address.octets().to_vec(),
            std::net::IpAddr::V6(address) => address.octets().to_vec(),
        },
        port: u32::from(value.port()),
    }
}

fn ingress_reply_ready_matches(
    ready: &IngressReplySocketReady,
    authority: IngressAuthority,
    remote: SocketAddr,
    application: SocketAddr,
) -> bool {
    ready.client_runtime_id.as_slice() == authority.client_runtime_id
        && ready.ingress_handle.as_slice() == authority.ingress_handle
        && ready.remote.as_ref() == Some(&ingress_address(remote))
        && ready.application.as_ref() == Some(&ingress_address(application))
}

fn ingress_receipts(
    prepared: &PreparedClientIngress,
    sockets: &[AcquiredIngressSocket; REQUIRED_INGRESS_SOCKETS],
) -> Result<Vec<IngressSocketReceipt>, HelperClientError> {
    if prepared.sockets.len() != REQUIRED_INGRESS_SOCKETS {
        return Err(HelperClientError::Correlation);
    }
    let mut identities = BTreeSet::new();
    let mut all_handles = BTreeSet::from([prepared.authority.ingress_handle]);
    for socket in sockets {
        let expected = prepared
            .sockets
            .get(&socket.identity)
            .ok_or(HelperClientError::Correlation)?;
        if socket.authority != prepared.authority
            || socket.socket_handle != expected.socket_handle
            || socket.local != expected.local
            || !expected.acquisition_started
            || !identities.insert(socket.identity)
            || !all_handles.insert(socket.socket_handle)
            || !all_handles.insert(socket.receipt_handle)
        {
            return Err(HelperClientError::Correlation);
        }
    }
    if identities != prepared.sockets.keys().copied().collect::<BTreeSet<_>>() {
        return Err(HelperClientError::Correlation);
    }
    let mut ordered = sockets.iter().collect::<Vec<_>>();
    ordered.sort_by_key(|socket| socket.identity);
    Ok(ordered
        .into_iter()
        .map(|socket| IngressSocketReceipt {
            socket_handle: socket.socket_handle.to_vec(),
            receipt_handle: socket.receipt_handle.to_vec(),
            descriptor_kind: wire_ingress_kind(socket.identity.kind) as i32,
            address_family: wire_ingress_family(socket.identity.family) as i32,
        })
        .collect())
}

const fn wire_ingress_kind(value: ClientIngressSocketKind) -> WireIngressSocketKind {
    match value {
        ClientIngressSocketKind::TransparentTcpListener => {
            WireIngressSocketKind::TransparentTcpListener
        }
        ClientIngressSocketKind::TransparentUdp => WireIngressSocketKind::TransparentUdp,
        ClientIngressSocketKind::DnsTcpListener => WireIngressSocketKind::DnsTcpListener,
        ClientIngressSocketKind::DnsUdp => WireIngressSocketKind::DnsUdp,
    }
}

const fn wire_ingress_family(value: ClientIngressSocketFamily) -> WireIngressSocketFamily {
    match value {
        ClientIngressSocketFamily::Ipv4 => WireIngressSocketFamily::Ipv4,
        ClientIngressSocketFamily::Ipv6 => WireIngressSocketFamily::Ipv6,
    }
}

const fn kernel_ingress_kind(value: ClientIngressSocketKind) -> KernelIngressSocketKind {
    match value {
        ClientIngressSocketKind::TransparentTcpListener => {
            KernelIngressSocketKind::TransparentTcpListener
        }
        ClientIngressSocketKind::TransparentUdp => KernelIngressSocketKind::TransparentUdp,
        ClientIngressSocketKind::DnsTcpListener => KernelIngressSocketKind::DnsTcpListener,
        ClientIngressSocketKind::DnsUdp => KernelIngressSocketKind::DnsUdp,
    }
}

const fn kernel_ingress_family(value: ClientIngressSocketFamily) -> KernelIngressSocketFamily {
    match value {
        ClientIngressSocketFamily::Ipv4 => KernelIngressSocketFamily::Ipv4,
        ClientIngressSocketFamily::Ipv6 => KernelIngressSocketFamily::Ipv6,
    }
}

fn validate_correlation(
    response: &HelperResponse,
    request_id: &[u8; 16],
    expected_digest: &[u8; 32],
) -> Result<(), HelperClientError> {
    if response.protocol_version != HELPER_PROTOCOL_VERSION
        || response.request_id.as_slice() != request_id
        || response.operation_digest.as_slice() != expected_digest
    {
        return Err(HelperClientError::Correlation);
    }
    Ok(())
}

async fn receive_bound_descriptor(stream: &UnixStream, binding: &[u8]) -> std::io::Result<OwnedFd> {
    loop {
        stream.readable().await?;
        match stream.try_io(Interest::READABLE, || {
            receive_fd_with_binding(stream, binding)
        }) {
            Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
            result => return result,
        }
    }
}

fn validate_server_uid(actual: u32, expected: u32) -> Result<(), HelperClientError> {
    if actual != expected {
        return Err(HelperClientError::UntrustedServer);
    }
    Ok(())
}

fn zeroize_cleanup_token(request: &mut HelperRequest) {
    if let Some(helper_request::Operation::CleanupOwned(cleanup)) = request.operation.as_mut() {
        cleanup.cleanup_token.zeroize();
    }
}

fn read_cleanup_token(path: &Path) -> Result<Zeroizing<Vec<u8>>, HelperClientError> {
    let metadata = fs::symlink_metadata(path).map_err(HelperClientError::Io)?;
    if !metadata.file_type().is_file()
        || metadata.file_type().is_symlink()
        || metadata.nlink() != 1
        || !matches!(metadata.mode() & 0o777, 0o600 | 0o640)
        || metadata.len() != CLEANUP_TOKEN_BYTES as u64
    {
        return Err(HelperClientError::UnsafeToken);
    }
    let mut file = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_CLOEXEC | libc::O_NOFOLLOW)
        .open(path)
        .map_err(HelperClientError::Io)?;
    let mut token = Zeroizing::new(Vec::with_capacity(CLEANUP_TOKEN_BYTES));
    file.read_to_end(&mut token)
        .map_err(HelperClientError::Io)?;
    if token.len() != CLEANUP_TOKEN_BYTES {
        return Err(HelperClientError::UnsafeToken);
    }
    Ok(token)
}

/// Stable helper-client failure categories.
#[derive(Debug, Error)]
pub enum HelperClientError {
    /// Socket or token I/O failed.
    #[error("helper I/O is unavailable")]
    Io(#[source] std::io::Error),
    /// Token type, mode, links or length was unsafe.
    #[error("helper cleanup token is unsafe")]
    UnsafeToken,
    /// Typed framing or response validation failed.
    #[error("helper protocol validation failed")]
    Protocol(#[source] volparossa_routing::HelperProtocolError),
    /// Ancillary descriptor count, flags, CLOEXEC state or canonical binding was invalid.
    #[error("helper descriptor handoff failed")]
    DescriptorHandoff(#[source] std::io::Error),
    /// Kernel type, family, flags, bind tuple or transparent socket options did not match.
    #[error("helper ingress descriptor kernel validation failed")]
    DescriptorValidation(#[source] std::io::Error),
    /// A one-shot local ingress acquisition capability was already consumed.
    #[error("helper ingress acquisition capability was already used")]
    CapabilityAlreadyUsed,
    /// Fixed operation deadline elapsed.
    #[error("helper request timed out")]
    Timeout,
    /// Response did not bind to this exact request and expected typed outcome.
    #[error("helper response correlation failed")]
    Correlation,
    /// Connected socket endpoint was not owned by the expected root helper.
    #[error("helper server credentials are untrusted")]
    UntrustedServer,
    /// The helper process identity changed before exact reconciliation.
    #[error("helper runtime identity changed")]
    RuntimeChanged,
    /// Helper safely rejected the operation.
    #[error("helper rejected the operation with {0:?}")]
    Rejected(HelperResult),
}

#[cfg(test)]
mod tests {
    use std::{
        fs::Permissions,
        io::{Read, Write},
        os::fd::OwnedFd,
        os::unix::{fs::PermissionsExt, net::UnixStream as StdUnixStream},
        time::{Duration, Instant as StdInstant},
    };

    use nix::fcntl::{FcntlArg, FdFlag, fcntl};
    use nix::unistd::{geteuid, write as fd_write};
    use tokio::{io::AsyncReadExt, net::UnixListener};
    use volparossa_linux_uapi::send_fd_with_binding;
    use volparossa_routing::{
        AcquireTransportSocket, CommittedLease, ContextRole, HelperResponse, LeaseActivation,
        LeaseCommit, LeasePlan, PreparedLease, PublicUdpEndpoint, TransportSocketAddress,
        TransportSocketKind, TransportSocketReady, UnderlayEvidence, WireguardRole,
        encode_response, ingress_fd_binding, read_request, transport_fd_binding,
    };

    use super::*;

    async fn serve_once(
        listener: UnixListener,
        expected: fn(&helper_request::Operation) -> bool,
        outcome: helper_response::Outcome,
    ) {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let request = read_request(&mut stream).await.expect("request");
        assert!(request.operation.as_ref().is_some_and(expected));
        let response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "TEST_OK".to_owned(),
            operation_digest: operation_digest(&request).expect("digest").to_vec(),
            outcome: Some(outcome),
        };
        stream
            .write_all(&encode_response(&response).expect("response"))
            .await
            .expect("write");
    }

    async fn serve_prepare_sequence(listener: UnixListener, prepared: PreparedLeaseBatch) {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let bind = read_request(&mut stream).await.expect("Bind request");
        let Some(helper_request::Operation::BindHelperRuntime(BindHelperRuntime {
            prepare_intent: Some(intent),
        })) = bind.operation.as_ref()
        else {
            panic!("Bind(Some PrepareIntent)");
        };
        let bind_response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: bind.request_id.clone(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "TEST_RUNTIME".to_owned(),
            operation_digest: operation_digest(&bind).expect("Bind digest").to_vec(),
            outcome: Some(helper_response::Outcome::HelperRuntime(HelperRuntime {
                helper_runtime_id: vec![0xa5; 32],
            })),
        };
        stream
            .write_all(&encode_response(&bind_response).expect("Bind response"))
            .await
            .expect("write Bind response");

        let prepare = read_request(&mut stream).await.expect("Prepare request");
        let Some(helper_request::Operation::PrepareLeaseBatch(value)) = prepare.operation.as_ref()
        else {
            panic!("Prepare");
        };
        assert_ne!(bind.request_id, prepare.request_id);
        assert_eq!(intent.route_context_id, value.route_context_id);
        assert_eq!(intent.prepare_request_id, prepare.request_id);
        assert_eq!(
            intent.prepare_operation_digest,
            operation_digest(&prepare).expect("Prepare digest")
        );
        assert_eq!(intent.setup_expires_at_unix, value.setup_expires_at_unix);
        assert_eq!(intent.hard_expires_at_unix, value.hard_expires_at_unix);
        assert_eq!(
            intent.closed_plan.as_ref(),
            Some(&closed_plan_from_prepare(value)),
            "Bind must carry the exact role and canonical lease sequence dispatched by Prepare"
        );

        let prepare_response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: prepare.request_id.clone(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "TEST_PREPARED".to_owned(),
            operation_digest: operation_digest(&prepare).expect("Prepare digest").to_vec(),
            outcome: Some(helper_response::Outcome::PreparedLeaseBatch(prepared)),
        };
        stream
            .write_all(&encode_response(&prepare_response).expect("Prepare response"))
            .await
            .expect("write Prepare response");
    }

    fn prepare_sequence_value() -> PrepareLeaseBatch {
        PrepareLeaseBatch {
            route_context_id: vec![7; 16],
            role: ContextRole::Client as i32,
            mptcp_accepted_addrs: 4,
            mptcp_subflows: 4,
            leases: vec![LeasePlan {
                path_id: 1,
                role: WireguardRole::Client as i32,
            }],
            setup_expires_at_unix: 120,
            hard_expires_at_unix: 900,
            traversal_hints: Vec::new(),
        }
    }

    #[test]
    fn closed_prepare_plan_preserves_role_and_every_canonical_lease_identity() {
        let value = PrepareLeaseBatch {
            route_context_id: vec![7; 16],
            role: ContextRole::Relay as i32,
            mptcp_accepted_addrs: 4,
            mptcp_subflows: 4,
            leases: vec![
                LeasePlan {
                    path_id: 1,
                    role: WireguardRole::RelayClient as i32,
                },
                LeasePlan {
                    path_id: 1,
                    role: WireguardRole::RelayExit as i32,
                },
                LeasePlan {
                    path_id: 2,
                    role: WireguardRole::RelayClient as i32,
                },
                LeasePlan {
                    path_id: 2,
                    role: WireguardRole::RelayExit as i32,
                },
            ],
            setup_expires_at_unix: 120,
            hard_expires_at_unix: 900,
            traversal_hints: Vec::new(),
        };
        let prepare = HelperRequest {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: vec![0xb1; 16],
            operation: Some(helper_request::Operation::PrepareLeaseBatch(value.clone())),
        };
        encode_request(&prepare).expect("canonical relay Prepare");

        let plan = closed_plan_from_prepare(&value);
        assert_eq!(plan.context_role, value.role);
        assert_eq!(plan.leases, value.leases);

        let mut wrong_context_role = value.clone();
        wrong_context_role.role = ContextRole::Client as i32;
        assert_ne!(plan, closed_plan_from_prepare(&wrong_context_role));

        let mut missing_lease = value.clone();
        missing_lease.leases.pop();
        assert_ne!(plan, closed_plan_from_prepare(&missing_lease));

        let mut reordered = value.clone();
        reordered.leases.swap(0, 1);
        assert_ne!(plan, closed_plan_from_prepare(&reordered));

        let mut substituted_identity = value;
        substituted_identity.leases[2].path_id = 3;
        assert_ne!(plan, closed_plan_from_prepare(&substituted_identity));
    }

    async fn write_test_response(
        stream: &mut UnixStream,
        request: &HelperRequest,
        result: HelperResult,
        outcome: Option<helper_response::Outcome>,
    ) {
        let response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: result as i32,
            diagnostic_code: "TEST_RESPONSE".to_owned(),
            operation_digest: operation_digest(request).expect("request digest").to_vec(),
            outcome,
        };
        stream
            .write_all(&encode_response(&response).expect("response"))
            .await
            .expect("write response");
    }

    async fn read_bind_some(stream: &mut UnixStream) -> HelperRequest {
        let bind = read_request(stream).await.expect("Bind request");
        assert!(matches!(
            bind.operation.as_ref(),
            Some(helper_request::Operation::BindHelperRuntime(
                BindHelperRuntime {
                    prepare_intent: Some(_),
                }
            ))
        ));
        bind
    }

    async fn write_runtime(stream: &mut UnixStream, bind: &HelperRequest, runtime: [u8; 32]) {
        write_test_response(
            stream,
            bind,
            HelperResult::Ok,
            Some(helper_response::Outcome::HelperRuntime(HelperRuntime {
                helper_runtime_id: runtime.to_vec(),
            })),
        )
        .await;
    }

    async fn assert_no_followup_frame(stream: &mut UnixStream) {
        let mut byte = [0_u8; 1];
        let followup = timeout(Duration::from_millis(250), stream.read(&mut byte)).await;
        assert!(
            matches!(followup, Ok(Ok(0))),
            "client must close at exact EOF without sending any second-frame byte"
        );
    }

    #[derive(Clone, Copy)]
    enum DescriptorTestMode {
        Exact,
        WrongBinding,
        Missing,
        WrongCorrelation,
    }

    async fn send_test_descriptor(
        stream: &UnixStream,
        descriptor: &OwnedFd,
        binding: &[u8],
    ) -> std::io::Result<()> {
        loop {
            stream.writable().await?;
            match stream.try_io(Interest::WRITABLE, || {
                send_fd_with_binding(stream, descriptor, binding)
            }) {
                Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {}
                result => return result,
            }
        }
    }

    async fn serve_transport_once(
        listener: UnixListener,
        descriptor: Option<OwnedFd>,
        mode: DescriptorTestMode,
    ) {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let request = read_request(&mut stream).await.expect("request");
        let Some(helper_request::Operation::AcquireTransportSocket(value)) =
            request.operation.as_ref()
        else {
            panic!("acquire operation");
        };
        let ready = TransportSocketReady {
            path_id: value.path_id,
            role: value.role,
            descriptor_kind: value.descriptor_kind,
            local: value.expected_local.clone(),
            remote: value.expected_remote.clone(),
        };
        let mut response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "TRANSPORT_SOCKET_READY".to_owned(),
            operation_digest: operation_digest(&request).expect("digest").to_vec(),
            outcome: Some(helper_response::Outcome::TransportSocketReady(ready)),
        };
        if matches!(mode, DescriptorTestMode::WrongCorrelation) {
            response.request_id[0] ^= 1;
        }
        stream
            .write_all(&encode_response(&response).expect("response"))
            .await
            .expect("write response");
        stream.flush().await.expect("flush response");
        if let Some(descriptor) = descriptor {
            let mut binding = transport_fd_binding(&response).expect("binding");
            if matches!(mode, DescriptorTestMode::WrongBinding) {
                binding[0] ^= 1;
            }
            let _ = send_test_descriptor(&stream, &descriptor, &binding).await;
        } else {
            assert!(matches!(mode, DescriptorTestMode::Missing));
        }
    }

    fn client_ingress_identities() -> [ClientIngressSocketIdentity; REQUIRED_INGRESS_SOCKETS] {
        [
            ClientIngressSocketIdentity::new(
                ClientIngressSocketKind::TransparentTcpListener,
                ClientIngressSocketFamily::Ipv4,
            ),
            ClientIngressSocketIdentity::new(
                ClientIngressSocketKind::TransparentTcpListener,
                ClientIngressSocketFamily::Ipv6,
            ),
            ClientIngressSocketIdentity::new(
                ClientIngressSocketKind::TransparentUdp,
                ClientIngressSocketFamily::Ipv4,
            ),
            ClientIngressSocketIdentity::new(
                ClientIngressSocketKind::TransparentUdp,
                ClientIngressSocketFamily::Ipv6,
            ),
            ClientIngressSocketIdentity::new(
                ClientIngressSocketKind::DnsTcpListener,
                ClientIngressSocketFamily::Ipv4,
            ),
            ClientIngressSocketIdentity::new(
                ClientIngressSocketKind::DnsTcpListener,
                ClientIngressSocketFamily::Ipv6,
            ),
            ClientIngressSocketIdentity::new(
                ClientIngressSocketKind::DnsUdp,
                ClientIngressSocketFamily::Ipv4,
            ),
            ClientIngressSocketIdentity::new(
                ClientIngressSocketKind::DnsUdp,
                ClientIngressSocketFamily::Ipv6,
            ),
        ]
    }

    fn ingress_local(identity: ClientIngressSocketIdentity, port: u32) -> IngressSocketAddress {
        IngressSocketAddress {
            address: match identity.family {
                ClientIngressSocketFamily::Ipv4 => vec![0; 4],
                ClientIngressSocketFamily::Ipv6 => vec![0; 16],
            },
            port,
        }
    }

    fn prepared_ingress_wire() -> PreparedClientIngressResponse {
        PreparedClientIngressResponse {
            client_runtime_id: vec![7; 16],
            ingress_handle: vec![8; 32],
            sockets: client_ingress_identities()
                .into_iter()
                .enumerate()
                .map(|(index, identity)| PreparedIngressSocket {
                    socket_handle: vec![u8::try_from(index + 11).expect("bounded handle"); 32],
                    descriptor_kind: wire_ingress_kind(identity.kind) as i32,
                    address_family: wire_ingress_family(identity.family) as i32,
                    local: Some(ingress_local(
                        identity,
                        42_000 + u32::try_from(index).expect("bounded port"),
                    )),
                })
                .collect(),
            hard_expires_at_unix: 900,
        }
    }

    fn prepared_ingress_capability() -> PreparedClientIngress {
        prepared_client_ingress(prepared_ingress_wire(), [7; 16], 120, 900)
            .expect("prepared capability")
    }

    fn acquired_ingress_set(
        prepared: &mut PreparedClientIngress,
    ) -> (
        [AcquiredIngressSocket; REQUIRED_INGRESS_SOCKETS],
        Vec<StdUnixStream>,
    ) {
        let authority = prepared.authority;
        let mut sockets = Vec::with_capacity(REQUIRED_INGRESS_SOCKETS);
        let mut peers = Vec::with_capacity(REQUIRED_INGRESS_SOCKETS);
        for (index, identity) in client_ingress_identities().into_iter().enumerate() {
            let prepared_socket = prepared
                .sockets
                .get_mut(&identity)
                .expect("prepared identity");
            prepared_socket.acquisition_started = true;
            let (descriptor, peer) = StdUnixStream::pair().expect("descriptor pair");
            sockets.push(AcquiredIngressSocket {
                descriptor: OwnedFd::from(descriptor),
                authority,
                socket_handle: prepared_socket.socket_handle,
                receipt_handle: [u8::try_from(index + 21).expect("bounded receipt"); 32],
                identity,
                local: prepared_socket.local,
            });
            peers.push(peer);
        }
        let Ok(sockets) = sockets.try_into() else {
            panic!("exact ingress descriptor count");
        };
        (sockets, peers)
    }

    async fn serve_ingress_once(
        listener: UnixListener,
        descriptor: OwnedFd,
        local: IngressSocketAddress,
    ) {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let request = read_request(&mut stream).await.expect("request");
        let Some(helper_request::Operation::AcquireIngressSocket(value)) =
            request.operation.as_ref()
        else {
            panic!("ingress acquire operation");
        };
        let ready = IngressSocketReady {
            client_runtime_id: value.client_runtime_id.clone(),
            ingress_handle: value.ingress_handle.clone(),
            socket_handle: value.socket_handle.clone(),
            receipt_handle: vec![21; 32],
            descriptor_kind: value.descriptor_kind,
            address_family: value.address_family,
            local: Some(local),
        };
        let response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "INGRESS_SOCKET_READY".to_owned(),
            operation_digest: operation_digest(&request).expect("digest").to_vec(),
            outcome: Some(helper_response::Outcome::IngressSocketReady(ready)),
        };
        stream
            .write_all(&encode_response(&response).expect("response"))
            .await
            .expect("write response");
        stream.flush().await.expect("flush response");
        let binding = ingress_fd_binding(&response).expect("binding");
        send_test_descriptor(&stream, &descriptor, &binding)
            .await
            .expect("send descriptor");
    }

    async fn serve_activation_once(listener: UnixListener) {
        let (mut stream, _) = listener.accept().await.expect("accept");
        let request = read_request(&mut stream).await.expect("request");
        let Some(helper_request::Operation::ActivateClientIngress(value)) =
            request.operation.as_ref()
        else {
            panic!("ingress activation operation");
        };
        assert_eq!(value.receipts.len(), REQUIRED_INGRESS_SOCKETS);
        let mut all_handles = BTreeSet::from([value.ingress_handle.as_slice()]);
        let mut identities = BTreeSet::new();
        for receipt in &value.receipts {
            assert!(all_handles.insert(receipt.socket_handle.as_slice()));
            assert!(all_handles.insert(receipt.receipt_handle.as_slice()));
            assert!(identities.insert((receipt.descriptor_kind, receipt.address_family)));
        }
        assert_eq!(all_handles.len(), 1 + (REQUIRED_INGRESS_SOCKETS * 2));
        assert_eq!(identities.len(), REQUIRED_INGRESS_SOCKETS);
        let response = HelperResponse {
            protocol_version: HELPER_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: HelperResult::Ok as i32,
            diagnostic_code: "INGRESS_ACTIVATED".to_owned(),
            operation_digest: operation_digest(&request).expect("digest").to_vec(),
            outcome: Some(helper_response::Outcome::ActivatedClientIngress(
                volparossa_routing::ActivatedClientIngress {
                    client_runtime_id: value.client_runtime_id.clone(),
                    ingress_handle: value.ingress_handle.clone(),
                },
            )),
        };
        stream
            .write_all(&encode_response(&response).expect("response"))
            .await
            .expect("write response");
    }

    fn transport_address(address: [u8; 4], port: u32) -> TransportSocketAddress {
        TransportSocketAddress {
            address: address.to_vec(),
            port,
        }
    }

    fn transport_request(kind: TransportSocketKind) -> AcquireTransportSocket {
        AcquireTransportSocket {
            route_context_id: vec![7; 16],
            context_handle: vec![8; 32],
            path_id: 1,
            role: WireguardRole::Client as i32,
            descriptor_kind: kind as i32,
            expected_local: Some(transport_address([10, 77, 0, 2], 42_000)),
            expected_remote: (kind == TransportSocketKind::MptcpConnected)
                .then(|| transport_address([10, 77, 0, 3], 443)),
        }
    }

    #[tokio::test]
    async fn route_cleanup_uses_correlated_route_only_scope() {
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = directory.path().join("helper.sock");
        let token_path = directory.path().join("helper.cleanup-token");
        fs::write(&token_path, [9_u8; 32]).expect("token");
        fs::set_permissions(&token_path, Permissions::from_mode(0o600)).expect("mode");
        let listener = UnixListener::bind(&socket).expect("bind");
        let server = tokio::spawn(serve_once(
            listener,
            |operation| {
                matches!(
                    operation,
                    helper_request::Operation::CleanupOwned(cleanup)
                        if CleanupScope::try_from(cleanup.scope).ok()
                            == Some(CleanupScope::RouteContextsOnly)
                )
            },
            helper_response::Outcome::Empty(Empty {}),
        ));
        HelperClient::new_for_test(socket, token_path, geteuid().as_raw())
            .cleanup_route_contexts()
            .await
            .expect("cleanup");
        server.await.expect("server");
    }

    #[tokio::test]
    async fn cleanup_owner_covers_unpolled_and_pre_io_error_paths() {
        let directory = tempfile::tempdir().expect("tempdir");
        let client = HelperClient::new_for_test(
            directory.path().join("missing.sock"),
            directory.path().join("unused-token"),
            geteuid().as_raw(),
        );

        let unpolled =
            client.execute_empty(helper_request::Operation::CleanupOwned(CleanupOwned {
                cleanup_token: vec![0x51; CLEANUP_TOKEN_BYTES],
                scope: CleanupScope::AllOwnedResources as i32,
            }));
        drop(unpolled);

        let error = client
            .execute_empty(helper_request::Operation::CleanupOwned(CleanupOwned {
                cleanup_token: vec![0x52; CLEANUP_TOKEN_BYTES - 1],
                scope: CleanupScope::AllOwnedResources as i32,
            }))
            .await
            .expect_err("invalid token must fail before socket I/O");
        assert!(matches!(
            error,
            HelperClientError::Protocol(volparossa_routing::HelperProtocolError::Invalid(
                "cleanup token"
            ))
        ));
    }

    #[tokio::test]
    async fn prepare_returns_only_typed_public_endpoint_data() {
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = directory.path().join("helper.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let prepared = PreparedLeaseBatch {
            context_handle: vec![3; 32],
            leases: vec![PreparedLease {
                lease_handle: vec![4; 32],
                path_id: 1,
                role: WireguardRole::Client as i32,
                public_key: vec![5; 32],
                public_endpoint: Some(PublicUdpEndpoint {
                    address: vec![8, 8, 8, 8],
                    port: 51_820,
                }),
                underlay_evidence: UnderlayEvidence::DirectAssigned as i32,
            }],
        };
        let server = tokio::spawn(serve_prepare_sequence(listener, prepared.clone()));
        let response =
            HelperClient::new_for_test(socket, directory.path().join("unused"), geteuid().as_raw())
                .prepare_lease_batch(PrepareLeaseBatch {
                    route_context_id: vec![7; 16],
                    role: ContextRole::Client as i32,
                    mptcp_accepted_addrs: 4,
                    mptcp_subflows: 4,
                    leases: vec![LeasePlan {
                        path_id: 1,
                        role: WireguardRole::Client as i32,
                    }],
                    setup_expires_at_unix: 120,
                    hard_expires_at_unix: 900,
                    traversal_hints: Vec::new(),
                })
                .await
                .expect("prepared");
        assert_eq!(response.prepared(), &prepared);
        server.await.expect("server");
    }

    #[tokio::test]
    #[allow(
        clippy::too_many_lines,
        reason = "one smoke test keeps the exact Prepare, Activate, Commit and Destroy stream order visible"
    )]
    async fn prepared_owner_binds_same_runtime_before_activate_commit_and_destroy() {
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = directory.path().join("helper.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let prepared = PreparedLeaseBatch {
            context_handle: vec![3; 32],
            leases: vec![PreparedLease {
                lease_handle: vec![4; 32],
                path_id: 1,
                role: WireguardRole::Client as i32,
                public_key: vec![5; 32],
                public_endpoint: Some(PublicUdpEndpoint {
                    address: vec![8, 8, 8, 8],
                    port: 51_820,
                }),
                underlay_evidence: UnderlayEvidence::DirectAssigned as i32,
            }],
        };
        let prepare_response = prepared.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept Prepare stream");
            let bind = read_bind_some(&mut stream).await;
            write_runtime(&mut stream, &bind, [0xa5; 32]).await;
            let prepare = read_request(&mut stream).await.expect("Prepare request");
            assert!(matches!(
                prepare.operation,
                Some(helper_request::Operation::PrepareLeaseBatch(_))
            ));
            write_test_response(
                &mut stream,
                &prepare,
                HelperResult::Ok,
                Some(helper_response::Outcome::PreparedLeaseBatch(
                    prepare_response,
                )),
            )
            .await;

            for phase in ["activate", "commit", "destroy"] {
                let (mut stream, _) = listener.accept().await.expect("accept phase stream");
                let bind = read_request(&mut stream).await.expect("Bind(None)");
                assert!(matches!(
                    bind.operation,
                    Some(helper_request::Operation::BindHelperRuntime(
                        BindHelperRuntime {
                            prepare_intent: None
                        }
                    ))
                ));
                write_runtime(&mut stream, &bind, [0xa5; 32]).await;
                let request = read_request(&mut stream).await.expect("phase request");
                let outcome = match (phase, request.operation.as_ref()) {
                    ("activate", Some(helper_request::Operation::ActivateLeaseBatch(value))) => {
                        helper_response::Outcome::ActivatedLeaseBatch(ActivatedLeaseBatch {
                            context_handle: value.context_handle.clone(),
                            lease_handles: value
                                .leases
                                .iter()
                                .map(|lease| lease.lease_handle.clone())
                                .collect(),
                        })
                    }
                    ("commit", Some(helper_request::Operation::CommitLeaseBatch(value))) => {
                        helper_response::Outcome::CommittedLeaseBatch(CommittedLeaseBatch {
                            context_handle: value.context_handle.clone(),
                            leases: value
                                .leases
                                .iter()
                                .map(|lease| CommittedLease {
                                    lease_handle: lease.lease_handle.clone(),
                                    latest_handshake_unix: 1,
                                    received_bytes: 1,
                                    transmitted_bytes: 1,
                                })
                                .collect(),
                        })
                    }
                    ("destroy", Some(helper_request::Operation::DestroyContext(value))) => {
                        assert_eq!(value.route_context_id, vec![7; 16]);
                        assert_eq!(value.context_handle, vec![3; 32]);
                        helper_response::Outcome::DestroyedContext(DestroyedContext {
                            existed: true,
                        })
                    }
                    _ => panic!("unexpected lifecycle phase"),
                };
                write_test_response(&mut stream, &request, HelperResult::Ok, Some(outcome)).await;
            }
        });

        let client =
            HelperClient::new_for_test(socket, directory.path().join("unused"), geteuid().as_raw());
        let prepare = prepare_sequence_value();
        let mut owner = client
            .prepare_lease_batch(prepare.clone())
            .await
            .expect("runtime-bound Prepare");
        let activation = ActivateLeaseBatch {
            route_context_id: prepare.route_context_id.clone(),
            context_handle: prepared.context_handle.clone(),
            leases: vec![LeaseActivation {
                lease_handle: vec![4; 32],
                path_id: 1,
                role: WireguardRole::Client as i32,
                peer_public_key: vec![6; 32],
                peer_endpoint: Some(PublicUdpEndpoint {
                    address: vec![1, 1, 1, 1],
                    port: 51_821,
                }),
                maximum_up_mbps: 0,
                maximum_down_mbps: 0,
                signed_relay_reservation: vec![7],
                signed_client_relay_request: Vec::new(),
            }],
        };
        client
            .activate_lease_batch(&mut owner, activation.clone())
            .await
            .expect("same-runtime Activate");
        client
            .commit_lease_batch(
                &mut owner,
                CommitLeaseBatch {
                    route_context_id: activation.route_context_id,
                    context_handle: activation.context_handle,
                    leases: vec![LeaseCommit {
                        lease_handle: vec![4; 32],
                        path_id: 1,
                        role: WireguardRole::Client as i32,
                    }],
                },
            )
            .await
            .expect("same-runtime Commit");
        client
            .destroy_context(&owner)
            .await
            .expect("same-runtime Destroy");
        server.await.expect("server");
    }

    #[tokio::test]
    async fn changed_runtime_sends_no_activation_and_retains_prepared_owner() {
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = directory.path().join("helper.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let prepared = PreparedLeaseBatch {
            context_handle: vec![3; 32],
            leases: vec![PreparedLease {
                lease_handle: vec![4; 32],
                path_id: 1,
                role: WireguardRole::Client as i32,
                public_key: vec![5; 32],
                public_endpoint: Some(PublicUdpEndpoint {
                    address: vec![8, 8, 8, 8],
                    port: 51_820,
                }),
                underlay_evidence: UnderlayEvidence::DirectAssigned as i32,
            }],
        };
        let server_prepared = prepared.clone();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept Prepare stream");
            let bind = read_bind_some(&mut stream).await;
            write_runtime(&mut stream, &bind, [0xa5; 32]).await;
            let prepare = read_request(&mut stream).await.expect("Prepare request");
            write_test_response(
                &mut stream,
                &prepare,
                HelperResult::Ok,
                Some(helper_response::Outcome::PreparedLeaseBatch(
                    server_prepared,
                )),
            )
            .await;

            let (mut stream, _) = listener.accept().await.expect("accept Activate stream");
            let bind = read_request(&mut stream).await.expect("Bind(None)");
            write_runtime(&mut stream, &bind, [0xb6; 32]).await;
            assert_no_followup_frame(&mut stream).await;
        });
        let client =
            HelperClient::new_for_test(socket, directory.path().join("unused"), geteuid().as_raw());
        let prepare = prepare_sequence_value();
        let mut owner = client
            .prepare_lease_batch(prepare.clone())
            .await
            .expect("runtime-bound Prepare");
        let error = client
            .activate_lease_batch(
                &mut owner,
                ActivateLeaseBatch {
                    route_context_id: prepare.route_context_id,
                    context_handle: prepared.context_handle,
                    leases: vec![LeaseActivation {
                        lease_handle: vec![4; 32],
                        path_id: 1,
                        role: WireguardRole::Client as i32,
                        peer_public_key: vec![6; 32],
                        peer_endpoint: Some(PublicUdpEndpoint {
                            address: vec![1, 1, 1, 1],
                            port: 51_821,
                        }),
                        maximum_up_mbps: 0,
                        maximum_down_mbps: 0,
                        signed_relay_reservation: vec![7],
                        signed_client_relay_request: Vec::new(),
                    }],
                },
            )
            .await
            .expect_err("changed runtime");
        assert!(matches!(error, HelperClientError::RuntimeChanged));
        assert!(matches!(owner.phase, RuntimeLeasePhase::Prepared));
        server.await.expect("server");
    }

    #[tokio::test]
    async fn bind_rejection_and_correlation_fail_before_prepare_dispatch() {
        for wrong_correlation in [false, true] {
            let directory = tempfile::tempdir().expect("tempdir");
            let socket = directory.path().join("helper.sock");
            let listener = UnixListener::bind(&socket).expect("bind");
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let bind = read_bind_some(&mut stream).await;
                if wrong_correlation {
                    let response = HelperResponse {
                        protocol_version: HELPER_PROTOCOL_VERSION,
                        request_id: vec![0xcc; 16],
                        result: HelperResult::Ok as i32,
                        diagnostic_code: "TEST_WRONG_ID".to_owned(),
                        operation_digest: operation_digest(&bind).expect("Bind digest").to_vec(),
                        outcome: Some(helper_response::Outcome::HelperRuntime(HelperRuntime {
                            helper_runtime_id: vec![0xa5; 32],
                        })),
                    };
                    stream
                        .write_all(&encode_response(&response).expect("response"))
                        .await
                        .expect("write response");
                } else {
                    write_test_response(&mut stream, &bind, HelperResult::Unavailable, None).await;
                }
                assert_no_followup_frame(&mut stream).await;
            });
            let client = HelperClient::new_for_test(
                socket,
                directory.path().join("unused"),
                geteuid().as_raw(),
            );
            let Err(failure) = client.prepare_lease_batch(prepare_sequence_value()).await else {
                panic!("Bind must fail before Prepare dispatch");
            };
            if wrong_correlation {
                assert!(matches!(
                    failure,
                    PrepareLeaseBatchFailure::Definitive(HelperClientError::Correlation)
                ));
            } else {
                assert!(matches!(
                    failure,
                    PrepareLeaseBatchFailure::Definitive(HelperClientError::Rejected(
                        HelperResult::Unavailable
                    ))
                ));
            }
            server.await.expect("server");
        }
    }

    #[tokio::test]
    async fn bind_timeout_is_definitive_and_sends_no_prepare() {
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = directory.path().join("helper.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let _bind = read_bind_some(&mut stream).await;
            tokio::time::sleep(HELPER_TIMEOUT + Duration::from_millis(250)).await;
            assert_no_followup_frame(&mut stream).await;
        });
        let client =
            HelperClient::new_for_test(socket, directory.path().join("unused"), geteuid().as_raw());
        let Err(failure) = client.prepare_lease_batch(prepare_sequence_value()).await else {
            panic!("Bind timeout");
        };
        assert!(matches!(
            failure,
            PrepareLeaseBatchFailure::Definitive(HelperClientError::Timeout)
        ));
        server.await.expect("server");
    }

    #[tokio::test]
    async fn every_failure_after_prepare_write_retains_redacted_authority() {
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = directory.path().join("helper.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let bind = read_bind_some(&mut stream).await;
            write_runtime(&mut stream, &bind, [0xa5; 32]).await;
            let prepare = read_request(&mut stream).await.expect("Prepare request");
            assert!(matches!(
                prepare.operation,
                Some(helper_request::Operation::PrepareLeaseBatch(_))
            ));
            // EOF after the mutating frame is deliberately ambiguous.
        });
        let client =
            HelperClient::new_for_test(socket, directory.path().join("unused"), geteuid().as_raw());
        let Err(failure) = client.prepare_lease_batch(prepare_sequence_value()).await else {
            panic!("truncated Prepare response");
        };
        let rendered = format!("{failure:?}");
        assert!(rendered.contains("Ambiguous"));
        assert!(!rendered.contains("helper_runtime_id"));
        assert!(!rendered.contains("prepare_request_id"));
        let PrepareLeaseBatchFailure::Ambiguous { authority, .. } = failure else {
            panic!("post-write failure must retain authority");
        };
        assert_eq!(authority.helper_runtime_id, [0xa5; 32]);
        assert_eq!(authority.route_context_id, [7; 16]);
        assert_eq!(authority.setup_expires_at_unix, 120);
        assert_eq!(authority.hard_expires_at_unix, 900);
        server.await.expect("server");
    }

    #[tokio::test]
    async fn bind_and_prepare_share_one_absolute_ten_second_deadline() {
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = directory.path().join("helper.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let bind = read_bind_some(&mut stream).await;
            tokio::time::sleep(Duration::from_secs(6)).await;
            write_runtime(&mut stream, &bind, [0xa5; 32]).await;
            let _prepare = read_request(&mut stream).await.expect("Prepare request");
            tokio::time::sleep(Duration::from_secs(6)).await;
        });
        let client =
            HelperClient::new_for_test(socket, directory.path().join("unused"), geteuid().as_raw());
        let started = StdInstant::now();
        let Err(failure) = client.prepare_lease_batch(prepare_sequence_value()).await else {
            panic!("6s + 6s must exceed one 10s sequence budget");
        };
        let elapsed = started.elapsed();
        assert!(matches!(
            failure,
            PrepareLeaseBatchFailure::Ambiguous {
                source: HelperClientError::Timeout,
                ..
            }
        ));
        assert!(elapsed >= Duration::from_millis(9_500));
        assert!(elapsed < Duration::from_secs(11));
        server.abort();
        let _ = server.await;
    }

    #[tokio::test]
    async fn reconciliation_queries_runtime_then_echoes_exact_authority_on_one_stream() {
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = directory.path().join("helper.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let bind = read_request(&mut stream).await.expect("Bind(None)");
            assert!(matches!(
                bind.operation,
                Some(helper_request::Operation::BindHelperRuntime(
                    BindHelperRuntime {
                        prepare_intent: None
                    }
                ))
            ));
            write_runtime(&mut stream, &bind, [0xa5; 32]).await;
            let reconcile = read_request(&mut stream).await.expect("Reconcile");
            let Some(helper_request::Operation::ReconcileExpiredPrepare(value)) =
                reconcile.operation.as_ref()
            else {
                panic!("ReconcileExpiredPrepare");
            };
            assert_ne!(bind.request_id, reconcile.request_id);
            assert_ne!(bind.request_id, value.prepare_request_id);
            assert_ne!(reconcile.request_id, value.prepare_request_id);
            write_test_response(
                &mut stream,
                &reconcile,
                HelperResult::Ok,
                Some(helper_response::Outcome::ReconciledExpiredPrepare(
                    ReconciledExpiredPrepare {
                        helper_runtime_id: value.helper_runtime_id.clone(),
                        route_context_id: value.route_context_id.clone(),
                        prepare_request_id: value.prepare_request_id.clone(),
                        prepare_operation_digest: value.prepare_operation_digest.clone(),
                        setup_expires_at_unix: value.setup_expires_at_unix,
                        hard_expires_at_unix: value.hard_expires_at_unix,
                    },
                )),
            )
            .await;
        });
        let authority = PrepareReconciliationAuthority::for_test(&prepare_sequence_value());
        let client =
            HelperClient::new_for_test(socket, directory.path().join("unused"), geteuid().as_raw());
        let receipt = client
            .reconcile_expired_prepare(&authority)
            .await
            .expect("exact same-runtime reconciliation");
        assert!(authority.matches_reconciled(&receipt));
        server.await.expect("server");
    }

    #[tokio::test]
    async fn reconciliation_retries_reuse_one_stable_outer_request_identity() {
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = directory.path().join("helper.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let server = tokio::spawn(async move {
            let mut observed = Vec::new();
            for attempt in 0..2 {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let bind = read_request(&mut stream).await.expect("Bind(None)");
                assert!(matches!(
                    bind.operation,
                    Some(helper_request::Operation::BindHelperRuntime(
                        BindHelperRuntime {
                            prepare_intent: None
                        }
                    ))
                ));
                write_runtime(&mut stream, &bind, [0xa5; 32]).await;
                let reconcile = read_request(&mut stream).await.expect("Reconcile");
                let Some(helper_request::Operation::ReconcileExpiredPrepare(value)) =
                    reconcile.operation.as_ref()
                else {
                    panic!("ReconcileExpiredPrepare");
                };
                assert_ne!(bind.request_id, reconcile.request_id);
                assert_ne!(bind.request_id, value.prepare_request_id);
                assert_ne!(reconcile.request_id, value.prepare_request_id);
                observed.push((
                    reconcile.request_id.clone(),
                    operation_digest(&reconcile).expect("Reconcile digest"),
                ));
                if attempt == 0 {
                    write_test_response(
                        &mut stream,
                        &reconcile,
                        HelperResult::CleanupIncomplete,
                        None,
                    )
                    .await;
                } else {
                    write_test_response(
                        &mut stream,
                        &reconcile,
                        HelperResult::Ok,
                        Some(helper_response::Outcome::ReconciledExpiredPrepare(
                            ReconciledExpiredPrepare {
                                helper_runtime_id: value.helper_runtime_id.clone(),
                                route_context_id: value.route_context_id.clone(),
                                prepare_request_id: value.prepare_request_id.clone(),
                                prepare_operation_digest: value.prepare_operation_digest.clone(),
                                setup_expires_at_unix: value.setup_expires_at_unix,
                                hard_expires_at_unix: value.hard_expires_at_unix,
                            },
                        )),
                    )
                    .await;
                }
            }
            observed
        });
        let authority = PrepareReconciliationAuthority::for_test(&prepare_sequence_value());
        let client =
            HelperClient::new_for_test(socket, directory.path().join("unused"), geteuid().as_raw());
        assert!(matches!(
            client.reconcile_expired_prepare(&authority).await,
            Err(HelperClientError::Rejected(HelperResult::CleanupIncomplete))
        ));
        let receipt = client
            .reconcile_expired_prepare(&authority)
            .await
            .expect("exact retry settles");
        assert!(authority.matches_reconciled(&receipt));
        let observed = server.await.expect("server");
        assert_eq!(observed.len(), 2);
        assert_eq!(observed[0], observed[1]);
        assert_eq!(observed[0].0.as_slice(), authority.reconcile_request_id);
    }

    #[tokio::test]
    async fn runtime_change_stops_before_reconciliation_frame() {
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = directory.path().join("helper.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.expect("accept");
            let bind = read_request(&mut stream).await.expect("Bind(None)");
            assert!(matches!(
                bind.operation,
                Some(helper_request::Operation::BindHelperRuntime(
                    BindHelperRuntime {
                        prepare_intent: None
                    }
                ))
            ));
            write_runtime(&mut stream, &bind, [0xb6; 32]).await;
            assert_no_followup_frame(&mut stream).await;
        });
        let authority = PrepareReconciliationAuthority::for_test(&prepare_sequence_value());
        let client =
            HelperClient::new_for_test(socket, directory.path().join("unused"), geteuid().as_raw());
        assert!(matches!(
            client.reconcile_expired_prepare(&authority).await,
            Err(HelperClientError::RuntimeChanged)
        ));
        server.await.expect("server");
    }

    #[tokio::test]
    async fn every_reconciliation_echo_substitution_is_rejected() {
        for substituted_field in 0..6 {
            let directory = tempfile::tempdir().expect("tempdir");
            let socket = directory.path().join("helper.sock");
            let listener = UnixListener::bind(&socket).expect("bind");
            let server = tokio::spawn(async move {
                let (mut stream, _) = listener.accept().await.expect("accept");
                let bind = read_request(&mut stream).await.expect("Bind(None)");
                write_runtime(&mut stream, &bind, [0xa5; 32]).await;
                let reconcile = read_request(&mut stream).await.expect("Reconcile");
                let Some(helper_request::Operation::ReconcileExpiredPrepare(value)) =
                    reconcile.operation.as_ref()
                else {
                    panic!("ReconcileExpiredPrepare");
                };
                let mut receipt = ReconciledExpiredPrepare {
                    helper_runtime_id: value.helper_runtime_id.clone(),
                    route_context_id: value.route_context_id.clone(),
                    prepare_request_id: value.prepare_request_id.clone(),
                    prepare_operation_digest: value.prepare_operation_digest.clone(),
                    setup_expires_at_unix: value.setup_expires_at_unix,
                    hard_expires_at_unix: value.hard_expires_at_unix,
                };
                match substituted_field {
                    0 => receipt.helper_runtime_id[0] ^= 1,
                    1 => receipt.route_context_id[0] ^= 1,
                    2 => receipt.prepare_request_id[0] ^= 1,
                    3 => receipt.prepare_operation_digest[0] ^= 1,
                    4 => receipt.setup_expires_at_unix += 1,
                    5 => receipt.hard_expires_at_unix += 1,
                    _ => unreachable!(),
                }
                write_test_response(
                    &mut stream,
                    &reconcile,
                    HelperResult::Ok,
                    Some(helper_response::Outcome::ReconciledExpiredPrepare(receipt)),
                )
                .await;
            });
            let authority = PrepareReconciliationAuthority::for_test(&prepare_sequence_value());
            let client = HelperClient::new_for_test(
                socket,
                directory.path().join("unused"),
                geteuid().as_raw(),
            );
            assert!(matches!(
                client.reconcile_expired_prepare(&authority).await,
                Err(HelperClientError::Correlation)
            ));
            server.await.expect("server");
        }
    }

    #[test]
    fn prepared_ingress_rejects_cross_category_handle_collisions() {
        let mut wire = prepared_ingress_wire();
        wire.sockets[0].socket_handle = wire.ingress_handle.clone();
        assert!(matches!(
            prepared_client_ingress(wire, [7; 16], 120, 900),
            Err(HelperClientError::Correlation)
        ));
    }

    #[tokio::test]
    async fn ingress_descriptor_protocol_handoff_is_correlated_cloexec_and_one_shot() {
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = directory.path().join("helper.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let mut prepared = prepared_ingress_capability();
        let identity = client_ingress_identities()[0];
        let expected_local = prepared
            .sockets
            .get(&identity)
            .expect("prepared identity")
            .wire_local
            .clone();
        let (sent, mut peer) = StdUnixStream::pair().expect("descriptor pair");
        let server = tokio::spawn(serve_ingress_once(
            listener,
            OwnedFd::from(sent),
            expected_local,
        ));
        let client =
            HelperClient::new_for_test(socket, directory.path().join("unused"), geteuid().as_raw());
        let acquired = client
            .acquire_ingress_socket_protocol(&mut prepared, identity)
            .await
            .expect("protocol acquisition");
        assert_eq!(acquired.identity(), identity);
        assert_eq!(acquired.local_address().port(), 42_000);
        let flags = FdFlag::from_bits_truncate(
            fcntl(acquired.descriptor(), FcntlArg::F_GETFD).expect("descriptor flags"),
        );
        assert!(flags.contains(FdFlag::FD_CLOEXEC));
        assert_eq!(
            fd_write(acquired.descriptor(), b"x").expect("write descriptor"),
            1
        );
        let mut byte = [0_u8; 1];
        peer.read_exact(&mut byte).expect("read peer");
        assert_eq!(byte, *b"x");
        server.await.expect("server");

        assert!(matches!(
            client
                .acquire_ingress_socket_protocol(&mut prepared, identity)
                .await,
            Err(HelperClientError::CapabilityAlreadyUsed)
        ));
        drop(acquired);
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        assert_eq!(peer.read(&mut byte).expect("descriptor closed"), 0);
    }

    #[tokio::test]
    async fn ingress_kernel_revalidation_failure_closes_fd_and_consumes_local_acquire_token() {
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = directory.path().join("helper.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let mut prepared = prepared_ingress_capability();
        let identity = client_ingress_identities()[0];
        let expected_local = prepared
            .sockets
            .get(&identity)
            .expect("prepared identity")
            .wire_local
            .clone();
        let (sent, mut peer) = StdUnixStream::pair().expect("descriptor pair");
        let server = tokio::spawn(serve_ingress_once(
            listener,
            OwnedFd::from(sent),
            expected_local,
        ));
        let client =
            HelperClient::new_for_test(socket, directory.path().join("unused"), geteuid().as_raw());
        assert!(matches!(
            client.acquire_ingress_socket(&mut prepared, identity).await,
            Err(HelperClientError::DescriptorValidation(_))
        ));
        server.await.expect("server");
        assert!(matches!(
            client.acquire_ingress_socket(&mut prepared, identity).await,
            Err(HelperClientError::CapabilityAlreadyUsed)
        ));
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("rejected descriptor closed"), 0);
    }

    #[test]
    fn activation_receipts_require_complete_cross_unique_one_shot_capabilities() {
        let mut prepared = prepared_ingress_capability();
        let (mut sockets, mut peers) = acquired_ingress_set(&mut prepared);
        let receipts = ingress_receipts(&prepared, &sockets).expect("complete receipts");
        assert_eq!(receipts.len(), REQUIRED_INGRESS_SOCKETS);
        let cross_category_collision = sockets[0].socket_handle;
        sockets[7].receipt_handle = cross_category_collision;
        assert!(matches!(
            ingress_receipts(&prepared, &sockets),
            Err(HelperClientError::Correlation)
        ));
        drop(sockets);
        for peer in &mut peers {
            peer.set_read_timeout(Some(Duration::from_secs(1)))
                .expect("read timeout");
            let mut byte = [0_u8; 1];
            assert_eq!(peer.read(&mut byte).expect("descriptor closed"), 0);
        }
    }

    #[tokio::test]
    async fn activation_io_failure_returns_cleanup_authority_and_all_descriptors() {
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = directory.path().join("helper.sock");
        let client = HelperClient::new_for_test(
            socket.clone(),
            directory.path().join("unused"),
            geteuid().as_raw(),
        );
        let mut prepared = prepared_ingress_capability();
        let (sockets, mut peers) = acquired_ingress_set(&mut prepared);
        let failure = match client.activate_client_ingress(prepared, sockets).await {
            Ok(_) => panic!("missing helper must not activate"),
            Err(failure) => failure,
        };
        let (error, prepared, sockets) = failure.into_parts();
        assert!(matches!(error, HelperClientError::Io(_)));
        assert_eq!(prepared.socket_identities().len(), REQUIRED_INGRESS_SOCKETS);
        assert_eq!(sockets.len(), REQUIRED_INGRESS_SOCKETS);
        assert!(matches!(
            client.destroy_prepared_client_ingress(&prepared).await,
            Err(HelperClientError::Io(_))
        ));

        let listener = UnixListener::bind(&socket).expect("bind retry helper");
        let server = tokio::spawn(serve_once(
            listener,
            |operation| {
                matches!(
                    operation,
                    helper_request::Operation::DestroyClientIngress(_)
                )
            },
            helper_response::Outcome::DestroyedClientIngress(
                volparossa_routing::DestroyedClientIngress { existed: true },
            ),
        ));
        assert!(
            client
                .destroy_prepared_client_ingress(&prepared)
                .await
                .expect("retry destroy")
        );
        server.await.expect("server");
        drop(sockets);
        for peer in &mut peers {
            peer.set_read_timeout(Some(Duration::from_secs(1)))
                .expect("read timeout");
            let mut byte = [0_u8; 1];
            assert_eq!(peer.read(&mut byte).expect("descriptor closed"), 0);
        }
    }

    #[tokio::test]
    async fn activation_sends_exact_eight_receipts_and_active_destroy_remains_retryable() {
        let directory = tempfile::tempdir().expect("tempdir");
        let activation_socket = directory.path().join("activate.sock");
        let listener = UnixListener::bind(&activation_socket).expect("bind activation");
        let server = tokio::spawn(serve_activation_once(listener));
        let client = HelperClient::new_for_test(
            activation_socket,
            directory.path().join("unused"),
            geteuid().as_raw(),
        );
        let mut prepared = prepared_ingress_capability();
        let (sockets, mut peers) = acquired_ingress_set(&mut prepared);
        let active = match client.activate_client_ingress(prepared, sockets).await {
            Ok(active) => active,
            Err(failure) => panic!("{failure}"),
        };
        server.await.expect("server");
        assert_eq!(active.sockets().len(), REQUIRED_INGRESS_SOCKETS);
        for identity in client_ingress_identities() {
            assert_eq!(
                active.socket(identity).expect("active identity").identity(),
                identity
            );
        }

        let destroy_socket = directory.path().join("destroy.sock");
        let destroy_client = HelperClient::new_for_test(
            destroy_socket.clone(),
            directory.path().join("unused"),
            geteuid().as_raw(),
        );
        assert!(matches!(
            destroy_client.destroy_active_client_ingress(&active).await,
            Err(HelperClientError::Io(_))
        ));
        assert_eq!(active.sockets().len(), REQUIRED_INGRESS_SOCKETS);
        let listener = UnixListener::bind(&destroy_socket).expect("bind destroy retry");
        let server = tokio::spawn(serve_once(
            listener,
            |operation| {
                matches!(
                    operation,
                    helper_request::Operation::DestroyClientIngress(_)
                )
            },
            helper_response::Outcome::DestroyedClientIngress(
                volparossa_routing::DestroyedClientIngress { existed: false },
            ),
        ));
        assert!(
            !destroy_client
                .destroy_active_client_ingress(&active)
                .await
                .expect("retry destroy")
        );
        server.await.expect("server");
        assert_eq!(active.sockets().len(), REQUIRED_INGRESS_SOCKETS);
        drop(active);
        for peer in &mut peers {
            peer.set_read_timeout(Some(Duration::from_secs(1)))
                .expect("read timeout");
            let mut byte = [0_u8; 1];
            assert_eq!(peer.read(&mut byte).expect("descriptor closed"), 0);
        }
    }

    #[tokio::test]
    async fn typed_owned_fd_handoff_covers_mptcp_connected_listener_and_unconnected_udp() {
        for (index, kind) in [
            TransportSocketKind::MptcpConnected,
            TransportSocketKind::MptcpListener,
            TransportSocketKind::QuicUdpUnconnected,
        ]
        .into_iter()
        .enumerate()
        {
            let directory = tempfile::tempdir().expect("tempdir");
            let socket = directory.path().join(format!("helper-{index}.sock"));
            let listener = UnixListener::bind(&socket).expect("bind");
            let (sent, mut peer) = StdUnixStream::pair().expect("descriptor pair");
            let server = tokio::spawn(serve_transport_once(
                listener,
                Some(OwnedFd::from(sent)),
                DescriptorTestMode::Exact,
            ));
            let request = transport_request(kind);
            let acquired = HelperClient::new_for_test(
                socket,
                directory.path().join("unused"),
                geteuid().as_raw(),
            )
            .acquire_transport_socket(request.clone())
            .await
            .expect("acquire descriptor");
            assert_eq!(
                acquired.metadata(),
                &TransportSocketReady {
                    path_id: request.path_id,
                    role: request.role,
                    descriptor_kind: request.descriptor_kind,
                    local: request.expected_local,
                    remote: request.expected_remote,
                }
            );
            let flags = FdFlag::from_bits_truncate(
                fcntl(acquired.descriptor(), FcntlArg::F_GETFD).expect("descriptor flags"),
            );
            assert!(flags.contains(FdFlag::FD_CLOEXEC));
            let (descriptor, _) = acquired.into_parts();
            let mut received = StdUnixStream::from(descriptor);
            peer.write_all(b"route").expect("write peer");
            let mut payload = [0_u8; 5];
            received.read_exact(&mut payload).expect("read acquired");
            assert_eq!(&payload, b"route");
            server.await.expect("server");
        }
    }

    async fn rejected_descriptor_is_closed(mode: DescriptorTestMode) -> HelperClientError {
        let directory = tempfile::tempdir().expect("tempdir");
        let socket = directory.path().join("helper.sock");
        let listener = UnixListener::bind(&socket).expect("bind");
        let (sent, mut peer) = StdUnixStream::pair().expect("descriptor pair");
        let descriptor =
            (!matches!(mode, DescriptorTestMode::Missing)).then(|| OwnedFd::from(sent));
        let server = tokio::spawn(serve_transport_once(listener, descriptor, mode));
        let result =
            HelperClient::new_for_test(socket, directory.path().join("unused"), geteuid().as_raw())
                .acquire_transport_socket(transport_request(
                    TransportSocketKind::QuicUdpUnconnected,
                ))
                .await;
        let error = match result {
            Ok(_) => panic!("descriptor handoff must fail"),
            Err(error) => error,
        };
        server.await.expect("server");
        peer.set_read_timeout(Some(Duration::from_secs(1)))
            .expect("read timeout");
        let mut byte = [0_u8; 1];
        assert_eq!(peer.read(&mut byte).expect("descriptor must be closed"), 0);
        error
    }

    #[tokio::test]
    async fn mismatched_or_missing_descriptor_fails_closed() {
        assert!(matches!(
            rejected_descriptor_is_closed(DescriptorTestMode::WrongBinding).await,
            HelperClientError::DescriptorHandoff(_)
        ));
        assert!(matches!(
            rejected_descriptor_is_closed(DescriptorTestMode::Missing).await,
            HelperClientError::DescriptorHandoff(_)
        ));
    }

    #[tokio::test]
    async fn response_mismatch_never_installs_the_queued_descriptor() {
        assert!(matches!(
            rejected_descriptor_is_closed(DescriptorTestMode::WrongCorrelation).await,
            HelperClientError::Correlation
        ));
    }

    #[test]
    fn token_reader_rejects_links_and_wrong_modes() {
        let directory = tempfile::tempdir().expect("tempdir");
        let token = directory.path().join("token");
        fs::write(&token, [1_u8; 32]).expect("token");
        fs::set_permissions(&token, Permissions::from_mode(0o644)).expect("mode");
        assert!(matches!(
            read_cleanup_token(&token),
            Err(HelperClientError::UnsafeToken)
        ));
        fs::set_permissions(&token, Permissions::from_mode(0o600)).expect("mode");
        let link = directory.path().join("link");
        std::os::unix::fs::symlink(&token, &link).expect("symlink");
        assert!(matches!(
            read_cleanup_token(&link),
            Err(HelperClientError::UnsafeToken)
        ));
    }
}
