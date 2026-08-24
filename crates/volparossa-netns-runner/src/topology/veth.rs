//! Fixed RTNETLINK creation and rollback for one disposable veth pair.
//!
//! The caller selects only endpoint A or B and supplies the lifecycle run ID
//! plus an already retained target-network-namespace descriptor. Interface
//! names and mutable link attributes are derived here from the version-1
//! lifecycle contract. Creation is one atomic `RTM_NEWLINK`: the peer is born
//! directly in the target namespace through `IFLA_NET_NS_FD`; there is no
//! create-then-move fallback.
//!
//! A possible mutation is journalled before its ACK is received. Every
//! ambiguous post-send outcome is reconciled through a fresh socket. Cleanup
//! pins the first exact lineage-bound provisional observation, deletes only the
//! freshly reverified parent ifindex, and requires a subsequent exact absence
//! observation. If an armed guard cannot establish cleanup, the fixed PID-1
//! process aborts rather than continuing with unknown network state.
//! This relies on the runner's existing one-PID-1-task, pristine-parent and
//! trusted-launcher scope; it makes no hostile same-UID concurrency claim.

use std::{
    io,
    marker::PhantomData,
    os::fd::{AsFd, AsRawFd, OwnedFd},
    rc::Rc,
    time::{Duration, Instant},
};

use netlink_sys::{Socket, SocketAddr, protocols::NETLINK_ROUTE};
use nix::{
    fcntl::{FcntlArg, FdFlag, OFlag, fcntl},
    libc,
    poll::{PollFd, PollFlags, PollTimeout, poll},
};
use rustix::fs::{FsWord, Mode, OFlags, fstat, fstatfs, open};
use thiserror::Error;
use volparossa_linux_uapi::{namespace_type, owning_user_namespace};
use volparossa_test_support::RunId;

const VETH_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
const CURRENT_NETWORK_NAMESPACE: &str = "/proc/thread-self/ns/net";
const NSFS_MAGIC: FsWord = 0x6e73_6673;

const MAX_NETLINK_DATAGRAM_BYTES: usize = 16 * 1024;
const MAX_ATTRIBUTES: usize = 128;
const MAX_REQUEST_BYTES: usize = 512;
const MAX_RECONCILIATION_DELETE_ATTEMPTS: usize = 2;
const NLMSG_HEADER_LEN: usize = 16;
const NLMSG_ERROR_CODE_LEN: usize = 4;
const IFINFO_LEN: usize = 16;
const ATTRIBUTE_HEADER_LEN: usize = 4;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_CAPPED: u16 = 0x0100;
const NLM_F_ACK_TLVS: u16 = 0x0200;
const NLM_F_EXCL: u16 = 0x0200;
const NLM_F_CREATE: u16 = 0x0400;
const NLMSG_ERROR: u16 = 2;
const RTM_NEWLINK: u16 = 16;
const RTM_DELLINK: u16 = 17;
const RTM_GETLINK: u16 = 18;
const RTM_NEWNSID: u16 = 88;
const RTM_GETNSID: u16 = 90;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

const IFLA_IFNAME: u16 = 3;
const IFLA_MTU: u16 = 4;
const IFLA_LINK: u16 = 5;
const IFLA_TXQLEN: u16 = 13;
const IFLA_LINKINFO: u16 = 18;
const IFLA_NET_NS_FD: u16 = 28;
const IFLA_NUM_TX_QUEUES: u16 = 31;
const IFLA_NUM_RX_QUEUES: u16 = 32;
const IFLA_LINK_NETNSID: u16 = 37;
const IFLA_INFO_KIND: u16 = 1;
const IFLA_INFO_DATA: u16 = 2;
const VETH_INFO_PEER: u16 = 1;
const NETNSA_NSID: u16 = 1;
const NETNSA_FD: u16 = 3;
const NSID_HEADER_LEN: usize = 4;

const AF_UNSPEC: u8 = 0;
const ARPHRD_ETHER: u16 = 1;
const IFF_BROADCAST: u32 = 0x0002;
const IFF_MULTICAST: u32 = 0x1000;
const FIXED_DOWN_VETH_FLAGS: u32 = IFF_BROADCAST | IFF_MULTICAST;

/// Exact interface name used for the endpoint side of both fixed pairs.
pub(crate) const FIXED_VETH_PEER_NAME: &str = "eth0";
/// Exact MTU applied to both sides at atomic creation.
pub(crate) const FIXED_VETH_MTU: u32 = 1_500;
/// Exact transmit queue length applied to both sides at atomic creation.
pub(crate) const FIXED_VETH_TX_QUEUE_LENGTH: u32 = 1_000;
/// Exact transmit and receive queue count applied to both sides at atomic creation.
pub(crate) const FIXED_VETH_QUEUE_COUNT: u32 = 1;

/// Endpoint selector from the fixed two-endpoint lifecycle specification.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FixedVethEndpoint {
    /// Pair connecting the parent namespace to endpoint A.
    A,
    /// Pair connecting the parent namespace to endpoint B.
    B,
}

impl FixedVethEndpoint {
    const fn letter(self) -> char {
        match self {
            Self::A => 'a',
            Self::B => 'b',
        }
    }
}

/// Bounded RTNETLINK or namespace-verification failure.
#[derive(Debug, Error)]
pub(crate) enum VethOperationError {
    /// A fixed descriptor, socket, send, receive, or wait operation failed.
    #[error("fixed veth operation {operation} failed: {source}")]
    Io {
        /// Static operation label.
        operation: &'static str,
        /// Kernel or standard-library error.
        #[source]
        source: io::Error,
    },
    /// The kernel returned an exact negative ACK.
    #[error("kernel rejected fixed veth operation {operation} with errno {errno}")]
    Kernel {
        /// Static operation label.
        operation: &'static str,
        /// Positive Linux errno.
        errno: i32,
    },
    /// A response or retained object contradicted the fixed protocol.
    #[error("fixed veth proof was unsafe: {0}")]
    Unsafe(&'static str),
    /// A response or encoding exceeded a fixed resource limit.
    #[error("fixed veth operation exceeded its resource bound")]
    Limit,
}

impl VethOperationError {
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }

    fn errno(operation: &'static str, errno: i32) -> Self {
        Self::Kernel { operation, errno }
    }
}

/// Failure to create one fixed pair.
#[derive(Debug, Error)]
pub(crate) enum VethCreateError {
    /// Failure before a request could have reached the kernel mutation path.
    #[error("fixed veth creation failed before mutation")]
    BeforeMutation(#[source] VethOperationError),
    /// Exact negative create ACK; the atomic request did not create a pair.
    #[error("kernel rejected atomic fixed veth creation with errno {0}")]
    Rejected(i32),
    /// Send or ACK ambiguity after which exact absence was re-established.
    #[error("fixed veth creation may have executed; rollback restored exact absence")]
    PossiblyApplied(#[source] VethOperationError),
    /// Creation was acknowledged but exact readback failed; rollback restored absence.
    #[error("fixed veth creation was rolled back after its readback proof failed")]
    Readback(#[source] VethOperationError),
}

/// Failure to freshly reverify a retained fixed pair.
#[derive(Debug, Error)]
#[error("retained fixed veth pair verification failed")]
pub(crate) struct VethVerifyError(#[source] VethOperationError);

/// A rollback anomaly after fresh reconciliation nevertheless proved absence.
#[derive(Debug, Error)]
#[error("fixed veth rollback required reconciliation; exact absence was restored")]
pub(crate) struct VethRollbackError(#[source] VethOperationError);

#[derive(Clone, Debug, Eq, PartialEq)]
struct VethSpecification {
    endpoint: FixedVethEndpoint,
    parent_name: String,
}

impl VethSpecification {
    fn new(run_id: &RunId, endpoint: FixedVethEndpoint) -> Result<Self, VethOperationError> {
        let prefix = run_id
            .as_str()
            .get(..8)
            .ok_or(VethOperationError::Unsafe("run ID prefix is unavailable"))?;
        if !prefix.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(VethOperationError::Unsafe(
                "run ID prefix is not hexadecimal",
            ));
        }
        let parent_name = format!("vp{}{prefix}", endpoint.letter());
        if parent_name.len() >= libc::IFNAMSIZ {
            return Err(VethOperationError::Unsafe(
                "derived parent interface name exceeds IFNAMSIZ",
            ));
        }
        Ok(Self {
            endpoint,
            parent_name,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct LinkObservation {
    parent_ifindex: u32,
    peer_ifindex: u32,
    peer_netnsid: i32,
}

/// Stable nsfs identity retained for the exact endpoint target of one pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct VethTargetNamespaceIdentity {
    device: u64,
    inode: u64,
}

impl VethTargetNamespaceIdentity {
    /// Namespace backing-device number.
    pub(crate) const fn device(self) -> u64 {
        self.device
    }

    /// Namespace inode number.
    pub(crate) const fn inode(self) -> u64 {
        self.inode
    }
}

struct RetainedTargetNamespace {
    descriptor: OwnedFd,
    identity: VethTargetNamespaceIdentity,
    owner_identity: VethTargetNamespaceIdentity,
}

impl RetainedTargetNamespace {
    fn capture<Fd: AsFd>(target: &Fd) -> Result<Self, VethOperationError> {
        let (identity, owner_identity) = validate_target_namespace(target)?;
        let descriptor = target
            .as_fd()
            .try_clone_to_owned()
            .map_err(|source| VethOperationError::io("retain target network namespace", source))?;
        let (cloned_identity, cloned_owner_identity) = validate_target_namespace(&descriptor)?;
        if cloned_identity != identity || cloned_owner_identity != owner_identity {
            return Err(VethOperationError::Unsafe(
                "retained target namespace descriptor changed during cloning",
            ));
        }
        Ok(Self {
            descriptor,
            identity,
            owner_identity,
        })
    }

    fn verify(&self) -> Result<(), VethOperationError> {
        let (identity, owner_identity) = validate_target_namespace(&self.descriptor)?;
        if identity != self.identity || owner_identity != self.owner_identity {
            return Err(VethOperationError::Unsafe(
                "retained target namespace identity changed",
            ));
        }
        Ok(())
    }

    fn verify_descriptor<Fd: AsFd>(&self, descriptor: &Fd) -> Result<(), VethOperationError> {
        let (identity, owner_identity) = validate_target_namespace(descriptor)?;
        if identity != self.identity || owner_identity != self.owner_identity {
            return Err(VethOperationError::Unsafe(
                "supplied endpoint namespace does not match retained target identity",
            ));
        }
        Ok(())
    }
}

struct MutationJournal {
    specification: VethSpecification,
    target: RetainedTargetNamespace,
    observation: Option<LinkObservation>,
}

impl MutationJournal {
    fn provisional(specification: VethSpecification, target: RetainedTargetNamespace) -> Self {
        Self {
            specification,
            target,
            observation: None,
        }
    }

    fn expected(&self) -> Result<LinkObservation, VethOperationError> {
        self.observation.ok_or(VethOperationError::Unsafe(
            "veth journal lacks a finalized link observation",
        ))
    }
}

/// Affine ownership and rollback authority for one exact fixed veth pair.
///
/// The token is deliberately neither cloneable nor transferable to another
/// thread. Dropping an armed token performs bounded exact cleanup and aborts if
/// absence cannot be established.
#[must_use = "dropping an armed fixed veth pair triggers fail-closed rollback"]
pub(crate) struct FixedVethPair {
    journal: Option<MutationJournal>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl FixedVethPair {
    /// Fixed endpoint associated with this pair.
    pub(crate) fn endpoint(&self) -> FixedVethEndpoint {
        self.journal().specification.endpoint
    }

    /// Run-derived parent-side interface name.
    pub(crate) fn parent_name(&self) -> &str {
        &self.journal().specification.parent_name
    }

    /// Fixed endpoint-side interface name.
    pub(crate) fn peer_name(&self) -> &'static str {
        let _ = self.journal();
        FIXED_VETH_PEER_NAME
    }

    /// Parent-namespace ifindex retained after exact creation readback.
    pub(crate) fn parent_ifindex(&self) -> u32 {
        self.observation().parent_ifindex
    }

    /// Endpoint-namespace peer ifindex retained from `IFLA_LINK` readback.
    pub(crate) fn peer_ifindex(&self) -> u32 {
        self.observation().peer_ifindex
    }

    /// Exact nsfs device/inode retained from the atomic target descriptor.
    pub(crate) fn target_namespace_identity(&self) -> VethTargetNamespaceIdentity {
        self.journal().target.identity
    }

    /// Prove that a caller-retained endpoint descriptor is this pair's target.
    pub(crate) fn verify_target_namespace_descriptor<Fd: AsFd>(
        &self,
        descriptor: &Fd,
    ) -> Result<(), VethVerifyError> {
        self.journal()
            .target
            .verify_descriptor(descriptor)
            .map_err(VethVerifyError)
    }

    /// Reopen RTNETLINK and prove the exact retained parent-side binding.
    pub(crate) fn verify(&self) -> Result<(), VethVerifyError> {
        verify_journal(self.journal()).map_err(VethVerifyError)
    }

    /// Delete through the freshly verified parent ifindex and prove absence.
    ///
    /// If the first attempt is ambiguous, a fresh bounded reconciliation is
    /// performed. An error is returned only after cleanup is nevertheless
    /// proven; failure to prove cleanup aborts fail closed.
    pub(crate) fn rollback(mut self) -> Result<(), VethRollbackError> {
        let result = delete_journal_exact(self.journal());
        match result {
            Ok(()) => {
                self.journal = None;
                Ok(())
            }
            Err(source) => {
                if reconcile_journal(self.journal()).is_err() {
                    std::process::abort();
                }
                self.journal = None;
                Err(VethRollbackError(source))
            }
        }
    }

    fn journal(&self) -> &MutationJournal {
        self.journal
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }

    fn observation(&self) -> LinkObservation {
        self.journal()
            .observation
            .unwrap_or_else(|| std::process::abort())
    }
}

impl Drop for FixedVethPair {
    fn drop(&mut self) {
        if let Some(journal) = self.journal.as_ref() {
            if reconcile_journal(journal).is_err() {
                std::process::abort();
            }
            self.journal = None;
        }
    }
}

struct ProvisionalVethGuard {
    journal: Option<MutationJournal>,
    armed: bool,
}

impl ProvisionalVethGuard {
    fn new(specification: VethSpecification, target: RetainedTargetNamespace) -> Self {
        Self {
            journal: Some(MutationJournal::provisional(specification, target)),
            armed: false,
        }
    }

    fn journal(&self) -> &MutationJournal {
        self.journal
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }

    fn mark_possibly_applied(&mut self) {
        self.armed = true;
    }

    fn reject(mut self, errno: i32) -> VethCreateError {
        self.armed = false;
        VethCreateError::Rejected(errno)
    }

    fn fail_possibly_applied(mut self, source: VethOperationError) -> VethCreateError {
        if reconcile_journal(self.journal()).is_err() {
            std::process::abort();
        }
        self.armed = false;
        VethCreateError::PossiblyApplied(source)
    }

    fn fail_readback(mut self, source: VethOperationError) -> VethCreateError {
        if reconcile_journal(self.journal()).is_err() {
            std::process::abort();
        }
        self.armed = false;
        VethCreateError::Readback(source)
    }

    fn into_pair(mut self, observation: LinkObservation) -> FixedVethPair {
        if !self.armed || observation.parent_ifindex == 0 || observation.peer_ifindex == 0 {
            std::process::abort();
        }
        self.journal
            .as_mut()
            .unwrap_or_else(|| std::process::abort())
            .observation = Some(observation);
        let journal = self.journal.take().unwrap_or_else(|| std::process::abort());
        self.armed = false;
        FixedVethPair {
            journal: Some(journal),
            _thread_bound: PhantomData,
        }
    }
}

impl Drop for ProvisionalVethGuard {
    fn drop(&mut self) {
        if self.armed {
            let journal = self
                .journal
                .as_ref()
                .unwrap_or_else(|| std::process::abort());
            if reconcile_journal(journal).is_err() {
                std::process::abort();
            }
        }
    }
}

/// Atomically create and exactly prove one fixed veth pair.
///
/// The target descriptor must be a distinct, read-only, close-on-exec network
/// namespace owned by the same user namespace as the current parent network
/// namespace.
pub(crate) fn create_fixed_veth_pair<Fd: AsFd>(
    run_id: &RunId,
    endpoint: FixedVethEndpoint,
    target_netns: &Fd,
) -> Result<FixedVethPair, VethCreateError> {
    let target =
        RetainedTargetNamespace::capture(target_netns).map_err(VethCreateError::BeforeMutation)?;
    let specification =
        VethSpecification::new(run_id, endpoint).map_err(VethCreateError::BeforeMutation)?;
    require_fixed_name_absent(observe_fixed_link(&specification))
        .map_err(VethCreateError::BeforeMutation)?;
    let request_payload = encode_create_payload(&specification, target.descriptor.as_raw_fd())
        .map_err(VethCreateError::BeforeMutation)?;
    let deadline =
        Deadline::after(VETH_OPERATION_TIMEOUT).map_err(VethCreateError::BeforeMutation)?;
    let mut client = NetlinkClient::connect(deadline).map_err(VethCreateError::BeforeMutation)?;
    let sequence = client
        .next_sequence()
        .map_err(VethCreateError::BeforeMutation)?;
    let request = encode_message(
        RTM_NEWLINK,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        sequence,
        &request_payload,
    )
    .map_err(VethCreateError::BeforeMutation)?;
    let mut guard = ProvisionalVethGuard::new(specification, target);
    match send_bounded(&client.socket, &request, deadline) {
        Ok(()) => guard.mark_possibly_applied(),
        Err(SendFailure::NotSent(source)) => {
            return Err(VethCreateError::BeforeMutation(source));
        }
        Err(SendFailure::PossiblySent(source)) => {
            guard.mark_possibly_applied();
            return Err(guard.fail_possibly_applied(source));
        }
    }
    let reply = match receive_bounded(&client.socket, deadline) {
        Ok(reply) => reply,
        Err(source) => return Err(guard.fail_possibly_applied(source)),
    };
    match parse_ack(&reply, client.local_port, &request) {
        Ok(Ack::Success) => {}
        Ok(Ack::Rejected(errno)) => return Err(guard.reject(errno)),
        Err(source) => return Err(guard.fail_possibly_applied(source)),
    }
    drop(client);

    let observation = match observe_fixed_link(&guard.journal().specification) {
        Ok(Some(observation)) => observation,
        Ok(None) => {
            return Err(guard.fail_readback(VethOperationError::Unsafe(
                "ACKed fixed veth is absent from exact readback",
            )));
        }
        Err(source) => return Err(guard.fail_readback(source)),
    };
    if let Err(source) = verify_target_lineage(&guard.journal().target, observation) {
        return Err(guard.fail_readback(source));
    }
    Ok(guard.into_pair(observation))
}

fn require_fixed_name_absent(
    observation: Result<Option<LinkObservation>, VethOperationError>,
) -> Result<(), VethOperationError> {
    match observation? {
        None => Ok(()),
        Some(_) => Err(VethOperationError::Unsafe(
            "fixed parent interface name already exists before creation",
        )),
    }
}

fn validate_target_namespace<Fd: AsFd>(
    target: &Fd,
) -> Result<(VethTargetNamespaceIdentity, VethTargetNamespaceIdentity), VethOperationError> {
    let descriptor_flags = FdFlag::from_bits_truncate(
        fcntl(target, FcntlArg::F_GETFD)
            .map_err(|source| errno_io("read target namespace descriptor flags", source))?,
    );
    let status_flags = OFlag::from_bits_truncate(
        fcntl(target, FcntlArg::F_GETFL)
            .map_err(|source| errno_io("read target namespace status flags", source))?,
    );
    if !descriptor_flags.contains(FdFlag::FD_CLOEXEC)
        || status_flags & OFlag::O_ACCMODE != OFlag::O_RDONLY
    {
        return Err(VethOperationError::Unsafe(
            "target namespace descriptor is not read-only and close-on-exec",
        ));
    }
    require_network_nsfs(target)?;
    let target_identity = object_identity(target)?;
    let target_owner = owning_user_namespace(target)
        .map_err(|source| VethOperationError::io("open target owning user namespace", source))?;

    let current = open(
        CURRENT_NETWORK_NAMESPACE,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| rustix_io("open current parent network namespace", source))?;
    require_network_nsfs(&current)?;
    if object_identity(&current)? == target_identity {
        return Err(VethOperationError::Unsafe(
            "target network namespace equals the current parent namespace",
        ));
    }
    let current_owner = owning_user_namespace(&current)
        .map_err(|source| VethOperationError::io("open parent owning user namespace", source))?;
    let target_owner_identity = object_identity(&target_owner)?;
    if target_owner_identity != object_identity(&current_owner)? {
        return Err(VethOperationError::Unsafe(
            "target network namespace has a different owning user namespace",
        ));
    }
    Ok((target_identity, target_owner_identity))
}

fn object_identity<Fd: AsFd>(
    descriptor: Fd,
) -> Result<VethTargetNamespaceIdentity, VethOperationError> {
    let metadata =
        fstat(descriptor).map_err(|source| rustix_io("measure namespace descriptor", source))?;
    if metadata.st_dev == 0 || metadata.st_ino == 0 {
        return Err(VethOperationError::Unsafe(
            "namespace descriptor identity is zero",
        ));
    }
    Ok(VethTargetNamespaceIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

fn require_network_nsfs<Fd: AsFd>(descriptor: Fd) -> Result<(), VethOperationError> {
    if fstatfs(&descriptor)
        .map_err(|source| rustix_io("identify namespace filesystem", source))?
        .f_type
        != NSFS_MAGIC
        || namespace_type(&descriptor)
            .map_err(|source| VethOperationError::io("identify network namespace", source))?
            != libc::CLONE_NEWNET
    {
        return Err(VethOperationError::Unsafe(
            "target descriptor is not a network nsfs object",
        ));
    }
    Ok(())
}

fn errno_io(operation: &'static str, source: nix::errno::Errno) -> VethOperationError {
    VethOperationError::io(operation, io::Error::from_raw_os_error(source as i32))
}

fn rustix_io(operation: &'static str, source: rustix::io::Errno) -> VethOperationError {
    VethOperationError::io(
        operation,
        io::Error::from_raw_os_error(source.raw_os_error()),
    )
}

#[derive(Clone, Copy)]
struct Deadline(Instant);

impl Deadline {
    fn after(duration: Duration) -> Result<Self, VethOperationError> {
        Instant::now()
            .checked_add(duration)
            .map(Self)
            .ok_or(VethOperationError::Limit)
    }

    fn poll_timeout(self) -> Result<PollTimeout, VethOperationError> {
        let remaining = self
            .0
            .checked_duration_since(Instant::now())
            .ok_or_else(timeout_error)?;
        let millis = remaining.as_millis();
        let rounded = if remaining.subsec_nanos() % 1_000_000 == 0 {
            millis
        } else {
            millis.checked_add(1).ok_or(VethOperationError::Limit)?
        };
        PollTimeout::try_from(rounded).map_err(|_| VethOperationError::Limit)
    }

    fn ensure_unexpired(self) -> Result<(), VethOperationError> {
        if Instant::now() < self.0 {
            Ok(())
        } else {
            Err(timeout_error())
        }
    }
}

fn timeout_error() -> VethOperationError {
    VethOperationError::io(
        "wait for RTNETLINK response",
        io::Error::new(io::ErrorKind::TimedOut, "fixed veth deadline expired"),
    )
}

struct NetlinkClient {
    socket: Socket,
    local_port: u32,
    sequence: u32,
}

impl NetlinkClient {
    fn connect(deadline: Deadline) -> Result<Self, VethOperationError> {
        deadline.ensure_unexpired()?;
        let mut socket = Socket::new(NETLINK_ROUTE)
            .map_err(|source| VethOperationError::io("open RTNETLINK socket", source))?;
        socket
            .set_non_blocking(true)
            .map_err(|source| VethOperationError::io("harden RTNETLINK socket", source))?;
        let address = socket
            .bind_auto()
            .map_err(|source| VethOperationError::io("bind RTNETLINK socket", source))?;
        if address.port_number() == 0 || address.multicast_groups() != 0 {
            return Err(VethOperationError::Unsafe(
                "RTNETLINK socket binding is not exact",
            ));
        }
        socket
            .connect(&SocketAddr::new(0, 0))
            .map_err(|source| VethOperationError::io("connect RTNETLINK socket", source))?;
        deadline.ensure_unexpired()?;
        Ok(Self {
            socket,
            local_port: address.port_number(),
            sequence: 1,
        })
    }

    fn next_sequence(&mut self) -> Result<u32, VethOperationError> {
        let current = self.sequence;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(VethOperationError::Limit)?;
        if current == 0 {
            Err(VethOperationError::Unsafe("RTNETLINK sequence is zero"))
        } else {
            Ok(current)
        }
    }
}

enum SendFailure {
    NotSent(VethOperationError),
    PossiblySent(VethOperationError),
}

fn send_bounded(socket: &Socket, request: &[u8], deadline: Deadline) -> Result<(), SendFailure> {
    loop {
        deadline.ensure_unexpired().map_err(SendFailure::NotSent)?;
        match socket.send(request, 0) {
            Ok(written) if written == request.len() => return Ok(()),
            Ok(_) => {
                return Err(SendFailure::PossiblySent(VethOperationError::io(
                    "send complete RTNETLINK datagram",
                    io::Error::new(io::ErrorKind::WriteZero, "short RTNETLINK datagram write"),
                )));
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                wait_for_socket(socket, PollFlags::POLLOUT, deadline)
                    .map_err(SendFailure::NotSent)?;
            }
            Err(error) if error.kind() == io::ErrorKind::Interrupted => {}
            Err(error) => {
                return Err(SendFailure::NotSent(VethOperationError::io(
                    "send RTNETLINK request",
                    error,
                )));
            }
        }
    }
}

struct NetlinkReply {
    sender: SocketAddr,
    bytes: Vec<u8>,
}

fn receive_bounded(
    socket: &Socket,
    deadline: Deadline,
) -> Result<NetlinkReply, VethOperationError> {
    loop {
        wait_for_socket(socket, PollFlags::POLLIN, deadline)?;
        let mut probe = Vec::new();
        let (length, peek_sender) =
            match socket.recv_from(&mut probe, libc::MSG_PEEK | libc::MSG_TRUNC) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(VethOperationError::io("measure RTNETLINK response", error));
                }
            };
        if peek_sender != SocketAddr::new(0, 0) {
            return Err(VethOperationError::Unsafe(
                "RTNETLINK response sender is not the kernel",
            ));
        }
        if !(NLMSG_HEADER_LEN..=MAX_NETLINK_DATAGRAM_BYTES).contains(&length) {
            return Err(VethOperationError::Limit);
        }
        deadline.ensure_unexpired()?;
        let mut bytes = Vec::with_capacity(length);
        let (received, sender) = match socket.recv_from(&mut bytes, 0) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(VethOperationError::io("receive RTNETLINK response", error));
            }
        };
        deadline.ensure_unexpired()?;
        if received != length || bytes.len() != length || sender != peek_sender {
            return Err(VethOperationError::Unsafe(
                "RTNETLINK response changed during bounded receive",
            ));
        }
        return Ok(NetlinkReply { sender, bytes });
    }
}

fn wait_for_socket(
    socket: &Socket,
    expected: PollFlags,
    deadline: Deadline,
) -> Result<(), VethOperationError> {
    loop {
        let mut descriptors = [PollFd::new(socket.as_fd(), expected)];
        match poll(&mut descriptors, deadline.poll_timeout()?) {
            Ok(0) => return Err(timeout_error()),
            Ok(_) => {
                deadline.ensure_unexpired()?;
                let events = descriptors[0].revents().unwrap_or_else(PollFlags::empty);
                if events.intersects(PollFlags::POLLERR | PollFlags::POLLHUP | PollFlags::POLLNVAL)
                    || !events.contains(expected)
                    || !(events - expected).is_empty()
                {
                    return Err(VethOperationError::Unsafe(
                        "RTNETLINK poll state is ambiguous",
                    ));
                }
                return Ok(());
            }
            Err(nix::errno::Errno::EINTR) => deadline.ensure_unexpired()?,
            Err(source) => return Err(errno_io("poll RTNETLINK socket", source)),
        }
    }
}

fn encode_create_payload(
    specification: &VethSpecification,
    target_fd: i32,
) -> Result<Vec<u8>, VethOperationError> {
    if target_fd < 0 {
        return Err(VethOperationError::Unsafe(
            "target namespace descriptor is negative",
        ));
    }
    let mut peer = interface_info(0, 0, 0);
    push_string_attribute(&mut peer, IFLA_IFNAME, FIXED_VETH_PEER_NAME)?;
    push_attribute(&mut peer, IFLA_MTU, &FIXED_VETH_MTU.to_ne_bytes())?;
    push_attribute(
        &mut peer,
        IFLA_TXQLEN,
        &FIXED_VETH_TX_QUEUE_LENGTH.to_ne_bytes(),
    )?;
    push_fixed_queue_attributes(&mut peer)?;
    push_attribute(&mut peer, IFLA_NET_NS_FD, &target_fd.to_ne_bytes())?;

    let mut data = Vec::new();
    push_attribute(&mut data, VETH_INFO_PEER | NLA_F_NESTED, &peer)?;
    let mut link_info = Vec::new();
    push_string_attribute(&mut link_info, IFLA_INFO_KIND, "veth")?;
    push_attribute(&mut link_info, IFLA_INFO_DATA | NLA_F_NESTED, &data)?;

    let mut payload = interface_info(0, 0, 0);
    push_string_attribute(&mut payload, IFLA_IFNAME, &specification.parent_name)?;
    push_attribute(&mut payload, IFLA_MTU, &FIXED_VETH_MTU.to_ne_bytes())?;
    push_attribute(
        &mut payload,
        IFLA_TXQLEN,
        &FIXED_VETH_TX_QUEUE_LENGTH.to_ne_bytes(),
    )?;
    push_fixed_queue_attributes(&mut payload)?;
    push_attribute(&mut payload, IFLA_LINKINFO | NLA_F_NESTED, &link_info)?;
    if payload.len() > MAX_REQUEST_BYTES {
        return Err(VethOperationError::Limit);
    }
    Ok(payload)
}

fn push_fixed_queue_attributes(payload: &mut Vec<u8>) -> Result<(), VethOperationError> {
    let queue_count = FIXED_VETH_QUEUE_COUNT.to_ne_bytes();
    push_attribute(payload, IFLA_NUM_TX_QUEUES, &queue_count)?;
    push_attribute(payload, IFLA_NUM_RX_QUEUES, &queue_count)
}

fn encode_get_payload(name: &str) -> Result<Vec<u8>, VethOperationError> {
    let mut payload = interface_info(0, 0, 0);
    push_string_attribute(&mut payload, IFLA_IFNAME, name)?;
    Ok(payload)
}

fn encode_get_nsid_payload(target_fd: i32) -> Result<Vec<u8>, VethOperationError> {
    let target_fd = u32::try_from(target_fd)
        .map_err(|_| VethOperationError::Unsafe("target namespace descriptor is negative"))?;
    let mut payload = vec![AF_UNSPEC, 0, 0, 0];
    push_attribute(&mut payload, NETNSA_FD, &target_fd.to_ne_bytes())?;
    Ok(payload)
}

fn encode_delete_payload(ifindex: u32) -> Result<Vec<u8>, VethOperationError> {
    if ifindex == 0 || ifindex > i32::MAX as u32 {
        return Err(VethOperationError::Unsafe(
            "parent veth ifindex is not representable",
        ));
    }
    Ok(interface_info(ifindex, 0, 0))
}

fn interface_info(index: u32, flags: u32, change: u32) -> Vec<u8> {
    let mut payload = Vec::with_capacity(IFINFO_LEN);
    payload.push(AF_UNSPEC);
    payload.push(0);
    payload.extend_from_slice(&0_u16.to_ne_bytes());
    payload.extend_from_slice(&index.to_ne_bytes());
    payload.extend_from_slice(&flags.to_ne_bytes());
    payload.extend_from_slice(&change.to_ne_bytes());
    payload
}

fn encode_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    payload: &[u8],
) -> Result<Vec<u8>, VethOperationError> {
    if sequence == 0 {
        return Err(VethOperationError::Unsafe("netlink sequence is zero"));
    }
    let length = NLMSG_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(VethOperationError::Limit)?;
    if length > MAX_REQUEST_BYTES {
        return Err(VethOperationError::Limit);
    }
    let mut message = Vec::with_capacity(length);
    message.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| VethOperationError::Limit)?
            .to_ne_bytes(),
    );
    message.extend_from_slice(&message_type.to_ne_bytes());
    message.extend_from_slice(&flags.to_ne_bytes());
    message.extend_from_slice(&sequence.to_ne_bytes());
    message.extend_from_slice(&0_u32.to_ne_bytes());
    message.extend_from_slice(payload);
    Ok(message)
}

fn push_string_attribute(
    buffer: &mut Vec<u8>,
    kind: u16,
    value: &str,
) -> Result<(), VethOperationError> {
    if value.is_empty()
        || value.len() >= libc::IFNAMSIZ
        || value.as_bytes().contains(&0)
        || !value.is_ascii()
    {
        return Err(VethOperationError::Unsafe(
            "fixed link string attribute is invalid",
        ));
    }
    let mut encoded = value.as_bytes().to_vec();
    encoded.push(0);
    push_attribute(buffer, kind, &encoded)
}

fn push_attribute(
    buffer: &mut Vec<u8>,
    kind: u16,
    payload: &[u8],
) -> Result<(), VethOperationError> {
    let length = ATTRIBUTE_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(VethOperationError::Limit)?;
    let encoded_length = u16::try_from(length).map_err(|_| VethOperationError::Limit)?;
    buffer.extend_from_slice(&encoded_length.to_ne_bytes());
    buffer.extend_from_slice(&kind.to_ne_bytes());
    buffer.extend_from_slice(payload);
    buffer.resize(align4(buffer.len())?, 0);
    if buffer.len() > MAX_REQUEST_BYTES {
        return Err(VethOperationError::Limit);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum Ack {
    Success,
    Rejected(i32),
}

fn parse_ack(
    reply: &NetlinkReply,
    local_port: u32,
    request: &[u8],
) -> Result<Ack, VethOperationError> {
    if reply.sender != SocketAddr::new(0, 0) {
        return Err(VethOperationError::Unsafe(
            "netlink ACK sender is not the kernel",
        ));
    }
    let frame = single_frame(&reply.bytes)?;
    let flags = read_u16(frame, 6)?;
    if read_u16(frame, 4)? != NLMSG_ERROR
        || read_u32(frame, 8)? != read_u32(request, 8)?
        || read_u32(frame, 12)? != local_port
    {
        return Err(VethOperationError::Unsafe(
            "netlink ACK header is not exact",
        ));
    }
    let payload = &frame[NLMSG_HEADER_LEN..];
    let embedded_length = NLMSG_ERROR_CODE_LEN
        .checked_add(NLMSG_HEADER_LEN)
        .ok_or(VethOperationError::Limit)?;
    if payload.len() < embedded_length
        || payload[NLMSG_ERROR_CODE_LEN..embedded_length] != request[..NLMSG_HEADER_LEN]
    {
        return Err(VethOperationError::Unsafe(
            "netlink ACK does not bind the exact request header",
        ));
    }
    let trailing = &payload[embedded_length..];
    let errno = read_i32(payload, 0)?;
    if flags & NLM_F_ACK_TLVS != 0 {
        return Err(VethOperationError::Unsafe(
            "netlink ACK unexpectedly carries extended ACK attributes",
        ));
    }
    match errno {
        0 if flags == NLM_F_CAPPED && trailing.is_empty() => Ok(Ack::Success),
        errno
            if errno < 0
                && errno != i32::MIN
                && flags == 0
                && trailing == &request[NLMSG_HEADER_LEN..] =>
        {
            Ok(Ack::Rejected(-errno))
        }
        0 => Err(VethOperationError::Unsafe(
            "successful netlink ACK is not the canonical capped form",
        )),
        errno if errno < 0 => Err(VethOperationError::Unsafe(
            "negative netlink ACK does not exactly echo the request",
        )),
        _ => Err(VethOperationError::Unsafe(
            "netlink ACK errno is not canonical",
        )),
    }
}

fn single_frame(bytes: &[u8]) -> Result<&[u8], VethOperationError> {
    if bytes.len() < NLMSG_HEADER_LEN {
        return Err(VethOperationError::Unsafe(
            "netlink datagram lacks a complete header",
        ));
    }
    let length = usize::try_from(read_u32(bytes, 0)?).map_err(|_| VethOperationError::Limit)?;
    let aligned = align4(length)?;
    if length < NLMSG_HEADER_LEN || aligned != bytes.len() {
        return Err(VethOperationError::Unsafe(
            "netlink datagram does not contain exactly one frame",
        ));
    }
    if bytes[length..aligned].iter().any(|byte| *byte != 0) {
        return Err(VethOperationError::Unsafe(
            "netlink frame padding is nonzero",
        ));
    }
    Ok(&bytes[..length])
}

#[derive(Clone, Copy)]
struct Attribute<'a> {
    kind: u16,
    flags: u16,
    payload: &'a [u8],
}

fn parse_attributes(mut bytes: &[u8]) -> Result<Vec<Attribute<'_>>, VethOperationError> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if result.len() >= MAX_ATTRIBUTES || bytes.len() < ATTRIBUTE_HEADER_LEN {
            return Err(VethOperationError::Limit);
        }
        let length = usize::from(read_u16(bytes, 0)?);
        let aligned = align4(length)?;
        if length < ATTRIBUTE_HEADER_LEN || aligned > bytes.len() {
            return Err(VethOperationError::Unsafe(
                "netlink attribute length is invalid",
            ));
        }
        if bytes[length..aligned].iter().any(|byte| *byte != 0) {
            return Err(VethOperationError::Unsafe(
                "netlink attribute padding is nonzero",
            ));
        }
        let raw_kind = read_u16(bytes, 2)?;
        let flags = raw_kind & !NLA_TYPE_MASK;
        if flags == NLA_F_NESTED | NLA_F_NET_BYTEORDER {
            return Err(VethOperationError::Unsafe(
                "netlink attribute flags are contradictory",
            ));
        }
        result.push(Attribute {
            kind: raw_kind & NLA_TYPE_MASK,
            flags,
            payload: &bytes[ATTRIBUTE_HEADER_LEN..length],
        });
        bytes = &bytes[aligned..];
    }
    Ok(result)
}

fn parse_fixed_link(
    frame: &[u8],
    local_port: u32,
    sequence: u32,
    specification: &VethSpecification,
) -> Result<LinkObservation, VethOperationError> {
    if read_u16(frame, 4)? != RTM_NEWLINK
        || read_u16(frame, 6)? != 0
        || read_u32(frame, 8)? != sequence
        || read_u32(frame, 12)? != local_port
        || frame.len() < NLMSG_HEADER_LEN + IFINFO_LEN
    {
        return Err(VethOperationError::Unsafe(
            "RTM_GETLINK response header is not exact",
        ));
    }
    let info = &frame[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + IFINFO_LEN];
    if info[0] != AF_UNSPEC
        || info[1] != 0
        || read_u16(info, 2)? != ARPHRD_ETHER
        || read_u32(info, 8)? != FIXED_DOWN_VETH_FLAGS
        || read_u32(info, 12)? != 0
    {
        return Err(VethOperationError::Unsafe(
            "fixed parent veth header is not exact and down",
        ));
    }
    let parent_index = read_i32(info, 4)?;
    if parent_index <= 0 {
        return Err(VethOperationError::Unsafe(
            "fixed parent veth ifindex is not positive",
        ));
    }

    let mut name = None;
    let mut mtu = None;
    let mut peer_ifindex = None;
    let mut peer_netnsid = None;
    let mut queue_length = None;
    let mut transmit_queues = None;
    let mut receive_queues = None;
    let mut kind = None;
    for attribute in parse_attributes(&frame[NLMSG_HEADER_LEN + IFINFO_LEN..])? {
        match attribute.kind {
            IFLA_IFNAME if attribute.flags == 0 => {
                set_once(&mut name, parse_string(attribute.payload)?)?;
            }
            IFLA_MTU if attribute.flags == 0 => {
                set_once(&mut mtu, read_exact_u32(attribute.payload)?)?;
            }
            IFLA_LINK if attribute.flags == 0 => {
                set_once(&mut peer_ifindex, read_exact_u32(attribute.payload)?)?;
            }
            IFLA_LINK_NETNSID if attribute.flags == 0 => {
                set_once(&mut peer_netnsid, read_exact_i32(attribute.payload)?)?;
            }
            IFLA_TXQLEN if attribute.flags == 0 => {
                set_once(&mut queue_length, read_exact_u32(attribute.payload)?)?;
            }
            IFLA_NUM_TX_QUEUES if attribute.flags == 0 => {
                set_once(&mut transmit_queues, read_exact_u32(attribute.payload)?)?;
            }
            IFLA_NUM_RX_QUEUES if attribute.flags == 0 => {
                set_once(&mut receive_queues, read_exact_u32(attribute.payload)?)?;
            }
            IFLA_LINKINFO if matches!(attribute.flags, 0 | NLA_F_NESTED) => {
                set_once(&mut kind, parse_link_kind(attribute.payload)?)?;
            }
            _ => {}
        }
    }
    let peer_ifindex = peer_ifindex.ok_or(VethOperationError::Unsafe(
        "fixed parent veth lacks peer ifindex",
    ))?;
    let peer_netnsid = peer_netnsid.ok_or(VethOperationError::Unsafe(
        "fixed parent veth lacks peer network namespace ID",
    ))?;
    if name.as_deref() != Some(specification.parent_name.as_str())
        || mtu != Some(FIXED_VETH_MTU)
        || queue_length != Some(FIXED_VETH_TX_QUEUE_LENGTH)
        || transmit_queues != Some(FIXED_VETH_QUEUE_COUNT)
        || receive_queues != Some(FIXED_VETH_QUEUE_COUNT)
        || kind.as_deref() != Some("veth")
        || peer_ifindex == 0
        || peer_netnsid < 0
    {
        return Err(VethOperationError::Unsafe(
            "fixed parent veth attributes do not match the contract",
        ));
    }
    Ok(LinkObservation {
        parent_ifindex: u32::try_from(parent_index).map_err(|_| VethOperationError::Limit)?,
        peer_ifindex,
        peer_netnsid,
    })
}

fn parse_nsid_reply(
    reply: &NetlinkReply,
    local_port: u32,
    sequence: u32,
) -> Result<i32, VethOperationError> {
    if reply.sender != SocketAddr::new(0, 0) {
        return Err(VethOperationError::Unsafe(
            "network namespace ID response sender is not the kernel",
        ));
    }
    let frame = single_frame(&reply.bytes)?;
    if read_u16(frame, 4)? != RTM_NEWNSID
        || read_u16(frame, 6)? != 0
        || read_u32(frame, 8)? != sequence
        || read_u32(frame, 12)? != local_port
        || frame.len() < NLMSG_HEADER_LEN + NSID_HEADER_LEN
        || frame[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + NSID_HEADER_LEN] != [AF_UNSPEC, 0, 0, 0]
    {
        return Err(VethOperationError::Unsafe(
            "RTM_GETNSID response header is not exact",
        ));
    }
    let attributes = parse_attributes(&frame[NLMSG_HEADER_LEN + NSID_HEADER_LEN..])?;
    let mut nsid = None;
    for attribute in attributes {
        if attribute.kind != NETNSA_NSID || attribute.flags != 0 {
            return Err(VethOperationError::Unsafe(
                "RTM_GETNSID response has an unexpected attribute",
            ));
        }
        set_once(&mut nsid, read_exact_i32(attribute.payload)?)?;
    }
    match nsid {
        Some(value) if value >= 0 => Ok(value),
        Some(_) => Err(VethOperationError::Unsafe(
            "target network namespace has no assigned parent namespace ID",
        )),
        None => Err(VethOperationError::Unsafe(
            "RTM_GETNSID response lacks the target namespace ID",
        )),
    }
}

fn parse_link_kind(payload: &[u8]) -> Result<String, VethOperationError> {
    let mut kind = None;
    for attribute in parse_attributes(payload)? {
        if attribute.kind == IFLA_INFO_KIND && attribute.flags == 0 {
            set_once(&mut kind, parse_string(attribute.payload)?)?;
        }
    }
    kind.ok_or(VethOperationError::Unsafe("link info lacks an exact kind"))
}

fn parse_string(payload: &[u8]) -> Result<String, VethOperationError> {
    let bytes = payload
        .strip_suffix(&[0])
        .ok_or(VethOperationError::Unsafe(
            "netlink string is not NUL terminated",
        ))?;
    if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ || bytes.contains(&0) || !bytes.is_ascii()
    {
        return Err(VethOperationError::Unsafe(
            "netlink string is not canonical",
        ));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| VethOperationError::Unsafe("netlink string is not UTF-8"))
}

fn observe_fixed_link(
    specification: &VethSpecification,
) -> Result<Option<LinkObservation>, VethOperationError> {
    let deadline = Deadline::after(VETH_OPERATION_TIMEOUT)?;
    let mut client = NetlinkClient::connect(deadline)?;
    let sequence = client.next_sequence()?;
    let payload = encode_get_payload(&specification.parent_name)?;
    let request = encode_message(RTM_GETLINK, NLM_F_REQUEST, sequence, &payload)?;
    send_bounded(&client.socket, &request, deadline).map_err(|failure| match failure {
        SendFailure::NotSent(source) | SendFailure::PossiblySent(source) => source,
    })?;
    let reply = receive_bounded(&client.socket, deadline)?;
    let frame = single_frame(&reply.bytes)?;
    if read_u16(frame, 4)? == NLMSG_ERROR {
        return match parse_ack(&reply, client.local_port, &request)? {
            Ack::Rejected(errno) if errno == libc::ENODEV || errno == libc::ENOENT => Ok(None),
            Ack::Rejected(errno) => Err(VethOperationError::errno("query fixed veth", errno)),
            Ack::Success => Err(VethOperationError::Unsafe(
                "RTM_GETLINK returned a success ACK without link data",
            )),
        };
    }
    parse_fixed_link(frame, client.local_port, sequence, specification).map(Some)
}

fn query_target_nsid(target: &RetainedTargetNamespace) -> Result<i32, VethOperationError> {
    target.verify()?;
    let deadline = Deadline::after(VETH_OPERATION_TIMEOUT)?;
    let mut client = NetlinkClient::connect(deadline)?;
    let sequence = client.next_sequence()?;
    let payload = encode_get_nsid_payload(target.descriptor.as_raw_fd())?;
    let request = encode_message(RTM_GETNSID, NLM_F_REQUEST, sequence, &payload)?;
    send_bounded(&client.socket, &request, deadline).map_err(|failure| match failure {
        SendFailure::NotSent(source) | SendFailure::PossiblySent(source) => source,
    })?;
    let reply = receive_bounded(&client.socket, deadline)?;
    let frame = single_frame(&reply.bytes)?;
    if read_u16(frame, 4)? == NLMSG_ERROR {
        return match parse_ack(&reply, client.local_port, &request)? {
            Ack::Rejected(errno) => Err(VethOperationError::errno(
                "query target network namespace ID",
                errno,
            )),
            Ack::Success => Err(VethOperationError::Unsafe(
                "RTM_GETNSID returned a success ACK without namespace data",
            )),
        };
    }
    parse_nsid_reply(&reply, client.local_port, sequence)
}

fn verify_target_lineage(
    target: &RetainedTargetNamespace,
    observation: LinkObservation,
) -> Result<(), VethOperationError> {
    target.verify()?;
    require_matching_target_nsid(observation, query_target_nsid(target)?)
}

fn require_matching_target_nsid(
    observation: LinkObservation,
    target_nsid: i32,
) -> Result<(), VethOperationError> {
    if target_nsid < 0 || target_nsid != observation.peer_netnsid {
        return Err(VethOperationError::Unsafe(
            "parent veth peer namespace ID does not bind the retained target namespace",
        ));
    }
    Ok(())
}

fn verify_journal(journal: &MutationJournal) -> Result<(), VethOperationError> {
    let expected = journal.expected()?;
    match observe_fixed_link(&journal.specification)? {
        Some(observed) if observed == expected => verify_target_lineage(&journal.target, observed),
        Some(_) => Err(VethOperationError::Unsafe(
            "retained fixed veth ifindex binding changed",
        )),
        None => Err(VethOperationError::Unsafe(
            "retained fixed veth parent is absent",
        )),
    }
}

fn delete_journal_exact(journal: &MutationJournal) -> Result<(), VethOperationError> {
    let expected = journal.expected()?;
    delete_observed_exact(journal, expected)
}

fn delete_observed_exact(
    journal: &MutationJournal,
    expected: LinkObservation,
) -> Result<(), VethOperationError> {
    match observe_fixed_link(&journal.specification)? {
        Some(observed) if observed == expected => verify_target_lineage(&journal.target, observed)?,
        Some(_) => {
            return Err(VethOperationError::Unsafe(
                "fixed veth changed before exact deletion",
            ));
        }
        None => {
            return Err(VethOperationError::Unsafe(
                "fixed veth disappeared before exact deletion",
            ));
        }
    }
    let deadline = Deadline::after(VETH_OPERATION_TIMEOUT)?;
    let mut client = NetlinkClient::connect(deadline)?;
    let sequence = client.next_sequence()?;
    let payload = encode_delete_payload(expected.parent_ifindex)?;
    let request = encode_message(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, sequence, &payload)?;
    send_bounded(&client.socket, &request, deadline).map_err(|failure| match failure {
        SendFailure::NotSent(source) | SendFailure::PossiblySent(source) => source,
    })?;
    let reply = receive_bounded(&client.socket, deadline)?;
    match parse_ack(&reply, client.local_port, &request)? {
        Ack::Success => {}
        Ack::Rejected(errno) => {
            return Err(VethOperationError::errno("delete fixed veth", errno));
        }
    }
    drop(client);
    if observe_fixed_link(&journal.specification)?.is_some() {
        return Err(VethOperationError::Unsafe(
            "deleted fixed veth remains visible",
        ));
    }
    Ok(())
}

fn reconcile_journal(journal: &MutationJournal) -> Result<(), VethOperationError> {
    reconcile_observed_state(
        journal.observation,
        || observe_fixed_link(&journal.specification),
        |observed| verify_target_lineage(&journal.target, observed),
        |observed| delete_observed_exact(journal, observed),
    )
}

fn reconcile_observed_state<Observe, Verify, Delete>(
    mut expected: Option<LinkObservation>,
    mut observe: Observe,
    mut verify: Verify,
    mut delete: Delete,
) -> Result<(), VethOperationError>
where
    Observe: FnMut() -> Result<Option<LinkObservation>, VethOperationError>,
    Verify: FnMut(LinkObservation) -> Result<(), VethOperationError>,
    Delete: FnMut(LinkObservation) -> Result<(), VethOperationError>,
{
    for _ in 0..MAX_RECONCILIATION_DELETE_ATTEMPTS {
        let observed = match observe()? {
            None => return Ok(()),
            Some(observed) => observed,
        };
        if expected.is_some_and(|candidate| observed != candidate) {
            return Err(VethOperationError::Unsafe(
                "cleanup encountered a different fixed-name veth",
            ));
        }
        verify(observed)?;

        // After a lost create ACK, the first exact, lineage-bound observation
        // is the only candidate this cleanup transaction may adopt. Pinning it
        // locally prevents a later same-name replacement from being deleted
        // after an ambiguous first delete.
        expected.get_or_insert(observed);
        if delete(observed).is_ok() {
            return Ok(());
        }
    }

    match observe()? {
        None => Ok(()),
        Some(observed) if expected.is_some_and(|candidate| observed != candidate) => Err(
            VethOperationError::Unsafe("cleanup encountered a different fixed-name veth"),
        ),
        Some(_) => Err(VethOperationError::Unsafe(
            "fixed veth cleanup could not prove absence",
        )),
    }
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, VethOperationError> {
    let end = offset.checked_add(2).ok_or(VethOperationError::Limit)?;
    let value = bytes
        .get(offset..end)
        .ok_or(VethOperationError::Unsafe("truncated netlink u16"))?
        .try_into()
        .map_err(|_| VethOperationError::Unsafe("invalid netlink u16"))?;
    Ok(u16::from_ne_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, VethOperationError> {
    let end = offset.checked_add(4).ok_or(VethOperationError::Limit)?;
    let value = bytes
        .get(offset..end)
        .ok_or(VethOperationError::Unsafe("truncated netlink u32"))?
        .try_into()
        .map_err(|_| VethOperationError::Unsafe("invalid netlink u32"))?;
    Ok(u32::from_ne_bytes(value))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, VethOperationError> {
    let end = offset.checked_add(4).ok_or(VethOperationError::Limit)?;
    let value = bytes
        .get(offset..end)
        .ok_or(VethOperationError::Unsafe("truncated netlink i32"))?
        .try_into()
        .map_err(|_| VethOperationError::Unsafe("invalid netlink i32"))?;
    Ok(i32::from_ne_bytes(value))
}

fn read_exact_u32(bytes: &[u8]) -> Result<u32, VethOperationError> {
    if bytes.len() != 4 {
        return Err(VethOperationError::Unsafe(
            "netlink u32 attribute has the wrong size",
        ));
    }
    read_u32(bytes, 0)
}

fn read_exact_i32(bytes: &[u8]) -> Result<i32, VethOperationError> {
    if bytes.len() != 4 {
        return Err(VethOperationError::Unsafe(
            "netlink i32 attribute has the wrong size",
        ));
    }
    read_i32(bytes, 0)
}

fn align4(length: usize) -> Result<usize, VethOperationError> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(VethOperationError::Limit)
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), VethOperationError> {
    if slot.replace(value).is_some() {
        Err(VethOperationError::Unsafe(
            "required netlink attribute is duplicated",
        ))
    } else {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use std::{cell::RefCell, collections::VecDeque, rc::Rc};

    use super::*;

    const RUN: &str = "0123456789abcdef0123456789abcdef";
    const SEQUENCE: u32 = 7;
    const PORT: u32 = 41;

    fn run_id() -> RunId {
        RunId::parse(RUN).expect("fixed run ID")
    }

    fn specification() -> VethSpecification {
        VethSpecification::new(&run_id(), FixedVethEndpoint::A).expect("specification")
    }

    fn reply(bytes: Vec<u8>) -> NetlinkReply {
        NetlinkReply {
            sender: SocketAddr::new(0, 0),
            bytes,
        }
    }

    fn ack_with_shape(request: &[u8], errno: i32, flags: u16, echo_payload: bool) -> Vec<u8> {
        let mut payload = Vec::new();
        payload.extend_from_slice(&errno.to_ne_bytes());
        payload.extend_from_slice(&request[..NLMSG_HEADER_LEN]);
        if echo_payload {
            payload.extend_from_slice(&request[NLMSG_HEADER_LEN..]);
        }
        encode_message(NLMSG_ERROR, flags, SEQUENCE, &payload)
            .expect("ACK")
            .into_iter()
            .enumerate()
            .map(|(index, byte)| {
                if (12..16).contains(&index) {
                    PORT.to_ne_bytes()[index - 12]
                } else {
                    byte
                }
            })
            .collect()
    }

    fn ack(request: &[u8], errno: i32) -> Vec<u8> {
        if errno == 0 {
            ack_with_shape(request, errno, NLM_F_CAPPED, false)
        } else {
            ack_with_shape(request, errno, 0, true)
        }
    }

    fn create_request(target_fd: i32) -> Vec<u8> {
        let payload = encode_create_payload(&specification(), target_fd).expect("create payload");
        encode_message(
            RTM_NEWLINK,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
            SEQUENCE,
            &payload,
        )
        .expect("create request")
    }

    fn link_frame(
        specification: &VethSpecification,
        parent: u32,
        peer: u32,
        peer_netnsid: i32,
    ) -> Vec<u8> {
        let mut link_info = Vec::new();
        push_string_attribute(&mut link_info, IFLA_INFO_KIND, "veth").expect("kind");
        let mut payload = interface_info(parent, FIXED_DOWN_VETH_FLAGS, 0);
        payload[2..4].copy_from_slice(&ARPHRD_ETHER.to_ne_bytes());
        push_string_attribute(&mut payload, IFLA_IFNAME, &specification.parent_name).expect("name");
        push_attribute(&mut payload, IFLA_MTU, &FIXED_VETH_MTU.to_ne_bytes()).expect("mtu");
        push_attribute(&mut payload, IFLA_LINK, &peer.to_ne_bytes()).expect("peer");
        push_attribute(&mut payload, IFLA_LINK_NETNSID, &peer_netnsid.to_ne_bytes())
            .expect("peer netnsid");
        push_attribute(
            &mut payload,
            IFLA_TXQLEN,
            &FIXED_VETH_TX_QUEUE_LENGTH.to_ne_bytes(),
        )
        .expect("queue");
        push_fixed_queue_attributes(&mut payload).expect("fixed queue counts");
        push_attribute(&mut payload, IFLA_LINKINFO, &link_info).expect("link info");
        let mut message = encode_message(RTM_NEWLINK, 0, SEQUENCE, &payload).expect("link frame");
        message[12..16].copy_from_slice(&PORT.to_ne_bytes());
        message
    }

    fn replace_frame_attribute(
        frame: &[u8],
        target_kind: u16,
        replacement_kind: u16,
        replacement_payload: &[u8],
    ) -> Vec<u8> {
        rebuild_link_frame(
            frame,
            target_kind,
            Some((replacement_kind, replacement_payload)),
        )
    }

    fn without_frame_attribute(frame: &[u8], target_kind: u16) -> Vec<u8> {
        rebuild_link_frame(frame, target_kind, None)
    }

    fn rebuild_link_frame(
        frame: &[u8],
        target_kind: u16,
        replacement: Option<(u16, &[u8])>,
    ) -> Vec<u8> {
        let mut payload = frame[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + IFINFO_LEN].to_vec();
        let attributes = parse_attributes(&frame[NLMSG_HEADER_LEN + IFINFO_LEN..])
            .expect("source link attributes");
        let mut replaced = false;
        for attribute in attributes {
            if attribute.kind == target_kind {
                assert!(!replaced, "source attribute must be unique");
                replaced = true;
                if let Some((kind, replacement_payload)) = replacement {
                    push_attribute(&mut payload, kind, replacement_payload)
                        .expect("replacement attribute");
                }
            } else {
                push_attribute(
                    &mut payload,
                    attribute.kind | attribute.flags,
                    attribute.payload,
                )
                .expect("retained attribute");
            }
        }
        assert!(replaced, "source attribute must exist");
        let mut rebuilt =
            encode_message(RTM_NEWLINK, 0, SEQUENCE, &payload).expect("rebuilt frame");
        rebuilt[12..16].copy_from_slice(&PORT.to_ne_bytes());
        rebuilt
    }

    fn set_frame_length(frame: &mut [u8]) {
        let length = u32::try_from(frame.len())
            .expect("frame length")
            .to_ne_bytes();
        frame[..4].copy_from_slice(&length);
    }

    fn nsid_frame(nsid: i32) -> Vec<u8> {
        let mut payload = vec![AF_UNSPEC, 0, 0, 0];
        push_attribute(&mut payload, NETNSA_NSID, &nsid.to_ne_bytes()).expect("nsid");
        let mut message = encode_message(RTM_NEWNSID, 0, SEQUENCE, &payload).expect("nsid frame");
        message[12..16].copy_from_slice(&PORT.to_ne_bytes());
        message
    }

    struct ReconciliationHarness {
        observations: VecDeque<Option<LinkObservation>>,
        delete_outcomes: VecDeque<bool>,
        lineage_is_valid: bool,
        observation_calls: usize,
        verified: Vec<LinkObservation>,
        deleted: Vec<LinkObservation>,
    }

    impl ReconciliationHarness {
        fn observe(&mut self) -> Result<Option<LinkObservation>, VethOperationError> {
            self.observation_calls += 1;
            self.observations
                .pop_front()
                .ok_or(VethOperationError::Unsafe(
                    "scripted reconciliation observation exhausted",
                ))
        }

        fn verify(&mut self, observed: LinkObservation) -> Result<(), VethOperationError> {
            self.verified.push(observed);
            if self.lineage_is_valid {
                Ok(())
            } else {
                Err(VethOperationError::Unsafe(
                    "scripted reconciliation lineage rejection",
                ))
            }
        }

        fn delete(&mut self, observed: LinkObservation) -> Result<(), VethOperationError> {
            self.deleted.push(observed);
            match self.delete_outcomes.pop_front() {
                Some(true) => Ok(()),
                Some(false) => Err(VethOperationError::Unsafe(
                    "scripted ambiguous delete outcome",
                )),
                None => Err(VethOperationError::Unsafe(
                    "scripted reconciliation delete outcome exhausted",
                )),
            }
        }
    }

    fn run_scripted_reconciliation(
        expected: Option<LinkObservation>,
        observations: impl IntoIterator<Item = Option<LinkObservation>>,
        delete_outcomes: impl IntoIterator<Item = bool>,
        lineage_is_valid: bool,
    ) -> (
        Result<(), VethOperationError>,
        Rc<RefCell<ReconciliationHarness>>,
    ) {
        let harness = Rc::new(RefCell::new(ReconciliationHarness {
            observations: observations.into_iter().collect(),
            delete_outcomes: delete_outcomes.into_iter().collect(),
            lineage_is_valid,
            observation_calls: 0,
            verified: Vec::new(),
            deleted: Vec::new(),
        }));
        let observer = Rc::clone(&harness);
        let verifier = Rc::clone(&harness);
        let deleter = Rc::clone(&harness);
        let result = reconcile_observed_state(
            expected,
            move || observer.borrow_mut().observe(),
            move |observed| verifier.borrow_mut().verify(observed),
            move |observed| deleter.borrow_mut().delete(observed),
        );
        (result, harness)
    }

    #[test]
    fn names_are_derived_only_from_run_and_fixed_endpoint() {
        assert_eq!(
            VethSpecification::new(&run_id(), FixedVethEndpoint::A)
                .expect("A")
                .parent_name,
            "vpa01234567"
        );
        assert_eq!(
            VethSpecification::new(&run_id(), FixedVethEndpoint::B)
                .expect("B")
                .parent_name,
            "vpb01234567"
        );
        assert_eq!(FIXED_VETH_PEER_NAME, "eth0");
    }

    #[test]
    fn atomic_create_encoding_contains_direct_peer_namespace() {
        let target_fd = 73;
        let request = create_request(target_fd);
        assert_eq!(read_u16(&request, 4).expect("type"), RTM_NEWLINK);
        assert_eq!(
            read_u16(&request, 6).expect("flags"),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        );
        let outer =
            parse_attributes(&request[NLMSG_HEADER_LEN + IFINFO_LEN..]).expect("outer attributes");
        assert_fixed_queue_attributes(&outer);
        let link_info = outer
            .iter()
            .find(|attribute| attribute.kind == IFLA_LINKINFO)
            .expect("link info");
        assert_eq!(link_info.flags, NLA_F_NESTED);
        let info = parse_attributes(link_info.payload).expect("info attributes");
        assert_eq!(
            parse_string(
                info.iter()
                    .find(|attribute| attribute.kind == IFLA_INFO_KIND)
                    .expect("kind")
                    .payload
            )
            .expect("kind string"),
            "veth"
        );
        let data = info
            .iter()
            .find(|attribute| attribute.kind == IFLA_INFO_DATA)
            .expect("info data");
        assert_eq!(data.flags, NLA_F_NESTED);
        let peer_container = parse_attributes(data.payload).expect("veth data");
        let peer = peer_container
            .iter()
            .find(|attribute| attribute.kind == VETH_INFO_PEER)
            .expect("peer");
        assert_eq!(peer.flags, NLA_F_NESTED);
        assert_eq!(&peer.payload[..IFINFO_LEN], interface_info(0, 0, 0));
        let peer_attributes = parse_attributes(&peer.payload[IFINFO_LEN..]).expect("peer attrs");
        assert_fixed_queue_attributes(&peer_attributes);
        assert_eq!(
            parse_string(
                peer_attributes
                    .iter()
                    .find(|attribute| attribute.kind == IFLA_IFNAME)
                    .expect("peer name")
                    .payload
            )
            .expect("peer name string"),
            FIXED_VETH_PEER_NAME
        );
        assert_eq!(
            read_i32(
                peer_attributes
                    .iter()
                    .find(|attribute| attribute.kind == IFLA_NET_NS_FD)
                    .expect("target fd")
                    .payload,
                0
            )
            .expect("target fd value"),
            target_fd
        );
    }

    fn assert_fixed_queue_attributes(attributes: &[Attribute<'_>]) {
        for kind in [IFLA_NUM_TX_QUEUES, IFLA_NUM_RX_QUEUES] {
            let matching = attributes
                .iter()
                .filter(|attribute| attribute.kind == kind)
                .collect::<Vec<_>>();
            assert_eq!(matching.len(), 1, "queue attribute {kind} must be unique");
            assert_eq!(matching[0].flags, 0);
            assert_eq!(
                read_exact_u32(matching[0].payload).expect("queue count"),
                FIXED_VETH_QUEUE_COUNT
            );
        }
    }

    #[test]
    fn delete_encoding_is_ifindex_only_and_acknowledged() {
        let payload = encode_delete_payload(19).expect("delete payload");
        assert_eq!(payload, interface_info(19, 0, 0));
        let request = encode_message(RTM_DELLINK, NLM_F_REQUEST | NLM_F_ACK, SEQUENCE, &payload)
            .expect("delete request");
        assert_eq!(read_u16(&request, 4).expect("type"), RTM_DELLINK);
        assert_eq!(
            read_u16(&request, 6).expect("flags"),
            NLM_F_REQUEST | NLM_F_ACK
        );
        assert!(encode_delete_payload(0).is_err());
    }

    #[test]
    fn preexisting_fixed_name_is_rejected_before_mutation() {
        require_fixed_name_absent(Ok(None)).expect("absent fixed name");
        assert!(
            require_fixed_name_absent(Ok(Some(LinkObservation {
                parent_ifindex: 17,
                peer_ifindex: 4,
                peer_netnsid: 3,
            })))
            .is_err()
        );
        assert!(
            require_fixed_name_absent(Err(VethOperationError::Unsafe(
                "ambiguous preflight observation",
            )))
            .is_err()
        );
    }

    #[test]
    fn exact_success_and_negative_ack_are_classified() {
        let request = create_request(73);
        assert_eq!(
            parse_ack(&reply(ack(&request, 0)), PORT, &request).expect("success ACK"),
            Ack::Success
        );
        assert_eq!(
            parse_ack(&reply(ack(&request, -libc::EEXIST)), PORT, &request).expect("negative ACK"),
            Ack::Rejected(libc::EEXIST)
        );
    }

    #[test]
    fn ack_payload_shape_is_bound_to_capped_status() {
        let request = create_request(73);
        assert!(
            parse_ack(
                &reply(ack_with_shape(&request, 0, 0, false)),
                PORT,
                &request,
            )
            .is_err()
        );
        assert!(
            parse_ack(
                &reply(ack_with_shape(&request, 0, NLM_F_CAPPED, true)),
                PORT,
                &request,
            )
            .is_err()
        );
        assert!(
            parse_ack(
                &reply(ack_with_shape(&request, -libc::EEXIST, NLM_F_CAPPED, false,)),
                PORT,
                &request,
            )
            .is_err()
        );
        assert!(
            parse_ack(
                &reply(ack_with_shape(
                    &request,
                    -libc::EEXIST,
                    NLM_F_ACK_TLVS,
                    true,
                )),
                PORT,
                &request,
            )
            .is_err()
        );
    }

    #[test]
    fn ack_ambiguity_is_rejected_adversarially() {
        let request = create_request(73);
        let canonical = ack(&request, 0);
        for mutate in [
            |bytes: &mut Vec<u8>| bytes[8] ^= 1,
            |bytes: &mut Vec<u8>| bytes[12] ^= 1,
            |bytes: &mut Vec<u8>| bytes[16] = 1,
            |bytes: &mut Vec<u8>| bytes[24] ^= 1,
            |bytes: &mut Vec<u8>| bytes.extend_from_slice(&[0; NLMSG_HEADER_LEN]),
        ] {
            let mut malformed = canonical.clone();
            mutate(&mut malformed);
            assert!(parse_ack(&reply(malformed), PORT, &request).is_err());
        }
        let mut wrong_sender = reply(canonical.clone());
        wrong_sender.sender = SocketAddr::new(9, 0);
        assert!(parse_ack(&wrong_sender, PORT, &request).is_err());
        let mut positive = canonical;
        positive[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + 4].copy_from_slice(&libc::EIO.to_ne_bytes());
        assert!(parse_ack(&reply(positive), PORT, &request).is_err());
    }

    #[test]
    fn exact_link_readback_binds_both_ifindices_and_fixed_attributes() {
        let specification = specification();
        let frame = link_frame(&specification, 17, 4, 3);
        assert_eq!(
            parse_fixed_link(&frame, PORT, SEQUENCE, &specification).expect("link proof"),
            LinkObservation {
                parent_ifindex: 17,
                peer_ifindex: 4,
                peer_netnsid: 3,
            }
        );
        for mutate in [
            |bytes: &mut Vec<u8>| bytes[NLMSG_HEADER_LEN + 2] = 0,
            |bytes: &mut Vec<u8>| bytes[NLMSG_HEADER_LEN + 8] |= 1,
            |bytes: &mut Vec<u8>| bytes[NLMSG_HEADER_LEN + IFINFO_LEN + 4] ^= 1,
        ] {
            let mut malformed = frame.clone();
            mutate(&mut malformed);
            assert!(parse_fixed_link(&malformed, PORT, SEQUENCE, &specification).is_err());
        }

        for kind in [IFLA_NUM_TX_QUEUES, IFLA_NUM_RX_QUEUES] {
            let wrong_count = replace_frame_attribute(&frame, kind, kind, &2_u32.to_ne_bytes());
            assert!(parse_fixed_link(&wrong_count, PORT, SEQUENCE, &specification).is_err());

            let wrong_flags = replace_frame_attribute(
                &frame,
                kind,
                kind | NLA_F_NET_BYTEORDER,
                &FIXED_VETH_QUEUE_COUNT.to_ne_bytes(),
            );
            assert!(parse_fixed_link(&wrong_flags, PORT, SEQUENCE, &specification).is_err());

            let missing = without_frame_attribute(&frame, kind);
            assert!(parse_fixed_link(&missing, PORT, SEQUENCE, &specification).is_err());

            let mut duplicate = frame.clone();
            let mut extra = Vec::new();
            push_attribute(&mut extra, kind, &FIXED_VETH_QUEUE_COUNT.to_ne_bytes())
                .expect("duplicate queue attribute");
            duplicate.extend_from_slice(&extra);
            set_frame_length(&mut duplicate);
            assert!(parse_fixed_link(&duplicate, PORT, SEQUENCE, &specification).is_err());
        }
    }

    #[test]
    fn attribute_parser_rejects_truncation_duplicate_and_nonzero_padding() {
        let mut malformed = vec![3, 0, 4, 0];
        assert!(parse_attributes(&malformed).is_err());
        malformed = vec![5, 0, 3, 0, b'x', 1, 0, 0];
        assert!(parse_attributes(&malformed).is_err());

        let specification = specification();
        let mut frame = link_frame(&specification, 17, 4, 3);
        let mut duplicate = Vec::new();
        push_string_attribute(&mut duplicate, IFLA_IFNAME, &specification.parent_name)
            .expect("duplicate name");
        frame.extend_from_slice(&duplicate);
        let length = u32::try_from(frame.len()).expect("frame length");
        frame[..4].copy_from_slice(&length.to_ne_bytes());
        assert!(parse_fixed_link(&frame, PORT, SEQUENCE, &specification).is_err());
    }

    #[test]
    fn target_nsid_query_encoding_and_reply_are_exact() {
        let payload = encode_get_nsid_payload(73).expect("GETNSID payload");
        assert_eq!(&payload[..NSID_HEADER_LEN], &[AF_UNSPEC, 0, 0, 0]);
        let attributes = parse_attributes(&payload[NSID_HEADER_LEN..]).expect("GETNSID attrs");
        assert_eq!(attributes.len(), 1);
        assert_eq!(attributes[0].kind, NETNSA_FD);
        assert_eq!(attributes[0].flags, 0);
        assert_eq!(read_exact_u32(attributes[0].payload).expect("fd"), 73);
        assert_eq!(
            parse_nsid_reply(&reply(nsid_frame(3)), PORT, SEQUENCE).expect("nsid reply"),
            3
        );
        assert!(parse_nsid_reply(&reply(nsid_frame(-1)), PORT, SEQUENCE).is_err());
        assert!(encode_get_nsid_payload(-1).is_err());
    }

    #[test]
    fn target_nsid_disambiguates_equal_ifindices() {
        let observation = LinkObservation {
            parent_ifindex: 17,
            peer_ifindex: 17,
            peer_netnsid: 3,
        };
        require_matching_target_nsid(observation, 3).expect("exact target lineage");
        assert!(require_matching_target_nsid(observation, 4).is_err());
        assert!(require_matching_target_nsid(observation, -1).is_err());
    }

    #[test]
    fn current_network_namespace_is_not_an_authorized_peer_target() {
        let current = open(
            CURRENT_NETWORK_NAMESPACE,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .expect("current network namespace");
        assert!(validate_target_namespace(&current).is_err());
    }

    #[test]
    fn lost_create_ack_adopts_one_lineage_verified_provisional_candidate() {
        let candidate = LinkObservation {
            parent_ifindex: 17,
            peer_ifindex: 4,
            peer_netnsid: 3,
        };
        let (result, harness) = run_scripted_reconciliation(None, [Some(candidate)], [true], true);

        result.expect("lineage-bound provisional candidate is deleted");
        let harness = harness.borrow();
        assert_eq!(harness.observation_calls, 1);
        assert_eq!(harness.verified, [candidate]);
        assert_eq!(harness.deleted, [candidate]);
    }

    #[test]
    fn lost_create_ack_never_deletes_an_unverified_provisional_candidate() {
        let candidate = LinkObservation {
            parent_ifindex: 17,
            peer_ifindex: 4,
            peer_netnsid: 3,
        };
        let (result, harness) = run_scripted_reconciliation(None, [Some(candidate)], [true], false);

        assert!(matches!(
            result,
            Err(VethOperationError::Unsafe(
                "scripted reconciliation lineage rejection"
            ))
        ));
        let harness = harness.borrow();
        assert_eq!(harness.observation_calls, 1);
        assert_eq!(harness.verified, [candidate]);
        assert!(harness.deleted.is_empty());
    }

    #[test]
    fn ambiguous_delete_that_applied_is_reconciled_by_exact_absence() {
        let expected = LinkObservation {
            parent_ifindex: 17,
            peer_ifindex: 4,
            peer_netnsid: 3,
        };
        let (result, harness) =
            run_scripted_reconciliation(Some(expected), [Some(expected), None], [false], true);

        result.expect("lost delete ACK is reconciled by absence");
        let harness = harness.borrow();
        assert_eq!(harness.observation_calls, 2);
        assert_eq!(harness.verified, [expected]);
        assert_eq!(harness.deleted, [expected]);
    }

    #[test]
    fn ambiguous_provisional_delete_refuses_a_same_name_replacement() {
        let adopted = LinkObservation {
            parent_ifindex: 17,
            peer_ifindex: 4,
            peer_netnsid: 3,
        };
        let replacement = LinkObservation {
            parent_ifindex: 29,
            peer_ifindex: 8,
            peer_netnsid: 3,
        };
        let (result, harness) =
            run_scripted_reconciliation(None, [Some(adopted), Some(replacement)], [false], true);

        assert!(matches!(
            result,
            Err(VethOperationError::Unsafe(
                "cleanup encountered a different fixed-name veth"
            ))
        ));
        let harness = harness.borrow();
        assert_eq!(harness.observation_calls, 2);
        assert_eq!(harness.verified, [adopted]);
        assert_eq!(harness.deleted, [adopted]);
    }

    #[test]
    fn reconciliation_allows_only_two_delete_attempts_then_one_absence_check() {
        let expected = LinkObservation {
            parent_ifindex: 17,
            peer_ifindex: 4,
            peer_netnsid: 3,
        };
        let (result, harness) = run_scripted_reconciliation(
            Some(expected),
            [Some(expected), Some(expected), Some(expected), None],
            [false, false, true],
            true,
        );

        assert!(matches!(
            result,
            Err(VethOperationError::Unsafe(
                "fixed veth cleanup could not prove absence"
            ))
        ));
        let harness = harness.borrow();
        assert_eq!(
            harness.observation_calls,
            MAX_RECONCILIATION_DELETE_ATTEMPTS + 1
        );
        assert_eq!(
            harness.deleted,
            vec![expected; MAX_RECONCILIATION_DELETE_ATTEMPTS]
        );
        assert_eq!(harness.delete_outcomes.len(), 1);
        assert_eq!(harness.observations.len(), 1);
    }

    #[test]
    fn one_bounded_second_delete_attempt_may_succeed_without_a_third_observation() {
        let expected = LinkObservation {
            parent_ifindex: 17,
            peer_ifindex: 4,
            peer_netnsid: 3,
        };
        let (result, harness) = run_scripted_reconciliation(
            Some(expected),
            [Some(expected), Some(expected), None],
            [false, true, false],
            true,
        );

        result.expect("one retry deletes the exact retained candidate");
        let harness = harness.borrow();
        assert_eq!(harness.observation_calls, 2);
        assert_eq!(
            harness.deleted,
            vec![expected; MAX_RECONCILIATION_DELETE_ATTEMPTS]
        );
        assert_eq!(harness.delete_outcomes.len(), 1);
        assert_eq!(harness.observations.len(), 1);
    }

    #[test]
    fn second_ambiguous_delete_may_finish_only_with_final_exact_absence() {
        let expected = LinkObservation {
            parent_ifindex: 17,
            peer_ifindex: 4,
            peer_netnsid: 3,
        };
        let (result, harness) = run_scripted_reconciliation(
            Some(expected),
            [Some(expected), Some(expected), None],
            [false, false],
            true,
        );

        result.expect("final observation proves the second ambiguous delete applied");
        let harness = harness.borrow();
        assert_eq!(
            harness.deleted,
            vec![expected; MAX_RECONCILIATION_DELETE_ATTEMPTS]
        );
        assert_eq!(harness.observation_calls, 3);
    }
}
