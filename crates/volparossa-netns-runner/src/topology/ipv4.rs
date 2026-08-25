//! Fixed IPv4 address mutation and affine rollback for disposable veth links.
//!
//! This module exposes only the four addresses from the fixed lifecycle
//! contract. The caller supplies an existing [`FixedVethPair`] and a retained
//! descriptor for the network namespace that is current on this thread. The
//! interface index and label are derived from the pair; callers cannot provide
//! an address, prefix, interface index, or interface name.
//!
//! Every mutation is journalled before its ACK is received. A lost create ACK
//! adopts only an exact, freshly read-back address; every other ambiguous state
//! is rolled back or aborts fail closed. Cleanup performs at most two delete
//! attempts and one final absence observation. Links remain down throughout.
//! Adding an IPv4 address causes Linux to create its namespace-local local-table
//! route. The enclosing network-delta proof admits and exactly proves that one
//! kernel-owned route. This module never sends an explicit route or link-state
//! mutation.
//!
//! The implementation relies on the runner's fixed single-PID-1-task scope. An
//! indistinguishable same-address replacement by a concurrent same-UID actor
//! cannot be assigned cryptographic lineage by RTNETLINK and is outside that
//! trusted-launcher scope.

use std::{
    io,
    marker::PhantomData,
    os::fd::{AsFd, OwnedFd},
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
use volparossa_linux_uapi::namespace_type;

use super::veth::{FixedVethEndpoint, FixedVethPair};

const IPV4_OPERATION_TIMEOUT: Duration = Duration::from_secs(2);
const CURRENT_NETWORK_NAMESPACE: &str = "/proc/thread-self/ns/net";
const NSFS_MAGIC: FsWord = 0x6e73_6673;

const MAX_NETLINK_DATAGRAM_BYTES: usize = 64 * 1024;
const MAX_NETLINK_TOTAL_BYTES: usize = 256 * 1024;
const MAX_NETLINK_DATAGRAMS: usize = 32;
const MAX_NETLINK_FRAMES: usize = 128;
const MAX_ADDRESS_RECORDS: usize = 64;
const MAX_ATTRIBUTES: usize = 128;
const MAX_REQUEST_BYTES: usize = 256;
const MAX_RECONCILIATION_DELETE_ATTEMPTS: usize = 2;

const NLMSG_HEADER_LEN: usize = 16;
const NLMSG_ERROR_CODE_LEN: usize = 4;
const IFINFO_LEN: usize = 16;
const IFADDR_LEN: usize = 8;
const ATTRIBUTE_HEADER_LEN: usize = 4;

const NLM_F_REQUEST: u16 = 0x0001;
const NLM_F_MULTI: u16 = 0x0002;
const NLM_F_ACK: u16 = 0x0004;
const NLM_F_ROOT: u16 = 0x0100;
const NLM_F_CAPPED: u16 = 0x0100;
const NLM_F_MATCH: u16 = 0x0200;
const NLM_F_ACK_TLVS: u16 = 0x0200;
const NLM_F_EXCL: u16 = 0x0200;
const NLM_F_CREATE: u16 = 0x0400;
const NLM_F_DUMP: u16 = NLM_F_ROOT | NLM_F_MATCH;

const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
const NLMSG_OVERRUN: u16 = 4;
const RTM_NEWLINK: u16 = 16;
const RTM_GETLINK: u16 = 18;
const RTM_NEWADDR: u16 = 20;
const RTM_DELADDR: u16 = 21;
const RTM_GETADDR: u16 = 22;

const NLA_F_NESTED: u16 = 1 << 15;
const NLA_F_NET_BYTEORDER: u16 = 1 << 14;
const NLA_TYPE_MASK: u16 = !(NLA_F_NESTED | NLA_F_NET_BYTEORDER);

const IFLA_IFNAME: u16 = 3;
const IFA_ADDRESS: u16 = 1;
const IFA_LOCAL: u16 = 2;
const IFA_LABEL: u16 = 3;
const IFA_BROADCAST: u16 = 4;
const IFA_CACHEINFO: u16 = 6;
const IFA_FLAGS: u16 = 8;

const AF_UNSPEC: u8 = 0;
const AF_INET: u8 = 2;
const ARPHRD_ETHER: u16 = 1;
const IFF_BROADCAST: u32 = 0x0002;
const IFF_MULTICAST: u32 = 0x1000;
const FIXED_DOWN_VETH_FLAGS: u32 = IFF_BROADCAST | IFF_MULTICAST;
const RT_SCOPE_UNIVERSE: u8 = 0;
const IFA_F_PERMANENT_U8: u8 = 0x80;
const IFA_F_PERMANENT: u32 = 0x80;
const FIXED_PREFIX_LENGTH: u8 = 30;
const INFINITE_ADDRESS_LIFETIME: u32 = u32::MAX;

/// One of the four fixed IPv4 addresses in the disposable topology contract.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum FixedIpv4Address {
    /// Parent side of pair A: `10.241.1.1/30`.
    ParentA,
    /// Endpoint side of pair A: `10.241.1.2/30`.
    EndpointA,
    /// Parent side of pair B: `10.241.2.1/30`.
    ParentB,
    /// Endpoint side of pair B: `10.241.2.2/30`.
    EndpointB,
}

impl FixedIpv4Address {
    /// Exact network-order address octets.
    pub(crate) const fn octets(self) -> [u8; 4] {
        match self {
            Self::ParentA => [10, 241, 1, 1],
            Self::EndpointA => [10, 241, 1, 2],
            Self::ParentB => [10, 241, 2, 1],
            Self::EndpointB => [10, 241, 2, 2],
        }
    }

    /// Exact prefix length shared by all fixed addresses.
    pub(crate) const fn prefix_length(self) -> u8 {
        let _ = self;
        FIXED_PREFIX_LENGTH
    }

    const fn endpoint(self) -> FixedVethEndpoint {
        match self {
            Self::ParentA | Self::EndpointA => FixedVethEndpoint::A,
            Self::ParentB | Self::EndpointB => FixedVethEndpoint::B,
        }
    }

    const fn side(self) -> AddressSide {
        match self {
            Self::ParentA | Self::ParentB => AddressSide::Parent,
            Self::EndpointA | Self::EndpointB => AddressSide::Endpoint,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddressSide {
    Parent,
    Endpoint,
}

/// Stable nsfs identity of the namespace in which an address was installed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) struct Ipv4NamespaceIdentity {
    device: u64,
    inode: u64,
}

impl Ipv4NamespaceIdentity {
    /// Namespace backing-device number.
    pub(crate) const fn device(self) -> u64 {
        self.device
    }

    /// Namespace inode number.
    pub(crate) const fn inode(self) -> u64 {
        self.inode
    }
}

/// Bounded RTNETLINK or current-namespace verification failure.
#[derive(Debug, Error)]
pub(crate) enum Ipv4OperationError {
    /// A descriptor, socket, send, receive, or wait operation failed.
    #[error("fixed IPv4 operation {operation} failed: {source}")]
    Io {
        /// Static operation label.
        operation: &'static str,
        /// Kernel or standard-library error.
        #[source]
        source: io::Error,
    },
    /// The kernel returned an exact negative ACK.
    #[error("kernel rejected fixed IPv4 operation {operation} with errno {errno}")]
    Kernel {
        /// Static operation label.
        operation: &'static str,
        /// Positive Linux errno.
        errno: i32,
    },
    /// A response or retained object contradicted the fixed protocol.
    #[error("fixed IPv4 proof was unsafe: {0}")]
    Unsafe(&'static str),
    /// A response or encoding exceeded a fixed resource limit.
    #[error("fixed IPv4 operation exceeded its resource bound")]
    Limit,
}

impl Ipv4OperationError {
    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }

    fn errno(operation: &'static str, errno: i32) -> Self {
        Self::Kernel { operation, errno }
    }
}

/// Failure to install one fixed IPv4 address.
#[derive(Debug, Error)]
pub(crate) enum Ipv4AddError {
    /// Failure before a request could have reached the kernel mutation path.
    #[error("fixed IPv4 installation failed before mutation")]
    BeforeMutation(#[source] Ipv4OperationError),
    /// Exact negative create ACK; the exclusive request did not add an address.
    #[error("kernel rejected exclusive fixed IPv4 installation with errno {0}")]
    Rejected(i32),
    /// Send or ACK ambiguity after which exact absence was re-established.
    #[error("fixed IPv4 installation may have executed; rollback restored exact absence")]
    PossiblyApplied(#[source] Ipv4OperationError),
    /// Installation was acknowledged but readback failed; rollback restored absence.
    #[error("fixed IPv4 installation was rolled back after its readback proof failed")]
    Readback(#[source] Ipv4OperationError),
}

/// Failure to freshly verify one retained fixed IPv4 address.
#[derive(Debug, Error)]
#[error("retained fixed IPv4 address verification failed")]
pub(crate) struct Ipv4VerifyError(#[source] Ipv4OperationError);

/// A rollback anomaly after fresh reconciliation nevertheless proved absence.
#[derive(Debug, Error)]
#[error("fixed IPv4 rollback required reconciliation; exact absence was restored")]
pub(crate) struct Ipv4RollbackError(#[source] Ipv4OperationError);

#[derive(Clone, Debug, Eq, PartialEq)]
struct InterfaceBinding {
    ifindex: u32,
    name: String,
}

struct RetainedCurrentNamespace {
    descriptor: OwnedFd,
    identity: Ipv4NamespaceIdentity,
}

impl RetainedCurrentNamespace {
    fn capture<Fd: AsFd>(supplied: &Fd) -> Result<Self, Ipv4OperationError> {
        validate_namespace_descriptor(supplied)?;
        let supplied_identity = object_identity(supplied)?;
        let current = open_current_network_namespace()?;
        if object_identity(&current)? != supplied_identity {
            return Err(Ipv4OperationError::Unsafe(
                "supplied namespace descriptor is not the current thread network namespace",
            ));
        }
        let descriptor = supplied
            .as_fd()
            .try_clone_to_owned()
            .map_err(|source| Ipv4OperationError::io("retain current network namespace", source))?;
        validate_namespace_descriptor(&descriptor)?;
        if object_identity(&descriptor)? != supplied_identity {
            return Err(Ipv4OperationError::Unsafe(
                "current namespace descriptor changed during cloning",
            ));
        }
        Ok(Self {
            descriptor,
            identity: supplied_identity,
        })
    }

    fn verify_current(&self) -> Result<(), Ipv4OperationError> {
        validate_namespace_descriptor(&self.descriptor)?;
        if object_identity(&self.descriptor)? != self.identity
            || object_identity(&open_current_network_namespace()?)? != self.identity
        {
            return Err(Ipv4OperationError::Unsafe(
                "retained address namespace is no longer current on this thread",
            ));
        }
        Ok(())
    }
}

struct AddressJournal<'pair> {
    specification: FixedIpv4Address,
    namespace: RetainedCurrentNamespace,
    interface: InterfaceBinding,
    pair: &'pair FixedVethPair,
}

impl AddressJournal<'_> {
    fn verify_context(&self) -> Result<(), Ipv4OperationError> {
        self.namespace.verify_current()?;
        verify_pair_binding(
            self.specification,
            self.pair,
            &self.namespace,
            &self.interface,
        )?;
        verify_link_is_exactly_down(&self.interface)
    }
}

/// Affine ownership and rollback authority for one exact fixed IPv4 address.
///
/// The token borrows its veth owner, preventing the pair from being consumed
/// before the address is rolled back. It is neither cloneable nor transferable
/// to another thread. Dropping an armed token performs bounded exact cleanup
/// and aborts if absence cannot be established.
#[must_use = "dropping an armed fixed IPv4 address triggers fail-closed rollback"]
pub(crate) struct FixedIpv4AddressOwner<'pair> {
    journal: Option<AddressJournal<'pair>>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl FixedIpv4AddressOwner<'_> {
    /// Fixed address represented by this owner.
    pub(crate) fn address(&self) -> FixedIpv4Address {
        self.journal().specification
    }

    /// Exact interface index pinned at installation time.
    pub(crate) fn ifindex(&self) -> u32 {
        self.journal().interface.ifindex
    }

    /// Exact interface label pinned at installation time.
    pub(crate) fn interface_name(&self) -> &str {
        &self.journal().interface.name
    }

    /// Exact namespace identity pinned at installation time.
    pub(crate) fn namespace_identity(&self) -> Ipv4NamespaceIdentity {
        self.journal().namespace.identity
    }

    /// Reopen RTNETLINK and prove the exact address, down-link, and namespace binding.
    pub(crate) fn verify(&self) -> Result<(), Ipv4VerifyError> {
        require_exact_presence(self.journal()).map_err(Ipv4VerifyError)
    }

    /// Delete the freshly reverified address and prove exact absence.
    ///
    /// If the first attempt is ambiguous, at most two fresh delete attempts and
    /// one final absence observation are used. An error is returned only when
    /// cleanup was nevertheless proved; inability to prove cleanup aborts.
    pub(crate) fn rollback(mut self) -> Result<(), Ipv4RollbackError> {
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
                Err(Ipv4RollbackError(source))
            }
        }
    }

    fn journal(&self) -> &AddressJournal<'_> {
        self.journal
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }
}

impl Drop for FixedIpv4AddressOwner<'_> {
    fn drop(&mut self) {
        if let Some(journal) = self.journal.as_ref() {
            if reconcile_journal(journal).is_err() {
                std::process::abort();
            }
            self.journal = None;
        }
    }
}

struct ProvisionalAddressGuard<'pair> {
    journal: Option<AddressJournal<'pair>>,
    armed: bool,
}

impl<'pair> ProvisionalAddressGuard<'pair> {
    fn new(journal: AddressJournal<'pair>) -> Self {
        Self {
            journal: Some(journal),
            armed: false,
        }
    }

    fn journal(&self) -> &AddressJournal<'_> {
        self.journal
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }

    fn mark_possibly_applied(&mut self) {
        self.armed = true;
    }

    fn reject_after_exact_absence(mut self, errno: i32) -> Ipv4AddError {
        self.armed = false;
        if observe_presence(self.journal()).ok() != Some(AddressPresence::Absent) {
            std::process::abort();
        }
        Ipv4AddError::Rejected(errno)
    }

    fn recover_ambiguous(
        mut self,
        source: Ipv4OperationError,
    ) -> Result<FixedIpv4AddressOwner<'pair>, Ipv4AddError> {
        match observe_presence(self.journal()) {
            Ok(AddressPresence::Exact) => Ok(self.into_owner()),
            Ok(AddressPresence::Absent) => {
                self.armed = false;
                Err(Ipv4AddError::PossiblyApplied(source))
            }
            Err(_) => {
                if reconcile_journal(self.journal()).is_err() {
                    std::process::abort();
                }
                self.armed = false;
                Err(Ipv4AddError::PossiblyApplied(source))
            }
        }
    }

    fn fail_readback(mut self, source: Ipv4OperationError) -> Ipv4AddError {
        if reconcile_journal(self.journal()).is_err() {
            std::process::abort();
        }
        self.armed = false;
        Ipv4AddError::Readback(source)
    }

    fn into_owner(mut self) -> FixedIpv4AddressOwner<'pair> {
        if !self.armed {
            std::process::abort();
        }
        let journal = self.journal.take().unwrap_or_else(|| std::process::abort());
        self.armed = false;
        FixedIpv4AddressOwner {
            journal: Some(journal),
            _thread_bound: PhantomData,
        }
    }
}

impl Drop for ProvisionalAddressGuard<'_> {
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

/// Install and exactly prove one fixed IPv4 address on an existing down-veth.
///
/// `current_netns` must be a read-only, close-on-exec descriptor for the
/// network namespace currently active on this thread. The selected address
/// determines both the required pair and side; the interface index and label
/// are taken only from `pair`. No link-up or route request is sent.
pub(crate) fn add_fixed_ipv4_address<'pair, Fd: AsFd>(
    specification: FixedIpv4Address,
    pair: &'pair FixedVethPair,
    current_netns: &Fd,
) -> Result<FixedIpv4AddressOwner<'pair>, Ipv4AddError> {
    let namespace =
        RetainedCurrentNamespace::capture(current_netns).map_err(Ipv4AddError::BeforeMutation)?;
    let interface = derive_interface_binding(specification, pair, &namespace)
        .map_err(Ipv4AddError::BeforeMutation)?;
    let journal = AddressJournal {
        specification,
        namespace,
        interface,
        pair,
    };
    require_absence(&journal).map_err(Ipv4AddError::BeforeMutation)?;

    let payload = encode_address_payload(&journal).map_err(Ipv4AddError::BeforeMutation)?;
    let deadline = Deadline::after(IPV4_OPERATION_TIMEOUT).map_err(Ipv4AddError::BeforeMutation)?;
    let mut client = NetlinkClient::connect(deadline).map_err(Ipv4AddError::BeforeMutation)?;
    let sequence = client
        .next_sequence()
        .map_err(Ipv4AddError::BeforeMutation)?;
    let request = encode_message(
        RTM_NEWADDR,
        NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        sequence,
        &payload,
    )
    .map_err(Ipv4AddError::BeforeMutation)?;
    let mut guard = ProvisionalAddressGuard::new(journal);
    match send_bounded(&client.socket, &request, deadline) {
        Ok(()) => guard.mark_possibly_applied(),
        Err(SendFailure::NotSent(source)) => {
            return Err(Ipv4AddError::BeforeMutation(source));
        }
        Err(SendFailure::PossiblySent(source)) => {
            guard.mark_possibly_applied();
            return guard.recover_ambiguous(source);
        }
    }
    let reply = match receive_one(&client.socket, deadline) {
        Ok(reply) => reply,
        Err(source) => return guard.recover_ambiguous(source),
    };
    let acknowledgement = match parse_ack(&reply, client.local_port, &request) {
        Ok(acknowledgement) => acknowledgement,
        Err(source) => return guard.recover_ambiguous(source),
    };
    drop(client);
    match acknowledgement {
        Ack::Rejected(errno) => Err(guard.reject_after_exact_absence(errno)),
        Ack::Success => match observe_presence(guard.journal()) {
            Ok(AddressPresence::Exact) => Ok(guard.into_owner()),
            Ok(AddressPresence::Absent) => Err(guard.fail_readback(Ipv4OperationError::Unsafe(
                "ACKed fixed IPv4 address is absent from exact readback",
            ))),
            Err(source) => Err(guard.fail_readback(source)),
        },
    }
}

fn derive_interface_binding(
    specification: FixedIpv4Address,
    pair: &FixedVethPair,
    namespace: &RetainedCurrentNamespace,
) -> Result<InterfaceBinding, Ipv4OperationError> {
    if pair.endpoint() != specification.endpoint() {
        return Err(Ipv4OperationError::Unsafe(
            "fixed address does not belong to the supplied veth pair",
        ));
    }
    let binding = match specification.side() {
        AddressSide::Parent => {
            pair.verify()
                .map_err(|_| Ipv4OperationError::Unsafe("fixed parent veth verification failed"))?;
            let target = pair.target_namespace_identity();
            if target.device() == namespace.identity.device
                && target.inode() == namespace.identity.inode
            {
                return Err(Ipv4OperationError::Unsafe(
                    "parent address is being installed in the endpoint namespace",
                ));
            }
            InterfaceBinding {
                ifindex: pair.parent_ifindex(),
                name: pair.parent_name().to_owned(),
            }
        }
        AddressSide::Endpoint => {
            let target = pair.target_namespace_identity();
            if target.device() != namespace.identity.device
                || target.inode() != namespace.identity.inode
            {
                return Err(Ipv4OperationError::Unsafe(
                    "endpoint address namespace does not match the veth target",
                ));
            }
            InterfaceBinding {
                ifindex: pair.peer_ifindex(),
                name: pair.peer_name().to_owned(),
            }
        }
    };
    validate_interface_binding(&binding)?;
    verify_link_is_exactly_down(&binding)?;
    Ok(binding)
}

fn verify_pair_binding(
    specification: FixedIpv4Address,
    pair: &FixedVethPair,
    namespace: &RetainedCurrentNamespace,
    expected: &InterfaceBinding,
) -> Result<(), Ipv4OperationError> {
    if pair.endpoint() != specification.endpoint() {
        return Err(Ipv4OperationError::Unsafe(
            "retained address no longer belongs to its veth pair",
        ));
    }
    let observed = match specification.side() {
        AddressSide::Parent => {
            pair.verify().map_err(|_| {
                Ipv4OperationError::Unsafe("retained parent veth verification failed")
            })?;
            InterfaceBinding {
                ifindex: pair.parent_ifindex(),
                name: pair.parent_name().to_owned(),
            }
        }
        AddressSide::Endpoint => {
            let target = pair.target_namespace_identity();
            if target.device() != namespace.identity.device
                || target.inode() != namespace.identity.inode
            {
                return Err(Ipv4OperationError::Unsafe(
                    "retained endpoint namespace no longer matches the veth target",
                ));
            }
            InterfaceBinding {
                ifindex: pair.peer_ifindex(),
                name: pair.peer_name().to_owned(),
            }
        }
    };
    if &observed != expected {
        return Err(Ipv4OperationError::Unsafe(
            "retained veth interface binding changed",
        ));
    }
    Ok(())
}

fn validate_interface_binding(binding: &InterfaceBinding) -> Result<(), Ipv4OperationError> {
    if binding.ifindex == 0
        || binding.ifindex > i32::MAX as u32
        || binding.name.is_empty()
        || binding.name.len() >= libc::IFNAMSIZ
        || !binding.name.is_ascii()
        || binding.name.as_bytes().contains(&0)
    {
        return Err(Ipv4OperationError::Unsafe(
            "fixed IPv4 interface binding is invalid",
        ));
    }
    Ok(())
}

fn validate_namespace_descriptor<Fd: AsFd>(descriptor: &Fd) -> Result<(), Ipv4OperationError> {
    let descriptor_flags = FdFlag::from_bits_truncate(
        fcntl(descriptor, FcntlArg::F_GETFD)
            .map_err(|source| errno_io("read namespace descriptor flags", source))?,
    );
    let status_flags = OFlag::from_bits_truncate(
        fcntl(descriptor, FcntlArg::F_GETFL)
            .map_err(|source| errno_io("read namespace status flags", source))?,
    );
    if !descriptor_flags.contains(FdFlag::FD_CLOEXEC)
        || status_flags & OFlag::O_ACCMODE != OFlag::O_RDONLY
    {
        return Err(Ipv4OperationError::Unsafe(
            "network namespace descriptor is not read-only and close-on-exec",
        ));
    }
    if fstatfs(descriptor)
        .map_err(|source| rustix_io("identify namespace filesystem", source))?
        .f_type
        != NSFS_MAGIC
        || namespace_type(descriptor)
            .map_err(|source| Ipv4OperationError::io("identify network namespace", source))?
            != libc::CLONE_NEWNET
    {
        return Err(Ipv4OperationError::Unsafe(
            "descriptor is not a network nsfs object",
        ));
    }
    Ok(())
}

fn open_current_network_namespace() -> Result<OwnedFd, Ipv4OperationError> {
    let descriptor = open(
        CURRENT_NETWORK_NAMESPACE,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
        Mode::empty(),
    )
    .map_err(|source| rustix_io("open current network namespace", source))?;
    validate_namespace_descriptor(&descriptor)?;
    Ok(descriptor)
}

fn object_identity<Fd: AsFd>(descriptor: &Fd) -> Result<Ipv4NamespaceIdentity, Ipv4OperationError> {
    let metadata =
        fstat(descriptor).map_err(|source| rustix_io("measure namespace descriptor", source))?;
    if metadata.st_dev == 0 || metadata.st_ino == 0 {
        return Err(Ipv4OperationError::Unsafe(
            "namespace descriptor identity is zero",
        ));
    }
    Ok(Ipv4NamespaceIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

fn errno_io(operation: &'static str, source: nix::errno::Errno) -> Ipv4OperationError {
    Ipv4OperationError::io(operation, io::Error::from_raw_os_error(source as i32))
}

fn rustix_io(operation: &'static str, source: rustix::io::Errno) -> Ipv4OperationError {
    Ipv4OperationError::io(
        operation,
        io::Error::from_raw_os_error(source.raw_os_error()),
    )
}

#[derive(Clone, Copy)]
struct Deadline(Instant);

impl Deadline {
    fn after(duration: Duration) -> Result<Self, Ipv4OperationError> {
        Instant::now()
            .checked_add(duration)
            .map(Self)
            .ok_or(Ipv4OperationError::Limit)
    }

    fn poll_timeout(self) -> Result<PollTimeout, Ipv4OperationError> {
        let remaining = self
            .0
            .checked_duration_since(Instant::now())
            .ok_or_else(timeout_error)?;
        let millis = remaining.as_millis();
        let rounded = if remaining.subsec_nanos() % 1_000_000 == 0 {
            millis
        } else {
            millis.checked_add(1).ok_or(Ipv4OperationError::Limit)?
        };
        PollTimeout::try_from(rounded).map_err(|_| Ipv4OperationError::Limit)
    }

    fn ensure_unexpired(self) -> Result<(), Ipv4OperationError> {
        if Instant::now() < self.0 {
            Ok(())
        } else {
            Err(timeout_error())
        }
    }
}

fn timeout_error() -> Ipv4OperationError {
    Ipv4OperationError::io(
        "wait for RTNETLINK response",
        io::Error::new(io::ErrorKind::TimedOut, "fixed IPv4 deadline expired"),
    )
}

struct NetlinkClient {
    socket: Socket,
    local_port: u32,
    sequence: u32,
}

impl NetlinkClient {
    fn connect(deadline: Deadline) -> Result<Self, Ipv4OperationError> {
        deadline.ensure_unexpired()?;
        let mut socket = Socket::new(NETLINK_ROUTE)
            .map_err(|source| Ipv4OperationError::io("open RTNETLINK socket", source))?;
        socket
            .set_netlink_get_strict_chk(true)
            .map_err(|source| Ipv4OperationError::io("enable strict RTNETLINK checking", source))?;
        socket
            .set_non_blocking(true)
            .map_err(|source| Ipv4OperationError::io("harden RTNETLINK socket", source))?;
        let address = socket
            .bind_auto()
            .map_err(|source| Ipv4OperationError::io("bind RTNETLINK socket", source))?;
        if address.port_number() == 0 || address.multicast_groups() != 0 {
            return Err(Ipv4OperationError::Unsafe(
                "RTNETLINK socket binding is not exact",
            ));
        }
        socket
            .connect(&SocketAddr::new(0, 0))
            .map_err(|source| Ipv4OperationError::io("connect RTNETLINK socket", source))?;
        deadline.ensure_unexpired()?;
        Ok(Self {
            socket,
            local_port: address.port_number(),
            sequence: 1,
        })
    }

    fn next_sequence(&mut self) -> Result<u32, Ipv4OperationError> {
        let current = self.sequence;
        self.sequence = self
            .sequence
            .checked_add(1)
            .ok_or(Ipv4OperationError::Limit)?;
        if current == 0 {
            Err(Ipv4OperationError::Unsafe("RTNETLINK sequence is zero"))
        } else {
            Ok(current)
        }
    }
}

enum SendFailure {
    NotSent(Ipv4OperationError),
    PossiblySent(Ipv4OperationError),
}

fn send_bounded(socket: &Socket, request: &[u8], deadline: Deadline) -> Result<(), SendFailure> {
    loop {
        deadline.ensure_unexpired().map_err(SendFailure::NotSent)?;
        match socket.send(request, 0) {
            Ok(written) if written == request.len() => return Ok(()),
            Ok(_) => {
                return Err(SendFailure::PossiblySent(Ipv4OperationError::io(
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
                return Err(SendFailure::NotSent(Ipv4OperationError::io(
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

fn receive_one(socket: &Socket, deadline: Deadline) -> Result<NetlinkReply, Ipv4OperationError> {
    let mut budget = ReceiveBudget::single();
    receive_bounded(socket, deadline, &mut budget)
}

fn receive_bounded(
    socket: &Socket,
    deadline: Deadline,
    budget: &mut ReceiveBudget,
) -> Result<NetlinkReply, Ipv4OperationError> {
    loop {
        wait_for_socket(socket, PollFlags::POLLIN, deadline)?;
        let mut probe = Vec::new();
        let (length, peek_sender) =
            match socket.recv_from(&mut probe, libc::MSG_PEEK | libc::MSG_TRUNC) {
                Ok(value) => value,
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
                Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
                Err(error) => {
                    return Err(Ipv4OperationError::io("measure RTNETLINK response", error));
                }
            };
        if peek_sender != SocketAddr::new(0, 0) {
            return Err(Ipv4OperationError::Unsafe(
                "RTNETLINK response sender is not the kernel",
            ));
        }
        budget.can_receive(length)?;
        deadline.ensure_unexpired()?;
        let mut bytes = Vec::with_capacity(length);
        let (received, sender) = match socket.recv_from(&mut bytes, 0) {
            Ok(value) => value,
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => continue,
            Err(error) if error.kind() == io::ErrorKind::Interrupted => continue,
            Err(error) => {
                return Err(Ipv4OperationError::io("receive RTNETLINK response", error));
            }
        };
        deadline.ensure_unexpired()?;
        if received != length || bytes.len() != length || sender != peek_sender {
            return Err(Ipv4OperationError::Unsafe(
                "RTNETLINK response changed during bounded receive",
            ));
        }
        budget.record_datagram(length)?;
        return Ok(NetlinkReply { sender, bytes });
    }
}

fn wait_for_socket(
    socket: &Socket,
    expected: PollFlags,
    deadline: Deadline,
) -> Result<(), Ipv4OperationError> {
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
                    return Err(Ipv4OperationError::Unsafe(
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

struct ReceiveBudget {
    bytes: usize,
    datagrams: usize,
    frames: usize,
    max_bytes: usize,
    max_datagrams: usize,
    max_frames: usize,
}

impl ReceiveBudget {
    const fn single() -> Self {
        Self {
            bytes: 0,
            datagrams: 0,
            frames: 0,
            max_bytes: MAX_NETLINK_DATAGRAM_BYTES,
            max_datagrams: 1,
            max_frames: 1,
        }
    }

    const fn dump() -> Self {
        Self {
            bytes: 0,
            datagrams: 0,
            frames: 0,
            max_bytes: MAX_NETLINK_TOTAL_BYTES,
            max_datagrams: MAX_NETLINK_DATAGRAMS,
            max_frames: MAX_NETLINK_FRAMES,
        }
    }

    fn can_receive(&self, length: usize) -> Result<(), Ipv4OperationError> {
        if !(NLMSG_HEADER_LEN..=MAX_NETLINK_DATAGRAM_BYTES).contains(&length)
            || self
                .bytes
                .checked_add(length)
                .is_none_or(|total| total > self.max_bytes)
        {
            return Err(Ipv4OperationError::Limit);
        }
        Ok(())
    }

    fn record_datagram(&mut self, length: usize) -> Result<(), Ipv4OperationError> {
        self.can_receive(length)?;
        self.bytes = self
            .bytes
            .checked_add(length)
            .ok_or(Ipv4OperationError::Limit)?;
        self.datagrams = self
            .datagrams
            .checked_add(1)
            .ok_or(Ipv4OperationError::Limit)?;
        if self.datagrams > self.max_datagrams {
            return Err(Ipv4OperationError::Limit);
        }
        Ok(())
    }

    fn record_frame(&mut self) -> Result<(), Ipv4OperationError> {
        self.frames = self
            .frames
            .checked_add(1)
            .ok_or(Ipv4OperationError::Limit)?;
        if self.frames > self.max_frames {
            return Err(Ipv4OperationError::Limit);
        }
        Ok(())
    }
}

fn encode_address_payload(journal: &AddressJournal<'_>) -> Result<Vec<u8>, Ipv4OperationError> {
    encode_address_payload_for(
        journal.specification,
        journal.interface.ifindex,
        &journal.interface.name,
    )
}

fn encode_address_payload_for(
    specification: FixedIpv4Address,
    ifindex: u32,
    interface_name: &str,
) -> Result<Vec<u8>, Ipv4OperationError> {
    let binding = InterfaceBinding {
        ifindex,
        name: interface_name.to_owned(),
    };
    validate_interface_binding(&binding)?;
    let mut payload = ifaddr_message(ifindex, 0)?;
    let octets = specification.octets();
    push_attribute(&mut payload, IFA_ADDRESS, &octets)?;
    push_attribute(&mut payload, IFA_LOCAL, &octets)?;
    push_string_attribute(&mut payload, IFA_LABEL, interface_name)?;
    if payload.len() > MAX_REQUEST_BYTES {
        return Err(Ipv4OperationError::Limit);
    }
    Ok(payload)
}

fn encode_address_dump_payload() -> Vec<u8> {
    vec![AF_INET, 0, 0, 0, 0, 0, 0, 0]
}

fn encode_get_link_payload(ifindex: u32) -> Result<Vec<u8>, Ipv4OperationError> {
    if ifindex == 0 || ifindex > i32::MAX as u32 {
        return Err(Ipv4OperationError::Unsafe(
            "fixed IPv4 interface index is not representable",
        ));
    }
    let mut payload = Vec::with_capacity(IFINFO_LEN);
    payload.push(AF_UNSPEC);
    payload.push(0);
    payload.extend_from_slice(&0_u16.to_ne_bytes());
    payload.extend_from_slice(&ifindex.to_ne_bytes());
    payload.extend_from_slice(&0_u32.to_ne_bytes());
    payload.extend_from_slice(&0_u32.to_ne_bytes());
    Ok(payload)
}

fn ifaddr_message(ifindex: u32, flags: u8) -> Result<Vec<u8>, Ipv4OperationError> {
    if ifindex == 0 || ifindex > i32::MAX as u32 {
        return Err(Ipv4OperationError::Unsafe(
            "fixed IPv4 interface index is not representable",
        ));
    }
    let mut payload = Vec::with_capacity(IFADDR_LEN);
    payload.push(AF_INET);
    payload.push(FIXED_PREFIX_LENGTH);
    payload.push(flags);
    payload.push(RT_SCOPE_UNIVERSE);
    payload.extend_from_slice(&ifindex.to_ne_bytes());
    Ok(payload)
}

fn encode_message(
    message_type: u16,
    flags: u16,
    sequence: u32,
    payload: &[u8],
) -> Result<Vec<u8>, Ipv4OperationError> {
    if sequence == 0 {
        return Err(Ipv4OperationError::Unsafe("netlink sequence is zero"));
    }
    let length = NLMSG_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(Ipv4OperationError::Limit)?;
    if length > MAX_REQUEST_BYTES {
        return Err(Ipv4OperationError::Limit);
    }
    let mut message = Vec::with_capacity(length);
    message.extend_from_slice(
        &u32::try_from(length)
            .map_err(|_| Ipv4OperationError::Limit)?
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
) -> Result<(), Ipv4OperationError> {
    if value.is_empty()
        || value.len() >= libc::IFNAMSIZ
        || value.as_bytes().contains(&0)
        || !value.is_ascii()
    {
        return Err(Ipv4OperationError::Unsafe("fixed IPv4 label is invalid"));
    }
    let mut encoded = value.as_bytes().to_vec();
    encoded.push(0);
    push_attribute(buffer, kind, &encoded)
}

fn push_attribute(
    buffer: &mut Vec<u8>,
    kind: u16,
    payload: &[u8],
) -> Result<(), Ipv4OperationError> {
    let length = ATTRIBUTE_HEADER_LEN
        .checked_add(payload.len())
        .ok_or(Ipv4OperationError::Limit)?;
    let encoded_length = u16::try_from(length).map_err(|_| Ipv4OperationError::Limit)?;
    buffer.extend_from_slice(&encoded_length.to_ne_bytes());
    buffer.extend_from_slice(&kind.to_ne_bytes());
    buffer.extend_from_slice(payload);
    buffer.resize(align4(buffer.len())?, 0);
    if buffer.len() > MAX_REQUEST_BYTES {
        return Err(Ipv4OperationError::Limit);
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
) -> Result<Ack, Ipv4OperationError> {
    if reply.sender != SocketAddr::new(0, 0) {
        return Err(Ipv4OperationError::Unsafe(
            "netlink ACK sender is not the kernel",
        ));
    }
    let frame = single_frame(&reply.bytes)?;
    let flags = read_u16(frame, 6)?;
    if read_u16(frame, 4)? != NLMSG_ERROR
        || read_u32(frame, 8)? != read_u32(request, 8)?
        || read_u32(frame, 12)? != local_port
    {
        return Err(Ipv4OperationError::Unsafe(
            "netlink ACK header is not exact",
        ));
    }
    let payload = &frame[NLMSG_HEADER_LEN..];
    let embedded_length = NLMSG_ERROR_CODE_LEN
        .checked_add(NLMSG_HEADER_LEN)
        .ok_or(Ipv4OperationError::Limit)?;
    if payload.len() < embedded_length
        || payload[NLMSG_ERROR_CODE_LEN..embedded_length] != request[..NLMSG_HEADER_LEN]
    {
        return Err(Ipv4OperationError::Unsafe(
            "netlink ACK does not bind the exact request header",
        ));
    }
    let trailing = &payload[embedded_length..];
    let errno = read_i32(payload, 0)?;
    if flags & NLM_F_ACK_TLVS != 0 {
        return Err(Ipv4OperationError::Unsafe(
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
        0 => Err(Ipv4OperationError::Unsafe(
            "successful netlink ACK is not the canonical capped form",
        )),
        errno if errno < 0 => Err(Ipv4OperationError::Unsafe(
            "negative netlink ACK does not exactly echo the request",
        )),
        _ => Err(Ipv4OperationError::Unsafe(
            "netlink ACK errno is not canonical",
        )),
    }
}

fn single_frame(bytes: &[u8]) -> Result<&[u8], Ipv4OperationError> {
    if bytes.len() < NLMSG_HEADER_LEN {
        return Err(Ipv4OperationError::Unsafe(
            "netlink datagram lacks a complete header",
        ));
    }
    let length = usize::try_from(read_u32(bytes, 0)?).map_err(|_| Ipv4OperationError::Limit)?;
    let aligned = align4(length)?;
    if length < NLMSG_HEADER_LEN || aligned != bytes.len() {
        return Err(Ipv4OperationError::Unsafe(
            "netlink datagram does not contain exactly one frame",
        ));
    }
    if bytes[length..aligned].iter().any(|byte| *byte != 0) {
        return Err(Ipv4OperationError::Unsafe(
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

fn parse_attributes(mut bytes: &[u8]) -> Result<Vec<Attribute<'_>>, Ipv4OperationError> {
    let mut result = Vec::new();
    while !bytes.is_empty() {
        if result.len() >= MAX_ATTRIBUTES || bytes.len() < ATTRIBUTE_HEADER_LEN {
            return Err(Ipv4OperationError::Limit);
        }
        let length = usize::from(read_u16(bytes, 0)?);
        let aligned = align4(length)?;
        if length < ATTRIBUTE_HEADER_LEN || aligned > bytes.len() {
            return Err(Ipv4OperationError::Unsafe(
                "netlink attribute length is invalid",
            ));
        }
        if bytes[length..aligned].iter().any(|byte| *byte != 0) {
            return Err(Ipv4OperationError::Unsafe(
                "netlink attribute padding is nonzero",
            ));
        }
        let raw_kind = read_u16(bytes, 2)?;
        let flags = raw_kind & !NLA_TYPE_MASK;
        if flags == NLA_F_NESTED | NLA_F_NET_BYTEORDER {
            return Err(Ipv4OperationError::Unsafe(
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

fn verify_link_is_exactly_down(binding: &InterfaceBinding) -> Result<(), Ipv4OperationError> {
    validate_interface_binding(binding)?;
    let deadline = Deadline::after(IPV4_OPERATION_TIMEOUT)?;
    let mut client = NetlinkClient::connect(deadline)?;
    let sequence = client.next_sequence()?;
    let payload = encode_get_link_payload(binding.ifindex)?;
    let request = encode_message(RTM_GETLINK, NLM_F_REQUEST, sequence, &payload)?;
    send_bounded(&client.socket, &request, deadline).map_err(send_failure_source)?;
    let reply = receive_one(&client.socket, deadline)?;
    let frame = single_frame(&reply.bytes)?;
    if read_u16(frame, 4)? == NLMSG_ERROR {
        return match parse_ack(&reply, client.local_port, &request)? {
            Ack::Rejected(errno) => Err(Ipv4OperationError::errno("query fixed veth", errno)),
            Ack::Success => Err(Ipv4OperationError::Unsafe(
                "RTM_GETLINK returned a success ACK without link data",
            )),
        };
    }
    parse_exact_down_link(frame, client.local_port, sequence, binding)
}

fn parse_exact_down_link(
    frame: &[u8],
    local_port: u32,
    sequence: u32,
    binding: &InterfaceBinding,
) -> Result<(), Ipv4OperationError> {
    if read_u16(frame, 4)? != RTM_NEWLINK
        || read_u16(frame, 6)? != 0
        || read_u32(frame, 8)? != sequence
        || read_u32(frame, 12)? != local_port
        || frame.len() < NLMSG_HEADER_LEN + IFINFO_LEN
    {
        return Err(Ipv4OperationError::Unsafe(
            "RTM_GETLINK response header is not exact",
        ));
    }
    let info = &frame[NLMSG_HEADER_LEN..NLMSG_HEADER_LEN + IFINFO_LEN];
    if info[0] != AF_UNSPEC
        || info[1] != 0
        || read_u16(info, 2)? != ARPHRD_ETHER
        || read_i32(info, 4)?
            != i32::try_from(binding.ifindex).map_err(|_| Ipv4OperationError::Limit)?
        || read_u32(info, 8)? != FIXED_DOWN_VETH_FLAGS
        || read_u32(info, 12)? != 0
    {
        return Err(Ipv4OperationError::Unsafe(
            "fixed IPv4 veth header is not exact and down",
        ));
    }
    let mut name = None;
    for attribute in parse_attributes(&frame[NLMSG_HEADER_LEN + IFINFO_LEN..])? {
        if attribute.kind == IFLA_IFNAME && attribute.flags == 0 {
            set_once(&mut name, parse_string(attribute.payload)?)?;
        }
    }
    if name.as_deref() != Some(binding.name.as_str()) {
        return Err(Ipv4OperationError::Unsafe(
            "fixed IPv4 veth interface name changed",
        ));
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum AddressPresence {
    Absent,
    Exact,
}

fn observe_presence(journal: &AddressJournal<'_>) -> Result<AddressPresence, Ipv4OperationError> {
    journal.verify_context()?;
    let observations = collect_interface_addresses(&journal.interface, journal.specification)?;
    match observations.as_slice() {
        [] => Ok(AddressPresence::Absent),
        [_] => Ok(AddressPresence::Exact),
        _ => Err(Ipv4OperationError::Unsafe(
            "fixed veth has more than one IPv4 address",
        )),
    }
}

fn require_absence(journal: &AddressJournal<'_>) -> Result<(), Ipv4OperationError> {
    match observe_presence(journal)? {
        AddressPresence::Absent => Ok(()),
        AddressPresence::Exact => Err(Ipv4OperationError::Unsafe(
            "fixed IPv4 address already exists before installation",
        )),
    }
}

fn require_exact_presence(journal: &AddressJournal<'_>) -> Result<(), Ipv4OperationError> {
    match observe_presence(journal)? {
        AddressPresence::Exact => Ok(()),
        AddressPresence::Absent => Err(Ipv4OperationError::Unsafe(
            "retained fixed IPv4 address is absent",
        )),
    }
}

fn collect_interface_addresses(
    binding: &InterfaceBinding,
    specification: FixedIpv4Address,
) -> Result<Vec<FixedAddressObservation>, Ipv4OperationError> {
    let deadline = Deadline::after(IPV4_OPERATION_TIMEOUT)?;
    let mut client = NetlinkClient::connect(deadline)?;
    let sequence = client.next_sequence()?;
    let request = encode_message(
        RTM_GETADDR,
        NLM_F_REQUEST | NLM_F_DUMP,
        sequence,
        &encode_address_dump_payload(),
    )?;
    send_bounded(&client.socket, &request, deadline).map_err(send_failure_source)?;
    let mut state = AddressDumpState::new(sequence, client.local_port, request);
    let mut budget = ReceiveBudget::dump();
    while !state.done {
        let reply = receive_bounded(&client.socket, deadline, &mut budget)?;
        state.ingest(&reply, &mut budget, binding, specification)?;
    }
    deadline.ensure_unexpired()?;
    state.finish()
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct FixedAddressObservation {
    ifindex: u32,
    address: [u8; 4],
    label: String,
}

struct AddressDumpState {
    sequence: u32,
    local_port: u32,
    request: Vec<u8>,
    done: bool,
    records: usize,
    matching: Vec<FixedAddressObservation>,
}

impl AddressDumpState {
    fn new(sequence: u32, local_port: u32, request: Vec<u8>) -> Self {
        Self {
            sequence,
            local_port,
            request,
            done: false,
            records: 0,
            matching: Vec::new(),
        }
    }

    fn ingest(
        &mut self,
        reply: &NetlinkReply,
        budget: &mut ReceiveBudget,
        binding: &InterfaceBinding,
        specification: FixedIpv4Address,
    ) -> Result<(), Ipv4OperationError> {
        if self.done || reply.sender != SocketAddr::new(0, 0) {
            return Err(Ipv4OperationError::Unsafe(
                "address dump sender or completion state is invalid",
            ));
        }
        let mut offset = 0;
        while offset < reply.bytes.len() {
            let remaining = &reply.bytes[offset..];
            if remaining.len() < NLMSG_HEADER_LEN {
                return Err(Ipv4OperationError::Unsafe(
                    "address dump has a truncated frame",
                ));
            }
            let length =
                usize::try_from(read_u32(remaining, 0)?).map_err(|_| Ipv4OperationError::Limit)?;
            let aligned = align4(length)?;
            if length < NLMSG_HEADER_LEN || aligned > remaining.len() {
                return Err(Ipv4OperationError::Unsafe(
                    "address dump frame length is invalid",
                ));
            }
            if remaining[length..aligned].iter().any(|byte| *byte != 0) {
                return Err(Ipv4OperationError::Unsafe(
                    "address dump frame padding is nonzero",
                ));
            }
            budget.record_frame()?;
            self.ingest_frame(&remaining[..length], binding, specification)?;
            offset = offset
                .checked_add(aligned)
                .ok_or(Ipv4OperationError::Limit)?;
            if self.done && offset != reply.bytes.len() {
                return Err(Ipv4OperationError::Unsafe(
                    "address dump carries data after completion",
                ));
            }
        }
        Ok(())
    }

    fn ingest_frame(
        &mut self,
        frame: &[u8],
        binding: &InterfaceBinding,
        specification: FixedIpv4Address,
    ) -> Result<(), Ipv4OperationError> {
        if read_u32(frame, 8)? != self.sequence || read_u32(frame, 12)? != self.local_port {
            return Err(Ipv4OperationError::Unsafe(
                "address dump sequence or port is not exact",
            ));
        }
        let message_type = read_u16(frame, 4)?;
        let flags = read_u16(frame, 6)?;
        let payload = &frame[NLMSG_HEADER_LEN..];
        match message_type {
            NLMSG_DONE => {
                parse_dump_done(flags, payload)?;
                self.done = true;
            }
            NLMSG_ERROR => return Err(parse_dump_error(flags, payload, &self.request)?),
            NLMSG_OVERRUN => {
                return Err(Ipv4OperationError::Unsafe(
                    "address dump overrun is ambiguous",
                ));
            }
            RTM_NEWADDR if flags == NLM_F_MULTI => {
                self.records = self
                    .records
                    .checked_add(1)
                    .ok_or(Ipv4OperationError::Limit)?;
                if self.records > MAX_ADDRESS_RECORDS {
                    return Err(Ipv4OperationError::Limit);
                }
                if let Some(observation) = parse_address_record(payload, binding, specification)? {
                    if self.matching.len() >= 2 {
                        return Err(Ipv4OperationError::Unsafe(
                            "fixed veth has too many IPv4 address records",
                        ));
                    }
                    self.matching.push(observation);
                }
            }
            _ => {
                return Err(Ipv4OperationError::Unsafe(
                    "address dump contains an unexpected message",
                ));
            }
        }
        Ok(())
    }

    fn finish(self) -> Result<Vec<FixedAddressObservation>, Ipv4OperationError> {
        if self.done {
            Ok(self.matching)
        } else {
            Err(Ipv4OperationError::Unsafe(
                "address dump ended without NLMSG_DONE",
            ))
        }
    }
}

fn parse_address_record(
    payload: &[u8],
    binding: &InterfaceBinding,
    specification: FixedIpv4Address,
) -> Result<Option<FixedAddressObservation>, Ipv4OperationError> {
    if payload.len() < IFADDR_LEN || payload[0] != AF_INET {
        return Err(Ipv4OperationError::Unsafe(
            "IPv4 address dump record header is malformed",
        ));
    }
    let ifindex = read_u32(payload, 4)?;
    let attributes = parse_attributes(&payload[IFADDR_LEN..])?;
    if ifindex != binding.ifindex {
        return Ok(None);
    }
    if payload[1] != FIXED_PREFIX_LENGTH
        || payload[2] != IFA_F_PERMANENT_U8
        || payload[3] != RT_SCOPE_UNIVERSE
    {
        return Err(Ipv4OperationError::Unsafe(
            "fixed IPv4 readback header is not permanent global /30",
        ));
    }
    let mut address = None;
    let mut local = None;
    let mut label = None;
    let mut flags = None;
    let mut cache = None;
    for attribute in attributes {
        if attribute.flags != 0 {
            return Err(Ipv4OperationError::Unsafe(
                "fixed IPv4 readback attribute carries flags",
            ));
        }
        match attribute.kind {
            IFA_ADDRESS => set_once(&mut address, read_exact_ipv4(attribute.payload)?)?,
            IFA_LOCAL => set_once(&mut local, read_exact_ipv4(attribute.payload)?)?,
            IFA_LABEL => set_once(&mut label, parse_string(attribute.payload)?)?,
            IFA_FLAGS => set_once(&mut flags, read_exact_u32(attribute.payload)?)?,
            IFA_CACHEINFO => set_once(&mut cache, parse_cache_info(attribute.payload)?)?,
            IFA_BROADCAST => {
                return Err(Ipv4OperationError::Unsafe(
                    "fixed IPv4 readback unexpectedly contains a broadcast attribute",
                ));
            }
            _ => {
                return Err(Ipv4OperationError::Unsafe(
                    "fixed IPv4 readback contains an unknown attribute",
                ));
            }
        }
    }
    let expected = specification.octets();
    if address != Some(expected)
        || local != Some(expected)
        || label.as_deref() != Some(binding.name.as_str())
        || flags != Some(IFA_F_PERMANENT)
        || cache.is_none()
    {
        return Err(Ipv4OperationError::Unsafe(
            "fixed IPv4 readback does not match the exact static contract",
        ));
    }
    Ok(Some(FixedAddressObservation {
        ifindex,
        address: expected,
        label: binding.name.clone(),
    }))
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct AddressCacheInfo {
    preferred_lifetime: u32,
    valid_lifetime: u32,
}

fn parse_cache_info(payload: &[u8]) -> Result<AddressCacheInfo, Ipv4OperationError> {
    if payload.len() != 16 {
        return Err(Ipv4OperationError::Unsafe(
            "IPv4 cache-info telemetry has the wrong size",
        ));
    }
    let preferred_lifetime = read_u32(payload, 0)?;
    let valid_lifetime = read_u32(payload, 4)?;
    let _creation_timestamp = read_u32(payload, 8)?;
    let _update_timestamp = read_u32(payload, 12)?;
    if preferred_lifetime != INFINITE_ADDRESS_LIFETIME
        || valid_lifetime != INFINITE_ADDRESS_LIFETIME
    {
        return Err(Ipv4OperationError::Unsafe(
            "fixed IPv4 address lifetimes are not infinite",
        ));
    }
    Ok(AddressCacheInfo {
        preferred_lifetime,
        valid_lifetime,
    })
}

fn parse_dump_done(flags: u16, payload: &[u8]) -> Result<(), Ipv4OperationError> {
    if flags != NLM_F_MULTI {
        return Err(Ipv4OperationError::Unsafe(
            "address dump completion flags are not exact",
        ));
    }
    match payload {
        [] => Ok(()),
        bytes if bytes.len() == 4 => match read_i32(bytes, 0)? {
            0 => Ok(()),
            errno if errno < 0 && errno != i32::MIN => {
                Err(Ipv4OperationError::errno("dump IPv4 addresses", -errno))
            }
            _ => Err(Ipv4OperationError::Unsafe(
                "address dump completion errno is not canonical",
            )),
        },
        _ => Err(Ipv4OperationError::Unsafe(
            "address dump completion payload is not exact",
        )),
    }
}

fn parse_dump_error(
    flags: u16,
    payload: &[u8],
    request: &[u8],
) -> Result<Ipv4OperationError, Ipv4OperationError> {
    if flags != 0 || payload.len() != NLMSG_ERROR_CODE_LEN + request.len() {
        return Err(Ipv4OperationError::Unsafe(
            "address dump error shape is not exact",
        ));
    }
    let errno = read_i32(payload, 0)?;
    if payload[NLMSG_ERROR_CODE_LEN..] != *request {
        return Err(Ipv4OperationError::Unsafe(
            "address dump error does not echo the exact request",
        ));
    }
    if errno < 0 && errno != i32::MIN {
        Ok(Ipv4OperationError::errno("dump IPv4 addresses", -errno))
    } else {
        Err(Ipv4OperationError::Unsafe(
            "address dump error errno is not canonical",
        ))
    }
}

fn delete_journal_exact(journal: &AddressJournal<'_>) -> Result<(), Ipv4OperationError> {
    require_exact_presence(journal)?;
    let payload = encode_address_payload(journal)?;
    let deadline = Deadline::after(IPV4_OPERATION_TIMEOUT)?;
    let mut client = NetlinkClient::connect(deadline)?;
    let sequence = client.next_sequence()?;
    let request = encode_message(RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK, sequence, &payload)?;
    send_bounded(&client.socket, &request, deadline).map_err(send_failure_source)?;
    let reply = receive_one(&client.socket, deadline)?;
    match parse_ack(&reply, client.local_port, &request)? {
        Ack::Success => {}
        Ack::Rejected(errno) => {
            return Err(Ipv4OperationError::errno(
                "delete fixed IPv4 address",
                errno,
            ));
        }
    }
    drop(client);
    match observe_presence(journal)? {
        AddressPresence::Absent => Ok(()),
        AddressPresence::Exact => Err(Ipv4OperationError::Unsafe(
            "deleted fixed IPv4 address remains visible",
        )),
    }
}

fn reconcile_journal(journal: &AddressJournal<'_>) -> Result<(), Ipv4OperationError> {
    reconcile_observed_state(
        || observe_presence(journal),
        || delete_journal_exact(journal),
    )
}

fn reconcile_observed_state<Observe, Delete>(
    mut observe: Observe,
    mut delete: Delete,
) -> Result<(), Ipv4OperationError>
where
    Observe: FnMut() -> Result<AddressPresence, Ipv4OperationError>,
    Delete: FnMut() -> Result<(), Ipv4OperationError>,
{
    for _ in 0..MAX_RECONCILIATION_DELETE_ATTEMPTS {
        match observe()? {
            AddressPresence::Absent => return Ok(()),
            AddressPresence::Exact => {}
        }
        let _ = delete();
    }
    match observe()? {
        AddressPresence::Absent => Ok(()),
        AddressPresence::Exact => Err(Ipv4OperationError::Unsafe(
            "fixed IPv4 cleanup could not prove absence",
        )),
    }
}

fn send_failure_source(failure: SendFailure) -> Ipv4OperationError {
    match failure {
        SendFailure::NotSent(source) | SendFailure::PossiblySent(source) => source,
    }
}

fn parse_string(payload: &[u8]) -> Result<String, Ipv4OperationError> {
    let bytes = payload
        .strip_suffix(&[0])
        .ok_or(Ipv4OperationError::Unsafe(
            "netlink string is not NUL terminated",
        ))?;
    if bytes.is_empty() || bytes.len() >= libc::IFNAMSIZ || bytes.contains(&0) || !bytes.is_ascii()
    {
        return Err(Ipv4OperationError::Unsafe(
            "netlink string is not canonical",
        ));
    }
    String::from_utf8(bytes.to_vec())
        .map_err(|_| Ipv4OperationError::Unsafe("netlink string is not UTF-8"))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, Ipv4OperationError> {
    let end = offset.checked_add(2).ok_or(Ipv4OperationError::Limit)?;
    let value = bytes
        .get(offset..end)
        .ok_or(Ipv4OperationError::Unsafe("truncated netlink u16"))?
        .try_into()
        .map_err(|_| Ipv4OperationError::Unsafe("invalid netlink u16"))?;
    Ok(u16::from_ne_bytes(value))
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, Ipv4OperationError> {
    let end = offset.checked_add(4).ok_or(Ipv4OperationError::Limit)?;
    let value = bytes
        .get(offset..end)
        .ok_or(Ipv4OperationError::Unsafe("truncated netlink u32"))?
        .try_into()
        .map_err(|_| Ipv4OperationError::Unsafe("invalid netlink u32"))?;
    Ok(u32::from_ne_bytes(value))
}

fn read_i32(bytes: &[u8], offset: usize) -> Result<i32, Ipv4OperationError> {
    let end = offset.checked_add(4).ok_or(Ipv4OperationError::Limit)?;
    let value = bytes
        .get(offset..end)
        .ok_or(Ipv4OperationError::Unsafe("truncated netlink i32"))?
        .try_into()
        .map_err(|_| Ipv4OperationError::Unsafe("invalid netlink i32"))?;
    Ok(i32::from_ne_bytes(value))
}

fn read_exact_u32(bytes: &[u8]) -> Result<u32, Ipv4OperationError> {
    if bytes.len() != 4 {
        return Err(Ipv4OperationError::Unsafe(
            "netlink u32 attribute has the wrong size",
        ));
    }
    read_u32(bytes, 0)
}

fn read_exact_ipv4(bytes: &[u8]) -> Result<[u8; 4], Ipv4OperationError> {
    bytes
        .try_into()
        .map_err(|_| Ipv4OperationError::Unsafe("IPv4 attribute has the wrong size"))
}

fn align4(length: usize) -> Result<usize, Ipv4OperationError> {
    length
        .checked_add(3)
        .map(|value| value & !3)
        .ok_or(Ipv4OperationError::Limit)
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), Ipv4OperationError> {
    if slot.replace(value).is_some() {
        Err(Ipv4OperationError::Unsafe(
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

    const SEQUENCE: u32 = 7;
    const PORT: u32 = 41;
    const IFINDEX: u32 = 17;
    const NAME: &str = "eth0";

    fn binding() -> InterfaceBinding {
        InterfaceBinding {
            ifindex: IFINDEX,
            name: NAME.to_owned(),
        }
    }

    fn request(message_type: u16, flags: u16) -> Vec<u8> {
        let payload = encode_address_payload_for(FixedIpv4Address::EndpointA, IFINDEX, NAME)
            .expect("address payload");
        encode_message(message_type, flags, SEQUENCE, &payload).expect("request")
    }

    fn frame(message_type: u16, flags: u16, sequence: u32, port: u32, payload: &[u8]) -> Vec<u8> {
        let length = NLMSG_HEADER_LEN + payload.len();
        let mut result = Vec::new();
        result.extend_from_slice(
            &u32::try_from(length)
                .expect("test frame length is representable")
                .to_ne_bytes(),
        );
        result.extend_from_slice(&message_type.to_ne_bytes());
        result.extend_from_slice(&flags.to_ne_bytes());
        result.extend_from_slice(&sequence.to_ne_bytes());
        result.extend_from_slice(&port.to_ne_bytes());
        result.extend_from_slice(payload);
        result.resize((length + 3) & !3, 0);
        result
    }

    fn ack_with_shape(request: &[u8], errno: i32, flags: u16, echo_payload: bool) -> NetlinkReply {
        let mut payload = Vec::new();
        payload.extend_from_slice(&errno.to_ne_bytes());
        payload.extend_from_slice(&request[..NLMSG_HEADER_LEN]);
        if echo_payload {
            payload.extend_from_slice(&request[NLMSG_HEADER_LEN..]);
        }
        NetlinkReply {
            sender: SocketAddr::new(0, 0),
            bytes: frame(NLMSG_ERROR, flags, SEQUENCE, PORT, &payload),
        }
    }

    fn cache_info(preferred: u32, valid: u32, created: u32, updated: u32) -> [u8; 16] {
        let mut result = [0_u8; 16];
        result[0..4].copy_from_slice(&preferred.to_ne_bytes());
        result[4..8].copy_from_slice(&valid.to_ne_bytes());
        result[8..12].copy_from_slice(&created.to_ne_bytes());
        result[12..16].copy_from_slice(&updated.to_ne_bytes());
        result
    }

    fn exact_address_payload() -> Vec<u8> {
        let mut payload = ifaddr_message(IFINDEX, IFA_F_PERMANENT_U8).expect("ifaddr");
        let address = FixedIpv4Address::EndpointA.octets();
        push_attribute(&mut payload, IFA_ADDRESS, &address).expect("address");
        push_attribute(&mut payload, IFA_LOCAL, &address).expect("local");
        push_string_attribute(&mut payload, IFA_LABEL, NAME).expect("label");
        push_attribute(&mut payload, IFA_FLAGS, &IFA_F_PERMANENT.to_ne_bytes()).expect("flags");
        push_attribute(
            &mut payload,
            IFA_CACHEINFO,
            &cache_info(u32::MAX, u32::MAX, 11, 12),
        )
        .expect("cache info");
        payload
    }

    fn parse_exact(payload: &[u8]) -> Result<Option<FixedAddressObservation>, Ipv4OperationError> {
        parse_address_record(payload, &binding(), FixedIpv4Address::EndpointA)
    }

    #[test]
    fn fixed_selector_exposes_only_four_contract_addresses() {
        assert_eq!(FixedIpv4Address::ParentA.octets(), [10, 241, 1, 1]);
        assert_eq!(FixedIpv4Address::EndpointA.octets(), [10, 241, 1, 2]);
        assert_eq!(FixedIpv4Address::ParentB.octets(), [10, 241, 2, 1]);
        assert_eq!(FixedIpv4Address::EndpointB.octets(), [10, 241, 2, 2]);
        for address in [
            FixedIpv4Address::ParentA,
            FixedIpv4Address::EndpointA,
            FixedIpv4Address::ParentB,
            FixedIpv4Address::EndpointB,
        ] {
            assert_eq!(address.prefix_length(), 30);
        }
    }

    #[test]
    fn create_request_is_exclusive_fixed_and_contains_no_broadcast_or_link_up() {
        let request = request(
            RTM_NEWADDR,
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL,
        );
        assert_eq!(read_u16(&request, 4).expect("type"), RTM_NEWADDR);
        assert_eq!(
            read_u16(&request, 6).expect("flags"),
            NLM_F_REQUEST | NLM_F_ACK | NLM_F_CREATE | NLM_F_EXCL
        );
        let payload = &request[NLMSG_HEADER_LEN..];
        assert_eq!(&payload[..IFADDR_LEN], &[AF_INET, 30, 0, 0, 17, 0, 0, 0]);
        let attributes = parse_attributes(&payload[IFADDR_LEN..]).expect("attributes");
        assert_eq!(
            attributes
                .iter()
                .map(|attribute| attribute.kind)
                .collect::<Vec<_>>(),
            [IFA_ADDRESS, IFA_LOCAL, IFA_LABEL]
        );
        assert!(attributes.iter().all(|attribute| attribute.flags == 0));
        assert!(
            !attributes
                .iter()
                .any(|attribute| attribute.kind == IFA_BROADCAST)
        );
        assert!(
            !request
                .windows(2)
                .any(|bytes| bytes == RTM_NEWLINK.to_ne_bytes())
        );
    }

    #[test]
    fn delete_request_is_exact_address_only_and_acknowledged() {
        let request = request(RTM_DELADDR, NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(read_u16(&request, 4).expect("type"), RTM_DELADDR);
        assert_eq!(
            read_u16(&request, 6).expect("flags"),
            NLM_F_REQUEST | NLM_F_ACK
        );
        assert_eq!(
            parse_attributes(&request[NLMSG_HEADER_LEN + IFADDR_LEN..])
                .expect("attributes")
                .iter()
                .map(|attribute| attribute.kind)
                .collect::<Vec<_>>(),
            [IFA_ADDRESS, IFA_LOCAL, IFA_LABEL]
        );
    }

    #[test]
    fn exact_success_and_negative_ack_are_classified() {
        let request = request(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK);
        assert_eq!(
            parse_ack(
                &ack_with_shape(&request, 0, NLM_F_CAPPED, false),
                PORT,
                &request
            )
            .expect("success"),
            Ack::Success
        );
        assert_eq!(
            parse_ack(
                &ack_with_shape(&request, -libc::EEXIST, 0, true),
                PORT,
                &request
            )
            .expect("rejection"),
            Ack::Rejected(libc::EEXIST)
        );
    }

    #[test]
    fn malformed_ack_shapes_fail_closed() {
        let request = request(RTM_NEWADDR, NLM_F_REQUEST | NLM_F_ACK);
        for reply in [
            ack_with_shape(&request, 0, 0, false),
            ack_with_shape(&request, 0, NLM_F_CAPPED, true),
            ack_with_shape(&request, -libc::EINVAL, 0, false),
            ack_with_shape(&request, -libc::EINVAL, NLM_F_CAPPED, true),
            ack_with_shape(&request, 1, 0, true),
            ack_with_shape(&request, i32::MIN, 0, true),
        ] {
            assert!(parse_ack(&reply, PORT, &request).is_err());
        }
        let mut wrong_sequence = ack_with_shape(&request, 0, NLM_F_CAPPED, false);
        wrong_sequence.bytes[8..12].copy_from_slice(&(SEQUENCE + 1).to_ne_bytes());
        assert!(parse_ack(&wrong_sequence, PORT, &request).is_err());
        let mut wrong_sender = ack_with_shape(&request, 0, NLM_F_CAPPED, false);
        wrong_sender.sender = SocketAddr::new(9, 0);
        assert!(parse_ack(&wrong_sender, PORT, &request).is_err());
        let mut extra_frame = ack_with_shape(&request, 0, NLM_F_CAPPED, false);
        extra_frame
            .bytes
            .extend_from_slice(&frame(NLMSG_DONE, 0, SEQUENCE, PORT, &[]));
        assert!(parse_ack(&extra_frame, PORT, &request).is_err());
    }

    #[test]
    fn debian13_static_readback_is_accepted_semantically() {
        let first = exact_address_payload();
        let mut second = exact_address_payload();
        let cache_offset = second
            .windows(2)
            .position(|bytes| bytes == IFA_CACHEINFO.to_ne_bytes())
            .expect("cache kind")
            + 2;
        second[cache_offset + 8..cache_offset + 12].copy_from_slice(&999_u32.to_ne_bytes());
        second[cache_offset + 12..cache_offset + 16].copy_from_slice(&1000_u32.to_ne_bytes());
        assert_eq!(
            parse_exact(&first).expect("first"),
            parse_exact(&second).expect("second")
        );
        assert_eq!(
            parse_exact(&first)
                .expect("exact")
                .expect("matching")
                .address,
            [10, 241, 1, 2]
        );
    }

    #[test]
    fn static_readback_rejects_wrong_header_address_label_and_lifetimes() {
        let exact = exact_address_payload();
        for (offset, value) in [(0, AF_UNSPEC), (1, 29), (2, 0), (3, 253)] {
            let mut malformed = exact.clone();
            malformed[offset] = value;
            assert!(parse_exact(&malformed).is_err());
        }
        let mut wrong_address = exact.clone();
        let address_offset = IFADDR_LEN + ATTRIBUTE_HEADER_LEN;
        wrong_address[address_offset + 3] = 9;
        assert!(parse_exact(&wrong_address).is_err());

        let mut wrong_label = exact.clone();
        let label = wrong_label
            .windows(NAME.len())
            .position(|bytes| bytes == NAME.as_bytes())
            .expect("label");
        wrong_label[label] = b'x';
        assert!(parse_exact(&wrong_label).is_err());

        let mut finite = exact;
        let cache_header = finite
            .windows(2)
            .position(|bytes| bytes == IFA_CACHEINFO.to_ne_bytes())
            .expect("cache kind");
        finite[cache_header + 2..cache_header + 6].copy_from_slice(&60_u32.to_ne_bytes());
        assert!(parse_exact(&finite).is_err());
    }

    #[test]
    fn readback_rejects_broadcast_unknown_duplicate_and_flagged_attributes() {
        let exact = exact_address_payload();
        for (kind, payload) in [(IFA_BROADCAST, vec![10, 241, 1, 3]), (99, vec![0; 4])] {
            let mut malformed = exact.clone();
            push_attribute(&mut malformed, kind, &payload).expect("extra attribute");
            assert!(parse_exact(&malformed).is_err());
        }

        let mut duplicate = exact.clone();
        push_attribute(
            &mut duplicate,
            IFA_LOCAL,
            &FixedIpv4Address::EndpointA.octets(),
        )
        .expect("duplicate local");
        assert!(parse_exact(&duplicate).is_err());

        let mut flagged = exact;
        let first_kind = IFADDR_LEN + 2;
        flagged[first_kind..first_kind + 2]
            .copy_from_slice(&(IFA_ADDRESS | NLA_F_NET_BYTEORDER).to_ne_bytes());
        assert!(parse_exact(&flagged).is_err());
    }

    #[test]
    fn readback_rejects_missing_or_malformed_cache_telemetry() {
        let mut missing = ifaddr_message(IFINDEX, IFA_F_PERMANENT_U8).expect("ifaddr");
        let address = FixedIpv4Address::EndpointA.octets();
        push_attribute(&mut missing, IFA_ADDRESS, &address).expect("address");
        push_attribute(&mut missing, IFA_LOCAL, &address).expect("local");
        push_string_attribute(&mut missing, IFA_LABEL, NAME).expect("label");
        push_attribute(&mut missing, IFA_FLAGS, &IFA_F_PERMANENT.to_ne_bytes()).expect("flags");
        assert!(parse_exact(&missing).is_err());

        let mut malformed = missing;
        push_attribute(&mut malformed, IFA_CACHEINFO, &[0; 12]).expect("cache");
        assert!(parse_exact(&malformed).is_err());
    }

    #[test]
    fn unrelated_interface_record_is_structurally_checked_but_ignored() {
        let mut unrelated = exact_address_payload();
        unrelated[4..8].copy_from_slice(&(IFINDEX + 1).to_ne_bytes());
        assert_eq!(parse_exact(&unrelated).expect("unrelated"), None);

        unrelated.truncate(IFADDR_LEN + 3);
        assert!(parse_exact(&unrelated).is_err());
    }

    #[test]
    fn exact_down_link_requires_ifindex_name_and_no_up_bit() {
        let binding = binding();
        let mut payload = Vec::new();
        payload.push(AF_UNSPEC);
        payload.push(0);
        payload.extend_from_slice(&ARPHRD_ETHER.to_ne_bytes());
        payload.extend_from_slice(&IFINDEX.to_ne_bytes());
        payload.extend_from_slice(&FIXED_DOWN_VETH_FLAGS.to_ne_bytes());
        payload.extend_from_slice(&0_u32.to_ne_bytes());
        push_string_attribute(&mut payload, IFLA_IFNAME, NAME).expect("name");
        let exact = frame(RTM_NEWLINK, 0, SEQUENCE, PORT, &payload);
        let exact_frame = single_frame(&exact).expect("frame");
        parse_exact_down_link(exact_frame, PORT, SEQUENCE, &binding).expect("down link");

        let mut up = exact.clone();
        let flags_offset = NLMSG_HEADER_LEN + 8;
        up[flags_offset..flags_offset + 4]
            .copy_from_slice(&(FIXED_DOWN_VETH_FLAGS | 1).to_ne_bytes());
        assert!(parse_exact_down_link(&up, PORT, SEQUENCE, &binding).is_err());

        let mut renamed = exact;
        let name_offset = renamed
            .windows(NAME.len())
            .position(|bytes| bytes == NAME.as_bytes())
            .expect("name offset");
        renamed[name_offset] = b'x';
        assert!(parse_exact_down_link(&renamed, PORT, SEQUENCE, &binding).is_err());
    }

    #[test]
    fn address_dump_accepts_exact_multi_record_and_done() {
        let request = encode_message(
            RTM_GETADDR,
            NLM_F_REQUEST | NLM_F_DUMP,
            SEQUENCE,
            &encode_address_dump_payload(),
        )
        .expect("dump request");
        let mut state = AddressDumpState::new(SEQUENCE, PORT, request);
        let mut bytes = frame(
            RTM_NEWADDR,
            NLM_F_MULTI,
            SEQUENCE,
            PORT,
            &exact_address_payload(),
        );
        bytes.extend_from_slice(&frame(
            NLMSG_DONE,
            NLM_F_MULTI,
            SEQUENCE,
            PORT,
            &0_i32.to_ne_bytes(),
        ));
        let mut budget = ReceiveBudget::dump();
        budget.record_datagram(bytes.len()).expect("datagram");
        state
            .ingest(
                &NetlinkReply {
                    sender: SocketAddr::new(0, 0),
                    bytes,
                },
                &mut budget,
                &binding(),
                FixedIpv4Address::EndpointA,
            )
            .expect("dump");
        assert_eq!(state.finish().expect("finish").len(), 1);
    }

    #[test]
    fn address_dump_rejects_wrong_sender_sequence_flags_and_trailing_frames() {
        let dump_request = || {
            encode_message(
                RTM_GETADDR,
                NLM_F_REQUEST | NLM_F_DUMP,
                SEQUENCE,
                &encode_address_dump_payload(),
            )
            .expect("dump request")
        };
        let cases = [
            (
                SocketAddr::new(2, 0),
                frame(NLMSG_DONE, NLM_F_MULTI, SEQUENCE, PORT, &[]),
            ),
            (
                SocketAddr::new(0, 0),
                frame(NLMSG_DONE, NLM_F_MULTI, SEQUENCE + 1, PORT, &[]),
            ),
            (
                SocketAddr::new(0, 0),
                frame(NLMSG_DONE, 0, SEQUENCE, PORT, &[]),
            ),
        ];
        for (sender, bytes) in cases {
            let mut state = AddressDumpState::new(SEQUENCE, PORT, dump_request());
            let mut budget = ReceiveBudget::dump();
            assert!(
                state
                    .ingest(
                        &NetlinkReply { sender, bytes },
                        &mut budget,
                        &binding(),
                        FixedIpv4Address::EndpointA,
                    )
                    .is_err()
            );
        }

        let mut after_done = frame(NLMSG_DONE, NLM_F_MULTI, SEQUENCE, PORT, &[]);
        after_done.extend_from_slice(&frame(
            RTM_NEWADDR,
            NLM_F_MULTI,
            SEQUENCE,
            PORT,
            &exact_address_payload(),
        ));
        let mut state = AddressDumpState::new(SEQUENCE, PORT, dump_request());
        let mut budget = ReceiveBudget::dump();
        assert!(
            state
                .ingest(
                    &NetlinkReply {
                        sender: SocketAddr::new(0, 0),
                        bytes: after_done,
                    },
                    &mut budget,
                    &binding(),
                    FixedIpv4Address::EndpointA,
                )
                .is_err()
        );
    }

    #[test]
    fn reconciliation_stops_after_two_delete_attempts_and_one_final_observation() {
        let observations = Rc::new(RefCell::new(VecDeque::from([
            AddressPresence::Exact,
            AddressPresence::Exact,
            AddressPresence::Absent,
        ])));
        let delete_count = Rc::new(RefCell::new(0_usize));
        let observed = Rc::clone(&observations);
        let delete_count_for_closure = Rc::clone(&delete_count);
        reconcile_observed_state(
            || {
                observed
                    .borrow_mut()
                    .pop_front()
                    .ok_or(Ipv4OperationError::Unsafe("missing observation"))
            },
            || {
                *delete_count_for_closure.borrow_mut() += 1;
                Err(Ipv4OperationError::Unsafe("lost delete ACK"))
            },
        )
        .expect("final absence");
        assert_eq!(*delete_count.borrow(), 2);
        assert!(observations.borrow().is_empty());
    }

    #[test]
    fn reconciliation_never_exceeds_delete_bound_or_accepts_remaining_address() {
        let observations = Rc::new(RefCell::new(VecDeque::from([
            AddressPresence::Exact,
            AddressPresence::Exact,
            AddressPresence::Exact,
        ])));
        let delete_count = Rc::new(RefCell::new(0_usize));
        let observed = Rc::clone(&observations);
        let delete_count_for_closure = Rc::clone(&delete_count);
        assert!(
            reconcile_observed_state(
                || {
                    observed
                        .borrow_mut()
                        .pop_front()
                        .ok_or(Ipv4OperationError::Unsafe("missing observation"))
                },
                || {
                    *delete_count_for_closure.borrow_mut() += 1;
                    Err(Ipv4OperationError::Unsafe("delete failed"))
                },
            )
            .is_err()
        );
        assert_eq!(*delete_count.borrow(), 2);
        assert!(observations.borrow().is_empty());
    }

    #[test]
    fn reconciliation_does_not_delete_after_mismatch_observation() {
        let delete_count = Rc::new(RefCell::new(0_usize));
        let delete_count_for_closure = Rc::clone(&delete_count);
        assert!(
            reconcile_observed_state(
                || Err(Ipv4OperationError::Unsafe("replacement or mismatch")),
                || {
                    *delete_count_for_closure.borrow_mut() += 1;
                    Ok(())
                },
            )
            .is_err()
        );
        assert_eq!(*delete_count.borrow(), 0);
    }

    #[test]
    fn resource_bounds_and_alignment_fail_closed() {
        let mut budget = ReceiveBudget {
            bytes: MAX_NETLINK_TOTAL_BYTES,
            datagrams: 0,
            frames: 0,
            max_bytes: MAX_NETLINK_TOTAL_BYTES,
            max_datagrams: MAX_NETLINK_DATAGRAMS,
            max_frames: MAX_NETLINK_FRAMES,
        };
        assert!(budget.record_datagram(NLMSG_HEADER_LEN).is_err());
        budget.bytes = 0;
        budget.frames = MAX_NETLINK_FRAMES;
        assert!(budget.record_frame().is_err());
        assert!(align4(usize::MAX).is_err());
        assert!(encode_address_payload_for(FixedIpv4Address::ParentA, 0, NAME).is_err());
        assert!(
            encode_address_payload_for(
                FixedIpv4Address::ParentA,
                IFINDEX,
                "interface-name-too-long",
            )
            .is_err()
        );
    }
}
