use std::{
    fs::File,
    io,
    marker::PhantomData,
    os::fd::{AsFd, AsRawFd},
    rc::Rc,
};

use nix::{
    libc,
    sched::{CloneFlags, setns, unshare},
    unistd::getpid,
};
use rustix::{
    fd::OwnedFd,
    fs::{
        AtFlags, FsWord, Mode, OFlags, ResolveFlags, StatxFlags, fstat, fstatfs, open, openat2,
        statx,
    },
    io::Errno,
    mount::{MoveMountFlags, OpenTreeFlags, UnmountFlags, move_mount, open_tree, unmount},
    thread::{Pid, gettid},
};
use thiserror::Error;
use volparossa_linux_uapi::{namespace_type, owning_user_namespace};

use super::{
    ipv4::{
        FixedIpv4Address, FixedIpv4AddressOwner, Ipv4AddError, Ipv4RollbackError, Ipv4VerifyError,
        add_fixed_ipv4_address,
    },
    link::{
        AllLinksAddrgenNone, AllLinksUp, FixedLinkEnd, FixedLinkMutationJournal,
        FixedLinkOperationError, FixedLinkRetirement, FixedPairAbsenceProof,
        PendingFixedPairAbsenceProof,
    },
    ownership::{AuthorizedPrivateRun, AuthorizedPrivateRunError, NamespacePinTarget},
    route::{
        FixedEndpointRouteOwner, FixedEndpointRoutePlan, FixedEndpointRouteRetirement,
        FixedRouteInstallError, FixedRouteOperationError, FixedRoutePlanError,
        FixedRouteVerifyError,
    },
    veth::{
        FixedVethEndpoint, FixedVethPair, VethCreateError, VethRollbackError, VethVerifyError,
        create_fixed_veth_pair,
    },
};

const CURRENT_NETWORK_NAMESPACE: &str = "/proc/thread-self/ns/net";
const PRIVATE_NETNS_PREFIX: &str = "/run/netns/";
const NSFS_MAGIC: FsWord = 0x6e73_6673;
const ENDPOINT_COUNT: usize = 2;
const RAW_LINK_RETIREMENT_PROOF_ATTEMPTS: usize = 2;

const NAMESPACE_STATX_FLAGS: StatxFlags = StatxFlags::TYPE
    .union(StatxFlags::INO)
    .union(StatxFlags::MNT_ID);

/// Failure to create, prove, join, or reverse the fixed live namespace-pin pair.
#[derive(Debug, Error)]
pub(crate) enum NamespacePinError {
    /// One fixed kernel or descriptor operation failed.
    #[error("namespace-pin operation {operation} failed: {source}")]
    Io {
        operation: &'static str,
        #[source]
        source: io::Error,
    },
    /// The private-run backing proof failed.
    #[error("namespace-pin private-run proof failed: {0}")]
    PrivateRun(#[source] AuthorizedPrivateRunError),
    /// A task, namespace, mount, join, or cleanup observation was ambiguous.
    #[error("namespace-pin proof failed: {0}")]
    Unsafe(&'static str),
}

/// Canonical endpoint order for the fixed live namespace pair.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum NamespaceEndpoint {
    /// Run-derived endpoint A.
    A,
    /// Run-derived endpoint B.
    B,
}

impl NamespaceEndpoint {
    const fn index(self) -> usize {
        match self {
            Self::A => 0,
            Self::B => 1,
        }
    }
}

const FORWARD_NAMESPACE_VISIT_ORDER: [NamespaceEndpoint; ENDPOINT_COUNT] =
    [NamespaceEndpoint::A, NamespaceEndpoint::B];
const REVERSE_NAMESPACE_VISIT_ORDER: [NamespaceEndpoint; ENDPOINT_COUNT] =
    [NamespaceEndpoint::B, NamespaceEndpoint::A];

/// Failure from either the namespace excursion boundary or its scoped visitor.
#[derive(Debug)]
pub(crate) enum NamespaceVisitError<VisitorError> {
    /// Entering, proving, or restoring a network namespace failed.
    Namespace(NamespacePinError),
    /// The supplied scoped operation failed after exact parent restoration.
    Visitor(VisitorError),
}

/// Failure to create, prove, or reverse the fixed two-veth transaction.
#[derive(Debug, Error)]
pub(crate) enum VethPairError {
    /// The retained namespace-pin owner or its restoration proof failed.
    #[error("fixed veth namespace binding failed: {0}")]
    Namespace(#[from] NamespacePinError),
    /// One atomic pair creation failed.
    #[error("fixed veth pair creation failed: {0}")]
    Create(#[source] VethCreateError),
    /// Fresh readback no longer matched one retained pair.
    #[error("fixed veth pair verification failed: {0}")]
    Verify(#[source] VethVerifyError),
    /// Reverse deletion encountered an anomaly after restoring absence.
    #[error("fixed veth pair rollback failed: {0}")]
    Rollback(#[source] VethRollbackError),
    /// The exact pair set or affine owner was incomplete.
    #[error("fixed veth pair proof failed: {0}")]
    Unsafe(&'static str),
}

/// Failure to install, prove, or reverse the fixed four-address transaction.
#[derive(Debug, Error)]
pub(crate) enum FixedIpv4AddressSetError {
    /// The retained veth-pair owner no longer proved its exact lineage.
    #[error("fixed IPv4 veth binding failed: {0}")]
    Veth(#[source] VethPairError),
    /// Entering or restoring one retained endpoint namespace failed.
    #[error("fixed IPv4 namespace binding failed: {0}")]
    Namespace(#[from] NamespacePinError),
    /// One exclusive address installation failed.
    #[error("fixed IPv4 address installation failed: {0}")]
    Add(#[source] Ipv4AddError),
    /// Fresh readback no longer matched one retained address.
    #[error("fixed IPv4 address verification failed: {0}")]
    Verify(#[source] Ipv4VerifyError),
    /// Reverse deletion required reconciliation after restoring absence.
    #[error("fixed IPv4 address rollback failed: {0}")]
    Rollback(#[source] Ipv4RollbackError),
    /// The exact address set or affine owner was incomplete.
    #[error("fixed IPv4 address-set proof failed: {0}")]
    Unsafe(&'static str),
}

/// Failure before or during the fixed link activation transaction.
#[derive(Debug, Error)]
pub(crate) enum FixedLinkActivationError {
    /// The original four-address authority failed its last preflight proof.
    #[error("fixed link activation address binding failed: {0}")]
    Addressed(#[source] FixedIpv4AddressSetError),
    /// One fixed link mutation or retained-state proof failed.
    #[error("fixed link activation failed: {0}")]
    Link(#[source] FixedLinkOperationError),
    /// Entering, proving, or restoring one retained endpoint namespace failed.
    #[error("fixed link activation namespace binding failed: {0}")]
    Namespace(#[from] NamespacePinError),
}

/// Failure to install or reprove the exact A/B endpoint-route set.
#[derive(Debug, Error)]
pub(crate) enum FixedEndpointRouteSetError {
    /// The activated topology failed its final preflight or postflight proof.
    #[error("fixed endpoint-route active-topology binding failed: {0}")]
    Activated(#[source] FixedLinkActivationError),
    /// Entering or restoring one retained endpoint namespace failed.
    #[error("fixed endpoint-route namespace binding failed: {0}")]
    Namespace(#[from] NamespacePinError),
    /// The retained active lineage could not derive the sole fixed route.
    #[error("fixed endpoint-route plan failed: {0}")]
    Plan(#[source] FixedRoutePlanError),
    /// Installation failed before any route request could reach the kernel.
    #[error("fixed endpoint-route installation failed before mutation: {0}")]
    InstallBeforeMutation(#[source] FixedRouteOperationError),
    /// An exclusive route request was rejected and freshly reconciled absent.
    #[error("fixed endpoint-route installation was rejected with errno {0}")]
    InstallRejected(i32),
    /// A route request crossed its deletion-only boundary.
    #[error("fixed endpoint-route installation crossed its deletion-only boundary: {0}")]
    InstallDeletionBound(#[source] FixedRouteOperationError),
    /// Fresh readback no longer matched one retained route owner.
    #[error("fixed endpoint-route verification failed: {0}")]
    Verify(#[source] FixedRouteVerifyError),
    /// The fixed route set, visit order, or affine owner set was incomplete.
    #[error("fixed endpoint-route set proof failed: {0}")]
    Unsafe(&'static str),
}

/// Affine failed route transition preserving deletion-bound cleanup authority.
#[must_use = "a failed endpoint-route transition retains mandatory cleanup authority"]
pub(crate) struct FixedEndpointRouteFailure {
    source: FixedEndpointRouteSetError,
    deleted: Box<AuthorizedDeletedTopology>,
}

impl std::fmt::Debug for FixedEndpointRouteFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FixedEndpointRouteFailure")
            .field("source", &self.source)
            .field("deleted", &true)
            .finish()
    }
}

impl std::fmt::Display for FixedEndpointRouteFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for FixedEndpointRouteFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl FixedEndpointRouteFailure {
    /// Recover the original failure and the still-armed deleted topology.
    pub(crate) fn into_parts(self) -> (FixedEndpointRouteSetError, AuthorizedDeletedTopology) {
        (self.source, *self.deleted)
    }

    fn deleted(source: FixedEndpointRouteSetError, deleted: AuthorizedDeletedTopology) -> Self {
        Self {
            source,
            deleted: Box::new(deleted),
        }
    }
}

/// Affine failed-transition result preserving any mandatory deleted topology.
///
/// `deleted == None` means the low-level journal proved that no SETLINK request
/// crossed the possibly-sent boundary, so ordinary lower-owner cleanup was
/// still safe and has already occurred. Otherwise the caller must run the full
/// pristine-network proof over the retained deleted topology before extracting
/// its source error and releasing namespace authority.
#[must_use = "a failed post-SETLINK transition retains mandatory cleanup authority"]
pub(crate) struct FixedLinkActivationFailure {
    source: FixedLinkActivationError,
    deleted: Option<Box<AuthorizedDeletedTopology>>,
}

/// Failure from a scoped parent or endpoint visit through a link typestate.
#[derive(Debug)]
pub(crate) enum FixedTopologyVisitError<VisitorError> {
    /// The retained link typestate failed its pre- or post-visit proof.
    Topology(FixedLinkActivationError),
    /// Entering or restoring a retained endpoint namespace failed.
    Namespace(NamespacePinError),
    /// The scoped caller operation failed after exact restoration.
    Visitor(VisitorError),
}

impl std::fmt::Debug for FixedLinkActivationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("FixedLinkActivationFailure")
            .field("source", &self.source)
            .field("deleted", &self.deleted.is_some())
            .finish()
    }
}

impl std::fmt::Display for FixedLinkActivationFailure {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.source.fmt(formatter)
    }
}

impl std::error::Error for FixedLinkActivationFailure {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        Some(&self.source)
    }
}

impl FixedLinkActivationFailure {
    /// Consume the affine failure into its source and optional deleted topology.
    pub(crate) fn into_parts(
        self,
    ) -> (FixedLinkActivationError, Option<AuthorizedDeletedTopology>) {
        (self.source, self.deleted.map(|deleted| *deleted))
    }

    fn untouched(source: FixedLinkActivationError) -> Self {
        Self {
            source,
            deleted: None,
        }
    }

    fn deleted(source: FixedLinkActivationError, deleted: AuthorizedDeletedTopology) -> Self {
        Self {
            source,
            deleted: Some(Box::new(deleted)),
        }
    }
}

impl NamespacePinError {
    fn rustix(operation: &'static str, source: Errno) -> Self {
        Self::Io {
            operation,
            source: io::Error::from_raw_os_error(source.raw_os_error()),
        }
    }

    fn nix(operation: &'static str, source: nix::errno::Errno) -> Self {
        Self::Io {
            operation,
            source: io::Error::from_raw_os_error(source as i32),
        }
    }

    fn io(operation: &'static str, source: io::Error) -> Self {
        Self::Io { operation, source }
    }
}

impl From<AuthorizedPrivateRunError> for NamespacePinError {
    fn from(source: AuthorizedPrivateRunError) -> Self {
        Self::PrivateRun(source)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ObjectIdentity {
    device: u64,
    inode: u64,
}

fn object_identity<Fd: AsFd>(descriptor: Fd) -> Result<ObjectIdentity, NamespacePinError> {
    let metadata = fstat(descriptor)
        .map_err(|source| NamespacePinError::rustix("measure namespace object", source))?;
    if metadata.st_dev == 0 || metadata.st_ino == 0 {
        return Err(NamespacePinError::Unsafe(
            "namespace object identity is zero",
        ));
    }
    Ok(ObjectIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

fn require_nsfs<Fd: AsFd>(descriptor: Fd) -> Result<(), NamespacePinError> {
    let observed = fstatfs(descriptor)
        .map_err(|source| NamespacePinError::rustix("identify nsfs object", source))?;
    if observed.f_type != NSFS_MAGIC {
        return Err(NamespacePinError::Unsafe(
            "namespace descriptor is not on nsfs",
        ));
    }
    Ok(())
}

fn mount_id<Fd: AsFd>(descriptor: Fd) -> Result<u64, NamespacePinError> {
    let observed = statx(
        descriptor,
        "",
        AtFlags::EMPTY_PATH | AtFlags::NO_AUTOMOUNT | AtFlags::SYMLINK_NOFOLLOW,
        NAMESPACE_STATX_FLAGS,
    )
    .map_err(|source| NamespacePinError::rustix("measure namespace mount", source))?;
    let mask = StatxFlags::from_bits_retain(observed.stx_mask);
    if !mask.contains(NAMESPACE_STATX_FLAGS) || observed.stx_ino == 0 || observed.stx_mnt_id == 0 {
        return Err(NamespacePinError::Unsafe(
            "namespace mount identity is incomplete",
        ));
    }
    Ok(observed.stx_mnt_id)
}

struct NetworkNamespace {
    descriptor: OwnedFd,
    identity: ObjectIdentity,
    owner: OwnedFd,
    owner_identity: ObjectIdentity,
}

impl NetworkNamespace {
    fn capture_current() -> Result<Self, NamespacePinError> {
        let descriptor = open(
            CURRENT_NETWORK_NAMESPACE,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK,
            Mode::empty(),
        )
        .map_err(|source| NamespacePinError::rustix("open current network namespace", source))?;
        Self::from_descriptor(descriptor)
    }

    fn from_descriptor(descriptor: OwnedFd) -> Result<Self, NamespacePinError> {
        if namespace_type(&descriptor)
            .map_err(|source| NamespacePinError::io("identify network namespace", source))?
            != libc::CLONE_NEWNET
        {
            return Err(NamespacePinError::Unsafe(
                "namespace descriptor is not a network namespace",
            ));
        }
        require_nsfs(&descriptor)?;
        let identity = object_identity(&descriptor)?;
        let owner = owning_user_namespace(&descriptor)
            .map_err(|source| NamespacePinError::io("open owning user namespace", source))?;
        require_nsfs(&owner)?;
        let owner_identity = object_identity(&owner)?;
        Ok(Self {
            descriptor,
            identity,
            owner,
            owner_identity,
        })
    }

    fn verify(&self) -> Result<(), NamespacePinError> {
        if namespace_type(&self.descriptor)
            .map_err(|source| NamespacePinError::io("reidentify network namespace", source))?
            != libc::CLONE_NEWNET
            || namespace_type(&self.owner).map_err(|source| {
                NamespacePinError::io("reidentify owning user namespace", source)
            })? != libc::CLONE_NEWUSER
        {
            return Err(NamespacePinError::Unsafe(
                "retained namespace types changed",
            ));
        }
        require_nsfs(&self.descriptor)?;
        require_nsfs(&self.owner)?;
        if object_identity(&self.descriptor)? != self.identity
            || object_identity(&self.owner)? != self.owner_identity
        {
            return Err(NamespacePinError::Unsafe(
                "retained namespace identity changed",
            ));
        }
        let observed_owner = owning_user_namespace(&self.descriptor)
            .map_err(|source| NamespacePinError::io("reopen owning user namespace", source))?;
        if object_identity(&observed_owner)? != self.owner_identity {
            return Err(NamespacePinError::Unsafe("network namespace owner changed"));
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct TaskIdentity {
    pid: i32,
    tid: Pid,
}

impl TaskIdentity {
    fn require_pid_one() -> Result<Self, NamespacePinError> {
        let identity = Self {
            pid: getpid().as_raw(),
            tid: gettid(),
        };
        if identity.pid != 1 || identity.tid.as_raw_pid() != 1 {
            return Err(NamespacePinError::Unsafe(
                "namespace pins require the fixed PID-1 task",
            ));
        }
        Ok(identity)
    }

    fn verify(self) -> Result<(), NamespacePinError> {
        if getpid().as_raw() != self.pid || gettid() != self.tid {
            return Err(NamespacePinError::Unsafe(
                "namespace-pin operation moved to another task",
            ));
        }
        Ok(())
    }
}

struct ParentRestoreGuard<'a> {
    parent: &'a NetworkNamespace,
    task: TaskIdentity,
    armed: bool,
}

impl<'a> ParentRestoreGuard<'a> {
    fn new(parent: &'a NetworkNamespace, task: TaskIdentity) -> Self {
        Self {
            parent,
            task,
            armed: false,
        }
    }

    fn mark_entered(&mut self) {
        self.armed = true;
    }

    fn restore(&mut self) -> Result<(), NamespacePinError> {
        if !self.armed {
            return Err(NamespacePinError::Unsafe(
                "parent namespace restoration was not armed",
            ));
        }
        self.task.verify()?;
        setns(&self.parent.descriptor, CloneFlags::CLONE_NEWNET)
            .map_err(|source| NamespacePinError::nix("restore parent network namespace", source))?;
        let current = NetworkNamespace::capture_current()?;
        if current.identity != self.parent.identity
            || current.owner_identity != self.parent.owner_identity
        {
            return Err(NamespacePinError::Unsafe(
                "setns did not restore the exact parent network namespace",
            ));
        }
        self.parent.verify()?;
        self.armed = false;
        Ok(())
    }
}

impl Drop for ParentRestoreGuard<'_> {
    fn drop(&mut self) {
        if self.armed && self.restore().is_err() {
            // Continuing the single PID-1 task in an unknown network namespace
            // could redirect every later proof and cleanup operation. There is
            // no safe unwind target after the exact parent restore fails.
            std::process::abort();
        }
    }
}

fn create_network_namespace(
    parent: &NetworkNamespace,
    task: TaskIdentity,
) -> Result<NetworkNamespace, NamespacePinError> {
    task.verify()?;
    require_current_namespace(parent)?;
    let mut restore = ParentRestoreGuard::new(parent, task);
    unshare(CloneFlags::CLONE_NEWNET)
        .map_err(|source| NamespacePinError::nix("create network namespace", source))?;
    restore.mark_entered();
    let captured = NetworkNamespace::capture_current();
    let restored = restore.restore();
    match (captured, restored) {
        (_, Err(_)) => Err(NamespacePinError::Unsafe(
            "network namespace capture did not prove parent restoration",
        )),
        (Err(error), Ok(())) => Err(error),
        (Ok(namespace), Ok(())) => {
            if namespace.identity == parent.identity
                || namespace.owner_identity != parent.owner_identity
            {
                return Err(NamespacePinError::Unsafe(
                    "new network namespace identity or owner is not exact",
                ));
            }
            namespace.verify()?;
            Ok(namespace)
        }
    }
}

fn require_current_namespace(expected: &NetworkNamespace) -> Result<(), NamespacePinError> {
    let current = NetworkNamespace::capture_current()?;
    if current.identity != expected.identity || current.owner_identity != expected.owner_identity {
        return Err(NamespacePinError::Unsafe(
            "current task is not in the expected network namespace",
        ));
    }
    Ok(())
}

fn join_and_restore(
    endpoint: &NetworkNamespace,
    visible_pin: &OwnedFd,
    parent: &NetworkNamespace,
    task: TaskIdentity,
) -> Result<(), NamespacePinError> {
    task.verify()?;
    require_current_namespace(parent)?;
    let mut restore = ParentRestoreGuard::new(parent, task);
    setns(visible_pin, CloneFlags::CLONE_NEWNET)
        .map_err(|source| NamespacePinError::nix("join retained network namespace", source))?;
    restore.mark_entered();
    let joined = require_current_namespace(endpoint);
    let restored = restore.restore();
    match (joined, restored) {
        (_, Err(_)) => Err(NamespacePinError::Unsafe(
            "namespace join did not prove parent restoration",
        )),
        (Err(error), Ok(())) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn clone_file(descriptor: &File, operation: &'static str) -> Result<File, NamespacePinError> {
    descriptor
        .try_clone()
        .map_err(|source| NamespacePinError::io(operation, source))
}

fn open_visible_namespace(parent: &File, name: &str) -> Result<OwnedFd, NamespacePinError> {
    openat2(
        parent,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NONBLOCK | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|source| NamespacePinError::rustix("open visible namespace pin", source))
}

fn cleanup_path(parent: &File, name: &str) -> String {
    format!("/proc/thread-self/fd/{}/{name}", parent.as_raw_fd())
}

fn canonical_mount_point(name: &str) -> Result<String, NamespacePinError> {
    if name.is_empty()
        || name == "."
        || name == ".."
        || !name.is_ascii()
        || name.as_bytes().contains(&b'/')
        || name.as_bytes().contains(&0)
    {
        return Err(NamespacePinError::Unsafe(
            "namespace mount leaf is not canonical",
        ));
    }
    Ok(format!("{PRIVATE_NETNS_PREFIX}{name}"))
}

struct MountedEndpoint {
    namespace: NetworkNamespace,
    parent: File,
    hidden_slot: File,
    hidden_identity: ObjectIdentity,
    hidden_mount_id: u64,
    name: String,
    mount_point: String,
    mount_id: u64,
}

impl MountedEndpoint {
    fn verify(&self) -> Result<(), NamespacePinError> {
        self.namespace.verify()?;
        if object_identity(&self.hidden_slot)? != self.hidden_identity
            || mount_id(&self.hidden_slot)? != self.hidden_mount_id
        {
            return Err(NamespacePinError::Unsafe(
                "hidden namespace-slot identity changed",
            ));
        }
        let visible = self.open_verified_visible()?;
        if self.mount_point != canonical_mount_point(&self.name)? {
            return Err(NamespacePinError::Unsafe(
                "visible namespace mount point is not exact",
            ));
        }
        drop(visible);
        Ok(())
    }

    fn open_verified_visible(&self) -> Result<OwnedFd, NamespacePinError> {
        let visible = open_visible_namespace(&self.parent, &self.name)?;
        verify_visible_binding(
            &self.namespace,
            &visible,
            self.hidden_mount_id,
            self.mount_id,
        )?;
        Ok(visible)
    }

    fn verify_unmounted(&self) -> Result<(), NamespacePinError> {
        verify_hidden_visible(
            &self.parent,
            &self.name,
            &self.hidden_slot,
            self.hidden_identity,
            self.hidden_mount_id,
        )
    }

    fn unmount(self) -> Result<(), UnmountFailure> {
        if let Err(error) = self.verify() {
            return Err(UnmountFailure {
                error,
                unmounted: false,
                endpoint: Some(Box::new(self)),
            });
        }
        let result = unmount(
            cleanup_path(&self.parent, &self.name),
            UnmountFlags::NOFOLLOW,
        );
        if let Err(source) = result {
            return Err(UnmountFailure {
                error: NamespacePinError::rustix("unmount visible namespace pin", source),
                unmounted: false,
                endpoint: Some(Box::new(self)),
            });
        }
        self.verify_unmounted().map_err(|error| UnmountFailure {
            error,
            unmounted: true,
            endpoint: None,
        })
    }
}

struct UnmountFailure {
    error: NamespacePinError,
    unmounted: bool,
    endpoint: Option<Box<MountedEndpoint>>,
}

struct ProvisionalMountGuard {
    namespace: Option<NetworkNamespace>,
    mount_descriptor: Option<OwnedFd>,
    parent: Option<File>,
    hidden_slot: Option<File>,
    hidden_identity: ObjectIdentity,
    hidden_mount_id: u64,
    name: String,
    mount_point: String,
    mount_id: Option<u64>,
    armed: bool,
}

impl ProvisionalMountGuard {
    fn mark_attached(&mut self) {
        self.armed = true;
    }

    fn finalize(&mut self) -> Result<(), NamespacePinError> {
        if !self.armed || self.mount_id.is_some() {
            return Err(NamespacePinError::Unsafe(
                "namespace mount guard cannot be finalized",
            ));
        }
        let parent = self.parent.as_ref().ok_or(NamespacePinError::Unsafe(
            "namespace mount guard lost its parent",
        ))?;
        let namespace = self.namespace.as_ref().ok_or(NamespacePinError::Unsafe(
            "namespace mount guard lost its source namespace",
        ))?;
        let mount_descriptor = self
            .mount_descriptor
            .as_ref()
            .ok_or(NamespacePinError::Unsafe(
                "namespace mount guard lost its detached mount",
            ))?;
        let visible = open_visible_namespace(parent, &self.name)?;
        let visible_mount_id = mount_id(&visible)?;
        verify_mount_descriptor_binding(
            namespace,
            mount_descriptor,
            self.hidden_mount_id,
            visible_mount_id,
        )?;
        verify_visible_binding(namespace, &visible, self.hidden_mount_id, visible_mount_id)?;
        self.mount_id = Some(visible_mount_id);
        Ok(())
    }

    fn rollback(&mut self) -> Result<(), NamespacePinError> {
        if !self.armed {
            return Ok(());
        }
        let namespace = self.namespace.as_ref().ok_or(NamespacePinError::Unsafe(
            "provisional cleanup lost its source namespace",
        ))?;
        let parent = self.parent.as_ref().ok_or(NamespacePinError::Unsafe(
            "provisional cleanup lost its slot parent",
        ))?;
        let visible = open_visible_namespace(parent, &self.name)?;
        let visible_mount_id = mount_id(&visible)?;
        verify_visible_binding(namespace, &visible, self.hidden_mount_id, visible_mount_id)?;
        if let Some(expected) = self.mount_id {
            if expected != visible_mount_id {
                return Err(NamespacePinError::Unsafe(
                    "provisional namespace mount identity changed",
                ));
            }
        }
        drop(visible);
        drop(self.mount_descriptor.take());
        unmount(cleanup_path(parent, &self.name), UnmountFlags::NOFOLLOW).map_err(|source| {
            NamespacePinError::rustix("roll back provisional namespace mount", source)
        })?;
        verify_hidden_visible(
            parent,
            &self.name,
            self.hidden_slot.as_ref().ok_or(NamespacePinError::Unsafe(
                "provisional cleanup lost its hidden slot",
            ))?,
            self.hidden_identity,
            self.hidden_mount_id,
        )?;
        self.armed = false;
        Ok(())
    }

    fn into_endpoint(mut self) -> MountedEndpoint {
        if !self.armed || self.mount_id.is_none() {
            std::process::abort();
        }
        let mount_id = self.mount_id.unwrap_or_else(|| std::process::abort());
        // Neither an attached-clone descriptor nor a descriptor opened through
        // the visible mount may survive into ordinary teardown.
        drop(self.mount_descriptor.take());
        let endpoint = MountedEndpoint {
            namespace: self
                .namespace
                .take()
                .unwrap_or_else(|| std::process::abort()),
            parent: self.parent.take().unwrap_or_else(|| std::process::abort()),
            hidden_slot: self
                .hidden_slot
                .take()
                .unwrap_or_else(|| std::process::abort()),
            hidden_identity: self.hidden_identity,
            hidden_mount_id: self.hidden_mount_id,
            name: std::mem::take(&mut self.name),
            mount_point: std::mem::take(&mut self.mount_point),
            mount_id,
        };
        self.armed = false;
        endpoint
    }
}

impl Drop for ProvisionalMountGuard {
    fn drop(&mut self) {
        if self.armed && self.rollback().is_err() {
            std::process::abort();
        }
    }
}

fn verify_visible_binding<Fd: AsFd>(
    namespace: &NetworkNamespace,
    visible: Fd,
    hidden_mount_id: u64,
    expected_mount_id: u64,
) -> Result<(), NamespacePinError> {
    require_nsfs(&visible)?;
    if object_identity(&visible)? != namespace.identity
        || mount_id(&visible)? != expected_mount_id
        || expected_mount_id == hidden_mount_id
        || namespace_type(&visible)
            .map_err(|source| NamespacePinError::io("identify visible namespace", source))?
            != libc::CLONE_NEWNET
    {
        return Err(NamespacePinError::Unsafe(
            "visible nsfs pin identity is not exact",
        ));
    }
    let owner = owning_user_namespace(&visible)
        .map_err(|source| NamespacePinError::io("open visible namespace owner", source))?;
    if object_identity(&owner)? != namespace.owner_identity {
        return Err(NamespacePinError::Unsafe(
            "visible namespace owner is not exact",
        ));
    }
    Ok(())
}

fn verify_mount_descriptor_binding<Fd: AsFd>(
    namespace: &NetworkNamespace,
    mount_descriptor: Fd,
    hidden_mount_id: u64,
    expected_mount_id: u64,
) -> Result<(), NamespacePinError> {
    // `open_tree(2)` returns an O_PATH mount descriptor. Its stat and
    // filesystem observations are valid, but namespace ioctls are not; type
    // and owner ioctls are proved separately on the O_RDONLY visible view.
    require_nsfs(&mount_descriptor)?;
    if object_identity(&mount_descriptor)? != namespace.identity
        || mount_id(&mount_descriptor)? != expected_mount_id
        || expected_mount_id == hidden_mount_id
    {
        return Err(NamespacePinError::Unsafe(
            "attached nsfs mount-descriptor identity is not exact",
        ));
    }
    Ok(())
}

fn verify_hidden_visible(
    parent: &File,
    name: &str,
    hidden_slot: &File,
    hidden_identity: ObjectIdentity,
    hidden_mount_id: u64,
) -> Result<(), NamespacePinError> {
    let visible_hidden = openat2(
        parent,
        name,
        OFlags::PATH | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(|source| NamespacePinError::rustix("reopen unmounted hidden slot", source))?;
    if object_identity(hidden_slot)? != hidden_identity
        || mount_id(hidden_slot)? != hidden_mount_id
        || object_identity(&visible_hidden)? != hidden_identity
        || mount_id(&visible_hidden)? != hidden_mount_id
    {
        return Err(NamespacePinError::Unsafe(
            "ordinary unmount did not reveal the exact hidden slot",
        ));
    }
    Ok(())
}

fn attach_namespace(
    target: NamespacePinTarget<'_>,
    namespace: NetworkNamespace,
) -> Result<MountedEndpoint, NamespacePinError> {
    let parent = clone_file(target.parent, "retain namespace-slot parent")?;
    let hidden_slot = clone_file(target.hidden_slot, "retain hidden namespace slot")?;
    let hidden_identity = object_identity(&hidden_slot)?;
    let hidden_mount_id = mount_id(&hidden_slot)?;
    let name = target.name.to_owned();
    let mount_point = canonical_mount_point(&name)?;
    let mount_descriptor = open_tree(
        &namespace.descriptor,
        "",
        OpenTreeFlags::OPEN_TREE_CLONE
            | OpenTreeFlags::OPEN_TREE_CLOEXEC
            | OpenTreeFlags::AT_EMPTY_PATH,
    )
    .map_err(|source| NamespacePinError::rustix("clone detached nsfs mount", source))?;

    // The guard is fully populated before the only attaching operation. The immediate
    // infallible arm closes the success-to-cleanup window if any later proof fails.
    let mut guard = ProvisionalMountGuard {
        namespace: Some(namespace),
        mount_descriptor: Some(mount_descriptor),
        parent: Some(parent),
        hidden_slot: Some(hidden_slot),
        hidden_identity,
        hidden_mount_id,
        name,
        mount_point,
        mount_id: None,
        armed: false,
    };
    let mount_descriptor = guard
        .mount_descriptor
        .as_ref()
        .ok_or(NamespacePinError::Unsafe(
            "provisional namespace mount disappeared",
        ))?;
    let hidden_slot = guard.hidden_slot.as_ref().ok_or(NamespacePinError::Unsafe(
        "provisional namespace slot disappeared",
    ))?;
    move_mount(
        mount_descriptor,
        "",
        hidden_slot,
        "",
        MoveMountFlags::MOVE_MOUNT_F_EMPTY_PATH | MoveMountFlags::MOVE_MOUNT_T_EMPTY_PATH,
    )
    .map_err(|source| NamespacePinError::rustix("attach nsfs mount to retained slot", source))?;
    guard.mark_attached();
    if let Err(error) = guard.finalize() {
        if guard.rollback().is_err() {
            return Err(NamespacePinError::Unsafe(
                "namespace mount finalization and cleanup both failed",
            ));
        }
        return Err(error);
    }
    Ok(guard.into_endpoint())
}

struct MountJournal {
    entries: Vec<MountedEndpoint>,
    armed: bool,
    _thread_bound: PhantomData<Rc<()>>,
}

impl MountJournal {
    fn new() -> Self {
        Self {
            entries: Vec::with_capacity(ENDPOINT_COUNT),
            armed: true,
            _thread_bound: PhantomData,
        }
    }

    fn push(&mut self, endpoint: MountedEndpoint) -> Result<(), NamespacePinError> {
        if self.entries.len() == ENDPOINT_COUNT {
            self.entries.push(endpoint);
            if self.rollback().is_err() {
                return Err(NamespacePinError::Unsafe(
                    "full namespace mount journal could not be cleaned",
                ));
            }
            return Err(NamespacePinError::Unsafe(
                "namespace mount rollback journal is full",
            ));
        }
        self.entries.push(endpoint);
        Ok(())
    }

    fn rollback(&mut self) -> Result<(), NamespacePinError> {
        let mut proof_error = None;
        while let Some(endpoint) = self.entries.pop() {
            match endpoint.unmount() {
                Ok(()) => {}
                Err(failure) if failure.unmounted => {
                    proof_error.get_or_insert(failure.error);
                }
                Err(mut failure) => {
                    if let Some(endpoint) = failure.endpoint.take() {
                        self.entries.push(*endpoint);
                    }
                    return Err(failure.error);
                }
            }
        }
        self.armed = false;
        proof_error.map_or(Ok(()), Err)
    }
}

impl Drop for MountJournal {
    fn drop(&mut self) {
        if self.armed && self.rollback().is_err() {
            std::process::abort();
        }
    }
}

struct VethPairJournal {
    entries: Vec<FixedVethPair>,
    armed: bool,
}

impl VethPairJournal {
    fn new() -> Self {
        Self {
            entries: Vec::with_capacity(ENDPOINT_COUNT),
            armed: true,
        }
    }

    fn push(&mut self, pair: FixedVethPair) -> Result<(), VethPairError> {
        let expected = match self.entries.len() {
            0 => FixedVethEndpoint::A,
            1 => FixedVethEndpoint::B,
            _ => {
                return Err(VethPairError::Unsafe(
                    "fixed veth journal exceeded two pairs",
                ));
            }
        };
        if pair.endpoint() != expected {
            return Err(VethPairError::Unsafe(
                "fixed veth journal order is not A then B",
            ));
        }
        self.entries.push(pair);
        Ok(())
    }

    fn verify(&self) -> Result<(), VethPairError> {
        if !self.armed || self.entries.len() != ENDPOINT_COUNT {
            return Err(VethPairError::Unsafe(
                "fixed veth journal is not exactly armed with two pairs",
            ));
        }
        let first = &self.entries[0];
        let second = &self.entries[1];
        if first.endpoint() != FixedVethEndpoint::A
            || second.endpoint() != FixedVethEndpoint::B
            || first.parent_name() == second.parent_name()
            || first.parent_ifindex() == second.parent_ifindex()
            || first.peer_name() != "eth0"
            || second.peer_name() != "eth0"
        {
            return Err(VethPairError::Unsafe(
                "fixed veth pair identities are incomplete or ambiguous",
            ));
        }
        first.verify().map_err(VethPairError::Verify)?;
        second.verify().map_err(VethPairError::Verify)
    }

    fn rollback(&mut self) -> Result<(), VethPairError> {
        let mut first_error = None;
        while let Some(pair) = self.entries.pop() {
            if let Err(error) = pair.rollback() {
                first_error.get_or_insert(VethPairError::Rollback(error));
            }
        }
        self.armed = false;
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for VethPairJournal {
    fn drop(&mut self) {
        if self.armed {
            while let Some(pair) = self.entries.pop() {
                drop(pair);
            }
            self.armed = false;
        }
    }
}

/// Affine owner of exactly two live run-bound nsfs network-namespace pins.
///
/// The state retains both the lower empty-slot view and the visible nsfs view.
/// It can be consumed only into the fixed two-down-veth transaction; it owns no
/// configured address, route, firewall, ownership-manifest, or topology-ready authority.
/// Path-based ordinary unmount remains scoped to the disposable runner's fixed
/// one-task PID 1 and trusted launcher; this is not a race-free cleanup claim
/// against a hostile mapped-same-UID process holding a writable private-run fd.
pub(crate) struct AuthorizedNamespacePins {
    // Mounts precede their private-run backing so implicit field teardown
    // preserves the required B/A-unmount-before-slot-unlink order.
    mounts: MountJournal,
    private_run: Option<AuthorizedPrivateRun>,
    parent: NetworkNamespace,
    task: TaskIdentity,
    _thread_bound: PhantomData<Rc<()>>,
}

/// Affine owner of exactly two fixed down veth pairs and their live namespace pins.
///
/// The veth journal is declared before the namespace owner so implicit unwind
/// deletes B then A before either target namespace can be unmounted. The state
/// can be consumed only into the fixed four-address sub-transaction; it grants no
/// link-up, explicit-route, forwarding, firewall, probe, dataplane,
/// ownership-manifest, or topology-ready authority.
pub(crate) struct AuthorizedVethPairs {
    veths: VethPairJournal,
    namespace_pins: Option<AuthorizedNamespacePins>,
    _thread_bound: PhantomData<Rc<()>>,
}

struct FixedIpv4AddressJournal {
    parent: [Option<FixedIpv4AddressOwner>; ENDPOINT_COUNT],
    endpoints: [Option<FixedIpv4AddressOwner>; ENDPOINT_COUNT],
    armed: bool,
}

/// Affine authority for all four fixed IPv4 addresses and their veth backing.
///
/// The state owns the veth-pair authority so the links and namespace pins
/// cannot be consumed separately while any address remains live. Dropping it
/// performs exact reverse address cleanup inside B, A and then the parent
/// namespace before the veth backing can unwind. It grants no link-up,
/// explicit-route, forwarding, firewall, packet, or readiness authority.
#[must_use = "dropping an armed fixed IPv4 address set triggers fail-closed rollback"]
pub(crate) struct AuthorizedIpv4Addresses {
    // The address journal precedes its backing owner so custom teardown can
    // disarm every address before ordinary field teardown reaches the veths.
    journal: FixedIpv4AddressJournal,
    veth_pairs: Option<AuthorizedVethPairs>,
    _thread_bound: PhantomData<Rc<()>>,
}

/// Affine authority after all four addressed links passed the all-NONE barrier.
///
/// The original addressed owner remains whole inside an `Option`; neither it
/// nor either lower Drop type is ever destructured. Any transition after this
/// point is deletion-only and cannot restore EUI64 or invoke ordinary address
/// or veth rollback.
#[must_use = "the all-NONE topology owns deletion-only retirement authority"]
pub(crate) struct AuthorizedIpv4AddrgenNone {
    addressed: Option<AuthorizedIpv4Addresses>,
    links: Option<AllLinksAddrgenNone>,
    _thread_bound: PhantomData<Rc<()>>,
}

/// Affine authority for exactly four addressed, addrgen-NONE, active veth ends.
#[must_use = "the activated topology must begin deletion-only retirement"]
pub(crate) struct AuthorizedActivatedTopology {
    addressed: Option<AuthorizedIpv4Addresses>,
    links: Option<AllLinksUp>,
    _thread_bound: PhantomData<Rc<()>>,
}

/// Affine authority for both exact endpoint routes over the activated links.
///
/// Route A and then route B were derived solely from retained link, pair,
/// address, and namespace lineage and freshly read back. There is no route
/// deletion API: this state can proceed only to direct B/A pair deletion and
/// full pristine-network retirement.
#[must_use = "the routed topology must begin deletion-only retirement"]
pub(crate) struct AuthorizedEndpointRoutes {
    activated: Option<AuthorizedActivatedTopology>,
    routes: [Option<FixedEndpointRouteOwner>; ENDPOINT_COUNT],
    _thread_bound: PhantomData<Rc<()>>,
}

/// Intermediate authority after direct B/A pair deletion and raw lineage proof.
///
/// Zero, one, or two route-retirement owners, all four address owners, and both
/// pair owners remain armed. Only the higher private-mount owner can compare
/// its retained parent and endpoint baselines; it must do so before calling
/// `finish_after_pristine_network_proof`.
#[must_use = "deleted topology still requires the full pristine-network barrier"]
pub(crate) struct AuthorizedDeletedTopology {
    addressed: Option<AuthorizedIpv4Addresses>,
    absence: Option<FixedPairAbsenceProof>,
    route_retirements: [Option<FixedEndpointRouteRetirement>; ENDPOINT_COUNT],
    _thread_bound: PhantomData<Rc<()>>,
}

/// One retained pair identity that remains readable after its link disappeared.
#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct DeletedVethPairIdentity {
    endpoint: NamespaceEndpoint,
    parent_name: String,
    parent_ifindex: u32,
    peer_ifindex: u32,
    target_namespace_device: u64,
    target_namespace_inode: u64,
}

impl DeletedVethPairIdentity {
    pub(crate) const fn endpoint(&self) -> NamespaceEndpoint {
        self.endpoint
    }

    pub(crate) fn parent_name(&self) -> &str {
        &self.parent_name
    }

    pub(crate) const fn parent_ifindex(&self) -> u32 {
        self.parent_ifindex
    }

    pub(crate) const fn peer_ifindex(&self) -> u32 {
        self.peer_ifindex
    }

    pub(crate) const fn target_namespace_device(&self) -> u64 {
        self.target_namespace_device
    }

    pub(crate) const fn target_namespace_inode(&self) -> u64 {
        self.target_namespace_inode
    }
}

/// Private guard spanning the first possibly-sent SETLINK and all-NONE proof.
struct ProvisionalLinkActivation {
    addressed: Option<AuthorizedIpv4Addresses>,
    links: Option<FixedLinkMutationJournal>,
    _thread_bound: PhantomData<Rc<()>>,
}

impl AuthorizedPrivateRun {
    /// Consume the empty-slot state and attach exactly two distinct live network namespaces.
    pub(crate) fn pin_network_namespaces(
        self,
    ) -> Result<AuthorizedNamespacePins, NamespacePinError> {
        self.verify()?;
        let task = TaskIdentity::require_pid_one()?;
        let parent = NetworkNamespace::capture_current()?;
        parent.verify()?;
        require_current_namespace(&parent)?;
        let targets = self.namespace_pin_targets();
        let mut mounts = MountJournal::new();

        let staged = (|| {
            for target in targets {
                let namespace = create_network_namespace(&parent, task)?;
                let endpoint = attach_namespace(target, namespace)?;
                mounts.push(endpoint)?;
            }
            Ok(())
        })();
        if let Err(error) = staged {
            if mounts.rollback().is_err() || self.verify().is_err() {
                return Err(NamespacePinError::Unsafe(
                    "namespace-pin staging and cleanup both failed",
                ));
            }
            return Err(error);
        }

        let mut state = AuthorizedNamespacePins {
            private_run: Some(self),
            parent,
            task,
            mounts,
            _thread_bound: PhantomData,
        };
        if let Err(error) = state.verify() {
            if state.mounts.rollback().is_err()
                || state
                    .private_run
                    .as_ref()
                    .is_none_or(|private_run| private_run.verify().is_err())
            {
                return Err(NamespacePinError::Unsafe(
                    "namespace-pin final proof and cleanup both failed",
                ));
            }
            return Err(error);
        }
        Ok(state)
    }
}

impl AuthorizedNamespacePins {
    /// Reprove task affinity, hidden/visible dual views, exact mounts, ownership, and joins.
    pub(crate) fn verify(&self) -> Result<(), NamespacePinError> {
        self.task.verify()?;
        let private_run = self.private_run.as_ref().ok_or(NamespacePinError::Unsafe(
            "authorized private-run owner was consumed",
        ))?;
        private_run.verify_namespace_pin_backing()?;
        self.parent.verify()?;
        require_current_namespace(&self.parent)?;
        if self.mounts.entries.len() != ENDPOINT_COUNT {
            return Err(NamespacePinError::Unsafe(
                "namespace mount pair is incomplete",
            ));
        }
        let targets = private_run.namespace_pin_targets();
        for (endpoint, target) in self.mounts.entries.iter().zip(targets) {
            if endpoint.name != target.name
                || object_identity(&endpoint.parent)? != object_identity(target.parent)?
                || object_identity(&endpoint.hidden_slot)? != object_identity(target.hidden_slot)?
            {
                return Err(NamespacePinError::Unsafe(
                    "namespace mount escaped its run-bound slot",
                ));
            }
            endpoint.verify()?;
        }
        let alpha = &self.mounts.entries[0];
        let omega = &self.mounts.entries[1];
        require_distinct_pair(
            self.parent.identity,
            alpha.namespace.identity,
            omega.namespace.identity,
            alpha.mount_id,
            omega.mount_id,
        )?;
        let alpha_visible = alpha.open_verified_visible()?;
        join_and_restore(&alpha.namespace, &alpha_visible, &self.parent, self.task)?;
        drop(alpha_visible);
        let omega_visible = omega.open_verified_visible()?;
        join_and_restore(&omega.namespace, &omega_visible, &self.parent, self.task)?;
        drop(omega_visible);
        require_current_namespace(&self.parent)
    }

    /// Return the exact visible mount IDs in canonical A, B order.
    pub(crate) fn mount_ids(&self) -> [u64; ENDPOINT_COUNT] {
        [
            self.mounts.entries[0].mount_id,
            self.mounts.entries[1].mount_id,
        ]
    }

    /// Return the exact canonical mount-point bytes in A, B order.
    pub(crate) fn mount_point_bytes(&self) -> [&[u8]; ENDPOINT_COUNT] {
        [
            self.mounts.entries[0].mount_point.as_bytes(),
            self.mounts.entries[1].mount_point.as_bytes(),
        ]
    }

    /// Consume the pristine two-pin owner and atomically create A then B.
    pub(crate) fn create_fixed_veth_pairs(self) -> Result<AuthorizedVethPairs, VethPairError> {
        self.verify()?;
        let run_id = self
            .private_run
            .as_ref()
            .ok_or(VethPairError::Unsafe(
                "authorized private-run owner was consumed before veth creation",
            ))?
            .verified_run_id()
            .map_err(NamespacePinError::from)?
            .clone();
        let mut veths = VethPairJournal::new();
        for (index, endpoint) in [FixedVethEndpoint::A, FixedVethEndpoint::B]
            .into_iter()
            .enumerate()
        {
            let target = &self.mounts.entries[index].namespace.descriptor;
            let pair = match create_fixed_veth_pair(&run_id, endpoint, target) {
                Ok(pair) => pair,
                Err(source) => {
                    let cleanup = veths.rollback();
                    let backing = self.verify().map_err(VethPairError::Namespace);
                    return match (cleanup, backing) {
                        (Err(error), _) | (Ok(()), Err(error)) => Err(error),
                        (Ok(()), Ok(())) => Err(VethPairError::Create(source)),
                    };
                }
            };
            veths.push(pair)?;
        }
        let state = AuthorizedVethPairs {
            veths,
            namespace_pins: Some(self),
            _thread_bound: PhantomData,
        };
        state.verify()?;
        Ok(state)
    }

    /// Visit A then B synchronously and restore the exact parent before every return.
    ///
    /// The visitor receives no namespace descriptor or retained capability. A
    /// scoped caller may perform its own fixed operation in the current
    /// namespace. Restoration failure takes precedence over a simultaneous
    /// visitor error; unwind also restores the parent or aborts the disposable
    /// PID-1 process.
    pub(crate) fn visit_network_namespaces<Visitor, VisitorError>(
        &self,
        visitor: Visitor,
    ) -> Result<(), NamespaceVisitError<VisitorError>>
    where
        Visitor: FnMut(NamespaceEndpoint) -> Result<(), VisitorError>,
    {
        self.visit_network_namespaces_in_order(FORWARD_NAMESPACE_VISIT_ORDER, visitor)
    }

    /// Visit B then A synchronously for exact reverse-order rollback.
    pub(crate) fn visit_network_namespaces_reverse<Visitor, VisitorError>(
        &self,
        visitor: Visitor,
    ) -> Result<(), NamespaceVisitError<VisitorError>>
    where
        Visitor: FnMut(NamespaceEndpoint) -> Result<(), VisitorError>,
    {
        self.visit_network_namespaces_in_order(REVERSE_NAMESPACE_VISIT_ORDER, visitor)
    }

    /// Exercise the real B/A path, force one visitor error, and prove parent restoration.
    pub(crate) fn prove_reverse_visit_restoration_after_visitor_error(
        &self,
    ) -> Result<(), NamespacePinError> {
        self.verify()?;
        let mut observed = [None, None];
        let mut count = 0_usize;
        let result = self.visit_network_namespaces_reverse(|endpoint| {
            if count >= ENDPOINT_COUNT {
                return Err(());
            }
            observed[count] = Some(endpoint);
            count += 1;
            if endpoint == NamespaceEndpoint::A {
                Err(())
            } else {
                Ok(())
            }
        });
        match result {
            Err(NamespaceVisitError::Visitor(()))
                if observed == [Some(NamespaceEndpoint::B), Some(NamespaceEndpoint::A)]
                    && count == ENDPOINT_COUNT => {}
            Err(NamespaceVisitError::Namespace(source)) => return Err(source),
            _ => {
                return Err(NamespacePinError::Unsafe(
                    "reverse namespace visitor-error restoration proof was not exact",
                ));
            }
        }
        require_current_namespace(&self.parent)?;
        self.verify()
    }

    fn visit_network_namespaces_in_order<Visitor, VisitorError>(
        &self,
        order: [NamespaceEndpoint; ENDPOINT_COUNT],
        mut visitor: Visitor,
    ) -> Result<(), NamespaceVisitError<VisitorError>>
    where
        Visitor: FnMut(NamespaceEndpoint) -> Result<(), VisitorError>,
    {
        self.verify().map_err(NamespaceVisitError::Namespace)?;
        for label in order {
            let index = match label {
                NamespaceEndpoint::A => 0,
                NamespaceEndpoint::B => 1,
            };
            let endpoint = &self.mounts.entries[index];
            self.task.verify().map_err(NamespaceVisitError::Namespace)?;
            require_current_namespace(&self.parent).map_err(NamespaceVisitError::Namespace)?;
            let visible = endpoint
                .open_verified_visible()
                .map_err(NamespaceVisitError::Namespace)?;
            let mut restore = ParentRestoreGuard::new(&self.parent, self.task);
            setns(&visible, CloneFlags::CLONE_NEWNET).map_err(|source| {
                NamespaceVisitError::Namespace(NamespacePinError::nix(
                    "visit retained network namespace",
                    source,
                ))
            })?;
            restore.mark_entered();
            let entered = require_current_namespace(&endpoint.namespace);
            let visited = if entered.is_ok() {
                Some(visitor(label))
            } else {
                None
            };
            let restored = restore.restore();
            drop(visible);
            if restored.is_err() {
                return Err(NamespaceVisitError::Namespace(NamespacePinError::Unsafe(
                    "namespace visit did not prove parent restoration",
                )));
            }
            if let Err(error) = entered {
                return Err(NamespaceVisitError::Namespace(error));
            }
            self.verify().map_err(NamespaceVisitError::Namespace)?;
            if let Some(Err(error)) = visited {
                return Err(NamespaceVisitError::Visitor(error));
            }
        }
        self.verify().map_err(NamespaceVisitError::Namespace)
    }

    /// Consume both pins, ordinarily unmount B then A, and recover the empty-slot state.
    pub(crate) fn rollback(mut self) -> Result<AuthorizedPrivateRun, NamespacePinError> {
        self.verify()?;
        let cleanup = self.mounts.rollback();
        let private_run = take_backing_after_cleanup(cleanup, &mut self.private_run, || {
            NamespacePinError::Unsafe("authorized private-run owner was already consumed")
        })?;
        let backing = private_run.verify();
        match backing {
            Ok(()) => Ok(private_run),
            Err(error) => Err(error.into()),
        }
    }
}

fn take_backing_after_cleanup<Backing, Error, Missing>(
    cleanup: Result<(), Error>,
    backing: &mut Option<Backing>,
    missing: Missing,
) -> Result<Backing, Error>
where
    Missing: FnOnce() -> Error,
{
    cleanup?;
    backing.take().ok_or_else(missing)
}

impl AuthorizedVethPairs {
    /// Reprove both pair identities and their unchanged live namespace backing.
    pub(crate) fn verify(&self) -> Result<(), VethPairError> {
        let namespace_pins = self.namespace_pins();
        namespace_pins.verify().map_err(VethPairError::Namespace)?;
        self.veths.verify()?;
        let pairs = self.fixed_pairs();
        for (pair, endpoint) in pairs.iter().zip(&namespace_pins.mounts.entries) {
            pair.verify_target_namespace_descriptor(&endpoint.namespace.descriptor)
                .map_err(VethPairError::Verify)?;
            let target = pair.target_namespace_identity();
            if target.device() != endpoint.namespace.identity.device
                || target.inode() != endpoint.namespace.identity.inode
            {
                return Err(VethPairError::Unsafe(
                    "fixed veth target escaped its retained endpoint namespace",
                ));
            }
        }
        namespace_pins.verify().map_err(VethPairError::Namespace)
    }

    /// Borrow the fixed pair owners in canonical A, B order.
    pub(crate) fn fixed_pairs(&self) -> [&FixedVethPair; ENDPOINT_COUNT] {
        [&self.veths.entries[0], &self.veths.entries[1]]
    }

    fn endpoint_namespace_descriptor(&self, endpoint: NamespaceEndpoint) -> &OwnedFd {
        &self.namespace_pins().mounts.entries[endpoint.index()]
            .namespace
            .descriptor
    }

    /// Return the exact visible nsfs mount IDs in canonical A, B order.
    pub(crate) fn mount_ids(&self) -> [u64; ENDPOINT_COUNT] {
        self.namespace_pins().mount_ids()
    }

    /// Return the exact canonical nsfs mount-point bytes in A, B order.
    pub(crate) fn mount_point_bytes(&self) -> [&[u8]; ENDPOINT_COUNT] {
        self.namespace_pins().mount_point_bytes()
    }

    /// Visit A then B and restore the exact parent before every return.
    pub(crate) fn visit_network_namespaces<Visitor, VisitorError>(
        &self,
        visitor: Visitor,
    ) -> Result<(), NamespaceVisitError<VisitorError>>
    where
        Visitor: FnMut(NamespaceEndpoint) -> Result<(), VisitorError>,
    {
        self.namespace_pins().visit_network_namespaces(visitor)
    }

    /// Visit B then A and restore the exact parent before every return.
    pub(crate) fn visit_network_namespaces_reverse<Visitor, VisitorError>(
        &self,
        visitor: Visitor,
    ) -> Result<(), NamespaceVisitError<VisitorError>>
    where
        Visitor: FnMut(NamespaceEndpoint) -> Result<(), VisitorError>,
    {
        self.namespace_pins()
            .visit_network_namespaces_reverse(visitor)
    }

    /// Consume the exact pair owner into one four-address transaction.
    pub(crate) fn configure_fixed_ipv4_addresses(
        self,
    ) -> Result<AuthorizedIpv4Addresses, FixedIpv4AddressSetError> {
        self.verify().map_err(FixedIpv4AddressSetError::Veth)?;
        let mut authorized = AuthorizedIpv4Addresses {
            journal: FixedIpv4AddressJournal::new(),
            veth_pairs: Some(self),
            _thread_bound: PhantomData,
        };

        let staged = (|| {
            let parent_alpha = {
                let veth_pairs = authorized.veth_pairs();
                let pairs = veth_pairs.fixed_pairs();
                let namespace_pins = veth_pairs.namespace_pins();
                add_fixed_ipv4_address(
                    FixedIpv4Address::ParentA,
                    pairs[0],
                    &namespace_pins.parent.descriptor,
                )
                .map_err(FixedIpv4AddressSetError::Add)?
            };
            authorized.journal.parent[0] = Some(parent_alpha);
            let parent_omega = {
                let veth_pairs = authorized.veth_pairs();
                let pairs = veth_pairs.fixed_pairs();
                let namespace_pins = veth_pairs.namespace_pins();
                add_fixed_ipv4_address(
                    FixedIpv4Address::ParentB,
                    pairs[1],
                    &namespace_pins.parent.descriptor,
                )
                .map_err(FixedIpv4AddressSetError::Add)?
            };
            authorized.journal.parent[1] = Some(parent_omega);
            let veth_pairs = authorized
                .veth_pairs
                .as_ref()
                .unwrap_or_else(|| std::process::abort());
            let pairs = veth_pairs.fixed_pairs();
            let namespace_pins = veth_pairs.namespace_pins();
            let endpoint_descriptors = [
                &namespace_pins.mounts.entries[0].namespace.descriptor,
                &namespace_pins.mounts.entries[1].namespace.descriptor,
            ];
            let endpoint_addresses = &mut authorized.journal.endpoints;
            veth_pairs
                .visit_network_namespaces(|endpoint| {
                    let index = endpoint.index();
                    let specification = match endpoint {
                        NamespaceEndpoint::A => FixedIpv4Address::EndpointA,
                        NamespaceEndpoint::B => FixedIpv4Address::EndpointB,
                    };
                    endpoint_addresses[index] = Some(
                        add_fixed_ipv4_address(
                            specification,
                            pairs[index],
                            endpoint_descriptors[index],
                        )
                        .map_err(FixedIpv4AddressSetError::Add)?,
                    );
                    Ok(())
                })
                .map_err(map_ipv4_visit_error)?;
            Ok(())
        })();
        if let Err(error) = staged {
            let cleanup = {
                let veth_pairs = authorized
                    .veth_pairs
                    .as_ref()
                    .unwrap_or_else(|| std::process::abort());
                authorized.journal.rollback(veth_pairs)
            };
            return match cleanup {
                Ok(()) => Err(error),
                Err(cleanup) => Err(cleanup),
            };
        }
        authorized.verify()?;
        Ok(authorized)
    }

    fn namespace_pins(&self) -> &AuthorizedNamespacePins {
        self.namespace_pins
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }
}

impl FixedIpv4AddressJournal {
    fn new() -> Self {
        Self {
            parent: [None, None],
            endpoints: [None, None],
            armed: true,
        }
    }

    fn verify(&self, pairs: &AuthorizedVethPairs) -> Result<(), FixedIpv4AddressSetError> {
        if !self.armed {
            return Err(FixedIpv4AddressSetError::Unsafe(
                "fixed IPv4 address journal is disarmed",
            ));
        }
        pairs.verify().map_err(FixedIpv4AddressSetError::Veth)?;
        let fixed_pairs = pairs.fixed_pairs();
        let expected_parent = [FixedIpv4Address::ParentA, FixedIpv4Address::ParentB];
        let expected_endpoints = [FixedIpv4Address::EndpointA, FixedIpv4Address::EndpointB];
        for (index, expected) in expected_parent.into_iter().enumerate() {
            let parent = self.parent[index]
                .as_ref()
                .ok_or(FixedIpv4AddressSetError::Unsafe(
                    "fixed parent IPv4 address is missing",
                ))?;
            if parent.address() != expected {
                return Err(FixedIpv4AddressSetError::Unsafe(
                    "fixed parent IPv4 address order changed",
                ));
            }
            parent
                .verify(fixed_pairs[index])
                .map_err(FixedIpv4AddressSetError::Verify)?;
        }
        let mut visited = [false, false];
        pairs
            .visit_network_namespaces(|endpoint| {
                let index = endpoint.index();
                let address =
                    self.endpoints[index]
                        .as_ref()
                        .ok_or(FixedIpv4AddressSetError::Unsafe(
                            "fixed endpoint IPv4 address is missing",
                        ))?;
                if visited[index] || address.address() != expected_endpoints[index] {
                    return Err(FixedIpv4AddressSetError::Unsafe(
                        "fixed endpoint IPv4 address order changed",
                    ));
                }
                address
                    .verify(fixed_pairs[index])
                    .map_err(FixedIpv4AddressSetError::Verify)?;
                visited[index] = true;
                Ok(())
            })
            .map_err(map_ipv4_visit_error)?;
        if visited != [true, true] {
            return Err(FixedIpv4AddressSetError::Unsafe(
                "fixed endpoint IPv4 address visit was incomplete",
            ));
        }
        pairs.verify().map_err(FixedIpv4AddressSetError::Veth)
    }

    fn owners(&self) -> [&FixedIpv4AddressOwner; 4] {
        [
            self.parent[0]
                .as_ref()
                .unwrap_or_else(|| std::process::abort()),
            self.endpoints[0]
                .as_ref()
                .unwrap_or_else(|| std::process::abort()),
            self.parent[1]
                .as_ref()
                .unwrap_or_else(|| std::process::abort()),
            self.endpoints[1]
                .as_ref()
                .unwrap_or_else(|| std::process::abort()),
        ]
    }

    fn rollback(&mut self, pairs: &AuthorizedVethPairs) -> Result<(), FixedIpv4AddressSetError> {
        if !self.armed {
            return Ok(());
        }
        pairs.verify().map_err(FixedIpv4AddressSetError::Veth)?;
        let fixed_pairs = pairs.fixed_pairs();
        let mut first_error = None;
        let endpoint_addresses = &mut self.endpoints;
        let visited = pairs.visit_network_namespaces_reverse(|endpoint| {
            let index = endpoint.index();
            if let Some(address) = endpoint_addresses[index].take() {
                if let Err(error) = address.rollback(fixed_pairs[index]) {
                    first_error.get_or_insert(FixedIpv4AddressSetError::Rollback(error));
                }
            }
            Ok::<(), std::convert::Infallible>(())
        });
        if let Err(error) = visited {
            return match error {
                NamespaceVisitError::Namespace(source) => {
                    Err(FixedIpv4AddressSetError::Namespace(source))
                }
                NamespaceVisitError::Visitor(never) => match never {},
            };
        }
        for index in (0..ENDPOINT_COUNT).rev() {
            if let Some(address) = self.parent[index].take() {
                if let Err(error) = address.rollback(fixed_pairs[index]) {
                    first_error.get_or_insert(FixedIpv4AddressSetError::Rollback(error));
                }
            }
        }
        if self.parent.iter().any(Option::is_some) || self.endpoints.iter().any(Option::is_some) {
            return Err(FixedIpv4AddressSetError::Unsafe(
                "fixed IPv4 rollback left an owned address",
            ));
        }
        self.armed = false;
        pairs.verify().map_err(FixedIpv4AddressSetError::Veth)?;
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for FixedIpv4AddressJournal {
    fn drop(&mut self) {
        if self.armed {
            std::process::abort();
        }
    }
}

impl AuthorizedIpv4Addresses {
    /// Freshly reprove all four address, namespace, interface, and veth bindings.
    pub(crate) fn verify(&self) -> Result<(), FixedIpv4AddressSetError> {
        self.journal.verify(self.veth_pairs())
    }

    /// Borrow the four affine owners as parent A, endpoint A, parent B, endpoint B.
    pub(crate) fn owners(&self) -> [&FixedIpv4AddressOwner; 4] {
        self.journal.owners()
    }

    /// Borrow the exact veth authority retained behind the four addresses.
    pub(crate) fn veth_pairs(&self) -> &AuthorizedVethPairs {
        self.veth_pairs
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }

    /// Consume the addressed DOWN topology through four exact addrgen-NONE
    /// updates and a separate four-end proof barrier.
    pub(crate) fn disable_ipv6_address_generation(
        self,
    ) -> Result<AuthorizedIpv4AddrgenNone, FixedLinkActivationFailure> {
        if let Err(source) = self.verify() {
            drop(self);
            return Err(FixedLinkActivationFailure::untouched(
                FixedLinkActivationError::Addressed(source),
            ));
        }
        let links = {
            let pairs = self.veth_pairs().fixed_pairs();
            match FixedLinkMutationJournal::begin(pairs[0], pairs[1]) {
                Ok(links) => links,
                Err(source) => {
                    drop(self);
                    return Err(FixedLinkActivationFailure::untouched(
                        FixedLinkActivationError::Link(source),
                    ));
                }
            }
        };
        let mut provisional = ProvisionalLinkActivation {
            addressed: Some(self),
            links: Some(links),
            _thread_bound: PhantomData,
        };
        if let Err(source) = provisional.stage_all_addrgen_none() {
            return Err(provisional.into_failure(source));
        }
        provisional.finish()
    }
}

impl ProvisionalLinkActivation {
    fn stage_all_addrgen_none(&mut self) -> Result<(), FixedLinkActivationError> {
        {
            let addressed = self
                .addressed
                .as_ref()
                .unwrap_or_else(|| std::process::abort());
            let links = self.links.as_mut().unwrap_or_else(|| std::process::abort());
            let pairs = addressed.veth_pairs().fixed_pairs();
            links
                .set_addrgen_none(FixedLinkEnd::ParentA, pairs[0])
                .map_err(FixedLinkActivationError::Link)?;
            links
                .set_addrgen_none(FixedLinkEnd::ParentB, pairs[1])
                .map_err(FixedLinkActivationError::Link)?;
            addressed
                .veth_pairs()
                .visit_network_namespaces(|endpoint| {
                    let index = endpoint.index();
                    let end = match endpoint {
                        NamespaceEndpoint::A => FixedLinkEnd::EndpointA,
                        NamespaceEndpoint::B => FixedLinkEnd::EndpointB,
                    };
                    links.set_addrgen_none(end, pairs[index])
                })
                .map_err(map_link_visit_error)?;
        }
        {
            let addressed = self
                .addressed
                .as_ref()
                .unwrap_or_else(|| std::process::abort());
            let links = self.links.as_mut().unwrap_or_else(|| std::process::abort());
            let pairs = addressed.veth_pairs().fixed_pairs();
            links
                .prove_addrgen_none(FixedLinkEnd::ParentA, pairs[0])
                .map_err(FixedLinkActivationError::Link)?;
            links
                .prove_addrgen_none(FixedLinkEnd::ParentB, pairs[1])
                .map_err(FixedLinkActivationError::Link)?;
            addressed
                .veth_pairs()
                .visit_network_namespaces(|endpoint| {
                    let index = endpoint.index();
                    let end = match endpoint {
                        NamespaceEndpoint::A => FixedLinkEnd::EndpointA,
                        NamespaceEndpoint::B => FixedLinkEnd::EndpointB,
                    };
                    links.prove_addrgen_none(end, pairs[index])
                })
                .map_err(map_link_visit_error)?;
        }
        Ok(())
    }

    fn finish(mut self) -> Result<AuthorizedIpv4AddrgenNone, FixedLinkActivationFailure> {
        let links = self
            .links
            .take()
            .unwrap_or_else(|| std::process::abort())
            .finish_all_none_barrier();
        let addressed = self
            .addressed
            .take()
            .unwrap_or_else(|| std::process::abort());
        let authorized = AuthorizedIpv4AddrgenNone {
            addressed: Some(addressed),
            links: Some(links),
            _thread_bound: PhantomData,
        };
        match authorized.verify() {
            Ok(()) => Ok(authorized),
            Err(source) => Err(authorized.into_failure(source)),
        }
    }

    fn into_failure(mut self, source: FixedLinkActivationError) -> FixedLinkActivationFailure {
        let links = self.links.take().unwrap_or_else(|| std::process::abort());
        let addressed = self
            .addressed
            .take()
            .unwrap_or_else(|| std::process::abort());
        failure_after_retirement(source, addressed, links.into_retirement())
    }
}

impl AuthorizedIpv4AddrgenNone {
    /// Reprove the retained namespace pins and the low-level all-NONE barrier.
    pub(crate) fn verify(&self) -> Result<(), FixedLinkActivationError> {
        let addressed = self.addressed();
        addressed
            .veth_pairs()
            .namespace_pins()
            .verify()
            .map_err(FixedLinkActivationError::Namespace)?;
        self.links()
            .verify()
            .map_err(FixedLinkActivationError::Link)?;
        addressed
            .veth_pairs()
            .namespace_pins()
            .verify()
            .map_err(FixedLinkActivationError::Namespace)
    }

    /// Borrow the four retained address identities in canonical order.
    pub(crate) fn owners(&self) -> [&FixedIpv4AddressOwner; 4] {
        self.addressed().owners()
    }

    /// Borrow both retained pair identities without invoking the DOWN parser.
    pub(crate) fn fixed_pairs(&self) -> [&FixedVethPair; ENDPOINT_COUNT] {
        self.addressed().veth_pairs().fixed_pairs()
    }

    pub(crate) fn mount_ids(&self) -> [u64; ENDPOINT_COUNT] {
        self.addressed().veth_pairs().mount_ids()
    }

    pub(crate) fn mount_point_bytes(&self) -> [&[u8]; ENDPOINT_COUNT] {
        self.addressed().veth_pairs().mount_point_bytes()
    }

    /// Run one parent-scoped proof between fresh all-NONE reproofs.
    pub(crate) fn visit_parent_network_namespace<Visitor, Output, VisitorError>(
        &self,
        visitor: Visitor,
    ) -> Result<Output, FixedTopologyVisitError<VisitorError>>
    where
        Visitor: FnOnce() -> Result<Output, VisitorError>,
    {
        visit_link_state_parent(self, Self::verify, visitor)
    }

    /// Visit endpoint A then B while retaining the exact all-NONE authority.
    pub(crate) fn visit_network_namespaces<Visitor, VisitorError>(
        &self,
        visitor: Visitor,
    ) -> Result<(), FixedTopologyVisitError<VisitorError>>
    where
        Visitor: FnMut(NamespaceEndpoint) -> Result<(), VisitorError>,
    {
        visit_link_state_endpoints(self, Self::verify, visitor)
    }

    /// Consume the all-NONE barrier through four exact link-UP mutations and
    /// a separate four-end active proof barrier.
    pub(crate) fn activate_links(
        mut self,
    ) -> Result<AuthorizedActivatedTopology, FixedLinkActivationFailure> {
        if let Err(source) = self.verify() {
            return Err(self.into_failure(source));
        }
        if let Err(source) = self.stage_all_links_up() {
            return Err(self.into_failure(source));
        }
        let links = self
            .links
            .take()
            .unwrap_or_else(|| std::process::abort())
            .finish_all_up();
        let addressed = self
            .addressed
            .take()
            .unwrap_or_else(|| std::process::abort());
        let authorized = AuthorizedActivatedTopology {
            addressed: Some(addressed),
            links: Some(links),
            _thread_bound: PhantomData,
        };
        match authorized.verify() {
            Ok(()) => Ok(authorized),
            Err(source) => Err(authorized.into_failure(source)),
        }
    }

    /// Enter deletion-only retirement without attempting any link-UP request.
    pub(crate) fn begin_retirement(mut self) -> AuthorizedDeletedTopology {
        let links = self.links.take().unwrap_or_else(|| std::process::abort());
        let addressed = self
            .addressed
            .take()
            .unwrap_or_else(|| std::process::abort());
        match links.into_retirement() {
            FixedLinkRetirement::Deleted(pending) => {
                complete_raw_link_retirement(addressed, pending, [None, None])
            }
            FixedLinkRetirement::Untouched => std::process::abort(),
        }
    }

    fn stage_all_links_up(&mut self) -> Result<(), FixedLinkActivationError> {
        {
            let addressed = self
                .addressed
                .as_ref()
                .unwrap_or_else(|| std::process::abort());
            let links = self.links.as_mut().unwrap_or_else(|| std::process::abort());
            let pairs = addressed.veth_pairs().fixed_pairs();
            links
                .set_link_up(FixedLinkEnd::ParentA, pairs[0])
                .map_err(FixedLinkActivationError::Link)?;
            links
                .set_link_up(FixedLinkEnd::ParentB, pairs[1])
                .map_err(FixedLinkActivationError::Link)?;
            addressed
                .veth_pairs()
                .visit_network_namespaces(|endpoint| {
                    let index = endpoint.index();
                    let end = match endpoint {
                        NamespaceEndpoint::A => FixedLinkEnd::EndpointA,
                        NamespaceEndpoint::B => FixedLinkEnd::EndpointB,
                    };
                    links.set_link_up(end, pairs[index])
                })
                .map_err(map_link_visit_error)?;
        }
        {
            let addressed = self
                .addressed
                .as_ref()
                .unwrap_or_else(|| std::process::abort());
            let links = self.links.as_mut().unwrap_or_else(|| std::process::abort());
            let pairs = addressed.veth_pairs().fixed_pairs();
            links
                .prove_link_up(FixedLinkEnd::ParentA, pairs[0])
                .map_err(FixedLinkActivationError::Link)?;
            links
                .prove_link_up(FixedLinkEnd::ParentB, pairs[1])
                .map_err(FixedLinkActivationError::Link)?;
            addressed
                .veth_pairs()
                .visit_network_namespaces(|endpoint| {
                    let index = endpoint.index();
                    let end = match endpoint {
                        NamespaceEndpoint::A => FixedLinkEnd::EndpointA,
                        NamespaceEndpoint::B => FixedLinkEnd::EndpointB,
                    };
                    links.prove_link_up(end, pairs[index])
                })
                .map_err(map_link_visit_error)?;
        }
        Ok(())
    }

    fn addressed(&self) -> &AuthorizedIpv4Addresses {
        self.addressed
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }

    fn links(&self) -> &AllLinksAddrgenNone {
        self.links.as_ref().unwrap_or_else(|| std::process::abort())
    }

    fn into_failure(mut self, source: FixedLinkActivationError) -> FixedLinkActivationFailure {
        let links = self.links.take().unwrap_or_else(|| std::process::abort());
        let addressed = self
            .addressed
            .take()
            .unwrap_or_else(|| std::process::abort());
        failure_after_retirement(source, addressed, links.into_retirement())
    }
}

impl AuthorizedActivatedTopology {
    /// Reprove the retained namespace pins and exact four-end active barrier.
    pub(crate) fn verify(&self) -> Result<(), FixedLinkActivationError> {
        let addressed = self.addressed();
        addressed
            .veth_pairs()
            .namespace_pins()
            .verify()
            .map_err(FixedLinkActivationError::Namespace)?;
        self.links()
            .verify()
            .map_err(FixedLinkActivationError::Link)?;
        addressed
            .veth_pairs()
            .namespace_pins()
            .verify()
            .map_err(FixedLinkActivationError::Namespace)
    }

    pub(crate) fn owners(&self) -> [&FixedIpv4AddressOwner; 4] {
        self.addressed().owners()
    }

    pub(crate) fn fixed_pairs(&self) -> [&FixedVethPair; ENDPOINT_COUNT] {
        self.addressed().veth_pairs().fixed_pairs()
    }

    pub(crate) fn mount_ids(&self) -> [u64; ENDPOINT_COUNT] {
        self.addressed().veth_pairs().mount_ids()
    }

    pub(crate) fn mount_point_bytes(&self) -> [&[u8]; ENDPOINT_COUNT] {
        self.addressed().veth_pairs().mount_point_bytes()
    }

    pub(crate) fn visit_parent_network_namespace<Visitor, Output, VisitorError>(
        &self,
        visitor: Visitor,
    ) -> Result<Output, FixedTopologyVisitError<VisitorError>>
    where
        Visitor: FnOnce() -> Result<Output, VisitorError>,
    {
        visit_link_state_parent(self, Self::verify, visitor)
    }

    pub(crate) fn visit_network_namespaces<Visitor, VisitorError>(
        &self,
        visitor: Visitor,
    ) -> Result<(), FixedTopologyVisitError<VisitorError>>
    where
        Visitor: FnMut(NamespaceEndpoint) -> Result<(), VisitorError>,
    {
        visit_link_state_endpoints(self, Self::verify, visitor)
    }

    /// Install route A and then route B while visiting only their exact
    /// retained endpoint namespaces.
    ///
    /// Every route field is derived inside the low-level UAPI from the
    /// all-links-up authority, both pair lineages, the local endpoint-address
    /// owner, and the current retained namespace descriptor. Any failure
    /// consumes this active state into direct B/A pair deletion; route
    /// authority that crossed the possibly-sent boundary remains armed there.
    pub(crate) fn install_endpoint_routes(
        self,
    ) -> Result<AuthorizedEndpointRoutes, FixedEndpointRouteFailure> {
        if let Err(source) = self.verify() {
            return Err(self.into_endpoint_route_failure(
                FixedEndpointRouteSetError::Activated(source),
                [None, None],
            ));
        }

        let mut route_owners: [Option<FixedEndpointRouteOwner>; ENDPOINT_COUNT] = [None, None];
        let mut route_retirements: [Option<FixedEndpointRouteRetirement>; ENDPOINT_COUNT] =
            [None, None];
        let installed = {
            let addressed = self.addressed();
            let links = self.links();
            let pairs = addressed.veth_pairs().fixed_pairs();
            let owners = addressed.owners();
            addressed.veth_pairs().visit_network_namespaces(|endpoint| {
                let index = endpoint.index();
                if route_owners[index].is_some() || route_retirements[index].is_some() {
                    return Err(FixedEndpointRouteSetError::Unsafe(
                        "fixed endpoint-route namespace visit was duplicated",
                    ));
                }
                let descriptor = addressed
                    .veth_pairs()
                    .endpoint_namespace_descriptor(endpoint);
                let plan = FixedEndpointRoutePlan::derive(
                    links,
                    descriptor,
                    pairs[index],
                    pairs[1 - index],
                    owners[(index * 2) + 1],
                )
                .map_err(FixedEndpointRouteSetError::Plan)?;
                match plan.install() {
                    Ok(route) => {
                        route_owners[index] = Some(route);
                        Ok(())
                    }
                    Err(FixedRouteInstallError::BeforeMutation(source)) => {
                        Err(FixedEndpointRouteSetError::InstallBeforeMutation(source))
                    }
                    Err(FixedRouteInstallError::Rejected(errno)) => {
                        Err(FixedEndpointRouteSetError::InstallRejected(errno))
                    }
                    Err(FixedRouteInstallError::DeletionBound { source, authority }) => {
                        route_retirements[index] = Some(*authority);
                        Err(FixedEndpointRouteSetError::InstallDeletionBound(source))
                    }
                }
            })
        };
        if let Err(error) = installed {
            let source = match error {
                NamespaceVisitError::Namespace(source) => {
                    FixedEndpointRouteSetError::Namespace(source)
                }
                NamespaceVisitError::Visitor(source) => source,
            };
            route_retirements = merge_route_retirements(route_owners, route_retirements);
            return Err(self.into_endpoint_route_failure(source, route_retirements));
        }
        if route_owners.iter().any(Option::is_none) || route_retirements.iter().any(Option::is_some)
        {
            route_retirements = merge_route_retirements(route_owners, route_retirements);
            return Err(self.into_endpoint_route_failure(
                FixedEndpointRouteSetError::Unsafe(
                    "fixed endpoint-route namespace visit was incomplete",
                ),
                route_retirements,
            ));
        }

        let routed = AuthorizedEndpointRoutes {
            activated: Some(self),
            routes: route_owners,
            _thread_bound: PhantomData,
        };
        match routed.verify() {
            Ok(()) => Ok(routed),
            Err(source) => Err(routed.into_failure(source)),
        }
    }

    /// Delete pair B then A and retain every lower owner through the external
    /// full pristine-network proof barrier.
    pub(crate) fn begin_retirement(self) -> AuthorizedDeletedTopology {
        self.into_deleted_topology([None, None])
    }

    fn addressed(&self) -> &AuthorizedIpv4Addresses {
        self.addressed
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }

    fn links(&self) -> &AllLinksUp {
        self.links.as_ref().unwrap_or_else(|| std::process::abort())
    }

    fn into_failure(mut self, source: FixedLinkActivationError) -> FixedLinkActivationFailure {
        let links = self.links.take().unwrap_or_else(|| std::process::abort());
        let addressed = self
            .addressed
            .take()
            .unwrap_or_else(|| std::process::abort());
        failure_after_retirement(source, addressed, links.into_retirement())
    }

    fn into_endpoint_route_failure(
        mut self,
        source: FixedEndpointRouteSetError,
        route_retirements: [Option<FixedEndpointRouteRetirement>; ENDPOINT_COUNT],
    ) -> FixedEndpointRouteFailure {
        let links = self.links.take().unwrap_or_else(|| std::process::abort());
        let addressed = self
            .addressed
            .take()
            .unwrap_or_else(|| std::process::abort());
        let deleted = match links.into_retirement() {
            FixedLinkRetirement::Deleted(pending) => {
                complete_raw_link_retirement(addressed, pending, route_retirements)
            }
            FixedLinkRetirement::Untouched => std::process::abort(),
        };
        FixedEndpointRouteFailure::deleted(source, deleted)
    }

    fn into_deleted_topology(
        mut self,
        route_retirements: [Option<FixedEndpointRouteRetirement>; ENDPOINT_COUNT],
    ) -> AuthorizedDeletedTopology {
        let links = self.links.take().unwrap_or_else(|| std::process::abort());
        let addressed = self
            .addressed
            .take()
            .unwrap_or_else(|| std::process::abort());
        match links.into_retirement() {
            FixedLinkRetirement::Deleted(pending) => {
                complete_raw_link_retirement(addressed, pending, route_retirements)
            }
            FixedLinkRetirement::Untouched => std::process::abort(),
        }
    }
}

impl AuthorizedEndpointRoutes {
    /// Reprove the complete active link authority and both installed route
    /// owners in canonical A/B namespace order.
    pub(crate) fn verify(&self) -> Result<(), FixedEndpointRouteSetError> {
        self.activated()
            .verify()
            .map_err(FixedEndpointRouteSetError::Activated)?;
        let mut visited = [false, false];
        self.activated()
            .visit_network_namespaces(|endpoint| {
                let index = endpoint.index();
                let route =
                    self.routes[index]
                        .as_ref()
                        .ok_or(FixedEndpointRouteSetError::Unsafe(
                            "fixed endpoint-route owner is missing",
                        ))?;
                let expected_endpoint = match endpoint {
                    NamespaceEndpoint::A => FixedVethEndpoint::A,
                    NamespaceEndpoint::B => FixedVethEndpoint::B,
                };
                if visited[index] || route.endpoint() != expected_endpoint {
                    return Err(FixedEndpointRouteSetError::Unsafe(
                        "fixed endpoint-route owner order changed",
                    ));
                }
                route.verify().map_err(FixedEndpointRouteSetError::Verify)?;
                visited[index] = true;
                Ok(())
            })
            .map_err(|error| match error {
                FixedTopologyVisitError::Topology(source) => {
                    FixedEndpointRouteSetError::Activated(source)
                }
                FixedTopologyVisitError::Namespace(source) => {
                    FixedEndpointRouteSetError::Namespace(source)
                }
                FixedTopologyVisitError::Visitor(source) => source,
            })?;
        if visited != [true, true] {
            return Err(FixedEndpointRouteSetError::Unsafe(
                "fixed endpoint-route verification visit was incomplete",
            ));
        }
        self.activated()
            .verify()
            .map_err(FixedEndpointRouteSetError::Activated)
    }

    pub(crate) fn mount_ids(&self) -> [u64; ENDPOINT_COUNT] {
        self.activated().mount_ids()
    }

    pub(crate) fn mount_point_bytes(&self) -> [&[u8]; ENDPOINT_COUNT] {
        self.activated().mount_point_bytes()
    }

    pub(crate) fn visit_parent_network_namespace<Visitor, Output, VisitorError>(
        &self,
        visitor: Visitor,
    ) -> Result<Output, FixedEndpointRouteVisitError<VisitorError>>
    where
        Visitor: FnOnce() -> Result<Output, VisitorError>,
    {
        visit_endpoint_route_state_parent(self, visitor)
    }

    pub(crate) fn visit_network_namespaces<Visitor, VisitorError>(
        &self,
        visitor: Visitor,
    ) -> Result<(), FixedEndpointRouteVisitError<VisitorError>>
    where
        Visitor: FnMut(NamespaceEndpoint) -> Result<(), VisitorError>,
    {
        visit_endpoint_route_state_endpoints(self, visitor)
    }

    /// Delete pair B then A and retain both route owners, all address owners,
    /// and both pair owners through the external pristine-network proof.
    pub(crate) fn begin_retirement(mut self) -> AuthorizedDeletedTopology {
        let activated = self
            .activated
            .take()
            .unwrap_or_else(|| std::process::abort());
        let routes = take_route_retirements(&mut self.routes);
        activated.into_deleted_topology(routes)
    }

    fn activated(&self) -> &AuthorizedActivatedTopology {
        self.activated
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }

    fn into_failure(mut self, source: FixedEndpointRouteSetError) -> FixedEndpointRouteFailure {
        let activated = self
            .activated
            .take()
            .unwrap_or_else(|| std::process::abort());
        let routes = take_route_retirements(&mut self.routes);
        FixedEndpointRouteFailure::deleted(source, activated.into_deleted_topology(routes))
    }
}

/// Failure from a scoped parent or endpoint visit through routed typestate.
#[derive(Debug)]
pub(crate) enum FixedEndpointRouteVisitError<VisitorError> {
    /// The retained routed typestate failed its pre- or post-visit proof.
    Topology(FixedEndpointRouteSetError),
    /// Entering or restoring a retained endpoint namespace failed.
    Namespace(NamespacePinError),
    /// The scoped caller operation failed after exact restoration.
    Visitor(VisitorError),
}

fn visit_endpoint_route_state_parent<Visitor, Output, VisitorError>(
    state: &AuthorizedEndpointRoutes,
    visitor: Visitor,
) -> Result<Output, FixedEndpointRouteVisitError<VisitorError>>
where
    Visitor: FnOnce() -> Result<Output, VisitorError>,
{
    state
        .verify()
        .map_err(FixedEndpointRouteVisitError::Topology)?;
    let visited = visitor();
    state
        .verify()
        .map_err(FixedEndpointRouteVisitError::Topology)?;
    visited.map_err(FixedEndpointRouteVisitError::Visitor)
}

fn visit_endpoint_route_state_endpoints<Visitor, VisitorError>(
    state: &AuthorizedEndpointRoutes,
    visitor: Visitor,
) -> Result<(), FixedEndpointRouteVisitError<VisitorError>>
where
    Visitor: FnMut(NamespaceEndpoint) -> Result<(), VisitorError>,
{
    state
        .verify()
        .map_err(FixedEndpointRouteVisitError::Topology)?;
    let visited = state
        .activated()
        .addressed()
        .veth_pairs()
        .namespace_pins()
        .visit_network_namespaces(visitor)
        .map_err(|error| match error {
            NamespaceVisitError::Namespace(source) => {
                FixedEndpointRouteVisitError::Namespace(source)
            }
            NamespaceVisitError::Visitor(source) => FixedEndpointRouteVisitError::Visitor(source),
        });
    state
        .verify()
        .map_err(FixedEndpointRouteVisitError::Topology)?;
    visited
}

fn take_route_retirements(
    routes: &mut [Option<FixedEndpointRouteOwner>; ENDPOINT_COUNT],
) -> [Option<FixedEndpointRouteRetirement>; ENDPOINT_COUNT] {
    routes
        .each_mut()
        .map(|route| route.take().map(FixedEndpointRouteOwner::into_retirement))
}

fn merge_route_retirements(
    routes: [Option<FixedEndpointRouteOwner>; ENDPOINT_COUNT],
    mut retirements: [Option<FixedEndpointRouteRetirement>; ENDPOINT_COUNT],
) -> [Option<FixedEndpointRouteRetirement>; ENDPOINT_COUNT] {
    for (index, route) in routes.into_iter().enumerate() {
        if let Some(route) = route {
            if retirements[index].is_some() {
                std::process::abort();
            }
            retirements[index] = Some(route.into_retirement());
        }
    }
    retirements
}

trait RetainedLinkState {
    fn retained_namespace_pins(&self) -> &AuthorizedNamespacePins;
}

impl RetainedLinkState for AuthorizedIpv4AddrgenNone {
    fn retained_namespace_pins(&self) -> &AuthorizedNamespacePins {
        self.addressed().veth_pairs().namespace_pins()
    }
}

impl RetainedLinkState for AuthorizedActivatedTopology {
    fn retained_namespace_pins(&self) -> &AuthorizedNamespacePins {
        self.addressed().veth_pairs().namespace_pins()
    }
}

fn visit_link_state_parent<State, Visitor, Output, VisitorError>(
    state: &State,
    verify: fn(&State) -> Result<(), FixedLinkActivationError>,
    visitor: Visitor,
) -> Result<Output, FixedTopologyVisitError<VisitorError>>
where
    Visitor: FnOnce() -> Result<Output, VisitorError>,
{
    verify(state).map_err(FixedTopologyVisitError::Topology)?;
    let visited = visitor();
    verify(state).map_err(FixedTopologyVisitError::Topology)?;
    visited.map_err(FixedTopologyVisitError::Visitor)
}

fn visit_link_state_endpoints<State, Visitor, VisitorError>(
    state: &State,
    verify: fn(&State) -> Result<(), FixedLinkActivationError>,
    visitor: Visitor,
) -> Result<(), FixedTopologyVisitError<VisitorError>>
where
    State: RetainedLinkState,
    Visitor: FnMut(NamespaceEndpoint) -> Result<(), VisitorError>,
{
    verify(state).map_err(FixedTopologyVisitError::Topology)?;
    let visited = state
        .retained_namespace_pins()
        .visit_network_namespaces(visitor)
        .map_err(|error| match error {
            NamespaceVisitError::Namespace(source) => FixedTopologyVisitError::Namespace(source),
            NamespaceVisitError::Visitor(source) => FixedTopologyVisitError::Visitor(source),
        });
    verify(state).map_err(FixedTopologyVisitError::Topology)?;
    visited
}

impl AuthorizedDeletedTopology {
    /// Retained B/A identities for higher-level exact pristine observations.
    pub(crate) fn fixed_pair_identities(&self) -> [DeletedVethPairIdentity; ENDPOINT_COUNT] {
        let pairs = self.addressed().veth_pairs().fixed_pairs();
        pairs.map(|pair| {
            let target = pair.target_namespace_identity();
            DeletedVethPairIdentity {
                endpoint: match pair.endpoint() {
                    FixedVethEndpoint::A => NamespaceEndpoint::A,
                    FixedVethEndpoint::B => NamespaceEndpoint::B,
                },
                parent_name: pair.parent_name().to_owned(),
                parent_ifindex: pair.parent_ifindex(),
                peer_ifindex: pair.peer_ifindex(),
                target_namespace_device: target.device(),
                target_namespace_inode: target.inode(),
            }
        })
    }

    pub(crate) fn mount_ids(&self) -> [u64; ENDPOINT_COUNT] {
        self.namespace_pins().mount_ids()
    }

    pub(crate) fn mount_point_bytes(&self) -> [&[u8]; ENDPOINT_COUNT] {
        self.namespace_pins().mount_point_bytes()
    }

    /// Run a parent-scoped pristine proof while every lower owner remains armed.
    pub(crate) fn visit_parent_network_namespace<Visitor, Output, VisitorError>(
        &self,
        visitor: Visitor,
    ) -> Result<Output, FixedTopologyVisitError<VisitorError>>
    where
        Visitor: FnOnce() -> Result<Output, VisitorError>,
    {
        self.namespace_pins()
            .verify()
            .map_err(FixedTopologyVisitError::Namespace)?;
        let visited = visitor();
        self.namespace_pins()
            .verify()
            .map_err(FixedTopologyVisitError::Namespace)?;
        visited.map_err(FixedTopologyVisitError::Visitor)
    }

    /// Visit endpoint A then B for consuming pristine-baseline verification.
    pub(crate) fn visit_network_namespaces<Visitor, VisitorError>(
        &self,
        visitor: Visitor,
    ) -> Result<(), FixedTopologyVisitError<VisitorError>>
    where
        Visitor: FnMut(NamespaceEndpoint) -> Result<(), VisitorError>,
    {
        self.namespace_pins()
            .visit_network_namespaces(visitor)
            .map_err(|error| match error {
                NamespaceVisitError::Namespace(source) => {
                    FixedTopologyVisitError::Namespace(source)
                }
                NamespaceVisitError::Visitor(source) => FixedTopologyVisitError::Visitor(source),
            })
    }

    /// Release lower affine owners only after consuming the unforgeable affine
    /// token minted by the higher layer's external parent/A/B pristine-network
    /// proof. Every retained route, address, and pair is prevalidated before
    /// the first infallible journal disarm.
    #[allow(clippy::needless_pass_by_value)] // consuming this affine token is the disarm boundary
    pub(crate) fn finish_after_pristine_network_proof(
        mut self,
        pristine_network_proof: crate::mounts::PristineNetworkRetirementProof,
    ) -> AuthorizedNamespacePins {
        let proof = self
            .absence
            .as_ref()
            .unwrap_or_else(|| std::process::abort());
        let route_prevalidated = self.route_retirements.iter().flatten().all(|route| {
            route
                .prevalidate_pair_absence_retirement(proof, &pristine_network_proof)
                .is_ok()
        });
        let addressed = self
            .addressed
            .as_mut()
            .unwrap_or_else(|| std::process::abort());
        let address_prevalidated = addressed
            .journal
            .owners()
            .into_iter()
            .all(|owner| owner.prevalidate_pair_absence_retirement(proof).is_ok());
        let pair_prevalidated = addressed
            .veth_pairs()
            .fixed_pairs()
            .into_iter()
            .all(|pair| pair.prevalidate_pair_absence_retirement(proof).is_ok());
        if !route_prevalidated || !address_prevalidated || !pair_prevalidated {
            std::process::abort();
        }

        for index in (0..ENDPOINT_COUNT).rev() {
            if let Some(route) = self.route_retirements[index].take() {
                route.retire_after_validated_pair_absence(proof, &pristine_network_proof);
            }
        }
        for index in (0..ENDPOINT_COUNT).rev() {
            addressed.journal.endpoints[index]
                .take()
                .unwrap_or_else(|| std::process::abort())
                .retire_after_validated_pair_absence(proof);
        }
        for index in (0..ENDPOINT_COUNT).rev() {
            addressed.journal.parent[index]
                .take()
                .unwrap_or_else(|| std::process::abort())
                .retire_after_validated_pair_absence(proof);
        }
        addressed.journal.armed = false;

        let veth_pairs = addressed
            .veth_pairs
            .as_mut()
            .unwrap_or_else(|| std::process::abort());
        while let Some(pair) = veth_pairs.veths.entries.pop() {
            pair.retire_after_validated_pair_absence(proof);
        }
        veth_pairs.veths.armed = false;
        let namespace_pins = veth_pairs
            .namespace_pins
            .take()
            .unwrap_or_else(|| std::process::abort());
        drop(
            addressed
                .veth_pairs
                .take()
                .unwrap_or_else(|| std::process::abort()),
        );
        drop(
            self.addressed
                .take()
                .unwrap_or_else(|| std::process::abort()),
        );
        self.absence = None;
        namespace_pins
    }

    fn addressed(&self) -> &AuthorizedIpv4Addresses {
        self.addressed
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }

    fn namespace_pins(&self) -> &AuthorizedNamespacePins {
        self.addressed().veth_pairs().namespace_pins()
    }
}

fn failure_after_retirement(
    source: FixedLinkActivationError,
    addressed: AuthorizedIpv4Addresses,
    retirement: FixedLinkRetirement,
) -> FixedLinkActivationFailure {
    match retirement {
        FixedLinkRetirement::Untouched => {
            drop(addressed);
            FixedLinkActivationFailure::untouched(source)
        }
        FixedLinkRetirement::Deleted(pending) => FixedLinkActivationFailure::deleted(
            source,
            complete_raw_link_retirement(addressed, pending, [None, None]),
        ),
    }
}

fn complete_raw_link_retirement(
    addressed: AuthorizedIpv4Addresses,
    mut pending: PendingFixedPairAbsenceProof,
    route_retirements: [Option<FixedEndpointRouteRetirement>; ENDPOINT_COUNT],
) -> AuthorizedDeletedTopology {
    let mut endpoint_proved = false;
    for _ in 0..RAW_LINK_RETIREMENT_PROOF_ATTEMPTS {
        let result = addressed
            .veth_pairs()
            .visit_network_namespaces_reverse(|endpoint| {
                pending.prove_endpoint_absence(match endpoint {
                    NamespaceEndpoint::A => FixedVethEndpoint::A,
                    NamespaceEndpoint::B => FixedVethEndpoint::B,
                })
            });
        if result.is_ok() {
            endpoint_proved = true;
            break;
        }
    }
    if !endpoint_proved {
        std::process::abort();
    }

    let mut parent_proved = false;
    for _ in 0..RAW_LINK_RETIREMENT_PROOF_ATTEMPTS {
        if pending.prove_parent_absence().is_ok() {
            parent_proved = true;
            break;
        }
    }
    if !parent_proved {
        std::process::abort();
    }
    AuthorizedDeletedTopology {
        addressed: Some(addressed),
        absence: Some(pending.finish()),
        route_retirements,
        _thread_bound: PhantomData,
    }
}

fn map_link_visit_error(
    error: NamespaceVisitError<FixedLinkOperationError>,
) -> FixedLinkActivationError {
    match error {
        NamespaceVisitError::Namespace(source) => FixedLinkActivationError::Namespace(source),
        NamespaceVisitError::Visitor(source) => FixedLinkActivationError::Link(source),
    }
}

impl Drop for ProvisionalLinkActivation {
    fn drop(&mut self) {
        match (self.addressed.take(), self.links.take()) {
            (None, None) => {}
            (Some(addressed), Some(links)) => {
                drop_activation_state(addressed, links.into_retirement());
            }
            _ => std::process::abort(),
        }
    }
}

impl Drop for AuthorizedIpv4AddrgenNone {
    fn drop(&mut self) {
        match (self.addressed.take(), self.links.take()) {
            (None, None) => {}
            (Some(addressed), Some(links)) => {
                drop_activation_state(addressed, links.into_retirement());
            }
            _ => std::process::abort(),
        }
    }
}

impl Drop for AuthorizedActivatedTopology {
    fn drop(&mut self) {
        match (self.addressed.take(), self.links.take()) {
            (None, None) => {}
            (Some(addressed), Some(links)) => {
                drop_activation_state(addressed, links.into_retirement());
            }
            _ => std::process::abort(),
        }
    }
}

impl Drop for AuthorizedEndpointRoutes {
    fn drop(&mut self) {
        match self.activated.take() {
            None => {
                if self.routes.iter().any(Option::is_some) {
                    std::process::abort();
                }
            }
            Some(activated) => {
                let routes = take_route_retirements(&mut self.routes);
                drop(activated.into_deleted_topology(routes));
            }
        }
    }
}

impl Drop for AuthorizedDeletedTopology {
    fn drop(&mut self) {
        if self.addressed.is_some()
            || self.absence.is_some()
            || self.route_retirements.iter().any(Option::is_some)
        {
            // The higher mount/network layer did not authorize affine release.
            // Abort before either armed lower Drop field can execute.
            std::process::abort();
        }
    }
}

fn drop_activation_state(addressed: AuthorizedIpv4Addresses, retirement: FixedLinkRetirement) {
    match retirement {
        FixedLinkRetirement::Untouched => drop(addressed),
        FixedLinkRetirement::Deleted(pending) => {
            drop(complete_raw_link_retirement(
                addressed,
                pending,
                [None, None],
            ));
        }
    }
}

impl Drop for AuthorizedIpv4Addresses {
    fn drop(&mut self) {
        if self.journal.armed {
            let veth_pairs = self
                .veth_pairs
                .as_ref()
                .unwrap_or_else(|| std::process::abort());
            let rollback_failed = self.journal.rollback(veth_pairs).is_err();
            if rollback_failed && self.journal.armed {
                std::process::abort();
            }
        }
    }
}

fn map_ipv4_visit_error(
    error: NamespaceVisitError<FixedIpv4AddressSetError>,
) -> FixedIpv4AddressSetError {
    match error {
        NamespaceVisitError::Namespace(source) => FixedIpv4AddressSetError::Namespace(source),
        NamespaceVisitError::Visitor(source) => source,
    }
}

fn require_distinct_pair(
    parent: ObjectIdentity,
    alpha: ObjectIdentity,
    omega: ObjectIdentity,
    alpha_mount_id: u64,
    omega_mount_id: u64,
) -> Result<(), NamespacePinError> {
    if parent == alpha
        || parent == omega
        || alpha == omega
        || alpha_mount_id == 0
        || omega_mount_id == 0
        || alpha_mount_id == omega_mount_id
    {
        return Err(NamespacePinError::Unsafe(
            "parent, A, B, and their visible mounts are not distinct",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use std::{
        cell::{Cell, RefCell},
        rc::Rc,
    };

    use super::*;

    #[test]
    fn namespace_visit_orders_are_exact_reverses() {
        assert_eq!(
            FORWARD_NAMESPACE_VISIT_ORDER,
            [NamespaceEndpoint::A, NamespaceEndpoint::B]
        );
        assert_eq!(
            REVERSE_NAMESPACE_VISIT_ORDER,
            [NamespaceEndpoint::B, NamespaceEndpoint::A]
        );
        assert_eq!(
            FORWARD_NAMESPACE_VISIT_ORDER.map(NamespaceEndpoint::index),
            [0, 1]
        );
        assert_eq!(
            REVERSE_NAMESPACE_VISIT_ORDER.map(NamespaceEndpoint::index),
            [1, 0]
        );
    }

    struct RetryMountJournal {
        events: Rc<RefCell<Vec<&'static str>>>,
        armed: bool,
        attempts: usize,
    }

    impl RetryMountJournal {
        fn rollback(&mut self) -> Result<(), ()> {
            self.attempts += 1;
            if self.attempts == 1 {
                self.events.borrow_mut().push("first unmount failed");
                Err(())
            } else {
                self.events.borrow_mut().push("drop retry unmounted");
                self.armed = false;
                Ok(())
            }
        }
    }

    impl Drop for RetryMountJournal {
        fn drop(&mut self) {
            assert!(
                !self.armed || self.rollback().is_ok(),
                "mock mount cleanup retry failed"
            );
        }
    }

    struct BackingOwner(Rc<RefCell<Vec<&'static str>>>);

    impl Drop for BackingOwner {
        fn drop(&mut self) {
            self.0.borrow_mut().push("backing owner dropped");
        }
    }

    struct RollbackHarness {
        // This is the same safety-critical declaration order as
        // `AuthorizedNamespacePins`: mount cleanup precedes backing cleanup.
        mounts: RetryMountJournal,
        backing: Option<BackingOwner>,
    }

    impl RollbackHarness {
        fn rollback(mut self) -> Result<BackingOwner, ()> {
            let cleanup = self.mounts.rollback();
            take_backing_after_cleanup(cleanup, &mut self.backing, || ())
        }
    }

    struct RetryVethJournal {
        events: Rc<RefCell<Vec<&'static str>>>,
        armed: bool,
        attempts: usize,
    }

    impl RetryVethJournal {
        fn rollback(&mut self) -> Result<(), ()> {
            self.attempts += 1;
            if self.attempts == 1 {
                self.events.borrow_mut().push("first veth rollback failed");
                Err(())
            } else {
                self.events.borrow_mut().push("drop retry deleted links");
                self.armed = false;
                Ok(())
            }
        }
    }

    impl Drop for RetryVethJournal {
        fn drop(&mut self) {
            assert!(
                !self.armed || self.rollback().is_ok(),
                "mock veth cleanup retry failed"
            );
        }
    }

    struct NamespacePinsOwner(Rc<RefCell<Vec<&'static str>>>);

    impl Drop for NamespacePinsOwner {
        fn drop(&mut self) {
            self.0.borrow_mut().push("namespace owner dropped");
        }
    }

    struct VethRollbackHarness {
        // This mirrors `AuthorizedVethPairs`: links must disappear before the
        // namespace owner and its target descriptors may be dropped.
        veths: RetryVethJournal,
        namespace_pins: Option<NamespacePinsOwner>,
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ModelNetworkNamespace {
        Parent,
        Endpoint(NamespaceEndpoint),
    }

    struct ModelVethPairOwner {
        events: Rc<RefCell<Vec<&'static str>>>,
        live: Rc<Cell<bool>>,
        proof_valid: Rc<Cell<bool>>,
    }

    impl ModelVethPairOwner {
        fn verify(&self) -> Result<(), ()> {
            if self.live.get() && self.proof_valid.get() {
                Ok(())
            } else {
                Err(())
            }
        }
    }

    impl Drop for ModelVethPairOwner {
        fn drop(&mut self) {
            assert!(self.live.replace(false), "model veth owner dropped twice");
            self.events.borrow_mut().push("veth pair owner dropped");
        }
    }

    struct ModelIpv4AddressOwner {
        specification: FixedIpv4Address,
        veth_live: Rc<Cell<bool>>,
        events: Rc<RefCell<Vec<&'static str>>>,
        armed: bool,
    }

    impl ModelIpv4AddressOwner {
        fn rollback(mut self, current: ModelNetworkNamespace) {
            assert!(self.veth_live.get(), "address outlived its veth owner");
            assert_eq!(
                current,
                model_namespace_for(self.specification),
                "address rolled back from the wrong namespace"
            );
            self.events
                .borrow_mut()
                .push(model_rollback_event(self.specification));
            self.armed = false;
        }
    }

    impl Drop for ModelIpv4AddressOwner {
        fn drop(&mut self) {
            assert!(!self.armed, "armed model address owner was dropped");
        }
    }

    struct PartialIpv4AddressJournal {
        parent: [Option<ModelIpv4AddressOwner>; ENDPOINT_COUNT],
        endpoints: [Option<ModelIpv4AddressOwner>; ENDPOINT_COUNT],
        veth_live: Rc<Cell<bool>>,
        events: Rc<RefCell<Vec<&'static str>>>,
        current: Rc<Cell<ModelNetworkNamespace>>,
        armed: bool,
    }

    impl PartialIpv4AddressJournal {
        fn new(
            veth_live: Rc<Cell<bool>>,
            events: Rc<RefCell<Vec<&'static str>>>,
            current: Rc<Cell<ModelNetworkNamespace>>,
        ) -> Self {
            Self {
                parent: [None, None],
                endpoints: [None, None],
                veth_live,
                events,
                current,
                armed: true,
            }
        }

        fn stage(
            &mut self,
            specification: FixedIpv4Address,
            fail_at: Option<FixedIpv4Address>,
        ) -> Result<(), ()> {
            assert!(self.veth_live.get(), "staging lost its veth owner");
            assert_eq!(
                self.current.get(),
                model_namespace_for(specification),
                "address staged in the wrong namespace"
            );
            if fail_at == Some(specification) {
                self.events
                    .borrow_mut()
                    .push(model_failure_event(specification));
                return Err(());
            }

            self.events
                .borrow_mut()
                .push(model_stage_event(specification));
            let owner = ModelIpv4AddressOwner {
                specification,
                veth_live: Rc::clone(&self.veth_live),
                events: Rc::clone(&self.events),
                armed: true,
            };
            match specification {
                FixedIpv4Address::ParentA => {
                    assert!(self.parent[0].replace(owner).is_none());
                }
                FixedIpv4Address::ParentB => {
                    assert!(self.parent[1].replace(owner).is_none());
                }
                FixedIpv4Address::EndpointA => {
                    assert!(self.endpoints[0].replace(owner).is_none());
                }
                FixedIpv4Address::EndpointB => {
                    assert!(self.endpoints[1].replace(owner).is_none());
                }
            }
            Ok(())
        }

        fn rollback(&mut self, pairs: &ModelVethPairOwner) -> Result<(), ()> {
            assert!(self.armed, "model journal rolled back twice");
            assert!(Rc::ptr_eq(&self.veth_live, &pairs.live));
            pairs.verify()?;
            let endpoints = &mut self.endpoints;
            model_visit_network_namespaces(
                REVERSE_NAMESPACE_VISIT_ORDER,
                &self.current,
                &self.events,
                |endpoint, current| {
                    if let Some(address) = endpoints[endpoint.index()].take() {
                        address.rollback(current);
                    }
                    Ok::<(), ()>(())
                },
            )
            .expect("model reverse namespace visit");
            for index in (0..ENDPOINT_COUNT).rev() {
                if let Some(address) = self.parent[index].take() {
                    address.rollback(self.current.get());
                }
            }
            assert!(self.parent.iter().all(Option::is_none));
            assert!(self.endpoints.iter().all(Option::is_none));
            assert_eq!(self.current.get(), ModelNetworkNamespace::Parent);
            assert!(pairs.live.get(), "veth owner was released during cleanup");
            self.events
                .borrow_mut()
                .push("veth pair owner retained through address rollback");
            self.armed = false;
            Ok(())
        }
    }

    impl Drop for PartialIpv4AddressJournal {
        fn drop(&mut self) {
            assert!(!self.armed, "armed model address journal was dropped");
        }
    }

    struct ModelAuthorizedIpv4Addresses {
        journal: PartialIpv4AddressJournal,
        veth_pairs: Option<ModelVethPairOwner>,
    }

    impl ModelAuthorizedIpv4Addresses {
        fn new(
            veth_pairs: ModelVethPairOwner,
            events: Rc<RefCell<Vec<&'static str>>>,
            current: Rc<Cell<ModelNetworkNamespace>>,
        ) -> Self {
            Self {
                journal: PartialIpv4AddressJournal::new(
                    Rc::clone(&veth_pairs.live),
                    events,
                    current,
                ),
                veth_pairs: Some(veth_pairs),
            }
        }

        fn veth_pairs(&self) -> &ModelVethPairOwner {
            self.veth_pairs
                .as_ref()
                .expect("model veth owner must remain present")
        }

        fn rollback_addresses(&mut self) -> Result<(), ()> {
            let veth_pairs = self
                .veth_pairs
                .as_ref()
                .expect("model veth owner must remain present");
            self.journal.rollback(veth_pairs)
        }

        fn rollback(mut self) -> Result<ModelVethPairOwner, ()> {
            self.rollback_addresses()?;
            Ok(self
                .veth_pairs
                .take()
                .expect("model veth owner must be returned once"))
        }
    }

    impl Drop for ModelAuthorizedIpv4Addresses {
        fn drop(&mut self) {
            if self.journal.armed {
                assert!(
                    self.rollback_addresses().is_ok(),
                    "model aggregate cleanup could not prove its veth authority"
                );
            }
        }
    }

    fn model_visit_network_namespaces<VisitorError>(
        order: [NamespaceEndpoint; ENDPOINT_COUNT],
        current: &Cell<ModelNetworkNamespace>,
        events: &RefCell<Vec<&'static str>>,
        mut visitor: impl FnMut(NamespaceEndpoint, ModelNetworkNamespace) -> Result<(), VisitorError>,
    ) -> Result<(), VisitorError> {
        assert_eq!(current.get(), ModelNetworkNamespace::Parent);
        for endpoint in order {
            events.borrow_mut().push(model_enter_event(endpoint));
            let entered = ModelNetworkNamespace::Endpoint(endpoint);
            current.set(entered);
            let result = visitor(endpoint, entered);
            current.set(ModelNetworkNamespace::Parent);
            events.borrow_mut().push(model_restore_event(endpoint));
            result?;
        }
        assert_eq!(current.get(), ModelNetworkNamespace::Parent);
        Ok(())
    }

    fn stage_complete_model_ipv4_addresses(
        events: &Rc<RefCell<Vec<&'static str>>>,
        current: &Rc<Cell<ModelNetworkNamespace>>,
        live: &Rc<Cell<bool>>,
        proof_valid: &Rc<Cell<bool>>,
    ) -> ModelAuthorizedIpv4Addresses {
        let pairs = ModelVethPairOwner {
            events: Rc::clone(events),
            live: Rc::clone(live),
            proof_valid: Rc::clone(proof_valid),
        };
        let mut addresses =
            ModelAuthorizedIpv4Addresses::new(pairs, Rc::clone(events), Rc::clone(current));
        addresses
            .journal
            .stage(FixedIpv4Address::ParentA, None)
            .expect("stage parent A");
        addresses
            .journal
            .stage(FixedIpv4Address::ParentB, None)
            .expect("stage parent B");
        model_visit_network_namespaces(
            FORWARD_NAMESPACE_VISIT_ORDER,
            current,
            events,
            |endpoint, _current| {
                addresses.journal.stage(
                    match endpoint {
                        NamespaceEndpoint::A => FixedIpv4Address::EndpointA,
                        NamespaceEndpoint::B => FixedIpv4Address::EndpointB,
                    },
                    None,
                )
            },
        )
        .expect("stage endpoint addresses");
        addresses
    }

    fn run_partial_ipv4_staging(fail_at: FixedIpv4Address) -> Vec<&'static str> {
        let events = Rc::new(RefCell::new(Vec::new()));
        let current = Rc::new(Cell::new(ModelNetworkNamespace::Parent));
        let live = Rc::new(Cell::new(true));
        let proof_valid = Rc::new(Cell::new(true));
        {
            let pairs = ModelVethPairOwner {
                events: Rc::clone(&events),
                live: Rc::clone(&live),
                proof_valid,
            };
            {
                let mut addresses = ModelAuthorizedIpv4Addresses::new(
                    pairs,
                    Rc::clone(&events),
                    Rc::clone(&current),
                );
                let staged = (|| {
                    addresses
                        .journal
                        .stage(FixedIpv4Address::ParentA, Some(fail_at))?;
                    addresses
                        .journal
                        .stage(FixedIpv4Address::ParentB, Some(fail_at))?;
                    model_visit_network_namespaces(
                        FORWARD_NAMESPACE_VISIT_ORDER,
                        &current,
                        &events,
                        |endpoint, _current| {
                            addresses.journal.stage(
                                match endpoint {
                                    NamespaceEndpoint::A => FixedIpv4Address::EndpointA,
                                    NamespaceEndpoint::B => FixedIpv4Address::EndpointB,
                                },
                                Some(fail_at),
                            )
                        },
                    )
                })();
                assert_eq!(staged, Err(()));
                assert_eq!(current.get(), ModelNetworkNamespace::Parent);
                assert!(addresses.veth_pairs().live.get());
                addresses
                    .rollback_addresses()
                    .expect("model partial address rollback");
            }
        }
        assert!(!live.get());
        assert_eq!(current.get(), ModelNetworkNamespace::Parent);
        let observed = events.borrow().clone();
        observed
    }

    const fn model_namespace_for(specification: FixedIpv4Address) -> ModelNetworkNamespace {
        match specification {
            FixedIpv4Address::ParentA | FixedIpv4Address::ParentB => ModelNetworkNamespace::Parent,
            FixedIpv4Address::EndpointA => ModelNetworkNamespace::Endpoint(NamespaceEndpoint::A),
            FixedIpv4Address::EndpointB => ModelNetworkNamespace::Endpoint(NamespaceEndpoint::B),
        }
    }

    const fn model_stage_event(specification: FixedIpv4Address) -> &'static str {
        match specification {
            FixedIpv4Address::ParentA => "stage parent A",
            FixedIpv4Address::ParentB => "stage parent B",
            FixedIpv4Address::EndpointA => "stage endpoint A",
            FixedIpv4Address::EndpointB => "stage endpoint B",
        }
    }

    const fn model_failure_event(specification: FixedIpv4Address) -> &'static str {
        match specification {
            FixedIpv4Address::ParentA => "fail parent A",
            FixedIpv4Address::ParentB => "fail parent B",
            FixedIpv4Address::EndpointA => "fail endpoint A",
            FixedIpv4Address::EndpointB => "fail endpoint B",
        }
    }

    const fn model_rollback_event(specification: FixedIpv4Address) -> &'static str {
        match specification {
            FixedIpv4Address::ParentA => "rollback parent A",
            FixedIpv4Address::ParentB => "rollback parent B",
            FixedIpv4Address::EndpointA => "rollback endpoint A",
            FixedIpv4Address::EndpointB => "rollback endpoint B",
        }
    }

    const fn model_enter_event(endpoint: NamespaceEndpoint) -> &'static str {
        match endpoint {
            NamespaceEndpoint::A => "enter endpoint A",
            NamespaceEndpoint::B => "enter endpoint B",
        }
    }

    const fn model_restore_event(endpoint: NamespaceEndpoint) -> &'static str {
        match endpoint {
            NamespaceEndpoint::A => "restore parent from endpoint A",
            NamespaceEndpoint::B => "restore parent from endpoint B",
        }
    }

    impl VethRollbackHarness {
        fn rollback(mut self) -> Result<NamespacePinsOwner, ()> {
            let cleanup = self.veths.rollback();
            take_backing_after_cleanup(cleanup, &mut self.namespace_pins, || ())
        }
    }

    #[test]
    fn current_network_namespace_has_exact_type_owner_and_nsfs_identity() {
        let current = NetworkNamespace::capture_current().expect("capture current netns");
        current.verify().expect("verify current netns");
        assert_ne!(current.identity.device, 0);
        assert_ne!(current.identity.inode, 0);
        assert_ne!(current.owner_identity.inode, 0);
    }

    #[test]
    fn first_mount_rollback_failure_retries_before_backing_owner_drop() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let state = RollbackHarness {
            mounts: RetryMountJournal {
                events: Rc::clone(&events),
                armed: true,
                attempts: 0,
            },
            backing: Some(BackingOwner(Rc::clone(&events))),
        };

        assert!(state.rollback().is_err());
        assert_eq!(
            *events.borrow(),
            [
                "first unmount failed",
                "drop retry unmounted",
                "backing owner dropped",
            ]
        );
    }

    #[test]
    fn first_veth_rollback_failure_retries_before_namespace_owner_drop() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let state = VethRollbackHarness {
            veths: RetryVethJournal {
                events: Rc::clone(&events),
                armed: true,
                attempts: 0,
            },
            namespace_pins: Some(NamespacePinsOwner(Rc::clone(&events))),
        };

        assert!(state.rollback().is_err());
        assert_eq!(
            *events.borrow(),
            [
                "first veth rollback failed",
                "drop retry deleted links",
                "namespace owner dropped",
            ]
        );
    }

    #[test]
    fn successful_ipv4_rollback_returns_the_live_veth_owner_after_reverse_cleanup() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let current = Rc::new(Cell::new(ModelNetworkNamespace::Parent));
        let live = Rc::new(Cell::new(true));
        let proof_valid = Rc::new(Cell::new(true));
        let addresses = stage_complete_model_ipv4_addresses(&events, &current, &live, &proof_valid);

        let pairs = addresses.rollback().expect("model address rollback");
        assert!(pairs.live.get());
        assert_eq!(current.get(), ModelNetworkNamespace::Parent);
        assert_eq!(
            *events.borrow(),
            [
                "stage parent A",
                "stage parent B",
                "enter endpoint A",
                "stage endpoint A",
                "restore parent from endpoint A",
                "enter endpoint B",
                "stage endpoint B",
                "restore parent from endpoint B",
                "enter endpoint B",
                "rollback endpoint B",
                "restore parent from endpoint B",
                "enter endpoint A",
                "rollback endpoint A",
                "restore parent from endpoint A",
                "rollback parent B",
                "rollback parent A",
                "veth pair owner retained through address rollback",
            ]
        );
        drop(pairs);
        assert!(!live.get());
        assert_eq!(
            events.borrow().last().copied(),
            Some("veth pair owner dropped")
        );
    }

    #[test]
    fn automatic_ipv4_aggregate_drop_cleans_addresses_before_veth_authority() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let current = Rc::new(Cell::new(ModelNetworkNamespace::Parent));
        let live = Rc::new(Cell::new(true));
        let proof_valid = Rc::new(Cell::new(true));
        let addresses = stage_complete_model_ipv4_addresses(&events, &current, &live, &proof_valid);
        events.borrow_mut().clear();

        drop(addresses);

        assert!(!live.get());
        assert_eq!(current.get(), ModelNetworkNamespace::Parent);
        assert_eq!(
            *events.borrow(),
            [
                "enter endpoint B",
                "rollback endpoint B",
                "restore parent from endpoint B",
                "enter endpoint A",
                "rollback endpoint A",
                "restore parent from endpoint A",
                "rollback parent B",
                "rollback parent A",
                "veth pair owner retained through address rollback",
                "veth pair owner dropped",
            ]
        );
    }

    #[test]
    fn failed_precleanup_pair_proof_retains_every_armed_authority_without_cleanup() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let current = Rc::new(Cell::new(ModelNetworkNamespace::Parent));
        let live = Rc::new(Cell::new(true));
        let proof_valid = Rc::new(Cell::new(true));
        let mut addresses =
            stage_complete_model_ipv4_addresses(&events, &current, &live, &proof_valid);
        events.borrow_mut().clear();
        proof_valid.set(false);

        assert_eq!(addresses.rollback_addresses(), Err(()));
        assert!(events.borrow().is_empty());
        assert!(addresses.journal.armed);
        assert!(addresses.journal.parent.iter().all(Option::is_some));
        assert!(addresses.journal.endpoints.iter().all(Option::is_some));
        assert!(addresses.veth_pairs().live.get());
        assert_eq!(current.get(), ModelNetworkNamespace::Parent);

        proof_valid.set(true);
        drop(addresses);
        assert!(!live.get());
    }

    #[test]
    fn parent_b_staging_failure_rolls_back_parent_a_before_veth_owner_release() {
        assert_eq!(
            run_partial_ipv4_staging(FixedIpv4Address::ParentB),
            [
                "stage parent A",
                "fail parent B",
                "enter endpoint B",
                "restore parent from endpoint B",
                "enter endpoint A",
                "restore parent from endpoint A",
                "rollback parent A",
                "veth pair owner retained through address rollback",
                "veth pair owner dropped",
            ]
        );
    }

    #[test]
    fn endpoint_a_staging_failure_restores_parent_then_rolls_back_parent_b_a() {
        assert_eq!(
            run_partial_ipv4_staging(FixedIpv4Address::EndpointA),
            [
                "stage parent A",
                "stage parent B",
                "enter endpoint A",
                "fail endpoint A",
                "restore parent from endpoint A",
                "enter endpoint B",
                "restore parent from endpoint B",
                "enter endpoint A",
                "restore parent from endpoint A",
                "rollback parent B",
                "rollback parent A",
                "veth pair owner retained through address rollback",
                "veth pair owner dropped",
            ]
        );
    }

    #[test]
    fn endpoint_b_staging_failure_rolls_back_endpoint_a_then_parent_b_a() {
        assert_eq!(
            run_partial_ipv4_staging(FixedIpv4Address::EndpointB),
            [
                "stage parent A",
                "stage parent B",
                "enter endpoint A",
                "stage endpoint A",
                "restore parent from endpoint A",
                "enter endpoint B",
                "fail endpoint B",
                "restore parent from endpoint B",
                "enter endpoint B",
                "restore parent from endpoint B",
                "enter endpoint A",
                "rollback endpoint A",
                "restore parent from endpoint A",
                "rollback parent B",
                "rollback parent A",
                "veth pair owner retained through address rollback",
                "veth pair owner dropped",
            ]
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ModelLinkOperation {
        NoneParentA,
        NoneParentB,
        NoneEndpointA,
        NoneEndpointB,
        UpParentA,
        UpParentB,
        UpEndpointA,
        UpEndpointB,
    }

    const MODEL_LINK_OPERATIONS: [ModelLinkOperation; 8] = [
        ModelLinkOperation::NoneParentA,
        ModelLinkOperation::NoneParentB,
        ModelLinkOperation::NoneEndpointA,
        ModelLinkOperation::NoneEndpointB,
        ModelLinkOperation::UpParentA,
        ModelLinkOperation::UpParentB,
        ModelLinkOperation::UpEndpointA,
        ModelLinkOperation::UpEndpointB,
    ];

    impl ModelLinkOperation {
        const fn event(self) -> &'static str {
            match self {
                Self::NoneParentA => "set NONE parent A",
                Self::NoneParentB => "set NONE parent B",
                Self::NoneEndpointA => "set NONE endpoint A",
                Self::NoneEndpointB => "set NONE endpoint B",
                Self::UpParentA => "set UP parent A",
                Self::UpParentB => "set UP parent B",
                Self::UpEndpointA => "set UP endpoint A",
                Self::UpEndpointB => "set UP endpoint B",
            }
        }

        const fn namespace(self) -> ModelNetworkNamespace {
            match self {
                Self::NoneParentA | Self::NoneParentB | Self::UpParentA | Self::UpParentB => {
                    ModelNetworkNamespace::Parent
                }
                Self::NoneEndpointA | Self::UpEndpointA => {
                    ModelNetworkNamespace::Endpoint(NamespaceEndpoint::A)
                }
                Self::NoneEndpointB | Self::UpEndpointB => {
                    ModelNetworkNamespace::Endpoint(NamespaceEndpoint::B)
                }
            }
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ModelLinkFailure {
        NotSent,
        Rejected,
        AppliedAckLost,
        MalformedAck,
    }

    impl ModelLinkFailure {
        const fn event(self) -> &'static str {
            match self {
                Self::NotSent => "link request not sent",
                Self::Rejected => "link request rejected",
                Self::AppliedAckLost => "link request applied with lost ACK",
                Self::MalformedAck => "link request returned malformed ACK",
            }
        }
    }

    const MODEL_LINK_FAILURES: [ModelLinkFailure; 4] = [
        ModelLinkFailure::NotSent,
        ModelLinkFailure::Rejected,
        ModelLinkFailure::AppliedAckLost,
        ModelLinkFailure::MalformedAck,
    ];

    struct ModelActivationPins {
        events: Rc<RefCell<Vec<&'static str>>>,
    }

    impl Drop for ModelActivationPins {
        fn drop(&mut self) {
            self.events.borrow_mut().push("namespace pins dropped");
        }
    }

    struct ModelActivationAddressedAuthority {
        events: Rc<RefCell<Vec<&'static str>>>,
        addresses_armed: [bool; 4],
        address_lineage_valid: [bool; 4],
        pairs_armed: [bool; ENDPOINT_COUNT],
        pairs_live: [bool; ENDPOINT_COUNT],
        pair_lineage_valid: [bool; ENDPOINT_COUNT],
        endpoint_absence_valid: [bool; ENDPOINT_COUNT],
        parent_absence_valid: bool,
        pins: Option<ModelActivationPins>,
    }

    impl ModelActivationAddressedAuthority {
        fn new(events: Rc<RefCell<Vec<&'static str>>>) -> Self {
            Self {
                pins: Some(ModelActivationPins {
                    events: Rc::clone(&events),
                }),
                events,
                addresses_armed: [true; 4],
                address_lineage_valid: [true; 4],
                pairs_armed: [true; ENDPOINT_COUNT],
                pairs_live: [true; ENDPOINT_COUNT],
                pair_lineage_valid: [true; ENDPOINT_COUNT],
                endpoint_absence_valid: [true; ENDPOINT_COUNT],
                parent_absence_valid: true,
            }
        }

        fn delete_pairs_reverse(&mut self) -> Result<(), ()> {
            let mut failed = false;
            for endpoint in REVERSE_NAMESPACE_VISIT_ORDER {
                let index = endpoint.index();
                if !self.pairs_live[index] {
                    continue;
                }
                if !self.pair_lineage_valid[index] {
                    self.events.borrow_mut().push(match endpoint {
                        NamespaceEndpoint::A => "reject wrong pair A lineage",
                        NamespaceEndpoint::B => "reject wrong pair B lineage",
                    });
                    failed = true;
                    continue;
                }
                self.events.borrow_mut().push(match endpoint {
                    NamespaceEndpoint::A => "delete pair A",
                    NamespaceEndpoint::B => "delete pair B",
                });
                self.pairs_live[index] = false;
            }
            if failed { Err(()) } else { Ok(()) }
        }

        fn prove_absence(&mut self, current: &Cell<ModelNetworkNamespace>) -> Result<(), ()> {
            if self.pairs_live != [false; ENDPOINT_COUNT] {
                return Err(());
            }
            for endpoint in REVERSE_NAMESPACE_VISIT_ORDER {
                self.events.borrow_mut().push(model_enter_event(endpoint));
                current.set(ModelNetworkNamespace::Endpoint(endpoint));
                let index = endpoint.index();
                let endpoint_valid = self.endpoint_absence_valid[index];
                if endpoint_valid {
                    self.events.borrow_mut().push(match endpoint {
                        NamespaceEndpoint::A => "prove pair A endpoint absent",
                        NamespaceEndpoint::B => "prove pair B endpoint absent",
                    });
                }
                current.set(ModelNetworkNamespace::Parent);
                self.events.borrow_mut().push(model_restore_event(endpoint));
                if !endpoint_valid {
                    return Err(());
                }
            }
            if !self.parent_absence_valid {
                return Err(());
            }
            self.events
                .borrow_mut()
                .push("prove both parent links absent");
            Ok(())
        }

        fn disarm_after_absence(&mut self) -> ModelActivationPins {
            assert_eq!(self.pairs_live, [false; ENDPOINT_COUNT]);
            assert!(self.parent_absence_valid);
            assert_eq!(self.endpoint_absence_valid, [true; ENDPOINT_COUNT]);
            assert_eq!(self.address_lineage_valid, [true; 4]);
            assert_eq!(self.pair_lineage_valid, [true; ENDPOINT_COUNT]);
            for (index, event) in [
                "disarm endpoint B address",
                "disarm endpoint A address",
                "disarm parent B address",
                "disarm parent A address",
            ]
            .into_iter()
            .enumerate()
            {
                let address_index = [3, 2, 1, 0][index];
                assert!(self.addresses_armed[address_index]);
                self.addresses_armed[address_index] = false;
                self.events.borrow_mut().push(event);
            }
            for endpoint in REVERSE_NAMESPACE_VISIT_ORDER {
                let index = endpoint.index();
                assert!(self.pairs_armed[index]);
                self.pairs_armed[index] = false;
                self.events.borrow_mut().push(match endpoint {
                    NamespaceEndpoint::A => "disarm pair A",
                    NamespaceEndpoint::B => "disarm pair B",
                });
            }
            self.events.borrow_mut().push("release namespace pins");
            self.pins
                .take()
                .expect("model namespace pins must be released exactly once")
        }
    }

    impl Drop for ModelActivationAddressedAuthority {
        fn drop(&mut self) {
            assert_eq!(
                self.addresses_armed, [false; 4],
                "activation owner attempted ordinary address rollback"
            );
            assert_eq!(
                self.pairs_armed, [false; ENDPOINT_COUNT],
                "activation owner attempted ordinary veth rollback"
            );
            assert!(
                self.pins.is_none(),
                "activation owner leaked namespace pins"
            );
        }
    }

    struct ModelActivationCore {
        // This mirrors the production requirement: the original Drop type is
        // retained whole in an Option and is never destructured after SETLINK.
        addressed: Option<ModelActivationAddressedAuthority>,
        events: Rc<RefCell<Vec<&'static str>>>,
        current: Rc<Cell<ModelNetworkNamespace>>,
        completed_operations: usize,
    }

    impl ModelActivationCore {
        fn new(
            events: Rc<RefCell<Vec<&'static str>>>,
            current: Rc<Cell<ModelNetworkNamespace>>,
        ) -> Self {
            Self {
                addressed: Some(ModelActivationAddressedAuthority::new(Rc::clone(&events))),
                events,
                current,
                completed_operations: 0,
            }
        }

        fn stage(
            &mut self,
            operation: ModelLinkOperation,
            failure: Option<ModelLinkFailure>,
        ) -> Result<(), ()> {
            assert_eq!(MODEL_LINK_OPERATIONS[self.completed_operations], operation);
            assert_eq!(self.current.get(), ModelNetworkNamespace::Parent);
            let endpoint = match operation.namespace() {
                ModelNetworkNamespace::Parent => None,
                ModelNetworkNamespace::Endpoint(endpoint) => {
                    self.events.borrow_mut().push(model_enter_event(endpoint));
                    self.current.set(ModelNetworkNamespace::Endpoint(endpoint));
                    Some(endpoint)
                }
            };
            assert_eq!(self.current.get(), operation.namespace());
            self.events.borrow_mut().push(operation.event());
            let result = if let Some(failure) = failure {
                self.events.borrow_mut().push(failure.event());
                Err(())
            } else {
                self.completed_operations += 1;
                Ok(())
            };
            if let Some(endpoint) = endpoint {
                self.current.set(ModelNetworkNamespace::Parent);
                self.events.borrow_mut().push(model_restore_event(endpoint));
            }
            result
        }

        fn begin_retirement(&mut self) -> Result<ModelDeletedTopology, ()> {
            let addressed = self
                .addressed
                .as_mut()
                .expect("model addressed owner must remain present until retirement");
            addressed.delete_pairs_reverse()?;
            addressed.prove_absence(&self.current)?;
            assert_eq!(self.current.get(), ModelNetworkNamespace::Parent);
            Ok(ModelDeletedTopology {
                addressed: self.addressed.take(),
                route_retirements: [false; ENDPOINT_COUNT],
                route_lineage_valid: [true; ENDPOINT_COUNT],
            })
        }
    }

    impl Drop for ModelActivationCore {
        fn drop(&mut self) {
            if self.addressed.is_some() {
                if let Ok(deleted) = self.begin_retirement() {
                    drop(deleted);
                } else {
                    self.events
                        .borrow_mut()
                        .push("abort after failed raw retirement");
                    if let Some(addressed) = self.addressed.take() {
                        std::mem::forget(addressed);
                    }
                }
            }
        }
    }

    struct ModelDeletedTopology {
        addressed: Option<ModelActivationAddressedAuthority>,
        route_retirements: [bool; ENDPOINT_COUNT],
        route_lineage_valid: [bool; ENDPOINT_COUNT],
    }

    impl std::fmt::Debug for ModelDeletedTopology {
        fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
            formatter
                .debug_struct("ModelDeletedTopology")
                .field("addressed", &self.addressed.is_some())
                .field("route_retirements", &self.route_retirements)
                .field("route_lineage_valid", &self.route_lineage_valid)
                .finish()
        }
    }

    impl ModelDeletedTopology {
        fn finish_after_pristine_network_proof(
            &mut self,
            proof_valid: bool,
        ) -> Result<ModelActivationPins, ()> {
            let addressed = self
                .addressed
                .as_ref()
                .expect("deleted topology must retain its addressed owner");
            if !proof_valid
                || self
                    .route_retirements
                    .iter()
                    .zip(self.route_lineage_valid)
                    .any(|(armed, valid)| *armed && !valid)
                || addressed.address_lineage_valid != [true; 4]
                || addressed.pair_lineage_valid != [true; ENDPOINT_COUNT]
            {
                return Err(());
            }
            let addressed = self
                .addressed
                .as_mut()
                .expect("deleted topology must retain its addressed owner");
            addressed.events.borrow_mut().push("prove pristine network");
            for endpoint in REVERSE_NAMESPACE_VISIT_ORDER {
                let index = endpoint.index();
                if self.route_retirements[index] {
                    self.route_retirements[index] = false;
                    addressed.events.borrow_mut().push(match endpoint {
                        NamespaceEndpoint::A => "retire route A",
                        NamespaceEndpoint::B => "retire route B",
                    });
                }
            }
            let pins = addressed.disarm_after_absence();
            drop(
                self.addressed
                    .take()
                    .expect("deleted addressed owner must be consumed after disarm"),
            );
            Ok(pins)
        }
    }

    impl Drop for ModelDeletedTopology {
        fn drop(&mut self) {
            if let Some(addressed) = self.addressed.take() {
                addressed
                    .events
                    .borrow_mut()
                    .push("abort before unproven authority release");
                std::mem::forget(addressed);
            }
        }
    }

    struct ModelProvisionalActivation {
        core: Option<ModelActivationCore>,
    }

    impl ModelProvisionalActivation {
        fn new(
            events: Rc<RefCell<Vec<&'static str>>>,
            current: Rc<Cell<ModelNetworkNamespace>>,
        ) -> Self {
            Self {
                core: Some(ModelActivationCore::new(events, current)),
            }
        }

        fn stage_none(
            &mut self,
            operation: ModelLinkOperation,
            failure: Option<ModelLinkFailure>,
        ) -> Result<(), ()> {
            assert!(self.core().completed_operations < 4);
            self.core_mut().stage(operation, failure)
        }

        fn finish_none(
            mut self,
            proof_valid: bool,
        ) -> Result<ModelAllNoneActivation, ModelDeletedTopology> {
            assert_eq!(self.core().completed_operations, 4);
            self.core().events.borrow_mut().push("prove all links NONE");
            if !proof_valid {
                return Err(self.begin_retirement());
            }
            Ok(ModelAllNoneActivation {
                core: self.core.take(),
            })
        }

        fn begin_retirement(mut self) -> ModelDeletedTopology {
            let deleted = self
                .core_mut()
                .begin_retirement()
                .expect("model provisional raw retirement");
            drop(self.core.take());
            deleted
        }

        fn core(&self) -> &ModelActivationCore {
            self.core
                .as_ref()
                .expect("model provisional core must remain owned")
        }

        fn core_mut(&mut self) -> &mut ModelActivationCore {
            self.core
                .as_mut()
                .expect("model provisional core must remain owned")
        }
    }

    impl Drop for ModelProvisionalActivation {
        fn drop(&mut self) {
            drop(self.core.take());
        }
    }

    struct ModelAllNoneActivation {
        core: Option<ModelActivationCore>,
    }

    impl ModelAllNoneActivation {
        fn stage_up(
            &mut self,
            operation: ModelLinkOperation,
            failure: Option<ModelLinkFailure>,
        ) -> Result<(), ()> {
            assert!((4..8).contains(&self.core().completed_operations));
            self.core_mut().stage(operation, failure)
        }

        fn finish_up(
            mut self,
            proof_valid: bool,
        ) -> Result<ModelActivatedTopology, ModelDeletedTopology> {
            assert_eq!(self.core().completed_operations, 8);
            self.core().events.borrow_mut().push("prove all links UP");
            if !proof_valid {
                return Err(self.begin_retirement());
            }
            Ok(ModelActivatedTopology {
                core: self.core.take(),
            })
        }

        fn begin_retirement(mut self) -> ModelDeletedTopology {
            let deleted = self
                .core_mut()
                .begin_retirement()
                .expect("model all-NONE raw retirement");
            drop(self.core.take());
            deleted
        }

        fn core(&self) -> &ModelActivationCore {
            self.core
                .as_ref()
                .expect("model all-NONE core must remain owned")
        }

        fn core_mut(&mut self) -> &mut ModelActivationCore {
            self.core
                .as_mut()
                .expect("model all-NONE core must remain owned")
        }
    }

    impl Drop for ModelAllNoneActivation {
        fn drop(&mut self) {
            drop(self.core.take());
        }
    }

    struct ModelActivatedTopology {
        core: Option<ModelActivationCore>,
    }

    impl ModelActivatedTopology {
        fn core_mut(&mut self) -> &mut ModelActivationCore {
            self.core
                .as_mut()
                .expect("model activated core must remain owned")
        }

        fn begin_retirement(mut self) -> ModelDeletedTopology {
            let deleted = self
                .core_mut()
                .begin_retirement()
                .expect("model activated raw retirement");
            drop(self.core.take());
            deleted
        }
    }

    impl Drop for ModelActivatedTopology {
        fn drop(&mut self) {
            drop(self.core.take());
        }
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum ModelRouteFailure {
        BeforeMutation,
        Rejected,
        DeletionBound,
    }

    struct ModelRoutedTopology {
        activated: Option<ModelActivatedTopology>,
        route_owners: [bool; ENDPOINT_COUNT],
    }

    impl ModelRoutedTopology {
        fn begin_retirement(mut self) -> ModelDeletedTopology {
            let mut deleted = self
                .activated
                .take()
                .expect("model routed topology must retain active authority")
                .begin_retirement();
            deleted.route_retirements = self.route_owners;
            self.route_owners = [false; ENDPOINT_COUNT];
            deleted
        }
    }

    impl Drop for ModelRoutedTopology {
        fn drop(&mut self) {
            if let Some(activated) = self.activated.take() {
                let mut deleted = activated.begin_retirement();
                deleted.route_retirements = self.route_owners;
                self.route_owners = [false; ENDPOINT_COUNT];
                drop(deleted);
            }
        }
    }

    fn model_install_endpoint_routes(
        activated: ModelActivatedTopology,
        fail_at: Option<(NamespaceEndpoint, ModelRouteFailure)>,
    ) -> Result<ModelRoutedTopology, (ModelRouteFailure, ModelDeletedTopology)> {
        let mut route_authorities = [false; ENDPOINT_COUNT];
        for endpoint in FORWARD_NAMESPACE_VISIT_ORDER {
            let index = endpoint.index();
            let events = &activated
                .core
                .as_ref()
                .expect("model activated authority")
                .events;
            events.borrow_mut().push(model_enter_event(endpoint));
            events.borrow_mut().push(match endpoint {
                NamespaceEndpoint::A => "install route A",
                NamespaceEndpoint::B => "install route B",
            });
            let failure = fail_at
                .filter(|(failed_endpoint, _)| *failed_endpoint == endpoint)
                .map(|(_, failure)| failure);
            if !matches!(
                failure,
                Some(ModelRouteFailure::BeforeMutation | ModelRouteFailure::Rejected)
            ) {
                route_authorities[index] = true;
            }
            events.borrow_mut().push(model_restore_event(endpoint));
            if let Some(failure) = failure {
                let mut deleted = activated.begin_retirement();
                deleted.route_retirements = route_authorities;
                return Err((failure, deleted));
            }
        }
        Ok(ModelRoutedTopology {
            activated: Some(activated),
            route_owners: route_authorities,
        })
    }

    fn model_stage_all_none(
        provisional: &mut ModelProvisionalActivation,
        fail_at: Option<(usize, ModelLinkFailure)>,
    ) -> Result<(), ()> {
        for (index, operation) in MODEL_LINK_OPERATIONS[..4].iter().copied().enumerate() {
            provisional.stage_none(
                operation,
                fail_at
                    .filter(|(failure_index, _)| *failure_index == index)
                    .map(|(_, failure)| failure),
            )?;
        }
        Ok(())
    }

    fn model_stage_all_up(
        all_none: &mut ModelAllNoneActivation,
        fail_at: Option<(usize, ModelLinkFailure)>,
    ) -> Result<(), ()> {
        for (index, operation) in MODEL_LINK_OPERATIONS[4..].iter().copied().enumerate() {
            let absolute_index = index + 4;
            all_none.stage_up(
                operation,
                fail_at
                    .filter(|(failure_index, _)| *failure_index == absolute_index)
                    .map(|(_, failure)| failure),
            )?;
        }
        Ok(())
    }

    fn model_complete_activation(
        events: &Rc<RefCell<Vec<&'static str>>>,
        current: &Rc<Cell<ModelNetworkNamespace>>,
    ) -> ModelActivatedTopology {
        let mut provisional =
            ModelProvisionalActivation::new(Rc::clone(events), Rc::clone(current));
        model_stage_all_none(&mut provisional, None).expect("model stage all NONE");
        let mut all_none = provisional.finish_none(true).expect("model all-NONE proof");
        model_stage_all_up(&mut all_none, None).expect("model stage all UP");
        all_none.finish_up(true).expect("model all-UP proof")
    }

    fn assert_model_raw_retirement(events: &[&'static str]) {
        let pair_b = events
            .iter()
            .rposition(|event| *event == "delete pair B")
            .expect("model retirement must delete pair B");
        let pair_a = events
            .iter()
            .rposition(|event| *event == "delete pair A")
            .expect("model retirement must delete pair A");
        assert!(pair_b < pair_a, "model pair retirement was not B then A");
        let endpoint_b = events
            .iter()
            .rposition(|event| *event == "prove pair B endpoint absent")
            .expect("model retirement must prove endpoint B absent");
        let endpoint_a = events
            .iter()
            .rposition(|event| *event == "prove pair A endpoint absent")
            .expect("model retirement must prove endpoint A absent");
        let parent = events
            .iter()
            .rposition(|event| *event == "prove both parent links absent")
            .expect("model retirement must reprove parent absence");
        assert!(pair_a < endpoint_b && endpoint_b < endpoint_a && endpoint_a < parent);
    }

    fn assert_model_finished_retirement(events: &[&'static str]) {
        assert_model_raw_retirement(events);
        assert!(events.ends_with(&[
            "prove pristine network",
            "disarm endpoint B address",
            "disarm endpoint A address",
            "disarm parent B address",
            "disarm parent A address",
            "disarm pair B",
            "disarm pair A",
            "release namespace pins",
            "namespace pins dropped",
        ]));
    }

    #[test]
    fn every_route_failure_preserves_exact_authority_through_direct_pair_deletion() {
        for endpoint in FORWARD_NAMESPACE_VISIT_ORDER {
            for failure in [
                ModelRouteFailure::BeforeMutation,
                ModelRouteFailure::Rejected,
                ModelRouteFailure::DeletionBound,
            ] {
                let events = Rc::new(RefCell::new(Vec::new()));
                let current = Rc::new(Cell::new(ModelNetworkNamespace::Parent));
                let activated = model_complete_activation(&events, &current);
                events.borrow_mut().clear();
                let (observed, mut deleted) =
                    match model_install_endpoint_routes(activated, Some((endpoint, failure))) {
                        Ok(_) => panic!("model route failure was accepted"),
                        Err(failure) => failure,
                    };
                assert_eq!(observed, failure);
                let expected = match (endpoint, failure) {
                    (NamespaceEndpoint::A, ModelRouteFailure::DeletionBound) => [true, false],
                    (NamespaceEndpoint::A, _) => [false, false],
                    (NamespaceEndpoint::B, ModelRouteFailure::DeletionBound) => [true, true],
                    (NamespaceEndpoint::B, _) => [true, false],
                };
                assert_eq!(deleted.route_retirements, expected);
                assert_model_raw_retirement(&events.borrow());
                assert!(
                    !events
                        .borrow()
                        .iter()
                        .any(|event| event.contains("rollback"))
                );

                let pins = deleted
                    .finish_after_pristine_network_proof(true)
                    .expect("finish model route-failure retirement");
                let observed = events.borrow();
                let route_b = observed.iter().position(|event| *event == "retire route B");
                let route_a = observed.iter().position(|event| *event == "retire route A");
                if expected[1] {
                    assert!(route_b.is_some());
                } else {
                    assert!(route_b.is_none());
                }
                if expected[0] {
                    let route_a = route_a.expect("route A retirement");
                    if let Some(route_b) = route_b {
                        assert!(route_b < route_a);
                    }
                    let first_address = observed
                        .iter()
                        .position(|event| *event == "disarm endpoint B address")
                        .expect("address retirement");
                    assert!(route_a < first_address);
                } else {
                    assert!(route_a.is_none());
                }
                drop(observed);
                drop(pins);
                assert_eq!(current.get(), ModelNetworkNamespace::Parent);
            }
        }
    }

    #[test]
    fn routed_retirement_prevalidates_all_routes_before_disarming_any_owner() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let current = Rc::new(Cell::new(ModelNetworkNamespace::Parent));
        let activated = model_complete_activation(&events, &current);
        let routed = model_install_endpoint_routes(activated, None).expect("model routed topology");
        events.borrow_mut().clear();
        let mut deleted = routed.begin_retirement();
        deleted.route_lineage_valid[1] = false;
        let events_before = events.borrow().len();

        assert!(deleted.finish_after_pristine_network_proof(true).is_err());
        assert_eq!(deleted.route_retirements, [true, true]);
        let addressed = deleted
            .addressed
            .as_ref()
            .expect("retained addressed authority");
        assert_eq!(addressed.addresses_armed, [true; 4]);
        assert_eq!(addressed.pairs_armed, [true; ENDPOINT_COUNT]);
        assert_eq!(events.borrow().len(), events_before);

        deleted.route_lineage_valid = [true; ENDPOINT_COUNT];
        let pins = deleted
            .finish_after_pristine_network_proof(true)
            .expect("valid routed retirement");
        let observed = events.borrow();
        let route_b = observed
            .iter()
            .position(|event| *event == "retire route B")
            .expect("route B retirement");
        let route_a = observed
            .iter()
            .position(|event| *event == "retire route A")
            .expect("route A retirement");
        let first_address = observed
            .iter()
            .position(|event| *event == "disarm endpoint B address")
            .expect("address retirement");
        assert!(route_b < route_a && route_a < first_address);
        drop(observed);
        drop(pins);
    }

    #[test]
    fn every_partial_link_stage_failure_directly_retires_pairs_without_lower_rollback() {
        for failure_index in 0..MODEL_LINK_OPERATIONS.len() {
            for failure in MODEL_LINK_FAILURES {
                let events = Rc::new(RefCell::new(Vec::new()));
                let current = Rc::new(Cell::new(ModelNetworkNamespace::Parent));
                let mut provisional =
                    ModelProvisionalActivation::new(Rc::clone(&events), Rc::clone(&current));
                if failure_index < 4 {
                    assert_eq!(
                        model_stage_all_none(&mut provisional, Some((failure_index, failure)),),
                        Err(())
                    );
                    let mut deleted = provisional.begin_retirement();
                    let pins = deleted
                        .finish_after_pristine_network_proof(true)
                        .expect("finish failed-NONE retirement");
                    drop(pins);
                } else {
                    model_stage_all_none(&mut provisional, None)
                        .expect("stage pre-failure NONE operations");
                    let mut all_none = provisional
                        .finish_none(true)
                        .expect("prove pre-failure all-NONE state");
                    assert_eq!(
                        model_stage_all_up(&mut all_none, Some((failure_index, failure))),
                        Err(())
                    );
                    let mut deleted = all_none.begin_retirement();
                    let pins = deleted
                        .finish_after_pristine_network_proof(true)
                        .expect("finish failed-UP retirement");
                    drop(pins);
                }
                let observed = events.borrow();
                assert!(observed.contains(&failure.event()));
                assert!(!observed.iter().any(|event| event.contains("rollback")));
                assert_model_finished_retirement(&observed);
                assert_eq!(current.get(), ModelNetworkNamespace::Parent);
            }
        }
    }

    #[test]
    fn none_and_up_barrier_failures_drop_through_direct_pair_retirement() {
        for fail_none_barrier in [true, false] {
            let events = Rc::new(RefCell::new(Vec::new()));
            let current = Rc::new(Cell::new(ModelNetworkNamespace::Parent));
            let mut provisional =
                ModelProvisionalActivation::new(Rc::clone(&events), Rc::clone(&current));
            model_stage_all_none(&mut provisional, None).expect("stage all NONE");
            let mut deleted = if fail_none_barrier {
                match provisional.finish_none(false) {
                    Err(deleted) => deleted,
                    Ok(_) => panic!("invalid all-NONE barrier was accepted"),
                }
            } else {
                let mut all_none = provisional.finish_none(true).expect("all-NONE proof");
                model_stage_all_up(&mut all_none, None).expect("stage all UP");
                match all_none.finish_up(false) {
                    Err(deleted) => deleted,
                    Ok(_) => panic!("invalid all-UP barrier was accepted"),
                }
            };
            let pins = deleted
                .finish_after_pristine_network_proof(true)
                .expect("finish barrier-failure retirement");
            drop(pins);
            assert_model_finished_retirement(&events.borrow());
            assert_eq!(current.get(), ModelNetworkNamespace::Parent);
        }
    }

    #[test]
    fn deleted_topology_returns_pins_only_after_external_pristine_proof() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let current = Rc::new(Cell::new(ModelNetworkNamespace::Parent));
        let activated = model_complete_activation(&events, &current);
        let mut deleted = activated.begin_retirement();
        assert!(deleted.finish_after_pristine_network_proof(false).is_err());
        let addressed = deleted
            .addressed
            .as_ref()
            .expect("unproved deleted authority must remain owned");
        assert_eq!(addressed.addresses_armed, [true; 4]);
        assert_eq!(addressed.pairs_armed, [true; ENDPOINT_COUNT]);
        assert!(
            !events
                .borrow()
                .iter()
                .any(|event| event.starts_with("disarm"))
        );

        let pins = deleted
            .finish_after_pristine_network_proof(true)
            .expect("model pristine retirement barrier");
        assert_eq!(current.get(), ModelNetworkNamespace::Parent);
        assert!(events.borrow().ends_with(&[
            "prove pristine network",
            "disarm endpoint B address",
            "disarm endpoint A address",
            "disarm parent B address",
            "disarm parent A address",
            "disarm pair B",
            "disarm pair A",
            "release namespace pins",
        ]));
        assert!(!events.borrow().contains(&"namespace pins dropped"));
        drop(pins);
        assert_eq!(
            events.borrow().last().copied(),
            Some("namespace pins dropped")
        );
    }

    #[test]
    fn deleted_wrong_lineage_prevalidation_disarms_nothing_and_retains_authority() {
        for corrupt_address in [true, false] {
            let events = Rc::new(RefCell::new(Vec::new()));
            let current = Rc::new(Cell::new(ModelNetworkNamespace::Parent));
            let activated = model_complete_activation(&events, &current);
            let mut deleted = activated.begin_retirement();
            let events_before_prevalidation = events.borrow().len();
            {
                let addressed = deleted.addressed.as_mut().expect("deleted model authority");
                if corrupt_address {
                    addressed.address_lineage_valid[3] = false;
                } else {
                    addressed.pair_lineage_valid[1] = false;
                }
            }

            assert!(deleted.finish_after_pristine_network_proof(true).is_err());
            let addressed = deleted
                .addressed
                .as_mut()
                .expect("failed prevalidation must retain authority");
            assert_eq!(addressed.addresses_armed, [true; 4]);
            assert_eq!(addressed.pairs_armed, [true; ENDPOINT_COUNT]);
            assert_eq!(events.borrow().len(), events_before_prevalidation);
            addressed.address_lineage_valid = [true; 4];
            addressed.pair_lineage_valid = [true; ENDPOINT_COUNT];

            let pins = deleted
                .finish_after_pristine_network_proof(true)
                .expect("retry valid retirement prevalidation");
            drop(pins);
            assert_model_finished_retirement(&events.borrow());
            assert_eq!(current.get(), ModelNetworkNamespace::Parent);
        }
    }

    #[test]
    fn wrong_pair_lineage_never_disarms_and_retry_deletes_only_owned_lineage() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let current = Rc::new(Cell::new(ModelNetworkNamespace::Parent));
        let mut activated = model_complete_activation(&events, &current);
        events.borrow_mut().clear();
        {
            let addressed = activated
                .core_mut()
                .addressed
                .as_mut()
                .expect("model addressed authority");
            addressed.pair_lineage_valid[1] = false;
        }

        assert!(activated.core_mut().begin_retirement().is_err());
        {
            let core = activated.core_mut();
            let addressed = core.addressed.as_mut().expect("authority retained");
            assert_eq!(addressed.addresses_armed, [true; 4]);
            assert_eq!(addressed.pairs_armed, [true; ENDPOINT_COUNT]);
            assert_eq!(addressed.pairs_live, [false, true]);
            addressed.pair_lineage_valid[1] = true;
        }
        assert_eq!(
            *events.borrow(),
            ["reject wrong pair B lineage", "delete pair A"]
        );

        let mut deleted = activated.begin_retirement();
        let pins = deleted
            .finish_after_pristine_network_proof(true)
            .expect("finish retried exact retirement");
        assert!(
            !events
                .borrow()
                .iter()
                .any(|event| event.contains("rollback"))
        );
        assert_eq!(current.get(), ModelNetworkNamespace::Parent);
        drop(pins);
    }

    #[test]
    fn partial_absence_proof_retains_all_journals_for_idempotent_drop_retry() {
        let events = Rc::new(RefCell::new(Vec::new()));
        let current = Rc::new(Cell::new(ModelNetworkNamespace::Parent));
        let mut activated = model_complete_activation(&events, &current);
        events.borrow_mut().clear();
        activated
            .core_mut()
            .addressed
            .as_mut()
            .expect("model addressed authority")
            .endpoint_absence_valid[1] = false;

        assert!(activated.core_mut().begin_retirement().is_err());
        {
            let addressed = activated
                .core_mut()
                .addressed
                .as_mut()
                .expect("authority retained after partial proof");
            assert_eq!(addressed.pairs_live, [false; ENDPOINT_COUNT]);
            assert_eq!(addressed.addresses_armed, [true; 4]);
            assert_eq!(addressed.pairs_armed, [true; ENDPOINT_COUNT]);
            addressed.endpoint_absence_valid[1] = true;
        }
        assert_eq!(current.get(), ModelNetworkNamespace::Parent);
        assert!(
            !events
                .borrow()
                .iter()
                .any(|event| event.starts_with("disarm"))
        );

        let mut deleted = activated.begin_retirement();
        let pins = deleted
            .finish_after_pristine_network_proof(true)
            .expect("finish idempotent proof retry");
        drop(pins);
        assert_model_finished_retirement(&events.borrow());
        assert_eq!(current.get(), ModelNetworkNamespace::Parent);
    }

    #[test]
    fn automatic_drop_proves_raw_absence_then_aborts_before_unproved_release() {
        for phase in 0..3 {
            let events = Rc::new(RefCell::new(Vec::new()));
            let current = Rc::new(Cell::new(ModelNetworkNamespace::Parent));
            let mut provisional =
                ModelProvisionalActivation::new(Rc::clone(&events), Rc::clone(&current));
            provisional
                .stage_none(ModelLinkOperation::NoneParentA, None)
                .expect("stage first NONE operation");
            if phase == 0 {
                drop(provisional);
            } else {
                for operation in MODEL_LINK_OPERATIONS[1..4].iter().copied() {
                    provisional
                        .stage_none(operation, None)
                        .expect("stage remaining NONE operation");
                }
                let mut all_none = provisional.finish_none(true).expect("all-NONE proof");
                if phase == 1 {
                    drop(all_none);
                } else {
                    model_stage_all_up(&mut all_none, None).expect("stage all UP");
                    let activated = all_none.finish_up(true).expect("all-UP proof");
                    drop(activated);
                }
            }
            assert_model_raw_retirement(&events.borrow());
            assert_eq!(
                events.borrow().last().copied(),
                Some("abort before unproven authority release")
            );
            assert!(
                !events
                    .borrow()
                    .iter()
                    .any(|event| event.starts_with("disarm"))
            );
            assert!(!events.borrow().contains(&"namespace pins dropped"));
            assert_eq!(current.get(), ModelNetworkNamespace::Parent);
        }
    }

    #[test]
    fn canonical_mount_point_is_fixed_and_rejects_non_leaf_input() {
        assert_eq!(
            canonical_mount_point("vpl-0123456789abcdef0123456789abcdef-a")
                .expect("canonical mount point"),
            "/run/netns/vpl-0123456789abcdef0123456789abcdef-a"
        );
        for invalid in ["", ".", "..", "a/b", "nonascii-é"] {
            assert!(canonical_mount_point(invalid).is_err(), "{invalid:?}");
        }
    }

    #[test]
    fn pair_proof_rejects_namespace_aliases_and_mount_aliases() {
        let parent = ObjectIdentity {
            device: 1,
            inode: 1,
        };
        let alpha = ObjectIdentity {
            device: 1,
            inode: 2,
        };
        let omega = ObjectIdentity {
            device: 1,
            inode: 3,
        };
        require_distinct_pair(parent, alpha, omega, 10, 11).expect("distinct pair");
        assert!(require_distinct_pair(parent, parent, omega, 10, 11).is_err());
        assert!(require_distinct_pair(parent, alpha, alpha, 10, 11).is_err());
        assert!(require_distinct_pair(parent, alpha, omega, 10, 10).is_err());
        assert!(require_distinct_pair(parent, alpha, omega, 0, 11).is_err());
    }

    #[test]
    fn package_test_process_cannot_claim_the_pid_one_transition() {
        if getpid().as_raw() != 1 || gettid().as_raw_pid() != 1 {
            assert!(TaskIdentity::require_pid_one().is_err());
        }
    }
}
