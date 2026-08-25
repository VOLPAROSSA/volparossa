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
    ownership::{AuthorizedPrivateRun, AuthorizedPrivateRunError, NamespacePinTarget},
    veth::{
        FixedVethEndpoint, FixedVethPair, VethCreateError, VethRollbackError, VethVerifyError,
        create_fixed_veth_pair,
    },
};

const CURRENT_NETWORK_NAMESPACE: &str = "/proc/thread-self/ns/net";
const PRIVATE_NETNS_PREFIX: &str = "/run/netns/";
const NSFS_MAGIC: FsWord = 0x6e73_6673;
const ENDPOINT_COUNT: usize = 2;

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
/// grants only the fixed borrowed four-address sub-transaction; it grants no
/// link-up, explicit-route, forwarding, firewall, probe, dataplane,
/// ownership-manifest, or topology-ready authority.
pub(crate) struct AuthorizedVethPairs {
    veths: VethPairJournal,
    namespace_pins: Option<AuthorizedNamespacePins>,
    _thread_bound: PhantomData<Rc<()>>,
}

struct FixedIpv4AddressJournal<'pairs> {
    // Address owners precede the borrowed pair authority so field teardown
    // cannot release the borrow before reverse address cleanup is attempted.
    parent: [Option<FixedIpv4AddressOwner<'pairs>>; ENDPOINT_COUNT],
    endpoints: [Option<FixedIpv4AddressOwner<'pairs>>; ENDPOINT_COUNT],
    pairs: &'pairs AuthorizedVethPairs,
    armed: bool,
}

/// Scoped affine authority for all four fixed IPv4 addresses.
///
/// The state borrows the veth-pair owner, so the links and namespace pins
/// cannot be consumed while any address remains live. Dropping it performs
/// exact reverse cleanup inside B, A and then the parent namespace. It grants
/// no link-up, explicit-route, forwarding, firewall, packet, or readiness authority.
#[must_use = "dropping an armed fixed IPv4 address set triggers fail-closed rollback"]
pub(crate) struct AuthorizedIpv4Addresses<'pairs> {
    journal: FixedIpv4AddressJournal<'pairs>,
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

    /// Borrow the exact pair owner into one scoped four-address transaction.
    pub(crate) fn configure_fixed_ipv4_addresses(
        &self,
    ) -> Result<AuthorizedIpv4Addresses<'_>, FixedIpv4AddressSetError> {
        self.verify().map_err(FixedIpv4AddressSetError::Veth)?;
        let pairs = self.fixed_pairs();
        let namespace_pins = self.namespace_pins();
        let mut journal = FixedIpv4AddressJournal::new(self);

        let staged = (|| {
            journal.parent[0] = Some(
                add_fixed_ipv4_address(
                    FixedIpv4Address::ParentA,
                    pairs[0],
                    &namespace_pins.parent.descriptor,
                )
                .map_err(FixedIpv4AddressSetError::Add)?,
            );
            journal.parent[1] = Some(
                add_fixed_ipv4_address(
                    FixedIpv4Address::ParentB,
                    pairs[1],
                    &namespace_pins.parent.descriptor,
                )
                .map_err(FixedIpv4AddressSetError::Add)?,
            );
            let endpoint_descriptors = [
                &namespace_pins.mounts.entries[0].namespace.descriptor,
                &namespace_pins.mounts.entries[1].namespace.descriptor,
            ];
            self.visit_network_namespaces(|endpoint| {
                let index = endpoint.index();
                let specification = match endpoint {
                    NamespaceEndpoint::A => FixedIpv4Address::EndpointA,
                    NamespaceEndpoint::B => FixedIpv4Address::EndpointB,
                };
                journal.endpoints[index] = Some(
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
            return match journal.rollback() {
                Ok(()) => Err(error),
                Err(cleanup) => Err(cleanup),
            };
        }
        journal.verify()?;
        Ok(AuthorizedIpv4Addresses {
            journal,
            _thread_bound: PhantomData,
        })
    }

    /// Delete B then A, prove both absent, and recover the unchanged pin owner.
    pub(crate) fn rollback(mut self) -> Result<AuthorizedNamespacePins, VethPairError> {
        self.verify()?;
        let cleanup = self.veths.rollback();
        let namespace_pins = take_backing_after_cleanup(cleanup, &mut self.namespace_pins, || {
            VethPairError::Unsafe("namespace-pin owner was consumed before veth rollback")
        })?;
        let backing = namespace_pins.verify().map_err(VethPairError::Namespace);
        match backing {
            Ok(()) => Ok(namespace_pins),
            Err(error) => Err(error),
        }
    }

    fn namespace_pins(&self) -> &AuthorizedNamespacePins {
        self.namespace_pins
            .as_ref()
            .unwrap_or_else(|| std::process::abort())
    }
}

impl<'pairs> FixedIpv4AddressJournal<'pairs> {
    fn new(pairs: &'pairs AuthorizedVethPairs) -> Self {
        Self {
            parent: [None, None],
            endpoints: [None, None],
            pairs,
            armed: true,
        }
    }

    fn verify(&self) -> Result<(), FixedIpv4AddressSetError> {
        if !self.armed {
            return Err(FixedIpv4AddressSetError::Unsafe(
                "fixed IPv4 address journal is disarmed",
            ));
        }
        self.pairs
            .verify()
            .map_err(FixedIpv4AddressSetError::Veth)?;
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
            parent.verify().map_err(FixedIpv4AddressSetError::Verify)?;
        }
        let mut visited = [false, false];
        self.pairs
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
                address.verify().map_err(FixedIpv4AddressSetError::Verify)?;
                visited[index] = true;
                Ok(())
            })
            .map_err(map_ipv4_visit_error)?;
        if visited != [true, true] {
            return Err(FixedIpv4AddressSetError::Unsafe(
                "fixed endpoint IPv4 address visit was incomplete",
            ));
        }
        self.pairs.verify().map_err(FixedIpv4AddressSetError::Veth)
    }

    fn owners(&self) -> [&FixedIpv4AddressOwner<'pairs>; 4] {
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

    fn rollback(&mut self) -> Result<(), FixedIpv4AddressSetError> {
        if !self.armed {
            return Ok(());
        }
        let mut first_error = None;
        let endpoint_addresses = &mut self.endpoints;
        let visited = self.pairs.visit_network_namespaces_reverse(|endpoint| {
            let index = endpoint.index();
            if let Some(address) = endpoint_addresses[index].take() {
                if let Err(error) = address.rollback() {
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
                if let Err(error) = address.rollback() {
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
        self.pairs
            .verify()
            .map_err(FixedIpv4AddressSetError::Veth)?;
        first_error.map_or(Ok(()), Err)
    }
}

impl Drop for FixedIpv4AddressJournal<'_> {
    fn drop(&mut self) {
        if self.armed {
            let rollback_failed = self.rollback().is_err();
            if rollback_failed && self.armed {
                std::process::abort();
            }
        }
    }
}

impl AuthorizedIpv4Addresses<'_> {
    /// Freshly reprove all four address, namespace, interface, and veth bindings.
    pub(crate) fn verify(&self) -> Result<(), FixedIpv4AddressSetError> {
        self.journal.verify()
    }

    /// Borrow the four affine owners as parent A, endpoint A, parent B, endpoint B.
    pub(crate) fn owners(&self) -> [&FixedIpv4AddressOwner<'_>; 4] {
        self.journal.owners()
    }

    /// Remove endpoint B/A then parent B/A and prove every address absent.
    pub(crate) fn rollback(mut self) -> Result<(), FixedIpv4AddressSetError> {
        self.verify()?;
        self.journal.rollback()
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
    }

    impl Drop for ModelVethPairOwner {
        fn drop(&mut self) {
            assert!(self.live.replace(false), "model veth owner dropped twice");
            self.events.borrow_mut().push("veth pair owner dropped");
        }
    }

    struct ModelIpv4AddressOwner<'pairs> {
        specification: FixedIpv4Address,
        pairs: &'pairs ModelVethPairOwner,
        events: Rc<RefCell<Vec<&'static str>>>,
        armed: bool,
    }

    impl ModelIpv4AddressOwner<'_> {
        fn rollback(mut self, current: ModelNetworkNamespace) {
            assert!(self.pairs.live.get(), "address outlived its veth owner");
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

    impl Drop for ModelIpv4AddressOwner<'_> {
        fn drop(&mut self) {
            assert!(!self.armed, "armed model address owner was dropped");
        }
    }

    struct PartialIpv4AddressJournal<'pairs> {
        parent: [Option<ModelIpv4AddressOwner<'pairs>>; ENDPOINT_COUNT],
        endpoints: [Option<ModelIpv4AddressOwner<'pairs>>; ENDPOINT_COUNT],
        pairs: &'pairs ModelVethPairOwner,
        events: Rc<RefCell<Vec<&'static str>>>,
        current: Rc<Cell<ModelNetworkNamespace>>,
        armed: bool,
    }

    impl<'pairs> PartialIpv4AddressJournal<'pairs> {
        fn new(
            pairs: &'pairs ModelVethPairOwner,
            events: Rc<RefCell<Vec<&'static str>>>,
            current: Rc<Cell<ModelNetworkNamespace>>,
        ) -> Self {
            Self {
                parent: [None, None],
                endpoints: [None, None],
                pairs,
                events,
                current,
                armed: true,
            }
        }

        fn stage(
            &mut self,
            specification: FixedIpv4Address,
            fail_at: FixedIpv4Address,
        ) -> Result<(), ()> {
            assert!(self.pairs.live.get(), "staging lost its veth owner");
            assert_eq!(
                self.current.get(),
                model_namespace_for(specification),
                "address staged in the wrong namespace"
            );
            if specification == fail_at {
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
                pairs: self.pairs,
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

        fn rollback(&mut self) {
            assert!(self.armed, "model journal rolled back twice");
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
            assert!(
                self.pairs.live.get(),
                "veth owner was released during cleanup"
            );
            self.events
                .borrow_mut()
                .push("veth pair owner retained through address rollback");
            self.armed = false;
        }
    }

    impl Drop for PartialIpv4AddressJournal<'_> {
        fn drop(&mut self) {
            assert!(!self.armed, "armed model address journal was dropped");
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

    fn run_partial_ipv4_staging(fail_at: FixedIpv4Address) -> Vec<&'static str> {
        let events = Rc::new(RefCell::new(Vec::new()));
        let current = Rc::new(Cell::new(ModelNetworkNamespace::Parent));
        let live = Rc::new(Cell::new(true));
        {
            let pairs = ModelVethPairOwner {
                events: Rc::clone(&events),
                live: Rc::clone(&live),
            };
            {
                let mut journal =
                    PartialIpv4AddressJournal::new(&pairs, Rc::clone(&events), Rc::clone(&current));
                let staged = (|| {
                    journal.stage(FixedIpv4Address::ParentA, fail_at)?;
                    journal.stage(FixedIpv4Address::ParentB, fail_at)?;
                    model_visit_network_namespaces(
                        FORWARD_NAMESPACE_VISIT_ORDER,
                        &current,
                        &events,
                        |endpoint, _current| {
                            journal.stage(
                                match endpoint {
                                    NamespaceEndpoint::A => FixedIpv4Address::EndpointA,
                                    NamespaceEndpoint::B => FixedIpv4Address::EndpointB,
                                },
                                fail_at,
                            )
                        },
                    )
                })();
                assert_eq!(staged, Err(()));
                assert_eq!(current.get(), ModelNetworkNamespace::Parent);
                journal.rollback();
            }
            assert!(pairs.live.get());
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
