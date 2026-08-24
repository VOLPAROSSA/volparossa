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

use super::ownership::{AuthorizedPrivateRun, AuthorizedPrivateRunError, NamespacePinTarget};

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

/// Failure from either the namespace excursion boundary or its read-only visitor.
#[derive(Debug)]
pub(crate) enum NamespaceVisitError<VisitorError> {
    /// Entering, proving, or restoring a network namespace failed.
    Namespace(NamespacePinError),
    /// The supplied read-only proof failed after exact parent restoration.
    Visitor(VisitorError),
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

/// Affine owner of exactly two live run-bound nsfs network-namespace pins.
///
/// The state retains both the lower empty-slot view and the visible nsfs view.
/// It owns no veth, address, route, firewall, ownership-manifest, or topology-ready authority.
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

    /// Visit A then B synchronously and restore the exact parent before every return.
    ///
    /// The visitor receives no namespace descriptor or mutation capability. A
    /// restoration failure takes precedence over a simultaneous visitor error;
    /// unwind also restores the parent or aborts the disposable PID-1 process.
    pub(crate) fn visit_network_namespaces<Visitor, VisitorError>(
        &self,
        mut visitor: Visitor,
    ) -> Result<(), NamespaceVisitError<VisitorError>>
    where
        Visitor: FnMut(NamespaceEndpoint) -> Result<(), VisitorError>,
    {
        self.verify().map_err(NamespaceVisitError::Namespace)?;
        for (endpoint, label) in self
            .mounts
            .entries
            .iter()
            .zip([NamespaceEndpoint::A, NamespaceEndpoint::B])
        {
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
                    "read-only namespace visit did not prove parent restoration",
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
        let private_run = self.private_run.take().ok_or(NamespacePinError::Unsafe(
            "authorized private-run owner was already consumed",
        ))?;
        let backing = private_run.verify();
        match (cleanup, backing) {
            (Ok(()), Ok(())) => Ok(private_run),
            (Err(error), _) => Err(error),
            (Ok(()), Err(error)) => Err(error.into()),
        }
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
    use super::*;

    #[test]
    fn current_network_namespace_has_exact_type_owner_and_nsfs_identity() {
        let current = NetworkNamespace::capture_current().expect("capture current netns");
        current.verify().expect("verify current netns");
        assert_ne!(current.identity.device, 0);
        assert_ne!(current.identity.inode, 0);
        assert_ne!(current.owner_identity.inode, 0);
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
