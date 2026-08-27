//! Fail-closed systemd descriptor-store observation and dormant publication adapter.
//!
//! Its publication adapter is reachable from the private live-proof selector and a private dormant
//! supervisor publisher, but neither is connected to the production server, engine, or request
//! path. It can publish one exact borrowed
//! pidfd/network-namespace pair to the current service's systemd descriptor store, wait for a
//! separate barrier acknowledgement, and attest the resulting manager inventory over D-Bus. The
//! caller retains both local owners throughout. Once the first `sendmsg(2)` is attempted, every
//! failure is classified as `ManagerMayOwn`. A separate callerless observer can classify that
//! exact poisoned in-process attempt as present, absent, or unresolved, but never clears the
//! poison or authorizes a resend. A read-only startup observer uses one manager barrier and two
//! uncached exact-service snapshots, then exposes only an opaque exact-set comparison against
//! inherited custody bindings. That observer never publishes descriptors. A separate dormant
//! removal adapter can remove one already-proven exact custody name, orders that notification with
//! a barrier, and accepts success only for the stable complete baseline-minus-pair inventory. It
//! has no production caller. This slice never sends `READY=1`.

use std::{
    collections::BTreeMap,
    env,
    ffi::OsStr,
    fmt,
    future::Future,
    io::{self, IoSlice},
    num::{NonZeroU32, NonZeroU64},
    os::{
        fd::{AsRawFd, BorrowedFd, OwnedFd, RawFd},
        unix::ffi::OsStrExt as _,
    },
    path::Path,
};

use nix::{
    fcntl::{FcntlArg, OFlag, fcntl},
    sys::{
        socket::{
            AddressFamily, ControlMessage, MsgFlags, SockFlag, SockType, UnixAddr, sendmsg, socket,
        },
        stat::{fstat, major, minor},
    },
    unistd::{pipe2, read},
};
use tokio::io::unix::AsyncFd;
use zbus::{
    Connection, Proxy,
    names::OwnedUniqueName,
    proxy::{Builder as ProxyBuilder, CacheProperties},
    zvariant::OwnedObjectPath,
};

use crate::{
    deadline::HardDeadline,
    ownership_journal::{
        DurableCustodyDescriptorBinding, DurableCustodyDescriptorIdentity,
        DurableCustodyDescriptorIdentityParts, DurableCustodyNameDigest,
    },
    systemd_custody::{CUSTODY_FD_NAME_BYTES, CUSTODY_FD_NAME_PREFIX, custody_fd_name_is_valid},
};
const DESCRIPTORS_PER_CUSTODY: usize = 2;
const MAX_DESCRIPTOR_STORE_ENTRIES: usize = 128;
const MAX_DESCRIPTOR_STORE_ENTRIES_U32: u32 = 128;
const MAX_DESCRIPTOR_NAME_BYTES: usize = 255;
const MAX_DUMP_PATH_BYTES: usize = 4_096;
const MAX_CONTROL_GROUP_BYTES: usize = 4_096;
const MAX_CONTROL_GROUP_COMPONENTS: usize = 256;
const MAX_CONTROL_GROUP_COMPONENT_BYTES: usize = 255;
const MAX_ISOLATION_PROPERTY_BYTES: usize = 32;
const SYSTEMD_INVOCATION_ID_BYTES: usize = 16;
const FDSTORE_PREFIX: &[u8] = b"FDSTORE=1\nFDNAME=";
const FDSTORE_SUFFIX: &[u8] = b"\nFDPOLL=0";
const FDSTORE_MESSAGE_BYTES: usize =
    FDSTORE_PREFIX.len() + CUSTODY_FD_NAME_BYTES + FDSTORE_SUFFIX.len();
const FDSTORE_REMOVE_PREFIX: &[u8] = b"FDSTOREREMOVE=1\nFDNAME=";
const FDSTORE_REMOVE_MESSAGE_BYTES: usize = FDSTORE_REMOVE_PREFIX.len() + CUSTODY_FD_NAME_BYTES;
const BARRIER_MESSAGE: &[u8] = b"BARRIER=1";
const SYSTEMD_DESTINATION: &str = "org.freedesktop.systemd1";
const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const SYSTEMD_UNIT_INTERFACE: &str = "org.freedesktop.systemd1.Unit";
const SYSTEMD_SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";
const DBUS_DESTINATION: &str = "org.freedesktop.DBus";
const DBUS_PATH: &str = "/org/freedesktop/DBus";
const DBUS_INTERFACE: &str = "org.freedesktop.DBus";
static PRODUCTION_MANAGER_MUTATION_GATE: ManagerMutationGate = ManagerMutationGate::new();

/// One opaque, fixed-shape systemd descriptor-store name.
///
/// Construction is fixed from the typed durable digest, and the dormant worker binds that name to
/// its journal authority. Production publication/recovery composition remains later work. This type
/// intentionally exposes neither a `String` nor path authority.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct CustodyFdName([u8; CUSTODY_FD_NAME_BYTES]);

impl CustodyFdName {
    /// Convert the typed durable digest directly into the fixed descriptor-store name buffer.
    pub(crate) fn from_durable_digest(digest: DurableCustodyNameDigest) -> Self {
        let mut bytes = [0_u8; CUSTODY_FD_NAME_BYTES];
        let prefix = CUSTODY_FD_NAME_PREFIX.as_bytes();
        let encoded_digest = digest.encode_lower_hex();
        bytes[..prefix.len()].copy_from_slice(prefix);
        bytes[prefix.len()..].copy_from_slice(&encoded_digest);
        Self(bytes)
    }

    pub(crate) fn parse(value: &str) -> Result<Self, FdStoreError> {
        if !custody_fd_name_is_valid(value) {
            return Err(FdStoreError::InvalidCustodyName);
        }
        let mut bytes = [0_u8; CUSTODY_FD_NAME_BYTES];
        bytes.copy_from_slice(value.as_bytes());
        Ok(Self(bytes))
    }

    fn as_bytes(&self) -> &[u8; CUSTODY_FD_NAME_BYTES] {
        &self.0
    }
}

impl fmt::Debug for CustodyFdName {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CustodyFdName(<redacted>)")
    }
}

/// Opaque process-local identity of one descriptor-store send boundary.
///
/// The ID comes from the one monotonic manager-mutation sequence and exists only to prevent a stale
/// terminal from reconciling a newer attempt which happens to use the same deterministic custody
/// target. Its type prevents using a removal attempt as publication authority.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct PublicationAttemptId(NonZeroU64);

impl fmt::Debug for PublicationAttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicationAttemptId(<redacted>)")
    }
}

impl PublicationAttemptId {
    #[cfg(test)]
    pub(crate) fn for_test(value: u64) -> Self {
        Self(NonZeroU64::new(value).expect("test publication attempt ID must be nonzero"))
    }
}

/// Opaque process-local identity of one exact descriptor-store removal attempt. It shares the
/// manager-mutation sequence with publication while remaining a distinct authority type.
#[derive(Clone, Copy, Eq, PartialEq)]
pub(crate) struct RemovalAttemptId(NonZeroU64);

impl fmt::Debug for RemovalAttemptId {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemovalAttemptId(<redacted>)")
    }
}

impl RemovalAttemptId {
    #[cfg(test)]
    fn for_test(value: u64) -> Self {
        Self(NonZeroU64::new(value).expect("test removal attempt ID must be nonzero"))
    }
}

/// Two role-specific borrowed descriptors. Publication never consumes or duplicates these local
/// owners.
#[derive(Clone, Copy)]
pub(crate) struct BorrowedCustodyPair<'a> {
    pidfd: BorrowedFd<'a>,
    network_namespace: BorrowedFd<'a>,
}

impl<'a> BorrowedCustodyPair<'a> {
    pub(crate) fn new(
        pidfd: BorrowedFd<'a>,
        network_namespace: BorrowedFd<'a>,
    ) -> Result<Self, FdStoreError> {
        if pidfd.as_raw_fd() == network_namespace.as_raw_fd() {
            return Err(FdStoreError::DuplicateCustodyDescriptor);
        }
        Ok(Self {
            pidfd,
            network_namespace,
        })
    }

    fn raw_descriptors(self) -> [RawFd; DESCRIPTORS_PER_CUSTODY] {
        [self.pidfd.as_raw_fd(), self.network_namespace.as_raw_fd()]
    }

    fn identities(self) -> Result<[DescriptorIdentity; DESCRIPTORS_PER_CUSTODY], FdStoreError> {
        Ok([
            DescriptorIdentity::from_descriptor(self.pidfd)?,
            DescriptorIdentity::from_descriptor(self.network_namespace)?,
        ])
    }

    /// Freeze the already measured pidfd-then-network-namespace identity for durable correlation.
    ///
    /// This deliberately reuses the exact publication identity path. The worker and journal must
    /// never grow a second `fstat`/`F_GETFL` interpretation of the same descriptors.
    pub(crate) fn durable_binding(self) -> Result<DurableCustodyDescriptorBinding, FdStoreError> {
        let [pidfd, network_namespace] = exact_custody_identities(self)?;
        let pidfd = durable_descriptor_identity(&pidfd)?;
        let network_namespace = durable_descriptor_identity(&network_namespace)?;
        DurableCustodyDescriptorBinding::try_from_role_ordered(pidfd, network_namespace)
            .ok_or_else(|| invalid_inventory("durable custody descriptor binding is invalid"))
    }
}

/// Whether the first descriptor-store send was ever attempted.
#[derive(Debug, thiserror::Error)]
pub(crate) enum PublicationFailure {
    #[error(
        "this publication attempt sent no custody pair; ownership from an older attempt is not disproven"
    )]
    BeforeSend {
        #[source]
        error: FdStoreError,
    },
    #[error("descriptor-store publication is ambiguous; systemd may own the custody pair")]
    ManagerMayOwn {
        attempt_id: PublicationAttemptId,
        #[source]
        error: FdStoreError,
    },
}

impl PublicationFailure {
    fn before_send(error: FdStoreError) -> Self {
        Self::BeforeSend { error }
    }

    fn manager_may_own(attempt_id: PublicationAttemptId, error: FdStoreError) -> Self {
        Self::ManagerMayOwn { attempt_id, error }
    }
}

/// Whether the exact named-removal send boundary was crossed.
#[derive(Debug, thiserror::Error)]
pub(crate) enum RemovalFailure {
    #[error("this removal attempt sent no descriptor-store removal notification")]
    BeforeSend {
        #[source]
        error: FdStoreError,
    },
    #[error("descriptor-store removal is ambiguous; systemd may have removed the custody pair")]
    ManagerMayHaveRemoved {
        attempt_id: RemovalAttemptId,
        #[source]
        error: FdStoreError,
    },
}

impl RemovalFailure {
    fn before_send(error: FdStoreError) -> Self {
        Self::BeforeSend { error }
    }

    fn manager_may_have_removed(attempt_id: RemovalAttemptId, error: FdStoreError) -> Self {
        Self::ManagerMayHaveRemoved { attempt_id, error }
    }
}

#[derive(Debug, thiserror::Error)]
pub(crate) enum FdStoreError {
    #[error("custody descriptor-store name is invalid")]
    InvalidCustodyName,
    #[error("custody descriptors must be distinct")]
    DuplicateCustodyDescriptor,
    #[error("NOTIFY_SOCKET is unavailable or invalid")]
    InvalidNotifySocket,
    #[error("descriptor-store I/O failed")]
    Io(#[source] io::Error),
    #[error("systemd D-Bus operation failed")]
    Dbus(#[source] zbus::Error),
    #[error("descriptor-store operation deadline elapsed")]
    Deadline,
    #[error("systemd descriptor-store inventory is invalid: {0}")]
    InvalidInventory(&'static str),
    #[error("descriptor-store publication is permanently blocked after ambiguous ownership")]
    PublicationPoisoned,
    #[error("descriptor-store publication attempt identity is exhausted")]
    PublicationAttemptExhausted,
    #[error("descriptor-store publication has no ambiguous attempt to reconcile")]
    PublicationNotPoisoned,
    #[error("descriptor-store reconciliation target does not match the ambiguous attempt")]
    PublicationTargetMismatch,
    #[error("descriptor-store inventory changed across reconciliation snapshots")]
    UnstableInventory,
    #[error("descriptor-store removal is blocked by an unresolved earlier attempt")]
    RemovalPoisoned,
    #[error("descriptor-store removal attempt identity is exhausted")]
    RemovalAttemptExhausted,
    #[error("descriptor-store removal has no ambiguous attempt to reconcile")]
    RemovalNotPoisoned,
    #[error("descriptor-store removal target does not match the ambiguous attempt")]
    RemovalTargetMismatch,
    #[error("descriptor-store removal was ordered but the exact custody pair remains present")]
    RemovalStillPresent,
}

impl From<io::Error> for FdStoreError {
    fn from(error: io::Error) -> Self {
        Self::Io(error)
    }
}

impl From<zbus::Error> for FdStoreError {
    fn from(error: zbus::Error) -> Self {
        Self::Dbus(error)
    }
}

/// Proof that publication crossed a causal barrier and the resulting D-Bus inventory was exactly
/// its baseline plus the requested pair.
#[must_use = "successful descriptor-store publication requires retaining its exact inventory proof"]
#[derive(Eq, PartialEq)]
pub(crate) struct InventoryAttestation {
    custody_name: CustodyFdName,
    identities: [DescriptorIdentity; DESCRIPTORS_PER_CUSTODY],
    stored_descriptors: u32,
}

impl fmt::Debug for InventoryAttestation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("InventoryAttestation(<redacted>)")
    }
}

impl InventoryAttestation {
    /// Revalidate that this inventory proof names and identifies the exact borrowed custody pair.
    pub(crate) fn verify_exact_custody(
        &self,
        custody_name: CustodyFdName,
        custody: BorrowedCustodyPair<'_>,
    ) -> Result<(), FdStoreError> {
        let identities = exact_custody_identities(custody)?;
        if self.custody_name != custody_name || self.identities != identities {
            return Err(invalid_inventory(
                "inventory attestation does not match the exact custody pair",
            ));
        }
        Ok(())
    }

    /// Construct exact test evidence without exposing attestation fields or production authority.
    #[cfg(test)]
    pub(crate) fn for_test_exact_custody(
        custody_name: CustodyFdName,
        custody: BorrowedCustodyPair<'_>,
    ) -> Result<Self, FdStoreError> {
        Ok(Self {
            custody_name,
            identities: exact_custody_identities(custody)?,
            stored_descriptors: 2,
        })
    }
}

#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
struct DescriptorIdentity {
    mode: u32,
    device_major: u32,
    device_minor: u32,
    inode: u64,
    special_device_major: u32,
    special_device_minor: u32,
    status_flags: u32,
}

/// Role-ordered identity of exactly one pidfd followed by one network-namespace descriptor.
///
/// This is correlation evidence only, never descriptor or cleanup authority. The affine
/// `OwnedFd`s must remain alive anywhere the binding is relied upon.
#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
pub(super) struct CustodyDescriptorBinding([DescriptorIdentity; DESCRIPTORS_PER_CUSTODY]);

impl CustodyDescriptorBinding {
    pub(super) fn from_custody(custody: BorrowedCustodyPair<'_>) -> Result<Self, FdStoreError> {
        Ok(Self(exact_custody_identities(custody)?))
    }

    pub(super) fn overlaps(&self, other: &Self) -> bool {
        self.0.iter().any(|identity| {
            other
                .0
                .iter()
                .any(|candidate| identity.is_same_kernel_object(candidate))
        })
    }
}

impl fmt::Debug for CustodyDescriptorBinding {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("CustodyDescriptorBinding(<redacted>)")
    }
}

impl DescriptorIdentity {
    fn is_same_kernel_object(&self, other: &Self) -> bool {
        self.mode == other.mode
            && self.device_major == other.device_major
            && self.device_minor == other.device_minor
            && self.inode == other.inode
            && self.special_device_major == other.special_device_major
            && self.special_device_minor == other.special_device_minor
    }

    fn from_descriptor(descriptor: BorrowedFd<'_>) -> Result<Self, FdStoreError> {
        let status = fstat(descriptor).map_err(nix_io)?;
        let flags = fcntl(descriptor, FcntlArg::F_GETFL).map_err(nix_io)?;
        Ok(Self {
            mode: status.st_mode,
            device_major: checked_device_component(major(status.st_dev))?,
            device_minor: checked_device_component(minor(status.st_dev))?,
            inode: status.st_ino,
            special_device_major: checked_device_component(major(status.st_rdev))?,
            special_device_minor: checked_device_component(minor(status.st_rdev))?,
            status_flags: normalize_status_flags(
                u32::try_from(flags)
                    .map_err(|_| invalid_inventory("descriptor flags are invalid"))?,
            ),
        })
    }
}

fn durable_descriptor_identity(
    identity: &DescriptorIdentity,
) -> Result<DurableCustodyDescriptorIdentity, FdStoreError> {
    let mode = NonZeroU32::new(identity.mode)
        .ok_or_else(|| invalid_inventory("custody descriptor mode is zero"))?;
    let inode = NonZeroU64::new(identity.inode)
        .ok_or_else(|| invalid_inventory("custody descriptor inode is zero"))?;
    DurableCustodyDescriptorIdentity::try_from_parts(DurableCustodyDescriptorIdentityParts {
        mode,
        device_major: identity.device_major,
        device_minor: identity.device_minor,
        inode,
        special_device_major: identity.special_device_major,
        special_device_minor: identity.special_device_minor,
        status_flags: identity.status_flags,
    })
    .ok_or_else(|| invalid_inventory("durable custody descriptor identity is invalid"))
}

fn exact_custody_identities(
    custody: BorrowedCustodyPair<'_>,
) -> Result<[DescriptorIdentity; DESCRIPTORS_PER_CUSTODY], FdStoreError> {
    let identities = custody.identities()?;
    if identities[0].is_same_kernel_object(&identities[1]) {
        return Err(FdStoreError::DuplicateCustodyDescriptor);
    }
    Ok(identities)
}

fn checked_device_component(value: u64) -> Result<u32, FdStoreError> {
    u32::try_from(value).map_err(|_| invalid_inventory("descriptor device number is too large"))
}

fn normalize_status_flags(flags: u32) -> u32 {
    flags & !rustix::fs::OFlags::LARGEFILE.bits()
}

#[derive(Clone, Eq, Ord, PartialEq, PartialOrd)]
struct InventoryEntry {
    name: Box<[u8]>,
    identity: DescriptorIdentity,
}

/// Exact systemd service identity observed for this process.
///
/// The object path is retained as a typed D-Bus path and never exposed as path or string
/// authority. Reconciliation reopens this exact service object instead of resolving the current
/// process through a second, potentially different `GetUnitByPID` lookup.
#[derive(Clone, Eq, PartialEq)]
struct DescriptorStoreScope {
    manager_owner: OwnedUniqueName,
    unit_path: OwnedObjectPath,
    main_pid: NonZeroU32,
}

impl DescriptorStoreScope {
    fn new(
        manager_owner: OwnedUniqueName,
        unit_path: OwnedObjectPath,
        main_pid: u32,
    ) -> Result<Self, FdStoreError> {
        let main_pid = NonZeroU32::new(main_pid)
            .ok_or_else(|| invalid_inventory("MainPID must be nonzero"))?;
        Ok(Self {
            manager_owner,
            unit_path,
            main_pid,
        })
    }

    fn main_pid(&self) -> u32 {
        self.main_pid.get()
    }
}

impl fmt::Debug for DescriptorStoreScope {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("DescriptorStoreScope(<redacted>)")
    }
}

impl fmt::Debug for InventoryEntry {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("InventoryEntry")
            .field("name", &"<redacted>")
            .field("identity", &self.identity)
            .finish()
    }
}

#[derive(Clone, Eq, PartialEq)]
struct DescriptorStoreSnapshot {
    scope: DescriptorStoreScope,
    main_pid: u32,
    notify_access: Box<str>,
    store_max: u32,
    store_preserve: Box<str>,
    entries: Vec<InventoryEntry>,
}

/// Opaque evidence that one complete startup inventory was stable across a manager barrier and
/// two uncached reads of the exact service object for the current process.
///
/// Descriptor identities and manager snapshot fields remain private. The only supported use is
/// an exact-set comparison against the affine descriptor bindings already inherited by this
/// process.
#[must_use = "startup inventory evidence must be checked against the inherited custody set"]
pub(crate) struct StableStartupInventory {
    snapshot: DescriptorStoreSnapshot,
    notify_address: NotifySocketAddress,
}

impl fmt::Debug for StableStartupInventory {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StableStartupInventory(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
struct ServiceCgroupIsolationSnapshot {
    scope: DescriptorStoreScope,
    invocation_id: [u8; SYSTEMD_INVOCATION_ID_BYTES],
    control_group: Box<str>,
    control_group_id: NonZeroU64,
}

#[derive(Clone)]
struct RawServiceCgroupIsolationSnapshot {
    invocation_id: Vec<u8>,
    main_pid: u32,
    control_pid: u32,
    control_group: String,
    control_group_id: u64,
    delegate: bool,
    delegate_controllers: Vec<String>,
    delegate_subgroup: String,
    protect_control_groups: bool,
    protect_control_groups_ex: String,
    private_pids: String,
    kill_mode: String,
    send_sigkill: bool,
}

impl ServiceCgroupIsolationSnapshot {
    fn from_raw(
        scope: DescriptorStoreScope,
        raw: RawServiceCgroupIsolationSnapshot,
    ) -> Result<Self, FdStoreError> {
        if raw.invocation_id.len() != SYSTEMD_INVOCATION_ID_BYTES
            || raw.invocation_id.iter().all(|byte| *byte == 0)
        {
            return Err(invalid_inventory("InvocationID is invalid"));
        }
        if raw.main_pid != scope.main_pid() || raw.main_pid != std::process::id() {
            return Err(invalid_inventory(
                "MainPID changed during isolation observation",
            ));
        }
        if raw.control_pid != 0 {
            return Err(invalid_inventory("ControlPID is not zero"));
        }
        validate_control_group(&raw.control_group)?;
        let control_group_id = NonZeroU64::new(raw.control_group_id)
            .ok_or_else(|| invalid_inventory("ControlGroupId is zero"))?;
        if raw.delegate || !raw.delegate_controllers.is_empty() || !raw.delegate_subgroup.is_empty()
        {
            return Err(invalid_inventory("cgroup delegation is enabled"));
        }
        if !raw.protect_control_groups
            || !exact_bounded_property(&raw.protect_control_groups_ex, "strict")
        {
            return Err(invalid_inventory("ProtectControlGroups is not strict"));
        }
        if !exact_bounded_property(&raw.private_pids, "no") {
            return Err(invalid_inventory("PrivatePIDs is not disabled"));
        }
        if !exact_bounded_property(&raw.kill_mode, "control-group") || !raw.send_sigkill {
            return Err(invalid_inventory("service kill policy is not exact"));
        }
        let invocation_id: [u8; SYSTEMD_INVOCATION_ID_BYTES] = raw
            .invocation_id
            .try_into()
            .map_err(|_| invalid_inventory("InvocationID is invalid"))?;
        Ok(Self {
            scope,
            invocation_id,
            control_group: raw.control_group.into_boxed_str(),
            control_group_id,
        })
    }
}

fn exact_bounded_property(observed: &str, expected: &str) -> bool {
    observed.len() <= MAX_ISOLATION_PROPERTY_BYTES && observed == expected
}

fn validate_control_group(control_group: &str) -> Result<(), FdStoreError> {
    let bytes = control_group.as_bytes();
    if bytes.len() < 2
        || bytes.len() > MAX_CONTROL_GROUP_BYTES
        || bytes.first() != Some(&b'/')
        || bytes.last() == Some(&b'/')
    {
        return Err(invalid_inventory("ControlGroup is invalid"));
    }
    let mut components = 0_usize;
    for component in bytes[1..].split(|byte| *byte == b'/') {
        components = components
            .checked_add(1)
            .ok_or_else(|| invalid_inventory("ControlGroup is invalid"))?;
        if components > MAX_CONTROL_GROUP_COMPONENTS
            || component.is_empty()
            || component.len() > MAX_CONTROL_GROUP_COMPONENT_BYTES
            || matches!(component, b"." | b"..")
            || component.ends_with(b" (deleted)")
            || component
                .iter()
                .any(|byte| *byte == 0 || *byte < b' ' || *byte == 0x7f)
        {
            return Err(invalid_inventory("ControlGroup is invalid"));
        }
    }
    Ok(())
}

/// Stable, configured systemd isolation evidence for the exact retained helper invocation.
///
/// This remains bounded snapshot evidence. It is not cgroup mutation, migration, cleanup,
/// descriptor, journal, or server authority and does not claim that PID 1 cannot move a process.
#[must_use = "service-cgroup isolation evidence must remain joined to its pinned kernel cgroup"]
pub(crate) struct StableServiceCgroupIsolation {
    snapshot: ServiceCgroupIsolationSnapshot,
}

impl fmt::Debug for StableServiceCgroupIsolation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("StableServiceCgroupIsolation(<redacted>)")
    }
}

impl StableServiceCgroupIsolation {
    pub(crate) fn verify_exact_scope_and_kernel_id(
        &self,
        inventory: &StableStartupInventory,
        current_main_pid: NonZeroU32,
        kernel_cgroup_id: NonZeroU64,
    ) -> Result<(), FdStoreError> {
        if self.snapshot.scope != inventory.snapshot.scope
            || self.snapshot.scope.main_pid() != current_main_pid.get()
            || inventory.snapshot.main_pid != current_main_pid.get()
            || self.snapshot.control_group_id != kernel_cgroup_id
        {
            return Err(invalid_inventory(
                "service-cgroup isolation does not match the pinned service scope",
            ));
        }
        Ok(())
    }

    pub(crate) fn matches_exact(&self, candidate: &Self) -> bool {
        self.snapshot == candidate.snapshot
    }
}

/// Construct an exact stable-inventory fixture for sibling startup-custody tests.
#[cfg(test)]
pub(super) fn stable_startup_inventory_for_test(
    inherited: &BTreeMap<CustodyFdName, CustodyDescriptorBinding>,
) -> StableStartupInventory {
    let main_pid = std::process::id();
    let scope = DescriptorStoreScope::new(
        OwnedUniqueName::try_from(":1.4242").expect("valid fixture manager owner"),
        OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/volparossa_2dtest_2eservice")
            .expect("valid fixture service object path"),
        main_pid,
    )
    .expect("nonzero fixture service PID");
    let mut entries = Vec::with_capacity(inherited.len() * DESCRIPTORS_PER_CUSTODY);
    for (name, binding) in inherited {
        for identity in &binding.0 {
            entries.push(InventoryEntry {
                name: Box::<[u8]>::from(name.as_bytes().as_slice()),
                identity: identity.clone(),
            });
        }
    }
    entries.sort_unstable();
    StableStartupInventory {
        snapshot: DescriptorStoreSnapshot {
            scope,
            main_pid,
            notify_access: "main".into(),
            store_max: MAX_DESCRIPTOR_STORE_ENTRIES_U32,
            store_preserve: "yes".into(),
            entries,
        },
        notify_address: NotifySocketAddress::parse(OsStr::new("/run/volparossa-test-notify.sock"))
            .expect("valid fixture notify address"),
    }
}

#[cfg(test)]
pub(super) fn stable_service_cgroup_isolation_for_test(
    inventory: &StableStartupInventory,
    kernel_cgroup_id: NonZeroU64,
) -> StableServiceCgroupIsolation {
    StableServiceCgroupIsolation {
        snapshot: ServiceCgroupIsolationSnapshot {
            scope: inventory.snapshot.scope.clone(),
            invocation_id: [0x5a; SYSTEMD_INVOCATION_ID_BYTES],
            control_group: "/volparossa-test.service".into(),
            control_group_id: kernel_cgroup_id,
        },
    }
}

/// Exact stable proof that one named pair is absent and every unrelated manager entry is
/// unchanged. This is manager-inventory evidence only, not kernel-cleanup or journal authority.
#[must_use = "exact removal evidence must remain joined to durable cleanup settlement"]
pub(crate) struct ExactRemovalProof {
    custody_name: CustodyFdName,
    binding: CustodyDescriptorBinding,
    successor: StableStartupInventory,
    stored_descriptors: u32,
}

impl fmt::Debug for ExactRemovalProof {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactRemovalProof(<redacted>)")
    }
}

impl ExactRemovalProof {
    /// Revalidate only the opaque target correlation carried by this proof.
    pub(crate) fn verify_exact_target(
        &self,
        custody_name: CustodyFdName,
        binding: &CustodyDescriptorBinding,
    ) -> Result<(), FdStoreError> {
        if self.custody_name != custody_name || &self.binding != binding {
            return Err(invalid_inventory(
                "removal proof does not match the exact custody target",
            ));
        }
        Ok(())
    }

    /// Continue a bounded sequence from the exact stable post-removal inventory.
    pub(crate) fn into_successor(self) -> StableStartupInventory {
        self.successor
    }
}

/// Stable observation that an attempted exact removal left the complete baseline unchanged.
///
/// This deliberately carries no retry method or mutation authority.
#[must_use = "exact-still-present evidence never authorizes a blind removal retry"]
pub(crate) struct ExactStillPresentRemovalEvidence {
    attempt: PoisonedRemoval,
    stored_descriptors: u32,
}

impl fmt::Debug for ExactStillPresentRemovalEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactStillPresentRemovalEvidence(<redacted>)")
    }
}

/// Observation-only reconciliation of one exact ambiguous removal attempt.
#[must_use = "removal reconciliation does not authorize an implicit retry"]
pub(crate) enum RemovalInventoryReconciliation {
    ExactRemoved(ExactRemovalProof),
    ExactStillPresent(ExactStillPresentRemovalEvidence),
    Unresolved { error: FdStoreError },
}

impl fmt::Debug for RemovalInventoryReconciliation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExactRemoved(_) => formatter.write_str("ExactRemoved(<redacted>)"),
            Self::ExactStillPresent(_) => formatter.write_str("ExactStillPresent(<redacted>)"),
            Self::Unresolved { error } => formatter
                .debug_struct("Unresolved")
                .field("error", error)
                .finish(),
        }
    }
}

impl fmt::Debug for DescriptorStoreSnapshot {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("DescriptorStoreSnapshot")
            .field("scope", &self.scope)
            .field("main_pid", &self.main_pid)
            .field("notify_access", &self.notify_access)
            .field("store_max", &self.store_max)
            .field("store_preserve", &self.store_preserve)
            .field("entry_count", &self.entries.len())
            .finish()
    }
}

type RawInventoryEntry = (String, u32, u32, u32, u64, u32, u32, String, u32);

impl DescriptorStoreSnapshot {
    #[allow(
        clippy::too_many_arguments,
        reason = "the D-Bus trust boundary validates every independently observed field before construction"
    )]
    fn from_raw(
        scope: DescriptorStoreScope,
        main_pid: u32,
        notify_access: String,
        store_max: u32,
        store_preserve: String,
        count_before_dump: u32,
        count_after_dump: u32,
        raw_entries: Vec<RawInventoryEntry>,
    ) -> Result<Self, FdStoreError> {
        if notify_access.len() > 16 || store_preserve.len() > 16 {
            return Err(invalid_inventory("service properties are oversized"));
        }
        if count_before_dump != count_after_dump {
            return Err(invalid_inventory("descriptor count changed during dump"));
        }
        let count = usize::try_from(count_after_dump)
            .map_err(|_| invalid_inventory("descriptor count is invalid"))?;
        if count > MAX_DESCRIPTOR_STORE_ENTRIES || raw_entries.len() != count {
            return Err(invalid_inventory("descriptor dump count is invalid"));
        }
        let mut entries = Vec::with_capacity(count);
        for (name, mode, dev_major, dev_minor, inode, rdev_major, rdev_minor, path, flags) in
            raw_entries
        {
            let name = name.into_bytes();
            if name.is_empty()
                || name.len() > MAX_DESCRIPTOR_NAME_BYTES
                || !name
                    .iter()
                    .all(|byte| byte.is_ascii() && !byte.is_ascii_control() && *byte != b':')
                || path.len() > MAX_DUMP_PATH_BYTES
            {
                return Err(invalid_inventory("descriptor dump entry is invalid"));
            }
            entries.push(InventoryEntry {
                name: name.into_boxed_slice(),
                identity: DescriptorIdentity {
                    mode,
                    device_major: dev_major,
                    device_minor: dev_minor,
                    inode,
                    special_device_major: rdev_major,
                    special_device_minor: rdev_minor,
                    status_flags: normalize_status_flags(flags),
                },
            });
        }
        entries.sort_unstable();
        Ok(Self {
            scope,
            main_pid,
            notify_access: notify_access.into_boxed_str(),
            store_max,
            store_preserve: store_preserve.into_boxed_str(),
            entries,
        })
    }

    fn validate_baseline(
        &self,
        expected_scope: &DescriptorStoreScope,
        custody_name: CustodyFdName,
        custody_identities: &[DescriptorIdentity; DESCRIPTORS_PER_CUSTODY],
    ) -> Result<(), FdStoreError> {
        self.validate_service_contract(expected_scope)?;
        if self.entries.len() > MAX_DESCRIPTOR_STORE_ENTRIES - DESCRIPTORS_PER_CUSTODY {
            return Err(invalid_inventory("descriptor store has no pair capacity"));
        }
        if self
            .entries
            .iter()
            .any(|entry| entry.name.as_ref() == custody_name.as_bytes())
        {
            return Err(invalid_inventory("custody name already exists"));
        }
        if self.entries.iter().any(|entry| {
            custody_identities
                .iter()
                .any(|identity| identity.is_same_kernel_object(&entry.identity))
        }) {
            return Err(invalid_inventory(
                "custody descriptor identity already exists",
            ));
        }
        Ok(())
    }

    fn validate_service_contract(
        &self,
        expected_scope: &DescriptorStoreScope,
    ) -> Result<(), FdStoreError> {
        if &self.scope != expected_scope || self.main_pid != expected_scope.main_pid() {
            return Err(invalid_inventory(
                "service scope is not the publishing service",
            ));
        }
        if self.notify_access.as_ref() != "main" {
            return Err(invalid_inventory("NotifyAccess is not main"));
        }
        if self.store_max != MAX_DESCRIPTOR_STORE_ENTRIES_U32 {
            return Err(invalid_inventory("FileDescriptorStoreMax is not exact"));
        }
        if self.store_preserve.as_ref() != "yes" {
            return Err(invalid_inventory("FileDescriptorStorePreserve is not yes"));
        }
        Ok(())
    }

    fn attest_extension(
        &self,
        post: &Self,
        custody_name: CustodyFdName,
        identities: [DescriptorIdentity; DESCRIPTORS_PER_CUSTODY],
    ) -> Result<InventoryAttestation, FdStoreError> {
        if self.scope != post.scope
            || self.main_pid != post.main_pid
            || self.notify_access != post.notify_access
            || self.store_max != post.store_max
            || self.store_preserve != post.store_preserve
        {
            return Err(invalid_inventory("service identity or policy changed"));
        }
        let mut expected_entries = self.entries.clone();
        expected_entries.extend(identities.iter().cloned().map(|identity| InventoryEntry {
            name: Box::<[u8]>::from(custody_name.as_bytes().as_slice()),
            identity,
        }));
        expected_entries.sort_unstable();
        if post.entries != expected_entries {
            return Err(invalid_inventory(
                "descriptor inventory is not the exact baseline plus custody pair",
            ));
        }
        let stored_descriptors = u32::try_from(post.entries.len())
            .map_err(|_| invalid_inventory("descriptor count is invalid"))?;
        Ok(InventoryAttestation {
            custody_name,
            identities,
            stored_descriptors,
        })
    }

    fn validate_removal_target(
        &self,
        expected_scope: &DescriptorStoreScope,
        custody_name: CustodyFdName,
        binding: &CustodyDescriptorBinding,
    ) -> Result<(), FdStoreError> {
        self.validate_service_contract(expected_scope)?;
        if self.entries.len() > MAX_DESCRIPTOR_STORE_ENTRIES {
            return Err(invalid_inventory(
                "removal baseline exceeds the descriptor-store bound",
            ));
        }
        let mut grouped = BTreeMap::<CustodyFdName, Vec<&DescriptorIdentity>>::new();
        let mut identities = Vec::<&DescriptorIdentity>::with_capacity(self.entries.len());
        for entry in &self.entries {
            let name = std::str::from_utf8(&entry.name)
                .map_err(|_| invalid_inventory("removal baseline name is not valid UTF-8"))?;
            let name = CustodyFdName::parse(name)
                .map_err(|_| invalid_inventory("removal baseline custody name is invalid"))?;
            if identities
                .iter()
                .any(|identity| identity.is_same_kernel_object(&entry.identity))
            {
                return Err(invalid_inventory(
                    "removal baseline descriptor identity is reused",
                ));
            }
            identities.push(&entry.identity);
            grouped.entry(name).or_default().push(&entry.identity);
        }
        if grouped
            .values()
            .any(|group| group.len() != DESCRIPTORS_PER_CUSTODY)
        {
            return Err(invalid_inventory(
                "removal baseline custody name does not contain exactly two descriptors",
            ));
        }
        let target = grouped
            .get(&custody_name)
            .ok_or_else(|| invalid_inventory("removal target is absent from the baseline"))?;
        let [first, second] = target.as_slice() else {
            return Err(invalid_inventory(
                "removal baseline custody name does not contain exactly two descriptors",
            ));
        };
        let [pidfd, network_namespace] = &binding.0;
        if !((*first == pidfd && *second == network_namespace)
            || (*first == network_namespace && *second == pidfd))
        {
            return Err(invalid_inventory(
                "removal target does not match the exact local binding",
            ));
        }
        Ok(())
    }

    fn project_exact_removal(
        &self,
        post: &Self,
        custody_name: CustodyFdName,
        binding: &CustodyDescriptorBinding,
    ) -> Result<RemovalProjection, FdStoreError> {
        self.validate_removal_target(&self.scope, custody_name, binding)?;
        if self.scope != post.scope
            || self.main_pid != post.main_pid
            || self.notify_access != post.notify_access
            || self.store_max != post.store_max
            || self.store_preserve != post.store_preserve
        {
            return Err(invalid_inventory(
                "service identity or policy changed during removal",
            ));
        }
        if post.entries.len() > MAX_DESCRIPTOR_STORE_ENTRIES {
            return Err(invalid_inventory(
                "removal successor exceeds the descriptor-store bound",
            ));
        }
        let stored_descriptors = u32::try_from(post.entries.len())
            .map_err(|_| invalid_inventory("descriptor count is invalid"))?;
        if post.entries == self.entries {
            return Ok(RemovalProjection::ExactStillPresent { stored_descriptors });
        }
        let expected = self
            .entries
            .iter()
            .filter(|entry| entry.name.as_ref() != custody_name.as_bytes())
            .cloned()
            .collect::<Vec<_>>();
        if post.entries != expected {
            return Err(invalid_inventory(
                "descriptor inventory is not the exact baseline minus custody pair",
            ));
        }
        Ok(RemovalProjection::ExactRemoved {
            snapshot: post.clone(),
            stored_descriptors,
        })
    }

    fn project_poisoned_target(
        &self,
        target: &PublicationTarget,
    ) -> Result<TargetInventoryProjection, FdStoreError> {
        if self.entries.iter().any(|entry| {
            entry.name.as_ref() != target.custody_name.as_bytes()
                && target
                    .identities
                    .iter()
                    .any(|identity| identity.is_same_kernel_object(&entry.identity))
        }) {
            return Err(invalid_inventory(
                "custody descriptor identity exists under another name",
            ));
        }

        let mut target_identities = self
            .entries
            .iter()
            .filter(|entry| entry.name.as_ref() == target.custody_name.as_bytes())
            .map(|entry| entry.identity.clone())
            .collect::<Vec<_>>();
        let stored_descriptors = u32::try_from(self.entries.len())
            .map_err(|_| invalid_inventory("descriptor count is invalid"))?;
        if target_identities.is_empty() {
            return Ok(TargetInventoryProjection::ExactAbsent { stored_descriptors });
        }
        if target_identities.len() != DESCRIPTORS_PER_CUSTODY {
            return Err(invalid_inventory(
                "custody name does not contain exactly one descriptor pair",
            ));
        }
        target_identities.sort_unstable();
        let mut expected = target.identities.clone();
        expected.sort_unstable();
        if target_identities != expected {
            return Err(invalid_inventory(
                "custody name does not contain the exact correlated descriptor pair",
            ));
        }
        Ok(TargetInventoryProjection::ExactPresent { stored_descriptors })
    }
}

enum RemovalProjection {
    ExactRemoved {
        snapshot: DescriptorStoreSnapshot,
        stored_descriptors: u32,
    },
    ExactStillPresent {
        stored_descriptors: u32,
    },
}

impl StableStartupInventory {
    /// Reobserve the retained unit scope/object path without resolving a unit by PID again.
    ///
    /// One manager barrier and two uncached snapshots use the caller's unchanged hard deadline.
    /// The ordinary service-contract validation still requires its fresh `MainPID` to be the
    /// current process. No unit path or PID is exposed to the caller. The retained unique manager
    /// owner identifies the systemd manager incarnation and is rejected if it changes.
    pub(crate) async fn observe_same_service_scope(
        &self,
        deadline: HardDeadline,
    ) -> Result<Self, FdStoreError> {
        let scope = self.snapshot.scope.clone();
        let address = self.notify_address.clone();
        let source = SystemdDescriptorStoreSource::for_scope(scope, deadline).await?;
        let sender = NotifySender::new(&address)?;
        observe_stable_startup_inventory(
            &source,
            address,
            synchronize_manager(&sender, deadline),
            deadline,
        )
        .await
    }

    /// Observe the exact retained unit invocation's configured cgroup isolation twice.
    ///
    /// This reuses the manager unique-name owner and object path retained by the startup
    /// inventory. It performs no `GetUnitByPID`, mutation, cleanup, or readiness notification.
    pub(crate) async fn observe_same_service_cgroup_isolation(
        &self,
        deadline: HardDeadline,
    ) -> Result<StableServiceCgroupIsolation, FdStoreError> {
        let scope = self.snapshot.scope.clone();
        let source = SystemdDescriptorStoreSource::for_scope(scope, deadline).await?;
        let sender = NotifySender::new(&self.notify_address)?;
        observe_stable_service_cgroup_isolation(
            &source,
            synchronize_manager(&sender, deadline),
            deadline,
        )
        .await
    }

    /// Compare two opaque snapshots to the retained unit object path and current main process.
    ///
    /// Unit path and PID remain private. This binds the retained manager incarnation and unit
    /// scope, but does not itself attest `ControlGroup`, delegation, or cgroup membership.
    pub(crate) fn matches_current_service_scope(&self, candidate: &Self) -> bool {
        let current_pid = std::process::id();
        self.snapshot.scope == candidate.snapshot.scope
            && self.snapshot.main_pid == current_pid
            && candidate.snapshot.main_pid == current_pid
            && self.snapshot.scope.main_pid() == current_pid
            && candidate.snapshot.scope.main_pid() == current_pid
    }

    /// Verify that the complete manager inventory is exactly the caller's inherited custody set.
    ///
    /// Manager ordering is irrelevant, while the caller's binding remains role ordered as
    /// pidfd-then-network-namespace. No manager name, descriptor identity, or service property is
    /// exposed by this comparison.
    pub(crate) fn verify_complete_exact_set(
        &self,
        inherited: &BTreeMap<CustodyFdName, CustodyDescriptorBinding>,
    ) -> Result<(), FdStoreError> {
        let mut observed = BTreeMap::<CustodyFdName, Vec<&DescriptorIdentity>>::new();
        let mut observed_identities =
            Vec::<&DescriptorIdentity>::with_capacity(self.snapshot.entries.len());
        for entry in &self.snapshot.entries {
            let name = std::str::from_utf8(&entry.name)
                .map_err(|_| invalid_inventory("startup custody name is not valid UTF-8"))?;
            let name = CustodyFdName::parse(name)
                .map_err(|_| invalid_inventory("startup custody name is invalid"))?;
            if observed_identities
                .iter()
                .any(|identity| identity.is_same_kernel_object(&entry.identity))
            {
                return Err(invalid_inventory("startup descriptor identity is reused"));
            }
            observed_identities.push(&entry.identity);
            observed.entry(name).or_default().push(&entry.identity);
        }
        if observed
            .values()
            .any(|identities| identities.len() != DESCRIPTORS_PER_CUSTODY)
        {
            return Err(invalid_inventory(
                "startup custody name does not contain exactly two descriptors",
            ));
        }

        let mut inherited_bindings =
            Vec::<&CustodyDescriptorBinding>::with_capacity(inherited.len());
        for (name, binding) in inherited {
            let name = std::str::from_utf8(name.as_bytes())
                .map_err(|_| invalid_inventory("inherited custody name is not valid UTF-8"))?;
            if !custody_fd_name_is_valid(name) {
                return Err(invalid_inventory("inherited custody name is invalid"));
            }
            if binding.0[0].is_same_kernel_object(&binding.0[1])
                || inherited_bindings
                    .iter()
                    .any(|candidate| candidate.overlaps(binding))
            {
                return Err(invalid_inventory("inherited descriptor identity is reused"));
            }
            inherited_bindings.push(binding);
        }

        let inherited_descriptor_count = inherited
            .len()
            .checked_mul(DESCRIPTORS_PER_CUSTODY)
            .ok_or_else(|| invalid_inventory("inherited custody set is oversized"))?;
        if inherited.len() > MAX_DESCRIPTOR_STORE_ENTRIES / DESCRIPTORS_PER_CUSTODY
            || observed.len() != inherited.len()
            || self.snapshot.entries.len() != inherited_descriptor_count
        {
            return Err(invalid_inventory(
                "startup inventory is not the complete inherited custody set",
            ));
        }

        for (name, binding) in inherited {
            let observed_pair = observed.get(name).ok_or_else(|| {
                invalid_inventory("startup inventory is missing inherited custody")
            })?;
            let [first, second] = observed_pair.as_slice() else {
                return Err(invalid_inventory(
                    "startup custody name does not contain exactly two descriptors",
                ));
            };
            let [pidfd, network_namespace] = &binding.0;
            let exact_unordered = (*first == pidfd && *second == network_namespace)
                || (*first == network_namespace && *second == pidfd);
            if !exact_unordered {
                return Err(invalid_inventory(
                    "startup custody pair does not match inherited descriptors",
                ));
            }
        }
        Ok(())
    }
}

enum TargetInventoryProjection {
    ExactPresent { stored_descriptors: u32 },
    ExactAbsent { stored_descriptors: u32 },
}

#[derive(Clone, Eq, PartialEq)]
struct PublicationTarget {
    scope: DescriptorStoreScope,
    notify_address: NotifySocketAddress,
    custody_name: CustodyFdName,
    identities: [DescriptorIdentity; DESCRIPTORS_PER_CUSTODY],
}

impl fmt::Debug for PublicationTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PublicationTarget(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
struct PoisonedPublication {
    attempt_id: PublicationAttemptId,
    target: PublicationTarget,
}

impl fmt::Debug for PoisonedPublication {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PoisonedPublication(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
struct RemovalTarget {
    scope: DescriptorStoreScope,
    notify_address: NotifySocketAddress,
    custody_name: CustodyFdName,
    binding: CustodyDescriptorBinding,
    baseline: DescriptorStoreSnapshot,
}

impl fmt::Debug for RemovalTarget {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("RemovalTarget(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
struct PoisonedRemoval {
    attempt_id: RemovalAttemptId,
    target: RemovalTarget,
}

impl fmt::Debug for PoisonedRemoval {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("PoisonedRemoval(<redacted>)")
    }
}

#[derive(Clone, Eq, PartialEq)]
enum PoisonedManagerMutation {
    Publication(PoisonedPublication),
    Removal(PoisonedRemoval),
}

struct ManagerMutationGateState {
    last_attempt_id: u64,
    poisoned: Option<PoisonedManagerMutation>,
}

/// Serializes every descriptor-store mutation from its fresh baseline observation through final
/// attestation. Publication and removal draw typed IDs from one monotonic sequence and share one
/// poison state. Dropping either attempt after its first send boundary blocks both mutation kinds.
/// After an ambiguous attempt, publication reconciliation is observation-only; only exact-removed
/// reconciliation of that removal may reopen this gate.
struct ManagerMutationGate {
    state: tokio::sync::Mutex<ManagerMutationGateState>,
}

impl ManagerMutationGate {
    const fn new() -> Self {
        Self {
            state: tokio::sync::Mutex::const_new(ManagerMutationGateState {
                last_attempt_id: 0,
                poisoned: None,
            }),
        }
    }

    async fn lock_state(
        &self,
        deadline: HardDeadline,
    ) -> Result<tokio::sync::MutexGuard<'_, ManagerMutationGateState>, FdStoreError> {
        ensure_deadline(deadline)?;
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline.expires_at()),
            self.state.lock(),
        )
        .await
        .map_err(|_| FdStoreError::Deadline)
    }

    async fn acquire_removal(
        &self,
        deadline: HardDeadline,
    ) -> Result<RemovalAttempt<'_>, FdStoreError> {
        let state = self.lock_state(deadline).await?;
        if state.poisoned.is_some() {
            return Err(FdStoreError::RemovalPoisoned);
        }
        Ok(RemovalAttempt {
            state,
            crossed: None,
        })
    }

    async fn acquire_poisoned_removal(
        &self,
        attempt_id: RemovalAttemptId,
        custody_name: CustodyFdName,
        binding: &CustodyDescriptorBinding,
        deadline: HardDeadline,
    ) -> Result<PoisonedRemovalObservation<'_>, FdStoreError> {
        let state = self.lock_state(deadline).await?;
        let poisoned = match state.poisoned.clone() {
            Some(PoisonedManagerMutation::Removal(poisoned)) => poisoned,
            Some(PoisonedManagerMutation::Publication(_)) => {
                return Err(FdStoreError::RemovalTargetMismatch);
            }
            None => return Err(FdStoreError::RemovalNotPoisoned),
        };
        if poisoned.attempt_id != attempt_id
            || poisoned.target.custody_name != custody_name
            || &poisoned.target.binding != binding
        {
            return Err(FdStoreError::RemovalTargetMismatch);
        }
        Ok(PoisonedRemovalObservation { state, poisoned })
    }

    async fn acquire_publication(
        &self,
        deadline: HardDeadline,
    ) -> Result<PublicationAttempt<'_>, FdStoreError> {
        let state = self.lock_state(deadline).await?;
        if state.poisoned.is_some() {
            return Err(FdStoreError::PublicationPoisoned);
        }
        Ok(PublicationAttempt {
            state,
            crossed: None,
        })
    }

    async fn acquire_poisoned_publication(
        &self,
        attempt_id: PublicationAttemptId,
        custody_name: CustodyFdName,
        identities: &[DescriptorIdentity; DESCRIPTORS_PER_CUSTODY],
        deadline: HardDeadline,
    ) -> Result<PoisonedObservation<'_>, FdStoreError> {
        let state = self.lock_state(deadline).await?;
        let poisoned = match state.poisoned.clone() {
            Some(PoisonedManagerMutation::Publication(poisoned)) => poisoned,
            Some(PoisonedManagerMutation::Removal(_)) => {
                return Err(FdStoreError::PublicationTargetMismatch);
            }
            None => return Err(FdStoreError::PublicationNotPoisoned),
        };
        if poisoned.attempt_id != attempt_id
            || poisoned.target.custody_name != custody_name
            || &poisoned.target.identities != identities
        {
            return Err(FdStoreError::PublicationTargetMismatch);
        }
        Ok(PoisonedObservation {
            _state: state,
            poisoned,
        })
    }
}

struct PublicationAttempt<'a> {
    state: tokio::sync::MutexGuard<'a, ManagerMutationGateState>,
    crossed: Option<PoisonedPublication>,
}

impl PublicationAttempt<'_> {
    /// Mark immediately before invoking the first `sendmsg(2)`. Conservatively poisoning on
    /// cancellation between this mark and the syscall is safe; silently permitting a retry is not.
    fn mark_send_attempted(
        &mut self,
        target: PublicationTarget,
    ) -> Result<PublicationAttemptId, FdStoreError> {
        if self.crossed.is_some() || self.state.poisoned.is_some() {
            return Err(FdStoreError::PublicationPoisoned);
        }
        let next = self
            .state
            .last_attempt_id
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(FdStoreError::PublicationAttemptExhausted)?;
        let poisoned = PoisonedPublication {
            attempt_id: PublicationAttemptId(next),
            target,
        };
        self.state.last_attempt_id = next.get();
        self.state.poisoned = Some(PoisonedManagerMutation::Publication(poisoned.clone()));
        self.crossed = Some(poisoned);
        Ok(PublicationAttemptId(next))
    }

    fn complete_success(mut self, attempt_id: PublicationAttemptId) {
        let exact = self.crossed.as_ref().is_some_and(|crossed| {
            crossed.attempt_id == attempt_id
                && matches!(
                    self.state.poisoned.as_ref(),
                    Some(PoisonedManagerMutation::Publication(poisoned)) if poisoned == crossed
                )
        });
        if !exact {
            std::process::abort();
        }
        self.state.poisoned = None;
        self.crossed = None;
    }
}

/// Holds the shared manager-mutation gate while a poisoned publication is observed. Dropping this
/// guard never clears the poison, including cancellation and panic unwinding.
struct PoisonedObservation<'a> {
    _state: tokio::sync::MutexGuard<'a, ManagerMutationGateState>,
    poisoned: PoisonedPublication,
}

struct RemovalAttempt<'a> {
    state: tokio::sync::MutexGuard<'a, ManagerMutationGateState>,
    crossed: Option<PoisonedRemoval>,
}

impl RemovalAttempt<'_> {
    /// Conservatively mark immediately before invoking the exact removal send.
    fn mark_send_attempted(
        &mut self,
        target: RemovalTarget,
    ) -> Result<RemovalAttemptId, FdStoreError> {
        if self.crossed.is_some() || self.state.poisoned.is_some() {
            return Err(FdStoreError::RemovalPoisoned);
        }
        let next = self
            .state
            .last_attempt_id
            .checked_add(1)
            .and_then(NonZeroU64::new)
            .ok_or(FdStoreError::RemovalAttemptExhausted)?;
        let poisoned = PoisonedRemoval {
            attempt_id: RemovalAttemptId(next),
            target,
        };
        self.state.last_attempt_id = next.get();
        self.state.poisoned = Some(PoisonedManagerMutation::Removal(poisoned.clone()));
        self.crossed = Some(poisoned);
        Ok(RemovalAttemptId(next))
    }

    fn complete_exact_removed(mut self, attempt_id: RemovalAttemptId) {
        let exact = self.crossed.as_ref().is_some_and(|crossed| {
            crossed.attempt_id == attempt_id
                && matches!(
                    self.state.poisoned.as_ref(),
                    Some(PoisonedManagerMutation::Removal(poisoned)) if poisoned == crossed
                )
        });
        if !exact {
            std::process::abort();
        }
        self.state.poisoned = None;
        self.crossed = None;
    }
}

struct PoisonedRemovalObservation<'a> {
    state: tokio::sync::MutexGuard<'a, ManagerMutationGateState>,
    poisoned: PoisonedRemoval,
}

impl PoisonedRemovalObservation<'_> {
    fn complete_exact_removed(mut self) {
        let exact = matches!(
            self.state.poisoned.as_ref(),
            Some(PoisonedManagerMutation::Removal(poisoned)) if poisoned == &self.poisoned
        );
        if !exact {
            std::process::abort();
        }
        self.state.poisoned = None;
    }
}

trait DescriptorStoreInventorySource: Sync {
    fn scope(&self) -> &DescriptorStoreScope;

    fn snapshot(
        &self,
        deadline: HardDeadline,
    ) -> impl Future<Output = Result<DescriptorStoreSnapshot, FdStoreError>> + Send;
}

trait ServiceCgroupIsolationSource: Sync {
    fn scope(&self) -> &DescriptorStoreScope;

    fn isolation_snapshot(
        &self,
        deadline: HardDeadline,
    ) -> impl Future<Output = Result<ServiceCgroupIsolationSnapshot, FdStoreError>> + Send;
}

/// Production D-Bus source bound to the unit owning the current process.
struct SystemdDescriptorStoreSource {
    connection: Connection,
    scope: DescriptorStoreScope,
}

impl SystemdDescriptorStoreSource {
    async fn for_current_process(deadline: HardDeadline) -> Result<Self, FdStoreError> {
        let expected_main_pid = std::process::id();
        within_deadline(deadline, async move {
            let connection = Connection::system().await?;
            let manager_owner = systemd_manager_owner(&connection).await?;
            let manager: Proxy<'_> = ProxyBuilder::new(&connection)
                .destination(manager_owner.clone())?
                .path(SYSTEMD_MANAGER_PATH)?
                .interface(SYSTEMD_MANAGER_INTERFACE)?
                .cache_properties(CacheProperties::No)
                .build()
                .await?;
            let unit_path: OwnedObjectPath =
                manager.call("GetUnitByPID", &(expected_main_pid,)).await?;
            drop(manager);
            if systemd_manager_owner(&connection).await? != manager_owner {
                return Err(FdStoreError::UnstableInventory);
            }
            let scope = DescriptorStoreScope::new(manager_owner, unit_path, expected_main_pid)?;
            Ok(Self { connection, scope })
        })
        .await
    }

    async fn for_scope(
        scope: DescriptorStoreScope,
        deadline: HardDeadline,
    ) -> Result<Self, FdStoreError> {
        within_deadline(deadline, async move {
            let connection = Connection::system().await?;
            if systemd_manager_owner(&connection).await? != scope.manager_owner {
                return Err(FdStoreError::UnstableInventory);
            }
            Ok(Self { connection, scope })
        })
        .await
    }

    async fn snapshot_unbounded(&self) -> Result<DescriptorStoreSnapshot, FdStoreError> {
        let service: Proxy<'_> = ProxyBuilder::new(&self.connection)
            .destination(self.scope.manager_owner.clone())?
            .path(self.scope.unit_path.clone())?
            .interface(SYSTEMD_SERVICE_INTERFACE)?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        let main_pid = service.get_property::<u32>("MainPID").await?;
        let notify_access = service.get_property::<String>("NotifyAccess").await?;
        let store_max = service
            .get_property::<u32>("FileDescriptorStoreMax")
            .await?;
        let store_preserve = service
            .get_property::<String>("FileDescriptorStorePreserve")
            .await?;
        let count_before_dump = service.get_property::<u32>("NFileDescriptorStore").await?;
        validate_properties_before_dump(
            self.scope.main_pid(),
            main_pid,
            &notify_access,
            store_max,
            &store_preserve,
            count_before_dump,
        )?;
        let entries: Vec<RawInventoryEntry> = service.call("DumpFileDescriptorStore", &()).await?;
        let count_after_dump = service.get_property::<u32>("NFileDescriptorStore").await?;
        DescriptorStoreSnapshot::from_raw(
            self.scope.clone(),
            main_pid,
            notify_access,
            store_max,
            store_preserve,
            count_before_dump,
            count_after_dump,
            entries,
        )
    }

    async fn isolation_snapshot_unbounded(
        &self,
    ) -> Result<ServiceCgroupIsolationSnapshot, FdStoreError> {
        let unit: Proxy<'_> = ProxyBuilder::new(&self.connection)
            .destination(self.scope.manager_owner.clone())?
            .path(self.scope.unit_path.clone())?
            .interface(SYSTEMD_UNIT_INTERFACE)?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        let invocation_id = unit.get_property::<Vec<u8>>("InvocationID").await?;
        drop(unit);

        let service: Proxy<'_> = ProxyBuilder::new(&self.connection)
            .destination(self.scope.manager_owner.clone())?
            .path(self.scope.unit_path.clone())?
            .interface(SYSTEMD_SERVICE_INTERFACE)?
            .cache_properties(CacheProperties::No)
            .build()
            .await?;
        let raw = RawServiceCgroupIsolationSnapshot {
            invocation_id,
            main_pid: service.get_property::<u32>("MainPID").await?,
            control_pid: service.get_property::<u32>("ControlPID").await?,
            control_group: service.get_property::<String>("ControlGroup").await?,
            control_group_id: service.get_property::<u64>("ControlGroupId").await?,
            delegate: service.get_property::<bool>("Delegate").await?,
            delegate_controllers: service
                .get_property::<Vec<String>>("DelegateControllers")
                .await?,
            delegate_subgroup: service.get_property::<String>("DelegateSubgroup").await?,
            protect_control_groups: service.get_property::<bool>("ProtectControlGroups").await?,
            protect_control_groups_ex: service
                .get_property::<String>("ProtectControlGroupsEx")
                .await?,
            private_pids: service.get_property::<String>("PrivatePIDs").await?,
            kill_mode: service.get_property::<String>("KillMode").await?,
            send_sigkill: service.get_property::<bool>("SendSIGKILL").await?,
        };
        ServiceCgroupIsolationSnapshot::from_raw(self.scope.clone(), raw)
    }
}

async fn systemd_manager_owner(connection: &Connection) -> Result<OwnedUniqueName, FdStoreError> {
    let bus: Proxy<'_> = ProxyBuilder::new(connection)
        .destination(DBUS_DESTINATION)?
        .path(DBUS_PATH)?
        .interface(DBUS_INTERFACE)?
        .cache_properties(CacheProperties::No)
        .build()
        .await?;
    bus.call("GetNameOwner", &(SYSTEMD_DESTINATION,))
        .await
        .map_err(FdStoreError::from)
}

fn validate_properties_before_dump(
    expected_main_pid: u32,
    main_pid: u32,
    notify_access: &str,
    store_max: u32,
    store_preserve: &str,
    count_before_dump: u32,
) -> Result<(), FdStoreError> {
    if main_pid != expected_main_pid {
        return Err(invalid_inventory("MainPID is not the publishing process"));
    }
    if notify_access.len() > 16 || notify_access != "main" {
        return Err(invalid_inventory("NotifyAccess is not exact"));
    }
    if store_max != MAX_DESCRIPTOR_STORE_ENTRIES_U32 {
        return Err(invalid_inventory("FileDescriptorStoreMax is not exact"));
    }
    if store_preserve.len() > 16 || store_preserve != "yes" {
        return Err(invalid_inventory(
            "FileDescriptorStorePreserve is not exact",
        ));
    }
    if count_before_dump > MAX_DESCRIPTOR_STORE_ENTRIES_U32 {
        return Err(invalid_inventory(
            "descriptor count exceeds the bounded store",
        ));
    }
    Ok(())
}

impl DescriptorStoreInventorySource for SystemdDescriptorStoreSource {
    fn scope(&self) -> &DescriptorStoreScope {
        &self.scope
    }

    fn snapshot(
        &self,
        deadline: HardDeadline,
    ) -> impl Future<Output = Result<DescriptorStoreSnapshot, FdStoreError>> + Send {
        within_deadline(deadline, self.snapshot_unbounded())
    }
}

impl ServiceCgroupIsolationSource for SystemdDescriptorStoreSource {
    fn scope(&self) -> &DescriptorStoreScope {
        &self.scope
    }

    fn isolation_snapshot(
        &self,
        deadline: HardDeadline,
    ) -> impl Future<Output = Result<ServiceCgroupIsolationSnapshot, FdStoreError>> + Send {
        within_deadline(deadline, self.isolation_snapshot_unbounded())
    }
}

struct NotifySocketAddress {
    address: UnixAddr,
    identity: Box<[u8]>,
}

impl Clone for NotifySocketAddress {
    fn clone(&self) -> Self {
        Self {
            address: self.address,
            identity: self.identity.clone(),
        }
    }
}

impl PartialEq for NotifySocketAddress {
    fn eq(&self, other: &Self) -> bool {
        self.identity == other.identity
    }
}

impl Eq for NotifySocketAddress {}

impl fmt::Debug for NotifySocketAddress {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("NotifySocketAddress(<redacted>)")
    }
}

impl NotifySocketAddress {
    fn from_environment() -> Result<Self, FdStoreError> {
        let value = env::var_os("NOTIFY_SOCKET").ok_or(FdStoreError::InvalidNotifySocket)?;
        Self::parse(&value)
    }

    fn parse(value: &OsStr) -> Result<Self, FdStoreError> {
        let bytes = value.as_bytes();
        let address = match bytes {
            [b'@', abstract_name @ ..] if !abstract_name.is_empty() => {
                UnixAddr::new_abstract(abstract_name)
            }
            [] | [b'@'] => return Err(FdStoreError::InvalidNotifySocket),
            _ if Path::new(value).is_absolute() => UnixAddr::new(Path::new(value)),
            _ => return Err(FdStoreError::InvalidNotifySocket),
        }
        .map_err(|_| FdStoreError::InvalidNotifySocket)?;
        Ok(Self {
            address,
            identity: bytes.into(),
        })
    }
}

struct NotifySender {
    socket: OwnedFd,
    address: UnixAddr,
}

impl NotifySender {
    fn new(address: &NotifySocketAddress) -> Result<Self, FdStoreError> {
        let socket = socket(
            AddressFamily::Unix,
            SockType::Datagram,
            SockFlag::SOCK_CLOEXEC | SockFlag::SOCK_NONBLOCK,
            None,
        )
        .map_err(nix_io)?;
        Ok(Self {
            socket,
            address: address.address,
        })
    }

    /// Perform exactly one `sendmsg(2)` call. The caller decides whether this attempt crosses the
    /// manager-ownership ambiguity boundary.
    fn send_once(&self, payload: &[u8], descriptors: &[RawFd]) -> Result<(), FdStoreError> {
        let vectors = [IoSlice::new(payload)];
        let control = [ControlMessage::ScmRights(descriptors)];
        let written = sendmsg(
            self.socket.as_raw_fd(),
            &vectors,
            &control,
            MsgFlags::MSG_NOSIGNAL,
            Some(&self.address),
        )
        .map_err(nix_io)?;
        if written != payload.len() {
            return Err(FdStoreError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "systemd notification datagram was incomplete",
            )));
        }
        Ok(())
    }

    /// Perform exactly one payload-only `sendmsg(2)` call with no ancillary data.
    fn send_without_descriptors_once(&self, payload: &[u8]) -> Result<(), FdStoreError> {
        let vectors = [IoSlice::new(payload)];
        let control: [ControlMessage<'_>; 0] = [];
        let written = sendmsg(
            self.socket.as_raw_fd(),
            &vectors,
            &control,
            MsgFlags::MSG_NOSIGNAL,
            Some(&self.address),
        )
        .map_err(nix_io)?;
        if written != payload.len() {
            return Err(FdStoreError::Io(io::Error::new(
                io::ErrorKind::WriteZero,
                "systemd notification datagram was incomplete",
            )));
        }
        Ok(())
    }
}

/// Observe the complete startup descriptor-store inventory without publishing or removing any
/// descriptor.
///
/// The source is resolved once from the current PID to one exact systemd service object. The
/// current process's `NOTIFY_SOCKET` is used for one non-mutating barrier, after which two
/// uncached complete D-Bus snapshots must agree under the caller's single absolute deadline.
pub(crate) async fn observe_current_process_startup_inventory(
    deadline: HardDeadline,
) -> Result<StableStartupInventory, FdStoreError> {
    ensure_deadline(deadline)?;
    let source = SystemdDescriptorStoreSource::for_current_process(deadline).await?;
    let address = NotifySocketAddress::from_environment()?;
    let sender = NotifySender::new(&address)?;
    observe_stable_startup_inventory(
        &source,
        address,
        synchronize_manager(&sender, deadline),
        deadline,
    )
    .await
}

async fn observe_stable_startup_inventory<S, B>(
    source: &S,
    notify_address: NotifySocketAddress,
    barrier: B,
    deadline: HardDeadline,
) -> Result<StableStartupInventory, FdStoreError>
where
    S: DescriptorStoreInventorySource,
    B: Future<Output = Result<(), FdStoreError>>,
{
    ensure_deadline(deadline)?;
    within_deadline(deadline, barrier).await?;
    let first = within_deadline(deadline, source.snapshot(deadline)).await?;
    first.validate_service_contract(source.scope())?;
    let second = within_deadline(deadline, source.snapshot(deadline)).await?;
    second.validate_service_contract(source.scope())?;
    if first != second {
        return Err(FdStoreError::UnstableInventory);
    }
    ensure_deadline(deadline)?;
    Ok(StableStartupInventory {
        snapshot: first,
        notify_address,
    })
}

async fn observe_stable_service_cgroup_isolation<S, B>(
    source: &S,
    barrier: B,
    deadline: HardDeadline,
) -> Result<StableServiceCgroupIsolation, FdStoreError>
where
    S: ServiceCgroupIsolationSource,
    B: Future<Output = Result<(), FdStoreError>>,
{
    ensure_deadline(deadline)?;
    within_deadline(deadline, barrier).await?;
    let first = within_deadline(deadline, source.isolation_snapshot(deadline)).await?;
    if &first.scope != source.scope() {
        return Err(invalid_inventory("service-cgroup isolation scope changed"));
    }
    let second = within_deadline(deadline, source.isolation_snapshot(deadline)).await?;
    if &second.scope != source.scope() || first != second {
        return Err(FdStoreError::UnstableInventory);
    }
    ensure_deadline(deadline)?;
    Ok(StableServiceCgroupIsolation { snapshot: first })
}

/// Dormant exact named-removal adapter. No production server, engine, or request-path caller
/// exists yet.
///
/// `custody` retains the exact affine owners across the operation and is remeasured before the send
/// boundary and after the stable post-removal inventory. The adapter performs at most one removal
/// send.
#[allow(dead_code)]
pub(crate) async fn remove_current_process_custody(
    baseline: StableStartupInventory,
    custody_name: CustodyFdName,
    expected_binding: CustodyDescriptorBinding,
    custody: BorrowedCustodyPair<'_>,
    deadline: HardDeadline,
) -> Result<ExactRemovalProof, RemovalFailure> {
    ensure_deadline(deadline).map_err(RemovalFailure::before_send)?;
    let source = SystemdDescriptorStoreSource::for_scope(baseline.snapshot.scope.clone(), deadline)
        .await
        .map_err(RemovalFailure::before_send)?;
    let sender =
        NotifySender::new(&baseline.notify_address).map_err(RemovalFailure::before_send)?;
    remove_and_attest(
        &PRODUCTION_MANAGER_MUTATION_GATE,
        &source,
        &sender,
        baseline,
        custody_name,
        expected_binding,
        custody,
        deadline,
    )
    .await
}

#[allow(
    clippy::too_many_arguments,
    clippy::too_many_lines,
    reason = "the removal transaction keeps every authority and deadline input explicit"
)]
async fn remove_and_attest<S>(
    gate: &ManagerMutationGate,
    source: &S,
    sender: &NotifySender,
    baseline: StableStartupInventory,
    custody_name: CustodyFdName,
    expected_binding: CustodyDescriptorBinding,
    custody: BorrowedCustodyPair<'_>,
    deadline: HardDeadline,
) -> Result<ExactRemovalProof, RemovalFailure>
where
    S: DescriptorStoreInventorySource,
{
    ensure_deadline(deadline).map_err(RemovalFailure::before_send)?;
    let mut attempt = gate
        .acquire_removal(deadline)
        .await
        .map_err(RemovalFailure::before_send)?;
    if source.scope() != &baseline.snapshot.scope {
        return Err(RemovalFailure::before_send(
            FdStoreError::RemovalTargetMismatch,
        ));
    }
    baseline
        .snapshot
        .validate_removal_target(source.scope(), custody_name, &expected_binding)
        .map_err(RemovalFailure::before_send)?;
    let preflight = within_deadline(deadline, source.snapshot(deadline))
        .await
        .map_err(RemovalFailure::before_send)?;
    preflight
        .validate_service_contract(source.scope())
        .map_err(RemovalFailure::before_send)?;
    if preflight != baseline.snapshot {
        return Err(RemovalFailure::before_send(invalid_inventory(
            "removal baseline changed before the send boundary",
        )));
    }
    let before =
        CustodyDescriptorBinding::from_custody(custody).map_err(RemovalFailure::before_send)?;
    if before != expected_binding {
        return Err(RemovalFailure::before_send(invalid_inventory(
            "local custody binding does not match the removal target",
        )));
    }
    let sender_address = baseline.notify_address.clone();
    let (barrier_read, barrier_write) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
        .map_err(nix_io)
        .map_err(RemovalFailure::before_send)?;
    let barrier_read = AsyncFd::new(barrier_read)
        .map_err(FdStoreError::Io)
        .map_err(RemovalFailure::before_send)?;
    let removal_message = fdstore_remove_message(custody_name);
    ensure_deadline(deadline).map_err(RemovalFailure::before_send)?;

    let target = RemovalTarget {
        scope: source.scope().clone(),
        notify_address: sender_address.clone(),
        custody_name,
        binding: expected_binding.clone(),
        baseline: baseline.snapshot.clone(),
    };
    let attempt_id = attempt
        .mark_send_attempted(target)
        .map_err(RemovalFailure::before_send)?;
    sender
        .send_without_descriptors_once(&removal_message)
        .map_err(|error| RemovalFailure::manager_may_have_removed(attempt_id, error))?;
    ensure_deadline(deadline)
        .map_err(|error| RemovalFailure::manager_may_have_removed(attempt_id, error))?;
    sender
        .send_once(BARRIER_MESSAGE, &[barrier_write.as_raw_fd()])
        .map_err(|error| RemovalFailure::manager_may_have_removed(attempt_id, error))?;
    drop(barrier_write);
    wait_for_barrier(&barrier_read, deadline)
        .await
        .map_err(|error| RemovalFailure::manager_may_have_removed(attempt_id, error))?;
    let first = within_deadline(deadline, source.snapshot(deadline))
        .await
        .map_err(|error| RemovalFailure::manager_may_have_removed(attempt_id, error))?;
    first
        .validate_service_contract(source.scope())
        .map_err(|error| RemovalFailure::manager_may_have_removed(attempt_id, error))?;
    let second = within_deadline(deadline, source.snapshot(deadline))
        .await
        .map_err(|error| RemovalFailure::manager_may_have_removed(attempt_id, error))?;
    second
        .validate_service_contract(source.scope())
        .map_err(|error| RemovalFailure::manager_may_have_removed(attempt_id, error))?;
    if first != second {
        return Err(RemovalFailure::manager_may_have_removed(
            attempt_id,
            FdStoreError::UnstableInventory,
        ));
    }
    let after = CustodyDescriptorBinding::from_custody(custody)
        .map_err(|error| RemovalFailure::manager_may_have_removed(attempt_id, error))?;
    if after != before || after != expected_binding {
        return Err(RemovalFailure::manager_may_have_removed(
            attempt_id,
            invalid_inventory("local custody binding changed during removal"),
        ));
    }
    let projection = baseline
        .snapshot
        .project_exact_removal(&first, custody_name, &expected_binding)
        .map_err(|error| RemovalFailure::manager_may_have_removed(attempt_id, error))?;
    let RemovalProjection::ExactRemoved {
        snapshot,
        stored_descriptors,
    } = projection
    else {
        return Err(RemovalFailure::manager_may_have_removed(
            attempt_id,
            FdStoreError::RemovalStillPresent,
        ));
    };
    ensure_deadline(deadline)
        .map_err(|error| RemovalFailure::manager_may_have_removed(attempt_id, error))?;
    let proof = ExactRemovalProof {
        custody_name,
        binding: expected_binding,
        successor: StableStartupInventory {
            snapshot,
            notify_address: sender_address,
        },
        stored_descriptors,
    };
    attempt.complete_exact_removed(attempt_id);
    Ok(proof)
}

/// Reobserve one exact ambiguous removal attempt. Exact-still-present evidence never authorizes a
/// retry; exact-removed evidence only settles this process-local manager-mutation gate after that
/// exact removal.
#[allow(dead_code)]
pub(crate) async fn reconcile_current_process_removal(
    attempt_id: RemovalAttemptId,
    custody_name: CustodyFdName,
    expected_binding: CustodyDescriptorBinding,
    custody: BorrowedCustodyPair<'_>,
    deadline: HardDeadline,
) -> RemovalInventoryReconciliation {
    if let Err(error) = ensure_deadline(deadline) {
        return RemovalInventoryReconciliation::Unresolved { error };
    }
    let observation = match PRODUCTION_MANAGER_MUTATION_GATE
        .acquire_poisoned_removal(attempt_id, custody_name, &expected_binding, deadline)
        .await
    {
        Ok(observation) => observation,
        Err(error) => return RemovalInventoryReconciliation::Unresolved { error },
    };
    let source = match SystemdDescriptorStoreSource::for_scope(
        observation.poisoned.target.scope.clone(),
        deadline,
    )
    .await
    {
        Ok(source) => source,
        Err(error) => return RemovalInventoryReconciliation::Unresolved { error },
    };
    let sender = match NotifySender::new(&observation.poisoned.target.notify_address) {
        Ok(sender) => sender,
        Err(error) => return RemovalInventoryReconciliation::Unresolved { error },
    };
    reconcile_poisoned_removal(
        observation,
        &source,
        synchronize_manager(&sender, deadline),
        custody,
        deadline,
    )
    .await
}

async fn reconcile_poisoned_removal<S, B>(
    observation: PoisonedRemovalObservation<'_>,
    source: &S,
    barrier: B,
    custody: BorrowedCustodyPair<'_>,
    deadline: HardDeadline,
) -> RemovalInventoryReconciliation
where
    S: DescriptorStoreInventorySource,
    B: Future<Output = Result<(), FdStoreError>>,
{
    let outcome = async {
        ensure_deadline(deadline)?;
        if source.scope() != &observation.poisoned.target.scope {
            return Err(FdStoreError::RemovalTargetMismatch);
        }
        let before = CustodyDescriptorBinding::from_custody(custody)?;
        if before != observation.poisoned.target.binding {
            return Err(FdStoreError::RemovalTargetMismatch);
        }
        within_deadline(deadline, barrier).await?;
        let first = within_deadline(deadline, source.snapshot(deadline)).await?;
        first.validate_service_contract(&observation.poisoned.target.scope)?;
        let second = within_deadline(deadline, source.snapshot(deadline)).await?;
        second.validate_service_contract(&observation.poisoned.target.scope)?;
        if first != second {
            return Err(FdStoreError::UnstableInventory);
        }
        let after = CustodyDescriptorBinding::from_custody(custody)?;
        if before != after || after != observation.poisoned.target.binding {
            return Err(invalid_inventory(
                "local custody binding changed during removal reconciliation",
            ));
        }
        let projection = observation.poisoned.target.baseline.project_exact_removal(
            &first,
            observation.poisoned.target.custody_name,
            &observation.poisoned.target.binding,
        )?;
        ensure_deadline(deadline)?;
        Ok(projection)
    }
    .await;

    match outcome {
        Ok(RemovalProjection::ExactRemoved {
            snapshot,
            stored_descriptors,
        }) => {
            let custody_name = observation.poisoned.target.custody_name;
            let binding = observation.poisoned.target.binding.clone();
            let notify_address = observation.poisoned.target.notify_address.clone();
            observation.complete_exact_removed();
            RemovalInventoryReconciliation::ExactRemoved(ExactRemovalProof {
                custody_name,
                binding,
                successor: StableStartupInventory {
                    snapshot,
                    notify_address,
                },
                stored_descriptors,
            })
        }
        Ok(RemovalProjection::ExactStillPresent { stored_descriptors }) => {
            RemovalInventoryReconciliation::ExactStillPresent(ExactStillPresentRemovalEvidence {
                attempt: observation.poisoned.clone(),
                stored_descriptors,
            })
        }
        Err(error) => RemovalInventoryReconciliation::Unresolved { error },
    }
}

/// Publish through the production systemd manager interfaces. No production server, engine, or
/// request-path caller exists yet.
pub(crate) async fn publish_current_process_custody(
    custody_name: CustodyFdName,
    custody: BorrowedCustodyPair<'_>,
    deadline: HardDeadline,
) -> Result<InventoryAttestation, PublicationFailure> {
    let source = SystemdDescriptorStoreSource::for_current_process(deadline)
        .await
        .map_err(PublicationFailure::before_send)?;
    let address =
        NotifySocketAddress::from_environment().map_err(PublicationFailure::before_send)?;
    publish_and_attest(
        &PRODUCTION_MANAGER_MUTATION_GATE,
        &source,
        &address,
        custody_name,
        custody,
        deadline,
    )
    .await
}

async fn publish_and_attest<S: DescriptorStoreInventorySource>(
    gate: &ManagerMutationGate,
    source: &S,
    address: &NotifySocketAddress,
    custody_name: CustodyFdName,
    custody: BorrowedCustodyPair<'_>,
    deadline: HardDeadline,
) -> Result<InventoryAttestation, PublicationFailure> {
    ensure_deadline(deadline).map_err(PublicationFailure::before_send)?;
    // The gate precedes the baseline read. Two callers can therefore never both validate against
    // the same inventory and subsequently publish from stale state.
    let mut attempt = gate
        .acquire_publication(deadline)
        .await
        .map_err(PublicationFailure::before_send)?;
    let baseline = source
        .snapshot(deadline)
        .await
        .map_err(PublicationFailure::before_send)?;
    let identities = exact_custody_identities(custody).map_err(PublicationFailure::before_send)?;
    baseline
        .validate_baseline(source.scope(), custody_name, &identities)
        .map_err(PublicationFailure::before_send)?;
    let sender = NotifySender::new(address).map_err(PublicationFailure::before_send)?;
    let (barrier_read, barrier_write) = pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK)
        .map_err(nix_io)
        .map_err(PublicationFailure::before_send)?;
    let barrier_read = AsyncFd::new(barrier_read)
        .map_err(FdStoreError::Io)
        .map_err(PublicationFailure::before_send)?;
    let fdstore_message = fdstore_message(custody_name);
    ensure_deadline(deadline).map_err(PublicationFailure::before_send)?;

    // This first send attempt is the irreversible classification boundary. Even an error can no
    // longer justify a blind retry.
    let target = PublicationTarget {
        scope: source.scope().clone(),
        notify_address: address.clone(),
        custody_name,
        identities: identities.clone(),
    };
    let attempt_id = attempt
        .mark_send_attempted(target)
        .map_err(PublicationFailure::before_send)?;
    sender
        .send_once(&fdstore_message, &custody.raw_descriptors())
        .map_err(|error| PublicationFailure::manager_may_own(attempt_id, error))?;
    ensure_deadline(deadline)
        .map_err(|error| PublicationFailure::manager_may_own(attempt_id, error))?;
    sender
        .send_once(BARRIER_MESSAGE, &[barrier_write.as_raw_fd()])
        .map_err(|error| PublicationFailure::manager_may_own(attempt_id, error))?;
    drop(barrier_write);
    wait_for_barrier(&barrier_read, deadline)
        .await
        .map_err(|error| PublicationFailure::manager_may_own(attempt_id, error))?;
    let post = source
        .snapshot(deadline)
        .await
        .map_err(|error| PublicationFailure::manager_may_own(attempt_id, error))?;
    let attestation = baseline
        .attest_extension(&post, custody_name, identities)
        .map_err(|error| PublicationFailure::manager_may_own(attempt_id, error))?;
    ensure_deadline(deadline)
        .map_err(|error| PublicationFailure::manager_may_own(attempt_id, error))?;
    attempt.complete_success(attempt_id);
    Ok(attestation)
}

/// Observation-only evidence that one poisoned in-process publication is present in the exact
/// stable manager inventory projection.
///
/// This is deliberately a different type from [`InventoryAttestation`]. It cannot arm a worker,
/// adopt custody, remove descriptors, clear publication poison, or authorize a retry.
#[must_use = "present descriptor-store evidence must remain bound to its poisoned attempt"]
pub(crate) struct ExactPresentEvidence {
    attempt: PoisonedPublication,
    stored_descriptors: u32,
}

impl fmt::Debug for ExactPresentEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactPresentEvidence(<redacted>)")
    }
}

/// Observation-only evidence that one poisoned in-process publication is absent from the exact
/// stable manager inventory projection.
///
/// Absence does not clear the permanent publication poison and does not authorize a resend.
#[must_use = "absent descriptor-store evidence must remain bound to its poisoned attempt"]
pub(crate) struct ExactAbsentEvidence {
    attempt: PoisonedPublication,
    stored_descriptors: u32,
}

impl fmt::Debug for ExactAbsentEvidence {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("ExactAbsentEvidence(<redacted>)")
    }
}

/// Bounded result of observing one exact, still-poisoned in-process publication attempt.
///
/// Every variant is terminal only for this observation. None changes manager or gate state.
#[must_use = "descriptor-store reconciliation never authorizes an implicit retry"]
pub(crate) enum CustodyInventoryReconciliation {
    ExactPresent(ExactPresentEvidence),
    ExactAbsent(ExactAbsentEvidence),
    Unresolved { error: FdStoreError },
}

impl fmt::Debug for CustodyInventoryReconciliation {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::ExactPresent(_) => formatter.write_str("ExactPresent(<redacted>)"),
            Self::ExactAbsent(_) => formatter.write_str("ExactAbsent(<redacted>)"),
            Self::Unresolved { error } => formatter
                .debug_struct("Unresolved")
                .field("error", error)
                .finish(),
        }
    }
}

/// Observe the manager inventory for the exact poisoned publication attempt.
///
/// The affine descriptor owners remain borrowed across the full barrier and both snapshots. This
/// function reopens the exact unit object stored at the send boundary and reuses that attempt's
/// parsed notify address. It has no production server/request-path caller yet.
#[allow(dead_code)]
pub(crate) async fn reconcile_current_process_custody(
    attempt_id: PublicationAttemptId,
    custody_name: CustodyFdName,
    custody: BorrowedCustodyPair<'_>,
    deadline: HardDeadline,
) -> CustodyInventoryReconciliation {
    if let Err(error) = ensure_deadline(deadline) {
        return CustodyInventoryReconciliation::Unresolved { error };
    }
    let identities = match exact_custody_identities(custody) {
        Ok(identities) => identities,
        Err(error) => return CustodyInventoryReconciliation::Unresolved { error },
    };
    let observation = match PRODUCTION_MANAGER_MUTATION_GATE
        .acquire_poisoned_publication(attempt_id, custody_name, &identities, deadline)
        .await
    {
        Ok(observation) => observation,
        Err(error) => return CustodyInventoryReconciliation::Unresolved { error },
    };
    let source = match SystemdDescriptorStoreSource::for_scope(
        observation.poisoned.target.scope.clone(),
        deadline,
    )
    .await
    {
        Ok(source) => source,
        Err(error) => return CustodyInventoryReconciliation::Unresolved { error },
    };
    let sender = match NotifySender::new(&observation.poisoned.target.notify_address) {
        Ok(sender) => sender,
        Err(error) => return CustodyInventoryReconciliation::Unresolved { error },
    };
    reconcile_poisoned_observation(
        observation,
        &source,
        custody,
        synchronize_manager(&sender, deadline),
        deadline,
    )
    .await
}

async fn reconcile_poisoned_observation<S, B>(
    observation: PoisonedObservation<'_>,
    source: &S,
    custody: BorrowedCustodyPair<'_>,
    barrier: B,
    deadline: HardDeadline,
) -> CustodyInventoryReconciliation
where
    S: DescriptorStoreInventorySource,
    B: Future<Output = Result<(), FdStoreError>>,
{
    let outcome = async {
        ensure_deadline(deadline)?;
        if source.scope() != &observation.poisoned.target.scope {
            return Err(FdStoreError::PublicationTargetMismatch);
        }
        let before = exact_custody_identities(custody)?;
        if before != observation.poisoned.target.identities {
            return Err(FdStoreError::PublicationTargetMismatch);
        }
        within_deadline(deadline, barrier).await?;
        let first = within_deadline(deadline, source.snapshot(deadline)).await?;
        first.validate_service_contract(&observation.poisoned.target.scope)?;
        let second = within_deadline(deadline, source.snapshot(deadline)).await?;
        second.validate_service_contract(&observation.poisoned.target.scope)?;
        if first != second {
            return Err(FdStoreError::UnstableInventory);
        }
        let after = exact_custody_identities(custody)?;
        if before != after || after != observation.poisoned.target.identities {
            return Err(invalid_inventory(
                "retained custody descriptor binding changed during reconciliation",
            ));
        }
        let projection = first.project_poisoned_target(&observation.poisoned.target)?;
        ensure_deadline(deadline)?;
        Ok(projection)
    }
    .await;

    match outcome {
        Ok(TargetInventoryProjection::ExactPresent { stored_descriptors }) => {
            CustodyInventoryReconciliation::ExactPresent(ExactPresentEvidence {
                attempt: observation.poisoned.clone(),
                stored_descriptors,
            })
        }
        Ok(TargetInventoryProjection::ExactAbsent { stored_descriptors }) => {
            CustodyInventoryReconciliation::ExactAbsent(ExactAbsentEvidence {
                attempt: observation.poisoned.clone(),
                stored_descriptors,
            })
        }
        Err(error) => CustodyInventoryReconciliation::Unresolved { error },
    }
}

/// Send one non-mutating systemd manager barrier and wait for its pipe acknowledgement. This
/// orders every earlier notification on the same attempt endpoint before inventory observation.
async fn synchronize_manager(
    sender: &NotifySender,
    deadline: HardDeadline,
) -> Result<(), FdStoreError> {
    ensure_deadline(deadline)?;
    let (barrier_read, barrier_write) =
        pipe2(OFlag::O_CLOEXEC | OFlag::O_NONBLOCK).map_err(nix_io)?;
    let barrier_read = AsyncFd::new(barrier_read).map_err(FdStoreError::Io)?;
    sender.send_once(BARRIER_MESSAGE, &[barrier_write.as_raw_fd()])?;
    drop(barrier_write);
    wait_for_barrier(&barrier_read, deadline).await
}

fn fdstore_message(custody_name: CustodyFdName) -> [u8; FDSTORE_MESSAGE_BYTES] {
    let mut message = [0_u8; FDSTORE_MESSAGE_BYTES];
    let name_start = FDSTORE_PREFIX.len();
    let suffix_start = name_start + CUSTODY_FD_NAME_BYTES;
    message[..name_start].copy_from_slice(FDSTORE_PREFIX);
    message[name_start..suffix_start].copy_from_slice(custody_name.as_bytes());
    message[suffix_start..].copy_from_slice(FDSTORE_SUFFIX);
    message
}

fn fdstore_remove_message(custody_name: CustodyFdName) -> [u8; FDSTORE_REMOVE_MESSAGE_BYTES] {
    let mut message = [0_u8; FDSTORE_REMOVE_MESSAGE_BYTES];
    let name_start = FDSTORE_REMOVE_PREFIX.len();
    message[..name_start].copy_from_slice(FDSTORE_REMOVE_PREFIX);
    message[name_start..].copy_from_slice(custody_name.as_bytes());
    message
}

async fn wait_for_barrier(
    descriptor: &AsyncFd<OwnedFd>,
    deadline: HardDeadline,
) -> Result<(), FdStoreError> {
    loop {
        ensure_deadline(deadline)?;
        let mut readiness = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline.expires_at()),
            descriptor.readable(),
        )
        .await
        .map_err(|_| FdStoreError::Deadline)?
        .map_err(FdStoreError::Io)?;
        let mut byte = [0_u8; 1];
        match read(descriptor.get_ref(), &mut byte) {
            Ok(0) => {
                ensure_deadline(deadline)?;
                return Ok(());
            }
            Ok(_) => return Err(invalid_inventory("systemd barrier pipe carried data")),
            Err(nix::errno::Errno::EAGAIN) => readiness.clear_ready(),
            Err(nix::errno::Errno::EINTR) => {}
            Err(error) => return Err(nix_io(error)),
        }
    }
}

async fn within_deadline<T>(
    deadline: HardDeadline,
    operation: impl Future<Output = Result<T, FdStoreError>>,
) -> Result<T, FdStoreError> {
    ensure_deadline(deadline)?;
    tokio::time::timeout_at(
        tokio::time::Instant::from_std(deadline.expires_at()),
        operation,
    )
    .await
    .map_err(|_| FdStoreError::Deadline)?
}

fn ensure_deadline(deadline: HardDeadline) -> Result<(), FdStoreError> {
    deadline
        .ensure_remaining()
        .map_err(|_| FdStoreError::Deadline)
}

fn invalid_inventory(message: &'static str) -> FdStoreError {
    FdStoreError::InvalidInventory(message)
}

fn nix_io(error: nix::errno::Errno) -> FdStoreError {
    FdStoreError::Io(io::Error::from_raw_os_error(error as i32))
}

#[cfg(test)]
mod tests {
    use std::{
        collections::{BTreeMap, VecDeque},
        fs::OpenOptions,
        io::{IoSliceMut, Write as _},
        os::{
            fd::{AsFd as _, AsRawFd as _},
            unix::{fs::MetadataExt as _, net::UnixDatagram},
        },
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, AtomicUsize, Ordering},
        },
        task::Poll,
        thread,
        time::Duration,
    };

    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
    use tempfile::{NamedTempFile, tempdir, tempfile};

    use super::*;
    use crate::systemd_custody::CUSTODY_FD_NAME_PREFIX;

    struct FakeInventorySource {
        scope: DescriptorStoreScope,
        snapshots: Mutex<VecDeque<DescriptorStoreSnapshot>>,
        required_barrier: Option<Arc<AtomicBool>>,
    }

    impl FakeInventorySource {
        fn new(expected_main_pid: u32, snapshots: Vec<DescriptorStoreSnapshot>) -> Self {
            Self {
                scope: fake_scope(expected_main_pid),
                snapshots: Mutex::new(snapshots.into()),
                required_barrier: None,
            }
        }

        fn after_barrier(
            expected_main_pid: u32,
            snapshots: Vec<DescriptorStoreSnapshot>,
            required_barrier: Arc<AtomicBool>,
        ) -> Self {
            Self {
                scope: fake_scope(expected_main_pid),
                snapshots: Mutex::new(snapshots.into()),
                required_barrier: Some(required_barrier),
            }
        }
    }

    impl DescriptorStoreInventorySource for FakeInventorySource {
        fn scope(&self) -> &DescriptorStoreScope {
            &self.scope
        }

        fn snapshot(
            &self,
            deadline: HardDeadline,
        ) -> impl Future<Output = Result<DescriptorStoreSnapshot, FdStoreError>> + Send {
            let result = ensure_deadline(deadline).and_then(|()| {
                if self
                    .required_barrier
                    .as_ref()
                    .is_some_and(|barrier| !barrier.load(Ordering::SeqCst))
                {
                    return Err(invalid_inventory("snapshot preceded manager barrier"));
                }
                self.snapshots
                    .lock()
                    .map_err(|_| invalid_inventory("fake inventory lock is poisoned"))?
                    .pop_front()
                    .ok_or_else(|| invalid_inventory("fake inventory is exhausted"))
            });
            std::future::ready(result)
        }
    }

    struct FakeIsolationSource {
        scope: DescriptorStoreScope,
        snapshots: Mutex<VecDeque<Result<ServiceCgroupIsolationSnapshot, FdStoreError>>>,
        required_barrier: Option<Arc<AtomicBool>>,
    }

    impl ServiceCgroupIsolationSource for FakeIsolationSource {
        fn scope(&self) -> &DescriptorStoreScope {
            &self.scope
        }

        fn isolation_snapshot(
            &self,
            deadline: HardDeadline,
        ) -> impl Future<Output = Result<ServiceCgroupIsolationSnapshot, FdStoreError>> + Send
        {
            let result = ensure_deadline(deadline).and_then(|()| {
                if self
                    .required_barrier
                    .as_ref()
                    .is_some_and(|barrier| !barrier.load(Ordering::SeqCst))
                {
                    return Err(invalid_inventory(
                        "isolation snapshot preceded manager barrier",
                    ));
                }
                self.snapshots
                    .lock()
                    .map_err(|_| invalid_inventory("fake isolation lock is poisoned"))?
                    .pop_front()
                    .ok_or_else(|| invalid_inventory("fake isolation source is exhausted"))?
            });
            std::future::ready(result)
        }
    }

    fn exact_raw_isolation(
        main_pid: u32,
        control_group_id: u64,
    ) -> RawServiceCgroupIsolationSnapshot {
        RawServiceCgroupIsolationSnapshot {
            invocation_id: vec![0x5a; SYSTEMD_INVOCATION_ID_BYTES],
            main_pid,
            control_pid: 0,
            control_group: "/volparossa-test.service".to_owned(),
            control_group_id,
            delegate: false,
            delegate_controllers: Vec::new(),
            delegate_subgroup: String::new(),
            protect_control_groups: true,
            protect_control_groups_ex: "strict".to_owned(),
            private_pids: "no".to_owned(),
            kill_mode: "control-group".to_owned(),
            send_sigkill: true,
        }
    }

    fn isolation_snapshot(main_pid: u32, control_group_id: u64) -> ServiceCgroupIsolationSnapshot {
        ServiceCgroupIsolationSnapshot::from_raw(
            fake_scope(main_pid),
            exact_raw_isolation(main_pid, control_group_id),
        )
        .expect("exact fake isolation snapshot")
    }

    #[test]
    fn service_cgroup_isolation_rejects_every_non_exact_contract_field() {
        let pid = std::process::id();
        let scope = fake_scope(pid);
        let exact = exact_raw_isolation(pid, 73);
        ServiceCgroupIsolationSnapshot::from_raw(scope.clone(), exact.clone())
            .expect("exact strict isolation contract");

        let mut invalid = Vec::new();
        let mut value = exact.clone();
        value.invocation_id = vec![0; SYSTEMD_INVOCATION_ID_BYTES];
        invalid.push(value);
        let mut value = exact.clone();
        value.invocation_id.pop();
        invalid.push(value);
        let mut value = exact.clone();
        value.main_pid = pid.checked_add(1).unwrap_or(pid - 1);
        invalid.push(value);
        let mut value = exact.clone();
        value.control_pid = 1;
        invalid.push(value);
        let mut value = exact.clone();
        value.control_group = "/".to_owned();
        invalid.push(value);
        let mut value = exact.clone();
        value.control_group_id = 0;
        invalid.push(value);
        let mut value = exact.clone();
        value.delegate = true;
        invalid.push(value);
        let mut value = exact.clone();
        value.delegate_controllers.push("memory".to_owned());
        invalid.push(value);
        let mut value = exact.clone();
        value.delegate_subgroup = "worker".to_owned();
        invalid.push(value);
        let mut value = exact.clone();
        value.protect_control_groups = false;
        invalid.push(value);
        let mut value = exact.clone();
        value.protect_control_groups_ex = "yes".to_owned();
        invalid.push(value);
        let mut value = exact.clone();
        value.private_pids = "yes".to_owned();
        invalid.push(value);
        let mut value = exact.clone();
        value.kill_mode = "mixed".to_owned();
        invalid.push(value);
        let mut value = exact;
        value.send_sigkill = false;
        invalid.push(value);

        for malformed in invalid {
            assert!(ServiceCgroupIsolationSnapshot::from_raw(scope.clone(), malformed).is_err());
        }
    }

    #[test]
    fn service_control_group_path_is_canonical_and_bounded() {
        for malformed in [
            "",
            "/",
            "relative.service",
            "/trailing/",
            "/double//component",
            "/./component",
            "/../component",
            "/deleted (deleted)",
            "/control\u{7f}",
        ] {
            assert!(validate_control_group(malformed).is_err(), "{malformed:?}");
        }
        assert!(validate_control_group("/system.slice/volparossa-helper.service").is_ok());
        let oversized = format!("/{}", "a".repeat(MAX_CONTROL_GROUP_COMPONENT_BYTES + 1));
        assert!(validate_control_group(&oversized).is_err());
    }

    #[tokio::test]
    async fn isolation_observer_requires_barrier_stability_and_exact_kernel_binding() {
        let pid = std::process::id();
        let first = isolation_snapshot(pid, 73);
        let barrier_seen = Arc::new(AtomicBool::new(false));
        let source = FakeIsolationSource {
            scope: fake_scope(pid),
            snapshots: Mutex::new(VecDeque::from([Ok(first.clone()), Ok(first.clone())])),
            required_barrier: Some(Arc::clone(&barrier_seen)),
        };
        let observed_barrier = Arc::clone(&barrier_seen);
        let evidence = observe_stable_service_cgroup_isolation(
            &source,
            async move {
                observed_barrier.store(true, Ordering::SeqCst);
                Ok(())
            },
            HardDeadline::after(Duration::from_secs(2)).expect("isolation deadline"),
        )
        .await
        .expect("stable strict isolation evidence");
        let inventory = stable_inventory(snapshot(pid, Vec::new()), fake_notify_address());
        evidence
            .verify_exact_scope_and_kernel_id(
                &inventory,
                NonZeroU32::new(pid).expect("nonzero current PID"),
                NonZeroU64::new(73).expect("nonzero cgroup ID"),
            )
            .expect("exact service scope and kernel cgroup ID");
        assert!(
            evidence
                .verify_exact_scope_and_kernel_id(
                    &inventory,
                    NonZeroU32::new(pid).expect("nonzero current PID"),
                    NonZeroU64::new(74).expect("nonzero wrong cgroup ID"),
                )
                .is_err()
        );
        assert_eq!(
            format!("{evidence:?}"),
            "StableServiceCgroupIsolation(<redacted>)"
        );

        let changed = isolation_snapshot(pid, 74);
        let unstable = FakeIsolationSource {
            scope: fake_scope(pid),
            snapshots: Mutex::new(VecDeque::from([Ok(first), Ok(changed)])),
            required_barrier: None,
        };
        assert!(matches!(
            observe_stable_service_cgroup_isolation(
                &unstable,
                std::future::ready(Ok(())),
                HardDeadline::after(Duration::from_secs(2)).expect("drift deadline"),
            )
            .await,
            Err(FdStoreError::UnstableInventory)
        ));
    }

    fn custody_name(seed: u8) -> CustodyFdName {
        CustodyFdName::parse(&format!(
            "{}{}",
            CUSTODY_FD_NAME_PREFIX,
            format_args!("{seed:064x}")
        ))
        .expect("valid custody name")
    }

    #[test]
    fn durable_binding_reuses_exact_role_ordered_publication_identities_and_redacts() {
        let pidfd = tempfile().expect("pidfd fixture");
        let mut network_namespace = tempfile().expect("network namespace fixture");
        network_namespace
            .write_all(b"distinct durable descriptor")
            .expect("make durable fixture distinct");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("distinct durable custody roles");
        let [pidfd_identity, namespace_identity] =
            exact_custody_identities(custody).expect("exact publication identities");
        let expected = DurableCustodyDescriptorBinding::try_from_role_ordered(
            durable_descriptor_identity(&pidfd_identity).expect("durable pidfd identity"),
            durable_descriptor_identity(&namespace_identity).expect("durable namespace identity"),
        )
        .expect("valid role-ordered durable binding");
        let reversed = DurableCustodyDescriptorBinding::try_from_role_ordered(
            durable_descriptor_identity(&namespace_identity)
                .expect("reversed durable namespace identity"),
            durable_descriptor_identity(&pidfd_identity).expect("reversed durable pidfd identity"),
        )
        .expect("valid reversed durable binding shape");

        let actual = custody.durable_binding().expect("durable custody binding");

        assert!(actual == expected);
        assert!(actual != reversed, "durable binding preserves role order");
        assert_eq!(
            format!("{actual:?}"),
            "DurableCustodyDescriptorBinding(<redacted>)"
        );

        let duplicate = nix::unistd::dup(pidfd.as_fd()).expect("duplicate pidfd fixture");
        let duplicate_pair = BorrowedCustodyPair::new(pidfd.as_fd(), duplicate.as_fd())
            .expect("duplicate open-file descriptions have distinct descriptor numbers");
        assert!(matches!(
            duplicate_pair.durable_binding(),
            Err(FdStoreError::DuplicateCustodyDescriptor)
        ));
    }

    #[test]
    fn durable_binding_rejects_independent_aliases_with_different_status_flags() {
        let object = NamedTempFile::new().expect("shared kernel-object fixture");
        let first = OpenOptions::new()
            .read(true)
            .open(object.path())
            .expect("first independent open");
        let second = OpenOptions::new()
            .read(true)
            .open(object.path())
            .expect("second independent open");
        fcntl(second.as_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
            .expect("set independent nonblocking flag");
        let first_identity =
            DescriptorIdentity::from_descriptor(first.as_fd()).expect("first identity");
        let second_identity =
            DescriptorIdentity::from_descriptor(second.as_fd()).expect("second identity");
        assert!(first_identity.is_same_kernel_object(&second_identity));
        assert_ne!(first_identity.status_flags, second_identity.status_flags);
        let aliases = BorrowedCustodyPair::new(first.as_fd(), second.as_fd())
            .expect("independent aliases use distinct descriptor numbers");

        assert!(matches!(
            aliases.durable_binding(),
            Err(FdStoreError::DuplicateCustodyDescriptor)
        ));
    }

    fn snapshot(pid: u32, entries: Vec<InventoryEntry>) -> DescriptorStoreSnapshot {
        let mut entries = entries;
        entries.sort_unstable();
        DescriptorStoreSnapshot {
            scope: fake_scope(pid),
            main_pid: pid,
            notify_access: "main".into(),
            store_max: MAX_DESCRIPTOR_STORE_ENTRIES_U32,
            store_preserve: "yes".into(),
            entries,
        }
    }

    fn fake_scope(pid: u32) -> DescriptorStoreScope {
        DescriptorStoreScope::new(
            OwnedUniqueName::try_from(":1.4242").expect("valid fake manager owner"),
            OwnedObjectPath::try_from("/org/freedesktop/systemd1/unit/volparossa_2dtest_2eservice")
                .expect("valid fake service object path"),
            pid,
        )
        .expect("valid fake descriptor-store scope")
    }

    fn inventory_entry(name: CustodyFdName, identity: DescriptorIdentity) -> InventoryEntry {
        InventoryEntry {
            name: Box::<[u8]>::from(name.as_bytes().as_slice()),
            identity,
        }
    }

    fn fake_notify_address() -> NotifySocketAddress {
        NotifySocketAddress::parse(OsStr::new("/run/volparossa-test-notify.sock"))
            .expect("valid fake notify address")
    }

    fn stable_inventory(
        snapshot: DescriptorStoreSnapshot,
        notify_address: NotifySocketAddress,
    ) -> StableStartupInventory {
        StableStartupInventory {
            snapshot,
            notify_address,
        }
    }

    fn custody_binding(custody: BorrowedCustodyPair<'_>) -> CustodyDescriptorBinding {
        CustodyDescriptorBinding::from_custody(custody).expect("exact custody binding")
    }

    fn exact_pair_entries(
        name: CustodyFdName,
        binding: &CustodyDescriptorBinding,
    ) -> [InventoryEntry; DESCRIPTORS_PER_CUSTODY] {
        [
            inventory_entry(name, binding.0[1].clone()),
            inventory_entry(name, binding.0[0].clone()),
        ]
    }

    fn assert_no_datagram(socket: &UnixDatagram) {
        socket
            .set_read_timeout(Some(Duration::from_millis(50)))
            .expect("set no-datagram timeout");
        let mut payload = [0_u8; 1];
        let error = socket
            .recv(&mut payload)
            .expect_err("no manager notification was sent");
        assert!(
            matches!(
                error.kind(),
                io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
            ),
            "unexpected no-datagram error: {error:?}"
        );
    }

    async fn poison_attempt(
        gate: &ManagerMutationGate,
        scope: &DescriptorStoreScope,
        notify_address: &NotifySocketAddress,
        custody_name: CustodyFdName,
        custody: BorrowedCustodyPair<'_>,
    ) -> PublicationAttemptId {
        let identities = exact_custody_identities(custody).expect("exact poisoned identities");
        let mut attempt = gate
            .acquire_publication(
                HardDeadline::after(Duration::from_secs(2)).expect("poison deadline"),
            )
            .await
            .expect("open publication gate");
        attempt
            .mark_send_attempted(PublicationTarget {
                scope: scope.clone(),
                notify_address: notify_address.clone(),
                custody_name,
                identities,
            })
            .expect("poison publication gate")
    }

    async fn reconcile_fake<B>(
        gate: &ManagerMutationGate,
        source: &FakeInventorySource,
        attempt_id: PublicationAttemptId,
        custody_name: CustodyFdName,
        custody: BorrowedCustodyPair<'_>,
        barrier: B,
    ) -> CustodyInventoryReconciliation
    where
        B: Future<Output = Result<(), FdStoreError>>,
    {
        let deadline = HardDeadline::after(Duration::from_secs(2)).expect("reconcile deadline");
        let identities = exact_custody_identities(custody).expect("exact reconcile identities");
        let observation = gate
            .acquire_poisoned_publication(attempt_id, custody_name, &identities, deadline)
            .await
            .expect("exact poisoned observation");
        reconcile_poisoned_observation(observation, source, custody, barrier, deadline).await
    }

    fn descriptor_identity(seed: u32) -> DescriptorIdentity {
        DescriptorIdentity {
            mode: 0o100_600,
            device_major: seed,
            device_minor: seed + 1,
            inode: u64::from(seed) + 2,
            special_device_major: seed + 3,
            special_device_minor: seed + 4,
            status_flags: seed + 5,
        }
    }

    fn assert_invalid_inventory_reason(result: Result<(), FdStoreError>, expected: &'static str) {
        match result {
            Err(FdStoreError::InvalidInventory(observed)) => assert_eq!(observed, expected),
            other => panic!("unexpected baseline validation result: {other:?}"),
        }
    }

    fn receive_message(socket: &UnixDatagram) -> (Vec<u8>, Vec<RawFd>) {
        let mut payload = [0_u8; 256];
        let mut vectors = [IoSliceMut::new(&mut payload)];
        let mut control = nix::cmsg_space!([RawFd; DESCRIPTORS_PER_CUSTODY]);
        let message = recvmsg::<()>(
            socket.as_raw_fd(),
            &mut vectors,
            Some(&mut control),
            MsgFlags::MSG_CMSG_CLOEXEC,
        )
        .expect("receive systemd notification");
        assert!(!message.flags.contains(MsgFlags::MSG_CTRUNC));
        let bytes = message.bytes;
        let mut descriptors = Vec::new();
        for control in message.cmsgs().expect("parse ancillary records") {
            if let ControlMessageOwned::ScmRights(received) = control {
                descriptors.extend(received);
            }
        }
        (payload[..bytes].to_vec(), descriptors)
    }

    fn close_received(descriptors: Vec<RawFd>) {
        for descriptor in descriptors {
            nix::unistd::close(descriptor).expect("close received descriptor");
        }
    }

    fn expected_stat_identity(identity: &DescriptorIdentity) -> (u32, u32, u32, u64, u32, u32) {
        (
            identity.mode,
            identity.device_major,
            identity.device_minor,
            identity.inode,
            identity.special_device_major,
            identity.special_device_minor,
        )
    }

    fn received_stat_identity(descriptor: RawFd) -> (u32, u32, u32, u64, u32, u32) {
        let metadata = std::fs::metadata(format!("/proc/self/fd/{descriptor}"))
            .expect("stat received descriptor through procfs");
        (
            metadata.mode(),
            u32::try_from(major(metadata.dev())).expect("device major fits"),
            u32::try_from(minor(metadata.dev())).expect("device minor fits"),
            metadata.ino(),
            u32::try_from(major(metadata.rdev())).expect("special device major fits"),
            u32::try_from(minor(metadata.rdev())).expect("special device minor fits"),
        )
    }

    #[test]
    fn custody_name_length_and_redaction_are_fixed() {
        let _: fn(DurableCustodyNameDigest) -> CustodyFdName = CustodyFdName::from_durable_digest;
        assert_eq!(CUSTODY_FD_NAME_PREFIX.len(), 22);
        assert_eq!(CUSTODY_FD_NAME_BYTES, 86);
        let name = custody_name(1);
        let debug = format!("{name:?}");
        assert_eq!(debug, "CustodyFdName(<redacted>)");
        assert!(!debug.contains("0000000000000001"));
        assert!(CustodyFdName::parse("volparossa-custody-v1-secret").is_err());
        assert!(
            CustodyFdName::parse(&format!("{}{}", CUSTODY_FD_NAME_PREFIX, "A".repeat(64))).is_err()
        );
    }

    #[test]
    fn exact_attestation_revalidates_name_role_order_and_open_file_identity() {
        let pidfd = tempfile().expect("pidfd fixture");
        let mut network_namespace = tempfile().expect("network namespace fixture");
        network_namespace
            .write_all(b"distinct descriptor")
            .expect("make fixture distinct");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let name = custody_name(24);
        let attestation = InventoryAttestation::for_test_exact_custody(name, custody)
            .expect("exact test attestation");
        assert_eq!(attestation.stored_descriptors, 2);
        assert!(attestation.verify_exact_custody(name, custody).is_ok());
        assert!(
            attestation
                .verify_exact_custody(custody_name(25), custody)
                .is_err()
        );
        let reversed = BorrowedCustodyPair::new(network_namespace.as_fd(), pidfd.as_fd())
            .expect("borrow reversed pair");
        assert!(attestation.verify_exact_custody(name, reversed).is_err());
        assert_eq!(
            format!("{attestation:?}"),
            "InventoryAttestation(<redacted>)"
        );

        let duplicate = nix::unistd::dup(pidfd.as_fd()).expect("duplicate descriptor");
        let duplicate_pair = BorrowedCustodyPair::new(pidfd.as_fd(), duplicate.as_fd())
            .expect("raw descriptors remain distinct");
        assert!(
            InventoryAttestation::for_test_exact_custody(name, duplicate_pair).is_err(),
            "one open file identity cannot fill both custody roles"
        );
    }

    #[test]
    fn baseline_preserves_exact_name_rejection_before_identity_overlap() {
        let target_name = custody_name(26);
        let identities = [descriptor_identity(10), descriptor_identity(20)];
        let baseline = snapshot(
            42,
            vec![inventory_entry(target_name, descriptor_identity(30))],
        );

        assert_invalid_inventory_reason(
            baseline.validate_baseline(&fake_scope(42), target_name, &identities),
            "custody name already exists",
        );
    }

    #[test]
    fn baseline_rejects_partial_and_full_cross_name_identity_overlap() {
        let target_name = custody_name(27);
        let first = descriptor_identity(40);
        let second = descriptor_identity(50);
        let identities = [first.clone(), second.clone()];
        let first_name = custody_name(28);
        let second_name = custody_name(29);
        let partial_first = snapshot(42, vec![inventory_entry(first_name, first.clone())]);
        let partial_second = snapshot(42, vec![inventory_entry(second_name, second.clone())]);
        let full = snapshot(
            42,
            vec![
                inventory_entry(first_name, first),
                inventory_entry(second_name, second),
            ],
        );

        for baseline in [partial_first, partial_second, full] {
            assert_invalid_inventory_reason(
                baseline.validate_baseline(&fake_scope(42), target_name, &identities),
                "custody descriptor identity already exists",
            );
        }

        let mut flag_variant = identities[0].clone();
        flag_variant.status_flags ^=
            u32::try_from(OFlag::O_NONBLOCK.bits()).expect("nonblocking flag fits identity field");
        assert_ne!(flag_variant, identities[0]);
        assert!(flag_variant.is_same_kernel_object(&identities[0]));
        let flagged_alias = snapshot(42, vec![inventory_entry(custody_name(33), flag_variant)]);
        assert_invalid_inventory_reason(
            flagged_alias.validate_baseline(&fake_scope(42), target_name, &identities),
            "custody descriptor identity already exists",
        );
    }

    #[test]
    fn baseline_accepts_unrelated_cross_name_inventory() {
        let target_name = custody_name(30);
        let identities = [descriptor_identity(60), descriptor_identity(70)];
        let baseline = snapshot(
            42,
            vec![
                inventory_entry(custody_name(31), descriptor_identity(80)),
                inventory_entry(custody_name(32), descriptor_identity(90)),
            ],
        );

        baseline
            .validate_baseline(&fake_scope(42), target_name, &identities)
            .expect("unrelated baseline entries remain valid");
    }

    #[test]
    fn notify_socket_accepts_path_and_abstract_but_rejects_empty() {
        assert!(NotifySocketAddress::parse(OsStr::new("/run/example.sock")).is_ok());
        assert!(NotifySocketAddress::parse(OsStr::new("@systemd-test")).is_ok());
        assert!(NotifySocketAddress::parse(OsStr::new("relative.sock")).is_err());
        assert!(NotifySocketAddress::parse(OsStr::new("")).is_err());
        assert!(NotifySocketAddress::parse(OsStr::new("@")).is_err());
    }

    #[tokio::test]
    async fn manager_barrier_waits_for_the_exact_received_pipe_to_close() {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound receive timeout");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let sender = NotifySender::new(&address).expect("barrier sender");
        let (received_sender, received_receiver) = tokio::sync::oneshot::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let receiver_thread = thread::spawn(move || {
            let (message, descriptors) = receive_message(&receiver);
            assert_eq!(message, BARRIER_MESSAGE);
            assert_eq!(descriptors.len(), 1);
            received_sender
                .send(())
                .expect("signal retained barrier descriptor");
            release_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("retain manager barrier descriptor until released");
            close_received(descriptors);
        });
        let deadline = HardDeadline::after(Duration::from_secs(2)).expect("barrier deadline");
        let mut barrier = Box::pin(synchronize_manager(&sender, deadline));
        tokio::select! {
            result = &mut barrier => panic!("barrier completed before manager closed its pipe: {result:?}"),
            barrier_observed = received_receiver => barrier_observed.expect("manager received barrier"),
        }
        release_sender
            .send(())
            .expect("release manager barrier descriptor");
        barrier.await.expect("barrier completes after pipe close");
        receiver_thread.join().expect("fake systemd receiver");
    }

    #[tokio::test]
    async fn startup_observer_barriers_once_and_accepts_exact_unordered_inventory() {
        let first_name = custody_name(60);
        let second_name = custody_name(61);
        let first_binding =
            CustodyDescriptorBinding([descriptor_identity(600), descriptor_identity(610)]);
        let second_binding =
            CustodyDescriptorBinding([descriptor_identity(620), descriptor_identity(630)]);
        let exact = snapshot(
            42,
            vec![
                inventory_entry(first_name, first_binding.0[1].clone()),
                inventory_entry(second_name, second_binding.0[1].clone()),
                inventory_entry(first_name, first_binding.0[0].clone()),
                inventory_entry(second_name, second_binding.0[0].clone()),
            ],
        );
        let barrier_seen = Arc::new(AtomicBool::new(false));
        let barrier_count = Arc::new(AtomicUsize::new(0));
        let source = FakeInventorySource::after_barrier(
            42,
            vec![exact.clone(), exact],
            Arc::clone(&barrier_seen),
        );
        let observed_barrier = Arc::clone(&barrier_seen);
        let observed_count = Arc::clone(&barrier_count);
        let barrier = async move {
            observed_count.fetch_add(1, Ordering::SeqCst);
            observed_barrier.store(true, Ordering::SeqCst);
            Ok(())
        };
        let deadline = HardDeadline::after(Duration::from_secs(2)).expect("startup deadline");

        let inventory =
            observe_stable_startup_inventory(&source, fake_notify_address(), barrier, deadline)
                .await
                .expect("stable exact startup inventory");
        let inherited = BTreeMap::from([
            (first_name, first_binding.clone()),
            (second_name, second_binding.clone()),
        ]);

        inventory
            .verify_complete_exact_set(&inherited)
            .expect("unordered manager pairs match role-ordered inherited pairs");
        assert_eq!(barrier_count.load(Ordering::SeqCst), 1);
        assert!(
            source
                .snapshots
                .lock()
                .expect("fake snapshot lock")
                .is_empty(),
            "both complete snapshots were consumed"
        );
        assert_eq!(
            format!("{inventory:?}"),
            "StableStartupInventory(<redacted>)"
        );

        let wrong = BTreeMap::from([(
            first_name,
            CustodyDescriptorBinding([first_binding.0[0].clone(), descriptor_identity(640)]),
        )]);
        assert!(inventory.verify_complete_exact_set(&wrong).is_err());
    }

    #[tokio::test]
    async fn startup_observer_accepts_exact_empty_inventory() {
        let empty = snapshot(42, Vec::new());
        let barrier_seen = Arc::new(AtomicBool::new(false));
        let source = FakeInventorySource::after_barrier(
            42,
            vec![empty.clone(), empty],
            Arc::clone(&barrier_seen),
        );
        let observed_barrier = Arc::clone(&barrier_seen);
        let inventory = observe_stable_startup_inventory(
            &source,
            fake_notify_address(),
            async move {
                observed_barrier.store(true, Ordering::SeqCst);
                Ok(())
            },
            HardDeadline::after(Duration::from_secs(2)).expect("empty startup deadline"),
        )
        .await
        .expect("stable empty startup inventory");

        inventory
            .verify_complete_exact_set(&BTreeMap::new())
            .expect("empty manager and inherited sets agree");
    }

    #[tokio::test]
    async fn startup_observer_rejects_byte_or_struct_instability() {
        let name = custody_name(62);
        let first_identity = descriptor_identity(650);
        let second_identity = descriptor_identity(660);
        let first = snapshot(
            42,
            vec![
                inventory_entry(name, first_identity.clone()),
                inventory_entry(name, second_identity.clone()),
            ],
        );
        let byte_changed = snapshot(
            42,
            vec![
                inventory_entry(custody_name(63), first_identity.clone()),
                inventory_entry(custody_name(63), second_identity.clone()),
            ],
        );
        let mut flag_changed = first.clone();
        flag_changed.entries[0].identity.status_flags ^= 1;
        flag_changed.entries.sort_unstable();

        for changed in [byte_changed, flag_changed] {
            let source = FakeInventorySource::new(42, vec![first.clone(), changed]);
            let result = observe_stable_startup_inventory(
                &source,
                fake_notify_address(),
                std::future::ready(Ok(())),
                HardDeadline::after(Duration::from_secs(2)).expect("unstable startup deadline"),
            )
            .await;
            assert!(matches!(result, Err(FdStoreError::UnstableInventory)));
        }
    }

    #[tokio::test]
    async fn startup_observer_rejects_malformed_scope_main_pid_and_names() {
        let mut wrong_main_pid = snapshot(42, Vec::new());
        wrong_main_pid.main_pid = 41;
        let mut wrong_scope = snapshot(42, Vec::new());
        wrong_scope.scope = fake_scope(43);
        for malformed in [wrong_main_pid, wrong_scope] {
            let source = FakeInventorySource::new(42, vec![malformed.clone(), malformed]);
            let result = observe_stable_startup_inventory(
                &source,
                fake_notify_address(),
                std::future::ready(Ok(())),
                HardDeadline::after(Duration::from_secs(2)).expect("malformed startup deadline"),
            )
            .await;
            assert!(matches!(result, Err(FdStoreError::InvalidInventory(_))));
        }

        let first = descriptor_identity(670);
        let second = descriptor_identity(680);
        let malformed_name = snapshot(
            42,
            vec![
                InventoryEntry {
                    name: Box::from(&b"legacy-custody"[..]),
                    identity: first.clone(),
                },
                InventoryEntry {
                    name: Box::from(&b"legacy-custody"[..]),
                    identity: second.clone(),
                },
            ],
        );
        let source = FakeInventorySource::new(42, vec![malformed_name.clone(), malformed_name]);
        let inventory = observe_stable_startup_inventory(
            &source,
            fake_notify_address(),
            std::future::ready(Ok(())),
            HardDeadline::after(Duration::from_secs(2)).expect("malformed name deadline"),
        )
        .await
        .expect("service-level snapshot is otherwise stable");
        let inherited =
            BTreeMap::from([(custody_name(64), CustodyDescriptorBinding([first, second]))]);
        assert!(matches!(
            inventory.verify_complete_exact_set(&inherited),
            Err(FdStoreError::InvalidInventory(
                "startup custody name is invalid"
            ))
        ));
    }

    #[tokio::test]
    async fn startup_inventory_rejects_extra_or_partial_custody_sets() {
        let first_name = custody_name(65);
        let second_name = custody_name(66);
        let first_binding =
            CustodyDescriptorBinding([descriptor_identity(690), descriptor_identity(700)]);
        let second_binding =
            CustodyDescriptorBinding([descriptor_identity(710), descriptor_identity(720)]);
        let inherited = BTreeMap::from([(first_name, first_binding.clone())]);
        let extra_snapshot = snapshot(
            42,
            vec![
                inventory_entry(first_name, first_binding.0[0].clone()),
                inventory_entry(first_name, first_binding.0[1].clone()),
                inventory_entry(second_name, second_binding.0[0].clone()),
                inventory_entry(second_name, second_binding.0[1].clone()),
            ],
        );
        let extra_source =
            FakeInventorySource::new(42, vec![extra_snapshot.clone(), extra_snapshot]);
        let extra = observe_stable_startup_inventory(
            &extra_source,
            fake_notify_address(),
            std::future::ready(Ok(())),
            HardDeadline::after(Duration::from_secs(2)).expect("extra startup deadline"),
        )
        .await
        .expect("stable extra manager inventory");
        assert!(matches!(
            extra.verify_complete_exact_set(&inherited),
            Err(FdStoreError::InvalidInventory(
                "startup inventory is not the complete inherited custody set"
            ))
        ));

        let partial_snapshot = snapshot(
            42,
            vec![inventory_entry(first_name, first_binding.0[0].clone())],
        );
        let partial_source =
            FakeInventorySource::new(42, vec![partial_snapshot.clone(), partial_snapshot]);
        let partial = observe_stable_startup_inventory(
            &partial_source,
            fake_notify_address(),
            std::future::ready(Ok(())),
            HardDeadline::after(Duration::from_secs(2)).expect("partial startup deadline"),
        )
        .await
        .expect("stable partial manager inventory");
        assert!(matches!(
            partial.verify_complete_exact_set(&inherited),
            Err(FdStoreError::InvalidInventory(
                "startup custody name does not contain exactly two descriptors"
            ))
        ));
    }

    #[tokio::test]
    async fn startup_inventory_rejects_cross_name_kernel_object_aliases() {
        let first_name = custody_name(67);
        let second_name = custody_name(68);
        let first = descriptor_identity(730);
        let mut alias = first.clone();
        alias.status_flags ^= 1;
        assert_ne!(alias, first);
        assert!(alias.is_same_kernel_object(&first));
        let manager_snapshot = snapshot(
            42,
            vec![
                inventory_entry(first_name, first.clone()),
                inventory_entry(first_name, descriptor_identity(740)),
                inventory_entry(second_name, alias),
                inventory_entry(second_name, descriptor_identity(750)),
            ],
        );
        let source = FakeInventorySource::new(42, vec![manager_snapshot.clone(), manager_snapshot]);
        let manager = observe_stable_startup_inventory(
            &source,
            fake_notify_address(),
            std::future::ready(Ok(())),
            HardDeadline::after(Duration::from_secs(2)).expect("alias startup deadline"),
        )
        .await
        .expect("stable aliased manager inventory");
        let inherited = BTreeMap::from([
            (
                first_name,
                CustodyDescriptorBinding([first, descriptor_identity(740)]),
            ),
            (
                second_name,
                CustodyDescriptorBinding([descriptor_identity(760), descriptor_identity(750)]),
            ),
        ]);

        assert!(matches!(
            manager.verify_complete_exact_set(&inherited),
            Err(FdStoreError::InvalidInventory(
                "startup descriptor identity is reused"
            ))
        ));
    }

    #[tokio::test]
    async fn startup_observer_bounds_barrier_and_snapshots_by_one_deadline() {
        let empty = snapshot(42, Vec::new());
        let source = FakeInventorySource::new(42, vec![empty.clone(), empty]);
        let deadline = HardDeadline::after(Duration::from_millis(20)).expect("short deadline");

        let result = observe_stable_startup_inventory(
            &source,
            fake_notify_address(),
            std::future::pending::<Result<(), FdStoreError>>(),
            deadline,
        )
        .await;

        assert!(matches!(result, Err(FdStoreError::Deadline)));
        assert_eq!(
            source.snapshots.lock().expect("fake snapshot lock").len(),
            2,
            "deadline did not permit a snapshot before barrier acknowledgement"
        );
    }

    #[test]
    fn startup_observer_source_has_only_one_non_mutating_barrier_path() {
        let source = include_str!("systemd_fdstore.rs");
        let start = source
            .find("pub(crate) async fn observe_current_process_startup_inventory")
            .expect("startup observer source start");
        let end = source[start..]
            .find("/// Dormant exact named-removal adapter")
            .map(|offset| start + offset)
            .expect("startup observer source end");
        let observer = &source[start..end];
        assert!(observer.contains("SystemdDescriptorStoreSource::for_current_process"));
        assert!(observer.contains("NotifySocketAddress::from_environment"));
        assert_eq!(observer.matches("synchronize_manager").count(), 1);
        assert_eq!(observer.matches("source.snapshot(deadline)").count(), 2);
        for forbidden in [
            "FDSTORE",
            "publish_and_attest",
            "fdstore_message",
            "FDSTORE_PREFIX",
            "FDSTORE=1",
            "FDSTOREREMOVE=1",
            "READY=1",
        ] {
            assert!(
                !observer.contains(forbidden),
                "startup observer must not contain {forbidden}"
            );
        }
    }

    #[tokio::test]
    async fn shared_gate_blocks_both_cross_direction_transactions_before_inventory_or_send() {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory.path().join("cross-inflight.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let sender = NotifySender::new(&address).expect("manager sender");
        let pidfd = tempfile().expect("pidfd fixture");
        let network_namespace = tempfile().expect("network namespace fixture");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let binding = custody_binding(custody);
        let name = custody_name(69);
        let removal_baseline = snapshot(42, Vec::from(exact_pair_entries(name, &binding)));
        let gate = ManagerMutationGate::new();

        let held_publication = gate
            .acquire_publication(
                HardDeadline::after(Duration::from_secs(2)).expect("held publication deadline"),
            )
            .await
            .expect("hold publication transaction");
        let removal_source = FakeInventorySource::new(42, vec![removal_baseline.clone()]);
        let mut blocked_removal = Box::pin(remove_and_attest(
            &gate,
            &removal_source,
            &sender,
            stable_inventory(removal_baseline, address.clone()),
            name,
            binding,
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("blocked removal deadline"),
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut blocked_removal)
                .await
                .is_err(),
            "removal must wait behind an in-flight publication"
        );
        drop(blocked_removal);
        assert_eq!(
            removal_source
                .snapshots
                .lock()
                .expect("removal snapshots")
                .len(),
            1,
            "blocked removal must not read a preflight snapshot"
        );
        assert_no_datagram(&receiver);
        drop(held_publication);
        drop(
            gate.acquire_removal(
                HardDeadline::after(Duration::from_secs(1)).expect("released removal deadline"),
            )
            .await
            .expect("dropping an unpoisoned publication releases removal"),
        );

        let held_removal = gate
            .acquire_removal(
                HardDeadline::after(Duration::from_secs(2)).expect("held removal deadline"),
            )
            .await
            .expect("hold removal transaction");
        let publication_source = FakeInventorySource::new(42, vec![snapshot(42, Vec::new())]);
        let mut blocked_publication = Box::pin(publish_and_attest(
            &gate,
            &publication_source,
            &address,
            custody_name(68),
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("blocked publication deadline"),
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut blocked_publication)
                .await
                .is_err(),
            "publication must wait behind an in-flight removal"
        );
        drop(blocked_publication);
        assert_eq!(
            publication_source
                .snapshots
                .lock()
                .expect("publication snapshots")
                .len(),
            1,
            "blocked publication must not read a baseline snapshot"
        );
        assert_no_datagram(&receiver);
        drop(held_removal);
        drop(
            gate.acquire_publication(
                HardDeadline::after(Duration::from_secs(1)).expect("released publication deadline"),
            )
            .await
            .expect("dropping an unpoisoned removal releases publication"),
        );
    }

    #[tokio::test]
    async fn exact_removal_is_payload_only_barriered_and_preserves_unrelated_inventory_and_owners()
    {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory.path().join("remove-notify.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound receive timeout");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let sender = NotifySender::new(&address).expect("removal sender");
        let pidfd = tempfile().expect("pidfd fixture");
        let mut network_namespace = tempfile().expect("network namespace fixture");
        network_namespace
            .write_all(b"distinct removal descriptor")
            .expect("make removal fixture distinct");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow removal pair");
        let binding = custody_binding(custody);
        let target_name = custody_name(70);
        let unrelated_name = custody_name(71);
        let unrelated_binding =
            CustodyDescriptorBinding([descriptor_identity(800), descriptor_identity(810)]);
        let mut baseline_entries = Vec::from(exact_pair_entries(target_name, &binding));
        baseline_entries.extend(exact_pair_entries(unrelated_name, &unrelated_binding));
        let baseline_snapshot = snapshot(42, baseline_entries);
        let successor_snapshot = snapshot(
            42,
            Vec::from(exact_pair_entries(unrelated_name, &unrelated_binding)),
        );
        let source = FakeInventorySource::new(
            42,
            vec![
                baseline_snapshot.clone(),
                successor_snapshot.clone(),
                successor_snapshot,
            ],
        );
        let gate = ManagerMutationGate::new();
        let expected_removal = fdstore_remove_message(target_name);
        let receiver_thread = thread::spawn(move || {
            let (message, descriptors) = receive_message(&receiver);
            assert_eq!(message, expected_removal);
            assert!(descriptors.is_empty(), "removal carried ancillary FDs");
            for forbidden in [b"FDSTORE=1".as_slice(), b"FDPOLL=0", b"READY=1"] {
                assert!(
                    !message
                        .windows(forbidden.len())
                        .any(|window| window == forbidden),
                    "removal carried forbidden assignment"
                );
            }
            let (message, descriptors) = receive_message(&receiver);
            assert_eq!(message, BARRIER_MESSAGE);
            assert_eq!(descriptors.len(), 1, "barrier carried the wrong FD count");
            close_received(descriptors);
        });
        let deadline = HardDeadline::after(Duration::from_secs(2)).expect("removal deadline");

        let proof = remove_and_attest(
            &gate,
            &source,
            &sender,
            stable_inventory(baseline_snapshot, address.clone()),
            target_name,
            binding.clone(),
            custody,
            deadline,
        )
        .await
        .expect("exact named removal");

        receiver_thread.join().expect("fake systemd receiver");
        proof
            .verify_exact_target(target_name, &binding)
            .expect("proof target correlation");
        assert_eq!(proof.stored_descriptors, 2);
        assert_eq!(format!("{proof:?}"), "ExactRemovalProof(<redacted>)");
        DescriptorIdentity::from_descriptor(pidfd.as_fd()).expect("pidfd owner remains alive");
        DescriptorIdentity::from_descriptor(network_namespace.as_fd())
            .expect("namespace owner remains alive");
        let successor = proof.into_successor();
        assert_eq!(successor.notify_address, address);
        successor
            .verify_complete_exact_set(&BTreeMap::from([(unrelated_name, unrelated_binding)]))
            .expect("only the unrelated pair remains");
        drop(
            gate.acquire_removal(
                HardDeadline::after(Duration::from_secs(2)).expect("open gate deadline"),
            )
            .await
            .expect("successful removal clears gate"),
        );
    }

    #[test]
    fn removal_baseline_requires_fixed_complete_unaliased_pairs_and_exact_target_binding() {
        let target_name = custody_name(72);
        let unrelated_name = custody_name(73);
        let binding =
            CustodyDescriptorBinding([descriptor_identity(820), descriptor_identity(830)]);
        let exact = snapshot(42, Vec::from(exact_pair_entries(target_name, &binding)));
        exact
            .validate_removal_target(&fake_scope(42), target_name, &binding)
            .expect("exact unordered target pair is valid");

        let absent = snapshot(42, Vec::from(exact_pair_entries(unrelated_name, &binding)));
        assert!(matches!(
            absent.validate_removal_target(&fake_scope(42), target_name, &binding),
            Err(FdStoreError::InvalidInventory(
                "removal target is absent from the baseline"
            ))
        ));

        let partial = snapshot(42, vec![inventory_entry(target_name, binding.0[0].clone())]);
        assert!(matches!(
            partial.validate_removal_target(&fake_scope(42), target_name, &binding),
            Err(FdStoreError::InvalidInventory(
                "removal baseline custody name does not contain exactly two descriptors"
            ))
        ));

        let mut overfull_entries = Vec::from(exact_pair_entries(target_name, &binding));
        overfull_entries.push(inventory_entry(target_name, descriptor_identity(840)));
        let overfull = snapshot(42, overfull_entries);
        assert!(matches!(
            overfull.validate_removal_target(&fake_scope(42), target_name, &binding),
            Err(FdStoreError::InvalidInventory(
                "removal baseline custody name does not contain exactly two descriptors"
            ))
        ));

        let wrong = CustodyDescriptorBinding([binding.0[0].clone(), descriptor_identity(850)]);
        assert!(matches!(
            exact.validate_removal_target(&fake_scope(42), target_name, &wrong),
            Err(FdStoreError::InvalidInventory(
                "removal target does not match the exact local binding"
            ))
        ));

        let mut malformed_entries = Vec::from(exact_pair_entries(target_name, &binding));
        malformed_entries.extend([
            InventoryEntry {
                name: Box::from(&b"legacy-name"[..]),
                identity: descriptor_identity(860),
            },
            InventoryEntry {
                name: Box::from(&b"legacy-name"[..]),
                identity: descriptor_identity(870),
            },
        ]);
        let malformed = snapshot(42, malformed_entries);
        assert!(matches!(
            malformed.validate_removal_target(&fake_scope(42), target_name, &binding),
            Err(FdStoreError::InvalidInventory(
                "removal baseline custody name is invalid"
            ))
        ));

        let mut alias = binding.0[0].clone();
        alias.status_flags ^= 1;
        assert!(alias.is_same_kernel_object(&binding.0[0]));
        let mut aliased_entries = Vec::from(exact_pair_entries(target_name, &binding));
        aliased_entries.extend([
            inventory_entry(unrelated_name, alias),
            inventory_entry(unrelated_name, descriptor_identity(880)),
        ]);
        let aliased = snapshot(42, aliased_entries);
        assert!(matches!(
            aliased.validate_removal_target(&fake_scope(42), target_name, &binding),
            Err(FdStoreError::InvalidInventory(
                "removal baseline descriptor identity is reused"
            ))
        ));
    }

    #[test]
    fn removal_projection_accepts_only_unchanged_or_exact_baseline_minus_target() {
        let target_name = custody_name(74);
        let unrelated_name = custody_name(75);
        let added_name = custody_name(76);
        let binding =
            CustodyDescriptorBinding([descriptor_identity(900), descriptor_identity(910)]);
        let unrelated =
            CustodyDescriptorBinding([descriptor_identity(920), descriptor_identity(930)]);
        let mut baseline_entries = Vec::from(exact_pair_entries(target_name, &binding));
        baseline_entries.extend(exact_pair_entries(unrelated_name, &unrelated));
        let baseline = snapshot(42, baseline_entries);
        let exact_post = snapshot(
            42,
            Vec::from(exact_pair_entries(unrelated_name, &unrelated)),
        );

        assert!(matches!(
            baseline
                .project_exact_removal(&baseline, target_name, &binding)
                .expect("unchanged projection"),
            RemovalProjection::ExactStillPresent {
                stored_descriptors: 4
            }
        ));
        assert!(matches!(
            baseline
                .project_exact_removal(&exact_post, target_name, &binding)
                .expect("exact removed projection"),
            RemovalProjection::ExactRemoved {
                stored_descriptors: 2,
                ..
            }
        ));

        let mut partial_entries = Vec::from(exact_pair_entries(unrelated_name, &unrelated));
        partial_entries.push(inventory_entry(target_name, binding.0[0].clone()));
        let partial = snapshot(42, partial_entries);
        let mut wrong = exact_post.clone();
        wrong.entries[0].identity.status_flags ^= 1;
        wrong.entries.sort_unstable();
        let mut extra_entries = exact_post.entries.clone();
        extra_entries.extend(exact_pair_entries(
            added_name,
            &CustodyDescriptorBinding([descriptor_identity(940), descriptor_identity(950)]),
        ));
        let extra = snapshot(42, extra_entries);
        let unrelated_partial = snapshot(
            42,
            vec![inventory_entry(unrelated_name, unrelated.0[0].clone())],
        );
        let mut service_drift = exact_post.clone();
        service_drift.notify_access = "all".into();

        for drift in [partial, wrong, extra, unrelated_partial, service_drift] {
            assert!(matches!(
                baseline.project_exact_removal(&drift, target_name, &binding),
                Err(FdStoreError::InvalidInventory(_))
            ));
        }
    }

    #[tokio::test]
    async fn removal_preflight_drift_is_before_send_and_emits_no_datagram() {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory.path().join("preflight-drift.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let sender = NotifySender::new(&address).expect("removal sender");
        let pidfd = tempfile().expect("pidfd fixture");
        let network_namespace = tempfile().expect("network namespace fixture");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow removal pair");
        let binding = custody_binding(custody);
        let target_name = custody_name(77);
        let baseline_snapshot = snapshot(42, Vec::from(exact_pair_entries(target_name, &binding)));
        let unrelated_name = custody_name(78);
        let unrelated =
            CustodyDescriptorBinding([descriptor_identity(960), descriptor_identity(970)]);
        let mut drifted_entries = baseline_snapshot.entries.clone();
        drifted_entries.extend(exact_pair_entries(unrelated_name, &unrelated));
        let source = FakeInventorySource::new(42, vec![snapshot(42, drifted_entries)]);
        let gate = ManagerMutationGate::new();

        let result = remove_and_attest(
            &gate,
            &source,
            &sender,
            stable_inventory(baseline_snapshot, address),
            target_name,
            binding,
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("preflight deadline"),
        )
        .await;

        assert!(matches!(
            result,
            Err(RemovalFailure::BeforeSend {
                error: FdStoreError::InvalidInventory(
                    "removal baseline changed before the send boundary"
                )
            })
        ));
        assert_no_datagram(&receiver);
        drop(
            gate.acquire_removal(
                HardDeadline::after(Duration::from_secs(2)).expect("open gate deadline"),
            )
            .await
            .expect("preflight failure leaves gate open"),
        );
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one test follows one poisoned attempt through every forbidden and terminal path"
    )]
    #[tokio::test]
    async fn exact_still_present_poison_reconciles_without_blind_retry() {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory.path().join("still-present.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound receive timeout");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let sender = NotifySender::new(&address).expect("removal sender");
        let pidfd = tempfile().expect("pidfd fixture");
        let network_namespace = tempfile().expect("network namespace fixture");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow removal pair");
        let binding = custody_binding(custody);
        let target_name = custody_name(79);
        let baseline_snapshot = snapshot(42, Vec::from(exact_pair_entries(target_name, &binding)));
        let source = FakeInventorySource::new(
            42,
            vec![
                baseline_snapshot.clone(),
                baseline_snapshot.clone(),
                baseline_snapshot.clone(),
            ],
        );
        let gate = ManagerMutationGate::new();
        let expected_removal = fdstore_remove_message(target_name);
        let receiver_thread = thread::spawn(move || {
            let (message, descriptors) = receive_message(&receiver);
            assert_eq!(message, expected_removal);
            assert!(descriptors.is_empty());
            let (message, descriptors) = receive_message(&receiver);
            assert_eq!(message, BARRIER_MESSAGE);
            assert_eq!(descriptors.len(), 1);
            close_received(descriptors);
        });

        let result = remove_and_attest(
            &gate,
            &source,
            &sender,
            stable_inventory(baseline_snapshot.clone(), address.clone()),
            target_name,
            binding.clone(),
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("removal deadline"),
        )
        .await;
        receiver_thread.join().expect("fake systemd receiver");
        let attempt_id = match result {
            Err(RemovalFailure::ManagerMayHaveRemoved {
                attempt_id,
                error: FdStoreError::RemovalStillPresent,
            }) => attempt_id,
            other => panic!("unexpected still-present result: {other:?}"),
        };
        assert!(matches!(
            gate.acquire_removal(
                HardDeadline::after(Duration::from_secs(2)).expect("poison check deadline")
            )
            .await,
            Err(FdStoreError::RemovalPoisoned)
        ));

        let blocked_path = directory
            .path()
            .join("removal-poison-blocks-publication.sock");
        let blocked_receiver =
            UnixDatagram::bind(&blocked_path).expect("bind blocked publication socket");
        let blocked_address =
            NotifySocketAddress::parse(blocked_path.as_os_str()).expect("blocked notify address");
        let blocked_publication_source =
            FakeInventorySource::new(42, vec![snapshot(42, Vec::new())]);
        let blocked_publication = publish_and_attest(
            &gate,
            &blocked_publication_source,
            &blocked_address,
            custody_name(78),
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("blocked publication deadline"),
        )
        .await;
        assert!(matches!(
            blocked_publication,
            Err(PublicationFailure::BeforeSend {
                error: FdStoreError::PublicationPoisoned
            })
        ));
        assert_eq!(
            blocked_publication_source
                .snapshots
                .lock()
                .expect("blocked publication snapshots")
                .len(),
            1,
            "removal poison blocks publication before its baseline read"
        );
        assert_no_datagram(&blocked_receiver);

        let identities = exact_custody_identities(custody).expect("cross-kind identities");
        assert!(matches!(
            gate.acquire_poisoned_publication(
                PublicationAttemptId::for_test(attempt_id.0.get()),
                target_name,
                &identities,
                HardDeadline::after(Duration::from_secs(2))
                    .expect("wrong-kind publication reconciliation deadline"),
            )
            .await,
            Err(FdStoreError::PublicationTargetMismatch)
        ));

        let wrong_scope_source = FakeInventorySource::new(43, Vec::new());
        let wrong_scope_observation = gate
            .acquire_poisoned_removal(
                attempt_id,
                target_name,
                &binding,
                HardDeadline::after(Duration::from_secs(2))
                    .expect("wrong-scope removal observation deadline"),
            )
            .await
            .expect("exact removal poison remains observable");
        assert!(matches!(
            reconcile_poisoned_removal(
                wrong_scope_observation,
                &wrong_scope_source,
                std::future::ready(Ok(())),
                custody,
                HardDeadline::after(Duration::from_secs(2))
                    .expect("wrong-scope removal reconciliation deadline"),
            )
            .await,
            RemovalInventoryReconciliation::Unresolved {
                error: FdStoreError::RemovalTargetMismatch
            }
        ));
        assert!(matches!(
            gate.acquire_publication(
                HardDeadline::after(Duration::from_secs(2))
                    .expect("unresolved cross-poison deadline")
            )
            .await,
            Err(FdStoreError::PublicationPoisoned)
        ));

        let retry_source = FakeInventorySource::new(42, vec![baseline_snapshot.clone()]);
        let retry = remove_and_attest(
            &gate,
            &retry_source,
            &sender,
            stable_inventory(baseline_snapshot.clone(), address),
            target_name,
            binding.clone(),
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("retry deadline"),
        )
        .await;
        assert!(matches!(
            retry,
            Err(RemovalFailure::BeforeSend {
                error: FdStoreError::RemovalPoisoned
            })
        ));
        assert_eq!(
            retry_source
                .snapshots
                .lock()
                .expect("retry snapshots")
                .len(),
            1,
            "blocked retry did not even reobserve the manager"
        );

        let mismatch_deadline =
            HardDeadline::after(Duration::from_secs(2)).expect("mismatch deadline");
        assert!(matches!(
            gate.acquire_poisoned_removal(
                RemovalAttemptId::for_test(999),
                target_name,
                &binding,
                mismatch_deadline,
            )
            .await,
            Err(FdStoreError::RemovalTargetMismatch)
        ));
        assert!(matches!(
            gate.acquire_poisoned_removal(
                attempt_id,
                custody_name(80),
                &binding,
                mismatch_deadline,
            )
            .await,
            Err(FdStoreError::RemovalTargetMismatch)
        ));
        let wrong_binding =
            CustodyDescriptorBinding([binding.0[0].clone(), descriptor_identity(980)]);
        assert!(matches!(
            gate.acquire_poisoned_removal(
                attempt_id,
                target_name,
                &wrong_binding,
                mismatch_deadline,
            )
            .await,
            Err(FdStoreError::RemovalTargetMismatch)
        ));

        let still_source = FakeInventorySource::new(
            42,
            vec![baseline_snapshot.clone(), baseline_snapshot.clone()],
        );
        let observation = gate
            .acquire_poisoned_removal(
                attempt_id,
                target_name,
                &binding,
                HardDeadline::after(Duration::from_secs(2)).expect("still observation deadline"),
            )
            .await
            .expect("exact poisoned attempt");
        let still = reconcile_poisoned_removal(
            observation,
            &still_source,
            std::future::ready(Ok(())),
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("still reconcile deadline"),
        )
        .await;
        match still {
            RemovalInventoryReconciliation::ExactStillPresent(evidence) => {
                assert_eq!(evidence.attempt.attempt_id, attempt_id);
                assert_eq!(evidence.stored_descriptors, 2);
                assert_eq!(
                    format!("{evidence:?}"),
                    "ExactStillPresentRemovalEvidence(<redacted>)"
                );
            }
            other => panic!("unexpected exact-still-present reconciliation: {other:?}"),
        }
        assert!(matches!(
            gate.acquire_removal(
                HardDeadline::after(Duration::from_secs(2)).expect("still poison deadline")
            )
            .await,
            Err(FdStoreError::RemovalPoisoned)
        ));
        let blocked_again = publish_and_attest(
            &gate,
            &blocked_publication_source,
            &blocked_address,
            custody_name(78),
            custody,
            HardDeadline::after(Duration::from_secs(2))
                .expect("still-present cross-poison deadline"),
        )
        .await;
        assert!(matches!(
            blocked_again,
            Err(PublicationFailure::BeforeSend {
                error: FdStoreError::PublicationPoisoned
            })
        ));
        assert_eq!(
            blocked_publication_source
                .snapshots
                .lock()
                .expect("still blocked publication snapshots")
                .len(),
            1,
            "exact-still-present observation cannot release publication"
        );
        assert_no_datagram(&blocked_receiver);

        let removed_snapshot = snapshot(42, Vec::new());
        let removed_source =
            FakeInventorySource::new(42, vec![removed_snapshot.clone(), removed_snapshot]);
        let observation = gate
            .acquire_poisoned_removal(
                attempt_id,
                target_name,
                &binding,
                HardDeadline::after(Duration::from_secs(2)).expect("removed observation deadline"),
            )
            .await
            .expect("same exact poisoned attempt");
        let removed = reconcile_poisoned_removal(
            observation,
            &removed_source,
            std::future::ready(Ok(())),
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("removed reconcile deadline"),
        )
        .await;
        match removed {
            RemovalInventoryReconciliation::ExactRemoved(proof) => {
                proof
                    .verify_exact_target(target_name, &binding)
                    .expect("exact removed target");
                assert_eq!(proof.stored_descriptors, 0);
            }
            other => panic!("unexpected exact-removed reconciliation: {other:?}"),
        }
        drop(
            gate.acquire_publication(
                HardDeadline::after(Duration::from_secs(2)).expect("cleared gate deadline"),
            )
            .await
            .expect("exact-removed reconciliation reopens publication too"),
        );
    }

    #[tokio::test]
    async fn unstable_post_send_inventory_is_ambiguous_and_poisoned() {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory.path().join("unstable-removal.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound receive timeout");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let sender = NotifySender::new(&address).expect("removal sender");
        let pidfd = tempfile().expect("pidfd fixture");
        let network_namespace = tempfile().expect("network namespace fixture");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow removal pair");
        let binding = custody_binding(custody);
        let target_name = custody_name(81);
        let baseline_snapshot = snapshot(42, Vec::from(exact_pair_entries(target_name, &binding)));
        let removed_snapshot = snapshot(42, Vec::new());
        let source = FakeInventorySource::new(
            42,
            vec![
                baseline_snapshot.clone(),
                removed_snapshot,
                baseline_snapshot.clone(),
            ],
        );
        let gate = ManagerMutationGate::new();
        let receiver_thread = thread::spawn(move || {
            let (message, descriptors) = receive_message(&receiver);
            assert_eq!(message, fdstore_remove_message(target_name));
            assert!(descriptors.is_empty());
            let (message, descriptors) = receive_message(&receiver);
            assert_eq!(message, BARRIER_MESSAGE);
            assert_eq!(descriptors.len(), 1);
            close_received(descriptors);
        });

        let result = remove_and_attest(
            &gate,
            &source,
            &sender,
            stable_inventory(baseline_snapshot, address),
            target_name,
            binding,
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("unstable deadline"),
        )
        .await;

        receiver_thread.join().expect("fake systemd receiver");
        assert!(matches!(
            result,
            Err(RemovalFailure::ManagerMayHaveRemoved {
                error: FdStoreError::UnstableInventory,
                ..
            })
        ));
        assert!(matches!(
            gate.acquire_removal(
                HardDeadline::after(Duration::from_secs(2)).expect("poison deadline")
            )
            .await,
            Err(FdStoreError::RemovalPoisoned)
        ));
    }

    #[tokio::test]
    async fn local_owner_drift_after_barrier_is_ambiguous_and_poisoned() {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory.path().join("local-drift.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound receive timeout");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let sender = NotifySender::new(&address).expect("removal sender");
        let pidfd = tempfile().expect("pidfd fixture");
        let network_namespace = tempfile().expect("network namespace fixture");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow removal pair");
        let binding = custody_binding(custody);
        let shared_pidfd = nix::unistd::dup(pidfd.as_fd()).expect("duplicate shared pidfd");
        let target_name = custody_name(82);
        let baseline_snapshot = snapshot(42, Vec::from(exact_pair_entries(target_name, &binding)));
        let removed_snapshot = snapshot(42, Vec::new());
        let source = FakeInventorySource::new(
            42,
            vec![
                baseline_snapshot.clone(),
                removed_snapshot.clone(),
                removed_snapshot,
            ],
        );
        let gate = ManagerMutationGate::new();
        let receiver_thread = thread::spawn(move || {
            let (message, descriptors) = receive_message(&receiver);
            assert_eq!(message, fdstore_remove_message(target_name));
            assert!(descriptors.is_empty());
            let (message, descriptors) = receive_message(&receiver);
            assert_eq!(message, BARRIER_MESSAGE);
            assert_eq!(descriptors.len(), 1);
            fcntl(shared_pidfd.as_fd(), FcntlArg::F_SETFL(OFlag::O_NONBLOCK))
                .expect("change retained open-file status flags");
            close_received(descriptors);
        });

        let result = remove_and_attest(
            &gate,
            &source,
            &sender,
            stable_inventory(baseline_snapshot, address),
            target_name,
            binding,
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("local drift deadline"),
        )
        .await;

        receiver_thread.join().expect("fake systemd receiver");
        assert!(matches!(
            result,
            Err(RemovalFailure::ManagerMayHaveRemoved {
                error: FdStoreError::InvalidInventory(
                    "local custody binding changed during removal"
                ),
                ..
            })
        ));
        assert!(matches!(
            gate.acquire_removal(
                HardDeadline::after(Duration::from_secs(2)).expect("poison deadline")
            )
            .await,
            Err(FdStoreError::RemovalPoisoned)
        ));
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one test compares both sides of the removal send boundary under deadlines"
    )]
    #[tokio::test]
    async fn removal_deadline_before_and_after_send_preserves_attempt_boundary() {
        let directory = tempdir().expect("notification directory");
        let before_path = directory.path().join("before-deadline.sock");
        let before_receiver =
            UnixDatagram::bind(&before_path).expect("bind before-deadline socket");
        let before_address =
            NotifySocketAddress::parse(before_path.as_os_str()).expect("before notify address");
        let before_sender = NotifySender::new(&before_address).expect("before sender");
        let pidfd = tempfile().expect("pidfd fixture");
        let network_namespace = tempfile().expect("network namespace fixture");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow removal pair");
        let binding = custody_binding(custody);
        let target_name = custody_name(83);
        let baseline_snapshot = snapshot(42, Vec::from(exact_pair_entries(target_name, &binding)));
        let before_source = FakeInventorySource::new(42, vec![baseline_snapshot.clone()]);
        let before_gate = ManagerMutationGate::new();
        let expired = HardDeadline::after(Duration::from_millis(1)).expect("short deadline");
        tokio::time::sleep(Duration::from_millis(5)).await;

        let before = remove_and_attest(
            &before_gate,
            &before_source,
            &before_sender,
            stable_inventory(baseline_snapshot.clone(), before_address),
            target_name,
            binding.clone(),
            custody,
            expired,
        )
        .await;
        assert!(matches!(
            before,
            Err(RemovalFailure::BeforeSend {
                error: FdStoreError::Deadline
            })
        ));
        assert_no_datagram(&before_receiver);
        drop(
            before_gate
                .acquire_removal(
                    HardDeadline::after(Duration::from_secs(2)).expect("before open-gate deadline"),
                )
                .await
                .expect("expired before-send leaves gate open"),
        );

        let after_path = directory.path().join("after-deadline.sock");
        let after_receiver = UnixDatagram::bind(&after_path).expect("bind after-deadline socket");
        after_receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound receive timeout");
        let after_address =
            NotifySocketAddress::parse(after_path.as_os_str()).expect("after notify address");
        let after_sender = NotifySender::new(&after_address).expect("after sender");
        let removed_snapshot = snapshot(42, Vec::new());
        let after_source = FakeInventorySource::new(
            42,
            vec![
                baseline_snapshot.clone(),
                removed_snapshot.clone(),
                removed_snapshot,
            ],
        );
        let after_gate = ManagerMutationGate::new();
        let receiver_thread = thread::spawn(move || {
            let (message, descriptors) = receive_message(&after_receiver);
            assert_eq!(message, fdstore_remove_message(target_name));
            assert!(descriptors.is_empty());
            let (message, descriptors) = receive_message(&after_receiver);
            assert_eq!(message, BARRIER_MESSAGE);
            assert_eq!(descriptors.len(), 1);
            thread::sleep(Duration::from_millis(400));
            close_received(descriptors);
        });
        let one_deadline =
            HardDeadline::after(Duration::from_millis(200)).expect("one removal deadline");

        let after = remove_and_attest(
            &after_gate,
            &after_source,
            &after_sender,
            stable_inventory(baseline_snapshot, after_address),
            target_name,
            binding,
            custody,
            one_deadline,
        )
        .await;

        receiver_thread.join().expect("fake systemd receiver");
        assert!(matches!(
            after,
            Err(RemovalFailure::ManagerMayHaveRemoved {
                error: FdStoreError::Deadline,
                ..
            })
        ));
        assert!(matches!(
            after_gate
                .acquire_removal(
                    HardDeadline::after(Duration::from_secs(2)).expect("after poison deadline")
                )
                .await,
            Err(FdStoreError::RemovalPoisoned)
        ));
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one test compares cancellation immediately before and after the send boundary"
    )]
    #[tokio::test]
    async fn cancellation_before_send_is_clean_but_after_send_remains_poisoned() {
        let directory = tempdir().expect("notification directory");
        let pidfd = tempfile().expect("pidfd fixture");
        let network_namespace = tempfile().expect("network namespace fixture");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow removal pair");
        let binding = custody_binding(custody);
        let target_name = custody_name(84);
        let baseline_snapshot = snapshot(42, Vec::from(exact_pair_entries(target_name, &binding)));

        let before_path = directory.path().join("cancel-before.sock");
        let before_receiver = UnixDatagram::bind(&before_path).expect("bind cancel-before socket");
        let before_address =
            NotifySocketAddress::parse(before_path.as_os_str()).expect("before notify address");
        let before_sender = NotifySender::new(&before_address).expect("before sender");
        let before_source = FakeInventorySource::new(42, vec![baseline_snapshot.clone()]);
        let before_gate = ManagerMutationGate::new();
        let held = before_gate
            .acquire_removal(
                HardDeadline::after(Duration::from_secs(2)).expect("held-gate deadline"),
            )
            .await
            .expect("hold removal gate before boundary");
        let mut before = Box::pin(remove_and_attest(
            &before_gate,
            &before_source,
            &before_sender,
            stable_inventory(baseline_snapshot.clone(), before_address),
            target_name,
            binding.clone(),
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("cancel-before deadline"),
        ));
        assert!(
            tokio::time::timeout(Duration::from_millis(20), &mut before)
                .await
                .is_err(),
            "operation is blocked before the send boundary"
        );
        drop(before);
        drop(held);
        assert_no_datagram(&before_receiver);
        assert_eq!(
            before_source
                .snapshots
                .lock()
                .expect("before snapshots")
                .len(),
            1
        );
        drop(
            before_gate
                .acquire_publication(
                    HardDeadline::after(Duration::from_secs(2)).expect("before reopened deadline"),
                )
                .await
                .expect("cancel-before leaves both mutation directions open"),
        );

        let after_path = directory.path().join("cancel-after.sock");
        let after_receiver = UnixDatagram::bind(&after_path).expect("bind cancel-after socket");
        after_receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound receive timeout");
        let after_address =
            NotifySocketAddress::parse(after_path.as_os_str()).expect("after notify address");
        let after_sender = NotifySender::new(&after_address).expect("after sender");
        let removed_snapshot = snapshot(42, Vec::new());
        let after_source = FakeInventorySource::new(
            42,
            vec![
                baseline_snapshot.clone(),
                removed_snapshot.clone(),
                removed_snapshot,
            ],
        );
        let after_gate = ManagerMutationGate::new();
        let (sent_sender, sent_receiver) = tokio::sync::oneshot::channel();
        let (release_sender, release_receiver) = std::sync::mpsc::channel();
        let receiver_thread = thread::spawn(move || {
            let (message, descriptors) = receive_message(&after_receiver);
            assert_eq!(message, fdstore_remove_message(target_name));
            assert!(descriptors.is_empty());
            sent_sender.send(()).expect("signal removal send");
            release_receiver
                .recv_timeout(Duration::from_secs(2))
                .expect("hold fake manager endpoint");
        });
        let mut after = Box::pin(remove_and_attest(
            &after_gate,
            &after_source,
            &after_sender,
            stable_inventory(baseline_snapshot, after_address),
            target_name,
            binding,
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("cancel-after deadline"),
        ));
        tokio::select! {
            result = &mut after => panic!("operation completed before cancellation: {result:?}"),
            observed = sent_receiver => observed.expect("manager observed removal send"),
        }
        drop(after);
        release_sender
            .send(())
            .expect("release fake manager endpoint");
        receiver_thread.join().expect("fake systemd receiver");
        assert!(matches!(
            after_gate
                .acquire_removal(
                    HardDeadline::after(Duration::from_secs(2))
                        .expect("cancel-after poison deadline")
                )
                .await,
            Err(FdStoreError::RemovalPoisoned)
        ));
        assert!(matches!(
            after_gate
                .acquire_publication(
                    HardDeadline::after(Duration::from_secs(2))
                        .expect("cross-kind cancel-after poison deadline")
                )
                .await,
            Err(FdStoreError::PublicationPoisoned)
        ));
    }

    #[allow(
        clippy::too_many_lines,
        reason = "the sequential proof keeps both affine owner pairs and both socket exchanges visible"
    )]
    #[tokio::test]
    async fn exact_successors_support_bounded_sequential_named_removals() {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory.path().join("sequential-removal.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound receive timeout");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let sender = NotifySender::new(&address).expect("removal sender");
        let first_pidfd = tempfile().expect("first pidfd fixture");
        let first_namespace = tempfile().expect("first namespace fixture");
        let second_pidfd = tempfile().expect("second pidfd fixture");
        let second_namespace = tempfile().expect("second namespace fixture");
        let first_custody = BorrowedCustodyPair::new(first_pidfd.as_fd(), first_namespace.as_fd())
            .expect("borrow first removal pair");
        let second_custody =
            BorrowedCustodyPair::new(second_pidfd.as_fd(), second_namespace.as_fd())
                .expect("borrow second removal pair");
        let first_binding = custody_binding(first_custody);
        let second_binding = custody_binding(second_custody);
        let first_name = custody_name(85);
        let second_name = custody_name(86);
        let mut baseline_entries = Vec::from(exact_pair_entries(first_name, &first_binding));
        baseline_entries.extend(exact_pair_entries(second_name, &second_binding));
        let baseline_snapshot = snapshot(42, baseline_entries);
        let first_successor = snapshot(
            42,
            Vec::from(exact_pair_entries(second_name, &second_binding)),
        );
        let second_successor = snapshot(42, Vec::new());
        let source = FakeInventorySource::new(
            42,
            vec![
                baseline_snapshot.clone(),
                first_successor.clone(),
                first_successor.clone(),
                first_successor.clone(),
                second_successor.clone(),
                second_successor,
            ],
        );
        let gate = ManagerMutationGate::new();
        let receiver_thread = thread::spawn(move || {
            for name in [first_name, second_name] {
                let (message, descriptors) = receive_message(&receiver);
                assert_eq!(message, fdstore_remove_message(name));
                assert!(descriptors.is_empty());
                let (message, descriptors) = receive_message(&receiver);
                assert_eq!(message, BARRIER_MESSAGE);
                assert_eq!(descriptors.len(), 1);
                close_received(descriptors);
            }
        });

        let first_proof = remove_and_attest(
            &gate,
            &source,
            &sender,
            stable_inventory(baseline_snapshot, address.clone()),
            first_name,
            first_binding.clone(),
            first_custody,
            HardDeadline::after(Duration::from_secs(2)).expect("first removal deadline"),
        )
        .await
        .expect("first exact removal");
        assert_eq!(first_proof.stored_descriptors, 2);
        let first_successor = first_proof.into_successor();
        first_successor
            .verify_complete_exact_set(&BTreeMap::from([(second_name, second_binding.clone())]))
            .expect("first successor retains only second pair");

        let second_proof = remove_and_attest(
            &gate,
            &source,
            &sender,
            first_successor,
            second_name,
            second_binding,
            second_custody,
            HardDeadline::after(Duration::from_secs(2)).expect("second removal deadline"),
        )
        .await
        .expect("second exact removal");
        assert_eq!(second_proof.stored_descriptors, 0);
        let empty_successor = second_proof.into_successor();
        assert_eq!(empty_successor.notify_address, address);
        empty_successor
            .verify_complete_exact_set(&BTreeMap::new())
            .expect("second successor is exactly empty");
        receiver_thread.join().expect("fake systemd receiver");
        assert!(
            source
                .snapshots
                .lock()
                .expect("sequential snapshots")
                .is_empty()
        );
        DescriptorIdentity::from_descriptor(first_pidfd.as_fd())
            .expect("first pidfd owner remains alive");
        DescriptorIdentity::from_descriptor(first_namespace.as_fd())
            .expect("first namespace owner remains alive");
        DescriptorIdentity::from_descriptor(second_pidfd.as_fd())
            .expect("second pidfd owner remains alive");
        DescriptorIdentity::from_descriptor(second_namespace.as_fd())
            .expect("second namespace owner remains alive");
    }

    #[test]
    fn removal_inventory_is_bounded_at_sixty_four_exact_pairs() {
        let target_name = custody_name(0);
        let target_binding =
            CustodyDescriptorBinding([descriptor_identity(1_000), descriptor_identity(1_001)]);
        let mut entries = Vec::with_capacity(MAX_DESCRIPTOR_STORE_ENTRIES);
        entries.extend(exact_pair_entries(target_name, &target_binding));
        for seed in 1_u8..64 {
            let identity_seed = 1_100 + u32::from(seed) * 10;
            let binding = CustodyDescriptorBinding([
                descriptor_identity(identity_seed),
                descriptor_identity(identity_seed + 1),
            ]);
            entries.extend(exact_pair_entries(custody_name(seed), &binding));
        }
        let maximum = snapshot(42, entries);
        assert_eq!(maximum.entries.len(), MAX_DESCRIPTOR_STORE_ENTRIES);
        maximum
            .validate_removal_target(&fake_scope(42), target_name, &target_binding)
            .expect("maximum complete inventory is accepted");
        let exact_post = snapshot(
            42,
            maximum
                .entries
                .iter()
                .filter(|entry| entry.name.as_ref() != target_name.as_bytes())
                .cloned()
                .collect(),
        );
        assert!(matches!(
            maximum
                .project_exact_removal(&exact_post, target_name, &target_binding)
                .expect("bounded exact successor"),
            RemovalProjection::ExactRemoved {
                stored_descriptors: 126,
                ..
            }
        ));

        let overflow_name = custody_name(64);
        let overflow_binding =
            CustodyDescriptorBinding([descriptor_identity(2_000), descriptor_identity(2_001)]);
        let mut overflow_entries = maximum.entries.clone();
        overflow_entries.extend(exact_pair_entries(overflow_name, &overflow_binding));
        let overflow = snapshot(42, overflow_entries);
        assert!(matches!(
            overflow.validate_removal_target(&fake_scope(42), target_name, &target_binding),
            Err(FdStoreError::InvalidInventory(
                "removal baseline exceeds the descriptor-store bound"
            ))
        ));
    }

    #[test]
    fn removal_source_has_one_payload_only_send_one_barrier_and_no_production_caller() {
        let name = custody_name(87);
        let message = fdstore_remove_message(name);
        let mut expected = FDSTORE_REMOVE_PREFIX.to_vec();
        expected.extend_from_slice(name.as_bytes());
        assert_eq!(message.as_slice(), expected);
        assert_eq!(message.len(), FDSTORE_REMOVE_MESSAGE_BYTES);
        for forbidden in [b"FDSTORE=1".as_slice(), b"FDPOLL=0", b"READY=1"] {
            assert!(
                !message
                    .windows(forbidden.len())
                    .any(|window| window == forbidden)
            );
        }

        let source = include_str!("systemd_fdstore.rs");
        let start = source
            .find("pub(crate) async fn remove_current_process_custody")
            .expect("removal adapter source start");
        let reconcile = source[start..]
            .find("pub(crate) async fn reconcile_current_process_removal")
            .map(|offset| start + offset)
            .expect("removal reconcile source start");
        let end = source[reconcile..]
            .find("/// Publish through the production systemd manager interfaces")
            .map(|offset| reconcile + offset)
            .expect("removal adapter source end");
        let transaction = &source[start..reconcile];
        assert_eq!(
            transaction.matches("send_without_descriptors_once").count(),
            1
        );
        assert_eq!(transaction.matches("send_once(BARRIER_MESSAGE").count(), 1);
        assert_eq!(transaction.matches("source.snapshot(deadline)").count(), 3);
        for forbidden in [
            "FDSTORE_PREFIX",
            "FDPOLL=0",
            "READY=1",
            "publish_and_attest",
            "synchronize_manager",
        ] {
            assert!(
                !transaction.contains(forbidden),
                "removal transaction must not contain {forbidden}"
            );
        }
        let reconciliation = &source[reconcile..end];
        assert_eq!(reconciliation.matches("synchronize_manager").count(), 1);
        assert_eq!(
            reconciliation.matches("source.snapshot(deadline)").count(),
            2
        );
        assert!(!reconciliation.contains("send_without_descriptors_once"));
        let manager_gate_declaration = ["static PRODUCTION_MANAGER_", "MUTATION_GATE:"].concat();
        assert_eq!(
            source.matches(&manager_gate_declaration).count(),
            1,
            "publication and removal must use one production mutation gate"
        );
        let legacy_publication_gate = ["PRODUCTION_PUBLICATION_", "GATE"].concat();
        let legacy_removal_gate = ["PRODUCTION_REMOVAL_", "GATE"].concat();
        assert!(!source.contains(&legacy_publication_gate));
        assert!(!source.contains(&legacy_removal_gate));

        let server = include_str!("server.rs");
        for forbidden in [
            "remove_current_process_custody",
            "reconcile_current_process_removal",
        ] {
            assert!(
                !server.contains(forbidden),
                "production server must not wire dormant {forbidden}"
            );
        }
    }

    #[tokio::test]
    async fn exact_pair_is_published_barriered_and_attested_without_consuming_owners() {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound receive timeout");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let pidfd = tempfile().expect("pidfd fixture");
        let mut network_namespace = tempfile().expect("network namespace fixture");
        network_namespace
            .write_all(b"distinct descriptor")
            .expect("make fixture distinct");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let identities = custody.identities().expect("local identities");
        let name = custody_name(1);
        let baseline = snapshot(42, Vec::new());
        let post = snapshot(
            42,
            identities
                .iter()
                .cloned()
                .map(|identity| inventory_entry(name, identity))
                .collect(),
        );
        let source = FakeInventorySource::new(42, vec![baseline, post]);
        let gate = ManagerMutationGate::new();
        let mut expected_received_identities = identities
            .iter()
            .map(expected_stat_identity)
            .collect::<Vec<_>>();
        expected_received_identities.sort_unstable();
        let expected_message = b"FDSTORE=1\nFDNAME=volparossa-custody-v1-0000000000000000000000000000000000000000000000000000000000000001\nFDPOLL=0";
        let receiver_thread = thread::spawn(move || {
            let (message, descriptors) = receive_message(&receiver);
            assert_eq!(message, expected_message);
            assert!(
                !message
                    .windows(b"READY=1".len())
                    .any(|part| part == b"READY=1")
            );
            assert!(
                !message
                    .windows(b"FDSTOREREMOVE=1".len())
                    .any(|part| part == b"FDSTOREREMOVE=1")
            );
            assert_eq!(descriptors.len(), DESCRIPTORS_PER_CUSTODY);
            let mut received_identities = descriptors
                .iter()
                .copied()
                .map(received_stat_identity)
                .collect::<Vec<_>>();
            received_identities.sort_unstable();
            assert_eq!(received_identities, expected_received_identities);
            close_received(descriptors);
            let (message, descriptors) = receive_message(&receiver);
            assert_eq!(message, BARRIER_MESSAGE);
            assert_eq!(descriptors.len(), 1);
            close_received(descriptors);
        });

        let attestation = publish_and_attest(
            &gate,
            &source,
            &address,
            name,
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("deadline"),
        )
        .await
        .expect("attested publication");
        receiver_thread.join().expect("fake systemd receiver");
        assert_eq!(attestation.custody_name, name);
        assert_eq!(attestation.identities, identities);
        assert_eq!(attestation.stored_descriptors, 2);
        assert_eq!(
            format!("{attestation:?}"),
            "InventoryAttestation(<redacted>)"
        );
        assert!(fstat(pidfd.as_fd()).is_ok());
        assert!(fstat(network_namespace.as_fd()).is_ok());
        drop(
            gate.acquire_removal(
                HardDeadline::after(Duration::from_secs(1)).expect("cross-release deadline"),
            )
            .await
            .expect("successful publication releases the shared removal gate"),
        );
    }

    #[tokio::test]
    async fn invalid_baseline_is_definitely_before_send() {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        receiver
            .set_nonblocking(true)
            .expect("nonblocking receiver");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let pidfd = tempfile().expect("pidfd fixture");
        let network_namespace = tempfile().expect("network namespace fixture");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let mut invalid = snapshot(42, Vec::new());
        invalid.store_max = 127;
        let source = FakeInventorySource::new(42, vec![invalid]);
        let gate = ManagerMutationGate::new();
        let error = publish_and_attest(
            &gate,
            &source,
            &address,
            custody_name(2),
            custody,
            HardDeadline::after(Duration::from_secs(1)).expect("deadline"),
        )
        .await
        .expect_err("invalid baseline");
        assert!(matches!(error, PublicationFailure::BeforeSend { .. }));
        let mut byte = [0_u8; 1];
        assert_eq!(
            receiver
                .recv(&mut byte)
                .expect_err("no datagram before send")
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn cross_name_identity_overlap_is_definitely_before_send() {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        receiver
            .set_nonblocking(true)
            .expect("nonblocking receiver");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let pidfd = tempfile().expect("pidfd fixture");
        let mut network_namespace = tempfile().expect("network namespace fixture");
        network_namespace
            .write_all(b"distinct descriptor")
            .expect("make fixture distinct");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let identities = custody.identities().expect("local identities");
        let source = FakeInventorySource::new(
            42,
            vec![snapshot(
                42,
                vec![inventory_entry(custody_name(34), identities[0].clone())],
            )],
        );
        let gate = ManagerMutationGate::new();

        let error = publish_and_attest(
            &gate,
            &source,
            &address,
            custody_name(33),
            custody,
            HardDeadline::after(Duration::from_secs(1)).expect("deadline"),
        )
        .await
        .expect_err("cross-name custody overlap");
        assert!(matches!(error, PublicationFailure::BeforeSend { .. }));
        let mut byte = [0_u8; 1];
        assert_eq!(
            receiver
                .recv(&mut byte)
                .expect_err("overlap rejection sends no datagram")
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn any_error_after_first_send_is_manager_may_own() {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory.path().join("notify.sock");
        let _receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let pidfd = tempfile().expect("pidfd fixture");
        let network_namespace = tempfile().expect("network namespace fixture");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let source = FakeInventorySource::new(42, vec![snapshot(42, Vec::new())]);
        let gate = ManagerMutationGate::new();
        let error = publish_and_attest(
            &gate,
            &source,
            &address,
            custody_name(3),
            custody,
            HardDeadline::after(Duration::from_millis(50)).expect("deadline"),
        )
        .await
        .expect_err("barrier must time out without a manager");
        assert!(matches!(error, PublicationFailure::ManagerMayOwn { .. }));
        assert!(fstat(pidfd.as_fd()).is_ok());
        assert!(fstat(network_namespace.as_fd()).is_ok());
    }

    #[tokio::test]
    async fn duplicate_open_file_identity_is_rejected_before_send() {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        receiver
            .set_nonblocking(true)
            .expect("nonblocking receiver");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let first = tempfile().expect("custody fixture");
        let duplicate = nix::unistd::dup(first.as_fd()).expect("duplicate open file description");
        let custody = BorrowedCustodyPair::new(first.as_fd(), duplicate.as_fd())
            .expect("raw descriptors are distinct");
        let source = FakeInventorySource::new(42, vec![snapshot(42, Vec::new())]);
        let gate = ManagerMutationGate::new();
        let error = publish_and_attest(
            &gate,
            &source,
            &address,
            custody_name(9),
            custody,
            HardDeadline::after(Duration::from_secs(1)).expect("deadline"),
        )
        .await
        .expect_err("identical descriptor identities must fail");
        assert!(matches!(error, PublicationFailure::BeforeSend { .. }));
        let mut byte = [0_u8; 1];
        assert_eq!(
            receiver
                .recv(&mut byte)
                .expect_err("identity rejection sends no datagram")
                .kind(),
            io::ErrorKind::WouldBlock
        );
    }

    #[tokio::test]
    async fn cancellation_after_send_poisons_gate_against_blind_retry() {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound receive timeout");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let pidfd = tempfile().expect("pidfd fixture");
        let network_namespace = tempfile().expect("network namespace fixture");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let source = FakeInventorySource::new(42, vec![snapshot(42, Vec::new())]);
        let gate = ManagerMutationGate::new();
        let (sent_tx, sent_rx) = tokio::sync::oneshot::channel();
        let (release_tx, release_rx) = std::sync::mpsc::channel();
        let receiver_thread = thread::spawn(move || {
            let (message, descriptors) = receive_message(&receiver);
            assert!(message.starts_with(FDSTORE_PREFIX));
            close_received(descriptors);
            sent_tx.send(()).expect("signal first send observation");
            release_rx
                .recv_timeout(Duration::from_secs(2))
                .expect("hold fake manager through cancellation");
        });

        let mut publication = Box::pin(publish_and_attest(
            &gate,
            &source,
            &address,
            custody_name(10),
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("deadline"),
        ));
        tokio::select! {
            result = &mut publication => panic!("publication unexpectedly completed: {result:?}"),
            observed = sent_rx => observed.expect("fake manager observation"),
        }
        drop(publication);

        let retry_source = FakeInventorySource::new(42, vec![snapshot(42, Vec::new())]);
        let error = publish_and_attest(
            &gate,
            &retry_source,
            &address,
            custody_name(11),
            custody,
            HardDeadline::after(Duration::from_secs(1)).expect("retry deadline"),
        )
        .await
        .expect_err("poisoned gate must reject blind retry");
        assert!(matches!(
            error,
            PublicationFailure::BeforeSend {
                error: FdStoreError::PublicationPoisoned
            }
        ));
        assert!(matches!(
            gate.acquire_removal(
                HardDeadline::after(Duration::from_secs(1))
                    .expect("cross-kind publication poison deadline")
            )
            .await,
            Err(FdStoreError::RemovalPoisoned)
        ));
        release_tx.send(()).expect("release fake manager");
        receiver_thread.join().expect("fake systemd receiver");
    }

    #[tokio::test]
    async fn barrier_without_exact_post_inventory_is_manager_may_own() {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound receive timeout");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let pidfd = tempfile().expect("pidfd fixture");
        let network_namespace = tempfile().expect("network namespace fixture");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let source =
            FakeInventorySource::new(42, vec![snapshot(42, Vec::new()), snapshot(42, Vec::new())]);
        let gate = ManagerMutationGate::new();
        let receiver_thread = thread::spawn(move || {
            let (_, descriptors) = receive_message(&receiver);
            close_received(descriptors);
            let (_, descriptors) = receive_message(&receiver);
            close_received(descriptors);
        });
        let error = publish_and_attest(
            &gate,
            &source,
            &address,
            custody_name(4),
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("deadline"),
        )
        .await
        .expect_err("post inventory mismatch");
        receiver_thread.join().expect("fake systemd receiver");
        assert!(matches!(error, PublicationFailure::ManagerMayOwn { .. }));
    }

    #[tokio::test]
    async fn reconciliation_uses_one_causal_barrier_then_observes_exact_present() {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory.path().join("notify.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        receiver
            .set_read_timeout(Some(Duration::from_secs(2)))
            .expect("bound receive timeout");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let pidfd = tempfile().expect("pidfd fixture");
        let mut network_namespace = tempfile().expect("network namespace fixture");
        network_namespace
            .write_all(b"distinct reconciliation descriptor")
            .expect("make fixture distinct");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let identities = exact_custody_identities(custody).expect("exact identities");
        let name = custody_name(40);
        let unrelated = inventory_entry(custody_name(41), descriptor_identity(400));
        let exact = snapshot(
            42,
            vec![
                unrelated,
                inventory_entry(name, identities[1].clone()),
                inventory_entry(name, identities[0].clone()),
            ],
        );
        let barrier_seen = Arc::new(AtomicBool::new(false));
        let source = FakeInventorySource::after_barrier(
            42,
            vec![exact.clone(), exact],
            Arc::clone(&barrier_seen),
        );
        let gate = ManagerMutationGate::new();
        let attempt_id = poison_attempt(&gate, source.scope(), &address, name, custody).await;
        let deadline = HardDeadline::after(Duration::from_secs(2)).expect("reconcile deadline");
        let observation = gate
            .acquire_poisoned_publication(attempt_id, name, &identities, deadline)
            .await
            .expect("exact poisoned observation");
        let sender = NotifySender::new(&address).expect("barrier sender");
        let receiver_barrier_seen = Arc::clone(&barrier_seen);
        let receiver_thread = thread::spawn(move || {
            let (message, descriptors) = receive_message(&receiver);
            assert_eq!(message, BARRIER_MESSAGE);
            assert_eq!(descriptors.len(), 1);
            assert!(
                !message
                    .windows(FDSTORE_PREFIX.len())
                    .any(|part| part == FDSTORE_PREFIX)
            );
            assert!(
                !message
                    .windows(b"FDSTOREREMOVE=1".len())
                    .any(|part| part == b"FDSTOREREMOVE=1")
            );
            receiver_barrier_seen.store(true, Ordering::SeqCst);
            close_received(descriptors);
        });

        let result = reconcile_poisoned_observation(
            observation,
            &source,
            custody,
            synchronize_manager(&sender, deadline),
            deadline,
        )
        .await;
        receiver_thread.join().expect("fake systemd receiver");
        let CustodyInventoryReconciliation::ExactPresent(evidence) = result else {
            panic!("exact inventory was not classified present: {result:?}")
        };
        assert_eq!(evidence.attempt.attempt_id, attempt_id);
        assert_eq!(evidence.attempt.target.custody_name, name);
        assert_eq!(evidence.stored_descriptors, 3);
        assert_eq!(format!("{evidence:?}"), "ExactPresentEvidence(<redacted>)");
        assert!(barrier_seen.load(Ordering::SeqCst));
        assert!(
            source
                .snapshots
                .lock()
                .expect("fake snapshot lock")
                .is_empty(),
            "reconciliation consumes exactly two snapshots"
        );
        assert!(matches!(
            gate.acquire_publication(
                HardDeadline::after(Duration::from_secs(1)).expect("poison check deadline")
            )
            .await,
            Err(FdStoreError::PublicationPoisoned)
        ));
    }

    #[tokio::test]
    async fn reconciliation_observes_exact_absent_but_never_clears_poison() {
        let pidfd = tempfile().expect("pidfd fixture");
        let mut network_namespace = tempfile().expect("network namespace fixture");
        network_namespace
            .write_all(b"distinct absent descriptor")
            .expect("make fixture distinct");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let name = custody_name(42);
        let unrelated = snapshot(
            42,
            vec![inventory_entry(custody_name(43), descriptor_identity(430))],
        );
        let source = FakeInventorySource::new(42, vec![unrelated.clone(), unrelated]);
        let gate = ManagerMutationGate::new();
        let attempt_id =
            poison_attempt(&gate, source.scope(), &fake_notify_address(), name, custody).await;

        let result = reconcile_fake(
            &gate,
            &source,
            attempt_id,
            name,
            custody,
            std::future::ready(Ok(())),
        )
        .await;
        let CustodyInventoryReconciliation::ExactAbsent(evidence) = result else {
            panic!("exact inventory was not classified absent: {result:?}")
        };
        assert_eq!(evidence.attempt.attempt_id, attempt_id);
        assert_eq!(evidence.stored_descriptors, 1);
        assert_eq!(format!("{evidence:?}"), "ExactAbsentEvidence(<redacted>)");
        assert!(matches!(
            gate.acquire_publication(
                HardDeadline::after(Duration::from_secs(1)).expect("poison check deadline")
            )
            .await,
            Err(FdStoreError::PublicationPoisoned)
        ));
    }

    #[allow(
        clippy::too_many_lines,
        reason = "one test proves publication poison blocks the complete opposite mutation before I/O"
    )]
    #[tokio::test]
    async fn publication_poison_blocks_removal_and_wrong_kind_reconciliation_cannot_clear_it() {
        let directory = tempdir().expect("notification directory");
        let socket_path = directory
            .path()
            .join("publication-poison-blocks-removal.sock");
        let receiver = UnixDatagram::bind(&socket_path).expect("bind fake notify socket");
        let address = NotifySocketAddress::parse(socket_path.as_os_str()).expect("notify address");
        let sender = NotifySender::new(&address).expect("removal sender");
        let pidfd = tempfile().expect("pidfd fixture");
        let mut network_namespace = tempfile().expect("network namespace fixture");
        network_namespace
            .write_all(b"distinct cross-poison descriptor")
            .expect("make fixture distinct");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let identities = exact_custody_identities(custody).expect("exact identities");
        let binding = custody_binding(custody);
        let name = custody_name(54);
        let baseline = snapshot(42, Vec::from(exact_pair_entries(name, &binding)));
        let gate = ManagerMutationGate::new();
        let attempt_id = poison_attempt(&gate, &fake_scope(42), &address, name, custody).await;

        let removal_source = FakeInventorySource::new(42, vec![baseline.clone()]);
        let blocked = remove_and_attest(
            &gate,
            &removal_source,
            &sender,
            stable_inventory(baseline.clone(), address.clone()),
            name,
            binding.clone(),
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("blocked removal deadline"),
        )
        .await;
        assert!(matches!(
            blocked,
            Err(RemovalFailure::BeforeSend {
                error: FdStoreError::RemovalPoisoned
            })
        ));
        assert_eq!(
            removal_source
                .snapshots
                .lock()
                .expect("blocked removal snapshots")
                .len(),
            1,
            "publication poison blocks removal before preflight"
        );
        assert_no_datagram(&receiver);

        assert!(matches!(
            gate.acquire_poisoned_removal(
                RemovalAttemptId::for_test(attempt_id.0.get()),
                name,
                &binding,
                HardDeadline::after(Duration::from_secs(2))
                    .expect("wrong-kind removal reconciliation deadline"),
            )
            .await,
            Err(FdStoreError::RemovalTargetMismatch)
        ));

        let wrong_scope_source = FakeInventorySource::new(43, Vec::new());
        let wrong_scope_observation = gate
            .acquire_poisoned_publication(
                attempt_id,
                name,
                &identities,
                HardDeadline::after(Duration::from_secs(2))
                    .expect("wrong-scope publication observation deadline"),
            )
            .await
            .expect("exact publication poison remains observable");
        assert!(matches!(
            reconcile_poisoned_observation(
                wrong_scope_observation,
                &wrong_scope_source,
                custody,
                std::future::ready(Ok(())),
                HardDeadline::after(Duration::from_secs(2))
                    .expect("wrong-scope publication reconciliation deadline"),
            )
            .await,
            CustodyInventoryReconciliation::Unresolved {
                error: FdStoreError::PublicationTargetMismatch
            }
        ));
        assert!(matches!(
            gate.acquire_removal(
                HardDeadline::after(Duration::from_secs(1))
                    .expect("unresolved publication cross-poison deadline")
            )
            .await,
            Err(FdStoreError::RemovalPoisoned)
        ));

        let absent = snapshot(42, Vec::new());
        let absent_source = FakeInventorySource::new(42, vec![absent.clone(), absent]);
        assert!(matches!(
            reconcile_fake(
                &gate,
                &absent_source,
                attempt_id,
                name,
                custody,
                std::future::ready(Ok(())),
            )
            .await,
            CustodyInventoryReconciliation::ExactAbsent(_)
        ));
        assert!(matches!(
            gate.acquire_removal(
                HardDeadline::after(Duration::from_secs(1)).expect("absent cross-poison deadline")
            )
            .await,
            Err(FdStoreError::RemovalPoisoned)
        ));

        let exact_present = snapshot(
            42,
            identities
                .iter()
                .cloned()
                .map(|identity| inventory_entry(name, identity))
                .collect(),
        );
        let present_source =
            FakeInventorySource::new(42, vec![exact_present.clone(), exact_present]);
        assert!(matches!(
            reconcile_fake(
                &gate,
                &present_source,
                attempt_id,
                name,
                custody,
                std::future::ready(Ok(())),
            )
            .await,
            CustodyInventoryReconciliation::ExactPresent(_)
        ));

        let blocked_again = remove_and_attest(
            &gate,
            &removal_source,
            &sender,
            stable_inventory(baseline, address),
            name,
            binding,
            custody,
            HardDeadline::after(Duration::from_secs(2)).expect("present cross-poison deadline"),
        )
        .await;
        assert!(matches!(
            blocked_again,
            Err(RemovalFailure::BeforeSend {
                error: FdStoreError::RemovalPoisoned
            })
        ));
        assert_eq!(
            removal_source
                .snapshots
                .lock()
                .expect("still blocked removal snapshots")
                .len(),
            1,
            "publication reconciliation never releases removal"
        );
        assert_no_datagram(&receiver);
    }

    #[test]
    fn reconciliation_projection_rejects_partial_wrong_duplicate_and_aliased_pairs() {
        let name = custody_name(44);
        let first = descriptor_identity(440);
        let second = descriptor_identity(450);
        let target = PublicationTarget {
            scope: fake_scope(42),
            notify_address: fake_notify_address(),
            custody_name: name,
            identities: [first.clone(), second.clone()],
        };
        let exact_reversed = snapshot(
            42,
            vec![
                inventory_entry(name, second.clone()),
                inventory_entry(name, first.clone()),
            ],
        );
        assert!(matches!(
            exact_reversed.project_poisoned_target(&target),
            Ok(TargetInventoryProjection::ExactPresent {
                stored_descriptors: 2
            })
        ));
        assert!(matches!(
            snapshot(
                42,
                vec![inventory_entry(custody_name(45), descriptor_identity(460))]
            )
            .project_poisoned_target(&target),
            Ok(TargetInventoryProjection::ExactAbsent {
                stored_descriptors: 1
            })
        ));

        let mut flag_alias = first.clone();
        flag_alias.status_flags ^=
            u32::try_from(OFlag::O_NONBLOCK.bits()).expect("nonblocking flag fits identity field");
        assert!(flag_alias.is_same_kernel_object(&first));
        let invalid = [
            snapshot(42, vec![inventory_entry(name, first.clone())]),
            snapshot(
                42,
                vec![
                    inventory_entry(name, first.clone()),
                    inventory_entry(name, second.clone()),
                    inventory_entry(name, descriptor_identity(470)),
                ],
            ),
            snapshot(
                42,
                vec![
                    inventory_entry(name, first.clone()),
                    inventory_entry(name, first.clone()),
                ],
            ),
            snapshot(
                42,
                vec![
                    inventory_entry(name, descriptor_identity(480)),
                    inventory_entry(name, descriptor_identity(490)),
                ],
            ),
            snapshot(42, vec![inventory_entry(custody_name(45), first.clone())]),
            snapshot(42, vec![inventory_entry(custody_name(45), flag_alias)]),
            snapshot(
                42,
                vec![
                    inventory_entry(name, first.clone()),
                    inventory_entry(name, second.clone()),
                    inventory_entry(custody_name(45), first),
                ],
            ),
        ];
        for inventory in invalid {
            assert!(inventory.project_poisoned_target(&target).is_err());
        }
    }

    #[tokio::test]
    async fn reconciliation_rejects_unstable_full_inventory_and_scope() {
        let pidfd = tempfile().expect("pidfd fixture");
        let mut network_namespace = tempfile().expect("network namespace fixture");
        network_namespace
            .write_all(b"distinct unstable descriptor")
            .expect("make fixture distinct");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let identities = exact_custody_identities(custody).expect("exact identities");
        let name = custody_name(46);
        let first = snapshot(
            42,
            identities
                .iter()
                .cloned()
                .map(|identity| inventory_entry(name, identity))
                .collect(),
        );
        let mut second = first.clone();
        second
            .entries
            .push(inventory_entry(custody_name(47), descriptor_identity(500)));
        second.entries.sort_unstable();
        let source = FakeInventorySource::new(42, vec![first, second]);
        let gate = ManagerMutationGate::new();
        let attempt_id =
            poison_attempt(&gate, source.scope(), &fake_notify_address(), name, custody).await;
        let result = reconcile_fake(
            &gate,
            &source,
            attempt_id,
            name,
            custody,
            std::future::ready(Ok(())),
        )
        .await;
        assert!(matches!(
            result,
            CustodyInventoryReconciliation::Unresolved {
                error: FdStoreError::UnstableInventory
            }
        ));

        let wrong_source = FakeInventorySource::new(43, Vec::new());
        let polled = Arc::new(AtomicBool::new(false));
        let observed_poll = Arc::clone(&polled);
        let barrier = std::future::poll_fn(move |_| {
            observed_poll.store(true, Ordering::SeqCst);
            Poll::Ready(Ok(()))
        });
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("scope deadline");
        let observation = gate
            .acquire_poisoned_publication(attempt_id, name, &identities, deadline)
            .await
            .expect("poison remains observable");
        let result =
            reconcile_poisoned_observation(observation, &wrong_source, custody, barrier, deadline)
                .await;
        assert!(matches!(
            result,
            CustodyInventoryReconciliation::Unresolved {
                error: FdStoreError::PublicationTargetMismatch
            }
        ));
        assert!(!polled.load(Ordering::SeqCst));
    }

    #[tokio::test]
    async fn stale_attempt_name_or_role_binding_cannot_start_reconciliation() {
        let pidfd = tempfile().expect("pidfd fixture");
        let mut network_namespace = tempfile().expect("network namespace fixture");
        network_namespace
            .write_all(b"distinct target descriptor")
            .expect("make fixture distinct");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let identities = exact_custody_identities(custody).expect("exact identities");
        let source = FakeInventorySource::new(42, Vec::new());
        let gate = ManagerMutationGate::new();
        let name = custody_name(48);
        let attempt_id =
            poison_attempt(&gate, source.scope(), &fake_notify_address(), name, custody).await;
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("mismatch deadline");
        let stale = PublicationAttemptId::for_test(attempt_id.0.get() + 1);
        for mismatch in [
            gate.acquire_poisoned_publication(stale, name, &identities, deadline)
                .await,
            gate.acquire_poisoned_publication(attempt_id, custody_name(49), &identities, deadline)
                .await,
            gate.acquire_poisoned_publication(
                attempt_id,
                name,
                &[identities[1].clone(), identities[0].clone()],
                deadline,
            )
            .await,
        ] {
            assert!(matches!(
                mismatch,
                Err(FdStoreError::PublicationTargetMismatch)
            ));
        }
        assert!(
            source
                .snapshots
                .lock()
                .expect("fake snapshot lock")
                .is_empty()
        );
        assert_eq!(
            format!("{attempt_id:?}"),
            "PublicationAttemptId(<redacted>)"
        );
    }

    #[tokio::test]
    async fn manager_mutation_attempt_ids_are_shared_monotone_and_overflow_is_fail_atomic() {
        let pidfd = tempfile().expect("pidfd fixture");
        let mut network_namespace = tempfile().expect("network namespace fixture");
        network_namespace
            .write_all(b"distinct monotone descriptor")
            .expect("make fixture distinct");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let identities = exact_custody_identities(custody).expect("exact identities");
        let name = custody_name(50);
        let publication_target = PublicationTarget {
            scope: fake_scope(42),
            notify_address: fake_notify_address(),
            custody_name: name,
            identities: identities.clone(),
        };
        let binding = custody_binding(custody);
        let baseline = snapshot(42, Vec::from(exact_pair_entries(name, &binding)));
        let removal_target = RemovalTarget {
            scope: fake_scope(42),
            notify_address: fake_notify_address(),
            custody_name: name,
            binding,
            baseline,
        };
        let gate = ManagerMutationGate::new();
        let deadline = HardDeadline::after(Duration::from_secs(2)).expect("attempt deadline");
        let mut first = gate
            .acquire_publication(deadline)
            .await
            .expect("first open gate");
        let first_id = first
            .mark_send_attempted(publication_target.clone())
            .expect("first attempt ID");
        first.complete_success(first_id);
        let mut second = gate
            .acquire_removal(deadline)
            .await
            .expect("second open gate");
        let second_id = second
            .mark_send_attempted(removal_target.clone())
            .expect("second attempt ID");
        assert_eq!(first_id.0.get(), 1);
        assert_eq!(second_id.0.get(), 2);
        assert_eq!(format!("{second_id:?}"), "RemovalAttemptId(<redacted>)");
        second.complete_exact_removed(second_id);

        let mut third = gate
            .acquire_publication(deadline)
            .await
            .expect("third open gate");
        let third_id = third
            .mark_send_attempted(publication_target.clone())
            .expect("third attempt ID");
        assert_eq!(third_id.0.get(), 3);
        third.complete_success(third_id);

        gate.state.lock().await.last_attempt_id = u64::MAX;
        let mut exhausted_publication = gate
            .acquire_publication(deadline)
            .await
            .expect("publication overflow open gate");
        assert!(matches!(
            exhausted_publication.mark_send_attempted(publication_target),
            Err(FdStoreError::PublicationAttemptExhausted)
        ));
        drop(exhausted_publication);
        let mut exhausted_removal = gate
            .acquire_removal(deadline)
            .await
            .expect("removal overflow open gate");
        assert!(matches!(
            exhausted_removal.mark_send_attempted(removal_target),
            Err(FdStoreError::RemovalAttemptExhausted)
        ));
        drop(exhausted_removal);
        let state = gate.state.lock().await;
        assert_eq!(state.last_attempt_id, u64::MAX);
        assert!(state.poisoned.is_none());
    }

    #[tokio::test]
    async fn cancellation_during_reconciliation_barrier_retains_poison_and_owner_binding() {
        let pidfd = tempfile().expect("pidfd fixture");
        let mut network_namespace = tempfile().expect("network namespace fixture");
        network_namespace
            .write_all(b"distinct cancellation descriptor")
            .expect("make fixture distinct");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let identities = exact_custody_identities(custody).expect("exact identities");
        let name = custody_name(51);
        let exact = snapshot(
            42,
            identities
                .iter()
                .cloned()
                .map(|identity| inventory_entry(name, identity))
                .collect(),
        );
        let source = FakeInventorySource::new(42, vec![exact.clone(), exact]);
        let gate = ManagerMutationGate::new();
        let attempt_id =
            poison_attempt(&gate, source.scope(), &fake_notify_address(), name, custody).await;
        let deadline = HardDeadline::after(Duration::from_secs(2)).expect("cancel deadline");
        let observation = gate
            .acquire_poisoned_publication(attempt_id, name, &identities, deadline)
            .await
            .expect("poisoned observation");
        let (entered_sender, entered_receiver) = tokio::sync::oneshot::channel();
        let barrier = async move {
            let _ = entered_sender.send(());
            std::future::pending::<Result<(), FdStoreError>>().await
        };
        let mut reconciliation = Box::pin(reconcile_poisoned_observation(
            observation,
            &source,
            custody,
            barrier,
            deadline,
        ));
        tokio::select! {
            result = &mut reconciliation => panic!("pending reconciliation completed: {result:?}"),
            entered = entered_receiver => entered.expect("barrier entered"),
        }
        drop(reconciliation);
        assert!(matches!(
            gate.acquire_publication(
                HardDeadline::after(Duration::from_secs(1)).expect("poison check deadline")
            )
            .await,
            Err(FdStoreError::PublicationPoisoned)
        ));
        assert_eq!(
            source.snapshots.lock().expect("fake snapshot lock").len(),
            2
        );
        assert_eq!(
            exact_custody_identities(custody).expect("retained exact owners"),
            identities
        );
    }

    #[tokio::test]
    async fn reconciliation_core_bounds_a_noncompliant_barrier_by_the_absolute_deadline() {
        let pidfd = tempfile().expect("pidfd fixture");
        let mut network_namespace = tempfile().expect("network namespace fixture");
        network_namespace
            .write_all(b"distinct deadline descriptor")
            .expect("make fixture distinct");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let identities = exact_custody_identities(custody).expect("exact identities");
        let name = custody_name(53);
        let exact = snapshot(
            42,
            identities
                .iter()
                .cloned()
                .map(|identity| inventory_entry(name, identity))
                .collect(),
        );
        let source = FakeInventorySource::new(42, vec![exact.clone(), exact]);
        let gate = ManagerMutationGate::new();
        let attempt_id =
            poison_attempt(&gate, source.scope(), &fake_notify_address(), name, custody).await;
        let deadline = HardDeadline::after(Duration::from_millis(20)).expect("short deadline");
        let observation = gate
            .acquire_poisoned_publication(attempt_id, name, &identities, deadline)
            .await
            .expect("poisoned observation");

        let result = reconcile_poisoned_observation(
            observation,
            &source,
            custody,
            std::future::pending(),
            deadline,
        )
        .await;
        assert!(matches!(
            result,
            CustodyInventoryReconciliation::Unresolved {
                error: FdStoreError::Deadline
            }
        ));
        assert!(matches!(
            gate.acquire_publication(
                HardDeadline::after(Duration::from_secs(1)).expect("poison check deadline")
            )
            .await,
            Err(FdStoreError::PublicationPoisoned)
        ));
        assert_eq!(
            source.snapshots.lock().expect("fake snapshot lock").len(),
            2
        );
    }

    #[tokio::test]
    async fn live_descriptor_binding_change_during_barrier_is_unresolved() {
        let pidfd = tempfile().expect("pidfd fixture");
        let mut network_namespace = tempfile().expect("network namespace fixture");
        network_namespace
            .write_all(b"distinct mutable descriptor")
            .expect("make fixture distinct");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let identities = exact_custody_identities(custody).expect("exact identities");
        let name = custody_name(52);
        let exact = snapshot(
            42,
            identities
                .iter()
                .cloned()
                .map(|identity| inventory_entry(name, identity))
                .collect(),
        );
        let source = FakeInventorySource::new(42, vec![exact.clone(), exact]);
        let gate = ManagerMutationGate::new();
        let attempt_id =
            poison_attempt(&gate, source.scope(), &fake_notify_address(), name, custody).await;
        let result = reconcile_fake(&gate, &source, attempt_id, name, custody, async {
            fcntl(
                network_namespace.as_fd(),
                FcntlArg::F_SETFL(OFlag::O_NONBLOCK),
            )
            .map_err(nix_io)?;
            Ok(())
        })
        .await;
        assert!(matches!(
            result,
            CustodyInventoryReconciliation::Unresolved {
                error: FdStoreError::InvalidInventory(
                    "retained custody descriptor binding changed during reconciliation"
                )
            }
        ));
        assert!(matches!(
            gate.acquire_publication(
                HardDeadline::after(Duration::from_secs(1)).expect("poison check deadline")
            )
            .await,
            Err(FdStoreError::PublicationPoisoned)
        ));
    }

    #[test]
    fn reconciliation_source_has_only_non_mutating_barrier_notification() {
        let source = include_str!("systemd_fdstore.rs");
        let start = source
            .find("pub(crate) async fn reconcile_current_process_custody")
            .expect("reconciliation source start");
        let end = source[start..]
            .find("fn fdstore_message")
            .map(|offset| start + offset)
            .expect("reconciliation source end");
        let reconciliation = &source[start..end];
        assert!(reconciliation.contains("synchronize_manager"));
        for forbidden in ["FDSTORE_PREFIX", "FDSTORE=1", "FDSTOREREMOVE=1", "READY=1"] {
            assert!(
                !reconciliation.contains(forbidden),
                "reconciliation must not contain {forbidden}"
            );
        }
    }

    #[test]
    fn raw_inventory_is_bounded_and_normalizes_largefile() {
        let snapshot = DescriptorStoreSnapshot::from_raw(
            fake_scope(42),
            42,
            "main".to_owned(),
            128,
            "yes".to_owned(),
            1,
            1,
            vec![(
                "existing entry".to_owned(),
                1,
                2,
                3,
                4,
                5,
                6,
                "/dev/example".to_owned(),
                rustix::fs::OFlags::LARGEFILE.bits() | libc::O_NONBLOCK as u32,
            )],
        )
        .expect("bounded raw inventory");
        assert_eq!(snapshot.entries.len(), 1);
        assert_eq!(
            snapshot.entries[0].identity.status_flags,
            libc::O_NONBLOCK as u32
        );
        assert_ne!(rustix::fs::OFlags::LARGEFILE.bits(), 0);
        assert!(
            DescriptorStoreSnapshot::from_raw(
                fake_scope(42),
                42,
                "main".to_owned(),
                128,
                "yes".to_owned(),
                0,
                1,
                Vec::new(),
            )
            .is_err()
        );
        assert!(
            DescriptorStoreSnapshot::from_raw(
                fake_scope(42),
                42,
                "main".to_owned(),
                128,
                "yes".to_owned(),
                1,
                1,
                vec![(
                    "bad\tname".to_owned(),
                    1,
                    2,
                    3,
                    4,
                    5,
                    6,
                    "/dev/example".to_owned(),
                    0,
                )],
            )
            .is_err()
        );
    }

    #[test]
    fn pre_dump_properties_and_complete_inventory_are_exact() {
        assert!(validate_properties_before_dump(42, 42, "main", 128, "yes", 128).is_ok());
        for invalid in [
            validate_properties_before_dump(42, 41, "main", 128, "yes", 0),
            validate_properties_before_dump(42, 42, "all", 128, "yes", 0),
            validate_properties_before_dump(42, 42, "main", 127, "yes", 0),
            validate_properties_before_dump(42, 42, "main", 128, "restart", 0),
            validate_properties_before_dump(42, 42, "main", 128, "yes", 129),
        ] {
            assert!(invalid.is_err());
        }

        let baseline_name = custody_name(20);
        let target_name = custody_name(21);
        let baseline_identity = DescriptorIdentity {
            mode: 1,
            device_major: 2,
            device_minor: 3,
            inode: 4,
            special_device_major: 5,
            special_device_minor: 6,
            status_flags: 7,
        };
        let first = DescriptorIdentity {
            inode: 8,
            ..baseline_identity.clone()
        };
        let second = DescriptorIdentity {
            inode: 9,
            ..baseline_identity.clone()
        };
        let pair = [first.clone(), second.clone()];
        let baseline = snapshot(
            42,
            vec![inventory_entry(baseline_name, baseline_identity.clone())],
        );
        let exact = snapshot(
            42,
            vec![
                inventory_entry(baseline_name, baseline_identity.clone()),
                inventory_entry(target_name, first.clone()),
                inventory_entry(target_name, second.clone()),
            ],
        );
        assert!(
            baseline
                .attest_extension(&exact, target_name, pair.clone())
                .is_ok()
        );

        let missing_baseline = snapshot(
            42,
            vec![
                inventory_entry(target_name, first.clone()),
                inventory_entry(target_name, second.clone()),
            ],
        );
        let extra = snapshot(
            42,
            vec![
                inventory_entry(baseline_name, baseline_identity.clone()),
                inventory_entry(target_name, first.clone()),
                inventory_entry(target_name, second.clone()),
                inventory_entry(custody_name(22), baseline_identity.clone()),
            ],
        );
        let wrong_name = snapshot(
            42,
            vec![
                inventory_entry(baseline_name, baseline_identity.clone()),
                inventory_entry(target_name, first.clone()),
                inventory_entry(custody_name(22), second.clone()),
            ],
        );
        let wrong_flags = snapshot(
            42,
            vec![
                inventory_entry(baseline_name, baseline_identity),
                inventory_entry(target_name, first),
                inventory_entry(
                    target_name,
                    DescriptorIdentity {
                        status_flags: second.status_flags ^ 1,
                        ..second
                    },
                ),
            ],
        );
        for invalid in [missing_baseline, extra, wrong_name, wrong_flags] {
            assert!(
                baseline
                    .attest_extension(&invalid, target_name, pair.clone())
                    .is_err()
            );
        }
    }
}
