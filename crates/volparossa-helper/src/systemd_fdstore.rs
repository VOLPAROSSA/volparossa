//! Dormant, fail-closed systemd descriptor-store publication adapter.
//!
//! Its publication adapter is reachable from the private live-proof selector and a private dormant
//! supervisor publisher, but neither is connected to the production server, engine, or request
//! path. It can publish one exact borrowed
//! pidfd/network-namespace pair to the current service's systemd descriptor store, wait for a
//! separate barrier acknowledgement, and attest the resulting manager inventory over D-Bus. The
//! caller retains both local owners throughout. Once the first `sendmsg(2)` is attempted, every
//! failure is classified as `ManagerMayOwn`. A separate callerless observer can classify that
//! exact poisoned in-process attempt as present, absent, or unresolved, but never clears the
//! poison or authorizes a resend. This slice never sends `FDSTOREREMOVE=1` or `READY=1`.

use std::{
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
const FDSTORE_PREFIX: &[u8] = b"FDSTORE=1\nFDNAME=";
const FDSTORE_SUFFIX: &[u8] = b"\nFDPOLL=0";
const FDSTORE_MESSAGE_BYTES: usize =
    FDSTORE_PREFIX.len() + CUSTODY_FD_NAME_BYTES + FDSTORE_SUFFIX.len();
const BARRIER_MESSAGE: &[u8] = b"BARRIER=1";
const SYSTEMD_DESTINATION: &str = "org.freedesktop.systemd1";
const SYSTEMD_MANAGER_PATH: &str = "/org/freedesktop/systemd1";
const SYSTEMD_MANAGER_INTERFACE: &str = "org.freedesktop.systemd1.Manager";
const SYSTEMD_SERVICE_INTERFACE: &str = "org.freedesktop.systemd1.Service";
static PRODUCTION_PUBLICATION_GATE: PublicationGate = PublicationGate::new();

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
/// The ID is monotonic within one publication gate and exists only to prevent a stale terminal
/// from reconciling a newer attempt which happens to use the same deterministic custody target.
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
    unit_path: OwnedObjectPath,
    main_pid: NonZeroU32,
}

impl DescriptorStoreScope {
    fn new(unit_path: OwnedObjectPath, main_pid: u32) -> Result<Self, FdStoreError> {
        let main_pid = NonZeroU32::new(main_pid)
            .ok_or_else(|| invalid_inventory("MainPID must be nonzero"))?;
        Ok(Self {
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

struct PublicationGateState {
    last_attempt_id: u64,
    poisoned: Option<PoisonedPublication>,
}

/// Serializes baseline observation through final attestation. Dropping an attempt after its first
/// send boundary poisons the gate, including task cancellation and panic unwinding. This dormant
/// slice intentionally provides no way to clear the poison. Reconciliation is observation-only
/// and cannot authorize another publication attempt.
struct PublicationGate {
    state: tokio::sync::Mutex<PublicationGateState>,
}

impl PublicationGate {
    const fn new() -> Self {
        Self {
            state: tokio::sync::Mutex::const_new(PublicationGateState {
                last_attempt_id: 0,
                poisoned: None,
            }),
        }
    }

    async fn lock_state(
        &self,
        deadline: HardDeadline,
    ) -> Result<tokio::sync::MutexGuard<'_, PublicationGateState>, FdStoreError> {
        ensure_deadline(deadline)?;
        tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline.expires_at()),
            self.state.lock(),
        )
        .await
        .map_err(|_| FdStoreError::Deadline)
    }

    async fn acquire_open(
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

    async fn acquire_poisoned(
        &self,
        attempt_id: PublicationAttemptId,
        custody_name: CustodyFdName,
        identities: &[DescriptorIdentity; DESCRIPTORS_PER_CUSTODY],
        deadline: HardDeadline,
    ) -> Result<PoisonedObservation<'_>, FdStoreError> {
        let state = self.lock_state(deadline).await?;
        let poisoned = state
            .poisoned
            .clone()
            .ok_or(FdStoreError::PublicationNotPoisoned)?;
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
    state: tokio::sync::MutexGuard<'a, PublicationGateState>,
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
        self.state.poisoned = Some(poisoned.clone());
        self.crossed = Some(poisoned);
        Ok(PublicationAttemptId(next))
    }

    fn complete_success(mut self, attempt_id: PublicationAttemptId) {
        let exact = self.crossed.as_ref().is_some_and(|crossed| {
            crossed.attempt_id == attempt_id && self.state.poisoned.as_ref() == Some(crossed)
        });
        if !exact {
            std::process::abort();
        }
        self.state.poisoned = None;
        self.crossed = None;
    }
}

/// Holds the one affine publication gate while a poisoned attempt is observed. Dropping this
/// guard never clears the poison, including cancellation and panic unwinding.
struct PoisonedObservation<'a> {
    _state: tokio::sync::MutexGuard<'a, PublicationGateState>,
    poisoned: PoisonedPublication,
}

trait DescriptorStoreInventorySource: Sync {
    fn scope(&self) -> &DescriptorStoreScope;

    fn snapshot(
        &self,
        deadline: HardDeadline,
    ) -> impl Future<Output = Result<DescriptorStoreSnapshot, FdStoreError>> + Send;
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
            let manager: Proxy<'_> = ProxyBuilder::new(&connection)
                .destination(SYSTEMD_DESTINATION)?
                .path(SYSTEMD_MANAGER_PATH)?
                .interface(SYSTEMD_MANAGER_INTERFACE)?
                .cache_properties(CacheProperties::No)
                .build()
                .await?;
            let unit_path: OwnedObjectPath =
                manager.call("GetUnitByPID", &(expected_main_pid,)).await?;
            drop(manager);
            let scope = DescriptorStoreScope::new(unit_path, expected_main_pid)?;
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
            Ok(Self { connection, scope })
        })
        .await
    }

    async fn snapshot_unbounded(&self) -> Result<DescriptorStoreSnapshot, FdStoreError> {
        let service: Proxy<'_> = ProxyBuilder::new(&self.connection)
            .destination(SYSTEMD_DESTINATION)?
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
        &PRODUCTION_PUBLICATION_GATE,
        &source,
        &address,
        custody_name,
        custody,
        deadline,
    )
    .await
}

async fn publish_and_attest<S: DescriptorStoreInventorySource>(
    gate: &PublicationGate,
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
        .acquire_open(deadline)
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
    let observation = match PRODUCTION_PUBLICATION_GATE
        .acquire_poisoned(attempt_id, custody_name, &identities, deadline)
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
        collections::VecDeque,
        fs::OpenOptions,
        io::{IoSliceMut, Write as _},
        os::{
            fd::{AsFd as _, AsRawFd as _},
            unix::{fs::MetadataExt as _, net::UnixDatagram},
        },
        sync::{
            Arc, Mutex,
            atomic::{AtomicBool, Ordering},
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

    async fn poison_attempt(
        gate: &PublicationGate,
        scope: &DescriptorStoreScope,
        notify_address: &NotifySocketAddress,
        custody_name: CustodyFdName,
        custody: BorrowedCustodyPair<'_>,
    ) -> PublicationAttemptId {
        let identities = exact_custody_identities(custody).expect("exact poisoned identities");
        let mut attempt = gate
            .acquire_open(HardDeadline::after(Duration::from_secs(2)).expect("poison deadline"))
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
        gate: &PublicationGate,
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
            .acquire_poisoned(attempt_id, custody_name, &identities, deadline)
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
        let gate = PublicationGate::new();
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
        let gate = PublicationGate::new();
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
        let gate = PublicationGate::new();

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
        let gate = PublicationGate::new();
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
        let gate = PublicationGate::new();
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
        let gate = PublicationGate::new();
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
        let gate = PublicationGate::new();
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
        let gate = PublicationGate::new();
        let attempt_id = poison_attempt(&gate, source.scope(), &address, name, custody).await;
        let deadline = HardDeadline::after(Duration::from_secs(2)).expect("reconcile deadline");
        let observation = gate
            .acquire_poisoned(attempt_id, name, &identities, deadline)
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
            gate.acquire_open(
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
        let gate = PublicationGate::new();
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
            gate.acquire_open(
                HardDeadline::after(Duration::from_secs(1)).expect("poison check deadline")
            )
            .await,
            Err(FdStoreError::PublicationPoisoned)
        ));
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
        let gate = PublicationGate::new();
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
            .acquire_poisoned(attempt_id, name, &identities, deadline)
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
        let gate = PublicationGate::new();
        let name = custody_name(48);
        let attempt_id =
            poison_attempt(&gate, source.scope(), &fake_notify_address(), name, custody).await;
        let deadline = HardDeadline::after(Duration::from_secs(1)).expect("mismatch deadline");
        let stale = PublicationAttemptId::for_test(attempt_id.0.get() + 1);
        for mismatch in [
            gate.acquire_poisoned(stale, name, &identities, deadline)
                .await,
            gate.acquire_poisoned(attempt_id, custody_name(49), &identities, deadline)
                .await,
            gate.acquire_poisoned(
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
    async fn publication_attempt_ids_are_monotone_and_overflow_is_fail_atomic() {
        let pidfd = tempfile().expect("pidfd fixture");
        let mut network_namespace = tempfile().expect("network namespace fixture");
        network_namespace
            .write_all(b"distinct monotone descriptor")
            .expect("make fixture distinct");
        let custody = BorrowedCustodyPair::new(pidfd.as_fd(), network_namespace.as_fd())
            .expect("borrow exact pair");
        let identities = exact_custody_identities(custody).expect("exact identities");
        let target = PublicationTarget {
            scope: fake_scope(42),
            notify_address: fake_notify_address(),
            custody_name: custody_name(50),
            identities,
        };
        let gate = PublicationGate::new();
        let deadline = HardDeadline::after(Duration::from_secs(2)).expect("attempt deadline");
        let mut first = gate.acquire_open(deadline).await.expect("first open gate");
        let first_id = first
            .mark_send_attempted(target.clone())
            .expect("first attempt ID");
        first.complete_success(first_id);
        let mut second = gate.acquire_open(deadline).await.expect("second open gate");
        let second_id = second
            .mark_send_attempted(target.clone())
            .expect("second attempt ID");
        assert_eq!(first_id.0.get(), 1);
        assert_eq!(second_id.0.get(), 2);
        second.complete_success(second_id);

        gate.state.lock().await.last_attempt_id = u64::MAX;
        let mut exhausted = gate
            .acquire_open(deadline)
            .await
            .expect("overflow open gate");
        assert!(matches!(
            exhausted.mark_send_attempted(target),
            Err(FdStoreError::PublicationAttemptExhausted)
        ));
        drop(exhausted);
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
        let gate = PublicationGate::new();
        let attempt_id =
            poison_attempt(&gate, source.scope(), &fake_notify_address(), name, custody).await;
        let deadline = HardDeadline::after(Duration::from_secs(2)).expect("cancel deadline");
        let observation = gate
            .acquire_poisoned(attempt_id, name, &identities, deadline)
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
            gate.acquire_open(
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
        let gate = PublicationGate::new();
        let attempt_id =
            poison_attempt(&gate, source.scope(), &fake_notify_address(), name, custody).await;
        let deadline = HardDeadline::after(Duration::from_millis(20)).expect("short deadline");
        let observation = gate
            .acquire_poisoned(attempt_id, name, &identities, deadline)
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
            gate.acquire_open(
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
        let gate = PublicationGate::new();
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
            gate.acquire_open(
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
