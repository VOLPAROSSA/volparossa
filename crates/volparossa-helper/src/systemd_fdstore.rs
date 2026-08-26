//! Dormant, fail-closed systemd descriptor-store publication adapter.
//!
//! This module deliberately has no production caller. It can publish one exact borrowed
//! pidfd/network-namespace pair to the current service's systemd descriptor store, wait for a
//! separate barrier acknowledgement, and attest the resulting manager inventory over D-Bus. The
//! caller retains both local owners throughout. Once the first `sendmsg(2)` is attempted, every
//! failure is classified as `ManagerMayOwn`; reconciliation must therefore happen before any
//! resend. This slice never sends `FDSTOREREMOVE=1` or `READY=1`.

use std::{
    env,
    ffi::OsStr,
    fmt,
    future::Future,
    io::{self, IoSlice},
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
    systemd_custody::{CUSTODY_FD_NAME_BYTES, custody_fd_name_is_valid},
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
/// Construction from the durable ownership key belongs to the later worker/journal wiring. This
/// type intentionally exposes neither a `String` nor path authority.
#[derive(Clone, Copy, Eq, Hash, Ord, PartialEq, PartialOrd)]
pub(crate) struct CustodyFdName([u8; CUSTODY_FD_NAME_BYTES]);

impl CustodyFdName {
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
        #[source]
        error: FdStoreError,
    },
}

impl PublicationFailure {
    fn before_send(error: FdStoreError) -> Self {
        Self::BeforeSend { error }
    }

    fn manager_may_own(error: FdStoreError) -> Self {
        Self::ManagerMayOwn { error }
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
    #[error("descriptor-store publication is blocked pending ambiguous-ownership reconciliation")]
    PublicationPoisoned,
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

/// Proof that a barrier completed and D-Bus reported exactly the baseline inventory plus the
/// requested pair.
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

impl DescriptorIdentity {
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
    fn from_raw(
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
            main_pid,
            notify_access: notify_access.into_boxed_str(),
            store_max,
            store_preserve: store_preserve.into_boxed_str(),
            entries,
        })
    }

    fn validate_baseline(
        &self,
        expected_main_pid: u32,
        custody_name: CustodyFdName,
    ) -> Result<(), FdStoreError> {
        if self.main_pid != expected_main_pid {
            return Err(invalid_inventory("MainPID is not the publishing process"));
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
        Ok(())
    }

    fn attest_extension(
        &self,
        post: &Self,
        custody_name: CustodyFdName,
        identities: [DescriptorIdentity; DESCRIPTORS_PER_CUSTODY],
    ) -> Result<InventoryAttestation, FdStoreError> {
        if self.main_pid != post.main_pid
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
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum PublicationGateState {
    Open,
    Poisoned,
}

/// Serializes baseline observation through final attestation. Dropping an attempt after its first
/// send boundary poisons the gate, including task cancellation and panic unwinding. This dormant
/// slice intentionally provides no way to clear the poison: a later reconciliation slice must
/// prove manager inventory before another publication can be attempted.
struct PublicationGate {
    state: tokio::sync::Mutex<PublicationGateState>,
}

impl PublicationGate {
    const fn new() -> Self {
        Self {
            state: tokio::sync::Mutex::const_new(PublicationGateState::Open),
        }
    }

    async fn acquire(
        &self,
        deadline: HardDeadline,
    ) -> Result<PublicationAttempt<'_>, FdStoreError> {
        ensure_deadline(deadline)?;
        let state = tokio::time::timeout_at(
            tokio::time::Instant::from_std(deadline.expires_at()),
            self.state.lock(),
        )
        .await
        .map_err(|_| FdStoreError::Deadline)?;
        if *state == PublicationGateState::Poisoned {
            return Err(FdStoreError::PublicationPoisoned);
        }
        Ok(PublicationAttempt {
            state,
            send_boundary_crossed: false,
            resolved: false,
        })
    }
}

struct PublicationAttempt<'a> {
    state: tokio::sync::MutexGuard<'a, PublicationGateState>,
    send_boundary_crossed: bool,
    resolved: bool,
}

impl PublicationAttempt<'_> {
    /// Mark immediately before invoking the first `sendmsg(2)`. Conservatively poisoning on
    /// cancellation between this mark and the syscall is safe; silently permitting a retry is not.
    fn mark_send_attempted(&mut self) {
        self.send_boundary_crossed = true;
    }

    fn complete_success(mut self) {
        *self.state = PublicationGateState::Open;
        self.resolved = true;
    }
}

impl Drop for PublicationAttempt<'_> {
    fn drop(&mut self) {
        if !self.resolved {
            *self.state = if self.send_boundary_crossed {
                PublicationGateState::Poisoned
            } else {
                PublicationGateState::Open
            };
        }
    }
}

trait DescriptorStoreInventorySource: Sync {
    fn expected_main_pid(&self) -> u32;

    fn snapshot(
        &self,
        deadline: HardDeadline,
    ) -> impl Future<Output = Result<DescriptorStoreSnapshot, FdStoreError>> + Send;
}

/// Production D-Bus source bound to the unit owning the current process.
struct SystemdDescriptorStoreSource {
    connection: Connection,
    unit_path: OwnedObjectPath,
    expected_main_pid: u32,
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
            Ok(Self {
                connection,
                unit_path,
                expected_main_pid,
            })
        })
        .await
    }

    async fn snapshot_unbounded(&self) -> Result<DescriptorStoreSnapshot, FdStoreError> {
        let service: Proxy<'_> = ProxyBuilder::new(&self.connection)
            .destination(SYSTEMD_DESTINATION)?
            .path(self.unit_path.clone())?
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
            self.expected_main_pid,
            main_pid,
            &notify_access,
            store_max,
            &store_preserve,
            count_before_dump,
        )?;
        let entries: Vec<RawInventoryEntry> = service.call("DumpFileDescriptorStore", &()).await?;
        let count_after_dump = service.get_property::<u32>("NFileDescriptorStore").await?;
        DescriptorStoreSnapshot::from_raw(
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
    fn expected_main_pid(&self) -> u32 {
        self.expected_main_pid
    }

    fn snapshot(
        &self,
        deadline: HardDeadline,
    ) -> impl Future<Output = Result<DescriptorStoreSnapshot, FdStoreError>> + Send {
        within_deadline(deadline, self.snapshot_unbounded())
    }
}

struct NotifySocketAddress(UnixAddr);

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
        Ok(Self(address))
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
            address: address.0,
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

/// Publish through the production systemd manager interfaces. No production caller exists yet.
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
        .acquire(deadline)
        .await
        .map_err(PublicationFailure::manager_may_own)?;
    let baseline = source
        .snapshot(deadline)
        .await
        .map_err(PublicationFailure::before_send)?;
    baseline
        .validate_baseline(source.expected_main_pid(), custody_name)
        .map_err(PublicationFailure::before_send)?;
    let identities = custody
        .identities()
        .map_err(PublicationFailure::before_send)?;
    if identities[0] == identities[1] {
        return Err(PublicationFailure::before_send(
            FdStoreError::DuplicateCustodyDescriptor,
        ));
    }
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
    attempt.mark_send_attempted();
    sender
        .send_once(&fdstore_message, &custody.raw_descriptors())
        .map_err(PublicationFailure::manager_may_own)?;
    ensure_deadline(deadline).map_err(PublicationFailure::manager_may_own)?;
    sender
        .send_once(BARRIER_MESSAGE, &[barrier_write.as_raw_fd()])
        .map_err(PublicationFailure::manager_may_own)?;
    drop(barrier_write);
    wait_for_barrier(&barrier_read, deadline)
        .await
        .map_err(PublicationFailure::manager_may_own)?;
    let post = source
        .snapshot(deadline)
        .await
        .map_err(PublicationFailure::manager_may_own)?;
    let attestation = baseline
        .attest_extension(&post, custody_name, identities)
        .map_err(PublicationFailure::manager_may_own)?;
    ensure_deadline(deadline).map_err(PublicationFailure::manager_may_own)?;
    attempt.complete_success();
    Ok(attestation)
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
        io::{IoSliceMut, Write as _},
        os::{
            fd::{AsFd as _, AsRawFd as _},
            unix::{fs::MetadataExt as _, net::UnixDatagram},
        },
        sync::Mutex,
        thread,
        time::Duration,
    };

    use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
    use tempfile::{tempdir, tempfile};

    use super::*;
    use crate::systemd_custody::CUSTODY_FD_NAME_PREFIX;

    struct FakeInventorySource {
        expected_main_pid: u32,
        snapshots: Mutex<VecDeque<DescriptorStoreSnapshot>>,
    }

    impl FakeInventorySource {
        fn new(expected_main_pid: u32, snapshots: Vec<DescriptorStoreSnapshot>) -> Self {
            Self {
                expected_main_pid,
                snapshots: Mutex::new(snapshots.into()),
            }
        }
    }

    impl DescriptorStoreInventorySource for FakeInventorySource {
        fn expected_main_pid(&self) -> u32 {
            self.expected_main_pid
        }

        fn snapshot(
            &self,
            deadline: HardDeadline,
        ) -> impl Future<Output = Result<DescriptorStoreSnapshot, FdStoreError>> + Send {
            let result = ensure_deadline(deadline).and_then(|()| {
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

    fn snapshot(pid: u32, entries: Vec<InventoryEntry>) -> DescriptorStoreSnapshot {
        let mut entries = entries;
        entries.sort_unstable();
        DescriptorStoreSnapshot {
            main_pid: pid,
            notify_access: "main".into(),
            store_max: MAX_DESCRIPTOR_STORE_ENTRIES_U32,
            store_preserve: "yes".into(),
            entries,
        }
    }

    fn inventory_entry(name: CustodyFdName, identity: DescriptorIdentity) -> InventoryEntry {
        InventoryEntry {
            name: Box::<[u8]>::from(name.as_bytes().as_slice()),
            identity,
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
    fn notify_socket_accepts_path_and_abstract_but_rejects_empty() {
        assert!(NotifySocketAddress::parse(OsStr::new("/run/example.sock")).is_ok());
        assert!(NotifySocketAddress::parse(OsStr::new("@systemd-test")).is_ok());
        assert!(NotifySocketAddress::parse(OsStr::new("relative.sock")).is_err());
        assert!(NotifySocketAddress::parse(OsStr::new("")).is_err());
        assert!(NotifySocketAddress::parse(OsStr::new("@")).is_err());
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
            PublicationFailure::ManagerMayOwn {
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

    #[test]
    fn raw_inventory_is_bounded_and_normalizes_largefile() {
        let snapshot = DescriptorStoreSnapshot::from_raw(
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
