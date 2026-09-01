//! Applied route-worker sandbox and independently observed bootstrap evidence.
//!
//! The production child first enters a fresh network namespace and then pauses at an affine
//! bootstrap barrier after setting no-new-privileges and installing one fixed seccomp filter that
//! denies descendant creation, re-exec and every later namespace transition. While the child is root,
//! the parent pins that namespace and attests the filter, exact descriptor set and single task. Only
//! after the pin acknowledgement may the child clear all supplementary groups, irreversibly assume
//! its dedicated uid/gid and reduce every capability set to exactly `CAP_NET_ADMIN`. The child and
//! parent both read the final identity and sandbox state back before the first authenticated request.
//! Test applicators are compiled only under `cfg(test)`; production has no environment or runtime
//! switch that can select one.

use std::{
    collections::BTreeSet,
    ffi::OsStr,
    fs::{self, File},
    io::{self, Read},
    num::{NonZeroU32, NonZeroU64},
    os::fd::{AsFd, BorrowedFd, OwnedFd},
    os::unix::ffi::OsStrExt,
    process::Child,
};

use nix::{
    poll::{PollFd, PollFlags, poll},
    sched::{CloneFlags, unshare},
    sys::signal::kill,
    unistd::{Pid as NixPid, getppid},
};
use rustix::{
    fs::{Dir, FileType, Mode, OFlags, ResolveFlags, fstat, fstatfs, open, openat, openat2},
    process::{Pid, PidfdFlags, getgroups, pidfd_open},
    thread::{
        CapabilitySet, CapabilitySets, Gid, Uid, capabilities, clear_ambient_capability_set,
        get_keep_capabilities, remove_capability_from_bounding_set, set_capabilities,
        set_keep_capabilities, set_no_new_privs, set_thread_groups, set_thread_res_gid,
        set_thread_res_uid,
    },
};
use thiserror::Error;
use volparossa_linux_uapi::{
    duplicate_descriptor_cloexec, install_worker_confinement_filter, namespace_type,
};

const SANDBOX_PROOF_DOMAIN: &[u8; 32] = b"volparossa/worker-sandbox/v5\0\0\0\0";
const SANDBOX_PROOF_VERSION: u32 = 5;
const MAX_DESCRIPTOR_AUDIT: usize = 4_096;
const MAX_PROC_STATUS_BYTES: usize = 64 * 1024;
const MAX_PROC_STAT_BYTES: usize = 4 * 1024;
const MAX_PROC_CGROUP_BYTES: usize = 4 * 1024;
const MAX_CGROUP_COMPONENTS: usize = 256;
const MAX_CGROUP_COMPONENT_BYTES: usize = 255;
const BOOT_ID_BYTES: usize = 37;
const CGROUP2_SUPER_MAGIC: i64 = 0x6367_7270;
const PROC_SUPER_MAGIC: i64 = 0x0000_9fa0;
const MAX_CAP_LAST_CAP_BYTES: usize = 4;
const WORKER_CHANNEL_DESCRIPTOR: i32 = 3;
const CAP_KILL: u32 = 5;
const CAP_SETGID: u32 = 6;
const CAP_SETUID: u32 = 7;
const CAP_SETPCAP: u32 = 8;
const CAP_NET_ADMIN: u32 = 12;
const CAP_NET_RAW: u32 = 13;
const CAP_SYS_ADMIN: u32 = 21;
const CAP_KILL_BIT: u64 = 1_u64 << CAP_KILL;
const CAP_SETGID_BIT: u64 = 1_u64 << CAP_SETGID;
const CAP_SETUID_BIT: u64 = 1_u64 << CAP_SETUID;
const CAP_SETPCAP_BIT: u64 = 1_u64 << CAP_SETPCAP;
const CAP_NET_ADMIN_BIT: u64 = 1_u64 << CAP_NET_ADMIN;
const CAP_NET_RAW_BIT: u64 = 1_u64 << CAP_NET_RAW;
const CAP_SYS_ADMIN_BIT: u64 = 1_u64 << CAP_SYS_ADMIN;
const HELPER_BOOTSTRAP_CAPABILITY_BITS: u64 = CAP_KILL_BIT
    | CAP_NET_ADMIN_BIT
    | CAP_NET_RAW_BIT
    | CAP_SETGID_BIT
    | CAP_SETPCAP_BIT
    | CAP_SETUID_BIT
    | CAP_SYS_ADMIN_BIT;
pub(super) const SYSTEMD_RESERVED_ID: u32 = 65_535;

pub(super) type ContextId = [u8; 16];

/// Dedicated non-root identity selected by the privileged parent for one route worker.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WorkerIdentity {
    uid: u32,
    gid: u32,
}

impl WorkerIdentity {
    pub(super) fn new(uid: u32, gid: u32) -> Result<Self, WorkerSandboxError> {
        if uid == 0
            || gid == 0
            || uid == SYSTEMD_RESERVED_ID
            || gid == SYSTEMD_RESERVED_ID
            || uid == u32::MAX
            || gid == u32::MAX
        {
            return Err(WorkerSandboxError::Invalid);
        }
        Ok(Self { uid, gid })
    }

    pub(super) const fn uid(self) -> u32 {
        self.uid
    }

    pub(super) const fn gid(self) -> u32 {
        self.gid
    }

    #[cfg(test)]
    pub(super) const fn fixture(uid: u32, gid: u32) -> Self {
        assert!(
            uid != SYSTEMD_RESERVED_ID
                && gid != SYSTEMD_RESERVED_ID
                && uid != u32::MAX
                && gid != u32::MAX,
            "worker fixture uses a systemd or kernel-reserved identity"
        );
        Self { uid, gid }
    }
}

#[derive(Debug, Error)]
pub(super) enum WorkerSandboxError {
    #[error("invalid worker sandbox evidence")]
    Invalid,
    #[error("worker sandbox state does not match the production plan")]
    Mismatch,
    #[error("unexpected inherited worker descriptor")]
    UnexpectedDescriptor,
    #[error("worker descriptor allowlist is incomplete")]
    MissingDescriptor,
    #[error("worker sandbox inspection failed")]
    Io(#[from] io::Error),
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct NetworkNamespaceIdentity {
    device: u64,
    inode: u64,
}

impl NetworkNamespaceIdentity {
    #[cfg(test)]
    pub(super) const fn fixture(device: u64, inode: u64) -> Self {
        Self { device, inode }
    }

    fn is_valid(self) -> bool {
        self.device != 0 && self.inode != 0
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct FileIdentity {
    device: u64,
    inode: u64,
}

impl FileIdentity {
    fn nonzero_parts(self) -> Result<(NonZeroU64, NonZeroU64), WorkerSandboxError> {
        Ok((
            NonZeroU64::new(self.device).ok_or(WorkerSandboxError::Mismatch)?,
            NonZeroU64::new(self.inode).ok_or(WorkerSandboxError::Mismatch)?,
        ))
    }
}

/// Numeric recovery identity proven by the retained authenticated worker pins.
///
/// These coordinates are intentionally separate from worker-registry and journal generations.
/// Callers must retain the affine `PinnedWorkerRecoveryIdentity` which produced them until the
/// durable ownership handoff has completed.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WorkerRecoveryAnchorParts {
    pub(super) boot_id: [u8; 16],
    pub(super) pid: NonZeroU32,
    pub(super) process_start_ticks: NonZeroU64,
    pub(super) network_namespace_device: NonZeroU64,
    pub(super) network_namespace_inode: NonZeroU64,
    pub(super) executable_device: NonZeroU64,
    pub(super) executable_inode: NonZeroU64,
    pub(super) service_cgroup_inode: NonZeroU64,
}

/// Retained kernel objects from which one worker's durable recovery anchor is revalidated.
///
/// The cgroup path is kernel-observed and retained only in memory. It is never part of the
/// durable journal; the journal receives only the exact pinned service-cgroup inode.
struct PinnedWorkerRecoveryAnchor {
    process_directory_identity: FileIdentity,
    boot_id_file: OwnedFd,
    boot_id_file_identity: FileIdentity,
    boot_id: [u8; 16],
    pid: NonZeroU32,
    process_start_ticks: NonZeroU64,
    executable: OwnedFd,
    executable_identity: FileIdentity,
    cgroup_namespace: OwnedFd,
    cgroup_namespace_identity: NetworkNamespaceIdentity,
    cgroup_root: OwnedFd,
    cgroup_root_identity: FileIdentity,
    service_cgroup: OwnedFd,
    service_cgroup_identity: FileIdentity,
    service_cgroup_path: Box<[u8]>,
}

impl PinnedWorkerRecoveryAnchor {
    fn duplicate(&self) -> Result<Self, WorkerSandboxError> {
        Ok(Self {
            process_directory_identity: self.process_directory_identity,
            boot_id_file: duplicate_descriptor_cloexec(&self.boot_id_file)?,
            boot_id_file_identity: self.boot_id_file_identity,
            boot_id: self.boot_id,
            pid: self.pid,
            process_start_ticks: self.process_start_ticks,
            executable: duplicate_descriptor_cloexec(&self.executable)?,
            executable_identity: self.executable_identity,
            cgroup_namespace: duplicate_descriptor_cloexec(&self.cgroup_namespace)?,
            cgroup_namespace_identity: self.cgroup_namespace_identity,
            cgroup_root: duplicate_descriptor_cloexec(&self.cgroup_root)?,
            cgroup_root_identity: self.cgroup_root_identity,
            service_cgroup: duplicate_descriptor_cloexec(&self.service_cgroup)?,
            service_cgroup_identity: self.service_cgroup_identity,
            service_cgroup_path: self.service_cgroup_path.clone(),
        })
    }
}

/// Affine parent-side ownership of one independently pinned worker network namespace.
///
/// The descriptor, rather than only its numeric identity, is retained so a concurrent worker reap
/// cannot destroy the expected namespace and permit an nsfs inode-reuse race while an adopted
/// transport socket is being validated.
#[derive(Debug)]
#[must_use = "dropping the worker network-namespace pin releases its kernel reference"]
pub(crate) struct PinnedWorkerNetworkNamespace {
    descriptor: OwnedFd,
    identity: NetworkNamespaceIdentity,
}

impl PinnedWorkerNetworkNamespace {
    pub(crate) fn verified_descriptor(&self) -> Result<BorrowedFd<'_>, WorkerSandboxError> {
        if typed_network_namespace_identity(&self.descriptor)? != self.identity {
            return Err(WorkerSandboxError::Mismatch);
        }
        Ok(self.descriptor.as_fd())
    }

    /// Compares another typed network-namespace descriptor with this still-live exact pin.
    ///
    /// Both descriptors are re-read on every comparison. The cached identity must still match this
    /// owner before the observed descriptor can be accepted.
    pub(crate) fn matches_descriptor<Fd: AsFd>(
        &self,
        observed: &Fd,
    ) -> Result<bool, WorkerSandboxError> {
        let retained = typed_network_namespace_identity(&self.descriptor)?;
        if retained != self.identity {
            return Err(WorkerSandboxError::Mismatch);
        }
        Ok(typed_network_namespace_identity(observed)? == self.identity)
    }

    /// Re-reads the retained typed descriptor before exposing its stable nsfs coordinates.
    ///
    /// Numeric coordinates alone are not ownership. Callers must keep this affine pin alive for
    /// as long as they use the returned recovery identity.
    pub(super) fn verified_identity_parts(
        &self,
    ) -> Result<(NonZeroU64, NonZeroU64), WorkerSandboxError> {
        let retained = typed_network_namespace_identity(&self.descriptor)?;
        if retained != self.identity {
            return Err(WorkerSandboxError::Mismatch);
        }
        let device = NonZeroU64::new(retained.device).ok_or(WorkerSandboxError::Mismatch)?;
        let inode = NonZeroU64::new(retained.inode).ok_or(WorkerSandboxError::Mismatch)?;
        Ok((device, inode))
    }

    #[cfg(test)]
    pub(crate) fn identity_for_test(&self) -> NetworkNamespaceIdentity {
        self.identity
    }
}

/// Affine duplicate of every parent-side kernel pin which identifies one authenticated worker.
#[must_use = "dropping recovery identity pins releases their exact kernel references"]
pub(super) struct PinnedWorkerRecoveryIdentity {
    pidfd: OwnedFd,
    process_directory: OwnedFd,
    network_namespace: PinnedWorkerNetworkNamespace,
    recovery_anchor: PinnedWorkerRecoveryAnchor,
}

/// Candidate cleanup capabilities selected for future restart custody.
///
/// The pidfd preserves exact task continuity and the namespace descriptor preserves the exact
/// anonymous `CLONE_NEWNET` object. All other recovery pins remain required as pre-arm proof
/// inputs. Whether this smaller pair is sufficient across restart remains unproven until PID 1
/// publication, journal-bound adoption and reaper evidence exist.
#[must_use = "dropping restart custody releases exact worker cleanup capability"]
pub(super) struct PinnedWorkerRestartCustody {
    pidfd: OwnedFd,
    network_namespace: PinnedWorkerNetworkNamespace,
}

impl PinnedWorkerRestartCustody {
    /// Borrow the exact pidfd cleanup capability without duplicating or transferring ownership.
    pub(super) fn borrowed_pidfd(&self) -> BorrowedFd<'_> {
        self.pidfd.as_fd()
    }

    /// Borrow the exact anonymous worker network-namespace cleanup capability.
    pub(super) fn borrowed_network_namespace(&self) -> BorrowedFd<'_> {
        self.network_namespace.descriptor.as_fd()
    }

    pub(super) fn ensure_live_and_namespace_matches_anchor(
        &self,
        anchor: WorkerRecoveryAnchorParts,
    ) -> Result<(), WorkerSandboxError> {
        let mut descriptors = [PollFd::new(self.pidfd.as_fd(), PollFlags::POLLIN)];
        let ready = poll(&mut descriptors, 0_u8).map_err(nix_io)?;
        if ready != 0
            || descriptors[0]
                .revents()
                .is_some_and(|events| !events.is_empty())
        {
            return Err(WorkerSandboxError::Mismatch);
        }
        let (device, inode) = self.network_namespace.verified_identity_parts()?;
        if (device, inode)
            != (
                anchor.network_namespace_device,
                anchor.network_namespace_inode,
            )
        {
            return Err(WorkerSandboxError::Mismatch);
        }
        Ok(())
    }
}

impl std::fmt::Debug for PinnedWorkerRestartCustody {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("PinnedWorkerRestartCustody(<redacted>)")
    }
}

impl PinnedWorkerRecoveryIdentity {
    pub(super) fn ensure_alive(&self) -> Result<(), WorkerSandboxError> {
        let mut descriptors = [PollFd::new(self.pidfd.as_fd(), PollFlags::POLLIN)];
        let ready = poll(&mut descriptors, 0_u8).map_err(nix_io)?;
        if ready != 0
            || descriptors[0]
                .revents()
                .is_some_and(|events| !events.is_empty())
        {
            return Err(WorkerSandboxError::Mismatch);
        }
        Ok(())
    }

    /// Revalidates every exact retained object before exposing durable numeric coordinates.
    ///
    /// This performs proof I/O and therefore must be called only after dropping the worker
    /// registry lock. Descriptor duplication itself is the short affine handoff done while the
    /// registered worker is still visible.
    pub(super) fn verified_recovery_anchor_parts(
        &self,
    ) -> Result<WorkerRecoveryAnchorParts, WorkerSandboxError> {
        self.ensure_alive()?;
        let (network_namespace_device, network_namespace_inode) =
            self.network_namespace.verified_identity_parts()?;
        let anchor = &self.recovery_anchor;
        verify_sealed_recovery_anchor(&self.process_directory, anchor)?;
        let (executable_device, executable_inode) = anchor.executable_identity.nonzero_parts()?;
        let service_cgroup_inode = NonZeroU64::new(anchor.service_cgroup_identity.inode)
            .ok_or(WorkerSandboxError::Mismatch)?;
        self.ensure_alive()?;
        Ok(WorkerRecoveryAnchorParts {
            boot_id: anchor.boot_id,
            pid: anchor.pid,
            process_start_ticks: anchor.process_start_ticks,
            network_namespace_device,
            network_namespace_inode,
            executable_device,
            executable_inode,
            service_cgroup_inode,
        })
    }

    /// Revalidates the full pre-arm proof, then duplicates only the two restart capabilities.
    pub(super) fn verified_anchor_with_restart_custody(
        &self,
    ) -> Result<(WorkerRecoveryAnchorParts, PinnedWorkerRestartCustody), WorkerSandboxError> {
        let anchor = self.verified_recovery_anchor_parts()?;
        let custody = PinnedWorkerRestartCustody {
            pidfd: duplicate_descriptor_cloexec(&self.pidfd)?,
            network_namespace: PinnedWorkerNetworkNamespace {
                descriptor: duplicate_descriptor_cloexec(&self.network_namespace.descriptor)?,
                identity: self.network_namespace.identity,
            },
        };
        custody.ensure_live_and_namespace_matches_anchor(anchor)?;
        self.ensure_alive()?;
        Ok((anchor, custody))
    }

    #[cfg(test)]
    pub(super) fn network_namespace_pin_for_test(&self) -> &PinnedWorkerNetworkNamespace {
        &self.network_namespace
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LinuxCapabilitySnapshot {
    inheritable: u64,
    permitted: u64,
    effective: u64,
    bounding: u64,
    ambient: u64,
}

impl LinuxCapabilitySnapshot {
    #[cfg(test)]
    pub(super) const fn fixture(
        inheritable: u64,
        permitted: u64,
        effective: u64,
        bounding: u64,
        ambient: u64,
    ) -> Self {
        Self {
            inheritable,
            permitted,
            effective,
            bounding,
            ambient,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct LinuxSeccompState {
    mode: u8,
    filter_count: u32,
}

impl LinuxSeccompState {
    #[cfg(test)]
    pub(super) const fn fixture(mode: u8, filter_count: u32) -> Self {
        Self { mode, filter_count }
    }

    fn from_status(mode: u32, filter_count: u32) -> Result<Self, WorkerSandboxError> {
        let mode = u8::try_from(mode).map_err(|_| WorkerSandboxError::Invalid)?;
        let state = Self { mode, filter_count };
        if !state.is_kernel_consistent() {
            return Err(WorkerSandboxError::Invalid);
        }
        Ok(state)
    }

    fn is_kernel_consistent(self) -> bool {
        matches!(
            (u32::from(self.mode), self.filter_count),
            (libc::SECCOMP_MODE_DISABLED | libc::SECCOMP_MODE_STRICT, 0)
        ) || (u32::from(self.mode) == libc::SECCOMP_MODE_FILTER && self.filter_count > 0)
    }

    fn expected_after_worker_filter(self) -> Result<Self, WorkerSandboxError> {
        if !self.is_kernel_consistent() || u32::from(self.mode) == libc::SECCOMP_MODE_STRICT {
            return Err(WorkerSandboxError::Invalid);
        }
        Ok(Self {
            mode: u8::try_from(libc::SECCOMP_MODE_FILTER)
                .map_err(|_| WorkerSandboxError::Invalid)?,
            filter_count: self
                .filter_count
                .checked_add(1)
                .ok_or(WorkerSandboxError::Invalid)?,
        })
    }

    #[cfg(test)]
    fn predecessor_for_fixture(self) -> Result<Self, WorkerSandboxError> {
        if u32::from(self.mode) != libc::SECCOMP_MODE_FILTER || self.filter_count == 0 {
            return Err(WorkerSandboxError::Invalid);
        }
        let filter_count = self
            .filter_count
            .checked_sub(1)
            .ok_or(WorkerSandboxError::Invalid)?;
        Ok(Self {
            mode: if filter_count == 0 {
                u8::try_from(libc::SECCOMP_MODE_DISABLED)
                    .map_err(|_| WorkerSandboxError::Invalid)?
            } else {
                u8::try_from(libc::SECCOMP_MODE_FILTER).map_err(|_| WorkerSandboxError::Invalid)?
            },
            filter_count,
        })
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WorkerSandboxSnapshot {
    parent_network_namespace: NetworkNamespaceIdentity,
    worker_network_namespace: NetworkNamespaceIdentity,
    identity: WorkerIdentity,
    supplementary_groups_empty: bool,
    no_new_privileges: bool,
    seccomp: LinuxSeccompState,
    capabilities: LinuxCapabilitySnapshot,
}

impl WorkerSandboxSnapshot {
    #[cfg(test)]
    pub(super) const fn fixture(
        parent_network_namespace: NetworkNamespaceIdentity,
        worker_network_namespace: NetworkNamespaceIdentity,
        identity: WorkerIdentity,
        supplementary_groups_empty: bool,
        no_new_privileges: bool,
        seccomp: LinuxSeccompState,
        capabilities: LinuxCapabilitySnapshot,
    ) -> Self {
        Self {
            parent_network_namespace,
            worker_network_namespace,
            identity,
            supplementary_groups_empty,
            no_new_privileges,
            seccomp,
            capabilities,
        }
    }

    #[cfg(test)]
    pub(super) fn fixture_seccomp_baseline(self) -> Result<LinuxSeccompState, WorkerSandboxError> {
        self.seccomp.predecessor_for_fixture()
    }
}

/// Exact state every production route-context child must prove before its first request.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct WorkerSandboxPlan {
    identity: WorkerIdentity,
    capabilities: LinuxCapabilitySnapshot,
    seccomp: LinuxSeccompState,
}

impl WorkerSandboxPlan {
    pub(super) fn production(
        baseline_seccomp: LinuxSeccompState,
        identity: WorkerIdentity,
    ) -> Result<Self, WorkerSandboxError> {
        Ok(Self {
            identity,
            capabilities: LinuxCapabilitySnapshot {
                inheritable: 0,
                permitted: CAP_NET_ADMIN_BIT,
                effective: CAP_NET_ADMIN_BIT,
                bounding: CAP_NET_ADMIN_BIT,
                ambient: 0,
            },
            seccomp: baseline_seccomp.expected_after_worker_filter()?,
        })
    }

    pub(super) fn verify(self, snapshot: WorkerSandboxSnapshot) -> Result<(), WorkerSandboxError> {
        if !snapshot.parent_network_namespace.is_valid()
            || !snapshot.worker_network_namespace.is_valid()
        {
            return Err(WorkerSandboxError::Invalid);
        }
        if snapshot.parent_network_namespace == snapshot.worker_network_namespace
            || snapshot.identity != self.identity
            || !snapshot.supplementary_groups_empty
            || !snapshot.no_new_privileges
            || snapshot.seccomp != self.seccomp
            || snapshot.capabilities != self.capabilities
        {
            return Err(WorkerSandboxError::Mismatch);
        }
        Ok(())
    }
}

/// Fixed, domain-separated child statement bound to the one-time bootstrap challenge.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct SandboxProofRecord {
    context_id: ContextId,
    generation: u64,
    challenge: [u8; 32],
    parent_pid: u32,
    child_pid: u32,
    snapshot: WorkerSandboxSnapshot,
}

impl SandboxProofRecord {
    pub(super) const LENGTH: usize = 192;

    pub(super) const fn new(
        context_id: ContextId,
        generation: u64,
        challenge: [u8; 32],
        parent_pid: u32,
        child_pid: u32,
        snapshot: WorkerSandboxSnapshot,
    ) -> Self {
        Self {
            context_id,
            generation,
            challenge,
            parent_pid,
            child_pid,
            snapshot,
        }
    }

    #[cfg(test)]
    pub(super) const fn fixture(
        context_id: ContextId,
        generation: u64,
        challenge: [u8; 32],
        parent_pid: u32,
        child_pid: u32,
        snapshot: WorkerSandboxSnapshot,
    ) -> Self {
        Self::new(
            context_id, generation, challenge, parent_pid, child_pid, snapshot,
        )
    }

    pub(super) fn encode(self) -> [u8; Self::LENGTH] {
        let mut encoded = [0_u8; Self::LENGTH];
        encoded[0..32].copy_from_slice(SANDBOX_PROOF_DOMAIN);
        encoded[32..36].copy_from_slice(&SANDBOX_PROOF_VERSION.to_be_bytes());
        encoded[36..52].copy_from_slice(&self.context_id);
        encoded[52..60].copy_from_slice(&self.generation.to_be_bytes());
        encoded[60..92].copy_from_slice(&self.challenge);
        encoded[92..96].copy_from_slice(&self.parent_pid.to_be_bytes());
        encoded[96..100].copy_from_slice(&self.child_pid.to_be_bytes());
        encoded[100..108]
            .copy_from_slice(&self.snapshot.parent_network_namespace.device.to_be_bytes());
        encoded[108..116]
            .copy_from_slice(&self.snapshot.parent_network_namespace.inode.to_be_bytes());
        encoded[116..124]
            .copy_from_slice(&self.snapshot.worker_network_namespace.device.to_be_bytes());
        encoded[124..132]
            .copy_from_slice(&self.snapshot.worker_network_namespace.inode.to_be_bytes());
        encoded[132..136].copy_from_slice(&self.snapshot.identity.uid.to_be_bytes());
        encoded[136..140].copy_from_slice(&self.snapshot.identity.gid.to_be_bytes());
        encoded[140] = u8::from(self.snapshot.supplementary_groups_empty);
        encoded[141] = u8::from(self.snapshot.no_new_privileges);
        encoded[142] = self.snapshot.seccomp.mode;
        encoded[144..148].copy_from_slice(&self.snapshot.seccomp.filter_count.to_be_bytes());
        for (offset, value) in [
            self.snapshot.capabilities.inheritable,
            self.snapshot.capabilities.permitted,
            self.snapshot.capabilities.effective,
            self.snapshot.capabilities.bounding,
            self.snapshot.capabilities.ambient,
        ]
        .into_iter()
        .enumerate()
        {
            let start = 152 + offset * 8;
            encoded[start..start + 8].copy_from_slice(&value.to_be_bytes());
        }
        encoded
    }

    pub(super) fn decode(encoded: &[u8]) -> Result<Self, WorkerSandboxError> {
        if encoded.len() != Self::LENGTH
            || encoded.get(0..32) != Some(SANDBOX_PROOF_DOMAIN.as_slice())
            || encoded.get(143..144) != Some([0_u8; 1].as_slice())
            || encoded.get(148..152) != Some([0_u8; 4].as_slice())
            || u32::from_be_bytes(read_array(encoded, 32)?) != SANDBOX_PROOF_VERSION
        {
            return Err(WorkerSandboxError::Invalid);
        }
        let supplementary_groups_empty = match encoded[140] {
            0 => false,
            1 => true,
            _ => return Err(WorkerSandboxError::Invalid),
        };
        let no_new_privileges = match encoded[141] {
            0 => false,
            1 => true,
            _ => return Err(WorkerSandboxError::Invalid),
        };
        let record = Self {
            context_id: read_array(encoded, 36)?,
            generation: u64::from_be_bytes(read_array(encoded, 52)?),
            challenge: read_array(encoded, 60)?,
            parent_pid: u32::from_be_bytes(read_array(encoded, 92)?),
            child_pid: u32::from_be_bytes(read_array(encoded, 96)?),
            snapshot: WorkerSandboxSnapshot {
                parent_network_namespace: NetworkNamespaceIdentity {
                    device: u64::from_be_bytes(read_array(encoded, 100)?),
                    inode: u64::from_be_bytes(read_array(encoded, 108)?),
                },
                worker_network_namespace: NetworkNamespaceIdentity {
                    device: u64::from_be_bytes(read_array(encoded, 116)?),
                    inode: u64::from_be_bytes(read_array(encoded, 124)?),
                },
                identity: WorkerIdentity::new(
                    u32::from_be_bytes(read_array(encoded, 132)?),
                    u32::from_be_bytes(read_array(encoded, 136)?),
                )?,
                supplementary_groups_empty,
                no_new_privileges,
                seccomp: LinuxSeccompState::from_status(
                    u32::from(encoded[142]),
                    u32::from_be_bytes(read_array(encoded, 144)?),
                )?,
                capabilities: LinuxCapabilitySnapshot {
                    inheritable: u64::from_be_bytes(read_array(encoded, 152)?),
                    permitted: u64::from_be_bytes(read_array(encoded, 160)?),
                    effective: u64::from_be_bytes(read_array(encoded, 168)?),
                    bounding: u64::from_be_bytes(read_array(encoded, 176)?),
                    ambient: u64::from_be_bytes(read_array(encoded, 184)?),
                },
            },
        };
        if record.context_id.iter().all(|byte| *byte == 0)
            || record.generation == 0
            || record.challenge.iter().all(|byte| *byte == 0)
            || record.parent_pid <= 1
            || record.child_pid == 0
            || !record.snapshot.parent_network_namespace.is_valid()
            || !record.snapshot.worker_network_namespace.is_valid()
        {
            return Err(WorkerSandboxError::Invalid);
        }
        Ok(record)
    }
}

/// Consumed exactly once while matching a child proof to independently observed kernel state.
pub(super) struct SandboxProofExpectation {
    context_id: ContextId,
    generation: u64,
    challenge: [u8; 32],
    parent_pid: u32,
    child_pid: u32,
    independently_observed_snapshot: WorkerSandboxSnapshot,
}

impl SandboxProofExpectation {
    pub(super) const fn new(
        context_id: ContextId,
        generation: u64,
        challenge: [u8; 32],
        parent_pid: u32,
        child_pid: u32,
        independently_observed_snapshot: WorkerSandboxSnapshot,
    ) -> Self {
        Self {
            context_id,
            generation,
            challenge,
            parent_pid,
            child_pid,
            independently_observed_snapshot,
        }
    }

    #[cfg(test)]
    pub(super) const fn fixture(
        context_id: ContextId,
        generation: u64,
        challenge: [u8; 32],
        parent_pid: u32,
        child_pid: u32,
        independently_observed_snapshot: WorkerSandboxSnapshot,
    ) -> Self {
        Self::new(
            context_id,
            generation,
            challenge,
            parent_pid,
            child_pid,
            independently_observed_snapshot,
        )
    }

    pub(super) fn verify_once(
        self,
        encoded: &[u8],
        plan: WorkerSandboxPlan,
    ) -> Result<(), WorkerSandboxError> {
        let record = SandboxProofRecord::decode(encoded)?;
        if record.context_id != self.context_id
            || record.generation != self.generation
            || record.challenge != self.challenge
            || record.parent_pid != self.parent_pid
            || record.child_pid != self.child_pid
            || record.snapshot != self.independently_observed_snapshot
        {
            return Err(WorkerSandboxError::Mismatch);
        }
        plan.verify(record.snapshot)
    }
}

fn read_array<const LENGTH: usize>(
    encoded: &[u8],
    offset: usize,
) -> Result<[u8; LENGTH], WorkerSandboxError> {
    encoded
        .get(offset..offset.saturating_add(LENGTH))
        .ok_or(WorkerSandboxError::Invalid)?
        .try_into()
        .map_err(|_| WorkerSandboxError::Invalid)
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct ParsedProcessStatus {
    pid: u32,
    parent_pid: u32,
    uids: [u32; 4],
    gids: [u32; 4],
    supplementary_groups: SupplementaryGroups,
    no_new_privileges: bool,
    seccomp: LinuxSeccompState,
    capabilities: LinuxCapabilitySnapshot,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SupplementaryGroups {
    Empty,
    Singleton(u32),
    Multiple,
}

impl SupplementaryGroups {
    fn is_empty(self) -> bool {
        self == Self::Empty
    }
}

fn parse_process_status(bytes: &[u8]) -> Result<ParsedProcessStatus, WorkerSandboxError> {
    let text = std::str::from_utf8(bytes).map_err(|_| WorkerSandboxError::Invalid)?;
    let mut pid = None;
    let mut parent_pid = None;
    let mut uids = None;
    let mut gids = None;
    let mut supplementary_groups = None;
    let mut no_new_privileges = None;
    let mut seccomp_mode = None;
    let mut seccomp_filters = None;
    let mut inheritable = None;
    let mut permitted = None;
    let mut effective = None;
    let mut bounding = None;
    let mut ambient = None;
    for (index, line) in text.lines().enumerate() {
        if index >= 2_048 || line.len() > 4_096 {
            return Err(WorkerSandboxError::Invalid);
        }
        if let Some(value) = line.strip_prefix("Pid:\t") {
            set_once(&mut pid, parse_decimal_u32(value)?)?;
        } else if let Some(value) = line.strip_prefix("PPid:\t") {
            set_once(&mut parent_pid, parse_decimal_u32(value)?)?;
        } else if let Some(value) = line.strip_prefix("Uid:\t") {
            set_once(&mut uids, parse_identity_quad(value)?)?;
        } else if let Some(value) = line.strip_prefix("Gid:\t") {
            set_once(&mut gids, parse_identity_quad(value)?)?;
        } else if let Some(value) = line.strip_prefix("Groups:\t") {
            set_once(
                &mut supplementary_groups,
                parse_supplementary_groups(value)?,
            )?;
        } else if let Some(value) = line.strip_prefix("NoNewPrivs:\t") {
            let value = match value {
                "0" => false,
                "1" => true,
                _ => return Err(WorkerSandboxError::Invalid),
            };
            set_once(&mut no_new_privileges, value)?;
        } else if let Some(value) = line.strip_prefix("Seccomp:\t") {
            set_once(&mut seccomp_mode, parse_decimal_u32(value)?)?;
        } else if let Some(value) = line.strip_prefix("Seccomp_filters:\t") {
            set_once(&mut seccomp_filters, parse_decimal_u32(value)?)?;
        } else if let Some(value) = line.strip_prefix("CapInh:\t") {
            set_once(&mut inheritable, parse_capability_mask(value)?)?;
        } else if let Some(value) = line.strip_prefix("CapPrm:\t") {
            set_once(&mut permitted, parse_capability_mask(value)?)?;
        } else if let Some(value) = line.strip_prefix("CapEff:\t") {
            set_once(&mut effective, parse_capability_mask(value)?)?;
        } else if let Some(value) = line.strip_prefix("CapBnd:\t") {
            set_once(&mut bounding, parse_capability_mask(value)?)?;
        } else if let Some(value) = line.strip_prefix("CapAmb:\t") {
            set_once(&mut ambient, parse_capability_mask(value)?)?;
        }
    }
    Ok(ParsedProcessStatus {
        pid: pid.ok_or(WorkerSandboxError::Invalid)?,
        parent_pid: parent_pid.ok_or(WorkerSandboxError::Invalid)?,
        uids: uids.ok_or(WorkerSandboxError::Invalid)?,
        gids: gids.ok_or(WorkerSandboxError::Invalid)?,
        supplementary_groups: supplementary_groups.ok_or(WorkerSandboxError::Invalid)?,
        no_new_privileges: no_new_privileges.ok_or(WorkerSandboxError::Invalid)?,
        seccomp: LinuxSeccompState::from_status(
            seccomp_mode.ok_or(WorkerSandboxError::Invalid)?,
            seccomp_filters.ok_or(WorkerSandboxError::Invalid)?,
        )?,
        capabilities: LinuxCapabilitySnapshot {
            inheritable: inheritable.ok_or(WorkerSandboxError::Invalid)?,
            permitted: permitted.ok_or(WorkerSandboxError::Invalid)?,
            effective: effective.ok_or(WorkerSandboxError::Invalid)?,
            bounding: bounding.ok_or(WorkerSandboxError::Invalid)?,
            ambient: ambient.ok_or(WorkerSandboxError::Invalid)?,
        },
    })
}

fn set_once<T>(slot: &mut Option<T>, value: T) -> Result<(), WorkerSandboxError> {
    if slot.replace(value).is_some() {
        return Err(WorkerSandboxError::Invalid);
    }
    Ok(())
}

fn parse_decimal_u32(value: &str) -> Result<u32, WorkerSandboxError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(WorkerSandboxError::Invalid);
    }
    value.parse().map_err(|_| WorkerSandboxError::Invalid)
}

fn parse_identity_quad(value: &str) -> Result<[u32; 4], WorkerSandboxError> {
    let values = value
        .split_ascii_whitespace()
        .map(parse_decimal_u32)
        .collect::<Result<Vec<_>, _>>()?;
    values.try_into().map_err(|_| WorkerSandboxError::Invalid)
}

fn parse_supplementary_groups(value: &str) -> Result<SupplementaryGroups, WorkerSandboxError> {
    let mut count = 0_usize;
    let mut previous = None;
    for group in value.split_ascii_whitespace() {
        count = count.checked_add(1).ok_or(WorkerSandboxError::Invalid)?;
        if count > 256 {
            return Err(WorkerSandboxError::Invalid);
        }
        let group = parse_decimal_u32(group)?;
        if previous.is_some_and(|previous| previous >= group) {
            return Err(WorkerSandboxError::Invalid);
        }
        previous = Some(group);
    }
    Ok(match (count, previous) {
        (0, None) => SupplementaryGroups::Empty,
        (1, Some(group)) => SupplementaryGroups::Singleton(group),
        (2.., Some(_)) => SupplementaryGroups::Multiple,
        _ => return Err(WorkerSandboxError::Invalid),
    })
}

fn parse_capability_mask(value: &str) -> Result<u64, WorkerSandboxError> {
    if value.len() != 16
        || !value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || matches!(byte, b'a'..=b'f'))
    {
        return Err(WorkerSandboxError::Invalid);
    }
    u64::from_str_radix(value, 16).map_err(|_| WorkerSandboxError::Invalid)
}

fn read_bounded(mut file: File, maximum: usize) -> Result<Vec<u8>, WorkerSandboxError> {
    let mut bytes = Vec::with_capacity(maximum.saturating_add(1));
    file.by_ref()
        .take(u64::try_from(maximum.saturating_add(1)).map_err(|_| WorkerSandboxError::Invalid)?)
        .read_to_end(&mut bytes)?;
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(WorkerSandboxError::Invalid);
    }
    Ok(bytes)
}

fn namespace_identity<Fd: AsFd>(
    descriptor: &Fd,
) -> Result<NetworkNamespaceIdentity, WorkerSandboxError> {
    let metadata = fstat(descriptor).map_err(rustix_io)?;
    let identity = NetworkNamespaceIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    };
    if !identity.is_valid() {
        return Err(WorkerSandboxError::Invalid);
    }
    Ok(identity)
}

fn typed_network_namespace_identity<Fd: AsFd>(
    descriptor: &Fd,
) -> Result<NetworkNamespaceIdentity, WorkerSandboxError> {
    if namespace_type(descriptor)? != libc::CLONE_NEWNET {
        return Err(WorkerSandboxError::Mismatch);
    }
    namespace_identity(descriptor)
}

fn typed_namespace_identity<Fd: AsFd>(
    descriptor: &Fd,
    expected_type: i32,
) -> Result<NetworkNamespaceIdentity, WorkerSandboxError> {
    if namespace_type(descriptor)? != expected_type {
        return Err(WorkerSandboxError::Mismatch);
    }
    namespace_identity(descriptor)
}

fn descriptor_identity<Fd: AsFd>(
    descriptor: &Fd,
    expected_type: FileType,
) -> Result<FileIdentity, WorkerSandboxError> {
    let metadata = fstat(descriptor).map_err(rustix_io)?;
    if FileType::from_raw_mode(metadata.st_mode) != expected_type
        || metadata.st_dev == 0
        || metadata.st_ino == 0
    {
        return Err(WorkerSandboxError::Mismatch);
    }
    Ok(FileIdentity {
        device: metadata.st_dev,
        inode: metadata.st_ino,
    })
}

fn read_bounded_descriptor<Fd: AsFd>(
    descriptor: &Fd,
    maximum: usize,
) -> Result<Vec<u8>, WorkerSandboxError> {
    const READ_CHUNK_BYTES: usize = 1_024;
    let limit = maximum.checked_add(1).ok_or(WorkerSandboxError::Invalid)?;
    let mut bytes = Vec::with_capacity(limit);
    while bytes.len() < limit {
        let mut chunk = [0_u8; READ_CHUNK_BYTES];
        let remaining = limit - bytes.len();
        let length = rustix::io::pread(
            descriptor,
            &mut chunk[..remaining.min(READ_CHUNK_BYTES)],
            u64::try_from(bytes.len()).map_err(|_| WorkerSandboxError::Invalid)?,
        )
        .map_err(rustix_io)?;
        if length == 0 {
            break;
        }
        bytes.extend_from_slice(&chunk[..length]);
    }
    if bytes.is_empty() || bytes.len() > maximum {
        return Err(WorkerSandboxError::Invalid);
    }
    Ok(bytes)
}

fn parse_boot_id(bytes: &[u8]) -> Result<[u8; 16], WorkerSandboxError> {
    const HYPHENS: [usize; 4] = [8, 13, 18, 23];
    if bytes.len() != BOOT_ID_BYTES || bytes[BOOT_ID_BYTES - 1] != b'\n' {
        return Err(WorkerSandboxError::Invalid);
    }
    let text = &bytes[..BOOT_ID_BYTES - 1];
    for (index, byte) in text.iter().copied().enumerate() {
        if HYPHENS.contains(&index) {
            if byte != b'-' {
                return Err(WorkerSandboxError::Invalid);
            }
        } else if !byte.is_ascii_digit() && !matches!(byte, b'a'..=b'f') {
            return Err(WorkerSandboxError::Invalid);
        }
    }
    let mut decoded = [0_u8; 16];
    let mut nibble_index = 0_usize;
    for byte in text.iter().copied().filter(|byte| *byte != b'-') {
        let nibble = match byte {
            b'0'..=b'9' => byte - b'0',
            b'a'..=b'f' => byte - b'a' + 10,
            _ => return Err(WorkerSandboxError::Invalid),
        };
        let target = nibble_index / 2;
        decoded[target] = if nibble_index % 2 == 0 {
            nibble << 4
        } else {
            decoded[target] | nibble
        };
        nibble_index += 1;
    }
    if nibble_index != 32 || decoded == [0; 16] {
        return Err(WorkerSandboxError::Invalid);
    }
    Ok(decoded)
}

fn parse_canonical_u64(bytes: &[u8]) -> Result<u64, WorkerSandboxError> {
    if bytes.is_empty()
        || (bytes.len() > 1 && bytes[0] == b'0')
        || !bytes.iter().all(u8::is_ascii_digit)
    {
        return Err(WorkerSandboxError::Invalid);
    }
    bytes.iter().try_fold(0_u64, |value, byte| {
        value
            .checked_mul(10)
            .and_then(|value| value.checked_add(u64::from(byte - b'0')))
            .ok_or(WorkerSandboxError::Invalid)
    })
}

fn parse_process_start_ticks(
    bytes: &[u8],
    expected_pid: NonZeroU32,
) -> Result<NonZeroU64, WorkerSandboxError> {
    if bytes.is_empty()
        || bytes.len() > MAX_PROC_STAT_BYTES
        || bytes.last() != Some(&b'\n')
        || bytes.contains(&0)
    {
        return Err(WorkerSandboxError::Invalid);
    }
    let pid_end = bytes
        .iter()
        .position(|byte| *byte == b' ')
        .ok_or(WorkerSandboxError::Invalid)?;
    let pid = parse_canonical_u64(&bytes[..pid_end])?;
    if pid != u64::from(expected_pid.get()) || bytes.get(pid_end + 1) != Some(&b'(') {
        return Err(WorkerSandboxError::Mismatch);
    }
    let command_start = pid_end + 2;
    let command_end = bytes[..bytes.len() - 1]
        .iter()
        .rposition(|byte| *byte == b')')
        .ok_or(WorkerSandboxError::Invalid)?;
    if command_end < command_start
        || command_end - command_start > 15
        || bytes.get(command_end + 1) != Some(&b' ')
        || bytes.get(command_end + 3) != Some(&b' ')
    {
        return Err(WorkerSandboxError::Invalid);
    }
    if !matches!(
        bytes.get(command_end + 2),
        Some(b'R' | b'S' | b'D' | b'Z' | b'T' | b't' | b'X' | b'x' | b'K' | b'W' | b'P' | b'I')
    ) {
        return Err(WorkerSandboxError::Invalid);
    }
    let fields = bytes[command_end + 4..bytes.len() - 1]
        .split(|byte| *byte == b' ')
        .collect::<Vec<_>>();
    if fields.len() < 19 || fields.iter().any(|field| field.is_empty()) {
        return Err(WorkerSandboxError::Invalid);
    }
    let parent_pid = parse_canonical_u64(fields[0])?;
    if parent_pid > u64::from(u32::MAX) {
        return Err(WorkerSandboxError::Invalid);
    }
    NonZeroU64::new(parse_canonical_u64(fields[18])?).ok_or(WorkerSandboxError::Invalid)
}

fn parse_unified_cgroup_path(bytes: &[u8]) -> Result<Box<[u8]>, WorkerSandboxError> {
    if bytes.is_empty()
        || bytes.len() > MAX_PROC_CGROUP_BYTES
        || !bytes.starts_with(b"0::/")
        || bytes.last() != Some(&b'\n')
        || bytes[..bytes.len() - 1].contains(&b'\n')
    {
        return Err(WorkerSandboxError::Invalid);
    }
    let path = &bytes[3..bytes.len() - 1];
    if path == b"/" {
        return Ok(path.into());
    }
    if path.last() == Some(&b'/') {
        return Err(WorkerSandboxError::Invalid);
    }
    let mut count = 0_usize;
    for component in path[1..].split(|byte| *byte == b'/') {
        count = count.checked_add(1).ok_or(WorkerSandboxError::Invalid)?;
        if count > MAX_CGROUP_COMPONENTS
            || component.is_empty()
            || component.len() > MAX_CGROUP_COMPONENT_BYTES
            || matches!(component, b"." | b"..")
            || component.ends_with(b" (deleted)")
            || component
                .iter()
                .any(|byte| *byte == 0 || *byte < b' ' || *byte == 0x7f)
        {
            return Err(WorkerSandboxError::Invalid);
        }
    }
    Ok(path.into())
}

fn ensure_filesystem_type<Fd: AsFd>(
    descriptor: &Fd,
    expected_magic: i64,
) -> Result<(), WorkerSandboxError> {
    let filesystem = fstatfs(descriptor).map_err(rustix_io)?;
    if i128::from(filesystem.f_type) != i128::from(expected_magic) {
        return Err(WorkerSandboxError::Mismatch);
    }
    Ok(())
}

fn ensure_cgroup2<Fd: AsFd>(descriptor: &Fd) -> Result<(), WorkerSandboxError> {
    ensure_filesystem_type(descriptor, CGROUP2_SUPER_MAGIC)
}

fn ensure_procfs<Fd: AsFd>(descriptor: &Fd) -> Result<(), WorkerSandboxError> {
    ensure_filesystem_type(descriptor, PROC_SUPER_MAGIC)
}

fn open_process_file<Fd: AsFd>(
    process_directory: &Fd,
    name: &str,
) -> Result<OwnedFd, WorkerSandboxError> {
    Ok(openat2(
        process_directory,
        name,
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH | ResolveFlags::NO_MAGICLINKS | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(rustix_io)?)
}

fn open_process_magic_link<Fd: AsFd>(
    process_directory: &Fd,
    name: &str,
    flags: OFlags,
) -> Result<OwnedFd, WorkerSandboxError> {
    // `exe` and `ns/cgroup` are procfs magic links by definition. Their names are fixed here,
    // relative to the already pinned exact process directory; no caller-controlled path enters
    // this resolution.
    Ok(openat2(
        process_directory,
        name,
        flags | OFlags::CLOEXEC,
        Mode::empty(),
        ResolveFlags::empty(),
    )
    .map_err(rustix_io)?)
}

fn resolve_service_cgroup<Fd: AsFd>(
    cgroup_root: &Fd,
    absolute_path: &[u8],
) -> Result<OwnedFd, WorkerSandboxError> {
    let relative = if absolute_path == b"/" {
        &b"."[..]
    } else {
        absolute_path
            .strip_prefix(b"/")
            .ok_or(WorkerSandboxError::Invalid)?
    };
    Ok(openat2(
        cgroup_root,
        OsStr::from_bytes(relative),
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
        ResolveFlags::BENEATH
            | ResolveFlags::NO_XDEV
            | ResolveFlags::NO_MAGICLINKS
            | ResolveFlags::NO_SYMLINKS,
    )
    .map_err(rustix_io)?)
}

fn capture_recovery_anchor(
    process_directory: &OwnedFd,
    child_pid: u32,
) -> Result<PinnedWorkerRecoveryAnchor, WorkerSandboxError> {
    let pid = NonZeroU32::new(child_pid).ok_or(WorkerSandboxError::Invalid)?;
    ensure_procfs(process_directory)?;
    let process_directory_identity = descriptor_identity(process_directory, FileType::Directory)?;
    let boot_id_file = open(
        "/proc/sys/kernel/random/boot_id",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(rustix_io)?;
    ensure_procfs(&boot_id_file)?;
    let boot_id_file_identity = descriptor_identity(&boot_id_file, FileType::RegularFile)?;
    let boot_id = parse_boot_id(&read_bounded_descriptor(&boot_id_file, BOOT_ID_BYTES)?)?;
    let stat = open_process_file(process_directory, "stat")?;
    ensure_procfs(&stat)?;
    let _ = descriptor_identity(&stat, FileType::RegularFile)?;
    let process_start_ticks =
        parse_process_start_ticks(&read_bounded_descriptor(&stat, MAX_PROC_STAT_BYTES)?, pid)?;
    let executable = open_process_magic_link(process_directory, "exe", OFlags::PATH)?;
    let executable_identity = descriptor_identity(&executable, FileType::RegularFile)?;
    let parent_executable = open(
        "/proc/self/exe",
        OFlags::PATH | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(rustix_io)?;
    if descriptor_identity(&parent_executable, FileType::RegularFile)? != executable_identity {
        return Err(WorkerSandboxError::Mismatch);
    }

    let cgroup_namespace = open_process_magic_link(process_directory, "ns/cgroup", OFlags::RDONLY)?;
    let cgroup_namespace_identity =
        typed_namespace_identity(&cgroup_namespace, libc::CLONE_NEWCGROUP)?;
    let parent_cgroup_namespace = open(
        "/proc/self/ns/cgroup",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(rustix_io)?;
    if typed_namespace_identity(&parent_cgroup_namespace, libc::CLONE_NEWCGROUP)?
        != cgroup_namespace_identity
    {
        return Err(WorkerSandboxError::Mismatch);
    }

    let cgroup_record = open_process_file(process_directory, "cgroup")?;
    ensure_procfs(&cgroup_record)?;
    let _ = descriptor_identity(&cgroup_record, FileType::RegularFile)?;
    let service_cgroup_path = parse_unified_cgroup_path(&read_bounded_descriptor(
        &cgroup_record,
        MAX_PROC_CGROUP_BYTES,
    )?)?;
    let parent_cgroup_record = open(
        "/proc/self/cgroup",
        OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(rustix_io)?;
    ensure_procfs(&parent_cgroup_record)?;
    let _ = descriptor_identity(&parent_cgroup_record, FileType::RegularFile)?;
    let parent_service_cgroup_path = parse_unified_cgroup_path(&read_bounded_descriptor(
        &parent_cgroup_record,
        MAX_PROC_CGROUP_BYTES,
    )?)?;
    if parent_service_cgroup_path != service_cgroup_path {
        return Err(WorkerSandboxError::Mismatch);
    }
    let cgroup_root = open(
        "/sys/fs/cgroup",
        OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
        Mode::empty(),
    )
    .map_err(rustix_io)?;
    ensure_cgroup2(&cgroup_root)?;
    let cgroup_root_identity = descriptor_identity(&cgroup_root, FileType::Directory)?;
    let service_cgroup = resolve_service_cgroup(&cgroup_root, &service_cgroup_path)?;
    ensure_cgroup2(&service_cgroup)?;
    let service_cgroup_identity = descriptor_identity(&service_cgroup, FileType::Directory)?;
    if service_cgroup_identity.device != cgroup_root_identity.device {
        return Err(WorkerSandboxError::Mismatch);
    }

    let anchor = PinnedWorkerRecoveryAnchor {
        process_directory_identity,
        boot_id_file,
        boot_id_file_identity,
        boot_id,
        pid,
        process_start_ticks,
        executable,
        executable_identity,
        cgroup_namespace,
        cgroup_namespace_identity,
        cgroup_root,
        cgroup_root_identity,
        service_cgroup,
        service_cgroup_identity,
        service_cgroup_path,
    };
    verify_bootstrap_recovery_anchor(process_directory, &anchor)?;
    Ok(anchor)
}

fn verify_bootstrap_recovery_anchor(
    process_directory: &OwnedFd,
    anchor: &PinnedWorkerRecoveryAnchor,
) -> Result<(), WorkerSandboxError> {
    verify_recovery_anchor(process_directory, anchor, true)
}

fn verify_sealed_recovery_anchor(
    process_directory: &OwnedFd,
    anchor: &PinnedWorkerRecoveryAnchor,
) -> Result<(), WorkerSandboxError> {
    verify_recovery_anchor(process_directory, anchor, false)
}

fn attest_protected_magic_link_denials(
    process_directory: &OwnedFd,
) -> Result<(), WorkerSandboxError> {
    // A successful post-transition open would mean that the parent has an unexpected ptrace-like
    // authority or that the child's credential/dumpability boundary was not applied. Neither is
    // part of the fixed production service contract.
    for (name, flags) in [("exe", OFlags::PATH), ("ns/cgroup", OFlags::RDONLY)] {
        match open_process_magic_link(process_directory, name, flags) {
            Err(WorkerSandboxError::Io(error)) if error.raw_os_error() == Some(libc::EACCES) => {}
            Ok(_) | Err(_) => return Err(WorkerSandboxError::Mismatch),
        }
    }
    Ok(())
}

fn verify_recovery_anchor(
    process_directory: &OwnedFd,
    anchor: &PinnedWorkerRecoveryAnchor,
    reopen_protected_magic_links: bool,
) -> Result<(), WorkerSandboxError> {
    ensure_procfs(process_directory)?;
    if descriptor_identity(process_directory, FileType::Directory)?
        != anchor.process_directory_identity
    {
        return Err(WorkerSandboxError::Mismatch);
    }
    ensure_procfs(&anchor.boot_id_file)?;
    if descriptor_identity(&anchor.boot_id_file, FileType::RegularFile)?
        != anchor.boot_id_file_identity
    {
        return Err(WorkerSandboxError::Mismatch);
    }
    if parse_boot_id(&read_bounded_descriptor(
        &anchor.boot_id_file,
        BOOT_ID_BYTES,
    )?)? != anchor.boot_id
    {
        return Err(WorkerSandboxError::Mismatch);
    }
    let stat = open_process_file(process_directory, "stat")?;
    ensure_procfs(&stat)?;
    let _ = descriptor_identity(&stat, FileType::RegularFile)?;
    if parse_process_start_ticks(
        &read_bounded_descriptor(&stat, MAX_PROC_STAT_BYTES)?,
        anchor.pid,
    )? != anchor.process_start_ticks
    {
        return Err(WorkerSandboxError::Mismatch);
    }

    if descriptor_identity(&anchor.executable, FileType::RegularFile)? != anchor.executable_identity
    {
        return Err(WorkerSandboxError::Mismatch);
    }
    if reopen_protected_magic_links {
        let executable = open_process_magic_link(process_directory, "exe", OFlags::PATH)?;
        if descriptor_identity(&executable, FileType::RegularFile)? != anchor.executable_identity {
            return Err(WorkerSandboxError::Mismatch);
        }
    }

    if typed_namespace_identity(&anchor.cgroup_namespace, libc::CLONE_NEWCGROUP)?
        != anchor.cgroup_namespace_identity
    {
        return Err(WorkerSandboxError::Mismatch);
    }
    if reopen_protected_magic_links {
        let cgroup_namespace =
            open_process_magic_link(process_directory, "ns/cgroup", OFlags::RDONLY)?;
        if typed_namespace_identity(&cgroup_namespace, libc::CLONE_NEWCGROUP)?
            != anchor.cgroup_namespace_identity
        {
            return Err(WorkerSandboxError::Mismatch);
        }
    }

    ensure_cgroup2(&anchor.cgroup_root)?;
    if descriptor_identity(&anchor.cgroup_root, FileType::Directory)? != anchor.cgroup_root_identity
    {
        return Err(WorkerSandboxError::Mismatch);
    }
    ensure_cgroup2(&anchor.service_cgroup)?;
    if descriptor_identity(&anchor.service_cgroup, FileType::Directory)?
        != anchor.service_cgroup_identity
    {
        return Err(WorkerSandboxError::Mismatch);
    }
    let cgroup_record = open_process_file(process_directory, "cgroup")?;
    ensure_procfs(&cgroup_record)?;
    let _ = descriptor_identity(&cgroup_record, FileType::RegularFile)?;
    let current_path = parse_unified_cgroup_path(&read_bounded_descriptor(
        &cgroup_record,
        MAX_PROC_CGROUP_BYTES,
    )?)?;
    if current_path != anchor.service_cgroup_path {
        return Err(WorkerSandboxError::Mismatch);
    }
    let current_service_cgroup = resolve_service_cgroup(&anchor.cgroup_root, &current_path)?;
    if descriptor_identity(&current_service_cgroup, FileType::Directory)?
        != anchor.service_cgroup_identity
    {
        return Err(WorkerSandboxError::Mismatch);
    }
    Ok(())
}

pub(super) fn current_network_namespace_identity()
-> Result<NetworkNamespaceIdentity, WorkerSandboxError> {
    let descriptor = open(
        "/proc/self/ns/net",
        OFlags::RDONLY | OFlags::CLOEXEC,
        Mode::empty(),
    )
    .map_err(rustix_io)?;
    namespace_identity(&descriptor)
}

pub(super) fn current_thread_seccomp_state() -> Result<LinuxSeccompState, WorkerSandboxError> {
    Ok(parse_process_status(&read_bounded(
        File::open("/proc/thread-self/status")?,
        MAX_PROC_STATUS_BYTES,
    )?)?
    .seccomp)
}

/// Requires the exact root/systemd privilege envelope used by the fixed live proof.
pub(super) fn validate_live_proof_parent_contract(
    required_group: u32,
) -> Result<(), WorkerSandboxError> {
    let status = parse_process_status(&read_bounded(
        File::open("/proc/thread-self/status")?,
        MAX_PROC_STATUS_BYTES,
    )?)?;
    validate_live_proof_parent_status(status, required_group)
}

fn validate_live_proof_parent_status(
    status: ParsedProcessStatus,
    required_group: u32,
) -> Result<(), WorkerSandboxError> {
    let expected_capabilities = LinuxCapabilitySnapshot {
        inheritable: HELPER_BOOTSTRAP_CAPABILITY_BITS,
        permitted: HELPER_BOOTSTRAP_CAPABILITY_BITS,
        effective: HELPER_BOOTSTRAP_CAPABILITY_BITS,
        bounding: HELPER_BOOTSTRAP_CAPABILITY_BITS,
        ambient: HELPER_BOOTSTRAP_CAPABILITY_BITS,
    };
    if status.pid != std::process::id()
        || status.uids != [0; 4]
        || status.gids != [required_group; 4]
        || status.supplementary_groups != SupplementaryGroups::Singleton(required_group)
        || !status.no_new_privileges
        || u32::from(status.seccomp.mode) != libc::SECCOMP_MODE_FILTER
        || status.seccomp.filter_count == 0
        || status.capabilities != expected_capabilities
    {
        return Err(WorkerSandboxError::Mismatch);
    }
    Ok(())
}

fn current_process_snapshot(
    parent_network_namespace: NetworkNamespaceIdentity,
) -> Result<WorkerSandboxSnapshot, WorkerSandboxError> {
    let worker_network_namespace = current_network_namespace_identity()?;
    let status = parse_process_status(&read_bounded(
        File::open("/proc/self/status")?,
        MAX_PROC_STATUS_BYTES,
    )?)?;
    let parent_pid = u32::try_from(getppid().as_raw()).map_err(|_| WorkerSandboxError::Invalid)?;
    if status.pid != std::process::id() || status.parent_pid != parent_pid {
        return Err(WorkerSandboxError::Mismatch);
    }
    let identity = exact_status_identity(status)?;
    let supplementary_groups_empty = getgroups().map_err(rustix_io)?.is_empty();
    if supplementary_groups_empty != status.supplementary_groups.is_empty() {
        return Err(WorkerSandboxError::Mismatch);
    }
    Ok(WorkerSandboxSnapshot {
        parent_network_namespace,
        worker_network_namespace,
        identity,
        supplementary_groups_empty,
        no_new_privileges: status.no_new_privileges,
        seccomp: status.seccomp,
        capabilities: status.capabilities,
    })
}

fn exact_status_identity(
    status: ParsedProcessStatus,
) -> Result<WorkerIdentity, WorkerSandboxError> {
    if status.uids.iter().any(|uid| *uid != status.uids[0])
        || status.gids.iter().any(|gid| *gid != status.gids[0])
    {
        return Err(WorkerSandboxError::Mismatch);
    }
    WorkerIdentity::new(status.uids[0], status.gids[0])
}

/// Kernel pins created immediately after spawn and retained until confirmed reap.
///
/// This value is owned only by `ProcessRetirement`. Moving a retirement record to the reaper also
/// moves its pidfd, anchored process-directory descriptor, and pinned network namespace.
pub(super) struct WorkerKernelPins {
    pidfd: OwnedFd,
    process_directory: OwnedFd,
    network_namespace: Option<OwnedFd>,
    network_namespace_identity: Option<NetworkNamespaceIdentity>,
    final_descriptor_directory: Option<OwnedFd>,
    recovery_anchor: PinnedWorkerRecoveryAnchor,
    recovery_anchor_protected_links_attested: bool,
    recovery_anchor_sealed: bool,
}

impl WorkerKernelPins {
    pub(super) fn pin_process(child: &Child) -> Result<Self, WorkerSandboxError> {
        let pid = Pid::from_child(child);
        let pidfd = pidfd_open(pid, PidfdFlags::empty()).map_err(rustix_io)?;
        let process_directory = open(
            format!("/proc/{}", child.id()),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(rustix_io)?;
        let recovery_anchor = capture_recovery_anchor(&process_directory, child.id())?;
        Ok(Self {
            pidfd,
            process_directory,
            network_namespace: None,
            network_namespace_identity: None,
            final_descriptor_directory: None,
            recovery_anchor,
            recovery_anchor_protected_links_attested: false,
            recovery_anchor_sealed: false,
        })
    }

    /// Attests and pins the child's fresh namespace before the child drops root identity.
    pub(super) fn pin_network_namespace_before_identity_drop(
        &mut self,
        parent_network_namespace: NetworkNamespaceIdentity,
        parent_seccomp: LinuxSeccompState,
        required_group: u32,
        parent_pid: u32,
        child_pid: u32,
    ) -> Result<NetworkNamespaceIdentity, WorkerSandboxError> {
        if !parent_network_namespace.is_valid()
            || self.network_namespace.is_some()
            || self.network_namespace_identity.is_some()
            || self.final_descriptor_directory.is_some()
            || self.recovery_anchor_protected_links_attested
            || self.recovery_anchor_sealed
        {
            return Err(WorkerSandboxError::Invalid);
        }
        self.ensure_alive()?;
        let (worker_network_namespace, status) =
            self.observe_and_pin_common(parent_pid, child_pid, true)?;
        validate_pre_identity_state(
            parent_network_namespace,
            worker_network_namespace,
            parent_seccomp,
            required_group,
            status,
        )?;
        // `exe` and `ns/cgroup` become unreadable to the capability-bounded parent when the child
        // changes uid/gid and Linux clears dumpability. Revalidate those magic links only here:
        // the independently observed worker filter already forbids re-exec and namespace changes,
        // while the child still has its pre-transition identity.
        verify_bootstrap_recovery_anchor(&self.process_directory, &self.recovery_anchor)?;
        self.ensure_alive()?;
        self.recovery_anchor_protected_links_attested = true;
        Ok(worker_network_namespace)
    }

    /// Observes final state through the process and namespace descriptors pinned before uid drop.
    pub(super) fn observe_and_pin(
        &mut self,
        parent_network_namespace: NetworkNamespaceIdentity,
        parent_seccomp: LinuxSeccompState,
        parent_pid: u32,
        child_pid: u32,
        identity: WorkerIdentity,
    ) -> Result<WorkerSandboxSnapshot, WorkerSandboxError> {
        let plan = WorkerSandboxPlan::production(parent_seccomp, identity)?;
        self.ensure_alive()?;
        if !self.recovery_anchor_protected_links_attested || self.recovery_anchor_sealed {
            return Err(WorkerSandboxError::Invalid);
        }
        let network_namespace = self
            .network_namespace
            .as_ref()
            .ok_or(WorkerSandboxError::Invalid)?;
        let worker_network_namespace = typed_network_namespace_identity(network_namespace)?;
        if self.network_namespace_identity != Some(worker_network_namespace) {
            return Err(WorkerSandboxError::Mismatch);
        }
        let descriptor_directory = self
            .final_descriptor_directory
            .take()
            .ok_or(WorkerSandboxError::Invalid)?;
        validate_exact_worker_descriptors(read_numeric_directory(descriptor_directory)?)?;
        let status = self.observe_status(parent_pid, child_pid)?;
        let snapshot = WorkerSandboxSnapshot {
            parent_network_namespace,
            worker_network_namespace,
            identity: exact_status_identity(status)?,
            supplementary_groups_empty: status.supplementary_groups.is_empty(),
            no_new_privileges: status.no_new_privileges,
            seccomp: status.seccomp,
            capabilities: status.capabilities,
        };
        plan.verify(snapshot)?;
        // Post-transition proof uses only retained protected descriptors plus procfs records which
        // remain readable without CAP_SYS_PTRACE. The pre-transition attestation and monotone
        // seccomp denials bind the protected magic links across the credential transition.
        attest_protected_magic_link_denials(&self.process_directory)?;
        verify_sealed_recovery_anchor(&self.process_directory, &self.recovery_anchor)?;
        self.ensure_alive()?;
        self.recovery_anchor_sealed = true;
        Ok(snapshot)
    }

    #[cfg(test)]
    pub(super) fn pin_network_namespace_before_identity_drop_fixture(
        &mut self,
        parent_pid: u32,
        child_pid: u32,
    ) -> Result<NetworkNamespaceIdentity, WorkerSandboxError> {
        if self.network_namespace.is_some()
            || self.network_namespace_identity.is_some()
            || self.final_descriptor_directory.is_some()
            || self.recovery_anchor_protected_links_attested
            || self.recovery_anchor_sealed
        {
            return Err(WorkerSandboxError::Invalid);
        }
        self.ensure_alive()?;
        let (worker_network_namespace, _) =
            self.observe_and_pin_common(parent_pid, child_pid, false)?;
        verify_bootstrap_recovery_anchor(&self.process_directory, &self.recovery_anchor)?;
        self.ensure_alive()?;
        self.recovery_anchor_protected_links_attested = true;
        Ok(worker_network_namespace)
    }

    #[cfg(test)]
    pub(super) fn observe_and_pin_fixture(
        &mut self,
        parent_pid: u32,
        child_pid: u32,
        fixture: WorkerSandboxSnapshot,
        parent_seccomp: LinuxSeccompState,
    ) -> Result<WorkerSandboxSnapshot, WorkerSandboxError> {
        let plan = WorkerSandboxPlan::production(parent_seccomp, fixture.identity)?;
        self.ensure_alive()?;
        if self.network_namespace.is_none()
            || !self.recovery_anchor_protected_links_attested
            || self.recovery_anchor_sealed
        {
            return Err(WorkerSandboxError::Invalid);
        }
        let descriptor_directory = self
            .final_descriptor_directory
            .take()
            .ok_or(WorkerSandboxError::Invalid)?;
        validate_exact_worker_descriptors(read_numeric_directory(descriptor_directory)?)?;
        let _ = self.observe_status(parent_pid, child_pid)?;
        plan.verify(fixture)?;
        verify_sealed_recovery_anchor(&self.process_directory, &self.recovery_anchor)?;
        self.ensure_alive()?;
        self.recovery_anchor_sealed = true;
        Ok(fixture)
    }

    pub(super) fn ensure_alive(&self) -> Result<(), WorkerSandboxError> {
        let mut descriptors = [PollFd::new(self.pidfd.as_fd(), PollFlags::POLLIN)];
        let ready = poll(&mut descriptors, 0_u8).map_err(nix_io)?;
        if ready != 0
            || descriptors[0]
                .revents()
                .is_some_and(|events| !events.is_empty())
        {
            return Err(WorkerSandboxError::Mismatch);
        }
        Ok(())
    }

    fn observe_status(
        &self,
        parent_pid: u32,
        child_pid: u32,
    ) -> Result<ParsedProcessStatus, WorkerSandboxError> {
        let status_descriptor = openat(
            &self.process_directory,
            "status",
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(rustix_io)?;
        let status = parse_process_status(&read_bounded(
            File::from(status_descriptor),
            MAX_PROC_STATUS_BYTES,
        )?)?;
        if status.pid != child_pid || status.parent_pid != parent_pid {
            return Err(WorkerSandboxError::Mismatch);
        }
        Ok(status)
    }

    fn observe_and_pin_common(
        &mut self,
        parent_pid: u32,
        child_pid: u32,
        require_single_task: bool,
    ) -> Result<(NetworkNamespaceIdentity, ParsedProcessStatus), WorkerSandboxError> {
        if self.network_namespace.is_some()
            || self.network_namespace_identity.is_some()
            || self.final_descriptor_directory.is_some()
        {
            return Err(WorkerSandboxError::Invalid);
        }
        let status = self.observe_status(parent_pid, child_pid)?;

        let descriptor_directory = openat(
            &self.process_directory,
            "fd",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(rustix_io)?;
        validate_exact_worker_descriptors(read_numeric_directory(descriptor_directory)?)?;
        self.final_descriptor_directory = Some(
            openat(
                &self.process_directory,
                "fd",
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .map_err(rustix_io)?,
        );

        let task_directory = openat(
            &self.process_directory,
            "task",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(rustix_io)?;
        let task_ids = read_numeric_directory(task_directory)?;
        if require_single_task {
            validate_exact_worker_tasks(&task_ids, child_pid)?;
        } else if !task_ids.contains(&child_pid) {
            return Err(WorkerSandboxError::Mismatch);
        }

        let network_namespace = openat(
            &self.process_directory,
            "ns/net",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .map_err(rustix_io)?;
        let worker_network_namespace = typed_network_namespace_identity(&network_namespace)?;
        self.network_namespace = Some(network_namespace);
        self.network_namespace_identity = Some(worker_network_namespace);
        Ok((worker_network_namespace, status))
    }

    pub(super) fn has_complete_pins(&self) -> bool {
        self.network_namespace.is_some()
            && self.network_namespace_identity.is_some()
            && self.recovery_anchor_protected_links_attested
            && self.recovery_anchor_sealed
    }

    /// Duplicates the retained worker network namespace into an independent affine call pin.
    ///
    /// The already-attested identity snapshot is copied without proof reads; the duplicate itself
    /// keeps that namespace alive until its planned call finishes or is rejected. Callers which
    /// hold a registry lock may use this only as an FD ownership operation. The affine pin's
    /// comparison methods re-read its typed identity, and process liveness is checked outside the
    /// registry lock.
    pub(super) fn duplicate_network_namespace_pin(
        &self,
    ) -> Result<PinnedWorkerNetworkNamespace, WorkerSandboxError> {
        let source = self
            .network_namespace
            .as_ref()
            .ok_or(WorkerSandboxError::Invalid)?;
        let identity = self
            .network_namespace_identity
            .ok_or(WorkerSandboxError::Invalid)?;
        let descriptor = duplicate_descriptor_cloexec(source)?;
        Ok(PinnedWorkerNetworkNamespace {
            descriptor,
            identity,
        })
    }

    /// Duplicates the complete authenticated process and namespace pin set into one affine owner.
    pub(super) fn duplicate_recovery_identity_pins(
        &self,
    ) -> Result<PinnedWorkerRecoveryIdentity, WorkerSandboxError> {
        if !self.recovery_anchor_protected_links_attested || !self.recovery_anchor_sealed {
            return Err(WorkerSandboxError::Invalid);
        }
        let network_namespace = self.duplicate_network_namespace_pin()?;
        let pidfd = duplicate_descriptor_cloexec(&self.pidfd)?;
        let process_directory = duplicate_descriptor_cloexec(&self.process_directory)?;
        Ok(PinnedWorkerRecoveryIdentity {
            pidfd,
            process_directory,
            network_namespace,
            recovery_anchor: self.recovery_anchor.duplicate()?,
        })
    }

    #[cfg(test)]
    pub(super) fn fixture() -> Self {
        let process_directory = open(
            format!("/proc/{}", std::process::id()),
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("pin current test process directory");
        let network_namespace = open(
            "/proc/thread-self/ns/net",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("pin current test network namespace");
        let network_namespace_identity = typed_network_namespace_identity(&network_namespace)
            .expect("type current test network namespace");
        let recovery_anchor = capture_recovery_anchor(&process_directory, std::process::id())
            .expect("pin current test recovery anchor");
        Self {
            pidfd: pidfd_open(rustix::process::getpid(), PidfdFlags::empty())
                .expect("pin current test process"),
            process_directory,
            network_namespace: Some(network_namespace),
            network_namespace_identity: Some(network_namespace_identity),
            final_descriptor_directory: None,
            recovery_anchor,
            recovery_anchor_protected_links_attested: true,
            recovery_anchor_sealed: true,
        }
    }
}

fn read_numeric_directory(directory: OwnedFd) -> Result<Vec<u32>, WorkerSandboxError> {
    let mut directory = Dir::new(directory).map_err(rustix_io)?;
    let mut descriptors = Vec::new();
    while let Some(entry) = directory.read() {
        if descriptors.len() >= MAX_DESCRIPTOR_AUDIT {
            return Err(WorkerSandboxError::Invalid);
        }
        let entry = entry.map_err(rustix_io)?;
        let name = entry.file_name().to_bytes();
        if matches!(name, b"." | b"..") {
            continue;
        }
        let name = std::str::from_utf8(name).map_err(|_| WorkerSandboxError::Invalid)?;
        descriptors.push(
            name.parse::<u32>()
                .map_err(|_| WorkerSandboxError::Invalid)?,
        );
    }
    Ok(descriptors)
}

fn validate_exact_worker_tasks(task_ids: &[u32], child_pid: u32) -> Result<(), WorkerSandboxError> {
    if task_ids != [child_pid] {
        return Err(WorkerSandboxError::Mismatch);
    }
    Ok(())
}

fn validate_exact_worker_descriptors(descriptors: Vec<u32>) -> Result<(), WorkerSandboxError> {
    let descriptor_count = descriptors.len();
    let observed = descriptors.into_iter().collect::<BTreeSet<_>>();
    if descriptor_count != 3
        || observed.len() != descriptor_count
        || observed
            != [
                1_u32,
                2_u32,
                u32::try_from(WORKER_CHANNEL_DESCRIPTOR).unwrap_or(0),
            ]
            .into_iter()
            .collect()
    {
        return Err(WorkerSandboxError::UnexpectedDescriptor);
    }
    Ok(())
}

trait SandboxKernel {
    fn initial_capabilities(&mut self) -> Result<CapabilitySets, WorkerSandboxError>;
    fn unshare_network(&mut self) -> Result<(), WorkerSandboxError>;
    fn observe_network_namespace(&mut self)
    -> Result<NetworkNamespaceIdentity, WorkerSandboxError>;
    fn install_no_new_privileges(&mut self) -> Result<(), WorkerSandboxError>;
    fn observe_initial_seccomp(&mut self) -> Result<LinuxSeccompState, WorkerSandboxError>;
    fn install_process_tree_filter(&mut self) -> Result<(), WorkerSandboxError>;
    fn clear_ambient(&mut self) -> Result<(), WorkerSandboxError>;
    fn last_capability(&mut self) -> Result<u32, WorkerSandboxError>;
    fn drop_bounding(&mut self, capability: u32) -> Result<(), WorkerSandboxError>;
    fn set_pre_identity_capabilities(&mut self) -> Result<(), WorkerSandboxError>;
    fn clear_supplementary_groups(&mut self) -> Result<(), WorkerSandboxError>;
    fn set_keep_capabilities_enabled(&mut self, enabled: bool) -> Result<(), WorkerSandboxError>;
    fn set_res_gid(&mut self, gid: u32) -> Result<(), WorkerSandboxError>;
    fn set_res_uid(&mut self, uid: u32) -> Result<(), WorkerSandboxError>;
    fn set_post_identity_capabilities(&mut self) -> Result<(), WorkerSandboxError>;
    fn keep_capabilities_enabled(&mut self) -> Result<bool, WorkerSandboxError>;
    fn set_exact_capabilities(&mut self) -> Result<(), WorkerSandboxError>;
    fn observe_final(
        &mut self,
        parent_network_namespace: NetworkNamespaceIdentity,
    ) -> Result<WorkerSandboxSnapshot, WorkerSandboxError>;
}

struct ProductionSandboxKernel;

impl SandboxKernel for ProductionSandboxKernel {
    fn initial_capabilities(&mut self) -> Result<CapabilitySets, WorkerSandboxError> {
        capabilities(None).map_err(rustix_io).map_err(Into::into)
    }

    fn unshare_network(&mut self) -> Result<(), WorkerSandboxError> {
        unshare(CloneFlags::CLONE_NEWNET)
            .map_err(nix_io)
            .map_err(Into::into)
    }

    fn observe_network_namespace(
        &mut self,
    ) -> Result<NetworkNamespaceIdentity, WorkerSandboxError> {
        current_network_namespace_identity()
    }

    fn install_no_new_privileges(&mut self) -> Result<(), WorkerSandboxError> {
        set_no_new_privs(true)
            .map_err(rustix_io)
            .map_err(Into::into)
    }

    fn observe_initial_seccomp(&mut self) -> Result<LinuxSeccompState, WorkerSandboxError> {
        current_thread_seccomp_state()
    }

    fn install_process_tree_filter(&mut self) -> Result<(), WorkerSandboxError> {
        install_worker_confinement_filter().map_err(Into::into)
    }

    fn clear_ambient(&mut self) -> Result<(), WorkerSandboxError> {
        clear_ambient_capability_set()
            .map_err(rustix_io)
            .map_err(Into::into)
    }

    fn last_capability(&mut self) -> Result<u32, WorkerSandboxError> {
        let bytes = read_bounded(
            File::open("/proc/sys/kernel/cap_last_cap")?,
            MAX_CAP_LAST_CAP_BYTES,
        )?;
        let value = std::str::from_utf8(&bytes)
            .map_err(|_| WorkerSandboxError::Invalid)?
            .strip_suffix('\n')
            .ok_or(WorkerSandboxError::Invalid)?;
        let value = parse_decimal_u32(value)?;
        if !(CAP_SYS_ADMIN..=63).contains(&value) {
            return Err(WorkerSandboxError::Invalid);
        }
        Ok(value)
    }

    fn drop_bounding(&mut self, capability: u32) -> Result<(), WorkerSandboxError> {
        let mask = CapabilitySet::from_bits_retain(1_u64 << capability);
        remove_capability_from_bounding_set(mask)
            .map_err(rustix_io)
            .map_err(Into::into)
    }

    fn set_pre_identity_capabilities(&mut self) -> Result<(), WorkerSandboxError> {
        let capabilities = CapabilitySet::SETGID
            | CapabilitySet::SETUID
            | CapabilitySet::SETPCAP
            | CapabilitySet::NET_ADMIN;
        set_capabilities(
            None,
            CapabilitySets {
                effective: capabilities,
                permitted: capabilities,
                inheritable: CapabilitySet::empty(),
            },
        )
        .map_err(rustix_io)
        .map_err(Into::into)
    }

    fn clear_supplementary_groups(&mut self) -> Result<(), WorkerSandboxError> {
        set_thread_groups(&[])
            .map_err(rustix_io)
            .map_err(Into::into)
    }

    fn set_keep_capabilities_enabled(&mut self, enabled: bool) -> Result<(), WorkerSandboxError> {
        set_keep_capabilities(enabled)
            .map_err(rustix_io)
            .map_err(Into::into)
    }

    fn set_res_gid(&mut self, gid: u32) -> Result<(), WorkerSandboxError> {
        let gid = Gid::from_raw(gid);
        set_thread_res_gid(gid, gid, gid)
            .map_err(rustix_io)
            .map_err(Into::into)
    }

    fn set_res_uid(&mut self, uid: u32) -> Result<(), WorkerSandboxError> {
        let uid = Uid::from_raw(uid);
        set_thread_res_uid(uid, uid, uid)
            .map_err(rustix_io)
            .map_err(Into::into)
    }

    fn set_post_identity_capabilities(&mut self) -> Result<(), WorkerSandboxError> {
        let transition = CapabilitySet::NET_ADMIN | CapabilitySet::SETPCAP;
        set_capabilities(
            None,
            CapabilitySets {
                effective: transition,
                permitted: transition,
                inheritable: CapabilitySet::empty(),
            },
        )
        .map_err(rustix_io)
        .map_err(Into::into)
    }

    fn keep_capabilities_enabled(&mut self) -> Result<bool, WorkerSandboxError> {
        get_keep_capabilities()
            .map_err(rustix_io)
            .map_err(Into::into)
    }

    fn set_exact_capabilities(&mut self) -> Result<(), WorkerSandboxError> {
        set_capabilities(
            None,
            CapabilitySets {
                effective: CapabilitySet::NET_ADMIN,
                permitted: CapabilitySet::NET_ADMIN,
                inheritable: CapabilitySet::empty(),
            },
        )
        .map_err(rustix_io)
        .map_err(Into::into)
    }

    fn observe_final(
        &mut self,
        parent_network_namespace: NetworkNamespaceIdentity,
    ) -> Result<WorkerSandboxSnapshot, WorkerSandboxError> {
        current_process_snapshot(parent_network_namespace)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
struct PreparedWorkerSandboxState {
    parent_network_namespace: NetworkNamespaceIdentity,
    worker_network_namespace: NetworkNamespaceIdentity,
    baseline_seccomp: LinuxSeccompState,
}

/// Affine child-side token proving NEWNET and monotonic confinement completed before identity drop.
pub(super) struct PreparedWorkerSandbox {
    state: PreparedWorkerSandboxState,
}

pub(super) fn begin_production_sandbox(
    parent_network_namespace: NetworkNamespaceIdentity,
) -> Result<PreparedWorkerSandbox, WorkerSandboxError> {
    Ok(PreparedWorkerSandbox {
        state: begin_sandbox(&mut ProductionSandboxKernel, parent_network_namespace)?,
    })
}

impl PreparedWorkerSandbox {
    /// Consumes the pre-identity phase after the parent acknowledges its namespace pin.
    pub(super) fn finish(
        self,
        identity: WorkerIdentity,
    ) -> Result<WorkerSandboxSnapshot, WorkerSandboxError> {
        let snapshot = finish_sandbox(&mut ProductionSandboxKernel, self.state, identity)?;
        prove_post_identity_denials()?;
        Ok(snapshot)
    }
}

fn prove_post_identity_denials() -> Result<(), WorkerSandboxError> {
    let parent = NixPid::from_raw(getppid().as_raw());
    if !matches!(kill(parent, None), Err(nix::errno::Errno::EPERM)) {
        return Err(WorkerSandboxError::Mismatch);
    }
    for path in [
        "/run/volparossa",
        "/run/volparossa/helper.cleanup-token",
        "/run/volparossa/helper.sock",
    ] {
        match open(
            path,
            OFlags::RDONLY | OFlags::CLOEXEC | OFlags::NOFOLLOW | OFlags::NONBLOCK,
            Mode::empty(),
        ) {
            Err(rustix::io::Errno::ACCESS) => {}
            Ok(_) | Err(_) => return Err(WorkerSandboxError::Mismatch),
        }
    }
    Ok(())
}

fn pre_identity_capabilities() -> CapabilitySet {
    CapabilitySet::SETGID
        | CapabilitySet::SETUID
        | CapabilitySet::SETPCAP
        | CapabilitySet::NET_ADMIN
}

fn bootstrap_capabilities() -> CapabilitySet {
    pre_identity_capabilities() | CapabilitySet::KILL | CapabilitySet::SYS_ADMIN
}

fn validate_pre_identity_state(
    parent_network_namespace: NetworkNamespaceIdentity,
    worker_network_namespace: NetworkNamespaceIdentity,
    parent_seccomp: LinuxSeccompState,
    required_group: u32,
    status: ParsedProcessStatus,
) -> Result<(), WorkerSandboxError> {
    let expected_capabilities = LinuxCapabilitySnapshot {
        inheritable: 0,
        permitted: pre_identity_capabilities().bits(),
        effective: pre_identity_capabilities().bits(),
        bounding: CAP_NET_ADMIN_BIT | CAP_SETPCAP_BIT,
        ambient: 0,
    };
    let required_seccomp = parent_seccomp.expected_after_worker_filter()?;
    if !parent_network_namespace.is_valid()
        || !worker_network_namespace.is_valid()
        || worker_network_namespace == parent_network_namespace
        || status.uids != [0; 4]
        || status.gids != [required_group; 4]
        || !status.no_new_privileges
        || status.seccomp != required_seccomp
        || status.capabilities != expected_capabilities
    {
        return Err(WorkerSandboxError::Mismatch);
    }
    Ok(())
}

fn verify_bootstrap_capabilities(capabilities: CapabilitySets) -> Result<(), WorkerSandboxError> {
    let required = bootstrap_capabilities();
    if !capabilities.effective.contains(required) || !capabilities.permitted.contains(required) {
        return Err(WorkerSandboxError::Mismatch);
    }
    Ok(())
}

fn verify_pre_identity_capabilities(
    capabilities: CapabilitySets,
) -> Result<(), WorkerSandboxError> {
    let expected = pre_identity_capabilities();
    if capabilities.effective != expected
        || capabilities.permitted != expected
        || !capabilities.inheritable.is_empty()
    {
        return Err(WorkerSandboxError::Mismatch);
    }
    Ok(())
}

fn begin_sandbox<K: SandboxKernel>(
    kernel: &mut K,
    parent_network_namespace: NetworkNamespaceIdentity,
) -> Result<PreparedWorkerSandboxState, WorkerSandboxError> {
    if !parent_network_namespace.is_valid() {
        return Err(WorkerSandboxError::Invalid);
    }
    verify_bootstrap_capabilities(kernel.initial_capabilities()?)?;
    kernel.unshare_network()?;
    let worker_network_namespace = kernel.observe_network_namespace()?;
    if !worker_network_namespace.is_valid() || worker_network_namespace == parent_network_namespace
    {
        return Err(WorkerSandboxError::Mismatch);
    }
    let baseline_seccomp = kernel.observe_initial_seccomp()?;
    kernel.clear_ambient()?;
    let last_capability = kernel.last_capability()?;
    for capability in 0..=last_capability {
        if capability != CAP_NET_ADMIN && capability != CAP_SETPCAP {
            kernel.drop_bounding(capability)?;
        }
    }
    kernel.set_pre_identity_capabilities()?;
    verify_pre_identity_capabilities(kernel.initial_capabilities()?)?;
    kernel.install_no_new_privileges()?;
    kernel.install_process_tree_filter()?;
    Ok(PreparedWorkerSandboxState {
        parent_network_namespace,
        worker_network_namespace,
        baseline_seccomp,
    })
}

fn finish_sandbox<K: SandboxKernel>(
    kernel: &mut K,
    prepared: PreparedWorkerSandboxState,
    identity: WorkerIdentity,
) -> Result<WorkerSandboxSnapshot, WorkerSandboxError> {
    verify_pre_identity_capabilities(kernel.initial_capabilities()?)?;
    if kernel.observe_network_namespace()? != prepared.worker_network_namespace {
        return Err(WorkerSandboxError::Mismatch);
    }
    let plan = WorkerSandboxPlan::production(prepared.baseline_seccomp, identity)?;
    kernel.clear_supplementary_groups()?;
    kernel.set_keep_capabilities_enabled(true)?;
    kernel.set_res_gid(identity.gid)?;
    kernel.set_res_uid(identity.uid)?;
    kernel.set_post_identity_capabilities()?;
    kernel.set_keep_capabilities_enabled(false)?;
    if kernel.keep_capabilities_enabled()? {
        return Err(WorkerSandboxError::Mismatch);
    }
    // CAP_SETPCAP is deliberately the final bounding-set removal. It remains effective until the
    // subsequent capset atomically reduces effective/permitted to CAP_NET_ADMIN.
    kernel.drop_bounding(CAP_SETPCAP)?;
    kernel.set_exact_capabilities()?;
    let snapshot = kernel.observe_final(prepared.parent_network_namespace)?;
    plan.verify(snapshot)?;
    Ok(snapshot)
}

fn rustix_io(error: rustix::io::Errno) -> io::Error {
    io::Error::from_raw_os_error(error.raw_os_error())
}

fn nix_io(error: nix::errno::Errno) -> io::Error {
    io::Error::from_raw_os_error(error as i32)
}

/// Verifies the child-visible descriptor set after exec and before authentication or kernel work.
///
/// The `/proc/self/fd` iterator owns a transient descriptor. It is dropped before symlink probes;
/// disappeared entries are ignored, while every still-open descriptor must be explicitly allowed.
pub(super) fn validate_post_exec_descriptor_allowlist(
    allowed_descriptors: &[i32],
) -> Result<(), WorkerSandboxError> {
    if allowed_descriptors.is_empty()
        || allowed_descriptors.iter().any(|descriptor| *descriptor < 0)
    {
        return Err(WorkerSandboxError::Invalid);
    }
    let allowed = allowed_descriptors
        .iter()
        .map(|descriptor| u32::try_from(*descriptor).map_err(|_| WorkerSandboxError::Invalid))
        .collect::<Result<BTreeSet<_>, _>>()?;
    if allowed.len() != allowed_descriptors.len() {
        return Err(WorkerSandboxError::Invalid);
    }

    let mut observed = Vec::new();
    {
        let entries = fs::read_dir("/proc/self/fd")?;
        for entry in entries {
            if observed.len() >= MAX_DESCRIPTOR_AUDIT {
                return Err(WorkerSandboxError::Invalid);
            }
            let descriptor = entry?
                .file_name()
                .to_str()
                .ok_or(WorkerSandboxError::Invalid)?
                .parse::<u32>()
                .map_err(|_| WorkerSandboxError::Invalid)?;
            observed.push(descriptor);
        }
    }
    observed.sort_unstable();
    if observed.windows(2).any(|pair| pair[0] == pair[1]) {
        return Err(WorkerSandboxError::Invalid);
    }

    for descriptor in observed {
        match fs::read_link(format!("/proc/self/fd/{descriptor}")) {
            Ok(_) if !allowed.contains(&descriptor) => {
                return Err(WorkerSandboxError::UnexpectedDescriptor);
            }
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {}
            Err(error) => return Err(WorkerSandboxError::Io(error)),
        }
    }
    for descriptor in allowed {
        match fs::read_link(format!("/proc/self/fd/{descriptor}")) {
            Ok(_) => {}
            Err(error) if error.kind() == io::ErrorKind::NotFound => {
                return Err(WorkerSandboxError::MissingDescriptor);
            }
            Err(error) => return Err(WorkerSandboxError::Io(error)),
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const PROTECTED_LINK_ACCESS_FIXTURE: &str = "VOLPAROSSA_TEST_RECOVERY_PROTECTED_LINK_ACCESS";

    fn worker_identity() -> WorkerIdentity {
        WorkerIdentity::fixture(987, 988)
    }

    fn production_seccomp_baseline() -> LinuxSeccompState {
        LinuxSeccompState::fixture(
            u8::try_from(libc::SECCOMP_MODE_FILTER).expect("seccomp mode fits u8"),
            3,
        )
    }

    fn production_snapshot() -> WorkerSandboxSnapshot {
        WorkerSandboxSnapshot::fixture(
            NetworkNamespaceIdentity::fixture(1, 10),
            NetworkNamespaceIdentity::fixture(1, 11),
            worker_identity(),
            true,
            true,
            LinuxSeccompState::fixture(
                u8::try_from(libc::SECCOMP_MODE_FILTER).expect("seccomp mode fits u8"),
                4,
            ),
            LinuxCapabilitySnapshot::fixture(
                0,
                CAP_NET_ADMIN_BIT,
                CAP_NET_ADMIN_BIT,
                CAP_NET_ADMIN_BIT,
                0,
            ),
        )
    }

    fn proof() -> SandboxProofRecord {
        SandboxProofRecord::fixture([7; 16], 9, [11; 32], 42, 43, production_snapshot())
    }

    #[test]
    fn production_plan_requires_newnet_nnp_seccomp_and_exact_capabilities() {
        let plan = WorkerSandboxPlan::production(production_seccomp_baseline(), worker_identity())
            .expect("plan");
        let valid = production_snapshot();
        assert!(plan.verify(valid).is_ok());

        let mut invalid = valid;
        invalid.worker_network_namespace = invalid.parent_network_namespace;
        assert!(plan.verify(invalid).is_err());
        let mut invalid = valid;
        invalid.identity = WorkerIdentity::fixture(989, 988);
        assert!(plan.verify(invalid).is_err());
        let mut invalid = valid;
        invalid.supplementary_groups_empty = false;
        assert!(plan.verify(invalid).is_err());
        let mut invalid = valid;
        invalid.no_new_privileges = false;
        assert!(plan.verify(invalid).is_err());
        for seccomp in [
            LinuxSeccompState::fixture(0, 0),
            LinuxSeccompState::fixture(2, 3),
            LinuxSeccompState::fixture(2, 5),
        ] {
            let mut invalid = valid;
            invalid.seccomp = seccomp;
            assert!(plan.verify(invalid).is_err());
        }

        for invalid_baseline in [
            LinuxSeccompState::fixture(0, 1),
            LinuxSeccompState::fixture(1, 0),
            LinuxSeccompState::fixture(2, 0),
            LinuxSeccompState::fixture(2, u32::MAX),
        ] {
            assert!(WorkerSandboxPlan::production(invalid_baseline, worker_identity()).is_err());
        }

        let zero_baseline = LinuxSeccompState::fixture(0, 0);
        let mut first_filter = valid;
        first_filter.seccomp = LinuxSeccompState::fixture(2, 1);
        WorkerSandboxPlan::production(zero_baseline, worker_identity())
            .expect("unfiltered baseline accepts one worker filter")
            .verify(first_filter)
            .expect("0/0 baseline must become filter mode 2/count 1");
        for capabilities in [
            LinuxCapabilitySnapshot::fixture(
                1,
                CAP_NET_ADMIN_BIT,
                CAP_NET_ADMIN_BIT,
                CAP_NET_ADMIN_BIT,
                0,
            ),
            LinuxCapabilitySnapshot::fixture(0, 0, CAP_NET_ADMIN_BIT, CAP_NET_ADMIN_BIT, 0),
            LinuxCapabilitySnapshot::fixture(0, CAP_NET_ADMIN_BIT, 0, CAP_NET_ADMIN_BIT, 0),
            LinuxCapabilitySnapshot::fixture(
                0,
                CAP_NET_ADMIN_BIT,
                CAP_NET_ADMIN_BIT,
                CAP_NET_ADMIN_BIT | 1,
                0,
            ),
            LinuxCapabilitySnapshot::fixture(
                0,
                CAP_NET_ADMIN_BIT,
                CAP_NET_ADMIN_BIT,
                CAP_NET_ADMIN_BIT,
                1,
            ),
        ] {
            let mut invalid = valid;
            invalid.capabilities = capabilities;
            assert!(plan.verify(invalid).is_err());
        }
    }

    #[test]
    fn duplicated_worker_namespace_pin_is_typed_exact_and_survives_source_owner_drop() {
        let pins = WorkerKernelPins::fixture();
        let pin = pins
            .duplicate_network_namespace_pin()
            .expect("duplicate current test network namespace pin");
        let original_identity = pin.identity_for_test();
        assert!(original_identity.is_valid());
        assert_eq!(
            namespace_type(&pin.descriptor).expect("query duplicate namespace type"),
            libc::CLONE_NEWNET
        );
        let descriptor_flags = nix::fcntl::FdFlag::from_bits_truncate(
            nix::fcntl::fcntl(&pin.descriptor, nix::fcntl::FcntlArg::F_GETFD)
                .expect("read duplicate descriptor flags"),
        );
        assert!(descriptor_flags.contains(nix::fcntl::FdFlag::FD_CLOEXEC));

        drop(pins);
        let current = open(
            "/proc/self/ns/net",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open current network namespace after source drop");
        assert!(
            pin.matches_descriptor(&current)
                .expect("compare retained exact namespace")
        );
        assert_eq!(pin.identity_for_test(), original_identity);

        let wrong_type = open(
            "/proc/self/ns/user",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open current user namespace");
        assert!(pin.matches_descriptor(&wrong_type).is_err());
    }

    #[test]
    fn duplicating_worker_namespace_pin_does_not_probe_process_liveness() {
        let mut pins = WorkerKernelPins::fixture();
        pins.pidfd = File::open("/dev/null")
            .expect("open a deliberately non-pidfd descriptor")
            .into();
        assert!(
            pins.ensure_alive().is_err(),
            "fixture must fail if the namespace-only operation accidentally probes liveness"
        );

        let pin = pins
            .duplicate_network_namespace_pin()
            .expect("namespace ownership is independent of process probing");
        let current = open(
            "/proc/self/ns/net",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open current network namespace");
        assert!(
            pin.matches_descriptor(&current)
                .expect("compare independently retained namespace")
        );
    }

    fn process_stat(pid: u32, command: &str, start_ticks: &str) -> Vec<u8> {
        format!("{pid} ({command}) S 1 1 1 0 -1 4194304 1 0 0 0 1 1 0 0 20 0 1 0 {start_ticks}\n")
            .into_bytes()
    }

    #[test]
    fn recovery_boot_id_parser_is_canonical_exact_and_nonzero() {
        let canonical = b"00112233-4455-6677-8899-aabbccddeeff\n";
        assert_eq!(
            parse_boot_id(canonical).expect("canonical boot id"),
            [
                0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd,
                0xee, 0xff,
            ]
        );
        for invalid in [
            b"00000000-0000-0000-0000-000000000000\n".as_slice(),
            b"00112233-4455-6677-8899-AABBCCDDEEFF\n",
            b"001122334455-6677-8899-aabbccddeeff\n",
            b"00112233-4455-6677-8899-aabbccddeeff",
            b"00112233-4455-6677-8899-aabbccddeeff\n\n",
        ] {
            assert!(parse_boot_id(invalid).is_err());
        }
    }

    #[test]
    fn recovery_process_stat_parser_binds_pid_start_ticks_and_weird_comm() {
        let pid = NonZeroU32::new(43).expect("nonzero pid");
        assert_eq!(
            parse_process_start_ticks(&process_stat(43, "worker) name", "987654"), pid)
                .expect("bounded proc stat"),
            NonZeroU64::new(987_654).expect("nonzero ticks")
        );
        for invalid in [
            process_stat(44, "worker", "987654"),
            process_stat(43, "worker", "0"),
            process_stat(43, "worker", "0987654"),
            process_stat(43, "sixteen-byte-name", "987654"),
            b"43 (worker) S 1 1 1\n".to_vec(),
            process_stat(43, "worker", "18446744073709551616"),
            vec![b'x'; MAX_PROC_STAT_BYTES + 1],
        ] {
            assert!(parse_process_start_ticks(&invalid, pid).is_err());
        }
    }

    #[test]
    fn unified_cgroup_parser_rejects_ambiguity_and_traversal() {
        assert_eq!(
            parse_unified_cgroup_path(b"0::/\n").expect("root cgroup"),
            Box::<[u8]>::from(b"/".as_slice())
        );
        assert_eq!(
            parse_unified_cgroup_path(b"0::/system.slice/volparossa-helper.service\n")
                .expect("systemd service cgroup"),
            Box::<[u8]>::from(b"/system.slice/volparossa-helper.service".as_slice())
        );
        for invalid in [
            b"1:name=/legacy\n".as_slice(),
            b"0::relative\n",
            b"0::/a\n0::/b\n",
            b"0::/a/../b\n",
            b"0::/a/./b\n",
            b"0::/a//b\n",
            b"0::/a/\n",
            b"0::/system.slice/volparossa-helper.service (deleted)\n",
            b"0::/a\0b\n",
        ] {
            assert!(parse_unified_cgroup_path(invalid).is_err());
        }
        let oversized_component = [
            b"0::/".as_slice(),
            vec![b'x'; MAX_CGROUP_COMPONENT_BYTES + 1].as_slice(),
            b"\n",
        ]
        .concat();
        assert!(parse_unified_cgroup_path(&oversized_component).is_err());
        let too_many_components = [
            b"0::/".as_slice(),
            vec![b'a'; MAX_CGROUP_COMPONENTS * 2 + 1].as_slice(),
            b"\n",
        ]
        .concat();
        let too_many_components = too_many_components
            .into_iter()
            .enumerate()
            .map(|(index, byte)| {
                if index >= 4 && index % 2 == 1 && byte == b'a' {
                    b'/'
                } else {
                    byte
                }
            })
            .collect::<Vec<_>>();
        assert!(parse_unified_cgroup_path(&too_many_components).is_err());
    }

    #[test]
    fn recovery_reads_are_bounded_segmented_and_restart_at_offset_zero() {
        use std::io::Write as _;

        let mut file = tempfile::tempfile().expect("temporary recovery evidence");
        let evidence = vec![b'x'; 2 * 1_024 + 17];
        file.write_all(&evidence).expect("write segmented evidence");
        assert_eq!(
            read_bounded_descriptor(&file, evidence.len()).expect("segmented pread"),
            evidence
        );
        assert_eq!(
            read_bounded_descriptor(&file, evidence.len()).expect("repeat from offset zero"),
            evidence
        );
        assert!(read_bounded_descriptor(&file, evidence.len() - 1).is_err());
    }

    #[test]
    fn protected_link_access_transition_child_fixture() {
        use std::io::{Read as _, Write as _};

        if std::env::var_os(PROTECTED_LINK_ACCESS_FIXTURE).is_none() {
            return;
        }

        let mut control = [0_u8; 1];
        io::stderr()
            .write_all(b"P")
            .expect("publish pre-transition readiness");
        io::stderr().flush().expect("flush readiness");
        io::stdin()
            .read_exact(&mut control)
            .expect("receive dumpability transition");
        nix::sys::prctl::set_dumpable(false).expect("clear child dumpability");
        io::stderr()
            .write_all(b"D")
            .expect("publish protected-access transition");
        io::stderr().flush().expect("flush transition");
        let _ = io::stdin().read_exact(&mut control);
    }

    #[test]
    fn dumpability_boundary_uses_retained_anchor_without_reopening_magic_links() {
        use std::{
            io::{Read as _, Write as _},
            process::{Command, Stdio},
        };

        let mut child = Command::new("/proc/self/exe")
            .arg("--exact")
            .arg("worker_sandbox::tests::protected_link_access_transition_child_fixture")
            .arg("--nocapture")
            .env(PROTECTED_LINK_ACCESS_FIXTURE, "1")
            .stdin(Stdio::piped())
            .stdout(Stdio::null())
            .stderr(Stdio::piped())
            .spawn()
            .expect("spawn exact recovery access fixture");
        let mut child_input = child.stdin.take().expect("fixture control input");
        let mut child_evidence = child.stderr.take().expect("fixture evidence output");
        let mut signal = [0_u8; 1];
        child_evidence
            .read_exact(&mut signal)
            .expect("receive pre-transition readiness");
        assert_eq!(signal, *b"P");

        let pins = WorkerKernelPins::pin_process(&child).expect("capture pre-transition anchor");
        child_input
            .write_all(b"D")
            .expect("request dumpability transition");
        child_evidence
            .read_exact(&mut signal)
            .expect("receive protected-access transition");
        assert_eq!(signal, *b"D");

        let error =
            verify_bootstrap_recovery_anchor(&pins.process_directory, &pins.recovery_anchor)
                .expect_err("protected proc magic links must no longer be reopenable");
        assert!(matches!(
            error,
            WorkerSandboxError::Io(ref error)
                if error.kind() == io::ErrorKind::PermissionDenied
                    && error.raw_os_error() == Some(libc::EACCES)
        ));
        attest_protected_magic_link_denials(&pins.process_directory)
            .expect("both protected magic links deny exact EACCES");
        verify_sealed_recovery_anchor(&pins.process_directory, &pins.recovery_anchor)
            .expect("retained descriptors and readable records remain exact");

        child_input.write_all(b"X").expect("release access fixture");
        assert!(child.wait().expect("wait for access fixture").success());
    }

    #[test]
    fn cgroup_resolution_refuses_symlinks_and_parent_escape() {
        use std::os::unix::fs::symlink;

        let temporary = tempfile::tempdir().expect("temporary cgroup resolver root");
        fs::create_dir(temporary.path().join("target")).expect("create target");
        symlink("target", temporary.path().join("link")).expect("create symlink");
        let root = open(
            temporary.path(),
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("open resolver root");
        assert!(resolve_service_cgroup(&root, b"/target").is_ok());
        assert!(resolve_service_cgroup(&root, b"/link").is_err());
        assert!(resolve_service_cgroup(&root, b"/../target").is_err());
    }

    #[test]
    fn complete_recovery_anchor_is_repeatable_affine_and_exact() {
        let mut unsealed = WorkerKernelPins::fixture();
        unsealed.recovery_anchor_sealed = false;
        assert!(unsealed.duplicate_recovery_identity_pins().is_err());

        let pins = WorkerKernelPins::fixture();
        let recovery = pins
            .duplicate_recovery_identity_pins()
            .expect("duplicate full recovery pins");
        let first = recovery
            .verified_recovery_anchor_parts()
            .expect("first complete proof");
        let second = recovery
            .verified_recovery_anchor_parts()
            .expect("repeat proof from offset zero");
        let (third, custody) = recovery
            .verified_anchor_with_restart_custody()
            .expect("derive restart custody only after full proof");
        assert_eq!(first, second);
        assert_eq!(second, third);
        assert_eq!(first.pid.get(), std::process::id());
        assert_ne!(first.boot_id, [0; 16]);
        assert_ne!(first.process_start_ticks.get(), 0);
        assert_ne!(first.executable_device.get(), 0);
        assert_ne!(first.executable_inode.get(), 0);
        assert_ne!(first.service_cgroup_inode.get(), 0);

        drop(pins);
        assert_eq!(
            recovery
                .verified_recovery_anchor_parts()
                .expect("duplicate owns every retained pin after source drop"),
            first
        );
        drop(recovery);
        {
            use std::os::fd::AsRawFd as _;

            assert_ne!(
                custody.borrowed_pidfd().as_raw_fd(),
                custody.borrowed_network_namespace().as_raw_fd(),
                "role-specific custody borrows must remain distinct"
            );
        }
        custody
            .ensure_live_and_namespace_matches_anchor(first)
            .expect("pidfd and namespace custody survive all pre-arm proof owners");
        assert_eq!(
            format!("{custody:?}"),
            "PinnedWorkerRestartCustody(<redacted>)"
        );
    }

    #[test]
    fn restart_custody_rejects_wrong_namespace_and_exited_pidfd() {
        let recovery = WorkerKernelPins::fixture()
            .duplicate_recovery_identity_pins()
            .expect("duplicate anchor");
        let (anchor, mut custody) = recovery
            .verified_anchor_with_restart_custody()
            .expect("derive custody candidate");
        let mut wrong_namespace = anchor;
        let changed_inode = if anchor.network_namespace_inode.get() == u64::MAX {
            anchor.network_namespace_inode.get() - 1
        } else {
            anchor.network_namespace_inode.get() + 1
        };
        wrong_namespace.network_namespace_inode =
            NonZeroU64::new(changed_inode).expect("changed inode remains nonzero");
        assert!(
            custody
                .ensure_live_and_namespace_matches_anchor(wrong_namespace)
                .is_err()
        );

        let mut child = std::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn bounded custody liveness fixture");
        custody.pidfd =
            pidfd_open(Pid::from_child(&child), PidfdFlags::empty()).expect("pin child pidfd");
        custody
            .ensure_live_and_namespace_matches_anchor(anchor)
            .expect("liveness subcheck accepts live fd; construction supplies causality");
        child.kill().expect("kill custody liveness fixture");
        child.wait().expect("reap custody liveness fixture");
        assert!(
            custody
                .ensure_live_and_namespace_matches_anchor(anchor)
                .is_err()
        );
    }

    #[test]
    fn complete_recovery_anchor_rejects_each_wrong_retained_object() {
        let mut wrong_boot = WorkerKernelPins::fixture()
            .duplicate_recovery_identity_pins()
            .expect("duplicate anchor");
        wrong_boot.recovery_anchor.boot_id_file = File::open("/dev/null")
            .expect("open wrong boot object")
            .into();
        assert!(wrong_boot.verified_recovery_anchor_parts().is_err());

        let mut wrong_process_directory = WorkerKernelPins::fixture()
            .duplicate_recovery_identity_pins()
            .expect("duplicate anchor");
        wrong_process_directory.process_directory = open(
            "/tmp",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("open wrong process directory");
        assert!(
            wrong_process_directory
                .verified_recovery_anchor_parts()
                .is_err()
        );

        let mut wrong_start_ticks = WorkerKernelPins::fixture()
            .duplicate_recovery_identity_pins()
            .expect("duplicate anchor");
        wrong_start_ticks.recovery_anchor.process_start_ticks = NonZeroU64::new(
            wrong_start_ticks
                .recovery_anchor
                .process_start_ticks
                .get()
                .checked_add(1)
                .expect("fixture ticks increment"),
        )
        .expect("nonzero fixture ticks");
        assert!(wrong_start_ticks.verified_recovery_anchor_parts().is_err());

        let mut wrong_executable = WorkerKernelPins::fixture()
            .duplicate_recovery_identity_pins()
            .expect("duplicate anchor");
        wrong_executable.recovery_anchor.executable =
            open("/dev/null", OFlags::PATH | OFlags::CLOEXEC, Mode::empty())
                .expect("open wrong executable object");
        assert!(wrong_executable.verified_recovery_anchor_parts().is_err());

        let mut wrong_cgroup_namespace = WorkerKernelPins::fixture()
            .duplicate_recovery_identity_pins()
            .expect("duplicate anchor");
        wrong_cgroup_namespace.recovery_anchor.cgroup_namespace = open(
            "/proc/self/ns/net",
            OFlags::RDONLY | OFlags::CLOEXEC,
            Mode::empty(),
        )
        .expect("open wrong namespace type");
        assert!(
            wrong_cgroup_namespace
                .verified_recovery_anchor_parts()
                .is_err()
        );

        let mut wrong_cgroup = WorkerKernelPins::fixture()
            .duplicate_recovery_identity_pins()
            .expect("duplicate anchor");
        wrong_cgroup.recovery_anchor.service_cgroup = open(
            "/tmp",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("open wrong cgroup object");
        assert!(wrong_cgroup.verified_recovery_anchor_parts().is_err());

        let mut wrong_cgroup_root = WorkerKernelPins::fixture()
            .duplicate_recovery_identity_pins()
            .expect("duplicate anchor");
        wrong_cgroup_root.recovery_anchor.cgroup_root = open(
            "/tmp",
            OFlags::PATH | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .expect("open wrong cgroup root");
        assert!(wrong_cgroup_root.verified_recovery_anchor_parts().is_err());

        let mut wrong_cgroup_path = WorkerKernelPins::fixture()
            .duplicate_recovery_identity_pins()
            .expect("duplicate anchor");
        wrong_cgroup_path.recovery_anchor.service_cgroup_path =
            Box::from(b"/definitely-not-the-service-cgroup".as_slice());
        assert!(wrong_cgroup_path.verified_recovery_anchor_parts().is_err());
    }

    #[test]
    fn recovery_pidfd_reports_real_child_exit() {
        let mut child = std::process::Command::new("/bin/sleep")
            .arg("60")
            .spawn()
            .expect("spawn bounded liveness fixture");
        let mut recovery = WorkerKernelPins::fixture()
            .duplicate_recovery_identity_pins()
            .expect("duplicate anchor");
        recovery.pidfd =
            pidfd_open(Pid::from_child(&child), PidfdFlags::empty()).expect("pin child pidfd");
        recovery.ensure_alive().expect("child alive");
        child.kill().expect("kill fixture child");
        child.wait().expect("reap fixture child");
        assert!(recovery.ensure_alive().is_err());
    }

    #[test]
    fn proof_is_canonical_and_one_expectation_binds_every_bootstrap_field() {
        let proof = proof();
        let encoded = proof.encode();
        assert_eq!(SandboxProofRecord::LENGTH, 192);
        assert_eq!(&encoded[0..32], SANDBOX_PROOF_DOMAIN);
        assert_eq!(&encoded[32..36], &SANDBOX_PROOF_VERSION.to_be_bytes());
        assert_eq!(&encoded[36..52], &[7; 16]);
        assert_eq!(&encoded[52..60], &9_u64.to_be_bytes());
        assert_eq!(&encoded[60..92], &[11; 32]);
        assert_eq!(&encoded[92..96], &42_u32.to_be_bytes());
        assert_eq!(&encoded[96..100], &43_u32.to_be_bytes());
        assert_eq!(&encoded[132..136], &worker_identity().uid.to_be_bytes());
        assert_eq!(&encoded[136..140], &worker_identity().gid.to_be_bytes());
        assert_eq!(encoded[140], 1);
        assert_eq!(encoded[141], 1);
        assert_eq!(encoded[142], 2);
        assert_eq!(encoded[143], 0);
        assert_eq!(&encoded[144..148], &4_u32.to_be_bytes());
        assert_eq!(&encoded[148..152], &[0; 4]);
        assert_eq!(&encoded[152..160], &0_u64.to_be_bytes());
        assert_eq!(&encoded[160..168], &CAP_NET_ADMIN_BIT.to_be_bytes());
        assert_eq!(&encoded[168..176], &CAP_NET_ADMIN_BIT.to_be_bytes());
        assert_eq!(&encoded[176..184], &CAP_NET_ADMIN_BIT.to_be_bytes());
        assert_eq!(&encoded[184..192], &0_u64.to_be_bytes());
        assert_eq!(
            SandboxProofRecord::decode(&encoded).expect("canonical"),
            proof
        );
        SandboxProofExpectation::fixture(
            proof.context_id,
            proof.generation,
            proof.challenge,
            proof.parent_pid,
            proof.child_pid,
            proof.snapshot,
        )
        .verify_once(
            &encoded,
            WorkerSandboxPlan::production(production_seccomp_baseline(), worker_identity())
                .expect("plan"),
        )
        .expect("exact fake proof");

        for index in [
            0, 32, 36, 52, 60, 92, 96, 100, 108, 116, 124, 132, 136, 140, 141, 142, 143, 144, 148,
            152, 160, 168, 176, 184,
        ] {
            let mut changed = encoded;
            changed[index] ^= 1;
            let expectation = SandboxProofExpectation::fixture(
                proof.context_id,
                proof.generation,
                proof.challenge,
                proof.parent_pid,
                proof.child_pid,
                proof.snapshot,
            );
            assert!(
                expectation
                    .verify_once(
                        &changed,
                        WorkerSandboxPlan::production(
                            production_seccomp_baseline(),
                            worker_identity(),
                        )
                        .expect("plan"),
                    )
                    .is_err()
            );
        }
        assert!(SandboxProofRecord::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut retired_v4 = encoded;
        retired_v4[27] = b'4';
        retired_v4[32..36].copy_from_slice(&4_u32.to_be_bytes());
        assert!(SandboxProofRecord::decode(&retired_v4).is_err());
        for range in [132..136, 136..140] {
            let mut reserved = encoded;
            reserved[range].copy_from_slice(&SYSTEMD_RESERVED_ID.to_be_bytes());
            assert!(SandboxProofRecord::decode(&reserved).is_err());
        }
    }

    fn status() -> Vec<u8> {
        concat!(
            "Name:\tworker\n",
            "Pid:\t43\n",
            "PPid:\t42\n",
            "Uid:\t987\t987\t987\t987\n",
            "Gid:\t988\t988\t988\t988\n",
            "Groups:\t\n",
            "CapInh:\t0000000000000000\n",
            "CapPrm:\t0000000000001000\n",
            "CapEff:\t0000000000001000\n",
            "CapBnd:\t0000000000001000\n",
            "CapAmb:\t0000000000000000\n",
            "NoNewPrivs:\t1\n",
            "Seccomp:\t2\n",
            "Seccomp_filters:\t4\n",
        )
        .as_bytes()
        .to_vec()
    }

    #[test]
    fn proc_status_parser_is_bounded_exact_and_duplicate_rejecting() {
        let parsed = parse_process_status(&status()).expect("strict status");
        assert_eq!(parsed.pid, 43);
        assert_eq!(parsed.parent_pid, 42);
        assert_eq!(
            exact_status_identity(parsed).expect("identity"),
            worker_identity()
        );
        assert_eq!(parsed.supplementary_groups, SupplementaryGroups::Empty);
        assert!(parsed.no_new_privileges);
        assert_eq!(parsed.seccomp, production_snapshot().seccomp);
        assert_eq!(parsed.capabilities, production_snapshot().capabilities);
        assert_eq!(
            parse_supplementary_groups("777").expect("singleton group"),
            SupplementaryGroups::Singleton(777)
        );
        assert_eq!(
            parse_supplementary_groups("777 888").expect("multiple groups"),
            SupplementaryGroups::Multiple
        );
        for invalid_groups in ["2 1", "1 1", "01"] {
            assert!(parse_supplementary_groups(invalid_groups).is_err());
        }
        let too_many_groups = (0..=256)
            .map(|group| group.to_string())
            .collect::<Vec<_>>()
            .join(" ");
        assert!(parse_supplementary_groups(&too_many_groups).is_err());

        for changed in [
            b"Pid:\t43\n".to_vec(),
            [status(), b"Uid:\t987\t987\t987\t987\n".to_vec()].concat(),
            [status(), b"CapEff:\t0000000000001000\n".to_vec()].concat(),
            [status(), b"Seccomp:\t2\n".to_vec()].concat(),
            [status(), b"Seccomp_filters:\t4\n".to_vec()].concat(),
            status().replace_ascii(b"Seccomp:\t2\n", b""),
            status().replace_ascii(b"Seccomp_filters:\t4\n", b""),
            status().replace_ascii(b"NoNewPrivs:\t1", b"NoNewPrivs:\t2"),
            status().replace_ascii(b"Uid:\t987\t987\t987\t987", b"Uid:\t987\t987\t987"),
            status().replace_ascii(b"Gid:\t988\t988\t988\t988", b"Gid:\t988\t988\t988\t0988"),
            status().replace_ascii(b"Groups:\t", b"Groups:\t2 1"),
            status().replace_ascii(b"Seccomp:\t2", b"Seccomp:\t0"),
            status().replace_ascii(b"Seccomp:\t2", b"Seccomp:\t4294967296"),
            status().replace_ascii(b"Seccomp:\t2", b"Seccomp:\t02"),
            status().replace_ascii(b"Seccomp:\t2", b"Seccomp:\t+2"),
            status().replace_ascii(b"Seccomp:\t2", b"Seccomp:\t2 "),
            status().replace_ascii(b"Seccomp_filters:\t4", b"Seccomp_filters:\t4294967296"),
            status().replace_ascii(b"Seccomp_filters:\t4", b"Seccomp_filters:\t04"),
            status().replace_ascii(b"Seccomp_filters:\t4", b"Seccomp_filters:\t+4"),
            status().replace_ascii(b"Seccomp_filters:\t4", b"Seccomp_filters:\t4 "),
            status().replace_ascii(b"CapBnd:\t0000000000001000", b"CapBnd:\t00000000000001000"),
            vec![b'x'; MAX_PROC_STATUS_BYTES + 1],
        ] {
            assert!(parse_process_status(&changed).is_err());
        }
    }

    trait ReplaceAscii {
        fn replace_ascii(self, old: &[u8], new: &[u8]) -> Vec<u8>;
    }

    impl ReplaceAscii for Vec<u8> {
        fn replace_ascii(self, old: &[u8], new: &[u8]) -> Vec<u8> {
            let position = self
                .windows(old.len())
                .position(|window| window == old)
                .expect("fixture substring");
            [
                self[..position].to_vec(),
                new.to_vec(),
                self[position + old.len()..].to_vec(),
            ]
            .concat()
        }
    }

    #[test]
    fn parent_descriptor_attestation_is_exact() {
        assert!(validate_exact_worker_descriptors(vec![1, 2, 3]).is_ok());
        for invalid in [
            vec![0, 1, 2, 3],
            vec![1, 2],
            vec![1, 2, 3, 4],
            vec![1, 2, 3, 3],
        ] {
            assert!(validate_exact_worker_descriptors(invalid).is_err());
        }
        assert!(validate_exact_worker_tasks(&[43], 43).is_ok());
        for invalid in [&[][..], &[42][..], &[43, 44][..], &[43, 43][..]] {
            assert!(validate_exact_worker_tasks(invalid, 43).is_err());
        }
    }

    #[test]
    fn live_proof_parent_contract_requires_exact_systemd_identity_groups_and_capabilities() {
        let required_group = 777;
        let valid = ParsedProcessStatus {
            pid: std::process::id(),
            parent_pid: 1,
            uids: [0; 4],
            gids: [required_group; 4],
            supplementary_groups: SupplementaryGroups::Singleton(required_group),
            no_new_privileges: true,
            seccomp: production_seccomp_baseline(),
            capabilities: LinuxCapabilitySnapshot {
                inheritable: HELPER_BOOTSTRAP_CAPABILITY_BITS,
                permitted: HELPER_BOOTSTRAP_CAPABILITY_BITS,
                effective: HELPER_BOOTSTRAP_CAPABILITY_BITS,
                bounding: HELPER_BOOTSTRAP_CAPABILITY_BITS,
                ambient: HELPER_BOOTSTRAP_CAPABILITY_BITS,
            },
        };
        validate_live_proof_parent_status(valid, required_group).expect("exact parent contract");

        let mut invalid = Vec::new();
        let mut changed = valid;
        changed.uids[3] = 1;
        invalid.push(changed);
        let mut changed = valid;
        changed.gids[0] = required_group + 1;
        invalid.push(changed);
        let mut changed = valid;
        changed.supplementary_groups = SupplementaryGroups::Empty;
        invalid.push(changed);
        let mut changed = valid;
        changed.supplementary_groups = SupplementaryGroups::Singleton(required_group + 1);
        invalid.push(changed);
        let mut changed = valid;
        changed.supplementary_groups = SupplementaryGroups::Multiple;
        invalid.push(changed);
        let mut changed = valid;
        changed.no_new_privileges = false;
        invalid.push(changed);
        let mut changed = valid;
        changed.seccomp = LinuxSeccompState::fixture(0, 0);
        invalid.push(changed);
        for field in 0..5 {
            let mut missing = valid;
            match field {
                0 => missing.capabilities.inheritable &= !CAP_NET_RAW_BIT,
                1 => missing.capabilities.permitted &= !CAP_NET_RAW_BIT,
                2 => missing.capabilities.effective &= !CAP_NET_RAW_BIT,
                3 => missing.capabilities.bounding &= !CAP_NET_RAW_BIT,
                4 => missing.capabilities.ambient &= !CAP_NET_RAW_BIT,
                _ => unreachable!(),
            }
            invalid.push(missing);
            let mut extra = valid;
            match field {
                0 => extra.capabilities.inheritable |= 1,
                1 => extra.capabilities.permitted |= 1,
                2 => extra.capabilities.effective |= 1,
                3 => extra.capabilities.bounding |= 1,
                4 => extra.capabilities.ambient |= 1,
                _ => unreachable!(),
            }
            invalid.push(extra);
        }
        for changed in invalid {
            assert!(validate_live_proof_parent_status(changed, required_group).is_err());
        }
        assert_eq!(HELPER_BOOTSTRAP_CAPABILITY_BITS, 0x20_31e0);
    }

    #[test]
    fn production_finish_requires_real_signal_and_runtime_path_denials() {
        let source = include_str!("worker_sandbox.rs");
        let finish_start = source
            .find("impl PreparedWorkerSandbox {")
            .expect("production finish boundary");
        let finish_end = source[finish_start..]
            .find("\nfn pre_identity_capabilities()")
            .map(|offset| finish_start + offset)
            .expect("production denial boundary");
        let finish = &source[finish_start..finish_end];
        let applied = finish
            .find("finish_sandbox(&mut ProductionSandboxKernel")
            .expect("production sandbox apply");
        let denied = finish
            .find("prove_post_identity_denials()?")
            .expect("post-identity denial proof");
        assert!(applied < denied);
        for required in [
            "kill(parent, None)",
            "Err(nix::errno::Errno::EPERM)",
            "\"/run/volparossa\"",
            "\"/run/volparossa/helper.cleanup-token\"",
            "\"/run/volparossa/helper.sock\"",
            "Err(rustix::io::Errno::ACCESS)",
        ] {
            assert!(
                finish.contains(required),
                "missing denial proof: {required}"
            );
        }
    }

    #[test]
    fn parent_pre_identity_attestation_rejects_namespace_identity_filter_and_capability_drift() {
        let parent_namespace = NetworkNamespaceIdentity::fixture(1, 10);
        let worker_namespace = NetworkNamespaceIdentity::fixture(1, 11);
        let parent_seccomp = production_seccomp_baseline();
        let required_group = 777;
        let transition = pre_identity_capabilities().bits();
        let valid = ParsedProcessStatus {
            pid: 43,
            parent_pid: 42,
            uids: [0; 4],
            gids: [required_group; 4],
            supplementary_groups: SupplementaryGroups::Singleton(required_group),
            no_new_privileges: true,
            seccomp: parent_seccomp
                .expected_after_worker_filter()
                .expect("worker filter state"),
            capabilities: LinuxCapabilitySnapshot {
                inheritable: 0,
                permitted: transition,
                effective: transition,
                bounding: CAP_NET_ADMIN_BIT | CAP_SETPCAP_BIT,
                ambient: 0,
            },
        };
        assert!(
            validate_pre_identity_state(
                parent_namespace,
                worker_namespace,
                parent_seccomp,
                required_group,
                valid,
            )
            .is_ok()
        );

        let mut invalid_states = Vec::new();
        let mut invalid = valid;
        invalid.uids[3] = 1;
        invalid_states.push(invalid);
        let mut invalid = valid;
        invalid.gids[2] = required_group + 1;
        invalid_states.push(invalid);
        let mut invalid = valid;
        invalid.no_new_privileges = false;
        invalid_states.push(invalid);
        let mut invalid = valid;
        invalid.seccomp = parent_seccomp;
        invalid_states.push(invalid);
        for capability in [
            CAP_SETGID_BIT,
            CAP_SETUID_BIT,
            CAP_SETPCAP_BIT,
            CAP_NET_ADMIN_BIT,
        ] {
            let mut missing_effective = valid;
            missing_effective.capabilities.effective &= !capability;
            invalid_states.push(missing_effective);
            let mut missing_permitted = valid;
            missing_permitted.capabilities.permitted &= !capability;
            invalid_states.push(missing_permitted);
        }
        for field in 0..5 {
            let mut extra = valid;
            match field {
                0 => extra.capabilities.inheritable |= CAP_SYS_ADMIN_BIT,
                1 => extra.capabilities.permitted |= CAP_SYS_ADMIN_BIT,
                2 => extra.capabilities.effective |= CAP_SYS_ADMIN_BIT,
                3 => extra.capabilities.bounding |= CAP_SYS_ADMIN_BIT,
                4 => extra.capabilities.ambient |= CAP_SYS_ADMIN_BIT,
                _ => unreachable!(),
            }
            invalid_states.push(extra);
        }
        for invalid in invalid_states {
            assert!(
                validate_pre_identity_state(
                    parent_namespace,
                    worker_namespace,
                    parent_seccomp,
                    required_group,
                    invalid,
                )
                .is_err()
            );
        }
        assert!(
            validate_pre_identity_state(
                parent_namespace,
                parent_namespace,
                parent_seccomp,
                required_group,
                valid,
            )
            .is_err()
        );
    }

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Step {
        Capabilities,
        Unshare,
        ObserveNamespace,
        ObserveInitialSeccomp,
        ClearAmbient,
        LastCapability,
        Drop(u32),
        SetPreIdentityCapabilities,
        ClearGroups,
        SetKeepCapabilities(bool),
        SetGid(u32),
        SetUid(u32),
        SetPostIdentityCapabilities,
        ObserveKeepCapabilities,
        SetExact,
        NoNewPrivileges,
        InstallProcessTreeFilter,
        Observe,
    }

    struct FakeKernel {
        steps: Vec<Step>,
        fail_at: Option<Step>,
        initial: CapabilitySets,
        network_namespace: NetworkNamespaceIdentity,
        keep_capabilities: bool,
    }

    impl FakeKernel {
        fn production() -> Self {
            let required = bootstrap_capabilities();
            Self {
                steps: Vec::new(),
                fail_at: None,
                initial: CapabilitySets {
                    effective: required,
                    permitted: required,
                    inheritable: CapabilitySet::empty(),
                },
                network_namespace: production_snapshot().worker_network_namespace,
                keep_capabilities: false,
            }
        }

        fn record(&mut self, step: Step) -> Result<(), WorkerSandboxError> {
            self.steps.push(step);
            if self.fail_at == Some(step) {
                return Err(WorkerSandboxError::Io(io::Error::other(
                    "injected sandbox syscall failure",
                )));
            }
            Ok(())
        }
    }

    impl SandboxKernel for FakeKernel {
        fn initial_capabilities(&mut self) -> Result<CapabilitySets, WorkerSandboxError> {
            self.record(Step::Capabilities)?;
            Ok(self.initial)
        }

        fn unshare_network(&mut self) -> Result<(), WorkerSandboxError> {
            self.record(Step::Unshare)
        }

        fn observe_network_namespace(
            &mut self,
        ) -> Result<NetworkNamespaceIdentity, WorkerSandboxError> {
            self.record(Step::ObserveNamespace)?;
            Ok(self.network_namespace)
        }

        fn install_no_new_privileges(&mut self) -> Result<(), WorkerSandboxError> {
            self.record(Step::NoNewPrivileges)
        }

        fn observe_initial_seccomp(&mut self) -> Result<LinuxSeccompState, WorkerSandboxError> {
            self.record(Step::ObserveInitialSeccomp)?;
            Ok(production_seccomp_baseline())
        }

        fn install_process_tree_filter(&mut self) -> Result<(), WorkerSandboxError> {
            self.record(Step::InstallProcessTreeFilter)
        }

        fn clear_ambient(&mut self) -> Result<(), WorkerSandboxError> {
            self.record(Step::ClearAmbient)
        }

        fn last_capability(&mut self) -> Result<u32, WorkerSandboxError> {
            self.record(Step::LastCapability)?;
            Ok(CAP_SYS_ADMIN)
        }

        fn drop_bounding(&mut self, capability: u32) -> Result<(), WorkerSandboxError> {
            self.record(Step::Drop(capability))
        }

        fn set_pre_identity_capabilities(&mut self) -> Result<(), WorkerSandboxError> {
            self.record(Step::SetPreIdentityCapabilities)?;
            let capabilities = pre_identity_capabilities();
            self.initial = CapabilitySets {
                effective: capabilities,
                permitted: capabilities,
                inheritable: CapabilitySet::empty(),
            };
            Ok(())
        }

        fn clear_supplementary_groups(&mut self) -> Result<(), WorkerSandboxError> {
            self.record(Step::ClearGroups)
        }

        fn set_keep_capabilities_enabled(
            &mut self,
            enabled: bool,
        ) -> Result<(), WorkerSandboxError> {
            self.record(Step::SetKeepCapabilities(enabled))
        }

        fn set_res_gid(&mut self, gid: u32) -> Result<(), WorkerSandboxError> {
            self.record(Step::SetGid(gid))
        }

        fn set_res_uid(&mut self, uid: u32) -> Result<(), WorkerSandboxError> {
            self.record(Step::SetUid(uid))
        }

        fn set_post_identity_capabilities(&mut self) -> Result<(), WorkerSandboxError> {
            self.record(Step::SetPostIdentityCapabilities)
        }

        fn keep_capabilities_enabled(&mut self) -> Result<bool, WorkerSandboxError> {
            self.record(Step::ObserveKeepCapabilities)?;
            Ok(self.keep_capabilities)
        }

        fn set_exact_capabilities(&mut self) -> Result<(), WorkerSandboxError> {
            self.record(Step::SetExact)
        }

        fn observe_final(
            &mut self,
            _parent_network_namespace: NetworkNamespaceIdentity,
        ) -> Result<WorkerSandboxSnapshot, WorkerSandboxError> {
            self.record(Step::Observe)?;
            Ok(production_snapshot())
        }
    }

    #[test]
    fn sandbox_phases_are_affine_and_confinement_precedes_identity_drop() {
        let mut kernel = FakeKernel::production();
        let prepared = begin_sandbox(&mut kernel, production_snapshot().parent_network_namespace)
            .expect("prepared fake sandbox");
        assert_eq!(
            &kernel.steps[..6],
            [
                Step::Capabilities,
                Step::Unshare,
                Step::ObserveNamespace,
                Step::ObserveInitialSeccomp,
                Step::ClearAmbient,
                Step::LastCapability,
            ]
        );
        let set_pre = kernel
            .steps
            .iter()
            .position(|step| *step == Step::SetPreIdentityCapabilities)
            .expect("pre-identity capset");
        assert_eq!(kernel.steps[set_pre + 1], Step::Capabilities);
        assert_eq!(kernel.steps[set_pre + 2], Step::NoNewPrivileges);
        assert_eq!(kernel.steps[set_pre + 3], Step::InstallProcessTreeFilter);
        assert!(!kernel.steps[..set_pre].contains(&Step::Drop(CAP_NET_ADMIN)));
        assert!(!kernel.steps[..set_pre].contains(&Step::Drop(CAP_SETPCAP)));
        assert!(kernel.steps[..set_pre].contains(&Step::Drop(CAP_KILL)));
        assert!(!kernel.initial.effective.contains(CapabilitySet::KILL));
        assert!(!kernel.initial.permitted.contains(CapabilitySet::KILL));
        let begin_steps = kernel.steps.len();
        let snapshot = finish_sandbox(&mut kernel, prepared, worker_identity())
            .expect("finished fake sandbox");
        assert_eq!(snapshot, production_snapshot());
        assert_eq!(
            &kernel.steps[begin_steps..begin_steps + 3],
            &[
                Step::Capabilities,
                Step::ObserveNamespace,
                Step::ClearGroups,
            ]
        );
        let clear_groups = kernel
            .steps
            .iter()
            .position(|step| *step == Step::ClearGroups)
            .expect("groups cleared");
        assert_eq!(
            kernel.steps[clear_groups + 1],
            Step::SetKeepCapabilities(true)
        );
        assert_eq!(
            kernel.steps[clear_groups + 2],
            Step::SetGid(worker_identity().gid)
        );
        assert_eq!(
            kernel.steps[clear_groups + 3],
            Step::SetUid(worker_identity().uid)
        );
        assert_eq!(
            kernel.steps[clear_groups + 4],
            Step::SetPostIdentityCapabilities
        );
        assert_eq!(
            kernel.steps[clear_groups + 5],
            Step::SetKeepCapabilities(false)
        );
        assert_eq!(
            kernel.steps[clear_groups + 6],
            Step::ObserveKeepCapabilities
        );
        let set_exact = kernel
            .steps
            .iter()
            .position(|step| *step == Step::SetExact)
            .expect("capset step");
        assert_eq!(kernel.steps[set_exact - 1], Step::Drop(CAP_SETPCAP));
        assert_eq!(kernel.steps[set_exact + 1], Step::Observe);
        let filter = kernel
            .steps
            .iter()
            .position(|step| *step == Step::InstallProcessTreeFilter)
            .expect("confinement filter");
        assert!(filter < clear_groups);
        assert!(!kernel.steps[..set_exact - 1].contains(&Step::Drop(CAP_NET_ADMIN)));
    }

    #[test]
    fn sandbox_begin_stops_at_every_injected_failure() {
        for fail_at in [
            Step::Capabilities,
            Step::Unshare,
            Step::ObserveNamespace,
            Step::ObserveInitialSeccomp,
            Step::ClearAmbient,
            Step::LastCapability,
            Step::Drop(0),
            Step::SetPreIdentityCapabilities,
            Step::NoNewPrivileges,
            Step::InstallProcessTreeFilter,
        ] {
            let mut kernel = FakeKernel::production();
            kernel.fail_at = Some(fail_at);
            assert!(
                begin_sandbox(&mut kernel, production_snapshot().parent_network_namespace,)
                    .is_err()
            );
            assert_eq!(kernel.steps.last(), Some(&fail_at));
        }
    }

    #[test]
    fn sandbox_finish_stops_at_every_injected_failure() {
        for fail_at in [
            Step::Capabilities,
            Step::ObserveNamespace,
            Step::ClearGroups,
            Step::SetKeepCapabilities(true),
            Step::SetGid(worker_identity().gid),
            Step::SetUid(worker_identity().uid),
            Step::SetPostIdentityCapabilities,
            Step::SetKeepCapabilities(false),
            Step::ObserveKeepCapabilities,
            Step::Drop(CAP_SETPCAP),
            Step::SetExact,
            Step::Observe,
        ] {
            let mut kernel = FakeKernel::production();
            let prepared =
                begin_sandbox(&mut kernel, production_snapshot().parent_network_namespace)
                    .expect("prepared fake sandbox");
            kernel.steps.clear();
            kernel.fail_at = Some(fail_at);
            assert!(finish_sandbox(&mut kernel, prepared, worker_identity()).is_err());
            assert_eq!(kernel.steps.last(), Some(&fail_at));
        }
    }

    #[test]
    fn sandbox_finish_rejects_post_barrier_namespace_capability_and_keepcaps_drift() {
        let parent_namespace = production_snapshot().parent_network_namespace;

        let mut changed_namespace = FakeKernel::production();
        let prepared = begin_sandbox(&mut changed_namespace, parent_namespace).expect("begin");
        changed_namespace.network_namespace = NetworkNamespaceIdentity::fixture(1, 12);
        assert!(finish_sandbox(&mut changed_namespace, prepared, worker_identity()).is_err());

        for capability in [
            CapabilitySet::SETGID,
            CapabilitySet::SETUID,
            CapabilitySet::SETPCAP,
            CapabilitySet::NET_ADMIN,
        ] {
            for permitted in [false, true] {
                let mut kernel = FakeKernel::production();
                let prepared = begin_sandbox(&mut kernel, parent_namespace).expect("begin");
                if permitted {
                    kernel.initial.permitted.remove(capability);
                } else {
                    kernel.initial.effective.remove(capability);
                }
                assert!(finish_sandbox(&mut kernel, prepared, worker_identity()).is_err());
            }
        }

        let mut kept = FakeKernel::production();
        let prepared = begin_sandbox(&mut kept, parent_namespace).expect("begin");
        kept.keep_capabilities = true;
        assert!(finish_sandbox(&mut kept, prepared, worker_identity()).is_err());
        assert_eq!(kept.steps.last(), Some(&Step::ObserveKeepCapabilities));
    }

    #[test]
    fn missing_bootstrap_capability_fails_before_unshare() {
        for capability in [
            CapabilitySet::KILL,
            CapabilitySet::SETGID,
            CapabilitySet::SETUID,
            CapabilitySet::SETPCAP,
            CapabilitySet::NET_ADMIN,
            CapabilitySet::SYS_ADMIN,
        ] {
            for permitted in [false, true] {
                let mut kernel = FakeKernel::production();
                if permitted {
                    kernel.initial.permitted.remove(capability);
                } else {
                    kernel.initial.effective.remove(capability);
                }
                assert!(
                    begin_sandbox(&mut kernel, production_snapshot().parent_network_namespace,)
                        .is_err()
                );
                assert_eq!(kernel.steps, vec![Step::Capabilities]);
            }
        }
        assert_eq!(CapabilitySet::KILL.bits(), 1_u64 << 5);
        assert_eq!(CAP_SETGID_BIT, 1_u64 << 6);
        assert_eq!(CAP_SETUID_BIT, 1_u64 << 7);
        assert_eq!(CAP_SETPCAP_BIT, 1_u64 << 8);
        assert_eq!(CAP_SYS_ADMIN_BIT, 1_u64 << 21);
    }

    #[test]
    fn worker_identity_rejects_root_and_reserved_values() {
        assert_eq!(
            WorkerIdentity::new(worker_identity().uid, worker_identity().gid).expect("identity"),
            worker_identity()
        );
        for (uid, gid) in [
            (0, 1),
            (1, 0),
            (SYSTEMD_RESERVED_ID, 1),
            (1, SYSTEMD_RESERVED_ID),
            (u32::MAX, 1),
            (1, u32::MAX),
        ] {
            assert!(WorkerIdentity::new(uid, gid).is_err());
        }
        assert!(
            std::panic::catch_unwind(|| WorkerIdentity::fixture(SYSTEMD_RESERVED_ID, 1)).is_err()
        );
        assert!(
            std::panic::catch_unwind(|| WorkerIdentity::fixture(1, SYSTEMD_RESERVED_ID)).is_err()
        );
    }
}
