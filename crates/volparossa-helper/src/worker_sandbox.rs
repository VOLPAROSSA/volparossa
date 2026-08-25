//! Applied route-worker sandbox and independently observed bootstrap evidence.
//!
//! The production child first enters a fresh network namespace and then pauses at an affine
//! bootstrap barrier after setting no-new-privileges and installing one fixed seccomp filter that
//! denies descendant creation and every later namespace transition. While the child is still root,
//! the parent pins that namespace and attests the filter, exact descriptor set and single task. Only
//! after the pin acknowledgement may the child clear all supplementary groups, irreversibly assume
//! its dedicated uid/gid and reduce every capability set to exactly `CAP_NET_ADMIN`. The child and
//! parent both read the final identity and sandbox state back before the first authenticated request.
//! Test applicators are compiled only under `cfg(test)`; production has no environment or runtime
//! switch that can select one.

use std::{
    collections::BTreeSet,
    fs::{self, File},
    io::{self, Read},
    os::fd::{AsFd, OwnedFd},
    process::Child,
};

use nix::{
    poll::{PollFd, PollFlags, poll},
    sched::{CloneFlags, unshare},
    sys::signal::kill,
    unistd::{Pid as NixPid, getppid},
};
use rustix::{
    fs::{Dir, Mode, OFlags, fstat, open, openat},
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

    #[cfg(test)]
    pub(crate) fn identity_for_test(&self) -> NetworkNamespaceIdentity {
        self.identity
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
    final_descriptor_directory: Option<OwnedFd>,
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
        Ok(Self {
            pidfd,
            process_directory,
            network_namespace: None,
            final_descriptor_directory: None,
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
            || self.final_descriptor_directory.is_some()
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
        self.ensure_alive()?;
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
        let network_namespace = self
            .network_namespace
            .as_ref()
            .ok_or(WorkerSandboxError::Invalid)?;
        let worker_network_namespace = namespace_identity(network_namespace)?;
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
        self.ensure_alive()?;
        Ok(snapshot)
    }

    #[cfg(test)]
    pub(super) fn pin_network_namespace_before_identity_drop_fixture(
        &mut self,
        parent_pid: u32,
        child_pid: u32,
    ) -> Result<NetworkNamespaceIdentity, WorkerSandboxError> {
        if self.network_namespace.is_some() || self.final_descriptor_directory.is_some() {
            return Err(WorkerSandboxError::Invalid);
        }
        self.ensure_alive()?;
        let (worker_network_namespace, _) =
            self.observe_and_pin_common(parent_pid, child_pid, false)?;
        self.ensure_alive()?;
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
        if self.network_namespace.is_none() {
            return Err(WorkerSandboxError::Invalid);
        }
        let descriptor_directory = self
            .final_descriptor_directory
            .take()
            .ok_or(WorkerSandboxError::Invalid)?;
        validate_exact_worker_descriptors(read_numeric_directory(descriptor_directory)?)?;
        let _ = self.observe_status(parent_pid, child_pid)?;
        plan.verify(fixture)?;
        self.ensure_alive()?;
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
        if self.network_namespace.is_some() || self.final_descriptor_directory.is_some() {
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
        let worker_network_namespace = namespace_identity(&network_namespace)?;
        self.network_namespace = Some(network_namespace);
        Ok((worker_network_namespace, status))
    }

    pub(super) fn has_complete_pins(&self) -> bool {
        self.network_namespace.is_some()
    }

    /// Duplicates the retained worker network namespace into an independent affine call pin.
    ///
    /// Exact nsfs device and inode identity is read from both owners, and the duplicate itself
    /// keeps that namespace alive until its planned call finishes or is rejected. This method does
    /// not probe the worker process: callers which hold a registry lock may use it only as an FD
    /// ownership operation and must check liveness outside that lock.
    pub(super) fn duplicate_network_namespace_pin(
        &self,
    ) -> Result<PinnedWorkerNetworkNamespace, WorkerSandboxError> {
        let source = self
            .network_namespace
            .as_ref()
            .ok_or(WorkerSandboxError::Invalid)?;
        let identity = typed_network_namespace_identity(source)?;
        let descriptor = duplicate_descriptor_cloexec(source)?;
        if typed_network_namespace_identity(&descriptor)? != identity {
            return Err(WorkerSandboxError::Mismatch);
        }
        Ok(PinnedWorkerNetworkNamespace {
            descriptor,
            identity,
        })
    }

    #[cfg(test)]
    pub(super) fn fixture() -> Self {
        Self {
            pidfd: pidfd_open(rustix::process::getpid(), PidfdFlags::empty())
                .expect("pin current test process"),
            process_directory: open(
                format!("/proc/{}", std::process::id()),
                OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
                Mode::empty(),
            )
            .expect("pin current test process directory"),
            network_namespace: Some(
                open(
                    "/proc/thread-self/ns/net",
                    OFlags::RDONLY | OFlags::CLOEXEC,
                    Mode::empty(),
                )
                .expect("pin current test network namespace"),
            ),
            final_descriptor_directory: None,
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
