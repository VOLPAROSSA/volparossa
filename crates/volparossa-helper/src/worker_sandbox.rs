//! Applied route-worker sandbox and independently observed bootstrap evidence.
//!
//! The production child enters a fresh network namespace, installs no-new-privileges, installs one
//! fixed seccomp filter that denies creation of descendants, reduces every capability set to
//! exactly `CAP_NET_ADMIN`, and reads the final state back before it can authenticate a request.
//! The parent pins both a pidfd and one `/proc/<pid>` directory, opens the child's network namespace
//! relative to that directory, reads bounded status fields, and attests the exact descriptor set
//! `{1, 2, 3}`. A child statement is accepted only when it equals that independently observed
//! state. Test applicators are compiled only under `cfg(test)`; production has no environment or
//! runtime switch that can select one.

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
    unistd::getppid,
};
use rustix::{
    fs::{Dir, Mode, OFlags, fstat, open, openat},
    process::{Pid, PidfdFlags, pidfd_open},
    thread::{
        CapabilitySet, CapabilitySets, capabilities, clear_ambient_capability_set,
        remove_capability_from_bounding_set, set_capabilities, set_no_new_privs,
    },
};
use thiserror::Error;
use volparossa_linux_uapi::install_worker_no_descendants_filter;

const SANDBOX_PROOF_DOMAIN: &[u8; 32] = b"volparossa/worker-sandbox/v4\0\0\0\0";
const SANDBOX_PROOF_VERSION: u32 = 4;
const MAX_DESCRIPTOR_AUDIT: usize = 4_096;
const MAX_PROC_STATUS_BYTES: usize = 64 * 1024;
const MAX_CAP_LAST_CAP_BYTES: usize = 4;
const WORKER_CHANNEL_DESCRIPTOR: i32 = 3;
const CAP_SETPCAP: u32 = 8;
const CAP_NET_ADMIN: u32 = 12;
const CAP_SYS_ADMIN: u32 = 21;
const CAP_SETPCAP_BIT: u64 = 1_u64 << CAP_SETPCAP;
const CAP_NET_ADMIN_BIT: u64 = 1_u64 << CAP_NET_ADMIN;
const CAP_SYS_ADMIN_BIT: u64 = 1_u64 << CAP_SYS_ADMIN;

pub(super) type ContextId = [u8; 16];

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
    no_new_privileges: bool,
    seccomp: LinuxSeccompState,
    capabilities: LinuxCapabilitySnapshot,
}

impl WorkerSandboxSnapshot {
    #[cfg(test)]
    pub(super) const fn fixture(
        parent_network_namespace: NetworkNamespaceIdentity,
        worker_network_namespace: NetworkNamespaceIdentity,
        no_new_privileges: bool,
        seccomp: LinuxSeccompState,
        capabilities: LinuxCapabilitySnapshot,
    ) -> Self {
        Self {
            parent_network_namespace,
            worker_network_namespace,
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
    required_capabilities: LinuxCapabilitySnapshot,
    required_seccomp: LinuxSeccompState,
}

impl WorkerSandboxPlan {
    pub(super) fn production(
        baseline_seccomp: LinuxSeccompState,
    ) -> Result<Self, WorkerSandboxError> {
        Ok(Self {
            required_capabilities: LinuxCapabilitySnapshot {
                inheritable: 0,
                permitted: CAP_NET_ADMIN_BIT,
                effective: CAP_NET_ADMIN_BIT,
                bounding: CAP_NET_ADMIN_BIT,
                ambient: 0,
            },
            required_seccomp: baseline_seccomp.expected_after_worker_filter()?,
        })
    }

    pub(super) fn verify(self, snapshot: WorkerSandboxSnapshot) -> Result<(), WorkerSandboxError> {
        if !snapshot.parent_network_namespace.is_valid()
            || !snapshot.worker_network_namespace.is_valid()
        {
            return Err(WorkerSandboxError::Invalid);
        }
        if snapshot.parent_network_namespace == snapshot.worker_network_namespace
            || !snapshot.no_new_privileges
            || snapshot.seccomp != self.required_seccomp
            || snapshot.capabilities != self.required_capabilities
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
    pub(super) const LENGTH: usize = 180;

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
        encoded[132] = u8::from(self.snapshot.no_new_privileges);
        encoded[133] = self.snapshot.seccomp.mode;
        encoded[134..138].copy_from_slice(&self.snapshot.seccomp.filter_count.to_be_bytes());
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
            let start = 140 + offset * 8;
            encoded[start..start + 8].copy_from_slice(&value.to_be_bytes());
        }
        encoded
    }

    pub(super) fn decode(encoded: &[u8]) -> Result<Self, WorkerSandboxError> {
        if encoded.len() != Self::LENGTH
            || encoded.get(0..32) != Some(SANDBOX_PROOF_DOMAIN.as_slice())
            || encoded.get(138..140) != Some([0_u8; 2].as_slice())
            || u32::from_be_bytes(read_array(encoded, 32)?) != SANDBOX_PROOF_VERSION
        {
            return Err(WorkerSandboxError::Invalid);
        }
        let no_new_privileges = match encoded[132] {
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
                no_new_privileges,
                seccomp: LinuxSeccompState::from_status(
                    u32::from(encoded[133]),
                    u32::from_be_bytes(read_array(encoded, 134)?),
                )?,
                capabilities: LinuxCapabilitySnapshot {
                    inheritable: u64::from_be_bytes(read_array(encoded, 140)?),
                    permitted: u64::from_be_bytes(read_array(encoded, 148)?),
                    effective: u64::from_be_bytes(read_array(encoded, 156)?),
                    bounding: u64::from_be_bytes(read_array(encoded, 164)?),
                    ambient: u64::from_be_bytes(read_array(encoded, 172)?),
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
    no_new_privileges: bool,
    seccomp: LinuxSeccompState,
    capabilities: LinuxCapabilitySnapshot,
}

fn parse_process_status(bytes: &[u8]) -> Result<ParsedProcessStatus, WorkerSandboxError> {
    let text = std::str::from_utf8(bytes).map_err(|_| WorkerSandboxError::Invalid)?;
    let mut pid = None;
    let mut parent_pid = None;
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
    Ok(WorkerSandboxSnapshot {
        parent_network_namespace,
        worker_network_namespace,
        no_new_privileges: status.no_new_privileges,
        seccomp: status.seccomp,
        capabilities: status.capabilities,
    })
}

/// Kernel pins created immediately after spawn and retained until confirmed reap.
///
/// This value is owned only by `ProcessRetirement`. Moving a retirement record to the reaper also
/// moves its pidfd, anchored process-directory descriptor, and pinned network namespace.
pub(super) struct WorkerKernelPins {
    pidfd: OwnedFd,
    process_directory: OwnedFd,
    network_namespace: Option<OwnedFd>,
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
        })
    }

    pub(super) fn observe_and_pin(
        &mut self,
        parent_network_namespace: NetworkNamespaceIdentity,
        parent_seccomp: LinuxSeccompState,
        parent_pid: u32,
        child_pid: u32,
    ) -> Result<WorkerSandboxSnapshot, WorkerSandboxError> {
        let plan = WorkerSandboxPlan::production(parent_seccomp)?;
        self.ensure_alive()?;
        let (worker_network_namespace, status) =
            self.observe_common(parent_pid, child_pid, true)?;
        let snapshot = WorkerSandboxSnapshot {
            parent_network_namespace,
            worker_network_namespace,
            no_new_privileges: status.no_new_privileges,
            seccomp: status.seccomp,
            capabilities: status.capabilities,
        };
        plan.verify(snapshot)?;
        self.ensure_alive()?;
        Ok(snapshot)
    }

    #[cfg(test)]
    pub(super) fn observe_and_pin_fixture(
        &mut self,
        parent_pid: u32,
        child_pid: u32,
        fixture: WorkerSandboxSnapshot,
        parent_seccomp: LinuxSeccompState,
    ) -> Result<WorkerSandboxSnapshot, WorkerSandboxError> {
        let plan = WorkerSandboxPlan::production(parent_seccomp)?;
        self.ensure_alive()?;
        // Rust's test harness owns a coordinator thread in addition to the exact test thread.
        // This cfg(test)-only observer still anchors and bounds the task view and requires the
        // process leader; production always takes the exact-single-task branch above.
        let _ = self.observe_common(parent_pid, child_pid, false)?;
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

    fn observe_common(
        &mut self,
        parent_pid: u32,
        child_pid: u32,
        require_single_task: bool,
    ) -> Result<(NetworkNamespaceIdentity, ParsedProcessStatus), WorkerSandboxError> {
        if self.network_namespace.is_some() {
            return Err(WorkerSandboxError::Invalid);
        }
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

        let descriptor_directory = openat(
            &self.process_directory,
            "fd",
            OFlags::RDONLY | OFlags::DIRECTORY | OFlags::CLOEXEC | OFlags::NOFOLLOW,
            Mode::empty(),
        )
        .map_err(rustix_io)?;
        validate_exact_worker_descriptors(read_numeric_directory(descriptor_directory)?)?;

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

    #[cfg(test)]
    pub(super) fn has_complete_pins(&self) -> bool {
        self.network_namespace.is_some()
    }

    #[cfg(test)]
    pub(super) fn fixture() -> Self {
        Self {
            pidfd: File::open("/dev/null").expect("fake pidfd").into(),
            process_directory: File::open("/dev/null")
                .expect("fake process directory")
                .into(),
            network_namespace: Some(
                File::open("/dev/null")
                    .expect("fake network namespace")
                    .into(),
            ),
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
    fn install_no_new_privileges(&mut self) -> Result<(), WorkerSandboxError>;
    fn observe_initial_seccomp(&mut self) -> Result<LinuxSeccompState, WorkerSandboxError>;
    fn install_process_tree_filter(&mut self) -> Result<(), WorkerSandboxError>;
    fn clear_ambient(&mut self) -> Result<(), WorkerSandboxError>;
    fn last_capability(&mut self) -> Result<u32, WorkerSandboxError>;
    fn drop_bounding(&mut self, capability: u32) -> Result<(), WorkerSandboxError>;
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

    fn install_no_new_privileges(&mut self) -> Result<(), WorkerSandboxError> {
        set_no_new_privs(true)
            .map_err(rustix_io)
            .map_err(Into::into)
    }

    fn observe_initial_seccomp(&mut self) -> Result<LinuxSeccompState, WorkerSandboxError> {
        current_thread_seccomp_state()
    }

    fn install_process_tree_filter(&mut self) -> Result<(), WorkerSandboxError> {
        install_worker_no_descendants_filter().map_err(Into::into)
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

pub(super) fn apply_production_sandbox(
    parent_network_namespace: NetworkNamespaceIdentity,
) -> Result<WorkerSandboxSnapshot, WorkerSandboxError> {
    apply_sandbox(&mut ProductionSandboxKernel, parent_network_namespace)
}

fn apply_sandbox<K: SandboxKernel>(
    kernel: &mut K,
    parent_network_namespace: NetworkNamespaceIdentity,
) -> Result<WorkerSandboxSnapshot, WorkerSandboxError> {
    let initial = kernel.initial_capabilities()?;
    let required_bootstrap =
        CapabilitySet::NET_ADMIN | CapabilitySet::SETPCAP | CapabilitySet::SYS_ADMIN;
    if !initial.effective.contains(required_bootstrap)
        || !initial.permitted.contains(required_bootstrap)
    {
        return Err(WorkerSandboxError::Mismatch);
    }

    kernel.unshare_network()?;
    kernel.install_no_new_privileges()?;
    let baseline_seccomp = kernel.observe_initial_seccomp()?;
    let plan = WorkerSandboxPlan::production(baseline_seccomp)?;
    kernel.install_process_tree_filter()?;
    kernel.clear_ambient()?;
    let last_capability = kernel.last_capability()?;
    for capability in 0..=last_capability {
        if capability != CAP_NET_ADMIN && capability != CAP_SETPCAP {
            kernel.drop_bounding(capability)?;
        }
    }
    // CAP_SETPCAP is deliberately the final bounding-set removal. It remains effective until the
    // subsequent capset atomically reduces effective/permitted to CAP_NET_ADMIN.
    kernel.drop_bounding(CAP_SETPCAP)?;
    kernel.set_exact_capabilities()?;
    let snapshot = kernel.observe_final(parent_network_namespace)?;
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
        let plan = WorkerSandboxPlan::production(production_seccomp_baseline()).expect("plan");
        let valid = production_snapshot();
        assert!(plan.verify(valid).is_ok());

        let mut invalid = valid;
        invalid.worker_network_namespace = invalid.parent_network_namespace;
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
            assert!(WorkerSandboxPlan::production(invalid_baseline).is_err());
        }

        let zero_baseline = LinuxSeccompState::fixture(0, 0);
        let mut first_filter = valid;
        first_filter.seccomp = LinuxSeccompState::fixture(2, 1);
        WorkerSandboxPlan::production(zero_baseline)
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
    fn proof_is_canonical_and_one_expectation_binds_every_bootstrap_field() {
        let proof = proof();
        let encoded = proof.encode();
        assert_eq!(SandboxProofRecord::LENGTH, 180);
        assert_eq!(&encoded[0..32], SANDBOX_PROOF_DOMAIN);
        assert_eq!(&encoded[32..36], &4_u32.to_be_bytes());
        assert_eq!(&encoded[36..52], &[7; 16]);
        assert_eq!(&encoded[52..60], &9_u64.to_be_bytes());
        assert_eq!(&encoded[60..92], &[11; 32]);
        assert_eq!(&encoded[92..96], &42_u32.to_be_bytes());
        assert_eq!(&encoded[96..100], &43_u32.to_be_bytes());
        assert_eq!(encoded[132], 1);
        assert_eq!(encoded[133], 2);
        assert_eq!(&encoded[134..138], &4_u32.to_be_bytes());
        assert_eq!(&encoded[138..140], &[0, 0]);
        assert_eq!(&encoded[140..148], &0_u64.to_be_bytes());
        assert_eq!(&encoded[148..156], &CAP_NET_ADMIN_BIT.to_be_bytes());
        assert_eq!(&encoded[156..164], &CAP_NET_ADMIN_BIT.to_be_bytes());
        assert_eq!(&encoded[164..172], &CAP_NET_ADMIN_BIT.to_be_bytes());
        assert_eq!(&encoded[172..180], &0_u64.to_be_bytes());
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
            WorkerSandboxPlan::production(production_seccomp_baseline()).expect("plan"),
        )
        .expect("exact fake proof");

        for index in [
            0, 32, 36, 52, 60, 92, 96, 100, 108, 116, 124, 132, 133, 134, 138, 139, 140, 148, 156,
            164, 172,
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
                        WorkerSandboxPlan::production(production_seccomp_baseline()).expect("plan"),
                    )
                    .is_err()
            );
        }
        assert!(SandboxProofRecord::decode(&encoded[..encoded.len() - 1]).is_err());
        let mut retired_v3 = encoded;
        retired_v3[27] = b'3';
        retired_v3[32..36].copy_from_slice(&3_u32.to_be_bytes());
        assert!(SandboxProofRecord::decode(&retired_v3).is_err());
    }

    fn status() -> Vec<u8> {
        concat!(
            "Name:\tworker\n",
            "Pid:\t43\n",
            "PPid:\t42\n",
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
        assert!(parsed.no_new_privileges);
        assert_eq!(parsed.seccomp, production_snapshot().seccomp);
        assert_eq!(parsed.capabilities, production_snapshot().capabilities);

        for changed in [
            b"Pid:\t43\n".to_vec(),
            [status(), b"CapEff:\t0000000000001000\n".to_vec()].concat(),
            [status(), b"Seccomp:\t2\n".to_vec()].concat(),
            [status(), b"Seccomp_filters:\t4\n".to_vec()].concat(),
            status().replace_ascii(b"Seccomp:\t2\n", b""),
            status().replace_ascii(b"Seccomp_filters:\t4\n", b""),
            status().replace_ascii(b"NoNewPrivs:\t1", b"NoNewPrivs:\t2"),
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

    #[derive(Clone, Copy, Debug, Eq, PartialEq)]
    enum Step {
        Initial,
        Unshare,
        NoNewPrivileges,
        ObserveInitialSeccomp,
        InstallProcessTreeFilter,
        ClearAmbient,
        LastCapability,
        Drop(u32),
        SetExact,
        Observe,
    }

    struct FakeKernel {
        steps: Vec<Step>,
        fail_at: Option<Step>,
        initial: CapabilitySets,
    }

    impl FakeKernel {
        fn production() -> Self {
            let required =
                CapabilitySet::NET_ADMIN | CapabilitySet::SETPCAP | CapabilitySet::SYS_ADMIN;
            Self {
                steps: Vec::new(),
                fail_at: None,
                initial: CapabilitySets {
                    effective: required,
                    permitted: required,
                    inheritable: CapabilitySet::empty(),
                },
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
            self.record(Step::Initial)?;
            Ok(self.initial)
        }

        fn unshare_network(&mut self) -> Result<(), WorkerSandboxError> {
            self.record(Step::Unshare)
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
    fn sandbox_syscall_order_drops_setpcap_last_and_reads_back_exact_state() {
        let mut kernel = FakeKernel::production();
        let snapshot = apply_sandbox(&mut kernel, production_snapshot().parent_network_namespace)
            .expect("fake sandbox");
        assert_eq!(snapshot, production_snapshot());
        assert_eq!(kernel.steps.first(), Some(&Step::Initial));
        assert_eq!(
            &kernel.steps[1..7],
            &[
                Step::Unshare,
                Step::NoNewPrivileges,
                Step::ObserveInitialSeccomp,
                Step::InstallProcessTreeFilter,
                Step::ClearAmbient,
                Step::LastCapability,
            ]
        );
        let set_exact = kernel
            .steps
            .iter()
            .position(|step| *step == Step::SetExact)
            .expect("capset step");
        assert_eq!(kernel.steps[set_exact - 1], Step::Drop(CAP_SETPCAP));
        assert_eq!(kernel.steps[set_exact + 1], Step::Observe);
        assert!(!kernel.steps[..set_exact - 1].contains(&Step::Drop(CAP_NET_ADMIN)));
    }

    #[test]
    fn sandbox_application_stops_at_every_injected_failure() {
        for fail_at in [
            Step::Initial,
            Step::Unshare,
            Step::NoNewPrivileges,
            Step::ObserveInitialSeccomp,
            Step::InstallProcessTreeFilter,
            Step::ClearAmbient,
            Step::LastCapability,
            Step::Drop(0),
            Step::Drop(CAP_SETPCAP),
            Step::SetExact,
            Step::Observe,
        ] {
            let mut kernel = FakeKernel::production();
            kernel.fail_at = Some(fail_at);
            assert!(
                apply_sandbox(&mut kernel, production_snapshot().parent_network_namespace).is_err()
            );
            assert_eq!(kernel.steps.last(), Some(&fail_at));
        }
    }

    #[test]
    fn missing_bootstrap_capability_fails_before_unshare() {
        let mut kernel = FakeKernel::production();
        kernel.initial.effective.remove(CapabilitySet::SETPCAP);
        assert!(
            apply_sandbox(&mut kernel, production_snapshot().parent_network_namespace).is_err()
        );
        assert_eq!(kernel.steps, vec![Step::Initial]);
        assert_eq!(CAP_SETPCAP_BIT, 1_u64 << 8);
        assert_eq!(CAP_SYS_ADMIN_BIT, 1_u64 << 21);
    }
}
