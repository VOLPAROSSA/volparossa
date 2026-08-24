use std::str;

use thiserror::Error;
use volparossa_test_support::{MAX_LIFECYCLE_FRAME_BYTES, RunId};

use crate::signals::ManagedSignal;

const NAMESPACES_CREATED_HEADER: &str = "VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V1 NAMESPACES_CREATED";
const MAPPINGS_INSTALLED_HEADER: &str = "VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V1 MAPPINGS_INSTALLED";
const MAPPINGS_VERIFIED_HEADER: &str = "VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V1 MAPPINGS_VERIFIED";
const MAPPINGS_PINNED_HEADER: &str = "VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V1 MAPPINGS_PINNED";
const PID1_SPAWNED_HEADER: &str = "VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V1 PID1_SPAWNED";
const PID1_PINNED_HEADER: &str = "VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V1 PID1_PINNED";
const PRIVATE_MOUNTS_READY_HEADER: &str =
    "VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V1 PRIVATE_MOUNTS_READY";
const PRIVATE_MOUNTS_VERIFIED_HEADER: &str =
    "VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V1 PRIVATE_MOUNTS_VERIFIED";
const PRIVATE_MOUNTS_UNAVAILABLE_HEADER: &str =
    "VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V1 PRIVATE_MOUNTS_UNAVAILABLE";
const MUTATION_ROLLBACK_COMPLETE_HEADER: &str =
    "VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V1 MUTATION_ROLLBACK_COMPLETE";
const PID1_SIGNAL_OBSERVED_HEADER: &str =
    "VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V1 PID1_SIGNAL_OBSERVED";
const PID1_REAPED_HEADER: &str = "VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V1 PID1_REAPED";
const PID1_REAPED_STATUS: i32 = 77;
const MAX_LINUX_PID: u32 = 2_147_483_647;

/// Rejection of the fixed internal bootstrap-control exchange.
#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum BootstrapControlError {
    /// A record exceeded the lifecycle transport's fixed byte bound.
    #[error("bootstrap-control record exceeds its fixed size bound")]
    FrameTooLarge,
    /// A record was empty or did not end in exactly one line feed.
    #[error("bootstrap-control record must end in exactly one line feed")]
    MissingFinalLineFeed,
    /// A carriage return appeared anywhere in a record.
    #[error("carriage returns are forbidden in bootstrap-control records")]
    CarriageReturn,
    /// A record was not valid UTF-8.
    #[error("bootstrap-control record is not UTF-8")]
    Utf8,
    /// The header, field name, field order, or field count was not exact.
    #[error("bootstrap-control record shape is not canonical")]
    FrameShape,
    /// The run identifier was not canonical.
    #[error("bootstrap-control run identifier is invalid")]
    RunId,
    /// A PID was not a canonical positive Linux process identifier.
    #[error("bootstrap-control PID is invalid")]
    Pid,
    /// A PID-1 completion record did not carry the sole blocked status.
    #[error("bootstrap-control PID-1 status is invalid")]
    ExitStatus,
    /// A managed-signal field was not one of the fixed canonical names.
    #[error("bootstrap-control managed signal is invalid")]
    Signal,
    /// A valid record travelled in the wrong direction or appeared at the wrong receive step.
    #[error("unexpected bootstrap-control record")]
    UnexpectedRecord,
    /// A record was bound to another lifecycle run.
    #[error("bootstrap-control run identifier mismatch")]
    RunIdMismatch,
    /// A record named another process than the affinely retained PID-1 child.
    #[error("bootstrap-control PID mismatch")]
    PidMismatch,
    /// A record named another signal than the affinely expected managed signal.
    #[error("bootstrap-control managed signal mismatch")]
    SignalMismatch,
    /// An affine state transition was attempted more than once or out of order.
    #[error("invalid bootstrap-control state transition")]
    StateTransition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordKind {
    NamespacesCreated,
    MappingsInstalled,
    MappingsVerified,
    MappingsPinned,
    Pid1Spawned,
    Pid1Pinned,
    PrivateMountsReady,
    PrivateMountsVerified,
    PrivateMountsUnavailable,
    MutationRollbackComplete,
    Pid1SignalObserved,
    Pid1Reaped,
}

impl RecordKind {
    const fn header(self) -> &'static str {
        match self {
            Self::NamespacesCreated => NAMESPACES_CREATED_HEADER,
            Self::MappingsInstalled => MAPPINGS_INSTALLED_HEADER,
            Self::MappingsVerified => MAPPINGS_VERIFIED_HEADER,
            Self::MappingsPinned => MAPPINGS_PINNED_HEADER,
            Self::Pid1Spawned => PID1_SPAWNED_HEADER,
            Self::Pid1Pinned => PID1_PINNED_HEADER,
            Self::PrivateMountsReady => PRIVATE_MOUNTS_READY_HEADER,
            Self::PrivateMountsVerified => PRIVATE_MOUNTS_VERIFIED_HEADER,
            Self::PrivateMountsUnavailable => PRIVATE_MOUNTS_UNAVAILABLE_HEADER,
            Self::MutationRollbackComplete => MUTATION_ROLLBACK_COMPLETE_HEADER,
            Self::Pid1SignalObserved => PID1_SIGNAL_OBSERVED_HEADER,
            Self::Pid1Reaped => PID1_REAPED_HEADER,
        }
    }

    fn parse(header: &str) -> Result<Self, BootstrapControlError> {
        match header {
            NAMESPACES_CREATED_HEADER => Ok(Self::NamespacesCreated),
            MAPPINGS_INSTALLED_HEADER => Ok(Self::MappingsInstalled),
            MAPPINGS_VERIFIED_HEADER => Ok(Self::MappingsVerified),
            MAPPINGS_PINNED_HEADER => Ok(Self::MappingsPinned),
            PID1_SPAWNED_HEADER => Ok(Self::Pid1Spawned),
            PID1_PINNED_HEADER => Ok(Self::Pid1Pinned),
            PRIVATE_MOUNTS_READY_HEADER => Ok(Self::PrivateMountsReady),
            PRIVATE_MOUNTS_VERIFIED_HEADER => Ok(Self::PrivateMountsVerified),
            PRIVATE_MOUNTS_UNAVAILABLE_HEADER => Ok(Self::PrivateMountsUnavailable),
            MUTATION_ROLLBACK_COMPLETE_HEADER => Ok(Self::MutationRollbackComplete),
            PID1_SIGNAL_OBSERVED_HEADER => Ok(Self::Pid1SignalObserved),
            PID1_REAPED_HEADER => Ok(Self::Pid1Reaped),
            _ => Err(BootstrapControlError::FrameShape),
        }
    }

    const fn has_pid(self) -> bool {
        matches!(
            self,
            Self::Pid1Spawned
                | Self::Pid1Pinned
                | Self::PrivateMountsReady
                | Self::PrivateMountsVerified
                | Self::PrivateMountsUnavailable
                | Self::MutationRollbackComplete
                | Self::Pid1SignalObserved
                | Self::Pid1Reaped
        )
    }

    const fn has_status(self) -> bool {
        matches!(self, Self::Pid1Reaped)
    }

    const fn has_signal(self) -> bool {
        matches!(self, Self::Pid1SignalObserved)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ControlRecord {
    kind: RecordKind,
    run_id: RunId,
    pid: Option<u32>,
    status: Option<i32>,
    signal: Option<ManagedSignal>,
}

impl ControlRecord {
    fn new(kind: RecordKind, run_id: RunId) -> Self {
        Self {
            kind,
            run_id,
            pid: None,
            status: None,
            signal: None,
        }
    }

    fn for_pid(kind: RecordKind, run_id: RunId, pid: u32) -> Self {
        Self {
            kind,
            run_id,
            pid: Some(pid),
            status: None,
            signal: None,
        }
    }

    fn pid1_reaped(run_id: RunId, pid: u32, status: i32) -> Self {
        Self {
            kind: RecordKind::Pid1Reaped,
            run_id,
            pid: Some(pid),
            status: Some(status),
            signal: None,
        }
    }

    fn pid1_signal_observed(run_id: RunId, pid: u32, signal: ManagedSignal) -> Self {
        Self {
            kind: RecordKind::Pid1SignalObserved,
            run_id,
            pid: Some(pid),
            status: None,
            signal: Some(signal),
        }
    }

    fn encode(&self) -> Result<String, BootstrapControlError> {
        self.validate_fields()?;
        let encoded = match (self.pid, self.status, self.signal) {
            (None, None, None) => {
                format!("{}\nrun_id={}\n", self.kind.header(), self.run_id.as_str())
            }
            (Some(pid), None, None) => format!(
                "{}\nrun_id={}\npid={pid}\n",
                self.kind.header(),
                self.run_id.as_str()
            ),
            (Some(pid), Some(status), None) => format!(
                "{}\nrun_id={}\npid={pid}\nstatus={status}\n",
                self.kind.header(),
                self.run_id.as_str()
            ),
            (Some(pid), None, Some(signal)) => format!(
                "{}\nrun_id={}\npid={pid}\nsignal={}\n",
                self.kind.header(),
                self.run_id.as_str(),
                signal.as_str()
            ),
            _ => return Err(BootstrapControlError::FrameShape),
        };
        if encoded.len() > MAX_LIFECYCLE_FRAME_BYTES {
            return Err(BootstrapControlError::FrameTooLarge);
        }
        Ok(encoded)
    }

    fn validate_fields(&self) -> Result<(), BootstrapControlError> {
        if self.kind.has_pid() != self.pid.is_some()
            || self.kind.has_status() != self.status.is_some()
            || self.kind.has_signal() != self.signal.is_some()
        {
            return Err(BootstrapControlError::FrameShape);
        }
        if self.pid.is_some_and(|pid| pid == 0 || pid > MAX_LINUX_PID) {
            return Err(BootstrapControlError::Pid);
        }
        if self
            .status
            .is_some_and(|status| status != PID1_REAPED_STATUS)
        {
            return Err(BootstrapControlError::ExitStatus);
        }
        Ok(())
    }

    fn parse(bytes: &[u8]) -> Result<Self, BootstrapControlError> {
        if bytes.len() > MAX_LIFECYCLE_FRAME_BYTES {
            return Err(BootstrapControlError::FrameTooLarge);
        }
        if bytes.is_empty() || bytes.last() != Some(&b'\n') {
            return Err(BootstrapControlError::MissingFinalLineFeed);
        }
        if bytes.contains(&b'\r') {
            return Err(BootstrapControlError::CarriageReturn);
        }
        let text = str::from_utf8(bytes).map_err(|_| BootstrapControlError::Utf8)?;
        let body = text
            .strip_suffix('\n')
            .ok_or(BootstrapControlError::MissingFinalLineFeed)?;
        if body.ends_with('\n') {
            return Err(BootstrapControlError::FrameShape);
        }
        let mut lines = body.split('\n');
        let header = lines.next().ok_or(BootstrapControlError::FrameShape)?;
        let run_line = lines.next().ok_or(BootstrapControlError::FrameShape)?;
        let kind = RecordKind::parse(header)?;
        let run_value = run_line
            .strip_prefix("run_id=")
            .ok_or(BootstrapControlError::FrameShape)?;
        let run_id = RunId::parse(run_value).map_err(|_| BootstrapControlError::RunId)?;
        let pid = if kind.has_pid() {
            let pid_line = lines.next().ok_or(BootstrapControlError::FrameShape)?;
            let pid_value = pid_line
                .strip_prefix("pid=")
                .ok_or(BootstrapControlError::FrameShape)?;
            Some(parse_canonical_pid(pid_value)?)
        } else {
            None
        };
        let status = if kind.has_status() {
            let status_line = lines.next().ok_or(BootstrapControlError::FrameShape)?;
            let status_value = status_line
                .strip_prefix("status=")
                .ok_or(BootstrapControlError::FrameShape)?;
            if status_value != "77" {
                return Err(BootstrapControlError::ExitStatus);
            }
            Some(PID1_REAPED_STATUS)
        } else {
            None
        };
        let signal = if kind.has_signal() {
            let signal_line = lines.next().ok_or(BootstrapControlError::FrameShape)?;
            let signal_value = signal_line
                .strip_prefix("signal=")
                .ok_or(BootstrapControlError::FrameShape)?;
            Some(ManagedSignal::parse(signal_value).map_err(|_| BootstrapControlError::Signal)?)
        } else {
            None
        };
        if lines.next().is_some() {
            return Err(BootstrapControlError::FrameShape);
        }
        let record = Self {
            kind,
            run_id,
            pid,
            status,
            signal,
        };
        if record.encode()?.as_bytes() != bytes {
            return Err(BootstrapControlError::FrameShape);
        }
        Ok(record)
    }
}

fn parse_canonical_pid(value: &str) -> Result<u32, BootstrapControlError> {
    if value.is_empty()
        || value.starts_with('0')
        || !value.bytes().all(|byte| byte.is_ascii_digit())
    {
        return Err(BootstrapControlError::Pid);
    }
    value
        .parse::<u32>()
        .ok()
        .filter(|pid| *pid > 0 && *pid <= MAX_LINUX_PID)
        .ok_or(BootstrapControlError::Pid)
}

/// Observable outer-side phase of the fixed mapping and PID-1 proof handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OuterBootstrapPhase {
    /// Waiting for the launcher to prove that the fixed namespaces exist.
    AwaitingNamespacesCreated,
    /// The namespace record was accepted; the mapping acknowledgement may be emitted once.
    NamespacesCreated,
    /// The mapping acknowledgement was emitted; launcher verification is outstanding.
    AwaitingMappingsVerified,
    /// Launcher mapping verification arrived; the outer pin may be emitted once.
    MappingsVerified,
    /// The outer mapping pin was emitted; the PID-1 spawn record is outstanding.
    AwaitingPid1Spawned,
    /// The exact PID-1 child was retained; its pin acknowledgement may be emitted once.
    Pid1Spawned,
    /// The pin acknowledgement was emitted; private-mount readiness is outstanding.
    AwaitingPrivateMountsReady,
    /// Private-mount readiness was accepted; its verification may be emitted once.
    PrivateMountsReady,
    /// Private mounts were verified; mutation rollback completion is outstanding.
    AwaitingMutationRollbackComplete,
    /// Mutation rollback completion was accepted; exact managed-signal observation is outstanding.
    AwaitingSignalObserved,
    /// Exact managed-signal observation was accepted; PID-1 reaping is outstanding.
    AwaitingPid1Reaped,
    /// One exact private-mount result branch and the PID-1 reap completed.
    Complete,
}

/// Affine owner of the outer side of one run-bound bootstrap handshake.
#[derive(Debug)]
pub(crate) struct OuterBootstrapControl {
    run_id: RunId,
    phase: OuterBootstrapPhase,
    pid1_pid: Option<u32>,
}

impl OuterBootstrapControl {
    /// Begin an outer exchange for one exact lifecycle run.
    pub(crate) const fn new(run_id: RunId) -> Self {
        Self {
            run_id,
            phase: OuterBootstrapPhase::AwaitingNamespacesCreated,
            pid1_pid: None,
        }
    }

    /// Return the current outer-side phase.
    #[cfg(test)]
    pub(crate) const fn phase(&self) -> OuterBootstrapPhase {
        self.phase
    }

    /// Accept the launcher's sole `NAMESPACES_CREATED` record.
    pub(crate) fn accept_namespaces_created(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), BootstrapControlError> {
        if self.phase != OuterBootstrapPhase::AwaitingNamespacesCreated {
            return Err(BootstrapControlError::StateTransition);
        }
        accept_record(bytes, RecordKind::NamespacesCreated, &self.run_id)?;
        self.phase = OuterBootstrapPhase::NamespacesCreated;
        Ok(())
    }

    /// Emit the outer's sole `MAPPINGS_INSTALLED` record.
    pub(crate) fn mappings_installed(&mut self) -> Result<String, BootstrapControlError> {
        if self.phase != OuterBootstrapPhase::NamespacesCreated {
            return Err(BootstrapControlError::StateTransition);
        }
        let encoded =
            ControlRecord::new(RecordKind::MappingsInstalled, self.run_id.clone()).encode()?;
        self.phase = OuterBootstrapPhase::AwaitingMappingsVerified;
        Ok(encoded)
    }

    /// Accept the launcher's sole `MAPPINGS_VERIFIED` record.
    pub(crate) fn accept_mappings_verified(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), BootstrapControlError> {
        if self.phase != OuterBootstrapPhase::AwaitingMappingsVerified {
            return Err(BootstrapControlError::StateTransition);
        }
        accept_record(bytes, RecordKind::MappingsVerified, &self.run_id)?;
        self.phase = OuterBootstrapPhase::MappingsVerified;
        Ok(())
    }

    /// Emit the sole proceed acknowledgement after the outer independently re-pins the mappings.
    pub(crate) fn mappings_pinned(&mut self) -> Result<String, BootstrapControlError> {
        if self.phase != OuterBootstrapPhase::MappingsVerified {
            return Err(BootstrapControlError::StateTransition);
        }
        let encoded =
            ControlRecord::new(RecordKind::MappingsPinned, self.run_id.clone()).encode()?;
        self.phase = OuterBootstrapPhase::AwaitingPid1Spawned;
        Ok(encoded)
    }

    /// Accept the launcher's sole `PID1_SPAWNED` record and retain its positive PID.
    pub(crate) fn accept_pid1_spawned(
        &mut self,
        bytes: &[u8],
    ) -> Result<u32, BootstrapControlError> {
        if self.phase != OuterBootstrapPhase::AwaitingPid1Spawned {
            return Err(BootstrapControlError::StateTransition);
        }
        let pid = accept_pid_record(bytes, RecordKind::Pid1Spawned, &self.run_id, None)?;
        self.pid1_pid = Some(pid);
        self.phase = OuterBootstrapPhase::Pid1Spawned;
        Ok(pid)
    }

    /// Emit the outer's sole `PID1_PINNED` acknowledgement for the retained PID.
    pub(crate) fn pid1_pinned(&mut self, pid: u32) -> Result<String, BootstrapControlError> {
        if self.phase != OuterBootstrapPhase::Pid1Spawned {
            return Err(BootstrapControlError::StateTransition);
        }
        if self.pid1_pid != Some(pid) {
            return Err(BootstrapControlError::PidMismatch);
        }
        let encoded =
            ControlRecord::for_pid(RecordKind::Pid1Pinned, self.run_id.clone(), pid).encode()?;
        self.phase = OuterBootstrapPhase::AwaitingPrivateMountsReady;
        Ok(encoded)
    }

    /// Accept the launcher's sole `PRIVATE_MOUNTS_READY` record for the retained PID.
    pub(crate) fn accept_private_mounts_ready(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), BootstrapControlError> {
        if self.phase != OuterBootstrapPhase::AwaitingPrivateMountsReady {
            return Err(BootstrapControlError::StateTransition);
        }
        let expected_pid = self
            .pid1_pid
            .ok_or(BootstrapControlError::StateTransition)?;
        accept_pid_record(
            bytes,
            RecordKind::PrivateMountsReady,
            &self.run_id,
            Some(expected_pid),
        )?;
        self.phase = OuterBootstrapPhase::PrivateMountsReady;
        Ok(())
    }

    /// Accept the launcher's sole policy-denied `PRIVATE_MOUNTS_UNAVAILABLE` record.
    pub(crate) fn accept_private_mounts_unavailable(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), BootstrapControlError> {
        if self.phase != OuterBootstrapPhase::AwaitingPrivateMountsReady {
            return Err(BootstrapControlError::StateTransition);
        }
        let expected_pid = self
            .pid1_pid
            .ok_or(BootstrapControlError::StateTransition)?;
        accept_pid_record(
            bytes,
            RecordKind::PrivateMountsUnavailable,
            &self.run_id,
            Some(expected_pid),
        )?;
        self.phase = OuterBootstrapPhase::AwaitingPid1Reaped;
        Ok(())
    }

    /// Emit the outer's sole `PRIVATE_MOUNTS_VERIFIED` acknowledgement for the retained PID.
    pub(crate) fn private_mounts_verified(
        &mut self,
        pid: u32,
    ) -> Result<String, BootstrapControlError> {
        if self.phase != OuterBootstrapPhase::PrivateMountsReady {
            return Err(BootstrapControlError::StateTransition);
        }
        if self.pid1_pid != Some(pid) {
            return Err(BootstrapControlError::PidMismatch);
        }
        let encoded =
            ControlRecord::for_pid(RecordKind::PrivateMountsVerified, self.run_id.clone(), pid)
                .encode()?;
        self.phase = OuterBootstrapPhase::AwaitingMutationRollbackComplete;
        Ok(encoded)
    }

    /// Accept the launcher's sole rollback-complete bridge for the retained PID.
    ///
    /// This records only an internal rollback checkpoint; it does not assert topology readiness,
    /// lifecycle completion, or acceptance evidence.
    pub(crate) fn accept_mutation_rollback_complete(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), BootstrapControlError> {
        if self.phase != OuterBootstrapPhase::AwaitingMutationRollbackComplete {
            return Err(BootstrapControlError::StateTransition);
        }
        let expected_pid = self
            .pid1_pid
            .ok_or(BootstrapControlError::StateTransition)?;
        accept_pid_record(
            bytes,
            RecordKind::MutationRollbackComplete,
            &self.run_id,
            Some(expected_pid),
        )?;
        self.phase = OuterBootstrapPhase::AwaitingSignalObserved;
        Ok(())
    }

    /// Accept the launcher's sole signal observation for the retained PID and expected signal.
    pub(crate) fn accept_pid1_signal_observed(
        &mut self,
        bytes: &[u8],
        expected_signal: ManagedSignal,
    ) -> Result<(), BootstrapControlError> {
        if self.phase != OuterBootstrapPhase::AwaitingSignalObserved {
            return Err(BootstrapControlError::StateTransition);
        }
        let expected_pid = self
            .pid1_pid
            .ok_or(BootstrapControlError::StateTransition)?;
        accept_pid_signal_record(
            bytes,
            RecordKind::Pid1SignalObserved,
            &self.run_id,
            expected_pid,
            expected_signal,
        )?;
        self.phase = OuterBootstrapPhase::AwaitingPid1Reaped;
        Ok(())
    }

    /// Accept the launcher's sole `PID1_REAPED` record for status 77.
    pub(crate) fn accept_pid1_reaped(&mut self, bytes: &[u8]) -> Result<(), BootstrapControlError> {
        if self.phase != OuterBootstrapPhase::AwaitingPid1Reaped {
            return Err(BootstrapControlError::StateTransition);
        }
        let expected_pid = self
            .pid1_pid
            .ok_or(BootstrapControlError::StateTransition)?;
        accept_pid_record(
            bytes,
            RecordKind::Pid1Reaped,
            &self.run_id,
            Some(expected_pid),
        )?;
        self.phase = OuterBootstrapPhase::Complete;
        Ok(())
    }
}

/// Observable launcher-side phase of the fixed mapping and PID-1 proof handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LauncherBootstrapPhase {
    /// The namespace record has not yet been emitted.
    NamespacesCreatedPending,
    /// Waiting for the outer's mapping acknowledgement.
    AwaitingMappingsInstalled,
    /// The mapping acknowledgement was accepted and local verification succeeded.
    MappingsInstalled,
    /// Mapping verification was emitted; the outer mapping pin is outstanding.
    AwaitingMappingsPinned,
    /// The outer mapping pin was accepted; the PID-1 spawn record may be emitted once.
    Pid1SpawnPending,
    /// The exact PID-1 spawn was emitted; the outer pin acknowledgement is outstanding.
    AwaitingPid1Pinned,
    /// The exact PID-1 pin acknowledgement was accepted; mount readiness may be emitted once.
    PrivateMountsReadyPending,
    /// Mount readiness was emitted; the outer verification acknowledgement is outstanding.
    AwaitingPrivateMountsVerified,
    /// Private mounts were verified; the rollback-complete bridge may be emitted once.
    MutationRollbackCompletePending,
    /// Mutation rollback completion was emitted; managed-signal observation is outstanding.
    AwaitingSignalObserved,
    /// One exact mount-result branch completed; PID-1 reap may be emitted once.
    Pid1ReapPending,
    /// One exact private-mount result branch and the PID-1 reap completed.
    Complete,
}

/// Affine owner of the launcher side of one run-bound bootstrap handshake.
#[derive(Debug)]
pub(crate) struct LauncherBootstrapControl {
    run_id: RunId,
    phase: LauncherBootstrapPhase,
    pid1_pid: Option<u32>,
}

impl LauncherBootstrapControl {
    /// Begin a launcher exchange for one exact lifecycle run.
    pub(crate) const fn new(run_id: RunId) -> Self {
        Self {
            run_id,
            phase: LauncherBootstrapPhase::NamespacesCreatedPending,
            pid1_pid: None,
        }
    }

    /// Return the current launcher-side phase.
    #[cfg(test)]
    pub(crate) const fn phase(&self) -> LauncherBootstrapPhase {
        self.phase
    }

    /// Emit the launcher's sole `NAMESPACES_CREATED` record.
    pub(crate) fn namespaces_created(&mut self) -> Result<String, BootstrapControlError> {
        if self.phase != LauncherBootstrapPhase::NamespacesCreatedPending {
            return Err(BootstrapControlError::StateTransition);
        }
        let encoded =
            ControlRecord::new(RecordKind::NamespacesCreated, self.run_id.clone()).encode()?;
        self.phase = LauncherBootstrapPhase::AwaitingMappingsInstalled;
        Ok(encoded)
    }

    /// Accept the outer's sole `MAPPINGS_INSTALLED` record.
    pub(crate) fn accept_mappings_installed(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), BootstrapControlError> {
        if self.phase != LauncherBootstrapPhase::AwaitingMappingsInstalled {
            return Err(BootstrapControlError::StateTransition);
        }
        accept_record(bytes, RecordKind::MappingsInstalled, &self.run_id)?;
        self.phase = LauncherBootstrapPhase::MappingsInstalled;
        Ok(())
    }

    /// Emit the launcher's sole `MAPPINGS_VERIFIED` record.
    pub(crate) fn mappings_verified(&mut self) -> Result<String, BootstrapControlError> {
        if self.phase != LauncherBootstrapPhase::MappingsInstalled {
            return Err(BootstrapControlError::StateTransition);
        }
        let encoded =
            ControlRecord::new(RecordKind::MappingsVerified, self.run_id.clone()).encode()?;
        self.phase = LauncherBootstrapPhase::AwaitingMappingsPinned;
        Ok(encoded)
    }

    /// Accept the outer's sole mapping-pin proceed acknowledgement before spawning PID 1.
    pub(crate) fn accept_mappings_pinned(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), BootstrapControlError> {
        if self.phase != LauncherBootstrapPhase::AwaitingMappingsPinned {
            return Err(BootstrapControlError::StateTransition);
        }
        accept_record(bytes, RecordKind::MappingsPinned, &self.run_id)?;
        self.phase = LauncherBootstrapPhase::Pid1SpawnPending;
        Ok(())
    }

    /// Emit the launcher's sole `PID1_SPAWNED` record for a positive Linux PID.
    pub(crate) fn pid1_spawned(&mut self, pid: u32) -> Result<String, BootstrapControlError> {
        if self.phase != LauncherBootstrapPhase::Pid1SpawnPending {
            return Err(BootstrapControlError::StateTransition);
        }
        let encoded =
            ControlRecord::for_pid(RecordKind::Pid1Spawned, self.run_id.clone(), pid).encode()?;
        self.pid1_pid = Some(pid);
        self.phase = LauncherBootstrapPhase::AwaitingPid1Pinned;
        Ok(encoded)
    }

    /// Accept the outer's sole `PID1_PINNED` acknowledgement for the retained PID.
    pub(crate) fn accept_pid1_pinned(&mut self, bytes: &[u8]) -> Result<(), BootstrapControlError> {
        if self.phase != LauncherBootstrapPhase::AwaitingPid1Pinned {
            return Err(BootstrapControlError::StateTransition);
        }
        let expected_pid = self
            .pid1_pid
            .ok_or(BootstrapControlError::StateTransition)?;
        accept_pid_record(
            bytes,
            RecordKind::Pid1Pinned,
            &self.run_id,
            Some(expected_pid),
        )?;
        self.phase = LauncherBootstrapPhase::PrivateMountsReadyPending;
        Ok(())
    }

    /// Emit the sole `PRIVATE_MOUNTS_READY` record for the retained PID.
    pub(crate) fn private_mounts_ready(
        &mut self,
        pid: u32,
    ) -> Result<String, BootstrapControlError> {
        if self.phase != LauncherBootstrapPhase::PrivateMountsReadyPending {
            return Err(BootstrapControlError::StateTransition);
        }
        if self.pid1_pid != Some(pid) {
            return Err(BootstrapControlError::PidMismatch);
        }
        let encoded =
            ControlRecord::for_pid(RecordKind::PrivateMountsReady, self.run_id.clone(), pid)
                .encode()?;
        self.phase = LauncherBootstrapPhase::AwaitingPrivateMountsVerified;
        Ok(encoded)
    }

    /// Emit the sole policy-denied `PRIVATE_MOUNTS_UNAVAILABLE` record for the retained PID.
    pub(crate) fn private_mounts_unavailable(
        &mut self,
        pid: u32,
    ) -> Result<String, BootstrapControlError> {
        if self.phase != LauncherBootstrapPhase::PrivateMountsReadyPending {
            return Err(BootstrapControlError::StateTransition);
        }
        if self.pid1_pid != Some(pid) {
            return Err(BootstrapControlError::PidMismatch);
        }
        let encoded = ControlRecord::for_pid(
            RecordKind::PrivateMountsUnavailable,
            self.run_id.clone(),
            pid,
        )
        .encode()?;
        self.phase = LauncherBootstrapPhase::Pid1ReapPending;
        Ok(encoded)
    }

    /// Accept the outer's sole `PRIVATE_MOUNTS_VERIFIED` acknowledgement for the retained PID.
    pub(crate) fn accept_private_mounts_verified(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), BootstrapControlError> {
        if self.phase != LauncherBootstrapPhase::AwaitingPrivateMountsVerified {
            return Err(BootstrapControlError::StateTransition);
        }
        let expected_pid = self
            .pid1_pid
            .ok_or(BootstrapControlError::StateTransition)?;
        accept_pid_record(
            bytes,
            RecordKind::PrivateMountsVerified,
            &self.run_id,
            Some(expected_pid),
        )?;
        self.phase = LauncherBootstrapPhase::MutationRollbackCompletePending;
        Ok(())
    }

    /// Emit the sole rollback-complete bridge for the retained PID.
    ///
    /// This records only an internal rollback checkpoint; it does not assert topology readiness,
    /// lifecycle completion, or acceptance evidence.
    pub(crate) fn mutation_rollback_complete(
        &mut self,
        pid: u32,
    ) -> Result<String, BootstrapControlError> {
        if self.phase != LauncherBootstrapPhase::MutationRollbackCompletePending {
            return Err(BootstrapControlError::StateTransition);
        }
        if self.pid1_pid != Some(pid) {
            return Err(BootstrapControlError::PidMismatch);
        }
        let encoded = ControlRecord::for_pid(
            RecordKind::MutationRollbackComplete,
            self.run_id.clone(),
            pid,
        )
        .encode()?;
        self.phase = LauncherBootstrapPhase::AwaitingSignalObserved;
        Ok(encoded)
    }

    /// Emit the sole managed-signal observation for the retained PID.
    pub(crate) fn pid1_signal_observed(
        &mut self,
        pid: u32,
        signal: ManagedSignal,
    ) -> Result<String, BootstrapControlError> {
        if self.phase != LauncherBootstrapPhase::AwaitingSignalObserved {
            return Err(BootstrapControlError::StateTransition);
        }
        if self.pid1_pid != Some(pid) {
            return Err(BootstrapControlError::PidMismatch);
        }
        let encoded =
            ControlRecord::pid1_signal_observed(self.run_id.clone(), pid, signal).encode()?;
        self.phase = LauncherBootstrapPhase::Pid1ReapPending;
        Ok(encoded)
    }

    /// Emit the sole `PID1_REAPED` record for the retained PID and exact status 77.
    pub(crate) fn pid1_reaped(
        &mut self,
        pid: u32,
        status: i32,
    ) -> Result<String, BootstrapControlError> {
        if self.phase != LauncherBootstrapPhase::Pid1ReapPending {
            return Err(BootstrapControlError::StateTransition);
        }
        if self.pid1_pid != Some(pid) {
            return Err(BootstrapControlError::PidMismatch);
        }
        let encoded = ControlRecord::pid1_reaped(self.run_id.clone(), pid, status).encode()?;
        self.phase = LauncherBootstrapPhase::Complete;
        Ok(encoded)
    }
}

fn accept_record(
    bytes: &[u8],
    expected_kind: RecordKind,
    expected_run_id: &RunId,
) -> Result<(), BootstrapControlError> {
    let record = ControlRecord::parse(bytes)?;
    if record.kind != expected_kind {
        return Err(BootstrapControlError::UnexpectedRecord);
    }
    if &record.run_id != expected_run_id {
        return Err(BootstrapControlError::RunIdMismatch);
    }
    Ok(())
}

fn accept_pid_record(
    bytes: &[u8],
    expected_kind: RecordKind,
    expected_run_id: &RunId,
    expected_pid: Option<u32>,
) -> Result<u32, BootstrapControlError> {
    let record = ControlRecord::parse(bytes)?;
    if record.kind != expected_kind {
        return Err(BootstrapControlError::UnexpectedRecord);
    }
    if &record.run_id != expected_run_id {
        return Err(BootstrapControlError::RunIdMismatch);
    }
    let pid = record.pid.ok_or(BootstrapControlError::FrameShape)?;
    if expected_pid.is_some_and(|expected| pid != expected) {
        return Err(BootstrapControlError::PidMismatch);
    }
    Ok(pid)
}

fn accept_pid_signal_record(
    bytes: &[u8],
    expected_kind: RecordKind,
    expected_run_id: &RunId,
    expected_pid: u32,
    expected_signal: ManagedSignal,
) -> Result<(), BootstrapControlError> {
    let record = ControlRecord::parse(bytes)?;
    if record.kind != expected_kind {
        return Err(BootstrapControlError::UnexpectedRecord);
    }
    if &record.run_id != expected_run_id {
        return Err(BootstrapControlError::RunIdMismatch);
    }
    if record.pid != Some(expected_pid) {
        return Err(BootstrapControlError::PidMismatch);
    }
    if record.signal != Some(expected_signal) {
        return Err(BootstrapControlError::SignalMismatch);
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: &str = "0123456789abcdef0123456789abcdef";
    const OTHER_RUN: &str = "fedcba9876543210fedcba9876543210";
    const PID1_PID: u32 = 4242;
    const OTHER_PID: u32 = 4343;

    fn run_id() -> RunId {
        RunId::parse(RUN).expect("canonical run ID")
    }

    fn other_run_id() -> RunId {
        RunId::parse(OTHER_RUN).expect("canonical other run ID")
    }

    fn encoded(kind: RecordKind, run_id: RunId) -> String {
        ControlRecord::new(kind, run_id)
            .encode()
            .expect("bounded record")
    }

    fn pid_encoded(kind: RecordKind, run_id: RunId, pid: u32) -> String {
        ControlRecord::for_pid(kind, run_id, pid)
            .encode()
            .expect("bounded PID record")
    }

    fn reaped_encoded(run_id: RunId, pid: u32) -> String {
        ControlRecord::pid1_reaped(run_id, pid, PID1_REAPED_STATUS)
            .encode()
            .expect("bounded reaped record")
    }

    fn signal_observed_encoded(run_id: RunId, pid: u32, signal: ManagedSignal) -> String {
        ControlRecord::pid1_signal_observed(run_id, pid, signal)
            .encode()
            .expect("bounded signal-observation record")
    }

    fn advance_to_mapping_pin(
        outer: &mut OuterBootstrapControl,
        launcher: &mut LauncherBootstrapControl,
    ) {
        let namespaces = launcher.namespaces_created().expect("namespaces record");
        outer
            .accept_namespaces_created(namespaces.as_bytes())
            .expect("outer accepts namespaces");
        let installed = outer.mappings_installed().expect("mapping record");
        launcher
            .accept_mappings_installed(installed.as_bytes())
            .expect("launcher accepts mapping record");
        let verified = launcher.mappings_verified().expect("verified record");
        outer
            .accept_mappings_verified(verified.as_bytes())
            .expect("outer accepts verification");
    }

    fn complete_mapping_exchange(
        outer: &mut OuterBootstrapControl,
        launcher: &mut LauncherBootstrapControl,
    ) {
        advance_to_mapping_pin(outer, launcher);
        let pinned = outer.mappings_pinned().expect("mapping pin record");
        launcher
            .accept_mappings_pinned(pinned.as_bytes())
            .expect("launcher accepts mapping pin");
    }

    fn complete_pid1_pin_exchange(
        outer: &mut OuterBootstrapControl,
        launcher: &mut LauncherBootstrapControl,
    ) {
        complete_mapping_exchange(outer, launcher);
        let spawned = launcher.pid1_spawned(PID1_PID).expect("spawn record");
        assert_eq!(
            outer
                .accept_pid1_spawned(spawned.as_bytes())
                .expect("outer accepts spawn record"),
            PID1_PID
        );
        let pinned = outer.pid1_pinned(PID1_PID).expect("pin record");
        launcher
            .accept_pid1_pinned(pinned.as_bytes())
            .expect("launcher accepts pin record");
    }

    fn advance_to_private_mounts_after_oversized_rejections(
        oversized: &[u8],
    ) -> (OuterBootstrapControl, LauncherBootstrapControl) {
        let mut outer = OuterBootstrapControl::new(run_id());
        assert_eq!(
            outer.accept_namespaces_created(oversized),
            Err(BootstrapControlError::FrameTooLarge)
        );
        assert_eq!(
            outer.phase(),
            OuterBootstrapPhase::AwaitingNamespacesCreated
        );

        let mut launcher = LauncherBootstrapControl::new(run_id());
        let _ = launcher.namespaces_created().expect("namespaces record");
        assert_eq!(
            launcher.accept_mappings_installed(oversized),
            Err(BootstrapControlError::FrameTooLarge)
        );
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::AwaitingMappingsInstalled
        );

        let mut outer = OuterBootstrapControl::new(run_id());
        let mut launcher = LauncherBootstrapControl::new(run_id());
        complete_mapping_exchange(&mut outer, &mut launcher);
        assert_eq!(
            outer.accept_pid1_spawned(oversized),
            Err(BootstrapControlError::FrameTooLarge)
        );
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingPid1Spawned);

        let spawned = launcher.pid1_spawned(PID1_PID).expect("spawn record");
        outer
            .accept_pid1_spawned(spawned.as_bytes())
            .expect("matching spawn record");
        let _ = outer.pid1_pinned(PID1_PID).expect("pin record");
        assert_eq!(
            launcher.accept_pid1_pinned(oversized),
            Err(BootstrapControlError::FrameTooLarge)
        );
        assert_eq!(launcher.phase(), LauncherBootstrapPhase::AwaitingPid1Pinned);

        let pinned = pid_encoded(RecordKind::Pid1Pinned, run_id(), PID1_PID);
        launcher
            .accept_pid1_pinned(pinned.as_bytes())
            .expect("matching pin record");
        (outer, launcher)
    }

    #[test]
    fn every_record_round_trips_in_exact_canonical_lf_format() {
        for kind in [
            RecordKind::NamespacesCreated,
            RecordKind::MappingsInstalled,
            RecordKind::MappingsVerified,
            RecordKind::MappingsPinned,
        ] {
            let record = ControlRecord::new(kind, run_id());
            let canonical = record.encode().expect("canonical encoding");
            assert_eq!(canonical, format!("{}\nrun_id={RUN}\n", kind.header()));
            assert_eq!(ControlRecord::parse(canonical.as_bytes()), Ok(record));
            assert!(canonical.is_ascii());
            assert!(!canonical.contains('\r'));
            assert_eq!(canonical.as_bytes().last(), Some(&b'\n'));
            assert!(!canonical.ends_with("\n\n"));
            assert!(canonical.len() <= MAX_LIFECYCLE_FRAME_BYTES);
        }

        for kind in [
            RecordKind::Pid1Spawned,
            RecordKind::Pid1Pinned,
            RecordKind::PrivateMountsReady,
            RecordKind::PrivateMountsVerified,
            RecordKind::PrivateMountsUnavailable,
            RecordKind::MutationRollbackComplete,
        ] {
            let record = ControlRecord::for_pid(kind, run_id(), PID1_PID);
            let canonical = record.encode().expect("canonical PID encoding");
            assert_eq!(
                canonical,
                format!("{}\nrun_id={RUN}\npid={PID1_PID}\n", kind.header())
            );
            assert_eq!(ControlRecord::parse(canonical.as_bytes()), Ok(record));
            assert!(canonical.is_ascii());
            assert!(!canonical.contains('\r'));
            assert!(!canonical.contains("fd="));
            assert!(canonical.len() <= MAX_LIFECYCLE_FRAME_BYTES);
        }

        let reaped = ControlRecord::pid1_reaped(run_id(), PID1_PID, PID1_REAPED_STATUS);
        let canonical = reaped.encode().expect("canonical reaped encoding");
        assert_eq!(
            canonical,
            format!("{PID1_REAPED_HEADER}\nrun_id={RUN}\npid={PID1_PID}\nstatus=77\n")
        );
        assert_eq!(ControlRecord::parse(canonical.as_bytes()), Ok(reaped));
        assert!(canonical.is_ascii());
        assert!(!canonical.contains('\r'));
        assert!(!canonical.contains("fd="));
        assert!(canonical.len() <= MAX_LIFECYCLE_FRAME_BYTES);

        for signal in [ManagedSignal::Hup, ManagedSignal::Int, ManagedSignal::Term] {
            let observed = ControlRecord::pid1_signal_observed(run_id(), PID1_PID, signal);
            let canonical = observed.encode().expect("canonical observation encoding");
            assert_eq!(
                canonical,
                format!(
                    "{PID1_SIGNAL_OBSERVED_HEADER}\nrun_id={RUN}\npid={PID1_PID}\nsignal={}\n",
                    signal.as_str()
                )
            );
            assert_eq!(ControlRecord::parse(canonical.as_bytes()), Ok(observed));
            assert!(canonical.is_ascii());
            assert!(!canonical.contains('\r'));
            assert!(!canonical.contains("fd="));
            assert!(canonical.len() <= MAX_LIFECYCLE_FRAME_BYTES);
        }
    }

    #[test]
    fn complete_affine_exchange_has_exact_direction_and_order() {
        let mut outer = OuterBootstrapControl::new(run_id());
        let mut launcher = LauncherBootstrapControl::new(run_id());
        complete_pid1_pin_exchange(&mut outer, &mut launcher);
        assert_eq!(
            outer.phase(),
            OuterBootstrapPhase::AwaitingPrivateMountsReady
        );
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::PrivateMountsReadyPending
        );

        let mounts_ready = launcher
            .private_mounts_ready(PID1_PID)
            .expect("private mounts ready record");
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::AwaitingPrivateMountsVerified
        );
        outer
            .accept_private_mounts_ready(mounts_ready.as_bytes())
            .expect("outer accepts private mounts readiness");
        assert_eq!(outer.phase(), OuterBootstrapPhase::PrivateMountsReady);

        let mounts_verified = outer
            .private_mounts_verified(PID1_PID)
            .expect("private mounts verified record");
        assert_eq!(
            outer.phase(),
            OuterBootstrapPhase::AwaitingMutationRollbackComplete
        );
        launcher
            .accept_private_mounts_verified(mounts_verified.as_bytes())
            .expect("launcher accepts private mounts verification");
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::MutationRollbackCompletePending
        );

        let rollback_complete = launcher
            .mutation_rollback_complete(PID1_PID)
            .expect("mutation rollback checkpoint");
        assert_eq!(
            rollback_complete,
            format!("{MUTATION_ROLLBACK_COMPLETE_HEADER}\nrun_id={RUN}\npid={PID1_PID}\n")
        );
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::AwaitingSignalObserved
        );
        outer
            .accept_mutation_rollback_complete(rollback_complete.as_bytes())
            .expect("outer accepts mutation rollback checkpoint");
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingSignalObserved);

        let signal_observed = launcher
            .pid1_signal_observed(PID1_PID, ManagedSignal::Term)
            .expect("signal-observation record");
        assert_eq!(launcher.phase(), LauncherBootstrapPhase::Pid1ReapPending);
        outer
            .accept_pid1_signal_observed(signal_observed.as_bytes(), ManagedSignal::Term)
            .expect("outer accepts exact signal observation");
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingPid1Reaped);

        let reaped = launcher
            .pid1_reaped(PID1_PID, PID1_REAPED_STATUS)
            .expect("reaped record");
        assert_eq!(launcher.phase(), LauncherBootstrapPhase::Complete);
        outer
            .accept_pid1_reaped(reaped.as_bytes())
            .expect("outer accepts exact reap");
        assert_eq!(outer.phase(), OuterBootstrapPhase::Complete);
    }

    #[test]
    fn malformed_framing_utf8_headers_and_run_ids_are_rejected() {
        let valid = encoded(RecordKind::NamespacesCreated, run_id());
        let missing_final_lf = valid.trim_end_matches('\n').as_bytes().to_vec();
        let mut carriage_return = valid.as_bytes().to_vec();
        carriage_return.insert(NAMESPACES_CREATED_HEADER.len(), b'\r');
        let invalid_utf8 = vec![0xff, b'\n'];

        assert_eq!(
            ControlRecord::parse(b""),
            Err(BootstrapControlError::MissingFinalLineFeed)
        );
        assert_eq!(
            ControlRecord::parse(&missing_final_lf),
            Err(BootstrapControlError::MissingFinalLineFeed)
        );
        assert_eq!(
            ControlRecord::parse(&carriage_return),
            Err(BootstrapControlError::CarriageReturn)
        );
        assert_eq!(
            ControlRecord::parse(&invalid_utf8),
            Err(BootstrapControlError::Utf8)
        );
        for malformed in [
            format!("{NAMESPACES_CREATED_HEADER}\n"),
            format!("VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V2 NAMESPACES_CREATED\nrun_id={RUN}\n"),
            format!("VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V1 UNKNOWN\nrun_id={RUN}\n"),
            format!("{NAMESPACES_CREATED_HEADER}\nrun={RUN}\n"),
            format!("{NAMESPACES_CREATED_HEADER}\nrun_id={RUN}\n\n"),
        ] {
            assert!(matches!(
                ControlRecord::parse(malformed.as_bytes()),
                Err(BootstrapControlError::FrameShape)
            ));
        }
        for invalid_run in [
            "",
            "0123456789abcdef",
            "0123456789abcdef0123456789abcdeF",
            "0123456789abcdef0123456789abcdeg",
            "000000000000000000000000000000000",
            "0123456789abcdef0123456789abcdef=",
        ] {
            let malformed = format!("{NAMESPACES_CREATED_HEADER}\nrun_id={invalid_run}\n");
            assert_eq!(
                ControlRecord::parse(malformed.as_bytes()),
                Err(BootstrapControlError::RunId)
            );
        }
    }

    #[test]
    fn pid_status_and_signal_fields_accept_only_exact_canonical_values() {
        for invalid_pid in [
            "",
            "0",
            "00",
            "01",
            "+1",
            "-1",
            " 1",
            "1 ",
            "1_0",
            "2147483648",
            "4294967295",
            "pid1",
        ] {
            let malformed = format!("{PID1_SPAWNED_HEADER}\nrun_id={RUN}\npid={invalid_pid}\n");
            assert_eq!(
                ControlRecord::parse(malformed.as_bytes()),
                Err(BootstrapControlError::Pid),
                "PID spelling {invalid_pid:?} must fail closed"
            );
        }
        for invalid_status in ["", "0", "76", "078", "+77", "077", "77 ", "255", "-1"] {
            let malformed = format!(
                "{PID1_REAPED_HEADER}\nrun_id={RUN}\npid={PID1_PID}\nstatus={invalid_status}\n"
            );
            assert_eq!(
                ControlRecord::parse(malformed.as_bytes()),
                Err(BootstrapControlError::ExitStatus),
                "status spelling {invalid_status:?} must fail closed"
            );
        }
        for invalid_signal in ["", "term", "SIGTERM", "KILL", "TERM ", " TERM", "TERM\0"] {
            let malformed = format!(
                "{PID1_SIGNAL_OBSERVED_HEADER}\nrun_id={RUN}\npid={PID1_PID}\nsignal={invalid_signal}\n"
            );
            assert_eq!(
                ControlRecord::parse(malformed.as_bytes()),
                Err(BootstrapControlError::Signal),
                "signal spelling {invalid_signal:?} must fail closed"
            );
        }
        assert_eq!(parse_canonical_pid("1"), Ok(1));
        assert_eq!(parse_canonical_pid("2147483647"), Ok(MAX_LINUX_PID));
        assert_eq!(
            ControlRecord::for_pid(RecordKind::Pid1Spawned, run_id(), 0).encode(),
            Err(BootstrapControlError::Pid)
        );
        assert_eq!(
            ControlRecord::pid1_reaped(run_id(), PID1_PID, 0).encode(),
            Err(BootstrapControlError::ExitStatus)
        );
    }

    #[test]
    fn reordered_duplicate_and_extra_fields_are_rejected() {
        for malformed in [
            format!("run_id={RUN}\n{NAMESPACES_CREATED_HEADER}\n"),
            format!("{NAMESPACES_CREATED_HEADER}\nrun_id={RUN}\nrun_id={RUN}\n"),
            format!("{NAMESPACES_CREATED_HEADER}\nextra=true\nrun_id={RUN}\n"),
            format!("{NAMESPACES_CREATED_HEADER}\nrun_id={RUN}\nextra=true\n"),
            format!(
                "{NAMESPACES_CREATED_HEADER}\nrun_id={RUN}\n{MAPPINGS_INSTALLED_HEADER}\nrun_id={RUN}\n"
            ),
            format!("{PID1_SPAWNED_HEADER}\npid={PID1_PID}\nrun_id={RUN}\n"),
            format!("{PID1_SPAWNED_HEADER}\nrun_id={RUN}\npid={PID1_PID}\npid={PID1_PID}\n"),
            format!("{PID1_SPAWNED_HEADER}\nrun_id={RUN}\nstatus=77\npid={PID1_PID}\n"),
            format!("{PID1_SPAWNED_HEADER}\nrun_id={RUN}\npid={PID1_PID}\nstatus=77\n"),
            format!("{PID1_PINNED_HEADER}\nrun_id={RUN}\npid={PID1_PID}\nfd=9\n"),
            format!("{PID1_REAPED_HEADER}\nrun_id={RUN}\nstatus=77\npid={PID1_PID}\n"),
            format!("{PID1_REAPED_HEADER}\nrun_id={RUN}\npid={PID1_PID}\nstatus=77\nfd=9\n"),
            format!("{PID1_SIGNAL_OBSERVED_HEADER}\nrun_id={RUN}\nsignal=TERM\npid={PID1_PID}\n"),
            format!(
                "{PID1_SIGNAL_OBSERVED_HEADER}\nrun_id={RUN}\npid={PID1_PID}\nsignal=TERM\nsignal=TERM\n"
            ),
        ] {
            assert_eq!(
                ControlRecord::parse(malformed.as_bytes()),
                Err(BootstrapControlError::FrameShape)
            );
        }
        assert_eq!(
            ControlRecord::new(RecordKind::Pid1Spawned, run_id()).encode(),
            Err(BootstrapControlError::FrameShape)
        );
        assert_eq!(
            ControlRecord::for_pid(RecordKind::MappingsVerified, run_id(), PID1_PID).encode(),
            Err(BootstrapControlError::FrameShape)
        );
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn wrong_direction_is_rejected_without_advancing_either_state_machine() {
        let namespaces = encoded(RecordKind::NamespacesCreated, run_id());
        let installed = encoded(RecordKind::MappingsInstalled, run_id());
        let verified = encoded(RecordKind::MappingsVerified, run_id());

        let mut outer = OuterBootstrapControl::new(run_id());
        for wrong in [&installed, &verified] {
            assert_eq!(
                outer.accept_namespaces_created(wrong.as_bytes()),
                Err(BootstrapControlError::UnexpectedRecord)
            );
            assert_eq!(
                outer.phase(),
                OuterBootstrapPhase::AwaitingNamespacesCreated
            );
        }
        outer
            .accept_namespaces_created(namespaces.as_bytes())
            .expect("correct namespaces record");
        let _ = outer.mappings_installed().expect("mapping record");
        for wrong in [&namespaces, &installed] {
            assert_eq!(
                outer.accept_mappings_verified(wrong.as_bytes()),
                Err(BootstrapControlError::UnexpectedRecord)
            );
            assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingMappingsVerified);
        }

        let mut launcher = LauncherBootstrapControl::new(run_id());
        let _ = launcher.namespaces_created().expect("namespaces record");
        for wrong in [&namespaces, &verified] {
            assert_eq!(
                launcher.accept_mappings_installed(wrong.as_bytes()),
                Err(BootstrapControlError::UnexpectedRecord)
            );
            assert_eq!(
                launcher.phase(),
                LauncherBootstrapPhase::AwaitingMappingsInstalled
            );
        }

        let mut outer = OuterBootstrapControl::new(run_id());
        let mut launcher = LauncherBootstrapControl::new(run_id());
        complete_mapping_exchange(&mut outer, &mut launcher);
        let spawned = pid_encoded(RecordKind::Pid1Spawned, run_id(), PID1_PID);
        let pinned = pid_encoded(RecordKind::Pid1Pinned, run_id(), PID1_PID);
        let mounts_ready = pid_encoded(RecordKind::PrivateMountsReady, run_id(), PID1_PID);
        let mounts_verified = pid_encoded(RecordKind::PrivateMountsVerified, run_id(), PID1_PID);
        let mounts_unavailable =
            pid_encoded(RecordKind::PrivateMountsUnavailable, run_id(), PID1_PID);
        let rollback_complete =
            pid_encoded(RecordKind::MutationRollbackComplete, run_id(), PID1_PID);
        let signal_observed = signal_observed_encoded(run_id(), PID1_PID, ManagedSignal::Term);
        let reaped = reaped_encoded(run_id(), PID1_PID);

        for wrong in [
            &pinned,
            &mounts_ready,
            &mounts_verified,
            &mounts_unavailable,
            &rollback_complete,
            &reaped,
            &verified,
        ] {
            assert_eq!(
                outer.accept_pid1_spawned(wrong.as_bytes()),
                Err(BootstrapControlError::UnexpectedRecord)
            );
            assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingPid1Spawned);
        }
        outer
            .accept_pid1_spawned(spawned.as_bytes())
            .expect("matching PID-1 spawn");
        let pinned_record = outer.pid1_pinned(PID1_PID).expect("pin record");

        let _ = launcher.pid1_spawned(PID1_PID).expect("spawn record");
        for wrong in [
            &spawned,
            &mounts_ready,
            &mounts_verified,
            &mounts_unavailable,
            &rollback_complete,
            &reaped,
            &installed,
        ] {
            assert_eq!(
                launcher.accept_pid1_pinned(wrong.as_bytes()),
                Err(BootstrapControlError::UnexpectedRecord)
            );
            assert_eq!(launcher.phase(), LauncherBootstrapPhase::AwaitingPid1Pinned);
        }
        launcher
            .accept_pid1_pinned(pinned_record.as_bytes())
            .expect("matching pin record");

        for wrong in [
            &spawned,
            &pinned,
            &mounts_verified,
            &mounts_unavailable,
            &rollback_complete,
            &reaped,
            &verified,
        ] {
            assert_eq!(
                outer.accept_private_mounts_ready(wrong.as_bytes()),
                Err(BootstrapControlError::UnexpectedRecord)
            );
            assert_eq!(
                outer.phase(),
                OuterBootstrapPhase::AwaitingPrivateMountsReady
            );
        }
        let ready_record = launcher
            .private_mounts_ready(PID1_PID)
            .expect("mount-ready record");
        outer
            .accept_private_mounts_ready(ready_record.as_bytes())
            .expect("matching mount-ready record");
        let verified_record = outer
            .private_mounts_verified(PID1_PID)
            .expect("mount-verified record");

        for wrong in [
            &spawned,
            &pinned,
            &mounts_ready,
            &mounts_unavailable,
            &rollback_complete,
            &reaped,
            &installed,
        ] {
            assert_eq!(
                launcher.accept_private_mounts_verified(wrong.as_bytes()),
                Err(BootstrapControlError::UnexpectedRecord)
            );
            assert_eq!(
                launcher.phase(),
                LauncherBootstrapPhase::AwaitingPrivateMountsVerified
            );
        }
        launcher
            .accept_private_mounts_verified(verified_record.as_bytes())
            .expect("matching mount-verified record");

        for wrong in [
            &spawned,
            &pinned,
            &mounts_ready,
            &mounts_verified,
            &mounts_unavailable,
            &signal_observed,
            &reaped,
            &verified,
        ] {
            assert_eq!(
                outer.accept_mutation_rollback_complete(wrong.as_bytes()),
                Err(BootstrapControlError::UnexpectedRecord)
            );
            assert_eq!(
                outer.phase(),
                OuterBootstrapPhase::AwaitingMutationRollbackComplete
            );
        }
        assert_eq!(
            launcher.pid1_signal_observed(PID1_PID, ManagedSignal::Term),
            Err(BootstrapControlError::StateTransition)
        );
        let emitted_rollback = launcher
            .mutation_rollback_complete(PID1_PID)
            .expect("matching rollback checkpoint");
        assert_eq!(emitted_rollback, rollback_complete);
        outer
            .accept_mutation_rollback_complete(emitted_rollback.as_bytes())
            .expect("matching rollback-checkpoint acceptance");

        for wrong in [
            &spawned,
            &pinned,
            &mounts_ready,
            &mounts_verified,
            &mounts_unavailable,
            &rollback_complete,
            &reaped,
            &verified,
        ] {
            assert_eq!(
                outer.accept_pid1_signal_observed(wrong.as_bytes(), ManagedSignal::Term),
                Err(BootstrapControlError::UnexpectedRecord)
            );
            assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingSignalObserved);
        }
        let emitted_observation = launcher
            .pid1_signal_observed(PID1_PID, ManagedSignal::Term)
            .expect("matching signal observation");
        assert_eq!(emitted_observation, signal_observed);
        outer
            .accept_pid1_signal_observed(emitted_observation.as_bytes(), ManagedSignal::Term)
            .expect("matching signal observation acceptance");

        for wrong in [
            &spawned,
            &pinned,
            &mounts_ready,
            &mounts_verified,
            &mounts_unavailable,
            &rollback_complete,
            &signal_observed,
            &verified,
        ] {
            assert_eq!(
                outer.accept_pid1_reaped(wrong.as_bytes()),
                Err(BootstrapControlError::UnexpectedRecord)
            );
            assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingPid1Reaped);
        }
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn wrong_run_is_rejected_at_every_receive_step_without_advancing() {
        let wrong_namespaces = encoded(RecordKind::NamespacesCreated, other_run_id());
        let wrong_installed = encoded(RecordKind::MappingsInstalled, other_run_id());
        let wrong_verified = encoded(RecordKind::MappingsVerified, other_run_id());

        let mut outer = OuterBootstrapControl::new(run_id());
        assert_eq!(
            outer.accept_namespaces_created(wrong_namespaces.as_bytes()),
            Err(BootstrapControlError::RunIdMismatch)
        );
        assert_eq!(
            outer.phase(),
            OuterBootstrapPhase::AwaitingNamespacesCreated
        );
        outer
            .accept_namespaces_created(encoded(RecordKind::NamespacesCreated, run_id()).as_bytes())
            .expect("matching namespaces");
        let _ = outer.mappings_installed().expect("mapping record");
        assert_eq!(
            outer.accept_mappings_verified(wrong_verified.as_bytes()),
            Err(BootstrapControlError::RunIdMismatch)
        );
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingMappingsVerified);

        let mut launcher = LauncherBootstrapControl::new(run_id());
        let _ = launcher.namespaces_created().expect("namespaces record");
        assert_eq!(
            launcher.accept_mappings_installed(wrong_installed.as_bytes()),
            Err(BootstrapControlError::RunIdMismatch)
        );
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::AwaitingMappingsInstalled
        );

        let mut outer = OuterBootstrapControl::new(run_id());
        let mut launcher = LauncherBootstrapControl::new(run_id());
        complete_mapping_exchange(&mut outer, &mut launcher);
        let wrong_spawned = pid_encoded(RecordKind::Pid1Spawned, other_run_id(), PID1_PID);
        assert_eq!(
            outer.accept_pid1_spawned(wrong_spawned.as_bytes()),
            Err(BootstrapControlError::RunIdMismatch)
        );
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingPid1Spawned);

        let spawned = launcher.pid1_spawned(PID1_PID).expect("spawn record");
        outer
            .accept_pid1_spawned(spawned.as_bytes())
            .expect("matching spawn record");
        let wrong_pinned = pid_encoded(RecordKind::Pid1Pinned, other_run_id(), PID1_PID);
        assert_eq!(
            launcher.accept_pid1_pinned(wrong_pinned.as_bytes()),
            Err(BootstrapControlError::RunIdMismatch)
        );
        assert_eq!(launcher.phase(), LauncherBootstrapPhase::AwaitingPid1Pinned);

        let pinned = outer.pid1_pinned(PID1_PID).expect("pin record");
        launcher
            .accept_pid1_pinned(pinned.as_bytes())
            .expect("matching pin record");

        let wrong_mounts_ready =
            pid_encoded(RecordKind::PrivateMountsReady, other_run_id(), PID1_PID);
        assert_eq!(
            outer.accept_private_mounts_ready(wrong_mounts_ready.as_bytes()),
            Err(BootstrapControlError::RunIdMismatch)
        );
        assert_eq!(
            outer.phase(),
            OuterBootstrapPhase::AwaitingPrivateMountsReady
        );
        let mounts_ready = launcher
            .private_mounts_ready(PID1_PID)
            .expect("matching mounts-ready record");
        outer
            .accept_private_mounts_ready(mounts_ready.as_bytes())
            .expect("accept matching mounts-ready record");

        let mounts_verified = outer
            .private_mounts_verified(PID1_PID)
            .expect("matching mounts-verified record");
        let wrong_mounts_verified =
            pid_encoded(RecordKind::PrivateMountsVerified, other_run_id(), PID1_PID);
        assert_eq!(
            launcher.accept_private_mounts_verified(wrong_mounts_verified.as_bytes()),
            Err(BootstrapControlError::RunIdMismatch)
        );
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::AwaitingPrivateMountsVerified
        );
        launcher
            .accept_private_mounts_verified(mounts_verified.as_bytes())
            .expect("accept matching mounts-verified record");

        let wrong_rollback = pid_encoded(
            RecordKind::MutationRollbackComplete,
            other_run_id(),
            PID1_PID,
        );
        assert_eq!(
            outer.accept_mutation_rollback_complete(wrong_rollback.as_bytes()),
            Err(BootstrapControlError::RunIdMismatch)
        );
        assert_eq!(
            outer.phase(),
            OuterBootstrapPhase::AwaitingMutationRollbackComplete
        );
        let rollback = launcher
            .mutation_rollback_complete(PID1_PID)
            .expect("matching rollback checkpoint");
        outer
            .accept_mutation_rollback_complete(rollback.as_bytes())
            .expect("accept matching rollback checkpoint");

        let wrong_observation =
            signal_observed_encoded(other_run_id(), PID1_PID, ManagedSignal::Term);
        assert_eq!(
            outer.accept_pid1_signal_observed(wrong_observation.as_bytes(), ManagedSignal::Term),
            Err(BootstrapControlError::RunIdMismatch)
        );
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingSignalObserved);
        let observation = launcher
            .pid1_signal_observed(PID1_PID, ManagedSignal::Term)
            .expect("matching signal observation");
        outer
            .accept_pid1_signal_observed(observation.as_bytes(), ManagedSignal::Term)
            .expect("accept matching signal observation");

        let wrong_reaped = reaped_encoded(other_run_id(), PID1_PID);
        assert_eq!(
            outer.accept_pid1_reaped(wrong_reaped.as_bytes()),
            Err(BootstrapControlError::RunIdMismatch)
        );
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingPid1Reaped);
    }

    #[test]
    fn mapping_pin_rejects_the_wrong_run_without_enabling_pid_one_spawn() {
        let mut outer = OuterBootstrapControl::new(run_id());
        let mut launcher = LauncherBootstrapControl::new(run_id());
        advance_to_mapping_pin(&mut outer, &mut launcher);

        let wrong = encoded(RecordKind::MappingsPinned, other_run_id());
        assert_eq!(
            launcher.accept_mappings_pinned(wrong.as_bytes()),
            Err(BootstrapControlError::RunIdMismatch)
        );
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::AwaitingMappingsPinned
        );
        assert_eq!(
            launcher.pid1_spawned(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );

        let pinned = outer.mappings_pinned().expect("matching mapping pin");
        launcher
            .accept_mappings_pinned(pinned.as_bytes())
            .expect("accept matching mapping pin");
        assert_eq!(launcher.phase(), LauncherBootstrapPhase::Pid1SpawnPending);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn wrong_pid_is_rejected_at_every_bound_step_without_advancing() {
        let mut outer = OuterBootstrapControl::new(run_id());
        let mut launcher = LauncherBootstrapControl::new(run_id());
        complete_mapping_exchange(&mut outer, &mut launcher);

        let spawned = launcher.pid1_spawned(PID1_PID).expect("spawn record");
        outer
            .accept_pid1_spawned(spawned.as_bytes())
            .expect("matching spawn record");
        assert_eq!(
            outer.pid1_pinned(OTHER_PID),
            Err(BootstrapControlError::PidMismatch)
        );
        assert_eq!(outer.phase(), OuterBootstrapPhase::Pid1Spawned);
        let pinned = outer.pid1_pinned(PID1_PID).expect("pin record");

        let wrong_pinned = pid_encoded(RecordKind::Pid1Pinned, run_id(), OTHER_PID);
        assert_eq!(
            launcher.accept_pid1_pinned(wrong_pinned.as_bytes()),
            Err(BootstrapControlError::PidMismatch)
        );
        assert_eq!(launcher.phase(), LauncherBootstrapPhase::AwaitingPid1Pinned);
        launcher
            .accept_pid1_pinned(pinned.as_bytes())
            .expect("matching pin record");

        assert_eq!(
            launcher.private_mounts_ready(OTHER_PID),
            Err(BootstrapControlError::PidMismatch)
        );
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::PrivateMountsReadyPending
        );
        let wrong_ready = pid_encoded(RecordKind::PrivateMountsReady, run_id(), OTHER_PID);
        assert_eq!(
            outer.accept_private_mounts_ready(wrong_ready.as_bytes()),
            Err(BootstrapControlError::PidMismatch)
        );
        assert_eq!(
            outer.phase(),
            OuterBootstrapPhase::AwaitingPrivateMountsReady
        );

        let ready = launcher
            .private_mounts_ready(PID1_PID)
            .expect("matching mount-ready record");
        outer
            .accept_private_mounts_ready(ready.as_bytes())
            .expect("matching mount-ready acceptance");
        assert_eq!(
            outer.private_mounts_verified(OTHER_PID),
            Err(BootstrapControlError::PidMismatch)
        );
        assert_eq!(outer.phase(), OuterBootstrapPhase::PrivateMountsReady);
        let verified = outer
            .private_mounts_verified(PID1_PID)
            .expect("matching mount-verified record");
        let wrong_verified = pid_encoded(RecordKind::PrivateMountsVerified, run_id(), OTHER_PID);
        assert_eq!(
            launcher.accept_private_mounts_verified(wrong_verified.as_bytes()),
            Err(BootstrapControlError::PidMismatch)
        );
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::AwaitingPrivateMountsVerified
        );
        launcher
            .accept_private_mounts_verified(verified.as_bytes())
            .expect("matching mount-verified acceptance");

        assert_eq!(
            launcher.mutation_rollback_complete(OTHER_PID),
            Err(BootstrapControlError::PidMismatch)
        );
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::MutationRollbackCompletePending
        );
        let wrong_rollback = pid_encoded(RecordKind::MutationRollbackComplete, run_id(), OTHER_PID);
        assert_eq!(
            outer.accept_mutation_rollback_complete(wrong_rollback.as_bytes()),
            Err(BootstrapControlError::PidMismatch)
        );
        assert_eq!(
            outer.phase(),
            OuterBootstrapPhase::AwaitingMutationRollbackComplete
        );
        let rollback = launcher
            .mutation_rollback_complete(PID1_PID)
            .expect("matching rollback checkpoint");
        outer
            .accept_mutation_rollback_complete(rollback.as_bytes())
            .expect("matching rollback-checkpoint acceptance");

        assert_eq!(
            launcher.pid1_signal_observed(OTHER_PID, ManagedSignal::Term),
            Err(BootstrapControlError::PidMismatch)
        );
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::AwaitingSignalObserved
        );
        let wrong_observation = signal_observed_encoded(run_id(), OTHER_PID, ManagedSignal::Term);
        assert_eq!(
            outer.accept_pid1_signal_observed(wrong_observation.as_bytes(), ManagedSignal::Term),
            Err(BootstrapControlError::PidMismatch)
        );
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingSignalObserved);
        let observation = launcher
            .pid1_signal_observed(PID1_PID, ManagedSignal::Term)
            .expect("matching observation");
        outer
            .accept_pid1_signal_observed(observation.as_bytes(), ManagedSignal::Term)
            .expect("matching observation acceptance");

        assert_eq!(
            launcher.pid1_reaped(OTHER_PID, PID1_REAPED_STATUS),
            Err(BootstrapControlError::PidMismatch)
        );
        assert_eq!(launcher.phase(), LauncherBootstrapPhase::Pid1ReapPending);
        let wrong_status =
            format!("{PID1_REAPED_HEADER}\nrun_id={RUN}\npid={PID1_PID}\nstatus=76\n");
        assert_eq!(
            outer.accept_pid1_reaped(wrong_status.as_bytes()),
            Err(BootstrapControlError::ExitStatus)
        );
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingPid1Reaped);
        let wrong_reaped = reaped_encoded(run_id(), OTHER_PID);
        assert_eq!(
            outer.accept_pid1_reaped(wrong_reaped.as_bytes()),
            Err(BootstrapControlError::PidMismatch)
        );
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingPid1Reaped);
    }

    #[test]
    fn duplicate_and_out_of_order_transitions_are_affinely_rejected() {
        let mut launcher = LauncherBootstrapControl::new(run_id());
        assert_eq!(
            launcher.mappings_verified(),
            Err(BootstrapControlError::StateTransition)
        );
        let namespaces = launcher.namespaces_created().expect("first emission");
        assert_eq!(
            launcher.namespaces_created(),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.mappings_verified(),
            Err(BootstrapControlError::StateTransition)
        );

        let mut outer = OuterBootstrapControl::new(run_id());
        assert_eq!(
            outer.mappings_installed(),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            outer.accept_mappings_verified(
                encoded(RecordKind::MappingsVerified, run_id()).as_bytes()
            ),
            Err(BootstrapControlError::StateTransition)
        );
        outer
            .accept_namespaces_created(namespaces.as_bytes())
            .expect("first acceptance");
        assert_eq!(
            outer.accept_namespaces_created(namespaces.as_bytes()),
            Err(BootstrapControlError::StateTransition)
        );
        let installed = outer.mappings_installed().expect("first mapping emission");
        assert_eq!(
            outer.mappings_installed(),
            Err(BootstrapControlError::StateTransition)
        );
        launcher
            .accept_mappings_installed(installed.as_bytes())
            .expect("first mapping acceptance");
        assert_eq!(
            launcher.accept_mappings_installed(installed.as_bytes()),
            Err(BootstrapControlError::StateTransition)
        );
        let verified = launcher.mappings_verified().expect("first verification");
        assert_eq!(
            launcher.mappings_verified(),
            Err(BootstrapControlError::StateTransition)
        );
        outer
            .accept_mappings_verified(verified.as_bytes())
            .expect("first verification acceptance");
        assert_eq!(
            outer.accept_mappings_verified(verified.as_bytes()),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.accept_mappings_pinned(&vec![0xff; MAX_LIFECYCLE_FRAME_BYTES + 1]),
            Err(BootstrapControlError::FrameTooLarge)
        );
        assert_eq!(
            launcher.accept_mappings_pinned(installed.as_bytes()),
            Err(BootstrapControlError::UnexpectedRecord)
        );
        assert_eq!(
            launcher.pid1_spawned(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::AwaitingMappingsPinned
        );
        let mapping_pin = outer.mappings_pinned().expect("first mapping pin");
        assert_eq!(
            outer.mappings_pinned(),
            Err(BootstrapControlError::StateTransition)
        );
        launcher
            .accept_mappings_pinned(mapping_pin.as_bytes())
            .expect("first mapping pin acceptance");
        assert_eq!(
            launcher.accept_mappings_pinned(mapping_pin.as_bytes()),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(launcher.phase(), LauncherBootstrapPhase::Pid1SpawnPending);
    }

    #[test]
    #[allow(clippy::too_many_lines)]
    fn pid1_duplicate_invalid_and_out_of_order_transitions_are_affinely_rejected() {
        let mut outer = OuterBootstrapControl::new(run_id());
        let mut launcher = LauncherBootstrapControl::new(run_id());
        complete_mapping_exchange(&mut outer, &mut launcher);

        assert_eq!(
            outer.pid1_pinned(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            outer.accept_pid1_reaped(reaped_encoded(run_id(), PID1_PID).as_bytes()),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            outer.accept_pid1_signal_observed(
                signal_observed_encoded(run_id(), PID1_PID, ManagedSignal::Term).as_bytes(),
                ManagedSignal::Term
            ),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            outer.accept_private_mounts_ready(
                pid_encoded(RecordKind::PrivateMountsReady, run_id(), PID1_PID).as_bytes()
            ),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            outer.accept_private_mounts_unavailable(
                pid_encoded(RecordKind::PrivateMountsUnavailable, run_id(), PID1_PID,).as_bytes()
            ),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            outer.private_mounts_verified(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            outer.accept_mutation_rollback_complete(
                pid_encoded(RecordKind::MutationRollbackComplete, run_id(), PID1_PID,).as_bytes()
            ),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.accept_pid1_pinned(
                pid_encoded(RecordKind::Pid1Pinned, run_id(), PID1_PID).as_bytes()
            ),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.pid1_reaped(PID1_PID, PID1_REAPED_STATUS),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.pid1_signal_observed(PID1_PID, ManagedSignal::Term),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.private_mounts_ready(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.private_mounts_unavailable(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.accept_private_mounts_verified(
                pid_encoded(RecordKind::PrivateMountsVerified, run_id(), PID1_PID).as_bytes()
            ),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.mutation_rollback_complete(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );

        let malformed_pid = format!("{PID1_SPAWNED_HEADER}\nrun_id={RUN}\npid=0\n");
        assert_eq!(
            outer.accept_pid1_spawned(malformed_pid.as_bytes()),
            Err(BootstrapControlError::Pid)
        );
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingPid1Spawned);
        assert_eq!(launcher.pid1_spawned(0), Err(BootstrapControlError::Pid));
        assert_eq!(launcher.phase(), LauncherBootstrapPhase::Pid1SpawnPending);

        let spawned = launcher.pid1_spawned(PID1_PID).expect("first spawn");
        assert_eq!(
            launcher.pid1_spawned(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );
        outer
            .accept_pid1_spawned(spawned.as_bytes())
            .expect("first spawn acceptance");
        assert_eq!(
            outer.accept_pid1_spawned(spawned.as_bytes()),
            Err(BootstrapControlError::StateTransition)
        );

        let pinned = outer.pid1_pinned(PID1_PID).expect("first pin");
        assert_eq!(
            outer.pid1_pinned(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );
        launcher
            .accept_pid1_pinned(pinned.as_bytes())
            .expect("first pin acceptance");
        assert_eq!(
            launcher.accept_pid1_pinned(pinned.as_bytes()),
            Err(BootstrapControlError::StateTransition)
        );

        let ready = launcher
            .private_mounts_ready(PID1_PID)
            .expect("first mount-ready emission");
        assert_eq!(
            launcher.private_mounts_ready(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.private_mounts_unavailable(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );
        outer
            .accept_private_mounts_ready(ready.as_bytes())
            .expect("first mount-ready acceptance");
        assert_eq!(
            outer.accept_private_mounts_ready(ready.as_bytes()),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            outer.accept_private_mounts_unavailable(
                pid_encoded(RecordKind::PrivateMountsUnavailable, run_id(), PID1_PID,).as_bytes()
            ),
            Err(BootstrapControlError::StateTransition)
        );

        let mounts_verified = outer
            .private_mounts_verified(PID1_PID)
            .expect("first mount-verified emission");
        assert_eq!(
            outer.private_mounts_verified(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );
        launcher
            .accept_private_mounts_verified(mounts_verified.as_bytes())
            .expect("first mount-verified acceptance");
        assert_eq!(
            launcher.accept_private_mounts_verified(mounts_verified.as_bytes()),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.private_mounts_unavailable(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.pid1_reaped(PID1_PID, 0),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::MutationRollbackCompletePending
        );
        assert_eq!(
            outer.accept_pid1_signal_observed(
                signal_observed_encoded(run_id(), PID1_PID, ManagedSignal::Term).as_bytes(),
                ManagedSignal::Term
            ),
            Err(BootstrapControlError::StateTransition)
        );
        let rollback = launcher
            .mutation_rollback_complete(PID1_PID)
            .expect("first rollback-checkpoint emission");
        assert_eq!(
            launcher.mutation_rollback_complete(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );
        outer
            .accept_mutation_rollback_complete(rollback.as_bytes())
            .expect("first rollback-checkpoint acceptance");
        assert_eq!(
            outer.accept_mutation_rollback_complete(rollback.as_bytes()),
            Err(BootstrapControlError::StateTransition)
        );
        let wrong_signal = signal_observed_encoded(run_id(), PID1_PID, ManagedSignal::Hup);
        assert_eq!(
            outer.accept_pid1_signal_observed(wrong_signal.as_bytes(), ManagedSignal::Term),
            Err(BootstrapControlError::SignalMismatch)
        );
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingSignalObserved);

        let observed = launcher
            .pid1_signal_observed(PID1_PID, ManagedSignal::Term)
            .expect("first signal observation");
        assert_eq!(
            launcher.pid1_signal_observed(PID1_PID, ManagedSignal::Term),
            Err(BootstrapControlError::StateTransition)
        );
        outer
            .accept_pid1_signal_observed(observed.as_bytes(), ManagedSignal::Term)
            .expect("first signal-observation acceptance");
        assert_eq!(
            outer.accept_pid1_signal_observed(observed.as_bytes(), ManagedSignal::Term),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(launcher.phase(), LauncherBootstrapPhase::Pid1ReapPending);
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingPid1Reaped);

        assert_eq!(
            launcher.pid1_reaped(PID1_PID, 0),
            Err(BootstrapControlError::ExitStatus)
        );
        assert_eq!(launcher.phase(), LauncherBootstrapPhase::Pid1ReapPending);

        let reaped = launcher
            .pid1_reaped(PID1_PID, PID1_REAPED_STATUS)
            .expect("first reap");
        assert_eq!(
            launcher.pid1_reaped(PID1_PID, PID1_REAPED_STATUS),
            Err(BootstrapControlError::StateTransition)
        );
        outer
            .accept_pid1_reaped(reaped.as_bytes())
            .expect("first reap acceptance");
        assert_eq!(
            outer.accept_pid1_reaped(reaped.as_bytes()),
            Err(BootstrapControlError::StateTransition)
        );
    }

    #[test]
    fn private_mounts_unavailable_is_an_exclusive_affine_terminal_result() {
        let mut outer = OuterBootstrapControl::new(run_id());
        let mut launcher = LauncherBootstrapControl::new(run_id());
        complete_pid1_pin_exchange(&mut outer, &mut launcher);

        assert_eq!(
            launcher.private_mounts_unavailable(OTHER_PID),
            Err(BootstrapControlError::PidMismatch)
        );
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::PrivateMountsReadyPending
        );
        let unavailable = launcher
            .private_mounts_unavailable(PID1_PID)
            .expect("policy-denied mount result");
        assert_eq!(
            unavailable,
            format!("{PRIVATE_MOUNTS_UNAVAILABLE_HEADER}\nrun_id={RUN}\npid={PID1_PID}\n")
        );
        assert_eq!(launcher.phase(), LauncherBootstrapPhase::Pid1ReapPending);
        assert_eq!(
            launcher.private_mounts_unavailable(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.private_mounts_ready(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.accept_private_mounts_verified(
                pid_encoded(RecordKind::PrivateMountsVerified, run_id(), PID1_PID).as_bytes()
            ),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            launcher.mutation_rollback_complete(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );

        let wrong_run = pid_encoded(
            RecordKind::PrivateMountsUnavailable,
            other_run_id(),
            PID1_PID,
        );
        assert_eq!(
            outer.accept_private_mounts_unavailable(wrong_run.as_bytes()),
            Err(BootstrapControlError::RunIdMismatch)
        );
        let wrong_pid = pid_encoded(RecordKind::PrivateMountsUnavailable, run_id(), OTHER_PID);
        assert_eq!(
            outer.accept_private_mounts_unavailable(wrong_pid.as_bytes()),
            Err(BootstrapControlError::PidMismatch)
        );
        assert_eq!(
            outer.phase(),
            OuterBootstrapPhase::AwaitingPrivateMountsReady
        );
        outer
            .accept_private_mounts_unavailable(unavailable.as_bytes())
            .expect("accept policy-denied mount result");
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingPid1Reaped);
        assert_eq!(
            outer.accept_private_mounts_unavailable(unavailable.as_bytes()),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            outer.accept_private_mounts_ready(
                pid_encoded(RecordKind::PrivateMountsReady, run_id(), PID1_PID).as_bytes()
            ),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            outer.private_mounts_verified(PID1_PID),
            Err(BootstrapControlError::StateTransition)
        );
        assert_eq!(
            outer.accept_mutation_rollback_complete(
                pid_encoded(RecordKind::MutationRollbackComplete, run_id(), PID1_PID).as_bytes()
            ),
            Err(BootstrapControlError::StateTransition)
        );

        let reaped = launcher
            .pid1_reaped(PID1_PID, PID1_REAPED_STATUS)
            .expect("policy-denied PID-1 reap");
        outer
            .accept_pid1_reaped(reaped.as_bytes())
            .expect("accept policy-denied PID-1 reap");
        assert_eq!(launcher.phase(), LauncherBootstrapPhase::Complete);
        assert_eq!(outer.phase(), OuterBootstrapPhase::Complete);
    }

    #[test]
    fn oversized_input_is_rejected_before_utf8_or_shape_and_state_does_not_advance() {
        let oversized = vec![0xff; MAX_LIFECYCLE_FRAME_BYTES + 1];
        assert_eq!(
            ControlRecord::parse(&oversized),
            Err(BootstrapControlError::FrameTooLarge)
        );

        let (mut outer, mut launcher) =
            advance_to_private_mounts_after_oversized_rejections(&oversized);
        assert_eq!(
            outer.accept_private_mounts_ready(&oversized),
            Err(BootstrapControlError::FrameTooLarge)
        );
        assert_eq!(
            outer.accept_private_mounts_unavailable(&oversized),
            Err(BootstrapControlError::FrameTooLarge)
        );
        assert_eq!(
            outer.phase(),
            OuterBootstrapPhase::AwaitingPrivateMountsReady
        );

        let ready = launcher
            .private_mounts_ready(PID1_PID)
            .expect("mount-ready record");
        outer
            .accept_private_mounts_ready(ready.as_bytes())
            .expect("matching mount-ready record");
        let mounts_verified = outer
            .private_mounts_verified(PID1_PID)
            .expect("mount-verified record");
        assert_eq!(
            launcher.accept_private_mounts_verified(&oversized),
            Err(BootstrapControlError::FrameTooLarge)
        );
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::AwaitingPrivateMountsVerified
        );
        launcher
            .accept_private_mounts_verified(mounts_verified.as_bytes())
            .expect("matching mount-verified record");
        assert_eq!(
            outer.accept_mutation_rollback_complete(&oversized),
            Err(BootstrapControlError::FrameTooLarge)
        );
        assert_eq!(
            outer.phase(),
            OuterBootstrapPhase::AwaitingMutationRollbackComplete
        );
        let rollback = launcher
            .mutation_rollback_complete(PID1_PID)
            .expect("matching rollback-checkpoint record");
        outer
            .accept_mutation_rollback_complete(rollback.as_bytes())
            .expect("matching rollback-checkpoint acceptance");
        assert_eq!(
            outer.accept_pid1_signal_observed(&oversized, ManagedSignal::Term),
            Err(BootstrapControlError::FrameTooLarge)
        );
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingSignalObserved);
        let observed = launcher
            .pid1_signal_observed(PID1_PID, ManagedSignal::Term)
            .expect("matching signal-observation record");
        outer
            .accept_pid1_signal_observed(observed.as_bytes(), ManagedSignal::Term)
            .expect("matching signal-observation acceptance");
        assert_eq!(
            outer.accept_pid1_reaped(&oversized),
            Err(BootstrapControlError::FrameTooLarge)
        );
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingPid1Reaped);
    }
}
