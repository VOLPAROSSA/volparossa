use std::str;

use thiserror::Error;
use volparossa_test_support::{MAX_LIFECYCLE_FRAME_BYTES, NamespaceIdentity, RunId};

const PROVISION_HEADER: &str = "VOLPAROSSA_NETNS_PID1_CONTROL_V1 PROVISION";
const PARENT_DEATH_ARMED_HEADER: &str = "VOLPAROSSA_NETNS_PID1_CONTROL_V1 PARENT_DEATH_ARMED";
const PARENT_ALIVE_HEADER: &str = "VOLPAROSSA_NETNS_PID1_CONTROL_V1 PARENT_ALIVE";
const EXECUTED_HEADER: &str = "VOLPAROSSA_NETNS_PID1_CONTROL_V1 EXECUTED";
const ABORT_BEFORE_PRIVATE_MOUNTS_HEADER: &str =
    "VOLPAROSSA_NETNS_PID1_CONTROL_V1 ABORT_BEFORE_PRIVATE_MOUNTS";
const SETUP_PRIVATE_MOUNTS_HEADER: &str = "VOLPAROSSA_NETNS_PID1_CONTROL_V1 SETUP_PRIVATE_MOUNTS";
const PRIVATE_MOUNTS_READY_HEADER: &str = "VOLPAROSSA_NETNS_PID1_CONTROL_V1 PRIVATE_MOUNTS_READY";
const PRIVATE_MOUNTS_VERIFIED_HEADER: &str =
    "VOLPAROSSA_NETNS_PID1_CONTROL_V1 PRIVATE_MOUNTS_VERIFIED";
const PRIVATE_MOUNTS_UNAVAILABLE_HEADER: &str =
    "VOLPAROSSA_NETNS_PID1_CONTROL_V1 PRIVATE_MOUNTS_UNAVAILABLE";
const EXPECT_LIFECYCLE_EOF_HEADER: &str = "VOLPAROSSA_NETNS_PID1_CONTROL_V1 EXPECT_LIFECYCLE_EOF";
const LIFECYCLE_EOF_HEADER: &str = "VOLPAROSSA_NETNS_PID1_CONTROL_V1 LIFECYCLE_EOF";

#[derive(Clone, Debug, Eq, Error, PartialEq)]
pub(crate) enum PidOneControlError {
    #[error("PID-1 control record exceeds its fixed size bound")]
    FrameTooLarge,
    #[error("PID-1 control record framing is not canonical")]
    Framing,
    #[error("PID-1 control record is not UTF-8")]
    Utf8,
    #[error("PID-1 control record shape is not canonical")]
    Shape,
    #[error("PID-1 control run identifier is invalid")]
    RunId,
    #[error("PID-1 control namespace identity is invalid")]
    Namespace,
    #[error("PID-1 control decimal is invalid")]
    Decimal,
    #[error("PID-1 control record used the wrong run identifier")]
    RunIdMismatch,
    #[error("PID-1 control record appeared in the wrong direction or order")]
    StateTransition,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub(crate) struct PidOneProvision {
    run_id: RunId,
    user_namespace: NamespaceIdentity,
    network_namespace: NamespaceIdentity,
    mount_namespace: NamespaceIdentity,
    pid_namespace: NamespaceIdentity,
    outer_user_id: u32,
    outer_group_id: u32,
}

impl PidOneProvision {
    pub(crate) fn new(
        run_id: RunId,
        user_namespace: NamespaceIdentity,
        network_namespace: NamespaceIdentity,
        mount_namespace: NamespaceIdentity,
        pid_namespace: NamespaceIdentity,
        outer_user_id: u32,
        outer_group_id: u32,
    ) -> Result<Self, PidOneControlError> {
        let identities = [
            user_namespace,
            network_namespace,
            mount_namespace,
            pid_namespace,
        ];
        for (index, identity) in identities.iter().enumerate() {
            if identities[index.saturating_add(1)..].contains(identity) {
                return Err(PidOneControlError::Namespace);
            }
        }
        Ok(Self {
            run_id,
            user_namespace,
            network_namespace,
            mount_namespace,
            pid_namespace,
            outer_user_id,
            outer_group_id,
        })
    }

    pub(crate) const fn run_id(&self) -> &RunId {
        &self.run_id
    }

    pub(crate) const fn user_namespace(&self) -> NamespaceIdentity {
        self.user_namespace
    }

    pub(crate) const fn network_namespace(&self) -> NamespaceIdentity {
        self.network_namespace
    }

    pub(crate) const fn mount_namespace(&self) -> NamespaceIdentity {
        self.mount_namespace
    }

    pub(crate) const fn pid_namespace(&self) -> NamespaceIdentity {
        self.pid_namespace
    }

    pub(crate) const fn outer_user_id(&self) -> u32 {
        self.outer_user_id
    }

    pub(crate) const fn outer_group_id(&self) -> u32 {
        self.outer_group_id
    }

    fn encode(&self) -> Result<String, PidOneControlError> {
        encode_lines(&[
            PROVISION_HEADER.to_owned(),
            format!("run_id={}", self.run_id.as_str()),
            format!("user_ns_dev={}", self.user_namespace.device()),
            format!("user_ns_inode={}", self.user_namespace.inode()),
            format!("net_ns_dev={}", self.network_namespace.device()),
            format!("net_ns_inode={}", self.network_namespace.inode()),
            format!("mount_ns_dev={}", self.mount_namespace.device()),
            format!("mount_ns_inode={}", self.mount_namespace.inode()),
            format!("pid_ns_dev={}", self.pid_namespace.device()),
            format!("pid_ns_inode={}", self.pid_namespace.inode()),
            format!("outer_uid={}", self.outer_user_id),
            format!("outer_gid={}", self.outer_group_id),
        ])
    }

    fn parse(bytes: &[u8]) -> Result<Self, PidOneControlError> {
        let lines = decode_lines(bytes)?;
        if lines.len() != 12 || lines[0] != PROVISION_HEADER {
            return Err(PidOneControlError::Shape);
        }
        let provision = Self::new(
            RunId::parse(field(&lines, 1, "run_id")?).map_err(|_| PidOneControlError::RunId)?,
            namespace(&lines, 2, "user_ns_dev", "user_ns_inode")?,
            namespace(&lines, 4, "net_ns_dev", "net_ns_inode")?,
            namespace(&lines, 6, "mount_ns_dev", "mount_ns_inode")?,
            namespace(&lines, 8, "pid_ns_dev", "pid_ns_inode")?,
            parse_u32(field(&lines, 10, "outer_uid")?)?,
            parse_u32(field(&lines, 11, "outer_gid")?)?,
        )?;
        require_canonical(bytes, &provision.encode()?)?;
        Ok(provision)
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum SimpleKind {
    ParentDeathArmed,
    ParentAlive,
    Executed,
    AbortBeforePrivateMounts,
    SetupPrivateMounts,
    PrivateMountsReady,
    PrivateMountsVerified,
    PrivateMountsUnavailable,
    ExpectLifecycleEof,
    LifecycleEof,
}

impl SimpleKind {
    const fn header(self) -> &'static str {
        match self {
            Self::ParentDeathArmed => PARENT_DEATH_ARMED_HEADER,
            Self::ParentAlive => PARENT_ALIVE_HEADER,
            Self::Executed => EXECUTED_HEADER,
            Self::AbortBeforePrivateMounts => ABORT_BEFORE_PRIVATE_MOUNTS_HEADER,
            Self::SetupPrivateMounts => SETUP_PRIVATE_MOUNTS_HEADER,
            Self::PrivateMountsReady => PRIVATE_MOUNTS_READY_HEADER,
            Self::PrivateMountsVerified => PRIVATE_MOUNTS_VERIFIED_HEADER,
            Self::PrivateMountsUnavailable => PRIVATE_MOUNTS_UNAVAILABLE_HEADER,
            Self::ExpectLifecycleEof => EXPECT_LIFECYCLE_EOF_HEADER,
            Self::LifecycleEof => LIFECYCLE_EOF_HEADER,
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum LauncherPhase {
    ProvisionPending,
    AwaitingParentDeathArmed,
    ParentDeathArmed,
    AwaitingExecuted,
    SetupPrivateMountsPending,
    AwaitingPrivateMountsResult,
    PrivateMountsReady,
    PrivateMountsComplete,
    AwaitingLifecycleEof,
    LifecycleEof,
    Complete,
}

pub(crate) struct LauncherPidOneControl {
    provision: PidOneProvision,
    phase: LauncherPhase,
}

impl LauncherPidOneControl {
    pub(crate) const fn new(provision: PidOneProvision) -> Self {
        Self {
            provision,
            phase: LauncherPhase::ProvisionPending,
        }
    }

    pub(crate) fn provision(&mut self) -> Result<String, PidOneControlError> {
        if self.phase != LauncherPhase::ProvisionPending {
            return Err(PidOneControlError::StateTransition);
        }
        let encoded = self.provision.encode()?;
        self.phase = LauncherPhase::AwaitingParentDeathArmed;
        Ok(encoded)
    }

    pub(crate) fn accept_parent_death_armed(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), PidOneControlError> {
        self.accept(
            bytes,
            LauncherPhase::AwaitingParentDeathArmed,
            LauncherPhase::ParentDeathArmed,
            SimpleKind::ParentDeathArmed,
        )
    }

    pub(crate) fn parent_alive(&mut self) -> Result<String, PidOneControlError> {
        self.emit(
            LauncherPhase::ParentDeathArmed,
            LauncherPhase::AwaitingExecuted,
            SimpleKind::ParentAlive,
        )
    }

    pub(crate) fn accept_executed(&mut self, bytes: &[u8]) -> Result<(), PidOneControlError> {
        self.accept(
            bytes,
            LauncherPhase::AwaitingExecuted,
            LauncherPhase::SetupPrivateMountsPending,
            SimpleKind::Executed,
        )
    }

    pub(crate) fn setup_private_mounts(&mut self) -> Result<String, PidOneControlError> {
        self.emit(
            LauncherPhase::SetupPrivateMountsPending,
            LauncherPhase::AwaitingPrivateMountsResult,
            SimpleKind::SetupPrivateMounts,
        )
    }

    /// Abort affinely before any private-mount operation when the outer cannot pin PID 1.
    pub(crate) fn abort_before_private_mounts(&mut self) -> Result<String, PidOneControlError> {
        self.emit(
            LauncherPhase::SetupPrivateMountsPending,
            LauncherPhase::PrivateMountsComplete,
            SimpleKind::AbortBeforePrivateMounts,
        )
    }

    pub(crate) fn accept_private_mounts_ready(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), PidOneControlError> {
        self.accept(
            bytes,
            LauncherPhase::AwaitingPrivateMountsResult,
            LauncherPhase::PrivateMountsReady,
            SimpleKind::PrivateMountsReady,
        )
    }

    pub(crate) fn accept_private_mounts_unavailable(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), PidOneControlError> {
        self.accept(
            bytes,
            LauncherPhase::AwaitingPrivateMountsResult,
            LauncherPhase::PrivateMountsComplete,
            SimpleKind::PrivateMountsUnavailable,
        )
    }

    pub(crate) fn private_mounts_verified(&mut self) -> Result<String, PidOneControlError> {
        self.emit(
            LauncherPhase::PrivateMountsReady,
            LauncherPhase::PrivateMountsComplete,
            SimpleKind::PrivateMountsVerified,
        )
    }

    pub(crate) fn expect_lifecycle_eof(&mut self) -> Result<String, PidOneControlError> {
        self.emit(
            LauncherPhase::PrivateMountsComplete,
            LauncherPhase::AwaitingLifecycleEof,
            SimpleKind::ExpectLifecycleEof,
        )
    }

    pub(crate) fn accept_lifecycle_eof(&mut self, bytes: &[u8]) -> Result<(), PidOneControlError> {
        self.accept(
            bytes,
            LauncherPhase::AwaitingLifecycleEof,
            LauncherPhase::LifecycleEof,
            SimpleKind::LifecycleEof,
        )
    }

    pub(crate) fn complete(&mut self) -> Result<(), PidOneControlError> {
        if self.phase != LauncherPhase::LifecycleEof {
            return Err(PidOneControlError::StateTransition);
        }
        self.phase = LauncherPhase::Complete;
        Ok(())
    }

    fn emit(
        &mut self,
        expected: LauncherPhase,
        next: LauncherPhase,
        kind: SimpleKind,
    ) -> Result<String, PidOneControlError> {
        if self.phase != expected {
            return Err(PidOneControlError::StateTransition);
        }
        let encoded = encode_simple(kind, self.provision.run_id())?;
        self.phase = next;
        Ok(encoded)
    }

    fn accept(
        &mut self,
        bytes: &[u8],
        expected: LauncherPhase,
        next: LauncherPhase,
        kind: SimpleKind,
    ) -> Result<(), PidOneControlError> {
        if self.phase != expected {
            return Err(PidOneControlError::StateTransition);
        }
        accept_simple(bytes, kind, self.provision.run_id())?;
        self.phase = next;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum PidOnePhase {
    AwaitingProvision,
    ParentDeathArmedPending,
    AwaitingParentAlive,
    ExecutedPending,
    AwaitingSetupPrivateMounts,
    PrivateMountsResultPending,
    AwaitingPrivateMountsVerified,
    AwaitingLifecycleEof,
    LifecycleEofPending,
    Complete,
}

pub(crate) struct PidOneControl {
    provision: Option<PidOneProvision>,
    phase: PidOnePhase,
}

impl PidOneControl {
    pub(crate) const fn new() -> Self {
        Self {
            provision: None,
            phase: PidOnePhase::AwaitingProvision,
        }
    }

    pub(crate) fn accept_provision(
        &mut self,
        bytes: &[u8],
    ) -> Result<&PidOneProvision, PidOneControlError> {
        if self.phase != PidOnePhase::AwaitingProvision {
            return Err(PidOneControlError::StateTransition);
        }
        self.provision = Some(PidOneProvision::parse(bytes)?);
        self.phase = PidOnePhase::ParentDeathArmedPending;
        self.provision
            .as_ref()
            .ok_or(PidOneControlError::StateTransition)
    }

    pub(crate) fn parent_death_armed(&mut self) -> Result<String, PidOneControlError> {
        self.emit(
            PidOnePhase::ParentDeathArmedPending,
            PidOnePhase::AwaitingParentAlive,
            SimpleKind::ParentDeathArmed,
        )
    }

    pub(crate) fn accept_parent_alive(&mut self, bytes: &[u8]) -> Result<(), PidOneControlError> {
        self.accept(
            bytes,
            PidOnePhase::AwaitingParentAlive,
            PidOnePhase::ExecutedPending,
            SimpleKind::ParentAlive,
        )
    }

    pub(crate) fn executed(&mut self) -> Result<String, PidOneControlError> {
        self.emit(
            PidOnePhase::ExecutedPending,
            PidOnePhase::AwaitingSetupPrivateMounts,
            SimpleKind::Executed,
        )
    }

    pub(crate) fn accept_setup_private_mounts(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), PidOneControlError> {
        self.accept(
            bytes,
            PidOnePhase::AwaitingSetupPrivateMounts,
            PidOnePhase::PrivateMountsResultPending,
            SimpleKind::SetupPrivateMounts,
        )
    }

    /// Accept the launcher's sole pre-mount abort after outer PID-1 proof is unavailable.
    pub(crate) fn accept_abort_before_private_mounts(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), PidOneControlError> {
        self.accept(
            bytes,
            PidOnePhase::AwaitingSetupPrivateMounts,
            PidOnePhase::AwaitingLifecycleEof,
            SimpleKind::AbortBeforePrivateMounts,
        )
    }

    pub(crate) fn private_mounts_ready(&mut self) -> Result<String, PidOneControlError> {
        self.emit(
            PidOnePhase::PrivateMountsResultPending,
            PidOnePhase::AwaitingPrivateMountsVerified,
            SimpleKind::PrivateMountsReady,
        )
    }

    pub(crate) fn private_mounts_unavailable(&mut self) -> Result<String, PidOneControlError> {
        self.emit(
            PidOnePhase::PrivateMountsResultPending,
            PidOnePhase::AwaitingLifecycleEof,
            SimpleKind::PrivateMountsUnavailable,
        )
    }

    pub(crate) fn accept_private_mounts_verified(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), PidOneControlError> {
        self.accept(
            bytes,
            PidOnePhase::AwaitingPrivateMountsVerified,
            PidOnePhase::AwaitingLifecycleEof,
            SimpleKind::PrivateMountsVerified,
        )
    }

    pub(crate) fn accept_expect_lifecycle_eof(
        &mut self,
        bytes: &[u8],
    ) -> Result<(), PidOneControlError> {
        self.accept(
            bytes,
            PidOnePhase::AwaitingLifecycleEof,
            PidOnePhase::LifecycleEofPending,
            SimpleKind::ExpectLifecycleEof,
        )
    }

    pub(crate) fn lifecycle_eof(&mut self) -> Result<String, PidOneControlError> {
        self.emit(
            PidOnePhase::LifecycleEofPending,
            PidOnePhase::Complete,
            SimpleKind::LifecycleEof,
        )
    }

    fn run_id(&self) -> Result<&RunId, PidOneControlError> {
        self.provision
            .as_ref()
            .map(PidOneProvision::run_id)
            .ok_or(PidOneControlError::StateTransition)
    }

    fn emit(
        &mut self,
        expected: PidOnePhase,
        next: PidOnePhase,
        kind: SimpleKind,
    ) -> Result<String, PidOneControlError> {
        if self.phase != expected {
            return Err(PidOneControlError::StateTransition);
        }
        let encoded = encode_simple(kind, self.run_id()?)?;
        self.phase = next;
        Ok(encoded)
    }

    fn accept(
        &mut self,
        bytes: &[u8],
        expected: PidOnePhase,
        next: PidOnePhase,
        kind: SimpleKind,
    ) -> Result<(), PidOneControlError> {
        if self.phase != expected {
            return Err(PidOneControlError::StateTransition);
        }
        accept_simple(bytes, kind, self.run_id()?)?;
        self.phase = next;
        Ok(())
    }
}

fn encode_simple(kind: SimpleKind, run_id: &RunId) -> Result<String, PidOneControlError> {
    encode_lines(&[
        kind.header().to_owned(),
        format!("run_id={}", run_id.as_str()),
    ])
}

fn accept_simple(
    bytes: &[u8],
    expected: SimpleKind,
    expected_run_id: &RunId,
) -> Result<(), PidOneControlError> {
    let lines = decode_lines(bytes)?;
    if lines.len() != 2 || lines[0] != expected.header() {
        return Err(PidOneControlError::Shape);
    }
    let run_id =
        RunId::parse(field(&lines, 1, "run_id")?).map_err(|_| PidOneControlError::RunId)?;
    if &run_id != expected_run_id {
        return Err(PidOneControlError::RunIdMismatch);
    }
    require_canonical(bytes, &encode_simple(expected, &run_id)?)
}

fn namespace(
    lines: &[&str],
    index: usize,
    device_key: &str,
    inode_key: &str,
) -> Result<NamespaceIdentity, PidOneControlError> {
    NamespaceIdentity::new(
        parse_u64(field(lines, index, device_key)?)?,
        parse_u64(field(lines, index + 1, inode_key)?)?,
    )
    .map_err(|_| PidOneControlError::Namespace)
}

fn field<'a>(lines: &'a [&str], index: usize, key: &str) -> Result<&'a str, PidOneControlError> {
    lines
        .get(index)
        .and_then(|line| line.strip_prefix(key))
        .and_then(|value| value.strip_prefix('='))
        .ok_or(PidOneControlError::Shape)
}

fn parse_u32(value: &str) -> Result<u32, PidOneControlError> {
    parse_decimal(value)?
        .try_into()
        .map_err(|_| PidOneControlError::Decimal)
}

fn parse_u64(value: &str) -> Result<u64, PidOneControlError> {
    parse_decimal(value)
}

fn parse_decimal(value: &str) -> Result<u64, PidOneControlError> {
    if value.is_empty()
        || !value.bytes().all(|byte| byte.is_ascii_digit())
        || (value.len() > 1 && value.starts_with('0'))
    {
        return Err(PidOneControlError::Decimal);
    }
    value.parse().map_err(|_| PidOneControlError::Decimal)
}

fn encode_lines(lines: &[String]) -> Result<String, PidOneControlError> {
    let mut encoded = lines.join("\n");
    encoded.push('\n');
    if encoded.len() > MAX_LIFECYCLE_FRAME_BYTES {
        Err(PidOneControlError::FrameTooLarge)
    } else {
        Ok(encoded)
    }
}

fn decode_lines(bytes: &[u8]) -> Result<Vec<&str>, PidOneControlError> {
    if bytes.len() > MAX_LIFECYCLE_FRAME_BYTES {
        return Err(PidOneControlError::FrameTooLarge);
    }
    if bytes.is_empty()
        || bytes.last() != Some(&b'\n')
        || bytes.contains(&b'\r')
        || bytes.contains(&0)
    {
        return Err(PidOneControlError::Framing);
    }
    let text = str::from_utf8(bytes).map_err(|_| PidOneControlError::Utf8)?;
    let body = text.strip_suffix('\n').ok_or(PidOneControlError::Framing)?;
    if body.is_empty() || body.ends_with('\n') {
        return Err(PidOneControlError::Shape);
    }
    Ok(body.split('\n').collect())
}

fn require_canonical(bytes: &[u8], canonical: &str) -> Result<(), PidOneControlError> {
    if bytes == canonical.as_bytes() {
        Ok(())
    } else {
        Err(PidOneControlError::Shape)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: &str = "0123456789abcdef0123456789abcdef";
    const OTHER_RUN: &str = "fedcba9876543210fedcba9876543210";

    fn identity(value: u64) -> NamespaceIdentity {
        NamespaceIdentity::new(7, value).expect("identity")
    }

    fn run_id() -> RunId {
        RunId::parse(RUN).expect("run")
    }

    fn other_run_id() -> RunId {
        RunId::parse(OTHER_RUN).expect("other run")
    }

    fn provision() -> PidOneProvision {
        PidOneProvision::new(
            run_id(),
            identity(101),
            identity(102),
            identity(103),
            identity(104),
            1000,
            1001,
        )
        .expect("provision")
    }

    fn advance_through_executed(launcher: &mut LauncherPidOneControl, pid_one: &mut PidOneControl) {
        let provision_record = launcher.provision().expect("provision record");
        pid_one
            .accept_provision(provision_record.as_bytes())
            .expect("accept provision");
        let armed = pid_one.parent_death_armed().expect("armed record");
        launcher
            .accept_parent_death_armed(armed.as_bytes())
            .expect("accept armed");
        let alive = launcher.parent_alive().expect("alive record");
        pid_one
            .accept_parent_alive(alive.as_bytes())
            .expect("accept alive");
        let executed = pid_one.executed().expect("executed record");
        launcher
            .accept_executed(executed.as_bytes())
            .expect("accept executed");
    }

    #[test]
    fn exact_private_exchange_is_affine_and_canonical() {
        let expected = provision();
        let mut launcher = LauncherPidOneControl::new(expected.clone());
        let mut pid_one = PidOneControl::new();

        let encoded = launcher.provision().expect("provision record");
        assert_eq!(PidOneProvision::parse(encoded.as_bytes()), Ok(expected));
        pid_one
            .accept_provision(encoded.as_bytes())
            .expect("accept provision");
        let armed = pid_one.parent_death_armed().expect("armed");
        launcher
            .accept_parent_death_armed(armed.as_bytes())
            .expect("accept armed");
        let alive = launcher.parent_alive().expect("alive");
        pid_one
            .accept_parent_alive(alive.as_bytes())
            .expect("accept alive");
        let executed = pid_one.executed().expect("executed");
        launcher
            .accept_executed(executed.as_bytes())
            .expect("accept executed");
        let setup_mounts = launcher
            .setup_private_mounts()
            .expect("setup private mounts");
        assert_eq!(
            setup_mounts,
            format!("{SETUP_PRIVATE_MOUNTS_HEADER}\nrun_id={RUN}\n")
        );
        pid_one
            .accept_setup_private_mounts(setup_mounts.as_bytes())
            .expect("accept private-mount setup");
        let mounts_ready = pid_one.private_mounts_ready().expect("mounts ready");
        assert_eq!(
            mounts_ready,
            format!("{PRIVATE_MOUNTS_READY_HEADER}\nrun_id={RUN}\n")
        );
        launcher
            .accept_private_mounts_ready(mounts_ready.as_bytes())
            .expect("accept private-mount readiness");
        let mounts_verified = launcher.private_mounts_verified().expect("mounts verified");
        assert_eq!(
            mounts_verified,
            format!("{PRIVATE_MOUNTS_VERIFIED_HEADER}\nrun_id={RUN}\n")
        );
        pid_one
            .accept_private_mounts_verified(mounts_verified.as_bytes())
            .expect("accept private-mount verification");
        let expect_eof = launcher.expect_lifecycle_eof().expect("expect EOF");
        pid_one
            .accept_expect_lifecycle_eof(expect_eof.as_bytes())
            .expect("accept expect EOF");
        let eof = pid_one.lifecycle_eof().expect("EOF");
        launcher
            .accept_lifecycle_eof(eof.as_bytes())
            .expect("accept EOF");
        launcher.complete().expect("complete");
        assert_eq!(
            launcher.complete(),
            Err(PidOneControlError::StateTransition)
        );
    }

    #[test]
    fn policy_denied_private_mounts_take_the_exclusive_unavailable_branch() {
        let mut launcher = LauncherPidOneControl::new(provision());
        let mut pid_one = PidOneControl::new();
        advance_through_executed(&mut launcher, &mut pid_one);

        let setup = launcher
            .setup_private_mounts()
            .expect("setup private mounts");
        pid_one
            .accept_setup_private_mounts(setup.as_bytes())
            .expect("accept setup");
        let unavailable = pid_one
            .private_mounts_unavailable()
            .expect("private mounts unavailable");
        assert_eq!(
            unavailable,
            format!("{PRIVATE_MOUNTS_UNAVAILABLE_HEADER}\nrun_id={RUN}\n")
        );
        assert_eq!(pid_one.phase, PidOnePhase::AwaitingLifecycleEof);
        assert_eq!(
            pid_one.private_mounts_ready(),
            Err(PidOneControlError::StateTransition)
        );
        assert_eq!(
            pid_one.private_mounts_unavailable(),
            Err(PidOneControlError::StateTransition)
        );

        launcher
            .accept_private_mounts_unavailable(unavailable.as_bytes())
            .expect("accept unavailable result");
        assert_eq!(launcher.phase, LauncherPhase::PrivateMountsComplete);
        assert_eq!(
            launcher.accept_private_mounts_ready(
                encode_simple(SimpleKind::PrivateMountsReady, &run_id())
                    .expect("ready record")
                    .as_bytes()
            ),
            Err(PidOneControlError::StateTransition)
        );
        assert_eq!(
            launcher.accept_private_mounts_unavailable(unavailable.as_bytes()),
            Err(PidOneControlError::StateTransition)
        );
        assert_eq!(
            launcher.private_mounts_verified(),
            Err(PidOneControlError::StateTransition)
        );

        let expect_eof = launcher.expect_lifecycle_eof().expect("expect EOF");
        pid_one
            .accept_expect_lifecycle_eof(expect_eof.as_bytes())
            .expect("accept expect EOF");
        let eof = pid_one.lifecycle_eof().expect("EOF");
        launcher
            .accept_lifecycle_eof(eof.as_bytes())
            .expect("accept EOF");
        launcher.complete().expect("complete unavailable branch");
        assert_eq!(pid_one.phase, PidOnePhase::Complete);
        assert_eq!(launcher.phase, LauncherPhase::Complete);
    }

    #[test]
    fn unavailable_outer_pid_pin_aborts_affinely_before_mount_setup() {
        let mut launcher = LauncherPidOneControl::new(provision());
        let mut pid_one = PidOneControl::new();
        advance_through_executed(&mut launcher, &mut pid_one);

        let abort = launcher
            .abort_before_private_mounts()
            .expect("pre-mount abort");
        assert_eq!(
            abort,
            format!("{ABORT_BEFORE_PRIVATE_MOUNTS_HEADER}\nrun_id={RUN}\n")
        );
        assert_eq!(launcher.phase, LauncherPhase::PrivateMountsComplete);
        assert_eq!(
            launcher.setup_private_mounts(),
            Err(PidOneControlError::StateTransition)
        );
        assert_eq!(
            launcher.abort_before_private_mounts(),
            Err(PidOneControlError::StateTransition)
        );

        pid_one
            .accept_abort_before_private_mounts(abort.as_bytes())
            .expect("accept pre-mount abort");
        assert_eq!(pid_one.phase, PidOnePhase::AwaitingLifecycleEof);
        assert_eq!(
            pid_one.accept_setup_private_mounts(
                encode_simple(SimpleKind::SetupPrivateMounts, &run_id())
                    .expect("setup record")
                    .as_bytes()
            ),
            Err(PidOneControlError::StateTransition)
        );
        assert_eq!(
            pid_one.accept_abort_before_private_mounts(abort.as_bytes()),
            Err(PidOneControlError::StateTransition)
        );

        let expect_eof = launcher.expect_lifecycle_eof().expect("expect EOF");
        pid_one
            .accept_expect_lifecycle_eof(expect_eof.as_bytes())
            .expect("accept expect EOF");
        let eof = pid_one.lifecycle_eof().expect("EOF");
        launcher
            .accept_lifecycle_eof(eof.as_bytes())
            .expect("accept EOF");
        launcher.complete().expect("complete abort branch");
        assert_eq!(pid_one.phase, PidOnePhase::Complete);
        assert_eq!(launcher.phase, LauncherPhase::Complete);
    }

    #[test]
    fn all_simple_records_are_canonical_bounded_and_run_bound() {
        for kind in [
            SimpleKind::ParentDeathArmed,
            SimpleKind::ParentAlive,
            SimpleKind::Executed,
            SimpleKind::AbortBeforePrivateMounts,
            SimpleKind::SetupPrivateMounts,
            SimpleKind::PrivateMountsReady,
            SimpleKind::PrivateMountsVerified,
            SimpleKind::PrivateMountsUnavailable,
            SimpleKind::ExpectLifecycleEof,
            SimpleKind::LifecycleEof,
        ] {
            let record = encode_simple(kind, &run_id()).expect("simple record");
            assert_eq!(record, format!("{}\nrun_id={RUN}\n", kind.header()));
            assert!(record.is_ascii());
            assert!(!record.contains('\r'));
            assert!(!record.ends_with("\n\n"));
            assert!(record.len() <= MAX_LIFECYCLE_FRAME_BYTES);
            assert_eq!(accept_simple(record.as_bytes(), kind, &run_id()), Ok(()));
            assert_eq!(
                accept_simple(record.as_bytes(), kind, &other_run_id()),
                Err(PidOneControlError::RunIdMismatch)
            );
        }
    }

    #[test]
    fn provision_rejects_aliases_and_noncanonical_fields() {
        let valid = provision().encode().expect("valid");
        assert_eq!(PidOneProvision::parse(valid.as_bytes()), Ok(provision()));
        assert_eq!(
            PidOneProvision::new(
                provision().run_id.clone(),
                identity(101),
                identity(101),
                identity(103),
                identity(104),
                1000,
                1001,
            ),
            Err(PidOneControlError::Namespace)
        );
        for malformed in [
            valid.replace("outer_uid=1000", "outer_uid=01000"),
            valid.replace("pid_ns_inode=104", "pid_ns_inode=0"),
            valid.replace("run_id=", "run="),
            valid.replace("\nouter_gid=1001\n", "\nouter_gid=1001\nextra=true\n"),
        ] {
            assert!(PidOneProvision::parse(malformed.as_bytes()).is_err());
        }
    }

    #[test]
    fn wrong_run_direction_order_and_framing_never_advance() {
        let mut launcher = LauncherPidOneControl::new(provision());
        let mut pid_one = PidOneControl::new();
        let provision_record = launcher.provision().expect("provision");
        pid_one
            .accept_provision(provision_record.as_bytes())
            .expect("accept provision");
        let wrong_run = encode_simple(
            SimpleKind::ParentDeathArmed,
            &RunId::parse("fedcba9876543210fedcba9876543210").expect("other run"),
        )
        .expect("wrong run record");
        assert_eq!(
            launcher.accept_parent_death_armed(wrong_run.as_bytes()),
            Err(PidOneControlError::RunIdMismatch)
        );
        let wrong_direction =
            encode_simple(SimpleKind::Executed, provision().run_id()).expect("wrong direction");
        assert_eq!(
            launcher.accept_parent_death_armed(wrong_direction.as_bytes()),
            Err(PidOneControlError::Shape)
        );
        for malformed in [
            b"".as_slice(),
            b"record",
            b"record\r\n",
            b"record\n\n",
            b"\xff\n",
        ] {
            assert!(decode_lines(malformed).is_err());
        }
        let armed = pid_one.parent_death_armed().expect("valid armed");
        launcher
            .accept_parent_death_armed(armed.as_bytes())
            .expect("state did not advance on rejection");
    }

    #[test]
    fn private_mount_receivers_fail_closed_without_advancing() {
        let mut launcher = LauncherPidOneControl::new(provision());
        let mut pid_one = PidOneControl::new();
        advance_through_executed(&mut launcher, &mut pid_one);
        let oversized = vec![0xff; MAX_LIFECYCLE_FRAME_BYTES + 1];

        let wrong_setup = encode_simple(SimpleKind::SetupPrivateMounts, &other_run_id())
            .expect("wrong-run setup");
        assert_eq!(
            pid_one.accept_setup_private_mounts(wrong_setup.as_bytes()),
            Err(PidOneControlError::RunIdMismatch)
        );
        let wrong_direction = encode_simple(SimpleKind::PrivateMountsReady, &run_id())
            .expect("wrong-direction readiness");
        assert_eq!(
            pid_one.accept_setup_private_mounts(wrong_direction.as_bytes()),
            Err(PidOneControlError::Shape)
        );
        assert_eq!(
            pid_one.accept_setup_private_mounts(&oversized),
            Err(PidOneControlError::FrameTooLarge)
        );
        assert_eq!(pid_one.phase, PidOnePhase::AwaitingSetupPrivateMounts);

        let setup = launcher.setup_private_mounts().expect("valid setup record");
        pid_one
            .accept_setup_private_mounts(setup.as_bytes())
            .expect("accept valid setup");

        let wrong_ready = encode_simple(SimpleKind::PrivateMountsReady, &other_run_id())
            .expect("wrong-run ready");
        assert_eq!(
            launcher.accept_private_mounts_ready(wrong_ready.as_bytes()),
            Err(PidOneControlError::RunIdMismatch)
        );
        let wrong_unavailable =
            encode_simple(SimpleKind::PrivateMountsUnavailable, &other_run_id())
                .expect("wrong-run unavailable");
        assert_eq!(
            launcher.accept_private_mounts_unavailable(wrong_unavailable.as_bytes()),
            Err(PidOneControlError::RunIdMismatch)
        );
        assert_eq!(
            launcher.accept_private_mounts_ready(setup.as_bytes()),
            Err(PidOneControlError::Shape)
        );
        assert_eq!(
            launcher.accept_private_mounts_unavailable(&oversized),
            Err(PidOneControlError::FrameTooLarge)
        );
        assert_eq!(launcher.phase, LauncherPhase::AwaitingPrivateMountsResult);

        let ready = pid_one.private_mounts_ready().expect("valid ready record");
        launcher
            .accept_private_mounts_ready(ready.as_bytes())
            .expect("accept valid ready");
        let wrong_verified = encode_simple(SimpleKind::PrivateMountsVerified, &other_run_id())
            .expect("wrong-run verification");
        assert_eq!(
            pid_one.accept_private_mounts_verified(wrong_verified.as_bytes()),
            Err(PidOneControlError::RunIdMismatch)
        );
        assert_eq!(
            pid_one.accept_private_mounts_verified(ready.as_bytes()),
            Err(PidOneControlError::Shape)
        );
        assert_eq!(
            pid_one.accept_private_mounts_verified(&oversized),
            Err(PidOneControlError::FrameTooLarge)
        );
        assert_eq!(pid_one.phase, PidOnePhase::AwaitingPrivateMountsVerified);

        let verified = launcher
            .private_mounts_verified()
            .expect("valid verification");
        pid_one
            .accept_private_mounts_verified(verified.as_bytes())
            .expect("accept valid verification after rejections");
        assert_eq!(pid_one.phase, PidOnePhase::AwaitingLifecycleEof);
    }

    #[test]
    fn private_mount_transitions_reject_order_replay_and_branch_switching() {
        let mut launcher = LauncherPidOneControl::new(provision());
        let mut pid_one = PidOneControl::new();

        assert_eq!(
            launcher.setup_private_mounts(),
            Err(PidOneControlError::StateTransition)
        );
        assert_eq!(
            launcher.abort_before_private_mounts(),
            Err(PidOneControlError::StateTransition)
        );
        assert_eq!(
            launcher.private_mounts_verified(),
            Err(PidOneControlError::StateTransition)
        );
        assert_eq!(
            pid_one.private_mounts_ready(),
            Err(PidOneControlError::StateTransition)
        );
        assert_eq!(
            pid_one.private_mounts_unavailable(),
            Err(PidOneControlError::StateTransition)
        );
        assert_eq!(
            pid_one.accept_abort_before_private_mounts(
                encode_simple(SimpleKind::AbortBeforePrivateMounts, &run_id())
                    .expect("abort record")
                    .as_bytes()
            ),
            Err(PidOneControlError::StateTransition)
        );

        advance_through_executed(&mut launcher, &mut pid_one);
        assert_eq!(
            launcher.expect_lifecycle_eof(),
            Err(PidOneControlError::StateTransition)
        );
        assert_eq!(
            pid_one.accept_expect_lifecycle_eof(
                encode_simple(SimpleKind::ExpectLifecycleEof, &run_id())
                    .expect("expect-EOF record")
                    .as_bytes()
            ),
            Err(PidOneControlError::StateTransition)
        );

        let setup = launcher.setup_private_mounts().expect("first setup");
        assert_eq!(
            launcher.setup_private_mounts(),
            Err(PidOneControlError::StateTransition)
        );
        pid_one
            .accept_setup_private_mounts(setup.as_bytes())
            .expect("first setup acceptance");
        assert_eq!(
            pid_one.accept_setup_private_mounts(setup.as_bytes()),
            Err(PidOneControlError::StateTransition)
        );

        let ready = pid_one.private_mounts_ready().expect("first readiness");
        assert_eq!(
            pid_one.private_mounts_ready(),
            Err(PidOneControlError::StateTransition)
        );
        assert_eq!(
            pid_one.private_mounts_unavailable(),
            Err(PidOneControlError::StateTransition)
        );
        launcher
            .accept_private_mounts_ready(ready.as_bytes())
            .expect("first readiness acceptance");
        assert_eq!(
            launcher.accept_private_mounts_ready(ready.as_bytes()),
            Err(PidOneControlError::StateTransition)
        );
        assert_eq!(
            launcher.accept_private_mounts_unavailable(
                encode_simple(SimpleKind::PrivateMountsUnavailable, &run_id())
                    .expect("unavailable record")
                    .as_bytes()
            ),
            Err(PidOneControlError::StateTransition)
        );

        let verified = launcher
            .private_mounts_verified()
            .expect("first verification");
        assert_eq!(
            launcher.private_mounts_verified(),
            Err(PidOneControlError::StateTransition)
        );
        pid_one
            .accept_private_mounts_verified(verified.as_bytes())
            .expect("first verification acceptance");
        assert_eq!(
            pid_one.accept_private_mounts_verified(verified.as_bytes()),
            Err(PidOneControlError::StateTransition)
        );
    }
}
