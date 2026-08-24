use std::str;

use thiserror::Error;
use volparossa_test_support::{MAX_LIFECYCLE_FRAME_BYTES, NamespaceIdentity, RunId};

const PROVISION_HEADER: &str = "VOLPAROSSA_NETNS_PID1_CONTROL_V1 PROVISION";
const PARENT_DEATH_ARMED_HEADER: &str = "VOLPAROSSA_NETNS_PID1_CONTROL_V1 PARENT_DEATH_ARMED";
const PARENT_ALIVE_HEADER: &str = "VOLPAROSSA_NETNS_PID1_CONTROL_V1 PARENT_ALIVE";
const EXECUTED_HEADER: &str = "VOLPAROSSA_NETNS_PID1_CONTROL_V1 EXECUTED";
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
    ExpectLifecycleEof,
    LifecycleEof,
}

impl SimpleKind {
    const fn header(self) -> &'static str {
        match self {
            Self::ParentDeathArmed => PARENT_DEATH_ARMED_HEADER,
            Self::ParentAlive => PARENT_ALIVE_HEADER,
            Self::Executed => EXECUTED_HEADER,
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
    Executed,
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
            LauncherPhase::Executed,
            SimpleKind::Executed,
        )
    }

    pub(crate) fn expect_lifecycle_eof(&mut self) -> Result<String, PidOneControlError> {
        self.emit(
            LauncherPhase::Executed,
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
            PidOnePhase::AwaitingLifecycleEof,
            SimpleKind::Executed,
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

    fn identity(value: u64) -> NamespaceIdentity {
        NamespaceIdentity::new(7, value).expect("identity")
    }

    fn provision() -> PidOneProvision {
        PidOneProvision::new(
            RunId::parse("0123456789abcdef0123456789abcdef").expect("run"),
            identity(101),
            identity(102),
            identity(103),
            identity(104),
            1000,
            1001,
        )
        .expect("provision")
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
}
