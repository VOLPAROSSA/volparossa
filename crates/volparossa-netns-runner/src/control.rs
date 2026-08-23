use std::str;

use thiserror::Error;
use volparossa_test_support::{MAX_LIFECYCLE_FRAME_BYTES, RunId};

const NAMESPACES_CREATED_HEADER: &str = "VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V1 NAMESPACES_CREATED";
const MAPPINGS_INSTALLED_HEADER: &str = "VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V1 MAPPINGS_INSTALLED";
const MAPPINGS_VERIFIED_HEADER: &str = "VOLPAROSSA_NETNS_BOOTSTRAP_CONTROL_V1 MAPPINGS_VERIFIED";

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
    /// A valid record travelled in the wrong direction or appeared at the wrong receive step.
    #[error("unexpected bootstrap-control record")]
    UnexpectedRecord,
    /// A record was bound to another lifecycle run.
    #[error("bootstrap-control run identifier mismatch")]
    RunIdMismatch,
    /// An affine state transition was attempted more than once or out of order.
    #[error("invalid bootstrap-control state transition")]
    StateTransition,
}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
enum RecordKind {
    NamespacesCreated,
    MappingsInstalled,
    MappingsVerified,
}

impl RecordKind {
    const fn header(self) -> &'static str {
        match self {
            Self::NamespacesCreated => NAMESPACES_CREATED_HEADER,
            Self::MappingsInstalled => MAPPINGS_INSTALLED_HEADER,
            Self::MappingsVerified => MAPPINGS_VERIFIED_HEADER,
        }
    }

    fn parse(header: &str) -> Result<Self, BootstrapControlError> {
        match header {
            NAMESPACES_CREATED_HEADER => Ok(Self::NamespacesCreated),
            MAPPINGS_INSTALLED_HEADER => Ok(Self::MappingsInstalled),
            MAPPINGS_VERIFIED_HEADER => Ok(Self::MappingsVerified),
            _ => Err(BootstrapControlError::FrameShape),
        }
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
struct ControlRecord {
    kind: RecordKind,
    run_id: RunId,
}

impl ControlRecord {
    fn new(kind: RecordKind, run_id: RunId) -> Self {
        Self { kind, run_id }
    }

    fn encode(&self) -> Result<String, BootstrapControlError> {
        let encoded = format!("{}\nrun_id={}\n", self.kind.header(), self.run_id.as_str());
        if encoded.len() > MAX_LIFECYCLE_FRAME_BYTES {
            return Err(BootstrapControlError::FrameTooLarge);
        }
        Ok(encoded)
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
        if lines.next().is_some() {
            return Err(BootstrapControlError::FrameShape);
        }
        let kind = RecordKind::parse(header)?;
        let run_value = run_line
            .strip_prefix("run_id=")
            .ok_or(BootstrapControlError::FrameShape)?;
        let run_id = RunId::parse(run_value).map_err(|_| BootstrapControlError::RunId)?;
        let record = Self::new(kind, run_id);
        if record.encode()?.as_bytes() != bytes {
            return Err(BootstrapControlError::FrameShape);
        }
        Ok(record)
    }
}

/// Observable outer-side phase of the fixed mapping handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum OuterBootstrapPhase {
    /// Waiting for the launcher to prove that the fixed namespaces exist.
    AwaitingNamespacesCreated,
    /// The namespace record was accepted; the mapping acknowledgement may be emitted once.
    NamespacesCreated,
    /// The mapping acknowledgement was emitted; launcher verification is outstanding.
    AwaitingMappingsVerified,
    /// The exact three-record exchange completed.
    Complete,
}

/// Affine owner of the outer side of one run-bound mapping handshake.
#[derive(Debug)]
pub(crate) struct OuterBootstrapControl {
    run_id: RunId,
    phase: OuterBootstrapPhase,
}

impl OuterBootstrapControl {
    /// Begin an outer exchange for one exact lifecycle run.
    pub(crate) const fn new(run_id: RunId) -> Self {
        Self {
            run_id,
            phase: OuterBootstrapPhase::AwaitingNamespacesCreated,
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
        self.phase = OuterBootstrapPhase::Complete;
        Ok(())
    }
}

/// Observable launcher-side phase of the fixed mapping handshake.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(crate) enum LauncherBootstrapPhase {
    /// The namespace record has not yet been emitted.
    NamespacesCreatedPending,
    /// Waiting for the outer's mapping acknowledgement.
    AwaitingMappingsInstalled,
    /// The mapping acknowledgement was accepted and local verification succeeded.
    MappingsInstalled,
    /// The exact three-record exchange completed.
    Complete,
}

/// Affine owner of the launcher side of one run-bound mapping handshake.
#[derive(Debug)]
pub(crate) struct LauncherBootstrapControl {
    run_id: RunId,
    phase: LauncherBootstrapPhase,
}

impl LauncherBootstrapControl {
    /// Begin a launcher exchange for one exact lifecycle run.
    pub(crate) const fn new(run_id: RunId) -> Self {
        Self {
            run_id,
            phase: LauncherBootstrapPhase::NamespacesCreatedPending,
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

#[cfg(test)]
mod tests {
    use super::*;

    const RUN: &str = "0123456789abcdef0123456789abcdef";
    const OTHER_RUN: &str = "fedcba9876543210fedcba9876543210";

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

    #[test]
    fn every_record_round_trips_in_exact_canonical_lf_format() {
        for kind in [
            RecordKind::NamespacesCreated,
            RecordKind::MappingsInstalled,
            RecordKind::MappingsVerified,
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
    }

    #[test]
    fn complete_affine_exchange_has_exact_direction_and_order() {
        let mut outer = OuterBootstrapControl::new(run_id());
        let mut launcher = LauncherBootstrapControl::new(run_id());
        assert_eq!(
            outer.phase(),
            OuterBootstrapPhase::AwaitingNamespacesCreated
        );
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::NamespacesCreatedPending
        );

        let namespaces = launcher.namespaces_created().expect("namespaces record");
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::AwaitingMappingsInstalled
        );
        outer
            .accept_namespaces_created(namespaces.as_bytes())
            .expect("outer accepts namespaces");
        assert_eq!(outer.phase(), OuterBootstrapPhase::NamespacesCreated);

        let installed = outer.mappings_installed().expect("mapping record");
        assert_eq!(outer.phase(), OuterBootstrapPhase::AwaitingMappingsVerified);
        launcher
            .accept_mappings_installed(installed.as_bytes())
            .expect("launcher accepts mapping record");
        assert_eq!(launcher.phase(), LauncherBootstrapPhase::MappingsInstalled);

        let verified = launcher.mappings_verified().expect("verified record");
        assert_eq!(launcher.phase(), LauncherBootstrapPhase::Complete);
        outer
            .accept_mappings_verified(verified.as_bytes())
            .expect("outer accepts verification");
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
    fn reordered_duplicate_and_extra_fields_are_rejected() {
        for malformed in [
            format!("run_id={RUN}\n{NAMESPACES_CREATED_HEADER}\n"),
            format!("{NAMESPACES_CREATED_HEADER}\nrun_id={RUN}\nrun_id={RUN}\n"),
            format!("{NAMESPACES_CREATED_HEADER}\nextra=true\nrun_id={RUN}\n"),
            format!("{NAMESPACES_CREATED_HEADER}\nrun_id={RUN}\nextra=true\n"),
            format!(
                "{NAMESPACES_CREATED_HEADER}\nrun_id={RUN}\n{MAPPINGS_INSTALLED_HEADER}\nrun_id={RUN}\n"
            ),
        ] {
            assert_eq!(
                ControlRecord::parse(malformed.as_bytes()),
                Err(BootstrapControlError::FrameShape)
            );
        }
    }

    #[test]
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
    }

    #[test]
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
    }

    #[test]
    fn oversized_input_is_rejected_before_utf8_or_shape_and_state_does_not_advance() {
        let oversized = vec![0xff; MAX_LIFECYCLE_FRAME_BYTES + 1];
        assert_eq!(
            ControlRecord::parse(&oversized),
            Err(BootstrapControlError::FrameTooLarge)
        );

        let mut outer = OuterBootstrapControl::new(run_id());
        assert_eq!(
            outer.accept_namespaces_created(&oversized),
            Err(BootstrapControlError::FrameTooLarge)
        );
        assert_eq!(
            outer.phase(),
            OuterBootstrapPhase::AwaitingNamespacesCreated
        );

        let mut launcher = LauncherBootstrapControl::new(run_id());
        let _ = launcher.namespaces_created().expect("namespaces record");
        assert_eq!(
            launcher.accept_mappings_installed(&oversized),
            Err(BootstrapControlError::FrameTooLarge)
        );
        assert_eq!(
            launcher.phase(),
            LauncherBootstrapPhase::AwaitingMappingsInstalled
        );
    }
}
