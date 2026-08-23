//! Strict machine-readable A01-A15 acceptance-report model.

use std::collections::{BTreeMap, HashSet};

use serde::{Serialize, Serializer};
use thiserror::Error;

/// Machine-report schema version.
pub const ACCEPTANCE_REPORT_SCHEMA_VERSION: u32 = 1;
/// Exact number of required acceptance cases in VOLPAROSSA v1.
pub const ACCEPTANCE_CASE_COUNT: usize = 15;
/// Maximum number of execution blockers in one bounded report.
pub const MAX_ACCEPTANCE_BLOCKERS: usize = 32;
/// Maximum number of evidence objects attached to one acceptance case.
pub const MAX_ACCEPTANCE_EVIDENCE_PER_CASE: usize = 32;
/// Maximum number of native source revisions in environment provenance.
pub const MAX_NATIVE_REVISIONS: usize = 32;
/// Maximum count accepted for remaining owned objects.
pub const MAX_REMAINING_OWNED_OBJECTS: u64 = 1_000_000;

const PARTIAL_SUITE_CODE: &str = "PARTIAL_SUITE";
const NOT_SELECTED_CODE: &str = "NOT_SELECTED";
const A14_REQUIRED_CHECKS: [&str; 4] = [
    "FORCED_AGENT_CRASH_CLEANUP",
    "FORCED_HELPER_CRASH_CLEANUP",
    "FORCED_NATIVE_CRASH_CLEANUP",
    "OWNED_OBJECTS_ABSENT",
];
const A15_BEFORE_EVIDENCE_ID: &str = "a15.host_before";
const A15_AFTER_EVIDENCE_ID: &str = "a15.host_after";

/// Stable identifier for one required acceptance case.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize)]
pub enum AcceptanceId {
    /// Discovery survives loss of either bootstrap peer.
    A01,
    /// TCP carries data over at least two real MPTCP subflows.
    A02,
    /// Constrained MPTCP paths aggregate bandwidth.
    A03,
    /// Removing one relay preserves the MPTCP application flow.
    A04,
    /// General UDP uses exactly one relay and no direct exit path.
    A05,
    /// HTTP/3 uses at least two real MPQUIC paths.
    A06,
    /// Removing one MPQUIC relay preserves the inner QUIC flow.
    A07,
    /// An allowed destination succeeds.
    A08,
    /// Forbidden domain, IP, SNI, and port requests fail closed.
    A09,
    /// Unverifiable ECH fails closed.
    A10,
    /// Relay capture does not reveal the Internet destination.
    A11,
    /// Exit capture sees relay peers rather than the client address.
    A12,
    /// Client capture proves no direct client-to-exit dataplane.
    A13,
    /// Forced-crash cleanup removes every owned resource.
    A14,
    /// Host routes, DNS, firewall, and related state remain unchanged.
    A15,
}

/// All required identifiers in canonical report order.
pub const ALL_ACCEPTANCE_IDS: [AcceptanceId; ACCEPTANCE_CASE_COUNT] = [
    AcceptanceId::A01,
    AcceptanceId::A02,
    AcceptanceId::A03,
    AcceptanceId::A04,
    AcceptanceId::A05,
    AcceptanceId::A06,
    AcceptanceId::A07,
    AcceptanceId::A08,
    AcceptanceId::A09,
    AcceptanceId::A10,
    AcceptanceId::A11,
    AcceptanceId::A12,
    AcceptanceId::A13,
    AcceptanceId::A14,
    AcceptanceId::A15,
];

/// Requested acceptance-suite scope.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum AcceptanceSuite {
    /// Select all A01 through A15 cases.
    #[serde(rename = "all")]
    All,
    /// Select MPTCP cases A02-A04 plus cleanup and host-safety cases.
    #[serde(rename = "mptcp")]
    Mptcp,
    /// Select MPQUIC cases A06-A07 plus cleanup and host-safety cases.
    #[serde(rename = "mpquic")]
    Mpquic,
}

impl AcceptanceSuite {
    /// Whether this suite selects the supplied case.
    #[must_use]
    pub const fn selects(self, id: AcceptanceId) -> bool {
        match self {
            Self::All => true,
            Self::Mptcp => matches!(
                id,
                AcceptanceId::A02
                    | AcceptanceId::A03
                    | AcceptanceId::A04
                    | AcceptanceId::A14
                    | AcceptanceId::A15
            ),
            Self::Mpquic => matches!(
                id,
                AcceptanceId::A06 | AcceptanceId::A07 | AcceptanceId::A14 | AcceptanceId::A15
            ),
        }
    }
}

/// Requested runner behavior.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum RequestedMode {
    /// Inspect prerequisites without attempting privileged topology creation.
    #[serde(rename = "PREVIEW")]
    Preview,
    /// Execute the selected acceptance suite.
    #[serde(rename = "EXECUTE")]
    Execute,
}

/// Outcome of one acceptance case.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum AcceptanceCaseResult {
    /// The asserted behavior passed with content-addressed evidence.
    #[serde(rename = "PASS")]
    Pass,
    /// The case ran and contradicted its assertion.
    #[serde(rename = "FAIL")]
    Fail,
    /// The case was not run because it was unselected or blocked.
    #[serde(rename = "SKIPPED")]
    Skipped,
    /// The case mechanism encountered an execution error.
    #[serde(rename = "ERROR")]
    Error,
}

/// Overall report outcome.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
pub enum AcceptanceOverallResult {
    /// Full A01-A15 acceptance passed.
    #[serde(rename = "PASS")]
    Pass,
    /// At least one selected assertion was contradicted.
    #[serde(rename = "FAIL")]
    Fail,
    /// Full acceptance could not be established.
    #[serde(rename = "BLOCKED")]
    Blocked,
    /// At least one selected case encountered an execution error.
    #[serde(rename = "ERROR")]
    Error,
}

/// Kind of content-addressed evidence artifact.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "lowercase")]
pub enum AcceptanceEvidenceKind {
    /// A bounded counter snapshot.
    Counter,
    /// A privacy-safe packet capture.
    Capture,
    /// Output from a fixed diagnostic command.
    Command,
    /// A state fingerprint or other digest artifact.
    Digest,
    /// A bounded performance or path measurement.
    Measurement,
    /// A bounded state snapshot.
    State,
}

/// A validated Git-compatible SHA-1 or SHA-256 source revision.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct SourceRevision(String);

impl SourceRevision {
    /// Construct a lowercase 40- or 64-hex source revision.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not a canonical supported revision.
    pub fn new(value: String) -> Result<Self, AcceptanceReportError> {
        if !valid_hex_with_lengths(&value, &[40, 64]) {
            return Err(AcceptanceReportError::Revision);
        }
        Ok(Self(value))
    }

    /// Revision text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated lowercase SHA-256 digest.
#[derive(Clone, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize)]
#[serde(transparent)]
pub struct Sha256Digest(String);

impl Sha256Digest {
    /// Construct a canonical lowercase SHA-256 digest.
    ///
    /// # Errors
    ///
    /// Returns an error when the value is not exactly 64 lowercase hex characters.
    pub fn new(value: String) -> Result<Self, AcceptanceReportError> {
        if !valid_hex_with_lengths(&value, &[64]) {
            return Err(AcceptanceReportError::Digest);
        }
        Ok(Self(value))
    }

    /// Digest text.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// Canonical whole-second UTC report timestamp.
#[derive(Clone, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub struct ReportTimestamp {
    encoded: String,
    order_key: (u16, u8, u8, u8, u8, u8),
}

impl ReportTimestamp {
    /// Parse exact `YYYY-MM-DDTHH:MM:SSZ` UTC notation.
    ///
    /// This intentionally rejects offsets, leap seconds, and subseconds so the
    /// Rust model and the shell semantic validator compare identical instants.
    ///
    /// # Errors
    ///
    /// Returns an error for a malformed or impossible Gregorian UTC timestamp.
    pub fn parse(value: String) -> Result<Self, AcceptanceReportError> {
        let bytes = value.as_bytes();
        if bytes.len() != 20
            || bytes[4] != b'-'
            || bytes[7] != b'-'
            || bytes[10] != b'T'
            || bytes[13] != b':'
            || bytes[16] != b':'
            || bytes[19] != b'Z'
        {
            return Err(AcceptanceReportError::Timestamp);
        }
        let year =
            u16::try_from(parse_decimal(&bytes[0..4]).ok_or(AcceptanceReportError::Timestamp)?)
                .map_err(|_| AcceptanceReportError::Timestamp)?;
        let month =
            u8::try_from(parse_decimal(&bytes[5..7]).ok_or(AcceptanceReportError::Timestamp)?)
                .map_err(|_| AcceptanceReportError::Timestamp)?;
        let day =
            u8::try_from(parse_decimal(&bytes[8..10]).ok_or(AcceptanceReportError::Timestamp)?)
                .map_err(|_| AcceptanceReportError::Timestamp)?;
        let hour =
            u8::try_from(parse_decimal(&bytes[11..13]).ok_or(AcceptanceReportError::Timestamp)?)
                .map_err(|_| AcceptanceReportError::Timestamp)?;
        let minute =
            u8::try_from(parse_decimal(&bytes[14..16]).ok_or(AcceptanceReportError::Timestamp)?)
                .map_err(|_| AcceptanceReportError::Timestamp)?;
        let second =
            u8::try_from(parse_decimal(&bytes[17..19]).ok_or(AcceptanceReportError::Timestamp)?)
                .map_err(|_| AcceptanceReportError::Timestamp)?;
        if year == 0
            || !(1..=12).contains(&month)
            || day == 0
            || day > days_in_month(year, month)
            || hour > 23
            || minute > 59
            || second > 59
        {
            return Err(AcceptanceReportError::Timestamp);
        }
        Ok(Self {
            encoded: value,
            order_key: (year, month, day, hour, minute, second),
        })
    }

    /// Canonical UTC representation.
    #[must_use]
    pub fn as_str(&self) -> &str {
        &self.encoded
    }
}

impl Serialize for ReportTimestamp {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.encoded)
    }
}

/// Bounded stable reason for a blocker or non-passing case.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcceptanceReason {
    code: String,
    message: String,
}

impl AcceptanceReason {
    /// Construct a privacy-safe reason.
    ///
    /// # Errors
    ///
    /// Returns an error for a noncanonical code or unsafe/oversized message.
    pub fn new(code: String, message: String) -> Result<Self, AcceptanceReportError> {
        if !valid_reason_code(&code) || !valid_bounded_text(&message, 1, 512) {
            return Err(AcceptanceReportError::Reason);
        }
        Ok(Self { code, message })
    }

    /// Stable reason code.
    #[must_use]
    pub fn code(&self) -> &str {
        &self.code
    }

    /// Bounded human-readable explanation.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

/// One bounded content-addressed evidence reference.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcceptanceEvidence {
    id: String,
    kind: AcceptanceEvidenceKind,
    sha256: Sha256Digest,
    path: String,
    check: String,
}

impl AcceptanceEvidence {
    /// Construct one evidence reference below the run-owned artifact root.
    ///
    /// # Errors
    ///
    /// Returns an error for malformed identifiers, traversal-capable paths, or
    /// unsafe/oversized producer checks.
    pub fn new(
        id: String,
        kind: AcceptanceEvidenceKind,
        sha256: Sha256Digest,
        path: String,
        check: String,
    ) -> Result<Self, AcceptanceReportError> {
        if !valid_evidence_id(&id)
            || !valid_evidence_path(&path)
            || !valid_bounded_text(&check, 1, 512)
        {
            return Err(AcceptanceReportError::Evidence);
        }
        Ok(Self {
            id,
            kind,
            sha256,
            path,
            check,
        })
    }

    /// Stable evidence identifier.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// Evidence kind.
    #[must_use]
    pub const fn kind(&self) -> AcceptanceEvidenceKind {
        self.kind
    }

    /// Artifact digest.
    #[must_use]
    pub const fn sha256(&self) -> &Sha256Digest {
        &self.sha256
    }

    /// Artifact path relative to the run-owned artifact root.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.path
    }

    /// Stable producer check or assertion.
    #[must_use]
    pub fn check(&self) -> &str {
        &self.check
    }
}

/// Bounded, non-sensitive execution environment metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcceptanceEnvironment {
    debian_version: Option<String>,
    architecture: Option<String>,
    kernel: Option<String>,
    rustc: Option<String>,
    native_revisions: BTreeMap<String, SourceRevision>,
}

impl AcceptanceEnvironment {
    /// Construct an entirely unknown environment for a pre-attempt refusal.
    #[must_use]
    pub const fn unknown() -> Self {
        Self {
            debian_version: None,
            architecture: None,
            kernel: None,
            rustc: None,
            native_revisions: BTreeMap::new(),
        }
    }

    /// Construct bounded optional environment provenance.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, unsafe, excessive, or malformed metadata.
    pub fn new(
        debian_version: Option<String>,
        architecture: Option<String>,
        kernel: Option<String>,
        rustc: Option<String>,
        native_revisions: BTreeMap<String, SourceRevision>,
    ) -> Result<Self, AcceptanceReportError> {
        let bounded_values = [
            (debian_version.as_deref(), 64),
            (architecture.as_deref(), 64),
            (kernel.as_deref(), 256),
            (rustc.as_deref(), 256),
        ];
        if bounded_values
            .into_iter()
            .any(|(value, maximum)| value.is_some_and(|text| !valid_bounded_text(text, 1, maximum)))
            || native_revisions.len() > MAX_NATIVE_REVISIONS
            || native_revisions
                .keys()
                .any(|name| !valid_native_revision_name(name))
        {
            return Err(AcceptanceReportError::Environment);
        }
        Ok(Self {
            debian_version,
            architecture,
            kernel,
            rustc,
            native_revisions,
        })
    }

    /// Construct the complete environment required for an attempted run.
    ///
    /// # Errors
    ///
    /// Returns an error when any supplied metadata violates its fixed bounds.
    pub fn complete(
        debian_version: String,
        architecture: String,
        kernel: String,
        rustc: String,
        native_revisions: BTreeMap<String, SourceRevision>,
    ) -> Result<Self, AcceptanceReportError> {
        Self::new(
            Some(debian_version),
            Some(architecture),
            Some(kernel),
            Some(rustc),
            native_revisions,
        )
    }

    fn is_supported_target(&self) -> bool {
        self.debian_version.as_deref() == Some("13")
            && self.architecture.as_deref() == Some("amd64")
            && self.kernel.is_some()
            && self.rustc.is_some()
    }
}

/// Provenance available when no acceptance execution was attempted.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct PartialAcceptanceProvenance {
    source_revision: Option<SourceRevision>,
    generated_at: Option<ReportTimestamp>,
}

impl PartialAcceptanceProvenance {
    /// Construct unavailable provenance for a fail-closed early refusal.
    #[must_use]
    pub const fn unavailable() -> Self {
        Self {
            source_revision: None,
            generated_at: None,
        }
    }

    /// Construct known generation provenance for a report that was not attempted.
    #[must_use]
    pub const fn known(source_revision: SourceRevision, generated_at: ReportTimestamp) -> Self {
        Self {
            source_revision: Some(source_revision),
            generated_at: Some(generated_at),
        }
    }
}

/// Complete immutable provenance for an attempted acceptance run.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CompleteAcceptanceProvenance {
    source_revision: SourceRevision,
    generated_at: ReportTimestamp,
    started_at: ReportTimestamp,
    finished_at: ReportTimestamp,
}

impl CompleteAcceptanceProvenance {
    /// Construct ordered source and timestamp provenance.
    ///
    /// # Errors
    ///
    /// Returns an error unless `started_at <= finished_at <= generated_at`.
    pub fn new(
        source_revision: SourceRevision,
        generated_at: ReportTimestamp,
        started_at: ReportTimestamp,
        finished_at: ReportTimestamp,
    ) -> Result<Self, AcceptanceReportError> {
        if started_at > finished_at || finished_at > generated_at {
            return Err(AcceptanceReportError::Timestamp);
        }
        Ok(Self {
            source_revision,
            generated_at,
            started_at,
            finished_at,
        })
    }
}

/// Acceptance-run execution state.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcceptanceExecution {
    requested_mode: RequestedMode,
    attempted: bool,
    completed: bool,
    topology_created: bool,
    blockers: Vec<AcceptanceReason>,
}

impl AcceptanceExecution {
    /// Construct the state of an attempted execute-mode run.
    ///
    /// # Errors
    ///
    /// Returns an error for excessive or duplicate blocker codes.
    pub fn attempted(
        completed: bool,
        topology_created: bool,
        blockers: Vec<AcceptanceReason>,
    ) -> Result<Self, AcceptanceReportError> {
        validate_blockers(&blockers)?;
        Ok(Self {
            requested_mode: RequestedMode::Execute,
            attempted: true,
            completed,
            topology_created,
            blockers,
        })
    }

    fn blocked_before_attempt(
        requested_mode: RequestedMode,
        blockers: Vec<AcceptanceReason>,
    ) -> Result<Self, AcceptanceReportError> {
        if blockers.is_empty() {
            return Err(AcceptanceReportError::Execution);
        }
        validate_blockers(&blockers)?;
        Ok(Self {
            requested_mode,
            attempted: false,
            completed: false,
            topology_created: false,
            blockers,
        })
    }

    /// Whether privileged execution was attempted.
    #[must_use]
    pub const fn attempted_execution(&self) -> bool {
        self.attempted
    }

    /// Execution blockers.
    #[must_use]
    pub fn blockers(&self) -> &[AcceptanceReason] {
        &self.blockers
    }
}

/// Captured host-state comparison.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcceptanceHostState {
    captured: bool,
    before_digest: Option<Sha256Digest>,
    after_digest: Option<Sha256Digest>,
    unchanged: Option<bool>,
}

impl AcceptanceHostState {
    /// Construct the absence of a complete before-and-after capture.
    #[must_use]
    pub const fn not_captured() -> Self {
        Self {
            captured: false,
            before_digest: None,
            after_digest: None,
            unchanged: None,
        }
    }

    /// Construct a complete comparison and derive `unchanged` from its digests.
    #[must_use]
    pub fn captured(before_digest: Sha256Digest, after_digest: Sha256Digest) -> Self {
        let unchanged = before_digest == after_digest;
        Self {
            captured: true,
            before_digest: Some(before_digest),
            after_digest: Some(after_digest),
            unchanged: Some(unchanged),
        }
    }

    /// Whether complete host-state evidence was captured.
    #[must_use]
    pub const fn was_captured(&self) -> bool {
        self.captured
    }

    /// Derived host-state equality, or `None` without complete capture.
    #[must_use]
    pub const fn unchanged(&self) -> Option<bool> {
        self.unchanged
    }
}

/// Cleanup observation for run-owned resources.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcceptanceCleanup {
    attempted: bool,
    complete: Option<bool>,
    remaining_owned_objects: Option<u64>,
}

impl AcceptanceCleanup {
    /// Construct cleanup state for a run that never attempted cleanup.
    #[must_use]
    pub const fn not_attempted() -> Self {
        Self {
            attempted: false,
            complete: None,
            remaining_owned_objects: None,
        }
    }

    /// Construct verified complete cleanup with zero remaining owned objects.
    #[must_use]
    pub const fn complete() -> Self {
        Self {
            attempted: true,
            complete: Some(true),
            remaining_owned_objects: Some(0),
        }
    }

    /// Construct verified incomplete cleanup.
    ///
    /// # Errors
    ///
    /// Returns an error for zero or an excessive remaining-object count.
    pub fn incomplete(remaining_owned_objects: u64) -> Result<Self, AcceptanceReportError> {
        if remaining_owned_objects == 0 || remaining_owned_objects > MAX_REMAINING_OWNED_OBJECTS {
            return Err(AcceptanceReportError::Cleanup);
        }
        Ok(Self {
            attempted: true,
            complete: Some(false),
            remaining_owned_objects: Some(remaining_owned_objects),
        })
    }

    /// Construct cleanup that was attempted but could not be verified.
    #[must_use]
    pub const fn indeterminate_after_attempt() -> Self {
        Self {
            attempted: true,
            complete: None,
            remaining_owned_objects: None,
        }
    }

    fn is_complete(&self) -> bool {
        self.attempted && self.complete == Some(true) && self.remaining_owned_objects == Some(0)
    }

    fn is_observed_incomplete(&self) -> bool {
        self.attempted
            && self.complete == Some(false)
            && self
                .remaining_owned_objects
                .is_some_and(|remaining| remaining > 0)
    }
}

/// One canonical acceptance-case entry.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcceptanceCase {
    id: AcceptanceId,
    selected: bool,
    result: AcceptanceCaseResult,
    reason: Option<AcceptanceReason>,
    evidence: Vec<AcceptanceEvidence>,
}

impl AcceptanceCase {
    /// Construct a selected passing case.
    ///
    /// # Errors
    ///
    /// Returns an error unless one to 32 evidence objects are supplied.
    pub fn passed(
        id: AcceptanceId,
        evidence: Vec<AcceptanceEvidence>,
    ) -> Result<Self, AcceptanceReportError> {
        validate_evidence_count(&evidence, true)?;
        Ok(Self {
            id,
            selected: true,
            result: AcceptanceCaseResult::Pass,
            reason: None,
            evidence,
        })
    }

    /// Construct a selected failed assertion.
    ///
    /// # Errors
    ///
    /// Returns an error unless one to 32 evidence objects are supplied.
    pub fn failed(
        id: AcceptanceId,
        reason: AcceptanceReason,
        evidence: Vec<AcceptanceEvidence>,
    ) -> Result<Self, AcceptanceReportError> {
        validate_evidence_count(&evidence, true)?;
        Ok(Self {
            id,
            selected: true,
            result: AcceptanceCaseResult::Fail,
            reason: Some(reason),
            evidence,
        })
    }

    /// Construct a selected skipped case.
    ///
    /// # Errors
    ///
    /// Returns an error for more than 32 evidence objects.
    pub fn skipped(
        id: AcceptanceId,
        reason: AcceptanceReason,
        evidence: Vec<AcceptanceEvidence>,
    ) -> Result<Self, AcceptanceReportError> {
        validate_evidence_count(&evidence, false)?;
        Ok(Self {
            id,
            selected: true,
            result: AcceptanceCaseResult::Skipped,
            reason: Some(reason),
            evidence,
        })
    }

    /// Construct a selected case that encountered an execution error.
    ///
    /// # Errors
    ///
    /// Returns an error for more than 32 evidence objects.
    pub fn errored(
        id: AcceptanceId,
        reason: AcceptanceReason,
        evidence: Vec<AcceptanceEvidence>,
    ) -> Result<Self, AcceptanceReportError> {
        validate_evidence_count(&evidence, false)?;
        Ok(Self {
            id,
            selected: true,
            result: AcceptanceCaseResult::Error,
            reason: Some(reason),
            evidence,
        })
    }

    fn not_selected(id: AcceptanceId, suite: AcceptanceSuite) -> Self {
        let message = format!("The case is outside the selected {suite:?} suite.");
        Self {
            id,
            selected: false,
            result: AcceptanceCaseResult::Skipped,
            reason: Some(
                AcceptanceReason::new(NOT_SELECTED_CODE.to_owned(), message)
                    .expect("fixed not-selected reason is valid"),
            ),
            evidence: Vec::new(),
        }
    }

    /// Case identifier.
    #[must_use]
    pub const fn id(&self) -> AcceptanceId {
        self.id
    }

    /// Whether this case belongs to the requested suite.
    #[must_use]
    pub const fn selected(&self) -> bool {
        self.selected
    }

    /// Case result.
    #[must_use]
    pub const fn result(&self) -> AcceptanceCaseResult {
        self.result
    }

    /// Content-addressed evidence references.
    #[must_use]
    pub fn evidence(&self) -> &[AcceptanceEvidence] {
        &self.evidence
    }
}

#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
enum ReportKind {
    #[serde(rename = "acceptance")]
    Acceptance,
}

/// Complete canonical machine-readable acceptance report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcceptanceReport {
    schema_version: u32,
    report_kind: ReportKind,
    suite: AcceptanceSuite,
    source_revision: Option<SourceRevision>,
    generated_at: Option<ReportTimestamp>,
    started_at: Option<ReportTimestamp>,
    finished_at: Option<ReportTimestamp>,
    execution: AcceptanceExecution,
    environment: AcceptanceEnvironment,
    host_state: AcceptanceHostState,
    cases: [AcceptanceCase; ACCEPTANCE_CASE_COUNT],
    cleanup: AcceptanceCleanup,
    overall: AcceptanceOverallResult,
}

impl AcceptanceReport {
    /// Construct a fail-closed report for a request refused before execution.
    ///
    /// Selected cases are skipped with the first blocker; unselected cases are
    /// generated canonically. Partial-suite provenance is added automatically.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, excessive, or duplicate blockers.
    pub fn blocked_before_attempt(
        suite: AcceptanceSuite,
        requested_mode: RequestedMode,
        provenance: PartialAcceptanceProvenance,
        environment: AcceptanceEnvironment,
        mut blockers: Vec<AcceptanceReason>,
    ) -> Result<Self, AcceptanceReportError> {
        if blockers.is_empty() {
            return Err(AcceptanceReportError::Execution);
        }
        let selected_reason = blockers[0].clone();
        add_partial_suite_blocker(suite, &mut blockers)?;
        let execution = AcceptanceExecution::blocked_before_attempt(requested_mode, blockers)?;
        let cases = ALL_ACCEPTANCE_IDS.map(|id| {
            if suite.selects(id) {
                AcceptanceCase {
                    id,
                    selected: true,
                    result: AcceptanceCaseResult::Skipped,
                    reason: Some(selected_reason.clone()),
                    evidence: Vec::new(),
                }
            } else {
                AcceptanceCase::not_selected(id, suite)
            }
        });
        Ok(Self {
            schema_version: ACCEPTANCE_REPORT_SCHEMA_VERSION,
            report_kind: ReportKind::Acceptance,
            suite,
            source_revision: provenance.source_revision,
            generated_at: provenance.generated_at,
            started_at: None,
            finished_at: None,
            execution,
            environment,
            host_state: AcceptanceHostState::not_captured(),
            cases,
            cleanup: AcceptanceCleanup::not_attempted(),
            overall: AcceptanceOverallResult::Blocked,
        })
    }

    /// Construct an attempted report and derive its overall outcome.
    ///
    /// The supplied vector contains only selected cases, exactly once and in
    /// canonical order. Unselected cases and partial-suite blockers are added
    /// automatically.
    ///
    /// # Errors
    ///
    /// Returns an error for incomplete provenance/environment, a wrong case
    /// set, duplicate evidence IDs, incoherent execution state, or invalid
    /// A14/A15 evidence and state binding.
    pub fn from_attempt(
        suite: AcceptanceSuite,
        provenance: CompleteAcceptanceProvenance,
        environment: AcceptanceEnvironment,
        mut execution: AcceptanceExecution,
        selected_cases: Vec<AcceptanceCase>,
        host_state: AcceptanceHostState,
        cleanup: AcceptanceCleanup,
    ) -> Result<Self, AcceptanceReportError> {
        if !execution.attempted || execution.requested_mode != RequestedMode::Execute {
            return Err(AcceptanceReportError::Execution);
        }
        if !environment.is_supported_target() {
            return Err(AcceptanceReportError::Environment);
        }
        add_partial_suite_blocker(suite, &mut execution.blockers)?;
        validate_blockers(&execution.blockers)?;
        let cases = canonical_cases(suite, selected_cases)?;
        validate_execution_cases(&execution, &cases)?;
        validate_unique_evidence_ids(&cases)?;
        validate_skipped_blockers(&cases, &execution.blockers)?;
        validate_a14(&cases[13], &cleanup)?;
        validate_a15(&cases[14], &host_state)?;
        let overall = derive_overall(suite, &execution, &cases, &host_state, &cleanup)?;
        Ok(Self {
            schema_version: ACCEPTANCE_REPORT_SCHEMA_VERSION,
            report_kind: ReportKind::Acceptance,
            suite,
            source_revision: Some(provenance.source_revision),
            generated_at: Some(provenance.generated_at),
            started_at: Some(provenance.started_at),
            finished_at: Some(provenance.finished_at),
            execution,
            environment,
            host_state,
            cases,
            cleanup,
            overall,
        })
    }

    /// Requested suite.
    #[must_use]
    pub const fn suite(&self) -> AcceptanceSuite {
        self.suite
    }

    /// Derived overall result.
    #[must_use]
    pub const fn overall(&self) -> AcceptanceOverallResult {
        self.overall
    }

    /// True only for full A01-A15 acceptance.
    #[must_use]
    pub const fn is_success(&self) -> bool {
        matches!(self.overall, AcceptanceOverallResult::Pass)
    }

    /// Cases in canonical A01-A15 order.
    #[must_use]
    pub const fn cases(&self) -> &[AcceptanceCase; ACCEPTANCE_CASE_COUNT] {
        &self.cases
    }

    /// Execution metadata, including automatically derived partial-suite blockers.
    #[must_use]
    pub const fn execution(&self) -> &AcceptanceExecution {
        &self.execution
    }
}

fn canonical_cases(
    suite: AcceptanceSuite,
    selected_cases: Vec<AcceptanceCase>,
) -> Result<[AcceptanceCase; ACCEPTANCE_CASE_COUNT], AcceptanceReportError> {
    let mut selected = selected_cases.into_iter();
    let mut cases = Vec::with_capacity(ACCEPTANCE_CASE_COUNT);
    for id in ALL_ACCEPTANCE_IDS {
        if suite.selects(id) {
            let case = selected.next().ok_or(AcceptanceReportError::Cases)?;
            if case.id != id || !case.selected {
                return Err(AcceptanceReportError::Cases);
            }
            cases.push(case);
        } else {
            cases.push(AcceptanceCase::not_selected(id, suite));
        }
    }
    if selected.next().is_some() {
        return Err(AcceptanceReportError::Cases);
    }
    cases.try_into().map_err(|_| AcceptanceReportError::Cases)
}

fn derive_overall(
    suite: AcceptanceSuite,
    execution: &AcceptanceExecution,
    cases: &[AcceptanceCase; ACCEPTANCE_CASE_COUNT],
    host_state: &AcceptanceHostState,
    cleanup: &AcceptanceCleanup,
) -> Result<AcceptanceOverallResult, AcceptanceReportError> {
    let selected_has = |result| {
        cases
            .iter()
            .filter(|case| case.selected)
            .any(|case| case.result == result)
    };
    let post_attempt_indeterminate = (execution.attempted && !host_state.captured)
        || (execution.topology_created && (!cleanup.attempted || cleanup.complete.is_none()));
    if selected_has(AcceptanceCaseResult::Error) || post_attempt_indeterminate {
        return Ok(AcceptanceOverallResult::Error);
    }
    if selected_has(AcceptanceCaseResult::Fail)
        || (host_state.captured && host_state.unchanged == Some(false))
        || cleanup.is_observed_incomplete()
    {
        return Ok(AcceptanceOverallResult::Fail);
    }
    if suite != AcceptanceSuite::All
        || !execution.completed
        || !execution.topology_created
        || !execution.blockers.is_empty()
        || selected_has(AcceptanceCaseResult::Skipped)
    {
        if execution.blockers.is_empty() {
            return Err(AcceptanceReportError::Overall);
        }
        return Ok(AcceptanceOverallResult::Blocked);
    }
    if !selected_has(AcceptanceCaseResult::Skipped)
        && host_state.captured
        && host_state.unchanged == Some(true)
        && cleanup.is_complete()
    {
        return Ok(AcceptanceOverallResult::Pass);
    }
    Err(AcceptanceReportError::Overall)
}

fn validate_a14(
    case: &AcceptanceCase,
    cleanup: &AcceptanceCleanup,
) -> Result<(), AcceptanceReportError> {
    if case.id != AcceptanceId::A14 || !case.selected {
        return Err(AcceptanceReportError::A14);
    }
    if case.result == AcceptanceCaseResult::Pass
        && (!cleanup.is_complete()
            || A14_REQUIRED_CHECKS
                .iter()
                .any(|required| !case.evidence.iter().any(|item| item.check == *required)))
    {
        return Err(AcceptanceReportError::A14);
    }
    if cleanup.is_observed_incomplete() && case.result != AcceptanceCaseResult::Fail {
        return Err(AcceptanceReportError::A14);
    }
    Ok(())
}

fn validate_a15(
    case: &AcceptanceCase,
    host_state: &AcceptanceHostState,
) -> Result<(), AcceptanceReportError> {
    if case.id != AcceptanceId::A15 || !case.selected {
        return Err(AcceptanceReportError::A15);
    }
    if case.result == AcceptanceCaseResult::Pass {
        let (Some(before), Some(after)) = (
            host_state.before_digest.as_ref(),
            host_state.after_digest.as_ref(),
        ) else {
            return Err(AcceptanceReportError::A15);
        };
        let evidence_binds = |id: &str, digest: &Sha256Digest| {
            case.evidence.iter().any(|item| {
                item.id == id
                    && item.kind == AcceptanceEvidenceKind::Digest
                    && item.sha256 == *digest
            })
        };
        if !host_state.captured
            || host_state.unchanged != Some(true)
            || before != after
            || !evidence_binds(A15_BEFORE_EVIDENCE_ID, before)
            || !evidence_binds(A15_AFTER_EVIDENCE_ID, after)
        {
            return Err(AcceptanceReportError::A15);
        }
    }
    if host_state.captured
        && host_state.unchanged == Some(false)
        && case.result != AcceptanceCaseResult::Fail
    {
        return Err(AcceptanceReportError::A15);
    }
    Ok(())
}

fn validate_skipped_blockers(
    cases: &[AcceptanceCase; ACCEPTANCE_CASE_COUNT],
    blockers: &[AcceptanceReason],
) -> Result<(), AcceptanceReportError> {
    for case in cases
        .iter()
        .filter(|case| case.selected && case.result == AcceptanceCaseResult::Skipped)
    {
        let reason = case.reason.as_ref().ok_or(AcceptanceReportError::Cases)?;
        if !blockers.iter().any(|blocker| blocker.code == reason.code) {
            return Err(AcceptanceReportError::Execution);
        }
    }
    Ok(())
}

fn validate_execution_cases(
    execution: &AcceptanceExecution,
    cases: &[AcceptanceCase; ACCEPTANCE_CASE_COUNT],
) -> Result<(), AcceptanceReportError> {
    if !execution.topology_created
        && (execution.completed
            || cases.iter().filter(|case| case.selected).any(|case| {
                matches!(
                    case.result,
                    AcceptanceCaseResult::Pass | AcceptanceCaseResult::Fail
                )
            }))
    {
        return Err(AcceptanceReportError::Execution);
    }
    Ok(())
}

fn validate_unique_evidence_ids(
    cases: &[AcceptanceCase; ACCEPTANCE_CASE_COUNT],
) -> Result<(), AcceptanceReportError> {
    let mut ids = HashSet::new();
    if cases
        .iter()
        .flat_map(|case| &case.evidence)
        .any(|item| !ids.insert(item.id.as_str()))
    {
        return Err(AcceptanceReportError::DuplicateEvidence);
    }
    Ok(())
}

fn add_partial_suite_blocker(
    suite: AcceptanceSuite,
    blockers: &mut Vec<AcceptanceReason>,
) -> Result<(), AcceptanceReportError> {
    if suite == AcceptanceSuite::All {
        return Ok(());
    }
    let canonical = AcceptanceReason::new(
        PARTIAL_SUITE_CODE.to_owned(),
        "Only a selected subset ran; full A01-A15 acceptance is not established.".to_owned(),
    )
    .expect("fixed partial-suite reason is valid");
    if let Some(existing) = blockers
        .iter()
        .find(|blocker| blocker.code == PARTIAL_SUITE_CODE)
    {
        if existing != &canonical {
            return Err(AcceptanceReportError::Execution);
        }
    } else {
        if blockers.len() == MAX_ACCEPTANCE_BLOCKERS {
            return Err(AcceptanceReportError::Execution);
        }
        blockers.push(canonical);
    }
    Ok(())
}

fn validate_blockers(blockers: &[AcceptanceReason]) -> Result<(), AcceptanceReportError> {
    if blockers.len() > MAX_ACCEPTANCE_BLOCKERS {
        return Err(AcceptanceReportError::Execution);
    }
    let mut codes = HashSet::new();
    if blockers
        .iter()
        .any(|blocker| !codes.insert(blocker.code.as_str()))
    {
        return Err(AcceptanceReportError::Execution);
    }
    Ok(())
}

fn validate_evidence_count(
    evidence: &[AcceptanceEvidence],
    required: bool,
) -> Result<(), AcceptanceReportError> {
    if evidence.len() > MAX_ACCEPTANCE_EVIDENCE_PER_CASE || (required && evidence.is_empty()) {
        return Err(AcceptanceReportError::Evidence);
    }
    Ok(())
}

fn valid_reason_code(value: &str) -> bool {
    let mut bytes = value.bytes();
    bytes.next().is_some_and(|byte| byte.is_ascii_uppercase())
        && value.len() <= 64
        && bytes.all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_evidence_id(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 128
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b':' | b'-'))
}

fn valid_evidence_path(value: &str) -> bool {
    valid_bounded_text(value, 1, 512)
        && !value.starts_with('/')
        && !value.contains('\\')
        && value.split('/').all(|component| {
            !component.is_empty()
                && component != "."
                && component != ".."
                && component
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'.' | b'_' | b'-'))
        })
}

fn valid_native_revision_name(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || matches!(byte, b'_' | b'.' | b'+' | b'-'))
}

fn valid_bounded_text(value: &str, minimum: usize, maximum: usize) -> bool {
    let length = value.chars().count();
    (minimum..=maximum).contains(&length) && !value.chars().any(char::is_control)
}

fn valid_hex_with_lengths(value: &str, lengths: &[usize]) -> bool {
    lengths.contains(&value.len())
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn parse_decimal(bytes: &[u8]) -> Option<u32> {
    bytes.iter().try_fold(0_u32, |value, byte| {
        byte.is_ascii_digit()
            .then_some(value * 10 + u32::from(byte - b'0'))
    })
}

const fn days_in_month(year: u16, month: u8) -> u8 {
    match month {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if year % 400 == 0 || (year % 4 == 0 && year % 100 != 0) => 29,
        2 => 28,
        _ => 0,
    }
}

/// Invalid machine-report structure, provenance, state, or evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AcceptanceReportError {
    /// A source revision is not canonical lowercase Git SHA-1/SHA-256 text.
    #[error("acceptance source revision is invalid")]
    Revision,
    /// A SHA-256 digest is malformed.
    #[error("acceptance SHA-256 digest is invalid")]
    Digest,
    /// A report timestamp is malformed or out of order.
    #[error("acceptance report timestamp is invalid")]
    Timestamp,
    /// A reason code or message violates fixed bounds.
    #[error("acceptance reason is invalid")]
    Reason,
    /// Evidence metadata violates fixed bounds or path safety.
    #[error("acceptance evidence is invalid")]
    Evidence,
    /// Environment metadata is incomplete, unsafe, or oversized.
    #[error("acceptance environment metadata is invalid")]
    Environment,
    /// Execution state or blocker provenance is incoherent.
    #[error("acceptance execution state is invalid")]
    Execution,
    /// Cleanup state is incoherent or excessive.
    #[error("acceptance cleanup state is invalid")]
    Cleanup,
    /// The selected case set is missing, duplicated, or out of order.
    #[error("acceptance case set or ordering is invalid")]
    Cases,
    /// Evidence identifiers are not globally unique.
    #[error("acceptance evidence identifiers are duplicated")]
    DuplicateEvidence,
    /// A14 contradicts cleanup state or lacks mandatory crash evidence.
    #[error("A14 cleanup evidence or state is invalid")]
    A14,
    /// A15 contradicts host state or lacks digest-bound evidence.
    #[error("A15 host-state evidence or state is invalid")]
    A15,
    /// The execution state cannot produce an honest overall outcome.
    #[error("acceptance overall result is incoherent")]
    Overall,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn revision() -> SourceRevision {
        SourceRevision::new("a".repeat(40)).unwrap()
    }

    fn timestamp(value: &str) -> ReportTimestamp {
        ReportTimestamp::parse(value.to_owned()).unwrap()
    }

    fn provenance() -> CompleteAcceptanceProvenance {
        CompleteAcceptanceProvenance::new(
            revision(),
            timestamp("2026-08-23T12:00:02Z"),
            timestamp("2026-08-23T12:00:00Z"),
            timestamp("2026-08-23T12:00:01Z"),
        )
        .unwrap()
    }

    fn environment() -> AcceptanceEnvironment {
        AcceptanceEnvironment::complete(
            "13".to_owned(),
            "amd64".to_owned(),
            "6.12.0".to_owned(),
            "rustc 1.85.0".to_owned(),
            BTreeMap::new(),
        )
        .unwrap()
    }

    fn reason(code: &str) -> AcceptanceReason {
        AcceptanceReason::new(code.to_owned(), "bounded reason".to_owned()).unwrap()
    }

    fn digest(character: char) -> Sha256Digest {
        Sha256Digest::new(character.to_string().repeat(64)).unwrap()
    }

    fn evidence(
        id: &str,
        kind: AcceptanceEvidenceKind,
        digest: Sha256Digest,
        check: &str,
    ) -> AcceptanceEvidence {
        AcceptanceEvidence::new(
            id.to_owned(),
            kind,
            digest,
            format!("artifacts/{id}.json"),
            check.to_owned(),
        )
        .unwrap()
    }

    fn passing_case(id: AcceptanceId, host_digest: &Sha256Digest) -> AcceptanceCase {
        match id {
            AcceptanceId::A14 => AcceptanceCase::passed(
                id,
                A14_REQUIRED_CHECKS
                    .into_iter()
                    .enumerate()
                    .map(|(index, check)| {
                        evidence(
                            &format!("a14.check{index}"),
                            AcceptanceEvidenceKind::State,
                            digest('b'),
                            check,
                        )
                    })
                    .collect(),
            )
            .unwrap(),
            AcceptanceId::A15 => AcceptanceCase::passed(
                id,
                vec![
                    evidence(
                        A15_BEFORE_EVIDENCE_ID,
                        AcceptanceEvidenceKind::Digest,
                        host_digest.clone(),
                        "HOST_STATE_BEFORE",
                    ),
                    evidence(
                        A15_AFTER_EVIDENCE_ID,
                        AcceptanceEvidenceKind::Digest,
                        host_digest.clone(),
                        "HOST_STATE_AFTER",
                    ),
                ],
            )
            .unwrap(),
            _ => AcceptanceCase::passed(
                id,
                vec![evidence(
                    &format!("{id:?}.evidence"),
                    AcceptanceEvidenceKind::Measurement,
                    digest('c'),
                    "ASSERTION_VERIFIED",
                )],
            )
            .unwrap(),
        }
    }

    fn passing_selected_cases(
        suite: AcceptanceSuite,
        host_digest: &Sha256Digest,
    ) -> Vec<AcceptanceCase> {
        ALL_ACCEPTANCE_IDS
            .into_iter()
            .filter(|id| suite.selects(*id))
            .map(|id| passing_case(id, host_digest))
            .collect()
    }

    fn attempted_report(
        suite: AcceptanceSuite,
        cases: Vec<AcceptanceCase>,
        blockers: Vec<AcceptanceReason>,
        host_state: AcceptanceHostState,
        cleanup: AcceptanceCleanup,
    ) -> Result<AcceptanceReport, AcceptanceReportError> {
        AcceptanceReport::from_attempt(
            suite,
            provenance(),
            environment(),
            AcceptanceExecution::attempted(true, true, blockers).unwrap(),
            cases,
            host_state,
            cleanup,
        )
    }

    #[test]
    fn full_report_serializes_exact_contract_names_and_passes() {
        let host_digest = digest('d');
        let report = attempted_report(
            AcceptanceSuite::All,
            passing_selected_cases(AcceptanceSuite::All, &host_digest),
            Vec::new(),
            AcceptanceHostState::captured(host_digest.clone(), host_digest.clone()),
            AcceptanceCleanup::complete(),
        )
        .unwrap();
        assert!(report.is_success());
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value["schema_version"], 1);
        assert_eq!(value["report_kind"], "acceptance");
        assert_eq!(value["suite"], "all");
        assert_eq!(value["overall"], "PASS");
        assert_eq!(value["cases"].as_array().unwrap().len(), 15);
        assert_eq!(value["cases"][0]["id"], "A01");
        assert_eq!(value["cases"][14]["id"], "A15");
        assert_eq!(value["started_at"], "2026-08-23T12:00:00Z");
    }

    #[test]
    fn full_and_partial_model_reports_validate_against_normative_draft_2020_12_schema() {
        let schema: serde_json::Value = serde_json::from_str(include_str!(
            "../../../tests/integration/acceptance-report.schema.json"
        ))
        .unwrap();
        jsonschema::draft202012::meta::validate(&schema).unwrap();
        let validator = jsonschema::options()
            .with_draft(jsonschema::Draft::Draft202012)
            .should_validate_formats(true)
            .build(&schema)
            .unwrap();
        let host_digest = digest('d');
        let full = attempted_report(
            AcceptanceSuite::All,
            passing_selected_cases(AcceptanceSuite::All, &host_digest),
            Vec::new(),
            AcceptanceHostState::captured(host_digest.clone(), host_digest.clone()),
            AcceptanceCleanup::complete(),
        )
        .unwrap();
        let partial = attempted_report(
            AcceptanceSuite::Mptcp,
            passing_selected_cases(AcceptanceSuite::Mptcp, &host_digest),
            Vec::new(),
            AcceptanceHostState::captured(host_digest.clone(), host_digest.clone()),
            AcceptanceCleanup::complete(),
        )
        .unwrap();
        let mpquic = attempted_report(
            AcceptanceSuite::Mpquic,
            passing_selected_cases(AcceptanceSuite::Mpquic, &host_digest),
            Vec::new(),
            AcceptanceHostState::captured(host_digest.clone(), host_digest),
            AcceptanceCleanup::complete(),
        )
        .unwrap();
        assert!(validator.is_valid(&serde_json::to_value(full).unwrap()));
        assert!(validator.is_valid(&serde_json::to_value(partial).unwrap()));
        assert!(validator.is_valid(&serde_json::to_value(mpquic).unwrap()));

        let mut structurally_invalid = serde_json::to_value(
            AcceptanceReport::blocked_before_attempt(
                AcceptanceSuite::All,
                RequestedMode::Preview,
                PartialAcceptanceProvenance::unavailable(),
                AcceptanceEnvironment::unknown(),
                vec![reason("DRIVER_UNAVAILABLE")],
            )
            .unwrap(),
        )
        .unwrap();
        structurally_invalid["unexpected"] = serde_json::Value::Bool(true);
        assert!(!validator.is_valid(&structurally_invalid));
        structurally_invalid
            .as_object_mut()
            .unwrap()
            .remove("unexpected");
        structurally_invalid["generated_at"] =
            serde_json::Value::String("2023-02-29T12:00:02Z".to_owned());
        assert!(!validator.is_valid(&structurally_invalid));
    }

    #[test]
    fn suite_selection_is_exact_and_partial_suites_are_blocked() {
        let host_digest = digest('d');
        for (suite, selected) in [
            (
                AcceptanceSuite::Mptcp,
                vec![
                    AcceptanceId::A02,
                    AcceptanceId::A03,
                    AcceptanceId::A04,
                    AcceptanceId::A14,
                    AcceptanceId::A15,
                ],
            ),
            (
                AcceptanceSuite::Mpquic,
                vec![
                    AcceptanceId::A06,
                    AcceptanceId::A07,
                    AcceptanceId::A14,
                    AcceptanceId::A15,
                ],
            ),
        ] {
            let report = attempted_report(
                suite,
                passing_selected_cases(suite, &host_digest),
                Vec::new(),
                AcceptanceHostState::captured(host_digest.clone(), host_digest.clone()),
                AcceptanceCleanup::complete(),
            )
            .unwrap();
            assert_eq!(report.overall(), AcceptanceOverallResult::Blocked);
            assert_eq!(
                report
                    .cases()
                    .iter()
                    .filter(|case| case.selected())
                    .map(AcceptanceCase::id)
                    .collect::<Vec<_>>(),
                selected
            );
            assert!(
                report
                    .execution()
                    .blockers()
                    .iter()
                    .any(|blocker| blocker.code() == PARTIAL_SUITE_CODE)
            );
        }
    }

    #[test]
    fn blocked_before_attempt_is_canonical_and_never_claims_a_pass() {
        let report = AcceptanceReport::blocked_before_attempt(
            AcceptanceSuite::Mptcp,
            RequestedMode::Execute,
            PartialAcceptanceProvenance::unavailable(),
            AcceptanceEnvironment::unknown(),
            vec![reason("DRIVER_UNAVAILABLE")],
        )
        .unwrap();
        assert_eq!(report.overall(), AcceptanceOverallResult::Blocked);
        assert!(!report.is_success());
        assert!(
            report
                .cases()
                .iter()
                .all(|case| case.result() == AcceptanceCaseResult::Skipped)
        );
        let value = serde_json::to_value(report).unwrap();
        assert_eq!(value["started_at"], serde_json::Value::Null);
        assert_eq!(value["host_state"]["captured"], false);
        assert_eq!(value["cleanup"]["attempted"], false);
    }

    #[test]
    fn timestamp_is_canonical_valid_gregorian_utc_and_ordered() {
        assert!(ReportTimestamp::parse("2024-02-29T23:59:59Z".to_owned()).is_ok());
        for invalid in [
            "2023-02-29T23:59:59Z",
            "2026-08-23T12:00:00.1Z",
            "2026-08-23T14:00:00+02:00",
            "2026-08-23t12:00:00z",
            "2026-08-23T12:00:60Z",
        ] {
            assert_eq!(
                ReportTimestamp::parse(invalid.to_owned()).unwrap_err(),
                AcceptanceReportError::Timestamp
            );
        }
        assert_eq!(
            CompleteAcceptanceProvenance::new(
                revision(),
                timestamp("2026-08-23T12:00:00Z"),
                timestamp("2026-08-23T12:00:02Z"),
                timestamp("2026-08-23T12:00:01Z"),
            )
            .unwrap_err(),
            AcceptanceReportError::Timestamp
        );
    }

    #[test]
    fn revisions_reasons_environment_and_paths_are_strictly_bounded() {
        assert!(SourceRevision::new("a".repeat(40)).is_ok());
        assert!(SourceRevision::new("b".repeat(64)).is_ok());
        assert!(SourceRevision::new("A".repeat(40)).is_err());
        assert!(AcceptanceReason::new("1BAD".to_owned(), "reason".to_owned()).is_err());
        assert!(AcceptanceReason::new("GOOD_CODE".to_owned(), "x".repeat(512)).is_ok());
        assert!(AcceptanceReason::new("GOOD_CODE".to_owned(), "x".repeat(513)).is_err());
        for path in [
            "/absolute",
            "../escape",
            "safe/../escape",
            "safe//file",
            "safe\\file",
            "safe/colon:file",
            "safe/ünicode",
        ] {
            assert!(
                AcceptanceEvidence::new(
                    "id".to_owned(),
                    AcceptanceEvidenceKind::State,
                    digest('a'),
                    path.to_owned(),
                    "CHECK".to_owned(),
                )
                .is_err()
            );
        }
        let mut revisions = BTreeMap::new();
        revisions.insert("bad/name".to_owned(), revision());
        assert!(
            AcceptanceEnvironment::complete(
                "13".to_owned(),
                "amd64".to_owned(),
                "kernel".to_owned(),
                "rustc".to_owned(),
                revisions,
            )
            .is_err()
        );
        let host_digest = digest('d');
        for (debian, architecture) in [("12", "amd64"), ("13", "arm64")] {
            let unsupported = AcceptanceEnvironment::complete(
                debian.to_owned(),
                architecture.to_owned(),
                "kernel".to_owned(),
                "rustc".to_owned(),
                BTreeMap::new(),
            )
            .unwrap();
            assert_eq!(
                AcceptanceReport::from_attempt(
                    AcceptanceSuite::All,
                    provenance(),
                    unsupported,
                    AcceptanceExecution::attempted(true, true, Vec::new()).unwrap(),
                    passing_selected_cases(AcceptanceSuite::All, &host_digest),
                    AcceptanceHostState::captured(host_digest.clone(), host_digest.clone()),
                    AcceptanceCleanup::complete(),
                )
                .unwrap_err(),
                AcceptanceReportError::Environment
            );
        }
    }

    #[test]
    fn cases_require_canonical_order_and_unique_evidence_ids() {
        let host_digest = digest('d');
        let mut cases = passing_selected_cases(AcceptanceSuite::All, &host_digest);
        cases.swap(0, 1);
        assert_eq!(
            attempted_report(
                AcceptanceSuite::All,
                cases,
                Vec::new(),
                AcceptanceHostState::captured(host_digest.clone(), host_digest.clone()),
                AcceptanceCleanup::complete(),
            )
            .unwrap_err(),
            AcceptanceReportError::Cases
        );

        let mut cases = passing_selected_cases(AcceptanceSuite::All, &host_digest);
        let duplicate_id = cases[0].evidence[0].id.clone();
        cases[1].evidence[0].id = duplicate_id;
        assert_eq!(
            attempted_report(
                AcceptanceSuite::All,
                cases,
                Vec::new(),
                AcceptanceHostState::captured(host_digest.clone(), host_digest),
                AcceptanceCleanup::complete(),
            )
            .unwrap_err(),
            AcceptanceReportError::DuplicateEvidence
        );
    }

    #[test]
    fn a14_pass_requires_complete_cleanup_and_all_crash_checks() {
        let host_digest = digest('d');
        let mut cases = passing_selected_cases(AcceptanceSuite::All, &host_digest);
        cases[13].evidence.pop();
        assert_eq!(
            attempted_report(
                AcceptanceSuite::All,
                cases,
                Vec::new(),
                AcceptanceHostState::captured(host_digest.clone(), host_digest.clone()),
                AcceptanceCleanup::complete(),
            )
            .unwrap_err(),
            AcceptanceReportError::A14
        );

        let cases = passing_selected_cases(AcceptanceSuite::All, &host_digest);
        assert_eq!(
            attempted_report(
                AcceptanceSuite::All,
                cases,
                Vec::new(),
                AcceptanceHostState::captured(host_digest.clone(), host_digest),
                AcceptanceCleanup::incomplete(1).unwrap(),
            )
            .unwrap_err(),
            AcceptanceReportError::A14
        );
    }

    #[test]
    fn a15_pass_requires_evidence_bound_to_equal_host_digests() {
        let host_digest = digest('d');
        let mut cases = passing_selected_cases(AcceptanceSuite::All, &host_digest);
        cases[14].evidence[0].sha256 = digest('e');
        assert_eq!(
            attempted_report(
                AcceptanceSuite::All,
                cases,
                Vec::new(),
                AcceptanceHostState::captured(host_digest.clone(), host_digest.clone()),
                AcceptanceCleanup::complete(),
            )
            .unwrap_err(),
            AcceptanceReportError::A15
        );

        let cases = passing_selected_cases(AcceptanceSuite::All, &host_digest);
        assert_eq!(
            attempted_report(
                AcceptanceSuite::All,
                cases,
                Vec::new(),
                AcceptanceHostState::captured(host_digest, digest('e')),
                AcceptanceCleanup::complete(),
            )
            .unwrap_err(),
            AcceptanceReportError::A15
        );
    }

    #[test]
    fn error_and_failure_outcomes_take_precedence_over_blocked() {
        let host_digest = digest('d');
        let mut cases = passing_selected_cases(AcceptanceSuite::Mptcp, &host_digest);
        cases[0] = AcceptanceCase::failed(
            AcceptanceId::A02,
            reason("ASSERTION_FAILED"),
            vec![evidence(
                "a02.failure",
                AcceptanceEvidenceKind::Measurement,
                digest('f'),
                "FAILURE_OBSERVED",
            )],
        )
        .unwrap();
        let report = attempted_report(
            AcceptanceSuite::Mptcp,
            cases,
            Vec::new(),
            AcceptanceHostState::captured(host_digest.clone(), host_digest.clone()),
            AcceptanceCleanup::complete(),
        )
        .unwrap();
        assert_eq!(report.overall(), AcceptanceOverallResult::Fail);

        let mut cases = passing_selected_cases(AcceptanceSuite::Mptcp, &host_digest);
        cases[0] =
            AcceptanceCase::errored(AcceptanceId::A02, reason("EXECUTION_ERROR"), Vec::new())
                .unwrap();
        let report = attempted_report(
            AcceptanceSuite::Mptcp,
            cases,
            Vec::new(),
            AcceptanceHostState::captured(host_digest.clone(), host_digest),
            AcceptanceCleanup::complete(),
        )
        .unwrap();
        assert_eq!(report.overall(), AcceptanceOverallResult::Error);

        let host_digest = digest('d');
        assert_eq!(
            AcceptanceReport::from_attempt(
                AcceptanceSuite::All,
                provenance(),
                environment(),
                AcceptanceExecution::attempted(false, false, vec![reason("TOPOLOGY_UNAVAILABLE")],)
                    .unwrap(),
                passing_selected_cases(AcceptanceSuite::All, &host_digest),
                AcceptanceHostState::captured(host_digest.clone(), host_digest),
                AcceptanceCleanup::not_attempted(),
            )
            .unwrap_err(),
            AcceptanceReportError::Execution
        );
    }

    #[test]
    fn indeterminate_post_attempt_state_is_an_error_even_with_blockers() {
        let blocker = reason("HOST_CAPTURE_UNAVAILABLE");
        let cases = ALL_ACCEPTANCE_IDS
            .into_iter()
            .map(|id| AcceptanceCase::skipped(id, blocker.clone(), Vec::new()).unwrap())
            .collect();
        let report = AcceptanceReport::from_attempt(
            AcceptanceSuite::All,
            provenance(),
            environment(),
            AcceptanceExecution::attempted(false, false, vec![blocker]).unwrap(),
            cases,
            AcceptanceHostState::not_captured(),
            AcceptanceCleanup::not_attempted(),
        )
        .unwrap();
        assert_eq!(report.overall(), AcceptanceOverallResult::Error);
    }

    #[test]
    fn selected_skip_requires_a_matching_execution_blocker() {
        let host_digest = digest('d');
        let mut cases = passing_selected_cases(AcceptanceSuite::All, &host_digest);
        cases[0] = AcceptanceCase::skipped(
            AcceptanceId::A01,
            reason("PREREQUISITE_MISSING"),
            Vec::new(),
        )
        .unwrap();
        assert_eq!(
            attempted_report(
                AcceptanceSuite::All,
                cases.clone(),
                Vec::new(),
                AcceptanceHostState::captured(host_digest.clone(), host_digest.clone()),
                AcceptanceCleanup::complete(),
            )
            .unwrap_err(),
            AcceptanceReportError::Execution
        );
        let report = attempted_report(
            AcceptanceSuite::All,
            cases,
            vec![reason("PREREQUISITE_MISSING")],
            AcceptanceHostState::captured(host_digest.clone(), host_digest),
            AcceptanceCleanup::complete(),
        )
        .unwrap();
        assert_eq!(report.overall(), AcceptanceOverallResult::Blocked);
    }
}
