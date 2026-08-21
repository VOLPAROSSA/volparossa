//! Strict machine-readable A01-A15 acceptance-report schema.

use std::collections::HashSet;

use serde::Serialize;
use thiserror::Error;

/// Machine-report schema version.
pub const ACCEPTANCE_REPORT_SCHEMA_VERSION: u32 = 1;
/// Exact number of required acceptance cases in VOLPAROSSA v1.
pub const ACCEPTANCE_CASE_COUNT: usize = 15;

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

/// Honest outcome of an attempted acceptance case.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum AcceptanceStatus {
    /// The real asserted behavior and its evidence passed.
    Passed,
    /// The case ran and contradicted its assertion.
    Failed,
    /// A prerequisite was unavailable, so no pass is claimed.
    Blocked,
}

/// One privacy-safe result with content-addressed evidence.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcceptanceResult {
    id: AcceptanceId,
    status: AcceptanceStatus,
    evidence_codes: Vec<String>,
    artifact_sha256: Vec<String>,
}

impl AcceptanceResult {
    /// Construct one bounded result.
    ///
    /// Evidence codes are stable non-sensitive assertions, not free-form logs.
    /// Artifact digests bind external captures/reports without embedding their
    /// potentially sensitive contents.
    ///
    /// # Errors
    ///
    /// Returns an error for empty/excessive/malformed evidence or digests.
    pub fn new(
        id: AcceptanceId,
        status: AcceptanceStatus,
        evidence_codes: Vec<String>,
        artifact_sha256: Vec<String>,
    ) -> Result<Self, AcceptanceReportError> {
        if evidence_codes.is_empty()
            || evidence_codes.len() > 32
            || evidence_codes.iter().any(|value| !valid_code(value))
            || artifact_sha256.len() > 32
            || artifact_sha256.iter().any(|value| !valid_sha256(value))
        {
            return Err(AcceptanceReportError::Evidence);
        }
        Ok(Self {
            id,
            status,
            evidence_codes,
            artifact_sha256,
        })
    }

    /// Case identifier.
    #[must_use]
    pub const fn id(&self) -> AcceptanceId {
        self.id
    }

    /// Recorded outcome.
    #[must_use]
    pub const fn status(&self) -> AcceptanceStatus {
        self.status
    }
}

/// Bounded, non-sensitive execution environment metadata.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcceptanceEnvironment {
    debian_version: String,
    architecture: String,
    kernel_release: String,
    rustc_version: String,
}

impl AcceptanceEnvironment {
    /// Construct environment metadata without hostnames, usernames, or addresses.
    ///
    /// # Errors
    ///
    /// Returns an error for empty, oversized, or control-character-bearing values.
    pub fn new(
        debian_version: String,
        architecture: String,
        kernel_release: String,
        rustc_version: String,
    ) -> Result<Self, AcceptanceReportError> {
        let values = [
            &debian_version,
            &architecture,
            &kernel_release,
            &rustc_version,
        ];
        if values.iter().any(|value| {
            value.is_empty() || value.len() > 128 || value.chars().any(char::is_control)
        }) {
            return Err(AcceptanceReportError::Environment);
        }
        Ok(Self {
            debian_version,
            architecture,
            kernel_release,
            rustc_version,
        })
    }
}

/// Complete canonical-order machine-readable acceptance report.
#[derive(Clone, Debug, Eq, PartialEq, Serialize)]
pub struct AcceptanceReport {
    schema_version: u32,
    started_at_ms: u64,
    completed_at_ms: u64,
    environment: AcceptanceEnvironment,
    host_before_sha256: String,
    host_after_sha256: String,
    results: Vec<AcceptanceResult>,
}

impl AcceptanceReport {
    /// Construct a complete report containing exactly A01 through A15 once.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid timestamps/fingerprints, missing, duplicate,
    /// or out-of-order cases, or an A15 pass with unequal host fingerprints.
    pub fn new(
        started_at_ms: u64,
        completed_at_ms: u64,
        environment: AcceptanceEnvironment,
        host_before_sha256: String,
        host_after_sha256: String,
        results: Vec<AcceptanceResult>,
    ) -> Result<Self, AcceptanceReportError> {
        if started_at_ms == 0 || completed_at_ms < started_at_ms {
            return Err(AcceptanceReportError::Timestamp);
        }
        if !valid_sha256(&host_before_sha256) || !valid_sha256(&host_after_sha256) {
            return Err(AcceptanceReportError::HostFingerprint);
        }
        if results.len() != ACCEPTANCE_CASE_COUNT
            || results
                .iter()
                .map(AcceptanceResult::id)
                .collect::<HashSet<_>>()
                .len()
                != ACCEPTANCE_CASE_COUNT
            || results
                .iter()
                .map(AcceptanceResult::id)
                .ne(ALL_ACCEPTANCE_IDS)
        {
            return Err(AcceptanceReportError::Cases);
        }
        if results[ACCEPTANCE_CASE_COUNT - 1].status == AcceptanceStatus::Passed
            && host_before_sha256 != host_after_sha256
        {
            return Err(AcceptanceReportError::HostChanged);
        }
        Ok(Self {
            schema_version: ACCEPTANCE_REPORT_SCHEMA_VERSION,
            started_at_ms,
            completed_at_ms,
            environment,
            host_before_sha256,
            host_after_sha256,
            results,
        })
    }

    /// True only when all fifteen cases passed and host fingerprints match.
    #[must_use]
    pub fn is_success(&self) -> bool {
        self.host_before_sha256 == self.host_after_sha256
            && self
                .results
                .iter()
                .all(|result| result.status == AcceptanceStatus::Passed)
    }

    /// Results in canonical A01-A15 order.
    #[must_use]
    pub fn results(&self) -> &[AcceptanceResult] {
        &self.results
    }
}

fn valid_code(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_uppercase() || byte.is_ascii_digit() || byte == b'_')
}

fn valid_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

/// Invalid machine-report structure or evidence.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum AcceptanceReportError {
    /// Evidence codes or artifact hashes violate fixed bounds.
    #[error("acceptance evidence is invalid")]
    Evidence,
    /// Environment metadata is unsafe or oversized.
    #[error("acceptance environment metadata is invalid")]
    Environment,
    /// Start/completion timestamps are invalid.
    #[error("acceptance report timestamps are invalid")]
    Timestamp,
    /// A host fingerprint is not a lowercase SHA-256 digest.
    #[error("acceptance host fingerprint is invalid")]
    HostFingerprint,
    /// The report does not contain exactly canonical A01-A15 results.
    #[error("acceptance case set or ordering is invalid")]
    Cases,
    /// A15 cannot pass when the before/after fingerprints differ.
    #[error("A15 claims pass despite changed host fingerprint")]
    HostChanged,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn environment() -> AcceptanceEnvironment {
        AcceptanceEnvironment::new(
            "13".to_owned(),
            "amd64".to_owned(),
            "6.12.0".to_owned(),
            "rustc 1.85.0".to_owned(),
        )
        .unwrap()
    }

    fn results(status: AcceptanceStatus) -> Vec<AcceptanceResult> {
        ALL_ACCEPTANCE_IDS
            .into_iter()
            .map(|id| {
                AcceptanceResult::new(id, status, vec!["EVIDENCE_RECORDED".to_owned()], Vec::new())
                    .unwrap()
            })
            .collect()
    }

    #[test]
    fn complete_blocked_report_is_honest_but_not_successful() {
        let report = AcceptanceReport::new(
            1,
            2,
            environment(),
            "1".repeat(64),
            "1".repeat(64),
            results(AcceptanceStatus::Blocked),
        )
        .unwrap();
        assert!(!report.is_success());
        let json = serde_json::to_string(&report).unwrap();
        assert!(json.contains("\"A01\""));
        assert!(json.contains("\"blocked\""));
    }

    #[test]
    fn host_change_cannot_be_reported_as_a15_pass() {
        let error = AcceptanceReport::new(
            1,
            2,
            environment(),
            "1".repeat(64),
            "2".repeat(64),
            results(AcceptanceStatus::Passed),
        )
        .unwrap_err();
        assert_eq!(error, AcceptanceReportError::HostChanged);
    }

    #[test]
    fn all_passed_equal_fingerprints_is_successful() {
        let report = AcceptanceReport::new(
            1,
            2,
            environment(),
            "a".repeat(64),
            "a".repeat(64),
            results(AcceptanceStatus::Passed),
        )
        .unwrap();
        assert!(report.is_success());
    }
}
