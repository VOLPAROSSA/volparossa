//! Bounded owner-side transfer observations, never provider denial or custody proof.

use std::{fmt, io};

use anyhow::Error;
use serde::{Deserialize, Deserializer, Serialize, Serializer, ser::SerializeStruct};
use volparossa_content::private_storage::{
    protocol::{ProtocolError, StorageOperation},
    wire::WireError,
};
use volparossa_local_control::{
    ControlResult, PrivateStorageChallengeDetail, PrivateStorageChallengePhase,
    PrivateStorageDeadlineScope, PrivateStorageElapsedBucket, PrivateStorageRemoteDetail,
    PrivateStorageRemoteStage, PrivateStorageStreamFailure, PrivateStorageTlsFailure,
};

use super::outcome::{AgentOutcome, AppendOutcome};

#[path = "peer_flow_acquire.rs"]
mod flow_acquire;
#[path = "peer_tls_close.rs"]
mod tls_close;

const MAX_FAILURES: usize = 8;

tokio::task_local! {
    static APPEND_TIMING: bool;
    static FLOW_ACQUIRE: bool;
    static TLS_CLOSE: bool;
}

pub(super) fn tls_close_enabled() -> bool {
    TLS_CLOSE.try_with(|enabled| *enabled).unwrap_or(false)
}

pub(super) async fn with_tls_close<F: Future>(enabled: bool, work: F) -> F::Output {
    TLS_CLOSE.scope(enabled, work).await
}

pub(super) fn append_timing_enabled() -> bool {
    APPEND_TIMING.try_with(|enabled| *enabled).unwrap_or(false)
}

pub(super) async fn with_append_timing<F: Future>(enabled: bool, work: F) -> F::Output {
    APPEND_TIMING.scope(enabled, work).await
}

pub(super) fn flow_acquire_enabled() -> bool {
    FLOW_ACQUIRE.try_with(|enabled| *enabled).unwrap_or(false)
}

pub(super) async fn with_flow_acquire<F: Future>(enabled: bool, work: F) -> F::Output {
    FLOW_ACQUIRE.scope(enabled, work).await
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Operation {
    Prepare,
    Reserve,
    Progress,
    Append,
    Finalize,
    Renew,
    ReadRange,
    Delete,
}

impl From<StorageOperation> for Operation {
    fn from(operation: StorageOperation) -> Self {
        match operation {
            StorageOperation::Reserve { .. } => Self::Reserve,
            StorageOperation::Progress => Self::Progress,
            StorageOperation::Append { .. } => Self::Append,
            StorageOperation::Finalize => Self::Finalize,
            StorageOperation::Renew { .. } => Self::Renew,
            StorageOperation::ReadRange { .. } => Self::ReadRange,
            StorageOperation::Delete => Self::Delete,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
pub(super) enum Stage {
    JournalOpen,
    Authorization,
    AgentReady,
    Challenge,
    SignedRequest,
    WireReceipt,
    AgentTerminal,
    Accounting,
    LocalInput,
    ReceiptValidation,
    JournalSave,
    Deadline,
    Unknown,
}

/// This context contains no runtime strings, keys, archive IDs, paths or payload.
#[derive(Clone, Copy, Debug)]
pub(super) struct Boundary {
    pub(super) operation: Operation,
    pub(super) stage: Stage,
}

impl Boundary {
    pub(super) fn new(operation: StorageOperation, stage: Stage) -> Self {
        Self {
            operation: operation.into(),
            stage,
        }
    }
}

impl fmt::Display for Boundary {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private storage transfer boundary failed")
    }
}

impl std::error::Error for Boundary {}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Category {
    Io,
    Timeout,
    Protocol,
    AgentRejected,
    Invalid,
    Busy,
    Store,
    Unknown,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
enum AgentCode {
    #[serde(rename = "CONTENT_INVALID")]
    Invalid,
    #[serde(rename = "CONTENT_UNAVAILABLE")]
    Unavailable,
    #[serde(rename = "CONTENT_BUSY")]
    Busy,
    #[serde(rename = "CONTENT_POLICY")]
    Policy,
    #[serde(rename = "unknown")]
    Unknown,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Failure {
    #[serde(deserialize_with = "Option::deserialize")]
    fragment_index: Option<usize>,
    copy_index: usize,
    operation: Operation,
    stage: Stage,
    category: Category,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_code: Option<AgentCode>,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_detail: Option<AgentDetail>,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_outcome: Option<AgentOutcome>,
}

/// New v7 failure alone permits the opt-in outcome timing field.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AppendFailure {
    #[serde(deserialize_with = "Option::deserialize")]
    fragment_index: Option<usize>,
    copy_index: usize,
    operation: Operation,
    stage: Stage,
    category: Category,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_code: Option<AgentCode>,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_detail: Option<AgentDetail>,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_outcome: Option<AppendOutcome>,
}

impl From<&Failure> for AppendFailure {
    fn from(value: &Failure) -> Self {
        Self {
            fragment_index: value.fragment_index,
            copy_index: value.copy_index,
            operation: value.operation,
            stage: value.stage,
            category: value.category,
            agent_code: value.agent_code,
            agent_detail: value.agent_detail.clone(),
            agent_outcome: value.agent_outcome.map(Into::into),
        }
    }
}

impl From<AppendFailure> for Failure {
    fn from(value: AppendFailure) -> Self {
        Self {
            fragment_index: value.fragment_index,
            copy_index: value.copy_index,
            operation: value.operation,
            stage: value.stage,
            category: value.category,
            agent_code: value.agent_code,
            agent_detail: value.agent_detail,
            agent_outcome: value.agent_outcome.map(Into::into),
        }
    }
}

/// Original exact six-field failure. Historical reports never gain a new claim.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OriginalFailure {
    #[serde(deserialize_with = "Option::deserialize")]
    fragment_index: Option<usize>,
    copy_index: usize,
    operation: Operation,
    stage: Stage,
    category: Category,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_code: Option<AgentCode>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AgentDetail {
    stage: PrivateStorageRemoteStage,
    deadline_scope: PrivateStorageDeadlineScope,
    #[serde(deserialize_with = "Option::deserialize")]
    tls_failure: Option<PrivateStorageTlsFailure>,
    #[serde(deserialize_with = "Option::deserialize")]
    stream_failure: Option<PrivateStorageStreamFailure>,
    #[serde(deserialize_with = "Option::deserialize")]
    challenge: Option<ChallengeDetail>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct ChallengeDetail {
    phase: PrivateStorageChallengePhase,
    before_challenge: PrivateStorageElapsedBucket,
    in_challenge: PrivateStorageElapsedBucket,
}

impl ChallengeDetail {
    fn from_wire(detail: PrivateStorageChallengeDetail) -> Option<Self> {
        Some(Self {
            phase: PrivateStorageChallengePhase::try_from(detail.phase).ok()?,
            before_challenge: PrivateStorageElapsedBucket::try_from(detail.before_challenge)
                .ok()?,
            in_challenge: PrivateStorageElapsedBucket::try_from(detail.in_challenge).ok()?,
        })
    }

    fn wire(&self) -> PrivateStorageChallengeDetail {
        PrivateStorageChallengeDetail {
            phase: self.phase as i32,
            before_challenge: self.before_challenge as i32,
            in_challenge: self.in_challenge as i32,
        }
    }
}

/// Exact v5 detail: challenge progress must not widen historical acceptance.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyStreamDetail {
    stage: PrivateStorageRemoteStage,
    deadline_scope: PrivateStorageDeadlineScope,
    #[serde(deserialize_with = "Option::deserialize")]
    tls_failure: Option<PrivateStorageTlsFailure>,
    #[serde(deserialize_with = "Option::deserialize")]
    stream_failure: Option<PrivateStorageStreamFailure>,
}

impl From<&AgentDetail> for LegacyStreamDetail {
    fn from(detail: &AgentDetail) -> Self {
        Self {
            stage: detail.stage,
            deadline_scope: detail.deadline_scope,
            tls_failure: detail.tls_failure,
            stream_failure: detail.stream_failure,
        }
    }
}

impl From<LegacyStreamDetail> for AgentDetail {
    fn from(detail: LegacyStreamDetail) -> Self {
        Self {
            stage: detail.stage,
            deadline_scope: detail.deadline_scope,
            tls_failure: detail.tls_failure,
            stream_failure: detail.stream_failure,
            challenge: None,
        }
    }
}

/// Exact v3/v4 detail: new stream observations cannot change historical schemas.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct LegacyTlsDetail {
    stage: PrivateStorageRemoteStage,
    deadline_scope: PrivateStorageDeadlineScope,
    #[serde(deserialize_with = "Option::deserialize")]
    tls_failure: Option<PrivateStorageTlsFailure>,
}

impl From<&AgentDetail> for LegacyTlsDetail {
    fn from(detail: &AgentDetail) -> Self {
        Self {
            stage: detail.stage,
            deadline_scope: detail.deadline_scope,
            tls_failure: detail.tls_failure,
        }
    }
}

impl From<LegacyTlsDetail> for AgentDetail {
    fn from(detail: LegacyTlsDetail) -> Self {
        Self {
            stage: detail.stage,
            deadline_scope: detail.deadline_scope,
            tls_failure: detail.tls_failure,
            stream_failure: None,
            challenge: None,
        }
    }
}

/// The exact v2 DTO: adding a TLS field never changes historical acceptance.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OriginalAgentDetail {
    stage: PrivateStorageRemoteStage,
    deadline_scope: PrivateStorageDeadlineScope,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OriginalDetailedFailure {
    #[serde(deserialize_with = "Option::deserialize")]
    fragment_index: Option<usize>,
    copy_index: usize,
    operation: Operation,
    stage: Stage,
    category: Category,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_code: Option<AgentCode>,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_detail: Option<OriginalAgentDetail>,
}

/// The exact v3 DTO has TLS detail but no post-READY outcome observation.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OriginalTlsFailure {
    #[serde(deserialize_with = "Option::deserialize")]
    fragment_index: Option<usize>,
    copy_index: usize,
    operation: Operation,
    stage: Stage,
    category: Category,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_code: Option<AgentCode>,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_detail: Option<LegacyTlsDetail>,
}

/// Exact v4 failure, including outcome but not the v5 stream detail field.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OriginalOutcomeFailure {
    #[serde(deserialize_with = "Option::deserialize")]
    fragment_index: Option<usize>,
    copy_index: usize,
    operation: Operation,
    stage: Stage,
    category: Category,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_code: Option<AgentCode>,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_detail: Option<LegacyTlsDetail>,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_outcome: Option<AgentOutcome>,
}

/// Exact v5 failure, including stream detail but no challenge progress field.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct OriginalStreamFailure {
    #[serde(deserialize_with = "Option::deserialize")]
    fragment_index: Option<usize>,
    copy_index: usize,
    operation: Operation,
    stage: Stage,
    category: Category,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_code: Option<AgentCode>,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_detail: Option<LegacyStreamDetail>,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_outcome: Option<AgentOutcome>,
}

impl From<&Failure> for OriginalStreamFailure {
    fn from(failure: &Failure) -> Self {
        Self {
            fragment_index: failure.fragment_index,
            copy_index: failure.copy_index,
            operation: failure.operation,
            stage: failure.stage,
            category: failure.category,
            agent_code: failure.agent_code,
            agent_detail: failure.agent_detail.as_ref().map(LegacyStreamDetail::from),
            agent_outcome: failure.agent_outcome,
        }
    }
}

impl From<OriginalStreamFailure> for Failure {
    fn from(failure: OriginalStreamFailure) -> Self {
        Self {
            fragment_index: failure.fragment_index,
            copy_index: failure.copy_index,
            operation: failure.operation,
            stage: failure.stage,
            category: failure.category,
            agent_code: failure.agent_code,
            agent_detail: failure.agent_detail.map(AgentDetail::from),
            agent_outcome: failure.agent_outcome,
        }
    }
}

impl AgentDetail {
    fn from_wire(detail: PrivateStorageRemoteDetail) -> Option<Self> {
        detail.validate().ok()?;
        Some(Self {
            stage: PrivateStorageRemoteStage::try_from(detail.stage).ok()?,
            deadline_scope: PrivateStorageDeadlineScope::try_from(detail.deadline_scope).ok()?,
            tls_failure: detail
                .tls_failure
                .map(PrivateStorageTlsFailure::try_from)
                .transpose()
                .ok()?,
            stream_failure: detail
                .stream_failure
                .map(PrivateStorageStreamFailure::try_from)
                .transpose()
                .ok()?,
            challenge: match detail.challenge {
                Some(challenge) => Some(ChallengeDetail::from_wire(challenge)?),
                None => None,
            },
        })
    }

    fn valid_for(&self, code: Option<AgentCode>) -> bool {
        let (result, code) = match code {
            Some(AgentCode::Invalid) => (ControlResult::InvalidRequest, "CONTENT_INVALID"),
            Some(AgentCode::Unavailable) => (ControlResult::Unavailable, "CONTENT_UNAVAILABLE"),
            Some(AgentCode::Busy) => (ControlResult::InvalidState, "CONTENT_BUSY"),
            Some(AgentCode::Policy) => (ControlResult::Policy, "CONTENT_POLICY"),
            Some(AgentCode::Unknown) | None => return false,
        };
        PrivateStorageRemoteDetail {
            flow_acquire: None,
            stage: self.stage as i32,
            deadline_scope: self.deadline_scope as i32,
            tls_failure: self.tls_failure.map(|failure| failure as i32),
            stream_failure: self.stream_failure.map(|failure| failure as i32),
            challenge: self.challenge.as_ref().map(ChallengeDetail::wire),
        }
        .validate_rejection(result, code)
        .is_ok()
    }
}

#[derive(Debug)]
pub(super) struct Diagnostics {
    version: u8,
    failures: Vec<Failure>,
    // Parallel bounded storage keeps every historical serde DTO unchanged.
    flow_acquire: [Option<flow_acquire::Detail>; MAX_FAILURES],
    omitted_failures: usize,
}

#[derive(Serialize)]
#[serde(untagged)]
enum CurrentFailure {
    V8(flow_acquire::Failure),
    V9(tls_close::Failure),
}

impl Diagnostics {
    fn current_failure(&self, index: usize, failure: &Failure) -> CurrentFailure {
        if self.version == 9 {
            CurrentFailure::V9(tls_close::Failure::new(failure, self.flow_acquire[index]))
        } else {
            CurrentFailure::V8(flow_acquire::Failure::new(
                failure,
                self.flow_acquire[index],
            ))
        }
    }
}

fn decode_current_failure(
    version: u8,
    value: serde_json::Value,
) -> Result<(Failure, Option<flow_acquire::Detail>), serde_json::Error> {
    if version == 9 {
        tls_close::Failure::decode(value)
    } else {
        flow_acquire::Failure::decode(value)
    }
}

impl Default for Diagnostics {
    fn default() -> Self {
        Self {
            version: if tls_close_enabled() {
                9
            } else if flow_acquire_enabled() {
                8
            } else if append_timing_enabled() {
                7
            } else {
                6
            },
            failures: Vec::new(),
            flow_acquire: [None; MAX_FAILURES],
            omitted_failures: 0,
        }
    }
}

impl Serialize for Diagnostics {
    fn serialize<S: Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
        let mut value = serializer.serialize_struct("Diagnostics", 3)?;
        value.serialize_field("version", &self.version)?;
        if self.version == 1 {
            let original: Vec<_> = self
                .failures
                .iter()
                .map(|failure| OriginalFailure {
                    fragment_index: failure.fragment_index,
                    copy_index: failure.copy_index,
                    operation: failure.operation,
                    stage: failure.stage,
                    category: failure.category,
                    agent_code: failure.agent_code,
                })
                .collect();
            value.serialize_field("failures", &original)?;
        } else if self.version == 2 {
            let original: Vec<_> =
                self.failures
                    .iter()
                    .map(|failure| OriginalDetailedFailure {
                        fragment_index: failure.fragment_index,
                        copy_index: failure.copy_index,
                        operation: failure.operation,
                        stage: failure.stage,
                        category: failure.category,
                        agent_code: failure.agent_code,
                        agent_detail: failure.agent_detail.as_ref().map(|detail| {
                            OriginalAgentDetail {
                                stage: detail.stage,
                                deadline_scope: detail.deadline_scope,
                            }
                        }),
                    })
                    .collect();
            value.serialize_field("failures", &original)?;
        } else if self.version == 3 {
            let original: Vec<_> = self
                .failures
                .iter()
                .map(|failure| OriginalTlsFailure {
                    fragment_index: failure.fragment_index,
                    copy_index: failure.copy_index,
                    operation: failure.operation,
                    stage: failure.stage,
                    category: failure.category,
                    agent_code: failure.agent_code,
                    agent_detail: failure.agent_detail.as_ref().map(LegacyTlsDetail::from),
                })
                .collect();
            value.serialize_field("failures", &original)?;
        } else if self.version == 4 {
            let original: Vec<_> = self
                .failures
                .iter()
                .map(|failure| OriginalOutcomeFailure {
                    fragment_index: failure.fragment_index,
                    copy_index: failure.copy_index,
                    operation: failure.operation,
                    stage: failure.stage,
                    category: failure.category,
                    agent_code: failure.agent_code,
                    agent_detail: failure.agent_detail.as_ref().map(LegacyTlsDetail::from),
                    agent_outcome: failure.agent_outcome,
                })
                .collect();
            value.serialize_field("failures", &original)?;
        } else if self.version == 5 {
            let original: Vec<_> = self
                .failures
                .iter()
                .map(OriginalStreamFailure::from)
                .collect();
            value.serialize_field("failures", &original)?;
        } else if self.version == 7 {
            let current: Vec<_> = self.failures.iter().map(AppendFailure::from).collect();
            value.serialize_field("failures", &current)?;
        } else if matches!(self.version, 8 | 9) {
            let current: Vec<_> = self
                .failures
                .iter()
                .enumerate()
                .map(|(index, failure)| self.current_failure(index, failure))
                .collect();
            value.serialize_field("failures", &current)?;
        } else {
            value.serialize_field("failures", &self.failures)?;
        }
        value.serialize_field("omitted_failures", &self.omitted_failures)?;
        value.end()
    }
}

impl Failure {
    fn validate_scope(&self) -> Result<(), serde_json::Error> {
        if self.agent_detail.as_ref().is_some_and(|detail| {
            !(matches!(self.stage, Stage::AgentReady)
                && matches!(self.category, Category::AgentRejected)
                && detail.valid_for(self.agent_code))
        }) {
            return Err(<serde_json::Error as serde::de::Error>::custom(
                "diagnostic detail scope",
            ));
        }
        if self.agent_outcome.as_ref().is_some_and(|outcome| {
            !matches!(
                self.stage,
                Stage::WireReceipt | Stage::AgentTerminal | Stage::Deadline
            ) || !outcome.valid()
                || (outcome.has_append_timing() && !matches!(self.operation, Operation::Append))
        }) {
            return Err(<serde_json::Error as serde::de::Error>::custom(
                "diagnostic outcome scope",
            ));
        }
        Ok(())
    }
}

impl<'de> Deserialize<'de> for Diagnostics {
    fn deserialize<D: Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        #[derive(Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Wire {
            version: u8,
            failures: Vec<serde_json::Value>,
            omitted_failures: usize,
        }
        let wire = Wire::deserialize(deserializer)?;
        if !matches!(wire.version, 1..=9) || wire.failures.len() > MAX_FAILURES {
            return Err(serde::de::Error::custom(
                "diagnostic version or failure bound",
            ));
        }
        let mut flow_acquire = [None; MAX_FAILURES];
        let failures = wire
            .failures
            .into_iter()
            .enumerate()
            .map(|(index, value)| {
                let failure = if wire.version >= 8 {
                    let (failure, detail) = decode_current_failure(wire.version, value)?;
                    flow_acquire[index] = detail;
                    failure
                } else if wire.version == 1 {
                    let old: OriginalFailure = serde_json::from_value(value)?;
                    Failure {
                        fragment_index: old.fragment_index,
                        copy_index: old.copy_index,
                        operation: old.operation,
                        stage: old.stage,
                        category: old.category,
                        agent_code: old.agent_code,
                        agent_detail: None,
                        agent_outcome: None,
                    }
                } else if wire.version == 2 {
                    let original: OriginalDetailedFailure = serde_json::from_value(value)?;
                    Failure {
                        fragment_index: original.fragment_index,
                        copy_index: original.copy_index,
                        operation: original.operation,
                        stage: original.stage,
                        category: original.category,
                        agent_code: original.agent_code,
                        agent_detail: original.agent_detail.map(|detail| AgentDetail {
                            stage: detail.stage,
                            deadline_scope: detail.deadline_scope,
                            tls_failure: None,
                            stream_failure: None,
                            challenge: None,
                        }),
                        agent_outcome: None,
                    }
                } else if wire.version == 3 {
                    let original: OriginalTlsFailure = serde_json::from_value(value)?;
                    Failure {
                        fragment_index: original.fragment_index,
                        copy_index: original.copy_index,
                        operation: original.operation,
                        stage: original.stage,
                        category: original.category,
                        agent_code: original.agent_code,
                        agent_detail: original.agent_detail.map(AgentDetail::from),
                        agent_outcome: None,
                    }
                } else if wire.version == 4 {
                    let original: OriginalOutcomeFailure = serde_json::from_value(value)?;
                    Failure {
                        fragment_index: original.fragment_index,
                        copy_index: original.copy_index,
                        operation: original.operation,
                        stage: original.stage,
                        category: original.category,
                        agent_code: original.agent_code,
                        agent_detail: original.agent_detail.map(AgentDetail::from),
                        agent_outcome: original.agent_outcome,
                    }
                } else if wire.version == 5 {
                    serde_json::from_value::<OriginalStreamFailure>(value)?.into()
                } else if wire.version == 7 {
                    serde_json::from_value::<AppendFailure>(value)?.into()
                } else {
                    serde_json::from_value::<Failure>(value)?
                };
                failure.validate_scope()?;
                Ok(failure)
            })
            .collect::<Result<Vec<_>, serde_json::Error>>()
            .map_err(serde::de::Error::custom)?;
        Ok(Self {
            version: wire.version,
            failures,
            flow_acquire,
            omitted_failures: wire.omitted_failures,
        })
    }
}

impl Diagnostics {
    pub(super) fn push(&mut self, copy_index: usize, error: &Error, fallback: Boundary) {
        if self.failures.len() == MAX_FAILURES {
            self.omitted_failures += 1;
            return;
        }
        let boundary = error
            .downcast_ref::<Boundary>()
            .copied()
            .unwrap_or(fallback);
        let (category, agent_code) = classify(error);
        let agent_detail = matches!(boundary.stage, Stage::AgentReady)
            .then(|| {
                error
                    .downcast_ref::<crate::control::AgentRejected>()
                    .and_then(|rejected| rejected.private_storage_remote_detail)
                    .and_then(AgentDetail::from_wire)
            })
            .flatten();
        let agent_outcome = matches!(
            boundary.stage,
            Stage::WireReceipt | Stage::AgentTerminal | Stage::Deadline
        )
        .then(|| error.downcast_ref::<AgentOutcome>().copied())
        .flatten();
        if self.version >= 8 && matches!(boundary.stage, Stage::AgentReady) {
            self.flow_acquire[self.failures.len()] = error
                .downcast_ref::<crate::control::AgentRejected>()
                .and_then(|rejected| {
                    let detail = rejected.private_storage_remote_detail?;
                    detail
                        .validate_rejection(ControlResult::Unavailable, &rejected.diagnostic_code)
                        .ok()?;
                    detail
                        .flow_acquire
                        .and_then(flow_acquire::Detail::from_wire)
                });
        }
        self.failures.push(Failure {
            fragment_index: None,
            copy_index,
            operation: boundary.operation,
            stage: boundary.stage,
            category,
            agent_code,
            agent_detail,
            agent_outcome,
        });
    }

    /// Only merges this executable's own bounded replica report, never peer JSON.
    pub(super) fn append_fragment(
        &mut self,
        fragment_index: usize,
        report: &serde_json::Value,
    ) -> anyhow::Result<()> {
        let child: Self = serde_json::from_value(report["deposit_diagnostics"].clone())?;
        anyhow::ensure!(
            self.version == child.version || (self.version < 7 && child.version < 7),
            "append diagnostic profile mismatch"
        );
        self.omitted_failures += child.omitted_failures;
        for (index, mut failure) in child.failures.into_iter().enumerate() {
            if self.failures.len() == MAX_FAILURES {
                self.omitted_failures += 1;
            } else {
                failure.fragment_index = Some(fragment_index);
                self.flow_acquire[self.failures.len()] = child.flow_acquire[index];
                self.failures.push(failure);
            }
        }
        Ok(())
    }
}

fn classify(error: &Error) -> (Category, Option<AgentCode>) {
    if let Some(rejected) = error.downcast_ref::<crate::control::AgentRejected>() {
        let code = match rejected.diagnostic_code.as_str() {
            "CONTENT_INVALID" => AgentCode::Invalid,
            "CONTENT_UNAVAILABLE" => AgentCode::Unavailable,
            "CONTENT_BUSY" => AgentCode::Busy,
            "CONTENT_POLICY" => AgentCode::Policy,
            _ => AgentCode::Unknown,
        };
        return (Category::AgentRejected, Some(code));
    }
    if error
        .downcast_ref::<tokio::time::error::Elapsed>()
        .is_some()
    {
        return (Category::Timeout, None);
    }
    if let Some(wire) = error.downcast_ref::<WireError>() {
        return (
            match wire {
                WireError::Io(_) => Category::Io,
                WireError::Protocol(_) => Category::Protocol,
                WireError::Invalid => Category::Invalid,
                WireError::Busy => Category::Busy,
                WireError::Store => Category::Store,
                WireError::Timeout => Category::Timeout,
            },
            None,
        );
    }
    if error.downcast_ref::<ProtocolError>().is_some() {
        return (Category::Protocol, None);
    }
    if let Some(control) = error.downcast_ref::<volparossa_local_control::ControlProtocolError>() {
        return (
            match control {
                volparossa_local_control::ControlProtocolError::Io(_) => Category::Io,
                volparossa_local_control::ControlProtocolError::Decode(_)
                | volparossa_local_control::ControlProtocolError::TooLarge
                | volparossa_local_control::ControlProtocolError::Invalid(_) => Category::Invalid,
            },
            None,
        );
    }
    if error.downcast_ref::<io::Error>().is_some() {
        return (Category::Io, None);
    }
    (Category::Unknown, None)
}

#[cfg(test)]
#[path = "peer_diagnostics_tests.rs"]
mod tests;

#[cfg(test)]
#[path = "peer_tls_close_tests.rs"]
mod tls_close_tests;
