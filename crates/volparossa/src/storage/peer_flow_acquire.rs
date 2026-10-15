//! Explicit v8 projection; local loop observations never prove remote failure or capacity.

use serde::{Deserialize, Serialize};
use volparossa_local_control::{
    ControlResult, PrivateStorageDeadlineScope, PrivateStorageFlowAcquireDetail,
    PrivateStorageFlowAcquireFailure, PrivateStorageFlowAcquireReason,
    PrivateStorageFlowAcquireStage, PrivateStorageRemoteDetail, PrivateStorageRemoteStage,
    PrivateStorageStreamFailure, PrivateStorageTlsFailure,
};

use super::{AgentCode, AppendOutcome, Category, ChallengeDetail, Operation, Stage};

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Boundary {
    stage: PrivateStorageFlowAcquireStage,
    reason: PrivateStorageFlowAcquireReason,
}

impl Boundary {
    fn from_wire(value: PrivateStorageFlowAcquireFailure) -> Option<Self> {
        Some(Self {
            stage: PrivateStorageFlowAcquireStage::try_from(value.stage).ok()?,
            reason: PrivateStorageFlowAcquireReason::try_from(value.reason).ok()?,
        })
    }

    fn wire(self) -> PrivateStorageFlowAcquireFailure {
        PrivateStorageFlowAcquireFailure {
            stage: self.stage as i32,
            reason: self.reason as i32,
        }
    }
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Detail {
    rounds: u32,
    first: Boundary,
    last: Boundary,
}

impl Detail {
    pub(super) fn from_wire(value: PrivateStorageFlowAcquireDetail) -> Option<Self> {
        value.validate().ok()?;
        Some(Self {
            rounds: value.rounds,
            first: Boundary::from_wire(value.first?)?,
            last: Boundary::from_wire(value.last?)?,
        })
    }

    fn wire(self) -> PrivateStorageFlowAcquireDetail {
        PrivateStorageFlowAcquireDetail {
            rounds: self.rounds,
            first: Some(self.first.wire()),
            last: Some(self.last.wire()),
        }
    }
}

#[derive(Debug, Deserialize, Serialize)]
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
    #[serde(deserialize_with = "Option::deserialize")]
    flow_acquire: Option<Detail>,
}

impl AgentDetail {
    fn validate_flow(&self, code: Option<AgentCode>) -> Result<(), serde_json::Error> {
        let Some(flow) = self.flow_acquire else {
            return Ok(());
        };
        let invalid =
            || <serde_json::Error as serde::de::Error>::custom("diagnostic flow acquisition scope");
        if !matches!(code, Some(AgentCode::Unavailable)) {
            return Err(invalid());
        }
        PrivateStorageRemoteDetail {
            stage: self.stage as i32,
            deadline_scope: self.deadline_scope as i32,
            tls_failure: self.tls_failure.map(|failure| failure as i32),
            stream_failure: self.stream_failure.map(|failure| failure as i32),
            challenge: self.challenge.as_ref().map(ChallengeDetail::wire),
            flow_acquire: Some(flow.wire()),
        }
        .validate_rejection(ControlResult::Unavailable, "CONTENT_UNAVAILABLE")
        .map_err(|_| invalid())
    }
}

impl From<AgentDetail> for super::AgentDetail {
    fn from(value: AgentDetail) -> Self {
        Self {
            stage: value.stage,
            deadline_scope: value.deadline_scope,
            tls_failure: value.tls_failure,
            stream_failure: value.stream_failure,
            challenge: value.challenge,
        }
    }
}

/// Separate DTO: no nullable v8 key is admitted by any historical detail decoder.
#[derive(Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Failure {
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

impl Failure {
    pub(super) fn new(value: &super::Failure, flow: Option<Detail>) -> Self {
        Self {
            fragment_index: value.fragment_index,
            copy_index: value.copy_index,
            operation: value.operation,
            stage: value.stage,
            category: value.category,
            agent_code: value.agent_code,
            agent_detail: value.agent_detail.as_ref().map(|detail| AgentDetail {
                stage: detail.stage,
                deadline_scope: detail.deadline_scope,
                tls_failure: detail.tls_failure,
                stream_failure: detail.stream_failure,
                challenge: detail.challenge.clone(),
                flow_acquire: flow,
            }),
            agent_outcome: value.agent_outcome.map(AppendOutcome::from),
        }
    }

    pub(super) fn decode(
        value: serde_json::Value,
    ) -> Result<(super::Failure, Option<Detail>), serde_json::Error> {
        let value: Self = serde_json::from_value(value)?;
        if let Some(detail) = &value.agent_detail {
            detail.validate_flow(value.agent_code)?;
        }
        let flow = value
            .agent_detail
            .as_ref()
            .and_then(|detail| detail.flow_acquire);
        Ok((
            super::Failure {
                fragment_index: value.fragment_index,
                copy_index: value.copy_index,
                operation: value.operation,
                stage: value.stage,
                category: value.category,
                agent_code: value.agent_code,
                agent_detail: value.agent_detail.map(super::AgentDetail::from),
                agent_outcome: value.agent_outcome.map(super::AgentOutcome::from),
            },
            flow,
        ))
    }
}
