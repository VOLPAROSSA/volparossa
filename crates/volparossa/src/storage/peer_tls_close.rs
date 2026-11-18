//! Explicit v9 projection of a failed local outer TLS close, never a remote-cause claim.

use serde::{Deserialize, Serialize};

use super::super::outcome::{AgentOutcome, CloseOutcome};
use super::{AgentCode, Category, Operation, Stage, flow_acquire};

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
    agent_detail: Option<flow_acquire::AgentDetail>,
    #[serde(deserialize_with = "Option::deserialize")]
    agent_outcome: Option<CloseOutcome>,
}

impl Failure {
    pub(super) fn new(value: &super::Failure, flow: Option<flow_acquire::Detail>) -> Self {
        Self {
            fragment_index: value.fragment_index,
            copy_index: value.copy_index,
            operation: value.operation,
            stage: value.stage,
            category: value.category,
            agent_code: value.agent_code,
            agent_detail: value
                .agent_detail
                .as_ref()
                .map(|detail| flow_acquire::AgentDetail::new(detail, flow)),
            agent_outcome: value.agent_outcome.map(CloseOutcome::from),
        }
    }

    pub(super) fn decode(
        value: serde_json::Value,
    ) -> Result<(super::Failure, Option<flow_acquire::Detail>), serde_json::Error> {
        let value: Self = serde_json::from_value(value)?;
        if let Some(detail) = &value.agent_detail {
            detail.validate_flow(value.agent_code)?;
        }
        let flow = value
            .agent_detail
            .as_ref()
            .and_then(flow_acquire::AgentDetail::flow);
        Ok((
            super::Failure {
                fragment_index: value.fragment_index,
                copy_index: value.copy_index,
                operation: value.operation,
                stage: value.stage,
                category: value.category,
                agent_code: value.agent_code,
                agent_detail: value.agent_detail.map(super::AgentDetail::from),
                agent_outcome: value.agent_outcome.map(AgentOutcome::from),
            },
            flow,
        ))
    }
}
