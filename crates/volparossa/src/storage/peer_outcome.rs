//! Best-effort local observations after a failed handoff, never a storage-operation retry.

use std::{fmt, path::Path, time::Duration};

use serde::{Deserialize, Serialize};
use volparossa_local_control::{
    PrivateStorageAppendTiming, PrivateStorageElapsedBucket, PrivateStorageOutcome,
    PrivateStorageOutcomeCategory, PrivateStorageOutcomeDeadline, PrivateStorageOutcomePhase,
    PrivateStorageOutcomeRequest, PrivateStorageOutcomeStatus, control_request::Operation,
    control_response::Payload,
};

const QUERY_BUDGET: Duration = Duration::from_secs(1);
const PENDING_INTERVAL: Duration = Duration::from_millis(25);
const MAX_QUERIES: usize = 3;

#[derive(Clone, Copy, Debug, Eq, PartialEq, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Status {
    Observed,
    Missing,
    Pending,
    Expired,
    QueryFailed,
    QueryTimeout,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct Detail {
    phase: PrivateStorageOutcomePhase,
    category: PrivateStorageOutcomeCategory,
    deadline_scope: PrivateStorageOutcomeDeadline,
}

/// Closed error context. It cannot carry the original ID, paths, keys or free-form errors.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AgentOutcome {
    status: Status,
    #[serde(deserialize_with = "Option::deserialize")]
    detail: Option<Detail>,
    // The original v4/v5/v6 serde shape stays exact; v7 has a separate explicit DTO.
    #[serde(skip)]
    append_timing: Option<AppendTiming>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
struct AppendTiming {
    before_payload: PrivateStorageElapsedBucket,
    in_payload_write_flush: PrivateStorageElapsedBucket,
    #[serde(deserialize_with = "Option::deserialize")]
    in_receipt_read: Option<PrivateStorageElapsedBucket>,
}

impl AppendTiming {
    fn from_wire(value: PrivateStorageAppendTiming) -> Option<Self> {
        Some(Self {
            before_payload: PrivateStorageElapsedBucket::try_from(value.before_payload).ok()?,
            in_payload_write_flush: PrivateStorageElapsedBucket::try_from(
                value.in_payload_write_flush,
            )
            .ok()?,
            in_receipt_read: value
                .in_receipt_read
                .map(PrivateStorageElapsedBucket::try_from)
                .transpose()
                .ok()?,
        })
    }

    fn wire(self) -> PrivateStorageAppendTiming {
        PrivateStorageAppendTiming {
            before_payload: self.before_payload as i32,
            in_payload_write_flush: self.in_payload_write_flush as i32,
            in_receipt_read: self.in_receipt_read.map(|bucket| bucket as i32),
        }
    }
}

/// Explicit v7 DTO; never reused by the original exact outcome decoders.
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct AppendOutcome {
    status: Status,
    #[serde(deserialize_with = "Option::deserialize")]
    detail: Option<Detail>,
    #[serde(deserialize_with = "Option::deserialize")]
    append_timing: Option<AppendTiming>,
}

impl From<AgentOutcome> for AppendOutcome {
    fn from(value: AgentOutcome) -> Self {
        Self {
            status: value.status,
            detail: value.detail,
            append_timing: value.append_timing,
        }
    }
}

impl From<AppendOutcome> for AgentOutcome {
    fn from(value: AppendOutcome) -> Self {
        Self {
            status: value.status,
            detail: value.detail,
            append_timing: value.append_timing,
        }
    }
}

impl AgentOutcome {
    fn status(status: Status) -> Self {
        Self {
            status,
            detail: None,
            append_timing: None,
        }
    }

    fn from_wire(outcome: PrivateStorageOutcome) -> Option<Self> {
        outcome.validate().ok()?;
        Some(
            match PrivateStorageOutcomeStatus::try_from(outcome.status).ok()? {
                PrivateStorageOutcomeStatus::Missing => Self::status(Status::Missing),
                PrivateStorageOutcomeStatus::Pending => Self::status(Status::Pending),
                PrivateStorageOutcomeStatus::Expired => Self::status(Status::Expired),
                PrivateStorageOutcomeStatus::Observed => Self {
                    status: Status::Observed,
                    detail: Some(Detail {
                        phase: PrivateStorageOutcomePhase::try_from(outcome.phase).ok()?,
                        category: PrivateStorageOutcomeCategory::try_from(outcome.category).ok()?,
                        deadline_scope: PrivateStorageOutcomeDeadline::try_from(outcome.deadline)
                            .ok()?,
                    }),
                    append_timing: outcome.append_timing.and_then(AppendTiming::from_wire),
                },
            },
        )
    }

    pub(super) fn valid(self) -> bool {
        match (self.status, self.detail) {
            (Status::Observed, Some(detail)) => PrivateStorageOutcome {
                status: PrivateStorageOutcomeStatus::Observed as i32,
                phase: detail.phase as i32,
                category: detail.category as i32,
                deadline: detail.deadline_scope as i32,
                append_timing: self.append_timing.map(AppendTiming::wire),
            }
            .validate()
            .is_ok(),
            (Status::Observed, None) | (_, Some(_)) => false,
            (_, None) => self.append_timing.is_none(),
        }
    }

    pub(super) fn has_append_timing(self) -> bool {
        self.append_timing.is_some()
    }
}

impl fmt::Display for AgentOutcome {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str("private storage local outcome observation")
    }
}

impl std::error::Error for AgentOutcome {}

/// Query only after dropping the original stream. Missing includes an observation omitted
/// at capacity; it proves neither provider failure nor absent custody. Older agents may reject.
pub(super) async fn query(socket: &Path, original_request_id: &[u8]) -> AgentOutcome {
    let include_append_timing = super::diagnostics::append_timing_enabled();
    tokio::time::timeout(QUERY_BUDGET, async {
        for attempt in 0..MAX_QUERIES {
            let response = crate::control::request(
                socket,
                Operation::PrivateStorageOutcome(PrivateStorageOutcomeRequest {
                    original_request_id: original_request_id.to_vec(),
                    include_append_timing,
                }),
            )
            .await;
            let outcome = match response {
                Ok(response) => match response.payload {
                    Some(Payload::PrivateStorageOutcome(outcome)) => {
                        if !include_append_timing && outcome.append_timing.is_some() {
                            None
                        } else {
                            AgentOutcome::from_wire(outcome)
                        }
                    }
                    _ => None,
                },
                Err(_) => None,
            };
            let Some(outcome) = outcome else {
                return AgentOutcome::status(Status::QueryFailed);
            };
            if outcome.status != Status::Pending || attempt + 1 == MAX_QUERIES {
                return outcome;
            }
            tokio::time::sleep(PENDING_INTERVAL).await;
        }
        // MAX_QUERIES is nonzero; no unbounded polling or registry retention refresh.
        AgentOutcome::status(Status::Pending)
    })
    .await
    .unwrap_or_else(|_| AgentOutcome::status(Status::QueryTimeout))
}

#[cfg(test)]
#[path = "peer_outcome_tests.rs"]
mod tests;
