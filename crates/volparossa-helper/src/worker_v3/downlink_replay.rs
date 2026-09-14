//! Expiring replay custody for already-verified adjacent receive-budget updates.
//!
//! Other worker operations retain their generation-lifetime replay protection. Expired budget
//! messages cannot be readmitted, and the worker's per-path sequence remains monotone.

use super::{HardDeadline, InternalWorkerRequest, WorkerV3Error, internal_worker_request};
use std::time::{Duration, Instant, SystemTime, UNIX_EPOCH};
use volparossa_protocol::MAX_ADJACENT_RECEIVE_BUDGET_LIFETIME_MS;

// 128 actor legs, two updates per second and five seconds of live authority require 1,280
// records. Keep bounded scheduling headroom separate from the lifetime/terminal replay reserve.
pub(super) const MAX_BUDGET_REPLAY_ENTRIES: usize = 2048;

#[derive(Clone, Copy)]
pub(super) struct BudgetReplayClock {
    pub(super) unix_ms: u64,
    pub(super) boottime_ns: u64,
}

impl BudgetReplayClock {
    pub(super) fn for_request(
        request: &InternalWorkerRequest,
    ) -> Result<Option<Self>, WorkerV3Error> {
        if !matches!(
            request.operation,
            Some(internal_worker_request::Operation::ApplyDownlinkBudget(_))
        ) {
            return Ok(None);
        }
        Self::now().map(Some)
    }

    pub(super) fn now() -> Result<Self, WorkerV3Error> {
        let unix_ms = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .ok()
            .and_then(|value| u64::try_from(value.as_millis()).ok())
            .ok_or(WorkerV3Error::Deadline)?;
        Ok(Self {
            unix_ms,
            boottime_ns: super::functional_backend::current_boottime_nanos()
                .map_err(|_| WorkerV3Error::Deadline)?,
        })
    }

    pub(super) fn expiry(
        self,
        request: &crate::internal_protocol::ApplyWorkerDownlinkBudget,
        now: Instant,
    ) -> Result<Instant, WorkerV3Error> {
        let wall_ms = request
            .expires_at_ms
            .checked_sub(self.unix_ms)
            .filter(|value| (1..=MAX_ADJACENT_RECEIVE_BUDGET_LIFETIME_MS).contains(value))
            .ok_or(WorkerV3Error::Deadline)?;
        let boot_ns = request
            .expires_at_boottime_ns
            .checked_sub(self.boottime_ns)
            .filter(|value| {
                *value > 0 && *value <= MAX_ADJACENT_RECEIVE_BUDGET_LIFETIME_MS * 1_000_000
            })
            .ok_or(WorkerV3Error::Deadline)?;
        now.checked_add(Duration::from_nanos(boot_ns.min(wall_ms * 1_000_000)))
            .ok_or(WorkerV3Error::Deadline)
    }
}

pub(super) fn bounded_replay_expiry(
    request: &InternalWorkerRequest,
    clock: Option<BudgetReplayClock>,
    now: Instant,
    context_expiry: Instant,
    deadline: HardDeadline,
) -> Result<(Instant, HardDeadline, bool), WorkerV3Error> {
    let Some(internal_worker_request::Operation::ApplyDownlinkBudget(value)) =
        request.operation.as_ref()
    else {
        return Ok((context_expiry, deadline, false));
    };
    let expiry = clock
        .ok_or(WorkerV3Error::Invalid)?
        .expiry(value, now)?
        .min(context_expiry);
    let deadline =
        HardDeadline::at(deadline.expires_at().min(expiry)).map_err(WorkerV3Error::Io)?;
    Ok((expiry, deadline, true))
}
