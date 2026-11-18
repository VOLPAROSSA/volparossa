//! Finite execution accounting only; this cannot authorize a worker or private input.

use std::time::Duration;

use anyhow::{Context as _, Result, ensure};
use tokio::{
    sync::{mpsc, watch},
    time::{Instant, sleep_until},
};

use super::{Event, MAX_REQUESTS, MAX_TASK_SECONDS};

/// An absolute caller-owned deadline and finite request ceiling.
/// No serializer, renewal operation or admission/attestation conversion exists.
pub(in crate::compute) struct SessionBudget {
    deadline: Instant,
    maximum_requests: u16,
}

impl SessionBudget {
    /// Retain the supplied deadline unchanged, including any subsequent start delay.
    pub(in crate::compute) fn new(deadline: Instant, maximum_requests: u16) -> Result<Self> {
        let now = Instant::now();
        if deadline <= now {
            return Err(super::super::ExecutionDeadline.into());
        }
        ensure!(
            deadline.duration_since(now) <= Duration::from_secs(MAX_TASK_SECONDS)
                && (1..=MAX_REQUESTS).contains(&maximum_requests),
            "compute_native_session_budget"
        );
        Ok(Self {
            deadline,
            maximum_requests,
        })
    }

    pub(super) const fn deadline(&self) -> Instant {
        self.deadline
    }

    pub(super) const fn maximum_requests(&self) -> u16 {
        self.maximum_requests
    }

    pub(super) fn check(&self) -> Result<()> {
        check_deadline(self.deadline)
    }

    pub(super) fn turn_deadline(&self, seconds: u16) -> Result<Instant> {
        self.check()?;
        ensure!((1..=600).contains(&seconds), "compute_private_budget");
        Ok(self
            .deadline
            .min(Instant::now() + Duration::from_secs(u64::from(seconds))))
    }
}

pub(super) fn check_deadline(deadline: Instant) -> Result<()> {
    if Instant::now() >= deadline {
        return Err(super::super::ExecutionDeadline.into());
    }
    Ok(())
}

pub(super) fn check_execution(deadline: Instant, activity: &watch::Receiver<bool>) -> Result<()> {
    check_deadline(deadline)?;
    ensure!(
        *activity.borrow() && activity.has_changed().is_ok(),
        "compute_owner_busy"
    );
    Ok(())
}

/// Reserve capacity before moving the bounded event, so owner updates cannot lose it.
/// Even immediately available capacity is checked against the original deadline.
pub(super) async fn send_event(
    events: &mpsc::Sender<Event>,
    event: Event,
    deadline: Instant,
    activity: &mut watch::Receiver<bool>,
) -> Result<()> {
    loop {
        check_execution(deadline, activity)?;
        tokio::select! {
            biased;
            () = sleep_until(deadline) => return Err(super::super::ExecutionDeadline.into()),
            changed = activity.changed() => {
                ensure!(changed.is_ok() && *activity.borrow(), "compute_owner_busy");
            },
            permit = events.reserve() => {
                let permit = permit.context("compute_native_session_receiver")?;
                check_execution(deadline, activity)?;
                permit.send(event);
                return Ok(());
            },
        }
    }
}
