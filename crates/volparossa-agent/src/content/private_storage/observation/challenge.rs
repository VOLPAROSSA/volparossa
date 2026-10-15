//! Request-owned monotonic progress, projected only into coarse finite intervals.

use std::{sync::Mutex, time::Duration};

use tokio::time::Instant;
use volparossa_local_control::{
    PrivateStorageChallengeDetail, PrivateStorageChallengePhase as Phase,
    PrivateStorageElapsedBucket as Bucket,
};

#[derive(Default)]
pub(super) struct Progress(Mutex<State>);

#[derive(Default)]
struct State {
    operation_started: Option<Instant>,
    entered: Option<Instant>,
    phase: Option<Phase>,
    failed_at: Option<Instant>,
}

impl Progress {
    pub(super) fn operation_started(&self) -> Option<Instant> {
        self.0.lock().ok()?.operation_started
    }

    pub(super) fn start_operation(&self, started: Instant) {
        if let Ok(mut state) = self.0.lock() {
            state.operation_started = Some(started);
        }
    }

    pub(super) fn reset(&self) {
        if let Ok(mut state) = self.0.lock() {
            // Boundary resets must retain the enclosing operation's original start.
            state.entered = None;
            state.phase = None;
            state.failed_at = None;
        }
    }

    pub(super) fn enter(&self) {
        if let Ok(mut state) = self.0.lock() {
            state.entered = Some(Instant::now());
            state.phase = None;
            state.failed_at = None;
        }
    }

    pub(super) fn phase(&self, phase: Phase) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        if state.entered.is_some() && state.failed_at.is_none() {
            state.phase = Some(phase);
        }
    }

    pub(super) fn fail(&self) {
        let Ok(mut state) = self.0.lock() else {
            return;
        };
        if state.entered.is_some() && state.failed_at.is_none() {
            state.failed_at = Some(Instant::now());
        }
    }

    pub(super) fn detail(&self) -> Option<PrivateStorageChallengeDetail> {
        let state = self.0.lock().ok()?;
        let started = state.operation_started?;
        let entered = state.entered?;
        let failed = state.failed_at?;
        Some(PrivateStorageChallengeDetail {
            phase: state.phase? as i32,
            before_challenge: bucket(entered.saturating_duration_since(started)) as i32,
            in_challenge: bucket(failed.saturating_duration_since(entered)) as i32,
        })
    }
}

fn bucket(elapsed: Duration) -> Bucket {
    match elapsed.as_secs() {
        0 => Bucket::Under1s,
        1..=4 => Bucket::S1To5,
        5..=14 => Bucket::S5To15,
        15..=29 => Bucket::S15To30,
        30..=59 => Bucket::S30To60,
        60..=89 => Bucket::S60To90,
        90..=119 => Bucket::S90To120,
        _ => Bucket::AtLeast120s,
    }
}

#[cfg(test)]
mod tests;
