//! Idle-only activation of explicit owner-approved learning results.
//!
//! The training loop owns selection; this broker copies a checked snapshot into its
//! own directory before activation. Training retention cannot remove live weights.

use super::{Broker, Decision, Duration, JOB_RESERVATION_BYTES, MAX_RETAINED_BYTES, now, sha};
use crate::compute::serving_snapshot;

const CHECK_INTERVAL: Duration = Duration::from_secs(2);

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) enum InitialBase {
    Unknown,
    NeverSelected,
    Withdrawn,
}

impl Broker {
    pub(super) fn successor_valid(&self, time: u64) -> bool {
        self.successor.as_ref().map_or_else(
            || {
                self.options.serving_directory.is_none()
                    || (self.initial_base == InitialBase::NeverSelected
                        && self.options.serving_directory.as_ref().is_some_and(|root| {
                            matches!(
                                serving_snapshot::peek(root, &self.options.runtime_root),
                                Ok(None)
                            )
                        }))
            },
            |snapshot| {
                snapshot.selection.expires_unix_seconds > time
                    && self.options.serving_directory.as_ref().is_some_and(|root| {
                        serving_snapshot::admission_allowed(
                            root,
                            &self.options.runtime_root,
                            &snapshot.selection,
                        )
                        .unwrap_or(false)
                    })
            },
        )
    }

    pub(super) fn successor_bytes(&self) -> u64 {
        self.successor.as_ref().map_or(0, |snapshot| {
            snapshot
                .selection
                .adapter_files
                .values()
                .fold(0_u64, |total, file| total.saturating_add(file.bytes))
        })
    }

    pub(super) fn refresh_successor(&mut self, time: u64) {
        let Some(root) = self.options.serving_directory.as_ref() else {
            return;
        };
        if self.jobs.iter().any(|job| job.execution.is_some())
            || self.budget.current() != Decision::Run
            || tokio::time::Instant::now() < self.next_successor_check
        {
            return;
        }
        self.next_successor_check = tokio::time::Instant::now() + CHECK_INTERVAL;
        // Missing, incomplete or rejected new selections never overwrite accepted
        // weights. The existing selection's original expiry still stops new work.
        let selection = match serving_snapshot::peek(root, &self.options.runtime_root) {
            Ok(None) => {
                if self.initial_base == InitialBase::Unknown {
                    self.initial_base = InitialBase::NeverSelected;
                }
                return;
            }
            Ok(Some(selection)) => {
                self.initial_base = InitialBase::Withdrawn;
                selection
            }
            Err(_) => {
                self.initial_base = InitialBase::Withdrawn;
                return;
            }
        };
        // An expired pointer is not a never-selected directory, especially after a
        // restart. Keep an existing valid copy, but never fall back to the base.
        if selection.expires_unix_seconds <= time {
            return;
        }
        if !serving_snapshot::admission_allowed(root, &self.options.runtime_root, &selection)
            .unwrap_or(false)
        {
            return;
        }
        if self
            .successor
            .as_ref()
            .is_some_and(|current| current.selection.id == selection.id)
        {
            return;
        }
        let bytes = selection
            .adapter_files
            .values()
            .fold(0_u64, |total, file| total.saturating_add(file.bytes));
        let retained = self.jobs.iter().fold(self.successor_bytes(), |total, job| {
            total.saturating_add(job.retained_bytes)
        });
        // Bound the transient old+new copies as well as the next job reservation.
        if retained
            .saturating_add(bytes)
            .saturating_add(JOB_RESERVATION_BYTES)
            > MAX_RETAINED_BYTES
        {
            return;
        }
        let copied = serving_snapshot::copy_selection(root, &selection, &self.options.work_root);
        let Ok(snapshot) = copied else {
            return;
        };
        let Ok(observed) = now() else {
            return;
        };
        if snapshot.selection.expires_unix_seconds <= observed {
            return;
        }
        let mut model = self.capabilities.model.clone();
        model.adapter_files = Some(snapshot.selection.adapter_files.clone());
        let Ok(encoded) = serde_json::to_vec(&model) else {
            return;
        };
        self.capabilities.model = model;
        self.capabilities.model_fingerprint = sha(&encoded);
        self.successor = Some(snapshot);
        // Model identity is public capability metadata; no paths, prompts or
        // training sources are written to this diagnostic stream.
        eprintln!(
            "compute successor_activated model={}",
            self.capabilities.model_fingerprint
        );
    }
}

#[cfg(test)]
mod tests;
