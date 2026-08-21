use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use volparossa_core::{Bandwidth, PathId, UnixTime};

const MAX_BYTES_IN_FLIGHT: u64 = 1 << 40;
const MAX_RATE_MBPS: f64 = 1_000_000.0;
const MAX_RTT_MS: f64 = 120_000.0;
const MAX_SCHEDULING_PENALTY_MS: f64 = 120_000.0;

/// Hard allocation bound for concurrently observed replacement pairs.
pub const MAXIMUM_HYSTERESIS_PAIRS: usize = 64;

/// Lifecycle state of one selected `WireGuard` relay path.
#[derive(Clone, Copy, Debug, Eq, Hash, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathState {
    /// Known only from an advertisement.
    Cold,
    /// A light reachability probe succeeded.
    Reachable,
    /// Reserved and lightly probed, but not carrying ordinary traffic.
    Warm,
    /// Eligible to carry ordinary multipath traffic.
    Active,
    /// Warm failover path kept outside ordinary scheduling.
    Backup,
    /// Still present but failing quality or progress thresholds.
    Degraded,
    /// Unreachable or timed out; never schedulable.
    Dead,
}

impl PathState {
    /// Returns whether user traffic may be scheduled on this state.
    #[must_use]
    pub const fn is_schedulable(self) -> bool {
        matches!(self, Self::Active)
    }

    fn can_transition_to(self, next: Self) -> bool {
        self == next
            || matches!(
                (self, next),
                (Self::Cold, Self::Reachable | Self::Dead)
                    | (
                        Self::Reachable,
                        Self::Warm | Self::Degraded | Self::Dead | Self::Cold
                    )
                    | (
                        Self::Warm,
                        Self::Active | Self::Backup | Self::Degraded | Self::Dead
                    )
                    | (
                        Self::Active,
                        Self::Backup | Self::Degraded | Self::Dead | Self::Warm
                    )
                    | (
                        Self::Backup,
                        Self::Active | Self::Degraded | Self::Dead | Self::Warm
                    )
                    | (
                        Self::Degraded,
                        Self::Reachable | Self::Warm | Self::Active | Self::Backup | Self::Dead
                    )
                    | (Self::Dead, Self::Reachable | Self::Cold)
            )
    }
}

/// Passive or lightly probed transport metrics for one path.
#[derive(Clone, Copy, Debug, PartialEq, Serialize, Deserialize)]
pub struct PathMetrics {
    /// Smoothed round-trip time.
    pub smoothed_rtt_ms: f64,
    /// RTT variance.
    pub rtt_variance_ms: f64,
    /// Packet-loss ratio from 0 through 1.
    pub packet_loss_ratio: f64,
    /// Estimated delivery rate.
    pub delivery_rate_mbps: f64,
    /// RTT under observed load.
    pub loaded_rtt_ms: f64,
    /// Bytes currently counted in flight by the transport.
    pub bytes_in_flight: u64,
    /// Last instant at which forward progress was observed.
    pub last_progress_at: UnixTime,
    /// Relay's untrusted free-capacity claim.
    pub relay_reported_free: Bandwidth,
    /// Locally conservative free-capacity estimate.
    pub locally_estimated_free: Bandwidth,
}

impl PathMetrics {
    /// Validates all externally supplied metric bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid RTT, loss, rate, bytes-in-flight, or capacity metrics.
    pub fn validate(self) -> Result<(), PathMetricsError> {
        for rtt in [
            self.smoothed_rtt_ms,
            self.rtt_variance_ms,
            self.loaded_rtt_ms,
        ] {
            if !rtt.is_finite() || !(0.0..=MAX_RTT_MS).contains(&rtt) {
                return Err(PathMetricsError::InvalidRtt);
            }
        }
        if !self.packet_loss_ratio.is_finite() || !(0.0..=1.0).contains(&self.packet_loss_ratio) {
            return Err(PathMetricsError::InvalidLoss);
        }
        if !self.delivery_rate_mbps.is_finite()
            || self.delivery_rate_mbps < 0.0
            || self.delivery_rate_mbps > MAX_RATE_MBPS
        {
            return Err(PathMetricsError::InvalidDeliveryRate);
        }
        if self.bytes_in_flight > MAX_BYTES_IN_FLIGHT {
            return Err(PathMetricsError::InvalidBytesInFlight);
        }
        self.relay_reported_free
            .validate()
            .map_err(|_| PathMetricsError::InvalidCapacity)?;
        self.locally_estimated_free
            .validate()
            .map_err(|_| PathMetricsError::InvalidCapacity)?;
        Ok(())
    }

    /// Estimates next-datagram delivery time without duplication or FEC.
    ///
    /// The calculation follows `RTT/2 + queued/rate + congestion + loss`.
    ///
    /// # Errors
    ///
    /// Returns an error when stored metrics, queued bytes, or scheduling penalties violate their
    /// defensive bounds.
    pub fn estimated_delivery_time_ms(
        self,
        queued_bytes: u64,
        congestion_penalty_ms: f64,
        loss_penalty_ms: f64,
    ) -> Result<f64, PathMetricsError> {
        self.validate()?;
        if queued_bytes > MAX_BYTES_IN_FLIGHT {
            return Err(PathMetricsError::InvalidBytesInFlight);
        }
        if !congestion_penalty_ms.is_finite()
            || !(0.0..=MAX_SCHEDULING_PENALTY_MS).contains(&congestion_penalty_ms)
            || !loss_penalty_ms.is_finite()
            || !(0.0..=MAX_SCHEDULING_PENALTY_MS).contains(&loss_penalty_ms)
        {
            return Err(PathMetricsError::InvalidPenalty);
        }
        if self.delivery_rate_mbps == 0.0 {
            return Ok(f64::INFINITY);
        }
        let bytes_per_millisecond = self.delivery_rate_mbps * 125.0;
        #[allow(clippy::cast_precision_loss)]
        // queued bytes are bounded below f64's exact integer range.
        Ok(self.smoothed_rtt_ms / 2.0
            + queued_bytes as f64 / bytes_per_millisecond
            + congestion_penalty_ms
            + loss_penalty_ms)
    }
}

/// A per-path metric validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum PathMetricsError {
    /// An RTT value is non-finite, negative or implausibly large.
    #[error("invalid RTT metric")]
    InvalidRtt,
    /// Loss is non-finite or outside 0 through 1.
    #[error("invalid packet loss metric")]
    InvalidLoss,
    /// Delivery rate is non-finite, negative or implausibly large.
    #[error("invalid delivery-rate metric")]
    InvalidDeliveryRate,
    /// Bytes in flight exceeds the defensive memory/resource bound.
    #[error("invalid bytes-in-flight metric")]
    InvalidBytesInFlight,
    /// A capacity metric violates defensive bounds.
    #[error("invalid path capacity")]
    InvalidCapacity,
    /// A caller-supplied scheduling penalty is invalid.
    #[error("invalid scheduling penalty")]
    InvalidPenalty,
    /// A caller supplied a future or backwards local metric timestamp.
    #[error("invalid path metric timestamp")]
    InvalidTimestamp,
}

/// Current state and metrics for one route-local path identifier.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct PathStatus {
    /// Route-local path identifier.
    pub path_id: PathId,
    /// Current lifecycle state.
    pub state: PathState,
    /// Most recent bounded metrics.
    pub metrics: PathMetrics,
    /// Last state transition instant.
    pub state_changed_at: UnixTime,
}

impl PathStatus {
    /// Constructs a status after validating its initial metrics.
    ///
    /// # Errors
    ///
    /// Returns an error when any initial path metric is invalid.
    pub fn new(
        path_id: PathId,
        state: PathState,
        metrics: PathMetrics,
        state_changed_at: UnixTime,
    ) -> Result<Self, PathMetricsError> {
        metrics.validate()?;
        Ok(Self {
            path_id,
            state,
            metrics,
            state_changed_at,
        })
    }

    /// Applies an explicit, validated lifecycle transition.
    ///
    /// # Errors
    ///
    /// Returns an error when `now` predates the current state or the requested state edge would
    /// bypass a required lifecycle stage.
    pub fn transition(
        &mut self,
        next: PathState,
        now: UnixTime,
    ) -> Result<(), PathTransitionError> {
        if now < self.state_changed_at {
            return Err(PathTransitionError::ClockMovedBackwards);
        }
        if !self.state.can_transition_to(next) {
            return Err(PathTransitionError::InvalidTransition {
                from: self.state,
                to: next,
            });
        }
        if next != self.state {
            self.state = next;
            self.state_changed_at = now;
        }
        Ok(())
    }

    /// Replaces metrics and automatically marks stalled or lossy live paths.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid metrics or hysteresis thresholds, a backwards timestamp, or
    /// an invalid automatic lifecycle transition.
    pub fn observe(
        &mut self,
        metrics: PathMetrics,
        now: UnixTime,
        policy: HysteresisPolicy,
    ) -> Result<(), PathTransitionError> {
        metrics.validate()?;
        policy.validate()?;
        if now < self.state_changed_at || metrics.last_progress_at > now {
            return Err(PathTransitionError::ClockMovedBackwards);
        }
        let stalled_for = metrics.last_progress_at.age_at(now);
        let next = if stalled_for >= policy.dead_after_seconds {
            Some(PathState::Dead)
        } else if stalled_for >= policy.degraded_after_seconds
            || metrics.packet_loss_ratio >= policy.degraded_loss_ratio
        {
            Some(PathState::Degraded)
        } else {
            None
        };
        if let Some(next_state) = next {
            if !self.state.can_transition_to(next_state) {
                return Err(PathTransitionError::InvalidTransition {
                    from: self.state,
                    to: next_state,
                });
            }
        }

        self.metrics = metrics;
        if let Some(next_state) = next {
            if next_state != self.state {
                self.state = next_state;
                self.state_changed_at = now;
            }
        }
        Ok(())
    }
}

/// Invalid lifecycle transition or hysteresis policy.
#[derive(Clone, Copy, Debug, Error, PartialEq)]
pub enum PathTransitionError {
    /// The requested direct transition would bypass required setup/probing.
    #[error("invalid path transition from {from:?} to {to:?}")]
    InvalidTransition {
        /// Existing state.
        from: PathState,
        /// Requested state.
        to: PathState,
    },
    /// A supplied timestamp predates the current state.
    #[error("path timestamp moved backwards")]
    ClockMovedBackwards,
    /// A path metric failed validation.
    #[error(transparent)]
    InvalidMetrics(#[from] PathMetricsError),
    /// Hysteresis thresholds are inconsistent.
    #[error("invalid path hysteresis policy")]
    InvalidPolicy,
}

/// Thresholds for degradation and stable-better replacement.
#[derive(Clone, Copy, Debug, PartialEq)]
pub struct HysteresisPolicy {
    /// Minimum continuous clearly-better interval before replacement.
    pub minimum_better_seconds: u64,
    /// Required reduction in estimated delivery time, from 0 through 1.
    pub minimum_improvement_ratio: f64,
    /// Loss ratio at which an otherwise live path is degraded.
    pub degraded_loss_ratio: f64,
    /// No-progress interval that marks a path degraded.
    pub degraded_after_seconds: u64,
    /// Longer no-progress interval that marks a path dead.
    pub dead_after_seconds: u64,
}

impl Default for HysteresisPolicy {
    fn default() -> Self {
        Self {
            minimum_better_seconds: 15,
            minimum_improvement_ratio: 0.15,
            degraded_loss_ratio: 0.10,
            degraded_after_seconds: 10,
            dead_after_seconds: 30,
        }
    }
}

impl HysteresisPolicy {
    fn validate(self) -> Result<(), PathTransitionError> {
        if self.minimum_better_seconds == 0
            || !self.minimum_improvement_ratio.is_finite()
            || !(0.0..=1.0).contains(&self.minimum_improvement_ratio)
            || !self.degraded_loss_ratio.is_finite()
            || !(0.0..=1.0).contains(&self.degraded_loss_ratio)
            || self.degraded_after_seconds == 0
            || self.dead_after_seconds <= self.degraded_after_seconds
        {
            return Err(PathTransitionError::InvalidPolicy);
        }
        Ok(())
    }
}

/// Why hysteresis authorized replacement.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplacementReason {
    /// The active path is already degraded or dead.
    ActivePathDegraded,
    /// The candidate stayed clearly better for the configured interval.
    StableImprovement,
}

/// Result of considering a candidate replacement path.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum ReplacementDecision {
    /// Keep the active path and clear any stale better-candidate timer.
    Keep,
    /// Keep observing for this many more seconds.
    Observe {
        /// Remaining stable-better interval.
        remaining_seconds: u64,
    },
    /// Replace the active path for a specific auditable reason.
    Replace {
        /// Hysteresis or degradation reason.
        reason: ReplacementReason,
    },
}

/// Stateful minimum-duration hysteresis keyed by active/candidate path pair.
#[derive(Debug)]
pub struct ReplacementHysteresis {
    policy: HysteresisPolicy,
    better_since: HashMap<(PathId, PathId), UnixTime>,
}

impl ReplacementHysteresis {
    /// Constructs a tracker after validating thresholds.
    ///
    /// # Errors
    ///
    /// Returns an error when the hysteresis policy has inconsistent or out-of-range thresholds.
    pub fn new(policy: HysteresisPolicy) -> Result<Self, PathTransitionError> {
        policy.validate()?;
        Ok(Self {
            policy,
            better_since: HashMap::new(),
        })
    }

    /// Returns the bounded number of replacement pairs currently carrying a timer.
    #[must_use]
    pub fn tracked_pair_count(&self) -> usize {
        self.better_since.len()
    }

    /// Considers one warm candidate without probing any unrelated peer.
    ///
    /// # Errors
    ///
    /// Returns an error when either path has invalid metrics or its estimated delivery time cannot
    /// be calculated from the bounded inputs.
    pub fn consider(
        &mut self,
        active: &PathStatus,
        candidate: &PathStatus,
        now: UnixTime,
    ) -> Result<ReplacementDecision, PathMetricsError> {
        active.metrics.validate()?;
        candidate.metrics.validate()?;
        let key = (active.path_id, candidate.path_id);
        if active.state_changed_at > now
            || candidate.state_changed_at > now
            || active.metrics.last_progress_at > now
            || candidate.metrics.last_progress_at > now
            || self
                .better_since
                .get(&key)
                .is_some_and(|since| *since > now)
        {
            return Err(PathMetricsError::InvalidTimestamp);
        }
        if matches!(active.state, PathState::Degraded | PathState::Dead)
            && matches!(
                candidate.state,
                PathState::Reachable | PathState::Warm | PathState::Backup | PathState::Active
            )
        {
            self.better_since.remove(&key);
            return Ok(ReplacementDecision::Replace {
                reason: ReplacementReason::ActivePathDegraded,
            });
        }
        if matches!(
            candidate.state,
            PathState::Cold | PathState::Degraded | PathState::Dead
        ) {
            self.better_since.remove(&key);
            return Ok(ReplacementDecision::Keep);
        }
        let active_cost = active.metrics.estimated_delivery_time_ms(
            active.metrics.bytes_in_flight,
            0.0,
            active.metrics.packet_loss_ratio * active.metrics.smoothed_rtt_ms,
        )?;
        let candidate_cost = candidate.metrics.estimated_delivery_time_ms(
            candidate.metrics.bytes_in_flight,
            0.0,
            candidate.metrics.packet_loss_ratio * candidate.metrics.smoothed_rtt_ms,
        )?;
        if !candidate_cost.is_finite() || active.path_id == candidate.path_id {
            self.better_since.remove(&key);
            return Ok(ReplacementDecision::Keep);
        }
        let clearly_better = !active_cost.is_finite()
            || candidate_cost <= active_cost * (1.0 - self.policy.minimum_improvement_ratio);
        if !clearly_better {
            self.better_since.remove(&key);
            return Ok(ReplacementDecision::Keep);
        }
        if !self.better_since.contains_key(&key)
            && self.better_since.len() >= MAXIMUM_HYSTERESIS_PAIRS
        {
            let oldest = self
                .better_since
                .iter()
                .min_by(|(left_key, left_since), (right_key, right_since)| {
                    left_since
                        .cmp(right_since)
                        .then_with(|| left_key.cmp(right_key))
                })
                .map(|(oldest_key, _)| *oldest_key);
            if let Some(oldest_key) = oldest {
                self.better_since.remove(&oldest_key);
            }
        }
        let since = *self.better_since.entry(key).or_insert(now);
        let elapsed = since.age_at(now);
        if elapsed >= self.policy.minimum_better_seconds {
            self.better_since.remove(&key);
            return Ok(ReplacementDecision::Replace {
                reason: ReplacementReason::StableImprovement,
            });
        }
        Ok(ReplacementDecision::Observe {
            remaining_seconds: self.policy.minimum_better_seconds - elapsed,
        })
    }
}
