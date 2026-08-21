use std::{collections::HashSet, time::Duration};

use serde::{Deserialize, Serialize};
use thiserror::Error;

/// Direction whose independently observed path characteristics are being scheduled.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Direction {
    /// Client towards exit.
    Uplink,
    /// Exit towards client.
    Downlink,
}

/// Control-plane lifecycle state for a selected relay path.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PathState {
    /// Advertised but not probed.
    Cold,
    /// A light probe succeeded.
    Reachable,
    /// `WireGuard` and authorisation are prepared without payload scheduling.
    Warm,
    /// Path is eligible to carry payload now.
    Active,
    /// Warm failover path, excluded from ordinary payload scheduling.
    Backup,
    /// Path makes progress but should be replaced.
    Degraded,
    /// No recent progress; path is ineligible.
    Dead,
}

/// Native per-path transport telemetry used for one scheduling direction.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathTelemetry {
    /// Route-context-local path identifier.
    pub path_id: u32,
    /// Selected relay node identifier (ephemeral/session representation is preferred).
    pub relay_id: String,
    /// Kernel index of the `WireGuard` interface bound to this outer QUIC path.
    pub interface_index: u32,
    /// Lifecycle state.
    pub state: PathState,
    /// Smoothed round-trip time.
    pub smoothed_rtt: Duration,
    /// RTT variance.
    pub rtt_variance: Duration,
    /// Recent packet-loss ratio in `[0, 1]`.
    pub packet_loss_ratio: f64,
    /// Recent unique delivery rate.
    pub delivery_rate_mbps: f64,
    /// Bytes waiting to be scheduled/sent on the path.
    pub queued_bytes: u64,
    /// Native congestion window.
    pub congestion_window_bytes: u64,
    /// Native bytes currently in flight.
    pub bytes_in_flight: u64,
    /// Extra congestion-delay estimate reported by native xquic.
    pub congestion_penalty: Duration,
    /// Whether native congestion control currently permits another datagram.
    pub writable: bool,
}

impl PathTelemetry {
    fn validate(&self) -> Result<(), ScheduleError> {
        if self.path_id == 0 || self.interface_index == 0 || self.relay_id.is_empty() {
            return Err(ScheduleError::InvalidTelemetry(
                "path, relay, and WireGuard interface identifiers are required".into(),
            ));
        }
        if self.relay_id.len() > 128 {
            return Err(ScheduleError::InvalidTelemetry(
                "relay identifier exceeds 128 bytes".into(),
            ));
        }
        if !self.packet_loss_ratio.is_finite()
            || !(0.0..=1.0).contains(&self.packet_loss_ratio)
            || !self.delivery_rate_mbps.is_finite()
            || self.delivery_rate_mbps < 0.0
        {
            return Err(ScheduleError::InvalidTelemetry(
                "loss and delivery-rate measurements must be finite and non-negative".into(),
            ));
        }
        if self.bytes_in_flight > self.congestion_window_bytes {
            return Err(ScheduleError::InvalidTelemetry(
                "bytes-in-flight exceeds congestion window".into(),
            ));
        }
        Ok(())
    }

    /// Predicts one-way delivery time using the v1 scheduling equation.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid telemetry, an inactive or blocked path, integer overflow, a
    /// queued-byte total above `u32::MAX`, a full congestion window, or a missing delivery-rate
    /// estimate.
    pub fn estimated_delivery_time(&self, datagram_len: usize) -> Result<Duration, ScheduleError> {
        self.validate()?;
        if self.state != PathState::Active || !self.writable {
            return Err(ScheduleError::IneligiblePath(self.path_id));
        }
        let datagram_len = u64::try_from(datagram_len)
            .map_err(|_| ScheduleError::InvalidTelemetry("datagram length overflow".into()))?;
        let bytes_in_flight = self
            .bytes_in_flight
            .checked_add(datagram_len)
            .ok_or_else(|| ScheduleError::InvalidTelemetry("bytes-in-flight overflow".into()))?;
        if bytes_in_flight > self.congestion_window_bytes {
            return Err(ScheduleError::CongestionWindow(self.path_id));
        }
        if self.delivery_rate_mbps <= f64::EPSILON {
            return Err(ScheduleError::NoDeliveryRate(self.path_id));
        }

        let one_way = self.smoothed_rtt.div_f64(2.0);
        let queued_bytes = self
            .queued_bytes
            .checked_add(datagram_len)
            .and_then(|value| u32::try_from(value).ok())
            .ok_or_else(|| {
                ScheduleError::InvalidTelemetry("queued bytes exceed scheduling bound".into())
            })?;
        let queued_bits = f64::from(queued_bytes) * 8.0;
        let queue_seconds = queued_bits / (self.delivery_rate_mbps * 1_000_000.0);
        let queue_delay = Duration::from_secs_f64(queue_seconds.min(60.0));
        // Loss is a penalty only, never a reason to duplicate. As loss approaches one the path is
        // made unattractive while finite arithmetic is preserved.
        let loss_multiplier = self.packet_loss_ratio / (1.0 - self.packet_loss_ratio).max(0.01);
        let loss_penalty = self.smoothed_rtt.mul_f64(loss_multiplier.min(100.0));
        Ok(one_way
            .saturating_add(queue_delay)
            .saturating_add(self.congestion_penalty)
            .saturating_add(loss_penalty))
    }
}

/// A pre-grouped set that proves distinct relay-bound paths before native session start.
#[derive(Clone, Debug)]
pub struct MultipathSet {
    paths: Vec<PathTelemetry>,
}

impl MultipathSet {
    /// Validates path count, distinct relays/interfaces, and RTT-spread policy.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid multipath bounds, too few or too many paths, invalid or
    /// inactive telemetry, duplicate path/relay/interface identifiers, or excessive RTT spread.
    pub fn new(
        paths: Vec<PathTelemetry>,
        minimum_paths: usize,
        maximum_paths: usize,
        maximum_rtt_spread: Duration,
    ) -> Result<Self, ScheduleError> {
        if minimum_paths < 2 || maximum_paths > 8 || minimum_paths > maximum_paths {
            return Err(ScheduleError::InvalidSet(
                "multipath bounds must satisfy 2 <= minimum <= maximum <= 8".into(),
            ));
        }
        if paths.len() < minimum_paths || paths.len() > maximum_paths {
            return Err(ScheduleError::InsufficientPaths {
                required: minimum_paths,
                available: paths.len(),
            });
        }

        let mut path_ids = HashSet::with_capacity(paths.len());
        let mut relay_ids = HashSet::with_capacity(paths.len());
        let mut interfaces = HashSet::with_capacity(paths.len());
        let mut minimum_rtt = Duration::MAX;
        let mut maximum_rtt = Duration::ZERO;
        for path in &paths {
            path.validate()?;
            if path.state != PathState::Active {
                return Err(ScheduleError::IneligiblePath(path.path_id));
            }
            if !path_ids.insert(path.path_id)
                || !relay_ids.insert(path.relay_id.as_str())
                || !interfaces.insert(path.interface_index)
            {
                return Err(ScheduleError::InvalidSet(
                    "multipath requires distinct path IDs, relays, and WireGuard interfaces".into(),
                ));
            }
            minimum_rtt = minimum_rtt.min(path.smoothed_rtt);
            maximum_rtt = maximum_rtt.max(path.smoothed_rtt);
        }
        if maximum_rtt.saturating_sub(minimum_rtt) > maximum_rtt_spread {
            return Err(ScheduleError::InvalidSet(
                "active path RTT spread exceeds configured limit".into(),
            ));
        }
        Ok(Self { paths })
    }

    /// Returns the validated active paths.
    #[must_use]
    pub fn paths(&self) -> &[PathTelemetry] {
        &self.paths
    }
}

/// Scheduling failures. None of these permit a direct or single-path downgrade.
#[derive(Clone, Debug, Error, PartialEq)]
pub enum ScheduleError {
    /// Native telemetry was nonsensical or incomplete.
    #[error("invalid path telemetry: {0}")]
    InvalidTelemetry(String),
    /// Path is not currently active/writable.
    #[error("path {0} is not eligible")]
    IneligiblePath(u32),
    /// Congestion control does not permit another datagram.
    #[error("path {0} congestion window is full")]
    CongestionWindow(u32),
    /// Delivery-rate estimate is unavailable.
    #[error("path {0} has no delivery-rate estimate")]
    NoDeliveryRate(u32),
    /// The path group violates a multipath invariant.
    #[error("invalid multipath set: {0}")]
    InvalidSet(String),
    /// Fewer than the required genuine paths are usable.
    #[error("insufficient genuine paths: required {required}, available {available}")]
    InsufficientPaths {
        /// Required path count.
        required: usize,
        /// Usable path count.
        available: usize,
    },
    /// No active path can currently accept the datagram.
    #[error("all active paths are congestion blocked or invalid")]
    NoWritablePath,
}

/// Replaceable scheduler interface; it returns exactly one path and performs no redundancy.
pub trait Scheduler: Send + Sync {
    /// Chooses one native path for the next outer QUIC datagram.
    ///
    /// # Errors
    ///
    /// Returns an error when no eligible active path can accept the datagram or path telemetry is
    /// invalid.
    fn select_path(
        &self,
        direction: Direction,
        datagram_len: usize,
        paths: &MultipathSet,
    ) -> Result<u32, ScheduleError>;
}

/// v1 estimated-delivery-time scheduler.
#[derive(Clone, Copy, Debug, Default)]
pub struct WeightedLatencyBandwidthScheduler;

impl Scheduler for WeightedLatencyBandwidthScheduler {
    fn select_path(
        &self,
        _direction: Direction,
        datagram_len: usize,
        paths: &MultipathSet,
    ) -> Result<u32, ScheduleError> {
        paths
            .paths()
            .iter()
            .filter_map(|path| {
                path.estimated_delivery_time(datagram_len)
                    .ok()
                    .map(|estimate| (path.path_id, estimate))
            })
            .min_by_key(|(_, estimate)| *estimate)
            .map(|(path_id, _)| path_id)
            .ok_or(ScheduleError::NoWritablePath)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn path(id: u32, relay: &str, interface: u32, rtt_ms: u64, rate: f64) -> PathTelemetry {
        PathTelemetry {
            path_id: id,
            relay_id: relay.into(),
            interface_index: interface,
            state: PathState::Active,
            smoothed_rtt: Duration::from_millis(rtt_ms),
            rtt_variance: Duration::from_millis(2),
            packet_loss_ratio: 0.0,
            delivery_rate_mbps: rate,
            queued_bytes: 0,
            congestion_window_bytes: 128_000,
            bytes_in_flight: 0,
            congestion_penalty: Duration::ZERO,
            writable: true,
        }
    }

    #[test]
    fn requires_distinct_relay_and_interface_per_path() {
        let duplicate_relay = vec![
            path(1, "relay-a", 10, 10, 100.0),
            path(2, "relay-a", 11, 12, 100.0),
        ];
        assert!(MultipathSet::new(duplicate_relay, 2, 8, Duration::from_millis(20)).is_err());

        let duplicate_interface = vec![
            path(1, "relay-a", 10, 10, 100.0),
            path(2, "relay-b", 10, 12, 100.0),
        ];
        assert!(MultipathSet::new(duplicate_interface, 2, 8, Duration::from_millis(20)).is_err());
    }

    #[test]
    fn scheduler_prefers_earliest_predicted_delivery() {
        let mut slow_queue = path(1, "relay-a", 10, 10, 100.0);
        slow_queue.queued_bytes = 1_000_000;
        let set = MultipathSet::new(
            vec![slow_queue, path(2, "relay-b", 11, 18, 50.0)],
            2,
            8,
            Duration::from_millis(20),
        )
        .expect("set");
        assert_eq!(
            WeightedLatencyBandwidthScheduler
                .select_path(Direction::Uplink, 1_200, &set)
                .expect("path"),
            2
        );
    }

    #[test]
    fn full_congestion_window_is_never_selected() {
        let mut blocked = path(1, "relay-a", 10, 10, 100.0);
        blocked.bytes_in_flight = blocked.congestion_window_bytes;
        let set = MultipathSet::new(
            vec![blocked, path(2, "relay-b", 11, 15, 50.0)],
            2,
            8,
            Duration::from_millis(20),
        )
        .expect("set");
        assert_eq!(
            WeightedLatencyBandwidthScheduler
                .select_path(Direction::Downlink, 1_200, &set)
                .expect("path"),
            2
        );
    }
}
