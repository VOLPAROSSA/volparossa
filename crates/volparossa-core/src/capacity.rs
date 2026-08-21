use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A defensive upper bound used to reject implausible capacity claims.
pub const MAX_BANDWIDTH_MBPS: u32 = 1_000_000;

/// Upload and download capacity in decimal megabits per second.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq, Serialize, Deserialize)]
pub struct Bandwidth {
    /// Upload capacity in Mbit/s.
    pub up_mbps: u32,
    /// Download capacity in Mbit/s.
    pub down_mbps: u32,
}

impl Bandwidth {
    /// Constructs a bandwidth pair after checking defensive bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when either direction exceeds the defensive bandwidth bound.
    pub fn new(up_mbps: u32, down_mbps: u32) -> Result<Self, CapacityError> {
        let value = Self { up_mbps, down_mbps };
        value.validate()?;
        Ok(value)
    }

    /// Takes the component-wise minimum.
    #[must_use]
    pub fn component_min(self, other: Self) -> Self {
        Self {
            up_mbps: self.up_mbps.min(other.up_mbps),
            down_mbps: self.down_mbps.min(other.down_mbps),
        }
    }

    /// Returns whether both directions satisfy a requirement.
    #[must_use]
    pub const fn satisfies(self, required: Self) -> bool {
        self.up_mbps >= required.up_mbps && self.down_mbps >= required.down_mbps
    }

    /// Returns true when neither direction can carry traffic.
    #[must_use]
    pub const fn is_zero(self) -> bool {
        self.up_mbps == 0 && self.down_mbps == 0
    }

    /// Validates defensive protocol bounds.
    ///
    /// # Errors
    ///
    /// Returns an error when either direction exceeds the defensive bandwidth bound.
    pub fn validate(self) -> Result<(), CapacityError> {
        if self.up_mbps > MAX_BANDWIDTH_MBPS || self.down_mbps > MAX_BANDWIDTH_MBPS {
            return Err(CapacityError::ImplausibleBandwidth);
        }
        Ok(())
    }
}

/// Capacity and slot counts carried by a short-lived node advertisement.
#[derive(Clone, Copy, Debug, Eq, PartialEq, Serialize, Deserialize)]
pub struct CapacitySnapshot {
    /// Operator-configured relay limit.
    pub relay_limit: Bandwidth,
    /// Operator-configured exit limit.
    pub exit_limit: Bandwidth,
    /// Capacity already reserved across enabled roles.
    pub currently_reserved: Bandwidth,
    /// Conservatively advertised free capacity.
    pub estimated_free: Bandwidth,
    /// Number of active relay sessions.
    pub active_relay_sessions: u32,
    /// Number of active exit sessions.
    pub active_exit_sessions: u32,
    /// Remaining relay slots.
    pub free_relay_slots: u32,
    /// Remaining exit slots.
    pub free_exit_slots: u32,
    /// Duration of the measurement sample window.
    pub sample_window_seconds: u16,
}

impl CapacitySnapshot {
    /// Rejects internally inconsistent or implausible advertised values.
    ///
    /// # Errors
    ///
    /// Returns an error for implausible bandwidth, an invalid sample window, or a capacity value
    /// that exceeds the combined role limits.
    pub fn validate(self) -> Result<(), CapacityError> {
        self.relay_limit.validate()?;
        self.exit_limit.validate()?;
        self.currently_reserved.validate()?;
        self.estimated_free.validate()?;
        if self.sample_window_seconds == 0 || self.sample_window_seconds > 300 {
            return Err(CapacityError::InvalidSampleWindow);
        }

        let maximum_up = u64::from(self.relay_limit.up_mbps) + u64::from(self.exit_limit.up_mbps);
        let maximum_down =
            u64::from(self.relay_limit.down_mbps) + u64::from(self.exit_limit.down_mbps);
        if u64::from(self.currently_reserved.up_mbps) > maximum_up
            || u64::from(self.currently_reserved.down_mbps) > maximum_down
            || u64::from(self.estimated_free.up_mbps) > maximum_up
            || u64::from(self.estimated_free.down_mbps) > maximum_down
        {
            return Err(CapacityError::InconsistentClaim);
        }
        Ok(())
    }
}

/// A conservative capacity result and whether it used local history.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct ConservativeCapacity {
    /// Component-wise minimum of all available evidence.
    pub bandwidth: Bandwidth,
    /// True only when a local p25 measurement constrained the estimate.
    pub locally_measured: bool,
}

impl ConservativeCapacity {
    /// Computes `min(advertised free, local p25, reserved path limit)`.
    ///
    /// A peer without local history is capped by the advertisement and path
    /// reservation only and is marked unmeasured so selection can keep it in
    /// the limited exploration pool instead of treating the claim as proof.
    #[must_use]
    pub fn estimate(
        advertised_free: Bandwidth,
        locally_measured_p25: Option<Bandwidth>,
        reserved_path_limit: Bandwidth,
    ) -> Self {
        let advertised_and_reserved = advertised_free.component_min(reserved_path_limit);
        match locally_measured_p25 {
            Some(measured) => Self {
                bandwidth: advertised_and_reserved.component_min(measured),
                locally_measured: true,
            },
            None => Self {
                bandwidth: advertised_and_reserved,
                locally_measured: false,
            },
        }
    }
}

/// A capacity validation failure.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum CapacityError {
    /// A claim exceeds the defensive upper bound.
    #[error("implausible bandwidth claim")]
    ImplausibleBandwidth,
    /// Reserved or free bandwidth exceeds the operator limit.
    #[error("capacity claim is internally inconsistent")]
    InconsistentClaim,
    /// The sample window is zero or too large.
    #[error("invalid capacity sample window")]
    InvalidSampleWindow,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn conservative_capacity_is_component_wise_minimum() {
        let result = ConservativeCapacity::estimate(
            Bandwidth::new(80, 100).expect("valid"),
            Some(Bandwidth::new(60, 120).expect("valid")),
            Bandwidth::new(70, 90).expect("valid"),
        );
        assert_eq!(result.bandwidth, Bandwidth::new(60, 90).expect("valid"));
        assert!(result.locally_measured);
    }

    #[test]
    fn unmeasured_capacity_is_explicitly_marked() {
        let result = ConservativeCapacity::estimate(
            Bandwidth::new(100, 100).expect("valid"),
            None,
            Bandwidth::new(20, 30).expect("valid"),
        );
        assert_eq!(result.bandwidth, Bandwidth::new(20, 30).expect("valid"));
        assert!(!result.locally_measured);
    }
}
