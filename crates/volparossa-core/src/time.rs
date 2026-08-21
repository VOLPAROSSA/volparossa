use serde::{Deserialize, Serialize};
use thiserror::Error;

/// A wall-clock timestamp represented as seconds since the Unix epoch.
#[derive(Clone, Copy, Debug, Eq, Hash, Ord, PartialEq, PartialOrd, Serialize, Deserialize)]
#[serde(transparent)]
pub struct UnixTime(u64);

/// A checked timestamp arithmetic error.
#[derive(Clone, Copy, Debug, Eq, Error, PartialEq)]
pub enum TimeError {
    /// Adding a duration overflowed the supported timestamp range.
    #[error("timestamp arithmetic overflow")]
    Overflow,
}

impl UnixTime {
    /// Constructs a timestamp from Unix epoch seconds.
    #[must_use]
    pub const fn from_secs(seconds: u64) -> Self {
        Self(seconds)
    }

    /// Returns seconds since the Unix epoch.
    #[must_use]
    pub const fn as_secs(self) -> u64 {
        self.0
    }

    /// Adds a bounded duration.
    ///
    /// # Errors
    ///
    /// Returns an error when the timestamp addition overflows `u64`.
    pub fn checked_add(self, seconds: u64) -> Result<Self, TimeError> {
        self.0
            .checked_add(seconds)
            .map(Self)
            .ok_or(TimeError::Overflow)
    }

    /// Returns true at and after the expiry instant.
    #[must_use]
    pub const fn is_expired_at(self, now: Self) -> bool {
        now.0 >= self.0
    }

    /// Returns a saturating age in seconds.
    #[must_use]
    pub const fn age_at(self, now: Self) -> u64 {
        now.0.saturating_sub(self.0)
    }
}
