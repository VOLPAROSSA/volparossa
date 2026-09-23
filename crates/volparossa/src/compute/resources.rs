//! Fixed owner-selected model budgets, never values negotiated by a remote requester.

use anyhow::{Result, ensure};

use super::ModelProfile;

const GIB: u64 = 1024 * 1024 * 1024;
const RESERVE: u64 = GIB / 2;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub(super) struct Limits {
    pub(super) address_space: u64,
    pub(super) observed_rss: u64,
    /// Additional pre-launch admission, not a reservation or an absence-of-impact claim.
    pub(super) admission_headroom: Option<u64>,
}

pub(super) const fn limits(profile: ModelProfile) -> Limits {
    match profile {
        ModelProfile::Default135 | ModelProfile::Smol360 => Limits {
            address_space: 6 * GIB,
            observed_rss: 3 * GIB,
            admission_headroom: None,
        },
        ModelProfile::Smol1700 => Limits {
            address_space: 10 * GIB,
            observed_rss: 5 * GIB,
            admission_headroom: Some(5 * GIB + RESERVE),
        },
    }
}

pub(super) fn admits(profile: ModelProfile, available: Option<u64>) -> bool {
    limits(profile)
        .admission_headroom
        .is_none_or(|required| available.is_some_and(|bytes| bytes >= required))
}

pub(super) fn admission(profile: ModelProfile) -> Result<()> {
    if limits(profile).admission_headroom.is_some() {
        ensure!(
            admits(profile, super::spare_capacity::memory_headroom()),
            "compute_model_memory_headroom"
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn existing_profiles_keep_their_exact_resource_contracts() {
        for profile in [ModelProfile::Default135, ModelProfile::Smol360] {
            assert_eq!(limits(profile).address_space, 6 * GIB);
            assert_eq!(limits(profile).observed_rss, 3 * GIB);
            assert_eq!(limits(profile).admission_headroom, None);
            // The existing supervisor still performs its original pressure checks.
            assert!(admits(profile, None));
        }
    }

    #[test]
    fn larger_explicit_profile_requires_known_spare_memory_before_launch() {
        let profile = ModelProfile::Smol1700;
        let required = 5 * GIB + RESERVE;
        for available in [None, Some(0), Some(required - 1)] {
            assert!(!admits(profile, available));
        }
        assert!(admits(profile, Some(required)));
        assert_eq!(limits(profile).observed_rss, 5 * GIB);
        assert_eq!(limits(profile).address_space, 10 * GIB);
    }
}
