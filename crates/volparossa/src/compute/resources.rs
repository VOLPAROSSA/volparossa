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
        ModelProfile::Qwen600 => Limits {
            address_space: 10 * GIB,
            observed_rss: 4 * GIB,
            admission_headroom: Some(4 * GIB + RESERVE),
        },
        ModelProfile::Qwen4bInstruct2507 => Limits {
            address_space: 24 * GIB,
            observed_rss: 10 * GIB,
            admission_headroom: Some(10 * GIB + RESERVE),
        },
    }
}

pub(super) fn admits(profile: ModelProfile, available: Option<u64>) -> bool {
    limits(profile)
        .admission_headroom
        .is_none_or(|required| available.is_some_and(|bytes| bytes >= required))
}

pub(super) fn admission(profile: ModelProfile, diagnostic: bool) -> Result<()> {
    admission_with(profile, diagnostic, super::spare_capacity::memory::sample)
}

fn admission_with(
    profile: ModelProfile,
    diagnostic: bool,
    sample: impl FnOnce(bool) -> super::spare_capacity::memory::Sample,
) -> Result<()> {
    if let Some(required) = limits(profile).admission_headroom {
        let observe = diagnostic && super::spare_capacity::memory::enabled();
        let sample = sample(observe);
        let admitted = admits(profile, sample.headroom);
        if observe {
            super::spare_capacity::memory::emit(&serde_json::json!({
                "version":1,"phase":"admission","required_bytes":required,
                "admitted":admitted,"sample":sample.snapshot()
            }));
        }
        ensure!(admitted, "compute_model_memory_headroom");
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[derive(Clone)]
    struct Log(std::sync::Arc<std::sync::Mutex<Vec<u8>>>);

    impl std::io::Write for Log {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(bytes);
            Ok(bytes.len())
        }

        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    #[test]
    fn admission_observation_requires_both_explicit_native_scope_and_debug_opt_in() {
        let profile = ModelProfile::Qwen4bInstruct2507;
        for diagnostic in [false, true] {
            for enabled in [false, true] {
                let log = Log(std::sync::Arc::default());
                let writer = log.clone();
                let subscriber = tracing_subscriber::fmt()
                    .without_time()
                    .with_ansi(false)
                    .with_target(false)
                    .with_level(false)
                    .with_max_level(if enabled {
                        tracing::Level::DEBUG
                    } else {
                        tracing::Level::ERROR
                    })
                    .with_writer(move || writer.clone())
                    .finish();
                tracing::subscriber::with_default(subscriber, || {
                    let result = admission_with(profile, diagnostic, |stats| {
                        assert_eq!(stats, diagnostic && enabled);
                        super::super::spare_capacity::memory::Sample::for_test(None)
                    });
                    assert_eq!(
                        result.unwrap_err().to_string(),
                        "compute_model_memory_headroom"
                    );
                });
                let raw = log.0.lock().unwrap();
                if diagnostic && enabled {
                    let text = std::str::from_utf8(&raw).unwrap();
                    let record: serde_json::Value = serde_json::from_str(
                        text.trim()
                            .strip_prefix("private_memory_diagnostic ")
                            .unwrap(),
                    )
                    .unwrap();
                    assert_eq!(record["version"], 1);
                    assert_eq!(record["phase"], "admission");
                    assert_eq!(record["required_bytes"], 11_274_289_152_u64);
                    assert_eq!(record["admitted"], false);
                    assert_eq!(record["sample"]["missing_stage"], "meminfo");
                    assert!(raw.len() <= 4096);
                } else {
                    assert!(raw.is_empty());
                }
            }
        }
    }

    #[test]
    fn memory_diagnostic_sampling_uses_the_same_unbounded_value_once() {
        let profile = ModelProfile::Qwen4bInstruct2507;
        let required = limits(profile).admission_headroom.unwrap();
        for diagnostic in [false, true] {
            for value in [
                None,
                Some(0),
                Some(required - 1),
                Some(required),
                Some(u64::MAX),
            ] {
                let calls = std::cell::Cell::new(0);
                let result = admission_with(profile, diagnostic, |_| {
                    calls.set(calls.get() + 1);
                    super::super::spare_capacity::memory::Sample::for_test(value)
                });
                assert_eq!(calls.get(), 1);
                assert_eq!(result.is_ok(), admits(profile, value));
                if let Err(error) = result {
                    assert_eq!(error.to_string(), "compute_model_memory_headroom");
                }
            }
        }
    }

    #[test]
    fn profiles_without_admission_never_gain_a_memory_sample() {
        for profile in [ModelProfile::Default135, ModelProfile::Smol360] {
            for diagnostic in [false, true] {
                admission_with(profile, diagnostic, |_| panic!("unrequested sample")).unwrap();
            }
        }
    }

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

    #[test]
    fn qwen_budget_requires_headroom_and_does_not_claim_hard_cgroup_proof() {
        let profile = ModelProfile::Qwen600;
        assert_eq!(limits(profile).observed_rss, 4 * GIB);
        assert_eq!(limits(profile).address_space, 10 * GIB);
        assert!(!admits(profile, None));
        assert!(!admits(profile, Some(4 * GIB + RESERVE - 1)));
        assert!(admits(profile, Some(4 * GIB + RESERVE)));
    }

    #[test]
    fn qwen4b_candidate_budget_is_explicit_and_never_bypasses_missing_memory() {
        let profile = ModelProfile::Qwen4bInstruct2507;
        assert_eq!(limits(profile).observed_rss, 10 * GIB);
        assert_eq!(limits(profile).address_space, 24 * GIB);
        assert_eq!(limits(profile).admission_headroom, Some(10 * GIB + RESERVE));
        for available in [None, Some(0), Some(10 * GIB + RESERVE - 1)] {
            assert!(!admits(profile, available));
        }
        assert!(admits(profile, Some(10 * GIB + RESERVE)));
        assert_eq!(limits(ModelProfile::Qwen600).observed_rss, 4 * GIB);
    }
}
