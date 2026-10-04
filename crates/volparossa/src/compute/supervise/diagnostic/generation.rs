//! Bounded, opt-in scalar observations; CPU features do not prove kernel selection.

use anyhow::{Context, Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::Value;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
enum Isa {
    #[serde(rename = "DEFAULT")]
    Default,
    #[serde(rename = "NO AVX")]
    NoAvx,
    #[serde(rename = "AVX2")]
    Avx2,
    #[serde(rename = "AVX512")]
    Avx512,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
struct Cpu {
    isa: Option<Isa>,
    avx2: Option<bool>,
    avx512_bf16: Option<bool>,
    amx_bf16: Option<bool>,
    amx_tile: Option<bool>,
    mkldnn_available: Option<bool>,
    mkldnn_enabled: Option<bool>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub(super) struct Snapshot {
    prompt_tokens: u64,
    threads: Option<u8>,
    interop_threads: Option<u8>,
    cpu: Cpu,
    first_forward_started_ms: Option<u64>,
    first_forward_completed_ms: Option<u64>,
    first_token_ms: Option<u64>,
    generated_tokens: u64,
    complete: bool,
    elapsed_ms: u64,
}

#[derive(Clone, Copy, Debug, Serialize)]
pub(super) struct Observation {
    pub(super) snapshot: Snapshot,
    records: u8,
}

impl Observation {
    pub(super) fn observe(previous: Option<Self>, value: &Value, elapsed: u64) -> Result<Self> {
        // Option fields must be explicitly null, not silently omitted.
        ensure!(
            value.as_object().is_some_and(|v| v.len() == 10)
                && value["cpu"].as_object().is_some_and(|v| v.len() == 7),
            "compute_private_progress"
        );
        let next: Snapshot =
            serde_json::from_value(value.clone()).context("compute_private_progress")?;
        ensure!(
            elapsed < 600_000
                && next.elapsed_ms == elapsed
                && (1..=12_288).contains(&next.prompt_tokens)
                && next.threads.is_none_or(|v| (1..=2).contains(&v))
                && next.interop_threads.is_none_or(|v| (1..=2).contains(&v))
                && next.generated_tokens <= 1024,
            "compute_private_progress"
        );
        for timestamp in [
            next.first_forward_started_ms,
            next.first_forward_completed_ms,
            next.first_token_ms,
        ] {
            ensure!(
                timestamp.is_none_or(|v| v <= elapsed),
                "compute_private_progress"
            );
        }
        ensure!(
            next.first_forward_completed_ms.is_none_or(|v| next
                .first_forward_started_ms
                .is_some_and(|start| start <= v))
                && next
                    .first_token_ms
                    .is_none_or(|v| next.first_forward_completed_ms.is_some_and(|end| end <= v))
                && (next.first_token_ms.is_some() == (next.generated_tokens > 0))
                && (!next.complete || next.generated_tokens > 0),
            "compute_private_progress"
        );
        let records = if let Some(previous) = previous {
            let old = previous.snapshot;
            ensure!(
                previous.records < 64
                    && !old.complete
                    && elapsed >= old.elapsed_ms
                    && next.prompt_tokens == old.prompt_tokens
                    && next.cpu == old.cpu
                    && next.threads == old.threads
                    && next.interop_threads == old.interop_threads
                    && next.generated_tokens >= old.generated_tokens,
                "compute_private_progress"
            );
            for (before, after) in [
                (old.first_forward_started_ms, next.first_forward_started_ms),
                (
                    old.first_forward_completed_ms,
                    next.first_forward_completed_ms,
                ),
                (old.first_token_ms, next.first_token_ms),
            ] {
                ensure!(
                    before.is_none_or(|v| after == Some(v)),
                    "compute_private_progress"
                );
            }
            if old.first_forward_started_ms.is_none() {
                ensure!(
                    next.first_forward_started_ms.is_some()
                        && next.first_forward_completed_ms.is_none()
                        && next.generated_tokens == 0,
                    "compute_private_progress"
                );
            } else if old.first_forward_completed_ms.is_none() {
                ensure!(
                    next.first_forward_completed_ms.is_some() && next.generated_tokens == 0,
                    "compute_private_progress"
                );
            } else if old.generated_tokens > 0 && !next.complete {
                ensure!(
                    elapsed - old.elapsed_ms >= 10_000,
                    "compute_private_progress"
                );
            }
            ensure!(
                next.first_forward_started_ms != old.first_forward_started_ms
                    || next.first_forward_completed_ms != old.first_forward_completed_ms
                    || next.generated_tokens > old.generated_tokens
                    || next.complete,
                "compute_private_progress"
            );
            previous.records + 1
        } else {
            ensure!(
                next.first_forward_started_ms.is_none()
                    && next.first_forward_completed_ms.is_none()
                    && next.generated_tokens == 0
                    && !next.complete,
                "compute_private_progress"
            );
            1
        };
        Ok(Self {
            snapshot: next,
            records,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    pub(super) fn initial() -> Value {
        serde_json::json!({"prompt_tokens":12_288,"threads":2,"interop_threads":1,
            "cpu":{"isa":"AVX2","avx2":true,"avx512_bf16":false,"amx_bf16":null,
                "amx_tile":null,"mkldnn_available":true,"mkldnn_enabled":true},
            "first_forward_started_ms":null,"first_forward_completed_ms":null,"first_token_ms":null,
            "generated_tokens":0,"complete":false,"elapsed_ms":10})
    }

    #[test]
    fn first_forward_tokens_and_completion_are_separate_bounded_observations() {
        let mut value = initial();
        let mut state = Observation::observe(None, &value, 10).unwrap();
        assert!(Observation::observe(Some(state), &value, 10).is_err());
        value["first_forward_started_ms"] = 10.into();
        state = Observation::observe(Some(state), &value, 10).unwrap();
        value["first_forward_completed_ms"] = 10.into();
        state = Observation::observe(Some(state), &value, 10).unwrap();
        value["first_token_ms"] = 10.into();
        value["generated_tokens"] = 1.into();
        state = Observation::observe(Some(state), &value, 10).unwrap();
        value["generated_tokens"] = 2.into();
        assert!(Observation::observe(Some(state), &value, 10).is_err());
        value["elapsed_ms"] = 10_010.into();
        state = Observation::observe(Some(state), &value, 10_010).unwrap();
        value["complete"] = true.into();
        state = Observation::observe(Some(state), &value, 10_010).unwrap();
        assert!(Observation::observe(Some(state), &value, 10_010).is_err());
        assert_eq!(state.snapshot.generated_tokens, 2);
    }

    #[test]
    fn unknown_capabilities_are_null_and_private_fields_types_and_impossible_counts_are_rejected() {
        let original = initial();
        for (key, changed) in [
            ("prompt_tokens", serde_json::json!(12_289)),
            ("prompt_tokens", serde_json::json!(true)),
            ("threads", serde_json::json!(3)),
            ("generated_tokens", serde_json::json!(1025)),
            ("complete", serde_json::json!(true)),
            ("private_text", serde_json::json!("PRIVATE_CANARY")),
        ] {
            let mut value = original.clone();
            value[key] = changed;
            assert!(Observation::observe(None, &value, 10).is_err());
        }
        for changed in [
            serde_json::json!("PRIVATE_CANARY"),
            serde_json::json!(1),
            serde_json::json!({}),
        ] {
            let mut value = original.clone();
            value["cpu"]["avx512_bf16"] = changed;
            assert!(Observation::observe(None, &value, 10).is_err());
        }
        let mut value = original;
        value["cpu"]["isa"] = Value::Null;
        value["threads"] = Value::Null;
        let observed = Observation::observe(None, &value, 10).unwrap();
        assert!(observed.snapshot.cpu.isa.is_none());
        assert!(observed.snapshot.threads.is_none());
        value["cpu"].as_object_mut().unwrap().remove("isa");
        assert!(Observation::observe(None, &value, 10).is_err());
    }

    #[test]
    fn lifecycle_regression_mutated_metadata_and_record_overflow_are_rejected() {
        let mut value = initial();
        let state = Observation::observe(None, &value, 10).unwrap();
        value["first_forward_started_ms"] = 10.into();
        value["first_forward_completed_ms"] = 10.into();
        assert!(Observation::observe(Some(state), &value, 10).is_err());
        value["first_forward_completed_ms"] = Value::Null;
        let full = Observation {
            records: 64,
            ..state
        };
        assert!(Observation::observe(Some(full), &value, 10).is_err());
        value["cpu"]["avx2"] = false.into();
        assert!(Observation::observe(Some(state), &value, 10).is_err());
        value["cpu"]["avx2"] = true.into();
        value["elapsed_ms"] = 9.into();
        assert!(Observation::observe(Some(state), &value, 9).is_err());
        value["elapsed_ms"] = 600_000.into();
        assert!(Observation::observe(Some(state), &value, 600_000).is_err());
    }
}
