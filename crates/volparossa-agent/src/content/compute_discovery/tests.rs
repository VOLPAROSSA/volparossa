//! Pure capability-selection fixtures; no worker or network execution is claimed.

use super::*;
use sha2::{Digest, Sha256};
use volparossa_content::agent_artifact::{BASE_MODEL_SHA256, MODEL_ID, MODEL_REVISION};

fn key(seed: u8) -> [u8; 32] {
    SigningKey::from_bytes(&[seed; 32])
        .verifying_key()
        .to_bytes()
}

fn query() -> rpc::EligibilityQuery {
    rpc::EligibilityQuery {
        publisher_keys: vec![hex::encode(key(1))],
        model_fingerprint: None,
        model_profile: None,
        require_task_derivation_v1: true,
        require_document_inference_v2: true,
        require_derived_inference_v3: true,
    }
}

fn observation(seed: u8, adapter: bool) -> ([u8; 32], rpc::Eligibility) {
    let model = rpc::ModelIdentity {
        model_id: MODEL_ID.into(),
        model_revision: MODEL_REVISION.into(),
        base_weights: rpc::FileIdentity {
            bytes: 269_060_552,
            sha256: hex::encode(BASE_MODEL_SHA256),
        },
        adapter_files: adapter.then(|| {
            [
                "README.md",
                "adapter_config.json",
                "adapter_model.safetensors",
            ]
            .into_iter()
            .map(|name| {
                (
                    name.into(),
                    rpc::FileIdentity {
                        bytes: 12,
                        sha256: "a".repeat(64),
                    },
                )
            })
            .collect()
        }),
    };
    let model_fingerprint = hex::encode(Sha256::digest(serde_json::to_vec(&model).unwrap()));
    (
        key(seed),
        rpc::Eligibility {
            eligible: true,
            capabilities: rpc::Capabilities {
                model,
                model_fingerprint,
                accepting_work: true,
                public_inference_only: true,
                runtime_slots: 1,
                max_threads: 2,
                max_job_seconds: 600,
                max_dataset_bytes: 1024 * 1024,
                max_rows: 4,
                task_derivation_v1: true,
                document_inference_v2: true,
                derived_inference_v3: true,
            },
        },
    )
}

#[test]
fn largest_compatible_pool_and_ties_do_not_depend_on_probe_order() {
    let samples = vec![
        observation(2, false),
        observation(3, false),
        observation(4, true),
        observation(5, true),
        observation(6, true),
    ];
    let selected = select_pool(&query(), samples.clone(), 2, 2).unwrap();
    let reversed = select_pool(&query(), samples.into_iter().rev().collect(), 2, 2).unwrap();
    assert_eq!(selected, reversed);
    let mut expected = [key(4).to_vec(), key(5).to_vec(), key(6).to_vec()];
    expected.sort();
    assert_eq!(
        selected
            .providers
            .iter()
            .map(|provider| provider.provider_key.clone())
            .collect::<Vec<_>>(),
        expected[..2]
    );
    let caps: rpc::Capabilities =
        serde_json::from_str(&selected.providers[0].capabilities_json).unwrap();
    assert!(caps.model.adapter_files.is_some());

    let tied = vec![
        observation(2, false),
        observation(3, false),
        observation(4, true),
        observation(5, true),
    ];
    let fingerprint = tied
        .iter()
        .map(|(_, reply)| &reply.capabilities.model_fingerprint)
        .min()
        .unwrap()
        .clone();
    let selected = select_pool(&query(), tied.clone(), 2, 4).unwrap();
    assert_eq!(
        selected,
        select_pool(&query(), tied.into_iter().rev().collect(), 2, 4).unwrap()
    );
    assert_eq!(selected.providers.len(), 2);
    for provider in selected.providers {
        let caps: rpc::Capabilities = serde_json::from_str(&provider.capabilities_json).unwrap();
        assert_eq!(caps.model_fingerprint, fingerprint);
    }
}

#[test]
fn selected_base_profile_filters_larger_other_model_pool_without_excluding_adapters() {
    let mut samples = vec![observation(2, true), observation(3, true)];
    let profile = volparossa_content::ModelProfile::Smol360;
    let spec = profile.spec();
    for seed in 4..=6 {
        let mut sample = observation(seed, false);
        let caps = &mut sample.1.capabilities;
        caps.model.model_id = spec.model_id.into();
        caps.model.model_revision = spec.revision.into();
        caps.model.base_weights = rpc::FileIdentity {
            bytes: spec.weights_bytes,
            sha256: spec.weights_sha256.into(),
        };
        caps.model_fingerprint =
            hex::encode(Sha256::digest(serde_json::to_vec(&caps.model).unwrap()));
        caps.max_rows = spec.max_rows;
        samples.push(sample);
    }
    assert_eq!(
        select_pool(&query(), samples.clone(), 2, 4)
            .unwrap()
            .providers
            .len(),
        3
    );
    let mut requested = query();
    requested.model_profile = Some("smollm2-135m-v1".into());
    let selected = select_pool(&requested, samples.clone(), 2, 4).unwrap();
    assert_eq!(selected.providers.len(), 2);
    for provider in selected.providers {
        let caps: rpc::Capabilities = serde_json::from_str(&provider.capabilities_json).unwrap();
        assert_eq!(caps.model.model_id, MODEL_ID);
        assert!(caps.model.adapter_files.is_some());
    }
    requested.model_profile = Some(profile.to_string());
    let selected = select_pool(&requested, samples, 2, 4).unwrap();
    assert_eq!(selected.providers.len(), 3);
    for provider in selected.providers {
        let caps: rpc::Capabilities = serde_json::from_str(&provider.capabilities_json).unwrap();
        assert_eq!(caps.model.model_id, spec.model_id);
        assert!(caps.model.adapter_files.is_none());
    }
}

#[test]
fn eligibility_busy_legacy_profile_and_identity_mismatches_fail_closed() {
    let eligible = observation(2, false);
    assert!(select_pool(&query(), vec![eligible.clone(), eligible.clone()], 2, 2).is_err());
    for variant in 0..7 {
        let mut rejected = observation(3, false);
        match variant {
            0 => rejected.1.eligible = false,
            1 => rejected.1.capabilities.accepting_work = false,
            2 => rejected.1.capabilities.derived_inference_v3 = false,
            3 => rejected.1.capabilities.model_fingerprint = "b".repeat(64),
            4 => rejected.1.capabilities.max_threads = 3,
            5 => rejected.0 = [0; 32],
            _ => rejected.1.capabilities.model.model_revision = "c".repeat(40),
        }
        assert!(select_pool(&query(), vec![eligible.clone(), rejected], 2, 2).is_err());
    }
    let mut pinned = query();
    pinned.model_fingerprint = Some(observation(4, true).1.capabilities.model_fingerprint);
    assert!(select_pool(&pinned, vec![eligible, observation(3, false)], 2, 2).is_err());
    assert!(select_pool(&query(), vec![observation(2, false); 17], 2, 2).is_err());
    assert!(
        select_pool(
            &query(),
            vec![observation(2, false), observation(3, false)],
            2,
            1
        )
        .is_err()
    );
}

#[test]
fn one_exact_model_replacement_requires_explicit_lower_minimum() {
    let candidate = observation(2, true);
    let mut pinned = query();
    pinned.model_fingerprint = Some(candidate.1.capabilities.model_fingerprint.clone());
    assert!(select_pool(&pinned, vec![candidate.clone()], 2, 4).is_err());
    let selected = select_pool(&pinned, vec![candidate.clone()], 1, 1).unwrap();
    assert_eq!(selected.providers.len(), 1);
    assert_eq!(selected.providers[0].provider_key, candidate.0);
    assert!(select_pool(&pinned, vec![observation(3, false)], 1, 4).is_err());
    assert!(select_pool(&pinned, vec![], 1, 4).is_err());
    for (minimum, maximum) in [(0, 4), (2, 1), (5, 4), (1, 0), (1, 5)] {
        assert!(select_pool(&pinned, vec![candidate.clone()], minimum, maximum).is_err());
    }
}

#[test]
fn unavailable_pool_can_become_ready_inside_the_original_window() {
    let started = Instant::now();
    let deadline = started + DISCOVERY_TIMEOUT;
    let mut busy = observation(3, false);
    busy.1.capabilities.accepting_work = false;
    let unavailable = select_pool(&query(), vec![observation(2, false), busy], 2, 4).unwrap_err();
    let retry_at = readiness_retry_at(&unavailable, started + Duration::from_secs(5), deadline)
        .expect("a temporarily busy peer can become ready");
    assert_eq!(retry_at, started + Duration::from_secs(7));
    let ready = select_pool(
        &query(),
        vec![observation(2, false), observation(3, false)],
        2,
        4,
    )
    .unwrap();
    assert_eq!(ready.providers.len(), 2);
    // Previous successful/unsuccessful probes never push this original deadline out.
    for at in [
        deadline - READINESS_RETRY,
        deadline,
        deadline + READINESS_RETRY,
    ] {
        assert!(readiness_retry_at(&unavailable, at, deadline).is_none());
    }
    assert!(readiness_retry_at(&ContentError::Busy, started, deadline).is_some());
    for error in [
        ContentError::Invalid,
        ContentError::Policy,
        ContentError::NameConflict,
        ContentError::NameRollback,
    ] {
        assert!(readiness_retry_at(&error, started, deadline).is_none());
    }
}

#[test]
fn readiness_errors_preserve_invalid_policy_and_protocol_boundaries() {
    let started = Instant::now();
    let deadline = started + DISCOVERY_TIMEOUT;
    for error in [
        ContentDiscoveryError::Invalid,
        ContentDiscoveryError::Invalidated,
    ] {
        assert!(readiness_retry_at(&discovery_error(error), started, deadline).is_none());
    }
    for error in [
        ContentDiscoveryError::Busy,
        ContentDiscoveryError::Closed,
        ContentDiscoveryError::Timeout,
        ContentDiscoveryError::Unavailable,
    ] {
        assert!(readiness_retry_at(&discovery_error(error), started, deadline).is_some());
    }
    for error in [rpc::ErrorCode::Busy, rpc::ErrorCode::Unavailable] {
        let error = eligibility_response(rpc::Outcome::Error(error)).unwrap_err();
        assert!(readiness_retry_at(&error, started, deadline).is_some());
    }
    for outcome in [
        rpc::Outcome::Error(rpc::ErrorCode::Invalid),
        rpc::Outcome::Error(rpc::ErrorCode::Missing),
        rpc::Outcome::Capabilities(observation(2, false).1.capabilities),
    ] {
        let error = eligibility_response(outcome).unwrap_err();
        assert!(matches!(error, ContentError::Invalid));
        assert!(readiness_retry_at(&error, started, deadline).is_none());
    }
}

#[test]
fn diagnostics_separate_availability_from_profile_and_eligibility() {
    let compatible = observation(2, false).1;
    assert_eq!(
        eligibility_diagnostics(&query(), [&compatible].into_iter()),
        [None, None, None]
    );
    let mut busy = compatible.clone();
    busy.capabilities.accepting_work = false;
    assert_eq!(
        eligibility_diagnostics(&query(), [&busy].into_iter()),
        [None, Some("COMPUTE_DISCOVERY_PEERS_BUSY"), None]
    );
    let mut declined = compatible.clone();
    declined.eligible = false;
    assert_eq!(
        eligibility_diagnostics(&query(), [&declined].into_iter()),
        [Some("COMPUTE_DISCOVERY_ELIGIBILITY_DECLINED"), None, None]
    );
    let mut mismatch = compatible;
    mismatch.capabilities.derived_inference_v3 = false;
    assert_eq!(
        eligibility_diagnostics(&query(), [&mismatch].into_iter()),
        [None, None, Some("COMPUTE_DISCOVERY_PROFILE_MISMATCH")]
    );
    assert_eq!(
        eligibility_diagnostics(&query(), [&busy, &declined, &mismatch].into_iter()),
        [
            Some("COMPUTE_DISCOVERY_ELIGIBILITY_DECLINED"),
            Some("COMPUTE_DISCOVERY_PEERS_BUSY"),
            Some("COMPUTE_DISCOVERY_PROFILE_MISMATCH"),
        ]
    );
    assert!(!busy.capabilities.accepting_work);
    assert!(!declined.eligible);
    assert!(!mismatch.capabilities.derived_inference_v3);
}
