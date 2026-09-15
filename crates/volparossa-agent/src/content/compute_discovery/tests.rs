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
    let selected = select_pool(&query(), samples.clone(), 2).unwrap();
    let reversed = select_pool(&query(), samples.into_iter().rev().collect(), 2).unwrap();
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
    let selected = select_pool(&query(), tied.clone(), 4).unwrap();
    assert_eq!(
        selected,
        select_pool(&query(), tied.into_iter().rev().collect(), 4).unwrap()
    );
    assert_eq!(selected.providers.len(), 2);
    for provider in selected.providers {
        let caps: rpc::Capabilities = serde_json::from_str(&provider.capabilities_json).unwrap();
        assert_eq!(caps.model_fingerprint, fingerprint);
    }
}

#[test]
fn eligibility_busy_legacy_profile_and_identity_mismatches_fail_closed() {
    let eligible = observation(2, false);
    assert!(select_pool(&query(), vec![eligible.clone(), eligible.clone()], 2).is_err());
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
        assert!(select_pool(&query(), vec![eligible.clone(), rejected], 2).is_err());
    }
    let mut pinned = query();
    pinned.model_fingerprint = Some(observation(4, true).1.capabilities.model_fingerprint);
    assert!(select_pool(&pinned, vec![eligible, observation(3, false)], 2).is_err());
    assert!(select_pool(&query(), vec![observation(2, false); 17], 2).is_err());
    assert!(
        select_pool(
            &query(),
            vec![observation(2, false), observation(3, false)],
            1
        )
        .is_err()
    );
}
