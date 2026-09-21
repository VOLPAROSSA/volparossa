use std::os::unix::fs::PermissionsExt;

use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity, publish};

use super::*;

fn options(root: &Path, index: usize) -> ReadyOptions {
    let provider = ed25519_dalek::SigningKey::from_bytes(&[21; 32]).verifying_key();
    ReadyOptions {
        source: Source {
            dataset: root.join(format!("source-{index}.json")),
            dataset_manifest: root.join(format!("source-{index}.bin")),
            publisher_key: provider,
        },
        providers: vec![provider],
        output: root.join(format!("attempt-{index}")),
        max_seconds: 600,
        task: None,
        model_fingerprint: None,
        ready_rows: vec![0],
        pending: Vec::new(),
        executor_admission: None,
    }
}

fn package(root: &Path, index: usize) -> Package {
    let args = options(root, index);
    let publisher = ed25519_dalek::SigningKey::from_bytes(&[21; 32]);
    let json = serde_json::json!({"version":1,"visibility":"public","license":"GPL-3.0-only",
        "source_revision":"a".repeat(40),"train":[],
        "heldout":[{"question":"Purpose?","context":"Public fixture.","answer":"Queue test."}],
        "inference":[{"question":"Input?","context":"Public source."}]})
    .to_string();
    let mut cache = ChunkStore::create(
        &root.join(format!("cache-{index}")),
        CacheLimits {
            max_bytes: 1024 * 1024,
            max_entries: 16,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let at = now().unwrap();
    let signed = publish(
        &mut json.as_bytes(),
        Publication {
            metadata: Metadata {
                name: format!("cohort-source-{index}"),
                revision: 1,
                content_type: volparossa_content::provider::compute::dataset::CONTENT_TYPE.into(),
            },
            length: json.len() as u64,
            validity: Validity {
                created: at,
                expires: at + 1200,
            },
        },
        &publisher,
        &mut cache,
    )
    .unwrap();
    fs::write(&args.source.dataset, json).unwrap();
    fs::write(&args.source.dataset_manifest, signed.encode()).unwrap();
    let mut caps = super::super::tests::handle(21, 1, at + 600).capabilities;
    caps.model.model_id = volparossa_content::agent_artifact::MODEL_ID.into();
    caps.model.model_revision = volparossa_content::agent_artifact::MODEL_REVISION.into();
    caps.model.base_weights.bytes = volparossa_content::ModelProfile::default()
        .spec()
        .weights_bytes;
    caps.model.base_weights.sha256 =
        hex::encode(volparossa_content::agent_artifact::BASE_MODEL_SHA256);
    caps.model_fingerprint = sha(&serde_json::to_vec(&caps.model).unwrap());
    initialize(
        prepare(args).unwrap(),
        &BTreeMap::from([(hex::encode(publisher.verifying_key().as_bytes()), caps)]),
    )
    .unwrap()
}

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    root
}

#[tokio::test]
async fn stable_append_indices_survive_idle_with_original_external_lease() {
    let root = private_root();
    let (_owner, activity) = watch::channel(false);
    let original = super::super::tests::handle(1, 2, now().unwrap() + 600);
    let exact = serde_json::to_vec(&original).unwrap();
    let mut driver = ReadyCohort::new(
        &[ReadyPending {
            handle: original.clone(),
            verified_status: None,
        }],
        Path::new("unused-no-network"),
        &activity,
    )
    .unwrap();
    assert!(driver.next_completed().await.unwrap().is_none());
    for index in 0..2 {
        assert_eq!(
            driver
                .append(vec![options(root.path(), index)])
                .await
                .unwrap(),
            vec![index]
        );
        let (received, result) = driver.next_completed().await.unwrap().unwrap();
        assert_eq!(received, index);
        assert!(result.is_err()); // Explicit source files do not exist: no metadata RPC.
        assert!(driver.next_completed().await.unwrap().is_none());
        assert!(!driver.leases.free(&original.provider_key));
        assert_eq!(
            serde_json::to_vec(
                &driver.leases.held[&original.provider_key][&original.binding.job_id]
            )
            .unwrap(),
            exact
        );
    }
    assert!(driver.cancel_and_drain().await.unwrap().is_empty());
}

#[tokio::test]
async fn append_bounds_include_completed_packages_and_reject_duplicate_output() {
    let root = private_root();
    let (_owner, activity) = watch::channel(false);
    let mut driver = ReadyCohort::new(&[], Path::new("unused-no-network"), &activity).unwrap();
    let first = options(root.path(), 0);
    driver.append(vec![first.clone()]).await.unwrap();
    assert!(driver.next_completed().await.unwrap().unwrap().1.is_err());
    assert_eq!(
        driver.append(vec![first]).await.unwrap_err().to_string(),
        "compute_cohort_duplicate_output"
    );
    driver
        .append(
            (1..MAX_PACKAGES)
                .map(|index| options(root.path(), index))
                .collect(),
        )
        .await
        .unwrap();
    assert_eq!(
        driver
            .append(vec![options(root.path(), MAX_PACKAGES)])
            .await
            .unwrap_err()
            .to_string(),
        "compute_cohort_package_bound"
    );
    assert_eq!(
        driver.cancel_and_drain().await.unwrap().len(),
        MAX_PACKAGES - 1
    );
}

#[tokio::test]
async fn cancellation_never_creates_late_plan_or_submits_appended_source() {
    let root = private_root();
    let source = package(root.path(), 0).args;
    let mut next = source.clone();
    next.output = root.path().join("cancelled-attempt");
    let (_owner, activity) = watch::channel(false);
    let mut driver = ReadyCohort::new(&[], Path::new("unused-no-network"), &activity).unwrap();
    driver.cancel_and_drain().await.unwrap();
    assert_eq!(driver.append(vec![next.clone()]).await.unwrap(), vec![0]);
    let (_, result) = driver.next_completed().await.unwrap().unwrap();
    assert_eq!(
        result.unwrap_err().to_string(),
        "compute_distribute_cancelled_before_submit"
    );
    assert!(!next.output.exists());
    assert!(driver.cancel_and_drain().await.unwrap().is_empty());
}

#[tokio::test]
async fn package_receipt_is_yielded_while_other_exact_handle_future_is_alive() {
    let root = private_root();
    let (_owner, activity) = watch::channel(false);
    let mut driver = ReadyCohort::new(&[], Path::new("unused-no-network"), &activity).unwrap();
    let mut senders = Vec::new();
    let mut original_handles = Vec::new();
    for index in 0..2 {
        let mut package = package(root.path(), index);
        let caps = super::super::tests::handle(21, 1, now().unwrap() + 600).capabilities;
        let mut handle = JobHandle {
            version: 1,
            provider_key: hex::encode(package.args.providers[0].as_bytes()),
            binding: rpc::JobBinding {
                job_id: hex::encode([u8::try_from(index + 1).unwrap(); 16]),
                dataset_manifest_id: package.plan.dataset_manifest_id.clone(),
                dataset_sha256: package.plan.dataset_sha256.clone(),
                model_fingerprint: package.plan.model_fingerprint.clone(),
                row_indices: vec![0],
                expires_unix_seconds: now().unwrap() + 600,
                task: None,
            },
            capabilities: caps,
        };
        // Distinct pure-fixture peers, without opening transport or running a model.
        handle.provider_key = hex::encode(
            ed25519_dalek::SigningKey::from_bytes(&[u8::try_from(index + 21).unwrap(); 32])
                .verifying_key()
                .as_bytes(),
        );
        save_new(&package.args.output.join("job-0.json"), &handle).unwrap();
        driver
            .leases
            .observe(&handle, None, now().unwrap())
            .unwrap();
        original_handles.push(handle.clone());
        package.rows.clear();
        package.inflight = 1;
        let (sender, receiver) = tokio::sync::oneshot::channel::<()>();
        senders.push(sender);
        driver.tasks.spawn(async move {
            receiver.await.unwrap();
            let status = rpc::JobStatus {
                binding: handle.binding.clone(),
                state: rpc::JobState::Failed,
                cancellation_requested: false,
                report_json: None,
                report_sha256: None,
                error: None,
            };
            GroupEvent::Finished {
                package: index,
                handle,
                result: Ok(status),
                new_submission: true,
            }
        });
        driver.packages.push(Some(package));
        driver.results.push(None);
    }
    senders.remove(1).send(()).unwrap();
    let (index, result) = timeout(Duration::from_secs(1), driver.next_completed())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(index, 1);
    assert!(!result.unwrap()["complete"].as_bool().unwrap());
    assert!(driver.packages[0].is_some());
    assert_eq!(driver.tasks.len(), 1);
    let completed = root.path().join("attempt-1");
    assert!(completed.join("result.json").exists());
    assert!(
        completed
            .join(format!("receipt-{}.json", hex::encode([2; 16])))
            .exists()
    );
    // A newly ready child's admission failure is yielded without draining the
    // unrelated original future. Missing source is intentional: no transport/model.
    assert_eq!(
        driver.append(vec![options(root.path(), 2)]).await.unwrap(),
        vec![2]
    );
    let (child, result) = timeout(Duration::from_secs(1), driver.next_completed())
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(child, 2);
    assert!(result.is_err());
    assert_eq!(driver.tasks.len(), 1);
    assert!(!senders[0].is_closed());
    let original = &original_handles[0];
    assert_eq!(
        serde_json::to_vec(&driver.leases.held[&original.provider_key][&original.binding.job_id])
            .unwrap(),
        serde_json::to_vec(original).unwrap()
    );
    senders.remove(0).send(()).unwrap();
    assert_eq!(driver.next_completed().await.unwrap().unwrap().0, 0);
    assert!(driver.next_completed().await.unwrap().is_none());
    assert!(driver.cancel_and_drain().await.unwrap().is_empty());
}
