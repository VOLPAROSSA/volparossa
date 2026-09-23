//! Inert snapshots and task sentinels only: no host model or remote execution.

use super::super::{
    Budget, ErrorCode, FileIdentity, JobState, OpenOptions, OpenOptionsExt, Operation, Outcome,
    Path, PathBuf, PermissionsExt, Write, fs, tests as fixtures, timeout, watch,
};
use super::*;
use serde_json::json;

fn directory(parent: &Path, name: &str) -> PathBuf {
    let path = parent.join(name);
    fs::create_dir(&path).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}

fn publish(
    publisher: &serving_snapshot::Publisher,
    adapter: &Path,
    label: &str,
    expires: u64,
    time: u64,
) -> serving_snapshot::Selection {
    let mut files = std::collections::BTreeMap::new();
    for name in [
        "README.md",
        "adapter_config.json",
        "adapter_model.safetensors",
    ] {
        // Not executable weights: only copy/hash/ownership is tested here.
        let bytes = format!("Inert snapshot fixture {label}: {name}");
        let path = adapter.join(name);
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(&path)
            .unwrap();
        file.write_all(bytes.as_bytes()).unwrap();
        files.insert(
            name,
            FileIdentity {
                bytes: bytes.len() as u64,
                sha256: sha(bytes.as_bytes()),
            },
        );
    }
    publisher
        .publish(
            adapter,
            expires,
            &json!({"kind":"approved_local_successor",
        "approved":true,"adapter_files":files}),
            time,
        )
        .unwrap()
}

fn configured(root: &Path) -> (Broker, serving_snapshot::Publisher, PathBuf) {
    let runtime = directory(root, "runtime");
    let selected = directory(root, "selected");
    let work = directory(root, "work");
    let adapter = directory(root, "adapter");
    let mut broker = fixtures::broker(&work);
    broker.options.runtime_root = runtime.clone();
    broker.options.serving_directory = Some(selected.clone());
    broker.capabilities.successor_activation_v1 = true;
    let publisher =
        serving_snapshot::Publisher::open(&selected, &runtime, &"a".repeat(64)).unwrap();
    (broker, publisher, adapter)
}

fn restart(broker: &Broker) -> Broker {
    let mut restarted = fixtures::broker(&broker.options.work_root);
    restarted
        .options
        .runtime_root
        .clone_from(&broker.options.runtime_root);
    restarted
        .options
        .serving_directory
        .clone_from(&broker.options.serving_directory);
    restarted.capabilities.successor_activation_v1 = true;
    restarted
}

async fn accepting(broker: &mut Broker, time: u64) -> bool {
    let request = fixtures::request(Operation::Capabilities);
    let Outcome::Capabilities(caps) = broker.handle(request, time).await.outcome else {
        panic!("capabilities");
    };
    caps.accepting_work
}

#[tokio::test]
async fn initial_base_waits_for_successful_empty_observation_and_is_never_reenabled() {
    let root = tempfile::tempdir().unwrap();
    let (mut broker, _publisher, _adapter) = configured(root.path());
    let time = now().unwrap();
    assert!(!broker.successor_valid(time));
    broker.budget = Budget::fixed_for_test(Decision::Pause);
    broker.refresh(time).await;
    assert_eq!(broker.initial_base, InitialBase::Unknown);
    assert!(!broker.successor_valid(time));
    broker.budget = Budget::fixed_for_test(Decision::Run);
    assert!(accepting(&mut broker, time).await);
    assert_eq!(broker.initial_base, InitialBase::NeverSelected);
    let current = broker
        .options
        .serving_directory
        .as_ref()
        .unwrap()
        .join("current.json");
    fs::write(&current, b"invalid current selection").unwrap();
    fs::set_permissions(&current, fs::Permissions::from_mode(0o600)).unwrap();
    broker.next_successor_check = tokio::time::Instant::now();
    assert!(!accepting(&mut broker, time).await);
    assert_eq!(broker.initial_base, InitialBase::Withdrawn);
    fs::remove_file(&current).unwrap();
    broker.next_successor_check = tokio::time::Instant::now();
    assert!(!accepting(&mut broker, time).await);
}

#[tokio::test]
async fn initial_base_admission_observes_withdrawal_before_the_next_copy_refresh() {
    let root = tempfile::tempdir().unwrap();
    let (mut broker, publisher, adapter) = configured(root.path());
    let time = now().unwrap();
    assert!(accepting(&mut broker, time).await);
    assert_eq!(broker.initial_base, InitialBase::NeverSelected);
    assert!(broker.successor.is_none());
    let scheduled = broker.next_successor_check;
    publish(&publisher, &adapter, "first", time + 300, time);
    publisher.withdraw_current().unwrap();
    assert!(!accepting(&mut broker, time).await);
    assert_eq!(broker.next_successor_check, scheduled);
    assert!(broker.successor.is_none());
}

#[tokio::test]
async fn restarted_expired_corrupt_or_missing_selection_never_advertises_base_work() {
    let root = tempfile::tempdir().unwrap();
    let (broker, publisher, adapter) = configured(root.path());
    let time = now().unwrap();
    publish(&publisher, &adapter, "expired", time - 1, time - 10);
    let mut expired = restart(&broker);
    assert!(!accepting(&mut expired, time).await);
    assert!(expired.successor.is_none());
    assert_eq!(expired.initial_base, InitialBase::Withdrawn);
    let current = broker
        .options
        .serving_directory
        .as_ref()
        .unwrap()
        .join("current.json");
    fs::write(&current, b"invalid current selection").unwrap();
    let mut corrupt = restart(&broker);
    assert!(!accepting(&mut corrupt, time).await);
    assert!(corrupt.successor.is_none());
    fs::remove_file(current).unwrap();
    // An orphaned previously selected snapshot is not a never-selected directory.
    let mut missing = restart(&broker);
    assert!(!accepting(&mut missing, time).await);
    assert!(missing.successor.is_none());
}

#[tokio::test]
async fn bad_new_metadata_keeps_valid_owned_successor_only_until_original_expiry() {
    let root = tempfile::tempdir().unwrap();
    let (mut broker, publisher, adapter) = configured(root.path());
    let time = now().unwrap();
    let first = publish(&publisher, &adapter, "valid", time + 300, time);
    assert!(accepting(&mut broker, time).await);
    let model = broker.capabilities.model_fingerprint.clone();
    let owned = broker.successor.as_ref().unwrap().adapter_path().to_owned();
    let weights = fs::read(owned.join("adapter_model.safetensors")).unwrap();
    publish(&publisher, &adapter, "already-expired", time - 1, time - 10);
    broker.next_successor_check = tokio::time::Instant::now();
    assert!(accepting(&mut broker, time).await);
    let current = broker
        .options
        .serving_directory
        .as_ref()
        .unwrap()
        .join("current.json");
    fs::write(current, b"invalid newer selection").unwrap();
    broker.next_successor_check = tokio::time::Instant::now();
    assert!(accepting(&mut broker, time + 1).await);
    assert_eq!(broker.capabilities.model_fingerprint, model);
    assert_eq!(broker.successor.as_ref().unwrap().selection.id, first.id);
    assert_eq!(
        fs::read(owned.join("adapter_model.safetensors")).unwrap(),
        weights
    );
    assert!(!accepting(&mut broker, time + 300).await);
    assert_eq!(broker.capabilities.model_fingerprint, model);
}

#[tokio::test]
async fn accepted_snapshot_changes_new_model_but_retains_old_receipt_binding() {
    let root = tempfile::tempdir().unwrap();
    let (mut broker, publisher, adapter) = configured(root.path());
    let time = now().unwrap();
    let mut old = fixtures::terminal_job(0);
    old.status.binding.expires_unix_seconds = time + 600;
    old.terminal_retain_until = Some(time + 600);
    let original = old.status.clone();
    broker.jobs.push_back(old);
    let selection = publish(&publisher, &adapter, "one", time + 300, time);
    broker.refresh(time).await;
    assert_eq!(
        broker.successor.as_ref().unwrap().selection.id,
        selection.id
    );
    assert_ne!(
        broker.capabilities.model_fingerprint,
        original.binding.model_fingerprint
    );
    assert_eq!(
        broker.capabilities.model.adapter_files,
        Some(selection.adapter_files)
    );
    assert_eq!(
        broker.observe(&"b".repeat(64), &original.binding, false),
        Outcome::Job(original.clone())
    );
    let mut wrong = original.binding.clone();
    wrong.model_fingerprint = broker.capabilities.model_fingerprint.clone();
    assert_eq!(
        broker.observe(&"b".repeat(64), &wrong, false),
        Outcome::Error(ErrorCode::Missing)
    );
    let request = fixtures::request(Operation::Capabilities);
    let Outcome::Capabilities(caps) = broker.handle(request.clone(), time + 250).await.outcome
    else {
        panic!("capabilities");
    };
    assert_eq!(caps.max_job_seconds, 50);
    assert!(caps.accepting_work);
    let Outcome::Capabilities(caps) = broker.handle(request, time + 300).await.outcome else {
        panic!("capabilities");
    };
    assert!(!caps.accepting_work);
    assert_eq!(
        broker.observe(&"b".repeat(64), &original.binding, false),
        Outcome::Job(original)
    );
}

#[tokio::test]
async fn live_execution_keeps_its_snapshot_until_settled_without_changing_lease() {
    let root = tempfile::tempdir().unwrap();
    let (mut broker, publisher, adapter) = configured(root.path());
    let time = now().unwrap();
    let first = publish(&publisher, &adapter, "one", time + 900, time);
    broker.refresh(time).await;
    let original_path = broker.successor.as_ref().unwrap().adapter_path().to_owned();
    let original_bytes = fs::read(original_path.join("adapter_model.safetensors")).unwrap();
    let (sender, mut receiver) = watch::channel(true);
    let execution = tokio::spawn(async move {
        while *receiver.borrow() {
            receiver.changed().await?;
        }
        anyhow::bail!("compute_owner_busy")
    });
    let mut job = fixtures::terminal_job(0);
    job.status.binding.expires_unix_seconds = time + 600;
    job.status.binding.model_fingerprint = broker.capabilities.model_fingerprint.clone();
    job.status.state = JobState::Running;
    job.status.cancellation_requested = false;
    job.activity = sender;
    job.execution = Some(execution);
    let original = job.status.binding.clone();
    broker.jobs.push_back(job);
    let second = publish(&publisher, &adapter, "two", time + 900, time);
    let third = publish(&publisher, &adapter, "three", time + 900, time);
    assert_ne!(second.id, third.id);
    broker.next_successor_check = tokio::time::Instant::now();
    broker.refresh(time).await;
    assert_eq!(broker.successor.as_ref().unwrap().selection.id, first.id);
    assert_eq!(
        fs::read(original_path.join("adapter_model.safetensors")).unwrap(),
        original_bytes
    );
    assert_eq!(broker.jobs[0].status.binding, original);
    let _ = broker.observe(&"b".repeat(64), &original, true);
    timeout(Duration::from_secs(1), async {
        while !broker.jobs[0].execution.as_ref().unwrap().is_finished() {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    broker.next_successor_check = tokio::time::Instant::now();
    broker.refresh(time).await;
    assert_eq!(broker.successor.as_ref().unwrap().selection.id, third.id);
    assert_eq!(broker.jobs[0].status.binding, original);
    assert_eq!(broker.jobs[0].status.state, JobState::Cancelled);
    assert!(!original_path.exists());
}

#[tokio::test]
async fn owner_withdrawal_stops_owned_copy_admission_and_preserves_original_receipts() {
    let root = tempfile::tempdir().unwrap();
    let (mut broker, publisher, adapter) = configured(root.path());
    let time = now().unwrap();
    let first = publish(&publisher, &adapter, "first", time + 300, time);
    assert!(accepting(&mut broker, time).await);
    let path = broker.successor.as_ref().unwrap().adapter_path().to_owned();
    let mut old = fixtures::terminal_job(0);
    old.status.binding.expires_unix_seconds = time + 600;
    old.terminal_retain_until = Some(time + 600);
    let receipt = old.status.clone();
    broker.jobs.push_back(old);
    publisher.withdraw_current().unwrap();
    // Admission observes explicit withdrawal even between scheduled copy refreshes.
    assert!(!accepting(&mut broker, time).await);
    assert_eq!(broker.successor.as_ref().unwrap().selection.id, first.id);
    assert!(path.exists());
    assert_eq!(
        broker.observe(&"b".repeat(64), &receipt.binding, false),
        Outcome::Job(receipt.clone())
    );
    let mut restarted = restart(&broker);
    assert!(!accepting(&mut restarted, time).await);
    assert!(restarted.successor.is_none());
    let approved = publish(
        &publisher,
        &adapter,
        "approved-predecessor",
        time + 200,
        time,
    );
    // The accepted old copy stays withheld until the checked replacement is copied.
    assert!(!broker.successor_valid(time));
    broker.next_successor_check = tokio::time::Instant::now();
    assert!(accepting(&mut broker, time).await);
    assert_eq!(broker.successor.as_ref().unwrap().selection.id, approved.id);
    assert_eq!(
        broker.observe(&"b".repeat(64), &receipt.binding, false),
        Outcome::Job(receipt)
    );
    assert!(!broker.successor_valid(time + 200));
}
