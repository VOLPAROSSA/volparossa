//! Filesystem protocol fixtures only; these inert bytes are never executed as an adapter.

use super::*;
use serde_json::json;

fn setup() -> TempDir {
    let root = tempfile::tempdir().unwrap();
    fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
    for name in ["published", "runtime", "adapter", "work", "other-runtime"] {
        fs::DirBuilder::new()
            .mode(0o700)
            .create(root.path().join(name))
            .unwrap();
    }
    for (name, _) in FILES {
        write_new(
            &root.path().join("adapter").join(name),
            b"inert storage fixture",
        )
        .unwrap();
    }
    root
}

fn provenance(root: &Path, sequence: u64) -> Value {
    let files: BTreeMap<_, _> = adapter_bytes(&root.join("adapter"))
        .unwrap()
        .into_iter()
        .map(|(name, bytes)| (name, identity(&bytes)))
        .collect();
    json!({"kind":"approved_local_successor","approved":true,"adapter_files":files,"sequence":sequence})
}

#[test]
fn snapshot_preserves_original_expiry_and_exact_bytes_without_a_worker() {
    let root = setup();
    let at = root.path();
    let publisher =
        Publisher::open(&at.join("published"), &at.join("runtime"), &"a".repeat(64)).unwrap();
    assert!(
        peek(&at.join("published"), &at.join("runtime"))
            .unwrap()
            .is_none()
    );
    let first = publisher
        .publish(&at.join("adapter"), 100, &provenance(at, 1), 10)
        .unwrap();
    let before = fs::read(at.join("published/current.json")).unwrap();
    assert_eq!(
        publisher
            .publish(&at.join("adapter"), 100, &provenance(at, 1), 90)
            .unwrap()
            .id,
        first.id
    );
    assert_eq!(fs::read(at.join("published/current.json")).unwrap(), before);
    let loaded = peek(&at.join("published"), &at.join("runtime"))
        .unwrap()
        .unwrap();
    assert_eq!(loaded.id, first.id);
    assert_eq!(loaded.expires_unix_seconds, 100);
    // The original expiry remains visible; an expired selection is never absence.
    assert_eq!(
        peek(&at.join("published"), &at.join("runtime"))
            .unwrap()
            .unwrap()
            .expires_unix_seconds,
        100
    );
    let snapshot = copy_selection(&at.join("published"), &loaded, &at.join("work")).unwrap();
    assert_eq!(fs::read_dir(snapshot.adapter_path()).unwrap().count(), 3);
    for (name, _) in FILES {
        assert_eq!(
            fs::read(snapshot.adapter_path().join(name)).unwrap(),
            b"inert storage fixture"
        );
    }
    assert_eq!(snapshot.selection.id, first.id);
}

#[test]
fn bounded_publication_retention_cannot_erase_the_brokers_owned_copy() {
    let root = setup();
    let at = root.path();
    let publisher =
        Publisher::open(&at.join("published"), &at.join("runtime"), &"a".repeat(64)).unwrap();
    let first = publisher
        .publish(&at.join("adapter"), 100, &provenance(at, 1), 10)
        .unwrap();
    let copy = copy_selection(&at.join("published"), &first, &at.join("work")).unwrap();
    for sequence in 2..=5 {
        fs::write(
            at.join("adapter/README.md"),
            format!("inert revision {sequence}"),
        )
        .unwrap();
        publisher
            .publish(
                &at.join("adapter"),
                100,
                &provenance(at, sequence),
                10 + sequence,
            )
            .unwrap();
        let copies = fs::read_dir(at.join("published"))
            .unwrap()
            .filter(|entry| {
                entry
                    .as_ref()
                    .unwrap()
                    .file_name()
                    .to_str()
                    .unwrap()
                    .starts_with("snapshot-")
            })
            .count();
        assert_eq!(copies, 2);
    }
    assert!(!snapshot_path(&at.join("published"), &first).exists());
    assert_eq!(
        fs::read(copy.adapter_path().join("README.md")).unwrap(),
        b"inert storage fixture"
    );
}

#[test]
fn rejected_changed_or_expired_candidate_preserves_the_previous_selection() {
    let root = setup();
    let at = root.path();
    let publisher =
        Publisher::open(&at.join("published"), &at.join("runtime"), &"a".repeat(64)).unwrap();
    let proof = provenance(at, 1);
    let first = publisher
        .publish(&at.join("adapter"), 100, &proof, 10)
        .unwrap();
    let mut rejected = proof.clone();
    rejected["approved"] = false.into();
    assert!(
        publisher
            .publish(&at.join("adapter"), 100, &rejected, 11)
            .is_err()
    );
    assert!(
        publisher
            .publish(&at.join("adapter"), 11, &proof, 11)
            .is_err()
    );
    fs::write(at.join("adapter/README.md"), b"changed after approval").unwrap();
    assert!(
        publisher
            .publish(&at.join("adapter"), 100, &proof, 11)
            .is_err()
    );
    assert_eq!(
        peek(&at.join("published"), &at.join("runtime"))
            .unwrap()
            .unwrap()
            .id,
        first.id
    );
    fs::write(
        snapshot_path(&at.join("published"), &first).join("README.md"),
        b"changed saved bytes",
    )
    .unwrap();
    assert!(copy_selection(&at.join("published"), &first, &at.join("work")).is_err());
}

#[test]
fn runtime_and_single_producer_authority_are_not_transferable() {
    let root = setup();
    let at = root.path();
    let publisher =
        Publisher::open(&at.join("published"), &at.join("runtime"), &"a".repeat(64)).unwrap();
    publisher
        .publish(&at.join("adapter"), 100, &provenance(at, 1), 10)
        .unwrap();
    assert!(Publisher::open(&at.join("published"), &at.join("runtime"), &"a".repeat(64)).is_err());
    assert!(peek(&at.join("published"), &at.join("other-runtime")).is_err());
    drop(publisher);
    assert!(Publisher::open(&at.join("published"), &at.join("runtime"), &"b".repeat(64)).is_err());
    let publisher =
        Publisher::open(&at.join("published"), &at.join("runtime"), &"a".repeat(64)).unwrap();
    fs::write(at.join("published/unowned.txt"), b"not ours to remove").unwrap();
    assert!(
        publisher
            .publish(&at.join("adapter"), 100, &provenance(at, 2), 12)
            .is_err()
    );
    assert_eq!(
        fs::read(at.join("published/unowned.txt")).unwrap(),
        b"not ours to remove"
    );
}
