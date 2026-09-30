use sha2::{Digest as _, Sha256};

use super::{PrivateStorageStore, StorageError};
use crate::{CHUNK_BYTES, private_storage::StorageLimits};

const NOW: u64 = 1_800_000_000;

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn limits(capacity_bytes: u64) -> StorageLimits {
    StorageLimits {
        capacity_bytes,
        min_free_bytes: 0,
    }
}

#[test]
fn admission_lowering_retains_reserved_and_committed_copies_across_restart() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let bytes = vec![83; CHUNK_BYTES + 31];
    let length = bytes.len() as u64;
    let mut store = PrivateStorageStore::create(&path, limits(4 * length)).unwrap();
    assert_eq!(store.admission_status().unwrap().target_bytes, 4 * length);
    let first = store.reserve(length, hash(&bytes), NOW + 60, NOW).unwrap();
    store
        .write_reserved(first, &mut bytes.as_slice(), NOW)
        .unwrap();
    let second = store.reserve(length, hash(&bytes), NOW + 60, NOW).unwrap();
    let prefix = &bytes[..CHUNK_BYTES];
    store
        .append_chunk(second, 0, hash(prefix), prefix, NOW)
        .unwrap();

    let lowered = store.set_admission_target(length).unwrap();
    assert_eq!(lowered.reserved_bytes, length);
    assert_eq!(lowered.committed_bytes, length);
    assert_eq!(lowered.retained_payload_bytes, 2 * length);
    assert_eq!(lowered.pending_drain_bytes, length);
    assert_eq!(lowered.available_for_new_reservations_bytes, 0);
    assert_eq!(lowered.leases, 2);
    assert!(matches!(
        store.reserve(1, hash(&[1]), NOW + 60, NOW),
        Err(StorageError::Quota)
    ));
    // Lowering admission does not invalidate usage against the original hard capacity.
    assert_eq!(store.usage().unwrap().committed_bytes, length);
    drop(store);

    let mut store = PrivateStorageStore::open(&path, limits(4 * length)).unwrap();
    assert_eq!(store.admission_status().unwrap(), lowered);
    let mut restored = Vec::new();
    store.restore(first, &mut restored, NOW + 1).unwrap();
    assert_eq!(restored, bytes);
    let suffix = &bytes[CHUNK_BYTES..];
    store
        .append_chunk(second, 1, hash(suffix), suffix, NOW + 1)
        .unwrap();
    store.finalize(second, NOW + 1).unwrap();
    store.renew(first, NOW + 600, NOW + 1).unwrap();
    restored.clear();
    store.restore(second, &mut restored, NOW + 1).unwrap();
    assert_eq!(restored, bytes);
    assert_eq!(
        store.admission_status().unwrap().committed_bytes,
        2 * length
    );
    assert_eq!(
        store.admission_status().unwrap().pending_drain_bytes,
        length
    );

    assert!(store.delete(first).unwrap());
    let drained = store.admission_status().unwrap();
    assert_eq!(drained.pending_drain_bytes, 0);
    assert_eq!(drained.retained_payload_bytes, length);
    assert_eq!(drained.available_for_new_reservations_bytes, 0);
    assert!(matches!(
        store.reserve(1, hash(&[1]), NOW + 60, NOW),
        Err(StorageError::Quota)
    ));
    assert!(store.delete(second).unwrap());
    assert_eq!(
        store
            .admission_status()
            .unwrap()
            .available_for_new_reservations_bytes,
        length
    );
    store.reserve(length, hash(&bytes), NOW + 60, NOW).unwrap();
    assert!(matches!(
        store.reserve(1, hash(&[1]), NOW + 60, NOW),
        Err(StorageError::Quota)
    ));
}

#[test]
fn admission_zero_closes_even_empty_archive_admission_without_deleting_expired_leases() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let mut store = PrivateStorageStore::create(&path, limits(128)).unwrap();
    let id = store.reserve(32, hash(&[5; 32]), NOW + 1, NOW).unwrap();
    let closed = store.set_admission_target(0).unwrap();
    assert_eq!(closed.pending_drain_bytes, 32);
    assert!(matches!(
        store.reserve(0, hash(&[]), NOW + 100, NOW + 2),
        Err(StorageError::Quota)
    ));
    assert_eq!(store.inspect(id).unwrap().expires_at_unix, NOW + 1);
    assert_eq!(store.usage().unwrap().reserved_bytes, 32);
    assert!(matches!(
        store.set_admission_target(129),
        Err(StorageError::InvalidInput)
    ));
    assert_eq!(store.admission_status().unwrap(), closed);
    store.renew(id, NOW + 600, NOW + 2).unwrap();
    assert_eq!(
        store
            .set_admission_target(64)
            .unwrap()
            .available_for_new_reservations_bytes,
        32
    );
    store.reserve(32, hash(&[8; 32]), NOW + 60, NOW).unwrap();
    assert!(matches!(
        store.reserve(1, hash(&[1]), NOW + 60, NOW),
        Err(StorageError::Quota)
    ));
}

#[test]
fn admission_upgrades_real_v1_store_atomically_without_changing_archive_or_hard_limits() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("private");
    let bytes = b"opaque caller-encrypted archive";
    let mut store = PrivateStorageStore::create(&path, limits(1024)).unwrap();
    let id = store
        .reserve(bytes.len() as u64, hash(bytes), NOW + 600, NOW)
        .unwrap();
    store
        .write_reserved(id, &mut bytes.as_slice(), NOW)
        .unwrap();
    // Reconstruct the exact original v1 metadata schema; ownership and real payload stay.
    store
        .connection
        .execute_batch(
            "ALTER TABLE storage_meta DROP COLUMN admission_target_bytes;
         UPDATE storage_meta SET version = 1; PRAGMA user_version = 1;",
        )
        .unwrap();
    drop(store);

    let mut store = PrivateStorageStore::open_existing(&path).unwrap();
    assert_eq!(store.admission_status().unwrap().target_bytes, 1024);
    let schema: i64 = store
        .connection
        .pragma_query_value(None, "user_version", |row| row.get(0))
        .unwrap();
    assert_eq!(schema, 2);
    let mut restored = Vec::new();
    store.restore(id, &mut restored, NOW + 1).unwrap();
    assert_eq!(restored, bytes);
    store.set_admission_target(0).unwrap();
    drop(store);
    let store = PrivateStorageStore::open_existing(&path).unwrap();
    assert_eq!(store.admission_status().unwrap().target_bytes, 0);
    assert_eq!(store.limits(), limits(1024));
    assert_eq!(store.inspect(id).unwrap().sha256, hash(bytes));
}
