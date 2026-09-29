//! Actual local SQLite/ciphertext lifecycle; these tests do not assert remote custody.

use std::{
    fs,
    io::{self, Read as _, Write as _},
    os::unix::fs::PermissionsExt as _,
};

use rusqlite::params;
use sha2::{Digest as _, Sha256};
use volparossa_content::{
    CHUNK_BYTES,
    private_storage::{
        LeaseId, MAX_ARCHIVE_BYTES, MAX_LEASE_SECONDS, PrivateStorageStore, StorageError,
        StorageLimits,
    },
};

const NOW: u64 = 1_800_000_000;

fn limits(bytes: u64) -> StorageLimits {
    StorageLimits {
        capacity_bytes: bytes,
        min_free_bytes: 0,
    }
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[test]
fn private_storage_restart_restore_is_nonconsuming_and_renewal_keeps_immutable_bytes() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let bytes = (0..CHUNK_BYTES + 71)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect::<Vec<_>>();
    let configuration = limits(4 * CHUNK_BYTES as u64);
    let mut store = PrivateStorageStore::create(&root, configuration).unwrap();
    let id = store
        .reserve(bytes.len() as u64, hash(&bytes), NOW + 60, NOW)
        .unwrap();
    assert_eq!(id.to_string().parse::<LeaseId>().unwrap(), id);
    assert_eq!(LeaseId::from_bytes(*id.as_bytes()), id);
    assert!(!store.inspect(id).unwrap().committed);
    let expected = store
        .write_reserved(id, &mut bytes.as_slice(), NOW)
        .unwrap();
    assert!(expected.committed);
    assert_eq!(store.usage().unwrap().reserved_bytes, 0);
    assert_eq!(store.usage().unwrap().committed_bytes, bytes.len() as u64);
    drop(store);

    let mut store = PrivateStorageStore::open_existing(&root).unwrap();
    assert_eq!(store.limits(), configuration);
    for _ in 0..2 {
        let mut restored = Vec::new();
        assert_eq!(store.restore(id, &mut restored, NOW + 1).unwrap(), expected);
        assert_eq!(restored, bytes);
    }
    assert!(matches!(
        store.restore(id, &mut io::sink(), NOW + 60),
        Err(StorageError::Expired)
    ));
    assert_eq!(store.usage().unwrap().committed_bytes, bytes.len() as u64);
    let renewed = store.renew(id, NOW + 600, NOW + 61).unwrap();
    assert_eq!(renewed.sha256, expected.sha256);
    assert_eq!(renewed.ciphertext_bytes, expected.ciphertext_bytes);
    assert_eq!(renewed.expires_at_unix, NOW + 600);
    assert!(matches!(
        store.renew(id, NOW + 500, NOW + 61),
        Err(StorageError::InvalidInput)
    ));
    assert!(matches!(
        store.renew(id, NOW + MAX_LEASE_SECONDS + 1, NOW),
        Err(StorageError::InvalidInput)
    ));
    store.restore(id, &mut io::sink(), NOW + 100).unwrap();
    assert!(store.delete(id).unwrap());
    assert!(!store.delete(id).unwrap());
    assert!(matches!(
        store.renew(id, NOW + 700, NOW),
        Err(StorageError::NotFound)
    ));
    assert_eq!(store.usage().unwrap().committed_bytes, 0);
}

#[test]
fn private_storage_reservations_and_each_physical_copy_share_one_durable_capacity() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let bytes = b"ciphertext";
    let capacity = 2 * bytes.len() as u64;
    let mut store = PrivateStorageStore::create(&root, limits(capacity)).unwrap();
    let first = store
        .reserve(bytes.len() as u64, hash(bytes), NOW + 60, NOW)
        .unwrap();
    let second = store
        .reserve(bytes.len() as u64, hash(bytes), NOW + 60, NOW)
        .unwrap();
    assert_ne!(first, second);
    assert!(matches!(
        store.reserve(1, hash(b"x"), NOW + 60, NOW),
        Err(StorageError::Quota)
    ));
    assert!(matches!(
        PrivateStorageStore::open_existing(&root),
        Err(StorageError::Busy)
    ));
    assert_eq!(store.usage().unwrap().reserved_bytes, capacity);
    drop(store);

    let mut store = PrivateStorageStore::open_existing(&root).unwrap();
    assert_eq!(store.usage().unwrap().reserved_bytes, capacity);
    store
        .write_reserved(first, &mut bytes.as_slice(), NOW)
        .unwrap();
    store
        .write_reserved(second, &mut bytes.as_slice(), NOW)
        .unwrap();
    assert_eq!(store.usage().unwrap().reserved_bytes, 0);
    assert_eq!(store.usage().unwrap().committed_bytes, capacity);
    assert!(matches!(
        store.write_reserved(first, &mut bytes.as_slice(), NOW),
        Err(StorageError::AlreadyCommitted)
    ));
    assert!(store.delete(first).unwrap());
    assert_eq!(store.usage().unwrap().committed_bytes, bytes.len() as u64);
    let mut restored = Vec::new();
    store.restore(second, &mut restored, NOW).unwrap();
    assert_eq!(restored, bytes);
    let replacement = store
        .reserve(bytes.len() as u64, hash(bytes), NOW + 60, NOW)
        .unwrap();
    assert!(!store.inspect(replacement).unwrap().committed);
    let usage = store.usage().unwrap();
    assert_eq!(usage.reserved_bytes + usage.committed_bytes, capacity);
}

#[test]
fn private_storage_failed_upload_rolls_back_chunks_but_keeps_reservation_for_retry() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let bytes = vec![0x9a; CHUNK_BYTES + 31];
    let mut store = PrivateStorageStore::create(&root, limits(bytes.len() as u64)).unwrap();
    let id = store
        .reserve(bytes.len() as u64, hash(&bytes), NOW + 60, NOW)
        .unwrap();
    // The first complete chunk reaches SQLite before this short stream fails.
    assert!(
        store
            .write_reserved(id, &mut &bytes[..=CHUNK_BYTES], NOW)
            .is_err()
    );
    let mut wrong = bytes.clone();
    wrong[CHUNK_BYTES] ^= 1;
    assert!(matches!(
        store.write_reserved(id, &mut wrong.as_slice(), NOW),
        Err(StorageError::Integrity)
    ));
    let mut long = bytes.clone();
    long.push(1);
    assert!(matches!(
        store.write_reserved(id, &mut long.as_slice(), NOW),
        Err(StorageError::Integrity)
    ));
    assert!(matches!(
        store.restore(id, &mut io::sink(), NOW),
        Err(StorageError::NotCommitted)
    ));
    assert_eq!(store.usage().unwrap().reserved_bytes, bytes.len() as u64);
    drop(store);

    let connection = rusqlite::Connection::open(root.join("private-storage.sqlite3")).unwrap();
    let count: u64 = connection
        .query_row("SELECT count(*) FROM chunks", [], |row| row.get(0))
        .unwrap();
    assert_eq!(count, 0);
    drop(connection);
    let mut store = PrivateStorageStore::open_existing(&root).unwrap();
    store
        .write_reserved(id, &mut bytes.as_slice(), NOW)
        .unwrap();
    store.restore(id, &mut io::sink(), NOW).unwrap();
}

#[test]
fn private_storage_restore_rejects_corruption_without_deleting_another_copy() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let bytes = vec![0x41; CHUNK_BYTES + 9];
    let mut store = PrivateStorageStore::create(&root, limits(2 * bytes.len() as u64)).unwrap();
    let damaged = store
        .reserve(bytes.len() as u64, hash(&bytes), NOW + 60, NOW)
        .unwrap();
    let intact = store
        .reserve(bytes.len() as u64, hash(&bytes), NOW + 60, NOW)
        .unwrap();
    for id in [damaged, intact] {
        store
            .write_reserved(id, &mut bytes.as_slice(), NOW)
            .unwrap();
    }
    drop(store);
    let connection = rusqlite::Connection::open(root.join("private-storage.sqlite3")).unwrap();
    connection.execute("UPDATE chunks SET payload = zeroblob(length(payload)) WHERE lease_id = ?1 AND ordinal = 1", [damaged.as_bytes().as_slice()]).unwrap();
    drop(connection);
    let mut store = PrivateStorageStore::open_existing(&root).unwrap();
    assert!(matches!(
        store.restore(damaged, &mut io::sink(), NOW),
        Err(StorageError::Integrity)
    ));
    store.restore(intact, &mut io::sink(), NOW).unwrap();
    assert!(store.delete(damaged).unwrap());
    assert_eq!(store.usage().unwrap().committed_bytes, bytes.len() as u64);
    drop(store);
    let connection = rusqlite::Connection::open(root.join("private-storage.sqlite3")).unwrap();
    connection
        .execute(
            "UPDATE chunks SET ordinal = 3 WHERE lease_id = ?1 AND ordinal = 1",
            params![intact.as_bytes().as_slice()],
        )
        .unwrap();
    drop(connection);
    let store = PrivateStorageStore::open_existing(&root).unwrap();
    assert!(matches!(
        store.restore(intact, &mut io::sink(), NOW),
        Err(StorageError::Integrity)
    ));
}

#[test]
fn private_storage_owner_and_persisted_limits_cannot_be_silently_replaced() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let store = PrivateStorageStore::create(&root, limits(32 * 1024 * 1024 * 1024)).unwrap();
    assert_eq!(store.limits().capacity_bytes, 32 * 1024 * 1024 * 1024);
    assert!(PrivateStorageStore::create(&root, limits(100)).is_err());
    drop(store);
    assert!(matches!(
        PrivateStorageStore::open(&root, limits(100)),
        Err(StorageError::InvalidInput)
    ));
    let foreign = temporary.path().join("copied-marker");
    fs::create_dir(&foreign).unwrap();
    fs::set_permissions(&foreign, fs::Permissions::from_mode(0o700)).unwrap();
    fs::copy(
        root.join(".volparossa-private-storage-v1"),
        foreign.join(".volparossa-private-storage-v1"),
    )
    .unwrap();
    assert!(matches!(
        PrivateStorageStore::open_existing(&foreign),
        Err(StorageError::InvalidStore)
    ));
    let mut store = PrivateStorageStore::open_existing(&root).unwrap();
    assert!(matches!(
        store.reserve(MAX_ARCHIVE_BYTES + 1, [1; 32], NOW + 60, NOW),
        Err(StorageError::InvalidInput)
    ));
    assert!(matches!(
        store.reserve(1, [1; 32], NOW, NOW),
        Err(StorageError::InvalidInput)
    ));
}

struct DigestWriter {
    hash: Sha256,
    bytes: u64,
}

impl io::Write for DigestWriter {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.hash.update(bytes);
        self.bytes += bytes.len() as u64;
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[test]
#[ignore = "explicit 1 GiB disk proof; run separately with --ignored on disposable storage"]
fn private_storage_one_gib_streams_through_real_disk_and_restores_after_restart() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let length = 1024_u64 * 1024 * 1024;
    let mut expected = DigestWriter {
        hash: Sha256::new(),
        bytes: 0,
    };
    io::copy(&mut io::repeat(0xa7).take(length), &mut expected).unwrap();
    assert_eq!(expected.bytes, length);
    let sha256: [u8; 32] = expected.hash.finalize().into();
    let mut store = PrivateStorageStore::create(&root, limits(2 * length)).unwrap();
    let id = store.reserve(length, sha256, NOW + 60, NOW).unwrap();
    store
        .write_reserved(id, &mut io::repeat(0xa7).take(length), NOW)
        .unwrap();
    drop(store);
    let mut store = PrivateStorageStore::open_existing(&root).unwrap();
    let mut restored = DigestWriter {
        hash: Sha256::new(),
        bytes: 0,
    };
    store.restore(id, &mut restored, NOW + 1).unwrap();
    restored.flush().unwrap();
    assert_eq!(restored.bytes, length);
    assert_eq!(<[u8; 32]>::from(restored.hash.finalize()), sha256);
    assert_eq!(store.usage().unwrap().committed_bytes, length);
    assert!(store.delete(id).unwrap());
    assert_eq!(store.usage().unwrap().committed_bytes, 0);
}
