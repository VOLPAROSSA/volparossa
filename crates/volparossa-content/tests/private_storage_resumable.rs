//! Real local durable-prefix tests, not evidence of remote storage or contribution credit.

use std::io::{self, Write as _};

use sha2::{Digest as _, Sha256};
use volparossa_content::{
    CHUNK_BYTES,
    private_storage::{
        MAX_RANGE_BYTES, MAX_RANGE_CHUNKS, PrivateStorageStore, StorageError, StorageLimits,
    },
};

const NOW: u64 = 1_800_000_000;

fn limits(capacity_bytes: u64) -> StorageLimits {
    StorageLimits {
        capacity_bytes,
        min_free_bytes: 0,
    }
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

#[test]
fn resumable_prefix_survives_restart_and_is_not_readable_until_complete() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let bytes = (0..2 * CHUNK_BYTES + 71)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect::<Vec<_>>();
    let length = bytes.len() as u64;
    let mut store = PrivateStorageStore::create(&root, limits(length)).unwrap();
    let id = store.reserve(length, hash(&bytes), NOW + 60, NOW).unwrap();
    let first = &bytes[..CHUNK_BYTES];
    let progress = store.append_chunk(id, 0, hash(first), first, NOW).unwrap();
    assert_eq!(progress.next_chunk, 1);
    assert_eq!(progress.received_bytes, CHUNK_BYTES as u64);
    assert!(!progress.archive.committed);
    assert_eq!(store.usage().unwrap().reserved_bytes, length);
    assert!(matches!(
        store.finalize(id, NOW),
        Err(StorageError::Integrity)
    ));
    assert!(matches!(
        store.read_range(id, 0, 1, &mut io::sink(), NOW),
        Err(StorageError::NotCommitted)
    ));
    // The existing one-shot local command must not overwrite a resumable prefix.
    assert!(matches!(
        store.write_reserved(id, &mut bytes.as_slice(), NOW),
        Err(StorageError::InvalidStore)
    ));
    drop(store);

    let mut store = PrivateStorageStore::open_existing(&root).unwrap();
    assert_eq!(store.upload_progress(id, NOW + 1).unwrap(), progress);
    assert_eq!(
        store
            .append_chunk(id, 0, hash(first), first, NOW + 1)
            .unwrap(),
        progress
    );
    let last = &bytes[2 * CHUNK_BYTES..];
    assert!(matches!(
        store.append_chunk(id, 2, hash(last), last, NOW + 1),
        Err(StorageError::InvalidInput)
    ));
    for (ordinal, chunk) in bytes.chunks(CHUNK_BYTES).enumerate().skip(1) {
        store
            .append_chunk(id, ordinal as u64, hash(chunk), chunk, NOW + 1)
            .unwrap();
    }
    let committed = store.finalize(id, NOW + 1).unwrap();
    assert!(committed.committed);
    assert_eq!(store.finalize(id, NOW + 1).unwrap(), committed);
    assert_eq!(store.usage().unwrap().reserved_bytes, 0);
    assert_eq!(store.usage().unwrap().committed_bytes, length);
    assert!(
        store
            .append_chunk(id, 0, hash(first), first, NOW + 1)
            .unwrap()
            .archive
            .committed
    );
    drop(store);

    let store = PrivateStorageStore::open_existing(&root).unwrap();
    for _ in 0..2 {
        let mut output = Vec::new();
        let first_range = store.read_range(id, 0, 1, &mut output, NOW + 2).unwrap();
        assert_eq!(first_range.ciphertext_bytes, CHUNK_BYTES as u64);
        let last_range = store.read_range(id, 1, 2, &mut output, NOW + 2).unwrap();
        assert_eq!(last_range.first_chunk, 1);
        assert_eq!(last_range.chunk_count, 2);
        assert_eq!(last_range.ciphertext_bytes, (CHUNK_BYTES + 71) as u64);
        assert_eq!(last_range.archive, committed);
        assert_eq!(output, bytes);
    }
    assert_eq!(store.inspect(id).unwrap(), committed);
    assert_eq!(store.usage().unwrap().committed_bytes, length);
}

#[test]
fn resumable_chunks_reject_conflicting_retries_lengths_hashes_and_gaps() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let bytes = vec![0x7a; CHUNK_BYTES + 17];
    let mut store = PrivateStorageStore::create(&root, limits(bytes.len() as u64)).unwrap();
    let id = store
        .reserve(bytes.len() as u64, hash(&bytes), NOW + 60, NOW)
        .unwrap();
    let chunk = &bytes[..CHUNK_BYTES];
    for ordinal in [1, u64::MAX] {
        assert!(
            store
                .append_chunk(id, ordinal, hash(chunk), chunk, NOW)
                .is_err()
        );
    }
    for invalid in [&chunk[..CHUNK_BYTES - 1], &bytes[..=CHUNK_BYTES], &[]] {
        assert!(matches!(
            store.append_chunk(id, 0, hash(invalid), invalid, NOW),
            Err(StorageError::InvalidInput)
        ));
    }
    assert!(matches!(
        store.append_chunk(id, 0, [0; 32], chunk, NOW),
        Err(StorageError::Integrity)
    ));
    let expected = store.append_chunk(id, 0, hash(chunk), chunk, NOW).unwrap();
    let other = vec![0x3c; CHUNK_BYTES];
    assert!(matches!(
        store.append_chunk(id, 0, hash(&other), &other, NOW),
        Err(StorageError::Integrity)
    ));
    assert_eq!(store.upload_progress(id, NOW).unwrap(), expected);
    assert_eq!(store.usage().unwrap().reserved_bytes, bytes.len() as u64);
}

#[test]
fn complete_prefix_with_wrong_archive_hash_remains_charged_and_unreadable() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let bytes = b"already encrypted archive";
    let mut store = PrivateStorageStore::create(&root, limits(bytes.len() as u64)).unwrap();
    let id = store
        .reserve(
            bytes.len() as u64,
            hash(b"different archive"),
            NOW + 60,
            NOW,
        )
        .unwrap();
    store.append_chunk(id, 0, hash(bytes), bytes, NOW).unwrap();
    assert!(matches!(
        store.finalize(id, NOW),
        Err(StorageError::Integrity)
    ));
    drop(store);
    let mut store = PrivateStorageStore::open_existing(&root).unwrap();
    assert!(!store.upload_progress(id, NOW).unwrap().archive.committed);
    assert!(matches!(
        store.finalize(id, NOW),
        Err(StorageError::Integrity)
    ));
    assert!(matches!(
        store.restore(id, &mut io::sink(), NOW),
        Err(StorageError::NotCommitted)
    ));
    assert!(matches!(
        store.read_range(id, 0, 1, &mut io::sink(), NOW),
        Err(StorageError::NotCommitted)
    ));
    assert_eq!(store.usage().unwrap().reserved_bytes, bytes.len() as u64);
    assert!(store.delete(id).unwrap());
    assert_eq!(store.usage().unwrap().reserved_bytes, 0);
}

#[test]
fn lease_expiry_blocks_new_chunks_progress_finalization_and_reads_until_explicit_renewal() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let bytes = b"ciphertext";
    let mut store = PrivateStorageStore::create(&root, limits(bytes.len() as u64)).unwrap();
    let id = store
        .reserve(bytes.len() as u64, hash(bytes), NOW + 1, NOW)
        .unwrap();
    assert!(matches!(
        store.upload_progress(id, 0),
        Err(StorageError::InvalidInput)
    ));
    assert!(matches!(
        store.upload_progress(id, NOW + 1),
        Err(StorageError::Expired)
    ));
    assert!(matches!(
        store.append_chunk(id, 0, hash(bytes), bytes, NOW + 1),
        Err(StorageError::Expired)
    ));
    assert!(matches!(
        store.finalize(id, NOW + 1),
        Err(StorageError::Expired)
    ));
    store.renew(id, NOW + 10, NOW + 1).unwrap();
    store
        .append_chunk(id, 0, hash(bytes), bytes, NOW + 1)
        .unwrap();
    store.finalize(id, NOW + 1).unwrap();
    assert!(matches!(
        store.read_range(id, 0, 1, &mut io::sink(), NOW + 10),
        Err(StorageError::Expired)
    ));
    assert_eq!(store.usage().unwrap().committed_bytes, bytes.len() as u64);
}

#[test]
fn range_limits_are_exact_and_writer_failures_do_not_consume_the_archive() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let chunk = vec![0x41; CHUNK_BYTES];
    let chunks = u64::from(MAX_RANGE_CHUNKS) + 1;
    let mut whole = Sha256::new();
    for _ in 0..chunks {
        whole.update(&chunk);
    }
    let mut store =
        PrivateStorageStore::create(&root, limits(chunks * CHUNK_BYTES as u64)).unwrap();
    let id = store
        .reserve(
            chunks * CHUNK_BYTES as u64,
            whole.finalize().into(),
            NOW + 60,
            NOW,
        )
        .unwrap();
    let chunk_hash = hash(&chunk);
    for ordinal in 0..chunks {
        store
            .append_chunk(id, ordinal, chunk_hash, &chunk, NOW)
            .unwrap();
    }
    store.finalize(id, NOW).unwrap();
    assert_eq!(
        store
            .read_range(id, 0, MAX_RANGE_CHUNKS, &mut io::sink(), NOW)
            .unwrap()
            .ciphertext_bytes,
        MAX_RANGE_BYTES
    );
    for (first, count) in [
        (0, 0),
        (0, MAX_RANGE_CHUNKS + 1),
        (chunks, 1),
        (u64::MAX, 1),
        (chunks - 1, 2),
    ] {
        assert!(matches!(
            store.read_range(id, first, count, &mut io::sink(), NOW),
            Err(StorageError::InvalidInput)
        ));
    }
    // A fixed empty destination fails the first write without changing stored state.
    assert!(matches!(
        store.read_range(id, 0, 1, &mut &mut [][..], NOW),
        Err(StorageError::Io(_))
    ));
    store
        .read_range(id, chunks - 1, 1, &mut io::sink(), NOW)
        .unwrap();
    assert_eq!(
        store.usage().unwrap().committed_bytes,
        chunks * CHUNK_BYTES as u64
    );
}

#[test]
fn finalize_rechecks_committed_bytes_and_range_reads_detect_corruption() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let bytes = vec![0x67; CHUNK_BYTES + 23];
    let mut store = PrivateStorageStore::create(&root, limits(bytes.len() as u64)).unwrap();
    let id = store
        .reserve(bytes.len() as u64, hash(&bytes), NOW + 60, NOW)
        .unwrap();
    for (ordinal, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
        store
            .append_chunk(id, ordinal as u64, hash(chunk), chunk, NOW)
            .unwrap();
    }
    store.finalize(id, NOW).unwrap();
    drop(store);
    let connection = rusqlite::Connection::open(root.join("private-storage.sqlite3")).unwrap();
    connection
        .execute(
            "UPDATE chunks SET payload = zeroblob(length(payload)) WHERE ordinal = 1",
            [],
        )
        .unwrap();
    drop(connection);
    let mut store = PrivateStorageStore::open_existing(&root).unwrap();
    assert!(matches!(
        store.finalize(id, NOW),
        Err(StorageError::Integrity)
    ));
    assert!(matches!(
        store.read_range(id, 1, 1, &mut io::sink(), NOW),
        Err(StorageError::Integrity)
    ));
    // Unaffected ranges have their own integrity check, not a claim about the entire file.
    store.read_range(id, 0, 1, &mut io::sink(), NOW).unwrap();
    assert_eq!(store.usage().unwrap().committed_bytes, bytes.len() as u64);
}

#[test]
fn progress_and_finalize_reject_a_gap_after_restart() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let bytes = vec![0x27; 2 * CHUNK_BYTES + 19];
    let mut store = PrivateStorageStore::create(&root, limits(bytes.len() as u64)).unwrap();
    let id = store
        .reserve(bytes.len() as u64, hash(&bytes), NOW + 60, NOW)
        .unwrap();
    for (ordinal, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
        store
            .append_chunk(id, ordinal as u64, hash(chunk), chunk, NOW)
            .unwrap();
    }
    drop(store);
    let connection = rusqlite::Connection::open(root.join("private-storage.sqlite3")).unwrap();
    connection
        .execute("DELETE FROM chunks WHERE ordinal = 1", [])
        .unwrap();
    drop(connection);
    let mut store = PrivateStorageStore::open_existing(&root).unwrap();
    assert!(matches!(
        store.upload_progress(id, NOW),
        Err(StorageError::Integrity)
    ));
    assert!(matches!(
        store.finalize(id, NOW),
        Err(StorageError::Integrity)
    ));
    assert!(!store.inspect(id).unwrap().committed);
}

#[test]
fn empty_archives_finalize_without_inventing_a_zero_length_chunk() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let mut store = PrivateStorageStore::create(&root, limits(1)).unwrap();
    let id = store.reserve(0, hash(&[]), NOW + 60, NOW).unwrap();
    assert_eq!(store.upload_progress(id, NOW).unwrap().next_chunk, 0);
    assert!(matches!(
        store.append_chunk(id, 0, hash(&[]), &[], NOW),
        Err(StorageError::InvalidInput)
    ));
    store.finalize(id, NOW).unwrap();
    store.restore(id, &mut io::sink(), NOW).unwrap();
    assert!(matches!(
        store.read_range(id, 0, 1, &mut io::sink(), NOW),
        Err(StorageError::InvalidInput)
    ));
}

#[derive(Default)]
struct DigestWriter {
    bytes: u64,
    hash: Sha256,
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
#[ignore = "manual 1 GiB local SQLite restart/resume proof; no remote transport claim"]
fn resumable_one_gib_archive_restarts_and_restores_in_bounded_ranges() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let total = 1024_u64 * 1024 * 1024;
    let chunk = vec![0xa3; CHUNK_BYTES];
    let chunks = total / CHUNK_BYTES as u64;
    let mut expected = DigestWriter::default();
    for _ in 0..chunks {
        expected.write_all(&chunk).unwrap();
    }
    let expected_hash: [u8; 32] = expected.hash.finalize().into();
    let mut store = PrivateStorageStore::create(&root, limits(total)).unwrap();
    let id = store.reserve(total, expected_hash, NOW + 600, NOW).unwrap();
    let chunk_hash = hash(&chunk);
    for ordinal in 0..chunks / 2 {
        store
            .append_chunk(id, ordinal, chunk_hash, &chunk, NOW)
            .unwrap();
    }
    drop(store);
    let mut store = PrivateStorageStore::open_existing(&root).unwrap();
    let progress = store.upload_progress(id, NOW + 1).unwrap();
    assert_eq!(progress.received_bytes, total / 2);
    assert_eq!(progress.next_chunk, chunks / 2);
    assert!(!progress.archive.committed);
    assert!(matches!(
        store.read_range(id, 0, 1, &mut io::sink(), NOW + 1),
        Err(StorageError::NotCommitted)
    ));
    store
        .append_chunk(id, chunks / 2 - 1, chunk_hash, &chunk, NOW + 1)
        .unwrap();
    for ordinal in chunks / 2..chunks {
        store
            .append_chunk(id, ordinal, chunk_hash, &chunk, NOW + 1)
            .unwrap();
    }
    store.finalize(id, NOW + 1).unwrap();
    drop(store);
    let store = PrivateStorageStore::open_existing(&root).unwrap();
    for _ in 0..2 {
        let mut restored = DigestWriter::default();
        for first in (0..chunks).step_by(MAX_RANGE_CHUNKS as usize) {
            store
                .read_range(id, first, MAX_RANGE_CHUNKS, &mut restored, NOW + 2)
                .unwrap();
        }
        assert_eq!(restored.bytes, total);
        assert_eq!(<[u8; 32]>::from(restored.hash.finalize()), expected_hash);
    }
    assert_eq!(store.usage().unwrap().committed_bytes, total);
}
