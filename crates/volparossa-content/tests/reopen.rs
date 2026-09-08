//! Actual persisted-index and ownership checks, independent of network transport.

use std::fs;
use std::os::unix::fs::{DirBuilderExt, symlink};

use ed25519_dalek::SigningKey;
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, CacheUsage, ChunkId, ChunkStore, Error, Metadata, Publication,
    SignedManifest, Validity, publish, reassemble_to_file,
};

const OWNER: &str = ".volparossa-owner-v1";
const INDEX: &str = ".volparossa-index-v1";

#[test]
fn reopened_replicas_reconstruct_verified_object_after_all_original_handles_are_dropped() {
    let root = tempfile::tempdir().expect("test root");
    let origin = tempfile::tempdir_in(root.path()).expect("publisher directory");
    let mut source = ChunkStore::create(&origin.path().join("source"), limits()).expect("source");
    let first_path = root.path().join("replica-a");
    let second_path = root.path().join("replica-b");
    let mut first = ChunkStore::create(&first_path, limits()).expect("first store");
    let mut second = ChunkStore::create(&second_path, limits()).expect("second store");
    let publisher = SigningKey::generate(&mut rand_core::OsRng);
    let trusted_publisher = publisher.verifying_key();
    let mut input = vec![0x31; CHUNK_BYTES];
    input.extend(vec![0xa4; CHUNK_BYTES]);
    input.extend(b"persisted native publication");
    let expected_digest = ChunkId::digest(&input);
    let signed = publish(
        &mut input.as_slice(),
        Publication {
            metadata: Metadata {
                name: "restart-object".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length: input.len() as u64,
            validity: Validity {
                created: 100,
                expires: 200,
            },
        },
        &publisher,
        &mut source,
    )
    .expect("publication");
    let manifest = signed
        .verify(&trusted_publisher, 101)
        .expect("verified publication");
    for (index, chunk) in manifest.chunks().iter().enumerate() {
        let data = source.get(chunk.id()).expect("source read").expect("chunk");
        let target = if index % 2 == 0 {
            &mut first
        } else {
            &mut second
        };
        target
            .put_verified(*chunk.id(), &data)
            .expect("copy replica");
    }
    let wire = signed.encode();
    drop((source, first, second, publisher, input));
    origin.close().expect("publisher storage removed");

    let mut first = ChunkStore::open(&first_path, limits()).expect("reopen first index");
    let mut second = ChunkStore::open(&second_path, limits()).expect("reopen second index");
    assert_eq!(first.usage().entries, 2);
    assert_eq!(second.usage().entries, 1);
    let verified = SignedManifest::decode(&wire)
        .expect("manifest")
        .verify(&trusted_publisher, 110)
        .expect("publisher authority");
    let output = root.path().join("reconstructed.bin");
    reassemble_to_file(&verified, &mut [&mut first, &mut second], 110, &output)
        .expect("reopened reconstruction");
    assert_eq!(
        ChunkId::digest(&fs::read(output).expect("bytes")),
        expected_digest
    );
}

#[test]
fn reopen_enforces_new_quotas_exclusive_lock_and_persisted_eviction() {
    let root = tempfile::tempdir().expect("root");
    let cache = root.path().join("cache");
    let configured = CacheLimits {
        max_bytes: 6,
        max_entries: 2,
        min_free_bytes: 0,
    };
    let mut store = ChunkStore::create(&cache, configured).expect("store");
    let first = store.put(b"abc").expect("first");
    let second = store.put(b"def").expect("second");
    assert!(
        matches!(ChunkStore::open(&cache, configured), Err(Error::Io(error)) if error.kind() == std::io::ErrorKind::WouldBlock)
    );
    drop(store);
    let original_index = fs::read(cache.join(INDEX)).expect("index");
    for too_small in [
        CacheLimits {
            max_bytes: 5,
            ..configured
        },
        CacheLimits {
            max_entries: 1,
            ..configured
        },
        CacheLimits {
            min_free_bytes: u64::MAX,
            ..configured
        },
    ] {
        assert!(matches!(
            ChunkStore::open(&cache, too_small),
            Err(Error::Quota)
        ));
        assert_eq!(
            fs::read(cache.join(INDEX)).expect("unchanged index"),
            original_index
        );
    }
    let moved = root.path().join("renamed-cache");
    fs::rename(&cache, &moved).expect("move same owned directory");
    let mut reopened = ChunkStore::open(&moved, configured).expect("renamed store");
    assert_eq!(
        reopened.usage(),
        CacheUsage {
            bytes: 6,
            entries: 2
        }
    );
    let third = reopened.put(b"ghi").expect("evict persisted oldest");
    drop(reopened);
    let mut reopened = ChunkStore::open(&moved, configured).expect("reopen after eviction");
    assert!(reopened.get(&first).expect("first absent").is_none());
    assert_eq!(
        reopened.get(&second).expect("second read"),
        Some(b"def".to_vec())
    );
    assert_eq!(
        reopened.get(&third).expect("third read"),
        Some(b"ghi".to_vec())
    );
    assert_eq!(
        reopened.usage(),
        CacheUsage {
            bytes: 6,
            entries: 2
        }
    );
}

#[test]
fn foreign_directories_copied_markers_and_symlinks_are_never_adopted_or_cleaned() {
    let root = tempfile::tempdir().expect("root");
    let owned = root.path().join("owned");
    let mut store = ChunkStore::create(&owned, limits()).expect("owned cache");
    let id = store.put(b"native content").expect("chunk");
    drop(store);
    let foreign = root.path().join("foreign");
    fs::DirBuilder::new()
        .mode(0o700)
        .create(&foreign)
        .expect("foreign directory");
    fs::write(foreign.join("keep-me"), b"user data").expect("foreign file");
    assert!(ChunkStore::open(&foreign, limits()).is_err());
    for name in [OWNER.to_owned(), INDEX.to_owned(), id.to_string()] {
        fs::copy(owned.join(&name), foreign.join(&name)).expect("copied cache bytes");
    }
    assert!(matches!(
        ChunkStore::open(&foreign, limits()),
        Err(Error::InvalidStore)
    ));
    assert_eq!(
        fs::read(foreign.join("keep-me")).expect("preserved user file"),
        b"user data"
    );
    assert_eq!(
        fs::read(foreign.join(id.to_string())).expect("not deleted"),
        b"native content"
    );
    let alias = root.path().join("symlink-cache");
    symlink(&owned, &alias).expect("symlink");
    assert!(ChunkStore::open(&alias, limits()).is_err());
    let mut original = ChunkStore::open(&owned, limits()).expect("original still owned");
    assert_eq!(
        original.get(&id).expect("original read"),
        Some(b"native content".to_vec())
    );
}

#[test]
fn corrupt_index_truncated_chunk_and_interrupted_mutations_fail_without_cleanup() {
    let root = tempfile::tempdir().expect("root");
    let cache = root.path().join("cache");
    let mut store = ChunkStore::create(&cache, limits()).expect("store");
    let id = store.put(b"complete chunk").expect("chunk");
    drop(store);
    let valid_index = fs::read(cache.join(INDEX)).expect("index bytes");
    let mut corrupt_index = valid_index.clone();
    let last = corrupt_index.len() - 1;
    corrupt_index[last] ^= 1;
    fs::write(cache.join(INDEX), &corrupt_index).expect("corrupt index checksum");
    assert!(matches!(
        ChunkStore::open(&cache, limits()),
        Err(Error::InvalidStore)
    ));
    assert_eq!(
        fs::read(cache.join(INDEX)).expect("untouched corruption"),
        corrupt_index
    );
    fs::write(cache.join(INDEX), &valid_index).expect("restore test index");

    fs::write(cache.join(id.to_string()), b"short").expect("truncate chunk");
    assert!(
        matches!(ChunkStore::open(&cache, limits()), Err(Error::Integrity(chunk)) if chunk == id)
    );
    assert_eq!(
        fs::read(cache.join(id.to_string())).expect("not deleted"),
        b"short"
    );
    fs::write(cache.join(id.to_string()), b"complete chunk").expect("restore test chunk");

    let stage = cache.join(".volparossa-index-next-v1");
    fs::write(&stage, b"interrupted index write").expect("incomplete stage");
    assert!(matches!(
        ChunkStore::open(&cache, limits()),
        Err(Error::InvalidStore)
    ));
    assert_eq!(
        fs::read(&stage).expect("not swept"),
        b"interrupted index write"
    );
    fs::remove_file(&stage).expect("test removes its stage");
    fs::remove_file(cache.join(id.to_string())).expect("missing indexed chunk");
    assert!(ChunkStore::open(&cache, limits()).is_err());
    assert_eq!(
        fs::read(cache.join(INDEX)).expect("index preserved"),
        valid_index
    );
}

fn limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 4 * CHUNK_BYTES as u64,
        max_entries: 4,
        min_free_bytes: 0,
    }
}
