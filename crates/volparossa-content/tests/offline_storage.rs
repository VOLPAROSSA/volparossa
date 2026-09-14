//! Actual disk-store checks; these do not stand in for peer discovery or network tests.

use std::fs;

use ed25519_dalek::SigningKey;
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, CacheUsage, ChunkId, ChunkStore, Error, Metadata, Publication,
    SignedManifest, Validity, publish, reassemble_to_file,
};

#[test]
fn offline_publisher_reconstructs_exact_object_from_two_independent_disk_stores() {
    let root = tempfile::tempdir().expect("test root");
    let origin = tempfile::tempdir_in(root.path()).expect("publisher root");
    let mut publisher_store =
        ChunkStore::create(&origin.path().join("chunks"), limits(4)).expect("publisher store");
    let mut first = ChunkStore::create(&root.path().join("first"), limits(2)).expect("first store");
    let mut second =
        ChunkStore::create(&root.path().join("second"), limits(2)).expect("second store");
    let publisher = SigningKey::generate(&mut rand_core::OsRng);
    let trusted_publisher = publisher.verifying_key();
    let input = object();
    let expected_hash = ChunkId::digest(&input);
    let expected_length = input.len() as u64;
    let wire = publish(
        &mut input.as_slice(),
        publication(expected_length),
        &publisher,
        &mut publisher_store,
    )
    .expect("native publication")
    .encode();
    let manifest = SignedManifest::decode(&wire)
        .expect("bounded canonical manifest")
        .verify(&trusted_publisher, 101)
        .expect("pre-established publisher authority");
    for (index, chunk) in manifest.chunks().iter().enumerate() {
        let bytes = publisher_store
            .get(chunk.id())
            .expect("read origin")
            .expect("chunk");
        let target = if index % 2 == 0 {
            &mut first
        } else {
            &mut second
        };
        target
            .put_verified(*chunk.id(), &bytes)
            .expect("copy authentic bytes");
    }
    assert_eq!(first.usage().entries, 2);
    assert_eq!(second.usage().entries, 1);
    drop(publisher_store);
    drop(publisher);
    drop(input);
    origin.close().expect("publisher disk goes offline");

    let destination = root.path().join("reconstructed.bin");
    let verified = SignedManifest::decode(&wire)
        .expect("transported manifest bytes")
        .verify(&trusted_publisher, 110)
        .expect("offline signature verification");
    assert_eq!(
        reassemble_to_file(&verified, &mut [&mut first, &mut second], 110, &destination)
            .expect("offline multi-store reconstruction"),
        expected_length
    );
    assert_eq!(
        ChunkId::digest(&fs::read(destination).expect("output")),
        expected_hash
    );
    assert_eq!(verified.metadata().name, "explicit-native-publication");
    assert_eq!(verified.metadata().revision, 7);
    assert_eq!(verified.publisher(), trusted_publisher.as_bytes());
}

#[test]
fn missing_corrupt_and_expired_content_never_publishes_a_complete_output_file() {
    let root = tempfile::tempdir().expect("root");
    let cache_path = root.path().join("chunks");
    let mut store = ChunkStore::create(&cache_path, limits(4)).expect("store");
    let input = object();
    let publisher = SigningKey::generate(&mut rand_core::OsRng);
    let signed = publish(
        &mut input.as_slice(),
        publication(input.len() as u64),
        &publisher,
        &mut store,
    )
    .expect("publish");
    let verified = signed
        .verify(&publisher.verifying_key(), 101)
        .expect("verify");
    let last = verified.chunks().last().expect("last chunk");
    let valid_last = store.get(last.id()).expect("read").expect("last bytes");
    fs::remove_file(cache_path.join(last.id().to_string())).expect("remove replica");
    let destination = root.path().join("missing.bin");
    assert!(matches!(
        reassemble_to_file(&verified, &mut [&mut store], 101, &destination),
        Err(Error::MissingChunk(_))
    ));
    assert!(!destination.exists());
    store
        .put_verified(*last.id(), &valid_last)
        .expect("repair missing replica");
    let mut corrupt_last = valid_last.clone();
    corrupt_last[0] ^= 1;
    fs::write(cache_path.join(last.id().to_string()), &corrupt_last)
        .expect("corrupt same-size file");
    let destination = root.path().join("corrupt.bin");
    assert!(matches!(
        reassemble_to_file(&verified, &mut [&mut store], 101, &destination),
        Err(Error::Integrity(_))
    ));
    assert!(!destination.exists());
    let destination = root.path().join("expired.bin");
    assert!(matches!(
        reassemble_to_file(&verified, &mut [&mut store], 200, &destination),
        Err(Error::Expired)
    ));
    assert!(!destination.exists());
    assert!(matches!(
        store.put_verified(*last.id(), &corrupt_last),
        Err(Error::Integrity(_))
    ));
}

#[test]
fn byte_entry_and_free_space_quotas_evict_only_owned_lru_chunks() {
    let root = tempfile::tempdir().expect("root");
    let path = root.path().join("chunks");
    let mut store = ChunkStore::create(
        &path,
        CacheLimits {
            max_bytes: 6,
            max_entries: 2,
            min_free_bytes: 0,
        },
    )
    .expect("store");
    let first = store.put(b"abc").expect("first");
    let second = store.put(b"def").expect("second");
    assert_eq!(
        store.usage(),
        CacheUsage {
            bytes: 6,
            entries: 2
        }
    );
    store
        .get(&first)
        .expect("touch first")
        .expect("first remains");
    let third = store.put(b"ghi").expect("third evicts second");
    assert_eq!(store.get(&second).expect("absent evicted"), None);
    assert!(!path.join(second.to_string()).exists());
    assert!(store.get(&first).expect("first").is_some());
    assert!(store.get(&third).expect("third").is_some());
    assert!(matches!(store.put(b"1234567"), Err(Error::Quota)));
    assert!(matches!(store.put(b""), Err(Error::Limit(_))));
    assert!(matches!(
        store.put(&vec![0; CHUNK_BYTES + 1]),
        Err(Error::Limit(_))
    ));
    assert_eq!(
        store.usage(),
        CacheUsage {
            bytes: 6,
            entries: 2
        }
    );

    let mut tiny = ChunkStore::create(
        &root.path().join("tiny"),
        CacheLimits {
            max_bytes: 1_000,
            max_entries: 2,
            min_free_bytes: 0,
        },
    )
    .expect("tiny store");
    let evicted = tiny.put(b"a").expect("a");
    tiny.put(b"b").expect("b");
    tiny.put(b"c").expect("c");
    assert_eq!(
        tiny.usage(),
        CacheUsage {
            bytes: 2,
            entries: 2
        }
    );
    assert!(tiny.get(&evicted).expect("evicted tiny chunk").is_none());

    let floor = ChunkStore::create(
        &root.path().join("floor"),
        CacheLimits {
            max_bytes: 1_000,
            max_entries: 2,
            min_free_bytes: u64::MAX,
        },
    );
    assert!(matches!(floor, Err(Error::Quota)));

    let foreign = root.path().join("foreign");
    fs::create_dir(&foreign).expect("foreign directory");
    fs::write(foreign.join("keep-me"), b"user data").expect("foreign file");
    assert!(ChunkStore::create(&foreign, limits(1)).is_err());
    assert_eq!(
        fs::read(foreign.join("keep-me")).expect("unchanged user file"),
        b"user data"
    );
}

#[test]
fn publication_enforces_exact_size_capacity_and_empty_objects_without_overwriting_output() {
    let root = tempfile::tempdir().expect("root");
    let mut store = ChunkStore::create(&root.path().join("cache"), limits(1)).expect("store");
    let publisher = SigningKey::generate(&mut rand_core::OsRng);
    assert!(matches!(
        publish(&mut &b"long"[..], publication(3), &publisher, &mut store),
        Err(Error::Limit(_))
    ));
    assert!(matches!(
        publish(&mut &b"short"[..], publication(6), &publisher, &mut store),
        Err(Error::Io(_))
    ));
    assert!(matches!(
        publish(
            &mut &b""[..],
            publication(2 * CHUNK_BYTES as u64),
            &publisher,
            &mut store
        ),
        Err(Error::Quota)
    ));
    let signed = publish(&mut &b""[..], publication(0), &publisher, &mut store)
        .expect("empty native object");
    let manifest = signed
        .verify(&publisher.verifying_key(), 101)
        .expect("empty verified");
    assert!(manifest.chunks().is_empty());
    let destination = root.path().join("empty");
    reassemble_to_file(&manifest, &mut [&mut store], 101, &destination).expect("empty file");
    assert_eq!(fs::metadata(&destination).expect("file").len(), 0);
    fs::write(&destination, b"do not overwrite").expect("existing user output");
    assert!(reassemble_to_file(&manifest, &mut [&mut store], 101, &destination).is_err());
    assert_eq!(
        fs::read(destination).expect("preserved"),
        b"do not overwrite"
    );
}

fn object() -> Vec<u8> {
    let mut bytes = vec![0x31; CHUNK_BYTES];
    bytes.extend(vec![0xa4; CHUNK_BYTES]);
    bytes.extend(b"native publisher authenticated final piece");
    bytes
}

fn limits(chunks: usize) -> CacheLimits {
    CacheLimits {
        max_bytes: chunks as u64 * CHUNK_BYTES as u64,
        max_entries: chunks,
        min_free_bytes: 0,
    }
}

fn publication(length: u64) -> Publication {
    Publication {
        metadata: Metadata {
            name: "explicit-native-publication".into(),
            revision: 7,
            content_type: "application/octet-stream".into(),
        },
        length,
        validity: Validity {
            created: 100,
            expires: 200,
        },
    }
}
