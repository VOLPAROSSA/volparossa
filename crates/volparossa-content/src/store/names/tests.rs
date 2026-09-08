//! Explicit library-clock disk tests, not elapsed-time or network availability claims.

use std::{fs, os::unix::fs::PermissionsExt as _};

use ed25519_dalek::SigningKey;

use crate::{
    CacheLimits, ChunkStore, Error, Metadata, Publication, SignedManifest, Validity,
    private_message::PRIVATE_MESSAGE_CONTENT_TYPE, publish, reassemble,
};

const NOW: u64 = 1_000;
const SNAPSHOT: &str = ".volparossa-named-manifests-v1";

fn limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 1024 * 1024,
        max_entries: 8,
        min_free_bytes: 0,
    }
}

fn publication(
    store: &mut ChunkStore,
    signer: &SigningKey,
    name: &str,
    revision: u64,
    content_type: &str,
    payload: &[u8],
) -> SignedManifest {
    publish(
        &mut &*payload,
        Publication {
            metadata: Metadata {
                name: name.into(),
                revision,
                content_type: content_type.into(),
            },
            length: payload.len() as u64,
            validity: Validity {
                created: NOW,
                expires: NOW + 600,
            },
        },
        signer,
        store,
    )
    .unwrap()
}

#[test]
fn cached_named_manifest_reopens_exact_bytes_without_rollback_or_expiry_renewal() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("cache");
    let mut cache = ChunkStore::create(&root, limits()).unwrap();
    let signer = SigningKey::generate(&mut rand_core::OsRng);
    let trusted = signer.verifying_key();
    let original = publication(
        &mut cache,
        &signer,
        "site",
        1,
        "text/html",
        b"original site",
    );
    cache
        .remember_named_manifest(&original, &trusted, NOW)
        .unwrap();
    drop(cache);

    let mut cache = ChunkStore::open(&root, limits()).unwrap();
    let retained = cache
        .cached_named_manifest(trusted.as_bytes(), "site", 1, NOW + 1)
        .unwrap()
        .unwrap();
    assert_eq!(retained.encode(), original.encode());
    let checked = retained.verify(&trusted, NOW + 1).unwrap();
    let mut bytes = Vec::new();
    reassemble(&checked, &mut [&mut cache], NOW + 1, &mut bytes).unwrap();
    assert_eq!(bytes, b"original site");
    assert!(
        cache
            .cached_named_manifest(trusted.as_bytes(), "other", 0, NOW)
            .unwrap()
            .is_none()
    );
    assert!(matches!(
        cache.cached_named_manifest(trusted.as_bytes(), "site", 2, NOW),
        Err(Error::NameRollback)
    ));

    let mut source = ChunkStore::create(&directory.path().join("source"), limits()).unwrap();
    let higher = publication(&mut source, &signer, "site", 2, "text/html", b"new site");
    cache
        .observe_name_revision(&higher.verify(&trusted, NOW).unwrap(), NOW)
        .unwrap();
    drop(cache); // Simulate a complete floor write followed by no snapshot/chunk admission.
    let mut cache = ChunkStore::open(&root, limits()).unwrap();
    assert!(matches!(
        cache.cached_named_manifest(trusted.as_bytes(), "site", 0, NOW),
        Err(Error::NameRollback)
    ));
    assert!(matches!(
        cache.remember_named_manifest(&original, &trusted, NOW),
        Err(Error::NameRollback)
    ));
    let conflict = publication(&mut source, &signer, "site", 2, "text/html", b"new site");
    assert!(matches!(
        cache.remember_named_manifest(&conflict, &trusted, NOW),
        Err(Error::NameConflict)
    ));
    drop(cache);
    let mut cache = ChunkStore::open(&root, limits()).unwrap();
    assert!(matches!(
        cache.cached_named_manifest(trusted.as_bytes(), "site", 0, NOW),
        Err(Error::NameConflict)
    ));

    let newest = publication(&mut source, &signer, "site", 3, "text/html", b"newest site");
    cache
        .remember_named_manifest(&newest, &trusted, NOW)
        .unwrap();
    drop(cache);
    let mut cache = ChunkStore::open(&root, limits()).unwrap();
    let retained = cache
        .cached_named_manifest(trusted.as_bytes(), "site", 0, NOW + 599)
        .unwrap()
        .unwrap();
    assert_eq!(retained.encode(), newest.encode());
    assert!(matches!(
        reassemble(
            &retained.verify(&trusted, NOW).unwrap(),
            &mut [&mut cache],
            NOW,
            &mut std::io::sink()
        ),
        Err(Error::MissingChunk(_))
    ));
    assert!(matches!(
        cache.cached_named_manifest(trusted.as_bytes(), "site", 0, NOW + 600),
        Err(Error::Expired)
    ));
    assert_eq!(
        cache
            .name_revision_floor(trusted.as_bytes(), "site")
            .unwrap()
            .unwrap()
            .revision(),
        3
    );
}

#[test]
fn cached_named_manifests_are_public_only_owned_private_and_bounded() {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("cache");
    let mut cache = ChunkStore::create(&root, limits()).unwrap();
    let signer = SigningKey::generate(&mut rand_core::OsRng);
    let trusted = signer.verifying_key();
    let private = publication(
        &mut cache,
        &signer,
        "private",
        1,
        PRIVATE_MESSAGE_CONTENT_TYPE,
        b"opaque",
    );
    assert!(matches!(
        cache.remember_named_manifest(&private, &trusted, NOW),
        Err(Error::InvalidManifest)
    ));
    assert!(
        cache
            .name_revision_floor(trusted.as_bytes(), "private")
            .unwrap()
            .is_none()
    );
    let empty = publication(&mut cache, &signer, "empty", 1, "text/plain", b"");
    let wrong = SigningKey::generate(&mut rand_core::OsRng).verifying_key();
    assert!(matches!(
        cache.remember_named_manifest(&empty, &wrong, NOW),
        Err(Error::WrongPublisher)
    ));
    cache
        .remember_named_manifest(&empty, &trusted, NOW)
        .unwrap();
    for index in 1..super::MAX_PINS {
        let envelope = publication(
            &mut cache,
            &signer,
            &format!("name-{index:02}"),
            1,
            "text/plain",
            b"",
        );
        cache
            .remember_named_manifest(&envelope, &trusted, NOW)
            .unwrap();
    }
    let overflow = publication(&mut cache, &signer, "overflow", 1, "text/plain", b"");
    assert!(matches!(
        cache.remember_named_manifest(&overflow, &trusted, NOW),
        Err(Error::Limit(_))
    ));
    assert!(
        cache
            .name_revision_floor(trusted.as_bytes(), "overflow")
            .unwrap()
            .is_none()
    );
    assert_eq!(
        fs::metadata(root.join(SNAPSHOT))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    drop(cache);
    let mut cache = ChunkStore::open(&root, limits()).unwrap();
    let retained = cache
        .cached_named_manifest(trusted.as_bytes(), "empty", 0, NOW)
        .unwrap()
        .unwrap();
    let checked = retained.verify(&trusted, NOW).unwrap();
    assert_eq!(
        reassemble(&checked, &mut [&mut cache], NOW, &mut std::io::sink()).unwrap(),
        0
    );
    drop(cache);

    let foreign = directory.path().join("foreign");
    drop(ChunkStore::create(&foreign, limits()).unwrap());
    fs::copy(root.join(SNAPSHOT), foreign.join(SNAPSHOT)).unwrap();
    assert!(matches!(
        ChunkStore::open(&foreign, limits()),
        Err(Error::InvalidStore)
    ));
    fs::write(
        root.join(".volparossa-named-manifests-next-v1"),
        b"interrupted",
    )
    .unwrap();
    assert!(matches!(
        ChunkStore::open(&root, limits()),
        Err(Error::InvalidStore)
    ));
}
