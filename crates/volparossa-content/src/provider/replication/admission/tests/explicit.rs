//! Complete foreground admission, not a partial-cache publication acknowledgment.

use super::*;

#[test]
fn explicit_publication_restores_complete_original_object_and_empty_publication() {
    for bytes in [
        [11_u8, 29, 11, 71]
            .into_iter()
            .flat_map(|byte| vec![byte; CHUNK_BYTES])
            .collect::<Vec<_>>(),
        Vec::new(),
    ] {
        let directory = tempfile::tempdir().unwrap();
        let key = SigningKey::generate(&mut rand_core::OsRng);
        let mut source = ChunkStore::create(&directory.path().join("source"), limits(8)).unwrap();
        let root = directory.path().join("configured-cache");
        let mut destination = ChunkStore::create(&root, limits(8)).unwrap();
        let signed = publication(&mut source, &key, &bytes, "application/octet-stream");
        let manifest = signed.verify(&key.verifying_key(), AT).unwrap();
        let replica =
            admit_public_publication(&signed, &manifest, &mut source, &mut destination, AT)
                .unwrap();
        assert_eq!(replica.signed_manifest().encode(), signed.encode());
        assert_eq!(replica.validity(), manifest.validity());
        assert_eq!(
            replica.chunk_ids().len(),
            if bytes.is_empty() { 0 } else { 3 }
        );
        let usage = destination.usage();
        let repeated =
            admit_public_publication(&signed, &manifest, &mut source, &mut destination, AT + 1)
                .unwrap();
        assert_eq!(
            repeated.chunk_ids().iter().collect::<BTreeSet<_>>(),
            replica.chunk_ids().iter().collect::<BTreeSet<_>>()
        );
        assert_eq!(
            destination.usage(),
            usage,
            "idempotent admission adds no payload"
        );
        drop(destination);
        let mut reopened = ChunkStore::open(&root, limits(8)).unwrap();
        let restored = restore_public_replicas(&mut reopened, AT + 2).unwrap();
        assert_eq!(restored.len(), 1);
        assert_eq!(restored[0].signed_manifest().encode(), signed.encode());
        let mut output = Vec::new();
        crate::reassemble(&manifest, &mut [&mut reopened], AT + 2, &mut output).unwrap();
        assert_eq!(output, bytes);
        assert!(
            restore_public_replicas(&mut reopened, manifest.validity().expires)
                .unwrap()
                .is_empty()
        );
        drop(reopened);
        let mut registry = PublicationRegistry::new();
        registry.set_name_lookup(true);
        registry
            .register_replica(restored[0].clone(), root, limits(8), AT + 2)
            .unwrap();
        assert!(registry.contains(manifest.manifest_id()));
        assert!(registry.has_live_publications(AT + 2));
    }
}

#[test]
fn explicit_publication_never_acknowledges_quota_prefix_or_admits_private_content() {
    let mut fixture = Fixture::new();
    let result = admit_public_publication(
        &fixture.signed,
        &fixture.checked,
        &mut fixture.source,
        &mut fixture.destination,
        AT,
    );
    assert!(matches!(result, Err(ProviderError::Content(Error::Quota))));
    assert_eq!(
        fixture.destination.get(&fixture.foreground).unwrap(),
        Some(vec![91; 17])
    );
    let partial = restore_public_replicas(&mut fixture.destination, AT).unwrap();
    assert_eq!(partial.len(), 1);
    assert_eq!(partial[0].chunk_ids().len(), 2);
    let usage = fixture.destination.usage();
    let private = publication(
        &mut fixture.source,
        &fixture.key,
        b"ciphertext",
        PRIVATE_MESSAGE_CONTENT_TYPE,
    );
    let checked = private.verify(&fixture.key.verifying_key(), AT).unwrap();
    assert!(
        admit_public_publication(
            &private,
            &checked,
            &mut fixture.source,
            &mut fixture.destination,
            AT,
        )
        .is_err()
    );
    assert!(
        admit_public_publication(
            &fixture.signed,
            &fixture.checked,
            &mut fixture.source,
            &mut fixture.destination,
            fixture.checked.validity().expires,
        )
        .is_err()
    );
    assert_eq!(fixture.destination.usage(), usage);
    assert_eq!(
        restore_public_replicas(&mut fixture.destination, AT)
            .unwrap()
            .len(),
        1
    );
}
