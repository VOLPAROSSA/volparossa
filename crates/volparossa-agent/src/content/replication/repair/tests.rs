//! Real production runtime journal/credit/registration operations on owned disk and duplex
//! streams. Route setup, provider discovery and a fully offline node need the separate VM run.

use super::*;
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, Metadata, Publication, Validity,
    provider::{
        pull_publication,
        replication::{LocalReplicaLimits, admit_public_replica},
        serve_publication,
    },
    publish, reassemble,
    transfer::TransferLimits,
};
use volparossa_local_control::{ContentCacheLimits, ContentReplicationConfig};

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One real source-removal, partial-journal restore, repair and second-restart retrieval lifecycle"
)]
async fn restarted_runtime_repairs_exact_missing_public_chunks_and_serves_after_second_restart() {
    let directory = tempfile::tempdir().unwrap();
    let limits = CacheLimits {
        max_bytes: 4 * CHUNK_BYTES as u64,
        max_entries: 8,
        min_free_bytes: 0,
    };
    let original = tempfile::tempdir_in(directory.path()).unwrap();
    let mut source = ChunkStore::create(&original.path().join("publisher"), limits).unwrap();
    let key = ed25519_dalek::SigningKey::generate(&mut rand_core::OsRng);
    let payload = [17_u8, 59, 101]
        .into_iter()
        .flat_map(|byte| vec![byte; CHUNK_BYTES])
        .collect::<Vec<_>>();
    let at = now();
    let signed = publish(
        &mut payload.as_slice(),
        Publication {
            metadata: Metadata {
                name: "public-repair-runtime".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length: payload.len() as u64,
            validity: Validity {
                created: at,
                expires: at + 600,
            },
        },
        &key,
        &mut source,
    )
    .unwrap();
    let manifest = signed.verify(&key.verifying_key(), at).unwrap();
    drop(key); // No repair authorization is re-signed on behalf of the original publisher.
    let holder_root = directory.path().join("holder-a");
    drop(ChunkStore::create(&holder_root, limits).unwrap());
    let holder = PublicCustodyStore::open(holder_root.clone(), limits).unwrap();
    holder
        .admit(&signed, &manifest, &mut source, now())
        .unwrap();
    let root = directory.path().join("partial-b");
    let mut partial = ChunkStore::create(&root, limits).unwrap();
    let admitted = admit_public_replica(
        &signed,
        &manifest,
        &mut source,
        &mut partial,
        LocalReplicaLimits {
            max_chunks: 1,
            max_bytes: CHUNK_BYTES as u64,
        },
        now(),
    )
    .unwrap();
    assert_eq!(admitted.chunks, 1);
    drop(partial);
    drop(source);
    original.close().unwrap(); // Original bytes and their cache owner are really gone.
    let mut source_registry = PublicationRegistry::new();
    holder
        .register_complete(&mut source_registry, now())
        .unwrap();
    let config = ContentReplicationConfig {
        replica_cache: root.to_str().unwrap().into(),
        reuse_replica_cache: true,
        limits: Some(ContentCacheLimits {
            quota_bytes: limits.max_bytes,
            max_entries: u32::try_from(limits.max_entries).unwrap(),
            min_free_bytes: 0,
        }),
        max_bytes: 1024 * 1024,
        max_chunks: 4,
    };
    let mut registry = PublicationRegistry::new();
    registry.set_name_lookup(true);
    let runtime = ReplicationRuntime::create_public(config.clone(), &mut registry).unwrap();
    assert!(runtime.state.lock().await.contacts.is_empty()); // No remembered foreground peers.
    let target = runtime.repair_candidate().await.unwrap().unwrap();
    assert_eq!(target.chunk_ids().len(), 1);
    let (mut receiver, mut sender) = tokio::io::duplex(4096);
    let object_policy = volparossa_content::object_policy::ObjectPolicyGate::default();
    let (uptake, transmitted) = tokio::join!(
        runtime.repair_from_stream(&mut receiver, &target, &object_policy, || {
            std::future::ready(true)
        }),
        serve_publication(&mut sender, &source_registry, TransferLimits::default()),
    );
    assert_eq!(uptake.unwrap().chunks, 2);
    assert_eq!(transmitted.unwrap().chunks, 2);
    let registry = Mutex::new(registry);
    // A status/serving owner can hold the registry after real chunks and their
    // journal have committed. That is not a reason to lose completion forever.
    let registration_owner = registry.lock().await;
    assert!(matches!(
        runtime.finalize_pending(&registry).await,
        Err(CompletionError::Registry)
    ));
    assert!(runtime.state.lock().await.repair_pending.is_some());
    assert!(runtime.repair_candidate().await.unwrap().is_none());
    drop(registration_owner);
    assert_eq!(
        runtime.finalize_pending(&registry).await.unwrap(),
        Some(true)
    );
    // Verification itself does not consume pending state: production consumes it only
    // after publishing the completion event. A cancelled event therefore remains retryable.
    assert!(runtime.state.lock().await.repair_pending.is_some());
    assert_eq!(
        runtime.finalize_pending(&registry).await.unwrap(),
        Some(true)
    );
    let held = PublicCustodyStore::open(root.clone(), limits)
        .unwrap()
        .inspect_complete(manifest.manifest_id(), now())
        .unwrap()
        .unwrap();
    assert_eq!(held.validity(), manifest.validity());
    drop(runtime);
    drop(registry);
    drop(source_registry);
    drop(holder);
    // Only the new B registry is used for this final complete application retrieval.
    let mut restored = PublicationRegistry::new();
    restored.set_name_lookup(true);
    let _restarted = ReplicationRuntime::create_public(config, &mut restored).unwrap();
    let mut consumer =
        ChunkStore::create(&directory.path().join("fresh-consumer"), limits).unwrap();
    let (mut receiver, mut sender) = tokio::io::duplex(4096);
    let (uptake, transmitted) = tokio::join!(
        pull_publication(
            &mut receiver,
            &manifest,
            &mut consumer,
            TransferLimits::default()
        ),
        serve_publication(&mut sender, &restored, TransferLimits::default()),
    );
    assert_eq!(uptake.unwrap().bytes, payload.len() as u64);
    assert_eq!(transmitted.unwrap().chunks, 3);
    let mut output = Vec::new();
    reassemble(&manifest, &mut [&mut consumer], now(), &mut output).unwrap();
    assert_eq!(output, payload);
}
