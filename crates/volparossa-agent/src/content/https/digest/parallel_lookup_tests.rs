//! Real digest selector exchanges gated until both client requests have arrived, no host sockets.

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use ed25519_dalek::SigningKey;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream, copy_bidirectional, duplex},
    sync::Barrier,
};
use volparossa_content::provider::{PublicationRegistry, serve_publication};
use volparossa_content::{CacheLimits, Metadata, Publication, Validity, publish};

use super::*;

fn provider(root: &Path, seed: u8) -> (PublicationRegistry, SignedManifest, VerifiedManifest) {
    let limits = CacheLimits {
        max_bytes: 1024,
        max_entries: 2,
        min_free_bytes: 0,
    };
    let mut store = ChunkStore::create(root, limits).unwrap();
    let key = SigningKey::from_bytes(&[seed; 32]);
    let bytes = b"one shared object, independent original transport indexes";
    let signed = publish(
        &mut bytes.as_slice(),
        Publication {
            metadata: Metadata {
                name: format!("original-{seed}"),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length: bytes.len() as u64,
            validity: Validity {
                created: now(),
                expires: now() + 60,
            },
        },
        &key,
        &mut store,
    )
    .unwrap();
    let verified = signed.verify(&key.verifying_key(), now()).unwrap();
    drop(store);
    let mut registry = PublicationRegistry::new();
    registry
        .register_signed(
            signed.clone(),
            &key.verifying_key(),
            root.to_path_buf(),
            limits,
            now(),
        )
        .unwrap();
    (registry, signed, verified)
}

async fn gated_provider(
    mut ingress: DuplexStream,
    registry: &PublicationRegistry,
    barrier: &Barrier,
) {
    let (mut forward, mut server) = duplex(1024);
    let forwarding = async {
        let mut prefix = [0_u8; 128];
        let count = ingress.read(&mut prefix).await.unwrap();
        assert!(count > 0, "actual digest request arrived");
        barrier.wait().await;
        // Neither provider can answer until both actual client selector streams wrote data.
        forward.write_all(&prefix[..count]).await.unwrap();
        copy_bidirectional(&mut ingress, &mut forward)
            .await
            .unwrap();
    };
    let serving = async {
        let result = serve_publication(&mut server, registry, TransferLimits::default()).await;
        drop(server);
        let progress = result.unwrap();
        assert_eq!(progress.bytes, 0, "index lookup carries no object payload");
    };
    tokio::join!(forwarding, serving);
}

#[tokio::test]
async fn digest_index_lookups_overlap_keep_provider_order_and_drop_timed_out_sibling() {
    tokio::time::timeout(Duration::from_secs(5), overlapping_requests())
        .await
        .unwrap();
    let dropped = Arc::new(AtomicBool::new(false));
    let observation = Arc::clone(&dropped);
    let hanging = async move {
        let _guard = DropProof(observation);
        std::future::pending::<usize>().await
    };
    let results = lookup_pair_until(
        async { 17_usize },
        hanging,
        Instant::now() + Duration::from_millis(20),
    )
    .await;
    assert_eq!(
        results,
        [Some(17), None],
        "keep an already completed sibling"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "timed-out flow owner cannot outlive fallback"
    );
}

async fn overlapping_requests() {
    let directory = tempfile::tempdir().unwrap();
    let (registry_a, signed_a, manifest_a) = provider(&directory.path().join("a"), 31);
    let (registry_b, signed_b, manifest_b) = provider(&directory.path().join("b"), 32);
    assert_ne!(manifest_a.manifest_id(), manifest_b.manifest_id());
    assert!(compatible_transport(&manifest_a, &manifest_b));
    let query = DigestQuery::new(*manifest_a.object_sha256(), manifest_a.length()).unwrap();
    let (mut client_a, server_a) = duplex(1024);
    let (mut client_b, server_b) = duplex(1024);
    let barrier = Barrier::new(2);
    let queries = lookup_pair_until(
        async {
            let result = lookup_publication(&mut client_a, &query, TransferLimits::default())
                .await
                .unwrap();
            drop(client_a);
            result
        },
        async {
            let result = lookup_publication(&mut client_b, &query, TransferLimits::default())
                .await
                .unwrap();
            drop(client_b);
            result
        },
        Instant::now() + Duration::from_secs(2),
    );
    let (results, (), ()) = tokio::join!(
        queries,
        gated_provider(server_a, &registry_a, &barrier),
        gated_provider(server_b, &registry_b, &barrier)
    );
    let [Some(Some(first)), Some(Some(second))] = results else {
        panic!("both independently authenticated original indexes");
    };
    assert_eq!(first.signed().encode(), signed_a.encode());
    assert_eq!(second.signed().encode(), signed_b.encode());
    assert_eq!(
        first.transport_manifest().manifest_id(),
        manifest_a.manifest_id()
    );
    assert_eq!(
        second.transport_manifest().manifest_id(),
        manifest_b.manifest_id()
    );
}

struct DropProof(Arc<AtomicBool>);

impl Drop for DropProof {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
