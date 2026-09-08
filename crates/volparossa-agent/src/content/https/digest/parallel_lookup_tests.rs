//! Real digest selector exchanges gated until all three requests arrive, no host sockets.

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
        // No provider can answer until all actual client selector streams wrote data.
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
    let lookups: Vec<std::pin::Pin<Box<dyn Future<Output = usize>>>> = vec![
        Box::pin(async { 17 }),
        Box::pin(hanging),
        Box::pin(async { 19 }),
    ];
    let results = lookup_many_until(lookups, Instant::now() + Duration::from_millis(20)).await;
    assert_eq!(
        results,
        [Some(17), None, Some(19)],
        "keep an already completed sibling"
    );
    assert!(
        dropped.load(Ordering::SeqCst),
        "timed-out flow owner cannot outlive fallback"
    );
}

async fn overlapping_requests() {
    let directory = tempfile::tempdir().unwrap();
    let providers = (0..3)
        .map(|index| provider(&directory.path().join(format!("p{index}")), 31 + index))
        .collect::<Vec<_>>();
    let expected = &providers[0].2;
    for (_, _, candidate) in &providers[1..] {
        assert_ne!(expected.manifest_id(), candidate.manifest_id());
        assert!(compatible_transport(expected, candidate));
    }
    let query = DigestQuery::new(*expected.object_sha256(), expected.length()).unwrap();
    let (clients, servers): (Vec<_>, Vec<_>) = (0..3).map(|_| duplex(1024)).unzip();
    let barrier = Barrier::new(3);
    let lookups = clients
        .into_iter()
        .map(|mut client| {
            let query = &query;
            async move {
                let result = lookup_publication(&mut client, query, TransferLimits::default())
                    .await
                    .unwrap();
                drop(client);
                result
            }
        })
        .collect();
    let queries = lookup_many_until(lookups, Instant::now() + Duration::from_secs(2));
    let services = servers
        .into_iter()
        .zip(&providers)
        .map(|(server, (registry, _, _))| gated_provider(server, registry, &barrier))
        .collect();
    let (results, services) = tokio::join!(
        queries,
        lookup_many_until(services, Instant::now() + Duration::from_secs(2))
    );
    assert!(services.iter().all(Option::is_some));
    assert_eq!(results.len(), 3);
    for (result, (_, signed, manifest)) in results.into_iter().zip(&providers) {
        let candidate = result
            .flatten()
            .expect("independently authenticated original index");
        assert_eq!(candidate.signed().encode(), signed.encode());
        assert_eq!(
            candidate.transport_manifest().manifest_id(),
            manifest.manifest_id()
        );
    }
}

struct DropProof(Arc<AtomicBool>);

impl Drop for DropProof {
    fn drop(&mut self) {
        self.0.store(true, Ordering::SeqCst);
    }
}
