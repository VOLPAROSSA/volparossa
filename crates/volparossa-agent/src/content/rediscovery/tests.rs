//! Deterministic snapshot changes around real signed manifests, stores and v1 chunk streams.
//! These are coordinator/stream tests, not a distributed discovery or protected-overlay proof.

use std::{
    collections::{BTreeMap, VecDeque},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    task::Poll,
};

use ed25519_dalek::SigningKey;
use tokio::{io::duplex, sync::Notify};
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, Metadata, Publication, Validity,
    provider::{
        ProviderEndpoint, PublicationRegistry, SignedProviderOffer, pull_publication_worker,
        serve_publication,
    },
    publish, reassemble,
    transfer::{TransferProgress, parallel::ParallelDownload},
};
use volparossa_discovery::ContentDiscoveryRequest;

use super::*;
use crate::content::now;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stall {
    None,
    Discovery,
    Transfer,
}

struct Held(Arc<AtomicUsize>);

impl Held {
    fn new(count: &Arc<AtomicUsize>) -> Self {
        count.fetch_add(1, Ordering::SeqCst);
        Self(Arc::clone(count))
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::SeqCst);
    }
}

// Independent fault-injection switches exercise combinations, not one exclusive state.
#[allow(clippy::struct_excessive_bools)]
struct Fixture {
    _directory: tempfile::TempDir,
    manifest: VerifiedManifest,
    cache: ChunkStore,
    registries: BTreeMap<PeerId, PublicationRegistry>,
    providers: Vec<DiscoveredContentProvider>,
    recent: Vec<DiscoveredContentProvider>,
    snapshots: VecDeque<Result<Vec<DiscoveredContentProvider>, ContentDiscoveryError>>,
    requests: Vec<ContentDiscoveryRequest>,
    opened: Vec<PeerId>,
    deadlines: Vec<Instant>,
    bytes: Vec<u8>,
    invalid: bool,
    invalidate_discovery: bool,
    invalidate_transfer: bool,
    fail_transfer: bool,
    stall: Stall,
    held: Arc<AtomicUsize>,
    entered: Arc<Notify>,
}

fn fixture(provider_count: usize) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let limits = CacheLimits {
        max_bytes: (4 * CHUNK_BYTES) as u64,
        max_entries: 4,
        min_free_bytes: 0,
    };
    let mut publisher = ChunkStore::create(&directory.path().join("publisher"), limits).unwrap();
    let cache = ChunkStore::create(&directory.path().join("receiver"), limits).unwrap();
    let bytes = [31_u8, 47, 91]
        .into_iter()
        .flat_map(|value| vec![value; CHUNK_BYTES])
        .collect::<Vec<_>>();
    let signer = SigningKey::from_bytes(&[181; 32]);
    let validity = Validity {
        created: now(),
        expires: now() + 60,
    };
    let envelope = publish(
        &mut bytes.as_slice(),
        Publication {
            length: bytes.len() as u64,
            metadata: Metadata {
                name: "private-looking-object-not-in-discovery".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            validity,
        },
        &signer,
        &mut publisher,
    )
    .unwrap();
    let manifest = envelope.verify(&signer.verifying_key(), now()).unwrap();
    let mut providers = Vec::new();
    let mut registries = BTreeMap::new();
    for index in 0..provider_count {
        let key = SigningKey::from_bytes(&[u8::try_from(index + 1).unwrap(); 32]);
        let public =
            libp2p::identity::ed25519::PublicKey::try_from_bytes(key.verifying_key().as_bytes())
                .unwrap();
        let peer_id = libp2p::identity::PublicKey::from(public).to_peer_id();
        let offer = SignedProviderOffer::sign(
            &key,
            ProviderEndpoint::new("provider.volparossa.test", 18443).unwrap(),
            validity,
        )
        .unwrap()
        .verify(&key.verifying_key(), now())
        .unwrap();
        providers.push(DiscoveredContentProvider { peer_id, offer });
        let root = directory.path().join(format!("provider-{index}"));
        let mut store = ChunkStore::create(&root, limits).unwrap();
        for (chunk_index, chunk) in manifest.chunks().iter().enumerate() {
            // A has only the first chunk; B has the remaining chunks AND the first.
            // Exact transferred byte counts therefore detect refetching a verified chunk.
            if (index == 0 && chunk_index == 0) || index == 1 {
                store
                    .put_verified(*chunk.id(), &publisher.get(chunk.id()).unwrap().unwrap())
                    .unwrap();
            }
        }
        drop(store);
        let mut registry = PublicationRegistry::new();
        registry
            .register(manifest.clone(), root, limits, now())
            .unwrap();
        registries.insert(peer_id, registry);
    }
    Fixture {
        _directory: directory,
        manifest,
        cache,
        registries,
        providers,
        recent: Vec::new(),
        snapshots: VecDeque::new(),
        requests: Vec::new(),
        opened: Vec::new(),
        deadlines: Vec::new(),
        bytes,
        invalid: false,
        invalidate_discovery: false,
        invalidate_transfer: false,
        fail_transfer: false,
        stall: Stall::None,
        held: Arc::new(AtomicUsize::new(0)),
        entered: Arc::new(Notify::new()),
    }
}

impl Source for Fixture {
    fn complete(&mut self) -> Result<bool, ContentError> {
        complete(&self.manifest, &mut self.cache)
    }

    async fn validate(&mut self) -> Result<(), ContentError> {
        check_publication_time(&self.manifest)?;
        if self.invalid {
            Err(ContentError::Policy)
        } else {
            Ok(())
        }
    }

    async fn recent(&mut self, _budget: Duration) -> Vec<DiscoveredContentProvider> {
        std::mem::take(&mut self.recent)
    }

    async fn discover(
        &mut self,
        maximum: usize,
    ) -> Result<Vec<DiscoveredContentProvider>, ContentDiscoveryError> {
        self.requests
            .push(ContentDiscoveryRequest::new(maximum).unwrap());
        if self.stall == Stall::Discovery {
            let _held = Held::new(&self.held);
            self.entered.notify_one();
            std::future::pending::<()>().await;
        }
        self.invalid |= self.invalidate_discovery;
        self.snapshots.pop_front().unwrap_or(Ok(Vec::new()))
    }

    async fn transfer(
        &mut self,
        providers: Vec<DiscoveredContentProvider>,
        deadline: Instant,
    ) -> Result<(Vec<String>, u64), ContentError> {
        self.deadlines.push(deadline);
        self.opened
            .extend(providers.iter().map(|provider| provider.peer_id));
        if self.fail_transfer {
            return Err(ContentError::Invalid);
        }
        let limits = TransferLimits {
            session_timeout: deadline.saturating_duration_since(Instant::now()),
            exchange_timeout: Duration::from_secs(2),
            max_requests: 3,
            max_bytes: self.bytes.len() as u64,
        };
        let (download, workers) = ParallelDownload::new_adaptive(
            &self.manifest,
            providers.len(),
            &mut self.cache,
            limits,
            providers.len(),
        )
        .unwrap();
        let mut progress = vec![TransferProgress::default(); providers.len()];
        let mut streams = workers
            .into_iter()
            .zip(&providers)
            .map(|(mut worker, provider)| {
                let registry = &self.registries[&provider.peer_id];
                let stalled = self.stall == Stall::Transfer;
                let held = &self.held;
                let entered = &self.entered;
                // Owned futures, real selector/chunk protocol and real cache writer. No tasks
                // outlive the coordinator when the requester cancels or its deadline expires.
                Some(Box::pin(async move {
                    let _held = Held::new(held);
                    let (mut client, mut server) = duplex(4096);
                    let serve = async {
                        if stalled {
                            entered.notify_one();
                            std::future::pending::<()>().await;
                        }
                        serve_publication(&mut server, registry, limits).await
                    };
                    let (received, sent) =
                        tokio::join!(pull_publication_worker(&mut client, &mut worker), serve);
                    received.unwrap();
                    sent.unwrap();
                }))
            })
            .collect::<Vec<_>>();
        let joined = async {
            let all_streams = std::future::poll_fn(|cx| {
                for slot in &mut streams {
                    if slot
                        .as_mut()
                        .is_some_and(|work| work.as_mut().poll(cx).is_ready())
                    {
                        *slot = None;
                    }
                }
                if streams.iter().all(Option::is_none) {
                    Poll::Ready(())
                } else {
                    Poll::Pending
                }
            });
            let (written, ()) = tokio::join!(
                download.run_with_allowance(&mut self.cache, &mut progress, || providers.len()),
                all_streams
            );
            written.map_err(|_| ContentError::Unavailable)
        };
        timeout_at(deadline, joined)
            .await
            .map_err(|_| ContentError::Unavailable)??;
        self.invalid |= self.invalidate_transfer;
        let bytes = progress.iter().map(|p| p.bytes).sum();
        let used = providers
            .iter()
            .zip(progress)
            .filter(|(_, p)| p.bytes > 0)
            .map(|(provider, _)| provider.peer_id.to_string())
            .collect();
        Ok((used, bytes))
    }
}

fn deadline() -> Instant {
    Instant::now() + Duration::from_secs(8)
}

#[tokio::test]
async fn late_complementary_snapshot_reconstructs_without_refetching_or_renewing_deadline() {
    let mut source = fixture(2);
    let first = source.providers[0].clone();
    let second = source.providers[1].clone();
    source.snapshots.extend([
        Ok(vec![first.clone()]),
        Ok(vec![first.clone(), second.clone()]),
    ]);
    let until = deadline();
    let (providers, bytes) = run(&mut source, until).await.unwrap();
    assert_eq!(
        bytes,
        source.bytes.len() as u64,
        "each verified chunk counted only once"
    );
    assert_eq!(providers.len(), 2);
    assert_eq!(source.opened, [first.peer_id, second.peer_id]);
    assert_eq!(source.deadlines, [until, until]);
    assert_eq!(source.requests.len(), 2);
    let mut output = Vec::new();
    assert_eq!(
        reassemble(
            &source.manifest,
            &mut [&mut source.cache],
            now(),
            &mut output
        )
        .unwrap(),
        source.bytes.len() as u64
    );
    assert_eq!(output, source.bytes);
    let (providers, bytes) = run(&mut source, until).await.unwrap();
    assert!(providers.is_empty());
    assert_eq!(bytes, 0);
    assert_eq!(source.requests.len(), 2, "complete cache needs no network");
    assert_eq!(source.opened.len(), 2);
}

#[tokio::test]
async fn complete_single_provider_needs_neither_a_second_provider_nor_rediscovery() {
    let mut source = fixture(2);
    source
        .snapshots
        .push_back(Ok(vec![source.providers[1].clone()]));
    let (providers, bytes) = run(&mut source, deadline()).await.unwrap();
    assert_eq!(providers.len(), 1);
    assert_eq!(bytes, source.bytes.len() as u64);
    assert_eq!(source.requests.len(), 1);
    assert_eq!(source.opened.len(), 1);
}

#[tokio::test]
async fn duplicate_recent_hints_and_snapshots_do_not_repeat_provider_work() {
    let mut source = fixture(2);
    let first = source.providers[0].clone();
    let second = source.providers[1].clone();
    source.recent = vec![first.clone(), first.clone()];
    source.snapshots.extend([
        Ok(vec![first.clone(), first.clone()]),
        Ok(vec![first.clone(), second.clone(), second.clone()]),
    ]);
    let (_, bytes) = run(&mut source, deadline()).await.unwrap();
    assert_eq!(bytes, source.bytes.len() as u64);
    assert_eq!(source.opened, [first.peer_id, second.peer_id]);
}

#[tokio::test]
async fn repeated_same_and_empty_snapshots_are_bounded_and_not_full_object_success() {
    for duplicate in [false, true] {
        let mut source = fixture(2);
        for _ in 0..=MAX_ROUNDS {
            source.snapshots.push_back(Ok(if duplicate {
                vec![source.providers[0].clone()]
            } else {
                Vec::new()
            }));
        }
        let (_, bytes) = run(&mut source, deadline()).await.unwrap();
        assert_eq!(source.requests.len(), MAX_ROUNDS);
        assert_eq!(source.opened.len(), usize::from(duplicate));
        assert_eq!(bytes, if duplicate { CHUNK_BYTES as u64 } else { 0 });
        assert!(!source.complete().unwrap());
        assert!(
            reassemble(
                &source.manifest,
                &mut [&mut source.cache],
                now(),
                &mut std::io::sink()
            )
            .is_err()
        );
        for request in &source.requests {
            assert_eq!(request.maximum_offers(), MAX_PROVIDERS);
            assert!(request.target_peers().unwrap().is_empty());
            assert_eq!(request.nonce().len(), 32);
        }
        assert!(
            source
                .requests
                .windows(2)
                .all(|r| r[0].nonce() != r[1].nonce())
        );
    }
}

#[tokio::test]
async fn total_unique_attempts_include_hints_and_cannot_exceed_one_offer_batch() {
    let mut source = fixture(MAX_PROVIDERS + 3);
    // Empty providers only, so completion cannot mask the total-attempt bound.
    source.recent = source.providers[2..4].to_vec();
    source
        .snapshots
        .push_back(Ok(source.providers[3..MAX_PROVIDERS + 3].to_vec()));
    let (_, bytes) = run(&mut source, deadline()).await.unwrap();
    assert_eq!(bytes, 0);
    assert_eq!(source.opened.len(), MAX_PROVIDERS);
    assert_eq!(
        source.opened.iter().copied().collect::<BTreeSet<_>>().len(),
        MAX_PROVIDERS
    );
    assert_eq!(source.requests.len(), 1);
}

#[tokio::test]
async fn authority_and_discovery_errors_remain_fatal_or_preserve_only_verified_partial_progress() {
    for error in [
        ContentDiscoveryError::Invalid,
        ContentDiscoveryError::Invalidated,
        ContentDiscoveryError::Busy,
        ContentDiscoveryError::Closed,
        ContentDiscoveryError::Timeout,
        ContentDiscoveryError::Unavailable,
    ] {
        for partial in [false, true] {
            let mut source = fixture(2);
            if partial {
                source.recent.push(source.providers[0].clone());
            }
            source.snapshots.push_back(Err(error));
            let result = run(&mut source, deadline()).await;
            match error {
                ContentDiscoveryError::Invalid => {
                    assert!(matches!(result, Err(ContentError::Invalid)));
                }
                ContentDiscoveryError::Invalidated => {
                    assert!(matches!(result, Err(ContentError::Policy)));
                }
                _ if partial => assert_eq!(result.unwrap().1, CHUNK_BYTES as u64),
                _ => assert!(matches!(result, Err(ContentError::Unavailable))),
            }
            assert_eq!(source.requests.len(), 1);
            assert_eq!(
                source
                    .cache
                    .get(source.manifest.chunks()[0].id())
                    .unwrap()
                    .is_some(),
                partial
            );
        }
    }
    for after_transfer in [false, true] {
        let mut source = fixture(2);
        source.invalidate_discovery = !after_transfer;
        source.invalidate_transfer = after_transfer;
        source.snapshots.push_back(Ok(source.providers.clone()));
        assert!(matches!(
            run(&mut source, deadline()).await,
            Err(ContentError::Policy)
        ));
        assert_eq!(source.opened.len(), if after_transfer { 2 } else { 0 });
    }
    let mut source = fixture(2);
    source.fail_transfer = true;
    source.snapshots.push_back(Ok(source.providers.clone()));
    assert!(matches!(
        run(&mut source, deadline()).await,
        Err(ContentError::Invalid)
    ));
}

#[tokio::test]
async fn deadlines_and_requester_cancellation_drop_owned_discovery_and_stream_futures() {
    for stall in [Stall::Discovery, Stall::Transfer] {
        let mut source = fixture(2);
        source.stall = stall;
        source.snapshots.push_back(Ok(source.providers.clone()));
        let held = Arc::clone(&source.held);
        let entered = Arc::clone(&source.entered);
        {
            let work = run(&mut source, deadline());
            tokio::pin!(work);
            tokio::select! { result = &mut work => panic!("must remain pending: {result:?}"), () = entered.notified() => {} }
            assert!(held.load(Ordering::SeqCst) > 0);
        }
        assert_eq!(
            held.load(Ordering::SeqCst),
            0,
            "requester drop owns cancellation"
        );
        let mut source = fixture(2);
        source.stall = stall;
        source.snapshots.push_back(Ok(source.providers.clone()));
        let result = run(&mut source, Instant::now() + Duration::from_millis(30)).await;
        assert!(matches!(result, Err(ContentError::Unavailable)));
        assert_eq!(source.held.load(Ordering::SeqCst), 0);
        assert_eq!(source.requests.len(), 1);
    }
    let mut source = fixture(2);
    assert!(matches!(
        run(&mut source, Instant::now()).await,
        Err(ContentError::Unavailable)
    ));
    assert!(source.requests.is_empty());
    assert!(source.opened.is_empty());
}
