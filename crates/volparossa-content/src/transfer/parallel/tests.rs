//! Real production selector/chunk handlers over backpressured streams, not host networking.

mod adaptive;
mod transports;

use std::{
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tokio::{
    io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf},
    sync::Notify,
};

use super::{ChunkWorker, ParallelDownload, TransferError, TransferLimits, TransferProgress};
use crate::{
    CHUNK_BYTES, CacheLimits, ChunkStore, Metadata, Publication, Validity, VerifiedManifest,
    provider::{ProviderError, PublicationRegistry, pull_publication_worker, serve_publication},
    publish, reassemble,
};

#[derive(Clone, Copy)]
enum Mode {
    Slow,
    Disconnect,
    Missing,
    Reconnect,
}

struct Observation {
    written: AtomicUsize,
    blocked: AtomicBool,
    released: AtomicBool,
    changed: Notify,
    writer: Mutex<Option<Waker>>,
}

impl Observation {
    fn new() -> Arc<Self> {
        Arc::new(Self {
            written: AtomicUsize::new(0),
            blocked: AtomicBool::new(false),
            released: AtomicBool::new(false),
            changed: Notify::new(),
            writer: Mutex::new(None),
        })
    }
    fn release(&self) {
        self.released.store(true, Ordering::SeqCst);
        if let Some(writer) = self.writer.lock().unwrap().take() {
            writer.wake();
        }
    }
}

struct ObservedStream {
    inner: DuplexStream,
    observation: Arc<Observation>,
    mode: Option<Mode>,
}

impl AsyncRead for ObservedStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buffer)
    }
}

impl AsyncWrite for ObservedStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let total = self.observation.written.load(Ordering::SeqCst);
        let controlled = matches!(
            self.mode,
            Some(Mode::Slow | Mode::Disconnect | Mode::Reconnect)
        );
        if controlled && total >= 4096 {
            if !self.observation.released.load(Ordering::SeqCst) {
                *self.observation.writer.lock().unwrap() = Some(cx.waker().clone());
                self.observation.blocked.store(true, Ordering::SeqCst);
                self.observation.changed.notify_one();
                return Poll::Pending;
            }
            if matches!(self.mode, Some(Mode::Disconnect | Mode::Reconnect)) {
                return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
            }
        }
        let maximum = if controlled && total < 4096 {
            bytes.len().min(4096 - total)
        } else {
            bytes.len()
        };
        let written = match Pin::new(&mut self.inner).poll_write(cx, &bytes[..maximum]) {
            Poll::Ready(Ok(written)) => written,
            other => return other,
        };
        self.observation
            .written
            .fetch_add(written, Ordering::SeqCst);
        self.observation.changed.notify_one();
        Poll::Ready(Ok(written))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

struct Fixture {
    directory: tempfile::TempDir,
    manifest: VerifiedManifest,
    registries: [PublicationRegistry; 2],
    output: ChunkStore,
    original: Vec<u8>,
}

fn fixture(mode: Mode) -> Fixture {
    let directory = tempfile::tempdir().unwrap();
    let limits = CacheLimits {
        max_bytes: 8 * CHUNK_BYTES as u64,
        max_entries: 16,
        min_free_bytes: 0,
    };
    let mut original = Vec::new();
    for value in [1_u8, 2, 3, 4, 1] {
        original.extend(vec![value; CHUNK_BYTES]);
    }
    let first_path = directory.path().join("provider-a");
    let second_path = directory.path().join("provider-b");
    let mut first = ChunkStore::create(&first_path, limits).unwrap();
    let mut second = ChunkStore::create(&second_path, limits).unwrap();
    let publisher = SigningKey::generate(&mut OsRng);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let signed = publish(
        &mut original.as_slice(),
        Publication {
            length: original.len() as u64,
            metadata: Metadata {
                name: "parallel-object".into(),
                content_type: "application/octet-stream".into(),
                revision: 1,
            },
            validity: Validity {
                created: now,
                expires: now + 300,
            },
        },
        &publisher,
        &mut second,
    )
    .unwrap();
    let manifest = signed.verify(&publisher.verifying_key(), now).unwrap();
    if !matches!(mode, Mode::Missing) {
        for chunk in manifest.chunks() {
            first
                .put_verified(*chunk.id(), &second.get(chunk.id()).unwrap().unwrap())
                .unwrap();
        }
    }
    drop(first);
    drop(second);
    let mut a = PublicationRegistry::new();
    let mut b = PublicationRegistry::new();
    a.register(manifest.clone(), first_path, limits, now)
        .unwrap();
    b.register(manifest.clone(), second_path, limits, now)
        .unwrap();
    drop(publisher);
    let output = ChunkStore::create(&directory.path().join("receiver"), limits).unwrap();
    Fixture {
        directory,
        manifest,
        registries: [a, b],
        output,
        original,
    }
}

#[tokio::test]
async fn two_streams_overlap_without_duplicate_requests_and_reassign_only_missing_or_failed_chunks()
{
    for mode in [Mode::Slow, Mode::Disconnect, Mode::Missing, Mode::Reconnect] {
        tokio::time::timeout(Duration::from_secs(10), transfer(mode))
            .await
            .expect("bounded parallel proof");
    }
}

async fn transfer(mode: Mode) {
    let Fixture {
        directory,
        manifest,
        registries: [a, b],
        mut output,
        original,
    } = fixture(mode);
    let limits = TransferLimits {
        exchange_timeout: Duration::from_secs(5),
        session_timeout: Duration::from_secs(8),
        max_requests: 8,
        max_bytes: 8 * CHUNK_BYTES as u64,
    };
    let (download, [worker_a, worker_b]) =
        ParallelDownload::new(&manifest, &mut output, limits).unwrap();
    let (mut client_a, server_a) = tokio::io::duplex(4096);
    let (client_b, server_b) = tokio::io::duplex(4096);
    let (retry_client, retry_server) = tokio::io::duplex(4096);
    let slow = Observation::new();
    let fast = Observation::new();
    let mut server_a = ObservedStream {
        inner: server_a,
        observation: slow.clone(),
        mode: Some(mode),
    };
    let server_b = ObservedStream {
        inner: server_b,
        observation: fast.clone(),
        mode: None,
    };
    let serving_a = tokio::spawn(async move { serve_publication(&mut server_a, &a, limits).await });
    let serving_b = tokio::spawn(serve_fast(
        server_b,
        retry_server,
        b,
        limits,
        mode,
        slow.clone(),
    ));
    let release = unblock_after_fast_payload(mode, slow, fast);
    let mut progress = [TransferProgress::default(); 2];
    let (written, pulled_a, pulled_b, ()) = tokio::join!(
        download.run(&mut output, &mut progress),
        async {
            let mut worker = worker_a;
            pull_publication_worker(&mut client_a, &mut worker).await
        },
        pull_fast(client_b, retry_client, worker_b, mode),
        release
    );
    written.unwrap();
    pulled_b.unwrap();
    drop(client_a);
    let sent_a = serving_a.await.unwrap();
    let sent_b = serving_b.await.unwrap();
    if matches!(mode, Mode::Disconnect | Mode::Reconnect) {
        assert!(pulled_a.is_err());
        assert!(sent_a.is_err());
    } else {
        pulled_a.unwrap();
        assert!(sent_a.is_ok());
    }
    // Five ordered chunks contain only four distinct hashes. Any duplicate active request
    // would add a fifth complete provider response in the slow/full-replica case.
    assert_eq!(progress.iter().map(|p| p.chunks).sum::<usize>(), 4);
    assert_eq!(
        progress.iter().map(|p| p.bytes).sum::<u64>(),
        4 * CHUNK_BYTES as u64
    );
    if matches!(mode, Mode::Slow) {
        assert_eq!(sent_a.unwrap().chunks, 1);
        assert_eq!(
            sent_b.chunks, 3,
            "fast peer finished the other chunks while the first stayed in flight"
        );
    } else if matches!(mode, Mode::Reconnect) {
        assert_eq!(
            sent_b.chunks, 1,
            "reopened stream fetched only the reassigned chunk"
        );
        assert_eq!(
            progress[1].chunks, 4,
            "three previous inserts survived reconnection"
        );
    } else {
        assert_eq!(
            sent_b.chunks, 4,
            "missing/truncated assignment was reassigned"
        );
    }
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut reconstructed = Vec::new();
    reassemble(&manifest, &mut [&mut output], now, &mut reconstructed).unwrap();
    assert_eq!(reconstructed, original);
    drop(output);
    drop(directory);
}

async fn unblock_after_fast_payload(mode: Mode, slow: Arc<Observation>, fast: Arc<Observation>) {
    if matches!(mode, Mode::Missing) {
        return;
    }
    while !slow.blocked.load(Ordering::SeqCst) {
        slow.changed.notified().await;
    }
    while fast.written.load(Ordering::SeqCst) < 3 * CHUNK_BYTES {
        fast.changed.notified().await;
    }
    assert_eq!(
        slow.written.load(Ordering::SeqCst),
        4096,
        "first real response is still incomplete"
    );
    if !matches!(mode, Mode::Reconnect) {
        slow.release();
    }
}

async fn serve_fast(
    mut first: ObservedStream,
    mut retry: DuplexStream,
    registry: PublicationRegistry,
    limits: TransferLimits,
    mode: Mode,
    slow: Arc<Observation>,
) -> TransferProgress {
    if !matches!(mode, Mode::Reconnect) {
        return serve_publication(&mut first, &registry, limits)
            .await
            .unwrap();
    }
    // Exercise the production server's actual idle deadline, shortened only in this fixture.
    // It closes before the failed sibling releases its assignment; no timeout is extended.
    let idle_limits = TransferLimits {
        exchange_timeout: Duration::from_secs(1),
        ..limits
    };
    let result = serve_publication(&mut first, &registry, idle_limits).await;
    assert!(matches!(
        result,
        Err(ProviderError::Transfer(TransferError::Timeout))
    ));
    assert!(first.observation.written.load(Ordering::SeqCst) >= 3 * CHUNK_BYTES);
    assert_eq!(slow.written.load(Ordering::SeqCst), 4096);
    drop(first);
    slow.release();
    serve_publication(&mut retry, &registry, limits)
        .await
        .unwrap()
}

async fn pull_fast(
    mut first: DuplexStream,
    mut retry: DuplexStream,
    mut worker: ChunkWorker,
    mode: Mode,
) -> Result<(), ProviderError> {
    let result = pull_publication_worker(&mut first, &mut worker).await;
    if !matches!(mode, Mode::Reconnect) {
        return result;
    }
    assert!(matches!(
        result,
        Err(ProviderError::Transfer(TransferError::Io(_)))
    ));
    assert!(worker.has_resumable_assignment());
    assert_eq!(worker.received, 3);
    let original_deadline = worker.deadline;
    let requested_before_retry = worker.session.requests;
    drop(first);
    pull_publication_worker(&mut retry, &mut worker).await?;
    assert_eq!(worker.deadline, original_deadline);
    assert_eq!(worker.session.requests, requested_before_retry + 1);
    assert_eq!(worker.received, 4);
    Ok(())
}
