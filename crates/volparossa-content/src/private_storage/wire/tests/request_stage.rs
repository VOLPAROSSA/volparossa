//! Actual signed duplex/SQLite boundaries; synthetic fixtures, not consumer acceptance.
use super::*;
use crate::private_storage::wire::{bridge_observation, diagnostic};
use crate::provider::{
    activity::{Observer, RequestStage, Stage, WorkerObserver},
    serve_publication_with_activity,
};
use std::{sync::atomic::AtomicBool, task::Waker};
use tokio::sync::{Notify, oneshot};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Event {
    Verified,
    Entered,
    Returned(bool),
    ReceiptWrite,
    ReceiptFlushed,
}

#[derive(Default)]
struct Trace {
    events: Arc<Mutex<Vec<Event>>>,
    prepared: AtomicBool,
    returned: Arc<Notify>,
}

struct WorkerTrace {
    events: Arc<Mutex<Vec<Event>>>,
    returned: Arc<Notify>,
}

impl WorkerObserver for WorkerTrace {
    fn entered(&self) {
        self.events.lock().unwrap().push(Event::Entered);
    }
    fn returned(&self, success: bool) {
        self.events.lock().unwrap().push(Event::Returned(success));
        self.returned.notify_one();
    }
}

impl Observer for Trace {
    fn enter(&self, _: Stage) {}
    fn verified_request(&self, _: &VerifiedStorageRequest) {
        self.events.lock().unwrap().push(Event::Verified);
    }
    fn request_stage(&self, stage: RequestStage) {
        self.events.lock().unwrap().push(match stage {
            RequestStage::ReceiptWriteEntered => Event::ReceiptWrite,
            RequestStage::ReceiptFlushReturned => Event::ReceiptFlushed,
        });
    }
    fn worker(&self) -> Option<Arc<dyn WorkerObserver>> {
        self.prepared.store(true, Ordering::SeqCst);
        Some(Arc::new(WorkerTrace {
            events: Arc::clone(&self.events),
            returned: Arc::clone(&self.returned),
        }))
    }
}

struct ReceiptFlushGate {
    stream: DuplexStream,
    flushes: usize,
    fail: bool,
    entered: Option<oneshot::Sender<()>>,
    released: Arc<AtomicBool>,
    waker: Arc<Mutex<Option<Waker>>>,
}

impl AsyncRead for ReceiptFlushGate {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, bytes)
    }
}
impl AsyncWrite for ReceiptFlushGate {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        // Challenge is the first flush; latch the receipt's second flush only.
        if this.flushes == 1 && this.fail {
            return Poll::Ready(Err(std::io::Error::other(
                "synthetic-provider-receipt-flush",
            )));
        }
        if this.flushes == 1 && !this.released.load(Ordering::SeqCst) {
            *this.waker.lock().unwrap() = Some(cx.waker().clone());
            if let Some(entered) = this.entered.take() {
                let _ = entered.send(());
            }
            return Poll::Pending;
        }
        let result = Pin::new(&mut this.stream).poll_flush(cx);
        if matches!(result, Poll::Ready(Ok(()))) {
            this.flushes += 1;
        }
        result
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn fixture_request_provider_receipt_flush_is_only_recorded_after_actual_return() {
    let fixture = Fixture::new();
    let trace = Arc::new(Trace::default());
    let mut registry = PublicationRegistry::new();
    registry.set_private_storage(Arc::clone(fixture.service.as_ref().unwrap()));
    let (mut client, server) = tokio::io::duplex(4096);
    let (entered, waiting) = oneshot::channel();
    let released = Arc::new(AtomicBool::new(false));
    let waker = Arc::new(Mutex::new(None));
    let mut server = ReceiptFlushGate {
        stream: server,
        flushes: 0,
        fail: false,
        entered: Some(entered),
        released: Arc::clone(&released),
        waker: Arc::clone(&waker),
    };
    let observer = Arc::clone(&trace);
    let server = tokio::spawn(async move {
        serve_publication_with_activity(
            &mut server,
            &registry,
            TransferLimits::default(),
            &mut None,
            observer.as_ref(),
        )
        .await
    });
    let challenge = begin(&mut client, &fixture.grant).await.unwrap();
    let request = fixture.request(
        &challenge,
        target(b"receipt-flush"),
        StorageOperation::Reserve {
            expires_at: unix_now().unwrap() + 600,
        },
    );
    let grant = fixture.grant.clone();
    let client =
        tokio::spawn(async move { finish(&mut client, &grant, &challenge, &request, &[]).await });
    timeout(Duration::from_secs(5), waiting)
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        *trace.events.lock().unwrap(),
        vec![
            Event::Verified,
            Event::Entered,
            Event::Returned(true),
            Event::ReceiptWrite
        ]
    );
    // Backend success and readable receipt bytes must not fabricate a successful flush.
    assert_eq!(
        fixture.usage().reserved_bytes,
        b"receipt-flush".len() as u64
    );
    released.store(true, Ordering::SeqCst);
    if let Some(waker) = waker.lock().unwrap().take() {
        waker.wake();
    }
    server.await.unwrap().unwrap();
    client.await.unwrap().unwrap();
    assert_eq!(
        *trace.events.lock().unwrap(),
        vec![
            Event::Verified,
            Event::Entered,
            Event::Returned(true),
            Event::ReceiptWrite,
            Event::ReceiptFlushed
        ]
    );
}

#[tokio::test(start_paused = true)]
async fn fixture_request_backend_can_really_return_after_original_connection_timeout() {
    let fixture = Fixture::new();
    let service = Arc::clone(fixture.service.as_ref().unwrap());
    let blocker = Arc::clone(&service);
    let (held_send, held_receive) = std::sync::mpsc::channel();
    let (release_send, release_receive) = std::sync::mpsc::channel();
    let holder = std::thread::spawn(move || {
        let held = blocker.provider.lock().unwrap();
        held_send.send(()).unwrap();
        let _ = release_receive.recv_timeout(Duration::from_secs(10));
        drop(held);
    });
    held_receive.recv_timeout(Duration::from_secs(5)).unwrap();
    let trace = Arc::new(Trace::default());
    let observer = Arc::clone(&trace);
    let (mut client, mut stream) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        service
            .serve_with_activity(
                &mut stream,
                &mut diagnostic::Observation::default(),
                observer.as_ref(),
            )
            .await
    });
    // StorageService begins after selector dispatch, so send the grant directly.
    write_frame(&mut client, &fixture.grant.signed().encode())
        .await
        .unwrap();
    let challenge = StorageChallenge::decode_and_verify(
        &read_frame(&mut client, MAX_CHALLENGE_BYTES).await.unwrap(),
        &fixture.grant,
        unix_now().unwrap(),
    )
    .unwrap();
    let request = fixture.request(
        &challenge,
        target(b"late-backend"),
        StorageOperation::Reserve {
            expires_at: unix_now().unwrap() + 600,
        },
    );
    write_frame(&mut client, &request.encode()).await.unwrap();
    for _ in 0..1000 {
        if trace.prepared.load(Ordering::SeqCst) {
            break;
        }
        tokio::task::yield_now().await;
    }
    assert!(trace.prepared.load(Ordering::SeqCst));
    tokio::time::advance(IO_TIMEOUT + Duration::from_secs(1)).await;
    assert!(matches!(server.await.unwrap(), Err(WireError::Timeout)));
    assert_eq!(*trace.events.lock().unwrap(), vec![Event::Verified]);
    tokio::time::resume();
    release_send.send(()).unwrap();
    holder.join().unwrap();
    timeout(Duration::from_secs(5), trace.returned.notified())
        .await
        .unwrap();
    assert_eq!(
        *trace.events.lock().unwrap(),
        vec![Event::Verified, Event::Entered, Event::Returned(true)]
    );
    assert_eq!(fixture.usage().reserved_bytes, b"late-backend".len() as u64);
    assert!(
        !trace
            .events
            .lock()
            .unwrap()
            .contains(&Event::ReceiptFlushed)
    );
}

struct ClientTrace(Mutex<Vec<&'static str>>);
impl bridge_observation::Observer for ClientTrace {
    fn phase(&self, _: bridge_observation::Phase) {}
    fn deadline(&self, _: bridge_observation::Deadline) {}
    fn verified_request(&self, _: &VerifiedStorageRequest) {
        self.0.lock().unwrap().push("verified");
    }
    fn request_flushed(&self, _: &VerifiedStorageRequest) {
        self.0.lock().unwrap().push("flushed");
    }
}

struct FailedFlush(DuplexStream);
impl AsyncRead for FailedFlush {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_read(cx, bytes)
    }
}
impl AsyncWrite for FailedFlush {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().0).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, _: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Poll::Ready(Err(std::io::Error::other("synthetic-failed-flush")))
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().0).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn fixture_request_client_binding_requires_successful_original_request_flush() {
    for fail in [false, true] {
        let fixture = Fixture::new();
        let (client, server, challenge) = fixture.session().await;
        let request = fixture.request(
            &challenge,
            target(b"client-flush"),
            StorageOperation::Reserve {
                expires_at: unix_now().unwrap() + 600,
            },
        );
        let trace = ClientTrace(Mutex::new(Vec::new()));
        if fail {
            let mut client = FailedFlush(client);
            assert!(matches!(
                finish_observed(
                    &mut client,
                    &fixture.grant,
                    &challenge,
                    &request,
                    &[],
                    &trace
                )
                .await,
                Err(WireError::Io(_))
            ));
            drop(client);
            let _ = server.await.unwrap();
            assert_eq!(*trace.0.lock().unwrap(), vec!["verified"]);
        } else {
            let mut client = client;
            finish_observed(
                &mut client,
                &fixture.grant,
                &challenge,
                &request,
                &[],
                &trace,
            )
            .await
            .unwrap();
            server.await.unwrap().unwrap();
            assert_eq!(*trace.0.lock().unwrap(), vec!["verified", "flushed"]);
        }
    }
}

#[tokio::test]
async fn fixture_request_actual_backend_error_does_not_fabricate_receipt_or_success() {
    let fixture = Fixture::new();
    let (mut first, server, challenge) = fixture.session().await;
    let full = StorageTarget {
        ciphertext_bytes: 4 * CHUNK_BYTES as u64,
        ..target(b"quota")
    };
    let request = fixture.request(
        &challenge,
        full,
        StorageOperation::Reserve {
            expires_at: unix_now().unwrap() + 600,
        },
    );
    finish(&mut first, &fixture.grant, &challenge, &request, &[])
        .await
        .unwrap();
    server.await.unwrap().unwrap();
    let trace = Arc::new(Trace::default());
    let observer = Arc::clone(&trace);
    let service = Arc::clone(fixture.service.as_ref().unwrap());
    let (mut client, mut stream) = tokio::io::duplex(4096);
    let server = tokio::spawn(async move {
        service
            .serve_with_activity(
                &mut stream,
                &mut diagnostic::Observation::default(),
                observer.as_ref(),
            )
            .await
    });
    write_frame(&mut client, &fixture.grant.signed().encode())
        .await
        .unwrap();
    let challenge = StorageChallenge::decode_and_verify(
        &read_frame(&mut client, MAX_CHALLENGE_BYTES).await.unwrap(),
        &fixture.grant,
        unix_now().unwrap(),
    )
    .unwrap();
    let overflow = StorageTarget {
        archive_id: [32; 32],
        ..target(b"overflow")
    };
    let request = fixture.request(
        &challenge,
        overflow,
        StorageOperation::Reserve {
            expires_at: unix_now().unwrap() + 600,
        },
    );
    write_frame(&mut client, &request.encode()).await.unwrap();
    assert!(matches!(server.await.unwrap(), Err(WireError::Store)));
    assert_eq!(
        *trace.events.lock().unwrap(),
        vec![Event::Verified, Event::Entered, Event::Returned(false)]
    );
    assert_eq!(fixture.usage().reserved_bytes, 4 * CHUNK_BYTES as u64);
    assert!(!trace.events.lock().unwrap().contains(&Event::ReceiptWrite));
    assert!(
        !trace
            .events
            .lock()
            .unwrap()
            .contains(&Event::ReceiptFlushed)
    );
    assert!(Observer::worker(&()).is_none());
}

#[tokio::test]
async fn fixture_request_provider_flush_error_preserves_committed_backend_and_wire_failure() {
    let fixture = Fixture::new();
    let trace = Arc::new(Trace::default());
    let observer = Arc::clone(&trace);
    let service = Arc::clone(fixture.service.as_ref().unwrap());
    let (mut client, stream) = tokio::io::duplex(4096);
    let mut stream = ReceiptFlushGate {
        stream,
        flushes: 0,
        fail: true,
        entered: None,
        released: Arc::new(AtomicBool::new(true)),
        waker: Arc::new(Mutex::new(None)),
    };
    let server = tokio::spawn(async move {
        service
            .serve_with_activity(
                &mut stream,
                &mut diagnostic::Observation::default(),
                observer.as_ref(),
            )
            .await
    });
    write_frame(&mut client, &fixture.grant.signed().encode())
        .await
        .unwrap();
    let challenge = StorageChallenge::decode_and_verify(
        &read_frame(&mut client, MAX_CHALLENGE_BYTES).await.unwrap(),
        &fixture.grant,
        unix_now().unwrap(),
    )
    .unwrap();
    let request = fixture.request(
        &challenge,
        target(b"provider-flush-error"),
        StorageOperation::Reserve {
            expires_at: unix_now().unwrap() + 600,
        },
    );
    write_frame(&mut client, &request.encode()).await.unwrap();
    assert!(matches!(server.await.unwrap(), Err(WireError::Io(_))));
    assert_eq!(
        *trace.events.lock().unwrap(),
        vec![
            Event::Verified,
            Event::Entered,
            Event::Returned(true),
            Event::ReceiptWrite
        ]
    );
    assert_eq!(
        fixture.usage().reserved_bytes,
        b"provider-flush-error".len() as u64
    );
    assert!(
        !trace
            .events
            .lock()
            .unwrap()
            .contains(&Event::ReceiptFlushed)
    );
}
