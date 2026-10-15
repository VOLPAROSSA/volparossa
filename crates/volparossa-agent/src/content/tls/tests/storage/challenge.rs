//! Real signed challenge/receipt under deliberately blocked reverse transport reads.
//! All gates and transport counters are test-only; no protocol or product budget changes.

use super::*;
use std::{
    pin::Pin,
    sync::{
        Mutex,
        atomic::{AtomicUsize, Ordering::SeqCst},
    },
    task::{Context, Poll, Waker},
};
use tokio::{
    io::{DuplexStream, ReadBuf},
    sync::watch,
    task::{JoinError, JoinSet},
    time::{Instant, timeout_at},
};
use volparossa_content::provider::{
    activity::{Observer, Stage},
    serve_publication_with_activity,
};
use wire::begin_observation::{self, Phase};

const TRANSPORT_BYTES: usize = 16;

#[derive(Default)]
struct ReadGate {
    blocked: bool,
    reader: Option<Waker>,
}

struct Control {
    gate: Mutex<ReadGate>,
    stage: watch::Sender<Stage>,
    phase: watch::Sender<Option<Phase>>,
    pending: watch::Sender<bool>,
    reverse_written: AtomicUsize,
    reverse_read: AtomicUsize,
    dropped: AtomicUsize,
}

impl Control {
    fn new() -> Self {
        Self {
            gate: Mutex::new(ReadGate::default()),
            stage: watch::channel(Stage::TlsHandshake).0,
            phase: watch::channel(None).0,
            pending: watch::channel(false).0,
            reverse_written: AtomicUsize::new(0),
            reverse_read: AtomicUsize::new(0),
            dropped: AtomicUsize::new(0),
        }
    }

    fn release(&self) {
        let reader = {
            let mut gate = self.gate.lock().unwrap();
            gate.blocked = false;
            gate.reader.take()
        };
        if let Some(reader) = reader {
            reader.wake();
        }
    }

    async fn blocked_challenge(&self) {
        self.phase
            .subscribe()
            .wait_for(|phase| *phase == Some(Phase::ChallengeReadVerify))
            .await
            .unwrap();
        self.pending
            .subscribe()
            .wait_for(|pending| *pending)
            .await
            .unwrap();
    }
}

impl Observer for Control {
    fn enter(&self, stage: Stage) {
        self.stage.send_replace(stage);
        if stage == Stage::StorageChallengeWriteFlush {
            // Both genuine TLS handshakes and signed grant verification have finished.
            // Stop only the proxy's reads of the provider-to-client transport direction.
            self.gate.lock().unwrap().blocked = true;
        }
    }
}

impl begin_observation::Observer for Control {
    fn phase(&self, phase: Phase) {
        self.phase.send_replace(Some(phase));
    }
}

#[derive(Clone, Copy, Eq, PartialEq)]
enum Role {
    Client,
    Exit,
    Forwarded,
    Provider,
}

struct Endpoint {
    stream: DuplexStream,
    control: Arc<Control>,
    role: Role,
}

impl Endpoint {
    fn new(stream: DuplexStream, control: &Arc<Control>, role: Role) -> Self {
        Self {
            stream,
            control: Arc::clone(control),
            role,
        }
    }
}

impl Drop for Endpoint {
    fn drop(&mut self) {
        self.control.dropped.fetch_add(1, SeqCst);
    }
}

impl AsyncRead for Endpoint {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let this = self.get_mut();
        if this.role == Role::Forwarded {
            let mut gate = this.control.gate.lock().unwrap();
            if gate.blocked {
                gate.reader = Some(cx.waker().clone());
                return Poll::Pending;
            }
        }
        let before = bytes.filled().len();
        let result = Pin::new(&mut this.stream).poll_read(cx, bytes);
        if this.role == Role::Forwarded {
            this.control
                .reverse_read
                .fetch_add(bytes.filled().len() - before, SeqCst);
        }
        result
    }
}

impl AsyncWrite for Endpoint {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        let this = self.get_mut();
        let result = Pin::new(&mut this.stream).poll_write(cx, bytes);
        if let (Role::Provider, Poll::Ready(Ok(written))) = (this.role, &result) {
            this.control.reverse_written.fetch_add(*written, SeqCst);
        }
        if result.is_pending()
            && this.role == Role::Provider
            && *this.control.stage.borrow() == Stage::StorageChallengeWriteFlush
            && this.control.reverse_written.load(SeqCst) - this.control.reverse_read.load(SeqCst)
                == TRANSPORT_BYTES
        {
            // This is a real full 16-byte transport buffer, not an injected write error
            // or a synthetic Pending returned by a TLS/protocol implementation.
            this.control.pending.send_replace(true);
        }
        result
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

enum Completed {
    Client(Box<StorageTransfer>),
    Provider,
    Proxy,
}

async fn client(
    fixture: Arc<Fixture>,
    stream: Endpoint,
    control: Arc<Control>,
    target: StorageTarget,
    received: Arc<Barrier>,
) -> Completed {
    let mut outer = connect(stream, fixture.exit_peer, &fixture.exit_offer)
        .await
        .unwrap();
    let mut inner = connect(&mut outer, fixture.provider_peer, &fixture.provider_offer)
        .await
        .unwrap();
    let challenge = wire::begin_observed(&mut inner, &fixture.grant, control.as_ref())
        .await
        .unwrap();
    let now = crate::content::now();
    let request = SignedStorageRequest::sign(
        &fixture.owner,
        &fixture.grant,
        &challenge,
        target,
        StorageOperation::Finalize,
        Validity {
            created: now,
            expires: (now + 60).min(challenge.validity().expires),
        },
    )
    .unwrap();
    let (mut owner, mut agent) = duplex(4096);
    let (owner_result, bridge_result) = tokio::join!(
        wire::finish(&mut owner, &fixture.grant, &challenge, &request, &[]),
        wire::bridge(&mut agent, &mut inner, &fixture.grant, &challenge),
    );
    let owner_result = owner_result.unwrap();
    assert_eq!(
        owner_result.receipt.encode(),
        bridge_result.unwrap().receipt.encode()
    );
    // Provider and client may close only after a verified, exact-request-bound receipt.
    received.wait().await;
    finish(&mut inner).await.unwrap();
    drop(inner);
    finish(&mut outer).await.unwrap();
    Completed::Client(Box::new(owner_result))
}

fn start(
    fixture: &Arc<Fixture>,
    control: &Arc<Control>,
    target: StorageTarget,
) -> JoinSet<Completed> {
    // Keep the original fixture capacity around the outer TLS tunnel. Only the
    // provider transport below is the sixteen-byte reverse-backpressure subject.
    let (client_io, exit_io) = duplex(4096);
    let (forwarded, provider_io) = duplex(TRANSPORT_BYTES);
    let client_io = Endpoint::new(client_io, control, Role::Client);
    let exit_io = Endpoint::new(exit_io, control, Role::Exit);
    let mut forwarded = Endpoint::new(forwarded, control, Role::Forwarded);
    let provider_io = Endpoint::new(provider_io, control, Role::Provider);
    let received = Arc::new(Barrier::new(2));
    let mut tasks = JoinSet::new();
    tasks.spawn(client(
        Arc::clone(fixture),
        client_io,
        Arc::clone(control),
        target,
        Arc::clone(&received),
    ));
    let provider = Arc::clone(fixture);
    let observer = Arc::clone(control);
    tasks.spawn(async move {
        let mut stream = provider.provider_tls.accept(provider_io).await.unwrap();
        serve_publication_with_activity(
            &mut stream,
            &provider.registry,
            TransferLimits::default(),
            &mut None,
            observer.as_ref(),
        )
        .await
        .unwrap();
        received.wait().await;
        finish(&mut stream).await.unwrap();
        Completed::Provider
    });
    let exit = Arc::clone(fixture);
    tasks.spawn(async move {
        let mut stream = exit.exit_tls.accept(exit_io).await.unwrap();
        forward(&mut stream, &mut forwarded).await;
        Completed::Proxy
    });
    tasks
}

async fn prepared() -> (Arc<Fixture>, StorageTarget) {
    let fixture = Arc::new(Fixture::new());
    let bytes = b"signed-finalize-challenge";
    let mut target = StorageTarget {
        archive_id: [41; 32],
        lease_id: None,
        ciphertext_bytes: bytes.len() as u64,
        sha256: Sha256::digest(bytes).into(),
    };
    let reserved = fixture
        .exchange(
            target,
            StorageOperation::Reserve {
                expires_at: crate::content::now() + 600,
            },
            &[],
        )
        .await;
    assert_eq!(reserved.receipt.result().state, ReceiptState::Reserved);
    target.lease_id = Some(reserved.receipt.result().lease_id);
    let appended = fixture
        .exchange(
            target,
            StorageOperation::Append {
                offset: 0,
                length: u32::try_from(bytes.len()).unwrap(),
                sha256: target.sha256,
            },
            bytes,
        )
        .await;
    assert_eq!(
        appended.receipt.result().stored_bytes,
        target.ciphertext_bytes
    );
    (fixture, target)
}

async fn drain(tasks: &mut JoinSet<Completed>) -> Vec<Result<Completed, JoinError>> {
    let mut results = Vec::new();
    while let Some(result) = tasks.join_next().await {
        results.push(result);
    }
    results
}

async fn exchange(cancel: bool) -> Vec<Result<Completed, JoinError>> {
    let (fixture, target) = prepared().await;
    let control = Arc::new(Control::new());
    // One unchanged ten-second fixture deadline, never restarted when the gate opens.
    let deadline = Instant::now() + Duration::from_secs(10);
    let mut tasks = start(&fixture, &control, target);
    let blocked = timeout_at(deadline, control.blocked_challenge())
        .await
        .is_ok();
    // Snapshot only synthetic test enums and counters, before cancellation or draining.
    let observed = (
        *control.stage.borrow(),
        *control.phase.borrow(),
        control.gate.lock().unwrap().blocked,
        *control.pending.borrow(),
        control.reverse_written.load(SeqCst),
        control.reverse_read.load(SeqCst),
        control.dropped.load(SeqCst),
    );
    let at_challenge = *control.stage.borrow() == Stage::StorageChallengeWriteFlush;
    let no_transport_dropped = control.dropped.load(SeqCst) == 0;
    if cancel || !blocked {
        tasks.abort_all();
    } else {
        control.release();
    }
    let completed = timeout_at(deadline, drain(&mut tasks)).await;
    // Also join every owned task on a failing assertion/timeout path. No detached work.
    if completed.is_err() {
        tasks.abort_all();
        drain(&mut tasks).await;
    }
    assert!(
        blocked,
        "real signed challenge must reach reverse backpressure; before cleanup (stage, phase, gate, pending, written, read, dropped)={observed:?}"
    );
    assert!(at_challenge);
    assert!(no_transport_dropped);
    assert!(tasks.is_empty());
    assert_eq!(control.dropped.load(SeqCst), 4);
    let completed = completed.expect("same original fixture deadline");
    assert_eq!(completed.len(), 3);
    completed
}

#[tokio::test]
async fn signed_challenge_reverse_backpressure_releases_without_extra_write_or_eof() {
    let completed = exchange(false).await;
    let mut receipts = 0;
    for result in completed {
        if let Completed::Client(transfer) = result.unwrap() {
            assert_eq!(transfer.receipt.result().state, ReceiptState::Committed);
            assert!(transfer.ciphertext.is_empty());
            receipts += 1;
        }
    }
    assert_eq!(receipts, 1);
}

#[tokio::test]
async fn cancelling_signed_challenge_backpressure_joins_every_task_and_drops_streams() {
    for result in exchange(true).await {
        assert!(result.is_err_and(|error| error.is_cancelled()));
    }
}
