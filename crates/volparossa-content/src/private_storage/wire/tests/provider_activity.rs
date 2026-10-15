//! Genuine signed exchange and explicit flush latch; no network acceptance claims.

use super::*;
use crate::provider::{
    activity::{Observer, Stage},
    serve_publication_with_activity,
};
use std::{sync::atomic::AtomicBool, task::Waker};
use tokio::sync::{oneshot, watch};

struct Trace {
    stage: watch::Sender<Stage>,
    history: Mutex<Vec<Stage>>,
}

impl Observer for Trace {
    fn enter(&self, stage: Stage) {
        self.history.lock().unwrap().push(stage);
        self.stage.send_replace(stage);
    }
}

fn trace() -> (Arc<Trace>, watch::Receiver<Stage>) {
    let (stage, receiver) = watch::channel(Stage::TlsHandshake);
    (
        Arc::new(Trace {
            stage,
            history: Mutex::new(Vec::new()),
        }),
        receiver,
    )
}

async fn wait_stage(receiver: &mut watch::Receiver<Stage>, stage: Stage) {
    timeout(
        Duration::from_secs(5),
        receiver.wait_for(|value| *value == stage),
    )
    .await
    .unwrap()
    .unwrap();
}

async fn selector(client: &mut DuplexStream) {
    write_frame(
        client,
        &Selector {
            version: SELECTOR_VERSION,
            manifest_id: Vec::new(),
            operation: SELECTOR_OPERATION,
        }
        .encode_to_vec(),
    )
    .await
    .unwrap();
}

struct FlushGate {
    stream: DuplexStream,
    entered: Option<oneshot::Sender<()>>,
    release: Arc<AtomicBool>,
    waker: Arc<Mutex<Option<Waker>>>,
    fail: bool,
}

impl AsyncRead for FlushGate {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, bytes)
    }
}

impl AsyncWrite for FlushGate {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        Pin::new(&mut self.get_mut().stream).poll_write(cx, bytes)
    }

    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        let this = self.get_mut();
        if this.fail {
            return Poll::Ready(Err(std::io::Error::other(
                "private-canary-not-an-observation",
            )));
        }
        *this.waker.lock().unwrap() = Some(cx.waker().clone());
        if let Some(entered) = this.entered.take() {
            let _ = entered.send(());
        }
        if this.release.load(Ordering::SeqCst) {
            Pin::new(&mut this.stream).poll_flush(cx)
        } else {
            Poll::Pending
        }
    }

    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn provider_activity_request_stage_requires_successful_challenge_flush() {
    let fixture = Fixture::new();
    let mut registry = PublicationRegistry::new();
    registry.set_private_storage(Arc::clone(fixture.service.as_ref().unwrap()));
    let (mut client, server) = tokio::io::duplex(4096);
    let (entered, waiting) = oneshot::channel();
    let release = Arc::new(AtomicBool::new(false));
    let waker = Arc::new(Mutex::new(None));
    let mut server = FlushGate {
        stream: server,
        entered: Some(entered),
        release: Arc::clone(&release),
        waker: Arc::clone(&waker),
        fail: false,
    };
    let (trace, mut receiver) = trace();
    let observer = Arc::clone(&trace);
    let task = tokio::spawn(async move {
        serve_publication_with_activity(
            &mut server,
            &registry,
            TransferLimits::default(),
            &mut None,
            observer.as_ref(),
        )
        .await
    });
    wait_stage(&mut receiver, Stage::SelectorRead).await;
    selector(&mut client).await;
    wait_stage(&mut receiver, Stage::StorageGrantReadVerify).await;
    write_frame(&mut client, &fixture.grant.signed().encode())
        .await
        .unwrap();
    waiting.await.unwrap();
    // The challenge bytes can already be readable, but flush has not succeeded.
    let challenge = StorageChallenge::decode_and_verify(
        &read_frame(&mut client, MAX_CHALLENGE_BYTES).await.unwrap(),
        &fixture.grant,
        unix_now().unwrap(),
    )
    .unwrap();
    assert_eq!(*receiver.borrow(), Stage::StorageChallengeWriteFlush);
    assert!(
        !trace
            .history
            .lock()
            .unwrap()
            .contains(&Stage::StorageRequestReadVerify)
    );
    release.store(true, Ordering::SeqCst);
    waker.lock().unwrap().take().unwrap().wake();
    wait_stage(&mut receiver, Stage::StorageRequestReadVerify).await;
    let request = fixture.request(
        &challenge,
        target(b"activity"),
        StorageOperation::Reserve {
            expires_at: unix_now().unwrap() + 600,
        },
    );
    let transfer = finish(&mut client, &fixture.grant, &challenge, &request, &[])
        .await
        .unwrap();
    assert_eq!(transfer.receipt.result().state, ReceiptState::Reserved);
    task.await.unwrap().unwrap();
    assert_eq!(
        *trace.history.lock().unwrap(),
        vec![
            Stage::SelectorRead,
            Stage::StorageGrantReadVerify,
            Stage::StorageChallengeWriteFlush,
            Stage::StorageRequestReadVerify,
            Stage::StorageOperation,
        ]
    );
}

#[tokio::test]
async fn provider_activity_failed_flush_preserves_wire_failure_and_never_enters_request() {
    let fixture = Fixture::new();
    let service = Arc::clone(fixture.service.as_ref().unwrap());
    let (mut client, server) = tokio::io::duplex(4096);
    let mut server = FlushGate {
        stream: server,
        entered: None,
        release: Arc::new(AtomicBool::new(true)),
        waker: Arc::new(Mutex::new(None)),
        fail: true,
    };
    let (trace, _) = trace();
    let observer = Arc::clone(&trace);
    let before = fixture.usage();
    let task = tokio::spawn(async move {
        service
            .serve_with_activity(
                &mut server,
                &mut crate::private_storage::wire::diagnostic::Observation::default(),
                observer.as_ref(),
            )
            .await
    });
    write_frame(&mut client, &fixture.grant.signed().encode())
        .await
        .unwrap();
    assert!(matches!(task.await.unwrap(), Err(WireError::Io(_))));
    assert_eq!(
        *trace.history.lock().unwrap(),
        vec![
            Stage::StorageGrantReadVerify,
            Stage::StorageChallengeWriteFlush
        ]
    );
    assert_eq!(fixture.usage(), before);
}

#[tokio::test(start_paused = true)]
async fn provider_activity_preserves_original_stalled_grant_deadline() {
    let fixture = Fixture::new();
    let service = Arc::clone(fixture.service.as_ref().unwrap());
    let (_client, mut server) = tokio::io::duplex(4096);
    let (trace, mut receiver) = trace();
    let observer = Arc::clone(&trace);
    let task = tokio::spawn(async move {
        service
            .serve_with_activity(
                &mut server,
                &mut crate::private_storage::wire::diagnostic::Observation::default(),
                observer.as_ref(),
            )
            .await
    });
    wait_stage(&mut receiver, Stage::StorageGrantReadVerify).await;
    tokio::time::advance(IO_TIMEOUT + Duration::from_millis(1)).await;
    assert!(matches!(task.await.unwrap(), Err(WireError::Timeout)));
    assert_eq!(
        *trace.history.lock().unwrap(),
        vec![Stage::StorageGrantReadVerify]
    );
}

#[tokio::test]
async fn provider_activity_rejected_grant_does_not_imply_challenge_or_verified_operation() {
    let fixture = Fixture::new();
    let service = Arc::clone(fixture.service.as_ref().unwrap());
    let (mut client, mut server) = tokio::io::duplex(4096);
    let (trace, _) = trace();
    let observer = Arc::clone(&trace);
    let task = tokio::spawn(async move {
        service
            .serve_with_activity(
                &mut server,
                &mut crate::private_storage::wire::diagnostic::Observation::default(),
                observer.as_ref(),
            )
            .await
    });
    let mut grant = fixture.grant.signed().encode();
    *grant.last_mut().unwrap() ^= 1;
    write_frame(&mut client, &grant).await.unwrap();
    assert!(matches!(task.await.unwrap(), Err(WireError::Protocol(_))));
    assert_eq!(
        *trace.history.lock().unwrap(),
        vec![Stage::StorageGrantReadVerify]
    );
}
