//! Synthetic software transport/lifetime tests, not firmware or worker admission.

use std::{
    io,
    sync::{
        atomic::{AtomicBool, AtomicUsize},
        mpsc as blocking,
    },
    task::{Context, Poll},
};

use tokio::io::{AsyncWriteExt as _, DuplexStream, ReadBuf};

use super::super::{
    ComputeBackend, ComputeFuture, ComputeService,
    attestation::{LocalPolicy, MilanTcb, SessionLimits, SessionOwner, SmtPolicy, TcbMinimums},
    guest::QuoteResponse,
};
use super::*;
use crate::{
    provider::{PublicationRegistry, serve_publication},
    transfer::TransferLimits,
};

struct Authority(AtomicBool);
impl QuoteAuthority for Authority {
    fn check(&self, _requester: [u8; 32]) -> QuoteAuthorityFuture<'_> {
        Box::pin(async {
            if self.0.load(Ordering::SeqCst) {
                Ok(())
            } else {
                Err(QuoteError::Unauthorized)
            }
        })
    }
}

fn requester() -> SigningKey {
    SigningKey::from_bytes(&[2; 32])
}

fn request_with_lifetime(seconds: u64) -> QuoteRequest {
    let minimum = MilanTcb {
        bootloader: 0,
        tee: 0,
        snp: 0,
        microcode: 0,
    };
    let policy = LocalPolicy::new(
        [3; 48],
        0,
        TcbMinimums {
            current: minimum,
            reported: minimum,
            committed: minimum,
            launch: minimum,
        },
        SmtPolicy::Allow,
    )
    .unwrap();
    let verifier = SessionOwner::new(
        [4; 32],
        policy,
        SessionLimits {
            expires_at: protocol::now().unwrap() + seconds,
            maximum_pending: 1,
            maximum_attempts: 1,
        },
    )
    .unwrap();
    let pending = verifier.begin().unwrap();
    QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap()
}

fn request() -> QuoteRequest {
    request_with_lifetime(120)
}

fn report(data: [u8; 64]) -> Vec<u8> {
    let mut bytes = vec![0; 1184];
    bytes[..4].copy_from_slice(&2_u32.to_le_bytes());
    bytes[0x50..0x90].copy_from_slice(&data);
    bytes
}

fn fixture(attempts: u16) -> (Arc<QuoteService>, Arc<Authority>, Arc<Semaphore>) {
    let authority = Arc::new(Authority(AtomicBool::new(true)));
    let firmware = Arc::new(Semaphore::new(1));
    let service = QuoteService::new(
        Arc::new(SigningKey::from_bytes(&[1; 32])),
        QuoteGrant {
            requester_key: requester().verifying_key().to_bytes(),
            limits: GuestLimits {
                expires_at: protocol::now().unwrap() + 120,
                maximum_attempts: attempts,
            },
        },
        Arc::clone(&firmware),
        authority.clone(),
    )
    .unwrap();
    (service, authority, firmware)
}

fn synthetic(service: &QuoteService) {
    *service.source.lock().unwrap() = Some(Box::new(|data| Ok(report(data))));
}

fn start(service: &Arc<QuoteService>) -> JoinHandle<()> {
    tokio::spawn(Arc::clone(service).supervise().unwrap())
}

async fn stop(service: &QuoteService, supervisor: JoinHandle<()>) {
    service.deactivate();
    timeout(Duration::from_secs(5), supervisor)
        .await
        .unwrap()
        .unwrap();
}

async fn roundtrip(
    service: &Arc<QuoteService>,
    caller: &SigningKey,
    request: &QuoteRequest,
) -> Result<QuoteResponse, QuoteError> {
    let mut registry = PublicationRegistry::new();
    registry.set_quote(Arc::clone(service));
    let (mut client, mut server) = tokio::io::duplex(4096);
    let serving = async {
        let result = serve_publication(&mut server, &registry, TransferLimits::default()).await;
        drop(server);
        result
    };
    let requesting = async {
        let challenge = begin(&mut client, &service.signer.verifying_key().to_bytes()).await?;
        exchange(&mut client, challenge, caller, request).await
    };
    let (server_result, response) = tokio::join!(serving, requesting);
    if response.is_ok() {
        assert!(server_result.is_ok());
    }
    response
}

#[test]
fn quote_signed_purpose_rejects_compute_and_cross_stream_replay() {
    let provider = SigningKey::from_bytes(&[1; 32]);
    let caller = requester();
    let compute = Record::challenge(&provider, 100).unwrap();
    let quote = Record::challenge_for(&provider, 100, Purpose::QuoteV1).unwrap();
    assert!(Record::decode(&compute.encode(), Kind::Challenge, 101).is_ok());
    assert!(Record::decode_for(&compute.encode(), Kind::Challenge, 101, Purpose::QuoteV1).is_err());
    assert!(Record::decode(&quote.encode(), Kind::Challenge, 101).is_err());
    let request = Record::request(&caller, &quote, vec![1], 101).unwrap();
    let decoded =
        Record::decode_for(&request.encode(), Kind::Request, 102, Purpose::QuoteV1).unwrap();
    assert!(decoded.matches_challenge(&quote).is_ok());
    assert!(decoded.matches_challenge(&compute).is_err());
    let other = Record::challenge_for(&provider, 100, Purpose::QuoteV1).unwrap();
    assert!(decoded.matches_challenge(&other).is_err());
    assert!(Record::decode(&request.encode(), Kind::Request, 102).is_err());
    assert!(Record::decode_for(&request.encode(), Kind::Request, 130, Purpose::QuoteV1).is_err());
    assert!(
        Record::request(
            &caller,
            &quote,
            vec![0; guest::MAX_QUOTE_REQUEST_BYTES + 1],
            101
        )
        .is_err()
    );
}

struct Echo(AtomicUsize);
impl ComputeBackend for Echo {
    fn exchange(&self, _requester: [u8; 32], request: Vec<u8>) -> ComputeFuture<'_> {
        self.0.fetch_add(1, Ordering::SeqCst);
        Box::pin(async move { Ok(request) })
    }
}

#[tokio::test]
async fn quote_registry_coexists_with_public_compute_without_fallback() {
    let (service, _, _) = fixture(2);
    let supervisor = start(&service);
    synthetic(&service);
    let mut registry = PublicationRegistry::new();
    registry.set_quote(Arc::clone(&service));
    let echo = Arc::new(Echo(AtomicUsize::new(0)));
    registry.set_compute(Arc::new(ComputeService::new(
        Arc::clone(&service.signer),
        echo.clone(),
    )));
    assert!(registry.has_quote() && registry.has_compute());
    let (mut client, mut server) = tokio::io::duplex(4096);
    let requesting = async {
        let challenge =
            super::super::begin(&mut client, &service.signer.verifying_key().to_bytes())
                .await
                .unwrap();
        super::super::exchange(&mut client, challenge, &requester(), b"public".to_vec())
            .await
            .unwrap()
    };
    let (publication, reply) = tokio::join!(
        serve_publication(&mut server, &registry, TransferLimits::default()),
        requesting
    );
    assert!(publication.is_ok());
    assert_eq!(reply, b"public");
    assert_eq!(echo.0.load(Ordering::SeqCst), 1);
    assert!(roundtrip(&service, &requester(), &request()).await.is_ok());
    assert_eq!(echo.0.load(Ordering::SeqCst), 1);
    service.deactivate();
    assert!(!registry.has_quote());
    registry.clear_quote();
    assert!(registry.has_compute());
    stop(&service, supervisor).await;
}

#[tokio::test]
async fn quote_requires_live_supervisor_and_exact_local_requester_grant() {
    let (service, _, firmware) = fixture(1);
    synthetic(&service);
    assert!(roundtrip(&service, &requester(), &request()).await.is_err());
    let supervisor = start(&service);
    assert!(
        roundtrip(&service, &SigningKey::from_bytes(&[9; 32]), &request())
            .await
            .is_err()
    );
    assert!(service.source.lock().unwrap().is_some());
    assert_eq!(firmware.available_permits(), 1);
    // Wrong-caller attempts did not consume the one explicitly authorized attempt.
    assert!(roundtrip(&service, &requester(), &request()).await.is_ok());
    stop(&service, supervisor).await;
}

#[tokio::test]
async fn quote_binary_frames_are_strict_bounded_and_request_bound() {
    let request = request();
    let owner = GuestSessionOwner::new(GuestLimits {
        expires_at: protocol::now().unwrap() + 120,
        maximum_attempts: 1,
    })
    .unwrap();
    let quote = owner
        .begin(QuoteRequest::decode(&request.encode()).unwrap())
        .unwrap()
        .collect_source(guest::ReportSource::Fake(Box::new(|data| Ok(report(data)))))
        .unwrap();
    let (mut writer, mut reader) = tokio::io::duplex(4096);
    let (written, read) = tokio::join!(
        write_response(&mut writer, quote.response().unwrap()),
        read_response(&mut reader, &request)
    );
    assert!(written.is_ok() && read.is_ok());
    assert!(
        QuoteResponse::decode(
            &quote.response().unwrap().encode(),
            &request_with_lifetime(119)
        )
        .is_err()
    );
    let (mut writer, mut reader) = tokio::io::duplex(16);
    writer
        .write_u32(u32::try_from(guest::MAX_QUOTE_REQUEST_BYTES + 1).unwrap())
        .await
        .unwrap();
    assert!(matches!(
        read_request(&mut reader).await,
        Err(QuoteError::Invalid)
    ));
    let (mut writer, mut reader) = tokio::io::duplex(4096);
    let mut malformed = request.encode();
    malformed.extend_from_slice(&[0x18, 1]);
    protocol::write(&mut writer, &malformed, guest::MAX_QUOTE_REQUEST_BYTES)
        .await
        .unwrap();
    assert!(matches!(
        read_request(&mut reader).await,
        Err(QuoteError::Invalid)
    ));
}

#[tokio::test]
async fn quote_delivery_retains_owned_key_until_original_expiry() {
    let (service, _, _) = fixture(2);
    let supervisor = start(&service);
    synthetic(&service);
    let request = request_with_lifetime(3);
    assert!(roundtrip(&service, &requester(), &request).await.is_ok());
    let (cancellation, deadline) = {
        let retained = service.retained.lock().unwrap();
        let retained = retained.as_ref().unwrap();
        assert_eq!(retained.requester, requester().verifying_key().to_bytes());
        (
            retained.quote.cancellation(),
            Instant::from_std(retained.quote.deadline()),
        )
    };
    assert!(!cancellation.is_erased());
    assert!(deadline <= Instant::now() + Duration::from_secs(3));
    sleep_until(deadline + Duration::from_millis(20)).await;
    assert!(cancellation.is_erased());
    assert!(service.retained.lock().unwrap().is_none());
    stop(&service, supervisor).await;
}

struct FailWrite {
    inner: DuplexStream,
    fail: Arc<AtomicBool>,
}
impl AsyncRead for FailWrite {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for FailWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.fail.load(Ordering::SeqCst) {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

#[tokio::test]
async fn quote_write_failure_erases_collected_key_and_releases_owner_slot() {
    let (service, _, firmware) = fixture(2);
    let supervisor = start(&service);
    let fail = Arc::new(AtomicBool::new(false));
    let failing = Arc::clone(&fail);
    let captured = Arc::new(Mutex::new(None));
    let capturing = Arc::clone(&captured);
    let collecting = Arc::downgrade(&service);
    *service.source.lock().unwrap() = Some(Box::new(move |data| {
        *capturing.lock().unwrap() = collecting.upgrade().unwrap().owner.active_cancellation();
        failing.store(true, Ordering::SeqCst);
        Ok(report(data))
    }));
    let mut registry = PublicationRegistry::new();
    registry.set_quote(Arc::clone(&service));
    let (mut client, inner) = tokio::io::duplex(4096);
    let serving = async {
        let mut stream = FailWrite { inner, fail };
        serve_publication(&mut stream, &registry, TransferLimits::default()).await
    };
    let requesting = async {
        let challenge = begin(&mut client, &service.signer.verifying_key().to_bytes())
            .await
            .unwrap();
        exchange(&mut client, challenge, &requester(), &request()).await
    };
    let (served, result) = tokio::join!(serving, requesting);
    assert!(served.is_err() && result.is_err());
    assert!(captured.lock().unwrap().as_ref().unwrap().is_erased());
    assert!(service.retained.lock().unwrap().is_none());
    assert_eq!(firmware.available_permits(), 1);
    // A real second owned session can occupy the slot; the failed one was dropped.
    let session = service.owner.begin(request()).unwrap();
    let cancellation = session.cancellation();
    drop(session);
    assert!(cancellation.is_erased());
    stop(&service, supervisor).await;
}

struct Release(Option<blocking::Sender<()>>);
impl Drop for Release {
    fn drop(&mut self) {
        if let Some(sender) = self.0.take() {
            let _ = sender.send(());
        }
    }
}

fn latched(service: &QuoteService) -> (oneshot::Receiver<()>, Release) {
    let (started, observing) = oneshot::channel();
    let (release, waiting) = blocking::channel();
    *service.source.lock().unwrap() = Some(Box::new(move |data| {
        let _ = started.send(());
        waiting
            .recv_timeout(Duration::from_secs(5))
            .map_err(|_| GuestError::Firmware)?;
        Ok(report(data))
    }));
    (observing, Release(Some(release)))
}

#[tokio::test]
async fn quote_cancellation_keeps_process_permit_until_firmware_really_returns() {
    let (service, _, firmware) = fixture(2);
    let supervisor = start(&service);
    let (started, release) = latched(&service);
    let collecting = Arc::clone(&service);
    let task = tokio::spawn(async move { collecting.collect(request()).await });
    timeout(Duration::from_secs(3), started)
        .await
        .unwrap()
        .unwrap();
    let cancellation = service.owner.active_cancellation().unwrap();
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    assert!(cancellation.is_erased());
    assert_eq!(firmware.available_permits(), 0);
    assert!(matches!(
        service.owner.begin(request()),
        Err(GuestError::Budget)
    ));
    drop(release);
    stop(&service, supervisor).await;
    assert_eq!(firmware.available_permits(), 1);
    assert!(service.retained.lock().unwrap().is_none());
}

#[tokio::test]
async fn quote_detach_and_late_firmware_result_cannot_publish_or_retain() {
    let (service, _, firmware) = fixture(2);
    let supervisor = start(&service);
    let (started, release) = latched(&service);
    let serving = Arc::clone(&service);
    let task = tokio::spawn(async move { roundtrip(&serving, &requester(), &request()).await });
    timeout(Duration::from_secs(3), started)
        .await
        .unwrap()
        .unwrap();
    let cancellation = service.owner.active_cancellation().unwrap();
    service.deactivate();
    assert!(cancellation.is_erased());
    assert_eq!(firmware.available_permits(), 0);
    let replacement = QuoteService::new(
        Arc::clone(&service.signer),
        QuoteGrant {
            requester_key: requester().verifying_key().to_bytes(),
            limits: GuestLimits {
                expires_at: protocol::now().unwrap() + 120,
                maximum_attempts: 1,
            },
        },
        Arc::clone(&firmware),
        Arc::new(Authority(AtomicBool::new(true))),
    )
    .unwrap();
    let replacement_supervisor = start(&replacement);
    assert!(matches!(
        replacement.collect(request()).await,
        Err(QuoteError::Busy)
    ));
    drop(release);
    assert!(
        timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(service.retained.lock().unwrap().is_none());
    stop(&service, supervisor).await;
    stop(&replacement, replacement_supervisor).await;
    assert_eq!(firmware.available_permits(), 1);
}

#[tokio::test]
async fn quote_failed_authority_recheck_revokes_retained_evidence() {
    let (service, authority, _) = fixture(1);
    let supervisor = start(&service);
    synthetic(&service);
    assert!(roundtrip(&service, &requester(), &request()).await.is_ok());
    let cancellation = service
        .retained
        .lock()
        .unwrap()
        .as_ref()
        .unwrap()
        .quote
        .cancellation();
    authority.0.store(false, Ordering::SeqCst);
    timeout(Duration::from_secs(3), supervisor)
        .await
        .unwrap()
        .unwrap();
    assert!(!service.is_active());
    assert!(cancellation.is_erased());
    assert!(service.retained.lock().unwrap().is_none());
}

#[tokio::test]
async fn quote_replay_and_nonrefundable_attempts_are_finite() {
    let (service, _, _) = fixture(2);
    let supervisor = start(&service);
    let first = request();
    synthetic(&service);
    let (quote, guard) = service
        .collect(QuoteRequest::decode(&first.encode()).unwrap())
        .await
        .unwrap();
    drop((quote, guard));
    assert!(matches!(
        service.collect(first).await,
        Err(QuoteError::Unauthorized)
    ));
    *service.source.lock().unwrap() = Some(Box::new(|_| Err(GuestError::Firmware)));
    assert!(matches!(
        service.collect(request()).await,
        Err(QuoteError::Unavailable)
    ));
    assert!(matches!(
        service.collect(request()).await,
        Err(QuoteError::Busy)
    ));
    stop(&service, supervisor).await;
}

#[test]
fn quote_pending_drop_before_supervisor_poll_revokes_attachment() {
    let (service, _, _) = fixture(1);
    let future = Arc::clone(&service).supervise().unwrap();
    assert!(service.is_active());
    drop(future);
    assert!(!service.is_active());
    assert!(Arc::clone(&service).supervise().is_err());
}

#[test]
fn quote_owned_owner_drop_cancels_surviving_session_without_key_access() {
    let owner = GuestSessionOwner::new(GuestLimits {
        expires_at: protocol::now().unwrap() + 120,
        maximum_attempts: 1,
    })
    .unwrap();
    let session = owner.begin(request()).unwrap();
    let cancellation = session.cancellation();
    assert!(!cancellation.is_erased());
    drop(owner);
    assert!(cancellation.is_erased());
    assert!(matches!(
        session.collect_source(guest::ReportSource::Fake(Box::new(|_| panic!(
            "cancelled before source"
        )))),
        Err(GuestError::Cancelled)
    ));
}
