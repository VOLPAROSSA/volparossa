//! Synthetic protocol/lifetime regressions, never real firmware or route evidence.

use std::{
    io,
    sync::{
        atomic::{AtomicBool, AtomicUsize},
        mpsc as blocking,
    },
    task::{Context, Poll},
};

use prost::Message;
use tokio::io::{AsyncWriteExt as _, DuplexStream, ReadBuf};

use super::super::{
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

fn request_for(seconds: u64) -> QuoteRequest {
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
    QuoteRequest::from_challenge(verifier.begin().unwrap().challenge_bytes()).unwrap()
}

fn request() -> QuoteRequest {
    request_for(120)
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

fn unavailable(service: &QuoteService) -> Arc<AtomicUsize> {
    let calls = Arc::new(AtomicUsize::new(0));
    let counting = Arc::clone(&calls);
    *service.source.lock().unwrap() = Some(Box::new(move |_| {
        counting.fetch_add(1, Ordering::SeqCst);
        Err(GuestError::DeviceUnavailable)
    }));
    calls
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
    legacy: bool,
) -> Result<QuoteOutcome, QuoteError> {
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
        if legacy {
            exchange(&mut client, challenge, caller, request)
                .await
                .map(QuoteOutcome::Evidence)
        } else {
            exchange_outcome(&mut client, challenge, caller, request).await
        }
    };
    let (publication, response) = tokio::join!(serving, requesting);
    if response.is_ok() {
        assert!(publication.is_ok());
    }
    response
}

fn refusal(request: &QuoteRequest) -> Vec<u8> {
    let mut bytes = vec![8, 2, 16, 1, 26, 32];
    bytes.extend_from_slice(&Sha256::digest(request.encode()));
    bytes
}

#[test]
fn refusal_is_canonical_bounded_and_exactly_request_bound() {
    let request = request();
    let bytes = refusal(&request);
    assert_eq!(
        outcome::encode(&QuoteOutcome::DeviceUnavailable, &request).unwrap(),
        bytes
    );
    assert!(matches!(
        outcome::decode(&bytes, &request),
        Ok(QuoteOutcome::DeviceUnavailable)
    ));
    let mut wrong_version = bytes.clone();
    wrong_version[1] = 3;
    let mut wrong_code = bytes.clone();
    wrong_code[3] = 2;
    let mut wrong_hash = bytes.clone();
    wrong_hash[6] ^= 1;
    let mut duplicate = bytes.clone();
    duplicate.extend_from_slice(&[16, 1]);
    let mut unknown = bytes.clone();
    unknown.extend_from_slice(&[32, 1]);
    for invalid in [
        Vec::new(),
        bytes[..bytes.len() - 1].to_vec(),
        wrong_version,
        wrong_code,
        wrong_hash,
        duplicate,
        unknown,
        vec![0; guest::MAX_QUOTE_RESPONSE_BYTES + 1],
    ] {
        assert!(outcome::decode(&invalid, &request).is_err());
    }
    assert!(outcome::decode(&bytes, &request_for(119)).is_err());
}

#[derive(Clone, PartialEq, Message)]
struct RequestView {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    challenge: Vec<u8>,
}

#[derive(Clone, PartialEq, Message)]
struct ChallengeView {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    nonce: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    public_policy_id: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    expected_measurement: Vec<u8>,
    #[prost(uint32, tag = "5")]
    minimum_guest_svn: u32,
    #[prost(uint64, tag = "6")]
    created_at: u64,
    #[prost(uint64, tag = "7")]
    expires_at: u64,
    #[prost(bytes = "vec", tag = "8")]
    local_policy: Vec<u8>,
}

fn with_window(request: &QuoteRequest, created: u64, expires: u64) -> QuoteRequest {
    let wrapped = RequestView::decode(request.encode().as_slice()).unwrap();
    let mut challenge = ChallengeView::decode(wrapped.challenge.as_slice()).unwrap();
    challenge.created_at = created;
    challenge.expires_at = expires;
    QuoteRequest::from_challenge(&challenge.encode_to_vec()).unwrap()
}

#[test]
fn refusal_rejects_stale_and_future_inner_challenges() {
    let request = request();
    let now = protocol::now().unwrap();
    for request in [
        with_window(&request, now - 60, now - 30),
        with_window(&request, now + 60, now + 90),
    ] {
        assert!(matches!(
            outcome::decode(&refusal(&request), &request),
            Err(QuoteError::Expired)
        ));
        assert!(matches!(
            outcome::encode(&QuoteOutcome::DeviceUnavailable, &request),
            Err(QuoteError::Expired)
        ));
    }
}

#[tokio::test]
async fn original_success_bytes_and_legacy_local_reader_are_unchanged() {
    let request = request();
    let owner = GuestSessionOwner::new(GuestLimits {
        expires_at: protocol::now().unwrap() + 120,
        maximum_attempts: 1,
    })
    .unwrap();
    let quote = owner
        .begin(QuoteRequest::decode(&request.encode()).unwrap())
        .unwrap()
        .collect_source(guest::ReportSource::Fake(Box::new(|data| {
            let mut report = vec![0; 1184];
            report[..4].copy_from_slice(&2_u32.to_le_bytes());
            report[0x50..0x90].copy_from_slice(&data);
            Ok(report)
        })))
        .unwrap();
    let original = quote.response().unwrap().encode();
    let outcome = outcome::decode(&original, &request).unwrap();
    assert!(matches!(outcome, QuoteOutcome::Evidence(_)));
    assert_eq!(outcome::encode(&outcome, &request).unwrap(), original);
    let (mut writer, mut reader) = tokio::io::duplex(4096);
    let (written, read) = tokio::join!(
        write_outcome(&mut writer, &outcome, &request),
        read_response(&mut reader, &request)
    );
    assert!(written.is_ok());
    assert_eq!(read.unwrap().encode(), original);
    assert!(QuoteResponse::decode(&original, &request_for(119)).is_err());
}

#[tokio::test]
async fn legacy_local_reader_refuses_negative_without_reinterpreting_as_evidence() {
    let request = request();
    let (mut writer, mut reader) = tokio::io::duplex(4096);
    let (written, read) = tokio::join!(
        write_outcome(&mut writer, &QuoteOutcome::DeviceUnavailable, &request),
        read_response(&mut reader, &request)
    );
    assert!(written.is_ok());
    assert!(matches!(read, Err(QuoteError::Unavailable)));
    let (mut writer, mut reader) = tokio::io::duplex(16);
    writer
        .write_u32(u32::try_from(guest::MAX_QUOTE_RESPONSE_BYTES + 1).unwrap())
        .await
        .unwrap();
    assert!(matches!(
        read_outcome(&mut reader, &request).await,
        Err(QuoteError::Invalid)
    ));
}

#[tokio::test]
async fn signed_refusal_rejects_outer_substitution_signature_purpose_and_time() {
    for mutation in 0..7 {
        let provider = SigningKey::from_bytes(&[1; 32]);
        let request = request();
        let payload = refusal(&request);
        let (mut client, mut server) = tokio::io::duplex(4096);
        let serving = async {
            let _: crate::provider::Selector =
                crate::provider::read_frame(&mut server).await.unwrap();
            let now = protocol::now().unwrap();
            let challenge = Record::challenge_for(&provider, now - 2, Purpose::QuoteV1).unwrap();
            protocol::write(&mut server, &challenge.encode(), FRAME_OVERHEAD)
                .await
                .unwrap();
            let raw = protocol::read(&mut server, guest::MAX_QUOTE_REQUEST_BYTES + FRAME_OVERHEAD)
                .await
                .unwrap();
            let now = protocol::now().unwrap();
            let signed = Record::decode_for(&raw, Kind::Request, now, Purpose::QuoteV1).unwrap();
            let alternate = if mutation == 2 {
                Record::challenge(&provider, now).unwrap()
            } else {
                Record::challenge_for(&provider, now, Purpose::QuoteV1).unwrap()
            };
            let wrong_provider = SigningKey::from_bytes(&[9; 32]);
            let mut payload = payload;
            if mutation == 5 {
                payload[6] ^= 1;
            }
            let reply = Record::reply(
                if mutation == 0 {
                    &wrong_provider
                } else {
                    &provider
                },
                if matches!(mutation, 1 | 2) {
                    &alternate
                } else {
                    &challenge
                },
                if mutation == 3 {
                    [9; 32]
                } else {
                    Sha256::digest(&raw).into()
                },
                payload,
                if mutation == 6 {
                    signed.created() - 1
                } else {
                    now
                },
            )
            .unwrap();
            let mut bytes = reply.encode();
            if mutation == 4 {
                *bytes.last_mut().unwrap() ^= 1;
            }
            protocol::write(
                &mut server,
                &bytes,
                guest::MAX_QUOTE_RESPONSE_BYTES + FRAME_OVERHEAD,
            )
            .await
            .unwrap();
        };
        let requesting = async {
            let challenge = begin(&mut client, &provider.verifying_key().to_bytes()).await?;
            exchange_outcome(&mut client, challenge, &requester(), &request).await
        };
        let ((), result) = tokio::join!(serving, requesting);
        assert!(result.is_err(), "mutation {mutation}");
    }
}

#[tokio::test]
async fn authorized_refusal_consumes_one_attempt_without_retained_key_or_retry() {
    let (service, _, firmware) = fixture(2);
    let supervisor = start(&service);
    let calls = unavailable(&service);
    let first = request();
    assert!(matches!(
        roundtrip(&service, &requester(), &first, false).await,
        Ok(QuoteOutcome::DeviceUnavailable)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(firmware.available_permits(), 1);
    assert!(service.owner.active_cancellation().is_none());
    assert!(service.retained.lock().unwrap().is_none());
    assert!(matches!(
        service.collect_outcome(first).await,
        Err(QuoteError::Unauthorized)
    ));
    let second_calls = unavailable(&service);
    assert!(matches!(
        roundtrip(&service, &requester(), &request(), false).await,
        Ok(QuoteOutcome::DeviceUnavailable)
    ));
    assert_eq!(second_calls.load(Ordering::SeqCst), 1);
    assert!(matches!(
        service.collect_outcome(request()).await,
        Err(QuoteError::Busy)
    ));
    stop(&service, supervisor).await;
}

#[tokio::test]
async fn legacy_exchange_refuses_signed_negative_without_retry() {
    let (service, _, firmware) = fixture(1);
    let supervisor = start(&service);
    let calls = unavailable(&service);
    assert!(matches!(
        roundtrip(&service, &requester(), &request(), true).await,
        Err(QuoteError::Unavailable)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    assert_eq!(firmware.available_permits(), 1);
    assert!(service.retained.lock().unwrap().is_none());
    stop(&service, supervisor).await;
}

#[tokio::test]
async fn other_collection_errors_do_not_become_device_refusals() {
    for error in [
        GuestError::Firmware,
        GuestError::Unavailable,
        GuestError::Encoding,
        GuestError::Cancelled,
        GuestError::Expired,
    ] {
        let (service, _, firmware) = fixture(1);
        let supervisor = start(&service);
        *service.source.lock().unwrap() = Some(Box::new(move |_| Err(error)));
        assert!(
            roundtrip(&service, &requester(), &request(), false)
                .await
                .is_err()
        );
        assert_eq!(firmware.available_permits(), 1);
        assert!(service.retained.lock().unwrap().is_none());
        stop(&service, supervisor).await;
    }
}

#[tokio::test]
async fn wrong_requester_cannot_probe_device_or_consume_attempt() {
    let (service, _, _) = fixture(1);
    let supervisor = start(&service);
    let calls = unavailable(&service);
    assert!(
        roundtrip(
            &service,
            &SigningKey::from_bytes(&[9; 32]),
            &request(),
            false
        )
        .await
        .is_err()
    );
    assert_eq!(calls.load(Ordering::SeqCst), 0);
    assert!(matches!(
        roundtrip(&service, &requester(), &request(), false).await,
        Ok(QuoteOutcome::DeviceUnavailable)
    ));
    assert_eq!(calls.load(Ordering::SeqCst), 1);
    stop(&service, supervisor).await;
}

#[tokio::test]
async fn authority_revoked_during_collection_prevents_refusal() {
    let (service, authority, firmware) = fixture(1);
    let supervisor = start(&service);
    *service.source.lock().unwrap() = Some(Box::new(move |_| {
        authority.0.store(false, Ordering::SeqCst);
        Err(GuestError::DeviceUnavailable)
    }));
    assert!(
        roundtrip(&service, &requester(), &request(), false)
            .await
            .is_err()
    );
    assert_eq!(firmware.available_permits(), 1);
    assert!(service.retained.lock().unwrap().is_none());
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
    *service.source.lock().unwrap() = Some(Box::new(move |_| {
        let _ = started.send(());
        waiting
            .recv_timeout(Duration::from_secs(8))
            .map_err(|_| GuestError::Firmware)?;
        Err(GuestError::DeviceUnavailable)
    }));
    (observing, Release(Some(release)))
}

#[tokio::test]
async fn cancelled_collection_keeps_permit_until_late_unavailable_return() {
    let (service, _, firmware) = fixture(2);
    let supervisor = start(&service);
    let (started, release) = latched(&service);
    let serving = Arc::clone(&service);
    let task =
        tokio::spawn(async move { roundtrip(&serving, &requester(), &request(), false).await });
    timeout(Duration::from_secs(3), started)
        .await
        .unwrap()
        .unwrap();
    let cancellation = service.owner.active_cancellation().unwrap();
    cancellation.cancel();
    assert!(cancellation.is_erased());
    assert_eq!(firmware.available_permits(), 0);
    assert!(!task.is_finished());
    drop(release);
    assert!(
        timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert_eq!(firmware.available_permits(), 1);
    assert!(service.retained.lock().unwrap().is_none());
    stop(&service, supervisor).await;
}

#[tokio::test]
async fn expired_collection_cannot_publish_late_unavailable_or_release_early() {
    let (service, _, firmware) = fixture(2);
    let supervisor = start(&service);
    let (started, release) = latched(&service);
    let serving = Arc::clone(&service);
    let request = request_for(2);
    let task =
        tokio::spawn(async move { roundtrip(&serving, &requester(), &request, false).await });
    timeout(Duration::from_secs(3), started)
        .await
        .unwrap()
        .unwrap();
    let cancellation = service.owner.active_cancellation().unwrap();
    assert!(
        timeout(Duration::from_secs(4), task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    assert!(cancellation.is_erased());
    assert_eq!(firmware.available_permits(), 0);
    drop(release);
    stop(&service, supervisor).await;
    assert_eq!(firmware.available_permits(), 1);
    assert!(service.retained.lock().unwrap().is_none());
}

#[test]
fn post_collection_cancellation_takes_precedence_over_device_unavailable() {
    let owner = GuestSessionOwner::new(GuestLimits {
        expires_at: protocol::now().unwrap() + 120,
        maximum_attempts: 1,
    })
    .unwrap();
    let session = owner.begin(request()).unwrap();
    let cancellation = session.cancellation();
    assert!(matches!(
        session.collect_source(guest::ReportSource::Fake(Box::new(move |_| {
            cancellation.cancel();
            Err(GuestError::DeviceUnavailable)
        }))),
        Err(GuestError::Cancelled)
    ));
}

#[tokio::test]
async fn post_collection_expiry_takes_precedence_over_device_unavailable() {
    let owner = GuestSessionOwner::new(GuestLimits {
        expires_at: protocol::now().unwrap() + 120,
        maximum_attempts: 1,
    })
    .unwrap();
    let session = owner.begin(request_for(2)).unwrap();
    let deadline = session.deadline();
    let entered = Arc::new(AtomicBool::new(false));
    let entering = Arc::clone(&entered);
    let collecting = tokio::task::spawn_blocking(move || {
        session.collect_source(guest::ReportSource::Fake(Box::new(move |_| {
            entering.store(true, Ordering::SeqCst);
            // Wait for this actual monotonic session deadline, not an arbitrary
            // scheduling delay. No local fake time changes the production clock.
            std::thread::sleep(
                deadline.saturating_duration_since(std::time::Instant::now())
                    + Duration::from_millis(10),
            );
            Err(GuestError::DeviceUnavailable)
        })))
    });
    assert!(matches!(
        timeout(Duration::from_secs(4), collecting)
            .await
            .unwrap()
            .unwrap(),
        Err(GuestError::Expired)
    ));
    assert!(entered.load(Ordering::SeqCst));
    assert!(owner.active_cancellation().is_none());
}

struct RefusalWrite {
    inner: DuplexStream,
    armed: Arc<AtomicBool>,
    revoke: Option<Arc<Authority>>,
}
impl AsyncRead for RefusalWrite {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_read(cx, buf)
    }
}
impl AsyncWrite for RefusalWrite {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if self.armed.load(Ordering::SeqCst) && self.revoke.is_none() {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        Pin::new(&mut self.inner).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        let result = Pin::new(&mut self.inner).poll_flush(cx);
        if result.is_ready()
            && self.armed.load(Ordering::SeqCst)
            && let Some(authority) = &self.revoke
        {
            authority.0.store(false, Ordering::SeqCst);
        }
        result
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.inner).poll_shutdown(cx)
    }
}

async fn refusal_write_case(revoke: bool) {
    let (service, authority, firmware) = fixture(1);
    let supervisor = start(&service);
    let armed = Arc::new(AtomicBool::new(false));
    let arming = Arc::clone(&armed);
    *service.source.lock().unwrap() = Some(Box::new(move |_| {
        arming.store(true, Ordering::SeqCst);
        Err(GuestError::DeviceUnavailable)
    }));
    let mut registry = PublicationRegistry::new();
    registry.set_quote(Arc::clone(&service));
    let (mut client, inner) = tokio::io::duplex(4096);
    let serving = async {
        let mut server = RefusalWrite {
            inner,
            armed,
            revoke: revoke.then_some(authority),
        };
        serve_publication(&mut server, &registry, TransferLimits::default()).await
    };
    let requesting = async {
        let challenge = begin(&mut client, &service.signer.verifying_key().to_bytes()).await?;
        exchange_outcome(&mut client, challenge, &requester(), &request()).await
    };
    let (served, result) = tokio::join!(serving, requesting);
    assert!(served.is_err());
    if revoke {
        // Bytes can already be visible; the provider must still reject final success.
        assert!(matches!(result, Ok(QuoteOutcome::DeviceUnavailable)));
    } else {
        assert!(result.is_err());
    }
    assert_eq!(firmware.available_permits(), 1);
    assert!(service.retained.lock().unwrap().is_none());
    stop(&service, supervisor).await;
}

#[tokio::test]
async fn refusal_write_failure_does_not_retry_or_retain() {
    refusal_write_case(false).await;
}

#[tokio::test]
async fn authority_is_rechecked_after_refusal_write() {
    refusal_write_case(true).await;
}
