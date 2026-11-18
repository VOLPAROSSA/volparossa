//! Software-only chain tests. Synthetic report/binding exists only under cfg(test);
//! real HPKE, signed records, selector dispatch and owned lifecycle run unchanged.

use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use std::time::Duration;

use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _, DuplexStream},
    sync::Semaphore,
    task::JoinHandle,
    time::timeout,
};

use super::super::super::{
    attestation::{
        LocalPolicy, MilanTcb, PendingSession, SessionLimits, SessionOwner, SmtPolicy, TcbMinimums,
        synthetic_confirmation_lifetime,
    },
    guest::{GuestError, GuestLimits, QuoteRequest},
    protocol,
};
use super::super::{QuoteAuthority, QuoteAuthorityFuture, QuoteError, QuoteGrant, QuoteService};
use super::*;
use crate::{
    provider::{ProviderError, PublicationRegistry, serve_publication},
    transfer::{TransferLimits, TransferProgress},
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

fn provider() -> [u8; 32] {
    SigningKey::from_bytes(&[1; 32]).verifying_key().to_bytes()
}

fn owner() -> SessionOwner {
    let minimum = MilanTcb {
        bootloader: 0,
        tee: 0,
        snp: 0,
        microcode: 0,
    };
    SessionOwner::new(
        [4; 32],
        LocalPolicy::new(
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
        .unwrap(),
        SessionLimits {
            expires_at: protocol::now().unwrap() + 120,
            maximum_pending: 1,
            maximum_attempts: 2,
        },
    )
    .unwrap()
}

struct Fixture {
    service: Arc<QuoteService>,
    authority: Arc<Authority>,
    firmware: Arc<Semaphore>,
    collections: Arc<AtomicUsize>,
    supervisor: JoinHandle<()>,
}

impl Fixture {
    fn new(confirmation: bool) -> Self {
        Self::with_lifetime(confirmation, 120)
    }

    fn with_lifetime(confirmation: bool, seconds: u64) -> Self {
        let authority = Arc::new(Authority(AtomicBool::new(true)));
        let firmware = Arc::new(Semaphore::new(1));
        let grant = QuoteGrant {
            requester_key: requester().verifying_key().to_bytes(),
            limits: GuestLimits {
                expires_at: protocol::now().unwrap() + seconds,
                maximum_attempts: 1,
            },
        };
        let signer = Arc::new(SigningKey::from_bytes(&[1; 32]));
        let service = if confirmation {
            QuoteService::new_confirmation(signer, grant, firmware.clone(), authority.clone())
        } else {
            QuoteService::new(signer, grant, firmware.clone(), authority.clone())
        }
        .unwrap();
        let collections = Arc::new(AtomicUsize::new(0));
        let count = collections.clone();
        *service.source.lock().unwrap() = Some(Box::new(move |data| {
            count.fetch_add(1, Ordering::SeqCst);
            let mut bytes = vec![0; 1184];
            bytes[..4].copy_from_slice(&2_u32.to_le_bytes());
            bytes[0x50..0x90].copy_from_slice(&data);
            Ok(bytes)
        }));
        let supervisor = tokio::spawn(service.clone().supervise().unwrap());
        Self {
            service,
            authority,
            firmware,
            collections,
            supervisor,
        }
    }

    fn connection(
        &self,
    ) -> (
        DuplexStream,
        JoinHandle<Result<TransferProgress, ProviderError>>,
    ) {
        let mut registry = PublicationRegistry::new();
        registry.set_quote(self.service.clone());
        let (client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_publication(&mut server, &registry, TransferLimits::default()).await
        });
        (client, task)
    }

    async fn stop(self) {
        self.service.deactivate();
        timeout(Duration::from_secs(5), self.supervisor)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(self.firmware.available_permits(), 1);
    }
}

async fn joined(task: JoinHandle<Result<TransferProgress, ProviderError>>) -> bool {
    timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .is_ok()
}

async fn close_tls<S>(stream: &mut S)
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
{
    // Keep both in-memory endpoints alive until each peer's close_notify arrives.
    // Dropping the provider immediately after its write races the client's close.
    timeout(Duration::from_secs(5), async {
        stream.shutdown().await.unwrap();
        assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
    })
    .await
    .unwrap();
}

fn software_prepared(pending: PendingSession<'_>, offer: Offer) -> PreparedConfirmation<'_> {
    let live = synthetic_confirmation_lifetime(pending, *offer.response().unwrap().public_key());
    PreparedConfirmation::from_live(live, offer).unwrap()
}

#[tokio::test]
async fn signed_selector_hpke_confirmation_preserves_open_appraisal_and_releases_slot() {
    let fixture = Fixture::new(true);
    let owner = owner();
    let pending = owner.begin().unwrap();
    let request = QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap();
    let (mut stream, serving) = fixture.connection();
    let mut relay = begin(&mut stream, &provider()).await.unwrap();
    let deadline = relay.deadline();
    let offer = relay.quote(&requester(), &request).await.unwrap();
    let effective_expiry = offer.expires_at();
    assert!(relay.deadline() <= deadline);
    // This constructor is cfg(test) lifetime/binding state, NOT a signed SNP report.
    let prepared = software_prepared(pending, offer);
    assert!(owner.begin().is_err());
    let reply = relay
        .confirm(&requester(), prepared.probe().unwrap())
        .await
        .unwrap();
    let confirmed = prepared.confirm(reply).unwrap();
    assert!(owner.begin().is_err());
    assert!(joined(serving).await);
    let facts = confirmed.finish().unwrap();
    assert_eq!(facts.outstanding_appraisal().len(), 4);
    assert_eq!(facts.expires_at(), effective_expiry);
    assert!(owner.begin().is_ok());
    assert_eq!(fixture.collections.load(Ordering::SeqCst), 1);
    assert!(fixture.service.retained.lock().unwrap().is_none());
    assert_eq!(fixture.firmware.available_permits(), 1);
    fixture.stop().await;
}

#[tokio::test]
async fn old_constructor_never_enables_confirmation_or_calls_firmware() {
    let fixture = Fixture::new(false);
    let (mut stream, serving) = fixture.connection();
    assert!(begin(&mut stream, &provider()).await.is_err());
    assert!(!joined(serving).await);
    assert_eq!(fixture.collections.load(Ordering::SeqCst), 0);
    fixture.stop().await;
}

#[tokio::test]
async fn explicit_confirmation_attachment_does_not_downgrade_to_quote_only() {
    let fixture = Fixture::new(true);
    let (mut stream, serving) = fixture.connection();
    assert!(super::super::begin(&mut stream, &provider()).await.is_err());
    assert!(!joined(serving).await);
    assert_eq!(fixture.collections.load(Ordering::SeqCst), 0);
    fixture.stop().await;
}

#[tokio::test]
async fn confirmation_requires_signed_positive_v3_and_exact_original_expiry_bounds() {
    let fixture = Fixture::new(true);
    let owner = owner();
    let pending = owner.begin().unwrap();
    let request = QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap();
    let (mut stream, serving) = fixture.connection();
    let mut relay = begin(&mut stream, &provider()).await.unwrap();
    let offer = relay.quote(&requester(), &request).await.unwrap();
    for payload in [
        offer.response().unwrap().encode(),
        wire::quote_payload(offer.response().unwrap(), 0),
        wire::quote_payload(offer.response().unwrap(), protocol::now().unwrap()),
        wire::quote_payload(offer.response().unwrap(), request.expires_at() + 1),
    ] {
        let reply = protocol::Record::reply(
            &SigningKey::from_bytes(&[1; 32]),
            &offer.challenge,
            Sha256::digest(offer.request.encode()).into(),
            payload,
            protocol::now().unwrap(),
        )
        .unwrap();
        assert!(
            Offer::decode(
                &Offer::encode_records(&offer.challenge, &offer.request, &reply),
                &provider(),
                &requester().verifying_key().to_bytes(),
                &request,
            )
            .is_err()
        );
    }
    drop(relay);
    drop(stream);
    assert!(!joined(serving).await);
    fixture.stop().await;
}

#[tokio::test]
async fn signed_software_confirmation_runs_over_tls13_without_network_or_hardware_claim() {
    let fixture = Fixture::new(true);
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["confirmation.test".into()]).unwrap();
    let crypto = Arc::new(rustls::crypto::ring::default_provider());
    let server_config = rustls::ServerConfig::builder_with_provider(crypto.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(
            vec![cert.der().clone()],
            rustls::pki_types::PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
        )
        .unwrap();
    let mut roots = rustls::RootCertStore::empty();
    roots.add(cert.der().clone()).unwrap();
    let client_config = rustls::ClientConfig::builder_with_provider(crypto)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(roots)
        .with_no_client_auth();
    let (client, server) = tokio::io::duplex(4096);
    let mut registry = PublicationRegistry::new();
    registry.set_quote(fixture.service.clone());
    let serving = tokio::spawn(async move {
        let mut stream = tokio_rustls::TlsAcceptor::from(Arc::new(server_config))
            .accept(server)
            .await
            .unwrap();
        let result = serve_publication(&mut stream, &registry, TransferLimits::default()).await;
        close_tls(&mut stream).await;
        result
    });
    let connector = tokio_rustls::TlsConnector::from(Arc::new(client_config));
    let mut stream = timeout(
        Duration::from_secs(5),
        connector.connect(
            rustls::pki_types::ServerName::try_from("confirmation.test").unwrap(),
            client,
        ),
    )
    .await
    .unwrap()
    .unwrap();
    let owner = owner();
    let pending = owner.begin().unwrap();
    let request = QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap();
    let mut relay = begin(&mut stream, &provider()).await.unwrap();
    let offer = relay.quote(&requester(), &request).await.unwrap();
    let prepared = software_prepared(pending, offer);
    let reply = relay
        .confirm(&requester(), prepared.probe().unwrap())
        .await
        .unwrap();
    let confirmed = prepared.confirm(reply).unwrap();
    close_tls(&mut stream).await;
    assert!(joined(serving).await);
    assert_eq!(confirmed.finish().unwrap().outstanding_appraisal().len(), 4);
    fixture.stop().await;
}

#[tokio::test]
async fn wrong_requester_rejects_before_collection() {
    let fixture = Fixture::new(true);
    let owner = owner();
    let pending = owner.begin().unwrap();
    let request = QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap();
    let (mut stream, serving) = fixture.connection();
    let mut relay = begin(&mut stream, &provider()).await.unwrap();
    assert!(
        relay
            .quote(&SigningKey::from_bytes(&[8; 32]), &request)
            .await
            .is_err()
    );
    drop(relay);
    assert!(!joined(serving).await);
    assert_eq!(fixture.collections.load(Ordering::SeqCst), 0);
    fixture.stop().await;
}

#[tokio::test]
async fn original_offer_checks_wrong_provider_requester_request_and_unknown_fields() {
    let fixture = Fixture::new(true);
    let owner = owner();
    let pending = owner.begin().unwrap();
    let request = QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap();
    let (mut stream, serving) = fixture.connection();
    let mut relay = begin(&mut stream, &provider()).await.unwrap();
    let offer = relay.quote(&requester(), &request).await.unwrap();
    let raw = offer.encode();
    let requester_key = requester().verifying_key().to_bytes();
    assert!(Offer::decode(&raw, &[9; 32], &requester_key, &request).is_err());
    assert!(Offer::decode(&raw, &provider(), &[9; 32], &request).is_err());
    let other = self::owner();
    let other_pending = other.begin().unwrap();
    let other_request = QuoteRequest::from_challenge(other_pending.challenge_bytes()).unwrap();
    assert!(Offer::decode(&raw, &provider(), &requester_key, &other_request).is_err());
    let mut noncanonical = raw;
    noncanonical.extend_from_slice(&[0x78, 1]);
    assert!(Offer::decode(&noncanonical, &provider(), &requester_key, &request).is_err());
    drop(relay);
    drop(stream);
    assert!(!joined(serving).await);
    fixture.stop().await;
}

#[tokio::test]
async fn production_verifier_rejects_synthetic_report_before_any_probe() {
    let fixture = Fixture::new(true);
    let owner = owner();
    let pending = owner.begin().unwrap();
    let request = QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap();
    let (mut stream, serving) = fixture.connection();
    let mut relay = begin(&mut stream, &provider()).await.unwrap();
    let offer = relay.quote(&requester(), &request).await.unwrap();
    let vcek = include_bytes!("../../../../../tests/fixtures/snp/vcek_milan.der");
    assert!(
        pending
            .prepare_confirmation(offer, vcek, b"not a CRL")
            .is_err()
    );
    drop(relay);
    drop(stream);
    assert!(!joined(serving).await);
    assert!(owner.begin().is_ok());
    fixture.stop().await;
}

#[tokio::test]
async fn fixed_device_refusal_remains_signed_but_cannot_enter_confirmation() {
    let fixture = Fixture::new(true);
    *fixture.service.source.lock().unwrap() =
        Some(Box::new(|_| Err(GuestError::DeviceUnavailable)));
    let owner = owner();
    let pending = owner.begin().unwrap();
    let request = QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap();
    let (mut stream, serving) = fixture.connection();
    let mut relay = begin(&mut stream, &provider()).await.unwrap();
    let offer = relay.quote(&requester(), &request).await.unwrap();
    assert!(offer.is_device_unavailable());
    assert!(pending.prepare_confirmation(offer, &[], &[]).is_err());
    drop(relay);
    assert!(joined(serving).await);
    fixture.stop().await;
}

#[tokio::test]
async fn corrupted_probe_is_not_echoed_and_key_slot_is_released_without_retry() {
    let fixture = Fixture::new(true);
    let owner = owner();
    let pending = owner.begin().unwrap();
    let request = QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap();
    let (mut stream, serving) = fixture.connection();
    let mut relay = begin(&mut stream, &provider()).await.unwrap();
    let offer = relay.quote(&requester(), &request).await.unwrap();
    let prepared = software_prepared(pending, offer);
    let mut probe = Probe::decode(&prepared.probe().unwrap().encode()).unwrap();
    probe.ciphertext[0] ^= 1;
    assert!(relay.confirm(&requester(), &probe).await.is_err());
    assert!(!joined(serving).await);
    assert!(
        fixture
            .service
            .owner
            .begin(QuoteRequest::decode(&request.encode()).unwrap())
            .is_err()
    );
    assert_eq!(fixture.collections.load(Ordering::SeqCst), 1);
    fixture.stop().await;
}

#[tokio::test]
async fn owner_cancellation_rejects_prepared_probe_and_late_terminal_finish() {
    let fixture = Fixture::new(true);
    let owner = owner();
    let pending = owner.begin().unwrap();
    let request = QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap();
    let (mut stream, serving) = fixture.connection();
    let mut relay = begin(&mut stream, &provider()).await.unwrap();
    let offer = relay.quote(&requester(), &request).await.unwrap();
    let prepared = software_prepared(pending, offer);
    let reply = relay
        .confirm(&requester(), prepared.probe().unwrap())
        .await
        .unwrap();
    let confirmed = prepared.confirm(reply).unwrap();
    assert!(joined(serving).await);
    owner.cancel();
    assert!(confirmed.finish().is_err());
    fixture.stop().await;
}

#[tokio::test]
async fn cancellation_before_probe_never_releases_generated_bytes() {
    let fixture = Fixture::new(true);
    let owner = owner();
    let pending = owner.begin().unwrap();
    let request = QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap();
    let (mut stream, serving) = fixture.connection();
    let mut relay = begin(&mut stream, &provider()).await.unwrap();
    let offer = relay.quote(&requester(), &request).await.unwrap();
    let prepared = software_prepared(pending, offer);
    owner.cancel();
    assert!(prepared.probe().is_err());
    drop(relay);
    drop(stream);
    assert!(!joined(serving).await);
    fixture.stop().await;
}

#[tokio::test]
async fn shorter_provider_grant_caps_original_deadline_and_rejects_late_echo() {
    let fixture = Fixture::with_lifetime(true, 5);
    let owner = owner();
    let pending = owner.begin().unwrap();
    let original = pending.deadline().unwrap();
    let request = QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap();
    let (mut stream, serving) = fixture.connection();
    let mut relay = begin(&mut stream, &provider()).await.unwrap();
    let offer = relay.quote(&requester(), &request).await.unwrap();
    assert!(offer.deadline() < original);
    let prepared = software_prepared(pending, offer);
    assert!(prepared.deadline() < original);
    let reply = relay
        .confirm(&requester(), prepared.probe().unwrap())
        .await
        .unwrap();
    assert!(joined(serving).await);
    tokio::time::sleep_until(prepared.deadline() + Duration::from_millis(1)).await;
    assert!(prepared.confirm(reply).is_err());
    fixture.stop().await;
}

#[tokio::test]
async fn final_ack_cannot_extend_shorter_provider_grant() {
    let fixture = Fixture::with_lifetime(true, 5);
    let owner = owner();
    let pending = owner.begin().unwrap();
    let original = pending.deadline().unwrap();
    let request = QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap();
    let (mut stream, serving) = fixture.connection();
    let mut relay = begin(&mut stream, &provider()).await.unwrap();
    let offer = relay.quote(&requester(), &request).await.unwrap();
    let prepared = software_prepared(pending, offer);
    let reply = relay
        .confirm(&requester(), prepared.probe().unwrap())
        .await
        .unwrap();
    let confirmed = prepared.confirm(reply).unwrap();
    assert!(confirmed.deadline() < original);
    assert!(joined(serving).await);
    tokio::time::sleep_until(confirmed.deadline() + Duration::from_millis(1)).await;
    assert!(confirmed.finish().is_err());
    fixture.stop().await;
}

#[tokio::test]
async fn signed_reply_from_another_connection_cannot_confirm_this_probe() {
    let first = Fixture::new(true);
    let second = Fixture::new(true);
    let owner_a = owner();
    let owner_b = owner();
    let pending_a = owner_a.begin().unwrap();
    let pending_b = owner_b.begin().unwrap();
    let request_a = QuoteRequest::from_challenge(pending_a.challenge_bytes()).unwrap();
    let request_b = QuoteRequest::from_challenge(pending_b.challenge_bytes()).unwrap();
    let (mut stream_a, serving_a) = first.connection();
    let (mut stream_b, serving_b) = second.connection();
    let mut relay_a = begin(&mut stream_a, &provider()).await.unwrap();
    let mut relay_b = begin(&mut stream_b, &provider()).await.unwrap();
    let offer_a = relay_a.quote(&requester(), &request_a).await.unwrap();
    let offer_b = relay_b.quote(&requester(), &request_b).await.unwrap();
    let prepared_a = software_prepared(pending_a, offer_a);
    let prepared_b = software_prepared(pending_b, offer_b);
    assert!(prepared_a.probe().unwrap().context != prepared_b.probe().unwrap().context);
    let reply = relay_a
        .confirm(&requester(), prepared_a.probe().unwrap())
        .await
        .unwrap();
    assert!(prepared_b.confirm(reply).is_err());
    assert!(joined(serving_a).await);
    drop(relay_b);
    drop(stream_b);
    assert!(!joined(serving_b).await);
    first.stop().await;
    second.stop().await;
}

#[tokio::test]
async fn corrupted_signed_reply_cannot_become_key_confirmation() {
    let fixture = Fixture::new(true);
    let owner = owner();
    let pending = owner.begin().unwrap();
    let request = QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap();
    let (mut stream, serving) = fixture.connection();
    let mut relay = begin(&mut stream, &provider()).await.unwrap();
    let offer = relay.quote(&requester(), &request).await.unwrap();
    let prepared = software_prepared(pending, offer);
    let mut reply = relay
        .confirm(&requester(), prepared.probe().unwrap())
        .await
        .unwrap();
    let last = reply.reply.last_mut().unwrap();
    *last ^= 1;
    assert!(prepared.confirm(reply).is_err());
    assert!(joined(serving).await);
    fixture.stop().await;
}

#[tokio::test]
async fn provider_signature_without_the_correct_random_echo_is_not_possession() {
    use prost::Message as _;
    use protocol::{Kind, Purpose, Record};

    let fixture = Fixture::new(true);
    let owner = owner();
    let pending = owner.begin().unwrap();
    let request = QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap();
    let (mut stream, serving) = fixture.connection();
    let mut relay = begin(&mut stream, &provider()).await.unwrap();
    let offer = relay.quote(&requester(), &request).await.unwrap();
    let challenge = Record::decode_for(
        &offer.challenge.encode(),
        Kind::Challenge,
        protocol::now().unwrap(),
        Purpose::QuoteConfirmationV1,
    )
    .unwrap();
    let prepared = software_prepared(pending, offer);
    let mut reply = relay
        .confirm(&requester(), prepared.probe().unwrap())
        .await
        .unwrap();
    let original = Record::decode_for(
        &reply.reply,
        Kind::Reply,
        protocol::now().unwrap(),
        Purpose::QuoteConfirmationV1,
    )
    .unwrap();
    let mut echo = wire::Echo::decode(original.payload()).unwrap();
    echo.value[0] ^= 1;
    reply.reply = Record::reply(
        &SigningKey::from_bytes(&[1; 32]),
        &challenge,
        Sha256::digest(&reply.request).into(),
        echo.encode_to_vec(),
        protocol::now().unwrap(),
    )
    .unwrap()
    .encode();
    assert!(prepared.confirm(reply).is_err());
    assert!(joined(serving).await);
    fixture.stop().await;
}

#[tokio::test]
async fn framing_rejects_truncated_offer_probe_and_reply_without_fallback() {
    for maximum in [MAX_OFFER_BYTES, MAX_PROBE_BYTES, MAX_REPLY_BYTES] {
        let (mut client, mut server) = tokio::io::duplex(32);
        server
            .write_u32(u32::try_from(maximum).unwrap())
            .await
            .unwrap();
        server.write_all(&[8, 1]).await.unwrap();
        server.shutdown().await.unwrap();
        assert!(protocol::read(&mut client, maximum).await.is_err());
    }
}

#[tokio::test]
async fn provider_revocation_after_quote_rejects_probe_and_preserves_real_cleanup() {
    let fixture = Fixture::new(true);
    let owner = owner();
    let pending = owner.begin().unwrap();
    let request = QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap();
    let (mut stream, serving) = fixture.connection();
    let mut relay = begin(&mut stream, &provider()).await.unwrap();
    let offer = relay.quote(&requester(), &request).await.unwrap();
    let prepared = software_prepared(pending, offer);
    fixture.authority.0.store(false, Ordering::SeqCst);
    assert!(
        relay
            .confirm(&requester(), prepared.probe().unwrap())
            .await
            .is_err()
    );
    assert!(!joined(serving).await);
    fixture.stop().await;
}

#[tokio::test]
async fn local_eof_after_quote_cleans_session_without_waiting_for_deadline() {
    let fixture = Fixture::new(true);
    let owner = owner();
    let pending = owner.begin().unwrap();
    let request = QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap();
    let (mut stream, serving) = fixture.connection();
    let mut relay = begin(&mut stream, &provider()).await.unwrap();
    relay.quote(&requester(), &request).await.unwrap();
    drop(relay);
    stream.shutdown().await.unwrap();
    assert!(!joined(serving).await);
    assert_eq!(fixture.firmware.available_permits(), 1);
    fixture.stop().await;
}

#[test]
fn bounded_probe_and_reply_decode_never_accept_unknown_or_duplicate_fields() {
    let probe = Probe {
        context: [1; 32],
        encapsulated: [2; 32],
        ciphertext: [3; 48],
    };
    for suffix in [&[0x78, 1][..], &[8, 1][..]] {
        let mut raw = probe.encode();
        raw.extend_from_slice(suffix);
        assert!(Probe::decode(&raw).is_err());
        let reply = ConfirmationReply {
            request: vec![1],
            reply: vec![2],
        };
        let mut raw = reply.encode();
        raw.extend_from_slice(suffix);
        assert!(ConfirmationReply::decode(&raw).is_err());
    }
    assert!(Probe::decode(&vec![0; MAX_PROBE_BYTES + 1]).is_err());
    assert!(ConfirmationReply::decode(&vec![0; MAX_REPLY_BYTES + 1]).is_err());
}
