//! Software lifecycle and wire tests only. All successful report acquisition here
//! uses cfg(test) synthetic bytes, not firmware, an approved image or admission.

use std::sync::{
    atomic::{AtomicBool, Ordering},
    mpsc,
};

use prost::Message as _;

use super::*;
use crate::provider::compute::attestation::{
    LocalPolicy, MilanTcb, SessionLimits, SessionOwner, SmtPolicy, TcbMinimums,
    verify_milan_v2_signature_facts,
};

#[derive(Clone, PartialEq, prost::Message)]
struct TestChallenge {
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

#[derive(Clone, PartialEq, prost::Message)]
struct TestResponse {
    #[prost(uint32, tag = "1")]
    version: u32,
    #[prost(bytes = "vec", tag = "2")]
    challenge_sha256: Vec<u8>,
    #[prost(bytes = "vec", tag = "3")]
    public_key: Vec<u8>,
    #[prost(bytes = "vec", tag = "4")]
    report: Vec<u8>,
}

fn request() -> QuoteRequest {
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
            expires_at: Stamp::now().unwrap().unix + 120,
            maximum_pending: 1,
            maximum_attempts: 1,
        },
    )
    .unwrap();
    let pending = verifier.begin().unwrap();
    QuoteRequest::from_challenge(pending.challenge_bytes()).unwrap()
}

fn owner(attempts: u16) -> GuestSessionOwner {
    GuestSessionOwner::new(GuestLimits {
        expires_at: Stamp::now().unwrap().unix + 120,
        maximum_attempts: attempts,
    })
    .unwrap()
}

fn request_at(created: u64, expires: u64) -> QuoteRequest {
    let mut fields = TestChallenge::decode(request().challenge.as_slice()).unwrap();
    fields.created_at = created;
    fields.expires_at = expires;
    QuoteRequest::from_challenge(&fields.encode_to_vec()).unwrap()
}

fn synthetic_report(data: [u8; 64]) -> Vec<u8> {
    let mut raw = vec![0; 1184];
    raw[..4].copy_from_slice(&2_u32.to_le_bytes());
    raw[0x50..0x90].copy_from_slice(&data);
    raw
}

fn synthetic_source() -> ReportSource {
    ReportSource::Fake(Box::new(|data| Ok(synthetic_report(data))))
}

fn erased(handle: &GuestCancellation) -> bool {
    handle.0.0.lock().unwrap().is_none()
}

#[test]
fn guest_owner_limits_are_local_bounded_and_nondefault() {
    let now = Stamp::now().unwrap();
    for (seconds, attempts) in [(0, 1), (601, 1), (1, 0), (1, 65)] {
        assert!(matches!(
            GuestSessionOwner::new_at(
                GuestLimits {
                    expires_at: now.unix + seconds,
                    maximum_attempts: attempts,
                },
                now,
            ),
            Err(GuestError::Configuration)
        ));
    }
    assert!(
        GuestSessionOwner::new_at(
            GuestLimits {
                expires_at: now.unix + 600,
                maximum_attempts: 64,
            },
            now,
        )
        .is_ok()
    );
}

#[test]
fn guest_request_reuses_exact_challenge_v2_encoding() {
    let request = request();
    let encoded = request.encode();
    assert!(encoded.len() <= MAX_QUOTE_REQUEST_BYTES);
    let decoded = QuoteRequest::decode(&encoded).unwrap();
    assert_eq!(decoded.challenge, request.challenge);
    let valid = TestChallenge::decode(request.challenge.as_slice()).unwrap();
    for version in [0, 1, 3] {
        let mut fields = valid.clone();
        fields.version = version;
        assert!(matches!(
            QuoteRequest::from_challenge(&fields.encode_to_vec()),
            Err(GuestError::Encoding)
        ));
    }
    let mut missing_policy = valid.clone();
    missing_policy.local_policy.clear();
    assert!(QuoteRequest::from_challenge(&missing_policy.encode_to_vec()).is_err());
    let mut too_long = valid.clone();
    too_long.expires_at = too_long.created_at + 31;
    assert!(QuoteRequest::from_challenge(&too_long.encode_to_vec()).is_err());
    let mut invalid_policy = valid;
    invalid_policy.local_policy[17] = 2;
    assert!(QuoteRequest::from_challenge(&invalid_policy.encode_to_vec()).is_err());
}

#[test]
fn guest_request_rejects_unknown_noncanonical_and_oversized_bytes() {
    let request = request();
    let mut unknown = request.encode();
    unknown.extend_from_slice(&[0x18, 1]);
    let mut duplicate = request.encode();
    duplicate.extend_from_slice(&[0x08, 1]);
    let mut noncanonical = request.encode();
    noncanonical.splice(1..2, [0x81, 0]);
    let mut unsupported = request.encode();
    unsupported[1] = 2;
    for raw in [
        vec![],
        vec![0; MAX_QUOTE_REQUEST_BYTES + 1],
        unknown,
        duplicate,
        noncanonical,
        unsupported,
    ] {
        assert!(matches!(
            QuoteRequest::decode(&raw),
            Err(GuestError::Encoding)
        ));
    }
    let mut unknown_challenge = request.challenge;
    unknown_challenge.extend_from_slice(&[0x48, 1]);
    assert!(QuoteRequest::from_challenge(&unknown_challenge).is_err());
}

#[test]
fn guest_begin_enforces_both_clocks_and_challenge_window() {
    let now = Stamp::now().unwrap();
    let owner = GuestSessionOwner::new_at(
        GuestLimits {
            expires_at: now.unix + 60,
            maximum_attempts: 10,
        },
        now,
    )
    .unwrap();
    for (created, expires) in [
        (now.unix + 1, now.unix + 30),
        (now.unix - 1, now.unix),
        (0, 30),
    ] {
        assert!(matches!(
            owner.begin_at(request_at(created, expires), now),
            Err(GuestError::Expired)
        ));
    }
    for observed in [
        Stamp {
            unix: now.unix - 1,
            ..now
        },
        Stamp {
            unix: now.unix + 60,
            ..now
        },
        Stamp {
            monotonic: now.monotonic + Duration::from_secs(60),
            ..now
        },
        Stamp {
            monotonic: now.monotonic.checked_sub(Duration::from_secs(1)).unwrap(),
            ..now
        },
    ] {
        assert!(matches!(
            owner.begin_at(request_at(now.unix, now.unix + 30), observed),
            Err(GuestError::Expired)
        ));
    }
    let session = owner
        .begin_at(request_at(now.unix, now.unix + 30), now)
        .unwrap();
    let cancellation = session.cancellation();
    assert_eq!(
        session.check_at(Stamp {
            monotonic: now.monotonic + Duration::from_secs(30),
            ..now
        }),
        Err(GuestError::Expired)
    );
    assert!(erased(&cancellation));
}

#[test]
fn guest_capacity_and_attempts_remain_owned_until_drop() {
    let owner = owner(2);
    let first = owner.begin(request()).unwrap();
    assert!(matches!(owner.begin(request()), Err(GuestError::Budget)));
    let cancellation = first.cancellation();
    drop(first);
    assert!(erased(&cancellation));
    let collected = owner
        .begin(request())
        .unwrap()
        .collect_source(synthetic_source())
        .unwrap();
    assert!(matches!(owner.begin(request()), Err(GuestError::Budget)));
    let cancellation = collected.cancellation();
    drop(collected);
    assert!(erased(&cancellation));
    assert!(matches!(owner.begin(request()), Err(GuestError::Budget)));
}

#[test]
fn guest_replay_stays_rejected_after_cancel_and_failure() {
    let owner = owner(4);
    let first = request().encode();
    owner
        .begin(QuoteRequest::decode(&first).unwrap())
        .unwrap()
        .cancel();
    assert!(matches!(
        owner.begin(QuoteRequest::decode(&first).unwrap()),
        Err(GuestError::Replay)
    ));
    let second = request().encode();
    let session = owner.begin(QuoteRequest::decode(&second).unwrap()).unwrap();
    assert!(matches!(
        session.collect_source(ReportSource::Fake(Box::new(|_| Err(GuestError::Firmware)))),
        Err(GuestError::Firmware)
    ));
    assert!(matches!(
        owner.begin(QuoteRequest::decode(&second).unwrap()),
        Err(GuestError::Replay)
    ));
}

#[test]
fn guest_keys_are_generated_fresh() {
    let owner = owner(2);
    let first = owner.begin(request()).unwrap();
    let public = first.public_key;
    assert_ne!(public, [0; 32]);
    let cancellation = first.cancellation();
    drop(first);
    let second = owner.begin(request()).unwrap();
    assert_ne!(second.public_key, public);
    cancellation.cancel(); // An old handle cannot cancel the replacement session.
    assert!(second.key.check().is_ok());
}

#[test]
fn guest_cancel_erases_key_before_or_after_collection() {
    let owner = owner(2);
    let before = owner.begin(request()).unwrap();
    let cancellation = before.cancellation();
    cancellation.cancel();
    assert!(erased(&cancellation));
    let never_called =
        ReportSource::Fake(Box::new(|_| panic!("cancelled request reached firmware")));
    assert!(matches!(
        before.collect_source(never_called),
        Err(GuestError::Cancelled)
    ));
    let after = owner
        .begin(request())
        .unwrap()
        .collect_source(synthetic_source())
        .unwrap();
    let cancellation = after.cancellation();
    cancellation.cancel();
    assert!(erased(&cancellation));
    assert!(matches!(after.response(), Err(GuestError::Cancelled)));
    assert!(matches!(owner.begin(request()), Err(GuestError::Budget)));
    drop(after);
}

#[test]
fn guest_owner_cancel_invalidates_current_and_future_sessions() {
    let owner = owner(3);
    let session = owner.begin(request()).unwrap();
    let cancellation = session.cancellation();
    owner.cancel();
    assert!(erased(&cancellation));
    assert!(matches!(
        session.collect_source(synthetic_source()),
        Err(GuestError::Cancelled)
    ));
    assert!(matches!(owner.begin(request()), Err(GuestError::Cancelled)));
}

#[test]
fn guest_inflight_cancel_retains_slot_until_firmware_returns() {
    let owner = owner(3);
    let session = owner.begin(request()).unwrap();
    let cancellation = session.cancellation();
    let (started_tx, started_rx) = mpsc::channel();
    let (finish_tx, finish_rx) = mpsc::channel();
    std::thread::scope(|scope| {
        let worker = scope.spawn(move || {
            session.collect_source(ReportSource::Fake(Box::new(move |data| {
                started_tx.send(()).unwrap();
                finish_rx.recv_timeout(Duration::from_secs(5)).unwrap();
                Ok(synthetic_report(data))
            })))
        });
        started_rx.recv_timeout(Duration::from_secs(5)).unwrap();
        cancellation.cancel();
        assert!(erased(&cancellation));
        assert!(matches!(owner.begin(request()), Err(GuestError::Budget)));
        finish_tx.send(()).unwrap();
        assert!(matches!(worker.join().unwrap(), Err(GuestError::Cancelled)));
    });
    assert!(owner.begin(request()).is_ok());
}

#[test]
fn guest_expiry_during_collection_rejects_and_erases() {
    let owner = owner(2);
    let mut session = owner.begin(request()).unwrap();
    let cancellation = session.cancellation();
    // Test-only shortening, not a production extension or wall-clock injection.
    let deadline = Instant::now() + Duration::from_millis(250);
    session.deadline = deadline;
    let entered = Arc::new(AtomicBool::new(false));
    let entered_source = Arc::clone(&entered);
    let result = session.collect_source(ReportSource::Fake(Box::new(move |data| {
        entered_source.store(true, Ordering::SeqCst);
        while Instant::now() < deadline {
            std::thread::sleep(Duration::from_millis(10));
        }
        Ok(synthetic_report(data))
    })));
    assert!(entered.load(Ordering::SeqCst));
    assert!(matches!(result, Err(GuestError::Expired)));
    assert!(erased(&cancellation));
    assert!(owner.begin(request()).is_ok());
}

#[test]
fn guest_report_preserves_bytes_and_refuses_unsupported_versions() {
    let request = request();
    let key = [2; 32];
    let mut raw = synthetic_report(session_report_data(&request.challenge, &key).unwrap());
    raw[300] = 19; // Deliberately unappraised bytes remain unchanged, not normalized.
    let quote = QuoteResponse::new(&request, key, raw.clone()).unwrap();
    assert_eq!(quote.report(), raw);
    for version in [0_u32, 1, 3, 4, 5, u32::MAX] {
        let mut modern = raw.clone();
        modern[..4].copy_from_slice(&version.to_le_bytes());
        assert!(matches!(
            QuoteResponse::new(&request, key, modern),
            Err(GuestError::UnsupportedReport(actual)) if actual == version
        ));
    }
}

#[test]
fn guest_report_refuses_wrong_lengths_vmpl_and_report_data() {
    let request = request();
    let key = [2; 32];
    let raw = synthetic_report(session_report_data(&request.challenge, &key).unwrap());
    for length in [0, 1183, 1185] {
        assert!(matches!(
            QuoteResponse::new(&request, key, vec![0; length]),
            Err(GuestError::ReportBinding)
        ));
    }
    for offset in [0x30, 0x33, 0x50, 0x8f] {
        let mut changed = raw.clone();
        changed[offset] ^= 1;
        assert!(matches!(
            QuoteResponse::new(&request, key, changed),
            Err(GuestError::ReportBinding)
        ));
    }
    assert!(QuoteResponse::new(&request, [0; 32], raw.clone()).is_err());
    assert!(QuoteResponse::new(&request, [3; 32], raw).is_err());
}

#[test]
fn guest_response_enforces_canonical_binding_and_bounds() {
    let request = request();
    let raw = synthetic_report(session_report_data(&request.challenge, &[2; 32]).unwrap());
    let quote = QuoteResponse::new(&request, [2; 32], raw).unwrap();
    let bytes = quote.encode();
    assert!(bytes.len() <= MAX_QUOTE_RESPONSE_BYTES);
    assert!(QuoteResponse::decode(&bytes, &request).is_ok());
    assert!(
        QuoteResponse::decode(&bytes, &request_at(request.created_at, request.expires_at)).is_err()
    );
    let valid = TestResponse::decode(bytes.as_slice()).unwrap();
    let mut wrong_hash = valid.clone();
    wrong_hash.challenge_sha256[0] ^= 1;
    let mut wrong_key = valid.clone();
    wrong_key.public_key[0] ^= 1;
    let mut missing_key = valid.clone();
    missing_key.public_key.clear();
    let mut wrong_version = valid;
    wrong_version.version = 2;
    let mut unknown = bytes.clone();
    unknown.extend_from_slice(&[0x28, 1]);
    let mut duplicate = bytes.clone();
    duplicate.extend_from_slice(&[8, 1]);
    let mut noncanonical = bytes;
    noncanonical.splice(1..2, [0x81, 0]);
    for invalid in [
        vec![],
        vec![0; MAX_QUOTE_RESPONSE_BYTES + 1],
        wrong_hash.encode_to_vec(),
        wrong_key.encode_to_vec(),
        missing_key.encode_to_vec(),
        wrong_version.encode_to_vec(),
        unknown,
        duplicate,
        noncanonical,
    ] {
        assert!(QuoteResponse::decode(&invalid, &request).is_err());
    }
}

#[test]
fn guest_firmware_errors_have_no_quote_or_fallback() {
    let owner = owner(2);
    for error in [GuestError::DeviceUnavailable, GuestError::Firmware] {
        let session = owner.begin(request()).unwrap();
        let cancellation = session.cancellation();
        let result = session.collect_source(ReportSource::Fake(Box::new(move |_| Err(error))));
        assert!(matches!(
            result,
            Err(GuestError::DeviceUnavailable | GuestError::Firmware)
        ));
        assert!(erased(&cancellation));
        assert!(owner.inner.state.lock().unwrap().active.is_none());
    }
}

#[test]
fn guest_quote_wire_roundtrip_does_not_create_verified_evidence() {
    let owner = owner(1);
    let original = request();
    let request_bytes = original.encode();
    let collected = owner
        .begin(QuoteRequest::decode(&request_bytes).unwrap())
        .unwrap()
        .collect_source(synthetic_source())
        .unwrap();
    let bytes = collected.response().unwrap().encode();
    let decoded = QuoteResponse::decode(&bytes, &original).unwrap();
    assert_eq!(decoded.public_key(), &collected.session.public_key);
    let vcek = include_bytes!("../../../../tests/fixtures/snp/vcek_milan.der");
    assert!(verify_milan_v2_signature_facts(decoded.report(), vcek).is_err());
    // Conversely, an authentic old report cannot answer this new challenge.
    let historical = hex::decode(include_bytes!(
        "../../../../tests/fixtures/snp/report_milan.hex"
    ))
    .unwrap();
    assert!(matches!(
        QuoteResponse::new(&original, *decoded.public_key(), historical),
        Err(GuestError::ReportBinding)
    ));
}
