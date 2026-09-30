//! Pure protocol and real owned-process lifecycle tests, not recursive DNS evidence.

use std::net::{IpAddr, Ipv4Addr};

use hickory_proto::{
    op::Query,
    rr::{Name, RecordType},
};

use super::session::{
    HEADER_BYTES, MAGIC, MAX_REPLY_BYTES, decode_reply, encode_request, permitted_question,
};
use super::*;
use crate::{DnsPeerBackend, DnsPeerFuture, DnsQueryType, DnsResolutionScope, ExitResolver};

fn nonce() -> [u8; 16] {
    let mut value = [0; 16];
    getrandom::fill(&mut value).unwrap();
    value
}

fn response(nonce: [u8; 16], status: u8, secure: bool, address: Option<Ipv4Addr>) -> Vec<u8> {
    let mut bytes = vec![0; HEADER_BYTES];
    bytes[..8].copy_from_slice(MAGIC);
    bytes[8] = status;
    bytes[16..32].copy_from_slice(&nonce);
    bytes[40..42].copy_from_slice(&1_u16.to_be_bytes());
    bytes[42..44].copy_from_slice(&12_u16.to_be_bytes());
    bytes.extend_from_slice(b"fixture.test");
    if let Some(address) = address {
        bytes[9] = u8::from(secure);
        bytes[10..12].copy_from_slice(&1_u16.to_be_bytes());
        bytes[12..16].copy_from_slice(&12_u32.to_be_bytes());
        bytes.extend_from_slice(&address.octets());
    }
    bytes
}

#[test]
fn private_wire_binds_nonce_question_sequence_size_ttl_and_validator_verdict() {
    let nonce = nonce();
    let name = "fixture.test";
    let encoded = encode_request(name, RecordType::A, nonce, 0).unwrap();
    assert_eq!(&encoded[..8], MAGIC);
    assert_eq!(&encoded[8..12], &[0, 1, 0, 12]);
    assert_eq!(&encoded[12..16], &[0; 4]);
    assert_eq!(&encoded[16..32], &nonce);
    assert_eq!(&encoded[32..], name.as_bytes());
    let origin = Instant::now() - Duration::from_secs(2);
    let start_ms = proof::unix_millis().unwrap() - 2_000;
    let decode =
        |bytes: &[u8]| decode_reply(name, RecordType::A, nonce, 0, bytes, origin, start_ms);
    for secure in [false, true] {
        let bytes = response(nonce, 0, secure, Some(Ipv4Addr::new(93, 184, 216, 34)));
        let answer = decode(&bytes).unwrap().answer.unwrap();
        assert_eq!(
            answer.addresses(),
            ["93.184.216.34".parse::<IpAddr>().unwrap()]
        );
        assert!(answer.ttl_seconds() <= 10);
        assert_eq!(
            answer.source(),
            DnsAnswerSource::PrivateUnbound {
                dnssec_secure: secure
            }
        );
        for index in [8, 9, 10, 16, 32, 36, 40, 42, HEADER_BYTES] {
            let mut altered = bytes.clone();
            altered[index] ^= 0x80;
            assert!(decode(&altered).is_err(), "altered field at {index}");
        }
        let mut zero = bytes.clone();
        zero[12..16].fill(0);
        assert!(decode(&zero).is_err());
        let mut trailing = bytes;
        trailing.push(0);
        assert!(decode(&trailing).is_err());
    }
    for (status, expected) in [
        (1, DnsResolverError::Unavailable),
        (2, DnsResolverError::NameNotFound),
        (3, DnsResolverError::NoData),
        (4, DnsResolverError::Bogus),
        (5, DnsResolverError::InvalidProof),
    ] {
        assert_eq!(
            decode(&response(nonce, status, false, None)).err(),
            Some(expected)
        );
    }
    assert!(decode(&response(nonce, 0, false, Some(Ipv4Addr::LOCALHOST))).is_err());
    assert!(decode(&vec![0; MAX_REPLY_BYTES + 1]).is_err());
    let mut raw = response(nonce, 0, true, Some(Ipv4Addr::new(93, 184, 216, 34)));
    raw[36..40].copy_from_slice(&3_u32.to_be_bytes());
    raw.extend_from_slice(&[1, 2, 3]);
    let evidence = decode(&raw).unwrap().raw.unwrap();
    assert_eq!(evidence.packet, [1, 2, 3]);
    assert_eq!(evidence.started_at_ms, start_ms);
}

#[test]
fn supplemental_queries_are_only_original_question_dnssec_ancestors() {
    let original = DnsQuestion::new("www.fixture.test", DnsQueryType::A).unwrap();
    for (name, kind, sequence, allowed) in [
        ("www.fixture.test.", RecordType::A, 0, true),
        ("www.fixture.test.", RecordType::DNSKEY, 1, true),
        ("fixture.test.", RecordType::DS, 2, true),
        ("test.", RecordType::DNSKEY, 3, true),
        (".", RecordType::DNSKEY, 4, true),
        (".", RecordType::DS, 4, false),
        ("www.fixture.test.", RecordType::A, 1, false),
        ("fixture.test.", RecordType::A, 0, false),
        ("unrelated.test.", RecordType::DNSKEY, 1, false),
        ("ixture.test.", RecordType::DS, 1, false),
    ] {
        let query = Query::query(Name::from_ascii(name).unwrap(), kind);
        assert_eq!(
            permitted_question(&original, &query, sequence).is_ok(),
            allowed
        );
    }
}

// No DNS or native resolver is involved: this owned subprocess exercises actual
// framed pipes, a supplemental reply, EOF and reaping. Cryptographic proof
// validation and packet provenance are tested separately in proof/tests.rs.
fn framed_fixture(secure: bool) -> Child {
    Command::new("/usr/bin/python3")
        .args([
            "-c",
            r"
import sys, struct
def exact(n):
    data = sys.stdin.buffer.read(n)
    if len(data) != n: raise RuntimeError('short fixed fixture request')
    return data
while True:
    first = sys.stdin.buffer.read(1)
    if not first: break
    request = first + exact(31)
    if sys.argv[1] == 'secure' and request[12:16] != bytes(4):
        raise RuntimeError('cache-disabled fixture accepts only the primary request')
    kind, size = struct.unpack('!HH', request[8:12])
    name = exact(size)
    header = bytearray(44)
    header[:8] = request[:8]
    header[9] = int(sys.argv[1] == 'secure')
    header[12:16] = struct.pack('!I', 60)
    header[16:32] = request[16:32]
    header[32:36] = request[12:16]
    header[40:44] = request[8:12]
    payload = bytes([93, 184, 216, 34]) if kind == 1 else b'raw-fixture'
    if kind == 1: header[10:12] = struct.pack('!H', 1)
    else: header[36:40] = struct.pack('!I', len(payload))
    sys.stdout.buffer.write(header + name + payload)
    sys.stdout.buffer.flush()
",
        ])
        .arg(if secure { "secure" } else { "unsigned" })
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap()
}

#[tokio::test]
async fn one_real_pipe_session_keeps_primary_origin_and_closes_after_supplemental_reply() {
    let mut child = framed_fixture(false);
    let pid = child.id().unwrap();
    let question = DnsQuestion::new("fixture.test", DnsQueryType::A).unwrap();
    let session = Session::new(&mut child, question.clone(), nonce()).unwrap();
    let primary = session.request(question.query().unwrap()).await.unwrap();
    assert_eq!(primary.answer.unwrap().addresses().len(), 1);
    assert!(primary.raw.is_none());
    let query = Query::query(Name::from_ascii("test.").unwrap(), RecordType::DNSKEY);
    let supplemental = session.request(query).await.unwrap();
    assert!(supplemental.answer.is_none());
    assert_eq!(supplemental.raw.unwrap().packet, b"raw-fixture");
    session.finish().await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(1), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());

    let mut child = framed_fixture(false);
    let (mut reply, _result) = oneshot::channel();
    let result = supervise(
        &mut child,
        &question,
        nonce(),
        Instant::now() + Duration::from_secs(2),
        true,
        &mut reply,
    )
    .await
    .unwrap();
    assert!(result.proof.is_none());
    assert!(child.try_wait().unwrap().is_some());
}

#[tokio::test]
async fn disabled_cache_returns_native_primary_only_after_owned_process_cleanup() {
    let mut child = framed_fixture(true);
    let question = DnsQuestion::new("fixture.test", DnsQueryType::A).unwrap();
    let (mut reply, _result) = oneshot::channel();
    let answer = supervise(
        &mut child,
        &question,
        nonce(),
        Instant::now() + Duration::from_secs(2),
        false,
        &mut reply,
    )
    .await
    .unwrap();
    assert!(answer.proof.is_none());
    assert_eq!(
        answer.fallback.source(),
        DnsAnswerSource::PrivateUnbound {
            dnssec_secure: true
        }
    );
    assert!(child.try_wait().unwrap().is_some());
}

struct ForbiddenPeer;

impl DnsPeerBackend for ForbiddenPeer {
    fn fetch<'a>(&'a self, _: &'a DnsQuestion, _: &'a DnsResolutionScope) -> DnsPeerFuture<'a> {
        panic!("cache-disabled resolution must not consult a peer")
    }
}

#[tokio::test]
async fn disabled_cache_keeps_private_fallback_and_never_consults_peers_or_system() {
    let resolver = ExitResolver::new(None, Some(Arc::new(ForbiddenPeer)))
        .with_private_unbound_fallback()
        .unwrap()
        .with_cache_enabled(false);
    // An unavailable private backend must remain unavailable; no subprocess/network or
    // OS fallback may occur. A peer call would fail the test before this fixed error.
    resolver
        .private_unbound
        .as_ref()
        .unwrap()
        .0
        .quarantined
        .store(true, Ordering::Release);
    let question = DnsQuestion::new("fixture.test", DnsQueryType::A).unwrap();
    let scope = DnsResolutionScope::new([43; 32], vec![vec![1]]).unwrap();
    assert_eq!(
        resolver.resolve(&question, &scope).await.err(),
        Some(DnsResolverError::CleanupUnconfirmed)
    );
    assert_eq!(resolver.counts().trusted_fallback, 0);
    assert_eq!(resolver.counts().peer_validated, 0);
}

#[tokio::test]
async fn owned_timeout_and_cancel_reap_before_completion_without_network() {
    for cancel in [false, true] {
        let mut child = Command::new("/usr/bin/sleep")
            .arg("30")
            .env_clear()
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let pid = child.id().unwrap();
        let (mut reply, result) = oneshot::channel();
        let deadline = Instant::now() + Duration::from_millis(700);
        if cancel {
            drop(result);
        }
        let question = DnsQuestion::new("fixture.test", DnsQueryType::A).unwrap();
        let answer = supervise(&mut child, &question, nonce(), deadline, true, &mut reply).await;
        assert_eq!(answer.err(), Some(DnsResolverError::Unavailable));
        assert!(Instant::now() < deadline);
        assert!(child.try_wait().unwrap().is_some());
        assert!(
            !std::path::Path::new(&format!("/proc/{pid}")).exists(),
            "exact owned child reaped"
        );
    }
}

#[tokio::test]
async fn reaped_output_is_required_even_when_the_pipe_closes_without_data() {
    let mut child = Command::new("/usr/bin/true")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let pid = child.id().unwrap();
    let (mut reply, _result) = oneshot::channel();
    let question = DnsQuestion::new("fixture.test", DnsQueryType::A).unwrap();
    let result = supervise(
        &mut child,
        &question,
        nonce(),
        Instant::now() + Duration::from_secs(1),
        true,
        &mut reply,
    )
    .await;
    assert_eq!(result.err(), Some(DnsResolverError::Unavailable));
    assert!(child.try_wait().unwrap().is_some());
    assert!(!std::path::Path::new(&format!("/proc/{pid}")).exists());
}
