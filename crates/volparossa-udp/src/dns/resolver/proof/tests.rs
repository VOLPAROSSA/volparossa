use std::{
    net::{Ipv4Addr, Ipv6Addr},
    process::Command,
    time::Duration,
};

use hickory_proto::{
    dnssec::{
        Algorithm, DigestType, SigSigner, SigningKey, TBS,
        crypto::Ed25519SigningKey,
        rdata::{DNSKEY, DS, RRSIG},
    },
    rr::{
        Name, Record,
        rdata::{A, AAAA},
    },
};
use tokio::{
    net::TcpListener,
    time::{Instant, timeout},
};

use super::*;
use crate::{DnsAnswerSource, DnsQueryType, DnsResolutionScope, ExitResolver};

struct Fixture {
    bundle: DnsProofBundle,
    anchors: Arc<TrustAnchors>,
}

fn signer(name: Name) -> SigSigner {
    let pkcs8 = Ed25519SigningKey::generate_pkcs8().expect("ephemeral fixture key");
    let key = Ed25519SigningKey::from_pkcs8(&pkcs8).unwrap();
    let dnskey = DNSKEY::new(true, true, false, key.to_public_key().unwrap());
    SigSigner::dnssec(dnskey, Box::new(key), name, Duration::from_secs(120))
}

fn signed_message(records: Vec<Record>, signer: &SigSigner, now: u32) -> Message {
    let name = records[0].name().clone();
    let kind = records[0].record_type();
    let signature = |bytes| {
        RRSIG::new(
            kind,
            Algorithm::ED25519,
            name.num_labels(),
            60,
            now + 120,
            now - 60,
            signer.calculate_key_tag().unwrap(),
            signer.signer_name().clone(),
            bytes,
        )
    };
    let unsigned = Record::from_rdata(name.clone(), 60, signature(Vec::new()));
    let signature_bytes = signer
        .sign(&TBS::from_rrsig(&unsigned, records.iter()).unwrap())
        .unwrap();
    let mut message = Message::new();
    message
        .set_message_type(MessageType::Response)
        .set_response_code(ResponseCode::NoError)
        .add_query(Query::query(name.clone(), kind))
        .add_answers(records)
        .add_answer(Record::from_rdata(
            name.clone(),
            60,
            RData::DNSSEC(DNSSECRData::RRSIG(signature(signature_bytes))),
        ));
    message
}

fn fixture(kind: DnsQueryType) -> Fixture {
    let now = u32::try_from(unix_millis().unwrap() / 1000).unwrap();
    let root = signer(Name::root());
    let zone = Name::from_ascii("test.").unwrap();
    let child = signer(zone.clone());
    let root_key = root.to_dnskey().unwrap();
    let child_key = child.to_dnskey().unwrap();
    let mut anchors = TrustAnchors::empty();
    anchors.insert(root_key.public_key());
    let ds = DS::new(
        child_key.calculate_key_tag().unwrap(),
        Algorithm::ED25519,
        DigestType::SHA256,
        child_key
            .to_digest(&zone, DigestType::SHA256)
            .unwrap()
            .as_ref()
            .to_vec(),
    );
    let question = DnsQuestion::new("fixture.test", kind).unwrap();
    let answer = match kind {
        DnsQueryType::A => RData::A(A(Ipv4Addr::new(93, 184, 216, 34))),
        DnsQueryType::Aaaa => {
            RData::AAAA(AAAA("2606:4700:4700::1111".parse::<Ipv6Addr>().unwrap()))
        }
    };
    let messages = vec![
        signed_message(
            vec![Record::from_rdata(
                Name::root(),
                60,
                RData::DNSSEC(DNSSECRData::DNSKEY(root_key)),
            )],
            &root,
            now,
        ),
        signed_message(
            vec![Record::from_rdata(
                zone.clone(),
                60,
                RData::DNSSEC(DNSSECRData::DS(ds)),
            )],
            &root,
            now,
        ),
        signed_message(
            vec![Record::from_rdata(
                zone,
                60,
                RData::DNSSEC(DNSSECRData::DNSKEY(child_key)),
            )],
            &child,
            now,
        ),
        signed_message(
            vec![Record::from_rdata(
                question.query().unwrap().name().clone(),
                60,
                answer,
            )],
            &child,
            now,
        ),
    ];
    Fixture {
        anchors: Arc::new(anchors),
        bundle: DnsProofBundle::from_wire(BundleWire {
            version: 1,
            name: question.name().to_owned(),
            rrtype: u32::from(u16::from(question.record_type())),
            expires_at_ms: unix_millis().unwrap() + 60_000,
            messages: messages
                .iter()
                .map(|message| message.to_vec().unwrap())
                .collect(),
        })
        .unwrap(),
    }
}

#[tokio::test]
async fn positive_chain_is_independent_and_bad_or_incomplete_proofs_fail() {
    for kind in [DnsQueryType::A, DnsQueryType::Aaaa] {
        let fixture = fixture(kind);
        let wire = fixture.bundle.encode();
        let decoded = DnsProofBundle::decode(&wire).unwrap();
        let validated = validate_with_anchors(decoded.clone(), Arc::clone(&fixture.anchors))
            .await
            .unwrap();
        assert_eq!(validated.addresses.len(), 1);
        assert!(
            validate(decoded.clone()).await.is_err(),
            "fixture key must never become a production root"
        );
        let mut missing = decoded.clone();
        missing.wire.messages.remove(1);
        assert!(
            validate_with_anchors(missing, Arc::clone(&fixture.anchors))
                .await
                .is_err()
        );
        let mut forged = decoded.clone();
        let mut response = parse_message(forged.wire.messages.last().unwrap()).unwrap();
        response.answers_mut()[0].set_data(match kind {
            DnsQueryType::A => RData::A(A(Ipv4Addr::new(93, 184, 216, 35))),
            DnsQueryType::Aaaa => RData::AAAA(AAAA("2606:4700:4700::1001".parse().unwrap())),
        });
        *forged.wire.messages.last_mut().unwrap() = response.to_vec().unwrap();
        assert!(
            validate_with_anchors(forged, Arc::clone(&fixture.anchors))
                .await
                .is_err()
        );
        let mut expired = decoded;
        expired.bound_expiry(unix_millis().unwrap() - 1);
        assert!(
            validate_with_anchors(expired, Arc::clone(&fixture.anchors))
                .await
                .is_err()
        );
        let mut noncanonical = wire;
        noncanonical.extend_from_slice(&[8, 1]);
        assert!(DnsProofBundle::decode(&noncanonical).is_err());
        assert!(DnsProofBundle::decode(&vec![0; super::super::MAX_DNS_PROOF_BYTES + 1]).is_err());
    }
}

#[tokio::test]
async fn received_rrsig_ttl_and_original_first_seen_deadline_never_renew() {
    let fixture = fixture(DnsQueryType::A);
    let mut short = fixture.bundle.clone();
    let mut message = parse_message(short.wire.messages.last().unwrap()).unwrap();
    message.answers_mut().last_mut().unwrap().set_ttl(2);
    *short.wire.messages.last_mut().unwrap() = message.to_vec().unwrap();
    let proof = validate_with_anchors(short, Arc::clone(&fixture.anchors))
        .await
        .unwrap();
    assert!(proof.bundle.expires_at_unix_ms() <= unix_millis().unwrap() + 2000);
    let resolver = ExitResolver::default();
    let policy = [1; 32];
    let question = proof.bundle.question().clone();
    let original = resolver
        .retain(proof, &policy, DnsAnswerSource::PeerValidated)
        .unwrap();
    let replay = validate_with_anchors(fixture.bundle, fixture.anchors)
        .await
        .unwrap();
    let repeated = resolver
        .retain(replay, &policy, DnsAnswerSource::PeerValidated)
        .unwrap();
    assert!(repeated.ttl_seconds() <= original.ttl_seconds());
    assert!(
        resolver
            .cached_bundle(&question, &policy)
            .unwrap()
            .expires_at_unix_ms()
            <= unix_millis().unwrap() + 2000
    );
    assert!(resolver.cached_bundle(&question, &[2; 32]).is_none());
    assert!(!DnsResolutionScope::without_peers(policy).permits_peers());
    assert!(DnsResolutionScope::new(policy, Vec::new()).is_err());
}

#[test]
fn real_recursive_collector_uses_bounded_tcp_and_validates_the_full_chain() {
    const ENV: &str = "VOLPAROSSA_DNS_COLLECTOR_PARENT_NETNS";
    const TEST: &str = "dns::resolver::proof::tests::real_recursive_collector_uses_bounded_tcp_and_validates_the_full_chain";
    let current = std::fs::read_link("/proc/self/ns/net").unwrap();
    if let Some(parent) = std::env::var_os(ENV) {
        assert_ne!(
            current.as_os_str(),
            parent,
            "never open a fixture socket in the host namespace"
        );
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(collector_scenario());
        return;
    }
    let output = Command::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/run-isolated-test.sh"
    ))
    .arg(std::env::current_exe().unwrap())
    .args([TEST, ENV, "loopback"])
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "isolated collector proof failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn collector_scenario() {
    let fixture = fixture(DnsQueryType::A);
    let mut messages = BTreeMap::new();
    for bytes in &fixture.bundle.wire.messages {
        let message = parse_message(bytes).unwrap();
        messages.insert(EvidenceHandle::key(&message.queries()[0]), message);
    }
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let address = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let counter = Arc::clone(&requests);
    let server = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            let length = usize::from(stream.read_u16().await.unwrap());
            assert!(length <= MAX_MESSAGE_BYTES);
            let mut bytes = vec![0; length];
            stream.read_exact(&mut bytes).await.unwrap();
            let request = Message::from_vec(&bytes).unwrap();
            assert!(request.extensions().as_ref().unwrap().flags().dnssec_ok);
            let mut response = messages
                .get(&EvidenceHandle::key(&request.queries()[0]))
                .unwrap()
                .clone();
            response.set_id(request.id());
            let bytes = response.to_vec().unwrap();
            stream
                .write_u16(u16::try_from(bytes.len()).unwrap())
                .await
                .unwrap();
            stream.write_all(&bytes).await.unwrap();
            counter.fetch_add(1, Ordering::Relaxed);
        }
    });
    let result = timeout(
        Duration::from_secs(5),
        collect_with_anchors(fixture.bundle.question(), address, fixture.anchors.clone()),
    )
    .await
    .unwrap()
    .unwrap();
    assert_eq!(
        result.addresses,
        vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
    );
    assert!(
        requests.load(Ordering::Relaxed) >= 4,
        "A, child DNSKEY, parent DS, root DNSKEY traversed real TCP"
    );
    server.abort();
    let _ = server.await;
    let started = Instant::now();
    let independently = validate_with_anchors(result.bundle, fixture.anchors)
        .await
        .unwrap();
    assert_eq!(independently.addresses.len(), 1);
    assert!(
        started.elapsed() < Duration::from_secs(1),
        "offline verification needs no origin socket"
    );
}
