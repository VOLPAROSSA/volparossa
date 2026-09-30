//! Wire/selection tests use controlled DNS messages, not evidence that Unbound was executed.

use std::{
    net::Ipv4Addr,
    process::Command,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use hickory_proto::{
    op::Query,
    rr::{
        Name, Record,
        rdata::{A, CNAME},
    },
};
use tokio::{net::TcpListener, time::timeout};

use super::*;
use crate::{DnsQueryType, DnsResolutionScope, ExitResolver};

fn answer() -> (DnsQuestion, Message) {
    let question = DnsQuestion::new("inert.example", DnsQueryType::A).unwrap();
    let mut message = Message::new();
    message
        .set_id(7)
        .set_message_type(MessageType::Response)
        .set_recursion_available(true)
        .add_query(question.query().unwrap());
    (question, message)
}

fn address(name: &str, ttl: u32, ip: Ipv4Addr) -> Record {
    Record::from_rdata(Name::from_ascii(name).unwrap(), ttl, RData::A(A(ip)))
}

#[test]
fn cname_lifetime_and_local_validator_provenance_are_not_peer_proofs() {
    let (question, mut message) = answer();
    message
        .add_answer(Record::from_rdata(
            Name::from_ascii("inert.example.").unwrap(),
            9,
            RData::CNAME(CNAME(Name::from_ascii("target.example.").unwrap())),
        ))
        .add_answer(address(
            "target.example.",
            60,
            Ipv4Addr::new(93, 184, 216, 34),
        ));
    for authenticated_data in [false, true] {
        message.set_authentic_data(authenticated_data);
        let result = parse_answer(
            &question,
            7,
            &message.to_vec().unwrap(),
            Instant::now() - Duration::from_secs(2),
        )
        .unwrap();
        assert!((5..=7).contains(&result.ttl_seconds()));
        assert_eq!(
            result.source(),
            DnsAnswerSource::TrustedUnbound { authenticated_data }
        );
        assert_eq!(
            result.addresses(),
            [IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]
        );
    }
}

#[test]
fn errors_and_rebinding_do_not_become_fresh_or_unsigned_answers() {
    let (question, mut message) = answer();
    message.set_response_code(ResponseCode::NXDomain);
    assert!(matches!(
        parse_answer(&question, 7, &message.to_vec().unwrap(), Instant::now()),
        Err(DnsResolverError::NameNotFound)
    ));
    message.set_response_code(ResponseCode::NoError);
    assert!(matches!(
        parse_answer(&question, 7, &message.to_vec().unwrap(), Instant::now()),
        Err(DnsResolverError::NoData)
    ));
    message.set_response_code(ResponseCode::ServFail);
    assert!(matches!(
        parse_answer(&question, 7, &message.to_vec().unwrap(), Instant::now()),
        Err(DnsResolverError::Unavailable)
    ));
    message.set_response_code(ResponseCode::NoError);
    for (name, ttl, ip) in [
        ("inert.example.", 0, Ipv4Addr::new(93, 184, 216, 34)),
        ("inert.example.", 30, Ipv4Addr::LOCALHOST),
        ("unrelated.example.", 30, Ipv4Addr::new(93, 184, 216, 34)),
    ] {
        let mut invalid = message.clone();
        invalid.add_answer(address(name, ttl, ip));
        assert!(parse_answer(&question, 7, &invalid.to_vec().unwrap(), Instant::now()).is_err());
    }
    message.add_answer(Record::from_rdata(
        Name::from_ascii("inert.example.").unwrap(),
        10,
        RData::CNAME(CNAME(Name::from_ascii("inert.example.").unwrap())),
    ));
    assert!(parse_answer(&question, 7, &message.to_vec().unwrap(), Instant::now()).is_err());
    assert!(parse_answer(&question, 8, &message.to_vec().unwrap(), Instant::now()).is_err());
}

#[test]
fn real_tcp_fallback_is_bounded_local_nonsharing_and_fails_closed() {
    const ENV: &str = "VOLPAROSSA_DNS_COLLECTOR_PARENT_NETNS";
    const TEST: &str = "dns::resolver::unbound::tests::real_tcp_fallback_is_bounded_local_nonsharing_and_fails_closed";
    let current = std::fs::read_link("/proc/self/ns/net").unwrap();
    if let Some(parent) = std::env::var_os(ENV) {
        assert_ne!(
            current.as_os_str(),
            parent,
            "never open fixture sockets in the host namespace"
        );
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(wire_scenario());
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
        "isolated wire fallback failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

async fn wire_scenario() {
    let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let endpoint = listener.local_addr().unwrap();
    let requests = Arc::new(AtomicUsize::new(0));
    let observed = Arc::clone(&requests);
    let server = tokio::spawn(async move {
        loop {
            let (mut connection, _) = listener.accept().await.unwrap();
            let length = usize::from(connection.read_u16().await.unwrap());
            assert!(length <= MAX_MESSAGE_BYTES);
            let mut raw = vec![0; length];
            connection.read_exact(&mut raw).await.unwrap();
            let request = Message::from_vec(&raw).unwrap();
            let query = &request.queries()[0];
            let mut reply = Message::new();
            reply
                .set_id(request.id())
                .set_message_type(MessageType::Response)
                .set_recursion_available(true)
                .add_query(query.clone());
            if query == &Query::query(Name::from_ascii("inert.example.").unwrap(), RecordType::A) {
                reply.add_answer(address(
                    "inert.example.",
                    15,
                    Ipv4Addr::new(93, 184, 216, 34),
                ));
            } else {
                reply.set_response_code(ResponseCode::ServFail);
            }
            if !request.checking_disabled() {
                assert!(request.extensions().as_ref().unwrap().flags().dnssec_ok);
            }
            let bytes = reply.to_vec().unwrap();
            connection
                .write_u16(u16::try_from(bytes.len()).unwrap())
                .await
                .unwrap();
            connection.write_all(&bytes).await.unwrap();
            observed.fetch_add(1, Ordering::Relaxed);
        }
    });
    let resolver = ExitResolver::new(None, None)
        .with_unbound_fallback(endpoint)
        .unwrap();
    let question = DnsQuestion::new("inert.example", DnsQueryType::A).unwrap();
    let scope = DnsResolutionScope::without_peers([8; 32]);
    let result = timeout(Duration::from_secs(6), resolver.resolve(&question, &scope))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        result.source(),
        DnsAnswerSource::TrustedUnbound {
            authenticated_data: false
        }
    );
    assert!((1..=15).contains(&result.ttl_seconds()));
    assert!(!resolver.has_shareable_proof(scope.policy_hash()));
    assert!(
        resolver
            .cached_bundle(&question, scope.policy_hash())
            .is_none()
    );
    assert_eq!(resolver.counts().trusted_fallback, 1);
    let refused = DnsQuestion::new("refused.example", DnsQueryType::A).unwrap();
    assert!(resolver.resolve(&refused, &scope).await.is_err());
    assert_eq!(
        resolver.counts().trusted_fallback,
        1,
        "SERVFAIL must not call OS fallback"
    );
    assert!(requests.load(Ordering::Relaxed) >= 4);
    server.abort();
    let _ = server.await;
    assert!(
        resolver.resolve(&question, &scope).await.is_err(),
        "unavailable service must fail closed"
    );
    assert_eq!(resolver.counts().trusted_fallback, 1);
}
