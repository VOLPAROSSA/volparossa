// SPDX-License-Identifier: GPL-3.0-only

//! Bounded, in-memory tests of the 0.25 stub caching path. These inject DNSSEC
//! verdicts from a validating handle; they do not replace cryptographic proof
//! tests or exercise the separate, unlinked hickory-recursor implementation.

use futures::{executor::block_on, stream};
use hickory_proto::{
    dnssec::Proof,
    op::{Message, MessageType, Query},
    rr::{
        rdata::{A, AAAA, CNAME},
        Name, RData, Record, RecordType,
    },
    xfer::{DnsHandle, DnsRequest, DnsRequestOptions, DnsResponse},
    ProtoError, ProtoErrorKind,
};
use hickory_resolver::caching_client::CachingClient;
use std::{
    collections::VecDeque,
    sync::{Arc, Mutex},
};

type Reply = Result<DnsResponse, ProtoError>;

#[derive(Clone)]
struct StubHandle {
    validating: bool,
    replies: Arc<Mutex<VecDeque<Reply>>>,
    queries: Arc<Mutex<Vec<Query>>>,
}

impl StubHandle {
    fn new(validating: bool, replies: Vec<Reply>) -> Self {
        Self {
            validating,
            replies: Arc::new(Mutex::new(replies.into())),
            queries: Arc::new(Mutex::new(Vec::new())),
        }
    }

    fn queries(&self) -> Vec<Query> {
        self.queries.lock().unwrap().clone()
    }
}

impl DnsHandle for StubHandle {
    type Response = stream::Iter<std::vec::IntoIter<Reply>>;

    fn is_verifying_dnssec(&self) -> bool {
        self.validating
    }

    fn send<R: Into<DnsRequest> + Unpin + Send + 'static>(&self, request: R) -> Self::Response {
        let request = request.into();
        self.queries
            .lock()
            .unwrap()
            .extend_from_slice(request.queries());
        let reply = self
            .replies
            .lock()
            .unwrap()
            .pop_front()
            .expect("unexpected extra query from bounded in-memory resolver");
        stream::iter(vec![reply])
    }
}

fn name(value: &str) -> Name {
    Name::from_ascii(value).unwrap()
}

fn query(value: &str, kind: RecordType) -> Query {
    Query::query(name(value), kind)
}

fn address(value: &str, kind: RecordType, proof: Proof) -> Record {
    let data = match kind {
        RecordType::A => RData::A(A::new(192, 0, 2, 1)),
        RecordType::AAAA => RData::AAAA(AAAA::new(0x2001, 0xdb8, 0, 0, 0, 0, 0, 1)),
        _ => panic!("fixture requires an address type"),
    };
    let mut record = Record::from_rdata(name(value), 300, data);
    record.set_proof(proof);
    record
}

fn cname(owner: &str, target: &str, proof: Proof) -> Record {
    let mut record = Record::from_rdata(name(owner), 300, RData::CNAME(CNAME(name(target))));
    record.set_proof(proof);
    record
}

fn response(query: &Query, answers: Vec<Record>) -> Message {
    let mut message = Message::new();
    message
        .set_message_type(MessageType::Response)
        .add_query(query.clone())
        .add_answers(answers);
    message
}

fn reply(message: Message) -> Reply {
    DnsResponse::from_message(message)
}

#[test]
fn validating_stub_rejects_bogus_ipv4_and_ipv6_answers() {
    for kind in [RecordType::A, RecordType::AAAA] {
        let query = query("host.example.", kind);
        let handle = StubHandle::new(
            true,
            vec![reply(response(
                &query,
                vec![address("host.example.", kind, Proof::Bogus)],
            ))],
        );
        let client = CachingClient::new(8, handle.clone(), false);
        let error = block_on(client.lookup(query.clone(), DnsRequestOptions::default())).unwrap_err();
        assert!(matches!(
            error.proto().unwrap().kind(),
            ProtoErrorKind::Message("DNSSEC validation failed")
        ));
        assert_eq!(handle.queries(), vec![query]);
    }
}

#[test]
fn validating_stub_rejects_mixed_secure_and_bogus_answers() {
    let query = query("host.example.", RecordType::A);
    let handle = StubHandle::new(
        true,
        vec![reply(response(
            &query,
            vec![
                address("host.example.", RecordType::A, Proof::Secure),
                address("host.example.", RecordType::A, Proof::Bogus),
            ],
        ))],
    );
    let client = CachingClient::new(8, handle.clone(), false);
    assert!(block_on(client.lookup(query.clone(), DnsRequestOptions::default())).is_err());
    assert_eq!(handle.queries(), vec![query]);
}

#[test]
fn validating_stub_rejects_bogus_alias_before_following_it() {
    let query = query("host.example.", RecordType::A);
    let handle = StubHandle::new(
        true,
        vec![reply(response(
            &query,
            vec![cname("host.example.", "target.example.", Proof::Bogus)],
        ))],
    );
    let client = CachingClient::new(8, handle.clone(), false);
    assert!(block_on(client.lookup(query.clone(), DnsRequestOptions::default())).is_err());
    assert_eq!(handle.queries(), vec![query]);
}

#[test]
fn bogus_answer_is_not_cached_and_subsequent_secure_answer_is_cached() {
    let query = query("host.example.", RecordType::A);
    let handle = StubHandle::new(
        true,
        [Proof::Bogus, Proof::Secure]
            .into_iter()
            .map(|proof| {
                reply(response(
                    &query,
                    vec![address("host.example.", RecordType::A, proof)],
                ))
            })
            .collect(),
    );
    let client = CachingClient::new(8, handle.clone(), false);
    assert!(block_on(client.lookup(query.clone(), DnsRequestOptions::default())).is_err());
    for _ in 0..2 {
        let lookup = block_on(client.lookup(query.clone(), DnsRequestOptions::default())).unwrap();
        assert_eq!(lookup.record_iter().count(), 1);
    }
    assert_eq!(handle.queries(), vec![query.clone(), query]);
}

#[test]
fn bogus_nsec_error_still_propagates_without_becoming_a_cached_negative() {
    let query = query("host.example.", RecordType::A);
    let handle = StubHandle::new(
        true,
        vec![
            Err(ProtoErrorKind::Nsec {
                query: Box::new(query.clone()),
                proof: Proof::Bogus,
            }
            .into()),
            reply(response(
                &query,
                vec![address("host.example.", RecordType::A, Proof::Secure)],
            )),
        ],
    );
    let client = CachingClient::new(8, handle.clone(), false);
    let error = block_on(client.lookup(query.clone(), DnsRequestOptions::default())).unwrap_err();
    assert!(matches!(
        error.proto().unwrap().kind(),
        ProtoErrorKind::Nsec {
            proof: Proof::Bogus,
            ..
        }
    ));
    assert!(block_on(client.lookup(query.clone(), DnsRequestOptions::default())).is_ok());
    assert_eq!(handle.queries(), vec![query.clone(), query]);
}

#[test]
fn secure_insecure_and_indeterminate_answers_keep_existing_stub_semantics() {
    // This backport rejects Bogus, not all unsigned data. VOLPAROSSA's separate
    // positive DNSSEC proof service still imposes its stricter Secure requirement.
    for proof in [Proof::Secure, Proof::Insecure, Proof::Indeterminate] {
        let query = query("host.example.", RecordType::A);
        let handle = StubHandle::new(
            true,
            vec![reply(response(
                &query,
                vec![address("host.example.", RecordType::A, proof)],
            ))],
        );
        let client = CachingClient::new(8, handle.clone(), false);
        assert!(block_on(client.lookup(query.clone(), DnsRequestOptions::default())).is_ok());
        assert_eq!(handle.queries(), vec![query]);
    }
}

#[test]
fn nonvalidating_stub_behavior_is_unchanged() {
    let query = query("host.example.", RecordType::A);
    let handle = StubHandle::new(
        false,
        vec![reply(response(
            &query,
            vec![address("host.example.", RecordType::A, Proof::Bogus)],
        ))],
    );
    let client = CachingClient::new(8, handle.clone(), false);
    assert!(block_on(client.lookup(query.clone(), DnsRequestOptions::default())).is_ok());
    assert_eq!(handle.queries(), vec![query]);
}

#[test]
fn stub_does_not_follow_unrelated_answer_or_authority_or_additional_aliases() {
    for section in 0..3 {
        let query = query("host.example.", RecordType::A);
        let mut message = response(&query, Vec::new());
        match section {
            0 => message.add_answer(cname(
                "unrelated.example.",
                "target.example.",
                Proof::Indeterminate,
            )),
            1 => message.add_name_server(cname(
                "host.example.",
                "target.example.",
                Proof::Indeterminate,
            )),
            _ => message.add_additional(cname(
                "host.example.",
                "target.example.",
                Proof::Indeterminate,
            )),
        };
        let handle = StubHandle::new(false, vec![reply(message)]);
        let client = CachingClient::new(8, handle.clone(), false);
        assert!(block_on(client.lookup(query.clone(), DnsRequestOptions::default())).is_err());
        assert_eq!(handle.queries(), vec![query]);
    }
}

#[test]
fn stub_follows_only_the_effective_answer_chain_with_one_additional_query() {
    let first = query("host.example.", RecordType::A);
    let last = query("target.example.", RecordType::A);
    let mut message = response(
        &first,
        vec![
            cname("host.example.", "middle.example.", Proof::Indeterminate),
            cname("unrelated.example.", "unused.example.", Proof::Indeterminate),
            cname("middle.example.", "target.example.", Proof::Indeterminate),
        ],
    );
    message.add_additional(cname(
        "target.example.",
        "unrequested.example.",
        Proof::Indeterminate,
    ));
    let handle = StubHandle::new(
        false,
        vec![
            reply(message),
            reply(response(
                &last,
                vec![address(
                    "target.example.",
                    RecordType::A,
                    Proof::Indeterminate,
                )],
            )),
        ],
    );
    let client = CachingClient::new(8, handle.clone(), false);
    let lookup = block_on(client.lookup(first.clone(), DnsRequestOptions::default())).unwrap();
    assert_eq!(lookup.record_iter().count(), 1);
    assert_eq!(handle.queries(), vec![first, last]);
}

#[test]
fn stub_alias_cycles_remain_bounded_by_existing_eight_query_limit() {
    let first = query("first.example.", RecordType::A);
    let second = query("second.example.", RecordType::A);
    let expected: Vec<_> = (0..8)
        .map(|index| {
            if index % 2 == 0 {
                first.clone()
            } else {
                second.clone()
            }
        })
        .collect();
    let replies = expected
        .iter()
        .map(|query| {
            let target = if query == &first {
                "second.example."
            } else {
                "first.example."
            };
            reply(response(
                query,
                vec![cname(
                    &query.name().to_ascii(),
                    target,
                    Proof::Indeterminate,
                )],
            ))
        })
        .collect();
    let handle = StubHandle::new(false, replies);
    let client = CachingClient::new(8, handle.clone(), false);
    assert!(block_on(client.lookup(first, DnsRequestOptions::default())).is_err());
    assert_eq!(handle.queries(), expected);
}
