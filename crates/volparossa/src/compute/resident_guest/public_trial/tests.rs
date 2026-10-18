//! Real public protocol with an inert injected worker, never inference evidence.
use super::super::{Policy, serve, tls_config};
use super::*;
use crate::compute::{native_cpu, private_task, supervise::native_session};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use volparossa_content::provider::compute::resident_task::GrantVerifier;

fn key() -> SigningKey {
    SigningKey::from_bytes(&[24; 32])
}

fn answer(sequence: u32, text: &str) -> wire::Frame {
    wire::frame(wire::RESULT,sequence,serde_json::to_vec(&json!({
        "version":2,"execution_complete":true,"turn_complete":true,
        "model_profile":"qwen3-4b-instruct-2507-v1",
        "output":{"type":"assistant","text":text},"prompt_tokens":12,"generated_tokens":2,
        "cleanup":{"version":2,"request_files_removed":true,"session_closed":false,"session_private_state_retained":true}
    })).unwrap())
}

#[test]
fn policy_binds_only_fixed_public_worker_inputs() {
    let inputs = inputs().unwrap();
    assert_ne!(inputs[0], inputs[1]);
    let policy =
        Policy::decode(&serde_json::to_vec(&policy(&key(), [7; 32]).unwrap()).unwrap()).unwrap();
    assert_eq!(policy.visibility, "public_fixture");
    assert_eq!(
        policy.requester_key,
        hex::encode(key().verifying_key().to_bytes())
    );
    assert_eq!(
        policy.public_input_sha256,
        inputs
            .clone()
            .map(|bytes| hex::encode(Sha256::digest(bytes)))
    );
    for input in inputs {
        let decoded = crate::compute::private_conversation::Input::decode_profile(
            &input,
            crate::compute::ModelProfile::Qwen4bInstruct2507,
        )
        .unwrap();
        assert!(decoded.requires_generation_policy_handshake());
    }
}

#[test]
fn requester_grant_passes_real_verifier_and_consumes_each_input_once() {
    let policy =
        Policy::decode(&serde_json::to_vec(&policy(&key(), [7; 32]).unwrap()).unwrap()).unwrap();
    let verifier = GrantVerifier::new(policy.expectations([8; 32], [9; 32]).unwrap()).unwrap();
    let now = verifier.issued_at_ms();
    let challenge = wire::Challenge {
        nonce: verifier.nonce().to_vec(),
        issued_at_ms: now,
        maximum_expires_at_ms: verifier.maximum_expires_at_ms(),
    };
    let signed = grant(
        &wire::frame(wire::CHALLENGE, 0, challenge.encode_to_vec()),
        &key(),
        [7; 32],
        [8; 32],
        [9; 32],
        now,
        Instant::now() + Duration::from_secs(10),
    )
    .unwrap();
    let mut allowance = verifier.verify(&signed).unwrap();
    for input in inputs().unwrap() {
        allowance
            .consume_input(&Sha256::digest(input).into())
            .unwrap();
    }
    assert!(allowance.consume_input(&[0; 32]).is_err());
}

#[test]
fn malformed_or_unbounded_challenges_are_never_signed() {
    let challenge = wire::Challenge {
        nonce: vec![8; 32],
        issued_at_ms: 1_000_000,
        maximum_expires_at_ms: 3_400_000,
    };
    for (issued, expires) in [
        (1_000_000, 3_400_001),
        (900_000, 3_000_000),
        (1_000_000, 1_000_000),
    ] {
        let mut changed = challenge.clone();
        changed.issued_at_ms = issued;
        changed.maximum_expires_at_ms = expires;
        assert!(
            grant(
                &wire::frame(wire::CHALLENGE, 0, changed.encode_to_vec()),
                &key(),
                [7; 32],
                [8; 32],
                [9; 32],
                1_000_000,
                Instant::now() + Duration::from_secs(10)
            )
            .is_err()
        );
    }
    let mut bytes = challenge.encode_to_vec();
    bytes.extend_from_slice(&[80, 1]);
    assert!(
        grant(
            &wire::frame(wire::CHALLENGE, 0, bytes),
            &key(),
            [7; 32],
            [8; 32],
            [9; 32],
            1_000_000,
            Instant::now() + Duration::from_secs(10)
        )
        .is_err()
    );
    assert!(
        grant(
            &wire::frame(wire::GRANT, 0, challenge.encode_to_vec()),
            &key(),
            [7; 32],
            [8; 32],
            [9; 32],
            1_000_000,
            Instant::now() + Duration::from_secs(10)
        )
        .is_err()
    );
}

#[test]
fn result_requires_correct_answer_real_completion_and_retained_session_receipt() {
    assert!(result(&answer(1, " READY\n"), "READY").is_ok());
    assert!(result(&answer(1, "wrong"), "READY").is_err());
    for (field, value) in [
        ("execution_complete", json!(false)),
        ("turn_complete", json!(false)),
        ("cleanup", json!({"complete":true})),
        ("prompt_tokens", Value::Null),
        ("generated_tokens", json!({})),
        ("prompt_tokens", json!(12_289)),
        ("generated_tokens", json!(0)),
    ] {
        let mut frame = answer(1, "READY");
        let mut body: Value = serde_json::from_slice(&frame.body).unwrap();
        body[field] = value;
        frame.body = serde_json::to_vec(&body).unwrap();
        assert!(result(&frame, "READY").is_err());
    }
}

#[test]
fn verified_certificate_must_also_match_the_exact_selected_peer_key() {
    let first = rcgen::generate_simple_self_signed(vec!["resident.test".into()]).unwrap();
    let second = rcgen::generate_simple_self_signed(vec!["resident.test".into()]).unwrap();
    let (_, selected) = client_config(first.cert.der().to_vec()).unwrap();
    assert!(check_peer_key(first.cert.der().as_ref(), selected).is_ok());
    assert!(check_peer_key(second.cert.der().as_ref(), selected).is_err());
}

#[tokio::test(start_paused = true)]
async fn signed_guest_budget_cannot_restart_the_requester_deadline() {
    let policy =
        Policy::decode(&serde_json::to_vec(&policy(&key(), [7; 32]).unwrap()).unwrap()).unwrap();
    let verifier = GrantVerifier::new(policy.expectations([8; 32], [9; 32]).unwrap()).unwrap();
    let now = verifier.issued_at_ms();
    let started = Instant::now();
    let deadline = started + Duration::from_secs(5);
    let challenge = wire::Challenge {
        nonce: verifier.nonce().to_vec(),
        issued_at_ms: now,
        maximum_expires_at_ms: verifier.maximum_expires_at_ms(),
    };
    tokio::time::advance(Duration::from_secs(2)).await;
    let signed = grant(
        &wire::frame(wire::CHALLENGE, 0, challenge.encode_to_vec()),
        &key(),
        [7; 32],
        [8; 32],
        [9; 32],
        now,
        deadline,
    )
    .unwrap();
    let allowance = verifier.verify(&signed).unwrap();
    assert!(allowance.deadline() <= deadline);
    tokio::time::advance(Duration::from_secs(3)).await;
    assert!(
        grant(
            &wire::frame(wire::CHALLENGE, 0, challenge.encode_to_vec()),
            &key(),
            [7; 32],
            [8; 32],
            [9; 32],
            now,
            deadline
        )
        .is_err()
    );
}

#[tokio::test]
async fn requester_and_guest_complete_one_tls_channel_and_join_the_inert_worker() {
    let rcgen::CertifiedKey { cert, key_pair } =
        rcgen::generate_simple_self_signed(vec!["resident.test".into()]).unwrap();
    let (acceptor, spki) = tls_config(cert.der().to_vec(), key_pair.serialize_der()).unwrap();
    let (connector, pinned) = client_config(cert.der().to_vec()).unwrap();
    assert_eq!(spki, pinned);
    let policy =
        Policy::decode(&serde_json::to_vec(&policy(&key(), [7; 32]).unwrap()).unwrap()).unwrap();
    let config = private_task::ExecutionConfig {
        runtime_root: "/unused/runtime".into(),
        model_root: "/unused/model".into(),
        work_parent: "/unused/work".into(),
        model_profile: crate::compute::ModelProfile::Qwen4bInstruct2507,
        native_backend: native_cpu::Options::default(),
        threads: 2,
        max_seconds: 600,
    };
    let turns = Arc::new(AtomicUsize::new(0));
    let joined = Arc::new(AtomicBool::new(false));
    let (count, done) = (turns.clone(), joined.clone());
    let (client_io, server_io) = tokio::io::duplex(4096);
    let serving = tokio::spawn(serve(
        server_io,
        acceptor,
        spki,
        policy,
        config,
        move |_, mut commands, events, mut activity, _| async move {
            events.send(native_session::Event::Opened).await.unwrap();
            loop {
                tokio::select! {
                    biased;
                    _ = activity.changed() => break,
                    command = commands.recv() => match command {
                        Some(native_session::Command::Submit{id,input}) => {
                            let turn = count.fetch_add(1,Ordering::SeqCst);
                            assert_eq!(input,inputs().unwrap()[turn]);
                            let frame = answer(u32::try_from(turn + 1).unwrap(),["READY","4"][turn]);
                            events.send(native_session::Event::Result{id,value:serde_json::from_slice(&frame.body).unwrap()}).await.unwrap();
                        },
                        _ => break,
                    }
                }
            }
            done.store(true, Ordering::SeqCst);
            Ok(json!({"version":1,"child_reaped":true,"private_state_removed":true}))
        },
    ));
    let deadline = Instant::now() + Duration::from_secs(10);
    let tls = connector
        .connect("resident.test".try_into().unwrap(), client_io)
        .await
        .unwrap();
    let report = exchange(tls, &key(), [7; 32], spki, deadline)
        .await
        .unwrap();
    serving.await.unwrap().unwrap();
    assert_eq!(report["turns"].as_array().unwrap().len(), 2);
    assert_eq!(turns.load(Ordering::SeqCst), 2);
    assert!(joined.load(Ordering::SeqCst));
    assert_eq!(report["hardware_attestation"], false);
    assert_eq!(report["private_inputs"], false);
}
