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
    for invalid in [b"".as_slice(), b"PRIVATE_CERTIFICATE_CANARY".as_slice()] {
        let error = check_peer_key(invalid, [0; 32]).unwrap_err();
        assert_eq!(error.to_string(), "resident_peer_certificate_decode");
        assert_eq!(error.chain().count(), 1);
    }
    let first = rcgen::generate_simple_self_signed(vec!["resident.test".into()]).unwrap();
    let second = rcgen::generate_simple_self_signed(vec!["resident.test".into()]).unwrap();
    let (_, selected) = client_config(first.cert.der().to_vec()).unwrap();
    assert!(check_peer_key(first.cert.der().as_ref(), selected).is_ok());
    let error = check_peer_key(second.cert.der().as_ref(), selected).unwrap_err();
    assert_eq!(error.to_string(), "resident_peer_key_pin");
    assert_eq!(error.chain().count(), 1);
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
    requester_fixture(false).await;
}

#[tokio::test]
async fn authenticated_guest_failure_is_terminal_even_with_export_disabled() {
    requester_fixture(true).await;
}

async fn requester_fixture(failure: bool) {
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
                            if failure {
                                done.store(true, Ordering::SeqCst);
                                return Err(native_session::public_fixture_test_failure(anyhow::anyhow!("compute_memory_budget")));
                            }
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
    let report = exchange(tls, &key(), [7; 32], spki, deadline, false).await;
    let served = serving.await.unwrap();
    if failure {
        assert_eq!(
            report.unwrap_err().to_string(),
            "resident_public_trial_guest_failed"
        );
        assert_eq!(
            served.unwrap_err().to_string(),
            "compute_native_session_execution_failed"
        );
        assert_eq!(turns.load(Ordering::SeqCst), 1);
        assert!(joined.load(Ordering::SeqCst));
        return;
    }
    let report = report.unwrap();
    served.unwrap();
    assert_eq!(report["turns"].as_array().unwrap().len(), 2);
    assert_eq!(turns.load(Ordering::SeqCst), 2);
    assert!(joined.load(Ordering::SeqCst));
    assert_eq!(report["hardware_attestation"], false);
    assert_eq!(report["private_inputs"], false);
}

#[test]
fn public_fixture_stage_diagnostics_require_explicit_execution_opt_in() {
    use clap::Parser as _;
    #[derive(clap::Parser)]
    struct Command {
        #[command(flatten)]
        options: Options,
    }
    let mut args = vec![
        "requester",
        "--socket",
        "/unused/socket",
        "--certificate",
        "/unused/cert",
        "--requester-key",
        "/unused/key",
        "--workload-sha256",
        "unused",
    ];
    assert!(
        !Command::try_parse_from(&args)
            .unwrap()
            .options
            .diagnostic_stages
    );
    args.push("--diagnostic-stages");
    assert!(Command::try_parse_from(&args).is_err());
    args.push("--execute");
    assert!(
        Command::try_parse_from(&args)
            .unwrap()
            .options
            .diagnostic_stages
    );
}

#[test]
fn public_fixture_stage_sink_is_fixed_optional_and_cannot_replace_failure() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("private-error-canary"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            panic!("no_extra_flush")
        }
    }
    let mut output = Vec::new();
    observe_stage(false, Stage::Configuration, &mut output);
    assert!(output.is_empty());
    observe_stage(true, Stage::Configuration, &mut output);
    observe_stage(true, Stage::Turn1Result, &mut output);
    observe_stage(true, Stage::Turn2Result, &mut output);
    assert_eq!(
        output,
        b"VP_PUBLIC_REQUESTER_STAGE_V1 configuration\nVP_PUBLIC_REQUESTER_STAGE_V1 turn_1_result\nVP_PUBLIC_REQUESTER_STAGE_V1 turn_2_result\n"
    );
    observe_stage(true, Stage::Cleanup, Broken);
}

#[test]
fn result_rejections_have_closed_categories_without_exporting_answer_or_bytes() {
    for (field, value, category) in [
        (
            "execution_complete",
            json!(false),
            ResultFailure::ResultCompletion,
        ),
        (
            "model_profile",
            json!("PRIVATE_CANARY"),
            ResultFailure::ResultProfile,
        ),
        (
            "output",
            json!({"type":"tool","text":"PRIVATE_CANARY"}),
            ResultFailure::ResultOutput,
        ),
        (
            "output",
            json!({"type":"assistant","text":"PRIVATE_CANARY"}),
            ResultFailure::ResultAnswer,
        ),
        ("generated_tokens", json!(0), ResultFailure::ResultTokens),
        ("cleanup", json!({}), ResultFailure::ResultCleanup),
    ] {
        let mut frame = answer(1, "READY");
        let mut body: Value = serde_json::from_slice(&frame.body).unwrap();
        body[field] = value;
        frame.body = serde_json::to_vec(&body).unwrap();
        let error = result(&frame, "READY").unwrap_err();
        assert_eq!(error.downcast_ref::<ResultFailure>(), Some(&category));
        let mut output = Vec::new();
        observe_result_failure(true, 1, category, None, &mut output);
        assert!(
            !String::from_utf8(output)
                .unwrap()
                .contains("PRIVATE_CANARY")
        );
    }
    let error = result(
        &wire::frame(wire::RESULT, 1, b"PRIVATE_CANARY".to_vec()),
        "READY",
    )
    .unwrap_err();
    assert_eq!(
        error.downcast_ref::<ResultFailure>(),
        Some(&ResultFailure::ResultJson)
    );
}

#[tokio::test]
async fn first_result_reader_distinguishes_eof_bound_frame_and_deadline() {
    use tokio::io::AsyncWriteExt as _;
    let (writer, mut reader) = tokio::io::duplex(32);
    drop(writer);
    let stop = Instant::now() + Duration::from_secs(5);
    assert_eq!(
        read_failure(&wire::read(&mut reader, stop).await.unwrap_err()),
        ResultFailure::ReadEof
    );
    for (bytes, category) in [
        (
            (u32::try_from(wire::MAX_FRAME).unwrap() + 1)
                .to_be_bytes()
                .to_vec(),
            ResultFailure::ReadBound,
        ),
        (vec![0, 0, 0, 1, 0], ResultFailure::ReadFrame),
    ] {
        let (mut writer, mut reader) = tokio::io::duplex(32);
        writer.write_all(&bytes).await.unwrap();
        assert_eq!(
            read_failure(&wire::read(&mut reader, stop).await.unwrap_err()),
            category
        );
    }
    let (_, mut reader) = tokio::io::duplex(32);
    assert_eq!(
        read_failure(&wire::read(&mut reader, Instant::now()).await.unwrap_err()),
        ResultFailure::ReadDeadline
    );
    assert_eq!(
        read_failure(&std::io::Error::other("PRIVATE_CANARY").into()),
        ResultFailure::ReadIo
    );
    assert_eq!(
        read_failure(&anyhow::anyhow!("PRIVATE_CANARY")),
        ResultFailure::ReadOther
    );
}

#[tokio::test]
async fn terminal_frame_old_reader_rejects_and_new_reader_validates_before_failure() {
    let detail = json!({"code":"NATIVE_MODEL_LOAD_FAILED","io_kind":"none",
        "exit_code":null,"signal":null,"stderr_class":null});
    let frame = wire::failure(1, &detail).unwrap();
    for (sequence, old) in [(1, true), (1, false), (2, false)] {
        let (mut writer, mut reader) = tokio::io::duplex(2048);
        let stop = Instant::now() + Duration::from_secs(5);
        wire::write(&mut writer, frame.clone(), stop).await.unwrap();
        let error = if old {
            expected(&mut reader, wire::RESULT, sequence, stop)
                .await
                .unwrap_err()
        } else {
            turn_result(&mut reader, sequence, stop, false)
                .await
                .unwrap_err()
        };
        assert!(!error.to_string().contains("NATIVE_MODEL_LOAD_FAILED"));
    }
}

#[test]
fn result_diagnostic_export_is_optional_bounded_and_sink_errors_are_ignored() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("PRIVATE_CANARY"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            panic!("no_extra_flush")
        }
    }
    let mut output = Vec::new();
    observe_result_failure(false, 1, ResultFailure::ReadEof, None, &mut output);
    observe_result_failure(true, 3, ResultFailure::ReadEof, None, &mut output);
    assert!(output.is_empty());
    observe_result_failure(true, 1, ResultFailure::ReadEof, None, &mut output);
    assert_eq!(output, b"VP_PUBLIC_REQUESTER_FAILURE_V1 {\"category\":\"read_eof\",\"guest\":null,\"turn\":1,\"version\":1}\n");
    observe_result_failure(true, 1, ResultFailure::ReadEof, None, Broken);
}

fn socket_observation(
    path: &Path,
    owner: u32,
) -> (Result<()>, Vec<(SocketCondition, SocketIoKind)>) {
    let mut observations = Vec::new();
    let result = socket_preflight(path, owner, |condition, error| {
        observations.push((condition, socket_io_kind(error)));
    });
    (result, observations)
}

fn private_socket_directory() -> tempfile::TempDir {
    use std::os::unix::fs::PermissionsExt as _;
    let directory = tempfile::tempdir().unwrap();
    // These fixtures must satisfy the real validator independently of umask.
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

#[test]
fn socket_preflight_accepts_owned_socket_without_an_observation() {
    let directory = private_socket_directory();
    let path = directory
        .path()
        .canonicalize()
        .unwrap()
        .join("channel.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&path).unwrap();
    let (result, observations) = socket_observation(&path, nix::unistd::geteuid().as_raw());
    result.unwrap();
    assert!(observations.is_empty());
}

#[test]
fn socket_preflight_preserves_exact_parent_validation_rejections() {
    use std::os::unix::fs::{PermissionsExt as _, symlink};
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().canonicalize().unwrap();
    let (result, observations) =
        socket_observation(Path::new("/"), nix::unistd::geteuid().as_raw());
    assert_eq!(result.unwrap_err().to_string(), "resident_socket_parent");
    assert_eq!(
        observations,
        vec![(SocketCondition::ParentValidation, SocketIoKind::None)]
    );
    let private = root.join("private");
    std::fs::create_dir(&private).unwrap();
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
    let alias = root.join("alias");
    symlink(&private, &alias).unwrap();
    // A symlink ancestor reaches the canonical-path guard after valid metadata.
    let nested = private.join("nested");
    std::fs::create_dir(&nested).unwrap();
    std::fs::set_permissions(&nested, std::fs::Permissions::from_mode(0o700)).unwrap();
    let file = root.join("file");
    std::fs::write(&file, b"PRIVATE_CANARY").unwrap();
    for (parent, expected) in [
        (PathBuf::from("relative"), "compute_path_absolute"),
        (root.join("missing"), "compute_directory_missing"),
        (file, "compute_directory_not_private"),
        (alias.clone(), "compute_directory_not_private"),
        (alias.join("nested"), "compute_directory_symlink"),
    ] {
        let original = crate::compute::private_directory(&parent).unwrap_err();
        let (result, observations) = socket_observation(
            &parent.join("channel.sock"),
            nix::unistd::geteuid().as_raw(),
        );
        let error = result.unwrap_err();
        assert_eq!(error.to_string(), expected);
        assert_eq!(error.to_string(), original.to_string());
        assert_eq!(
            observations,
            vec![(SocketCondition::ParentValidation, socket_io_kind(&original))]
        );
    }
    for mode in [0o755, 0o770, 0o600] {
        std::fs::set_permissions(&private, std::fs::Permissions::from_mode(mode)).unwrap();
        let (result, observations) = socket_observation(
            &private.join("channel.sock"),
            nix::unistd::geteuid().as_raw(),
        );
        assert_eq!(
            result.unwrap_err().to_string(),
            "compute_directory_not_private"
        );
        assert_eq!(
            observations,
            vec![(SocketCondition::ParentValidation, SocketIoKind::None)]
        );
    }
    std::fs::set_permissions(&private, std::fs::Permissions::from_mode(0o700)).unwrap();
}

#[test]
fn socket_preflight_distinguishes_metadata_type_and_owner_without_following_links() {
    use std::os::unix::fs::symlink;
    let directory = private_socket_directory();
    let root = directory.path().canonicalize().unwrap();
    let owner = nix::unistd::geteuid().as_raw();
    let socket = root.join("channel.sock");
    let _listener = std::os::unix::net::UnixListener::bind(&socket).unwrap();
    let file = root.join("file");
    std::fs::write(&file, b"PRIVATE_CANARY").unwrap();
    let alias = root.join("alias");
    symlink(&socket, &alias).unwrap();
    for (path, uid, condition, io, expected) in [
        (
            root.join("missing"),
            owner,
            SocketCondition::SocketMetadata,
            SocketIoKind::NotFound,
            None,
        ),
        (
            file,
            owner,
            SocketCondition::NotSocket,
            SocketIoKind::None,
            Some("resident_socket_owner"),
        ),
        (
            alias,
            owner,
            SocketCondition::NotSocket,
            SocketIoKind::None,
            Some("resident_socket_owner"),
        ),
        (
            socket,
            owner ^ 1,
            SocketCondition::OwnerMismatch,
            SocketIoKind::None,
            Some("resident_socket_owner"),
        ),
    ] {
        let (result, observations) = socket_observation(&path, uid);
        let error = result.unwrap_err();
        if let Some(expected) = expected {
            assert_eq!(error.to_string(), expected);
        } else {
            assert_eq!(
                error.downcast_ref::<std::io::Error>().unwrap().kind(),
                std::io::ErrorKind::NotFound
            );
        }
        assert_eq!(observations, vec![(condition, io)]);
    }
}

#[test]
fn socket_diagnostic_io_kinds_are_closed_and_never_include_raw_errors() {
    for (kind, expected) in [
        (std::io::ErrorKind::NotFound, SocketIoKind::NotFound),
        (
            std::io::ErrorKind::PermissionDenied,
            SocketIoKind::PermissionDenied,
        ),
        (std::io::ErrorKind::Interrupted, SocketIoKind::Interrupted),
        (std::io::ErrorKind::InvalidInput, SocketIoKind::InvalidInput),
        (std::io::ErrorKind::InvalidData, SocketIoKind::InvalidData),
        (std::io::ErrorKind::BrokenPipe, SocketIoKind::Other),
    ] {
        let error = anyhow::Error::from(std::io::Error::new(kind, "PRIVATE_CANARY"))
            .context("/private/path-canary");
        assert_eq!(socket_io_kind(&error), expected);
        let mut output = Vec::new();
        observe_socket_failure(true, SocketCondition::SocketMetadata, &error, &mut output);
        assert!(output.len() <= MAX_SOCKET_DIAGNOSTIC);
        let output = String::from_utf8(output).unwrap();
        assert!(!output.contains("CANARY"));
        assert!(!output.contains("/private"));
    }
    assert_eq!(
        socket_io_kind(&anyhow::anyhow!("PRIVATE_CANARY")),
        SocketIoKind::None
    );
}

#[test]
fn socket_diagnostic_is_optional_and_cannot_replace_the_original_error() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("PRIVATE_CANARY"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            panic!("no_extra_flush")
        }
    }
    let error = anyhow::anyhow!("resident_socket_owner");
    let mut output = Vec::new();
    observe_socket_failure(false, SocketCondition::NotSocket, &error, &mut output);
    assert!(output.is_empty());
    observe_socket_failure(true, SocketCondition::NotSocket, &error, &mut output);
    assert_eq!(output, b"VP_PUBLIC_REQUESTER_SOCKET_FAILURE_V1 {\"condition\":\"not_socket\",\"io_kind\":\"none\",\"version\":1}\n");
    let directory = private_socket_directory();
    let path = directory.path().canonicalize().unwrap().join("file");
    std::fs::write(&path, b"PRIVATE_CANARY").unwrap();
    let error = socket_preflight(
        &path,
        nix::unistd::geteuid().as_raw(),
        |condition, error| {
            observe_socket_failure(true, condition, error, Broken);
        },
    )
    .unwrap_err();
    assert_eq!(error.to_string(), "resident_socket_owner");
}

#[test]
fn connect_diagnostic_io_kinds_are_closed_and_never_include_raw_errors() {
    use std::io::ErrorKind as K;
    for (kind, expected) in [
        (K::NotFound, ConnectIoKind::NotFound),
        (K::PermissionDenied, ConnectIoKind::PermissionDenied),
        (K::ConnectionRefused, ConnectIoKind::ConnectionRefused),
        (K::ConnectionReset, ConnectIoKind::ConnectionReset),
        (K::ConnectionAborted, ConnectIoKind::ConnectionAborted),
        (K::NotConnected, ConnectIoKind::NotConnected),
        (K::AddrInUse, ConnectIoKind::AddrInUse),
        (K::AddrNotAvailable, ConnectIoKind::AddrNotAvailable),
        (K::TimedOut, ConnectIoKind::TimedOut),
        (K::Interrupted, ConnectIoKind::Interrupted),
        (K::WouldBlock, ConnectIoKind::WouldBlock),
        (K::InvalidInput, ConnectIoKind::InvalidInput),
        (K::InvalidData, ConnectIoKind::InvalidData),
        (K::UnexpectedEof, ConnectIoKind::Other),
    ] {
        let error = std::io::Error::new(kind, "/private/PATH_UID_PID_ERROR_CANARY");
        assert_eq!(connect_io_kind(Some(&error)), expected);
        let mut output = Vec::new();
        observe_connect_failure(true, ConnectCondition::ConnectIo, Some(&error), &mut output);
        let output = String::from_utf8(output).unwrap();
        assert!(output.len() <= MAX_CONNECT_DIAGNOSTIC);
        assert!(!output.contains("CANARY") && !output.contains("/private"));
    }
    assert_eq!(connect_io_kind(None), ConnectIoKind::None);
}

#[test]
fn connect_diagnostic_is_optional_and_cannot_replace_original_peer_error() {
    struct Broken;
    impl std::io::Write for Broken {
        fn write(&mut self, _: &[u8]) -> std::io::Result<usize> {
            Err(std::io::Error::other("PRIVATE_CANARY"))
        }
        fn flush(&mut self) -> std::io::Result<()> {
            panic!("no_extra_flush")
        }
    }
    let mut output = Vec::new();
    observe_connect_failure(false, ConnectCondition::PeerUidMismatch, None, &mut output);
    assert!(output.is_empty());
    observe_connect_failure(true, ConnectCondition::ConnectDeadline, None, &mut output);
    assert_eq!(output, b"VP_PUBLIC_REQUESTER_CONNECT_FAILURE_V1 {\"condition\":\"connect_deadline\",\"io_kind\":\"none\",\"version\":1}\n");
    let error = check_peer_uid(Ok(123), 456, |condition, error| {
        observe_connect_failure(true, condition, error, Broken);
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "resident_socket_peer");
    let error = check_peer_uid(
        Err(std::io::Error::from_raw_os_error(libc::EACCES)),
        456,
        |condition, error| observe_connect_failure(true, condition, error, Broken),
    )
    .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(libc::EACCES)
    );
}

#[test]
fn connect_peer_check_preserves_original_io_owner_guard_and_success() {
    let mut observed = Vec::new();
    check_peer_uid(Ok(123), 123, |_, _| {
        panic!("success is never an observation")
    })
    .unwrap();
    let error = check_peer_uid(Ok(123), 456, |condition, error| {
        observed.push((condition, connect_io_kind(error)));
    })
    .unwrap_err();
    assert_eq!(error.to_string(), "resident_socket_peer");
    assert_eq!(
        observed,
        vec![(ConnectCondition::PeerUidMismatch, ConnectIoKind::None)]
    );
    observed.clear();
    let error = check_peer_uid(
        Err(std::io::Error::from_raw_os_error(libc::EBADF)),
        456,
        |condition, error| observed.push((condition, connect_io_kind(error))),
    )
    .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .raw_os_error(),
        Some(libc::EBADF)
    );
    assert_eq!(
        observed,
        vec![(ConnectCondition::PeerCredentialIo, ConnectIoKind::Other)]
    );
}

#[tokio::test]
async fn connect_socket_preserves_original_io_and_success_guards() {
    let directory = private_socket_directory();
    let path = directory.path().join("channel.sock");
    let original = UnixStream::connect(&path).await.unwrap_err();
    let mut observed = Vec::new();
    let error = connect_socket(
        &path,
        Instant::now() + Duration::from_secs(5),
        |condition, error| {
            observed.push((condition, connect_io_kind(error)));
        },
    )
    .await
    .unwrap_err();
    assert_eq!(
        error
            .downcast_ref::<std::io::Error>()
            .unwrap()
            .raw_os_error(),
        original.raw_os_error()
    );
    assert_eq!(
        observed,
        vec![(ConnectCondition::ConnectIo, ConnectIoKind::NotFound)]
    );
    let _listener = tokio::net::UnixListener::bind(&path).unwrap();
    connect_socket(&path, Instant::now() + Duration::from_secs(5), |_, _| {
        panic!("successful same-owner connection has no failure observation");
    })
    .await
    .unwrap();
}
