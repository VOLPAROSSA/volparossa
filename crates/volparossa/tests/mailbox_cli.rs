// SPDX-License-Identifier: GPL-3.0-only
//! Actual CLI processes and signed local-stream mailbox service; not a protected-network proof.

use std::{
    collections::BTreeMap,
    fs,
    io::Write as _,
    os::unix::fs::{OpenOptionsExt as _, PermissionsExt as _},
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicI32, AtomicUsize, Ordering},
    },
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use serde_json::Value;
use sha2::{Digest as _, Sha256};
use tokio::{
    net::{UnixListener, UnixStream},
    task::JoinHandle,
};
use volparossa_content::{
    CacheLimits, SignedManifest,
    mailbox::{
        SignedMailboxGrant,
        store::MailboxStore,
        wire::{MailboxCommand, MailboxOperation, MailboxService, begin, bridge},
    },
    provider::{PublicationRegistry, serve_publication},
    transfer::TransferLimits,
};
use volparossa_identity::{IdentityStore, Passphrase};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentReceipt, ControlResponse, ControlResult, MailboxReady,
    control_request::Operation, control_response::Payload, read_request, write_response,
};

const MARKER: &str = "VOLPAROSSA_HANDOFF_TEST_PARENT_NETNS";

#[test]
fn mailbox_cli_discovers_and_decrypts_after_sender_and_provider_process_lifetimes() {
    isolated(
        "mailbox_cli_discovers_and_decrypts_after_sender_and_provider_process_lifetimes",
        round_trip(),
    );
}

#[test]
fn mailbox_cli_rejects_wrong_identity_and_uncorrelated_final_before_exposing_plaintext() {
    isolated(
        "mailbox_cli_rejects_wrong_identity_and_uncorrelated_final_before_exposing_plaintext",
        rejects_final(),
    );
}

#[test]
fn mailbox_cli_fetch_waits_for_import_and_retries_partial_ack_after_restart() {
    isolated(
        "mailbox_cli_fetch_waits_for_import_and_retries_partial_ack_after_restart",
        split_import(),
    );
}

fn isolated(name: &str, scenario: impl Future<Output = ()>) {
    if let Some(parent) = std::env::var_os(MARKER) {
        assert_ne!(
            fs::read_link("/proc/self/ns/net").unwrap().as_os_str(),
            parent
        );
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(scenario);
        return;
    }
    let output = Command::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/run-isolated-test.sh"
    ))
    .arg(std::env::current_exe().unwrap())
    .args([name, MARKER, "none"])
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "isolated mailbox CLI failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

struct Fixture {
    directory: tempfile::TempDir,
    provider_keys: [Arc<SigningKey>; 2],
    sender_key: String,
    owner_key: String,
    owner_encrypted: Vec<u8>,
    fault: Arc<AtomicI32>,
    requests: Arc<AtomicUsize>,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let root = directory.path();
        let passphrase = Passphrase::new(b"temporary mailbox CLI proof passphrase").unwrap();
        let mut password = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(root.join("passphrase"))
            .unwrap();
        password
            .write_all(b"temporary mailbox CLI proof passphrase")
            .unwrap();
        let sender = IdentityStore::new(root.join("sender"))
            .create(&passphrase)
            .unwrap();
        let owner = IdentityStore::new(root.join("recipient"))
            .create(&passphrase)
            .unwrap();
        let sender_key = hex::encode(sender.ed25519_public_key_bytes().unwrap());
        let owner_key = hex::encode(owner.ed25519_public_key_bytes().unwrap());
        let owner_encrypted = fs::read(root.join("recipient")).unwrap();
        Self {
            directory,
            provider_keys: [
                Arc::new(SigningKey::generate(&mut OsRng)),
                Arc::new(SigningKey::generate(&mut OsRng)),
            ],
            sender_key,
            owner_key,
            owner_encrypted,
            fault: Arc::new(AtomicI32::new(0)),
            requests: Arc::new(AtomicUsize::new(0)),
        }
    }

    fn server(&self, reopen: bool) -> JoinHandle<()> {
        let root = self.directory.path();
        let socket = root.join("control.sock");
        if reopen {
            fs::remove_file(&socket).unwrap();
        }
        let listener = UnixListener::bind(socket).unwrap();
        let mut providers = BTreeMap::new();
        for (index, key) in self.provider_keys.iter().enumerate() {
            let path = root.join(format!("provider-{index}"));
            let limits = CacheLimits {
                max_bytes: 8 * 1024 * 1024,
                max_entries: 64,
                min_free_bytes: 0,
            };
            let store = if reopen {
                MailboxStore::open(&path, limits, now())
            } else {
                MailboxStore::create(&path, limits, now())
            }
            .unwrap();
            providers.insert(
                key.verifying_key().to_bytes(),
                Arc::new(MailboxService::new(key.clone(), store)),
            );
        }
        let fault = self.fault.clone();
        let requests = self.requests.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                requests.fetch_add(1, Ordering::SeqCst);
                serve_request(&mut stream, &providers, fault.load(Ordering::SeqCst)).await;
            }
        })
    }

    async fn invoke(&self, arguments: &[&str]) -> Output {
        let root = self.directory.path().to_path_buf();
        let arguments: Vec<String> = arguments.iter().map(|arg| (*arg).to_owned()).collect();
        tokio::time::timeout(
            Duration::from_secs(25),
            tokio::task::spawn_blocking(move || {
                Command::new(env!("CARGO_BIN_EXE_volparossa"))
                    .current_dir(&root)
                    .arg("--control-socket")
                    .arg(root.join("control.sock"))
                    .args(["content", "mailbox"])
                    .args(arguments)
                    .stdin(Stdio::null())
                    .output()
                    .unwrap()
            }),
        )
        .await
        .expect("bounded CLI command")
        .unwrap()
    }

    async fn success(&self, arguments: &[&str]) -> Value {
        let output = self.invoke(arguments).await;
        assert!(
            output.status.success(),
            "CLI failed: {}",
            String::from_utf8_lossy(&output.stderr)
        );
        serde_json::from_slice(&output.stdout).unwrap()
    }

    async fn invite_and_enroll(&self) {
        let first = hex::encode(self.provider_keys[0].verifying_key().to_bytes());
        let second = hex::encode(self.provider_keys[1].verifying_key().to_bytes());
        self.success(&[
            "invite",
            "--sender-key",
            &self.sender_key,
            "--provider-key",
            &first,
            "--provider-key",
            &second,
            "--invitation",
            "invitation",
            "--identity",
            "recipient",
            "--passphrase-file",
            "passphrase",
            "--lifetime-seconds",
            "300",
        ])
        .await;
        let enrolled = self
            .success(&[
                "enroll",
                "--invitation",
                "invitation",
                "--identity",
                "recipient",
                "--passphrase-file",
                "passphrase",
            ])
            .await;
        assert_eq!(enrolled["registered_providers"], 2);
    }

    async fn send(&self) -> Value {
        self.success(&[
            "send",
            "--invitation",
            "invitation",
            "--owner-key",
            &self.owner_key,
            "--input",
            "input",
            "--cache",
            "sender-cache",
            "--manifest",
            "sender-manifest",
            "--identity",
            "sender",
            "--passphrase-file",
            "passphrase",
            "--min-free-bytes",
            "0",
            "--lifetime-seconds",
            "200",
        ])
        .await
    }

    fn receive_args<'a>(output: &'a str, identity: &'a str) -> [&'a str; 11] {
        [
            "receive",
            "--invitation",
            "invitation",
            "--output-dir",
            output,
            "--identity",
            identity,
            "--passphrase-file",
            "passphrase",
            "--min-free-bytes",
            "0",
        ]
    }
}

async fn serve_request(
    stream: &mut UnixStream,
    providers: &BTreeMap<[u8; 32], Arc<MailboxService>>,
    fault: i32,
) {
    let request = read_request(stream).await.unwrap();
    let Some(Operation::MailboxRemote(parameters)) = request.operation else {
        panic!("typed mailbox operation required")
    };
    let provider: [u8; 32] = parameters.provider_key.as_slice().try_into().unwrap();
    if fault == -3
        && parameters.operation == MailboxOperation::List as i32
        && providers
            .first_key_value()
            .is_some_and(|(first, _)| first == &provider)
    {
        let mut unavailable = response(
            request.request_id,
            "MAILBOX_UNAVAILABLE",
            Payload::Ack(volparossa_local_control::Empty {}),
        );
        unavailable.result = ControlResult::Unavailable as i32;
        write_response(stream, &unavailable).await.unwrap();
        return;
    }
    let signed = SignedMailboxGrant::decode(&parameters.grant).unwrap();
    let owner = VerifyingKey::from_bytes(&signed.owner_key_hint().unwrap()).unwrap();
    let grant = signed.verify(&owner, now()).unwrap();
    let command = MailboxCommand {
        operation: MailboxOperation::try_from(parameters.operation).unwrap(),
        manifest: (!parameters.manifest.is_empty())
            .then(|| SignedManifest::decode(&parameters.manifest).unwrap()),
        message_id: (!parameters.message_id.is_empty())
            .then(|| parameters.message_id.as_slice().try_into().unwrap()),
    };
    let mut registry = PublicationRegistry::new();
    registry.set_mailbox(providers[&provider].clone());
    let (mut remote, mut serving) = tokio::io::duplex(4096);
    let service = tokio::spawn(async move {
        serve_publication(&mut serving, &registry, TransferLimits::default())
            .await
            .unwrap();
    });
    let challenge = begin(&mut remote, &provider).await.unwrap();
    write_response(
        stream,
        &response(
            request.request_id.clone(),
            "MAILBOX_READY",
            Payload::MailboxReady(MailboxReady {
                provider_key: provider.to_vec(),
                challenge: challenge.encode(),
            }),
        ),
    )
    .await
    .unwrap();
    let receipt = bridge(stream, &mut remote, &challenge, &grant, &command)
        .await
        .unwrap();
    service.await.unwrap();
    let mut correlation = request.request_id;
    if fault == parameters.operation
        || (fault == -4
            && parameters.operation == MailboxOperation::Acknowledge as i32
            && providers
                .last_key_value()
                .is_some_and(|(last, _)| last == &provider))
    {
        correlation[0] ^= 1;
    }
    write_response(
        stream,
        &response(
            correlation,
            "CONTENT_OK",
            Payload::Content(ContentReceipt {
                bytes: receipt.ciphertext_bytes(),
                providers_used: 1,
                provider_peer_ids: vec!["12D3ProviderA".into()],
                control_relay_peer_id: "12D3Control".into(),
                ..ContentReceipt::default()
            }),
        ),
    )
    .await
    .unwrap();
}

fn response(request_id: Vec<u8>, code: &str, payload: Payload) -> ControlResponse {
    ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id,
        result: ControlResult::Ok as i32,
        diagnostic_code: code.into(),
        payload: Some(payload),
    }
}

async fn round_trip() {
    let fixture = Fixture::new();
    let server = fixture.server(false);
    fixture.invite_and_enroll().await;
    let plaintext = vec![0x62; 262_144 + 127];
    fs::write(fixture.directory.path().join("input"), &plaintext).unwrap();
    let sent = fixture.send().await;
    assert_eq!(sent["confirmed_providers"], 2);
    let id = sent["message_id"].as_str().unwrap();
    let root = fixture.directory.path();
    for name in ["input", "sender", "sender-manifest"] {
        fs::remove_file(root.join(name)).unwrap();
    }
    server.abort();
    let _ = server.await;
    let restarted = fixture.server(true);
    let received = fixture
        .success(&Fixture::receive_args("received", "recipient"))
        .await;
    assert_eq!(received["messages_discovered"], 1);
    assert_eq!(received["messages_delivered"], 1);
    assert_eq!(fs::read(root.join("received").join(id)).unwrap(), plaintext);
    assert_eq!(
        fs::metadata(root.join("received"))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o700
    );
    assert_eq!(
        fs::metadata(root.join("received").join(id))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let before = fixture.requests.load(Ordering::SeqCst);
    assert!(
        !fixture
            .invoke(&Fixture::receive_args("received", "recipient"))
            .await
            .status
            .success()
    );
    assert_eq!(fixture.requests.load(Ordering::SeqCst), before);
    let empty = fixture
        .success(&Fixture::receive_args("empty", "recipient"))
        .await;
    assert_eq!(empty["messages_discovered"], 0);
    assert_eq!(
        fs::read(root.join("recipient")).unwrap(),
        fixture.owner_encrypted
    );
    restarted.abort();
    let _ = restarted.await;
}

async fn rejects_final() {
    let fixture = Fixture::new();
    let server = fixture.server(false);
    fixture.invite_and_enroll().await;
    fs::write(
        fixture.directory.path().join("input"),
        b"no plaintext before a correlated delivery",
    )
    .unwrap();
    fixture.send().await;
    let before = fixture.requests.load(Ordering::SeqCst);
    assert!(
        !fixture
            .invoke(&Fixture::receive_args("wrong-owner", "sender"))
            .await
            .status
            .success()
    );
    assert!(!fixture.directory.path().join("wrong-owner").exists());
    assert_eq!(fixture.requests.load(Ordering::SeqCst), before);
    fixture
        .fault
        .store(MailboxOperation::Get as i32, Ordering::SeqCst);
    let output = fixture
        .invoke(&Fixture::receive_args("uncorrelated", "recipient"))
        .await;
    assert!(!output.status.success());
    assert_eq!(
        fs::read_dir(fixture.directory.path().join("uncorrelated"))
            .unwrap()
            .count(),
        0
    );
    fixture.fault.store(-3, Ordering::SeqCst);
    let recovered = fixture
        .success(&Fixture::receive_args("recovered", "recipient"))
        .await;
    assert_eq!(
        recovered["messages_delivered"], 1,
        "failed final did not acknowledge/delete remote custody"
    );
    assert_eq!(recovered["listed_providers"], 1);
    assert_eq!(
        recovered["degraded"], true,
        "a failed list does not hide the other valid replica"
    );
    server.abort();
    let _ = server.await;
}

async fn split_import() {
    let fixture = Fixture::new();
    let server = fixture.server(false);
    fixture.invite_and_enroll().await;
    let root = fixture.directory.path();
    let payload = b"Message-ID: <fixture@example.invalid>\r\nSubject: private fixture\r\n\r\nretained until explicit import";
    fs::write(root.join("input"), payload).unwrap();
    let sent = fixture.send().await;
    let id = sent["message_id"].as_str().unwrap();
    let mut fetch_args = Fixture::receive_args("handoff", "recipient");
    fetch_args[0] = "fetch";
    let fetched = fixture.success(&fetch_args).await;
    assert_eq!(fetched["messages_fetched"], 1);
    assert_eq!(fetched["acknowledged_providers_per_message"], 0);
    assert_eq!(fetched["consumer_import_attested"], false);
    assert_eq!(fetched["application_import_proven"], false);
    let pending = format!("handoff/{id}/pending.pb");
    let token = format!("handoff/{id}/import-token");
    let payload_path = format!("handoff/{id}/payload");
    assert_eq!(fs::read(root.join(&payload_path)).unwrap(), payload);
    for name in [&pending, &token, &payload_path] {
        assert_eq!(
            fs::metadata(root.join(name)).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    // A second independent fetch still sees the original custody: download never ACKed it.
    fetch_args[4] = "still-present";
    assert_eq!(fixture.success(&fetch_args).await["messages_fetched"], 1);
    let imported_digest = hex::encode(Sha256::digest(payload));
    let mut args = vec![
        "confirm-import",
        "--pending",
        pending.as_str(),
        "--import-token-file",
        token.as_str(),
        "--imported-sha256",
        imported_digest.as_str(),
        "--identity",
        "recipient",
        "--passphrase-file",
        "passphrase",
    ];
    let before = fixture.requests.load(Ordering::SeqCst);
    args[8] = "sender";
    assert!(!fixture.invoke(&args).await.status.success());
    args[8] = "recipient";
    let wrong_digest = "00".repeat(32);
    args[6] = &wrong_digest;
    assert!(!fixture.invoke(&args).await.status.success());
    args[6] = &imported_digest;
    let original_token = fs::read(root.join(&token)).unwrap();
    let mut wrong_token = original_token.clone();
    wrong_token[0] ^= 1;
    fs::write(root.join(&token), wrong_token).unwrap();
    assert!(!fixture.invoke(&args).await.status.success());
    fs::write(root.join(&token), &original_token).unwrap();
    let original_receipt = fs::read(root.join(&pending)).unwrap();
    let mut wrong_receipt = original_receipt.clone();
    *wrong_receipt.last_mut().unwrap() ^= 1;
    fs::write(root.join(&pending), wrong_receipt).unwrap();
    assert!(!fixture.invoke(&args).await.status.success());
    fs::write(root.join(&pending), &original_receipt).unwrap();
    assert_eq!(
        fixture.requests.load(Ordering::SeqCst),
        before,
        "invalid confirmation must never contact a provider"
    );
    // The test consumer saves a separate file; this is not a native mail/Signal importer proof.
    fs::copy(root.join(&payload_path), root.join("consumer-imported")).unwrap();
    fs::File::open(root.join("consumer-imported"))
        .unwrap()
        .sync_all()
        .unwrap();
    fixture.fault.store(-4, Ordering::SeqCst);
    assert!(!fixture.invoke(&args).await.status.success());
    let directory = root.join("handoff").join(id);
    assert!(!directory.join("confirmed.json").exists());
    assert_eq!(
        fs::read_dir(&directory)
            .unwrap()
            .filter(|item| item
                .as_ref()
                .unwrap()
                .file_name()
                .to_string_lossy()
                .starts_with("ack-"))
            .count(),
        1
    );
    assert_eq!(fs::read(root.join(&pending)).unwrap(), original_receipt);
    assert_eq!(fs::read(root.join(&token)).unwrap(), original_token);
    server.abort();
    let _ = server.await;
    fixture.fault.store(0, Ordering::SeqCst);
    let restarted = fixture.server(true);
    let confirmed = fixture.success(&args).await;
    assert_eq!(confirmed["acknowledged_providers"], 2);
    assert_eq!(confirmed["consumer_import_attested"], true);
    assert_eq!(confirmed["application_import_proven"], false);
    assert_eq!(confirmed["local_handoff_retained"], true);
    assert!(directory.join("confirmed.json").is_file());
    assert_eq!(
        fixture.success(&args).await["acknowledged_providers"],
        2,
        "exact confirmation retry remains idempotent"
    );
    fetch_args[4] = "after-confirmation";
    assert_eq!(fixture.success(&fetch_args).await["messages_fetched"], 0);
    assert_eq!(fs::read(root.join("consumer-imported")).unwrap(), payload);
    restarted.abort();
    let _ = restarted.await;
}
