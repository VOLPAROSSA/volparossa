// SPDX-License-Identifier: GPL-3.0-only
//! Actual CLI processes and chunk framing against a local protocol peer, in a disposable netns.
//! This is not a different-UID, packaged-agent, overlay, or message-delivery proof.

use std::{
    fs,
    path::Path,
    process::{Command, Output, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{SigningKey, VerifyingKey};
use rand_core::OsRng;
use tokio::{io::AsyncReadExt as _, net::UnixListener};
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkStore, Metadata, Publication, SignedManifest, Validity,
    VerifiedManifest,
    private_message::{RecipientKeyPair, open_private_message, publish_private_message},
    publish,
    transfer::{TransferLimits, pull_from_peer, serve_peer},
};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentReceipt, ContentTransferReady, ControlResponse, ControlResult,
    control_request::Operation, control_response::Payload, read_request, write_response,
};

const INNER: &str = "VOLPAROSSA_HANDOFF_TEST_PARENT_NETNS";
#[test]
fn ciphertext_handoff_cli_round_trip_and_correlation_are_real() {
    isolated(
        "ciphertext_handoff_cli_round_trip_and_correlation_are_real",
        scenario(),
    );
}

#[test]
fn public_content_handoff_cli_is_explicit_streamed_and_empty_safe() {
    isolated(
        "public_content_handoff_cli_is_explicit_streamed_and_empty_safe",
        public_scenario(),
    );
}

fn isolated(test_name: &str, scenario: impl Future<Output = ()>) {
    let current = fs::read_link("/proc/self/ns/net").expect("current namespace");
    if let Some(parent) = std::env::var_os(INNER) {
        assert_ne!(
            current.as_os_str(),
            parent,
            "never run socket proof on host"
        );
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .expect("isolated runtime")
            .block_on(scenario);
        return;
    }
    let output = Command::new("/usr/bin/unshare")
        .args(["--user", "--map-root-user", "--net"])
        .arg(std::env::current_exe().expect("current test executable"))
        .args(["--exact", test_name, "--nocapture"])
        .env(INNER, current)
        .output()
        .expect("execute proof in a disposable user/network namespace");
    assert!(
        output.status.success(),
        "isolated CLI proof failed (no host socket fallback): {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn cache_limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 8 * 1024 * 1024,
        max_entries: 32,
        min_free_bytes: 0,
    }
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .expect("clock")
        .as_secs()
}

async fn invoke(root: &Path, arguments: Vec<String>) -> Output {
    let root = root.to_owned();
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_volparossa"))
            .current_dir(&root)
            .arg("--control-socket")
            .arg(root.join("control.sock"))
            .arg("content")
            .args(arguments)
            .stdin(Stdio::null())
            .output()
            .expect("actual CLI process")
    })
    .await
    .expect("CLI process task")
}

fn arguments(
    root: &Path,
    operation: &str,
    user: &str,
    agent: &str,
    key: &VerifyingKey,
) -> Vec<String> {
    [
        operation.to_owned(),
        "--manifest".into(),
        "manifest.pb".into(),
        "--publisher-key".into(),
        hex::encode(key.as_bytes()),
        "--cache".into(),
        user.into(),
        "--agent-cache".into(),
        root.join(agent).to_str().expect("fixture path").into(),
        "--min-free-bytes".into(),
        "0".into(),
    ]
    .into()
}

#[derive(Clone, Copy)]
enum Fault {
    None,
    WrongReady,
    WrongFinal,
}

#[allow(clippy::too_many_lines)] // Keep the exact Ready/chunks/final protocol transcript together.
async fn exchange(
    root: &Path,
    args: Vec<String>,
    manifest: &VerifiedManifest,
    fault: Fault,
) -> Output {
    let socket = root.join("control.sock");
    let listener = UnixListener::bind(&socket).expect("isolated local-control fixture");
    let server = async {
        let (mut stream, _) = listener.accept().await.expect("CLI connection");
        let request = read_request(&mut stream)
            .await
            .expect("bounded control request");
        let (encoded, key, cache, importing, allow_public_content) =
            match request.operation.expect("operation") {
                Operation::ContentImport(value) => (
                    value.manifest,
                    value.publisher_key,
                    value.cache,
                    true,
                    value.allow_public_content,
                ),
                Operation::ContentExport(value) => (
                    value.manifest,
                    value.publisher_key,
                    value.cache,
                    false,
                    value.allow_public_content,
                ),
                _ => panic!("expected only explicit ciphertext handoff"),
            };
        let key =
            VerifyingKey::from_bytes(&key.try_into().expect("public key bytes")).expect("key");
        let verified = SignedManifest::decode(&encoded)
            .expect("canonical manifest")
            .verify(&key, now())
            .expect("trusted sender");
        assert_eq!(verified.manifest_id(), manifest.manifest_id());
        assert_eq!(
            allow_public_content,
            manifest.metadata().content_type == "application/octet-stream"
        );
        assert!(
            Path::new(&cache).starts_with(root),
            "only fixture-owned paths"
        );
        let mut ready_id = manifest.manifest_id().to_vec();
        if matches!(fault, Fault::WrongReady) {
            ready_id[0] ^= 1;
        }
        let response = ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: ControlResult::Ok as i32,
            diagnostic_code: "CONTENT_TRANSFER_READY".into(),
            payload: Some(Payload::ContentTransferReady(ContentTransferReady {
                manifest_id: ready_id,
                bytes: manifest.length(),
                chunks: u32::try_from(manifest.chunks().len()).expect("bounded chunks"),
            })),
        };
        write_response(&mut stream, &response).await.expect("Ready");
        if matches!(fault, Fault::WrongReady) {
            assert_eq!(
                stream
                    .read(&mut [0; 1])
                    .await
                    .expect("closed invalid handoff"),
                0
            );
            return;
        }
        let limits = TransferLimits {
            exchange_timeout: Duration::from_secs(5),
            session_timeout: Duration::from_secs(30),
            max_requests: manifest.chunks().len().max(1),
            max_bytes: manifest.length().max(1),
        };
        let mut store = if importing {
            ChunkStore::create(Path::new(&cache), cache_limits())
        } else {
            ChunkStore::open(Path::new(&cache), cache_limits())
        }
        .expect("independent owned store");
        let progress = if importing {
            pull_from_peer(&mut stream, manifest, &mut store, limits).await
        } else {
            serve_peer(&mut stream, manifest, &mut store, limits).await
        }
        .expect("real framed chunk transfer");
        assert_eq!(progress.bytes, manifest.length());
        assert_eq!(progress.chunks, manifest.chunks().len());
        assert_eq!(progress.missing, 0);
        let mut request_id = request.request_id;
        if matches!(fault, Fault::WrongFinal) {
            request_id[0] ^= 1;
        }
        write_response(
            &mut stream,
            &ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id,
                result: ControlResult::Ok as i32,
                diagnostic_code: "CONTENT_OK".into(),
                payload: Some(Payload::Content(ContentReceipt {
                    bytes: manifest.length(),
                    chunks: u32::try_from(manifest.chunks().len()).expect("bounded chunks"),
                    ..ContentReceipt::default()
                })),
            },
        )
        .await
        .expect("correlated final receipt");
    };
    let ((), output) = tokio::time::timeout(Duration::from_secs(40), async {
        tokio::join!(server, invoke(root, args))
    })
    .await
    .expect("bounded real CLI exchange");
    drop(listener);
    fs::remove_file(socket).expect("remove only fixture listener path");
    output
}

fn successful(output: &Output) -> serde_json::Value {
    assert!(
        output.status.success(),
        "CLI failed: {}",
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).expect("normal CLI JSON")
}

#[allow(clippy::too_many_lines)] // One ordered real-process round trip and its bounded rejections.
async fn scenario() {
    let directory = tempfile::tempdir().expect("private fixture root");
    let root = directory.path();
    let sender = SigningKey::generate(&mut OsRng);
    let key = sender.verifying_key();
    let recipient = RecipientKeyPair::generate().expect("recipient key held only in memory");
    let plaintext = vec![0x53; CHUNK_BYTES + 127];
    let mut source =
        ChunkStore::create(&root.join("user-source"), cache_limits()).expect("user source");
    let signed = publish_private_message(
        &plaintext,
        recipient.public_key(),
        &sender,
        Validity {
            created: now(),
            expires: now() + 300,
        },
        &mut source,
    )
    .expect("real HPKE ciphertext fixture");
    let manifest = signed
        .verify(&key, now())
        .expect("verified ciphertext manifest");
    fs::write(root.join("manifest.pb"), signed.encode()).expect("public signed manifest");
    drop(source);

    let imported = successful(
        &exchange(
            root,
            arguments(root, "import", "user-source", "agent-cache", &key),
            &manifest,
            Fault::None,
        )
        .await,
    );
    assert_eq!(imported["operation"], "content_import");
    assert_eq!(imported["ciphertext_bytes"], manifest.length());
    assert_eq!(imported["private_keys_transferred"], false);
    let exported = successful(
        &exchange(
            root,
            arguments(root, "export", "user-copy", "agent-cache", &key),
            &manifest,
            Fault::None,
        )
        .await,
    );
    assert_eq!(exported["operation"], "content_export");
    assert_eq!(exported["manifest_id"], hex::encode(manifest.manifest_id()));
    assert_eq!(exported["network_transfer"], false);
    let mut copied = ChunkStore::open(&root.join("user-copy"), cache_limits())
        .expect("fresh-process output cache");
    let opened = open_private_message(&manifest, &mut [&mut copied], now(), &recipient)
        .expect("recipient-only authenticated plaintext");
    assert_eq!(opened.as_slice(), plaintext);
    drop(copied);

    // These fail before any agent connection or destination creation; there is no listener.
    let wrong_key = SigningKey::generate(&mut OsRng).verifying_key();
    assert!(
        !invoke(
            root,
            arguments(root, "import", "user-source", "wrong-key", &wrong_key)
        )
        .await
        .status
        .success()
    );
    assert!(!root.join("wrong-key").exists());
    assert!(
        !invoke(
            root,
            arguments(root, "export", "user-copy", "agent-cache", &key)
        )
        .await
        .status
        .success()
    );
    let mut copied = ChunkStore::open(&root.join("user-copy"), cache_limits())
        .expect("existing cache preserved");
    assert_eq!(
        open_private_message(&manifest, &mut [&mut copied], now(), &recipient)
            .expect("unchanged ciphertext")
            .as_slice(),
        plaintext
    );
    drop(copied);

    let rejected = exchange(
        root,
        arguments(root, "export", "bad-ready", "agent-cache", &key),
        &manifest,
        Fault::WrongReady,
    )
    .await;
    assert!(!rejected.status.success());
    assert!(!root.join("bad-ready").exists());
    let rejected = exchange(
        root,
        arguments(root, "export", "bad-final", "agent-cache", &key),
        &manifest,
        Fault::WrongFinal,
    )
    .await;
    assert!(!rejected.status.success());
    assert!(
        rejected.stdout.is_empty(),
        "uncorrelated final receipt is never success"
    );
    let mut retained = ChunkStore::open(&root.join("bad-final"), cache_limits())
        .expect("verified ciphertext retained after final failure");
    assert_eq!(
        open_private_message(&manifest, &mut [&mut retained], now(), &recipient)
            .expect("retained bytes remain authentic")
            .as_slice(),
        plaintext
    );
}

async fn public_scenario() {
    for length in [4 * 1024 * 1024 + 127, 0] {
        public_roundtrip(length).await;
    }
}

async fn public_roundtrip(length: usize) {
    let directory = tempfile::tempdir().expect("explicit public fixture root");
    let root = directory.path();
    let sender = SigningKey::generate(&mut OsRng);
    let key = sender.verifying_key();
    let mut bytes = vec![0; length];
    for (index, chunk) in bytes.chunks_mut(CHUNK_BYTES).enumerate() {
        chunk.fill(u8::try_from(index).expect("bounded distinct chunks"));
    }
    let mut source = ChunkStore::create(&root.join("user-source"), cache_limits()).expect("source");
    let signed = publish(
        &mut bytes.as_slice(),
        Publication {
            metadata: Metadata {
                name: "explicit-file.bin".into(),
                revision: 1,
                content_type: "application/octet-stream".into(),
            },
            length: u64::try_from(length).expect("bounded object length"),
            validity: Validity {
                created: now(),
                expires: now() + 300,
            },
        },
        &sender,
        &mut source,
    )
    .expect("signed ordinary native publication");
    let manifest = signed.verify(&key, now()).expect("trusted public manifest");
    fs::write(root.join("manifest.pb"), signed.encode()).expect("public descriptor");
    drop(source);
    let import = arguments(root, "import", "user-source", "agent-cache", &key);
    let rejected = invoke(root, import.clone()).await;
    assert!(!rejected.status.success());
    assert!(String::from_utf8_lossy(&rejected.stderr).contains("--public-content"));
    assert!(!root.join("agent-cache").exists());
    let mut import = import;
    import.push("--public-content".into());
    let imported = successful(&exchange(root, import, &manifest, Fault::None).await);
    assert_eq!(imported["public_content"], true);
    assert_eq!(imported["content_bytes"], length);
    assert_eq!(imported["ciphertext_format_verified"], false);
    assert!(imported.get("ciphertext_bytes").is_none());
    let mut export = arguments(root, "export", "user-copy", "agent-cache", &key);
    assert!(!invoke(root, export.clone()).await.status.success());
    assert!(!root.join("user-copy").exists());
    export.push("--public-content".into());
    let exported = successful(&exchange(root, export, &manifest, Fault::None).await);
    assert_eq!(exported["content_bytes"], length);
    assert_eq!(exported["public_content"], true);
    assert_eq!(exported["origin_authenticated"], false);
    assert_eq!(exported["network_transfer"], false);
    successful(
        &invoke(
            root,
            [
                "assemble".into(),
                "--manifest".into(),
                "manifest.pb".into(),
                "--publisher-key".into(),
                hex::encode(key.as_bytes()),
                "--cache".into(),
                "user-copy".into(),
                "--output".into(),
                "assembled.bin".into(),
                "--min-free-bytes".into(),
                "0".into(),
            ]
            .into(),
        )
        .await,
    );
    assert_eq!(
        fs::read(root.join("assembled.bin")).expect("actual CLI reconstruction"),
        bytes
    );
}
