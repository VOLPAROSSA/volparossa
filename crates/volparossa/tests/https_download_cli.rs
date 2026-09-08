// SPDX-License-Identifier: GPL-3.0-only
//! Actual CLI processes against a local protocol fixture, not an HTTPS-origin or overlay proof.
//! Every socket is created only inside a verified disposable, capability-free network namespace.

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Output, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tokio::{
    io::{AsyncBufReadExt as _, AsyncReadExt as _, AsyncWriteExt as _, BufReader},
    net::{TcpStream, UnixListener},
};
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkId, ChunkStore, Metadata, Publication, SignedManifest, Validity,
    VerifiedManifest, publish,
    transfer::{TransferLimits, serve_peer},
};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentReceipt, ControlResponse, ControlResult,
    HttpsContentTransferReady, control_request::Operation, control_response::Payload, read_request,
    write_response,
};

const RESOURCE: &str = "https://origin.example/object.bin";
const MARKER: &str = "VOLPAROSSA_HANDOFF_TEST_PARENT_NETNS";

#[test]
fn https_local_output_streams_exact_bytes_and_preserves_origin_accounting() {
    isolated(
        "https_local_output_streams_exact_bytes_and_preserves_origin_accounting",
        successful_downloads(),
    );
}

#[test]
fn https_local_output_is_not_published_before_valid_ready_and_final() {
    isolated(
        "https_local_output_is_not_published_before_valid_ready_and_final",
        rejected_downloads(),
    );
}

fn isolated(test: &str, scenario: impl Future<Output = ()>) {
    isolated_network(test, scenario, "none");
}

fn isolated_network(test: &str, scenario: impl Future<Output = ()>, network: &str) {
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
    .args([test, MARKER, network])
    .output()
    .expect("isolated test runner");
    assert!(
        output.status.success(),
        "isolated CLI proof failed: {}{}",
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
    store: ChunkStore,
    signed: SignedManifest,
    manifest: VerifiedManifest,
    bytes: Vec<u8>,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let mut store = ChunkStore::create(
            &directory.path().join("served-store"),
            CacheLimits {
                max_bytes: 1024 * 1024,
                max_entries: 8,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let mut bytes = vec![0x31; CHUNK_BYTES + 127];
        bytes[CHUNK_BYTES..].fill(0x62);
        let key = SigningKey::generate(&mut OsRng);
        let signed = publish(
            &mut bytes.as_slice(),
            Publication {
                metadata: Metadata {
                    name: "local-protocol-fixture".into(),
                    revision: 1,
                    content_type: "application/octet-stream".into(),
                },
                length: u64::try_from(bytes.len()).unwrap(),
                validity: Validity {
                    created: now(),
                    expires: now() + 300,
                },
            },
            &key,
            &mut store,
        )
        .unwrap();
        let manifest = signed.verify(&key.verifying_key(), now()).unwrap();
        Self {
            directory,
            store,
            signed,
            manifest,
            bytes,
        }
    }

    async fn serve(&mut self, listener: &UnixListener, fault: Fault, origin_bytes: u64) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        let Some(Operation::ContentDownloadHttps(parameters)) = request.operation else {
            panic!("the local-output command requires the typed stream upgrade");
        };
        assert_eq!(parameters.resource_url, RESOURCE);
        assert_eq!(parameters.metadata_path, "/metadata");
        assert_eq!(
            Path::new(&parameters.cache),
            self.directory.path().join("agent-cache")
        );
        assert!(
            parameters.output.is_empty(),
            "user output path must never reach the agent"
        );
        let ready = HttpsContentTransferReady {
            manifest: self.signed.encode(),
            publisher_key: self.manifest.publisher().to_vec(),
            resource_url: if matches!(fault, Fault::WrongResource) {
                "https://different.example/object.bin".into()
            } else {
                RESOURCE.into()
            },
            expires_unix_seconds: if matches!(fault, Fault::ExpiredReady) {
                now() - 1
            } else {
                self.manifest.validity().expires
            },
        };
        write_response(
            &mut stream,
            &response(
                request.request_id.clone(),
                "HTTPS_CONTENT_TRANSFER_READY",
                Payload::HttpsContentTransferReady(ready),
            ),
        )
        .await
        .unwrap();
        if matches!(fault, Fault::WrongResource | Fault::ExpiredReady) {
            assert_eq!(
                stream.read(&mut [0; 1]).await.unwrap(),
                0,
                "no chunk request after invalid Ready"
            );
            return;
        }
        let progress = serve_peer(
            &mut stream,
            &self.manifest,
            &mut self.store,
            TransferLimits {
                exchange_timeout: Duration::from_secs(5),
                session_timeout: Duration::from_secs(15),
                max_requests: self.manifest.chunks().len(),
                max_bytes: self.manifest.length(),
            },
        )
        .await
        .unwrap();
        assert_eq!(progress.bytes, self.manifest.length());
        assert_eq!(progress.chunks, self.manifest.chunks().len());
        assert_eq!(progress.missing, 0);
        if matches!(fault, Fault::Disconnect) {
            return;
        }
        let mut request_id = request.request_id;
        if matches!(fault, Fault::WrongFinal) {
            request_id[0] ^= 1;
        }
        write_response(
            &mut stream,
            &response(
                request_id,
                "CONTENT_OK",
                Payload::Content(ContentReceipt {
                    bytes: self.manifest.length(),
                    chunks: u32::try_from(self.manifest.chunks().len()).unwrap(),
                    origin_authenticated: true,
                    origin_body_bytes: origin_bytes,
                    peer_bytes: self.manifest.length() - origin_bytes,
                    origin_range_requests: u32::from(origin_bytes > 0),
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
}

#[derive(Clone, Copy, Debug)]
enum Fault {
    None,
    WrongResource,
    ExpiredReady,
    Disconnect,
    WrongFinal,
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

async fn invoke(root: &Path, name: &str) -> Output {
    let root = root.to_owned();
    let name = name.to_owned();
    tokio::task::spawn_blocking(move || {
        Command::new(env!("CARGO_BIN_EXE_volparossa"))
            .current_dir(&root)
            .arg("--control-socket")
            .arg(root.join("control.sock"))
            .args([
                "content",
                "fetch-https",
                "--url",
                RESOURCE,
                "--metadata-path",
                "/metadata",
                "--cache",
            ])
            .arg(root.join("agent-cache"))
            .args(["--local-output", &name, "--min-free-bytes", "0"])
            .stdin(Stdio::null())
            .output()
            .expect("real CLI process")
    })
    .await
    .unwrap()
}

async fn exchange(fixture: &mut Fixture, name: &str, fault: Fault, origin_bytes: u64) -> Output {
    let root = fixture.directory.path().to_owned();
    let listener = UnixListener::bind(root.join("control.sock")).unwrap();
    let ((), output) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(
            fixture.serve(&listener, fault, origin_bytes),
            invoke(&root, name)
        )
    })
    .await
    .expect("bounded actual CLI/stream exchange");
    drop(listener);
    fs::remove_file(root.join("control.sock")).unwrap();
    output
}

async fn successful_downloads() {
    let mut fixture = Fixture::new();
    for (name, origin_bytes) in [("peer-only.bin", 0), ("partial-origin.bin", 127)] {
        let output = exchange(&mut fixture, name, Fault::None, origin_bytes).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["operation"], "https_content_download");
        assert_eq!(result["bytes"], fixture.manifest.length());
        assert_eq!(result["chunks"], 2);
        assert_eq!(
            result["sha256"],
            hex::encode(fixture.manifest.object_sha256())
        );
        assert_eq!(
            result["peer_bytes"],
            fixture.manifest.length() - origin_bytes
        );
        assert_eq!(result["origin_body_bytes"], origin_bytes);
        assert_eq!(result["origin_range_requests"], u32::from(origin_bytes > 0));
        assert_eq!(result["origin_authenticated"], true);
        assert_eq!(result["local_delivery"], true);
        assert_eq!(result["origin_authority_persisted"], false);
        assert_eq!(result["ownership_changed"], false);
        assert_eq!(result["output_mode"], "0600");
        let path = fixture.directory.path().join(name);
        let bytes = fs::read(&path).unwrap();
        assert_eq!(bytes, fixture.bytes);
        assert_eq!(
            ChunkId::digest(&bytes).as_bytes(),
            fixture.manifest.object_sha256()
        );
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let refused = invoke(fixture.directory.path(), name).await;
        assert!(
            !refused.status.success(),
            "existing user output cannot be overwritten"
        );
        assert!(String::from_utf8_lossy(&refused.stderr).contains("already exists"));
        assert_eq!(fs::read(&path).unwrap(), fixture.bytes);
    }
    assert_eq!(
        directory_names(fixture.directory.path()),
        ["partial-origin.bin", "peer-only.bin", "served-store"]
    );
}

fn directory_names(path: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}

async fn rejected_downloads() {
    let mut fixture = Fixture::new();
    for fault in [
        Fault::WrongResource,
        Fault::ExpiredReady,
        Fault::Disconnect,
        Fault::WrongFinal,
    ] {
        let output = exchange(&mut fixture, "not-published.bin", fault, 0).await;
        assert!(
            !output.status.success(),
            "invalid local exchange was accepted: {fault:?}"
        );
        assert!(!fixture.directory.path().join("not-published.bin").exists());
        assert_eq!(
            directory_names(fixture.directory.path()),
            ["served-store"],
            "a rejected exchange must leave neither output nor a secondary user cache/tempfile"
        );
    }
}

#[test]
fn browser_download_cli_is_single_use_and_requires_complete_origin_authorized_delivery() {
    isolated_network(
        "browser_download_cli_is_single_use_and_requires_complete_origin_authorized_delivery",
        browser_downloads(),
        "loopback",
    );
}

async fn browser_downloads() {
    let mut fixture = Fixture::new();
    let root = fixture.directory.path().to_owned();
    fs::create_dir(root.join("temporary")).unwrap();
    for fault in [Fault::None, Fault::WrongFinal, Fault::ExpiredReady] {
        let listener = UnixListener::bind(root.join("control.sock")).unwrap();
        let expected = fixture.bytes.clone();
        tokio::time::timeout(Duration::from_secs(30), async {
            tokio::join!(
                fixture.serve(&listener, fault, 127),
                browser_process(&root, fault, &expected)
            );
        })
        .await
        .expect("bounded actual browser-command proof");
        drop(listener);
        fs::remove_file(root.join("control.sock")).unwrap();
        assert!(
            directory_names(&root.join("temporary")).is_empty(),
            "private spool not removed"
        );
    }
}

async fn browser_process(root: &Path, fault: Fault, expected: &[u8]) {
    let mut child = tokio::process::Command::new(env!("CARGO_BIN_EXE_volparossa"))
        .arg("--control-socket")
        .arg(root.join("control.sock"))
        .args([
            "content",
            "browser-download",
            "--url",
            RESOURCE,
            "--metadata-path",
            "/metadata",
            "--cache",
        ])
        .arg(root.join("agent-cache"))
        .args(["--min-free-bytes", "0"])
        .env("TMPDIR", root.join("temporary"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    let count = stdout.read_line(&mut line).await.unwrap();
    if !matches!(fault, Fault::None) {
        assert_eq!(
            count, 0,
            "no browser URL before valid readiness and final receipt"
        );
        assert!(!child.wait_with_output().await.unwrap().status.success());
        return;
    }
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(ready["operation"], "browser_download_ready");
    assert_eq!(ready["authentication_scope"], "cooperative-origin");
    assert!(ready["expires_unix_seconds"].as_u64().unwrap() <= now() + 300);
    let directories = directory_names(&root.join("temporary"));
    assert_eq!(directories.len(), 1);
    let directory = root.join("temporary").join(&directories[0]);
    assert_eq!(
        fs::metadata(&directory).unwrap().permissions().mode() & 0o777,
        0o700
    );
    let files = directory_names(&directory);
    assert_eq!(files.len(), 1);
    assert_eq!(
        fs::metadata(directory.join(&files[0]))
            .unwrap()
            .permissions()
            .mode()
            & 0o777,
        0o600
    );
    let address = consume_browser_link(&ready, expected).await;
    line.clear();
    assert!(stdout.read_line(&mut line).await.unwrap() > 0);
    let completed: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(completed["operation"], "browser_content_download");
    assert_eq!(completed["bytes"].as_u64().unwrap(), expected.len() as u64);
    assert_eq!(
        completed["sha256"],
        hex::encode(ChunkId::digest(expected).as_bytes())
    );
    assert_eq!(
        completed["peer_bytes"].as_u64().unwrap(),
        expected.len() as u64 - 127
    );
    assert_eq!(completed["origin_body_bytes"], 127);
    assert_eq!(completed["origin_range_requests"], 1);
    assert_eq!(completed["private_spool_removed"], true);
    assert_eq!(completed["https_origin_privileges"], false);
    assert!(child.wait_with_output().await.unwrap().status.success());
    assert!(
        TcpStream::connect(&address).await.is_err(),
        "single-use listener still exists"
    );
}

async fn consume_browser_link(ready: &serde_json::Value, expected: &[u8]) -> String {
    let url = ready["download_url"].as_str().unwrap();
    let (address, token) = url
        .strip_prefix("http://")
        .unwrap()
        .split_once('/')
        .unwrap();
    assert!(address.starts_with("127.0.0.1:"));
    assert_eq!(token.len(), 64);
    assert_eq!(hex::decode(token).unwrap().len(), 32);
    let path = format!("/{token}");
    for (host, target) in [
        ("attacker.example", path.as_str()),
        (address, "/wrong-token"),
    ] {
        let response = browser_get(address, host, target).await;
        assert!(response.starts_with(b"HTTP/1.1 404"));
        assert!(response.ends_with(b"\r\n\r\n"));
    }
    let response = browser_get(address, address, &path).await;
    let offset = response
        .windows(4)
        .position(|bytes| bytes == b"\r\n\r\n")
        .unwrap()
        + 4;
    assert!(response.starts_with(b"HTTP/1.1 200 OK"));
    let headers = std::str::from_utf8(&response[..offset]).unwrap();
    assert!(headers.contains("Content-Disposition: attachment;"));
    assert!(headers.contains("Content-Type: application/octet-stream"));
    assert!(headers.contains("Cache-Control: no-store"));
    assert!(headers.contains("X-Content-Type-Options: nosniff"));
    assert_eq!(&response[offset..], expected);
    address.to_owned()
}

async fn browser_get(address: &str, host: &str, path: &str) -> Vec<u8> {
    let mut socket = TcpStream::connect(address).await.unwrap();
    socket
        .write_all(format!("GET {path} HTTP/1.1\r\nHost: {host}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    socket
        .take(1024 * 1024)
        .read_to_end(&mut response)
        .await
        .unwrap();
    response
}
