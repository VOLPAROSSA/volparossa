// SPDX-License-Identifier: GPL-3.0-only
//! Isolated fixture control peer; no real provider discovery or network hosting.
use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use std::{
    fs,
    os::unix::fs::OpenOptionsExt as _,
    path::Path,
    process::Stdio,
    time::{Duration, SystemTime, UNIX_EPOCH},
};
use tokio::{
    io::{AsyncBufReadExt as _, BufReader},
    net::{TcpStream, UnixListener},
    process::Command,
    time::timeout,
};
use volparossa_content::{
    CacheLimits, ChunkStore, Metadata, Publication, Validity, publish,
    site::SITE_CONTENT_TYPE,
    transfer::{TransferLimits, serve_peer},
};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentReceipt, ControlResponse, ControlResult,
    NamedContentTransferReady, control_request::Operation, control_response::Payload, read_request,
    write_response,
};

const NAME: &str = "studio-synthetic-local-viewer";

// Closed progress records are the only diagnostic projected from the private
// invocation log. Panic hooks and child output remain private and are deleted.
#[derive(Clone, Copy)]
pub(super) enum Stage {
    Pack,
    Decode,
    ChildControls,
    Sign,
    Transfer,
    Ready,
    BrowserObservation,
    Shutdown,
    Complete,
}
impl Stage {
    fn name(self) -> &'static str {
        match self {
            Self::Pack => "pack",
            Self::Decode => "decode",
            Self::ChildControls => "child_controls",
            Self::Sign => "sign",
            Self::Transfer => "transfer",
            Self::Ready => "ready",
            Self::BrowserObservation => "browser_observation",
            Self::Shutdown => "shutdown",
            Self::Complete => "complete",
        }
    }
}
pub(super) fn diagnostic(stage: Stage) {
    emit_diagnostic(stage, "not_observed");
}
fn emit_diagnostic(stage: Stage, browser_stage: &str) {
    // Callers supply either a literal or the exact closed projection below.
    println!(
        "STUDIO_VIEWER_DIAGNOSTIC {}",
        serde_json::json!({
            "schema": 1, "core_stage": stage.name(), "browser_stage": browser_stage
        })
    );
}
fn failed_browser_stage(path: &Path) -> &'static str {
    use std::io::Read as _;
    let read = || -> Option<serde_json::Value> {
        let file = fs::OpenOptions::new()
            .read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_NONBLOCK)
            .open(path)
            .ok()?;
        let metadata = file.metadata().ok()?;
        if !metadata.is_file() || metadata.len() > 4096 {
            return None;
        }
        let mut bytes = Vec::new();
        file.take(4097).read_to_end(&mut bytes).ok()?;
        if bytes.len() > 4096 {
            return None;
        }
        serde_json::from_slice(&bytes).ok()
    };
    let Some(value) = read() else {
        return "invalid_receipt";
    };
    let Some(object) = value.as_object() else {
        return "invalid_receipt";
    };
    if object.len() != 5
        || value["schema"].as_u64() != Some(1)
        || value["status"] != "failed"
        || value["browser_closed"].as_bool().is_none()
        || !value["rendered_http_requests"]
            .as_u64()
            .is_some_and(|n| n <= 1024)
    {
        return "invalid_receipt";
    }
    match value["stage"].as_str() {
        Some("launch") => "launch",
        Some("http") => "http",
        Some("securityheaders") => "securityheaders",
        Some("marker") => "marker",
        Some("style") => "style",
        Some("assets") => "assets",
        Some("close") => "close",
        _ => "invalid_receipt",
    }
}

// The outer Python runner owns/drains the whole group on cancellation. This
// guard additionally kills and reaps direct children on Rust assertion failure
// or a dropped timeout future, before their private directories are removed.
struct OwnedChild(tokio::process::Child);
impl std::ops::Deref for OwnedChild {
    type Target = tokio::process::Child;
    fn deref(&self) -> &Self::Target {
        &self.0
    }
}
impl std::ops::DerefMut for OwnedChild {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.0
    }
}
impl Drop for OwnedChild {
    fn drop(&mut self) {
        if let Some(pid) = self.0.id() {
            let _ = self.0.start_kill();
            loop {
                match nix::sys::wait::waitpid(nix::unistd::Pid::from_raw(pid as i32), None) {
                    Err(nix::errno::Errno::EINTR) => continue,
                    // Tokio may already have reaped a successfully completed child.
                    Ok(_) | Err(nix::errno::Errno::ECHILD) => break,
                    Err(_) => break,
                }
            }
        }
    }
}

// Hosted-only adversarial controls execute inside the same already verified
// disposable namespace, without a new command mode or runtime dependency.
async fn verify_owned_child_cleanup() {
    fn child(executable: &str, args: &[&str]) -> OwnedChild {
        OwnedChild(
            Command::new(executable)
                .args(args)
                .stdin(Stdio::null())
                .stdout(Stdio::null())
                .stderr(Stdio::null())
                .kill_on_drop(true)
                .spawn()
                .unwrap(),
        )
    }
    fn reaped(pid: u32) {
        assert_eq!(
            nix::sys::wait::waitpid(
                nix::unistd::Pid::from_raw(pid as i32),
                Some(nix::sys::wait::WaitPidFlag::WNOHANG)
            ),
            Err(nix::errno::Errno::ECHILD),
            "owned direct child must already be reaped"
        );
    }
    let mut exited = child("/bin/false", &[]);
    let pid = exited.id().unwrap();
    assert!(
        !timeout(Duration::from_secs(2), exited.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    drop(exited);
    reaped(pid);

    let cancelled = child("/bin/sleep", &["10"]);
    let pid = cancelled.id().unwrap();
    let panic = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _owned = cancelled;
        panic!("synthetic hosted child-drop cleanup control");
    }));
    assert!(panic.is_err());
    reaped(pid);

    let mut timed = child("/bin/sleep", &["10"]);
    let pid = timed.id().unwrap();
    assert!(
        timeout(Duration::from_millis(25), timed.wait())
            .await
            .is_err()
    );
    drop(timed);
    reaped(pid);
}

pub(super) fn verify(bytes: &[u8], assets: &[serde_json::Value]) -> serde_json::Value {
    // No socket or browser may run on the development host.
    let parent = std::env::var_os("VOLPAROSSA_HANDOFF_TEST_PARENT_NETNS")
        .expect("isolated parent netns marker");
    assert_ne!(
        fs::read_link("/proc/self/ns/net").unwrap().as_os_str(),
        parent
    );
    assert!(!nix::unistd::Uid::effective().is_root());
    let status = fs::read_to_string("/proc/self/status").unwrap();
    for name in ["CapInh:", "CapPrm:", "CapEff:", "CapBnd:", "CapAmb:"] {
        assert_eq!(
            u64::from_str_radix(
                status
                    .lines()
                    .find(|line| line.starts_with(name))
                    .unwrap()
                    .split_whitespace()
                    .nth(1)
                    .unwrap(),
                16
            )
            .unwrap(),
            0
        );
    }
    assert_eq!(
        status
            .lines()
            .find(|line| line.starts_with("NoNewPrivs:"))
            .unwrap()
            .split_whitespace()
            .nth(1),
        Some("1")
    );
    tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .unwrap()
        .block_on(async {
            diagnostic(Stage::ChildControls);
            verify_owned_child_cleanup().await;
            timeout(Duration::from_secs(65), scenario(bytes, assets))
                .await
                .expect("bounded viewer scenario")
        })
}

async fn scenario(bytes: &[u8], assets: &[serde_json::Value]) -> serde_json::Value {
    use sha2::{Digest as _, Sha256};
    diagnostic(Stage::Sign);
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let limits = CacheLimits {
        max_bytes: 32 * 1024 * 1024,
        max_entries: 256,
        min_free_bytes: 0,
    };
    let mut store = ChunkStore::create(&root.join("served-store"), limits).unwrap();
    let key = SigningKey::generate(&mut OsRng);
    let now = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    // Production signing API with a fresh in-memory test identity. No real key,
    // persistent identity initialization, participation, or publication dispatch.
    let signed = publish(
        &mut &bytes[..],
        Publication {
            metadata: Metadata {
                name: NAME.into(),
                revision: 1,
                content_type: SITE_CONTENT_TYPE.into(),
            },
            length: bytes.len() as u64,
            validity: Validity {
                created: now,
                expires: now + 120,
            },
        },
        &key,
        &mut store,
    )
    .unwrap();
    let verified = signed.verify(&key.verifying_key(), now).unwrap();
    diagnostic(Stage::Transfer);
    let listener = UnixListener::bind(root.join("control.sock")).unwrap();
    let mut child = OwnedChild(
        Command::new(env!("CARGO_BIN_EXE_volparossa"))
            .current_dir(root)
            .env("TMPDIR", root)
            .arg("--control-socket")
            .arg(root.join("control.sock"))
            .args(["content", "site", "open", "--publisher-key"])
            .arg(hex::encode(key.verifying_key().to_bytes()))
            .args(["--name", NAME, "--min-revision", "1", "--cache"])
            .arg(root.join("agent-cache"))
            .args(["--min-free-bytes", "0", "--lifetime-seconds", "60"])
            .stdin(Stdio::null())
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap(),
    );
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    let mut line = String::new();
    let peer = async {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        let Some(Operation::ContentFetchName(parameters)) = request.operation else {
            panic!("named transfer required")
        };
        assert_eq!(parameters.publisher_key, key.verifying_key().to_bytes());
        assert_eq!(parameters.name, NAME);
        assert_eq!(parameters.min_revision, Some(1));
        assert!(!parameters.reuse_cache && !parameters.cache_only);
        assert_eq!(Path::new(&parameters.cache), root.join("agent-cache"));
        let response = |code: &str, payload| ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: request.request_id.clone(),
            result: ControlResult::Ok as i32,
            diagnostic_code: code.into(),
            private_storage_remote_detail: None,
            payload: Some(payload),
        };
        write_response(
            &mut stream,
            &response(
                "NAMED_CONTENT_TRANSFER_READY",
                Payload::NamedContentTransferReady(NamedContentTransferReady {
                    manifest: signed.encode(),
                    cache_only: false,
                }),
            ),
        )
        .await
        .unwrap();
        let progress = serve_peer(
            &mut stream,
            &verified,
            &mut store,
            TransferLimits {
                exchange_timeout: Duration::from_secs(5),
                session_timeout: Duration::from_secs(15),
                max_requests: verified.chunks().len(),
                max_bytes: verified.length(),
            },
        )
        .await
        .unwrap();
        assert_eq!(progress.bytes, bytes.len() as u64);
        assert_eq!(progress.missing, 0);
        write_response(
            &mut stream,
            &response(
                "CONTENT_OK",
                Payload::Content(ContentReceipt {
                    bytes: verified.length(),
                    chunks: verified.chunks().len() as u32,
                    peer_bytes: verified.length(),
                    providers_used: 1,
                    provider_peer_ids: vec!["12D3SyntheticLocalFixture".into()],
                    control_relay_peer_id: "12D3SyntheticMockControl".into(),
                    ..ContentReceipt::default()
                }),
            ),
        )
        .await
        .unwrap();
    };
    timeout(Duration::from_secs(20), async {
        let ((), read) = tokio::join!(peer, stdout.read_line(&mut line));
        assert!(read.unwrap() > 0 && line.len() <= 16384);
    })
    .await
    .unwrap();
    drop(listener);
    fs::remove_file(root.join("control.sock")).unwrap();
    diagnostic(Stage::Ready);
    let ready: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(ready["operation"], "native_site_ready");
    assert_eq!(ready["native_publisher_authenticated"], true);
    assert_eq!(ready["https_origin_authenticated"], false);
    assert_eq!(ready["assets"].as_u64(), Some(assets.len() as u64));
    assert_eq!(ready["peer_bytes"].as_u64(), Some(bytes.len() as u64));
    let url = ready["site_url"].as_str().unwrap();
    let host = url
        .strip_prefix("http://")
        .unwrap()
        .strip_suffix('/')
        .unwrap();
    let (domain, port) = host.rsplit_once(':').unwrap();
    assert!(domain.starts_with("vp") && domain.ends_with(".localhost"));
    assert_eq!(domain.len(), 2 + 32 + ".localhost".len());
    let port = port.parse::<u16>().unwrap();
    let sha256 = hex::encode(Sha256::digest(bytes));
    let handoff = root.join("viewer-context.json");
    let receipt_path = root.join("viewer-browser.json");
    let handoff_value = serde_json::json!({"schema":1,"url":url,"bundle_sha256":sha256,
        "bundle_bytes":bytes.len(),"assets":assets,"receipt":receipt_path});
    {
        use std::io::Write as _;
        let mut file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .mode(0o600)
            .open(&handoff)
            .unwrap();
        serde_json::to_writer(&mut file, &handoff_value).unwrap();
        file.flush().unwrap();
    }
    diagnostic(Stage::BrowserObservation);
    let mut browser = OwnedChild(
        Command::new(std::env::var_os("STUDIO_NODE").unwrap())
            .arg(std::env::var_os("STUDIO_VIEWER_OBSERVER").unwrap())
            .arg(&handoff)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap(),
    );
    let browser_status = timeout(Duration::from_secs(35), browser.wait()).await;
    if !matches!(&browser_status, Ok(Ok(status)) if status.success()) {
        emit_diagnostic(
            Stage::BrowserObservation,
            failed_browser_stage(&receipt_path),
        );
    }
    assert!(browser_status.unwrap().unwrap().success());
    assert!(fs::metadata(&receipt_path).unwrap().len() <= 4096);
    let browser_receipt: serde_json::Value =
        serde_json::from_slice(&fs::read(receipt_path).unwrap()).unwrap();
    assert_eq!(browser_receipt.as_object().unwrap().len(), 12);
    assert_eq!(browser_receipt["schema"], 1);
    assert_eq!(browser_receipt["bundle_sha256"], sha256);
    assert_eq!(
        browser_receipt["bundle_bytes"].as_u64(),
        Some(bytes.len() as u64)
    );
    assert_eq!(
        browser_receipt["asset_count"].as_u64(),
        Some(assets.len() as u64)
    );
    for flag in [
        "visible_marker",
        "computed_37px",
        "all_assets_verified",
        "security_headers_preserved",
        "independent_browser",
        "browser_closed",
    ] {
        assert_eq!(browser_receipt[flag], true);
    }
    assert_eq!(browser_receipt["status"], "passed");
    assert!((1..=1024).contains(&browser_receipt["rendered_http_requests"].as_u64().unwrap()));
    diagnostic(Stage::Shutdown);
    nix::sys::signal::kill(
        nix::unistd::Pid::from_raw(child.id().unwrap() as i32),
        nix::sys::signal::Signal::SIGTERM,
    )
    .unwrap();
    line.clear();
    timeout(Duration::from_secs(5), stdout.read_line(&mut line))
        .await
        .unwrap()
        .unwrap();
    let closed: serde_json::Value = serde_json::from_str(&line).unwrap();
    assert_eq!(closed["operation"], "native_site_closed");
    assert_eq!(closed["private_spool_removed"], true);
    assert!(
        timeout(Duration::from_secs(5), child.wait())
            .await
            .unwrap()
            .unwrap()
            .success()
    );
    assert!(
        TcpStream::connect((std::net::Ipv4Addr::LOCALHOST, port))
            .await
            .is_err()
    );
    assert!(!fs::read_dir(root).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with("volparossa-site-")
    }));
    let result = serde_json::json!({"schema":1,"status":"passed","bundle_sha256":sha256,
        "bundle_bytes":bytes.len(),"asset_count":assets.len(),"ephemeral_test_publisher":true,
        "mock_local_control_peer":true,"direct_child_adversarial_cleanup":true,"production_signed_verification":true,"actual_site_open_cli":true,
        "browser":browser_receipt,"private_spool_removed":true,"listener_closed":true,
        "network_published":false,"independent_peer_retrieval":false});
    directory.close().unwrap();
    diagnostic(Stage::Complete);
    result
}
