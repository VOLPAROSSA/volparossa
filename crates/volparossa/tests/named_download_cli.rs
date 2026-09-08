// SPDX-License-Identifier: GPL-3.0-only
//! Actual CLI/local-stream proof, not a provider-discovery or globally-latest-version proof.
//! Sockets exist only inside the verified disposable, capability-free network namespace.

#[path = "named_download_cli/site.rs"]
mod site;

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::Path,
    process::{Command, Output, Stdio},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use tokio::{io::AsyncReadExt as _, net::UnixListener};
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkId, ChunkStore, Metadata, Publication, SignedManifest, Validity,
    VerifiedManifest, publish,
    transfer::{TransferLimits, serve_peer},
};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentReceipt, ControlResponse, ControlResult,
    NamedContentTransferReady, control_request::Operation, control_response::Payload, read_request,
    write_response,
};

const NAME: &str = "notes.résumé";
const MARKER: &str = "VOLPAROSSA_HANDOFF_TEST_PARENT_NETNS";

#[test]
fn named_download_streams_verified_bytes_to_new_private_user_output() {
    isolated(
        "named_download_streams_verified_bytes_to_new_private_user_output",
        successful_downloads(),
    );
}

#[test]
fn named_download_rejects_wrong_publisher_name_revision_expiry_and_final() {
    isolated(
        "named_download_rejects_wrong_publisher_name_revision_expiry_and_final",
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
        "isolated named CLI proof failed: {}{}",
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
    key: SigningKey,
    bytes: Vec<u8>,
    content_type: &'static str,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let store = ChunkStore::create(
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
        Self {
            directory,
            store,
            key: SigningKey::generate(&mut OsRng),
            bytes,
            content_type: "application/octet-stream",
        }
    }

    fn publication(&mut self, fault: Fault) -> (SignedManifest, VerifiedManifest) {
        let wrong_key = SigningKey::generate(&mut OsRng);
        let key = if matches!(fault, Fault::WrongPublisher) {
            &wrong_key
        } else {
            &self.key
        };
        let created = if matches!(fault, Fault::Expired) {
            now() - 600
        } else {
            now()
        };
        let signed = publish(
            &mut self.bytes.as_slice(),
            Publication {
                metadata: Metadata {
                    name: if matches!(fault, Fault::WrongName) {
                        "different-name"
                    } else {
                        NAME
                    }
                    .into(),
                    revision: if matches!(fault, Fault::OldRevision) {
                        2
                    } else {
                        3
                    },
                    content_type: self.content_type.into(),
                },
                length: u64::try_from(self.bytes.len()).unwrap(),
                validity: Validity {
                    created,
                    expires: created + 300,
                },
            },
            key,
            &mut self.store,
        )
        .unwrap();
        let verified = signed.verify(&key.verifying_key(), created).unwrap();
        (signed, verified)
    }

    async fn serve(&mut self, listener: &UnixListener, fault: Fault, resume: bool) {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        let Some(Operation::ContentFetchName(parameters)) = request.operation else {
            panic!("expected named stream upgrade without an output path or supplied manifest");
        };
        assert_eq!(
            parameters.publisher_key,
            self.key.verifying_key().to_bytes()
        );
        assert_eq!(parameters.name, NAME);
        assert_eq!(parameters.min_revision, resume.then_some(3));
        assert_eq!(parameters.reuse_cache, resume);
        assert_eq!(
            Path::new(&parameters.cache),
            self.directory.path().join("agent-cache")
        );
        let (signed, verified) = self.publication(fault);
        write_response(
            &mut stream,
            &response(
                request.request_id.clone(),
                "NAMED_CONTENT_TRANSFER_READY",
                Payload::NamedContentTransferReady(NamedContentTransferReady {
                    manifest: signed.encode(),
                }),
            ),
        )
        .await
        .unwrap();
        if fault.rejects_ready() {
            assert_eq!(stream.read(&mut [0; 1]).await.unwrap(), 0);
            return;
        }
        let progress = serve_peer(
            &mut stream,
            &verified,
            &mut self.store,
            TransferLimits {
                exchange_timeout: Duration::from_secs(5),
                session_timeout: Duration::from_secs(15),
                max_requests: verified.chunks().len(),
                max_bytes: verified.length(),
            },
        )
        .await
        .unwrap();
        assert_eq!(progress.bytes, verified.length());
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
                    bytes: verified.length(),
                    chunks: u32::try_from(verified.chunks().len()).unwrap(),
                    peer_bytes: verified.length(),
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
    WrongPublisher,
    WrongName,
    OldRevision,
    Expired,
    Disconnect,
    WrongFinal,
}

impl Fault {
    fn rejects_ready(self) -> bool {
        matches!(
            self,
            Self::WrongPublisher | Self::WrongName | Self::OldRevision | Self::Expired
        )
    }
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

async fn invoke(root: &Path, key: [u8; 32], name: &str, resume: bool) -> Output {
    let root = root.to_owned();
    let name = name.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_volparossa"));
        command
            .current_dir(&root)
            .arg("--control-socket")
            .arg(root.join("control.sock"))
            .args(["content", "fetch-name", "--publisher-key"])
            .arg(hex::encode(key))
            .args(["--name", NAME, "--cache"])
            .arg(root.join("agent-cache"))
            .args(["--local-output", &name, "--min-free-bytes", "0"]);
        if resume {
            command.args(["--reuse-cache", "--min-revision", "3"]);
        }
        command
            .stdin(Stdio::null())
            .output()
            .expect("real CLI process")
    })
    .await
    .unwrap()
}

async fn exchange(fixture: &mut Fixture, name: &str, fault: Fault, resume: bool) -> Output {
    let root = fixture.directory.path().to_owned();
    let key = fixture.key.verifying_key().to_bytes();
    let listener = UnixListener::bind(root.join("control.sock")).unwrap();
    let ((), output) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(
            fixture.serve(&listener, fault, resume),
            invoke(&root, key, name, resume)
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
    for (name, resume) in [("new.bin", false), ("resumed.bin", true)] {
        let output = exchange(&mut fixture, name, Fault::None, resume).await;
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let result: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(result["operation"], "named_content_download");
        assert_eq!(result["name"], NAME);
        assert_eq!(result["revision"], 3);
        assert_eq!(
            result["publisher_key"],
            hex::encode(fixture.key.verifying_key().to_bytes())
        );
        assert_eq!(
            result["sha256"],
            hex::encode(ChunkId::digest(&fixture.bytes).as_bytes())
        );
        assert_eq!(result["bytes"], u64::try_from(fixture.bytes.len()).unwrap());
        assert_eq!(result["chunks"], 2);
        assert_eq!(result["origin_authenticated"], false);
        assert_eq!(result["globally_latest"], false);
        assert_eq!(result["local_delivery"], true);
        assert_eq!(result["ownership_changed"], false);
        assert_eq!(result["local_output"], name);
        assert_eq!(
            result["cache"],
            fixture
                .directory
                .path()
                .join("agent-cache")
                .to_str()
                .unwrap()
        );
        assert_eq!(result["output_mode"], "0600");
        let path = fixture.directory.path().join(name);
        assert_eq!(fs::read(&path).unwrap(), fixture.bytes);
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
        let refused = invoke(
            fixture.directory.path(),
            fixture.key.verifying_key().to_bytes(),
            name,
            resume,
        )
        .await;
        assert!(!refused.status.success());
        assert!(String::from_utf8_lossy(&refused.stderr).contains("already exists"));
        assert_eq!(fs::read(path).unwrap(), fixture.bytes);
    }
    assert_eq!(
        directory_names(fixture.directory.path()),
        ["new.bin", "resumed.bin", "served-store"]
    );
}

async fn rejected_downloads() {
    let mut fixture = Fixture::new();
    for fault in [
        Fault::WrongPublisher,
        Fault::WrongName,
        Fault::OldRevision,
        Fault::Expired,
        Fault::Disconnect,
        Fault::WrongFinal,
    ] {
        let output = exchange(&mut fixture, "rejected.bin", fault, true).await;
        assert!(
            !output.status.success(),
            "invalid named response accepted: {fault:?}"
        );
        assert_eq!(
            directory_names(fixture.directory.path()),
            ["served-store"],
            "no published output, manifest, secondary cache or tempfile after rejection"
        );
    }
}

fn directory_names(path: &Path) -> Vec<String> {
    let mut names: Vec<_> = fs::read_dir(path)
        .unwrap()
        .map(|entry| entry.unwrap().file_name().into_string().unwrap())
        .collect();
    names.sort();
    names
}
