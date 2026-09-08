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

#[test]
fn named_cache_only_correlates_ready_and_rejects_network_receipts() {
    isolated(
        "named_cache_only_correlates_ready_and_rejects_network_receipts",
        cache_only_downloads(),
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
    cache_only: bool,
    retained: Option<(SignedManifest, VerifiedManifest)>,
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
            cache_only: false,
            retained: None,
        }
    }

    fn retain_for_cache_only(&mut self) {
        let (signed, manifest) = self.publication(Fault::None);
        self.store
            .remember_named_manifest(&signed, &self.key.verifying_key(), now())
            .unwrap();
        let original = self
            .store
            .cached_named_manifest(&self.key.verifying_key().to_bytes(), NAME, 3, now())
            .unwrap()
            .unwrap();
        assert_eq!(original.encode(), signed.encode());
        self.retained = Some((original, manifest));
        self.cache_only = true;
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
        assert_eq!(parameters.cache_only, self.cache_only);
        assert_eq!(
            Path::new(&parameters.cache),
            self.directory.path().join(if self.cache_only {
                "served-store"
            } else {
                "agent-cache"
            })
        );
        let (signed, verified) = match &self.retained {
            Some(original) => original.clone(),
            None => self.publication(fault),
        };
        write_response(
            &mut stream,
            &response(
                request.request_id.clone(),
                "NAMED_CONTENT_TRANSFER_READY",
                Payload::NamedContentTransferReady(NamedContentTransferReady {
                    manifest: signed.encode(),
                    cache_only: self.cache_only != matches!(fault, Fault::WrongMode),
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
        let network = !self.cache_only || matches!(fault, Fault::NetworkReceipt);
        write_response(
            &mut stream,
            &response(
                request_id,
                "CONTENT_OK",
                Payload::Content(transfer_receipt(&verified, network)),
            ),
        )
        .await
        .unwrap();
    }
}

fn transfer_receipt(manifest: &VerifiedManifest, network: bool) -> ContentReceipt {
    ContentReceipt {
        bytes: manifest.length(),
        chunks: u32::try_from(manifest.chunks().len()).unwrap(),
        peer_bytes: if network { manifest.length() } else { 0 },
        providers_used: u32::from(network),
        provider_peer_ids: if network {
            vec!["12D3ProviderA".into()]
        } else {
            Vec::new()
        },
        control_relay_peer_id: if network {
            "12D3Control".into()
        } else {
            String::new()
        },
        ..ContentReceipt::default()
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
    WrongMode,
    NetworkReceipt,
}

impl Fault {
    fn rejects_ready(self) -> bool {
        matches!(
            self,
            Self::WrongPublisher
                | Self::WrongName
                | Self::OldRevision
                | Self::Expired
                | Self::WrongMode
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
    invoke_mode(root, key, name, resume, false).await
}

async fn invoke_mode(
    root: &Path,
    key: [u8; 32],
    name: &str,
    resume: bool,
    cache_only: bool,
) -> Output {
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
            .arg(root.join(if cache_only {
                "served-store"
            } else {
                "agent-cache"
            }))
            .args(["--local-output", &name, "--min-free-bytes", "0"]);
        if resume {
            command.args(["--reuse-cache", "--min-revision", "3"]);
        }
        if cache_only {
            command.arg("--cache-only");
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
    let cache_only = fixture.cache_only;
    let listener = UnixListener::bind(root.join("control.sock")).unwrap();
    let ((), output) = tokio::time::timeout(Duration::from_secs(30), async {
        tokio::join!(
            fixture.serve(&listener, fault, resume),
            invoke_mode(&root, key, name, resume, cache_only)
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
        assert_eq!(result["cache_only"], false);
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
        Fault::WrongMode,
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

async fn cache_only_downloads() {
    let mut fixture = Fixture::new();
    fixture.retain_for_cache_only();
    let original = fixture.retained.as_ref().unwrap().0.encode();
    for fault in [Fault::WrongMode, Fault::NetworkReceipt] {
        let output = exchange(&mut fixture, "rejected.bin", fault, true).await;
        assert!(
            !output.status.success(),
            "cache-only source contract accepted {fault:?}"
        );
        assert_eq!(directory_names(fixture.directory.path()), ["served-store"]);
    }
    let output = exchange(&mut fixture, "local.bin", Fault::None, true).await;
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["cache_only"], true);
    assert_eq!(report["peer_bytes"], 0);
    assert_eq!(report["origin_body_bytes"], 0);
    assert_eq!(report["origin_range_requests"], 0);
    assert_eq!(
        report["publication_expires_unix_seconds"],
        fixture.retained.as_ref().unwrap().1.validity().expires
    );
    assert_eq!(report["providers_used"], 0);
    assert_eq!(report["provider_peer_ids"], serde_json::json!([]));
    assert_eq!(report["control_relay_peer_id"], "");
    assert_eq!(
        report["manifest_id"],
        hex::encode(ChunkId::digest(&original).as_bytes())
    );
    let path = fixture.directory.path().join("local.bin");
    assert_eq!(fs::read(&path).unwrap(), fixture.bytes);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o600
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
