// SPDX-License-Identifier: GPL-3.0-only
//! Real CLI processes, typed Unix handoffs and durable remote custody backends.
//! The remote hop is a bounded duplex stream, not evidence of a protected overlay route.

use std::{
    fs,
    os::unix::fs::PermissionsExt as _,
    path::{Path, PathBuf},
    process::{Command, Output, Stdio},
    sync::{Arc, Weak},
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use ed25519_dalek::{SigningKey, VerifyingKey};
use serde_json::Value;
use tokio::{net::UnixListener, sync::Mutex};
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkStore, SignedManifest, VerifiedManifest,
    provider::{
        PublicationRegistry,
        custody::{
            CustodyAdmission, CustodyBackend, CustodyError, CustodyFuture, CustodyOperation,
            CustodyReceipt, CustodyService, CustodyState, begin, bridge,
        },
        custody_storage::PublicCustodyStore,
        serve_publication,
    },
    transfer::{TransferLimits, TransferProgress},
};
use volparossa_identity::{IdentityStore, Passphrase, PublicKey};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentCustodyReady, ContentReceipt, ControlResponse, ControlResult,
    control_request::Operation, control_response::Payload, read_request, write_response,
};

const MARKER: &str = "VOLPAROSSA_HANDOFF_TEST_PARENT_NETNS";

#[test]
fn custody_cli_retains_two_real_copies_after_source_loss_and_rejects_bad_final_accounting() {
    isolated(
        "custody_cli_retains_two_real_copies_after_source_loss_and_rejects_bad_final_accounting",
        scenario(),
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
        "isolated custody CLI failed: {}{}",
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

fn limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 8 * 1024 * 1024,
        max_entries: 32,
        min_free_bytes: 0,
    }
}

#[derive(Clone)]
struct DiskBackend {
    storage: PublicCustodyStore,
    staging_parent: PathBuf,
    registry: Weak<Mutex<PublicationRegistry>>,
}

struct Admission {
    source: ChunkStore,
    temporary: tempfile::TempDir,
    backend: DiskBackend,
    signed: SignedManifest,
    manifest: VerifiedManifest,
}

impl CustodyAdmission for Admission {
    fn store(&mut self) -> &mut ChunkStore {
        &mut self.source
    }

    fn commit(self: Box<Self>) -> CustodyFuture<'static, ()> {
        Box::pin(async move {
            let Self {
                mut source,
                temporary,
                backend,
                signed,
                manifest,
            } = *self;
            backend
                .storage
                .admit(&signed, &manifest, &mut source, now())
                .map_err(|_| CustodyError::Store)?;
            drop(source);
            temporary.close().map_err(|_| CustodyError::Store)?;
            let registry = backend.registry.upgrade().ok_or(CustodyError::Store)?;
            backend
                .storage
                .register_complete(&mut *registry.lock().await, now())
                .map_err(|_| CustodyError::Store)?;
            Ok(())
        })
    }
}

impl CustodyBackend for DiskBackend {
    fn begin_deposit(
        &self,
        signed: SignedManifest,
        manifest: VerifiedManifest,
    ) -> CustodyFuture<'_, Box<dyn CustodyAdmission>> {
        Box::pin(async move {
            let temporary =
                tempfile::tempdir_in(&self.staging_parent).map_err(|_| CustodyError::Store)?;
            let source = ChunkStore::create(&temporary.path().join("payload"), limits())
                .map_err(|_| CustodyError::Store)?;
            Ok(Box::new(Admission {
                source,
                temporary,
                backend: self.clone(),
                signed,
                manifest,
            }) as Box<dyn CustodyAdmission>)
        })
    }

    fn inspect(
        &self,
        _signed: SignedManifest,
        manifest: VerifiedManifest,
    ) -> CustodyFuture<'_, CustodyState> {
        Box::pin(async move {
            let complete = self
                .storage
                .inspect_complete(manifest.manifest_id(), now())
                .map_err(|_| CustodyError::Store)?
                .is_some();
            let registry = self.registry.upgrade().ok_or(CustodyError::Store)?;
            Ok(
                if complete && registry.lock().await.contains(manifest.manifest_id()) {
                    CustodyState::Complete
                } else {
                    CustodyState::Missing
                },
            )
        })
    }
}

struct Provider {
    key: Arc<SigningKey>,
    root: PathBuf,
    registry: Arc<Mutex<PublicationRegistry>>,
}

impl Provider {
    async fn open(key: Arc<SigningKey>, root: PathBuf) -> Self {
        let storage = PublicCustodyStore::open(root.clone(), limits()).unwrap();
        let registry = Arc::new(Mutex::new(PublicationRegistry::new()));
        storage
            .register_complete(&mut *registry.lock().await, now())
            .unwrap();
        let backend = DiskBackend {
            storage,
            staging_parent: root.parent().unwrap().to_owned(),
            registry: Arc::downgrade(&registry),
        };
        registry
            .lock()
            .await
            .set_custody(Arc::new(CustodyService::new(
                key.clone(),
                Arc::new(backend),
            )));
        Self {
            key,
            root,
            registry,
        }
    }
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
            .unwrap()
    })
    .await
    .unwrap()
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

#[allow(clippy::too_many_lines)] // Keep one exact Ready/chunks/signed receipt/final transcript together.
async fn phase(
    root: &Path,
    providers: &[Provider],
    signed: &SignedManifest,
    operation: CustodyOperation,
    bad_second_accounting: bool,
) -> (Output, Vec<(CustodyReceipt, TransferProgress)>) {
    let listener = UnixListener::bind(root.join("control.sock")).unwrap();
    let mut args = vec![
        "custody".to_owned(),
        match operation {
            CustodyOperation::Deposit => "deposit",
            CustodyOperation::Inspect => "inspect",
        }
        .to_owned(),
        "--manifest".into(),
        "manifest.pb".into(),
        "--identity".into(),
        "identity.key".into(),
        "--passphrase-file".into(),
        "passphrase".into(),
    ];
    if operation == CustodyOperation::Deposit {
        args.extend(["--cache", "source", "--min-free-bytes", "0"].map(str::to_owned));
    }
    for provider in providers {
        args.extend([
            "--provider-key".into(),
            hex::encode(provider.key.verifying_key().as_bytes()),
        ]);
    }
    let service = async {
        let mut observed = Vec::new();
        for (index, provider) in providers.iter().enumerate() {
            let (mut stream, _) = listener.accept().await.unwrap();
            let request = read_request(&mut stream).await.unwrap();
            let Some(Operation::ContentCustody(parameters)) = request.operation else {
                panic!("typed public custody handoff required")
            };
            let provider_key = provider.key.verifying_key().to_bytes();
            assert_eq!(parameters.provider_key, provider_key);
            assert_eq!(parameters.operation, operation as i32);
            assert_eq!(parameters.manifest, signed.encode());
            let publisher =
                VerifyingKey::from_bytes(&parameters.publisher_key.try_into().unwrap()).unwrap();
            signed.verify(&publisher, now()).unwrap();
            let registry = provider.registry.lock().await.clone();
            let (mut remote, mut server) = tokio::io::duplex(1024);
            let serving = tokio::spawn(async move {
                serve_publication(&mut server, &registry, TransferLimits::default())
                    .await
                    .unwrap()
            });
            let challenge = begin(&mut remote, &provider_key).await.unwrap();
            write_response(
                &mut stream,
                &response(
                    request.request_id.clone(),
                    "CONTENT_CUSTODY_READY",
                    Payload::ContentCustodyReady(ContentCustodyReady {
                        provider_key: provider_key.to_vec(),
                        challenge: challenge.encode(),
                    }),
                ),
            )
            .await
            .unwrap();
            let receipt = bridge(
                &mut stream,
                &mut remote,
                &challenge,
                signed,
                operation,
                TransferLimits::default(),
            )
            .await
            .unwrap();
            let progress = serving.await.unwrap();
            let complete = receipt.state() == CustodyState::Complete;
            let mut encoded_key = vec![8, 1, 18, 32];
            encoded_key.extend_from_slice(&provider_key);
            let peer = PublicKey::try_decode_protobuf(&encoded_key)
                .unwrap()
                .to_peer_id()
                .to_string();
            let mut accounting = ContentReceipt {
                network_publication: complete,
                bytes: if complete { receipt.object_bytes() } else { 0 },
                chunks: if complete { receipt.unique_chunks() } else { 0 },
                providers_used: 1,
                provider_peer_ids: vec![peer],
                ..ContentReceipt::default()
            };
            if bad_second_accounting && index == 1 {
                // The independently signed receipt remains valid; only the final typed
                // local handoff lies about the logical byte count and must not count.
                accounting.bytes += 1;
            }
            write_response(
                &mut stream,
                &response(
                    request.request_id,
                    "CONTENT_OK",
                    Payload::Content(accounting),
                ),
            )
            .await
            .unwrap();
            observed.push((receipt, progress));
        }
        observed
    };
    let (output, observations) = tokio::time::timeout(Duration::from_secs(40), async {
        tokio::join!(invoke(root, args), service)
    })
    .await
    .expect("bounded two-provider custody CLI exchange");
    drop(listener);
    fs::remove_file(root.join("control.sock")).unwrap();
    (output, observations)
}

fn report(output: &Output, success: bool) -> Value {
    assert_eq!(
        output.status.success(),
        success,
        "CLI status: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    serde_json::from_slice(&output.stdout).unwrap()
}

#[allow(clippy::too_many_lines)] // One ordered CLI deposit/retry/source-loss/provider-restart lifecycle.
async fn scenario() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let password = b"temporary explicit custody CLI passphrase";
    fs::write(root.join("passphrase"), password).unwrap();
    fs::set_permissions(root.join("passphrase"), fs::Permissions::from_mode(0o600)).unwrap();
    let identity = IdentityStore::new(root.join("identity.key"))
        .create(&Passphrase::new(password).unwrap())
        .unwrap();
    let publisher =
        VerifyingKey::from_bytes(&identity.ed25519_public_key_bytes().unwrap()).unwrap();
    drop(identity);
    let encrypted_identity = fs::read(root.join("identity.key")).unwrap();
    let bytes: Vec<_> = [7, 13, 7]
        .into_iter()
        .flat_map(|byte| vec![byte; CHUNK_BYTES])
        .chain([9; 123])
        .collect();
    fs::write(root.join("input"), &bytes).unwrap();
    let output = invoke(
        root,
        [
            "publish",
            "--input",
            "input",
            "--cache",
            "source",
            "--manifest",
            "manifest.pb",
            "--name",
            "public-custody-cli",
            "--revision",
            "1",
            "--identity",
            "identity.key",
            "--passphrase-file",
            "passphrase",
            "--min-free-bytes",
            "0",
            "--lifetime-seconds",
            "600",
        ]
        .map(str::to_owned)
        .to_vec(),
    )
    .await;
    assert_eq!(report(&output, true)["network_publication"], false);
    let signed = SignedManifest::decode(&fs::read(root.join("manifest.pb")).unwrap()).unwrap();
    let manifest = signed.verify(&publisher, now()).unwrap();
    let mut providers = Vec::new();
    for index in 0..2 {
        let provider_root = root.join(format!("provider-{index}"));
        drop(ChunkStore::create(&provider_root, limits()).unwrap());
        providers.push(
            Provider::open(
                Arc::new(SigningKey::generate(&mut rand_core::OsRng)),
                provider_root,
            )
            .await,
        );
    }

    let (output, observations) =
        phase(root, &providers, &signed, CustodyOperation::Inspect, false).await;
    let missing = report(&output, false);
    assert_eq!(missing["confirmed_complete_providers"], 0);
    assert_eq!(missing["failed_providers"], 0);
    for (index, (receipt, progress)) in observations.iter().enumerate() {
        assert_eq!(receipt.state(), CustodyState::Missing);
        assert_eq!(*progress, TransferProgress::default());
        assert_eq!(missing["observations"][index]["state"], "missing");
        assert_eq!(
            missing["observations"][index]["agent_handoff_complete"],
            true
        );
    }

    for bad_second in [false, true] {
        let (output, observations) = phase(
            root,
            &providers,
            &signed,
            CustodyOperation::Deposit,
            bad_second,
        )
        .await;
        let deposited = report(&output, !bad_second);
        assert_eq!(deposited["complete"], !bad_second);
        assert_eq!(
            deposited["confirmed_complete_providers"],
            if bad_second { 1 } else { 2 }
        );
        assert_eq!(deposited["failed_providers"], usize::from(bad_second));
        for (index, (receipt, progress)) in observations.iter().enumerate() {
            assert_eq!(receipt.state(), CustodyState::Complete);
            assert_eq!(receipt.object_bytes(), bytes.len() as u64);
            assert_eq!(receipt.unique_chunks(), 3);
            assert_eq!(receipt.original_expiry(), manifest.validity().expires);
            assert_eq!(progress.bytes, (2 * CHUNK_BYTES + 123) as u64);
            assert_eq!(progress.chunks, 3);
            assert_eq!(
                deposited["observations"][index]["signed_receipt_hex"],
                hex::encode(receipt.encode())
            );
            assert_eq!(
                deposited["observations"][index]["agent_handoff_complete"],
                !(bad_second && index == 1)
            );
        }
        if bad_second {
            assert!(
                deposited["observations"][1]["error"]
                    .as_str()
                    .unwrap()
                    .contains("accounting")
            );
        }
    }

    // Discard only this disposable publisher's payload. Inspect has no source cache argument.
    fs::remove_dir_all(root.join("source")).unwrap();
    fs::remove_file(root.join("input")).unwrap();
    let locations: Vec<_> = providers
        .iter()
        .map(|provider| (provider.key.clone(), provider.root.clone()))
        .collect();
    let old_owners: Vec<_> = providers
        .iter()
        .map(|provider| Arc::downgrade(&provider.registry))
        .collect();
    drop(providers);
    assert!(old_owners.iter().all(|owner| owner.upgrade().is_none()));
    let mut reopened = Vec::new();
    for (key, path) in locations {
        reopened.push(Provider::open(key, path).await);
    }
    let (output, observations) =
        phase(root, &reopened, &signed, CustodyOperation::Inspect, false).await;
    let inspected = report(&output, true);
    assert_eq!(inspected["confirmed_complete_providers"], 2);
    assert_eq!(inspected["failed_providers"], 0);
    assert_eq!(inspected["complete"], true);
    assert_eq!(inspected["future_availability_guaranteed"], false);
    for (index, (receipt, progress)) in observations.iter().enumerate() {
        assert_eq!(receipt.state(), CustodyState::Complete);
        assert_eq!(receipt.original_expiry(), manifest.validity().expires);
        assert_eq!(*progress, TransferProgress::default());
        assert_eq!(
            inspected["observations"][index]["signed_receipt_hex"],
            hex::encode(receipt.encode())
        );
    }
    assert!(!root.join("source").exists());
    assert_eq!(
        fs::read(root.join("identity.key")).unwrap(),
        encrypted_identity
    );
}
