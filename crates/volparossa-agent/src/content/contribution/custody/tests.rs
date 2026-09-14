//! Actual contribution startup, provider TLS, custody backend and Stop/restart in an isolated
//! network namespace. Loopback exercises the service, not the normal two-leg overlay route.

use std::{
    fs, net::SocketAddr, os::unix::fs::PermissionsExt as _, path::Path, process::Command,
    time::Duration,
};

use ed25519_dalek::SigningKey;
use tokio::{net::TcpStream, sync::watch, task::JoinHandle, time::timeout};
use volparossa_config::{Config, RolesConfig, RuntimeMode};
use volparossa_content::{
    CHUNK_BYTES,
    provider::{
        custody::{CustodyAuthorization, CustodyOperation, CustodyReceipt, begin, execute},
        pull_publication, serve_publication,
    },
    reassemble,
    transfer::TransferLimits,
};
use volparossa_identity::Identity;
use volparossa_metrics::MetricsRegistry;
use volparossa_peerstore::PeerStore;
use volparossa_policy::{DestinationRule, ProtocolPort, TransportProtocol};
use volparossa_test_support::verified_development_manifest;

use super::*;
use crate::{
    content::tls,
    discovery::{DiscoveryRuntime, DiscoveryRuntimeResources},
    helper::HelperClient,
    roles::RoleStore,
    route_setup::ClientRouteControl,
};

const TEST_NAME: &str = "content::contribution::custody::tests::custody_agent_empty_receiver_serves_and_stop_restart_rejects_stale_owner";
const MARKER: &str = "VOLPAROSSA_HANDOFF_TEST_PARENT_NETNS";

#[test]
fn custody_agent_empty_receiver_serves_and_stop_restart_rejects_stale_owner() {
    if let Some(parent) = std::env::var_os(MARKER) {
        assert_ne!(
            fs::read_link("/proc/self/ns/net").unwrap().as_os_str(),
            parent
        );
        tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap()
            .block_on(async {
                timeout(Duration::from_secs(40), scenario())
                    .await
                    .expect("bounded actual contribution service lifecycle");
            });
        return;
    }
    let output = Command::new(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../../scripts/run-isolated-test.sh"
    ))
    .arg(std::env::current_exe().unwrap())
    .args([TEST_NAME, MARKER, "loopback"])
    .output()
    .unwrap();
    assert!(
        output.status.success(),
        "isolated custody backend failed: {}{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}

fn context(root: &Path) -> (ControlContext, watch::Sender<bool>, JoinHandle<()>) {
    let probe = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let bind = probe.local_addr().unwrap();
    drop(probe);
    let roles = RolesConfig {
        client: false,
        relay: true,
        exit: false,
    };
    let mut config = Config {
        roles,
        runtime_mode: RuntimeMode::Development,
        ..Config::default()
    };
    config.network.operator_id = Some("custody-lifecycle-test".into());
    config.network.advertised_region = "test".into();
    config.network.advertised_country_code = "NL".into();
    config.network.advertised_asn = 64_512;
    config.network.advertised_ipv4_prefix = Some("44.160.1.0/24".into());
    config.network.listen_addresses = vec!["/memory/987645321".into()];
    config.capacity.relay_upload_limit_mbps = 100;
    config.capacity.relay_download_limit_mbps = 100;
    config.capacity.maximum_relay_sessions = 4;
    // Validated configuration only: this service test never starts privileged sharing setup.
    config.sharing.enabled = true;
    config.sharing.interface = "lo".into();
    config.sharing.total_upload_mbps = 100;
    config.sharing.contribution_upload_ceiling_mbps = 50;
    config.download_sharing.enabled = true;
    config.download_sharing.interface = "lo".into();
    config.download_sharing.total_download_mbps = 100;
    config.download_sharing.contribution_download_ceiling_mbps = 50;
    config.content_contribution = ContentContributionConfig {
        enabled: true,
        bind_address: bind.to_string(),
        advertised_hostname: "provider.example".into(),
        cache: root.join("contribution").to_string_lossy().into_owned(),
        quota_bytes: 1024 * 1024,
        max_entries: 8,
        min_free_bytes: 0,
        ..ContentContributionConfig::default()
    };
    config.validate().unwrap();
    let permission = ProtocolPort::new(TransportProtocol::Tcp, bind.port()).unwrap();
    let policy = verified_development_manifest(
        unix_millis(),
        vec![DestinationRule::exact_domain("provider.example", [permission]).unwrap()],
    )
    .unwrap();
    let metrics = MetricsRegistry::new();
    let state = Arc::new(RwLock::new(
        AgentState::new(&config, roles, Some(policy.clone()), metrics.clone()).unwrap(),
    ));
    let helper = HelperClient::new(root.join("absent-helper.sock"), root.join("absent-token"));
    let role_store = RoleStore::new(root.join("roles.json"));
    role_store.load_or_initialize(roles).unwrap();
    let identity = Identity::generate();
    let content = ContentRuntime::new(&identity).unwrap();
    let (runtime, discovery) = DiscoveryRuntime::new(
        identity,
        &config,
        PeerStore::open(root.join("peers.sqlite")).unwrap(),
        root.join("advertisement.sequence"),
        DiscoveryRuntimeResources {
            roles,
            policy: Some(policy),
            role_store,
            metrics,
            helper: helper.clone(),
            mpquic_socket: root.join("absent-mpquic.sock"),
        },
    )
    .unwrap();
    let (stop, receiver) = watch::channel(false);
    let task = tokio::spawn(runtime.run(Arc::clone(&state), receiver));
    (
        ControlContext {
            config: Arc::new(config),
            state,
            helper,
            discovery,
            content,
            routes: ClientRouteControl::new(root.join("absent-mpquic.sock")),
            dns_routes: ClientRouteControl::new(root.join("absent-dns-mpquic.sock")),
        },
        stop,
        task,
    )
}

async fn backend(context: &ControlContext) -> Backend {
    let runtime = context.content.contribution.lock().await.clone().unwrap();
    let current = context.content.service.lock().await;
    let active = current.as_ref().unwrap();
    Backend {
        service: Arc::downgrade(&context.content.service),
        registry: Arc::downgrade(&active.registry),
        state: Arc::clone(&context.state),
        replication: Arc::clone(&runtime.replication),
        foreground: Arc::clone(&context.content.foreground),
        config: runtime.config.clone(),
        endpoint: active.endpoint.clone(),
    }
}

async fn connection(context: &ControlContext) -> tokio_rustls::client::TlsStream<TcpStream> {
    let endpoint = context
        .content
        .service
        .lock()
        .await
        .as_ref()
        .unwrap()
        .endpoint
        .clone();
    let signed = context.content.offer(endpoint).unwrap();
    let offer = signed
        .verify(&context.content.signer.verifying_key(), now())
        .unwrap();
    let stream = TcpStream::connect(&context.config.content_contribution.bind_address)
        .await
        .unwrap();
    tls::connect(
        stream,
        context.content.tls_identity.public().to_peer_id(),
        &offer,
    )
    .await
    .unwrap()
}

async fn exchange(
    context: &ControlContext,
    signed: &SignedManifest,
    publisher: &SigningKey,
    operation: CustodyOperation,
    source: Option<&mut ChunkStore>,
) -> CustodyReceipt {
    let mut stream = connection(context).await;
    let challenge = begin(
        &mut stream,
        context.content.signer.verifying_key().as_bytes(),
    )
    .await
    .unwrap();
    let authorization =
        CustodyAuthorization::sign(&challenge, operation, signed.clone(), publisher, now())
            .unwrap();
    let receipt = execute(
        &mut stream,
        &challenge,
        &authorization,
        source,
        TransferLimits::default(),
    )
    .await
    .unwrap();
    tls::finish(&mut stream).await.unwrap();
    receipt
}

#[allow(clippy::too_many_lines)] // One real startup/admission/cancel/restart/serve lifecycle.
async fn scenario() {
    let directory = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let (context, stop_discovery, discovery_task) = context(directory.path());
    context.content.start_contribution(&context).await.unwrap();
    let status = context.content.status(&context).await.unwrap();
    assert!(status.serving && status.publications == 0);
    let original = backend(&context).await;
    let registry_owner = original.registry.upgrade().unwrap();
    let registry_snapshot = registry_owner.lock().await.clone();
    assert!(registry_snapshot.has_custody());
    assert!(!registry_snapshot.has_live_publications(now()));
    let limits = configured_limits(&context.config.content_contribution);
    let source_root = directory.path().join("publisher");
    let mut source = ChunkStore::create(&source_root, limits).unwrap();
    let publisher = SigningKey::generate(&mut rand_core::OsRng);
    let payload = vec![47; CHUNK_BYTES + 93];
    let signed = super::super::tests::publication(
        &mut source,
        &publisher,
        &payload,
        "application/octet-stream",
    );
    let manifest = signed.verify(&publisher.verifying_key(), now()).unwrap();
    let missing = exchange(
        &context,
        &signed,
        &publisher,
        CustodyOperation::Inspect,
        None,
    )
    .await;
    assert_eq!(missing.state(), CustodyState::Missing);
    let deposited = exchange(
        &context,
        &signed,
        &publisher,
        CustodyOperation::Deposit,
        Some(&mut source),
    )
    .await;
    assert_eq!(deposited.state(), CustodyState::Complete);
    assert_eq!(deposited.original_expiry(), manifest.validity().expires);
    assert!(registry_owner.lock().await.contains_at(
        manifest.manifest_id(),
        &PathBuf::from(&original.config.cache)
    ));
    assert_eq!(
        context.content.status(&context).await.unwrap().publications,
        1
    );
    assert!(!context.content.foreground.active());
    assert!(original.replication.try_background_slot().is_some());

    // Begin using the actual Backend implementation and keep its live transfer owners across
    // the actual ContentRuntime::stop call. This cancelled retry must not resurrect service.
    let mut pending = original
        .begin_deposit(signed.clone(), manifest.clone())
        .await
        .unwrap();
    for chunk in manifest.chunks() {
        pending
            .store()
            .put_verified(*chunk.id(), &source.get(chunk.id()).unwrap().unwrap())
            .unwrap();
    }
    assert!(context.content.foreground.active());
    assert!(original.replication.try_background_slot().is_none());
    context.content.stop(&context.discovery).await.unwrap();
    assert!(pending.commit().await.is_err());
    assert!(!context.content.foreground.active());
    assert!(original.replication.try_background_slot().is_some());
    let bind: SocketAddr = context
        .config
        .content_contribution
        .bind_address
        .parse()
        .unwrap();
    assert!(TcpStream::connect(bind).await.is_err());
    assert!(
        original
            .inspect(signed.clone(), manifest.clone())
            .await
            .is_err()
    );
    assert!(!fs::read_dir(directory.path()).unwrap().any(|entry| {
        entry
            .unwrap()
            .file_name()
            .as_encoded_bytes()
            .starts_with(b".volparossa-publication-")
    }));
    drop(source);
    fs::remove_dir_all(&source_root).unwrap();

    context.content.start_contribution(&context).await.unwrap();
    let restarted = backend(&context).await;
    assert!(!original.registry.ptr_eq(&restarted.registry));
    assert!(!Arc::ptr_eq(&original.replication, &restarted.replication));
    assert!(
        original
            .inspect(signed.clone(), manifest.clone())
            .await
            .is_err()
    );
    let retained = exchange(
        &context,
        &signed,
        &publisher,
        CustodyOperation::Inspect,
        None,
    )
    .await;
    assert_eq!(retained.state(), CustodyState::Complete);
    assert_eq!(retained.original_expiry(), manifest.validity().expires);
    let mut destination = ChunkStore::create(&directory.path().join("consumer"), limits).unwrap();
    let mut stream = connection(&context).await;
    let progress = pull_publication(
        &mut stream,
        &manifest,
        &mut destination,
        TransferLimits::default(),
    )
    .await
    .unwrap();
    assert_eq!(progress.bytes, payload.len() as u64);
    tls::finish(&mut stream).await.unwrap();
    let mut actual = Vec::new();
    reassemble(&manifest, &mut [&mut destination], now(), &mut actual).unwrap();
    assert_eq!(actual, payload);

    // Even a retained protocol-service snapshot cannot operate on a replacement service.
    let (mut client, mut server) = tokio::io::duplex(1024);
    let stale_server = async move {
        serve_publication(&mut server, &registry_snapshot, TransferLimits::default()).await
    };
    let provider_key = context.content.signer.verifying_key().to_bytes();
    let stale_client = async move {
        let challenge = begin(&mut client, &provider_key).await.unwrap();
        let authorization = CustodyAuthorization::sign(
            &challenge,
            CustodyOperation::Inspect,
            signed,
            &publisher,
            now(),
        )
        .unwrap();
        execute(
            &mut client,
            &challenge,
            &authorization,
            None,
            TransferLimits::default(),
        )
        .await
    };
    let (observed, rejected_snapshot) = tokio::join!(stale_client, stale_server);
    assert!(observed.is_err() && rejected_snapshot.is_err());
    context.content.stop(&context.discovery).await.unwrap();
    drop(registry_owner);
    assert!(original.registry.upgrade().is_none());
    assert!(restarted.registry.upgrade().is_none());
    stop_discovery.send(true).unwrap();
    discovery_task.await.unwrap();
    assert!(!directory.path().join("absent-helper.sock").exists());
}
