//! Private temporary sockets and synthetic signed data only; no overlay or browser run.

use std::{os::unix::fs::symlink, time::Duration};

use clap::{CommandFactory as _, Parser as _};
use ed25519_dalek::SigningKey;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity};

use super::*;

const FILTERS: &str = "[Adblock Plus 2.0]\r\n||ads.fixture.test^\r\n||metrics.fixture.test^\n";

struct Fixture {
    root: tempfile::TempDir,
    service: Arc<Service>,
    grant: Value,
    signed: Vec<u8>,
}

fn fixture(cached: bool) -> Fixture {
    let root = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let key = SigningKey::from_bytes(&[91; 32]);
    let now = Sample::now().unwrap();
    let seconds = now.wall_ns / NS;
    let cache = root.path().join("cache");
    let limits = Limits {
        quota_bytes: 2 * filter_snapshot::MAX_BYTES as u64,
        max_entries: 16,
        min_free_bytes: 0,
    };
    let mut store = ChunkStore::create(
        &cache,
        CacheLimits {
            max_bytes: limits.quota_bytes,
            max_entries: 16,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let signed = volparossa_content::publish(
        &mut FILTERS.as_bytes(),
        Publication {
            metadata: Metadata {
                name: "filters.synthetic.1".into(),
                revision: 1,
                content_type: "text/plain".into(),
            },
            length: FILTERS.len() as u64,
            validity: Validity {
                created: seconds,
                expires: seconds + 600,
            },
        },
        &key,
        &mut store,
    )
    .unwrap();
    let manifest = signed.verify(&key.verifying_key(), seconds).unwrap();
    let grant = json!({"version":1,"enabled":true,"public_content":true,"authorize_filter_publisher":true,
        "publisher_key":hex::encode(key.verifying_key().as_bytes()),"name":"filters.synthetic.1",
        "manifest_id":hex::encode(manifest.manifest_id()),"not_after_unix_seconds":seconds+500});
    let path = root.path().join("authority.json");
    fs::write(&path, serde_json::to_vec(&grant).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let authority = Authority::load(&path).unwrap();
    let source = public_text::TextSource {
        publisher_key: authority.publisher,
        name: authority.name.clone(),
        manifest_id: authority.manifest_id,
        cache,
        reuse_cache: true,
        limits,
    };
    let mut broker = Broker::new(authority, now).unwrap();
    if cached {
        broker
            .install(
                public_text::TextDownload {
                    signed_manifest: signed.encode(),
                    text: FILTERS.into(),
                    receipt: json!({"inert_test_only":true}),
                    expires: seconds + 600,
                    verified_at: seconds,
                },
                now,
            )
            .unwrap();
    }
    let service = Arc::new(Service {
        broker: Mutex::new(broker),
        fetch_slot: tokio::sync::Mutex::new(()),
        source,
        control: root.path().join("agent.sock"),
        work_parent: root.path().to_owned(),
    });
    Fixture {
        root,
        service,
        grant,
        signed: signed.encode(),
    }
}

fn request(id: u8, operation: &str) -> wire::Request {
    wire::parse(
        &serde_json::to_vec(&json!({"version":1,"id":format!("{id:032x}"),
        "operation":{"type":operation}}))
        .unwrap(),
    )
    .unwrap()
}

async fn send(stream: &mut UnixStream, id: u8, operation: &str) -> Value {
    let payload = serde_json::to_vec(&json!({"version":1,"id":format!("{id:032x}"),
        "operation":{"type":operation}}))
    .unwrap();
    stream
        .write_all(&u32::try_from(payload.len()).unwrap().to_be_bytes())
        .await
        .unwrap();
    stream.write_all(&payload).await.unwrap();
    receive(stream).await
}

async fn receive(stream: &mut UnixStream) -> Value {
    let length = stream.read_u32().await.unwrap() as usize;
    assert!(length <= wire::MAX_RESPONSE);
    let mut body = vec![0; length];
    stream.read_exact(&mut body).await.unwrap();
    serde_json::from_slice(&body).unwrap()
}

#[test]
fn request_contract_rejects_authority_paths_private_data_unknowns_and_duplicates() {
    for operation in ["capabilities", "status", "fetch"] {
        request(1, operation);
    }
    let baseline = json!({"version":1,"id":"0".repeat(32),"operation":{"type":"fetch"}});
    for key in [
        "publisher_key",
        "name",
        "manifest_id",
        "url",
        "path",
        "context",
        "history",
    ] {
        for nested in [false, true] {
            let mut value = baseline.clone();
            if nested {
                value["operation"][key] = "PRIVATE_CANARY".into();
            } else {
                value[key] = "PRIVATE_CANARY".into();
            }
            let error = wire::parse(&serde_json::to_vec(&value).unwrap()).unwrap_err();
            assert_eq!(error.to_string(), "invalid_request");
        }
    }
    for (key, bad) in [
        ("version", json!(2)),
        ("version", json!(true)),
        ("id", json!("A".repeat(32))),
        ("id", json!("a".repeat(33))),
        ("operation", json!({"type":"connect"})),
    ] {
        let mut value = baseline.clone();
        value[key] = bad;
        assert!(wire::parse(&serde_json::to_vec(&value).unwrap()).is_err());
    }
    assert!(wire::parse(b"{\"version\":1,\"version\":1}").is_err());
    assert!(wire::parse(&vec![b' '; wire::MAX_REQUEST + 1]).is_err());
}

#[test]
fn authority_requires_explicit_owned_bounded_private_file() {
    let fixture = fixture(false);
    let path = fixture.root.path().join("authority.json");
    for key in ["enabled", "public_content", "authorize_filter_publisher"] {
        let mut grant = fixture.grant.clone();
        grant[key] = false.into();
        fs::write(&path, serde_json::to_vec(&grant).unwrap()).unwrap();
        assert!(Authority::load(&path).is_err());
    }
    let mut grant = fixture.grant.clone();
    grant["url"] = "https://not-authority.test".into();
    fs::write(&path, serde_json::to_vec(&grant).unwrap()).unwrap();
    assert!(Authority::load(&path).is_err());
    fs::write(&path, serde_json::to_vec(&fixture.grant).unwrap()).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
    assert!(Authority::load(&path).is_err());
    fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
    let link = fixture.root.path().join("link");
    symlink(&path, &link).unwrap();
    assert!(Authority::load(&link).is_err());
    fs::hard_link(&path, fixture.root.path().join("hardlink")).unwrap();
    assert!(Authority::load(&path).is_err());
}

#[test]
fn owner_revocation_is_terminal_even_if_the_original_file_returns() {
    let fixture = fixture(true);
    let mut broker = fixture.service.broker.lock().unwrap();
    let original = broker.authority.original.clone();
    fs::write(&broker.authority.path, b"{}").unwrap();
    assert_eq!(broker.check().unwrap_err(), "revoked");
    fs::write(&broker.authority.path, original).unwrap();
    assert_eq!(broker.check().unwrap_err(), "revoked");
}

#[test]
fn deletion_expiry_suspend_and_clock_rollback_refuse_authority() {
    for mode in [
        "deleted",
        "wall_expiry",
        "suspend",
        "wall_rollback",
        "boot_rollback",
    ] {
        let fixture = fixture(true);
        let mut broker = fixture.service.broker.lock().unwrap();
        let mut now = broker.previous;
        match mode {
            "deleted" => fs::remove_file(&broker.authority.path).unwrap(),
            "wall_expiry" => now.wall_ns = broker.authority.expires * NS,
            "suspend" => now.boot_ns = broker.boot_deadline,
            "wall_rollback" => now.wall_ns -= 1,
            _ => now.boot_ns -= 1,
        }
        let expected = if mode == "deleted" {
            "revoked"
        } else if mode.ends_with("rollback") {
            "clock_error"
        } else {
            "expired"
        };
        assert_eq!(broker.check_at(now).unwrap_err(), expected);
    }
}

#[test]
fn newly_received_manifest_cannot_restart_time_spent_suspended_in_retrieval() {
    let fixture = fixture(true);
    let mut broker = fixture.service.broker.lock().unwrap();
    let download = broker.cached.take().unwrap().download;
    // A still-live longer local grant does not extend the shorter signed object.
    broker.authority.expires += 1000;
    broker.boot_deadline += 1000 * NS;
    let mut after_suspend = broker.previous;
    after_suspend.boot_ns += 700 * NS;
    assert_eq!(
        broker.install(download, after_suspend).unwrap_err(),
        "expired"
    );
    assert!(broker.cached.is_none());
    assert_eq!(broker.terminal, Some("expired"));
}

#[tokio::test]
async fn complete_original_named_download_is_served_by_the_broker_without_rewriting() {
    use volparossa_content::{
        SignedManifest,
        transfer::{TransferLimits, serve_peer},
    };
    use volparossa_local_control::{
        CONTROL_PROTOCOL_VERSION, ContentReceipt, ControlResponse, ControlResult,
        NamedContentTransferReady, control_response::Payload, read_request, write_response,
    };

    let fixture = fixture(false);
    let (listener, _guard) = bind(&fixture.service.control).unwrap();
    let signed = fixture.signed.clone();
    let expected = signed.clone();
    let cache = fixture.service.source.cache.clone();
    let publisher = fixture.service.source.publisher_key;
    let limits = fixture.service.source.limits.cache_limits().unwrap();
    // An inert local agent-shaped stream, explicitly not a protected-peer proof.
    let agent = tokio::spawn(async move {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        let manifest = SignedManifest::decode(&signed)
            .unwrap()
            .verify(&publisher, super::super::now_seconds().unwrap())
            .unwrap();
        let mut response = ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: request.request_id,
            result: ControlResult::Ok as i32,
            diagnostic_code: "NAMED_CONTENT_TRANSFER_READY".into(),
            payload: Some(Payload::NamedContentTransferReady(
                NamedContentTransferReady {
                    manifest: signed,
                    cache_only: false,
                },
            )),
        };
        write_response(&mut stream, &response).await.unwrap();
        let mut store = ChunkStore::open(&cache, limits).unwrap();
        let progress = serve_peer(
            &mut stream,
            &manifest,
            &mut store,
            TransferLimits::default(),
        )
        .await
        .unwrap();
        response.diagnostic_code = "CONTENT_OK".into();
        response.payload = Some(Payload::Content(ContentReceipt {
            bytes: progress.bytes,
            chunks: u32::try_from(progress.chunks).unwrap(),
            ..ContentReceipt::default()
        }));
        write_response(&mut stream, &response).await.unwrap();
    });
    let (mut client, server) = UnixStream::pair().unwrap();
    let connection = tokio::spawn(connection(server, fixture.service.clone()));
    assert_eq!(
        send(&mut client, 1, "capabilities").await["event"],
        "capabilities"
    );
    let delivered = send(&mut client, 2, "fetch").await;
    agent.await.unwrap();
    assert_eq!(delivered["event"], "snapshot");
    assert_eq!(delivered["filters"], FILTERS);
    assert_eq!(delivered["manifest_hex"], hex::encode(expected));
    assert_eq!(
        delivered["snapshot"]["generation"],
        fixture.grant["manifest_id"]
    );
    assert_eq!(
        send(&mut client, 3, "fetch").await["snapshot"],
        delivered["snapshot"]
    );
    drop(client);
    connection.await.unwrap().unwrap();
}

#[tokio::test]
async fn revocation_after_serialization_prevents_any_authorized_frame() {
    let fixture = fixture(true);
    let response = fixture.service.response(&request(1, "fetch")).await;
    let bytes = wire::encode(&response).unwrap();
    fs::remove_file(fixture.root.path().join("authority.json")).unwrap();
    let mut output = Vec::new();
    assert!(
        wire::write(&mut output, &bytes, || fixture.service.live_response())
            .await
            .is_err()
    );
    assert!(output.is_empty());
}

#[test]
fn shared_signature_grammar_and_original_expiry_remain_binding() {
    for mutation in [
        "content",
        "signature",
        "publisher",
        "manifest",
        "name",
        "expiry",
        "verified_at",
    ] {
        let fixture = fixture(true);
        let mut broker = fixture.service.broker.lock().unwrap();
        match mutation {
            "content" => broker.cached.as_mut().unwrap().download.text.push('\n'),
            "signature" => broker.cached.as_mut().unwrap().download.signed_manifest[0] ^= 1,
            "publisher" => {
                broker.authority.publisher = SigningKey::from_bytes(&[92; 32]).verifying_key();
            }
            "manifest" => broker.authority.manifest_id[0] ^= 1,
            "name" => broker.authority.name.push('x'),
            "expiry" => broker.cached.as_mut().unwrap().download.expires += 1,
            _ => broker.cached.as_mut().unwrap().download.verified_at += 1000,
        }
        assert_eq!(
            broker.validate_cached(broker.previous).unwrap_err(),
            "invalid_snapshot"
        );
    }
}

#[tokio::test]
async fn actual_private_socket_handshake_fetch_reuse_and_closed_metadata() {
    let fixture = fixture(true);
    let socket = fixture.root.path().join("filter.sock");
    let (listener, guard) = bind(&socket).unwrap();
    assert_eq!(fs::metadata(&socket).unwrap().mode() & 0o777, 0o600);
    let service = fixture.service.clone();
    let task =
        tokio::spawn(async move { connection(listener.accept().await.unwrap().0, service).await });
    let mut client = UnixStream::connect(&socket).await.unwrap();
    assert_eq!(
        send(&mut client, 1, "fetch").await["code"],
        "handshake_required"
    );
    let capabilities = send(&mut client, 2, "capabilities").await;
    assert_eq!(capabilities["browser_activation"], false);
    assert_eq!(capabilities["manifest_id"], fixture.grant["manifest_id"]);
    let first = send(&mut client, 3, "fetch").await;
    let second = send(&mut client, 4, "fetch").await;
    assert_eq!(first["snapshot"], second["snapshot"]);
    assert_eq!(first["filters"], FILTERS);
    assert_eq!(first["manifest_hex"], second["manifest_hex"]);
    assert_eq!(
        first["snapshot"]["generation"],
        fixture.grant["manifest_id"]
    );
    assert_eq!(
        first["snapshot"]["authorization_expires_unix_seconds"],
        fixture.grant["not_after_unix_seconds"]
    );
    assert!(first.get("receipt").is_none());
    assert!(
        !serde_json::to_string(&first)
            .unwrap()
            .contains(fixture.root.path().to_str().unwrap())
    );
    assert_eq!(
        send(&mut client, 4, "fetch").await["code"],
        "duplicate_request"
    );
    fs::remove_file(fixture.root.path().join("authority.json")).unwrap();
    assert_eq!(send(&mut client, 5, "fetch").await["code"], "revoked");
    drop(client);
    task.await.unwrap().unwrap();
    drop(guard);
    assert!(!socket.exists());
    assert!(!fixture.service.control.exists()); // Verified reuse did not open any agent socket.
}

#[tokio::test]
async fn only_fetch_contacts_exact_existing_content_api_and_mid_fetch_revoke_wins() {
    let fixture = fixture(false);
    let (listener, _guard) = bind(&fixture.service.control).unwrap();
    assert_eq!(
        fixture.service.response(&request(1, "status")).await["state"],
        "unavailable"
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(20), listener.accept())
            .await
            .is_err()
    );
    let service = fixture.service.clone();
    let task = tokio::spawn(async move { service.response(&request(2, "fetch")).await });
    let (mut stream, _) = listener.accept().await.unwrap();
    let query = volparossa_local_control::read_request(&mut stream)
        .await
        .unwrap();
    let Some(volparossa_local_control::control_request::Operation::ContentFetchName(value)) =
        query.operation
    else {
        panic!("only named protected content is permitted");
    };
    assert_eq!(
        value.publisher_key,
        fixture.service.source.publisher_key.as_bytes()
    );
    assert_eq!(
        value.expected_manifest_id,
        Some(fixture.service.source.manifest_id.to_vec())
    );
    assert_eq!(value.name, fixture.service.source.name);
    assert!(value.reuse_cache && value.prefer_cached && !value.cache_only);
    assert_eq!(value.expected_content_type.as_deref(), Some("text/plain"));
    assert_eq!(
        value.max_object_bytes,
        Some(filter_snapshot::MAX_BYTES as u64)
    );
    fs::remove_file(fixture.root.path().join("authority.json")).unwrap();
    drop(stream);
    assert_eq!(task.await.unwrap()["code"], "revoked");
    assert!(fs::read_dir(fixture.root.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".filter-broker-")
    }));
}

#[tokio::test]
async fn stalled_agent_is_bounded_to_55_seconds_and_cleans_the_pending_download() {
    let fixture = fixture(false);
    let (listener, _guard) = bind(&fixture.service.control).unwrap();
    let service = fixture.service.clone();
    let task = tokio::spawn(async move { service.response(&request(1, "fetch")).await });
    let (mut stream, _) = listener.accept().await.unwrap();
    volparossa_local_control::read_request(&mut stream)
        .await
        .unwrap();
    // Pause after real local socket establishment; the agent sends no response.
    tokio::time::pause();
    tokio::time::advance(Duration::from_secs(54)).await;
    assert!(!task.is_finished());
    tokio::time::advance(Duration::from_secs(1)).await;
    assert_eq!(task.await.unwrap()["code"], "unavailable");
    assert_eq!(stream.read(&mut [0]).await.unwrap(), 0);
    assert!(fs::read_dir(fixture.root.path()).unwrap().all(|entry| {
        !entry
            .unwrap()
            .file_name()
            .to_string_lossy()
            .starts_with(".filter-broker-")
    }));
}

#[tokio::test]
async fn revoked_authority_and_busy_fetch_do_not_start_another_transfer() {
    let fixture = fixture(false);
    let slot = fixture.service.fetch_slot.lock().await;
    assert_eq!(
        fixture.service.response(&request(1, "fetch")).await["code"],
        "busy"
    );
    drop(slot);
    fs::remove_file(fixture.root.path().join("authority.json")).unwrap();
    assert_eq!(
        fixture.service.response(&request(2, "fetch")).await["code"],
        "revoked"
    );
    assert!(!fixture.service.control.exists());
}

#[tokio::test]
async fn oversized_frame_is_closed_without_echo_or_allocation() {
    let fixture = fixture(false);
    let (mut client, server) = UnixStream::pair().unwrap();
    let task = tokio::spawn(connection(server, fixture.service));
    client.write_all(&u32::MAX.to_be_bytes()).await.unwrap();
    let error = receive(&mut client).await;
    assert_eq!(error, wire::error(None, "invalid_request"));
    assert_eq!(client.read(&mut [0]).await.unwrap(), 0);
    task.await.unwrap().unwrap();
}

#[test]
fn socket_creation_never_clobbers_and_cleanup_only_removes_owned_inode() {
    let fixture = fixture(false);
    let path = fixture.root.path().join("filter.sock");
    fs::write(&path, "existing").unwrap();
    assert!(bind(&path).is_err());
    assert_eq!(fs::read_to_string(&path).unwrap(), "existing");
    fs::remove_file(&path).unwrap();
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let _entered = runtime.enter();
    let (listener, guard) = bind(&path).unwrap();
    fs::remove_file(&path).unwrap();
    fs::write(&path, "replacement").unwrap();
    drop(listener);
    drop(guard);
    assert_eq!(fs::read_to_string(path).unwrap(), "replacement");
}

#[test]
fn complete_cli_help_and_filter_subcommand_are_unambiguous() {
    crate::Cli::command().debug_assert();
    let cli = crate::Cli::try_parse_from([
        "volparossa",
        "content",
        "filter-serve",
        "--authority",
        "/private/grant",
        "--cache",
        "/private/cache",
        "--work-parent",
        "/private/work",
        "--socket",
        "/private/filter.sock",
    ])
    .unwrap();
    let crate::CliCommand::Content { command } = cli.command else {
        panic!("content command");
    };
    let super::super::Command::FilterServe(options) = *command else {
        panic!("filter broker command");
    };
    assert!(!options.execute);
    assert!(
        crate::Cli::try_parse_from(["volparossa", "content", "filter-serve", "--help"])
            .unwrap_err()
            .to_string()
            .contains("filter-serve")
    );
}

#[tokio::test]
async fn cache_paths_are_fixed_normalized_and_delegated_without_local_access() {
    let fixture = fixture(false);
    let absent_parent = fixture.root.path().join("agent-private-not-created");
    let mut options = Options {
        authority: fixture.root.path().join("authority.json"),
        cache: absent_parent.join("cache"),
        work_parent: fixture.root.path().to_owned(),
        socket: fixture.root.path().join("filter.sock"),
        execute: false,
        limits: fixture.service.source.limits.clone(),
    };
    // Preview must not require access to the other account's cache or create it.
    run(&options, &fixture.service.control).await.unwrap();
    assert!(!absent_parent.exists());
    assert!(!options.socket.exists());
    assert!(!fixture.service.control.exists());
    let sentinel = fixture.root.path().join("agent-owned-sentinel");
    fs::write(&sentinel, b"untouched-cache-account-boundary").unwrap();
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o000)).unwrap();
    options.cache = sentinel.clone();
    // Cache type/ownership checks belong to the agent, not the preview.
    run(&options, &fixture.service.control).await.unwrap();
    assert_eq!(fs::metadata(&sentinel).unwrap().mode() & 0o777, 0);
    fs::set_permissions(&sentinel, fs::Permissions::from_mode(0o600)).unwrap();
    assert_eq!(
        fs::read(&sentinel).unwrap(),
        b"untouched-cache-account-boundary"
    );
    for invalid in [
        "cache",
        "/a/../cache",
        "/a/./cache",
        "/a//cache",
        "/a/cache/",
        "/",
    ] {
        options.cache = PathBuf::from(invalid);
        assert!(run(&options, &fixture.service.control).await.is_err());
    }
    assert!(!options.socket.exists());
}
