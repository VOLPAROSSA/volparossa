//! Local CLI/journal/framed-IPC tests, not a normal overlay route acceptance claim.

use std::{
    fs,
    os::unix::fs::{MetadataExt as _, PermissionsExt as _},
    sync::Arc,
};

use clap::Parser as _;
use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use volparossa_content::{
    CHUNK_BYTES, Validity,
    private_storage::{
        PrivateStorageStore, StorageLimits,
        protocol::{
            GrantLimits, ReceiptState, SignedStorageGrant, StorageOperation, StorageRights,
            StorageTarget, VerifiedStorageGrant,
        },
        provider::PrivateStorageProvider,
        wire::{self, StorageService},
    },
};

use super::{
    state::{Journal, LockedJournal},
    transfer,
};

fn fixture_grant() -> (SigningKey, SigningKey, VerifiedStorageGrant) {
    let provider = SigningKey::from_bytes(&[11; 32]);
    let owner = SigningKey::from_bytes(&[22; 32]);
    let now = super::super::now().unwrap();
    let grant = SignedStorageGrant::issue(
        &provider,
        &owner.verifying_key(),
        GrantLimits {
            max_payload_bytes: 4 * CHUNK_BYTES as u64,
            max_leases: 2,
            rights: StorageRights::ALL,
            max_retention_seconds: 1800,
        },
        Validity {
            created: now,
            expires: now + 3600,
        },
    )
    .unwrap()
    .verify(&provider.verifying_key(), now)
    .unwrap();
    (provider, owner, grant)
}

#[test]
fn peer_storage_commands_accept_explicit_scoped_operations() {
    let key = hex::encode(SigningKey::from_bytes(&[11; 32]).verifying_key().as_bytes());
    let common = ["volparossa", "storage", "peer"];
    for command in [
        vec!["admission", "--provider-key", &key],
        vec!["admission", "--provider-key", &key, "--target-bytes", "0"],
        vec![
            "serve",
            "--bind",
            "127.0.0.1:8443",
            "--advertised-hostname",
            "store.example",
            "--store",
            "/store",
            "--capacity-bytes",
            "1073741824",
        ],
        vec![
            "serve",
            "--bind",
            "127.0.0.1:8443",
            "--advertised-hostname",
            "store.example",
            "--store",
            "/store",
            "--reuse-store",
        ],
        vec![
            "grant",
            "--provider-key",
            &key,
            "--owner-key",
            &key,
            "--max-payload-bytes",
            "1073741824",
            "--output",
            "/grant",
        ],
        vec![
            "deposit",
            "--provider-key",
            &key,
            "--grant",
            "/grant",
            "--input",
            "/encrypted",
            "--sha256",
            &key,
            "--state",
            "/state",
            "--already-encrypted",
            "--resume",
        ],
        vec!["progress", "--provider-key", &key, "--state", "/state"],
        vec![
            "restore",
            "--provider-key",
            &key,
            "--state",
            "/state",
            "--output",
            "/new-restore",
        ],
        vec![
            "renew",
            "--provider-key",
            &key,
            "--state",
            "/state",
            "--lifetime-seconds",
            "600",
        ],
        vec!["delete", "--provider-key", &key, "--state", "/state"],
    ] {
        assert!(crate::Cli::try_parse_from(common.into_iter().chain(command)).is_ok());
    }
}

#[test]
fn peer_storage_commands_require_explicit_trust_encryption_and_no_reuse_override() {
    let key = hex::encode(SigningKey::from_bytes(&[11; 32]).verifying_key().as_bytes());
    let common = ["volparossa", "storage", "peer"];
    for command in [
        vec!["admission", "--target-bytes", "1"],
        vec![
            "admission",
            "--provider-key",
            &key,
            "--target-bytes",
            "1099511627777",
        ],
        vec![
            "serve",
            "--bind",
            "127.0.0.1:8443",
            "--advertised-hostname",
            "store.example",
            "--store",
            "/store",
            "--reuse-store",
            "--capacity-bytes",
            "1",
        ],
        vec![
            "serve",
            "--bind",
            "127.0.0.1:8443",
            "--advertised-hostname",
            "store.example",
            "--store",
            "/store",
            "--reuse-store",
            "--min-free-bytes",
            "0",
        ],
        vec![
            "deposit",
            "--provider-key",
            &key,
            "--grant",
            "/grant",
            "--input",
            "/encrypted",
            "--sha256",
            &key,
            "--state",
            "/state",
        ],
        vec!["progress", "--state", "/state"],
    ] {
        assert!(crate::Cli::try_parse_from(common.into_iter().chain(command)).is_err());
    }
}

#[test]
fn private_archive_journal_is_durable_locked_private_and_bound_before_reservation() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("archive-state");
    let (provider, owner, grant) = fixture_grant();
    let journal = Journal::new(&grant, 1024, [7; 32], super::super::now().unwrap() + 600).unwrap();
    let saved = LockedJournal::create(&path, journal).unwrap();
    let original = saved.journal.target().unwrap();
    assert!(original.lease_id.is_none());
    assert!(LockedJournal::open(&path).is_err());
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(path.join("archive.json")).unwrap().mode() & 0o777,
        0o600
    );
    drop(saved);
    let reopened = LockedJournal::open(&path).unwrap();
    assert_eq!(reopened.journal.target().unwrap(), original);
    assert_eq!(
        reopened
            .journal
            .grant(&provider.verifying_key(), &owner.verifying_key())
            .unwrap()
            .signed()
            .encode(),
        grant.signed().encode()
    );
    assert!(
        reopened
            .journal
            .grant(&owner.verifying_key(), &owner.verifying_key())
            .is_err()
    );
    assert!(
        reopened
            .journal
            .grant(&provider.verifying_key(), &provider.verifying_key())
            .is_err()
    );
    drop(reopened);
    fs::set_permissions(&path, fs::Permissions::from_mode(0o755)).unwrap();
    assert!(LockedJournal::open(&path).is_err());
}

#[tokio::test]
async fn local_provider_admission_cli_uses_real_framed_status_and_preserves_custody() {
    use volparossa_local_control::{
        CONTROL_PROTOCOL_VERSION, ControlResponse, ControlResult, PrivateStorageAdmission,
        control_request::Operation, control_response::Payload, read_request, write_response,
    };
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path().join("store");
    let socket = directory.path().join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let mut secret = [0; 32];
    rand_core::RngCore::fill_bytes(&mut rand_core::OsRng, &mut secret);
    let signer = SigningKey::from_bytes(&secret);
    let provider_key = signer.verifying_key();
    let now = super::super::now().unwrap();
    let bytes = vec![0x43; 2048];
    let mut store = PrivateStorageStore::create(
        &root,
        StorageLimits {
            capacity_bytes: 4096,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let lease = store
        .reserve(2048, Sha256::digest(&bytes).into(), now + 300, now)
        .unwrap();
    store
        .write_reserved(lease, &mut std::io::Cursor::new(&bytes), now)
        .unwrap();
    let backend = PrivateStorageProvider::new(store, provider_key).unwrap();
    let service = Arc::new(StorageService::new(Arc::new(signer), backend));
    let serving = Arc::clone(&service);
    // This is a local agent framing fixture around the actual disk-slot/backend, not an
    // overlay or remote storage proof. Both operations use the production CLI client.
    let server = tokio::spawn(async move {
        for expected_target in [Some(1024), None] {
            let (mut stream, _) = listener.accept().await.unwrap();
            let incoming = read_request(&mut stream).await.unwrap();
            let Some(Operation::PrivateStorageAdmission(change)) = incoming.operation else {
                panic!("scoped local provider admission operation");
            };
            assert_eq!(change.provider_key, provider_key.as_bytes());
            assert_eq!(change.target_bytes, expected_target);
            let status = serving.admission(change.target_bytes).await.unwrap();
            let reply = ControlResponse {
                protocol_version: CONTROL_PROTOCOL_VERSION,
                request_id: incoming.request_id,
                result: ControlResult::Ok as i32,
                diagnostic_code: "PRIVATE_STORAGE_ADMISSION".into(),
                payload: Some(Payload::PrivateStorageAdmission(PrivateStorageAdmission {
                    provider_key: provider_key.to_bytes().to_vec(),
                    capacity_bytes: status.capacity_bytes,
                    target_bytes: status.target_bytes,
                    reserved_bytes: status.reserved_bytes,
                    committed_bytes: status.committed_bytes,
                    leases: status.leases,
                    retained_payload_bytes: status.retained_payload_bytes,
                    pending_drain_bytes: status.pending_drain_bytes,
                    available_for_new_reservations_bytes: status
                        .available_for_new_reservations_bytes,
                })),
            };
            write_response(&mut stream, &reply).await.unwrap();
        }
    });
    for target_bytes in [Some(1024), None] {
        let report = super::admission(
            &super::Admission {
                provider_key,
                target_bytes,
            },
            &socket,
        )
        .await
        .unwrap();
        assert_eq!(report["target_bytes"], 1024);
        assert_eq!(report["retained_payload_bytes"], 2048);
        assert_eq!(report["pending_drain_bytes"], 1024);
        assert_eq!(report["automatic_migration"], false);
        assert_eq!(report["network_contribution_verified"], false);
    }
    server.await.unwrap();
    drop(service);
    let mut reopened = PrivateStorageStore::open_existing(&root).unwrap();
    assert_eq!(reopened.admission_status().unwrap().target_bytes, 1024);
    assert!(reopened.reserve(1, [1; 32], now + 300, now).is_err());
    let mut restored = Vec::new();
    reopened.restore(lease, &mut restored, now).unwrap();
    assert_eq!(restored, bytes);
    assert_eq!(reopened.usage().unwrap().committed_bytes, 2048);
}

#[test]
fn private_metadata_refuses_symlinks_and_output_overwrite() {
    let directory = tempfile::tempdir().unwrap();
    let output = directory.path().join("grant");
    super::state::private_output(&output, b"original private grant").unwrap();
    assert!(super::state::private_output(&output, b"replacement").is_err());
    assert_eq!(
        super::state::read_private(&output, 100).unwrap(),
        b"original private grant"
    );
    let symlink = directory.path().join("alias");
    std::os::unix::fs::symlink(&output, &symlink).unwrap();
    assert!(super::state::read_private(&symlink, 100).is_err());
    assert!(super::state::read_private(&output, 2).is_err());
}

#[test]
fn progress_renew_and_delete_cannot_allocate_an_unknown_reservation() {
    let (_, _, grant) = fixture_grant();
    let mut journal =
        Journal::new(&grant, 1024, [7; 32], super::super::now().unwrap() + 600).unwrap();
    let original = journal.target().unwrap();
    let error = transfer::known_target(&journal).unwrap_err();
    assert!(error.to_string().contains("deposit --resume"));
    assert_eq!(journal.target().unwrap(), original);
    journal.lease = Some("11".repeat(16));
    let known = transfer::known_target(&journal).unwrap();
    assert!(known.lease_id.is_some());
    assert_eq!(known.archive_id, original.archive_id);
}

fn peer_id(key: &ed25519_dalek::VerifyingKey) -> String {
    let mut encoded = vec![8, 1, 18, 32];
    encoded.extend_from_slice(key.as_bytes());
    volparossa_identity::PublicKey::try_decode_protobuf(&encoded)
        .unwrap()
        .to_peer_id()
        .to_string()
}

async fn fake_agent(
    listener: tokio::net::UnixListener,
    service: Arc<StorageService>,
    grant: VerifiedStorageGrant,
) {
    use volparossa_content::{
        provider::{PublicationRegistry, serve_publication},
        transfer::TransferLimits,
    };
    use volparossa_local_control::{
        CONTROL_PROTOCOL_VERSION, ContentReceipt, ControlResponse, PrivateStorageReady,
        control_request::Operation, control_response::Payload, read_request, write_response,
    };
    for index in 0..11 {
        let (mut local, _) = listener.accept().await.unwrap();
        let request = read_request(&mut local).await.unwrap();
        let Some(Operation::PrivateStorageRemote(requested)) = request.operation else {
            panic!("wrong IPC operation")
        };
        assert_eq!(requested.provider_key, grant.provider_key().as_bytes());
        assert_eq!(requested.grant, grant.signed().encode());
        let (mut remote, mut provider) = tokio::io::duplex(4096);
        let mut registry = PublicationRegistry::new();
        registry.set_private_storage(Arc::clone(&service));
        let provider_task = tokio::spawn(async move {
            serve_publication(&mut provider, &registry, TransferLimits::default())
                .await
                .unwrap()
        });
        let challenge = wire::begin(&mut remote, &grant).await.unwrap();
        let mut response = ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: request.request_id,
            result: 0,
            diagnostic_code: "PRIVATE_STORAGE_READY".into(),
            payload: Some(Payload::PrivateStorageReady(PrivateStorageReady {
                provider_key: grant.provider_key().to_bytes().to_vec(),
                challenge: challenge.encode(),
            })),
        };
        write_response(&mut local, &response).await.unwrap();
        let receipt = wire::bridge(&mut local, &mut remote, &grant, &challenge)
            .await
            .unwrap();
        provider_task.await.unwrap();
        // First Reserve reached disk, but local terminal success was lost. A verified signed
        // receipt alone must not turn a failed agent handoff into a successful CLI operation.
        if index == 0 {
            continue;
        }
        response.diagnostic_code = "CONTENT_OK".into();
        response.payload = Some(Payload::Content(ContentReceipt {
            bytes: receipt.ciphertext_bytes,
            peer_bytes: receipt.ciphertext_bytes,
            providers_used: 1,
            provider_peer_ids: vec![peer_id(grant.provider_key())],
            control_relay_peer_id: peer_id(grant.owner_key()),
            ..ContentReceipt::default()
        }));
        write_response(&mut local, &response).await.unwrap();
    }
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One bounded real SQLite/Unix IPC lifecycle proves lost-terminal resume and two non-consuming restores together."
)]
async fn peer_ipc_requires_terminal_and_streams_resumable_private_copy() {
    let directory = tempfile::tempdir().unwrap();
    let socket = directory.path().join("agent.sock");
    let listener = tokio::net::UnixListener::bind(&socket).unwrap();
    let (provider, owner, grant) = fixture_grant();
    let store = PrivateStorageStore::create(
        &directory.path().join("provider"),
        StorageLimits {
            capacity_bytes: 4 * CHUNK_BYTES as u64,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let backend = PrivateStorageProvider::new(store, provider.verifying_key()).unwrap();
    let service = Arc::new(StorageService::new(Arc::new(provider), backend));
    let server = tokio::spawn(fake_agent(listener, Arc::clone(&service), grant.clone()));
    let bytes = vec![43_u8; CHUNK_BYTES + 31];
    let mut target = StorageTarget {
        archive_id: [9; 32],
        lease_id: None,
        ciphertext_bytes: bytes.len() as u64,
        sha256: Sha256::digest(&bytes).into(),
    };
    let reserve = StorageOperation::Reserve {
        expires_at: super::super::now().unwrap() + 600,
    };
    assert!(
        transfer::remote(&socket, &grant, &owner, target, reserve, &[])
            .await
            .is_err()
    );
    let reserved = transfer::remote(&socket, &grant, &owner, target, reserve, &[])
        .await
        .unwrap();
    assert_eq!(reserved.receipt.result().state, ReceiptState::Reserved);
    target.lease_id = Some(reserved.receipt.result().lease_id);
    let chunk = &bytes[..CHUNK_BYTES];
    transfer::remote(
        &socket,
        &grant,
        &owner,
        target,
        StorageOperation::Append {
            offset: 0,
            length: u32::try_from(chunk.len()).unwrap(),
            sha256: Sha256::digest(chunk).into(),
        },
        chunk,
    )
    .await
    .unwrap();
    let progress = transfer::remote(
        &socket,
        &grant,
        &owner,
        target,
        StorageOperation::Progress,
        &[],
    )
    .await
    .unwrap();
    assert_eq!(progress.receipt.result().stored_bytes, CHUNK_BYTES as u64);
    assert_eq!(progress.receipt.result().state, ReceiptState::Partial);
    let chunk = &bytes[CHUNK_BYTES..];
    transfer::remote(
        &socket,
        &grant,
        &owner,
        target,
        StorageOperation::Append {
            offset: CHUNK_BYTES as u64,
            length: u32::try_from(chunk.len()).unwrap(),
            sha256: Sha256::digest(chunk).into(),
        },
        chunk,
    )
    .await
    .unwrap();
    let committed = transfer::remote(
        &socket,
        &grant,
        &owner,
        target,
        StorageOperation::Finalize,
        &[],
    )
    .await
    .unwrap();
    assert_eq!(committed.receipt.result().state, ReceiptState::Committed);
    for _ in 0..2 {
        let result = transfer::remote(
            &socket,
            &grant,
            &owner,
            target,
            StorageOperation::ReadRange {
                offset: 0,
                length: bytes.len() as u64,
            },
            &[],
        )
        .await
        .unwrap();
        assert_eq!(result.ciphertext, bytes);
        assert_eq!(result.receipt.result().lease_id, target.lease_id.unwrap());
    }
    let renewed = transfer::remote(
        &socket,
        &grant,
        &owner,
        target,
        StorageOperation::Renew {
            expires_at: super::super::now().unwrap() + 1200,
        },
        &[],
    )
    .await
    .unwrap();
    assert_eq!(renewed.receipt.result().state, ReceiptState::Renewed);
    for _ in 0..2 {
        let deleted = transfer::remote(
            &socket,
            &grant,
            &owner,
            target,
            StorageOperation::Delete,
            &[],
        )
        .await
        .unwrap();
        assert_eq!(deleted.receipt.result().state, ReceiptState::Deleted);
    }
    server.await.unwrap();
    drop(service);
    let store = PrivateStorageStore::open_existing(&directory.path().join("provider")).unwrap();
    let usage = store.usage().unwrap();
    assert_eq!(usage.reserved_bytes + usage.committed_bytes, 0);
}
