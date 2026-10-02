//! Real local `SQLite` providers and framed Unix IPC; no protected-overlay or Signal proof.

use std::{
    fs,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

use clap::Parser as _;
use ed25519_dalek::{SigningKey, VerifyingKey};
use sha2::{Digest as _, Sha256};
use volparossa_content::{
    CHUNK_BYTES, Validity,
    private_storage::{
        PrivateStorageStore, StorageLimits,
        protocol::{GrantLimits, SignedStorageGrant, StorageRights, VerifiedStorageGrant},
        provider::PrivateStorageProvider,
        wire::{self, StorageService},
    },
};

use super::{
    operations,
    retained::{Charge, LockedSet},
    transfer,
};

#[path = "replicas_handoff_tests.rs"]
pub(super) mod handoff;

fn keys_and_grants() -> (SigningKey, Vec<SigningKey>, Vec<VerifiedStorageGrant>) {
    let owner = SigningKey::from_bytes(&[22; 32]);
    let providers = vec![
        SigningKey::from_bytes(&[11; 32]),
        SigningKey::from_bytes(&[33; 32]),
    ];
    let now = crate::storage::now().unwrap();
    let grants = providers
        .iter()
        .map(|provider| {
            SignedStorageGrant::issue(
                provider,
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
            .unwrap()
        })
        .collect();
    (owner, providers, grants)
}

#[test]
fn replica_metadata_is_private_locked_distinct_and_owner_bound() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("set");
    let (owner, providers, grants) = keys_and_grants();
    let set = LockedSet::create(&path, &owner.verifying_key(), 99, [9; 32], &grants, 600).unwrap();
    assert!(LockedSet::open(&path).is_err());
    assert_eq!(fs::metadata(&path).unwrap().mode() & 0o777, 0o700);
    assert_eq!(
        fs::metadata(path.join("replicas.json")).unwrap().mode() & 0o777,
        0o600
    );
    assert!(set.check_owner(&providers[0]).is_err());
    assert_eq!(
        set.report("status").unwrap()["physical_payload_charge_upper_bound"],
        0
    );
    let original = set.copy(0).unwrap().journal.target().unwrap();
    drop(set);
    let mut reopened = LockedSet::open(&path).unwrap();
    assert_eq!(
        reopened.copy(0).unwrap().journal.target().unwrap(),
        original
    );
    reopened.begin(0).unwrap();
    drop(reopened);
    let reopened = LockedSet::open(&path).unwrap();
    assert_eq!(
        reopened.report("status").unwrap()["uncertain_payload_bytes"],
        99
    );
    let duplicate = [grants[0].clone(), grants[0].clone()];
    let rejected = temporary.path().join("duplicate");
    assert!(
        LockedSet::create(
            &rejected,
            &owner.verifying_key(),
            99,
            [9; 32],
            &duplicate,
            600
        )
        .is_err()
    );
    assert!(!rejected.exists());
    assert!(
        LockedSet::create(
            &temporary.path().join("wrong-owner"),
            &providers[0].verifying_key(),
            99,
            [9; 32],
            &grants,
            600
        )
        .is_err()
    );
    assert!(LockedSet::create(&path, &owner.verifying_key(), 99, [9; 32], &grants, 600).is_err());
}

#[test]
fn replica_cli_requires_explicit_ciphertext_and_single_copy_delete() {
    let (_, providers, _) = keys_and_grants();
    let first = hex::encode(providers[0].verifying_key().as_bytes());
    let second = hex::encode(providers[1].verifying_key().as_bytes());
    let common = ["volparossa", "storage", "replicas"];
    for args in [
        vec![
            "create",
            "--state",
            "/set",
            "--input",
            "/archive",
            "--sha256",
            &first,
            "--provider-key",
            &first,
            "--grant",
            "/first",
            "--provider-key",
            &second,
            "--grant",
            "/second",
            "--already-encrypted",
        ],
        vec![
            "deposit",
            "--state",
            "/set",
            "--input",
            "/archive",
            "--already-encrypted",
        ],
        vec!["status", "--state", "/set"],
        vec!["progress", "--state", "/set"],
        vec!["restore", "--state", "/set", "--output", "/new"],
        vec!["renew", "--state", "/set", "--lifetime-seconds", "600"],
        vec!["delete", "--state", "/set", "--provider-key", &first],
    ] {
        assert!(crate::Cli::try_parse_from(common.into_iter().chain(args)).is_ok());
    }
    for args in [
        vec!["deposit", "--state", "/set", "--input", "/archive"],
        vec!["delete", "--state", "/set"],
    ] {
        assert!(crate::Cli::try_parse_from(common.into_iter().chain(args)).is_err());
    }
}

fn peer_id(key: &VerifyingKey) -> String {
    let mut bytes = vec![8, 1, 18, 32];
    bytes.extend_from_slice(key.as_bytes());
    volparossa_identity::PublicKey::try_decode_protobuf(&bytes)
        .unwrap()
        .to_peer_id()
        .to_string()
}

struct FixturePeer {
    service: Arc<StorageService>,
    grant: VerifiedStorageGrant,
    online: Arc<AtomicBool>,
    lose_terminal: Arc<AtomicBool>,
}

pub(super) struct LocalProviders {
    pub(super) socket: PathBuf,
    pub(super) online: Vec<Arc<AtomicBool>>,
    pub(super) lose_terminal: Vec<Arc<AtomicBool>>,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl LocalProviders {
    pub(super) fn start(
        root: &Path,
        providers: &[SigningKey],
        grants: &[VerifiedStorageGrant],
        fresh: bool,
    ) -> Self {
        let socket = root.join("agent.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let mut peers = Vec::new();
        let mut online = Vec::new();
        let mut lose_terminal = Vec::new();
        for (index, signer) in providers.iter().enumerate() {
            let path = root.join(format!("provider-{index}"));
            let store = if fresh {
                PrivateStorageStore::create(
                    &path,
                    StorageLimits {
                        capacity_bytes: 4 * CHUNK_BYTES as u64,
                        min_free_bytes: 0,
                    },
                )
            } else {
                PrivateStorageStore::open_existing(&path)
            }
            .unwrap();
            let backend = PrivateStorageProvider::new(store, signer.verifying_key()).unwrap();
            let live = Arc::new(AtomicBool::new(true));
            let lose = Arc::new(AtomicBool::new(false));
            peers.push(FixturePeer {
                service: Arc::new(StorageService::new(Arc::new(signer.clone()), backend)),
                grant: grants[index].clone(),
                online: Arc::clone(&live),
                lose_terminal: Arc::clone(&lose),
            });
            online.push(live);
            lose_terminal.push(lose);
        }
        let (stop, mut stopping) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                let accepted = tokio::select! {
                    accepted = listener.accept() => accepted.unwrap(),
                    _ = &mut stopping => break,
                };
                local_exchange(accepted.0, &peers).await;
            }
        });
        Self {
            socket,
            online,
            lose_terminal,
            stop,
            task,
        }
    }

    pub(super) async fn stop(self) {
        self.stop.send(()).unwrap();
        self.task.await.unwrap();
        fs::remove_file(self.socket).unwrap();
    }
}

async fn local_exchange(mut local: tokio::net::UnixStream, peers: &[FixturePeer]) {
    use volparossa_content::{
        provider::{PublicationRegistry, serve_publication},
        transfer::TransferLimits,
    };
    use volparossa_local_control::{
        CONTROL_PROTOCOL_VERSION, ContentReceipt, ControlResponse, PrivateStorageReady,
        control_request::Operation, control_response::Payload, read_request, write_response,
    };
    let request = read_request(&mut local).await.unwrap();
    let Some(Operation::PrivateStorageRemote(requested)) = request.operation else {
        panic!("wrong IPC operation")
    };
    let peer = peers
        .iter()
        .find(|peer| requested.provider_key == peer.grant.provider_key().as_bytes())
        .unwrap();
    assert_eq!(requested.grant, peer.grant.signed().encode());
    if !peer.online.load(Ordering::SeqCst) {
        return;
    }
    let (mut remote, mut provider) = tokio::io::duplex(4096);
    let mut registry = PublicationRegistry::new();
    registry.set_private_storage(Arc::clone(&peer.service));
    let serving = tokio::spawn(async move {
        serve_publication(&mut provider, &registry, TransferLimits::default())
            .await
            .unwrap();
    });
    let challenge = wire::begin(&mut remote, &peer.grant).await.unwrap();
    let mut response = ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id: request.request_id,
        result: 0,
        diagnostic_code: "PRIVATE_STORAGE_READY".into(),
        payload: Some(Payload::PrivateStorageReady(PrivateStorageReady {
            provider_key: peer.grant.provider_key().to_bytes().to_vec(),
            challenge: challenge.encode(),
        })),
    };
    write_response(&mut local, &response).await.unwrap();
    let receipt = wire::bridge(&mut local, &mut remote, &peer.grant, &challenge)
        .await
        .unwrap();
    serving.await.unwrap();
    if peer.lose_terminal.swap(false, Ordering::SeqCst) {
        return;
    }
    response.diagnostic_code = "CONTENT_OK".into();
    response.payload = Some(Payload::Content(ContentReceipt {
        bytes: receipt.ciphertext_bytes,
        peer_bytes: receipt.ciphertext_bytes,
        providers_used: 1,
        provider_peer_ids: vec![peer_id(peer.grant.provider_key())],
        control_relay_peer_id: peer_id(peer.grant.owner_key()),
        ..ContentReceipt::default()
    }));
    write_response(&mut local, &response).await.unwrap();
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One bounded two-store lifecycle joins lost acknowledgements, restart, failover, non-consuming restores and single-copy deletion."
)]
async fn replica_two_real_stores_resume_failover_and_delete_without_consuming_survivor() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let (owner, providers, grants) = keys_and_grants();
    let ciphertext = vec![43_u8; CHUNK_BYTES + 73];
    let hash: [u8; 32] = Sha256::digest(&ciphertext).into();
    let length = ciphertext.len() as u64;
    let input_path = root.join("synthetic-opaque-transport-fixture");
    fs::write(&input_path, &ciphertext).unwrap();
    let state_path = root.join("set");
    let mut set = LockedSet::create(
        &state_path,
        &owner.verifying_key(),
        length,
        hash,
        &grants,
        600,
    )
    .unwrap();
    let identities: Vec<_> = (0..2)
        .map(|index| {
            set.copy(index)
                .unwrap()
                .journal
                .target()
                .unwrap()
                .archive_id
        })
        .collect();
    let first = LocalProviders::start(root, &providers, &grants, true);
    first.lose_terminal[0].store(true, Ordering::SeqCst);
    let (mut input, _) = transfer::checked_input(&input_path, hash).unwrap();
    let partial = operations::deposit(&mut set, &first.socket, &owner, &mut input)
        .await
        .unwrap();
    assert_eq!(partial["operation_complete"], false);
    assert_eq!(partial["uncertain_payload_bytes"], length);
    assert_eq!(partial["committed_payload_bytes"], length);
    assert_eq!(partial["physical_payload_charge_upper_bound"], 2 * length);
    assert!(set.copy(0).unwrap().journal.lease.is_none());
    drop(set);
    first.stop().await;
    for index in 0..2 {
        let store =
            PrivateStorageStore::open_existing(&root.join(format!("provider-{index}"))).unwrap();
        let usage = store.usage().unwrap();
        assert_eq!(usage.leases, 1);
        assert_eq!(usage.reserved_bytes + usage.committed_bytes, length);
    }
    let second = LocalProviders::start(root, &providers, &grants, false);
    let mut set = LockedSet::open(&state_path).unwrap();
    let completed = operations::deposit(&mut set, &second.socket, &owner, &mut input)
        .await
        .unwrap();
    assert_eq!(completed["operation_complete"], true);
    assert_eq!(completed["committed_payload_bytes"], 2 * length);
    for (index, original) in identities.iter().enumerate() {
        assert_eq!(
            &set.copy(index)
                .unwrap()
                .journal
                .target()
                .unwrap()
                .archive_id,
            original
        );
    }
    let refreshed = operations::refresh(&mut set, &second.socket, &owner, None)
        .await
        .unwrap();
    assert_eq!(refreshed["operation_complete"], true);
    let renewed = operations::refresh(&mut set, &second.socket, &owner, Some(1200))
        .await
        .unwrap();
    assert_eq!(renewed["committed_payload_bytes"], 2 * length);
    drop(input);
    fs::remove_file(&input_path).unwrap();
    second.online[0].store(false, Ordering::SeqCst);
    for index in 0..2 {
        let output = root.join(format!("restored-{index}"));
        let restored = operations::restore(&mut set, &second.socket, &owner, &output)
            .await
            .unwrap();
        assert_eq!(restored["operation_complete"], true);
        assert_eq!(
            restored["restored_from_provider_key"],
            hex::encode(providers[1].verifying_key().as_bytes())
        );
        assert_eq!(restored["physical_payload_charge_upper_bound"], 2 * length);
        assert_eq!(fs::read(&output).unwrap(), ciphertext);
        assert_eq!(fs::metadata(&output).unwrap().mode() & 0o777, 0o600);
        assert!(
            operations::restore(&mut set, &second.socket, &owner, &output)
                .await
                .is_err()
        );
    }
    second.online[0].store(true, Ordering::SeqCst);
    second.lose_terminal[0].store(true, Ordering::SeqCst);
    let uncertain_delete = operations::delete(
        &mut set,
        &second.socket,
        &owner,
        providers[0].verifying_key(),
    )
    .await
    .unwrap();
    assert_eq!(uncertain_delete["operation_complete"], false);
    assert_eq!(
        uncertain_delete["physical_payload_charge_upper_bound"],
        2 * length
    );
    drop(set);
    let mut set = LockedSet::open(&state_path).unwrap();
    let deleted = operations::delete(
        &mut set,
        &second.socket,
        &owner,
        providers[0].verifying_key(),
    )
    .await
    .unwrap();
    assert_eq!(deleted["operation_complete"], true);
    assert_eq!(deleted["committed_payload_bytes"], length);
    assert_eq!(deleted["physical_payload_charge_upper_bound"], length);
    assert_eq!(set.data.copies[0].charge, Charge::Deleted);
    assert_eq!(set.data.copies[1].charge, Charge::Committed);
    assert!(
        operations::delete(
            &mut set,
            &second.socket,
            &owner,
            SigningKey::from_bytes(&[55; 32]).verifying_key()
        )
        .await
        .is_err()
    );
    let final_output = root.join("survivor-restored");
    assert_eq!(
        operations::restore(&mut set, &second.socket, &owner, &final_output)
            .await
            .unwrap()["operation_complete"],
        true
    );
    assert_eq!(fs::read(final_output).unwrap(), ciphertext);
    second.stop().await;
    let removed = PrivateStorageStore::open_existing(&root.join("provider-0")).unwrap();
    assert_eq!(removed.usage().unwrap().leases, 0);
    let survivor = PrivateStorageStore::open_existing(&root.join("provider-1")).unwrap();
    assert_eq!(survivor.usage().unwrap().leases, 1);
    assert_eq!(survivor.usage().unwrap().committed_bytes, length);
}
