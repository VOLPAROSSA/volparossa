//! Actual three-store handoff over signed frames, not independent-host custody proof.

use std::{
    fs,
    os::unix::fs::MetadataExt as _,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
};

use ed25519_dalek::SigningKey;
use sha2::{Digest as _, Sha256};
use volparossa_content::{
    CHUNK_BYTES, Validity,
    private_storage::{
        PrivateStorageStore, StorageLimits,
        protocol::{
            GrantLimits, ReceiptState, SignedStorageGrant, StorageRights, VerifiedStorageGrant,
        },
        provider::PrivateStorageProvider,
        wire::{self, StorageService},
    },
    provider::{PublicationRegistry, serve_publication},
    transfer::TransferLimits,
};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentReceipt, ControlResponse, PrivateStorageReady,
    control_request::Operation, control_response::Payload, read_request, write_response,
};

use super::super::{
    handoff, operations,
    retained::{Charge, LockedSet},
    transfer,
};
use super::{keys_and_grants, peer_id};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Step {
    Reserve,
    Read,
    Delete,
    Other,
}

#[derive(Clone, Copy, Debug)]
struct Event {
    provider: usize,
    step: Step,
    bytes: u64,
    terminal_sent: bool,
}

struct Peer {
    service: Arc<StorageService>,
    grant: VerifiedStorageGrant,
}

struct HandoffPeers {
    socket: PathBuf,
    lose: Arc<Mutex<Option<(usize, Step)>>>,
    trace: Arc<Mutex<Vec<Event>>>,
    stop: tokio::sync::oneshot::Sender<()>,
    task: tokio::task::JoinHandle<()>,
}

impl HandoffPeers {
    fn start(
        root: &Path,
        signers: &[SigningKey],
        grants: &[VerifiedStorageGrant],
        fresh: bool,
    ) -> Self {
        let socket = root.join("handoff-agent.sock");
        let listener = tokio::net::UnixListener::bind(&socket).unwrap();
        let peers: Vec<_> = signers
            .iter()
            .enumerate()
            .map(|(index, signer)| {
                let path = root.join(format!("handoff-provider-{index}"));
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
                let provider = PrivateStorageProvider::new(store, signer.verifying_key()).unwrap();
                Peer {
                    service: Arc::new(StorageService::new(Arc::new(signer.clone()), provider)),
                    grant: grants[index].clone(),
                }
            })
            .collect();
        let lose = Arc::new(Mutex::new(None));
        let trace = Arc::new(Mutex::new(Vec::new()));
        let fault = Arc::clone(&lose);
        let events = Arc::clone(&trace);
        let (stop, mut stopping) = tokio::sync::oneshot::channel();
        let task = tokio::spawn(async move {
            loop {
                let (local, _) = tokio::select! {
                    accepted = listener.accept() => accepted.unwrap(),
                    _ = &mut stopping => break,
                };
                exchange(local, &peers, &fault, &events).await;
            }
        });
        Self {
            socket,
            lose,
            trace,
            stop,
            task,
        }
    }

    fn lose_next(&self, provider: usize, step: Step) {
        assert!(
            self.lose
                .lock()
                .unwrap()
                .replace((provider, step))
                .is_none()
        );
    }

    fn events(&self) -> Vec<Event> {
        self.trace.lock().unwrap().clone()
    }

    async fn stop(self) {
        assert!(
            self.lose.lock().unwrap().is_none(),
            "fault was not exercised"
        );
        self.stop.send(()).unwrap();
        self.task.await.unwrap();
        fs::remove_file(self.socket).unwrap();
    }
}

async fn exchange(
    mut local: tokio::net::UnixStream,
    peers: &[Peer],
    fault: &Mutex<Option<(usize, Step)>>,
    trace: &Mutex<Vec<Event>>,
) {
    let request = read_request(&mut local).await.unwrap();
    let Some(Operation::PrivateStorageRemote(requested)) = request.operation else {
        panic!("expected protected private-storage IPC handoff")
    };
    let index = peers
        .iter()
        .position(|peer| requested.provider_key == peer.grant.provider_key().as_bytes())
        .unwrap();
    let peer = &peers[index];
    assert_eq!(requested.grant, peer.grant.signed().encode());
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
    let result = receipt.receipt.result();
    let step = if result.range_sha256.is_some() {
        Step::Read
    } else {
        match result.state {
            ReceiptState::Reserved => Step::Reserve,
            ReceiptState::Deleted => Step::Delete,
            _ => Step::Other,
        }
    };
    let lose = {
        let mut armed = fault.lock().unwrap();
        if *armed == Some((index, step)) {
            armed.take();
            true
        } else {
            false
        }
    };
    if !lose {
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
    trace.lock().unwrap().push(Event {
        provider: index,
        step,
        bytes: receipt.ciphertext_bytes,
        terminal_sent: !lose,
    });
}

fn assert_usage(root: &Path, index: usize, committed: u64, reserved: u64, leases: u64) {
    let store = PrivateStorageStore::open_existing(&root.join(format!("handoff-provider-{index}")))
        .unwrap();
    let usage = store.usage().unwrap();
    assert_eq!(usage.committed_bytes, committed);
    assert_eq!(usage.reserved_bytes, reserved);
    assert_eq!(usage.leases, leases);
}

fn assert_pending(report: &serde_json::Value, stage: &str, length: u64) {
    assert_eq!(report["operation_complete"], false);
    assert_eq!(report["handoff_stage"], stage);
    assert_eq!(report["physical_payload_charge_upper_bound"], 3 * length);
    assert_eq!(report["uncertain_payload_bytes"], length);
    assert_eq!(report["committed_payload_bytes"], 2 * length);
}

#[tokio::test]
#[allow(
    clippy::too_many_lines,
    reason = "One real three-store lifecycle proves readback-before-delete and durable accounting across three separately lost confirmations."
)]
async fn handoff_real_stores_verify_replacement_before_delete_and_keep_lost_replies_charged() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path();
    let (owner, mut providers, mut grants) = keys_and_grants();
    let replacement = SigningKey::generate(&mut rand_core::OsRng);
    let now = crate::storage::now().unwrap();
    let grant = SignedStorageGrant::issue(
        &replacement,
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
    .verify(&replacement.verifying_key(), now)
    .unwrap();
    providers.push(replacement);
    grants.push(grant);
    let ciphertext = vec![43_u8; CHUNK_BYTES + 73];
    let hash: [u8; 32] = Sha256::digest(&ciphertext).into();
    let length = ciphertext.len() as u64;
    let input_path = root.join("opaque-source");
    fs::write(&input_path, &ciphertext).unwrap();
    let state_path = root.join("set");
    let mut set = LockedSet::create(
        &state_path,
        &owner.verifying_key(),
        length,
        hash,
        &grants[..2],
        600,
    )
    .unwrap();
    let first = HandoffPeers::start(root, &providers, &grants, true);
    let (mut input, _) = transfer::checked_input(&input_path, hash).unwrap();
    assert_eq!(
        operations::deposit(&mut set, &first.socket, &owner, &mut input)
            .await
            .unwrap()["operation_complete"],
        true
    );
    let originals: Vec<_> = (0..2)
        .map(|index| set.copy(index).unwrap().journal.target().unwrap())
        .collect();
    drop(input);
    fs::remove_file(input_path).unwrap();

    first.lose_next(2, Step::Reserve);
    let pending = handoff::replace(
        &mut set,
        &first.socket,
        &owner,
        providers[0].verifying_key(),
        &grants[2],
        600,
    )
    .await
    .unwrap();
    assert_pending(&pending, "replacement_upload_pending", length);
    assert!(
        first
            .events()
            .iter()
            .all(|event| event.step != Step::Delete)
    );
    let replacement_id = set.copy(2).unwrap().journal.target().unwrap().archive_id;
    assert!(set.copy(2).unwrap().journal.lease.is_none());
    drop(set);
    first.stop().await;
    assert_usage(root, 0, length, 0, 1);
    assert_usage(root, 1, length, 0, 1);
    assert_usage(root, 2, 0, length, 1);

    let second = HandoffPeers::start(root, &providers, &grants, false);
    let mut set = LockedSet::open(&state_path).unwrap();
    second.lose_next(2, Step::Read);
    let pending = handoff::replace(
        &mut set,
        &second.socket,
        &owner,
        providers[0].verifying_key(),
        &grants[2],
        600,
    )
    .await
    .unwrap();
    assert_pending(&pending, "replacement_verification_pending", length);
    assert_eq!(
        set.copy(2).unwrap().journal.target().unwrap().archive_id,
        replacement_id
    );
    assert!(second.events().iter().any(|event| {
        event.provider == 2
            && event.step == Step::Read
            && event.bytes == length
            && !event.terminal_sent
    }));
    assert!(
        second
            .events()
            .iter()
            .all(|event| event.step != Step::Delete)
    );
    drop(set);
    second.stop().await;
    for index in 0..3 {
        assert_usage(root, index, length, 0, 1);
    }

    let third = HandoffPeers::start(root, &providers, &grants, false);
    let mut set = LockedSet::open(&state_path).unwrap();
    third.lose_next(0, Step::Delete);
    let pending = handoff::replace(
        &mut set,
        &third.socket,
        &owner,
        providers[0].verifying_key(),
        &grants[2],
        600,
    )
    .await
    .unwrap();
    assert_pending(&pending, "source_delete_unconfirmed", length);
    let events = third.events();
    let readback = events
        .iter()
        .position(|event| {
            event.provider == 2
                && event.step == Step::Read
                && event.bytes == length
                && event.terminal_sent
        })
        .unwrap();
    let deletion = events
        .iter()
        .position(|event| event.provider == 0 && event.step == Step::Delete && !event.terminal_sent)
        .unwrap();
    assert!(readback < deletion);
    assert!(
        events
            .iter()
            .all(|event| event.provider != 1 || event.step != Step::Delete)
    );
    assert_eq!(set.data.copies[0].charge, Charge::Uncertain);
    drop(set);
    third.stop().await;
    assert_usage(root, 0, 0, 0, 0);
    assert_usage(root, 1, length, 0, 1);
    assert_usage(root, 2, length, 0, 1);

    let fourth = HandoffPeers::start(root, &providers, &grants, false);
    let mut set = LockedSet::open(&state_path).unwrap();
    assert_eq!(
        set.report("status").unwrap()["physical_payload_charge_upper_bound"],
        3 * length
    );
    let completed = handoff::replace(
        &mut set,
        &fourth.socket,
        &owner,
        providers[0].verifying_key(),
        &grants[2],
        600,
    )
    .await
    .unwrap();
    assert_eq!(completed["operation_complete"], true);
    assert_eq!(completed["handoff_stage"], "complete");
    assert_eq!(completed["physical_payload_charge_upper_bound"], 2 * length);
    assert_eq!(completed["committed_payload_bytes"], 2 * length);
    assert_eq!(completed["uncertain_payload_bytes"], 0);
    assert_eq!(set.data.copies[0].charge, Charge::Deleted);
    assert_eq!(set.data.copies[1].charge, Charge::Committed);
    assert_eq!(set.data.copies[2].charge, Charge::Committed);
    for (index, original) in originals.iter().enumerate() {
        assert_eq!(
            &set.copy(index).unwrap().journal.target().unwrap(),
            original
        );
    }
    assert_eq!(
        set.copy(2).unwrap().journal.target().unwrap().archive_id,
        replacement_id
    );
    let mut retained = set.copy(2).unwrap();
    for index in 0..2 {
        let output = root.join(format!("replacement-restored-{index}"));
        transfer::restore_retained(&fourth.socket, &grants[2], &owner, &mut retained, &output)
            .await
            .unwrap();
        assert_eq!(fs::read(&output).unwrap(), ciphertext);
        assert_eq!(fs::metadata(&output).unwrap().mode() & 0o777, 0o600);
    }
    drop(retained);
    drop(set);
    fourth.stop().await;
    assert_usage(root, 0, 0, 0, 0);
    assert_usage(root, 1, length, 0, 1);
    assert_usage(root, 2, length, 0, 1);
}
