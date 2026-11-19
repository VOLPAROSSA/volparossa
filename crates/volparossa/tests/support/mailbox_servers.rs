// SPDX-License-Identifier: GPL-3.0-only
//! Two signed mailbox services over local streams for isolated CLI and consumer tests.
use ed25519_dalek::{SigningKey, VerifyingKey};
use std::{
    collections::BTreeMap,
    fs,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicI32, AtomicUsize, Ordering},
    },
    time::{SystemTime, UNIX_EPOCH},
};
use tokio::{
    net::{UnixListener, UnixStream},
    task::JoinHandle,
};
use volparossa_content::{
    CacheLimits, SignedManifest,
    mailbox::{
        SignedMailboxGrant,
        store::MailboxStore,
        wire::{MailboxCommand, MailboxOperation, MailboxService, begin, bridge},
    },
    provider::{PublicationRegistry, serve_publication},
    transfer::TransferLimits,
};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentReceipt, ControlResponse, ControlResult, MailboxReady,
    control_request::Operation, control_response::Payload, read_request, write_response,
};
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}

pub(super) fn start(
    root: &Path,
    keys: &[Arc<SigningKey>; 2],
    reopen: bool,
    fault: Arc<AtomicI32>,
    requests: Arc<AtomicUsize>,
) -> JoinHandle<()> {
    let socket = root.join("control.sock");
    if reopen {
        fs::remove_file(&socket).unwrap();
    }
    let listener = UnixListener::bind(socket).unwrap();
    let mut providers = BTreeMap::new();
    for (index, key) in keys.iter().enumerate() {
        let path = root.join(format!("provider-{index}"));
        let limits = CacheLimits {
            max_bytes: 8 * 1024 * 1024,
            max_entries: 64,
            min_free_bytes: 0,
        };
        let store = if reopen {
            MailboxStore::open(&path, limits, now())
        } else {
            MailboxStore::create(&path, limits, now())
        }
        .unwrap();
        providers.insert(
            key.verifying_key().to_bytes(),
            Arc::new(MailboxService::new(key.clone(), store)),
        );
    }
    tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            requests.fetch_add(1, Ordering::SeqCst);
            serve_request(&mut stream, &providers, fault.load(Ordering::SeqCst)).await;
        }
    })
}

async fn serve_request(
    stream: &mut UnixStream,
    providers: &BTreeMap<[u8; 32], Arc<MailboxService>>,
    fault: i32,
) {
    let request = read_request(stream).await.unwrap();
    let Some(Operation::MailboxRemote(parameters)) = request.operation else {
        panic!("typed mailbox operation required")
    };
    let provider: [u8; 32] = parameters.provider_key.as_slice().try_into().unwrap();
    if fault == -3
        && parameters.operation == MailboxOperation::List as i32
        && providers
            .first_key_value()
            .is_some_and(|(first, _)| first == &provider)
    {
        let mut unavailable = response(
            request.request_id,
            "MAILBOX_UNAVAILABLE",
            Payload::Ack(volparossa_local_control::Empty {}),
        );
        unavailable.result = ControlResult::Unavailable as i32;
        write_response(stream, &unavailable).await.unwrap();
        return;
    }
    let signed = SignedMailboxGrant::decode(&parameters.grant).unwrap();
    let owner = VerifyingKey::from_bytes(&signed.owner_key_hint().unwrap()).unwrap();
    let grant = signed.verify(&owner, now()).unwrap();
    let command = MailboxCommand {
        operation: MailboxOperation::try_from(parameters.operation).unwrap(),
        manifest: (!parameters.manifest.is_empty())
            .then(|| SignedManifest::decode(&parameters.manifest).unwrap()),
        message_id: (!parameters.message_id.is_empty())
            .then(|| parameters.message_id.as_slice().try_into().unwrap()),
    };
    let mut registry = PublicationRegistry::new();
    registry.set_mailbox(providers[&provider].clone());
    let (mut remote, mut serving) = tokio::io::duplex(4096);
    let service = tokio::spawn(async move {
        serve_publication(&mut serving, &registry, TransferLimits::default())
            .await
            .unwrap();
    });
    let challenge = begin(&mut remote, &provider).await.unwrap();
    write_response(
        stream,
        &response(
            request.request_id.clone(),
            "MAILBOX_READY",
            Payload::MailboxReady(MailboxReady {
                provider_key: provider.to_vec(),
                challenge: challenge.encode(),
            }),
        ),
    )
    .await
    .unwrap();
    let receipt = bridge(stream, &mut remote, &challenge, &grant, &command)
        .await
        .unwrap();
    service.await.unwrap();
    let mut correlation = request.request_id;
    if fault == parameters.operation
        || (fault == -4
            && parameters.operation == MailboxOperation::Acknowledge as i32
            && providers
                .last_key_value()
                .is_some_and(|(last, _)| last == &provider))
    {
        correlation[0] ^= 1;
    }
    write_response(
        stream,
        &response(
            correlation,
            "CONTENT_OK",
            Payload::Content(ContentReceipt {
                bytes: receipt.ciphertext_bytes(),
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

fn response(request_id: Vec<u8>, code: &str, payload: Payload) -> ControlResponse {
    ControlResponse {
        protocol_version: CONTROL_PROTOCOL_VERSION,
        request_id,
        result: ControlResult::Ok as i32,
        diagnostic_code: code.into(),
        private_storage_remote_detail: None,
        payload: Some(payload),
    }
}
