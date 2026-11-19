//! Lost final acknowledgements on a real `SQLite` provider, over the normal owner IPC.
use super::*;
use tokio::io::{AsyncReadExt as _, AsyncWriteExt as _};
use tokio::net::{UnixListener, UnixStream};
use volparossa_content::private_storage::protocol::{SignedStorageReceipt, VerifiedStorageRequest};
use volparossa_local_control::{
    CONTROL_PROTOCOL_VERSION, ContentReceipt, ControlRequest, ControlResponse,
    PrivateStorageOutcome, PrivateStorageOutcomeCategory, PrivateStorageOutcomeDeadline,
    PrivateStorageOutcomePhase, PrivateStorageOutcomeStatus, control_request::Operation,
    control_response::Payload, read_request, write_response,
};

async fn response(stream: &mut UnixStream, request: ControlRequest, code: &str, payload: Payload) {
    write_response(
        stream,
        &ControlResponse {
            protocol_version: CONTROL_PROTOCOL_VERSION,
            request_id: request.request_id,
            result: 0,
            diagnostic_code: code.into(),
            private_storage_remote_detail: None,
            payload: Some(payload),
        },
    )
    .await
    .unwrap();
}

async fn reply(
    stream: &mut UnixStream,
    request: ControlRequest,
    signed: &VerifiedStorageRequest,
    provider: &SigningKey,
    backend: &mut PrivateStorageProvider,
) {
    let mut payload = Vec::new();
    if let StorageOperation::Append { length, .. } = signed.operation() {
        assert_eq!(stream.read_u32().await.unwrap(), length);
        payload.resize(length as usize, 0);
        stream.read_exact(&mut payload).await.unwrap();
    }
    let now = crate::storage::now().unwrap();
    let outcome = backend.apply(signed, &payload, now).unwrap();
    let receipt = SignedStorageReceipt::sign(
        provider,
        signed,
        outcome.receipt,
        Validity {
            created: now,
            expires: signed.validity().expires,
        },
    )
    .unwrap()
    .encode();
    stream
        .write_u32(u32::try_from(receipt.len()).unwrap())
        .await
        .unwrap();
    stream.write_all(&receipt).await.unwrap();
    response(
        stream,
        request,
        "CONTENT_OK",
        Payload::Content(ContentReceipt {
            providers_used: 1,
            provider_peer_ids: vec![peer_id(signed.grant().provider_key())],
            control_relay_peer_id: peer_id(signed.grant().owner_key()),
            ..ContentReceipt::default()
        }),
    )
    .await;
}

async fn serve(
    listener: UnixListener,
    provider: SigningKey,
    grant: VerifiedStorageGrant,
    mut backend: PrivateStorageProvider,
    delivered: bool,
    expires_at: u64,
    background: bool,
) {
    let payload = [23_u8; 32];
    let mut original = Vec::new();
    for expected in [
        Some(StorageOperation::Reserve { expires_at }),
        Some(StorageOperation::Append {
            offset: 0,
            length: 32,
            sha256: Sha256::digest(payload).into(),
        }),
        Some(StorageOperation::Finalize),
        None,
    ]
    .into_iter()
    .chain((!background).then_some(Some(StorageOperation::Progress)))
    {
        let (mut stream, _) = listener.accept().await.unwrap();
        let request = read_request(&mut stream).await.unwrap();
        if let Some(operation) = expected {
            let signed =
                outcome_transfer::signed_request(&mut stream, &request, &provider, &grant).await;
            assert_eq!(signed.operation(), operation);
            if operation == StorageOperation::Finalize {
                if delivered {
                    let result = backend
                        .apply(&signed, &[], crate::storage::now().unwrap())
                        .unwrap();
                    assert_eq!(result.receipt.state, ReceiptState::Committed);
                }
                original = request.request_id;
                continue; // Drop the original exchange without a receipt.
            }
            reply(&mut stream, request, &signed, &provider, &mut backend).await;
        } else {
            let Some(Operation::PrivateStorageOutcome(query)) = &request.operation else {
                panic!("expected caller-bound local observation after Finalize")
            };
            assert_eq!(query.original_request_id, original);
            response(
                &mut stream,
                request,
                "PRIVATE_STORAGE_OUTCOME",
                Payload::PrivateStorageOutcome(PrivateStorageOutcome {
                    status: PrivateStorageOutcomeStatus::Observed as i32,
                    phase: PrivateStorageOutcomePhase::RemoteReceiptRead as i32,
                    category: PrivateStorageOutcomeCategory::Timeout as i32,
                    deadline: PrivateStorageOutcomeDeadline::Operation as i32,
                    ..Default::default()
                }),
            )
            .await;
        }
    }
    if background {
        assert!(
            tokio::time::timeout(std::time::Duration::from_millis(100), listener.accept())
                .await
                .is_err()
        );
    }
}

#[tokio::test]
async fn lost_final_receipt_only_completes_on_signed_progress_for_the_original_committed_lease() {
    for (delivered, background) in [(true, false), (false, false), (true, true)] {
        tokio::time::timeout(
            std::time::Duration::from_secs(15),
            deposit_case(delivered, background),
        )
        .await
        .expect("the owner and provider must finish the bounded script");
    }
}

async fn deposit_case(delivered: bool, background: bool) {
    let directory = tempfile::tempdir().unwrap();
    let root = directory.path();
    let socket = root.join("agent.sock");
    let listener = UnixListener::bind(&socket).unwrap();
    let (provider, owner, grant) = fixture_grant();
    let path = root.join("provider");
    let store = PrivateStorageStore::create(
        &path,
        StorageLimits {
            capacity_bytes: 2 * CHUNK_BYTES as u64,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let backend = PrivateStorageProvider::new(store, provider.verifying_key()).unwrap();
    let expires = crate::storage::now().unwrap() + 600;
    let server = tokio::spawn(serve(
        listener,
        provider,
        grant.clone(),
        backend,
        delivered,
        expires,
        background,
    ));
    let bytes = [23_u8; 32];
    let original = Journal::new(&grant, 32, Sha256::digest(bytes).into(), expires).unwrap();
    let journal = root.join("owner");
    let mut retained = LockedJournal::create(&journal, original).unwrap();
    let input = root.join("ciphertext");
    fs::write(&input, bytes).unwrap();
    let mut input = fs::File::open(input).unwrap();
    let deposit = transfer::deposit_retained(&socket, &grant, &owner, &mut retained, &mut input);
    let result = if background {
        transfer::with_maintenance_turn(vec![1; 32], deposit).await
    } else {
        deposit.await
    };
    if delivered && !background {
        result.unwrap();
    } else {
        let error = result.unwrap_err();
        let boundary = error
            .downcast_ref::<super::super::diagnostics::Boundary>()
            .unwrap();
        assert!(matches!(
            boundary.operation,
            super::super::diagnostics::Operation::Finalize
        ));
        assert!(matches!(
            boundary.stage,
            super::super::diagnostics::Stage::WireReceipt
        ));
    }
    server.await.unwrap();
    drop(retained);
    let persisted = LockedJournal::open(&journal).unwrap();
    let state = if delivered && !background {
        ReceiptState::Committed
    } else {
        ReceiptState::Partial
    };
    assert_eq!(persisted.journal.last_state, Some(state as i32));
    assert_eq!(persisted.journal.last_stored_bytes, 32);
    let usage = PrivateStorageStore::open_existing(&path)
        .unwrap()
        .usage()
        .unwrap();
    assert_eq!(usage.leases, 1);
    assert_eq!(usage.committed_bytes, if delivered { 32 } else { 0 });
    assert_eq!(usage.reserved_bytes + usage.committed_bytes, 32);
}
