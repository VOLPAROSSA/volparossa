//! Real signed requests and durable custody; diagnostics do not establish remote availability.

use super::*;
use crate::private_storage::LeaseId;
use crate::private_storage::wire::diagnostic::{Failure, Observation};
use std::sync::atomic::AtomicBool;

type ObservedServer = JoinHandle<(Result<(), WireError>, Option<Failure>)>;
const BYTES: &[u8] = b"opaque diagnostic fixture";
const CANARY: &str = "/private/provider/archive-and-owner-key";

#[tokio::test]
async fn append_payload_header_and_body_eof_keep_wire_error_and_custody_unchanged() {
    for header in [true, false] {
        let fixture = Fixture::new();
        let original = target(BYTES);
        let reserved = fixture
            .exchange(
                original,
                StorageOperation::Reserve {
                    expires_at: unix_now().unwrap() + 600,
                },
                &[],
            )
            .await
            .unwrap();
        let owned = StorageTarget {
            lease_id: Some(reserved.receipt.result().lease_id),
            ..original
        };
        let before = fixture.usage();
        let (mut client, task, challenge) =
            session(&fixture, Arc::new(AtomicBool::new(false))).await;
        let signed = fixture.request(&challenge, owned, append(0, BYTES));
        write_frame(&mut client, &signed.encode()).await.unwrap();
        if header {
            client.write_all(&[0, 0]).await.unwrap();
        } else {
            client
                .write_u32(u32::try_from(BYTES.len()).unwrap())
                .await
                .unwrap();
            client.write_all(&BYTES[..BYTES.len() - 1]).await.unwrap();
        }
        client.shutdown().await.unwrap();
        let (result, failure) = timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert!(
            matches!(result, Err(WireError::Io(error)) if error.kind() == std::io::ErrorKind::UnexpectedEof)
        );
        let failure = failure.unwrap();
        assert_eq!(
            failure.event_code(),
            "CONTENT_PROVIDER_STORAGE_V1_APPEND__PAYLOAD__IO"
        );
        assert_eq!(
            failure.payload_io_event_code(),
            Some(if header {
                "CONTENT_PROVIDER_STORAGE_V2_APPEND__PAYLOAD_HEADER__UNEXPECTED_EOF"
            } else {
                "CONTENT_PROVIDER_STORAGE_V2_APPEND__PAYLOAD_BODY__UNEXPECTED_EOF"
            })
        );
        assert_eq!(fixture.usage(), before);
        let progress = fixture
            .exchange(owned, StorageOperation::Progress, &[])
            .await
            .unwrap();
        assert_eq!(progress.receipt.result().stored_bytes, 0);
        drop(client);
    }
}

#[tokio::test]
async fn invalid_append_payload_length_is_not_misreported_as_read_io() {
    for length in [0, u32::try_from(CHUNK_BYTES + 1).unwrap()] {
        let fixture = Fixture::new();
        let (mut client, task, challenge) =
            session(&fixture, Arc::new(AtomicBool::new(false))).await;
        let owned = StorageTarget {
            lease_id: Some(LeaseId::from_bytes([32; 16])),
            ..target(BYTES)
        };
        let signed = fixture.request(&challenge, owned, append(0, BYTES));
        write_frame(&mut client, &signed.encode()).await.unwrap();
        client.write_u32(length).await.unwrap();
        client.flush().await.unwrap();
        let (result, failure) = timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap();
        assert!(matches!(result, Err(WireError::Invalid)));
        let failure = failure.unwrap();
        assert_eq!(
            failure.event_code(),
            "CONTENT_PROVIDER_STORAGE_V1_APPEND__PAYLOAD__INVALID"
        );
        assert!(failure.payload_io_event_code().is_none());
        assert_eq!(fixture.usage().leases, 0);
        drop(client);
    }
}

#[tokio::test(start_paused = true)]
async fn stalled_append_payload_keeps_existing_timeout_without_inventing_io_error_kind() {
    let fixture = Fixture::new();
    let (mut client, task, challenge) = session(&fixture, Arc::new(AtomicBool::new(false))).await;
    let owned = StorageTarget {
        lease_id: Some(LeaseId::from_bytes([32; 16])),
        ..target(BYTES)
    };
    let signed = fixture.request(&challenge, owned, append(0, BYTES));
    write_frame(&mut client, &signed.encode()).await.unwrap();
    client
        .write_u32(u32::try_from(BYTES.len()).unwrap())
        .await
        .unwrap();
    client.flush().await.unwrap();
    let (result, failure) = timeout(IO_TIMEOUT + Duration::from_secs(1), task)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(WireError::Timeout)));
    let failure = failure.unwrap();
    assert_eq!(
        failure.event_code(),
        "CONTENT_PROVIDER_STORAGE_V1_APPEND__PAYLOAD__TIMEOUT"
    );
    assert!(failure.payload_io_event_code().is_none());
    assert_eq!(fixture.usage().leases, 0);
    drop(client);
}

struct ReceiptFault {
    stream: DuplexStream,
    fail: Arc<AtomicBool>,
}

impl AsyncRead for ReceiptFault {
    fn poll_read(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut tokio::io::ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_read(cx, buffer)
    }
}

impl AsyncWrite for ReceiptFault {
    fn poll_write(
        self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let this = self.get_mut();
        if this.fail.load(Ordering::SeqCst) {
            return Poll::Ready(Err(std::io::Error::other(CANARY)));
        }
        Pin::new(&mut this.stream).poll_write(cx, bytes)
    }
    fn poll_flush(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_flush(cx)
    }
    fn poll_shutdown(self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.get_mut().stream).poll_shutdown(cx)
    }
}

async fn session(
    fixture: &Fixture,
    fail: Arc<AtomicBool>,
) -> (DuplexStream, ObservedServer, StorageChallenge) {
    let service = Arc::clone(fixture.service.as_ref().unwrap());
    let (mut client, stream) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        let mut stream = ReceiptFault { stream, fail };
        let mut observation = Observation::default();
        let result = service.serve_observed(&mut stream, &mut observation).await;
        (result, observation.failure(false))
    });
    write_frame(&mut client, &fixture.grant.signed().encode())
        .await
        .unwrap();
    let challenge = StorageChallenge::decode_and_verify(
        &read_frame(&mut client, MAX_CHALLENGE_BYTES).await.unwrap(),
        &fixture.grant,
        unix_now().unwrap(),
    )
    .unwrap();
    (client, task, challenge)
}

async fn failure(
    fixture: &Fixture,
    owned: StorageTarget,
    operation: StorageOperation,
) -> (WireError, Failure) {
    let (mut client, task, challenge) = session(fixture, Arc::new(AtomicBool::new(false))).await;
    let signed = fixture.request(&challenge, owned, operation);
    assert!(
        finish(&mut client, &fixture.grant, &challenge, &signed, &[])
            .await
            .is_err()
    );
    drop(client);
    let (result, diagnostic) = timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    (result.unwrap_err(), diagnostic.unwrap())
}

async fn seed(fixture: &Fixture, wrong_whole_hash: bool) -> StorageTarget {
    let mut original = target(BYTES);
    if wrong_whole_hash {
        original.sha256 = hash(b"different immutable whole hash");
    }
    let reserved = fixture
        .exchange(
            original,
            StorageOperation::Reserve {
                expires_at: unix_now().unwrap() + 600,
            },
            &[],
        )
        .await
        .unwrap();
    let owned = StorageTarget {
        lease_id: Some(reserved.receipt.result().lease_id),
        ..original
    };
    fixture
        .exchange(owned, append(0, BYTES), BYTES)
        .await
        .unwrap();
    owned
}

#[tokio::test]
async fn lost_receipt_after_committed_finalize_keeps_wire_error_and_custody() {
    let mut fixture = Fixture::new();
    let owned = seed(&fixture, false).await;
    let charged = fixture.usage();
    let fail = Arc::new(AtomicBool::new(false));
    let (mut client, task, challenge) = session(&fixture, Arc::clone(&fail)).await;
    let signed = fixture.request(&challenge, owned, StorageOperation::Finalize);
    // The real challenge has arrived. Only the later server receipt write now fails.
    fail.store(true, Ordering::SeqCst);
    let bridge_trace = bridge_observation::Trace::default();
    assert!(matches!(
        finish_observed(
            &mut client,
            &fixture.grant,
            &challenge,
            &signed,
            &[],
            &bridge_trace,
        )
        .await,
        Err(WireError::Io(_))
    ));
    assert_eq!(
        bridge_trace.0.lock().unwrap().0.last(),
        Some(&crate::private_storage::wire::bridge_observation::Phase::RemoteReceiptRead)
    );
    drop(client);
    let (result, diagnostic) = timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(WireError::Io(_))));
    let diagnostic = diagnostic.unwrap();
    assert_eq!(
        diagnostic.event_code(),
        "CONTENT_PROVIDER_STORAGE_V1_FINALIZE__RECEIPT__IO"
    );
    assert!(!format!("{diagnostic:?}").contains(CANARY));
    fixture.reopen();
    assert_eq!(fixture.usage().committed_bytes, BYTES.len() as u64);
    assert_eq!(fixture.usage().reserved_bytes, 0);
    assert_eq!(fixture.usage().leases, charged.leases);
    let progress = fixture
        .exchange(owned, StorageOperation::Progress, &[])
        .await
        .unwrap();
    assert_eq!(progress.receipt.result().state, ReceiptState::Committed);
    let restored = fixture
        .exchange(
            owned,
            StorageOperation::ReadRange {
                offset: 0,
                length: BYTES.len() as u64,
            },
            &[],
        )
        .await
        .unwrap();
    assert_eq!(restored.ciphertext, BYTES);
    assert_eq!(fixture.usage().committed_bytes, BYTES.len() as u64);
}

#[tokio::test]
async fn verified_finalize_backend_integrity_is_not_payload_or_grant_failure() {
    let fixture = Fixture::new();
    let owned = seed(&fixture, true).await;
    let before = fixture.usage();
    let (error, diagnostic) = failure(&fixture, owned, StorageOperation::Finalize).await;
    assert!(matches!(error, WireError::Store));
    assert_eq!(
        diagnostic.event_code(),
        "CONTENT_PROVIDER_STORAGE_V1_FINALIZE__BACKEND__INTEGRITY"
    );
    assert_eq!(fixture.usage(), before);
    assert_eq!(fixture.usage().committed_bytes, 0);
}

#[tokio::test]
async fn backend_database_expiry_and_ownership_preserve_the_original_store_error() {
    for category in ["DATABASE", "EXPIRED", "OWNERSHIP"] {
        let fixture = Fixture::new();
        let mut owned = seed(&fixture, false).await;
        let before = fixture.usage();
        let connection = rusqlite::Connection::open(
            fixture
                .temporary
                .path()
                .join("private/private-storage.sqlite3"),
        )
        .unwrap();
        match category {
            "DATABASE" => connection.execute_batch("CREATE TRIGGER deny_commit BEFORE UPDATE OF committed ON leases BEGIN SELECT RAISE(ABORT, 'private database error canary'); END;").unwrap(),
            "EXPIRED" => { connection.execute("UPDATE leases SET expires = 1", []).unwrap(); }
            "OWNERSHIP" => owned.archive_id = [99; 32],
            _ => unreachable!(),
        }
        drop(connection);
        let (error, diagnostic) = failure(&fixture, owned, StorageOperation::Finalize).await;
        assert!(matches!(error, WireError::Store));
        assert_eq!(
            diagnostic.event_code(),
            format!("CONTENT_PROVIDER_STORAGE_V1_FINALIZE__BACKEND__{category}")
        );
        assert!(!format!("{diagnostic:?}").contains("canary"));
        assert_eq!(fixture.usage(), before);
    }
}

#[tokio::test]
async fn busy_disk_slot_keeps_verified_operation_and_original_accounting() {
    let fixture = Fixture::new();
    let owned = seed(&fixture, false).await;
    let before = fixture.usage();
    let permit = Arc::clone(&fixture.service.as_ref().unwrap().disk_slot)
        .try_acquire_owned()
        .unwrap();
    let (error, diagnostic) = failure(&fixture, owned, StorageOperation::Finalize).await;
    assert!(matches!(error, WireError::Busy));
    assert_eq!(
        diagnostic.event_code(),
        "CONTENT_PROVIDER_STORAGE_V1_FINALIZE__DISK_ADMISSION__BUSY"
    );
    assert_eq!(fixture.usage(), before);
    drop(permit);
    fixture
        .exchange(owned, StorageOperation::Finalize, &[])
        .await
        .unwrap();
}

#[tokio::test]
async fn unverified_request_never_exports_its_claimed_operation() {
    let fixture = Fixture::new();
    let (mut client, task, challenge) = session(&fixture, Arc::new(AtomicBool::new(false))).await;
    let mut encoded = fixture
        .request(
            &challenge,
            target(BYTES),
            StorageOperation::Reserve {
                expires_at: unix_now().unwrap() + 600,
            },
        )
        .encode();
    *encoded.last_mut().unwrap() ^= 1;
    write_frame(&mut client, &encoded).await.unwrap();
    drop(client);
    let (result, diagnostic) = timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(result, Err(WireError::Protocol(_))));
    assert!(
        diagnostic
            .unwrap()
            .event_code()
            .starts_with("CONTENT_PROVIDER_STORAGE_V1_UNKNOWN__REQUEST__")
    );
    assert_eq!(fixture.usage().leases, 0);
}

#[tokio::test]
async fn selector_keeps_historical_protocol_error_and_closed_storage_tuple() {
    let fixture = Fixture::new();
    let owned = seed(&fixture, true).await;
    let mut registry = PublicationRegistry::new();
    registry.set_private_storage(Arc::clone(fixture.service.as_ref().unwrap()));
    let (mut client, mut server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        let mut diagnostic = None;
        let result = crate::provider::serve_publication_observed(
            &mut server,
            &registry,
            TransferLimits::default(),
            &mut diagnostic,
        )
        .await;
        (result, diagnostic)
    });
    let challenge = begin(&mut client, &fixture.grant).await.unwrap();
    let signed = fixture.request(&challenge, owned, StorageOperation::Finalize);
    assert!(
        finish(&mut client, &fixture.grant, &challenge, &signed, &[])
            .await
            .is_err()
    );
    drop(client);
    let (result, diagnostic) = timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        result,
        Err(crate::provider::ProviderError::Protocol)
    ));
    assert_eq!(
        diagnostic.unwrap().event_code(),
        "CONTENT_PROVIDER_STORAGE_V1_FINALIZE__BACKEND__INTEGRITY"
    );
    // A reused output cannot misattribute this failure to another selector/early refusal.
    let mut diagnostic = diagnostic;
    let (mut stream, _other) = tokio::io::duplex(4096);
    let result = crate::provider::serve_publication_observed(
        &mut stream,
        &PublicationRegistry::new(),
        TransferLimits {
            session_timeout: Duration::ZERO,
            ..TransferLimits::default()
        },
        &mut diagnostic,
    )
    .await;
    assert!(matches!(result, Err(crate::provider::ProviderError::Limit)));
    assert!(diagnostic.is_none());
}

#[tokio::test]
async fn outer_selector_deadline_preserves_the_actual_unverified_request_phase() {
    let fixture = Fixture::new();
    let mut registry = PublicationRegistry::new();
    registry.set_private_storage(Arc::clone(fixture.service.as_ref().unwrap()));
    let (mut client, mut server) = tokio::io::duplex(4096);
    let task = tokio::spawn(async move {
        let mut diagnostic = None;
        let result = crate::provider::serve_publication_observed(
            &mut server,
            &registry,
            TransferLimits {
                session_timeout: Duration::from_secs(1),
                ..TransferLimits::default()
            },
            &mut diagnostic,
        )
        .await;
        (result, diagnostic)
    });
    let _challenge = begin(&mut client, &fixture.grant).await.unwrap();
    // Keep the genuine challenge stream open but send no owner request. The selector's
    // existing outer deadline, not EOF or the wire's longer deadline, ends this exchange.
    let (result, diagnostic) = timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap();
    assert!(matches!(
        result,
        Err(crate::provider::ProviderError::Timeout)
    ));
    assert_eq!(
        diagnostic.unwrap().event_code(),
        "CONTENT_PROVIDER_STORAGE_V1_UNKNOWN__REQUEST__TIMEOUT"
    );
    drop(client);
    assert_eq!(fixture.usage().leases, 0);
}

#[tokio::test]
async fn cancelled_observed_exchange_cannot_release_its_blocking_disk_permit() {
    let fixture = Fixture::new();
    let owned = seed(&fixture, false).await;
    let service = fixture.service.as_ref().unwrap();
    let provider = Arc::clone(&service.provider);
    let disk_slot = Arc::clone(&service.disk_slot);
    let (locked_tx, locked_rx) = tokio::sync::oneshot::channel();
    let (release_tx, release_rx) = std::sync::mpsc::channel();
    let blocker = tokio::task::spawn_blocking(move || {
        let _lock = provider.lock().unwrap();
        locked_tx.send(()).unwrap();
        // The test-only owner holds the backend mutex, not the provider's disk permit.
        release_rx.recv().unwrap();
    });
    locked_rx.await.unwrap();
    let (mut client, task, challenge) = session(&fixture, Arc::new(AtomicBool::new(false))).await;
    let signed = fixture.request(&challenge, owned, StorageOperation::Finalize);
    write_frame(&mut client, &signed.encode()).await.unwrap();
    timeout(Duration::from_secs(5), async {
        while disk_slot.available_permits() != 0 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    task.abort();
    assert!(task.await.unwrap_err().is_cancelled());
    assert_eq!(disk_slot.available_permits(), 0);
    // No diagnostic or rollback is invented for the cancelled caller. The already owned
    // blocking operation can still complete, retaining the permit through its full commit.
    release_tx.send(()).unwrap();
    blocker.await.unwrap();
    timeout(Duration::from_secs(5), async {
        while disk_slot.available_permits() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .unwrap();
    drop(client);
    assert_eq!(fixture.usage().committed_bytes, BYTES.len() as u64);
    assert_eq!(fixture.usage().reserved_bytes, 0);
}
