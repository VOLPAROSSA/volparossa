//! Real framed duplex streams and `SQLite` custody, not a network/privacy acceptance proof.

use ed25519_dalek::Signer as _;
use tokio::{io::DuplexStream, task::JoinHandle};

use super::*;
use crate::{
    private_storage::{
        PrivateStorageStore, StorageLimits, StorageUsage,
        protocol::{GrantLimits, ReceiptState, StorageRights, StorageTarget},
    },
    provider::{PublicationRegistry, serve_publication},
    transfer::{TransferLimits, TransferProgress},
};

type Server = JoinHandle<Result<TransferProgress, crate::provider::ProviderError>>;

struct Fixture {
    temporary: tempfile::TempDir,
    signer: Arc<SigningKey>,
    owner: SigningKey,
    grant: VerifiedStorageGrant,
    service: Option<Arc<StorageService>>,
}

impl Fixture {
    fn new() -> Self {
        let temporary = tempfile::tempdir().unwrap();
        let signer = Arc::new(SigningKey::from_bytes(&[11; 32]));
        let owner = SigningKey::from_bytes(&[22; 32]);
        let now = unix_now().unwrap();
        let grant = SignedStorageGrant::issue(
            &signer,
            &owner.verifying_key(),
            GrantLimits {
                max_payload_bytes: 4 * CHUNK_BYTES as u64,
                max_leases: 4,
                rights: StorageRights::ALL,
                max_retention_seconds: 1800,
            },
            Validity {
                created: now,
                expires: now + 3600,
            },
        )
        .unwrap()
        .verify(&signer.verifying_key(), now)
        .unwrap();
        let store = PrivateStorageStore::create(
            &temporary.path().join("private"),
            StorageLimits {
                capacity_bytes: 4 * CHUNK_BYTES as u64,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let provider = PrivateStorageProvider::new(store, signer.verifying_key()).unwrap();
        let service = Some(Arc::new(StorageService::new(Arc::clone(&signer), provider)));
        Self {
            temporary,
            signer,
            owner,
            grant,
            service,
        }
    }

    fn reopen(&mut self) {
        let service = self.service.take().unwrap();
        assert_eq!(
            Arc::strong_count(&service),
            1,
            "all exchanges must finish before reopen"
        );
        drop(service);
        let store =
            PrivateStorageStore::open_existing(&self.temporary.path().join("private")).unwrap();
        let provider = PrivateStorageProvider::new(store, self.signer.verifying_key()).unwrap();
        self.service = Some(Arc::new(StorageService::new(
            Arc::clone(&self.signer),
            provider,
        )));
    }

    fn usage(&self) -> StorageUsage {
        self.service
            .as_ref()
            .unwrap()
            .provider
            .lock()
            .unwrap()
            .usage()
            .unwrap()
    }

    fn stream(&self) -> (DuplexStream, Server) {
        let mut registry = PublicationRegistry::new();
        registry.set_private_storage(Arc::clone(self.service.as_ref().unwrap()));
        let (client, mut server) = tokio::io::duplex(4096);
        let task = tokio::spawn(async move {
            serve_publication(&mut server, &registry, TransferLimits::default()).await
        });
        (client, task)
    }

    async fn session(&self) -> (DuplexStream, Server, StorageChallenge) {
        let (mut client, server) = self.stream();
        let challenge = begin(&mut client, &self.grant).await.unwrap();
        (client, server, challenge)
    }

    fn request(
        &self,
        challenge: &StorageChallenge,
        target: StorageTarget,
        operation: StorageOperation,
    ) -> SignedStorageRequest {
        let now = unix_now().unwrap();
        SignedStorageRequest::sign(
            &self.owner,
            &self.grant,
            challenge,
            target,
            operation,
            Validity {
                created: now,
                expires: (now + 60).min(challenge.validity().expires),
            },
        )
        .unwrap()
    }

    async fn exchange(
        &self,
        target: StorageTarget,
        operation: StorageOperation,
        payload: &[u8],
    ) -> Result<StorageTransfer, WireError> {
        let (mut client, server, challenge) = self.session().await;
        let request = self.request(&challenge, target, operation);
        let result = finish(&mut client, &self.grant, &challenge, &request, payload).await;
        drop(client);
        let outcome = timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(outcome.is_ok(), result.is_ok());
        result
    }

    async fn bridged(
        &self,
        target: StorageTarget,
        operation: StorageOperation,
        payload: &[u8],
    ) -> StorageTransfer {
        let (mut remote, server, challenge) = self.session().await;
        let (mut owner, mut agent) = tokio::io::duplex(4096);
        let signed = self.request(&challenge, target, operation);
        let (received, forwarded) = tokio::join!(
            finish(&mut owner, &self.grant, &challenge, &signed, payload),
            bridge(&mut agent, &mut remote, &self.grant, &challenge),
        );
        let received = received.unwrap();
        let forwarded = forwarded.unwrap();
        assert_eq!(forwarded.receipt.encode(), received.receipt.encode());
        assert_eq!(forwarded.ciphertext_bytes, received.ciphertext.len() as u64);
        drop(remote);
        timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        received
    }
}

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn target(bytes: &[u8]) -> StorageTarget {
    StorageTarget {
        archive_id: [31; 32],
        lease_id: None,
        ciphertext_bytes: bytes.len() as u64,
        sha256: hash(bytes),
    }
}

fn append(offset: u64, bytes: &[u8]) -> StorageOperation {
    StorageOperation::Append {
        offset,
        length: u32::try_from(bytes.len()).unwrap(),
        sha256: hash(bytes),
    }
}

async fn denied(server: Server) {
    // No body needs to arrive after an oversized header, and no failure needs a 120s timeout.
    assert!(
        timeout(Duration::from_secs(5), server)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
}

#[tokio::test]
async fn owner_signed_bridge_transfers_real_custody_and_unchanged_receipts() {
    let fixture = Fixture::new();
    let bytes = vec![0xb6; CHUNK_BYTES + 57];
    let original = target(&bytes);
    let reserved = fixture
        .bridged(
            original,
            StorageOperation::Reserve {
                expires_at: unix_now().unwrap() + 600,
            },
            &[],
        )
        .await;
    let owned = StorageTarget {
        lease_id: Some(reserved.receipt.result().lease_id),
        ..original
    };
    for (ordinal, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
        fixture
            .bridged(owned, append((ordinal * CHUNK_BYTES) as u64, chunk), chunk)
            .await;
    }
    fixture
        .bridged(owned, StorageOperation::Finalize, &[])
        .await;
    for _ in 0..2 {
        let restored = fixture
            .bridged(
                owned,
                StorageOperation::ReadRange {
                    offset: 0,
                    length: bytes.len() as u64,
                },
                &[],
            )
            .await;
        assert_eq!(restored.ciphertext, bytes);
    }
    assert_eq!(fixture.usage().committed_bytes, bytes.len() as u64);
}

#[tokio::test]
async fn bridge_rejects_an_owner_request_from_another_connection_before_custody() {
    let fixture = Fixture::new();
    let (old_stream, old_server, old_challenge) = fixture.session().await;
    let signed = fixture.request(
        &old_challenge,
        target(b"opaque"),
        StorageOperation::Reserve {
            expires_at: unix_now().unwrap() + 600,
        },
    );
    drop(old_stream);
    denied(old_server).await;
    let (mut remote, server, challenge) = fixture.session().await;
    let (mut owner, mut agent) = tokio::io::duplex(4096);
    write_frame(&mut owner, &signed.encode()).await.unwrap();
    assert!(matches!(
        bridge(&mut agent, &mut remote, &fixture.grant, &challenge).await,
        Err(WireError::Protocol(_))
    ));
    drop(remote);
    denied(server).await;
    assert_eq!(fixture.usage().leases, 0);
}

#[tokio::test]
#[allow(clippy::too_many_lines, reason = "One full real persisted lifecycle")]
async fn framed_storage_lifecycle_restores_twice_without_consuming_the_copy() {
    let fixture = Fixture::new();
    let bytes = vec![0xa5; 2 * CHUNK_BYTES + 73];
    let original = target(&bytes);
    let expires_at = unix_now().unwrap() + 600;
    let reserved = fixture
        .exchange(original, StorageOperation::Reserve { expires_at }, &[])
        .await
        .unwrap();
    let lease = reserved.receipt.result().lease_id;
    assert_eq!(reserved.receipt.result().state, ReceiptState::Reserved);
    let owned = StorageTarget {
        lease_id: Some(lease),
        ..original
    };
    let retry = fixture
        .exchange(original, StorageOperation::Reserve { expires_at }, &[])
        .await
        .unwrap();
    assert_eq!(retry.receipt.result().lease_id, lease);
    assert_eq!(
        fixture.usage(),
        StorageUsage {
            reserved_bytes: original.ciphertext_bytes,
            committed_bytes: 0,
            leases: 1,
        }
    );
    for (ordinal, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
        let response = fixture
            .exchange(owned, append((ordinal * CHUNK_BYTES) as u64, chunk), chunk)
            .await
            .unwrap();
        assert_eq!(response.receipt.result().state, ReceiptState::Partial);
        assert_eq!(
            response.receipt.result().stored_bytes,
            ((ordinal * CHUNK_BYTES) + chunk.len()) as u64
        );
    }
    let progress = fixture
        .exchange(owned, StorageOperation::Progress, &[])
        .await
        .unwrap();
    assert_eq!(
        progress.receipt.result().stored_bytes,
        original.ciphertext_bytes
    );
    assert_eq!(progress.receipt.result().state, ReceiptState::Partial);
    let finalized = fixture
        .exchange(owned, StorageOperation::Finalize, &[])
        .await
        .unwrap();
    assert_eq!(finalized.receipt.result().state, ReceiptState::Committed);
    let extended = expires_at + 300;
    let renewed = fixture
        .exchange(
            owned,
            StorageOperation::Renew {
                expires_at: extended,
            },
            &[],
        )
        .await
        .unwrap();
    assert_eq!(renewed.receipt.result().state, ReceiptState::Renewed);
    assert_eq!(renewed.receipt.result().expires_at, extended);
    let committed = fixture.usage();
    assert_eq!(
        committed,
        StorageUsage {
            reserved_bytes: 0,
            committed_bytes: original.ciphertext_bytes,
            leases: 1,
        }
    );
    for _ in 0..2 {
        let mut restored = Vec::new();
        for (offset, length) in [(0, 2 * CHUNK_BYTES as u64), (2 * CHUNK_BYTES as u64, 73)] {
            let response = fixture
                .exchange(owned, StorageOperation::ReadRange { offset, length }, &[])
                .await
                .unwrap();
            assert_eq!(response.receipt.result().expires_at, extended);
            assert_eq!(
                response.receipt.result().range_sha256,
                Some(hash(&response.ciphertext))
            );
            restored.extend_from_slice(&response.ciphertext);
        }
        assert_eq!(restored, bytes);
        assert_eq!(hash(&restored), original.sha256);
        assert_eq!(
            fixture.usage(),
            committed,
            "a successful restore must not release custody"
        );
    }
    for _ in 0..2 {
        let deleted = fixture
            .exchange(owned, StorageOperation::Delete, &[])
            .await
            .unwrap();
        assert_eq!(deleted.receipt.result().state, ReceiptState::Deleted);
        assert_eq!(deleted.receipt.result().lease_id, lease);
        assert_eq!(
            fixture.usage(),
            StorageUsage {
                reserved_bytes: 0,
                committed_bytes: 0,
                leases: 0
            }
        );
    }
    assert!(
        fixture
            .exchange(
                owned,
                StorageOperation::ReadRange {
                    offset: 0,
                    length: CHUNK_BYTES as u64
                },
                &[]
            )
            .await
            .is_err()
    );
    assert!(
        fixture
            .exchange(original, StorageOperation::Reserve { expires_at }, &[])
            .await
            .is_err()
    );
}

#[tokio::test]
async fn partial_upload_reopens_and_resumes_only_with_a_fresh_connection_challenge() {
    let mut fixture = Fixture::new();
    let bytes = vec![0x6d; CHUNK_BYTES + 19];
    let original = target(&bytes);
    let reserve = StorageOperation::Reserve {
        expires_at: unix_now().unwrap() + 600,
    };
    let lease = fixture
        .exchange(original, reserve, &[])
        .await
        .unwrap()
        .receipt
        .result()
        .lease_id;
    let owned = StorageTarget {
        lease_id: Some(lease),
        ..original
    };
    let first = &bytes[..CHUNK_BYTES];
    fixture
        .exchange(owned, append(0, first), first)
        .await
        .unwrap();
    let charged = fixture.usage();
    assert!(
        fixture
            .exchange(
                owned,
                StorageOperation::ReadRange {
                    offset: 0,
                    length: CHUNK_BYTES as u64
                },
                &[]
            )
            .await
            .is_err()
    );
    assert!(
        fixture
            .exchange(owned, StorageOperation::Finalize, &[])
            .await
            .is_err()
    );

    let (old_stream, old_server, old_challenge) = fixture.session().await;
    let old_request = fixture.request(&old_challenge, owned, StorageOperation::Progress);
    drop(old_stream);
    denied(old_server).await;
    fixture.reopen();
    assert_eq!(fixture.usage(), charged);
    let (mut new_stream, new_server, new_challenge) = fixture.session().await;
    assert_ne!(old_challenge.id(), new_challenge.id());
    write_frame(&mut new_stream, &old_request.encode())
        .await
        .unwrap();
    denied(new_server).await;
    drop(new_stream);
    assert_eq!(fixture.usage(), charged);

    let progress = fixture
        .exchange(owned, StorageOperation::Progress, &[])
        .await
        .unwrap();
    assert_eq!(progress.receipt.result().state, ReceiptState::Partial);
    assert_eq!(progress.receipt.result().stored_bytes, CHUNK_BYTES as u64);
    let retry = fixture.exchange(original, reserve, &[]).await.unwrap();
    assert_eq!(retry.receipt.result().lease_id, lease);
    assert_eq!(retry.receipt.result().stored_bytes, CHUNK_BYTES as u64);
    fixture
        .exchange(owned, append(0, first), first)
        .await
        .unwrap();
    assert_eq!(
        fixture.usage(),
        charged,
        "retry must not reserve a second copy"
    );
    let tail = &bytes[CHUNK_BYTES..];
    fixture
        .exchange(owned, append(CHUNK_BYTES as u64, tail), tail)
        .await
        .unwrap();
    fixture
        .exchange(owned, StorageOperation::Finalize, &[])
        .await
        .unwrap();
    let restored = fixture
        .exchange(
            owned,
            StorageOperation::ReadRange {
                offset: 0,
                length: original.ciphertext_bytes,
            },
            &[],
        )
        .await
        .unwrap();
    assert_eq!(restored.ciphertext, bytes);
    assert_eq!(hash(&restored.ciphertext), original.sha256);
}

// Decode only the envelope's two length-delimited fields to simulate a hostile wire peer.
// The opaque body remains byte-for-byte identical; no production authorization is bypassed.
#[derive(Clone, PartialEq, Message)]
struct RawEnvelope {
    #[prost(bytes = "vec", tag = "1")]
    body: Vec<u8>,
    #[prost(bytes = "vec", tag = "2")]
    signature: Vec<u8>,
}

#[tokio::test]
async fn wrong_owner_and_changed_append_bytes_are_rejected_by_the_server_without_new_custody() {
    let fixture = Fixture::new();
    let bytes = b"opaque already encrypted archive bytes";
    let original = target(bytes);
    let reserve = StorageOperation::Reserve {
        expires_at: unix_now().unwrap() + 600,
    };
    let empty = fixture.usage();
    let (mut stream, server, challenge) = fixture.session().await;
    let request = fixture.request(&challenge, original, reserve);
    let encoded = request.encode();
    let mut hostile = RawEnvelope::decode(encoded.as_slice()).unwrap();
    assert_eq!(hostile.encode_to_vec(), encoded);
    let mut signing_bytes = b"VOLPAROSSA/private-storage/v1\0".to_vec();
    signing_bytes.extend_from_slice(&hostile.body);
    hostile.signature = SigningKey::from_bytes(&[99; 32])
        .sign(&signing_bytes)
        .to_bytes()
        .to_vec();
    write_frame(&mut stream, &hostile.encode_to_vec())
        .await
        .unwrap();
    denied(server).await;
    drop(stream);
    assert_eq!(fixture.usage(), empty);

    let lease = fixture
        .exchange(original, reserve, &[])
        .await
        .unwrap()
        .receipt
        .result()
        .lease_id;
    let owned = StorageTarget {
        lease_id: Some(lease),
        ..original
    };
    let charged = fixture.usage();
    let (mut stream, server, challenge) = fixture.session().await;
    let request = fixture.request(&challenge, owned, append(0, bytes));
    write_frame(&mut stream, &request.encode()).await.unwrap();
    let mut altered = bytes.to_vec();
    altered[0] ^= 1;
    write_frame(&mut stream, &altered).await.unwrap();
    denied(server).await;
    drop(stream);
    assert_eq!(fixture.usage(), charged);
    let progress = fixture
        .exchange(owned, StorageOperation::Progress, &[])
        .await
        .unwrap();
    assert_eq!(progress.receipt.result().stored_bytes, 0);
    assert_eq!(progress.receipt.result().state, ReceiptState::Reserved);
    fixture
        .exchange(owned, append(0, bytes), bytes)
        .await
        .unwrap();
    fixture
        .exchange(owned, StorageOperation::Finalize, &[])
        .await
        .unwrap();
}

#[tokio::test]
async fn oversized_frames_are_rejected_before_their_bodies_arrive() {
    let fixture = Fixture::new();
    let empty = fixture.usage();
    let (mut stream, server) = fixture.stream();
    write_frame(
        &mut stream,
        &Selector {
            version: SELECTOR_VERSION,
            manifest_id: Vec::new(),
            operation: SELECTOR_OPERATION,
        }
        .encode_to_vec(),
    )
    .await
    .unwrap();
    stream
        .write_u32(u32::try_from(MAX_GRANT_BYTES + 1).unwrap())
        .await
        .unwrap();
    denied(server).await;
    drop(stream);
    assert_eq!(fixture.usage(), empty);

    let (mut stream, server, _) = fixture.session().await;
    stream
        .write_u32(u32::try_from(MAX_REQUEST_BYTES + 1).unwrap())
        .await
        .unwrap();
    denied(server).await;
    drop(stream);
    assert_eq!(fixture.usage(), empty);

    let bytes = vec![0x41; CHUNK_BYTES];
    let original = target(&bytes);
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
    let charged = fixture.usage();
    let (mut stream, server, challenge) = fixture.session().await;
    let request = fixture.request(&challenge, owned, append(0, &bytes));
    write_frame(&mut stream, &request.encode()).await.unwrap();
    stream
        .write_u32(u32::try_from(CHUNK_BYTES + 1).unwrap())
        .await
        .unwrap();
    denied(server).await;
    drop(stream);
    assert_eq!(fixture.usage(), charged);
    let progress = fixture
        .exchange(owned, StorageOperation::Progress, &[])
        .await
        .unwrap();
    assert_eq!(progress.receipt.result().stored_bytes, 0);
}
