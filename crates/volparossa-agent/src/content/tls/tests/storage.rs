//! Signed custody over genuine nested TLS and the production bounded proxy.
//! In-memory transports are not proof of MPTCP, relays, or the Cloud application.

mod challenge;
mod kernel;

use super::*;
use sha2::{Digest as _, Sha256};
use tokio::sync::{Barrier, oneshot};
use volparossa_content::{
    CHUNK_BYTES,
    private_storage::{
        PrivateStorageStore, StorageLimits,
        protocol::{
            GrantLimits, ReceiptState, SignedStorageGrant, SignedStorageRequest, StorageOperation,
            StorageRights, StorageTarget, VerifiedStorageGrant,
        },
        provider::PrivateStorageProvider,
        wire::{self, StorageService, StorageTransfer},
    },
};

struct Fixture {
    _temporary: tempfile::TempDir,
    owner: SigningKey,
    grant: VerifiedStorageGrant,
    registry: PublicationRegistry,
    provider_peer: PeerId,
    provider_offer: VerifiedProviderOffer,
    provider_tls: ContentTlsServer,
    exit_peer: PeerId,
    exit_offer: VerifiedProviderOffer,
    exit_tls: ContentTlsServer,
}

impl Fixture {
    fn new() -> Self {
        let provider = identity::Keypair::generate_ed25519();
        let pair = provider.clone().try_into_ed25519().unwrap();
        let bytes = Zeroizing::new(pair.to_bytes());
        let signer = Arc::new(SigningKey::from_keypair_bytes(&bytes).unwrap());
        let owner = SigningKey::from_bytes(&[22; 32]);
        let now = crate::content::now();
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
        let temporary = tempfile::tempdir().unwrap();
        let store = PrivateStorageStore::create(
            &temporary.path().join("private"),
            StorageLimits {
                capacity_bytes: 4 * CHUNK_BYTES as u64,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let storage = PrivateStorageProvider::new(store, signer.verifying_key()).unwrap();
        let mut registry = PublicationRegistry::new();
        registry.set_private_storage(Arc::new(StorageService::new(signer, storage)));
        let exit = identity::Keypair::generate_ed25519();
        Self {
            _temporary: temporary,
            owner,
            grant,
            registry,
            provider_peer: provider.public().to_peer_id(),
            provider_offer: offer(&provider, HOSTNAME),
            provider_tls: ContentTlsServer::new(&provider, HOSTNAME).unwrap(),
            exit_peer: exit.public().to_peer_id(),
            exit_offer: offer(&exit, HOSTNAME),
            exit_tls: ContentTlsServer::new(&exit, HOSTNAME).unwrap(),
        }
    }

    async fn exchange(
        &self,
        target: StorageTarget,
        operation: StorageOperation,
        payload: &[u8],
    ) -> StorageTransfer {
        // Each operation uses a fresh authenticated session and provider challenge.
        // Small transports force backpressure beneath both real TLS layers.
        let (client, observed) = duplex(4096);
        let (mut forwarded, server) = duplex(4096);
        let (mut owner, mut agent) = duplex(4096);
        let (challenge_sender, challenge_receiver) = oneshot::channel();
        let receipt_before_close = Barrier::new(3);
        let (received, bridged, (), ()) = Box::pin(timeout(Duration::from_secs(10), async {
            tokio::join!(
                async {
                    // Only fixture coordination carries the original challenge here;
                    // signed metadata, payload and receipt use the actual local wire.
                    let challenge = challenge_receiver.await.unwrap();
                    let now = crate::content::now();
                    let signed = SignedStorageRequest::sign(
                        &self.owner,
                        &self.grant,
                        &challenge,
                        target,
                        operation,
                        Validity {
                            created: now,
                            expires: (now + 60).min(challenge.validity().expires),
                        },
                    )
                    .unwrap();
                    let received =
                        wire::finish(&mut owner, &self.grant, &challenge, &signed, payload)
                            .await
                            .unwrap();
                    // finish has verified the signed, exact-request-bound receipt.
                    receipt_before_close.wait().await;
                    received
                },
                async {
                    let mut outer = connect(client, self.exit_peer, &self.exit_offer)
                        .await
                        .unwrap();
                    let mut inner = connect(&mut outer, self.provider_peer, &self.provider_offer)
                        .await
                        .unwrap();
                    let challenge = wire::begin(&mut inner, &self.grant).await.unwrap();
                    challenge_sender.send(challenge.clone()).unwrap();
                    let bridged = wire::bridge(&mut agent, &mut inner, &self.grant, &challenge)
                        .await
                        .unwrap();
                    // No extra application write, TLS close, or EOF may induce a receipt.
                    receipt_before_close.wait().await;
                    finish(&mut inner).await.unwrap();
                    drop(inner);
                    finish(&mut outer).await.unwrap();
                    bridged
                },
                async {
                    let mut stream = self.provider_tls.accept(server).await.unwrap();
                    serve_publication(&mut stream, &self.registry, TransferLimits::default())
                        .await
                        .unwrap();
                    receipt_before_close.wait().await;
                    finish(&mut stream).await.unwrap();
                },
                async {
                    let mut observed = self.exit_tls.accept(observed).await.unwrap();
                    forward(&mut observed, &mut forwarded).await;
                },
            )
        }))
        .await
        .expect("signed storage receipt must arrive before shutdown, within 10 seconds");
        assert_eq!(received.receipt.encode(), bridged.receipt.encode());
        assert_eq!(received.ciphertext.len() as u64, bridged.ciphertext_bytes);
        received
    }
}

async fn forward<S, D>(observed: &mut S, forwarded: &mut D)
where
    S: AsyncRead + AsyncWrite + Unpin,
    D: AsyncRead + AsyncWrite + Unpin,
{
    // Match the existing nested-TLS fixture: inspect the actual inner ClientHello
    // before the production bidirectional proxy forwards encrypted provider traffic.
    let mut record = [0_u8; 5];
    observed.read_exact(&mut record).await.unwrap();
    assert_eq!(record[0], 0x16);
    let length = usize::from(u16::from_be_bytes([record[3], record[4]]));
    assert!(length <= 16 * 1024);
    let mut hello = vec![0; length + record.len()];
    hello[..5].copy_from_slice(&record);
    observed.read_exact(&mut hello[5..]).await.unwrap();
    volparossa_exit::inspect_tls_client_hello(&hello, HOSTNAME).unwrap();
    forwarded.write_all(&hello).await.unwrap();
    let statistics = volparossa_tcp_proxy::proxy_bidirectional(
        observed,
        forwarded,
        volparossa_tcp_proxy::StreamTransferLimits::new(
            64 * 1024,
            1024 * 1024,
            1024 * 1024,
            Duration::from_secs(10),
        )
        .unwrap(),
    )
    .await
    .unwrap();
    assert!(statistics.client_to_exit_bytes > 0);
    assert!(statistics.exit_to_client_bytes > 0);
}

#[tokio::test]
async fn signed_append_receipts_cross_nested_tls_without_extra_write_or_eof() {
    let fixture = Fixture::new();
    let bytes = vec![0xb6; CHUNK_BYTES + 57];
    let original = StorageTarget {
        archive_id: [31; 32],
        lease_id: None,
        ciphertext_bytes: bytes.len() as u64,
        sha256: Sha256::digest(&bytes).into(),
    };
    let reserved = fixture
        .exchange(
            original,
            StorageOperation::Reserve {
                expires_at: crate::content::now() + 600,
            },
            &[],
        )
        .await;
    assert_eq!(reserved.receipt.result().state, ReceiptState::Reserved);
    let owned = StorageTarget {
        lease_id: Some(reserved.receipt.result().lease_id),
        ..original
    };
    for (ordinal, chunk) in bytes.chunks(CHUNK_BYTES).enumerate() {
        let offset = (ordinal * CHUNK_BYTES) as u64;
        let appended = fixture
            .exchange(
                owned,
                StorageOperation::Append {
                    offset,
                    length: u32::try_from(chunk.len()).unwrap(),
                    sha256: Sha256::digest(chunk).into(),
                },
                chunk,
            )
            .await;
        assert_eq!(
            appended.receipt.result().stored_bytes,
            offset + chunk.len() as u64
        );
        assert!(appended.ciphertext.is_empty());
    }
    let finalized = fixture
        .exchange(owned, StorageOperation::Finalize, &[])
        .await;
    assert_eq!(finalized.receipt.result().state, ReceiptState::Committed);
    let restored = fixture
        .exchange(
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
