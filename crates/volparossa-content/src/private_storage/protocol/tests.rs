use ed25519_dalek::SigningKey;
use prost::Message as _;

use super::*;
use crate::{
    CHUNK_BYTES, Validity,
    private_storage::{LeaseId, MAX_RANGE_BYTES},
};

const NOW: u64 = 1_800_000_000;

struct Fixture {
    provider: SigningKey,
    owner: SigningKey,
    grant: VerifiedStorageGrant,
}

impl Fixture {
    fn new(rights: StorageRights) -> Self {
        let provider = SigningKey::from_bytes(&[11; 32]);
        let owner = SigningKey::from_bytes(&[22; 32]);
        let grant = SignedStorageGrant::issue(
            &provider,
            &owner.verifying_key(),
            GrantLimits {
                max_payload_bytes: 1024 * 1024 * 1024,
                max_leases: 8,
                rights,
                max_retention_seconds: 3600,
            },
            Validity {
                created: NOW,
                expires: NOW + 7200,
            },
        )
        .unwrap()
        .verify(&provider.verifying_key(), NOW)
        .unwrap();
        Self {
            provider,
            owner,
            grant,
        }
    }

    fn challenge(&self) -> StorageChallenge {
        StorageChallenge::issue(&self.provider, &self.grant, validity()).unwrap()
    }

    fn request(&self, operation: StorageOperation) -> VerifiedStorageRequest {
        let mut target = target();
        if matches!(operation, StorageOperation::Reserve { .. }) {
            target.lease_id = None;
        }
        let challenge = self.challenge();
        let signed = SignedStorageRequest::sign(
            &self.owner,
            &self.grant,
            &challenge,
            target,
            operation,
            validity(),
        )
        .unwrap();
        SignedStorageRequest::decode_and_verify(&signed.encode(), &self.grant, &challenge, NOW)
            .unwrap()
    }
}

fn validity() -> Validity {
    Validity {
        created: NOW,
        expires: NOW + 60,
    }
}

fn target() -> StorageTarget {
    StorageTarget {
        archive_id: [31; 32],
        lease_id: Some(LeaseId::from_bytes([41; 16])),
        ciphertext_bytes: CHUNK_BYTES as u64 + 31,
        sha256: [51; 32],
    }
}

#[test]
fn private_storage_protocol_provider_not_owner_authorizes_bounded_grants() {
    let fixture = Fixture::new(StorageRights::ALL);
    let encoded = fixture.grant.signed().encode();
    let decoded = SignedStorageGrant::decode(&encoded).unwrap();
    assert!(matches!(
        decoded.verify(&fixture.owner.verifying_key(), NOW),
        Err(ProtocolError::Unauthorized)
    ));
    assert!(matches!(
        decoded.verify(&fixture.provider.verifying_key(), NOW + 7200),
        Err(ProtocolError::Expired)
    ));
    let verified = decoded
        .verify(&fixture.provider.verifying_key(), NOW)
        .unwrap();
    assert_eq!(verified.owner_key(), &fixture.owner.verifying_key());
    assert_eq!(verified.limits().max_payload_bytes, 1024 * 1024 * 1024);
    assert_ne!(
        fixture.grant.capability_id(),
        Fixture::new(StorageRights::ALL).grant.capability_id()
    );
    assert!(StorageChallenge::issue(&fixture.owner, &fixture.grant, validity()).is_err());

    let fake_provider_grant = SignedStorageGrant::issue(
        &fixture.owner,
        &fixture.owner.verifying_key(),
        fixture.grant.limits(),
        fixture.grant.validity(),
    )
    .unwrap();
    assert!(matches!(
        fake_provider_grant.verify(&fixture.provider.verifying_key(), NOW),
        Err(ProtocolError::Unauthorized)
    ));

    // Canonical protobuf rejects unknown fields rather than dropping signed metadata.
    let mut unknown = encoded.clone();
    unknown.extend_from_slice(&[0x18, 1]);
    assert!(matches!(
        SignedStorageGrant::decode(&unknown),
        Err(ProtocolError::Invalid)
    ));
    let mut forged: envelope::Envelope = envelope::decode(&encoded, MAX_GRANT_BYTES).unwrap();
    forged.signature[0] ^= 1;
    assert!(matches!(
        SignedStorageGrant::decode(&forged.encode_to_vec())
            .unwrap()
            .verify(&fixture.provider.verifying_key(), NOW),
        Err(ProtocolError::Unauthorized)
    ));
    assert!(SignedStorageGrant::decode(&vec![0; MAX_GRANT_BYTES + 1]).is_err());
    assert!(StorageRights::from_bits(0).is_err());
    assert!(StorageRights::from_bits(1 << 7).is_err());
}

#[test]
fn private_storage_protocol_exact_fresh_challenge_owner_and_rights_are_required() {
    let fixture = Fixture::new(StorageRights::PROGRESS.union(StorageRights::READ_RANGE));
    let challenge = fixture.challenge();
    let received =
        StorageChallenge::decode_and_verify(&challenge.encode(), &fixture.grant, NOW).unwrap();
    assert_eq!(received.validity(), validity());
    let signed = SignedStorageRequest::sign(
        &fixture.owner,
        &fixture.grant,
        &received,
        target(),
        StorageOperation::Progress,
        validity(),
    )
    .unwrap();
    let verified = signed.verify(&fixture.grant, &challenge, NOW).unwrap();
    assert_eq!(verified.target(), target());
    assert_eq!(verified.challenge_id(), &challenge.id());
    assert!(matches!(
        signed.verify(&fixture.grant, &fixture.challenge(), NOW),
        Err(ProtocolError::Unauthorized)
    ));
    assert!(matches!(
        signed.verify(&fixture.grant, &challenge, NOW + 60),
        Err(ProtocolError::Expired)
    ));
    assert!(verified.current(NOW + 60).is_err());
    assert!(
        SignedStorageRequest::sign(
            &fixture.provider,
            &fixture.grant,
            &challenge,
            target(),
            StorageOperation::Progress,
            validity()
        )
        .is_err()
    );
    assert!(
        SignedStorageRequest::sign(
            &fixture.owner,
            &fixture.grant,
            &challenge,
            target(),
            StorageOperation::Delete,
            validity()
        )
        .is_err()
    );
    let other_grant = Fixture::new(StorageRights::ALL).grant;
    assert!(StorageChallenge::decode_and_verify(&challenge.encode(), &other_grant, NOW).is_err());
    assert!(
        SignedStorageRequest::sign(
            &fixture.owner,
            &fixture.grant,
            &challenge,
            target(),
            StorageOperation::Progress,
            Validity {
                created: NOW,
                expires: NOW + 61
            }
        )
        .is_err()
    );

    // Even changing a canonical nonce with an otherwise identical scope invalidates the
    // original owner signature; no TLS identity is accepted as a substitute for it.
    let mut changed: envelope::Envelope =
        envelope::decode(&signed.encode(), MAX_REQUEST_BYTES).unwrap();
    changed.body.as_mut().unwrap().nonce[0] ^= 1;
    assert!(matches!(
        SignedStorageRequest::decode_and_verify(
            &changed.encode_to_vec(),
            &fixture.grant,
            &challenge,
            NOW
        ),
        Err(ProtocolError::Unauthorized)
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "One matrix binds all seven operation results to their exact requests"
)]
fn private_storage_protocol_all_operations_and_receipts_keep_exact_request_scope() {
    let fixture = Fixture::new(StorageRights::ALL);
    let operations = [
        (
            StorageOperation::Reserve {
                expires_at: NOW + 600,
            },
            ReceiptState::Reserved,
            0,
            NOW + 600,
            None,
        ),
        (
            StorageOperation::Append {
                offset: 0,
                length: u32::try_from(CHUNK_BYTES).unwrap(),
                sha256: [61; 32],
            },
            ReceiptState::Partial,
            CHUNK_BYTES as u64,
            NOW + 600,
            None,
        ),
        (
            StorageOperation::Progress,
            ReceiptState::Partial,
            CHUNK_BYTES as u64,
            NOW + 600,
            None,
        ),
        (
            StorageOperation::Finalize,
            ReceiptState::Committed,
            target().ciphertext_bytes,
            NOW + 600,
            None,
        ),
        (
            StorageOperation::ReadRange {
                offset: 0,
                length: target().ciphertext_bytes,
            },
            ReceiptState::Committed,
            target().ciphertext_bytes,
            NOW + 600,
            Some([71; 32]),
        ),
        (
            StorageOperation::Renew {
                expires_at: NOW + 1200,
            },
            ReceiptState::Renewed,
            target().ciphertext_bytes,
            NOW + 1200,
            None,
        ),
        (StorageOperation::Delete, ReceiptState::Deleted, 0, 0, None),
    ];
    for (operation, state, stored_bytes, expires_at, range_sha256) in operations {
        let request = fixture.request(operation);
        assert_eq!(request.operation(), operation);
        let result = ReceiptResult {
            state,
            lease_id: target().lease_id.unwrap(),
            stored_bytes,
            expires_at,
            range_sha256,
        };
        let receipt =
            SignedStorageReceipt::sign(&fixture.provider, &request, result, validity()).unwrap();
        assert_eq!(
            SignedStorageReceipt::decode_and_verify(&receipt.encode(), &request, NOW)
                .unwrap()
                .result(),
            result
        );
        // A separately signed retry requires its own receipt even when the operation is
        // idempotent at the storage layer and its immutable archive identity is unchanged.
        let retry = fixture.request(operation);
        assert!(matches!(
            SignedStorageReceipt::decode_and_verify(&receipt.encode(), &retry, NOW),
            Err(ProtocolError::Unauthorized)
        ));
        assert!(SignedStorageReceipt::sign(&fixture.owner, &request, result, validity()).is_err());
        if request.target().lease_id.is_some() {
            let changed_lease = ReceiptResult {
                lease_id: LeaseId::from_bytes([99; 16]),
                ..result
            };
            assert!(
                SignedStorageReceipt::sign(&fixture.provider, &request, changed_lease, validity())
                    .is_err()
            );
        }
    }
    let read = fixture.request(StorageOperation::ReadRange {
        offset: 0,
        length: target().ciphertext_bytes,
    });
    let no_hash = ReceiptResult {
        state: ReceiptState::Committed,
        lease_id: target().lease_id.unwrap(),
        stored_bytes: target().ciphertext_bytes,
        expires_at: NOW + 600,
        range_sha256: None,
    };
    assert!(SignedStorageReceipt::sign(&fixture.provider, &read, no_hash, validity()).is_err());
    let delete = fixture.request(StorageOperation::Delete);
    assert!(SignedStorageReceipt::sign(&fixture.provider, &delete, no_hash, validity()).is_err());
}

#[test]
fn private_storage_protocol_rejects_oversized_or_ambiguous_chunks_ranges_and_retention() {
    let fixture = Fixture::new(StorageRights::ALL);
    let challenge = fixture.challenge();
    let invalid = [
        StorageOperation::Append {
            offset: 1,
            length: 1,
            sha256: [2; 32],
        },
        StorageOperation::Append {
            offset: 0,
            length: u32::try_from(CHUNK_BYTES + 1).unwrap(),
            sha256: [2; 32],
        },
        StorageOperation::Append {
            offset: CHUNK_BYTES as u64,
            length: 32,
            sha256: [2; 32],
        },
        StorageOperation::ReadRange {
            offset: 1,
            length: 31,
        },
        StorageOperation::ReadRange {
            offset: 0,
            length: 1,
        },
        StorageOperation::ReadRange {
            offset: 0,
            length: 0,
        },
        StorageOperation::ReadRange {
            offset: 0,
            length: MAX_RANGE_BYTES + 1,
        },
        StorageOperation::ReadRange {
            offset: u64::MAX,
            length: 1,
        },
        StorageOperation::Renew { expires_at: NOW },
        StorageOperation::Renew {
            expires_at: NOW + 3601,
        },
    ];
    for operation in invalid {
        assert!(
            SignedStorageRequest::sign(
                &fixture.owner,
                &fixture.grant,
                &challenge,
                target(),
                operation,
                validity()
            )
            .is_err()
        );
    }
    fixture.request(StorageOperation::Append {
        offset: CHUNK_BYTES as u64,
        length: 31,
        sha256: [2; 32],
    });
    fixture.request(StorageOperation::ReadRange {
        offset: CHUNK_BYTES as u64,
        length: 31,
    });
    let oversized = StorageTarget {
        ciphertext_bytes: fixture.grant.limits().max_payload_bytes + 1,
        ..target()
    };
    assert!(
        SignedStorageRequest::sign(
            &fixture.owner,
            &fixture.grant,
            &challenge,
            oversized,
            StorageOperation::Progress,
            validity()
        )
        .is_err()
    );
    let missing_lease = StorageTarget {
        lease_id: None,
        ..target()
    };
    assert!(
        SignedStorageRequest::sign(
            &fixture.owner,
            &fixture.grant,
            &challenge,
            missing_lease,
            StorageOperation::Progress,
            validity()
        )
        .is_err()
    );
}
