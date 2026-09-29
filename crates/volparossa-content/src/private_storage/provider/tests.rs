//! Real SQLite/ciphertext operations with real provider/owner signatures. These are local
//! backend tests, not evidence of an independent remote replica or global contribution credit.

use ed25519_dalek::SigningKey;

use super::*;
use crate::{
    Validity,
    private_storage::{
        StorageLimits,
        protocol::{
            GrantLimits, SignedStorageGrant, SignedStorageRequest, StorageChallenge, StorageRights,
        },
    },
};

const NOW: u64 = 1_800_000_000;

fn hash(bytes: &[u8]) -> [u8; 32] {
    Sha256::digest(bytes).into()
}

fn grant(
    provider: &SigningKey,
    owner: &SigningKey,
    bytes: u64,
    leases: u32,
) -> VerifiedStorageGrant {
    SignedStorageGrant::issue(
        provider,
        &owner.verifying_key(),
        GrantLimits {
            max_payload_bytes: bytes,
            max_leases: leases,
            rights: StorageRights::ALL,
            max_retention_seconds: 3600,
        },
        Validity {
            created: NOW,
            expires: NOW + 3600,
        },
    )
    .unwrap()
    .verify(&provider.verifying_key(), NOW)
    .unwrap()
}

fn request(
    provider: &SigningKey,
    owner: &SigningKey,
    grant: &VerifiedStorageGrant,
    target: StorageTarget,
    operation: StorageOperation,
    now: u64,
) -> VerifiedStorageRequest {
    let validity = Validity {
        created: now,
        expires: now + 30,
    };
    let challenge = StorageChallenge::issue(provider, grant, validity).unwrap();
    SignedStorageRequest::sign(owner, grant, &challenge, target, operation, validity)
        .unwrap()
        .verify(grant, &challenge, now)
        .unwrap()
}

fn target(id: u8, bytes: &[u8]) -> StorageTarget {
    StorageTarget {
        archive_id: [id; 32],
        lease_id: None,
        ciphertext_bytes: bytes.len() as u64,
        sha256: hash(bytes),
    }
}

fn open(path: &std::path::Path, key: &SigningKey) -> PrivateStorageProvider {
    PrivateStorageProvider::new(
        PrivateStorageStore::open_existing(path).unwrap(),
        key.verifying_key(),
    )
    .unwrap()
}

fn create(path: &std::path::Path, key: &SigningKey, capacity: u64) -> PrivateStorageProvider {
    PrivateStorageProvider::new(
        PrivateStorageStore::create(
            path,
            StorageLimits {
                capacity_bytes: capacity,
                min_free_bytes: 0,
            },
        )
        .unwrap(),
        key.verifying_key(),
    )
    .unwrap()
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one signed owner lifecycle proves that lowering admission preserves every retained lease operation"
)]
fn provider_admission_drain_keeps_signed_existing_reserve_retry_and_lease_rights() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("ciphertext");
    let mut entropy = [0; 32];
    getrandom::fill(&mut entropy).unwrap();
    let provider = SigningKey::from_bytes(&entropy);
    getrandom::fill(&mut entropy).unwrap();
    let owner = SigningKey::from_bytes(&entropy);
    let bytes = b"opaque encrypted archive";
    let authorization = grant(&provider, &owner, 1024, 4);
    let archive = target(61, bytes);
    let mut backend = create(&path, &provider, 1024);
    let reserve = StorageOperation::Reserve {
        expires_at: NOW + 600,
    };
    let execute = |backend: &mut PrivateStorageProvider, target, operation, payload: &[u8]| {
        backend.apply(
            &request(&provider, &owner, &authorization, target, operation, NOW),
            payload,
            NOW,
        )
    };
    let first = execute(&mut backend, archive, reserve, &[])
        .unwrap()
        .receipt;
    let closed = backend.set_admission_target(0).unwrap();
    assert_eq!(closed.pending_drain_bytes, bytes.len() as u64);
    drop(backend);

    let mut backend = open(&path, &provider);
    assert_eq!(backend.admission_status().unwrap(), closed);
    let resumed = execute(&mut backend, archive, reserve, &[])
        .unwrap()
        .receipt;
    assert_eq!(resumed.lease_id, first.lease_id);
    assert_eq!(backend.admission_status().unwrap(), closed);
    assert!(matches!(
        execute(&mut backend, target(62, bytes), reserve, &[]),
        Err(ProviderError::Storage(StorageError::Quota))
    ));
    let bound = StorageTarget {
        lease_id: Some(first.lease_id),
        ..archive
    };
    execute(
        &mut backend,
        bound,
        StorageOperation::Append {
            offset: 0,
            length: u32::try_from(bytes.len()).unwrap(),
            sha256: hash(bytes),
        },
        bytes,
    )
    .unwrap();
    assert_eq!(
        execute(&mut backend, bound, StorageOperation::Finalize, &[])
            .unwrap()
            .receipt
            .state,
        ReceiptState::Committed
    );
    let committed = execute(&mut backend, archive, reserve, &[])
        .unwrap()
        .receipt;
    assert_eq!(committed.state, ReceiptState::Committed);
    assert_eq!(committed.lease_id, first.lease_id);
    execute(
        &mut backend,
        bound,
        StorageOperation::Renew {
            expires_at: NOW + 900,
        },
        &[],
    )
    .unwrap();
    for _ in 0..2 {
        assert_eq!(
            execute(
                &mut backend,
                bound,
                StorageOperation::ReadRange {
                    offset: 0,
                    length: bytes.len() as u64,
                },
                &[]
            )
            .unwrap()
            .payload,
            bytes
        );
    }
    assert_eq!(
        backend.admission_status().unwrap().pending_drain_bytes,
        bytes.len() as u64
    );
    execute(&mut backend, bound, StorageOperation::Delete, &[]).unwrap();
    let empty = backend.admission_status().unwrap();
    assert_eq!(empty.retained_payload_bytes, 0);
    assert_eq!(empty.pending_drain_bytes, 0);
    assert_eq!(empty.target_bytes, 0);
    assert!(matches!(
        execute(&mut backend, archive, reserve, &[]),
        Err(ProviderError::Deleted)
    ));
    backend.set_admission_target(1024).unwrap();
    execute(&mut backend, target(62, bytes), reserve, &[]).unwrap();
    assert_eq!(backend.usage().unwrap().leases, 1);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one complete durable upload, reopen and restore lifecycle"
)]
fn provider_reopen_resumes_one_owned_copy_and_fresh_retry_reports_actual_state() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("ciphertext");
    let provider = SigningKey::from_bytes(&[41; 32]);
    let owner = SigningKey::from_bytes(&[42; 32]);
    let bytes: Vec<u8> = (0..CHUNK_BYTES + 31)
        .map(|index| u8::try_from(index % 251).unwrap())
        .collect();
    let authorization = grant(&provider, &owner, bytes.len() as u64, 1);
    let initial = target(1, &bytes);
    let mut backend = create(&path, &provider, 2 * bytes.len() as u64);
    let reserve = request(
        &provider,
        &owner,
        &authorization,
        initial,
        StorageOperation::Reserve {
            expires_at: NOW + 600,
        },
        NOW,
    );
    let reserved = backend.apply(&reserve, &[], NOW).unwrap().receipt;
    assert_eq!(reserved.state, ReceiptState::Reserved);
    let reserved_target = StorageTarget {
        lease_id: Some(reserved.lease_id),
        ..initial
    };
    let first = &bytes[..CHUNK_BYTES];
    let append = request(
        &provider,
        &owner,
        &authorization,
        reserved_target,
        StorageOperation::Append {
            offset: 0,
            length: u32::try_from(first.len()).unwrap(),
            sha256: hash(first),
        },
        NOW,
    );
    backend.apply(&append, first, NOW).unwrap();
    assert_eq!(backend.usage().unwrap().reserved_bytes, bytes.len() as u64);
    drop(backend);

    let mut backend = open(&path, &provider);
    let retry = request(
        &provider,
        &owner,
        &authorization,
        initial,
        StorageOperation::Reserve {
            expires_at: NOW + 800,
        },
        NOW + 1,
    );
    assert_ne!(retry.challenge_id(), reserve.challenge_id());
    let resumed = backend.apply(&retry, &[], NOW + 1).unwrap().receipt;
    assert_eq!(resumed.lease_id, reserved.lease_id);
    assert_eq!(resumed.state, ReceiptState::Partial);
    assert_eq!(resumed.stored_bytes, CHUNK_BYTES as u64);
    assert_eq!(resumed.expires_at, NOW + 600);
    let retry_first = request(
        &provider,
        &owner,
        &authorization,
        reserved_target,
        append.operation(),
        NOW + 1,
    );
    assert_eq!(
        backend.apply(&retry_first, first, NOW + 1).unwrap().receipt,
        resumed
    );
    let last = &bytes[CHUNK_BYTES..];
    let last_request = request(
        &provider,
        &owner,
        &authorization,
        reserved_target,
        StorageOperation::Append {
            offset: CHUNK_BYTES as u64,
            length: u32::try_from(last.len()).unwrap(),
            sha256: hash(last),
        },
        NOW + 1,
    );
    backend.apply(&last_request, last, NOW + 1).unwrap();
    let finalize = request(
        &provider,
        &owner,
        &authorization,
        reserved_target,
        StorageOperation::Finalize,
        NOW + 1,
    );
    assert_eq!(
        backend
            .apply(&finalize, &[], NOW + 1)
            .unwrap()
            .receipt
            .state,
        ReceiptState::Committed
    );
    let renew = request(
        &provider,
        &owner,
        &authorization,
        reserved_target,
        StorageOperation::Renew {
            expires_at: NOW + 900,
        },
        NOW + 1,
    );
    assert_eq!(
        backend.apply(&renew, &[], NOW + 1).unwrap().receipt.state,
        ReceiptState::Renewed
    );
    drop(backend);

    let mut backend = open(&path, &provider);
    let retry = request(
        &provider,
        &owner,
        &authorization,
        initial,
        StorageOperation::Reserve {
            expires_at: NOW + 700,
        },
        NOW + 2,
    );
    let resumed = backend.apply(&retry, &[], NOW + 2).unwrap().receipt;
    assert_eq!(resumed.state, ReceiptState::Committed);
    assert_eq!(resumed.expires_at, NOW + 900);
    assert_eq!(resumed.lease_id, reserved.lease_id);
    for _ in 0..2 {
        let read = request(
            &provider,
            &owner,
            &authorization,
            reserved_target,
            StorageOperation::ReadRange {
                offset: 0,
                length: bytes.len() as u64,
            },
            NOW + 2,
        );
        let restored = backend.apply(&read, &[], NOW + 2).unwrap();
        assert_eq!(restored.payload, bytes);
        assert_eq!(restored.receipt.range_sha256, Some(hash(&bytes)));
    }
    assert_eq!(
        backend.usage().unwrap(),
        StorageUsage {
            reserved_bytes: 0,
            committed_bytes: bytes.len() as u64,
            leases: 1
        }
    );
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one owned archive scenario with independently signed scope mismatches"
)]
fn provider_rejects_real_signed_wrong_owner_provider_grant_lease_and_changed_identity() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("ciphertext");
    let provider = SigningKey::from_bytes(&[51; 32]);
    let owner = SigningKey::from_bytes(&[52; 32]);
    let other_owner = SigningKey::from_bytes(&[53; 32]);
    let other_provider = SigningKey::from_bytes(&[54; 32]);
    let authorization = grant(&provider, &owner, 100, 3);
    let mut backend = create(&path, &provider, 1000);
    let initial = target(1, b"opaque bytes");
    let reserve = request(
        &provider,
        &owner,
        &authorization,
        initial,
        StorageOperation::Reserve {
            expires_at: NOW + 600,
        },
        NOW,
    );
    let id = backend.apply(&reserve, &[], NOW).unwrap().receipt.lease_id;
    let reserved_target = StorageTarget {
        lease_id: Some(id),
        ..initial
    };
    let other_grant = grant(&provider, &other_owner, 100, 3);
    let wrong_owner = request(
        &provider,
        &other_owner,
        &other_grant,
        reserved_target,
        StorageOperation::Delete,
        NOW,
    );
    assert!(matches!(
        backend.apply(&wrong_owner, &[], NOW),
        Err(ProviderError::Unauthorized)
    ));
    // Register the other owner's real grant too: knowing the first lease still grants no access.
    let register = request(
        &provider,
        &other_owner,
        &other_grant,
        target(2, b"other"),
        StorageOperation::Reserve {
            expires_at: NOW + 600,
        },
        NOW,
    );
    backend.apply(&register, &[], NOW).unwrap();
    assert!(matches!(
        backend.apply(&wrong_owner, &[], NOW),
        Err(ProviderError::Unauthorized)
    ));
    let changed_grant = grant(&provider, &owner, 200, 3);
    let cross_grant = request(
        &provider,
        &owner,
        &changed_grant,
        initial,
        reserve.operation(),
        NOW,
    );
    assert!(matches!(
        backend.apply(&cross_grant, &[], NOW),
        Err(ProviderError::Unauthorized)
    ));
    let foreign_grant = grant(&other_provider, &owner, 100, 3);
    let foreign = request(
        &other_provider,
        &owner,
        &foreign_grant,
        initial,
        reserve.operation(),
        NOW,
    );
    assert!(matches!(
        backend.apply(&foreign, &[], NOW),
        Err(ProviderError::Unauthorized)
    ));
    let wrong_lease = request(
        &provider,
        &owner,
        &authorization,
        StorageTarget {
            lease_id: Some(LeaseId::from_bytes([99; 16])),
            ..reserved_target
        },
        StorageOperation::Progress,
        NOW,
    );
    assert!(matches!(
        backend.apply(&wrong_lease, &[], NOW),
        Err(ProviderError::Unauthorized)
    ));
    for changed in [
        StorageTarget {
            sha256: [9; 32],
            ..initial
        },
        StorageTarget {
            ciphertext_bytes: initial.ciphertext_bytes + 1,
            ..initial
        },
    ] {
        let conflict = request(
            &provider,
            &owner,
            &authorization,
            changed,
            reserve.operation(),
            NOW,
        );
        assert!(matches!(
            backend.apply(&conflict, &[], NOW),
            Err(ProviderError::Conflict)
        ));
    }
    assert_eq!(backend.usage().unwrap().leases, 2);
    assert!(matches!(
        backend.apply(&reserve, &[], NOW + 30),
        Err(ProviderError::Protocol(ProtocolError::Expired))
    ));
    drop(backend);
    let store = PrivateStorageStore::open_existing(&path).unwrap();
    assert!(matches!(
        PrivateStorageProvider::new(store, other_provider.verifying_key()),
        Err(ProviderError::Unauthorized)
    ));
    assert_eq!(open(&path, &provider).usage().unwrap().leases, 2);
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one quota lifecycle spanning incomplete, committed, expired and renewed copies"
)]
fn provider_full_charge_survives_expiry_failures_commit_and_grant_limits() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("ciphertext");
    let provider = SigningKey::from_bytes(&[61; 32]);
    let owner = SigningKey::from_bytes(&[62; 32]);
    let authorization = grant(&provider, &owner, 8, 3);
    let mut backend = create(&path, &provider, 100);
    let first = target(1, b"four");
    let reserve = request(
        &provider,
        &owner,
        &authorization,
        first,
        StorageOperation::Reserve {
            expires_at: NOW + 5,
        },
        NOW,
    );
    let first_id = backend.apply(&reserve, &[], NOW).unwrap().receipt.lease_id;
    let second = target(2, b"next");
    let reserve_second = request(
        &provider,
        &owner,
        &authorization,
        second,
        StorageOperation::Reserve {
            expires_at: NOW + 600,
        },
        NOW,
    );
    let second_id = backend
        .apply(&reserve_second, &[], NOW)
        .unwrap()
        .receipt
        .lease_id;
    let second = StorageTarget {
        lease_id: Some(second_id),
        ..second
    };
    let append = request(
        &provider,
        &owner,
        &authorization,
        second,
        StorageOperation::Append {
            offset: 0,
            length: 4,
            sha256: hash(b"next"),
        },
        NOW,
    );
    assert!(backend.apply(&append, b"fake", NOW).is_err());
    assert_eq!(backend.usage().unwrap().reserved_bytes, 8);
    backend.apply(&append, b"next", NOW).unwrap();
    let finalize = request(
        &provider,
        &owner,
        &authorization,
        second,
        StorageOperation::Finalize,
        NOW,
    );
    backend.apply(&finalize, &[], NOW).unwrap();
    assert_eq!(
        backend.usage().unwrap(),
        StorageUsage {
            reserved_bytes: 4,
            committed_bytes: 4,
            leases: 2
        }
    );
    drop(backend);

    let mut backend = open(&path, &provider);
    let excess = request(
        &provider,
        &owner,
        &authorization,
        target(3, b"x"),
        StorageOperation::Reserve {
            expires_at: NOW + 600,
        },
        NOW + 10,
    );
    assert!(matches!(
        backend.apply(&excess, &[], NOW + 10),
        Err(ProviderError::Storage(StorageError::Quota))
    ));
    // Expired pending storage cannot be read or silently reopened, but is explicitly renewable.
    let expired = StorageTarget {
        lease_id: Some(first_id),
        ..first
    };
    let progress = request(
        &provider,
        &owner,
        &authorization,
        expired,
        StorageOperation::Progress,
        NOW + 10,
    );
    assert!(matches!(
        backend.apply(&progress, &[], NOW + 10),
        Err(ProviderError::Storage(StorageError::Expired))
    ));
    let renew = request(
        &provider,
        &owner,
        &authorization,
        expired,
        StorageOperation::Renew {
            expires_at: NOW + 500,
        },
        NOW + 10,
    );
    backend.apply(&renew, &[], NOW + 10).unwrap();
    assert!(matches!(
        backend.apply(&excess, &[], NOW + 10),
        Err(ProviderError::Storage(StorageError::Quota))
    ));
    // A separate real capability has an independent aggregate lease-count ceiling.
    let count_grant = grant(&provider, &owner, 20, 1);
    let count_first = request(
        &provider,
        &owner,
        &count_grant,
        target(4, b"one"),
        StorageOperation::Reserve {
            expires_at: NOW + 600,
        },
        NOW + 10,
    );
    backend.apply(&count_first, &[], NOW + 10).unwrap();
    let count_second = request(
        &provider,
        &owner,
        &count_grant,
        target(5, b"two"),
        count_first.operation(),
        NOW + 10,
    );
    assert!(matches!(
        backend.apply(&count_second, &[], NOW + 10),
        Err(ProviderError::Storage(StorageError::Quota))
    ));
}

#[test]
#[allow(
    clippy::too_many_lines,
    reason = "one deletion lifecycle across provider restart and local maintenance"
)]
fn provider_deleted_binding_is_durable_idempotent_and_cannot_be_resurrected() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("ciphertext");
    let provider = SigningKey::from_bytes(&[71; 32]);
    let owner = SigningKey::from_bytes(&[72; 32]);
    let authorization = grant(&provider, &owner, 4, 1);
    let mut backend = create(&path, &provider, 100);
    let initial = target(1, b"data");
    let reserve = request(
        &provider,
        &owner,
        &authorization,
        initial,
        StorageOperation::Reserve {
            expires_at: NOW + 5,
        },
        NOW,
    );
    let id = backend.apply(&reserve, &[], NOW).unwrap().receipt.lease_id;
    let reserved_target = StorageTarget {
        lease_id: Some(id),
        ..initial
    };
    // Expiry alone kept it charged; explicit owned deletion can release an expired copy.
    let delete = request(
        &provider,
        &owner,
        &authorization,
        reserved_target,
        StorageOperation::Delete,
        NOW + 10,
    );
    let deleted = backend.apply(&delete, &[], NOW + 10).unwrap().receipt;
    assert_eq!(deleted.state, ReceiptState::Deleted);
    assert_eq!(backend.usage().unwrap().leases, 0);
    drop(backend);

    let mut backend = open(&path, &provider);
    let retry_delete = request(
        &provider,
        &owner,
        &authorization,
        reserved_target,
        StorageOperation::Delete,
        NOW + 11,
    );
    assert_eq!(
        backend.apply(&retry_delete, &[], NOW + 11).unwrap().receipt,
        deleted
    );
    let retry_reserve = request(
        &provider,
        &owner,
        &authorization,
        initial,
        StorageOperation::Reserve {
            expires_at: NOW + 600,
        },
        NOW + 11,
    );
    assert!(matches!(
        backend.apply(&retry_reserve, &[], NOW + 11),
        Err(ProviderError::Deleted)
    ));
    let append = request(
        &provider,
        &owner,
        &authorization,
        reserved_target,
        StorageOperation::Append {
            offset: 0,
            length: 4,
            sha256: hash(b"data"),
        },
        NOW + 11,
    );
    assert!(matches!(
        backend.apply(&append, b"data", NOW + 11),
        Err(ProviderError::Deleted)
    ));
    // Reusing capacity requires an explicit new immutable archive ID, not replay resurrection.
    let fresh = request(
        &provider,
        &owner,
        &authorization,
        target(2, b"data"),
        retry_reserve.operation(),
        NOW + 11,
    );
    let fresh_id = backend
        .apply(&fresh, &[], NOW + 11)
        .unwrap()
        .receipt
        .lease_id;
    assert_ne!(fresh_id, id);
    drop(backend);
    // Existing local maintenance remains compatible and atomically retains provider tombstones.
    let mut local = PrivateStorageStore::open_existing(&path).unwrap();
    assert!(local.delete(fresh_id).unwrap());
    assert!(!local.delete(fresh_id).unwrap());
    drop(local);
    let mut backend = open(&path, &provider);
    assert!(matches!(
        backend.apply(&fresh, &[], NOW + 11),
        Err(ProviderError::Deleted)
    ));
    assert_eq!(backend.usage().unwrap().leases, 0);
}

#[test]
fn provider_reservation_and_deletion_rollback_with_their_ownership_records() {
    let temporary = tempfile::tempdir().unwrap();
    let path = temporary.path().join("ciphertext");
    let provider = SigningKey::from_bytes(&[81; 32]);
    let owner = SigningKey::from_bytes(&[82; 32]);
    let authorization = grant(&provider, &owner, 4, 1);
    let mut backend = create(&path, &provider, 4);
    let initial = target(1, b"data");
    let reserve = request(
        &provider,
        &owner,
        &authorization,
        initial,
        StorageOperation::Reserve {
            expires_at: NOW + 600,
        },
        NOW,
    );
    backend.store.connection.execute_batch("CREATE TRIGGER fail_binding BEFORE INSERT ON storage_bindings BEGIN SELECT RAISE(ABORT, 'injected binding failure'); END;").unwrap();
    assert!(backend.apply(&reserve, &[], NOW).is_err());
    assert_eq!(backend.usage().unwrap().leases, 0);
    assert_eq!(
        count(
            &backend.store.connection,
            "SELECT count(*) FROM storage_grants"
        )
        .unwrap(),
        0
    );
    backend
        .store
        .connection
        .execute_batch("DROP TRIGGER fail_binding;")
        .unwrap();
    let id = backend.apply(&reserve, &[], NOW).unwrap().receipt.lease_id;
    let reserved_target = StorageTarget {
        lease_id: Some(id),
        ..initial
    };
    let append = request(
        &provider,
        &owner,
        &authorization,
        reserved_target,
        StorageOperation::Append {
            offset: 0,
            length: 4,
            sha256: hash(b"data"),
        },
        NOW,
    );
    backend.apply(&append, b"data", NOW).unwrap();
    let finalize = request(
        &provider,
        &owner,
        &authorization,
        reserved_target,
        StorageOperation::Finalize,
        NOW,
    );
    backend.apply(&finalize, &[], NOW).unwrap();
    backend.store.connection.execute_batch("CREATE TRIGGER fail_tombstone BEFORE UPDATE OF deleted ON storage_bindings BEGIN SELECT RAISE(ABORT, 'injected tombstone failure'); END;").unwrap();
    let delete = request(
        &provider,
        &owner,
        &authorization,
        reserved_target,
        StorageOperation::Delete,
        NOW,
    );
    assert!(backend.apply(&delete, &[], NOW).is_err());
    assert_eq!(backend.usage().unwrap().committed_bytes, 4);
    let read = request(
        &provider,
        &owner,
        &authorization,
        reserved_target,
        StorageOperation::ReadRange {
            offset: 0,
            length: 4,
        },
        NOW,
    );
    assert_eq!(backend.apply(&read, &[], NOW).unwrap().payload, b"data");
    backend
        .store
        .connection
        .execute_batch("DROP TRIGGER fail_tombstone;")
        .unwrap();
    backend.apply(&delete, &[], NOW).unwrap();
    assert_eq!(backend.usage().unwrap().committed_bytes, 0);
}
