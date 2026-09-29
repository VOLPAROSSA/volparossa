use super::*;

fn operator_grant(owner: &SigningKey) -> PrivateStorageGrantRequest {
    PrivateStorageGrantRequest {
        owner_key: owner.verifying_key().to_bytes().to_vec(),
        max_payload_bytes: 1024,
        max_leases: 2,
        max_retention_seconds: 300,
        rights: StorageRights::RESERVE.union(StorageRights::PROGRESS).bits(),
        lifetime_seconds: 600,
    }
}

#[test]
fn private_storage_grant_preserves_exact_operator_owner_limits_and_rights() {
    let node = SigningKey::from_bytes(&[31; 32]);
    let owner = SigningKey::from_bytes(&[32; 32]);
    let request = operator_grant(&owner);
    let at = now();
    let issued = issue_grant(&node, &request, at).unwrap();
    assert_eq!(issued.provider_key, node.verifying_key().as_bytes());
    let grant = SignedStorageGrant::decode(&issued.grant)
        .unwrap()
        .verify(&node.verifying_key(), at)
        .unwrap();
    assert_eq!(grant.owner_key(), &owner.verifying_key());
    assert_eq!(grant.provider_key(), &node.verifying_key());
    assert_eq!(
        grant.validity(),
        Validity {
            created: at,
            expires: at + 600
        }
    );
    assert_eq!(grant.limits().max_payload_bytes, 1024);
    assert_eq!(grant.limits().max_leases, 2);
    assert_eq!(grant.limits().max_retention_seconds, 300);
    assert_eq!(grant.limits().rights.bits(), request.rights);
    assert_ne!(grant.limits().rights, StorageRights::ALL);
    let mut invalid = request.clone();
    invalid.rights = 128;
    assert!(issue_grant(&node, &invalid, at).is_err());
    invalid = request;
    invalid.lifetime_seconds = 0;
    assert!(issue_grant(&node, &invalid, at).is_err());
}

#[test]
fn private_storage_remote_binds_independent_provider_before_discovery() {
    let node = SigningKey::from_bytes(&[41; 32]);
    let owner = SigningKey::from_bytes(&[42; 32]);
    let issued = issue_grant(&node, &operator_grant(&owner), now()).unwrap();
    let mut request = PrivateStorageRemoteRequest {
        provider_key: issued.provider_key,
        grant: issued.grant,
    };
    let checked = validate_remote(&request).unwrap();
    assert_eq!(checked.grant.owner_key(), &owner.verifying_key());
    assert_eq!(checked.provider_key, node.verifying_key().to_bytes());
    let public = identity::ed25519::PublicKey::try_from_bytes(&checked.provider_key).unwrap();
    assert_eq!(
        checked.peer,
        PeerId::from_public_key(&identity::PublicKey::from(public))
    );
    request.provider_key = SigningKey::from_bytes(&[43; 32])
        .verifying_key()
        .to_bytes()
        .to_vec();
    assert!(validate_remote(&request).is_err());
    request.provider_key = node.verifying_key().to_bytes().to_vec();
    let last = request.grant.len() - 1;
    request.grant[last] ^= 1;
    assert!(validate_remote(&request).is_err());
}

#[test]
fn private_storage_attachment_reuses_owned_store_without_resizing_or_changing_provider() {
    let temporary = tempfile::tempdir().unwrap();
    let root = temporary.path().join("private");
    let node = SigningKey::from_bytes(&[51; 32]);
    let mut request = PrivateStorageServeRequest {
        bind_address: "127.0.0.1:8443".into(),
        advertised_hostname: "provider.example".into(),
        store: root.to_str().unwrap().into(),
        capacity_bytes: 4096,
        min_free_bytes: 1024,
        reuse_store: false,
    };
    let provider = open_provider(&request, node.verifying_key()).unwrap();
    assert!(open_provider(&request, node.verifying_key()).is_err());
    drop(provider);
    assert!(open_provider(&request, node.verifying_key()).is_err());
    request.reuse_store = true;
    assert!(open_provider(&request, node.verifying_key()).is_err());
    request.capacity_bytes = 0;
    request.min_free_bytes = 0;
    assert!(open_provider(&request, SigningKey::from_bytes(&[52; 32]).verifying_key()).is_err());
    drop(open_provider(&request, node.verifying_key()).unwrap());
    let mut store = PrivateStorageStore::open_existing(&root).unwrap();
    assert_eq!(
        store.limits(),
        StorageLimits {
            capacity_bytes: 4096,
            min_free_bytes: 1024
        }
    );
    assert!(matches!(
        store.reserve(4097, [1; 32], now() + 60, now()),
        Err(volparossa_content::private_storage::StorageError::Quota)
    ));
    assert_eq!(store.usage().unwrap().leases, 0);
}
