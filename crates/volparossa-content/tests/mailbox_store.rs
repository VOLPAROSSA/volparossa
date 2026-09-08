// SPDX-License-Identifier: GPL-3.0-only
//! Real owned disk storage and recipient decryption, not a network/mailbox-service proof.

use std::{fs, os::unix::fs::PermissionsExt as _, path::Path};

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkStore, Metadata, Publication, SignedManifest, Validity,
    mailbox::{
        MailboxQuota, SignedMailboxGrant, VerifiedMailboxGrant,
        store::{MailboxStore, MailboxStoreError, StoredMessage},
    },
    private_message::{
        PRIVATE_MESSAGE_CONTENT_TYPE, RecipientKeyPair, open_private_message,
        publish_private_message,
    },
    publish, reassemble,
};

const NOW: u64 = 2_000_000_000;

fn limits(max_bytes: u64) -> CacheLimits {
    CacheLimits {
        max_bytes,
        max_entries: 64,
        min_free_bytes: 0,
    }
}

fn invitation(
    sender: &SigningKey,
    recipient: &RecipientKeyPair,
    max_bytes: u64,
    max_messages: u32,
) -> VerifiedMailboxGrant {
    let owner = SigningKey::generate(&mut OsRng);
    let providers = [
        SigningKey::generate(&mut OsRng).verifying_key().to_bytes(),
        SigningKey::generate(&mut OsRng).verifying_key().to_bytes(),
    ];
    SignedMailboxGrant::sign(
        &owner,
        sender.verifying_key().to_bytes(),
        *recipient.public_key(),
        providers,
        Validity {
            created: NOW,
            expires: NOW + 300,
        },
        MailboxQuota {
            max_bytes,
            max_messages,
        },
    )
    .unwrap()
    .verify(&owner.verifying_key(), NOW)
    .unwrap()
}

fn message(
    sender: &SigningKey,
    recipient: &RecipientKeyPair,
    plaintext: &[u8],
    created: u64,
    expires: u64,
) -> (SignedManifest, Vec<u8>) {
    let publisher_directory = tempfile::tempdir().unwrap();
    let path = publisher_directory.path().join("publisher-cache");
    let mut cache = ChunkStore::create(&path, limits(8 * 1024 * 1024)).unwrap();
    let signed = publish_private_message(
        plaintext,
        recipient.public_key(),
        sender,
        Validity { created, expires },
        &mut cache,
    )
    .unwrap();
    let verified = signed.verify(&sender.verifying_key(), created).unwrap();
    let mut ciphertext = Vec::new();
    reassemble(&verified, &mut [&mut cache], created, &mut ciphertext).unwrap();
    drop(cache);
    drop(publisher_directory);
    assert!(
        !path.exists(),
        "publisher cache has actually gone before delivery"
    );
    (signed, ciphertext)
}

#[test]
fn mailbox_reopens_offline_ciphertext_and_ack_preserves_shared_data_without_resurrection() {
    let root = tempfile::tempdir().unwrap();
    let path = root.path().join("mailbox-cache");
    let sender = SigningKey::generate(&mut OsRng);
    let recipient = RecipientKeyPair::generate().unwrap();
    let plaintext = vec![0x62; CHUNK_BYTES + 123];
    let (signed, ciphertext) = message(&sender, &recipient, &plaintext, NOW, NOW + 100);
    let quota = u64::try_from(ciphertext.len()).unwrap();
    let first = invitation(&sender, &recipient, quota, 2);
    let second = invitation(&sender, &recipient, quota, 2);
    let mut store = MailboxStore::create(&path, limits(quota), NOW).unwrap();
    store.register(&first, NOW).unwrap();
    store.register(&first, NOW).unwrap();
    store.register(&second, NOW).unwrap();
    let deposited = store
        .deposit(first.mailbox_id(), &signed, &ciphertext, NOW)
        .unwrap();
    assert!(!deposited.already_present && !deposited.acknowledged);
    store
        .deposit(second.mailbox_id(), &signed, &ciphertext, NOW)
        .unwrap();
    assert_eq!(
        store.usage().bytes,
        quota,
        "shared ciphertext is physically retained once"
    );
    assert!(
        MailboxStore::open(&path, limits(quota), NOW).is_err(),
        "exclusive store lock"
    );
    drop(store);
    drop(sender);

    let mut store = MailboxStore::open(&path, limits(quota), NOW + 1).unwrap();
    assert_eq!(
        store
            .grant(first.mailbox_id(), NOW + 1)
            .unwrap()
            .unwrap()
            .grant_id(),
        first.grant_id()
    );
    let entries = store.list(first.mailbox_id(), NOW + 1).unwrap();
    assert_eq!(entries.len(), 1);
    assert_eq!(entries[0].signed.encode(), signed.encode());
    assert_eq!(entries[0].expires_at, NOW + 100);
    let fetched = store
        .get(first.mailbox_id(), &deposited.message_id, NOW + 1)
        .unwrap()
        .unwrap();
    assert_eq!(fetched.ciphertext, ciphertext);
    decrypt_retrieved(root.path(), &fetched, &first, &recipient, &plaintext);
    assert_eq!(
        fs::metadata(&path).unwrap().permissions().mode() & 0o777,
        0o700
    );
    assert!(
        store
            .acknowledge(first.mailbox_id(), &deposited.message_id, NOW + 2)
            .unwrap()
    );
    assert!(store.list(first.mailbox_id(), NOW + 2).unwrap().is_empty());
    assert_eq!(
        store.usage().bytes,
        quota,
        "the second mailbox still owns the shared chunks"
    );
    assert!(
        store
            .get(second.mailbox_id(), &deposited.message_id, NOW + 2)
            .unwrap()
            .is_some()
    );
    drop(store);
    let mut store = MailboxStore::open(&path, limits(quota), NOW + 3).unwrap();
    let retry = store
        .deposit(first.mailbox_id(), &signed, &ciphertext, NOW + 3)
        .unwrap();
    assert!(retry.already_present && retry.acknowledged);
    assert!(
        store
            .acknowledge(second.mailbox_id(), &deposited.message_id, NOW + 3)
            .unwrap()
    );
    assert_eq!(store.usage().bytes, 0);
    assert!(
        store
            .acknowledge(first.mailbox_id(), &deposited.message_id, NOW + 3)
            .unwrap()
    );
    assert!(
        store
            .get(second.mailbox_id(), &deposited.message_id, NOW + 3)
            .unwrap()
            .is_none()
    );
}

fn decrypt_retrieved(
    root: &Path,
    fetched: &StoredMessage,
    grant: &VerifiedMailboxGrant,
    recipient: &RecipientKeyPair,
    plaintext: &[u8],
) {
    let verified = fetched
        .entry
        .signed
        .verify(
            &ed25519_dalek::VerifyingKey::from_bytes(grant.sender_key()).unwrap(),
            NOW + 1,
        )
        .unwrap();
    let mut local =
        ChunkStore::create(&root.join("recipient-cache"), limits(verified.length())).unwrap();
    let mut remaining = fetched.ciphertext.as_slice();
    for chunk in verified.chunks() {
        let (part, rest) = remaining.split_at(chunk.length() as usize);
        local.put_verified(*chunk.id(), part).unwrap();
        remaining = rest;
    }
    let opened = open_private_message(&verified, &mut [&mut local], NOW + 1, recipient).unwrap();
    assert_eq!(opened.as_slice(), plaintext);
}

#[test]
fn mailbox_quota_never_evicts_committed_data_and_original_expiry_reclaims_tombstones() {
    let root = tempfile::tempdir().unwrap();
    let sender = SigningKey::generate(&mut OsRng);
    let recipient = RecipientKeyPair::generate().unwrap();
    let plaintext = vec![0x21; CHUNK_BYTES + 7];
    let (first, ciphertext) = message(&sender, &recipient, &plaintext, NOW, NOW + 100);
    let (second, other_ciphertext) = message(&sender, &recipient, &plaintext, NOW, NOW + 100);
    let quota = u64::try_from(ciphertext.len()).unwrap();
    assert_eq!(ciphertext.len(), other_ciphertext.len());
    let grant = invitation(&sender, &recipient, quota * 2, 2);
    let mut store = MailboxStore::create(&root.path().join("cache"), limits(quota), NOW).unwrap();
    store.register(&grant, NOW).unwrap();
    let initial = store
        .deposit(grant.mailbox_id(), &first, &ciphertext, NOW)
        .unwrap();
    let mut corrupt = other_ciphertext.clone();
    corrupt[0] ^= 1;
    assert!(
        store
            .deposit(grant.mailbox_id(), &second, &corrupt, NOW)
            .is_err()
    );
    assert!(matches!(
        store.deposit(grant.mailbox_id(), &second, &other_ciphertext, NOW),
        Err(MailboxStoreError::Quota)
    ));
    assert_eq!(
        store
            .get(grant.mailbox_id(), &initial.message_id, NOW)
            .unwrap()
            .unwrap()
            .ciphertext,
        ciphertext
    );
    store
        .acknowledge(grant.mailbox_id(), &initial.message_id, NOW + 1)
        .unwrap();
    assert_eq!(store.usage().bytes, 0);
    let next = store
        .deposit(grant.mailbox_id(), &second, &other_ciphertext, NOW + 1)
        .unwrap();
    store
        .acknowledge(grant.mailbox_id(), &next.message_id, NOW + 2)
        .unwrap();
    let (third, third_ciphertext) = message(&sender, &recipient, &plaintext, NOW + 2, NOW + 200);
    assert!(
        matches!(
            store.deposit(grant.mailbox_id(), &third, &third_ciphertext, NOW + 2),
            Err(MailboxStoreError::Quota)
        ),
        "ACK records still bound count before original expiry"
    );
    assert!(
        store
            .list(grant.mailbox_id(), NOW + 100)
            .unwrap()
            .is_empty()
    );
    assert!(
        store
            .deposit(grant.mailbox_id(), &first, &ciphertext, NOW + 100)
            .is_err(),
        "original expired signature never refreshed"
    );
    let final_deposit = store
        .deposit(grant.mailbox_id(), &third, &third_ciphertext, NOW + 100)
        .unwrap();
    assert_eq!(final_deposit.expires_at, NOW + 200);
    assert!(
        store
            .list(grant.mailbox_id(), NOW + 200)
            .unwrap()
            .is_empty()
    );
    assert_eq!(store.usage().bytes, 0);
    assert!(
        store
            .grant(grant.mailbox_id(), NOW + 300)
            .unwrap()
            .is_none()
    );
}

#[test]
fn mailbox_rejects_malformed_private_envelopes_foreign_journals_and_corrupt_owned_files() {
    let root = tempfile::tempdir().unwrap();
    let sender = SigningKey::generate(&mut OsRng);
    let recipient = RecipientKeyPair::generate().unwrap();
    let grant = invitation(&sender, &recipient, 1024 * 1024, 4);
    let path = root.path().join("mailbox");
    let capacity = limits(1024 * 1024);
    let mut store = MailboxStore::create(&path, capacity, NOW).unwrap();
    store.register(&grant, NOW).unwrap();
    let malformed = malformed_message(root.path(), &sender);
    assert!(
        store
            .deposit(grant.mailbox_id(), &malformed, &[0; 54], NOW)
            .is_err()
    );
    assert_eq!(
        store.usage().bytes,
        0,
        "invalid envelope cannot consume lasting promised storage"
    );
    assert!(store.list(grant.mailbox_id(), NOW).unwrap().is_empty());
    let (signed, ciphertext) = message(
        &sender,
        &recipient,
        b"ciphertext survives only intact",
        NOW,
        NOW + 100,
    );
    let outcome = store
        .deposit(grant.mailbox_id(), &signed, &ciphertext, NOW)
        .unwrap();
    let unknown = SigningKey::generate(&mut OsRng);
    let (foreign, foreign_bytes) = message(&unknown, &recipient, b"unauthorized", NOW, NOW + 100);
    assert!(
        store
            .deposit(grant.mailbox_id(), &foreign, &foreign_bytes, NOW)
            .is_err()
    );
    assert!(
        !store
            .acknowledge(grant.mailbox_id(), &[0; 32], NOW)
            .unwrap()
    );
    assert!(
        store
            .get(grant.mailbox_id(), &outcome.message_id, NOW)
            .unwrap()
            .is_some()
    );
    drop(store);

    let journal = path.join(".volparossa-mailbox-v1");
    let original = fs::read(&journal).unwrap();
    let other_path = root.path().join("other-mailbox");
    drop(MailboxStore::create(&other_path, capacity, NOW).unwrap());
    fs::write(other_path.join(".volparossa-mailbox-v1"), &original).unwrap();
    assert!(MailboxStore::open(&other_path, capacity, NOW).is_err());
    assert!(
        other_path.join(".volparossa-mailbox-v1").exists(),
        "foreign journal is not silently deleted or adopted"
    );
    let mut corrupt = original.clone();
    corrupt[40] ^= 1;
    fs::write(&journal, &corrupt).unwrap();
    assert!(MailboxStore::open(&path, capacity, NOW).is_err());
    assert_eq!(fs::read(&journal).unwrap(), corrupt);
    fs::write(&journal, &original).unwrap();
    let checked = signed.verify(&sender.verifying_key(), NOW).unwrap();
    let chunk_path = path.join(checked.chunks()[0].id().to_string());
    fs::OpenOptions::new()
        .write(true)
        .open(&chunk_path)
        .unwrap()
        .set_len(1)
        .unwrap();
    assert!(MailboxStore::open(&path, capacity, NOW).is_err());
    assert_eq!(fs::metadata(chunk_path).unwrap().len(), 1);
    let plain_cache = root.path().join("not-a-mailbox");
    drop(ChunkStore::create(&plain_cache, capacity).unwrap());
    assert!(
        MailboxStore::open(&plain_cache, capacity, NOW).is_err(),
        "ordinary caches are not adopted as mailboxes"
    );
}

fn malformed_message(root: &Path, sender: &SigningKey) -> SignedManifest {
    let mut temporary = ChunkStore::create(&root.join("invalid-producer"), limits(1024)).unwrap();
    let mut name = [0; 32];
    rand_core::RngCore::fill_bytes(&mut OsRng, &mut name);
    publish(
        &mut [0; 54].as_slice(),
        Publication {
            metadata: Metadata {
                name: hex::encode(name),
                revision: 1,
                content_type: PRIVATE_MESSAGE_CONTENT_TYPE.into(),
            },
            length: 54,
            validity: Validity {
                created: NOW,
                expires: NOW + 100,
            },
        },
        sender,
        &mut temporary,
    )
    .unwrap()
}
