// SPDX-License-Identifier: GPL-3.0-only
//! Original owner/manifest/token binding, not evidence of an application's database commit.

use ed25519_dalek::SigningKey;
use rand_core::OsRng;
use sha2::{Digest as _, Sha256};
use volparossa_content::{
    CacheLimits, ChunkStore, Validity,
    mailbox::{MailboxQuota, SignedMailboxGrant, import::SignedImportReceipt},
    private_message::{RecipientKeyPair, publish_private_message},
};

const NOW: u64 = 2_000_000_000;

#[test]
fn import_receipt_retains_original_authority_after_decode_and_rejects_substitution() {
    let owner = SigningKey::generate(&mut OsRng);
    let sender = SigningKey::generate(&mut OsRng);
    let recipient = RecipientKeyPair::from_node_identity(&owner).unwrap();
    let providers = [
        SigningKey::generate(&mut OsRng),
        SigningKey::generate(&mut OsRng),
    ];
    let grant = SignedMailboxGrant::sign(
        &owner,
        sender.verifying_key().to_bytes(),
        *recipient.public_key(),
        providers.map(|key| key.verifying_key().to_bytes()),
        Validity {
            created: NOW,
            expires: NOW + 300,
        },
        MailboxQuota {
            max_bytes: 1048576,
            max_messages: 8,
        },
    )
    .unwrap();
    let checked = grant.verify(&owner.verifying_key(), NOW).unwrap();
    let directory = tempfile::tempdir().unwrap();
    let mut cache = ChunkStore::create(
        &directory.path().join("ciphertext"),
        CacheLimits {
            max_bytes: 1048576,
            max_entries: 16,
            min_free_bytes: 0,
        },
    )
    .unwrap();
    let plaintext = b"exact private consumer bytes including message headers";
    let message = publish_private_message(
        plaintext,
        recipient.public_key(),
        &sender,
        Validity {
            created: NOW,
            expires: NOW + 200,
        },
        &mut cache,
    )
    .unwrap();
    let mut token = [0; 32];
    getrandom::fill(&mut token).unwrap();
    let original =
        SignedImportReceipt::sign(&owner, &checked, &message, plaintext, &token, NOW + 1).unwrap();
    let encoded = original.encode();
    let restored = SignedImportReceipt::decode(&encoded).unwrap();
    assert_eq!(restored.encode(), encoded);
    let verified = restored.verify(&owner.verifying_key(), NOW + 150).unwrap();
    assert_eq!(verified.grant().signed().encode(), grant.encode());
    assert_eq!(verified.expires(), NOW + 200);
    assert_eq!(verified.plaintext_bytes(), plaintext.len() as u64);
    assert_eq!(
        verified.message_id(),
        message
            .verify(&sender.verifying_key(), NOW)
            .unwrap()
            .manifest_id()
    );
    let imported: [u8; 32] = Sha256::digest(plaintext).into();
    verified.confirm(&token, &imported).unwrap();
    let mut different_token = token;
    different_token[0] ^= 1;
    assert!(verified.confirm(&different_token, &imported).is_err());
    let mut wrong_bytes = imported;
    wrong_bytes[0] ^= 1;
    assert!(verified.confirm(&token, &wrong_bytes).is_err());
    assert!(restored.verify(&sender.verifying_key(), NOW + 2).is_err());
    assert!(restored.verify(&owner.verifying_key(), NOW + 200).is_err());
    assert!(restored.verify(&owner.verifying_key(), NOW).is_err());
    assert!(
        SignedImportReceipt::sign(&sender, &checked, &message, plaintext, &token, NOW + 1).is_err()
    );
    let mut tampered = encoded;
    *tampered.last_mut().unwrap() ^= 1;
    assert!(
        SignedImportReceipt::decode(&tampered)
            .unwrap()
            .verify(&owner.verifying_key(), NOW + 2)
            .is_err()
    );
    assert!(SignedImportReceipt::decode(&grant.encode()).is_err());
    assert!(SignedMailboxGrant::decode(&original.encode()).is_err());
    let mut trailing = original.encode();
    trailing.extend_from_slice(&[0x18, 1]);
    assert!(SignedImportReceipt::decode(&trailing).is_err());
}
