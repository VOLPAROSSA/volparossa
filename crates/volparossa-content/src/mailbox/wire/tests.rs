use super::*;
use crate::{
    CacheLimits, ChunkStore,
    mailbox::MailboxQuota,
    private_message::{RecipientKeyPair, open_private_message, publish_private_message},
    provider::{PublicationRegistry, serve_publication},
    transfer::TransferLimits,
};

fn limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 16 * 1024 * 1024,
        max_entries: 128,
        min_free_bytes: 0,
    }
}

async fn exchange(
    registry: PublicationRegistry,
    provider: [u8; 32],
    grant: &VerifiedMailboxGrant,
    command: &MailboxCommand,
    key: &SigningKey,
    ciphertext: &[u8],
) -> MailboxReply {
    let (mut application, mut bridge_local) = tokio::io::duplex(1024);
    let (mut bridge_remote, mut server) = tokio::io::duplex(1024);
    let serving = tokio::spawn(async move {
        serve_publication(&mut server, &registry, TransferLimits::default())
            .await
            .unwrap();
    });
    let challenge = begin(&mut bridge_remote, &provider).await.unwrap();
    let forwarded_grant = grant.clone();
    let forwarded_command = command.clone();
    let forwarded_challenge = challenge.clone();
    let forwarding = tokio::spawn(async move {
        bridge(
            &mut bridge_local,
            &mut bridge_remote,
            &forwarded_challenge,
            &forwarded_grant,
            &forwarded_command,
        )
        .await
        .unwrap()
    });
    let reply = execute(
        &mut application,
        &challenge,
        grant,
        command,
        key,
        ciphertext,
    )
    .await
    .unwrap();
    assert_eq!(forwarding.await.unwrap().encode(), reply.receipt.encode());
    serving.await.unwrap();
    reply
}

fn command(operation: MailboxOperation) -> MailboxCommand {
    MailboxCommand {
        operation,
        manifest: None,
        message_id: None,
    }
}

#[tokio::test]
#[allow(clippy::too_many_lines)] // Keep the complete two-provider/restart scenario together.
async fn mailbox_stream_reopens_two_replicas_and_delivers_without_sender_manifest() {
    let root = tempfile::tempdir().unwrap();
    let now = unix_now().unwrap();
    let owner = SigningKey::from_bytes(&[11; 32]);
    let sender = SigningKey::from_bytes(&[12; 32]);
    let recipient = RecipientKeyPair::from_node_identity(&owner).unwrap();
    let provider_keys = [
        Arc::new(SigningKey::from_bytes(&[13; 32])),
        Arc::new(SigningKey::from_bytes(&[14; 32])),
    ];
    let signed_grant = SignedMailboxGrant::sign(
        &owner,
        sender.verifying_key().to_bytes(),
        *recipient.public_key(),
        provider_keys
            .each_ref()
            .map(|key| key.verifying_key().to_bytes()),
        Validity {
            created: now,
            expires: now + 300,
        },
        MailboxQuota {
            max_bytes: 8 * 1024 * 1024,
            max_messages: 8,
        },
    )
    .unwrap();
    let grant = signed_grant.verify(&owner.verifying_key(), now).unwrap();
    let mut registries = Vec::new();
    for (index, key) in provider_keys.iter().enumerate() {
        let store = MailboxStore::create(
            &root.path().join(format!("provider-{index}")),
            limits(),
            now,
        )
        .unwrap();
        let mut registry = PublicationRegistry::new();
        registry.set_mailbox(Arc::new(MailboxService::new(key.clone(), store)));
        let reply = exchange(
            registry.clone(),
            key.verifying_key().to_bytes(),
            &grant,
            &command(MailboxOperation::Register),
            &owner,
            &[],
        )
        .await;
        assert_eq!(reply.receipt.retained_until(), grant.validity().expires);
        registries.push(registry);
    }
    let plaintext = vec![43; CHUNK_BYTES + 37];
    let (sender_manifest, ciphertext) = {
        let mut cache = ChunkStore::create(&root.path().join("sender"), limits()).unwrap();
        let signed = publish_private_message(
            &plaintext,
            recipient.public_key(),
            &sender,
            Validity {
                created: now,
                expires: now + 240,
            },
            &mut cache,
        )
        .unwrap();
        let verified = signed.verify(&sender.verifying_key(), now).unwrap();
        let mut ciphertext = Vec::new();
        crate::reassemble(&verified, &mut [&mut cache], now, &mut ciphertext).unwrap();
        (signed, ciphertext)
    };
    let deposit = MailboxCommand {
        operation: MailboxOperation::Deposit,
        manifest: Some(sender_manifest),
        message_id: None,
    };
    let mut receipts = Vec::new();
    for (registry, key) in registries.iter().zip(&provider_keys) {
        let reply = exchange(
            registry.clone(),
            key.verifying_key().to_bytes(),
            &grant,
            &deposit,
            &sender,
            &ciphertext,
        )
        .await;
        assert!(!reply.receipt.acknowledged());
        assert_eq!(reply.receipt.ciphertext_bytes(), ciphertext.len() as u64);
        receipts.push(*reply.receipt.provider_key());
    }
    assert_ne!(receipts[0], receipts[1]);
    drop(deposit);
    drop(sender);
    drop(ciphertext);
    drop(registries);
    // No sender key, object, or original manifest is passed to the recipient's operation.
    for (index, key) in provider_keys.iter().enumerate() {
        let reopened = MailboxStore::open(
            &root.path().join(format!("provider-{index}")),
            limits(),
            now,
        )
        .unwrap();
        let mut registry = PublicationRegistry::new();
        registry.set_mailbox(Arc::new(MailboxService::new(key.clone(), reopened)));
        receive_and_ack(
            registry,
            key,
            &grant,
            &owner,
            &recipient,
            &plaintext,
            root.path(),
            index,
        )
        .await;
    }
}

#[allow(clippy::too_many_arguments)]
async fn receive_and_ack(
    registry: PublicationRegistry,
    key: &SigningKey,
    grant: &VerifiedMailboxGrant,
    owner: &SigningKey,
    recipient: &RecipientKeyPair,
    plaintext: &[u8],
    root: &std::path::Path,
    index: usize,
) {
    let provider = key.verifying_key().to_bytes();
    let now = unix_now().unwrap();
    let inbox = exchange(
        registry.clone(),
        provider,
        grant,
        &command(MailboxOperation::List),
        owner,
        &[],
    )
    .await;
    let manifests = inbox.receipt.manifests(grant, now).unwrap();
    assert_eq!(manifests.len(), 1);
    let verified = manifests[0]
        .verify(&VerifyingKey::from_bytes(grant.sender_key()).unwrap(), now)
        .unwrap();
    let id = *verified.manifest_id();
    let get = MailboxCommand {
        operation: MailboxOperation::Get,
        manifest: None,
        message_id: Some(id),
    };
    let reply = exchange(registry.clone(), provider, grant, &get, owner, &[]).await;
    let mut cache = ChunkStore::create(&root.join(format!("recipient-{index}")), limits()).unwrap();
    for (chunk, bytes) in verified
        .chunks()
        .iter()
        .zip(reply.ciphertext.chunks(CHUNK_BYTES))
    {
        cache.put_verified(*chunk.id(), bytes).unwrap();
    }
    assert_eq!(
        &*open_private_message(&verified, &mut [&mut cache], now, recipient).unwrap(),
        plaintext
    );
    let ack = MailboxCommand {
        operation: MailboxOperation::Acknowledge,
        manifest: None,
        message_id: Some(id),
    };
    assert!(
        exchange(registry.clone(), provider, grant, &ack, owner, &[])
            .await
            .receipt
            .acknowledged()
    );
    assert!(
        exchange(registry.clone(), provider, grant, &ack, owner, &[])
            .await
            .receipt
            .acknowledged()
    );
    assert!(
        exchange(
            registry,
            provider,
            grant,
            &command(MailboxOperation::List),
            owner,
            &[]
        )
        .await
        .receipt
        .manifests(grant, now)
        .unwrap()
        .is_empty()
    );
}

#[test]
fn mailbox_challenge_binds_connection_provider_grant_and_operation() {
    let now = unix_now().unwrap();
    let owner = SigningKey::from_bytes(&[21; 32]);
    let sender = SigningKey::from_bytes(&[22; 32]);
    let provider = SigningKey::from_bytes(&[23; 32]);
    let other = SigningKey::from_bytes(&[24; 32]);
    let signed = SignedMailboxGrant::sign(
        &owner,
        sender.verifying_key().to_bytes(),
        [25; 32],
        [
            provider.verifying_key().to_bytes(),
            other.verifying_key().to_bytes(),
        ],
        Validity {
            created: now,
            expires: now + 300,
        },
        MailboxQuota {
            max_bytes: 1024 * 1024,
            max_messages: 2,
        },
    )
    .unwrap();
    let grant = signed.verify(&owner.verifying_key(), now).unwrap();
    let challenge = MailboxChallenge {
        provider: provider.verifying_key().to_bytes(),
        envelope: sign_envelope(
            &provider,
            CHALLENGE_TYPE,
            ChallengePayload {
                random: vec![26; 32],
            }
            .encode_to_vec(),
            Validity {
                created: now,
                expires: now + 60,
            },
        )
        .unwrap(),
    };
    let request = command(MailboxOperation::List)
        .payload(&grant, &challenge)
        .unwrap();
    let auth = sign_envelope(
        &owner,
        AUTH_TYPE,
        request.encode_to_vec(),
        Validity {
            created: now,
            expires: now + 30,
        },
    )
    .unwrap();
    assert!(verify_authorization(&auth.encode_to_vec(), &challenge, now).is_ok());
    let changed = MailboxChallenge {
        provider: provider.verifying_key().to_bytes(),
        envelope: sign_envelope(
            &provider,
            CHALLENGE_TYPE,
            ChallengePayload {
                random: vec![27; 32],
            }
            .encode_to_vec(),
            Validity {
                created: now,
                expires: now + 60,
            },
        )
        .unwrap(),
    };
    assert!(verify_authorization(&auth.encode_to_vec(), &changed, now).is_err());
    assert!(verify_authorization(&auth.encode_to_vec(), &challenge, now + 31).is_err());
    let unauthorized = sign_envelope(
        &sender,
        AUTH_TYPE,
        request.encode_to_vec(),
        Validity {
            created: now,
            expires: now + 30,
        },
    )
    .unwrap();
    assert!(verify_authorization(&unauthorized.encode_to_vec(), &challenge, now).is_err());
    assert!(
        MailboxChallenge::decode(&challenge.encode(), &other.verifying_key().to_bytes(), now)
            .is_err()
    );
    assert!(signed.verify(&sender.verifying_key(), now).is_err());
    let mut malformed = signed.encode();
    malformed.extend_from_slice(&[8, 1]);
    assert!(SignedMailboxGrant::decode(&malformed).is_err());
}
