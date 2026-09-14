//! Real ciphertext-only disk replicas and explicit recipient-key authority.

use std::fs;

use ed25519_dalek::SigningKey;
use volparossa_content::private_message::{
    MAX_PRIVATE_MESSAGE_BYTES, PrivateMessageError, RecipientKeyPair, open_private_message,
    publish_private_message,
};
use volparossa_content::{
    CHUNK_BYTES, CacheLimits, ChunkStore, Error, Publication, SignedManifest, Validity,
    VerifiedManifest, publish, reassemble,
};
use zeroize::Zeroizing;

const VALIDITY: Validity = Validity {
    created: 100,
    expires: 200,
};

#[test]
fn intended_recipient_reads_reopened_ciphertext_replicas_after_publisher_storage_is_gone() {
    let root = tempfile::tempdir().expect("test root");
    let origin = tempfile::tempdir_in(root.path()).expect("publisher directory");
    let mut source = ChunkStore::create(&origin.path().join("source"), limits()).expect("source");
    let first_path = root.path().join("replica-a");
    let second_path = root.path().join("replica-b");
    let mut first = ChunkStore::create(&first_path, limits()).expect("first replica");
    let mut second = ChunkStore::create(&second_path, limits()).expect("second replica");
    let sender = SigningKey::generate(&mut rand_core::OsRng);
    let trusted_sender = sender.verifying_key();
    let recipient = provisioned_recipient();
    let plaintext = Zeroizing::new(vec![0x76; CHUNK_BYTES * 2 + 73]);
    let signed = publish_private_message(
        &plaintext,
        recipient.public_key(),
        &sender,
        VALIDITY,
        &mut source,
    )
    .expect("encrypted publication");
    let manifest = signed.verify(&trusted_sender, 101).expect("sender");
    assert_eq!(manifest.chunks().len(), 3);
    assert_eq!(manifest.metadata().name.len(), 64);
    for (index, chunk) in manifest.chunks().iter().enumerate() {
        let ciphertext = source.get(chunk.id()).expect("source read").expect("chunk");
        assert!(
            !ciphertext
                .windows(64)
                .any(|window| window == &plaintext[..64])
        );
        let target = if index % 2 == 0 {
            &mut first
        } else {
            &mut second
        };
        target
            .put_verified(*chunk.id(), &ciphertext)
            .expect("replica");
    }
    let wire = signed.encode();
    drop((source, first, second, sender, signed, manifest));
    origin.close().expect("publisher storage removed");

    let mut first = ChunkStore::open(&first_path, limits()).expect("reopen first replica");
    let mut second = ChunkStore::open(&second_path, limits()).expect("reopen second replica");
    let manifest = SignedManifest::decode(&wire)
        .expect("manifest decode")
        .verify(&trusted_sender, 110)
        .expect("independent sender authority");
    assert!(matches!(
        open_private_message(&manifest, &mut [&mut first], 110, &recipient),
        Err(PrivateMessageError::Content(Error::MissingChunk(_)))
    ));
    let output = open_private_message(&manifest, &mut [&mut first, &mut second], 110, &recipient)
        .expect("intended recipient decryption");
    assert_eq!(output.as_slice(), plaintext.as_slice());
    assert_eq!(first.usage().entries, 2);
    assert_eq!(second.usage().entries, 1);
}

#[test]
fn wrong_recipient_sender_and_corrupt_stored_ciphertext_are_rejected() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let signed = fixture.publish(
        b"private message for exactly the provisioned recipient",
        &mut store,
    );
    let manifest = signed
        .verify(&fixture.sender.verifying_key(), 101)
        .expect("sender");
    let unrelated_sender = SigningKey::generate(&mut rand_core::OsRng);
    assert!(matches!(
        signed.verify(&unrelated_sender.verifying_key(), 101),
        Err(Error::WrongPublisher)
    ));
    let wrong_recipient = RecipientKeyPair::generate().expect("unrelated encryption key");
    assert!(matches!(
        open_private_message(&manifest, &mut [&mut store], 101, &wrong_recipient),
        Err(PrivateMessageError::Open)
    ));
    let chunk = manifest.chunks()[0].id();
    let mut corrupted = store.get(chunk).expect("read").expect("ciphertext");
    let last = corrupted.last_mut().expect("ciphertext authentication tag");
    *last ^= 1;
    fs::write(
        fixture.root.path().join("store").join(chunk.to_string()),
        corrupted,
    )
    .expect("simulate corrupt same-length disk chunk");
    assert!(matches!(
        open_private_message(&manifest, &mut [&mut store], 101, &fixture.recipient),
        Err(PrivateMessageError::Content(Error::Integrity(_)))
    ));
}

#[test]
fn expiry_and_signed_rewrapping_cannot_change_the_encrypted_publication_context() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let signed = fixture.publish(
        b"bound sender, metadata, expiry and full ciphertext",
        &mut store,
    );
    let manifest = signed
        .verify(&fixture.sender.verifying_key(), 101)
        .expect("sender");
    for now in [99, 200] {
        assert!(matches!(
            open_private_message(&manifest, &mut [&mut store], now, &fixture.recipient),
            Err(PrivateMessageError::Content(Error::Expired))
        ));
    }
    let mut ciphertext = Vec::new();
    reassemble(&manifest, &mut [&mut store], 101, &mut ciphertext).expect("ciphertext only");
    let other_sender = SigningKey::generate(&mut rand_core::OsRng);
    for change in 0..4 {
        let mut publication = publication_from(&manifest);
        let mut publisher = &fixture.sender;
        let alternate = alternate_hex(&publication.metadata.name);
        match change {
            0 => publication.metadata.name.replace_range(..1, alternate),
            1 => publication.validity.expires += 1,
            2 => publication.validity.created -= 1,
            _ => publisher = &other_sender,
        }
        let replacement = publish(
            &mut ciphertext.as_slice(),
            publication,
            publisher,
            &mut store,
        )
        .expect("new signed manifest over identical ciphertext")
        .verify(&publisher.verifying_key(), 101)
        .expect("new publisher signature is valid");
        assert!(matches!(
            open_private_message(&replacement, &mut [&mut store], 101, &fixture.recipient),
            Err(PrivateMessageError::Open)
        ));
    }
    *ciphertext.last_mut().expect("tag") ^= 1;
    let tampered = publish(
        &mut ciphertext.as_slice(),
        publication_from(&manifest),
        &fixture.sender,
        &mut store,
    )
    .expect("resigned changed ciphertext")
    .verify(&fixture.sender.verifying_key(), 101)
    .expect("valid outer signature");
    assert!(matches!(
        open_private_message(&tampered, &mut [&mut store], 101, &fixture.recipient),
        Err(PrivateMessageError::Open)
    ));
}

#[test]
fn zero_and_maximum_messages_roundtrip_with_fresh_names_and_encapsulation() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    for length in [0, MAX_PRIVATE_MESSAGE_BYTES] {
        let plaintext = Zeroizing::new(vec![0x65; length]);
        let first = fixture
            .publish(&plaintext, &mut store)
            .verify(&fixture.sender.verifying_key(), 101)
            .expect("first sender");
        let second = fixture
            .publish(&plaintext, &mut store)
            .verify(&fixture.sender.verifying_key(), 101)
            .expect("second sender");
        assert_ne!(first.metadata().name, second.metadata().name);
        assert_ne!(first.chunks()[0].id(), second.chunks()[0].id());
        assert!(first.length() > length as u64);
        assert!(first.length() < length as u64 + 64);
        let output = open_private_message(&first, &mut [&mut store], 101, &fixture.recipient)
            .expect("boundary plaintext");
        assert_eq!(output.as_slice(), plaintext.as_slice());
    }
    let oversized = Zeroizing::new(vec![0; MAX_PRIVATE_MESSAGE_BYTES + 1]);
    let usage = store.usage();
    assert!(matches!(
        publish_private_message(
            &oversized,
            fixture.recipient.public_key(),
            &fixture.sender,
            VALIDITY,
            &mut store,
        ),
        Err(PrivateMessageError::TooLarge)
    ));
    assert_eq!(store.usage(), usage);
}

#[test]
fn noncanonical_envelope_and_invalid_validity_never_return_plaintext() {
    let fixture = Fixture::new();
    let mut store = fixture.store();
    let signed = fixture.publish(b"canonical envelope", &mut store);
    let manifest = signed
        .verify(&fixture.sender.verifying_key(), 101)
        .expect("sender");
    let mut ciphertext = Vec::new();
    reassemble(&manifest, &mut [&mut store], 101, &mut ciphertext).expect("ciphertext only");
    ciphertext.extend([0x20, 1]); // Unknown field 4: bounded protobuf decode is not sufficient.
    let mut publication = publication_from(&manifest);
    publication.length = ciphertext.len() as u64;
    let replacement = publish(
        &mut ciphertext.as_slice(),
        publication,
        &fixture.sender,
        &mut store,
    )
    .expect("signed noncanonical envelope")
    .verify(&fixture.sender.verifying_key(), 101)
    .expect("valid outer signature");
    assert!(matches!(
        open_private_message(&replacement, &mut [&mut store], 101, &fixture.recipient),
        Err(PrivateMessageError::InvalidEnvelope)
    ));
    let usage = store.usage();
    assert!(matches!(
        publish_private_message(
            b"not stored",
            fixture.recipient.public_key(),
            &fixture.sender,
            Validity {
                created: 200,
                expires: 100
            },
            &mut store,
        ),
        Err(PrivateMessageError::Content(Error::InvalidManifest))
    ));
    assert_eq!(store.usage(), usage);
}

struct Fixture {
    root: tempfile::TempDir,
    sender: SigningKey,
    recipient: RecipientKeyPair,
}

impl Fixture {
    fn new() -> Self {
        Self {
            root: tempfile::tempdir().expect("root"),
            sender: SigningKey::generate(&mut rand_core::OsRng),
            recipient: RecipientKeyPair::generate().expect("recipient key"),
        }
    }

    fn store(&self) -> ChunkStore {
        ChunkStore::create(&self.root.path().join("store"), limits()).expect("ciphertext store")
    }

    fn publish(&self, plaintext: &[u8], store: &mut ChunkStore) -> SignedManifest {
        publish_private_message(
            plaintext,
            self.recipient.public_key(),
            &self.sender,
            VALIDITY,
            store,
        )
        .expect("encrypted publication")
    }
}

fn provisioned_recipient() -> RecipientKeyPair {
    let mut secret = Zeroizing::new([0; 32]);
    getrandom::fill(&mut *secret).expect("explicit caller-owned CSPRNG key material");
    RecipientKeyPair::from_private_key(secret).expect("explicit X25519 key import")
}

fn limits() -> CacheLimits {
    CacheLimits {
        max_bytes: 20 * 1024 * 1024,
        max_entries: 100,
        min_free_bytes: 0,
    }
}

fn publication_from(manifest: &VerifiedManifest) -> Publication {
    Publication {
        metadata: manifest.metadata().clone(),
        length: manifest.length(),
        validity: manifest.validity(),
    }
}

fn alternate_hex(name: &str) -> &'static str {
    if name.starts_with('0') { "1" } else { "0" }
}
