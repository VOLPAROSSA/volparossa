use super::*;
use crate::{
    CacheLimits, ChunkStore, Metadata, Publication, Validity,
    object_policy::{ObjectPolicyGate, ObjectRule, ObjectSubject},
    provider::custody_storage::PublicCustodyStore,
    publish, reassemble,
};
use ed25519_dalek::SigningKey;

struct Fixture {
    _directory: tempfile::TempDir,
    registry: PublicationRegistry,
    source: ChunkStore,
    custody: PublicCustodyStore,
    publisher: SigningKey,
    at: u64,
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::tempdir().unwrap();
        let limits = CacheLimits {
            max_bytes: 4096,
            max_entries: 8,
            min_free_bytes: 0,
        };
        let root = directory.path().join("custody");
        drop(ChunkStore::create(&root, limits).unwrap());
        let source = ChunkStore::create(&directory.path().join("source"), limits).unwrap();
        let custody = PublicCustodyStore::open(root, limits).unwrap();
        let mut registry = PublicationRegistry::new();
        registry.set_name_lookup(true);
        Self {
            _directory: directory,
            registry,
            source,
            custody,
            publisher: SigningKey::generate(&mut rand_core::OsRng),
            at: now().unwrap(),
        }
    }

    fn add(&mut self, bytes: &[u8]) -> SignedManifest {
        let signed = publish(
            &mut &bytes[..],
            Publication {
                length: u64::try_from(bytes.len()).unwrap(),
                metadata: Metadata {
                    name: "authority-inbox".into(),
                    revision: 1,
                    content_type: "application/octet-stream".into(),
                },
                validity: Validity {
                    created: self.at,
                    expires: self.at + 60,
                },
            },
            &self.publisher,
            &mut self.source,
        )
        .unwrap();
        let manifest = signed
            .verify(&self.publisher.verifying_key(), self.at)
            .unwrap();
        self.custody
            .admit(&signed, &manifest, &mut self.source, self.at)
            .unwrap();
        self.custody
            .register_complete(&mut self.registry, self.at)
            .unwrap();
        signed
    }

    fn query(&self, revision: u64) -> NameQuery {
        NameQuery::new(
            self.publisher.verifying_key().to_bytes(),
            "authority-inbox",
            revision,
        )
        .unwrap()
    }
}

#[test]
fn local_registry_reads_original_custody_without_download_name_index() {
    let mut fixture = Fixture::new();
    let bytes = b"public assessment request, no copied private key";
    let signed = fixture.add(bytes);
    let query = fixture.query(1);
    let NameResolution::Candidate(selected) = fixture
        .registry
        .resolve_local_name(&query, fixture.at)
        .unwrap()
    else {
        panic!("local custody candidate");
    };
    assert_eq!(selected.signed().encode(), signed.encode());
    let mut local = fixture
        .registry
        .open_local_candidate(&selected, fixture.at)
        .unwrap();
    let mut actual = Vec::new();
    reassemble(
        selected.manifest(),
        &mut [&mut local],
        fixture.at,
        &mut actual,
    )
    .unwrap();
    assert_eq!(actual, bytes);
    drop(local);
    assert!(matches!(
        fixture
            .registry
            .resolve_local_name(&fixture.query(2), fixture.at)
            .unwrap(),
        NameResolution::Missing
    ));
    assert!(matches!(
        fixture
            .registry
            .resolve_local_name(&query, fixture.at + 60)
            .unwrap(),
        NameResolution::Missing
    ));
    assert!(
        fixture
            .registry
            .open_local_candidate(&selected, fixture.at + 60)
            .is_err()
    );
    fixture.registry.set_name_lookup(false);
    assert!(matches!(
        fixture
            .registry
            .resolve_local_name(&query, fixture.at)
            .unwrap(),
        NameResolution::Missing
    ));
    assert!(
        fixture
            .registry
            .open_local_candidate(&selected, fixture.at)
            .is_err()
    );
}

#[test]
fn local_registry_preserves_conflicts_and_live_withdrawal() {
    let mut fixture = Fixture::new();
    fixture.add(b"first original request");
    let query = fixture.query(1);
    let NameResolution::Candidate(selected) = fixture
        .registry
        .resolve_local_name(&query, fixture.at)
        .unwrap()
    else {
        panic!("candidate");
    };
    fixture.add(b"conflicting original request");
    assert!(matches!(
        fixture
            .registry
            .resolve_local_name(&query, fixture.at)
            .unwrap(),
        NameResolution::Conflict(_)
    ));
    let gate = ObjectPolicyGate::default();
    fixture.registry.set_object_policy_gate(gate.clone());
    gate.install(ObjectRule {
        subject: ObjectSubject::from_manifest(selected.manifest()),
        policy_hash: [1; 32],
        allow: false,
        expires_at_ms: (fixture.at + 60) * 1000,
    })
    .unwrap();
    assert!(
        fixture
            .registry
            .open_local_candidate(&selected, fixture.at)
            .is_err()
    );
}
