use super::*;
use ed25519_dalek::SigningKey;
use serde_json::json;
use std::os::unix::fs::PermissionsExt as _;
use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity, publish};
use volparossa_policy::object::{ObjectDecision, ObjectSubject as DecisionSubject};
use volparossa_policy::{
    ManifestSpec, PolicyMode, TrustStore, TrustedMaintainer, VerificationPolicy, sign_manifest,
};

struct Fixture {
    directory: tempfile::TempDir,
    keys: Vec<SigningKey>,
    config: Config,
    trust_path: PathBuf,
    epoch: VerifiedManifest,
    subject: volparossa_content::VerifiedManifest,
}

fn write(path: &Path, bytes: &[u8]) {
    let mut file = OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

impl Fixture {
    fn new() -> Self {
        let directory = tempfile::Builder::new()
            .permissions(fs::Permissions::from_mode(0o700))
            .tempdir()
            .unwrap();
        let keys: Vec<_> = (1_u8..=5)
            .map(|value| SigningKey::from_bytes(&[value; 32]))
            .collect();
        let trust = TrustStore::new(
            PolicyMode::Production,
            keys.iter()
                .map(|key| TrustedMaintainer::production(key.verifying_key()))
                .collect(),
        )
        .unwrap();
        let trust_path = directory.path().join("trust.json");
        write(&trust_path, &trust_bytes(&keys));
        let epoch_bytes = sign_manifest(
            &ManifestSpec::new(7, 2, 1000, 1000, 20_000).unwrap(),
            &trust,
            &[&keys[0], &keys[1], &keys[2]],
        )
        .unwrap();
        let epoch =
            verify_manifest(&epoch_bytes, 2000, &trust, VerificationPolicy::default()).unwrap();
        let epoch_path = directory.path().join("epoch.pb");
        write(&epoch_path, &epoch_bytes);
        let mut config = Config::default();
        config.policy.manifest_path = epoch_path.to_str().unwrap().into();
        let mut cache = ChunkStore::create(
            &directory.path().join("cache"),
            CacheLimits {
                max_bytes: 1024 * 1024,
                max_entries: 16,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let bytes = b"explicit public subject";
        let subject = publish(
            &mut bytes.as_slice(),
            Publication {
                metadata: Metadata {
                    name: "object-policy-test".into(),
                    revision: 1,
                    content_type: "text/plain".into(),
                },
                length: bytes.len() as u64,
                validity: Validity {
                    created: 1,
                    expires: 30,
                },
            },
            &keys[4],
            &mut cache,
        )
        .unwrap()
        .verify(&keys[4].verifying_key(), 2)
        .unwrap();
        Self {
            directory,
            keys,
            config,
            trust_path,
            epoch,
            subject,
        }
    }

    fn owner(
        &self,
        gate: ObjectPolicyGate,
        current: Option<&VerifiedManifest>,
    ) -> Result<ObjectPolicyOwner, ContentError> {
        ObjectPolicyOwner::load(
            &self.config,
            &self.trust_path,
            self.directory.path(),
            current,
            gate,
        )
    }

    fn body(&self, revision: u64, outcome: ObjectOutcome) -> ObjectDecision {
        ObjectDecision {
            policy_hash: *self.epoch.policy_hash(),
            policy_version: self.epoch.manifest_version(),
            decision_revision: revision,
            subject: DecisionSubject {
                publisher_key: *self.subject.publisher(),
                manifest_id: *self.subject.manifest_id(),
                object_sha256: *self.subject.object_sha256(),
            },
            framework_sha256: [10; 32],
            evidence_sha256: [11; 32],
            outcome,
            issued_at_ms: 2000,
            expires_at_ms: 10_000,
            nonce: [12; 32],
        }
    }

    fn sign(&self, body: ObjectDecision) -> Vec<u8> {
        let mut proposal = SignedObjectDecision::new(body).unwrap();
        for key in &self.keys[..3] {
            proposal.endorse(key).unwrap();
        }
        proposal.encode().unwrap()
    }

    fn journal(&self) -> Vec<u8> {
        fs::read(self.directory.path().join("object-policy/journal.json")).unwrap()
    }
}

fn trust_bytes(keys: &[SigningKey]) -> Vec<u8> {
    serde_json::to_vec(
        &json!({"schema_version":1,"maintainers":keys.iter().map(|key| json!({
        "public_key_hex":hex::encode(key.verifying_key().to_bytes()),"environment":"production"
    })).collect::<Vec<_>>()}),
    )
    .unwrap()
}

#[test]
fn original_deny_and_revision_floor_survive_restart_and_retry_preserves_bytes() {
    let fixture = Fixture::new();
    let gate = ObjectPolicyGate::default();
    let owner = fixture.owner(gate.clone(), Some(&fixture.epoch)).unwrap();
    let deny = fixture.sign(fixture.body(3, ObjectOutcome::Deny));
    let receipt = owner.apply_at(&deny, &fixture.epoch, 3000).unwrap();
    assert_eq!(receipt.body().decision_revision, 3);
    assert!(!gate.allows(&fixture.subject, 3000));
    let retained = fixture.journal();
    owner.apply_at(&deny, &fixture.epoch, 4000).unwrap();
    assert_eq!(fixture.journal(), retained);
    drop(owner);
    let restored_gate = ObjectPolicyGate::default();
    let owner = fixture
        .owner(restored_gate.clone(), Some(&fixture.epoch))
        .unwrap();
    assert!(!restored_gate.allows(&fixture.subject, 4000));
    assert!(
        owner
            .apply_at(
                &fixture.sign(fixture.body(2, ObjectOutcome::Allow)),
                &fixture.epoch,
                4000
            )
            .is_err()
    );
    assert!(
        owner
            .apply_at(
                &fixture.sign(fixture.body(3, ObjectOutcome::Allow)),
                &fixture.epoch,
                4000
            )
            .is_err()
    );
    assert_eq!(fixture.journal(), retained);
    owner
        .apply_at(
            &fixture.sign(fixture.body(4, ObjectOutcome::Allow)),
            &fixture.epoch,
            4000,
        )
        .unwrap();
    assert!(restored_gate.allows(&fixture.subject, 4000));
}

#[test]
fn expired_or_other_epoch_allow_is_restored_as_withheld_never_renewed() {
    let fixture = Fixture::new();
    let owner = fixture
        .owner(ObjectPolicyGate::default(), Some(&fixture.epoch))
        .unwrap();
    owner
        .apply_at(
            &fixture.sign(fixture.body(1, ObjectOutcome::Allow)),
            &fixture.epoch,
            3000,
        )
        .unwrap();
    drop(owner);
    let gate = ObjectPolicyGate::default();
    let owner = fixture.owner(gate.clone(), Some(&fixture.epoch)).unwrap();
    assert!(gate.allows(&fixture.subject, 9999));
    assert!(!gate.allows(&fixture.subject, 10_000));
    drop(owner);
    let gate = ObjectPolicyGate::default();
    let owner = fixture.owner(gate.clone(), None).unwrap();
    assert!(!gate.allows(&fixture.subject, 3000));
    assert!(
        owner
            .apply_at(
                &fixture.sign(fixture.body(2, ObjectOutcome::Allow)),
                &fixture.epoch,
                3000
            )
            .is_err()
    );
}

#[test]
fn subject_substitution_current_epoch_mismatch_and_unsigned_update_cannot_activate() {
    let fixture = Fixture::new();
    let gate = ObjectPolicyGate::default();
    let owner = fixture.owner(gate.clone(), Some(&fixture.epoch)).unwrap();
    owner
        .apply_at(
            &fixture.sign(fixture.body(1, ObjectOutcome::Deny)),
            &fixture.epoch,
            3000,
        )
        .unwrap();
    let retained = fixture.journal();
    let mut changed = fixture.body(2, ObjectOutcome::Allow);
    changed.subject.object_sha256 = [90; 32];
    assert!(
        owner
            .apply_at(&fixture.sign(changed), &fixture.epoch, 3000)
            .is_err()
    );
    let unsigned = SignedObjectDecision::new(fixture.body(2, ObjectOutcome::Allow))
        .unwrap()
        .encode()
        .unwrap();
    assert!(owner.apply_at(&unsigned, &fixture.epoch, 3000).is_err());
    gate.set_epoch(Some([91; 32]));
    assert!(
        owner
            .apply_at(
                &fixture.sign(fixture.body(2, ObjectOutcome::Allow)),
                &fixture.epoch,
                3000
            )
            .is_err()
    );
    assert_eq!(fixture.journal(), retained);
    assert!(!gate.allows(&fixture.subject, 3000));
}

#[test]
fn incompatible_configured_trust_or_missing_committed_journal_fails_closed() {
    let fixture = Fixture::new();
    let owner = fixture
        .owner(ObjectPolicyGate::default(), Some(&fixture.epoch))
        .unwrap();
    owner
        .apply_at(
            &fixture.sign(fixture.body(1, ObjectOutcome::Deny)),
            &fixture.epoch,
            3000,
        )
        .unwrap();
    assert!(matches!(
        fixture.owner(ObjectPolicyGate::default(), Some(&fixture.epoch)),
        Err(ContentError::Busy)
    ));
    let different: Vec<_> = (20_u8..25)
        .map(|value| SigningKey::from_bytes(&[value; 32]))
        .collect();
    write(&fixture.trust_path, &trust_bytes(&different));
    let changed_trust = TrustStore::new(
        PolicyMode::Production,
        different
            .iter()
            .map(|key| TrustedMaintainer::production(key.verifying_key()))
            .collect(),
    )
    .unwrap();
    let changed_epoch = sign_manifest(
        &ManifestSpec::new(8, 2, 1000, 1000, 20_000).unwrap(),
        &changed_trust,
        &[&different[0], &different[1], &different[2]],
    )
    .unwrap();
    let current = verify_manifest(
        &changed_epoch,
        3000,
        &changed_trust,
        VerificationPolicy::default(),
    )
    .unwrap();
    write(
        Path::new(&fixture.config.policy.manifest_path),
        &changed_epoch,
    );
    let mut proposal = SignedObjectDecision::new(ObjectDecision {
        policy_hash: *current.policy_hash(),
        policy_version: 8,
        ..fixture.body(2, ObjectOutcome::Allow)
    })
    .unwrap();
    for key in &different[..3] {
        proposal.endorse(key).unwrap();
    }
    owner.gate.set_epoch(Some(*current.policy_hash()));
    let retained = fixture.journal();
    assert!(
        owner
            .apply_at(&proposal.encode().unwrap(), &current, 3000)
            .is_err()
    );
    assert_eq!(fixture.journal(), retained);
    drop(owner);
    assert!(
        fixture
            .owner(ObjectPolicyGate::default(), Some(&fixture.epoch))
            .is_err()
    );
    write(&fixture.trust_path, &trust_bytes(&fixture.keys));
    fs::remove_file(fixture.directory.path().join("object-policy/journal.json")).unwrap();
    assert!(fixture.owner(ObjectPolicyGate::default(), None).is_err());
}

#[test]
fn empty_startup_needs_no_active_authority_and_quota_never_discards_prior_entries() {
    let directory = tempfile::Builder::new()
        .permissions(fs::Permissions::from_mode(0o700))
        .tempdir()
        .unwrap();
    let owner = ObjectPolicyOwner::load(
        &Config::default(),
        &directory.path().join("missing-trust.json"),
        directory.path(),
        None,
        ObjectPolicyGate::default(),
    )
    .unwrap();
    let previous = fs::read(owner.directory.join(JOURNAL)).unwrap();
    let excessive = Journal {
        version: 1,
        entries: vec![
            Entry {
                envelope_hex: "00".into(),
                epoch_manifest_hex: "00".into()
            };
            MAX_OBJECT_POLICY_RULES + 1
        ],
    };
    assert!(matches!(
        persist(&owner.directory, &owner.directory_file, &excessive),
        Err(ContentError::Busy)
    ));
    assert_eq!(fs::read(owner.directory.join(JOURNAL)).unwrap(), previous);
}
