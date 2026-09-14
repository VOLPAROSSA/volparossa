//! Native catalog signatures and actual coordinator-store checkpoints; no network or model run.

use std::{fs, os::unix::fs::PermissionsExt as _};

use ed25519_dalek::SigningKey;
use volparossa_content::{CacheLimits, ChunkStore, Metadata, Publication, Validity};

use super::*;

struct Fixture {
    root: tempfile::TempDir,
    cache: ChunkStore,
    key: SigningKey,
    time: u64,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let cache = ChunkStore::create(
            &root.path().join("native-cache"),
            CacheLimits {
                max_bytes: 4 * 1024 * 1024,
                max_entries: 64,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        Self {
            root,
            cache,
            key: SigningKey::from_bytes(&[91; 32]),
            time: now().unwrap(),
        }
    }

    fn source(&self, name: &str) -> Source {
        Source {
            publisher_key: hex::encode(self.key.verifying_key().as_bytes()),
            name: name.into(),
            min_revision: Some(1),
            manifest_id: None,
        }
    }

    fn plan(&self) -> Plan {
        Plan {
            version: 2,
            sources: vec![self.source("static-explicit")],
            catalogs: vec![self.source("public-training-feed")],
        }
    }

    fn snapshot(&mut self, name: &str, revision: u64, rows: &[Value]) -> Snapshot {
        let body = json!({"version":1,"visibility":"public","purpose":"agent_training",
            "dataset_profile":volparossa_content::provider::compute::dataset::CONTENT_TYPE,
            "license":"GPL-3.0-only","sources":rows})
        .to_string();
        let signed = volparossa_content::publish(
            &mut body.as_bytes(),
            Publication {
                metadata: Metadata {
                    name: name.into(),
                    revision,
                    content_type: source_catalog::CONTENT_TYPE.into(),
                },
                length: body.len() as u64,
                validity: Validity {
                    created: self.time - 60,
                    expires: self.time + 600,
                },
            },
            &self.key,
            &mut self.cache,
        )
        .unwrap();
        let verified = signed.verify(&self.key.verifying_key(), self.time).unwrap();
        Snapshot {
            revision,
            manifest_id: hex::encode(verified.manifest_id()),
            expires: verified.validity().expires,
            verified_at: self.time,
            signed_manifest_hex: hex::encode(signed.encode()),
            body,
            receipt: json!({"synthetic_catalog_fixture_not_network_or_training":true}),
        }
    }
}

fn row(name: &str, revision: u64, byte: u8) -> Value {
    json!({"name":name,"revision":revision,"manifest_id":hex::encode([byte;32])})
}

fn encoded(registry: &Registry) -> Value {
    serde_json::to_value(registry).unwrap()
}

#[test]
fn real_signed_catalog_updates_keep_stable_slots_and_reopen_exact_owned_store() {
    let mut fixture = Fixture::new();
    let mut plan = fixture.plan();
    plan.catalogs[0].publisher_key.make_ascii_uppercase();
    let mut registry = Registry::new(&plan).unwrap();
    let first = fixture.snapshot("public-training-feed", 1, &[row("new-a", 4, 1)]);
    registry
        .accept(&plan, 0, first, None, fixture.time)
        .unwrap();
    assert_eq!(registry.static_count(), 1);
    assert_eq!(registry.sources(&plan)[1].name, "new-a");
    let second = fixture.snapshot(
        "public-training-feed",
        2,
        &[row("new-b", 1, 2), row("new-a", 5, 3)],
    );
    registry
        .accept(&plan, 0, second, None, fixture.time)
        .unwrap();
    let pool = registry.sources(&plan);
    assert_eq!(
        pool.iter()
            .map(|source| source.name.as_str())
            .collect::<Vec<_>>(),
        ["static-explicit", "new-a", "new-b"]
    );
    assert_eq!(pool[1].min_revision, Some(5));
    let runtime = Plan {
        version: 2,
        sources: pool,
        catalogs: plan.catalogs.clone(),
    };
    let proof = registry.proof_for(&runtime, 1).unwrap();
    assert_eq!(proof["selected_source"]["name"], "new-a");
    assert_eq!(
        proof["selected_source"]["manifest_id"],
        hex::encode([3; 32])
    );
    assert_eq!(proof["catalog_revision"], 2);
    assert_eq!(
        proof["catalog_publisher_key"],
        hex::encode(fixture.key.verifying_key().as_bytes())
    );
    assert!(registry.proof_for(&runtime, 0).is_none());
    let directory = fixture.root.path().join("coordinator");
    let enrollment = json!({"version":2,"catalog_fixture":plan.catalogs});
    let store = Store::open(&directory, &enrollment, false).unwrap();
    store.save_state(&encoded(&registry)).unwrap();
    drop(store);
    let reopened = Store::open(&directory, &enrollment, true).unwrap();
    let retained: Registry =
        serde_json::from_value(reopened.load_state().unwrap().unwrap()).unwrap();
    retained.validate(&plan, fixture.time).unwrap();
    assert_eq!(encoded(&retained), encoded(&registry));
    assert!(retained.eligible(1, 2, fixture.time));
    assert!(!retained.eligible(0, 2, fixture.time));
    assert_eq!(retained.proof_for(&runtime, 1).unwrap(), proof);
}

#[test]
fn withdrawal_expiry_and_reappearance_preserve_source_highwater_and_reject_forks() {
    let mut fixture = Fixture::new();
    let plan = fixture.plan();
    let mut registry = Registry::new(&plan).unwrap();
    let original = fixture.snapshot("public-training-feed", 1, &[row("new-a", 4, 1)]);
    registry
        .accept(&plan, 0, original.clone(), None, fixture.time)
        .unwrap();
    let before = encoded(&registry);
    let fork = fixture.snapshot("public-training-feed", 1, &[row("new-b", 1, 2)]);
    assert!(registry.accept(&plan, 0, fork, None, fixture.time).is_err());
    assert_eq!(encoded(&registry), before);
    let withdrawal = fixture.snapshot("public-training-feed", 2, &[]);
    registry
        .accept(&plan, 0, withdrawal, None, fixture.time)
        .unwrap();
    assert_eq!(registry.sources(&plan).len(), 2);
    assert_eq!(registry.sources(&plan)[1].min_revision, Some(4));
    assert!(!registry.eligible(1, 1, fixture.time));
    assert!(registry.proof_for(&plan, 1).is_none());
    assert!(
        registry
            .accept(&plan, 0, original, None, fixture.time)
            .is_err()
    );
    for entry in [row("new-a", 3, 3), row("new-a", 4, 4)] {
        let before = encoded(&registry);
        let invalid = fixture.snapshot("public-training-feed", 3, &[entry]);
        assert!(
            registry
                .accept(&plan, 0, invalid, None, fixture.time)
                .is_err()
        );
        assert_eq!(encoded(&registry), before);
    }
    let fresh = fixture.snapshot("public-training-feed", 3, &[row("new-a", 5, 5)]);
    registry
        .accept(&plan, 0, fresh, None, fixture.time)
        .unwrap();
    assert_eq!(registry.sources(&plan).len(), 2);
    assert!(registry.eligible(1, 1, fixture.time));
    registry.validate(&plan, fixture.time + 600).unwrap();
    assert!(!registry.eligible(1, 1, fixture.time + 600));
    assert!(registry.eligible(1, 0, fixture.time + 600));
}

#[test]
fn admission_is_atomic_for_static_validation_other_feed_and_retained_snapshot_conflicts() {
    let mut fixture = Fixture::new();
    let mut plan = fixture.plan();
    plan.catalogs.push(fixture.source("other-enrolled-feed"));
    let mut registry = Registry::new(&plan).unwrap();
    for entries in [
        vec![row("new-a", 1, 1), row("static-explicit", 1, 2)],
        vec![row("new-a", 1, 1), row("evaluation-only", 1, 2)],
    ] {
        let snapshot = fixture.snapshot("public-training-feed", 1, &entries);
        let before = encoded(&registry);
        let validation = Source {
            manifest_id: Some(hex::encode([2; 32])),
            ..fixture.source("evaluation-only")
        };
        assert!(
            registry
                .accept(&plan, 0, snapshot, Some(&validation), fixture.time)
                .is_err()
        );
        assert_eq!(encoded(&registry), before);
    }
    let source = fixture.snapshot("public-training-feed", 1, &[row("new-a", 1, 1)]);
    registry
        .accept(&plan, 0, source, None, fixture.time)
        .unwrap();
    let other = fixture.snapshot("other-enrolled-feed", 1, &[row("new-a", 1, 1)]);
    let before = encoded(&registry);
    assert!(
        registry
            .accept(&plan, 1, other, None, fixture.time)
            .is_err()
    );
    assert_eq!(encoded(&registry), before);
    let mut altered = registry.clone();
    altered.slots[0].source.manifest_id = Some(hex::encode([99; 32]));
    assert!(altered.validate(&plan, fixture.time).is_err());
    let mut altered = registry.clone();
    altered.feeds[0].snapshot.as_mut().unwrap().body.push(' ');
    assert!(altered.validate(&plan, fixture.time).is_err());
    let mut altered = registry.clone();
    altered.feeds[0].snapshot.as_mut().unwrap().verified_at = fixture.time + 1;
    assert!(altered.validate(&plan, fixture.time).is_err());
    let mut changed_plan = plan.clone();
    changed_plan.catalogs[0].publisher_key =
        hex::encode(SigningKey::from_bytes(&[92; 32]).verifying_key().as_bytes());
    assert!(registry.validate(&changed_plan, fixture.time).is_err());
}

#[test]
fn full_registry_refuses_entire_update_without_evicting_prior_source_progress() {
    let mut fixture = Fixture::new();
    let plan = fixture.plan();
    let mut registry = Registry::new(&plan).unwrap();
    let mut rows: Vec<_> = (0..MAX_SOURCES - 1)
        .map(|index| row(&format!("public-{index:03}"), 1, 1))
        .collect();
    let first = fixture.snapshot("public-training-feed", 1, &rows);
    registry
        .accept(&plan, 0, first, None, fixture.time)
        .unwrap();
    assert_eq!(registry.sources(&plan).len(), MAX_SOURCES);
    rows.push(row("one-extra-source", 1, 2));
    let before = encoded(&registry);
    let too_many = fixture.snapshot("public-training-feed", 2, &rows);
    let error = registry
        .accept(&plan, 0, too_many, None, fixture.time)
        .unwrap_err();
    assert_eq!(error.to_string(), "train_catalog_registry_capacity");
    assert_eq!(encoded(&registry), before);
    assert!(registry.eligible(1, MAX_SOURCES - 1, fixture.time));
    registry.validate(&plan, fixture.time).unwrap();
}
