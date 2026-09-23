//! Real signed publications and synthetic comparison receipts; never model-execution proof.

use super::*;
use clap::Parser as _;
use std::{io::Write as _, os::unix::fs::OpenOptionsExt as _};
use volparossa_content::{
    CacheLimits, ChunkStore, Metadata, Publication, Validity,
    agent_artifact::{
        ADAPTER_CONTENT_TYPE, AdapterFiles, BASE_MODEL_SHA256, MODEL_ID, MODEL_REVISION,
    },
};

fn write(path: &Path, bytes: &[u8]) {
    let mut file = fs::OpenOptions::new()
        .write(true)
        .create(true)
        .truncate(true)
        .mode(0o600)
        .open(path)
        .unwrap();
    file.write_all(bytes).unwrap();
}

fn json_file(path: &Path, value: &Value) {
    write(path, &serde_json::to_vec(value).unwrap());
}

fn directory(path: &Path) {
    fs::DirBuilder::new().mode(0o700).create(path).unwrap();
}

struct Fixture {
    _root: tempfile::TempDir,
    args: Options,
    store: Store,
    state: State,
    cache: ChunkStore,
    key: ed25519_dalek::SigningKey,
    at: u64,
    dataset: Vec<u8>,
    signed: Vec<u8>,
    source: Source,
    enrollment: Value,
}

impl Fixture {
    fn new() -> Self {
        let root = tempfile::tempdir().unwrap();
        fs::set_permissions(root.path(), fs::Permissions::from_mode(0o700)).unwrap();
        let mut argv = vec![
            "volparossa".to_owned(),
            "compute".into(),
            "train-loop".into(),
        ];
        for (flag, name) in [
            ("--plan", "plan"),
            ("--directory", "loop"),
            ("--runtime-root", "runtime"),
            ("--model-root", "model"),
            ("--cache", "cache"),
        ] {
            argv.extend([flag.into(), root.path().join(name).to_str().unwrap().into()]);
        }
        let crate::CliCommand::Compute {
            command: crate::compute::Command::TrainLoop(args),
        } = crate::Cli::try_parse_from(argv).unwrap().command
        else {
            panic!("options")
        };
        let key = ed25519_dalek::SigningKey::from_bytes(&[83; 32]);
        let channel = Channel {
            publisher_key: hex::encode(key.verifying_key().as_bytes()),
            name: "rollback-adapter".into(),
            min_revision: Some(1),
        };
        let enrollment = json!({"peer_updates":{"version":1,"channels":[channel]}});
        let store = Store::open(&args.directory, &enrollment, false).unwrap();
        let mut state = State::new(1);
        state.peer_updates = Some(Registry {
            version: 1,
            next_sequence: 1,
            cursor: 0,
            feeds: vec![Feed {
                channel,
                revision: None,
                manifest_id: None,
                processed_manifest: None,
                next_poll: 0,
            }],
            pending: None,
            completed: vec![],
            active: None,
            garbage: vec![],
        });
        let cache = ChunkStore::create(
            &root.path().join("signed-cache"),
            CacheLimits {
                max_bytes: 16 * 1024 * 1024,
                max_entries: 64,
                min_free_bytes: 0,
            },
        )
        .unwrap();
        let at = now().unwrap();
        let dataset = serde_json::to_vec(&json!({"version":1,"visibility":"public","license":"GPL-3.0-only","source_revision":"a".repeat(40),"train":[],
            "heldout":[{"question":"Was a model executed?","context":"Synthetic receipt fixture.","answer":"No."}],
            "inference":[{"question":"What is this?","context":"Synthetic receipt fixture."}]})).unwrap();
        let source = Source {
            publisher_key: hex::encode(key.verifying_key().as_bytes()),
            name: "rollback-source".into(),
            min_revision: Some(1),
            manifest_id: None,
        };
        let mut result = Self {
            _root: root,
            args: *args,
            store,
            state,
            cache,
            key,
            at,
            dataset,
            signed: vec![],
            source,
            enrollment,
        };
        result.signed = result.sign(
            &result.dataset.clone(),
            "rollback-source",
            1,
            dataset::CONTENT_TYPE,
            at + 1200,
        );
        result.source.manifest_id = Some(hex::encode(Sha256::digest(&result.signed)));
        result
    }

    fn sign(
        &mut self,
        bytes: &[u8],
        name: &str,
        revision: u64,
        mime: &str,
        expires: u64,
    ) -> Vec<u8> {
        volparossa_content::publish(
            &mut &bytes[..],
            Publication {
                metadata: Metadata {
                    name: name.into(),
                    revision,
                    content_type: mime.into(),
                },
                length: bytes.len() as u64,
                validity: Validity {
                    created: self.at - 60,
                    expires,
                },
            },
            &self.key,
            &mut self.cache,
        )
        .unwrap()
        .encode()
    }

    fn receipt(&self, signed: &[u8]) -> Value {
        let verified = SignedManifest::decode(signed)
            .unwrap()
            .verify(&self.key.verifying_key(), self.at - 20)
            .unwrap();
        json!({"manifest_id":hex::encode(verified.manifest_id()),"sha256":hex::encode(verified.object_sha256()),"bytes":verified.length(),"chunks":verified.chunks().len()})
    }

    #[allow(clippy::too_many_lines)] // One explicitly inert but fully source/receipt-bound adoption fixture.
    fn approve(&mut self, expires: u64) {
        let id = self.state.peer_updates.as_ref().unwrap().next_sequence;
        let previous = active(
            &self.args,
            self.state.peer_updates.as_ref().unwrap(),
            self.state.latest,
        )
        .unwrap();
        let baseline_origin = previous
            .as_ref()
            .map_or(json!({"kind":"pinned_base"}), |value| value.origin.clone());
        let baseline_path = previous.as_ref().map(|value| value.adapter_root.clone());
        let baseline_files = baseline_path
            .as_deref()
            .map(super::super::super::peer_evaluation::adapter_files)
            .transpose()
            .unwrap();
        let root = round_root(&self.args, id).unwrap();
        directory(&root);
        for name in [
            "pending",
            "import",
            "import/adapter",
            "comparison",
            "comparison/baseline",
            "comparison/candidate",
        ] {
            directory(&root.join(name));
        }
        let contents = format!("synthetic adapter {id}; no executable tensors").into_bytes();
        let bundle = AdapterBundle::encode(
            self.source.manifest().unwrap().unwrap(),
            AdapterFiles {
                readme: contents.clone(),
                config: contents.clone(),
                weights: contents.clone(),
            },
        )
        .unwrap();
        let signed = self.sign(
            &bundle,
            "rollback-adapter",
            id,
            ADAPTER_CONTENT_TYPE,
            expires,
        );
        let manifest_id = hex::encode(Sha256::digest(&signed));
        let adapter_receipt = self.receipt(&signed);
        let pending = json!({"version":1,"operation":"peer_update_pending","adapter":{
            "publisher_key":self.source.publisher_key,"name":"rollback-adapter","revision":id,"manifest_id":manifest_id,
            "manifest_sha256":hex::encode(Sha256::digest(&signed)),"sha256":hex::encode(Sha256::digest(&bundle)),"bytes":bundle.len(),
            "dataset_manifest_id":self.source.manifest_id,"expires_unix_seconds":expires},"adapter_receipt":adapter_receipt,
            "expires_unix_seconds":expires,"model_activated":false,"model_quality_proven":false,"private_data_supported":false});
        for prefix in ["pending", "import"] {
            write(&root.join(prefix).join("adapter.bundle"), &bundle);
            write(&root.join(prefix).join("adapter.manifest"), &signed);
        }
        json_file(&root.join("pending/provenance.json"), &pending);
        let mut imported = pending;
        imported["operation"] = "peer_update_import".into();
        imported["dataset"] = json!({"publisher_key":self.source.publisher_key,"name":self.source.name,"revision":1,
            "manifest_id":self.source.manifest_id,"manifest_sha256":hex::encode(Sha256::digest(&self.signed)),
            "sha256":hex::encode(Sha256::digest(&self.dataset)),"bytes":self.dataset.len(),"expires_unix_seconds":self.at+1200});
        imported["dataset_receipt"] = self.receipt(&self.signed);
        json_file(&root.join("import/provenance.json"), &imported);
        for prefix in ["import", "comparison"] {
            write(&root.join(prefix).join("dataset.json"), &self.dataset);
            write(&root.join(prefix).join("dataset.manifest"), &self.signed);
        }
        for (name, _) in ADAPTER_FILES {
            write(&root.join("import/adapter").join(name), &contents);
        }
        let candidate_files =
            super::super::super::peer_evaluation::adapter_files(&root.join("import/adapter"))
                .unwrap();
        let selection = json!({"version":1,"policy":"local-peer-update-validation-loss-v1","scope":"owner-selected-public-validation-not-independent-benchmark-or-poisoning-proof",
            "validation_source":self.source,"validation_manifest":identity(&self.signed),"validation_sha256":identity(&self.dataset),
            "baseline_origin":baseline_origin,"baseline_adapter":baseline_path,"baseline_files":baseline_files,
            "candidate_adapter":root.join("import/adapter"),"candidate_files":candidate_files,"import_proof":imported,
            "expires":expires,"max_seconds":10,"threads":2});
        json_file(&root.join("comparison/selection.json"), &selection);
        json_file(
            &root.join("comparison/provenance.json"),
            &json!({"synthetic_fixture":true}),
        );
        for (stage, offset, loss, files) in [
            ("baseline", 30, 0.4, baseline_files.as_ref()),
            ("candidate", 18, 0.3, Some(&candidate_files)),
        ] {
            let mut report = json!({"version":1,"kind":"result","status":"ok","id":format!("{:032x}",id*100+offset),"mode":"infer","device":"cpu","threads":2,
                "updates_completed":0,"artifacts":[],"elapsed_ms":5,"model":{"id":MODEL_ID,"revision":MODEL_REVISION,"files":{"model.safetensors":{"sha256":hex::encode(BASE_MODEL_SHA256),"bytes":269_060_552}}},
                "dataset":{"sha256":identity(&self.dataset).sha256,"bytes":self.dataset.len(),"training_examples":0},"baseline_evaluation":{"loss":loss,"target_tokens":8}});
            if let Some(files) = files {
                report["input_adapter"] = json!({"applied":true,"model_id":MODEL_ID,"model_revision":MODEL_REVISION,"files":files,
                "applied_parameters":{"parameters":230400,"sha256":"ab".repeat(32)},"base_parameters_before_apply":{"synthetic":true},"base_parameters_after_apply":{"synthetic":true}});
            }
            json_file(
                &root.join("comparison").join(stage).join("report.json"),
                &report,
            );
            report["supervisor"] = json!({"deadline_seconds":10,"child_reaped":true,"network_access":false,"spare_capacity":true});
            json_file(
                &root.join("comparison").join(format!("{stage}-report.json")),
                &json!({"version":1,"started_at":self.at-offset,"completed_at":self.at-offset+1,"deadline":self.at-offset+10,"report":report}),
            );
        }
        let files: Snapshot = [
            "selection.json",
            "dataset.json",
            "dataset.manifest",
            "provenance.json",
            "baseline-report.json",
            "candidate-report.json",
            "baseline/report.json",
            "candidate/report.json",
        ]
        .into_iter()
        .map(|name| {
            (
                name.into(),
                identity(&fs::read(root.join("comparison").join(name)).unwrap()),
            )
        })
        .collect();
        json_file(
            &root.join("comparison/decision.json"),
            &json!({"version":1,"policy":selection["policy"],"scope":selection["scope"],"approved":true,"baseline_origin":baseline_origin,"import_proof":imported,
            "candidate_files":candidate_files,"baseline":{"loss":0.4,"target_tokens":8},"candidate":{"loss":0.3,"target_tokens":8},"validation_manifest_id":self.source.manifest_id,"files":files}),
        );
        let round = Round {
            sequence: id,
            channel: 0,
            revision: id,
            manifest_id: manifest_id.clone(),
            dataset_manifest_id: self.source.manifest_id.clone().unwrap(),
            observed_at: self.at - 40,
            expires,
            next_attempt: 0,
            phase: Phase::Approved,
            source: Some(self.source.clone()),
            imported_at: Some(self.at - 35),
            baseline: Some(Baseline {
                adapter_root: baseline_path,
                origin: baseline_origin,
                local_predecessor: self.state.latest,
            }),
            snapshot: Some(snapshot(&root).unwrap()),
            retirement: None,
        };
        let registry = self.state.peer_updates.as_mut().unwrap();
        registry.next_sequence += 1;
        registry.feeds[0].revision = Some(id);
        registry.feeds[0].manifest_id = Some(manifest_id.clone());
        registry.feeds[0].processed_manifest = Some(manifest_id);
        registry.completed.push(round);
        registry.active = Some(id);
        active(&self.args, registry, self.state.latest)
            .unwrap()
            .unwrap();
        self.store
            .save_state(&serde_json::to_value(&self.state).unwrap())
            .unwrap();
    }

    fn damage(&self, sequence: u64) {
        write(
            &round_root(&self.args, sequence)
                .unwrap()
                .join("import/adapter/adapter_model.safetensors"),
            b"changed local copy, not a changed signed publication",
        );
    }

    fn pending_local_validation(&mut self, peer: u64) -> PathBuf {
        let mut selected = self.state.peer_updates.clone().unwrap();
        selected.active = Some(peer);
        let accepted = active(&self.args, &selected, self.state.latest)
            .unwrap()
            .unwrap();
        let root = self.store.cycle_path(1).unwrap();
        directory(&root);
        for name in ["training", "training/adapter"] {
            directory(&root.join(name));
        }
        for name in [
            "dataset.json",
            "dataset.manifest",
            "source-provenance.json",
            "training-report.json",
            "result.json",
            "adapter.bundle",
            "training/report.json",
            "training/adapter/README.md",
            "training/adapter/adapter_config.json",
            "training/adapter/adapter_model.safetensors",
        ] {
            write(
                &root.join(name),
                b"opaque checkpoint fixture, no model execution",
            );
        }
        json_file(
            &root.join("selection.json"),
            &json!({"adapter_root":accepted.adapter_root,"peer_predecessor":accepted.origin}),
        );
        self.state.cycles.push(super::super::super::Cycle {
            sequence: 1,
            source: 0,
            phase: super::super::super::Phase::Evaluating,
            snapshot: None,
            training: Some(self.store.snapshot_training(1).unwrap()),
            publication: None,
            next_publication_attempt: 0,
        });
        self.state.next_sequence = 2;
        self.store
            .save_state(&serde_json::to_value(&self.state).unwrap())
            .unwrap();
        root
    }
}

#[test]
fn accepted_peer_local_integrity_rollback_is_durable_exact_and_idempotent() {
    let mut fixture = Fixture::new();
    fixture.approve(fixture.at + 600);
    fixture.approve(fixture.at + 900);
    let original = fixture.state.peer_updates.as_ref().unwrap().completed[1]
        .snapshot
        .clone();
    fixture.damage(2);
    assert!(recover_active(&fixture.args, &fixture.store, &mut fixture.state).unwrap());
    let registry = fixture.state.peer_updates.as_ref().unwrap();
    assert_eq!(registry.active, Some(1));
    assert_eq!(registry.completed[1].snapshot, original);
    assert_eq!(
        registry.completed[1]
            .retirement
            .as_ref()
            .unwrap()
            .restored_expires,
        fixture.at + 600
    );
    verify(&fixture.args, registry, &registry.completed[1]).unwrap();
    let saved = serde_json::to_value(&fixture.state).unwrap();
    assert!(!recover_active(&fixture.args, &fixture.store, &mut fixture.state).unwrap());
    assert_eq!(saved, serde_json::to_value(&fixture.state).unwrap());
    fixture.args.resume = true;
    restore(
        &fixture.args,
        &fixture.store,
        &mut fixture.state,
        &fixture.enrollment,
    )
    .unwrap();
    assert_eq!(saved, serde_json::to_value(&fixture.state).unwrap());
    let registry = fixture.state.peer_updates.as_mut().unwrap();
    admit_revision(&mut registry.feeds[0], 3, &"33".repeat(32)).unwrap();
    assert_eq!(registry.active, Some(1)); // Same publisher's later revisions remain eligible.
}

#[test]
fn changed_original_or_missing_extraction_cannot_mint_local_retirement() {
    for path in [
        "comparison/decision.json",
        "pending/adapter.bundle",
        "import/dataset.json",
    ] {
        let mut fixture = Fixture::new();
        fixture.approve(fixture.at + 600);
        fixture.approve(fixture.at + 900);
        fixture.damage(2);
        write(
            &round_root(&fixture.args, 2).unwrap().join(path),
            b"not intact evidence",
        );
        let failure =
            recover_active(&fixture.args, &fixture.store, &mut fixture.state).unwrap_err();
        assert!(!recovery_blocked(&failure));
        assert_eq!(fixture.state.peer_updates.as_ref().unwrap().active, Some(2));
        assert!(
            fixture.state.peer_updates.as_ref().unwrap().completed[1]
                .retirement
                .is_none()
        );
    }
    let mut fixture = Fixture::new();
    fixture.approve(fixture.at + 600);
    fs::remove_file(
        round_root(&fixture.args, 1)
            .unwrap()
            .join("import/adapter/README.md"),
    )
    .unwrap();
    let failure = recover_active(&fixture.args, &fixture.store, &mut fixture.state).unwrap_err();
    assert!(!recovery_blocked(&failure));
}

#[test]
fn missing_or_expired_approved_predecessor_never_invents_base_fallback() {
    let mut fixture = Fixture::new();
    fixture.approve(fixture.at + 600);
    fixture.damage(1);
    let failure = recover_active(&fixture.args, &fixture.store, &mut fixture.state).unwrap_err();
    assert!(recovery_blocked(&failure));
    assert_eq!(fixture.state.peer_updates.as_ref().unwrap().active, Some(1));
    assert!(!recovery_blocked(&anyhow::anyhow!(failure.to_string())));
    let mut fixture = Fixture::new();
    fixture.approve(fixture.at + 600);
    fixture.approve(fixture.at + 900);
    let registry = fixture.state.peer_updates.as_ref().unwrap();
    let round = &registry.completed[1];
    let selection = approved_original(&fixture.args, registry, round).unwrap();
    assert!(
        predecessor(
            &fixture.args,
            &fixture.store,
            &fixture.state,
            registry,
            round,
            &selection,
            fixture.at + 600
        )
        .is_err()
    );
}

#[test]
fn retention_protects_direct_accepted_predecessor_inside_existing_eight_slots() {
    let mut fixture = Fixture::new();
    fixture.approve(fixture.at + 600);
    fixture.approve(fixture.at + 900);
    let mut registry = fixture.state.peer_updates.clone().unwrap();
    for sequence in 3..=8 {
        let mut failed = registry.completed[1].clone();
        failed.sequence = sequence;
        failed.phase = Phase::Failed;
        failed.snapshot = Some(Snapshot::new());
        directory(&round_root(&fixture.args, sequence).unwrap());
        registry.completed.push(failed);
    }
    registry.next_sequence = 9;
    assert!(
        make_room(
            &fixture.args,
            &fixture.store,
            &mut fixture.state,
            &mut registry
        )
        .unwrap()
    );
    assert_eq!(registry.completed.len(), RETAINED - 1);
    assert!(registry.completed.iter().any(|round| round.sequence == 1));
    assert!(!registry.completed.iter().any(|round| round.sequence == 3));
    assert!(round_root(&fixture.args, 1).unwrap().is_dir());
}

#[test]
fn rollback_finishes_existing_comparison_without_rebinding_its_baseline() {
    let mut fixture = Fixture::new();
    fixture.approve(fixture.at + 600);
    fixture.approve(fixture.at + 900);
    let registry = fixture.state.peer_updates.as_mut().unwrap();
    let mut pending = registry.completed[1].clone();
    pending.sequence = 3;
    pending.phase = Phase::Evaluating;
    pending.snapshot = None;
    let original_baseline = pending.baseline.as_ref().unwrap().origin.clone();
    directory(&round_root(&fixture.args, 3).unwrap());
    registry.pending = Some(pending);
    registry.next_sequence = 4;
    fixture.damage(2);
    assert!(recover_active(&fixture.args, &fixture.store, &mut fixture.state).unwrap());
    let registry = fixture.state.peer_updates.as_ref().unwrap();
    assert!(registry.pending.is_none());
    assert_eq!(registry.completed[2].phase, Phase::Failed);
    assert_eq!(
        registry.completed[2].baseline.as_ref().unwrap().origin,
        original_baseline
    );
}

#[test]
fn rollback_retires_interrupted_local_validation_only_for_exact_damaged_peer() {
    let mut fixture = Fixture::new();
    fixture.approve(fixture.at + 600);
    fixture.approve(fixture.at + 900);
    let root = fixture.pending_local_validation(2);
    let selected = fs::read(root.join("selection.json")).unwrap();
    let training = fixture.state.cycles[0].training.clone();
    // Partial validation evidence is retained, not rebound or erased for a retry.
    let receipt = b"opaque original validation receipt";
    write(&root.join("baseline-report.json"), receipt);
    fixture.damage(2);
    super::super::super::recover(&fixture.store, &mut fixture.state, 1).unwrap();
    assert!(recover_active(&fixture.args, &fixture.store, &mut fixture.state).unwrap());
    assert_eq!(fixture.state.peer_updates.as_ref().unwrap().active, Some(1));
    assert!(fixture.state.cycles[0].phase == super::super::super::Phase::Failed);
    assert_eq!(fixture.state.cycles[0].training, training);
    assert_eq!(
        fixture.store.snapshot_training(1).unwrap(),
        training.unwrap()
    );
    assert_eq!(fs::read(root.join("selection.json")).unwrap(), selected);
    assert_eq!(
        fs::read(root.join("baseline-report.json")).unwrap(),
        receipt
    );
    assert_eq!(
        (
            fixture.state.completed,
            fixture.state.promoted,
            fixture.state.rejected
        ),
        (0, 0, 0)
    );
    let saved = fixture.store.load_state().unwrap().unwrap();
    fixture.state = serde_json::from_value(saved.clone()).unwrap();
    fixture.args.resume = true;
    super::super::super::recover(&fixture.store, &mut fixture.state, 1).unwrap();
    restore(
        &fixture.args,
        &fixture.store,
        &mut fixture.state,
        &fixture.enrollment,
    )
    .unwrap();
    assert_eq!(serde_json::to_value(&fixture.state).unwrap(), saved);
    let current =
        super::super::super::current_adapter(&fixture.args, &fixture.store, &fixture.state)
            .unwrap();
    assert_eq!(current.origin["import_sequence"], 1);
    assert!(
        !fixture
            .state
            .cycles
            .iter()
            .any(|cycle| cycle.phase == super::super::super::Phase::Evaluating)
    );
}

#[test]
fn rollback_preserves_interrupted_local_validation_against_a_different_peer() {
    let mut fixture = Fixture::new();
    fixture.approve(fixture.at + 600);
    fixture.approve(fixture.at + 900);
    let root = fixture.pending_local_validation(1);
    let before = serde_json::to_value(&fixture.state.cycles[0]).unwrap();
    let selected = fs::read(root.join("selection.json")).unwrap();
    fixture.damage(2);
    assert!(recover_active(&fixture.args, &fixture.store, &mut fixture.state).unwrap());
    assert_eq!(
        serde_json::to_value(&fixture.state.cycles[0]).unwrap(),
        before
    );
    assert_eq!(fs::read(root.join("selection.json")).unwrap(), selected);
}
