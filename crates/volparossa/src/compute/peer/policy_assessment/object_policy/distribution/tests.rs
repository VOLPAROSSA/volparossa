//! Inert signed transport fixtures, not learned judgment or network execution evidence.

use std::os::unix::fs::PermissionsExt as _;

use clap::{CommandFactory as _, Parser as _};
use ed25519_dalek::SigningKey;
use volparossa_content::{Metadata, Publication, Validity};
use volparossa_policy::object::{ObjectDecision, ObjectOutcome, SignedObjectDecision};

use super::*;

fn fixture(at: u64) -> (Selection, Vec<u8>, PolicyContext) {
    let (authorities, context) = super::super::tests::context(at);
    let publisher = SigningKey::from_bytes(&[21; 32]).verifying_key();
    let mut signed = SignedObjectDecision::new(ObjectDecision {
        policy_hash: *context.manifest.policy_hash(),
        policy_version: context.manifest.manifest_version(),
        decision_revision: 1,
        subject: ObjectSubject {
            publisher_key: publisher.to_bytes(),
            manifest_id: [22; 32],
            object_sha256: [23; 32],
        },
        framework_sha256: [24; 32],
        evidence_sha256: [25; 32],
        outcome: ObjectOutcome::Undetermined,
        issued_at_ms: at,
        expires_at_ms: at + 10_999,
        nonce: [26; 32],
    })
    .unwrap();
    for authority in &authorities[..3] {
        signed.endorse(authority).unwrap();
    }
    let bytes = signed.encode().unwrap();
    let verified = verify_object_decision(
        &bytes,
        at,
        &context.trust,
        context.verification,
        &context.manifest,
    )
    .unwrap();
    let args = Selection {
        decision: "/tmp/original-decision.bin".into(),
        policy_config: "/tmp/receiver-config.yaml".into(),
        subject_publisher_key: publisher,
        subject_manifest_id: [22; 32],
        subject_sha256: [23; 32],
        decision_hash: *verified.decision_hash(),
        evidence_sha256: [25; 32],
    };
    (args, bytes, context)
}

#[test]
fn received_bytes_require_original_full_subject_and_receivers_own_quorum() {
    let at = 100_000;
    let (selection, bytes, context) = fixture(at);
    verify_selected(&selection, &bytes, &context, at).unwrap();
    let mut changed = selection.clone();
    changed.subject_publisher_key = SigningKey::from_bytes(&[29; 32]).verifying_key();
    assert!(verify_selected(&changed, &bytes, &context, at).is_err());
    changed = selection.clone();
    changed.subject_manifest_id[0] ^= 1;
    assert!(verify_selected(&changed, &bytes, &context, at).is_err());
    changed = selection.clone();
    changed.subject_sha256[0] ^= 1;
    assert!(verify_selected(&changed, &bytes, &context, at).is_err());
    changed = selection.clone();
    changed.decision_hash[0] ^= 1;
    assert!(verify_selected(&changed, &bytes, &context, at).is_err());
    changed = selection.clone();
    changed.evidence_sha256[0] ^= 1;
    assert!(verify_selected(&changed, &bytes, &context, at).is_err());
    assert!(verify_selected(&selection, &bytes, &context, at + 10_999).is_err());

    let body = SignedObjectDecision::decode(&bytes).unwrap().body().clone();
    let (authorities, _) = super::super::tests::context(at);
    let mut insufficient = SignedObjectDecision::new(body).unwrap();
    insufficient.endorse(&authorities[0]).unwrap();
    insufficient.endorse(&authorities[1]).unwrap();
    // A valid native content publisher is still not the missing policy authority.
    insufficient
        .endorse(&SigningKey::from_bytes(&[29; 32]))
        .unwrap();
    assert!(verify_selected(&selection, &insufficient.encode().unwrap(), &context, at).is_err());
}

#[derive(clap::Parser)]
struct PublishParser {
    #[command(flatten)]
    options: Publish,
}

fn publish_arguments() -> Vec<String> {
    let publisher = SigningKey::from_bytes(&[21; 32]).verifying_key();
    [
        "fixture",
        "--decision",
        "/tmp/decision.bin",
        "--policy-config",
        "/tmp/policy.yaml",
        "--subject-publisher-key",
        &hex::encode(publisher.as_bytes()),
        "--subject-manifest-id",
        &hex::encode([22; 32]),
        "--subject-sha256",
        &hex::encode([23; 32]),
        "--decision-hash",
        &hex::encode([24; 32]),
        "--evidence-sha256",
        &hex::encode([25; 32]),
        "--publication-key",
        &hex::encode(publisher.as_bytes()),
        "--name",
        "policy-decision",
        "--revision",
        "1",
        "--identity",
        "/tmp/identity",
        "--passphrase-file",
        "/tmp/passphrase",
        "--output",
        "/tmp/publication",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect()
}

#[test]
fn original_publication_and_decision_survive_reopen_without_new_expiry() {
    let at = 100_000;
    let (selection, bytes, context) = fixture(at);
    let decision = verify_selected(&selection, &bytes, &context, at).unwrap();
    assert_eq!(wrapper_expiry(&decision, at).unwrap(), 110);
    assert_eq!(wrapper_expiry(&decision, 109_000).unwrap(), 110);
    assert!(wrapper_expiry(&decision, 109_001).is_err());
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    let mut args = PublishParser::parse_from(publish_arguments()).options;
    args.output = root.path().join("publication");
    let _lock = open_output(&args.output).unwrap();
    let signer = SigningKey::from_bytes(&[21; 32]);
    let mut cache = ChunkStore::create(
        &args.output.join("cache"),
        args.limits.cache_limits().unwrap(),
    )
    .unwrap();
    let native = volparossa_content::publish(
        &mut bytes.as_slice(),
        Publication {
            metadata: Metadata {
                name: args.name.clone(),
                revision: 1,
                content_type: content::POLICY_DECISION_CONTENT_TYPE.into(),
            },
            length: bytes.len() as u64,
            validity: Validity {
                created: at / 1000,
                expires: wrapper_expiry(&decision, at).unwrap(),
            },
        },
        &signer,
        &mut cache,
    )
    .unwrap();
    drop(cache);
    let raw_manifest = native.encode();
    let path = args.output.join("publication.manifest");
    retain(&path, &raw_manifest).unwrap();
    retain(&args.output.join("decision.bin"), &bytes).unwrap();
    for when in [100, 109] {
        let (reopened, verified) = publication_binding(&args, &bytes, &decision, when).unwrap();
        assert_eq!(reopened, raw_manifest);
        assert_eq!(verified.validity().expires, 110);
        retain(&path, &reopened).unwrap();
    }
    assert!(publication_binding(&args, &bytes, &decision, 110).is_err());
    let mut changed = bytes.clone();
    changed[0] ^= 1;
    assert!(publication_binding(&args, &changed, &decision, 109).is_err());
    assert!(retain(&args.output.join("decision.bin"), &changed).is_err());
    assert_eq!(storage::read(&path, 64 * 1024).unwrap(), raw_manifest);
}

#[test]
fn distribution_cli_keeps_receiver_unsigned_and_policy_config_separate() {
    crate::Cli::command().debug_assert();
    let publication_args = publish_arguments();
    let mut args: Vec<String> = [
        "volparossa",
        "--config",
        "/tmp/global.yaml",
        "compute",
        "peer",
        "policy-publish",
    ]
    .into_iter()
    .map(str::to_owned)
    .collect();
    args.extend_from_slice(&publication_args[1..]);
    let parsed = crate::Cli::try_parse_from(&args).unwrap();
    assert_eq!(parsed.config, PathBuf::from("/tmp/global.yaml"));
    let crate::CliCommand::Compute {
        command: crate::compute::Command::Peer { command },
    } = parsed.command
    else {
        panic!("wrong command");
    };
    let crate::compute::peer::Command::PolicyPublish(options) = *command else {
        panic!("wrong publication command");
    };
    assert_eq!(
        options.selection.policy_config,
        PathBuf::from("/tmp/policy.yaml")
    );
    args[5] = "policy-import".into();
    let publication_start = args
        .iter()
        .position(|arg| arg == "--publication-key")
        .unwrap();
    args.truncate(publication_start);
    args.extend(["--output".into(), "/tmp/import".into()]);
    assert!(crate::Cli::try_parse_from(&args).is_ok());
    args.push("--apply".into());
    assert!(crate::Cli::try_parse_from(&args).is_err());
    args.push("--execute".into());
    assert!(crate::Cli::try_parse_from(&args).is_ok());
    args.extend(["--identity".into(), "/tmp/must-not-be-required".into()]);
    assert!(crate::Cli::try_parse_from(&args).is_err());
}
