//! Inert ownership and signed-authority checks, not neural or protected-network evidence.

use std::os::unix::fs::PermissionsExt as _;

use clap::{CommandFactory as _, Parser as _};
use ed25519_dalek::SigningKey;
use rand_core::{OsRng, RngCore as _};
use volparossa_content::{Metadata, Publication, Validity};
use volparossa_policy::{
    DestinationRule, ManifestSpec, ProtocolPort, TransportProtocol,
    object::{ObjectDecision, ObjectOutcome, ObjectSubject, SignedObjectDecision},
    sign_manifest,
};

use super::*;

#[derive(clap::Parser)]
struct Parser {
    #[command(flatten)]
    options: Options,
}

fn options() -> Options {
    let publisher = hex::encode(SigningKey::from_bytes(&[21; 32]).verifying_key().as_bytes());
    Parser::parse_from([
        "fixture",
        "--policy-config",
        "/tmp/policy.yaml",
        "--publisher-key",
        &publisher,
        "--name",
        "selected-decisions",
        "--subject-publisher-key",
        &publisher,
        "--subject-manifest-id",
        &hex::encode([22; 32]),
        "--subject-sha256",
        &hex::encode([23; 32]),
        "--framework-sha256",
        &hex::encode([24; 32]),
        "--directory",
        "/tmp/follower",
        "--cache",
        "/tmp/follow-cache",
    ])
    .options
}

fn private_root() -> tempfile::TempDir {
    let directory = tempfile::tempdir().unwrap();
    std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    directory
}

fn fresh_nonce() -> [u8; 32] {
    std::array::from_fn(|_| OsRng.next_u32().to_le_bytes()[0])
}

fn authority(at: u64) -> (Vec<SigningKey>, PolicyContext, Vec<u8>) {
    let (keys, context) = super::super::tests::context(at);
    let mut spec = ManifestSpec::new(7, 1, at - 1000, at - 1000, at + 30_000).unwrap();
    spec.add_rule(
        DestinationRule::exact_domain(
            "example.com",
            [ProtocolPort::new(TransportProtocol::Tcp, 443).unwrap()],
        )
        .unwrap(),
    )
    .unwrap();
    let raw = sign_manifest(&spec, &context.trust, &[&keys[0], &keys[1], &keys[2]]).unwrap();
    assert_eq!(
        verify_manifest(&raw, at, &context.trust, context.verification)
            .unwrap()
            .policy_hash(),
        context.manifest.policy_hash()
    );
    (keys, context, raw)
}

fn record(
    args: &Options,
    keys: &[SigningKey],
    context: &PolicyContext,
    epoch: &[u8],
    wrapper_revision: u64,
    decision_revision: u64,
    nonce: [u8; 32],
) -> Record {
    let mut original = SignedObjectDecision::new(ObjectDecision {
        policy_hash: *context.manifest.policy_hash(),
        policy_version: context.manifest.manifest_version(),
        decision_revision,
        subject: ObjectSubject {
            publisher_key: args.subject_publisher_key.to_bytes(),
            manifest_id: args.subject_manifest_id,
            object_sha256: args.subject_sha256,
        },
        framework_sha256: args.framework_sha256,
        evidence_sha256: [25; 32],
        outcome: ObjectOutcome::Undetermined,
        issued_at_ms: 100_000,
        expires_at_ms: 110_999,
        nonce,
    })
    .unwrap();
    for signer in &keys[..3] {
        original.endorse(signer).unwrap();
    }
    let raw = original.encode().unwrap();
    let root = private_root();
    let mut cache = ChunkStore::create(
        &root.path().join("cache"),
        args.limits.cache_limits().unwrap(),
    )
    .unwrap();
    let native = volparossa_content::publish(
        &mut raw.as_slice(),
        Publication {
            metadata: Metadata {
                name: args.name.clone(),
                revision: wrapper_revision,
                content_type: content::POLICY_DECISION_CONTENT_TYPE.into(),
            },
            length: raw.len() as u64,
            validity: Validity {
                created: 100,
                expires: 110,
            },
        },
        &SigningKey::from_bytes(&[21; 32]),
        &mut cache,
    )
    .unwrap();
    let verified = native.verify(&args.publisher_key, 100).unwrap();
    let download_receipt = json!({"operation":"named_content_download","name":args.name,
        "publisher_key":hex::encode(args.publisher_key.as_bytes()),"manifest_id":hex::encode(verified.manifest_id()),
        "bytes":raw.len(),"sha256":sha(&raw),"cache_only":false});
    Record {
        phase: Phase::Pending,
        observed_at_ms: 100_000,
        manifest_hex: hex::encode(native.encode()),
        decision_hex: hex::encode(raw),
        epoch_manifest_hex: hex::encode(epoch),
        download_receipt,
        apply_receipt: None,
    }
}

#[test]
fn fresh_owner_initializes_real_cache_and_resume_requires_exact_enrollment() {
    let root = private_root();
    let mut args = options();
    args.directory = root.path().join("follow");
    args.cache = root.path().join("cache");
    let lock = task::open_directory(&args.directory, false).unwrap();
    assert!(!args.cache.exists());
    let saved = load(&args).unwrap();
    assert!(ChunkStore::open(&args.cache, args.limits.cache_limits().unwrap()).is_ok());
    assert_eq!(
        saved.status(&serde_json::to_vec(&saved).unwrap()).unwrap()["completed_polls"],
        0
    );
    assert!(!args.directory.join("unused-policy-output").exists());
    drop(lock);
    args.resume = true;
    let _lock = task::open_directory(&args.directory, true).unwrap();
    load(&args).unwrap();
    args.framework_sha256[0] ^= 1;
    assert!(load(&args).is_err());
}

#[test]
fn pending_checkpoint_reopens_original_authority_and_receipt_without_renewal() {
    let root = private_root();
    let mut args = options();
    args.directory = root.path().join("follow");
    args.cache = root.path().join("cache");
    let _lock = task::open_directory(&args.directory, false).unwrap();
    let mut saved = load(&args).unwrap();
    let (keys, authority, epoch) = authority(100_000);
    let original = record(&args, &keys, &authority, &epoch, 1, 1, fresh_nonce());
    let verified = original.verify_live(&args, &authority, 100_000).unwrap();
    saved.latest = Some(original.clone());
    saved.poll_completed(100_000, "pending").unwrap();
    checkpoint(&args, &saved).unwrap();
    args.resume = true;
    let mut reopened = load(&args).unwrap();
    reopened.validate(&args, &authority).unwrap();
    assert_eq!(reopened.latest, Some(original.clone()));
    assert!(original.verify_live(&args, &authority, 110_000).is_err());
    let receipt = json!({"version":1,"manifest_id":args.subject_manifest_id.to_vec(),
        "decision_hash":verified.decision_hash().to_vec(),"decision_revision":1,
        "policy_hash":authority.manifest.policy_hash().to_vec(),"outcome":3});
    reopened.applied(receipt).unwrap();
    checkpoint(&args, &reopened).unwrap();
    let replayed = load(&args).unwrap();
    replayed.validate(&args, &authority).unwrap();
    let before = serde_json::to_vec(&replayed).unwrap();
    assert_eq!(
        replayed.latest.as_ref().unwrap().decision_hex,
        original.decision_hex
    );
    let status = replayed.status(&before).unwrap();
    assert_eq!(status["applied"], true);
    assert_eq!(status["pending"], false);
    assert_eq!(status["expires_at_ms"], 110_999);
    assert_eq!(status["state_sha256"], sha(&before));
}

#[test]
fn followed_feed_rejects_equivocation_rollback_and_changed_subject_or_framework() {
    let args = options();
    let (keys, authority, epoch) = authority(100_000);
    // Reuse the original nonce only where the test deliberately repeats the
    // signed decision; changing it must still create a different decision body.
    let original_nonce = fresh_nonce();
    let next_nonce = fresh_nonce();
    let original = record(&args, &keys, &authority, &epoch, 2, 2, original_nonce);
    let mut state = State::default();
    assert!(state.accepts(&args, &authority, &original).unwrap());
    state.latest = Some(original.clone());
    assert!(!state.accepts(&args, &authority, &original).unwrap());
    let same_revision = record(&args, &keys, &authority, &epoch, 2, 2, original_nonce);
    assert!(state.accepts(&args, &authority, &same_revision).is_err());
    for (wrapper, decision, nonce) in [
        (1, 2, original_nonce),
        (3, 1, next_nonce),
        (3, 2, next_nonce),
    ] {
        assert!(
            state
                .accepts(
                    &args,
                    &authority,
                    &record(&args, &keys, &authority, &epoch, wrapper, decision, nonce)
                )
                .is_err()
        );
    }
    assert!(
        state
            .accepts(
                &args,
                &authority,
                &record(&args, &keys, &authority, &epoch, 3, 3, next_nonce)
            )
            .unwrap()
    );
    let mut changed = options();
    changed.subject_sha256[0] ^= 1;
    assert!(original.verify_live(&changed, &authority, 100_000).is_err());
    changed = options();
    changed.framework_sha256[0] ^= 1;
    assert!(original.verify_live(&changed, &authority, 100_000).is_err());
}

#[test]
fn follower_cli_has_no_signer_or_outcome_and_real_poll_completion_is_explicit() {
    crate::Cli::command().debug_assert();
    let mut state = State::default();
    state.poll_completed(100_000, "fetch_failed").unwrap();
    let status = state.status(&serde_json::to_vec(&state).unwrap()).unwrap();
    assert_eq!(status["completed_polls"], 1);
    assert_eq!(status["last_poll"]["outcome"], "fetch_failed");
    assert_eq!(status["applied"], false);
    let mut command = Parser::command();
    for forbidden in ["identity", "passphrase_file", "outcome", "decision_hash"] {
        assert!(
            !command
                .get_arguments()
                .any(|arg| arg.get_id().as_str() == forbidden)
        );
    }
    command.build();
}
