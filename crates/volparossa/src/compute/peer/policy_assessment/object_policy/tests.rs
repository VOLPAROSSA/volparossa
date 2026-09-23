//! Synthetic signed-transport fixtures: no model execution or semantic-quality claim.

use std::os::unix::fs::PermissionsExt as _;

use ed25519_dalek::SigningKey;
use volparossa_policy::{
    DestinationRule, ManifestSpec, PolicyMode, ProtocolPort, TransportProtocol, TrustStore,
    TrustedMaintainer, VerificationPolicy, sign_manifest, verify_manifest,
};

use super::*;

#[test]
fn command_tree_keeps_global_and_authority_policy_config_distinct() {
    use clap::{CommandFactory as _, Parser as _};

    crate::Cli::command().debug_assert();
    let keys: Vec<_> = (21..=24)
        .map(|byte| {
            hex::encode(
                SigningKey::from_bytes(&[byte; 32])
                    .verifying_key()
                    .as_bytes(),
            )
        })
        .collect();
    let manifest = hex::encode([25; 32]);
    for operation in ["policy-propose", "policy-endorse", "policy-combine"] {
        let mut arguments = vec![
            "volparossa",
            "--config",
            "/tmp/global-config.yaml",
            "compute",
            "peer",
            operation,
            "--assessment-bundle",
            "/tmp/assessment.bundle",
            "--policy-config",
            "/tmp/authority-config.yaml",
            "--requester-key",
            &keys[0],
            "--source-publisher-key",
            &keys[1],
            "--source-manifest-id",
            &manifest,
            "--provider-key",
            &keys[2],
            "--provider-key",
            &keys[3],
            "--output",
            "/tmp/result",
        ];
        match operation {
            "policy-propose" => arguments.extend(["--decision-revision", "1"]),
            "policy-endorse" => arguments.extend(["--proposal", "/tmp/proposal.bin"]),
            _ => arguments.extend([
                "--proposal",
                "/tmp/proposal.bin",
                "--endorsement",
                "/tmp/endorsement.bin",
            ]),
        }
        let parsed = crate::Cli::try_parse_from(arguments).unwrap();
        assert_eq!(parsed.config, PathBuf::from("/tmp/global-config.yaml"));
        let crate::CliCommand::Compute {
            command: crate::compute::Command::Peer { command },
        } = parsed.command
        else {
            panic!("wrong object-policy command");
        };
        let selection = match *command {
            crate::compute::peer::Command::PolicyPropose(options) => options.selection,
            crate::compute::peer::Command::PolicyEndorse(options) => options.selection,
            crate::compute::peer::Command::PolicyCombine(options) => options.selection,
            _ => panic!("wrong policy command"),
        };
        assert_eq!(
            selection.policy_config,
            PathBuf::from("/tmp/authority-config.yaml")
        );
    }
}

fn private_root() -> tempfile::TempDir {
    let root = tempfile::tempdir().unwrap();
    std::fs::set_permissions(root.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
    root
}

fn context(at: u64) -> (Vec<SigningKey>, PolicyContext) {
    let keys: Vec<_> = (31_u8..=35)
        .map(|byte| SigningKey::from_bytes(&[byte; 32]))
        .collect();
    let trust = TrustStore::new(
        PolicyMode::Production,
        keys.iter()
            .map(|key| TrustedMaintainer::production(key.verifying_key()))
            .collect(),
    )
    .unwrap();
    let mut spec = ManifestSpec::new(7, 1, at - 1000, at - 1000, at + 30_000).unwrap();
    spec.add_rule(
        DestinationRule::exact_domain(
            "example.com",
            [ProtocolPort::new(TransportProtocol::Tcp, 443).unwrap()],
        )
        .unwrap(),
    )
    .unwrap();
    let bytes = sign_manifest(&spec, &trust, &[&keys[0], &keys[1], &keys[2]]).unwrap();
    let verification = VerificationPolicy::default();
    let manifest = verify_manifest(&bytes, at, &trust, verification).unwrap();
    (
        keys,
        PolicyContext {
            trust,
            verification,
            manifest,
        },
    )
}

fn selection(enrolled: &Enrollment, requester: &SigningKey, root: &Path) -> Selection {
    Selection {
        assessment_bundle: root.join("original.bundle"),
        policy_config: root.join("config.yaml"),
        requester_key: requester.verifying_key(),
        source_publisher_key: parse_key(&enrolled.scope.source_publisher_key).unwrap(),
        source_manifest_id: parse_manifest(&enrolled.scope.source_manifest_id).unwrap(),
        provider_key: enrolled
            .providers
            .iter()
            .map(|key| parse_key(key).unwrap())
            .collect(),
        model_profile: enrolled.profile().unwrap(),
    }
}

fn body(evidence: &AssessmentEvidence, context: &PolicyContext, at: u64) -> ObjectDecision {
    ObjectDecision {
        policy_hash: *context.manifest.policy_hash(),
        policy_version: context.manifest.manifest_version(),
        decision_revision: 1,
        subject: evidence.subject,
        framework_sha256: evidence.framework_sha256,
        evidence_sha256: evidence.evidence_sha256,
        outcome: evidence.outcome,
        issued_at_ms: at,
        expires_at_ms: expiry(evidence, context, at).unwrap(),
        nonce: [40; 32],
    }
}

#[tokio::test]
async fn original_four_transcripts_drive_separate_authorities_same_immutable_decision() {
    let source = private_root();
    let retained = private_root();
    let requester = SigningKey::from_bytes(&[25; 32]);
    let bytes = transfer::tests::fixture_bundle(source.path(), &requester).await;
    let (enrolled, result) =
        transfer::replay_bundle(&bytes, &requester.verifying_key(), retained.path()).unwrap();
    let args = selection(&enrolled, &requester, retained.path());
    let at = milliseconds().unwrap();
    let evidence = evidence_from_replay(&args, &enrolled, &result, &bytes, at).unwrap();
    let (authorities, context) = context(at);
    let original = body(&evidence, &context, at);
    let mut combined = SignedObjectDecision::new(original.clone()).unwrap();
    for authority in &authorities[..3] {
        let (original_enrollment, original_result) =
            transfer::replay_bundle(&bytes, &requester.verifying_key(), retained.path()).unwrap();
        let replayed =
            evidence_from_replay(&args, &original_enrollment, &original_result, &bytes, at)
                .unwrap();
        validate_body(&original, &replayed, &context, at).unwrap();
        let mut own = SignedObjectDecision::new(original.clone()).unwrap();
        own.endorse(authority).unwrap();
        combined.merge(&own).unwrap();
    }
    let verified = verify_object_decision(
        &combined.encode().unwrap(),
        at,
        &context.trust,
        context.verification,
        &context.manifest,
    )
    .unwrap();
    assert_eq!(verified.body(), &original);
    assert_eq!(
        verified.body().expires_at_ms,
        context.manifest.expires_at_ms()
    );
    assert_eq!(result["network_policy_activation"], false);
    assert!(
        transfer::replay_bundle(&bytes, &authorities[0].verifying_key(), retained.path()).is_err()
    );
    let mut wrong_selection = selection(&enrolled, &requester, retained.path());
    wrong_selection.provider_key.swap(0, 1);
    assert!(evidence_from_replay(&wrong_selection, &enrolled, &result, &bytes, at).is_err());
    wrong_selection = selection(&enrolled, &requester, retained.path());
    wrong_selection.model_profile = ModelProfile::Smol1700;
    assert!(evidence_from_replay(&wrong_selection, &enrolled, &result, &bytes, at).is_err());
    assert!(
        evidence_from_replay(&args, &enrolled, &result, &bytes, enrolled.expires * 1000).is_err()
    );
    let mut changed = original.clone();
    changed.outcome = if original.outcome == ObjectOutcome::Deny {
        ObjectOutcome::Allow
    } else {
        ObjectOutcome::Deny
    };
    assert!(validate_body(&changed, &evidence, &context, at).is_err());
    changed = original.clone();
    changed.subject.manifest_id[0] ^= 1;
    assert!(validate_body(&changed, &evidence, &context, at).is_err());
    changed = original;
    changed.evidence_sha256[0] ^= 1;
    assert!(validate_body(&changed, &evidence, &context, at).is_err());
}

fn evidence(at: u64) -> AssessmentEvidence {
    AssessmentEvidence {
        subject: ObjectSubject {
            publisher_key: SigningKey::from_bytes(&[21; 32]).verifying_key().to_bytes(),
            manifest_id: [22; 32],
            object_sha256: [23; 32],
        },
        framework_sha256: [24; 32],
        evidence_sha256: [25; 32],
        outcome: ObjectOutcome::Undetermined,
        selected_at_ms: at - 1000,
        expires_at_ms: at + 10_000,
    }
}

#[test]
fn proposal_expiry_is_original_minimum_and_resume_never_renews_it() {
    let at = 100_000;
    let (_, context) = context(at);
    let evidence = evidence(at);
    let original = body(&evidence, &context, at);
    assert_eq!(original.expires_at_ms, evidence.expires_at_ms);
    validate_body(&original, &evidence, &context, at + 1).unwrap();
    assert!(validate_body(&original, &evidence, &context, original.expires_at_ms).is_err());
    let mut changed = original.clone();
    changed.expires_at_ms += 1;
    assert!(validate_body(&changed, &evidence, &context, at + 1).is_err());
    changed = original.clone();
    changed.policy_hash[0] ^= 1;
    assert!(validate_body(&changed, &evidence, &context, at).is_err());
    let retained = private_root();
    let path = retained.path().join("proposal.bin");
    let bytes = SignedObjectDecision::new(original.clone())
        .unwrap()
        .encode()
        .unwrap();
    retain(&path, &bytes).unwrap();
    retain(&path, &bytes).unwrap();
    assert_eq!(
        proposal(&path, &evidence, &context, at + 1)
            .unwrap()
            .1
            .body(),
        &original
    );
    changed = original;
    changed.nonce[0] ^= 1;
    let changed_bytes = SignedObjectDecision::new(changed)
        .unwrap()
        .encode()
        .unwrap();
    assert!(retain(&path, &changed_bytes).is_err());
    assert_eq!(storage::read(&path, MAX_DECISION_BYTES).unwrap(), bytes);
}

#[test]
fn compute_signatures_cannot_replace_existing_policy_quorum() {
    let at = 100_000;
    let (authorities, context) = context(at);
    let original = body(&evidence(at), &context, at);
    let mut signed = SignedObjectDecision::new(original).unwrap();
    for byte in [23, 24] {
        signed
            .endorse(&SigningKey::from_bytes(&[byte; 32]))
            .unwrap();
    }
    signed.endorse(&authorities[0]).unwrap();
    assert!(
        verify_object_decision(
            &signed.encode().unwrap(),
            at,
            &context.trust,
            context.verification,
            &context.manifest
        )
        .is_err()
    );
}
