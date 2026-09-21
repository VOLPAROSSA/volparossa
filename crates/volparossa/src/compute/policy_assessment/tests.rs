//! Inert contract evidence, not successful model reasoning or policy activation.

use super::*;
use serde_json::{Value, json};

const SOURCE: &str = "This public text describes harmful conduct to help prevent it.";

fn key(seed: u8) -> String {
    hex::encode(
        ed25519_dalek::SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .as_bytes(),
    )
}

fn scope() -> Scope {
    Scope::new(&key(3), &"a".repeat(64), SOURCE).unwrap()
}

fn evidence(peer: u8, job: u8) -> Evidence {
    Evidence {
        provider_key: key(peer),
        job_id: hex::encode([job; 16]),
        report_sha256: hex::encode([job; 32]),
        model_fingerprint: "b".repeat(64),
        package_manifest_id: "c".repeat(64),
    }
}

fn payload(outcome: Outcome) -> Value {
    json!({"version":1,"outcome":outcome,
        "reasoning":[{"principle":"Humanitas","quote":"help prevent it",
            "reason":"Explain the relation to the stated protective purpose."}],
        "counterargument":"A stated purpose alone does not settle the effect of the content.",
        "uncertainty":{"material":false,"reason":"This is an inert parser fixture, not a real assessment."}})
}

fn assessment(peer: u8, outcome: Outcome) -> Assessment {
    decode_assessment(
        &serde_json::to_vec(&payload(outcome)).unwrap(),
        &scope(),
        &evidence(peer, peer),
        SOURCE,
    )
    .unwrap()
}

fn review(peer: u8, target: &Assessment) -> Review {
    let mut value = payload(target.assessment.outcome);
    value["verdict"] = json!("support");
    decode_review(
        &serde_json::to_vec(&value).unwrap(),
        &scope(),
        &evidence(peer, peer + 10),
        target,
        SOURCE,
    )
    .unwrap()
}

fn records(outcome: Outcome) -> ([Assessment; 2], [Review; 2]) {
    let assessments = [assessment(1, outcome), assessment(2, outcome)];
    let reviews = [review(1, &assessments[1]), review(2, &assessments[0])];
    (assessments, reviews)
}

#[test]
fn complete_versioned_framework_is_the_context_not_an_example_catalogue() {
    let value = framework();
    assert_eq!(value.version, 1);
    let context = assessment_context(SOURCE).unwrap();
    let mut latin = BTreeSet::new();
    for (principle, english) in value.virtues.into_iter().chain(value.vices) {
        assert!(latin.insert(principle));
        assert!(context.contains(&format!("{principle:?} ({english})")));
    }
    assert_eq!(latin.len(), 14);
    for required in [
        "Humanity / Kindness",
        "Sloth / Apathy",
        "Temperance / Moderation",
        "Castitas includes consent and personal boundaries",
        "Describing a vice is not facilitating it",
        "does not determine lawfulness or activate policy",
    ] {
        assert!(context.contains(required));
    }
    assert_eq!(scope().framework_sha256, hash(&framework()).unwrap());
    assert!(assessment_question().len() <= 512 && review_question().len() <= 512);
    let record = assessment(1, Outcome::Allow);
    let reviewed = review_context(SOURCE, &record).unwrap();
    assert!(reviewed.contains(&record.sha256().unwrap()));
    assert!(reviewed.contains(&serde_json::to_string(&record.assessment).unwrap()));
    assert!(reviewed.len() <= MAX_CONTEXT_BYTES);
}

#[test]
fn exact_public_source_framework_and_receipt_identity_are_bound() {
    let original = scope();
    original.validate(SOURCE).unwrap();
    assert!(original.validate("Changed source").is_err());
    let mut changed = original.clone();
    changed.framework_version += 1;
    assert!(changed.validate(SOURCE).is_err());
    changed = original.clone();
    changed.framework_sha256 = "f".repeat(64);
    assert!(changed.validate(SOURCE).is_err());
    changed = original.clone();
    changed.source_bytes += 1;
    assert!(changed.validate(SOURCE).is_err());
    for invalid in ["", " ", "\0", &"x".repeat(513)] {
        assert!(Scope::new(&key(3), &"a".repeat(64), invalid).is_err());
    }
    assert!(Scope::new(&key(3), &"A".repeat(64), SOURCE).is_err());
    assert!(Scope::new(&"0".repeat(64), &"a".repeat(64), SOURCE).is_err());
    let raw = serde_json::to_vec(&payload(Outcome::Allow)).unwrap();
    let first = decode_assessment(&raw, &original, &evidence(1, 1), SOURCE).unwrap();
    let different_receipt = decode_assessment(&raw, &original, &evidence(1, 2), SOURCE).unwrap();
    assert_eq!(first.output_sha256, sha(&raw));
    assert_ne!(first.sha256().unwrap(), different_receipt.sha256().unwrap());
    let padded = [b" \n".as_slice(), &raw].concat();
    let same_payload = decode_assessment(&padded, &original, &evidence(1, 1), SOURCE).unwrap();
    assert_eq!(first.assessment, same_payload.assessment);
    assert_ne!(first.sha256().unwrap(), same_payload.sha256().unwrap());
}

#[test]
fn malformed_payload_unknown_principles_and_invented_quotes_fail_closed() {
    let mutations: &[fn(&mut Value)] = &[
        |v| v["version"] = json!(2),
        |v| v["outcome"] = json!("lawful"),
        |v| v["legal_rule"] = json!("invented"),
        |v| v["reasoning"][0]["principle"] = json!("Invented"),
        |v| v["reasoning"][0]["principle"] = json!("humanitas"),
        |v| v["reasoning"][0]["quote"] = json!("not in the original source"),
        |v| v["reasoning"][0]["quote"] = json!(" "),
        |v| v["reasoning"][0]["reason"] = json!("é".repeat(97)),
        |v| v["reasoning"][0]["reason"] = json!("\0"),
        |v| v["reasoning"] = json!([]),
        |v| v["reasoning"] = json!([v["reasoning"][0], v["reasoning"][0]]),
        |v| v["counterargument"] = json!(""),
        |v| v["uncertainty"]["material"] = json!("false"),
        |v| v["uncertainty"]["confidence"] = json!(100),
    ];
    for mutate in mutations {
        let mut value = payload(Outcome::Allow);
        mutate(&mut value);
        assert!(
            decode_assessment(
                &serde_json::to_vec(&value).unwrap(),
                &scope(),
                &evidence(1, 1),
                SOURCE
            )
            .is_err()
        );
    }
    for raw in [
        b"```json\n{}\n```".as_slice(),
        b"prefix {}",
        b"{\"version\":1,\"version\":1}",
        b"{}{}",
        &vec![b' '; MAX_OUTPUT_BYTES + 1],
    ] {
        assert!(decode_assessment(raw, &scope(), &evidence(1, 1), SOURCE).is_err());
    }
}

#[test]
fn a_concept_needs_both_assessments_and_both_opposite_supporting_reviews() {
    for outcome in [Outcome::Allow, Outcome::Deny] {
        let (assessments, mut reviews) = records(outcome);
        reviews.swap(0, 1);
        let concept = resolve(&scope(), SOURCE, &assessments, &reviews).unwrap();
        assert_eq!(concept.outcome, outcome);
        assert_eq!(
            concept.reasons,
            [DecisionReason::MatchingAssessmentsAndOppositeReviews]
        );
        assert_eq!(concept.decision_scope, "principle_framework_concept_only");
        assert_eq!(concept.legal_status, "not_determined");
        assert!(!concept.enforcement_authority && !concept.network_policy_changed);
        assert!(
            !concept.independent_evidence_proven && !concept.semantic_reasoning_correctness_proven
        );
        assert_eq!(
            concept.assessments[0].sha256().unwrap(),
            assessments[0].sha256().unwrap()
        );
        assert_eq!(
            hash(&concept.reviews[0]).unwrap(),
            hash(&reviews[0]).unwrap()
        );
    }
}

#[test]
fn disagreement_and_material_uncertainty_are_retained_not_majority_voted_away() {
    let assessments = [assessment(1, Outcome::Allow), assessment(2, Outcome::Deny)];
    let reviews = [review(1, &assessments[1]), review(2, &assessments[0])];
    let concept = resolve(&scope(), SOURCE, &assessments, &reviews).unwrap();
    assert_eq!(concept.outcome, Outcome::Undetermined);
    assert!(
        concept
            .reasons
            .contains(&DecisionReason::AssessmentDisagreement)
    );
    assert_eq!(concept.assessments[1].assessment.outcome, Outcome::Deny);

    for uncertain in 0..4 {
        let (mut assessments, mut reviews) = records(Outcome::Allow);
        if uncertain < 2 {
            assessments[uncertain].assessment.uncertainty.material = true;
            // Retain valid opposite review bindings to the changed assessment.
            reviews = [review(1, &assessments[1]), review(2, &assessments[0])];
        } else {
            reviews[uncertain - 2].review.uncertainty.material = true;
        }
        let concept = resolve(&scope(), SOURCE, &assessments, &reviews).unwrap();
        assert_eq!(concept.outcome, Outcome::Undetermined);
        assert!(
            concept
                .reasons
                .contains(&DecisionReason::MaterialUncertainty)
        );
    }
    for verdict in [ReviewVerdict::Disagree, ReviewVerdict::Undetermined] {
        let (assessments, mut reviews) = records(Outcome::Allow);
        reviews[0].review.verdict = verdict;
        let concept = resolve(&scope(), SOURCE, &assessments, &reviews).unwrap();
        assert_eq!(concept.outcome, Outcome::Undetermined);
        assert_eq!(concept.reviews[0].review.verdict, verdict);
    }
    let (assessments, reviews) = records(Outcome::Undetermined);
    assert_eq!(
        resolve(&scope(), SOURCE, &assessments, &reviews)
            .unwrap()
            .outcome,
        Outcome::Undetermined
    );
}

#[test]
fn self_review_duplicate_jobs_and_wrong_review_target_cannot_mint_consensus() {
    let (assessments, reviews) = records(Outcome::Allow);
    let mut raw = payload(Outcome::Allow);
    raw["verdict"] = json!("support");
    assert!(
        decode_review(
            &serde_json::to_vec(&raw).unwrap(),
            &scope(),
            &evidence(1, 9),
            &assessments[0],
            SOURCE
        )
        .is_err()
    );
    let mut wrong_scope = scope();
    wrong_scope.source_manifest_id = "f".repeat(64);
    assert!(resolve(&wrong_scope, SOURCE, &assessments, &reviews).is_err());
    assert!(
        resolve(
            &scope(),
            SOURCE,
            &[assessments[0].clone(), assessments[0].clone()],
            &reviews
        )
        .is_err()
    );
    for mutation in 0..5 {
        let mut changed = reviews.clone();
        match mutation {
            0 => changed[0].reviewed_assessment_sha256 = "d".repeat(64),
            1 => changed[0].evidence.provider_key = key(3),
            2 => changed[0]
                .evidence
                .job_id
                .clone_from(&assessments[0].evidence.job_id),
            3 => changed[0] = changed[1].clone(),
            _ => changed[0].scope.source_publisher_key = key(4),
        }
        assert!(resolve(&scope(), SOURCE, &assessments, &changed).is_err());
    }
}
