use super::*;

fn output() -> Value {
    json!({"text":"An explicitly public answer.",
        "provider_key":hex::encode(ed25519_dalek::SigningKey::from_bytes(&[19;32]).verifying_key().as_bytes()),
        "job_id":"1".repeat(32),"report_sha256":"2".repeat(64),
        "model_fingerprint":"3".repeat(64),"output_index":0,
        "generated_tokens":64,"text_truncated":false})
}

#[test]
fn execution_limits_are_retained_without_fabricating_answer_quality() {
    let mut row = output();
    let answer = Answer::from_output(&row, &"4".repeat(64), 0, 123).unwrap();
    assert_eq!(answer.generated_tokens, 64);
    assert_eq!(unusable(std::slice::from_ref(&answer)), None);
    row["text_truncated"] = true.into();
    let truncated = Answer::from_output(&row, &"4".repeat(64), 0, 123).unwrap();
    assert_eq!(
        unusable(&[truncated]),
        Some("worker_output_was_wire_truncated")
    );
    row["text"] = " ".into();
    row["text_truncated"] = false.into();
    let empty = Answer::from_output(&row, &"4".repeat(64), 0, 123).unwrap();
    assert_eq!(unusable(&[empty]), Some("worker_produced_empty_answer"));
    row.as_object_mut().unwrap().remove("generated_tokens");
    assert!(Answer::from_output(&row, &"4".repeat(64), 0, 123).is_err());
    row = output();
    row["generated_tokens"] = 65.into();
    assert!(Answer::from_output(&row, &"4".repeat(64), 0, 123).is_err());
}

#[test]
fn incomplete_synthesis_cannot_inherit_leaf_completion() {
    let mut result = json!({"complete":true,"answers":["retained original answer"]});
    unfinished(
        "reduction_did_not_shrink_no_inputs_discarded",
        &[],
        &mut result,
    );
    assert_eq!(result["complete"], false);
    assert_eq!(result["synthesis"]["complete"], false);
    assert_eq!(result["answers"][0], "retained original answer");
    assert!(result.get("synthesized_answer").is_none());
}
