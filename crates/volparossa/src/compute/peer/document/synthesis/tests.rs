use super::*;

#[test]
fn completed_replay_preserves_execution_summary_but_new_work_is_recorded() {
    use std::{
        fs,
        os::unix::fs::{MetadataExt, PermissionsExt},
    };

    let directory = tempfile::tempdir().unwrap();
    fs::set_permissions(directory.path(), fs::Permissions::from_mode(0o700)).unwrap();
    let path = directory.path().join("last-workflow-report.json");
    let first = json!({"complete":true,"rounds_this_invocation":1,"maximum_rounds_per_window":32});
    retain_workflow_report(directory.path(), &first).unwrap();
    let original = fs::read(&path).unwrap();
    let inode = fs::metadata(&path).unwrap().ino();
    let replay = json!({"complete":true,"rounds_this_invocation":0,"maximum_rounds_per_window":1});
    retain_workflow_report(directory.path(), &replay).unwrap();
    assert_eq!(fs::read(&path).unwrap(), original);
    assert_eq!(fs::metadata(&path).unwrap().ino(), inode);

    let pending = json!({"complete":false,"rounds_this_invocation":0});
    retain_workflow_report(directory.path(), &pending).unwrap();
    assert_eq!(
        serde_json::from_slice::<Value>(&fs::read(&path).unwrap()).unwrap(),
        pending
    );
    retain_workflow_report(directory.path(), &first).unwrap();
    assert_eq!(fs::read(&path).unwrap(), original);

    let recovered = tempfile::tempdir().unwrap();
    fs::set_permissions(recovered.path(), fs::Permissions::from_mode(0o700)).unwrap();
    retain_workflow_report(recovered.path(), &replay).unwrap();
    assert!(recovered.path().join("last-workflow-report.json").is_file());
}

fn output() -> Value {
    json!({"text":"An explicitly public answer.",
        "provider_key":hex::encode(ed25519_dalek::SigningKey::from_bytes(&[19;32]).verifying_key().as_bytes()),
        "job_id":"1".repeat(32),"report_sha256":"2".repeat(64),
        "model_fingerprint":"3".repeat(64),"output_index":0,
        "generated_tokens":64,"text_truncated":false,
        "generation":{"version":1,"stop_reason":"eos","max_new_tokens":64}})
}

#[test]
fn execution_limits_are_retained_without_fabricating_answer_quality() {
    let mut row = output();
    let answer = Answer::from_output(&row, &"4".repeat(64), 0, 123).unwrap();
    assert_eq!(answer.generated_tokens, 64);
    assert_eq!(unusable(std::slice::from_ref(&answer)), None);
    row["generation"]["stop_reason"] = "token_limit".into();
    let limited = Answer::from_output(&row, &"4".repeat(64), 0, 123).unwrap();
    assert_eq!(unusable(&[limited]), Some("worker_output_hit_token_limit"));
    row["generation"]["stop_reason"] = "eos".into();
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
fn historical_parent_shape_is_preserved_without_inventing_eos() {
    let mut row = output();
    row.as_object_mut().unwrap().remove("generation");
    let original = Answer::from_output(&row, &"4".repeat(64), 0, 123).unwrap();
    assert_eq!(
        unusable(std::slice::from_ref(&original)),
        Some("legacy_generation_end_unknown")
    );
    let bytes = serde_json::to_vec(&original).unwrap();
    assert!(
        !serde_json::from_slice::<Value>(&bytes)
            .unwrap()
            .as_object()
            .unwrap()
            .contains_key("generation")
    );
    let restored: Answer = serde_json::from_slice(&bytes).unwrap();
    assert_eq!(serde_json::to_vec(&restored).unwrap(), bytes);
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
