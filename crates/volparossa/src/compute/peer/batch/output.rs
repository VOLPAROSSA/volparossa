//! Presentation of terminal worker output, never authority to retry a completed job.

use std::path::Path;

use anyhow::{Context as _, Result};
use serde_json::Value;

use crate::compute::inference_output::Generation;

/// Preserve the established legacy projection; new output carries its whole ending contract.
pub(in crate::compute::peer) fn retain(source: &Value, target: &mut Value) -> Result<()> {
    if let Some(generation) = Generation::from_output(source, false)? {
        target["generation"] = serde_json::to_value(generation)?;
        target["generated_tokens"] = source["generated_tokens"].clone();
        target["text_truncated"] = source["text_truncated"].clone();
    }
    Ok(())
}

pub(in crate::compute::peer) fn status(output: &Value) -> Result<&'static str> {
    let Some(generation) = Generation::from_output(output, false)? else {
        return Ok("legacy_unknown");
    };
    let text = output["text"].as_str().context("compute_answer_text")?;
    if output["text_truncated"]
        .as_bool()
        .context("compute_answer_truncation")?
    {
        Ok("wire_truncated")
    } else if text.trim().is_empty() {
        Ok("empty")
    } else if generation.is_eos() {
        Ok("eos")
    } else {
        Ok("token_limit")
    }
}

pub(in crate::compute::peer) fn annotate(output: &mut Value) -> Result<()> {
    let state = status(output)?;
    output["answer_status"] = state.into();
    output["answer_complete"] = (state == "eos").into();
    Ok(())
}

pub(in crate::compute::peer) fn all_complete(outputs: &[Value]) -> Result<bool> {
    let mut complete = !outputs.is_empty();
    for output in outputs {
        complete &= status(output)? == "eos";
    }
    Ok(complete)
}

pub(in crate::compute::peer) fn has_legacy_unknown(result: &Value) -> bool {
    result["answers"].as_array().is_some_and(|answers| {
        answers
            .iter()
            .any(|answer| answer["answer_status"] == "legacy_unknown")
    }) || result["nodes"].as_array().is_some_and(|nodes| {
        nodes
            .iter()
            .any(|node| node["answer_status"] == "legacy_unknown")
    }) || result["synthesis"]["reason"] == "legacy_generation_end_unknown"
}

/// Only an explicitly legacy-unknown current view may preserve an old aggregate.
/// This retains historical bytes, not a claim to have revalidated unreachable old
/// graph reductions; the current view reports only the execution actually checked.
pub(in crate::compute::peer) fn preserve_legacy_result(
    path: &Path,
    maximum: u64,
    rounds: u64,
    current: &Value,
) -> Result<bool> {
    if rounds != 0 || !has_legacy_unknown(current) || !path.try_exists()? {
        return Ok(false);
    }
    let saved: Value = serde_json::from_slice(&crate::compute::read_file(path, maximum)?)?;
    Ok(saved["version"] == 1 && saved["complete"] == true)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    #[test]
    fn ending_and_transport_shortening_are_independent_of_execution() {
        let mut row = json!({"text":"Public answer", "generated_tokens":64,
            "text_truncated":false,"generation":{"version":1,"stop_reason":"eos","max_new_tokens":64}});
        assert_eq!(status(&row).unwrap(), "eos");
        row["generation"]["stop_reason"] = "token_limit".into();
        assert_eq!(status(&row).unwrap(), "token_limit");
        assert!(!all_complete(&[row.clone()]).unwrap());
        row["text_truncated"] = true.into();
        assert_eq!(status(&row).unwrap(), "wire_truncated");
        row["text_truncated"] = false.into();
        row["text"] = " ".into();
        assert_eq!(status(&row).unwrap(), "empty");
        row.as_object_mut().unwrap().remove("generation");
        assert_eq!(status(&row).unwrap(), "legacy_unknown");
    }

    #[test]
    fn new_outputs_retain_ending_without_rewriting_legacy_projection() {
        let source = json!({"text":"public", "generated_tokens":4,"text_truncated":false});
        let mut target = json!({"text":"public"});
        retain(&source, &mut target).unwrap();
        assert_eq!(target, json!({"text":"public"}));
        let mut source = source;
        source["generation"] = json!({"version":1,"stop_reason":"eos","max_new_tokens":64});
        retain(&source, &mut target).unwrap();
        assert_eq!(target, source);
        annotate(&mut target).unwrap();
        assert_eq!(target["answer_complete"], true);
    }

    #[test]
    fn only_an_explicit_legacy_view_preserves_an_old_completed_result() {
        use std::os::unix::fs::{MetadataExt as _, PermissionsExt as _};
        let directory = tempfile::tempdir().unwrap();
        std::fs::set_permissions(directory.path(), std::fs::Permissions::from_mode(0o700)).unwrap();
        let path = directory.path().join("result.json");
        let raw = br#"{"version":1,"complete":true,"output":"historical"}"#;
        crate::compute::peer::task::write_bytes(&path, raw, false).unwrap();
        let inode = std::fs::metadata(&path).unwrap().ino();
        let view = json!({"version":2,"complete":false,"execution_complete":true,
            "answers":[{"answer_status":"legacy_unknown"}]});
        assert!(preserve_legacy_result(&path, 4096, 0, &view).unwrap());
        assert!(!preserve_legacy_result(&path, 4096, 1, &view).unwrap());
        assert!(
            !preserve_legacy_result(
                &path,
                4096,
                0,
                &json!({"version":2,"complete":true,"answers":[{"answer_status":"eos"}]})
            )
            .unwrap()
        );
        assert_eq!(std::fs::read(&path).unwrap(), raw);
        assert_eq!(std::fs::metadata(path).unwrap().ino(), inode);
    }
}
