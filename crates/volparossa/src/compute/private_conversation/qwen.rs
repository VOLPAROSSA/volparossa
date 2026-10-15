//! Native template aliases are transport names, not authority or executable commands.
use super::{Generation, Input, Output, Tool, Value, json};
use anyhow::{Result, ensure};
use serde::Deserialize;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Call {
    name: String,
    #[serde(deserialize_with = "super::strict_json::value")]
    arguments: Value,
}

fn parse(input: &Input, raw: &str, id: &str) -> Result<Output> {
    ensure!(
        id.len() == 32
            && id
                .bytes()
                .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)),
        "conversation_request_id"
    );
    ensure!(
        !["<think", "</think", "<|im_", "<|endoftext|>"]
            .iter()
            .any(|marker| raw.contains(marker)),
        "conversation_native_marker"
    );
    let trimmed = raw.trim();
    let call: Call = if !trimmed.contains("<tool_call") && !trimmed.contains("</tool_call") {
        // The exact standalone JSON object is a second proposal encoding, not
        // authority to execute. Never extract JSON from prose or repair a call.
        match (!input.tools.is_empty())
            .then(|| serde_json::from_str(trimmed).ok())
            .flatten()
        {
            Some(call) => call,
            None => {
                return Ok(Output::Assistant {
                    text: raw.to_owned(),
                });
            }
        }
    } else {
        // The pinned native template emits optional assistant content, then a
        // newline and the tagged call. Parse that whole bounded production, not
        // JSON extracted from prose or a fenced example. The preface grants no
        // authority; only the exact offered call becomes a proposal.
        let (preface, tagged_body) = trimmed
            .split_once("<tool_call>")
            .ok_or_else(|| anyhow::anyhow!("conversation_native_call"))?;
        ensure!(
            preface.is_empty()
                || (preface.ends_with('\n')
                    && super::text(preface, 4096, true)
                    && !["<tool_call", "</tool_call", "```", "~~~"]
                        .iter()
                        .any(|marker| preface.contains(marker))),
            "conversation_native_preface"
        );
        let body = tagged_body
            .strip_suffix("</tool_call>")
            .ok_or_else(|| anyhow::anyhow!("conversation_native_call"))?;
        serde_json::from_str(body)?
    };
    let tool = input
        .tools
        .iter()
        .enumerate()
        .find_map(|(index, tool)| (call.name == format!("vp_{index}")).then_some(tool))
        .ok_or_else(|| anyhow::anyhow!("conversation_unknown_tool"))?;
    let call_id = format!("vp-{id}");
    Ok(match tool {
        Tool::Function {
            name, namespace, ..
        } => Output::FunctionCall {
            call_id,
            name: name.clone(),
            namespace: namespace.clone(),
            arguments: call.arguments,
        },
        Tool::Custom {
            name, namespace, ..
        } => {
            let object = call
                .arguments
                .as_object()
                .ok_or_else(|| anyhow::anyhow!("conversation_custom_input"))?;
            ensure!(object.len() == 1, "conversation_custom_input");
            let input = object
                .get("input")
                .and_then(Value::as_str)
                .ok_or_else(|| anyhow::anyhow!("conversation_custom_input"))?;
            Output::CustomToolCall {
                call_id,
                name: name.clone(),
                namespace: namespace.clone(),
                input: input.to_owned(),
            }
        }
    })
}

fn checked_parse(input: &Input, raw: &str, id: &str) -> Result<Output> {
    let value = parse(input, raw, id)?;
    input.validate_output(&value)?;
    Ok(value)
}

fn json_rejection_code(error: &serde_json::Error) -> &'static str {
    // Never format the error: it may contain private field names or values.
    // The current string parser cannot produce I/O errors, but keep the
    // exhaustive category closed without treating that case as success.
    match error.classify() {
        serde_json::error::Category::Syntax => "conversation_native_json_syntax",
        serde_json::error::Category::Data => "conversation_native_json_data",
        serde_json::error::Category::Eof => "conversation_native_json_eof",
        serde_json::error::Category::Io => "conversation_native_json_io",
    }
}

/// A closed local observation, used only after the complete worker report has
/// been independently bound to this exact input/output. Never export the parser
/// error: JSON diagnostics can contain private tool names or argument text.
pub(super) fn rejection_code(input: &Input, output: &Value, id: &str) -> &'static str {
    let Some(raw) = output["text"].as_str() else {
        return "conversation_native_output_other";
    };
    let Err(error) = checked_parse(input, raw, id) else {
        return "conversation_native_output_other";
    };
    if let Some(error) = error.downcast_ref::<serde_json::Error>() {
        return json_rejection_code(error);
    }
    match error.to_string().as_str() {
        "conversation_request_id" => "conversation_request_id",
        "conversation_native_marker" => "conversation_native_marker",
        "conversation_native_call" => "conversation_native_call",
        "conversation_native_preface" => "conversation_native_preface",
        "conversation_unknown_tool" => "conversation_unknown_tool",
        "conversation_custom_input" => "conversation_custom_input",
        "conversation_arguments" => "conversation_arguments",
        "conversation_call_id" => "conversation_call_id",
        "conversation_empty_answer" => "conversation_empty_answer",
        _ => "conversation_native_output_other",
    }
}

pub(super) fn turn(input: &Input, output: &Value, id: &str) -> Result<Value> {
    let generation = Generation::from_output(output, true)?
        .ok_or_else(|| anyhow::anyhow!("conversation_generation"))?;
    let incomplete = |reason| json!({"type":"incomplete","reason":reason});
    if output["text_truncated"] == true {
        return Ok(incomplete("wire_truncated"));
    }
    if !generation.is_eos() {
        return Ok(incomplete("token_limit"));
    }
    match output["text"]
        .as_str()
        .and_then(|raw| checked_parse(input, raw, id).ok())
    {
        Some(value) => Ok(serde_json::to_value(value)?),
        None => Ok(incomplete("invalid_output")),
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn json_io_category_does_not_format_private_error_text() {
        // Inert classification only; the production from_str path performs no I/O.
        let error = serde_json::Error::io(std::io::Error::other("/PRIVATE_CANARY/field"));
        assert_eq!(
            super::json_rejection_code(&error),
            "conversation_native_json_io"
        );
    }
}
