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
        let body = trimmed
            .strip_prefix("<tool_call>")
            .and_then(|v| v.strip_suffix("</tool_call>"))
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
        .and_then(|raw| parse(input, raw, id).ok())
        .filter(|value| input.validate_output(value).is_ok())
    {
        Some(value) => Ok(serde_json::to_value(value)?),
        None => Ok(incomplete("invalid_output")),
    }
}
