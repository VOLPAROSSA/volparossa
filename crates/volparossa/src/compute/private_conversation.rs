//! Private model-generated conversation turns. Tool proposals are data, never execution.

use std::collections::BTreeSet;

use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use serde_json::{Value, json};

use super::{ModelProfile, inference_output::Generation};

mod limits;
mod qwen;
mod strict_json;

pub(super) const MAX_BYTES: usize = 24 * 1024;

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub(super) struct Input {
    version: u8,
    visibility: String,
    instructions: String,
    history: Vec<Item>,
    tools: Vec<Tool>,
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "present_generation_policy"
    )]
    generation_policy: Option<GenerationPolicy>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
enum GenerationPolicy {
    GreedyV1,
}

fn present_generation_policy<'de, D: serde::Deserializer<'de>>(
    deserializer: D,
) -> std::result::Result<Option<GenerationPolicy>, D::Error> {
    // Omission means legacy generation. Explicit null is not a policy selection.
    GenerationPolicy::deserialize(deserializer).map(Some)
}

/// The supervisor must not bind a result after silently accepting duplicate keys.
pub(super) fn decode_worker_message(raw: &[u8]) -> Result<Value> {
    #[derive(Deserialize)]
    struct Message(#[serde(deserialize_with = "strict_json::value")] Value);
    Ok(serde_json::from_slice::<Message>(raw)?.0)
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Role {
    User,
    Assistant,
    System,
    Developer,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Item {
    Message {
        role: Role,
        text: String,
    },
    FunctionCall {
        call_id: String,
        name: String,
        namespace: Option<String>,
        #[serde(deserialize_with = "strict_json::value")]
        arguments: Value,
    },
    CustomToolCall {
        call_id: String,
        name: String,
        namespace: Option<String>,
        input: String,
    },
    ToolResult {
        call_id: String,
        output: String,
    },
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Tool {
    Function {
        name: String,
        namespace: Option<String>,
        description: String,
        #[serde(deserialize_with = "strict_json::value")]
        parameters: Value,
    },
    Custom {
        name: String,
        namespace: Option<String>,
        description: String,
    },
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
enum Output {
    Assistant {
        text: String,
    },
    FunctionCall {
        call_id: String,
        name: String,
        namespace: Option<String>,
        #[serde(deserialize_with = "strict_json::value")]
        arguments: Value,
    },
    CustomToolCall {
        call_id: String,
        name: String,
        namespace: Option<String>,
        input: String,
    },
}

fn text(value: &str, maximum: usize, nonempty: bool) -> bool {
    value.len() <= maximum && !value.contains('\0') && (!nonempty || !value.trim().is_empty())
}

fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"_.-".contains(&byte))
}

fn arguments(value: &Value) -> bool {
    value.is_object() && serde_json::to_vec(value).is_ok_and(|raw| raw.len() <= 4096)
}

impl Tool {
    fn key(&self) -> (&str, Option<&str>) {
        match self {
            Self::Function {
                name, namespace, ..
            }
            | Self::Custom {
                name, namespace, ..
            } => (name, namespace.as_deref()),
        }
    }

    fn validate(&self, bounds: &limits::Limits) -> Result<()> {
        let (name, namespace) = self.key();
        ensure!(
            identifier(name) && namespace.is_none_or(identifier),
            "conversation_tool_name"
        );
        let description = match self {
            Self::Function {
                description,
                parameters,
                ..
            } => {
                ensure!(
                    arguments(parameters) && parameters["type"] == "object",
                    "conversation_tool_schema"
                );
                description
            }
            Self::Custom { description, .. } => description,
        };
        ensure!(
            text(description, bounds.description, true),
            "conversation_tool_description"
        );
        Ok(())
    }
}

impl Input {
    pub(super) fn requires_generation_policy_handshake(&self) -> bool {
        self.generation_policy.is_some()
    }

    #[cfg(test)]
    pub(super) fn decode(raw: &[u8]) -> Result<Self> {
        Self::decode_profile(raw, ModelProfile::Smol360)
    }

    pub(super) fn decode_profile(raw: &[u8], profile: ModelProfile) -> Result<Self> {
        ensure!(
            !raw.is_empty() && raw.len() <= limits::for_profile(profile).input,
            "conversation_input_bound"
        );
        let input: Self =
            serde_json::from_slice(raw).map_err(|_| anyhow::anyhow!("conversation_schema"))?;
        input.validate_profile(profile)?;
        Ok(input)
    }

    #[cfg(test)]
    pub(super) fn bytes(&self) -> Result<Vec<u8>> {
        self.bytes_profile(ModelProfile::Smol360)
    }

    pub(super) fn bytes_profile(&self, profile: ModelProfile) -> Result<Vec<u8>> {
        self.validate_profile(profile)?;
        let bytes = serde_json::to_vec(self)?;
        ensure!(
            bytes.len() <= limits::for_profile(profile).input,
            "conversation_input_bound"
        );
        Ok(bytes)
    }

    fn validate_profile(&self, profile: ModelProfile) -> Result<()> {
        let bounds = limits::for_profile(profile);
        ensure!(
            self.generation_policy.is_none() || profile.is_native_conversation(),
            "conversation_generation_policy"
        );
        ensure!(
            self.version == 1 && self.visibility == "private_local",
            "conversation_scope"
        );
        ensure!(
            text(&self.instructions, bounds.instructions, true)
                && (1..=bounds.history).contains(&self.history.len())
                && self.tools.len() <= bounds.tools,
            "conversation_input_bound"
        );
        let mut tools = BTreeSet::new();
        for tool in &self.tools {
            tool.validate(&bounds)?;
            ensure!(tools.insert(tool.key()), "conversation_duplicate_tool");
        }
        let mut pending = BTreeSet::new();
        let mut seen = BTreeSet::new();
        for item in &self.history {
            match item {
                Item::Message {
                    role,
                    text: content,
                } => ensure!(
                    pending.is_empty()
                        && text(content, bounds.text, true)
                        && (profile.is_native_conversation()
                            || matches!(role, Role::User | Role::Assistant)),
                    "conversation_message"
                ),
                Item::FunctionCall {
                    call_id,
                    name,
                    namespace,
                    arguments: args,
                } => {
                    self.call(call_id, name, namespace.as_deref(), false, &seen)?;
                    ensure!(arguments(args), "conversation_arguments");
                    seen.insert(call_id.as_str());
                    pending.insert(call_id.as_str());
                }
                Item::CustomToolCall {
                    call_id,
                    name,
                    namespace,
                    input,
                } => {
                    self.call(call_id, name, namespace.as_deref(), true, &seen)?;
                    ensure!(text(input, 4096, true), "conversation_custom_input");
                    seen.insert(call_id.as_str());
                    pending.insert(call_id.as_str());
                }
                Item::ToolResult { call_id, output } => ensure!(
                    pending.remove(call_id.as_str()) && text(output, bounds.text, false),
                    "conversation_tool_result"
                ),
            }
        }
        ensure!(
            pending.is_empty()
                && matches!(
                    self.history.last(),
                    Some(
                        Item::Message {
                            role: Role::User,
                            ..
                        } | Item::ToolResult { .. }
                    )
                ),
            "conversation_unfinished_history"
        );
        Ok(())
    }

    fn call(
        &self,
        id: &str,
        name: &str,
        namespace: Option<&str>,
        custom: bool,
        seen: &BTreeSet<&str>,
    ) -> Result<()> {
        ensure!(identifier(id) && !seen.contains(id), "conversation_call_id");
        ensure!(
            self.tools.iter().any(|tool| tool.key() == (name, namespace)
                && matches!(tool, Tool::Custom { .. }) == custom),
            "conversation_unknown_tool"
        );
        Ok(())
    }

    fn validate_output(&self, output: &Output) -> Result<()> {
        let seen = self
            .history
            .iter()
            .filter_map(|item| match item {
                Item::FunctionCall { call_id, .. } | Item::CustomToolCall { call_id, .. } => {
                    Some(call_id.as_str())
                }
                _ => None,
            })
            .collect();
        match output {
            Output::Assistant { text: content } => {
                ensure!(text(content, 4096, true), "conversation_empty_answer");
            }
            Output::FunctionCall {
                call_id,
                name,
                namespace,
                arguments: args,
            } => {
                self.call(call_id, name, namespace.as_deref(), false, &seen)?;
                ensure!(arguments(args), "conversation_arguments");
            }
            Output::CustomToolCall {
                call_id,
                name,
                namespace,
                input,
            } => {
                self.call(call_id, name, namespace.as_deref(), true, &seen)?;
                ensure!(text(input, 4096, true), "conversation_custom_input");
            }
        }
        Ok(())
    }
}

pub(super) fn capabilities(profile: ModelProfile) -> Value {
    let spec = profile.spec();
    let bounds = limits::for_profile(profile);
    let native = profile.is_native_conversation();
    let template = match profile {
        ModelProfile::Qwen600 => "qwen3-tools-nonthinking-v1",
        ModelProfile::Qwen4bInstruct2507 => "qwen3-tools-instruct-2507-v1",
        _ => "smollm2-json-turn-v1",
    };
    json!({"version":1,"visibility":"private_local","model_profile":profile,
        "max_input_bytes":bounds.input,"max_history_items":bounds.history,"max_tools":bounds.tools,
        "max_instructions_bytes":bounds.instructions,"max_message_bytes":bounds.text,"max_tool_description_bytes":bounds.description,
        "max_tool_payload_bytes":4096,
        "max_prompt_tokens":spec.prompt_tokens,"max_new_tokens":spec.max_new_tokens,
        "model_context_tokens":bounds.context_tokens,"max_output_bytes":spec.max_output_bytes,
        "conversation_template":template,"native_tool_template":native,
        "local_only":true,"tool_execution":false,"network_access":false,
        "public_cache":false,"training":false,"cloud_fallback":false,
        "model_tool_use_proven":false,"arbitrary_json_schema_validation":false})
}

pub(super) const fn request_frame(profile: ModelProfile) -> usize {
    limits::for_profile(profile).request_frame
}

/// Derive the typed turn from the original model text, never from broker-invented calls.
pub(super) fn turn(input: &Input, output: &Value) -> Result<Value> {
    let generation = Generation::from_output(output, true)?
        .ok_or_else(|| anyhow::anyhow!("conversation_generation"))?;
    let incomplete = |reason| json!({"type":"incomplete","reason":reason});
    if output["text_truncated"] == true {
        return Ok(incomplete("wire_truncated"));
    }
    if !generation.is_eos() {
        return Ok(incomplete("token_limit"));
    }
    let parsed = output["text"]
        .as_str()
        .and_then(|raw| serde_json::from_str::<Output>(raw).ok());
    match parsed.filter(|value| input.validate_output(value).is_ok()) {
        Some(value) => Ok(serde_json::to_value(value)?),
        None => Ok(incomplete("invalid_output")),
    }
}

pub(super) fn validate_report(report: &Value, raw: &[u8], profile: ModelProfile) -> Result<()> {
    let input = Input::decode_profile(raw, profile)?;
    let expected_policy = input.generation_policy.map(|policy| json!(policy));
    ensure!(
        report.get("generation_policy") == expected_policy.as_ref(),
        "conversation_generation_policy_binding"
    );
    let expected = if profile.is_native_conversation() {
        qwen::turn(
            &input,
            &report["outputs"][0],
            report["id"].as_str().unwrap_or_default(),
        )?
    } else {
        turn(&input, &report["outputs"][0])?
    };
    ensure!(
        report["conversation_limits"] == capabilities(profile)
            && report["prompt_tokens"]
                .as_u64()
                .is_some_and(|count| (1..=u64::from(profile.spec().prompt_tokens)).contains(&count))
            && report["conversation"] == expected,
        "conversation_report_binding"
    );
    Ok(())
}

pub(super) fn summary(report: &Value, profile: ModelProfile) -> Value {
    let mut result = json!({"version":1,"operation":"compute_private_conversation","model_profile":profile,
        "execution_complete":true,"turn_complete":report["conversation"]["type"] != "incomplete",
        "output":report["conversation"],"prompt_tokens":report["prompt_tokens"],
        "generated_tokens":report["outputs"][0]["generated_tokens"],"limits":report["conversation_limits"],
        "local_only":true,"private_data_supported":true,"tool_execution":false,
        "distributed_execution_claimed":false,"private_training_claimed":false,
        "model_answer_correctness_proven":false,
        "cleanup":{"complete":true,"retained_input":false,"retained_report":false}});
    if let Some(policy) = report.get("generation_policy") {
        result["generation_policy"] = policy.clone();
    }
    result
}

#[cfg(test)]
mod tests;
