# Private conversation v1 (local JSON exception)

This is an additive, typed operation family on `compute private-serve`'s existing
same-owner mode-0600 Unix socket. Existing `capabilities` and `submit` Q&A requests
and replies are unchanged for their existing model profiles. Framing remains unsigned
big-endian 4-byte length plus UTF-8 JSON. Existing requests remain at most 32,768
bytes; only `submit_conversation` on the explicitly selected Qwen profile permits
524,288 bytes. All response frames remain at most 65,536 bytes. No HTTP listener,
peer dispatch, public caching, training, tool execution or automatic model download.

Every envelope is `{ "version": 1, "id": "32 lowercase hex digits", "operation": ... }`.
IDs remain unique per connection, with the existing 256-request connection limit.
First send `{ "type": "conversation_capabilities" }`; response event is
`conversation_capabilities` with `capabilities`. The old Q&A handshake does not
authorize conversation submission. Both families share one execution slot.

## Submit and history

Operation: `{ "type": "submit_conversation", "conversation": INPUT }`, where INPUT
has exactly `version:1`, `visibility:"private_local"`, `instructions`, `history`, `tools`.
Instructions are text, not commands executed by the worker. History is ordered:

- `{ "type":"message", "role":"user"|"assistant", "text":"..." }`
- `{ "type":"function_call", "call_id":"c1", "name":"read_file", "namespace":null,
  "arguments":{ "name":"demo.rs" } }`
- `{ "type":"custom_tool_call", "call_id":"c2", "name":"patch", "namespace":null,
  "input":"literal proposed patch" }`
- `{ "type":"tool_result", "call_id":"c1", "output":"literal tool output" }`

Tool definitions are `{ "type":"function", "name", "namespace"?, "description",
"parameters":{ "type":"object", ... } }` or `{ "type":"custom", "name",
"namespace"?, "description" }`. Omitted namespace means null. Names, namespaces
and call IDs contain 1–64 ASCII letters/digits/underscore/dot/hyphen.

Each call refers to an offered tool of the matching kind and exact namespace. Call
IDs cannot repeat. Tool results must close a preceding open call exactly once.
Messages cannot interrupt open calls; all calls must be closed and the last item
must be a user message or tool result. Multiple preceding calls/results may be
represented, but this generation mode proposes at most one new call per turn.
Historical tools cannot silently disappear from the offered set in this version.
The Qwen profile additionally admits ordered `system` and `developer` message roles.
Its pinned template has no developer branch: the worker explicitly maps each such
item to a system message labeled `Developer instructions:\n`, at the same history
position. It does not silently drop developer text or move it to the initial prompt.

Function parameters are passed through to the model as data. This slice validates
object shape/size and offered identity, **not arbitrary JSON Schema semantics**.
The application/tool harness remains responsible for argument validation, user
approval, workspace restrictions and execution. Custom tools accept literal input;
grammar-enforced custom tools are not advertised by this contract.

## Result and cancellation

Admission yields `event:"admitted"`. The eventual `event:"result"` contains:

`{ version:1, operation:"compute_private_conversation", model_profile,
execution_complete:true, turn_complete, output, prompt_tokens, generated_tokens,
limits, local_only:true, private_data_supported:true, tool_execution:false,
distributed_execution_claimed:false, private_training_claimed:false,
model_answer_correctness_proven:false,
cleanup:{complete:true,retained_input:false,retained_report:false} }`.

`output` is exactly one of:

- `{ "type":"assistant", "text":"..." }`
- A `function_call` or `custom_tool_call` with the same fields as history above.
  Namespace is always explicitly null/string in results. Smol's JSON-turn contract
  asks the model for a fresh call ID. Qwen's native template has no generated ID:
  after parsing its genuine tool proposal the worker assigns `vp-` plus its fresh
  32-hex execution request ID. Neither may duplicate a historical call.
- `{ "type":"incomplete", "reason":"token_limit"|"wire_truncated"|"invalid_output" }`.

Only complete EOS generation can produce a complete assistant/tool proposal.
Smol requires strict JSON; Qwen accepts plain assistant text or exactly one native
`<tool_call>{"name":"vp_N","arguments":{...}}</tool_call>` with strict JSON.
Mixed prose/calls, multiple new calls, reasoning markers and partial calls are
incomplete rather than silently repaired. No Markdown stripping, JSON repair or invented
tool call. `turn_complete` means syntactic completion, not correctness or task
completion. Do not execute an incomplete result or count it as an answer.

Cancel uses the unchanged `{ "type":"cancel", "task_id": SUBMIT_ID }` operation.
`cancel_requested` is not terminal cleanup. Disconnect, cancellation and shutdown
retain the existing worker/descendant join and staging cleanup path; uncertain
cleanup quarantines the slot. Existing closed error events apply. The server does
not retry a failed generation or disclose raw parser/backend diagnostics.

## Explicit limits

Capabilities contain the same model/limits facts as result `limits`, plus
`execution_slots:1`, `max_seconds`, `max_request_bytes`, `max_response_bytes`,
`quarantined`. Fixed facts include version, visibility, local_only, tool_execution,
network_access:false, public_cache:false, training:false, cloud_fallback:false,
model_tool_use_proven:false, arbitrary_json_schema_validation:false.

For existing Smol profiles: `max_input_bytes=24576`, `max_history_items=32`, `max_tools=8`,
`max_instructions_bytes=4096`, `max_message_bytes=8192`,
`max_tool_description_bytes=2048`, `max_tool_payload_bytes=4096`.

The current exact profiles retain their existing prompt/output budgets: 135M is
192/64 tokens, 360M and 1.7B are 1024/256 tokens; output byte bounds remain 1024/4096.
Their pinned configuration has `model_context_tokens=8192`, **not permission to
use all 8192**. The complete instructions, JSON response contract, offered tools
and history go through the actual tokenizer's chat template and must fit
`max_prompt_tokens`; no input is truncated. Metadata reports the actual count.
Very small profiles/large inputs may consequently reject every offered task.

`conversation_template="smollm2-json-turn-v1"`, `native_tool_template=false`:
the current SmolLM template is used with an explicit JSON-turn instruction, not
misrepresented as native function-calling training. The normal Codex prompt/tools
do not fit these Smol limits. The opt-in Qwen profile below has separate limits;
an actual coding-loop proof remains separate work. This protocol does not itself
prove tool-use quality.

## Explicit Qwen native conversation profile

`qwen3-0.6b-v1` pins `Qwen/Qwen3-0.6B` revision
`c1899de289a04d12100db370d81485cdf75e47ca`, Apache-2.0. It is private conversation
only: no public broker, Q&A, training, planning, adapter or network execution.
The existing 38-wheel runtime is reused, with local-only model loading and no remote
Python code. Provisioning is a separate explicit guest-only operation.

Its exact caps are `max_input_bytes=262144`, `max_instructions_bytes=65536`,
`max_history_items=128`, `max_tools=32`, `max_message_bytes=65536`,
`max_tool_description_bytes=8192`, `max_tool_payload_bytes=4096`,
`max_prompt_tokens=12288`, `max_new_tokens=1024`, `model_context_tokens=32768`,
`max_output_bytes=4096`, `conversation_template="qwen3-tools-nonthinking-v1"`,
`native_tool_template=true`. Capability `max_request_bytes=524288` applies only to
conversation submission; other operations retain the old 32,768-byte bound.
The owner's model selector cannot be changed by an IPC request.

Complete instructions, history and schemas go through the actual pinned tokenizer
with native `tools=`, `enable_thinking=false`, no truncation and a 1,024-token output
reserve. The conservative 32,768 context is not the tokenizer's advertised 131,072.
20.9KB instructions pass the byte gate, but are **not guaranteed** to fit together
with every history/tool set after tokenization. Output retains the existing 4KiB
escaped-text limit and explicit incomplete status; this is not an unlimited coding agent.

Offered identities map by order to `vp_0`, `vp_1`, etc.; returned calls map back to
the exact original name and namespace. Function schemas are passed as supplied.
A custom tool is deliberately represented as a native function with exactly one
required string field `input`, then returned as `custom_tool_call`, never executed.
Historical call content and tool-result content explicitly carry their original
call IDs; tool results also carry the alias because the upstream template itself
omits call IDs. Native tool descriptions retain the original identity alongside
the alias. The worker does not fabricate model choices.

Qwen loads only CPU BF16 parameters and SDPA attention; actual report fields are
`model_parameter_dtype:"bfloat16"`, `model_attention_backend:"sdpa"`. There is no
FP32/eager retry. Admission requires 4.5GiB known spare memory; the supervisor's
RSS stop threshold is 4GiB, address-space limit 10GiB, maximum two threads. These
checks are not a hard 4GiB cgroup proof or a performance guarantee. Actual weights,
native tool quality, long-context memory use and an end-to-end coding loop still
require the disposable, hard-memory-bounded functional run.
