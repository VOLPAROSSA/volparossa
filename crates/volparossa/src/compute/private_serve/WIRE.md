# Private local compute IPC v1

This is a separate **same-owner local Unix socket** interface, not the public
compute broker or a signed peer protocol. Requests never select file paths,
executables, models, adapters or budgets. The owner starts
`volparossa compute private-serve --runtime-root … --model-root … --work-parent …
--socket … --execute`. Paths are absolute; directories must already be owned,
canonical and mode `0700`. The new socket is mode `0600`; peers must have the same
effective UID. No model installation/download or cloud fallback is performed.

## Framing and schema

Each frame is a four-byte **big-endian unsigned length**, then that many bytes of
UTF-8 JSON. Requests are 1–32768 bytes; responses are at most 65536 bytes. After a
frame begins, its remaining length/body must arrive within five seconds. Replies
have a three-second write deadline. All request objects/enums reject unknown and
duplicate fields. This strict, bounded JSON is a documented **local-only exception**
to the project's preferred protobuf encoding, allowing Firefox privileged JS to
use its native JSON facilities without a new generated-code dependency. It is not
used as a signature encoding or public/network protocol.

Every request has `version: 1`, a unique per-connection `id` of 32 lowercase hex
characters, and an `operation` object. At most 256 requests are accepted on one
connection. A new connection starts a new scope; no result can be retrieved by ID
from another connection. Unknown versions, fields, operations and invalid text
are rejected, without echoing parser diagnostics or submitted content.

```json
{"version":1,"id":"01010101010101010101010101010101","operation":{"type":"capabilities"}}
{"version":1,"id":"02020202020202020202020202020202","operation":{"type":"submit","question":"What does this passage mean?","context":"Explicit user-selected passage."}}
{"version":1,"id":"03030303030303030303030303030303","operation":{"type":"cancel","task_id":"02020202020202020202020202020202"}}
```

Capabilities must be requested before submission. Question/context must each be
nonblank, without NUL, and fit 512/4096 **UTF-8 bytes** respectively. A context is
untrusted model input, never an instruction to the local service or browser chrome.

## Responses

Every response has `version`, `id` and `event`. `id` is the corresponding request
ID; malformed frames/envelopes receive `id: null`, `event: "error"`,
`code: "invalid_request"`, then the connection closes.

- `capabilities`: a `capabilities` object with `visibility: "private_local"`,
  `local_only: true`, fixed `model_profile`, `max_question_bytes: 512`,
  `max_context_bytes: 4096`, `max_request_bytes: 32768`, `max_response_bytes: 65536`,
  `execution_slots: 1`, `max_connections: 8`, configured `max_seconds`, and
  `network_access`, `public_cache`, `training`, `cloud_fallback` all false.
  `model_execution_proven` is false: configuration is not an inference proof.
  `quarantined` reports unconfirmed cleanup that prevents further admission.
- `admitted`: the submit ID owns the one execution slot; no answer is implied.
- `result`: the same submit ID, plus `result`, the existing private-task summary.
  Answer text is `result.output.text`. Preserve `answer_complete`, `answer_status`
  and `cleanup.complete`; token-limited or truncated output is not a complete answer.
  Even complete generated text is not proof of factual or semantic correctness.
- `cancel_requested`: the cancel request ID, plus `task_id` identifying its submit.
  This is only an acknowledgement. The submit receives `error` / `cancelled` after
  execution has returned through cleanup. Cleanup uncertainty takes precedence.
- `error`: fixed `code` from `invalid_request`, `handshake_required`, `busy`,
  `no_such_task`, `cancelled`, `execution_failed`, `cleanup_unconfirmed`.

Conversation clients can independently opt into `execution_error_version: 1`
on `conversation_capabilities`; the reply echoes that field only when requested.
Absent means the original error vocabulary. Null, duplicate or unknown versions
are rejected. This negotiation is separate from `generation_policy_version` and
is captured when each conversation is admitted, not changed by a later handshake.
Q&A clients remain unchanged.

For opted-in, admitted conversations only, `execution_budget_exceeded` means the
supervisor deadline or the validated worker deadline elapsed **and cleanup has
returned successfully**. It is terminal for that attempt, not a temporary network
failure and not an instruction to retry the same expensive request automatically.
It does not say whether any useful model output was generated. Cleanup uncertainty
and explicit cancellation retain precedence; other failures stay `execution_failed`.
No raw exception, input, partial answer or model diagnostic is included in this error.

There is no task queue, streaming answer, history endpoint or cross-connection
cancel. There are at most eight connections and one running private task. On
disconnect/shutdown, cancellation signals the existing sandbox supervisor; it
kills/reaps only its exact owned child, never a broad host process group. The task
retains the execution slot until the backend returns and owned staging is removed.
Unconfirmed cleanup quarantines further admission. Temporary input/output files
exist only under the owner's private work directory and follow the existing
private-task cleanup contract; this is **not** a RAM-only or secure-erasure claim.

## Owner-selected native CPU backend

The owner may explicitly supply both `--native-backend-root` and
`--native-backend-sha256` at service startup. The latter is the SHA-256 of the
private `backend.json` manifest binding the pinned library and converted model.
An IPC request cannot supply these paths or authorize executable code. The
backend directory is mounted read-only inside the existing isolated worker;
the worker verifies the complete artifact hashes before loading the library.

This candidate supports only `qwen3-4b-instruct-2507-v1` conversations. Its
conversation capabilities add `inference_backend: "llama_cpp_bf16_v1"` and
`required_generation_policy: "greedy_v1"`; both fields are absent for the
unchanged default backend. Clients must negotiate `generation_policy_version: 1`
and explicitly submit `greedy_v1`. Missing policy is rejected before admission.
The existing Qwen4B wire validation rejects Q&A capabilities and submission;
the native backend does not enable a Q&A service. A conversation capability
response is not evidence that a model has run successfully. The public result
schema remains unchanged; the core binds
the worker's native artifact identity and reported precision internally.

This is still same-owner local execution, not confidential execution on peers.
Actual conversion, full generation and application trials remain required.

## Browser boundary

Only privileged, owner-authorized browser code may use the socket. Web page scripts
must not receive it or a generic command bridge. Explicit page/selection actions
send bounded text in the message body—not provider URLs, browsing history or logs.
No cookies, credentials, arbitrary paths or implicit entire-page export belong in
this schema. Model output remains untrusted text. Same UID is an OS ownership
boundary, not isolation from malicious software already running as that user.

This slice reuses actual private-task staging, execution, input/model report binding
and cleanup. Protocol/lifecycle tests are not model-inference, Firefox-UI, protected
network-routing or browser kill-switch evidence; those require separate live runs.
