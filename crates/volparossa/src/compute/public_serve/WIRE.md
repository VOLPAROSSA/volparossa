# Public cooperative compute IPC, version 1

This separate same-UID Unix socket is not the private-local compute service and
does not change that protocol. The operator fixes the agent control socket,
publisher identity, peer-selection mode, model profile and state directory at launch.
Requests never select commands, paths, keys, models, providers or Internet URLs.

In the default document mode, the operator supplies the local planning runtime/model
and two to four fixed `--provider-key` values, or selects
`--discover-peers` instead. Discovery reuses the core's protected-route capability
selection for each new task, requiring two to four distinct eligible providers
in one exact model cohort before enrollment. `--model-profile` remains an
operator choice; discovery may additionally pin `--model-fingerprint`. It does
not automatically switch models, authorize private input, or replace an enrolled
provider. Result `selected_provider_keys` comes from the validated original
enrollment, while `provider_keys` still contains only actual answer providers.
Unavailable peers or cancellation during capability selection do not quarantine
an otherwise quiescent service: no worker has started in that phase, and the
independent terminal-receipt cleanup check must still pass.

Frames are a four-byte big-endian length followed by UTF-8 JSON: at most 32768
request bytes and 65536 response bytes. Partial frames expire after five seconds;
writes after three seconds. Unknown fields, duplicate IDs, unsupported versions,
malformed UTF-8 and overlong input close the connection. At most eight same-UID
connections, 256 requests per connection and one executing task are admitted.

Every request has `version:1`, an `id` of 32 lowercase hexadecimal characters,
and an `operation`. First request capabilities:

```json
{"version":1,"id":"11111111111111111111111111111111","operation":{"type":"capabilities"}}
```

Submission requires a nonempty question of at most 512 UTF-8 bytes and a nonempty
context of at most 4096 UTF-8 bytes, without NUL. The user must explicitly confirm
both sharing and authorization, and select a license. A browser must never
silently retry a private-local task here.

```json
{"version":1,"id":"22222222222222222222222222222222","operation":{"type":"submit","question":"Summarize the public text.","context":"Public source text.","public_content":true,"rights_confirmed":true,"license":"CC0-1.0"}}
```

Licenses: `GPL-3.0-only`, `CC0-1.0`, `CC-BY-4.0`, `CC-BY-SA-4.0`. Confirmation is
an owner declaration, not automatic license validation. Question, source and
derived answers are disclosed to selected peers. They are not confidential from
those peers, and cancellation cannot guarantee deletion of previously shared data.

Responses contain `version`, the originating request `id`, and `event`:
`capabilities`, `admitted`, `result`, `cancel_requested`, or `error`.
Capabilities include `visibility:"public_cooperative"`, `network_access:true`,
`private_data_supported:false`, `public_cache:true`, `training:false`,
`cloud_fallback:false`, `retained_public_receipts:true`,
`remote_erasure_guaranteed:false`, `model_execution_proven:false`, the fixed
`model_profile`, byte bounds, `execution_slots:1`, `max_connections:8`,
`max_seconds` (worker lease, at most 600), `max_task_seconds` (task cancellation
deadline, at most 7200), and `quarantined`. The public-cache flag means signed
task publication storage, not permission to publish arbitrary browsing content.
Capabilities are configuration, not evidence that peers are currently available.

The submit request ID is the connection-scoped task ID. An admitted reply does
not claim successful execution. A terminal result carries `result` with
`answer_complete`, `answer_status` (`complete` or `incomplete`), `output.text`,
`provider_keys` (actual answer providers), `selected_provider_keys` (enrollment),
`joining`, `execution_complete`, `package_count`, `total_parts`,
`synthesis_levels`, `source_manifest_id`, `remote_cleanup_confirmed`,
`cleanup.complete`, `retained_public_receipts:true`,
`model_answer_correctness_proven:false`, and `semantic_completeness_proven:false`.
Incomplete results may have empty text; they must not be presented as complete.
The source and every signed workflow/synthesis receipt remain under the
operator's owner-only state directory for reconciliation; no paths or handles
are sent to the browser. Selected providers alone do not prove multi-peer work.

## Explicit public code mode

`--code-proposal-v6` selects a separate code-only service. It requires a pinned
Qwen model profile, one fixed provider or `--discover-peers`, and **no local
model/runtime**. The provider broker must independently enable the same code
capability and trust the publisher. This mode advertises `code_proposal_v6:true`
and `output_contract:"single_file_replacement_v1"`; those fields are omitted
entirely from legacy document capabilities. A client must check capabilities
before choosing the operation.

Use `operation.type:"public_code_proposal"` with the same question, context,
license and two explicit consent fields shown above. Context is the complete
selected source file, not a private conversation or an arbitrary local path.
The coordinator signs both the original source and its v6 task, selects a
compatible peer and submits one immutable job. A document-mode service rejects
code requests, and a code-mode service rejects ordinary `submit`, with
`unsupported_operation`. Neither mode silently switches to the other.

The code result is separate from the document result: it binds `source_sha256`,
`source_bytes`, `source_manifest_id`, `dataset_sha256`, `dataset_manifest_id`,
`provider_keys`, `model_profile`, `model_fingerprint` and the original local
`receipt` containing handle and status. It carries one unchanged `outputs` entry,
`execution_complete`, `proposal_complete` and `cleanup_confirmed`. A receipt
records the result checked over authenticated peer RPC, not a portable hardware
attestation or proof that a hostile provider actually ran a model.

`proposal_complete` requires nonempty, non-truncated output with observed EOS;
it does not establish correctness. The application must separately approve a
write, bind it to the unchanged local source and authorize any test execution.
No model-generated path or command grants that authority. Terminal receipts can
be read after their original execution lease expires; observation does not
extend the lease or authorize another job. Public disclosure, retention and
cancellation limits above also apply to this mode.

## Cancellation and errors

```json
{"version":1,"id":"33333333333333333333333333333333","operation":{"type":"cancel","task_id":"22222222222222222222222222222222"}}
```

`cancel_requested` acknowledges the request, not stopped remote execution. The
coordinator sends ordinary exact-handle cancellation and joins its existing
workers. Terminal `error` codes are closed: `invalid_request`,
`handshake_required`, `busy`, `no_such_task`, `cancelled`, `deadline_exceeded`,
`execution_failed`, `storage_bound`, `cleanup_unconfirmed`, `unsupported_operation`. Unconfirmed remote
cleanup quarantines new admission and retains original handles. EOF and service
shutdown follow the same cancellation/join path. A deadline starts cancellation;
it is not a promise that all remote acknowledgements arrive by that instant.
`cleanup.complete` is execution cleanup, never deletion of public receipts or
global erasure. Errors never include raw exceptions, prompts, paths or keys.
