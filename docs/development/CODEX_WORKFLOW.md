# Codex development and conversation handover

Resume from durable repository sources, not a previous chat transcript or
attachment. [AGENTS.md](../../AGENTS.md) contains engineering and host-safety
rules; the [complete goal](GOAL.md), including its amendments, defines full
project scope; [DPS_REQUIREMENTS.md](DPS_REQUIREMENTS.md) is the permanent joined
normative DPS scope; [STUDIO_HOSTING_REQUIREMENTS.md](STUDIO_HOSTING_REQUIREMENTS.md)
is the complete permanent Studio/hosting/AI addition; and the [implementation ledger](../IMPLEMENTATION_STATUS.md#current-integration-and-active-work)
defines current evidence and execution priorities. The
[DPS_GOAL_20261021 archive](DPS_GOAL_20261021.md) preserves original received
bytes for provenance only, while [services/DPS.md](../services/DPS.md) records
design and acceptance choices without limiting scope. This workflow describes
engineering coordination, not the VOLPAROSSA product's decentralized agent scheduler.

## Start a fresh conversation

1. Open the core checkout and select **GPT-6 Astra / Ultra** manually in Codex.
   Restart or reload the extension first if it was open during a configuration change.
   A saved default does not change the model of an existing conversation.
2. Read [AGENTS.md](../../AGENTS.md), the complete [GOAL.md](GOAL.md),
   [DPS_REQUIREMENTS.md](DPS_REQUIREMENTS.md),
   [STUDIO_HOSTING_REQUIREMENTS.md](STUDIO_HOSTING_REQUIREMENTS.md), and the ledger's current-work and
   retained-branches sections. Review [GOAL_VERIFICATION.md](GOAL_VERIFICATION.md)
   and run the inert [goal preservation verifier](../../scripts/verify-goal-preservation.py)
   as documented there. Follow relevant technical links; do not load the entire
   historical ledger into every subagent.
3. Inspect `git status --short --branch`, `git worktree list` and current remote
   heads/checks before choosing a checkout. Read the affected application's
   instructions and README/status next. Local branches can be older than `main`.
4. Inspect the active Codex goal. In a new conversation with no active goal,
   manually select or create it using the exact copyable
   UI text in [PURSUING_GOAL.md](PURSUING_GOAL.md). Do not mark an unfinished
   project complete, restart it, or create a replacement merely to transfer
   conversations. Preserve active work and continue the existing execution plan;
   do not silently shrink the goal. The 2026-10-20 follow-up explicitly
   authorizes organization-wide efficiency and quality work alongside these
   integrations; it supersedes the handover-only deferral of that work.

Use the exact first-message text in [PURSUING_GOAL.md](PURSUING_GOAL.md); do not
depend on a previous transcript or attachment for requirements. Preserve the
complete repository goal, all clarifications and active branches. Recheck the
live worktree and ongoing tasks; coordinate ownership before using an active
checkout, and preserve useful work when recovering or isolating branches. This
handover does not call for Codex configuration changes, software installation
or permission expansion.

## Delegate by task and ownership

| Role | Model and initial effort | Responsibility |
| --- | --- | --- |
| Principal | `gpt-6-astra`, Ultra | Architecture, consequential decisions, prioritization, coordination and integration. |
| `volparossa_implementer_medium` | `gpt-6.1-sol`, Medium | Bounded implementation within established, approved contracts; escalate ambiguity. |
| `volparossa_implementer` | `gpt-6.1-sol`, High | Substantial implementation, integration and complex debugging. |
| `volparossa_reviewer` | `gpt-6.1-sol`, High | Independent technical review of correctness, privacy and acceptance evidence. |
| `volparossa_support` | `gpt-6-luna`, Medium | Bounded exploration, documentation and assigned focused checks. |

Use at most two concurrent subagents initially, excluding the principal. Parallelize
independent work only; sequential work or no delegation is often better for a small
edit. The principal should not routinely redo reliable implementation/support work.
Escalate ambiguous or consequential findings rather than making Luna solve a task
outside its assignment.

Each assignment gives the goal, exact source, owned files/worktree, relevant
interfaces and invariants, allowed checks and expected evidence. One agent owns a
write scope at a time. Share concise findings rather than entire conversations.
Subagents do not recursively delegate or publish/dispatch work unless assigned;
the principal coordinates integration, branch protections and final claims.
Review by an agent is not a release signature or authority to weaken privacy.

### Task classification and escalation (approved Option A, 2026-10-22)

Classify the assignment in a sentence; trivial edits need no separate document:

- **Supporting:** Luna Medium handles bounded exploration, documentation and
  focused checks.
- **Implementation within established contracts:** Sol Medium may implement an
  explicitly scoped task whose interfaces, invariants and trust assumptions are
  already approved. Name those contracts and the acceptance criteria.
- **Consequential or ambiguous engineering:** Astra Ultra decides the architecture;
  Sol High handles suitable complex implementation, debugging and independent
  review. Medium must stop the affected change and escalate if a contract or trust
  assumption needs changing, compatibility is unclear, or passing requires relaxing
  an invariant. Unrelated safe work may continue.

Consequential triggers include networking protocols and shared wire contracts;
cryptography and identity; security and authorization boundaries; distributed
Storage and redundancy; confidential Compute and shared AI; Transaction and
financial authorization; update authority; DPS positioning integrity; and Studio
publication security and decentralized hosting. Record the principal decision,
compatibility impact, independent review and relevant regression/runtime evidence.
Independent review must come from a suitably capable agent other than the author;
the principal resolves findings and retains integration responsibility. A service
limit is a visible blocker, not permission to substitute author self-review.

Option A changes engineering allocation only. The complete goal, all preserved
payloads, DPS, Studio/hosting and existing security/host/authority rules remain in
force. Astra remains principal; existing High and support roles stay available,
and the two-child limit is unchanged. Do not change a live goal or reload the
active build to introduce the new role. A client that has not discovered it may
continue using High until an appropriate fresh session.

### Context, diagnostics and evidence efficiency

Inspect relevant files and current ledger sections before widening a search. Give
one owner the initial exploration and reuse its exact-source findings; the
principal assesses decisions and integration evidence without routinely repeating
the worker's implementation. Independent reviewers still inspect the affected
contracts, diff and evidence themselves.

An assignment contains: objective, classification, exact source/dependencies,
owned paths/worktree, approved contracts/invariants, permitted checks and acceptance
criteria. A result contains: changed paths/behavior, source and original run/log
locations, pass/fail with acceptance limits, review findings and unresolved risks.
Return relevant error excerpts and summaries instead of large raw logs. Keep full
diagnostic and cleanup evidence accessible with its source/run binding; do not
discard or conceal errors to reduce context.

Before rerunning CI, inspect completed or ongoing runs for that source and scope.
Reuse trustworthy results only for identical sources and acceptance scopes, or
document relevant tree/blob equivalence and why changed files cannot affect the
claim. Changed dependencies, environments, configuration or acceptance conditions
need new evidence. Reuse is evidence referencing, not caching a successful outcome.
After an environmental failure, record its signature, source, failed precondition
and next discriminating check. Retry only when an input/precondition changes or a
bounded diagnostic can distinguish causes. Changing models alone does not fix an
unchanged environment. Preserve all failed trials and required cleanup checks.

For a controlled Medium pilot, select two or three genuine current-plan tasks
with fixed contracts, clear acceptance and independent High review; begin with
one small task. Check current worker ownership, PRs and external contributor
issues first. Isolate worktrees and do not duplicate active work. If coordination
cannot establish an independent scope, prepare the next-milestone handoff and
defer execution. A routing marker is not an implementation pilot.

For each completed pilot task, record actual thread model/effort, input and cached
input (a subset), output, principal/reviewer involvement, verification, review
findings/corrections, integration failures/rework and functional acceptance. Count
principal, workers, review and repairs together. Use cumulative usage deltas without
repeated snapshots; identify resets, inherited counters and model switches. Compare
cautiously with representative High work; neither elapsed time nor routing success
proves savings or equivalent quality. Revert task allocation to High if meaningful
quality degradation appears; preserve the failing evidence.

Before allocating or changing shared wire fields, inspect both main and retained
active integration heads. A field absent from main may already belong to an
unfinished service. Preserve existing assignments, record the selected unused
fields and bind them with wire compatibility tests. Do not silently reinterpret
an older field or add aliases that collide with another service.

## Local configuration and verification

On 2026-10-20 the VSCodium extension `26.5908.31748` used bundled
`codex-cli 0.163.0`. There was no standalone `codex` on PATH; use the extension's
bundled binary for diagnostics rather than installing another CLI.
The user then authorized only the relevant `~/.codex/config.toml` changes and new
specialist files under `~/.codex/agents/`, with a configuration backup.
The following is the historical 2026-10-20 configuration, not a promise about the
current saved default or an existing conversation's selected model.

```toml
model = "gpt-6-astra"
model_reasoning_effort = "ultra"

[agents]
enabled = true
default_subagent_model = "gpt-6.1-sol"
default_subagent_reasoning_effort = "high"
max_concurrent_threads_per_session = 2
```

The specialist files use `name`, `description`, `model`,
`model_reasoning_effort` and `developer_instructions`. They do not override
permissions, providers, billing or release authority. Other existing settings,
including trust, memory, service tier and disabled apps, were preserved.
The local recovery copy is `~/.codex/config.toml.before-volparossa-handover-20261020`;
restore selectively if subsequent preferences have changed.

Verification distinguishes the following:

- TOML parsing and an exact old/new configuration comparison pass; only the
  principal model/effort and `[agents]` changed.
- The bundled model catalog lists all three requested models, including Astra
  Ultra, Sol High and Luna Medium.
- Strict app-server startup and `config/read` accept the requested keys.
  A new read-only ephemeral thread reports Astra/Ultra; rendered agent
  instructions report three total slots, meaning the principal plus two children.
- Real Sol and Luna delegated audits completed with repository/GitHub tool use.
  Small read-only custom-role tests returned `SUPPORT_OK` and `IMPLEMENTER_OK`.
  The same app-server's `thread/read` metadata independently recorded
  `volparossa_support` on `gpt-6-luna`/Medium and `volparossa_implementer` on
  `gpt-6.1-sol`/High, with the correct parent thread and completed turns. The
  reviewer file was syntax-checked but not given an additional inference test.
  The two-child cap was confirmed in effective config/instructions, not by
  deliberately exhausting it.

The existing IDE conversation is not hot-reloaded or used as evidence of future
session settings. Recheck model and effort in the new conversation. Account
availability may change. No paid service, API billing or wider execution permission
was enabled. Missing `rg` remains a tooling limitation; use `git grep`/`grep`.

Configuration semantics and custom-agent fields are documented in the official
[configuration reference](https://learn.chatgpt.com/docs/config-file/config-reference)
and [subagent guide](https://learn.chatgpt.com/docs/agent-configuration/subagents).

### Option A installation and bounded verification — 2026-10-22

The approved addition is `~/.codex/agents/volparossa-implementer-medium.toml`,
whose `name` is `volparossa_implementer_medium`, model `gpt-6.1-sol` and effort
`medium`. Its instructions require assigned ownership, established contracts,
escalation, appropriate checks, retained failure/cleanup evidence and concise
results. It forbids recursive delegation and permission expansion. Existing High
implementation/review and Luna support definitions are unchanged.

Before installation, the current config and three existing definitions were copied
with a hash/mode manifest to
`~/.codex/backups/volparossa-option-a-20261022T212017Z/`. Their byte hashes remained
unchanged afterwards. The saved default remained Sol High, default children High,
and the limit two; the separate active DICN principal still recorded Astra Ultra.
No permissions, providers, service tier, billing settings or active goal changed.

Strict bundled app-server initialization and TOML parsing passed. In a separate
validation thread, Astra Ultra spawned the custom role by name with **no model or
effort override**. Same-server `thread/read` metadata recorded parent
`01a1657d-365e-73a0-930c-24c7f1bee8aa` as `gpt-6-astra`/`ultra` and child
`01a1657d-4913-7900-8761-0d650ca8ca9d` as
`volparossa_implementer_medium`, `gpt-6.1-sol`/`medium`, with the correct parent.
Both turns completed without error; the child returned only its routing marker.
This verifies custom-role discovery and delegation, not implementation quality.
Local complete events, thread readbacks and the probe script are retained under
`.volparossa-dev/model-efficiency-option-a-20261022T212017Z/`.

The probe's final cumulative input/cached-input/output counters were
66,648/51,072/128 for Astra and 27,522/6,912/8 for Medium. Cached input is a subset;
the combined total is 94,306 tokens. These are configuration-validation costs,
not a functional pilot or evidence of savings. Review/support overhead must be
reported separately rather than hidden in a claim about the marker test.

Implementation pilot execution is deferred: live ownership inspection found
Storage tests owned by PR334/`storage_consumer_handshake`, resident-model work
owned by PR332/`model_corruption_transition`, Studio export-pack work owned by
PR330, and ledger/goal-verification updates owned by PR328. Contributor issue295
is excluded. No independent current-plan implementation scope was established.
Only this isolated branch owns AGENTS/workflow edits; it does not write those
active worktrees or the shared ledger. At the next integration checkpoint,
re-evaluate remaining Studio export-pack fixtures, bounded Storage diagnostics
parser controls and resident-model closed-classification controls as candidate
areas. Select two or three actual remaining gaps only after fresh source/ownership
checks and explicit acceptance criteria; begin with the smallest fixed-contract
task and independent High review. These are held areas, not ready assignments,
implemented changes or promises that existing tests leave such gaps.

Recovery: stop selecting the Medium role and use existing High. If removing the
new file, first compare its recorded installation hash and preserve subsequent
edits; it did not exist before this installation. Existing config/agents need no
restoration because they were not changed. If later restoration is needed, compare
the dated manifest and restore only intended files without overwriting newer
preferences. Do not blindly restore the older 2026-10-20 backup, reload the active
build or replace its goal. Repository instructions follow the reviewed PR path;
recheck the integrated revision before applying them to subsequent assignments.

## Preserve checkouts and evidence

The 2026-10-20 handover inventory found clean top-level application worktrees in
sibling `volparossa-*` directories. Browser and Mail local `main` were behind
their remote-tracking refs. Chat's `feature/signal-core-integration` and Code's
`feature/codex-runtime` were historical ancestors of their remote `main`, not
unpublished successors. In particular, the Code branch name does **not** undo the
OpenCode decision. Map and Weather had retained feature checkouts. Resolve the
current remote state before updating any of these worktrees.

For an application, use its own `AGENTS.md`, README and linked integration guides;
the [application overview](../applications/APPLICATIONS.md) supplies repository
links. There is no need to create competing per-application ledgers. The organization
profile belongs to `VOLPAROSSA/.github`, not the core repository's `.github/`.
No separate organization-profile clone was found in the inspected checkout set.

Core candidate paths are discoverable with `git worktree list`: the retained
Storage branches use `.git/codex-storage-route-retirement`,
`.git/codex-storage-real-route-sequence`, `.git/codex-storage-natural-expiry-sequence`
and `.git/codex-storage-post-acquire-clock`; model work uses
`.git/codex-protected-resident-model`; dependent upload work uses
`.git/codex-cloud-upload-tls-v9`. Revisions, PRs and acceptance belong in the ledger,
not a second status table here.

Preserve the unrelated untracked `error.log` in the core main checkout, the
uncommitted status edit in `.git/codex-native-cpu-inference`, and untracked
`tests/integration/__pycache__/` in `.git/codex-native-editor-core` and
`.git/codex-relay-refill`. Do not reset, delete or publish them merely to obtain a
clean-looking checkout. The older status edit contains Browser evidence retained
in the Browser integration guide; its old pending-candidate wording is not current.
Prunable worktree records are not permission to remove work.

Run Rust/native/model/VM/SDK/Gradle and package-installation trials on the approved
disposable hosted runners, not the development host. Local read-only inspection,
documentation checks and inert validation are appropriate. A cloud environment
named VOLPAROSSA was reported, but that is not confidential-computing hardware
or evidence of a working private-worker environment. No suitable confidential
server has been supplied; do not repeatedly ask for one without a new requirement.

Before a hosted run, inspect any existing run for that exact candidate and record
its original run ID. Do not rerun because a watcher or conversation ended. Failed
reports stay immutable. Bind new evidence to exact source and scope; source tests,
public VM execution and confidential private execution are different claims.
Retained local evidence under `.git/ci-evidence/` supplements the linked original
CI artifacts. If an artifact has expired, report the evidence gap rather than
reconstructing a successful outcome.

## Efficiency work authorized after the handover

The 2026-10-20 follow-up authorizes cross-repository optimization, while preserving
all agreed functionality and the retained Storage/compute/application candidates.
Start with current evidence of repeated cost or a demonstrated correctness issue;
compare benefit, migration cost, trust impact and reversibility before redesigning.
Keep a short prioritized record in the existing implementation ledger. Do not
create competing per-repository plans or move application-specific policy into
shared core mechanisms merely to reduce code duplication.

Use completed hosted results for the exact source and scope. Cache reusable build
inputs or checked source-built tools, never successful test outcomes, private
fixtures, credentials or authorization. Cache misses must use the ordinary pinned
source build. Keep default-branch cache writes separate from untrusted PR reads.
Cancel superseded automatic source checks; preserve explicit acceptance runs and
their cleanup/evidence. Retain comprehensive integration checks, action pins and
least-privilege permissions. Do not infer runtime speedups from CI savings.

The first live follow-up session independently inspected its own recorded turn
metadata: principal `gpt-6-astra`/Ultra, `volparossa_implementer`
`gpt-6.1-sol`/High and `volparossa_support` `gpt-6-luna`/Medium, each child bound
to that principal. Both custom roles performed real repository/GitHub inspections.
This verifies this session's delegation, not future account availability.

## Worktree and generated-artifact lifecycle

Create temporary worktrees beneath `.volparossa-dev/worktrees/`, outside Git's
`.git` administration directory. Do not copy a checkout's `target/` or `.git/`
into snapshots or backups. Preserve shared pinned build caches and their
provenance; remove only verified generated build outputs when their exact scope
is understood.

Before retiring a snapshot, verify it is clean, contains no ignored or untracked
unique evidence, and is fully integrated. Retire it with `git worktree remove`
so Git updates its registry; a prunable record alone does not authorize removal.
Keep failing reports, model/evidence artifacts, and recovery refs with a manifest
that identifies their source and purpose. Before pruning administration records,
inspect staged or missing-index state, preserve any recovery material, and confirm
all expected repositories remain readable. Do not automate deletion of ambiguous
checkouts or artifacts.
