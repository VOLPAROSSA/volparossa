# Codex development and conversation handover

Resume from the repositories, not from a previous chat transcript. The
[complete goal](GOAL.md) defines scope; the
[implementation ledger](../IMPLEMENTATION_STATUS.md#current-integration-and-active-work)
defines current progress and dependencies. This workflow describes development
coordination, not the VOLPAROSSA product's decentralized agent scheduler.

## Start a fresh conversation

1. Open the core checkout and select **GPT-6 Astra / Ultra** manually in Codex.
   Restart or reload the extension first if it was open during a configuration change.
   A saved default does not change the model of an existing conversation.
2. Read [AGENTS.md](../../AGENTS.md), [GOAL.md](GOAL.md), and the ledger's
   current-work and retained-branches sections. Follow the relevant technical
   links; do not load the entire historical ledger into every subagent.
3. Inspect `git status --short --branch`, `git worktree list` and current remote
   heads/checks before choosing a checkout. Read the affected application's
   instructions and README/status next. Local branches can be older than `main`.
4. Continue the existing execution plan and useful integrations. Do not restart
   the project or silently shrink the goal. The 2026-10-20 follow-up explicitly
   authorizes organization-wide efficiency and quality work alongside these
   integrations; it supersedes the handover-only deferral of that work.

Suggested first message:

> Continue VOLPAROSSA from AGENTS.md, docs/development/GOAL.md and the current
> sections of docs/IMPLEMENTATION_STATUS.md. Preserve the full goal and all
> existing work. Recheck the retained branches and original failed evidence,
> then continue the most useful existing integration. Use task-aware Sol/Luna
> delegation with at most two subagents. Continue the explicitly authorized
> organization-wide optimization using measured priorities, without repeating
> trials merely because the conversation changed.

The goal belongs to the new conversation only after it has been explicitly
created or selected there. Reuse the complete repository goal, including its
separately identified clarifications; do not mark the unfinished project complete
to transfer conversations. The previous conversation's automatic continuation
should not be left running against the same worktrees.

## Delegate by task and ownership

| Role | Model and initial effort | Responsibility |
| --- | --- | --- |
| Principal | `gpt-6-astra`, Ultra | Architecture, consequential decisions, prioritization, coordination and integration. |
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

## Local configuration and verification

On 2026-10-20 the VSCodium extension `26.5908.31748` used bundled
`codex-cli 0.163.0`. There was no standalone `codex` on PATH; use the extension's
bundled binary for diagnostics rather than installing another CLI.
The user authorized only the relevant `~/.codex/config.toml` changes and new
specialist files under `~/.codex/agents/`, with a configuration backup.

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
