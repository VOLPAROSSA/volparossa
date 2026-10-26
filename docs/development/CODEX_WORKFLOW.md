# Shared development workflow

This workflow applies to Codex, OpenCode and other coding agents. The historical
filename is retained for existing links. Use repository state and the user's latest
instructions rather than session transcripts or tool-specific rituals.

## Start or resume

1. Read the task, applicable AGENTS instructions and the compact
   [implementation status](../IMPLEMENTATION_STATUS.md). For a full-project resume,
   read the complete effective [goal](GOAL.md), including its incorporated
   [DPS](DPS_REQUIREMENTS.md) and [Studio/hosting](STUDIO_HOSTING_REQUIREMENTS.md)
   requirements. For a bounded task, load the relevant requirements and contracts.
2. Inspect status and ownership before writing. Use `git status --short --branch`
   and, when working across checkouts, `git worktree list`. Refresh remote heads,
   relevant PRs and CI when integration decisions depend on them; old pending or
   running records are not live state. Read affected applications' own instructions.
3. Continue useful unfinished work according to dependencies. An optional
   [continuation prompt](PURSUING_GOAL.md) can carry the full objective between
   clients; no special goal UI or prior attachment is required. Preserve an existing
   unfinished goal rather than completing/recreating it to change its display text.

Do not read provenance snapshots or the entire evidence history at startup.
Requirements are authoritative for scope; status is evidence and priorities, not a
replacement specification. The [documentation index](../README.md) locates topics.

## Plan and execute

Select models, reasoning effort, tools, skills and any agents dynamically using
available client capabilities, task complexity, uncertainty, risk, latency and cost.
Reassess when requirements or evidence change. There is no fixed vendor, model,
role-to-model mapping, skill roster or repository concurrency limit. Delegate only
when useful, with minimal sufficient context, explicit ownership, exact source and
expected evidence. Avoid competing writers and repeated exploration. The coordinating
agent integrates results and arranges independent review where the change warrants it.

A repository instruction cannot enable a model, switch a running session or override
client policy. Use supported controls and report limitations accurately; do not edit
host configuration, install tooling or run routing probes merely to satisfy a workflow.
Both [Codex](https://learn.chatgpt.com/docs/agent-configuration/subagents) and
[OpenCode](https://opencode.ai/docs/rules/) support project instructions, but their
configuration and delegation capabilities differ.

Implement complete usable slices within the agreed privacy and authority boundaries.
Before shared wire/interface allocation, inspect current and retained integration
heads; preserve field ownership and compatibility. Make ordinary scoped development,
commit and push decisions autonomously; branch protections and release authority apply.

## Verify and record

Choose checks for the changed behavior and actual risk. Use narrow formatter/compile
checks and targeted functional smoke during development; run broader integration and
release checks when their scope is affected. Documentation-only work needs relevant
link, scope and preservation checks, not runtime builds or model-routing demonstrations.
Run [goal preservation](GOAL_VERIFICATION.md) when effective requirements, preserved
sources or the continuation prompt change, not on every task or conversation.

Reuse completed exact-source results when still applicable. Inspect an existing hosted
run before dispatching another; preserve original failures and explicit acceptance
runs. Source checks, public fixtures, protected execution and product acceptance are
different evidence. Cache pinned build inputs, never test success, private fixtures,
credentials or authorization. Keep untrusted PR cache reads separate from trusted writes.

Update the compact implementation status with the source, bounded result, evidence
link and remaining dependency. Put detailed dated evidence in the linked history or
topic record, without repeating it in goal text, workflow and verification instructions.
Archive superseded narrative; keep unique failures and exact evidence bindings.

<a id="worktree-and-generated-artifact-lifecycle"></a>

## Checkouts and handover

Use `.volparossa-dev/worktrees/` for new temporary worktrees, never Git's administration
directory. Keep active work, unpublished changes and unrelated files intact. Before
retiring a checkout, verify integration and inspect dirty, ignored and untracked unique
material; use `git worktree remove`. A prunable record is not permission to delete it.
Do not copy `target/` or `.git/` into snapshots. Preserve recovery refs, evidence and
provenance; delete only understood generated outputs with verified recovery paths.

A handover needs the current branch/source, owned checkout, remaining work and exact
relevant evidence. Do not repeat machine inventories, UI character counts or historic
model tests. Approved hosted runners remain the place for builds and runtime trials;
local read-only inspection and inert documentation validation preserve host safety.
