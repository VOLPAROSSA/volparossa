# Shared development workflow

Codex, OpenCode and other coding agents use this workflow across VOLPAROSSA.
Each repository's root `AGENTS.md` links here and gives its own contracts,
verification guidance and authority boundaries. Changes to shared development
practice belong here. Use the user's latest scoped instructions and current
repository state when resuming work across clients.

## Start or resume

1. Read the task, the owning repository's `AGENTS.md`, any instructions for the
   affected paths and the relevant local README or status. Consult the Core
   [implementation status](../IMPLEMENTATION_STATUS.md) for shared dependencies.
   For a full-project resume, read the complete [goal](GOAL.md), including its
   integrated [DPS](GOAL.md#dps) and [Studio/hosting](GOAL.md#studio) sections.
   For a bounded task, load the relevant requirements and contracts.
2. Inspect status and ownership before writing. Use `git status --short --branch`
   and, when working across checkouts, `git worktree list`. Refresh remote heads,
   relevant PRs and CI when integration decisions depend on them; old pending or
   running records are not live state. Read affected applications' own instructions.
3. Continue useful unfinished work according to dependencies. Reference GOAL when
   changing clients or sessions; no parallel goal prompt, special UI or prior
   attachment is required. Preserve an existing unfinished goal rather than
   completing/recreating it to change its display text.

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

### Commit attribution for Erik's Codex work

For work that Erik Le Blansch authors with Codex, use his GitHub account
`erikleblansch` as the sole author. Configure each new working clone for his
tasks with his account-linked Git identity before creating source commits.

```sh
git config --local user.name erikleblansch
git config --local user.email 58982453+erikleblansch@users.noreply.github.com
```

Use that identity for delegated commits too. Omit tool co-author trailers from
Erik's commits and the final squash message. Check the source authors before
merging, since GitHub can credit them when it creates the squash commit.
Preserve the authorship of other contributors when integrating their work.

## Verify and record

Choose checks for the changed behavior and actual risk. Use narrow formatter/compile
checks and targeted functional smoke during development; run broader integration and
release checks when their scope is affected. Documentation-only work needs relevant
link, scope and preservation checks, not runtime builds or model-routing demonstrations.
Run [requirement preservation](TESTING.md#requirement-preservation) when effective
requirements or preserved sources change, not on every task or conversation.

Reuse completed exact-source results when still applicable. Inspect an existing hosted
run before dispatching another; preserve original failures and explicit acceptance
runs. Source checks, public fixtures, protected execution and product acceptance are
different evidence. Cache pinned build inputs, never test success, private fixtures,
credentials or authorization. Keep untrusted PR cache reads separate from trusted writes.

Update the affected row in the [Core status](../IMPLEMENTATION_STATUS.md) when
its result or next dependency changes. Cite the tested revision and evidence.
Put detailed Core trial narratives in the linked [topic records](../IMPLEMENTATION_STATUS.md#detailed-trial-records)
and keep application-specific results in the owning repository.
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
