# Shared development workflow

This workflow applies to all VOLPAROSSA contributors and any AI coding agents
working on their behalf. Start at the owning repository's root `AGENTS.md` for
its contracts, verification guidance and authority boundaries. Keep shared
development practice here. Use the user's latest scoped instructions and
current repository state when resuming work.

## Start or resume

1. Read the task, the owning repository's `AGENTS.md`, any instructions for the
   affected paths and the relevant local README or status. Consult the Core
   [implementation status](../IMPLEMENTATION_STATUS.md) for Core work and shared
   dependencies.
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

Choose models, reasoning effort, tools, skills, agents, context and parallelism
dynamically using available capabilities, task complexity, uncertainty, risk,
latency and cost. Reassess when requirements or evidence change. No vendor, model,
role-to-model mapping, skill roster or repository concurrency quota is prescribed.
When useful, delegate independent, bounded work with the goal, minimal sufficient
context, exact source revision, owned paths or checkout, relevant contracts and
expected evidence. Avoid competing writers and repeated exploration. The
coordinator integrates results and arranges independent review when correctness,
privacy or consequential integration warrants it. Agents may not approve their
own work or gain publication or release authority through delegation.

A repository instruction cannot enable a model, switch a running session or override
tool policy. Keep project requirements, implementation evidence and tool choices
distinct. Use supported controls and report their actual capabilities and limits.
Do not edit host configuration, install tooling or run routing probes merely to
satisfy the workflow.

Implement complete usable slices within the agreed privacy and authority boundaries.
Before shared wire/interface allocation, inspect current and retained integration
heads; preserve field ownership and compatibility. Choose implementation details,
priorities, checks and scoped commit or push timing autonomously. Keep changes
reviewable and preserve unrelated changes, unfinished work and branch protections.
Seek authorization for consequential actions outside the agreed scope, including
private disclosure, real funds, host changes, permission expansion or bypassing
release controls.

### Commit attribution

Use the contributor's verified, account-linked Git identity for new commits.
Attribute work performed by AI coding agents or subagents to the contributor
on whose behalf they work. Confirm the name and account-linked email. Set the
identity locally in the task's checkout when needed and check it with
`git var GIT_AUTHOR_IDENT` and `git var GIT_COMMITTER_IDENT`. Resolve missing or
conflicting identity information before committing on the contributor's behalf.

Omit AI-specific `Co-authored-by` trailers from source commits and final integration
messages where tooling and applicable terms permit. Report any unavoidable
AI-specific attribution before publishing. Before merging or squashing, check the
source authors and resulting attribution, including automatically generated
co-author trailers. Always preserve the original authorship of other contributors
when integrating their existing work. Use an integration method that retains
their credit if a squash would lose it.

## Verify and record

Choose checks for the changed behavior and actual risk. Use narrow formatter/compile
checks and targeted functional smoke during development; run broader integration and
release checks when their scope is affected. Documentation-only work needs relevant
link, technical-claim, scope and preservation checks without runtime builds or
model-routing demonstrations. Run builds and runtime trials on approved disposable
hosted runners. Local read-only inspection and inert validation preserve host safety.
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
model tests.
