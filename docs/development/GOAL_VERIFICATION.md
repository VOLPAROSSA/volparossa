# Requirement preservation

The effective requirements are [GOAL.md](GOAL.md), [DPS_REQUIREMENTS.md](DPS_REQUIREMENTS.md)
and [STUDIO_HOSTING_REQUIREMENTS.md](STUDIO_HOSTING_REQUIREMENTS.md). Their compact
wording incorporates the agreed functional scope; development-tool choices follow
[AGENTS.md](../../AGENTS.md) and the [shared workflow](CODEX_WORKFLOW.md).

## What is preserved

The three `*_SOURCE_20261023.md` files retain the previous complete requirements
byte-for-byte, beside their effective versions so existing relative links resolve.
[DPS_GOAL_20261021.md](DPS_GOAL_20261021.md) retains the originally received DPS parts.
These are provenance, not additional startup instructions. The 2026-10-26 amendment
supersedes their old model assignments, repeated reading sequences and completed
one-time consolidation steps; it does not remove product requirements.

The verifier checks the original goal payload and earlier amendment prefixes, received
DPS payloads and exact join, original Studio payload, full source-snapshot hashes and
explicit links from effective requirements and the continuation prompt. Historical
hash baselines stay unchanged. It reads only the necessary requirement documents,
not the implementation ledger or unrelated workflow history.

## When and how to check

Run this when changing effective requirements, preserved sources, their inclusion
links or the continuation prompt:

```sh
python3 -B scripts/verify-goal-preservation.py
```

For an immutable committed version, append `--git-revision FULL_COMMIT_SHA` using its
full 40-character commit identity. Both modes are inert, bounded reads and work
without attachments, network access or native builds. When changing the verifier,
also run its focused regressions:

```sh
python3 -B scripts/test-goal-preservation.py
```

Hashes prove recorded bytes; link checks prove explicit inclusion. Neither proves
semantic equivalence of a rewrite, functioning datapaths or product acceptance.
Review requirement edits against the preserved sources for functional coverage and
changed authority. Use [implementation status](../IMPLEMENTATION_STATUS.md) for
source-bound functional evidence and the [testing guide](TESTING.md) for runtime gates.
There is no preservation-check requirement for every fresh conversation or ordinary
code change that leaves these documents untouched.
