# Repository maintenance — 2026-10-20

This maintenance pass audited all 14 organization repositories and 11 local
primary repositories before resuming product development. Inventory and recovery
plans preceded removals. The full [agreed goal](GOAL.md) and existing runtime
acceptance gaps remain in force.

## Verified local cleanup

| Action | Evidence and retained boundary |
| --- | --- |
| Removed 102 old Cargo profiles in two reviewed batches | Filesystem free-space increases were 323,678,490,624 bytes and 41,154,564,096 bytes. Shared core caches, three recent profiles, source, dependency inputs and patches remain. |
| Retired 120 clean integrated worktrees using Git | Checked exact commits, ignored/untracked content, nested repositories, mount boundaries and visible process references. No forced worktree removal. The batch increased free space by 3,328,249,856 bytes. |
| Pruned 207 missing core worktree administration records | Archived administration data and verified an incremental unpublished-commit bundle first; preserved 51 unique detached revisions as recovery refs. |
| Retired 205 integrated local branches and six integrated remote branches | Recorded exact tips and verified ancestry, open-PR dependencies and active references. No history rewrite, forced branch deletion or destructive garbage collection. |
| Aligned nine clean primary application checkouts with current main | Kept Map's unique feature checkout and all unpublished changes. Repaired Code's obsolete explicit fetch refspec after saving its previous value. |

The measured cleanup-batch free-space increases total **342.88 GiB**. This is a
batch measurement: recovery archives, audit records and maintenance checkouts
occupy space. Net recovered space is approximately **340 GiB (365 GB)**, including
that retained recovery material. Exact filesystem byte counts are recorded in
the local audit; component `du` totals are not additive because of hardlinks.

Twelve deduplicated recovery objects (2,803,269,949 bytes) preserve all 24 legacy
fuzz executable/depfile mappings from four removed profiles. Independent full
SHA-256 verification passed. The second batch also verified the unchanged content
of 12,712 fuzz source, manifest, corpus and crash files. Historical build revisions
and execution compatibility of the archived harnesses are not established.

Retained material includes original CI/acceptance evidence, pinned model inputs,
all unique/unmerged branches, dirty worktrees, untracked fixtures and the original
error log. The 14.68 GB guest VM/Cargo cache and its lock files remain preserved;
so do native build copies whose upstream provenance is incomplete. Three additional
MPQUIC build trees (6.77 GiB) were reviewed but retained because process visibility
and staged-source equivalence remain uncertain. Their 420 metadata/evidence files
(7.15 MiB) have separate verified recovery copies, including historical ordinary
and sanitizer logs; those old logs are not fresh native acceptance. A missing
checkout with an unresolved three-stage index remains locked;
all three stage blobs are separately preserved and hash-verified. An existing
external checkout with a missing Git marker also remains locked. Neither was
mistaken for an empty disposable record. Process visibility has documented
permission gaps; no exhaustive claim about inaccessible processes is made.

## Security and dependency maintenance

Independent review identified nine file-race findings across core, Browser,
Cloud, Code and Weather. Reviewed readers now validate and bound reads through the
opened descriptor. Weather captures verified decoder bytes into an exclusive
private executable copy, retaining process bounds and cleanup. Source tests cover
symlinks, non-regular files, size/growth checks and substitutions as applicable.
No runtime datapath, model quality or new native ecCodes execution is claimed.

| Repository | Integrated maintenance |
| --- | --- |
| Core | [PR292](https://github.com/VOLPAROSSA/volparossa/pull/292): descriptor reads, artifact-action and contract pins, compatible Protobuf compiler/library pins, and both dependency lockfiles. Merged at `3cac793e`, with a source tree identical to tested candidate `fe9d6623`. Quality `39465279385` and all four CodeQL analyses in `39465269032` pass. |
| Browser | [PR18](https://github.com/VOLPAROSSA/volparossa-browser/pull/18), merged at `2192a15a`: descriptor-bound fixture reads; source and CodeQL checks pass. |
| Cloud | [PR17](https://github.com/VOLPAROSSA/volparossa-cloud/pull/17), merged at `dec0f2c2`: protected recovery asset reads; source and CodeQL checks pass. [PR10](https://github.com/VOLPAROSSA/volparossa-cloud/pull/10), merged at `28d5a0f3`: verified Node setup action pin with refreshed passing checks. |
| Code | [PR20](https://github.com/VOLPAROSSA/volparossa-code/pull/20), merged at `e1e3f63b`: descriptor reads, artifact-action update and preserved exact driver-hash assertion. Source run `39461692740` and CodeQL pass. |
| Weather | [PR26](https://github.com/VOLPAROSSA/volparossa-weather/pull/26), merged at `78fb8dba`: verified decoder capture/execution and artifact-action update; components and CodeQL pass. |
| Bank | [PR7](https://github.com/VOLPAROSSA/volparossa-bank/pull/7), merged at `f4d4f319`: leaf `sha2` update; refreshed offline run `39461159135` and CodeQL pass. |

The source-fix review recorded 111 focused/adjacent Node passes, 14 exact artifact
pin checks and syntax/diff checks. CI exposed two additional maintenance failures:
Core run `39459633287` used an obsolete Ubuntu Protobuf package revision; Code run
`39460081185` retained the old smoke-driver hash. The fixes retain the exact
assertions and runner restrictions. Code's corrected Python suite passes 169
tests with three existing skips, plus 22 focused Node tests. Quality run
`39461685805` passed its Rust tests, Clippy and audits, then failed
a second stale artifact-pin assertion in the final helper harness. Separate
CodeQL run `39461680784` passed all four analyses on the same commit. Its
one-line correction preserves all 48 exact workflow-literal checks. PR292 contains
the complete PR291 history plus this correction; superseded automatic runs on the
older combined candidate were cancelled with their results retained. Final Quality
run `39465279385` passes, including the corrected complete non-mutating integration
harness; all four CodeQL analyses pass in `39465269032`. Original failed runs
remain available. The dependency composition adds 64 passing inert
contract tests;
registry checksums, upstream source, MSRV and unchanged license files were reviewed.

Of the original 152 open CodeQL findings, 135 were independently verified as
test-only and eight as false positives, with per-alert source evidence and
recorded dispositions. All nine file-race findings now have GitHub state `fixed`
after code changes and rescanning; none was dismissed. One new Code test finding was
separately reviewed and classified as test-only:
it intentionally observes content and inode changes after an approved replacement.
No valid finding was suppressed and no security feature or branch protection was
weakened. The initial audit found
zero open Dependabot alerts and zero open secret alerts where scanning was
available. The final audit again observes zero open Dependabot alerts across all
14 repositories, zero open CodeQL findings across the 11 with available results,
and zero open secret alerts across the 13 with available results. Two public
repositories have no available CodeQL results; private scanning/protection
limitations remain explicit. All 81 comparable configuration observations are
unchanged, including the 13 public rulesets and Actions/token permissions.
Traditional branch-protection APIs remain unavailable (the public repositories
use rulesets), so this is not a claim of complete API coverage. No paid service
was enabled. The final organization snapshot retains 31 open PRs and 64 branches;
those retained candidates keep their original development status.

## PR decisions and recovery

- Closed core PR193 in favor of PR211 and PR234 in favor of PR279 after proving
  complete ancestry and checking downstream PR bases; retained their branches.
- Code PR13 and Weather PR20 are superseded by the integrated artifact-action
  updates. Weather's bot closure and Code's reviewed closure retain explanations.
- Keep Bank PR6 open: Ed25519 v3 conflicts with the pinned adapter's v2 key type
  and requires a deliberate API migration. Keep unfinished storage, upload,
  protected-compute and application candidates with their original failed evidence.
- Closed core PR220–224 and PR291 after PR292 passed and merged. The zeroize and
  HPKE pairs were complementary updates, now integrated coherently in both locks.
  Verified all action pins, exact dependency versions and downstream PR bases;
  retained predecessor history and original failed evidence.

Raw inventories, exact ref/path manifests, per-removal receipts, patches, verified
bundles and fuzz recovery objects remain under the ignored local
`.volparossa-dev/maintenance/20261020/` directory. They include private/local data
and are deliberately not published. `git fsck --full --no-dangling` passed in all
11 primary repositories again after the cleanup (17:09–17:11 UTC), with zero
warnings and stable primary HEADs. Newly created maintenance worktrees are
retired after integration, with their branches retained. Recovery refs and normal
Git history retain removed integrated tips. Final preservation checks match the
original goal/instruction/error-log hashes and both saved source patches; all five
original dirty-work path inventories still match. Untracked fixture and bytecode
contents did not have individual baseline hashes, so their byte identity is not
claimed.

The [development workflow](CODEX_WORKFLOW.md#worktree-and-generated-artifact-lifecycle)
now directs temporary worktrees outside `.git`, reuses pinned caches and requires
source/evidence review before retirement. Python bytecode caches are ignored.
No recurring deletion automation, host installation or network configuration
change was introduced.
