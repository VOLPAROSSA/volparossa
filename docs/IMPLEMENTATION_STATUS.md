# VOLPAROSSA implementation status

This is the current execution index for the complete [DICN goal](development/GOAL.md),
including [DPS](development/DPS_REQUIREMENTS.md) and
[Studio/hosting](development/STUDIO_HOSTING_REQUIREMENTS.md). Use [AGENTS.md](../AGENTS.md)
for engineering boundaries and the [development workflow](development/CODEX_WORKFLOW.md)
for scoped execution. A milestone does not reduce the agreed goal.

Reorganized: 2026-10-26. Technical evidence below is the repository's recorded
2026-10-23 checkpoint at `89d3aea585ed`; this edit runs no new product trial and
makes no current GitHub run/PR-state claim. Refresh the relevant branch, checks
and ownership before resuming it. A previously recorded pending job is not proof
that it is running now. Later local baseline `6542b42f505c` changes README text only.

[Current work](#current-integration-and-active-work) ·
[Priorities](#execution-priorities-and-next-milestones) ·
[Retained work](#retained-branches-and-resumption-dependencies) ·
[Historical evidence](IMPLEMENTATION_HISTORY_20261023.md) ·
[Completion](#definition-of-done)

The [historical ledger](IMPLEMENTATION_HISTORY_20261023.md) preserves the previous
1,424,479 bytes unchanged, including original source revisions, run/artifact IDs,
digests, failures and scorecard. Its dated model assignments, session status and
procedural instructions are historical; current AGENTS/workflow supersede them.
Read the linked evidence for the task, rather than loading the entire archive.

## Current integration and active work

### Development workflow — 2026-10-26

The revised development policy replaces fixed model/effort/role assignments with
task-driven selection supported by the current client. Effective requirements and
workflow are streamlined; original requirement snapshots and the evidence ledger
remain byte-identical. Preservation/reference checks and independent scope review
cover this change, not new runtime acceptance. Only the literal-document Rust test
is removed; behavioral tests and production paths are unchanged.

| Workstream | Recorded checkpoint; next boundary |
| --- | --- |
| Network | Original v1 A01–A15 passes on `482e33d0`, run 34047766913; expanded DICN and warm/mixed-link acceptance remain separate. |
| Storage / Image / Cloud | Components pass; full consumer restore/deletion and zero remote usage remain open after catalog/retention failures. |
| Protected Compute | Public answers/corruption/cleanup pass in 39842391908, but aggregate host comparison fails. Later connect failure and source gates do not close runtime/private-workload acceptance. |
| Studio | Real local edit/style/preview/export/Core packing passes in 39869460125; production publication, independent hosting, shared AI and dynamic execution remain open. |
| DPS / Map | Synthetic daemon, quality C ABI and bounded debug JNI slice pass; real sensors, fusion, accuracy/integrity evaluation, navigation and location authority remain open. |
| Cache / Weather | Actual Drizz.li/Overmorrow and installed emulator delivery/refresh/resume pass; real expiry, automatic acquisition, physical devices/iOS and full precipitation/air-quality coverage remain open. |
| Code / Browser AI | Pinned native coding and bounded public peer/browser milestones pass; new compositions, general quality/performance, native editor and protected peer execution need their own proof. |
| Transactions / Bank | Durable owner-local TEST accounting and bounded four-validator partition/replay pass; full finality/Byzantine coverage, protected transport, real assets, settlement and Bank functionality remain open. |
| Other applications / maintenance | Continue every agreed integration and organization-wide work; component/source checks do not complete consumer scenarios. |

### Execution priorities and next milestones

Choose complete executable slices by shared dependency, demonstrated failure and
system value; these priorities impose no fixed application/model/agent order.

1. **Storage:** drive the required ordinary renewal rotation without weakening
   retention authority; then exercise catalog restore and finish Image/Cloud
   publish, repair, restore, deletion and confirmed zero remote usage.
2. **Protected model:** use the retained connect diagnostic and strict host gate
   to prove two public turns, corruption rejection and complete cleanup on one
   source; join separately authorized private execution only with its own proof.
3. **Studio publication:** bound request geometry and Storage reads before
   allocations; separate untrusted editor/MCP preparation from trusted native
   review, identity/revision binding, signing and authorized contribution. Prove
   uncertain-handoff reconciliation, independent retention/retrieval,
   publisher-offline availability and rollback; continue shared AI/dynamic state.
4. **Consumers/platforms:** integrate real DPS/Map sensors, fusion/navigation and
   actual upload, Chat/Mail, Code/Browser and Weather scenarios through shared
   Core. Preserve existing offline/platform behavior and permission ceilings.
5. **Full goal and efficiency:** continue all layers, governance, transactions,
   authorized updates and applications. Optimize demonstrated repeated cost;
   keep runtime performance evidence separate from CI savings and respect the
   existing outreach, financial/legal, publication and host authority boundaries.

### Storage consumer and provider evidence

- **Integrated provider fixes:** PR327 merges close-before-log source
  `a41030a51471` as `157908ad1e4a`. Scoped run 39832609493 proves actual TLS
  session release under held event-log locks; ordinary Quality/CodeQL pass.
  PR331 merges provider event-drain source `c111114b65a5` as `2a15a7f114e6`;
  scoped run 39851344008 passes two queue units, five candidate cases, three
  negative controls, strict Clippy and host comparison. These controlled fixes
  do not establish the cause of earlier consumer stalls.
- **Consumer failure:** run 39837551972 on `a41030a51471` fails Cloud deposit
  (`CONTENT_UNAVAILABLE` at distinct TLS/route stages). Run 39855345985 on
  `7c569dd08a71` reaches `cloud_catalog_create/catalog_materialization_failed`;
  the API collapses peer restore, verification/decryption and local I/O, so the
  substage is unknown. Provider usage remains 6/6/4 leases and
  1,198,718/1,198,718/799,148 committed bytes with zero reservations. Local and
  coordinator cleanup pass; remote deletion and aggregate consumer cleanup do
  not. Image/Cloud fixture pins remain unchanged.
- **Integrated diagnostics:** PR334 merges as `a68b805a4a00` with passing Quality
  39857954009 and CodeQL 39857949804. Catalog restore diagnostic PR336, source
  `300766d9e822`, merges as `146cfe898e15`; Quality 39863841700, all CodeQL
  analyses and 66 Node tests pass. These source results do not prove catalog
  restoration. Failure snapshots are bounded/sequential, not per-request cause
  evidence; empty saturated rings do not prove absence of failures.
- **Latest actual and follow-up:** Alpha 39864473079 fails
  `private-storage-maintenance-core-restart`, specifically
  `baseline_custody/reconcile_progress/pending_handoff` with
  `replacement_retention_insufficient`. The retention guard correctly prevents
  deletion; a pending fragment can require its next renewal rotation. Consumer
  work is not reached. Reviewed PR339 at `145c49e35ac8`, tree `a0bc4b2eec1d`,
  preserves authority/custody behavior and drives the calculated ordinary turns.
  Its 93 inert smoke/44 wiring tests and real writer-to-bounded-reader controls
  pass; ordinary Quality and actual Alpha 39871646877 are recorded pending in
  this checkpoint. Refresh them before deciding the next action.

[Full Storage evidence and original failures](IMPLEMENTATION_HISTORY_20261023.md#execution-priorities-and-next-milestones)
retain exact pins, artifacts and receipts. Automatic upload branch PR279 still
requires the complete consumer profile, finite authority, actual enrollment,
repeated restore and all-copy deletion; SDK source checks do not replace it.

### Protected Compute evidence

- The retained resident feature PR276 includes PR326/PR329/PR333/PR338.
  Public trial 39842391908 at `e4824ae3c9a3` obtains `READY` and `4`, rejects a
  corrupt image before entrypoint and confirms VM/tool/scratch cleanup, but
  fails `host_network_observation_changed`; the changed field/cause is unknown.
- Trial 39855637060 at `291e94938ebe` fails
  `two_public_turns/command_failed` after the connect prefix. It proves phase
  entry only; no public answer or complete host comparison follows. Diagnostic
  source run 39866709823 passes 137 Rust/484 Python cases at `3a96ad7f110b`;
  PR338 merges into the feature as `ce438c27df80` with the same tree. Actual
  feature trial 39868428738 is recorded pending and must be refreshed.
- Main-based draft PR332, branch `integration/resident-model-main-20261022`,
  is separately reconciled at `af9ecc3ca400`, tree `eefe84a3565b`.
  Source gate 39868938187 passes 137 Rust/485 Python tests, compilation,
  formatting and Clippy; actual-model execution is skipped. Ordinary
  Quality/CodeQL for this newer source remain separate recorded pending gates.
  Earlier source `84be249dd014` passes Quality 39856525861 and CodeQL
  39856518477; alert341 is fixed in that PR instance without dismissal. Those
  results do not transfer to an untested composition.

Keep strict raw host equality, unchanged public-job authority, bounded
privacy-safe diagnostics and original failures. Public fixture execution is not
confidential/private-workload acceptance. The
[full record](IMPLEMENTATION_HISTORY_20261023.md#resumed-full-objective-and-dependency-work--2026-10-22)
retains exact source/tree manifests and failed/successful artifacts.

### Studio and shared hosting evidence

Paired actual [39869460125](https://github.com/VOLPAROSSA/volparossa/actions/runs/39869460125)
passes on Core `dfa6f3434bb9` and Studio `eaf9e336e003`: real editing and
37px styling/preview produce a 1,477-byte DownloadConnector ZIP; actual Core
packing/decoding verifies four assets, lengths, hashes and edited HTML/CSS.
Packing again into existing output is rejected. In-memory model serialization
preserves edits; saved-project reload is not proved. Scoped browser/server and
temporary-output cleanup pass, without a complete host-absence audit.
Studio PR2 merges as `bb89a781d56f` with the exact tested Studio tree;
Core PR330 merges as `18b96ff3ab50`, with separate combined-tree checks.

Expected-publisher guard PR337, source `35c9209b280d`, merges as
`b15559129bc5`. Quality 39865075626 and CodeQL pass its source: signer pin
mismatch is rejected before manifest/cache/signing/contribution side effects.
CLI peer receipts are simulated, not independent hosting. Full native review,
bounded export preparation, identity/revision authority, independently retained
hosting, shared AI and all fifteen Studio acceptance cases remain open.
The pinned publication route currently builds vectors and reads Storage assets
before calling the connector; preparation must be bounded before that seam.

[Studio evidence, failed trials and source bindings](IMPLEMENTATION_HISTORY_20261023.md#studiohosting-scope-and-preserved-work--2026-10-22)
remain available without becoming routine startup context.

### Decentralized positioning system — 2026-10-21

Core DPS service PR299, dormant-daemon proof PR305 and quality-only C ABI PR314
are integrated. Envelope 2 / DPS schema 1 uses field 64, preserving Storage's
46–49 / 34–37 assignments. The 36-byte quality ABI accepts canonical bounded
protobuf, returns no coordinates and grants no sensor/application authority.
Synthetic daemon execution, joined normal shutdown and bounded unchanged host
observations are proved, not hardware positioning or crash/restart recovery.

Map actual 39844370003 at `1546bf3ada1c` passes eight actual Android/JNI cases,
offline rebuild, owned cleanup and cancellation controls. The completed-emulator
configuration checkpoint is accepted; raw aggregate
`host_routes_dns_firewall_unchanged=false` is retained. The runner is
`7.0.0-1017-azure`, so the separately researched 6.17 profile remains unexercised.
Vendor patch lineage, physical positioning, sensors, main navigation and
application identity/permission authority remain unproved. The fixture stack
enters Map main as `ae7a5ccdbd14`, documentation as `8a227709e99f`.
Preserve unpublished Map `feature/native-traffic-lifecycle` at `ca7a4e59a057`.

[DPS/Map history](IMPLEMENTATION_HISTORY_20261023.md#decentralized-positioning-system--2026-10-21)
and the [service contract](services/DPS.md) retain research and acceptance detail.

### Latest completed integration evidence

- **Code:** actual 38824828727 on Code `fd4ff9688c58` / Core `7d0f9f0b492c`
  completes two reads, approved edit/test, independent verification and scoped
  cleanup with real native model output. Code PR11 is integrated. Core PR277
  separately integrates its native-only backend; that main composition has no
  new model trial. General coding quality/performance, native editor and
  protected peer execution remain open.
- **Weather/cache:** Drizz.li 38228710535 and Overmorrow 38241212407 prove actual
  protected acquisition and initial/refresh UI behavior. Installed Android
  38717988016 passes actual app-triggered delivery, cache refresh and
  background/resume on Core `aac5be7f` / Weather `3b90442a`. Expiry evidence is
  synthetic; physical devices, iOS and full source/feature coverage remain open.
- **Transactions:** actual 37669796654 on `2ea504e399eb` passes four-validator
  TEST conservation/conflict, 3–1/2–2 partitions, rejoin and committed-retry
  replay. Raw parent snapshots differ; the separately bounded expiry-countdown
  observer accepts the represented changes, not continuous unchanged-host
  proof. Full distributed finality/Byzantine/pre-commit crash coverage, external
  settlement and complete Bank functionality remain open.

These results remain bound to their actual source and scenario.
[Earlier completed integration details](IMPLEMENTATION_HISTORY_20261023.md#latest-completed-integration-evidence)
and [Transaction evidence](IMPLEMENTATION_HISTORY_20261023.md#bank-and-transaction-layer-implementation)
include independent review, resource limits, artifacts and unresolved cases.

### Retained branches and resumption dependencies

This index identifies preserved work, not current locks or verified live remote
heads. Inspect `git worktree list` and the task's relevant Git/CI state before
using a checkout. Never reset unpublished work or remove dirty/ambiguous trees.

| Work | Retained branch / checkout | Resume boundary |
| --- | --- | --- |
| Resident feature | `feature/protected-resident-model`, `.git/codex-protected-resident-model`, PR276 | Keep feature/runtime evidence distinct from main-based PR332; refresh trial 39868428738. |
| Main resident composition | `integration/resident-model-main-20261022`, PR332 | Source gate passes at af9ecc3c; runtime and newer ordinary gates require current evidence. |
| Model connect diagnostic | `.volparossa-dev/worktrees/resident-connect-observation-20261023`, PR338 | Integrated into retained feature; preserve original host/connect failures. |
| Storage rotation | `.volparossa-dev/worktrees/storage-maintenance-rotation-20261023`, PR339 | Refresh source/actual 39871646877; do not infer convergence or catalog restore. |
| Catalog diagnostic | `.volparossa-dev/worktrees/storage-catalog-restore-20261023`, PR336 | Integrated source; actual 39864473079 fails before catalog work. |
| Automatic upload | `feature/cloud-upload-tls-v9`, `.git/codex-cloud-upload-tls-v9`, PR279 at dd1fd4df | Complete shared consumer profile and remote cleanup before upload acceptance. |
| Earlier Storage dependencies | `.git/codex-storage-route-retirement`, `.git/codex-storage-real-route-sequence`, `.git/codex-storage-natural-expiry-sequence`, `.git/codex-storage-post-acquire-clock` | Preserve PR275/285/287/288 history and later integrated corrections; old heads are not current implementation status. |
| Map | `feature/native-traffic-lifecycle` at ca7a4e59; quality work `.volparossa-dev/worktrees/dps-native-quality-20261021` | Preserve unpublished work and accepted debug fixture; complete real sensors/navigation. |
| Studio publication | `.volparossa-dev/worktrees/studio-publisher-pin-20261023`, PR337 | Pin guard integrated; preparation, native authority and hosting remain required. |

The original root `error.log`, dirty/untracked work in other retained trees,
recovery manifests, pinned models/caches and `.git/ci-evidence/` remain preserved.
An old branch name, prunable registry entry or ended conversation is not evidence
that its work can be deleted. Existing failed reports are immutable; if their
artifacts expire, record the evidence gap rather than reconstructing success.

## Network baseline and remaining proof

The original [full v1 checkpoint](IMPLEMENTATION_HISTORY_20261023.md#current-live-integration-checkpoint)
passes A01–A15 on `482e33d0` with complete privacy captures, real MPTCP aggregation,
path-loss survival, 25 forced crashes/helper restart recovery and zero owned
objects after cleanup. Run 34047766913 and Quality 34047735082 bind that source.
The same-build mixed-link run 34047765944 fails its WAN-only warm-route baseline
with `INGRESS_MPQUIC_DATAGRAM_REJECTED`; it proves no new LAN+WAN gain ratio.
Reciprocal owner-priority download trial 34142685975 at `efc35ac9` passes its one
configured IPv4 bottleneck; arbitrary ISP/Wi-Fi/physical-radio guarantees do not
follow. Local-only configuration alone does not prove offline private-endpoint
routing. All newer shared-service, application and update requirements remain
part of completion.

## Fixed alpha v1 scorecard

The frozen original twenty-row, 100-point criteria and AV1/A01–A15 definitions
remain in the [preserved scorecard](IMPLEMENTATION_HISTORY_20261023.md#fixed-alpha-v1-scorecard).
Its pre-vertical 11/100 value is historical, not today's score. Later accepted
same-build v1 execution is recorded above; no new full-goal percentage is assigned
by reorganizing documentation. Functional extensions remain required regardless
of that baseline milestone.

## Historical evidence index

The following anchors preserve existing incoming references while directing
historical claims to their original source-bound records. They are navigation,
not additional startup reading or current completion assertions.

<a id="current-live-integration-checkpoint"></a>
<a id="current-candidate-functional-integration-in-progress"></a>
<a id="latest-completed-integration-evidence--15-october"></a>
<a id="latest-completed-integration-evidence--1516-october"></a>

- [Original live network checkpoint](IMPLEMENTATION_HISTORY_20261023.md#current-live-integration-checkpoint)
  and [earlier functional candidate](IMPLEMENTATION_HISTORY_20261023.md#current-candidate-functional-integration-in-progress).
- [Earlier native/consumer milestones](IMPLEMENTATION_HISTORY_20261023.md#latest-completed-integration-evidence).

<a id="latest-dns-integration-checkpoint"></a>
<a id="latest-known-contact-mailbox-integration-checkpoint"></a>
<a id="latest-content-integration-checkpoint"></a>
<a id="earlier-milestone-evidence"></a>

- [DNS](IMPLEMENTATION_HISTORY_20261023.md#latest-dns-integration-checkpoint),
  [known-contact mailbox](IMPLEMENTATION_HISTORY_20261023.md#latest-known-contact-mailbox-integration-checkpoint),
  [content](IMPLEMENTATION_HISTORY_20261023.md#latest-content-integration-checkpoint)
  and [earlier milestones](IMPLEMENTATION_HISTORY_20261023.md#earlier-milestone-evidence).

<a id="additional-application-and-autonomous-maintenance-scope"></a>
<a id="android-to-core-integration-boundary"></a>
<a id="warm-mpquic-growth-integration"></a>

- [Application/maintenance integration](IMPLEMENTATION_HISTORY_20261023.md#additional-application-and-autonomous-maintenance-scope)
  and [Android integration evidence](IMPLEMENTATION_HISTORY_20261023.md#installed-android-verification).
- [Network candidate and growth evidence](IMPLEMENTATION_HISTORY_20261023.md#current-candidate-functional-integration-in-progress).

<a id="explicit-local-policy-for-protected-compute"></a>
<a id="guest-owned-protected-compute-session-candidate"></a>
<a id="protected-compute-verifier-preparation"></a>
<a id="authorized-quote-exchange-candidate"></a>
<a id="explicit-public-code-proposals-bounded-peer-repair-passes"></a>

- [Protected local policy](IMPLEMENTATION_HISTORY_20261023.md#explicit-local-policy-for-protected-compute),
  [guest-owned session](IMPLEMENTATION_HISTORY_20261023.md#guest-owned-protected-compute-session-candidate),
  [verifier preparation](IMPLEMENTATION_HISTORY_20261023.md#protected-compute-verifier-preparation),
  [authorized quote exchange](IMPLEMENTATION_HISTORY_20261023.md#authorized-quote-exchange-and-authenticated-refusal)
  and [public peer repair](IMPLEMENTATION_HISTORY_20261023.md#explicit-public-code-proposals-bounded-peer-repair-passes).

## Definition of done

Completion requires the full [goal and all amendments](development/GOAL.md),
including complete DPS and Studio criteria, to work through their actual
production consumers with required trust, privacy, recovery, authority and
platform boundaries. Checked work needs passing scope-appropriate evidence;
unimplemented, skipped or simulated behavior remains open. A source test,
component fixture or older passing source cannot stand in for another source's
runtime acceptance. Keep this index current with the next action and evidence
link; add detailed immutable receipts to the historical/topic record rather
than growing another session transcript here.
