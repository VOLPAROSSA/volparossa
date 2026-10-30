# VOLPAROSSA implementation status

This is the current execution index for the complete [DICN goal](development/GOAL.md),
including [DPS](development/GOAL.md#dps) and
[Studio/hosting](development/GOAL.md#studio). Use [AGENTS.md](../AGENTS.md)
for engineering boundaries and the [development workflow](development/CODEX_WORKFLOW.md)
for scoped execution. A milestone does not reduce the agreed goal.

Reorganized: 2026-10-26; evidence reconciled: 2026-10-27. Technical evidence
combines the recorded 2026-10-23 checkpoint at `89d3aea585ed` with the
[PR343 evidence supplement](archive/integration-evidence-pr343-20261023.patch.txt)
at `a52ab4e77184`. That supplement preserves the original source/tree bindings,
artifact IDs, digests and failures without restoring obsolete workflow instructions.
The four formerly pending runs identified below have refreshed GitHub run/job
metadata as of 2026-10-27; their artifacts were not revalidated in this edit.
That documentation reconciliation ran no new product trial. Refresh relevant branch/check ownership before
resuming; an old source result does not establish current composition acceptance.

[Current work](#current-integration-and-active-work) ·
[Priorities](#execution-priorities-and-next-milestones) ·
[Retained work](#retained-branches-and-resumption-dependencies) ·
[Historical evidence](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md) ·
[Completion](#definition-of-done)

The [historical ledger](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md) preserves the previous
1,424,479 bytes unchanged, including original source revisions, run/artifact IDs,
digests, failures and scorecard. Its dated model assignments, session status and
procedural instructions are historical; current AGENTS/workflow supersede them.
The [local source archive](archive/requirements-20261023/README.md) retains the
original bytes for offline inspection. Read only evidence relevant to the task.

## Current integration and active work

### Core project website — 2026-10-30

The bounded Golden Harbour introduction lives in `website/`, with an isolated
Python static build and project Pages artifact for `/volparossa/`. It imports
reviewed shared theme v1.0.3 from homepage commit `8114d966f3e9` and preserves
development/permission boundaries from Core source `edf569300acb`.
[Website verification](../website/VERIFICATION.md) records responsive Chromium/
Firefox renders, accessibility, no-JavaScript behavior and performance results.
This work changes no runtime or project goal and supplies no new Core, DPS,
network, model or sensor acceptance evidence. Publication follows the existing
required PR gate and the separate scoped website deployment workflow.
The owner’s subsequent visual refinement restores the four concept scenes below
the unchanged hero and adds an accessible rotating nine-application strip,
excluding Bank/Citizen; [bounded website evidence](../website/REFINEMENT-VERIFICATION.md)
records the responsive renders, original icons and interaction checks.

### F04 — helperacceptatie geslaagd; handmatige integratie — 2026-10-27

De kandidaat voor [PR349](https://github.com/VOLPAROSSA/volparossa/pull/349) bevat de minimale
beveiligingsroute en de gerichte helpercorrecties. De oorspronkelijke
[F04-evidence en failures](https://github.com/VOLPAROSSA/volparossa/blob/ff2df276bc50a395dbcfa2d11b515c51fe0ee340/docs/IMPLEMENTATION_STATUS.md)
blijven behouden; PR347 is historische basis, geen afzonderlijke integratiekandidaat.

De verkeersblokkade was een fixture-omgevingsfout: een verse private
netwerknamespace begint met ICMP-datagramgroepbereik `1 0`, terwijl de hook bewust
geen `NET_RAW` heeft. Correctie `3a4ef6c9` staat uitsluitend de gevalideerde
agent-GID toe in de twee tijdelijke namespaces die werkelijk ping uitvoeren.
Root-/groep-/capability-/namespacebinding, beginwaarde en readback zijn fataal;
productiecode en capabilities blijven gelijk. De initiële hostnamespace wordt
alleen gelezen; haar pingbereik is aan de bestaande voor/na-vergelijking toegevoegd.

De enige geautoriseerde [Debian13-KVM-proef40542366058](https://github.com/VOLPAROSSA/volparossa/actions/runs/40542366058)
**slaagt** op exact `3a4ef6c9d3499cbe4d71db614194cba14e3a89b6`.
De bestaande Client/Exit/Relay-ping-, handshake-, RX/TX- en relaygroeicontroles,
exacte custody/FD-storecycli, commit/destroy/retry, één geforceerde singleton
CleanupConfirmedExactPresent-restart, cleanup/retirement, hostvergelijking en
VM-/image-/bronfences zijn werkelijk doorlopen. Dit is de bestaande niet-bewaarde
branchproef; geen retained-main-mijlpaal, algemeen restartbewijs of DICN-productacceptatie.
Numerieke bereik-/counterwaarden zijn niet als afzonderlijke artifacts bewaard;
de positieve grens volgt uit de fatale guards en de exact gebonden PASS.

Zes nieuwe private-fixtureregressies, acht diagnosetests, de volledige betrokken
livecontracttest en gerichte syntax/ShellCheck/diffcontroles slagen. Onafhankelijke
bron- en resultaatreview bevestigt de afbakening. Eerdere Quality40487291792,
CodeQL40487286993, dependency/RustSec- en zbus/crypto/DPS-native-evidence blijven
hergebruikt voor hun gecontroleerd gelijke inputs; dit is geen herhaalde audit.
De integratiekandidaat behoudt actuele main-documentatie en doorloopt de
[bestaande PR-controles](https://github.com/VOLPAROSSA/volparossa/pull/349/checks).
Integratie en administratieve F04-afsluiting blijven aan handmatige maintainermerge
gebonden. Geen automatische merge of productieactivatie.

### Development workflow — 2026-10-26

The remaining authored documentation has been reviewed across architecture,
network, services, development, privacy, applications and component references.
Repeated checklists and superseded trial narratives are consolidated; current
wire versions and runtime/installed-package claims are corrected against source
and existing evidence. Detailed records remain in the [documentation archive](archive/README.md).
This documentation work changes no product behavior or runtime acceptance.

The complete requirements now live in one GOAL, with DPS as a shared service and
Studio/hosting among the applications. Duplicate goal/prompt and add-on requirement
files are removed; source records live in the archive. The revised development
policy replaces fixed model/effort/role assignments with
task-driven selection supported by the current client. Effective requirements and
workflow are streamlined; original requirement snapshots and the evidence ledger
remain byte-identical. Preservation/reference checks and independent scope review
cover this change, not new runtime acceptance. Only the literal-document Rust test
is removed; behavioral tests and production paths are unchanged.

| Workstream | Recorded checkpoint; next boundary |
| --- | --- |
| Network | Original v1 A01–A15 passes on `482e33d0`, run 34047766913; expanded DICN and warm/mixed-link acceptance remain separate. |
| Storage / Image / Cloud | Components pass; full consumer restore/deletion and zero remote usage remain open after catalog/retention failures. |
| Protected Compute | Strict host gate fails in 39868428738 despite public answers/corruption/cleanup; later feature run 39876860833 has successful public-job metadata. Receipt-level host/configuration acceptance, main composition and private workloads remain separate. |
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
  pass. Recorded ordinary Quality 39871649767 and CodeQL 39871645927 pass;
  Quality tests merge `d78c02be1003`, tree `b6a107651409` (main `18b96ff3` plus
  source `145c49e3`), with 4,250 passed/0 failed/18 ignored top-level tests,
  334 focused Storage Python cases and 66 Node tests. Actual Alpha
  [39871646877](https://github.com/VOLPAROSSA/volparossa/actions/runs/39871646877)
  is now verified completed/failed at that source; its failed job step is
  `Require actual owner-private storage maintenance`. This metadata does not
  establish the underlying failure substage, rotation convergence, catalog
  restoration or independent remote cleanup.

[Full Storage evidence and original failures](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#execution-priorities-and-next-milestones)
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
  PR338 merges into the feature as `ce438c27df80` with the same tree.
- **Strict actual failure:** feature trial 39868428738 fails the final
  `host_network_observation_changed` gate despite both expected `READY`/`4`
  answers, corruption rejection at `verity_read` and VM/tool/scratch cleanup.
  Its aggregate remains `state=failed`, `model_execution=false`. The bounded
  Linux 6.17.0-1022-azure diagnostic identifies `REFERENCE_METADATA_ONLY`:
  renderer, IPv4 routes, DNS and all six IPv6 rows' non-reference-count bytes
  match; reference counts/raw IPv6 fingerprint differ. This localizes this
  run's difference, without identifying its actor or explaining earlier runs.
- **Feature checkpoint candidate:** PR341 at `81c6b6a5522b`, tree
  `411c728475a8`, preserves raw equality false and adds a separate versioned,
  bounded route/DNS configuration checkpoint plus sticky cancellation and
  post-cleanup terminal checks. Source gate 39875150717 passes 137 Rust/494
  Python tests, formatting, compilation and Clippy; actual execution is skipped.
  It merges into the retained feature as `2d004c2466ef`, with the tested tree.
  Follow-up [39876860833](https://github.com/VOLPAROSSA/volparossa/actions/runs/39876860833)
  is now verified successful at that SHA, including the `public-model` job and
  execution step. This refresh did not inspect its final receipt fields and
  does not reclassify the earlier strict failure. The terminal guard selects
  success after cleanup; cancellation at later receipt-write entry is not
  atomic with that decision and can retain an already selected pass.
- **Main composition:** PR332, branch `integration/resident-model-main-20261022`,
  is separately reconciled at `af9ecc3ca400`, tree `eefe84a3565b`.
  Source gate 39868938187 passes 137 Rust/485 Python tests, compilation,
  formatting and Clippy with actual-model execution skipped. Recorded Quality
  39868882810 and CodeQL 39868876355 pass; Quality tests merge `2d11a7778786`,
  tree `9550ea68f344` (main `a68b805a` plus `af9ecc3c`), with 4,345 top-level
  passes/0 failures/17 ignored. Later checkpoint reconciliation `c29f67c5a884`,
  tree `10b4bb01e73b`, has 243 inert controller/20 host tests and unchanged
  dependency/public-job authority. Its source run
  [39876866868](https://github.com/VOLPAROSSA/volparossa/actions/runs/39876866868)
  is now verified successful at that SHA with `public-model` skipped. Neither
  source run proves actual inference on main's dependency composition or any
  subsequent reconciliation. Earlier Quality/CodeQL results likewise remain
  bound to their tested composition.

Keep raw host equality separate from configuration-checkpoint acceptance,
unchanged public-job authority, bounded privacy-safe diagnostics and original
failures. Public fixture execution is not confidential/private-workload acceptance. The
[full record](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#resumed-full-objective-and-dependency-work--2026-10-22)
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

PR340 adds optional expected-input SHA-256 binding over a bounded owned,
zeroizing snapshot, publishing the same captured bytes and rejecting before
credential/cache/signing/IPC effects; omission preserves streaming behavior.
Initial Quality 39873065947 fails Clippy on test binding names; correction
`4c0e11a2b349`, tree `6802c497e899`, only renames that binding. This prerequisite
does not establish native review authority or hosting.

The subsequent local-viewer fixture uses Core PR342 `c815483c48e5` and Studio PR4
`65ab59b81b3c`, with an explicitly mocked local named transfer into actual
`content site open`; it is not independent peer hosting. Recorded actual
39875855784 fails `viewer-runtime/exit_nonzero`: editor/export and Core viewer
compilation pass, owned groups drain and temporary outputs are removed, but
no successful viewer, child-control or independent-browser result follows.
Its reviewed bounded diagnostic follow-up pairs Core `81ecc1a79561` with Studio
`164e08dfa487`; 13 inert diagnostic tests pass. Run
[39877380401](https://github.com/VOLPAROSSA/volparossa/actions/runs/39877380401)
is now verified completed/failed at that Core SHA in dependency acquisition/Studio
fixture compilation; the actual viewer/browser step is skipped. These metadata
localize that follow-up's reached step, not the earlier viewer failure's cause.

[Studio evidence, failed trials and source bindings](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#studiohosting-scope-and-preserved-work--2026-10-22)
and the [PR343 supplement](archive/integration-evidence-pr343-20261023.patch.txt)
retain artifacts, hashes and exact source/tree bindings without becoming routine
startup context.

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

[DPS/Map history](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#decentralized-positioning-system--2026-10-21)
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
[Earlier completed integration details](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#latest-completed-integration-evidence)
and [Transaction evidence](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#bank-and-transaction-layer-implementation)
include independent review, resource limits, artifacts and unresolved cases.

### Retained branches and resumption dependencies

This index identifies preserved work, not current locks or verified live remote
heads. Inspect `git worktree list` and the task's relevant Git/CI state before
using a checkout. Never reset unpublished work or remove dirty/ambiguous trees.

| Work | Retained branch / checkout | Resume boundary |
| --- | --- | --- |
| Resident feature | `feature/protected-resident-model`, `.git/codex-protected-resident-model`, PR276 | Keep strict failure 39868428738 and later successful-job metadata 39876860833 distinct; inspect the latter receipt before host/configuration claims. |
| Main resident composition | `integration/resident-model-main-20261022`, PR332 | Source gates pass at af9ecc3c and c29f67c5; ordinary merge results bind af9ecc3c, not later runtime compositions. |
| Model connect diagnostic | `.volparossa-dev/worktrees/resident-connect-observation-20261023`, PR338 | Integrated into retained feature; preserve original host/connect failures. |
| Storage rotation | `.volparossa-dev/worktrees/storage-maintenance-rotation-20261023`, PR339 | Ordinary source gates pass; actual 39871646877 fails owner-private maintenance. Inspect its report before diagnosing or claiming convergence. |
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

The original [full v1 checkpoint](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#current-live-integration-checkpoint)
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
remain in the [preserved scorecard](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#fixed-alpha-v1-scorecard).
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

- [Original live network checkpoint](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#current-live-integration-checkpoint)
  and [earlier functional candidate](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#current-candidate-functional-integration-in-progress).
- [Earlier native/consumer milestones](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#latest-completed-integration-evidence).

<a id="latest-dns-integration-checkpoint"></a>
<a id="latest-known-contact-mailbox-integration-checkpoint"></a>
<a id="latest-content-integration-checkpoint"></a>
<a id="earlier-milestone-evidence"></a>

- [DNS](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#latest-dns-integration-checkpoint),
  [known-contact mailbox](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#latest-known-contact-mailbox-integration-checkpoint),
  [content](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#latest-content-integration-checkpoint)
  and [earlier milestones](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#earlier-milestone-evidence).

<a id="additional-application-and-autonomous-maintenance-scope"></a>
<a id="android-to-core-integration-boundary"></a>
<a id="warm-mpquic-growth-integration"></a>

- [Application/maintenance integration](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#additional-application-and-autonomous-maintenance-scope)
  and [Android integration evidence](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#installed-android-verification).
- [Network candidate and growth evidence](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#current-candidate-functional-integration-in-progress).

<a id="explicit-local-policy-for-protected-compute"></a>
<a id="guest-owned-protected-compute-session-candidate"></a>
<a id="protected-compute-verifier-preparation"></a>
<a id="authorized-quote-exchange-candidate"></a>
<a id="explicit-public-code-proposals-bounded-peer-repair-passes"></a>

- [Protected local policy](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#explicit-local-policy-for-protected-compute),
  [guest-owned session](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#guest-owned-protected-compute-session-candidate),
  [verifier preparation](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#protected-compute-verifier-preparation),
  [authorized quote exchange](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#authorized-quote-exchange-and-authenticated-refusal)
  and [public peer repair](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#explicit-public-code-proposals-bounded-peer-repair-passes).

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
