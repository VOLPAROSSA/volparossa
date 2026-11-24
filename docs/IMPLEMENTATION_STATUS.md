# VOLPAROSSA implementation status

This is the current execution index for the complete [DICN goal](development/GOAL.md),
including [DPS](development/GOAL.md#dps) and
[Studio/hosting](development/GOAL.md#studio). Use [AGENTS.md](../AGENTS.md)
for engineering boundaries and the [development workflow](development/CODEX_WORKFLOW.md)
for scoped execution. A milestone does not reduce the agreed goal.

[Current work](#current-integration-and-active-work) ·
[Priorities](#execution-priorities-and-next-milestones) ·
[Retained work](#retained-branches-and-resumption-dependencies) ·
[Trial records](#detailed-trial-records) · [Historical evidence](#historical-evidence-index) ·
[Completion](#definition-of-done)

## Current integration and active work

| Workstream | Recorded checkpoint; next boundary |
| --- | --- |
| Network | Two independent runners built identical Core and DNS worker packages at `428e2899`. Both passed A01–A15 and the Debian 13 install, upgrade and removal trial. One 32 MiB mixed-link transfer measured 1.437× the WAN-only throughput. The earlier trial measured 0.972×. [Acceptance and packages](status/network.md#network-baseline-and-remaining-proof) · [Both mixed-link runs](https://github.com/VOLPAROSSA/volparossa/pull/439) |
| Storage / Image / Cloud | The real Immich album recovered from peer storage after one provider went offline. OpenCloud passed both direct upload and owner recovery of an interrupted upload before two cold browser downloads. An earlier combined run reached Image repair. On `200d58c5` the twelve-node trial reached Cloud FINALIZE after Image publication. Both owners confirmed deletion. The separate Core lifecycle recorded zero provider usage. Usage for the failed application deposits was unmeasured. Joint repair and cold restoration remain open. [Storage trials](status/storage.md#storage-consumer-and-provider-evidence) |
| Protected Compute | Public two-turn execution and corruption rejection passed. A two-path trial authenticated the provider’s refusal when the protected device was unavailable. Hardware-backed private workload execution remains open. [Verified trial](status/applications.md#protected-compute-evidence) |
| Studio | The native Silex desktop saved a page with a unique visible edit, reopened it in two fresh processes and quit normally on protected Studio main. In a separate trial, Firefox rendered the signed Silex export from a holder while the publisher was offline. Joining the native desktop export to that hosting path remains open. [Native desktop](https://github.com/VOLPAROSSA/volparossa-studio/actions/runs/44547586924) · [Independent hosting](https://github.com/VOLPAROSSA/volparossa/actions/runs/44384131952) |
| DPS / Map | On the real Monaco graph, synthetic signed traffic advisories changed a driving route from 1,083.24 m to 3,746.96 m. Expiry and replacement each restored the original geometry. The native desktop compared 1,489 expiry frames and 15 removal frames. Field positioning accuracy and mobile peer routing remain open. [Native traffic trial](https://github.com/VOLPAROSSA/volparossa-map/actions/runs/44539811197) |
| Cache / Weather | The Android 16 emulator and iPhone 16 Pro Max simulator each hid the expired ECMWF forecast, displayed a failed refresh and recovered after a second request. On iOS the source temperature was 7.115 °C. The four screenshots record the original display precision. NOAA remained available through the cycle. Physical-device validation remains open. [Android receipts](https://github.com/VOLPAROSSA/volparossa-weather/tree/3d1e6384a2ced86e3239598cac2173c5ff0696b8/docs/evidence/android-44514675704) · [iPhone trial and screenshots](https://github.com/VOLPAROSSA/volparossa-weather/actions/runs/44542699817) |
| Code / Browser AI | Two tabs in a source-built Firefox each downloaded 32 MiB over protected connections. Detaching one preserved the other. The coding, cooperative job and protected inference trials have separate acceptance criteria. [Native browser trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44434221054) |
| Transactions / Bank | Four validators preserved 100 TEST units across partitions, restart and replay. In a separate signed auction, independent readers can recalculate the indicative price from a frozen roster and fictitious limit orders. Full finality coverage, funding and external settlement remain open. [Validators](https://github.com/VOLPAROSSA/volparossa/actions/runs/44426288636) · [Auction reader](https://github.com/VOLPAROSSA/volparossa-bank/blob/6e234caf6d13eb37b58e192e57d52d2cc6c49fee/docs/PAPER_AUCTION.md) |
| Mail | The ordinary paired sender delivered 429 MIME bytes through two independent local provider stores. Stalwart lost its import reply and restarted. A retry found the same email and verified every byte before both providers acknowledged. A fresh Thunderbird profile opened its subject and body over implicit TLS. Public Internet receipt and protected multi-node Mail transport require separate trials. [Peer and Inbox receipt](development/evidence/mail-owner-44547309790/peer-mail.json) · [Complete Mail trial](https://github.com/VOLPAROSSA/volparossa-mail/actions/runs/44547309790) |
| Chat | Two standalone Signal Desktops exchanged a message while each correspondent was offline in turn. One Core client carried their traffic through the protected twelve-node topology to two independent providers. The recipient reopened its SQLCipher profile, the sender observed Delivered and both provider inboxes emptied. Separately, automatic delivery survived a worker restart on local provider sockets. [Protected transport and captures](https://github.com/VOLPAROSSA/volparossa/actions/runs/44538844389) · [Automatic delivery](https://github.com/VOLPAROSSA/volparossa-chat/actions/runs/44548794182) |
| Citizen | An independent protected client received all 28,782 public referendum bytes from a peer with zero origin bytes. Citizen ran Belenios 3.3.0 offline on that exact ZIP and independently retained setups. The three fictional proposals were adopted, indeterminate and rejected. Real-person eligibility and recognized deployment remain open. [Peer retrieval and ballot replay](https://github.com/VOLPAROSSA/volparossa/actions/runs/44525516565) |
| Other applications / maintenance | Continue every agreed integration and organization-wide work; component/source checks do not complete consumer scenarios. |

### Execution priorities and next milestones

Choose complete executable slices by shared dependency, demonstrated failure and
system value; these priorities impose no fixed application/model/agent order.

1. **Storage.** Complete the cross-application Image and Cloud maintenance run
   through repair, cold restore, deletion and zero provider usage. Keep that
   multi-application result distinct from the successful direct Cloud upload.
2. **Protected model.** Build on the verified public resident session. Private
   execution requires separately authorized inputs and its own acceptance proof.
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

### Retained branches and resumption dependencies

The owner-designated central build chat maintains the current work across repositories. The organization queue links to the open work and the protected project goal records its mandate. For local checkout paths, use `git worktree list` in the selected repository. [Organization maintenance](https://github.com/VOLPAROSSA/.github/blob/main/MAINTENANCE.md) · [Project goal](development/GOAL.md)

The automatic upload candidate continues in Core #279. The resident model trials retain their source-specific workflow revisions and original outcomes. The October index preserves the earlier branches, machine-local paths and failed trials as historical evidence. [Upload candidate](https://github.com/VOLPAROSSA/volparossa/pull/279) · [Resident model evidence](status/applications.md#protected-compute-evidence) · [October checkout index](https://github.com/VOLPAROSSA/volparossa/blob/425b888963243259bc269f8c8d30513660df3095/docs/IMPLEMENTATION_STATUS.md#retained-branches-and-resumption-dependencies)

## Detailed trial records

Open the section for the capability you are changing. Each record retains the tested source, results, failures and remaining dependencies.

- <a id="development-branches--18-november-2026"></a>[Cross-repository development trials](status/applications.md#development-branches--18-november-2026)
- <a id="native-firefox-ordinary-tabs"></a>[Two native Firefox transfers](status/applications.md#native-firefox-ordinary-tabs)
- <a id="core-project-website--2026-10-30"></a>[Website and asset checks](status/applications.md#core-project-website--2026-10-30)
- <a id="f04--helperacceptatie-en-integratie-geslaagd--2026-10-27"></a>[F04 privileged helper acceptance](status/network.md#f04--helperacceptatie-en-integratie-geslaagd--2026-10-27)
- <a id="development-workflow--2026-10-26"></a>[Development workflow history](status/applications.md#development-workflow--2026-10-26)
- <a id="storage-consumer-and-provider-evidence"></a>[Storage trials, failures and receipts](status/storage.md#storage-consumer-and-provider-evidence)
- <a id="automatic-upload-integration-candidate"></a>[Finite upload and lifecycle dependencies](status/storage.md#automatic-upload-integration-candidate)
- <a id="protected-compute-evidence"></a>[Protected Compute trials](status/applications.md#protected-compute-evidence)
- <a id="studio-and-shared-hosting-evidence"></a>[Authoring and hosting trials](status/applications.md#studio-and-shared-hosting-evidence)
- <a id="decentralized-positioning-system--2026-10-21"></a>[DPS acceptance and pending field work](status/applications.md#decentralized-positioning-system--2026-10-21)
- <a id="map-weather-and-application-evidence"></a>[Map and Weather trials](status/applications.md#map-weather-and-application-evidence)
- <a id="latest-completed-integration-evidence"></a>[Code, Weather and Transaction checkpoints](status/applications.md#latest-completed-integration-evidence)
- <a id="network-baseline-and-remaining-proof"></a>[Network acceptance and Debian package receipts](status/network.md#network-baseline-and-remaining-proof)

## Fixed alpha v1 scorecard

The frozen original twenty-row, 100-point criteria and AV1/A01–A15 definitions
remain in the [preserved scorecard](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md#fixed-alpha-v1-scorecard).
Its pre-vertical 11/100 value is historical, not today's score. Later accepted
same-build v1 execution is recorded above; no new full-goal percentage is assigned
by reorganizing documentation. Functional extensions remain required regardless
of that baseline milestone.

## Historical evidence index

Reorganized: 2026-10-26; evidence reconciled: 2026-10-27. Technical evidence
combines the recorded 2026-10-23 checkpoint at `89d3aea585ed` with the
[PR343 evidence supplement](archive/integration-evidence-pr343-20261023.patch.txt)
at `a52ab4e77184`. That supplement preserves the original source/tree bindings,
artifact IDs, digests and failures without restoring obsolete workflow instructions.
The reconciliation refreshed GitHub run/job metadata for four formerly pending
runs on 2026-10-27. Their artifacts were not revalidated at that time.
That documentation reconciliation ran no new product trial. Refresh relevant branch/check ownership before
resuming; an old source result does not establish current composition acceptance.

The [historical ledger](https://github.com/VOLPAROSSA/volparossa/blob/89d3aea585ed8a1e4d7db3beac76846d3d3e2dc1/docs/IMPLEMENTATION_STATUS.md) preserves the previous
1,424,479 bytes unchanged, including original source revisions, run/artifact IDs,
digests, failures and scorecard. Its dated model assignments, session status and
procedural instructions are historical; current AGENTS/workflow supersede them.
The [local source archive](archive/requirements-20261023/README.md) retains the
original bytes for offline inspection. Read only evidence relevant to the task.

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
