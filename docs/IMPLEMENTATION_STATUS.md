# VOLPAROSSA implementation status

This is the current execution index for the complete [DICN goal](development/GOAL.md),
including [DPS](development/GOAL.md#dps) and
[Studio/hosting](development/GOAL.md#studio). Use [AGENTS.md](../AGENTS.md)
for engineering boundaries and the [development workflow](development/WORKFLOW.md)
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
| Storage / Image / Cloud | Immich recovered an album after provider loss. OpenCloud separately recovered an interrupted upload and served two cold downloads. In the combined twelve-node run on `648e204a`, each app published four fragments with two copies and 1,598,292 committed bytes. The exercise stopped while checking the physical storage charge after the authenticated Cloud read. Joint cold restoration, remote deletion and zero application-provider usage remain open. [Storage trials](status/storage.md#storage-consumer-and-provider-evidence) · [Combined run](https://github.com/VOLPAROSSA/volparossa/actions/runs/45408914106) |
| Protected Compute | Public two-turn execution and corruption rejection passed. A two-path trial authenticated the provider’s refusal when the protected device was unavailable. Hardware-backed private workload execution remains open. [Verified trial](status/applications.md#protected-compute-evidence) |
| Studio | The native Silex desktop saved a page with a unique visible edit, reopened it in two fresh processes and quit normally on protected Studio main. In a separate trial, Firefox rendered the signed Silex export from a holder while the publisher was offline. Joining the native desktop export to that hosting path remains open. [Native desktop](https://github.com/VOLPAROSSA/volparossa-studio/actions/runs/44547586924) · [Independent hosting](https://github.com/VOLPAROSSA/volparossa/actions/runs/44384131952) |
| DPS / Map | On the real Monaco graph, synthetic signed traffic advisories changed a driving route from 1,083.24 m to 3,746.96 m. Expiry and replacement each restored the original geometry. The native desktop compared 1,489 expiry frames and 15 removal frames. Field positioning accuracy and mobile peer routing remain open. [Native traffic trial](https://github.com/VOLPAROSSA/volparossa-map/actions/runs/44539811197) |
| Cache / Weather | The installed Android 16 app hid the expired ECMWF forecast, showed a failed refresh and recovered to signed revision 2 after the second tap. The source temperature for that run was −0.154 °C. NOAA remained available throughout. The iPhone 16 Pro Max simulator previously exercised the same expiry and recovery with a 7.115 °C forecast. Physical-device validation remains open. [Android receipts and APK identity](https://github.com/VOLPAROSSA/volparossa-weather/tree/92bab93ec8d44accd6d02806741ea7a282e0ed9a/docs/evidence/android-45408377786) · [iPhone trial and screenshots](https://github.com/VOLPAROSSA/volparossa-weather/actions/runs/44542699817) |
| Code / Browser AI | The installed VSCodium extension enrolled one owner-selected public file. A peer returned the replacement. The owner approved the edit and the check separately, and an independent check passed using the original tests. The local OpenCode planner still needs its own end-to-end result. Two source-built Firefox tabs each downloaded 32 MiB over protected connections and detaching one preserved the other. Long-running cooperative job reconciliation remains open. [VSCodium trial and receipts](COOPERATIVE_CODE.md#public-peer-coding-in-the-native-vscodium-workbench) · [Native Firefox trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44434221054) |
| Transactions / Bank | Four validators committed a 70 TEST payment and released a separate 10 TEST reservation on its owner’s signed cancellation. After restart they replayed the same signed bytes and retained all 100 TEST units. In a separate signed auction, independent readers can recalculate the indicative price from a frozen roster and fictitious limit orders. Full finality coverage, funding and external settlement remain open. [Cancellation and replay](status/applications.md#bank-owner-cancellation) · [Auction reader](https://github.com/VOLPAROSSA/volparossa-bank/blob/6e234caf6d13eb37b58e192e57d52d2cc6c49fee/docs/PAPER_AUCTION.md) |
| Mail | Two independent Core clients took turns offline. Two providers retained the encrypted message until the recipient recovered all 90,139 MIME bytes in Stalwart. Both providers signed the acknowledgements, and the next fetch was empty. A separate trial covered the Thunderbird sender and Inbox. Public Internet reception remains open. [Mail trials and receipts](status/applications.md#paired-mail-delivery) |
| Chat | Two standalone Signal Desktops exchanged a message while each correspondent was offline in turn. One Core client carried their traffic through the protected twelve-node topology to two independent providers. The recipient reopened its SQLCipher profile, the sender observed Delivered and both provider inboxes emptied. Separately, automatic delivery survived a worker restart on local provider sockets. [Protected transport and captures](https://github.com/VOLPAROSSA/volparossa/actions/runs/44538844389) · [Automatic delivery](https://github.com/VOLPAROSSA/volparossa-chat/actions/runs/44548794182) |
| Citizen | A protected client fetched all 28,782 referendum bytes from a peer with zero origin bytes. Offline Belenios replay verified all three fictional outcomes against retained setups. In a separate trial on the tree merged as Citizen `1c8e6fc3`, four fictional voters prepared encrypted ballots. The final count confirmed the three submitted trackers and reported the fourth absent. Real-person eligibility and recognized deployment remain open. [Peer retrieval and replay](https://github.com/VOLPAROSSA/volparossa/actions/runs/44525516565) · [Independent voter trial](https://github.com/VOLPAROSSA/volparossa-citizen/actions/runs/45408384173/job/138495180143) |
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

The central build chat will schedule four additions within the full goal as
their dependencies permit. Decentralized Git and update delivery depend on
replicated source, isolated builds and release authority. Sabotage review needs
independent decision history and recoverable trusted versions. DeGoog search
and the supplementary Consent-O-Matic list depend on verified public content,
scoped Compute and Browser integration. These are planned capabilities. Their
functional trials are specified in the [acceptance guide](development/TESTING.md#development-cycle-and-browser-acceptance).

### Retained branches and resumption dependencies

The owner-designated central build chat maintains the current work across repositories. The organization queue links to the open work and the protected project goal records its mandate. For local checkout paths, use `git worktree list` in the selected repository. [Organization maintenance](https://github.com/VOLPAROSSA/.github/blob/main/MAINTENANCE.md) · [Project goal](development/GOAL.md)

The combined Storage trial continues in Core #279 with Image #8 and Cloud #15.
On Core `29b82140` the restarted client exhausted twelve route selections before
either application started. Restore, repair, deletion and final provider usage
still need one successful joint run. [Restart trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/45419750177) · [Storage candidate](https://github.com/VOLPAROSSA/volparossa/pull/279)

The installed Android Map trial covered four foreground position cases and two
ordinary offline routes on the earlier Core ABI. The next trial will bind the
installed app to the integrated ABI. The Silex desktop producer exported five
files and signed the nine-chunk bundle. The combined Studio trial follows this
export through hosting with the publisher offline.
[Map evidence](https://github.com/VOLPAROSSA/volparossa-map/pull/31) · [Core ABI](https://github.com/VOLPAROSSA/volparossa/pull/464) · [Silex producer](https://github.com/VOLPAROSSA/volparossa-studio/pull/20) · [Hosting trial](https://github.com/VOLPAROSSA/volparossa-studio/actions/runs/45505780043)

The local coding planner rejected an unknown tool before public delegation. The
Firefox trial on `19fdeedb` reached a hierarchical answer and a second task's
cancellation. Its independent route binding check failed. The speech recognition
trial using Whisper small passed on the same clips on which tiny missed the
per-clip word-error target. Synthetic speech generation has its own open trial.
[Code planner](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/45425334685) · [Firefox](https://github.com/VOLPAROSSA/volparossa/actions/runs/45424897092) · [Recognition](https://github.com/VOLPAROSSA/volparossa/actions/runs/45427534478) · [Synthesis](https://github.com/VOLPAROSSA/volparossa/pull/468)

The [prior checkpoint](https://github.com/VOLPAROSSA/volparossa/blob/d212a0b7389a129db8454ea9c401c5bd0105d424/docs/IMPLEMENTATION_STATUS.md#development-pause-on-24-november-2026)
and [October checkout index](https://github.com/VOLPAROSSA/volparossa/blob/425b888963243259bc269f8c8d30513660df3095/docs/IMPLEMENTATION_STATUS.md#retained-branches-and-resumption-dependencies)
retain the original sources, trial results and resumption details.

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
