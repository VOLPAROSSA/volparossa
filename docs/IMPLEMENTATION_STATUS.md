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
| Protected Compute | Public two-turn execution and corruption rejection passed. Two selected paths previously carried an authenticated refusal when the secure device was absent. No approved two-node AMD SEV-SNP setup is currently available for the private execution trial. [Protected Compute evidence](status/applications.md#protected-compute-evidence) |
| Studio | On Studio `3ce07136` and Core `6924fe8b`, a native Silex edit produced five signed site assets in nine chunks. With the publisher stopped, two fresh Firefox processes rendered the edit and its chart. The independent holder supplied 2,358,929 bytes and the origin supplied zero. Owner authorization, rollback and dynamic hosting still need their own integrated trials. [Combined desktop and hosting run](https://github.com/VOLPAROSSA/volparossa-studio/actions/runs/45505780043) · [Original reports](https://github.com/VOLPAROSSA/volparossa-studio/blob/e26c188060008853312e6869bc8d74eaf7a97db1/docs/evidence/native-webview/45505780043/reports.zip) |
| DPS / Map | Map `426ca252` passed five foreground cases in the installed Android x86_64 emulator app. The My Position panel warned about a recent simulated fix and withheld its numerical estimate. Two cold offline walks measured 390 m and 490 m. On Monaco the signed-advisory desktop trial independently demonstrated rerouting, expiry and recovery. Field positioning accuracy remains open. [Integrated device ABI](https://github.com/VOLPAROSSA/volparossa/pull/464) · [Android trial](https://github.com/VOLPAROSSA/volparossa-map/actions/runs/45507438201/attempts/2) · [Traffic trial](https://github.com/VOLPAROSSA/volparossa-map/actions/runs/44539811197) |
| Cache / Weather | After forecast expiry, the installed app refused stale Weather data and kept NOAA air quality available. The second refresh restored the signed forecast. The Android 16 and iPhone 16 Pro Max simulator trials used a −0.154 °C forecast. Both original receipts are archived. Physical-device validation remains open. [Android receipts and APK identity](https://github.com/VOLPAROSSA/volparossa-weather/tree/92bab93ec8d44accd6d02806741ea7a282e0ed9a/docs/evidence/android-45408377786) · [Five iPhone screenshots and receipt](https://github.com/VOLPAROSSA/volparossa-weather/tree/673dbd0940ec00241a0e23b7fadf6a9fba641e20/docs/evidence/iphone-signed-45510360656) |
| Code / Browser AI | The installed VSCodium extension enrolled one owner-selected public file. A peer returned the replacement. The owner approved the edit and the check separately, and an independent check passed using the original tests. The local OpenCode planner still needs its own end-to-end result. Two source-built Firefox tabs each downloaded 32 MiB over protected connections and detaching one preserved the other. Long-running cooperative job reconciliation remains open. [VSCodium trial and receipts](COOPERATIVE_CODE.md#public-peer-coding-in-the-native-vscodium-workbench) · [Native Firefox trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/44434221054) |
| Transactions / Bank | Four validators committed a 70 TEST payment and released a separate 10 TEST reservation on its owner’s signed cancellation. After restart they replayed the same signed bytes and retained all 100 TEST units. In a separate signed auction, independent readers can recalculate the indicative price from a frozen roster and fictitious limit orders. Full finality coverage, funding and external settlement remain open. [Cancellation and replay](status/applications.md#bank-owner-cancellation) · [Auction reader](https://github.com/VOLPAROSSA/volparossa-bank/blob/6e234caf6d13eb37b58e192e57d52d2cc6c49fee/docs/PAPER_AUCTION.md) |
| Mail | Two independent Core clients took turns offline. Two providers retained the encrypted message until the recipient recovered all 90,139 MIME bytes in Stalwart. Both providers signed the acknowledgements, and the next fetch was empty. The protected-main repeat on `e5daf201` reproduced the delivery, acknowledgements and empty next fetch. A separate trial covered Thunderbird. Public Internet reception remains open. [Native Mail trials](status/applications.md#paired-mail-delivery) · [Original Mail archives](https://github.com/VOLPAROSSA/volparossa-mail/tree/bd8aa04a29bc250284da0ba2d6fe5883cd8d60de/docs/evidence) |
| Chat | Two standalone Signal Desktops exchanged a message while each correspondent was offline in turn. One Core client carried their traffic through the protected twelve-node topology to two independent providers. The recipient reopened its SQLCipher profile, the sender observed Delivered and both provider inboxes emptied. Automatic delivery survived a worker restart on local provider sockets. The joint routed worker trial reached native import and then stopped during confirmation. [Protected transport and captures](https://github.com/VOLPAROSSA/volparossa/actions/runs/44538844389) · [Automatic delivery](https://github.com/VOLPAROSSA/volparossa-chat/actions/runs/44548794182) · [Routed worker trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/45517291030) |
| Citizen | A protected client fetched all 28,782 referendum bytes from a peer with zero origin bytes. Offline Belenios replay verified all three fictional outcomes against retained setups. In a separate trial on the tree merged as Citizen `1c8e6fc3`, four fictional voters prepared encrypted ballots. The final count confirmed the three submitted trackers and reported the fourth absent. Citizen `f28c7988` bound the count of six eligible residents to the independently retained opening. Four yes votes met the threshold. A post-close override to seven was refused. Real-person eligibility and recognized deployment remain open. [Peer retrieval and replay](https://github.com/VOLPAROSSA/volparossa/actions/runs/44525516565) · [Independent voter trial](https://github.com/VOLPAROSSA/volparossa-citizen/actions/runs/45408384173/job/138495180143) · [Opening and tally](https://github.com/VOLPAROSSA/volparossa-citizen/actions/runs/45520183577) |
| Other applications / maintenance | On Core `ad7748b7` an independent holder returned the enrolled 506-byte Git bundle after the publisher copy was removed. An empty bare repository restored the two pinned commits and passed strict Git object checks. Independent proposal review, release authority, update distribution and rollback across repositories remain open. [Source-recovery run](https://github.com/VOLPAROSSA/volparossa/actions/runs/45509864506) · [Second recovery and archived receipts](https://github.com/VOLPAROSSA/volparossa/pull/481) |

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
scoped Compute and Browser integration. The current trials cover public source recovery and the local search index. The remaining
functional trials are specified in the [acceptance guide](development/TESTING.md#development-cycle-and-browser-acceptance).

### Retained branches and resumption dependencies

The owner-designated central build chat maintains the current work across repositories. The organization queue links to the open work and the protected project goal records its mandate. For local checkout paths, use `git worktree list` in the selected repository. [Organization maintenance](https://github.com/VOLPAROSSA/.github/blob/main/MAINTENANCE.md) · [Project goal](development/GOAL.md)

On Core `f176b1b7`, the combined Image and Cloud run reached the application exercise, where route binding failed on the seventh sample. The guest released its own test resources. Joint cold recovery, remote deletion and zero application-provider usage remain open. The earlier run exhausted route selection before either app started. On protected main, a restarted client now requires a newly signed discovery advertisement when the previous one is stale.
[Original restart failure](https://github.com/VOLPAROSSA/volparossa/actions/runs/45419750177) · [Current joint trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/45506380399) · [Storage candidate](https://github.com/VOLPAROSSA/volparossa/pull/279) · [Restart correction](https://github.com/VOLPAROSSA/volparossa/pull/476)

Map is checking its ARM64-only package on Android's native bridge. Studio's next candidate lets the owner review the frozen export and sign it in a separate terminal.
[Map ARM64 candidate](https://github.com/VOLPAROSSA/volparossa-map/pull/35) · [Studio owner review](https://github.com/VOLPAROSSA/volparossa/pull/475)

The real local OpenCode planner used the enrolled public tool. One owner-approved replacement and a separately approved check reached VSCodium. The combined driver stopped when reading the displayed result, before inspecting the final file. Firefox previously completed an answer with 21 workers and two cancellations. A later Firefox run recorded 111 valid samples and 289 completed flows, then reported an invalid control observation. Eight terminal receipts and two unresolved refinement jobs were retained.
[Initial Code tool trial](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/45507026680) · [Owner edit trial](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/45516150432) · [Firefox cancellation](https://github.com/VOLPAROSSA/volparossa/actions/runs/45506355803) · [Control observations](https://github.com/VOLPAROSSA/volparossa/actions/runs/45512806565)

On Core `bf6657a6`, one independent holder supplied all 45,056 bytes of the enrolled DeGoog index after the publisher state was removed. The downloaded file matched the original public export. In a separate network-isolated process, DeGoog 1.2.0 imported three entries, returned all three expected documents and made zero external requests. An altered index was refused. Firefox address-bar submission and the privacy of the generic HTTP search handler remain open.
[Original public export](https://github.com/VOLPAROSSA/volparossa-browser/actions/runs/45517799338) · [Peer recovery and native search](https://github.com/VOLPAROSSA/volparossa/actions/runs/45518350752)

Offline Compute generated two marked US English files and one Dutch file at 16 kHz. Each matched the independent PCM reference. Whisper small made zero word errors on both eight-word English round trips. A longer trial reproduced an intermittent cleanup failure on the seventeenth synthesis. After the Linux process-check correction, 32 consecutive syntheses produced identical marked audio and confirmed cleanup. Broader voice quality and hardware-backed confidential execution remain open.
[Combined speech trial](https://github.com/VOLPAROSSA/volparossa/actions/runs/45508315595) · [Reproduced cleanup failure](https://github.com/VOLPAROSSA/volparossa/actions/runs/45512520095) · [32-run repeat](https://github.com/VOLPAROSSA/volparossa/actions/runs/45515457352)

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
