# Golden Harbour Core page — content and evidence notebook

Reviewed 30 October 2026 against Core commit
`edf569300acbdf5e7715b5192ffbb293235b15ab` (the clean checkout and current main
revision supplied by the coordinating agent). This is a read-only source review;
no Core, sensor, network, model or financial trial was run. Historical tests below
remain evidence only for their recorded revisions and scopes.

The uploaded BUILD-INSTRUCTIONS.txt was read in full, together with SOURCES.txt,
ASSET-BRIEF.txt and START-HERE.txt. The newer direct user request explicitly asks
for publication; the attachment's older review-only wording is not a new user
restriction. Publication authority remains with the coordinating agent.

## Editorial conclusion

The proposed headings and concise copy fit the current architecture when their
development labels remain visible. There is no supported end-user release.
Architecture, limited working trials and completed products must stay distinct.

Use the compact implementation status as the current evidence index. README's
dated “20 October” summary predates subsequent status reconciliation, and its
public-model failure is no longer the latest feature-run metadata. Do not copy
its old “latest trial” language onto the site. Avoid milestone numbers entirely
on this visual introduction; link “Explore the evidence” to the current index.

One compatible Core per device is the **intended integration architecture**;
complete multi-app isolation/lifecycle acceptance remains open. Prefer “Designed
around one compatible background Core per device…” to a present-tense assertion
that all integrations already share it successfully.

“Privacy-preserving positioning” is required visible HTML and is accurate as a
design ambition alongside “Research & development”. Do not imply guaranteed or
certified anonymity, finished sensor fusion, or measured navigation improvement.

## Ready-to-use English copy

The exact requested headings, hero text and three app summaries can be used as
provided. The following supplementary copy keeps the technical boundaries short.

### Shared five-layer introduction

**Architecture in development**

“These five layers describe a shared architecture in development. Individual
milestones have been tested; they are not yet five released services.”

Use the exact short labels from the brief, with one consistent native details
pattern for the following descriptions and source links:

| Layer | Short label | Accessible expansion |
| --- | --- | --- |
| Network | Connect participating devices. | Useful parallel routes connect participants through different relays. Each normal Internet path keeps one relay between the client and exit. |
| Cache | Reuse eligible public content. | Reuse verified public content when its source and permissions allow sharing. Private files and arbitrary encrypted web traffic do not become shared cache entries. |
| Storage | Keep encrypted private files recoverable. | Applications encrypt files before sharing fragments and recovery copies. Owners keep their recovery keys; providers hold ciphertext. Complete maintenance and application recovery remain in development. |
| Compute | Share suitable work and models. | Divide suitable tasks, combine results and reuse permitted models. Confidential execution of private work on other participants' devices remains unfinished. |
| Transactions | Record authorized test transfers. | Explore authorized transfers and durable accounting with fictitious test value. This is not a live banking or payment service. |

If illustrating exact transport paths rather than decorative harbour activity,
use client → exactly one relay → exit → destination; parallel routes use different
relays and the same selected exit. Keep the harbour's arcs explicitly illustrative
and do not introduce a controlling central node. DPS uses these five layers and
is not a sixth infrastructure layer.

### Applications strip

“Designed around one compatible background Core per device, shared by multiple
applications. Other participants run their own Core, with their own resources
and permissions.”

Use the exact three requested summaries, with “Integration in development” and
“Project repository · GitHub” visible for unpublished app destinations:

- Code — Built on OpenCode — “Coding workflows and cooperative AI.”
- Image — Built on Immich — “Your photos, with a shared storage foundation.”
- Cloud — Built on OpenCloud — “Files and collaboration across a shared network.”

No blanket server-independence claim follows from the scoped Image snapshots or
OpenCloud recovery trials. The current homepage registry marks all three
`published: false`, so their Explore links should use their real GitHub repositories.
Keep upstream marks and notices from the reviewed homepage export; this review
does not establish trademark permissions or partnerships.

### Cooperative intelligence

Use the brief's body and “In development” badge:

“VOLPAROSSA is being developed to let devices share suitable work, reuse models
and learn from measured outcomes. The aim is to make a modest device an entry
point to shared capabilities.”

Follow with:

“Suitable tasks can be divided and their results combined. Shared learning uses
permitted data, with evaluation and correction as part of development. Private
prompts, files and results are not automatically shared training material.”

“Confidential execution of private tasks on other participants' devices is still
in development.”

Keep the first supplementary sentence within the section's clear development
framing; it describes the architecture, not general task reliability. A local
coding result is not evidence for protected distributed private execution.

### DPS

Use the requested hierarchy exactly:

- Eyebrow: “DPS — Decentralized Positioning System”
- H2: “Find your way, together.”
- Prominent subheadline: “Privacy-preserving positioning”
- Badge next to the explanation: “Research & development”

“DPS is being developed to combine satellite signals, nearby devices and local
sensors, with explicit permissions and clear uncertainty. The goal is to improve
positioning while keeping precise locations and movement history private.”

Use the three exact points from the brief. A compact further explanation, either
in the section or an accessible details element, should retain these boundaries:

“Receiving positioning help, accessing sensors, contributing measurements,
retaining history and training models each need separate permission. Joining
the network does not authorize sharing your precise location or movement history.”

“The current prototype assesses supplied position claims. Real sensor fusion,
navigation and measured accuracy remain in development. Relative position does
not establish an absolute location, and agreeing or signed claims do not prove
geographic truth. Privacy is a design goal, not a guarantee of anonymity.”

The page itself should request no location, sensor or radio access. The artwork
and any diagram points are fictional illustrations, not a visitor-location map.

### Participation and closing

Use the exact requested heading/body and this compact explanation:

“Participation is voluntary. Joining the network means accepting its
resource-sharing responsibilities.”

“Participation requires explicit activation. Your own device use takes priority.
Shared storage calls for a matching usable contribution, including recovery
copies and overhead. No payment is required to participate.”

An optional details sentence can be added if space permits:

“Participants contribute according to available capabilities. Devices with an
independent Internet connection also provide authorized exit service; local-only
devices contribute local links and relay capacity.”

This explains the required participation model, not completed automatic storage
accounting. Do not equate an offered disk quota with verified usable contribution.

## Documentation destinations

All repository paths below exist at the audited commit. For maintenance-friendly
visitor links, `blob/main/` is appropriate; the exact audit source is pinned here.
The proposed central portal fragments must be created in the homepage PR before
the Core page links to them.

| Use | Destination |
| --- | --- |
| Core portal | `https://volparossa.org/docs/#core` only after a real `id="core"` exists |
| DPS portal | `https://volparossa.org/docs/#dps` only after a real `id="dps"` exists |
| General documentation | `https://volparossa.org/docs/` |
| Core architecture / Network source | `https://github.com/VOLPAROSSA/volparossa/blob/main/docs/architecture/ARCHITECTURE.md` |
| Cache source | `https://github.com/VOLPAROSSA/volparossa/blob/main/docs/services/CONTENT_NETWORK_PROPOSAL.md` |
| Storage source | `https://github.com/VOLPAROSSA/volparossa/blob/main/docs/services/PRIVATE_STORAGE.md` |
| Compute source | `https://github.com/VOLPAROSSA/volparossa/blob/main/docs/services/DECENTRALIZED_AGENTS.md` |
| Transactions source | `https://github.com/VOLPAROSSA/volparossa/blob/main/docs/services/TRANSACTION_LAYER.md` |
| Visible DPS fallback | `https://github.com/VOLPAROSSA/volparossa/blob/main/docs/services/DPS.md` |
| Start contributing | `https://github.com/VOLPAROSSA/volparossa/blob/main/CONTRIBUTING.md` |
| Explore the evidence | `https://github.com/VOLPAROSSA/volparossa/blob/main/docs/IMPLEMENTATION_STATUS.md` |
| Application architecture | `https://github.com/VOLPAROSSA/volparossa/blob/main/docs/architecture/APPLICATION_LIFECYCLE.md` |
| Code | `https://github.com/VOLPAROSSA/volparossa-code` |
| Image | `https://github.com/VOLPAROSSA/volparossa-image` |
| Cloud | `https://github.com/VOLPAROSSA/volparossa-cloud` |

Use “View on GitHub” in the central portal and a visible “DPS source on GitHub”
fallback beside “Explore DPS”. Do not present GitHub Markdown as centrally
rendered documentation. Existing site privacy/accessibility/credits destinations
can remain shared; hosting logs must not be denied by a blanket no-data claim.

## Claim-to-source map

Line references are at audited commit `edf569300acbdf5e7715b5192ffbb293235b15ab`.

| Claim / boundary | Source and lines | Evidence decision |
| --- | --- | --- |
| Developing shared Core, no supported release | `README.md:39–44,70–82`; `docs/community/OVERVIEW.md:3–19` | Keep Development preview; no install/download promises. |
| Exactly five distinct layers | `README.md:126–140`; `docs/development/GOAL.md:20–24,113–124` | Architecture labels, no six-layer DPS model. |
| One relay per ordinary Internet path | `docs/development/GOAL.md:21–22`; `README.md:144–210`; `docs/privacy/PRIVACY.md:27–31` | Parallel paths use different relays; no direct client-to-exit design. |
| Public cache authority, no arbitrary TLS interception | `README.md:217–250`; `docs/privacy/PRIVACY.md:56–88`; `docs/architecture/APPLICATION_LIFECYCLE.md:59–67` | Cache only eligible public content; keep private storage separate. |
| Encryption before storage; owner keys; recovery copies | `docs/services/PRIVATE_STORAGE.md:7–14,27–43,63–109` | Encrypted fragments and recovery are scoped milestones; not a complete cloud service. |
| Reciprocal usable contribution includes copies and overhead | `docs/services/PRIVATE_STORAGE.md:114–140,188–217`; `docs/development/GOAL.md:341–345` | Automatic accounting/placement/downscaling remain incomplete. |
| Suitable work, shared models, outcome evaluation | `docs/services/DECENTRALIZED_AGENTS.md:8–16,32–45`; `docs/development/GOAL.md:347–353` | Development architecture; do not promise better AI from peer count. |
| Private prompts/files/results not default training | `docs/services/DECENTRALIZED_AGENTS.md:1672–1686,1731–1736`; `docs/development/GOAL.md:363–368` | Permission and protection remain separate from transport encryption. |
| Protected private peer computation unfinished | `docs/services/DECENTRALIZED_AGENTS.md:14–16,1682–1686`; `docs/IMPLEMENTATION_STATUS.md:170–220,292–297` | Local public coding workflow is not protected private network proof. |
| Test transactions only | `docs/services/TRANSACTION_LAYER.md:9–13,108–141,293–307`; `docs/IMPLEMENTATION_STATUS.md:303–308` | Fictitious TEST units; no real assets, banking or settlement. |
| Shared Core per device is intended | `docs/architecture/APPLICATION_LIFECYCLE.md:3–12,24–44,69–90` | Phrase as designed architecture; full multi-app permissions/lifecycle proof open. |
| Code / Image / Cloud scopes | `docs/applications/APPLICATIONS.md:78–110,145–154`; `docs/IMPLEMENTATION_STATUS.md:88–98,124–168,290–297` | Keep Integration in development; upstream foundations are exact. |
| DPS uses the five layers | `docs/services/DPS.md:7–15,174–195`; `docs/development/GOAL.md:28–32,113–124` | Shared service, no payment dependency or sixth layer. |
| DPS multiple sources, privacy and uncertainty goals | `docs/development/GOAL.md:34–111`; `docs/services/DPS.md:17–24,146–195` | Research & development; no anonymity or hardware-support guarantee. |
| Supplied claims are not geographic truth | `docs/services/DPS.md:26–37,48–81,110–144`; `docs/IMPLEMENTATION_STATUS.md:268–288` | Synthetic assessment and debug JNI do not establish actual position/sensor/navigation capability. |
| Separate assistance/sensor/contribution/history/training permissions | `docs/services/DPS.md:19–24,182–195`; `docs/applications/APPLICATIONS.md:189–200` | Network participation grants none of them. |
| Explicit participation, voluntary entry and reciprocal roles | `AGENTS.md:36–51`; `README.md:203–210`; `docs/architecture/APPLICATION_LIFECYCLE.md:31–44` | Installation activates no participation; avoid implying client-only production consumption. |
| Owner priority, no payment prerequisite | `docs/development/GOAL.md:351`; `README.md:492–495`; `docs/community/SUPPORTING.md:3–15` | Resource-sharing responsibilities remain; monetary support is optional. |
| Contribution route and exact evidence | `CONTRIBUTING.md:1–14,16–31,50–71`; `docs/README.md:33–64,130–139` | Link guides and current status; no new test claims from this website review. |

## Source blob identities

The full commit above pins the complete source set. These blobs identify the main
content inputs for later comparison:

| Path | Git blob SHA |
| --- | --- |
| `README.md` | `9c491e7a6f28ed38bfa9ae36b966f04d7f7722c7` |
| `docs/development/GOAL.md` | `f7e18bea4c1b014cb7bf24570267497081f58ecc` |
| `docs/IMPLEMENTATION_STATUS.md` | `889c7be7cbb1a557b5f2cf25ed775285f825dfc5` |
| `docs/README.md` | `e6419530c40f0dca4050fb3c41a8d859dc2aa23d` |
| `docs/architecture/APPLICATION_LIFECYCLE.md` | `72cd24d9c3ef9a869b0565ba23f2c7448e570a69` |
| `docs/services/DPS.md` | `1f9bdbb49a36f1567ebf876409f41e80a884d475` |
| `docs/services/PRIVATE_STORAGE.md` | `ecaabea156c958baf9e9bdff39499703dd153691` |
| `docs/services/DECENTRALIZED_AGENTS.md` | `7e301e1d250a1f1b62ba8dd6098be5c91f1c72d4` |
| `docs/services/TRANSACTION_LAYER.md` | `56e1db695a6b79bd6294629a4d98355da629f316` |
| `docs/privacy/PRIVACY.md` | `b666c9a47bd9a6dfbde0feebcc22255c3e7455ad` |
| `docs/applications/APPLICATIONS.md` | `5475b1471d3b26aa7dc486f964d26d525f8e6923` |
| `CONTRIBUTING.md` | `6b8add8ce6286fa65431b521d10e0c2f4add710f` |

No public capability conflict was found in the brief when these qualifications
are retained. The only editorial correction needed is careful intended-versus-
completed wording around the common app service and avoidance of stale README
“latest” trial claims. Retain the supplied exact privacy subheadline and the
development labels rather than diluting either.
