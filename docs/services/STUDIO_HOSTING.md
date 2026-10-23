# Studio, shared website publishing and hosting

The complete [Studio/hosting requirements](../development/STUDIO_HOSTING_REQUIREMENTS.md)
are a permanent part of [GOAL](../development/GOAL.md), alongside DPS and every
previous amendment. This page records architecture, provenance and verification
work. It does not replace the normative text or overstate runtime acceptance.

## Current bounded runtime evidence — 2026-10-23

Hosted run `39869460125` used pinned Silex
`672efed69dda04c0a1e968859239e042f00d9538`, Studio `eaf9e336e003b7cab8f384271560b182aee464ae`
and Core `dfa6f3434bb9f7fe07c4fff2bacfc0042780faa7`. It passed a bounded browser
edit/preview/export-to-Core fixture: a real page, native text drag, keyboard marker
edit and 37px style edit, preview, and actual ZIP download flowed through safe extraction into the real Core
pack CLI and production bundle decoder. All four assets, hashes, lengths, edited HTML/CSS markers
and no-clobber rejection were verified. The [Core execution ledger](../IMPLEMENTATION_STATUS.md#current-integration-and-active-work)
retains the receipt, checks, source composition and cleanup evidence.

This proves in-memory page-model serialization, not saved-project reload or durable
project storage. Cleanup covers the owned fixture groups and temporary outputs, not a
complete independent host-absence or cancellation/crash audit. The fixture does not
accept native desktop review, signing, external hosting, independent browser retrieval,
publisher-offline retention, shared AI or dynamic execution; all fifteen complete
Studio acceptance cases remain open.

## Audited starting point — 2026-10-22 (historical)

Core source: `96f81fdd506a72533f11a7c5b4891ac15ff62320`, tree
`adf2400fe4832d2551d71361f284b94032becb1d`. The initial
[Studio repository](https://github.com/VOLPAROSSA/volparossa-studio/tree/97ddafa6a317e151c1352e0ac61978ddc3bd79f0)
at this initial baseline contained only README and the GPLv3 license text. Those
statements describe the starting state before the later fixture and integration.

| Existing Core facility | Reuse and evidence boundary |
| --- | --- |
| Signed chunks/manifests, explicit `content publish`, contribution handoff | Existing identity, original expiry, bounded object/cache and explicit public-content authority. A local signed object is not a published website. |
| `content site pack` / `site open` | Existing bounded site format, named retrieval and immutable local HTTP viewer; implementation in `crates/volparossa-content/src/site.rs` and `crates/volparossa/src/content/site/`. Pack is offline; the current 256-file/256-MiB bounds are implementation limits, not permanent product requirements. |
| Named publications and durable revision/conflict floors | Reuse publisher-key/name identity and anti-replay checks. They do not establish DNS ownership, a globally freshest revision or atomic fleet-wide rollout. |
| Protected discovery/retrieval | Reuse existing agent interfaces and relay/exit boundaries. A Studio frontend receives no general administrative socket, direct-exit permission or arbitrary network egress. |
| Public custody deposit/inspect and `content retain` | Existing signed observations, expiry, quota and cumulative upload budgets; owner-driven replacement. Prior bounded trials do not establish maintenance after the controller stops or universal availability. |
| Private Storage | Reuse authorized encrypted storage for drafts/project history, with the same Core redundancy/recovery policy. Public publication is a separate explicit transition. |
| Shared Compute and Code/OpenCode | Reuse model backend, task scheduling, cancellation and worker authority. Public model trials and local MCP calls do not establish protected private distributed editing. |

The [content-network guide](CONTENT_NETWORK_PROPOSAL.md#native-public-publishing-and-websites)
retains original trial links: `34214732165` covers cache-only site reopening with
actual HTTP requests, not a browser engine; `35916493141` and `35921884371` cover
bounded holder replacement and a fresh named download after publisher source/owner
removal, with the Client node still online. These are historical source-scoped
receipts, not rerun Studio acceptance. [Operations](../development/OPERATIONS.md#native-static-websites)
describes the actual commands and limits. The current viewer blocks forms, frames,
external requests, service workers and persistent origin storage. Do not weaken
that sandbox merely to call a Silex export compatible; conventional website and
dynamic modes need explicit, separately verified origin/execution boundaries.

Missing work includes a production desktop editor-to-Core publication adapter,
independent public browser rendering, identity/domain/TLS integration, authorized
atomic update/rollback and withdrawal, continuity of retention when the
publisher/controller is offline, measured independent replica health and repair/fairness, protected shared AI and
dynamic execution with durable private state. All remain unfinished.

## Silex source selection and interfaces

Select released **Silex v3.9.0**, exact commit
[`672efed69dda04c0a1e968859239e042f00d9538`](https://github.com/silexlabs/Silex/tree/672efed69dda04c0a1e968859239e042f00d9538),
as the reproducible initial adapter baseline. The release API reports publication
on 2026-07-26. Current upstream main was separately inspected at
`1fe592fbf7d06ec242c97be53e32cfb30884704d`; do not float to it or an unpinned package.
This selection initially followed source/interface/license inspection, not a
successful build, full dependency audit or security approval. The later hosted
fixture built and ran this pinned Silex source; it does not amount to a full
dependency audit or security approval. No upstream executable was installed on
the development host. Studio's `upstream.lock.json` records this selection and
inspected blob identities.

Primary source references at that revision:

- [README](https://github.com/silexlabs/Silex/blob/672efed69dda04c0a1e968859239e042f00d9538/README.md): GrapesJS visual editor, HTML/CSS/JS editing and portable static export, CMS/11ty integration, plugins, and OpenCode/MCP setup. Some desktop prose still says “coming soon” while it also links an alpha; use code/release evidence, not a general maturity claim.
- [Package](https://github.com/silexlabs/Silex/blob/672efed69dda04c0a1e968859239e042f00d9538/package.json): Node >=24, pnpm 10.34.4, TypeScript 6.0.3; package version is a development placeholder, so the tag/commit defines this baseline.
- [Plugin loader](https://github.com/silexlabs/Silex/blob/672efed69dda04c0a1e968859239e042f00d9538/common/silex-plugins/plugin.ts) and [publication API](https://github.com/silexlabs/Silex/blob/672efed69dda04c0a1e968859239e042f00d9538/server/api/publicationApi.ts): JS/TS configuration extensions, authenticated hosting connector selection, publication jobs and start/end events.
- [Desktop architecture](https://github.com/silexlabs/Silex/blob/672efed69dda04c0a1e968859239e042f00d9538/desktop/README.md): Tauri v2/WebView with an embedded Rust `silex-server`, distinct from the Node server. Its [HostingConnector](https://github.com/silexlabs/Silex/blob/672efed69dda04c0a1e968859239e042f00d9538/server-rust/src/connectors/traits.rs) and [publication routes](https://github.com/silexlabs/Silex/blob/672efed69dda04c0a1e968859239e042f00d9538/server-rust/src/routes/publication.rs) are candidate adapter seams; a Node plugin alone does not prove desktop compatibility.
- [MCP implementation](https://github.com/silexlabs/Silex/blob/672efed69dda04c0a1e968859239e042f00d9538/desktop/src-tauri/src/mcp.rs): loopback HTTP on port 6807 or stdio, editor capabilities and a JavaScript evaluation bridge. Transport compatibility is not task authorization. Broad editor/evaluation access must remain behind the scoped Studio tool broker.
- [Desktop startup](https://github.com/silexlabs/Silex/blob/672efed69dda04c0a1e968859239e042f00d9538/desktop/src-tauri/src/main.rs) contains telemetry-consent and updater paths. They are not VOLPAROSSA telemetry or release authority; a derivative must preserve VOLPAROSSA's no-hidden-telemetry and independently authorized update rules.

Prefer a portable export/publication adapter and supported plugin/connector seams.
Keep any unavoidable desktop connector registration patch small and recorded;
do not replace the visual editor, build another peer network or duplicate Code's
OpenCode runtime. Preserve templates, responsive design, accessibility tools and
manual editing. The bounded hosted fixture now demonstrates an actual pinned Silex
process and export path. Production desktop publication still needs a native adapter
and the independent review/authorization boundaries below.

Core's expected-publisher guard PR337 is merged, and its actual CLI tests pass. It
checks signer identity before publication side effects; it is an identity-boundary
prerequisite, not a desktop adapter or authorization flow. The editor/MCP window
cannot approve signing. Export preparation, separate trusted native review, offline
signing and separately authorized contribution remain distinct steps.

## Publication and AI authority contract

Studio owns projects, preview, user decisions and reviewable edits. Core owns
signed publication identity/version validation, protected discovery and transfer,
retention, quotas, repair and shared task scheduling. Keep these permissions
separate: editor access, AI tools, publication signing, hosting contribution and
visitor/application access. Never pass signing keys or general daemon authority
to imported content, templates, MCP tools or model workers.

The user chooses a public export set, identity, name, hosting mode and resource
budget. Validate paths, types, size, active content, licenses and accidental secret
inclusion before requesting a publication-specific authorization. Preview is
usable offline without a public deployment. Prepare an immutable complete revision,
verify it, and authorize the named update only when ready; failed deployment must
preserve the earlier authorized serving version where applicable. Rollback must
be a newly authorized revision referencing permitted prior content, not a bypass
of the retained anti-replay floor. Specify withdrawal/tombstone/expiry semantics
before allocating wire fields; inspect retained branches for existing assignments.
Withdrawal does not promise erasure of every remote public copy.

Expose separate statuses for prepared, authorized, locally stored, handed off,
retained by observed peers, independently retrieved/rendered, degraded, expired
and withdrawn. Check all referenced assets and current authorization through an
independent consumer. Count independent holders, not duplicated claims. Repair
and retention must have bounded resource/energy/bandwidth accounting and a defined
owner-offline responsibility. Hashes, publisher keys, domain proof, current-version
authority and availability are five different assertions.

The AI tool broker binds each task to a user/project, operations, expiry and
resource budget; permissions are revocable and project changes invalidate late
results. MCP output, generated code and imported assets are untrusted. Show a
reviewable change and test it before consequential modification or publication.
Agents cannot obtain credentials, extend permissions or approve their own release.
Use shared Core model/agent orchestration and Code's existing runtime. Private
drafts, credentials, customer data and code require authorized protected processing;
if unavailable, show waiting or an authorized local fallback. No silent public-peer
execution, cross-project disclosure or shared training is allowed.

## Static, dynamic and application boundaries

Static hosting is the first complete workflow, with ordinary portable export and
an explicit conventional-hosting alternative. Conventional DNS/domain validation,
HTTPS/certificate renewal, gateways and any trust/bootstrap anchors must be named
and verified before use. No development-host, domain, account or external deployment
change is authorized by this architecture record.

Dynamic forms/APIs/server execution, durable databases, sessions and authenticated
users remain progressive required capabilities where useful. They depend on real
Compute isolation/authorization, durable Storage consistency/recovery and service
availability. A generated static page or replicated object cannot satisfy them.
Research existing runtimes/protocols before adding infrastructure; no separate
hosting platform or competing storage/compute scheduler is selected here.

| Application | Required integration boundary |
| --- | --- |
| Browser | Discovery/rendering through existing Core; ordinary compatibility, authenticated TLS and current fallback/killswitch/privacy/policy behavior remain. No browsing-history publication. |
| Cloud | Private project/draft/template/asset/revision storage and sync reuse Storage authorization, uniform redundancy and recovery; drafts stay separate from public content. |
| Code | Source/components/tests/reviews through existing OpenCode and shared Core agents. |
| Image | Explicit selection and publication rights, ownership/license checks, private metadata filtering; no automatic photo publication. |
| Mail | Authorized forms/notifications/delivery, anti-spam/authentication/status and explicit external-mail trust boundaries. |
| DPS/Map | Optional useful maps/location features with explicit precision/purpose permissions; no automatic locations, routes or geographic metadata. |
| Chat/Weather/Citizen/Bank/future apps | Useful scoped components only; no implied financial, identity, vote, governance or transaction authority. Domain logic stays in the owning application. |

## License and distribution record

The inspected editor/server source notices say **AGPL-3.0-or-later**, and the Rust
server manifest uses that SPDX identifier; the root package's shorthand is
`AGPL-3.0`. Desktop metadata differs by source: `desktop/src-tauri/Cargo.toml`
declares `AGPL-3.0-or-later`, while `desktop/src-tauri/src/main.rs` carries a GNU
GPL version 3-or-later source header; the desktop also has a separate GPL license
file. Preserve this mixed metadata and source record without collapsing it to one
manifest/source label. Studio's pre-existing root GPLv3 text remains unchanged.
Do not overwrite upstream notices or describe the combined implementation as
uniformly covered by the initial repository license. Record modified components,
corresponding-source and network-service obligations, dependencies and attribution
before distribution/service activation. Templates, fonts, images and other assets
need their own rights review. No Silex code is imported in this documentation slice;
[third-party records](../../THIRD_PARTY_LICENSES.md) record research provenance.

## Acceptance and dependency order

Every complete acceptance case below remains open. The fixture above supplies
bounded partial evidence for edit/preview and ZIP creation/Core packing; narrower
Core checks remain reusable only within their original source/scope.

| Required case from amendment section 8 | Reproducible functional acceptance |
| --- | --- |
| 1–2 Create/import, edit, preview | Real pinned Silex process, representative responsive multi-page project/assets and preview; retain manual editing. The fixture proves page creation, text/style editing and preview for one bounded case, not the complete representative-project criteria. |
| 3–4 Authorization and signed publication | Denied/missing/revoked permission fails; exact selected identity/name/files reach actual Core validation. |
| 5 Complete independent rendering | Separate identity/consumer retrieves every asset over the required protected path and renders in a browser with origin isolation. |
| 6 Publisher offline | Stop publisher device/process and source, then retrieve/render from sufficient independent retained peers during a stated expiry window. Report controller dependency. |
| 7–9 Updates, attacks, failed deployment | Atomic revision selection; concurrent updates, stale/forged/substituted manifests and incomplete transfers; previous authorized version remains usable when specified. |
| 10 Resource fairness | Enforce quotas, upload/repair budgets, foreground priority and capacity/peer-loss behavior under measured load. |
| 11–12 Shared AI and review | Actual Core model/agent task uses an authorized Silex interface; independent review/tests precede publication. A local MCP call alone fails this criterion. |
| 13 Private data | Isolated identities/projects, denied/revoked tools and storage access, secret/metadata leak checks, protected execution or explicit unavailable/fallback state. |
| 14 Export | Complete portable site export opens through conventional hosting without VOLPAROSSA dependence. The fixture proves ZIP creation and Core decoding, not conventional-host opening. |
| 15 Recovery, withdrawal, cleanup | Authorized restore/rollback/withdrawal, original expiry, unavailable peers, cancellation/crash cleanup and accurately scoped deletion reports. |

Order work by shared dependencies: finish useful ongoing Storage/protected Compute,
DPS and network integrations; define the Silex/Core contract; exercise static
publication and independent offline-publisher delivery; integrate shared AI and
useful app paths; extend dynamic execution/state once their foundations work.
The order is adaptable, not permission to omit any accepted requirement. Use
existing reviewed hosted workflows for actual runtimes; no new paid infrastructure
or host installation. Record results and retained work in the
[execution ledger](../IMPLEMENTATION_STATUS.md#execution-priorities-and-next-milestones)
and Studio's own status, not a competing task list here.
