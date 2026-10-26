# VOLPAROSSA applications

[Documentation](../README.md) · [Project overview](../../README.md)

The core is a reusable background service. The application repositories connect familiar
applications and new research projects to its shared capabilities. They are
**development integrations and research**, not released products. Each repository records its
own current implementation and evidence; this page explains the scope and major boundaries.

The [complete agreed goal](../development/GOAL.md) preserves the full application scope;
its [DPS section](../development/GOAL.md#dps) preserves the
permanent cross-application positioning scope;
the [core implementation ledger](../IMPLEMENTATION_STATUS.md#current-integration-and-active-work)
records shared dependencies and exact acceptance evidence. Follow each application's linked
repository for its own implementation status rather than treating this overview as another ledger.

Applications should share one compatible core rather than create competing peer planners
or storage ledgers. Closing one frontend must not stop another application's work. Access
is scoped by user and application; system-wide operation requires an explicit choice.
See the [shared-service contract](../architecture/APPLICATION_LIFECYCLE.md).

## Studio

[volparossa-studio](https://github.com/VOLPAROSSA/volparossa-studio) is the required
Silex-based visual website editor, portable export and shared decentralized hosting
integration. The [Studio section of the goal](../development/GOAL.md#studio)
requires visual/manual editing, preview, explicit publication, actual independent
availability, updates/recovery/withdrawal and shared protected AI through Core and
supported Silex interfaces. [The architecture and initial audit](../services/STUDIO_HOSTING.md)
separate static publishing from progressive dynamic execution and durable state.
The initial audit started from a README/license scaffold. Current bounded
editing/export evidence is recorded in [implementation status](../IMPLEMENTATION_STATUS.md#studio-and-shared-hosting-evidence);
complete production publication and independently available hosting remain open.

Reuse Browser discovery/rendering with existing TLS/fallback/killswitch policy;
Cloud private project storage; Code/OpenCode editing/testing/review; explicitly
published Image assets; authorized Mail delivery; and optional permission-scoped
DPS/Map components. Useful Chat/Weather/Citizen/Bank integrations add no implicit
financial, identity, voting or transaction authority. Preserve source licenses,
Silex functionality and conventional export/hosting alternatives. Private drafts,
photos, geographic metadata and credentials never become public automatically.

## Browser

[volparossa-browser](https://github.com/VOLPAROSSA/volparossa-browser) integrates **Firefox**
with protected connectivity, eligible content caching and the shared VOLPAROSSA brain.

Privacy defaults include strict tracking protection; telemetry, Mozilla accounts and sponsored
links off; and uBlock Origin, Decentraleyes, Consent-O-Matic and Adaptive Tab Bar Color.
Consent-O-Matic remains upstream without a VOLPAROSSA fork; upstream contributions are opt-in.
Its cooperation with uBlock Origin must preserve necessary website functions and avoid unwanted consent.
The browser-specific kill switch starts **off**, permitting visible ordinary-Internet fallback when the overlay is
unavailable. It must not bypass a policy denial or weaken another core consumer's defaults.

Privacy/sidebar and scoped protected-TCP milestones have real browser evidence. Complete
network/cache integration and useful shared AI remain in development. The target is not
an exclusively local chatbot. [Core browser-network contract](BROWSER_NETWORK.md)

## Chat

[volparossa-chat](https://github.com/VOLPAROSSA/volparossa-chat) integrates **Signal** messaging,
voice/video calling and private backups. Message encryption, identities, sessions and linked
devices must retain Signal Protocol semantics.

Native encrypted backup export/import now has a scoped fragment-storage/provider-loss proof.
That does not complete message or media transport. Fully decentralized, mixed and ordinary
Signal delivery must be distinguished; registration, device discovery and prekeys are separate
dependencies. Mobile support, recovery UX and automatic storage contribution remain unfinished.

## Mail

[volparossa-mail](https://github.com/VOLPAROSSA/volparossa-mail) connects **Thunderbird** using
the user's existing accounts and addresses. Suitable VOLPAROSSA delivery should take priority
and use the Signal Protocol; ordinary e-mail remains available. The integration also targets
decentralized AI and optional self-hosting based on **Stalwart**.

Connector/JMAP import is a completed slice, not complete decentralized mail delivery.
Ordinary external mail still needs Internet-facing SMTP infrastructure with an explicit trust
boundary; opaque peer storage alone cannot receive it. Private mail must not be exposed to
arbitrary storage peers. Missing delivery confirmation is not automatic proof of failure.

## Code

[volparossa-code](https://github.com/VOLPAROSSA/volparossa-code) now uses **OpenCode** on its
`main` branch, replacing the earlier Codex foundation. OpenCode supplies coding workflows;
the core handles model access, execution and resource control. Shared agent cooperation
remains a core responsibility, not a separate network scheduler in the application.

A [real CPU-model trial](https://github.com/VOLPAROSSA/volparossa-code/actions/runs/38824828727)
completes two reads, an explicitly approved edit and test, and an independent check against
unchanged original tests. The coding task takes about 37 minutes. The native backend is
now also integrated into core `main`, with passing source checks. The trial remains bound
to its original core pin; it has not been repeated on the newly integrated core.
This is a bounded local workflow, not evidence of competitive performance, general coding
reliability or a working native editor UI.

The target remains code reading, editing and testing through network cooperation, including
protected private projects. Confidential private-peer execution is unfinished; local
execution does not satisfy that network requirement.

## Image

[volparossa-image](https://github.com/VOLPAROSSA/volparossa-image) connects **Immich** for Android,
iPhone/iPad and browsers. The aim is a private photo/video library without requiring the owner's
server to remain permanently on.

Peer-backed encrypted snapshot recovery has a scoped proof. Mobile synchronization and the
backend functions needed for complete server-independent use remain unfinished. Photos,
locations, metadata, thumbnails and other derived private data are not automatically public
cache entries or shared training material.

## Map

[volparossa-map](https://github.com/VOLPAROSSA/volparossa-map) connects **Organic Maps**, preserving
offline maps and navigation while adding shared map distribution and traffic information.

Signed traffic-snapshot validation exists; live aggregation and mobile display remain open.
Sharing congestion should not expose individual journeys or complete location histories.
Licenses, freshness and uncertainty remain relevant even when data comes from nearby peers.

The [joined DPS requirements](../development/GOAL.md#dps) define the
permanent application scope; the [DPS service design](../services/DPS.md) records
implementation and acceptance choices. Together they cover alternative or
complementary location sources, including weak-GNSS, tunnel/indoor and
manipulated-GNSS scenarios. Keep offline navigation, visible uncertainty and
application permission boundaries. Native integration and actual positioning
improvement remain unverified; journeys and movement histories are not shared
automatically. No application depends on a chat attachment or conversation history
for these requirements.

## Weather

[volparossa-weather](https://github.com/VOLPAROSSA/volparossa-weather) builds an application-independent
weather service from **direct public model data**, starting with ECMWF—not Open-Meteo.
Useful additional models and observations can complement that source.

Both Drizz.li and Overmorrow are integration targets. Precipitation and air-quality support
remain required follow-on work; unavailable data must be shown as unavailable, never invented.

Direct field decoding and a core-cache adapter exist. Distributed processing and learning
should produce measurable forecast improvements against observations; a learned forecasting
model has not yet been demonstrated. More participants or more training do not automatically
make a forecast better.

## Cloud

[volparossa-cloud](https://github.com/VOLPAROSSA/volparossa-cloud) connects **OpenCloud** to private
decentralized storage, with the aim of usable files and synchronization while the owner's
original server is off.

The original Files web UI has a scoped source-off recovery proof. Accounts, metadata, versions,
sharing, writable synchronization and general service availability still need integration.
Distributed backup or recovery does not alone create a server-independent OpenCloud service.
Search, previews and AI must preserve the privacy of both files and derived information.

## Bank

[volparossa-bank](https://github.com/VOLPAROSSA/volparossa-bank) investigates
participant-owned portfolios weighted by nonnegative ROIC and FCF-yield, internal
micro-payments and external financial connections. It requires the proposed
[Transaction-layer](../services/TRANSACTION_LAYER.md), separate from ordinary
network contribution and from private file storage.

The current scope is research and isolated simulations, not taking deposits,
trading securities or operating a payment institution. Enforceable ownership,
financial authorization, consensus, gateway settlement and dispute governance
remain required work. The immune system supplies bounded analysis, not unilateral
financial authority or a guarantee that dispersed funds can be recovered.

## Citizen

[volparossa-citizen](https://github.com/VOLPAROSSA/volparossa-citizen) targets
proposals, deliberation and referenda alongside existing democratic institutions.
The application owns its participation rules; transport, storage and compute
should reuse the core.

The first executable simulation is merged in [PR1](https://github.com/VOLPAROSSA/volparossa-citizen/pull/1).
It freezes all eligible fictional people separately from registered accounts:
one-third support opens a referendum, two-thirds yes adopts it and two-thirds
no rejects it. Other outcomes remain indeterminate and permit an explicit repeat
procedure after three calendar years. Twenty-one tests pass. The documented UTC,
calendar and renewed-support details are simulation assumptions, not additional
confirmed governance rules.

Real identity verification and uniqueness, secret verifiable voting, contestable
proposal review, core delivery and recovery remain open. A synthetic result is
neither a public-election security proof nor recognized legal authority.

## Shared positioning integration

The [shared DPS service](../services/DPS.md#application-integration-priorities)
supplies one versioned core interface with separate platform sensor adapters.
Applications must not duplicate its positioning engine or enable collection just
because the node participates in VOLPAROSSA.

- Weather may use permitted position estimates and geographically associated
  observations while protecting locations and accounting for correlated sources.
- Image may optionally retain photo/video locations only within existing user
  rights and private storage, without automatic publication.
- Chat may provide explicitly authorized encrypted location exchange/local
  positioning with bounded retention and the existing Signal Protocol.
- Browser must preserve platform and origin permissions and never give websites
  or extensions finer location than the user allowed.
- Cloud may store/synchronize only explicitly authorized private positioning
  data through the existing Storage layer.
- Other applications adopt DPS only for a concrete benefit. Unproven location
  claims cannot alone authorize transactions, identities, voting rights or access.

Hardware, permission revocation, privacy and native application behavior require
their own tests. Synthetic service tests do not prove functioning location sensors,
geographic truth or improved navigation. See the [DPS acceptance sequence](../services/DPS.md#acceptance-sequence).

## Shared boundaries

- Public cache, private retained storage and encrypted message custody have different
  authorization and retention rules.
- Storage applications use the core's common redundancy policy and physical-byte accounting,
  not separate protection tiers or invented contribution credits.
- Agents and application integrations fall within the intended shared immune system, but it
  does not replace access control or make private execution confidential by itself.
- Application-specific successes do not establish that all platforms, other applications
  or the complete expanded alpha work.

[Core implementation evidence](../IMPLEMENTATION_STATUS.md) · [Private storage](../services/PRIVATE_STORAGE.md) ·
[Cooperative agents](../services/DECENTRALIZED_AGENTS.md) · [Privacy](../privacy/PRIVACY.md)
