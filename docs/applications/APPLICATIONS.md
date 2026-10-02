# VOLPAROSSA applications

[Documentation](../README.md) · [Project overview](../../README.md)

The core is a reusable background service. These eight repositories connect familiar
applications to its network, cache, private storage and compute capabilities. They are
**development integrations**, not eight released products. Each repository records its
own current implementation and evidence; this page explains the scope and major boundaries.

Applications should share one compatible core rather than create competing peer planners
or storage ledgers. Closing one frontend must not stop another application's work. Access
is scoped by user and application; system-wide operation requires an explicit choice.
See the [shared-service contract](../architecture/APPLICATION_LIFECYCLE.md).

## Browser

[volparossa-browser](https://github.com/VOLPAROSSA/volparossa-browser) integrates **Firefox**
with protected connectivity, eligible content caching and the shared VOLPAROSSA brain.

Privacy defaults include strict tracking protection; telemetry, Mozilla accounts and sponsored
links off; and uBlock Origin, Decentraleyes and Adaptive Tab Bar Color. The browser-specific
kill switch starts **off**, permitting visible ordinary-Internet fallback when the overlay is
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

[volparossa-code](https://github.com/VOLPAROSSA/volparossa-code) is moving to **OpenCode**, replacing
the earlier Codex foundation. The core should organize model access, agent cooperation and
resource allocation; OpenCode supplies coding workflows and suitable client surfaces.

The target is actual code reading, editing and testing through network cooperation, including
protected private projects. The migration remains on its development branch. Native runtime
adapter checks are not proof of reliable model-driven coding, and private-peer execution is
unfinished. A local fallback does not satisfy that network requirement.

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

## Weather

[volparossa-weather](https://github.com/VOLPAROSSA/volparossa-weather) builds an application-independent
weather service from **direct public model data**, starting with ECMWF—not Open-Meteo.
Useful additional models and observations can complement that source.

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
