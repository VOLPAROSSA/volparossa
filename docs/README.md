# VOLPAROSSA documentation

Start here to understand the project, find an integration or work on the core.
VOLPAROSSA is a developing **Decentralized Intelligent Cooperative Network**;
the documentation describes both implemented milestones and intended capabilities.

[Project introduction](../README.md) · [Applications](applications/APPLICATIONS.md) ·
[Common questions](FAQ.md) · [Detailed implementation status](IMPLEMENTATION_STATUS.md)

## Find the right folder

The top level keeps this guide, the FAQ, a compact implementation status and its
separate historical evidence ledger.
Technical documents are grouped by subject so the folder itself is easier to browse:

| Folder | Contents |
| --- | --- |
| [architecture/](architecture/) | Core components, protocol, shared daemon and privileged helper. |
| [network/](network/) | Peer discovery, local links, routing, multipath transports and DNS. |
| [services/](services/) | Cache, private storage, message custody, cooperative compute and software maintenance. |
| [applications/](applications/) | Application family and browser-network integration. |
| [community/](community/) | Project overview for contributors and practical ways to support the work. |
| [privacy/](privacy/) | Privacy boundaries, threat model and destination policy. |
| [development/](development/) | Building, operating and testing the project. |
| [assets/](assets/) | Images used by the documentation. |

The folders organize the documentation; they do not represent separate daemons or
different completion levels. Follow the reading paths below for an introduction,
or go directly to a topic when you already know what you need.

## Choose a reading path

### I am new to the project

1. Read the [project introduction](../README.md) for the five layers and seven virtues.
2. Explore the [application family](applications/APPLICATIONS.md) to see what each integration is for.
3. Check the [development summary](../README.md#development-status) and [FAQ](FAQ.md)
   before trying a build. This is not a supported end-user release.

### I want to build or contribute

1. Start with the [community overview](community/OVERVIEW.md) and
   [supporting the project](community/SUPPORTING.md) for contribution paths and current needs.
   The organization-wide [contribution guide](https://github.com/VOLPAROSSA/.github/blob/main/CONTRIBUTING.md),
   [Code of Conduct](https://github.com/VOLPAROSSA/.github/blob/main/CODE_OF_CONDUCT.md),
   [support guide](https://github.com/VOLPAROSSA/.github/blob/main/SUPPORT.md) and
   [accessibility guide](https://github.com/VOLPAROSSA/.github/blob/main/ACCESSIBILITY.md)
   apply across repositories.
2. Read the repository's [engineering instructions](../AGENTS.md) and
   [current implementation status](IMPLEMENTATION_STATUS.md). For a full project
   resumption, read the [complete agreed goal](development/GOAL.md), including
   [DPS](development/DPS_REQUIREMENTS.md) and
   [Studio/hosting](development/STUDIO_HOSTING_REQUIREMENTS.md). For a bounded task,
   load the relevant requirements; the complete scope remains authoritative.
3. Follow the status links for retained work, exact revisions, acceptance evidence
   and dependencies. Read historical records only when the task needs them.
4. Follow the [architecture](architecture/ARCHITECTURE.md) and relevant topic guide below.
   Use [Contributing](../CONTRIBUTING.md) and the [shared development workflow](development/CODEX_WORKFLOW.md)
   when preparing scoped work or transferring it between clients or sessions.
5. Use the [read-only prerequisite checks](development/OPERATIONS.md#read-only-prerequisites), then
   the [build instructions](development/OPERATIONS.md#build-and-package).
6. Choose [focused tests](development/TESTING.md#unprivileged-quality-gate) for your change. Network
   tests run only in disposable namespaces or the documented VM, never on your active network.

### I want to evaluate the claims and privacy

1. Read the [privacy boundaries](privacy/PRIVACY.md) and [threat model](privacy/THREAT_MODEL.md).
2. Use [implementation status](IMPLEMENTATION_STATUS.md) to find the relevant result,
   exact source revision, acceptance report and unresolved failures.
3. Read the [testing guide](development/TESTING.md) to distinguish parser tests, simulated fixtures
   and actual data-carrying network trials.
4. Report vulnerabilities through the [security policy](../SECURITY.md).

## Network and service architecture

| Guide | What you will find |
| --- | --- |
| [Architecture](architecture/ARCHITECTURE.md) | Components, trust boundaries and the required v1 design. |
| [Shared application lifecycle](architecture/APPLICATION_LIFECYCLE.md) | Background service ownership, multiple apps and permission scope. |
| [Local links](network/LOCAL_LINK_NETWORK.md) | Direct Ethernet/Wi-Fi, local-only nodes and reciprocal participation. |
| [Discovery](network/DISCOVERY.md) | Peer advertisements and finding capabilities without a central catalogue. |
| [Routing](network/ROUTING.md) | Exit/relay selection, diversity and route contexts. |
| [MPTCP](network/MPTCP.md) and [path refill](network/MPTCP_REFILL.md) | TCP subflows and replacement-path behavior. |
| [Multipath QUIC](network/MULTIPATH_QUIC.md) | Native transport integration and genuine multi-path requirements. |
| [Browser networking](applications/BROWSER_NETWORK.md) | Browser attachment, fallback and kill-switch boundaries. |
| [Protocol](architecture/PROTOCOL.md) | Wire formats, versions, signatures and resource bounds. |
| [Privileged helper](architecture/HELPER_V3.md) | Typed privileged operations, ownership and cleanup. |

## Content, storage and computation

| Guide | What you will find |
| --- | --- |
| [Studio and hosting](services/STUDIO_HOSTING.md) | Silex audit, shared publishing/AI contracts, static and dynamic acceptance. |
| [Content network](services/CONTENT_NETWORK_PROPOSAL.md) | Cache chunks, publishing, HTTPS authority and offline delivery. |
| [Private storage](services/PRIVATE_STORAGE.md) | Encrypted fragments, redundancy, retention, usage and recovery. |
| [Transaction layer](services/TRANSACTION_LAYER.md) | Durable test-unit API, executable example, settlement boundaries and remaining work. |
| [Decentralized positioning](services/DPS.md) | Shared local positioning/integrity design, sensor research, privacy and phased acceptance. |
| [Mailbox import confirmation](services/MAILBOX_IMPORT_CONFIRMATION.md) | When an application may confirm message import. |
| [Unbound fallback](network/UNBOUND_FALLBACK.md) | Resolver lifecycle and bounded DNS-cache misses. |
| [Decentralized agents](services/DECENTRALIZED_AGENTS.md) | Training, public peer tasks, models, privacy and mutual review. |
| [Protected compute preparation](development/PROTECTED_COMPUTE_VERIFIER.md) | Public attestation fixtures, limited evidence and the missing private-worker acceptance path. |
| [Cooperative Code evidence](COOPERATIVE_CODE.md) | Public peer-repair evidence and the historical two-peer document trial; the [current native coding milestone](IMPLEMENTATION_STATUS.md#latest-completed-integration-evidence) is recorded separately. |
| [Cooperative browser evidence](COOPERATIVE_BROWSER.md) | Public peer execution, source-bound trials and remaining answer-completion limits. |
| [Whitelist](privacy/WHITELIST.md) | Current destination-policy authority and enforcement. |
| [Repository maintenance](services/REPOSITORY_MAINTENANCE.md) | Autonomous maintenance and authorized client-update design. |

## Operations and project reference

- [Agreed goal](development/GOAL.md): effective complete objective and integrated amendments.
- [Studio/hosting requirements](development/STUDIO_HOSTING_REQUIREMENTS.md): complete permanent Silex, hosting and shared AI amendment.
- [DPS requirements](development/DPS_REQUIREMENTS.md): complete joined and permanent normative positioning scope.
- [DPS source archive](development/DPS_GOAL_20261021.md): byte-preserved provenance only; not the current normative requirements file.
- [Continuation prompt](development/PURSUING_GOAL.md): optional text for resuming the complete goal in any client.
- [Goal verification](development/GOAL_VERIFICATION.md): source preservation and inclusion checks when requirements change.
- [Goal preservation verifier](../scripts/verify-goal-preservation.py): standard-library-only integrity check.
- [Shared development workflow](development/CODEX_WORKFLOW.md): task-driven execution, delegation, verification and handover for any client.
- [Operations](development/OPERATIONS.md): configuration, commands, packaging and removal.
- [Testing](development/TESTING.md): focused checks, disposable topologies and acceptance requirements.
- [Implementation status](IMPLEMENTATION_STATUS.md): compact current work, evidence and dependencies.
- [Historical evidence](IMPLEMENTATION_HISTORY_20261023.md): preserved detailed checkpoints, including failed trials; not default startup reading.
- [Public growth readiness](development/PUBLIC_GROWTH_20261020.md): organization audit, verification and sustainable outreach/funding roadmap.
- [2026-10-20 repository maintenance](development/MAINTENANCE_20261020.md): measured cleanup outcomes and retained recovery state.
- [Execution plan](IMPLEMENTATION_STATUS.md#execution-priorities-and-next-milestones): next milestones, shared dependencies and current blockers.
- [Applications](applications/APPLICATIONS.md): boundaries and links for the application repositories.
- [Community overview](community/OVERVIEW.md): project entry point and contributor routes.
- [Supporting the project](community/SUPPORTING.md): contributions, funding readiness and partnership boundaries.
- [Contributing](../CONTRIBUTING.md): how to propose and verify a useful change.
- [Security policy](../SECURITY.md): private vulnerability reporting.
- [License](../LICENSE) and [third-party notices](../THIRD_PARTY_LICENSES.md): reuse and provenance.

## How to read development claims

**Design** describes the intended behavior. **Implemented** means code exists, not that
every usage scenario works. **Verified** refers to a stated source revision and test scope.
**Pending** remains unfinished, even when adjacent components pass.

The status index links to detailed evidence without repeating the full history.
Older records retain failed experiments. A historical checkpoint does not qualify a
newer build; a passing small-model task does not establish reliable reasoning; a
connector does not establish a complete application.

Start with the concise README, follow the topic guide when needed, and use the ledger for
the exact claim. Feature branches may contain work not yet integrated into `main`.
