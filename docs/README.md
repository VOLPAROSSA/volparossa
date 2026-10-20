# VOLPAROSSA documentation

Start here to understand the project, find an integration or work on the core.
VOLPAROSSA is a developing **Decentralized Intelligent Cooperative Network**;
the documentation describes both implemented milestones and intended capabilities.

[Project introduction](../README.md) · [Applications](applications/APPLICATIONS.md) ·
[Common questions](FAQ.md) · [Detailed implementation status](IMPLEMENTATION_STATUS.md)

## Find the right folder

The top level keeps this guide, the FAQ and the implementation-status ledger.
Technical documents are grouped by subject so the folder itself is easier to browse:

| Folder | Contents |
| --- | --- |
| [architecture/](architecture/) | Core components, protocol, shared daemon and privileged helper. |
| [network/](network/) | Peer discovery, local links, routing, multipath transports and DNS. |
| [services/](services/) | Cache, private storage, message custody, cooperative compute and software maintenance. |
| [applications/](applications/) | Application family and browser-network integration. |
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

1. Read the repository's [engineering instructions](../AGENTS.md), then the
   [complete agreed goal](development/GOAL.md). The current milestone is not the full scope.
2. Read [current implementation status](IMPLEMENTATION_STATUS.md#current-integration-and-active-work)
   for retained branches, exact revisions, acceptance evidence and unresolved dependencies.
3. Follow the [architecture](architecture/ARCHITECTURE.md) and relevant topic guide below.
   Use [Contributing](../CONTRIBUTING.md) and the [Codex handover workflow](development/CODEX_WORKFLOW.md)
   when preparing scoped work or transferring it to another session.
4. Use the [read-only prerequisite checks](development/OPERATIONS.md#read-only-prerequisites), then
   the [build instructions](development/OPERATIONS.md#build-and-package).
5. Choose [focused tests](development/TESTING.md#unprivileged-quality-gate) for your change. Network
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
| [Content network](services/CONTENT_NETWORK_PROPOSAL.md) | Cache chunks, publishing, HTTPS authority and offline delivery. |
| [Private storage](services/PRIVATE_STORAGE.md) | Encrypted fragments, redundancy, retention, usage and recovery. |
| [Transaction layer](services/TRANSACTION_LAYER.md) | Durable test-unit API, executable example, settlement boundaries and remaining work. |
| [Mailbox import confirmation](services/MAILBOX_IMPORT_CONFIRMATION.md) | When an application may confirm message import. |
| [Unbound fallback](network/UNBOUND_FALLBACK.md) | Resolver lifecycle and bounded DNS-cache misses. |
| [Decentralized agents](services/DECENTRALIZED_AGENTS.md) | Training, public peer tasks, models, privacy and mutual review. |
| [Protected compute preparation](development/PROTECTED_COMPUTE_VERIFIER.md) | Public attestation fixtures, limited evidence and the missing private-worker acceptance path. |
| [Cooperative Code evidence](COOPERATIVE_CODE.md) | Public peer-repair evidence and the historical two-peer document trial; the [current native coding milestone](IMPLEMENTATION_STATUS.md#latest-completed-integration-evidence) is recorded separately. |
| [Cooperative browser evidence](COOPERATIVE_BROWSER.md) | Public peer execution, source-bound trials and remaining answer-completion limits. |
| [Whitelist](privacy/WHITELIST.md) | Current destination-policy authority and enforcement. |
| [Repository maintenance](services/REPOSITORY_MAINTENANCE.md) | Autonomous maintenance and authorized client-update design. |

## Operations and project reference

- [Agreed goal](development/GOAL.md): complete preserved objective and later clarifications.
- [Codex workflow](development/CODEX_WORKFLOW.md): safe resumption, scoped delegation and handover.
- [Operations](development/OPERATIONS.md): configuration, commands, packaging and removal.
- [Testing](development/TESTING.md): focused checks, disposable topologies and acceptance requirements.
- [Implementation status](IMPLEMENTATION_STATUS.md): detailed evidence ledger, including failed trials.
- [2026-10-20 repository maintenance](development/MAINTENANCE_20261020.md): measured cleanup outcomes and retained recovery state.
- [Execution plan](IMPLEMENTATION_STATUS.md#execution-priorities-and-next-milestones): next milestones, shared dependencies and current blockers.
- [Applications](applications/APPLICATIONS.md): boundaries and links for the application repositories.
- [Contributing](../CONTRIBUTING.md): how to propose and verify a useful change.
- [Security policy](../SECURITY.md): private vulnerability reporting.
- [License](../LICENSE) and [third-party notices](../THIRD_PARTY_LICENSES.md): reuse and provenance.

## How to read development claims

**Design** describes the intended behavior. **Implemented** means code exists, not that
every usage scenario works. **Verified** refers to a stated source revision and test scope.
**Pending** remains unfinished, even when adjacent components pass.

The detailed status file is an evidence ledger, not a quick-start guide. Its older records
are retained so a failed experiment is not silently turned into a success. A historical
checkpoint does not qualify a newer build; a passing small-model task does not establish
reliable reasoning; a connector does not establish a complete application.

Start with the concise README, follow the topic guide when needed, and use the ledger for
the exact claim. Feature branches may contain work not yet integrated into `main`.
