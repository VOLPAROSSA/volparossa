# VOLPAROSSA documentation

Start here to understand the project, find an integration or work on the core.
VOLPAROSSA is a developing **Decentralized Intelligent Cooperative Network**;
the documentation describes both implemented milestones and intended capabilities.

[Project introduction](../README.md) · [Applications](APPLICATIONS.md) ·
[Common questions](FAQ.md) · [Detailed implementation status](IMPLEMENTATION_STATUS.md)

## Choose a reading path

### I am new to the project

1. Read the [project introduction](../README.md) for the four layers and seven virtues.
2. Explore the [application family](APPLICATIONS.md) to see what each integration is for.
3. Check the [development summary](../README.md#development-status) and [FAQ](FAQ.md)
   before trying a build. This is not a supported end-user release.

### I want to build or contribute

1. Read [Contributing](../CONTRIBUTING.md) and the repository's [engineering instructions](../AGENTS.md).
2. Follow the [architecture](ARCHITECTURE.md) and the relevant topic guide below.
3. Use the [read-only prerequisite checks](OPERATIONS.md#read-only-prerequisites), then
   the [build instructions](OPERATIONS.md#build-and-package).
4. Choose [focused tests](TESTING.md#unprivileged-quality-gate) for your change. Network
   tests run only in disposable namespaces or the documented VM, never on your active network.

### I want to evaluate the claims and privacy

1. Read the [privacy boundaries](PRIVACY.md) and [threat model](THREAT_MODEL.md).
2. Use [implementation status](IMPLEMENTATION_STATUS.md) to find the relevant result,
   exact source revision, acceptance report and unresolved failures.
3. Read the [testing guide](TESTING.md) to distinguish parser tests, simulated fixtures
   and actual data-carrying network trials.
4. Report vulnerabilities through the [security policy](../SECURITY.md).

## Network and service architecture

| Guide | What you will find |
| --- | --- |
| [Architecture](ARCHITECTURE.md) | Components, trust boundaries and the required v1 design. |
| [Shared application lifecycle](APPLICATION_LIFECYCLE.md) | Background service ownership, multiple apps and permission scope. |
| [Local links](LOCAL_LINK_NETWORK.md) | Direct Ethernet/Wi-Fi, local-only nodes and reciprocal participation. |
| [Discovery](DISCOVERY.md) | Peer advertisements and finding capabilities without a central catalogue. |
| [Routing](ROUTING.md) | Exit/relay selection, diversity and route contexts. |
| [MPTCP](MPTCP.md) and [path refill](MPTCP_REFILL.md) | TCP subflows and replacement-path behavior. |
| [Multipath QUIC](MULTIPATH_QUIC.md) | Native transport integration and genuine multi-path requirements. |
| [Browser networking](BROWSER_NETWORK.md) | Browser attachment, fallback and kill-switch boundaries. |
| [Protocol](PROTOCOL.md) | Wire formats, versions, signatures and resource bounds. |
| [Privileged helper](HELPER_V3.md) | Typed privileged operations, ownership and cleanup. |

## Content, storage and computation

| Guide | What you will find |
| --- | --- |
| [Content network](CONTENT_NETWORK_PROPOSAL.md) | Cache chunks, publishing, HTTPS authority and offline delivery. |
| [Private storage](PRIVATE_STORAGE.md) | Encrypted fragments, redundancy, retention, usage and recovery. |
| [Mailbox import confirmation](MAILBOX_IMPORT_CONFIRMATION.md) | When an application may confirm message import. |
| [Unbound fallback](UNBOUND_FALLBACK.md) | Resolver lifecycle and bounded DNS-cache misses. |
| [Decentralized agents](DECENTRALIZED_AGENTS.md) | Training, public peer tasks, models, privacy and mutual review. |
| [Whitelist](WHITELIST.md) | Current destination-policy authority and enforcement. |
| [Repository maintenance](REPOSITORY_MAINTENANCE.md) | Autonomous maintenance and authorized client-update design. |

## Operations and project reference

- [Operations](OPERATIONS.md): configuration, commands, packaging and removal.
- [Testing](TESTING.md): focused checks, disposable topologies and acceptance requirements.
- [Implementation status](IMPLEMENTATION_STATUS.md): detailed evidence ledger, including failed trials.
- [Applications](APPLICATIONS.md): boundaries and links for the eight application repositories.
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
