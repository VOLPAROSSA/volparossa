# VOLPAROSSA Studio, decentralized hosting and shared AI

This permanent functional amendment is incorporated in full by [GOAL.md](GOAL.md),
alongside DPS and every earlier requirement. Build a fully integrated Silex-based
Studio for visual creation, AI assistance, publication, updates and maintenance
through the shared DICN infrastructure, preserving Silex functionality, portability,
security and privacy. [The source snapshot](STUDIO_HOSTING_REQUIREMENTS_SOURCE_20261023.md)
is provenance only: the user's 2026-10-26 revision replaces its fixed model and
one-time consolidation instructions with [AGENTS.md](../../AGENTS.md) and the
[development workflow](CODEX_WORKFLOW.md). Product model orchestration remains required.
[The design](../services/STUDIO_HOSTING.md) describes integration contracts;
[IMPLEMENTATION_STATUS.md](../IMPLEMENTATION_STATUS.md) records evidence and priorities.

## Shared Core publishing and hosting

Complete and reuse Core content-addressed storage, signed manifests, site packages,
named publications, peer discovery, protected transport, retention and replica management.
Provide website publication and maintenance through suitable independent peers,
including documented availability when the publisher is offline. Implement:

- static websites and associated authorized assets;
- authenticated publisher/site identities, stable names and atomic versioned updates;
- content integrity, publisher authenticity and independent availability verification;
- replica retention, verification, replacement, repair and recovery after peer/publisher loss;
- authorized rollback, expiry, withdrawal and lifecycle management;
- quotas, resource budgets, participant fairness, efficient cache/deduplication and delivery.

Keep content integrity, publisher identity, domain ownership, current-version authority
and availability guarantees distinct. Local caching or successful replication alone
does not prove general hosting. Avoid unnecessary central infrastructure and document
necessary trust anchors and bootstrap dependencies. Prefer completing these existing
facilities over overlapping hosting services.

## Silex editor and publication workflow

Inspect the current [Studio repository](https://github.com/VOLPAROSSA/volparossa-studio)
and [upstream Silex](https://github.com/silexlabs/Silex): architecture, versions, plugins,
publishing interfaces, desktop implementation, editor APIs and MCP capabilities.
Pin a reproducible, reviewed upstream version. Prefer maintainable adapters, plugins
and upstream-compatible contributions over invasive forks.

Preserve visual editing, responsive design, HTML/CSS export, templates, accessibility
features and normal non-AI operation. Keep output standard and portable, with export
and conventional hosting available; the editor must work before any public deployment.
The user workflow must support creating/importing a site, editing pages, local preview,
validation/preparation, selection of publication identity and hosting mode, explicit
publication authorization, Core publication, actual availability/replica-health monitoring,
and update, restore or withdrawal.

## Shared AI through supported interfaces

Use the established Core model backend, Compute-layer and agent orchestration for
suitable decentralized model execution, collaboration, scheduling and protected processing.
Investigate Silex's MCP server, OpenCode compatibility, plugin interfaces and AI-ready
desktop architecture; connect through supported MCP/extension mechanisms where suitable.
The user's device must not bound usable intelligence: use cooperating network resources
where permitted and supported. Do not create another AI network or independent
code-assistant runtime inside Studio.

Enable authorized AI assistance for:

- sites/pages from natural-language instructions, layouts, components, styles and responsive design;
- HTML, CSS and JavaScript edits through authorized Silex interfaces;
- text, images and other permitted assets;
- accessibility, semantic structure, metadata, discoverability, translation and localization;
- detection and correction proposals for broken links, layout and accessibility problems;
- explanations and review of proposed changes, updates, maintenance and migration;
- independent suitable subtasks coordinated through the shared agent network.

Protect private sites, unpublished drafts, credentials, customer information, source
code and sensitive content through existing protected computation and explicit rights.
Do not send private content to arbitrary peers or shared training. If suitable protected
execution is unavailable, offer waiting or authorized local fallback without weakening
privacy. Treat model-generated code, external templates, MCP responses and imported
assets as untrusted. Consequential modifications, external publication, account operations
and deployment need explicit authorization; agents may not acquire publication credentials,
enlarge permissions or bypass review/release controls on their own.

## Static and progressive dynamic hosting

Deliver complete, reliable static hosting first, then progressively implement useful
dynamic functionality as security, execution and durable-state foundations permit.
Research and implement appropriate capabilities for:

- HTML, CSS, JavaScript, fonts, images and other authorized assets;
- versioned manifests, stable identities, decentralized naming/discovery and existing Core delivery;
- custom domains with authenticated domain-to-publication binding, HTTPS and certificate lifecycles;
- publisher-offline availability and authorized deployment, rollback, withdrawal and recovery;
- forms, APIs and dynamic application functionality;
- protected, authorized server-side Compute execution;
- persistent state, databases, sessions and authenticated users;
- separation of public website content and private application data;
- abuse prevention, quotas and service-availability monitoring.

Dynamic hosting requires actual execution, durable state, authorization and suitable
availability guarantees; static replication does not supply them. Evaluate existing
open-source runtimes, databases and protocols without duplicating Core responsibilities.
Introduce a separate general hosting platform only for capabilities that cannot reasonably
fit the established architecture. Preserve conventional browsers and Internet standards;
provide explicit export/conventional hosting alternatives when decentralized hosting is
unavailable or incomplete. Claims of universal availability, censorship resistance,
guaranteed uptime or independence from conventional infrastructure require evidence.

## Application integrations

Prioritize actual functional value and permission-controlled reuse over unnecessary
dependencies. Keep application business rules in applications and shared infrastructure
in Core.

| Application | Integration and boundary |
| --- | --- |
| Browser | Discover/browse suitable hosted sites through existing Browser/Core integration; preserve ordinary web compatibility, TLS authentication, privacy settings and browser fallback/killswitch behavior. Do not bypass network policy or expose browsing history. |
| Cloud | Investigate private storage/sync of projects, drafts, assets, templates and revision history using existing access control, redundancy, recovery and synchronization. Keep unpublished data separate from public content. |
| Code | Connect source editing, testing, debugging, component creation and technical review to the existing OpenCode integration and shared Core orchestration. |
| Image | Permit explicitly authorized media selection/publication while preserving ownership, licenses, privacy and metadata protection; private photos never become public assets automatically. |
| Mail | Investigate contact forms, notifications and authorized delivery using existing Mail; preserve spam protection, delivery status, authentication and decentralized/external e-mail distinctions. |
| DPS/Map | Investigate optional map/location components only where useful and explicitly authorized; maps must not expose precise locations, movement history or private geographic metadata automatically. |
| Chat, Weather, Citizen, Bank and future apps | Evaluate useful components without granting financial, identity, governance or transaction authority through website components or AI workflows. |

## Security, privacy and licensing

Treat hosting as security-sensitive shared infrastructure. Protect against unauthorized
publication/modification, publisher impersonation, malicious hosting peers, stale/substituted/
replayed revisions, cross-user/site leakage, malicious HTML/JavaScript/templates/plugins/
dependencies, supply-chain attacks, dynamic-execution abuse, exhaustion/denial of service,
private-draft or credential access, insecure AI code/unauthorized agent actions, incorrect
domain/certificate validation and misleading integrity/availability claims.

Separate editor permissions, AI tools, publication authority, hosting responsibilities
and end-user access. Use independently verifiable publisher identities and authorized
release procedures, least privilege and isolation between unrelated users/sites.
Preserve relay/exit privacy and participant resource budgets.

Investigate Silex's upstream AGPL-3.0-or-later terms, dependencies and the Studio repository's
current license. Comply with integration, modification, distribution and network-service
obligations; retain attribution. Existing GPLv3 repository licensing does not automatically
satisfy an integrated AGPL implementation's obligations.

## Functional acceptance

Develop coherent end-to-end milestones using representative real processes, separate
identities, actual Core interfaces and appropriate integration tests. Verify all of:

1. Silex creates or imports a representative website.
2. The website can be edited and previewed.
3. The user explicitly authorizes publication.
4. Core produces and validates the signed publication.
5. An independent consumer retrieves and renders the complete site.
6. Suitable retained replicas serve the site after the publisher goes offline, under documented conditions.
7. Authorized updates become visible without mixing incompatible revisions.
8. Unauthorized changes and stale or forged publications are rejected.
9. Failed deployment preserves the previously authorized working version where appropriate.
10. Hosting respects participant resource limits.
11. Shared VOLPAROSSA models/agents perform an authorized, bounded Silex editing task.
12. AI changes can be independently reviewed and tested before publication.
13. Drafts, credentials and sensitive data remain protected.
14. Conventional website export remains functional.
15. Recovery, withdrawal and cleanup behave as documented.

Distinguish component tests, simulated peers, real distributed publication and verified
public availability. HTML export/signed-chunk storage does not complete decentralized
hosting, and a local MCP call alone does not prove decentralized AI integration.

## Delivery priorities

Build on an audit of verified, partial, missing and blocked Core hosting functionality.
Develop Studio with actual Core contracts, not a disconnected demonstration. Prefer the
least disruptive upstream approach. Establish the publishing contract, complete static
publication, independent retrieval and offline retention, shared AI and useful application
integrations; extend toward dynamic hosting as its foundations become ready. This is
indicative sequencing, not a fixed order. Coordinate with Storage, protected Compute,
DPS, networking and application work; record why higher-priority work is interrupted.
Keep relevant architecture/application documentation, evidence and next steps current;
documentation itself does not satisfy functional acceptance.
