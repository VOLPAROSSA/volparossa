<!-- Permanent normative amendment incorporated by GOAL.md. -->
<!-- Source: user amendment received 2026-10-22. The complete payload is preserved below. -->
<!-- BEGIN STUDIO HOSTING REQUIREMENTS -->
# VOLPAROSSA — Permanent Pursuing Goal Amendment: Decentralized Hosting & AI-Powered Studio

Extend the complete VOLPAROSSA Pursuing Goal with a fully integrated decentralized website hosting and publishing capability, using Silex as the foundation of VOLPAROSSA Studio.

This is a permanent functional addition to the existing DICN development-alpha objective, not a separate project, optional experiment, or replacement for existing requirements.

Preserve the entire original goal, all previous amendments including DPS, every existing architectural contract, and all active implementation work.

## 1. Preserve and extend the authoritative goal

First read:

- `AGENTS.md`
- `docs/development/GOAL.md`
- `docs/development/DPS_REQUIREMENTS.md`
- `docs/development/GOAL_VERIFICATION.md`
- `docs/development/PURSUING_GOAL.md`
- `docs/IMPLEMENTATION_STATUS.md`
- `docs/services/CONTENT_NETWORK_PROPOSAL.md`
- Relevant architecture, publishing, storage, compute and application documentation.

Inspect the current `VOLPAROSSA/volparossa-studio` repository and the upstream Silex project:

https://github.com/VOLPAROSSA/volparossa-studio

https://github.com/silexlabs/Silex

Preserve the original goal and all earlier amendments byte-for-byte where they are covered by established preservation records.

Create a clearly structured, permanent normative hosting/Studio amendment and incorporate it into the authoritative goal documentation.

Prefer a dedicated file such as `docs/development/STUDIO_HOSTING_REQUIREMENTS.md`, explicitly incorporated by `GOAL.md`.

Update the goal-preservation verification so that the new amendment is checked without invalidating or rewriting the historical original-goal, pre-DPS and DPS baselines.

Do not depend on temporary attachments or conversation history.

## 2. Decentralized hosting as a shared core capability

Develop a reusable decentralized website hosting and publishing capability within the existing VOLPAROSSA Core.

Reuse and complete the existing content-addressed storage, signed manifests, site packaging, named publications, peer discovery, protected transport, retention and replica-management mechanisms.

Do not create a competing hosting subsystem that duplicates these foundations.

The target functionality must enable users to publish and maintain websites through the cooperative VOLPAROSSA network, with appropriate availability even when the original publisher's device is offline.

Research and implement the required capabilities for:

- Publishing static websites and associated assets.
- Authenticated site identities and stable names.
- Versioned website updates and atomic publication.
- Content integrity and publisher authenticity.
- Distributed availability through suitable independent peers.
- Replica retention, verification, replacement and repair.
- Safe rollback to authorized previous revisions.
- Content expiry, withdrawal and lifecycle management.
- Quotas, resource budgets and participant fairness.
- Efficient caching, deduplication and content delivery.
- Recovery after individual peers or the original publisher become unavailable.
- Independent verification of actual website availability.

Distinguish content integrity, publisher identity, domain ownership, current-version authority and availability guarantees.

Do not treat successful replication or local caching as proof of general website hosting.

Avoid unnecessary central infrastructure, but document unavoidable trust anchors and bootstrap dependencies.

## 3. Integrate Silex as VOLPAROSSA Studio

Use the existing open-source Silex website builder as the primary foundation for VOLPAROSSA Studio.

Inspect its current architecture, supported versions, plugin system, publishing interfaces, desktop implementation, editor APIs and MCP capabilities.

Select a reproducible, reviewed upstream version.

Prefer maintainable adapters, plugins and upstream-compatible extensions over unnecessary invasive forks.

Preserve Silex's established editing capabilities, visual design workflow, responsive design, HTML/CSS export, templates and accessibility features.

Provide a user-friendly VOLPAROSSA publishing workflow:

1. Create or import a website.
2. Design and edit its pages.
3. Preview the website locally.
4. Validate and prepare the publication.
5. Select the intended publication identity and hosting mode.
6. Explicitly authorize publication.
7. Publish through the VOLPAROSSA Core.
8. Monitor actual availability and replica health.
9. Update, restore or withdraw the publication.

Maintain standard, portable website output and avoid proprietary content lock-in.

Ensure users can export their sites and host them elsewhere.

The editor must remain usable without requiring that a public website has already been deployed.

## 4. Connect the shared VOLPAROSSA AI to Silex

Integrate Silex with the existing decentralized VOLPAROSSA AI and agent infrastructure.

Use the shared VOLPAROSSA Core model backend and agent orchestration rather than building a second independent AI network inside Studio.

Investigate Silex's existing MCP server, OpenCode compatibility, plugin interfaces, and AI-ready desktop architecture.

Where suitable, connect the VOLPAROSSA AI orchestration through Silex's existing MCP interfaces and supported extension mechanisms.

Enable AI-assisted website creation and maintenance, including:

- Generating websites and individual pages from natural-language instructions.
- Creating and modifying layouts, components, styles, and responsive designs.
- Editing HTML, CSS, and JavaScript through authorized Silex interfaces.
- Generating and improving text, images, and other permitted website assets.
- Improving accessibility, semantic structure, metadata, and search-engine discoverability.
- Translating and localizing website content.
- Detecting and proposing fixes for broken links, layout problems, and accessibility issues.
- Explaining and reviewing proposed changes before publication.
- Assisting with website updates, maintenance, and migration.
- Coordinating suitable independent subtasks through the shared VOLPAROSSA agent network.

Preserve Silex's normal visual editing capabilities without requiring AI.

AI functionality must work through the established VOLPAROSSA Compute-layer, including suitable decentralized model execution, agent collaboration, resource scheduling, and protected processing.

The user's own device must not become the architectural limit of available intelligence. Where permitted and technically supported, suitable tasks may use cooperating network resources.

Protect private websites, unpublished drafts, credentials, customer information, source code, and sensitive content.

Do not send private website content to arbitrary peers or shared training systems. Use the existing protected-computation architecture and explicit permissions.

When suitable protected execution is unavailable, clearly offer waiting or an authorized local fallback rather than silently weakening privacy.

Treat AI-generated website code, external templates, MCP responses, and imported assets as untrusted inputs.

Require explicit authorization for consequential modifications, external publication, account operations, and deployment.

AI agents must not independently acquire publication credentials, expand their permissions, or bypass review and release authorization.

## 5. Support static and dynamic website hosting

Begin with complete, reliable decentralized hosting of static websites generated by Silex.

Research and progressively implement additional hosting capabilities where they provide genuine value.

Investigate:

- Static HTML, CSS, JavaScript, fonts, images, and other authorized assets.
- Versioned publication manifests and stable website identities.
- Custom domains and authenticated domain-to-publication binding.
- HTTPS delivery and certificate lifecycle management.
- Suitable decentralized naming and discovery.
- Content delivery through existing VOLPAROSSA networking and caching.
- Website availability when the publisher's device is offline.
- Authorized deployment, rollback, withdrawal, and recovery.
- Website forms, APIs, and dynamic application functionality.
- Server-side execution, where supported by protected and authorized Compute-layer capabilities.
- Persistent application state, databases, sessions, and authenticated users.
- Separation between public website content and private application data.
- Abuse prevention, resource quotas, and service availability monitoring.

Do not confuse static content replication with dynamic hosting.

Dynamic websites require actual execution, durable state management, authorization, and suitable availability guarantees.

Evaluate whether existing open-source runtimes, databases, and protocols can provide these capabilities efficiently without duplicating the Core's responsibilities.

Do not introduce a separate general-purpose hosting platform unless it provides capabilities that cannot reasonably be implemented through the established architecture.

Preserve interoperability with conventional web browsers and established Internet standards.

Support conventional hosting or export as an explicit alternative where decentralized hosting is unavailable or incomplete.

Do not claim universal website availability, censorship resistance, guaranteed uptime, or complete independence from conventional infrastructure without appropriate evidence.

## 6. Integrate hosting with other VOLPAROSSA applications

Investigate useful integrations between Studio, decentralized hosting, and the existing VOLPAROSSA applications.

Prioritize actual functional value rather than adding unnecessary dependencies.

### Browser

Enable suitable discovery and browsing of VOLPAROSSA-hosted websites through the existing Browser and Core integration.

Preserve ordinary web compatibility, TLS authentication, privacy settings, and the existing browser-specific fallback and killswitch behavior.

Do not silently bypass network policy or expose browsing history.

### Cloud

Investigate private storage and synchronization of Silex projects, drafts, assets, templates, and revision history through the existing Storage-layer.

Keep unpublished website data private and separate from publicly hosted content.

Reuse existing access-control, redundancy, recovery, and synchronization mechanisms.

### Code

Connect VOLPAROSSA Code to suitable Studio development workflows, including source editing, testing, debugging, component creation, and technical reviews.

Reuse the existing OpenCode integration and shared Core agent orchestration.

Avoid implementing a second independent code-assistant runtime inside Studio.

### Image

Enable authorized selection and use of images and other media from VOLPAROSSA Image.

Preserve ownership, licenses, privacy, metadata protection, and explicit publication permissions.

Private photos must never become public website assets automatically.

### Mail

Investigate website contact forms, notifications, and authorized mail delivery through existing VOLPAROSSA Mail capabilities.

Preserve spam protection, delivery status, authentication, and the distinction between decentralized and conventional external e-mail.

### DPS and Map

Investigate optional location-based website functionality and map components.

Use DPS only where useful and with explicit location permissions.

Never expose precise locations, movement histories, or private geographic metadata merely because a website includes a map.

### Other applications

Evaluate whether Chat, Weather, Citizen, Bank, and future applications can provide useful, permission-controlled website components or integrations.

Do not grant financial, identity, governance, or transaction authority merely through a website component or AI-generated workflow.

Keep application-specific business logic within the appropriate application and shared infrastructure within the Core.

## 7. Security, privacy, licensing, and trust boundaries

Treat decentralized hosting as a security-sensitive shared infrastructure service.

Protect against:

- Unauthorized website publication or modification.
- Publisher identity impersonation.
- Malicious or compromised hosting peers.
- Stale, substituted, or replayed website revisions.
- Cross-user and cross-site data leakage.
- Malicious HTML, JavaScript, templates, plugins, and dependencies.
- Supply-chain attacks.
- Abuse of dynamic execution capabilities.
- Resource exhaustion and denial-of-service attacks.
- Unauthorized access to private drafts and deployment credentials.
- AI-generated insecure code and unauthorized agent actions.
- Incorrect domain ownership or certificate validation.
- Misleading availability or integrity claims.

Separate editor permissions, AI tool permissions, publication authority, hosting responsibilities, and end-user access.

Use independently verifiable publisher identities and authorized release procedures.

Maintain least-privilege access and appropriate isolation between unrelated websites and users.

Preserve the existing VOLPAROSSA relay/exit privacy boundaries and participant resource budgets.

Investigate Silex's upstream AGPL-3.0-or-later licensing, existing dependencies, and the current VOLPAROSSA Studio repository license.

Ensure that integration, modification, distribution, and network-service use comply with applicable licenses.

Preserve upstream attribution and prefer maintainable upstream-compatible contributions.

Do not assume the existing GPLv3 repository license automatically satisfies all obligations of an integrated AGPL-licensed Silex implementation.

## 8. Functional verification and acceptance

Develop the hosting and Studio integration through coherent, end-to-end functional milestones.

Verify at minimum:

1. Silex can create or import a representative website.
2. The website can be edited and previewed.
3. The user can explicitly authorize publication.
4. The Core produces and validates the appropriate signed publication.
5. An independent consumer can retrieve and render the complete website.
6. The website remains available through suitable retained replicas after the original publisher goes offline, under documented conditions.
7. Authorized website updates become visible without mixing incompatible revisions.
8. Unauthorized modifications and stale or forged publications are rejected.
9. A failed deployment preserves the previously authorized working version where appropriate.
10. Hosting respects participant resource limits.
11. AI can perform an authorized, bounded Silex editing task through the shared VOLPAROSSA model and agent infrastructure.
12. AI-generated modifications can be independently reviewed and tested before publication.
13. Private drafts, credentials, and sensitive data remain protected.
14. Conventional website export remains functional.
15. Supported recovery, withdrawal, and cleanup operations behave as documented.

Use representative real processes, separate identities, actual Core interfaces, and appropriate integration tests.

Distinguish local component tests, simulated peer behavior, real distributed publication, and verified public website availability.

Do not claim completed decentralized hosting merely because Silex exports HTML or the Core stores signed chunks.

Do not claim decentralized AI integration merely because a local MCP client can call Silex.

## 9. Implementation strategy and prioritization

Begin by auditing the existing hosting and publishing implementation in VOLPAROSSA Core.

Identify which capabilities are already verified, partially implemented, missing, or blocked.

Inspect the current upstream Silex architecture and select the least disruptive integration approach.

Prefer completing existing Core publishing and retention functionality before introducing overlapping hosting services.

Develop Studio together with actual Core interfaces rather than implementing a disconnected demonstration.

Prioritize:

- Reusing verified Core capabilities.
- Establishing the Silex-to-Core publishing contract.
- Achieving a complete static-site publishing workflow.
- Verifying independent retrieval and publisher-offline availability.
- Integrating shared VOLPAROSSA AI through Silex's supported interfaces.
- Adding useful application integrations.
- Extending toward dynamic hosting when the necessary security, execution, and state-management foundations are ready.

This sequence is indicative, not a mandatory fixed implementation order.

Coordinate hosting work with ongoing Storage, protected Compute, DPS, networking, and application integrations.

Do not interrupt higher-priority critical work without documenting the reason.

Use the configured Astra Ultra principal agent, Sol High implementation and review agents, and Luna Medium supporting agents efficiently.

Reuse appropriate GitHub Actions workflows and preserve established quality gates.

## 10. Permanently incorporate this amendment into the Pursuing Goal

Consolidate this entire Studio and hosting amendment into the authoritative VOLPAROSSA development requirements.

Preserve the original goal and all earlier amendments, including DPS, without rewriting their protected source payloads.

Update:

- `docs/development/GOAL.md`
- `docs/development/GOAL_VERIFICATION.md`
- `docs/development/PURSUING_GOAL.md`
- `docs/IMPLEMENTATION_STATUS.md`
- Relevant architecture, publishing, Compute, Storage, and application documentation.
- The VOLPAROSSA Studio repository's project guidance and implementation status.

Create a dedicated, version-controlled normative requirements document for Studio and decentralized hosting, such as `docs/development/STUDIO_HOSTING_REQUIREMENTS.md`.

Update the goal-preservation verifier to ensure the new requirements remain permanently included without changing historical SHA-256 baselines.

Keep requirements, implementation evidence, and execution priorities clearly separated.

Verify that a fresh Codex conversation can reconstruct the complete objective using only the version-controlled repositories.

Integrate the documentation through the established reviewed GitHub workflow.

Do not overwrite the active Pursuing Goal UI with a temporary attachment reference.

Provide a concise, self-contained replacement Pursuing Goal text referring to the permanent repository documents.

Continue the full VOLPAROSSA development objective autonomously after the amendment is safely consolidated.

**The ultimate goal is a fully integrated VOLPAROSSA Studio in which users can visually create, AI-assist, publish, update, and maintain websites using the shared decentralized DICN infrastructure, without compromising portability, security, privacy, or the original functionality of Silex.**
<!-- END STUDIO HOSTING REQUIREMENTS -->
