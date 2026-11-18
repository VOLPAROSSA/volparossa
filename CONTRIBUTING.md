# Contributing to VOLPAROSSA

Contribute reproducible bug reports, documentation improvements and complete,
reviewable feature slices toward the full DICN development alpha. Start with the
[documentation guide](docs/README.md) and [current status](docs/IMPLEMENTATION_STATUS.md),
then read the affected requirements, contracts and application instructions.

The organization-wide [contribution guide](https://github.com/VOLPAROSSA/.github/blob/main/CONTRIBUTING.md),
[Code of Conduct](https://github.com/VOLPAROSSA/.github/blob/main/CODE_OF_CONDUCT.md),
[support](https://github.com/VOLPAROSSA/.github/blob/main/SUPPORT.md) and
[accessibility](https://github.com/VOLPAROSSA/.github/blob/main/ACCESSIBILITY.md) policies apply.
Use [Discussions](https://github.com/VOLPAROSSA/volparossa/discussions) for general or
cross-project questions and [issues](https://github.com/VOLPAROSSA/volparossa/issues)
for actionable work. Report vulnerabilities through [SECURITY.md](SECURITY.md).

## Prepare a contribution

1. Choose a concrete outcome and inspect the relevant source/evidence. A failed
   trial, old pending job or unmerged branch is not accepted behavior.
2. Before a build, follow [read-only prerequisites](docs/development/OPERATIONS.md#read-only-prerequisites)
   and the [build instructions](docs/development/OPERATIONS.md#build-and-package).
   `./scripts/check-system.sh` inspects without installing or changing networking;
   package installation is a separate explicit operation.
3. Follow the [shared workflow](docs/development/CODEX_WORKFLOW.md). Preserve
   unrelated and unpublished work, assign non-overlapping write scopes, and make
   changes reviewable. Coding clients select suitable models/tools dynamically;
   no particular vendor, model or agent arrangement is required.
4. Select verification for the changed behavior. Documentation needs link and
   technical-claim checks; code needs focused checks of its changed boundaries.
   Real network claims require disposable namespaces or the documented VM,
   machine-readable acceptance and complete cleanup, never the active host network.

## Engineering contract

[AGENTS.md](AGENTS.md) is the canonical engineering, privacy, authority and host-safety
contract for contributions. In particular, preserve the one-relay/exit path and
real transport semantics, bounded fail-closed inputs and privilege separation;
protect keys and browsing metadata; introduce no telemetry or hidden update authority.
Authorized releases still need independent verification and cannot expand installer
privileges. No contribution authorizes installing or changing a development host.
Never weaken a fail-closed boundary to make a test pass; document a real platform
limitation with exact versions and reproducible evidence.

New control-plane/orchestration code uses Rust. Keep necessary upstream native code
behind the documented isolated boundaries rather than duplicating that control plane.
Pin inputs, preserve third-party licenses/notices, and record origin/patches in
[THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md). Original contributions use GPL-3.0-only;
unpinned Git dependencies and unchecked prebuilt binaries are not accepted.

## Verify and document

During development, run the narrowest relevant formatter/compile check and functional
smoke, including failure/cleanup cases affected by the change. The [testing guide](docs/development/TESTING.md)
contains focused commands and the broad integration/release gate; do not repeat that
whole gate for each small edit. Dependency changes need `./scripts/check-rust-dependencies.sh`;
native changes need the appropriate upstream and sanitizer/Valgrind checks. Preserve
existing exact-source results without treating them as proof for another source.

State the commands, source, results and remaining limitations in the PR. For runtime
results include relevant OS, architecture, kernel and toolchain versions. Privileged
acceptance also needs host route/DNS/firewall observations and cleanup results. Redact
keys, private endpoints, full browsing hostnames, destinations and payloads. Update
[implementation status](docs/IMPLEMENTATION_STATUS.md) only to match passing evidence;
leave unproved behavior open.

Keep requirements in [GOAL](docs/development/GOAL.md), technical contracts in the
matching architecture/network/service/application/privacy topic, and dated detailed
evidence in the archive or linked receipt. Use the existing documentation index;
avoid parallel plans and copies of the same rules. A new milestone never shrinks scope.
When moving documentation, update Markdown links, code includes, packaging inputs and
fixture source paths. Preserve installed filenames and exact historical source URLs.
A changed guide may alter a future model-trial input; it does not rewrite earlier results.
