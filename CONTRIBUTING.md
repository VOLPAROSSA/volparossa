# Contributing to VOLPAROSSA

VOLPAROSSA values small, reviewable changes backed by evidence. Read `AGENTS.md`, the
[architecture](docs/ARCHITECTURE.md), and the [implementation status](docs/IMPLEMENTATION_STATUS.md)
before changing code.

## Ground rules

- Preserve `client -> exactly one relay -> exit` on every path. Different parallel paths require
  different relays and the same exit.
- Do not label ordinary TCP as MPTCP or single-path QUIC as Multipath QUIC.
- Keep the agent unprivileged and the helper request schema typed, bounded, and free of arbitrary
  commands, paths, interface names, sysctls, and firewall text.
- Reject ambiguous, expired, replayed, unsupported, oversized, or policy-inconsistent input.
- Never add production private keys, accounts, analytics, remote telemetry, update channels, or
  automatic code downloads.
- Do not add production logging or persistence of URLs, DNS history, payloads, full browsing
  hostnames, destination-IP history, or durable node-to-browsing links.
- Do not modify a development host's routes, DNS, firewall, interfaces, namespaces, sysctls, or VPN.
  Privileged tests must use disposable namespaces, preview changes, trap interruption, and prove
  complete cleanup.
- License original VOLPAROSSA contributions as GPL-3.0-only and preserve all applicable third-party notices.

## Workflow

1. Describe the invariant and failure mode the change addresses.
2. Add the narrowest unit/property test first for parsers, signatures, policy, selection, framing,
   or cleanup logic.
3. Keep every externally controlled length, allocation, peer/session count, timeout, and queue
   bounded.
4. Run focused tests while iterating, then run:

   ```sh
   ./scripts/check-shell.sh
   cargo fmt --all --check
   cargo clippy --workspace --all-targets --all-features -- -D warnings
   cargo test --workspace --all-features
   ./scripts/check-rust-dependencies.sh
   ```

5. For dataplane work, include a disposable network-namespace acceptance test and machine-readable
   evidence of actual data-carrying MPTCP subflows or MPQUIC paths.
6. Update documentation and check an item in `docs/IMPLEMENTATION_STATUS.md` only after its stated
   verification passes.

Do not weaken a fail-closed default to make a test pass. If a kernel or Debian limitation is real,
capture its exact version and reproducible evidence, then document the bounded alternative.

## Native code and dependencies

Rust is required for new control-plane and orchestration code. Native C/C++ belongs only in the
isolated MPQUIC integration where upstream mqvpn/xquic requires it. Pin exact source revisions,
record origin/license/patches in `THIRD_PARTY_LICENSES.md`, build from source, and run upstream tests
plus ASan/Valgrind. New dependencies must pass `./scripts/check-rust-dependencies.sh`; unpinned Git
dependencies and prebuilt binaries are not accepted.

## Reporting test results

State the OS, architecture, kernel, Rust version, exact command, and result. Privileged integration
reports must also include pre/post digests for host routes, DNS, and nftables, cleanup results, and
the generated acceptance report. Redact keys, full hostnames, destination addresses, and payloads.
