# Contributing to VOLPAROSSA

VOLPAROSSA welcomes documentation improvements, reproducible bug reports and complete,
reviewable feature slices. The current priority is a functional development alpha, not
release polish. Start with the [documentation guide](docs/README.md), then read
[AGENTS.md](AGENTS.md), the [architecture](docs/ARCHITECTURE.md) and the relevant section of
[implementation status](docs/IMPLEMENTATION_STATUS.md) before changing code.

For a first contribution, improve an unclear guide, reproduce an existing bounded example,
or propose a feature with a concrete user outcome and verification plan. Use
[issues](https://github.com/VOLPAROSSA/volparossa/issues) for non-sensitive questions and bugs;
follow [SECURITY.md](SECURITY.md) for vulnerabilities.

## Ground rules

- Preserve `client -> exactly one relay -> exit` on every path. Different parallel paths require
  different relays and the same exit.
- Do not label ordinary TCP as MPTCP or single-path QUIC as Multipath QUIC.
- Keep the agent unprivileged and the helper request schema typed, bounded, and free of arbitrary
  commands, paths, interface names, sysctls, and firewall text.
- Reject ambiguous, expired, replayed, unsupported, oversized, or policy-inconsistent input.
- Never add production private keys, accounts, analytics, remote telemetry or hidden update channels.
  The explicit authorized-update design is separate: only independently authorized releases,
  verified against established trust and without expanded installation privileges, may become
  client updates. Peer content and model output are not update authority. See
  [repository maintenance](docs/REPOSITORY_MAINTENANCE.md); this is not permission to install
  anything on a contributor's host.
- Do not add production logging or persistence of URLs, DNS history, payloads, full browsing
  hostnames, destination-IP history, or durable node-to-browsing links.
- Do not modify a development host's routes, DNS, firewall, interfaces, namespaces, sysctls, or VPN.
  Privileged tests must use disposable namespaces, preview changes, trap interruption, and prove
  complete cleanup.
- License original VOLPAROSSA contributions as GPL-3.0-only and preserve all applicable third-party notices.

## Workflow

1. Describe the user-visible outcome, invariant and failure mode the change addresses.
2. Add focused verification for the behavior being changed. Parsers, signatures, policy,
   selection, framing and cleanup need tests of their relevant boundaries.
3. Keep every externally controlled length, allocation, peer/session count, timeout, and queue
   bounded.
4. During iteration, run the narrowest relevant formatter/compile check and functional smoke.
   Documentation-only changes need link, structure and claim checks, not a fresh network trial.
   Use the broad gate at integration checkpoints/CI and release preparation, rather than
   repeating it for every small edit:

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
