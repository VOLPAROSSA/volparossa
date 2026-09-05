# VOLPAROSSA

> **Development status (pre-alpha):** VOLPAROSSA v1 is under construction and is **not yet a
> usable VPN**.
> The control-plane foundations in this repository must not be mistaken for a verified dataplane.
> See the evidence-based [implementation status](docs/IMPLEMENTATION_STATUS.md) before building,
> installing, or enabling a role.

VOLPAROSSA is an open-source, decentralised VPN overlay designed for Debian 13 amd64. Its target
low-latency path is always:

```mermaid
flowchart LR
    C[Client]
    R1[Voluntary relay A]
    R2[Voluntary relay B]
    E[One policy-enforcing exit]
    D[Allowed destination]

    C == path 1: WireGuard ==> R1
    R1 == path 1: separate WireGuard link ==> E
    C == path 2: WireGuard ==> R2
    R2 == path 2: separate WireGuard link ==> E
    E --> D
```

Every parallel path uses exactly one distinct relay between the same client and exit. The normal
client dataplane never connects directly to an exit. TCP is intended to use real Linux MPTCP over
the selected relay paths; ordinary UDP uses a protected single-path MASQUE association; browser
QUIC is intended to use genuine Multipath QUIC carrying MASQUE CONNECT-IP traffic over at least two
data-carrying paths.

## What it is—and is not

VOLPAROSSA is intended to be a volunteer-operated overlay with local peer reputation,
capability-indexed libp2p discovery, short-lived reservations, ephemeral WireGuard links, and a
threshold-signed destination whitelist enforced at every exit.

It is not an anonymity guarantee, a Tor replacement, a generic open proxy, a commercial VPN, or a
way to bypass the whitelist. It deliberately has no payment system, token, blockchain, GUI, cover
traffic, artificial delay, packet duplication, FEC, or automatic exit enablement. A global observer
who sees both ends may correlate this low-latency traffic.

## Components and roles

- `volparossa` is the user-facing CLI.
- `volparossa-agent` is the unprivileged control-plane and session service.
- `volparossa-helper` is the narrowly allowlisted privileged networking service.
- Every node runs the same software. Production client participation requires also offering relay
  AND exit service with nonzero capacity: use of the network includes contributing to it.
  Installation defaults to all roles off; enable participation explicitly after configuring the
  shared policy and contribution limits. Development fixtures can isolate roles for boundary tests.
- A relay forwards only a signed, expiring route ID between two dedicated WireGuard links. It must
  not offer host access or Internet egress.
- An exit is the only egress role. It resolves, pins, and enforces the same verified policy manifest
  before opening any destination flow.

The reciprocal participation requirement replaces optional client-only use as of 2026-09-05.
Combined-role native workers and privacy-preserving discovery are being integrated; a configuration
switch alone is not evidence that the all-combined-role topology already works.
Bootstrap contacts are replaceable user peers, not mandatory central infrastructure or authorities.

The detailed design is in [ARCHITECTURE.md](docs/ARCHITECTURE.md); wire formats are in
[PROTOCOL.md](docs/PROTOCOL.md).

## Safe development setup

The bootstrap script supports Debian 13 amd64 only. It reads package metadata, prints the exact apt
packages and candidates it found, and asks before installation. It never changes routes, DNS,
firewall rules, sysctls, interfaces, or namespaces.

```sh
./scripts/bootstrap-debian13-dev.sh --print-only
./scripts/bootstrap-debian13-dev.sh
./scripts/check-system.sh
cargo build --locked --workspace --all-features
```

Do not run network tests on the host network. Privileged integration tests belong in disposable
Linux network namespaces and must prove cleanup and unchanged host state. See
[TESTING.md](docs/TESTING.md).

## Installation and demo status

The repository contains candidate Debian packaging and hardened service definitions, but they are
not considered release-ready until the binaries compile, the package is reproduced on clean Debian
13, and the complete namespace acceptance suite passes. `just package-deb` and `just demo` may
therefore fail while their corresponding status items remain unchecked. Do not enable the systemd
services based on documentation alone.

When a verified release exists, the intended flow is:

```sh
just package-deb
sudo apt install ./dist/volparossa_0.1.0_amd64.deb
volparossa init
volparossa config validate
volparossa doctor
```

`init` must be run interactively and must never print the private identity. Relay or exit mode must
then be enabled explicitly; installing the package does not enable either role. Operational and
uninstall guidance is in [OPERATIONS.md](docs/OPERATIONS.md).

## Security warnings and known limitations

- This repository has not yet produced evidence for real MPTCP or Multipath QUIC data carriage.
- The native mqvpn/xquic component is pinned, source-integrated, and has passed a clean full-graph
  API-v6 ASan+UBSan run behind a bounded process boundary. API v6 correlates one role/process
  lifetime and each exact request, binds signed route provenance and request-binds one route socket
  for `AddPath` or listener-shaped descriptor for `StartExitSession`. Rust and the dormant native
  runtime validate its current socket flags and tuple before native closes it and fails closed. The
  runtime converts accepted wall expiry to a BOOTTIME deadline and uses a bounded, no-live-eviction
  process-local reservation/finalize ledger to reject pair replay and scope collisions. That ledger
  does not verify the signed bundle, cache general nonces, or survive process restart. The current
  same-UID socket is not authentication against an untrusted agent and no production caller exists.
  The native client now retains one immutable assignment with server `10.76.0.1/32`, client
  `10.76.0.2/32` through `10.76.0.254/32`, and optional client
  `fd76:6f6c:7062::2/112` through `fd76:6f6c:7062::fe/112`; it caps the MTU at 1280--1420 and
  independently enforces outbound-source and reverse-destination ownership. Helper origin,
  server-side allocation uniqueness/lifetime, assigned-address and namespace provenance, the exit
  backend, and disposable dataplane acceptance remain incomplete.
- Do not rely on the kill switch, whitelist enforcement, crash cleanup, or privacy properties until
  their acceptance checks are marked complete.
- Anti-Sybil diversity and local performance history can raise an attacker's cost but cannot
  cryptographically prevent Sybil participation.
- A relay and exit that collude can improve correlation; a global timing observer is outside the
  protection promised by this architecture.
- Local root can read process memory, keys, destinations, and traffic and can bypass the product.

Read the full [threat model](docs/THREAT_MODEL.md), [privacy design](docs/PRIVACY.md), and
[security reporting policy](SECURITY.md) before testing with sensitive data.

## Contributing and license

Original VOLPAROSSA code is licensed under GNU GPL v3.0 only. Third-party components retain their
own licenses; see [THIRD_PARTY_LICENSES.md](THIRD_PARTY_LICENSES.md). Contributions are welcome once
they follow [CONTRIBUTING.md](CONTRIBUTING.md), especially the evidence and host-safety rules.
