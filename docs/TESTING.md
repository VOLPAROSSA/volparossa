# Testing and acceptance

Unit tests establish parser and state-machine properties; they do not establish dataplane privacy or
multipath. Real dataplane claims require a disposable Debian 13 network-namespace topology,
independent kernel/native counters, packet captures, fault injection, cleanup, and a machine-readable
acceptance report.

## Unprivileged quality gate

```sh
cargo fmt --all --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
./scripts/check-rust-dependencies.sh
./packaging/test-collect-cargo-licenses.sh
```
The dependency script verifies exact crates.io archives, reviewed local
security patches, unchanged license files, complete vendor-tree hashes, and
the locked feature graph before running cargo-deny's license/ban/source checks
and a no-fetch `cargo-audit >= 0.22.1` scan. It records the local RustSec
database commit. Debian's cargo-deny 0.18.3 rejects CVSS 4.0 vectors; a
successful licenses/bans/sources subset alone does not replace the advisory
gate. See `third_party/rust/README.md` for the narrowly scoped local
backports and scanner exemptions.

The package-license regression proves both reviewed path overrides enter the
distributable notices while workspace and arbitrary path packages do not.

Focused unit/property tests cover canonical protobuf, all eighteen signed
control payloads, signatures/key binding, replay/TTL/skew, advertisements, two-hop forwarding,
direct datapath-relay framing, policy normalization/thresholds, peerstore privacy,
selection/diversity/capacity, reservation expiry and exact retries, route contexts/LRU,
helper/native/local frames, configuration, MPTCP netlink, WireGuard plans, schedulers, and
idempotent cleanup planning. These tests are not dataplane or privacy evidence.

`volparossa-discovery/tests/reservation_rpc.rs` establishes authenticated Noise/Yamux connections
among three real libp2p swarms over process-local MemoryTransport. It proves a client cannot send an
exit request directly to the exit, then carries the same canonical wrapper client -> control relay
-> exit and the signed response back. Its probe case proves
`/volparossa/datapath-relay/3` framing while the production handler returns a received
fail-closed `Unavailable` without exposing a fake probe event.

Discovery unit tests prove `/volparossa/advertisement/3` canonical bounds and reject request
versions 1, 2, and future values plus the retired direct-reservation v2 identifiers. Protocol,
reservation, exit, and relay tests cover fresh session identities, hold/permit/finalize/grant/
confirmation/receipt binding, exact successful retries, replay/expiry, capacity rollback, and
removal of permanent client Peer ID fields. Test-only exact evidence verifiers do not make a real
probe producer.

The production agent route state machine is not yet proven end to end. Helper `Prepare`, real
two-leg probing, client ingress, and live relay/exit publication remain fail-closed. None of the
tests above creates a WireGuard device or host route or satisfies a privileged acceptance case.

Fuzz targets are required for every externally controlled parser: all eighteen signed v3 control
payloads, advertisement-v3, exit-forwarding-v3, datapath-relay-v3, policy manifests, local/helper/
native control frames, `OPEN_TCP`, UDP authorization, TLS ClientHello, QUIC
Initial/classification, peerlinks, and configuration. Inputs must reach the 512 KiB frame boundary
and at least one byte beyond it. Corpora contain only synthetic metadata. Enforce allocation,
recursion, field, list, frame, timeout, peer, session, buffer, and replay-cache bounds. Parser
compilation or a short smoke run is not evidence of sustained fuzzing.

The A0 regression tests for tags 17 and 18 are likewise not sustained fuzz evidence; their
request, receipt, wrapper, and nested-envelope parsers remain under this open fuzzing requirement.

## Privileged topology safety contract

The topology runs only in disposable Linux namespaces connected by veth pairs. It may create
temporary namespace-scoped nftables rules, routes, addresses, WireGuard devices, MPTCP endpoints,
and `tc netem` limits. The runner must:

1. print exact proposed names, veths, address ranges, tables/marks, rules, and limits;
2. reject collisions and non-Debian/non-Linux prerequisites;
3. capture host route/rule, DNS, nftables, link, and namespace state before changes;
4. ask for confirmation unless a clearly named CI-only opt-in is set;
5. trap exit, error, INT, TERM, and HUP and call idempotent scoped cleanup;
6. avoid host sysctl, DNS, default-route, firewall, VPN, and physical-interface changes;
7. capture the same host state afterward and fail on any unrelated delta.

Never run a root script whose targets contain unresolved variables, globs, broad prefixes, or the
host namespace. Diagnostic `ip`, `wg`, `nft`, `ss`, `tcpdump`, and `tc` output is allowed in tests;
product behavior uses netlink/UAPI.

## Required nodes and links

The single command topology contains a client, two replaceable bootstrap peers, at least six relays,
two exits, allowed and denied TCP/UDP/HTTP3 destinations, independent operator/ASN/prefix
metadata, constrained paths, NAT cases, and a policy signer/fixture boundary. Each physical leg has a
distinct veth/network, and packet captures occur inside relevant namespaces, never on an unrelated
host interface.

## Acceptance cases

| ID | Required evidence |
|---|---|
| A01 | Discovery and advertisement/selection continue after either bootstrap contact is removed. |
| A02 | A real TCP download has at least two `IPPROTO_MPTCP` subflows through different relays, both with increasing data counters. |
| A03 | Constrained MPTCP paths aggregate beyond the measured capacity of one path. |
| A04 | Removing an active MPTCP relay does not terminate the application flow. |
| A05 | UDP echo uses one relay and packet/routing evidence proves no direct client-exit path. |
| A06 | Browser HTTP/3 inside MASQUE uses one genuine MPQUIC connection with at least two unique-byte-carrying relay paths. |
| A07 | Removing one MPQUIC relay avoids unnecessary inner-QUIC interruption and no downgrade/direct route occurs. |
| A08 | An allowed test domain/protocol/port succeeds. |
| A09 | Unlisted domain, raw IP, SNI mismatch/missing SNI, and forbidden port all fail closed. |
| A10 | ECH or otherwise unverifiable destination identity fails closed. |
| A11 | Relay capture shows only client/relay/exit overlay traffic, not the Internet destination in the routed outer layer. |
| A12 | Exit-namespace packet capture sees incoming control/datapath relays rather than the client's public address or direct connection. |
| A13 | Client packet capture plus routes prove no direct client-exit control or dataplane path. |
| A14 | Forced agent/helper/native crashes followed by cleanup remove all owned namespaces, links, routes, MP paths, sockets, and rules. |
| A15 | Original host routes, DNS, firewall, links, sysctls, and VPN state are unchanged after the run. |

An acceptance case passes only when its evidence is automatically checked. A configured interface,
handshake, signature, service-state transition, or scheduler decision without unique delivered bytes
does not count as a data-carrying path. A12 and A13 specifically require packet-capture evidence;
unit tests, route plans, and the absence of a direct-exit method cannot substitute for those
captures.

## Machine-readable report

Every acceptance invocation emits exactly one JSON document on standard output. Human explanation
goes to standard error. The normative structural contract is
`tests/integration/acceptance-report.schema.json`; the repository also provides the stricter semantic
validator `tests/integration/validate-report.sh`.

Every report lists A01 through A15 exactly once. A case can be `PASS` only with one or more
content-addressed evidence objects. An overall `PASS` additionally requires an attempted and
completed execution, captured and unchanged host state, complete cleanup, zero remaining owned
objects, and all fifteen cases passing. Evidence paths are relative, may not traverse upward, and
must identify their producer check and SHA-256 digest.

The current default commands are safe previews:

```sh
just test-integration
just test-netns
just test-mptcp
just test-mpquic
just benchmark
```

The acceptance and benchmark drivers required to exercise real datapaths are not present yet. The
production probe producer, helper backend, agent route orchestration, and client ingress are also
blocked. Consequently these commands intentionally emit `overall: "BLOCKED"`, mark unexecuted work
`SKIPPED` with a reason, and exit 77. Exit 64 denotes invalid arguments and 69 denotes a missing
local report prerequisite. Exit 77 is not a passing or successful acceptance result.

`tests/integration/test-harness.sh` is unprivileged and exercises argument parsing, schema
semantics, `--only mptcp|mpquic` selection, fail-closed execution requests, and non-mutation
previews with command shims. The root-capable topology currently refuses both arbitrary commands
and standalone cleanup. Privileged execution stays blocked until a fixed reviewed driver can own
setup, evidence finalization, and teardown in one trapped process.

## Native and performance gates

Native mqvpn/xquic runs its pinned upstream tests, warnings-as-errors build where feasible, ASan/
UBSan, and Valgrind. Interoperability fixes are patches recorded in `THIRD_PARTY_LICENSES.md`.

Benchmarks cover one/four relays; TCP/MPTCP and QUIC/MPQUIC; RTT spread, loss, jitter, capacity,
WireGuard overhead, setup/discovery/failover; CPU, memory, context switches; and net user versus
physical tunnel data. Benchmark results never substitute for functional/privacy acceptance.

The blocked preview reports are harness evidence only. They do not satisfy A01–A15, native
interoperability, fuzzing, performance, privacy, cleanup, or real-network acceptance.
