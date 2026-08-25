# Testing and acceptance

Unit tests establish parser and state-machine properties; they do not establish dataplane privacy or
multipath. Real dataplane claims require a disposable Debian 13 network-namespace topology,
independent kernel/native counters, packet captures, fault injection, cleanup, and a machine-readable
acceptance report.

## Unprivileged quality gate

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets --all-features -- -D warnings
cargo test --workspace --all-features
cargo fmt --manifest-path fuzz/Cargo.toml --all -- --check
cargo clippy --manifest-path fuzz/Cargo.toml --locked --offline --all-targets -- -D warnings
./scripts/check-rust-dependencies.sh
./packaging/test-collect-cargo-licenses.sh
```
The dependency script verifies exact crates.io archives, reviewed local
security changes, unchanged license files, complete vendor-tree hashes, and
the locked root and standalone fuzz feature graphs before running cargo-deny's
license/ban/source checks and no-fetch `cargo-audit >= 0.22.1` scans of both
lockfiles. It records the local RustSec database commit. Debian's cargo-deny
0.18.3 rejects CVSS 4.0 vectors; a successful licenses/bans/sources subset
alone does not replace the advisory gate. See `third_party/rust/README.md` for
the narrowly scoped local backports, single-backend Yamux hardening, and
scanner exemptions.

The package-license regression proves all three reviewed path overrides and
the exact `yamux 0.13.10` release-tag license fallback enter the distributable
notices while workspace and arbitrary path packages do not.

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
completed full-suite execution on Debian 13 amd64, complete source/time provenance, a created
topology, captured and unchanged host state, complete cleanup, zero remaining owned objects, and
all fifteen cases passing. MPTCP selects A02-A04/A14/A15 and MPQUIC selects A06-A07/A14/A15; a
successful subset remains overall `BLOCKED` with `PARTIAL_SUITE` because it is not full acceptance.

Evidence paths use bounded ASCII components below the report directory. The validator rejects
report or evidence symlinks, rehashes every readable regular evidence file, and compares its actual
SHA-256 with the report. A14 cannot pass without separate agent, helper, native, and owned-object
cleanup checks. A15 cannot pass unless fixed before/after evidence entries bind to present, equal
host-state digests. A case cannot pass or fail before a topology exists, and missing post-attempt
host or cleanup state is an `ERROR`, not a successful or merely blocked result.

The current default commands are safe previews:

```sh
just test-integration
just test-netns
just test-mptcp
just test-mpquic
just benchmark
```

An execute request must additionally include the explicit `--yes` acknowledgement after the
printed plan. Omitting or duplicating that acknowledgement is an argument error and cannot reach a
mutating path. The acknowledgement is not proof of safety: the fixed supervisor, environment gate,
ownership checks, teardown, and host-state comparison must all still succeed.

The acceptance and benchmark drivers required to exercise real datapaths are not present yet. The
production probe producer, helper backend, agent route orchestration, and client ingress are also
blocked. Consequently these commands intentionally emit `overall: "BLOCKED"`, mark unexecuted work
`SKIPPED` with a reason, and exit 77. Exit 64 denotes invalid arguments and 69 denotes a missing
local report prerequisite. Exit 77 is not a passing or successful acceptance result.

The Rust report-model tests compile the normative Draft 2020-12 schema and validate full, MPTCP,
and MPQUIC model reports against it. `tests/integration/test-harness.sh` is unprivileged and
exercises argument parsing, strict semantic and artifact validation, `--only mptcp|mpquic`
selection, false-PASS refusals, fail-closed execution requests, and non-mutation previews with
command shims. The root-capable topology entry point contains no dormant network mutator, refuses
arbitrary commands and standalone cleanup, and only prints the fixed future lifecycle plan.

The lifecycle protocol is separate from the acceptance result. Before its five bounded, canonical
frames, the outer sends one bounded canonical `LAUNCH_CONTEXT` transport-provisioning record over
a dedicated inherited unnamed channel. It contains only the random run ID, the three original-host
namespace identities, and the fixed topology-specification digest. It is not a lifecycle frame,
cannot authorize topology mutation, and malformed, missing, duplicated, or prematurely closed
provisioning never reaches `GO`. A separate inherited bidirectional channel then carries the five lifecycle
frames in one strict order. `BOOTSTRAP_READY` is an
attestation that the fixed inner worker must construct only after directly measuring that it is PID
1 in different network, mount, and PID
namespaces, with private mounts, the enumerated read-only pre-`GO` network baseline, handlers, and
the parent-death chain established before network-topology mutation. The outer independently
compares the three namespace identities with
its original host identities. Only then may it send the affine `GO` authorization. The current
early slice reaches that barrier and permits only one bounded private-`/run` root-and-slot,
two-transient-nsfs-pin, two-veth, four-address, exact parent-FORWARD-policy, link-activation, and
endpoint-route transaction with deletion-only link teardown and exact policy retirement; it does
not claim that the remaining configured topology lifecycle is implemented.
`TOPOLOGY_READY` attests to the run ID, fixed topology-specification digest, exact two run-bound
namespace identities, and the completed probe, all directly observed by that worker. The outer then
sends `STOP`; `FINISHED` must bind the SHA-256 of the exact `TOPOLOGY_READY` bytes and report
attempted cleanup. The outer independently reaps the complete sandbox and constructs the acceptance
report. EOF before `GO` explicitly means that no topology mutation was authorized; fixed pre-`GO`
bootstrap operations such as namespace creation, ID mapping, and private mounts may already have
occurred and must still be contained and reaped. EOF afterward requires cleanup. Missing,
malformed, reordered, duplicated, contradictory, or differently bound records fail closed. These
transient attestations are not A14 evidence and cannot themselves make any A01-A15 case pass.

After a real lifecycle-only run, normal teardown still leaves A14 `SKIPPED` with
`FORCED_CRASH_NOT_EXECUTED`. A15 alone may be `PASS` when two privacy-safe outer fingerprint
manifests are present, content-addressed, and exactly equal after the complete sandbox process tree
has been reaped. All selected datapath cases remain `SKIPPED` with `LIFECYCLE_ONLY`, so the report
and process result remain `BLOCKED`/77. The current blocked entry point has not produced that
evidence yet.

The test-only `volparossa-netns-runner` now owns an initial, deliberately early post-`GO`
containment slice. Its only transient topology is two otherwise-pristine network namespaces, their
kernel-default loopback/rules, their nsfs mounts, two fixed veth pairs, four fixed `/30` IPv4
addresses, four active link ends, two exact static `/32` endpoint routes, the exact kernel-created
qdisc and route side effects, and one run-bound generation-2 `inet` table containing the sole fixed
parent-FORWARD policy. While that policy is exact, the runner conditionally establishes
namespace-local IPv4 forwarding in PID 1's disposable parent network namespace and restores the
exact original record before policy retirement; the outer host setting remains unchanged. It
produces no packet-capture, probe, dataplane, or topology-readiness evidence. It re-executes only
`/proc/self/exe`,
once as the fixed launcher and once as namespace PID 1, with a distinct private selector for each role. It
clears both child environments, fences unrelated inherited descriptors, and uses three separate
unnamed descriptor-free `SOCK_SEQPACKET` outer-to-launcher channels plus one launcher-to-PID-1
bootstrap channel; the lifecycle endpoint is transferred affinely to PID 1. Exactly one
`LAUNCH_CONTEXT` is provisioned within a fixed child-side timeout. The launcher binds kernel peer
PID/UID/GID on all three outer channels to its live parent, requires the parent's executable inode
to match its own, accepts only the exact outer `--run` invocation, and installs a verified
parent-death `SIGKILL` before isolation. A launcher-selector invocation without that exact parent
contract, and a PID-1-selector invocation without its required namespace and channel contract, are
rejected.

The single-task launcher performs one direct `unshare` of anonymous user, mount, network, and
pending child PID namespaces. Before any child exists, the outer retains a pidfd and anchored
`/proc/<pid>` directory, pins the exact user, mount, network, and current PID namespace descriptors,
requires an empty child set, and proves that the existing `pid_for_children` magic link is in the
kernel-defined uninstantiated state. Only then does it write `deny` to `setgroups` and one exact
`0 <outer-id> 1` extent to each ID map; both sides independently read back those mappings and the
stable partial namespace set. The launcher then emits `MAPPINGS_VERIFIED`, but cannot spawn PID 1
yet. The outer repeats its anchored mapping readback and returns the affine `MAPPINGS_PINNED`
proceed record; EOF instead retires the launcher before a PID-namespace child can exist.

After that barrier the launcher makes exactly one second fixed `/proc/self/exe` invocation, which
becomes PID 1 in the pending namespace and remains blocked on a new private bootstrap channel. The
launcher and PID 1 perform an affine, run-bound provision, parent-death, liveness, execution,
private-mount, and EOF exchange. PID 1 independently requires PID 1/PPID 0, one task, mapped-root
credentials, the exact inherited namespace set, an empty environment, cwd `/`, and an armed
parent-death `SIGKILL`. The outer upgrades its launcher namespace pins only after the child exists
and independently proves the exact executable/selector, PID/PPID/nesting, mappings, namespaces,
empty descendant set, and sole launcher-child relation. Only after the outer returns its run- and
PID-bound `PID1_PINNED` acknowledgement does PID 1 recursively make the inherited mount tree
private. It then uses the descriptor-based Linux mount API to attach a 16 MiB, 4096-inode,
mode-0700 tmpfs at `/run` with `nosuid,nodev,noexec`, followed by a separately instantiated procfs
at `/proc` with the same hardening flags. No caller-selected path, mount option, command, or
fallback is accepted.

Linux 6.12 supports tmpfs `noswap`, but deliberately rejects changing swapability from this
unprivileged user-namespace boundary. This slice therefore proves that `/run` remains empty and
places no key, credential, or token material there. Future filesystem-backed secret material stays
forbidden until the runner can independently prove a non-swappable store without broadening the
unprivileged supervisor boundary.

PID 1 binds the visible mount IDs to a bounded mountinfo parse, requires every inherited mount to
have no propagation relationship, proves `/run` is the new bounded empty tmpfs, and proves that
private procfs exposes exactly PID/task set `{1}` with no child. It retains root, `/run`, and `/proc`
descriptors and repeats that proof after the outer acknowledgement and immediately before exit.
The outer independently reads the still-live PID through its pre-mount pidfd and anchored host
`/proc/<pid>` directory, matches visible `statx` mount IDs to mountinfo, checks tmpfs type, capacity,
inode bound, mode and mapped ownership, and matches `/proc/1/ns/pid` to the retained PID namespace.
Only then is `PRIVATE_MOUNTS_VERIFIED` returned.

Before any child or fallback-reaper thread exists, the outer requires exact default inherited
HUP/INT/TERM actions, a waitable default CHLD action, and an empty inherited signal mask. It then
blocks exactly HUP, INT, TERM and CHLD and owns a nonblocking close-on-exec `signalfd`.
PID 1 inherits that exact mask and, before reporting private-mount readiness, installs fixed real
HUP/INT/TERM emergency handlers. Normal delivery remains synchronous through `signalfd`; an
unexpectedly unblocked managed signal can only make the emergency handler call `_exit(128 +
signal)`. The outer binds its independent readback to the retained pidfd and anchored proc
directory: `SigBlk` is exactly `0000000000014003`, managed bits are absent from `SigIgn`, `SigPnd`
and `ShdPnd`, and `SigCgt` is exactly `0000000000004443`. That caught set is the `0x4003` managed
mask plus the `0x0440` process-start SIGBUS/SIGSEGV stack-overflow baseline of the repository-pinned
Rust 1.85.0 runtime on Debian 13 amd64, not a Linux ABI constant; the audited UAPI separately reads
back the exact managed handler addresses, flags and masks.

After `PRIVATE_MOUNTS_VERIFIED`, PID 1 directly proves the enumerated read-only pre-`GO` network
baseline, repeats its mount/runtime/signal proofs, and emits one canonical `BOOTSTRAP_READY` over
the affinely transferred lifecycle endpoint. The frame is bound to the run and PID 1's measured
network, mount, and PID namespace identities. The outer parses that actual frame, requires all
three identities to match its retained PID-1 namespace pins, repeats the live mount and signal
proofs, and accepts the frame through the strict outer lifecycle state. Only then does it send
one canonical `GO`. PID 1 consumes the resulting affine `MutationAuthorization` and immediately
revalidates the complete pristine network baseline before the first filesystem mutation. The
production ownership transition operates only through retained directory descriptors: it creates
exactly `/run/netns` and `/run/volparossa-netns-runner/<run_id>` at mode 0700 plus two run-derived,
empty namespace slots at mode 0000. It proves their exact entry set and retained identities. One
fixed PID-1 task then creates distinct network namespaces A and B, restoring its exact parent
network namespace after each excursion. Audited `open_tree` and `move_mount` calls publish each as
an exact run-derived nsfs pin. The runtime proves their type, owning user namespace, distinct
object and mount identities, visible read-only-pin joinability, and the hidden-slot/visible-pin
dual view. Its active mountinfo proof is the exact original bounded baseline plus exactly two
known mount-ID/path/nsfs/no-propagation additions beneath the private `/run` mount; it is not an
independent assertion about every possible nsfs root or option field. A read-only visitor joins
each visible pin, runs the complete pristine RTNL, IPv4-forwarding, and zero-nftables-table proof,
and restores the exact parent after each visit. PID 1 then sends exactly two `RTM_NEWLINK` requests
with `NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`. Each request derives its parent name from
the run ID, fixes MTU 1500, TXQLEN 1000, and one TX/RX queue on both ends, and places peer `eth0`
directly in the exact retained target namespace through `IFLA_NET_NS_FD`; there is no
create-then-move fallback. The affine owner retains the target nsfs identity plus the exact fresh
parent/peer indices. Independent bounded snapshots then require parent `lo+vpa*+vpb*`, endpoint A
`lo+eth0`, and endpoint B `lo+eth0`, with exact veth type, down flags, peer relations, namespace
lineage, link attributes, unique locally administered MACs, exact zero fresh-link statistics and
ifmap, unchanged non-link state, IPv4-forwarding record, qdisc state, and empty nftables baseline.
PID 1 then borrows that pair owner into one affine `AuthorizedIpv4Addresses` sub-transaction and
sends exactly four `RTM_NEWADDR` requests with
`NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`. Every address, `/30` prefix, interface
label/index, namespace identity, scope, permanent lifetime, and rollback target is derived from
retained authority: parent A `10.241.1.1/30`, endpoint A `10.241.1.2/30`, parent B
`10.241.2.1/30`, and endpoint B `10.241.2.2/30`. All four veth ends initially remain down.
Independent parent/A/B snapshots admit exactly those four address records and the four
kernel-created local-table `/32` routes coupled to them, while requiring every other route and
RTNL object, qdisc observation, IPv4-forwarding record, and nftables baseline to remain unchanged.
PID 1 then sends four separate bounded `RTM_NEWLINK` requests that change only IPv6
address-generation mode to `none`; ACK/readback is followed by a separate exact four-end proof
barrier. Before any link-up request, PID 1 derives one policy expectation only from the retained
run and canonical A/B veth lineage. One generation-pinned atomic `NETLINK_NETFILTER` transaction
installs a run-derived `inet vpl_<run_id>` table, one `filter` base chain named `forward` at the
`inet` forward hook with priority 0 and policy drop, one exact IPv4 ICMP echo-request accept rule
from endpoint A (`10.241.1.2`) to endpoint B (`10.241.2.2`), and only its exact reverse echo-reply
accept rule. Fresh full-ruleset observation proves exactly that semantic state at generation 2.
With that policy active and all four ends still down at IPv6 addrgen mode `none`, PID 1 uses its
retained private-proc descriptor to establish canonical `1\n` in the fixed parent
`/proc/sys/net/ipv4/ip_forward` record. It requests exactly one bounded two-byte write when the
retained original is `0\n`; an original `1\n` is freshly re-read and adopted without a write. It
next activates all four ends with separate link-up requests. Exact converged parent/A/B
observations require carrier-up `noqueue` links, no IPv6 addresses, four local `/32`, four
connected `/30`, four high-broadcast `/32`, and four local-table IPv6 `ff00::/8` multicast routes.
Only temporary stable kernel snapshots may be retried inside the same two-second absolute
deadline; the final verifier remains exact. Those admitted routes remain kernel side effects.
The generation-2 policy is freshly re-proved across each topology transition. PID 1 freshly
reverifies the complete active state and sends exactly two bounded raw
`RTM_NEWROUTE` requests: endpoint A `10.241.2.2/32 via 10.241.1.1 dev eth0` and endpoint B
`10.241.1.2/32 via 10.241.2.1 dev eth0`. Both use
`NLM_F_REQUEST|NLM_F_ACK|NLM_F_CREATE|NLM_F_EXCL`; the route header is exactly `AF_INET` `/32`,
main, `RTPROT_STATIC`, universe, unicast, flags zero, and the attributes are exactly
`RTA_TABLE=254`, `RTA_DST`, `RTA_GATEWAY`, and `RTA_OIF`. Retained namespace and pair authority
canonically supplies every value. Exact parent/A/B observations require an unchanged parent and
exactly the corresponding authorized route in each endpoint. A non-exact sibling or extra object
fails closed, and any possibly sent request retains deletion-bound authority even after an
ambiguous ACK/readback. No `RTM_DELROUTE` request or encoder exists. PID 1 directly deletes veth B
followed by A as the sole route-removal mechanism. Once a link request may have been sent, teardown
never tries to restore link-down/EUI-64 state and never runs ordinary per-address rollback. Both
route owners and every lower address and pair owner remain armed. After direct veth B/A deletion,
PID 1 restores the exact retained original parent `ip_forward` record while the exact generation-2
policy remains active: an original `0\n` causes one bounded two-byte restore write, while an
original `1\n` requires no write. It then proves all three namespaces byte-exactly equal to the
retained enumerated network baselines for the restored phase. PID 1 deletes only the freshly
observed table handle with a generation-pinned atomic transaction and requires a fresh complete
ruleset observation to prove semantic emptiness at generation 3. The final network proof binds the
restored RTNL, proc, and endpoint state to that generation-3 nftables result. A prevalidated
infallible retirement barrier disarms the route, address, and pair owners only after those final
proofs. This restoration claim covers only the fixed `ip_forward` record. Linux may reset related
per-device IPv4 configuration when forwarding changes; those other devconf values are not
exhaustively enumerated here, and their complete removal relies on destruction of the disposable
parent network namespace after its last reference closes. This slice does not separately observe
that destruction.
It ensures every detached-clone and transient visible-pin
descriptor is closed before ordinarily unmounting nsfs B then A with `UMOUNT_NOFOLLOW`, proves the
hidden empty slots and original mountinfo baseline are restored, and then rolls back slot B, slot A,
the per-run directory, the workspace root, and the netns root. Required directory `fsync` barriers
make every completed removal explicit. The proof removes every owned mount and link plus every
transaction-retained descriptor reference; it relies on kernel reference counting rather than
claiming to observe namespace destruction after the last reference closes.

After restoring the affine `PristineRun` state, PID 1 repeats its network, mount, runtime, and
signal proofs and sends one internal canonical `MUTATION_ROLLBACK_COMPLETE` record through the
launcher. The outer accepts and run/PID-binds it, then independently proves that the private
`/run` is empty again. Only then does the outer send exact TERM through the retained PID-1 pidfd.
PID 1 must consume that actual `signalfd` record and return one canonical run-, PID- and
signal-bound `MANAGED_SIGNAL_OBSERVED` through the launcher, which forwards the host-PID-bound
`PID1_SIGNAL_OBSERVED`. Once the outer accepts that observation and repeats the live signal proof,
it closes the lifecycle channel. Because `GO` was consumed, both lifecycle states require that EOF
to mean `CleanupRequired`; it can no longer mean `NoTopologyMutationAuthorized`. PID 1 then repeats
its proofs, exits 77, and is exactly reaped by the launcher and outer. Failure before the internal
rollback checkpoint proves bounded process containment only, not completed mutation rollback.

That fixed readiness baseline contains exactly one down `lo` link at ifindex 1 with loopback-only
flags, MTU 65536, transmit queue length 1000, `noop` qdisc, default link mode and group, zero
address/broadcast/promiscuity/all-multicast/protocol-down state, IPv6 EUI-64 address-generation
mode, GSO segment limit 65535, and GSO/GRO plus IPv4 GSO/GRO size limits 65536. It has no link
relationship, alias, alternate name, link-info, or attached XDP program. It
contains no addresses, routes, ordinary or proxy neighbours, nexthop objects, or unexpected qdisc
records. Its
routing-policy database is exactly IPv4 priorities 0/local, 32766/main, and 32767/default plus
IPv6 priorities 0/local and 32766/main. Each complete observation reads the fixed namespace-local
`/proc/sys/net/ipv4/ip_forward` record through the retained private-proc descriptor, accepts only
canonical `0\n` or `1\n`, and binds both the procfs object identity and value across the RTNL
snapshot. This readiness observation does not write the record; the later `GO`-authorized,
policy-bound transition described above may conditionally do so. A bounded read-only
`NETLINK_NETFILTER` sequence
requires generation 1 immediately before and after complete table, chain, rule, set, object, and
flowtable dumps, all of which must be empty. PID 1 repeats the complete observation immediately
before the authorized write and again after root/slot rollback; every pinned component must match,
while retained mount, runtime, and signal proofs bracket both barriers.

The production raw-`NFNETLINK` writer and strict observer implement the exact lifecycle forward
policy: one run-derived `inet vpl_<run_id>` table, one `filter` base chain named
`forward` at the `inet` forward hook with priority 0 and policy drop, one exact IPv4 ICMP echo
request tuple from endpoint A (`10.241.1.2`) to endpoint B (`10.241.2.2`), and only its exact echo
reply tuple in the reverse direction. Its only mutations are the bounded generation-pinned atomic
install transaction and the later handle-only table deletion; strict capped ACK binding and fresh
full-ruleset reconciliation cover every possibly sent request. Disposable namespace tests exercise
the production writer and prove the complete observed lineage from empty generation 1, through that
exact policy at generation 2, back to a semantically empty ruleset at generation 3. They record
canonical `0\n` or `1\n` before mutation and prove the value is byte-identical afterward. Extra or
altered tables, chains, rules, expressions, hooks, policies, tuples, verdicts, ACKs, handles, or
generations fail closed. This is real configuration and cleanup proof, but it is not forwarding,
packet-behaviour, probe, datapath, or acceptance evidence.

The readiness observation does not claim that forwarding is disabled and makes no pre-`GO`
forwarding-setting request. A separate fixed proc writer can target only the descriptor-pinned
parent-namespace `ip_forward` record, accepts only canonical `0\n` or `1\n`, performs at most one
two-byte write per transition, and returns affine reconciliation authority after a possibly written
request. After a possibly written enable, any stable result other than the exact enabled target,
including the original value, stays indeterminate and aborts fail closed. It has no general sysctl
surface. Neither proof claims that every firewall/netfilter
facility is empty.
Qdisc records are enumerated so an ingress/`clsact` hook cannot hide behind link qdisc name
`noop`; traffic-control classes, filters, and chains are not separately catalogued because this
slice admits no non-baseline qdisc on which they could attach. Other netconf, address-label,
neighbour-table parameter, conntrack, ipset,
NFQUEUE/NFLOG, legacy-xtables, and independent-hook state is outside it. A read-only GET or the
fixed writers may cause ordinary kernel module loading. The runner has no general sysctl or
general nftables mutation API: it can change only the fixed forwarding record and install or retire
only the exact policy above. A later
topology driver must pin every additional setting it relies on or extend this proof before packets
are sent.

The strict positive outer bootstrap exchange is `NAMESPACES_CREATED`, `MAPPINGS_INSTALLED`,
`MAPPINGS_VERIFIED`, `MAPPINGS_PINNED`, `PID1_SPAWNED`, `PID1_PINNED`, `PRIVATE_MOUNTS_READY`,
`PRIVATE_MOUNTS_VERIFIED`, `MUTATION_ROLLBACK_COMPLETE`, `PID1_SIGNAL_OBSERVED`, and
`PID1_REAPED`. The exclusive mount-policy branch substitutes `PRIVATE_MOUNTS_UNAVAILABLE` for the
two positive mount records. Only `EPERM` or `EACCES` from an exact fixed mount-UAPI operation may
take that branch; malformed state, missing targets, unsupported APIs, invalid options, resource
failures, and failed readback remain internal errors. Other fixed
kernel-policy denials return separate honest `BLOCKED` outcomes when required parent, namespace,
mapping, or outer PID-1 proof is unavailable, without fallback. A pre-isolation parent-proof or
namespace-policy denial uses a bounded two-channel half-close handshake: the launcher advertises
both EOFs but cannot exit until the outer acknowledges the control EOF, so early `SIGCHLD` never
races the admitted blocked result. Only the outer-owned containment deadline bounds that wait; the
launcher cannot time itself out before acknowledgement. If the outer PID-1 pin is
unavailable after spawn, the launcher sends one run-bound `ABORT_BEFORE_PRIVATE_MOUNTS` record to
PID 1, proves lifecycle EOF, and reaps it without issuing a mount instruction. A generic green CI
job may therefore prove only fail-closed behaviour; the complete positive path requires the
explicit `BlockedAfterForwardPolicyTeardown` outcome on the Debian 13 acceptance host:

The portable unit suite runs the live RTNL and read-only NFNETLINK collectors plus adversarial
wire/parser and RTNL link/object cases when unprivileged user/network namespaces are available.
Disposable live cases install both `clsact` and `ingress` qdiscs through bounded RTNETLINK and
prove that the collector sees and rejects them. A separate disposable live round trip installs one
fixed `/30` address on a down veth, proves its exact address record and kernel-created local-table
`/32` route, removes it, and requires byte-exact restoration of the retained down-veth snapshot.
Another disposable round trip sets addrgen mode `none`, activates both ends, retains the exact
carrier/qdisc/address/route requirements through bounded convergence, directly deletes the pair,
and requires byte-exact parent and endpoint restoration.
The exact endpoint-route cases prove canonical request encoding, strict route decoding,
both-pair/namespace lineage, fail-closed sibling classification, and deletion-bound ownership.
The live production-policy round trip installs the exact generation-2 ruleset in a disposable
namespace, deletes only its observed table handle, proves semantic-empty generation 3, and verifies
the inherited canonical forwarding value unchanged. It deliberately sends no packet.
Separate fixed-writer tests use a distinct disposable network namespace to establish `0\n`, perform
a real `0\n` to `1\n` to `0\n` round trip, and restore that namespace's initial value. Synthetic
descriptor-backed tests prove that an inherited `1\n` takes the no-write enable and restore path.
Together with the production lifecycle gate these cover both conditional branches without changing
the development host, but they are not a claim that two separately forced initial values traversed
the complete PID-1 lifecycle.
These portable cases treat only the exact util-linux `EPERM` forms for an unavailable `unshare` or
UID/GID-map write as an environmental skip; every other spawn, child, parser, or proof failure
remains fatal. Such a skip is not readiness evidence and cannot replace the dedicated gate.

```sh
just test-netns-ipv4-forwarding-runtime-proof
```

That opt-in gate requires an unprivileged Debian 13 amd64 host with unprivileged user namespaces
enabled, zero inherited, permitted, effective, and ambient capability sets, and `no_new_privs`. It
also requires Debian's `iproute2` (`ip` and `tc`) and `jq` packages for a read-only, canonical outer
configuration fingerprint. A dedicated ephemeral VM is required for authoritative acceptance, but
the gate itself proves only that its immediate host is a VM; CI job provenance must establish that
the VM was dedicated and ephemeral. A bare-metal development host may supply an additional local
proof because the runner remains inside disposable namespaces and the gate compares its outer
namespace and mount table plus canonical stable link fields, addresses without expiring lifetimes,
IPv4/IPv6 routes and policy rules, nexthops, qdiscs without counters, IPv4 `ip_forward`, IPv6
`all/default` forwarding, and `/etc/resolv.conf` object/target identity plus content before and
after. It deliberately excludes
volatile carrier/operstate, neighbour state, counters, address lifetimes, and resolver-daemon
caches. The unprivileged gate does not escalate and cannot authoritatively read host
nftables/legacy-firewall state or VPN-private peer/key state. This is useful rollback evidence, not
A14, A15, or acceptance evidence. A container on an Ubuntu runner does not supply the required
Debian-host kernel evidence, and a privileged container would test a different privilege boundary.
The gate executes a private, owner-only copy of the fixed-target build artifact.

The earlier `just test-netns-forward-policy-teardown-proof`,
`just test-netns-endpoint-route-teardown-proof`,
`just test-netns-link-activation-teardown-proof`,
`just test-netns-ipv4-address-rollback-proof`,
`just test-netns-veth-rollback-proof`, `just test-netns-live-nsfs-proof`,
`just test-netns-authorized-private-run-proof`, and `just test-netns-bootstrap-ready-proof` recipes
remain compatibility entry points, but the command above names the deepest currently implemented
proof.

The runner retains exact-child and namespace-FD ownership through a bounded synchronous reap
attempt. Normal reaping retains the pidfd and exact `Child` ownership; every forced `SIGKILL` after
admission targets that pidfd, including timeout and fallback-reaper paths. Pidfd acquisition is
mandatory; if it fails, the private channels close, `SIGKILL` is attempted against the still-owned
unreaped child, and that child is synchronously waited/reaped before the pidfd error returns. The
public `--run` entry requires exactly one initial task, and any non-default `SIGCHLD` handler or
`SA_NOCLDWAIT` is rejected before any channel, permit, reaper thread, or child is created. If a
later synchronous reap attempt cannot complete, ownership transfers to a process-local fallback
reaper instead of being silently detached; that rare fallback is not claimed as post-exit cleanup
or A14 evidence. The current positive `--run` path requires post-`GO` EOF to classify as
`CleanupRequired`, proves repeated exact PID-1 and outer-launcher reaping plus unchanged outer
namespace, mount-table, canonical link/address/route/rule/nexthop/qdisc, IPv4 `ip_forward`, IPv6
`all/default` forwarding, and resolver-file observations, and honestly returns
`BlockedAfterForwardPolicyTeardown`/77. That outcome additionally proves the complete
private-mount barrier, exact RTNL state, descriptor-pinned IPv4-forwarding baseline, zero nftables
tables bracketed by unchanged generation 1, one real pinned `BOOTSTRAP_READY`, canonical `GO`,
affine `MutationAuthorization`, the descriptor-relative root/slot transaction, two live pristine
nsfs pins, and two exactly proven down-veth pairs, each created through one atomic `RTM_NEWLINK`
request. It also proves the four fixed `/30` addresses and exactly four kernel-created local-table
`/32` routes while every veth end remains down, the all-addrgen-NONE barrier, the atomic exact
generation-2 parent-FORWARD policy installed before activation, exact carrier-up activation and
kernel-owned qdisc/route side effects, both exact static endpoint routes and their strict parent/A/B
observation, direct veth B/A deletion while the policy remains exact, parent/endpoint restoration
under generation 2 after exact restoration of the retained parent `ip_forward` record, handle-only
policy deletion, semantic-empty generation 3, final
parent/endpoint reproof before route/address/pair owner retirement, and the nsfs ordinary reverse
unmount, internal `MUTATION_ROLLBACK_COMPLETE` checkpoint, independent empty-`/run` verification,
and fixed pidfd-to-PID1-signalfd TERM observation described above. It conditionally writes only the
disposable parent namespace's fixed forwarding record, restores that exact original record, leaves
the outer host setting byte-identical, and creates no manifest. It produces no packet-absence,
probe, datapath, general crash-cleanup, A14, A15, or acceptance evidence. At supervised IPC boundaries, managed
outer HUP/INT/TERM events take
priority over pending protocol records and trigger bounded exact-launcher containment. The live
gate does not yet prove external-signal handling throughout every reap/report phase, a forced
parent-death/crash chain, a general descendant reaper, or A14 cleanup. Command/environment shims
prove that the runner invokes no namespace or networking utility. It still has no general
root-filesystem or supplementary-group isolation, `TOPOLOGY_READY`, `STOP`, `FINISHED`, configured
dataplane-topology mutation, crash-cleanup evidence, acceptance report, or A01-A15 result.
`BOOTSTRAP_READY` remains readiness evidence; this `GO` authorizes only the bounded private-root,
two-pin, two-veth, four-address, exact forward-policy, conditional forwarding enable/restore,
link-activation, endpoint-route, and policy teardown transaction, and the
rollback checkpoint is not A14 cleanup or acceptance evidence.
The dedicated-host proof also does not claim hostile same-UID sender provenance from the
`signalfd_siginfo` metadata; it proves that the retained pidfd send is followed by the exact
quiescent TERM observation within this fixed supervisor.

Privileged topology execution stays blocked until that fixed reviewed supervisor additionally owns
lifecycle setup and evidence finalization, complete process-tree containment, network-object
ownership, and teardown as one operation.
It may not accept a caller-selected command, executable, backend, timeout, cleanup prefix, or
network-object name.

Run-scoped names derive from one 128-bit lowercase hexadecimal run ID. The production ownership and
namespace modules and the `PristineRun`, `AuthorizedPrivateRun`, `AuthorizedNamespacePins`,
`AuthorizedVethPairs`, `AuthorizedIpv4Addresses`, `AuthorizedIpv4AddrgenNone`,
`AuthorizedActivatedTopology`, and `AuthorizedDeletedTopology` typestates are active in the runner.
Separate affine forwarding authorities distinguish the original, enabled, exactly restored, and
indeterminate record states; lower-owner retirement and policy deletion cannot cross an enabled or
unclassified forwarding state.
After consuming
`MutationAuthorization`, it uses only the retained private-`/run` descriptor to create the fixed
mode-0700 roots `/run/netns` and `/run/volparossa-netns-runner/<run_id>` plus exactly two
run-derived mode-0000 empty slots. It retains and rechecks their identities and exact entry sets.
A provisional containment guard exists immediately after every exclusive creation. In the fixed
one-PID-1-task, trusted-launcher model, an inotify witness rejects delete, move, and recreate
activity across the inherently non-atomic `mkdirat`-to-open handoff. A retained descriptor plus
that exact handoff observation permits only a scoped cleanup attempt; immediately before unlink,
the guard revalidates the descriptor, path, parent, and object shape. If the new directory cannot
be pinned unambiguously, the runner leaves the name untouched, fails closed, and
relies on destruction of its disposable mount namespace rather than risking deletion of a
replacement. Only a fully pinned and journalled layout can advance to the namespace transition.
That transition publishes exactly two live nsfs pins, visits each through its visible read-only
descriptor, creates and proves exactly two fixed down-veth pairs, installs and proves the four fixed
IPv4 addresses and their four kernel-created local-table routes while every end remains down,
proves the all-NONE barrier, installs the exact generation-2 policy, conditionally establishes
parent-namespace IPv4 forwarding, and proves the carrier-up
barrier plus both endpoint routes with exact qdisc/route side effects. It directly deletes veth B
then A, restores the exact original forwarding record, proves all three network namespaces pristine
for the enumerated restored phase under generation 2, deletes the policy by its observed handle,
proves semantic-empty generation 3, repeats the final network proof, retires the
lower owners, and ordinarily unmounts nsfs B then A,
and proves its exact mountinfo baseline before the success path reverses slot B, slot A, the per-run
directory, the workspace root, and the netns root, including directory `fsync`. Inotify and
compare-before-unlink
are not a race-free deletion
primitive against a hostile mapped-same-UID process with a previously opened writable directory
descriptor. That actor is explicitly outside this disposable runner's proof; a production helper
must instead provide root-owned exclusive mutation authority. This transaction neither creates
nor publishes an ownership manifest.

The future private ownership-manifest contract remains a mode-0600, owner-bound, bounded and
canonically sorted record of exact namespace names and unique nonzero device/inode pairs. Its
reader/classifier and atomic publication machine remain `cfg(test)`-only. Temporary-directory
regressions require initially empty mode-0700 roots, exact entry sets, descriptor and nonzero
`statx` mount identities, two mode-0000 empty slots, an exclusive mode-0600 `ownership.pending`,
exact bounded double readback, file sync, `RENAME_NOREPLACE`, directory sync, and an immediate
manifest pin. Failure injection at every modeled stage/publication boundary exercises reverse,
identity-scoped unlink of only the synthetic regular files created by that invocation.
`tests/netns/test-lifecycle-contract.sh` exercises the manifest decision logic without creating a
namespace or invoking a networking command.

Those publication tests deliberately use synthetic device/inode records and one tempfile actor;
they do not prove a live namespace, hostile same-UID concurrency safety, safe production namespace
teardown, topology/probe readiness, cleanup, A14, or A15. Separately, the runtime transaction
proves its own two transient live nsfs pins, two fixed veth pairs, four fixed IPv4 addresses,
their exact active qdisc/route side effects, one exact generation-2 parent-FORWARD policy,
conditional enable/restore of the fixed parent `ip_forward` record, and
deletion-only link teardown plus handle-only policy retirement with pre-retirement pristine and
semantic-empty generation-3 proofs inside the fixed one-PID-1-task, trusted-launcher model, but
production still has no manifest writer or configured topology lifecycle. The unmount target is
retained parent at `/proc/thread-self/fd/<fd>/<leaf>` and is identity-checked before unmount; the
intervening lookup is
not a race-free primitive against an excluded hostile mapped-same-UID actor. A production helper
must provide root-owned exclusive mutation authority and retain rollback authority across any
future ownership-manifest integration.

The V1 lifecycle specification digest also pins the two namespace and underlay-interface name
formulas, two isolated `/30` networks, two exact host routes, absence of default routes and host
links, namespace-local forwarding, an nftables forward policy of drop, and only the exact IPv4 ICMP
request/reply tuples needed by the one-shot probe. Changing that topology requires an explicit
contract/digest change rather than an implicit worker variation.

## Native and performance gates

Native mqvpn/xquic runs its pinned upstream tests, warnings-as-errors build where feasible, ASan/
UBSan, and Valgrind. Interoperability fixes are patches recorded in `THIRD_PARTY_LICENSES.md`.

Benchmarks cover one/four relays; TCP/MPTCP and QUIC/MPQUIC; RTT spread, loss, jitter, capacity,
WireGuard overhead, setup/discovery/failover; CPU, memory, context switches; and net user versus
physical tunnel data. Benchmark results never substitute for functional/privacy acceptance.

The blocked preview reports are harness evidence only. They do not satisfy A01–A15, native
interoperability, fuzzing, performance, privacy, cleanup, or real-network acceptance.
