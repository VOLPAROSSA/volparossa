# Testing and acceptance

Unit tests establish parser and state-machine properties; they do not establish dataplane privacy or
multipath. Real dataplane claims require a disposable Debian 13 network-namespace topology,
independent kernel/native counters, packet captures, fault injection, cleanup, and a machine-readable
acceptance report.

## Requirement preservation

[GOAL.md](GOAL.md) is the complete effective specification, including DPS and
Studio. The [source archive](../archive/requirements-20261023/README.md) preserves
the original goal, amendments, DPS parts and Studio source bytes. Archived model
assignments and one-time procedures are historical, not current instructions.

When changing requirements or their preserved sources, run:

```sh
python3 -B scripts/verify-goal-preservation.py
```

To check immutable committed blobs, append `--git-revision FULL_COMMIT_SHA` with
the full 40-character commit identity. When changing the verifier, also run
`python3 -B scripts/test-goal-preservation.py`. These are bounded inert reads;
they need no attachments, network, native builds or prior Git history.

The verifier checks source hashes, original payloads and amendment prefixes, the
exact DPS join, and explicit integrated DPS/Studio markers in GOAL. It reads no
status ledger and requires no duplicate goal/prompt file. These checks establish
preservation and inclusion markers, not semantic equivalence or runtime acceptance.
Review requirement rewrites against the sources for full functional coverage,
privacy and authority. Ordinary code tasks that leave these documents untouched
do not require this check at startup.

## Unprivileged quality gate

During functional development, run the narrowest formatter/compile check and relevant executable
smoke for the changed slice. The following broad gate belongs at integration checkpoints/CI and
release preparation; do not repeat it for every small edit. Retained real datapath and disposable
cleanup evidence is still required before claiming a networking feature works.

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
the locked root and standalone fuzz feature graphs before running pinned
`cargo-deny 0.18.6` all-in-one checks and independent no-fetch
`cargo-audit 0.22.1` scans of both lockfiles. Cargo-deny is built with its
pinned Rust 1.88 toolchain; the product remains pinned to Rust 1.85. The gate
records the local RustSec database commit. See `third_party/rust/README.md` for
the narrowly scoped local backports, single-backend Yamux hardening, and
scanner exemptions.

The read-only `RustSec pin review` workflow compares the Quality pin with official
RustSec `main` weekly and on manual dispatch. It cross-checks Git and GitHub API
commit identities and reports dates, API signature metadata and a candidate patch
in the job summary. It exits unsuccessfully when review is needed or acquisition
fails; it does not apply patches, create PRs or grant write permissions. Run its
inert checks with `python3 -B scripts/test-rustsec-pin-review.py` and its live
comparison with `python3 -B scripts/review-rustsec-pin.py`. The comparison does not
scan dependencies. A reviewed pin update must pass hosted Quality's existing
offline root/fuzz audits, exact vendor reconstruction and RSA scope checks; newly
discovered vulnerabilities require remediation rather than new exceptions.

The explicit Quality dispatch input `ctutils_compatibility=true` runs only the
reviewed Rust 1.85/32-bit compatibility and linked codegen capture recipe, bound
to `core_revision` equal to the workflow revision. See `third_party/rust/README.md`
for the exact adapted upstream source, twenty const API limitations and required
independent codegen review. A successful capture is not constant-time acceptance;
ordinary Quality's current-database dependency audits remain separate.

The package-license regression proves all three reviewed path overrides and
the exact `yamux 0.13.10` release-tag license fallback enter the distributable
notices while workspace and arbitrary path packages do not.

Focused unit/property tests cover canonical protobuf, versioned signed
control payloads, signatures/key binding, replay/TTL/skew, advertisements, two-hop forwarding,
direct datapath-relay framing, policy normalization/thresholds, peerstore privacy,
selection/diversity/capacity, reservation expiry and exact retries, route contexts/LRU,
helper/native/local frames, configuration, MPTCP netlink, WireGuard plans, schedulers, and
idempotent cleanup planning. These tests are not dataplane or privacy evidence.

`volparossa-discovery/tests/reservation_rpc.rs` establishes authenticated Noise/Yamux connections
among three real libp2p swarms over process-local MemoryTransport. It proves a client cannot send an
exit request directly to the exit, then carries the same canonical wrapper client -> control relay
-> exit and the signed response back. Its probe case proves
`/volparossa/datapath-relay/4` framing and exact delivery to the authenticated local relay
handler. It is not a WireGuard probe or the complete production topology.

Discovery unit tests prove `/volparossa/advertisement/4` canonical bounds and reject request
versions 1, 2, 3, and future values plus the retired direct-reservation v2 identifiers. Protocol,
reservation, exit, and relay tests cover fresh session identities, hold/permit/finalize/grant/
confirmation/receipt binding, exact successful retries, replay/expiry, capacity rollback, and
removal of permanent client Peer ID fields. Test-only exact evidence verifiers do not make a real
probe producer.

The integrated production route/helper/transport sequence passed all A01--A15 on unchanged
`482e33d0`, including real MPTCP/MPQUIC, privacy captures and crash cleanup. See
[implementation status](../IMPLEMENTATION_STATUS.md) for the retained run and artifact, and the
separate results/failures of newer extensions. Unit coverage of signed authority, complete-pair
prepare/activate/commit, descriptor custody and destruction is supporting evidence, not a
replacement for that live run. Network-backed tests remain confined to disposable namespaces;
ordinary parser/state-machine tests do not alter host networking. The historical helper-boundary
gate below is a narrower proof, not the current complete feature inventory.

## Native content-storage foundation

Use the narrow suite relevant to the changed operation. Socket-bearing fixtures
run only in approved disposable namespaces/VMs, not on the development host.

```sh
cargo fmt -p volparossa-content -- --check
cargo test --locked -p volparossa-content
cargo clippy --locked -p volparossa-content --all-targets -- -D warnings
cargo run --locked -p volparossa-content --example offline_publication
```

The offline example uses temporary local stores, signed publication, disjoint
replicas, publisher removal and exact reconstruction. It does not create multiple
network peers or prove offline hosting. Focused CLI coverage is available through
`cargo test --locked -p volparossa content::tests --bin volparossa`; publish/assemble
must retain encrypted identity, trusted publisher, cache ownership/reuse, integrity,
quota/expiry and no-clobber output checks without opening sockets.

| Area | Required positive and negative coverage |
| --- | --- |
| Native stores/streams | Persistent reopen, ownership, quota, missing/wrong-publisher and corrupt chunks, oversized prefixes, deadlines and atomic reconstruction; interrupted consumers reopen only owned verified chunks. |
| Recipient-encrypted messages | Correct local decryption, wrong recipient/sender, tampering/rebinding, expiry, fresh encapsulation and 4-MiB limits. Only the explicit fixture persists a temporary 0600 recipient key under a 0700 directory; neither key nor known test plaintext enters artifacts, and both are removed on interruption/error. |
| HTTPS authority | Real TLS with correct origin/CA/name, signed metadata, sharing/freshness/framing rules, same-version fallback, changed-resource and monotonic expiry rejection. In-memory TLS does not prove protected network transport. |
| Missing ranges | Disjoint/contiguous missing runs, exact 206, full-size accounting when Range is ignored, no unnecessary I/O on complete content, stale/corrupt/truncated responses, quota and deadline refusal. |
| Provider/control/CLI | Signed offers and exact-manifest selection, independent partial stores, bounded connection/correlation, typed controls and independent user/service ownership. |
| Local account handoff | Normal publish/import/export/assemble, default public-import refusal before destination creation, explicit `--public-content`, >4-MiB/empty objects, unchanged identities, exact hashes and private output/cache ownership; local copying is not network receipt or ciphertext authority. |

The existing Alpha production-helper KVM driver supplies distinct scenarios:

| Scenario | Acceptance boundary |
| --- | --- |
| `content` | Separate provider processes, partial then complete reconstruction, normal protected ingress, actual WireGuard traffic, privacy captures, exact cleanup and unchanged guest state. Providers sharing one allowed destination do not prove independent operator/node diversity. |
| `content-message` | Real encrypted transfer, recipient UID/mode separation, wrong-recipient refusal and independent plaintext hash/length; a normal local handoff still does not establish a mailbox. |
| `content-https` | Separately authorized HTTPS and peer flows, complete peer case and missing-range/fallback case, actual captures and unchanged guest state. No system CA installation, production-certificate claim, generic browsing or speed claim follows. |
| `content-provider` | Independent-node serving plus normal `publish -> import --public-content -> serve -> remote fetch -> export --public-content -> assemble`, actual service sandbox isolation, selected provider, drained captures and secret cleanup. |
| `content-replication` | Uptake of a second public object, original provider stop, exact owned-store reopen with `--reuse-replica-cache`, restoration from the journal, independent Client fetch and complete owned cleanup. This is not automatic boot activation, permanent availability or a general speed/fairness result. |

Each scenario's current source-bound verdict and original failures belong in
[implementation status](../IMPLEMENTATION_STATUS.md) and its linked evidence.
Earlier per-test counts, payload sizes and revision-by-revision proof narratives
remain in the [development archive](../archive/development-notes-20261026.txt).
A passing local, loopback or earlier whole-body-fallback fixture does not qualify
a later range/runtime variant or establish C02–C08 completion. See the canonical
[content contract](../services/CONTENT_NETWORK_PROPOSAL.md) for those requirements.

## Helper-boundary evidence

The narrow helper/IPC gate is separate from full datapath acceptance:

```sh
just build-helper-live-worker-identity-proof
sudo just test-helper-live-worker-identity-proof
```

Build as an ordinary user, then execute as root **only in an approved disposable
Debian 13 amd64 VM with systemd v257 as PID 1**. The execute path refuses containers,
unsafe/changing source state, unsupported hosts, missing artifacts and an occupied
host `/run/volparossa`; preview is the default. These commands do not authorize
changes on the development host.

The canonical producer, validators and adversarial controls are:

- [Live worker identity producer](../../tests/helper/require-live-worker-identity-proof.sh).
- [Report schema](../../tests/helper/helper-boundary-evidence-v1.schema.json) and
  [semantic validator](../../tests/helper/validate-helper-boundary-evidence-v1.sh).
- [False-PASS/report regressions](../../tests/helper/test-helper-boundary-evidence-v1.sh).
- [VM driver](../../tests/helper/run-helper-boundary-evidence-vm.sh) and
  [hosted workflow](../../.github/workflows/helper-boundary-evidence.yml).

A retained PASS requires the source-pinned disposable job to build both binaries
as an unprivileged user and then run the fixed root producer. A standalone report
validator cannot establish report authenticity or bind an arbitrary pre-existing
binary to a commit. The job preserves original source/artifact bookends and emits
one canonical JSON document to stdout only after removing its root-owned stage.

### Helper proof contract

The producer verifies, rather than assumes:

- Sequential Client and Exit singleton leases and one simultaneous Relay endpoint
  pair, distinct worker/namespace ownership, signed endpoint bindings, exact
  Prepare/Activate/Commit/Destroy correlation and byte-identical idempotent retries.
- PID 1's exact launch tuple, root-owned staged image and digest, invocation/process
  identities, server `SO_PEERCRED`, retained pidfd/proc/netns lineage, dedicated
  credentials, capabilities, no-new-privileges and seccomp state at live barriers.
- Each fixed isolated WireGuard leg's exact interface/route/peer lineage, one
  bounded ICMPv6 echo, non-zero handshake and increasing counters on both sides;
  temporary relay fixtures are removed before releasing the worker barrier.
- Terminal workers, empty owned WireGuard state, no helper children/custody, empty
  systemd descriptor store and the exact loopback/no-default-route cleanup state.
- Bounded private file capture and staged copies. Each original executable is a
  non-empty, single-link, workspace-owned regular file no larger than 128 MiB;
  each separate staged copy uses that bound before the producer and transient
  units enforce the fixed 1 MiB output limit. Empty diagnostic streams remain
  valid where no non-empty semantic content is required.
- Resolver records authorized only through the fixed live systemd-resolved service
  identity and exact Debian symlink/profile, not arbitrary non-root files below
  `/run`. Private content/metadata are digested and never printed.
- Canonical nftables authority plus separately classified legacy IPv4/IPv6 state,
  with exact repeated inventory/dump checks and fixed rejection labels. Equal
  fence records prove equality at those fences, not continuous host stability.

These legs terminate independently at Relay interfaces; the gate does not prove
cross-leg forwarding, a complete route, trusted discovery/policy selection,
transport handoff, ingress, package security, crash recovery, `CleanupOwned` or
A01–A15. The [current status](../IMPLEMENTATION_STATUS.md) distinguishes the later
full v1 checkpoint from these narrower original proofs. The detailed earlier
contract and exact run/artifact identities remain in the
[development evidence archive](../archive/development-notes-20261026.txt).

<a id="manual-non-retained-branch-smoke-and-retained-main-branch-vm-evidence"></a>

### Retained and non-retained VM modes

The workflow is manual. Exact `refs/heads/main` selects `retained-main`; another
canonical `refs/heads/*` selects `non-retained-pr-smoke`. There is no automatic PR
trigger or `refs/pull/*` support. Branch smoke validates the same source-bound
proof but discards every proof/failure file; a green smoke is not retained main
acceptance. Only a qualifying retained exact-main PASS is evidence for its
stated milestone, without automatically changing any score.

The driver verifies the pinned Debian image manifest/checksum before use and
rehashes it afterward. This is a reviewed genericcloud image, not detached-signature
attestation. Its first disposable boot acquires apt/Cargo inputs; a second KVM-only
boot uses restricted QEMU networking, checks blocked external HTTPS and builds
locked/offline. A fresh injected guest host key prevents SSH trust-on-first-use.
Offline Cargo alone is not a network sandbox.

The source workflow owns the exact `setpriv` invocation: original runner UID,
fixed device GID/identity, no supplementary groups or capabilities, no-new-privileges
and a reset environment. It never changes `/dev/kvm` permissions, ownership, ACL or
host group membership, and never falls back to TCG. Two actual KVM probes and
before/after device/ACL checks reject unstable access; a missing usable device is
an infrastructure failure, not negative helper evidence. The runner refuses host
root and never calls host sudo. Package installation in the disposable hosted
runner does not authorize host changes here.

A retained success allowlists the report/hash, bounded environment record, VM
console and proof stderr. Failure retains only bounded diagnostics; no failed
run publishes a success report/hash. Private-key markers redact or reject output,
including markers split across reads or outside the final rolling tail. Image,
disk, seed and ephemeral keys are never uploaded. Identity-bound pidfd supervision,
bounded stream draining, descendant handling and exact interrupted-temp cleanup
remain mandatory; unknown/malformed records fail closed. The canonical workflow
and driver contain the complete invocation and file allowlist.

## Parser and fuzzing coverage

Fuzz every externally controlled parser: all eighteen signed v4 control payloads,
advertisement-v4, exit-forwarding-v4, datapath-relay-v4, policy manifests, local/helper/
native frames, `OPEN_TCP`, UDP authorization, TLS ClientHello, QUIC Initial/classification,
peerlinks and configuration. Reach the 512 KiB frame boundary and at least one byte
beyond it using synthetic metadata only. Bound allocation, recursion, fields,
lists, frames, timeouts, peers, sessions, buffers and replay caches. Compilation,
short smoke runs and A0 tag-17/18 regressions are not sustained fuzzing evidence.

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

### Choose the correct runner

| Entry point | Scope |
| --- | --- |
| `just test-integration` | Package/license and unprivileged harness contracts, then `tests/integration/run.sh --preview --suite all`. |
| `just test-netns`, `just test-mptcp`, `just test-mpquic`, `just benchmark` | Non-mutating previews of the separate netns/benchmark harness. |
| `tests/integration/run.sh --execute --suite all` | The five-role disposable vertical runner; it records the first product blocker and its own limited host/cleanup observations. It is not the production-helper alpha gate. |
| `tests/integration/run-alpha-topology-vm.sh --preview` | Preview of the production-helper KVM driver and selected scenario. The explicit execute mode has its own pinned image/binary/package/source and acknowledgement requirements. |
| `just test-netns-fixed-icmp-echo-proof` | The bounded early netns lifecycle/rollback gate described below, not A01–A15. |

Use these only on approved disposable hosted environments. Inspect each driver's
own usage rather than copying flags between them: for example the vertical
`run.sh` selects `--suite`, while the older netns runner selects `--only` and
requires an explicit `--yes` for an execute request. Missing/duplicate acknowledgement
is an argument error where that profile requires it. Acknowledgement never replaces
supervisor, environment, ownership, teardown or host-state checks.

A preview or intentionally incomplete harness returns overall `BLOCKED`, with
unexecuted work `SKIPPED` and exit 77; that is not acceptance. Invalid arguments
and missing prerequisites have separate nonzero exits. Do not infer that production
drivers, helper networking or ingress are globally absent from an older harness's
BLOCKED result: the original same-build v1 A01–A15 evidence is retained in
[implementation status](../IMPLEMENTATION_STATUS.md#network-baseline-and-remaining-proof).
Every newer source and extension still needs its own applicable proof.

### Fixed netns lifecycle and containment contract

The [netns runner](../../crates/volparossa-netns-runner/src/main.rs),
[lifecycle contracts](../../tests/netns/test-lifecycle-contract.sh) and
[fixed echo gate](../../tests/netns/require-fixed-icmp-echo-proof.sh) own the exact
protocol, typestates, kernel layouts, source-bound specification digest and
adversarial controls. The previous detailed implementation narrative is preserved
in the [development archive](../archive/development-notes-20261026.txt); use source
and these contracts when changing that boundary.

The fixed proof retains all of the following limits:

1. **Authorization and launch:** one bounded canonical `LAUNCH_CONTEXT` provisions
   only the random run ID, original-host namespace identities and fixed specification
   digest. A separate affine lifecycle channel orders `BOOTSTRAP_READY`, `GO`,
   `TOPOLOGY_READY`, `STOP`, `FINISHED`; malformed, repeated, reordered or mismatched
   records fail closed. Readiness is measured, not asserted. Pre-GO EOF grants no
   topology mutation but still requires containment of bootstrap resources;
   post-GO EOF requires cleanup. The implemented fixed-echo slice has not completed
   the general `TOPOLOGY_READY`/`STOP`/`FINISHED` configured topology lifecycle.
2. **Measured isolation:** the single-task launcher and PID 1 independently bind
   exact executable/selector, process/parent identities, namespace pins, one-extent
   UID/GID maps, empty environment/groups, parent-death signal and mapped-root state.
   Outer acknowledgement precedes child creation or private mounts. Fixed hardened
   private `/run` and `/proc` mounts admit no caller-selected paths/options/fallback.
   `/run` has a 16 MiB/4096-inode bound; user-namespace mount limitations do not
   authorize storing filesystem-backed keys or secrets without proven non-swappable
   storage. Inherited mount propagation and extraneous proc tasks are rejected.
3. **Signals and child ownership:** exact inherited signal dispositions/masks are
   checked before channels, children or reaper threads. Managed HUP/INT/TERM and
   CHLD use the fixed signalfd contract with emergency handlers; live pidfd/proc
   observations bind readback. The pinned Rust runtime's signal baseline is not a
   universal Linux ABI. Pidfds and exact Child ownership persist through bounded
   reaping or the ownership-transferring fallback reaper; no silent detached child
   or caller-selected command/backend/time/name is allowed. Failure containment
   alone does not prove forced-crash or descendant cleanup.
4. **Network baseline:** repeated complete RTNL, proc and generation-bracketed
   NFNETLINK reads require the exact pristine loopback/rules/qdisc profile, no
   addresses/routes/neighbours/nexthops or nftables objects, and canonical original
   `ip_forward`. The observation itself writes nothing. Non-enumerated kernel
   facilities, physical radios, VPN-private state and module-loading side effects
   are outside this bounded proof.
5. **One authorized topology:** retained run/namespace/interface lineage creates
   exactly two nsfs pins, two veth pairs, four fixed `/30` IPv4 addresses, two static
   `/32` endpoint routes and four affine `NUD_PERMANENT` neighbours with zero probes
   and proxy neighbours. IPv6 addrgen is `none` before link activation; kernel
   routes/qdiscs must match exact allowed side effects. Canonical names, tuples,
   flags, lengths and attributes are pinned in the specification; changing them
   requires an explicit contract/digest change.
6. **One counted packet exchange:** the run-derived generation-2 `inet` table owns
   the exact parent-FORWARD drop policy, the A-to-B IPv4 echo accept, reverse reply
   accept and terminal counted drop. It is installed before conditional enablement
   of only the disposable parent's fixed `ip_forward` and before link activation.
   One no-retry 40-byte request yields one exact 60-byte reply bound to the full
   canonical run ID. Two complete post-close observations require request/reply/drop
   counters `1/60`, `1/60`, `0/0`; each of four veth ends must show exactly one RX/TX
   packet and 74 RX/TX bytes. A zero-counter phase cannot be regained after send.
   This is evidence of that exchange, not packet absence or capture-based privacy.
7. **Reverse retirement:** neighbours retire in reverse order; deletion-bound route,
   address and pair owners remain armed until direct veth B/A deletion, exact
   original forwarding restoration and parent/endpoint state restoration. There is
   no generic route-deletion API. Only the freshly observed table handle may retire
   policy, followed by semantic-empty generation 3 and final network proof. Nsfs
   pins unmount B/A with `UMOUNT_NOFOLLOW`; descriptor-relative roots/slots retire
   only after identity, entry-set, mountinfo and directory-fsync checks. Unknown
   ownership fails closed instead of deleting a possible replacement.
8. **Rollback limits:** `MUTATION_ROLLBACK_COMPLETE`, independent empty-/run readback,
   pidfd TERM/signalfd observation and exact reaping join the implemented positive
   path. Kernel reference counting, not observed last-reference destruction, removes
   detached namespace resources. Inotify plus compare-before-unlink is not race-free
   against a hostile mapped-same-UID actor; production needs root-owned exclusive
   mutation/rollback authority. Other IPv4 devconf reset effects are not exhaustively
   observed and rely on destruction of the disposable namespace.
9. **Output and result:** the canonical opt-in gate expects
   `BlockedAfterFixedIcmpEchoTeardown`/77. It proves the fixed echo and rollback,
   not general topology readiness, private-task authority, packet-capture privacy,
   A14, A15 or A01–A15 acceptance. A complete lifecycle-only report can at most
   make A15 PASS with equal content-addressed full host manifests after reaping;
   A14 stays SKIPPED without its forced crashes. Partial host fingerprints never
   establish full unchanged-host acceptance.

The fixed echo gate requires unprivileged Debian 13 amd64, user namespaces,
no inherited/permitted/effective/ambient capabilities and no-new-privileges, plus
`ip`, `tc` and `jq` for bounded read-only outer fingerprints. It changes only its
disposable namespaces. Authoritative provenance must establish a dedicated
ephemeral VM; a generic VM check, Ubuntu container or privileged container is not
that proof. It cannot authoritatively inspect host nftables/legacy firewall or
VPN-private peer/key state. It never grants permission to run this trial on the
development host.

Portable live collector tests may skip only the explicitly recognized util-linux
EPERM forms for unavailable user namespaces or ID-map writes. Other spawn, parser,
child or proof failures remain fatal; a skip cannot replace the positive gate.
Compatibility aliases are retained in [justfile](../../justfile), not separate
weaker acceptance profiles.

The private ownership-manifest classifier/publication model remains test-only:
mode-0600 bounded canonical records, exact owned mode-0700 roots and empty slots,
exclusive pending-file publication, double readback, sync, `RENAME_NOREPLACE` and
reverse identity-scoped cleanup are tested with synthetic records. This is not
production manifest publication, live namespace teardown or hostile same-UID
concurrency proof. Production-helper integration must retain exclusive mutation
and rollback authority before using that model for real ownership recovery.

## Native and performance gates

Native mqvpn/xquic runs its pinned upstream tests, warnings-as-errors build where feasible, ASan/
UBSan, and Valgrind. Interoperability fixes are patches recorded in `THIRD_PARTY_LICENSES.md`.

Benchmarks cover one/four relays; TCP/MPTCP and QUIC/MPQUIC; RTT spread, loss, jitter, capacity,
WireGuard overhead, setup/discovery/failover; CPU, memory, context switches; and net user versus
physical tunnel data. Benchmark results never substitute for functional/privacy acceptance.

The blocked preview reports are harness evidence only. They do not satisfy A01–A15, native
interoperability, fuzzing, performance, privacy, cleanup, or real-network acceptance.
